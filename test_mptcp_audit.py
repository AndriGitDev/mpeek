import argparse
import csv
import errno
import hashlib
import json
from pathlib import Path
import socket
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from unittest.mock import patch

import mptcp_audit as audit


class FakeSocket:
    def __init__(self, value=None, info=None, tcp_error=errno.EOPNOTSUPP, info_error=None):
        self.value, self.info = value, info
        self.tcp_error, self.info_error = tcp_error, info_error

    def getsockopt(self, level, option, *args):
        if option == audit.TCP_IS_MPTCP:
            if self.value is not None:
                return self.value
            raise OSError(self.tcp_error, "unsupported")
        if self.info_error:
            raise OSError(self.info_error, "unsupported")
        return self.info


class EvidenceTests(unittest.TestCase):
    def test_mpeek_entry_point_reports_version(self):
        entry_point = Path(audit.__file__).with_name("mpeek.py")
        result = subprocess.run([sys.executable, str(entry_point), "--version"],
                                capture_output=True, text=True, timeout=5, check=True)
        self.assertEqual(result.stdout.strip(), f"mpeek.py {audit.VERSION}")

    def test_suppression_counter_detection_ignores_normal_fallback(self):
        before = {"Blackhole": 3, "MPCapableSYNTXDrop": 2, "MPCapableFallbackACK": 0}
        after = {"Blackhole": 4, "MPCapableSYNTXDrop": 2, "MPCapableFallbackACK": 9}
        self.assertEqual(audit.suppression_deltas(before, after), {"Blackhole": 1})

    def test_canary_failure_preserves_every_started_attempt(self):
        attempted, recorded = [], []
        calls = []
        args = argparse.Namespace(concurrency=16, rate=1000000, mode="mptcp", timeout=1, vantage="test")

        def probe(ip, target, port, mode, timeout, vantage, inventory, pacer):
            if not pacer.acquire():
                return None
            attempted.append(port)
            cancelled = pacer.stop.wait(0.002)
            return {"port": port, "tcp_status": "cancelled" if cancelled else "open"}

        def canary(pacer):
            calls.append(1)
            if len(calls) == 2:
                raise audit.CanaryFailure("periodic canary failed")

        with patch.object(audit, "scan_endpoint", side_effect=probe):
            with self.assertRaises(audit.CanaryFailure):
                audit.run_scan([("127.0.0.1", "test")], range(1, 301), args, {}, recorded.append, canary)
        self.assertEqual(sorted(attempted), sorted(row["port"] for row in recorded))
        self.assertGreaterEqual(len(recorded), 100)
        self.assertLess(len(recorded), 300)

    def test_connection_wait_can_be_cancelled(self):
        stop = threading.Event()
        client = unittest.mock.Mock()
        client.connect_ex.return_value = errno.EINPROGRESS
        selector = unittest.mock.MagicMock()
        def select_once(timeout):
            stop.set()
            return []
        selector.__enter__.return_value.select.side_effect = select_once
        with patch.object(audit.selectors, "DefaultSelector", return_value=selector):
            self.assertFalse(audit.connect_with_timeout(client, ("127.0.0.1", 443), 30, stop))
        client.getsockopt.assert_not_called()

    def test_connection_deadline_is_enforced(self):
        client = unittest.mock.Mock()
        client.connect_ex.return_value = errno.EINPROGRESS
        with patch.object(audit.selectors, "DefaultSelector"), \
                patch.object(audit.time, "monotonic", side_effect=[0, 2]):
            with self.assertRaises(TimeoutError):
                audit.connect_with_timeout(client, ("127.0.0.1", 443), 1)

    def test_low_rate_pacing_cancel_is_prompt(self):
        pacer = audit.ConnectionPacer(0.001)
        self.assertTrue(pacer.acquire())
        result = []
        thread = threading.Thread(target=lambda: result.append(pacer.acquire()), daemon=True)
        thread.start()
        pacer.stop.set()
        thread.join(timeout=0.5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result, [False])

    def test_csv_formula_text_is_escaped_without_mutating_json_evidence(self):
        row = {"asset": "  =danger", "owner": "@formula", "port": 443, "target": "normal"}
        safe = audit.spreadsheet_safe(row)
        self.assertEqual(safe["asset"], "'  =danger")
        self.assertEqual(safe["owner"], "'@formula")
        self.assertEqual(safe["port"], 443)
        self.assertEqual(row["asset"], "  =danger")

    def test_modern_socket_detection(self):
        self.assertEqual(audit.mptcp_state(FakeSocket(value=1))[0], "observed")
        self.assertEqual(audit.mptcp_state(FakeSocket(value=0))[0], "not_observed")

    def test_uapi_flag_offset_and_negotiation(self):
        for flags, expected in [(2, "observed"), (1, "not_observed"),
                                (3, "not_observed"), (0, "unknown")]:
            # Token is intentionally different: parsing token as flags would fail.
            info = bytes(8) + struct.pack("=II", flags, 0x12345678)
            self.assertEqual(audit.mptcp_state(FakeSocket(info=info))[0], expected)

    def test_short_info_and_unexpected_errors_are_unknown(self):
        self.assertEqual(audit.mptcp_state(FakeSocket(info=bytes(8)))[0], "unknown")
        self.assertEqual(audit.mptcp_state(FakeSocket(tcp_error=errno.EBADF))[0], "unknown")
        self.assertEqual(audit.mptcp_state(FakeSocket(info_error=errno.EACCES))[0], "unknown")

    def test_preflight_rejects_false_positive_controls(self):
        with patch.object(audit.platform, "system", return_value="Linux"), \
                patch.object(audit, "check_path_manager", return_value={}), \
                patch.object(audit, "control_probe", return_value=("observed", "bad")):
            with self.assertRaisesRegex(ValueError, "calibration inconclusive"):
                audit.preflight("mptcp")

    def test_mac_does_not_silently_downgrade(self):
        with patch.object(audit.platform, "system", return_value="Darwin"):
            with self.assertRaisesRegex(ValueError, "requires Linux"):
                audit.preflight("mptcp")
            self.assertEqual(audit.preflight("tcp")["mode"], "tcp")

    def test_unpatched_tcp_still_requires_patching(self):
        row = dict(tcp_status="open", patch_status="unpatched", mptcp_status="not_observed")
        self.assertEqual(audit.next_action(row), "patch_running_kernel")
        row.update(patch_status="unknown", mptcp_status="observed")
        self.assertEqual(audit.next_action(row), "verify_endpoint_kernel_urgent")
        row["tcp_status"] = "timeout"
        self.assertEqual(audit.next_action(row), "resolve_reachability_gap")
        row["patch_status"] = "unpatched"
        self.assertEqual(audit.next_action(row), "patch_running_kernel")


class ScopeTests(unittest.TestCase):
    def test_canary_must_be_in_scope(self):
        scopes = [audit.ipv4_network("192.0.2.0/24")]
        self.assertEqual(audit.parse_canary("192.0.2.1:443", scopes), ("192.0.2.1", 443))
        for value in ["203.0.113.1:443", "192.0.2.1:80-81", "example.com:443"]:
            with self.assertRaises(ValueError):
                audit.parse_canary(value, scopes)

    def test_dns_addresses_are_pinned_filtered_and_deduplicated(self):
        resolver = lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))
                                  for ip in ["192.0.2.1", "203.0.113.5", "192.0.2.1"]]
        targets, issues = audit.build_targets(["edge.example", "192.0.2.1"],
                                             [audit.ipv4_network("192.0.2.0/24")], 10, resolver)
        self.assertEqual(targets, [("192.0.2.1", "192.0.2.1;edge.example")])
        self.assertEqual(issues[0]["ip"], "203.0.113.5")

    def test_dns_failure_is_retained(self):
        def resolver(*args):
            raise socket.gaierror("not found")
        targets, issues = audit.build_targets(["missing.example"],
                                             [audit.ipv4_network("192.0.2.0/24")], 10, resolver)
        self.assertFalse(targets)
        self.assertIn("DNS resolution failed", issues[0]["reason"])

    def test_large_cidr_rejected_before_expansion(self):
        with self.assertRaisesRegex(ValueError, "exceeds"):
            audit.build_targets(["10.0.0.0/8"], [audit.ipv4_network("10.0.0.0/8")], 4096)

    def test_ipv6_rejected_and_ipv4_slash32_supported(self):
        with self.assertRaises(ValueError):
            audit.ipv4_network("::/0")
        targets, _ = audit.build_targets(["192.0.2.1/32"], [audit.ipv4_network("192.0.2.1/32")], 10)
        self.assertEqual(targets[0][0], "192.0.2.1")

    def test_invalid_port_ranges(self):
        self.assertEqual(audit.parse_ports("443,22,80-81,443"), [22, 80, 81, 443])
        for item in ["0", "65536", "443-22", "1-2-3"]:
            with self.assertRaises(ValueError):
                audit.parse_ports(item)

    def test_inventory_requires_evidence_and_unique_endpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.csv"
            path.write_text("ip,port,patch_status,patch_evidence\n192.0.2.1,443,fixed,\n")
            with self.assertRaisesRegex(ValueError, "requires patch_evidence"):
                audit.load_inventory(path)
            path.write_text("ip,port,patch_status,patch_evidence\n192.0.2.1,443,unknown,\n"
                            "192.0.2.1,443,unknown,\n")
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                audit.load_inventory(path)

    def test_malformed_inventory_rows_produce_useful_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.csv"
            for content in [
                "ip,port,patch_status,patch_evidence\n192.0.2.1,443\n",
                "ip,port,patch_status,patch_evidence\n192.0.2.1,443,unknown,,extra\n",
                "ip,port,patch_status,patch_evidence,port\n",
            ]:
                path.write_text(content)
                with self.assertRaises(ValueError):
                    audit.load_inventory(path)
            path.write_text(" IP , Port , PATCH_STATUS , PATCH_EVIDENCE \n192.0.2.1,443,unknown,\n")
            self.assertIn(("192.0.2.1", 443), audit.load_inventory(path))

    def test_setup_interrupt_has_no_traceback(self):
        with patch.object(audit, "build_targets", side_effect=KeyboardInterrupt):
            self.assertEqual(audit.main(["192.0.2.1", "--allow", "192.0.2.1/32"]), 130)

    def test_scope_gaps_have_explicit_partial_exit_status(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "partial"
            code = audit.main(["192.0.2.1", "203.0.113.1", "--allow", "192.0.2.0/24",
                               "--dry-run", "--output", str(output)])
            self.assertEqual(code, 3)
            report = json.loads((output / "run.json").read_text())
            self.assertFalse(report["coverage_complete"])
            self.assertFalse(report["complete"])

    def test_dry_run_does_not_probe_or_calibrate(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(audit, "scan_endpoint", side_effect=AssertionError("network probe")), \
                patch.object(audit, "preflight", side_effect=AssertionError("calibration")):
            output = Path(directory) / "plan"
            code = audit.main(["192.0.2.1", "--allow", "192.0.2.1/32", "--dry-run",
                               "--ports", "443", "--output", str(output)])
            self.assertEqual(code, 0)
            report = json.loads((output / "run.json").read_text())
            self.assertEqual(report["planned_probes"], 1)
            self.assertFalse(report["complete"])


class LoopbackTests(unittest.TestCase):
    def test_real_canary_validates_before_and_after_scan(self):
        try:
            audit.preflight("mptcp")
        except ValueError as exc:
            self.skipTest(str(exc))
        servers, threads = [], []

        def serve(server, count):
            try:
                for _ in range(count):
                    conn, _ = server.accept()
                    with conn:
                        conn.settimeout(3)
                        conn.recv(1)
            except OSError:
                pass

        try:
            for protocol, count in [(socket.IPPROTO_TCP, 1), (audit.IPPROTO_MPTCP, 2)]:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM, protocol)
                server.bind(("127.0.0.1", 0))
                server.listen(2)
                server.settimeout(3)
                servers.append(server)
                thread = threading.Thread(target=serve, args=(server, count))
                thread.start()
                threads.append(thread)
            port = servers[0].getsockname()[1]
            canary_port = servers[1].getsockname()[1]
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "canary"
                code = audit.main(["127.0.0.1", "--allow", "127.0.0.1/32", "--ports", str(port),
                                   "--canary", f"127.0.0.1:{canary_port}", "--rate", "100",
                                   "--output", str(output)])
                self.assertEqual(code, 0)
                report = json.loads((output / "run.json").read_text())
                self.assertTrue(report["complete"])
                self.assertEqual(report["path_validation"], "passed_canary_only")
                self.assertEqual(len(report["canary_checks"]), 2)
                self.assertTrue(all(row["mptcp_status"] == "observed" for row in report["canary_checks"]))
        finally:
            for thread in threads:
                thread.join(timeout=4)
            for server in servers:
                server.close()

    def test_interrupted_scan_keeps_unattempted_inventory_in_patch_queue(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(audit, "run_scan", side_effect=KeyboardInterrupt):
            root = Path(directory)
            inventory = root / "inventory.csv"
            inventory.write_text("ip,port,patch_status,patch_evidence\n127.0.0.1,443,unpatched,test-fixture-only\n")
            output = root / "results"
            code = audit.main(["127.0.0.1", "--allow", "127.0.0.1/32", "--ports", "443", "--mode", "tcp",
                               "--inventory", str(inventory), "--output", str(output)])
            self.assertEqual(code, 130)
            with open(output / "triage.csv", newline="") as handle:
                queue = list(csv.DictReader(handle))
            self.assertEqual(queue[0]["tcp_status"], "not_scanned")
            self.assertEqual(queue[0]["next_action"], "patch_running_kernel")

    def test_sigint_stops_low_rate_cli_promptly(self):
        with tempfile.TemporaryDirectory() as directory, \
                socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
            held.bind(("127.0.0.1", 0))
            port = held.getsockname()[1]
            output = Path(directory) / "interrupted"
            script = str(Path(audit.__file__).resolve())
            process = subprocess.Popen([sys.executable, script, "127.0.0.1", "--allow", "127.0.0.1/32",
                                        "--ports", f"{port},{1 if port != 1 else 2}", "--mode", "tcp",
                                        "--rate", "0.001", "--output", str(output)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    path = output / "results.jsonl"
                    if path.exists() and path.read_text().strip():
                        break
                    if process.poll() is not None:
                        self.fail("CLI exited before interrupt test")
                    time.sleep(0.01)
                else:
                    self.fail("CLI did not produce a first result")
                process.send_signal(signal.SIGINT)
                _, stderr = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 130, stderr)
                self.assertNotIn("Traceback", stderr)
                report = json.loads((output / "run.json").read_text())
                self.assertFalse(report["complete"])
                self.assertEqual(report["completed_probes"], 1)
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate()

    def test_scanner_suppression_stops_run_as_inconclusive(self):
        row = dict.fromkeys(audit.FIELDS, "")
        row.update(ip="127.0.0.1", port=443, tcp_status="open", mptcp_status="not_observed",
                   patch_status="unknown", next_action="verify_endpoint_kernel")
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(audit, "preflight", return_value={}), \
                patch.object(audit, "scan_endpoint", return_value=row), \
                patch.object(audit, "read_mptcp_counters", side_effect=[{"Blackhole": 0}, {"Blackhole": 1}]):
            output = Path(directory) / "suppression"
            code = audit.main(["127.0.0.1", "--allow", "127.0.0.1/32", "--ports", "443",
                               "--output", str(output)])
            self.assertEqual(code, 2)
            report = json.loads((output / "run.json").read_text())
            self.assertEqual(report["scanner_health"], "failed")
            self.assertFalse(report["complete"])

    def test_unscanned_inventory_remains_in_patch_queue(self):
        row = dict.fromkeys(audit.FIELDS, "")
        row.update(ip="127.0.0.1", port=443, tcp_status="refused", mptcp_status="not_tested",
                   patch_status="unknown", next_action="resolve_reachability_gap")
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(audit, "scan_endpoint", return_value=row):
            root = Path(directory)
            inventory = root / "inventory.csv"
            inventory.write_text("ip,port,patch_status,patch_evidence\n192.0.2.1,8443,unpatched,test-fixture-only\n")
            output = root / "results"
            code = audit.main(["127.0.0.1", "--allow", "127.0.0.1/32", "--ports", "443", "--mode", "tcp",
                               "--inventory", str(inventory), "--output", str(output)])
            self.assertEqual(code, 3)
            report = json.loads((output / "run.json").read_text())
            self.assertFalse(report["coverage_complete"])
            self.assertEqual(report["inventory_not_scanned"][0]["ip"], "192.0.2.1")
            with open(output / "triage.csv", newline="") as handle:
                queue = list(csv.DictReader(handle))
            self.assertEqual(len(queue), 1)
            self.assertEqual(queue[0]["tcp_status"], "not_scanned")
            self.assertEqual(queue[0]["next_action"], "patch_running_kernel")

    def test_tcp_nonlistener_is_not_tested_for_mptcp(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
            held.bind(("127.0.0.1", 0))
            row = audit.scan_endpoint("127.0.0.1", "loopback", held.getsockname()[1], "tcp", 1, "test", {})
            # Linux refuses a bound nonlistener; macOS may silently drop its SYN.
            self.assertIn(row["tcp_status"], {"refused", "timeout"})
            self.assertEqual(row["mptcp_status"], "not_tested")
            self.assertTrue(row["self_probe"])

    def test_tcp_refusal_mapping_is_explicit(self):
        with patch.object(audit, "connect_with_timeout", side_effect=ConnectionRefusedError):
            row = audit.scan_endpoint("127.0.0.1", "loopback", 443, "tcp", 1, "test", {})
        self.assertEqual(row["tcp_status"], "refused")
        self.assertEqual(row["mptcp_status"], "not_tested")

    def test_full_scan_reports_and_inventory_join(self):
        try:
            audit.preflight("mptcp")
        except ValueError as exc:
            self.skipTest(str(exc))
        received = []
        listeners = []
        threads = []

        def receive_no_payload(server):
            try:
                conn, _ = server.accept()
                with conn:
                    conn.settimeout(3)
                    received.append(conn.recv(1024))
            except OSError as exc:
                received.append(str(exc))

        try:
            for protocol in (socket.IPPROTO_TCP, audit.IPPROTO_MPTCP):
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM, protocol)
                server.bind(("127.0.0.1", 0))
                server.listen(1)
                server.settimeout(3)
                listeners.append(server)
                thread = threading.Thread(target=receive_no_payload, args=(server,))
                thread.start()
                threads.append(thread)
            # Bound but not listening: a deterministic local connection refusal.
            closed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            closed.bind(("127.0.0.1", 0))
            listeners.append(closed)
            ports = [server.getsockname()[1] for server in listeners]
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                inventory = root / "inventory.csv"
                inventory.write_text("ip,port,patch_status,patch_evidence\n"
                                     f"127.0.0.1,{ports[0]},unpatched,test-fixture-only\n")
                code = audit.main(["127.0.0.1", "--allow", "127.0.0.1/32",
                                   "--ports", ",".join(map(str, ports)), "--inventory", str(inventory),
                                   "--rate", "20", "--output", str(root / "results")])
                self.assertEqual(code, 0)
                with open(root / "results" / "results.csv", newline="") as handle:
                    rows = {int(row["port"]): row for row in csv.DictReader(handle)}
                self.assertEqual(rows[ports[0]]["mptcp_status"], "not_observed")
                self.assertEqual(rows[ports[0]]["next_action"], "patch_running_kernel")
                self.assertEqual(rows[ports[1]]["mptcp_status"], "observed")
                self.assertEqual(rows[ports[1]]["next_action"], "verify_endpoint_kernel_urgent")
                self.assertEqual(rows[ports[2]]["tcp_status"], "refused")
                report = json.loads((root / "results" / "run.json").read_text())
                self.assertTrue(report["complete"])
                self.assertEqual(report["completed_probes"], 3)
                self.assertEqual(report["counts"]["mptcp_observed"], 1)
                lines = (root / "results" / "results.jsonl").read_text().splitlines()
                self.assertEqual(len(lines), 3)
                with open(root / "results" / "triage.csv", newline="") as handle:
                    triage = list(csv.DictReader(handle))
                self.assertEqual(len(triage), 2)
                self.assertEqual(triage[0]["next_action"], "patch_running_kernel")
        finally:
            for thread in threads:
                thread.join(timeout=4)
            for server in listeners:
                server.close()
        self.assertEqual(received, [b"", b""])

    def test_failed_canary_stops_target_probes_and_marks_incomplete(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(audit, "preflight", return_value={}), \
                patch.object(audit, "scan_endpoint", return_value={"mptcp_status": "not_observed"}) as scan:
            output = Path(directory) / "results"
            code = audit.main(["127.0.0.1", "--allow", "127.0.0.1/32", "--ports", "443",
                               "--canary", "127.0.0.1:8443", "--output", str(output)])
            self.assertEqual(code, 2)
            self.assertEqual(scan.call_count, 1)
            self.assertEqual(scan.call_args.args[2], 8443)
            report = json.loads((output / "run.json").read_text())
            self.assertFalse(report["complete"])
            self.assertEqual(report["path_validation"], "failed")
            self.assertEqual(report["completed_probes"], 0)

    def test_plain_tcp_mode(self):
        release = threading.Event()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            server.settimeout(2)

            def accept():
                conn, _ = server.accept()
                with conn:
                    release.wait(2)

            thread = threading.Thread(target=accept)
            thread.start()
            try:
                row = audit.scan_endpoint("127.0.0.1", "loopback", server.getsockname()[1],
                                          "tcp", 1, "test", {})
                self.assertEqual(row["tcp_status"], "open")
                self.assertEqual(row["mptcp_status"], "not_tested")
                self.assertEqual(row["patch_status"], "unknown")
            finally:
                release.set()
                thread.join()

    def test_real_mptcp_and_fallback(self):
        try:
            controls = audit.preflight("mptcp")
        except ValueError as exc:
            self.skipTest(str(exc))
        self.assertEqual(controls["positive_control"][0], "observed")
        self.assertEqual(controls["negative_control"][0], "not_observed")


@unittest.skipUnless((Path(audit.__file__).parent / ".git").exists(), "Release builder checks need a Git checkout")
class ReleaseTests(unittest.TestCase):
    def test_release_is_reproducible_allowlisted_and_manifested(self):
        from scripts import build_release
        with tempfile.TemporaryDirectory() as directory:
            first, checksum = build_release.build(Path(directory) / "one", allow_dirty=True)
            second, _ = build_release.build(Path(directory) / "two", allow_dirty=True)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(checksum.read_text().split()[0], hashlib.sha256(first.read_bytes()).hexdigest())
            prefix = f"mpeek-v{audit.VERSION}/"
            with zipfile.ZipFile(first) as archive:
                expected = {prefix + name for name in build_release.FILES} | {prefix + "MANIFEST.json"}
                self.assertEqual(set(archive.namelist()), expected)
                manifest = json.loads(archive.read(prefix + "MANIFEST.json"))
                for name, digest in manifest["files"].items():
                    self.assertEqual(hashlib.sha256(archive.read(prefix + name)).hexdigest(), digest)
                self.assertIn(b"MIT License", archive.read(prefix + "LICENSE"))

    def test_release_rejects_uncommitted_source_by_default(self):
        from scripts import build_release
        def dirty_git(*args):
            return " M README.md" if args[0] == "status" else "tracked"
        with tempfile.TemporaryDirectory() as directory, patch.object(build_release, "git", side_effect=dirty_git):
            with self.assertRaisesRegex(ValueError, "Commit all release source"):
                build_release.build(Path(directory))


if __name__ == "__main__":
    unittest.main()
