#!/usr/bin/env python3
"""Bounded TCP/MPTCP exposure inventory. Not an exploit or remote patch detector."""

import argparse
import concurrent.futures
import csv
import errno
import ipaddress
import json
import math
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import tempfile
from datetime import datetime, timezone

IPPROTO_MPTCP = 262
VERSION = "1.1.0"
SOL_MPTCP = 284
MPTCP_INFO = 1
TCP_IS_MPTCP = 43
FALLBACK = 1
REMOTE_KEY_RECEIVED = 2
UNSUPPORTED = {errno.ENOPROTOOPT, errno.EOPNOTSUPP, errno.EINVAL}
FIELDS = [
    "observed_at", "vantage", "target", "ip", "port", "tcp_status",
    "mptcp_status", "evidence", "elapsed_ms", "local_ip", "asset", "owner",
    "patch_status", "patch_evidence", "next_action", "self_probe",
]


class ScanStopped(ValueError):
    pass


class CanaryFailure(ScanStopped):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def write_json_atomic(path, value):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".run-", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(value, handle, indent=2)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def spreadsheet_safe(row):
    def safe(value):
        if isinstance(value, str) and (value.lstrip().startswith(("=", "+", "-", "@")) or
                                       value.startswith(("\t", "\r", "\n"))):
            return "'" + value
        return value
    return {key: safe(value) for key, value in row.items()}


def mptcp_state(sock):
    """Return evidence about this connection, never remote OS or patch status."""
    try:
        value = sock.getsockopt(socket.IPPROTO_TCP, TCP_IS_MPTCP)
        if value == 1:
            return "observed", "TCP_IS_MPTCP=1"
        if value == 0:
            return "not_observed", "TCP_IS_MPTCP=0; client, path or peer fallback possible"
        return "unknown", f"unexpected TCP_IS_MPTCP value: {value}"
    except OSError as exc:
        if exc.errno not in UNSUPPORTED:
            return "unknown", f"TCP_IS_MPTCP error: {exc}"
    try:
        info = sock.getsockopt(SOL_MPTCP, MPTCP_INFO, 256)
    except OSError as exc:
        # Only interpret this as fallback after both local calibration controls pass.
        if exc.errno in {errno.EOPNOTSUPP, errno.ENOPROTOOPT}:
            return "not_observed", "MPTCP_INFO unavailable after connect; client, path or peer fallback possible"
        return "unknown", f"MPTCP_INFO error: {exc}"
    if len(info) < 12:
        return "unknown", f"MPTCP_INFO too short: {len(info)} bytes"
    # Linux UAPI: six u8 fields, two padding bytes, then native-endian u32 flags.
    flags = struct.unpack_from("=I", info, 8)[0]
    if flags & FALLBACK:
        return "not_observed", f"MPTCP_INFO flags={flags:#x}: FALLBACK"
    if flags & REMOTE_KEY_RECEIVED:
        return "observed", f"MPTCP_INFO flags={flags:#x}: remote key received, no fallback"
    return "unknown", f"MPTCP_INFO flags={flags:#x}: negotiation not confirmed"


def control_probe(server_protocol):
    """Local known-positive/negative controls; never a remote calibration target."""
    release = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, server_protocol) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(3)

        def accept_once():
            try:
                conn, _ = server.accept()
                with conn:
                    release.wait(3)
            except OSError:
                pass

        thread = threading.Thread(target=accept_once, daemon=True)
        thread.start()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_MPTCP) as client:
                client.settimeout(2)
                client.connect(server.getsockname())
                return mptcp_state(client)
        finally:
            release.set()
            thread.join(timeout=3)


def check_path_manager():
    """Do not let a peer's ADD_ADDR make the kernel dial an unapproved address."""
    settings = {}
    for name in ("path_manager", "pm_type"):
        path = Path("/proc/sys/net/mptcp") / name
        if path.exists():
            settings[name] = path.read_text(encoding="ascii").strip()
    if not settings or settings.get("path_manager", "kernel") != "kernel" or \
            settings.get("pm_type", "0") != "0":
        raise ValueError("MPTCP scan requires the in-kernel path manager; cannot confirm it "
                         f"from local sysctls: {settings}. Use a dedicated Linux scanner.")
    for name in ("enabled", "blackhole_timeout", "syn_retrans_before_tcp_fallback"):
        path = Path("/proc/sys/net/mptcp") / name
        if path.exists():
            settings[name] = path.read_text(encoding="ascii").strip()
    ip_tool = shutil.which("ip")
    if not ip_tool:
        raise ValueError("MPTCP preflight requires iproute2 ('ip mptcp limits show') to "
                         "verify that peer-announced addresses cannot trigger extra connections.")
    result = subprocess.run([ip_tool, "mptcp", "limits", "show"], capture_output=True,
                            text=True, timeout=3, check=False)
    match = re.search(r"\badd_addr_accepted\s+(\d+)\b", result.stdout)
    if result.returncode or not match or int(match.group(1)) != 0:
        raise ValueError("Require 'add_addr_accepted 0' on the dedicated scanner to avoid "
                         "connecting to peer-announced addresses. Current limits: "
                         f"{result.stdout.strip() or result.stderr.strip()}. "
                         "No settings have been changed.")
    warnings = []
    subflows = re.search(r"\bsubflows\s+(\d+)\b", result.stdout)
    if not subflows or int(subflows.group(1)) != 0:
        warnings.append("Additional local subflows are permitted; this is not enforced single-path probing. "
                        "Use a dedicated scanner namespace with subflows 0 for one path.")
    try:
        endpoints = subprocess.run([ip_tool, "mptcp", "endpoint", "show"], capture_output=True,
                                   text=True, timeout=3, check=False)
        endpoint_info = {"available": endpoints.returncode == 0, "output": endpoints.stdout.strip(),
                         "error": endpoints.stderr.strip()}
        if endpoints.returncode:
            warnings.append("Cannot inspect local MPTCP endpoints; verify scanner path-manager configuration.")
        elif endpoints.stdout.strip():
            warnings.append("Local MPTCP endpoints are configured; review possible extra subflows/address advertisements.")
    except (OSError, subprocess.TimeoutExpired) as exc:
        endpoint_info = {"available": False, "error": str(exc)}
        warnings.append("Cannot inspect local MPTCP endpoints; verify scanner path-manager configuration.")
    return {"sysctls": settings, "limits": result.stdout.strip(),
            "endpoints": endpoint_info, "warnings": warnings}


def read_mptcp_counters():
    try:
        lines = Path("/proc/net/netstat").read_text(encoding="ascii").splitlines()
        for header, values in zip(lines, lines[1:]):
            if header.startswith("MPTcpExt:") and values.startswith("MPTcpExt:"):
                return dict(zip(header.split()[1:], map(int, values.split()[1:])))
    except (OSError, ValueError):
        pass
    return {}


def suppression_deltas(before, after):
    return {key: value - before.get(key, value) for key, value in after.items()
            if ("blackhole" in key.lower() or "syntxdrop" in key.lower() or
                "syntxdisabled" in key.lower()) and value > before.get(key, value)}


def preflight(mode):
    result = {"platform": platform.platform(), "mode": mode, "checked_at": utc_now()}
    if mode == "tcp":
        result["mptcp"] = "not tested: explicitly selected reachability-only mode"
        return result
    if platform.system() != "Linux":
        raise ValueError("MPTCP mode requires Linux. On macOS use --mode tcp for reachability only, "
                         "or run this script in a patched Linux VM with access to the networks.")
    result["path_manager"] = check_path_manager()
    try:
        positive = control_probe(IPPROTO_MPTCP)
        negative = control_probe(socket.IPPROTO_TCP)
    except OSError as exc:
        raise ValueError(f"Local MPTCP controls failed: {exc}. Check Linux MPTCP support and "
                         "net.mptcp.enabled. Use --mode tcp explicitly for reachability only.") from exc
    if positive[0] != "observed" or negative[0] != "not_observed":
        raise ValueError(f"Local calibration inconclusive: MPTCP={positive}; TCP={negative}. "
                         "No target scanning performed. Use a newer MPTCP-capable Linux VM.")
    result["positive_control"] = positive
    result["negative_control"] = negative
    return result


def ipv4_network(text):
    network = ipaddress.ip_network(text, strict=True)
    if network.version != 4:
        raise ValueError("This CVE-focused scanner accepts IPv4 scope only.")
    return network


def parse_ports(text):
    ports = set()
    for item in text.split(","):
        bounds = item.strip().split("-")
        if len(bounds) == 1:
            first = last = int(bounds[0])
        elif len(bounds) == 2:
            first, last = map(int, bounds)
        else:
            raise ValueError(f"Invalid port expression: {item}")
        if not 1 <= first <= last <= 65535:
            raise ValueError(f"Invalid port range: {item}")
        ports.update(range(first, last + 1))
    return sorted(ports)


def parse_canary(text, scopes):
    if not text:
        return None
    parts = text.split(":")
    if len(parts) != 2:
        raise ValueError("--canary must be an approved, known-good MPTCP IPv4:port")
    ip = ipaddress.IPv4Address(parts[0])
    ports = parse_ports(parts[1])
    if len(ports) != 1 or not any(ip in scope for scope in scopes) or \
            ip.is_multicast or ip.is_unspecified or int(ip) == 0xFFFFFFFF:
        raise ValueError("--canary must be a single unicast IPv4:port within --allow scope")
    return str(ip), ports[0]


def build_targets(entries, scopes, max_hosts, resolver=None):
    """Resolve once, check every address against scope, connect to pinned literals."""
    resolver = resolver or socket.getaddrinfo
    addresses = {}
    issues = []

    def add(ip, label):
        if not any(ip in scope for scope in scopes):
            issues.append({"target": label, "ip": str(ip), "reason": "outside explicit --allow scope"})
            return
        if ip.is_multicast or ip.is_unspecified or int(ip) == 0xFFFFFFFF:
            issues.append({"target": label, "ip": str(ip), "reason": "not a unicast destination"})
            return
        value = str(ip)
        addresses.setdefault(value, set()).add(label)
        if len(addresses) > max_hosts:
            raise ValueError(f"Target expansion exceeds --max-hosts={max_hosts}; narrow the targets.")

    for entry in entries:
        entry = entry.strip()
        if "/" in entry:
            network = ipv4_network(entry)
            if network.num_addresses > max_hosts + 2:
                raise ValueError(f"CIDR {entry} exceeds --max-hosts={max_hosts}.")
            for ip in network.hosts():
                add(ip, entry)
            continue
        try:
            ip = ipaddress.ip_address(entry)
        except ValueError:
            if ":" in entry or "://" in entry:
                raise ValueError(f"Use a hostname or IPv4 address without a port or URL: {entry}")
            try:
                resolved = resolver(entry, None, socket.AF_INET, socket.SOCK_STREAM)
            except OSError as exc:
                issues.append({"target": entry, "reason": f"DNS resolution failed: {exc}"})
                continue
            for answer in resolved:
                add(ipaddress.IPv4Address(answer[4][0]), entry)
        else:
            if ip.version != 4:
                raise ValueError(f"IPv6 target is out of scope for this scanner: {entry}")
            add(ip, entry)
    return [(ip, ";".join(sorted(labels))) for ip, labels in addresses.items()], issues


def load_inventory(path):
    """Evidence must describe the actual TCP endpoint kernel, not a guessed backend."""
    if not path:
        return {}
    inventory = {}
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle, strict=True)
        if reader.fieldnames:
            reader.fieldnames = [name.strip().lower() for name in reader.fieldnames]
        required = {"ip", "port", "patch_status", "patch_evidence"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError("Inventory needs columns: ip,port,patch_status,patch_evidence; "
                             "optional: asset,owner")
        if len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError("Inventory has duplicate column headers")
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"Inventory line {reader.line_num}: column count does not match headers")
            try:
                ip = str(ipaddress.IPv4Address(row["ip"].strip()))
                port = int(row["port"])
            except ValueError as exc:
                raise ValueError(f"Inventory line {reader.line_num}: invalid IPv4 address or port") from exc
            status = row["patch_status"].strip().lower()
            if not 1 <= port <= 65535 or status not in {"unknown", "unpatched", "fixed"}:
                raise ValueError(f"Invalid inventory row: {ip}:{port}")
            evidence = row["patch_evidence"].strip()
            if status != "unknown" and not evidence:
                raise ValueError(f"Inventory {ip}:{port}: {status} requires patch_evidence")
            key = (ip, port)
            if key in inventory:
                raise ValueError(f"Duplicate inventory endpoint: {ip}:{port}")
            inventory[key] = {"asset": row.get("asset", "").strip(),
                              "owner": row.get("owner", "").strip(),
                              "patch_status": status, "patch_evidence": evidence}
    return inventory


def connect_with_timeout(conn, address, timeout, stop=None):
    """Normal nonblocking TCP connect, with bounded waits and cooperative cancellation."""
    if stop is not None and stop.is_set():
        return False
    conn.setblocking(False)
    code = conn.connect_ex(address)
    if code == 0:
        return True
    if code not in {errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, errno.EINTR}:
        raise OSError(code, os.strerror(code))
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as selector:
        selector.register(conn, selectors.EVENT_WRITE)
        while stop is None or not stop.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("TCP connect timeout")
            if selector.select(min(remaining, 0.1)):
                code = conn.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if code:
                    raise OSError(code, os.strerror(code))
                return True
    return False


def next_action(row):
    if row["patch_status"] == "unpatched":
        return "patch_running_kernel"  # Also true when MPTCP is not observed.
    if row["tcp_status"] != "open":
        return "resolve_reachability_gap"  # A closed port is not a kernel-patch assessment.
    if row["patch_status"] == "fixed":
        return "retain_inventory_fix_evidence"
    if row["mptcp_status"] == "observed":
        return "verify_endpoint_kernel_urgent"
    return "verify_endpoint_kernel"


def scan_endpoint(ip, target, port, mode, timeout, vantage, inventory, pacer=None):
    if pacer and not pacer.acquire():
        return None
    started = time.monotonic()
    row = dict.fromkeys(FIELDS, "")
    row.update(observed_at=utc_now(), vantage=vantage, target=target, ip=ip, port=port,
               tcp_status="error", mptcp_status="not_tested" if mode == "tcp" else "unknown",
               patch_status="unknown", self_probe=False)
    row.update(inventory.get((ip, port), {}))
    protocol = IPPROTO_MPTCP if mode == "mptcp" else socket.IPPROTO_TCP
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, protocol) as conn:
            if not connect_with_timeout(conn, (ip, port), timeout, pacer.stop if pacer else None):
                row.update(tcp_status="cancelled", evidence="connection attempt cancelled; outcome unknown")
            else:
                row["local_ip"] = conn.getsockname()[0]
                row["tcp_status"] = "open"
                if mode == "mptcp":
                    row["mptcp_status"], row["evidence"] = mptcp_state(conn)
                else:
                    row.update(mptcp_status="not_tested", evidence="ordinary TCP connect; MPTCP not requested")
    except (TimeoutError, socket.timeout):
        row.update(tcp_status="timeout", evidence="connect timed out; filtering, loss or reachability unknown")
    except ConnectionRefusedError:
        row.update(tcp_status="refused", evidence="TCP connection refused at this vantage")
    except OSError as exc:
        row.update(evidence=f"socket error {exc.errno}: {exc}")
    row["elapsed_ms"] = round((time.monotonic() - started) * 1000, 1)
    if mode == "mptcp" and row["mptcp_status"] == "not_observed" and row["elapsed_ms"] >= 1000:
        row["mptcp_status"] = "unknown"
        row["evidence"] += "; slow handshake: retransmission/client fallback may obscure negotiation"
    row["self_probe"] = ipaddress.IPv4Address(ip).is_loopback or row["local_ip"] == ip
    if row["self_probe"]:
        row["evidence"] += "; scanner-local/loopback observation"
    row["next_action"] = next_action(row)
    return row


class ConnectionPacer:
    def __init__(self, rate):
        self.interval = 1 / rate
        self.next_start = 0.0
        self.lock = threading.Lock()
        self.stop = threading.Event()

    def acquire(self):
        with self.lock:
            if self.stop.is_set():
                return False
            delay = self.next_start - time.monotonic()
            if delay > 0 and self.stop.wait(delay):
                return False
            self.next_start = time.monotonic() + self.interval
            return True


def run_scan(targets, ports, args, inventory, on_result, canary_check=None):
    """Bound queued work and pace connection starts globally, without burst catch-up."""
    jobs = iter((ip, label, port) for ip, label in targets for port in ports)
    pending = set()
    pacer = ConnectionPacer(args.rate)
    exhausted = False
    completed = 0
    if canary_check:
        canary_check(pacer)
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency)
    try:
        while pending or not exhausted:
            if not exhausted and len(pending) < args.concurrency:
                try:
                    ip, label, port = next(jobs)
                except StopIteration:
                    exhausted = True
                else:
                    pending.add(pool.submit(scan_endpoint, ip, label, port, args.mode,
                                            args.timeout, args.vantage, inventory, pacer))
            done = {future for future in pending if future.done()}
            if not done and pending and (exhausted or len(pending) >= args.concurrency):
                done, _ = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                pending.remove(future)
                row = future.result()
                if row is None:
                    continue
                on_result(row)
                completed += 1
                if canary_check and completed % 100 == 0:
                    canary_check(pacer)
        if canary_check:
            canary_check(pacer)
    except (KeyboardInterrupt, ScanStopped):
        pacer.stop.set()
        for future in pending:
            future.cancel()
        # Retain completed observations; queued/pacing/connect waits stop promptly.
        pool.shutdown(wait=True, cancel_futures=True)
        for future in pending:
            if not future.cancelled() and future.exception() is None:
                row = future.result()
                if row is not None:
                    on_result(row)
        raise
    finally:
        pacer.stop.set()
        pool.shutdown(wait=True, cancel_futures=True)


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("targets", nargs="*", help="IPv4, strict CIDR, or hostname")
    parser.add_argument("--targets-file", type=Path, help="One target per line; # comments allowed")
    parser.add_argument("--allow", action="append", default=[], metavar="CIDR",
                        help="Explicit authorized IPv4 CIDR; repeat for multiple ranges")
    parser.add_argument("--ports", default="22,80,443", help="Comma-separated ports/ranges")
    parser.add_argument("--mode", choices=["mptcp", "tcp"], default="mptcp")
    parser.add_argument("--rate", type=float, default=5, help="Max new connection attempts/sec (default 5)")
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=2)
    parser.add_argument("--max-hosts", type=int, default=4096)
    parser.add_argument("--max-probes", type=int, default=20000)
    parser.add_argument("--vantage", default=socket.gethostname(), help="e.g. public-linux-vm or prod-vpc")
    parser.add_argument("--inventory", type=Path, help="Optional verified endpoint-kernel evidence CSV")
    parser.add_argument("--canary", help="Known-good MPTCP IPv4:port in --allow scope; check before, every 100 results and after")
    parser.add_argument("--output", type=Path,
                        default=Path(datetime.now(timezone.utc).strftime("mptcp-audit-%Y%m%dT%H%M%SZ")),
                        help="New output directory (default: timestamped name)")
    parser.add_argument("--dry-run", action="store_true", help="Resolve/check scope and write plan; no target connections")
    parser.add_argument("--self-test", action="store_true", help="Only run local TCP/MPTCP controls")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if not math.isfinite(args.rate) or not 0 < args.rate <= 100:
            raise ValueError("--rate must be finite, greater than zero and at most 100")
        if not math.isfinite(args.timeout) or not 0 < args.timeout <= 30:
            raise ValueError("--timeout must be finite, greater than zero and at most 30 seconds")
        if not 1 <= args.concurrency <= 64 or args.max_hosts < 1 or args.max_probes < 1:
            raise ValueError("--concurrency must be 1..64; --max-hosts and --max-probes must be positive")
        if args.self_test:
            if args.mode != "mptcp":
                raise ValueError("--self-test checks MPTCP controls and requires --mode mptcp on Linux.")
            print(json.dumps(preflight(args.mode), indent=2))
            return 0
        if not args.allow:
            raise ValueError("Specify authorized IPv4 ranges with --allow CIDR (use /32 for a single IP).")
        scopes = [ipv4_network(item) for item in args.allow]
        canary = parse_canary(args.canary, scopes)
        if canary and args.mode != "mptcp":
            raise ValueError("--canary requires --mode mptcp")
        entries = list(args.targets)
        if args.targets_file:
            entries.extend(line.split("#", 1)[0].strip() for line in
                           args.targets_file.read_text(encoding="utf-8-sig").splitlines())
        entries = [item for item in entries if item]
        if not entries:
            raise ValueError("Provide targets or --targets-file.")
        ports = parse_ports(args.ports)
        targets, issues = build_targets(entries, scopes, args.max_hosts)
        if not targets:
            raise ValueError(f"No in-scope targets ({len(issues)} resolution/scope issues). "
                             f"First issue: {issues[0] if issues else 'none'}")
        probes = len(targets) * len(ports)
        if probes > args.max_probes:
            raise ValueError(f"{probes} probes exceeds --max-probes={args.max_probes}; narrow the scan.")
        inventory = load_inventory(args.inventory)
        planned_keys = {(ip, port) for ip, _ in targets for port in ports}
        inventory_not_scanned = [{"ip": ip, "port": port, **details}
                                 for (ip, port), details in inventory.items() if (ip, port) not in planned_keys]
        coverage_complete = not issues and not inventory_not_scanned
        metadata = {
            "tool": "mptcp_audit", "version": VERSION, "schema_version": 1, "cve": "CVE-2026-98432",
            "started_at": utc_now(), "vantage": args.vantage, "allow": args.allow,
            "mode": args.mode, "ports": ports, "planned_probes": probes,
            "rate": args.rate, "concurrency": args.concurrency, "timeout": args.timeout,
            "targets": [{"ip": ip, "target": label} for ip, label in targets],
            "scope_and_resolution_issues": issues, "complete": False,
            "probes_complete": False, "coverage_complete": coverage_complete,
            "inventory_not_scanned": inventory_not_scanned,
            "canary": args.canary, "canary_checks": [],
            "path_validation": "pending" if canary else "not_provided",
            "limitations": ["MPTCP support does not establish Linux or missing patches.",
                            "Negative/timeout results do not establish safety.",
                            "Results describe the visible TCP endpoint, not hidden backends.",
                            "No IP-header options, application payloads, or exploit probes are sent.",
                            "Rate bounds attempts, not OS retransmissions or MPTCP path-manager traffic."],
        }
        if not args.dry_run:
            metadata["local_controls"] = preflight(args.mode)
        metadata["mptcp_counters_start"] = read_mptcp_counters() if args.mode == "mptcp" and not args.dry_run else {}
        metadata["scanner_health"] = "no_detected_suppression" if metadata["mptcp_counters_start"] else "not_instrumented"
        args.output.mkdir(parents=True, mode=0o700, exist_ok=False)
        # Endpoint inventories may contain internal addresses and ownership details.
        os.chmod(args.output, 0o700)
        report_path = args.output / "run.json"
        write_json_atomic(report_path, metadata)
        print(f"Plan: {len(targets)} addresses x {len(ports)} ports = {probes} probes; "
              f"{len(issues)} DNS/scope issues. Output: {args.output}", file=sys.stderr)
        if inventory_not_scanned:
            print(f"Inventory gap: {len(inventory_not_scanned)} endpoint rows are outside this scan plan; "
                  "listed in run.json (also inventory-not-scanned.csv after a scan).", file=sys.stderr)
        for warning in metadata.get("local_controls", {}).get("path_manager", {}).get("warnings", []):
            print(f"Scanner configuration: {warning}", file=sys.stderr)
        for issue in issues[:10]:
            print(f"Skipped {issue['target']}: {issue['reason']}", file=sys.stderr)
        if len(issues) > 10:
            print("Further exclusions are listed in run.json.", file=sys.stderr)
        if args.dry_run:
            print("Dry run: no target connections made; DNS resolution may have occurred.", file=sys.stderr)
            return 3 if not coverage_complete else 0
        rows = []
        interrupted = False
        scan_error = None
        with open(args.output / "results.csv", "w", newline="", encoding="utf-8") as csv_handle, \
                open(args.output / "results.jsonl", "w", encoding="utf-8") as json_handle:
            writer = csv.DictWriter(csv_handle, fieldnames=FIELDS)
            writer.writeheader()

            def check_scanner_health():
                if args.mode != "mptcp":
                    return
                after = read_mptcp_counters()
                metadata["mptcp_counters_latest"] = after
                changes = suppression_deltas(metadata["mptcp_counters_start"], after)
                if changes and metadata["scanner_health"] != "failed":
                    metadata["scanner_health"] = "failed"
                    metadata["suppression_counter_changes"] = changes
                    raise ScanStopped("Scanner MPTCP suppression/blackhole counters increased. "
                                      "Run is inconclusive; inspect scanner/path before resuming.")

            def record(row):
                # Prevent inventory/hostname text from becoming formulas in spreadsheets.
                writer.writerow(spreadsheet_safe(row))
                csv_handle.flush()
                json_handle.write(json.dumps(row) + "\n")
                json_handle.flush()
                rows.append(row)
                if row["tcp_status"] == "open":
                    print(f"{row['ip']}:{row['port']} open MPTCP={row['mptcp_status']} "
                          f"patch={row['patch_status']} action={row['next_action']}", file=sys.stderr)
                if len(rows) % 50 == 0:
                    metadata["completed_probes"] = len(rows)
                    check_scanner_health()
                    write_json_atomic(report_path, metadata)
                    print(f"Progress: {len(rows)}/{probes} endpoint probes completed.", file=sys.stderr)

            def check_canary(pacer):
                ip, port = canary
                observation = scan_endpoint(ip, "known-good-MPTCP-canary", port, "mptcp",
                                            args.timeout, args.vantage, {}, pacer)
                metadata["canary_checks"].append(observation)
                if observation["mptcp_status"] != "observed":
                    metadata["path_validation"] = "failed"
                    raise CanaryFailure(f"MPTCP canary {ip}:{port} failed. Stop scan and investigate "
                                        "the scanner/path; negative observations are inconclusive.")
                metadata["path_validation"] = "passed_canary_only"

            try:
                run_scan(targets, ports, args, inventory, record,
                         check_canary if canary else None)
                check_scanner_health()
            except KeyboardInterrupt:
                interrupted = True
                print("Interrupted; retained completed results. Run is incomplete.", file=sys.stderr)
            except ScanStopped as exc:
                scan_error = str(exc)
                metadata["scan_error"] = scan_error
                print(scan_error, file=sys.stderr)
            finally:
                probe_errors = sum(row["tcp_status"] == "error" for row in rows)
                probes_complete = not interrupted and not scan_error and len(rows) == probes
                observed_keys = {(row["ip"], row["port"]) for row in rows}
                inventory_not_scanned = [{"ip": ip, "port": port, **details}
                                         for (ip, port), details in inventory.items()
                                         if (ip, port) not in observed_keys]
                coverage_complete = coverage_complete and not inventory_not_scanned
                metadata.update(finished_at=utc_now(), completed_probes=len(rows),
                                probes_complete=probes_complete,
                                inventory_not_scanned=inventory_not_scanned,
                                coverage_complete=coverage_complete,
                                complete=probes_complete and coverage_complete and not probe_errors)
                metadata["counts"] = {"open": sum(r["tcp_status"] == "open" for r in rows),
                                      "mptcp_observed": sum(r["mptcp_status"] == "observed" for r in rows),
                                      "known_unpatched_open": sum(r["tcp_status"] == "open" and
                                                                  r["patch_status"] == "unpatched" for r in rows),
                                      "probe_errors": probe_errors}
                metadata["counts"]["known_unpatched_any"] = sum(row["patch_status"] == "unpatched" for row in rows)
                metadata["counts"]["known_unpatched_inventory_not_scanned"] = sum(
                    row["patch_status"] == "unpatched" for row in inventory_not_scanned)
                metadata["counts"]["known_unpatched_any"] += metadata["counts"]["known_unpatched_inventory_not_scanned"]
                write_json_atomic(report_path, metadata)
        action_order = {"patch_running_kernel": 0, "verify_endpoint_kernel_urgent": 1,
                        "verify_endpoint_kernel": 2, "retain_inventory_fix_evidence": 3}
        unscanned_rows = []
        for item in inventory_not_scanned:
            row = dict.fromkeys(FIELDS, "")
            row.update(item, vantage=args.vantage, target=item["ip"], tcp_status="not_scanned",
                       mptcp_status="not_tested", self_probe=False,
                       evidence="Inventory endpoint has no network observation: outside plan or scan ended before attempt")
            row["next_action"] = next_action(row)
            unscanned_rows.append(row)
        with open(args.output / "inventory-not-scanned.csv", "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(spreadsheet_safe(row) for row in unscanned_rows)
        findings = sorted((row for row in rows + unscanned_rows
                           if row["tcp_status"] == "open" or row["patch_status"] == "unpatched"),
                          key=lambda row: (action_order[row["next_action"]],
                                           row["mptcp_status"] != "observed",
                                           int(ipaddress.IPv4Address(row["ip"])), row["port"]))
        with open(args.output / "triage.csv", "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(spreadsheet_safe(row) for row in findings)
        print(f"Finished: {len(rows)}/{probes} probes; {metadata['counts']['open']} open endpoints; "
              f"{len(findings)} triage rows. "
              f"{'Complete' if metadata['complete'] else 'Incomplete or contains coverage/errors; inspect run.json'}. "
              f"Triage: {args.output / 'triage.csv'}", file=sys.stderr)
        return 130 if interrupted else (2 if scan_error else (3 if not coverage_complete or probe_errors else 0))
    except KeyboardInterrupt:
        print("Interrupted during setup/output; any existing output may be partial.", file=sys.stderr)
        return 130
    except (ValueError, OSError, csv.Error, subprocess.TimeoutExpired) as exc:
        parser.exit(2, f"Error: {exc}\n")


if __name__ == "__main__":
    sys.exit(main())
