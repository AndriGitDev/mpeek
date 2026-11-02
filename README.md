# mpeek

TCP/MPTCP exposure discovery for system administrators.

Version 1.1.0. Start with a dry run, then a small approved target list before
expanding to a subnet. Examples use documentation addresses; no organization-specific
targets or credentials are included. Start with [QUICKSTART.md](QUICKSTART.md).

Run `python3 mpeek.py --help` for options. The original `mptcp_audit.py` entry point
remains available with the same behavior. This repository is currently private;
an open-source license and public release have not yet been selected.

`mptcp_audit.py` inventories reachable IPv4 TCP endpoints and, on Linux, checks
whether an ordinary connection negotiated MPTCP. It sends no application payload,
IP-header options, malformed packets, or exploit attempts. No Python dependencies
or root privileges are required. Use Python 3.9 or newer. Linux MPTCP mode also
requires the `ip` tool from iproute2 for a read-only path-manager preflight.

**This is not a remote CVE-2026-98432 vulnerability detector.** MPTCP can exist on a
patched server or a non-Linux system. A TCP-only endpoint can still use an affected
Linux kernel. Firewall timeouts, path interference, a proxy, and load balancing can
hide capabilities. Scan results alone must never be recorded as "not vulnerable."

## Recommended workflow

1. Export authorized endpoint IPs and service ports from inventory. Include
   management services and known alternate origin routes, not just websites.
2. From an approved public vantage, scan the public endpoints. A scanner in a VPC
   establishes reachability from that VPC, not public internet exposure.
3. From an approved internal vantage, scan backend addresses that a terminating
   proxy hides. Identify the actual TCP endpoint at each hop.
4. Correlate every open endpoint with host/node inventory and current vendor fix
   evidence. Known unpatched ordinary TCP listeners also need patching.
5. Track SOC logger health, ingestion, and detection validation alongside the
   resulting patch queue. This scanner does not inspect the logger.

Use a **patched, dedicated Linux scanner** with working MPTCP support. Linux 5.16+
is recommended for the socket inspection interface, but both local calibration
controls must actually pass. A current supported, vendor-patched distribution is
preferable to choosing a kernel by upstream number alone.

## Running from macOS

macOS does not expose the Linux MPTCP socket API used here. For real MPTCP checks,
copy the script into a Linux VM or approved Linux host with network access. A
Linux container on macOS depends on the VM kernel's MPTCP support; the script
checks this rather than assuming it works. Verify VPN routing inside the VM.
Prefer bridged networking or a remote Linux host: a VM's userspace NAT/TCP proxy
may strip MPTCP negotiation even though local loopback controls pass.

On macOS you can explicitly use `--mode tcp` for reachability only; every open
endpoint will have `mptcp_status=not_tested`. There is no silent downgrade.

## Usage

First validate the Linux probe using loopback controls (one known MPTCP listener,
one ordinary TCP listener). This contacts only the local machine:

```bash
python3 mptcp_audit.py --self-test
```

Create `targets.txt` using approved addresses or hostnames, one per line. The
following are documentation examples; substitute your actual authorized scope:

```text
# Explicit hostnames or IPv4 addresses; CIDRs are also supported.
192.0.2.10
192.0.2.20
```

Preview a plan without connecting to targets (DNS resolution may occur):

```bash
python3 mptcp_audit.py --targets-file targets.txt \
  --allow 192.0.2.0/24 --ports 22,80,443,8443 \
  --vantage approved-public-vm --dry-run --output audit-plan
```

Run the scan into a new output directory:

```bash
python3 mptcp_audit.py --targets-file targets.txt \
  --allow 192.0.2.0/24 --ports 22,80,443,8443 \
  --rate 5 --concurrency 8 --timeout 2 \
  --vantage approved-public-vm --output audit-public
```

For an authorized internal range:

```bash
python3 mptcp_audit.py 10.20.30.0/24 \
  --allow 10.20.30.0/24 --ports 22,80,443,8080,8443 \
  --vantage approved-internal-vm --output audit-internal
```

For reachability only on the Mac, explicitly add `--mode tcp`.

If you already operate a known-good MPTCP listener along the relevant network
path, add `--canary 192.0.2.50:443` (and include its IP in `--allow`). The script
checks it before target probes, every 100 completed probes, and afterward, sharing
the same attempt-rate limit. A failed canary stops the scan, returns exit code 2,
and marks `run.json` incomplete. Results already recorded remain available.
`path_validation=passed_canary_only` validates that canary path, not every target
path; negatives still cannot prove absence. Without a canary the report records
`path_validation=not_provided` explicitly. Never use a third-party canary by default.

Repeat `--allow` for multiple approved CIDRs; use `/32` for a single IPv4 address.
Hostnames are resolved once to IPv4, every resolved IP is checked against the
allowlist, and the actual connection uses the pinned literal IP. Out-of-scope
answers and DNS failures are recorded in `run.json`, never silently scanned.
The script does not discover additional addresses or follow MPTCP address
announcements itself. It intentionally excludes IPv6 from this CVE-focused scan.

Defaults: 5 new attempts/second, 8 concurrent probes, 2-second connect timeout,
4,096 unique host addresses, and 20,000 probes maximum. The rate controls
application attempts, not packet count: the OS can retransmit SYNs and an existing
MPTCP path manager can initiate additional subflows. Use a dedicated scanner with
default/no extra path-manager endpoints if you need strictly single-path probing.
MPTCP mode refuses to scan unless the in-kernel path manager is selected and
`ip mptcp limits show` confirms `add_addr_accepted 0`; this prevents peer-announced
addresses from causing out-of-scope connections. The script changes no settings.
The preflight also records local endpoint configuration where permitted. It prints
configuration warnings when extra subflows remain permitted, endpoints are set,
or endpoint inspection is unavailable; single-path operation is not asserted.
It does not implement custom retries. Large/slow inventories may need a longer
timeout or separate explicitly selected follow-up runs.

The client kernel can fall back to TCP after SYN retransmissions, and blackhole
detection can temporarily suppress outgoing MPTCP within its network namespace.
The preflight records available fallback/blackhole sysctls without changing them.
Use the canary and a clean dedicated scanner; never interpret a run of negative
results as proof that targets lack MPTCP. This implementation records a single
handshake observation per endpoint, not a claim about later application traffic.
Slow handshakes (at least one second) without observed MPTCP are marked `unknown`
because retransmission fallback may obscure negotiation. Available `MPTcpExt`
counters are sampled before, every 50 results, and after a scan. Increases in
blackhole/SYN-TX suppression counters stop the run as inconclusive. Counter names
and visibility vary by kernel; missing counters are recorded as `not_instrumented`.
These counters cover the namespace and can reflect other applications, which is
another reason to use a dedicated scanner.

## Evidence and outputs

- `results.csv`: all attempted endpoints, suitable for SOC/patching inventory.
- `results.jsonl`: the same evidence without spreadsheet escaping.
- `triage.csv`: open endpoints plus all known-unpatched inventory endpoints,
  including refused, timed-out and unscanned ones, ordered by next action: unpatched first,
  then unknown patch status with MPTCP observed, other unknowns, then inventory-fixed.
  This ordering is an investigation queue, not a numerical risk assessment.
- `inventory-not-scanned.csv`: inventory endpoints outside the selected scan plan
  or left unattempted when a run ends early;
  these are reported, never added to the scan automatically.
- `run.json`: vantage, scope, pinned targets, controls, timestamps, counts,
  exclusions, and completion status. Reports are replaced atomically and progress
  is checkpointed every 50 completed probes. A dry run has `complete=false` because
  no scan was performed. A completed scan with scope/DNS exclusions, unmatched inventory, or probe errors
  also has `complete=false`; check `probes_complete` and `coverage_complete` for why.

Output directories default to a timestamped name and existing directories are
never overwritten. Ctrl-C stops queued probes and cancels pacing/connection waits,
preserving completed results and marking the run incomplete. A forced process kill
can leave `run.json` at its last checkpoint; CSV/JSONL contain flushed observations.

Exit codes: `0` completed without coverage/probe errors (or successful dry run),
`2` invalid input, failed preflight/canary, or an operational failure,
`3` scope/DNS exclusions, unmatched inventory, or probe errors requiring review, `130` interrupted.
Open/refused/timeout are observations, not proof of vulnerability or safety;
ordinary refused/timeouts do not by themselves make execution incomplete.
DNS lookup duration follows the system resolver; `--timeout` bounds TCP connects.
In `run.json`, `complete` refers to execution/coverage, not vulnerability assurance.

MPTCP evidence labels:

- `observed`: the client kernel confirms MPTCP on this connection.
- `not_observed`: MPTCP was not observed; fallback may be due to the client, path,
  or peer. This is not a statement that the target lacks MPTCP.
- `unknown`: timeout, refusal, error, or unconfirmed negotiation.
- `not_tested`: explicit ordinary TCP mode.

Scanner-local/loopback connections have `self_probe=true` and are labelled in
their evidence; these do not establish remote exposure. Probes cancelled after
starting are retained with `tcp_status=cancelled`; queued work stopped before
an attempt is not recorded as a network observation.

Each connection is closed after inspection. No banners, HTTP requests, TLS
handshakes, credentials, or remote commands are sent. Load balancers may select
different backends on other connections; one result does not characterize a pool.
Positive evidence identifies the visible endpoint's capability, not necessarily
the OS or MPTCP configuration of any backend behind it. A SYN proxy can also affect
what is visible. Kernel-generated protocol traffic remains possible on close.

## Optional verified inventory join

Copy `inventory.example.csv` and populate it with evidence for the **actual
visible TCP endpoint kernel**. Then add `--inventory inventory.csv` to the scan.
Do not attach a backend's patch status to an unrelated proxy/VIP. For a rotating
pool, use unknown unless evidence covers all eligible endpoint kernels.

Required columns: `ip,port,patch_status,patch_evidence`.
Optional columns: `asset,owner`.
Statuses: `unknown`, `unpatched`, `fixed`. Fixed and unpatched require evidence.
Use vendor advisory/package evidence for the **running** kernel or an applicable,
active livepatch, with an observation time. A new package awaiting reboot is not
evidence of a running fix. The script trusts these operator-supplied assertions;
it does not authenticate hosts or independently verify them.

`next_action` is deliberately evidence-based rather than a numerical risk score:

- Known unpatched: `patch_running_kernel`, regardless of reachability or MPTCP.
- Open + unknown patches + MPTCP observed: `verify_endpoint_kernel_urgent`.
- Other open + unknown patches: `verify_endpoint_kernel`.
- Open + inventory-confirmed fixed: `retain_inventory_fix_evidence`.
- Other not-open endpoints: `resolve_reachability_gap` (does not clear the host).

Unmatched inventory endpoints are listed in `run.json` even for a dry run. After
a scan, all unobserved known-unpatched entries also appear in `triage.csv` as
`tcp_status=not_scanned`; their patch evidence is from inventory, not a network
observation. Column headers are case-insensitive and tolerate surrounding spaces;
malformed rows and duplicate endpoints/headers produce explicit input errors.

Prioritize confirmed unpatched public listeners using service criticality and
blast radius; elevate confirmed MPTCP exposure within that queue. Never let a
capability-only candidate displace a confirmed unpatched TCP service automatically.

## Verification and sources

Run tests with `python3 -m unittest -v`. Integration tests create loopback TCP and
MPTCP listeners; MPTCP integration is skipped if the local controls cannot pass.
No external scan is performed by the tests.

- [Linux MPTCP socket API](https://docs.kernel.org/networking/mptcp.html)
- [MPTCP connection/fallback inspection](https://www.mptcp.dev/mptcp-info.html)
- [Linux UAPI flags and structure](https://github.com/torvalds/linux/blob/master/include/uapi/linux/mptcp.h)
- [Go Security Team: CVE scope and MPTCP limitations](https://www.openwall.com/lists/oss-security/2026/10/30/1)
- [AWS: forwarding versus terminating entry points](https://aws.amazon.com/security/security-bulletins/2026-160-aws/)
- [Red Hat: current patch/mitigation guidance](https://access.redhat.com/security/vulnerabilities/RHSB-2026-016)

Check vendor sources again when running the audit; patch status changes. Neither
packet filtering nor an installed logger establishes that a kernel is patched.
