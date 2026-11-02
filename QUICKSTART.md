# First run

Use mpeek version 1.1.0 from this repository. It contains no organization-specific
targets or credentials.
The scanner discovers TCP/MPTCP exposure; kernel patch status requires inventory
or authenticated host evidence. It never attempts exploitation.

1. Use a patched Linux VM or approved Linux host with access to the networks.
   Requirements: Python 3.9+ and iproute2 (`ip`). No Python packages or root are
   required for scanning. Verify VPN routing inside the VM. Native macOS supports
   only the explicit `--mode tcp` reachability mode.

2. Check the local scanner:

   ```bash
   python3 mpeek.py --version
   python3 mpeek.py --self-test
   ```

   Both local MPTCP and ordinary TCP controls must pass. Review configuration
   warnings. For enforced single-path operation, use a dedicated Linux namespace
   with no extra MPTCP endpoints and `subflows 0 add_addr_accepted 0`; the scanner
   does not change these settings. See README.md for path-manager limitations.

3. Put a small approved target list in `targets.txt`, one IPv4, hostname or strict
   CIDR per line. Start with a few known services, including one known MPTCP
   service if available. The following addresses are documentation examples:

   ```bash
   python3 mpeek.py --targets-file targets.txt \
     --allow 192.0.2.0/24 --ports 22,80,443,8443 \
     --vantage approved-public-vm --dry-run --output first-plan
   ```

   Replace the example scope with your authorized ranges. Repeat `--allow` as
   needed. Confirm pinned IPs, ports, and exclusions in `first-plan/run.json`.
   The dry run makes no target connections, though DNS resolution may occur.

4. Use the same arguments with a new output directory and without `--dry-run`:

   ```bash
   python3 mpeek.py --targets-file targets.txt \
     --allow 192.0.2.0/24 --ports 22,80,443,8443 \
     --vantage approved-public-vm --rate 5 --output first-scan
   ```

   Optionally add `--canary APPROVED_MPTCP_IP:PORT` to validate a known-good
   MPTCP endpoint on the relevant network path; include its IP in `--allow`.
   Optionally add `--inventory inventory.csv` using the included CSV template.

5. Inspect `run.json` first, then `triage.csv`, `results.csv`, and
   `inventory-not-scanned.csv`. Exit 3 means coverage/errors need review; exit 2
   means input, preflight, canary, scanner health, or another operational failure.
   Ctrl-C returns 130 and preserves available observations. A complete run is
   not a declaration that hosts are safe.

Scan both public entry points and authorized internal backends from appropriate
vantage points. A terminating NGINX proxy can hide backend MPTCP support. Confirm
each endpoint's actual kernel and vendor patch evidence before marking it fixed.
