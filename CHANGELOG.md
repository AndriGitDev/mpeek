# Changelog

## 1.1.0 — release candidate

Initial release of mpeek for TCP/MPTCP exposure discovery and patch triage.

- Normal IPv4 TCP/MPTCP connection probes, with no application payloads or exploit attempts.
- Explicit CIDR scope, pinned DNS answers, and bounded connection pacing.
- Local calibration and optional operator-supplied MPTCP canaries.
- Patch inventory joins, including known-unpatched endpoints that were not reachable or scanned.
- CSV/JSON evidence, ordered triage, coverage gaps, and interruption recovery.
- Native macOS TCP reachability mode; MPTCP negotiation requires Linux.
- macOS/Linux CI, local loopback tests, MIT licensing, and reproducible source bundles.

MPTCP capability is not proof of a vulnerable kernel. Negative observations do
not clear an asset; authenticated host and vendor patch evidence remain necessary.
