# Contributing

Run `python3 -m unittest -v` before submitting changes. Tests use local loopback
listeners or mocks; they do not scan external networks. Linux MPTCP integration
tests require working local controls and iproute2. Those tests skip on macOS,
where TCP reachability mode is supported.

Keep scanner observations separate from inferred vulnerability and patch status.
New probes should preserve explicit scope, bounded traffic, clear evidence, and
interruption behavior. Include a regression test for material fixes.

Use synthetic or documentation addresses in examples and issues. Operational
target lists, inventories, credentials, scan output, and packet captures belong
outside the repository. Describe sensitive failures using a minimal reproducer.

See [SECURITY.md](SECURITY.md) for reporting a suspected vulnerability in mpeek.
