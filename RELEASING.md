# Preparing and publishing a release

The repository and release candidate remain private until the owner explicitly
chooses to publish them. No workflow changes visibility or publishes a release.

1. Run `python3 -m unittest -v` and confirm Linux/macOS CI is green for the exact
   commit being released. Linux CI also requires real MPTCP controls to pass.
2. Review the README's current vendor references and limitations. Confirm the
   version in `mptcp_audit.py` and `CHANGELOG.md` agrees with the intended tag.
3. Commit the source, then run `python3 scripts/build_release.py`. It refuses
   dirty tracked files by default and emits an allowlisted ZIP and checksum
   file into `dist/`. `--allow-dirty` is for local development checks only.
4. Verify the checksum and `MANIFEST.json` in the archive. Prepare a GitHub draft
   release targeting that exact commit and attach the ZIP and checksum. Include
   the distinction between MPTCP observation and kernel vulnerability in the notes.
5. Before public distribution, confirm the intended license, repository contents
   and history, and release notes. Enable GitHub private vulnerability reporting
   when supported. Publishing the repository/release is a separate owner action.

To inspect a bundle locally:

```bash
python3 scripts/build_release.py
python3 -m zipfile -t dist/mpeek-v1.1.0.zip
```

From `dist/`, verify the checksum with `sha256sum -c mpeek-v1.1.0.zip.sha256`
on Linux or `shasum -a 256 -c mpeek-v1.1.0.zip.sha256` on macOS.
