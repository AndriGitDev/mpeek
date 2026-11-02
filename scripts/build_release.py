#!/usr/bin/env python3
"""Build a deterministic, explicitly allowlisted mpeek source bundle."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from mptcp_audit import VERSION

FILES = (
    "mpeek.py", "mptcp_audit.py", "test_mptcp_audit.py", "inventory.example.csv",
    "README.md", "QUICKSTART.md", "LICENSE", "CHANGELOG.md", "CONTRIBUTING.md",
    "SECURITY.md", "RELEASING.md", "scripts/build_release.py",
)


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True,
                          text=True, timeout=10, check=True).stdout.strip()


def build(output, allow_dirty=False):
    tracked_dirty = bool(git("status", "--porcelain", "--untracked-files=no"))
    files_untracked = [name for name in FILES if not git("ls-files", "--", name)]
    if (tracked_dirty or files_untracked) and not allow_dirty:
        raise ValueError("Commit all release source files first, or use --allow-dirty for development only.")
    contents = {name: (ROOT / name).read_bytes() for name in FILES}
    manifest = {
        "name": "mpeek", "version": VERSION, "source_commit": git("rev-parse", "HEAD"),
        "development_build": tracked_dirty or bool(files_untracked),
        "files": {name: hashlib.sha256(content).hexdigest() for name, content in contents.items()},
    }
    contents["MANIFEST.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    archive_path = output / f"mpeek-v{VERSION}.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(contents.items()):
            info = zipfile.ZipInfo(f"mpeek-v{VERSION}/{name}", date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    checksum_path = archive_path.with_suffix(".zip.sha256")
    checksum_path.write_text(f"{digest}  {archive_path.name}\n", encoding="ascii")
    return archive_path, checksum_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    try:
        archive, checksum = build(args.output, args.allow_dirty)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(2, f"Build failed: {exc}\n")
    print(archive)
    print(checksum)


if __name__ == "__main__":
    main()
