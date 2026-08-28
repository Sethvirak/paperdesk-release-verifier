#!/usr/bin/env python3
"""Download and hash-check the exact CPython 3.12 manylinux2014 wheel set."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "provider" / "requirements.lock"
EXPECTED = {
    "pyjwt-2.13.0-py3-none-any.whl": "66adcc2aff09b3f1bbd95fc1e1577df8ac8723c978552fd43304c8a290ac5728",
    "cryptography-50.0.0-cp311-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.whl": "06a32a980526a6ab9a4b9bf8f7385800791e2bb960903cb6b530e4817509a3b7",
    "cffi-2.0.0-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl": "3e17ed538242334bf70832644a32a7aae3d83b57567f9fd60a26257e992b79ba",
    "pycparser-2.23-py3-none-any.whl": "e5c6e8d3fbad53479cab09ac03729e0a9faf2bee3db8208a550daf5af81a5934",
    "gunicorn-23.0.0-py3-none-any.whl": "ec400d38950de4dfd418cff8328b2c8faed0edb0d517d3394e457c317908ca4d",
    "packaging-24.2-py3-none-any.whl": "09abb1bccd265c01f4a3aa3f7a7db064b36514d2cba19a2f694fe6150451a759",
}


class LinuxLockError(RuntimeError):
    pass


def verify(directory: Path) -> dict[str, object]:
    files = sorted(path for path in directory.iterdir() if path.is_file())
    if {path.name for path in files} != set(EXPECTED):
        raise LinuxLockError(
            "downloaded Linux wheel inventory is not exact: "
            + ",".join(path.name for path in files)
        )
    records = []
    for path in files:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != EXPECTED[path.name]:
            raise LinuxLockError(f"Linux wheel digest differs: {path.name}")
        records.append({"filename": path.name, "sha256": digest, "size": path.stat().st_size})
    return {
        "schemaVersion": 1,
        "status": "linux-cpython-312-lock-verified",
        "platform": "manylinux2014_x86_64",
        "files": records,
    }


def download(directory: Path) -> None:
    command = [
        sys.executable,
        "-m",
        "pip",
        "download",
        "--disable-pip-version-check",
        "--dest",
        str(directory),
        "--platform",
        "manylinux2014_x86_64",
        "--python-version",
        "3.12",
        "--implementation",
        "cp",
        "--abi",
        "cp312",
        "--only-binary",
        ":all:",
        "--no-deps",
        "--require-hashes",
        "--requirement",
        str(LOCK),
    ]
    completed = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if completed.returncode != 0:
        raise LinuxLockError("pip could not resolve the exact hashed Linux wheel set")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-directory")
    args = parser.parse_args()
    try:
        if args.verify_directory:
            result = verify(Path(args.verify_directory).resolve())
        else:
            with tempfile.TemporaryDirectory(prefix="paperdesk-watchdog-linux-lock-") as temporary:
                directory = Path(temporary)
                download(directory)
                result = verify(directory)
    except (OSError, LinuxLockError) as exc:
        print(f"watchdog Linux lock error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
