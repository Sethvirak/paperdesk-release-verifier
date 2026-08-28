#!/usr/bin/env python3
"""Build the fixed PaperDesk watchdog provider source package deterministically."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
SOURCES = (
    (ROOT / "provider" / "__init__.py", "provider/__init__.py", 0o644, 4096),
    (ROOT / "provider" / "accepted_release_manifest.py", "provider/accepted_release_manifest.py", 0o644, 128 * 1024),
    (ROOT / "provider" / "runtime.py", "provider/runtime.py", 0o644, 128 * 1024),
    (ROOT / "provider" / "watchdog_state_provider.py", "provider/watchdog_state_provider.py", 0o644, 512 * 1024),
    (ROOT / "provider" / "wsgi.py", "provider/wsgi.py", 0o644, 128 * 1024),
    (ROOT / "scripts" / "accepted_release_registry.py", "scripts/accepted_release_registry.py", 0o644, 256 * 1024),
    (ROOT / "scripts" / "check_deadline.py", "scripts/check_deadline.py", 0o644, 256 * 1024),
    (ROOT / "scripts" / "watchdog_contract.py", "scripts/watchdog_contract.py", 0o644, 128 * 1024),
    (ROOT / "scripts" / "watchdog_evidence.py", "scripts/watchdog_evidence.py", 0o644, 512 * 1024),
    (ROOT / "contracts" / "production_release_watchdog_contract.json", "contracts/production_release_watchdog_contract.json", 0o644, 65536),
    (ROOT / "provider" / "requirements.lock", "requirements.txt", 0o644, 16384),
    (ROOT / "provider" / "startup.sh", "startup.sh", 0o755, 4096),
)
EXPECTED_DEPENDENCIES = {
    "PyJWT": ("2.13.0", "66adcc2aff09b3f1bbd95fc1e1577df8ac8723c978552fd43304c8a290ac5728"),
    "cryptography": ("50.0.0", "06a32a980526a6ab9a4b9bf8f7385800791e2bb960903cb6b530e4817509a3b7"),
    "cffi": ("2.0.0", "3e17ed538242334bf70832644a32a7aae3d83b57567f9fd60a26257e992b79ba"),
    "pycparser": ("2.23", "e5c6e8d3fbad53479cab09ac03729e0a9faf2bee3db8208a550daf5af81a5934"),
    "gunicorn": ("23.0.0", "ec400d38950de4dfd418cff8328b2c8faed0edb0d517d3394e457c317908ca4d"),
    "packaging": ("24.2", "09abb1bccd265c01f4a3aa3f7a7db064b36514d2cba19a2f694fe6150451a759"),
}


class PackageError(RuntimeError):
    """The deterministic provider package contract was not met."""


def source_bytes(path: Path, maximum: int) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise PackageError(f"provider package source is not one regular non-link file: {path.name}")
    body = path.read_bytes()
    if not body or len(body) > maximum or b"\0" in body:
        raise PackageError(f"provider package source is empty or exceeds its bound: {path.name}")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PackageError(f"provider package source is not UTF-8: {path.name}") from exc
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def validate_dependency_lock(body: bytes) -> None:
    text = body.decode("utf-8")
    if (
        text.count("--only-binary :all:") != 1
        or text.count("--require-hashes") != 1
        or "--extra-index-url" in text
        or "http:" in text
        or "https:" in text
    ):
        raise PackageError("provider dependency lock boundary is invalid")
    for name, (version, digest) in EXPECTED_DEPENDENCIES.items():
        if text.count(f"{name}=={version}") != 1 or text.count(f"--hash=sha256:{digest}") != 1:
            raise PackageError(f"provider dependency lock is not exact for {name}")
    if text.count("--hash=sha256:") != len(EXPECTED_DEPENDENCIES):
        raise PackageError("provider dependency lock contains an unexpected wheel hash")


def build(output: Path) -> dict[str, object]:
    output = output.resolve()
    if output.exists() or output.is_symlink():
        raise PackageError("provider package output path must be unused")
    output.parent.mkdir(parents=True, exist_ok=True)
    bodies: list[tuple[str, int, bytes]] = []
    for source, member, mode, maximum in SOURCES:
        body = source_bytes(source, maximum)
        if member == "requirements.txt":
            validate_dependency_lock(body)
        bodies.append((member, mode, body))
    records: list[dict[str, object]] = []
    with tempfile.NamedTemporaryFile(
        prefix="paperdesk-watchdog-provider-", suffix=".zip", dir=output.parent, delete=False
    ) as handle:
        temporary = Path(handle.name)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED) as archive:
            for member, mode, body in bodies:
                info = zipfile.ZipInfo(member, FIXED_TIMESTAMP)
                info.create_system = 3
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = (stat.S_IFREG | mode) << 16
                archive.writestr(info, body)
                records.append({
                    "path": member,
                    "size": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "mode": f"{mode:04o}",
                })
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "schemaVersion": 2,
        "status": "built-source-ready-activation-blocked",
        "appName": "paperdesk-watchdog-state-9c4e0d0d",
        "packageSha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "dependencies": [
            {"name": name, "version": value[0], "wheelSha256": value[1]}
            for name, value in EXPECTED_DEPENDENCIES.items()
        ],
        "files": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = build(Path(args.output))
    except (OSError, PackageError, zipfile.BadZipFile) as exc:
        print(f"watchdog provider package error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
