#!/usr/bin/env python3
"""Build the dormant PaperDesk registry triggered-WebJob package deterministically."""

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
JOB_NAME = "paperdesk-accepted-release-registry"
PACKAGE_ROOT = f"App_Data/jobs/triggered/{JOB_NAME}"
FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
SOURCES = (
    (
        ROOT / "webjobs" / JOB_NAME / "run.sh",
        f"{PACKAGE_ROOT}/run.sh",
        0o755,
        4096,
    ),
    (
        ROOT / "scripts" / "accepted_release_registry.py",
        f"{PACKAGE_ROOT}/accepted_release_registry.py",
        0o644,
        2 * 1024 * 1024,
    ),
)


class PackageError(RuntimeError):
    """The immutable WebJob package contract was not met."""


def source_bytes(path: Path, maximum: int) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise PackageError(f"package source is not one regular non-link file: {path.name}")
    body = path.read_bytes()
    if not body or len(body) > maximum or b"\0" in body:
        raise PackageError(f"package source is empty or exceeds its bound: {path.name}")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PackageError(f"package source is not UTF-8 text: {path.name}") from exc
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def build(output: Path) -> dict[str, object]:
    output = output.resolve()
    if output.exists() or output.is_symlink():
        raise PackageError("output path must be unused")
    output.parent.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, object]] = []
    with tempfile.NamedTemporaryFile(
        prefix="paperdesk-registry-webjob-",
        suffix=".zip",
        dir=output.parent,
        delete=False,
    ) as handle:
        temporary = Path(handle.name)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED) as archive:
            for source, member, mode, maximum in SOURCES:
                body = source_bytes(source, maximum)
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
    package_digest = hashlib.sha256(output.read_bytes()).hexdigest()
    return {
        "schemaVersion": 1,
        "status": "built-dormant",
        "jobName": JOB_NAME,
        "packageSha256": package_digest,
        "files": records,
    }


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    root.add_argument("--output", required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        result = build(Path(args.output))
    except (OSError, PackageError, zipfile.BadZipFile) as exc:
        print(f"registry WebJob package error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
