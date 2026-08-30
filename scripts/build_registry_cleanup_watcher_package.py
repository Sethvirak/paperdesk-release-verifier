#!/usr/bin/env python3
"""Build the dormant deployable cleanup watcher package deterministically."""

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
CONTRACT_SHA256 = "3b7da11ea2677a5128fd0cc3a4a1dcc25a8f1e10957d6c00fd9ccccecb8ee4fc"
SOURCES = (
    (
        ROOT / "provider" / "registry_bridge_cleanup_watcher.py",
        "App_Data/jobs/continuous/paperdesk-registry-cleanup-watcher/registry_bridge_cleanup_watcher.py",
        0o644,
        512 * 1024,
    ),
    (
        ROOT / "provider" / "registry_bridge_cleanup_azure.py",
        "App_Data/jobs/continuous/paperdesk-registry-cleanup-watcher/registry_bridge_cleanup_azure.py",
        0o644,
        512 * 1024,
    ),
    (
        ROOT / "provider" / "registry_bridge_cleanup_runtime.py",
        "App_Data/jobs/continuous/paperdesk-registry-cleanup-watcher/registry_bridge_cleanup_runtime.py",
        0o644,
        128 * 1024,
    ),
    (
        ROOT / "contracts" / "registry_bridge_cleanup_contract.json",
        "App_Data/jobs/continuous/paperdesk-registry-cleanup-watcher/registry_bridge_cleanup_contract.json",
        0o644,
        128 * 1024,
    ),
    (
        ROOT / "webjobs" / "paperdesk-registry-cleanup-watcher" / "run.sh",
        "App_Data/jobs/continuous/paperdesk-registry-cleanup-watcher/run.sh",
        0o755,
        16 * 1024,
    ),
    (
        ROOT / "webjobs" / "paperdesk-registry-cleanup-watcher" / "settings.job",
        "App_Data/jobs/continuous/paperdesk-registry-cleanup-watcher/settings.job",
        0o644,
        4096,
    ),
)


class PackageError(RuntimeError):
    """The deterministic review-package boundary was not met."""


def duplicate_rejector(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PackageError("cleanup watcher contract contains a duplicate JSON key")
        result[key] = value
    return result


def source_bytes(path: Path, maximum: int) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise PackageError(f"watcher package source is not one regular non-link file: {path.name}")
    body = path.read_bytes()
    if not body or len(body) > maximum or b"\0" in body:
        raise PackageError(f"watcher package source is empty or exceeds its bound: {path.name}")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PackageError(f"watcher package source is not UTF-8: {path.name}") from exc
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def validate_contract(body: bytes) -> None:
    try:
        document = json.loads(body, object_pairs_hook=duplicate_rejector)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageError("cleanup watcher contract is not valid JSON") from exc
    if hashlib.sha256(body).hexdigest() != CONTRACT_SHA256:
        raise PackageError("cleanup watcher contract digest does not match the reviewed source")
    if (
        not isinstance(document, dict)
        or document.get("schemaVersion") != 1
        or document.get("contractId") != "paperdesk-registry-bridge-cleanup-watcher-v1"
        or document.get("immutableExternalControl", {}).get("mergedMutatingCommitSha") is not None
        or document.get("status") != "dormant-pending-independent-review-deployment-and-live-canary"
    ):
        raise PackageError("cleanup watcher contract is not safely dormant")


def validate_runner(body: bytes) -> None:
    text = body.decode("utf-8")
    required = (
        "set -euo pipefail",
        'WEBSITE_SITE_NAME:-',
        "paperdesk-registry-cleanup-watcher-9c4e0d0d",
        "python3 -I registry_bridge_cleanup_runtime.py --continuous",
    )
    if any(text.count(value) != 1 for value in required):
        raise PackageError("cleanup watcher runner is not the exact scheduled entry")
    for forbidden in ("curl ", "wget ", "az ", "--once", "http://", "https://"):
        if forbidden in text:
            raise PackageError("cleanup watcher runner expands the reviewed boundary")


def validate_settings(body: bytes) -> None:
    try:
        document = json.loads(body, object_pairs_hook=duplicate_rejector)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageError("cleanup watcher settings.job is invalid") from exc
    if document != {"is_singleton": True, "stopping_wait_time": 30}:
        raise PackageError("cleanup watcher settings.job is not the singleton contract")
    if body != b'{"is_singleton":true,"stopping_wait_time":30}\n':
        raise PackageError("cleanup watcher settings.job bytes are not canonical")


def build(output: Path) -> dict[str, object]:
    output = output.resolve()
    if output.exists() or output.is_symlink():
        raise PackageError("cleanup watcher package output path must be unused")
    output.parent.mkdir(parents=True, exist_ok=True)
    bodies: list[tuple[str, int, bytes]] = []
    for source, member, mode, maximum in SOURCES:
        body = source_bytes(source, maximum)
        if member.endswith("registry_bridge_cleanup_contract.json"):
            validate_contract(body)
        elif member.endswith("/run.sh"):
            validate_runner(body)
        elif member.endswith("/settings.job"):
            validate_settings(body)
        bodies.append((member, mode, body))
    records: list[dict[str, object]] = []
    with tempfile.NamedTemporaryFile(
        prefix="paperdesk-registry-cleanup-watcher-",
        suffix=".zip",
        dir=output.parent,
        delete=False,
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
        "appName": "paperdesk-registry-cleanup-watcher-9c4e0d0d",
        "transport": "independent-singleton-continuous-webjob",
        "publicHttpIngress": False,
        "mergedMutatingCommitSha": None,
        "packageSha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "files": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = build(Path(args.output))
    except (OSError, PackageError, zipfile.BadZipFile) as exc:
        print(f"registry cleanup watcher package error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
