#!/usr/bin/env python3
"""Build and persist a bounded PaperDesk accepted-release registry request.

The build command runs on the immutable public-control runner. The serve command
runs only in the fixed, normally stopped registry bridge App Service. This file
uses only the Python standard library so the deployed bridge has no package
restore or third-party runtime dependency.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import gzip
import hashlib
import hmac
import http.client
import http.server
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import socketserver
import ssl
import sys
import tarfile
import tempfile
import threading
from typing import Any, BinaryIO
import urllib.error
import urllib.parse
import urllib.request
import zipfile


ACCOUNT = "mdspdbak2608089c4e"
CONTAINER = "paperdesk-accepted-releases"
STORAGE_RESOURCE_GROUP = "rg-paperdesk-rollback-sea-20260808"
BRIDGE_APP = "paperdesk-release-registry-bridge-9c4e0d0d"
BRIDGE_RESOURCE_GROUP = "rg-master-data-structure-sea"
ENVIRONMENT = "production"
BRIDGE_PATH = "/internal/v1/persist-accepted-release"
SCHEMA = "paperdesk-accepted-release-registry-request-v1"
MANIFEST_SCHEMA = "paperdesk-accepted-release-registry-manifest-v1"
MAX_REQUEST_BYTES = 1280 * 1024 * 1024
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_OTHER_FILE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 1200 * 1024 * 1024
MAX_MEMBERS = 21
STORAGE_API_VERSION = "2023-11-03"

SHA40 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
POSITIVE_INTEGER = re.compile(r"[1-9][0-9]*")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
IMMUTABLE_WORKFLOW_REF = re.compile(
    r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml@[0-9a-f]{40}"
)
PAPERDESK_SOURCE_WORKFLOW_REF = (
    "Sethvirak/MasterDataStructure/.github/workflows/"
    "main_master-data-structure-sea-9c4e0d0d.yml@refs/heads/main"
)
CONTENT_MD5 = re.compile(r"[A-Za-z0-9+/]{22}==")
ETAG = re.compile(r"[^\r\n]{1,256}")

RELEASE_MATERIAL_PATHS = (
    "architecture/production_acceptance_evidence_contract.json",
    "package-lock.json",
    "package.json",
    "widget-showcase/package-lock.json",
    "widget-showcase/package.json",
)
ACCEPTANCE_RECEIPT_FIELDS = {
    "acceptanceWorkflowHeadSha", "acceptedAt", "acceptedByRunId", "candidateCompletedAt",
    "candidateFinalizeDeadline", "candidateRunAttempt", "candidateRunId", "candidateRuntimeSha256",
    "candidateSha", "environmentId", "evidenceArtifactId", "evidenceBundleSha256",
    "evidenceContractSha256", "evidenceRunId", "releaseScope", "schemaVersion", "status",
}


class RegistryError(RuntimeError):
    """A fail-closed registry contract violation."""


def fail(message: str) -> None:
    raise RegistryError(message)


def canonical_json(document: Any) -> bytes:
    return (json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def md5_file(path: Path) -> str:
    digest = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return base64.b64encode(digest.digest()).decode("ascii")


def regular_file(path: Path, label: str, maximum: int = MAX_OTHER_FILE_BYTES) -> Path:
    if not path.is_file() or path.is_symlink():
        fail(f"{label} must be one regular non-link file")
    size = path.stat().st_size
    if size <= 0 or size > maximum:
        fail(f"{label} has an invalid size")
    return path


def read_json(path: Path, label: str, maximum: int = MAX_OTHER_FILE_BYTES) -> Any:
    try:
        return json.loads(regular_file(path, label, maximum).read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"{label} is not valid UTF-8 JSON: {exc}")


def positive(value: str, label: str) -> str:
    if not POSITIVE_INTEGER.fullmatch(value):
        fail(f"{label} must be a positive integer")
    return value


def full_sha(value: str, label: str) -> str:
    if not SHA40.fullmatch(value):
        fail(f"{label} must be a full lowercase Git commit")
    return value


def digest(value: str, label: str) -> str:
    value = value.removeprefix("sha256:")
    if not SHA256.fullmatch(value):
        fail(f"{label} must be a lowercase SHA-256")
    return value


def workflow_ref(value: str, label: str) -> str:
    if not IMMUTABLE_WORKFLOW_REF.fullmatch(value):
        fail(f"{label} must be a workflow ref pinned to a full lowercase commit")
    return value


def paperdesk_source_workflow_ref(value: str, label: str) -> str:
    if value != PAPERDESK_SOURCE_WORKFLOW_REF:
        fail(f"{label} must be the fixed protected-main workflow ref")
    return value


def utc_timestamp(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"{label} must be an ISO-8601 UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        fail(f"{label} must be an ISO-8601 UTC timestamp")
    if parsed.tzinfo != dt.timezone.utc:
        fail(f"{label} must be UTC")
    return value


def receipt_timestamp(value: str, label: str) -> dt.datetime:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", value):
        fail(f"{label} must be canonical millisecond ISO-8601 UTC")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        fail(f"{label} must be canonical millisecond ISO-8601 UTC")
    return parsed


def safe_relative(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        fail("unsafe registry relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        fail("unsafe registry relative path")
    normalized = path.as_posix()
    if normalized != value or len(value) > 512:
        fail("unsafe registry relative path")
    return value


def expected_verified_inventory(source_sha: str) -> dict[str, int]:
    archive = f"paperdesk-azure-runtime-{source_sha}.tar.gz"
    names = (
        archive,
        f"{archive}.sha256",
        f"paperdesk-azure-runtime-{source_sha}.acceptance-contract.json",
        f"paperdesk-azure-runtime-{source_sha}.cdx.json",
        f"paperdesk-azure-runtime-{source_sha}.package-input.json",
        f"paperdesk-azure-runtime-{source_sha}.provenance.json",
        f"paperdesk-azure-runtime-{source_sha}.root-package-lock.json",
        f"paperdesk-azure-runtime-{source_sha}.root-package.json",
        f"paperdesk-azure-runtime-{source_sha}.runtime-files.json",
        f"paperdesk-azure-runtime-{source_sha}.widget-package-lock.json",
        f"paperdesk-azure-runtime-{source_sha}.widget-package.json",
        f"paperdesk-azure-runtime-{source_sha}.widget.cdx.json",
    )
    result = {name: (MAX_ARCHIVE_BYTES if name == archive else MAX_OTHER_FILE_BYTES) for name in names}
    for relative in RELEASE_MATERIAL_PATHS:
        result[f"paperdesk-prebuild-release-materials/{relative}"] = MAX_OTHER_FILE_BYTES
    return result


def verified_files(root: Path, source_sha: str) -> dict[str, Path]:
    if not root.is_dir() or root.is_symlink():
        fail("verified artifact root must be one real directory")
    expected = expected_verified_inventory(source_sha)
    top_expected = {path.split("/", 1)[0] for path in expected}
    if {entry.name for entry in root.iterdir()} != top_expected:
        fail("verified artifact top-level inventory is not exact")
    materials = root / "paperdesk-prebuild-release-materials"
    material_directories: set[str] = set()
    for item in materials.rglob("*"):
        if item.is_symlink():
            fail("verified release-material inventory contains a link")
        if item.is_dir():
            material_directories.add(item.relative_to(materials).as_posix())
    material_entries = {
        item.relative_to(materials).as_posix()
        for item in materials.rglob("*")
        if item.is_file() and not item.is_symlink()
    }
    if material_entries != set(RELEASE_MATERIAL_PATHS) or material_directories != {"architecture", "widget-showcase"}:
        fail("verified release-material inventory is not exact")
    result: dict[str, Path] = {}
    for relative, maximum in expected.items():
        result[relative] = regular_file(root / Path(*PurePosixPath(relative).parts), f"verified file {relative}", maximum)
    archive = f"paperdesk-azure-runtime-{source_sha}.tar.gz"
    checksum = regular_file(root / f"{archive}.sha256", "archive checksum", 256).read_text(encoding="ascii")
    if checksum != f"{sha256_file(root / archive)}  {archive}\n":
        fail("verified artifact checksum is not exact")
    return result


def validate_worm_snapshot(snapshot: Any) -> dict[str, Any]:
    keys = {
        "resourceId", "storageAccount", "container", "state",
        "immutabilityPeriodSinceCreationInDays", "allowProtectedAppendWrites",
        "allowProtectedAppendWritesAll", "etag", "observedAt",
    }
    if not isinstance(snapshot, dict) or set(snapshot) != keys:
        fail("WORM snapshot fields are not exact")
    expected_suffix = (
        f"/resourceGroups/{STORAGE_RESOURCE_GROUP}/providers/Microsoft.Storage/storageAccounts/{ACCOUNT}"
        f"/blobServices/default/containers/{CONTAINER}/immutabilityPolicies/default"
    ).lower()
    resource_id = snapshot.get("resourceId")
    if not isinstance(resource_id, str) or not resource_id.lower().endswith(expected_suffix):
        fail("WORM snapshot resource is not the fixed registry immutability policy")
    if not re.fullmatch(r"/subscriptions/[0-9a-f-]{36}/resourceGroups/.+", resource_id, re.I):
        fail("WORM snapshot resource ID is invalid")
    expected = {
        "storageAccount": ACCOUNT,
        "container": CONTAINER,
        "state": "Locked",
        "immutabilityPeriodSinceCreationInDays": 30,
        "allowProtectedAppendWrites": False,
        "allowProtectedAppendWritesAll": False,
    }
    for key, value in expected.items():
        if snapshot.get(key) != value:
            fail("WORM snapshot does not prove the fixed locked policy")
    if not isinstance(snapshot.get("etag"), str) or not ETAG.fullmatch(snapshot["etag"]):
        fail("WORM snapshot ETag is invalid")
    utc_timestamp(snapshot.get("observedAt"), "WORM observation")
    return dict(snapshot)


def validate_receipts(
    verification: Any,
    acceptance: Any,
    *,
    source_sha: str,
    source_run_id: str,
    source_run_attempt: str,
    acceptance_run_id: str,
    evidence_run_id: str,
    evidence_artifact_id: str,
    evidence_bundle_sha256: str,
    evidence_contract_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(verification, dict):
        fail("candidate-verification receipt is invalid")
    required_verification = {
        "schemaVersion": 1,
        "status": "candidate-verified",
        "candidateSha": source_sha,
        "sourceRunId": source_run_id,
        "sourceRunAttempt": source_run_attempt,
        "verifiedArtifactName": f"paperdesk-azure-runtime-verified-{source_sha}",
        "verifierJob": "verify_candidate",
    }
    for key, value in required_verification.items():
        if verification.get(key) != value:
            fail(f"candidate-verification receipt field {key} is not exact")
    workflow_ref(str(verification.get("verifierWorkflow", "")), "verifier workflow")
    positive(str(verification.get("verifierRunId", "")), "verifier run ID")
    positive(str(verification.get("verifierRunAttempt", "")), "verifier run attempt")
    for field in (
        "archiveSha256", "inputManifestSha256", "runtimeManifestSha256",
        "releaseMaterialsSha256", "rootSbomSha256", "widgetSbomSha256", "provenanceSha256",
    ):
        digest(str(verification.get(field, "")), f"verification receipt {field}")

    if not isinstance(acceptance, dict) or set(acceptance) != ACCEPTANCE_RECEIPT_FIELDS:
        fail("production-acceptance receipt is invalid")
    required_acceptance = {
        "schemaVersion": 1,
        "status": "fully-accepted",
        "candidateSha": source_sha,
        "candidateRunId": source_run_id,
        "candidateRunAttempt": source_run_attempt,
        "candidateRuntimeSha256": verification.get("archiveSha256"),
        "acceptanceWorkflowHeadSha": source_sha,
        "acceptedByRunId": acceptance_run_id,
        "evidenceRunId": evidence_run_id,
        "evidenceArtifactId": evidence_artifact_id,
        "evidenceBundleSha256": evidence_bundle_sha256,
        "evidenceContractSha256": evidence_contract_sha256,
    }
    for key, value in required_acceptance.items():
        if acceptance.get(key) != value:
            fail(f"production-acceptance receipt field {key} is not exact")
    runtime_digest = digest(str(acceptance.get("candidateRuntimeSha256", "")), "acceptance candidate runtime digest")
    if runtime_digest != verification.get("archiveSha256"):
        fail("production-acceptance receipt runtime digest does not match external verification")
    for field in ("evidenceBundleSha256", "evidenceContractSha256"):
        digest(str(acceptance.get(field, "")), f"production-acceptance receipt {field}")
    completed = receipt_timestamp(acceptance.get("candidateCompletedAt"), "candidate completion")
    deadline = receipt_timestamp(acceptance.get("candidateFinalizeDeadline"), "candidate finalization deadline")
    accepted = receipt_timestamp(acceptance.get("acceptedAt"), "release acceptance")
    if deadline != completed + dt.timedelta(hours=24):
        fail("production-acceptance receipt deadline is not exactly 24 hours")
    if accepted < completed or accepted > deadline:
        fail("production-acceptance receipt timestamp is outside the candidate window")
    if accepted > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
        fail("production-acceptance receipt timestamp is too far in the future")
    if acceptance.get("releaseScope") not in ("controlled-non-ha-pilot", "full-production"):
        fail("production-acceptance receipt release scope is invalid")
    if not isinstance(acceptance.get("environmentId"), str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}", acceptance["environmentId"]
    ):
        fail("production-acceptance receipt environment ID is invalid")
    return dict(verification), dict(acceptance)


def file_record(path: Path, relative: str) -> dict[str, Any]:
    return {
        "path": safe_relative(relative),
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
        "contentMd5": md5_file(path),
    }


def add_tar_file(handle: tarfile.TarFile, source: Path, name: str) -> None:
    info = tarfile.TarInfo(name)
    info.size = source.stat().st_size
    info.mode = 0o600
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    with source.open("rb") as stream:
        handle.addfile(info, stream)


def write_request_archive(output: Path, request: dict[str, Any], files: dict[str, Path]) -> None:
    if output.exists():
        fail("registry request output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    request_bytes = canonical_json(request)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                info = tarfile.TarInfo("request.json")
                info.size = len(request_bytes)
                info.mode = 0o600
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                archive.addfile(info, io.BytesIO(request_bytes))
                for relative in sorted(files):
                    add_tar_file(archive, files[relative], f"payload/{relative}")
    if output.stat().st_size > MAX_REQUEST_BYTES:
        output.unlink(missing_ok=True)
        fail("registry request archive exceeds the fixed bound")


def build_request(args: argparse.Namespace) -> dict[str, Any]:
    source_sha = full_sha(args.source_sha, "source SHA")
    source_run_id = positive(args.source_run_id, "source run ID")
    source_run_attempt = positive(args.source_run_attempt, "source run attempt")
    acceptance_run_id = positive(args.acceptance_run_id, "acceptance run ID")
    acceptance_run_attempt = positive(args.acceptance_run_attempt, "acceptance run attempt")
    acceptance_ref = workflow_ref(args.acceptance_workflow_ref, "acceptance workflow")
    if acceptance_ref.split("@", 1)[1] != source_sha:
        fail("acceptance workflow is not pinned to the candidate SHA")
    evidence_run_id = positive(args.evidence_run_id, "evidence run ID")
    evidence_run_attempt = positive(args.evidence_run_attempt, "evidence run attempt")
    if len({source_run_id, acceptance_run_id, evidence_run_id}) != 3:
        fail("source, acceptance, and evidence runs must be distinct")
    evidence_digest = digest(args.evidence_bundle_sha256, "evidence bundle digest")
    verified_artifact_digest = digest(args.verified_artifact_digest, "verified artifact digest")
    verification_artifact_digest = digest(args.verification_artifact_digest, "verification artifact digest")
    acceptance_artifact_digest = digest(args.acceptance_artifact_digest, "acceptance artifact digest")
    for value, label in (
        (args.verified_artifact_id, "verified artifact ID"),
        (args.verification_artifact_id, "verification artifact ID"),
        (args.acceptance_artifact_id, "acceptance artifact ID"),
        (args.evidence_artifact_id, "evidence artifact ID"),
    ):
        positive(value, label)

    verified_root = Path(args.verified_artifact_dir).resolve()
    source_files = verified_files(verified_root, source_sha)
    verification_path = Path(args.verification_receipt).resolve()
    acceptance_path = Path(args.acceptance_receipt).resolve()
    expected_verification_name = f"paperdesk-candidate-verification-receipt-{source_sha}.json"
    expected_acceptance_name = f"paperdesk-production-acceptance-receipt-{source_sha}.json"
    if verification_path.name != expected_verification_name or acceptance_path.name != expected_acceptance_name:
        fail("receipt file names are not exact")
    verification = read_json(verification_path, "candidate-verification receipt", 8192)
    acceptance = read_json(acceptance_path, "production-acceptance receipt", 65536)
    worm_snapshot = validate_worm_snapshot(read_json(Path(args.worm_snapshot).resolve(), "live WORM snapshot", 8192))
    acceptance_contract_name = f"paperdesk-azure-runtime-{source_sha}.acceptance-contract.json"
    evidence_contract_sha256 = sha256_file(source_files[acceptance_contract_name])
    verification, acceptance = validate_receipts(
        verification,
        acceptance,
        source_sha=source_sha,
        source_run_id=source_run_id,
        source_run_attempt=source_run_attempt,
        acceptance_run_id=acceptance_run_id,
        evidence_run_id=evidence_run_id,
        evidence_artifact_id=args.evidence_artifact_id,
        evidence_bundle_sha256=evidence_digest,
        evidence_contract_sha256=evidence_contract_sha256,
    )

    provenance_name = f"paperdesk-azure-runtime-{source_sha}.provenance.json"
    provenance = read_json(source_files[provenance_name], "candidate provenance")
    if not isinstance(provenance, dict):
        fail("candidate provenance is invalid")
    if provenance.get("commit") != source_sha or provenance.get("repository") != "Sethvirak/MasterDataStructure":
        fail("candidate provenance identity is not exact")
    if str(provenance.get("runId")) != source_run_id or str(provenance.get("runAttempt")) != source_run_attempt:
        fail("candidate provenance run binding is not exact")
    source_workflow_ref = paperdesk_source_workflow_ref(str(provenance.get("workflow", "")), "source workflow")

    payload: dict[str, Path] = {f"verified-artifact/{relative}": path for relative, path in source_files.items()}
    payload[f"receipts/{expected_verification_name}"] = regular_file(verification_path, "candidate-verification receipt", 8192)
    payload[f"receipts/{expected_acceptance_name}"] = regular_file(acceptance_path, "production-acceptance receipt", 65536)
    records = [file_record(payload[relative], relative) for relative in sorted(payload)]
    total = sum(record["size"] for record in records)
    if len(records) != 19 or total > MAX_EXPANDED_BYTES:
        fail("accepted-release payload inventory or expanded size is invalid")

    request = {
        "schema": SCHEMA,
        "environment": ENVIRONMENT,
        "registry": {
            "storageAccount": ACCOUNT,
            "container": CONTAINER,
            "bridgeApp": BRIDGE_APP,
            "bridgeResourceGroup": BRIDGE_RESOURCE_GROUP,
            "prefix": f"v1/releases/{source_sha}/{source_run_id}/{acceptance_run_id}/",
        },
        "candidate": {
            "repository": "Sethvirak/MasterDataStructure",
            "sha": source_sha,
            "runId": source_run_id,
            "runAttempt": source_run_attempt,
            "workflowRef": source_workflow_ref,
        },
        "acceptance": {
            "runId": acceptance_run_id,
            "runAttempt": acceptance_run_attempt,
            "workflowRef": acceptance_ref,
            "acceptedAt": acceptance["acceptedAt"],
            "candidateCompletedAt": acceptance["candidateCompletedAt"],
            "candidateFinalizeDeadline": acceptance["candidateFinalizeDeadline"],
            "candidateRuntimeSha256": acceptance["candidateRuntimeSha256"],
            "evidenceContractSha256": acceptance["evidenceContractSha256"],
            "releaseScope": acceptance["releaseScope"],
            "environmentId": acceptance["environmentId"],
        },
        "evidence": {
            "runId": evidence_run_id,
            "runAttempt": evidence_run_attempt,
            "artifactId": args.evidence_artifact_id,
            "artifactName": args.evidence_artifact_name,
            "bundleSha256": evidence_digest,
        },
        "artifacts": {
            "verified": {
                "id": args.verified_artifact_id,
                "name": f"paperdesk-azure-runtime-verified-{source_sha}",
                "digest": verified_artifact_digest,
            },
            "verificationReceipt": {
                "id": args.verification_artifact_id,
                "name": f"paperdesk-candidate-verification-receipt-{source_sha}",
                "digest": verification_artifact_digest,
                "fileSha256": sha256_file(verification_path),
            },
            "productionAcceptanceReceipt": {
                "id": args.acceptance_artifact_id,
                "name": f"paperdesk-production-acceptance-receipt-{source_sha}",
                "digest": acceptance_artifact_digest,
                "fileSha256": sha256_file(acceptance_path),
            },
        },
        "verifier": {
            "workflowRef": verification["verifierWorkflow"],
            "job": verification["verifierJob"],
            "runId": verification["verifierRunId"],
            "runAttempt": verification["verifierRunAttempt"],
        },
        "wormSnapshot": worm_snapshot,
        "files": records,
    }
    write_request_archive(Path(args.output).resolve(), request, payload)
    return {
        "requestSha256": sha256_file(Path(args.output).resolve()),
        "prefix": request["registry"]["prefix"],
        "fileCount": len(records),
        "expandedBytes": total,
    }


def safe_extract_actions_zip(archive_path: Path, output: Path) -> None:
    regular_file(archive_path, "Actions artifact archive", MAX_REQUEST_BYTES)
    if output.exists():
        fail("Actions artifact extraction target already exists")
    output.mkdir(parents=True, mode=0o700)
    count = 0
    total = 0
    seen: set[str] = set()
    try:
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                count += 1
                if count > 100000:
                    fail("Actions artifact member count is excessive")
                relative = safe_relative(info.filename.rstrip("/"))
                if relative in seen:
                    fail("Actions artifact contains a duplicate path")
                seen.add(relative)
                mode = (info.external_attr >> 16) & 0o170000
                if mode not in (0, 0o040000, 0o100000):
                    fail("Actions artifact contains a special or linked member")
                target = output / Path(*PurePosixPath(relative).parts)
                resolved = target.resolve()
                if output.resolve() not in resolved.parents and resolved != output.resolve():
                    fail("Actions artifact path escapes its target")
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                total += info.file_size
                if info.file_size > MAX_ARCHIVE_BYTES or total > MAX_EXPANDED_BYTES:
                    fail("Actions artifact expanded size is excessive")
                target.parent.mkdir(parents=True, exist_ok=True)
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with archive.open(info) as source, os.fdopen(descriptor, "wb") as sink:
                    shutil.copyfileobj(source, sink, 1024 * 1024)
                if target.stat().st_size != info.file_size:
                    fail("Actions artifact member size changed during extraction")
    except Exception:
        shutil.rmtree(output, ignore_errors=True)
        raise


def extract_request(archive_path: Path, output: Path) -> tuple[dict[str, Any], dict[str, Path]]:
    regular_file(archive_path, "registry request", MAX_REQUEST_BYTES)
    if output.exists():
        fail("request extraction target already exists")
    output.mkdir(parents=True, mode=0o700)
    seen: set[str] = set()
    total = 0
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            for member in archive:
                if len(seen) >= MAX_MEMBERS:
                    fail("registry request member count is excessive")
                relative = safe_relative(member.name)
                if relative in seen:
                    fail("registry request contains a duplicate path")
                seen.add(relative)
                if not member.isfile() or member.issym() or member.islnk() or member.isdev():
                    fail("registry request contains a non-regular member")
                total += member.size
                if member.size <= 0 or member.size > MAX_ARCHIVE_BYTES or total > MAX_EXPANDED_BYTES:
                    fail("registry request expanded size is invalid")
                target = output / Path(*PurePosixPath(relative).parts)
                resolved = target.resolve()
                if output.resolve() not in resolved.parents:
                    fail("registry request member escapes its target")
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                if stream is None:
                    fail("registry request member cannot be read")
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with stream, os.fdopen(descriptor, "wb") as sink:
                    shutil.copyfileobj(stream, sink, 1024 * 1024)
                if target.stat().st_size != member.size:
                    fail("registry request member size changed during extraction")
        if "request.json" not in seen:
            fail("registry request metadata is missing")
        request = read_json(output / "request.json", "registry request metadata", 1024 * 1024)
        files = validate_request(request, output)
        if seen != {"request.json", *(f"payload/{relative}" for relative in files)}:
            fail("registry request archive inventory is not exact")
        return request, files
    except Exception:
        shutil.rmtree(output, ignore_errors=True)
        raise


def validate_request(request: Any, root: Path) -> dict[str, Path]:
    keys = {"schema", "environment", "registry", "candidate", "acceptance", "evidence", "artifacts", "verifier", "wormSnapshot", "files"}
    if not isinstance(request, dict) or set(request) != keys or request.get("schema") != SCHEMA:
        fail("registry request fields or schema are not exact")
    if request.get("environment") != ENVIRONMENT:
        fail("registry request environment is invalid")
    candidate = request.get("candidate")
    acceptance = request.get("acceptance")
    registry = request.get("registry")
    if not isinstance(candidate, dict) or not isinstance(acceptance, dict) or not isinstance(registry, dict):
        fail("registry request coordinates are invalid")
    if set(candidate) != {"repository", "sha", "runId", "runAttempt", "workflowRef"}:
        fail("registry request candidate fields are not exact")
    if set(acceptance) != {
        "runId", "runAttempt", "workflowRef", "acceptedAt", "candidateCompletedAt",
        "candidateFinalizeDeadline", "candidateRuntimeSha256", "evidenceContractSha256",
        "releaseScope", "environmentId",
    }:
        fail("registry request acceptance fields are not exact")
    source_sha = full_sha(str(candidate.get("sha", "")), "request source SHA")
    source_run_id = positive(str(candidate.get("runId", "")), "request source run ID")
    acceptance_run_id = positive(str(acceptance.get("runId", "")), "request acceptance run ID")
    expected_registry = {
        "storageAccount": ACCOUNT,
        "container": CONTAINER,
        "bridgeApp": BRIDGE_APP,
        "bridgeResourceGroup": BRIDGE_RESOURCE_GROUP,
        "prefix": f"v1/releases/{source_sha}/{source_run_id}/{acceptance_run_id}/",
    }
    if registry != expected_registry:
        fail("registry request does not use the fixed registry resource and prefix")
    if candidate.get("repository") != "Sethvirak/MasterDataStructure":
        fail("registry request repository is invalid")
    source_ref = paperdesk_source_workflow_ref(str(candidate.get("workflowRef", "")), "request source workflow")
    source_run_attempt = positive(str(candidate.get("runAttempt", "")), "request source run attempt")
    acceptance_ref = workflow_ref(str(acceptance.get("workflowRef", "")), "request acceptance workflow")
    acceptance_run_attempt = positive(str(acceptance.get("runAttempt", "")), "request acceptance run attempt")
    if acceptance_ref.split("@", 1)[1] != source_sha:
        fail("registry request acceptance workflow is not pinned to the candidate SHA")
    worm_snapshot = validate_worm_snapshot(request.get("wormSnapshot"))

    evidence = request.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != {"runId", "runAttempt", "artifactId", "artifactName", "bundleSha256"}:
        fail("registry request evidence fields are not exact")
    evidence_run_id = positive(str(evidence.get("runId", "")), "request evidence run ID")
    evidence_run_attempt = positive(str(evidence.get("runAttempt", "")), "request evidence run attempt")
    positive(str(evidence.get("artifactId", "")), "request evidence artifact ID")
    evidence_digest = digest(str(evidence.get("bundleSha256", "")), "request evidence bundle digest")
    if not isinstance(evidence.get("artifactName"), str) or not re.fullmatch(
        rf"paperdesk-production-acceptance-evidence-post-deploy-{source_sha}", evidence["artifactName"]
    ):
        fail("registry request evidence artifact name is not exact")
    if len({source_run_id, acceptance_run_id, evidence_run_id}) != 3:
        fail("registry request source, acceptance, and evidence runs must be distinct")

    artifacts = request.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != {"verified", "verificationReceipt", "productionAcceptanceReceipt"}:
        fail("registry request artifact fields are not exact")
    expected_artifact_names = {
        "verified": f"paperdesk-azure-runtime-verified-{source_sha}",
        "verificationReceipt": f"paperdesk-candidate-verification-receipt-{source_sha}",
        "productionAcceptanceReceipt": f"paperdesk-production-acceptance-receipt-{source_sha}",
    }
    for label, expected_name in expected_artifact_names.items():
        artifact = artifacts.get(label)
        expected_keys = {"id", "name", "digest"} | ({"fileSha256"} if label != "verified" else set())
        if not isinstance(artifact, dict) or set(artifact) != expected_keys:
            fail(f"registry request {label} artifact fields are not exact")
        positive(str(artifact.get("id", "")), f"request {label} artifact ID")
        if artifact.get("name") != expected_name:
            fail(f"registry request {label} artifact name is not exact")
        digest(str(artifact.get("digest", "")), f"request {label} artifact digest")
        if label != "verified":
            digest(str(artifact.get("fileSha256", "")), f"request {label} receipt digest")

    verifier = request.get("verifier")
    if not isinstance(verifier, dict) or set(verifier) != {"workflowRef", "job", "runId", "runAttempt"}:
        fail("registry request verifier fields are not exact")
    workflow_ref(str(verifier.get("workflowRef", "")), "request verifier workflow")
    if verifier.get("job") != "verify_candidate":
        fail("registry request verifier job is invalid")
    positive(str(verifier.get("runId", "")), "request verifier run ID")
    positive(str(verifier.get("runAttempt", "")), "request verifier run attempt")
    records = request.get("files")
    if not isinstance(records, list) or len(records) != 19:
        fail("registry request file inventory count is invalid")
    files: dict[str, Path] = {}
    total = 0
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "size", "sha256", "contentMd5"}:
            fail("registry request file record fields are not exact")
        relative = safe_relative(record.get("path"))
        if relative in files:
            fail("registry request file path is duplicated")
        if not isinstance(record.get("size"), int) or record["size"] <= 0:
            fail("registry request file size is invalid")
        digest(str(record.get("sha256", "")), "registry request file digest")
        if not isinstance(record.get("contentMd5"), str) or not CONTENT_MD5.fullmatch(record["contentMd5"]):
            fail("registry request file Content-MD5 is invalid")
        path = regular_file(root / "payload" / Path(*PurePosixPath(relative).parts), f"request payload {relative}", MAX_ARCHIVE_BYTES)
        if path.stat().st_size != record["size"] or sha256_file(path) != record["sha256"] or md5_file(path) != record["contentMd5"]:
            fail("registry request payload bytes do not match the inventory")
        total += record["size"]
        files[relative] = path
    if total > MAX_EXPANDED_BYTES:
        fail("registry request payload is too large")
    expected_payload = {f"verified-artifact/{relative}" for relative in expected_verified_inventory(source_sha)}
    expected_payload |= {
        f"receipts/paperdesk-candidate-verification-receipt-{source_sha}.json",
        f"receipts/paperdesk-production-acceptance-receipt-{source_sha}.json",
    }
    if set(files) != expected_payload:
        fail("registry request preserved-file inventory is not exact")

    verification_path = files[f"receipts/paperdesk-candidate-verification-receipt-{source_sha}.json"]
    acceptance_path = files[f"receipts/paperdesk-production-acceptance-receipt-{source_sha}.json"]
    if sha256_file(verification_path) != artifacts["verificationReceipt"]["fileSha256"]:
        fail("registry request verification-receipt digest binding is invalid")
    if sha256_file(acceptance_path) != artifacts["productionAcceptanceReceipt"]["fileSha256"]:
        fail("registry request acceptance-receipt digest binding is invalid")
    verification = read_json(verification_path, "request candidate-verification receipt", 8192)
    production_acceptance = read_json(acceptance_path, "request production-acceptance receipt", 65536)
    validate_receipts(
        verification,
        production_acceptance,
        source_sha=source_sha,
        source_run_id=source_run_id,
        source_run_attempt=source_run_attempt,
        acceptance_run_id=acceptance_run_id,
        evidence_run_id=evidence_run_id,
        evidence_artifact_id=evidence["artifactId"],
        evidence_bundle_sha256=evidence_digest,
        evidence_contract_sha256=sha256_file(
            files[f"verified-artifact/paperdesk-azure-runtime-{source_sha}.acceptance-contract.json"]
        ),
    )
    if verifier != {
        "workflowRef": verification["verifierWorkflow"],
        "job": verification["verifierJob"],
        "runId": verification["verifierRunId"],
        "runAttempt": verification["verifierRunAttempt"],
    }:
        fail("registry request verifier does not match the candidate receipt")
    expected_acceptance = {
        "runId": production_acceptance["acceptedByRunId"],
        "runAttempt": acceptance_run_attempt,
        "workflowRef": acceptance_ref,
        "acceptedAt": production_acceptance["acceptedAt"],
        "candidateCompletedAt": production_acceptance["candidateCompletedAt"],
        "candidateFinalizeDeadline": production_acceptance["candidateFinalizeDeadline"],
        "candidateRuntimeSha256": production_acceptance["candidateRuntimeSha256"],
        "evidenceContractSha256": production_acceptance["evidenceContractSha256"],
        "releaseScope": production_acceptance["releaseScope"],
        "environmentId": production_acceptance["environmentId"],
    }
    if acceptance != expected_acceptance:
        fail("registry request acceptance metadata does not match the production receipt")
    validate_worm_snapshot(worm_snapshot)
    provenance_path = files[f"verified-artifact/paperdesk-azure-runtime-{source_sha}.provenance.json"]
    provenance = read_json(provenance_path, "request candidate provenance")
    if not isinstance(provenance, dict) or any((
        provenance.get("commit") != source_sha,
        provenance.get("repository") != candidate["repository"],
        str(provenance.get("runId")) != source_run_id,
        str(provenance.get("runAttempt")) != source_run_attempt,
        provenance.get("workflow") != source_ref,
    )):
        fail("registry request candidate provenance binding is invalid")
    return files


def identity_token(client_id: str) -> str:
    if not UUID.fullmatch(client_id):
        fail("bridge managed-identity client ID is invalid")
    endpoint = os.environ.get("IDENTITY_ENDPOINT", "")
    header = os.environ.get("IDENTITY_HEADER", "")
    if not endpoint.startswith("http://") or not header or "\r" in header or "\n" in header:
        fail("App Service managed-identity endpoint is unavailable")
    query = urllib.parse.urlencode({
        "api-version": "2019-08-01",
        "resource": "https://storage.azure.com/",
        "client_id": client_id,
    })
    request = urllib.request.Request(f"{endpoint}?{query}", headers={"X-IDENTITY-HEADER": header})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            document = json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        fail(f"managed-identity token acquisition failed: {exc}")
    token = document.get("access_token") if isinstance(document, dict) else None
    if not isinstance(token, str) or len(token) < 100 or "\r" in token or "\n" in token:
        fail("managed-identity token response is invalid")
    return token


def blob_url(blob_name: str, prefix: str) -> str:
    if not blob_name.startswith(prefix) or blob_name == prefix or "//" in blob_name:
        fail("blob name escapes the accepted-release prefix")
    safe_relative(blob_name)
    encoded = "/".join(urllib.parse.quote(part, safe="") for part in PurePosixPath(blob_name).parts)
    return f"/{CONTAINER}/{encoded}"


class StorageClient:
    def __init__(self, writer_token: str, reader_token: str):
        self.writer_token = writer_token
        self.reader_token = reader_token
        self.host = f"{ACCOUNT}.blob.core.windows.net"

    def _connection(self) -> http.client.HTTPSConnection:
        return http.client.HTTPSConnection(self.host, timeout=900, context=ssl.create_default_context())

    def get(self, blob_name: str, prefix: str, maximum: int) -> tuple[int, bytes, dict[str, str]]:
        connection = self._connection()
        path = blob_url(blob_name, prefix)
        headers = {
            "Authorization": f"Bearer {self.reader_token}",
            "x-ms-version": STORAGE_API_VERSION,
            "x-ms-date": email_date(),
        }
        try:
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            body = response.read(maximum + 1)
            if len(body) > maximum:
                fail("registry blob read exceeds the expected bound")
            return response.status, body, {key.lower(): value for key, value in response.getheaders()}
        finally:
            connection.close()

    def put_create_only(self, blob_name: str, prefix: str, path: Path, content_md5: str) -> tuple[int, str]:
        connection = self._connection()
        target = blob_url(blob_name, prefix)
        size = path.stat().st_size
        connection.putrequest("PUT", target)
        headers = {
            "Authorization": f"Bearer {self.writer_token}",
            "x-ms-version": STORAGE_API_VERSION,
            "x-ms-date": email_date(),
            "x-ms-blob-type": "BlockBlob",
            "x-ms-blob-content-md5": content_md5,
            "Content-MD5": content_md5,
            "Content-Length": str(size),
            "Content-Type": "application/octet-stream",
            "If-None-Match": "*",
        }
        for key, value in headers.items():
            connection.putheader(key, value)
        connection.endheaders()
        try:
            with path.open("rb") as stream:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    connection.send(chunk)
            response = connection.getresponse()
            body = response.read(65536)
            headers = {key.lower(): value for key, value in response.getheaders()}
            error_code = headers.get("x-ms-error-code", "")
            if response.status >= 300 and not error_code and body:
                match = re.search(rb"<Code>([A-Za-z0-9]+)</Code>", body)
                error_code = match.group(1).decode("ascii") if match else ""
            return response.status, error_code
        finally:
            connection.close()

    def put_bytes_create_only(self, blob_name: str, prefix: str, body: bytes) -> tuple[int, str]:
        with tempfile.NamedTemporaryFile(prefix="paperdesk-manifest-", delete=False) as handle:
            path = Path(handle.name)
            handle.write(body)
        try:
            encoded_md5 = base64.b64encode(hashlib.md5(body, usedforsecurity=False).digest()).decode("ascii")
            return self.put_create_only(blob_name, prefix, path, encoded_md5)
        finally:
            path.unlink(missing_ok=True)


def email_date() -> str:
    from email.utils import format_datetime
    return format_datetime(dt.datetime.now(dt.timezone.utc), usegmt=True)


def verify_readback(body: bytes, headers: dict[str, str], record: dict[str, Any]) -> None:
    if len(body) != record["size"] or hashlib.sha256(body).hexdigest() != record["sha256"]:
        fail("registry readback bytes differ from the accepted source")
    actual_md5 = base64.b64encode(hashlib.md5(body, usedforsecurity=False).digest()).decode("ascii")
    if actual_md5 != record["contentMd5"]:
        fail("registry readback Content-MD5 differs from the accepted source")
    if headers.get("content-md5") not in (None, record["contentMd5"]):
        fail("registry blob Content-MD5 property differs from the accepted source")


def persist_request(archive_path: Path, client: StorageClient) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="paperdesk-registry-request-") as temporary:
        root = Path(temporary) / "extracted"
        request, files = extract_request(archive_path, root)
        prefix = request["registry"]["prefix"]
        records = {record["path"]: record for record in request["files"]}
        manifest_name = prefix + "registry-manifest.json"
        existing_status, existing_body, _ = client.get(manifest_name, prefix, 1024 * 1024)
        if existing_status == 200:
            try:
                existing = json.loads(existing_body)
            except json.JSONDecodeError:
                fail("existing registry completion manifest is invalid")
            validate_existing_manifest(existing, request)
            completed = True
        elif existing_status == 404:
            completed = False
        else:
            fail(f"registry completion-manifest preflight failed with HTTP {existing_status}")
        created = 0
        overwrite_proved = False
        overwrite_probe: tuple[str, Path, str] | None = None
        for relative in sorted(files):
            record = records[relative]
            blob_name = prefix + relative
            status, body, headers = client.get(blob_name, prefix, record["size"])
            if status == 404:
                if completed:
                    fail("completed registry entry is missing a preserved payload blob")
                status, error_code = client.put_create_only(blob_name, prefix, files[relative], record["contentMd5"])
                if status not in (201, 202):
                    fail(f"create-only registry upload failed with HTTP {status}/{error_code}")
                created += 1
                if not overwrite_proved:
                    negative_status, negative_code = client.put_create_only(blob_name, prefix, files[relative], record["contentMd5"])
                    if (negative_status, negative_code) not in {
                        (403, "UnauthorizedBlobOverwrite"),
                        (409, "BlobAlreadyExists"),
                        (412, "TargetConditionNotMet"),
                    }:
                        fail("registry overwrite negative did not fail closed")
                    overwrite_proved = True
                status, body, headers = client.get(blob_name, prefix, record["size"])
            if status != 200:
                fail(f"registry readback failed with HTTP {status}")
            verify_readback(body, headers, record)
            if overwrite_probe is None:
                overwrite_probe = (blob_name, files[relative], record["contentMd5"])

        if not completed and not overwrite_proved:
            if overwrite_probe is None:
                fail("registry overwrite negative has no validated payload target")
            probe_name, probe_path, probe_md5 = overwrite_probe
            negative_status, negative_code = client.put_create_only(probe_name, prefix, probe_path, probe_md5)
            if (negative_status, negative_code) not in {
                (403, "UnauthorizedBlobOverwrite"),
                (409, "BlobAlreadyExists"),
                (412, "TargetConditionNotMet"),
            }:
                fail("registry overwrite negative did not fail closed")
            overwrite_proved = True

        # A local prefix escape must be rejected before the sole completion marker.
        try:
            blob_url(f"v1/releases/{request['candidate']['sha']}/outside", prefix)
        except RegistryError:
            pass
        else:
            fail("registry out-of-prefix negative did not fail closed")

        if completed:
            manifest_body = existing_body
        else:
            persisted_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            manifest = {
                "schema": MANIFEST_SCHEMA,
                "status": "complete",
                "persistedAt": persisted_at,
                **request,
            }
            manifest.pop("schema", None)
            manifest = {"schema": MANIFEST_SCHEMA, **manifest}
            manifest_body = canonical_json(manifest)
            status, error_code = client.put_bytes_create_only(manifest_name, prefix, manifest_body)
            if status not in (201, 202):
                fail(f"registry completion-manifest upload failed with HTTP {status}/{error_code}")
            status, readback, _ = client.get(manifest_name, prefix, len(manifest_body))
            if status != 200 or readback != manifest_body:
                fail("registry completion-manifest readback failed")
        return {
            "status": "complete",
            "prefix": prefix,
            "manifestBlob": manifest_name,
            "manifestSha256": hashlib.sha256(manifest_body).hexdigest(),
            "fileCount": len(files),
            "createdBlobCount": created + (0 if completed else 1),
            "overwriteNegative": "not-run-completed" if completed else ("passed" if overwrite_proved else "not-run"),
            "outOfPrefixNegative": "passed",
        }


def validate_existing_manifest(manifest: Any, request: dict[str, Any]) -> None:
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("status") != "complete":
        fail("existing registry completion manifest is invalid")
    utc_timestamp(manifest.get("persistedAt"), "manifest persistence time")
    expected = dict(request)
    expected.pop("schema", None)
    for key, value in expected.items():
        if manifest.get(key) != value:
            fail("existing registry completion manifest does not match the request")
    if set(manifest) != {"schema", "status", "persistedAt", *expected}:
        fail("existing registry completion manifest fields are not exact")


class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = False


class BridgeHandler(http.server.BaseHTTPRequestHandler):
    server_version = "PaperDeskRegistryBridge/1"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        sys.stderr.write("registry-bridge: " + format % args + "\n")

    def _json(self, status: int, document: dict[str, Any]) -> None:
        body = canonical_json(document)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path != "/healthz":
            self._json(404, {"error": "not-found"})
            return
        self._json(200, {"status": "ready", "bridge": BRIDGE_APP, "schema": SCHEMA})

    def do_POST(self) -> None:
        if self.path != BRIDGE_PATH:
            self._json(404, {"error": "not-found"})
            return
        expected_token_digest = os.environ.get("PAPERDESK_BRIDGE_SESSION_TOKEN_SHA256", "")
        authorization = self.headers.get("Authorization", "")
        token = authorization[7:] if authorization.startswith("Bearer ") else ""
        if not SHA256.fullmatch(expected_token_digest) or not token or not hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), expected_token_digest):
            self._json(401, {"error": "unauthorized"})
            return
        if self.headers.get("Content-Type") != "application/gzip":
            self._json(415, {"error": "unsupported-media-type"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        expected_digest = self.headers.get("X-PaperDesk-Request-SHA256", "")
        if length <= 0 or length > MAX_REQUEST_BYTES or not SHA256.fullmatch(expected_digest):
            self._json(400, {"error": "invalid-request-boundary"})
            return
        temporary = Path(tempfile.mkdtemp(prefix="paperdesk-bridge-upload-"))
        request_path = temporary / "request.tar.gz"
        try:
            remaining = length
            actual = hashlib.sha256()
            descriptor = os.open(request_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as sink:
                while remaining:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        fail("registry request upload ended early")
                    actual.update(chunk)
                    sink.write(chunk)
                    remaining -= len(chunk)
            if actual.hexdigest() != expected_digest:
                fail("registry request transfer digest is invalid")
            writer_id = os.environ.get("PAPERDESK_REGISTRY_WRITER_CLIENT_ID", "")
            reader_id = os.environ.get("PAPERDESK_REGISTRY_READER_CLIENT_ID", "")
            if writer_id == reader_id:
                fail("writer and reader managed identities must be distinct")
            client = StorageClient(identity_token(writer_id), identity_token(reader_id))
            result = persist_request(request_path, client)
            result["requestSha256"] = expected_digest
            self._json(200, result)
        except RegistryError as exc:
            self.log_error("persistence rejected by a contract guard")
            self._json(409, {"error": "persistence-rejected"})
        except Exception as exc:  # pragma: no cover - defensive boundary
            self.log_error("unexpected persistence failure: %s", type(exc).__name__)
            self._json(500, {"error": "internal-error"})
        finally:
            shutil.rmtree(temporary, ignore_errors=True)

    def do_PUT(self) -> None:
        self._json(405, {"error": "method-not-allowed"})

    do_DELETE = do_PUT
    do_PATCH = do_PUT


def serve(args: argparse.Namespace) -> None:
    if args.host != "0.0.0.0" or args.port < 1 or args.port > 65535:
        fail("bridge listener coordinates are invalid")
    server = ThreadingServer((args.host, args.port), BridgeHandler)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    extract = commands.add_parser("extract-actions-artifact")
    extract.add_argument("--archive", required=True)
    extract.add_argument("--output", required=True)
    build = commands.add_parser("build")
    for name in (
        "source-sha", "source-run-id", "source-run-attempt", "acceptance-run-id", "acceptance-run-attempt",
        "acceptance-workflow-ref", "evidence-run-id", "evidence-run-attempt", "evidence-artifact-id",
        "evidence-artifact-name", "evidence-bundle-sha256", "verified-artifact-id", "verified-artifact-digest",
        "verification-artifact-id", "verification-artifact-digest", "acceptance-artifact-id",
        "acceptance-artifact-digest", "verified-artifact-dir", "verification-receipt", "acceptance-receipt",
        "worm-snapshot", "output",
    ):
        build.add_argument(f"--{name}", required=True)
    bridge = commands.add_parser("serve")
    bridge.add_argument("--host", default="0.0.0.0")
    bridge.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "extract-actions-artifact":
            safe_extract_actions_zip(Path(args.archive).resolve(), Path(args.output).resolve())
            print("Actions artifact extracted through bounded safe extraction.")
        elif args.command == "build":
            print(json.dumps(build_request(args), sort_keys=True))
        elif args.command == "serve":
            serve(args)
        return 0
    except RegistryError as exc:
        print(f"accepted-release registry error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
