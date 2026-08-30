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
from collections.abc import MutableMapping
import datetime as dt
import gzip
import hashlib
import hmac
import http.client
import http.server
import ipaddress
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import socketserver
import ssl
import stat
import sys
import tarfile
import tempfile
import threading
from typing import Any, BinaryIO, Mapping
import urllib.error
import urllib.parse
import urllib.request
import zipfile


ACCOUNT = "mdspdbak2608089c4e"
CONTAINER = "paperdesk-accepted-releases"
RESULT_CONTAINER = "paperdesk-registry-webjob-results"
STORAGE_RESOURCE_GROUP = "rg-paperdesk-rollback-sea-20260808"
BRIDGE_APP = "paperdesk-release-registry-bridge-9c4e0d0d"
BRIDGE_RESOURCE_GROUP = "rg-master-data-structure-sea"
ENVIRONMENT = "production"
BRIDGE_PATH = "/internal/v1/persist-accepted-release"
SCHEMA = "paperdesk-accepted-release-registry-request-v2"
MANIFEST_SCHEMA = "paperdesk-accepted-release-registry-manifest-v2"
DEPLOYMENT_COORDINATE_RECEIPT_SCHEMA = "paperdesk-deployment-coordinate-receipt-v1"
RESULT_ATTESTATION_SCHEMA = "paperdesk-registry-webjob-result-attestation-v1"
MAX_REQUEST_BYTES = 1280 * 1024 * 1024
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_OTHER_FILE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 1200 * 1024 * 1024
MAX_MEMBERS = 22
MAX_ACTIONS_ARTIFACT_BYTES = MAX_REQUEST_BYTES
MAX_ACTIONS_ARTIFACT_URL_CHARS = 8192
MAX_ACTIONS_ARTIFACT_QUERY_CHARS = 4096
MAX_GITHUB_TOKEN_CHARS = 4096
MIN_ACTIONS_ARTIFACT_REMAINING_SECONDS = 10
MAX_ACTIONS_ARTIFACT_REMAINING_SECONDS = 300
MIN_ACCEPTED_RELEASE_RETENTION_DAYS = 91
MAX_ONE_SHOT_RESULT_BYTES = 4096
MAX_RESULT_ATTESTATION_BYTES = 8192
STORAGE_API_VERSION = "2023-11-03"

ACTIONS_REQUEST_NAME = "paperdesk-accepted-release-request.tar.gz"
ACTIONS_GITHUB_TOKEN_ENV = "PAPERDESK_REGISTRY_GITHUB_TOKEN"
ACTIONS_GITHUB_ARTIFACT_ID_ENV = "PAPERDESK_REGISTRY_GITHUB_ARTIFACT_ID"
ACTIONS_ARTIFACT_ZIP_SHA256_ENV = "PAPERDESK_REGISTRY_ARTIFACT_ZIP_SHA256"
ACTIONS_REQUEST_SHA256_ENV = "PAPERDESK_REGISTRY_REQUEST_SHA256"
EXPECTED_PREFIX_ENV = "PAPERDESK_REGISTRY_EXPECTED_PREFIX"
RBAC_CANARY_BLOB_ENV = "PAPERDESK_REGISTRY_RBAC_CANARY_BLOB"
RESULT_PURPOSE_ENV = "PAPERDESK_REGISTRY_RESULT_PURPOSE"
RESULT_EXECUTION_ENV = "PAPERDESK_REGISTRY_RESULT_EXECUTION"
RESULT_NONCE_ENV = "PAPERDESK_REGISTRY_RESULT_NONCE"
RESULT_BLOB_ENV = "PAPERDESK_REGISTRY_RESULT_BLOB"
RESULT_GITHUB_RUN_ID_ENV = "PAPERDESK_REGISTRY_RESULT_GITHUB_RUN_ID"
RESULT_GITHUB_RUN_ATTEMPT_ENV = "PAPERDESK_REGISTRY_RESULT_GITHUB_RUN_ATTEMPT"
RESULT_CONTROL_WORKFLOW_SHA_ENV = "PAPERDESK_REGISTRY_RESULT_CONTROL_WORKFLOW_SHA"
ATTESTED_HELPER_SHA256_ENV = "PAPERDESK_REGISTRY_ATTESTED_HELPER_SHA256"
PACKAGE_SHA256_ENV = "PAPERDESK_REGISTRY_PACKAGE_SHA256"
PAPERDESK_REPOSITORY = "Sethvirak/MasterDataStructure"
GITHUB_API_HOST = "api.github.com"
REGISTRY_WRITER_CLIENT_ID = "1a0d95c5-bbd5-4b57-bd6c-6d5645a50e16"
REGISTRY_READER_CLIENT_ID = "a52c21e2-b465-4f01-88b8-44bb5fb8b306"
# The same two fixed helper identities are intended to receive separate, exact
# add-only/read-only assignments at RESULT_CONTAINER.  The future immutable
# bootstrap receipt must prove those assignments do not overlap or widen the
# accepted-release container grants before this dormant source is activated.
RESULT_WRITER_CLIENT_ID = REGISTRY_WRITER_CLIENT_ID
RESULT_READER_CLIENT_ID = REGISTRY_READER_CLIENT_ID
WEBJOB_RUNNER_NAME = "run.sh"
WEBJOB_SETTINGS_NAME = "settings.job"
WEBJOB_RUNNER_SHA256 = "47369cdedfc874b28e850a8b3639413c1afddaf33f722edd80fb99684d68128b"
WEBJOB_SETTINGS_SHA256 = "cd75a1d6bcd7fdca484962635d8bfb84b170de2ef78aac84de339f8c00180e1e"

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
GITHUB_ACTIONS_BLOB_HOST = re.compile(
    r"productionresultssa[0-9]+\.blob\.core\.windows\.net"
)
GITHUB_ACTIONS_BLOB_PATH = re.compile(
    r"/actions-results/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/"
    r"workflow-job-run-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/"
    r"artifacts/[0-9a-f]{64}\.zip"
)
GITHUB_ACTIONS_SAS_QUERY_NAMES = frozenset({
    "rscd", "rsct", "se", "sig", "ske", "skoid", "sks", "skt", "sktid", "skv",
    "sp", "spr", "sr", "st", "sv",
})
REGISTRY_PREFIX = re.compile(r"v1/releases/[0-9a-f]{40}/[1-9][0-9]*/[1-9][0-9]*/")
RBAC_CANARY_BLOB = re.compile(
    r"v1/canaries/storage-rbac/[1-9][0-9]*/[1-9][0-9]*/"
    r"[0-9a-f]{32}(?:-reader-write-denied)?\.json"
)
RESULT_NONCE = re.compile(r"[0-9a-f]{32}")
WEBJOB_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
RESULT_PURPOSES = {
    "preflight-storage": ("storage-rbac-canary", frozenset({1})),
    "preflight-runtime": ("runtime-canary", frozenset({1})),
    "persistence-runtime": ("runtime-canary", frozenset({1})),
    "persistence-result": ("persist-actions-artifact", frozenset({1, 2})),
}
RESULT_BLOB = re.compile(
    r"v1/results/[1-9][0-9]*/[1-9][0-9]*/"
    r"(?:preflight-storage|preflight-runtime|persistence-runtime|persistence-result)/"
    r"[12]/[0-9a-f]{32}(?:-reader-write-denied)?\.json"
)

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
DEPLOYMENT_COORDINATE_RECEIPT_FIELDS = {
    "candidateRuntimeSha256", "candidateSha", "candidateSourceRunAttempt",
    "candidateSourceRunId", "deploymentRunAttempt", "deploymentRunId",
    "schema", "schemaVersion", "verifiedArtifactName",
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


def paperdesk_deployment_workflow_ref(value: str, source_sha: str, label: str) -> str:
    expected = PAPERDESK_SOURCE_WORKFLOW_REF.rsplit("@", 1)[0] + "@" + full_sha(
        source_sha, "deployment workflow source SHA"
    )
    if workflow_ref(value, label) != expected:
        fail(f"{label} must be the exact PaperDesk deployment workflow at the candidate SHA")
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
        "immutabilityPeriodSinceCreationInDays": snapshot.get(
            "immutabilityPeriodSinceCreationInDays"
        ),
        "allowProtectedAppendWrites": False,
        "allowProtectedAppendWritesAll": False,
    }
    for key, value in expected.items():
        if snapshot.get(key) != value:
            fail("WORM snapshot does not prove the fixed locked policy")
    retention = snapshot.get("immutabilityPeriodSinceCreationInDays")
    if type(retention) is not int or retention < MIN_ACCEPTED_RELEASE_RETENTION_DAYS:
        fail("WORM snapshot does not prove at least 91 days of accepted-release custody")
    if not isinstance(snapshot.get("etag"), str) or not ETAG.fullmatch(snapshot["etag"]):
        fail("WORM snapshot ETag is invalid")
    utc_timestamp(snapshot.get("observedAt"), "WORM observation")
    return dict(snapshot)


def validate_deployment_coordinate_receipt(
    value: Any,
    *,
    source_sha: str,
    source_run_id: str,
    source_run_attempt: str,
    deployment_run_id: str,
    deployment_run_attempt: str,
    verified_artifact_name: str,
    runtime_sha256: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != DEPLOYMENT_COORDINATE_RECEIPT_FIELDS:
        fail("deployment-coordinate receipt fields are not exact")
    expected = {
        "schema": DEPLOYMENT_COORDINATE_RECEIPT_SCHEMA,
        "schemaVersion": 1,
        "candidateSha": source_sha,
        "candidateSourceRunId": source_run_id,
        "candidateSourceRunAttempt": source_run_attempt,
        "deploymentRunId": deployment_run_id,
        "deploymentRunAttempt": deployment_run_attempt,
        "verifiedArtifactName": verified_artifact_name,
        "candidateRuntimeSha256": runtime_sha256,
    }
    if value != expected:
        fail("deployment-coordinate receipt identity is not exact")
    digest(str(value.get("candidateRuntimeSha256", "")), "deployment-coordinate runtime digest")
    return dict(value)


def validate_receipts(
    verification: Any,
    acceptance: Any,
    deployment_coordinate: Any,
    *,
    source_sha: str,
    source_run_id: str,
    source_run_attempt: str,
    deployment_run_id: str,
    deployment_run_attempt: str,
    acceptance_run_id: str,
    evidence_run_id: str,
    evidence_artifact_id: str,
    evidence_bundle_sha256: str,
    evidence_contract_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
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
        "candidateRunId": deployment_run_id,
        "candidateRunAttempt": deployment_run_attempt,
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
    deployment_coordinate = validate_deployment_coordinate_receipt(
        deployment_coordinate,
        source_sha=source_sha,
        source_run_id=source_run_id,
        source_run_attempt=source_run_attempt,
        deployment_run_id=deployment_run_id,
        deployment_run_attempt=deployment_run_attempt,
        verified_artifact_name=f"paperdesk-azure-runtime-verified-{source_sha}",
        runtime_sha256=str(verification.get("archiveSha256", "")),
    )
    return dict(verification), dict(acceptance), deployment_coordinate


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
    deployment_run_id = positive(args.candidate_run_id, "deployment run ID")
    deployment_run_attempt = positive(args.candidate_run_attempt, "deployment run attempt")
    deployment_ref = paperdesk_deployment_workflow_ref(
        args.deployment_workflow_ref, source_sha, "deployment workflow"
    )
    acceptance_run_id = positive(args.acceptance_run_id, "acceptance run ID")
    acceptance_run_attempt = positive(args.acceptance_run_attempt, "acceptance run attempt")
    acceptance_ref = workflow_ref(args.acceptance_workflow_ref, "acceptance workflow")
    if acceptance_ref.split("@", 1)[1] != source_sha:
        fail("acceptance workflow is not pinned to the candidate SHA")
    evidence_run_id = positive(args.evidence_run_id, "evidence run ID")
    evidence_run_attempt = positive(args.evidence_run_attempt, "evidence run attempt")
    if len({source_run_id, deployment_run_id, acceptance_run_id, evidence_run_id}) != 4:
        fail("source, deployment, acceptance, and evidence runs must be distinct")
    evidence_digest = digest(args.evidence_bundle_sha256, "evidence bundle digest")
    verified_artifact_digest = digest(args.verified_artifact_digest, "verified artifact digest")
    verification_artifact_digest = digest(args.verification_artifact_digest, "verification artifact digest")
    acceptance_artifact_digest = digest(args.acceptance_artifact_digest, "acceptance artifact digest")
    deployment_coordinate_artifact_digest = digest(
        args.deployment_coordinate_artifact_digest,
        "deployment-coordinate artifact digest",
    )
    for value, label in (
        (args.verified_artifact_id, "verified artifact ID"),
        (args.verification_artifact_id, "verification artifact ID"),
        (args.acceptance_artifact_id, "acceptance artifact ID"),
        (args.deployment_coordinate_artifact_id, "deployment-coordinate artifact ID"),
        (args.evidence_artifact_id, "evidence artifact ID"),
    ):
        positive(value, label)

    verified_root = Path(args.verified_artifact_dir).resolve()
    source_files = verified_files(verified_root, source_sha)
    verification_path = Path(args.verification_receipt).resolve()
    acceptance_path = Path(args.acceptance_receipt).resolve()
    deployment_coordinate_path = Path(args.deployment_coordinate_receipt).resolve()
    expected_verification_name = f"paperdesk-candidate-verification-receipt-{source_sha}.json"
    expected_acceptance_name = f"paperdesk-production-acceptance-receipt-{source_sha}.json"
    expected_deployment_coordinate_name = f"paperdesk-deployment-coordinate-receipt-{source_sha}.json"
    expected_deployment_coordinate_artifact_name = f"paperdesk-deployment-coordinate-receipt-{source_sha}"
    if (
        verification_path.name != expected_verification_name
        or acceptance_path.name != expected_acceptance_name
        or deployment_coordinate_path.name != expected_deployment_coordinate_name
        or args.deployment_coordinate_artifact_name != expected_deployment_coordinate_artifact_name
    ):
        fail("receipt file names are not exact")
    verification = read_json(verification_path, "candidate-verification receipt", 8192)
    acceptance = read_json(acceptance_path, "production-acceptance receipt", 65536)
    deployment_coordinate = read_json(
        deployment_coordinate_path, "deployment-coordinate receipt", 4096
    )
    worm_snapshot = validate_worm_snapshot(read_json(Path(args.worm_snapshot).resolve(), "live WORM snapshot", 8192))
    acceptance_contract_name = f"paperdesk-azure-runtime-{source_sha}.acceptance-contract.json"
    evidence_contract_sha256 = sha256_file(source_files[acceptance_contract_name])
    verification, acceptance, deployment_coordinate = validate_receipts(
        verification,
        acceptance,
        deployment_coordinate,
        source_sha=source_sha,
        source_run_id=source_run_id,
        source_run_attempt=source_run_attempt,
        deployment_run_id=deployment_run_id,
        deployment_run_attempt=deployment_run_attempt,
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
    payload[f"receipts/{expected_deployment_coordinate_name}"] = regular_file(
        deployment_coordinate_path, "deployment-coordinate receipt", 4096
    )
    records = [file_record(payload[relative], relative) for relative in sorted(payload)]
    total = sum(record["size"] for record in records)
    if len(records) != 20 or total > MAX_EXPANDED_BYTES:
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
        "source": {
            "repository": "Sethvirak/MasterDataStructure",
            "sha": source_sha,
            "runId": source_run_id,
            "runAttempt": source_run_attempt,
            "workflowRef": source_workflow_ref,
        },
        "deployment": {
            "runId": deployment_run_id,
            "runAttempt": deployment_run_attempt,
            "workflowRef": deployment_ref,
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
            "deploymentCoordinateReceipt": {
                "id": args.deployment_coordinate_artifact_id,
                "name": expected_deployment_coordinate_artifact_name,
                "digest": deployment_coordinate_artifact_digest,
                "fileSha256": sha256_file(deployment_coordinate_path),
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


def safe_extract_actions_zip(archive_path: Path, output: Path) -> tuple[str, ...]:
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
                    written = 0
                    while True:
                        chunk = source.read(min(1024 * 1024, info.file_size - written + 1))
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > info.file_size:
                            fail("Actions artifact member exceeds its declared size")
                        sink.write(chunk)
                if written != info.file_size or target.stat().st_size != info.file_size:
                    fail("Actions artifact member size changed during extraction")
        return tuple(sorted(seen))
    except RegistryError:
        shutil.rmtree(output, ignore_errors=True)
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile):
        shutil.rmtree(output, ignore_errors=True)
        fail("Actions artifact ZIP is invalid")


class RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Make an artifact URL single-hop so its exact host binding cannot drift."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: BinaryIO,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


def build_direct_artifact_opener() -> Any:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        RejectRedirectHandler(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )


def github_actions_artifact_api_url(artifact_id: str) -> str:
    validated_id = positive(artifact_id, "GitHub Actions artifact ID")
    if len(validated_id) > 20:
        fail("GitHub Actions artifact ID is invalid")
    return (
        f"https://{GITHUB_API_HOST}/repos/{PAPERDESK_REPOSITORY}/"
        f"actions/artifacts/{validated_id}/zip"
    )


def resolve_github_actions_artifact_url(
    artifact_id: str,
    token: str,
    opener: Any | None = None,
) -> tuple[str, str]:
    api_url = github_actions_artifact_api_url(artifact_id)
    if (
        not isinstance(token, str)
        or not token
        or token != token.strip()
        or len(token) > MAX_GITHUB_TOKEN_CHARS
        or any(ord(character) < 0x21 or ord(character) > 0x7e for character in token)
    ):
        fail("GitHub Actions artifact credential is invalid")
    request = urllib.request.Request(
        api_url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "PaperDeskRegistryBridge/1",
            "X-GitHub-Api-Version": "2026-03-10",
        },
        method="GET",
    )
    client = opener if opener is not None else build_direct_artifact_opener()
    response: Any | None = None
    try:
        try:
            response = client.open(request, timeout=30)
        except urllib.error.HTTPError as exc:
            if exc.code != 302 or exc.geturl() != api_url:
                code = exc.code if isinstance(exc.code, int) and 100 <= exc.code <= 599 else 0
                fail(f"GitHub Actions artifact resolution failed with HTTP {code}")
            response = exc
        if getattr(response, "status", getattr(response, "code", 0)) != 302:
            fail("GitHub Actions artifact resolution did not return one exact redirect")
        if response.geturl() != api_url:
            fail("GitHub Actions artifact resolution escaped the fixed API request")
        get_all = getattr(response.headers, "get_all", None)
        locations = get_all("Location") if callable(get_all) else None
        if locations is None:
            single_location = response.headers.get("Location", "")
            locations = [single_location] if single_location else []
        if len(locations) != 1:
            fail("GitHub Actions artifact redirect is invalid")
        location = locations[0]
        if (
            not isinstance(location, str)
            or not location
            or location != location.strip()
            or len(location) > MAX_ACTIONS_ARTIFACT_URL_CHARS
        ):
            fail("GitHub Actions artifact redirect is invalid")
        try:
            redirect_host = urllib.parse.urlsplit(location).hostname or ""
        except ValueError:
            fail("GitHub Actions artifact redirect is invalid")
        validate_actions_artifact_url(location, redirect_host)
        return location, redirect_host
    except RegistryError:
        raise
    except (OSError, urllib.error.URLError, http.client.HTTPException):
        fail("GitHub Actions artifact resolution failed")
    finally:
        request.remove_header("Authorization")
        token = ""
        if response is not None:
            try:
                response.close()
            except (AttributeError, OSError):
                pass


def build_direct_identity_opener() -> Any:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        RejectRedirectHandler(),
    )


def required_environment_value(environment: Mapping[str, str], name: str, maximum: int) -> str:
    value = environment.get(name, "")
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        fail(f"required one-shot coordinate {name} is invalid")
    if any(ord(character) < 0x20 or ord(character) > 0x7e for character in value):
        fail(f"required one-shot coordinate {name} is invalid")
    return value


def validate_actions_artifact_url(
    url: str,
    allowed_host: str,
    observed_at: dt.datetime | None = None,
) -> str:
    if (
        len(url) > MAX_ACTIONS_ARTIFACT_URL_CHARS
        or len(allowed_host) > 253
        or not GITHUB_ACTIONS_BLOB_HOST.fullmatch(allowed_host)
    ):
        fail("Actions artifact URL boundary is invalid")
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
        port = parsed.port
    except ValueError:
        fail("Actions artifact URL boundary is invalid")
    if any((
        parsed.scheme != "https",
        hostname != allowed_host,
        parsed.netloc != allowed_host,
        username is not None,
        password is not None,
        port is not None,
        bool(parsed.fragment),
        not parsed.path.startswith("/"),
        not GITHUB_ACTIONS_BLOB_PATH.fullmatch(parsed.path),
        len(parsed.path) > 2048,
        not parsed.query,
        len(parsed.query) > MAX_ACTIONS_ARTIFACT_QUERY_CHARS,
        "%0d" in url.lower(),
        "%0a" in url.lower(),
    )):
        fail("Actions artifact URL boundary is invalid")
    try:
        query = urllib.parse.parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=32,
        )
    except ValueError:
        fail("Actions artifact URL query is invalid")
    names = [name for name, _ in query]
    if (
        not names
        or len(set(names)) != len(names)
        or not set(names).issubset(GITHUB_ACTIONS_SAS_QUERY_NAMES)
        or any(not name or not value for name, value in query)
        or "sig" not in names
    ):
        fail("Actions artifact URL query is invalid")
    parameters = dict(query)
    if (
        parameters.get("sp") != "r"
        or parameters.get("sr") != "b"
        or parameters.get("spr") != "https"
    ):
        fail("Actions artifact URL permissions are not read-only HTTPS Blob access")
    expires = parameters.get("se", "")
    if not expires.endswith("Z"):
        fail("Actions artifact URL expiry is invalid")
    try:
        expiry = dt.datetime.fromisoformat(expires[:-1] + "+00:00")
    except ValueError:
        fail("Actions artifact URL expiry is invalid")
    now = observed_at or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None or now.utcoffset() != dt.timedelta(0):
        fail("Actions artifact URL observation time is invalid")
    remaining = (expiry - now).total_seconds()
    if not MIN_ACTIONS_ARTIFACT_REMAINING_SECONDS <= remaining <= MAX_ACTIONS_ARTIFACT_REMAINING_SECONDS:
        fail("Actions artifact URL expiry is outside the one-shot boundary")
    return url


def download_actions_artifact(
    url: str,
    allowed_host: str,
    expected_sha256: str,
    output: Path,
    opener: Any | None = None,
) -> str:
    validate_actions_artifact_url(url, allowed_host)
    expected = digest(expected_sha256, "Actions artifact ZIP digest")
    if output.exists():
        fail("Actions artifact download target already exists")
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/zip", "User-Agent": "PaperDeskRegistryBridge/1"},
        method="GET",
    )
    client = opener if opener is not None else build_direct_artifact_opener()
    descriptor: int | None = None
    try:
        with client.open(request, timeout=900) as response:
            if getattr(response, "status", 0) != 200 or response.geturl() != url:
                fail("Actions artifact download was not one exact successful hop")
            content_length_value = response.headers.get("Content-Length", "")
            if not POSITIVE_INTEGER.fullmatch(content_length_value):
                fail("Actions artifact Content-Length is invalid")
            content_length = int(content_length_value)
            if content_length > MAX_ACTIONS_ARTIFACT_BYTES:
                fail("Actions artifact download exceeds the fixed bound")
            if response.headers.get("Content-Encoding", "") not in ("", "identity"):
                fail("Actions artifact response encoding is invalid")
            if response.headers.get("Transfer-Encoding", ""):
                fail("Actions artifact transfer encoding is invalid")
            descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            actual = hashlib.sha256()
            total = 0
            with os.fdopen(descriptor, "wb") as sink:
                descriptor = None
                while True:
                    chunk = response.read(min(1024 * 1024, content_length - total + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > content_length or total > MAX_ACTIONS_ARTIFACT_BYTES:
                        fail("Actions artifact response exceeds its declared bound")
                    actual.update(chunk)
                    sink.write(chunk)
            if total != content_length:
                fail("Actions artifact response ended before its declared bound")
            actual_sha256 = actual.hexdigest()
            if not hmac.compare_digest(actual_sha256, expected):
                fail("Actions artifact ZIP digest is invalid")
            return actual_sha256
    except RegistryError:
        output.unlink(missing_ok=True)
        raise
    except urllib.error.HTTPError as exc:
        output.unlink(missing_ok=True)
        code = exc.code if isinstance(exc.code, int) and 100 <= exc.code <= 599 else 0
        fail(f"Actions artifact download failed with HTTP {code}")
    except (OSError, urllib.error.URLError, http.client.HTTPException):
        output.unlink(missing_ok=True)
        fail("Actions artifact download failed")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def validate_exact_actions_request_inventory(archive_path: Path) -> None:
    regular_file(archive_path, "Actions artifact archive", MAX_REQUEST_BYTES)
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            if len(members) != 1:
                fail("Actions artifact inventory is not the exact registry request")
            info = members[0]
            relative = safe_relative(info.filename.rstrip("/"))
            mode = (info.external_attr >> 16) & 0o170000
            if (
                relative != ACTIONS_REQUEST_NAME
                or info.is_dir()
                or mode not in (0, 0o100000)
                or info.file_size <= 0
                or info.file_size > MAX_REQUEST_BYTES
            ):
                fail("Actions artifact inventory is not the exact registry request")
    except RegistryError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile):
        fail("Actions artifact ZIP is invalid")


def extract_actions_request(archive_path: Path, output: Path) -> Path:
    # Reject extra inventory before any member bytes are extracted.
    validate_exact_actions_request_inventory(archive_path)
    inventory = safe_extract_actions_zip(archive_path, output)
    if inventory != (ACTIONS_REQUEST_NAME,):
        shutil.rmtree(output, ignore_errors=True)
        fail("Actions artifact inventory is not the exact registry request")
    return regular_file(output / ACTIONS_REQUEST_NAME, "Actions registry request", MAX_REQUEST_BYTES)


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
    keys = {
        "schema", "environment", "registry", "source", "deployment", "acceptance",
        "evidence", "artifacts", "verifier", "wormSnapshot", "files",
    }
    if not isinstance(request, dict) or set(request) != keys or request.get("schema") != SCHEMA:
        fail("registry request fields or schema are not exact")
    if request.get("environment") != ENVIRONMENT:
        fail("registry request environment is invalid")
    source = request.get("source")
    deployment = request.get("deployment")
    acceptance = request.get("acceptance")
    registry = request.get("registry")
    if (
        not isinstance(source, dict)
        or not isinstance(deployment, dict)
        or not isinstance(acceptance, dict)
        or not isinstance(registry, dict)
    ):
        fail("registry request coordinates are invalid")
    if set(source) != {"repository", "sha", "runId", "runAttempt", "workflowRef"}:
        fail("registry request source fields are not exact")
    if set(deployment) != {"runId", "runAttempt", "workflowRef"}:
        fail("registry request deployment fields are not exact")
    if set(acceptance) != {
        "runId", "runAttempt", "workflowRef", "acceptedAt", "candidateCompletedAt",
        "candidateFinalizeDeadline", "candidateRuntimeSha256", "evidenceContractSha256",
        "releaseScope", "environmentId",
    }:
        fail("registry request acceptance fields are not exact")
    source_sha = full_sha(str(source.get("sha", "")), "request source SHA")
    source_run_id = positive(str(source.get("runId", "")), "request source run ID")
    deployment_run_id = positive(
        str(deployment.get("runId", "")), "request deployment run ID"
    )
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
    if source.get("repository") != "Sethvirak/MasterDataStructure":
        fail("registry request repository is invalid")
    source_ref = paperdesk_source_workflow_ref(str(source.get("workflowRef", "")), "request source workflow")
    source_run_attempt = positive(str(source.get("runAttempt", "")), "request source run attempt")
    deployment_ref = paperdesk_deployment_workflow_ref(
        str(deployment.get("workflowRef", "")), source_sha, "request deployment workflow"
    )
    deployment_run_attempt = positive(
        str(deployment.get("runAttempt", "")), "request deployment run attempt"
    )
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
    if len({source_run_id, deployment_run_id, acceptance_run_id, evidence_run_id}) != 4:
        fail("registry request source, deployment, acceptance, and evidence runs must be distinct")

    artifacts = request.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != {
        "verified", "verificationReceipt", "productionAcceptanceReceipt",
        "deploymentCoordinateReceipt",
    }:
        fail("registry request artifact fields are not exact")
    expected_artifact_names = {
        "verified": f"paperdesk-azure-runtime-verified-{source_sha}",
        "verificationReceipt": f"paperdesk-candidate-verification-receipt-{source_sha}",
        "productionAcceptanceReceipt": f"paperdesk-production-acceptance-receipt-{source_sha}",
        "deploymentCoordinateReceipt": f"paperdesk-deployment-coordinate-receipt-{source_sha}",
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
    if not isinstance(records, list) or len(records) != 20:
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
        f"receipts/paperdesk-deployment-coordinate-receipt-{source_sha}.json",
    }
    if set(files) != expected_payload:
        fail("registry request preserved-file inventory is not exact")

    verification_path = files[f"receipts/paperdesk-candidate-verification-receipt-{source_sha}.json"]
    acceptance_path = files[f"receipts/paperdesk-production-acceptance-receipt-{source_sha}.json"]
    deployment_coordinate_path = files[
        f"receipts/paperdesk-deployment-coordinate-receipt-{source_sha}.json"
    ]
    if sha256_file(verification_path) != artifacts["verificationReceipt"]["fileSha256"]:
        fail("registry request verification-receipt digest binding is invalid")
    if sha256_file(acceptance_path) != artifacts["productionAcceptanceReceipt"]["fileSha256"]:
        fail("registry request acceptance-receipt digest binding is invalid")
    if (
        sha256_file(deployment_coordinate_path)
        != artifacts["deploymentCoordinateReceipt"]["fileSha256"]
    ):
        fail("registry request deployment-coordinate receipt digest binding is invalid")
    verification = read_json(verification_path, "request candidate-verification receipt", 8192)
    production_acceptance = read_json(acceptance_path, "request production-acceptance receipt", 65536)
    deployment_coordinate = read_json(
        deployment_coordinate_path, "request deployment-coordinate receipt", 4096
    )
    validate_receipts(
        verification,
        production_acceptance,
        deployment_coordinate,
        source_sha=source_sha,
        source_run_id=source_run_id,
        source_run_attempt=source_run_attempt,
        deployment_run_id=deployment_run_id,
        deployment_run_attempt=deployment_run_attempt,
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
        provenance.get("repository") != source["repository"],
        str(provenance.get("runId")) != source_run_id,
        str(provenance.get("runAttempt")) != source_run_attempt,
        provenance.get("workflow") != source_ref,
    )):
        fail("registry request candidate provenance binding is invalid")
    return files


def validate_registry_prefix(value: str, label: str = "expected registry prefix") -> str:
    if not isinstance(value, str) or len(value) > 160 or not REGISTRY_PREFIX.fullmatch(value):
        fail(f"{label} is invalid")
    return value


def validate_expected_request_prefix(archive_path: Path, expected_prefix: str) -> str:
    expected = validate_registry_prefix(expected_prefix)
    try:
        with tempfile.TemporaryDirectory(prefix="paperdesk-registry-prefix-") as temporary:
            request, _ = extract_request(archive_path, Path(temporary) / "extracted")
            actual = request["registry"]["prefix"]
    except RegistryError:
        raise
    except (OSError, tarfile.TarError, EOFError):
        fail("registry request cannot be validated before storage access")
    if not hmac.compare_digest(actual, expected):
        fail("registry request prefix does not match the expected one-shot prefix")
    return actual


def one_shot_coordinates(
    environment: MutableMapping[str, str],
    opener: Any | None = None,
) -> dict[str, str]:
    artifact_id = required_environment_value(
        environment, ACTIONS_GITHUB_ARTIFACT_ID_ENV, 20
    )
    artifact_sha256 = digest(required_environment_value(
        environment, ACTIONS_ARTIFACT_ZIP_SHA256_ENV, 64
    ), "Actions artifact ZIP digest")
    request_sha256 = digest(required_environment_value(
        environment, ACTIONS_REQUEST_SHA256_ENV, 64
    ), "Actions registry request digest")
    expected_prefix = validate_registry_prefix(required_environment_value(
        environment, EXPECTED_PREFIX_ENV, 160
    ))
    token = required_environment_value(
        environment, ACTIONS_GITHUB_TOKEN_ENV, MAX_GITHUB_TOKEN_CHARS
    )
    removed_token = environment.pop(ACTIONS_GITHUB_TOKEN_ENV, None)
    if not isinstance(removed_token, str) or not hmac.compare_digest(removed_token, token):
        fail("one-shot environment could not discard the GitHub credential")
    try:
        artifact_url, artifact_host = resolve_github_actions_artifact_url(
            artifact_id, token, opener
        )
    finally:
        token = ""
        removed_token = ""
    coordinates = {
        "artifactId": positive(artifact_id, "GitHub Actions artifact ID"),
        "url": artifact_url,
        "host": artifact_host,
        "artifactSha256": artifact_sha256,
        "requestSha256": request_sha256,
        "expectedPrefix": expected_prefix,
    }
    return coordinates


def validate_identity_endpoint(endpoint: str) -> str:
    if (
        not isinstance(endpoint, str)
        or not endpoint
        or endpoint != endpoint.strip()
        or len(endpoint) > 2048
        or any(ord(character) < 0x20 or ord(character) > 0x7e for character in endpoint)
    ):
        fail("App Service managed-identity endpoint is invalid")
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
        port = parsed.port
    except ValueError:
        fail("App Service managed-identity endpoint is invalid")
    if any((
        parsed.scheme != "http",
        username is not None,
        password is not None,
        port is None,
        bool(parsed.query),
        bool(parsed.fragment),
        parsed.path not in {"/MSI/token", "/MSI/token/"},
        not hostname,
        "%" in (hostname or ""),
    )):
        fail("App Service managed-identity endpoint is invalid")
    if hostname != "localhost":
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            fail("App Service managed-identity endpoint host is not local")
        if not (address.is_loopback or address.is_link_local):
            fail("App Service managed-identity endpoint host is not local")
    return endpoint


def identity_token(client_id: str) -> str:
    if not UUID.fullmatch(client_id):
        fail("bridge managed-identity client ID is invalid")
    endpoint = validate_identity_endpoint(os.environ.get("IDENTITY_ENDPOINT", ""))
    header = os.environ.get("IDENTITY_HEADER", "")
    if not header or len(header) > 8192 or "\r" in header or "\n" in header:
        fail("App Service managed-identity endpoint is unavailable")
    query = urllib.parse.urlencode({
        "api-version": "2019-08-01",
        "resource": "https://storage.azure.com/",
        "client_id": client_id,
    })
    token_url = f"{endpoint}?{query}"
    request = urllib.request.Request(token_url, headers={"X-IDENTITY-HEADER": header})
    try:
        with build_direct_identity_opener().open(request, timeout=30) as response:
            if getattr(response, "status", 0) != 200 or response.geturl() != token_url:
                fail("managed-identity token response boundary is invalid")
            body = response.read(65537)
            if len(body) > 65536:
                fail("managed-identity token response is excessive")
            document = json.loads(body)
    except RegistryError:
        raise
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        fail("managed-identity token acquisition failed")
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


def rbac_canary_blob_url(blob_name: str) -> str:
    if not isinstance(blob_name, str) or not RBAC_CANARY_BLOB.fullmatch(blob_name):
        fail("storage RBAC canary blob is outside the fixed canary prefix")
    safe_relative(blob_name)
    encoded = "/".join(urllib.parse.quote(part, safe="") for part in PurePosixPath(blob_name).parts)
    return f"/{CONTAINER}/{encoded}"


def result_blob_url(blob_name: str) -> str:
    if not isinstance(blob_name, str) or not RESULT_BLOB.fullmatch(blob_name):
        fail("WebJob result blob is outside the fixed attestation prefix")
    safe_relative(blob_name)
    encoded = "/".join(
        urllib.parse.quote(part, safe="") for part in PurePosixPath(blob_name).parts
    )
    return f"/{RESULT_CONTAINER}/{encoded}"


class StorageClient:
    def __init__(self, writer_token: str, reader_token: str):
        self.writer_token = writer_token
        self.reader_token = reader_token
        self.host = f"{ACCOUNT}.blob.core.windows.net"

    def _connection(self) -> http.client.HTTPSConnection:
        return http.client.HTTPSConnection(self.host, timeout=900, context=ssl.create_default_context())

    @staticmethod
    def _error_code(status: int, body: bytes, headers: dict[str, str]) -> str:
        error_code = headers.get("x-ms-error-code", "")
        if status >= 300 and not error_code and body:
            match = re.search(rb"<Code>([A-Za-z0-9]+)</Code>", body)
            error_code = match.group(1).decode("ascii") if match else ""
        return error_code

    def _get(
        self, target: str, token: str, maximum: int
    ) -> tuple[int, bytes, dict[str, str], str]:
        connection = self._connection()
        headers = {
            "Authorization": f"Bearer {token}",
            "x-ms-version": STORAGE_API_VERSION,
            "x-ms-date": email_date(),
        }
        try:
            connection.request("GET", target, headers=headers)
            response = connection.getresponse()
            body = response.read(maximum + 1)
            if len(body) > maximum:
                fail("registry blob read exceeds the expected bound")
            response_headers = {key.lower(): value for key, value in response.getheaders()}
            return (
                response.status,
                body,
                response_headers,
                self._error_code(response.status, body, response_headers),
            )
        finally:
            connection.close()

    def get(self, blob_name: str, prefix: str, maximum: int) -> tuple[int, bytes, dict[str, str]]:
        status, body, headers, _ = self._get(
            blob_url(blob_name, prefix), self.reader_token, maximum
        )
        return status, body, headers

    def reader_get_canary(self, blob_name: str, maximum: int) -> tuple[int, bytes, dict[str, str], str]:
        return self._get(rbac_canary_blob_url(blob_name), self.reader_token, maximum)

    def writer_get_canary(self, blob_name: str, maximum: int) -> tuple[int, bytes, dict[str, str], str]:
        return self._get(rbac_canary_blob_url(blob_name), self.writer_token, maximum)

    def _put(
        self,
        target: str,
        token: str,
        path: Path,
        content_md5: str,
        create_only: bool,
    ) -> tuple[int, str]:
        connection = self._connection()
        size = path.stat().st_size
        connection.putrequest("PUT", target)
        headers = {
            "Authorization": f"Bearer {token}",
            "x-ms-version": STORAGE_API_VERSION,
            "x-ms-date": email_date(),
            "x-ms-blob-type": "BlockBlob",
            "x-ms-blob-content-md5": content_md5,
            "Content-MD5": content_md5,
            "Content-Length": str(size),
            "Content-Type": "application/octet-stream",
        }
        if create_only:
            headers["If-None-Match"] = "*"
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
            return response.status, self._error_code(response.status, body, headers)
        finally:
            connection.close()

    def put_create_only(self, blob_name: str, prefix: str, path: Path, content_md5: str) -> tuple[int, str]:
        return self._put(
            blob_url(blob_name, prefix), self.writer_token, path, content_md5, True
        )

    def put_bytes_create_only(self, blob_name: str, prefix: str, body: bytes) -> tuple[int, str]:
        with tempfile.NamedTemporaryFile(prefix="paperdesk-manifest-", delete=False) as handle:
            path = Path(handle.name)
            handle.write(body)
        try:
            encoded_md5 = base64.b64encode(hashlib.md5(body, usedforsecurity=False).digest()).decode("ascii")
            return self.put_create_only(blob_name, prefix, path, encoded_md5)
        finally:
            path.unlink(missing_ok=True)

    def _put_canary_bytes_create_only(
        self, blob_name: str, token: str, body: bytes
    ) -> tuple[int, str]:
        with tempfile.NamedTemporaryFile(prefix="paperdesk-rbac-canary-", delete=False) as handle:
            path = Path(handle.name)
            handle.write(body)
        try:
            encoded_md5 = base64.b64encode(
                hashlib.md5(body, usedforsecurity=False).digest()
            ).decode("ascii")
            return self._put(
                rbac_canary_blob_url(blob_name), token, path, encoded_md5, True
            )
        finally:
            path.unlink(missing_ok=True)

    def writer_put_canary_create_only(self, blob_name: str, body: bytes) -> tuple[int, str]:
        return self._put_canary_bytes_create_only(blob_name, self.writer_token, body)

    def reader_put_canary_create_only(self, blob_name: str, body: bytes) -> tuple[int, str]:
        return self._put_canary_bytes_create_only(blob_name, self.reader_token, body)

    def writer_put_canary_unconditional(self, blob_name: str, body: bytes) -> tuple[int, str]:
        with tempfile.NamedTemporaryFile(prefix="paperdesk-rbac-overwrite-", delete=False) as handle:
            path = Path(handle.name)
            handle.write(body)
        try:
            encoded_md5 = base64.b64encode(
                hashlib.md5(body, usedforsecurity=False).digest()
            ).decode("ascii")
            return self._put(
                rbac_canary_blob_url(blob_name),
                self.writer_token,
                path,
                encoded_md5,
                False,
            )
        finally:
            path.unlink(missing_ok=True)

    def result_reader_get(
        self, blob_name: str, maximum: int
    ) -> tuple[int, bytes, dict[str, str], str]:
        return self._get(result_blob_url(blob_name), self.reader_token, maximum)

    def result_writer_get(
        self, blob_name: str, maximum: int
    ) -> tuple[int, bytes, dict[str, str], str]:
        return self._get(result_blob_url(blob_name), self.writer_token, maximum)

    def _put_result_bytes_create_only(
        self, blob_name: str, token: str, body: bytes
    ) -> tuple[int, str]:
        with tempfile.NamedTemporaryFile(prefix="paperdesk-webjob-result-", delete=False) as handle:
            path = Path(handle.name)
            handle.write(body)
        try:
            encoded_md5 = base64.b64encode(
                hashlib.md5(body, usedforsecurity=False).digest()
            ).decode("ascii")
            return self._put(result_blob_url(blob_name), token, path, encoded_md5, True)
        finally:
            path.unlink(missing_ok=True)

    def result_writer_put_create_only(
        self, blob_name: str, body: bytes
    ) -> tuple[int, str]:
        return self._put_result_bytes_create_only(blob_name, self.writer_token, body)

    def result_writer_put_unconditional(
        self, blob_name: str, body: bytes
    ) -> tuple[int, str]:
        with tempfile.NamedTemporaryFile(
            prefix="paperdesk-webjob-result-overwrite-", delete=False
        ) as handle:
            path = Path(handle.name)
            handle.write(body)
        try:
            encoded_md5 = base64.b64encode(
                hashlib.md5(body, usedforsecurity=False).digest()
            ).decode("ascii")
            return self._put(
                result_blob_url(blob_name),
                self.writer_token,
                path,
                encoded_md5,
                False,
            )
        finally:
            path.unlink(missing_ok=True)

    def result_reader_put_create_only(
        self, blob_name: str, body: bytes
    ) -> tuple[int, str]:
        return self._put_result_bytes_create_only(blob_name, self.reader_token, body)

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


def persist_request(
    archive_path: Path,
    client: StorageClient,
    expected_prefix: str | None = None,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="paperdesk-registry-request-") as temporary:
        root = Path(temporary) / "extracted"
        request, files = extract_request(archive_path, root)
        prefix = request["registry"]["prefix"]
        if expected_prefix is not None:
            expected = validate_registry_prefix(expected_prefix)
            if not hmac.compare_digest(prefix, expected):
                fail("registry request prefix does not match the expected one-shot prefix")
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
            blob_url(f"v1/releases/{request['source']['sha']}/outside", prefix)
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


def bounded_one_shot_result(
    persisted: dict[str, Any],
    expected_prefix: str,
    artifact_sha256: str,
    request_sha256: str,
) -> dict[str, Any]:
    if (
        not isinstance(persisted, dict)
        or persisted.get("status") != "complete"
        or persisted.get("prefix") != expected_prefix
        or persisted.get("fileCount") != 20
        or type(persisted.get("createdBlobCount")) is not int
        or not 0 <= persisted["createdBlobCount"] <= 21
        or not (
            (
                persisted["createdBlobCount"] == 0
                and persisted.get("overwriteNegative") == "not-run-completed"
            )
            or (
                1 <= persisted["createdBlobCount"] <= 21
                and persisted.get("overwriteNegative") == "passed"
            )
        )
        or persisted.get("outOfPrefixNegative") != "passed"
    ):
        fail("one-shot registry persistence result is invalid")
    manifest_sha256 = digest(
        str(persisted.get("manifestSha256", "")), "one-shot registry manifest digest"
    )
    document = {
        "status": "complete",
        "prefix": expected_prefix,
        "artifactZipSha256": digest(artifact_sha256, "Actions artifact ZIP digest"),
        "requestSha256": digest(request_sha256, "Actions registry request digest"),
        "manifestSha256": manifest_sha256,
        "fileCount": 20,
        "createdBlobCount": persisted["createdBlobCount"],
        "overwriteNegative": persisted["overwriteNegative"],
        "outOfPrefixNegative": "passed",
    }
    if len(canonical_json(document)) > MAX_ONE_SHOT_RESULT_BYTES:
        fail("one-shot registry persistence result exceeds its bound")
    return document


def validate_attested_helper_result(
    operation: str, purpose: str, result: Any
) -> dict[str, Any]:
    if not isinstance(result, dict):
        fail("WebJob helper result is not one JSON object")
    if operation == "storage-rbac-canary":
        if (
            purpose != "preflight-storage"
            or set(result) != {
                "schemaVersion", "status", "canaryBlob", "writerCreate",
                "readerRead", "writerUnconditionalOverwriteDenied",
                "writerReadDenied", "readerWriteDenied", "localPrefixGuard",
            }
            or type(result.get("schemaVersion")) is not int
            or result.get("schemaVersion") != 1
            or result.get("status") != "storage-rbac-ready"
            or not isinstance(result.get("canaryBlob"), str)
            or not RBAC_CANARY_BLOB.fullmatch(result["canaryBlob"])
            or result.get("writerCreate") != "passed"
            or result.get("readerRead") != "passed"
            or result.get("writerUnconditionalOverwriteDenied") != "passed"
            or result.get("writerReadDenied") != "passed"
            or result.get("readerWriteDenied") != "passed"
            or result.get("localPrefixGuard") != "passed-before-network"
        ):
            fail("storage RBAC helper result is not exact")
    elif operation == "runtime-canary":
        if (
            purpose not in {"preflight-runtime", "persistence-runtime"}
            or set(result) != {
                "schemaVersion", "status", "python", "isolated", "helperSha256",
                "runnerSha256", "settingsJobSha256", "writerClientId", "readerClientId",
            }
            or type(result.get("schemaVersion")) is not int
            or result.get("schemaVersion") != 1
            or result.get("status") != "runtime-ready"
            or result.get("python") != "3.12"
            or result.get("isolated") is not True
            or digest(str(result.get("helperSha256", "")), "runtime helper digest")
                != result["helperSha256"]
            or result.get("runnerSha256") != WEBJOB_RUNNER_SHA256
            or result.get("settingsJobSha256") != WEBJOB_SETTINGS_SHA256
            or result.get("writerClientId") != REGISTRY_WRITER_CLIENT_ID
            or result.get("readerClientId") != REGISTRY_READER_CLIENT_ID
        ):
            fail("runtime helper result is not exact")
    elif operation == "persist-actions-artifact":
        if (
            purpose != "persistence-result"
            or set(result) != {
                "status", "prefix", "artifactZipSha256", "requestSha256",
                "manifestSha256", "fileCount", "createdBlobCount",
                "overwriteNegative", "outOfPrefixNegative",
            }
            or result.get("status") != "complete"
            or not isinstance(result.get("prefix"), str)
            or validate_registry_prefix(result["prefix"]) != result["prefix"]
            or digest(str(result.get("artifactZipSha256", "")), "artifact ZIP digest")
                != result["artifactZipSha256"]
            or digest(str(result.get("requestSha256", "")), "request digest")
                != result["requestSha256"]
            or digest(str(result.get("manifestSha256", "")), "manifest digest")
                != result["manifestSha256"]
            or result.get("fileCount") != 20
            or type(result.get("createdBlobCount")) is not int
            or not 0 <= result["createdBlobCount"] <= 21
            or not (
                (
                    result["createdBlobCount"] == 0
                    and result.get("overwriteNegative") == "not-run-completed"
                )
                or (
                    1 <= result["createdBlobCount"] <= 21
                    and result.get("overwriteNegative") == "passed"
                )
            )
            or result.get("outOfPrefixNegative") != "passed"
        ):
            fail("persistence helper result is not exact")
    else:
        fail("WebJob helper operation is not attestable")
    return result


def result_attestation_coordinates(
    operation: str, environment: MutableMapping[str, str]
) -> dict[str, Any]:
    purpose = required_environment_value(environment, RESULT_PURPOSE_ENV, 32)
    contract = RESULT_PURPOSES.get(purpose)
    if contract is None or contract[0] != operation:
        fail("WebJob result purpose does not match the fixed operation")
    execution_text = positive(
        required_environment_value(environment, RESULT_EXECUTION_ENV, 1),
        "WebJob result execution",
    )
    execution = int(execution_text)
    if execution not in contract[1]:
        fail("WebJob result execution is outside the fixed purpose contract")
    nonce = required_environment_value(environment, RESULT_NONCE_ENV, 32)
    if not RESULT_NONCE.fullmatch(nonce):
        fail("WebJob result nonce is invalid")
    github_run_id = positive(
        required_environment_value(environment, RESULT_GITHUB_RUN_ID_ENV, 20),
        "result GitHub run ID",
    )
    github_run_attempt = positive(
        required_environment_value(environment, RESULT_GITHUB_RUN_ATTEMPT_ENV, 10),
        "result GitHub run attempt",
    )
    result_blob = required_environment_value(environment, RESULT_BLOB_ENV, 256)
    expected_blob = (
        f"v1/results/{github_run_id}/{github_run_attempt}/{purpose}/"
        f"{execution}/{nonce}.json"
    )
    if not hmac.compare_digest(result_blob, expected_blob):
        fail("WebJob result blob does not match its exact coordinates")
    result_blob_url(result_blob)
    webjobs_name = required_environment_value(environment, "WEBJOBS_NAME", 128)
    webjobs_type = required_environment_value(environment, "WEBJOBS_TYPE", 32)
    webjobs_run_id = required_environment_value(environment, "WEBJOBS_RUN_ID", 128)
    if webjobs_name != "paperdesk-accepted-release-registry":
        fail("WebJob result name is invalid")
    if webjobs_type != "triggered":
        fail("WebJob result type is invalid")
    if not WEBJOB_RUN_ID.fullmatch(webjobs_run_id):
        fail("WebJob result run ID is invalid")
    control_workflow_sha = full_sha(
        required_environment_value(environment, RESULT_CONTROL_WORKFLOW_SHA_ENV, 40),
        "result control workflow SHA",
    )
    package_sha256 = digest(
        required_environment_value(environment, PACKAGE_SHA256_ENV, 64),
        "result package digest",
    )
    helper_sha256 = digest(
        required_environment_value(environment, ATTESTED_HELPER_SHA256_ENV, 64),
        "result helper digest",
    )
    if not hmac.compare_digest(helper_sha256, sha256_file(Path(__file__).resolve())):
        fail("result helper digest does not match the executing helper")
    for name in (
        RESULT_PURPOSE_ENV,
        RESULT_EXECUTION_ENV,
        RESULT_NONCE_ENV,
        RESULT_BLOB_ENV,
        RESULT_GITHUB_RUN_ID_ENV,
        RESULT_GITHUB_RUN_ATTEMPT_ENV,
        RESULT_CONTROL_WORKFLOW_SHA_ENV,
        PACKAGE_SHA256_ENV,
        ATTESTED_HELPER_SHA256_ENV,
    ):
        environment.pop(name, None)
    return {
        "operation": operation,
        "purpose": purpose,
        "execution": execution,
        "nonce": nonce,
        "resultBlob": result_blob,
        "githubRunId": github_run_id,
        "githubRunAttempt": github_run_attempt,
        "controlWorkflowSha": control_workflow_sha,
        "packageSha256": package_sha256,
        "helperSha256": helper_sha256,
        "webJobsName": webjobs_name,
        "webJobsType": webjobs_type,
        "webJobsRunId": webjobs_run_id,
    }


def write_attested_webjob_result(
    operation: str,
    result: Any,
    coordinates: dict[str, Any],
    client: Any | None = None,
) -> dict[str, Any]:
    coordinate_fields = {
        "operation", "purpose", "execution", "nonce", "resultBlob",
        "githubRunId", "githubRunAttempt", "controlWorkflowSha",
        "packageSha256", "helperSha256", "webJobsName", "webJobsType",
        "webJobsRunId",
    }
    if (
        not isinstance(coordinates, dict)
        or set(coordinates) != coordinate_fields
        or coordinates.get("operation") != operation
    ):
        fail("prevalidated WebJob result coordinates are not exact")
    exact_result = validate_attested_helper_result(
        operation, coordinates["purpose"], result
    )
    if operation == "storage-rbac-canary":
        expected_canary_blob = (
            "v1/canaries/storage-rbac/"
            f'{coordinates["githubRunId"]}/{coordinates["githubRunAttempt"]}/'
            f'{coordinates["nonce"]}.json'
        )
        if not hmac.compare_digest(exact_result["canaryBlob"], expected_canary_blob):
            fail("storage RBAC canary is not bound to the result coordinates")
    elif operation == "runtime-canary" and not hmac.compare_digest(
        exact_result["helperSha256"], coordinates["helperSha256"]
    ):
        fail("runtime helper result digest differs from its result coordinates")
    result_body = canonical_json(exact_result)
    if len(result_body) > MAX_ONE_SHOT_RESULT_BYTES:
        fail("WebJob helper result exceeds its attestation bound")
    envelope = {
        "schema": RESULT_ATTESTATION_SCHEMA,
        "status": "attested",
        **coordinates,
        "resultSha256": hashlib.sha256(result_body).hexdigest(),
        "result": exact_result,
    }
    envelope_body = canonical_json(envelope)
    if len(envelope_body) > MAX_RESULT_ATTESTATION_BYTES:
        fail("WebJob result attestation exceeds its bound")
    if RESULT_WRITER_CLIENT_ID == RESULT_READER_CLIENT_ID:
        fail("result writer and reader managed identities must be distinct")
    if client is None:
        client = StorageClient(
            identity_token(RESULT_WRITER_CLIENT_ID),
            identity_token(RESULT_READER_CLIENT_ID),
        )
    result_blob = coordinates["resultBlob"]
    create_status, create_code = client.result_writer_put_create_only(
        result_blob, envelope_body
    )
    if create_status != 201 or create_code:
        fail("create-only WebJob result attestation failed")
    read_status, read_body, read_headers, read_code = client.result_reader_get(
        result_blob, len(envelope_body)
    )
    if read_status != 200 or read_code or read_body != envelope_body:
        fail("WebJob result reader exact-byte readback failed")
    expected_md5 = base64.b64encode(
        hashlib.md5(envelope_body, usedforsecurity=False).digest()
    ).decode("ascii")
    if read_headers.get("content-md5") != expected_md5:
        fail("WebJob result reader Content-MD5 differs")
    overwrite_status, overwrite_code = client.result_writer_put_unconditional(
        result_blob, envelope_body
    )
    if (overwrite_status, overwrite_code) not in {
        (403, "AuthorizationPermissionMismatch"),
        (403, "UnauthorizedBlobOverwrite"),
        (409, "BlobImmutableDueToPolicy"),
    }:
        fail("WebJob result writer unconditional overwrite was not denied")
    writer_read_status, _, _, writer_read_code = client.result_writer_get(
        result_blob, MAX_RESULT_ATTESTATION_BYTES
    )
    if (writer_read_status, writer_read_code) != (
        403, "AuthorizationPermissionMismatch"
    ):
        fail("WebJob result writer unexpectedly has read access")
    reader_probe = result_blob[:-5] + "-reader-write-denied.json"
    reader_write_status, reader_write_code = client.result_reader_put_create_only(
        reader_probe, envelope_body
    )
    if (reader_write_status, reader_write_code) != (
        403, "AuthorizationPermissionMismatch"
    ):
        fail("WebJob result reader unexpectedly has create access")
    return envelope


def attest_webjob_result(
    operation: str,
    result: Any,
    environment: MutableMapping[str, str] | None = None,
    client: Any | None = None,
) -> dict[str, Any]:
    environment = os.environ if environment is None else environment
    coordinates = result_attestation_coordinates(operation, environment)
    return write_attested_webjob_result(operation, result, coordinates, client)


def persist_actions_artifact(
    environment: MutableMapping[str, str] | None = None,
    opener: Any | None = None,
) -> dict[str, Any]:
    coordinates = one_shot_coordinates(
        os.environ if environment is None else environment,
        opener,
    )
    try:
        with tempfile.TemporaryDirectory(prefix="paperdesk-actions-artifact-") as temporary:
            root = Path(temporary)
            artifact_path = root / "actions-artifact.zip"
            artifact_sha256 = download_actions_artifact(
                coordinates["url"],
                coordinates["host"],
                coordinates["artifactSha256"],
                artifact_path,
                opener,
            )
            request_path = extract_actions_request(artifact_path, root / "artifact")
            request_sha256 = sha256_file(request_path)
            if not hmac.compare_digest(request_sha256, coordinates["requestSha256"]):
                fail("Actions registry request digest is invalid")

            # Validate the full request and its exact prefix before identity-token
            # acquisition, StorageClient construction, or any storage data-plane call.
            expected_prefix = validate_expected_request_prefix(
                request_path, coordinates["expectedPrefix"]
            )
            if REGISTRY_WRITER_CLIENT_ID == REGISTRY_READER_CLIENT_ID:
                fail("fixed writer and reader managed identities must be distinct")
            client = StorageClient(
                identity_token(REGISTRY_WRITER_CLIENT_ID),
                identity_token(REGISTRY_READER_CLIENT_ID),
            )
            persisted = persist_request(request_path, client, expected_prefix=expected_prefix)
            return bounded_one_shot_result(
                persisted,
                expected_prefix,
                artifact_sha256,
                request_sha256,
            )
    except RegistryError:
        raise
    except Exception:
        fail("one-shot registry persistence failed at a closed boundary")


def storage_rbac_canary(
    environment: MutableMapping[str, str] | None = None,
    client: Any | None = None,
) -> dict[str, Any]:
    environment = os.environ if environment is None else environment
    if ACTIONS_GITHUB_TOKEN_ENV in environment:
        fail("storage RBAC canary must not receive a GitHub credential")
    canary_blob = environment.pop(RBAC_CANARY_BLOB_ENV, "")
    rbac_canary_blob_url(canary_blob)
    reader_write_probe = canary_blob[:-5] + "-reader-write-denied.json"
    rbac_canary_blob_url(reader_write_probe)
    try:
        rbac_canary_blob_url("v1/releases/outside-storage-rbac-canary.json")
    except RegistryError:
        pass
    else:
        fail("storage RBAC canary out-of-prefix negative did not fail closed")

    body = canonical_json({
        "blob": canary_blob,
        "schemaVersion": 1,
        "status": "storage-rbac-canary",
    })
    if REGISTRY_WRITER_CLIENT_ID == REGISTRY_READER_CLIENT_ID:
        fail("fixed writer and reader managed identities must be distinct")
    if client is None:
        client = StorageClient(
            identity_token(REGISTRY_WRITER_CLIENT_ID),
            identity_token(REGISTRY_READER_CLIENT_ID),
        )

    create_status, create_code = client.writer_put_canary_create_only(canary_blob, body)
    if create_status not in (201, 202) or create_code:
        fail("storage RBAC writer create canary failed")

    read_status, read_body, _, read_code = client.reader_get_canary(
        canary_blob, len(body)
    )
    if read_status != 200 or read_code or read_body != body:
        fail("storage RBAC reader read canary failed")

    overwrite_status, overwrite_code = client.writer_put_canary_unconditional(
        canary_blob, body
    )
    if (overwrite_status, overwrite_code) not in {
        (403, "UnauthorizedBlobOverwrite"),
        (403, "AuthorizationPermissionMismatch"),
        (409, "BlobImmutableDueToPolicy"),
    }:
        fail("storage RBAC writer unconditional overwrite canary did not fail closed")

    writer_read_status, _, _, writer_read_code = client.writer_get_canary(
        canary_blob, 64 * 1024
    )
    if (writer_read_status, writer_read_code) != (
        403,
        "AuthorizationPermissionMismatch",
    ):
        fail("storage RBAC writer read canary did not fail closed")

    reader_write_status, reader_write_code = client.reader_put_canary_create_only(
        reader_write_probe, body
    )
    if (reader_write_status, reader_write_code) != (
        403,
        "AuthorizationPermissionMismatch",
    ):
        fail("storage RBAC reader create canary did not fail closed")

    document = {
        "schemaVersion": 1,
        "status": "storage-rbac-ready",
        "canaryBlob": canary_blob,
        "writerCreate": "passed",
        "readerRead": "passed",
        "writerUnconditionalOverwriteDenied": "passed",
        "writerReadDenied": "passed",
        "readerWriteDenied": "passed",
        "localPrefixGuard": "passed-before-network",
    }
    if len(canonical_json(document)) > MAX_ONE_SHOT_RESULT_BYTES:
        fail("storage RBAC canary result exceeds its bound")
    return document


def runtime_canary(job_directory: Path | None = None) -> dict[str, Any]:
    helper = Path(__file__).resolve()
    regular_file(helper, "registry WebJob helper", 2 * 1024 * 1024)
    job_directory = helper.parent if job_directory is None else job_directory.resolve()
    if not job_directory.is_dir() or job_directory.is_symlink():
        fail("registry WebJob directory must be one real directory")
    runner = regular_file(job_directory / WEBJOB_RUNNER_NAME, "registry WebJob runner", 4096)
    settings = regular_file(
        job_directory / WEBJOB_SETTINGS_NAME, "registry WebJob settings", 4096
    )
    if os.name == "posix" and not runner.stat().st_mode & stat.S_IXUSR:
        fail("registry WebJob runner must remain owner-executable")
    runner_sha256 = sha256_file(runner)
    settings_sha256 = sha256_file(settings)
    if not hmac.compare_digest(runner_sha256, WEBJOB_RUNNER_SHA256):
        fail("registry WebJob runner digest is invalid")
    if not hmac.compare_digest(settings_sha256, WEBJOB_SETTINGS_SHA256):
        fail("registry WebJob settings digest is invalid")
    if sys.version_info[:2] != (3, 12):
        fail("registry WebJob requires the reviewed Python 3.12 runtime")
    if sys.flags.isolated != 1:
        fail("registry WebJob helper must run in isolated Python mode")
    if ACTIONS_GITHUB_TOKEN_ENV in os.environ:
        fail("runtime canary must not receive a GitHub credential")
    document = {
        "schemaVersion": 1,
        "status": "runtime-ready",
        "python": "3.12",
        "isolated": True,
        "helperSha256": sha256_file(helper),
        "runnerSha256": runner_sha256,
        "settingsJobSha256": settings_sha256,
        "writerClientId": REGISTRY_WRITER_CLIENT_ID,
        "readerClientId": REGISTRY_READER_CLIENT_ID,
    }
    if REGISTRY_WRITER_CLIENT_ID == REGISTRY_READER_CLIENT_ID:
        fail("fixed writer and reader managed identities must be distinct")
    if len(canonical_json(document)) > MAX_ONE_SHOT_RESULT_BYTES:
        fail("registry WebJob runtime canary result exceeds its bound")
    return document


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
    commands.add_parser("persist-actions-artifact")
    commands.add_parser("runtime-canary")
    commands.add_parser("storage-rbac-canary")
    extract = commands.add_parser("extract-actions-artifact")
    extract.add_argument("--archive", required=True)
    extract.add_argument("--output", required=True)
    build = commands.add_parser("build")
    for name in (
        "source-sha", "source-run-id", "source-run-attempt", "candidate-run-id", "candidate-run-attempt",
        "deployment-workflow-ref", "acceptance-run-id", "acceptance-run-attempt",
        "acceptance-workflow-ref", "evidence-run-id", "evidence-run-attempt", "evidence-artifact-id",
        "evidence-artifact-name", "evidence-bundle-sha256", "verified-artifact-id", "verified-artifact-digest",
        "verification-artifact-id", "verification-artifact-digest", "acceptance-artifact-id",
        "acceptance-artifact-digest", "deployment-coordinate-artifact-id",
        "deployment-coordinate-artifact-name", "deployment-coordinate-artifact-digest",
        "verified-artifact-dir", "verification-receipt", "acceptance-receipt",
        "deployment-coordinate-receipt",
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
        if args.command == "persist-actions-artifact":
            coordinates = result_attestation_coordinates(args.command, os.environ)
            result = persist_actions_artifact()
            print(json.dumps(
                write_attested_webjob_result(args.command, result, coordinates),
                sort_keys=True,
                separators=(",", ":"),
            ))
        elif args.command == "runtime-canary":
            coordinates = result_attestation_coordinates(args.command, os.environ)
            result = runtime_canary()
            print(json.dumps(
                write_attested_webjob_result(args.command, result, coordinates),
                sort_keys=True,
                separators=(",", ":"),
            ))
        elif args.command == "storage-rbac-canary":
            coordinates = result_attestation_coordinates(args.command, os.environ)
            result = storage_rbac_canary()
            print(json.dumps(
                write_attested_webjob_result(args.command, result, coordinates),
                sort_keys=True,
                separators=(",", ":"),
            ))
        elif args.command == "extract-actions-artifact":
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
