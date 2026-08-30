"""Fail-closed accepted-release manifest validation for watchdog state promotion."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import re
from typing import Any, Mapping

from scripts import accepted_release_registry as producer
from scripts import watchdog_contract


MAX_ACCEPTED_MANIFEST_BYTES = 1024 * 1024
ROLLBACK_BASELINE_FIELDS = frozenset({
    "schemaVersion", "receiptSha256", "evidencePath", "sourceSha", "sourceRunId",
    "sourceRunAttempt", "acceptanceRunId", "acceptanceRunAttempt",
    "acceptedReleaseManifestSha256", "acceptedReleasePrefix", "reviewWorkflowRef",
    "reviewWorkflowSha", "reviewRunId", "reviewRunAttempt", "reviewEnvironment",
    "preparedAt",
})
MANIFEST_FIELDS = frozenset({
    "schema", "status", "persistedAt", "environment", "registry", "source",
    "deployment", "acceptance", "evidence", "artifacts", "verifier", "wormSnapshot",
    "files",
})
SHA256 = re.compile(r"^[0-9a-f]{64}$")
POSITIVE = re.compile(r"^[1-9][0-9]*$")
PERSISTED_AT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class AcceptedReleaseManifestError(ValueError):
    """The read-back WORM manifest cannot authorize baseline promotion."""


def fail(message: str) -> None:
    raise AcceptedReleaseManifestError(message)


def _exact_object(value: Any, fields: set[str] | frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        fail(f"{label} fields are not exact")
    return value


def _string(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        fail(f"{label} is invalid")
    return value


def _producer_timestamp(value: Any, label: str, *, milliseconds: bool) -> dt.datetime:
    if not isinstance(value, str):
        fail(f"{label} is invalid")
    try:
        if milliseconds:
            return producer.receipt_timestamp(value, label)
        if not PERSISTED_AT.fullmatch(value):
            fail(f"{label} is not the exact producer format")
        producer.utc_timestamp(value, label)
        return dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except producer.RegistryError as exc:
        fail(str(exc))


def _validate_transition_request(request: Any) -> Mapping[str, Any]:
    try:
        document = watchdog_contract.validate_transition_request({}, request)
    except (TypeError, ValueError) as exc:
        fail(str(exc))
    if document.get("operation") != "accept-candidate":
        fail("accepted-release validation requires accept-candidate")
    return document


def _validate_blob_binding(
    request: Mapping[str, Any],
    actual_registry_etag: Any,
    actual_registry_version_id: Any,
) -> None:
    actual_etag = _string(actual_registry_etag, watchdog_contract.ETAG, "registry readback ETag")
    actual_version = _string(
        actual_registry_version_id,
        watchdog_contract.VERSION_ID,
        "registry readback version ID",
    )
    if not hmac.compare_digest(request["registryManifestETag"], actual_etag):
        fail("request registry ETag differs from the manifest readback")
    if not hmac.compare_digest(request["registryManifestVersionId"], actual_version):
        fail("request registry version ID differs from the manifest readback")


def _validate_acceptance(
    value: Any,
    request: Mapping[str, Any],
) -> tuple[Mapping[str, Any], str, str]:
    acceptance = _exact_object(
        value,
        {
            "runId", "runAttempt", "workflowRef", "acceptedAt", "candidateCompletedAt",
            "candidateFinalizeDeadline", "candidateRuntimeSha256", "evidenceContractSha256",
            "releaseScope", "environmentId",
        },
        "accepted-release manifest acceptance",
    )
    if (
        acceptance.get("runId") != request["acceptanceRunId"]
        or acceptance.get("runAttempt") != request["acceptanceRunAttempt"]
    ):
        fail("accepted-release manifest acceptance run coordinates differ from the request")
    workflow_reference = acceptance.get("workflowRef")
    if not isinstance(workflow_reference, str):
        fail("accepted-release manifest acceptance workflow is invalid")
    try:
        workflow_reference = producer.workflow_ref(
            workflow_reference,
            "accepted-release manifest acceptance workflow",
        )
    except producer.RegistryError as exc:
        fail(str(exc))
    workflow_sha = workflow_reference.rsplit("@", 1)[1]
    if workflow_sha != request["candidateSha"]:
        fail("accepted-release manifest acceptance workflow is not pinned to the candidate")
    completed = _producer_timestamp(
        acceptance.get("candidateCompletedAt"),
        "accepted-release candidate completion",
        milliseconds=True,
    )
    deadline = _producer_timestamp(
        acceptance.get("candidateFinalizeDeadline"),
        "accepted-release candidate deadline",
        milliseconds=True,
    )
    accepted = _producer_timestamp(
        acceptance.get("acceptedAt"),
        "accepted-release acceptance time",
        milliseconds=True,
    )
    if deadline != completed + dt.timedelta(hours=24) or accepted < completed or accepted > deadline:
        fail("accepted-release manifest acceptance window is invalid")
    _string(acceptance.get("candidateRuntimeSha256"), SHA256, "accepted-release runtime digest")
    _string(
        acceptance.get("evidenceContractSha256"),
        SHA256,
        "accepted-release evidence contract digest",
    )
    if acceptance.get("releaseScope") not in {"controlled-non-ha-pilot", "full-production"}:
        fail("accepted-release manifest release scope is invalid")
    environment_id = acceptance.get("environmentId")
    if not isinstance(environment_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}", environment_id
    ):
        fail("accepted-release manifest environment ID is invalid")
    return acceptance, workflow_reference, workflow_sha


def _validate_evidence(value: Any, candidate_sha: str, excluded_runs: set[str]) -> None:
    evidence = _exact_object(
        value,
        {"runId", "runAttempt", "artifactId", "artifactName", "bundleSha256"},
        "accepted-release manifest evidence",
    )
    evidence_run_id = _string(evidence.get("runId"), POSITIVE, "accepted-release evidence run ID")
    _string(evidence.get("runAttempt"), POSITIVE, "accepted-release evidence run attempt")
    _string(evidence.get("artifactId"), POSITIVE, "accepted-release evidence artifact ID")
    _string(evidence.get("bundleSha256"), SHA256, "accepted-release evidence bundle digest")
    if evidence.get("artifactName") != f"paperdesk-production-acceptance-evidence-post-deploy-{candidate_sha}":
        fail("accepted-release manifest evidence artifact name is not exact")
    if evidence_run_id in excluded_runs:
        fail("accepted-release source, deployment, acceptance, and evidence runs must be distinct")


def _validate_artifacts(value: Any, candidate_sha: str, receipt_sha256: str) -> Mapping[str, Any]:
    artifacts = _exact_object(
        value,
        {
            "verified", "verificationReceipt", "productionAcceptanceReceipt",
            "deploymentCoordinateReceipt",
        },
        "accepted-release manifest artifacts",
    )
    expected_names = {
        "verified": f"paperdesk-azure-runtime-verified-{candidate_sha}",
        "verificationReceipt": f"paperdesk-candidate-verification-receipt-{candidate_sha}",
        "productionAcceptanceReceipt": f"paperdesk-production-acceptance-receipt-{candidate_sha}",
        "deploymentCoordinateReceipt": f"paperdesk-deployment-coordinate-receipt-{candidate_sha}",
    }
    for label, expected_name in expected_names.items():
        fields = {"id", "name", "digest"} | ({"fileSha256"} if label != "verified" else set())
        artifact = _exact_object(
            artifacts.get(label),
            fields,
            f"accepted-release manifest {label} artifact",
        )
        _string(artifact.get("id"), POSITIVE, f"accepted-release {label} artifact ID")
        if artifact.get("name") != expected_name:
            fail(f"accepted-release manifest {label} artifact name is not exact")
        _string(artifact.get("digest"), SHA256, f"accepted-release {label} artifact digest")
        if label != "verified":
            _string(
                artifact.get("fileSha256"),
                SHA256,
                f"accepted-release {label} receipt digest",
            )
    if artifacts["productionAcceptanceReceipt"]["fileSha256"] != receipt_sha256:
        fail("accepted-release production-acceptance receipt digest differs from the request")
    return artifacts


def _validate_verifier(value: Any) -> None:
    verifier = _exact_object(
        value,
        {"workflowRef", "job", "runId", "runAttempt"},
        "accepted-release manifest verifier",
    )
    workflow_reference = verifier.get("workflowRef")
    if not isinstance(workflow_reference, str):
        fail("accepted-release manifest verifier workflow is invalid")
    try:
        producer.workflow_ref(workflow_reference, "accepted-release manifest verifier workflow")
    except producer.RegistryError as exc:
        fail(str(exc))
    if verifier.get("job") != "verify_candidate":
        fail("accepted-release manifest verifier job is invalid")
    _string(verifier.get("runId"), POSITIVE, "accepted-release verifier run ID")
    _string(verifier.get("runAttempt"), POSITIVE, "accepted-release verifier run attempt")


def _validate_file_inventory(
    value: Any,
    candidate_sha: str,
    artifacts: Mapping[str, Any],
    production_receipt_sha256: str,
) -> str:
    if not isinstance(value, list) or len(value) != 20:
        fail("accepted-release manifest file inventory count is invalid")
    expected_maximums = {
        f"verified-artifact/{relative}": maximum
        for relative, maximum in producer.expected_verified_inventory(candidate_sha).items()
    }
    verification_path = f"receipts/paperdesk-candidate-verification-receipt-{candidate_sha}.json"
    production_path = f"receipts/paperdesk-production-acceptance-receipt-{candidate_sha}.json"
    deployment_coordinate_path = (
        f"receipts/paperdesk-deployment-coordinate-receipt-{candidate_sha}.json"
    )
    expected_maximums[verification_path] = 8192
    expected_maximums[production_path] = 65536
    expected_maximums[deployment_coordinate_path] = 4096
    records: dict[str, Mapping[str, Any]] = {}
    ordered_paths: list[str] = []
    total = 0
    for value_record in value:
        record = _exact_object(
            value_record,
            {"path", "size", "sha256", "contentMd5"},
            "accepted-release manifest file record",
        )
        relative_value = record.get("path")
        if not isinstance(relative_value, str):
            fail("accepted-release manifest file path is invalid")
        try:
            relative = producer.safe_relative(relative_value)
        except producer.RegistryError as exc:
            fail(str(exc))
        if relative in records:
            fail("accepted-release manifest file path is duplicated")
        size = record.get("size")
        maximum = expected_maximums.get(relative)
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
            or maximum is None
            or size > maximum
        ):
            fail("accepted-release manifest preserved-file inventory is not exact")
        _string(record.get("sha256"), SHA256, "accepted-release manifest file digest")
        content_md5 = record.get("contentMd5")
        if not isinstance(content_md5, str) or not producer.CONTENT_MD5.fullmatch(content_md5):
            fail("accepted-release manifest file Content-MD5 is invalid")
        total += size
        if total > producer.MAX_EXPANDED_BYTES:
            fail("accepted-release manifest payload size is excessive")
        records[relative] = record
        ordered_paths.append(relative)
    if set(records) != set(expected_maximums) or ordered_paths != sorted(expected_maximums):
        fail("accepted-release manifest preserved-file inventory is not exact")
    if records[verification_path]["sha256"] != artifacts["verificationReceipt"]["fileSha256"]:
        fail("accepted-release verification-receipt inventory digest is invalid")
    if records[production_path]["sha256"] != production_receipt_sha256:
        fail("accepted-release production-acceptance receipt inventory digest is invalid")
    if (
        records[deployment_coordinate_path]["sha256"]
        != artifacts["deploymentCoordinateReceipt"]["fileSha256"]
    ):
        fail("accepted-release deployment-coordinate receipt inventory digest is invalid")
    return production_path


def validate_accept_candidate_manifest(
    raw_manifest: bytes,
    request: Any,
    *,
    actual_registry_etag: str,
    actual_registry_version_id: str,
) -> dict[str, Any]:
    """Return a contract-exact rollback baseline from one exact blob readback.

    The actual ETag and version ID must be metadata from the same blob response
    that supplied ``raw_manifest``. Repeating unverified caller values here
    would violate the validator's storage-binding precondition.
    """

    transition = _validate_transition_request(request)
    _validate_blob_binding(transition, actual_registry_etag, actual_registry_version_id)
    if not isinstance(raw_manifest, bytes) or not 0 < len(raw_manifest) <= MAX_ACCEPTED_MANIFEST_BYTES:
        fail("accepted-release manifest bytes are missing or exceed the fixed bound")
    try:
        manifest = json.loads(raw_manifest.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("accepted-release manifest is not valid UTF-8 JSON")
    if not isinstance(manifest, dict) or producer.canonical_json(manifest) != raw_manifest:
        fail("accepted-release manifest is not exact canonical JSON")
    manifest_sha256 = hashlib.sha256(raw_manifest).hexdigest()
    if not hmac.compare_digest(manifest_sha256, transition["acceptedReleaseManifestSha256"]):
        fail("accepted-release manifest raw digest differs from the request")
    manifest = _exact_object(manifest, MANIFEST_FIELDS, "accepted-release manifest")
    if manifest.get("schema") != producer.MANIFEST_SCHEMA or manifest.get("status") != "complete":
        fail("accepted-release manifest schema or status is invalid")
    persisted_at_value = manifest.get("persistedAt")
    persisted_at_time = _producer_timestamp(
        persisted_at_value,
        "accepted-release persistence time",
        milliseconds=False,
    )
    persisted_at = persisted_at_time.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if manifest.get("environment") != producer.ENVIRONMENT:
        fail("accepted-release manifest environment is invalid")

    prefix = transition["acceptedReleasePrefix"]
    registry = _exact_object(
        manifest.get("registry"),
        {"storageAccount", "container", "bridgeApp", "bridgeResourceGroup", "prefix"},
        "accepted-release manifest registry",
    )
    if registry != {
        "storageAccount": producer.ACCOUNT,
        "container": producer.CONTAINER,
        "bridgeApp": producer.BRIDGE_APP,
        "bridgeResourceGroup": producer.BRIDGE_RESOURCE_GROUP,
        "prefix": prefix,
    }:
        fail("accepted-release manifest registry coordinates are not exact")

    source = _exact_object(
        manifest.get("source"),
        {"repository", "sha", "runId", "runAttempt", "workflowRef"},
        "accepted-release manifest source",
    )
    if source != {
        "repository": producer.PAPERDESK_REPOSITORY,
        "sha": transition["candidateSha"],
        "runId": transition["sourceRunId"],
        "runAttempt": transition["sourceRunAttempt"],
        "workflowRef": producer.PAPERDESK_SOURCE_WORKFLOW_REF,
    }:
        fail("accepted-release manifest source coordinates are not exact")

    deployment = _exact_object(
        manifest.get("deployment"),
        {"runId", "runAttempt", "workflowRef"},
        "accepted-release manifest deployment",
    )
    expected_deployment_ref = (
        producer.PAPERDESK_SOURCE_WORKFLOW_REF.rsplit("@", 1)[0]
        + "@"
        + transition["candidateSha"]
    )
    if deployment != {
        "runId": transition["candidateRunId"],
        "runAttempt": transition["candidateRunAttempt"],
        "workflowRef": expected_deployment_ref,
    }:
        fail("accepted-release manifest deployment coordinates are not exact")
    if len({
        transition["sourceRunId"], transition["candidateRunId"],
        transition["acceptanceRunId"],
    }) != 3:
        fail("accepted-release source, deployment, and acceptance runs must be distinct")
    if prefix != (
        f"v1/releases/{transition['candidateSha']}/{transition['sourceRunId']}/"
        f"{transition['acceptanceRunId']}/"
    ):
        fail("accepted-release manifest prefix does not bind source and acceptance runs")

    _, review_workflow_ref, review_workflow_sha = _validate_acceptance(
        manifest.get("acceptance"),
        transition,
    )
    _validate_evidence(
        manifest.get("evidence"),
        transition["candidateSha"],
        {
            transition["sourceRunId"], transition["candidateRunId"],
            transition["acceptanceRunId"],
        },
    )
    receipt_sha256 = transition["productionAcceptanceReceiptSha256"]
    artifacts = _validate_artifacts(manifest.get("artifacts"), transition["candidateSha"], receipt_sha256)
    _validate_verifier(manifest.get("verifier"))
    try:
        producer.validate_worm_snapshot(manifest.get("wormSnapshot"))
    except producer.RegistryError as exc:
        fail(str(exc))
    production_receipt_path = _validate_file_inventory(
        manifest.get("files"),
        transition["candidateSha"],
        artifacts,
        receipt_sha256,
    )

    baseline = {
        "schemaVersion": 2,
        "receiptSha256": receipt_sha256,
        "evidencePath": prefix + production_receipt_path,
        "sourceSha": transition["candidateSha"],
        "sourceRunId": transition["sourceRunId"],
        "sourceRunAttempt": transition["sourceRunAttempt"],
        "acceptanceRunId": transition["acceptanceRunId"],
        "acceptanceRunAttempt": transition["acceptanceRunAttempt"],
        "acceptedReleaseManifestSha256": manifest_sha256,
        "acceptedReleasePrefix": prefix,
        "reviewWorkflowRef": review_workflow_ref,
        "reviewWorkflowSha": review_workflow_sha,
        "reviewRunId": transition["acceptanceRunId"],
        "reviewRunAttempt": transition["acceptanceRunAttempt"],
        "reviewEnvironment": manifest["environment"],
        "preparedAt": persisted_at,
    }
    if set(baseline) != ROLLBACK_BASELINE_FIELDS:
        fail("rollback baseline projection fields are not exact")
    return baseline
