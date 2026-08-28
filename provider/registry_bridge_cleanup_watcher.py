#!/usr/bin/env python3
"""Dormant, fail-closed runner-loss cleanup core for the registry bridge.

The module deliberately supplies no HTTP server, timer trigger, Azure SDK
adapter, credential loader, or executable live entry point.  Its only cloud
surface is the narrow ``CleanupBoundary`` protocol.  A later independently
reviewed activation must implement that protocol with fixed-resource managed
identity calls, pin the merged mutating commit in the adjacent contract, and
prove the package through live runner-loss canaries.

The state machine is still concrete enough to review and test now: it uses an
authenticated server timestamp, ETag compare-and-swap, monotonically increasing
fences, exact bridge/settings postconditions, exact ARM WebJob history binding,
read-only result reconciliation, and create-only immutable receipts.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Protocol, Sequence


CONTRACT_ID = "paperdesk-registry-bridge-cleanup-watcher-v1"
CONTRACT_SHA256 = "2042a420c8da9ab30f5a71bd50c75fb023118fa4bba3709c5913024ea8334f90"
SESSION_SCHEMA = "paperdesk-registry-bridge-cleanup-session-v1"
RECEIPT_SCHEMA = "paperdesk-registry-bridge-cleanup-receipt-v1"
CLOSURE_SCHEMA = "paperdesk-registry-bridge-cleanup-closure-v1"
AUTHORITY_FENCE_SCHEMA = "paperdesk-registry-bridge-runner-authority-fence-v1"
AUTHORITY_GENERATION_SCHEMA = "paperdesk-registry-bridge-runner-authority-generation-v1"
RESULT_SCHEMA = "paperdesk-registry-webjob-result-attestation-v1"
RESULT_PROOF_SCHEMA = "paperdesk-registry-cleanup-result-proof-v1"
ASSESSMENT_SCHEMA = "paperdesk-registry-cleanup-assessment-v1"

MERGED_MUTATING_COMMIT_SHA: str | None = None

SUBSCRIPTION_ID = "9c4e0d0d-602f-4cde-84bd-337250e5b64c"
BRIDGE_RESOURCE_GROUP = "rg-master-data-structure-sea"
BRIDGE_NAME = "paperdesk-release-registry-bridge-9c4e0d0d"
BRIDGE_RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{BRIDGE_RESOURCE_GROUP}"
    f"/providers/Microsoft.Web/sites/{BRIDGE_NAME}"
)
WEBJOB_NAME = "paperdesk-accepted-release-registry"
HISTORY_RESOURCE_PREFIX = (
    f"{BRIDGE_RESOURCE_ID}/triggeredwebjobs/{WEBJOB_NAME}/history/"
)

STORAGE_ACCOUNT = "mdspdbak2608089c4e"
STATE_CONTAINER = "paperdesk-registry-cleanup-state"
STATE_BLOB = "v1/bridge/current.json"
RESULT_CONTAINER = "paperdesk-registry-webjob-results"
ACCEPTED_RELEASE_CONTAINER = "paperdesk-accepted-releases"
EVIDENCE_CONTAINER = "paperdesk-watchdog-evidence"
EVIDENCE_PREFIX = "v1/registry-bridge-cleanup"
AUTHORITY_FENCE_CONTAINER = "paperdesk-registry-runner-authority-fences"
AUTHORITY_FENCE_PREFIX = "v1/registry-bridge-runner-authority-fences"

SESSION_LEASE_SECONDS = 600
CLEANUP_LEASE_SECONDS = 600
MAX_SESSION_BYTES = 65536
MAX_RESULT_BYTES = 8192
MAX_RECEIPT_BYTES = 65536

PACKAGE_SHA256 = "76c9c8c51a07852e2aaa5139c5e544b672fec600bee30eb56633ec3df6b859c8"
HELPER_SHA256 = "889603801a301cb31d33c6d7515f74d601f2637ff40a2b0a49139927f3e25050"
RUNNER_SHA256 = "47369cdedfc874b28e850a8b3639413c1afddaf33f722edd80fb99684d68128b"
SETTINGS_SHA256 = "cd75a1d6bcd7fdca484962635d8bfb84b170de2ef78aac84de339f8c00180e1e"

PERSISTENT_SETTINGS = {
    "PAPERDESK_REGISTRY_HELPER_SHA256": HELPER_SHA256,
    "PAPERDESK_REGISTRY_PACKAGE_SHA256": PACKAGE_SHA256,
    "PAPERDESK_REGISTRY_RUNNER_SHA256": RUNNER_SHA256,
    "PAPERDESK_REGISTRY_SETTINGS_SHA256": SETTINGS_SHA256,
    "WEBSITE_SKIP_RUNNING_KUDUAGENT": "false",
}

TRANSIENT_SETTINGS = (
    "PAPERDESK_BRIDGE_SESSION_TOKEN_SHA256",
    "PAPERDESK_REGISTRY_ARTIFACT_HOST",
    "PAPERDESK_REGISTRY_ARTIFACT_URL",
    "PAPERDESK_REGISTRY_ARTIFACT_ZIP_SHA256",
    "PAPERDESK_REGISTRY_EXPECTED_PREFIX",
    "PAPERDESK_REGISTRY_GITHUB_ARTIFACT_ID",
    "PAPERDESK_REGISTRY_GITHUB_TOKEN",
    "PAPERDESK_REGISTRY_OPERATION",
    "PAPERDESK_REGISTRY_RBAC_CANARY_BLOB",
    "PAPERDESK_REGISTRY_REQUEST_SHA256",
    "PAPERDESK_REGISTRY_RESULT_BLOB",
    "PAPERDESK_REGISTRY_RESULT_CONTROL_WORKFLOW_SHA",
    "PAPERDESK_REGISTRY_RESULT_EXECUTION",
    "PAPERDESK_REGISTRY_RESULT_GITHUB_RUN_ATTEMPT",
    "PAPERDESK_REGISTRY_RESULT_GITHUB_RUN_ID",
    "PAPERDESK_REGISTRY_RESULT_NONCE",
    "PAPERDESK_REGISTRY_RESULT_PURPOSE",
)

SEALED_POSTURE = {
    "state": "Stopped",
    "publicNetworkAccess": "Disabled",
    "linuxFxVersion": "PYTHON|3.12",
    "alwaysOn": True,
    "webJobsEnabled": True,
    "scmIpSecurityRestrictionsUseMain": True,
    "ftpsState": "Disabled",
    "ipSecurityRestrictionsDefaultAction": "Deny",
    "scmIpSecurityRestrictionsDefaultAction": "Deny",
    "ftpBasicPublishingAllowed": False,
    "scmBasicPublishingAllowed": False,
}

MATRICES = {
    "preflight": {
        ("preflight-storage", 1): "storage-rbac-canary",
        ("preflight-runtime", 1): "runtime-canary",
    },
    "persistence": {
        ("persistence-runtime", 1): "runtime-canary",
        ("persistence-result", 1): "persist-actions-artifact",
        ("persistence-result", 2): "persist-actions-artifact",
    },
}

PHASES = (
    "armed",
    "settings-written",
    "bridge-started",
    "webjob-triggered",
    "result-observed",
    "runner-complete",
)

SESSION_KEYS = {
    "schema",
    "status",
    "sessionId",
    "fence",
    "phase",
    "mode",
    "leaseOwner",
    "leaseStartedAt",
    "leaseExpiresAt",
    "claimId",
    "claimant",
    "claimedAt",
    "claimLeaseExpiresAt",
    "githubRunId",
    "githubRunAttempt",
    "controlWorkflowSha",
    "sessionTokenSha256",
    "packageSha256",
    "helperSha256",
    "runnerAuthorityGenerationSha256",
    "expectedExecutions",
    "assessment",
    "authorityFence",
    "receipt",
}

EXECUTION_KEYS = {
    "operation",
    "purpose",
    "execution",
    "nonce",
    "resultBlob",
    "historyId",
    "webJobsRunId",
    "expectedPrefix",
    "artifactZipSha256",
    "requestSha256",
}

ENVELOPE_KEYS = {
    "schema",
    "status",
    "operation",
    "purpose",
    "execution",
    "nonce",
    "resultBlob",
    "githubRunId",
    "githubRunAttempt",
    "controlWorkflowSha",
    "packageSha256",
    "helperSha256",
    "webJobsName",
    "webJobsType",
    "webJobsRunId",
    "resultSha256",
    "result",
}

HISTORY_KEYS = {"id", "web_job_name", "web_job_id", "status", "start_time", "end_time"}
ASSESSMENT_KEYS = {
    "schema",
    "claimBindingSha256",
    "outcome",
    "cleanupActions",
    "bridgePostcondition",
    "resultReconciliation",
    "issues",
}
BRIDGE_ASSESSMENT_KEYS = {
    "status",
    "postureExact",
    "persistentSettingsExact",
    "transientSettingsPresent",
    "unknownSettingsPresent",
    "unknownSettingNamesSha256",
}
RECONCILIATION_KEYS = {
    "status",
    "resultAccess",
    "expectedExecutionCount",
    "persistenceCase",
    "executions",
}
RESULT_PROOF_KEYS = {
    "schema",
    "status",
    "purpose",
    "execution",
    "historyId",
    "webJobsRunId",
    "envelopeSha256",
    "resultSha256",
}
RECEIPT_REFERENCE_KEYS = {"path", "sha256", "status"}
AUTHORITY_FENCE_REFERENCE_KEYS = {
    "path", "sha256", "status", "runnerAuthorityGenerationSha256"
}
AUTHORITY_FENCE_KEYS = {
    "schema", "status", "contractId", "sessionId", "fence", "claimId",
    "claimedAt", "githubRunId", "githubRunAttempt", "controlWorkflowSha",
    "runnerAuthorityGenerationSha256", "bridgeResourceId",
    "controlPrincipalObjectId", "federatedCredentialResourceId",
    "mutatingRoleAssignmentIds", "revokedAt", "lastPossibleTokenExpiryAt",
    "observedServerTime", "producerReviewedCommitSha",
}

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
POSITIVE_RE = re.compile(r"^[1-9][0-9]*$")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
ETAG_RE = re.compile(r'^"[^"\r\n]{1,240}"$')
CANONICAL_TIME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$")
ARM_TIME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$")
PREFIX_RE = re.compile(r"^v1/releases/[0-9a-f]{40}/[1-9][0-9]*/[1-9][0-9]*/$")

_ACTIVATION_FACTORY_GUARD = object()


class CleanupContractError(RuntimeError):
    """A safe, non-secret contract failure."""

    def __init__(self, code: str):
        safe = code if re.fullmatch(r"[a-z0-9:-]{1,160}", code) else "contract-failure"
        super().__init__(safe)
        self.code = safe


def fail(code: str) -> None:
    raise CleanupContractError(code)


def canonical_json(document: Any) -> bytes:
    return (
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def digest_bytes(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _duplicate_rejector(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("json-duplicate-key")
        result[key] = value
    return result


def strict_canonical_json(body: bytes, maximum: int, code: str) -> Any:
    if not isinstance(body, bytes) or not 0 < len(body) <= maximum:
        fail(f"{code}:size")
    try:
        document = json.loads(body.decode("utf-8"), object_pairs_hook=_duplicate_rejector)
    except CleanupContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"{code}:json")
    if body != canonical_json(document):
        fail(f"{code}:noncanonical")
    return document


def exact_digest(value: object, code: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        fail(code)
    return value


def exact_sha(value: object, code: str) -> str:
    if not isinstance(value, str) or not SHA40_RE.fullmatch(value) or value == "0" * 40:
        fail(code)
    return value


def exact_positive(value: object, code: str) -> str:
    if not isinstance(value, str) or not POSITIVE_RE.fullmatch(value):
        fail(code)
    return value


def exact_safe_id(value: object, code: str) -> str:
    if not isinstance(value, str) or not SAFE_ID_RE.fullmatch(value):
        fail(code)
    return value


def parse_server_time(value: object) -> datetime:
    if not isinstance(value, str) or not CANONICAL_TIME_RE.fullmatch(value):
        fail("server-time-invalid")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        fail("server-time-invalid")


def parse_arm_time(value: object) -> tuple[datetime, int]:
    if not isinstance(value, str) or not ARM_TIME_RE.fullmatch(value):
        fail("history-time-invalid")
    match = re.fullmatch(
        r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?Z",
        value,
    )
    if match is None:
        fail("history-time-invalid")
    try:
        whole = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        fail("history-time-invalid")
    nanoseconds = int((match.group(2) or "0").ljust(9, "0"))
    return whole, nanoseconds


def exact_history_id(value: object, code: str) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        fail(code)
    prefix_length = len(HISTORY_RESOURCE_PREFIX)
    if value[:prefix_length].lower() != HISTORY_RESOURCE_PREFIX.lower():
        fail(code)
    suffix = value[prefix_length:]
    if not SAFE_ID_RE.fullmatch(suffix):
        fail(code)
    return value


def format_server_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        fail("server-time-invalid")
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def expires_from(server_time: str, seconds: int) -> str:
    if type(seconds) is not int or not 60 <= seconds <= 3600:
        fail("lease-duration-invalid")
    return format_server_time(parse_server_time(server_time) + timedelta(seconds=seconds))


@dataclass(frozen=True)
class StateRecord:
    """One state read/write response bound to Azure Storage server time."""

    body: bytes
    etag: str
    server_time: str
    clock_source: str = "azure-storage-date"

    def validate(self) -> "StateRecord":
        if not isinstance(self.etag, str) or not ETAG_RE.fullmatch(self.etag):
            fail("state-etag-invalid")
        if self.clock_source != "azure-storage-date":
            fail("state-clock-source-invalid")
        parse_server_time(self.server_time)
        strict_canonical_json(self.body, MAX_SESSION_BYTES, "state")
        return self


@dataclass(frozen=True)
class BridgeSnapshot:
    resource_id: str
    posture: Mapping[str, Any]
    settings: Mapping[str, str]


@dataclass(frozen=True)
class EvidencePolicy:
    container: str
    state: str
    retention_days: int


class CleanupBoundary(Protocol):
    """The complete allowed cloud authority surface of the watcher.

    Deliberately absent: start/run/deploy/publish, role writes, result writes,
    accepted-release access, and every blob-delete operation.
    """

    def probe_server_time(self) -> str: ...
    def read_state(self) -> StateRecord | None: ...
    def create_state(self, body: bytes) -> StateRecord: ...
    def replace_state(self, body: bytes, etag: str) -> StateRecord: ...
    def stop_bridge(self) -> None: ...
    def reseal_bridge(self) -> None: ...
    def delete_transient_settings(self, names: Sequence[str]) -> None: ...
    def read_bridge(self) -> BridgeSnapshot: ...
    def read_webjob_history(self, history_id: str) -> Mapping[str, Any] | None: ...
    def read_result(self, container: str, blob: str, maximum: int) -> bytes | None: ...
    def read_evidence_policy(self) -> EvidencePolicy: ...
    def read_authority_fence(self, container: str, blob: str, maximum: int) -> bytes | None: ...
    def create_evidence(self, container: str, blob: str, body: bytes) -> bool: ...
    def read_evidence(self, container: str, blob: str, maximum: int) -> bytes | None: ...


def _expected_blob(run_id: str, attempt: str, purpose: str, execution: int, nonce: str) -> str:
    return f"v1/results/{run_id}/{attempt}/{purpose}/{execution}/{nonce}.json"


def _validate_execution(
    item: object,
    *,
    run_id: str,
    attempt: str,
    coordinate: tuple[str, int],
    operation: str,
) -> dict[str, Any]:
    if not isinstance(item, dict) or set(item) != EXECUTION_KEYS:
        fail("session-execution-fields")
    purpose, execution = coordinate
    if (
        item.get("operation") != operation
        or item.get("purpose") != purpose
        or type(item.get("execution")) is not int
        or item.get("execution") != execution
    ):
        fail("session-execution-coordinate")
    nonce = item.get("nonce")
    if not isinstance(nonce, str) or not NONCE_RE.fullmatch(nonce):
        fail("session-execution-nonce")
    expected_blob = _expected_blob(run_id, attempt, purpose, execution, nonce)
    if item.get("resultBlob") != expected_blob:
        fail("session-execution-blob")
    history_id = item.get("historyId")
    webjobs_run_id = item.get("webJobsRunId")
    if (history_id is None) != (webjobs_run_id is None):
        fail("session-history-partial")
    if history_id is not None:
        exact_history_id(history_id, "session-history-id")
        exact_safe_id(webjobs_run_id, "session-webjob-run-id")
    expected_prefix = item.get("expectedPrefix")
    artifact_digest = item.get("artifactZipSha256")
    request_digest = item.get("requestSha256")
    if operation == "persist-actions-artifact":
        if not isinstance(expected_prefix, str) or not PREFIX_RE.fullmatch(expected_prefix):
            fail("session-persistence-prefix")
        exact_digest(artifact_digest, "session-artifact-digest")
        exact_digest(request_digest, "session-request-digest")
    elif any(value is not None for value in (expected_prefix, artifact_digest, request_digest)):
        fail("session-nonpersistence-expectation")
    return dict(item)


def validate_expected_executions(
    mode: object,
    executions: object,
    run_id: str,
    attempt: str,
) -> list[dict[str, Any]]:
    if not isinstance(mode, str) or mode not in MATRICES:
        fail("session-mode")
    if not isinstance(executions, list) or len(executions) != len(MATRICES[mode]):
        fail("session-execution-matrix")
    by_coordinate: dict[tuple[str, int], object] = {}
    for item in executions:
        if not isinstance(item, dict):
            fail("session-execution-fields")
        purpose = item.get("purpose")
        execution = item.get("execution")
        if not isinstance(purpose, str) or type(execution) is not int:
            fail("session-execution-coordinate")
        coordinate = (purpose, execution)
        if coordinate in by_coordinate:
            fail("session-execution-duplicate")
        by_coordinate[coordinate] = item
    if set(by_coordinate) != set(MATRICES[mode]):
        fail("session-execution-matrix")
    normalized: list[dict[str, Any]] = []
    for coordinate, operation in MATRICES[mode].items():
        normalized.append(_validate_execution(
            by_coordinate[coordinate],
            run_id=run_id,
            attempt=attempt,
            coordinate=coordinate,
            operation=operation,
        ))
    nonces = [item["nonce"] for item in normalized]
    blobs = [item["resultBlob"] for item in normalized]
    history_ids = [item["historyId"] for item in normalized if item["historyId"] is not None]
    webjobs_run_ids = [
        item["webJobsRunId"] for item in normalized if item["webJobsRunId"] is not None
    ]
    if any((
        len(set(nonces)) != len(nonces),
        len(set(blobs)) != len(blobs),
        len(set(history_ids)) != len(history_ids),
        len(set(webjobs_run_ids)) != len(webjobs_run_ids),
    )):
        fail("session-execution-reuse")
    return normalized


def assessment_claim_binding(session: Mapping[str, Any]) -> str:
    binding = {
        "schema": session.get("schema"),
        "sessionId": session.get("sessionId"),
        "fence": session.get("fence"),
        "phase": session.get("phase"),
        "mode": session.get("mode"),
        "leaseOwner": session.get("leaseOwner"),
        "leaseStartedAt": session.get("leaseStartedAt"),
        "leaseExpiresAt": session.get("leaseExpiresAt"),
        "claimId": session.get("claimId"),
        "claimant": session.get("claimant"),
        "claimedAt": session.get("claimedAt"),
        "githubRunId": session.get("githubRunId"),
        "githubRunAttempt": session.get("githubRunAttempt"),
        "controlWorkflowSha": session.get("controlWorkflowSha"),
        "sessionTokenSha256": session.get("sessionTokenSha256"),
        "packageSha256": session.get("packageSha256"),
        "helperSha256": session.get("helperSha256"),
        "runnerAuthorityGenerationSha256": session.get(
            "runnerAuthorityGenerationSha256"
        ),
        "expectedExecutions": session.get("expectedExecutions"),
    }
    return digest_bytes(canonical_json(binding))


def validate_assessment(
    assessment: object, session: Mapping[str, Any]
) -> dict[str, Any]:
    if not isinstance(assessment, dict) or set(assessment) != ASSESSMENT_KEYS:
        fail("assessment-fields")
    if assessment.get("schema") != ASSESSMENT_SCHEMA:
        fail("assessment-schema")
    if assessment.get("claimBindingSha256") != assessment_claim_binding(session):
        fail("assessment-claim-binding")

    actions = assessment.get("cleanupActions")
    action_keys = {"stop", "reseal", "deleteExactTransientSettings"}
    if (
        not isinstance(actions, dict)
        or set(actions) != action_keys
        or any(value not in {"passed", "failed"} for value in actions.values())
    ):
        fail("assessment-actions")

    bridge = assessment.get("bridgePostcondition")
    if not isinstance(bridge, dict) or set(bridge) != BRIDGE_ASSESSMENT_KEYS:
        fail("assessment-bridge-fields")
    for key in (
        "postureExact",
        "persistentSettingsExact",
        "transientSettingsPresent",
        "unknownSettingsPresent",
    ):
        if type(bridge.get(key)) is not bool:
            fail("assessment-bridge-types")
    unknown_digest = bridge.get("unknownSettingNamesSha256")
    if bridge["unknownSettingsPresent"]:
        if unknown_digest is not None:
            exact_digest(unknown_digest, "assessment-bridge-unknown-digest")
    elif unknown_digest is not None:
        fail("assessment-bridge-unknown-digest")
    bridge_sealed = (
        bridge["postureExact"]
        and bridge["persistentSettingsExact"]
        and not bridge["transientSettingsPresent"]
        and not bridge["unknownSettingsPresent"]
    )
    if bridge.get("status") != ("sealed" if bridge_sealed else "indeterminate"):
        fail("assessment-bridge-status")

    reconciliation = assessment.get("resultReconciliation")
    if not isinstance(reconciliation, dict) or set(reconciliation) != RECONCILIATION_KEYS:
        fail("assessment-reconciliation-fields")
    expected = session.get("expectedExecutions")
    proofs = reconciliation.get("executions")
    if (
        reconciliation.get("resultAccess") != "read-only"
        or type(reconciliation.get("expectedExecutionCount")) is not int
        or reconciliation.get("expectedExecutionCount") != len(expected)
        or not isinstance(proofs, list)
        or len(proofs) != len(expected)
    ):
        fail("assessment-reconciliation-shape")
    all_valid = True
    for proof, execution in zip(proofs, expected):
        if not isinstance(proof, dict) or set(proof) != RESULT_PROOF_KEYS:
            fail("assessment-proof-fields")
        status = proof.get("status")
        if any((
            proof.get("schema") != RESULT_PROOF_SCHEMA,
            status not in {"valid", "indeterminate"},
            proof.get("purpose") != execution["purpose"],
            type(proof.get("execution")) is not int,
            proof.get("execution") != execution["execution"],
            proof.get("historyId") != execution["historyId"],
            proof.get("webJobsRunId") != execution["webJobsRunId"],
        )):
            fail("assessment-proof-binding")
        if status == "valid":
            if execution["historyId"] is None or execution["webJobsRunId"] is None:
                fail("assessment-proof-valid-without-history")
            exact_digest(proof.get("envelopeSha256"), "assessment-proof-envelope")
            exact_digest(proof.get("resultSha256"), "assessment-proof-result")
        else:
            all_valid = False
            envelope_digest = proof.get("envelopeSha256")
            if envelope_digest is not None:
                exact_digest(envelope_digest, "assessment-proof-envelope")
            if proof.get("resultSha256") is not None:
                fail("assessment-proof-indeterminate-result")

    persistence_case = reconciliation.get("persistenceCase")
    allowed_cases = {
        "created-or-recovered-then-idempotent",
        "already-complete-before-both-executions",
    }
    if session.get("mode") == "preflight":
        if persistence_case is not None:
            fail("assessment-preflight-persistence-case")
        reconciled = all_valid
    else:
        if persistence_case is not None and persistence_case not in allowed_cases:
            fail("assessment-persistence-case")
        reconciled = all_valid and persistence_case in allowed_cases
    if reconciliation.get("status") != (
        "reconciled" if reconciled else "indeterminate"
    ):
        fail("assessment-reconciliation-status")

    issues = assessment.get("issues")
    if (
        not isinstance(issues, list)
        or len(issues) > 64
        or issues != sorted(set(issues))
        or any(
            not isinstance(issue, str)
            or not re.fullmatch(r"[a-z0-9:-]{1,160}", issue)
            for issue in issues
        )
    ):
        fail("assessment-issues")
    complete = (
        all(value == "passed" for value in actions.values())
        and bridge_sealed
        and reconciled
        and not issues
    )
    if assessment.get("outcome") != ("complete" if complete else "indeterminate"):
        fail("assessment-outcome")
    return dict(assessment)


def validate_receipt_reference(
    reference: object, session: Mapping[str, Any], assessment: Mapping[str, Any]
) -> dict[str, Any]:
    if not isinstance(reference, dict) or set(reference) != RECEIPT_REFERENCE_KEYS:
        fail("session-receipt-fields")
    expected_path = f'{EVIDENCE_PREFIX}/{session["sessionId"]}/{session["fence"]}.json'
    expected_status = (
        "sealed-reconciled"
        if assessment.get("outcome") == "complete"
        else "sealed-indeterminate"
    )
    if reference.get("path") != expected_path or reference.get("status") != expected_status:
        fail("session-receipt-binding")
    exact_digest(reference.get("sha256"), "session-receipt-digest")
    return dict(reference)


def validate_authority_fence_reference(
    reference: object, session: Mapping[str, Any]
) -> dict[str, Any]:
    if not isinstance(reference, dict) or set(reference) != AUTHORITY_FENCE_REFERENCE_KEYS:
        fail("session-authority-fence-fields")
    expected_path = (
        f'{AUTHORITY_FENCE_PREFIX}/{session["sessionId"]}/{session["fence"]}.json'
    )
    if (
        reference.get("path") != expected_path
        or reference.get("status") != "runner-mutation-authority-fenced"
        or reference.get("runnerAuthorityGenerationSha256")
        != session.get("runnerAuthorityGenerationSha256")
    ):
        fail("session-authority-fence-binding")
    exact_digest(reference.get("sha256"), "session-authority-fence-digest")
    return dict(reference)


def validate_session(document: object) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != SESSION_KEYS:
        fail("session-fields")
    if document.get("schema") != SESSION_SCHEMA:
        fail("session-schema")
    if document.get("status") not in {"active", "cleanup-claimed", "closed"}:
        fail("session-status")
    session_id = document.get("sessionId")
    if not isinstance(session_id, str) or not NONCE_RE.fullmatch(session_id):
        fail("session-id")
    fence = document.get("fence")
    if type(fence) is not int or fence <= 0:
        fail("session-fence")
    if document.get("phase") not in PHASES:
        fail("session-phase")
    exact_safe_id(document.get("leaseOwner"), "session-lease-owner")
    lease_started = document.get("leaseStartedAt")
    lease_expires = document.get("leaseExpiresAt")
    if parse_server_time(lease_expires) <= parse_server_time(lease_started):
        fail("session-lease-order")
    run_id = exact_positive(document.get("githubRunId"), "session-run-id")
    attempt = exact_positive(document.get("githubRunAttempt"), "session-run-attempt")
    exact_sha(document.get("controlWorkflowSha"), "session-control-sha")
    exact_digest(document.get("sessionTokenSha256"), "session-token-digest")
    exact_digest(
        document.get("runnerAuthorityGenerationSha256"),
        "session-authority-generation-digest",
    )
    if document.get("packageSha256") != PACKAGE_SHA256 or document.get("helperSha256") != HELPER_SHA256:
        fail("session-package-binding")
    normalized = validate_expected_executions(
        document.get("mode"), document.get("expectedExecutions"), run_id, attempt
    )
    session_for_binding = dict(document)
    session_for_binding["expectedExecutions"] = normalized
    status = document["status"]
    claim_values = (
        document.get("claimId"),
        document.get("claimant"),
        document.get("claimedAt"),
        document.get("claimLeaseExpiresAt"),
    )
    if status == "active":
        if any(value is not None for value in claim_values) or document.get("assessment") is not None or document.get("authorityFence") is not None or document.get("receipt") is not None:
            fail("session-active-state")
    else:
        claim_id, claimant, claimed_at, claim_expires = claim_values
        if not isinstance(claim_id, str) or not NONCE_RE.fullmatch(claim_id):
            fail("session-claim-id")
        exact_safe_id(claimant, "session-claimant")
        if parse_server_time(claim_expires) <= parse_server_time(claimed_at):
            fail("session-claim-order")
        if status == "cleanup-claimed" and document.get("receipt") is not None:
            fail("session-claimed-receipt")
        assessment = document.get("assessment")
        if assessment is not None:
            assessment = validate_assessment(assessment, session_for_binding)
        authority_fence = document.get("authorityFence")
        if authority_fence is not None:
            validate_authority_fence_reference(authority_fence, session_for_binding)
        if status == "closed":
            if assessment is None or authority_fence is None or document.get("receipt") is None:
                fail("session-closed-state")
            validate_receipt_reference(
                document.get("receipt"), session_for_binding, assessment
            )
    result = dict(document)
    result["expectedExecutions"] = normalized
    if status != "active" and document.get("assessment") is not None:
        result["assessment"] = validate_assessment(
            document.get("assessment"), result
        )
    return result


def read_session_record(record: StateRecord) -> dict[str, Any]:
    record.validate()
    return validate_session(strict_canonical_json(record.body, MAX_SESSION_BYTES, "state"))


def build_review_session(
    *,
    session_id: str,
    fence: int,
    phase: str,
    mode: str,
    lease_owner: str,
    server_time: str,
    github_run_id: str,
    github_run_attempt: str,
    control_workflow_sha: str,
    session_token_sha256: str,
    runner_authority_generation_sha256: str,
    expected_executions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a canonical review fixture; this function performs no I/O."""
    parse_server_time(server_time)
    document = {
        "schema": SESSION_SCHEMA,
        "status": "active",
        "sessionId": session_id,
        "fence": fence,
        "phase": phase,
        "mode": mode,
        "leaseOwner": lease_owner,
        "leaseStartedAt": server_time,
        "leaseExpiresAt": expires_from(server_time, SESSION_LEASE_SECONDS),
        "claimId": None,
        "claimant": None,
        "claimedAt": None,
        "claimLeaseExpiresAt": None,
        "githubRunId": github_run_id,
        "githubRunAttempt": github_run_attempt,
        "controlWorkflowSha": control_workflow_sha,
        "sessionTokenSha256": session_token_sha256,
        "packageSha256": PACKAGE_SHA256,
        "helperSha256": HELPER_SHA256,
        "runnerAuthorityGenerationSha256": runner_authority_generation_sha256,
        "expectedExecutions": expected_executions,
        "assessment": None,
        "authorityFence": None,
        "receipt": None,
    }
    return validate_session(document)


def open_session(
    boundary: CleanupBoundary,
    *,
    reviewed_mutating_sha: str,
    session_id: str,
    phase: str,
    mode: str,
    lease_owner: str,
    github_run_id: str,
    github_run_attempt: str,
    session_token_sha256: str,
    runner_authority_generation_sha256: str,
    expected_executions: list[dict[str, Any]],
) -> StateRecord:
    """Open the singleton session using only an authenticated server clock.

    A prior unresolved session is never replaced.  The live production factory
    cannot call this function while the reviewed SHA in the machine contract is
    null; the explicit SHA parameter exists so the state transition can be
    exhaustively exercised before that later activation commit.
    """
    reviewed_mutating_sha = exact_sha(reviewed_mutating_sha, "reviewed-mutating-sha")
    runner_authority_generation_sha256 = exact_digest(
        runner_authority_generation_sha256,
        "open-session-authority-generation-digest",
    )
    prior_record = boundary.read_state()
    if prior_record is None:
        server_time = boundary.probe_server_time()
        parse_server_time(server_time)
        fence = 1
    else:
        prior_record.validate()
        prior = read_session_record(prior_record)
        if prior["status"] != "closed":
            fail("open-session-unresolved-prior")
        if (
            prior["runnerAuthorityGenerationSha256"]
            == runner_authority_generation_sha256
        ):
            fail("open-session-authority-generation-reuse")
        retain_closure_marker(boundary, prior_record)
        server_time = boundary.probe_server_time()
        parse_server_time(server_time)
        fence = prior["fence"] + 1
    document = build_review_session(
        session_id=session_id,
        fence=fence,
        phase=phase,
        mode=mode,
        lease_owner=lease_owner,
        server_time=server_time,
        github_run_id=github_run_id,
        github_run_attempt=github_run_attempt,
        control_workflow_sha=reviewed_mutating_sha,
        session_token_sha256=session_token_sha256,
        runner_authority_generation_sha256=runner_authority_generation_sha256,
        expected_executions=expected_executions,
    )
    body = canonical_json(document)
    if prior_record is None:
        return boundary.create_state(body).validate()
    return boundary.replace_state(body, prior_record.etag).validate()


def _load_current(boundary: CleanupBoundary) -> tuple[StateRecord, dict[str, Any]]:
    record = boundary.read_state()
    if record is None:
        fail("state-missing")
    return record.validate(), read_session_record(record)


def heartbeat_session(
    boundary: CleanupBoundary,
    *,
    session_id: str,
    fence: int,
    lease_owner: str,
    phase: str,
    expected_executions: list[dict[str, Any]],
) -> StateRecord:
    record, current = _load_current(boundary)
    if (
        current["status"] != "active"
        or current["sessionId"] != session_id
        or current["fence"] != fence
        or current["leaseOwner"] != lease_owner
    ):
        fail("heartbeat-fenced")
    now = parse_server_time(record.server_time)
    if now > parse_server_time(current["leaseExpiresAt"]):
        fail("heartbeat-expired")
    if phase not in PHASES or PHASES.index(phase) < PHASES.index(current["phase"]):
        fail("heartbeat-phase")
    normalized = validate_expected_executions(
        current["mode"], expected_executions, current["githubRunId"], current["githubRunAttempt"]
    )
    for before, after in zip(current["expectedExecutions"], normalized):
        immutable = set(EXECUTION_KEYS) - {"historyId", "webJobsRunId"}
        if any(before[key] != after[key] for key in immutable):
            fail("heartbeat-coordinate-change")
        if before["historyId"] is not None and (
            before["historyId"] != after["historyId"]
            or before["webJobsRunId"] != after["webJobsRunId"]
        ):
            fail("heartbeat-history-change")
    updated = dict(current)
    updated["phase"] = phase
    updated["leaseExpiresAt"] = expires_from(record.server_time, SESSION_LEASE_SECONDS)
    updated["expectedExecutions"] = normalized
    body = canonical_json(validate_session(updated))
    return boundary.replace_state(body, record.etag).validate()


@dataclass(frozen=True)
class CleanupClaim:
    record: StateRecord
    session: dict[str, Any]


def claim_expired_session(boundary: CleanupBoundary, claimant: str) -> CleanupClaim | None:
    claimant = exact_safe_id(claimant, "claimant-invalid")
    record = boundary.read_state()
    if record is None:
        return None
    record.validate()
    current = read_session_record(record)
    now = parse_server_time(record.server_time)
    if current["status"] == "closed":
        retain_closure_marker(boundary, record)
        return None
    if current["status"] == "active" and now <= parse_server_time(current["leaseExpiresAt"]):
        return None
    if current["status"] == "cleanup-claimed":
        if current["claimant"] == claimant and now <= parse_server_time(current["claimLeaseExpiresAt"]):
            return CleanupClaim(record, current)
        if now <= parse_server_time(current["claimLeaseExpiresAt"]):
            return None
    fence = current["fence"] + 1
    claim_id = hashlib.sha256(
        f'{current["sessionId"]}:{fence}:{claimant}'.encode("ascii")
    ).hexdigest()[:32]
    claimed = dict(current)
    claimed.update({
        "status": "cleanup-claimed",
        "fence": fence,
        "claimId": claim_id,
        "claimant": claimant,
        "claimedAt": record.server_time,
        "claimLeaseExpiresAt": expires_from(record.server_time, CLEANUP_LEASE_SECONDS),
        "assessment": None,
        "authorityFence": None,
        "receipt": None,
    })
    body = canonical_json(validate_session(claimed))
    written = boundary.replace_state(body, record.etag).validate()
    return CleanupClaim(written, read_session_record(written))


def _issue(issues: set[str], value: str) -> None:
    if not re.fullmatch(r"[a-z0-9:-]{1,160}", value):
        value = "indeterminate-contract-failure"
    issues.add(value)


def _validate_bridge_snapshot(snapshot: BridgeSnapshot, issues: set[str]) -> dict[str, Any]:
    if snapshot.resource_id != BRIDGE_RESOURCE_ID:
        _issue(issues, "bridge-resource-mismatch")
    if not isinstance(snapshot.posture, Mapping) or set(snapshot.posture) != set(SEALED_POSTURE):
        _issue(issues, "bridge-posture-fields")
        posture_exact = False
    else:
        posture_exact = all(
            type(snapshot.posture.get(key)) is type(value) and snapshot.posture.get(key) == value
            for key, value in SEALED_POSTURE.items()
        )
        if not posture_exact:
            _issue(issues, "bridge-postcondition-failed")
    settings = snapshot.settings
    if not isinstance(settings, Mapping) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in settings.items()
    ):
        _issue(issues, "bridge-settings-invalid")
        return {
            "status": "indeterminate",
            "postureExact": posture_exact,
            "persistentSettingsExact": False,
            "transientSettingsPresent": True,
            "unknownSettingsPresent": True,
            "unknownSettingNamesSha256": None,
        }
    names = set(settings)
    persistent_names = set(PERSISTENT_SETTINGS)
    transient_names = set(TRANSIENT_SETTINGS)
    unknown = sorted(names - persistent_names - transient_names)
    transient_present = bool(names & transient_names)
    persistent_exact = names >= persistent_names and all(
        settings.get(name) == value for name, value in PERSISTENT_SETTINGS.items()
    )
    if unknown:
        _issue(issues, "unknown-settings-present")
    if transient_present:
        _issue(issues, "transient-settings-remain")
    if not persistent_exact:
        _issue(issues, "persistent-settings-mismatch")
    exact_names = names == persistent_names
    if not exact_names and not unknown and not transient_present:
        _issue(issues, "persistent-settings-mismatch")
    unknown_digest = digest_bytes(canonical_json(unknown)) if unknown else None
    return {
        "status": "sealed" if posture_exact and persistent_exact and exact_names else "indeterminate",
        "postureExact": posture_exact,
        "persistentSettingsExact": persistent_exact and exact_names,
        "transientSettingsPresent": transient_present,
        "unknownSettingsPresent": bool(unknown),
        "unknownSettingNamesSha256": unknown_digest,
    }


def _validate_storage_result(result: object, execution: Mapping[str, Any], session: Mapping[str, Any]) -> None:
    expected_keys = {
        "schemaVersion", "status", "canaryBlob", "writerCreate", "readerRead",
        "writerUnconditionalOverwriteDenied", "writerReadDenied", "readerWriteDenied",
        "localPrefixGuard",
    }
    expected_canary = (
        f'v1/canaries/storage-rbac/{session["githubRunId"]}/'
        f'{session["githubRunAttempt"]}/{execution["nonce"]}.json'
    )
    if not isinstance(result, dict) or set(result) != expected_keys or any((
        type(result.get("schemaVersion")) is not int,
        result.get("schemaVersion") != 1,
        result.get("status") != "storage-rbac-ready",
        result.get("canaryBlob") != expected_canary,
        result.get("writerCreate") != "passed",
        result.get("readerRead") != "passed",
        result.get("writerUnconditionalOverwriteDenied") != "passed",
        result.get("writerReadDenied") != "passed",
        result.get("readerWriteDenied") != "passed",
        result.get("localPrefixGuard") != "passed-before-network",
    )):
        fail("result-storage-contract")


def _validate_runtime_result(result: object) -> None:
    expected_keys = {
        "schemaVersion", "status", "python", "isolated", "helperSha256",
        "runnerSha256", "settingsJobSha256", "writerClientId", "readerClientId",
    }
    if not isinstance(result, dict) or set(result) != expected_keys or any((
        type(result.get("schemaVersion")) is not int,
        result.get("schemaVersion") != 1,
        result.get("status") != "runtime-ready",
        result.get("python") != "3.12",
        result.get("isolated") is not True,
        result.get("helperSha256") != HELPER_SHA256,
        result.get("runnerSha256") != RUNNER_SHA256,
        result.get("settingsJobSha256") != SETTINGS_SHA256,
        result.get("writerClientId") != "1a0d95c5-bbd5-4b57-bd6c-6d5645a50e16",
        result.get("readerClientId") != "a52c21e2-b465-4f01-88b8-44bb5fb8b306",
    )):
        fail("result-runtime-contract")


def _validate_persistence_result(result: object, execution: Mapping[str, Any]) -> None:
    expected_keys = {
        "status", "prefix", "artifactZipSha256", "requestSha256", "manifestSha256",
        "fileCount", "createdBlobCount", "overwriteNegative", "outOfPrefixNegative",
    }
    if not isinstance(result, dict) or set(result) != expected_keys:
        fail("result-persistence-contract")
    created = result.get("createdBlobCount")
    allowed_count = type(created) is int and 0 <= created <= 20
    allowed_overwrite = (
        (created == 0 and result.get("overwriteNegative") == "not-run-completed")
        or (type(created) is int and 1 <= created <= 20 and result.get("overwriteNegative") == "passed")
    )
    if any((
        result.get("status") != "complete",
        result.get("prefix") != execution.get("expectedPrefix"),
        result.get("artifactZipSha256") != execution.get("artifactZipSha256"),
        result.get("requestSha256") != execution.get("requestSha256"),
        not isinstance(result.get("manifestSha256"), str) or not SHA256_RE.fullmatch(result.get("manifestSha256", "")),
        result.get("fileCount") != 19,
        not allowed_count,
        not allowed_overwrite,
        result.get("outOfPrefixNegative") != "passed",
    )):
        fail("result-persistence-contract")


def validate_result_envelope(
    body: bytes,
    execution: Mapping[str, Any],
    session: Mapping[str, Any],
    history: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(history, Mapping) or set(history) != HISTORY_KEYS:
        fail("history-fields")
    exact_history_id(history.get("id"), "history-resource-id")
    if any((
        history.get("id") != execution.get("historyId"),
        history.get("web_job_name") != WEBJOB_NAME,
        history.get("web_job_id") != execution.get("webJobsRunId"),
        history.get("status") != "Success",
        not isinstance(history.get("start_time"), str) or not ARM_TIME_RE.fullmatch(history.get("start_time", "")),
        not isinstance(history.get("end_time"), str) or not ARM_TIME_RE.fullmatch(history.get("end_time", "")),
    )):
        fail("history-binding")
    if parse_arm_time(history["end_time"]) < parse_arm_time(history["start_time"]):
        fail("history-time-order")
    envelope = strict_canonical_json(body, MAX_RESULT_BYTES, "result-envelope")
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_KEYS:
        fail("result-envelope-fields")
    expected = {
        "schema": RESULT_SCHEMA,
        "status": "attested",
        "operation": execution["operation"],
        "purpose": execution["purpose"],
        "execution": execution["execution"],
        "nonce": execution["nonce"],
        "resultBlob": execution["resultBlob"],
        "githubRunId": session["githubRunId"],
        "githubRunAttempt": session["githubRunAttempt"],
        "controlWorkflowSha": session["controlWorkflowSha"],
        "packageSha256": PACKAGE_SHA256,
        "helperSha256": HELPER_SHA256,
        "webJobsName": WEBJOB_NAME,
        "webJobsType": "triggered",
        "webJobsRunId": execution["webJobsRunId"],
    }
    if any(type(envelope.get(key)) is not type(value) or envelope.get(key) != value for key, value in expected.items()):
        fail("result-envelope-binding")
    result = envelope.get("result")
    if execution["operation"] == "storage-rbac-canary":
        _validate_storage_result(result, execution, session)
    elif execution["operation"] == "runtime-canary":
        _validate_runtime_result(result)
    elif execution["operation"] == "persist-actions-artifact":
        _validate_persistence_result(result, execution)
    else:
        fail("result-operation")
    result_body = canonical_json(result)
    result_digest = digest_bytes(result_body)
    if envelope.get("resultSha256") != result_digest:
        fail("result-digest")
    return {
        "schema": RESULT_PROOF_SCHEMA,
        "status": "valid",
        "purpose": execution["purpose"],
        "execution": execution["execution"],
        "historyId": history["id"],
        "webJobsRunId": history["web_job_id"],
        "envelopeSha256": digest_bytes(body),
        "resultSha256": result_digest,
    }


def _validate_persistence_pair(
    executions: list[dict[str, Any]],
    envelope_results: Mapping[tuple[str, int], Mapping[str, Any]],
) -> str:
    if len(executions) != 3:
        fail("persistence-pair-missing")
    first = envelope_results.get(("persistence-result", 1))
    second = envelope_results.get(("persistence-result", 2))
    if first is None or second is None:
        fail("persistence-pair-missing")
    immutable = (
        "status", "prefix", "artifactZipSha256", "requestSha256", "manifestSha256",
        "fileCount", "outOfPrefixNegative",
    )
    if any(first.get(key) != second.get(key) for key in immutable):
        fail("persistence-pair-mismatch")
    first_count = first.get("createdBlobCount")
    second_count = second.get("createdBlobCount")
    first_overwrite = first.get("overwriteNegative")
    second_overwrite = second.get("overwriteNegative")
    if 1 <= first_count <= 20 and first_overwrite == "passed" and second_count == 0 and second_overwrite == "not-run-completed":
        return "created-or-recovered-then-idempotent"
    if first_count == 0 and second_count == 0 and first_overwrite == second_overwrite == "not-run-completed":
        return "already-complete-before-both-executions"
    fail("persistence-pair-invalid")


def _assess_results(
    boundary: CleanupBoundary,
    session: Mapping[str, Any],
    issues: set[str],
) -> dict[str, Any]:
    proofs: list[dict[str, Any]] = []
    envelope_results: dict[tuple[str, int], Mapping[str, Any]] = {}
    for execution in session["expectedExecutions"]:
        coordinate = f'{execution["purpose"]}:{execution["execution"]}'
        if execution["historyId"] is None or execution["webJobsRunId"] is None:
            _issue(issues, f"result:{coordinate}:history-binding-missing")
            proofs.append({
                "schema": RESULT_PROOF_SCHEMA,
                "status": "indeterminate",
                "purpose": execution["purpose"],
                "execution": execution["execution"],
                "historyId": execution["historyId"],
                "webJobsRunId": execution["webJobsRunId"],
                "envelopeSha256": None,
                "resultSha256": None,
            })
            continue
        try:
            history = boundary.read_webjob_history(execution["historyId"])
        except Exception:
            history = None
        if history is None:
            _issue(issues, f"result:{coordinate}:history-missing")
            proofs.append({
                "schema": RESULT_PROOF_SCHEMA,
                "status": "indeterminate",
                "purpose": execution["purpose"],
                "execution": execution["execution"],
                "historyId": execution["historyId"],
                "webJobsRunId": execution["webJobsRunId"],
                "envelopeSha256": None,
                "resultSha256": None,
            })
            continue
        try:
            body = boundary.read_result(RESULT_CONTAINER, execution["resultBlob"], MAX_RESULT_BYTES)
        except Exception:
            body = None
        if body is None:
            _issue(issues, f"result:{coordinate}:envelope-missing")
            proofs.append({
                "schema": RESULT_PROOF_SCHEMA,
                "status": "indeterminate",
                "purpose": execution["purpose"],
                "execution": execution["execution"],
                "historyId": execution["historyId"],
                "webJobsRunId": execution["webJobsRunId"],
                "envelopeSha256": None,
                "resultSha256": None,
            })
            continue
        try:
            proof = validate_result_envelope(body, execution, session, history)
            envelope = strict_canonical_json(body, MAX_RESULT_BYTES, "result-envelope")
            envelope_results[(execution["purpose"], execution["execution"])] = envelope["result"]
            proofs.append(proof)
        except CleanupContractError as exc:
            _issue(issues, f"result:{coordinate}:{exc.code}")
            proofs.append({
                "schema": RESULT_PROOF_SCHEMA,
                "status": "indeterminate",
                "purpose": execution["purpose"],
                "execution": execution["execution"],
                "historyId": execution["historyId"],
                "webJobsRunId": execution["webJobsRunId"],
                "envelopeSha256": digest_bytes(body),
                "resultSha256": None,
            })
    pair_case: str | None = None
    if session["mode"] == "persistence" and all(proof["status"] == "valid" for proof in proofs):
        try:
            pair_case = _validate_persistence_pair(session["expectedExecutions"], envelope_results)
        except CleanupContractError as exc:
            _issue(issues, f"result:persistence:{exc.code}")
    return {
        "status": "reconciled" if all(proof["status"] == "valid" for proof in proofs) and (session["mode"] != "persistence" or pair_case is not None) else "indeterminate",
        "resultAccess": "read-only",
        "expectedExecutionCount": len(session["expectedExecutions"]),
        "persistenceCase": pair_case,
        "executions": proofs,
    }


def assess_cleanup(boundary: CleanupBoundary, session: Mapping[str, Any]) -> dict[str, Any]:
    issues: set[str] = set()
    actions: dict[str, str] = {}
    for name, action in (
        ("stop", boundary.stop_bridge),
        ("reseal", boundary.reseal_bridge),
        ("deleteExactTransientSettings", lambda: boundary.delete_transient_settings(TRANSIENT_SETTINGS)),
    ):
        try:
            action()
            actions[name] = "passed"
        except Exception:
            actions[name] = "failed"
            _issue(issues, f"cleanup:{name.lower()}:failed")
    try:
        bridge = _validate_bridge_snapshot(boundary.read_bridge(), issues)
    except Exception:
        _issue(issues, "bridge-postcondition-unavailable")
        bridge = {
            "status": "indeterminate",
            "postureExact": False,
            "persistentSettingsExact": False,
            "transientSettingsPresent": True,
            "unknownSettingsPresent": True,
            "unknownSettingNamesSha256": None,
        }
    reconciliation = _assess_results(boundary, session, issues)
    outcome = (
        "complete"
        if not issues and bridge["status"] == "sealed" and reconciliation["status"] == "reconciled"
        else "indeterminate"
    )
    assessment = {
        "schema": ASSESSMENT_SCHEMA,
        "claimBindingSha256": assessment_claim_binding(session),
        "outcome": outcome,
        "cleanupActions": actions,
        "bridgePostcondition": bridge,
        "resultReconciliation": reconciliation,
        "issues": sorted(issues),
    }
    return validate_assessment(assessment, session)


def _same_claim(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return all(left.get(key) == right.get(key) for key in ("sessionId", "fence", "claimId", "claimant", "claimedAt"))


def stage_assessment(
    boundary: CleanupBoundary,
    claim: CleanupClaim,
    assessment: dict[str, Any] | None = None,
) -> CleanupClaim:
    record, current = _load_current(boundary)
    if current["status"] != "cleanup-claimed" or not _same_claim(current, claim.session):
        fail("assessment-fenced")
    if parse_server_time(record.server_time) > parse_server_time(current["claimLeaseExpiresAt"]):
        fail("assessment-claim-expired")
    fresh_assessment = assess_cleanup(boundary, current)
    if assessment is not None and assessment != fresh_assessment:
        fail("assessment-not-fresh")
    assessment = fresh_assessment
    record, latest = _load_current(boundary)
    if latest["status"] != "cleanup-claimed" or not _same_claim(latest, current):
        fail("assessment-fenced")
    if parse_server_time(record.server_time) > parse_server_time(latest["claimLeaseExpiresAt"]):
        fail("assessment-claim-expired")
    if latest["assessment"] is not None and latest["assessment"] != assessment:
        fail("assessment-conflict")
    updated = dict(latest)
    updated["assessment"] = assessment
    updated["claimLeaseExpiresAt"] = expires_from(record.server_time, CLEANUP_LEASE_SECONDS)
    body = canonical_json(validate_session(updated))
    written = boundary.replace_state(body, record.etag).validate()
    return CleanupClaim(written, read_session_record(written))


def receipt_path(session: Mapping[str, Any]) -> str:
    return f'{EVIDENCE_PREFIX}/{session["sessionId"]}/{session["fence"]}.json'


def build_receipt(session: Mapping[str, Any], reviewed_mutating_sha: str) -> dict[str, Any]:
    reviewed_mutating_sha = exact_sha(reviewed_mutating_sha, "receipt-reviewed-sha")
    session = validate_session(dict(session))
    if session["status"] != "cleanup-claimed":
        fail("receipt-session-status")
    if session["controlWorkflowSha"] != reviewed_mutating_sha:
        fail("receipt-reviewed-sha-mismatch")
    assessment = session.get("assessment")
    if assessment is None:
        fail("receipt-assessment-missing")
    authority_fence = session.get("authorityFence")
    if authority_fence is None:
        fail("receipt-authority-fence-missing")
    authority_fence = validate_authority_fence_reference(authority_fence, session)
    assessment = validate_assessment(assessment, session)
    outcome = assessment["outcome"]
    path = receipt_path(session)
    return {
        "schema": RECEIPT_SCHEMA,
        "status": "sealed-reconciled" if outcome == "complete" else "sealed-indeterminate",
        "contractId": CONTRACT_ID,
        "reviewedMutatingCommitSha": reviewed_mutating_sha,
        "claimedAt": session["claimedAt"],
        "authoritativeness": "requires-matching-immutable-closure-marker",
        "authorityFence": authority_fence,
        "session": {
            "sessionId": session["sessionId"],
            "fence": session["fence"],
            "claimId": session["claimId"],
            "claimant": session["claimant"],
            "phaseAtExpiry": session["phase"],
            "mode": session["mode"],
            "githubRunId": session["githubRunId"],
            "githubRunAttempt": session["githubRunAttempt"],
            "controlWorkflowSha": session["controlWorkflowSha"],
            "packageSha256": session["packageSha256"],
            "helperSha256": session["helperSha256"],
            "runnerAuthorityGenerationSha256": session[
                "runnerAuthorityGenerationSha256"
            ],
        },
        "bridge": {
            "resourceId": BRIDGE_RESOURCE_ID,
            "cleanupAuthority": "stop-reseal-delete-exact-transient-settings-only",
            "assessment": assessment,
        },
        "evidence": {
            "account": STORAGE_ACCOUNT,
            "container": EVIDENCE_CONTAINER,
            "path": path,
            "immutabilityState": "Locked",
            "retentionDays": 90,
            "writeMode": "create-only-exact-byte-idempotent",
        },
        "prohibitions": {
            "bridgeStart": False,
            "webJobRun": False,
            "deployOrPublish": False,
            "roleWrite": False,
            "resultWrite": False,
            "acceptedReleaseWrite": False,
            "blobDelete": False,
        },
    }


def validate_cleanup_receipt(
    receipt: object,
    session: Mapping[str, Any],
    reviewed_mutating_sha: str,
) -> dict[str, Any]:
    expected = build_receipt(session, reviewed_mutating_sha)
    if not isinstance(receipt, dict) or receipt != expected:
        fail("receipt-contract")
    return dict(receipt)


def _verify_evidence_policy(boundary: CleanupBoundary) -> None:
    policy = boundary.read_evidence_policy()
    if (
        not isinstance(policy, EvidencePolicy)
        or policy.container != EVIDENCE_CONTAINER
        or policy.state != "Locked"
        or type(policy.retention_days) is not int
        or policy.retention_days != 90
    ):
        fail("evidence-policy-invalid")


def authority_fence_path(session: Mapping[str, Any]) -> str:
    return f'{AUTHORITY_FENCE_PREFIX}/{session["sessionId"]}/{session["fence"]}.json'


def validate_authority_fence(
    body: bytes,
    session: Mapping[str, Any],
    authenticated_server_time: str,
) -> dict[str, Any]:
    document = strict_canonical_json(body, MAX_RECEIPT_BYTES, "authority-fence")
    if not isinstance(document, dict) or set(document) != AUTHORITY_FENCE_KEYS:
        fail("authority-fence-fields")
    if any((
        document.get("schema") != AUTHORITY_FENCE_SCHEMA,
        document.get("status") != "runner-mutation-authority-fenced",
        document.get("contractId") != CONTRACT_ID,
        document.get("sessionId") != session["sessionId"],
        document.get("fence") != session["fence"],
        document.get("claimId") != session["claimId"],
        document.get("claimedAt") != session["claimedAt"],
        document.get("githubRunId") != session["githubRunId"],
        document.get("githubRunAttempt") != session["githubRunAttempt"],
        document.get("controlWorkflowSha") != session["controlWorkflowSha"],
        document.get("runnerAuthorityGenerationSha256")
        != session["runnerAuthorityGenerationSha256"],
        document.get("bridgeResourceId") != BRIDGE_RESOURCE_ID,
    )):
        fail("authority-fence-binding")
    principal = document.get("controlPrincipalObjectId")
    if not isinstance(principal, str) or not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        principal,
    ):
        fail("authority-fence-principal")
    credential = document.get("federatedCredentialResourceId")
    if (
        not isinstance(credential, str)
        or not 1 <= len(credential) <= 2048
        or credential != credential.lower()
        or not credential.startswith(f"/subscriptions/{SUBSCRIPTION_ID}/")
        or "/federatedidentitycredentials/" not in credential
    ):
        fail("authority-fence-credential")
    assignments = document.get("mutatingRoleAssignmentIds")
    if (
        not isinstance(assignments, list)
        or not 1 <= len(assignments) <= 16
        or assignments != sorted(set(assignments))
        or any(
            not isinstance(item, str)
            or item != item.lower()
            or len(item) > 2048
            or not item.startswith(f"/subscriptions/{SUBSCRIPTION_ID}/")
            or "/providers/microsoft.authorization/roleassignments/" not in item
            for item in assignments
        )
    ):
        fail("authority-fence-assignments")
    revoked = parse_server_time(document.get("revokedAt"))
    expires = parse_server_time(document.get("lastPossibleTokenExpiryAt"))
    observed = parse_server_time(document.get("observedServerTime"))
    if expires < revoked or observed < expires:
        fail("authority-fence-time-order")
    if parse_server_time(authenticated_server_time) < observed:
        fail("authority-fence-not-yet-observed")
    exact_sha(
        document.get("producerReviewedCommitSha"),
        "authority-fence-producer-sha",
    )
    generation = {
        "schema": AUTHORITY_GENERATION_SCHEMA,
        "contractId": CONTRACT_ID,
        "bridgeResourceId": document["bridgeResourceId"],
        "controlWorkflowSha": document["controlWorkflowSha"],
        "controlPrincipalObjectId": document["controlPrincipalObjectId"],
        "federatedCredentialResourceId": document["federatedCredentialResourceId"],
        "mutatingRoleAssignmentIds": document["mutatingRoleAssignmentIds"],
        "producerReviewedCommitSha": document["producerReviewedCommitSha"],
    }
    if digest_bytes(canonical_json(generation)) != session[
        "runnerAuthorityGenerationSha256"
    ]:
        fail("authority-fence-generation-digest")
    return document


def bind_authority_fence(
    boundary: CleanupBoundary, claim: CleanupClaim
) -> CleanupClaim:
    record, current = _load_current(boundary)
    if current["status"] != "cleanup-claimed" or not _same_claim(current, claim.session):
        fail("authority-fence-fenced")
    path = authority_fence_path(current)
    body = boundary.read_authority_fence(
        AUTHORITY_FENCE_CONTAINER, path, MAX_RECEIPT_BYTES
    )
    if body is None:
        fail("authority-fence-missing")
    validate_authority_fence(body, current, record.server_time)
    reference = {
        "path": path,
        "sha256": digest_bytes(body),
        "status": "runner-mutation-authority-fenced",
        "runnerAuthorityGenerationSha256": current[
            "runnerAuthorityGenerationSha256"
        ],
    }
    if current.get("authorityFence") is not None:
        if current["authorityFence"] != reference:
            fail("authority-fence-conflict")
        return CleanupClaim(record, current)
    updated = dict(current)
    updated["authorityFence"] = reference
    written = boundary.replace_state(
        canonical_json(validate_session(updated)), record.etag
    ).validate()
    return CleanupClaim(written, read_session_record(written))


def refresh_claim_for_evidence(
    boundary: CleanupBoundary, claim: CleanupClaim
) -> CleanupClaim:
    record, current = _load_current(boundary)
    if current["status"] != "cleanup-claimed" or not _same_claim(current, claim.session):
        fail("receipt-fenced")
    if current.get("assessment") is None:
        fail("receipt-assessment-missing")
    if parse_server_time(record.server_time) > parse_server_time(current["claimLeaseExpiresAt"]):
        fail("receipt-claim-expired")
    fresh_assessment = assess_cleanup(boundary, current)
    record, latest = _load_current(boundary)
    if latest["status"] != "cleanup-claimed" or not _same_claim(latest, current):
        fail("receipt-fenced")
    if parse_server_time(record.server_time) > parse_server_time(latest["claimLeaseExpiresAt"]):
        fail("receipt-claim-expired")
    if latest.get("assessment") != fresh_assessment:
        fail("receipt-assessment-not-fresh")
    renewed = dict(latest)
    renewed["claimLeaseExpiresAt"] = expires_from(
        record.server_time, CLEANUP_LEASE_SECONDS
    )
    written = boundary.replace_state(
        canonical_json(validate_session(renewed)), record.etag
    ).validate()
    return CleanupClaim(written, read_session_record(written))


def create_or_replay_receipt(
    boundary: CleanupBoundary,
    claim: CleanupClaim,
    reviewed_mutating_sha: str,
) -> tuple[dict[str, Any], bytes, str, CleanupClaim]:
    _verify_evidence_policy(boundary)
    claim = bind_authority_fence(boundary, claim)
    claim = refresh_claim_for_evidence(boundary, claim)
    session = claim.session
    receipt = build_receipt(session, reviewed_mutating_sha)
    body = canonical_json(receipt)
    if not 0 < len(body) <= MAX_RECEIPT_BYTES:
        fail("receipt-size")
    path = receipt_path(session)
    created = boundary.create_evidence(EVIDENCE_CONTAINER, path, body)
    if type(created) is not bool:
        fail("receipt-create-response")
    existing = boundary.read_evidence(EVIDENCE_CONTAINER, path, MAX_RECEIPT_BYTES)
    if existing != body:
        fail("receipt-idempotency-conflict")
    return receipt, body, path, claim


def closure_marker_path(session: Mapping[str, Any]) -> str:
    return f'{EVIDENCE_PREFIX}/{session["sessionId"]}/{session["fence"]}.closed.json'


def retain_closure_marker(
    boundary: CleanupBoundary, closed_record: StateRecord
) -> dict[str, Any]:
    """Retain a WORM authority marker before a closed singleton may be replaced."""
    closed_record.validate()
    closed = read_session_record(closed_record)
    if closed["status"] != "closed":
        fail("closure-state-status")
    reference = closed["receipt"]
    receipt_body = boundary.read_evidence(
        EVIDENCE_CONTAINER, reference["path"], MAX_RECEIPT_BYTES
    )
    if receipt_body is None or digest_bytes(receipt_body) != reference["sha256"]:
        fail("closure-receipt-unavailable")
    receipt = strict_canonical_json(receipt_body, MAX_RECEIPT_BYTES, "closure-receipt")
    claimed = dict(closed)
    claimed["status"] = "cleanup-claimed"
    claimed["receipt"] = None
    validate_cleanup_receipt(receipt, claimed, claimed["controlWorkflowSha"])
    marker = {
        "schema": CLOSURE_SCHEMA,
        "status": "authoritative-closed",
        "sessionId": closed["sessionId"],
        "fence": closed["fence"],
        "closedStateSha256": digest_bytes(closed_record.body),
        "closedStateEtag": closed_record.etag,
        "authorityFence": closed["authorityFence"],
        "receipt": reference,
    }
    body = canonical_json(marker)
    path = closure_marker_path(closed)
    created = boundary.create_evidence(EVIDENCE_CONTAINER, path, body)
    if type(created) is not bool:
        fail("closure-create-response")
    if boundary.read_evidence(EVIDENCE_CONTAINER, path, MAX_RECEIPT_BYTES) != body:
        fail("closure-idempotency-conflict")
    return marker


def finalize_session(
    boundary: CleanupBoundary,
    claim: CleanupClaim,
    receipt: Mapping[str, Any],
    body: bytes,
    path: str,
) -> StateRecord:
    receipt = validate_cleanup_receipt(
        receipt, claim.session, claim.session["controlWorkflowSha"]
    )
    if body != canonical_json(receipt):
        fail("finalize-receipt-bytes")
    record, current = _load_current(boundary)
    if current["status"] != "cleanup-claimed" or not _same_claim(current, claim.session):
        fail("finalize-fenced")
    if current.get("assessment") != claim.session.get("assessment"):
        fail("finalize-assessment-mismatch")
    if parse_server_time(record.server_time) > parse_server_time(current["claimLeaseExpiresAt"]):
        fail("finalize-claim-expired")
    closed = dict(current)
    closed["status"] = "closed"
    closed["receipt"] = {
        "path": path,
        "sha256": digest_bytes(body),
        "status": receipt["status"],
    }
    written = boundary.replace_state(canonical_json(validate_session(closed)), record.etag)
    written.validate()
    retain_closure_marker(boundary, written)
    return written


def reconcile_claim(
    boundary: CleanupBoundary,
    claim: CleanupClaim,
    reviewed_mutating_sha: str,
) -> tuple[dict[str, Any], StateRecord]:
    reviewed_mutating_sha = exact_sha(reviewed_mutating_sha, "reviewed-mutating-sha")
    session = validate_session(claim.session)
    if session["status"] != "cleanup-claimed":
        fail("claim-status")
    if session["controlWorkflowSha"] != reviewed_mutating_sha:
        fail("reviewed-mutating-sha-mismatch")
    if session["assessment"] is None:
        claim = stage_assessment(boundary, claim)
        session = claim.session
    receipt, body, path, claim = create_or_replay_receipt(
        boundary, claim, reviewed_mutating_sha
    )
    closed = finalize_session(boundary, claim, receipt, body, path)
    return receipt, closed


class CleanupWatcher:
    """A testable engine whose production factory remains activation-blocked."""

    def __init__(
        self,
        boundary: CleanupBoundary,
        reviewed_mutating_sha: str,
        *,
        _activation_guard: object | None = None,
    ):
        if (
            _activation_guard is not _ACTIVATION_FACTORY_GUARD
            or MERGED_MUTATING_COMMIT_SHA is None
            or reviewed_mutating_sha != MERGED_MUTATING_COMMIT_SHA
        ):
            fail("activation-factory-required")
        self.boundary = boundary
        self.reviewed_mutating_sha = exact_sha(reviewed_mutating_sha, "reviewed-mutating-sha")

    @classmethod
    def from_dormant_contract(cls, boundary: CleanupBoundary) -> "CleanupWatcher":
        if MERGED_MUTATING_COMMIT_SHA is None:
            fail("activation-blocked-null-merged-sha")
        return cls(
            boundary,
            MERGED_MUTATING_COMMIT_SHA,
            _activation_guard=_ACTIVATION_FACTORY_GUARD,
        )

    def sweep(self, claimant: str) -> dict[str, Any]:
        claim = claim_expired_session(self.boundary, claimant)
        if claim is None:
            return {"schema": RECEIPT_SCHEMA, "status": "idle"}
        receipt, _ = reconcile_claim(
            self.boundary, claim, self.reviewed_mutating_sha
        )
        return receipt


def load_contract(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        fail("cleanup-contract-file")
    try:
        source = path.read_bytes()
        if not 0 < len(source) <= MAX_SESSION_BYTES or b"\0" in source:
            fail("cleanup-contract-file")
        normalized = source.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        if digest_bytes(normalized.encode("utf-8")) != CONTRACT_SHA256:
            fail("cleanup-contract-digest")
        document = json.loads(normalized, object_pairs_hook=_duplicate_rejector)
    except CleanupContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("cleanup-contract-json")
    if (
        not isinstance(document, dict)
        or document.get("schemaVersion") != 1
        or document.get("contractId") != CONTRACT_ID
        or document.get("status") != "dormant-pending-independent-review-deployment-and-live-canary"
        or document.get("immutableExternalControl", {}).get("mergedMutatingCommitSha") is not None
    ):
        fail("cleanup-contract-dormancy")
    return document


__all__ = [
    "ACCEPTED_RELEASE_CONTAINER",
    "AUTHORITY_FENCE_CONTAINER",
    "AUTHORITY_FENCE_SCHEMA",
    "AUTHORITY_GENERATION_SCHEMA",
    "BRIDGE_RESOURCE_ID",
    "BridgeSnapshot",
    "CleanupBoundary",
    "CleanupClaim",
    "CleanupContractError",
    "CleanupWatcher",
    "CONTRACT_SHA256",
    "EVIDENCE_CONTAINER",
    "EvidencePolicy",
    "HELPER_SHA256",
    "MATRICES",
    "PACKAGE_SHA256",
    "PERSISTENT_SETTINGS",
    "RESULT_CONTAINER",
    "RUNNER_SHA256",
    "SEALED_POSTURE",
    "SESSION_SCHEMA",
    "SETTINGS_SHA256",
    "StateRecord",
    "TRANSIENT_SETTINGS",
    "assess_cleanup",
    "build_receipt",
    "build_review_session",
    "canonical_json",
    "authority_fence_path",
    "claim_expired_session",
    "create_or_replay_receipt",
    "digest_bytes",
    "heartbeat_session",
    "load_contract",
    "open_session",
    "closure_marker_path",
    "reconcile_claim",
    "strict_canonical_json",
    "validate_result_envelope",
    "validate_session",
]
