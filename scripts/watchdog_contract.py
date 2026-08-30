#!/usr/bin/env python3
"""Exact shared PaperDesk/watchdog v2 machine-contract validation."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import stat
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "contracts" / "production_release_watchdog_contract.json"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
POSITIVE = re.compile(r"^[1-9][0-9]*$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
UTC_MILLISECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
ETAG = re.compile(r'^"[^"\r\n]{1,240}"$')
EVIDENCE_PATH = re.compile(r"^v2/[a-z0-9./-]{1,480}\.json$")
VERSION_ID = re.compile(r"^[A-Za-z0-9:._%+-]{1,192}$")

COMMON_RESPONSE_FIELDS = (
    "schemaVersion", "status", "operation", "previousStateSha256", "stateSha256",
    "stateETag", "transitionReceiptSha256", "transitionEvidencePath",
    "transitionEvidenceETag", "transitionEvidenceVersionId",
)

ACTIVATION_RULE = (
    "A PaperDesk workflow may use this control only after an independently reviewed commit containing all five "
    "required operations is merged, its full 40-character SHA is placed in source, the prior mutating SHA is "
    "denied, and live OIDC/provider/Kudu/Azure canaries pass."
)
ROLLBACK_ATOMICITY_RULE = (
    "The immutable control, not PaperDesk, must record rollback-workflow-observed, re-read the provider claim and "
    "exact attempt receipt, compare Kudu server/paperdesk-release-sha.txt to expectedCurrentLiveSha immediately "
    "before Azure mutation, deploy only the accepted rollback runtime, verify Kudu equals restoredSourceSha, and "
    "record rollback-completed before returning success."
)

EXPECTED_TRANSITIONS = {
    "publish-candidate": {
        "callerWorkflow": ".github/workflows/main_master-data-structure-sea-9c4e0d0d.yml",
        "requestFields": (
            "schemaVersion", "requestType", "operation", "expectedStateSha256",
            "candidateSha", "candidateRunId", "candidateRunAttempt", "completedAt",
            "deadline", "liveSha", "verificationReceiptSha256",
            "productionControlReceiptSha256", "rollbackBaselineReceiptSha256",
        ),
        "responseStatus": "candidate-published",
        "preconditions": (
            "provider state has one reviewed rollback baseline and no pending candidate",
            "candidateSha equals OIDC sha and candidateRunId/candidateRunAttempt equal the OIDC run",
            "liveSha equals candidateSha and the production control receipt proves that SHA through Kudu after deployment",
            "the provider recomputes and enforces deadline as exactly 1,440 minutes after completedAt",
            "rollbackBaselineReceiptSha256 equals rollbackBaseline.receiptSha256",
        ),
    },
    "accept-candidate": {
        "callerWorkflow": ".github/workflows/persist-accepted-release.yml",
        "requestFields": (
            "schemaVersion", "requestType", "operation", "expectedStateSha256",
            "candidateSha", "sourceRunId", "sourceRunAttempt", "candidateRunId",
            "candidateRunAttempt", "acceptanceRunId", "acceptanceRunAttempt",
            "productionAcceptanceReceiptSha256",
            "acceptedReleaseManifestSha256", "acceptedReleasePrefix",
            "registryManifestETag", "registryManifestVersionId",
        ),
        "responseStatus": "candidate-accepted",
        "preconditions": (
            "the exact pending candidate is live and its deadline has not passed",
            "dispatchGuard is available and attemptReceiptSha256 is null",
            "OIDC workflow_ref is the exact persist-accepted-release.yml workflow_run consumer; its OIDC run is distinct from the source acceptanceRunId and is retained in transition WORM evidence",
            "the accepted-release WORM manifest and production acceptance receipt independently bind the source run, candidate deployment run, acceptance run, registry ETag, and registry version ID",
            "the provider rereads the exact WORM manifest, promotes it to rollbackBaseline, and clears only the matching pending candidate",
        ),
    },
    "rollback-workflow-observed": {
        "callerWorkflow": ".github/workflows/main_master-data-structure-sea-9c4e0d0d.yml",
        "requestFields": (
            "schemaVersion", "requestType", "operation", "expectedStateSha256",
            "decisionReceiptSha256", "decisionEvidenceETag", "claimId",
            "dispatchGuardGeneration", "attemptReceiptSha256",
            "expectedCurrentLiveSha", "workflowRunId",
        ),
        "responseStatus": "requested-recorded",
        "preconditions": (
            "OIDC run_id equals workflowRunId and OIDC workflow_ref is the exact rollback workflow",
            "pendingCandidate.liveSha and pendingCandidate.candidateSha equal expectedCurrentLiveSha",
            "dispatchGuard is dispatching and its generation and attemptReceiptSha256 equal the request",
            "claimId, decision receipt digest, decision evidence ETag, and exact WORM attempt bytes all match provider metadata",
        ),
    },
    "rollback-authorize": {
        "callerWorkflow": ".github/workflows/main_master-data-structure-sea-9c4e0d0d.yml",
        "requestFields": (
            "schemaVersion", "requestType", "operation", "expectedStateSha256",
            "decisionReceiptSha256", "decisionEvidenceETag", "claimId",
            "dispatchGuardGeneration", "attemptReceiptSha256", "workflowRunId",
            "expectedCurrentLiveSha", "kuduObservedLiveSha", "kuduObservedAt",
            "kuduRequestSha256", "kuduResponseSha256",
        ),
        "responseStatus": "rollback-authorized",
        "preconditions": (
            "rollback-workflow-observed was recorded for this exact workflowRunId, claimId, generation, attempt receipt, decision receipt, and evidence ETag",
            "the immutable external control rereads the fresh provider state and exact WORM attempt receipt",
            "kuduObservedLiveSha equals expectedCurrentLiveSha and the Kudu request/response digests bind the immediately preceding observation",
            "the provider writes and reads back the authorization WORM receipt before changing requested to authorized",
        ),
    },
    "rollback-completed": {
        "callerWorkflow": ".github/workflows/main_master-data-structure-sea-9c4e0d0d.yml",
        "requestFields": (
            "schemaVersion", "requestType", "operation", "expectedStateSha256",
            "claimId", "dispatchGuardGeneration", "attemptReceiptSha256",
            "workflowRunId", "authorizationReceiptSha256", "expectedCurrentLiveSha",
            "rolledBackLiveSha", "liveVerificationReceiptSha256", "completedAt",
        ),
        "responseStatus": "rollback-completed",
        "preconditions": (
            "rollback-workflow-observed was recorded for this exact workflowRunId, claimId, generation, and attempt receipt",
            "the immutable external control receipt proves Kudu equaled expectedCurrentLiveSha immediately before Azure mutation",
            "the same control operation deployed the accepted rollback runtime and its live verification receipt proves Kudu equals rolledBackLiveSha after mutation",
            "rolledBackLiveSha equals rollbackBaseline.sourceSha and completion clears only the matching pending candidate",
        ),
    },
}

EXPECTED_RUN_BINDING = {
    "publish-candidate": {
        "eventName": "workflow_dispatch",
        "runIdField": "candidateRunId",
        "runAttemptField": "candidateRunAttempt",
    },
    "accept-candidate": {
        "eventName": "workflow_run",
        "runIdSource": "oidc-persistence-caller",
        "runAttemptSource": "oidc-persistence-caller",
        "mustDifferFromRunIdField": "acceptanceRunId",
    },
    "rollback-workflow-observed": {
        "eventName": "workflow_dispatch",
        "runIdField": "workflowRunId",
        "runAttempt": 1,
    },
    "rollback-authorize": {
        "eventName": "workflow_dispatch",
        "runIdField": "workflowRunId",
        "runAttempt": 1,
    },
    "rollback-completed": {
        "eventName": "workflow_dispatch",
        "runIdField": "workflowRunId",
        "runAttempt": 1,
    },
}

EXPECTED_STATE_FIELDS = {
    "topLevelFields": (
        "schemaVersion", "generatedAt", "sourceRepository", "rollbackBaseline", "pendingCandidate",
    ),
    "rollbackBaselineFields": (
        "schemaVersion", "receiptSha256", "evidencePath", "sourceSha", "sourceRunId",
        "sourceRunAttempt", "acceptanceRunId", "acceptanceRunAttempt",
        "acceptedReleaseManifestSha256", "acceptedReleasePrefix", "reviewWorkflowRef",
        "reviewWorkflowSha", "reviewRunId", "reviewRunAttempt", "reviewEnvironment", "preparedAt",
    ),
    "pendingCandidateFields": (
        "candidateSha", "candidateRunId", "candidateRunAttempt", "completedAt", "deadline",
        "acceptedReceiptPresent", "liveSha", "dispatchGuard", "rollback",
    ),
    "dispatchGuardFields": (
        "status", "generation", "claimId", "leaseExpiresAt", "watchdogRunId",
        "watchdogRunAttempt", "decisionReceiptSha256", "decisionEvidenceETag",
        "attemptReceiptSha256", "workflowRunId", "authorizationReceiptSha256",
    ),
    "dispatchGuardStatuses": ("available", "claimed", "dispatching", "requested", "authorized"),
    "dispatchGuardGenerationType": "positive-integer",
    "rollbackFields": (
        "sourceSha", "sourceRunId", "sourceRunAttempt", "acceptanceRunId",
        "acceptanceRunAttempt", "baselineReceiptSha256",
    ),
}

EXPECTED_RECONCILIATION = {
    "wormRetentionDays": 90,
    "writeReceiptBeforeStateCas": True,
    "readBackExactReceiptBeforeStateCas": True,
    "idempotency": (
        "An exact replay may return HTTP 200 only when operation, OIDC run, request body, prior state digest and "
        "ETag, and reconciliation receipt are identical."
    ),
    "automaticRelease": "Only an expired claimed lease with no attempt WORM receipt may return to available automatically.",
    "manualReview": (
        "Any attempt-present indeterminate outcome requires the protected paperdesk-watchdog-reconciliation "
        "environment; candidate acceptance may never clear claimed, dispatching, requested, or authorized state."
    ),
}


def fail(message: str) -> None:
    raise ValueError(f"watchdog contract rejected: {message}")


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _object(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def _exact(value: object, fields: tuple[str, ...] | list[str], label: str) -> Mapping[str, Any]:
    document = _object(value, label)
    if set(document) != set(fields) or len(document) != len(fields):
        fail(f"{label} fields must be exact")
    return document


def _string(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        fail(f"{label} is invalid")
    return value


def _timestamp(value: object, label: str) -> datetime:
    text = _string(value, UTC_MILLISECONDS, label)
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        fail(f"{label} is invalid: {exc}")
    if parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z") != text:
        fail(f"{label} is not canonical UTC")
    return parsed


def load_contract(path: Path | str = DEFAULT_CONTRACT) -> dict[str, Any]:
    resolved = Path(path).resolve()
    metadata = resolved.lstat()
    if not stat.S_ISREG(metadata.st_mode) or resolved.is_symlink() or not 2 < metadata.st_size <= 65536:
        fail("machine contract must be one bounded regular non-symlink file")
    try:
        document = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"machine contract is not valid UTF-8 JSON: {exc}")
    validate_machine_contract(document)
    return document


def validate_machine_contract(contract: object) -> Mapping[str, Any]:
    machine = _exact(contract, (
        "schemaVersion", "contractId", "status", "sourceRepository", "provider", "oidc",
        "immutableExternalControl", "state", "transitions", "reconciliation",
    ), "machine contract")
    if machine.get("schemaVersion") != 2 or machine.get("contractId") != "paperdesk-production-release-watchdog-provider-state-v2":
        fail("machine contract identity is invalid")
    if machine.get("status") != "dormant-pending-immutable-external-control":
        fail("machine contract must remain dormant")
    source = _exact(machine.get("sourceRepository"), (
        "repository", "repositoryId", "repositoryOwner", "repositoryOwnerId", "ref",
        "productionWorkflow", "rollbackWorkflow", "persistenceWorkflow",
    ), "sourceRepository")
    expected_source = {
        "repository": "Sethvirak/MasterDataStructure",
        "repositoryId": "1287744543",
        "repositoryOwner": "Sethvirak",
        "repositoryOwnerId": "202535166",
        "ref": "refs/heads/main",
        "productionWorkflow": ".github/workflows/main_master-data-structure-sea-9c4e0d0d.yml",
        "rollbackWorkflow": ".github/workflows/main_master-data-structure-sea-9c4e0d0d.yml",
        "persistenceWorkflow": ".github/workflows/persist-accepted-release.yml",
    }
    if source != expected_source:
        fail("source repository identity is not exact")
    provider = _exact(machine.get("provider"), (
        "origin", "stateMethod", "statePath", "transitionMethod", "transitionPath", "audience",
        "issuer", "authorizationHeader", "requestContentType", "requestType", "conditionalHeader",
        "stateETagHeader", "maximumRequestBytes", "maximumResponseBytes", "redirectsAllowed",
        "canonicalJsonRequired", "acceptedStatuses",
    ), "provider")
    expected_provider = {
        "origin": "https://paperdesk-watchdog-state-9c4e0d0d.azurewebsites.net",
        "stateMethod": "GET",
        "statePath": "/api/watchdog-state/v2",
        "transitionMethod": "POST",
        "transitionPath": "/api/watchdog-state/v2/transitions",
        "audience": "api://paperdesk-watchdog-evidence-v2",
        "issuer": "https://token.actions.githubusercontent.com",
        "authorizationHeader": "Authorization: Bearer <GitHub OIDC>",
        "requestContentType": "application/json",
        "requestType": "watchdog-state-transition",
        "conditionalHeader": "If-Match",
        "stateETagHeader": "ETag",
        "maximumRequestBytes": 65536,
        "maximumResponseBytes": 65536,
        "redirectsAllowed": False,
        "canonicalJsonRequired": True,
        "acceptedStatuses": {
            "created": 201,
            "idempotentReplay": 200,
            "malformedRequest": 400,
            "unauthenticated": 401,
            "wrongCaller": 403,
            "lifecycleConflict": 409,
            "staleStateETag": 412,
            "providerUnavailable": 503,
        },
    }
    if provider != expected_provider:
        fail("provider HTTP and OIDC boundary is not exact")
    oidc = _exact(machine.get("oidc"), (
        "tokenRepository", "tokenRepositoryId", "tokenRepositoryOwner", "tokenRepositoryOwnerId",
        "ref", "environment", "subject", "requiredClaims", "maximumLifetimeSeconds", "runBinding",
    ), "oidc")
    expected_oidc = {
        "tokenRepository": source["repository"],
        "tokenRepositoryId": source["repositoryId"],
        "tokenRepositoryOwner": source["repositoryOwner"],
        "tokenRepositoryOwnerId": source["repositoryOwnerId"],
        "ref": source["ref"],
        "environment": "paperdesk-production-control",
        "subject": "repo:Sethvirak/MasterDataStructure:environment:paperdesk-production-control",
        "requiredClaims": [
            "iss", "aud", "sub", "repository", "repository_owner", "repository_id",
            "repository_owner_id", "ref", "sha", "workflow_ref", "workflow_sha",
            "event_name", "run_id", "run_attempt", "environment", "job_workflow_ref",
            "job_workflow_sha", "iat", "nbf", "exp",
        ],
        "maximumLifetimeSeconds": 900,
        "runBinding": EXPECTED_RUN_BINDING,
    }
    if oidc != expected_oidc:
        fail("OIDC boundary is not exact")
    control = _exact(machine.get("immutableExternalControl"), (
        "repository", "repositoryId", "workflowPath", "mergedMutatingCommitSha",
        "requiredOperations", "requiredOutputs", "activationRule", "rollbackAtomicityRule",
    ), "immutableExternalControl")
    expected_control = {
        "repository": "Sethvirak/paperdesk-release-verifier",
        "repositoryId": "1333353701",
        "workflowPath": ".github/workflows/azure-production-control.yml",
        "mergedMutatingCommitSha": None,
        "requiredOperations": list(EXPECTED_TRANSITIONS),
        "requiredOutputs": [
            "operation_receipt_name", "operation_receipt_sha256", "watchdog_state_sha256",
            "watchdog_state_etag", "transition_receipt_sha256",
        ],
        "activationRule": ACTIVATION_RULE,
        "rollbackAtomicityRule": ROLLBACK_ATOMICITY_RULE,
    }
    if control != expected_control:
        fail("immutable external-control boundary is not exact and dormant")
    transitions = _exact(machine.get("transitions"), tuple(EXPECTED_TRANSITIONS), "transitions")
    for operation, expected in EXPECTED_TRANSITIONS.items():
        transition = _exact(transitions[operation], (
            "callerWorkflow", "requestFields", "responseFields", "responseStatus", "preconditions",
        ), f"transition {operation}")
        if (
            transition.get("callerWorkflow") != expected["callerWorkflow"]
            or transition.get("requestFields") != list(expected["requestFields"])
            or transition.get("responseFields") != list(COMMON_RESPONSE_FIELDS)
            or transition.get("responseStatus") != expected["responseStatus"]
            or transition.get("preconditions") != list(expected["preconditions"])
        ):
            fail(f"transition {operation} shape drifted")
    state = _exact(machine.get("state"), tuple(EXPECTED_STATE_FIELDS), "state")
    expected_state = {
        name: list(value) if isinstance(value, tuple) else value
        for name, value in EXPECTED_STATE_FIELDS.items()
    }
    if state != expected_state:
        fail("provider state shape, dispatch guard, or rollback fields drifted")
    reconciliation = _exact(machine.get("reconciliation"), tuple(EXPECTED_RECONCILIATION), "reconciliation")
    if reconciliation != EXPECTED_RECONCILIATION:
        fail("reconciliation contract is not fail closed")
    return machine


def validate_transition_request(
    contract: Mapping[str, Any],
    request: object,
    *,
    if_match: str | None = None,
) -> Mapping[str, Any]:
    document = _object(request, "transition request")
    operation = document.get("operation")
    if operation not in EXPECTED_TRANSITIONS:
        fail("transition operation is unsupported")
    expected = EXPECTED_TRANSITIONS[str(operation)]
    _exact(document, expected["requestFields"], f"{operation} request")
    expected_schema_version = 3 if operation == "accept-candidate" else 2
    if document.get("schemaVersion") != expected_schema_version or document.get("requestType") != "watchdog-state-transition":
        fail("schemaVersion or requestType is invalid")
    _string(document.get("expectedStateSha256"), SHA256, "expectedStateSha256")
    for name in (
        "verificationReceiptSha256", "productionControlReceiptSha256",
        "rollbackBaselineReceiptSha256", "productionAcceptanceReceiptSha256",
        "acceptedReleaseManifestSha256", "decisionReceiptSha256", "attemptReceiptSha256",
        "kuduRequestSha256", "kuduResponseSha256", "authorizationReceiptSha256",
        "liveVerificationReceiptSha256",
    ):
        if name in document:
            _string(document[name], SHA256, name)
    for name in ("candidateSha", "liveSha", "expectedCurrentLiveSha", "kuduObservedLiveSha", "rolledBackLiveSha"):
        if name in document:
            _string(document[name], SHA40, name)
    for name in (
        "sourceRunId", "sourceRunAttempt", "candidateRunId", "candidateRunAttempt",
        "acceptanceRunId", "acceptanceRunAttempt", "workflowRunId",
    ):
        if name in document:
            _string(document[name], POSITIVE, name)
    if "dispatchGuardGeneration" in document and (
        isinstance(document["dispatchGuardGeneration"], bool)
        or not isinstance(document["dispatchGuardGeneration"], int)
        or document["dispatchGuardGeneration"] < 1
    ):
        fail("dispatchGuardGeneration must be a positive integer")
    if "decisionEvidenceETag" in document:
        _string(document["decisionEvidenceETag"], ETAG, "decisionEvidenceETag")
    if "registryManifestETag" in document:
        _string(document["registryManifestETag"], ETAG, "registryManifestETag")
    if "registryManifestVersionId" in document:
        _string(document["registryManifestVersionId"], VERSION_ID, "registryManifestVersionId")
    if "claimId" in document:
        _string(document["claimId"], UUID, "claimId")
    if operation == "publish-candidate":
        completed = _timestamp(document["completedAt"], "completedAt")
        deadline = _timestamp(document["deadline"], "deadline")
        if (deadline - completed).total_seconds() != 1440 * 60:
            fail("deadline must be exactly 1,440 minutes after completedAt")
        if document["candidateSha"] != document["liveSha"]:
            fail("published candidateSha must equal liveSha")
    elif operation == "accept-candidate":
        if len({document["sourceRunId"], document["candidateRunId"], document["acceptanceRunId"]}) != 3:
            fail("source, candidate deployment, and acceptance runs must be distinct")
        prefix = f'v1/releases/{document["candidateSha"]}/{document["sourceRunId"]}/{document["acceptanceRunId"]}/'
        if document["acceptedReleasePrefix"] != prefix:
            fail("acceptedReleasePrefix is not bound to source and acceptance runs")
    elif operation == "rollback-authorize":
        _timestamp(document["kuduObservedAt"], "kuduObservedAt")
        if document["kuduObservedLiveSha"] != document["expectedCurrentLiveSha"]:
            fail("rollback authorization Kudu observation differs from expected live SHA")
    elif operation == "rollback-completed":
        _timestamp(document["completedAt"], "completedAt")
        if document["rolledBackLiveSha"] == document["expectedCurrentLiveSha"]:
            fail("rollback completion must restore a different accepted SHA")
    if if_match is not None:
        _string(if_match, ETAG, "If-Match")
        if if_match != f'"{document["expectedStateSha256"]}"':
            fail("If-Match must equal quoted expectedStateSha256")
    return document


def validate_oidc_binding(
    contract: Mapping[str, Any],
    request: Mapping[str, Any],
    claims: object,
) -> Mapping[str, Any]:
    token = _object(claims, "OIDC claims")
    operation = str(request["operation"])
    source = _object(contract["sourceRepository"], "sourceRepository")
    oidc = _object(contract["oidc"], "oidc")
    transition = EXPECTED_TRANSITIONS[operation]
    workflow_ref = f'{source["repository"]}/{transition["callerWorkflow"]}@{source["ref"]}'
    binding = _object(oidc["runBinding"].get(operation), f"OIDC runBinding {operation}")
    run_id_field = binding.get("runIdField")
    run_attempt_field = binding.get("runAttemptField")
    run_id = request[str(run_id_field)] if isinstance(run_id_field, str) else None
    run_attempt = request[str(run_attempt_field)] if isinstance(run_attempt_field, str) else binding.get("runAttempt")
    expected = {
        "iss": contract["provider"]["issuer"],
        "aud": contract["provider"]["audience"],
        "sub": oidc["subject"],
        "repository": source["repository"],
        "repository_owner": source["repositoryOwner"],
        "repository_id": source["repositoryId"],
        "repository_owner_id": source["repositoryOwnerId"],
        "ref": source["ref"],
        "workflow_ref": workflow_ref,
        "event_name": binding["eventName"],
        "environment": oidc["environment"],
    }
    if run_id is not None:
        expected["run_id"] = run_id
    if run_attempt is not None:
        expected["run_attempt"] = run_attempt
    for name, value in expected.items():
        if str(token.get(name, "")) != str(value):
            fail(f"OIDC claim {name} is not exact")
    _string(str(token.get("sha") or ""), SHA40, "OIDC sha")
    _string(str(token.get("workflow_sha") or ""), SHA40, "OIDC workflow_sha")
    if token["workflow_sha"] != token["sha"]:
        fail("OIDC workflow_sha must equal exact caller sha")
    _string(str(token.get("run_id") or ""), POSITIVE, "OIDC run_id")
    _string(str(token.get("run_attempt") or ""), POSITIVE, "OIDC run_attempt")
    must_differ = binding.get("mustDifferFromRunIdField")
    if isinstance(must_differ, str) and str(token["run_id"]) == str(request[must_differ]):
        fail("accept-candidate OIDC run must be the distinct persistence workflow run")
    if operation == "publish-candidate" and token["sha"] != request["candidateSha"]:
        fail("publish candidate SHA must equal OIDC sha")
    control = _object(contract["immutableExternalControl"], "immutableExternalControl")
    prefix = f'{control["repository"]}/{control["workflowPath"]}@'
    job_ref = str(token.get("job_workflow_ref") or "")
    job_sha = str(token.get("job_workflow_sha") or "")
    if not job_ref.startswith(prefix) or not SHA40.fullmatch(job_ref[len(prefix):]) or job_sha != job_ref[len(prefix):]:
        fail("OIDC claims do not bind one immutable external control commit")
    for name in ("iat", "nbf", "exp"):
        if isinstance(token.get(name), bool) or not isinstance(token.get(name), int):
            fail(f"OIDC claim {name} must be an integer")
    if (
        token["exp"] <= token["iat"]
        or token["exp"] <= token["nbf"]
        or token["exp"] - token["iat"] > oidc["maximumLifetimeSeconds"]
    ):
        fail("OIDC lifetime is invalid")
    return token


def validate_transition_response(
    request: Mapping[str, Any],
    response: object,
    *,
    http_status: int,
) -> Mapping[str, Any]:
    operation = str(request["operation"])
    document = _exact(response, COMMON_RESPONSE_FIELDS, f"{operation} response")
    if (
        document.get("schemaVersion") != 2
        or document.get("status") != EXPECTED_TRANSITIONS[operation]["responseStatus"]
        or document.get("operation") != operation
        or document.get("previousStateSha256") != request["expectedStateSha256"]
    ):
        fail("transition response identity is invalid")
    for name in ("previousStateSha256", "stateSha256", "transitionReceiptSha256"):
        _string(document.get(name), SHA256, name)
    _string(document.get("stateETag"), ETAG, "stateETag")
    if document["stateETag"] != f'"{document["stateSha256"]}"':
        fail("stateETag must equal quoted stateSha256")
    _string(document.get("transitionEvidencePath"), EVIDENCE_PATH, "transitionEvidencePath")
    _string(document.get("transitionEvidenceETag"), ETAG, "transitionEvidenceETag")
    _string(document.get("transitionEvidenceVersionId"), VERSION_ID, "transitionEvidenceVersionId")
    if http_status not in (200, 201):
        fail("successful transition HTTP status must be 201 or exact replay 200")
    return document


__all__ = [
    "COMMON_RESPONSE_FIELDS", "DEFAULT_CONTRACT", "EXPECTED_RUN_BINDING", "EXPECTED_TRANSITIONS", "canonical_json",
    "load_contract", "validate_machine_contract", "validate_oidc_binding",
    "validate_transition_request", "validate_transition_response",
]
