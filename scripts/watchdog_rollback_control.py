"""Fail-closed dormant watchdog rollback lifecycle orchestration."""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from typing import Any


SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


class RollbackControlError(ValueError):
    pass


def fail(code: str) -> None:
    raise RollbackControlError(code)


def digest(document: Mapping[str, Any]) -> str:
    raw = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return hashlib.sha256(raw).hexdigest()


def execute(
    coordinates: Mapping[str, Any], *,
    fetch_state: Callable[[], Mapping[str, Any]],
    transition: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    observe_live: Callable[[], Mapping[str, Any]],
    deploy_onedeploy: Callable[[str], Mapping[str, Any]],
    verify_live: Callable[[str], Mapping[str, Any]],
    completed_at: str,
) -> dict[str, Any]:
    required = {"claimId", "dispatchGuardGeneration", "attemptReceiptSha256",
                "decisionReceiptSha256", "decisionEvidenceETag", "workflowRunId"}
    if not isinstance(coordinates, Mapping) or set(coordinates) != required:
        fail("rollback-coordinates")
    claim = coordinates["claimId"]
    generation = coordinates["dispatchGuardGeneration"]
    attempt = coordinates["attemptReceiptSha256"]
    decision = coordinates["decisionReceiptSha256"]
    workflow_run = coordinates["workflowRunId"]
    etag = coordinates["decisionEvidenceETag"]
    if not isinstance(claim, str) or not UUID.fullmatch(claim): fail("rollback-claim")
    if type(generation) is not int or generation < 1: fail("rollback-generation")
    if not isinstance(attempt, str) or not SHA256.fullmatch(attempt): fail("rollback-attempt")
    if not isinstance(decision, str) or not SHA256.fullmatch(decision): fail("rollback-decision")
    if not isinstance(workflow_run, str) or not re.fullmatch(r"[1-9][0-9]*", workflow_run): fail("rollback-run")
    if not isinstance(etag, str) or not re.fullmatch(r'"[^"\r\n]{1,126}"', etag): fail("rollback-etag")

    def fresh(status: str):
        state = fetch_state()
        pending = state.get("pendingCandidate") if isinstance(state, Mapping) else None
        guard = pending.get("dispatchGuard") if isinstance(pending, Mapping) else None
        rollback = pending.get("rollback") if isinstance(pending, Mapping) else None
        if not isinstance(guard, Mapping) or not isinstance(rollback, Mapping): fail("rollback-state")
        expected = (guard.get("status") == status and guard.get("claimId") == claim
                    and guard.get("generation") == generation
                    and guard.get("attemptReceiptSha256") == attempt
                    and str(guard.get("workflowRunId")) == workflow_run
                    and guard.get("decisionReceiptSha256") == decision
                    and guard.get("decisionEvidenceETag") == etag)
        if not expected: fail("rollback-state-binding")
        if not SHA40.fullmatch(str(pending.get("candidateSha", ""))): fail("rollback-candidate")
        if not SHA40.fullmatch(str(rollback.get("sourceSha", ""))): fail("rollback-baseline")
        return state, pending, guard

    state, pending, _ = fresh("dispatching")
    common = {"schemaVersion": 2, "requestType": "watchdog-state-transition",
              "expectedStateSha256": digest(state), "claimId": claim,
              "dispatchGuardGeneration": generation, "attemptReceiptSha256": attempt,
              "workflowRunId": workflow_run, "expectedCurrentLiveSha": pending["candidateSha"]}
    transition({**common, "operation": "rollback-workflow-observed",
                "decisionReceiptSha256": decision, "decisionEvidenceETag": etag})
    state, pending, _ = fresh("requested")
    observed = observe_live()
    if not isinstance(observed, Mapping) or set(observed) != {"liveSha", "observedAt", "requestSha256", "responseSha256"}:
        fail("rollback-observation")
    if observed["liveSha"] != pending["candidateSha"]: fail("rollback-live-drift")
    if not SHA256.fullmatch(str(observed["requestSha256"])) or not SHA256.fullmatch(str(observed["responseSha256"])):
        fail("rollback-observation-digest")
    common["expectedStateSha256"] = digest(state)
    authorization = transition({**common, "operation": "rollback-authorize",
        "decisionReceiptSha256": decision, "decisionEvidenceETag": etag,
        "kuduObservedLiveSha": observed["liveSha"], "kuduObservedAt": observed["observedAt"],
        "kuduRequestSha256": observed["requestSha256"], "kuduResponseSha256": observed["responseSha256"]})
    state, pending, guard = fresh("authorized")
    authorization_sha = guard.get("authorizationReceiptSha256")
    if not isinstance(authorization_sha, str) or not SHA256.fullmatch(authorization_sha): fail("rollback-authorization")
    if authorization.get("operationReceiptSha256") != authorization_sha: fail("rollback-authorization-response")
    baseline = pending["rollback"]["sourceSha"]
    deployment = deploy_onedeploy(baseline)
    verification = verify_live(baseline)
    verification_sha = verification.get("receiptSha256") if isinstance(verification, Mapping) else None
    if not isinstance(verification_sha, str) or not SHA256.fullmatch(verification_sha): fail("rollback-verification")
    common["expectedStateSha256"] = digest(state)
    completion = transition({**common, "operation": "rollback-completed",
        "authorizationReceiptSha256": authorization_sha, "rolledBackLiveSha": baseline,
        "liveVerificationReceiptSha256": verification_sha, "completedAt": completed_at})
    return {"authorization": dict(authorization), "deployment": dict(deployment),
            "verification": dict(verification), "completion": dict(completion)}
