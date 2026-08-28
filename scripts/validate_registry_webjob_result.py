#!/usr/bin/env python3
"""Validate canonical result attestations emitted by the fixed registry WebJob.

This control-side validator is deliberately outside the deterministic WebJob
package.  It imports the reviewed helper contract, binds every downloaded
envelope to one exact ARM history run, and builds the relational preflight or
persistence result set retained by the control workflow.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable

import accepted_release_registry as registry


PROOF_SCHEMA = "paperdesk-registry-webjob-result-proof-v1"
RESULT_SET_SCHEMA = "paperdesk-registry-webjob-result-set-v1"
MAX_PROOF_BYTES = 16 * 1024
MAX_RESULT_SET_BYTES = 64 * 1024
HISTORY_ID = re.compile(r"/[A-Za-z0-9._:/-]{1,2047}")

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
PROOF_KEYS = {
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
    "envelopeSha256",
    "resultSha256",
    "history",
    "result",
}
HISTORY_KEYS = {"historyId", "status", "webJobsRunId", "startedAt", "endedAt"}
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


class ResultValidationError(RuntimeError):
    """A fail-closed control-side result validation error."""


def fail(message: str) -> None:
    raise ResultValidationError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            fail("result JSON contains a duplicate object key")
        document[key] = value
    return document


def load_canonical_json(path: Path, label: str, maximum: int) -> Any:
    if not path.is_file() or path.is_symlink():
        fail(f"{label} must be one regular non-link file")
    size = path.stat().st_size
    if size <= 0 or size > maximum:
        fail(f"{label} exceeds its byte boundary")
    raw = path.read_bytes()
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"{label} is not strict UTF-8 JSON: {exc}")
    if raw != registry.canonical_json(document):
        fail(f"{label} is not canonical sorted compact JSON")
    return document


def write_canonical_json(path: Path, document: Any, maximum: int) -> None:
    if path.exists() or path.is_symlink():
        fail("result validation output must not already exist")
    body = registry.canonical_json(document)
    if len(body) <= 0 or len(body) > maximum:
        fail("result validation output exceeds its byte boundary")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(body)


def exact_positive(value: str, label: str) -> str:
    if not isinstance(value, str):
        fail(f"{label} must be a string")
    return registry.positive(value, label)


def exact_digest(value: str, label: str) -> str:
    if not isinstance(value, str):
        fail(f"{label} must be a string")
    return registry.digest(value, label)


def exact_sha(value: str, label: str) -> str:
    if not isinstance(value, str):
        fail(f"{label} must be a string")
    return registry.full_sha(value, label)


def exact_nonce(value: str) -> str:
    if not isinstance(value, str) or not registry.RESULT_NONCE.fullmatch(value):
        fail("result nonce is invalid")
    return value


def exact_history_id(value: str) -> str:
    if not isinstance(value, str) or not HISTORY_ID.fullmatch(value):
        fail("ARM WebJob history ID is invalid")
    return value


def exact_webjobs_run_id(value: str) -> str:
    if not isinstance(value, str) or not registry.WEBJOB_RUN_ID.fullmatch(value):
        fail("ARM WebJob run ID is invalid")
    return value


def exact_timestamp(value: str, label: str) -> str:
    if not isinstance(value, str) or len(value) > 64:
        fail(f"{label} is invalid")
    return registry.utc_timestamp(value, label)


def timestamp_value(value: str, label: str):
    exact_timestamp(value, label)
    return registry.dt.datetime.fromisoformat(value[:-1] + "+00:00")


def validate_purpose(operation: str, purpose: str, execution: int) -> None:
    if type(execution) is not int:
        fail("result execution must be an integer")
    contract = registry.RESULT_PURPOSES.get(purpose)
    if contract is None or contract[0] != operation or execution not in contract[1]:
        fail("result purpose, operation, and execution do not match")


def expected_result_blob(
    github_run_id: str,
    github_run_attempt: str,
    purpose: str,
    execution: int,
    nonce: str,
) -> str:
    return (
        f"v1/results/{github_run_id}/{github_run_attempt}/{purpose}/"
        f"{execution}/{nonce}.json"
    )


def validate_nested_binding(
    operation: str,
    purpose: str,
    execution: int,
    nonce: str,
    github_run_id: str,
    github_run_attempt: str,
    helper_sha256: str,
    result: Any,
    expected_prefix: str | None = None,
    artifact_zip_sha256: str | None = None,
    request_sha256: str | None = None,
) -> dict[str, Any]:
    validate_purpose(operation, purpose, execution)
    if operation != "persist-actions-artifact" and any(
        value is not None
        for value in (expected_prefix, artifact_zip_sha256, request_sha256)
    ):
        fail("non-persistence result received persistence expectations")
    exact_result = registry.validate_attested_helper_result(operation, purpose, result)
    if operation == "storage-rbac-canary":
        expected_canary = (
            "v1/canaries/storage-rbac/"
            f"{github_run_id}/{github_run_attempt}/{nonce}.json"
        )
        if exact_result["canaryBlob"] != expected_canary:
            fail("storage RBAC result is not bound to the result nonce")
    elif operation == "runtime-canary":
        if exact_result["helperSha256"] != helper_sha256:
            fail("runtime result helper digest does not match the envelope")
    elif operation == "persist-actions-artifact":
        if expected_prefix is None or artifact_zip_sha256 is None or request_sha256 is None:
            fail("persistence validation expectations are incomplete")
        if registry.validate_registry_prefix(expected_prefix) != expected_prefix:
            fail("expected persistence prefix is invalid")
        if exact_result["prefix"] != expected_prefix:
            fail("persistence result prefix differs")
        if exact_result["artifactZipSha256"] != exact_digest(
            artifact_zip_sha256, "expected artifact ZIP digest"
        ):
            fail("persistence artifact ZIP digest differs")
        if exact_result["requestSha256"] != exact_digest(
            request_sha256, "expected request digest"
        ):
            fail("persistence request digest differs")
    return exact_result


def validate_envelope(
    path: Path,
    *,
    operation: str,
    purpose: str,
    execution: int,
    nonce: str,
    result_blob: str,
    github_run_id: str,
    github_run_attempt: str,
    control_workflow_sha: str,
    package_sha256: str,
    helper_sha256: str,
    webjobs_run_id: str,
    history_id: str,
    history_status: str,
    started_at: str,
    ended_at: str,
    expected_prefix: str | None = None,
    artifact_zip_sha256: str | None = None,
    request_sha256: str | None = None,
) -> dict[str, Any]:
    validate_purpose(operation, purpose, execution)
    nonce = exact_nonce(nonce)
    github_run_id = exact_positive(github_run_id, "GitHub run ID")
    github_run_attempt = exact_positive(github_run_attempt, "GitHub run attempt")
    control_workflow_sha = exact_sha(control_workflow_sha, "control workflow SHA")
    package_sha256 = exact_digest(package_sha256, "registry package digest")
    helper_sha256 = exact_digest(helper_sha256, "registry helper digest")
    webjobs_run_id = exact_webjobs_run_id(webjobs_run_id)
    history_id = exact_history_id(history_id)
    if history_status != "Success":
        fail("ARM WebJob history is not successful")
    started_value = timestamp_value(started_at, "ARM WebJob start time")
    ended_value = timestamp_value(ended_at, "ARM WebJob end time")
    if ended_value < started_value:
        fail("ARM WebJob history ends before it starts")
    if result_blob != expected_result_blob(
        github_run_id, github_run_attempt, purpose, execution, nonce
    ):
        fail("result blob differs from its exact coordinates")

    envelope = load_canonical_json(
        path, "registry WebJob result envelope", registry.MAX_RESULT_ATTESTATION_BYTES
    )
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_KEYS:
        fail("registry WebJob result envelope fields are not exact")
    expected_scalars = {
        "schema": registry.RESULT_ATTESTATION_SCHEMA,
        "status": "attested",
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
        "webJobsName": "paperdesk-accepted-release-registry",
        "webJobsType": "triggered",
        "webJobsRunId": webjobs_run_id,
    }
    for key, expected in expected_scalars.items():
        if type(envelope.get(key)) is not type(expected) or envelope.get(key) != expected:
            fail(f"registry WebJob result envelope {key} differs")
    result = validate_nested_binding(
        operation,
        purpose,
        execution,
        nonce,
        github_run_id,
        github_run_attempt,
        helper_sha256,
        envelope["result"],
        expected_prefix,
        artifact_zip_sha256,
        request_sha256,
    )
    result_sha256 = hashlib.sha256(registry.canonical_json(result)).hexdigest()
    if envelope.get("resultSha256") != result_sha256:
        fail("registry WebJob nested result digest differs")

    return {
        "schema": PROOF_SCHEMA,
        "status": "valid",
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
        "webJobsName": "paperdesk-accepted-release-registry",
        "webJobsType": "triggered",
        "envelopeSha256": hashlib.sha256(registry.canonical_json(envelope)).hexdigest(),
        "resultSha256": result_sha256,
        "history": {
            "historyId": history_id,
            "status": history_status,
            "webJobsRunId": webjobs_run_id,
            "startedAt": started_at,
            "endedAt": ended_at,
        },
        "result": result,
    }


def validate_proof(path: Path) -> dict[str, Any]:
    proof = load_canonical_json(path, "registry WebJob result proof", MAX_PROOF_BYTES)
    if not isinstance(proof, dict) or set(proof) != PROOF_KEYS:
        fail("registry WebJob result proof fields are not exact")
    if proof.get("schema") != PROOF_SCHEMA or proof.get("status") != "valid":
        fail("registry WebJob result proof status is invalid")
    operation = proof.get("operation")
    purpose = proof.get("purpose")
    execution = proof.get("execution")
    if not isinstance(operation, str) or not isinstance(purpose, str):
        fail("registry WebJob result proof operation is invalid")
    validate_purpose(operation, purpose, execution)
    nonce = exact_nonce(proof.get("nonce"))
    github_run_id = exact_positive(proof.get("githubRunId"), "proof GitHub run ID")
    github_run_attempt = exact_positive(
        proof.get("githubRunAttempt"), "proof GitHub run attempt"
    )
    helper_sha256 = exact_digest(proof.get("helperSha256"), "proof helper digest")
    if helper_sha256 != proof.get("helperSha256"):
        fail("proof helper digest is not canonical")
    package_sha256 = exact_digest(proof.get("packageSha256"), "proof package digest")
    if package_sha256 != proof.get("packageSha256"):
        fail("proof package digest is not canonical")
    exact_sha(proof.get("controlWorkflowSha"), "proof control workflow SHA")
    envelope_sha256 = exact_digest(proof.get("envelopeSha256"), "proof envelope digest")
    if envelope_sha256 != proof.get("envelopeSha256"):
        fail("proof envelope digest is not canonical")
    if proof.get("webJobsName") != "paperdesk-accepted-release-registry":
        fail("proof WebJob name is invalid")
    if proof.get("webJobsType") != "triggered":
        fail("proof WebJob type is invalid")
    if proof.get("resultBlob") != expected_result_blob(
        github_run_id, github_run_attempt, purpose, execution, nonce
    ):
        fail("proof result blob differs from its coordinates")
    history = proof.get("history")
    if not isinstance(history, dict) or set(history) != HISTORY_KEYS:
        fail("proof ARM history fields are not exact")
    exact_history_id(history.get("historyId"))
    exact_webjobs_run_id(history.get("webJobsRunId"))
    if history.get("status") != "Success":
        fail("proof ARM history status is invalid")
    proof_started = timestamp_value(history.get("startedAt"), "proof ARM start time")
    proof_ended = timestamp_value(history.get("endedAt"), "proof ARM end time")
    if proof_ended < proof_started:
        fail("proof ARM history ends before it starts")
    result = validate_nested_binding(
        operation,
        purpose,
        execution,
        nonce,
        github_run_id,
        github_run_attempt,
        helper_sha256,
        proof.get("result"),
        proof.get("result", {}).get("prefix")
            if operation == "persist-actions-artifact" else None,
        proof.get("result", {}).get("artifactZipSha256")
            if operation == "persist-actions-artifact" else None,
        proof.get("result", {}).get("requestSha256")
            if operation == "persist-actions-artifact" else None,
    )
    expected_result_sha256 = hashlib.sha256(registry.canonical_json(result)).hexdigest()
    if proof.get("resultSha256") != expected_result_sha256:
        fail("proof nested result digest differs")
    return proof


def persistence_case(run_one: dict[str, Any], run_two: dict[str, Any]) -> str:
    first = run_one["result"]
    second = run_two["result"]
    immutable = (
        "status",
        "prefix",
        "artifactZipSha256",
        "requestSha256",
        "manifestSha256",
        "fileCount",
        "outOfPrefixNegative",
    )
    if any(first[key] != second[key] for key in immutable):
        fail("persistence results disagree on immutable outcome fields")
    first_count = first["createdBlobCount"]
    second_count = second["createdBlobCount"]
    first_overwrite = first["overwriteNegative"]
    second_overwrite = second["overwriteNegative"]
    if (
        1 <= first_count <= 20
        and first_overwrite == "passed"
        and second_count == 0
        and second_overwrite == "not-run-completed"
    ):
        return "created-or-recovered-then-idempotent"
    if (
        first_count == 0
        and first_overwrite == "not-run-completed"
        and second_count == 0
        and second_overwrite == "not-run-completed"
    ):
        return "already-complete-before-both-executions"
    fail("persistence execution pair is not an allowed idempotence case")


def build_result_set(mode: str, proof_paths: Iterable[Path]) -> dict[str, Any]:
    if mode not in MATRICES:
        fail("result-set mode is invalid")
    proofs = [validate_proof(path) for path in proof_paths]
    matrix = MATRICES[mode]
    by_coordinate: dict[tuple[str, int], dict[str, Any]] = {}
    for proof in proofs:
        coordinate = (proof["purpose"], proof["execution"])
        if coordinate in by_coordinate:
            fail("result set contains duplicate purpose/execution coordinates")
        by_coordinate[coordinate] = proof
    if set(by_coordinate) != set(matrix):
        fail("result set does not contain the exact execution matrix")
    for coordinate, operation in matrix.items():
        if by_coordinate[coordinate]["operation"] != operation:
            fail("result set operation differs from its fixed execution matrix")

    ordered = [by_coordinate[coordinate] for coordinate in matrix]
    common_keys = (
        "githubRunId",
        "githubRunAttempt",
        "controlWorkflowSha",
        "packageSha256",
        "helperSha256",
    )
    for key in common_keys:
        if len({proof[key] for proof in ordered}) != 1:
            fail(f"result set does not share one {key}")
    for key, values in {
        "nonce": [proof["nonce"] for proof in ordered],
        "result blob": [proof["resultBlob"] for proof in ordered],
        "envelope digest": [proof["envelopeSha256"] for proof in ordered],
        "ARM history ID": [proof["history"]["historyId"] for proof in ordered],
        "ARM WebJob run ID": [proof["history"]["webJobsRunId"] for proof in ordered],
    }.items():
        if len(values) != len(set(values)):
            fail(f"result set reuses a {key}")

    pair_case: str | None = None
    if mode == "persistence":
        pair_case = persistence_case(
            by_coordinate[("persistence-result", 1)],
            by_coordinate[("persistence-result", 2)],
        )
    first = ordered[0]
    return {
        "schema": RESULT_SET_SCHEMA,
        "status": "valid",
        "mode": mode,
        "githubRunId": first["githubRunId"],
        "githubRunAttempt": first["githubRunAttempt"],
        "controlWorkflowSha": first["controlWorkflowSha"],
        "packageSha256": first["packageSha256"],
        "helperSha256": first["helperSha256"],
        "persistenceCase": pair_case,
        "executions": ordered,
    }


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    for name in (
        "input",
        "output",
        "operation",
        "purpose",
        "execution",
        "nonce",
        "result-blob",
        "github-run-id",
        "github-run-attempt",
        "control-workflow-sha",
        "package-sha256",
        "helper-sha256",
        "webjobs-run-id",
        "history-id",
        "history-status",
        "started-at",
        "ended-at",
    ):
        validate.add_argument(f"--{name}", required=True)
    validate.add_argument("--expected-prefix")
    validate.add_argument("--artifact-zip-sha256")
    validate.add_argument("--request-sha256")

    result_set = commands.add_parser("build-set")
    result_set.add_argument("--mode", choices=tuple(MATRICES), required=True)
    result_set.add_argument("--proof", action="append", required=True)
    result_set.add_argument("--output", required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "validate":
            if not registry.POSITIVE_INTEGER.fullmatch(args.execution):
                fail("result execution is invalid")
            proof = validate_envelope(
                Path(args.input).absolute(),
                operation=args.operation,
                purpose=args.purpose,
                execution=int(args.execution),
                nonce=args.nonce,
                result_blob=args.result_blob,
                github_run_id=args.github_run_id,
                github_run_attempt=args.github_run_attempt,
                control_workflow_sha=args.control_workflow_sha,
                package_sha256=args.package_sha256,
                helper_sha256=args.helper_sha256,
                webjobs_run_id=args.webjobs_run_id,
                history_id=args.history_id,
                history_status=args.history_status,
                started_at=args.started_at,
                ended_at=args.ended_at,
                expected_prefix=args.expected_prefix,
                artifact_zip_sha256=args.artifact_zip_sha256,
                request_sha256=args.request_sha256,
            )
            write_canonical_json(Path(args.output).absolute(), proof, MAX_PROOF_BYTES)
        else:
            document = build_result_set(
                args.mode, (Path(value).absolute() for value in args.proof)
            )
            write_canonical_json(
                Path(args.output).absolute(), document, MAX_RESULT_SET_BYTES
            )
        return 0
    except (ResultValidationError, registry.RegistryError, OSError, ValueError) as exc:
        print(f"registry result validation error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
