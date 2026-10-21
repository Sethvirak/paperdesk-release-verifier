"""Pure candidate/projection grammar and non-authorizing receipt consistency.

The provider's read-only baseline inspector imports this module for B1/B2
consistency. No workflow, initializer, transition or dispatch caller uses it.
Referenced custody, historical parity and human identities are NOT authenticated
or fetched here. B1/B2 inspect supplied WormRecord bytes; no result grants authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

from scripts import watchdog_evidence as evidence


CANDIDATE_TYPE = "paperdesk-watchdog-users-closed-baseline-candidate"
BASELINE_TYPE = "users-closed-bootstrap-v1"
MAX_CANDIDATE_BYTES = 65536
MAX_PACKAGE_BYTES = 1073741824
SOURCE_IDENTITY = {
    "repository": "Sethvirak/MasterDataStructure",
    "repositoryId": "1287744543",
    "repositoryOwner": "Sethvirak",
    "repositoryOwnerId": "202535166",
    "ref": "refs/heads/main",
}
# Historical pins are observations, including a known degraded health policy.
# Tests bind these exact values to the existing mailbox owner. No acceptance
# coordinates or historical-verifier trust upgrade are invented here.
HISTORICAL_SOURCE = {
    "sourceSha": "70f3ac3065e3dfbf2cc49f8dff60840711348335",
    "repositoryId": "1287744543", "ownerId": "202535166",
    "sourceRunId": "31845287909", "sourceRunAttempt": "1",
    "artifactId": "9236286421",
    "artifactSha256": "64db9dd541a2068172e8460cb8e275e1ef46477979ce54707fab40b84eac852c",
    "artifactMember": "paperdesk-azure-runtime-70f3ac3065e3dfbf2cc49f8dff60840711348335.tar.gz",
    "artifactMemberSha256": "cc74ac1541f5acf9e830bbbef67916909440275068bb21b57cd1f737d692af88",
    "servedIndexSha256": "20db1a82cb4fc6367b30e0e467f178130e833b8d739ed541587cc52da4dca031",
    "oneDeployInvariant": {
        "historicalActiveDeploymentId": "54214e75-d66c-4a62-8d04-17d5b48b6b52",
        "collectionSemanticProjectionSha256": "2b53bb7e0ef4910ca8e08fc38196d2a79d49eeafcedb148b6ddb2e3c933581c2",
        "propertyIdSetSha256": "7a74a9fa5bfa23babeb837bd6fad179ddf7d92b938f67a29a044afc585a40604",
        "deploymentCount": 10,
    },
    "readinessHttpStatus": 503,
    "readinessCode": "attachment-malware-ingestion-not-ready",
    "localEvidenceSha256": "99bd17ab59fe9324372f167fe77dcc6f991ab1f4074a6c2fe940bfa212c669fb",
}
SOURCE_SHA = HISTORICAL_SOURCE["sourceSha"]
EVIDENCE_PREFIX = f"v2/baselines/users-closed-bootstrap/{SOURCE_SHA}/"
DESCRIPTOR_FIELDS = {"blob", "sha256", "size", "etag", "versionId"}
TOP_FIELDS = {
    "schemaVersion", "candidateType", "baselineType", "sourceRepository",
    "historicalSource", "acceptedBaseline", "deploymentBundle",
    "bootstrapConsumedMarker", "historicalParityEvidence", "controlTrust",
    "custody", "independentDecisions", "closedIngress", "preparedAt",
}
REVIEWERS = frozenset({"jecebella168-cmyk", "jecebella169-cmyk"})
CUSTODY_CONTAINERS = {
    "package": ("paperdesk-deployment-packages", 91),
    "accepted": ("paperdesk-accepted-releases", 91),
    "result": ("paperdesk-registry-webjob-results", 91),
    "watchdog": ("paperdesk-watchdog-evidence", 90),
}
STORAGE_RESOURCE = (
    "/subscriptions/9c4e0d0d-602f-4cde-84bd-337250e5b64c"
    "/resourceGroups/rg-paperdesk-rollback-sea-20260808"
    "/providers/Microsoft.Storage/storageAccounts/mdspdbak2608089c4e"
)


class CandidateError(ValueError):
    """The local source candidate is malformed; no provider was consulted."""


def _fail(message: str) -> None:
    raise CandidateError(message)


def _exact(value: object, fields: set[str], label: str) -> Mapping[str, Any]:
    if type(value) is not dict or set(value) != fields:
        _fail(f"{label} fields must be exact")
    return value


def _canonical(value: object) -> bytes:
    try:
        return (json.dumps(value, ensure_ascii=False, allow_nan=False,
                           sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as exc:
        raise CandidateError("candidate must be finite JSON") from exc


def _helper(function: Any, value: object, label: str) -> str:
    try:
        return function(value, label)
    except evidence.EvidenceError as exc:
        raise CandidateError(str(exc)) from exc


def _digest(value: object, label: str) -> str:
    result = _helper(evidence.digest, value, label)
    if result == "0" * 64:
        _fail(f"{label} cannot be a placeholder digest")
    return result


def _sha(value: object, label: str) -> str:
    result = _helper(evidence.full_sha, value, label)
    if result == "0" * 40:
        _fail(f"{label} cannot be a placeholder commit")
    return result


def _time(value: object, label: str, prepared: str | None = None) -> str:
    result = _helper(evidence.canonical_timestamp, value, label)
    if prepared is not None and result > prepared:
        _fail(f"{label} occurs after candidate preparation")
    return result


def _etag(value: object, label: str) -> None:
    if (type(value) is not str or not evidence.ETAG.fullmatch(value)
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            or value[1:-1].lower() in {"0", "pending", "null", "none"}):
        _fail(f"{label} must be a non-placeholder quoted ETag")


def _descriptor(value: object, label: str, *, fixed_blob: str | None = None,
                maximum: int = MAX_CANDIDATE_BYTES) -> None:
    document = _exact(value, DESCRIPTOR_FIELDS, label)
    blob = document["blob"]
    if (type(blob) is not str or len(blob) > 512
            or not re.fullmatch(r"[A-Za-z0-9._/-]+", blob)
            or any(part in {"", ".", ".."} for part in blob.split("/"))):
        _fail(f"{label} Blob path must be canonical and relative")
    if fixed_blob is not None:
        if blob != fixed_blob:
            _fail(f"{label} Blob path differs from the fixed historical binding")
    elif not blob.startswith(EVIDENCE_PREFIX) or not blob.endswith(".json"):
        _fail(f"{label} must use the users-closed evidence namespace")
    _digest(document["sha256"], f"{label} SHA-256")
    if type(document["size"]) is not int or not 1 <= document["size"] <= maximum:
        _fail(f"{label} size must be a bounded positive integer")
    _etag(document["etag"], f"{label} ETag")
    version = document["versionId"]
    if (type(version) is not str or not evidence.SAFE_VERSION_ID.fullmatch(version)
            or version.lower() in {"0", "pending", "null", "none"}):
        _fail(f"{label} version must be non-placeholder and bounded")


def validate_users_closed_bootstrap_baseline_candidate(document: object) -> Mapping[str, Any]:
    """Validate declared pins only and return an explicitly non-authorizing digest.

    This cannot establish that any object exists, contains those bytes, retains
    data, proves whole-runtime parity, represents genuine human decisions or
    closes ingress. No clock, filesystem, environment, token or provider is read.
    """
    candidate = _exact(document, TOP_FIELDS, "users-closed baseline candidate")
    if (type(candidate["schemaVersion"]) is not int or candidate["schemaVersion"] != 1
            or candidate["candidateType"] != CANDIDATE_TYPE
            or candidate["baselineType"] != BASELINE_TYPE):
        _fail("candidate schema/version/type is not exact")
    if _canonical(candidate["sourceRepository"]) != _canonical(SOURCE_IDENTITY):
        _fail("candidate source repository identity differs")
    if _canonical(candidate["historicalSource"]) != _canonical(HISTORICAL_SOURCE):
        _fail("candidate historical source pins differ from the fixed observation")
    prepared = _time(candidate["preparedAt"], "candidate preparedAt")
    _descriptor(candidate["acceptedBaseline"], "candidate accepted baseline", fixed_blob=(
        f"v2/accepted/{SOURCE_SHA}/bootstrap-consumed/manifest.json"))
    _descriptor(candidate["deploymentBundle"], "candidate deployment bundle", fixed_blob=(
        f"v1/accepted/{SOURCE_SHA}/bootstrap/deployment.zip"), maximum=MAX_PACKAGE_BYTES)
    _descriptor(candidate["bootstrapConsumedMarker"], "candidate consumed marker",
                fixed_blob="v2/bootstrap/current-production/consumed.json")
    _descriptor(candidate["historicalParityEvidence"], "candidate historical parity evidence")

    trust = _exact(candidate["controlTrust"], {
        "repository", "sourceSha", "treeSha", "workflowRef", "workflowSha",
        "providerPackageSha256", "providerPackageManifestSha256", "evidence",
    }, "candidate control trust")
    control_sha = _sha(trust["sourceSha"], "candidate control source SHA")
    _sha(trust["treeSha"], "candidate control tree SHA")
    if (trust["repository"] != evidence.WATCHDOG_REPOSITORY
            or trust["workflowRef"] != evidence.BASELINE_WORKFLOW_REF
            or trust["workflowSha"] != control_sha):
        _fail("candidate control workflow/source binding differs")
    for name in ("providerPackageSha256", "providerPackageManifestSha256"):
        _digest(trust[name], f"candidate control {name}")
    _descriptor(trust["evidence"], "candidate control trust evidence")

    custody = _exact(candidate["custody"], set(CUSTODY_CONTAINERS), "candidate custody")
    for purpose, (container, minimum) in CUSTODY_CONTAINERS.items():
        policy = _exact(custody[purpose], {
            "resourceId", "policyState", "retentionDays", "policyETag",
            "policySha256", "observedAt", "evidence",
        }, f"candidate {purpose} custody")
        if (policy["resourceId"] != f"{STORAGE_RESOURCE}/blobServices/default/containers/{container}"
                or policy["policyState"] != "Locked"
                or type(policy["retentionDays"]) is not int
                or not minimum <= policy["retentionDays"] <= 2147483647):
            _fail(f"candidate {purpose} custody resource/retention differs")
        _etag(policy["policyETag"], f"candidate {purpose} policy ETag")
        _digest(policy["policySha256"], f"candidate {purpose} policy SHA-256")
        _time(policy["observedAt"], f"candidate {purpose} policy observedAt", prepared)
        _descriptor(policy["evidence"], f"candidate {purpose} custody evidence")

    decisions = candidate["independentDecisions"]
    if type(decisions) is not list or len(decisions) != len(REVIEWERS):
        _fail("candidate needs exactly the two distinct named reviewer pins")
    logins = set()
    design_digests = set()
    source_review_ids = set()
    design_comment_ids = set()
    for decision in decisions:
        item = _exact(decision, {
            "login", "decision", "controlSourceSha", "designSha256", "sourceReviewId",
            "sourceReviewSubmittedAt", "designDecisionCommentId", "designDecisionSubmittedAt",
            "evidence",
        }, "candidate reviewer decision")
        if (type(item["login"]) is not str or item["login"] not in REVIEWERS
                or item["decision"] != "approve" or item["controlSourceSha"] != control_sha):
            _fail("candidate reviewer/source decision binding differs")
        logins.add(item["login"])
        design_digests.add(_digest(item["designSha256"], "candidate reviewed design SHA-256"))
        for name in ("sourceReviewId", "designDecisionCommentId"):
            _helper(evidence.positive, item[name], f"candidate reviewer {name}")
        source_review_ids.add(item["sourceReviewId"])
        design_comment_ids.add(item["designDecisionCommentId"])
        for name in ("sourceReviewSubmittedAt", "designDecisionSubmittedAt"):
            _time(item[name], f"candidate reviewer {name}", prepared)
        _descriptor(item["evidence"], "candidate reviewer decision evidence")
    if (logins != REVIEWERS or len(design_digests) != 1
            or len(source_review_ids) != len(REVIEWERS)
            or len(design_comment_ids) != len(REVIEWERS)):
        _fail("candidate reviewer identities or reviewed designs are inconsistent")

    ingress = _exact(candidate["closedIngress"], {
        "admission", "policySha256", "callbackPolicySha256", "evidence",
    }, "candidate closed ingress")
    if ingress["admission"] != "users-closed":
        _fail("candidate ingress must declare users closed")
    for name in ("policySha256", "callbackPolicySha256"):
        _digest(ingress[name], f"candidate ingress {name}")
    _descriptor(ingress["evidence"], "candidate closed ingress evidence")

    raw = _canonical(candidate)
    if len(raw) > MAX_CANDIDATE_BYTES:
        _fail("candidate exceeds its canonical byte bound")
    return {
        "schemaVersion": 1,
        "status": "source-candidate-validated",
        "candidateType": CANDIDATE_TYPE,
        "baselineType": BASELINE_TYPE,
        "candidateSha256": hashlib.sha256(raw).hexdigest(),
        "authorizationAvailable": False,
        "providerStateInitializationAllowed": False,
        "liveActivationAllowed": False,
    }


PROJECTION_FIELDS = {
    "schemaVersion", "baselineType", "candidateSha256", "candidate", "baselineReceipt", "review",
}
REVIEW_FIELDS = {"workflowRef", "workflowSha", "runId", "runAttempt", "environment", "preparedAt"}
RECEIPT_TYPE = "watchdog-users-closed-baseline-candidate-receipt"


def _projection(document: object) -> tuple[Mapping[str, Any], Mapping[str, Any], bytes]:
    projection = _exact(document, PROJECTION_FIELDS, "users-closed baseline projection")
    if (type(projection["schemaVersion"]) is not int or projection["schemaVersion"] != 1
            or projection["baselineType"] != BASELINE_TYPE):
        _fail("projection schema/version/type is not exact")
    candidate = projection["candidate"]
    parsed = validate_users_closed_bootstrap_baseline_candidate(candidate)
    if _digest(projection["candidateSha256"], "projection candidate digest") != parsed["candidateSha256"]:
        _fail("projection candidate digest differs from its complete declared bytes")
    review = _exact(projection["review"], REVIEW_FIELDS, "projection review")
    if (review["workflowRef"] != evidence.BASELINE_WORKFLOW_REF
            or review["workflowSha"] != candidate["controlTrust"]["sourceSha"]
            or review["environment"] != evidence.BASELINE_ENVIRONMENT):
        _fail("projection review differs from its declared control binding")
    run_id = _helper(evidence.positive, review["runId"], "projection review run ID")
    run_attempt = _helper(evidence.positive, review["runAttempt"], "projection review run attempt")
    prepared = _time(review["preparedAt"], "projection review preparedAt")
    _time(candidate["preparedAt"], "projection candidate preparedAt", prepared)
    blob = EVIDENCE_PREFIX + f"{run_id}/{run_attempt}/initial.json"
    _descriptor(projection["baselineReceipt"], "projection baseline receipt", fixed_blob=blob)
    # The receipt never contains its own descriptor/digest. This expected local
    # body is only for comparison; it is never returned, written or submitted.
    expected = {
        "schemaVersion": 1, "receiptType": RECEIPT_TYPE, "recordedAt": prepared,
        "sourceRepository": candidate["sourceRepository"],
        "candidateSha256": parsed["candidateSha256"], "candidate": candidate,
        "review": review, "evidencePath": blob,
    }
    expected_raw = _canonical(expected)
    projection_raw = _canonical(projection)
    if len(expected_raw) > MAX_CANDIDATE_BYTES or len(projection_raw) > MAX_CANDIDATE_BYTES:
        _fail("projection or wrapped receipt exceeds the existing canonical byte bound")
    descriptor = projection["baselineReceipt"]
    if (descriptor["size"] != len(expected_raw)
            or descriptor["sha256"] != hashlib.sha256(expected_raw).hexdigest()):
        _fail("projection receipt digest/size differs from its complete expected body")
    return projection, expected, expected_raw


def _projection_result(projection: Mapping[str, Any], *, inspected: bool) -> Mapping[str, Any]:
    return {
        "schemaVersion": 1,
        "status": "source-baseline-receipt-inspected" if inspected else "source-projection-validated",
        "receiptScope": "caller-supplied-bytes-only" if inspected else "declared-pins-only",
        "baselineType": BASELINE_TYPE,
        "candidateSha256": projection["candidateSha256"],
        "projectionSha256": hashlib.sha256(_canonical(projection)).hexdigest(),
        "baselineReceiptSha256": projection["baselineReceipt"]["sha256"],
        "authorizationAvailable": False,
        "providerStateInitializationAllowed": False,
        "liveActivationAllowed": False,
    }


def validate_users_closed_baseline_projection(document: object) -> Mapping[str, Any]:
    """Validate declaration consistency; do not fetch or admit the receipt."""
    projection, _, _ = _projection(document)
    return _projection_result(projection, inspected=False)


def inspect_users_closed_baseline_receipt(document: object, record: object) -> Mapping[str, Any]:
    """Match supplied actual-owner WormRecord bytes, not authenticated Storage.

    No Storage/backend/client is constructed or invoked. Referenced package,
    custody, human decisions and closure remain declarations. Ordinary provider
    initialization/state/transition/dispatch grammars still reject this type.
    """
    # Existing owner import is inert; tests deny environment/credentials/client
    # construction/network/processes during a fresh owner-module import.
    from provider import watchdog_state_provider as provider

    projection, expected, expected_raw = _projection(document)
    descriptor = projection["baselineReceipt"]
    if (type(record) is not provider.WormRecord or type(record.raw) is not bytes
            or type(record.document) is not dict or type(record.created) is not bool
            or any(type(getattr(record, name)) is not str
                   for name in ("sha256", "path", "etag", "version_id"))):
        _fail("receipt must be the actual owner's bounded WormRecord type")
    try:
        parsed = provider._parse_durable_canonical(record.raw, "supplied users-closed receipt")
    except (provider.ProviderError, TypeError, ValueError, UnicodeError,
            OverflowError, RecursionError) as exc:
        raise CandidateError("supplied receipt bytes fail the owner's canonical contract") from exc
    if (record.path != descriptor["blob"] or record.etag != descriptor["etag"]
            or record.version_id != descriptor["versionId"] or len(record.raw) != descriptor["size"]
            or hashlib.sha256(record.raw).hexdigest() != descriptor["sha256"]
            or record.sha256 != descriptor["sha256"]):
        _fail("supplied receipt differs from its exact five-field descriptor")
    if (record.raw != expected_raw or _canonical(record.document) != record.raw
            or _canonical(parsed) != _canonical(expected)):
        _fail("supplied receipt body differs from the complete candidate/review projection")
    return _projection_result(projection, inspected=True)


RECOVERY_PROJECTION_TYPE = "paperdesk-watchdog-users-closed-recovery-projection"
RECOVERY_FIELDS = {
    "schemaVersion", "projectionType", "baselineType", "baselineProjectionSha256",
    "baselineReceipt", "sourceRepository", "historicalSource", "acceptedBaseline",
    "deploymentBundle", "bootstrapConsumedMarker", "closedIngress", "settlementPolicy",
}


def validate_users_closed_recovery_projection(
    document: object, baseline_projection: object, record: object,
) -> Mapping[str, Any]:
    """Bind declared recovery pins to full B1 bytes; never admit a rollback.

    Inspection is only caller-supplied consistency. It does not authenticate the
    receipt, custody, reviewers or closed ingress, read a clock, choose a deadline,
    install pending state, construct dispatch inputs or write any evidence.
    """
    recovery = _exact(document, RECOVERY_FIELDS, "users-closed recovery projection")
    if (type(recovery["schemaVersion"]) is not int or recovery["schemaVersion"] != 1
            or recovery["projectionType"] != RECOVERY_PROJECTION_TYPE
            or recovery["baselineType"] != BASELINE_TYPE):
        _fail("recovery projection schema/version/type is not exact")
    raw = _canonical(recovery)
    if len(raw) > MAX_CANDIDATE_BYTES:
        _fail("recovery projection exceeds the existing canonical byte bound")
    _digest(recovery["baselineProjectionSha256"], "recovery complete B1 projection digest")
    inspected = inspect_users_closed_baseline_receipt(baseline_projection, record)
    declared = baseline_projection["candidate"]
    expected = {
        "schemaVersion": 1, "projectionType": RECOVERY_PROJECTION_TYPE,
        "baselineType": BASELINE_TYPE,
        "baselineProjectionSha256": inspected["projectionSha256"],
        "baselineReceipt": baseline_projection["baselineReceipt"],
        **{name: declared[name] for name in (
            "sourceRepository", "historicalSource", "acceptedBaseline", "deploymentBundle",
            "bootstrapConsumedMarker", "closedIngress",
        )},
        "settlementPolicy": {
            "historicalReadinessStatus": HISTORICAL_SOURCE["readinessHttpStatus"],
            "historicalReadinessCode": HISTORICAL_SOURCE["readinessCode"],
            "classification": "users-closed-degraded",
            "healthy": False, "accepted": False, "userAdmissionAllowed": False,
            "scanWindowAllowed": False,
        },
    }
    for name, value in expected.items():
        if type(value) is dict:
            _exact(recovery[name], set(value), f"recovery {name}")
    _exact(recovery["historicalSource"]["oneDeployInvariant"],
           set(HISTORICAL_SOURCE["oneDeployInvariant"]), "recovery historical OneDeploy")
    _exact(recovery["closedIngress"]["evidence"], DESCRIPTOR_FIELDS, "recovery ingress evidence")
    if raw != _canonical(expected):
        _fail("recovery pins or degraded/closed policy differ from the complete inspected B1 projection")
    return {
        "schemaVersion": 1, "status": "source-recovery-projection-validated",
        "projectionType": RECOVERY_PROJECTION_TYPE, "baselineType": BASELINE_TYPE,
        "receiptScope": "caller-supplied-bytes-only",
        "settlementScope": "declared-historical-policy-only",
        "baselineProjectionSha256": inspected["projectionSha256"],
        "recoveryProjectionSha256": hashlib.sha256(raw).hexdigest(),
        "baselineReceiptSha256": inspected["baselineReceiptSha256"],
        "settlementClassification": "users-closed-degraded",
        "healthy": False, "accepted": False, "userAdmissionAllowed": False,
        "scanWindowAllowed": False, "authorizationAvailable": False,
        "providerStateInitializationAllowed": False, "liveActivationAllowed": False,
    }
