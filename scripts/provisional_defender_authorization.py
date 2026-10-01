"""Offline inspection of canonical private Defender marker candidate bytes.

This is deliberately not an issuer, provider reader, or authorization admission.
Caller-supplied pins and WormRecord metadata are comparison inputs, never trust.
The existing mailbox PS256 primitive is reused with a separate exact schema.
Nothing here invokes a signer, provider, service, database, workflow or claim.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
from pathlib import Path
import re
from typing import Any

from scripts import private_release_mailbox as box


DOMAIN = "paperdesk:v2:provisional:defender:authorization"
AUDIENCE = "paperdesk-private-defender-transition"
MAX_MARKER_BYTES = 65536
MAX_PINS_BYTES = 131072
POLICY_PATH = Path(__file__).resolve().parents[1] / "contracts" / "provisional_defender_authorization_reader.json"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
POSITIVE = re.compile(r"[1-9][0-9]{0,19}\Z")
UTC = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\Z")
KEY_ID = re.compile(r"https://[a-z0-9][a-z0-9-]{1,22}[a-z0-9]\.vault\.azure\.net/keys/[A-Za-z0-9-]{1,127}\Z")
STORAGE_ID = re.compile(r"/subscriptions/([0-9a-f-]{36})/resourceGroups/([A-Za-z0-9._()-]{1,90})/providers/Microsoft.Storage/storageAccounts/([a-z0-9]{3,24})\Z")
TOPIC_ID = re.compile(r"/subscriptions/([0-9a-f-]{36})/resourceGroups/([A-Za-z0-9._()-]{1,90})/providers/Microsoft.EventGrid/systemTopics/([A-Za-z0-9._()-]{1,90})\Z")
CONTAINER = re.compile(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]\Z")
OPERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}\Z")
POLICY = {
    "schemaVersion": 1, "status": "source-dormant", "domain": DOMAIN,
    "maximumMarkerBytes": MAX_MARKER_BYTES, "maximumWindowSeconds": 86400,
    "allowedCandidates": [], "authorizationAdmissionAllowed": False,
    "activationAllowed": False, "candidateConsumeAllowed": False,
    "acceptedRegistryWriteAllowed": False,
}
MARKER_FIELDS = frozenset({
    "schemaVersion", "kind", "domain", "audience", "operationId",
    "operationDigestSha256", "bindingSha256", "issuedAt", "startedAt", "deadlineAt",
    "approvalReceiptSha256", "candidate", "control", "rollback", "database",
    "provider", "principals", "evidence", "lifecycle",
})
LIFECYCLE = {
    "privateStoreOnly": True, "ordinaryEvidenceWritesAllowed": False,
    "restartAllowed": False, "cleanupAllowed": False, "maximumActiveOperations": 1,
    "versionPolicy": "explicit-etag-optional-version-id",
    "oneUseRequired": True, "rollbackExecutionReserveSeconds": 900,
}


class AuthorizationCandidateError(ValueError):
    """Bounded, path-free candidate rejection."""


def fail(code: str) -> None:
    raise AuthorizationCandidateError(code)


def exact(value: Any, fields: set[str] | frozenset[str], label: str) -> dict:
    if type(value) is not dict or set(value) != fields:
        fail(label + "-fields")
    return value


def text(value: Any, pattern: re.Pattern, label: str) -> str:
    if type(value) is not str or not pattern.fullmatch(value):
        fail(label)
    return value


def stamp(value: Any, label: str) -> dt.datetime:
    text(value, UTC, label)
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        fail(label)
    if parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z") != value:
        fail(label)
    return parsed


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate-json-key")
        result[key] = value
    return result


def strict_json(raw: bytes, maximum: int, label: str) -> dict:
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        fail(label + "-size")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                         parse_constant=lambda _: fail(label + "-number"))
        if type(doc) is not dict or box.canonical(doc) != raw:
            fail(label + "-canonical")
    except (UnicodeError, ValueError, RecursionError, OverflowError) as error:
        if isinstance(error, AuthorizationCandidateError):
            raise
        fail(label + "-json")
    return doc


def validate_policy() -> None:
    # Exact bytes and typed values: Python considers True == 1, so equality
    # alone is insufficient for this source-owned authority fence.
    if POLICY_PATH.is_symlink() or not POLICY_PATH.is_file():
        fail("policy-path")
    raw = POLICY_PATH.read_bytes()
    if strict_json(raw, 4096, "policy") != POLICY or raw != box.canonical(POLICY):
        fail("policy-dormant")


def descriptor(value: Any, label: str, blob: str | None = None) -> dict:
    exact(value, {"blob", "sha256", "size", "etag", "versionId"}, label)
    for key in ("blob", "sha256", "etag", "versionId"):
        if type(value[key]) is not str:
            fail(label)
    if not re.fullmatch(r'"[!#-~]{1,240}"', value["etag"]):
        fail(label)
    try:
        result = box.validate_descriptor(value, label)
    except box.MailboxError:
        fail(label)
    name = result["blob"]
    if (type(name) is not str or len(name) > 512
            or type(result["sha256"]) is not str or type(result["etag"]) is not str
            or type(result["versionId"]) is not str
            or not re.fullmatch(r"[A-Za-z0-9._/-]+", name)
            or any(part in {"", ".", ".."} for part in name.split("/"))
            or len(result["etag"]) > 242 or result["size"] > 1073741824
            or (blob is not None and name != blob)):
        fail(label)
    return result


def operation_digest(marker: dict) -> str:
    """Retain the existing app operationBinding array/UTF-8/no-newline domain."""
    value = ["paperdesk-provisional-defender-operation-v1", marker["operationId"],
             marker["candidate"]["sourceSha"], marker["rollback"]["sourceSha"],
             marker["approvalReceiptSha256"], marker["startedAt"], marker["deadlineAt"]]
    return box.digest(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def binding_digest(marker: dict) -> str:
    """Bind every signed field except the digest itself, using mailbox encoding."""
    return box.digest(box.canonical({key: value for key, value in marker.items() if key != "bindingSha256"}))


def validate_marker(value: Any, *, now: dt.datetime) -> dict:
    marker = exact(value, MARKER_FIELDS, "authorization")
    if (type(marker["schemaVersion"]) is not int or marker["schemaVersion"] != 1
            or marker["kind"] != "paperdesk-private-defender-authorization"
            or marker["domain"] != DOMAIN or marker["audience"] != AUDIENCE):
        fail("authorization-domain")
    text(marker["operationId"], OPERATION_ID, "operation-id")
    if re.search(r"example|replace|change[-_.]?me|placeholder|provisional[-_.]?id", marker["operationId"], re.I):
        fail("operation-id")
    for key in ("operationDigestSha256", "bindingSha256", "approvalReceiptSha256"):
        text(marker[key], SHA256, key)
    if type(now) is not dt.datetime or now.tzinfo is None or now.utcoffset() != dt.timedelta(0):
        fail("clock")
    issued = stamp(marker["issuedAt"], "issued-time")
    start = stamp(marker["startedAt"], "start-time")
    deadline = stamp(marker["deadlineAt"], "deadline-time")
    if (issued > start or start - issued > dt.timedelta(minutes=10)
            or not start <= now < deadline - dt.timedelta(seconds=900)
            or not 900 < (deadline - start).total_seconds() <= 86400):
        fail("authorization-window")
    candidate = exact(marker["candidate"], {
        "repository", "sourceSha", "treeSha", "sourceRunId", "sourceRunAttempt", "artifactId",
        "archiveSha256", "packageSha256", "verificationReceiptSha256", "servedIndexSha256", "package",
    }, "candidate")
    control = exact(marker["control"], {
        "repository", "sourceSha", "treeSha", "runId", "runAttempt", "workflowId",
        "bootstrapReceiptSha256", "activationEvidenceSha256", "sourceReviewEvidenceSha256", "bridgePackageSha256",
    }, "control")
    rollback = exact(marker["rollback"], {"sourceSha", "acceptedManifest", "packageSha256", "proofSha256"}, "rollback")
    if candidate["repository"] != "Sethvirak/MasterDataStructure" or control["repository"] != "Sethvirak/paperdesk-release-verifier":
        fail("repository")
    for item in (candidate, control, rollback):
        for key, content in item.items():
            if key.endswith("Sha256"):
                text(content, SHA256, key)
            elif key in {"sourceSha", "treeSha"}:
                text(content, SHA40, key)
            elif key in {"sourceRunId", "sourceRunAttempt", "artifactId", "runId", "runAttempt", "workflowId"}:
                text(content, POSITIVE, key)
    if candidate["sourceSha"] == rollback["sourceSha"]:
        fail("rollback-equals-candidate")
    package = descriptor(candidate["package"], "candidate-package", f"v1/pending/{candidate['sourceSha']}/{candidate['sourceRunId']}-{candidate['sourceRunAttempt']}-{candidate['artifactId']}/deployment.zip")
    if package["sha256"] != candidate["packageSha256"]:
        fail("candidate-package")
    accepted = descriptor(rollback["acceptedManifest"], "rollback-manifest")
    if accepted["blob"] not in {f"v2/accepted/{rollback['sourceSha']}/manifest.json", f"v2/accepted/{rollback['sourceSha']}/bootstrap-consumed/manifest.json"}:
        fail("rollback-manifest")
    if "/bootstrap-consumed/" in accepted["blob"] and rollback["sourceSha"] != box.BOOTSTRAP_BASELINE["sourceSha"]:
        fail("rollback-bootstrap-source")
    database = exact(marker["database"], {"migrationSha256", "schemaSha256", "rolePolicySha256", "checkpointSha256", "writerFenceSha256", "ownerRole", "transitionRole"}, "database")
    if database["ownerRole"] != "paperdesk_provisional_owner" or database["transitionRole"] != "paperdesk_provisional_transition":
        fail("database-role")
    for key in ("migrationSha256", "schemaSha256", "rolePolicySha256", "checkpointSha256", "writerFenceSha256"):
        text(database[key], SHA256, key)
    provider = exact(marker["provider"], {"storageAccountResourceId", "accountUrl", "container", "blobName", "storageReferenceHmac", "referenceKeyId", "referenceKeyGenerationSha256", "systemTopicResourceId", "topicHash", "storageScopeSha256", "fixtureSha256", "fixtureSize"}, "provider")
    account = text(provider["storageAccountResourceId"], STORAGE_ID, "storage-resource")
    account_match = STORAGE_ID.fullmatch(account)
    topic = text(provider["systemTopicResourceId"], TOPIC_ID, "topic-resource")
    topic_match = TOPIC_ID.fullmatch(topic)
    text(account_match[1], GUID, "storage-subscription")
    if topic_match.groups()[:2] != account_match.groups()[:2]:
        fail("provider-scope")
    if provider["accountUrl"] != f"https://{account_match[3]}.blob.core.windows.net":
        fail("account-url")
    text(provider["container"], CONTAINER, "container")
    if "--" in provider["container"]:
        fail("container")
    text(provider["storageReferenceHmac"], re.compile(r"hmac-sha256:[0-9a-f]{64}\Z"), "reference-hmac")
    text(provider["referenceKeyId"], re.compile(r"[A-Za-z0-9._:-]{1,128}\Z"), "reference-key")
    for key in ("referenceKeyGenerationSha256", "storageScopeSha256", "fixtureSha256"):
        text(provider[key], SHA256, key)
    text(provider["topicHash"], re.compile(r"sha256:[0-9a-f]{64}\Z"), "topic-hash")
    if type(provider["fixtureSize"]) is not int or not 1 <= provider["fixtureSize"] <= 4096:
        fail("fixture-size")
    principals = exact(marker["principals"], {"tenantId", "signerObjectId", "canaryObjectId", "eventGridObjectId", "canaryClientId", "eventGridClientId", "canaryAudience", "eventGridAudience", "issuer"}, "principals")
    for key in ("tenantId", "signerObjectId", "canaryObjectId", "eventGridObjectId", "canaryClientId", "eventGridClientId"):
        text(principals[key], GUID, key)
    if len({principals[key] for key in ("signerObjectId", "canaryObjectId", "eventGridObjectId")}) != 3 or principals["canaryClientId"] == principals["eventGridClientId"]:
        fail("principal-separation")
    for key in ("canaryAudience", "eventGridAudience"):
        text(principals[key], re.compile(r"api://[0-9a-f-]{36}\Z"), key)
        text(principals[key][6:], GUID, key)
    if principals["issuer"] != f"https://sts.windows.net/{principals['tenantId']}/":
        fail("principal-issuer")
    evidence = exact(marker["evidence"], {"repository", "maintenance", "capacity", "ingress", "cohortDrain", "rollbackDeadline", "providerBinding", "deliveryProvenance"}, "evidence")
    for key, item in evidence.items():
        item = descriptor(item, "evidence-" + key)
        if not item["blob"].startswith("v2/provisional-evidence/"):
            fail("evidence-prefix")
    if box.canonical(marker["lifecycle"]) != box.canonical(LIFECYCLE):
        fail("lifecycle")
    if marker["operationDigestSha256"] != operation_digest(marker) or marker["bindingSha256"] != binding_digest(marker):
        fail("operation-binding")
    target = box.digest(json.dumps(["paperdesk-provisional-defender-object-v1", marker["operationDigestSha256"]], separators=(",", ":")).encode())[:32]
    if provider["blobName"] != f"__paperdesk-defender-canary/v1/{target}.txt":
        fail("reserved-target")
    return marker


def _b64(value: Any, label: str) -> bytes:
    value = text(value, re.compile(r"[A-Za-z0-9_-]{1,1024}\Z"), label)
    try:
        raw = base64.urlsafe_b64decode(value + "=" * ((-len(value)) % 4))
    except ValueError:
        fail(label)
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        fail(label + "-canonical")
    return raw


def validate_key(value: Any) -> dict:
    key = exact(value, {"keyId", "keyVersion", "publicJwk"}, "inspection-key")
    text(key["keyId"], KEY_ID, "key-id")
    text(key["keyVersion"], re.compile(r"[0-9a-f]{32}\Z"), "key-version")
    jwk = exact(key["publicJwk"], {"kty", "kid", "n", "e", "key_ops"}, "public-jwk")
    if jwk["kty"] != "RSA" or jwk["kid"] != key["keyId"] + "/" + key["keyVersion"] or jwk["key_ops"] != ["sign", "verify"]:
        fail("public-jwk")
    modulus = _b64(jwk["n"], "public-modulus")
    exponent = _b64(jwk["e"], "public-exponent")
    number = int.from_bytes(modulus, "big")
    if len(modulus) != 384 or number.bit_length() != 3072 or number % 2 != 1 or exponent != b"\x01\x00\x01":
        fail("public-key-strength")
    return key


def inspect_candidate_record(record: box.WormRecord, *, pins_raw: bytes, now: dt.datetime) -> dict:
    """Verify exact supplied bytes against comparison pins, returning NO authority.

    The caller must already possess bytes; no boundary/callback/transport is
    accepted. A fabricated record or self-selected key can satisfy inspection
    but cannot satisfy the unavailable admission function below.
    """
    validate_policy()
    pins = strict_json(pins_raw, MAX_PINS_BYTES, "inspection-pins")
    exact(pins, {"schemaVersion", "purpose", "signing", "markerDescriptor", "expectedAuthorization"}, "inspection-pins")
    if type(pins["schemaVersion"]) is not int or pins["schemaVersion"] != 1 or pins["purpose"] != "candidate-inspection-only":
        fail("inspection-purpose")
    expected = validate_marker(pins["expectedAuthorization"], now=now)
    key = validate_key(pins["signing"])
    marker_blob = f"v2/provisional/{expected['operationDigestSha256']}/authorization.json"
    pinned_descriptor = descriptor(pins["markerDescriptor"], "marker-descriptor", marker_blob)
    if (pinned_descriptor["size"] > MAX_MARKER_BYTES or type(record) is not box.WormRecord
            or any(type(value) is not str or not value for value in (record.blob, record.etag, record.version_id))
            or type(record.body) is not bytes or not 0 < len(record.body) <= MAX_MARKER_BYTES):
        fail("marker-record")
    try:
        observed_descriptor = box._worm_descriptor(record)
    except box.MailboxError:
        fail("marker-record")
    if observed_descriptor != pinned_descriptor:
        fail("marker-readback")
    envelope = strict_json(record.body, MAX_MARKER_BYTES, "marker")
    exact(envelope, {"authorization", "signature"}, "marker-envelope")
    marker = validate_marker(envelope["authorization"], now=now)
    if box.canonical(marker) != box.canonical(expected):
        fail("marker-pin-binding")
    signing = exact(envelope["signature"], {"algorithm", "keyId", "keyVersion", "value"}, "marker-signature")
    if signing["algorithm"] != "PS256" or signing["keyId"] != key["keyId"] or signing["keyVersion"] != key["keyVersion"]:
        fail("marker-signature-key")
    signature = _b64(signing["value"], "signature")
    if len(signature) != 384 or int.from_bytes(signature, "big") >= int.from_bytes(_b64(key["publicJwk"]["n"], "public-modulus"), "big"):
        fail("signature-range")
    try:
        box.verify_ps256(box.canonical(marker), signing["value"], key["publicJwk"], key["publicJwk"]["kid"])
    except (box.MailboxError, ValueError, OverflowError):
        fail("marker-signature-invalid")
    return {
        "schemaVersion": 1, "status": "cryptographic-candidate-only",
        "markerSha256": box.digest(record.body), "bindingSha256": marker["bindingSha256"],
        "operationDigestSha256": marker["operationDigestSha256"],
        "inspectionPinsSha256": box.digest(pins_raw), "signatureValidForSuppliedKey": True,
        "externalAuthorityVerified": False, "providerReadbackVerified": False,
        "oneUseStateVerified": False, "authorizationAdmissionAllowed": False,
        "activationAllowed": False, "candidateConsumeAllowed": False,
        "acceptedRegistryWriteAllowed": False,
    }


def admit_authorization(*args: Any, **kwargs: Any) -> None:
    """There is no independently admitted issuer/provider/one-use context yet.

    Reject before inspecting arguments, calling a callback, reading a record or
    invoking any crypto/provider/database work. No boolean or role opens this.
    """
    fail("PROVISIONAL_DEFENDER_AUTHORIZATION_ADMISSION_UNAVAILABLE")
