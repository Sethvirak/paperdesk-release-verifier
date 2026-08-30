"""Canonical, secret-free receipts for the one-shot private-release V2 bootstrap.

This module performs no Azure, GitHub, filesystem-write, or credential action.
The bootstrap executor supplies already observed nonsecret projections; this
module builds canonical documents and rejects any receipt bundle that is not
exactly bound to the reviewed one-shot authorization and bootstrap plan.
"""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import ipaddress
import json
import re
import urllib.parse
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "contracts" / "private_release_bootstrap_evidence_model.json"
PLAN_PATH = ROOT / "contracts" / "private_release_bootstrap_plan.json"

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
QUOTED_ETAG = re.compile(r'^"[^"\r\n]+"$')
RAW_IPV4 = re.compile(
    r"(?<![0-9])(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}(?:/\d{1,2})?(?![0-9])"
)
PRIVATE_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
SAS_QUERY = re.compile(
    r"(?:\?|&)(?:sig|sv|se|sp|sr|sip|spr|st|srt|ss|skoid|sktid|skt|ske|sks|skv)=",
    re.IGNORECASE,
)
SECRET_VALUE = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+|\bSharedKey\s+|"
    r"AccountKey=|DefaultEndpointsProtocol=)",
    re.IGNORECASE,
)
COMPACT_JOSE = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}"
    r"(?:\.[A-Za-z0-9_-]{8,}){2,4}"
    r"(?![A-Za-z0-9_-])"
)
COMPACT_JOSE_OPAQUE = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{32,}"
    r"(?:\.[A-Za-z0-9_-]{32,}){2,4}(?![A-Za-z0-9_-])"
)

MODEL_KEYS = {
    "schemaVersion",
    "modelId",
    "status",
    "canonicalEncoding",
    "bundleType",
    "requiredBundleComponents",
    "publicEvidenceBoundary",
    "constants",
    "initialActivationFenceDocument",
    "receiptTypes",
    "requiredS2EvidencePaths",
    "requiredS2TerminalBundlePath",
    "rules",
}


class BootstrapReceiptError(ValueError):
    """A bootstrap receipt or cross-binding failed closed."""


def fail(message: str) -> None:
    raise BootstrapReceiptError(message)


def _reject_floats(value: Any, label: str = "document") -> None:
    if isinstance(value, float):
        fail(f"{label} contains a floating-point value")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                fail(f"{label} contains a non-string key")
            _reject_floats(item, f"{label}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            _reject_floats(item, f"{label}[{index}]")


def canonical_json_bytes(document: Any) -> bytes:
    """Return compact, sorted, UTF-8, newline-terminated canonical JSON."""

    _reject_floats(document)
    try:
        rendered = json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise BootstrapReceiptError("document is not canonical-JSON representable") from exc
    return (rendered + "\n").encode("utf-8")


def sha256_hex(value: bytes | bytearray | Mapping[str, Any] | Sequence[Any]) -> str:
    """Hash exact bytes or the canonical representation of a JSON value."""

    if isinstance(value, (bytes, bytearray)):
        body = bytes(value)
    else:
        body = canonical_json_bytes(value)
    return hashlib.sha256(body).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def load_canonical_json_bytes(
    raw: bytes | bytearray,
    *,
    label: str = "canonical JSON",
    maximum_bytes: int = 1024 * 1024,
) -> Any:
    """Load exact canonical bytes; whitespace, BOM and duplicate keys fail."""

    if not isinstance(raw, (bytes, bytearray)):
        fail(f"{label} must be bytes")
    body = bytes(raw)
    if not body or len(body) > maximum_bytes or body.startswith(b"\xef\xbb\xbf"):
        fail(f"{label} has an invalid byte boundary")
    try:
        text = body.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=_unique_object)
    except BootstrapReceiptError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BootstrapReceiptError(f"{label} is invalid JSON") from exc
    if canonical_json_bytes(value) != body:
        fail(f"{label} is not canonical JSON")
    return value


def _exact_keys(value: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        fail(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        missing = ",".join(sorted(expected - actual)) or "-"
        extra = ",".join(sorted(actual - expected)) or "-"
        fail(f"{label} fields are not exact (missing={missing}; extra={extra})")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        fail(f"{label} must be an array")
    return value


def _string(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        fail(f"{label} must be a nonempty string")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        fail(f"{label} must be an integer >= {minimum}")
    return value


def _hash(value: Any, label: str) -> str:
    text = _string(value, label)
    if not SHA256.fullmatch(text):
        fail(f"{label} must be lowercase SHA-256")
    return text


def _sha40(value: Any, label: str) -> str:
    text = _string(value, label)
    if not SHA40.fullmatch(text):
        fail(f"{label} must be a lowercase 40-character commit SHA")
    return text


def _guid(value: Any, label: str) -> str:
    text = _string(value, label)
    if not GUID.fullmatch(text):
        fail(f"{label} must be a lowercase UUID")
    return text


def _etag(value: Any, label: str) -> str:
    text = _string(value, label)
    if not QUOTED_ETAG.fullmatch(text):
        fail(f"{label} must be a quoted ETag")
    return text


def _timestamp(value: Any, label: str) -> dt.datetime:
    text = _string(value, label)
    if not STAMP.fullmatch(text):
        fail(f"{label} must be UTC with millisecond precision")
    try:
        return dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError as exc:
        raise BootstrapReceiptError(f"{label} is not a valid timestamp") from exc


def format_timestamp(value: dt.datetime) -> str:
    if not isinstance(value, dt.datetime) or value.tzinfo is None:
        fail("timestamp must be timezone-aware")
    utc = value.astimezone(dt.timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def _normalized_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _reject_secret_material(value: Any, label: str = "bundle") -> None:
    forbidden_keys = {
        "accesstoken",
        "refreshtoken",
        "githubtoken",
        "oidctoken",
        "sas",
        "sasuri",
        "sasurl",
        "storageaccountkey",
        "sharedkey",
        "password",
        "privatekey",
        "rawip",
        "rawipv4",
        "publicip",
        "publicipv4",
    }
    forbidden_sas_keys = {
        "sig",
        "sv",
        "se",
        "sp",
        "sr",
        "sip",
        "spr",
        "st",
        "srt",
        "ss",
        "skoid",
        "sktid",
        "skt",
        "ske",
        "sks",
        "skv",
    }
    if isinstance(value, Mapping):
        normalized_keys = {
            _normalized_key(urllib.parse.unquote(str(key))) for key in value
        }
        if {"iss", "sub"}.issubset(normalized_keys) or {
            "repositoryid",
            "repositoryownerid",
            "jobworkflowref",
        }.issubset(normalized_keys):
            fail(f"{label} contains a raw OIDC claims projection")
        for key, item in value.items():
            normalized = _normalized_key(urllib.parse.unquote(str(key)))
            if normalized in forbidden_keys or normalized in forbidden_sas_keys:
                fail(f"{label} contains forbidden field {key}")
            _reject_secret_material(item, f"{label}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            _reject_secret_material(item, f"{label}[{index}]")
    elif isinstance(value, str):
        variants: list[str] = []
        candidate = value
        for _ in range(5):
            if candidate in variants:
                break
            variants.append(candidate)
            decoded = urllib.parse.unquote(candidate)
            if decoded == candidate:
                break
            candidate = decoded
        for candidate in variants:
            for match in RAW_IPV4.finditer(candidate):
                address = ipaddress.ip_address(match.group(0).split("/", 1)[0])
                if not any(address in network for network in PRIVATE_IPV4_NETWORKS):
                    fail(f"{label} contains a raw public IPv4 address")
            if COMPACT_JOSE.search(candidate) or COMPACT_JOSE_OPAQUE.search(candidate):
                fail(f"{label} contains compact JOSE/OIDC material")
            if SAS_QUERY.search(candidate) or SECRET_VALUE.search(candidate):
                fail(f"{label} contains secret or capability material")


def load_model(path: Path | str = MODEL_PATH) -> dict[str, Any]:
    model_path = Path(path)
    try:
        model = json.loads(model_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BootstrapReceiptError("bootstrap evidence model cannot be loaded") from exc
    _exact_keys(model, MODEL_KEYS, "bootstrap evidence model")
    if (
        model["schemaVersion"] != 1
        or model["modelId"] != "paperdesk-private-release-v2-bootstrap-evidence-v1"
        or model["status"] != "source-dormant-model-only"
        or model["canonicalEncoding"] != "utf-8-json-sort-keys-compact-newline"
    ):
        fail("bootstrap evidence model identity is invalid")
    components = _list(model["requiredBundleComponents"], "model requiredBundleComponents")
    if len(components) != len(set(components)) or components != list(RECEIPT_COMPONENTS):
        fail("bootstrap evidence component order is invalid")
    _reject_secret_material(model["initialActivationFenceDocument"], "initial fence model")
    return copy.deepcopy(model)


RECEIPT_COMPONENTS = (
    "executionReceipt",
    "permanentMutationLedger",
    "temporaryAccessCleanup",
    "activationFenceBootstrap",
    "packageReadback",
    "managedIdentityFetchSelfTest",
    "bridgeEvidence",
    "leaseCanaryEvidence",
    "wormProjections",
    "s2OutputMetadata",
)

COMPONENT_DIGEST_KEYS = tuple(name for name in RECEIPT_COMPONENTS if name != "executionReceipt")

S2_EVIDENCE_COMPONENT_PATHS = {
    "provisioningEvidence": "evidence/private-release-provisioning-evidence.json",
    "bridgeRuntimeReceipt": "evidence/private-release-bridge-runtime-receipt.json",
    "temporaryAccessCleanup": (
        "evidence/private-release-bootstrap-temporary-access-cleanup-receipt.json"
    ),
    "activationFenceBootstrap": (
        "evidence/private-release-activation-fence-bootstrap-receipt.json"
    ),
    "bridgeEvidence": "evidence/private-release-bridge-canary-receipt.json",
}

S2_TERMINAL_BUNDLE_PATH = "evidence/private-release-bootstrap-receipt-bundle.json"
RICH_EVIDENCE_RULE = (
    "All source-pinned and action-time authorization evidence must match exactly "
    "before every privileged phase."
)


def _resource(plan: Mapping[str, Any], resource_id: str) -> Mapping[str, Any]:
    inventory = _list(plan.get("resourceInventory"), "plan.resourceInventory")
    matches = [item for item in inventory if isinstance(item, Mapping) and item.get("id") == resource_id]
    if len(matches) != 1:
        fail(f"plan resource {resource_id} is not unique")
    return matches[0]


def _plan_mutations(plan: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    mutations = _list(plan.get("mutations"), "plan.mutations")
    if not mutations:
        fail("plan has no mutations")
    ids: list[str] = []
    for index, item in enumerate(mutations):
        _exact_keys(item, {"id", "kind", "target", "temporary", "irreversible"}, f"plan.mutations[{index}]")
        ids.append(_string(item["id"], f"plan.mutations[{index}].id"))
    if len(ids) != len(set(ids)):
        fail("plan contains duplicate mutation IDs")
    return mutations


def _expected_permanent_mutations(plan: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [
        item
        for item in _plan_mutations(plan)
        if item["temporary"] is False and item["id"] != "captureCanonicalBootstrapReceipts"
    ]


def _context(authorization: Mapping[str, Any], plan: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(authorization, Mapping) or not isinstance(plan, Mapping):
        fail("authorization and plan must be objects")
    _exact_keys(
        authorization,
        {
            "schemaVersion",
            "authorizationType",
            "authorizationId",
            "repository",
            "source",
            "executor",
            "plan",
            "azure",
            "observedPreflight",
            "validity",
            "confirmation",
            "singleUse",
        },
        "authorization",
    )
    if authorization["schemaVersion"] != 1 or authorization["authorizationType"] != "paperdesk-private-release-v2-bootstrap-one-shot":
        fail("authorization identity is invalid")
    authorization_id = _guid(authorization["authorizationId"], "authorization.authorizationId")
    source = _exact_keys(authorization["source"], {"reviewedHead", "mergedMain"}, "authorization.source")
    if authorization["repository"] != "Sethvirak/paperdesk-release-verifier":
        fail("authorization repository is invalid")
    reviewed = _exact_keys(
        source["reviewedHead"],
        {
            "commitSha",
            "treeSha",
            "signatureVerified",
            "signingPrincipal",
            "signingKeyFingerprint",
            "pullRequestNumber",
            "pullRequestUrl",
            "reviewDecision",
            "requiredApprovals",
            "pushedAt",
            "reviews",
            "requiredCheck",
        },
        "authorization.source.reviewedHead",
    )
    merged = _exact_keys(
        source["mergedMain"],
        {
            "commitSha",
            "treeSha",
            "soleParentSha",
            "treeEqualsReviewedHead",
            "githubVerificationVerified",
            "githubVerificationReason",
            "mergedPullRequestNumber",
            "mergedPullRequestUrl",
            "mergedAt",
            "verificationApiUrl",
            "verificationRetrievedAt",
        },
        "authorization.source.mergedMain",
    )
    reviewed_sha = _sha40(reviewed.get("commitSha"), "authorization reviewed head")
    merged_sha = _sha40(merged.get("commitSha"), "authorization merged main")
    reviewed_tree = _sha40(reviewed.get("treeSha"), "authorization reviewed tree")
    merged_tree = _sha40(merged.get("treeSha"), "authorization merged tree")
    if reviewed_tree != merged_tree or merged.get("treeEqualsReviewedHead") is not True:
        fail("authorization reviewed and merged trees do not match")

    auth_executor = _exact_keys(
        authorization["executor"], {"path", "sha256"}, "authorization.executor"
    )
    auth_plan = _exact_keys(
        authorization["plan"],
        {
            "path",
            "sha256",
            "resourceIds",
            "mutationIds",
            "irreversibleMutationIds",
            "postconditionIds",
            "bridgePackageSourceSha",
            "bridgePackageSha256",
            "bridgePackageSize",
        },
        "authorization.plan",
    )
    auth_azure = _exact_keys(
        authorization["azure"],
        {
            "cloud",
            "subscriptionId",
            "tenantId",
            "accountId",
            "accountObjectId",
            "accountType",
        },
        "authorization.azure",
    )
    observed = _exact_keys(
        authorization["observedPreflight"],
        {"sha256", "observedAt", "maximumAgeSeconds"},
        "authorization.observedPreflight",
    )
    validity = _exact_keys(
        authorization["validity"],
        {"notBefore", "expiresAt", "maximumLifetimeSeconds"},
        "authorization.validity",
    )
    confirmation = _exact_keys(
        authorization["confirmation"],
        {"encoding", "phraseSha256"},
        "authorization.confirmation",
    )
    single_use = _exact_keys(
        authorization["singleUse"],
        {"required", "receiptDirectory", "azureClaimResourceId"},
        "authorization.singleUse",
    )
    if (
        auth_executor["path"] != "scripts/private_release_v2_bootstrap.py"
        or auth_plan["path"] != "contracts/private_release_bootstrap_plan.json"
        or validity["maximumLifetimeSeconds"] != 1800
        or observed["maximumAgeSeconds"] != 300
        or confirmation["encoding"] != "utf-8-exact-no-newline"
    ):
        fail("authorization fixed execution policy is invalid")
    _hash(confirmation["phraseSha256"], "authorization confirmation phrase digest")

    mutations = _plan_mutations(plan)
    mutation_ids = [item["id"] for item in mutations]
    resource_ids = [item.get("id") for item in _list(plan.get("resourceInventory"), "plan.resourceInventory")]
    mutation_irreversible = [item["id"] for item in mutations if item["irreversible"] is True]
    irreversible = _list(plan.get("irreversibleMutationIds"), "plan.irreversibleMutationIds")
    postcondition_ids = [
        item.get("id") for item in _list(plan.get("postconditions"), "plan.postconditions")
    ]
    if auth_plan.get("resourceIds") != resource_ids:
        fail("authorization resource IDs do not match the reviewed plan")
    if auth_plan.get("mutationIds") != mutation_ids:
        fail("authorization mutation IDs do not match the reviewed plan")
    if auth_plan.get("irreversibleMutationIds") != irreversible:
        fail("authorization irreversible mutation IDs do not match the reviewed plan")
    if auth_plan.get("postconditionIds") != postcondition_ids:
        fail("authorization postcondition IDs do not match the reviewed plan")
    if len(irreversible) != len(set(irreversible)) or set(irreversible) != set(mutation_irreversible):
        fail("plan irreversible mutation projection is inconsistent")

    model = load_model()
    constants = model["constants"]
    if (
        auth_azure.get("cloud") != "AzureCloud"
        or auth_azure.get("subscriptionId") != constants["subscriptionId"]
        or auth_azure.get("tenantId") != constants["tenantId"]
    ):
        fail("authorization Azure coordinates are invalid")
    operator_object = _guid(auth_azure.get("accountObjectId"), "authorization Azure account object")
    operator_account = _string(auth_azure.get("accountId"), "authorization Azure account ID")
    operator_type = auth_azure.get("accountType")
    if operator_type not in {"user", "servicePrincipal"}:
        fail("authorization Azure account type is invalid")
    not_before = _timestamp(validity.get("notBefore"), "authorization notBefore")
    expires_at = _timestamp(validity.get("expiresAt"), "authorization expiresAt")
    if expires_at <= not_before or (expires_at - not_before).total_seconds() > 1800:
        fail("authorization validity window is invalid")
    expected_claim_resource_id = (
        f"/subscriptions/{constants['subscriptionId']}/providers/Microsoft.Resources/deployments/"
        f"paperdesk-v2-bootstrap-{authorization_id}"
    )
    if (
        single_use["required"] is not True
        or single_use["azureClaimResourceId"] != expected_claim_resource_id
    ):
        fail("authorization one-shot Azure claim binding is invalid")

    package_source_sha = _sha40(
        auth_plan.get("bridgePackageSourceSha", merged_sha),
        "authorization package source",
    )

    bootstrap = _load_bootstrap_source()
    reviewed_plan, plan_sha256 = bootstrap.load_plan()
    if dict(plan) != reviewed_plan:
        fail("supplied plan does not equal the reviewed source plan")
    if auth_plan.get("sha256") != plan_sha256:
        fail("authorization plan digest does not match the reviewed plan file bytes")
    authorization_validator = getattr(
        bootstrap, "validate_authorization_evidence", None
    )
    if not callable(authorization_validator):
        fail("the source-owned immutable authorization validator is unavailable")
    try:
        validated_authorization = authorization_validator(
            authorization,
            plan=reviewed_plan,
            plan_sha256=plan_sha256,
        )
    except Exception as exc:
        if isinstance(exc, BootstrapReceiptError):
            raise
        raise BootstrapReceiptError(
            f"immutable authorization evidence is invalid: {exc}"
        ) from exc
    if dict(validated_authorization.document) != dict(authorization):
        fail("immutable authorization validator changed the supplied evidence")
    if context_terminal_path := model.get("requiredS2TerminalBundlePath"):
        if context_terminal_path != S2_TERMINAL_BUNDLE_PATH:
            fail("terminal receipt bundle path is not exact")
    else:
        fail("bootstrap evidence model lacks the durable terminal bundle path")

    return {
        "model": model,
        "authorizationId": authorization_id,
        "authorizationSha256": validated_authorization.sha256,
        "reviewedHeadSha": reviewed_sha,
        "mergedMainSha": merged_sha,
        "treeSha": reviewed_tree,
        "executorPath": _string(auth_executor.get("path"), "authorization executor path"),
        "executorSha256": _hash(auth_executor.get("sha256"), "authorization executor digest"),
        "planPath": _string(auth_plan.get("path"), "authorization plan path"),
        "planSha256": plan_sha256,
        "reviewedPlan": copy.deepcopy(reviewed_plan),
        "packageSourceSha": package_source_sha,
        "packageSha256": _hash(auth_plan.get("bridgePackageSha256"), "authorization package digest"),
        "packageSize": _integer(auth_plan.get("bridgePackageSize"), "authorization package size", minimum=1),
        "subscriptionId": auth_azure["subscriptionId"],
        "tenantId": auth_azure["tenantId"],
        "operatorObjectId": operator_object,
        "operatorAccountIdSha256": hashlib.sha256(operator_account.encode("utf-8")).hexdigest(),
        "operatorAccountType": operator_type,
        "preflightSha256": _hash(observed.get("sha256"), "authorization preflight digest"),
        "preflightAt": _timestamp(observed.get("observedAt"), "authorization preflight observedAt"),
        "preflightMaximumAge": _integer(observed.get("maximumAgeSeconds"), "preflight maximum age", minimum=1),
        "notBefore": not_before,
        "expiresAt": expires_at,
        "azureClaimResourceId": expected_claim_resource_id,
        "mutationIds": mutation_ids,
        "irreversibleMutationIds": irreversible,
    }


SOURCE_EVIDENCE_KEYS = {
    "schemaVersion",
    "evidenceType",
    "authorizationId",
    "authorizationSha256",
    "mergedSourceSha",
    "treeSha",
    "planSha256",
    "authorizedPreflightProjection",
    "claimReceipt",
    "allOperationProjections",
    "permanentMutationProjections",
    "postconditionProjections",
    "packageReadbackProjection",
    "managedIdentityFetchResponseProjection",
    "bridgeCanaryProof",
    "leaseCanaryProofs",
    "richProvisioningSourceProjections",
    "cleanupAbsenceProjections",
    "wormSourceProjections",
    "productionBoundary",
    "observedAt",
}


def _canonical_projection(value: Any, label: str) -> Any:
    if not isinstance(value, (Mapping, list)):
        fail(f"{label} must be a canonical object or array")
    canonical = load_canonical_json_bytes(canonical_json_bytes(value), label=label)
    _reject_secret_material(canonical, label)
    return canonical


def _load_bootstrap_source() -> Any:
    try:
        from scripts import private_release_v2_bootstrap as bootstrap
    except (ImportError, ModuleNotFoundError):
        try:
            import private_release_v2_bootstrap as bootstrap  # type: ignore[no-redef]
        except (ImportError, ModuleNotFoundError) as exc:
            raise BootstrapReceiptError(
                "the source-owned bootstrap module is unavailable"
            ) from exc
    return bootstrap


def _load_source_evidence_validator() -> Any:
    bootstrap = _load_bootstrap_source()
    validator = getattr(bootstrap, "validate_terminal_source_evidence", None)
    if not callable(validator):
        fail("the source-owned bootstrap evidence validator is unavailable")
    return validator


def _source_operation_universe(
    value: Any,
    *,
    plan: Mapping[str, Any],
    started_at: dt.datetime,
    completed_at: dt.datetime,
) -> dict[str, Mapping[str, Any]]:
    """Retain every validated source operation inside the actual execution."""

    expected = [
        item
        for item in _plan_mutations(plan)
        if item["kind"] != "local-create-only-canonical-evidence"
    ]
    entries = _list(value, "sourceEvidence.allOperationProjections")
    if len(entries) != len(expected):
        fail("source operation projection universe is incomplete")
    by_id: dict[str, Mapping[str, Any]] = {}
    for index, (raw, mutation) in enumerate(zip(entries, expected)):
        entry = _exact_keys(
            raw,
            {"operationId", "sourceProjection", "observedAt"},
            f"source operation projection {index}",
        )
        if entry["operationId"] != mutation["id"]:
            fail("source operation projection universe is reordered")
        _observation_in_window(
            entry["observedAt"],
            f"source operation {mutation['id']} observedAt",
            started_at=started_at,
            completed_at=completed_at,
        )
        by_id[mutation["id"]] = {
            "sourceProjection": _canonical_projection(
                entry["sourceProjection"],
                f"source operation {mutation['id']}.sourceProjection",
            ),
            "observedAt": entry["observedAt"],
        }
    return by_id


def _validate_postcondition_execution_window(
    value: Any,
    *,
    plan: Mapping[str, Any],
    started_at: dt.datetime,
    completed_at: dt.datetime,
) -> None:
    """Require every postcondition observation to belong to this execution."""

    expected = _list(plan.get("postconditions"), "plan.postconditions")
    entries = _list(value, "sourceEvidence.postconditionProjections")
    if len(entries) != len(expected):
        fail("source postcondition projection universe is incomplete")
    for index, (raw, postcondition) in enumerate(zip(entries, expected)):
        if not isinstance(postcondition, Mapping):
            fail("plan postcondition is invalid")
        entry = _exact_keys(
            raw,
            {"postconditionId", "sourceProjection", "observedAt"},
            f"source postcondition projection {index}",
        )
        if entry["postconditionId"] != postcondition.get("id"):
            fail("source postcondition projection universe is reordered")
        _canonical_projection(
            entry["sourceProjection"],
            f"source postcondition {entry['postconditionId']}.sourceProjection",
        )
        _observation_in_window(
            entry["observedAt"],
            f"source postcondition {entry['postconditionId']} observedAt",
            started_at=started_at,
            completed_at=completed_at,
        )


def _authorized_operation_contexts(
    preflight_projection: Mapping[str, Any],
    *,
    operation_ids: set[str],
) -> dict[str, Mapping[str, Any]]:
    admissions = _list(
        preflight_projection.get("operationAdmissions"),
        "authorized preflight operationAdmissions",
    )
    contexts: dict[str, Mapping[str, Any]] = {}
    for raw in admissions:
        if not isinstance(raw, Mapping):
            fail("authorized operation admission is invalid")
        operation_id = raw.get("operationId")
        context = raw.get("context")
        if (
            not isinstance(operation_id, str)
            or operation_id in contexts
            or not isinstance(context, Mapping)
        ):
            fail("authorized operation admissions are duplicate or invalid")
        contexts[operation_id] = context
    if set(contexts) != operation_ids:
        fail("authorized operation-context universe is incomplete")
    return contexts


def _validate_claim_receipt(
    value: Any,
    context: Mapping[str, Any],
    *,
    started_at: dt.datetime,
    completed_at: dt.datetime,
) -> Mapping[str, Any]:
    claim = _exact_keys(
        value,
        {
            "schemaVersion",
            "evidenceType",
            "authorizationId",
            "authorizationSha256",
            "source",
            "plan",
            "package",
            "azureClaimResourceId",
            "createHttpStatus",
            "createResponseProjection",
            "readbackHttpStatus",
            "readbackProjection",
            "claimedAt",
            "observedAt",
        },
        "claim receipt",
    )
    if (
        claim["schemaVersion"] != 1
        or claim["evidenceType"]
        != "paperdesk-private-release-v2-bootstrap-one-shot-claim-proof-v1"
        or claim["authorizationId"] != context["authorizationId"]
        or claim["authorizationSha256"] != context["authorizationSha256"]
        or claim["azureClaimResourceId"] != context["azureClaimResourceId"]
        or claim["createHttpStatus"] != 201
        or claim["readbackHttpStatus"] != 200
    ):
        fail("one-shot claim proof identity, resource, or HTTP status is invalid")
    if _exact_keys(claim["source"], {"mergedSourceSha", "treeSha"}, "claim source") != {
        "mergedSourceSha": context["mergedMainSha"],
        "treeSha": context["treeSha"],
    }:
        fail("one-shot claim source binding is invalid")
    if _exact_keys(claim["plan"], {"path", "sha256"}, "claim plan") != {
        "path": context["planPath"],
        "sha256": context["planSha256"],
    }:
        fail("one-shot claim plan binding is invalid")
    if _exact_keys(
        claim["package"], {"sourceSha", "sha256", "size"}, "claim package"
    ) != {
        "sourceSha": context["packageSourceSha"],
        "sha256": context["packageSha256"],
        "size": context["packageSize"],
    }:
        fail("one-shot claim package binding is invalid")
    expected_output = {
        "authorizationId": context["authorizationId"],
        "authorizationSha256": context["authorizationSha256"],
        "sourceSha": context["mergedMainSha"],
        "planSha256": context["planSha256"],
        "packageSha256": context["packageSha256"],
    }
    deployment_name = context["azureClaimResourceId"].rsplit("/", 1)[-1]
    expected_projection = {
        "resourceId": context["azureClaimResourceId"],
        "deploymentName": deployment_name,
        "provisioningState": "Succeeded",
        "claim": expected_output,
    }
    create_projection = _canonical_projection(
        claim["createResponseProjection"], "claim create response projection"
    )
    readback_projection = _canonical_projection(
        claim["readbackProjection"], "claim readback projection"
    )
    if create_projection != expected_projection or readback_projection != expected_projection:
        fail("one-shot claim create/readback projection is not exact")
    claimed_at = _timestamp(claim["claimedAt"], "claim receipt claimedAt")
    if claimed_at != started_at:
        fail("one-shot claim timestamp does not start the execution window")
    _observation_in_window(
        claim["observedAt"],
        "claim receipt observedAt",
        started_at=started_at,
        completed_at=completed_at,
    )
    return claim


def _validate_permanent_source_projections(
    value: Any,
    context: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    started_at: dt.datetime,
    completed_at: dt.datetime,
) -> dict[str, Mapping[str, Any]]:
    expected = _expected_permanent_mutations(plan)
    projections = _list(value, "sourceEvidence.permanentMutationProjections")
    if len(projections) != len(expected):
        fail("permanent source-projection universe is incomplete")
    by_id: dict[str, Mapping[str, Any]] = {}
    allowed_outcomes = {
        "created",
        "adopted-exact",
        "updated-exact",
        "deleted-exact",
        "read-back-exact",
    }
    for index, (projection_value, mutation) in enumerate(zip(projections, expected)):
        projection = _exact_keys(
            projection_value,
            {
                "mutationId",
                "target",
                "kind",
                "outcome",
                "sourceProjection",
                "observedAt",
            },
            f"permanent source projection {index}",
        )
        if (
            projection["mutationId"] != mutation["id"]
            or projection["target"] != mutation["target"]
            or projection["kind"] != mutation["kind"]
            or projection["outcome"] not in allowed_outcomes
        ):
            fail(f"permanent source projection {mutation['id']} is not plan-bound")
        source = _canonical_projection(
            projection["sourceProjection"],
            f"permanent source projection {mutation['id']}.sourceProjection",
        )
        if not source:
            fail(f"permanent source projection {mutation['id']} is empty")
        _observation_in_window(
            projection["observedAt"],
            f"permanent source projection {mutation['id']}.observedAt",
            started_at=started_at,
            completed_at=completed_at,
        )
        by_id[mutation["id"]] = projection
    return by_id


def _journal_bound_create_or_adopt_fields(
    *,
    operation_id: str,
    permanent: Mapping[str, Mapping[str, Any]],
    journal: Sequence[Mapping[str, Any]],
    operation_source: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind create/adopt vocabulary and blob version headers to the journal."""

    permanent_entry = permanent.get(operation_id)
    if not isinstance(permanent_entry, Mapping):
        fail(f"create-or-adopt permanent source is missing for {operation_id}")
    operation_projection = operation_source.get("projection")
    if not isinstance(operation_projection, Mapping):
        fail(f"create-or-adopt operation source is incomplete for {operation_id}")
    expected_etag = operation_projection.get("etag")
    expected_version = operation_projection.get("versionId")
    _etag(expected_etag, f"{operation_id} source ETag")
    _string(expected_version, f"{operation_id} source version ID")
    successful_results = [
        item
        for item in journal
        if item.get("phase") == "result"
        and item.get("operationId") == operation_id
        and type(item.get("status")) is int
        and 200 <= item["status"] <= 299
    ]
    outcome = permanent_entry.get("outcome")
    if outcome == "created":
        if (
            len(successful_results) != 1
            or successful_results[0].get("status") != 201
            or successful_results[0].get("etag") != expected_etag
            or successful_results[0].get("versionId") != expected_version
        ):
            fail(f"{operation_id} create result is not version/readback-bound")
        return {
            "provisioningOutcome": "created-by-authorization",
            "createCondition": "If-None-Match:*",
            "createHttpStatus": 201,
        }
    if outcome == "adopted-exact":
        if successful_results:
            fail(f"{operation_id} adopted object contains a write result")
        return {
            "provisioningOutcome": "adopted-exact",
            "createCondition": None,
            "createHttpStatus": None,
        }
    fail(f"{operation_id} has no truthful create-or-adopt outcome")


def _validate_lease_event(
    value: Any,
    label: str,
    *,
    action: str,
    allowed_statuses: set[int],
    lease_id_sha256: str,
    started_at: dt.datetime,
    completed_at: dt.datetime,
) -> dt.datetime:
    event = _exact_keys(
        value,
        {
            "action",
            "httpStatus",
            "leaseIdSha256",
            "requestProjection",
            "responseProjection",
            "observedAt",
        },
        label,
    )
    if (
        event["action"] != action
        or event["httpStatus"] not in allowed_statuses
        or event["leaseIdSha256"] != lease_id_sha256
    ):
        fail(f"{label} is not the exact lease transition")
    _canonical_projection(event["requestProjection"], f"{label}.requestProjection")
    _canonical_projection(event["responseProjection"], f"{label}.responseProjection")
    _observation_in_window(
        event["observedAt"],
        f"{label}.observedAt",
        started_at=started_at,
        completed_at=completed_at,
    )
    return _timestamp(event["observedAt"], f"{label}.observedAt")






def _source_bound_lease_component(
    value: Any,
    label: str,
    *,
    component_lease: Mapping[str, Any],
    required_keys: set[str],
) -> Mapping[str, Any]:
    """Consume one core-owned lease proof without inventing observations."""

    proof = _exact_keys(
        _canonical_projection(value, label),
        required_keys,
        label,
    )
    component = _exact_keys(
        component_lease,
        required_keys | {"evidenceSha256"},
        f"{label} component",
    )
    if {key: component[key] for key in required_keys} != proof:
        fail(f"{label} does not exactly bind its receipt component")
    _hash(component["evidenceSha256"], f"{label} component evidence")
    return proof


def _validate_lease_source_proof(
    value: Any,
    label: str,
    *,
    component_lease: Mapping[str, Any],
    started_at: dt.datetime,
    completed_at: dt.datetime,
) -> Mapping[str, Any]:
    del started_at, completed_at
    return _source_bound_lease_component(
        value,
        label,
        component_lease=component_lease,
        required_keys={
            "observationStatus",
            "operationSourceProjection",
            "leaseIdSha256",
            "targetResourceId",
            "actor",
        },
    )


def _validate_activation_lease_source_proof(
    value: Any,
    *,
    component_lease: Mapping[str, Any],
    webjob_terminal: Mapping[str, Any],
    expected_marker_sha256: str,
    context: Mapping[str, Any],
    plan: Mapping[str, Any],
    started_at: dt.datetime,
    completed_at: dt.datetime,
) -> Mapping[str, Any]:
    del expected_marker_sha256, started_at, completed_at
    proof = _source_bound_lease_component(
        value,
        "activation lease source proof",
        component_lease=component_lease,
        required_keys={
            "observationStatus",
            "leaseIdSha256",
            "targetResourceId",
            "actor",
            "sourceControlSha256",
            "terminalOperationSourceProjectionSha256",
            "expectedActions",
            "expectedFinalLeaseState",
        },
    )
    actor = _exact_keys(
        proof["actor"],
        {"actorType", "actorObjectId", "actorResourceId"},
        "activation lease actor",
    )
    if (
        proof["observationStatus"]
        != "source-derived-from-terminal-success-not-directly-observed"
        or proof["targetResourceId"]
        != _resource(plan, "activationFenceBlob")["resourceId"]
        or actor["actorType"] != "bridge-managed-identity"
        or actor["actorResourceId"]
        != _resource(plan, "bridgeIdentity")["resourceId"]
        or proof["expectedActions"]
        != ["acquire", "read", "renew", "release", "head-available"]
        or proof["expectedFinalLeaseState"] != "Available"
        or webjob_terminal["status"] != "Success"
    ):
        fail("activation lease proof is not exact and source-derived")
    _guid(actor["actorObjectId"], "activation lease actor object")
    _hash(proof["leaseIdSha256"], "activation lease identifier")
    _hash(proof["sourceControlSha256"], "activation source control")
    _hash(
        proof["terminalOperationSourceProjectionSha256"],
        "activation terminal operation source projection",
    )
    if component_lease["evidenceSha256"] != sha256_hex(proof):
        fail("activation lease component evidence is not source-derived")
    return proof


def _is_accepted_container_data_plane_write(
    entry: Mapping[str, Any], accepted_container_name: str
) -> bool:
    """Classify only writes to blobs beneath the exact accepted container.

    ARM control-plane writes to the accepted container resource, including the
    authorized immutability-policy PUT, are deliberately outside this class.
    """

    if (
        entry.get("phase") != "intent"
        or entry.get("method") not in {"POST", "PUT", "PATCH", "DELETE"}
    ):
        return False
    parsed = urllib.parse.urlsplit(str(entry.get("targetUrl", "")).lower())
    accepted_path = f"/{accepted_container_name.lower()}"
    path = parsed.path.lower().rstrip("/")
    return parsed.hostname == "mdspdbak2608089c4e.blob.core.windows.net" and (
        path == accepted_path or path.startswith(accepted_path + "/")
    )


def _validate_production_boundary(
    value: Any,
    *,
    context: Mapping[str, Any],
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    operation_projections: Mapping[str, Mapping[str, Any]],
    operation_contexts: Mapping[str, Mapping[str, Any]],
    bootstrap_source: Any,
    started_at: dt.datetime,
    completed_at: dt.datetime,
) -> tuple[Mapping[str, Any], str, list[dict[str, Any]]]:
    boundary = _exact_keys(
        value,
        {
            "authorizedPreflightProjection",
            "postExecutionProjection",
            "projectionsEqual",
            "journaledProductionWriteCount",
            "acceptedContainerWriteJournal",
            "mutationJournal",
            "acceptedReleaseObservationGate",
            "observedAt",
        },
        "sourceEvidence.productionBoundary",
    )
    before = _exact_keys(
        _canonical_projection(
            boundary["authorizedPreflightProjection"],
            "production authorized-preflight projection",
        ),
        {
            "sitePosture",
            "appSettingsSha256",
            "deploymentInventory",
            "oneDeployInventory",
        },
        "production authorized-preflight projection",
    )
    after = _canonical_projection(
        boundary["postExecutionProjection"], "production post-execution projection"
    )
    _hash(before["appSettingsSha256"], "production app-settings digest")
    accepted_writes = _list(
        boundary["acceptedContainerWriteJournal"],
        "production accepted-container write journal",
    )
    journal = _list(
        _canonical_projection(
            boundary["mutationJournal"], "production sanitized mutation journal"
        ),
        "production sanitized mutation journal",
    )
    journal_validator = getattr(
        bootstrap_source, "_validate_sanitized_mutation_journal", None
    )
    classifier = getattr(bootstrap_source, "_forbidden_release_mutation_classes", None)
    if not callable(journal_validator) or not callable(classifier):
        fail("source-owned journal or production-boundary validator is unavailable")
    try:
        normalized_journal = journal_validator(
            journal,
            plan=plan,
            authorization=authorization,
            operation_projections=operation_projections,
            operation_contexts=operation_contexts,
            execution_started_at=started_at,
            execution_completed_at=completed_at,
        )
    except Exception as exc:
        if isinstance(exc, BootstrapReceiptError):
            raise
        raise BootstrapReceiptError(
            f"source-owned exact mutation journal is invalid: {exc}"
        ) from exc
    production_writes = [
        entry
        for entry in normalized_journal
        if entry["phase"] == "intent"
        and classifier(entry["method"], entry["targetUrl"], plan)[0]
    ]
    derived_accepted_writes = [
        entry
        for entry in normalized_journal
        if entry["phase"] == "intent"
        and classifier(entry["method"], entry["targetUrl"], plan)[1]
    ]
    deferred = _exact_keys(
        boundary["acceptedReleaseObservationGate"],
        {
            "status",
            "requiredAfter",
            "requiredBefore",
            "acceptedContainerResourceId",
        },
        "production accepted-release observation gate",
    )
    if deferred != {
        "status": "deferred-required-post-s2",
        "requiredAfter": "separately-authorized-publisher-fic-repin",
        "requiredBefore": "accepted-release-publication-or-production-deploy",
        "acceptedContainerResourceId": _resource(plan, "acceptedContainer")[
            "resourceId"
        ],
    }:
        fail("accepted-release data-plane observation is not explicitly deferred")
    if (
        after != before
        or boundary["projectionsEqual"] is not True
        or boundary["journaledProductionWriteCount"] != len(production_writes)
        or production_writes != []
        or accepted_writes != derived_accepted_writes
        or derived_accepted_writes != []
    ):
        fail("full production boundary changed during bootstrap")
    _observation_in_window(
        boundary["observedAt"],
        "production boundary observedAt",
        started_at=started_at,
        completed_at=completed_at,
    )
    return boundary, sha256_hex(boundary), normalized_journal


def _receipt_header(
    document: Mapping[str, Any],
    component: str,
    context: Mapping[str, Any],
    *,
    status: str,
) -> None:
    types = context["model"]["receiptTypes"]
    if document.get("schemaVersion") != 1:
        fail(f"{component} schemaVersion is invalid")
    if document.get("receiptType") != types[component]:
        fail(f"{component} receiptType is invalid")
    if document.get("status") != status:
        fail(f"{component} status is invalid")
    if document.get("authorizationId") != context["authorizationId"]:
        fail(f"{component} authorization binding is invalid")
    if document.get("mergedSourceSha") != context["mergedMainSha"]:
        fail(f"{component} merged-source binding is invalid")
    if document.get("planSha256") != context["planSha256"]:
        fail(f"{component} plan binding is invalid")


def _observation_in_window(
    value: Any,
    label: str,
    *,
    started_at: dt.datetime,
    completed_at: dt.datetime,
) -> None:
    observed = _timestamp(value, label)
    if observed < started_at or observed > completed_at:
        fail(f"{label} is outside the execution window")


def _validate_permanent_ledger(
    document: Mapping[str, Any],
    context: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    started_at: dt.datetime,
    completed_at: dt.datetime,
    derived_evidence: Mapping[str, str] | None = None,
    derived_entries: Mapping[str, Mapping[str, Any]] | None = None,
) -> None:
    _exact_keys(
        document,
        {
            "schemaVersion",
            "receiptType",
            "status",
            "authorizationId",
            "mergedSourceSha",
            "planSha256",
            "entries",
            "failures",
            "pendingHousekeeping",
            "observedAt",
        },
        "permanentMutationLedger",
    )
    _receipt_header(document, "permanentMutationLedger", context, status="complete")
    if document["failures"] != [] or document["pendingHousekeeping"] != []:
        fail("permanent mutation ledger is not terminal-clean")
    expected = _expected_permanent_mutations(plan)
    entries = _list(document["entries"], "permanentMutationLedger.entries")
    if len(entries) != len(expected):
        fail("permanent mutation ledger is incomplete")
    by_id: dict[str, Mapping[str, Any]] = {}
    for index, entry in enumerate(entries):
        _exact_keys(
            entry,
            {
                "mutationId",
                "target",
                "kind",
                "irreversible",
                "outcome",
                "evidenceSha256",
                "observedAt",
            },
            f"permanentMutationLedger.entries[{index}]",
        )
        mutation_id = _string(entry["mutationId"], f"permanent ledger mutation {index}")
        if mutation_id in by_id:
            fail("permanent mutation ledger contains a duplicate mutation ID")
        if entry["outcome"] not in {
            "created",
            "adopted-exact",
            "updated-exact",
            "deleted-exact",
            "read-back-exact",
        }:
            fail(f"permanent mutation {mutation_id} has an invalid outcome")
        evidence_sha = _hash(
            entry["evidenceSha256"], f"permanent mutation {mutation_id} evidence"
        )
        if derived_evidence is not None and evidence_sha != derived_evidence.get(
            mutation_id
        ):
            fail(f"permanent mutation {mutation_id} evidence is not source-derived")
        if derived_entries is not None and entry != derived_entries.get(mutation_id):
            fail(f"permanent mutation {mutation_id} fields are not source-derived")
        _observation_in_window(
            entry["observedAt"],
            f"permanent mutation {mutation_id} observedAt",
            started_at=started_at,
            completed_at=completed_at,
        )
        by_id[mutation_id] = entry
    if list(by_id) != [item["id"] for item in expected]:
        fail("permanent mutation ledger order or universe is invalid")
    for mutation in expected:
        entry = by_id[mutation["id"]]
        if (
            entry["target"] != mutation["target"]
            or entry["kind"] != mutation["kind"]
            or entry["irreversible"] is not mutation["irreversible"]
        ):
            fail(f"permanent mutation {mutation['id']} does not match the plan")
    _observation_in_window(
        document["observedAt"],
        "permanentMutationLedger.observedAt",
        started_at=started_at,
        completed_at=completed_at,
    )


def _validate_temporary_role(
    value: Any,
    label: str,
    *,
    definition_id: str,
    assignment_id: str,
    scope_id: str,
    principal_id: str,
    add_mutation_id: str,
    remove_mutation_id: str,
    custom_definition: bool,
    started_at: dt.datetime,
    completed_at: dt.datetime,
    derived_absence_sha256: str | None = None,
) -> None:
    keys = {
        "roleDefinitionId",
        "roleAssignmentId",
        "scopeResourceId",
        "principalObjectId",
        "addMutationId",
        "removeMutationId",
        "createdByAuthorization",
        "removed",
        "presentAfterCleanup",
        "freshReadbackSha256",
        "observedAt",
    }
    if custom_definition:
        keys |= {
            "roleDefinitionCreatedByAuthorization",
            "roleDefinitionRemoved",
            "roleDefinitionPresentAfterCleanup",
        }
    role = _exact_keys(value, keys, label)
    if (
        role["roleDefinitionId"] != definition_id
        or role["roleAssignmentId"] != assignment_id
        or role["scopeResourceId"] != scope_id
        or role["principalObjectId"] != principal_id
        or role["addMutationId"] != add_mutation_id
        or role["removeMutationId"] != remove_mutation_id
    ):
        fail(f"{label} exact identity binding is invalid")
    if (
        role["createdByAuthorization"] is not True
        or role["removed"] is not True
        or role["presentAfterCleanup"] is not False
    ):
        fail(f"{label} is not proven absent")
    if custom_definition and (
        role["roleDefinitionCreatedByAuthorization"] is not True
        or role["roleDefinitionRemoved"] is not True
        or role["roleDefinitionPresentAfterCleanup"] is not False
    ):
        fail(f"{label} custom role definition is not proven absent")
    fresh_sha = _hash(
        role["freshReadbackSha256"], f"{label}.freshReadbackSha256"
    )
    if derived_absence_sha256 is not None and fresh_sha != derived_absence_sha256:
        fail(f"{label} absence proof is not source-derived")
    _observation_in_window(
        role["observedAt"],
        f"{label}.observedAt",
        started_at=started_at,
        completed_at=completed_at,
    )


def _validate_temporary_cleanup(
    document: Mapping[str, Any],
    context: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    started_at: dt.datetime,
    completed_at: dt.datetime,
    derived_absences: Mapping[str, str] | None = None,
) -> None:
    _exact_keys(
        document,
        {
            "schemaVersion",
            "receiptType",
            "status",
            "authorizationId",
            "mergedSourceSha",
            "planSha256",
            "publicIpv4CidrSha256",
            "packageIpv4Rule",
            "packageUploaderRole",
            "operatorKeyReadRole",
            "operatorFenceRole",
            "operatorControllerRole",
            "failures",
            "pendingHousekeeping",
            "observedAt",
        },
        "temporaryAccessCleanup",
    )
    _receipt_header(
        document,
        "temporaryAccessCleanup",
        context,
        status="complete-temporary-access-absent",
    )
    if document["failures"] != [] or document["pendingHousekeeping"] != []:
        fail("temporary access cleanup is not terminal-clean")
    cidr_sha = _hash(document["publicIpv4CidrSha256"], "temporary cleanup IPv4 CIDR digest")
    ip_rule = _exact_keys(
        document["packageIpv4Rule"],
        {
            "addMutationId",
            "removeMutationId",
            "cidrSha256",
            "armIpRuleSha256",
            "createdByAuthorization",
            "removed",
            "presentAfterCleanup",
            "freshReadbackSha256",
            "observedAt",
        },
        "temporaryAccessCleanup.packageIpv4Rule",
    )
    if (
        ip_rule["addMutationId"] != "addOwnedUploaderIpv4Rule"
        or ip_rule["removeMutationId"] != "removeOwnedUploaderIpv4Rule"
        or ip_rule["cidrSha256"] != cidr_sha
        or ip_rule["createdByAuthorization"] is not True
        or ip_rule["removed"] is not True
        or ip_rule["presentAfterCleanup"] is not False
    ):
        fail("temporary package IPv4 rule is not proven absent")
    _hash(ip_rule["armIpRuleSha256"], "temporary ARM IP-rule digest")
    ip_absence_sha = _hash(
        ip_rule["freshReadbackSha256"], "temporary IP-rule absence digest"
    )
    if derived_absences is not None and ip_absence_sha != derived_absences.get(
        "packageIpv4Rule"
    ):
        fail("temporary IP-rule absence proof is not source-derived")
    _observation_in_window(
        ip_rule["observedAt"],
        "temporary package IPv4 rule observedAt",
        started_at=started_at,
        completed_at=completed_at,
    )
    constants = context["model"]["constants"]
    temporary = plan.get("temporaryAccess")
    if not isinstance(temporary, Mapping):
        fail("plan temporaryAccess is invalid")
    if cidr_sha == sha256_hex(b""):
        fail("temporary IPv4 CIDR digest cannot bind an empty input")
    _validate_temporary_role(
        document["packageUploaderRole"],
        "temporaryAccessCleanup.packageUploaderRole",
        definition_id=temporary["roleDefinitionId"],
        assignment_id=temporary["roleAssignmentId"],
        scope_id=_resource(plan, temporary["scope"])["resourceId"],
        principal_id=context["operatorObjectId"],
        add_mutation_id="addOwnedUploaderPackageRole",
        remove_mutation_id="removeOwnedUploaderPackageRole",
        custom_definition=True,
        started_at=started_at,
        completed_at=completed_at,
        derived_absence_sha256=(
            None
            if derived_absences is None
            else derived_absences.get("packageUploaderRole")
        ),
    )
    _validate_temporary_role(
        document["operatorKeyReadRole"],
        "temporaryAccessCleanup.operatorKeyReadRole",
        definition_id=constants["temporaryKeyReadRoleDefinitionId"],
        assignment_id=constants["temporaryKeyReadRoleAssignmentId"],
        scope_id=_resource(plan, temporary["temporaryKeyReadScope"])["resourceId"],
        principal_id=context["operatorObjectId"],
        add_mutation_id="addOwnedOperatorKeyReadRole",
        remove_mutation_id="removeOwnedOperatorKeyReadRole",
        custom_definition=True,
        started_at=started_at,
        completed_at=completed_at,
        derived_absence_sha256=(
            None
            if derived_absences is None
            else derived_absences.get("operatorKeyReadRole")
        ),
    )
    _validate_temporary_role(
        document["operatorFenceRole"],
        "temporaryAccessCleanup.operatorFenceRole",
        definition_id=constants["temporaryFenceRoleDefinitionId"],
        assignment_id=constants["temporaryFenceRoleAssignmentId"],
        scope_id=_resource(plan, temporary["temporaryFenceScope"])["resourceId"],
        principal_id=context["operatorObjectId"],
        add_mutation_id="addOwnedOperatorFenceBootstrapRole",
        remove_mutation_id="removeOwnedOperatorFenceBootstrapRole",
        custom_definition=True,
        started_at=started_at,
        completed_at=completed_at,
        derived_absence_sha256=(
            None
            if derived_absences is None
            else derived_absences.get("operatorFenceRole")
        ),
    )
    _validate_temporary_role(
        document["operatorControllerRole"],
        "temporaryAccessCleanup.operatorControllerRole",
        definition_id=temporary["temporaryControllerRoleDefinitionId"],
        assignment_id=temporary["temporaryControllerRoleAssignmentId"],
        scope_id=_resource(plan, temporary["temporaryControllerScope"])["resourceId"],
        principal_id=context["operatorObjectId"],
        add_mutation_id="addOwnedOperatorControllerCanaryRole",
        remove_mutation_id="removeOwnedOperatorControllerCanaryRole",
        custom_definition=True,
        started_at=started_at,
        completed_at=completed_at,
        derived_absence_sha256=(
            None
            if derived_absences is None
            else derived_absences.get("operatorControllerRole")
        ),
    )
    _observation_in_window(
        document["observedAt"],
        "temporaryAccessCleanup.observedAt",
        started_at=started_at,
        completed_at=completed_at,
    )


def _validate_activation_fence(
    document: Mapping[str, Any],
    context: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    started_at: dt.datetime,
    completed_at: dt.datetime,
    derived_fields: Mapping[str, Any] | None = None,
) -> None:
    _exact_keys(
        document,
        {
            "schemaVersion",
            "receiptType",
            "status",
            "authorizationId",
            "mergedSourceSha",
            "planSha256",
            "containerResourceId",
            "blobResourceId",
            "blobName",
            "canonicalInitialDocument",
            "initialBodySha256",
            "size",
            "provisioningOutcome",
            "createCondition",
            "createHttpStatus",
            "etag",
            "versionId",
            "metadataSha256",
            "readbackSha256",
            "readbackHttpStatus",
            "leaseState",
            "leaseStatus",
            "temporaryAccessCleanupSha256",
            "observedAt",
        },
        "activationFenceBootstrap",
    )
    _receipt_header(
        document,
        "activationFenceBootstrap",
        context,
        status="initial-idle-fence-exact-created-or-adopted",
    )
    initial = context["model"]["initialActivationFenceDocument"]
    if document["canonicalInitialDocument"] != initial:
        fail("activation fence initial document is not exact")
    initial_bytes = canonical_json_bytes(initial)
    initial_sha = hashlib.sha256(initial_bytes).hexdigest()
    if (
        document["containerResourceId"] != _resource(plan, "activationFenceContainer")["resourceId"]
        or document["blobResourceId"] != _resource(plan, "activationFenceBlob")["resourceId"]
        or document["blobName"] != context["model"]["constants"]["activationFenceBlob"]
        or document["initialBodySha256"] != initial_sha
        or document["size"] != len(initial_bytes)
        or document["metadataSha256"] != initial_sha
        or document["readbackSha256"] != initial_sha
        or document["readbackHttpStatus"] != 200
        or document["leaseState"] != "Available"
        or document["leaseStatus"] != "Unlocked"
    ):
        fail("activation fence bootstrap evidence is invalid")
    if document["provisioningOutcome"] == "created-by-authorization":
        if (
            document["createCondition"] != "If-None-Match:*"
            or document["createHttpStatus"] != 201
        ):
            fail("activation fence create evidence is not journal-bound")
    elif document["provisioningOutcome"] == "adopted-exact":
        if document["createCondition"] is not None or document["createHttpStatus"] is not None:
            fail("adopted activation fence falsely claims a create")
    else:
        fail("activation fence provisioning outcome is invalid")
    if derived_fields is not None and any(
        document.get(key) != expected for key, expected in derived_fields.items()
    ):
        fail("activation fence fields are not source-derived")
    _etag(document["etag"], "activation fence ETag")
    _string(document["versionId"], "activation fence version ID")
    _hash(document["temporaryAccessCleanupSha256"], "activation fence cleanup digest")
    _observation_in_window(
        document["observedAt"],
        "activationFenceBootstrap.observedAt",
        started_at=started_at,
        completed_at=completed_at,
    )


def _validate_package_readback(
    document: Mapping[str, Any],
    context: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    started_at: dt.datetime,
    completed_at: dt.datetime,
    derived_fields: Mapping[str, Any] | None = None,
) -> None:
    _exact_keys(
        document,
        {
            "schemaVersion",
            "receiptType",
            "status",
            "authorizationId",
            "mergedSourceSha",
            "planSha256",
            "containerResourceId",
            "blobName",
            "packageSha256",
            "size",
            "provisioningOutcome",
            "createCondition",
            "createHttpStatus",
            "etag",
            "versionId",
            "versionedUrl",
            "metadataSha256",
            "readbackSha256",
            "readbackSize",
            "readbackHttpStatus",
            "observedAt",
        },
        "packageReadback",
    )
    _receipt_header(document, "packageReadback", context, status="exact-version-read-back")
    expected_blob = context["model"]["constants"]["packageBlobTemplate"].format(
        mergedSourceSha=context["packageSourceSha"]
    )
    if (
        document["containerResourceId"] != _resource(plan, "packageContainer")["resourceId"]
        or document["blobName"] != expected_blob
        or document["packageSha256"] != context["packageSha256"]
        or document["size"] != context["packageSize"]
        or document["readbackSha256"] != context["packageSha256"]
        or document["readbackSize"] != context["packageSize"]
        or document["metadataSha256"] != context["packageSha256"]
        or document["readbackHttpStatus"] != 200
    ):
        fail("package readback is not deterministic or exact")
    if document["provisioningOutcome"] == "created-by-authorization":
        if (
            document["createCondition"] != "If-None-Match:*"
            or document["createHttpStatus"] != 201
        ):
            fail("package create evidence is not journal-bound")
    elif document["provisioningOutcome"] == "adopted-exact":
        if document["createCondition"] is not None or document["createHttpStatus"] is not None:
            fail("adopted package falsely claims a create")
    else:
        fail("package provisioning outcome is invalid")
    if derived_fields is not None and any(
        document.get(key) != expected for key, expected in derived_fields.items()
    ):
        fail("package readback fields are not source-derived")
    _etag(document["etag"], "package ETag")
    version_id = _string(document["versionId"], "package version ID")
    url = _string(document["versionedUrl"], "package versioned URL")
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    expected_path = f"/paperdesk-deployment-packages/{expected_blob}"
    if (
        parsed.scheme != "https"
        or parsed.netloc != "mdspdbak2608089c4e.blob.core.windows.net"
        or urllib.parse.unquote(parsed.path) != expected_path
        or parsed.fragment
        or set(query) != {"versionid"}
        or query["versionid"] != [version_id]
    ):
        fail("package versioned URL is invalid or capability-bearing")
    _observation_in_window(
        document["observedAt"],
        "packageReadback.observedAt",
        started_at=started_at,
        completed_at=completed_at,
    )


def _validate_managed_identity_fetch(
    document: Mapping[str, Any],
    context: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    started_at: dt.datetime,
    completed_at: dt.datetime,
    derived_response_sha256: str | None = None,
) -> None:
    _exact_keys(
        document,
        {
            "schemaVersion",
            "receiptType",
            "status",
            "authorizationId",
            "mergedSourceSha",
            "planSha256",
            "evidenceMode",
            "directPackageBytesObservedByExecutor",
            "identityResourceId",
            "identityClientId",
            "identityPrincipalId",
            "authentication",
            "packageBlobName",
            "packageVersionId",
            "expectedPackageSha256",
            "expectedPackageSize",
            "sourceControlSha256",
            "webJobInvocationId",
            "terminalStatus",
            "responseProjectionSha256",
            "packageReadbackSha256",
            "observedAt",
        },
        "managedIdentityFetchSelfTest",
    )
    _receipt_header(
        document,
        "managedIdentityFetchSelfTest",
        context,
        status="source-derived-terminal-success",
    )
    reader = _resource(plan, "registryReaderIdentity")
    expected_blob = context["model"]["constants"]["packageBlobTemplate"].format(
        mergedSourceSha=context["packageSourceSha"]
    )
    if (
        document["evidenceMode"]
        != "source-derived-from-terminal-success-not-directly-observed"
        or document["directPackageBytesObservedByExecutor"] is not False
        or document["identityResourceId"] != reader["resourceId"]
        or document["identityClientId"] != reader.get("clientId")
        or document["identityPrincipalId"] != reader.get("principalId")
        or document["authentication"]
        != "platform-run-from-package-managed-identity"
        or document["packageBlobName"] != expected_blob
        or document["expectedPackageSha256"] != context["packageSha256"]
        or document["expectedPackageSize"] != context["packageSize"]
        or document["terminalStatus"] != "Success"
    ):
        fail("managed-identity run-from-package proof is not exact and truthful")
    _string(document["packageVersionId"], "managed-identity package version")
    _hash(document["sourceControlSha256"], "managed-identity source control")
    _string(document["webJobInvocationId"], "managed-identity WebJob invocation")
    response_sha = _hash(
        document["responseProjectionSha256"],
        "managed-identity response projection",
    )
    if derived_response_sha256 is not None and response_sha != derived_response_sha256:
        fail("managed-identity response projection is not source-derived")
    _hash(document["packageReadbackSha256"], "managed-identity package-readback binding")
    _observation_in_window(
        document["observedAt"],
        "managedIdentityFetchSelfTest.observedAt",
        started_at=started_at,
        completed_at=completed_at,
    )


def _validate_bridge_evidence(
    document: Mapping[str, Any],
    context: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    started_at: dt.datetime,
    completed_at: dt.datetime,
    derived_evidence: Mapping[str, str] | None = None,
    derived_fields: Mapping[str, Any] | None = None,
) -> None:
    _exact_keys(
        document,
        {
            "schemaVersion",
            "receiptType",
            "status",
            "authorizationId",
            "mergedSourceSha",
            "planSha256",
            "bridgeResourceId",
            "finalState",
            "settings",
            "webJobTerminalProjectionSha256",
            "sourceDerivedExpectedMarkerSha256",
            "packageReadbackSha256",
            "managedIdentityFetchSelfTestSha256",
            "leaseCanaryEvidenceSha256",
            "productionBoundarySha256",
            "observedAt",
        },
        "bridgeEvidence",
    )
    _receipt_header(
        document,
        "bridgeEvidence",
        context,
        status="terminal-success-with-source-derived-boundaries-complete",
    )
    if document["bridgeResourceId"] != _resource(plan, "bridgeSite")["resourceId"] or document["finalState"] != "Stopped":
        fail("bridge evidence does not prove the exact bridge is Stopped")
    settings = _exact_keys(
        document["settings"],
        {"beforeSha256", "desiredSha256", "afterSha256", "fullMapReadbackExact"},
        "bridgeEvidence.settings",
    )
    for field in ("beforeSha256", "desiredSha256", "afterSha256"):
        _hash(settings[field], f"bridge settings {field}")
    if settings["fullMapReadbackExact"] is not True or settings["afterSha256"] != settings["desiredSha256"]:
        fail("bridge settings full-map readback is invalid")
    for field in (
        "webJobTerminalProjectionSha256",
        "sourceDerivedExpectedMarkerSha256",
        "packageReadbackSha256",
        "managedIdentityFetchSelfTestSha256",
        "leaseCanaryEvidenceSha256",
        "productionBoundarySha256",
    ):
        _hash(document[field], f"bridgeEvidence.{field}")
    if derived_evidence is not None:
        expected = {
            "webJobTerminalProjectionSha256": derived_evidence.get(
                "webJobTerminalProjectionSha256"
            ),
            "sourceDerivedExpectedMarkerSha256": derived_evidence.get(
                "sourceDerivedExpectedMarkerSha256"
            ),
            "productionBoundarySha256": derived_evidence.get(
                "productionBoundarySha256"
            ),
        }
        if any(document[key] != value for key, value in expected.items()):
            fail("bridge evidence is not derived from exact terminal source proof")
    if derived_fields is not None and any(
        document.get(key) != expected for key, expected in derived_fields.items()
    ):
        fail("bridge state, settings, or observation is not source-derived")
    _observation_in_window(
        document["observedAt"],
        "bridgeEvidence.observedAt",
        started_at=started_at,
        completed_at=completed_at,
    )


def _validate_finite_lease(
    value: Any,
    label: str,
    constants: Mapping[str, Any],
    *,
    target_resource_id: str,
    actor_type: str,
    actor_object_id: str | None,
    actor_resource_id: str,
    derived_evidence_sha256: str | None = None,
) -> None:
    lease = _exact_keys(
        value,
        {
            "status",
            "targetResourceId",
            "actorType",
            "actorObjectId",
            "actorResourceId",
            "leaseDurationSeconds",
            "renewalCount",
            "acquireHttpStatus",
            "renewHttpStatus",
            "releaseHttpStatus",
            "leaseIdSha256",
            "finalLeaseState",
            "finalLeaseStatus",
            "evidenceSha256",
        },
        label,
    )
    if (
        lease["status"] != "succeeded"
        or lease["targetResourceId"] != target_resource_id
        or lease["actorType"] != actor_type
        or lease["actorResourceId"] != actor_resource_id
        or lease["leaseDurationSeconds"] != constants["finiteLeaseSeconds"]
        or lease["renewalCount"] != constants["finiteLeaseRenewalCount"]
        or lease["acquireHttpStatus"] not in {201, 202}
        or lease["renewHttpStatus"] != 200
        or lease["releaseHttpStatus"] not in {200, 202}
        or lease["finalLeaseState"] != "Available"
        or lease["finalLeaseStatus"] != "Unlocked"
    ):
        fail(f"{label} does not prove a released finite lease")
    observed_actor = _guid(lease["actorObjectId"], f"{label}.actorObjectId")
    if actor_object_id is not None and observed_actor != actor_object_id:
        fail(f"{label} actor identity is invalid")
    _hash(lease["leaseIdSha256"], f"{label}.leaseIdSha256")
    evidence_sha = _hash(lease["evidenceSha256"], f"{label}.evidenceSha256")
    if derived_evidence_sha256 is not None and evidence_sha != derived_evidence_sha256:
        fail(f"{label} evidence is not source-derived")


def _validate_activation_fence_lease(
    value: Any,
    context: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    derived_evidence_sha256: str | None = None,
) -> None:
    label = "activation finite lease"
    lease = _exact_keys(
        value,
        {
            "status",
            "evidenceMode",
            "targetResourceId",
            "actorType",
            "actorObjectId",
            "actorResourceId",
            "leaseDurationSeconds",
            "renewalCount",
            "directHttpEventsObserved",
            "leaseIdSha256",
            "finalReadbackHttpStatus",
            "finalLeaseState",
            "finalLeaseStatus",
            "evidenceSha256",
        },
        label,
    )
    constants = context["model"]["constants"]
    if (
        lease["status"] != "terminal-success-final-readback-complete"
        or lease["evidenceMode"]
        != "source-derived-from-terminal-success-not-directly-observed"
        or lease["targetResourceId"]
        != _resource(plan, "activationFenceBlob")["resourceId"]
        or lease["actorType"] != "bridge-managed-identity"
        or lease["actorResourceId"]
        != _resource(plan, "bridgeIdentity")["resourceId"]
        or lease["leaseDurationSeconds"] != constants["finiteLeaseSeconds"]
        or lease["renewalCount"] != constants["finiteLeaseRenewalCount"]
        or lease["directHttpEventsObserved"] is not False
        or lease["finalReadbackHttpStatus"] != 200
        or lease["finalLeaseState"] != "Available"
        or lease["finalLeaseStatus"] != "Unlocked"
    ):
        fail(f"{label} is not a truthful source-derived/final-readback proof")
    _guid(lease["actorObjectId"], f"{label}.actorObjectId")
    _hash(lease["leaseIdSha256"], f"{label}.leaseIdSha256")
    evidence_sha = _hash(lease["evidenceSha256"], f"{label}.evidenceSha256")
    if derived_evidence_sha256 is not None and evidence_sha != derived_evidence_sha256:
        fail(f"{label} evidence is not source-derived")


def _validate_lease_canaries(
    document: Mapping[str, Any],
    context: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    started_at: dt.datetime,
    completed_at: dt.datetime,
    derived_evidence: Mapping[str, str] | None = None,
) -> None:
    _exact_keys(
        document,
        {
            "schemaVersion",
            "receiptType",
            "status",
            "authorizationId",
            "mergedSourceSha",
            "planSha256",
            "controllerLease",
            "activationFenceLease",
            "cleanupFastLane",
            "cleanupExpiryFallback",
            "temporaryAccessCleanupSha256",
            "activationFenceBootstrapSha256",
            "publisherControllerRuntimeLeaseGate",
            "failures",
            "pendingHousekeeping",
            "observedAt",
        },
        "leaseCanaryEvidence",
    )
    _receipt_header(
        document,
        "leaseCanaryEvidence",
        context,
        status="direct-controller-and-source-derived-activation-proof-complete",
    )
    if document["failures"] != [] or document["pendingHousekeeping"] != []:
        fail("lease and cleanup canaries are not terminal-clean")
    controller = _exact_keys(
        document["controllerLease"],
        {
            "observationStatus",
            "operationSourceProjection",
            "leaseIdSha256",
            "targetResourceId",
            "actor",
            "evidenceSha256",
        },
        "leaseCanaryEvidence.controllerLease",
    )
    controller_actor = _exact_keys(
        controller["actor"],
        {"actorType", "actorObjectId", "actorResourceId"},
        "controller lease actor",
    )
    controller_projection = _canonical_projection(
        controller["operationSourceProjection"],
        "controller lease operation source projection",
    )
    if (
        controller["observationStatus"] != "directly-observed"
        or controller_actor
        != {
            "actorType": "authorized-local-operator",
            "actorObjectId": context["operatorObjectId"],
            "actorResourceId": "",
        }
        or controller["targetResourceId"]
        != controller_projection.get("projection", {}).get("url")
    ):
        fail("controller lease proof is not exact and operator-bound")
    _hash(controller["leaseIdSha256"], "controller lease identifier")
    controller_evidence_sha = _hash(
        controller["evidenceSha256"], "controller lease evidence"
    )
    if derived_evidence is not None and controller_evidence_sha != derived_evidence.get(
        "controllerLease"
    ):
        fail("controller lease evidence is not source-derived")

    activation = _exact_keys(
        document["activationFenceLease"],
        {
            "observationStatus",
            "leaseIdSha256",
            "targetResourceId",
            "actor",
            "sourceControlSha256",
            "terminalOperationSourceProjectionSha256",
            "expectedActions",
            "expectedFinalLeaseState",
            "evidenceSha256",
        },
        "leaseCanaryEvidence.activationFenceLease",
    )
    activation_actor = _exact_keys(
        activation["actor"],
        {"actorType", "actorObjectId", "actorResourceId"},
        "activation lease actor",
    )
    if (
        activation["observationStatus"]
        != "source-derived-from-terminal-success-not-directly-observed"
        or activation["targetResourceId"]
        != _resource(plan, "activationFenceBlob")["resourceId"]
        or activation_actor["actorType"] != "bridge-managed-identity"
        or activation_actor["actorResourceId"]
        != _resource(plan, "bridgeIdentity")["resourceId"]
        or activation["expectedActions"]
        != ["acquire", "read", "renew", "release", "head-available"]
        or activation["expectedFinalLeaseState"] != "Available"
    ):
        fail("activation lease proof is not exact and source-derived")
    _guid(activation_actor["actorObjectId"], "activation lease actor object")
    for field in (
        "leaseIdSha256",
        "sourceControlSha256",
        "terminalOperationSourceProjectionSha256",
    ):
        _hash(activation[field], f"activation lease {field}")
    activation_evidence_sha = _hash(
        activation["evidenceSha256"], "activation lease evidence"
    )
    if derived_evidence is not None and activation_evidence_sha != derived_evidence.get(
        "activationFenceLease"
    ):
        fail("activation lease evidence is not source-derived")
    if controller["leaseIdSha256"] == activation["leaseIdSha256"]:
        fail("controller and activation finite leases are not distinct")
    fast = _exact_keys(
        document["cleanupFastLane"],
        {
            "observationStatus",
            "controllerOperationSourceProjectionSha256",
            "stateTransitions",
            "observedAt",
            "evidenceSha256",
        },
        "leaseCanaryEvidence.cleanupFastLane",
    )
    if (
        fast["observationStatus"] != "directly-observed"
        or not isinstance(fast["stateTransitions"], Mapping)
        or not fast["stateTransitions"]
    ):
        fail("cleanup fast-lane canary is invalid")
    _hash(
        fast["controllerOperationSourceProjectionSha256"],
        "cleanup fast-lane controller source projection",
    )
    _observation_in_window(
        fast["observedAt"],
        "cleanup fast-lane observedAt",
        started_at=started_at,
        completed_at=completed_at,
    )
    fast_sha = _hash(fast["evidenceSha256"], "cleanup fast-lane evidence")
    if derived_evidence is not None and fast_sha != derived_evidence.get(
        "cleanupFastLane"
    ):
        fail("cleanup fast-lane evidence is not source-derived")
    fallback = _exact_keys(
        document["cleanupExpiryFallback"],
        {
            "observationStatus",
            "controllerOperationSourceProjectionSha256",
            "deadlineSeconds",
            "stateTransitions",
            "observedAt",
            "evidenceSha256",
        },
        "leaseCanaryEvidence.cleanupExpiryFallback",
    )
    if (
        fallback["observationStatus"] != "directly-observed"
        or fallback["deadlineSeconds"]
        != context["model"]["constants"]["finiteLeaseSeconds"]
        or not isinstance(fallback["stateTransitions"], Mapping)
        or not fallback["stateTransitions"]
    ):
        fail("cleanup expiry-fallback canary is invalid")
    _hash(
        fallback["controllerOperationSourceProjectionSha256"],
        "cleanup expiry-fallback controller source projection",
    )
    _observation_in_window(
        fallback["observedAt"],
        "cleanup expiry-fallback observedAt",
        started_at=started_at,
        completed_at=completed_at,
    )
    fallback_sha = _hash(
        fallback["evidenceSha256"], "cleanup expiry-fallback evidence"
    )
    if derived_evidence is not None and fallback_sha != derived_evidence.get(
        "cleanupExpiryFallback"
    ):
        fail("cleanup expiry-fallback evidence is not source-derived")
    _hash(document["temporaryAccessCleanupSha256"], "lease canary cleanup binding")
    _hash(document["activationFenceBootstrapSha256"], "lease canary fence binding")
    future_gate = _exact_keys(
        document["publisherControllerRuntimeLeaseGate"],
        {
            "status",
            "requiredAfter",
            "requiredBefore",
            "targetResourceId",
            "publisherIdentityResourceId",
        },
        "leaseCanaryEvidence.publisherControllerRuntimeLeaseGate",
    )
    if future_gate != {
        "status": "deferred-required-post-s2",
        "requiredAfter": "separately-authorized-publisher-fic-repin",
        "requiredBefore": "caller-integration-and-production-deploy",
        "targetResourceId": _resource(plan, "controllerLockContainer")["resourceId"],
        "publisherIdentityResourceId": _resource(plan, "publisherServicePrincipal")[
            "resourceId"
        ],
    }:
        fail("publisher controller runtime lease gate is not explicitly deferred")
    _observation_in_window(
        document["observedAt"],
        "leaseCanaryEvidence.observedAt",
        started_at=started_at,
        completed_at=completed_at,
    )


def _validate_worm_item(
    value: Any,
    label: str,
    *,
    container_resource_id: str,
    constants: Mapping[str, Any],
    started_at: dt.datetime,
    completed_at: dt.datetime,
    derived_evidence: Mapping[str, Any] | None = None,
) -> None:
    item = _exact_keys(
        value,
        {
            "containerResourceId",
            "policyResourceId",
            "publicAccess",
            "state",
            "retentionDays",
            "allowProtectedAppendWrites",
            "allowProtectedAppendWritesAll",
            "etag",
            "containerProjectionSha256",
            "policyProjectionSha256",
            "observedAt",
        },
        label,
    )
    expected_policy = container_resource_id + "/immutabilityPolicies/default"
    if (
        item["containerResourceId"] != container_resource_id
        or item["policyResourceId"] != expected_policy
        or item["publicAccess"] != "None"
        or item["state"] != "Locked"
        or type(item["retentionDays"]) is not int
        or item["retentionDays"] < constants["wormRetentionDays"]
        or item["allowProtectedAppendWrites"] is not False
        or item["allowProtectedAppendWritesAll"] is not False
    ):
        fail(f"{label} is not a private Locked WORM projection retained at least 91 days")
    _etag(item["etag"], f"{label}.etag")
    container_sha = _hash(
        item["containerProjectionSha256"], f"{label}.containerProjectionSha256"
    )
    policy_sha = _hash(
        item["policyProjectionSha256"], f"{label}.policyProjectionSha256"
    )
    if derived_evidence is not None and (
        container_sha != derived_evidence.get("container")
        or policy_sha != derived_evidence.get("policy")
    ):
        fail(f"{label} projection evidence is not source-derived")
    if derived_evidence is not None and any(
        item.get(key) != expected
        for key, expected in derived_evidence.items()
        if key not in {"container", "policy"}
    ):
        fail(f"{label} fields are not source-derived")
    _observation_in_window(
        item["observedAt"],
        f"{label}.observedAt",
        started_at=started_at,
        completed_at=completed_at,
    )


def _validate_worm_projections(
    document: Mapping[str, Any],
    context: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    started_at: dt.datetime,
    completed_at: dt.datetime,
    derived_evidence: Mapping[str, Mapping[str, Any]] | None = None,
) -> None:
    _exact_keys(
        document,
        {
            "schemaVersion",
            "receiptType",
            "status",
            "authorizationId",
            "mergedSourceSha",
            "planSha256",
            "containers",
            "observedAt",
        },
        "wormProjections",
    )
    _receipt_header(
        document, "wormProjections", context, status="locked-at-least-91-days"
    )
    containers = _exact_keys(
        document["containers"],
        {"acceptedReleases", "webJobResults", "deploymentPackages"},
        "wormProjections.containers",
    )
    constants = context["model"]["constants"]
    for name, resource_name in (
        ("acceptedReleases", "acceptedContainer"),
        ("webJobResults", "resultContainer"),
        ("deploymentPackages", "packageContainer"),
    ):
        _validate_worm_item(
            containers[name],
            f"wormProjections.containers.{name}",
            container_resource_id=_resource(plan, resource_name)["resourceId"],
            constants=constants,
            started_at=started_at,
            completed_at=completed_at,
            derived_evidence=(
                None if derived_evidence is None else derived_evidence.get(name)
            ),
        )
    _observation_in_window(
        document["observedAt"],
        "wormProjections.observedAt",
        started_at=started_at,
        completed_at=completed_at,
    )


def _validate_s2_metadata(
    document: Mapping[str, Any],
    context: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    started_at: dt.datetime,
    completed_at: dt.datetime,
) -> dict[str, str]:
    del plan
    _exact_keys(
        document,
        {
            "schemaVersion",
            "receiptType",
            "status",
            "authorizationId",
            "mergedSourceSha",
            "planSha256",
            "evidenceOnly",
            "sourceLogicChanged",
            "resourcePolicyChanged",
            "files",
            "evidenceSetSha256",
            "generatedAt",
        },
        "s2OutputMetadata",
    )
    _receipt_header(
        document,
        "s2OutputMetadata",
        context,
        status="ready-for-independent-review",
    )
    if (
        document["evidenceOnly"] is not True
        or document["sourceLogicChanged"] is not False
        or document["resourcePolicyChanged"] is not False
    ):
        fail("S2 metadata does not preserve the evidence-only boundary")
    files = _list(document["files"], "s2OutputMetadata.files")
    expected_paths = context["model"]["requiredS2EvidencePaths"]
    if len(files) != len(expected_paths):
        fail("S2 evidence file set is incomplete")
    digests: dict[str, str] = {}
    for index, item in enumerate(files):
        _exact_keys(item, {"path", "sha256", "size", "canonicalJson"}, f"s2OutputMetadata.files[{index}]")
        path = _string(item["path"], f"S2 evidence path {index}")
        if path != expected_paths[index] or path in digests:
            fail("S2 evidence path order or uniqueness is invalid")
        digests[path] = _hash(item["sha256"], f"S2 evidence digest {path}")
        _integer(item["size"], f"S2 evidence size {path}", minimum=2)
        if item["canonicalJson"] is not True:
            fail(f"S2 evidence file {path} is not canonical JSON")
    if document["evidenceSetSha256"] != sha256_hex(files):
        fail("S2 evidence-set digest is invalid")
    _observation_in_window(
        document["generatedAt"],
        "s2OutputMetadata.generatedAt",
        started_at=started_at,
        completed_at=completed_at,
    )
    return digests


EXECUTION_KEYS = {
    "schemaVersion",
    "receiptType",
    "status",
    "authorizationId",
    "authorizationSha256",
    "source",
    "executor",
    "plan",
    "package",
    "azure",
    "observedPreflightSha256",
    "singleUse",
    "startedAt",
    "completedAt",
    "mutationIds",
    "irreversibleMutationIds",
    "componentDigests",
    "evidenceFileDigests",
    "s2EvidenceSetSha256",
    "productionBoundarySha256",
    "productionMutationCount",
    "sourceEvidence",
    "failures",
    "pendingHousekeeping",
}


def _validate_execution(
    document: Mapping[str, Any],
    context: Mapping[str, Any],
    *,
    now: dt.datetime,
) -> tuple[dt.datetime, dt.datetime]:
    _exact_keys(document, EXECUTION_KEYS, "executionReceipt")
    if (
        document["schemaVersion"] != 1
        or document["receiptType"] != context["model"]["receiptTypes"]["executionReceipt"]
        or document["status"] != "succeeded-terminal"
        or document["authorizationId"] != context["authorizationId"]
        or document["authorizationSha256"] != context["authorizationSha256"]
    ):
        fail("execution receipt identity or authorization binding is invalid")
    source = _exact_keys(
        document["source"],
        {"reviewedHeadSha", "mergedMainSha", "treeSha"},
        "executionReceipt.source",
    )
    if source != {
        "reviewedHeadSha": context["reviewedHeadSha"],
        "mergedMainSha": context["mergedMainSha"],
        "treeSha": context["treeSha"],
    }:
        fail("execution receipt source binding is invalid")
    executor = _exact_keys(document["executor"], {"path", "sha256"}, "executionReceipt.executor")
    if executor != {"path": context["executorPath"], "sha256": context["executorSha256"]}:
        fail("execution receipt executor binding is invalid")
    plan_binding = _exact_keys(
        document["plan"], {"path", "sha256", "document"}, "executionReceipt.plan"
    )
    plan_document = _canonical_projection(
        plan_binding["document"], "executionReceipt.plan.document"
    )
    if plan_binding != {
        "path": context["planPath"],
        "sha256": context["planSha256"],
        "document": plan_document,
    } or plan_document != context["reviewedPlan"]:
        fail("execution receipt plan binding is invalid")
    package = _exact_keys(document["package"], {"sha256", "size"}, "executionReceipt.package")
    if package != {"sha256": context["packageSha256"], "size": context["packageSize"]}:
        fail("execution receipt package binding is invalid")
    azure = _exact_keys(
        document["azure"],
        {
            "cloud",
            "subscriptionId",
            "tenantId",
            "operatorObjectId",
            "operatorAccountIdSha256",
            "operatorAccountType",
        },
        "executionReceipt.azure",
    )
    if azure != {
        "cloud": "AzureCloud",
        "subscriptionId": context["subscriptionId"],
        "tenantId": context["tenantId"],
        "operatorObjectId": context["operatorObjectId"],
        "operatorAccountIdSha256": context["operatorAccountIdSha256"],
        "operatorAccountType": context["operatorAccountType"],
    }:
        fail("execution receipt Azure/operator binding is invalid")
    if document["observedPreflightSha256"] != context["preflightSha256"]:
        fail("execution receipt preflight binding is invalid")

    started_at = _timestamp(document["startedAt"], "executionReceipt.startedAt")
    completed_at = _timestamp(document["completedAt"], "executionReceipt.completedAt")
    if (
        started_at < context["notBefore"]
        or completed_at > context["expiresAt"]
        or completed_at < started_at
        or (completed_at - started_at).total_seconds() > 1800
    ):
        fail("execution receipt timestamps are outside the authorization window")
    if (
        started_at < context["preflightAt"]
        or (started_at - context["preflightAt"]).total_seconds() > context["preflightMaximumAge"]
    ):
        fail("execution started from a stale preflight")
    if now < completed_at or (
        now - completed_at
    ).total_seconds() > context["model"]["constants"]["maximumEvidenceLagSeconds"]:
        fail("terminal evidence is stale or from the future")

    single_use = _exact_keys(
        document["singleUse"],
        {
            "status",
            "azureClaimResourceId",
            "claimReceiptSha256",
            "claimedAt",
            "terminalAt",
            "retryable",
        },
        "executionReceipt.singleUse",
    )
    if (
        single_use["status"] != "consumed-terminal"
        or single_use["azureClaimResourceId"] != context["azureClaimResourceId"]
        or single_use["retryable"] is not False
    ):
        fail("one-shot authorization is not terminally consumed")
    _hash(single_use["claimReceiptSha256"], "one-shot claim receipt digest")
    claimed_at = _timestamp(single_use["claimedAt"], "one-shot claimedAt")
    terminal_at = _timestamp(single_use["terminalAt"], "one-shot terminalAt")
    if claimed_at != started_at or terminal_at != completed_at:
        fail("one-shot state timestamps do not bind the execution window")

    if document["mutationIds"] != context["mutationIds"]:
        fail("execution receipt mutation universe is invalid")
    if len(document["mutationIds"]) != len(set(document["mutationIds"])):
        fail("execution receipt contains duplicate mutation IDs")
    if document["irreversibleMutationIds"] != context["irreversibleMutationIds"]:
        fail("execution receipt irreversible mutation universe is invalid")
    component_digests = _exact_keys(
        document["componentDigests"], set(COMPONENT_DIGEST_KEYS), "executionReceipt.componentDigests"
    )
    for key in COMPONENT_DIGEST_KEYS:
        _hash(component_digests[key], f"execution component digest {key}")
    file_digests = document["evidenceFileDigests"]
    if not isinstance(file_digests, Mapping):
        fail("execution evidence-file digests must be an object")
    for path, digest in file_digests.items():
        _string(path, "execution evidence path")
        _hash(digest, f"execution evidence digest {path}")
    _hash(document["s2EvidenceSetSha256"], "execution S2 evidence-set digest")
    _hash(document["productionBoundarySha256"], "production boundary projection")
    if document["productionMutationCount"] != 0:
        fail("bootstrap receipt records a forbidden production mutation")
    if not isinstance(document["sourceEvidence"], Mapping):
        fail("execution receipt lacks full terminal source evidence")
    if document["failures"] != [] or document["pendingHousekeeping"] != []:
        fail("execution receipt is not terminal-clean")
    return started_at, completed_at


def _now(value: dt.datetime | str | None) -> dt.datetime:
    if value is None:
        fail("validation now is mandatory and must come from a trusted clock")
    if isinstance(value, str):
        return _timestamp(value, "validation now")
    if not isinstance(value, dt.datetime) or value.tzinfo is None:
        fail("validation now must be timezone-aware")
    return value.astimezone(dt.timezone.utc)


def _validate_non_execution_components(
    components: Mapping[str, Mapping[str, Any]],
    context: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    started_at: dt.datetime,
    completed_at: dt.datetime,
    derived_evidence: Mapping[str, Any] | None = None,
) -> tuple[dict[str, str], dict[str, str]]:
    """Validate every observed component before a terminal receipt is created."""

    if not isinstance(components, Mapping) or set(components) != set(COMPONENT_DIGEST_KEYS):
        fail("non-execution component universe is incomplete")
    for name in COMPONENT_DIGEST_KEYS:
        if not isinstance(components[name], Mapping):
            fail(f"{name} must be an object")

    _validate_permanent_ledger(
        components["permanentMutationLedger"],
        context,
        plan,
        started_at=started_at,
        completed_at=completed_at,
        derived_evidence=(
            None
            if derived_evidence is None
            else derived_evidence.get("permanentMutationSha256")
        ),
        derived_entries=(
            None
            if derived_evidence is None
            else derived_evidence.get("permanentMutationEntries")
        ),
    )
    _validate_temporary_cleanup(
        components["temporaryAccessCleanup"],
        context,
        plan,
        started_at=started_at,
        completed_at=completed_at,
        derived_absences=(
            None
            if derived_evidence is None
            else derived_evidence.get("cleanupAbsenceSha256")
        ),
    )
    _validate_activation_fence(
        components["activationFenceBootstrap"],
        context,
        plan,
        started_at=started_at,
        completed_at=completed_at,
        derived_fields=(
            None
            if derived_evidence is None
            else derived_evidence.get("activationFenceFields")
        ),
    )
    _validate_package_readback(
        components["packageReadback"],
        context,
        plan,
        started_at=started_at,
        completed_at=completed_at,
        derived_fields=(
            None
            if derived_evidence is None
            else derived_evidence.get("packageReadbackFields")
        ),
    )
    _validate_managed_identity_fetch(
        components["managedIdentityFetchSelfTest"],
        context,
        plan,
        started_at=started_at,
        completed_at=completed_at,
        derived_response_sha256=(
            None
            if derived_evidence is None
            else derived_evidence.get("managedIdentityFetchResponseProjectionSha256")
        ),
    )
    _validate_bridge_evidence(
        components["bridgeEvidence"],
        context,
        plan,
        started_at=started_at,
        completed_at=completed_at,
        derived_evidence=derived_evidence,
        derived_fields=(
            None
            if derived_evidence is None
            else derived_evidence.get("bridgeFields")
        ),
    )
    _validate_lease_canaries(
        components["leaseCanaryEvidence"],
        context,
        plan,
        started_at=started_at,
        completed_at=completed_at,
        derived_evidence=(
            None
            if derived_evidence is None
            else derived_evidence.get("leaseSourceSha256")
        ),
    )
    _validate_worm_projections(
        components["wormProjections"],
        context,
        plan,
        started_at=started_at,
        completed_at=completed_at,
        derived_evidence=(
            None
            if derived_evidence is None
            else derived_evidence.get("wormSourceSha256")
        ),
    )
    s2_file_digests = _validate_s2_metadata(
        components["s2OutputMetadata"],
        context,
        plan,
        started_at=started_at,
        completed_at=completed_at,
    )

    component_digests = {
        name: sha256_hex(components[name]) for name in COMPONENT_DIGEST_KEYS
    }
    temporary_sha = component_digests["temporaryAccessCleanup"]
    fence_sha = component_digests["activationFenceBootstrap"]
    package_sha = component_digests["packageReadback"]
    managed_identity_sha = component_digests["managedIdentityFetchSelfTest"]
    lease_sha = component_digests["leaseCanaryEvidence"]
    if components["activationFenceBootstrap"]["temporaryAccessCleanupSha256"] != temporary_sha:
        fail("activation fence does not bind temporary-access cleanup")
    if components["managedIdentityFetchSelfTest"]["packageReadbackSha256"] != package_sha:
        fail("managed-identity self-test does not bind package readback")
    if (
        components["managedIdentityFetchSelfTest"]["packageVersionId"]
        != components["packageReadback"]["versionId"]
    ):
        fail("managed-identity self-test package version does not match readback")
    if (
        components["leaseCanaryEvidence"]["activationFenceBootstrapSha256"] != fence_sha
        or components["leaseCanaryEvidence"]["temporaryAccessCleanupSha256"]
        != temporary_sha
    ):
        fail("lease canaries do not bind cleanup and activation-fence bootstrap")
    bridge = components["bridgeEvidence"]
    if (
        bridge["packageReadbackSha256"] != package_sha
        or bridge["managedIdentityFetchSelfTestSha256"] != managed_identity_sha
        or bridge["leaseCanaryEvidenceSha256"] != lease_sha
    ):
        fail("bridge evidence component-digest bindings are invalid")
    if derived_evidence is not None and bridge["productionBoundarySha256"] != _hash(
        derived_evidence.get("productionBoundarySha256"),
        "production boundary projection",
    ):
        fail("bridge evidence production-boundary binding is invalid")
    if derived_evidence is not None:
        terminal_observed_at = _string(
            derived_evidence.get("terminalObservedAt"),
            "derived terminal observation time",
        )
        for component_name in (
            "permanentMutationLedger",
            "temporaryAccessCleanup",
            "bridgeEvidence",
            "leaseCanaryEvidence",
            "wormProjections",
        ):
            if components[component_name].get("observedAt") != terminal_observed_at:
                fail(f"{component_name}.observedAt is not source-derived")
    return s2_file_digests, component_digests


def validate_receipt_bundle(
    bundle: Mapping[str, Any],
    *,
    authorization: Mapping[str, Any],
    plan: Mapping[str, Any],
    s2_documents: Mapping[str, bytes | bytearray],
    terminal_bundle_path: str,
    terminal_bundle_body: bytes | bytearray,
    authorized_preflight_projection: Mapping[str, Any],
    package_bytes: bytes | bytearray,
    now: dt.datetime | str | None,
) -> dict[str, Any]:
    """Validate exact S2 bodies plus the durable canonical terminal bundle."""

    expected_bundle_keys = {"schemaVersion", "bundleType", *RECEIPT_COMPONENTS}
    _exact_keys(bundle, expected_bundle_keys, "bootstrap receipt bundle")
    context = _context(authorization, plan)
    if terminal_bundle_path != context["model"]["requiredS2TerminalBundlePath"]:
        fail("durable terminal bundle path is not the reviewed exact path")
    if bundle["schemaVersion"] != 1 or bundle["bundleType"] != context["model"]["bundleType"]:
        fail("bootstrap receipt bundle identity is invalid")
    _reject_secret_material(bundle)
    trusted_now = _now(now)
    if not isinstance(terminal_bundle_body, (bytes, bytearray)):
        fail("durable terminal bundle body must be canonical bytes")
    terminal_document = load_canonical_json_bytes(
        terminal_bundle_body,
        label="durable terminal bundle body",
        maximum_bytes=16 * 1024 * 1024,
    )
    if terminal_document != bundle:
        fail("durable terminal bundle body does not equal the supplied bundle")

    execution = bundle["executionReceipt"]
    if not isinstance(execution, Mapping):
        fail("executionReceipt must be an object")
    started_at, completed_at = _validate_execution(
        execution, context, now=trusted_now
    )
    if execution["plan"]["document"] != plan:
        fail("terminal bundle does not retain the exact reviewed plan document")

    components: dict[str, Mapping[str, Any]] = {}
    for name in COMPONENT_DIGEST_KEYS:
        value = bundle[name]
        if not isinstance(value, Mapping):
            fail(f"{name} must be an object")
        components[name] = value

    expected_paths = list(context["model"]["requiredS2EvidencePaths"])
    decoded_s2 = _canonical_s2_document_map(
        s2_documents, expected_paths, require_bytes=True
    )
    canonical_s2 = build_s2_evidence_files(
        authorization=authorization,
        plan=plan,
        provisioning_evidence=decoded_s2[
            S2_EVIDENCE_COMPONENT_PATHS["provisioningEvidence"]
        ],
        bridge_runtime_receipt=decoded_s2[
            S2_EVIDENCE_COMPONENT_PATHS["bridgeRuntimeReceipt"]
        ],
        temporary_cleanup_receipt=decoded_s2[
            S2_EVIDENCE_COMPONENT_PATHS["temporaryAccessCleanup"]
        ],
        activation_fence_receipt=decoded_s2[
            S2_EVIDENCE_COMPONENT_PATHS["activationFenceBootstrap"]
        ],
        bridge_canary_receipt=decoded_s2[
            S2_EVIDENCE_COMPONENT_PATHS["bridgeEvidence"]
        ],
    )
    supplied_s2 = {path: bytes(s2_documents[path]) for path in expected_paths}
    if supplied_s2 != canonical_s2:
        fail("S2 documents are not the exact five canonical validated bodies")
    for component_name in (
        "temporaryAccessCleanup",
        "activationFenceBootstrap",
        "bridgeEvidence",
    ):
        path = S2_EVIDENCE_COMPONENT_PATHS[component_name]
        if decoded_s2[path] != components[component_name]:
            fail(f"S2 file {path} does not equal its terminal component")

    source_evidence, derived_evidence = _validate_source_evidence(
        execution["sourceEvidence"],
        authorization=authorization,
        context=context,
        plan=plan,
        provisioning=decoded_s2[
            S2_EVIDENCE_COMPONENT_PATHS["provisioningEvidence"]
        ],
        runtime_receipt=decoded_s2[
            S2_EVIDENCE_COMPONENT_PATHS["bridgeRuntimeReceipt"]
        ],
        components=components,
        authorized_preflight_projection=authorized_preflight_projection,
        package_bytes=package_bytes,
        started_at=started_at,
        completed_at=completed_at,
    )
    if source_evidence != execution["sourceEvidence"]:
        fail("execution receipt source evidence is not canonical")
    s2_file_digests, expected_component_digests = _validate_non_execution_components(
        components,
        context,
        plan,
        started_at=started_at,
        completed_at=completed_at,
        derived_evidence=derived_evidence,
    )
    if execution["componentDigests"] != expected_component_digests:
        fail("execution component-digest bindings are invalid")
    if execution["evidenceFileDigests"] != s2_file_digests:
        fail("execution S2 evidence-file digest bindings are invalid")
    if execution["s2EvidenceSetSha256"] != components["s2OutputMetadata"]["evidenceSetSha256"]:
        fail("execution S2 evidence-set binding is invalid")
    expected_descriptors = [
        {
            "path": path,
            "sha256": sha256_hex(supplied_s2[path]),
            "size": len(supplied_s2[path]),
            "canonicalJson": True,
        }
        for path in expected_paths
    ]
    if components["s2OutputMetadata"]["files"] != expected_descriptors:
        fail("S2 metadata does not describe the exact five supplied bodies")
    if execution["singleUse"]["claimReceiptSha256"] != derived_evidence[
        "claimReceiptSha256"
    ]:
        fail("one-shot claim receipt digest is not internally derived")
    if execution["productionBoundarySha256"] != derived_evidence[
        "productionBoundarySha256"
    ]:
        fail("terminal production boundary is not internally derived")

    canonical = canonical_json_bytes(bundle)
    if canonical != bytes(terminal_bundle_body):
        fail("terminal bundle canonical bytes changed during validation")
    return load_canonical_json_bytes(
        canonical, label="validated receipt bundle", maximum_bytes=16 * 1024 * 1024
    )


def validate_bootstrap_bundle(
    bundle: Mapping[str, Any],
    *,
    authorization: Mapping[str, Any],
    plan: Mapping[str, Any],
    s2_documents: Mapping[str, bytes | bytearray],
    terminal_bundle_path: str,
    terminal_bundle_body: bytes | bytearray,
    authorized_preflight_projection: Mapping[str, Any],
    package_bytes: bytes | bytearray,
    now: dt.datetime | str | None,
) -> dict[str, Any]:
    """Compatibility alias used by the one-shot bootstrap executor."""

    return validate_receipt_bundle(
        bundle,
        authorization=authorization,
        plan=plan,
        s2_documents=s2_documents,
        terminal_bundle_path=terminal_bundle_path,
        terminal_bundle_body=terminal_bundle_body,
        authorized_preflight_projection=authorized_preflight_projection,
        package_bytes=package_bytes,
        now=now,
    )


def _build_component(
    component: str,
    document: Mapping[str, Any] | None = None,
    **fields: Any,
) -> dict[str, Any]:
    if document is not None and fields:
        fail(f"{component} builder accepts either a document or keyword fields, not both")
    value: Any = document if document is not None else fields
    if not isinstance(value, Mapping):
        fail(f"{component} builder requires an object")
    maximum_bytes = 16 * 1024 * 1024 if component == "executionReceipt" else 1024 * 1024
    built = load_canonical_json_bytes(
        canonical_json_bytes(value),
        label=f"built {component}",
        maximum_bytes=maximum_bytes,
    )
    _reject_secret_material(built, component)
    expected_type = load_model()["receiptTypes"][component]
    if built.get("schemaVersion") != 1 or built.get("receiptType") != expected_type:
        fail(f"{component} builder identity is invalid")
    return built


def build_permanent_mutation_ledger(
    document: Mapping[str, Any] | None = None, **fields: Any
) -> dict[str, Any]:
    return _build_component("permanentMutationLedger", document, **fields)


def build_temporary_access_cleanup(
    document: Mapping[str, Any] | None = None, **fields: Any
) -> dict[str, Any]:
    return _build_component("temporaryAccessCleanup", document, **fields)


def build_activation_fence_evidence(
    document: Mapping[str, Any] | None = None, **fields: Any
) -> dict[str, Any]:
    return _build_component("activationFenceBootstrap", document, **fields)


def build_package_readback_evidence(
    document: Mapping[str, Any] | None = None, **fields: Any
) -> dict[str, Any]:
    return _build_component("packageReadback", document, **fields)


def build_managed_identity_fetch_self_test(
    document: Mapping[str, Any] | None = None, **fields: Any
) -> dict[str, Any]:
    return _build_component("managedIdentityFetchSelfTest", document, **fields)


def build_bridge_evidence(
    document: Mapping[str, Any] | None = None, **fields: Any
) -> dict[str, Any]:
    return _build_component("bridgeEvidence", document, **fields)


def build_lease_canary_evidence(
    document: Mapping[str, Any] | None = None, **fields: Any
) -> dict[str, Any]:
    return _build_component("leaseCanaryEvidence", document, **fields)


def build_worm_projection(
    document: Mapping[str, Any] | None = None, **fields: Any
) -> dict[str, Any]:
    return _build_component("wormProjections", document, **fields)


def build_s2_output_metadata(
    document: Mapping[str, Any] | None = None, **fields: Any
) -> dict[str, Any]:
    return _build_component("s2OutputMetadata", document, **fields)


def _canonical_document(document: Mapping[str, Any], label: str) -> dict[str, Any]:
    if not isinstance(document, Mapping):
        fail(f"{label} must be an object")
    value = load_canonical_json_bytes(canonical_json_bytes(document), label=label)
    _reject_secret_material(value, label)
    return value


def _resource_guid(resource_id: Any, label: str) -> str:
    value = _string(resource_id, label)
    return _guid(value.rsplit("/", 1)[-1].lower(), label)


def _mailbox_role(
    provisioning_evidence: Mapping[str, Any], name: str
) -> Mapping[str, Any]:
    roles = provisioning_evidence.get("roles")
    if not isinstance(roles, Mapping) or not isinstance(roles.get(name), Mapping):
        fail(f"provisioning evidence is missing mailbox role {name}")
    return roles[name]


def _load_mailbox_validator() -> Any:
    try:
        from scripts import private_release_mailbox as mailbox
    except (ImportError, ModuleNotFoundError):
        try:
            import private_release_mailbox as mailbox  # type: ignore[no-redef]
        except (ImportError, ModuleNotFoundError) as exc:
            raise BootstrapReceiptError(
                "the private-release mailbox validator is unavailable"
            ) from exc
    return mailbox


def _validate_rich_mailbox_s2_documents(
    *,
    authorization: Mapping[str, Any],
    plan: Mapping[str, Any],
    provisioning_evidence: Mapping[str, Any],
    bridge_runtime_receipt: Mapping[str, Any],
    activation_fence_receipt: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate the two mailbox-facing S2 files using the mailbox's own schema.

    The activation document is reconstructed only as an in-memory validator
    input from already observed rich evidence.  It is never returned, persisted
    or used to fill a missing observation.
    """

    context = _context(authorization, plan)
    if "bridgePackageSourceSha" not in authorization.get("plan", {}):
        fail("strict S2 assembly requires authorization.plan.bridgePackageSourceSha")
    evidence = _canonical_document(provisioning_evidence, "provisioning evidence")
    if evidence.get("rule") != RICH_EVIDENCE_RULE:
        fail("provisioning evidence rule is not the reviewed source-exact rule")
    runtime_receipt = _canonical_document(
        bridge_runtime_receipt, "bridge runtime receipt"
    )
    fence_receipt = _canonical_document(
        activation_fence_receipt, "activation fence receipt"
    )
    mailbox = _load_mailbox_validator()

    bridge_runtime = evidence.get("bridgeRuntime")
    key_boundary = evidence.get("keyVaultBoundary")
    publisher_identity = evidence.get("publisherIdentity")
    if not isinstance(bridge_runtime, Mapping):
        fail("provisioning evidence bridgeRuntime is missing")
    if not isinstance(key_boundary, Mapping):
        fail("provisioning evidence keyVaultBoundary is missing")
    if not isinstance(publisher_identity, Mapping):
        fail("provisioning evidence publisherIdentity is missing")

    package_blob = _string(
        bridge_runtime.get("packageBlob"), "provisioning bridge package blob"
    )
    package_match = re.fullmatch(
        r"v2/control/([0-9a-f]{40})/paperdesk-private-release-bridge\.zip",
        package_blob,
    )
    if package_match is None or package_match.group(1) != context["packageSourceSha"]:
        fail("provisioning evidence package source binding is invalid")
    if context["packageSourceSha"] != context["mergedMainSha"]:
        fail("pre-S2 provisioning package is not derived from the reviewed S1-prime source")
    if (
        bridge_runtime.get("packageSha256") != context["packageSha256"]
        or bridge_runtime.get("packageSize") != context["packageSize"]
    ):
        fail("provisioning evidence package bytes binding is invalid")

    key_projection = key_boundary.get("keyDataPlaneProjection")
    if not isinstance(key_projection, Mapping):
        fail("provisioning signing-key projection is missing")
    key_uri_with_version = _string(
        key_projection.get("kid"), "provisioning signing key URI"
    )
    if "/" not in key_uri_with_version:
        fail("provisioning signing key URI is not versioned")
    signing_key_id, signing_key_version = key_uri_with_version.rsplit("/", 1)

    mailbox_role = _mailbox_role(evidence, "publisherMailbox")
    controller_role = _mailbox_role(evidence, "publisherControllerLock")
    bridge_role = _mailbox_role(evidence, "bridgeMailboxResult")
    fence_role = _mailbox_role(evidence, "bridgeActivationFence")
    writer_role = _mailbox_role(evidence, "writerRegistryAdd")
    writer_package_role = _mailbox_role(evidence, "writerPackageAdd")
    reader_role = _mailbox_role(evidence, "readerRegistryRead")
    reader_package_role = _mailbox_role(evidence, "readerPackageRead")
    signer_role = _mailbox_role(evidence, "signerKeySign")
    production_role = _mailbox_role(evidence, "productionActivation")
    production_reader_role = _mailbox_role(evidence, "productionSystemPackageRead")

    activation = {
        "mergedControlWorkflowSha": context["mergedMainSha"],
        "mailboxResourceGroup": _string(
            mailbox_role.get("scope"), "mailbox role scope"
        ).rsplit("/", 1)[-1],
        "mailboxPublisherClientId": _guid(
            mailbox_role.get("identityClientId"), "publisher client ID"
        ),
        "mailboxPublisherPrincipalId": _guid(
            mailbox_role.get("principalId"), "publisher principal ID"
        ),
        "mailboxRoleDefinitionId": _resource_guid(
            mailbox_role.get("roleDefinitionResourceId"),
            "publisher mailbox role definition",
        ),
        "mailboxRoleAssignmentId": _resource_guid(
            mailbox_role.get("roleAssignmentResourceId"),
            "publisher mailbox role assignment",
        ),
        "controllerLockRoleDefinitionId": _resource_guid(
            controller_role.get("roleDefinitionResourceId"),
            "controller-lock role definition",
        ),
        "controllerLockRoleAssignmentId": _resource_guid(
            controller_role.get("roleAssignmentResourceId"),
            "controller-lock role assignment",
        ),
        "controllerLockRoleAssignmentScope": controller_role.get("scope"),
        "controllerLockRoleDefinitionActions": controller_role.get("actions"),
        "controllerLockForbiddenDataActions": controller_role.get("notDataActions"),
        "tenantId": context["tenantId"],
        "bridgeManagedIdentityClientId": bridge_role.get("identityClientId"),
        "bridgeManagedIdentityPrincipalId": bridge_role.get("principalId"),
        "bridgeManagedIdentityResourceId": bridge_role.get("identityResourceId"),
        "registryWriterManagedIdentityClientId": writer_role.get("identityClientId"),
        "registryWriterManagedIdentityPrincipalId": writer_role.get("principalId"),
        "registryWriterManagedIdentityResourceId": writer_role.get("identityResourceId"),
        "registryReaderManagedIdentityClientId": reader_role.get("identityClientId"),
        "registryReaderManagedIdentityPrincipalId": reader_role.get("principalId"),
        "registryReaderManagedIdentityResourceId": reader_role.get("identityResourceId"),
        "signerManagedIdentityClientId": signer_role.get("identityClientId"),
        "signerManagedIdentityPrincipalId": signer_role.get("principalId"),
        "signerManagedIdentityResourceId": signer_role.get("identityResourceId"),
        "signerRoleDefinitionId": _resource_guid(
            signer_role.get("roleDefinitionResourceId"), "signer role definition"
        ),
        "signerRoleAssignmentId": _resource_guid(
            signer_role.get("roleAssignmentResourceId"), "signer role assignment"
        ),
        "signerRoleAssignmentScope": signer_role.get("scope"),
        "signerRoleDefinitionDataActions": signer_role.get("dataActions"),
        "signerForbiddenRoleAssignments": [],
        "signingKeyId": signing_key_id,
        "signingKeyVersion": signing_key_version,
        "signingPublicJwk": {
            key: key_projection.get(key)
            for key in ("kid", "kty", "n", "e", "key_ops")
        },
        "bridgePackageSourceSha": context["packageSourceSha"],
        "bridgePackageSha256": context["packageSha256"],
        "productionActivationManagedIdentityClientId": production_role.get(
            "identityClientId"
        ),
        "productionActivationManagedIdentityPrincipalId": production_role.get(
            "principalId"
        ),
        "productionActivationManagedIdentityResourceId": production_role.get(
            "identityResourceId"
        ),
        "productionActivationRoleDefinitionId": _resource_guid(
            production_role.get("roleDefinitionResourceId"),
            "production activation role definition",
        ),
        "productionActivationRoleAssignmentId": _resource_guid(
            production_role.get("roleAssignmentResourceId"),
            "production activation role assignment",
        ),
        "productionActivationRoleAssignmentScope": production_role.get("scope"),
        "productionActivationRoleDefinitionActions": production_role.get("actions"),
        "productionActivationForbiddenRoleAssignments": [],
        "productionPackageReaderRoleAssignmentId": _resource_guid(
            production_reader_role.get("roleAssignmentResourceId"),
            "production package-reader role assignment",
        ),
        "productionPackageReaderRoleScope": production_reader_role.get("scope"),
        "productionForbiddenDataPlaneAssignments": [],
        "productionSystemIdentityClientId": production_reader_role.get(
            "identityClientId"
        ),
        "productionSystemIdentityPrincipalId": production_reader_role.get(
            "principalId"
        ),
        "packageWriterRoleAssignmentId": _resource_guid(
            writer_package_role.get("roleAssignmentResourceId"),
            "package writer role assignment",
        ),
        "packageReaderRoleAssignmentId": _resource_guid(
            reader_package_role.get("roleAssignmentResourceId"),
            "package reader role assignment",
        ),
        "activationFence": {
            "storageAccount": mailbox.FIXED_COORDS["packageAccount"],
            "container": mailbox.FIXED_COORDS["activationFenceContainer"],
            "blob": mailbox.FIXED_COORDS["activationFenceBlob"],
            "scope": fence_role.get("scope"),
            "bridgeRoleAssignmentId": _resource_guid(
                fence_role.get("roleAssignmentResourceId"),
                "bridge activation-fence role assignment",
            ),
            "bridgePrincipalId": fence_role.get("principalId"),
            "leaseDuration": context["model"]["constants"]["finiteLeaseSeconds"],
            "publicAccess": "None",
            "bootstrapReceiptSha256": sha256_hex(fence_receipt),
            "governanceBoundary": (
                "subscription-and-resource-group-owners-remain-out-of-band-and-"
                "third-state-is-never-overwritten"
            ),
        },
        "provisioningEvidenceSha256": sha256_hex(evidence),
    }

    contract_path = ROOT / "contracts" / "private_release_mailbox_contract.json"
    try:
        activation_document = json.loads(
            contract_path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BootstrapReceiptError(
            "mailbox activation contract cannot be loaded"
        ) from exc
    activation_document["status"] = "activated"
    activation_document["fixed"] = copy.deepcopy(mailbox.FIXED_COORDS)
    activation_document["activation"] = activation

    try:
        observed_activation = mailbox.load_activation_document(
            activation_document,
            runtime_workflow_sha=context["mergedMainSha"],
            observed_bridge_package_sha256=context["packageSha256"],
            provisioning_evidence=evidence,
            pre_s2_evidence_validation=True,
        )
        validated_runtime = mailbox.validate_bridge_runtime_receipt(
            runtime_receipt, observed_activation
        )
    except Exception as exc:
        mailbox_error = getattr(mailbox, "MailboxError", ValueError)
        if isinstance(exc, mailbox_error):
            raise BootstrapReceiptError(
                f"rich mailbox S2 evidence is invalid: {exc}"
            ) from exc
        raise
    if validated_runtime != runtime_receipt:
        fail("mailbox runtime validator changed the observed receipt")
    _observation_in_window(
        evidence.get("observedAt"),
        "provisioning evidence observedAt",
        started_at=context["notBefore"],
        completed_at=context["expiresAt"],
    )
    _observation_in_window(
        bridge_runtime.get("observedAt"),
        "provisioning bridge runtime observedAt",
        started_at=context["notBefore"],
        completed_at=context["expiresAt"],
    )
    _observation_in_window(
        runtime_receipt.get("observedAt"),
        "bridge runtime receipt observedAt",
        started_at=context["notBefore"],
        completed_at=context["expiresAt"],
    )
    return evidence, runtime_receipt


def _validate_rich_source_projections(
    value: Any,
    provisioning: Mapping[str, Any],
    context: Mapping[str, Any],
    plan: Mapping[str, Any],
) -> None:
    source = _exact_keys(
        value,
        {
            "publisherApplication",
            "publisherServicePrincipal",
            "solePublisherFederatedCredentials",
            "roleDefinitions",
            "roleAssignments",
            "principalDirectAssignments",
            "principalEffectiveAssignments",
            "controllerLockContainer",
            "networkTopology",
        },
        "rich provisioning source projections",
    )
    publisher = provisioning.get("publisherIdentity")
    if not isinstance(publisher, Mapping):
        fail("rich provisioning evidence lacks publisher identity")
    application = _exact_keys(
        _canonical_projection(
            source["publisherApplication"], "publisher application projection"
        ),
        {
            "id",
            "appId",
            "signInAudience",
            "passwordCredentialKeyIds",
            "keyCredentialKeyIds",
        },
        "publisher application projection",
    )
    service = _exact_keys(
        _canonical_projection(
            source["publisherServicePrincipal"],
            "publisher service-principal projection",
        ),
        {
            "id",
            "appId",
            "accountEnabled",
            "servicePrincipalType",
            "passwordCredentialKeyIds",
            "keyCredentialKeyIds",
        },
        "publisher service-principal projection",
    )
    if (
        sha256_hex(application) != publisher.get("applicationProjectionSha256")
        or application["id"] != publisher.get("applicationObjectId")
        or application["signInAudience"] != "AzureADMyOrg"
        or application["passwordCredentialKeyIds"] != []
        or application["keyCredentialKeyIds"] != []
        or sha256_hex(service) != publisher.get("servicePrincipalProjectionSha256")
        or service["accountEnabled"] is not True
        or service["servicePrincipalType"] != "Application"
        or service["passwordCredentialKeyIds"] != []
        or service["keyCredentialKeyIds"] != []
        or service["appId"] != application["appId"]
    ):
        fail("publisher application/service-principal source proof is not exact")

    fic_items = _list(
        _canonical_projection(
            source["solePublisherFederatedCredentials"],
            "sole publisher federated-credential projection",
        ),
        "sole publisher federated-credential projection",
    )
    if len(fic_items) != 1 or not isinstance(fic_items[0], Mapping):
        fail("publisher federated-credential projection is not sole")
    fic_resource = _resource(plan, "publisherFederatedCredential")
    expected_expression = fic_resource["claimsMatchingExpressionTemplate"].replace(
        "${authorization.source.mergedMain.commitSha}", context["mergedMainSha"]
    )
    fic = fic_items[0]
    if (
        fic.get("name") != fic_resource["name"]
        or fic.get("issuer") != fic_resource["issuer"]
        or fic.get("audiences") != fic_resource["audiences"]
        or fic.get("subject") is not None
        or fic.get("claimsMatchingExpression")
        != {
            "languageVersion": fic_resource[
                "claimsMatchingExpressionLanguageVersion"
            ],
            "value": expected_expression,
        }
    ):
        fail("publisher federated credential is not pinned to the authorized S1 source")

    roles = provisioning.get("roles")
    if not isinstance(roles, Mapping):
        fail("rich provisioning evidence lacks role projections")
    definition_bodies = _exact_keys(
        _canonical_projection(source["roleDefinitions"], "role-definition bodies"),
        set(roles),
        "role-definition bodies",
    )
    assignment_bodies = _exact_keys(
        _canonical_projection(source["roleAssignments"], "role-assignment bodies"),
        set(roles),
        "role-assignment bodies",
    )
    for name, role in roles.items():
        if not isinstance(role, Mapping):
            fail(f"rich role {name} is invalid")
        definition = _canonical_projection(
            definition_bodies[name], f"role definition {name}"
        )
        assignment = _canonical_projection(
            assignment_bodies[name], f"role assignment {name}"
        )
        if (
            sha256_hex(definition) != role.get("roleDefinitionSha256")
            or sha256_hex(assignment) != role.get("roleAssignmentSha256")
            or str(definition.get("id", "")).lower()
            != str(role.get("roleDefinitionResourceId", "")).lower()
            or str(assignment.get("id", "")).lower()
            != str(role.get("roleAssignmentResourceId", "")).lower()
        ):
            fail(f"role source projections do not bind {name}")

    inventories = provisioning.get("principalInventories")
    if not isinstance(inventories, Mapping):
        fail("rich provisioning evidence lacks principal inventories")
    direct = _exact_keys(
        _canonical_projection(
            source["principalDirectAssignments"], "direct RBAC source projections"
        ),
        set(inventories),
        "direct RBAC source projections",
    )
    effective = _exact_keys(
        _canonical_projection(
            source["principalEffectiveAssignments"],
            "effective RBAC source projections",
        ),
        set(inventories),
        "effective RBAC source projections",
    )
    for name, inventory in inventories.items():
        direct_items = _list(direct[name], f"direct RBAC source projection {name}")
        effective_items = _list(
            effective[name], f"effective RBAC source projection {name}"
        )
        if (
            sha256_hex(direct_items) != inventory.get("directAssignmentSetSha256")
            or sha256_hex(effective_items)
            != inventory.get("effectiveAssignmentSetSha256")
            or [item.get("id") for item in direct_items]
            != inventory.get("directAssignmentResourceIds")
            or [item.get("id") for item in effective_items]
            != inventory.get("effectiveAssignmentResourceIds")
        ):
            fail(f"principal RBAC source projections do not bind {name}")

    controller = provisioning.get("controllerLockContainer")
    controller_body = _canonical_projection(
        source["controllerLockContainer"], "controller-lock container projection"
    )
    if (
        not isinstance(controller, Mapping)
        or sha256_hex(controller_body) != controller.get("resourceSha256")
        or controller_body.get("publicAccess") != "None"
        or str(controller_body.get("id", "")).lower()
        != str(controller.get("scope", "")).lower()
    ):
        fail("controller-lock container source projection is invalid")

    bridge_runtime = provisioning.get("bridgeRuntime")
    topology = (
        bridge_runtime.get("networkTopology")
        if isinstance(bridge_runtime, Mapping)
        else None
    )
    if not isinstance(topology, Mapping):
        fail("rich provisioning evidence lacks network topology")
    topology_source = _exact_keys(
        _canonical_projection(source["networkTopology"], "network source projections"),
        {"virtualNetwork", "integrationSubnet", "packageStorageAccount", "productionSite"},
        "network source projections",
    )
    for name in topology_source:
        item = topology.get(name)
        if not isinstance(item, Mapping) or sha256_hex(topology_source[name]) != item.get(
            "projectionSha256"
        ):
            fail(f"network source projection does not bind {name}")


def _validate_source_evidence(
    value: Any,
    *,
    authorization: Mapping[str, Any],
    context: Mapping[str, Any],
    plan: Mapping[str, Any],
    provisioning: Mapping[str, Any],
    runtime_receipt: Mapping[str, Any],
    components: Mapping[str, Mapping[str, Any]],
    authorized_preflight_projection: Mapping[str, Any],
    package_bytes: bytes | bytearray,
    started_at: dt.datetime,
    completed_at: dt.datetime,
) -> tuple[dict[str, Any], dict[str, Any]]:
    source = _exact_keys(value, SOURCE_EVIDENCE_KEYS, "sourceEvidence")
    if (
        source["schemaVersion"] != 1
        or source["evidenceType"]
        != "paperdesk-private-release-v2-bootstrap-source-evidence-v1"
        or source["authorizationId"] != context["authorizationId"]
        or source["authorizationSha256"] != context["authorizationSha256"]
        or source["mergedSourceSha"] != context["mergedMainSha"]
        or source["treeSha"] != context["treeSha"]
        or source["planSha256"] != context["planSha256"]
    ):
        fail("source evidence identity or source binding is invalid")
    if not isinstance(authorized_preflight_projection, Mapping):
        fail("exact in-memory authorized preflight projection is mandatory")
    if sha256_hex(authorized_preflight_projection) != context["preflightSha256"]:
        fail("in-memory preflight projection is not authorization-bound")
    sanitized_preflight_projection = _canonical_projection(
        source["authorizedPreflightProjection"],
        "sanitized authorized preflight projection",
    )
    bootstrap_source = _load_bootstrap_source()
    validator = getattr(bootstrap_source, "validate_terminal_source_evidence", None)
    if not callable(validator):
        fail("the source-owned bootstrap evidence validator is unavailable")
    try:
        source_validated = validator(
            plan=plan,
            authorization=authorization,
            preflight_projection=authorized_preflight_projection,
            evidence=source,
        )
    except Exception as exc:
        if isinstance(exc, BootstrapReceiptError):
            raise
        raise BootstrapReceiptError(
            f"source-owned terminal evidence is invalid: {exc}"
        ) from exc
    if source_validated != source:
        fail("source-owned terminal evidence validator changed the supplied evidence")
    if source_validated["authorizedPreflightProjection"] != sanitized_preflight_projection:
        fail("source-owned validator did not bind the sanitized preflight projection")
    operation_entries = _source_operation_universe(
        source["allOperationProjections"],
        plan=plan,
        started_at=started_at,
        completed_at=completed_at,
    )
    operation_sources = {
        operation_id: entry["sourceProjection"]
        for operation_id, entry in operation_entries.items()
    }
    operation_contexts = _authorized_operation_contexts(
        authorized_preflight_projection,
        operation_ids=set(operation_entries),
    )
    _validate_postcondition_execution_window(
        source["postconditionProjections"],
        plan=plan,
        started_at=started_at,
        completed_at=completed_at,
    )
    claim = _validate_claim_receipt(
        source["claimReceipt"],
        context,
        started_at=started_at,
        completed_at=completed_at,
    )
    permanent = _validate_permanent_source_projections(
        source["permanentMutationProjections"],
        context,
        plan,
        started_at=started_at,
        completed_at=completed_at,
    )

    package_projection = _exact_keys(
        _canonical_projection(
            source["packageReadbackProjection"], "package readback source projection"
        ),
        {
            "blobName",
            "versionId",
            "etag",
            "httpStatus",
            "bytesObservedInMemory",
            "bytesSha256",
            "size",
            "metadataSha256",
            "observedAt",
        },
        "package readback source projection",
    )
    package_component = components["packageReadback"]
    if not isinstance(package_bytes, (bytes, bytearray)):
        fail("exact in-memory package readback bytes are mandatory")
    observed_package_bytes = bytes(package_bytes)
    if (
        sha256_hex(observed_package_bytes) != context["packageSha256"]
        or len(observed_package_bytes) != context["packageSize"]
    ):
        fail("in-memory package readback bytes do not match the authorized package")
    if (
        package_projection["blobName"] != package_component["blobName"]
        or package_projection["versionId"] != package_component["versionId"]
        or package_projection["etag"] != package_component["etag"]
        or package_projection["httpStatus"] != 200
        or package_projection["bytesObservedInMemory"] is not True
        or package_projection["bytesSha256"] != context["packageSha256"]
        or package_projection["size"] != context["packageSize"]
        or package_projection["metadataSha256"] != context["packageSha256"]
    ):
        fail("package source projection is not an exact in-memory version readback")

    managed_projection = _canonical_projection(
        source["managedIdentityFetchResponseProjection"],
        "managed-identity fetch response projection",
    )
    managed = components["managedIdentityFetchSelfTest"]
    expected_managed = {
        key: managed[key]
        for key in (
            "evidenceMode",
            "directPackageBytesObservedByExecutor",
            "identityResourceId",
            "identityClientId",
            "identityPrincipalId",
            "authentication",
            "packageBlobName",
            "packageVersionId",
            "expectedPackageSha256",
            "expectedPackageSize",
            "sourceControlSha256",
            "webJobInvocationId",
            "terminalStatus",
            "observedAt",
        )
    }
    if managed_projection != expected_managed:
        fail("managed-identity response projection is not source-exact")
    runtime_package = runtime_receipt.get("package")
    if not isinstance(runtime_package, Mapping) or (
        runtime_package.get("sha256") != context["packageSha256"]
        or runtime_package.get("size") != context["packageSize"]
        or runtime_package.get("blob") != package_component["blobName"]
        or runtime_package.get("versionId") != package_component["versionId"]
        or runtime_package.get("etag") != package_component["etag"]
    ):
        fail("rich runtime package proof is not bound to exact in-memory bytes")

    bridge_proof = _exact_keys(
        source["bridgeCanaryProof"],
        {"webJobTerminal", "sourceDerivedExpectedMarker"},
        "bridge canary source proof",
    )
    webjob = _exact_keys(
        _canonical_projection(
            bridge_proof["webJobTerminal"], "bridge WebJob terminal projection"
        ),
        {
            "status",
            "invocationId",
            "sourceSha",
            "packageSha256",
            "packageVersionId",
            "startedAt",
            "completedAt",
        },
        "bridge WebJob terminal projection",
    )
    if (
        webjob["status"] != "Success"
        or webjob["sourceSha"] != context["mergedMainSha"]
        or webjob["packageSha256"] != context["packageSha256"]
        or webjob["packageVersionId"] != package_component["versionId"]
        or managed_projection["webJobInvocationId"] != webjob["invocationId"]
        or managed_projection["terminalStatus"] != webjob["status"]
    ):
        fail("bridge WebJob terminal proof is not source/package pinned")
    webjob_started = _timestamp(webjob["startedAt"], "bridge WebJob startedAt")
    webjob_completed = _timestamp(webjob["completedAt"], "bridge WebJob completedAt")
    if (
        not _string(webjob["invocationId"], "bridge WebJob invocation ID")
        or webjob_started < started_at
        or webjob_completed < webjob_started
        or webjob_completed > completed_at
    ):
        fail("bridge WebJob terminal time window is invalid")
    expected_marker = _canonical_projection(
        bridge_proof["sourceDerivedExpectedMarker"],
        "source-derived expected bridge marker",
    )
    expected_marker_contract = {
        "schemaVersion": 1,
        "evidenceType": (
            "paperdesk-private-release-v2-source-derived-bridge-canary-"
            "expectation-v1"
        ),
        "observationStatus": "expected-not-observed",
        "authorizationId": context["authorizationId"],
        "sourceSha": context["mergedMainSha"],
        "packageSha256": context["packageSha256"],
        "packageVersionId": package_component["versionId"],
        "bridgeResourceId": _resource(plan, "bridgeSite")["resourceId"],
        "bridgeIdentityResourceId": _resource(plan, "bridgeIdentity")[
            "resourceId"
        ],
        "activationFenceBlobResourceId": _resource(plan, "activationFenceBlob")[
            "resourceId"
        ],
        "expectedTerminalStatus": "Success",
        "literalStdoutMarkerObserved": False,
        "httpHealthObserved": False,
    }
    if expected_marker != expected_marker_contract:
        fail("bridge expected-marker projection is not source-derived and exact")

    lease_sources = _exact_keys(
        source["leaseCanaryProofs"],
        {
            "controllerLease",
            "activationFenceLease",
            "cleanupFastLane",
            "cleanupExpiryFallback",
        },
        "lease canary source proofs",
    )
    lease_component = components["leaseCanaryEvidence"]
    controller_source = _validate_lease_source_proof(
        lease_sources["controllerLease"],
        "controller lease source proof",
        component_lease=lease_component["controllerLease"],
        started_at=started_at,
        completed_at=completed_at,
    )
    activation_source = _validate_activation_lease_source_proof(
        lease_sources["activationFenceLease"],
        component_lease=lease_component["activationFenceLease"],
        webjob_terminal=webjob,
        expected_marker_sha256=sha256_hex(expected_marker),
        context=context,
        plan=plan,
        started_at=started_at,
        completed_at=completed_at,
    )
    roles = provisioning.get("roles")
    if not isinstance(roles, Mapping):
        fail("rich provisioning evidence lacks identity role proofs")
    bridge_fence_role = roles.get("bridgeActivationFence")
    reader_role = roles.get("readerPackageRead")
    activation_actor = activation_source.get("actor")
    if (
        not isinstance(bridge_fence_role, Mapping)
        or not isinstance(reader_role, Mapping)
        or not isinstance(activation_actor, Mapping)
        or activation_actor.get("actorObjectId")
        != bridge_fence_role.get("principalId")
        or activation_actor.get("actorResourceId")
        != bridge_fence_role.get("identityResourceId")
        or managed_projection.get("identityResourceId")
        != reader_role.get("identityResourceId")
        or managed_projection.get("identityClientId")
        != reader_role.get("identityClientId")
        or managed_projection.get("identityPrincipalId")
        != reader_role.get("principalId")
    ):
        fail("S2 lease or managed-identity evidence is not identity-bound")
    fast_source = _source_bound_lease_component(
        lease_sources["cleanupFastLane"],
        "cleanup fast-lane source proof",
        component_lease=lease_component["cleanupFastLane"],
        required_keys={
            "observationStatus",
            "controllerOperationSourceProjectionSha256",
            "stateTransitions",
            "observedAt",
        },
    )
    fallback_source = _source_bound_lease_component(
        lease_sources["cleanupExpiryFallback"],
        "cleanup expiry-fallback source proof",
        component_lease=lease_component["cleanupExpiryFallback"],
        required_keys={
            "observationStatus",
            "controllerOperationSourceProjectionSha256",
            "deadlineSeconds",
            "stateTransitions",
            "observedAt",
        },
    )
    for item, label in (
        (fast_source, "cleanup fast-lane source proof"),
        (fallback_source, "cleanup expiry-fallback source proof"),
    ):
        if not isinstance(item["stateTransitions"], Mapping) or not item[
            "stateTransitions"
        ]:
            fail(f"{label} lacks canonical state transitions")
        _observation_in_window(
            item["observedAt"],
            f"{label}.observedAt",
            started_at=started_at,
            completed_at=completed_at,
        )

    cleanup = _exact_keys(
        _canonical_projection(
            source["cleanupAbsenceProjections"], "cleanup absence projections"
        ),
        {
            "packageIpv4Rule",
            "packageUploaderRole",
            "operatorKeyReadRole",
            "operatorFenceRole",
            "operatorControllerRole",
        },
        "cleanup absence projections",
    )
    for name, projection in cleanup.items():
        body = _exact_keys(
            projection,
            {"httpStatus", "present", "sanitizedProjection", "observedAt"},
            f"cleanup absence projection {name}",
        )
        if body["httpStatus"] not in {200, 404} or body["present"] is not False:
            fail(f"cleanup absence projection {name} does not prove absence")
        _canonical_projection(
            body["sanitizedProjection"],
            f"cleanup absence projection {name}.sanitizedProjection",
        )
        _observation_in_window(
            body["observedAt"],
            f"cleanup absence projection {name}.observedAt",
            started_at=started_at,
            completed_at=completed_at,
        )

    worm_sources = _exact_keys(
        _canonical_projection(source["wormSourceProjections"], "WORM source projections"),
        {"acceptedReleases", "webJobResults", "deploymentPackages"},
        "WORM source projections",
    )
    for name, projection in worm_sources.items():
        pair = _exact_keys(
            projection,
            {"container", "policy"},
            f"WORM source projection {name}",
        )
        _canonical_projection(pair["container"], f"WORM {name} container projection")
        _canonical_projection(pair["policy"], f"WORM {name} policy projection")

    _validate_rich_source_projections(
        source["richProvisioningSourceProjections"], provisioning, context, plan
    )
    production_boundary, production_sha, mutation_journal = _validate_production_boundary(
        source["productionBoundary"],
        context=context,
        plan=plan,
        authorization=authorization,
        operation_projections=operation_sources,
        operation_contexts=operation_contexts,
        bootstrap_source=bootstrap_source,
        started_at=started_at,
        completed_at=completed_at,
    )
    _observation_in_window(
        source["observedAt"],
        "sourceEvidence.observedAt",
        started_at=started_at,
        completed_at=completed_at,
    )
    if _timestamp(source["observedAt"], "sourceEvidence.observedAt") != completed_at:
        fail("terminal source observation does not end the execution window")
    _reject_secret_material(source, "sourceEvidence")

    permanent_plan = {
        item["id"]: item for item in _expected_permanent_mutations(plan)
    }
    permanent_components: dict[str, dict[str, Any]] = {}
    for mutation_id, item in permanent.items():
        mutation = permanent_plan[mutation_id]
        permanent_components[mutation_id] = {
            "mutationId": mutation_id,
            "target": item["target"],
            "kind": item["kind"],
            "irreversible": mutation["irreversible"],
            "outcome": item["outcome"],
            "evidenceSha256": sha256_hex(item["sourceProjection"]),
            "observedAt": item["observedAt"],
        }

    initial = context["model"]["initialActivationFenceDocument"]
    initial_bytes = canonical_json_bytes(initial)
    initial_sha = sha256_hex(initial_bytes)
    fence_operation = operation_sources["createInitialIdleActivationFence"]
    fence_projection = fence_operation.get("projection")
    fence_headers = fence_operation.get("headers")
    if not isinstance(fence_projection, Mapping) or not isinstance(
        fence_headers, Mapping
    ):
        fail("activation fence operation source is incomplete")
    fence_fields = {
        "containerResourceId": _resource(plan, "activationFenceContainer")[
            "resourceId"
        ],
        "blobResourceId": _resource(plan, "activationFenceBlob")["resourceId"],
        "blobName": _resource(plan, "activationFenceBlob")["name"],
        "canonicalInitialDocument": initial,
        "initialBodySha256": initial_sha,
        "size": len(initial_bytes),
        **_journal_bound_create_or_adopt_fields(
            operation_id="createInitialIdleActivationFence",
            permanent=permanent,
            journal=mutation_journal,
            operation_source=fence_operation,
        ),
        "etag": fence_projection.get("etag"),
        "versionId": fence_projection.get("versionId"),
        "metadataSha256": initial_sha,
        "readbackSha256": fence_projection.get("sha256"),
        "readbackHttpStatus": fence_operation.get("status"),
        "leaseState": fence_headers.get("leaseState"),
        "leaseStatus": fence_headers.get("leaseStatus"),
        "observedAt": permanent["createInitialIdleActivationFence"]["observedAt"],
    }

    upload_operation = operation_sources["uploadVersionedBridgePackage"]
    upload_projection = upload_operation.get("projection")
    if not isinstance(upload_projection, Mapping):
        fail("package upload operation source is incomplete")
    package_version_id = _string(
        upload_projection.get("versionId"), "package upload source version ID"
    )
    package_upload_url = _string(
        upload_projection.get("url"), "package upload source URL"
    )
    package_fields = {
        "containerResourceId": _resource(plan, "packageContainer")["resourceId"],
        "blobName": package_projection["blobName"],
        "packageSha256": context["packageSha256"],
        "size": context["packageSize"],
        **_journal_bound_create_or_adopt_fields(
            operation_id="uploadVersionedBridgePackage",
            permanent=permanent,
            journal=mutation_journal,
            operation_source=upload_operation,
        ),
        "etag": package_projection["etag"],
        "versionId": package_projection["versionId"],
        "versionedUrl": package_upload_url
        + "?versionid="
        + urllib.parse.quote(package_version_id, safe=""),
        "metadataSha256": package_projection["metadataSha256"],
        "readbackSha256": package_projection["bytesSha256"],
        "readbackSize": package_projection["size"],
        "readbackHttpStatus": package_projection["httpStatus"],
        "observedAt": package_projection["observedAt"],
    }

    configure_projection = operation_sources[
        "configureBridgeExactVersionedPackageAndCriticalSettings"
    ].get("projection")
    canary_projection = operation_sources["startBridgeForBoundedCanary"].get(
        "projection"
    )
    if not isinstance(configure_projection, Mapping) or not isinstance(
        canary_projection, Mapping
    ):
        fail("bridge configure or canary operation source is incomplete")
    stopped = canary_projection.get("stopped")
    if not isinstance(stopped, Mapping):
        fail("bridge canary source lacks the final stopped projection")
    bridge_fields = {
        "bridgeResourceId": _resource(plan, "bridgeSite")["resourceId"],
        "finalState": stopped.get("state"),
        "settings": {
            "beforeSha256": configure_projection.get("preAppSettingsSha256"),
            "desiredSha256": configure_projection.get("settingsSha256"),
            "afterSha256": configure_projection.get("settingsSha256"),
            "fullMapReadbackExact": True,
        },
        "observedAt": source["observedAt"],
    }

    worm_operation_ids = {
        "acceptedReleases": "extendAcceptedRetentionFrom30To91Days",
        "webJobResults": "extendResultRetentionFrom30To91Days",
        "deploymentPackages": "lockPackageRetentionAt91Days",
    }
    worm_components: dict[str, dict[str, Any]] = {}
    for name, pair in worm_sources.items():
        policy = pair["policy"]
        properties = policy["properties"]
        operation_id = worm_operation_ids[name]
        worm_components[name] = {
            "container": sha256_hex(pair["container"]),
            "policy": sha256_hex(policy),
            "containerResourceId": pair["container"]["id"],
            "policyResourceId": policy["id"],
            "publicAccess": pair["container"]["publicAccess"],
            "state": properties["state"],
            "retentionDays": properties[
                "immutabilityPeriodSinceCreationInDays"
            ],
            "allowProtectedAppendWrites": properties[
                "allowProtectedAppendWrites"
            ],
            "allowProtectedAppendWritesAll": properties[
                "allowProtectedAppendWritesAll"
            ],
            "etag": policy["etag"],
            "containerProjectionSha256": sha256_hex(pair["container"]),
            "policyProjectionSha256": sha256_hex(policy),
            "observedAt": permanent[operation_id]["observedAt"],
        }
    derived = {
        "claimReceiptSha256": sha256_hex(claim),
        "permanentMutationSha256": {
            mutation_id: sha256_hex(item["sourceProjection"])
            for mutation_id, item in permanent.items()
        },
        "permanentMutationEntries": permanent_components,
        "packageReadbackProjectionSha256": sha256_hex(package_projection),
        "packageReadbackFields": package_fields,
        "activationFenceFields": fence_fields,
        "managedIdentityFetchResponseProjectionSha256": sha256_hex(
            managed_projection
        ),
        "sourceDerivedExpectedMarkerSha256": sha256_hex(expected_marker),
        "webJobTerminalProjectionSha256": sha256_hex(webjob),
        "leaseSourceSha256": {
            "controllerLease": sha256_hex(controller_source),
            "activationFenceLease": sha256_hex(activation_source),
            "cleanupFastLane": sha256_hex(fast_source),
            "cleanupExpiryFallback": sha256_hex(fallback_source),
        },
        "cleanupAbsenceSha256": {
            name: sha256_hex(item) for name, item in cleanup.items()
        },
        "wormSourceSha256": worm_components,
        "bridgeFields": bridge_fields,
        "productionBoundarySha256": production_sha,
        "terminalObservedAt": source["observedAt"],
    }
    return dict(source), derived


def build_s2_evidence_files(
    *,
    authorization: Mapping[str, Any],
    plan: Mapping[str, Any],
    provisioning_evidence: Mapping[str, Any],
    bridge_runtime_receipt: Mapping[str, Any],
    temporary_cleanup_receipt: Mapping[str, Any],
    activation_fence_receipt: Mapping[str, Any],
    bridge_canary_receipt: Mapping[str, Any],
) -> dict[str, bytes]:
    """Validate and return the five create-only canonical S2 file bodies."""

    context = _context(authorization, plan)
    model_paths = list(context["model"]["requiredS2EvidencePaths"])
    if list(S2_EVIDENCE_COMPONENT_PATHS.values()) != model_paths:
        fail("S2 evidence path mapping does not match the reviewed evidence model")

    cleanup = _canonical_document(
        temporary_cleanup_receipt, "temporary-access cleanup S2 receipt"
    )
    fence = _canonical_document(
        activation_fence_receipt, "activation-fence S2 receipt"
    )
    bridge = _canonical_document(bridge_canary_receipt, "bridge-canary S2 receipt")
    started_at = context["notBefore"]
    completed_at = context["expiresAt"]
    _validate_temporary_cleanup(
        cleanup,
        context,
        plan,
        started_at=started_at,
        completed_at=completed_at,
    )
    _validate_activation_fence(
        fence,
        context,
        plan,
        started_at=started_at,
        completed_at=completed_at,
    )
    _validate_bridge_evidence(
        bridge,
        context,
        plan,
        started_at=started_at,
        completed_at=completed_at,
    )
    if fence["temporaryAccessCleanupSha256"] != sha256_hex(cleanup):
        fail("S2 activation-fence receipt does not bind cleanup evidence")

    rich_provisioning, rich_runtime = _validate_rich_mailbox_s2_documents(
        authorization=authorization,
        plan=plan,
        provisioning_evidence=provisioning_evidence,
        bridge_runtime_receipt=bridge_runtime_receipt,
        activation_fence_receipt=fence,
    )
    roles = rich_provisioning["roles"]
    activation_lease = None
    # The lease evidence itself is included in the complete component universe;
    # here the rich provisioning proof binds the bridge identity used by it.
    if isinstance(roles, Mapping):
        activation_lease = roles.get("bridgeActivationFence")
    if not isinstance(activation_lease, Mapping):
        fail("rich provisioning evidence lacks the bridge fence identity")

    documents = {
        S2_EVIDENCE_COMPONENT_PATHS["provisioningEvidence"]: rich_provisioning,
        S2_EVIDENCE_COMPONENT_PATHS["bridgeRuntimeReceipt"]: rich_runtime,
        S2_EVIDENCE_COMPONENT_PATHS["temporaryAccessCleanup"]: cleanup,
        S2_EVIDENCE_COMPONENT_PATHS["activationFenceBootstrap"]: fence,
        S2_EVIDENCE_COMPONENT_PATHS["bridgeEvidence"]: bridge,
    }
    return {path: canonical_json_bytes(documents[path]) for path in model_paths}


def _canonical_s2_document_map(
    s2_documents: Mapping[str, bytes | bytearray | Mapping[str, Any]],
    expected_paths: list[str],
    *,
    require_bytes: bool = False,
) -> dict[str, dict[str, Any]]:
    if not isinstance(s2_documents, Mapping) or set(s2_documents) != set(expected_paths):
        fail("S2 document set is incomplete or contains an unknown path")
    result: dict[str, dict[str, Any]] = {}
    for path in expected_paths:
        value = s2_documents[path]
        if isinstance(value, (bytes, bytearray)):
            document = load_canonical_json_bytes(
                value, label=f"S2 document {path}"
            )
        elif isinstance(value, Mapping) and not require_bytes:
            document = _canonical_document(value, f"S2 document {path}")
        else:
            expected = "canonical bytes" if require_bytes else "canonical bytes or an object"
            fail(f"S2 document {path} must be {expected}")
        if not isinstance(document, Mapping):
            fail(f"S2 document {path} must contain an object")
        result[path] = dict(document)
    return result




def _bind_source_derived_component_fields(
    components: Mapping[str, Mapping[str, Any]],
    derived: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    """Bind every duplicated digest to its validated full canonical source body."""

    bound = copy.deepcopy(dict(components))
    permanent_by_id = _exact_keys(
        derived.get("permanentMutationSha256"),
        {entry["mutationId"] for entry in bound["permanentMutationLedger"]["entries"]},
        "derived permanent mutation digests",
    )
    permanent_entries = _exact_keys(
        derived.get("permanentMutationEntries"),
        set(permanent_by_id),
        "derived permanent mutation entries",
    )
    for entry in bound["permanentMutationLedger"]["entries"]:
        mutation_id = entry["mutationId"]
        expected = copy.deepcopy(dict(permanent_entries[mutation_id]))
        expected["evidenceSha256"] = permanent_by_id[mutation_id]
        entry.clear()
        entry.update(expected)

    cleanup = _exact_keys(
        derived.get("cleanupAbsenceSha256"),
        {
            "packageIpv4Rule",
            "packageUploaderRole",
            "operatorKeyReadRole",
            "operatorFenceRole",
            "operatorControllerRole",
        },
        "derived cleanup absence digests",
    )
    for name in cleanup:
        bound["temporaryAccessCleanup"][name]["freshReadbackSha256"] = cleanup[
            name
        ]

    for component_name, derived_name in (
        ("activationFenceBootstrap", "activationFenceFields"),
        ("packageReadback", "packageReadbackFields"),
    ):
        fields = derived.get(derived_name)
        if not isinstance(fields, Mapping):
            fail(f"derived {component_name} fields are unavailable")
        for key, value in fields.items():
            bound[component_name][key] = copy.deepcopy(value)

    bound["managedIdentityFetchSelfTest"]["responseProjectionSha256"] = _hash(
        derived.get("managedIdentityFetchResponseProjectionSha256"),
        "derived managed-identity response projection",
    )
    bridge = bound["bridgeEvidence"]
    bridge_fields = derived.get("bridgeFields")
    if not isinstance(bridge_fields, Mapping):
        fail("derived bridge fields are unavailable")
    for key, value in bridge_fields.items():
        bridge[key] = copy.deepcopy(value)
    bridge["webJobTerminalProjectionSha256"] = _hash(
        derived.get("webJobTerminalProjectionSha256"),
        "derived WebJob terminal projection",
    )
    bridge["sourceDerivedExpectedMarkerSha256"] = _hash(
        derived.get("sourceDerivedExpectedMarkerSha256"),
        "derived expected bridge marker",
    )
    bridge["productionBoundarySha256"] = _hash(
        derived.get("productionBoundarySha256"),
        "derived production boundary",
    )
    terminal_observed_at = _string(
        derived.get("terminalObservedAt"), "derived terminal observation time"
    )
    for component_name in (
        "permanentMutationLedger",
        "temporaryAccessCleanup",
        "bridgeEvidence",
        "leaseCanaryEvidence",
        "wormProjections",
    ):
        bound[component_name]["observedAt"] = terminal_observed_at

    lease = _exact_keys(
        derived.get("leaseSourceSha256"),
        {
            "controllerLease",
            "activationFenceLease",
            "cleanupFastLane",
            "cleanupExpiryFallback",
        },
        "derived lease evidence digests",
    )
    lease_component = bound["leaseCanaryEvidence"]
    lease_component["controllerLease"]["evidenceSha256"] = lease[
        "controllerLease"
    ]
    lease_component["activationFenceLease"]["evidenceSha256"] = lease[
        "activationFenceLease"
    ]
    lease_component["cleanupFastLane"]["evidenceSha256"] = lease[
        "cleanupFastLane"
    ]
    lease_component["cleanupExpiryFallback"]["evidenceSha256"] = lease[
        "cleanupExpiryFallback"
    ]

    worm = _exact_keys(
        derived.get("wormSourceSha256"),
        {"acceptedReleases", "webJobResults", "deploymentPackages"},
        "derived WORM source digests",
    )
    for name, source_hashes in worm.items():
        item = _exact_keys(
            source_hashes,
            {
                "container",
                "policy",
                "containerResourceId",
                "policyResourceId",
                "publicAccess",
                "state",
                "retentionDays",
                "allowProtectedAppendWrites",
                "allowProtectedAppendWritesAll",
                "etag",
                "containerProjectionSha256",
                "policyProjectionSha256",
                "observedAt",
            },
            f"derived WORM {name}",
        )
        target = bound["wormProjections"]["containers"][name]
        target.pop("projectionSha256", None)
        for key, value in item.items():
            if key not in {"container", "policy"}:
                target[key] = copy.deepcopy(value)
        target["containerProjectionSha256"] = item["container"]
        target["policyProjectionSha256"] = item["policy"]

    # Derive all inter-component bindings after source-derived fields are final.
    temporary_sha = sha256_hex(bound["temporaryAccessCleanup"])
    bound["activationFenceBootstrap"]["temporaryAccessCleanupSha256"] = temporary_sha
    package_sha = sha256_hex(bound["packageReadback"])
    bound["managedIdentityFetchSelfTest"]["packageReadbackSha256"] = package_sha
    fence_sha = sha256_hex(bound["activationFenceBootstrap"])
    lease_component["temporaryAccessCleanupSha256"] = temporary_sha
    lease_component["activationFenceBootstrapSha256"] = fence_sha
    managed_sha = sha256_hex(bound["managedIdentityFetchSelfTest"])
    lease_sha = sha256_hex(lease_component)
    bridge["packageReadbackSha256"] = package_sha
    bridge["managedIdentityFetchSelfTestSha256"] = managed_sha
    bridge["leaseCanaryEvidenceSha256"] = lease_sha

    return {
        name: _build_component(name, bound[name])
        for name in (set(COMPONENT_DIGEST_KEYS) - {"s2OutputMetadata"})
    }


def _assemble_validated_execution_receipt(
    *,
    authorization: Mapping[str, Any],
    plan: Mapping[str, Any],
    context: Mapping[str, Any],
    components: Mapping[str, Mapping[str, Any]],
    source_evidence: Mapping[str, Any],
    derived_evidence: Mapping[str, Any],
    evidence_file_digests: Mapping[str, str],
    started_at: str,
    completed_at: str,
) -> dict[str, Any]:
    receipt = {
        "schemaVersion": 1,
        "receiptType": context["model"]["receiptTypes"]["executionReceipt"],
        "status": "succeeded-terminal",
        "authorizationId": context["authorizationId"],
        "authorizationSha256": context["authorizationSha256"],
        "source": {
            "reviewedHeadSha": context["reviewedHeadSha"],
            "mergedMainSha": context["mergedMainSha"],
            "treeSha": context["treeSha"],
        },
        "executor": {
            "path": context["executorPath"],
            "sha256": context["executorSha256"],
        },
        "plan": {
            "path": context["planPath"],
            "sha256": context["planSha256"],
            "document": copy.deepcopy(dict(plan)),
        },
        "package": {
            "sha256": context["packageSha256"],
            "size": context["packageSize"],
        },
        "azure": {
            "cloud": "AzureCloud",
            "subscriptionId": context["subscriptionId"],
            "tenantId": context["tenantId"],
            "operatorObjectId": context["operatorObjectId"],
            "operatorAccountIdSha256": context["operatorAccountIdSha256"],
            "operatorAccountType": context["operatorAccountType"],
        },
        "observedPreflightSha256": context["preflightSha256"],
        "singleUse": {
            "status": "consumed-terminal",
            "azureClaimResourceId": context["azureClaimResourceId"],
            "claimReceiptSha256": derived_evidence["claimReceiptSha256"],
            "claimedAt": started_at,
            "terminalAt": completed_at,
            "retryable": False,
        },
        "startedAt": started_at,
        "completedAt": completed_at,
        "mutationIds": list(context["mutationIds"]),
        "irreversibleMutationIds": list(context["irreversibleMutationIds"]),
        "componentDigests": {
            name: sha256_hex(components[name]) for name in COMPONENT_DIGEST_KEYS
        },
        "evidenceFileDigests": dict(evidence_file_digests),
        "s2EvidenceSetSha256": components["s2OutputMetadata"][
            "evidenceSetSha256"
        ],
        "productionBoundarySha256": derived_evidence[
            "productionBoundarySha256"
        ],
        "productionMutationCount": 0,
        "sourceEvidence": copy.deepcopy(dict(source_evidence)),
        "failures": [],
        "pendingHousekeeping": [],
    }
    return _build_component("executionReceipt", receipt)


def build_complete_receipt_bundle(
    *,
    authorization: Mapping[str, Any],
    plan: Mapping[str, Any],
    components: Mapping[str, Mapping[str, Any]],
    s2_documents: Mapping[str, bytes | bytearray],
    source_evidence: Mapping[str, Any],
    authorized_preflight_projection: Mapping[str, Any],
    package_bytes: bytes | bytearray,
    started_at: str,
    completed_at: str,
    now: dt.datetime | str | None,
) -> dict[str, Any]:
    """Build one terminal bundle only from full source-owned canonical proof."""

    trusted_now = _now(now)
    context = _context(authorization, plan)
    started = _timestamp(started_at, "execution startedAt")
    completed = _timestamp(completed_at, "execution completedAt")
    base_names = set(COMPONENT_DIGEST_KEYS) - {"s2OutputMetadata"}
    if not isinstance(components, Mapping) or set(components) != base_names:
        fail("complete receipt assembly requires every observed component exactly once")
    preliminary = {
        name: _build_component(name, components[name]) for name in base_names
    }

    expected_paths = list(context["model"]["requiredS2EvidencePaths"])
    decoded_s2 = _canonical_s2_document_map(
        s2_documents, expected_paths, require_bytes=True
    )
    canonical_s2 = build_s2_evidence_files(
        authorization=authorization,
        plan=plan,
        provisioning_evidence=decoded_s2[
            S2_EVIDENCE_COMPONENT_PATHS["provisioningEvidence"]
        ],
        bridge_runtime_receipt=decoded_s2[
            S2_EVIDENCE_COMPONENT_PATHS["bridgeRuntimeReceipt"]
        ],
        temporary_cleanup_receipt=decoded_s2[
            S2_EVIDENCE_COMPONENT_PATHS["temporaryAccessCleanup"]
        ],
        activation_fence_receipt=decoded_s2[
            S2_EVIDENCE_COMPONENT_PATHS["activationFenceBootstrap"]
        ],
        bridge_canary_receipt=decoded_s2[
            S2_EVIDENCE_COMPONENT_PATHS["bridgeEvidence"]
        ],
    )
    if {path: bytes(s2_documents[path]) for path in expected_paths} != canonical_s2:
        fail("complete receipt assembly requires exact canonical five-file bodies")

    source, derived = _validate_source_evidence(
        source_evidence,
        authorization=authorization,
        context=context,
        plan=plan,
        provisioning=decoded_s2[
            S2_EVIDENCE_COMPONENT_PATHS["provisioningEvidence"]
        ],
        runtime_receipt=decoded_s2[
            S2_EVIDENCE_COMPONENT_PATHS["bridgeRuntimeReceipt"]
        ],
        components=preliminary,
        authorized_preflight_projection=authorized_preflight_projection,
        package_bytes=package_bytes,
        started_at=started,
        completed_at=completed,
    )
    bound = _bind_source_derived_component_fields(preliminary, derived)
    for component_name in (
        "temporaryAccessCleanup",
        "activationFenceBootstrap",
        "bridgeEvidence",
    ):
        path = S2_EVIDENCE_COMPONENT_PATHS[component_name]
        if decoded_s2[path] != bound[component_name]:
            fail(f"S2 file {path} does not match the source-derived component")

    files = [
        {
            "path": path,
            "sha256": sha256_hex(canonical_s2[path]),
            "size": len(canonical_s2[path]),
            "canonicalJson": True,
        }
        for path in expected_paths
    ]
    metadata = build_s2_output_metadata(
        schemaVersion=1,
        receiptType=context["model"]["receiptTypes"]["s2OutputMetadata"],
        status="ready-for-independent-review",
        authorizationId=context["authorizationId"],
        mergedSourceSha=context["mergedMainSha"],
        planSha256=context["planSha256"],
        evidenceOnly=True,
        sourceLogicChanged=False,
        resourcePolicyChanged=False,
        files=files,
        evidenceSetSha256=sha256_hex(files),
        generatedAt=completed_at,
    )
    all_components = {**bound, "s2OutputMetadata": metadata}
    file_digests, _ = _validate_non_execution_components(
        all_components,
        context,
        plan,
        started_at=started,
        completed_at=completed,
        derived_evidence=derived,
    )
    execution = _assemble_validated_execution_receipt(
        authorization=authorization,
        plan=plan,
        context=context,
        components=all_components,
        source_evidence=source,
        derived_evidence=derived,
        evidence_file_digests=file_digests,
        started_at=started_at,
        completed_at=completed_at,
    )
    bundle = {
        "schemaVersion": 1,
        "bundleType": context["model"]["bundleType"],
        "executionReceipt": execution,
        **all_components,
    }
    terminal_body = canonical_json_bytes(bundle)
    validated = validate_receipt_bundle(
        bundle,
        authorization=authorization,
        plan=plan,
        s2_documents=s2_documents,
        terminal_bundle_path=S2_TERMINAL_BUNDLE_PATH,
        terminal_bundle_body=terminal_body,
        authorized_preflight_projection=authorized_preflight_projection,
        package_bytes=package_bytes,
        now=trusted_now,
    )
    return {
        "bundle": validated,
        "s2EvidenceFiles": dict(canonical_s2),
        "s2TerminalBundle": {S2_TERMINAL_BUNDLE_PATH: terminal_body},
    }


def canonical_receipt_descriptor(
    path: str,
    document: Mapping[str, Any],
    *,
    observed_at: str,
) -> dict[str, Any]:
    """Describe one canonical nonsecret receipt without retaining its bytes."""

    normalized_path = _string(path, "receipt descriptor path")
    if (
        normalized_path.startswith(("/", "\\"))
        or "\\" in normalized_path
        or ".." in normalized_path.split("/")
    ):
        fail("receipt descriptor path is not repository-relative")
    body = canonical_json_bytes(document)
    descriptor = {
        "path": normalized_path,
        "sha256": hashlib.sha256(body).hexdigest(),
        "size": len(body),
        "status": _string(document.get("status"), "receipt descriptor status"),
        "observedAt": _string(observed_at, "receipt descriptor observedAt"),
    }
    _timestamp(descriptor["observedAt"], "receipt descriptor observedAt")
    _reject_secret_material(descriptor, "receipt descriptor")
    return descriptor


# Explicit aliases keep the executor vocabulary aligned with the envelope keys.
build_activation_fence_bootstrap = build_activation_fence_evidence
build_package_readback = build_package_readback_evidence
build_managed_identity_fetch_evidence = build_managed_identity_fetch_self_test
build_worm_projections = build_worm_projection




def build_execution_receipt(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
    """Reject standalone terminal construction; use the complete bundle builder."""

    fail(
        "standalone execution receipt construction is disabled; "
        "use build_complete_receipt_bundle with full canonical evidence"
    )


def build_receipt_bundle(
    *,
    execution_receipt: Mapping[str, Any],
    permanent_mutation_ledger: Mapping[str, Any],
    temporary_access_cleanup: Mapping[str, Any],
    activation_fence_bootstrap: Mapping[str, Any],
    package_readback: Mapping[str, Any],
    managed_identity_fetch_self_test: Mapping[str, Any],
    bridge_evidence: Mapping[str, Any],
    lease_canary_evidence: Mapping[str, Any],
    worm_projections: Mapping[str, Any],
    s2_output_metadata: Mapping[str, Any],
    authorization: Mapping[str, Any],
    plan: Mapping[str, Any],
    s2_documents: Mapping[str, bytes | bytearray],
    terminal_bundle_path: str,
    terminal_bundle_body: bytes | bytearray,
    authorized_preflight_projection: Mapping[str, Any],
    package_bytes: bytes | bytearray,
    now: dt.datetime | str | None,
) -> dict[str, Any]:
    bundle = {
        "schemaVersion": 1,
        "bundleType": load_model()["bundleType"],
        "executionReceipt": execution_receipt,
        "permanentMutationLedger": permanent_mutation_ledger,
        "temporaryAccessCleanup": temporary_access_cleanup,
        "activationFenceBootstrap": activation_fence_bootstrap,
        "packageReadback": package_readback,
        "managedIdentityFetchSelfTest": managed_identity_fetch_self_test,
        "bridgeEvidence": bridge_evidence,
        "leaseCanaryEvidence": lease_canary_evidence,
        "wormProjections": worm_projections,
        "s2OutputMetadata": s2_output_metadata,
    }
    return validate_receipt_bundle(
        bundle,
        authorization=authorization,
        plan=plan,
        s2_documents=s2_documents,
        terminal_bundle_path=terminal_bundle_path,
        terminal_bundle_body=terminal_bundle_body,
        authorized_preflight_projection=authorized_preflight_projection,
        package_bytes=package_bytes,
        now=now,
    )
