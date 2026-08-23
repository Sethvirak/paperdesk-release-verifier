#!/usr/bin/env python3
"""Exact transient-OIDC client for the dormant PaperDesk watchdog v2 provider.

The Actions runner may read state and submit one decision.  Azure WORM writes,
state CAS, GitHub App token minting, and workflow dispatch remain provider-owned.
No bearer token is written to disk or returned in a receipt.
"""

from __future__ import annotations

import argparse
import base64
from collections.abc import MutableMapping
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping
import urllib.error
import urllib.parse
import urllib.request


WATCHDOG_REPOSITORY = "Sethvirak/paperdesk-release-verifier"
WATCHDOG_REPOSITORY_ID = "1333353701"
WATCHDOG_REPOSITORY_OWNER = "Sethvirak"
WATCHDOG_REPOSITORY_OWNER_ID = "202535166"
SOURCE_REPOSITORY = "Sethvirak/MasterDataStructure"
SOURCE_REPOSITORY_ID = "1287744543"
WATCHDOG_ENVIRONMENT = "paperdesk-watchdog"
BASELINE_ENVIRONMENT = "paperdesk-watchdog-baseline"
RECONCILIATION_ENVIRONMENT = "paperdesk-watchdog-reconciliation"
WATCHDOG_WORKFLOW_REF = (
    f"{WATCHDOG_REPOSITORY}/.github/workflows/"
    "accepted-release-deadline-watchdog.yml@refs/heads/main"
)
BASELINE_WORKFLOW_REF = (
    f"{WATCHDOG_REPOSITORY}/.github/workflows/"
    "initialize-watchdog-rollback-baseline.yml@refs/heads/main"
)
RECONCILIATION_WORKFLOW_REF = (
    f"{WATCHDOG_REPOSITORY}/.github/workflows/"
    "reconcile-watchdog-dispatch.yml@refs/heads/main"
)
OIDC_AUDIENCE = "api://paperdesk-watchdog-evidence-v2"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
WATCHDOG_PROVIDER_HOST = "paperdesk-watchdog-state-9c4e0d0d.azurewebsites.net"
STATE_API_PATH = "/api/watchdog-state/v2"
STATE_API_URL = f"https://{WATCHDOG_PROVIDER_HOST}{STATE_API_PATH}"
BASELINE_API_PATH = "/api/watchdog-state/v2/initial-baseline"
BASELINE_API_URL = f"https://{WATCHDOG_PROVIDER_HOST}{BASELINE_API_PATH}"
CLAIM_API_PATH = "/api/watchdog-dispatch/v2/claim"
CLAIM_API_URL = f"https://{WATCHDOG_PROVIDER_HOST}{CLAIM_API_PATH}"
DISPATCH_API_PATH = "/api/watchdog-dispatch/v2"
DISPATCH_API_URL = f"https://{WATCHDOG_PROVIDER_HOST}{DISPATCH_API_PATH}"
RECONCILE_AUTO_API_PATH = "/api/watchdog-reconciliation/v2/automatic"
RECONCILE_AUTO_API_URL = f"https://{WATCHDOG_PROVIDER_HOST}{RECONCILE_AUTO_API_PATH}"
RECONCILE_MANUAL_API_PATH = "/api/watchdog-reconciliation/v2/manual"
RECONCILE_MANUAL_API_URL = f"https://{WATCHDOG_PROVIDER_HOST}{RECONCILE_MANUAL_API_PATH}"

EVIDENCE_ACCOUNT = "mdspdbak2608089c4e"
EVIDENCE_CONTAINER = "paperdesk-watchdog-evidence"
EVIDENCE_POLICY_DAYS = 90
REGISTRY_ACCOUNT = EVIDENCE_ACCOUNT
REGISTRY_CONTAINER = "paperdesk-accepted-releases"
REGISTRY_POLICY_DAYS = 30
STORAGE_RESOURCE_GROUP = "rg-paperdesk-rollback-sea-20260808"

MAX_RECEIPT_BYTES = 65536
MAX_OIDC_RESPONSE_BYTES = 65536
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
POSITIVE = re.compile(r"^[1-9][0-9]*$")
CANONICAL_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)
ETAG = re.compile(r'^"[^"\r\n]{1,240}"$')
REQUEST_ID = re.compile(r"^[A-Za-z0-9:._-]{1,128}$")
SAFE_VERSION_ID = re.compile(r"^[A-Za-z0-9:._%+-]{1,192}$")

POLICY_FIELDS = {
    "resourceId", "state", "immutabilityPeriodSinceCreationInDays",
    "allowProtectedAppendWrites", "allowProtectedAppendWritesAll", "etag", "observedAt",
}
SECURITY_POSTURE_FIELDS = {
    "schemaVersion", "storageAccountResourceId", "allowSharedKeyAccess",
    "allowBlobPublicAccess", "publicNetworkAccess", "containers", "assignments", "observedAt",
}
SECURITY_CONTAINER_FIELDS = {"resourceId", "publicAccess"}
SECURITY_ASSIGNMENT_FIELDS = {
    "role", "clientId", "principalId", "identityResourceId", "scope",
    "roleAssignmentId", "roleDefinitionId", "actions", "dataActions",
}
DECISION_FIELDS = {
    "schemaVersion", "receiptType", "decision", "sourceRepository", "candidateSha",
    "candidateRunId", "candidateRunAttempt", "expectedCurrentLiveSha", "watchdogRunId",
    "watchdogRunAttempt", "observedStateSha256", "decidedAt",
}
BASELINE_FIELDS = {
    "schemaVersion", "receiptSha256", "evidencePath", "sourceSha", "sourceRunId",
    "sourceRunAttempt", "acceptanceRunId", "acceptanceRunAttempt",
    "acceptedReleaseManifestSha256", "acceptedReleasePrefix", "reviewWorkflowRef",
    "reviewWorkflowSha", "reviewRunId", "reviewRunAttempt", "reviewEnvironment", "preparedAt",
}
CLAIM_RESPONSE_FIELDS = {
    "status", "claimId", "dispatchGuardGeneration", "decisionReceiptSha256",
    "decisionEvidenceETag",
}
DISPATCH_RESPONSE_FIELDS = {
    "status", "claimId", "dispatchGuardGeneration", "attemptReceiptSha256",
    "workflowRunId", "workflowRunApiUrl", "workflowRunHtmlUrl", "githubRequestId",
    "dispatchReceiptSha256", "dispatchEvidenceETag", "dispatchEvidenceVersionId",
}


class EvidenceError(RuntimeError):
    """A fail-closed local client-contract rejection."""


def fail(message: str) -> None:
    raise EvidenceError(message)


def canonical_json(document: Any) -> bytes:
    return (
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def canonical_timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or not CANONICAL_UTC.fullmatch(value):
        fail(f"{label} must be canonical millisecond UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        fail(f"{label} must be canonical millisecond UTC")
    if parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z") != value:
        fail(f"{label} must be canonical millisecond UTC")
    return value


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def positive(value: object, label: str) -> str:
    if not isinstance(value, str) or not POSITIVE.fullmatch(value):
        fail(f"{label} must be a positive integer string")
    return value


def full_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA40.fullmatch(value):
        fail(f"{label} must be a full lowercase commit SHA")
    return value


def digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        fail(f"{label} must be a lowercase SHA-256")
    return value


def regular_file(path: Path, label: str, maximum: int = MAX_RECEIPT_BYTES) -> tuple[bytes, Any]:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or not 2 <= metadata.st_size <= maximum
    ):
        fail(f"{label} must be one bounded regular non-link file")
    raw = path.read_bytes()
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"{label} is not valid UTF-8 JSON")
    if raw != canonical_json(document):
        fail(f"{label} must use exact canonical JSON bytes")
    return raw, document


def create_only(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(canonical_json(document))


def _fixed_provider_url(value: str, expected: str, path: str, label: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        fail(f"{label} is invalid")
    if (
        value != expected
        or parsed.scheme != "https"
        or parsed.netloc != WATCHDOG_PROVIDER_HOST
        or parsed.hostname != WATCHDOG_PROVIDER_HOST
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path != path
        or parsed.query
        or parsed.fragment
    ):
        fail(f"{label} must be the credential-free fixed dedicated provider API")
    return value


def validate_state_url(value: str) -> str:
    return _fixed_provider_url(value, STATE_API_URL, STATE_API_PATH, "watchdog state URL")


def validate_baseline_url(value: str) -> str:
    return _fixed_provider_url(value, BASELINE_API_URL, BASELINE_API_PATH, "watchdog baseline URL")


def validate_claim_url(value: str) -> str:
    return _fixed_provider_url(value, CLAIM_API_URL, CLAIM_API_PATH, "watchdog claim URL")


def validate_dispatch_url(value: str) -> str:
    return _fixed_provider_url(value, DISPATCH_API_URL, DISPATCH_API_PATH, "watchdog dispatch URL")


def validate_reconciliation_url(value: str, *, manual: bool) -> str:
    return _fixed_provider_url(
        value,
        RECONCILE_MANUAL_API_URL if manual else RECONCILE_AUTO_API_URL,
        RECONCILE_MANUAL_API_PATH if manual else RECONCILE_AUTO_API_PATH,
        "watchdog reconciliation URL",
    )


def validate_policy(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != POLICY_FIELDS:
        fail("watchdog WORM policy proof fields are not exact")
    resource_id = value.get("resourceId")
    suffix = (
        f"/resourceGroups/{STORAGE_RESOURCE_GROUP}/providers/Microsoft.Storage/"
        f"storageAccounts/{EVIDENCE_ACCOUNT}/blobServices/default/containers/"
        f"{EVIDENCE_CONTAINER}/immutabilityPolicies/default"
    ).lower()
    if (
        not isinstance(resource_id, str)
        or not re.fullmatch(r"/subscriptions/[0-9a-f-]{36}/resourceGroups/.+", resource_id, re.I)
        or not resource_id.lower().endswith(suffix)
    ):
        fail("watchdog WORM policy proof is not the separate evidence container")
    if any(value.get(name) != expected for name, expected in {
        "state": "Locked",
        "immutabilityPeriodSinceCreationInDays": EVIDENCE_POLICY_DAYS,
        "allowProtectedAppendWrites": False,
        "allowProtectedAppendWritesAll": False,
    }.items()):
        fail("watchdog WORM policy is not exact locked 90-day retention")
    if not isinstance(value.get("etag"), str) or not ETAG.fullmatch(value["etag"]):
        fail("watchdog WORM policy ETag is invalid")
    canonical_timestamp(value.get("observedAt"), "watchdog WORM policy observation")
    return dict(value)


def validate_security_posture(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != SECURITY_POSTURE_FIELDS or value.get("schemaVersion") != 2:
        fail("watchdog Azure security posture fields are not exact v2")
    account_id = value.get("storageAccountResourceId")
    suffix = (
        f"/resourceGroups/{STORAGE_RESOURCE_GROUP}/providers/Microsoft.Storage/"
        f"storageAccounts/{EVIDENCE_ACCOUNT}"
    ).lower()
    if (
        not isinstance(account_id, str)
        or not re.fullmatch(r"/subscriptions/[0-9a-f-]{36}/resourceGroups/.+", account_id, re.I)
        or not account_id.lower().endswith(suffix)
        or value.get("allowSharedKeyAccess") is not False
        or value.get("allowBlobPublicAccess") is not False
        or value.get("publicNetworkAccess") != "Disabled"
    ):
        fail("watchdog storage account is not private with Shared Key disabled")
    expected_containers = [
        "paperdesk-accepted-releases", "paperdesk-watchdog-evidence", "paperdesk-watchdog-state",
    ]
    containers = value.get("containers")
    if not isinstance(containers, list) or len(containers) != 3:
        fail("watchdog storage container posture is invalid")
    seen: list[str] = []
    for item in containers:
        if not isinstance(item, dict) or set(item) != SECURITY_CONTAINER_FIELDS or item.get("publicAccess") is not None:
            fail("watchdog storage container is not private")
        resource_id = item.get("resourceId")
        prefix = account_id + "/blobServices/default/containers/"
        if not isinstance(resource_id, str) or not resource_id.startswith(prefix):
            fail("watchdog storage container scope is invalid")
        seen.append(resource_id.rsplit("/", 1)[-1])
    if seen != expected_containers:
        fail("watchdog storage container inventory is not exact")
    expected_permissions = {
        "state-read-write": ([], [
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
        ]),
        "evidence-create-only": ([], [
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
        ]),
        "evidence-read-only": ([], [
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        ]),
        "registry-read-only": ([], [
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        ]),
        "arm-policy-read-only": ([
            "Microsoft.Authorization/roleAssignments/read",
            "Microsoft.Authorization/roleDefinitions/read",
            "Microsoft.ManagedIdentity/userAssignedIdentities/read",
            "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/read",
            "Microsoft.Storage/storageAccounts/blobServices/containers/read",
            "Microsoft.Storage/storageAccounts/read",
        ], []),
    }
    assignments = value.get("assignments")
    if not isinstance(assignments, list) or len(assignments) != 5:
        fail("watchdog Azure role assignment proof is invalid")
    client_ids: set[str] = set()
    principal_ids: set[str] = set()
    assignment_ids: set[str] = set()
    roles: list[str] = []
    for item in assignments:
        if not isinstance(item, dict) or set(item) != SECURITY_ASSIGNMENT_FIELDS:
            fail("watchdog Azure role assignment fields are invalid")
        role = item.get("role")
        if (
            role not in expected_permissions
            or item.get("actions") != expected_permissions[role][0]
            or item.get("dataActions") != expected_permissions[role][1]
        ):
            fail("watchdog Azure role permissions are not exact least privilege")
        for field, target in (
            ("clientId", client_ids), ("principalId", principal_ids),
            ("roleAssignmentId", assignment_ids),
        ):
            identifier = item.get(field)
            if not isinstance(identifier, str) or not UUID.fullmatch(identifier):
                fail("watchdog Azure identity coordinate is invalid")
            target.add(identifier.lower())
        definition = item.get("roleDefinitionId")
        if not isinstance(definition, str) or not UUID.fullmatch(definition):
            fail("watchdog Azure custom role definition ID is invalid")
        exact_scopes = {
            "arm-policy-read-only": account_id.rsplit("/resourceGroups/", 1)[0],
            "state-read-write": account_id + "/blobServices/default/containers/paperdesk-watchdog-state",
            "evidence-create-only": account_id + "/blobServices/default/containers/paperdesk-watchdog-evidence",
            "evidence-read-only": account_id + "/blobServices/default/containers/paperdesk-watchdog-evidence",
            "registry-read-only": account_id + "/blobServices/default/containers/paperdesk-accepted-releases",
        }
        if not isinstance(item.get("scope"), str) or item["scope"].lower() != exact_scopes[role].lower():
            fail("watchdog Azure role scope is not exact")
        identity_prefix = (
            account_id.split("/providers/", 1)[0]
            + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/"
        )
        if not isinstance(item.get("identityResourceId"), str) or not item["identityResourceId"].startswith(identity_prefix):
            fail("watchdog Azure user-assigned identity resource is invalid")
        roles.append(role)
    if (
        roles != sorted(expected_permissions)
        or len(client_ids) != 5
        or len(principal_ids) != 5
        or len(assignment_ids) != 5
    ):
        fail("watchdog Azure identities are not five distinct fixed roles")
    canonical_timestamp(value.get("observedAt"), "watchdog Azure posture observation")
    return dict(value)


class RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def direct_opener() -> Any:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), RejectRedirectHandler())


def _read_exact_response(response: Any, maximum: int) -> bytes:
    content_length = response.headers.get("Content-Length", "")
    if not POSITIVE.fullmatch(content_length) or int(content_length) > maximum:
        fail("watchdog provider response Content-Length is invalid")
    if response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
        fail("watchdog provider response Content-Type is invalid")
    if response.headers.get("Content-Encoding", "") not in {"", "identity"}:
        fail("watchdog provider response encoding is invalid")
    if response.headers.get("Transfer-Encoding", ""):
        fail("watchdog provider response transfer encoding is forbidden")
    raw = response.read(int(content_length) + 1)
    if not isinstance(raw, bytes) or len(raw) != int(content_length):
        fail("watchdog provider response length is not exact")
    return raw


def _canonical_response(response: Any, maximum: int = MAX_RECEIPT_BYTES) -> tuple[bytes, Mapping[str, Any]]:
    raw = _read_exact_response(response, maximum)
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("watchdog provider response is not valid UTF-8 JSON")
    if not isinstance(document, dict) or raw != canonical_json(document):
        fail("watchdog provider response is not canonical JSON")
    return raw, document


def _github_json_response(response: Any, maximum: int = MAX_OIDC_RESPONSE_BYTES) -> Mapping[str, Any]:
    if response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
        fail("GitHub OIDC response Content-Type is invalid")
    if response.headers.get("Content-Encoding", "") not in {"", "identity"}:
        fail("GitHub OIDC response encoding is invalid")
    raw = response.read(maximum + 1)
    if not isinstance(raw, bytes) or not 2 <= len(raw) <= maximum:
        fail("GitHub OIDC response size is invalid")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("GitHub OIDC response is not valid UTF-8 JSON")
    if not isinstance(document, dict):
        fail("GitHub OIDC response is not one JSON object")
    return document


def validate_oidc_claims(
    token: str,
    *,
    repository: str,
    caller_sha: str,
    ref: str,
    workflow_ref: str,
    run_id: str,
    run_attempt: str,
    environment: str,
    event_name: str,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(token, str) or len(token) > 32768 or token.count(".") != 2:
        fail("GitHub OIDC token shape is invalid")
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        fail("GitHub OIDC token claims are invalid")
    if repository != WATCHDOG_REPOSITORY:
        fail("GitHub OIDC client repository is not the watchdog control repository")
    expected = {
        "aud": OIDC_AUDIENCE,
        "iss": OIDC_ISSUER,
        "sub": f"repo:{repository}:environment:{environment}",
        "repository": repository,
        "repository_owner": WATCHDOG_REPOSITORY_OWNER,
        "repository_id": WATCHDOG_REPOSITORY_ID,
        "repository_owner_id": WATCHDOG_REPOSITORY_OWNER_ID,
        "sha": caller_sha,
        "workflow_sha": caller_sha,
        "ref": ref,
        "workflow_ref": workflow_ref,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "environment": environment,
        "event_name": event_name,
    }
    if not isinstance(claims, dict) or any(str(claims.get(name, "")) != value for name, value in expected.items()):
        fail("GitHub OIDC claims are not exact")
    if any(type(claims.get(name)) is not int for name in ("iat", "nbf", "exp")):
        fail("GitHub OIDC lifetime claims are invalid")
    epoch = int((observed_at or datetime.now(timezone.utc)).timestamp())
    if (
        claims["iat"] > epoch + 30
        or claims["nbf"] > epoch + 30
        or claims["exp"] < epoch
        or claims["exp"] <= claims["iat"]
        or claims["exp"] <= claims["nbf"]
        or claims["exp"] - claims["iat"] > 900
    ):
        fail("GitHub OIDC token lifetime is invalid")
    return dict(claims)


def fetch_oidc_token(
    environment_values: MutableMapping[str, str],
    *,
    repository: str,
    caller_sha: str,
    ref: str,
    workflow_ref: str,
    run_id: str,
    run_attempt: str,
    environment_name: str,
    event_name: str,
    opener: Any | None = None,
) -> str:
    request_url = environment_values.pop("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    request_token = environment_values.pop("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    if (
        not isinstance(request_url, str)
        or not isinstance(request_token, str)
        or not request_url
        or not request_token
        or request_url != request_url.strip()
        or request_token != request_token.strip()
        or len(request_url) > 4096
        or len(request_token) > 4096
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in request_token)
    ):
        fail("GitHub OIDC request coordinates are missing")
    try:
        parsed = urllib.parse.urlsplit(request_url)
        query = urllib.parse.parse_qsl(
            parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=32,
        )
        port = parsed.port
    except ValueError:
        fail("GitHub OIDC request URL is invalid")
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or not parsed.hostname.endswith(".actions.githubusercontent.com")
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.fragment
        or not parsed.path.startswith("/")
        or any(name == "audience" for name, _ in query)
    ):
        fail("GitHub OIDC request boundary is invalid")
    query.append(("audience", OIDC_AUDIENCE))
    oidc_url = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), ""),
    )
    request = urllib.request.Request(
        oidc_url,
        headers={
            "Authorization": f"Bearer {request_token}",
            "Accept": "application/json",
            "User-Agent": "PaperDeskWatchdog/2",
        },
        method="GET",
    )
    response: Any | None = None
    try:
        response = (opener or direct_opener()).open(request, timeout=30)
        if getattr(response, "status", 0) != 200 or response.geturl() != oidc_url:
            fail("GitHub OIDC request was not one exact successful hop")
        document = _github_json_response(response, MAX_OIDC_RESPONSE_BYTES)
        if set(document) != {"value"} or not isinstance(document.get("value"), str):
            fail("GitHub OIDC response is invalid")
        validate_oidc_claims(
            document["value"], repository=repository, caller_sha=caller_sha, ref=ref,
            workflow_ref=workflow_ref, run_id=run_id, run_attempt=run_attempt,
            environment=environment_name, event_name=event_name,
        )
        return document["value"]
    except EvidenceError:
        raise
    except (OSError, urllib.error.URLError, http.client.HTTPException):
        fail("GitHub OIDC request failed")
    finally:
        request.remove_header("Authorization")
        request_token = ""
        if response is not None:
            try:
                response.close()
            except (AttributeError, OSError):
                pass


def fetch_state_with_token(*, token: str, opener: Any | None = None) -> tuple[bytes, str]:
    request = urllib.request.Request(
        validate_state_url(STATE_API_URL),
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json", "User-Agent": "PaperDeskWatchdog/2"},
        method="GET",
    )
    response: Any | None = None
    try:
        response = (opener or direct_opener()).open(request, timeout=30)
        if getattr(response, "status", 0) != 200 or response.geturl() != STATE_API_URL:
            fail("watchdog state request was not one exact successful hop")
        raw, _ = _canonical_response(response)
        content_sha256 = hashlib.sha256(raw).hexdigest()
        values = response.headers.get_all("ETag") if hasattr(response.headers, "get_all") else None
        if values is None:
            value = response.headers.get("ETag", "")
            values = [value] if value else []
        if values != [f'"{content_sha256}"']:
            fail("watchdog state response ETag is not the quoted raw digest")
        return raw, values[0]
    except EvidenceError:
        raise
    except urllib.error.HTTPError as exc:
        fail(f"watchdog state request failed with HTTP {exc.code if 100 <= exc.code <= 599 else 0}")
    except (OSError, urllib.error.URLError, http.client.HTTPException):
        fail("watchdog state request failed")
    finally:
        request.remove_header("Authorization")
        token = ""
        if response is not None:
            try:
                response.close()
            except (AttributeError, OSError):
                pass


def _post_with_token(
    *,
    url: str,
    raw: bytes,
    token: str,
    expected_status: int,
    opener: Any | None = None,
    etag_sha_field: str | None = None,
) -> Mapping[str, Any]:
    request = urllib.request.Request(
        url,
        data=raw,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Content-Length": str(len(raw)),
            "User-Agent": "PaperDeskWatchdog/2",
        },
        method="POST",
    )
    response: Any | None = None
    try:
        response = (opener or direct_opener()).open(request, timeout=60)
        if getattr(response, "status", 0) != expected_status or response.geturl() != url:
            fail("watchdog provider POST was not one exact successful hop")
        _, document = _canonical_response(response)
        if etag_sha_field is not None:
            value = document.get(etag_sha_field)
            if not isinstance(value, str) or not SHA256.fullmatch(value):
                fail("watchdog provider POST state digest is invalid")
            values = response.headers.get_all("ETag") if hasattr(response.headers, "get_all") else None
            if values is None:
                header = response.headers.get("ETag", "")
                values = [header] if header else []
            if values != [f'"{value}"']:
                fail("watchdog provider POST ETag is not the quoted state digest")
        return document
    except EvidenceError:
        raise
    except urllib.error.HTTPError as exc:
        fail(f"watchdog provider POST failed with HTTP {exc.code if 100 <= exc.code <= 599 else 0}")
    except (OSError, urllib.error.URLError, http.client.HTTPException):
        fail("watchdog provider POST failed")
    finally:
        request.remove_header("Authorization")
        token = ""
        if response is not None:
            try:
                response.close()
            except (AttributeError, OSError):
                pass


def validate_decision_receipt(document: object) -> Mapping[str, Any]:
    if not isinstance(document, dict) or set(document) != DECISION_FIELDS:
        fail("watchdog decision fields are not exact v2")
    if (
        document.get("schemaVersion") != 2
        or document.get("receiptType") != "watchdog-decision"
        or document.get("decision") != "dispatch-rollback"
        or document.get("sourceRepository") != SOURCE_REPOSITORY
    ):
        fail("watchdog rollback decision identity is invalid")
    full_sha(document.get("candidateSha"), "watchdog candidate SHA")
    full_sha(document.get("expectedCurrentLiveSha"), "watchdog expected live SHA")
    for name in ("candidateRunId", "candidateRunAttempt", "watchdogRunId", "watchdogRunAttempt"):
        positive(document.get(name), name)
    digest(document.get("observedStateSha256"), "watchdog observed state digest")
    canonical_timestamp(document.get("decidedAt"), "watchdog decision time")
    return document


def validate_initial_baseline(document: object) -> Mapping[str, Any]:
    if not isinstance(document, dict) or set(document) != BASELINE_FIELDS:
        fail("watchdog initial baseline fields are not exact v2")
    if document.get("schemaVersion") != 2:
        fail("watchdog initial baseline schema is invalid")
    digest(document.get("receiptSha256"), "watchdog baseline receipt digest")
    digest(document.get("acceptedReleaseManifestSha256"), "accepted-release manifest digest")
    source_sha = full_sha(document.get("sourceSha"), "watchdog baseline source SHA")
    for name in (
        "sourceRunId", "sourceRunAttempt", "acceptanceRunId", "acceptanceRunAttempt",
        "reviewRunId", "reviewRunAttempt",
    ):
        positive(document.get(name), f"watchdog baseline {name}")
    if document.get("acceptedReleasePrefix") != (
        f"v1/releases/{source_sha}/{document['sourceRunId']}/{document['acceptanceRunId']}/"
    ):
        fail("watchdog baseline accepted-release prefix is invalid")
    if (
        not isinstance(document.get("evidencePath"), str)
        or not re.fullmatch(r"v2/[a-z0-9./-]{1,480}\.json", document["evidencePath"])
        or ".." in document["evidencePath"].split("/")
    ):
        fail("watchdog baseline evidence path is invalid")
    if document.get("reviewWorkflowRef") != BASELINE_WORKFLOW_REF:
        fail("watchdog baseline review workflow is invalid")
    full_sha(document.get("reviewWorkflowSha"), "watchdog baseline review workflow SHA")
    if document.get("reviewEnvironment") != BASELINE_ENVIRONMENT:
        fail("watchdog baseline review environment is invalid")
    canonical_timestamp(document.get("preparedAt"), "watchdog baseline preparation time")
    return document


def initialize_baseline_with_token(
    *, raw_baseline: bytes, token: str, opener: Any | None = None,
) -> Mapping[str, Any]:
    try:
        baseline = json.loads(raw_baseline.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("watchdog initial baseline is not valid UTF-8 JSON")
    if raw_baseline != canonical_json(baseline):
        fail("watchdog initial baseline must use exact canonical JSON bytes")
    validate_initial_baseline(baseline)
    document = _post_with_token(
        url=validate_baseline_url(BASELINE_API_URL), raw=raw_baseline, token=token,
        expected_status=201, opener=opener, etag_sha_field="stateSha256",
    )
    if set(document) != {"schemaVersion", "status", "stateSha256"} or (
        document.get("schemaVersion") != 2 or document.get("status") != "baseline-initialized"
    ):
        fail("watchdog initial baseline response is invalid")
    digest(document.get("stateSha256"), "initialized watchdog state digest")
    return document


def claim_with_token(*, raw_decision: bytes, token: str, opener: Any | None = None) -> Mapping[str, Any]:
    try:
        decision = json.loads(raw_decision.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("watchdog decision is not valid UTF-8 JSON")
    if raw_decision != canonical_json(decision):
        fail("watchdog decision must use exact canonical JSON bytes")
    validate_decision_receipt(decision)
    document = _post_with_token(
        url=validate_claim_url(CLAIM_API_URL), raw=raw_decision, token=token,
        expected_status=201, opener=opener,
    )
    if not isinstance(document, dict) or set(document) != CLAIM_RESPONSE_FIELDS or document.get("status") != "claimed":
        fail("watchdog claim response fields are not exact")
    if not isinstance(document.get("claimId"), str) or not UUID.fullmatch(document["claimId"]):
        fail("watchdog claim ID is invalid")
    if type(document.get("dispatchGuardGeneration")) is not int or document["dispatchGuardGeneration"] < 1:
        fail("watchdog claim generation is invalid")
    digest(document.get("decisionReceiptSha256"), "watchdog decision receipt digest")
    if not isinstance(document.get("decisionEvidenceETag"), str) or not ETAG.fullmatch(document["decisionEvidenceETag"]):
        fail("watchdog decision evidence ETag is invalid")
    return document


def dispatch_with_token(*, claim: Mapping[str, Any], token: str, opener: Any | None = None) -> Mapping[str, Any]:
    if not isinstance(claim, dict) or set(claim) != CLAIM_RESPONSE_FIELDS or claim.get("status") != "claimed":
        fail("watchdog provider dispatch requires one exact claim")
    claim_id = claim.get("claimId")
    if not isinstance(claim_id, str) or not UUID.fullmatch(claim_id):
        fail("watchdog claim ID is invalid")
    request_document = {
        "schemaVersion": 2,
        "requestType": "watchdog-provider-dispatch",
        "claimId": claim_id,
    }
    document = _post_with_token(
        url=validate_dispatch_url(DISPATCH_API_URL), raw=canonical_json(request_document),
        token=token, expected_status=200, opener=opener,
    )
    if not isinstance(document, dict) or set(document) != DISPATCH_RESPONSE_FIELDS:
        fail("watchdog dispatch response fields are not exact")
    if document.get("status") != "requested" or document.get("claimId") != claim_id:
        fail("watchdog dispatch response identity is invalid")
    if type(document.get("dispatchGuardGeneration")) is not int or document["dispatchGuardGeneration"] < 1:
        fail("watchdog dispatch generation is invalid")
    for name in ("attemptReceiptSha256", "dispatchReceiptSha256"):
        digest(document.get(name), name)
    run_id = positive(document.get("workflowRunId"), "workflow run ID")
    if document.get("workflowRunApiUrl") != f"https://api.github.com/repos/{SOURCE_REPOSITORY}/actions/runs/{run_id}":
        fail("watchdog dispatch run API URL is not exact")
    if document.get("workflowRunHtmlUrl") != f"https://github.com/{SOURCE_REPOSITORY}/actions/runs/{run_id}":
        fail("watchdog dispatch run HTML URL is not exact")
    if not isinstance(document.get("githubRequestId"), str) or not REQUEST_ID.fullmatch(document["githubRequestId"]):
        fail("watchdog dispatch GitHub request ID is invalid")
    if not isinstance(document.get("dispatchEvidenceETag"), str) or not ETAG.fullmatch(document["dispatchEvidenceETag"]):
        fail("watchdog dispatch evidence ETag is invalid")
    if not isinstance(document.get("dispatchEvidenceVersionId"), str) or not SAFE_VERSION_ID.fullmatch(document["dispatchEvidenceVersionId"]):
        fail("watchdog dispatch evidence version is invalid")
    return document


def reconcile_with_token(
    *, claim_id: str, manual: bool, token: str, opener: Any | None = None,
) -> Mapping[str, Any]:
    if not isinstance(claim_id, str) or not UUID.fullmatch(claim_id):
        fail("watchdog reconciliation claim ID is invalid")
    request_document = {
        "schemaVersion": 2,
        "requestType": "watchdog-dispatch-reconciliation",
        "claimId": claim_id,
    }
    document = _post_with_token(
        url=validate_reconciliation_url(
            RECONCILE_MANUAL_API_URL if manual else RECONCILE_AUTO_API_URL,
            manual=manual,
        ),
        raw=canonical_json(request_document), token=token, expected_status=200, opener=opener,
    )
    required = {"status", "claimId", "dispatchGuardGeneration"}
    if (
        not isinstance(document, dict)
        or not required.issubset(document)
        or document.get("claimId") != claim_id
        or type(document.get("dispatchGuardGeneration")) is not int
        or document["dispatchGuardGeneration"] < 1
    ):
        fail("watchdog reconciliation response is invalid")
    if manual:
        if document.get("status") != "known-run-held-for-workflow-observation" or frozenset(document) not in {
            frozenset(required), frozenset(required | {"workflowRunId"}),
        }:
            fail("watchdog manual reconciliation response is invalid")
        if "workflowRunId" in document:
            positive(document["workflowRunId"], "reconciled workflow run ID")
    else:
        if (
            set(document) != required | {"reconciliationReceiptSha256"}
            or document.get("status") != "released-unattempted-expired-claim"
        ):
            fail("watchdog automatic reconciliation response is invalid")
        digest(document.get("reconciliationReceiptSha256"), "reconciliation receipt digest")
    return document


def _add_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository", required=True)
    parser.add_argument("--caller-sha", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--event-name", required=True)


def _token_from_args(args: argparse.Namespace) -> str:
    return fetch_oidc_token(
        os.environ,
        repository=args.repository,
        caller_sha=full_sha(args.caller_sha, "OIDC caller SHA"),
        ref=args.ref,
        workflow_ref=args.workflow_ref,
        run_id=positive(args.run_id, "OIDC run ID"),
        run_attempt=positive(args.run_attempt, "OIDC run attempt"),
        environment_name=args.environment,
        event_name=args.event_name,
    )


def _github_output(path: str | None, values: Mapping[str, object]) -> None:
    if not path:
        return
    with Path(path).open("a", encoding="utf-8", newline="\n") as handle:
        for name, value in values.items():
            handle.write(f"{name}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate-config")

    state_parser = subparsers.add_parser("fetch-state")
    _add_identity_arguments(state_parser)
    state_parser.add_argument("--output", required=True)
    state_parser.add_argument("--github-output")

    baseline_parser = subparsers.add_parser("initialize-baseline")
    _add_identity_arguments(baseline_parser)
    baseline_parser.add_argument("--baseline", required=True)
    baseline_parser.add_argument("--output", required=True)
    baseline_parser.add_argument("--github-output")

    claim_parser = subparsers.add_parser("claim")
    _add_identity_arguments(claim_parser)
    claim_parser.add_argument("--decision", required=True)
    claim_parser.add_argument("--output", required=True)
    claim_parser.add_argument("--github-output")

    dispatch_parser = subparsers.add_parser("provider-dispatch")
    _add_identity_arguments(dispatch_parser)
    dispatch_parser.add_argument("--claim", required=True)
    dispatch_parser.add_argument("--output", required=True)
    dispatch_parser.add_argument("--github-output")

    reconcile_parser = subparsers.add_parser("reconcile")
    _add_identity_arguments(reconcile_parser)
    reconcile_parser.add_argument("--claim-id", required=True)
    reconcile_parser.add_argument("--mode", choices=("automatic", "manual"), required=True)
    reconcile_parser.add_argument("--output", required=True)

    args = parser.parse_args()
    if args.command == "validate-config":
        validate_state_url(STATE_API_URL)
        validate_baseline_url(BASELINE_API_URL)
        validate_claim_url(CLAIM_API_URL)
        validate_dispatch_url(DISPATCH_API_URL)
        validate_reconciliation_url(RECONCILE_AUTO_API_URL, manual=False)
        validate_reconciliation_url(RECONCILE_MANUAL_API_URL, manual=True)
        print("Watchdog v2 fixed provider API boundaries passed.")
        return 0
    token = _token_from_args(args)
    if args.command == "fetch-state":
        raw, etag = fetch_state_with_token(token=token)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
        state_sha256 = hashlib.sha256(raw).hexdigest()
        _github_output(args.github_output, {"state_sha256": state_sha256, "state_etag": etag})
        print(f"Fetched watchdog state SHA-256: {state_sha256}")
        return 0
    if args.command == "initialize-baseline":
        raw, _ = regular_file(Path(args.baseline), "watchdog initial baseline")
        result = initialize_baseline_with_token(raw_baseline=raw, token=token)
        create_only(Path(args.output), result)
        _github_output(args.github_output, {"state_sha256": result["stateSha256"]})
        print(f"Initialized watchdog state SHA-256: {result['stateSha256']}")
        return 0
    if args.command == "claim":
        raw, _ = regular_file(Path(args.decision), "watchdog decision")
        result = claim_with_token(raw_decision=raw, token=token)
        create_only(Path(args.output), result)
        _github_output(args.github_output, {
            "claim_id": result["claimId"],
            "dispatch_guard_generation": result["dispatchGuardGeneration"],
            "decision_receipt_sha256": result["decisionReceiptSha256"],
            "decision_evidence_etag": result["decisionEvidenceETag"],
        })
        print(f"Claimed rollback dispatch: {result['claimId']}")
        return 0
    if args.command == "provider-dispatch":
        _, claim = regular_file(Path(args.claim), "watchdog claim")
        result = dispatch_with_token(claim=claim, token=token)
        create_only(Path(args.output), result)
        _github_output(args.github_output, {
            "dispatch_status": result["status"],
            "workflow_run_id": result["workflowRunId"],
            "dispatch_receipt_sha256": result["dispatchReceiptSha256"],
        })
        print(f"Provider dispatch bound workflow run: {result['workflowRunId']}")
        return 0
    result = reconcile_with_token(
        claim_id=args.claim_id, manual=args.mode == "manual", token=token,
    )
    create_only(Path(args.output), result)
    print(f"Reconciliation result: {result['status']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceError, OSError) as error:
        raise SystemExit(f"Watchdog evidence client failed: {error}")
