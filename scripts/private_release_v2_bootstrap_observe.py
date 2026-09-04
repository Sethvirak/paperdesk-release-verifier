#!/usr/bin/env python3
"""Read-only PaperDesk V2 bootstrap observation and authorization template.

This module deliberately does not contain an Azure mutation transport.  A
caller supplies a session whose only operation is ``read``; every request is
checked again here and is limited to ``GET`` or the one ARM read-only
``POST .../config/appsettings/list`` shape emitted by the reviewed bootstrap
policy.

The generated authorization document is a *template*, not an authorization.
It omits the executable ``authorizationType``, ``validity`` and
``confirmation`` fields required by :func:`validate_authorization`.  A
separate, explicit authorization ceremony must promote the proposed validity
and add an exact confirmation binding after reviewing the canonical preflight.
"""

from __future__ import annotations

import argparse
import copy
import dataclasses
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Callable, Mapping, Protocol, Sequence
import urllib.parse

_SCRIPT_DIRECTORY = str(Path(__file__).resolve().parent)
_REPOSITORY_ROOT = str(Path(__file__).resolve().parent.parent)
if _SCRIPT_DIRECTORY not in sys.path:
    # Azure CLI's embedded Windows Python runs with an isolated search path and
    # does not add the invoked script directory.  Add only this fixed local
    # directory so the documented direct invocation resolves its sibling.
    sys.path.insert(0, _SCRIPT_DIRECTORY)
if _REPOSITORY_ROOT not in sys.path:
    sys.path.insert(0, _REPOSITORY_ROOT)
_loaded_scripts = sys.modules.get("scripts")
_loaded_locations = {
    str(Path(item).resolve()).lower()
    for item in getattr(_loaded_scripts, "__path__", [])
}
if (
    _loaded_scripts is not None
    and _SCRIPT_DIRECTORY.lower() not in _loaded_locations
):
    # The Azure CLI runtime imports an unrelated win32 ``scripts`` namespace
    # during startup.  Remove only that foreign namespace before resolving the
    # repository's fixed local package boundary.
    sys.modules.pop("scripts", None)

try:
    from scripts import private_release_v2_bootstrap as bootstrap
except ImportError:
    # Support the documented direct invocation from the repository root:
    # ``python -B scripts/private_release_v2_bootstrap_observe.py ...``.
    import private_release_v2_bootstrap as bootstrap


EXECUTOR_RELATIVE_PATH = "scripts/private_release_v2_bootstrap.py"
TEMPLATE_TYPE = "paperdesk-private-release-v2-bootstrap-authorization-template"
TEMPLATE_STATUS = "NON_EXECUTABLE_REQUIRES_EXPLICIT_AUTHORIZATION_CEREMONY"
READ_METHODS = {"GET", "POST"}
SAFE_POST_SUFFIX = "/config/appsettings/list"
SENSITIVE_QUERY_FIELDS = {"sig", "se", "sp", "sv", "spr", "srt", "ss"}
SENSITIVE_TEXT = re.compile(
    r"(?:bearer\s+|password\s*=|client[_-]?secret\s*=|[?&]sig=)", re.IGNORECASE
)
SENSITIVE_KEYS = re.compile(
    r"(?:^|[_-])(?:access[-_]?token|refresh[-_]?token|client[-_]?secret|password|sas|connection[-_]?string|api[-_]?key|service[-_]?token|signing[-_]?key|private[-_]?secret)(?:$|[_-])",
    re.IGNORECASE,
)
OBSERVED_HEADERS = {
    "content-length",
    "etag",
    "x-ms-lease-state",
    "x-ms-lease-status",
    "x-ms-version-id",
}
GUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


class ObserveError(RuntimeError):
    """A read-only observation or source binding failed closed."""


def fail(message: str) -> None:
    raise ObserveError(message)


def _exact_keys(value: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} fields are not exact")
    return value


def _stamp(value: dt.datetime) -> str:
    if value.tzinfo != dt.timezone.utc:
        fail("observation clock must be exact UTC")
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _safe_json(value: Any, label: str) -> Any:
    try:
        raw = bootstrap.canonical_json_bytes(value)
    except Exception as exc:  # bootstrap owns the canonical JSON boundary
        raise ObserveError(f"{label} is not canonical-JSON representable") from exc
    if len(raw) > 8 * 1024 * 1024:
        fail(f"{label} exceeds the read-only observation limit")
    text = raw.decode("utf-8")
    if SENSITIVE_TEXT.search(text):
        fail(f"{label} contains a credential-shaped value")

    def inspect(item: Any, path: str) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    fail(f"{label} contains a non-string JSON key")
                lowered = key.lower()
                if (
                    SENSITIVE_KEYS.search(lowered)
                    or lowered in {"authorization", "cookie", "set-cookie"}
                    or (
                        lowered in {"passwordcredentials", "keycredentials"}
                        and child not in (None, [])
                    )
                ) and child not in (None, "", [], {}):
                    fail(f"{label} contains secret material at {path}.{key}")
                inspect(child, f"{path}.{key}")
        elif isinstance(item, list):
            for index, child in enumerate(item):
                inspect(child, f"{path}[{index}]")

    inspect(value, label)
    return copy.deepcopy(value)


def _safe_url(method: str, url: str) -> None:
    from urllib.parse import parse_qs, urlsplit

    if method not in READ_METHODS:
        fail(f"mutation-capable HTTP method is forbidden: {method}")
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise ObserveError("observation URL is invalid") from exc
    query = parse_qs(parsed.query, keep_blank_values=True)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.port not in (None, 443)
        or SENSITIVE_QUERY_FIELDS.intersection(key.lower() for key in query)
    ):
        fail("observation URL is outside the non-secret HTTPS boundary")
    if method == "POST" and not parsed.path.endswith(SAFE_POST_SUFFIX):
        fail("only the source-owned read-only app-settings POST is permitted")


@dataclasses.dataclass(frozen=True)
class ReadRequest:
    method: str
    url: str
    body: bytes = b""

    def __post_init__(self) -> None:
        _safe_url(self.method, self.url)
        if self.body:
            fail("read-only observation requests must have an empty body")
        if self.method == "GET" and self.body != b"":
            fail("GET observation body must be empty")


@dataclasses.dataclass(frozen=True)
class ReadResponse:
    method: str
    url: str
    status: int
    headers: Mapping[str, str]
    body: Any
    response_sha256: str | None = None


class ReadOnlySession(Protocol):
    """Injected read-only session; implementations must not expose mutation."""

    def account(self) -> Mapping[str, Any]: ...

    def read(self, request: ReadRequest) -> ReadResponse: ...


class AzureCliReadOnlySession:
    """Concrete Azure CLI credential boundary exposing only reviewed reads."""

    def __init__(
        self,
        *,
        clock: Callable[[], dt.datetime] | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self.clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        self.sleep = sleeper or time.sleep
        self._account: dict[str, Any] | None = None
        self._session: bootstrap.AzureCliRestSession | None = None

    def account(self) -> Mapping[str, Any]:
        if self._account is None:
            # Account inspection does not request a bearer token.  The exact
            # observed object ID is then used to bind every lazily requested
            # read-only ARM/Graph token in the real session.
            probe = bootstrap.AzureCliRestSession({}, clock=self.clock)
            account = dict(probe.account())
            self._account = dict(_account(_StaticAccountSession(account)))
            self._session = bootstrap.AzureCliRestSession(
                {"azure": self._account}, clock=self.clock
            )
        return dict(self._account)

    def read(self, request: ReadRequest) -> ReadResponse:
        _safe_url(request.method, request.url)
        if request.body:
            fail("concrete read-only session received a request body")
        if self._session is None:
            self.account()
        assert self._session is not None
        response = None
        for attempt in range(3):
            try:
                response = self._session.request(request.method, request.url)
                break
            except bootstrap.BootstrapError as exc:
                if (
                    str(exc) != "Azure REST transport failed closed"
                    or attempt == 2
                ):
                    raise
                # This class exposes only bounded read operations.  Retrying a
                # transient transport failure here cannot duplicate a mutation;
                # the mutation-capable executor deliberately has no such retry.
                self.sleep(0.5 * (2**attempt))
        if response is None:
            fail("read-only Azure retry boundary produced no response")
        response_sha256 = bootstrap._preflight_response_sha256(
            request.method, request.url, response
        )
        storage_error = bootstrap._package_blob_error_projection(
            request.method, request.url, response
        )
        if response.body:
            content_type = next(
                (
                    value
                    for key, value in response.headers.items()
                    if key.lower() == "content-type"
                ),
                "",
            )
            if "json" in content_type.lower() or response.body[:1] in {b"{", b"["}:
                try:
                    body = json.loads(
                        response.body.decode("utf-8"),
                        object_pairs_hook=_duplicate_safe_pairs,
                        parse_constant=lambda value: fail(
                            f"invalid JSON constant in read-only response: {value}"
                        ),
                    )
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ObserveError(
                        "Azure read-only response is not bounded JSON"
                    ) from exc
            else:
                host = (urllib.parse.urlsplit(request.url).hostname or "").lower()
                if host != "mdspdbak2608089c4e.blob.core.windows.net":
                    fail("non-JSON read-only response is outside the package blob boundary")
                # Blob absence is XML and an existing package is binary.  The
                # observer retains only the exact raw-body digest; operation
                # admission is determined by status and safe response headers.
                body = storage_error or {}
        else:
            body = {}
        return ReadResponse(
            method=request.method,
            url=request.url,
            status=response.status,
            headers=dict(response.headers),
            body=body,
            response_sha256=response_sha256,
        )


class _StaticAccountSession:
    def __init__(self, account: Mapping[str, Any]) -> None:
        self._account = dict(account)

    def account(self) -> Mapping[str, Any]:
        return dict(self._account)


def _duplicate_safe_pairs(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("read-only Azure response contains a duplicate JSON key")
        result[key] = value
    return result


def _normalize_response(request: ReadRequest, response: ReadResponse) -> dict[str, Any]:
    if response.method != request.method or response.url != request.url:
        fail("read-only session response drifted from the exact request")
    if type(response.status) is not int or not 200 <= response.status <= 599:
        fail("read-only session returned an invalid HTTP status")
    if not isinstance(response.headers, Mapping):
        fail("read-only session headers are invalid")
    headers: dict[str, str] = {}
    for key, value in response.headers.items():
        if (
            not isinstance(key, str)
            or not isinstance(value, str)
            or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", key)
            or len(value) > 4096
            or "\r" in value
            or "\n" in value
            or SENSITIVE_TEXT.search(value)
        ):
            fail("read-only session returned an unsafe header")
        lowered = key.lower()
        if lowered not in OBSERVED_HEADERS:
            continue
        if lowered in headers and headers[lowered] != value:
            fail("read-only session returned duplicate conflicting headers")
        headers[lowered] = value
    body = _safe_json(response.body, "read-only response body")
    envelope = {
        "method": request.method,
        "url": request.url,
        "status": response.status,
        "headers": dict(sorted(headers.items())),
        "body": body,
    }
    if response.response_sha256 is not None:
        if not bootstrap.SHA256.fullmatch(response.response_sha256):
            fail("read-only session returned an invalid response digest")
        envelope["responseSha256"] = response.response_sha256
    return envelope


def response_digest(envelope: Mapping[str, Any]) -> str:
    """Match the executor's fresh-preflight response projection.

    Method, URL and status are separate canonical probe fields.  JSON bodies
    are normalized to canonical bytes exactly as the executor does.  The exact
    package WORM-policy probe additionally binds its ETag header because an
    ETag appearing after authorization must stop before mutation.
    """

    override = envelope.get("responseSha256")
    body = envelope["body"]
    if isinstance(body, bytes):
        body_sha256 = bootstrap.sha256_bytes(body)
    else:
        body_sha256 = bootstrap.sha256_bytes(bootstrap.canonical_json_bytes(body))
    package_worm_digest = bootstrap._package_worm_policy_preflight_response_sha256(
        str(envelope.get("method", "")),
        str(envelope.get("url", "")),
        envelope.get("status"),
        body_sha256,
        envelope.get("headers", {}),
    )
    if package_worm_digest is not None:
        if isinstance(override, str) and override != package_worm_digest:
            fail("package WORM response digest drifted from its exact projection")
        return package_worm_digest
    if isinstance(override, str):
        return override
    return body_sha256


def _normalize_production_boundary_response(
    request: ReadRequest,
    response: ReadResponse,
) -> dict[str, Any]:
    """Normalize one boundary read without persisting production settings.

    App-settings names and values may themselves be sensitive.  They are
    validated as an exact string map, hashed in memory, and discarded after
    the shared source projector runs.  All other boundary bodies use the
    ordinary secret scanner.
    """

    if response.method != request.method or response.url != request.url:
        fail("read-only session response drifted from the exact request")
    if response.status != 200 or not isinstance(response.headers, Mapping):
        fail("production boundary read did not return one exact HTTP 200 response")
    if request.method == "POST":
        digest_document = bootstrap._production_boundary_digest_document(
            request.method, request.url, response.body
        )
        canonical_body = bootstrap.canonical_json_bytes(digest_document)
        return {
            "method": request.method,
            "url": request.url,
            "status": 200,
            "headers": {},
            "body": digest_document,
            "responseSha256": bootstrap.sha256_bytes(canonical_body),
        }
    envelope = _normalize_response(request, response)
    if envelope["status"] != 200:
        fail("production boundary read did not return one exact HTTP 200 response")
    return envelope


def _account(session: ReadOnlySession) -> dict[str, Any]:
    value = _exact_keys(
        session.account(),
        {
            "cloud",
            "subscriptionId",
            "tenantId",
            "accountId",
            "accountObjectId",
            "accountType",
        },
        "Azure read-only account",
    )
    result = dict(value)
    if (
        result["cloud"] != "AzureCloud"
        or result["subscriptionId"] != bootstrap.SUBSCRIPTION
        or result["tenantId"] != bootstrap.TENANT
        or result["accountType"] not in {"user", "servicePrincipal"}
        or not isinstance(result["accountId"], str)
        or not 3 <= len(result["accountId"]) <= 256
        or not isinstance(result["accountObjectId"], str)
        or not GUID.fullmatch(result["accountObjectId"])
    ):
        fail("Azure read-only account is outside the fixed plan boundary")
    if SENSITIVE_TEXT.search(result["accountId"]):
        fail("Azure account identifier is credential-shaped")
    return result


def _authorization_kernel(
    *,
    plan: Mapping[str, Any],
    plan_sha256: str,
    package: Mapping[str, Any],
    source: Mapping[str, Any],
    azure: Mapping[str, Any],
    authorization_id: str,
    receipt_directory: Path,
    observed_at: dt.datetime,
) -> dict[str, Any]:
    if not GUID.fullmatch(authorization_id):
        fail("authorization template ID is not one exact GUID")
    if not receipt_directory.is_absolute() or receipt_directory.name != (
        f"paperdesk-private-release-v2-bootstrap-{authorization_id}"
    ):
        fail("receipt directory is not the exact authorization-specific absolute path")
    source = _safe_json(source, "source evidence")
    if not isinstance(source, dict) or set(source) != {"reviewedHead", "mergedMain"}:
        fail("source evidence must contain the exact reviewed and merged records")
    merged = source["mergedMain"]
    if not isinstance(merged, dict) or not re.fullmatch(
        r"[0-9a-f]{40}", str(merged.get("commitSha", ""))
    ):
        fail("merged source evidence has no exact commit SHA")

    proposed_not_before = observed_at
    proposed_expires = observed_at + dt.timedelta(
        seconds=bootstrap.MAX_AUTHORIZATION_SECONDS
    )
    return {
        "authorizationId": authorization_id,
        "repository": bootstrap.REPOSITORY,
        "source": source,
        "executor": {
            "path": EXECUTOR_RELATIVE_PATH,
            "sha256": bootstrap.sha256_bytes(bootstrap.EXECUTOR_PATH.read_bytes()),
        },
        "plan": {
            "path": "contracts/private_release_bootstrap_plan.json",
            "sha256": plan_sha256,
            "resourceIds": [item["id"] for item in plan["resourceInventory"]],
            "mutationIds": [item["id"] for item in plan["mutations"]],
            "irreversibleMutationIds": list(plan["irreversibleMutationIds"]),
            "postconditionIds": [item["id"] for item in plan["postconditions"]],
            "bridgePackageSourceSha": merged["commitSha"],
            "bridgePackageSha256": package["sha256"],
            "bridgePackageSize": package["size"],
        },
        "azure": dict(azure),
        "proposedValidity": {
            "notBefore": _stamp(proposed_not_before),
            "expiresAt": _stamp(proposed_expires),
            "maximumLifetimeSeconds": bootstrap.MAX_AUTHORIZATION_SECONDS,
        },
        "singleUse": {
            "required": True,
            "receiptDirectory": str(receipt_directory),
            "azureClaimResourceId": (
                f"/subscriptions/{bootstrap.SUBSCRIPTION}/providers/"
                "Microsoft.Resources/deployments/"
                f"paperdesk-v2-bootstrap-{authorization_id}"
            ),
        },
    }


def _policy_authorization(kernel: Mapping[str, Any]) -> dict[str, Any]:
    """Internal shape used only to materialize reviewed source validators."""

    return {
        "authorizationId": kernel["authorizationId"],
        "source": kernel["source"],
        "plan": kernel["plan"],
        "azure": kernel["azure"],
        "validity": kernel["proposedValidity"],
        "singleUse": kernel["singleUse"],
    }


def _body_mapping(envelope: Mapping[str, Any], label: str) -> Mapping[str, Any]:
    body = envelope["body"]
    if not isinstance(body, dict):
        fail(f"{label} response body is not one object")
    return body


def _etag(envelope: Mapping[str, Any], label: str) -> str:
    headers = envelope["headers"]
    body = envelope["body"] if isinstance(envelope["body"], dict) else {}
    value = headers.get("etag") or body.get("etag")
    if not isinstance(value, str) or not (
        re.fullmatch(r'"[^"\r\n]{1,256}"', value) is not None
        or re.fullmatch(r"[0-9A-Fa-f]{8,64}", value) is not None
    ):
        fail(f"{label} has no exact strong ETag token")
    return value


def _properties(envelope: Mapping[str, Any], label: str) -> Mapping[str, Any]:
    body = _body_mapping(envelope, label)
    properties = body.get("properties")
    if not isinstance(properties, dict):
        fail(f"{label} response has no exact properties object")
    return properties


def _graph_collection(
    envelope: Mapping[str, Any], label: str
) -> list[Mapping[str, Any]]:
    return bootstrap._unpaginated_graph_collection(
        _body_mapping(envelope, label), label
    )


def _graph_one(envelope: Mapping[str, Any], label: str) -> Mapping[str, Any]:
    values = _graph_collection(envelope, label)
    if len(values) != 1:
        fail(f"{label} must resolve to exactly one Graph object")
    return values[0]


def _microsoft_graph_service_principal_id(
    envelope: Mapping[str, Any],
) -> str:
    if envelope.get("status") != 200:
        fail("Microsoft Graph service principal inventory is unreadable")
    service = _exact_keys(
        _graph_one(envelope, "Microsoft Graph service principal inventory"),
        {"id", "appId"},
        "Microsoft Graph service principal",
    )
    service_id = service["id"]
    if (
        service["appId"]
        != bootstrap.AzureCliBootstrapTransport.GRAPH_APP_ID
        or not isinstance(service_id, str)
        or GUID.fullmatch(service_id) is None
    ):
        fail("Microsoft Graph service principal inventory is not exact")
    return service_id


def _identity_adopted(envelope: Mapping[str, Any], expected_resource_id: str) -> dict[str, Any]:
    body = _body_mapping(envelope, "managed identity")
    properties = _properties(envelope, "managed identity")
    result = {
        "resourceId": body.get("id"),
        "clientId": properties.get("clientId"),
        "principalId": properties.get("principalId"),
    }
    if (
        envelope.get("status") != 200
        or body.get("type") != "Microsoft.ManagedIdentity/userAssignedIdentities"
        or properties.get("tenantId") != bootstrap.TENANT
        or str(result["resourceId"]).lower() != expected_resource_id.lower()
        or any(
        not isinstance(result[field], str) or not GUID.fullmatch(result[field])
        for field in ("clientId", "principalId")
        )
    ):
        fail("managed identity adoption response drifted from the fixed resource")
    return result


def _private_container_adopted(
    envelope: Mapping[str, Any],
    operation_id: str,
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    body = _body_mapping(envelope, operation_id)
    properties = body.get("properties")
    if not isinstance(properties, Mapping):
        fail(f"{operation_id} response has no exact properties object")
    bootstrap._validate_private_container_projection(
        {
            "id": body.get("id"),
            "name": body.get("name"),
            "type": body.get("type"),
            "publicAccess": properties.get("publicAccess"),
        },
        operation_id=operation_id,
        plan=plan,
    )
    return {}


def _storage_acl(envelope: Mapping[str, Any]) -> dict[str, Any]:
    properties = _properties(envelope, "storage account")
    acls = properties.get("networkAcls")
    if not isinstance(acls, dict):
        fail("storage account response has no network ACL object")
    return bootstrap._normalize_storage_acl_prestate(acls)


def _app_settings(envelope: Mapping[str, Any]) -> dict[str, str]:
    body = _body_mapping(envelope, "bridge app settings")
    properties = body.get("properties")
    if not isinstance(properties, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in properties.items()
    ):
        fail("bridge app settings response is not one exact string map")
    return dict(properties)


def _worm_policy_admission(
    operation_id: str,
    envelope: Mapping[str, Any],
    plan: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> tuple[str, dict[str, Any]]:
    status = envelope["status"]
    if status == 404:
        if operation_id != "lockPackageRetentionAt91Days":
            fail(f"{operation_id} required existing WORM policy is absent")
        return "absent", _policy_checked_context(
            operation_id,
            policy,
            {"executionDecision": "apply-exact", "etag": None},
        )
    if status != 200:
        fail(f"{operation_id} WORM preflight returned unsupported status")
    resources = {item["id"]: item for item in plan["resourceInventory"]}
    target = {
        "lockPackageRetentionAt91Days": "packageContainer",
        "extendAcceptedRetentionFrom30To91Days": "acceptedContainer",
        "extendResultRetentionFrom30To91Days": "resultContainer",
    }[operation_id]
    body = _body_mapping(envelope, operation_id)
    properties = body.get("properties")
    expected_id = resources[target]["resourceId"] + "/immutabilityPolicies/default"
    header_etags = [
        value
        for key, value in envelope["headers"].items()
        if str(key).lower() == "etag"
    ]
    body_keys = set(body)
    if (
        operation_id == "lockPackageRetentionAt91Days"
        and body_keys
        in (
            {"id", "name", "type", "properties"},
            {"id", "name", "type", "etag", "properties"},
        )
        and str(body.get("id", "")).lower() == expected_id.lower()
        and body.get("name") == "default"
        and body.get("type")
        == "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies"
        and body.get("etag") in (None, "")
        and all(value in (None, "") for value in header_etags)
        and isinstance(properties, Mapping)
        and set(properties)
        == {"immutabilityPeriodSinceCreationInDays", "state"}
        and properties["state"] == "Deleted"
        and type(properties["immutabilityPeriodSinceCreationInDays"]) is int
        and properties["immutabilityPeriodSinceCreationInDays"] == 0
    ):
        # Storage RP can retain the deleted child resource as an HTTP 200
        # tombstone even though the parent container has no active policy.
        # Normalize only this exact no-ETag, zero-day package-policy shape to
        # the existing create-only absence decision.  The executor will still
        # use If-None-Match:* and the terminal readback must be Locked >= 91.
        return "absent", _policy_checked_context(
            operation_id,
            policy,
            {"executionDecision": "apply-exact", "etag": None},
        )
    if (
        str(body.get("id", "")).lower() != expected_id.lower()
        or body.get("name") != "default"
        or body.get("type")
        != "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies"
        or not isinstance(properties, Mapping)
        or set(properties)
        != {
            "allowProtectedAppendWrites",
            "allowProtectedAppendWritesAll",
            "immutabilityPeriodSinceCreationInDays",
            "state",
        }
        or properties["allowProtectedAppendWrites"] is not False
        or properties["allowProtectedAppendWritesAll"] is not False
        or type(properties["immutabilityPeriodSinceCreationInDays"]) is not int
    ):
        fail(f"{operation_id} WORM policy prestate drifted")
    days = properties["immutabilityPeriodSinceCreationInDays"]
    state = properties["state"]
    if state == "Locked" and days >= 91:
        return "exact", _policy_checked_context(
            operation_id,
            policy,
            {"executionDecision": "adopt-exact", "adopted": {}},
        )
    if operation_id == "lockPackageRetentionAt91Days":
        if state not in {"Locked", "Unlocked"} or not 1 <= days <= 91:
            fail("package WORM policy is outside the supported resumable prestate")
    elif state != "Locked" or days != 30:
        fail(f"{operation_id} is not an exact locked 30-day policy")
    return "exact", _policy_checked_context(
        operation_id,
        policy,
        {"executionDecision": "apply-exact", "etag": _etag(envelope, operation_id)},
    )


def _adopted_projection(
    operation: Mapping[str, Any],
    envelope: Mapping[str, Any],
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    operation_id = operation["id"]
    resources = {item["id"]: item for item in plan["resourceInventory"]}
    result: dict[str, Any]
    if operation_id == "createPublisherApplication":
        item = _graph_one(envelope, operation_id)
        result = {"objectId": item.get("id"), "appId": item.get("appId")}
    elif operation_id == "createPublisherServicePrincipal":
        item = _graph_one(envelope, operation_id)
        result = {
            "objectId": item.get("id"),
            "appId": item.get("appId"),
            "principalId": item.get("id"),
        }
    elif operation_id == "grantPublisherGraphApplicationReadAll":
        item = _graph_one(envelope, operation_id)
        assignments = item.get("appRoleAssignments")
        if not isinstance(assignments, list) or len(assignments) != 1:
            fail("publisher Graph assignment adoption is not sole")
        assignment = assignments[0]
        if not isinstance(assignment, Mapping):
            fail("publisher Graph assignment adoption is not one object")
        result = {
            "assignmentId": assignment.get("id"),
            "resourceId": assignment.get("resourceId"),
        }
    else:
        identity_targets = {
            "createBridgeIdentity": "bridgeIdentity",
            "createSignerIdentity": "signerIdentity",
            "createProductionActivationIdentity": "productionActivationIdentity",
        }
        if operation_id in identity_targets:
            target = resources[identity_targets[operation_id]]["resourceId"]
            result = _identity_adopted(envelope, target)
        elif operation_id == "createStoppedPrivateBridge":
            body = _body_mapping(envelope, operation_id)
            result = {
                "resourceId": body.get("id"),
                "name": body.get("name"),
                "etag": _etag(envelope, operation_id),
            }
        elif operation_id == "createSigningKeyVersion":
            properties = _properties(envelope, operation_id)
            attributes = properties.get("attributes")
            if not isinstance(attributes, Mapping) or type(attributes.get("exp")) is not int:
                fail("adopted signing key lacks one exact live expiry")
            result = {
                "keyUriWithVersion": properties.get("keyUriWithVersion"),
                "expiresAt": _stamp(
                    dt.datetime.fromtimestamp(
                        attributes["exp"], tz=dt.timezone.utc
                    )
                ),
            }
        elif operation_id == "uploadVersionedBridgePackage":
            url = bootstrap._operation_readback_url(operation_id, plan, authorization)
            result = {
                "blob": (
                    f"v2/control/{authorization['source']['mergedMain']['commitSha']}/"
                    "paperdesk-private-release-bridge.zip"
                ),
                "etag": _etag(envelope, operation_id),
                "versionId": envelope["headers"].get("x-ms-version-id"),
                "url": url,
            }
        elif operation_id == "createInitialIdleActivationFence":
            contract = bootstrap._validator_contract(
                f"operation:{operation_id}", plan, authorization
            )
            result = {
                "url": contract["expectedUrl"],
                "etag": _etag(envelope, operation_id),
                "versionId": envelope["headers"].get("x-ms-version-id"),
                "sha256": contract["expectedBodySha256"],
            }
        else:
            result = {}
    expected_fields = set(policy["adoptedProjectionFields"] or [])
    if set(result) != expected_fields:
        fail(f"{operation_id} adoption cannot satisfy the source context policy")
    return result


def _policy_checked_context(
    operation_id: str,
    policy: Mapping[str, Any],
    context: Mapping[str, Any],
) -> dict[str, Any]:
    decision = context.get("executionDecision")
    if decision not in policy["allowedDecisions"]:
        fail(f"{operation_id} decision is outside the source context policy")
    if decision == "apply-exact":
        expected = {"executionDecision", *policy["observedApplyFields"]}
    elif decision == "adopt-pending-execution-empty-proof":
        if operation_id != "createPrivateControllerLockContainer":
            fail("pending empty-container proof is outside the controller container")
        expected = {"executionDecision"}
    else:
        expected = {"executionDecision", "adopted"}
        adopted = context.get("adopted")
        if not isinstance(adopted, dict) or set(adopted) != set(
            policy["adoptedProjectionFields"] or []
        ):
            fail(f"{operation_id} adopted projection drifted from source policy")
    if set(context) != expected:
        fail(f"{operation_id} context drifted from the source context policy")
    if decision == "apply-exact":
        serialized = bootstrap.canonical_json_bytes(context).decode("utf-8")
        for dependency in policy["executorDerivedDependencies"]:
            terminal_name = dependency.rsplit(".", 1)[-1]
            if f'"{terminal_name}":' in serialized:
                fail(
                    f"{operation_id} preflight authors executor-derived dependency {dependency}"
                )
    return dict(context)


def _is_future_executor_owned_remove(operation: Mapping[str, Any]) -> bool:
    kind = str(operation.get("kind", ""))
    return operation.get("temporary") is True and (
        kind.startswith("temporary-remove") or kind.startswith("stop-owned")
    )


def _operation_admission(
    operation: Mapping[str, Any],
    envelope: Mapping[str, Any],
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    observed_at: dt.datetime,
    uploader_ipv4: str,
    policy: Mapping[str, Any],
    dependency_facts: Mapping[str, Mapping[str, Any]],
    built_in_role_definitions: Mapping[str, Mapping[str, Any]] | None = None,
    graph_service_principal_envelope: Mapping[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    """Derive an admission from source policy plus exact read-only prestate.

    Values created by an earlier bootstrap operation (post-create ETags,
    version IDs, object IDs and principal IDs) are intentionally never placed
    in the preflight context.  The executor must capture and bind those values
    from its own mutation readback.
    """

    operation_id = str(operation["id"])
    kind = str(operation["kind"])
    status = envelope["status"]
    if status not in {200, 404}:
        if operation_id == "uploadVersionedBridgePackage" and status == 403:
            error = _exact_keys(
                _body_mapping(envelope, operation_id),
                {"storageErrorCode"},
                "package blob pre-network error",
            )
            if error["storageErrorCode"] not in {
                "AuthenticationFailed",
                "AuthorizationFailure",
                "AuthorizationPermissionMismatch",
            }:
                fail("package blob preflight is not blocked by temporary access")
            return "network-inaccessible", _policy_checked_context(
                operation_id,
                policy,
                {"executionDecision": "apply-exact"},
            )
        if operation_id == "readBackExactSigningPublicJwk" and status == 403:
            body = _body_mapping(envelope, operation_id)
            error = body.get("error")
            inner = error.get("innererror") if isinstance(error, Mapping) else None
            if (
                not isinstance(error, Mapping)
                or error.get("code") != "Forbidden"
                or not isinstance(inner, Mapping)
                or inner.get("code") != "ForbiddenByRbac"
            ):
                fail("signing JWK preflight is not blocked by temporary RBAC")
            return "temporary-access-inaccessible", _policy_checked_context(
                operation_id,
                policy,
                {"executionDecision": "apply-exact"},
            )
        if (
            operation_id
            in bootstrap.TEMPORARY_ACCESS_INACCESSIBLE_OPERATIONS
            and status == 403
        ):
            error = _exact_keys(
                _body_mapping(envelope, operation_id),
                {"storageErrorCode"},
                f"{operation_id} temporary storage-access error",
            )
            if error["storageErrorCode"] not in {
                "AuthenticationFailed",
                "AuthorizationFailure",
                "AuthorizationPermissionMismatch",
            }:
                fail(
                    f"{operation_id} preflight is not blocked by temporary RBAC"
                )
            return "temporary-access-inaccessible", _policy_checked_context(
                operation_id,
                policy,
                {"executionDecision": "apply-exact"},
            )
        fail(f"{operation_id} preflight returned unsupported status {status}")

    if status == 200 and operation_id in {
        "createStoppedPrivateBridge",
        "attachFiveUamisOnlyToBridge",
    }:
        body = _body_mapping(envelope, operation_id)
        properties = _properties(envelope, operation_id)
        identity = body.get("identity")
        resources = {item["id"]: item for item in plan["resourceInventory"]}
        bridge = resources["bridgeSite"]
        if (
            str(body.get("id", "")).lower() != bridge["resourceId"].lower()
            or body.get("name") != bridge["name"]
            or body.get("kind") != "app,linux"
            or properties.get("state") != "Stopped"
            or properties.get("httpsOnly") is not True
            or properties.get("publicNetworkAccess") != "Disabled"
            or str(properties.get("serverFarmId", "")).lower()
            != resources["bridgeAppServicePlan"]["resourceId"].lower()
            or str(properties.get("virtualNetworkSubnetId", "")).lower()
            != resources["integrationSubnet"]["resourceId"].lower()
            or not bootstrap._safe_bridge_outbound_vnet_routing(
                properties.get("outboundVnetRouting")
            )
        ):
            fail("existing bridge posture is outside the recovery boundary")
        prior = {}
        for dependency in (
            "createBridgeIdentity",
            "adoptExistingRegistryWriterIdentity",
            "adoptExistingRegistryReaderIdentity",
            "createSignerIdentity",
            "createProductionActivationIdentity",
        ):
            facts = dependency_facts.get(dependency)
            if not isinstance(facts, Mapping):
                fail("bridge recovery identity dependency is absent")
            prior[dependency] = {"projection": {
                "id": facts.get("resourceId"),
                "clientId": facts.get("clientId"),
                "principalId": facts.get("principalId"),
            }}
        if bootstrap._safe_bridge_no_identity(identity):
            mode, identity_ids = "pristine-no-identity", []
        else:
            identity_ids = bootstrap._validate_exact_bridge_uami_inventory(identity, prior)
            mode = "exact-five-user-assigned"
        if operation_id == "createStoppedPrivateBridge":
            return "exact", _policy_checked_context(operation_id, policy, {
                "executionDecision": "adopt-exact",
                "adopted": {
                    "resourceId": body["id"], "name": body["name"],
                    "etag": _etag(envelope, operation_id),
                        "bridgeIdentityMode": mode,
                        "identityResourceIds": identity_ids,
                        "identityProjectionSha256": bootstrap.sha256_bytes(
                            bootstrap.canonical_json_bytes(identity)
                        ),
                },
            })
        bridge_facts = dependency_facts.get("createStoppedPrivateBridge")
        if (
            not isinstance(bridge_facts, Mapping)
            or bridge_facts.get("bridgeIdentityMode") != mode
            or bridge_facts.get("identityResourceIds") != identity_ids
            or bridge_facts.get("etag") != _etag(envelope, operation_id)
        ):
            fail("bridge attachment state changed during observation")
        if mode == "exact-five-user-assigned":
            return "exact", _policy_checked_context(operation_id, policy, {
                "executionDecision": "adopt-exact",
                "adopted": {
                    "identityResourceIds": identity_ids,
                    "expectedEtag": _etag(envelope, operation_id),
                    "identityProjectionSha256": bootstrap.sha256_bytes(
                        bootstrap.canonical_json_bytes(identity)
                    ),
                },
            })
        return "exact", _policy_checked_context(
            operation_id, policy, {"executionDecision": "apply-exact"}
        )

    # Microsoft Graph collection queries return HTTP 200 with ``value: []``
    # when the source-named application or service principal is absent.  Treat
    # that exact, unpaginated empty collection as logical absence for the three
    # create-or-adopt operations; HTTP status alone cannot express this state.
    graph_create_or_adopt = {
        "createPublisherApplication",
        "createPublisherServicePrincipal",
        "grantPublisherGraphApplicationReadAll",
    }
    if status == 200 and operation_id in graph_create_or_adopt:
        values = _graph_collection(envelope, operation_id)
        if not values:
            status = 404
        elif len(values) != 1:
            fail(f"{operation_id} must resolve to at most one Graph object")
        elif operation_id == "createPublisherServicePrincipal":
            application = dependency_facts.get("createPublisherApplication")
            service = values[0]
            service_object_id = service.get("id")
            service_app_id = service.get("appId")
            assignments = service.get("appRoleAssignments")
            if (
                not isinstance(assignments, list)
                or service.get("appRoleAssignments@odata.nextLink")
                not in {None, ""}
            ):
                fail("publisher Graph assignment inventory is partial or paginated")
            if (
                not isinstance(application, Mapping)
                or service_app_id != application.get("appId")
                or service.get("displayName")
                != next(
                    item["name"]
                    for item in plan["resourceInventory"]
                    if item["id"] == "publisherServicePrincipal"
                )
                or service.get("accountEnabled") is not True
                or service.get("servicePrincipalType") != "Application"
                or service.get("passwordCredentials") != []
                or service.get("keyCredentials") != []
            ):
                fail(
                    "publisher service principal is not bound to the adopted application"
                )
            bootstrap._guid(
                service_object_id, "observed publisher service principal object ID"
            )
            bootstrap._guid(service_app_id, "observed publisher service principal app ID")
        elif operation_id == "grantPublisherGraphApplicationReadAll":
            publisher = dependency_facts.get("createPublisherServicePrincipal")
            service = values[0]
            assignments = service.get("appRoleAssignments")
            if graph_service_principal_envelope is None:
                fail("Microsoft Graph service principal inventory is missing")
            graph_service_id = _microsoft_graph_service_principal_id(
                graph_service_principal_envelope
            )
            if (
                not isinstance(publisher, Mapping)
                or service.get("id") != publisher.get("objectId")
                or service.get("appId") != publisher.get("appId")
                or service.get("accountEnabled") is not True
                or service.get("servicePrincipalType") != "Application"
                or service.get("passwordCredentials") != []
                or service.get("keyCredentials") != []
                or not isinstance(assignments, list)
                or service.get("appRoleAssignments@odata.nextLink")
                not in {None, ""}
            ):
                fail("publisher Graph assignment inventory is not exact")
            if not assignments:
                status = 404
            else:
                if (
                    len(assignments) != 1
                    or not isinstance(assignments[0], Mapping)
                    or set(assignments[0])
                    != {"id", "principalId", "resourceId", "appRoleId"}
                    or bootstrap._graph_app_role_assignment_id(
                        assignments[0].get("id"),
                        "observed publisher Graph assignment ID",
                    )
                    != assignments[0].get("id")
                    or assignments[0].get("principalId") != publisher.get("objectId")
                    or assignments[0].get("resourceId") != graph_service_id
                    or assignments[0].get("appRoleId")
                    != bootstrap.AzureCliBootstrapTransport.GRAPH_APPLICATION_READ_ALL
                ):
                    fail("pre-existing publisher Graph assignment is not sole and exact")
                return "exact", _policy_checked_context(
                    operation_id,
                    policy,
                    {
                        "executionDecision": "adopt-exact",
                        "adopted": _adopted_projection(
                            operation, envelope, plan, authorization, policy
                        ),
                    },
                )

    if status == 200 and operation_id in {
        "createPrivatePackageContainer",
        "createPrivateControllerLockContainer",
        "createPrivateActivationFenceContainer",
    }:
        if operation_id == "createPrivateControllerLockContainer":
            _private_container_adopted(envelope, operation_id, plan)
            return "adopt-pending-execution-empty-proof", _policy_checked_context(
                operation_id,
                policy,
                {"executionDecision": "adopt-pending-execution-empty-proof"},
            )
        adopted = _private_container_adopted(envelope, operation_id, plan)
        return "exact", _policy_checked_context(
            operation_id,
            policy,
            {"executionDecision": "adopt-exact", "adopted": adopted},
        )

    if operation_id in {
        "lockPackageRetentionAt91Days",
        "extendAcceptedRetentionFrom30To91Days",
        "extendResultRetentionFrom30To91Days",
    }:
        return _worm_policy_admission(operation_id, envelope, plan, policy)

    if operation_id == "createSolePublisherFicToSignedBootstrapSource":
        if status != 200:
            fail("publisher FIC inventory must use one Graph collection response")
        application, credentials = bootstrap._publisher_fic_inventory(
            _body_mapping(envelope, operation_id),
            plan,
            authorization,
            operation_id,
        )
        adopted_application = dependency_facts.get("createPublisherApplication")
        if adopted_application is None:
            if application is not None:
                fail("publisher application appeared after its absence observation")
            return "absent", _policy_checked_context(
                operation_id,
                policy,
                {"executionDecision": "apply-exact"},
            )
        if (
            application is None
            or application.get("id") != adopted_application.get("objectId")
            or application.get("appId") != adopted_application.get("appId")
        ):
            fail("publisher FIC inventory is not bound to the adopted application")
        if not credentials:
            return "absent", _policy_checked_context(
                operation_id,
                policy,
                {"executionDecision": "apply-exact"},
            )
        bootstrap._validate_exact_publisher_fic(
            credentials[0], plan, authorization, operation_id
        )
        return "exact", _policy_checked_context(
            operation_id,
            policy,
            {"executionDecision": "adopt-exact", "adopted": {}},
        )

    if operation_id == "claimAzureSingleUseAuthorization":
        if status != 404:
            fail("Azure-global single-use claim already exists")
        return "absent", _policy_checked_context(
            operation_id, policy, {"executionDecision": "apply-exact"}
        )

    if _is_future_executor_owned_remove(operation):
        if status not in {200, 404}:
            fail(f"{operation_id} future-owned cleanup observation is invalid")
        context: dict[str, Any] = {"executionDecision": "apply-exact"}
        if operation_id == "removeOwnedUploaderIpv4Rule":
            if status != 200:
                fail("storage account is absent while binding ACL restoration")
            context.update(
                {
                    "uploaderIpv4": uploader_ipv4,
                    "restoreNetworkAcls": _storage_acl(envelope),
                }
            )
        return "owned-present", _policy_checked_context(
            operation_id, policy, context
        )

    # The storage-account read itself is necessarily 200; temporary-rule
    # absence is a property of the exact ACL projection, not HTTP absence.
    if operation_id == "addOwnedUploaderIpv4Rule":
        if status != 200:
            fail("storage account is absent while observing uploader access")
        acl = _storage_acl(envelope)
        expected_ip = uploader_ipv4.split("/", 1)[0]
        if any(
            isinstance(rule, dict) and rule.get("value") == expected_ip
            for rule in acl["ipRules"]
        ):
            fail("temporary uploader IPv4 access is already present")
        return "absent", _policy_checked_context(operation_id, policy, {
            "executionDecision": "apply-exact",
            "uploaderIpv4": uploader_ipv4,
            "preNetworkAcls": acl,
        })

    delete_like = kind.startswith(("delete-", "remove-", "temporary-remove"))
    create_only = kind.startswith(("azure-global-create-only", "azure-ad-create-only"))
    temporary_add = kind.startswith("temporary-add")
    create_or_adopt = kind.startswith("create-or-adopt") or kind.startswith(
        "create-new-or-adopt"
    )

    if status == 404 and delete_like:
        return "absent", _policy_checked_context(
            operation_id,
            policy,
            {"executionDecision": "adopt-exact", "adopted": {}},
        )
    if status == 404 and (create_only or temporary_add or create_or_adopt):
        context: dict[str, Any] = {"executionDecision": "apply-exact"}
        if operation_id == "createSigningKeyVersion":
            context["expiresAt"] = _stamp(observed_at + dt.timedelta(days=60))
        return "absent", _policy_checked_context(operation_id, policy, context)
    if status == 200 and temporary_add:
        fail(f"temporary access is already present before bootstrap: {operation_id}")
    if (
        status == 200
        and (create_only or create_or_adopt)
        and "adopt-exact" in policy["allowedDecisions"]
    ):
        return "exact", _policy_checked_context(
            operation_id,
            policy,
            {
                "executionDecision": "adopt-exact",
                "adopted": _adopted_projection(
                    operation, envelope, plan, authorization, policy
                ),
            },
        )

    # Fixed existing resources may be adopted only through source validators.
    if str(kind).startswith("adopt-existing"):
        if status != 200:
            fail(f"required existing resource is absent: {operation_id}")
        return "exact", _policy_checked_context(
            operation_id,
            policy,
            {"executionDecision": "adopt-exact", "adopted": {}},
        )

    context = {"executionDecision": "apply-exact"}
    admission_status = "exact" if status == 200 else "absent"
    if operation_id == "retireLegacyPublisherFic":
        item = _graph_one(envelope, operation_id)
        credential_id = item.get("id")
        if not isinstance(credential_id, str) or not GUID.fullmatch(credential_id):
            fail("legacy FIC response has no exact object ID")
        context["legacyFederatedCredentialId"] = credential_id
    elif operation_id == "detachWriterAndReaderFromLegacyBridge":
        context["etag"] = _etag(envelope, operation_id)
    elif operation_id == "createSigningKeyVersion":
        context["expiresAt"] = _stamp(observed_at + dt.timedelta(days=60))
    elif operation_id == "removeOwnedUploaderIpv4Rule":
        context.update(
            {
                "uploaderIpv4": uploader_ipv4,
                "restoreNetworkAcls": _storage_acl(envelope),
            }
        )
    elif operation_id == "configureBridgeExactVersionedPackageAndCriticalSettings":
        if status != 200:
            fail("bridge app-settings prestate is not one exact readable resource")
        settings = {} if status == 404 else _app_settings(envelope)
        if settings:
            fail(
                "bridge app-settings prestate must be empty so the canonical preflight remains secret-free"
            )
        context.update(
            {
                "preAppSettings": settings,
                "preAppSettingsSha256": bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes(settings)
                ),
                "preAppSettingsEtag": _etag(envelope, operation_id),
                "bootstrapSelfTestStaticControl": (
                    bootstrap._bootstrap_self_test_static_control(authorization)
                ),
            }
        )
    elif operation_id in {"createCustomRoleDefinitions", "createExactRoleAssignments"}:
        body = _body_mapping(envelope, operation_id)
        values = body.get("value")
        if (
            not isinstance(values, list)
            or body.get("nextLink") not in {None, ""}
            or any(not isinstance(item, dict) for item in values)
        ):
            fail(f"{operation_id} response is partial or paginated")
        if operation_id == "createCustomRoleDefinitions":
            bootstrap._reject_residual_temporary_role_definitions(
                values, label="preflight custom role-definition inventory"
            )
            expected_specs = bootstrap._custom_role_definition_specs(plan)
            expected_by_resource_id = {
                str(projection["id"]).lower(): (member_id, projection)
                for member_id, projection in expected_specs.items()
            }
        else:
            bootstrap._reject_residual_temporary_role_assignments(
                values,
                plan=plan,
                label="preflight role-assignment inventory",
            )
            resources = {item["id"]: item for item in plan["resourceInventory"]}

            def principal_id(principal: str) -> str:
                fixed = resources.get(principal, {}).get("principalId")
                if isinstance(fixed, str) and GUID.fullmatch(fixed):
                    return fixed
                operation_by_principal = {
                    "publisherServicePrincipal": "createPublisherServicePrincipal",
                    "bridgeIdentity": "createBridgeIdentity",
                    "signerIdentity": "createSignerIdentity",
                    "productionActivationIdentity": "createProductionActivationIdentity",
                }
                dependency = dependency_facts.get(
                    operation_by_principal.get(principal, ""), {}
                ).get("principalId")
                if not isinstance(dependency, str) or not GUID.fullmatch(dependency):
                    fail(
                        f"role assignment principal is not yet exactly observed: {principal}"
                    )
                return dependency

            role_by_id = {role["assignmentId"]: role for role in plan["roleMatrix"]}
            expected_specs = {member_id: None for member_id in role_by_id}
            expected_by_resource_id = {
                str(
                    bootstrap._role_assignment_spec(
                        plan,
                        role,
                        # The principal does not affect the deterministic
                        # assignment resource ID.  A present member is rebuilt
                        # below with its exactly observed principal before it
                        # can be accepted.
                        "00000000-0000-4000-8000-000000000000",
                    )["id"]
                ).lower(): (member_id, role)
                for member_id, role in role_by_id.items()
            }
        present: set[str] = set()
        for item in values:
            item_id = str(item.get("id", "")).lower()
            expected_item = expected_by_resource_id.get(item_id)
            if expected_item is None:
                continue
            member_id, projection_or_role = expected_item
            if member_id in present:
                fail(f"{operation_id} response contains a duplicate member")
            if operation_id == "createCustomRoleDefinitions":
                projection = projection_or_role
                observed_projection = bootstrap._project_role_definition(item)
            else:
                role = projection_or_role
                projection = bootstrap._role_assignment_spec(
                    plan, role, principal_id(role["principal"])
                )
                observed_projection = bootstrap._project_role_assignment(item)
            if observed_projection != projection:
                fail(f"{operation_id} member is a third state: {member_id}")
            present.add(member_id)
        context["memberStates"] = {
            item: "exact" if item in present else "absent"
            for item in sorted(expected_specs)
        }
        if operation_id == "createCustomRoleDefinitions":
            context["builtInRoleDefinitionProjections"] = (
                bootstrap._validate_builtin_role_definition_projections(
                    built_in_role_definitions, plan
                )
            )
        if all(value == "absent" for value in context["memberStates"].values()):
            admission_status = "absent"
        elif all(value == "exact" for value in context["memberStates"].values()):
            admission_status = "exact"
        else:
            admission_status = "owned-present"
    return admission_status, _policy_checked_context(operation_id, policy, context)


def _preflight_probe(
    probe_id: str,
    request: ReadRequest,
    envelope: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "id": probe_id,
        "phase": "preflight",
        "method": request.method,
        "url": request.url,
        "requestBodySha256": (
            bootstrap.sha256_bytes(b"") if request.method == "POST" else None
        ),
        "status": envelope["status"],
        "responseSha256": response_digest(envelope),
        "validatorId": None,
        "validatorContract": None,
    }


def _readback_probe(probe_id: str, contract: Mapping[str, Any]) -> dict[str, Any]:
    method = contract["expectedMethod"]
    return {
        "id": probe_id,
        "phase": "readback",
        "method": method,
        "url": contract["expectedUrl"],
        "requestBodySha256": (
            bootstrap.sha256_bytes(b"") if method == "POST" else None
        ),
        "status": contract["expectedStatus"],
        "responseSha256": None,
        "validatorId": contract["validatorId"],
        "validatorContract": dict(contract),
    }


def build_read_only_observation(
    session: ReadOnlySession,
    *,
    source: Mapping[str, Any],
    authorization_id: str,
    receipt_directory: Path,
    observed_at: dt.datetime,
    uploader_ipv4: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return canonical-ready preflight and non-executable auth template."""

    try:
        network = ipaddress.ip_network(uploader_ipv4, strict=True)
    except ValueError as exc:
        raise ObserveError("uploader IPv4 must be one canonical address") from exc
    if network.version != 4 or network.prefixlen != 32:
        fail("uploader IPv4 must be one exact /32")

    reviewed_plan, plan_sha256 = bootstrap.load_plan()
    package = bootstrap.build_package_descriptor()
    azure = _account(session)
    kernel = _authorization_kernel(
        plan=reviewed_plan,
        plan_sha256=plan_sha256,
        package=package,
        source=source,
        azure=azure,
        authorization_id=authorization_id,
        receipt_directory=receipt_directory,
        observed_at=observed_at,
    )
    policy_authorization = _policy_authorization(kernel)
    plan = bootstrap.bind_temporary_role_ids(reviewed_plan, authorization_id)

    probes: list[dict[str, Any]] = []
    admissions: list[dict[str, Any]] = []
    dependency_facts: dict[str, Mapping[str, Any]] = {}
    cache: dict[tuple[str, str], dict[str, Any]] = {}
    azure_operations = [
        item
        for item in plan["mutations"]
        if item["kind"] != "local-create-only-canonical-evidence"
    ]
    for index, operation in enumerate(azure_operations):
        validator_id = f"operation:{operation['id']}"
        contract = bootstrap._validator_contract(
            validator_id, plan, policy_authorization
        )
        policy = bootstrap._operation_context_policy(
            operation["id"], plan, policy_authorization
        )
        if contract.get("preflightContextPolicy") != policy:
            fail("validator contract is not bound to the shared source context policy")
        request = ReadRequest(
            method=contract["expectedMethod"], url=contract["expectedUrl"]
        )
        key = (request.method, request.url)
        if key not in cache:
            cache[key] = _normalize_response(request, session.read(request))
        envelope = cache[key]
        built_in_role_definitions: dict[str, Mapping[str, Any]] | None = None
        graph_service_principal_envelope: Mapping[str, Any] | None = None
        extra_preflight_probes: list[dict[str, Any]] = []
        if operation["id"] == "claimAzureSingleUseAuthorization":
            lock_request = ReadRequest(method="GET", url=bootstrap._cleanup_lock_inventory_url())
            lock_envelope = _normalize_response(lock_request, session.read(lock_request))
            if lock_envelope["status"] != 200:
                fail("cleanup deletion-lock inventory is not readable")
            lock_projection = bootstrap._cleanup_lock_inventory_projection(
                _body_mapping(lock_envelope, "cleanup deletion locks"), plan
            )
            lock_probe = _preflight_probe("preflight-cleanup-lock-inventory", lock_request, lock_envelope)
            lock_probe["responseSha256"] = bootstrap.sha256_bytes(bootstrap.canonical_json_bytes(lock_projection))
            extra_preflight_probes.append(lock_probe)
        temporary_definition_url = (
            bootstrap._temporary_role_definition_readback_url(
                operation["id"], plan
            )
        )
        if temporary_definition_url is not None:
            definition_request = ReadRequest(
                method="GET", url=temporary_definition_url
            )
            definition_key = (
                definition_request.method,
                definition_request.url,
            )
            if definition_key not in cache:
                cache[definition_key] = _normalize_response(
                    definition_request, session.read(definition_request)
                )
            definition_envelope = cache[definition_key]
            if definition_envelope["status"] != 404:
                fail(
                    "temporary role definition is already present before bootstrap: "
                    + operation["id"]
                )
            extra_preflight_probes.append(
                _preflight_probe(
                    f"preflight-{index:02d}-temporary-definition",
                    definition_request,
                    definition_envelope,
                )
            )
        if operation["id"] == "createCustomRoleDefinitions":
            built_in_role_definitions = {}
            definition_ids = sorted(
                {
                    str(role["definitionId"])
                    for role in plan["roleMatrix"]
                    if role.get("definitionKind") == "BuiltInRole"
                }
            )
            for definition_index, definition_id in enumerate(definition_ids):
                definition_url = (
                    "https://management.azure.com/subscriptions/"
                    f"{bootstrap.SUBSCRIPTION}/providers/Microsoft.Authorization/"
                    f"roleDefinitions/{definition_id}?api-version=2022-04-01"
                )
                definition_request = ReadRequest(method="GET", url=definition_url)
                definition_key = (definition_request.method, definition_request.url)
                if definition_key not in cache:
                    cache[definition_key] = _normalize_response(
                        definition_request, session.read(definition_request)
                    )
                definition_envelope = cache[definition_key]
                if definition_envelope["status"] != 200:
                    fail("required built-in role definition is not readable")
                definition_body = _body_mapping(
                    definition_envelope, f"built-in role {definition_id}"
                )
                built_in_role_definitions[definition_id] = (
                    bootstrap._project_role_definition(definition_body)
                )
                extra_preflight_probes.append(
                    _preflight_probe(
                        f"preflight-{index:02d}-builtin-{definition_index}",
                        definition_request,
                        definition_envelope,
                    )
                )
        if operation["id"] == "grantPublisherGraphApplicationReadAll":
            graph_request = ReadRequest(
                method="GET",
                url=bootstrap._microsoft_graph_service_principal_inventory_url(),
            )
            graph_key = (graph_request.method, graph_request.url)
            if graph_key not in cache:
                cache[graph_key] = _normalize_response(
                    graph_request, session.read(graph_request)
                )
            graph_service_principal_envelope = cache[graph_key]
            extra_preflight_probes.append(
                _preflight_probe(
                    f"preflight-{index:02d}-graph-resource-sp",
                    graph_request,
                    graph_service_principal_envelope,
                )
            )
        status, context = _operation_admission(
            operation,
            envelope,
            plan,
            policy_authorization,
            observed_at,
            str(network),
            policy,
            dependency_facts,
            built_in_role_definitions,
            graph_service_principal_envelope,
        )
        pre_id = f"preflight-{index:02d}"
        read_id = f"readback-{index:02d}"
        probes.append(_preflight_probe(pre_id, request, envelope))
        probes.extend(extra_preflight_probes)
        probes.append(_readback_probe(read_id, contract))
        admissions.append(
            {
                "operationId": operation["id"],
                "status": status,
                "probeIds": [pre_id, *[item["id"] for item in extra_preflight_probes]],
                "desiredProbeIds": [read_id],
                "context": context,
            }
        )
        adopted = context.get("adopted")
        if operation["id"] in {
            "adoptExistingRegistryWriterIdentity",
            "adoptExistingRegistryReaderIdentity",
        }:
            resource_id = {
                "adoptExistingRegistryWriterIdentity": "registryWriterIdentity",
                "adoptExistingRegistryReaderIdentity": "registryReaderIdentity",
            }[operation["id"]]
            resource = next(
                item for item in plan["resourceInventory"] if item["id"] == resource_id
            )
            # These legacy identity admissions intentionally retain an empty
            # public adopted context.  Recovery still needs their identity
            # facts, so derive the private dependency exclusively from the
            # exact live GET envelope already validated for this operation.
            # The plan contributes only the fixed target resource ID; it is
            # never a fallback source for clientId or principalId.
            live_identity = _identity_adopted(
                envelope, resource["resourceId"]
            )
            if (
                live_identity["clientId"] != resource["clientId"]
                or live_identity["principalId"] != resource["principalId"]
            ):
                fail("fixed registry identity live projection drifted")
            dependency_facts[operation["id"]] = live_identity
        elif isinstance(adopted, Mapping):
            dependency_facts[operation["id"]] = dict(adopted)

    marker_inventory_projections: list[dict[str, Any]] = []
    for request_spec in bootstrap._temporary_role_marker_inventory_requests(plan):
        request = ReadRequest(method="GET", url=request_spec["url"])
        envelope = _normalize_response(request, session.read(request))
        if envelope["status"] != 200:
            fail("read-only temporary role marker inventory is not readable")
        document = _body_mapping(
            envelope, f"read-only {request_spec['kind']}"
        )
        validated = bootstrap._validate_temporary_role_marker_inventory_document(
            document,
            kind=request_spec["kind"],
            plan=plan,
            label=f"read-only {request_spec['kind']}",
        )
        marker_inventory_projections.append(
            {
                **request_spec,
                "status": 200,
                "responseSha256": bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes(validated)
                ),
            }
        )
    marker_inventory_sha256 = bootstrap._temporary_role_marker_inventory_sha256(
        marker_inventory_projections, plan
    )

    retired_role_absence: list[dict[str, Any]] = []
    retired_observed_at = _stamp(observed_at)
    for request_spec in bootstrap._retired_temporary_role_absence_requests(plan):
        request = ReadRequest(method="GET", url=request_spec["url"])
        envelope = _normalize_response(request, session.read(request))
        if envelope["status"] != 404:
            fail(
                "read-only observation found a retired temporary role "
                f"{request_spec['kind']}"
            )
        retired_role_absence.append(
            {
                **request_spec,
                "status": 404,
                "responseSha256": response_digest(envelope),
                "temporaryRoleMarkerInventorySha256": marker_inventory_sha256,
                "observedAt": retired_observed_at,
            }
        )
    retired_role_absence = (
        bootstrap._validate_retired_temporary_role_absence_projection(
            retired_role_absence,
            plan,
            label="read-only retired temporary role absence",
            expected_observed_at=retired_observed_at,
        )
    )

    production_documents: dict[str, Any] = {}
    production_probe_ids: list[str] = []
    for request_spec in bootstrap._production_boundary_requests(plan):
        request = ReadRequest(
            method=request_spec["method"], url=request_spec["url"]
        )
        response = session.read(request)
        envelope = _normalize_production_boundary_response(request, response)
        production_documents[request_spec["id"]] = envelope["body"]
        probe_id = request_spec["id"]
        production_probe_ids.append(probe_id)
        probes.append(_preflight_probe(probe_id, request, envelope))
    production_boundary_observation = {
        "probeIds": production_probe_ids,
        "sourceProjection": bootstrap._project_production_boundary_documents(
            production_documents, plan
        ),
        "retiredTemporaryRoleAbsence": retired_role_absence,
    }

    postcondition_admissions: list[dict[str, Any]] = []
    for index, postcondition in enumerate(plan["postconditions"]):
        contract = bootstrap._validator_contract(
            f"postcondition:{postcondition['id']}", plan, policy_authorization
        )
        probe_id = f"postcondition-{index:02d}"
        probes.append(_readback_probe(probe_id, contract))
        postcondition_admissions.append(
            {"postconditionId": postcondition["id"], "probeIds": [probe_id]}
        )

    projection = {
        "schemaVersion": 1,
        "planId": plan["planId"],
        "probes": probes,
        "operationAdmissions": admissions,
        "postconditionAdmissions": postcondition_admissions,
        "productionBoundaryObservation": production_boundary_observation,
    }
    projection_sha256 = bootstrap.sha256_bytes(
        bootstrap.canonical_json_bytes(projection)
    )
    preflight = {
        "schemaVersion": 1,
        "status": "observed-read-only",
        "observedAt": _stamp(observed_at),
        "projection": projection,
        "projectionSha256": projection_sha256,
    }
    template = {
        "schemaVersion": 1,
        "templateType": TEMPLATE_TYPE,
        "status": TEMPLATE_STATUS,
        "executable": False,
        "repository": kernel["repository"],
        "authorizationId": kernel["authorizationId"],
        "source": kernel["source"],
        "executor": kernel["executor"],
        "plan": kernel["plan"],
        "azure": kernel["azure"],
        "observedPreflight": {
            "sha256": projection_sha256,
            "observedAt": preflight["observedAt"],
            "maximumAgeSeconds": bootstrap.MAX_PREFLIGHT_AGE_SECONDS,
        },
        "proposedValidity": kernel["proposedValidity"],
        "singleUse": kernel["singleUse"],
        "requiredResidualRiskAcceptance": {
            "id": "temporary-storage-ip-rules-and-recovery-residuals",
            "exactConfirmationText": (
                bootstrap.STORAGE_ACL_AND_RECOVERY_RESIDUAL_ACCEPTANCE
                + " " + bootstrap.DELETION_LOCK_RESIDUAL_ACCEPTANCE
                + " " + bootstrap.BRIDGE_CONFIG_HARD_DEATH_RESIDUAL_ACCEPTANCE
            ),
        },
        "ceremonyRequirements": [
            "independently-review-canonical-preflight",
            "obtain-fresh-explicit-user-authorization",
            "promote-proposedValidity-to-validity-within-freshness-window",
            "add-exact-confirmation-phrase-sha256",
            "include-exact-storage-acl-concurrency-residual-acceptance-in-confirmation",
            "include-exact-bridge-config-hard-death-residual-acceptance-in-confirmation",
            "emit-separate-canonical-executable-authorization",
        ],
    }
    # Round-trip the exact byte representation before returning it to a caller.
    for label, value in (("preflight", preflight), ("authorization template", template)):
        raw = bootstrap.canonical_json_bytes(value)
        if json.loads(raw.decode("utf-8")) != value:
            fail(f"{label} canonical round-trip failed")
    return preflight, template


def write_canonical(path: Path, value: Mapping[str, Any]) -> None:
    """Create one new canonical output; never replace an existing artifact."""

    if (
        path.exists()
        or path.is_symlink()
        or not path.parent.is_dir()
        or path.parent.is_symlink()
    ):
        fail("canonical output path must be new under an existing directory")
    descriptor = path.open("xb")
    with descriptor:
        descriptor.write(bootstrap.canonical_json_bytes(value))
        descriptor.flush()
        os.fsync(descriptor.fileno())
    try:
        parent_descriptor = os.open(path.parent, os.O_RDONLY)
    except OSError:
        parent_descriptor = None
    if parent_descriptor is not None:
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)


def main(
    argv: Sequence[str] | None = None,
    *,
    session_factory: Callable[[], ReadOnlySession] | None = None,
    clock: Callable[[], dt.datetime] | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Read Azure state only and create a canonical bootstrap preflight "
            "plus a deliberately non-executable authorization template."
        )
    )
    parser.add_argument("--source-evidence", type=Path, required=True)
    parser.add_argument("--authorization-id", required=True)
    parser.add_argument("--receipt-directory", type=Path, required=True)
    parser.add_argument("--uploader-ipv4", required=True)
    parser.add_argument("--preflight-output", type=Path, required=True)
    parser.add_argument("--authorization-template-output", type=Path, required=True)
    args = parser.parse_args(argv)
    now = clock or (lambda: dt.datetime.now(dt.timezone.utc))
    try:
        source, _ = bootstrap.load_json(
            args.source_evidence, require_canonical=True
        )
        if not isinstance(source, Mapping):
            fail("source evidence must be one canonical object")
        if args.preflight_output == args.authorization_template_output:
            fail("preflight and authorization-template outputs must be distinct")
        for output in (
            args.preflight_output,
            args.authorization_template_output,
        ):
            if (
                not output.is_absolute()
                or not output.parent.is_dir()
                or output.parent.is_symlink()
                or output.exists()
                or output.is_symlink()
            ):
                fail("observer output must be a new absolute file under a real directory")
        if (
            not args.receipt_directory.is_absolute()
            or not args.receipt_directory.parent.is_dir()
            or args.receipt_directory.parent.is_symlink()
            or args.receipt_directory.exists()
            or args.receipt_directory.is_symlink()
        ):
            fail("future receipt directory must be absent under one real existing parent")
        observed_at = now().astimezone(dt.timezone.utc)
        if observed_at.tzinfo != dt.timezone.utc:
            fail("observer clock is not exact UTC")
        session = (
            session_factory()
            if session_factory is not None
            else AzureCliReadOnlySession(clock=now)
        )
        preflight, template = build_read_only_observation(
            session,
            source=source,
            authorization_id=args.authorization_id,
            receipt_directory=args.receipt_directory,
            observed_at=observed_at,
            uploader_ipv4=args.uploader_ipv4,
        )
        # Preflight is written first.  If the second create-only write fails,
        # the non-executable partial output remains reviewable and is never
        # silently replaced.
        write_canonical(args.preflight_output, preflight)
        write_canonical(args.authorization_template_output, template)
        outputs = {
            "status": "observed-read-only-non-executable-template",
            "preflight": {
                "path": str(args.preflight_output),
                "sha256": bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes(preflight)
                ),
            },
            "authorizationTemplate": {
                "path": str(args.authorization_template_output),
                "sha256": bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes(template)
                ),
                "executable": False,
            },
        }
        print(json.dumps(outputs, sort_keys=True, separators=(",", ":")))
        return 0
    except (ObserveError, bootstrap.BootstrapError, OSError) as exc:
        print(f"private release V2 read-only observation error: {exc}", file=sys.stderr)
        return 1


__all__: Sequence[str] = (
    "ObserveError",
    "AzureCliReadOnlySession",
    "ReadOnlySession",
    "ReadRequest",
    "ReadResponse",
    "TEMPLATE_STATUS",
    "build_read_only_observation",
    "response_digest",
    "write_canonical",
)


if __name__ == "__main__":
    raise SystemExit(main())
