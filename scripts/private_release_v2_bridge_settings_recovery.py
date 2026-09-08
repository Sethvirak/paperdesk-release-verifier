#!/usr/bin/env python3
"""Recover the exact PR55 bridge App Settings normalization incident.

``observe`` is read only and writes a non-executable, source-bound recovery
template. ``apply`` requires that exact template plus the user's exact phrase,
re-proves every safety boundary, records a durable one-use intent, issues one
full-map App Settings PUT without retry, and requires an exact empty readback.

This executor is intentionally incident-specific.  It cannot edit another App
Service, accept another settings digest, start a site, change RBAC, modify a
lock, or alter Storage networking.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Mapping, Protocol
import urllib.parse
import uuid

try:
    from scripts import private_release_v2_bootstrap as bootstrap
except ModuleNotFoundError:  # direct ``python scripts/...`` execution
    import private_release_v2_bootstrap as bootstrap  # type: ignore


ROOT = Path(__file__).resolve().parents[1]
EXECUTOR = Path(__file__).resolve()
REPOSITORY = "Sethvirak/paperdesk-release-verifier"
REMOTE = "https://github.com/Sethvirak/paperdesk-release-verifier.git"
SUBSCRIPTION = "9c4e0d0d-602f-4cde-84bd-337250e5b64c"
TENANT = "aba83bd8-3e5c-4a87-9eb1-7bca070685b2"
ACCOUNT_ID = "tasethvirak@gmail.com"
ACCOUNT_OBJECT_ID = "b97bfa13-b375-4b27-93d7-141029dbc05b"
MANAGEMENT = "https://management.azure.com"
INCIDENT_AUTHORIZATION_ID = "6af46788-e782-46fd-990b-72cfca7084d1"
INCIDENT_AUTHORIZATION_SHA256 = (
    "2b7c5559ffc01b3e0a9203167e26ce86c5be4fce989429e26843853a89f3a2fe"
)
INCIDENT_TERMINAL_SHA256 = (
    "59e3e659131b76fa31472b2bea3b567fb57d9679051f22748bc206eb6eeb9b20"
)
INCIDENT_CEREMONY_DIRECTORY = Path(
    r"C:\ProgramData\PaperDeskReleaseCeremonies-20260905-a75d00e9"
)
INCIDENT_RUN_DIRECTORY = INCIDENT_CEREMONY_DIRECTORY / (
    "paperdesk-private-release-v2-bootstrap-6af46788-e782-46fd-990b-72cfca7084d1"
)
INCIDENT_AUTHORIZATION_PATH = INCIDENT_CEREMONY_DIRECTORY / (
    "bootstrap-authorization-6af46788-e782-46fd-990b-72cfca7084d1.json"
)
INCIDENT_PREFLIGHT_PATH = INCIDENT_CEREMONY_DIRECTORY / (
    "observation-6af46788-e782-46fd-990b-72cfca7084d1/bootstrap-preflight.json"
)
INCIDENT_PREFLIGHT_FILE_SHA256 = (
    "8070154a4db996427d7cd33fb0ce8832ecb0d7b64dd342d39997062f20ac9229"
)

SITE_ID = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-master-data-structure-sea/"
    "providers/Microsoft.Web/sites/paperdesk-release-registry-bridge-v2-9c4e0d0d"
)
STORAGE_ID = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-paperdesk-rollback-sea-20260808/"
    "providers/Microsoft.Storage/storageAccounts/mdspdbak2608089c4e"
)
BRIDGE_IDENTITY_ID = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-master-data-structure-sea/"
    "providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-paperdesk-release-bridge-v2"
)
APP_SETTINGS_URL = f"{MANAGEMENT}{SITE_ID}/config/appsettings?api-version=2025-03-01"
APP_SETTINGS_LIST_URL = (
    f"{MANAGEMENT}{SITE_ID}/config/appsettings/list?api-version=2025-03-01"
)
SITE_URL = f"{MANAGEMENT}{SITE_ID}?api-version=2025-03-01"
STORAGE_URL = f"{MANAGEMENT}{STORAGE_ID}?api-version=2025-06-01"
BRIDGE_IDENTITY_URL = f"{MANAGEMENT}{BRIDGE_IDENTITY_ID}?api-version=2023-01-31"
EXPECTED_VNET_RULE = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-master-data-structure-sea/"
    "providers/Microsoft.Network/virtualNetworks/vnet-master-data-structure-sea/"
    "subnets/snet-appservice-integration"
)
EXPECTED_UAMIS = {
    BRIDGE_IDENTITY_ID.lower(),
    (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-master-data-structure-sea/"
        "providers/Microsoft.ManagedIdentity/userAssignedIdentities/"
        "id-paperdesk-release-production-activation-v2"
    ).lower(),
    (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-master-data-structure-sea/"
        "providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-paperdesk-release-signer-v2"
    ).lower(),
    (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-master-data-structure-sea/"
        "providers/Microsoft.ManagedIdentity/userAssignedIdentities/"
        "uami-paperdesk-accepted-release-reader"
    ).lower(),
    (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-master-data-structure-sea/"
        "providers/Microsoft.ManagedIdentity/userAssignedIdentities/"
        "uami-paperdesk-accepted-release-writer"
    ).lower(),
}

NORMALIZED_MAP_SHA256 = (
    "243e0437e058b404b42312837033c7916a50903331084c39e3d91b8f7b807c33"
)
NORMALIZED_WRAPPER_SHA256 = (
    "09ffa11e63332bb81b4847f76796405ad175e56c7a6cba3185e3b4d0c190481b"
)
NORMALIZED_CONTROL_SHA256 = (
    "ea5e0544bd6f372d9498d9ea0d79ed2b8c9f636c787c1e1272eb4e7b7b1db689"
)
ATTEMPTED_CONTROL_SHA256 = (
    "32e02a86df1a0559e52fd69a5f0da919ac0fc27eff8951b1fa32db721c54e74e"
)
ATTEMPTED_REQUEST_SHA256 = (
    "0b851763de48285fdb59c54fdb2a3c5077940d25450fc05a17e6d767ae212669"
)
EMPTY_MAP_SHA256 = hashlib.sha256(bootstrap.canonical_json_bytes({})).hexdigest()
EMPTY_REQUEST = bootstrap.canonical_json_bytes({"properties": {}})
EMPTY_REQUEST_SHA256 = hashlib.sha256(EMPTY_REQUEST).hexdigest()
MAX_AUTHORIZATION_SECONDS = 1800

TEMP_ASSIGNMENTS = {
    "packageAdd": (
        STORAGE_ID + "/blobServices/default/containers/paperdesk-deployment-packages",
        "398a454e-6b71-5c23-a91c-4dc3cb8f9f23",
    ),
    "packageRead": (
        STORAGE_ID + "/blobServices/default/containers/paperdesk-deployment-packages",
        "9b43fcc7-8c06-5408-a6fe-a3709abb8210",
    ),
    "keyRead": (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-master-data-structure-sea/"
        "providers/Microsoft.KeyVault/vaults/kv-mds-sea-9c4e0d0d/keys/"
        "paperdesk-release-result-signing",
        "f6bcff08-68d1-5b0a-8a32-b483e6971bf5",
    ),
    "fence": (
        STORAGE_ID + "/blobServices/default/containers/paperdesk-release-activation-control",
        "ce7c284d-2c3b-55fb-b887-3244a0f975f0",
    ),
    "controller": (
        STORAGE_ID + "/blobServices/default/containers/paperdesk-release-controller-lock",
        "ffa8a1c8-a4a6-5cbc-81a2-47d88f7be11e",
    ),
}
TEMP_KEY_DEFINITION_ID = "ca626680-f36d-59ba-ba61-5ebbd512b39d"
LOCKS = {
    "productionApp": (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-master-data-structure-sea/"
        "providers/Microsoft.Web/sites/master-data-structure-sea-9c4e0d0d/"
        "providers/Microsoft.Authorization/locks/paperdesk-protect-app-delete",
        "PaperDesk production App Service deletion protection. Remove only for an approved "
        "delete, replacement, RBAC cleanup, or diagnostic cleanup.",
    ),
    "rollback": (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-paperdesk-rollback-sea-20260808/"
        "providers/Microsoft.Authorization/locks/paperdesk-rollback-cannot-delete",
        "Protects verified PaperDesk pre-migration attachment rollback copy; remove lock "
        "explicitly before authorized retirement.",
    ),
    "signingVault": (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-master-data-structure-sea/"
        "providers/Microsoft.KeyVault/vaults/kv-mds-sea-9c4e0d0d/providers/"
        "Microsoft.Authorization/locks/paperdesk-protect-keyvault-delete",
        "PaperDesk production Key Vault deletion protection. Remove only for an approved "
        "delete, replacement, RBAC cleanup, or diagnostic cleanup.",
    ),
}
JOURNAL_HASHES = {
    "cloud-mutation-0029.json": "6655549d2939adefe3ca8dafa553d2173843055c4018404aa3d4d22a478c8a77",
    "cloud-mutation-0030.json": "52968eea969e5da8f0f8746023279e75c8dec9d5c8f6b57d77881d4553c62771",
    "cloud-mutation-0053.json": "8208bb6195a20831c08392b8cde9c4259e1f546cc1e090024bc41ed0de869ab6",
    "cloud-mutation-0054.json": "5f233fbb09cbab28460d9914f28f8da041582be7e4e11eb3bd962bb8b6cf07d0",
    "cloud-mutation-0063.json": "1e7b3ad0eca1720227432b9319d6c9d7f0cf38c48eaa035cff82441ba77ff0fe",
    "cloud-mutation-0064.json": "5cf2a538f063bd53012388f92ac50af026a700ec242d5faca391f144ed464286",
    "execution-terminal.json": INCIDENT_TERMINAL_SHA256,
}


class RecoveryError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise RecoveryError(message)


def digest(value: Any) -> str:
    return hashlib.sha256(bootstrap.canonical_json_bytes(value)).hexdigest()


def stamp(value: dt.datetime) -> str:
    if value.tzinfo != dt.timezone.utc:
        fail("clock must be exact UTC")
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_time(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"{label} is not an exact UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RecoveryError(f"{label} is invalid") from exc
    if parsed.tzinfo != dt.timezone.utc:
        fail(f"{label} is not UTC")
    return parsed


def load_json(path: Path) -> tuple[Mapping[str, Any], bytes]:
    if not path.is_file() or path.is_symlink():
        fail(f"not one regular JSON file: {path}")
    raw = path.read_bytes()
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=bootstrap._duplicate_safe_pairs
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryError(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict) or raw != bootstrap.canonical_json_bytes(value):
        fail(f"JSON is not one canonical object: {path}")
    return value, raw


def write_new(path: Path, value: Any) -> None:
    raw = value if isinstance(value, bytes) else bootstrap.canonical_json_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(fd)


def write_durable_ledger_file(directory: Path, name: str, value: Any) -> Path:
    if (
        not directory.is_dir()
        or directory.is_symlink()
        or "/" in name
        or "\\" in name
        or name in {"", ".", ".."}
    ):
        fail("recovery ledger file boundary is unsafe")
    target = directory / name
    write_new(target, value)
    bootstrap.UseLedger._fsync_directory(directory)
    return target


def create_durable_ledger(directory: Path) -> None:
    parent = directory.parent
    if not parent.is_dir() or parent.is_symlink():
        fail("recovery ledger parent must already exist as one real directory")
    try:
        directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    except FileExistsError as exc:
        raise RecoveryError("recovery receipt directory already exists") from exc
    bootstrap.UseLedger._fsync_directory(parent)


def git(*arguments: str) -> str:
    process = subprocess.run(
        ["git", *arguments], cwd=ROOT, check=False, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, encoding="utf-8", timeout=30,
    )
    if process.returncode != 0:
        fail("git source inspection failed")
    return process.stdout.strip()


def source_projection() -> dict[str, Any]:
    if git("status", "--porcelain"):
        fail("recovery source worktree is dirty")
    remote = git("remote", "get-url", "origin")
    if remote != REMOTE:
        fail("recovery source remote is not exact")
    return {
        "repository": REPOSITORY,
        "commitSha": git("rev-parse", "HEAD"),
        "treeSha": git("rev-parse", "HEAD^{tree}"),
        "executorSha256": hashlib.sha256(EXECUTOR.read_bytes()).hexdigest(),
        "bootstrapSha256": hashlib.sha256(
            (ROOT / "scripts" / "private_release_v2_bootstrap.py").read_bytes()
        ).hexdigest(),
        "bridgeEntrySha256": hashlib.sha256(
            (ROOT / "provider" / "private_release_bridge_entry.py").read_bytes()
        ).hexdigest(),
    }


def incident_projection() -> dict[str, Any]:
    authorization, authorization_raw = load_json(INCIDENT_AUTHORIZATION_PATH)
    preflight, preflight_raw = load_json(INCIDENT_PREFLIGHT_PATH)
    if (
        authorization.get("authorizationId") != INCIDENT_AUTHORIZATION_ID
        or hashlib.sha256(authorization_raw).hexdigest()
        != INCIDENT_AUTHORIZATION_SHA256
        or authorization.get("azure") != {
            "accountId": ACCOUNT_ID,
            "accountObjectId": ACCOUNT_OBJECT_ID,
            "accountType": "user",
            "cloud": "AzureCloud",
            "subscriptionId": SUBSCRIPTION,
            "tenantId": TENANT,
        }
    ):
        fail("incident authorization binding is not exact")
    observed_preflight = authorization.get("observedPreflight")
    if (
        hashlib.sha256(preflight_raw).hexdigest() != INCIDENT_PREFLIGHT_FILE_SHA256
        or not isinstance(observed_preflight, dict)
        or observed_preflight != {
            "maximumAgeSeconds": 300,
            "observedAt": "2026-09-08T09:08:19.253Z",
            "sha256": "3a4eacdba26decf581e7af13dfa02dad996d4156e9ec4bd8185eac6e2b617a63",
        }
        or preflight.get("observedAt") != observed_preflight["observedAt"]
        or preflight.get("projectionSha256") != observed_preflight["sha256"]
    ):
        fail("incident preflight binding is not exact")
    projection = preflight.get("projection")
    admissions = projection.get("operationAdmissions") if isinstance(projection, dict) else None
    configure = [
        item for item in admissions or []
        if isinstance(item, dict)
        and item.get("operationId")
        == "configureBridgeExactVersionedPackageAndCriticalSettings"
    ]
    context = configure[0].get("context") if len(configure) == 1 else None
    if (
        not isinstance(context, dict)
        or context.get("preAppSettings") != {}
        or context.get("preAppSettingsSha256") != EMPTY_MAP_SHA256
    ):
        fail("incident source App Settings prestate is not exact empty")
    loaded: dict[str, Mapping[str, Any]] = {}
    for name, expected in JOURNAL_HASHES.items():
        path = INCIDENT_RUN_DIRECTORY / name
        value, raw = load_json(path)
        if hashlib.sha256(raw).hexdigest() != expected:
            fail(f"incident journal hash drifted: {name}")
        loaded[name] = value
    upload = loaded["cloud-mutation-0030.json"]
    fence_intent = loaded["cloud-mutation-0053.json"]
    fence = loaded["cloud-mutation-0054.json"]
    configure_intent = loaded["cloud-mutation-0063.json"]
    configure_result = loaded["cloud-mutation-0064.json"]
    terminal = loaded["execution-terminal.json"]
    if (
        upload.get("operationId") != "uploadVersionedBridgePackage"
        or upload.get("phase") != "result"
        or upload.get("status") != 201
        or fence_intent.get("operationId") != "createInitialIdleActivationFence"
        or fence_intent.get("phase") != "intent"
        or fence.get("operationId") != "createInitialIdleActivationFence"
        or fence.get("phase") != "result"
        or fence.get("status") != 201
        or configure_intent.get("operationId")
        != "configureBridgeExactVersionedPackageAndCriticalSettings"
        or configure_intent.get("requestBodySha256") != ATTEMPTED_REQUEST_SHA256
        or configure_result.get("phase") != "result"
        or configure_result.get("status") != 200
        or terminal.get("status") != "failed"
        or terminal.get("consumed") is not True
    ):
        fail("incident journal semantics are not exact")
    return {
        "authorization": authorization,
        "authorizationSha256": INCIDENT_AUTHORIZATION_SHA256,
        "terminalSha256": INCIDENT_TERMINAL_SHA256,
        "preflightFileSha256": INCIDENT_PREFLIGHT_FILE_SHA256,
        "preflightProjectionSha256": observed_preflight["sha256"],
        "sourcePreAppSettingsSha256": EMPTY_MAP_SHA256,
        "packageVersionId": upload.get("versionId"),
        "fenceEtag": fence.get("etag"),
        "fenceVersionId": fence.get("versionId"),
        "fenceBodySha256": fence_intent.get("requestBodySha256"),
        "attemptedRequestSha256": ATTEMPTED_REQUEST_SHA256,
    }


class Session(Protocol):
    def account(self) -> Mapping[str, Any]: ...
    def request(
        self, method: str, url: str, *, body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        deadline: dt.datetime | None = None,
    ) -> Any: ...


def allowed_read_requests() -> set[tuple[str, str]]:
    requests = {
        ("GET", SITE_URL),
        ("GET", STORAGE_URL),
        ("GET", BRIDGE_IDENTITY_URL),
        ("POST", APP_SETTINGS_LIST_URL),
        (
            "GET",
            f"{MANAGEMENT}/subscriptions/{SUBSCRIPTION}/providers/"
            f"Microsoft.Authorization/roleDefinitions/{TEMP_KEY_DEFINITION_ID}"
            "?api-version=2022-04-01",
        ),
    }
    requests.update(
        (
            "GET",
            f"{MANAGEMENT}{scope}/providers/Microsoft.Authorization/roleAssignments/"
            f"{assignment_id}?api-version=2022-04-01",
        )
        for scope, assignment_id in TEMP_ASSIGNMENTS.values()
    )
    requests.update(
        ("GET", f"{MANAGEMENT}{resource_id}?api-version=2016-09-01")
        for resource_id, _ in LOCKS.values()
    )
    return requests


class RecoveryBoundSession:
    """Fail closed outside this incident's exact read set and sole mutation."""

    def __init__(self, inner: Session, *, allow_mutation: bool) -> None:
        self.inner = inner
        self.allow_mutation = allow_mutation
        self._put_attempted = False

    def account(self) -> Mapping[str, Any]:
        return self.inner.account()

    def request(
        self, method: str, url: str, *, body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        deadline: dt.datetime | None = None,
    ) -> Any:
        if (method, url) in allowed_read_requests():
            if body is not None or headers is not None or deadline is not None:
                fail("recovery read request parameters are outside the exact boundary")
        elif (method, url) == ("PUT", APP_SETTINGS_URL):
            if (
                not self.allow_mutation
                or self._put_attempted
                or body != EMPTY_REQUEST
                or headers != {"Content-Type": "application/json"}
                or not isinstance(deadline, dt.datetime)
                or deadline.utcoffset() is None
            ):
                fail("recovery mutation request is outside the exact boundary")
            self._put_attempted = True
        else:
            fail("Azure request is outside the incident recovery allowlist")
        return self.inner.request(
            method, url, body=body, headers=headers, deadline=deadline
        )


def response_json(response: Any, expected: set[int], label: str) -> Mapping[str, Any]:
    if response.status not in expected:
        fail(f"{label} returned HTTP {response.status}")
    try:
        value = json.loads(
            response.body.decode("utf-8"),
            object_pairs_hook=bootstrap._duplicate_safe_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryError(f"{label} returned invalid JSON") from exc
    if not isinstance(value, dict):
        fail(f"{label} did not return one object")
    return value


def read_json(session: Session, method: str, url: str, label: str) -> Mapping[str, Any]:
    response = session.request(method, url)
    return response_json(response, {200}, label)


def validate_account(account: Mapping[str, Any]) -> dict[str, Any]:
    if (
        account.get("cloud") != "AzureCloud"
        or account.get("subscriptionId") != SUBSCRIPTION
        or account.get("tenantId") != TENANT
        or account.get("accountId") != ACCOUNT_ID
        or account.get("accountObjectId") != ACCOUNT_OBJECT_ID
        or account.get("accountType") != "user"
    ):
        fail("Azure account boundary is not exact")
    return {
        "cloud": account["cloud"],
        "subscriptionId": account["subscriptionId"],
        "tenantId": account["tenantId"],
        "accountId": account["accountId"],
        "accountObjectId": account["accountObjectId"],
        "accountType": account["accountType"],
    }


def validate_site(site: Mapping[str, Any]) -> dict[str, Any]:
    properties = site.get("properties")
    identity = site.get("identity")
    uamis = identity.get("userAssignedIdentities") if isinstance(identity, dict) else None
    if (
        str(site.get("id", "")).lower() != SITE_ID.lower()
        or site.get("kind") != "app,linux"
        or not isinstance(properties, dict)
        or properties.get("state") != "Stopped"
        or properties.get("enabled") is not True
        or properties.get("httpsOnly") is not True
        or properties.get("publicNetworkAccess") != "Disabled"
        or not isinstance(identity, dict)
        or identity.get("type") != "UserAssigned"
        or not isinstance(uamis, dict)
        or {key.lower() for key in uamis} != EXPECTED_UAMIS
    ):
        fail("bridge site recovery posture is not exact and stopped")
    return {
        "state": "Stopped",
        "httpsOnly": True,
        "publicNetworkAccess": "Disabled",
        "identityCount": len(uamis),
    }


def validate_storage(storage: Mapping[str, Any]) -> dict[str, Any]:
    properties = storage.get("properties")
    network = properties.get("networkAcls") if isinstance(properties, dict) else None
    required_network_fields = {
        "bypass", "defaultAction", "ipRules", "virtualNetworkRules"
    }
    allowed_network_fields = required_network_fields | {
        "ipv6Rules", "resourceAccessRules"
    }
    expected_network = {
        "bypass": "None",
        "defaultAction": "Deny",
        "ipRules": [],
        "ipv6Rules": [],
        "resourceAccessRules": [],
        "virtualNetworkRules": [
            {
                "action": "Allow",
                "id": EXPECTED_VNET_RULE,
                "state": "Succeeded",
            }
        ],
    }
    if (
        not isinstance(network, dict)
        or not required_network_fields.issubset(network)
        or not set(network).issubset(allowed_network_fields)
    ):
        fail("Storage recovery boundary is not exact")
    normalized_network = dict(network)
    normalized_network.setdefault("ipv6Rules", [])
    normalized_network.setdefault("resourceAccessRules", [])
    if (
        str(storage.get("id", "")).lower() != STORAGE_ID.lower()
        or storage.get("type") != "Microsoft.Storage/storageAccounts"
        or normalized_network != expected_network
    ):
        fail("Storage recovery boundary is not exact")
    return {
        "id": STORAGE_ID,
        "type": "Microsoft.Storage/storageAccounts",
        "networkAcls": expected_network,
        "networkAclsSha256": digest(expected_network),
    }


def validate_lock(
    lock: Mapping[str, Any], label: str, resource_id: str, notes: str
) -> dict[str, Any]:
    reviewed = bootstrap.cleanup_locks.REVIEWED_CLEANUP_LOCKS.get(label)
    if reviewed != {
        "resourceId": resource_id,
        "properties": {"level": "CanNotDelete", "notes": notes},
    }:
        fail(f"{label} reviewed lock source is not exact")
    bootstrap.cleanup_locks.validate_lock_document(lock, reviewed, fail)
    return {
        "id": resource_id,
        "name": resource_id.rsplit("/", 1)[-1],
        "type": "Microsoft.Authorization/locks",
        "properties": {"level": "CanNotDelete", "notes": notes},
    }


def validate_control(
    raw: str, identity: Mapping[str, Any], incident: Mapping[str, Any]
) -> dict[str, Any]:
    if raw.endswith("\n") or hashlib.sha256(raw.encode("utf-8")).hexdigest() != NORMALIZED_CONTROL_SHA256:
        fail("normalized bootstrap control bytes are not exact")
    try:
        control = json.loads(raw, object_pairs_hook=bootstrap._duplicate_safe_pairs)
    except json.JSONDecodeError as exc:
        raise RecoveryError("normalized bootstrap control is invalid") from exc
    if (
        not isinstance(control, dict)
        or bootstrap.canonical_app_setting_json(control) != raw
        or hashlib.sha256(bootstrap.canonical_json_bytes(control)).hexdigest()
        != ATTEMPTED_CONTROL_SHA256
    ):
        fail("normalized bootstrap control canonical form is not exact")
    authorization = incident["authorization"]
    expected = bootstrap._bootstrap_self_test_static_control(authorization)
    for key, value in expected.items():
        if control.get(key) != value:
            fail(f"normalized bootstrap control drifted: {key}")
    properties = identity.get("properties")
    dynamic = {
        "authorizationSha256": INCIDENT_AUTHORIZATION_SHA256,
        "bridgeIdentityResourceId": identity.get("id"),
        "bridgeClientId": properties.get("clientId") if isinstance(properties, dict) else None,
        "bridgePrincipalId": properties.get("principalId") if isinstance(properties, dict) else None,
        "activationFenceEtag": incident["fenceEtag"],
        "activationFenceVersionId": incident["fenceVersionId"],
        "activationFenceBodySha256": incident["fenceBodySha256"],
        "issuedAt": "2026-09-08T09:20:19.724Z",
        "expiresAt": "2026-09-08T09:35:19.724Z",
    }
    if any(control.get(key) != value for key, value in dynamic.items()):
        fail("normalized bootstrap control dynamic facts drifted")
    if set(control) != set(expected) | set(dynamic):
        fail("normalized bootstrap control fields are not exact")
    return {
        "rawSha256": NORMALIZED_CONTROL_SHA256,
        "canonicalWithTerminalLfSha256": ATTEMPTED_CONTROL_SHA256,
        "normalization": "one-terminal-lf-removed-no-parsed-field-change",
    }


def read_settings(session: Session) -> Mapping[str, Any]:
    document = read_json(session, "POST", APP_SETTINGS_LIST_URL, "bridge App Settings read")
    properties = document.get("properties")
    if not isinstance(properties, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in properties.items()
    ):
        fail("bridge App Settings map is invalid")
    return properties


def require_absence(response: Any, expected_code: str, label: str) -> None:
    if response.status != 404:
        fail(f"{label} is not absent; HTTP {response.status}")
    try:
        document = json.loads(
            response.body.decode("utf-8"),
            object_pairs_hook=bootstrap._duplicate_safe_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryError(f"{label} absence response is invalid") from exc
    error = document.get("error") if isinstance(document, dict) else None
    if not isinstance(error, dict) or error.get("code") != expected_code:
        fail(f"{label} absence response code is not exact")


def classify_settings(
    settings: Mapping[str, Any], identity: Mapping[str, Any], incident: Mapping[str, Any]
) -> dict[str, Any]:
    if settings == {} and digest(settings) == EMPTY_MAP_SHA256:
        return {
            "state": "empty-source-prestate",
            "mapSha256": EMPTY_MAP_SHA256,
            "wrapperSha256": digest({"properties": settings}),
            "keyCount": 0,
        }
    expected_keys = {
        "WEBSITE_RUN_FROM_PACKAGE",
        "WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID",
        "WEBSITE_SKIP_RUNNING_KUDUAGENT",
        "PAPERDESK_BRIDGE_PACKAGE_SHA256",
        "PAPERDESK_BRIDGE_BOOTSTRAP_SELF_TEST_JSON",
    }
    authorization = incident["authorization"]
    package_url = (
        "https://mdspdbak2608089c4e.blob.core.windows.net/"
        "paperdesk-deployment-packages/v2/control/"
        f"{authorization['source']['mergedMain']['commitSha']}/"
        "paperdesk-private-release-bridge.zip?versionid="
        + urllib.parse.quote(str(incident["packageVersionId"]), safe="")
    )
    exact_incident = (
        set(settings) == expected_keys
        and settings["WEBSITE_RUN_FROM_PACKAGE"] == package_url
        and settings["WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID"].lower()
        == (
            f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-master-data-structure-sea/"
            "providers/Microsoft.ManagedIdentity/userAssignedIdentities/"
            "uami-paperdesk-accepted-release-reader"
        ).lower()
        and settings["WEBSITE_SKIP_RUNNING_KUDUAGENT"] == "false"
        and settings["PAPERDESK_BRIDGE_PACKAGE_SHA256"]
        == authorization["plan"]["bridgePackageSha256"]
        and digest(settings) == NORMALIZED_MAP_SHA256
        and digest({"properties": settings}) == NORMALIZED_WRAPPER_SHA256
    )
    if not exact_incident:
        return {
            "state": "third-state-untouched",
            "mapSha256": digest(settings),
            "wrapperSha256": digest({"properties": settings}),
            "keyCount": len(settings),
        }
    control_projection = validate_control(
        settings["PAPERDESK_BRIDGE_BOOTSTRAP_SELF_TEST_JSON"], identity, incident
    )
    return {
        "state": "exact-azure-normalized-incident-map",
        "mapSha256": NORMALIZED_MAP_SHA256,
        "wrapperSha256": NORMALIZED_WRAPPER_SHA256,
        "keyCount": 5,
        "control": control_projection,
    }


def observe_safety(
    session: Session, incident: Mapping[str, Any], *, expect_empty: bool | None
) -> dict[str, Any]:
    site = read_json(session, "GET", SITE_URL, "bridge site read")
    site_projection = validate_site(site)
    storage = read_json(session, "GET", STORAGE_URL, "Storage read")
    storage_projection = validate_storage(storage)
    identity = read_json(session, "GET", BRIDGE_IDENTITY_URL, "bridge identity read")
    if str(identity.get("id", "")).lower() != BRIDGE_IDENTITY_ID.lower():
        fail("bridge identity is not exact")

    for label, (scope, assignment_id) in TEMP_ASSIGNMENTS.items():
        url = (
            f"{MANAGEMENT}{scope}/providers/Microsoft.Authorization/roleAssignments/"
            f"{assignment_id}?api-version=2022-04-01"
        )
        response = session.request("GET", url)
        require_absence(response, "RoleAssignmentNotFound", f"temporary assignment {label}")
    definition = session.request(
        "GET",
        f"{MANAGEMENT}/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/"
        f"roleDefinitions/{TEMP_KEY_DEFINITION_ID}?api-version=2022-04-01",
    )
    require_absence(
        definition, "RoleDefinitionDoesNotExist", "temporary key role definition"
    )

    lock_projections: dict[str, Any] = {}
    for label, (resource_id, notes) in LOCKS.items():
        lock = read_json(
            session, "GET",
            f"{MANAGEMENT}{resource_id}?api-version=2016-09-01",
            f"{label} lock read",
        )
        lock_projections[label] = validate_lock(lock, label, resource_id, notes)

    settings = read_settings(session)
    settings_projection = classify_settings(settings, identity, incident)
    if expect_empty is True and settings_projection["state"] != "empty-source-prestate":
        fail("bridge App Settings restoration readback is not exact empty prestate")
    if (
        expect_empty is False
        and settings_projection["state"] != "exact-azure-normalized-incident-map"
    ):
        fail("bridge App Settings are not the exact normalized incident state")
    return {
        "site": site_projection,
        "storage": storage_projection,
        "temporaryAssignmentsAbsent": sorted(TEMP_ASSIGNMENTS),
        "temporaryKeyDefinitionAbsent": True,
        "locksExact": {key: lock_projections[key] for key in sorted(lock_projections)},
        "settings": settings_projection,
    }


def observe_final_mutation_boundary(session: Session) -> dict[str, Any]:
    """Read the stopped site and then the exact incident settings immediately adjacent."""
    site = validate_site(read_json(session, "GET", SITE_URL, "final bridge site read"))
    settings = read_settings(session)
    if (
        len(settings) != 5
        or digest(settings) != NORMALIZED_MAP_SHA256
        or digest({"properties": settings}) != NORMALIZED_WRAPPER_SHA256
    ):
        fail("final adjacent bridge App Settings state is not exact")
    return {
        "readOrder": ["site", "appSettings"],
        "site": site,
        "settings": {
            "state": "exact-azure-normalized-incident-map",
            "mapSha256": NORMALIZED_MAP_SHA256,
            "wrapperSha256": NORMALIZED_WRAPPER_SHA256,
            "keyCount": 5,
        },
    }


def recovery_ledger_directory(identifier: str) -> Path:
    if not bootstrap.GUID.fullmatch(identifier):
        fail("recovery authorization ID is invalid")
    return INCIDENT_CEREMONY_DIRECTORY / (
        f"paperdesk-private-release-v2-bridge-settings-recovery-{identifier}"
    )


def confirmation_artifact_path(identifier: str) -> Path:
    if not bootstrap.GUID.fullmatch(identifier):
        fail("recovery authorization ID is invalid")
    return INCIDENT_CEREMONY_DIRECTORY / (
        f"paperdesk-private-release-v2-bridge-settings-confirmation-{identifier}.json"
    )


REVIEW_COMMITMENT_KEYS = (
    "schemaVersion", "type", "status", "authorizationId", "observedAt",
    "expiresAt", "source", "incident", "azure", "live", "target",
    "mutationPolicy", "confirmationArtifactPath",
)


def review_commitment(preflight: Mapping[str, Any]) -> str:
    if any(key not in preflight for key in REVIEW_COMMITMENT_KEYS):
        fail("recovery review commitment fields are incomplete")
    return digest({key: preflight[key] for key in REVIEW_COMMITMENT_KEYS})


def confirmation_phrase(
    identifier: str, source_sha: str, executor_sha256: str,
    ledger_directory: Path, artifact_path: Path, observed_at: str,
    expires_at: str, review_commitment_sha256: str,
) -> str:
    return (
        f"Authorize Azure bridge App Settings recovery under authorization {identifier}: "
        "Authorize the separately reviewed source-bound PaperDesk V2 recovery for incident "
        f"{INCIDENT_AUTHORIZATION_ID}, source {source_sha}, and executor SHA-256 "
        f"{executor_sha256}. I authorize restoration of only the exact stopped "
        f"bridge map bound by wrapper SHA-256 {NORMALIZED_WRAPPER_SHA256} to the exact empty "
        f"source prestate using one full-map PUT whose SHA-256 is {EMPTY_REQUEST_SHA256}, "
        f"under review commitment SHA-256 {review_commitment_sha256}, observed at "
        f"{observed_at} and expiring at {expires_at}, with the sole durable one-use ledger "
        f"{ledger_directory} and separately created confirmation artifact {artifact_path}. "
        "I accept that App Service App Settings exposes no supported conditional ETag, so "
        "this recovery cannot atomically exclude an out-of-band administrator write between "
        "its final read and PUT. I also accept that no cross-resource atomic guard can prevent "
        "an out-of-band administrator from starting the bridge after the final adjacent "
        "stopped-site read and before the settings PUT; the executor never starts the site, "
        "and final success requires a fresh stopped-site proof. The executor must abort before "
        "mutation on any observed "
        "digest, site, temporary-access, lock, Storage, account, source, or journal drift; "
        "it must issue the settings PUT at most once without retry and require exact empty "
        "full-map readback. I accept that an ambiguous successful transport, process death, "
        "or local journal/fsync failure after intent can require another fresh read and manual "
        "cleanup. I authorize no site start, RBAC, lock, Storage-network, production, package, "
        "fence, retention, identity, or legacy-resource mutation."
    )


def observe(output_directory: Path, session: Session, now: dt.datetime) -> dict[str, Any]:
    if output_directory.exists() or output_directory.is_symlink():
        fail("recovery observation output already exists")
    source = source_projection()
    incident = incident_projection()
    incident_public = {
        key: value for key, value in incident.items() if key != "authorization"
    }
    account = validate_account(session.account())
    live = observe_safety(session, incident, expect_empty=False)
    identifier = str(uuid.uuid4())
    ledger_directory = recovery_ledger_directory(identifier)
    artifact_path = confirmation_artifact_path(identifier)
    if (
        ledger_directory.exists()
        or ledger_directory.is_symlink()
        or artifact_path.exists()
        or artifact_path.is_symlink()
    ):
        fail("recovery local authorization paths are not fresh")
    expires = now + dt.timedelta(seconds=MAX_AUTHORIZATION_SECONDS)
    observed_at = stamp(now)
    expires_at = stamp(expires)
    preflight_core = {
        "schemaVersion": 1,
        "type": "paperdesk-v2-bridge-settings-recovery-preflight",
        "status": "read-only-exact-normalized-incident-no-azure-mutation",
        "authorizationId": identifier,
        "observedAt": observed_at,
        "expiresAt": expires_at,
        "source": source,
        "incident": incident_public,
        "azure": account,
        "live": live,
        "target": {
            "map": {},
            "mapSha256": EMPTY_MAP_SHA256,
            "requestBodySha256": EMPTY_REQUEST_SHA256,
        },
        "mutationPolicy": {
            "method": "PUT",
            "url": APP_SETTINGS_URL,
            "maximumAttempts": 1,
            "retry": False,
            "otherAzureMutationsAuthorized": False,
            "ledgerDirectory": str(ledger_directory),
            "finalBoundaryReadOrder": ["site", "appSettings"],
        },
        "confirmationArtifactPath": str(artifact_path),
    }
    commitment_sha256 = review_commitment(preflight_core)
    phrase = confirmation_phrase(
        identifier, source["commitSha"], source["executorSha256"],
        ledger_directory, artifact_path, observed_at, expires_at,
        commitment_sha256,
    )
    preflight = {
        **preflight_core,
        "reviewCommitmentSha256": commitment_sha256,
        "confirmationPhraseSha256": hashlib.sha256(phrase.encode("utf-8")).hexdigest(),
        "executable": False,
    }
    output_directory.mkdir(parents=True, exist_ok=False)
    preflight_path = output_directory / "recovery-preflight.json"
    write_new(preflight_path, preflight)
    template = {
        "schemaVersion": 1,
        "type": "paperdesk-v2-bridge-settings-recovery-authorization-template",
        "status": "NON_EXECUTABLE_REQUIRES_EXACT_USER_CONFIRMATION",
        "authorizationId": identifier,
        "preflightSha256": digest(preflight),
        "source": source,
        "incidentAuthorizationId": INCIDENT_AUTHORIZATION_ID,
        "observedWrapperSha256": NORMALIZED_WRAPPER_SHA256,
        "targetRequestBodySha256": EMPTY_REQUEST_SHA256,
        "ledgerDirectory": str(ledger_directory),
        "confirmationArtifactPath": str(artifact_path),
        "reviewCommitmentSha256": commitment_sha256,
        "observedAt": observed_at,
        "expiresAt": expires_at,
        "confirmationPhraseSha256": preflight["confirmationPhraseSha256"],
        "executable": False,
    }
    write_new(output_directory / "authorization-template.json", template)
    write_new(output_directory / "confirmation-request.txt", phrase.encode("utf-8"))
    return {
        "status": "awaiting-exact-user-confirmation",
        "authorizationId": identifier,
        "preflightPath": str(preflight_path),
        "preflightSha256": digest(preflight),
        "confirmationRequestPath": str(output_directory / "confirmation-request.txt"),
        "confirmationArtifactPath": str(artifact_path),
        "reviewCommitmentSha256": commitment_sha256,
        "confirmationPhraseSha256": preflight["confirmationPhraseSha256"],
        "expiresAt": stamp(expires),
        "azureMutationPerformed": False,
    }


def validate_template(directory: Path, now: dt.datetime) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    preflight, _ = load_json(directory / "recovery-preflight.json")
    template, _ = load_json(directory / "authorization-template.json")
    if (
        set(preflight) != {
            "schemaVersion", "type", "status", "authorizationId", "observedAt",
            "expiresAt", "source", "incident", "azure", "live", "target",
            "mutationPolicy", "confirmationArtifactPath", "reviewCommitmentSha256",
            "confirmationPhraseSha256", "executable",
        }
        or set(template) != {
            "schemaVersion", "type", "status", "authorizationId",
            "preflightSha256", "source", "incidentAuthorizationId",
            "observedWrapperSha256", "targetRequestBodySha256", "observedAt",
            "expiresAt", "ledgerDirectory", "confirmationArtifactPath",
            "reviewCommitmentSha256", "confirmationPhraseSha256", "executable",
        }
        or preflight.get("schemaVersion") != 1
        or preflight.get("type") != "paperdesk-v2-bridge-settings-recovery-preflight"
        or preflight.get("status")
        != "read-only-exact-normalized-incident-no-azure-mutation"
        or template.get("schemaVersion") != 1
        or template.get("type")
        != "paperdesk-v2-bridge-settings-recovery-authorization-template"
        or template.get("status")
        != "NON_EXECUTABLE_REQUIRES_EXACT_USER_CONFIRMATION"
        or preflight.get("executable") is not False
        or template.get("executable") is not False
        or template.get("authorizationId") != preflight.get("authorizationId")
        or template.get("preflightSha256") != digest(preflight)
        or template.get("source") != preflight.get("source")
        or template.get("confirmationPhraseSha256")
        != preflight.get("confirmationPhraseSha256")
        or preflight.get("reviewCommitmentSha256") != review_commitment(preflight)
        or template.get("reviewCommitmentSha256")
        != preflight.get("reviewCommitmentSha256")
        or template.get("observedWrapperSha256") != NORMALIZED_WRAPPER_SHA256
        or template.get("targetRequestBodySha256") != EMPTY_REQUEST_SHA256
        or template.get("incidentAuthorizationId") != INCIDENT_AUTHORIZATION_ID
        or template.get("observedAt") != preflight.get("observedAt")
        or template.get("expiresAt") != preflight.get("expiresAt")
        or preflight.get("target") != {
            "map": {},
            "mapSha256": EMPTY_MAP_SHA256,
            "requestBodySha256": EMPTY_REQUEST_SHA256,
        }
        or preflight.get("mutationPolicy") != {
            "method": "PUT",
            "url": APP_SETTINGS_URL,
            "maximumAttempts": 1,
            "retry": False,
            "otherAzureMutationsAuthorized": False,
            "ledgerDirectory": str(
                recovery_ledger_directory(str(preflight.get("authorizationId", "")))
            ),
            "finalBoundaryReadOrder": ["site", "appSettings"],
        }
        or template.get("ledgerDirectory")
        != str(recovery_ledger_directory(str(preflight.get("authorizationId", ""))))
        or preflight.get("confirmationArtifactPath")
        != str(confirmation_artifact_path(str(preflight.get("authorizationId", ""))))
        or template.get("confirmationArtifactPath")
        != preflight.get("confirmationArtifactPath")
    ):
        fail("recovery authorization template binding is not exact")
    observed = parse_time(preflight.get("observedAt"), "preflight observedAt")
    expires = parse_time(preflight.get("expiresAt"), "preflight expiresAt")
    if not observed <= now < expires or (expires - observed).total_seconds() > MAX_AUTHORIZATION_SECONDS:
        fail("recovery authorization is not live")
    phrase = confirmation_phrase(
        str(preflight["authorizationId"]),
        str(preflight["source"]["commitSha"]),
        str(preflight["source"]["executorSha256"]),
        recovery_ledger_directory(str(preflight["authorizationId"])),
        confirmation_artifact_path(str(preflight["authorizationId"])),
        str(preflight["observedAt"]),
        str(preflight["expiresAt"]),
        str(preflight["reviewCommitmentSha256"]),
    )
    if hashlib.sha256(phrase.encode("utf-8")).hexdigest() != preflight.get(
        "confirmationPhraseSha256"
    ):
        fail("recovery confirmation phrase binding is not exact")
    if source_projection() != preflight.get("source"):
        fail("recovery source drifted after review")
    return preflight, template


def apply(
    directory: Path, session: Session, now: dt.datetime,
) -> dict[str, Any]:
    preflight, template = validate_template(directory, now)
    phrase = confirmation_phrase(
        str(preflight["authorizationId"]),
        str(preflight["source"]["commitSha"]),
        str(preflight["source"]["executorSha256"]),
        recovery_ledger_directory(str(preflight["authorizationId"])),
        confirmation_artifact_path(str(preflight["authorizationId"])),
        str(preflight["observedAt"]),
        str(preflight["expiresAt"]),
        str(preflight["reviewCommitmentSha256"]),
    )
    artifact_path = confirmation_artifact_path(str(preflight["authorizationId"]))
    confirmation, _ = load_json(artifact_path)
    if (
        str(artifact_path) != preflight.get("confirmationArtifactPath")
        or set(confirmation) != {
            "schemaVersion", "type", "status", "authorizationId",
            "reviewCommitmentSha256", "confirmationPhrase",
            "confirmationPhraseSha256", "confirmedAt",
        }
        or confirmation.get("schemaVersion") != 1
        or confirmation.get("type")
        != "paperdesk-v2-bridge-settings-recovery-user-confirmation"
        or confirmation.get("status") != "USER_CONFIRMED_EXACT_PHRASE"
        or confirmation.get("authorizationId") != preflight.get("authorizationId")
        or confirmation.get("reviewCommitmentSha256")
        != preflight.get("reviewCommitmentSha256")
        or confirmation.get("confirmationPhrase") != phrase
        or confirmation.get("confirmationPhraseSha256")
        != template["confirmationPhraseSha256"]
        or hashlib.sha256(phrase.encode("utf-8")).hexdigest()
        != confirmation.get("confirmationPhraseSha256")
    ):
        fail("recovery user confirmation artifact is not exact")
    confirmed_at = parse_time(confirmation.get("confirmedAt"), "confirmation confirmedAt")
    observed_at = parse_time(preflight["observedAt"], "preflight observedAt")
    if not observed_at <= confirmed_at <= now:
        fail("recovery user confirmation time is outside the reviewed window")
    receipt_directory = recovery_ledger_directory(str(preflight["authorizationId"]))
    if str(receipt_directory) != template.get("ledgerDirectory"):
        fail("recovery ledger binding is not exact")
    if receipt_directory.exists() or receipt_directory.is_symlink():
        fail("recovery receipt directory already exists")
    incident = incident_projection()
    incident_public = {
        key: value for key, value in incident.items() if key != "authorization"
    }
    if preflight.get("incident") != incident_public:
        fail("incident evidence drifted after recovery review")
    account = validate_account(session.account())
    if account != preflight.get("azure"):
        fail("Azure account drifted after recovery review")
    live = observe_safety(session, incident, expect_empty=False)
    if live != preflight.get("live"):
        fail("live recovery state drifted after review")

    create_durable_ledger(receipt_directory)
    claim = {
        "schemaVersion": 1,
        "status": "consumed-before-recovery-mutation",
        "authorizationId": preflight["authorizationId"],
        "preflightSha256": template["preflightSha256"],
        "source": preflight["source"],
        "claimedAt": stamp(dt.datetime.now(dt.timezone.utc)),
    }
    write_durable_ledger_file(receipt_directory, "single-use-state.json", claim)
    try:
        final_live = observe_safety(session, incident, expect_empty=False)
        if final_live != live:
            fail("live recovery state drifted during final pre-read")
        final_boundary = observe_final_mutation_boundary(session)
        if final_boundary["site"] != live["site"]:
            fail("bridge site drifted during final adjacent read")
    except BaseException as exc:
        write_durable_ledger_file(
            receipt_directory, "terminal.json",
            {
                "schemaVersion": 1,
                "status": "failed-before-recovery-mutation",
                "authorizationId": preflight["authorizationId"],
                "errorType": type(exc).__name__,
            },
        )
        raise
    intent = {
        "schemaVersion": 1,
        "status": "durable-intent-before-at-most-once-put",
        "authorizationId": preflight["authorizationId"],
        "source": preflight["source"],
        "observedWrapperSha256": NORMALIZED_WRAPPER_SHA256,
        "requestBodySha256": EMPTY_REQUEST_SHA256,
        "finalBoundary": final_boundary,
        "recordedAt": stamp(dt.datetime.now(dt.timezone.utc)),
    }
    write_durable_ledger_file(receipt_directory, "mutation-intent.json", intent)
    expires = parse_time(preflight["expiresAt"], "preflight expiresAt")
    try:
        response = session.request(
            "PUT", APP_SETTINGS_URL, body=EMPTY_REQUEST,
            headers={"Content-Type": "application/json"}, deadline=expires,
        )
    except BaseException as exc:
        write_durable_ledger_file(
            receipt_directory, "terminal.json",
            {
                "schemaVersion": 1,
                "status": "ambiguous-after-durable-intent",
                "authorizationId": preflight["authorizationId"],
                "errorType": type(exc).__name__,
            },
        )
        raise
    result = {
        "schemaVersion": 1,
        "status": response.status,
        "authorizationId": preflight["authorizationId"],
        "requestBodySha256": EMPTY_REQUEST_SHA256,
        "responseBodySha256": hashlib.sha256(response.body).hexdigest(),
        "recordedAt": stamp(dt.datetime.now(dt.timezone.utc)),
    }
    write_durable_ledger_file(receipt_directory, "mutation-result.json", result)
    final: dict[str, Any] | None = None
    if response.status != 200:
        try:
            final = observe_safety(session, incident, expect_empty=None)
        except BaseException as exc:
            write_durable_ledger_file(
                receipt_directory, "terminal.json",
                {
                    "schemaVersion": 1,
                    "status": "unresolved-non-200-after-recovery-put",
                    "authorizationId": preflight["authorizationId"],
                    "httpStatus": response.status,
                    "classification": "read-failed",
                    "errorType": type(exc).__name__,
                },
            )
            raise RecoveryError(
                f"recovery PUT returned HTTP {response.status}; live state is unresolved"
            ) from exc
        if final["settings"]["state"] != "empty-source-prestate":
            write_durable_ledger_file(
                receipt_directory, "terminal.json",
                {
                    "schemaVersion": 1,
                    "status": "unresolved-non-200-after-recovery-put",
                    "authorizationId": preflight["authorizationId"],
                    "httpStatus": response.status,
                    "classification": final,
                },
            )
            fail(
                f"recovery PUT returned HTTP {response.status}; live state is unresolved"
            )

    final_error: RecoveryError | None = None
    if final is None:
        for _ in range(20):
            try:
                final = observe_safety(session, incident, expect_empty=True)
                break
            except BaseException as exc:
                if isinstance(exc, RecoveryError) and "restoration readback" in str(exc):
                    final_error = exc
                    time.sleep(2)
                    continue
                write_durable_ledger_file(
                    receipt_directory, "terminal.json",
                    {
                        "schemaVersion": 1,
                        "status": "failed-after-definite-recovery-put",
                        "authorizationId": preflight["authorizationId"],
                        "errorType": type(exc).__name__,
                        "targetMapSha256": EMPTY_MAP_SHA256,
                    },
                )
                raise
    if final is None:
        write_durable_ledger_file(
            receipt_directory, "terminal.json",
            {
                "schemaVersion": 1,
                "status": "failed-after-definite-recovery-put",
                "authorizationId": preflight["authorizationId"],
                "errorType": type(final_error).__name__ if final_error else None,
                "targetMapSha256": EMPTY_MAP_SHA256,
            },
        )
        fail("recovery empty-map readback did not converge")
    terminal = {
        "schemaVersion": 1,
        "status": "complete",
        "authorizationId": preflight["authorizationId"],
        "mutationHttpStatus": response.status,
        "source": preflight["source"],
        "preflightSha256": template["preflightSha256"],
        "mutationIntentSha256": hashlib.sha256(
            (receipt_directory / "mutation-intent.json").read_bytes()
        ).hexdigest(),
        "mutationResultSha256": hashlib.sha256(
            (receipt_directory / "mutation-result.json").read_bytes()
        ).hexdigest(),
        "final": final,
        "completedAt": stamp(dt.datetime.now(dt.timezone.utc)),
    }
    write_durable_ledger_file(receipt_directory, "terminal.json", terminal)
    return {
        "status": "complete",
        "authorizationId": preflight["authorizationId"],
        "receiptDirectory": str(receipt_directory),
        "terminalSha256": hashlib.sha256(
            (receipt_directory / "terminal.json").read_bytes()
        ).hexdigest(),
        "azureMutationAttempts": 1,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("describe")
    observe_parser = sub.add_parser("observe")
    observe_parser.add_argument("--output-directory", type=Path, required=True)
    apply_parser = sub.add_parser("apply")
    apply_parser.add_argument("--observation-directory", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "describe":
        print(json.dumps({
            "status": "credential-free-no-Azure-transport-constructed",
            "source": source_projection(),
            "incidentAuthorizationId": INCIDENT_AUTHORIZATION_ID,
            "acceptedWrapperSha256": NORMALIZED_WRAPPER_SHA256,
            "targetRequestBodySha256": EMPTY_REQUEST_SHA256,
            "mutation": {"method": "PUT", "attempts": 1, "retry": False},
        }, sort_keys=True))
        return 0
    account_probe = bootstrap.AzureCliRestSession({})
    account = validate_account(account_probe.account())
    session = RecoveryBoundSession(
        bootstrap.AzureCliRestSession({"azure": account}),
        allow_mutation=args.command == "apply",
    )
    now = dt.datetime.now(dt.timezone.utc)
    if args.command == "observe":
        print(json.dumps(observe(args.output_directory, session, now), sort_keys=True))
        return 0
    print(json.dumps(apply(
        args.observation_directory, session, now,
    ), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RecoveryError, bootstrap.BootstrapError) as exc:
        print(f"PaperDesk bridge settings recovery error: {exc}", file=sys.stderr)
        raise SystemExit(1)
