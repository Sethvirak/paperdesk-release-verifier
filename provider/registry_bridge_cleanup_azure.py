#!/usr/bin/env python3
"""Fixed-resource Azure boundary for the dormant registry cleanup watcher.

This module is production-shaped but cannot activate the watcher by itself.
The adjacent reviewed contract deliberately contains null managed-identity
coordinates and the cleanup core deliberately contains a null merged commit.
The runtime checks both dormancy gates before constructing this boundary.

The boundary exposes only the methods in ``CleanupBoundary``.  It has no
bridge-start, WebJob-run, deployment, role-write, accepted-release, or blob
delete primitive.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import timezone
from email.utils import parsedate_to_datetime
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import PurePosixPath
import re
import ssl
import threading
import time
from typing import Any, Mapping, Protocol, Sequence
import urllib.error
import urllib.parse
import urllib.request

try:
    from provider import registry_bridge_cleanup_watcher as watcher
except ModuleNotFoundError:  # deterministic isolated WebJob package
    import registry_bridge_cleanup_watcher as watcher  # type: ignore


ARM_API_VERSION = "2025-05-01"
STORAGE_ARM_API_VERSION = "2025-06-01"
STORAGE_DATA_API_VERSION = "2023-11-03"
IDENTITY_API_VERSION = "2019-08-01"
MANAGEMENT_RESOURCE = "https://management.azure.com/"
STORAGE_RESOURCE = "https://storage.azure.com/"
MANAGEMENT_HOST = "management.azure.com"
STORAGE_HOST = f"{watcher.STORAGE_ACCOUNT}.blob.core.windows.net"
USER_AGENT = "PaperDeskRegistryCleanupWatcher/1"
MAX_REMOTE_JSON = 256 * 1024

IDENTITY_ROLES = frozenset({
    "state-read-write",
    "bridge-control",
    "result-read-only",
    "evidence-policy-read-only",
    "authority-fence-read-only",
    "evidence-create-only",
    "evidence-read-only",
})

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)
ETAG_RE = re.compile(r'^"[\x21\x23-\x7e]{1,256}"$')


def fail(code: str) -> None:
    raise watcher.CleanupContractError(code)


def _canonical_server_time(value: str) -> str:
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        fail("azure-storage-date-invalid")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        fail("azure-storage-date-invalid")
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _json_body(body: bytes, label: str, maximum: int = MAX_REMOTE_JSON) -> dict[str, Any]:
    if not 0 < len(body) <= maximum or b"\0" in body:
        fail(f"{label}-response-size")
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"{label}-response-json")
    if not isinstance(document, dict):
        fail(f"{label}-response-shape")
    return document


def _safe_blob_path(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2048
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or "//" in value
        or "?" in value
        or "#" in value
        or any(part in {"", ".", ".."} for part in PurePosixPath(value).parts)
    ):
        fail(f"{label}-path")
    return value


class RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _identity_endpoint(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        fail("managed-identity-endpoint-invalid")
    host = parsed.hostname
    if (
        parsed.scheme != "http"
        or parsed.username is not None
        or parsed.password is not None
        or port is None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"/MSI/token", "/MSI/token/"}
        or not host
        or "%" in host
    ):
        fail("managed-identity-endpoint-invalid")
    if host != "localhost":
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            fail("managed-identity-endpoint-not-local")
        if not (address.is_loopback or address.is_link_local):
            fail("managed-identity-endpoint-not-local")
    return value


class AppServiceManagedIdentity:
    """Acquire only ARM or Storage tokens for one reviewed UAMI client ID."""

    def __init__(
        self,
        client_id: str,
        environment: Mapping[str, str],
        opener: Any | None = None,
    ):
        if not UUID_RE.fullmatch(client_id):
            fail("managed-identity-client-id-invalid")
        self.client_id = client_id.lower()
        self.environment = environment
        self.opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}), RejectRedirectHandler()
        )
        self._cache: dict[str, tuple[str, int]] = {}
        self._lock = threading.Lock()

    def get(self, resource: str) -> str:
        if resource not in {MANAGEMENT_RESOURCE, STORAGE_RESOURCE}:
            fail("managed-identity-resource-not-fixed")
        with self._lock:
            cached = self._cache.get(resource)
            if cached is not None and cached[1] > int(time.time()) + 120:
                return cached[0]
            endpoint = _identity_endpoint(
                str(self.environment.get("IDENTITY_ENDPOINT") or "")
            )
            secret_header = str(self.environment.get("IDENTITY_HEADER") or "")
            if (
                not secret_header
                or len(secret_header) > 8192
                or "\r" in secret_header
                or "\n" in secret_header
            ):
                fail("managed-identity-header-unavailable")
            query = urllib.parse.urlencode({
                "api-version": IDENTITY_API_VERSION,
                "resource": resource,
                "client_id": self.client_id,
            })
            url = f"{endpoint}?{query}"
            request = urllib.request.Request(
                url,
                headers={"X-IDENTITY-HEADER": secret_header},
                method="GET",
            )
            try:
                with self.opener.open(request, timeout=15) as response:
                    if getattr(response, "status", 0) != 200 or response.geturl() != url:
                        fail("managed-identity-response-boundary")
                    body = response.read(65537)
            except watcher.CleanupContractError:
                raise
            except (OSError, urllib.error.URLError):
                fail("managed-identity-token-unavailable")
            document = _json_body(body, "managed-identity", 65536)
            token = document.get("access_token")
            expires = document.get("expires_on")
            try:
                expiry = int(expires)
            except (TypeError, ValueError):
                expiry = 0
            if (
                not isinstance(token, str)
                or not 100 <= len(token) <= 32768
                or "\r" in token
                or "\n" in token
                or expiry <= int(time.time()) + 120
            ):
                fail("managed-identity-token-invalid")
            self._cache[resource] = (token, expiry)
            return token


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes
    headers: Mapping[str, str]


class HttpTransport(Protocol):
    def request(
        self,
        method: str,
        host: str,
        target: str,
        headers: Mapping[str, str],
        body: bytes | None,
        maximum: int,
    ) -> HttpResponse: ...


class HttpsTransport:
    def request(
        self,
        method: str,
        host: str,
        target: str,
        headers: Mapping[str, str],
        body: bytes | None,
        maximum: int,
    ) -> HttpResponse:
        if host not in {MANAGEMENT_HOST, STORAGE_HOST}:
            fail("http-host-not-fixed")
        if method not in {"GET", "POST", "PUT", "PATCH"}:
            fail("http-method-not-allowed")
        if not target.startswith("/") or "#" in target or "\r" in target or "\n" in target:
            fail("http-target-invalid")
        connection = http.client.HTTPSConnection(
            host,
            timeout=30,
            context=ssl.create_default_context(),
        )
        try:
            connection.request(method, target, body=body, headers=dict(headers))
            response = connection.getresponse()
            response_body = response.read(maximum + 1)
            if len(response_body) > maximum:
                fail("http-response-excessive")
            return HttpResponse(
                status=response.status,
                body=response_body,
                headers={name.lower(): value for name, value in response.getheaders()},
            )
        except watcher.CleanupContractError:
            raise
        except (OSError, http.client.HTTPException):
            fail("http-request-failed")
        finally:
            connection.close()


def build_managed_identity_credentials(
    contract: Mapping[str, Any],
    environment: Mapping[str, str] | None = None,
    *,
    opener_factory: Any | None = None,
) -> dict[str, AppServiceManagedIdentity]:
    """Load seven exact UAMI coordinates only from an activated contract.

    Environment variables are used only for the App Service token endpoint and
    secret header.  Identity client IDs are never accepted from environment or
    command-line input.
    """

    env = os.environ if environment is None else environment
    identity_map = contract.get("watcher", {}).get("managedIdentityClientIds")
    if not isinstance(identity_map, dict) or set(identity_map) != IDENTITY_ROLES:
        fail("watcher-identity-contract-not-exact")
    client_ids = list(identity_map.values())
    if any(not isinstance(value, str) or not UUID_RE.fullmatch(value) for value in client_ids):
        fail("watcher-identities-not-activated")
    if len({value.lower() for value in client_ids}) != len(IDENTITY_ROLES):
        fail("watcher-identities-not-distinct")
    credentials: dict[str, AppServiceManagedIdentity] = {}
    for role in sorted(IDENTITY_ROLES):
        opener = opener_factory(role) if opener_factory is not None else None
        credentials[role] = AppServiceManagedIdentity(identity_map[role], env, opener)
    return credentials


class AzureCleanupBoundary:
    """Exact Azure implementation of the cleanup core's narrow authority."""

    def __init__(
        self,
        credentials: Mapping[str, AppServiceManagedIdentity],
        transport: HttpTransport | None = None,
    ):
        if set(credentials) != IDENTITY_ROLES:
            fail("watcher-credential-roles-not-exact")
        self.credentials = dict(credentials)
        self.transport = transport or HttpsTransport()

    @staticmethod
    def _blob_target(container: str, blob: str, allowed: set[str]) -> str:
        if container not in allowed:
            fail("blob-container-not-fixed")
        path = _safe_blob_path(blob, "blob")
        encoded = "/".join(
            urllib.parse.quote(part, safe="") for part in PurePosixPath(path).parts
        )
        return f"/{container}/{encoded}"

    def _request(
        self,
        method: str,
        role: str,
        host: str,
        target: str,
        resource: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        maximum: int = MAX_REMOTE_JSON,
    ) -> HttpResponse:
        if role not in IDENTITY_ROLES:
            fail("credential-role-not-fixed")
        token = self.credentials[role].get(resource)
        request_headers = {
            "Authorization": f"Bearer {token}",
            "User-Agent": USER_AGENT,
        }
        request_headers.update(headers or {})
        return self.transport.request(
            method, host, target, request_headers, body, maximum
        )

    def _storage(
        self,
        method: str,
        role: str,
        container: str,
        blob: str,
        *,
        body: bytes | None = None,
        conditions: Mapping[str, str] | None = None,
        maximum: int,
    ) -> HttpResponse:
        allowed = {
            "state-read-write": {watcher.STATE_CONTAINER},
            "result-read-only": {watcher.RESULT_CONTAINER},
            "authority-fence-read-only": {watcher.AUTHORITY_FENCE_CONTAINER},
            "evidence-create-only": {watcher.EVIDENCE_CONTAINER},
            "evidence-read-only": {watcher.EVIDENCE_CONTAINER},
        }
        if role not in allowed:
            fail("storage-role-not-fixed")
        if role.endswith("read-only") and (method != "GET" or body is not None or conditions):
            fail("read-only-storage-mutation")
        if role == "evidence-create-only" and (
            method != "PUT" or (conditions or {}).get("If-None-Match") != "*"
        ):
            fail("evidence-writer-not-create-only")
        if role == "state-read-write" and method not in {"GET", "PUT"}:
            fail("state-storage-method")
        target = self._blob_target(container, blob, allowed[role])
        request_headers = {
            "x-ms-version": STORAGE_DATA_API_VERSION,
            "Accept": "application/json",
        }
        if body is not None:
            request_headers.update({
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "x-ms-blob-type": "BlockBlob",
                "x-ms-blob-content-type": "application/json",
                "x-ms-blob-content-md5": base64.b64encode(
                    hashlib.md5(body, usedforsecurity=False).digest()
                ).decode("ascii"),
            })
        request_headers.update(conditions or {})
        return self._request(
            method,
            role,
            STORAGE_HOST,
            target,
            STORAGE_RESOURCE,
            body=body,
            headers=request_headers,
            maximum=maximum,
        )

    @staticmethod
    def _state_record(response: HttpResponse, expected_body: bytes | None = None) -> watcher.StateRecord:
        if response.status != 200:
            fail("state-read-status")
        if expected_body is not None and response.body != expected_body:
            fail("state-readback-bytes")
        record = watcher.StateRecord(
            body=response.body,
            etag=str(response.headers.get("etag") or ""),
            server_time=_canonical_server_time(str(response.headers.get("date") or "")),
        )
        return record.validate()

    def probe_server_time(self) -> str:
        response = self._storage(
            "GET",
            "state-read-write",
            watcher.STATE_CONTAINER,
            watcher.STATE_BLOB,
            maximum=watcher.MAX_SESSION_BYTES,
        )
        if response.status not in {200, 404}:
            fail("state-clock-probe-status")
        return _canonical_server_time(str(response.headers.get("date") or ""))

    def read_state(self) -> watcher.StateRecord | None:
        response = self._storage(
            "GET",
            "state-read-write",
            watcher.STATE_CONTAINER,
            watcher.STATE_BLOB,
            maximum=watcher.MAX_SESSION_BYTES,
        )
        if response.status == 404:
            _canonical_server_time(str(response.headers.get("date") or ""))
            return None
        return self._state_record(response)

    def create_state(self, body: bytes) -> watcher.StateRecord:
        watcher.strict_canonical_json(body, watcher.MAX_SESSION_BYTES, "state-create")
        response = self._storage(
            "PUT",
            "state-read-write",
            watcher.STATE_CONTAINER,
            watcher.STATE_BLOB,
            body=body,
            conditions={"If-None-Match": "*"},
            maximum=8192,
        )
        if response.status == 412:
            fail("state-create-conflict")
        if response.status != 201:
            fail("state-create-status")
        readback = self.read_state()
        if readback is None or readback.body != body:
            fail("state-create-readback")
        return readback

    def replace_state(self, body: bytes, etag: str) -> watcher.StateRecord:
        watcher.strict_canonical_json(body, watcher.MAX_SESSION_BYTES, "state-replace")
        if not watcher.ETAG_RE.fullmatch(etag):
            fail("state-replace-etag")
        response = self._storage(
            "PUT",
            "state-read-write",
            watcher.STATE_CONTAINER,
            watcher.STATE_BLOB,
            body=body,
            conditions={"If-Match": etag},
            maximum=8192,
        )
        if response.status == 412:
            fail("state-replace-conflict")
        if response.status != 201:
            fail("state-replace-status")
        readback = self.read_state()
        if readback is None or readback.body != body:
            fail("state-replace-readback")
        return readback

    def _arm(
        self,
        method: str,
        target: str,
        *,
        body: Mapping[str, Any] | None = None,
        if_match: str | None = None,
        maximum: int = MAX_REMOTE_JSON,
    ) -> HttpResponse:
        if (
            not target.startswith(f"/subscriptions/{watcher.SUBSCRIPTION_ID}/")
            or "//" in target
            or "#" in target
        ):
            fail("arm-target-not-fixed")
        raw = None if body is None else watcher.canonical_json(dict(body))
        headers = {"Accept": "application/json"}
        if if_match is not None:
            if not ETAG_RE.fullmatch(if_match):
                fail("arm-if-match-invalid")
            headers["If-Match"] = if_match
        if raw is not None:
            headers.update({
                "Content-Type": "application/json",
                "Content-Length": str(len(raw)),
            })
        return self._request(
            method,
            "bridge-control",
            MANAGEMENT_HOST,
            target,
            MANAGEMENT_RESOURCE,
            body=raw,
            headers=headers,
            maximum=maximum,
        )

    @staticmethod
    def _expect_arm_success(response: HttpResponse, label: str) -> dict[str, Any]:
        if response.status != 200:
            fail(f"{label}-status")
        return _json_body(response.body, label)

    def stop_bridge(self) -> None:
        response = self._arm(
            "POST", f"{watcher.BRIDGE_RESOURCE_ID}/stop?api-version={ARM_API_VERSION}",
            maximum=8192,
        )
        if response.status not in {200, 202}:
            fail("bridge-stop-status")

    def reseal_bridge(self) -> None:
        mutations = (
            (
                "PATCH",
                f"{watcher.BRIDGE_RESOURCE_ID}?api-version={ARM_API_VERSION}",
                {"properties": {"publicNetworkAccess": "Disabled"}},
                "bridge-reseal-site",
            ),
            (
                "PATCH",
                f"{watcher.BRIDGE_RESOURCE_ID}/config/web?api-version={ARM_API_VERSION}",
                {"properties": {
                    "linuxFxVersion": "PYTHON|3.12",
                    "alwaysOn": True,
                    "webJobsEnabled": True,
                    "scmIpSecurityRestrictionsUseMain": True,
                    "ftpsState": "Disabled",
                    "ipSecurityRestrictionsDefaultAction": "Deny",
                    "scmIpSecurityRestrictionsDefaultAction": "Deny",
                }},
                "bridge-reseal-config",
            ),
            (
                "PUT",
                f"{watcher.BRIDGE_RESOURCE_ID}/basicPublishingCredentialsPolicies/ftp"
                f"?api-version={ARM_API_VERSION}",
                {"properties": {"allow": False}},
                "bridge-reseal-ftp-policy",
            ),
            (
                "PUT",
                f"{watcher.BRIDGE_RESOURCE_ID}/basicPublishingCredentialsPolicies/scm"
                f"?api-version={ARM_API_VERSION}",
                {"properties": {"allow": False}},
                "bridge-reseal-scm-policy",
            ),
        )
        for method, target, body, label in mutations:
            response = self._arm(method, target, body=body)
            if response.status not in {200, 201, 202}:
                fail(f"{label}-status")

    def _read_settings_record(self) -> tuple[dict[str, str], str]:
        response = self._arm(
            "POST",
            f"{watcher.BRIDGE_RESOURCE_ID}/config/appsettings/list?api-version={ARM_API_VERSION}",
        )
        document = self._expect_arm_success(response, "bridge-settings")
        properties = document.get("properties")
        if (
            not isinstance(properties, dict)
            or any(
                not isinstance(key, str)
                or not isinstance(value, str)
                or len(key) > 256
                or len(value) > 32768
                for key, value in properties.items()
            )
        ):
            fail("bridge-settings-shape")
        etag = response.headers.get("etag")
        if not isinstance(etag, str) or not ETAG_RE.fullmatch(etag):
            fail("bridge-settings-etag")
        return dict(properties), etag

    def _read_settings(self) -> dict[str, str]:
        return self._read_settings_record()[0]

    def delete_transient_settings(self, names: Sequence[str]) -> None:
        if tuple(names) != watcher.TRANSIENT_SETTINGS:
            fail("transient-setting-names-not-exact")
        current, etag = self._read_settings_record()
        retained = {
            key: value for key, value in current.items()
            if key not in watcher.TRANSIENT_SETTINGS
        }
        response = self._arm(
            "PUT",
            f"{watcher.BRIDGE_RESOURCE_ID}/config/appsettings?api-version={ARM_API_VERSION}",
            body={"properties": retained},
            if_match=etag,
        )
        if response.status == 412:
            fail("bridge-settings-cleanup-conflict")
        if response.status not in {200, 201}:
            fail("bridge-settings-cleanup-status")
        readback = self._read_settings()
        if readback != retained:
            fail("bridge-settings-cleanup-readback")

    def read_bridge(self) -> watcher.BridgeSnapshot:
        site = self._expect_arm_success(
            self._arm("GET", f"{watcher.BRIDGE_RESOURCE_ID}?api-version={ARM_API_VERSION}"),
            "bridge-site",
        )
        config = self._expect_arm_success(
            self._arm(
                "GET",
                f"{watcher.BRIDGE_RESOURCE_ID}/config/web?api-version={ARM_API_VERSION}",
            ),
            "bridge-config",
        )
        policies: dict[str, bool] = {}
        for name in ("ftp", "scm"):
            document = self._expect_arm_success(
                self._arm(
                    "GET",
                    f"{watcher.BRIDGE_RESOURCE_ID}/basicPublishingCredentialsPolicies/{name}"
                    f"?api-version={ARM_API_VERSION}",
                ),
                f"bridge-{name}-policy",
            )
            properties = document.get("properties")
            if not isinstance(properties, dict) or type(properties.get("allow")) is not bool:
                fail(f"bridge-{name}-policy-shape")
            policies[name] = properties["allow"]
        site_properties = site.get("properties")
        config_properties = config.get("properties")
        if not isinstance(site_properties, dict) or not isinstance(config_properties, dict):
            fail("bridge-snapshot-shape")
        posture = {
            "state": site_properties.get("state"),
            "publicNetworkAccess": site_properties.get("publicNetworkAccess"),
            "linuxFxVersion": config_properties.get("linuxFxVersion"),
            "alwaysOn": config_properties.get("alwaysOn"),
            "webJobsEnabled": config_properties.get("webJobsEnabled"),
            "scmIpSecurityRestrictionsUseMain": config_properties.get(
                "scmIpSecurityRestrictionsUseMain"
            ),
            "ftpsState": config_properties.get("ftpsState"),
            "ipSecurityRestrictionsDefaultAction": config_properties.get(
                "ipSecurityRestrictionsDefaultAction"
            ),
            "scmIpSecurityRestrictionsDefaultAction": config_properties.get(
                "scmIpSecurityRestrictionsDefaultAction"
            ),
            "ftpBasicPublishingAllowed": policies["ftp"],
            "scmBasicPublishingAllowed": policies["scm"],
        }
        return watcher.BridgeSnapshot(
            resource_id=str(site.get("id") or ""),
            posture=posture,
            settings=self._read_settings(),
        )

    def read_webjob_history(self, history_id: str) -> Mapping[str, Any] | None:
        watcher.exact_history_id(history_id, "history-id")
        target = (
            f"{watcher.BRIDGE_RESOURCE_ID}/triggeredwebjobs/{watcher.WEBJOB_NAME}/history"
            f"?api-version={ARM_API_VERSION}"
        )
        document = self._expect_arm_success(self._arm("GET", target), "webjob-history")
        values = document.get("value")
        if not isinstance(values, list) or document.get("nextLink") not in {None, ""}:
            fail("webjob-history-shape")
        matches = [item for item in values if isinstance(item, dict) and item.get("id") == history_id]
        if not matches:
            return None
        if len(matches) != 1:
            fail("webjob-history-duplicate")
        item = matches[0]
        properties = item.get("properties")
        runs = properties.get("runs") if isinstance(properties, dict) else None
        if not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], dict):
            fail("webjob-history-run-shape")
        run = runs[0]
        projected = {
            "id": item.get("id"),
            "web_job_name": run.get("web_job_name"),
            "web_job_id": run.get("web_job_id"),
            "status": run.get("status"),
            "start_time": run.get("start_time"),
            "end_time": run.get("end_time"),
        }
        if set(projected) != watcher.HISTORY_KEYS:
            fail("webjob-history-projection")
        return projected

    def _read_blob(
        self,
        role: str,
        container: str,
        blob: str,
        maximum: int,
    ) -> bytes | None:
        if type(maximum) is not int or not 0 < maximum <= watcher.MAX_RECEIPT_BYTES:
            fail("blob-read-maximum")
        response = self._storage(
            "GET", role, container, blob, maximum=maximum
        )
        if response.status == 404:
            return None
        if response.status != 200:
            fail("blob-read-status")
        return response.body

    def read_result(self, container: str, blob: str, maximum: int) -> bytes | None:
        return self._read_blob("result-read-only", container, blob, maximum)

    def read_evidence_policy(self) -> watcher.EvidencePolicy:
        resource_id = (
            f"/subscriptions/{watcher.SUBSCRIPTION_ID}/resourceGroups/"
            "rg-paperdesk-rollback-sea-20260808/providers/Microsoft.Storage/"
            f"storageAccounts/{watcher.STORAGE_ACCOUNT}/blobServices/default/containers/"
            f"{watcher.EVIDENCE_CONTAINER}/immutabilityPolicies/default"
        )
        response = self._request(
            "GET",
            "evidence-policy-read-only",
            MANAGEMENT_HOST,
            f"{resource_id}?api-version={STORAGE_ARM_API_VERSION}",
            MANAGEMENT_RESOURCE,
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
            maximum=MAX_REMOTE_JSON,
        )
        if response.status != 200:
            fail("evidence-policy-status")
        document = _json_body(response.body, "evidence-policy")
        properties = document.get("properties")
        if not isinstance(properties, dict):
            fail("evidence-policy-shape")
        return watcher.EvidencePolicy(
            container=watcher.EVIDENCE_CONTAINER,
            state=properties.get("state"),
            retention_days=properties.get("immutabilityPeriodSinceCreationInDays"),
        )

    def read_authority_fence(
        self, container: str, blob: str, maximum: int
    ) -> bytes | None:
        return self._read_blob("authority-fence-read-only", container, blob, maximum)

    def create_evidence(self, container: str, blob: str, body: bytes) -> bool:
        watcher.strict_canonical_json(body, watcher.MAX_RECEIPT_BYTES, "evidence-create")
        response = self._storage(
            "PUT",
            "evidence-create-only",
            container,
            blob,
            body=body,
            conditions={"If-None-Match": "*"},
            maximum=8192,
        )
        if response.status == 201:
            return True
        if response.status == 412:
            return False
        fail("evidence-create-status")

    def read_evidence(self, container: str, blob: str, maximum: int) -> bytes | None:
        return self._read_blob("evidence-read-only", container, blob, maximum)


__all__ = [
    "ARM_API_VERSION",
    "AppServiceManagedIdentity",
    "AzureCleanupBoundary",
    "HttpResponse",
    "HttpTransport",
    "HttpsTransport",
    "IDENTITY_ROLES",
    "build_managed_identity_credentials",
]
