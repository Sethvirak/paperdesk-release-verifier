#!/usr/bin/env python3
"""Fixed-boundary PaperDesk watchdog v2 state, WORM evidence, and dispatch API.

The App Service provider uses managed identity for Azure Storage/ARM and
cryptographically verifies exact-workflow GitHub OIDC bearer tokens. Rollback
workflow dispatch is provider-owned and uses a short-lived GitHub App
installation token; the Actions runner never receives an Azure credential,
GitHub App private key, installation token, state token, or dispatch PAT.

The cryptographic verifier is supplied by pinned PyJWT/cryptography wheels and
the production HTTP boundary is a bounded Gunicorn WSGI deployment.  No caller
may select a host, Azure resource, GitHub repository, workflow, ref, query, or
redirect.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import sys
import threading
import time
from typing import Any, Callable, Mapping
import urllib.error
import urllib.parse
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import watchdog_evidence as evidence
from scripts import watchdog_contract as state_contract
from provider import accepted_release_manifest


APP_NAME = "paperdesk-watchdog-state-9c4e0d0d"
PROVIDER_HOST = f"{APP_NAME}.azurewebsites.net"
STATE_PATH = "/api/watchdog-state/v2"
EVIDENCE_PREFIX = "/api/watchdog-evidence/"
DISPATCH_PATH = "/api/watchdog-dispatch/v2"
STATE_CONTAINER = "paperdesk-watchdog-state"
STATE_BLOB = "v2/current.json"
STORAGE_ACCOUNT = evidence.EVIDENCE_ACCOUNT
STORAGE_RESOURCE_GROUP = evidence.STORAGE_RESOURCE_GROUP
EVIDENCE_CONTAINER = evidence.EVIDENCE_CONTAINER
REGISTRY_CONTAINER = evidence.REGISTRY_CONTAINER
SOURCE_REPOSITORY = evidence.SOURCE_REPOSITORY
SOURCE_OWNER, SOURCE_NAME = SOURCE_REPOSITORY.split("/", 1)
GITHUB_API_HOST = "api.github.com"
GITHUB_API_VERSION = "2026-03-10"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
OIDC_DISCOVERY_URL = f"{OIDC_ISSUER}/.well-known/openid-configuration"
OIDC_JWKS_URL = f"{OIDC_ISSUER}/.well-known/jwks"
STORAGE_API_VERSION = "2023-11-03"
ARM_API_VERSION = "2023-05-01"
MAX_BODY = evidence.MAX_RECEIPT_BYTES
MAX_JWT = 32768
MAX_REMOTE_JSON = 262144
CLAIM_SECONDS = 5 * 60
STATE_METADATA_KEYS = {
    "paperdesk_sha256",
    "paperdesk_schema",
    "paperdesk_initial_baseline_sha256",
    "paperdesk_last_transition_sha256",
}

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
POSITIVE_RE = re.compile(r"^[1-9][0-9]*$")
HOST_RE = re.compile(r"^[a-z0-9.-]{1,253}$")
KID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")


class ProviderError(RuntimeError):
    """A fail-closed provider error with a safe HTTP projection."""

    def __init__(self, message: str, status: int = 400, code: str = "contract-rejected"):
        super().__init__(message)
        self.status = status if 400 <= status <= 599 else 500
        self.code = code if re.fullmatch(r"[a-z0-9-]{1,64}", code) else "provider-error"


def fail(message: str, status: int = 400, code: str = "contract-rejected") -> None:
    raise ProviderError(message, status, code)


def canonical_json(document: Any) -> bytes:
    return evidence.canonical_json(document)


def compact_json(document: Any) -> bytes:
    return json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def now_utc(clock: Callable[[], datetime] | None = None) -> str:
    current = (clock or (lambda: datetime.now(timezone.utc)))()
    if current.tzinfo is None or current.utcoffset() != timedelta(0):
        fail("provider clock is not UTC", 500, "provider-clock-invalid")
    return current.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_canonical_time(value: object, label: str) -> datetime:
    try:
        evidence.canonical_timestamp(value, label)
        return datetime.strptime(str(value), "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except evidence.EvidenceError as exc:
        fail(str(exc))


def jwt_module() -> Any:
    try:
        import jwt
        from cryptography.hazmat.primitives import serialization  # noqa: F401
    except ImportError:
        fail(
            "pinned PyJWT/cryptography verifier dependencies are unavailable",
            503,
            "oidc-verifier-unavailable",
        )
    return jwt


class RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def direct_opener() -> Any:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        RejectRedirectHandler(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )


def read_bounded_json_response(response: Any, expected_url: str, maximum: int = MAX_REMOTE_JSON) -> dict[str, Any]:
    if getattr(response, "status", 0) != 200 or response.geturl() != expected_url:
        fail("remote identity response boundary is invalid", 503, "identity-unavailable")
    if response.headers.get("Content-Encoding", "") not in {"", "identity"}:
        fail("remote identity response encoding is invalid", 503, "identity-unavailable")
    body = response.read(maximum + 1)
    if len(body) > maximum:
        fail("remote identity response is excessive", 503, "identity-unavailable")
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("remote identity response is invalid", 503, "identity-unavailable")
    if not isinstance(document, dict):
        fail("remote identity response is invalid", 503, "identity-unavailable")
    return document


@dataclass(frozen=True)
class WorkflowTrust:
    repository: str
    repository_id: str
    repository_owner_id: str
    workflow_sha: str
    environment: str
    purposes: frozenset[str]


class OIDCVerifier:
    """Verify GitHub OIDC RS256 signatures and exact protected workflow claims."""

    def __init__(
        self,
        watchdog_workflow_sha: str,
        baseline_workflow_sha: str,
        *,
        reconciliation_workflow_sha: str | None = None,
        opener: Any | None = None,
        clock: Callable[[], datetime] | None = None,
    ):
        self.watchdog_workflow_sha = evidence.full_sha(watchdog_workflow_sha, "allowlisted watchdog workflow SHA")
        self.baseline_workflow_sha = evidence.full_sha(baseline_workflow_sha, "allowlisted baseline workflow SHA")
        self.trusts: dict[str, WorkflowTrust] = {
            evidence.WATCHDOG_WORKFLOW_REF: WorkflowTrust(
                evidence.WATCHDOG_REPOSITORY,
                evidence.WATCHDOG_REPOSITORY_ID,
                evidence.WATCHDOG_REPOSITORY_OWNER_ID,
                self.watchdog_workflow_sha,
                evidence.WATCHDOG_ENVIRONMENT,
                frozenset({"state", "evidence", "dispatch", "reconcile-auto"}),
            ),
            evidence.BASELINE_WORKFLOW_REF: WorkflowTrust(
                evidence.WATCHDOG_REPOSITORY,
                evidence.WATCHDOG_REPOSITORY_ID,
                evidence.WATCHDOG_REPOSITORY_OWNER_ID,
                self.baseline_workflow_sha,
                evidence.BASELINE_ENVIRONMENT,
                frozenset({"evidence"}),
            ),
        }
        if reconciliation_workflow_sha is not None:
            self.trusts[evidence.RECONCILIATION_WORKFLOW_REF] = WorkflowTrust(
                evidence.WATCHDOG_REPOSITORY,
                evidence.WATCHDOG_REPOSITORY_ID,
                evidence.WATCHDOG_REPOSITORY_OWNER_ID,
                evidence.full_sha(reconciliation_workflow_sha, "allowlisted reconciliation workflow SHA"),
                evidence.RECONCILIATION_ENVIRONMENT,
                frozenset({"reconcile-manual"}),
            )
        self.opener = opener or direct_opener()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._keys: dict[str, dict[str, Any]] = {}
        self._keys_expires = 0.0
        self._lock = threading.Lock()

    def _load_keys(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            if self._keys and time.monotonic() < self._keys_expires:
                return dict(self._keys)
            discovery_request = urllib.request.Request(
                OIDC_DISCOVERY_URL,
                headers={"Accept": "application/json", "User-Agent": "PaperDeskWatchdogProvider/2"},
                method="GET",
            )
            try:
                with self.opener.open(discovery_request, timeout=15) as response:
                    discovery = read_bounded_json_response(response, OIDC_DISCOVERY_URL)
            except ProviderError:
                raise
            except (OSError, urllib.error.URLError, http.client.HTTPException):
                fail("GitHub OIDC discovery is unavailable", 503, "oidc-keys-unavailable")
            if discovery.get("issuer") != OIDC_ISSUER or discovery.get("jwks_uri") != OIDC_JWKS_URL:
                fail("GitHub OIDC discovery identity is not exact", 503, "oidc-keys-invalid")
            jwks_request = urllib.request.Request(
                OIDC_JWKS_URL,
                headers={"Accept": "application/json", "User-Agent": "PaperDeskWatchdogProvider/2"},
                method="GET",
            )
            try:
                with self.opener.open(jwks_request, timeout=15) as response:
                    jwks = read_bounded_json_response(response, OIDC_JWKS_URL)
            except ProviderError:
                raise
            except (OSError, urllib.error.URLError, http.client.HTTPException):
                fail("GitHub OIDC signing keys are unavailable", 503, "oidc-keys-unavailable")
            values = jwks.get("keys")
            if not isinstance(values, list) or not 1 <= len(values) <= 32:
                fail("GitHub OIDC signing keys are invalid", 503, "oidc-keys-invalid")
            parsed: dict[str, dict[str, Any]] = {}
            for item in values:
                if not isinstance(item, dict) or item.get("kty") != "RSA" or item.get("use") not in {None, "sig"}:
                    continue
                kid = item.get("kid")
                if not isinstance(kid, str) or not KID_RE.fullmatch(kid) or kid in parsed:
                    fail("GitHub OIDC signing key identity is invalid", 503, "oidc-keys-invalid")
                if (
                    item.get("alg") not in {None, "RS256"}
                    or not isinstance(item.get("n"), str)
                    or not isinstance(item.get("e"), str)
                ):
                    fail("GitHub OIDC signing key strength is invalid", 503, "oidc-keys-invalid")
                parsed[kid] = dict(item)
            if not parsed:
                fail("GitHub OIDC has no acceptable signing key", 503, "oidc-keys-invalid")
            self._keys = parsed
            self._keys_expires = time.monotonic() + 300
            return dict(parsed)

    def verify(self, token: str, purpose: str) -> dict[str, Any]:
        if not isinstance(token, str) or not token or len(token) > MAX_JWT or token != token.strip():
            fail("GitHub OIDC bearer token is invalid", 401, "oidc-invalid")
        if token.count(".") != 2:
            fail("GitHub OIDC bearer token shape is invalid", 401, "oidc-invalid")
        jwt = jwt_module()
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            fail("GitHub OIDC bearer token is invalid", 401, "oidc-invalid")
        if header.get("alg") != "RS256" or header.get("typ") not in {None, "JWT"}:
            fail("GitHub OIDC algorithm is not exact RS256", 401, "oidc-invalid")
        kid = header.get("kid")
        if not isinstance(kid, str) or not KID_RE.fullmatch(kid):
            fail("GitHub OIDC key ID is invalid", 401, "oidc-invalid")
        jwk = self._load_keys().get(kid)
        if jwk is None:
            fail("GitHub OIDC signature key is not current", 401, "oidc-invalid")
        try:
            public_key = jwt.PyJWK.from_dict(jwk, algorithm="RS256").key
            claims = jwt.decode(
                token,
                key=public_key,
                algorithms=["RS256"],
                audience=evidence.OIDC_AUDIENCE,
                issuer=OIDC_ISSUER,
                leeway=30,
                options={
                    "require": [
                        "aud", "iss", "sub", "repository", "repository_owner",
                        "repository_id", "repository_owner_id", "ref", "sha",
                        "workflow_ref", "environment", "run_id", "run_attempt",
                        "iat", "nbf", "exp",
                    ],
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                    "verify_exp": True,
                },
            )
        except (jwt.PyJWTError, ValueError, TypeError):
            fail("GitHub OIDC signature or registered claims are invalid", 401, "oidc-invalid")
        if not isinstance(claims, dict):
            fail("GitHub OIDC claims are invalid", 401, "oidc-invalid")
        if purpose not in {
            "state", "evidence", "dispatch", "reconcile-auto", "reconcile-manual",
        }:
            fail("provider OIDC purpose is invalid", 500, "provider-contract-invalid")
        workflow_ref = str(claims.get("workflow_ref") or "")
        trust = self.trusts.get(workflow_ref)
        if trust is None or purpose not in trust.purposes:
            fail("GitHub OIDC workflow is not allowlisted for this operation", 403, "oidc-forbidden")
        repository_owner = trust.repository.split("/", 1)[0]
        expected = {
            "iss": OIDC_ISSUER,
            "aud": evidence.OIDC_AUDIENCE,
            "repository": trust.repository,
            "repository_owner": repository_owner,
            "repository_id": trust.repository_id,
            "repository_owner_id": trust.repository_owner_id,
            "ref": "refs/heads/main",
            "sha": trust.workflow_sha,
            "workflow_ref": workflow_ref,
            "environment": trust.environment,
            "sub": f"repo:{trust.repository}:environment:{trust.environment}",
        }
        for name, value in expected.items():
            if str(claims.get(name) or "") != value:
                fail(f"GitHub OIDC claim {name} is not exact", 403, "oidc-forbidden")
        for name in ("run_id", "run_attempt"):
            if not POSITIVE_RE.fullmatch(str(claims.get(name) or "")):
                fail(f"GitHub OIDC claim {name} is invalid", 403, "oidc-forbidden")
        current = self.clock()
        if current.tzinfo is None or current.utcoffset() != timedelta(0):
            fail("provider clock is invalid", 500, "provider-clock-invalid")
        epoch = int(current.timestamp())
        if not all(isinstance(claims.get(name), int) and not isinstance(claims.get(name), bool) for name in ("iat", "nbf", "exp")):
            fail("GitHub OIDC lifetime claims are invalid", 401, "oidc-invalid")
        if (
            claims["iat"] > epoch + 30 or claims["nbf"] > epoch + 30 or claims["exp"] <= epoch
            or claims["exp"] <= claims["iat"]
            or claims["exp"] - claims["iat"] > 900 or claims["exp"] <= claims["nbf"]
        ):
            fail("GitHub OIDC lifetime is invalid", 401, "oidc-invalid")
        return dict(claims)


@dataclass(frozen=True)
class BlobRecord:
    body: bytes
    etag: str
    version_id: str
    metadata: Mapping[str, str]


@dataclass(frozen=True)
class BlobWriteReceipt:
    etag: str
    version_id: str


class StorageBackend:
    """Interface used by the provider core and dependency-free fakes."""

    def get_blob(self, container: str, path: str, maximum: int) -> BlobRecord | None:
        raise NotImplementedError

    def put_create(self, container: str, path: str, body: bytes, metadata: Mapping[str, str]) -> bool:
        raise NotImplementedError

    def put_replace(
        self, container: str, path: str, body: bytes, expected_etag: str, metadata: Mapping[str, str]
    ) -> BlobWriteReceipt | None:
        raise NotImplementedError

    def policy(self, container: str) -> dict[str, Any]:
        raise NotImplementedError

    def security_posture(self) -> dict[str, Any]:
        """Return a live, fixed-scope Shared-Key/network/RBAC proof."""
        raise NotImplementedError


def safe_blob_path(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or "\\" in value or "\x00" in value or "//" in value:
        fail("blob path is unsafe")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(part in {"", ".", ".."} for part in path.parts):
        fail("blob path is unsafe")
    return value


def validate_identity_endpoint(endpoint: str) -> str:
    if not isinstance(endpoint, str) or not endpoint or endpoint != endpoint.strip() or len(endpoint) > 2048:
        fail("App Service managed identity endpoint is invalid", 500, "managed-identity-invalid")
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        fail("App Service managed identity endpoint is invalid", 500, "managed-identity-invalid")
    if (
        parsed.scheme != "http" or parsed.username is not None or parsed.password is not None or port is None
        or parsed.query or parsed.fragment or parsed.path not in {"/MSI/token", "/MSI/token/"} or not host or "%" in host
    ):
        fail("App Service managed identity endpoint is invalid", 500, "managed-identity-invalid")
    if host != "localhost":
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            fail("managed identity endpoint is not local", 500, "managed-identity-invalid")
        if not (address.is_loopback or address.is_link_local):
            fail("managed identity endpoint is not local", 500, "managed-identity-invalid")
    return endpoint


class ManagedIdentityTokens:
    def __init__(self, client_id: str, environment: Mapping[str, str], opener: Any | None = None):
        if not UUID_RE.fullmatch(client_id):
            fail("provider managed identity client ID is invalid", 500, "managed-identity-invalid")
        self.client_id = client_id
        self.environment = environment
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), RejectRedirectHandler())
        self._cache: dict[str, tuple[str, int]] = {}
        self._lock = threading.Lock()

    def get(self, resource: str) -> str:
        if resource not in {"https://storage.azure.com/", "https://management.azure.com/"}:
            fail("managed identity resource is not fixed", 500, "managed-identity-invalid")
        with self._lock:
            cached = self._cache.get(resource)
            if cached and cached[1] > int(time.time()) + 120:
                return cached[0]
            endpoint = validate_identity_endpoint(str(self.environment.get("IDENTITY_ENDPOINT") or ""))
            header = str(self.environment.get("IDENTITY_HEADER") or "")
            if not header or len(header) > 8192 or "\r" in header or "\n" in header:
                fail("App Service managed identity header is unavailable", 503, "managed-identity-unavailable")
            query = urllib.parse.urlencode({
                "api-version": "2019-08-01", "resource": resource, "client_id": self.client_id,
            })
            url = f"{endpoint}?{query}"
            request = urllib.request.Request(url, headers={"X-IDENTITY-HEADER": header}, method="GET")
            try:
                with self.opener.open(request, timeout=15) as response:
                    if getattr(response, "status", 0) != 200 or response.geturl() != url:
                        fail("managed identity response boundary is invalid", 503, "managed-identity-unavailable")
                    body = response.read(65537)
                if len(body) > 65536:
                    fail("managed identity response is excessive", 503, "managed-identity-unavailable")
                document = json.loads(body.decode("utf-8"))
            except ProviderError:
                raise
            except (OSError, urllib.error.URLError, UnicodeDecodeError, json.JSONDecodeError):
                fail("managed identity token acquisition failed", 503, "managed-identity-unavailable")
            token = document.get("access_token") if isinstance(document, dict) else None
            expires = document.get("expires_on") if isinstance(document, dict) else None
            try:
                expiry = int(expires)
            except (TypeError, ValueError):
                expiry = 0
            if not isinstance(token, str) or len(token) < 100 or len(token) > 32768 or "\r" in token or "\n" in token or expiry <= int(time.time()) + 120:
                fail("managed identity token response is invalid", 503, "managed-identity-unavailable")
            self._cache[resource] = (token, expiry)
            return token


def http_date() -> str:
    return format_datetime(datetime.now(timezone.utc), usegmt=True)


@dataclass(frozen=True)
class AzureIdentityBinding:
    role: str
    client_id: str
    principal_id: str
    identity_resource_id: str
    assignment_id: str
    definition_id: str
    scope: str


class AzureStorageBackend(StorageBackend):
    ROLE_NAMES = frozenset({
        "state-read-write", "evidence-create-only", "evidence-read-only",
        "registry-read-only", "arm-policy-read-only",
    })
    BLOB_READ = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
    BLOB_WRITE = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"
    ARM_POLICY_ACTIONS = frozenset({
        "Microsoft.Storage/storageAccounts/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/read",
        "Microsoft.Authorization/roleAssignments/read",
        "Microsoft.Authorization/roleDefinitions/read",
        "Microsoft.ManagedIdentity/userAssignedIdentities/read",
    })

    def __init__(
        self,
        subscription_id: str,
        identities: Mapping[str, tuple[ManagedIdentityTokens, AzureIdentityBinding]],
    ):
        if not UUID_RE.fullmatch(subscription_id):
            fail("Azure subscription ID is invalid", 500, "provider-config-invalid")
        if set(identities) != self.ROLE_NAMES:
            fail("provider Azure identity roles are not exact", 500, "provider-config-invalid")
        self.subscription_id = subscription_id
        self.identities = dict(identities)
        client_ids = {binding.client_id for _, binding in self.identities.values()}
        principal_ids = {binding.principal_id for _, binding in self.identities.values()}
        assignment_ids = {binding.assignment_id for _, binding in self.identities.values()}
        if len(client_ids) != 5 or len(principal_ids) != 5 or len(assignment_ids) != 5:
            fail("provider Azure identities and assignments must be distinct", 500, "provider-config-invalid")
        self.storage_host = f"{STORAGE_ACCOUNT}.blob.core.windows.net"
        self.account_scope = (
            f"/subscriptions/{subscription_id}/resourceGroups/{STORAGE_RESOURCE_GROUP}/providers/"
            f"Microsoft.Storage/storageAccounts/{STORAGE_ACCOUNT}"
        )
        self._posture_cache: tuple[float, dict[str, Any]] | None = None
        self._posture_lock = threading.Lock()

    @staticmethod
    def _target(container: str, path: str, allowed_containers: frozenset[str]) -> str:
        if container not in allowed_containers:
            fail("storage container is not fixed", 500, "provider-contract-invalid")
        path = safe_blob_path(path)
        encoded = "/".join(urllib.parse.quote(part, safe="") for part in PurePosixPath(path).parts)
        return f"/{container}/{encoded}"

    def _blob_request(
        self,
        method: str,
        role: str,
        container: str,
        path: str,
        *,
        body: bytes | None = None,
        conditions: Mapping[str, str] | None = None,
        metadata: Mapping[str, str] | None = None,
        maximum: int = MAX_BODY,
    ) -> tuple[int, bytes, dict[str, str]]:
        boundaries = {
            "state-read-write": ({"GET", "PUT"}, frozenset({STATE_CONTAINER})),
            "evidence-create-only": ({"PUT"}, frozenset({EVIDENCE_CONTAINER})),
            "evidence-read-only": ({"GET"}, frozenset({EVIDENCE_CONTAINER})),
            "registry-read-only": ({"GET"}, frozenset({REGISTRY_CONTAINER})),
        }
        allowed = boundaries.get(role)
        if allowed is None or method not in allowed[0]:
            fail("storage method is outside the fixed identity boundary", 500, "provider-contract-invalid")
        if role == "evidence-create-only" and (conditions or {}).get("If-None-Match") != "*":
            fail("evidence writer is not create-only", 500, "provider-contract-invalid")
        if role.endswith("read-only") and (body is not None or conditions or metadata):
            fail("read-only storage identity received a mutation", 500, "provider-contract-invalid")
        target = self._target(container, path, allowed[1])
        tokens, _ = self.identities[role]
        connection = http.client.HTTPSConnection(self.storage_host, timeout=30, context=ssl.create_default_context())
        headers = {
            "Authorization": f"Bearer {tokens.get('https://storage.azure.com/')}",
            "x-ms-version": STORAGE_API_VERSION,
            "x-ms-date": http_date(),
        }
        if body is not None:
            headers.update({
                "Content-Length": str(len(body)),
                "Content-Type": "application/json",
                "x-ms-blob-type": "BlockBlob",
                "x-ms-blob-content-type": "application/json",
                "x-ms-blob-content-md5": base64.b64encode(hashlib.md5(body, usedforsecurity=False).digest()).decode("ascii"),
            })
        for name, value in (conditions or {}).items():
            headers[name] = value
        for name, value in (metadata or {}).items():
            if name not in STATE_METADATA_KEYS or not isinstance(value, str) or not value or len(value) > 256 or "\r" in value or "\n" in value:
                fail("state metadata is invalid", 500, "provider-contract-invalid")
            headers[f"x-ms-meta-{name}"] = value
        try:
            connection.request(method, target, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read(maximum + 1)
            if len(response_body) > maximum:
                fail("Azure Blob response is excessive", 503, "storage-unavailable")
            return response.status, response_body, {name.lower(): value for name, value in response.getheaders()}
        except ProviderError:
            raise
        except (OSError, http.client.HTTPException):
            fail("Azure Blob request failed", 503, "storage-unavailable")
        finally:
            connection.close()

    def get_blob(self, container: str, path: str, maximum: int) -> BlobRecord | None:
        roles = {
            STATE_CONTAINER: "state-read-write",
            EVIDENCE_CONTAINER: "evidence-read-only",
            REGISTRY_CONTAINER: "registry-read-only",
        }
        role = roles.get(container)
        if role is None:
            fail("storage read container is not fixed", 500, "provider-contract-invalid")
        status, body, headers = self._blob_request("GET", role, container, path, maximum=maximum)
        if status == 404:
            return None
        if status != 200:
            fail(f"Azure Blob read failed with HTTP {status}", 503, "storage-unavailable")
        etag = headers.get("etag", "")
        version_id = headers.get("x-ms-version-id", "")
        if not evidence.ETAG.fullmatch(etag) or not evidence.SAFE_VERSION_ID.fullmatch(version_id):
            fail("Azure Blob provenance headers are invalid", 503, "storage-provenance-invalid")
        metadata = {
            name.removeprefix("x-ms-meta-"): value
            for name, value in headers.items()
            if name.startswith("x-ms-meta-")
        }
        return BlobRecord(body, etag, version_id, metadata)

    def put_create(self, container: str, path: str, body: bytes, metadata: Mapping[str, str]) -> bool:
        role = {
            STATE_CONTAINER: "state-read-write",
            EVIDENCE_CONTAINER: "evidence-create-only",
        }.get(container)
        if role is None:
            fail("storage create container is not fixed", 500, "provider-contract-invalid")
        status, _, _ = self._blob_request(
            "PUT", role, container, path, body=body, conditions={"If-None-Match": "*"}, metadata=metadata
        )
        if status == 201:
            return True
        if status == 412:
            return False
        fail(f"Azure Blob create-only write failed with HTTP {status}", 503, "storage-unavailable")

    def put_replace(
        self, container: str, path: str, body: bytes, expected_etag: str, metadata: Mapping[str, str]
    ) -> BlobWriteReceipt | None:
        if container != STATE_CONTAINER:
            fail("compare-and-swap is restricted to mutable watchdog state", 500, "provider-contract-invalid")
        if not evidence.ETAG.fullmatch(expected_etag):
            fail("state storage ETag is invalid", 500, "provider-contract-invalid")
        status, _, headers = self._blob_request(
            "PUT", "state-read-write", container, path, body=body,
            conditions={"If-Match": expected_etag}, metadata=metadata
        )
        if status == 201:
            etag = headers.get("etag", "")
            version_id = headers.get("x-ms-version-id", "")
            if not evidence.ETAG.fullmatch(etag) or not evidence.SAFE_VERSION_ID.fullmatch(version_id):
                fail(
                    "Azure Blob compare-and-swap response provenance is invalid",
                    503,
                    "storage-provenance-invalid",
                )
            return BlobWriteReceipt(etag=etag, version_id=version_id)
        if status == 412:
            return None
        fail(f"Azure Blob compare-and-swap failed with HTTP {status}", 503, "storage-unavailable")

    def policy(self, container: str) -> dict[str, Any]:
        if container not in {EVIDENCE_CONTAINER, REGISTRY_CONTAINER}:
            fail("immutability policy container is not fixed", 500, "provider-contract-invalid")
        resource_id = (
            f"/subscriptions/{self.subscription_id}/resourceGroups/{STORAGE_RESOURCE_GROUP}/providers/"
            f"Microsoft.Storage/storageAccounts/{STORAGE_ACCOUNT}/blobServices/default/containers/"
            f"{container}/immutabilityPolicies/default"
        )
        path = f"{resource_id}?api-version={ARM_API_VERSION}"
        connection = http.client.HTTPSConnection("management.azure.com", timeout=30, context=ssl.create_default_context())
        headers = {
            "Authorization": f"Bearer {self.identities['arm-policy-read-only'][0].get('https://management.azure.com/')}",
            "Accept": "application/json",
            "User-Agent": "PaperDeskWatchdogProvider/2",
        }
        try:
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            body = response.read(65537)
            if response.status != 200 or len(body) > 65536:
                fail("immutability policy read failed", 503, "policy-unavailable")
            document = json.loads(body.decode("utf-8"))
        except ProviderError:
            raise
        except (OSError, http.client.HTTPException, UnicodeDecodeError, json.JSONDecodeError):
            fail("immutability policy read failed", 503, "policy-unavailable")
        finally:
            connection.close()
        properties = document.get("properties") if isinstance(document, dict) else None
        if not isinstance(properties, dict):
            fail("immutability policy response is invalid", 503, "policy-invalid")
        return {
            "resourceId": resource_id,
            "state": properties.get("state"),
            "immutabilityPeriodSinceCreationInDays": properties.get("immutabilityPeriodSinceCreationInDays"),
            "allowProtectedAppendWrites": properties.get("allowProtectedAppendWrites"),
            "allowProtectedAppendWritesAll": properties.get("allowProtectedAppendWritesAll"),
            "etag": document.get("etag"),
            "observedAt": now_utc(),
        }

    def _arm_json(self, path: str) -> dict[str, Any]:
        if not path.startswith("/subscriptions/") or "//" in path or "#" in path:
            fail("ARM proof path is outside the fixed boundary", 500, "provider-contract-invalid")
        connection = http.client.HTTPSConnection("management.azure.com", timeout=30, context=ssl.create_default_context())
        headers = {
            "Authorization": f"Bearer {self.identities['arm-policy-read-only'][0].get('https://management.azure.com/')}",
            "Accept": "application/json",
            "User-Agent": "PaperDeskWatchdogProvider/2",
        }
        try:
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            body = response.read(MAX_REMOTE_JSON + 1)
            if response.status != 200 or len(body) > MAX_REMOTE_JSON:
                fail("live Azure security proof read failed", 503, "rbac-proof-unavailable")
            document = json.loads(body.decode("utf-8"))
        except ProviderError:
            raise
        except (OSError, http.client.HTTPException, UnicodeDecodeError, json.JSONDecodeError):
            fail("live Azure security proof read failed", 503, "rbac-proof-unavailable")
        finally:
            connection.close()
        if not isinstance(document, dict):
            fail("live Azure security proof is invalid", 503, "rbac-proof-invalid")
        return document

    def _read_security_posture(self) -> dict[str, Any]:
        account = self._arm_json(f"{self.account_scope}?api-version={ARM_API_VERSION}")
        properties = account.get("properties")
        if not isinstance(properties, dict):
            fail("storage account posture response is invalid", 503, "rbac-proof-invalid")
        containers: dict[str, dict[str, Any]] = {}
        for container in (STATE_CONTAINER, EVIDENCE_CONTAINER, REGISTRY_CONTAINER):
            scope = f"{self.account_scope}/blobServices/default/containers/{container}"
            document = self._arm_json(f"{scope}?api-version={ARM_API_VERSION}")
            container_properties = document.get("properties")
            if not isinstance(container_properties, dict):
                fail("storage container posture response is invalid", 503, "rbac-proof-invalid")
            containers[container] = {
                "resourceId": scope,
                "publicAccess": container_properties.get("publicAccess"),
            }
        expected_permissions = {
            "state-read-write": (frozenset(), frozenset({self.BLOB_READ, self.BLOB_WRITE})),
            "evidence-create-only": (frozenset(), frozenset({self.BLOB_WRITE})),
            "evidence-read-only": (frozenset(), frozenset({self.BLOB_READ})),
            "registry-read-only": (frozenset(), frozenset({self.BLOB_READ})),
            "arm-policy-read-only": (self.ARM_POLICY_ACTIONS, frozenset()),
        }
        assignments: list[dict[str, Any]] = []
        for role in sorted(self.ROLE_NAMES):
            _, binding = self.identities[role]
            identity = self._arm_json(f"{binding.identity_resource_id}?api-version=2023-01-31")
            identity_properties = identity.get("properties")
            if (
                not isinstance(identity_properties, dict)
                or identity.get("id", "").lower() != binding.identity_resource_id.lower()
                or str(identity_properties.get("clientId") or "").lower() != binding.client_id.lower()
                or str(identity_properties.get("principalId") or "").lower() != binding.principal_id.lower()
            ):
                fail("Azure user-assigned identity mapping is not exact", 503, "rbac-proof-invalid")
            assignment_resource = f"{binding.scope}/providers/Microsoft.Authorization/roleAssignments/{binding.assignment_id}"
            filter_value = f"principalId eq '{binding.principal_id}'"
            query = urllib.parse.urlencode({"api-version": "2022-04-01", "$filter": filter_value})
            effective = self._arm_json(
                f"/subscriptions/{self.subscription_id}/providers/"
                f"Microsoft.Authorization/roleAssignments?{query}"
            )
            values = effective.get("value")
            if effective.get("nextLink") not in (None, "") or not isinstance(values, list) or len(values) != 1:
                fail(
                    "Azure identity has missing, extra, or paginated direct role assignments",
                    503,
                    "rbac-proof-invalid",
                )
            assignment = values[0]
            if not isinstance(assignment, dict):
                fail("Azure effective role assignment proof is invalid", 503, "rbac-proof-invalid")
            assignment_properties = assignment.get("properties")
            expected_definition = (
                f"/subscriptions/{self.subscription_id}/providers/Microsoft.Authorization/"
                f"roleDefinitions/{binding.definition_id}"
            )
            if (
                not isinstance(assignment_properties, dict)
                or str(assignment.get("id") or "").lower() != assignment_resource.lower()
                or str(assignment.get("name") or "").lower() != binding.assignment_id.lower()
                or assignment.get("type") != "Microsoft.Authorization/roleAssignments"
                or str(assignment_properties.get("principalId") or "").lower() != binding.principal_id.lower()
                or assignment_properties.get("principalType") != "ServicePrincipal"
                or str(assignment_properties.get("roleDefinitionId") or "").lower() != expected_definition.lower()
                or str(assignment_properties.get("scope") or "").lower() != binding.scope.lower()
                or assignment_properties.get("condition") is not None
                or assignment_properties.get("conditionVersion") is not None
                or assignment_properties.get("delegatedManagedIdentityResourceId") is not None
            ):
                fail("Azure role assignment proof is not exact", 503, "rbac-proof-invalid")
            definition = self._arm_json(f"{expected_definition}?api-version=2022-04-01")
            definition_properties = definition.get("properties")
            permissions = definition_properties.get("permissions") if isinstance(definition_properties, dict) else None
            if (
                not isinstance(definition_properties, dict)
                or str(definition.get("id") or "").lower() != expected_definition.lower()
                or str(definition.get("name") or "").lower() != binding.definition_id.lower()
                or definition.get("type") != "Microsoft.Authorization/roleDefinitions"
                or definition_properties.get("type") != "CustomRole"
                or not isinstance(definition_properties.get("assignableScopes"), list)
                or len(definition_properties["assignableScopes"]) != 1
                or not isinstance(definition_properties["assignableScopes"][0], str)
                or definition_properties["assignableScopes"][0].lower()
                != f"/subscriptions/{self.subscription_id}".lower()
                or not isinstance(permissions, list) or len(permissions) != 1
                or not isinstance(permissions[0], dict)
            ):
                fail("Azure custom role definition proof is invalid", 503, "rbac-proof-invalid")
            permission = permissions[0]
            raw_actions = permission.get("actions")
            raw_data_actions = permission.get("dataActions")
            if (
                not isinstance(raw_actions, list)
                or not isinstance(raw_data_actions, list)
                or any(not isinstance(value, str) for value in raw_actions + raw_data_actions)
            ):
                fail("Azure custom role permissions are invalid", 503, "rbac-proof-invalid")
            actions = frozenset(raw_actions)
            data_actions = frozenset(raw_data_actions)
            if (
                actions != expected_permissions[role][0]
                or data_actions != expected_permissions[role][1]
                or len(raw_actions) != len(actions)
                or len(raw_data_actions) != len(data_actions)
                or permission.get("notActions") != []
                or permission.get("notDataActions") != []
                or any("delete" in value.lower() for value in actions | data_actions)
            ):
                fail("Azure custom role permissions are not the no-delete least-privilege contract", 503, "rbac-proof-invalid")
            assignments.append({
                "role": role,
                "clientId": binding.client_id,
                "principalId": binding.principal_id,
                "identityResourceId": binding.identity_resource_id,
                "scope": binding.scope,
                "roleAssignmentId": binding.assignment_id,
                "roleDefinitionId": binding.definition_id,
                "actions": sorted(actions),
                "dataActions": sorted(data_actions),
            })
        return {
            "schemaVersion": 2,
            "storageAccountResourceId": self.account_scope,
            "allowSharedKeyAccess": properties.get("allowSharedKeyAccess"),
            "allowBlobPublicAccess": properties.get("allowBlobPublicAccess"),
            "publicNetworkAccess": properties.get("publicNetworkAccess"),
            "containers": [containers[name] for name in sorted(containers)],
            "assignments": assignments,
            "observedAt": now_utc(),
        }

    def security_posture(self) -> dict[str, Any]:
        with self._posture_lock:
            if self._posture_cache is not None and self._posture_cache[0] > time.monotonic():
                return json.loads(json.dumps(self._posture_cache[1]))
            posture = self._read_security_posture()
            try:
                evidence.validate_security_posture(posture)
            except evidence.EvidenceError as exc:
                fail(str(exc), 503, "rbac-proof-invalid")
            self._posture_cache = (time.monotonic() + 60, posture)
            return json.loads(json.dumps(posture))


def github_app_jwt(app_id: str, private_key_pem: str, observed_at: datetime) -> str:
    if not POSITIVE_RE.fullmatch(app_id) or len(app_id) > 20:
        fail("GitHub App ID is invalid", 503, "github-app-unavailable")
    if observed_at.tzinfo is None or observed_at.utcoffset() != timedelta(0):
        fail("GitHub App clock is invalid", 500, "provider-clock-invalid")
    epoch = int(observed_at.timestamp())
    jwt = jwt_module()
    try:
        token = jwt.encode(
            {"exp": epoch + 540, "iat": epoch - 60, "iss": app_id},
            private_key_pem,
            algorithm="RS256",
            headers={"typ": "JWT"},
        )
    except (jwt.PyJWTError, ValueError, TypeError):
        fail("GitHub App private key is invalid", 503, "github-app-unavailable")
    if not isinstance(token, str) or len(token) > MAX_JWT:
        fail("GitHub App JWT is invalid", 503, "github-app-unavailable")
    return token


@dataclass(frozen=True)
class GithubDispatchResult:
    workflow_run_id: str
    workflow_run_api_url: str
    workflow_run_html_url: str
    github_request_id: str


class GithubAppDispatcher:
    """Mint one installation token server-side and dispatch one fixed workflow."""

    def __init__(
        self,
        app_id: str | None,
        installation_id: str | None,
        private_key_pem: str | None,
        *,
        connection_factory: Callable[[], http.client.HTTPSConnection] | None = None,
        clock: Callable[[], datetime] | None = None,
    ):
        self.app_id = app_id
        self.installation_id = installation_id
        self.private_key_pem = private_key_pem
        self.connection_factory = connection_factory or (
            lambda: http.client.HTTPSConnection(GITHUB_API_HOST, timeout=30, context=ssl.create_default_context())
        )
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def configured(self) -> bool:
        values = (self.app_id, self.installation_id, self.private_key_pem)
        return all(isinstance(value, str) and bool(value) for value in values)

    def _installation_token(self) -> str:
        if not self.configured():
            fail(
                "provider-side GitHub App dispatch is not configured",
                503,
                "github-app-activation-required",
            )
        assert self.app_id is not None and self.installation_id is not None and self.private_key_pem is not None
        if not POSITIVE_RE.fullmatch(self.installation_id) or len(self.installation_id) > 20:
            fail("GitHub App installation ID is invalid", 503, "github-app-unavailable")
        app_token = github_app_jwt(self.app_id, self.private_key_pem, self.clock())
        body = compact_json({
            "permissions": {"actions": "write", "metadata": "read"},
            "repository_ids": [1287744543],
        })
        path = f"/app/installations/{self.installation_id}/access_tokens"
        connection = self.connection_factory()
        try:
            connection.request("POST", path, body=body, headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {app_token}",
                "Content-Length": str(len(body)),
                "Content-Type": "application/json",
                "User-Agent": "PaperDeskWatchdogProvider/2",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
            })
            response = connection.getresponse()
            raw = response.read(65537)
            if response.status != 201 or len(raw) > 65536:
                fail("GitHub App installation-token mint failed", 503, "github-app-unavailable")
            document = json.loads(raw.decode("utf-8"))
        except ProviderError:
            raise
        except (OSError, http.client.HTTPException, UnicodeDecodeError, json.JSONDecodeError):
            fail("GitHub App installation-token mint failed", 503, "github-app-unavailable")
        finally:
            app_token = ""
            connection.close()
        token = document.get("token") if isinstance(document, dict) else None
        expires_at = document.get("expires_at") if isinstance(document, dict) else None
        repositories = document.get("repositories") if isinstance(document, dict) else None
        permissions = document.get("permissions") if isinstance(document, dict) else None
        if (
            not isinstance(token, str) or not 20 <= len(token) <= 4096
            or token != token.strip() or "\r" in token or "\n" in token
            or permissions != {"actions": "write", "metadata": "read"}
            or not isinstance(repositories, list) or len(repositories) != 1
            or not isinstance(repositories[0], dict)
            or repositories[0].get("id") != 1287744543
            or repositories[0].get("full_name") != SOURCE_REPOSITORY
        ):
            fail("GitHub App installation-token response is invalid", 503, "github-app-unavailable")
        expires = parse_canonical_or_github_time(expires_at, "GitHub App installation token expiry")
        remaining = (expires - self.clock()).total_seconds()
        if not 60 <= remaining <= 3600:
            fail("GitHub App installation-token lifetime is invalid", 503, "github-app-unavailable")
        return token

    def dispatch(self, attempt: Mapping[str, Any]) -> GithubDispatchResult:
        inputs = {
            "operation": "rollback-accepted-release",
            "confirmation": "ROLLBACK PAPERDESK PRODUCTION",
            "expected_current_live_sha": str(attempt["expectedCurrentLiveSha"]),
            "rollback_source_sha": str(attempt["rollback"]["sourceSha"]),
            "rollback_source_run_id": str(attempt["rollback"]["sourceRunId"]),
            "rollback_source_run_attempt": str(attempt["rollback"]["sourceRunAttempt"]),
            "rollback_acceptance_run_id": str(attempt["rollback"]["acceptanceRunId"]),
            "rollback_acceptance_run_attempt": str(attempt["rollback"]["acceptanceRunAttempt"]),
            "rollback_baseline_receipt_sha256": str(attempt["rollback"]["baselineReceiptSha256"]),
            "watchdog_claim_id": str(attempt["claimId"]),
            "watchdog_attempt_receipt_sha256": hashlib.sha256(canonical_json(attempt)).hexdigest(),
        }
        body = compact_json({"inputs": inputs, "ref": "main"})
        installation_token = self._installation_token()
        path = (
            f"/repos/{SOURCE_REPOSITORY}/actions/workflows/"
            "main_master-data-structure-sea-9c4e0d0d.yml/dispatches"
        )
        connection = self.connection_factory()
        try:
            connection.request("POST", path, body=body, headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {installation_token}",
                "Content-Length": str(len(body)),
                "Content-Type": "application/json",
                "User-Agent": "PaperDeskWatchdogProvider/2",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
            })
            response = connection.getresponse()
            response_body = response.read(65537)
            request_ids = [value for name, value in response.getheaders() if name.lower() == "x-github-request-id"]
            request_id = request_ids[0] if len(request_ids) == 1 and evidence.REQUEST_ID.fullmatch(request_ids[0]) else None
            if response.status == 200 and len(response_body) <= 65536 and request_id:
                try:
                    document = json.loads(response_body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    document = None
                if isinstance(document, dict):
                    run_id = str(document.get("workflow_run_id") or "")
                    api_url = document.get("run_url")
                    html_url = document.get("html_url")
                    if (
                        POSITIVE_RE.fullmatch(run_id)
                        and api_url == f"https://api.github.com/repos/{SOURCE_REPOSITORY}/actions/runs/{run_id}"
                        and html_url == f"https://github.com/{SOURCE_REPOSITORY}/actions/runs/{run_id}"
                    ):
                        return GithubDispatchResult(run_id, api_url, html_url, request_id)
                fail("GitHub workflow dispatch HTTP 200 omitted exact run details", 503, "github-dispatch-indeterminate")
            if 400 <= response.status <= 499 and request_id:
                fail("GitHub workflow dispatch was rejected", 503, "github-dispatch-rejected")
            fail("GitHub workflow dispatch outcome is indeterminate", 503, "github-dispatch-indeterminate")
        except (OSError, http.client.HTTPException):
            fail("GitHub workflow dispatch outcome is indeterminate", 503, "github-dispatch-indeterminate")
        finally:
            installation_token = ""
            connection.close()


def parse_canonical_or_github_time(value: object, label: str) -> datetime:
    text = str(value or "")
    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z",
        text,
    ):
        fail(f"{label} is invalid", 503, "github-app-unavailable")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        fail(f"{label} is invalid", 503, "github-app-unavailable")
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        fail(f"{label} is invalid", 503, "github-app-unavailable")
    return parsed.astimezone(timezone.utc)

STATE_FIELDS = (
    "schemaVersion", "generatedAt", "sourceRepository", "rollbackBaseline",
    "pendingCandidate",
)
BASELINE_FIELDS = (
    "schemaVersion", "receiptSha256", "evidencePath", "sourceSha", "sourceRunId",
    "sourceRunAttempt", "acceptanceRunId", "acceptanceRunAttempt",
    "acceptedReleaseManifestSha256", "acceptedReleasePrefix", "reviewWorkflowRef",
    "reviewWorkflowSha", "reviewRunId", "reviewRunAttempt", "reviewEnvironment",
    "preparedAt",
)
PENDING_FIELDS = (
    "candidateSha", "candidateRunId", "candidateRunAttempt", "completedAt",
    "deadline", "acceptedReceiptPresent", "liveSha", "dispatchGuard", "rollback",
)
GUARD_FIELDS = (
    "status", "generation", "claimId", "leaseExpiresAt", "watchdogRunId",
    "watchdogRunAttempt", "decisionReceiptSha256", "decisionEvidenceETag",
    "attemptReceiptSha256", "workflowRunId", "authorizationReceiptSha256",
)
ROLLBACK_FIELDS = (
    "sourceSha", "sourceRunId", "sourceRunAttempt", "acceptanceRunId",
    "acceptanceRunAttempt", "baselineReceiptSha256",
)
TRANSITION_RECEIPT_FIELDS = (
    "schemaVersion", "receiptType", "operation", "recordedAt", "request",
    "requestSha256", "callerOidc", "previousState", "previousStateSha256",
    "previousStateETag", "nextState", "nextStateSha256",
    "operationReceiptSha256",
)
INITIAL_BASELINE_RECEIPT_FIELDS = (
    "schemaVersion", "receiptType", "recordedAt", "storageAccount",
    "evidenceContainer", "evidencePath", "sourceRepository", "sourceSha",
    "sourceRunId", "sourceRunAttempt", "acceptanceRunId", "acceptanceRunAttempt",
    "acceptedReleaseManifestSha256", "acceptedReleasePrefix", "reviewWorkflowRef",
    "reviewWorkflowSha", "reviewRunId", "reviewRunAttempt", "reviewEnvironment",
)
RECONCILIATION_RECEIPT_FIELDS = (
    "schemaVersion", "receiptType", "resolution", "recordedAt", "claimId",
    "dispatchGuardGeneration", "attemptReceiptPresent", "workflowRunId",
    "dispatchReceiptSha256", "callerOidc", "previousState",
    "previousStateSha256", "previousStateLastTransitionSha256", "nextState",
    "nextStateSha256",
)
DECISION_FIELDS = (
    "schemaVersion", "receiptType", "decision", "sourceRepository",
    "candidateSha", "candidateRunId", "candidateRunAttempt",
    "expectedCurrentLiveSha", "watchdogRunId", "watchdogRunAttempt",
    "observedStateSha256", "decidedAt",
)
WATCHDOG_REPOSITORY = "Sethvirak/paperdesk-release-verifier"
WATCHDOG_REPOSITORY_ID = "1333353701"
WATCHDOG_OWNER_ID = "202535166"
WATCHDOG_WORKFLOW_REF = (
    f"{WATCHDOG_REPOSITORY}/.github/workflows/"
    "accepted-release-deadline-watchdog.yml@refs/heads/main"
)
RECONCILIATION_WORKFLOW_REF = (
    f"{WATCHDOG_REPOSITORY}/.github/workflows/"
    "reconcile-watchdog-dispatch.yml@refs/heads/main"
)
BASELINE_WORKFLOW_REF = (
    f"{WATCHDOG_REPOSITORY}/.github/workflows/"
    "initialize-watchdog-rollback-baseline.yml@refs/heads/main"
)
WATCHDOG_ENVIRONMENT = "paperdesk-watchdog"
RECONCILIATION_ENVIRONMENT = "paperdesk-watchdog-reconciliation"
BASELINE_ENVIRONMENT = "paperdesk-watchdog-baseline"


@dataclass(frozen=True)
class StateSnapshot:
    document: Mapping[str, Any]
    raw: bytes
    sha256: str
    etag: str
    storage_etag: str
    metadata: Mapping[str, str]


@dataclass(frozen=True)
class HTTPResult:
    status_code: int
    document: Mapping[str, Any]


@dataclass(frozen=True)
class WormRecord:
    document: Mapping[str, Any]
    raw: bytes
    sha256: str
    path: str
    etag: str
    version_id: str
    created: bool


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _exact_object(value: object, fields: tuple[str, ...], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != set(fields) or len(value) != len(fields):
        fail(f"{label} fields are not exact")
    return value


def _parse_canonical(raw: bytes, label: str, maximum: int = MAX_BODY) -> Mapping[str, Any]:
    if not isinstance(raw, bytes) or not 2 <= len(raw) <= maximum:
        fail(f"{label} byte length is invalid")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"{label} is not valid UTF-8 JSON")
    if not isinstance(document, dict) or canonical_json(document) != raw:
        fail(f"{label} must be one canonical JSON object")
    return document


def _parse_durable_canonical(raw: bytes, label: str, maximum: int = MAX_BODY) -> Mapping[str, Any]:
    try:
        return _parse_canonical(raw, label, maximum)
    except ProviderError as exc:
        if exc.status >= 500:
            raise
        fail(f"{label} durable bytes are invalid", 503, "durable-data-invalid")


def _positive(value: object, label: str) -> str:
    text = str(value or "")
    if not isinstance(value, str) or not POSITIVE_RE.fullmatch(text):
        fail(f"{label} must be a positive-integer string")
    return text


def _digest(value: object, label: str) -> str:
    text = str(value or "")
    if not isinstance(value, str) or not state_contract.SHA256.fullmatch(text):
        fail(f"{label} must be a lowercase SHA-256")
    return text


def _full_sha(value: object, label: str) -> str:
    text = str(value or "")
    if not isinstance(value, str) or not state_contract.SHA40.fullmatch(text):
        fail(f"{label} must be a full lowercase commit SHA")
    return text


def _etag(value: object, label: str) -> str:
    text = str(value or "")
    if not isinstance(value, str) or not state_contract.ETAG.fullmatch(text):
        fail(f"{label} is invalid")
    return text


def _validate_baseline(value: object) -> Mapping[str, Any]:
    baseline = _exact_object(value, BASELINE_FIELDS, "rollbackBaseline")
    if baseline.get("schemaVersion") != 2:
        fail("rollbackBaseline schemaVersion must equal 2", 503, "state-invalid")
    _digest(baseline.get("receiptSha256"), "rollbackBaseline receiptSha256")
    path = str(baseline.get("evidencePath") or "")
    if not path.endswith(".json") or len(path) > 512 or ".." in path.split("/"):
        fail("rollbackBaseline evidencePath is invalid", 503, "state-invalid")
    source_sha = _full_sha(baseline.get("sourceSha"), "rollbackBaseline sourceSha")
    for name in (
        "sourceRunId", "sourceRunAttempt", "acceptanceRunId",
        "acceptanceRunAttempt", "reviewRunId", "reviewRunAttempt",
    ):
        _positive(baseline.get(name), f"rollbackBaseline {name}")
    _digest(
        baseline.get("acceptedReleaseManifestSha256"),
        "rollbackBaseline acceptedReleaseManifestSha256",
    )
    prefix = (
        f"v1/releases/{source_sha}/{baseline['sourceRunId']}/"
        f"{baseline['acceptanceRunId']}/"
    )
    if baseline.get("acceptedReleasePrefix") != prefix:
        fail("rollbackBaseline acceptedReleasePrefix is not exact", 503, "state-invalid")
    workflow_ref = str(baseline.get("reviewWorkflowRef") or "")
    workflow_sha = _full_sha(
        baseline.get("reviewWorkflowSha"),
        "rollbackBaseline reviewWorkflowSha",
    )
    initial_review = (
        workflow_ref == BASELINE_WORKFLOW_REF
        and baseline.get("reviewEnvironment") == BASELINE_ENVIRONMENT
        and bool(state_contract.EVIDENCE_PATH.fullmatch(path))
    )
    promoted_workflow_ref = (
        f"{SOURCE_REPOSITORY}/.github/workflows/"
        f"main_master-data-structure-sea-9c4e0d0d.yml@{source_sha}"
    )
    promoted_review = (
        workflow_ref == promoted_workflow_ref
        and workflow_sha == source_sha
        and baseline.get("reviewEnvironment") == "production"
        and baseline.get("reviewRunId") == baseline.get("acceptanceRunId")
        and baseline.get("reviewRunAttempt") == baseline.get("acceptanceRunAttempt")
        and path == (
            prefix
            + f"receipts/paperdesk-production-acceptance-receipt-{source_sha}.json"
        )
    )
    if not initial_review and not promoted_review:
        fail("rollbackBaseline review provenance is not exact", 503, "state-invalid")
    parse_canonical_time(baseline.get("preparedAt"), "rollbackBaseline preparedAt")
    return baseline


def _validate_initial_baseline_receipt(
    record: WormRecord,
    baseline: Mapping[str, Any],
) -> Mapping[str, Any]:
    document = record.document
    if not isinstance(document, dict) or set(document) != set(INITIAL_BASELINE_RECEIPT_FIELDS):
        fail("initial baseline WORM receipt fields are invalid", 409, "baseline-evidence-conflict")
    expected = {
        "schemaVersion": 2,
        "receiptType": "watchdog-initial-rollback-baseline",
        "recordedAt": baseline["preparedAt"],
        "storageAccount": STORAGE_ACCOUNT,
        "evidenceContainer": EVIDENCE_CONTAINER,
        "evidencePath": baseline["evidencePath"],
        "sourceRepository": SOURCE_REPOSITORY,
        **{
            name: baseline[name]
            for name in (
                "sourceSha", "sourceRunId", "sourceRunAttempt", "acceptanceRunId",
                "acceptanceRunAttempt", "acceptedReleaseManifestSha256",
                "acceptedReleasePrefix", "reviewWorkflowRef", "reviewWorkflowSha",
                "reviewRunId", "reviewRunAttempt", "reviewEnvironment",
            )
        },
    }
    if document != expected:
        fail(
            "initial baseline WORM receipt differs from reviewed baseline coordinates",
            409,
            "baseline-evidence-conflict",
        )
    parse_canonical_time(document["recordedAt"], "initial baseline receipt recordedAt")
    return document


def empty_guard(generation: int) -> dict[str, Any]:
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        fail("dispatch guard generation must be a positive integer", 500, "provider-contract-invalid")
    return {
        "status": "available",
        "generation": generation,
        "claimId": None,
        "leaseExpiresAt": None,
        "watchdogRunId": None,
        "watchdogRunAttempt": None,
        "decisionReceiptSha256": None,
        "decisionEvidenceETag": None,
        "attemptReceiptSha256": None,
        "workflowRunId": None,
        "authorizationReceiptSha256": None,
    }


def _validate_guard(value: object) -> Mapping[str, Any]:
    guard = _exact_object(value, GUARD_FIELDS, "dispatchGuard")
    status = guard.get("status")
    if status not in {"available", "claimed", "dispatching", "requested", "authorized"}:
        fail("dispatchGuard status is invalid", 503, "state-invalid")
    generation = guard.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        fail("dispatchGuard generation must be a positive integer", 503, "state-invalid")
    nullable = tuple(name for name in GUARD_FIELDS if name not in {"status", "generation"})
    if status == "available":
        if any(guard.get(name) is not None for name in nullable):
            fail("available dispatchGuard must have null claim fields", 503, "state-invalid")
        return guard
    claim_id = str(guard.get("claimId") or "")
    if not UUID_RE.fullmatch(claim_id):
        fail("dispatchGuard claimId is invalid", 503, "state-invalid")
    parse_canonical_time(guard.get("leaseExpiresAt"), "dispatchGuard leaseExpiresAt")
    _positive(guard.get("watchdogRunId"), "dispatchGuard watchdogRunId")
    _positive(guard.get("watchdogRunAttempt"), "dispatchGuard watchdogRunAttempt")
    _digest(guard.get("decisionReceiptSha256"), "dispatchGuard decisionReceiptSha256")
    _etag(guard.get("decisionEvidenceETag"), "dispatchGuard decisionEvidenceETag")
    if status == "claimed":
        if any(guard.get(name) is not None for name in (
            "attemptReceiptSha256", "workflowRunId", "authorizationReceiptSha256",
        )):
            fail("claimed dispatchGuard has forbidden attempt fields", 503, "state-invalid")
        return guard
    _digest(guard.get("attemptReceiptSha256"), "dispatchGuard attemptReceiptSha256")
    if status == "dispatching":
        if guard.get("workflowRunId") is not None:
            _positive(guard.get("workflowRunId"), "dispatchGuard workflowRunId")
        if guard.get("authorizationReceiptSha256") is not None:
            fail("dispatching guard cannot be authorized", 503, "state-invalid")
        return guard
    _positive(guard.get("workflowRunId"), "dispatchGuard workflowRunId")
    if status == "requested":
        if guard.get("authorizationReceiptSha256") is not None:
            fail("requested guard cannot already be authorized", 503, "state-invalid")
        return guard
    _digest(
        guard.get("authorizationReceiptSha256"),
        "dispatchGuard authorizationReceiptSha256",
    )
    return guard


def _validate_pending(value: object, baseline: Mapping[str, Any]) -> Mapping[str, Any]:
    pending = _exact_object(value, PENDING_FIELDS, "pendingCandidate")
    candidate_sha = _full_sha(pending.get("candidateSha"), "pendingCandidate candidateSha")
    _positive(pending.get("candidateRunId"), "pendingCandidate candidateRunId")
    _positive(pending.get("candidateRunAttempt"), "pendingCandidate candidateRunAttempt")
    completed = parse_canonical_time(pending.get("completedAt"), "pendingCandidate completedAt")
    deadline = parse_canonical_time(pending.get("deadline"), "pendingCandidate deadline")
    if (deadline - completed).total_seconds() != 1440 * 60:
        fail("pendingCandidate deadline is not exactly 1,440 minutes", 503, "state-invalid")
    if type(pending.get("acceptedReceiptPresent")) is not bool:
        fail("pendingCandidate acceptedReceiptPresent must be boolean", 503, "state-invalid")
    if pending.get("liveSha") != candidate_sha:
        fail("pendingCandidate liveSha differs from candidateSha", 503, "state-invalid")
    _validate_guard(pending.get("dispatchGuard"))
    rollback = _exact_object(pending.get("rollback"), ROLLBACK_FIELDS, "pendingCandidate rollback")
    if (
        rollback.get("sourceSha") != baseline.get("sourceSha")
        or rollback.get("sourceRunId") != baseline.get("sourceRunId")
        or rollback.get("sourceRunAttempt") != baseline.get("sourceRunAttempt")
        or rollback.get("acceptanceRunId") != baseline.get("acceptanceRunId")
        or rollback.get("acceptanceRunAttempt") != baseline.get("acceptanceRunAttempt")
        or rollback.get("baselineReceiptSha256") != baseline.get("receiptSha256")
    ):
        fail("pendingCandidate rollback differs from reviewed baseline", 503, "state-invalid")
    return pending


def validate_state(value: object, machine: Mapping[str, Any]) -> Mapping[str, Any]:
    state = _exact_object(value, STATE_FIELDS, "watchdog state")
    if state.get("schemaVersion") != 2:
        fail("watchdog state schemaVersion must equal 2", 503, "state-invalid")
    parse_canonical_time(state.get("generatedAt"), "watchdog state generatedAt")
    source = state.get("sourceRepository")
    expected_source = {
        name: machine["sourceRepository"][name]
        for name in ("repository", "repositoryId", "repositoryOwner", "repositoryOwnerId", "ref")
    }
    if source != expected_source:
        fail("watchdog state sourceRepository is not exact", 503, "state-invalid")
    baseline = _validate_baseline(state.get("rollbackBaseline"))
    if state.get("pendingCandidate") is not None:
        _validate_pending(state["pendingCandidate"], baseline)
    return state


def _watchdog_claims(
    claims: object,
    *,
    manual: bool = False,
    baseline: bool = False,
    run_id: str | None = None,
    run_attempt: str | None = None,
) -> Mapping[str, Any]:
    if not isinstance(claims, dict):
        fail("watchdog caller claims are invalid", 403, "oidc-forbidden")
    if baseline:
        workflow_ref, environment = BASELINE_WORKFLOW_REF, BASELINE_ENVIRONMENT
    elif manual:
        workflow_ref, environment = RECONCILIATION_WORKFLOW_REF, RECONCILIATION_ENVIRONMENT
    else:
        workflow_ref, environment = WATCHDOG_WORKFLOW_REF, WATCHDOG_ENVIRONMENT
    expected = {
        "repository": WATCHDOG_REPOSITORY,
        "repository_id": WATCHDOG_REPOSITORY_ID,
        "repository_owner_id": WATCHDOG_OWNER_ID,
        "workflow_ref": workflow_ref,
        "environment": environment,
    }
    for name, value in expected.items():
        if str(claims.get(name) or "") != value:
            fail(f"watchdog caller claim {name} is not exact", 403, "oidc-forbidden")
    sha = _full_sha(claims.get("sha"), "watchdog caller sha")
    if claims.get("workflow_sha") != sha:
        fail("watchdog caller workflow_sha differs from sha", 403, "oidc-forbidden")
    actual_run = _positive(claims.get("run_id"), "watchdog caller run_id")
    actual_attempt = _positive(claims.get("run_attempt"), "watchdog caller run_attempt")
    if run_id is not None and actual_run != run_id:
        fail("watchdog caller run_id differs from durable decision", 403, "oidc-forbidden")
    if run_attempt is not None and actual_attempt != run_attempt:
        fail("watchdog caller run_attempt differs from durable decision", 403, "oidc-forbidden")
    return claims


def validate_registry_manifest_from_storage(
    storage: StorageBackend,
    request: Mapping[str, Any],
    pending_candidate: Mapping[str, Any],
    claims: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Read and bind the locked accepted-release manifest and receipt exactly once."""
    del claims
    if any(
        pending_candidate.get(name) != request.get(name)
        for name in ("candidateSha", "candidateRunId", "candidateRunAttempt")
    ):
        fail("accepted-release registry request differs from pending candidate", 409, "registry-conflict")
    manifest_path = safe_blob_path(request["acceptedReleasePrefix"] + "registry-manifest.json")
    manifest = storage.get_blob(
        REGISTRY_CONTAINER,
        manifest_path,
        accepted_release_manifest.MAX_ACCEPTED_MANIFEST_BYTES,
    )
    if manifest is None:
        fail("accepted-release registry manifest is missing", 409, "registry-conflict")
    try:
        baseline = accepted_release_manifest.validate_accept_candidate_manifest(
            manifest.body,
            request,
            actual_registry_etag=manifest.etag,
            actual_registry_version_id=manifest.version_id,
        )
    except accepted_release_manifest.AcceptedReleaseManifestError as exc:
        fail(str(exc), 409, "registry-conflict")
    receipt_path = safe_blob_path(str(baseline["evidencePath"]))
    receipt = storage.get_blob(REGISTRY_CONTAINER, receipt_path, MAX_BODY)
    if receipt is None or not hmac.compare_digest(
        _sha256(receipt.body), str(baseline["receiptSha256"]),
    ):
        fail("accepted-release production receipt bytes differ from manifest", 409, "registry-conflict")
    policy = storage.policy(REGISTRY_CONTAINER)
    if (
        not isinstance(policy, dict)
        or policy.get("state") != "Locked"
        or type(policy.get("immutabilityPeriodSinceCreationInDays")) is not int
        or policy.get("immutabilityPeriodSinceCreationInDays") < 91
        or policy.get("allowProtectedAppendWrites") is not False
        or policy.get("allowProtectedAppendWritesAll") is not False
    ):
        fail("accepted-release registry is not locked for at least 91 days", 503, "registry-policy-invalid")
    return baseline


class WatchdogProvider:
    """Provider-owned state CAS, WORM transitions, dispatch, and reconciliation."""

    def __init__(
        self,
        storage: StorageBackend,
        dispatcher: Any,
        *,
        registry_validator: Callable[
            [StorageBackend, Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]],
            Mapping[str, Any],
        ] | None = None,
        contract: Mapping[str, Any] | None = None,
        clock: Callable[[], datetime] | None = None,
        uuid_factory: Callable[[], uuid.UUID] | None = None,
    ):
        self.storage = storage
        self.dispatcher = dispatcher
        self.machine = dict(contract or state_contract.load_contract())
        state_contract.validate_machine_contract(self.machine)
        self.registry_validator = registry_validator or validate_registry_manifest_from_storage
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.uuid_factory = uuid_factory or uuid.uuid4

    def _now(self) -> datetime:
        current = self.clock()
        if current.tzinfo is None or current.utcoffset() != timedelta(0):
            fail("provider clock is not UTC", 500, "provider-clock-invalid")
        return current.astimezone(timezone.utc)

    def _now_text(self) -> str:
        return self._now().isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def _require_worm_policy(self) -> None:
        policy = self.storage.policy(EVIDENCE_CONTAINER)
        if (
            not isinstance(policy, dict)
            or policy.get("state") != "Locked"
            or policy.get("immutabilityPeriodSinceCreationInDays") != 90
            or policy.get("allowProtectedAppendWrites") is not False
            or policy.get("allowProtectedAppendWritesAll") is not False
        ):
            fail("watchdog evidence container is not locked for exactly 90 days", 503, "worm-policy-invalid")
        try:
            _etag(policy.get("etag"), "watchdog evidence policy ETag")
            observed = parse_canonical_time(
                policy.get("observedAt"),
                "watchdog evidence policy observedAt",
            )
        except ProviderError:
            fail("watchdog evidence policy proof is invalid", 503, "worm-policy-invalid")
        if abs((self._now() - observed).total_seconds()) > 300:
            fail("watchdog evidence policy proof is stale", 503, "worm-policy-invalid")

    def _get_worm(self, path: str) -> WormRecord | None:
        safe_blob_path(path)
        record = self.storage.get_blob(EVIDENCE_CONTAINER, path, MAX_BODY)
        if record is None:
            return None
        document = _parse_durable_canonical(record.body, f"WORM evidence {path}")
        return WormRecord(
            document=document,
            raw=record.body,
            sha256=_sha256(record.body),
            path=path,
            etag=_etag(record.etag, f"WORM evidence {path} ETag"),
            version_id=str(record.version_id),
            created=False,
        )

    def _write_worm(self, path: str, document: Mapping[str, Any]) -> WormRecord:
        safe_blob_path(path)
        self._require_worm_policy()
        raw = canonical_json(document)
        digest = _sha256(raw)
        created = self.storage.put_create(
            EVIDENCE_CONTAINER,
            path,
            raw,
            {"paperdesk_sha256": digest, "paperdesk_schema": "2"},
        )
        record = self.storage.get_blob(EVIDENCE_CONTAINER, path, MAX_BODY)
        if record is None or record.body != raw:
            fail("WORM evidence create/readback bytes differ", 409, "worm-evidence-conflict")
        if record.metadata and record.metadata.get("paperdesk_sha256") not in {None, digest}:
            fail("WORM evidence metadata digest differs", 409, "worm-evidence-conflict")
        parsed = _parse_durable_canonical(record.body, f"WORM evidence {path}")
        return WormRecord(
            document=parsed,
            raw=record.body,
            sha256=digest,
            path=path,
            etag=_etag(record.etag, f"WORM evidence {path} ETag"),
            version_id=str(record.version_id),
            created=created,
        )

    def state_snapshot(self) -> StateSnapshot:
        record = self.storage.get_blob(STATE_CONTAINER, STATE_BLOB, MAX_BODY)
        if record is None:
            fail("watchdog state is not initialized", 503, "state-uninitialized")
        document = _parse_durable_canonical(record.body, "watchdog state")
        try:
            validate_state(document, self.machine)
        except ProviderError as exc:
            if exc.status >= 500:
                raise
            fail("watchdog state durable document is invalid", 503, "state-invalid")
        digest = _sha256(record.body)
        metadata = dict(record.metadata)
        initial_fields = {
            "paperdesk_sha256", "paperdesk_schema", "paperdesk_initial_baseline_sha256",
        }
        transitioned_fields = initial_fields | {"paperdesk_last_transition_sha256"}
        if frozenset(metadata) not in {frozenset(initial_fields), frozenset(transitioned_fields)}:
            fail("watchdog state metadata fields are invalid", 503, "state-metadata-invalid")
        if (
            metadata.get("paperdesk_sha256") != digest
            or metadata.get("paperdesk_schema") != "2"
        ):
            fail("watchdog state metadata does not bind exact bytes", 503, "state-metadata-invalid")
        try:
            _digest(
                metadata.get("paperdesk_initial_baseline_sha256"),
                "watchdog state initial baseline metadata",
            )
            if "paperdesk_last_transition_sha256" in metadata:
                _digest(
                    metadata.get("paperdesk_last_transition_sha256"),
                    "watchdog state last transition metadata",
                )
        except ProviderError:
            fail("watchdog state metadata digest is invalid", 503, "state-metadata-invalid")
        return StateSnapshot(
            document=document,
            raw=record.body,
            sha256=digest,
            etag=f'"{digest}"',
            storage_etag=_etag(record.etag, "watchdog state storage ETag"),
            metadata=metadata,
        )

    def _replace_state(
        self,
        previous: StateSnapshot,
        next_state: Mapping[str, Any],
        *,
        transition_sha256: str,
    ) -> StateSnapshot:
        validate_state(next_state, self.machine)
        raw = canonical_json(next_state)
        _digest(transition_sha256, "state transition receipt digest")
        metadata = {
            "paperdesk_sha256": _sha256(raw),
            "paperdesk_schema": "2",
            "paperdesk_initial_baseline_sha256": previous.metadata[
                "paperdesk_initial_baseline_sha256"
            ],
            "paperdesk_last_transition_sha256": transition_sha256,
        }
        write_receipt = self.storage.put_replace(
            STATE_CONTAINER,
            STATE_BLOB,
            raw,
            previous.storage_etag,
            metadata,
        )
        if write_receipt is None:
            fail("watchdog state compare-and-swap was lost", 409, "state-conflict")
        if (
            not isinstance(write_receipt, BlobWriteReceipt)
            or not evidence.ETAG.fullmatch(write_receipt.etag)
            or not evidence.SAFE_VERSION_ID.fullmatch(write_receipt.version_id)
        ):
            fail("watchdog state CAS write proof is invalid", 503, "state-readback-invalid")
        written = StateSnapshot(
            document=next_state,
            raw=raw,
            sha256=metadata["paperdesk_sha256"],
            etag=f'"{metadata["paperdesk_sha256"]}"',
            storage_etag=write_receipt.etag,
            metadata=metadata,
        )
        current = self.state_snapshot()
        if current.storage_etag == write_receipt.etag:
            if current.raw != raw or current.metadata != metadata:
                fail("watchdog state CAS readback differs", 503, "state-readback-invalid")
            return current
        if current.raw == raw and current.metadata == metadata:
            return written
        if current.sha256 == previous.sha256:
            fail("watchdog state CAS readback differs", 503, "state-readback-invalid")
        return written

    def _transition_path(self, operation: str, claims: Mapping[str, Any]) -> str:
        run_id = _positive(claims.get("run_id"), "transition OIDC run_id")
        run_attempt = _positive(claims.get("run_attempt"), "transition OIDC run_attempt")
        return f"v2/transitions/{operation}/{run_id}/{run_attempt}.json"

    def _caller_projection(self, claims: Mapping[str, Any]) -> dict[str, Any]:
        required = self.machine["oidc"]["requiredClaims"]
        projection = {name: claims.get(name) for name in required}
        if any(value is None for value in projection.values()):
            fail("transition OIDC projection is incomplete", 403, "oidc-forbidden")
        return projection

    @staticmethod
    def _response(
        operation: str,
        previous_sha: str,
        next_sha: str,
        transition: WormRecord,
        *,
        status_code: int,
    ) -> HTTPResult:
        document = {
            "schemaVersion": 2,
            "status": state_contract.EXPECTED_TRANSITIONS[operation]["responseStatus"],
            "operation": operation,
            "previousStateSha256": previous_sha,
            "stateSha256": next_sha,
            "stateETag": f'"{next_sha}"',
            "transitionReceiptSha256": transition.sha256,
            "transitionEvidencePath": transition.path,
            "transitionEvidenceETag": transition.etag,
            "transitionEvidenceVersionId": transition.version_id,
        }
        return HTTPResult(status_code=status_code, document=document)

    def _transition_replay(
        self,
        record: WormRecord,
        request: Mapping[str, Any],
        claims: Mapping[str, Any],
        current: StateSnapshot,
    ) -> HTTPResult:
        if (
            not isinstance(record.document, dict)
            or set(record.document) != set(TRANSITION_RECEIPT_FIELDS)
        ):
            fail("transition receipt durable fields are invalid", 503, "transition-receipt-invalid")
        receipt = record.document
        if (
            receipt.get("schemaVersion") != 2
            or receipt.get("receiptType") != "watchdog-state-transition"
            or receipt.get("operation") != request["operation"]
            or receipt.get("request") != request
            or receipt.get("requestSha256") != _sha256(canonical_json(request))
            or receipt.get("callerOidc") != self._caller_projection(claims)
            or receipt.get("previousStateSha256") != request["expectedStateSha256"]
            or receipt.get("previousStateETag") != f'"{request["expectedStateSha256"]}"'
        ):
            fail("transition idempotency key already has different durable bytes", 409, "idempotency-conflict")
        previous_state = receipt.get("previousState")
        next_state = receipt.get("nextState")
        try:
            validate_state(previous_state, self.machine)
            validate_state(next_state, self.machine)
            previous_raw = canonical_json(previous_state)
            next_raw = canonical_json(next_state)
        except (ProviderError, TypeError, ValueError):
            fail(
                "transition receipt nested durable state is invalid",
                503,
                "transition-receipt-invalid",
            )
        if (
            _sha256(previous_raw) != receipt.get("previousStateSha256")
            or _sha256(next_raw) != receipt.get("nextStateSha256")
        ):
            fail("transition receipt state digests are invalid", 503, "transition-receipt-invalid")
        if current.sha256 == receipt["previousStateSha256"]:
            current = self._replace_state(
                current,
                next_state,
                transition_sha256=record.sha256,
            )
            return self._response(
                str(request["operation"]),
                str(receipt["previousStateSha256"]),
                current.sha256,
                record,
                status_code=201,
            )
        if current.sha256 == receipt["nextStateSha256"]:
            if current.metadata.get("paperdesk_last_transition_sha256") != record.sha256:
                fail(
                    "current state names a different transition receipt",
                    409,
                    "state-conflict",
                )
            return self._response(
                str(request["operation"]),
                str(receipt["previousStateSha256"]),
                str(receipt["nextStateSha256"]),
                record,
                status_code=200,
            )
        fail(
            "transition receipt conflicts with a competing current state",
            409,
            "state-conflict",
        )

    def _verify_guard_evidence(self, guard: Mapping[str, Any]) -> None:
        prefix = f"v2/watchdog-runs/{guard['watchdogRunId']}/{guard['watchdogRunAttempt']}/"
        decision = self._get_worm(prefix + "decision.json")
        attempt = self._get_worm(prefix + "dispatch-attempt.json")
        if (
            decision is None
            or decision.sha256 != guard.get("decisionReceiptSha256")
            or decision.etag != guard.get("decisionEvidenceETag")
            or attempt is None
            or attempt.sha256 != guard.get("attemptReceiptSha256")
        ):
            fail("dispatch guard does not match exact decision/attempt WORM bytes", 409, "dispatch-evidence-conflict")
        attempt_doc = attempt.document
        if (
            attempt_doc.get("claimId") != guard.get("claimId")
            or attempt_doc.get("dispatchGuardGeneration") != guard.get("generation")
            or attempt_doc.get("decisionReceiptSha256") != guard.get("decisionReceiptSha256")
        ):
            fail("dispatch attempt WORM receipt differs from current guard", 409, "dispatch-evidence-conflict")
        workflow_run_id = guard.get("workflowRunId")
        if workflow_run_id is not None:
            outcome = self._get_worm(prefix + "dispatch-requested.json")
            if outcome is None or outcome.document.get("workflowRunId") != workflow_run_id:
                fail("dispatch run binding lacks exact WORM outcome", 409, "dispatch-evidence-conflict")

    def _authorization_receipt(
        self,
        request: Mapping[str, Any],
        claims: Mapping[str, Any],
        guard: Mapping[str, Any],
    ) -> WormRecord:
        document = {
            "schemaVersion": 2,
            "receiptType": "watchdog-rollback-authorization",
            "operation": "rollback-authorize",
            "recordedAt": request["kuduObservedAt"],
            "claimId": request["claimId"],
            "dispatchGuardGeneration": request["dispatchGuardGeneration"],
            "attemptReceiptSha256": request["attemptReceiptSha256"],
            "workflowRunId": request["workflowRunId"],
            "expectedCurrentLiveSha": request["expectedCurrentLiveSha"],
            "kuduObservedLiveSha": request["kuduObservedLiveSha"],
            "kuduRequestSha256": request["kuduRequestSha256"],
            "kuduResponseSha256": request["kuduResponseSha256"],
            "callerOidc": self._caller_projection(claims),
        }
        path = (
            f"v2/rollback-authorizations/{guard['workflowRunId']}/"
            f"{guard['claimId']}.json"
        )
        return self._write_worm(path, document)

    def _next_transition_state(
        self,
        current: StateSnapshot,
        request: Mapping[str, Any],
        claims: Mapping[str, Any],
        recorded_at: str,
    ) -> tuple[dict[str, Any], str | None]:
        operation = str(request["operation"])
        next_state = json.loads(json.dumps(current.document))
        pending = next_state.get("pendingCandidate")
        baseline = next_state.get("rollbackBaseline")
        operation_receipt_sha: str | None = None

        if operation == "publish-candidate":
            if pending is not None or not isinstance(baseline, dict):
                fail("publish-candidate requires one baseline and no pending candidate", 409, "lifecycle-conflict")
            if request["rollbackBaselineReceiptSha256"] != baseline["receiptSha256"]:
                fail("publish-candidate baseline receipt differs", 409, "lifecycle-conflict")
            next_state["pendingCandidate"] = {
                "candidateSha": request["candidateSha"],
                "candidateRunId": request["candidateRunId"],
                "candidateRunAttempt": request["candidateRunAttempt"],
                "completedAt": request["completedAt"],
                "deadline": request["deadline"],
                "acceptedReceiptPresent": False,
                "liveSha": request["liveSha"],
                "dispatchGuard": empty_guard(1),
                "rollback": {
                    "sourceSha": baseline["sourceSha"],
                    "sourceRunId": baseline["sourceRunId"],
                    "sourceRunAttempt": baseline["sourceRunAttempt"],
                    "acceptanceRunId": baseline["acceptanceRunId"],
                    "acceptanceRunAttempt": baseline["acceptanceRunAttempt"],
                    "baselineReceiptSha256": baseline["receiptSha256"],
                },
            }

        elif operation == "accept-candidate":
            if not isinstance(pending, dict):
                fail("accept-candidate has no pending candidate", 409, "lifecycle-conflict")
            if any(
                pending[name] != request[name]
                for name in ("candidateSha", "candidateRunId", "candidateRunAttempt")
            ):
                fail("accept-candidate differs from pending candidate", 409, "lifecycle-conflict")
            if pending["liveSha"] != request["candidateSha"]:
                fail("accept-candidate is not the current live SHA", 409, "lifecycle-conflict")
            guard = _validate_guard(pending["dispatchGuard"])
            if guard["status"] != "available" or guard["attemptReceiptSha256"] is not None:
                fail("candidate acceptance cannot clear a claim or attempt", 409, "lifecycle-conflict")
            if self._now() > parse_canonical_time(pending["deadline"], "pendingCandidate deadline"):
                fail("candidate acceptance deadline has passed", 409, "lifecycle-conflict")
            promoted = self.registry_validator(self.storage, request, pending, claims)
            _validate_baseline(promoted)
            next_state["rollbackBaseline"] = json.loads(json.dumps(promoted))
            next_state["pendingCandidate"] = None

        else:
            if not isinstance(pending, dict):
                fail(f"{operation} has no pending candidate", 409, "lifecycle-conflict")
            guard = _validate_guard(pending["dispatchGuard"])
            expected_status = {
                "rollback-workflow-observed": "dispatching",
                "rollback-authorize": "requested",
                "rollback-completed": "authorized",
            }[operation]
            if guard["status"] != expected_status:
                fail(f"{operation} requires {expected_status} guard", 409, "lifecycle-conflict")
            for guard_name, request_name in (
                ("claimId", "claimId"),
                ("generation", "dispatchGuardGeneration"),
                ("attemptReceiptSha256", "attemptReceiptSha256"),
                ("workflowRunId", "workflowRunId"),
            ):
                if guard.get(guard_name) != request.get(request_name):
                    fail(f"{operation} {request_name} differs from dispatch guard", 409, "lifecycle-conflict")
            if (
                request["expectedCurrentLiveSha"] != pending["candidateSha"]
                or request["expectedCurrentLiveSha"] != pending["liveSha"]
            ):
                fail(f"{operation} expected live SHA differs from pending candidate", 409, "lifecycle-conflict")
            self._verify_guard_evidence(guard)

            if operation in {"rollback-workflow-observed", "rollback-authorize"}:
                if (
                    request["decisionReceiptSha256"] != guard["decisionReceiptSha256"]
                    or request["decisionEvidenceETag"] != guard["decisionEvidenceETag"]
                ):
                    fail(f"{operation} decision binding differs", 409, "lifecycle-conflict")
            if operation == "rollback-workflow-observed":
                guard["status"] = "requested"
            elif operation == "rollback-authorize":
                authorization = self._authorization_receipt(request, claims, guard)
                operation_receipt_sha = authorization.sha256
                guard["status"] = "authorized"
                guard["authorizationReceiptSha256"] = authorization.sha256
            else:
                if request["authorizationReceiptSha256"] != guard["authorizationReceiptSha256"]:
                    fail("rollback-completed authorization receipt differs", 409, "lifecycle-conflict")
                if (
                    request["rolledBackLiveSha"] != baseline["sourceSha"]
                    or request["rolledBackLiveSha"] != pending["rollback"]["sourceSha"]
                ):
                    fail("rollback-completed did not restore reviewed baseline SHA", 409, "lifecycle-conflict")
                authorization_path = (
                    f"v2/rollback-authorizations/{guard['workflowRunId']}/"
                    f"{guard['claimId']}.json"
                )
                authorization = self._get_worm(authorization_path)
                if authorization is None or authorization.sha256 != request["authorizationReceiptSha256"]:
                    fail("rollback-completed authorization WORM receipt differs", 409, "lifecycle-conflict")
                next_state["pendingCandidate"] = None

        next_state["generatedAt"] = recorded_at
        validate_state(next_state, self.machine)
        return next_state, operation_receipt_sha

    def transition(
        self,
        raw: bytes,
        if_match: str | None,
        claims: Mapping[str, Any],
    ) -> HTTPResult:
        request = _parse_canonical(raw, "transition request")
        state_contract.validate_transition_request(self.machine, request, if_match=if_match)
        state_contract.validate_oidc_binding(self.machine, request, claims)
        operation = str(request["operation"])
        current = self.state_snapshot()
        path = self._transition_path(operation, claims)
        existing = self._get_worm(path)
        if existing is not None:
            return self._transition_replay(existing, request, claims, current)
        if current.sha256 != request["expectedStateSha256"] or current.etag != if_match:
            fail("transition expected state digest/ETag is stale", 412, "stale-state-etag")
        recorded_at = self._now_text()
        next_state, operation_receipt_sha = self._next_transition_state(
            current, request, claims, recorded_at,
        )
        receipt_document = {
            "schemaVersion": 2,
            "receiptType": "watchdog-state-transition",
            "operation": operation,
            "recordedAt": recorded_at,
            "request": dict(request),
            "requestSha256": _sha256(raw),
            "callerOidc": self._caller_projection(claims),
            "previousState": current.document,
            "previousStateSha256": current.sha256,
            "previousStateETag": current.etag,
            "nextState": next_state,
            "nextStateSha256": _sha256(canonical_json(next_state)),
            "operationReceiptSha256": operation_receipt_sha,
        }
        durable = self._write_worm(path, receipt_document)
        updated = self._replace_state(current, next_state, transition_sha256=durable.sha256)
        return self._response(
            operation,
            current.sha256,
            updated.sha256,
            durable,
            status_code=201,
        )

    def claim_rollback(
        self,
        raw: bytes,
        decision_evidence_etag: str | None,
        claims: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        decision = _exact_object(_parse_canonical(raw, "watchdog decision"), DECISION_FIELDS, "watchdog decision")
        if (
            decision.get("schemaVersion") != 2
            or decision.get("receiptType") != "watchdog-decision"
            or decision.get("decision") != "dispatch-rollback"
            or decision.get("sourceRepository") != SOURCE_REPOSITORY
        ):
            fail("watchdog decision identity is invalid")
        _full_sha(decision.get("candidateSha"), "watchdog decision candidateSha")
        for name in ("candidateRunId", "candidateRunAttempt", "watchdogRunId", "watchdogRunAttempt"):
            _positive(decision.get(name), f"watchdog decision {name}")
        _full_sha(decision.get("expectedCurrentLiveSha"), "watchdog decision expectedCurrentLiveSha")
        _digest(decision.get("observedStateSha256"), "watchdog decision observedStateSha256")
        parse_canonical_time(decision.get("decidedAt"), "watchdog decision decidedAt")
        _watchdog_claims(
            claims,
            run_id=str(decision["watchdogRunId"]),
            run_attempt=str(decision["watchdogRunAttempt"]),
        )
        snapshot = self.state_snapshot()
        pending = snapshot.document.get("pendingCandidate")
        if not isinstance(pending, dict):
            fail("watchdog decision has no pending candidate", 409, "lifecycle-conflict")
        if (
            decision["candidateSha"] != pending["candidateSha"]
            or decision["candidateRunId"] != pending["candidateRunId"]
            or decision["candidateRunAttempt"] != pending["candidateRunAttempt"]
            or decision["expectedCurrentLiveSha"] != pending["liveSha"]
        ):
            fail("watchdog decision differs from current state", 409, "lifecycle-conflict")
        path = (
            f"v2/watchdog-runs/{decision['watchdogRunId']}/"
            f"{decision['watchdogRunAttempt']}/decision.json"
        )
        guard = _validate_guard(pending["dispatchGuard"])
        if guard["status"] == "claimed":
            durable = self._get_worm(path)
            if (
                durable is not None
                and durable.raw == raw
                and pending["acceptedReceiptPresent"] is False
                and snapshot.metadata.get("paperdesk_last_transition_sha256") == durable.sha256
                and guard["decisionReceiptSha256"] == durable.sha256
                and guard["decisionEvidenceETag"] == durable.etag
                and guard["watchdogRunId"] == decision["watchdogRunId"]
                and guard["watchdogRunAttempt"] == decision["watchdogRunAttempt"]
                and (
                    decision_evidence_etag is None
                    or decision_evidence_etag == durable.etag
                )
            ):
                return {
                    "status": "claimed",
                    "claimId": guard["claimId"],
                    "dispatchGuardGeneration": guard["generation"],
                    "decisionReceiptSha256": durable.sha256,
                    "decisionEvidenceETag": durable.etag,
                }
            fail("a different rollback claim already exists", 409, "claim-conflict")
        if guard["status"] != "available":
            fail("rollback claim is not available", 409, "claim-conflict")
        if decision["observedStateSha256"] != snapshot.sha256:
            fail("watchdog decision differs from current state", 409, "lifecycle-conflict")
        if self._now() <= parse_canonical_time(pending["deadline"], "pendingCandidate deadline"):
            fail("watchdog decision deadline has not passed", 409, "lifecycle-conflict")
        if pending["acceptedReceiptPresent"]:
            fail("accepted candidate cannot be claimed for rollback", 409, "lifecycle-conflict")
        durable = self._write_worm(path, decision)
        if decision_evidence_etag is not None and decision_evidence_etag != durable.etag:
            fail("watchdog decision evidence ETag differs from durable blob", 409, "decision-evidence-conflict")
        updated = json.loads(json.dumps(snapshot.document))
        lease = (self._now() + timedelta(seconds=CLAIM_SECONDS)).isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z")
        claim_id = str(self.uuid_factory())
        if not UUID_RE.fullmatch(claim_id):
            fail("provider UUID source returned an invalid claim ID", 500, "provider-contract-invalid")
        updated_guard = {
            "status": "claimed",
            "generation": guard["generation"],
            "claimId": claim_id,
            "leaseExpiresAt": lease,
            "watchdogRunId": decision["watchdogRunId"],
            "watchdogRunAttempt": decision["watchdogRunAttempt"],
            "decisionReceiptSha256": durable.sha256,
            "decisionEvidenceETag": durable.etag,
            "attemptReceiptSha256": None,
            "workflowRunId": None,
            "authorizationReceiptSha256": None,
        }
        updated["pendingCandidate"]["dispatchGuard"] = updated_guard
        updated["generatedAt"] = self._now_text()
        self._replace_state(snapshot, updated, transition_sha256=durable.sha256)
        return {
            "status": "claimed",
            "claimId": claim_id,
            "dispatchGuardGeneration": guard["generation"],
            "decisionReceiptSha256": durable.sha256,
            "decisionEvidenceETag": durable.etag,
        }

    @staticmethod
    def _dispatcher_configured(dispatcher: Any) -> bool:
        value = getattr(dispatcher, "configured", False)
        return bool(value() if callable(value) else value)

    def _dispatch_paths(self, guard: Mapping[str, Any]) -> tuple[str, str, str]:
        prefix = f"v2/watchdog-runs/{guard['watchdogRunId']}/{guard['watchdogRunAttempt']}/"
        return prefix + "decision.json", prefix + "dispatch-attempt.json", prefix + "dispatch-requested.json"

    def _outcome_projection(self, outcome: WormRecord) -> Mapping[str, Any]:
        document = outcome.document
        expected = {
            "schemaVersion", "receiptType", "status", "recordedAt", "claimId",
            "dispatchGuardGeneration", "attemptReceiptSha256", "workflowRunId",
            "workflowRunApiUrl", "workflowRunHtmlUrl", "githubRequestId",
        }
        if not isinstance(document, dict) or set(document) != expected:
            fail("dispatch outcome WORM fields are invalid", 503, "dispatch-evidence-invalid")
        if document.get("schemaVersion") != 2 or document.get("receiptType") != "watchdog-rollback-dispatch":
            fail("dispatch outcome WORM identity is invalid", 503, "dispatch-evidence-invalid")
        try:
            parse_canonical_time(document.get("recordedAt"), "dispatch outcome recordedAt")
            claim_id = str(document.get("claimId") or "")
            if not UUID_RE.fullmatch(claim_id):
                fail("dispatch outcome claimId is invalid")
            generation = document.get("dispatchGuardGeneration")
            if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
                fail("dispatch outcome generation is invalid")
            attempt_sha = _digest(
                document.get("attemptReceiptSha256"),
                "dispatch outcome attempt receipt digest",
            )
            run_id = _positive(document.get("workflowRunId"), "dispatch outcome workflow run ID")
            if (
                document.get("status") != "requested"
                or document.get("workflowRunApiUrl")
                != f"https://api.github.com/repos/{SOURCE_REPOSITORY}/actions/runs/{run_id}"
                or document.get("workflowRunHtmlUrl")
                != f"https://github.com/{SOURCE_REPOSITORY}/actions/runs/{run_id}"
                or not isinstance(document.get("githubRequestId"), str)
                or not evidence.REQUEST_ID.fullmatch(document["githubRequestId"])
            ):
                fail("dispatch outcome run binding is invalid")
        except ProviderError as exc:
            if exc.status >= 500:
                raise
            fail("dispatch outcome durable semantics are invalid", 503, "dispatch-evidence-invalid")
        return {
            "status": document["status"],
            "claimId": claim_id,
            "dispatchGuardGeneration": generation,
            "attemptReceiptSha256": attempt_sha,
            "workflowRunId": run_id,
            "workflowRunApiUrl": document["workflowRunApiUrl"],
            "workflowRunHtmlUrl": document["workflowRunHtmlUrl"],
            "githubRequestId": document["githubRequestId"],
            "dispatchReceiptSha256": outcome.sha256,
            "dispatchEvidenceETag": outcome.etag,
            "dispatchEvidenceVersionId": outcome.version_id,
        }

    def dispatch_rollback(
        self,
        claim_id: str,
        claims: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        if not UUID_RE.fullmatch(str(claim_id or "")):
            fail("rollback dispatch claim ID is invalid")
        snapshot = self.state_snapshot()
        pending = snapshot.document.get("pendingCandidate")
        if not isinstance(pending, dict):
            fail("rollback dispatch has no pending candidate", 409, "claim-conflict")
        guard = _validate_guard(pending["dispatchGuard"])
        if guard.get("claimId") != claim_id:
            fail("rollback dispatch claim is not current", 409, "claim-conflict")
        _watchdog_claims(
            claims,
            run_id=str(guard["watchdogRunId"]),
            run_attempt=str(guard["watchdogRunAttempt"]),
        )
        _, attempt_path, outcome_path = self._dispatch_paths(guard)
        existing_outcome = self._get_worm(outcome_path)
        if existing_outcome is not None:
            projection = self._outcome_projection(existing_outcome)
            if (
                projection["claimId"] != claim_id
                or projection["dispatchGuardGeneration"] != guard["generation"]
                or projection["attemptReceiptSha256"] != guard["attemptReceiptSha256"]
            ):
                fail("dispatch outcome differs from current guard", 409, "dispatch-evidence-conflict")
            if guard["status"] == "dispatching" and guard["workflowRunId"] is None:
                repaired = json.loads(json.dumps(snapshot.document))
                repaired["pendingCandidate"]["dispatchGuard"]["workflowRunId"] = projection[
                    "workflowRunId"
                ]
                repaired["generatedAt"] = self._now_text()
                try:
                    snapshot = self._replace_state(
                        snapshot,
                        repaired,
                        transition_sha256=existing_outcome.sha256,
                    )
                except ProviderError as exc:
                    if exc.status == 409:
                        fail(
                            "durable dispatch outcome could not repair state run binding",
                            409,
                            "dispatch-reconciliation-required",
                        )
                    raise
                guard = _validate_guard(
                    snapshot.document["pendingCandidate"]["dispatchGuard"]
                )
            if (
                guard["status"] not in {"dispatching", "requested", "authorized"}
                or guard["workflowRunId"] != projection["workflowRunId"]
            ):
                fail(
                    "durable dispatch outcome is not bound in current state",
                    409,
                    "dispatch-reconciliation-required",
                )
            return projection
        existing_attempt = self._get_worm(attempt_path)
        if existing_attempt is not None or guard["status"] == "dispatching":
            fail(
                "durable dispatch attempt has no outcome; reviewed reconciliation is required",
                409,
                "dispatch-reconciliation-required",
            )
        if guard["status"] != "claimed":
            fail("rollback dispatch requires a claimed guard", 409, "claim-conflict")
        if self._now() > parse_canonical_time(guard["leaseExpiresAt"], "dispatch claim leaseExpiresAt"):
            fail("rollback dispatch claim lease expired before attempt", 409, "claim-expired")
        if not self._dispatcher_configured(self.dispatcher):
            fail("provider-side GitHub App dispatch is not configured", 503, "github-app-activation-required")
        attempt_document = {
            "schemaVersion": 2,
            "receiptType": "watchdog-rollback-dispatch-attempt",
            "recordedAt": self._now_text(),
            "claimId": claim_id,
            "dispatchGuardGeneration": guard["generation"],
            "watchdogRunId": guard["watchdogRunId"],
            "watchdogRunAttempt": guard["watchdogRunAttempt"],
            "decisionReceiptSha256": guard["decisionReceiptSha256"],
            "decisionEvidenceETag": guard["decisionEvidenceETag"],
            "expectedCurrentLiveSha": pending["liveSha"],
            "candidateSha": pending["candidateSha"],
            "candidateRunId": pending["candidateRunId"],
            "candidateRunAttempt": pending["candidateRunAttempt"],
            "rollback": pending["rollback"],
        }
        attempt = self._write_worm(attempt_path, attempt_document)
        armed = json.loads(json.dumps(snapshot.document))
        armed_guard = armed["pendingCandidate"]["dispatchGuard"]
        armed_guard["status"] = "dispatching"
        armed_guard["attemptReceiptSha256"] = attempt.sha256
        armed["generatedAt"] = self._now_text()
        armed_snapshot = self._replace_state(snapshot, armed, transition_sha256=attempt.sha256)
        try:
            result = self.dispatcher.dispatch(attempt_document)
        except ProviderError:
            raise
        except Exception:
            fail("GitHub workflow dispatch outcome is indeterminate", 503, "github-dispatch-indeterminate")
        if not isinstance(result, GithubDispatchResult):
            fail("GitHub dispatcher returned an invalid result", 503, "github-dispatch-indeterminate")
        run_id = _positive(result.workflow_run_id, "GitHub workflow run ID")
        if (
            result.workflow_run_api_url
            != f"https://api.github.com/repos/{SOURCE_REPOSITORY}/actions/runs/{run_id}"
            or result.workflow_run_html_url
            != f"https://github.com/{SOURCE_REPOSITORY}/actions/runs/{run_id}"
            or not evidence.REQUEST_ID.fullmatch(result.github_request_id)
        ):
            fail("GitHub HTTP 200 run details are not exact", 503, "github-dispatch-indeterminate")
        outcome_document = {
            "schemaVersion": 2,
            "receiptType": "watchdog-rollback-dispatch",
            "status": "requested",
            "recordedAt": self._now_text(),
            "claimId": claim_id,
            "dispatchGuardGeneration": guard["generation"],
            "attemptReceiptSha256": attempt.sha256,
            "workflowRunId": run_id,
            "workflowRunApiUrl": result.workflow_run_api_url,
            "workflowRunHtmlUrl": result.workflow_run_html_url,
            "githubRequestId": result.github_request_id,
        }
        outcome = self._write_worm(outcome_path, outcome_document)
        latest = self.state_snapshot()
        latest_guard = latest.document.get("pendingCandidate", {}).get("dispatchGuard", {})
        if (
            latest.sha256 != armed_snapshot.sha256
            or latest_guard.get("status") != "dispatching"
            or latest_guard.get("claimId") != claim_id
            or latest_guard.get("attemptReceiptSha256") != attempt.sha256
        ):
            fail("dispatch outcome is durable but state run binding lost CAS", 409, "dispatch-reconciliation-required")
        settled = json.loads(json.dumps(latest.document))
        settled["pendingCandidate"]["dispatchGuard"]["workflowRunId"] = run_id
        settled["generatedAt"] = self._now_text()
        try:
            settled_snapshot = self._replace_state(
                latest,
                settled,
                transition_sha256=outcome.sha256,
            )
        except ProviderError as exc:
            if exc.status == 409:
                fail(
                    "dispatch outcome is durable but state run binding lost CAS",
                    409,
                    "dispatch-reconciliation-required",
                )
            raise
        settled_guard = settled_snapshot.document["pendingCandidate"]["dispatchGuard"]
        if settled_guard.get("workflowRunId") != run_id:
            fail("dispatch run binding readback is invalid", 503, "state-readback-invalid")
        return self._outcome_projection(outcome)

    @staticmethod
    def _internal_caller_projection(claims: Mapping[str, Any]) -> Mapping[str, Any]:
        fields = (
            "repository", "repository_id", "repository_owner_id", "workflow_ref",
            "workflow_sha", "sha", "run_id", "run_attempt", "environment",
        )
        projection = {name: claims.get(name) for name in fields}
        if any(not isinstance(value, str) or not value for value in projection.values()):
            fail("reconciliation OIDC projection is incomplete", 403, "oidc-forbidden")
        return projection

    def _validate_reconciliation_receipt(
        self,
        record: WormRecord,
        *,
        claim_id: str,
        claims: Mapping[str, Any],
        manual: bool,
    ) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
        receipt = record.document
        if not isinstance(receipt, dict) or set(receipt) != set(RECONCILIATION_RECEIPT_FIELDS):
            fail("reconciliation WORM fields are invalid", 503, "reconciliation-evidence-invalid")
        resolution = "known-run-binding-repaired" if manual else "released-unattempted-expired-claim"
        current_caller = self._internal_caller_projection(claims)
        stored_caller = receipt.get("callerOidc")
        if (
            receipt.get("schemaVersion") != 2
            or receipt.get("receiptType") != "watchdog-dispatch-reconciliation"
            or receipt.get("resolution") != resolution
            or receipt.get("claimId") != claim_id
            or not isinstance(stored_caller, dict)
            or set(stored_caller) != set(current_caller)
            or stored_caller != current_caller
        ):
            fail("reconciliation WORM identity differs", 409, "reconciliation-conflict")
        try:
            parse_canonical_time(receipt.get("recordedAt"), "reconciliation recordedAt")
            generation = receipt.get("dispatchGuardGeneration")
            if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
                fail("reconciliation generation is invalid")
            previous = receipt.get("previousState")
            next_state = receipt.get("nextState")
            validate_state(previous, self.machine)
            validate_state(next_state, self.machine)
            if (
                _sha256(canonical_json(previous)) != receipt.get("previousStateSha256")
                or _sha256(canonical_json(next_state)) != receipt.get("nextStateSha256")
            ):
                fail("reconciliation state digests differ")
            previous_last = receipt.get("previousStateLastTransitionSha256")
            if previous_last is not None:
                _digest(previous_last, "reconciliation previous transition digest")
        except ProviderError as exc:
            if exc.status >= 500:
                raise
            fail("reconciliation durable state is invalid", 503, "reconciliation-evidence-invalid")
        previous_pending = previous.get("pendingCandidate")
        next_pending = next_state.get("pendingCandidate")
        if not isinstance(previous_pending, dict) or not isinstance(next_pending, dict):
            fail("reconciliation durable pending state is invalid", 503, "reconciliation-evidence-invalid")
        previous_guard = _validate_guard(previous_pending["dispatchGuard"])
        next_guard = _validate_guard(next_pending["dispatchGuard"])
        if (
            previous_guard.get("claimId") != claim_id
            or previous_guard.get("generation") != generation
        ):
            fail("reconciliation prior guard differs", 409, "reconciliation-conflict")
        expected_next = json.loads(json.dumps(previous))
        expected_next["generatedAt"] = next_state["generatedAt"]
        if manual:
            workflow_run_id = _positive(receipt.get("workflowRunId"), "reconciliation workflow run ID")
            dispatch_receipt_sha = _digest(
                receipt.get("dispatchReceiptSha256"),
                "reconciliation dispatch receipt digest",
            )
            if (
                receipt.get("attemptReceiptPresent") is not True
                or previous_guard.get("status") != "dispatching"
                or previous_guard.get("workflowRunId") is not None
                or previous_guard.get("attemptReceiptSha256") is None
            ):
                fail("manual reconciliation prior guard is invalid", 409, "reconciliation-conflict")
            expected_next["pendingCandidate"]["dispatchGuard"]["workflowRunId"] = workflow_run_id
            if next_guard.get("workflowRunId") != workflow_run_id:
                fail("manual reconciliation next run binding differs", 503, "reconciliation-evidence-invalid")
            details = {
                "workflowRunId": workflow_run_id,
                "dispatchReceiptSha256": dispatch_receipt_sha,
            }
        else:
            if (
                receipt.get("attemptReceiptPresent") is not False
                or receipt.get("workflowRunId") is not None
                or receipt.get("dispatchReceiptSha256") is not None
                or previous_guard.get("status") != "claimed"
                or previous_guard.get("attemptReceiptSha256") is not None
            ):
                fail("automatic reconciliation prior guard is invalid", 409, "reconciliation-conflict")
            expected_next["pendingCandidate"]["dispatchGuard"] = empty_guard(generation + 1)
            if next_guard != empty_guard(generation + 1):
                fail("automatic reconciliation next guard differs", 503, "reconciliation-evidence-invalid")
            details = {}
        if expected_next != next_state:
            fail("reconciliation durable next state is invalid", 503, "reconciliation-evidence-invalid")
        return receipt, previous, details

    def _commit_or_recover_reconciliation(
        self,
        *,
        path: str,
        snapshot: StateSnapshot,
        next_state: Mapping[str, Any] | None,
        receipt_fields: Mapping[str, Any] | None,
        claim_id: str,
        claims: Mapping[str, Any],
        manual: bool,
    ) -> tuple[WormRecord, StateSnapshot, Mapping[str, Any]]:
        record = self._get_worm(path)
        if record is None:
            if next_state is None or receipt_fields is None:
                fail("reconciliation receipt is missing", 409, "reconciliation-conflict")
            record = self._write_worm(path, {
                **receipt_fields,
                "callerOidc": self._internal_caller_projection(claims),
                "previousState": snapshot.document,
                "previousStateSha256": snapshot.sha256,
                "previousStateLastTransitionSha256": snapshot.metadata.get(
                    "paperdesk_last_transition_sha256"
                ),
                "nextState": next_state,
                "nextStateSha256": _sha256(canonical_json(next_state)),
            })
        receipt, previous, details = self._validate_reconciliation_receipt(
            record,
            claim_id=claim_id,
            claims=claims,
            manual=manual,
        )
        if snapshot.sha256 == receipt["nextStateSha256"]:
            if snapshot.metadata.get("paperdesk_last_transition_sha256") != record.sha256:
                fail("reconciliation state names another receipt", 409, "reconciliation-conflict")
            return record, snapshot, details
        if (
            snapshot.sha256 != receipt["previousStateSha256"]
            or snapshot.document != previous
            or snapshot.metadata.get("paperdesk_last_transition_sha256")
            != receipt["previousStateLastTransitionSha256"]
        ):
            fail("reconciliation receipt conflicts with current state", 409, "reconciliation-conflict")
        recovered = self._replace_state(
            snapshot,
            receipt["nextState"],
            transition_sha256=record.sha256,
        )
        return record, recovered, details

    def reconcile(
        self,
        claim_id: str,
        claims: Mapping[str, Any],
        *,
        manual: bool,
    ) -> Mapping[str, Any]:
        verified_claims = _watchdog_claims(claims, manual=manual)
        snapshot = self.state_snapshot()
        pending = snapshot.document.get("pendingCandidate")
        if not isinstance(pending, dict):
            fail("reconciliation has no pending candidate", 409, "reconciliation-conflict")
        guard = _validate_guard(pending["dispatchGuard"])
        if not manual:
            path = f"v2/reconciliations/automatic/{claim_id}.json"
            existing = self._get_worm(path)
            if existing is None:
                if guard.get("claimId") != claim_id:
                    fail("reconciliation claim is not current", 409, "reconciliation-conflict")
                _, attempt_path, _ = self._dispatch_paths(guard)
                if guard["status"] != "claimed":
                    fail("automatic reconciliation cannot release attempted state", 409, "reconciliation-forbidden")
                if self._get_worm(attempt_path) is not None:
                    fail("automatic reconciliation cannot release a durable attempt", 409, "reconciliation-forbidden")
                if self._now() <= parse_canonical_time(
                    guard["leaseExpiresAt"], "dispatch claim leaseExpiresAt"
                ):
                    fail("automatic reconciliation claim lease has not expired", 409, "reconciliation-conflict")
                updated = json.loads(json.dumps(snapshot.document))
                updated["pendingCandidate"]["dispatchGuard"] = empty_guard(guard["generation"] + 1)
                updated["generatedAt"] = self._now_text()
                receipt_fields = {
                    "schemaVersion": 2,
                    "receiptType": "watchdog-dispatch-reconciliation",
                    "resolution": "released-unattempted-expired-claim",
                    "recordedAt": self._now_text(),
                    "claimId": claim_id,
                    "dispatchGuardGeneration": guard["generation"],
                    "attemptReceiptPresent": False,
                    "workflowRunId": None,
                    "dispatchReceiptSha256": None,
                }
            else:
                updated = None
                receipt_fields = None
            record, settled, _ = self._commit_or_recover_reconciliation(
                path=path,
                snapshot=snapshot,
                next_state=updated,
                receipt_fields=receipt_fields,
                claim_id=claim_id,
                claims=verified_claims,
                manual=False,
            )
            receipt = record.document
            expected_generation = receipt["dispatchGuardGeneration"] + 1
            if settled.document["pendingCandidate"]["dispatchGuard"] != empty_guard(
                expected_generation
            ):
                fail("automatic reconciliation readback is invalid", 503, "state-readback-invalid")
            return {
                "status": "released-unattempted-expired-claim",
                "claimId": claim_id,
                "dispatchGuardGeneration": expected_generation,
                "reconciliationReceiptSha256": record.sha256,
            }

        if guard.get("claimId") != claim_id:
            fail("reconciliation claim is not current", 409, "reconciliation-conflict")
        _, attempt_path, outcome_path = self._dispatch_paths(guard)
        attempt = self._get_worm(attempt_path)
        outcome = self._get_worm(outcome_path)
        if attempt is None:
            fail("manual reconciliation found no attempt; automatic expiry rule applies", 409, "reconciliation-conflict")
        if outcome is None:
            fail("indeterminate attempted dispatch must remain held", 409, "reconciliation-required")
        projection = self._outcome_projection(outcome)
        if (
            projection["claimId"] != claim_id
            or projection["dispatchGuardGeneration"] != guard["generation"]
            or projection["attemptReceiptSha256"] != attempt.sha256
            or guard["attemptReceiptSha256"] != attempt.sha256
        ):
            fail("manual reconciliation outcome differs from attempt", 409, "reconciliation-conflict")
        path = f"v2/reconciliations/manual/{claim_id}.json"
        existing = self._get_worm(path)
        if existing is None and guard["workflowRunId"] is not None:
            if guard["workflowRunId"] != projection["workflowRunId"]:
                fail("manual reconciliation current run differs", 409, "reconciliation-conflict")
            return {
                "status": "known-run-held-for-workflow-observation",
                "claimId": claim_id,
                "dispatchGuardGeneration": guard["generation"],
                "workflowRunId": projection["workflowRunId"],
            }
        if existing is None:
            updated = json.loads(json.dumps(snapshot.document))
            updated["pendingCandidate"]["dispatchGuard"]["workflowRunId"] = projection[
                "workflowRunId"
            ]
            updated["generatedAt"] = self._now_text()
            receipt_fields = {
                "schemaVersion": 2,
                "receiptType": "watchdog-dispatch-reconciliation",
                "resolution": "known-run-binding-repaired",
                "recordedAt": self._now_text(),
                "claimId": claim_id,
                "dispatchGuardGeneration": guard["generation"],
                "attemptReceiptPresent": True,
                "workflowRunId": projection["workflowRunId"],
                "dispatchReceiptSha256": projection["dispatchReceiptSha256"],
            }
        else:
            updated = None
            receipt_fields = None
        _, settled, details = self._commit_or_recover_reconciliation(
            path=path,
            snapshot=snapshot,
            next_state=updated,
            receipt_fields=receipt_fields,
            claim_id=claim_id,
            claims=verified_claims,
            manual=True,
        )
        settled_guard = settled.document["pendingCandidate"]["dispatchGuard"]
        if settled_guard.get("workflowRunId") != details["workflowRunId"]:
            fail("manual reconciliation readback is invalid", 503, "state-readback-invalid")
        return {
            "status": "known-run-held-for-workflow-observation",
            "claimId": claim_id,
            "dispatchGuardGeneration": guard["generation"],
            "workflowRunId": details["workflowRunId"],
        }

    def initialize_baseline(
        self,
        rollback_baseline: Mapping[str, Any],
        claims: Mapping[str, Any],
    ) -> StateSnapshot:
        verified_claims = _watchdog_claims(claims, baseline=True)
        baseline = _validate_baseline(rollback_baseline)
        if (
            baseline["reviewWorkflowRef"] != verified_claims["workflow_ref"]
            or baseline["reviewWorkflowSha"] != verified_claims["sha"]
            or baseline["reviewRunId"] != verified_claims["run_id"]
            or baseline["reviewRunAttempt"] != verified_claims["run_attempt"]
            or baseline["reviewEnvironment"] != verified_claims["environment"]
        ):
            fail(
                "initial baseline review coordinates differ from authenticated OIDC caller",
                403,
                "oidc-forbidden",
            )
        if self.storage.get_blob(STATE_CONTAINER, STATE_BLOB, MAX_BODY) is not None:
            fail("watchdog state baseline is already initialized", 409, "baseline-conflict")
        evidence_record = self._get_worm(str(rollback_baseline["evidencePath"]))
        if evidence_record is None or evidence_record.sha256 != rollback_baseline["receiptSha256"]:
            fail("initial baseline does not match reviewed WORM evidence", 409, "baseline-evidence-conflict")
        _validate_initial_baseline_receipt(evidence_record, baseline)
        source = {
            name: self.machine["sourceRepository"][name]
            for name in ("repository", "repositoryId", "repositoryOwner", "repositoryOwnerId", "ref")
        }
        document = {
            "schemaVersion": 2,
            "generatedAt": self._now_text(),
            "sourceRepository": source,
            "rollbackBaseline": dict(rollback_baseline),
            "pendingCandidate": None,
        }
        validate_state(document, self.machine)
        raw = canonical_json(document)
        metadata = {
            "paperdesk_sha256": _sha256(raw),
            "paperdesk_schema": "2",
            "paperdesk_initial_baseline_sha256": rollback_baseline["receiptSha256"],
        }
        if not self.storage.put_create(
            STATE_CONTAINER,
            STATE_BLOB,
            raw,
            metadata,
        ):
            fail("watchdog state baseline create lost exclusivity", 409, "baseline-conflict")
        return self.state_snapshot()


__all__ = [
    "APP_NAME", "AzureIdentityBinding", "AzureStorageBackend", "BlobRecord",
    "EVIDENCE_CONTAINER", "GithubAppDispatcher", "GithubDispatchResult", "HTTPResult",
    "ManagedIdentityTokens", "OIDCVerifier", "ProviderError", "REGISTRY_CONTAINER",
    "STATE_BLOB", "STATE_CONTAINER", "STORAGE_ACCOUNT", "StorageBackend",
    "StateSnapshot", "WatchdogProvider", "canonical_json", "empty_guard",
    "github_app_jwt", "validate_registry_manifest_from_storage", "validate_state",
]
