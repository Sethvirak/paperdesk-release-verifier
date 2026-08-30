"""Dormant, dependency-free PaperDesk Azure production release control.

This module deliberately owns no credential discovery, command-line interface,
environment-variable contract, or cloud-resource selector.  A future reviewed
workflow may inject authenticated HTTP transports after its existing hard stops.
Secrets such as the short-lived package URI remain in memory and are excluded
from request representations and returned receipts.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import subprocess
import time
import urllib.parse
import uuid
from collections.abc import Callable, Mapping
from typing import Any

from provider import accepted_release_manifest
from scripts import accepted_release_registry


SUBSCRIPTION_ID = "9c4e0d0d-602f-4cde-84bd-337250e5b64c"
RESOURCE_GROUP = "rg-master-data-structure-sea"
APP_NAME = "master-data-structure-sea-9c4e0d0d"
APP_RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}"
    f"/providers/Microsoft.Web/sites/{APP_NAME}"
)
WEB_API_VERSION = "2025-05-01"
ONEDEPLOY_URL = (
    f"https://management.azure.com{APP_RESOURCE_ID}/extensions/onedeploy"
    f"?api-version={WEB_API_VERSION}"
)
LIVE_ORIGIN = "https://master-data-structure-sea-9c4e0d0d.azurewebsites.net"
REGISTRY_ACCOUNT = accepted_release_registry.ACCOUNT
REGISTRY_CONTAINER = accepted_release_registry.CONTAINER
REGISTRY_ORIGIN = f"https://{REGISTRY_ACCOUNT}.blob.core.windows.net"

MAX_ARM_RESPONSE_BYTES = 1024 * 1024
MAX_LIVE_JSON_BYTES = 256 * 1024
MAX_RELEASE_SHA_BYTES = 128
MAX_PACKAGE_URI_LENGTH = 4096
MAX_DEPLOYMENT_ENTRIES = 16
MAX_DEPLOYMENT_POLLS = 180
DEPLOYMENT_POLL_SECONDS = 10
DEPLOYMENT_SETTLE_SECONDS = 120

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
POSITIVE = re.compile(r"^[1-9][0-9]*$")
DEPLOYMENT_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
PREFIX = re.compile(
    r"^v1/releases/(?P<sha>[0-9a-f]{40})/(?P<source>[1-9][0-9]*)/"
    r"(?P<acceptance>[1-9][0-9]*)/$"
)
GITHUB_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
SOURCE_REPOSITORY = "Sethvirak/MasterDataStructure"
SOURCE_BRANCH = "main"


class ReleaseControlError(ValueError):
    """The release-control input or observed response failed closed."""


def fail(message: str) -> None:
    raise ReleaseControlError(message)


def canonical_json(document: Any) -> bytes:
    """Return stable, UTF-8, newline-terminated canonical JSON bytes."""

    try:
        return (
            json.dumps(
                document,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        fail("document cannot be represented as canonical JSON")
        raise AssertionError from exc


@dataclasses.dataclass(frozen=True)
class HttpRequest:
    """One bounded request; authentication is added only by the injected transport."""

    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes | None = dataclasses.field(default=None, repr=False)
    maximum_response_bytes: int = MAX_ARM_RESPONSE_BYTES
    timeout_seconds: int = 30
    sensitive: bool = False


@dataclasses.dataclass(frozen=True)
class HttpResponse:
    status: int
    url: str
    headers: Mapping[str, str]
    body: bytes = dataclasses.field(repr=False)


HttpTransport = Callable[[HttpRequest], HttpResponse]


@dataclasses.dataclass(frozen=True)
class DeploymentPackage:
    source_sha: str
    package_uri: str = dataclasses.field(repr=False)
    package_sha256: str
    package_size: int


@dataclasses.dataclass(frozen=True)
class LocalDeploymentPackage:
    source_sha: str
    path: str
    package_sha256: str
    package_size: int


@dataclasses.dataclass(frozen=True)
class RegistryArchive:
    source_sha: str
    source_run_id: str
    acceptance_run_id: str
    accepted_release_prefix: str
    accepted_release_manifest_sha256: str
    blob_name: str
    archive_sha256: str
    archive_size: int
    body: bytes = dataclasses.field(repr=False)


def _sha40(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA40.fullmatch(value):
        fail(f"{label} is invalid")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        fail(f"{label} is invalid")
    return value


def _positive(value: Any, label: str) -> str:
    if not isinstance(value, str) or not POSITIVE.fullmatch(value):
        fail(f"{label} is invalid")
    return value


def validate_merged_main_artifact_provenance(
    *,
    run: Mapping[str, Any],
    artifacts: Mapping[str, Any],
    source_sha: str,
    source_run_id: str,
    artifact_name: str,
    artifact_id: str,
    artifact_digest: str,
) -> dict[str, Any]:
    """Resolve caller coordinates to one successful merged-main artifact.

    The caller may provide coordinates but cannot authorize them: this function
    binds them to fresh GitHub run and artifact API projections before bytes are
    admitted to deployment processing.
    """

    source_sha = _sha40(source_sha, "source SHA")
    source_run_id = _positive(source_run_id, "source run ID")
    artifact_id = _positive(artifact_id, "artifact ID")
    artifact_digest = _sha256(artifact_digest, "artifact digest")
    if not isinstance(artifact_name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", artifact_name):
        fail("artifact name is invalid")
    repository = run.get("repository")
    head_repository = run.get("head_repository")
    if (
        str(run.get("id")) != source_run_id
        or run.get("head_sha") != source_sha
        or run.get("head_branch") != SOURCE_BRANCH
        or run.get("event") != "push"
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or not isinstance(repository, Mapping)
        or repository.get("full_name") != SOURCE_REPOSITORY
        or not isinstance(head_repository, Mapping)
        or head_repository.get("full_name") != SOURCE_REPOSITORY
    ):
        fail("source run is not exact successful merged-main provenance")
    values = artifacts.get("artifacts") if isinstance(artifacts, Mapping) else None
    if not isinstance(values, list) or len(values) > 100:
        fail("artifact inventory is invalid")
    matches = []
    for item in values:
        if not isinstance(item, Mapping):
            fail("artifact inventory entry is invalid")
        workflow_run = item.get("workflow_run")
        digest_match = GITHUB_DIGEST.fullmatch(str(item.get("digest", "")))
        if (
            str(item.get("id")) == artifact_id
            and item.get("name") == artifact_name
            and item.get("expired") is False
            and isinstance(workflow_run, Mapping)
            and str(workflow_run.get("id")) == source_run_id
            and workflow_run.get("head_sha") == source_sha
            and digest_match is not None
            and digest_match.group(1) == artifact_digest
        ):
            matches.append(item)
    if len(matches) != 1:
        fail("selected artifact is not uniquely authorized by merged-main provenance")
    size = matches[0].get("size_in_bytes")
    if type(size) is not int or not 0 < size <= 1024 * 1024 * 1024:
        fail("selected artifact size is invalid")
    return {
        "artifactDigest": artifact_digest,
        "artifactId": artifact_id,
        "artifactName": artifact_name,
        "artifactSize": size,
        "sourceRepository": SOURCE_REPOSITORY,
        "sourceRunId": source_run_id,
        "sourceSha": source_sha,
    }


def _bounded_response(response: Any, request: HttpRequest, label: str) -> HttpResponse:
    if not isinstance(response, HttpResponse):
        fail(f"{label} transport response is invalid")
    if response.url != request.url:
        fail(f"{label} redirected or returned an unexpected URL")
    if type(response.status) is not int or not 100 <= response.status <= 599:
        fail(f"{label} HTTP status is invalid")
    if not isinstance(response.body, bytes) or len(response.body) > request.maximum_response_bytes:
        fail(f"{label} response exceeds the fixed bound")
    if not isinstance(response.headers, Mapping):
        fail(f"{label} response headers are invalid")
    return response


def _request(transport: HttpTransport, request: HttpRequest, label: str) -> HttpResponse:
    if not callable(transport):
        fail("authenticated HTTP transport is unavailable")
    try:
        response = transport(request)
    except ReleaseControlError:
        raise
    except Exception:
        # Never interpolate the exception: a transport error may contain a SAS
        # package URI or authorization header.  Suppress the chained transport
        # traceback for the same reason.
        raise ReleaseControlError(f"{label} transport failed") from None
    return _bounded_response(response, request, label)


def _json_no_duplicates(raw: bytes, label: str) -> Any:
    def exact_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(f"{label} contains duplicate JSON fields")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=exact_pairs)
    except ReleaseControlError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseControlError(f"{label} is not valid UTF-8 JSON") from exc


def _validate_package_uri(value: Any) -> str:
    if not isinstance(value, str) or not 0 < len(value) <= MAX_PACKAGE_URI_LENGTH:
        fail("OneDeploy package URI is invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise ReleaseControlError("OneDeploy package URI is invalid") from exc
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or not parsed.hostname
        or not parsed.hostname.lower().endswith(".blob.core.windows.net")
        or not parsed.path.startswith("/")
        or parsed.path == "/"
        or parsed.fragment
        or not pairs
    ):
        fail("OneDeploy package URI boundary is invalid")
    query: dict[str, str] = {}
    for key, item in pairs:
        lowered = key.lower()
        if lowered in query or not lowered or not item:
            fail("OneDeploy package URI query is invalid")
        query[lowered] = item
    if query.get("spr", "").lower() != "https" or query.get("sp", "").lower() != "r":
        fail("OneDeploy package URI is not read-only HTTPS")
    if query.get("sr", "").lower() != "b" or "sig" not in query or "sip" in query:
        fail("OneDeploy package URI scope is invalid")
    return value


def _collection(response: HttpResponse, label: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if response.status != 200:
        fail(f"{label} did not return HTTP 200")
    document = _json_no_duplicates(response.body, label)
    if not isinstance(document, dict) or not set(document).issubset({"value", "nextLink"}):
        fail(f"{label} fields are not exact")
    values = document.get("value")
    if (
        not isinstance(values, list)
        or len(values) > MAX_DEPLOYMENT_ENTRIES
        or document.get("nextLink", "") != ""
    ):
        fail(f"{label} collection is invalid or paginated")
    result: dict[str, Any] = {}
    for entry in values:
        if not isinstance(entry, dict) or not {"id", "name", "type", "properties"}.issubset(entry):
            fail(f"{label} deployment shape is invalid")
        name = entry.get("name")
        expected_id = f"{APP_RESOURCE_ID}/deployments/{name}"
        if (
            not isinstance(name, str)
            or not DEPLOYMENT_ID.fullmatch(name)
            or entry.get("id") != expected_id
            or entry.get("type") != "Microsoft.Web/sites/deployments"
            or name in result
            or not isinstance(entry.get("properties"), dict)
        ):
            fail(f"{label} deployment identity is invalid")
        result[name] = entry
    return document, result


def _terminal_deployment(entry: Mapping[str, Any], response_body: bytes) -> dict[str, Any]:
    properties = entry["properties"]
    required = {"active", "complete", "deployer", "status", "received_time", "start_time", "end_time"}
    if not required.issubset(properties):
        fail("OneDeploy terminal deployment fields are incomplete")
    if (
        properties.get("active") is not True
        or properties.get("complete") is not True
        or properties.get("deployer") != "OneDeploy"
        or type(properties.get("status")) is not int
        or properties.get("status") != 4
    ):
        fail("OneDeploy terminal deployment did not succeed")
    timestamps: list[str] = []
    for key in ("received_time", "start_time", "end_time"):
        value = properties.get(key)
        if not isinstance(value, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z", value
        ):
            fail("OneDeploy terminal timestamps are invalid")
        timestamps.append(value)
    # Canonical UTC strings of this fixed form retain chronological ordering.
    # Fractional precision can differ, so normalize to padded nanoseconds.
    def timestamp_key(value: str) -> str:
        main = value[:-1]
        if "." in main:
            base, fraction = main.split(".", 1)
        else:
            base, fraction = main, ""
        return f"{base}.{fraction.ljust(9, '0')}Z"

    if [timestamp_key(value) for value in timestamps] != sorted(timestamp_key(value) for value in timestamps):
        fail("OneDeploy terminal timestamps are out of order")
    return {
        "active": True,
        "completedAt": timestamps[2],
        "complete": True,
        "deployer": "OneDeploy",
        "deploymentId": entry["name"],
        "receivedAt": timestamps[0],
        "resourceId": entry["id"],
        "resourceType": entry["type"],
        "responseObjectSha256": hashlib.sha256(canonical_json(entry)).hexdigest(),
        "startedAt": timestamps[1],
        "statusCode": 4,
    }


def _intermediate_or_terminal(entry: Mapping[str, Any], response_body: bytes) -> dict[str, Any] | None:
    properties = entry["properties"]
    status = properties.get("status")
    complete = properties.get("complete")
    if type(status) is not int or type(complete) is not bool:
        fail("OneDeploy status fields are invalid")
    if status in {0, 1, 2} and complete is False:
        return None
    return _terminal_deployment(entry, response_body)


def deploy_candidate(
    package: DeploymentPackage,
    transport: HttpTransport,
    *,
    sleep: Callable[[float], None] = time.sleep,
    request_id_factory: Callable[[], uuid.UUID] = uuid.uuid4,
) -> dict[str, Any]:
    """Execute one exact OneDeploy PUT and return a secret-free receipt.

    The injected transport owns authentication.  This function never retries
    the mutation.  Transport ambiguity therefore fails closed and requires a
    separately reviewed reconciliation before any new deployment attempt.
    """

    if not isinstance(package, DeploymentPackage):
        fail("deployment package is invalid")
    source_sha = _sha40(package.source_sha, "candidate SHA")
    package_sha256 = _sha256(package.package_sha256, "deployment package digest")
    if type(package.package_size) is not int or not 0 < package.package_size <= 1024 * 1024 * 1024:
        fail("deployment package size is invalid")
    package_uri = _validate_package_uri(package.package_uri)
    request_id = str(request_id_factory())
    if not DEPLOYMENT_ID.fullmatch(request_id):
        fail("OneDeploy client request ID is invalid")

    get_request = HttpRequest(
        method="GET",
        url=ONEDEPLOY_URL,
        headers={"Accept": "application/json"},
        maximum_response_bytes=MAX_ARM_RESPONSE_BYTES,
    )
    pre_response = _request(transport, get_request, "OneDeploy preflight")
    _, pre_entries = _collection(pre_response, "OneDeploy preflight")

    request_document = {
        "properties": {
            "clean": True,
            "ignorestack": False,
            "packageUri": package_uri,
            "restart": True,
            "type": "zip",
        }
    }
    request_body = canonical_json(request_document)
    put_request = HttpRequest(
        method="PUT",
        url=ONEDEPLOY_URL,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
            "x-ms-client-request-id": request_id,
        },
        body=request_body,
        maximum_response_bytes=MAX_ARM_RESPONSE_BYTES,
        timeout_seconds=120,
        sensitive=True,
    )
    put_response = _request(transport, put_request, "OneDeploy mutation")
    if put_response.status != 200:
        fail("OneDeploy mutation did not return HTTP 200")

    terminal: dict[str, Any] | None = None
    terminal_raw = b""
    for _ in range(MAX_DEPLOYMENT_POLLS):
        sleep(DEPLOYMENT_POLL_SECONDS)
        poll_response = _request(transport, get_request, "OneDeploy status")
        _, entries = _collection(poll_response, "OneDeploy status")
        added = sorted(set(entries) - set(pre_entries))
        if not added:
            continue
        if len(added) != 1:
            fail("OneDeploy produced multiple new deployment identities")
        terminal = _intermediate_or_terminal(entries[added[0]], poll_response.body)
        if terminal is not None:
            terminal_raw = poll_response.body
            break
    if terminal is None:
        fail("OneDeploy did not reach one bounded terminal success")

    sleep(DEPLOYMENT_SETTLE_SECONDS)
    settled_response = _request(transport, get_request, "OneDeploy settlement")
    _, settled_entries = _collection(settled_response, "OneDeploy settlement")
    added = sorted(set(settled_entries) - set(pre_entries))
    if added != [terminal["deploymentId"]]:
        fail("OneDeploy settlement changed the deployment identity set")
    settled = _terminal_deployment(settled_entries[added[0]], settled_response.body)
    if settled != terminal:
        fail("OneDeploy terminal deployment changed during settlement")

    receipt = {
        "schema": "paperdesk-azure-production-deploy-v1",
        "status": "success",
        "operation": "deploy-candidate",
        "sourceSha": source_sha,
        "target": {
            "appName": APP_NAME,
            "apiVersion": WEB_API_VERSION,
            "resourceGroup": RESOURCE_GROUP,
            "resourceId": APP_RESOURCE_ID,
            "oneDeployUrl": ONEDEPLOY_URL,
        },
        "package": {
            "sha256": package_sha256,
            "size": package.package_size,
            "uriSha256": hashlib.sha256(package_uri.encode("utf-8")).hexdigest(),
        },
        "request": {
            "clientRequestId": request_id,
            "sha256": hashlib.sha256(request_body).hexdigest(),
        },
        "preDeploymentIds": sorted(pre_entries),
        "liveDeployment": terminal,
        "terminalCollectionSha256": hashlib.sha256(terminal_raw).hexdigest(),
        "settledCollectionSha256": hashlib.sha256(settled_response.body).hexdigest(),
    }
    canonical_json(receipt)
    return receipt


def deploy_local_file_candidate(
    package: LocalDeploymentPackage,
    transport: HttpTransport,
    mutate_once: Callable[[str], None],
    *,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Deploy one verified local ZIP, proving the resulting OneDeploy identity.

    The injected mutation adapter may execute exactly one ``az webapp deploy``.
    This controller independently snapshots ARM deployment IDs before it,
    polls the fixed OneDeploy collection afterward, and requires settlement.
    """
    if not isinstance(package, LocalDeploymentPackage): fail("local deployment package is invalid")
    source_sha = _sha40(package.source_sha, "candidate SHA")
    package_sha = _sha256(package.package_sha256, "deployment package digest")
    if (not isinstance(package.path, str) or not package.path.startswith("/") or "\0" in package.path
            or type(package.package_size) is not int or not 0 < package.package_size <= 1024 ** 3):
        fail("local deployment package boundary is invalid")
    get_request = HttpRequest(method="GET", url=ONEDEPLOY_URL, headers={"Accept": "application/json"})
    pre_response = _request(transport, get_request, "OneDeploy preflight")
    _, pre_entries = _collection(pre_response, "OneDeploy preflight")
    if not callable(mutate_once): fail("local mutation adapter is unavailable")
    try:
        mutate_once(package.path)
    except ReleaseControlError: raise
    except Exception:
        raise ReleaseControlError("local deployment mutation failed ambiguously") from None
    terminal = None
    terminal_raw = b""
    for _ in range(MAX_DEPLOYMENT_POLLS):
        sleep(DEPLOYMENT_POLL_SECONDS)
        observed = _request(transport, get_request, "OneDeploy status")
        _, entries = _collection(observed, "OneDeploy status")
        added = sorted(set(entries) - set(pre_entries))
        if not added: continue
        if len(added) != 1: fail("OneDeploy produced multiple new deployment identities")
        terminal = _intermediate_or_terminal(entries[added[0]], observed.body)
        if terminal is not None:
            terminal_raw = observed.body
            break
    if terminal is None: fail("OneDeploy did not reach one bounded terminal success")
    sleep(DEPLOYMENT_SETTLE_SECONDS)
    settled_response = _request(transport, get_request, "OneDeploy settlement")
    _, settled_entries = _collection(settled_response, "OneDeploy settlement")
    added = sorted(set(settled_entries) - set(pre_entries))
    if added != [terminal["deploymentId"]]: fail("OneDeploy settlement changed the deployment identity set")
    if _terminal_deployment(settled_entries[added[0]], settled_response.body) != terminal:
        fail("OneDeploy terminal deployment changed during settlement")
    return {"schema": "paperdesk-azure-production-local-deploy-v1", "status": "success",
            "operation": "deploy-candidate", "sourceSha": source_sha,
            "target": {"resourceId": APP_RESOURCE_ID, "oneDeployUrl": ONEDEPLOY_URL},
            "package": {"sha256": package_sha, "size": package.package_size},
            "preDeploymentIds": sorted(pre_entries), "liveDeployment": terminal,
            "terminalCollectionSha256": hashlib.sha256(terminal_raw).hexdigest(),
            "settledCollectionSha256": hashlib.sha256(settled_response.body).hexdigest()}


def azure_cli_local_file_mutation(path: str) -> None:
    """Exactly one non-retried fixed-coordinate Azure CLI mutation."""
    completed = subprocess.run([
        "az", "webapp", "deploy", "--resource-group", RESOURCE_GROUP, "--name", APP_NAME,
        "--src-path", path, "--type", "zip", "--clean", "true", "--restart", "true",
        "--async", "false", "--track-status", "false", "--timeout", "1800000",
        "--only-show-errors", "--output", "none",
    ], check=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if completed.returncode != 0: fail("Azure CLI local deployment mutation failed ambiguously")

def retrieve_accepted_rollback_archive(
    *,
    accepted_release_prefix: str,
    raw_manifest: bytes,
    manifest_etag: str,
    manifest_version_id: str,
    transition_request: Mapping[str, Any],
    archive_blob: str,
    transport: HttpTransport,
) -> RegistryArchive:
    """Read exactly one verified runtime archive from the accepted registry."""

    if not isinstance(accepted_release_prefix, str):
        fail("accepted-release prefix is invalid")
    match = PREFIX.fullmatch(accepted_release_prefix)
    if not match:
        fail("accepted-release prefix is invalid")
    try:
        baseline = accepted_release_manifest.validate_accept_candidate_manifest(
            raw_manifest,
            transition_request,
            actual_registry_etag=manifest_etag,
            actual_registry_version_id=manifest_version_id,
        )
    except accepted_release_manifest.AcceptedReleaseManifestError as exc:
        raise ReleaseControlError("accepted-release manifest binding is invalid") from exc
    if baseline.get("acceptedReleasePrefix") != accepted_release_prefix:
        fail("accepted-release prefix differs from the canonical manifest")
    source_sha = _sha40(baseline.get("sourceSha"), "accepted rollback SHA")
    if (
        match.group("sha") != source_sha
        or match.group("source") != baseline.get("sourceRunId")
        or match.group("acceptance") != baseline.get("acceptanceRunId")
    ):
        fail("accepted-release prefix coordinates are inconsistent")

    manifest = _json_no_duplicates(raw_manifest, "accepted-release manifest")
    relative = f"verified-artifact/paperdesk-azure-runtime-{source_sha}.tar.gz"
    records = [record for record in manifest.get("files", []) if isinstance(record, dict) and record.get("path") == relative]
    if len(records) != 1 or set(records[0]) != {"path", "size", "sha256", "contentMd5"}:
        fail("accepted-release runtime archive record is not exact")
    record = records[0]
    size = record.get("size")
    if type(size) is not int or not 0 < size <= 1024 * 1024 * 1024:
        fail("accepted-release runtime archive size is invalid")
    archive_sha256 = _sha256(record.get("sha256"), "accepted-release runtime archive digest")
    blob_name = accepted_release_prefix + relative
    if archive_blob != blob_name:
        fail("accepted-release archiveBlob differs from the canonical manifest")
    encoded_blob = urllib.parse.quote(blob_name, safe="/")
    url = f"{REGISTRY_ORIGIN}/{REGISTRY_CONTAINER}/{encoded_blob}"
    request = HttpRequest(
        method="GET",
        url=url,
        headers={"Accept": "application/octet-stream"},
        maximum_response_bytes=size,
        timeout_seconds=120,
    )
    response = _request(transport, request, "accepted-release archive readback")
    if response.status != 200:
        fail("accepted-release archive readback did not return HTTP 200")
    if len(response.body) != size or hashlib.sha256(response.body).hexdigest() != archive_sha256:
        fail("accepted-release archive bytes differ from the canonical manifest")
    return RegistryArchive(
        source_sha=source_sha,
        source_run_id=_positive(baseline.get("sourceRunId"), "accepted-release source run ID"),
        acceptance_run_id=_positive(baseline.get("acceptanceRunId"), "accepted-release acceptance run ID"),
        accepted_release_prefix=accepted_release_prefix,
        accepted_release_manifest_sha256=_sha256(
            baseline.get("acceptedReleaseManifestSha256"),
            "accepted-release manifest digest",
        ),
        blob_name=blob_name,
        archive_sha256=archive_sha256,
        archive_size=size,
        body=response.body,
    )


def _live_json(
    transport: HttpTransport,
    path: str,
    label: str,
) -> tuple[dict[str, Any], str]:
    url = LIVE_ORIGIN + path
    request = HttpRequest(
        method="GET",
        url=url,
        headers={"Accept": "application/json", "Cache-Control": "no-store"},
        maximum_response_bytes=MAX_LIVE_JSON_BYTES,
        timeout_seconds=30,
    )
    response = _request(transport, request, label)
    if response.status != 200:
        fail(f"{label} did not return HTTP 200")
    document = _json_no_duplicates(response.body, label)
    if not isinstance(document, dict):
        fail(f"{label} must be a JSON object")
    return document, hashlib.sha256(response.body).hexdigest()


def finalize_live_release(source_sha: str, transport: HttpTransport) -> dict[str, Any]:
    """Verify the exact production release and all public health boundaries."""

    source_sha = _sha40(source_sha, "finalized release SHA")
    sha_url = LIVE_ORIGIN + "/api/runtime-release-sha"
    sha_request = HttpRequest(
        method="GET",
        url=sha_url,
        headers={"Accept": "text/plain", "Cache-Control": "no-store"},
        maximum_response_bytes=MAX_RELEASE_SHA_BYTES,
        timeout_seconds=30,
    )
    sha_response = _request(transport, sha_request, "runtime release SHA")
    if sha_response.status != 200 or sha_response.body != source_sha.encode("ascii"):
        fail("live runtime release SHA is not exact")

    live, live_digest = _live_json(transport, "/api/health/live", "liveness")
    if live.get("ok") is not True or live.get("status") != "live":
        fail("live liveness predicate is not healthy")

    ready, ready_digest = _live_json(transport, "/api/health/ready", "readiness")
    malware = ready.get("attachmentMalware")
    if (
        ready.get("ok") is not True
        or ready.get("status") != "ready"
        or not isinstance(malware, dict)
        or malware.get("required") is not True
        or malware.get("ingestionReady") is not True
        or malware.get("code") != "attachment-malware-scan-ready"
    ):
        fail("live readiness predicate is not healthy")

    app_health, app_health_digest = _live_json(transport, "/api/app-health", "app health")
    if app_health.get("ok") is not True or app_health.get("diagnostics") != "restricted":
        fail("live app-health predicate is not healthy")

    security, security_digest = _live_json(transport, "/api/security-info", "security info")
    if (
        security.get("ok") is not True
        or security.get("requiresConfiguredUsers") is not True
        or security.get("diagnostics") != "restricted"
        or any(key in security for key in ("dataDir", "users", "securityPosture"))
    ):
        fail("live security-info predicate is invalid")

    receipt = {
        "schema": "paperdesk-azure-production-finalization-v1",
        "status": "verified",
        "operation": "finalize-live-release",
        "sourceSha": source_sha,
        "liveOrigin": LIVE_ORIGIN,
        "probes": {
            "runtimeReleaseSha": {
                "path": "/api/runtime-release-sha",
                "sha256": hashlib.sha256(sha_response.body).hexdigest(),
            },
            "liveness": {"path": "/api/health/live", "sha256": live_digest},
            "readiness": {"path": "/api/health/ready", "sha256": ready_digest},
            "appHealth": {"path": "/api/app-health", "sha256": app_health_digest},
            "securityInfo": {"path": "/api/security-info", "sha256": security_digest},
        },
    }
    canonical_json(receipt)
    return receipt
