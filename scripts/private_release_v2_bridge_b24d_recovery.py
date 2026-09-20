"""One-use recovery of the bridge left exposed by bootstrap b24d1e63.

Observe is read only. Apply requires a fresh, source-bound authorization and
the exact confirmation text. Every ARM mutation is journaled before its sole
attempt; uncertain results stop execution for operator review.
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
from typing import Any, Mapping
import urllib.parse
import uuid

try:
    from scripts import private_release_v2_bootstrap as bootstrap
except ModuleNotFoundError:
    import private_release_v2_bootstrap as bootstrap  # type: ignore


ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
CEREMONY = Path(r"C:\ProgramData\PaperDeskReleaseCeremonies-20260905-a75d00e9")
INCIDENT = "b24d1e63-9080-4214-9e7a-93c6f2e4ebe0"
SOURCE_SHA = "6752deb9cf6613e77124ce32809262092341ad66"
SUBSCRIPTION = "9c4e0d0d-602f-4cde-84bd-337250e5b64c"
TENANT = "aba83bd8-3e5c-4a87-9eb1-7bca070685b2"
ACCOUNT = "tasethvirak@gmail.com"
ACCOUNT_OBJECT = "b97bfa13-b375-4b27-93d7-141029dbc05b"
SITE_ID = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-master-data-structure-sea/"
    "providers/Microsoft.Web/sites/paperdesk-release-registry-bridge-v2-9c4e0d0d"
)
ARM = "https://management.azure.com"
SITE = f"{ARM}{SITE_ID}?api-version=2025-03-01"
STOP = f"{ARM}{SITE_ID}/stop?api-version=2025-03-01"
SCM = f"{ARM}{SITE_ID}/basicPublishingCredentialsPolicies/scm?api-version=2022-03-01"
SETTINGS = f"{ARM}{SITE_ID}/config/appsettings?api-version=2025-03-01"
SETTINGS_LIST = f"{ARM}{SITE_ID}/config/appsettings/list?api-version=2025-03-01"
INCIDENT_DIR = CEREMONY / f"paperdesk-private-release-v2-bootstrap-{INCIDENT}"
MARKER = INCIDENT_DIR / "unresolved-public-network-enable.json"
MARKER_SHA = "af533dd85df1e2daa83c10868d406c82d829e2473b054d94ea395249e4c5ebb1"
AUTH_PATH = CEREMONY / f"observation-{INCIDENT}" / "bootstrap-authorization.json"
AUTH_SHA = "fabc79ffa33d5f8825f53656c31289fe87049c55c5e85d4fa1f1183cf9a21761"
PREFLIGHT_PATH = CEREMONY / f"observation-{INCIDENT}" / "bootstrap-preflight.json"
PREFLIGHT_SHA = "f0fa3c372e0d358dca4e569db428454a9195eb3631a6c1ebecb04d88d353d18e"
JOURNAL_HASHES = {
    "cloud-mutation-0062.json": "7a3fba11a6e0ca301b63ecac5052bb78bc490aec22da00df426c1666386a0d4b",
    "cloud-mutation-0064.json": "7c7e64deeb57e5138aa4d1d46e810645f71773743a88c753185e90b3b4cebcdb",
    "cloud-mutation-0066.json": "9472cfd3688ed425fdf79f1c654a72d08b10c65872af63f4b7179511601582a0",
    "cloud-mutation-0068.json": "3271115e05a3b9109b5bb07d94ed8f805b9769b98d6d18b5dee9e5c91c15be90",
    "cloud-mutation-0070.json": "756a4cbab780e5b5168df9c68c40ef1df922608fca768456f51b0d133968f6fd",
    "cloud-mutation-0072.json": "ebf173ba66cf49936890ca3fa7b4b64cd8676af02b05598febf17e6727e54972",
}
INTENT_SHA = "32de2da5c6c7fdce5e139ef6276a535d29fd45690bdc559a1f8bd310efa1be4c"
TERMINAL_SHA = "4694363ddc33090da78f8799b3113a1821184804650a90bf28497b351cee6650"
SETTINGS_SHA = "23d13be26e679bb214bcace39174144d8982ddc3a3ed45662e39799a481127f1"
EMPTY_SETTINGS_SHA = "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"
SETTING_KEYS = {
    "PAPERDESK_BRIDGE_BOOTSTRAP_SELF_TEST_JSON",
    "PAPERDESK_BRIDGE_PACKAGE_SHA256",
    "WEBSITE_RUN_FROM_PACKAGE",
    "WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID",
    "WEBSITE_SKIP_RUNNING_KUDUAGENT",
}
IDENTITY_BASE = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-master-data-structure-sea/"
    "providers/Microsoft.ManagedIdentity/userAssignedIdentities/"
)
UAMI_IDS = {
    (IDENTITY_BASE + name).lower()
    for name in (
        "id-paperdesk-release-bridge-v2",
        "id-paperdesk-release-production-activation-v2",
        "id-paperdesk-release-signer-v2",
        "uami-paperdesk-accepted-release-reader",
        "uami-paperdesk-accepted-release-writer",
    )
}
PLAN_ID = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-master-data-structure-sea/"
    "providers/Microsoft.Web/serverfarms/asp-master-data-structure-b1-sea"
)
SUBNET_ID = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-master-data-structure-sea/"
    "providers/Microsoft.Network/virtualNetworks/vnet-master-data-structure-sea/"
    "subnets/snet-appservice-integration"
)
RECOVERY_PLAN = [
    "stop", "disable-scm", "post-scm-stop-if-running",
    "disable-public-network", "post-patch-stop-if-running",
    "restore-empty-settings", "post-settings-stop-if-running",
    "archive-incident-marker",
]
STOP_BODY = b""
SCM_BODY = bootstrap.canonical_json_bytes({"properties": {"allow": False}})
PUBLIC_BODY = bootstrap.canonical_json_bytes({"properties": {"publicNetworkAccess": "Disabled"}})
EMPTY_SETTINGS_BODY = bootstrap.canonical_json_bytes({"properties": {}})


class RecoveryError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise RecoveryError(message)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load(path: Path, expected_sha: str | None = None) -> Any:
    if not path.is_file() or path.is_symlink():
        fail(f"required real file is absent: {path.name}")
    raw = path.read_bytes()
    if expected_sha is not None and sha(raw) != expected_sha:
        fail(f"source-bound file changed: {path.name}")
    try:
        value = json.loads(raw, object_pairs_hook=bootstrap._duplicate_safe_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryError(f"invalid JSON: {path.name}") from exc
    if raw != bootstrap.canonical_json_bytes(value):
        fail(f"noncanonical JSON: {path.name}")
    return value


def write_new(path: Path, value: Any) -> None:
    raw = bootstrap.canonical_json_bytes(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    bootstrap.UseLedger._fsync_directory(path.parent)


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True,
        encoding="utf-8", timeout=30, check=False,
    )
    if result.returncode:
        fail("source git inspection failed")
    return result.stdout.strip()


def source() -> dict[str, str]:
    if git("status", "--porcelain=v1") or git("symbolic-ref", "--short", "HEAD") != "main":
        fail("recovery requires clean merged main")
    head = git("rev-parse", "HEAD")
    if head != git("rev-parse", "origin/main") or head == SOURCE_SHA:
        fail("recovery source must be a new merged main commit")
    if git("remote", "get-url", "origin") != "https://github.com/Sethvirak/paperdesk-release-verifier.git":
        fail("recovery repository remote changed")
    remote_main = git("ls-remote", "origin", "refs/heads/main").split()
    if len(remote_main) != 2 or remote_main != [head, "refs/heads/main"]:
        fail("remote main moved after local source checkout")
    return {"commitSha": head, "treeSha": git("rev-parse", "HEAD^{tree}"), "executorSha256": sha(SELF.read_bytes())}


def incident() -> dict[str, str]:
    auth = load(AUTH_PATH, AUTH_SHA)
    preflight = load(PREFLIGHT_PATH, PREFLIGHT_SHA)
    marker = load(MARKER, MARKER_SHA)
    if auth.get("authorizationId") != INCIDENT or marker.get("authorizationId") != INCIDENT:
        fail("incident authorization binding changed")
    if auth.get("source", {}).get("mergedMain", {}).get("commitSha") != SOURCE_SHA:
        fail("incident source changed")
    if marker.get("status") != "unresolved-public-network-enable" or marker.get("siteResourceId", "").lower() != SITE_ID.lower():
        fail("incident marker changed")
    admissions = preflight.get("projection", {}).get("operationAdmissions", [])
    configure = [
        item for item in admissions
        if isinstance(item, Mapping)
        and item.get("operationId") == "configureBridgeExactVersionedPackageAndCriticalSettings"
    ]
    context = configure[0].get("context") if len(configure) == 1 else None
    if (
        not isinstance(context, Mapping)
        or context.get("preAppSettings") != {}
        or context.get("preAppSettingsSha256") != EMPTY_SETTINGS_SHA
    ):
        fail("incident source App Settings prestate changed")
    for name, expected in JOURNAL_HASHES.items():
        value = load(INCIDENT_DIR / name, expected)
        if value.get("phase") != "result" or value.get("status") != 200:
            fail(f"incident journal result changed: {name}")
    intent = load(INCIDENT_DIR / "cloud-mutation-0073.json", INTENT_SHA)
    terminal = load(INCIDENT_DIR / "execution-terminal.json", TERMINAL_SHA)
    if (
        intent.get("phase") != "intent"
        or intent.get("operationId") != "startBridgeForBoundedCanary"
        or intent.get("method") != "POST"
        or terminal.get("status") != "failed"
        or terminal.get("consumed") is not True
        or terminal.get("failureType") != "BootstrapError"
    ):
        fail("incident unresolved canary or terminal record changed")
    return {"authorizationId": INCIDENT, "sourceSha": SOURCE_SHA, "markerSha256": MARKER_SHA}


class BoundSession:
    def __init__(self, inner: Any, mutate: bool) -> None:
        self.inner = inner
        self.mutate = mutate
        self.issued: dict[str, int] = {}
        self.async_url: str | None = None

    def account(self) -> Any:
        return self.inner.account()

    def request(self, method: str, url: str, body: bytes | None = None) -> Any:
        reads = {("GET", SITE), ("GET", SCM), ("POST", SETTINGS_LIST)}
        mutations = {
            ("POST", STOP): STOP_BODY,
            ("PUT", SCM): SCM_BODY,
            ("PATCH", SITE): PUBLIC_BODY,
            ("PUT", SETTINGS): EMPTY_SETTINGS_BODY,
        }
        if (method, url) in reads:
            if body is not None:
                fail("read body is outside boundary")
            return self.inner.request(method, url)
        if method == "GET" and url == self.async_url:
            return self.inner.request(method, url)
        if not self.mutate or (method, url) not in mutations or body != mutations[(method, url)]:
            fail("Azure request is outside recovery allowlist")
        key = f"{method} {url}"
        maximum = 4 if (method, url) == ("POST", STOP) else 1
        if self.issued.get(key, 0) >= maximum:
            fail("Azure mutation may be issued only once")
        self.issued[key] = self.issued.get(key, 0) + 1
        return self.inner.request(
            method, url, body=body,
            headers={"Content-Type": "application/json"} if method != "POST" else None,
            deadline=dt.datetime.now(dt.timezone.utc) + dt.timedelta(
                seconds=bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS + 30
            ),
        )


def document(response: Any, expected: set[int], label: str) -> Mapping[str, Any]:
    if response.status not in expected:
        fail(f"{label} returned HTTP {response.status}")
    try:
        value = json.loads(response.body, object_pairs_hook=bootstrap._duplicate_safe_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryError(f"{label} returned invalid JSON") from exc
    if not isinstance(value, Mapping):
        fail(f"{label} returned non-object JSON")
    return value


def live(session: BoundSession, *, state: str, public: str, scm: bool, settings: str) -> dict[str, Any]:
    site = document(session.request("GET", SITE), {200}, "bridge")
    props = site.get("properties")
    identity = site.get("identity")
    uamis = identity.get("userAssignedIdentities") if isinstance(identity, Mapping) else None
    if (
        str(site.get("id", "")).lower() != SITE_ID.lower()
        or site.get("kind") != "app,linux"
        or not isinstance(props, Mapping)
        or props.get("state") != state
        or props.get("enabled") is not True
        or props.get("httpsOnly") is not True
        or props.get("publicNetworkAccess") != public
        or not isinstance(identity, Mapping)
        or identity.get("type") != "UserAssigned"
        or not isinstance(uamis, Mapping)
        or {key.lower() for key in uamis} != UAMI_IDS
        or str(props.get("serverFarmId", "")).lower() != PLAN_ID.lower()
        or str(props.get("virtualNetworkSubnetId", "")).lower() != SUBNET_ID.lower()
        or not isinstance(props.get("outboundVnetRouting"), Mapping)
        or not bootstrap._safe_bridge_outbound_vnet_routing(props["outboundVnetRouting"])
        or not isinstance(props.get("siteConfig"), Mapping)
        or props["siteConfig"].get("webJobsEnabled") is not True
    ):
        fail("bridge site is outside exact recovery posture")
    policy = document(session.request("GET", SCM), {200}, "SCM policy")
    policy_properties = policy.get("properties")
    if str(policy.get("id", "")).lower() != (SITE_ID + "/basicPublishingCredentialsPolicies/scm").lower() or not isinstance(policy_properties, Mapping) or policy_properties.get("allow") is not scm:
        fail("SCM policy is outside exact recovery posture")
    config = document(session.request("POST", SETTINGS_LIST), {200}, "App Settings")
    values = config.get("properties")
    if not isinstance(values, Mapping):
        fail("App Settings map is invalid")
    if settings == "incident":
        if set(values) != SETTING_KEYS or sha(bootstrap.canonical_json_bytes(values)) != SETTINGS_SHA:
            fail("App Settings differ from exact incident map")
    elif settings == "empty" and values != {}:
        fail("App Settings restoration is not empty")
    return {
        "site": {"state": state, "publicNetworkAccess": public, "httpsOnly": True, "identityCount": len(uamis)},
        "scmAllow": scm,
        "settings": {"count": len(values), "sha256": sha(bootstrap.canonical_json_bytes(values))},
    }


def account(session: BoundSession) -> dict[str, Any]:
    value = session.account()
    expected = {
        "cloud": "AzureCloud", "subscriptionId": SUBSCRIPTION, "tenantId": TENANT,
        "accountId": ACCOUNT, "accountObjectId": ACCOUNT_OBJECT, "accountType": "user",
    }
    if value != expected:
        fail("Azure account boundary changed")
    return expected


def phrase(identifier: str, preflight_sha: str, source_sha: str) -> str:
    return (
        f"Authorize Azure bridge exposure recovery under authorization {identifier}: "
        f"For bootstrap incident {INCIDENT} at source {SOURCE_SHA}, authorize one "
        "journaled stop of the exact bridge, one SCM basic-auth disable PUT, at most one "
        "post-SCM stop if Azure restarts the bridge, one public-network disable PATCH, "
        "at most one post-PATCH stop if Azure restarts the bridge, and one exact "
        "empty App Settings PUT after the bridge is stopped and private, with at most one "
        "post-settings stop if Azure restarts it. Restore only the "
        "reviewed incident map with SHA-256 " + SETTINGS_SHA + " to its empty prestate. "
        f"Bind this action to recovery source {source_sha} and preflight SHA-256 {preflight_sha}. "
        "Each mutation is attempted at most once without retry. I accept that Azure offers no "
        "supported conditional ETag for these updates, and interruption or ambiguous transport "
        "can leave the bridge running, public, SCM auth enabled, or settings changed. Any such "
        "result stops the executor and requires fresh reads and reviewed recovery. The local "
        "incident marker is archived only after exact stopped, private, SCM-disabled, empty-map "
        "readback. No RBAC, lock, Storage, production, package, fence, identity, or legacy-resource "
        "mutation is authorized."
    )


def observe(output: Path) -> dict[str, Any]:
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        fail("observation directory boundary is unsafe")
    src = source()
    inc = incident()
    probe = BoundSession(bootstrap.AzureCliRestSession({}), False)
    acct = account(probe)
    session = BoundSession(bootstrap.AzureCliRestSession({"azure": acct}), False)
    projection = live(session, state="Running", public="Enabled", scm=True, settings="incident")
    now = dt.datetime.now(dt.timezone.utc)
    identifier = str(uuid.uuid4())
    preflight = {
        "schemaVersion": 1, "recoveryAuthorizationId": identifier,
        "observedAt": now.isoformat(), "expiresAt": (now + dt.timedelta(minutes=30)).isoformat(),
        "source": src, "incident": inc, "azure": acct, "live": projection,
        "plan": RECOVERY_PLAN,
    }
    raw = bootstrap.canonical_json_bytes(preflight)
    output.mkdir(mode=0o700, exist_ok=False)
    bootstrap.UseLedger._fsync_directory(output.parent)
    write_new(output / "recovery-preflight.json", preflight)
    request = phrase(identifier, sha(raw), src["commitSha"])
    write_new(output / "authorization-template.json", {
        "schemaVersion": 1, "recoveryAuthorizationId": identifier,
        "preflightSha256": sha(raw), "source": src,
        "expiresAt": preflight["expiresAt"], "exactConfirmationText": request,
        "executable": False,
    })
    return {"status": "read-only-review-required", "authorizationId": identifier, "preflightSha256": sha(raw), "expiresAt": preflight["expiresAt"], "confirmationText": request}


def prepare(template_path: Path, confirmation_path: Path, output_path: Path) -> dict[str, Any]:
    template = load(template_path)
    if not confirmation_path.is_file() or confirmation_path.is_symlink():
        fail("confirmation artifact missing")
    confirmation = confirmation_path.read_text(encoding="utf-8").rstrip("\r\n")
    src = source()
    identifier = template.get("recoveryAuthorizationId")
    if (
        set(template) != {"schemaVersion", "recoveryAuthorizationId", "preflightSha256", "source", "expiresAt", "exactConfirmationText", "executable"}
        or template.get("schemaVersion") != 1
        or template.get("source") != src
        or template.get("executable") is not False
        or confirmation != template.get("exactConfirmationText")
        or confirmation != phrase(identifier, template.get("preflightSha256"), src["commitSha"])
    ):
        fail("recovery confirmation does not match the reviewed template")
    try:
        expires = dt.datetime.fromisoformat(template["expiresAt"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RecoveryError("invalid authorization expiry") from exc
    if expires.utcoffset() is None or dt.datetime.now(dt.timezone.utc) >= expires:
        fail("recovery confirmation expired")
    authorization = dict(template)
    authorization["executable"] = True
    write_new(output_path, authorization)
    return {"status": "authorization-prepared", "authorizationId": identifier, "authorizationSha256": sha(output_path.read_bytes())}


def await_result(session: BoundSession, response: Any, label: str) -> None:
    if response.status == 200:
        return
    if response.status != 202:
        fail(f"{label} returned HTTP {response.status}")
    headers = {key.lower(): value for key, value in response.headers.items()}
    url = headers.get("azure-asyncoperation")
    if not isinstance(url, str):
        fail(f"{label} returned 202 without Azure-AsyncOperation")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != "management.azure.com" or not parsed.path.startswith(f"/subscriptions/{SUBSCRIPTION}/") or not parsed.query or parsed.fragment:
        fail(f"{label} returned an unsafe Azure-AsyncOperation URL")
    session.async_url = url
    for _ in range(20):
        result = document(session.request("GET", url), {200}, f"{label} poll")
        status = result.get("status")
        if status == "Succeeded":
            session.async_url = None
            return
        if status not in {"InProgress", "Running"}:
            fail(f"{label} reached non-success terminal status")
        time.sleep(2)
    fail(f"{label} did not reach Succeeded within bounded polling")


def wait_site(session: BoundSession, state: str, public: str) -> None:
    for _ in range(20):
        site = document(session.request("GET", SITE), {200}, "site convergence")
        props = site.get("properties", {})
        if props.get("state") == state and props.get("publicNetworkAccess") == public:
            return
        time.sleep(2)
    fail("bridge site did not converge to exact state")


def wait_scm_disabled(session: BoundSession) -> None:
    for _ in range(20):
        policy = document(session.request("GET", SCM), {200}, "SCM convergence")
        allow = policy.get("properties", {}).get("allow")
        if allow is False:
            return
        if allow is not True:
            fail("SCM policy reached a third state")
        time.sleep(2)
    fail("SCM policy did not converge to Disabled")


def wait_public_disabled(session: BoundSession) -> None:
    for _ in range(20):
        site = document(session.request("GET", SITE), {200}, "public-network convergence")
        value = site.get("properties", {}).get("publicNetworkAccess")
        if value == "Disabled":
            return
        if value != "Enabled":
            fail("public network reached a third state")
        time.sleep(2)
    fail("public network did not converge to Disabled")


def wait_settings_empty(session: BoundSession) -> None:
    for _ in range(20):
        config = document(session.request("POST", SETTINGS_LIST), {200}, "App Settings convergence")
        values = config.get("properties")
        if values == {}:
            return
        if not isinstance(values, Mapping) or set(values) != SETTING_KEYS or sha(bootstrap.canonical_json_bytes(values)) != SETTINGS_SHA:
            fail("App Settings reached a third state")
        time.sleep(2)
    fail("App Settings did not converge to empty")


def apply(preflight_path: Path, authorization_path: Path, confirmation_path: Path) -> dict[str, Any]:
    src = source()
    inc = incident()
    preflight = load(preflight_path)
    authorization = load(authorization_path)
    if not confirmation_path.is_file() or confirmation_path.is_symlink():
        fail("confirmation artifact missing")
    confirmation = confirmation_path.read_text(encoding="utf-8").rstrip("\r\n")
    now = dt.datetime.now(dt.timezone.utc)
    try:
        observed = dt.datetime.fromisoformat(preflight["observedAt"])
        expires = dt.datetime.fromisoformat(preflight["expiresAt"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RecoveryError("invalid preflight time boundary") from exc
    identifier = preflight.get("recoveryAuthorizationId")
    try:
        if not isinstance(identifier, str) or str(uuid.UUID(identifier)) != identifier:
            fail("recovery authorization ID is not a canonical GUID")
    except ValueError as exc:
        raise RecoveryError("recovery authorization ID is not a GUID") from exc
    preflight_sha = sha(preflight_path.read_bytes())
    expected_phrase = phrase(identifier, preflight_sha, src["commitSha"])
    if (
        set(preflight) != {"schemaVersion", "recoveryAuthorizationId", "observedAt", "expiresAt", "source", "incident", "azure", "live", "plan"}
        or preflight.get("schemaVersion") != 1
        or preflight.get("plan") != RECOVERY_PLAN
        or observed.utcoffset() is None or expires.utcoffset() is None
        or preflight.get("source") != src or preflight.get("incident") != inc
        or now < observed or now >= expires or (expires - observed) != dt.timedelta(minutes=30)
        or authorization != {
            "schemaVersion": 1, "recoveryAuthorizationId": identifier,
            "preflightSha256": preflight_sha, "source": src,
            "expiresAt": preflight["expiresAt"], "exactConfirmationText": expected_phrase,
            "executable": True,
        }
        or confirmation != expected_phrase
    ):
        fail("recovery authorization, source, time, or confirmation is not exact")
    session = BoundSession(bootstrap.AzureCliRestSession({"azure": preflight["azure"]}), True)
    if account(session) != preflight.get("azure"):
        fail("Azure account drifted")
    before = live(session, state="Running", public="Enabled", scm=True, settings="incident")
    if before != preflight.get("live"):
        fail("live recovery state drifted after review")
    ledger = CEREMONY / f"paperdesk-private-release-v2-bridge-b24d-recovery-{identifier}"
    if ledger.exists() or ledger.is_symlink():
        fail("one-use recovery ledger already exists")
    ledger.mkdir(mode=0o700, exist_ok=False)
    bootstrap.UseLedger._fsync_directory(CEREMONY)
    write_new(ledger / "claim.json", {"authorizationSha256": sha(authorization_path.read_bytes()), "preflightSha256": preflight_sha, "claimedAt": now.isoformat()})

    def mutation(name: str, method: str, url: str, body: bytes) -> Any:
        write_new(ledger / f"{name}-intent.json", {"method": method, "url": url, "bodySha256": sha(body), "recordedAt": dt.datetime.now(dt.timezone.utc).isoformat()})
        response = session.request(method, url, body)
        write_new(ledger / f"{name}-result.json", {"status": response.status, "responseSha256": sha(response.body), "recordedAt": dt.datetime.now(dt.timezone.utc).isoformat()})
        return response

    if live(session, state="Running", public="Enabled", scm=True, settings="incident") != before:
        fail("final pre-read drifted")
    stop_response = mutation("stop", "POST", STOP, STOP_BODY)
    if stop_response.status not in {200, 202}:
        fail(f"bridge stop returned HTTP {stop_response.status}")
    wait_site(session, "Stopped", "Enabled")
    live(session, state="Stopped", public="Enabled", scm=True, settings="incident")
    await_result(session, mutation("disable-scm", "PUT", SCM, SCM_BODY), "SCM disable")
    wait_scm_disabled(session)
    after_scm = document(session.request("GET", SITE), {200}, "post-SCM site")
    scm_site_props = after_scm.get("properties", {})
    if scm_site_props.get("publicNetworkAccess") != "Enabled":
        fail("post-SCM public network changed")
    if scm_site_props.get("state") == "Running":
        stop_response = mutation("post-scm-stop", "POST", STOP, STOP_BODY)
        if stop_response.status not in {200, 202}:
            fail(f"post-SCM stop returned HTTP {stop_response.status}")
    elif scm_site_props.get("state") != "Stopped":
        fail("post-SCM bridge state is unknown")
    wait_site(session, "Stopped", "Enabled")
    live(session, state="Stopped", public="Enabled", scm=False, settings="incident")
    await_result(session, mutation("disable-public", "PATCH", SITE, PUBLIC_BODY), "public disable")
    wait_public_disabled(session)
    current = document(session.request("GET", SITE), {200}, "post-public site")
    current_props = current.get("properties", {})
    if current_props.get("publicNetworkAccess") != "Disabled":
        fail("public network disable readback failed")
    if current_props.get("state") == "Running":
        stop_response = mutation("post-patch-stop", "POST", STOP, STOP_BODY)
        if stop_response.status not in {200, 202}:
            fail(f"post-patch stop returned HTTP {stop_response.status}")
    elif current_props.get("state") != "Stopped":
        fail("post-public bridge state is unknown")
    wait_site(session, "Stopped", "Disabled")
    live(session, state="Stopped", public="Disabled", scm=False, settings="incident")
    await_result(session, mutation("empty-settings", "PUT", SETTINGS, EMPTY_SETTINGS_BODY), "App Settings restoration")
    wait_settings_empty(session)
    after_settings = document(session.request("GET", SITE), {200}, "post-settings site")
    after_properties = after_settings.get("properties", {})
    if after_properties.get("publicNetworkAccess") != "Disabled":
        fail("post-settings public network changed")
    if after_properties.get("state") == "Running":
        stop_response = mutation("post-settings-stop", "POST", STOP, STOP_BODY)
        if stop_response.status not in {200, 202}:
            fail(f"post-settings stop returned HTTP {stop_response.status}")
    elif after_properties.get("state") != "Stopped":
        fail("post-settings bridge state is unknown")
    wait_site(session, "Stopped", "Disabled")
    final = live(session, state="Stopped", public="Disabled", scm=False, settings="empty")
    write_new(ledger / "final-proof.json", final)
    resolved = INCIDENT_DIR / f"resolved-public-network-enable-{identifier}.json"
    if resolved.exists() or sha(MARKER.read_bytes()) != MARKER_SHA:
        fail("incident marker changed before archival")
    write_new(ledger / "azure-recovered-marker-pending.json", {"status": "azure-recovered-marker-pending", "final": final, "target": str(resolved)})
    MARKER.rename(resolved)
    bootstrap.UseLedger._fsync_directory(INCIDENT_DIR)
    write_new(ledger / "terminal.json", {"status": "recovered", "final": final, "archivedMarker": str(resolved)})
    return {"status": "recovered", "authorizationId": identifier, "final": final}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    observation = commands.add_parser("observe")
    observation.add_argument("--output-directory", type=Path, required=True)
    preparation = commands.add_parser("prepare")
    preparation.add_argument("--template", type=Path, required=True)
    preparation.add_argument("--confirmation", type=Path, required=True)
    preparation.add_argument("--output", type=Path, required=True)
    execution = commands.add_parser("apply")
    execution.add_argument("--preflight", type=Path, required=True)
    execution.add_argument("--authorization", type=Path, required=True)
    execution.add_argument("--confirmation", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "observe":
            result = observe(args.output_directory)
        elif args.command == "prepare":
            result = prepare(args.template, args.confirmation, args.output)
        else:
            result = apply(args.preflight, args.authorization, args.confirmation)
    except (RecoveryError, OSError, RuntimeError) as exc:
        print(f"bridge b24d recovery error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
