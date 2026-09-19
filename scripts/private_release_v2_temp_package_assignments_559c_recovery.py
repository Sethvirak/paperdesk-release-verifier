"""Source-bound one-use recovery for two exact residual package role assignments.

The wrapper performs read-only observation by default.  Apply mode admits only
the reviewed rollback-lock DELETE, the two exact incident assignment DELETEs,
and an exact rollback-lock restoration PUT.  Every mutation is journaled before
issue and is attempted at most once.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid


ROOT = Path(r"C:\Users\HP PC\Downloads\paperdesk-release-verifier-v2-trust-20260829")
CEREMONY = Path(r"C:\ProgramData\PaperDeskReleaseCeremonies-20260905-a75d00e9")
REPORTS = CEREMONY
INCIDENT_ID = '559ce044-0537-4323-9a54-473c1929b9a0'
SOURCE_SHA = '0b141d02939b517e359c3ae1818d76125ad6b3ac'
SUBSCRIPTION = "9c4e0d0d-602f-4cde-84bd-337250e5b64c"
TENANT = "aba83bd8-3e5c-4a87-9eb1-7bca070685b2"
ACCOUNT_OBJECT_ID = "b97bfa13-b375-4b27-93d7-141029dbc05b"
PLAN_SHA256 = '49f2977345bbbb25a26a42049af0267603261c4f03909131cc30ffb1dbd8f760'
PACKAGE_SHA256 = '3395bc6c812b1b3c7d91e9abb823a939e651f8efba700565a834fc45d26693fe'
INCIDENT_AUTH_SHA256 = '426ab0bbed6512858c216016c0fb47ea7d17a16b04e8b5ad4f832bb357d1b90a'
EXECUTOR_SHA256 = 'b3addea38312515792a99fc22a7066c13e9d6e85c6abeb8d304282411c37ad6f'
OBSERVER_SHA256 = '17a17a23883996992e7e071b2a7a6cf583eaeeb494040e5ac9432aab96605193'
CLEANUP_LOCKS_SHA256 = "7b19b7c54996c1b3ed3b93e12018a63968870820946caccab7d8c012db61b956"
SOURCE_EVIDENCE_SHA256 = 'c1bc671bfd9e3f234497ae3f551024d484e36baa61cb02ebe9ec1fbc828a19d3'
PACKAGE_ADD_ASSIGNMENT_ID = '47bee99b-21e7-5715-8314-e6c838512c57'
PACKAGE_READ_ASSIGNMENT_ID = '6f4ec335-2f59-5df2-accf-124867306642'
PACKAGE_ADD_ROLE_DEFINITION_ID = "b5d9d7c7-9367-4ac0-9d41-28b71e0d517d"
PACKAGE_READ_ROLE_DEFINITION_ID = "e005b62b-037b-4989-b492-932669ec0842"
RECOVERY_OPERATION_ID = 'recoverExactResidualPackageAssignments559c'

MGMT = "https://management.azure.com"
SCOPE = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-paperdesk-rollback-sea-20260808/"
    "providers/Microsoft.Storage/storageAccounts/mdspdbak2608089c4e/blobServices/"
    "default/containers/paperdesk-deployment-packages"
)
PACKAGE_ADD_ASSIGNMENT_RESOURCE = (
    f"{SCOPE}/providers/Microsoft.Authorization/roleAssignments/{PACKAGE_ADD_ASSIGNMENT_ID}"
)
PACKAGE_ADD_ASSIGNMENT_URL = f"{MGMT}{PACKAGE_ADD_ASSIGNMENT_RESOURCE}?api-version=2022-04-01"
PACKAGE_READ_ASSIGNMENT_RESOURCE = (
    f"{SCOPE}/providers/Microsoft.Authorization/roleAssignments/{PACKAGE_READ_ASSIGNMENT_ID}"
)
PACKAGE_READ_ASSIGNMENT_URL = f"{MGMT}{PACKAGE_READ_ASSIGNMENT_RESOURCE}?api-version=2022-04-01"
PACKAGE_ADD_ROLE_DEFINITION_RESOURCE = (
    f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/"
    f"roleDefinitions/{PACKAGE_ADD_ROLE_DEFINITION_ID}"
)
PACKAGE_READ_ROLE_DEFINITION_RESOURCE = (
    f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/"
    f"roleDefinitions/{PACKAGE_READ_ROLE_DEFINITION_ID}"
)
LOCK_RESOURCE = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-paperdesk-rollback-sea-20260808/"
    "providers/Microsoft.Authorization/locks/paperdesk-rollback-cannot-delete"
)
LOCK_URL = f"{MGMT}{LOCK_RESOURCE}?api-version=2016-09-01"
LOCK_INVENTORY_URL = (
    f"{MGMT}/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/"
    "locks?api-version=2016-09-01"
)
STORAGE_URL = (
    f"{MGMT}/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-paperdesk-rollback-sea-20260808/"
    "providers/Microsoft.Storage/storageAccounts/mdspdbak2608089c4e?api-version=2025-06-01"
)
GUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
EXPECTED_LOCK_PROPERTIES = {
    "level": "CanNotDelete",
    "notes": (
        "Protects verified PaperDesk pre-migration attachment rollback copy; "
        "remove lock explicitly before authorized retirement."
    ),
}
EXPECTED_RECEIPT_HASHES = {
    'cloud-mutation-0001.json': '31e0d3a25e497dbdfd4236aac897f59c2b194fe1c027a8d1abd5368b95dd8076',
    'cloud-mutation-0002.json': '9b47968c6178305643c96998e2cb54c72409710e7f0a5fda5c373b20bd67dbe6',
    'cloud-mutation-0003.json': '0a3992d4f7af696245a974517b3c0fc3c1c10b95d803c2c5ce499ddf93bb82d5',
    'cloud-mutation-0004.json': '0c759da0ef5aa4aa6dc10af547bb6a526648b0da548144b51aa062ec3fbf510a',
    'cloud-mutation-0005.json': '973c2a3043da88f76f2760200c3768940f6b55d6bd32af9d2eee01cb70c49d86',
    'cloud-mutation-0006.json': '2a6dfc1882586d029538ed3702be46c7ea21fda97ad8e1566aa87624b62781a1',
    'cloud-mutation-0007.json': 'fbb141a942b5bb3727d3b1afe42955ec93657e0d058233b20e911eecdefb37ce',
    'cloud-mutation-0008.json': 'fc50eaaaccfb1e2ba904609783ec3f079110edb7cfc7ea65bd7c2f6c1c2d94f6',
    'cloud-mutation-0009.json': 'ace30f4c74b3a38cbac5457b7dc8fb8515bcf727d353d9d8526782b073a3e914',
    'cloud-mutation-0010.json': 'c1c26f54fd6586ef5ca5fcf3af2577c54878387365c66392d5e6725dc733c19d',
    'cloud-mutation-0011.json': '1622bf66ce439c96d55dbc2e0ed086b70d81d55d75ded8bf0df097948d50f4ba',
    'cloud-mutation-0012.json': '483d668da2a412d3599fbb8047e90653d360d904e0604277d47c10ecfee90e80',
    'cloud-mutation-0013.json': '226b47e6fc7c32a64f5d5c2ad71c04dca42d1c652d6893095177d8998488d506',
    'cloud-mutation-0014.json': 'e31e63613569db1dc74bb43d1adece13b77ed0ab8136b38386357a08bc693e25',
    'cloud-mutation-0015.json': '592eb6c2b43ce1565e7ece48873fcd8c3570a1c3a52d496683b97e6292e14f1c',
    'cloud-mutation-0016.json': '3fe66c264535dabb9da2c5e2bca70537c758dc2ecf6c2d98441ac6701536a086',
    'cloud-mutation-0017.json': '45f252b749662a7c6f1dbd848d1157a9a306b8db000c4e35b451dc06ec49503b',
    'cloud-mutation-0018.json': 'b54bc88a4cf73e2648a4d21e1b9628f346ee5387c55216291063a5a29163bf24',
    'cloud-mutation-0019.json': 'a279596a744d046a62de5f4cb437710564f9fa4e6c5865cd6507edbdebaa7123',
    'cloud-mutation-0020.json': '65fa99fa565292411e69d50ad137e9d216fefcfa5c74d8779b00e38b014834e6',
    'cloud-mutation-0021.json': 'f87a7df4e6a90b836fa9781edb1151c96e82ca142cfaa2ae556ab46445828784',
    'cloud-mutation-0022.json': 'cccdda8a23997c112bc8eb6833ae085172a56ccc20b24c7fa6adb9aa97125842',
    'cloud-mutation-0023.json': 'daa1b9e49602aa2e49d788ef0072ecd3071e079594b50a1b75fed60386a27bf7',
    'cloud-mutation-0024.json': '2553c4900303469528e33e86ddd0e19aa1610efd08b62d8ccaa9e8f53905ec6d',
    'cloud-mutation-0025.json': '9d07cb48eaa7db9b5cc0c5230c2e4190670fe2f8c94288a0fa434873e2a33f8d',
    'cloud-mutation-0026.json': '24d60121cb5ead89e033ee470077cb728aab76e5f0bd9d22a7265fd23886c55d',
    'cloud-mutation-0027.json': '37579fbf9e92df6013a051b7d07d048f9462643bdf228ee32ac12b946be9f038',
    'cloud-mutation-0028.json': '72e8e7e4315fa206fcfb578c55e8b39657ad719d8b301624fdd0fa65db992c6f',
    'cloud-mutation-0029.json': '2eea3f0de62f93b1b9c9a0a563ad19b4bd589ee19efc7927f529a8ffeadf5f13',
    'cloud-mutation-0030.json': 'a7c10481b0ce9913ba90eba975c65daec6e13352e786590005f030a759719d99',
    'cloud-mutation-0031.json': 'b88ba9d9aad5e22884f9832bca443be9369102f2668df52606083a9c442f3b6d',
    'cloud-mutation-0032.json': '3ad026311eed18339c594c721bfe9b2ad3f43263b0adc18369bc970e4aed4d80',
    'cloud-mutation-0033.json': '46e546cdbaeee0d8a5ee737e86acdb473796eb4c15fc35f6fcef51c4873c33c4',
    'cloud-mutation-0034.json': '270a2560a2b4b5d236eb7fad13a7b62de089a17316f87315862d46edcec21db3',
    'cloud-mutation-0035.json': '5c6a08baba0bd3994e24dbc74f83fe63f48f4b00bf453ae9b842b2295e309a02',
    'cloud-mutation-0036.json': 'f1344057f4f36d74c842bfe0951a86379c139b04fad91d93939513bfab251601',
    'cloud-mutation-0037.json': 'e3648f6a2e6393f8e9e3fa2a41a85477bba20678e2224833531340ce8b92c43d',
    'execution-terminal.json': '354736ce804263b56983855137a6b3e8c76862c11064d4a0ae5e4a7b5c9e50e1',
    'single-use-state.json': '359d830a3141c91a77d84c82829bfbb817f3b2fb22abf65daf9ff5a95da56da4',
}


def fail(message: str) -> None:
    raise RuntimeError(message)


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_new(path: Path, value: object) -> str:
    raw = canonical(value)
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return digest(raw)


def load_canonical(path: Path) -> tuple[dict, bytes]:
    if not path.is_file() or path.is_symlink():
        fail("canonical input is absent or unsafe")
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict) or raw != canonical(value):
        fail("canonical input bytes drifted")
    return value, raw


def git(*args: str) -> str:
    process = subprocess.run(
        ("git", *args), cwd=ROOT, text=True, encoding="utf-8",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    )
    if process.returncode:
        fail("trusted Git check failed")
    return process.stdout.strip()


def import_trusted_modules():
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    import private_release_v2_bootstrap as bootstrap  # pylint: disable=import-outside-toplevel
    import private_release_v2_cleanup_locks as cleanup_locks  # pylint: disable=import-outside-toplevel
    return bootstrap, cleanup_locks


def verify_local():
    if sys.flags.optimize:
        fail("optimized Python is forbidden")
    if git("status", "--porcelain=v1") or git("symbolic-ref", "--short", "HEAD") != "main":
        fail("trusted checkout is not clean main")
    if git("rev-parse", "HEAD") != SOURCE_SHA or git("rev-parse", "refs/remotes/origin/main") != SOURCE_SHA:
        fail("trusted source moved")
    expected_files = {
        ROOT / "scripts/private_release_v2_bootstrap.py": EXECUTOR_SHA256,
        ROOT / "scripts/private_release_v2_bootstrap_observe.py": OBSERVER_SHA256,
        ROOT / "scripts/private_release_v2_cleanup_locks.py": CLEANUP_LOCKS_SHA256,
        ROOT / "contracts/private_release_bootstrap_plan.json": PLAN_SHA256,
        CEREMONY / f"observation-{INCIDENT_ID}-refresh-2" / "bootstrap-authorization.json": INCIDENT_AUTH_SHA256,
        CEREMONY / f"source-pr88-{SOURCE_SHA}.json": SOURCE_EVIDENCE_SHA256,
    }
    for path, expected in expected_files.items():
        if not path.is_file() or path.is_symlink() or digest(path.read_bytes()) != expected:
            fail(f"trusted input moved: {path.name}")
    auth, _ = load_canonical(CEREMONY / f"observation-{INCIDENT_ID}-refresh-2" / "bootstrap-authorization.json")
    if (
        auth.get("authorizationId") != INCIDENT_ID
        or auth.get("source", {}).get("mergedMain", {}).get("commitSha") != SOURCE_SHA
        or auth.get("azure", {}).get("subscriptionId") != SUBSCRIPTION
        or auth.get("azure", {}).get("tenantId") != TENANT
        or auth.get("azure", {}).get("accountObjectId") != ACCOUNT_OBJECT_ID
        or auth.get("plan", {}).get("sha256") != PLAN_SHA256
        or auth.get("plan", {}).get("bridgePackageSha256") != PACKAGE_SHA256
    ):
        fail("incident authorization projection drifted")
    receipt = CEREMONY / f"paperdesk-private-release-v2-bootstrap-{INCIDENT_ID}"
    if not receipt.is_dir() or receipt.is_symlink():
        fail("incident receipt directory is unsafe")
    docs = {}
    for name, expected in EXPECTED_RECEIPT_HASHES.items():
        path = receipt / name
        if not path.is_file() or path.is_symlink() or digest(path.read_bytes()) != expected:
            fail(f"incident receipt drifted: {name}")
        docs[name] = json.loads(path.read_text(encoding="utf-8"))
    def bound(number, phase, method, url, status=None):
        item = docs[f"cloud-mutation-{number:04d}.json"]
        if item.get("phase") != phase or item.get("method") != method or item.get("targetUrl") != url:
            fail("incident mutation journal binding drifted")
        if status is not None and item.get("status") != status:
            fail("incident mutation journal status drifted")
        return item
    add = bound(25, "intent", "PUT", PACKAGE_ADD_ASSIGNMENT_URL)
    bound(26, "result", "PUT", PACKAGE_ADD_ASSIGNMENT_URL, 201)
    read = bound(27, "intent", "PUT", PACKAGE_READ_ASSIGNMENT_URL)
    bound(28, "result", "PUT", PACKAGE_READ_ASSIGNMENT_URL, 201)
    upload = docs["cloud-mutation-0029.json"]
    uploaded = docs["cloud-mutation-0030.json"]
    bound(31, "intent", "DELETE", LOCK_URL)
    bound(32, "result", "DELETE", LOCK_URL, 200)
    bound(33, "intent", "DELETE", PACKAGE_ADD_ASSIGNMENT_URL)
    bound(34, "intent", "PUT", LOCK_URL)
    bound(35, "result", "PUT", LOCK_URL, 201)
    bound(36, "intent", "PATCH", STORAGE_URL)
    bound(37, "result", "PATCH", STORAGE_URL, 200)
    terminal = docs["execution-terminal.json"]
    if (
        add.get("requestBodySha256") != expected_assignment_body_sha256("packageAdd")
        or read.get("requestBodySha256") != expected_assignment_body_sha256("packageRead")
        or upload.get("phase") != "intent" or upload.get("method") != "PUT"
        or upload.get("requestBodySha256") != PACKAGE_SHA256
        or uploaded.get("phase") != "result" or uploaded.get("status") != 201
        or uploaded.get("targetUrl") != upload.get("targetUrl")
        or terminal.get("status") != "failed" or terminal.get("consumed") is not True
        or terminal.get("failureType") != "_MutationOwnershipAmbiguity"
        or not any(x.get("operationId") == "addOwnedUploaderPackageRole" and x.get("status") == "cleanup-failed" for x in terminal.get("temporaryCleanup", []))
        or not any(x.get("operationId") == "addOwnedUploaderIpv4Rule" and x.get("status") == "removed-exact" for x in terminal.get("temporaryCleanup", []))
        or {p.name for p in receipt.glob("cloud-mutation-*.json")} != {n for n in EXPECTED_RECEIPT_HASHES if n.startswith("cloud-mutation-")}
    ):
        fail("incident ownership receipts are not exact")



def assignment_spec(name: str) -> dict:
    specs = {
        "packageAdd": {
            "id": PACKAGE_ADD_ASSIGNMENT_ID,
            "resource": PACKAGE_ADD_ASSIGNMENT_RESOURCE,
            "url": PACKAGE_ADD_ASSIGNMENT_URL,
            "roleDefinitionId": PACKAGE_ADD_ROLE_DEFINITION_ID,
            "roleDefinitionResource": PACKAGE_ADD_ROLE_DEFINITION_RESOURCE,
        },
        "packageRead": {
            "id": PACKAGE_READ_ASSIGNMENT_ID,
            "resource": PACKAGE_READ_ASSIGNMENT_RESOURCE,
            "url": PACKAGE_READ_ASSIGNMENT_URL,
            "roleDefinitionId": PACKAGE_READ_ROLE_DEFINITION_ID,
            "roleDefinitionResource": PACKAGE_READ_ROLE_DEFINITION_RESOURCE,
        },
    }
    try:
        return specs[name]
    except KeyError:
        fail("package assignment name is invalid")


def expected_assignment_body(name: str) -> dict:
    spec = assignment_spec(name)
    marker = f"paperdesk-private-release-v2-temporary:{INCIDENT_ID}:uploader-package-role"
    return {
        "properties": {
            "principalId": ACCOUNT_OBJECT_ID,
            "principalType": "User",
            "roleDefinitionId": spec["roleDefinitionResource"],
            "description": marker,
        }
    }


def expected_assignment_body_sha256(name: str) -> str:
    return digest(canonical(expected_assignment_body(name)))


def expected_assignment_projection(name: str) -> dict:
    spec = assignment_spec(name)
    properties = expected_assignment_body(name)["properties"]
    return {
        "id": spec["resource"],
        "name": spec["id"],
        "type": "Microsoft.Authorization/roleAssignments",
        "properties": {
            "principalId": properties["principalId"],
            "principalType": properties["principalType"],
            "roleDefinitionId": properties["roleDefinitionId"],
            "scope": SCOPE,
            "condition": None,
            "conditionVersion": None,
            "delegatedManagedIdentityResourceId": None,
            "description": properties["description"],
        },
    }


def expected_storage() -> dict:
    return {
        "bypass": "None",
        "defaultAction": "Deny",
        "ipRules": [],
        "ipv6Rules": [],
        "resourceAccessRules": [],
        "virtualNetworkRules": [
            {
                "action": "Allow",
                "id": (
                    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-master-data-structure-sea/"
                    "providers/Microsoft.Network/virtualNetworks/vnet-master-data-structure-sea/"
                    "subnets/snet-appservice-integration"
                ),
                "state": "Succeeded",
            }
        ],
    }


def bound_plan(bootstrap) -> dict:
    plan = json.loads((ROOT / "contracts/private_release_bootstrap_plan.json").read_text(encoding="utf-8"))
    return bootstrap.bind_temporary_role_ids(plan, INCIDENT_ID)


def other_temporary_assignment_urls(bootstrap) -> tuple[str, ...]:
    plan = bound_plan(bootstrap)
    temporary = plan["temporaryAccess"]
    values = (
        (bootstrap._resource_scope_from_plan(plan, "signingKey"), temporary["temporaryKeyReadRoleAssignmentId"]),
        (bootstrap._resource_scope_from_plan(plan, "controllerLockContainer"), temporary["temporaryControllerRoleAssignmentId"]),
        (bootstrap._resource_scope_from_plan(plan, "activationFenceContainer"), temporary["temporaryFenceRoleAssignmentId"]),
    )
    return tuple(
        f"{MGMT}{scope}/providers/Microsoft.Authorization/roleAssignments/{assignment_id}?api-version=2022-04-01"
        for scope, assignment_id in values
    )


def token() -> str:
    az = shutil.which("az.cmd") or shutil.which("az")
    if not az:
        fail("Azure CLI is unavailable")
    process = subprocess.run(
        (az, "account", "get-access-token", "--resource", f"{MGMT}/", "--query", "accessToken", "-o", "tsv"),
        text=True, encoding="utf-8", stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    )
    if process.returncode or not process.stdout.strip():
        fail("Azure token acquisition failed")
    return process.stdout.strip()


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    headers: dict[str, str]


def http(method: str, url: str, *, bearer: str, body: bytes | None = None, timeout: float = 30.0) -> Response:
    headers = {"Authorization": "Bearer " + bearer, "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return Response(response.status, response.read(), dict(response.headers))
    except urllib.error.HTTPError as exc:
        return Response(exc.code, exc.read(), dict(exc.headers))


def read_request(bearer: str, method: str, url: str, *, deadline: dt.datetime | None = None) -> Response:
    if method != "GET":
        fail("read path attempted a non-GET request")
    last_error = None
    for attempt in range(3):
        now = dt.datetime.now(dt.timezone.utc)
        if deadline is not None and now >= deadline:
            fail("read deadline expired")
        timeout = 30.0 if deadline is None else min(30.0, max(0.5, (deadline - now).total_seconds()))
        try:
            return http("GET", url, bearer=bearer, timeout=timeout)
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            last_error = type(exc).__name__
            if attempt < 2:
                time.sleep(2)
    fail(f"Azure read transport failed closed: {last_error}")


def json_object(response: Response, expected: set[int], label: str) -> dict:
    if response.status not in expected:
        fail(f"{label} returned unexpected HTTP {response.status}")
    try:
        value = json.loads(response.body)
    except (ValueError, TypeError, UnicodeError):
        fail(f"{label} returned invalid JSON")
    if not isinstance(value, dict):
        fail(f"{label} did not return one object")
    return value


def project_assignment(bootstrap, document: dict, expected_resource: str) -> dict:
    projected = bootstrap._project_role_assignment(document)
    raw_id = projected.get("id")
    if (
        not isinstance(raw_id, str)
        or raw_id.lower() != expected_resource.lower()
    ):
        fail("assignment resource ID drifted")
    properties = document.get("properties")
    if not isinstance(properties, dict):
        fail("assignment properties are absent")
    projected["properties"]["description"] = properties.get("description")
    projected["id"] = expected_resource
    return projected


def run_recovery_core(
    bootstrap,
    cleanup_locks,
    *,
    cleanup_read,
    mutate,
    require_exact_inventory,
    require_exact_lock,
    final_state_reader,
) -> tuple[dict, dict]:
    """Run the exact two-target sequence with injected transport and proof hooks."""

    require_exact_inventory()
    require_exact_lock()
    for name in ("packageAdd", "packageRead"):
        spec = assignment_spec(name)
        target_before = json_object(
            cleanup_read("GET", spec["url"]),
            {200},
            f"{name} target assignment prestate",
        )
        if (
            project_assignment(bootstrap, target_before, spec["resource"])
            != expected_assignment_projection(name)
        ):
            fail(f"{name} target assignment prestate drifted")
    try:
        mutate("DELETE", LOCK_URL, expected={200, 204})
        if cleanup_read("GET", LOCK_URL).status != 404:
            fail("rollback cleanup lock deletion did not converge")
        for name in ("packageAdd", "packageRead"):
            spec = assignment_spec(name)
            target_after_lock = json_object(
                cleanup_read("GET", spec["url"]),
                {200},
                f"{name} target assignment after lock suspension",
            )
            if (
                project_assignment(bootstrap, target_after_lock, spec["resource"])
                != expected_assignment_projection(name)
            ):
                fail(f"{name} target assignment drifted after lock suspension")
            mutate("DELETE", spec["url"], expected={200, 204})
            if cleanup_read("GET", spec["url"]).status != 404:
                fail(f"{name} target assignment deletion did not converge")
    finally:
        current_lock = cleanup_read("GET", LOCK_URL)
        if current_lock.status == 404:
            mutate(
                "PUT",
                LOCK_URL,
                body=canonical({"properties": EXPECTED_LOCK_PROPERTIES}),
                expected={200, 201},
                restore=True,
            )
        elif current_lock.status == 200:
            cleanup_locks.validate_lock_document(
                json_object(current_lock, {200}, "rollback cleanup lock"),
                cleanup_locks.REVIEWED_CLEANUP_LOCKS["rollback"],
                fail,
            )
        else:
            fail("rollback cleanup lock is absent, unreadable, or third-state")
        require_exact_lock()
    final_state = final_state_reader()
    proof = {
        "operationId": RECOVERY_OPERATION_ID,
        "assignmentsAbsent": {
            "packageAdd": True,
            "packageRead": True,
        },
        "lockRestored": True,
        "lockResourceId": LOCK_RESOURCE,
    }
    return final_state, proof


def selftest() -> None:
    bootstrap, cleanup_locks = import_trusted_modules()
    for name in ("packageAdd", "packageRead"):
        spec = assignment_spec(name)
        wrong = copy.deepcopy(expected_assignment_projection(name))
        wrong["id"] = SCOPE + "/providers/Microsoft.Authorization/roleAssignments/00000000-0000-4000-8000-000000000000"
        try:
            project_assignment(bootstrap, wrong, spec["resource"])
        except RuntimeError as exc:
            if str(exc) != "assignment resource ID drifted":
                raise
        else:
            fail("wrong raw assignment ID was not rejected")
        exact = project_assignment(
            bootstrap, copy.deepcopy(expected_assignment_projection(name)), spec["resource"]
        )
        if exact != expected_assignment_projection(name):
            fail("exact assignment projection self-test drifted")

    def exercise(*, failure_target=None, failure_mode=None, drift_phase=None):
        state = {
            "lock": True,
            "packageAdd": True,
            "packageRead": True,
            "afterLockReads": 0,
        }
        mutations = []
        journal = []
        final_calls = []

        def exact_lock_document():
            return {
                "id": LOCK_RESOURCE,
                "name": "paperdesk-rollback-cannot-delete",
                "type": "Microsoft.Authorization/locks",
                "properties": copy.deepcopy(EXPECTED_LOCK_PROPERTIES),
            }

        def fake_read(method: str, url: str, *, deadline=None):
            del deadline
            if method != "GET":
                fail("self-test read attempted mutation")
            if url == LOCK_URL:
                return Response(200, canonical(exact_lock_document()), {}) if state["lock"] else Response(404, b"", {})
            for name in ("packageAdd", "packageRead"):
                spec = assignment_spec(name)
                if url == spec["url"]:
                    if not state[name]:
                        return Response(404, b"", {})
                    value = copy.deepcopy(expected_assignment_projection(name))
                    if drift_phase == f"before:{name}" and state["lock"]:
                        value["properties"]["description"] = "third-state"
                    if drift_phase == f"after:{name}" and not state["lock"]:
                        value["properties"]["description"] = "third-state"
                    if not state["lock"]:
                        state["afterLockReads"] += 1
                    return Response(200, canonical(value), {})
            fail("self-test read URL is not allowed")

        def fake_mutate(method: str, url: str, *, body=None, expected, restore=False):
            del expected
            target = None
            if method == "DELETE" and url == LOCK_URL:
                target = "lock"
            elif method == "PUT" and url == LOCK_URL and restore:
                target = "restore"
            else:
                for name in ("packageAdd", "packageRead"):
                    if method == "DELETE" and url == assignment_spec(name)["url"]:
                        target = name
                        break
            if target is None:
                fail("self-test mutation escaped exact allowlist")
            if failure_mode == "expiry" and target == failure_target:
                raise RuntimeError("recovery authorization expired before a DELETE")
            mutations.append((method, url))
            journal.append(("intent", method, url))
            if target == failure_target and failure_mode == "transport":
                raise TimeoutError("simulated transport ambiguity")
            if target == failure_target and failure_mode == "status":
                journal.append(("result-500", method, url))
                raise RuntimeError("simulated unexpected status")
            if target == "lock":
                if body is not None or not state["lock"]:
                    fail("self-test lock delete drifted")
                state["lock"] = False
            elif target == "restore":
                if body != canonical({"properties": EXPECTED_LOCK_PROPERTIES}) or state["lock"]:
                    fail("self-test lock restoration drifted")
                state["lock"] = True
            else:
                if body is not None or not state[target]:
                    fail("self-test assignment delete drifted")
                state[target] = False
            journal.append(("result", method, url))
            return Response(201 if target == "restore" else 200, b"", {})

        def require_inventory():
            return bootstrap._expected_cleanup_lock_inventory()

        def require_lock():
            if not state["lock"]:
                fail("self-test exact lock absent")
            return exact_lock_document()

        def final_reader():
            if state["packageAdd"] or state["packageRead"] or not state["lock"]:
                fail("self-test final state is incomplete")
            final_calls.append(True)
            return expected_live_state("absent")

        outcome = None
        error = None
        try:
            outcome = run_recovery_core(
                bootstrap,
                cleanup_locks,
                cleanup_read=fake_read,
                mutate=fake_mutate,
                require_exact_inventory=require_inventory,
                require_exact_lock=require_lock,
                final_state_reader=final_reader,
            )
        except BaseException as exc:  # expected failure matrix is asserted below
            error = exc
        return state, mutations, journal, final_calls, outcome, error

    lock_delete = ("DELETE", LOCK_URL)
    add_delete = ("DELETE", PACKAGE_ADD_ASSIGNMENT_URL)
    read_delete = ("DELETE", PACKAGE_READ_ASSIGNMENT_URL)
    lock_restore = ("PUT", LOCK_URL)
    expected_mutations = [lock_delete, add_delete, read_delete, lock_restore]

    state, mutations, journal, final_calls, outcome, error = exercise()
    if error is not None or mutations != expected_mutations or len(journal) != 8:
        fail("two-target success sequence self-test drifted")
    if state != {"lock": True, "packageAdd": False, "packageRead": False, "afterLockReads": 2}:
        fail("two-target success state self-test drifted")
    if final_calls != [True] or outcome is None or outcome[1]["assignmentsAbsent"] != {"packageAdd": True, "packageRead": True}:
        fail("two-target terminal proof self-test drifted")

    for target, prefix in (("packageAdd", [lock_delete, add_delete]), ("packageRead", [lock_delete, add_delete, read_delete])):
        for mode in ("transport", "status"):
            state, mutations, journal, final_calls, outcome, error = exercise(
                failure_target=target, failure_mode=mode
            )
            if error is None or mutations != prefix + [lock_restore]:
                fail(f"{target} {mode} failure sequence self-test drifted")
            if mutations.count(prefix[-1]) != 1 or mutations.count(lock_restore) != 1:
                fail(f"{target} {mode} replay/restoration self-test drifted")
            if target == "packageAdd" and read_delete in mutations:
                fail("second target mutated after first-target failure")
            if not state["lock"] or final_calls or outcome is not None:
                fail(f"{target} {mode} failure proof self-test drifted")

    state, mutations, journal, final_calls, outcome, error = exercise(
        failure_target="packageRead", failure_mode="expiry"
    )
    if error is None or mutations != [lock_delete, add_delete, lock_restore] or read_delete in mutations:
        fail("between-target expiry self-test drifted")
    if not state["lock"] or final_calls or outcome is not None:
        fail("between-target expiry restoration self-test drifted")

    state, mutations, journal, final_calls, outcome, error = exercise(drift_phase="before:packageAdd")
    if error is None or mutations or not state["lock"] or final_calls or outcome is not None:
        fail("pre-lock third-state self-test drifted")
    state, mutations, journal, final_calls, outcome, error = exercise(drift_phase="after:packageRead")
    if error is None or mutations != [lock_delete, add_delete, lock_restore]:
        fail("post-lock third-state sequence self-test drifted")
    if not state["lock"] or not state["packageRead"] or final_calls or outcome is not None:
        fail("post-lock third-state restoration self-test drifted")
    print(json.dumps({"status": "selftest-passed", "azureMutationPerformed": False}, sort_keys=True))


def live_state(bearer: str, *, target_state: str) -> dict:
    bootstrap, cleanup_locks = import_trusted_modules()
    plan = bound_plan(bootstrap)
    targets = {}
    for name in ("packageAdd", "packageRead"):
        spec = assignment_spec(name)
        assignment_response = read_request(bearer, "GET", spec["url"])
        assignment_projection = None
        if assignment_response.status == 200:
            assignment_projection = project_assignment(
                bootstrap,
                json_object(assignment_response, {200}, f"{name} target assignment"),
                spec["resource"],
            )
            observed_target = (
                "exact"
                if assignment_projection == expected_assignment_projection(name)
                else "third-state"
            )
        elif assignment_response.status == 404:
            observed_target = "absent"
        else:
            fail(f"{name} target assignment read failed closed")
        if observed_target != target_state:
            fail(f"{name} target assignment is {observed_target}, expected {target_state}")
        targets[name] = {"state": observed_target, "projection": assignment_projection}

    related = {}
    for url in other_temporary_assignment_urls(bootstrap):
        response = read_request(bearer, "GET", url)
        if response.status != 404:
            fail("another incident temporary assignment is present or unreadable")
        related[url] = "absent"

    definition_hashes = {}
    stable_specs = {spec["name"]: spec for spec in bootstrap._stable_package_role_specs(plan)}
    if set(stable_specs) != {"packageAdd", "packageRead"}:
        fail("target stable package role definition specs drifted")
    for name in ("packageAdd", "packageRead"):
        spec = assignment_spec(name)
        expected_definition = stable_specs[name]["definitionProjection"]
        definition = json_object(
            read_request(
                bearer,
                "GET",
                f"{MGMT}{spec['roleDefinitionResource']}?api-version=2022-04-01",
            ),
            {200},
            f"target {name} role definition",
        )
        if bootstrap._project_role_definition(definition) != expected_definition:
            fail(f"target {name} role definition drifted")
        definition_hashes[name] = digest(canonical(expected_definition))

    key_definition_id = plan["temporaryAccess"]["temporaryKeyReadRoleDefinitionId"]
    key_definition_url = (
        f"{MGMT}/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/"
        f"roleDefinitions/{key_definition_id}?api-version=2022-04-01"
    )
    if read_request(bearer, "GET", key_definition_url).status != 404:
        fail("incident temporary key role definition is present or unreadable")

    storage_document = json_object(
        read_request(bearer, "GET", STORAGE_URL), {200}, "Storage baseline"
    )
    acls = storage_document.get("properties", {}).get("networkAcls", {})
    storage = {
        "bypass": acls.get("bypass"),
        "defaultAction": acls.get("defaultAction"),
        "ipRules": acls.get("ipRules", []),
        "ipv6Rules": acls.get("ipv6Rules", []),
        "resourceAccessRules": acls.get("resourceAccessRules", []),
        "virtualNetworkRules": acls.get("virtualNetworkRules", []),
    }
    if storage != expected_storage():
        fail("Storage network baseline drifted")

    inventory_document = json_object(
        read_request(bearer, "GET", LOCK_INVENTORY_URL), {200}, "cleanup lock inventory"
    )
    lock_inventory = bootstrap._cleanup_lock_inventory_projection(inventory_document, plan)
    locks = {}
    for key, spec in cleanup_locks.REVIEWED_CLEANUP_LOCKS.items():
        url = f"{MGMT}{spec['resourceId']}?api-version=2016-09-01"
        document = json_object(read_request(bearer, "GET", url), {200}, f"{key} lock")
        cleanup_locks.validate_lock_document(document, spec, fail)
        locks[url] = "exact"
    return {
        "targetAssignments": targets,
        "otherIncidentTemporaryAssignments": related,
        "targetStablePackageRoleDefinitionSha256": definition_hashes,
        "temporaryKeyRoleDefinition": "absent",
        "storageNetworkAcls": storage,
        "cleanupLockInventory": lock_inventory,
        "locks": locks,
    }


def expected_live_state(target_state: str) -> dict:
    bootstrap, cleanup_locks = import_trusted_modules()
    plan = bound_plan(bootstrap)
    stable_specs = {spec["name"]: spec for spec in bootstrap._stable_package_role_specs(plan)}
    if set(stable_specs) != {"packageAdd", "packageRead"}:
        fail("target stable package role definition specs drifted")
    locks = {
        f"{MGMT}{spec['resourceId']}?api-version=2016-09-01": "exact"
        for spec in cleanup_locks.REVIEWED_CLEANUP_LOCKS.values()
    }
    return {
        "targetAssignments": {
            name: {
                "state": target_state,
                "projection": expected_assignment_projection(name) if target_state == "exact" else None,
            }
            for name in ("packageAdd", "packageRead")
        },
        "otherIncidentTemporaryAssignments": {
            url: "absent" for url in other_temporary_assignment_urls(bootstrap)
        },
        "targetStablePackageRoleDefinitionSha256": {
            name: digest(canonical(stable_specs[name]["definitionProjection"]))
            for name in ("packageAdd", "packageRead")
        },
        "temporaryKeyRoleDefinition": "absent",
        "storageNetworkAcls": expected_storage(),
        "cleanupLockInventory": bootstrap._expected_cleanup_lock_inventory(),
        "locks": locks,
    }


def validate_preflight(identifier: str, preflight: dict, raw: bytes, wrapper_sha: str):
    expected_keys = {
        "schemaVersion", "executable", "authorizationId", "incidentAuthorizationId",
        "incidentAuthorizationSha256", "sourceSha", "executorSha256", "observerSha256",
        "cleanupLocksSha256", "planSha256", "packageSha256", "wrapperSha256",
        "targetUrls", "targetAssignmentProjectionSha256", "lockUrl", "lockPropertiesSha256",
        "observedAt", "freshnessDeadline", "liveState", "azureMutationPerformed",
    }
    if set(preflight) != expected_keys:
        fail("recovery preflight schema drifted")
    fixed = {
        "schemaVersion": 1,
        "executable": False,
        "authorizationId": identifier,
        "incidentAuthorizationId": INCIDENT_ID,
        "incidentAuthorizationSha256": INCIDENT_AUTH_SHA256,
        "sourceSha": SOURCE_SHA,
        "executorSha256": EXECUTOR_SHA256,
        "observerSha256": OBSERVER_SHA256,
        "cleanupLocksSha256": CLEANUP_LOCKS_SHA256,
        "planSha256": PLAN_SHA256,
        "packageSha256": PACKAGE_SHA256,
        "wrapperSha256": wrapper_sha,
        "targetUrls": {
            name: assignment_spec(name)["url"] for name in ("packageAdd", "packageRead")
        },
        "targetAssignmentProjectionSha256": {
            name: digest(canonical(expected_assignment_projection(name)))
            for name in ("packageAdd", "packageRead")
        },
        "lockUrl": LOCK_URL,
        "lockPropertiesSha256": digest(canonical(EXPECTED_LOCK_PROPERTIES)),
        "azureMutationPerformed": False,
    }
    if any(preflight.get(key) != value for key, value in fixed.items()):
        fail("recovery preflight fixed binding drifted")
    observed = dt.datetime.fromisoformat(preflight["observedAt"])
    deadline = dt.datetime.fromisoformat(preflight["freshnessDeadline"])
    if observed.tzinfo is None or deadline != observed + dt.timedelta(minutes=30):
        fail("recovery freshness interval drifted")
    if preflight["liveState"] != expected_live_state("exact"):
        fail("reviewed recovery live state drifted")
    if raw != canonical(preflight):
        fail("recovery preflight is not canonical")
    return observed, deadline, digest(raw)


def phrase(preflight: dict, preflight_sha: str) -> str:
    return (
        f"Authorize Azure temporary package role-assignment recovery under authorization {preflight['authorizationId']}: "
        f"Authorize the separately reviewed source-bound cleanup of only role assignments {PACKAGE_ADD_ASSIGNMENT_ID} and {PACKAGE_READ_ASSIGNMENT_ID} left by incident {INCIDENT_ID}, source {SOURCE_SHA}, wrapper SHA-256 {preflight['wrapperSha256']}, cleanup-lock module SHA-256 {CLEANUP_LOCKS_SHA256}, preflight SHA-256 {preflight_sha}, observed at {preflight['observedAt']}, and expiring at {preflight['freshnessDeadline']}. "
        f"I authorize temporary removal and exact restoration of only the reviewed CanNotDelete lock {LOCK_RESOURCE} solely around one DELETE of each exact assignment {PACKAGE_ADD_ASSIGNMENT_RESOURCE} and {PACKAGE_READ_ASSIGNMENT_RESOURCE}. "
        "I accept that Azure exposes no supported conditional ETag for these DELETEs and that lock updates have no atomic concurrency guard, so an out-of-band administrator change cannot be atomically excluded. The executor must issue each DELETE at most once without retry, must issue at most one exact lock-restoration PUT, and must never deliberately overwrite a third state. "
        "Definite success requires a fresh 404 for both target assignments, all three other incident temporary assignments absent, the incident temporary key role definition absent, both stable package role definitions exact, the restrictive Storage network baseline exact, and all three reviewed CanNotDelete locks present and exact. "
        "I accept that ambiguous transport, process death, or local journal/fsync failure after intent can leave either assignment present or deletion protection absent; execution and any later bootstrap must stop until fresh reads prove the exact final state, and manual cleanup may be required. "
        "I authorize no account, identity, role-definition, other assignment, other lock, Storage, bridge, package, production, fence, retention, or legacy-resource mutation."
    )


def observe() -> None:
    verify_local()
    identifier = str(uuid.uuid4())
    wrapper_sha = digest(Path(__file__).read_bytes())
    observed = dt.datetime.now(dt.timezone.utc)
    state = live_state(token(), target_state="exact")
    preflight = {
        "schemaVersion": 1,
        "executable": False,
        "authorizationId": identifier,
        "incidentAuthorizationId": INCIDENT_ID,
        "incidentAuthorizationSha256": INCIDENT_AUTH_SHA256,
        "sourceSha": SOURCE_SHA,
        "executorSha256": EXECUTOR_SHA256,
        "observerSha256": OBSERVER_SHA256,
        "cleanupLocksSha256": CLEANUP_LOCKS_SHA256,
        "planSha256": PLAN_SHA256,
        "packageSha256": PACKAGE_SHA256,
        "wrapperSha256": wrapper_sha,
        "targetUrls": {
            name: assignment_spec(name)["url"] for name in ("packageAdd", "packageRead")
        },
        "targetAssignmentProjectionSha256": {
            name: digest(canonical(expected_assignment_projection(name)))
            for name in ("packageAdd", "packageRead")
        },
        "lockUrl": LOCK_URL,
        "lockPropertiesSha256": digest(canonical(EXPECTED_LOCK_PROPERTIES)),
        "observedAt": observed.isoformat(),
        "freshnessDeadline": (observed + dt.timedelta(minutes=30)).isoformat(),
        "liveState": state,
        "azureMutationPerformed": False,
    }
    path = CEREMONY / f"temp-package-assignments-recovery-preflight-{identifier}.json"
    sha = write_new(path, preflight)
    print(json.dumps({
        "status": "observed-read-only-non-executable",
        "authorizationId": identifier,
        "preflight": str(path),
        "preflightSha256": sha,
        "freshnessDeadline": preflight["freshnessDeadline"],
    }, sort_keys=True))


def request_confirmation(identifier: str) -> None:
    verify_local()
    if not GUID4.fullmatch(identifier):
        fail("authorization ID is invalid")
    preflight, raw = load_canonical(
        CEREMONY / f"temp-package-assignments-recovery-preflight-{identifier}.json"
    )
    _, deadline, preflight_sha = validate_preflight(
        identifier, preflight, raw, digest(Path(__file__).read_bytes())
    )
    if dt.datetime.now(dt.timezone.utc) >= deadline:
        fail("recovery preflight is stale")
    value = phrase(preflight, preflight_sha)
    output = REPORTS / f"TEMP-PACKAGE-ASSIGNMENTS-RECOVERY-CONFIRMATION-{identifier}.txt"
    with output.open("x", encoding="utf-8", newline="") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({
        "status": "awaiting-user-authorization",
        "authorizationId": identifier,
        "confirmationRequestPath": str(output),
        "phraseSha256": digest(value.encode("utf-8")),
        "preflightSha256": preflight_sha,
        "freshnessDeadline": preflight["freshnessDeadline"],
    }, sort_keys=True))


def apply(identifier: str) -> None:
    verify_local()
    if not GUID4.fullmatch(identifier):
        fail("authorization ID is invalid")
    wrapper_sha = digest(Path(__file__).read_bytes())
    preflight, preflight_raw = load_canonical(
        CEREMONY / f"temp-package-assignments-recovery-preflight-{identifier}.json"
    )
    _, deadline, preflight_sha = validate_preflight(
        identifier, preflight, preflight_raw, wrapper_sha
    )
    now = dt.datetime.now(dt.timezone.utc)
    if now >= deadline:
        fail("recovery preflight is stale")
    confirmation_path = CEREMONY / f"temp-package-assignments-recovery-confirmation-{identifier}.txt"
    if not confirmation_path.is_file() or confirmation_path.is_symlink():
        fail("exact user confirmation is absent")
    confirmation_raw = confirmation_path.read_bytes()
    if (
        confirmation_raw.endswith((b"\r", b"\n"))
        or confirmation_raw.decode("utf-8") != phrase(preflight, preflight_sha)
    ):
        fail("user confirmation is not exact")
    result_dir = CEREMONY / f"paperdesk-private-release-v2-temp-package-assignments-recovery-{identifier}"
    if result_dir.exists() or result_dir.is_symlink():
        fail("one-use recovery ledger already exists")
    bearer = token()
    final_prestate = live_state(bearer, target_state="exact")
    if (deadline - dt.datetime.now(dt.timezone.utc)).total_seconds() < 120:
        fail("insufficient authorization lifetime remains before durable intent")
    result_dir.mkdir()
    write_new(result_dir / "single-use-state.json", {
        "schemaVersion": 1,
        "authorizationId": identifier,
        "status": "consumed-before-mutation",
        "recordedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "preflightSha256": preflight_sha,
        "confirmationSha256": digest(confirmation_raw),
        "wrapperSha256": wrapper_sha,
        "prestateSha256": digest(canonical(final_prestate)),
    })

    bootstrap, cleanup_locks = import_trusted_modules()
    sequence = 0
    issued: set[tuple[str, str]] = set()

    def require_live_authorization() -> None:
        if dt.datetime.now(dt.timezone.utc) >= deadline:
            fail("recovery authorization expired before a DELETE")

    def mutate(method: str, url: str, *, body=None, expected, restore=False):
        nonlocal sequence
        allowed = {
            ("DELETE", LOCK_URL),
            ("DELETE", PACKAGE_ADD_ASSIGNMENT_URL),
            ("DELETE", PACKAGE_READ_ASSIGNMENT_URL),
            ("PUT", LOCK_URL),
        }
        if (method, url) not in allowed:
            fail("recovery attempted an unrelated mutation")
        if restore:
            exact_body = canonical({"properties": EXPECTED_LOCK_PROPERTIES})
            if method != "PUT" or url != LOCK_URL or body != exact_body:
                fail("lock restoration is not the exact reviewed map")
        else:
            require_live_authorization()
            if body is not None:
                fail("recovery DELETE unexpectedly has a body")
        if (method, url) in issued:
            fail("recovery attempted to replay a mutation")
        issued.add((method, url))
        sequence += 1
        intent_name = f"cloud-mutation-{sequence:04d}"
        intent = {
            "schemaVersion": 1,
            "sequence": sequence,
            "phase": "intent",
            "authorizationId": identifier,
            "incidentAuthorizationId": INCIDENT_ID,
            "operationId": RECOVERY_OPERATION_ID,
            "method": method,
            "targetUrl": url,
            "requestBodySha256": digest(body or b""),
            "restore": bool(restore),
            "recordedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
        write_new(result_dir / f"{intent_name}.json", intent)
        response = http(method, url, bearer=bearer, body=body, timeout=30)
        if response.status not in expected:
            fail(f"recovery mutation returned unexpected HTTP {response.status}")
        sequence += 1
        write_new(result_dir / f"cloud-mutation-{sequence:04d}.json", {
            **intent,
            "sequence": sequence,
            "phase": "result",
            "intentId": intent_name,
            "status": response.status,
            "responseBodySha256": digest(response.body),
            "recordedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        })
        return response

    def cleanup_read(method: str, url: str, *, deadline=None):
        return read_request(bearer, method, url, deadline=deadline)

    def require_exact_lock() -> dict:
        spec = cleanup_locks.REVIEWED_CLEANUP_LOCKS["rollback"]
        document = json_object(
            cleanup_read("GET", LOCK_URL), {200}, "rollback cleanup lock"
        )
        cleanup_locks.validate_lock_document(document, spec, fail)
        return document

    def require_exact_inventory() -> dict:
        document = json_object(
            cleanup_read("GET", LOCK_INVENTORY_URL), {200}, "cleanup lock inventory"
        )
        projected = bootstrap._cleanup_lock_inventory_projection(
            document, bound_plan(bootstrap)
        )
        if projected != bootstrap._expected_cleanup_lock_inventory():
            fail("cleanup lock inventory drifted")
        return projected

    terminal_status = "failed"
    error_type = None
    final_state = None
    proof = None
    try:
        final_state, proof = run_recovery_core(
            bootstrap,
            cleanup_locks,
            cleanup_read=cleanup_read,
            mutate=mutate,
            require_exact_inventory=require_exact_inventory,
            require_exact_lock=require_exact_lock,
            final_state_reader=lambda: live_state(bearer, target_state="absent"),
        )
        terminal_status = "succeeded"
    except BaseException as exc:
        error_type = type(exc).__name__
        try:
            final_state = live_state(bearer, target_state="absent")
        except BaseException:
            final_state = None
        raise
    finally:
        terminal = {
            "schemaVersion": 1,
            "authorizationId": identifier,
            "incidentAuthorizationId": INCIDENT_ID,
            "status": terminal_status,
            "consumed": True,
            "issuedMutations": [
                {"method": method, "targetUrl": url}
                for method, url in sorted(issued)
            ],
            "cleanupProof": proof,
            "finalState": final_state,
            "errorType": error_type,
            "completedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
        write_new(result_dir / "execution-terminal.json", terminal)
        print(json.dumps(terminal, sort_keys=True))


parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest="mode", required=True)
subparsers.add_parser("selftest")
subparsers.add_parser("observe")
request_parser = subparsers.add_parser("request")
request_parser.add_argument("authorization_id")
apply_parser = subparsers.add_parser("apply")
apply_parser.add_argument("authorization_id")
args = parser.parse_args()
if args.mode == "selftest":
    selftest()
elif args.mode == "observe":
    observe()
elif args.mode == "request":
    request_confirmation(args.authorization_id)
else:
    apply(args.authorization_id)
