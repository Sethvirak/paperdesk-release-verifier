"""Source-bound one-use recovery for one exact residual package-read role assignment.

The wrapper performs read-only observation by default.  Apply mode admits only
the reviewed rollback-lock DELETE, the exact incident assignment DELETE, and an
exact rollback-lock restoration PUT.  Every mutation is journaled before issue
and is attempted at most once.
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
INCIDENT_ID = "8ca12de8-3e35-4e9c-9316-2826353b1045"
SOURCE_SHA = "a6db291e47ee1ec78de8c51021ecea83131d5fc8"
SUBSCRIPTION = "9c4e0d0d-602f-4cde-84bd-337250e5b64c"
TENANT = "aba83bd8-3e5c-4a87-9eb1-7bca070685b2"
ACCOUNT_OBJECT_ID = "b97bfa13-b375-4b27-93d7-141029dbc05b"
PLAN_SHA256 = "49f2977345bbbb25a26a42049af0267603261c4f03909131cc30ffb1dbd8f760"
PACKAGE_SHA256 = "3395bc6c812b1b3c7d91e9abb823a939e651f8efba700565a834fc45d26693fe"
INCIDENT_AUTH_SHA256 = "1abecae20c3be8f845ea0b68ee9bc21c17c2c8cef8d5115ac0afa694b7a2d1f1"
EXECUTOR_SHA256 = "26e88cff4067f63421dfd1d2312461557dc2f202d53a24e27dd5750a6ea8cf5f"
OBSERVER_SHA256 = "17a17a23883996992e7e071b2a7a6cf583eaeeb494040e5ac9432aab96605193"
CLEANUP_LOCKS_SHA256 = "7b19b7c54996c1b3ed3b93e12018a63968870820946caccab7d8c012db61b956"
SOURCE_EVIDENCE_SHA256 = "6d6efbb7479a5a0e561241290059aa9c4030c5c24b620dcad49ceb41922ecc14"
ASSIGNMENT_ID = "74f3e927-15a8-5e8f-911b-3baf3412a1bb"
PACKAGE_ADD_ASSIGNMENT_ID = "e3422926-16c0-523e-8cdc-3829f99fb74f"
ASSIGNMENT_ROLE_DEFINITION_ID = "e005b62b-037b-4989-b492-932669ec0842"
RECOVERY_OPERATION_ID = "recoverExactResidualPackageReadAssignment8ca"

MGMT = "https://management.azure.com"
SCOPE = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-paperdesk-rollback-sea-20260808/"
    "providers/Microsoft.Storage/storageAccounts/mdspdbak2608089c4e/blobServices/"
    "default/containers/paperdesk-deployment-packages"
)
ASSIGNMENT_RESOURCE = (
    f"{SCOPE}/providers/Microsoft.Authorization/roleAssignments/{ASSIGNMENT_ID}"
)
ASSIGNMENT_URL = f"{MGMT}{ASSIGNMENT_RESOURCE}?api-version=2022-04-01"
PACKAGE_ADD_ASSIGNMENT_RESOURCE = (
    f"{SCOPE}/providers/Microsoft.Authorization/roleAssignments/{PACKAGE_ADD_ASSIGNMENT_ID}"
)
PACKAGE_ADD_ASSIGNMENT_URL = f"{MGMT}{PACKAGE_ADD_ASSIGNMENT_RESOURCE}?api-version=2022-04-01"
ASSIGNMENT_ROLE_DEFINITION_RESOURCE = (
    f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/"
    f"roleDefinitions/{ASSIGNMENT_ROLE_DEFINITION_ID}"
)
ASSIGNMENT_ROLE_DEFINITION_URL = (
    f"{MGMT}{ASSIGNMENT_ROLE_DEFINITION_RESOURCE}?api-version=2022-04-01"
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
    'cloud-mutation-0001.json': 'ae62fe444e2d11294e660e3966fb0843e449275364d185f0a5bbb5be6d0b3f59',
    'cloud-mutation-0002.json': '7d19236c1ead0495ca56760f40ce4534e0fe2f3cf0482015da47c1820007ab27',
    'cloud-mutation-0003.json': 'd465c17a246e9f56ba4d4199d7a26c24200518b69e691c10511a750acd7b85fb',
    'cloud-mutation-0004.json': '0dd4bb19749a6cdd4a539cc24c6ea69a288f891d69a2913de5b838989281f635',
    'cloud-mutation-0005.json': '7c056e9af12e8ef3dc3bec3fb94711f06bfe40bac10a23b71c4b6c571d9ae232',
    'cloud-mutation-0006.json': '305539dbc38f1cc1398fba72862dc23fca7a1c06d2611cabf19e0e3a38e9e3d5',
    'cloud-mutation-0007.json': '32f356daf0479b023eef64cf6263ea55988eb687cdb9809302350da6a725b8e9',
    'cloud-mutation-0008.json': 'eff1eb3e6f78b16924e850d5de0edb0b68aec68b5bd7b2f8c1d0bde034b37bc1',
    'cloud-mutation-0009.json': '3f0966107197eaf3d07ace9cc85c64db2d91d5744c2c655b82d5aa8101ea5667',
    'cloud-mutation-0010.json': 'cee3e4f5819438a60439f62bf2baa843d521353398668e3f325ddc877472669d',
    'cloud-mutation-0011.json': '23f25a2f62097cdebf5a66a959b1fc9ca58665a0a366bca642c4283d51528cd5',
    'cloud-mutation-0012.json': 'a7681a8618b4a8a6f590a38da30a7c8ffb4f79ace1cf988ab54780f0ed14505c',
    'cloud-mutation-0013.json': 'bb7ab09ecadb18256bdcc1bcee63095e7299a0a242c334ec0e5c6bf275b72d06',
    'cloud-mutation-0014.json': '67839b8114824974a4e539257e781da8b7ea6aa5c5a29af498f6712049661d45',
    'cloud-mutation-0015.json': '72d56b374adb8d1cae94bf46b39c86d31ca9bf992140a83c0d61a781cf5f8385',
    'cloud-mutation-0016.json': '3b4063246a85c2663ce4547d80b4dceef6aa46d22e9a6946f445a40d228c9406',
    'cloud-mutation-0017.json': 'a850379faa3e21d7ce5cb2501e3cab20800338ce4acfe3e4f8b5568159fb1c2d',
    'cloud-mutation-0018.json': 'c911f8efe6c81e4f66b81f1ff1e0d16888232235562cb3d4071036aa4b388d2c',
    'cloud-mutation-0019.json': '739046eea75e63404663f41b04a8c3fecc72368a4170461e6218bba778131167',
    'cloud-mutation-0020.json': '1e9183067cf44bf038c6173f6789c2c83bcaaa701831b20413f9d47ef78b360d',
    'cloud-mutation-0021.json': '9652e14f014f805357021f3cb1bc5181d5ff5ff153b507fc3f92d41490f7dfb2',
    'cloud-mutation-0022.json': '6589f5c9611655639c269947a588fe9bf7eed8298f318cf10dc20df0f7648072',
    'cloud-mutation-0023.json': '3fead7276a0fd327b7d99cd431d5a524f0405257c4d8086319dee3c26f4837c9',
    'cloud-mutation-0024.json': '118e5e90ac72e8d424f3df04053c459f5aac934439e1589319e77234343ca297',
    'cloud-mutation-0025.json': 'bd2a3bf30ab03f568a1fa59888fcf1a157835fc1eb9f9e73e97d80fbaaa1684c',
    'cloud-mutation-0026.json': '31869d3b887795642c1ea2c9e5315da0639b3e37980e571595fc64efc07a6c3c',
    'cloud-mutation-0027.json': '9beaeb18e798f34a3ea6a9f9fc1e679d6c02f399c64b2438e666b4bbe0bf9763',
    'cloud-mutation-0028.json': '813bb0f516768939f9ab967e8de661ea9eed97f2960dfca24c7ad28754a7cb06',
    'cloud-mutation-0029.json': 'd60e3d70b4c22fdb0f35a82f795db58caf50337f7607ab709dbba6921330b68c',
    'cloud-mutation-0030.json': 'd24c00c0556d967c11ba112299dd121bab7215a416c90e0818bd0b3cd72243db',
    'cloud-mutation-0031.json': '1de9ca3269510b71cdf37a9dc59ef76fff0c690e539dfd8c7636cae93a19da78',
    'cloud-mutation-0032.json': 'b5d6e0700673e59b0de3fb8fd466028733baafd27398f02fcd80bb2d3974496b',
    'cloud-mutation-0033.json': '37b38fab21ac47492e00536e7fdbb8c9f6837f2520f055cb4553d4ff34f36a8e',
    'cloud-mutation-0034.json': '059d2c925bce8a3d14431e57b7d9020d3e2aa4a9585dff6874dd21bb5f4361c1',
    'cloud-mutation-0035.json': 'e51a8071b5fa50fa3511ec88856d2713f16573b0e23c84532908c9f6b9f8db05',
    'cloud-mutation-0036.json': 'aec13e7464ba9cce16730ce509bb9c08c47f68b3599e9b08847e1d779cedd026',
    'cloud-mutation-0037.json': 'dd2d52cf02510790a1680da0d54af47f86b81b5ae099826761df530562d446c6',
    'cloud-mutation-0038.json': '68b5fd8378d226aad5109a67893bcb618c5d9f89713473ba0c0726dab2247f14',
    'cloud-mutation-0039.json': 'dc605bc8604d43aae9122c1dce12a13c41d4af71ea8b4a32304cc64939a4107f',
    'execution-terminal.json': 'a02697a91ffb82e824858d80ba29cbcdd7ef57e14e6678f7d39d444e4f07bef9',
    'single-use-state.json': '5ab876e9186f68200f028508031266d5e3be10e5cef2cf55b586ef690b1d2342',
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
        CEREMONY / f"observation-{INCIDENT_ID}" / "bootstrap-authorization.json": INCIDENT_AUTH_SHA256,
        CEREMONY / f"source-pr90-{SOURCE_SHA}.json": SOURCE_EVIDENCE_SHA256,
    }
    for path, expected in expected_files.items():
        if not path.is_file() or path.is_symlink() or digest(path.read_bytes()) != expected:
            fail(f"trusted input moved: {path.name}")
    auth, _ = load_canonical(CEREMONY / f"observation-{INCIDENT_ID}" / "bootstrap-authorization.json")
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
    created = docs["cloud-mutation-0028.json"]
    lock_removed = docs["cloud-mutation-0032.json"]
    package_add_delete_intent = docs["cloud-mutation-0033.json"]
    package_add_deleted = docs["cloud-mutation-0034.json"]
    assignment_delete_intent = docs["cloud-mutation-0035.json"]
    lock_restore_intent = docs["cloud-mutation-0036.json"]
    lock_restored = docs["cloud-mutation-0037.json"]
    storage_restore_intent = docs["cloud-mutation-0038.json"]
    storage_restored = docs["cloud-mutation-0039.json"]
    terminal = docs["execution-terminal.json"]
    if (
        created.get("status") != 201
        or created.get("targetUrl") != ASSIGNMENT_URL
        or created.get("requestBodySha256") != expected_assignment_body_sha256()
        or lock_removed.get("status") != 200
        or lock_removed.get("targetUrl") != LOCK_URL
        or package_add_delete_intent.get("phase") != "intent"
        or package_add_delete_intent.get("method") != "DELETE"
        or package_add_delete_intent.get("targetUrl") != PACKAGE_ADD_ASSIGNMENT_URL
        or package_add_deleted.get("status") != 200
        or package_add_deleted.get("targetUrl") != PACKAGE_ADD_ASSIGNMENT_URL
        or assignment_delete_intent.get("phase") != "intent"
        or assignment_delete_intent.get("method") != "DELETE"
        or assignment_delete_intent.get("targetUrl") != ASSIGNMENT_URL
        or lock_restore_intent.get("phase") != "intent"
        or lock_restore_intent.get("method") != "PUT"
        or lock_restore_intent.get("targetUrl") != LOCK_URL
        or lock_restored.get("status") != 201
        or lock_restored.get("targetUrl") != LOCK_URL
        or storage_restore_intent.get("phase") != "intent"
        or storage_restore_intent.get("method") != "PATCH"
        or storage_restore_intent.get("targetUrl") != STORAGE_URL
        or storage_restored.get("status") != 200
        or storage_restored.get("targetUrl") != STORAGE_URL
        or terminal.get("status") != "failed"
        or terminal.get("consumed") is not True
        or terminal.get("failureType") != "_MutationOwnershipAmbiguity"
        or not any(item.get("operationId") == "addOwnedUploaderPackageRole" and item.get("status") == "cleanup-failed" for item in terminal.get("temporaryCleanup", []))
        or not any(item.get("operationId") == "addOwnedUploaderIpv4Rule" and item.get("status") == "removed-exact" for item in terminal.get("temporaryCleanup", []))
        or {p.name for p in receipt.glob("cloud-mutation-*.json")} != {name for name in EXPECTED_RECEIPT_HASHES if name.startswith("cloud-mutation-")}
    ):
        fail("incident ownership receipts are not exact")



def expected_assignment_body() -> dict:
    marker = f"paperdesk-private-release-v2-temporary:{INCIDENT_ID}:uploader-package-role"
    return {
        "properties": {
            "principalId": ACCOUNT_OBJECT_ID,
            "principalType": "User",
            "roleDefinitionId": ASSIGNMENT_ROLE_DEFINITION_RESOURCE,
            "description": marker,
        }
    }


def expected_assignment_body_sha256() -> str:
    return digest(canonical(expected_assignment_body()))


def expected_assignment_projection() -> dict:
    properties = expected_assignment_body()["properties"]
    return {
        "id": ASSIGNMENT_RESOURCE,
        "name": ASSIGNMENT_ID,
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
        (bootstrap._resource_scope_from_plan(plan, "packageContainer"), temporary["temporaryPackageAddRoleAssignmentId"]),
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


def project_assignment(bootstrap, document: dict) -> dict:
    projected = bootstrap._project_role_assignment(document)
    raw_id = projected.get("id")
    if (
        not isinstance(raw_id, str)
        or raw_id.lower() != ASSIGNMENT_RESOURCE.lower()
    ):
        fail("assignment resource ID drifted")
    properties = document.get("properties")
    if not isinstance(properties, dict):
        fail("assignment properties are absent")
    projected["properties"]["description"] = properties.get("description")
    projected["id"] = ASSIGNMENT_RESOURCE
    return projected


def selftest() -> None:
    bootstrap, _ = import_trusted_modules()
    wrong = copy.deepcopy(expected_assignment_projection())
    wrong["id"] = SCOPE + "/providers/Microsoft.Authorization/roleAssignments/00000000-0000-4000-8000-000000000000"
    try:
        project_assignment(bootstrap, wrong)
    except RuntimeError as exc:
        if str(exc) != "assignment resource ID drifted":
            raise
    else:
        fail("wrong raw assignment ID was not rejected")
    exact = project_assignment(bootstrap, copy.deepcopy(expected_assignment_projection()))
    if exact != expected_assignment_projection():
        fail("exact assignment projection self-test drifted")
    print(json.dumps({"status": "selftest-passed", "azureMutationPerformed": False}, sort_keys=True))


def live_state(bearer: str, *, target_state: str) -> dict:
    bootstrap, cleanup_locks = import_trusted_modules()
    plan = bound_plan(bootstrap)
    assignment_response = read_request(bearer, "GET", ASSIGNMENT_URL)
    assignment_projection = None
    if assignment_response.status == 200:
        assignment_projection = project_assignment(
            bootstrap, json_object(assignment_response, {200}, "target assignment")
        )
        observed_target = "exact" if assignment_projection == expected_assignment_projection() else "third-state"
    elif assignment_response.status == 404:
        observed_target = "absent"
    else:
        fail("target assignment read failed closed")
    if observed_target != target_state:
        fail(f"target assignment is {observed_target}, expected {target_state}")

    related = {}
    for url in other_temporary_assignment_urls(bootstrap):
        response = read_request(bearer, "GET", url)
        if response.status != 404:
            fail("another incident temporary assignment is present or unreadable")
        related[url] = "absent"

    package_read_specs = [
        spec for spec in bootstrap._stable_package_role_specs(plan)
        if spec["name"] == "packageRead"
    ]
    if len(package_read_specs) != 1:
        fail("target package-read role definition spec drifted")
    expected_definition = package_read_specs[0]["definitionProjection"]
    package_read_definition = json_object(
        read_request(bearer, "GET", ASSIGNMENT_ROLE_DEFINITION_URL),
        {200},
        "target package-read role definition",
    )
    if bootstrap._project_role_definition(package_read_definition) != expected_definition:
        fail("target package-read role definition drifted")

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
        "targetAssignment": {"state": observed_target, "projection": assignment_projection},
        "otherIncidentTemporaryAssignments": related,
        "targetPackageReadRoleDefinitionSha256": digest(canonical(expected_definition)),
        "temporaryKeyRoleDefinition": "absent",
        "storageNetworkAcls": storage,
        "cleanupLockInventory": lock_inventory,
        "locks": locks,
    }


def expected_live_state(target_state: str) -> dict:
    bootstrap, cleanup_locks = import_trusted_modules()
    plan = bound_plan(bootstrap)
    package_read_specs = [
        spec for spec in bootstrap._stable_package_role_specs(plan)
        if spec["name"] == "packageRead"
    ]
    if len(package_read_specs) != 1:
        fail("target package-read role definition spec drifted")
    expected_definition = package_read_specs[0]["definitionProjection"]
    locks = {
        f"{MGMT}{spec['resourceId']}?api-version=2016-09-01": "exact"
        for spec in cleanup_locks.REVIEWED_CLEANUP_LOCKS.values()
    }
    return {
        "targetAssignment": {
            "state": target_state,
            "projection": expected_assignment_projection() if target_state == "exact" else None,
        },
        "otherIncidentTemporaryAssignments": {
            url: "absent" for url in other_temporary_assignment_urls(bootstrap)
        },
        "targetPackageReadRoleDefinitionSha256": digest(canonical(expected_definition)),
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
        "targetUrl", "targetAssignmentProjectionSha256", "lockUrl", "lockPropertiesSha256",
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
        "targetUrl": ASSIGNMENT_URL,
        "targetAssignmentProjectionSha256": digest(canonical(expected_assignment_projection())),
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
        f"Authorize Azure temporary role-assignment recovery under authorization {preflight['authorizationId']}: "
        f"Authorize the separately reviewed source-bound cleanup of only role assignment {ASSIGNMENT_ID} left by incident {INCIDENT_ID}, source {SOURCE_SHA}, wrapper SHA-256 {preflight['wrapperSha256']}, cleanup-lock module SHA-256 {CLEANUP_LOCKS_SHA256}, preflight SHA-256 {preflight_sha}, observed at {preflight['observedAt']}, and expiring at {preflight['freshnessDeadline']}. "
        f"I authorize temporary removal and exact restoration of only the reviewed CanNotDelete lock {LOCK_RESOURCE} solely around one DELETE of the exact assignment {ASSIGNMENT_RESOURCE}. "
        "I accept that Azure exposes no supported conditional ETag for either DELETE and that lock updates have no atomic concurrency guard, so an out-of-band administrator change cannot be atomically excluded. The executor must issue each DELETE at most once without retry, must issue at most one exact lock-restoration PUT, and must never deliberately overwrite a third state. "
        "Definite success requires a fresh 404 for the target assignment, all four other incident temporary assignments absent, the incident temporary key role definition absent, the target package-read role definition exact, the restrictive Storage network baseline exact, and all three reviewed CanNotDelete locks present and exact. "
        "I accept that ambiguous transport, process death, or local journal/fsync failure after intent can leave the assignment present or deletion protection absent; execution and any later bootstrap must stop until fresh reads prove the exact final state, and manual cleanup may be required. "
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
        "targetUrl": ASSIGNMENT_URL,
        "targetAssignmentProjectionSha256": digest(canonical(expected_assignment_projection())),
        "lockUrl": LOCK_URL,
        "lockPropertiesSha256": digest(canonical(EXPECTED_LOCK_PROPERTIES)),
        "observedAt": observed.isoformat(),
        "freshnessDeadline": (observed + dt.timedelta(minutes=30)).isoformat(),
        "liveState": state,
        "azureMutationPerformed": False,
    }
    path = CEREMONY / f"temp-assignment-recovery-preflight-{identifier}.json"
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
    preflight, raw = load_canonical(CEREMONY / f"temp-assignment-recovery-preflight-{identifier}.json")
    _, deadline, preflight_sha = validate_preflight(
        identifier, preflight, raw, digest(Path(__file__).read_bytes())
    )
    if dt.datetime.now(dt.timezone.utc) >= deadline:
        fail("recovery preflight is stale")
    value = phrase(preflight, preflight_sha)
    output = REPORTS / f"TEMP-ASSIGNMENT-RECOVERY-CONFIRMATION-{identifier}.txt"
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
        CEREMONY / f"temp-assignment-recovery-preflight-{identifier}.json"
    )
    _, deadline, preflight_sha = validate_preflight(
        identifier, preflight, preflight_raw, wrapper_sha
    )
    now = dt.datetime.now(dt.timezone.utc)
    if now >= deadline:
        fail("recovery preflight is stale")
    confirmation_path = CEREMONY / f"temp-assignment-recovery-confirmation-{identifier}.txt"
    if not confirmation_path.is_file() or confirmation_path.is_symlink():
        fail("exact user confirmation is absent")
    confirmation_raw = confirmation_path.read_bytes()
    if (
        confirmation_raw.endswith((b"\r", b"\n"))
        or confirmation_raw.decode("utf-8") != phrase(preflight, preflight_sha)
    ):
        fail("user confirmation is not exact")
    result_dir = CEREMONY / f"paperdesk-private-release-v2-temp-assignment-recovery-{identifier}"
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
            ("DELETE", ASSIGNMENT_URL),
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
        require_exact_inventory()
        require_exact_lock()
        target_before = json_object(
            cleanup_read("GET", ASSIGNMENT_URL), {200}, "target assignment prestate"
        )
        if project_assignment(bootstrap, target_before) != expected_assignment_projection():
            fail("target assignment prestate drifted")
        try:
            mutate("DELETE", LOCK_URL, expected={200, 204})
            if cleanup_read("GET", LOCK_URL).status != 404:
                fail("rollback cleanup lock deletion did not converge")
            target_after_lock = json_object(
                cleanup_read("GET", ASSIGNMENT_URL),
                {200},
                "target assignment after lock suspension",
            )
            if project_assignment(bootstrap, target_after_lock) != expected_assignment_projection():
                fail("target assignment drifted after lock suspension")
            mutate("DELETE", ASSIGNMENT_URL, expected={200, 204})
            if cleanup_read("GET", ASSIGNMENT_URL).status != 404:
                fail("target assignment deletion did not converge")
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
        final_state = live_state(bearer, target_state="absent")
        proof = {
            "operationId": RECOVERY_OPERATION_ID,
            "assignmentAbsent": True,
            "lockRestored": True,
            "lockResourceId": LOCK_RESOURCE,
        }
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
