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
INCIDENT_ID = "dc3fb9de-8104-4706-957a-8e9f04d00fa9"
SOURCE_SHA = "34c3974f0d95108f6e0bdb75e515d28f35d7b36a"
SUBSCRIPTION = "9c4e0d0d-602f-4cde-84bd-337250e5b64c"
TENANT = "aba83bd8-3e5c-4a87-9eb1-7bca070685b2"
ACCOUNT_OBJECT_ID = "b97bfa13-b375-4b27-93d7-141029dbc05b"
PLAN_SHA256 = "49f2977345bbbb25a26a42049af0267603261c4f03909131cc30ffb1dbd8f760"
PACKAGE_SHA256 = "3395bc6c812b1b3c7d91e9abb823a939e651f8efba700565a834fc45d26693fe"
INCIDENT_AUTH_SHA256 = "55745f644c0d7a29c92b99b691c1e3dc0458ae02bd00b415a79d2c4a78deb7f2"
EXECUTOR_SHA256 = "b3addea38312515792a99fc22a7066c13e9d6e85c6abeb8d304282411c37ad6f"
OBSERVER_SHA256 = "17a17a23883996992e7e071b2a7a6cf583eaeeb494040e5ac9432aab96605193"
CLEANUP_LOCKS_SHA256 = "7b19b7c54996c1b3ed3b93e12018a63968870820946caccab7d8c012db61b956"
SOURCE_EVIDENCE_SHA256 = "d9155a346d1481b2b864e5585f63928879ee3de698074642ee87e9687f8a4abf"
ASSIGNMENT_ID = "768a99cb-4127-5852-ac3e-c71493cdd940"
PACKAGE_ADD_ASSIGNMENT_ID = "e8a9801e-67b6-5a5d-a2a6-b7c3cf977e55"
ASSIGNMENT_ROLE_DEFINITION_ID = "e005b62b-037b-4989-b492-932669ec0842"
RECOVERY_OPERATION_ID = "recoverExactResidualPackageReadAssignmentDc3f"

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
    'cloud-mutation-0001.json': '37092efaae851723a907cfb572257b39d8b41edc9b7febbe45378c8b978e42f3',
    'cloud-mutation-0002.json': 'cf38be4cad3d18c1be2c4cf1ebaccb805670125b631f60abb6cf69a58e563175',
    'cloud-mutation-0003.json': 'd9cc3eb1d698393e2ce0fc081f63342dac6bf65d7c773f812a58639b3f21f143',
    'cloud-mutation-0004.json': '64a4c71ea6d953453d7b505aa5a986ea32626a2690850045961a2fb70a9a7af2',
    'cloud-mutation-0005.json': 'd78ec464419173230521c236768cf9ea002b464e0ad8bc820dbd906906a0f469',
    'cloud-mutation-0006.json': 'f4f68d7798432b254269e9c2c70333fe8df34bb635a2cf0c74dceee34396da7a',
    'cloud-mutation-0007.json': '449e2b181af88871db37238c14dd777b3ab78e673424239609c7b966bea430b0',
    'cloud-mutation-0008.json': '9729c0f93f2ac48e2c4d6e184aea22fd1dd94794ef191da4e875906819243f3d',
    'cloud-mutation-0009.json': 'ea9680771cb8348b094c611994f30e12ddb4349eeeaee87cdffcdec6ca748259',
    'cloud-mutation-0010.json': '39847c191f970f0065a8472dafccfda8e1e3620cc4d36ec63a699d7d6330bc63',
    'cloud-mutation-0011.json': 'ee740fbf19c24f73226dc1faf21b255228231f12ad1c33e309862a3f990a4586',
    'cloud-mutation-0012.json': 'c3c3433911a4bf42bc52889dc902c5f13b2bffd842c46ee37b32274fedeedff1',
    'cloud-mutation-0013.json': '3817a36a4c0189f258d9aa24a7426a5ee47440c37e8540bc64eeef5328c95416',
    'cloud-mutation-0014.json': '2aa8cedf2016a82e3540ce4bf5c97c150087f261e7692acdd201c32776eff144',
    'cloud-mutation-0015.json': '73673b916882f538a4937cd57c2308229563ff2336a7bd0117ee85f9459eed67',
    'cloud-mutation-0016.json': '199a63b35acadf6737f9496bb7f59695c26fff6bc8524a1cd88721d69e07eaef',
    'cloud-mutation-0017.json': 'f8945b78fbcfd86793d3a61e65dd256bb954f354ea46498b830bfa8b5fe60521',
    'cloud-mutation-0018.json': '040b785b17a1fbb9b685a13c570289b212eefad4d55668986ec8e8ad37e0ee4a',
    'cloud-mutation-0019.json': '9b7f41035f1956f2103284ebc4eff258707e2b1378d3bca12f13553edf418300',
    'cloud-mutation-0020.json': '8038977bf5f27802cd55fd70cda4eb001f72a297bc3d0c1537872415cbc087b8',
    'cloud-mutation-0021.json': '194eeabab3a71e54d8e8df8e65ce0834ee24b6d5a33acfeed2cfe556f18e393d',
    'cloud-mutation-0022.json': '9ea6d46bafeceb641cbf9217309d2a241b9010c2f119ba636dc00c7b5fb1edf7',
    'cloud-mutation-0023.json': '0380dc3a7bafbc24da926a653ec5ff2ad8f46639578641d453dce1d8847b8d0b',
    'cloud-mutation-0024.json': '3b285e613b9fcd120de87d2559b9d74543b2ca6cc57cf036059bd48052a291a4',
    'cloud-mutation-0025.json': 'f4ad9183805c5749da73fc87c80f4d36193b5c258d41871a4391c4116b6a201f',
    'cloud-mutation-0026.json': '76868f9b12980c273279d049e718e78c42d7750daf12fdf6a1ff4a2067104e42',
    'cloud-mutation-0027.json': '11534a86b4bf3ad3362b4b06f6d2d4196d8bc2976a6a92235efb517a765cf5ef',
    'cloud-mutation-0028.json': 'f575a23b697106d912bd86ea02d049c613c990d7efcb1d669ba5c48778262db2',
    'cloud-mutation-0029.json': '48aa61509f95072902326a01b1391d0220737ba62461ffed67d3c9685af00aa0',
    'cloud-mutation-0030.json': 'd5ee79969fbb21e6516a7dfb3a797a92511f07af5f5a9d4720e6695f439946f1',
    'cloud-mutation-0031.json': 'bcfdc3468ec89ce8636d5ad4849315f59af2526f796a034e8e07636515e96ddd',
    'cloud-mutation-0032.json': '77030233c28a8f36ff23b793e0a63f1bada067c6a3b0e3353cfe803f034accfc',
    'cloud-mutation-0033.json': '3128cdf8036ed28685f30f88ed7f841c3607313197e9dae35c84ba6c2e2d68c8',
    'cloud-mutation-0034.json': 'e6fa37ce5ed053ddd6cbba075ce03708e12a8462310dc0ef35b7d699bf656b34',
    'cloud-mutation-0035.json': '1a935d64baabdb75837f2e4a3999313f87250b7e3c79c789c8dcde4cc484ed46',
    'cloud-mutation-0036.json': '373847f6c41084992cbff0b4302cf1d9375ad0a82621da144512f52b857ee3f1',
    'cloud-mutation-0037.json': '9f926727ade762a0d76d057b9d0e62f1992025f91397d5838893f3daddc2d5ae',
    'cloud-mutation-0038.json': 'a57e4fc2753a6ee454cd2e5a3f73d1d96d00765ea94e278a940536ec419e83ff',
    'cloud-mutation-0039.json': '613c39e597422cfdf2f2ccfff44c86b93b4ff5a833ec41cd1b1e04d63b90a4cf',
    'execution-terminal.json': 'ed3772e844f1d6445f8a53d77075c8c7f2c52de4b0e66eb73071cde776d27b42',
    'single-use-state.json': '3ce14ea3d65692285affcb83ff24773c953989e0750d76d0a64e9c799ac5cce8',
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
        CEREMONY / f"source-pr87-{SOURCE_SHA}.json": SOURCE_EVIDENCE_SHA256,
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
