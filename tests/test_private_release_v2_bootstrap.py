import contextlib
import base64
from collections.abc import Mapping
import copy
import datetime as dt
import io
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import urllib.parse
import uuid

from scripts import private_release_v2_bootstrap as bootstrap
from scripts import private_release_mailbox as mailbox


NOW = dt.datetime(2026, 8, 30, 4, 0, tzinfo=dt.timezone.utc)
HEAD = "1" * 40
MERGE = "2" * 40
TREE = "3" * 40
PARENT = "4" * 40
ACCOUNT_OBJECT = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
AUTH_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
# Representative of the live Microsoft Graph appRoleAssignment ID shape:
# canonical unpadded base64url encoding of exactly 32 opaque bytes.
CANONICAL_GRAPH_ASSIGNMENT_ID = (
    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
)
EXPECTED_STORAGE_ACL_AND_RECOVERY_RESIDUAL_ACCEPTANCE = (
    "I accept that Azure Storage exposes no ETag for this account update, so the "
    "temporary uploader ipRules PATCH cannot atomically exclude an unrelated "
    "concurrent administrator change during its bounded pre-read/PATCH/post-read window. "
    "I also accept that process death after the PATCH, an ambiguous successful transport, "
    "or a local result-journal/fsync failure can leave the exact uploader /32 in place; "
    "execution and any later release must stop until a fresh live read proves the /32 and "
    "all related temporary roles absent, and manual cleanup may be required."
)
EXPECTED_DELETION_LOCK_RESIDUAL_ACCEPTANCE = (
    "I authorize temporary removal and exact restoration of only the three reviewed "
    "CanNotDelete locks for the exact role-assignment deletions bound in this plan. "
    "I accept that lock updates have no atomic concurrency guard and that interruption, "
    "ambiguous transport, or journal failure can leave deletion protection absent; "
    "execution must stop NO-GO until fresh reads prove all three exact locks restored and "
    "all related temporary access absent, and manual cleanup may be required."
)
EXPECTED_BRIDGE_CONFIG_HARD_DEATH_RESIDUAL_ACCEPTANCE = (
    "I accept that App Service App Settings exposes no supported conditional ETag, so "
    "the exact full-map configuration PUT and any restoration "
    "cannot atomically exclude an out-of-band administrator write between their final "
    "pre-read and PUT. I also accept that process death after the bridge configuration "
    "or site-start request can leave a consumed use ledger and durable unresolved "
    "mutation intent while the bridge site remains changed or running. Each settings "
    "mutation is issued at most once without retry, and definite success requires exact "
    "full-map digest readback. The executor never deliberately overwrites a third state "
    "observed by its final pre-read or rollback classification; recovery may require an "
    "exact site stop and separately authorized source-bound prestate restoration, and "
    "every fresh apply must stop until that durable intent and live state are fully "
    "resolved."
)
PHRASE = (
    "Authorize the exact one-shot PaperDesk V2 bootstrap plan. "
    + EXPECTED_STORAGE_ACL_AND_RECOVERY_RESIDUAL_ACCEPTANCE
    + " " + EXPECTED_DELETION_LOCK_RESIDUAL_ACCEPTANCE
    + " " + EXPECTED_BRIDGE_CONFIG_HARD_DEATH_RESIDUAL_ACCEPTANCE
)


def stamp(value):
    return (
        value.astimezone(dt.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def build_retired_role_absence_projection(plan, observed_at):
    empty_inventory_sha256 = bootstrap.sha256_bytes(
        bootstrap.canonical_json_bytes({"value": []})
    )
    marker_inventory_sha256 = bootstrap._temporary_role_marker_inventory_sha256(
        [
            {
                **request,
                "status": 200,
                "responseSha256": empty_inventory_sha256,
            }
            for request in bootstrap._temporary_role_marker_inventory_requests()
        ]
    )
    return [
        {
            **request,
            "status": 404,
            "responseSha256": bootstrap.sha256_bytes(
                request["url"].encode("utf-8")
            ),
            "temporaryRoleMarkerInventorySha256": marker_inventory_sha256,
            "observedAt": observed_at,
        }
        for request in bootstrap._retired_temporary_role_absence_requests(plan)
    ]


def canonical_file(path, value):
    path.write_bytes(bootstrap.canonical_json_bytes(value))


def build_builtin_role_definition_projections(plan):
    result = {}
    for definition_id in sorted(
        {
            role["definitionId"]
            for role in plan["roleMatrix"]
            if role.get("definitionKind") == "BuiltInRole"
        }
    ):
        matching = [
            role
            for role in plan["roleMatrix"]
            if role.get("definitionKind") == "BuiltInRole"
            and role["definitionId"] == definition_id
        ]
        result[definition_id] = {
            "id": (
                f"/subscriptions/{bootstrap.SUBSCRIPTION}/providers/"
                f"Microsoft.Authorization/roleDefinitions/{definition_id}"
            ),
            "name": definition_id,
            "type": "Microsoft.Authorization/roleDefinitions",
            "properties": {
                "roleName": f"fixture built-in {definition_id}",
                "description": "full authorization-bound built-in role projection",
                "type": "BuiltInRole",
                "permissions": [
                    {
                        "actions": sorted(
                            {
                                action
                                for role in matching
                                for action in role.get("actions", [])
                            }
                        ),
                        "notActions": [],
                        "dataActions": sorted(
                            {
                                action
                                for role in matching
                                for action in role.get("dataActions", [])
                            }
                        ),
                        "notDataActions": [],
                    }
                ],
                "assignableScopes": ["/"],
            },
        }
    controller = result[bootstrap.CONTROLLER_BUILTIN_ROLE_ID]["properties"]
    controller["roleName"] = "Storage Blob Data Contributor"
    controller["permissions"] = copy.deepcopy(bootstrap.CONTROLLER_BUILTIN_PERMISSIONS)
    return result


def build_production_boundary_projection(plan):
    resources = {item["id"]: item for item in plan["resourceInventory"]}
    return {
        "sitePosture": {
            "id": resources["productionSite"]["resourceId"],
            "name": resources["productionSite"]["name"],
            "type": "Microsoft.Web/sites",
            "state": "Running",
            "identity": {
                "type": "SystemAssigned",
                "tenantId": bootstrap.TENANT,
                "principalId": resources["productionSystemIdentity"]["principalId"],
                "userAssignedIdentityResourceIds": [],
            },
            "virtualNetworkSubnetId": resources["integrationSubnet"]["resourceId"],
            "outboundVnetRouting": {
                "allTraffic": False,
                "applicationTraffic": True,
            },
            "legacyVnetRouteAllEnabled": True,
        },
        "appSettingsSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes({"fixture": "digest-only"})
        ),
        "deploymentInventory": [],
        "oneDeployInventory": [],
    }


def build_projection(plan, package, *, adopt_operations=()):
    plan = bootstrap.bind_temporary_role_ids(plan, AUTH_ID)
    base = (
        f"https://management.azure.com/subscriptions/{bootstrap.SUBSCRIPTION}/"
        "providers/Microsoft.Resources/deployments/bootstrap-probe"
        "?api-version=2022-09-01"
    )
    probes = []
    admissions = []
    context_authorization = {
        "authorizationId": AUTH_ID,
        "source": {"mergedMain": {"commitSha": MERGE}},
        "plan": {
            "sha256": bootstrap.load_plan()[1],
            "bridgePackageSourceSha": MERGE,
            "bridgePackageSha256": package["sha256"],
            "bridgePackageSize": package["size"],
        },
        "validity": {
            "notBefore": stamp(NOW),
            "expiresAt": stamp(
                NOW + dt.timedelta(seconds=bootstrap.MAX_AUTHORIZATION_SECONDS)
            ),
        },
        "azure": {
            "tenantId": bootstrap.TENANT,
        },
        "singleUse": {
            "azureClaimResourceId": (
                f"/subscriptions/{bootstrap.SUBSCRIPTION}/providers/Microsoft.Resources/"
                f"deployments/paperdesk-v2-bootstrap-{AUTH_ID}"
            )
        },
    }
    subnet = (
        f"/subscriptions/{bootstrap.SUBSCRIPTION}/resourceGroups/rg-master-data-structure-sea/"
        "providers/Microsoft.Network/virtualNetworks/vnet-master-data-structure-sea/"
        "subnets/snet-appservice-integration"
    )
    base_acl = {
        "defaultAction": "Deny",
        "bypass": "None",
        "ipRules": [],
        "resourceAccessRules": [],
        "ipv6Rules": [],
        "virtualNetworkRules": [{"id": subnet, "action": "Allow", "state": "Succeeded"}],
    }

    def operation_context(operation_id):
        if operation_id in adopt_operations:
            if operation_id == "uploadVersionedBridgePackage":
                contract = bootstrap._validator_contract(
                    "operation:uploadVersionedBridgePackage",
                    plan,
                    context_authorization,
                )
                return {
                    "executionDecision": "adopt-exact",
                    "adopted": {
                        "blob": f"v2/control/{MERGE}/paperdesk-private-release-bridge.zip",
                        "etag": '"package-etag"',
                        "url": contract["expectedUrl"],
                        "versionId": "2026-08-30T04:01:00.0000000Z",
                    },
                }
            if operation_id == "createInitialIdleActivationFence":
                contract = bootstrap._validator_contract(
                    "operation:createInitialIdleActivationFence",
                    plan,
                    context_authorization,
                )
                return {
                    "executionDecision": "adopt-exact",
                    "adopted": {
                        "url": contract["expectedUrl"],
                        "etag": '"fence-etag"',
                        "versionId": "2026-08-30T04:01:30.0000000Z",
                        "sha256": contract["expectedBodySha256"],
                    },
                }
            raise AssertionError(f"fixture cannot adopt {operation_id}")
        if operation_id in {
            "adoptExistingRegistryWriterIdentity",
            "adoptExistingRegistryReaderIdentity",
        }:
            return {"executionDecision": "adopt-exact", "adopted": {}}
        value = {"executionDecision": "apply-exact"}
        if operation_id == "retireLegacyPublisherFic":
            value["legacyFederatedCredentialId"] = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        elif operation_id == "detachWriterAndReaderFromLegacyBridge":
            value["etag"] = '"legacy-etag"'
        elif operation_id == "createSigningKeyVersion":
            value["expiresAt"] = stamp(NOW + dt.timedelta(days=60))
        elif operation_id == "addOwnedUploaderIpv4Rule":
            value.update({"uploaderIpv4": "203.0.113.10/32", "preNetworkAcls": copy.deepcopy(base_acl)})
        elif operation_id == "removeOwnedUploaderIpv4Rule":
            value.update({"uploaderIpv4": "203.0.113.10/32", "restoreNetworkAcls": copy.deepcopy(base_acl)})
        elif operation_id in bootstrap.CONTROLLER_ROLE_OPERATIONS:
            value["builtInRoleDefinitionProjection"] = build_builtin_role_definition_projections(plan)[bootstrap.CONTROLLER_BUILTIN_ROLE_ID]
        elif operation_id == "configureBridgeExactVersionedPackageAndCriticalSettings":
            value.update({
                "preAppSettings": {},
                "preAppSettingsSha256": bootstrap.sha256_bytes(bootstrap.canonical_json_bytes({})),
                "bootstrapSelfTestStaticControl": bootstrap._bootstrap_self_test_static_control(
                    context_authorization
                ),
            })
        elif operation_id == "createCustomRoleDefinitions":
            value["memberStates"] = {
                role["definitionId"]: "absent"
                for role in plan["roleMatrix"]
                if role.get("definitionKind") != "BuiltInRole"
            }
            value["builtInRoleDefinitionProjections"] = (
                build_builtin_role_definition_projections(plan)
            )
        elif operation_id == "createExactRoleAssignments":
            value["memberStates"] = {
                role["assignmentId"]: "absent" for role in plan["roleMatrix"]
            }
        elif operation_id in {
            "lockPackageRetentionAt91Days",
            "extendAcceptedRetentionFrom30To91Days",
            "extendResultRetentionFrom30To91Days",
        }:
            value["etag"] = '"retention-etag"'
        return value

    def operation_status(operation):
        if operation["id"] in {
            "readBackExactSigningPublicJwk",
            "proveControllerLockContainerEmpty",
        }:
            return "temporary-access-inaccessible"
        kind = operation["kind"]
        if kind.startswith(("azure-global-create-only", "azure-ad-create-only", "temporary-add", "create-or-adopt")):
            return "absent"
        return "exact"

    for index, operation in enumerate(plan["mutations"]):
        if operation["kind"] == "local-create-only-canonical-evidence":
            continue
        pre_id = f"pre-{index}-{operation['id']}"
        post_id = f"post-{index}-{operation['id']}"
        preflight_probe_ids = [pre_id]
        operation_contract = bootstrap._validator_contract(
            f"operation:{operation['id']}", plan, context_authorization
        )
        probes.extend(
            [
                {
                    "id": pre_id,
                    "phase": "preflight",
                    "method": operation_contract["expectedMethod"],
                    "url": operation_contract["expectedUrl"],
                    "requestBodySha256": (
                        bootstrap.sha256_bytes(b"")
                        if operation_contract["expectedMethod"] == "POST"
                        else None
                    ),
                    "status": 404 if index == 0 else 200,
                    "responseSha256": bootstrap.sha256_bytes(f"pre-{index}".encode()),
                    "validatorId": None,
                    "validatorContract": None,
                },
                {
                    "id": post_id,
                    "phase": "readback",
                    "method": operation_contract["expectedMethod"],
                    "url": operation_contract["expectedUrl"],
                    "requestBodySha256": (
                        bootstrap.sha256_bytes(b"")
                        if operation_contract["expectedMethod"] == "POST"
                        else None
                    ),
                    "status": operation_contract["expectedStatus"],
                    "responseSha256": None,
                    "validatorId": f"operation:{operation['id']}",
                    "validatorContract": operation_contract,
                },
            ]
        )
        temporary_definition_url = (
            bootstrap._temporary_role_definition_readback_url(
                operation["id"], plan
            )
        )
        if temporary_definition_url is not None:
            temporary_definition_probe_id = (
                f"pre-{index}-{operation['id']}-temporary-definition"
            )
            probes.append(
                {
                    "id": temporary_definition_probe_id,
                    "phase": "preflight",
                    "method": "GET",
                    "url": temporary_definition_url,
                    "requestBodySha256": None,
                    "status": 200 if operation["id"] in bootstrap.CONTROLLER_ROLE_OPERATIONS else 404,
                    "responseSha256": bootstrap.sha256_bytes(
                        f"pre-temporary-definition-{index}".encode()
                    ),
                    "validatorId": None,
                    "validatorContract": None,
                }
            )
            preflight_probe_ids.append(temporary_definition_probe_id)
        if operation["id"] == "grantPublisherGraphApplicationReadAll":
            graph_resource_probe_id = (
                f"pre-{index}-{operation['id']}-graph-resource-sp"
            )
            probes.append(
                {
                    "id": graph_resource_probe_id,
                    "phase": "preflight",
                    "method": "GET",
                    "url": bootstrap._microsoft_graph_service_principal_inventory_url(),
                    "requestBodySha256": None,
                    "status": 200,
                    "responseSha256": bootstrap.sha256_bytes(
                        f"pre-graph-resource-sp-{index}".encode()
                    ),
                    "validatorId": None,
                    "validatorContract": None,
                }
            )
            preflight_probe_ids.append(graph_resource_probe_id)
        if operation["id"] == "claimAzureSingleUseAuthorization":
            lock_probe_id = "preflight-cleanup-lock-inventory"
            probes.append({
                "id": lock_probe_id,
                "phase": "preflight",
                "method": "GET",
                "url": bootstrap._cleanup_lock_inventory_url(),
                "requestBodySha256": None,
                "status": 200,
                "responseSha256": bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes(bootstrap._expected_cleanup_lock_inventory())
                ),
                "validatorId": None,
                "validatorContract": None,
            })
            preflight_probe_ids.append(lock_probe_id)
        admissions.append(
            {
                "operationId": operation["id"],
                "status": operation_status(operation),
                "probeIds": preflight_probe_ids,
                "desiredProbeIds": [post_id],
                "context": operation_context(operation["id"]),
            }
        )
    postconditions = []
    for index, item in enumerate(plan["postconditions"]):
        probe_id = f"postcondition-{index}-{item['id']}"
        validator_id = f"postcondition:{item['id']}"
        contract = bootstrap._validator_contract(validator_id, plan, context_authorization)
        probes.append({
            "id": probe_id,
            "phase": "readback",
            "method": contract["expectedMethod"],
            "url": contract["expectedUrl"],
            "requestBodySha256": None,
            "status": contract["expectedStatus"],
            "responseSha256": None,
            "validatorId": validator_id,
            "validatorContract": contract,
        })
        postconditions.append({"postconditionId": item["id"], "probeIds": [probe_id]})
    boundary_probe_ids = []
    for request in bootstrap._production_boundary_requests(plan):
        boundary_probe_ids.append(request["id"])
        probes.append(
            {
                "id": request["id"],
                "phase": "preflight",
                "method": request["method"],
                "url": request["url"],
                "requestBodySha256": (
                    bootstrap.sha256_bytes(b"")
                    if request["method"] == "POST"
                    else None
                ),
                "status": 200,
                "responseSha256": bootstrap.sha256_bytes(
                    request["id"].encode("utf-8")
                ),
                "validatorId": None,
                "validatorContract": None,
            }
        )
    return {
        "schemaVersion": 1,
        "planId": plan["planId"],
        "probes": probes,
        "operationAdmissions": admissions,
        "postconditionAdmissions": postconditions,
        "productionBoundaryObservation": {
            "probeIds": boundary_probe_ids,
            "sourceProjection": build_production_boundary_projection(plan),
            "retiredTemporaryRoleAbsence": (
                build_retired_role_absence_projection(
                    plan, stamp(NOW - dt.timedelta(minutes=1))
                )
            ),
        },
    }


def build_authorization(plan, plan_sha, package, projection, receipt_directory):
    pushed = NOW - dt.timedelta(minutes=8)
    review_1 = NOW - dt.timedelta(minutes=7)
    review_2 = NOW - dt.timedelta(minutes=6)
    checked = NOW - dt.timedelta(minutes=5)
    merged = NOW - dt.timedelta(minutes=4)
    return {
        "schemaVersion": 1,
        "authorizationType": "paperdesk-private-release-v2-bootstrap-one-shot",
        "authorizationId": AUTH_ID,
        "repository": bootstrap.REPOSITORY,
        "source": {
            "reviewedHead": {
                "commitSha": HEAD,
                "treeSha": TREE,
                "signatureVerified": True,
                "signingPrincipal": bootstrap.SIGNING_PRINCIPAL,
                "signingKeyFingerprint": bootstrap.SIGNING_FINGERPRINT,
                "pullRequestNumber": 19,
                "pullRequestUrl": f"https://github.com/{bootstrap.REPOSITORY}/pull/19",
                "reviewDecision": "APPROVED",
                "requiredApprovals": 2,
                "pushedAt": stamp(pushed),
                "reviews": [
                    {
                        "login": "jecebella168-cmyk",
                        "userId": 316989178,
                        "reviewId": 9001,
                        "state": "APPROVED",
                        "submittedAt": stamp(review_1),
                        "commitSha": HEAD,
                    },
                    {
                        "login": "jecebella169-cmyk",
                        "userId": 322025901,
                        "reviewId": 9002,
                        "state": "APPROVED",
                        "submittedAt": stamp(review_2),
                        "commitSha": HEAD,
                    },
                ],
                "requiredCheck": {
                    "name": "test",
                    "runId": "12345",
                    "headSha": HEAD,
                    "conclusion": "success",
                    "completedAt": stamp(checked),
                },
            },
            "mergedMain": {
                "commitSha": MERGE,
                "treeSha": TREE,
                "soleParentSha": PARENT,
                "treeEqualsReviewedHead": True,
                "githubVerificationVerified": True,
                "githubVerificationReason": "valid",
                "mergedPullRequestNumber": 19,
                "mergedPullRequestUrl": f"https://github.com/{bootstrap.REPOSITORY}/pull/19",
                "mergedAt": stamp(merged),
                "verificationApiUrl": f"https://api.github.com/repos/{bootstrap.REPOSITORY}/commits/{MERGE}",
                "verificationRetrievedAt": stamp(merged + dt.timedelta(seconds=30)),
            },
        },
        "executor": {
            "path": "scripts/private_release_v2_bootstrap.py",
            "sha256": bootstrap.sha256_bytes(bootstrap.EXECUTOR_PATH.read_bytes()),
        },
        "plan": {
            "path": "contracts/private_release_bootstrap_plan.json",
            "sha256": plan_sha,
            "resourceIds": [item["id"] for item in plan["resourceInventory"]],
            "mutationIds": [item["id"] for item in plan["mutations"]],
            "irreversibleMutationIds": list(plan["irreversibleMutationIds"]),
            "postconditionIds": [item["id"] for item in plan["postconditions"]],
            "bridgePackageSourceSha": MERGE,
            "bridgePackageSha256": package["sha256"],
            "bridgePackageSize": package["size"],
        },
        "azure": {
            "cloud": "AzureCloud",
            "subscriptionId": bootstrap.SUBSCRIPTION,
            "tenantId": bootstrap.TENANT,
            "accountId": "operator@example.invalid",
            "accountObjectId": ACCOUNT_OBJECT,
            "accountType": "user",
        },
        "observedPreflight": {
            "sha256": bootstrap.sha256_bytes(bootstrap.canonical_json_bytes(projection)),
            "observedAt": stamp(NOW - dt.timedelta(minutes=1)),
            "maximumAgeSeconds": bootstrap.MAX_PREFLIGHT_AGE_SECONDS,
        },
        "validity": {
            "notBefore": stamp(NOW),
            "expiresAt": stamp(
                NOW + dt.timedelta(seconds=bootstrap.MAX_AUTHORIZATION_SECONDS)
            ),
            "maximumLifetimeSeconds": bootstrap.MAX_AUTHORIZATION_SECONDS,
        },
        "confirmation": {
            "encoding": "utf-8-exact-no-newline",
            "phraseSha256": bootstrap.sha256_bytes(PHRASE.encode()),
        },
        "singleUse": {
            "required": True,
            "receiptDirectory": str(receipt_directory),
            "azureClaimResourceId": (
                f"/subscriptions/{bootstrap.SUBSCRIPTION}/providers/Microsoft.Resources/"
                f"deployments/paperdesk-v2-bootstrap-{AUTH_ID}"
            ),
        },
    }


class _TerminalEvidenceFixture:
    """Construct one deterministic, fully source-validated terminal snapshot."""

    def __init__(
        self,
        plan,
        plan_sha,
        package,
        receipt_directory,
        *,
        adopt_operations=(),
    ):
        self.plan = plan
        self.execution_plan = bootstrap.bind_temporary_role_ids(plan, AUTH_ID)
        self.plan_sha = plan_sha
        self.package = package
        self.projection = build_projection(
            plan, package, adopt_operations=adopt_operations
        )
        self.authorization = build_authorization(
            plan, plan_sha, package, self.projection, receipt_directory
        )
        self.resources = {item["id"]: item for item in plan["resourceInventory"]}
        self.mutations = {item["id"]: item for item in plan["mutations"]}
        self.contexts = {
            item["operationId"]: item["context"]
            for item in self.projection["operationAdmissions"]
        }
        self.operations = {}
        self.authorization_sha = bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(self.authorization)
        )

    @staticmethod
    def guid(label):
        return str(uuid.uuid5(uuid.UUID(AUTH_ID), label))

    @staticmethod
    def digest(label):
        return bootstrap.sha256_bytes(label.encode("utf-8"))

    def envelope(self, operation_id, body, *, headers=None, runtime_facts=None):
        contract = bootstrap._validator_contract(
            f"operation:{operation_id}", self.plan, self.authorization
        )
        operation = self.mutations[operation_id]
        value = {
            "schemaVersion": 1,
            "operationId": operation_id,
            "family": bootstrap._operation_projection_family(operation_id),
            "method": contract["expectedMethod"],
            "url": contract["expectedUrl"],
            "status": contract["expectedStatus"],
            "target": operation["target"],
            "targetResourceId": contract.get("targetResourceId"),
            "responseSha256": self.digest(f"response:{operation_id}"),
            "headers": dict(headers or {}),
            "projection": copy.deepcopy(body),
        }
        validated = bootstrap._validate_operation_source_projection(
            value,
            operation_id=operation_id,
            plan=self.plan,
            authorization=self.authorization,
            prior=self.operations,
            operation_context=self.contexts[operation_id],
            runtime_facts=runtime_facts or {},
        )
        self.operations[operation_id] = validated
        return validated

    def webapp(self, resource_key, *, identity, state="Stopped"):
        resource = self.resources[resource_key]
        return {
            "id": resource["resourceId"],
            "name": resource["name"],
            "kind": "app,linux",
            "httpsOnly": True,
            "state": state,
            "publicNetworkAccess": "Disabled",
            "serverFarmId": self.resources["bridgeAppServicePlan"]["resourceId"],
            "virtualNetworkSubnetId": self.resources["integrationSubnet"]["resourceId"],
            "outboundVnetRouting": {"allTraffic": True, "applicationTraffic": True},
            "identity": identity,
        }

    def temp_role(self, operation_id):
        temporary = self.execution_plan["temporaryAccess"]
        specs = {
            "addOwnedUploaderPackageRole": (
                temporary["roleDefinitionId"],
                temporary["roleAssignmentId"],
                "packageContainer",
                "uploader-package-role",
                temporary["temporaryPackageDataActions"],
            ),
            "addOwnedOperatorKeyReadRole": (
                temporary["temporaryKeyReadRoleDefinitionId"],
                temporary["temporaryKeyReadRoleAssignmentId"],
                "signingKey",
                "operator-key-read-role",
                temporary["temporaryKeyReadDataActions"],
            ),
            "addOwnedOperatorFenceBootstrapRole": (
                temporary["temporaryFenceRoleDefinitionId"],
                temporary["temporaryFenceRoleAssignmentId"],
                "activationFenceContainer",
                "operator-fence-bootstrap-role",
                temporary["temporaryFenceDataActions"],
            ),
            "addOwnedOperatorControllerCanaryRole": (
                temporary["temporaryControllerRoleDefinitionId"],
                temporary["temporaryControllerRoleAssignmentId"],
                "controllerLockContainer",
                "operator-controller-canary-role",
                temporary["temporaryControllerDataActions"],
            ),
        }
        definition_id, assignment_id, scope_key, cleanup_key, data_actions = specs[
            operation_id
        ]
        metadata = bootstrap._temporary_role_metadata(AUTH_ID, cleanup_key)
        scope = self.resources[scope_key]["resourceId"]
        definition_resource = (
            f"/subscriptions/{bootstrap.SUBSCRIPTION}/providers/"
            f"Microsoft.Authorization/roleDefinitions/{definition_id}"
        )
        assignment_resource = (
            f"{scope}/providers/Microsoft.Authorization/roleAssignments/"
            f"{assignment_id}"
        )
        result = {
            "definitionResourceId": definition_resource,
            "assignmentResourceId": assignment_resource,
            "definitionCreated": True,
            "assignmentCreated": True,
            "cleanupKey": cleanup_key,
            "definition": {
                "id": definition_resource,
                "name": definition_id,
                "type": "Microsoft.Authorization/roleDefinitions",
                "properties": {
                    "roleName": metadata["roleName"],
                    "description": metadata["description"],
                    "type": "CustomRole",
                    "permissions": [
                        {
                            "actions": [],
                            "notActions": [],
                            "dataActions": data_actions,
                            "notDataActions": [],
                        }
                    ],
                    "assignableScopes": [f"/subscriptions/{bootstrap.SUBSCRIPTION}"],
                },
            },
            "assignment": {
                "id": assignment_resource,
                "name": assignment_id,
                "type": "Microsoft.Authorization/roleAssignments",
                "properties": {
                    "principalId": ACCOUNT_OBJECT,
                    "principalType": "User",
                    "roleDefinitionId": definition_resource,
                    "scope": scope,
                    "condition": None,
                    "conditionVersion": None,
                    "delegatedManagedIdentityResourceId": None,
                    "description": metadata["assignmentDescription"],
                },
            },
        }

        if operation_id in bootstrap.CONTROLLER_ROLE_OPERATIONS:
            result["definitionCreated"] = False
            result["definition"] = build_builtin_role_definition_projections(self.plan)[bootstrap.CONTROLLER_BUILTIN_ROLE_ID]
        return result

    def temp_cleanup(self, operation_id):
        add_by_remove = {
            "removeOwnedUploaderPackageRole": "addOwnedUploaderPackageRole",
            "removeOwnedOperatorKeyReadRole": "addOwnedOperatorKeyReadRole",
            "removeOwnedOperatorFenceBootstrapRole": "addOwnedOperatorFenceBootstrapRole",
            "removeOwnedOperatorControllerCanaryRole": "addOwnedOperatorControllerCanaryRole",
        }
        added = self.operations[add_by_remove[operation_id]]["projection"]
        result = {
            "cleanupKey": added["cleanupKey"],
            "assignmentResourceId": added["assignmentResourceId"],
            "definitionResourceId": added["definitionResourceId"],
            "assignmentRemoved": True,
            "definitionRemoved": True,
            "deletionLock": bootstrap._expected_deletion_lock_proof(operation_id),
            "assignmentAbsenceProjection": {
                "resourceId": added["assignmentResourceId"],
                "absent": True,
            },
            "definitionAbsenceProjection": {
                "resourceId": added["definitionResourceId"],
                "absent": True,
            },
        }

        if operation_id in bootstrap.CONTROLLER_ROLE_OPERATIONS:
            result["definitionRemoved"] = False
            del result["definitionAbsenceProjection"]
            result["definitionPreservationProjection"] = {
                "resourceId": added["definitionResourceId"], "present": True,
                "projection": copy.deepcopy(added["definition"]),
            }
        return result

    def site_state(self, state, observed_at):
        resource = self.resources["bridgeSite"]
        return {
            "attempts": 1,
            "observedAt": stamp(observed_at),
            "resourceId": resource["resourceId"],
            "state": state,
            "projectionSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(
                    {"id": resource["resourceId"], "name": resource["name"], "state": state}
                )
            ),
        }

    def build_operations(self):
        app_object = self.guid("publisher-app-object")
        app_client = self.guid("publisher-app-client")
        sp_object = self.guid("publisher-sp-object")
        claim_body = {
            "resourceId": self.authorization["singleUse"]["azureClaimResourceId"],
            "deploymentName": self.authorization["singleUse"]["azureClaimResourceId"].rsplit("/", 1)[-1],
            "provisioningState": "Succeeded",
            "claim": {
                "authorizationId": AUTH_ID,
                "authorizationSha256": self.authorization_sha,
                "sourceSha": MERGE,
                "planSha256": self.plan_sha,
                "packageSha256": self.package["sha256"],
            },
        }
        self.envelope("claimAzureSingleUseAuthorization", claim_body)
        mailbox = self.resources["mailboxResourceGroup"]
        self.envelope(
            "createMailboxResourceGroup",
            {"id": mailbox["resourceId"], "name": mailbox["name"], "type": "Microsoft.Resources/resourceGroups", "location": self.plan["azure"]["location"]},
        )
        self.envelope(
            "createPublisherApplication",
            {"id": app_object, "appId": app_client, "displayName": self.resources["publisherApplication"]["name"], "signInAudience": "AzureADMyOrg", "passwordCredentials": [], "keyCredentials": []},
        )
        service = {
            "id": sp_object,
            "appId": app_client,
            "displayName": self.resources["publisherServicePrincipal"]["name"],
            "accountEnabled": True,
            "servicePrincipalType": "Application",
            "passwordCredentials": [],
            "keyCredentials": [],
            "appRoleAssignments": [],
        }
        self.envelope("createPublisherServicePrincipal", service)
        granted = copy.deepcopy(service)
        granted["appRoleAssignments"] = [
            {
                "id": self.guid("graph-role-assignment"),
                "principalId": sp_object,
                "resourceId": self.guid("graph-resource-sp"),
                "appRoleId": bootstrap.AzureCliBootstrapTransport.GRAPH_APPLICATION_READ_ALL,
            }
        ]
        graph_assignment = granted["appRoleAssignments"][0]
        self.envelope(
            "grantPublisherGraphApplicationReadAll",
            granted,
            runtime_facts={
                "assignmentId": graph_assignment["id"],
                "resourceId": graph_assignment["resourceId"],
            },
        )

        dynamic_identities = {
            "createBridgeIdentity": "bridgeIdentity",
            "createSignerIdentity": "signerIdentity",
            "createProductionActivationIdentity": "productionActivationIdentity",
        }
        for operation_id, resource_key in (
            ("createBridgeIdentity", "bridgeIdentity"),
            ("adoptExistingRegistryWriterIdentity", "registryWriterIdentity"),
            ("adoptExistingRegistryReaderIdentity", "registryReaderIdentity"),
            ("createSignerIdentity", "signerIdentity"),
            ("createProductionActivationIdentity", "productionActivationIdentity"),
        ):
            resource = self.resources[resource_key]
            self.envelope(
                operation_id,
                {
                    "id": resource["resourceId"],
                    "name": resource["name"],
                    "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                    "clientId": resource.get("clientId") or self.guid(f"{operation_id}:client"),
                    "principalId": resource.get("principalId") or self.guid(f"{operation_id}:principal"),
                    "tenantId": bootstrap.TENANT,
                },
            )
        for operation_id, resource_key in (
            ("createPrivatePackageContainer", "packageContainer"),
            ("createPrivateControllerLockContainer", "controllerLockContainer"),
            ("createPrivateActivationFenceContainer", "activationFenceContainer"),
        ):
            resource = self.resources[resource_key]
            self.envelope(
                operation_id,
                {"id": resource["resourceId"], "name": resource["name"], "type": "Microsoft.Storage/storageAccounts/blobServices/containers", "publicAccess": "None"},
            )

        key_uri = (
            "https://kv-mds-sea-9c4e0d0d.vault.azure.net/keys/"
            "paperdesk-release-result-signing/" + "c" * 32
        )
        key_expiry = int(
            bootstrap.parse_time(
                self.contexts["createSigningKeyVersion"]["expiresAt"], "fixture key expiry"
            ).timestamp()
        )
        self.envelope(
            "createSigningKeyVersion",
            {"keyUriWithVersion": key_uri, "kty": "RSA", "keySize": 3072, "keyOps": ["sign", "verify"], "enabled": True, "exportable": False, "expiresAt": key_expiry, "releasePolicy": None},
        )
        definitions = [
            value
            for _key, value in sorted(bootstrap._custom_role_definition_specs(self.plan).items())
        ]
        self.envelope("createCustomRoleDefinitions", {"roleDefinitions": definitions})
        self.envelope(
            "createStoppedPrivateBridge",
            self.webapp("bridgeSite", identity={"type": "None", "userAssignedIdentities": {}}),
        )

        def principal_id(name):
            fixed = self.resources.get(name, {}).get("principalId")
            if fixed:
                return fixed
            dependency = {
                "publisherServicePrincipal": "createPublisherServicePrincipal",
                "bridgeIdentity": "createBridgeIdentity",
                "signerIdentity": "createSignerIdentity",
                "productionActivationIdentity": "createProductionActivationIdentity",
            }[name]
            projection = self.operations[dependency]["projection"]
            return projection["id"] if name == "publisherServicePrincipal" else projection["principalId"]

        assignments = sorted(
            [
                bootstrap._role_assignment_spec(
                    self.plan, role, principal_id(role["principal"])
                )
                for role in self.plan["roleMatrix"]
            ],
            key=lambda item: item["id"].lower(),
        )
        self.envelope("createExactRoleAssignments", {"roleAssignments": assignments})
        attached = {
            self.operations[operation_id]["projection"]["id"]: {
                "clientId": self.operations[operation_id]["projection"]["clientId"],
                "principalId": self.operations[operation_id]["projection"]["principalId"],
            }
            for operation_id in (
                "createBridgeIdentity",
                "adoptExistingRegistryWriterIdentity",
                "adoptExistingRegistryReaderIdentity",
                "createSignerIdentity",
                "createProductionActivationIdentity",
            )
        }
        self.envelope(
            "attachFiveUamisOnlyToBridge",
            self.webapp(
                "bridgeSite",
                identity={"type": "UserAssigned", "userAssignedIdentities": attached},
            ),
        )

        add_acl = copy.deepcopy(self.contexts["addOwnedUploaderIpv4Rule"]["preNetworkAcls"])
        add_acl["ipRules"] = [{"value": "203.0.113.10", "action": "Allow"}]
        self.envelope(
            "addOwnedUploaderIpv4Rule",
            {
                "networkAclsSha256": bootstrap.sha256_bytes(bootstrap.canonical_json_bytes(add_acl)),
                "defaultAction": add_acl["defaultAction"],
                "bypass": add_acl["bypass"],
                "ipRuleCount": 1,
                "resourceAccessRuleCount": 0,
                "virtualNetworkRules": add_acl["virtualNetworkRules"],
            },
        )
        for operation_id in (
            "addOwnedUploaderPackageRole",
            "addOwnedOperatorKeyReadRole",
            "addOwnedOperatorFenceBootstrapRole",
            "addOwnedOperatorControllerCanaryRole",
        ):
            self.envelope(operation_id, self.temp_role(operation_id))
        controller_projection = self.operations[
            "createPrivateControllerLockContainer"
        ]["projection"]
        self.envelope(
            "proveControllerLockContainerEmpty",
            {
                "containerUrl": (
                    "https://mdspdbak2608089c4e.blob.core.windows.net/"
                    "paperdesk-release-controller-lock"
                ),
                "listUrl": (
                    "https://mdspdbak2608089c4e.blob.core.windows.net/"
                    "paperdesk-release-controller-lock?restype=container&comp=list"
                ),
                "httpStatus": 200,
                "blobNames": [],
                "blobCount": 0,
                "nextMarker": "",
                "responseSha256": self.digest(
                    "response:proveControllerLockContainerEmpty"
                ),
                "observedAt": stamp(NOW + dt.timedelta(minutes=1)),
                "privateContainerPosture": copy.deepcopy(controller_projection),
                "controllerContainerDecision": self.contexts[
                    "createPrivateControllerLockContainer"
                ]["executionDecision"],
            },
        )

        package_contract = bootstrap._validator_contract(
            "operation:uploadVersionedBridgePackage", self.plan, self.authorization
        )
        package_version = "2026-08-30T04:01:00.0000000Z"
        package_etag = '"package-etag"'
        package_blob = f"v2/control/{MERGE}/paperdesk-private-release-bridge.zip"
        self.envelope(
            "uploadVersionedBridgePackage",
            {"url": package_contract["expectedUrl"], "blob": package_blob, "etag": package_etag, "versionId": package_version, "sha256": self.package["sha256"], "size": self.package["size"], "bodySha256": self.package["sha256"], "bodySize": self.package["size"]},
            headers={"etag": package_etag, "versionId": package_version},
        )
        modulus = base64.urlsafe_b64encode(b"\x80" + b"\x00" * 383).decode().rstrip("=")
        self.envelope(
            "readBackExactSigningPublicJwk",
            {
                "kid": key_uri,
                "kty": "RSA",
                "n": modulus,
                "e": "AQAB",
                "key_ops": ["sign", "verify"],
                "attributes": {
                    "enabled": True,
                    "nbf": int(NOW.timestamp()),
                    "exp": key_expiry,
                    "created": int(NOW.timestamp()),
                    "updated": int((NOW + dt.timedelta(seconds=1)).timestamp()),
                    "recoveryLevel": "Recoverable+Purgeable",
                    "recoverableDays": 90,
                    "exportable": False,
                },
            },
        )
        fence_contract = bootstrap._validator_contract(
            "operation:createInitialIdleActivationFence", self.plan, self.authorization
        )
        fence_etag = '"fence-etag"'
        fence_version = "2026-08-30T04:01:30.0000000Z"
        self.envelope(
            "createInitialIdleActivationFence",
            {"url": fence_contract["expectedUrl"], "etag": fence_etag, "versionId": fence_version, "sha256": fence_contract["expectedBodySha256"], "bodySha256": fence_contract["expectedBodySha256"], "bodySize": fence_contract["expectedBodySize"]},
            headers={
                "etag": fence_etag,
                "versionId": fence_version,
                "leaseState": "Available",
                "leaseStatus": "Unlocked",
            },
        )
        controller_contract = bootstrap._validator_contract(
            "operation:createControllerLeaseCanaryBlob", self.plan, self.authorization
        )
        controller_etag = '"controller-etag"'
        controller_version = "2026-08-30T04:02:00.0000000Z"
        self.envelope(
            "createControllerLeaseCanaryBlob",
            {"url": controller_contract["expectedUrl"], "etag": controller_etag, "versionId": controller_version, "sha256": controller_contract["expectedBodySha256"], "cleanupKey": "controller-lease-canary-blob", "bodySha256": controller_contract["expectedBodySha256"], "bodySize": controller_contract["expectedBodySize"]},
            headers={"etag": controller_etag, "versionId": controller_version},
        )
        lease_body = {
            "url": controller_contract["expectedUrl"],
            "leaseId": self.plan["temporaryAccess"]["controllerLeaseId"],
            "durationSeconds": 60,
            "renewals": 1,
            "releaseStatus": 200,
            "identity": {"kind": "authorized-local-azure-account", "objectId": ACCOUNT_OBJECT},
            "fastLane": {"acquiredAt": stamp(NOW + dt.timedelta(minutes=2)), "renewedAt": [stamp(NOW + dt.timedelta(minutes=2, seconds=20))], "releasedAt": stamp(NOW + dt.timedelta(minutes=2, seconds=40)), "finalLeaseState": "available"},
            "expiryFallback": {"leaseId": self.plan["temporaryAccess"]["controllerExpiryLeaseId"], "acquiredAt": stamp(NOW + dt.timedelta(minutes=3)), "releaseIntentionallyOmitted": True, "expiredAt": stamp(NOW + dt.timedelta(minutes=4, seconds=1)), "pollAttempts": 3, "finalLeaseState": "expired", "finalLeaseStatus": "unlocked", "finalLeaseDuration": None},
            "selfCleaned": True,
        }
        self.envelope(
            "exerciseControllerLeaseCanary",
            lease_body,
            headers={"leaseState": "Expired", "leaseStatus": "Unlocked"},
        )
        controller_container_url = (
            "https://mdspdbak2608089c4e.blob.core.windows.net/"
            + self.resources["controllerLockContainer"]["name"]
        )
        self.envelope(
            "removeControllerLeaseCanaryBlob",
            {
                "absent": True,
                "controllerLockInventory": {
                    "containerUrl": controller_container_url,
                    "listUrl": controller_container_url + "?restype=container&comp=list",
                    "httpStatus": 200,
                    "blobNames": [],
                    "blobCount": 0,
                    "nextMarker": "",
                },
            },
        )
        for operation_id in (
            "removeOwnedOperatorControllerCanaryRole",
            "removeOwnedOperatorFenceBootstrapRole",
            "removeOwnedOperatorKeyReadRole",
            "removeOwnedUploaderPackageRole",
        ):
            self.envelope(operation_id, self.temp_cleanup(operation_id))
        restore_acl = self.contexts["removeOwnedUploaderIpv4Rule"]["restoreNetworkAcls"]
        self.envelope(
            "removeOwnedUploaderIpv4Rule",
            {"networkAclsSha256": bootstrap.sha256_bytes(bootstrap.canonical_json_bytes(restore_acl)), "defaultAction": restore_acl["defaultAction"], "bypass": restore_acl["bypass"], "ipRuleCount": 0, "resourceAccessRuleCount": 0, "virtualNetworkRules": restore_acl["virtualNetworkRules"]},
        )

        configure_context = self.contexts[
            "configureBridgeExactVersionedPackageAndCriticalSettings"
        ]
        control = bootstrap._bootstrap_self_test_control_from_projections(
            self.authorization, self.operations,
            {"bootstrapSelfTestIssuedAt": stamp(NOW), "bootstrapSelfTestExpiresAt": stamp(NOW + dt.timedelta(seconds=900))},
        )
        upload = self.operations["uploadVersionedBridgePackage"]["projection"]
        package_url = upload["url"] + "?versionid=" + urllib.parse.quote(
            upload["versionId"], safe=""
        )
        desired_settings = dict(configure_context["preAppSettings"])
        desired_settings.update(
            {
                "WEBSITE_RUN_FROM_PACKAGE": package_url,
                "WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID": self.resources["registryReaderIdentity"]["resourceId"],
                "WEBSITE_SKIP_RUNNING_KUDUAGENT": "false",
                "PAPERDESK_BRIDGE_PACKAGE_SHA256": self.package["sha256"],
                "PAPERDESK_BRIDGE_BOOTSTRAP_SELF_TEST_JSON": bootstrap.canonical_json_bytes(control).decode("utf-8"),
            }
        )
        self.envelope(
            "configureBridgeExactVersionedPackageAndCriticalSettings",
            {"preAppSettingsSha256": configure_context["preAppSettingsSha256"], "settingsSha256": bootstrap.sha256_bytes(bootstrap.canonical_json_bytes(desired_settings)), "bootstrapSelfTestControlSha256": bootstrap.sha256_bytes(bootstrap.canonical_json_bytes(control)), "packageUrl": package_url, "packageVersionId": upload["versionId"], "bootstrapSelfTestIssuedAt": control["issuedAt"], "bootstrapSelfTestExpiresAt": control["expiresAt"], "settingsRequestBodySha256": bootstrap.sha256_bytes(bootstrap.canonical_json_bytes({"properties": desired_settings}))},
        )

        def worm(operation_id):
            target = self.resources[self.mutations[operation_id]["target"]]["resourceId"]
            return {"id": target + "/immutabilityPolicies/default", "name": "default", "type": "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies", "etag": f'"{operation_id}-etag"', "properties": {"state": "Locked", "immutabilityPeriodSinceCreationInDays": 91, "allowProtectedAppendWrites": False, "allowProtectedAppendWritesAll": False}, "stateAfterPut": "Locked", "lockPostIssued": False}

        self.envelope("lockPackageRetentionAt91Days", worm("lockPackageRetentionAt91Days"))

        site = self.resources["bridgeSite"]
        terminal = {
            "historyId": site["resourceId"] + "/triggeredwebjobs/paperdesk-accepted-release-registry/history/fresh-run",
            "webJobsRunId": "fresh-run",
            "status": "Success",
            "startedAt": stamp(NOW + dt.timedelta(minutes=5, seconds=4)),
            "endedAt": stamp(NOW + dt.timedelta(minutes=5, seconds=6)),
            "outputUrlMetadata": {"scheme": "https", "host": site["name"] + ".scm.azurewebsites.net", "pathSha256": self.digest("webjob-output-path"), "queryPresent": False},
        }
        canary = {
            "resourceId": site["resourceId"],
            "cleanupKey": "bounded-bridge-canary-start",
            "selfCleaned": True,
            "initialStopped": self.site_state("Stopped", NOW + dt.timedelta(minutes=5)),
            "running": self.site_state("Running", NOW + dt.timedelta(minutes=5, seconds=1)),
            "triggerStatus": 202,
            "triggerRequestedAt": stamp(NOW + dt.timedelta(minutes=5, seconds=3)),
            "historyBoundary": {"observedAt": stamp(NOW + dt.timedelta(minutes=5, seconds=2)), "entries": [], "entriesSha256": bootstrap.sha256_bytes(bootstrap.canonical_json_bytes([])), "responseSha256": self.digest("webjob-boundary-response")},
            "terminalHistory": terminal,
            "terminalHistoryObservedAt": stamp(NOW + dt.timedelta(minutes=5, seconds=7)),
            "terminalHistoryEntriesSha256": bootstrap.sha256_bytes(bootstrap.canonical_json_bytes([terminal])),
            "terminalHistoryResponseSha256": self.digest("webjob-terminal-response"),
            "pollAttempts": 2,
            "stopped": self.site_state("Stopped", NOW + dt.timedelta(minutes=5, seconds=8)),
            "package": {key: upload[key] for key in ("blob", "etag", "versionId", "url", "sha256", "size")},
            "settingsSha256": self.operations["configureBridgeExactVersionedPackageAndCriticalSettings"]["projection"]["settingsSha256"],
            "bootstrapSelfTestControlSha256": self.operations["configureBridgeExactVersionedPackageAndCriticalSettings"]["projection"]["bootstrapSelfTestControlSha256"],
            "activationFence": {key: self.operations["createInitialIdleActivationFence"]["projection"][key] for key in ("url", "etag", "versionId", "sha256")},
            "proofBoundary": "terminal Success proves execution of the exact source/package-pinned bootstrap branch; HTTP health and literal stdout marker bytes were not observed",
        }
        self.envelope("startBridgeForBoundedCanary", canary)
        self.envelope(
            "extendAcceptedRetentionFrom30To91Days",
            worm("extendAcceptedRetentionFrom30To91Days"),
        )
        self.envelope(
            "extendResultRetentionFrom30To91Days",
            worm("extendResultRetentionFrom30To91Days"),
        )
        self.envelope(
            "detachWriterAndReaderFromLegacyBridge",
            self.webapp("legacyBridgeSite", identity={"type": "None", "userAssignedIdentities": {}}),
        )
        for operation_id in (
            "removeLegacyWriterResultAssignment",
            "removeLegacyReaderResultAssignment",
        ):
            self.envelope(operation_id, {
                "absent": True,
                "deletionLock": bootstrap._expected_deletion_lock_proof(operation_id),
            })
        self.envelope(
            "retireLegacyPublisherFic",
            {"applicationObjectId": self.plan["legacyPublisherRetirement"]["applicationObjectId"], "removedFederatedCredentialId": self.contexts["retireLegacyPublisherFic"]["legacyFederatedCredentialId"], "federatedIdentityCredentials": []},
        )
        for operation_id in (
            "retireLegacyPublisherMutatorAssignment",
            "retireLegacyPublisherSitesReadAssignment",
            "retireLegacyPublisherResultReadAssignment",
        ):
            body = {"absent": True}
            lock_proof = bootstrap._expected_deletion_lock_proof(operation_id)
            if lock_proof is not None:
                body["deletionLock"] = lock_proof
            self.envelope(operation_id, body)
        fic = self.resources["publisherFederatedCredential"]
        self.envelope(
            "createSolePublisherFicToSignedBootstrapSource",
            {
                "applicationObjectId": app_object,
                "federatedIdentityCredentials": [
                    {
                        "id": self.guid("publisher-fic"),
                        "name": fic["name"],
                        "issuer": fic["issuer"],
                        "audiences": fic["audiences"],
                        "subject": None,
                        "claimsMatchingExpression": {"languageVersion": fic["claimsMatchingExpressionLanguageVersion"], "value": fic["claimsMatchingExpressionTemplate"].replace("${authorization.source.mergedMain.commitSha}", MERGE)},
                    }
                ],
            },
        )
        return self.operations

    def mutation_journal(self):
        journal = []

        def exact_url(normalized):
            # The source helper compares path segments case-insensitively, but
            # Microsoft Graph's concrete request contract retains these two
            # camel-cased segments.  Restore the actual request spelling in
            # the deterministic journal fixture.
            return normalized.replace(
                "/serviceprincipals", "/servicePrincipals"
            ).replace(
                "/approleassignments", "/appRoleAssignments"
            ).replace(
                "/federatedidentitycredentials",
                "/federatedIdentityCredentials",
            )

        operation_by_id = {
            item["id"]: item
            for item in self.plan["mutations"]
            if item["kind"] != "local-create-only-canonical-evidence"
        }
        for operation_id in operation_by_id:
            required, _optional = bootstrap._expected_terminal_mutation_targets(
                operation_id,
                plan=self.plan,
                authorization_id=self.authorization["authorizationId"],
                source_sha=self.authorization["source"]["mergedMain"]["commitSha"],
                operation_projections=self.operations,
                operation_contexts=self.contexts,
            )
            def mutation_order(item):
                target = item[0]
                method, url = target.split(" ", 1)
                is_lock = "/providers/microsoft.authorization/locks/" in url.lower()
                if is_lock:
                    return (0 if method == "DELETE" else 2, target)
                if method == "DELETE" and "/roleassignments/" in url.lower():
                    return (1, target)
                return (3, target)

            for target, count in sorted(required.items(), key=mutation_order):
                method, normalized_url = target.split(" ", 1)
                target_url = exact_url(normalized_url)
                if "/providers/microsoft.authorization/locks/" in target_url.lower():
                    target_url = ("https://management.azure.com"
                        + bootstrap._expected_deletion_lock_proof(operation_id)["resourceId"]
                        + "?api-version=2016-09-01")
                elif (bootstrap._expected_deletion_lock_proof(operation_id) is not None
                      and "/roleassignments/" in target_url.lower()):
                    target_url = ("https://management.azure.com"
                        + bootstrap._cleanup_assignment_resources(self.execution_plan)[operation_id]
                        + "?api-version=2022-04-01")
                for occurrence in range(count):
                    intent_sequence = len(journal) + 1
                    intent_id = f"cloud-mutation-{intent_sequence:04d}"
                    recorded = NOW + dt.timedelta(milliseconds=intent_sequence * 10)
                    is_storage = (
                        (urllib.parse.urlsplit(target_url).hostname or "").lower()
                        == "mdspdbak2608089c4e.blob.core.windows.net"
                    )
                    client_request_id = (
                        self.guid(
                            f"storage-client-request:{operation_id}:{target_url}:{occurrence}"
                        )
                        if is_storage
                        else None
                    )
                    intent = {
                        "sequence": intent_sequence,
                        "phase": "intent",
                        "intentId": intent_id,
                        "operationId": operation_id,
                        "temporary": operation_by_id[operation_id].get("temporary")
                        is True,
                        "method": method,
                        "targetUrl": target_url,
                        "requestBodySha256": self.digest(
                            f"{operation_id}:{target_url}:{occurrence}:request"
                        ),
                        "clientRequestId": client_request_id,
                        "status": None,
                        "responseBodySha256": None,
                        "etag": None,
                        "versionId": None,
                        "requestId": None,
                        "serverDate": None,
                        "storageErrorCode": None,
                        "recordedAt": stamp(recorded),
                    }
                    if "/providers/microsoft.authorization/locks/" in target_url.lower():
                        lock_proof = bootstrap._expected_deletion_lock_proof(operation_id)
                        request_bytes = (b"" if method == "DELETE" else
                            bootstrap.canonical_json_bytes({"properties": lock_proof["properties"]}))
                        intent["requestBodySha256"] = bootstrap.sha256_bytes(request_bytes)
                    journal.append(intent)
                    if operation_id == "configureBridgeExactVersionedPackageAndCriticalSettings":
                        intent["requestBodySha256"] = self.operations[operation_id]["projection"]["settingsRequestBodySha256"]
                    result = copy.deepcopy(intent)
                    versioned_headers = (
                        self.operations[operation_id]["headers"]
                        if operation_id
                        in {
                            "uploadVersionedBridgePackage",
                            "createInitialIdleActivationFence",
                        }
                        else {}
                    )
                    result.update(
                        {
                            "sequence": len(journal) + 1,
                            "phase": "result",
                            "status": (
                                201
                                if operation_id
                                in {
                                    "claimAzureSingleUseAuthorization",
                                    "uploadVersionedBridgePackage",
                                    "createInitialIdleActivationFence",
                                }
                                else 200
                            ),
                            "responseBodySha256": self.digest(
                                f"{operation_id}:{target_url}:{occurrence}:response"
                            ),
                            "etag": versioned_headers.get("etag"),
                            "versionId": versioned_headers.get("versionId"),
                            "requestId": (
                                self.guid(
                                    f"storage-service-request:{operation_id}:{target_url}:{occurrence}"
                                )
                                if is_storage
                                else None
                            ),
                            "serverDate": (
                                recorded.strftime(
                                    "%a, %d %b %Y %H:%M:%S GMT"
                                )
                                if is_storage
                                else None
                            ),
                            "storageErrorCode": "unknown" if is_storage else None,
                            "recordedAt": stamp(
                                recorded + dt.timedelta(milliseconds=5)
                            ),
                        }
                    )
                    journal.append(result)
        return journal

    def postcondition_local(self, postcondition_id, journal):
        policy = bootstrap._postcondition_semantic_policy(postcondition_id, self.plan)
        family = policy["family"]
        if family == "local-source-dormancy":
            contract, _ = bootstrap.load_json(bootstrap.ACTIVATION_CONTRACT_PATH)
            return {
                "contractPath": "contracts/private_release_mailbox_contract.json",
                "contractSha256": bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes(contract)
                ),
                "status": "source-dormant",
                "activationFieldCount": len(contract["activation"]),
                "allActivationValuesNull": True,
            }
        if family == "pairwise-identity-inventory":
            identities = []
            for operation_id in policy["requiredOperationIds"]:
                candidate = self.operations[operation_id]["projection"]
                identities.append(
                    {
                        "operationId": operation_id,
                        "clientId": (
                            candidate["appId"]
                            if operation_id == "createPublisherServicePrincipal"
                            else candidate["clientId"]
                        ),
                        "principalId": (
                            candidate["id"]
                            if operation_id == "createPublisherServicePrincipal"
                            else candidate["principalId"]
                        ),
                    }
                )
            production = self.resources["productionSystemIdentity"]
            identities.append(
                {
                    "operationId": "fixedProductionSystemIdentity",
                    "clientId": production["clientId"],
                    "principalId": production["principalId"],
                }
            )
            return {"identities": identities, "pairwiseDistinct": True}
        if family == "role-definition-and-assignment-inventories":
            return {
                "expectedRoleRecordCount": len(self.plan["roleMatrix"]),
                "roleDefinitions": self.operations["createCustomRoleDefinitions"][
                    "projection"
                ]["roleDefinitions"],
                "roleAssignments": self.operations["createExactRoleAssignments"][
                    "projection"
                ]["roleAssignments"],
            }
        if family in {
            "production-pre-post-equality-and-zero-write-journal",
            "forbidden-target-journal-audit",
            "vault-posture-plus-no-journal-write",
        }:
            return {
                "schemaVersion": 1,
                "recordCount": len(journal),
                "mutationJournal": copy.deepcopy(journal),
                "journalSha256": bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes(journal)
                ),
                "unresolvedIntentCount": 0,
                "productionWriteCount": 0,
                "acceptedContainerWriteJournal": [],
            }
        if family == "terminal-source-inputs-ready-for-local-assembly":
            outputs = self.plan["evidenceOutputs"]
            return {
                "status": "ready-for-create-only-local-terminal-assembly",
                "expectedOperationProofCount": len(self.operations),
                "expectedPriorPostconditionProofCount": next(
                    index
                    for index, item in enumerate(self.plan["postconditions"])
                    if item["id"] == postcondition_id
                ),
                "mutationJournalSha256": bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes(journal)
                ),
                "requiredS2EvidencePaths": [
                    outputs["provisioningEvidencePath"],
                    outputs["bridgeRuntimeReceiptPath"],
                    outputs["temporaryAccessCleanupReceiptPath"],
                    outputs["activationFenceReceiptPath"],
                    outputs["bridgeCanaryReceiptPath"],
                ],
                "terminalBundlePath": outputs["terminalBundlePath"],
                "terminalBundleCreated": False,
            }
        return {
            "requiredOperationProjectionCount": len(policy["requiredOperationIds"])
        }

    def build_postconditions(self, journal):
        admission_by_id = {
            item["postconditionId"]: item
            for item in self.projection["postconditionAdmissions"]
        }
        claim = self.operations["claimAzureSingleUseAuthorization"]
        values = []
        for index, postcondition in enumerate(self.plan["postconditions"]):
            postcondition_id = postcondition["id"]
            policy = bootstrap._postcondition_semantic_policy(
                postcondition_id, self.plan
            )
            probes = [
                {
                    "id": probe_id,
                    "validatorId": f"postcondition:{postcondition_id}",
                    "status": 200,
                    "responseSha256": claim["responseSha256"],
                    "sourceProjection": None,
                    "attempts": 1,
                    "startedAt": stamp(NOW + dt.timedelta(minutes=6, seconds=index)),
                    "observedAt": stamp(
                        NOW + dt.timedelta(minutes=6, seconds=index, milliseconds=100)
                    ),
                }
                for probe_id in admission_by_id[postcondition_id]["probeIds"]
            ]
            source = {
                "schemaVersion": 1,
                "postconditionId": postcondition_id,
                "predicateSha256": bootstrap.sha256_bytes(
                    postcondition["predicate"].encode("utf-8")
                ),
                "semanticPolicy": policy,
                "claimPersistenceProbes": probes,
                "requiredOperationProjections": [
                    {
                        "operationId": operation_id,
                        "sourceProjections": [
                            copy.deepcopy(self.operations[operation_id])
                        ],
                    }
                    for operation_id in policy["requiredOperationIds"]
                ],
                "localProjection": self.postcondition_local(
                    postcondition_id, journal
                ),
            }
            values.append(
                {
                    "postconditionId": postcondition_id,
                    "sourceProjection": source,
                    "observedAt": stamp(
                        NOW + dt.timedelta(minutes=6, seconds=index, milliseconds=200)
                    ),
                }
            )
        return values

    def rich_provisioning(self):
        application = self.operations["createPublisherApplication"]["projection"]
        service = self.operations["createPublisherServicePrincipal"]["projection"]
        assignments = self.operations["createExactRoleAssignments"]["projection"][
            "roleAssignments"
        ]
        custom = bootstrap._custom_role_definition_specs(self.plan)
        built_in = self.contexts["createCustomRoleDefinitions"][
            "builtInRoleDefinitionProjections"
        ]
        role_definitions = {}
        role_assignments = {}
        for role in self.plan["roleMatrix"]:
            role_definitions[role["name"]] = (
                built_in[role["definitionId"]]
                if role.get("definitionKind") == "BuiltInRole"
                else custom[role["definitionId"]]
            )
            role_assignments[role["name"]] = (
                bootstrap._normalized_role_assignment_projection(
                    next(
                        item
                        for item in assignments
                        if item["name"].lower() == role["assignmentId"].lower()
                    )
                )
            )
        principal_dependencies = {
            "publisherServicePrincipal": (
                "publisher",
                self.operations["createPublisherServicePrincipal"]["projection"]["id"],
            ),
            "bridgeIdentity": (
                "bridge",
                self.operations["createBridgeIdentity"]["projection"]["principalId"],
            ),
            "registryWriterIdentity": (
                "registryWriter",
                self.resources["registryWriterIdentity"]["principalId"],
            ),
            "registryReaderIdentity": (
                "registryReader",
                self.resources["registryReaderIdentity"]["principalId"],
            ),
            "signerIdentity": (
                "signer",
                self.operations["createSignerIdentity"]["projection"]["principalId"],
            ),
            "productionActivationIdentity": (
                "productionActivation",
                self.operations["createProductionActivationIdentity"]["projection"]["principalId"],
            ),
            "productionSystemIdentity": (
                "productionSystem",
                self.resources["productionSystemIdentity"]["principalId"],
            ),
        }
        inventories = {
            name: sorted(
                [
                    bootstrap._normalized_role_assignment_projection(item)
                    for item in assignments
                    if item["properties"]["principalId"] == principal_id
                ],
                key=lambda item: item["id"].lower(),
            )
            for _key, (name, principal_id) in principal_dependencies.items()
        }
        sole_fic = copy.deepcopy(
            self.operations["createSolePublisherFicToSignedBootstrapSource"][
                "projection"
            ]["federatedIdentityCredentials"][0]
        )
        subnet = self.resources["integrationSubnet"]["resourceId"]
        vnet = self.resources["integrationVnet"]["resourceId"]
        return {
            "publisherApplication": {
                "id": application["id"],
                "appId": application["appId"],
                "signInAudience": application["signInAudience"],
                "passwordCredentialKeyIds": [],
                "keyCredentialKeyIds": [],
            },
            "publisherServicePrincipal": {
                "id": service["id"],
                "appId": service["appId"],
                "accountEnabled": service["accountEnabled"],
                "servicePrincipalType": service["servicePrincipalType"],
                "passwordCredentialKeyIds": [],
                "keyCredentialKeyIds": [],
            },
            "solePublisherFederatedCredentials": [sole_fic],
            "roleDefinitions": role_definitions,
            "roleAssignments": role_assignments,
            "principalDirectAssignments": inventories,
            "principalEffectiveAssignments": copy.deepcopy(inventories),
            "controllerLockContainer": self.operations[
                "createPrivateControllerLockContainer"
            ]["projection"],
            "controllerLockInitialEmptyProof": self.operations[
                "proveControllerLockContainerEmpty"
            ]["projection"],
            "networkTopology": {
                "virtualNetwork": {"id": vnet, "type": "Microsoft.Network/virtualNetworks", "addressSpacePrefixes": ["10.41.0.0/16"]},
                "integrationSubnet": {"id": subnet, "type": "Microsoft.Network/virtualNetworks/subnets", "virtualNetworkResourceId": vnet, "delegations": ["Microsoft.Web/serverFarms"], "serviceEndpoints": [{"service": "Microsoft.Storage", "provisioningState": "Succeeded"}], "routeTableResourceId": None, "networkSecurityGroupResourceId": None},
                "packageStorageAccount": {"id": self.resources["storageAccount"]["resourceId"], "type": "Microsoft.Storage/storageAccounts", "publicNetworkAccess": "Enabled", "allowBlobPublicAccess": False, "defaultAction": "Deny", "bypass": "None", "ipRules": [], "resourceAccessRules": [], "virtualNetworkRules": [{"id": subnet, "action": "Allow", "state": "Succeeded"}]},
                "productionSite": {"id": self.resources["productionSite"]["resourceId"], "type": "Microsoft.Web/sites", "virtualNetworkSubnetId": subnet, "outboundVnetRouting": {"allTraffic": False, "applicationTraffic": True}, "legacyVnetRouteAllEnabled": True},
            },
        }

    def build_evidence(self):
        self.build_operations()
        journal = self.mutation_journal()
        postconditions = self.build_postconditions(journal)
        upload = self.operations["uploadVersionedBridgePackage"]["projection"]
        reader = self.operations["adoptExistingRegistryReaderIdentity"]["projection"]
        canary = self.operations["startBridgeForBoundedCanary"]["projection"]
        controller = self.operations["exerciseControllerLeaseCanary"]
        controller_body = controller["projection"]
        bridge_canary = {
            "webJobTerminal": {
                "status": "Success",
                "invocationId": canary["terminalHistory"]["webJobsRunId"],
                "sourceSha": MERGE,
                "packageSha256": self.package["sha256"],
                "packageVersionId": upload["versionId"],
                "startedAt": canary["terminalHistory"]["startedAt"],
                "completedAt": canary["terminalHistory"]["endedAt"],
            },
            "sourceDerivedExpectedMarker": bootstrap._source_derived_bridge_marker(
                plan=self.plan,
                authorization=self.authorization,
                prior=self.operations,
            ),
        }
        controller_sha = bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(controller)
        )
        lease_sources = {
            "controllerLease": {
                "observationStatus": "directly-observed",
                "operationSourceProjection": controller,
                "leaseIdSha256": bootstrap.sha256_bytes(
                    self.plan["temporaryAccess"]["controllerLeaseId"].encode("utf-8")
                ),
                "targetResourceId": controller_body["url"],
                "actor": {"actorType": "authorized-local-operator", "actorObjectId": ACCOUNT_OBJECT, "actorResourceId": ""},
            },
            "activationFenceLease": {
                "observationStatus": "source-derived-from-terminal-success-not-directly-observed",
                "leaseIdSha256": bootstrap.sha256_bytes(self.plan["temporaryAccess"]["activationFenceLeaseId"].encode("utf-8")),
                "targetResourceId": self.resources["activationFenceBlob"]["resourceId"],
                "actor": {"actorType": "bridge-managed-identity", "actorObjectId": self.operations["createBridgeIdentity"]["projection"]["principalId"], "actorResourceId": self.resources["bridgeIdentity"]["resourceId"]},
                "sourceControlSha256": self.operations["configureBridgeExactVersionedPackageAndCriticalSettings"]["projection"]["bootstrapSelfTestControlSha256"],
                "terminalOperationSourceProjectionSha256": bootstrap.sha256_bytes(bootstrap.canonical_json_bytes(self.operations["startBridgeForBoundedCanary"])),
                "expectedActions": ["acquire", "read", "renew", "release", "head-available"],
                "expectedFinalLeaseState": "Available",
            },
            "cleanupFastLane": {"observationStatus": "directly-observed", "controllerOperationSourceProjectionSha256": controller_sha, "stateTransitions": controller_body["fastLane"], "observedAt": stamp(NOW + dt.timedelta(minutes=4, seconds=2))},
            "cleanupExpiryFallback": {"observationStatus": "directly-observed", "controllerOperationSourceProjectionSha256": controller_sha, "deadlineSeconds": 60, "stateTransitions": controller_body["expiryFallback"], "observedAt": stamp(NOW + dt.timedelta(minutes=4, seconds=2))},
        }
        cleanup_operations = {
            "packageIpv4Rule": "removeOwnedUploaderIpv4Rule",
            "packageUploaderRole": "removeOwnedUploaderPackageRole",
            "operatorKeyReadRole": "removeOwnedOperatorKeyReadRole",
            "operatorFenceRole": "removeOwnedOperatorFenceBootstrapRole",
            "operatorControllerRole": "removeOwnedOperatorControllerCanaryRole",
        }
        cleanup = {
            name: {
                "httpStatus": 200 if name == "packageIpv4Rule" else 404,
                "present": False,
                "sanitizedProjection": self.operations[operation_id],
                "observedAt": stamp(NOW + dt.timedelta(minutes=4, seconds=3)),
            }
            for name, operation_id in cleanup_operations.items()
        }
        worm_map = {
            "acceptedReleases": ("acceptedContainer", "extendAcceptedRetentionFrom30To91Days"),
            "webJobResults": ("resultContainer", "extendResultRetentionFrom30To91Days"),
            "deploymentPackages": ("packageContainer", "lockPackageRetentionAt91Days"),
        }
        worm = {
            name: {
                "container": {
                    "id": self.resources[resource_key]["resourceId"],
                    "name": f"default/{self.resources[resource_key]['name']}",
                    "type": "Microsoft.Storage/storageAccounts/blobServices/containers",
                    "publicAccess": "None",
                },
            "policy": bootstrap._worm_final_policy_projection(
                self.operations[operation_id]["projection"]
            ),
            }
            for name, (resource_key, operation_id) in worm_map.items()
        }
        production_projection = copy.deepcopy(
            self.projection["productionBoundaryObservation"]["sourceProjection"]
        )
        claim_projection = self.operations["claimAzureSingleUseAuthorization"]["projection"]
        expected_permanent = [
            item
            for item in self.plan["mutations"]
            if item.get("temporary") is not True
            and item["kind"] != "local-create-only-canonical-evidence"
        ]
        evidence = {
            "schemaVersion": 1,
            "evidenceType": "paperdesk-private-release-v2-bootstrap-source-evidence-v1",
            "authorizationId": AUTH_ID,
            "authorizationSha256": self.authorization_sha,
            "mergedSourceSha": MERGE,
            "treeSha": TREE,
            "planSha256": self.plan_sha,
            "authorizedPreflightProjection": bootstrap.sanitize_authorized_preflight_projection(self.projection),
            "claimReceipt": {
                "schemaVersion": 1,
                "evidenceType": "paperdesk-private-release-v2-bootstrap-one-shot-claim-proof-v1",
                "authorizationId": AUTH_ID,
                "authorizationSha256": self.authorization_sha,
                "source": {"mergedSourceSha": MERGE, "treeSha": TREE},
                "plan": {"path": self.authorization["plan"]["path"], "sha256": self.plan_sha},
                "package": {"sourceSha": MERGE, "sha256": self.package["sha256"], "size": self.package["size"]},
                "azureClaimResourceId": self.authorization["singleUse"]["azureClaimResourceId"],
                "createHttpStatus": 201,
                "createResponseProjection": claim_projection,
                "readbackHttpStatus": 200,
                "readbackProjection": copy.deepcopy(claim_projection),
                "claimedAt": stamp(NOW),
                "observedAt": stamp(NOW + dt.timedelta(seconds=1)),
            },
            "allOperationProjections": [
                {
                    "operationId": mutation["id"],
                    "sourceProjection": self.operations[mutation["id"]],
                    "observedAt": stamp(NOW + dt.timedelta(minutes=1)),
                }
                for mutation in self.plan["mutations"]
                if mutation["kind"] != "local-create-only-canonical-evidence"
            ],
            "permanentMutationProjections": [
                {
                    "mutationId": mutation["id"],
                    "target": mutation["target"],
                    "kind": mutation["kind"],
                    "outcome": bootstrap._expected_permanent_outcome(
                        mutation, self.contexts[mutation["id"]]
                    ),
                    "sourceProjection": self.operations[mutation["id"]],
                    "observedAt": stamp(NOW + dt.timedelta(minutes=1)),
                }
                for mutation in expected_permanent
            ],
            "postconditionProjections": postconditions,
            "packageReadbackProjection": {"blobName": upload["blob"], "versionId": upload["versionId"], "etag": upload["etag"], "httpStatus": 200, "bytesObservedInMemory": True, "bytesSha256": self.package["sha256"], "size": self.package["size"], "metadataSha256": self.package["sha256"], "observedAt": stamp(NOW + dt.timedelta(minutes=5, seconds=9))},
            "managedIdentityFetchResponseProjection": {"evidenceMode": "source-derived-from-terminal-success-not-directly-observed", "directPackageBytesObservedByExecutor": False, "identityResourceId": reader["id"], "identityClientId": reader["clientId"], "identityPrincipalId": reader["principalId"], "authentication": "platform-run-from-package-managed-identity", "packageBlobName": upload["blob"], "packageVersionId": upload["versionId"], "expectedPackageSha256": self.package["sha256"], "expectedPackageSize": self.package["size"], "sourceControlSha256": self.operations["configureBridgeExactVersionedPackageAndCriticalSettings"]["projection"]["bootstrapSelfTestControlSha256"], "webJobInvocationId": canary["terminalHistory"]["webJobsRunId"], "terminalStatus": "Success", "observedAt": stamp(NOW + dt.timedelta(minutes=5, seconds=9))},
            "bridgeCanaryProof": bridge_canary,
            "leaseCanaryProofs": lease_sources,
            "richProvisioningSourceProjections": self.rich_provisioning(),
            "cleanupAbsenceProjections": cleanup,
            "wormSourceProjections": worm,
            "productionBoundary": {
                "authorizedPreflightProjection": production_projection,
                "postExecutionProjection": copy.deepcopy(production_projection),
                "freshPreflightRetiredRoleAbsence": (
                    build_retired_role_absence_projection(self.plan, stamp(NOW))
                ),
                "postExecutionRetiredRoleAbsence": (
                    build_retired_role_absence_projection(
                        self.plan, stamp(NOW + dt.timedelta(minutes=7))
                    )
                ),
                "projectionsEqual": True,
                "journaledProductionWriteCount": 0,
                "acceptedContainerWriteJournal": [],
                "acceptedReleaseObservationGate": {"status": "deferred-required-post-s2", "requiredAfter": "separately-authorized-publisher-fic-repin", "requiredBefore": "accepted-release-publication-or-production-deploy", "acceptedContainerResourceId": self.resources["acceptedContainer"]["resourceId"]},
                "mutationJournal": journal,
                "observedAt": stamp(NOW + dt.timedelta(minutes=7)),
            },
            "observedAt": stamp(NOW + dt.timedelta(minutes=7)),
        }
        return evidence


def build_valid_terminal_source_evidence_fixture(
    receipt_directory,
    *,
    plan=None,
    plan_sha=None,
    package=None,
    adopt_operations=(),
):
    plan, loaded_sha = bootstrap.load_plan() if plan is None else (plan, plan_sha)
    if plan_sha is None:
        plan_sha = loaded_sha
    package = package or bootstrap.build_package_descriptor()
    fixture = _TerminalEvidenceFixture(
        plan,
        plan_sha,
        package,
        Path(receipt_directory),
        adopt_operations=adopt_operations,
    )
    evidence = fixture.build_evidence()
    return {
        "plan": plan,
        "planSha256": plan_sha,
        "package": package,
        "authorization": fixture.authorization,
        "preflightProjection": fixture.projection,
        "sourceEvidence": evidence,
        "operationProjections": fixture.operations,
    }


def _build_mailbox_s2_documents_from_terminal_fixture(fixture, components):
    """Build rich mailbox-facing documents from one validated fake transport.

    This is deliberately a test helper, not a production observation path.
    Every body is derived from the same fake-Azure operation universe used by
    ``validate_terminal_source_evidence`` so receipt tests do not maintain a
    second parallel set of security-critical IDs or hashes.
    """

    plan = fixture["plan"]
    authorization = fixture["authorization"]
    source = fixture["sourceEvidence"]
    resources = {item["id"]: item for item in plan["resourceInventory"]}
    operations = {
        item["operationId"]: item["sourceProjection"]["projection"]
        for item in source["allOperationProjections"]
    }
    rich = source["richProvisioningSourceProjections"]
    observed_at = source["observedAt"]
    subscription_scope = f"/subscriptions/{bootstrap.SUBSCRIPTION}"
    owner_role = (
        subscription_scope
        + "/providers/Microsoft.Authorization/roleDefinitions/"
        + "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
    )

    identity_facts = {
        "publisherServicePrincipal": {
            "clientId": rich["publisherServicePrincipal"]["appId"],
            "principalId": rich["publisherServicePrincipal"]["id"],
            "resourceId": None,
        },
        "bridgeIdentity": {
            "clientId": operations["createBridgeIdentity"]["clientId"],
            "principalId": operations["createBridgeIdentity"]["principalId"],
            "resourceId": resources["bridgeIdentity"]["resourceId"],
        },
        "registryWriterIdentity": {
            "clientId": resources["registryWriterIdentity"]["clientId"],
            "principalId": resources["registryWriterIdentity"]["principalId"],
            "resourceId": resources["registryWriterIdentity"]["resourceId"],
        },
        "registryReaderIdentity": {
            "clientId": resources["registryReaderIdentity"]["clientId"],
            "principalId": resources["registryReaderIdentity"]["principalId"],
            "resourceId": resources["registryReaderIdentity"]["resourceId"],
        },
        "signerIdentity": {
            "clientId": operations["createSignerIdentity"]["clientId"],
            "principalId": operations["createSignerIdentity"]["principalId"],
            "resourceId": resources["signerIdentity"]["resourceId"],
        },
        "productionActivationIdentity": {
            "clientId": operations["createProductionActivationIdentity"]["clientId"],
            "principalId": operations["createProductionActivationIdentity"]["principalId"],
            "resourceId": resources["productionActivationIdentity"]["resourceId"],
        },
        "productionSystemIdentity": {
            "clientId": resources["productionSystemIdentity"]["clientId"],
            "principalId": resources["productionSystemIdentity"]["principalId"],
            "resourceId": resources["productionSite"]["resourceId"],
        },
    }

    role_records = {}
    for role in plan["roleMatrix"]:
        definition = rich["roleDefinitions"][role["name"]]
        assignment = rich["roleAssignments"][role["name"]]
        properties = assignment["properties"]
        identity = identity_facts[role["principal"]]
        definition_properties = definition["properties"]
        role_scope = (
            resources[role["scope"]]["resourceId"]
            if role["scope"] in resources
            else subscription_scope
            if role["scope"] == "subscription"
            else role["scope"]
        )
        permissions = definition_properties["permissions"]
        if len(permissions) != 1:
            raise AssertionError(f"test role {role['name']} is not single-permission")
        permission = permissions[0]
        role_records[role["name"]] = {
            "roleDefinitionResourceId": definition["id"],
            "roleDefinitionSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(definition)
            ),
            "roleAssignmentResourceId": assignment["id"],
            "roleAssignmentSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(assignment)
            ),
            "principalId": identity["principalId"],
            "principalType": properties["principalType"],
            "tenantId": bootstrap.TENANT,
            "identityClientId": identity["clientId"],
            "identityResourceId": identity["resourceId"],
            "scope": role_scope,
            "condition": properties["condition"],
            "conditionVersion": properties["conditionVersion"],
            "delegatedManagedIdentityResourceId": properties[
                "delegatedManagedIdentityResourceId"
            ],
            "assignableScopes": definition_properties["assignableScopes"],
            "actions": permission["actions"],
            "notActions": permission["notActions"],
            "dataActions": permission["dataActions"],
            "notDataActions": permission["notDataActions"],
        }

    inventory_names = {
        "publisher": "publisherServicePrincipal",
        "bridge": "bridgeIdentity",
        "registryWriter": "registryWriterIdentity",
        "registryReader": "registryReaderIdentity",
        "signer": "signerIdentity",
        "productionActivation": "productionActivationIdentity",
        "productionSystem": "productionSystemIdentity",
    }
    principal_inventories = {}
    for inventory_name, resource_key in inventory_names.items():
        principal_id = identity_facts[resource_key]["principalId"]
        direct = rich["principalDirectAssignments"][inventory_name]
        effective = rich["principalEffectiveAssignments"][inventory_name]
        direct_ids = [item["id"] for item in direct]
        effective_ids = [item["id"] for item in effective]
        encoded_principal = urllib.parse.quote(principal_id, safe="")
        query_root = (
            "https://management.azure.com"
            f"/subscriptions/{bootstrap.SUBSCRIPTION}/providers/"
            "Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter="
        )
        principal_inventories[inventory_name] = {
            "principalId": principal_id,
            "directQuery": query_root + f"principalId%20eq%20%27{encoded_principal}%27",
            "effectiveQuery": query_root + f"assignedTo%28%27{encoded_principal}%27%29",
            "directAssignmentResourceIds": direct_ids,
            "effectiveAssignmentResourceIds": effective_ids,
            "directAssignmentSetSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(direct)
            ),
            "effectiveAssignmentSetSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(effective)
            ),
            "observedAt": observed_at,
        }

    application = rich["publisherApplication"]
    service = rich["publisherServicePrincipal"]
    concrete_fic = rich["solePublisherFederatedCredentials"][0]
    fic_template = {
        "id": concrete_fic["id"],
        "name": concrete_fic["name"],
        "issuer": concrete_fic["issuer"],
        "audiences": concrete_fic["audiences"],
        "subject": None,
        "claimsMatchingExpressionTemplate": {
            "languageVersion": 1,
            "value": (
                f"claims['sub'] eq '{mailbox.OIDC_SUBJECT}' and "
                f"claims['repository_id'] eq '{mailbox.OWNER_REPOSITORY_ID}' and "
                f"claims['repository_owner_id'] eq '{mailbox.OWNER_ID}' and "
                "claims['job_workflow_ref'] eq '{controlWorkflowRef}'"
            ),
        },
    }
    graph_assignment = operations["grantPublisherGraphApplicationReadAll"][
        "appRoleAssignments"
    ][0]
    publisher_identity = {
        "applicationObjectId": application["id"],
        "applicationQuery": (
            f"https://graph.microsoft.com/beta/applications/{application['id']}"
            "?$select=id,appId,signInAudience,passwordCredentials,keyCredentials"
        ),
        "applicationProjectionSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(application)
        ),
        "servicePrincipalQuery": (
            f"https://graph.microsoft.com/v1.0/servicePrincipals/{service['id']}"
            "?$select=id,appId,accountEnabled,servicePrincipalType,passwordCredentials,keyCredentials"
        ),
        "servicePrincipalProjectionSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(service)
        ),
        "federatedIdentityCredentialsQuery": (
            f"https://graph.microsoft.com/beta/applications/{application['id']}"
            "/federatedIdentityCredentials"
        ),
        "federatedIdentityCredentialPolicy": fic_template,
        "federatedIdentityCredentialPolicySha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(fic_template)
        ),
        "appRoleAssignmentsQuery": (
            f"https://graph.microsoft.com/v1.0/servicePrincipals/{service['id']}"
            "/appRoleAssignments"
        ),
        "graphServicePrincipalObjectId": graph_assignment["resourceId"],
        "graphApplicationReadAllAppRoleAssignment": graph_assignment,
        "graphApplicationReadAllAppRoleAssignmentSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(graph_assignment)
        ),
        "observedAt": observed_at,
    }

    bridge_site = resources["bridgeSite"]["resourceId"]
    production_site = resources["productionSite"]["resourceId"]
    package_container = resources["packageContainer"]["resourceId"]
    accepted_container = resources["acceptedContainer"]["resourceId"]
    result_container = resources["resultContainer"]["resourceId"]
    controller_container = resources["controllerLockContainer"]["resourceId"]
    storage_account = resources["storageAccount"]["resourceId"]
    signing_vault = resources["signingVault"]["resourceId"]
    signing_key = resources["signingKey"]["resourceId"]
    integration_vnet = resources["integrationVnet"]["resourceId"]
    integration_subnet = resources["integrationSubnet"]["resourceId"]

    upload = operations["uploadVersionedBridgePackage"]
    package_url = upload["url"] + "?versionid=" + upload["versionId"]
    critical_settings = {
        "WEBSITE_RUN_FROM_PACKAGE": package_url,
        "WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID": identity_facts[
            "registryReaderIdentity"
        ]["resourceId"],
        "WEBSITE_SKIP_RUNNING_KUDUAGENT": "false",
        "PAPERDESK_BRIDGE_PACKAGE_SHA256": upload["sha256"],
    }
    attached_site = operations["attachFiveUamisOnlyToBridge"]
    site_posture = {
        "siteResourceId": bridge_site,
        "name": resources["bridgeSite"]["name"],
        "type": "Microsoft.Web/sites",
        "kind": attached_site["kind"],
        "serverFarmId": attached_site["serverFarmId"],
        "httpsOnly": attached_site["httpsOnly"],
        "publicNetworkAccess": attached_site["publicNetworkAccess"],
        "virtualNetworkSubnetId": attached_site["virtualNetworkSubnetId"],
        "outboundVnetRouting": attached_site["outboundVnetRouting"],
        "webConfig": {
            "alwaysOn": True,
            "linuxFxVersion": "PYTHON|3.12",
            "ftpsState": "Disabled",
            "minTlsVersion": "1.2",
            "scmMinTlsVersion": "1.2",
            "scmType": "None",
            "http20Enabled": True,
            "vnetRouteAllEnabled": True,
        },
        "ftpBasicAuthAllowed": False,
        "scmBasicAuthAllowed": False,
        "sourceControl": {"status": 404},
    }
    sensitive_identities = sorted(
        identity_facts[name]["resourceId"].lower()
        for name in (
            "bridgeIdentity",
            "registryWriterIdentity",
            "registryReaderIdentity",
            "signerIdentity",
            "productionActivationIdentity",
        )
    )
    graph_attachments = {
        identity: [bridge_site.lower()] for identity in sensitive_identities
    }
    identity_boundaries = {
        "ownerRoleDefinitionId": owner_role,
        "items": {
            identity: {
                "resourceId": identity,
                "roleAssignmentsQuery": (
                    "https://management.azure.com"
                    + identity
                    + "/providers/Microsoft.Authorization/roleAssignments"
                    "?api-version=2022-04-01"
                ),
                "allowedNonOwnerAssignerAssignmentIds": [],
                "assignerProjectionSha256": bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes([])
                ),
            }
            for identity in sensitive_identities
        },
        "observedAt": observed_at,
    }
    allowed_bridge_assignment = rich["roleAssignments"][
        "publisherBridgeController"
    ]
    mutation_boundary = {
        "bridgeScopeQuery": (
            "https://management.azure.com"
            + bridge_site
            + "/providers/Microsoft.Authorization/roleAssignments"
            "?api-version=2022-04-01"
        ),
        "allowedNonOwnerAssignmentIds": [allowed_bridge_assignment["id"]],
        "ownerRoleDefinitionId": owner_role,
        "sensitiveActionUniverse": list(mailbox.BRIDGE_SENSITIVE_ACTION_UNIVERSE),
        "sensitiveActionUniverseSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(
                list(mailbox.BRIDGE_SENSITIVE_ACTION_UNIVERSE)
            )
        ),
        "mutatorAssignmentSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes([allowed_bridge_assignment])
        ),
        "observedAt": observed_at,
    }
    legacy_source = operations["detachWriterAndReaderFromLegacyBridge"]
    legacy_projection = {
        "siteResourceId": resources["legacyBridgeSite"]["resourceId"],
        "state": legacy_source["state"],
        "publicNetworkAccess": legacy_source["publicNetworkAccess"],
        "userAssignedIdentityResourceIds": [],
        "transientAppSettingNamesPresent": [],
        "publisherMutatorAssignmentIds": [],
    }
    legacy_retirement = {
        **legacy_projection,
        "roleAssignmentsQuery": (
            "https://management.azure.com"
            + resources["legacyBridgeSite"]["resourceId"]
            + "/providers/Microsoft.Authorization/roleAssignments"
            "?api-version=2022-04-01"
        ),
        "projectionSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(legacy_projection)
        ),
        "observedAt": observed_at,
    }
    topology_source = rich["networkTopology"]
    topology = {
        "mode": "service-endpoint-firewall-v1",
        "virtualNetwork": {
            "resourceId": integration_vnet,
            "apiVersion": "2025-01-01",
            "projectionSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(topology_source["virtualNetwork"])
            ),
            "addressSpacePrefixes": topology_source["virtualNetwork"][
                "addressSpacePrefixes"
            ],
        },
        "integrationSubnet": {
            "resourceId": integration_subnet,
            "apiVersion": "2025-01-01",
            "projectionSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(topology_source["integrationSubnet"])
            ),
            **{
                key: topology_source["integrationSubnet"][key]
                for key in (
                    "virtualNetworkResourceId",
                    "delegations",
                    "serviceEndpoints",
                    "routeTableResourceId",
                    "networkSecurityGroupResourceId",
                )
            },
        },
        "packageStorageAccount": {
            "resourceId": storage_account,
            "apiVersion": "2025-06-01",
            "projectionSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(
                    topology_source["packageStorageAccount"]
                )
            ),
            **{
                key: topology_source["packageStorageAccount"][key]
                for key in (
                    "publicNetworkAccess",
                    "allowBlobPublicAccess",
                    "defaultAction",
                    "bypass",
                    "ipRules",
                    "resourceAccessRules",
                    "virtualNetworkRules",
                )
            },
        },
        "productionSite": {
            "resourceId": production_site,
            "apiVersion": "2025-03-01",
            "projectionSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(topology_source["productionSite"])
            ),
            "virtualNetworkSubnetId": topology_source["productionSite"][
                "virtualNetworkSubnetId"
            ],
            "outboundVnetRouting": topology_source["productionSite"][
                "outboundVnetRouting"
            ],
            "legacyVnetRouteAllEnabled": topology_source["productionSite"][
                "legacyVnetRouteAllEnabled"
            ],
        },
    }
    attachment_inventory = {
        identity: [bridge_site.lower()] for identity in sensitive_identities
    }
    resource_graph_inventory = {
        "query": (
            "Resources | where isnotnull(identity.userAssignedIdentities) | "
            "mv-expand uamiResourceId=bag_keys(identity.userAssignedIdentities) | "
            "project resourceId=tolower(id), "
            "uamiResourceId=tolower(tostring(uamiResourceId)) | "
            "order by uamiResourceId asc, resourceId asc"
        ),
        "sensitiveIdentityAttachments": attachment_inventory,
        "projectionSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(attachment_inventory)
        ),
        "evidenceMethod": "authorized-bootstrap-azure-resource-graph",
        "observedAt": observed_at,
    }
    bridge_runtime = {
        "siteResourceId": bridge_site,
        "packageBlob": upload["blob"],
        "packageSha256": upload["sha256"],
        "packageSize": upload["size"],
        "packageEtag": upload["etag"],
        "packageVersionId": upload["versionId"],
        "packageUrl": package_url,
        "packageReaderIdentityResourceId": identity_facts[
            "registryReaderIdentity"
        ]["resourceId"],
        "criticalAppSettings": critical_settings,
        "criticalAppSettingsSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(critical_settings)
        ),
        "sitePosture": site_posture,
        "sitePostureSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(site_posture)
        ),
        "siteInventoryQuery": (
            "https://management.azure.com/subscriptions/"
            f"{bootstrap.SUBSCRIPTION}/providers/Microsoft.Web/sites"
            "?api-version=2025-03-01"
        ),
        "sensitiveIdentityResourceIds": sensitive_identities,
        "sensitiveIdentityAttachmentSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(
                {bridge_site.lower(): sensitive_identities}
            )
        ),
        "resourceGraphAttachmentInventory": resource_graph_inventory,
        "identityAssignmentBoundaries": identity_boundaries,
        "bridgeMutationBoundary": mutation_boundary,
        "legacyBridgeRetirement": legacy_retirement,
        "networkTopology": topology,
        "bootstrapReceiptPath": "evidence/private-release-bridge-runtime-receipt.json",
        "bootstrapReceiptSha256": "0" * 64,
        "observedAt": observed_at,
    }

    key_source = operations["createSigningKeyVersion"]
    jwk_source = operations["readBackExactSigningPublicJwk"]
    key_uri = key_source["keyUriWithVersion"]
    vault_projection = {
        "id": signing_vault.lower(),
        "name": resources["signingVault"]["name"],
        "type": "Microsoft.KeyVault/vaults",
        "location": "southeastasia",
        "properties": {
            "enableRbacAuthorization": True,
            "enablePurgeProtection": True,
            "softDeleteRetentionInDays": 90,
            "publicNetworkAccess": "Enabled",
            "networkAcls": {
                "bypass": "None",
                "defaultAction": "Allow",
                "ipRules": [],
                "virtualNetworkRules": [],
            },
        },
    }
    key_projection = {
        "id": signing_key.lower(),
        "name": resources["signingKey"]["name"],
        "type": "Microsoft.KeyVault/vaults/keys",
        "properties": {
            "keyUriWithVersion": key_uri,
            "kty": key_source["kty"],
            "keySize": key_source["keySize"],
            "keyOps": key_source["keyOps"],
            "attributes": {
                "enabled": key_source["enabled"],
                "exportable": key_source["exportable"],
                "expiresOn": key_source["expiresAt"],
            },
            "releasePolicy": key_source["releasePolicy"],
        },
    }
    signer_assignment = rich["roleAssignments"]["signerKeySign"]
    key_boundary = {
        "vaultResourceId": signing_vault,
        "vaultApiVersion": "2025-05-01",
        "vaultProjection": vault_projection,
        "vaultProjectionSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(vault_projection)
        ),
        "keyResourceId": signing_key,
        "keyApiVersion": "2023-07-01",
        "keyProjection": key_projection,
        "keyProjectionSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(key_projection)
        ),
        "keyDataPlaneGetUrl": key_uri + "?api-version=7.4",
        "keyDataPlaneProjection": jwk_source,
        "keyDataPlaneProjectionSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(jwk_source)
        ),
        "minimumRemainingLifetimeSeconds": mailbox.KEY_RECOVERY_HORIZON_SECONDS,
        "roleAssignmentsQuery": (
            f"https://management.azure.com/subscriptions/{bootstrap.SUBSCRIPTION}"
            "/providers/Microsoft.Authorization/roleAssignments"
            "?api-version=2022-04-01"
        ),
        "ownerRoleDefinitionId": owner_role,
        "allowedNonOwnerSensitiveAssignmentIds": [signer_assignment["id"]],
        "sensitiveActionUniverse": list(mailbox.KEY_SENSITIVE_ACTION_UNIVERSE),
        "sensitiveActionUniverseSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(
                list(mailbox.KEY_SENSITIVE_ACTION_UNIVERSE)
            )
        ),
        "sensitiveAssignmentProjectionSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes([signer_assignment])
        ),
        "temporaryKeyProvisioningAssignmentIdsPresent": [],
        "observedAt": observed_at,
    }

    worm_names = {
        "accepted": (accepted_container, "acceptedReleases"),
        "packages": (package_container, "deploymentPackages"),
        "results": (result_container, "webJobResults"),
    }
    worm_policies = {}
    for mailbox_name, (scope, source_name) in worm_names.items():
        source_pair = source["wormSourceProjections"][source_name]
        container_projection = source_pair["container"]
        policy_projection = source_pair["policy"]
        properties = policy_projection["properties"]
        worm_policies[mailbox_name] = {
            "scope": scope,
            "policyResourceId": policy_projection["id"],
            "publicAccess": container_projection["publicAccess"],
            "containerResourceSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(container_projection)
            ),
            "state": properties["state"],
            "immutabilityPeriodSinceCreationInDays": properties[
                "immutabilityPeriodSinceCreationInDays"
            ],
            "allowProtectedAppendWrites": properties[
                "allowProtectedAppendWrites"
            ],
            "allowProtectedAppendWritesAll": properties[
                "allowProtectedAppendWritesAll"
            ],
            "etag": policy_projection["etag"],
            "resourceSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(policy_projection)
            ),
            "observedAt": observed_at,
        }

    publisher_effective_sha = principal_inventories["publisher"][
        "effectiveAssignmentSetSha256"
    ]
    publisher_principal = identity_facts["publisherServicePrincipal"]["principalId"]
    publisher_client = identity_facts["publisherServicePrincipal"]["clientId"]
    key_data_url = key_uri + "/sign?api-version=7.6"
    arm = lambda resource, suffix: "https://management.azure.com" + resource + suffix
    blob = lambda container, suffix: (
        f"https://{resources['storageAccount']['name']}.blob.core.windows.net/"
        f"{container}{suffix}"
    )
    decision_specs = {
        "productionConfigList": (
            "POST", production_site,
            arm(production_site, "/config/appsettings/list?api-version=2025-03-01"),
            "Microsoft.Web/sites/config/list/action",
        ),
        "productionConfigWrite": (
            "PUT", production_site,
            arm(production_site, "/config/appsettings?api-version=2025-03-01"),
            "Microsoft.Web/sites/config/write",
        ),
        "productionRestart": (
            "POST", production_site,
            arm(production_site, "/restart?api-version=2025-03-01"),
            "Microsoft.Web/sites/restart/action",
        ),
        "oneDeployRead": (
            "GET", production_site,
            arm(production_site, "/deployments?api-version=2025-03-01"),
            "Microsoft.Web/sites/deployments/read",
        ),
        "oneDeployWrite": (
            "PUT", production_site,
            arm(production_site, "/extensions/onedeploy?api-version=2025-03-01"),
            "Microsoft.Web/sites/extensions/write",
        ),
        "oneDeployPublish": (
            "POST", production_site,
            arm(production_site, "/publish?api-version=2025-03-01"),
            "Microsoft.Web/sites/publish/Action",
        ),
        "storageListKeys": (
            "POST", storage_account,
            arm(storage_account, "/listKeys?api-version=2025-06-01"),
            "Microsoft.Storage/storageAccounts/listKeys/action",
        ),
        "storageContainerWrite": (
            "PUT", package_container,
            arm(package_container, "?api-version=2025-06-01"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/write",
        ),
        "storageContainerDelete": (
            "DELETE", package_container,
            arm(package_container, "?api-version=2025-06-01"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
        ),
        "otherControllerLease": (
            "POST", package_container,
            arm(package_container, "/lease?api-version=2025-06-01"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/lease/action",
        ),
        "registryBlobList": (
            "GET", accepted_container,
            blob(resources["acceptedContainer"]["name"], "?restype=container&comp=list"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        ),
        "registryBlobRead": (
            "GET", accepted_container,
            blob(resources["acceptedContainer"]["name"], "/probe"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        ),
        "registryBlobWrite": (
            "PUT", accepted_container,
            blob(resources["acceptedContainer"]["name"], "/probe"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
        ),
        "resultBlobList": (
            "GET", result_container,
            blob(resources["resultContainer"]["name"], "?restype=container&comp=list"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        ),
        "resultBlobRead": (
            "GET", result_container,
            blob(resources["resultContainer"]["name"], "/probe"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        ),
        "resultBlobWrite": (
            "PUT", result_container,
            blob(resources["resultContainer"]["name"], "/probe"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
        ),
        "packageBlobList": (
            "GET", package_container,
            blob(resources["packageContainer"]["name"], "?restype=container&comp=list"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        ),
        "packageBlobRead": (
            "GET", package_container,
            blob(resources["packageContainer"]["name"], "/probe"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        ),
        "packageBlobWrite": (
            "PUT", package_container,
            blob(resources["packageContainer"]["name"], "/probe"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
        ),
        "keyVaultSign": (
            "POST", signing_key, key_data_url,
            "Microsoft.KeyVault/vaults/keys/sign/action",
        ),
    }
    decisions = {
        name: {
            "principalId": publisher_principal,
            "clientId": publisher_client,
            "plane": (
                "storage-data"
                if "Blob" in name
                else "key-vault-data"
                if name == "keyVaultSign"
                else "arm-control"
            ),
            "wouldInvokeMethod": method,
            "targetResourceId": target,
            "targetUrl": url,
            "azureAction": action,
            "decision": "denied",
            "grantingAssignmentIds": [],
            "inventorySha256": publisher_effective_sha,
            "evaluatedAt": observed_at,
        }
        for name, (method, target, url, action) in decision_specs.items()
    }

    controller_projection = rich["controllerLockContainer"]
    provisioning_evidence = {
        "schemaVersion": 1,
        "status": "activated",
        "subscriptionId": bootstrap.SUBSCRIPTION,
        "observedAt": observed_at,
        "publisherIdentity": publisher_identity,
        "roles": role_records,
        "principalInventories": principal_inventories,
        "controllerLockContainer": {
            "scope": controller_container,
            "publicAccess": controller_projection["publicAccess"],
            "blobCount": 0,
            "resourceSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(controller_projection)
            ),
            "evidenceMethod": "authorized-bootstrap-arm-and-blob-inventory",
            "observedAt": observed_at,
        },
        "bridgeRuntime": bridge_runtime,
        "keyVaultBoundary": key_boundary,
        "wormPolicies": worm_policies,
        "publisherAuthorizationDecisions": decisions,
        "rule": (
            "All source-pinned and action-time authorization evidence must match "
            "exactly before every privileged phase."
        ),
    }
    runtime_receipt = {
        "schemaVersion": 1,
        "status": "bridge-runtime-provisioned",
        "bridgeResourceId": bridge_site,
        "package": {
            "blob": upload["blob"],
            "sha256": upload["sha256"],
            "size": upload["size"],
            "etag": upload["etag"],
            "versionId": upload["versionId"],
            "url": package_url,
        },
        "packageReaderIdentityResourceId": identity_facts[
            "registryReaderIdentity"
        ]["resourceId"],
        "criticalAppSettingsSha256": bridge_runtime[
            "criticalAppSettingsSha256"
        ],
        "sitePostureSha256": bridge_runtime["sitePostureSha256"],
        "resourceGraphAttachmentSha256": resource_graph_inventory[
            "projectionSha256"
        ],
        "identityAssignmentBoundariesSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(identity_boundaries)
        ),
        "bridgeMutationBoundarySha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(mutation_boundary)
        ),
        "legacyBridgeRetirementSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(legacy_retirement)
        ),
        "networkTopologySha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(topology)
        ),
        "packagesWormPolicySha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(worm_policies["packages"])
        ),
        "publisherBridgeControllerAssignmentId": role_records[
            "publisherBridgeController"
        ]["roleAssignmentResourceId"],
        "observedAt": observed_at,
    }
    bridge_runtime["bootstrapReceiptSha256"] = bootstrap.sha256_bytes(
        bootstrap.canonical_json_bytes(runtime_receipt)
    )
    return {
        "provisioningEvidence": provisioning_evidence,
        "bridgeRuntimeReceipt": runtime_receipt,
        "temporaryAccessCleanup": copy.deepcopy(
            components["temporaryAccessCleanup"]
        ),
        "activationFenceBootstrap": copy.deepcopy(
            components["activationFenceBootstrap"]
        ),
        "bridgeEvidence": copy.deepcopy(components["bridgeEvidence"]),
    }


def build_complete_terminal_receipt_input_fixture(
    receipt_directory,
    *,
    adopt_operations=(),
):
    """Return one deterministic, fully validated complete-receipt input set.

    Receipt tests import this adapter rather than maintaining parallel fake
    identities, role bodies, or S2 document hashes.  The production executor
    uses the source-owned builders; this helper contributes fake observations
    only.
    """

    from scripts import private_release_v2_bootstrap_receipts as receipts

    package, package_bytes = bootstrap.build_package_artifact()
    fixture = build_valid_terminal_source_evidence_fixture(
        receipt_directory,
        package=package,
        adopt_operations=adopt_operations,
    )
    source = fixture["sourceEvidence"]
    started_at = source["claimReceipt"]["claimedAt"]
    completed_at = source["observedAt"]
    components = bootstrap.build_terminal_receipt_components(
        plan=fixture["plan"],
        authorization=fixture["authorization"],
        preflight_projection=fixture["preflightProjection"],
        source_evidence=source,
        started_at=started_at,
        completed_at=completed_at,
    )
    documents = _build_mailbox_s2_documents_from_terminal_fixture(
        fixture, components
    )
    s2_documents = receipts.build_s2_evidence_files(
        authorization=fixture["authorization"],
        plan=fixture["plan"],
        provisioning_evidence=documents["provisioningEvidence"],
        bridge_runtime_receipt=documents["bridgeRuntimeReceipt"],
        temporary_cleanup_receipt=documents["temporaryAccessCleanup"],
        activation_fence_receipt=documents["activationFenceBootstrap"],
        bridge_canary_receipt=documents["bridgeEvidence"],
    )
    trusted_now = dt.datetime.fromisoformat(
        completed_at.replace("Z", "+00:00")
    )
    complete_receipt = receipts.build_complete_receipt_bundle(
        authorization=fixture["authorization"],
        plan=fixture["plan"],
        components=components,
        s2_documents=s2_documents,
        source_evidence=source,
        authorized_preflight_projection=fixture["preflightProjection"],
        package_bytes=package_bytes,
        started_at=started_at,
        completed_at=completed_at,
        now=trusted_now,
    )
    return {
        "plan": fixture["plan"],
        "planSha256": fixture["planSha256"],
        "authorization": fixture["authorization"],
        "preflightProjection": fixture["preflightProjection"],
        "package": package,
        "packageBytes": package_bytes,
        "sourceEvidence": source,
        "components": components,
        "s2Documents": s2_documents,
        "startedAt": started_at,
        "completedAt": completed_at,
        "now": trusted_now,
        "completeReceipt": complete_receipt,
    }


class FakeTransport:
    def __init__(self, projection, *, drift=False, reject_operation=None, fail_operation=None):
        self.projection = projection
        self.drift = drift
        self.reject_operation = reject_operation
        self.fail_operation = fail_operation
        self.calls = []
        self.terminal_fixture = None
        self.cleanup_keys = {
            "addOwnedUploaderIpv4Rule": "uploader-ipv4-rule",
            "removeOwnedUploaderIpv4Rule": "uploader-ipv4-rule",
            "addOwnedUploaderPackageRole": "uploader-package-role",
            "removeOwnedUploaderPackageRole": "uploader-package-role",
            "addOwnedOperatorKeyReadRole": "operator-key-read-role",
            "removeOwnedOperatorKeyReadRole": "operator-key-read-role",
            "addOwnedOperatorFenceBootstrapRole": "operator-fence-bootstrap-role",
            "removeOwnedOperatorFenceBootstrapRole": "operator-fence-bootstrap-role",
            "addOwnedOperatorControllerCanaryRole": "operator-controller-canary-role",
            "removeOwnedOperatorControllerCanaryRole": "operator-controller-canary-role",
            "createControllerLeaseCanaryBlob": "controller-lease-canary-blob",
            "removeControllerLeaseCanaryBlob": "controller-lease-canary-blob",
            "configureBridgeExactVersionedPackageAndCriticalSettings": (
                bootstrap.BRIDGE_SETTINGS_CLEANUP_KEY
            ),
            "startBridgeForBoundedCanary": "bounded-bridge-canary-start",
            "stopBridgeAfterBoundedCanary": "bounded-bridge-canary-start",
        }

    def account(self):
        self.calls.append(("account", None))
        return {
            "cloud": "AzureCloud",
            "subscriptionId": bootstrap.SUBSCRIPTION,
            "tenantId": bootstrap.TENANT,
            "accountId": "operator@example.invalid",
            "accountObjectId": ACCOUNT_OBJECT,
            "accountType": "user",
        }

    def collect_preflight(self, plan):
        self.calls.append(("collect", None))
        value = copy.deepcopy(self.projection)
        if self.drift:
            value["probes"][0]["responseSha256"] = "f" * 64
        return value

    def inspect_operation(self, operation, state):
        self.calls.append(("inspect", operation["id"]))
        if operation["id"] == self.reject_operation:
            return {"operationId": operation["id"], "status": "partial"}
        return {"operationId": operation["id"], "status": "absent"}

    def observe_production_boundary(self):
        self.calls.append(("production-boundary", None))
        return copy.deepcopy(
            self.projection["productionBoundaryObservation"]["sourceProjection"]
        )

    def apply_operation(self, operation, state):
        self.calls.append(("apply", operation["id"]))
        if operation["id"] == self.fail_operation:
            raise bootstrap.BootstrapError("injected permanent failure")
        removed = operation["id"].startswith("removeOwned") or operation["id"] == "stopBridgeAfterBoundedCanary"
        removed = removed or operation["id"] == "removeControllerLeaseCanaryBlob"
        read = operation["id"] in {
            "readBackExactSigningPublicJwk",
            "proveControllerLockContainerEmpty",
        }
        self_cleaned = operation["id"] in {
            "exerciseControllerLeaseCanary",
            "startBridgeForBoundedCanary",
        }
        bridge_settings_owned = (
            operation["id"]
            == "configureBridgeExactVersionedPackageAndCriticalSettings"
        )
        return {
            "operationId": operation["id"],
            "status": "removed-exact" if removed else "verified-exact" if read else "created",
            "owned": (
                bridge_settings_owned
                or (
                    operation.get("temporary") is True
                    and not removed
                    and not read
                    and not self_cleaned
                )
            ),
            "cleanupKey": self.cleanup_keys.get(operation["id"]),
        }

    def compensate_temporary(self, operation, proof, state):
        self.calls.append(("compensate", operation["id"]))
        return {
            "operationId": operation["id"],
            "status": "removed-exact",
            "owned": True,
            "cleanupKey": proof.get("cleanupKey"),
        }

    def verify_postcondition(self, postcondition, state):
        self.calls.append(("postcondition", postcondition["id"]))
        return {"postconditionId": postcondition["id"], "status": "verified"}

    def bind_terminal_fixture(self, fixture):
        self.terminal_fixture = fixture

    def finalize_terminal_source_evidence(self, state, *, claimed_at, observed_at):
        self.calls.append(("terminal-source", None))
        if not isinstance(self.terminal_fixture, Mapping):
            raise bootstrap.BootstrapError("fake terminal fixture is not bound")
        source = self.terminal_fixture["sourceEvidence"]
        if (
            source["claimReceipt"]["claimedAt"] != claimed_at
            or source["observedAt"] != observed_at
            or state["authorization"] != self.terminal_fixture["authorization"]
        ):
            raise bootstrap.BootstrapError("fake terminal source binding drifted")
        return copy.deepcopy(source)

    def terminal_package_readback_bytes(self):
        self.calls.append(("terminal-package", None))
        if not isinstance(self.terminal_fixture, Mapping):
            raise bootstrap.BootstrapError("fake terminal fixture is not bound")
        return bytes(self.terminal_fixture["packageBytes"])


class BootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.plan_sha = bootstrap.load_plan()
        cls.package = bootstrap.build_package_descriptor()

    def test_plan_rejects_consumed_temporary_role_ids(self):
        expected_retired_specs = (
            {
                "scopeResourceKey": "packageContainer",
                "definitionId": "d3021f37-75b7-5dad-84ce-8bf84dd11e93",
                "assignmentId": "39989cff-44ef-596e-8b46-0a433bb5c0e2",
            },
            {
                "scopeResourceKey": "signingKey",
                "definitionId": "dba37aa5-3824-5c68-91ac-5f1e24e7aa9c",
                "assignmentId": "9420cd85-94df-5156-99b7-9a011702c69e",
            },
            {
                "scopeResourceKey": "activationFenceContainer",
                "definitionId": "1c425126-8044-52d8-b4f5-6dac8d60b1e1",
                "assignmentId": "bdfe78bb-909b-54df-86a0-1620898addf0",
            },
            {
                "scopeResourceKey": "controllerLockContainer",
                "definitionId": "fb109dbf-e475-5f97-8db3-3c1a94acf4b3",
                "assignmentId": "2d607095-edff-533c-a2c4-0e6e9d631715",
            },
            {
                "scopeResourceKey": "packageContainer",
                "definitionId": "2c66d02c-0545-469e-8fd6-b3bf08b2050b",
                "assignmentId": "9db51009-898e-44e9-bb80-dc955c62f746",
            },
            {
                "scopeResourceKey": "signingKey",
                "definitionId": "4b046f73-1755-446d-93a8-e3c3b545b611",
                "assignmentId": "212e0903-81a0-41ea-a11e-c07e91235a81",
            },
            {
                "scopeResourceKey": "activationFenceContainer",
                "definitionId": "91668da3-228c-4db3-ab59-5c2b65cd44d7",
                "assignmentId": "72b288cf-73cf-4496-9480-6161c972193b",
            },
            {
                "scopeResourceKey": "controllerLockContainer",
                "definitionId": "d57913de-def8-4495-b30e-9f1e1cca1943",
                "assignmentId": "807769aa-af4e-493e-b28d-803c58f10a44",
            },
        )
        self.assertEqual(
            bootstrap.RETIRED_TEMPORARY_ROLE_SPECS, expected_retired_specs
        )
        expected_retired_ids = {
            value
            for spec in expected_retired_specs
            for value in (spec["definitionId"], spec["assignmentId"])
        }
        self.assertEqual(
            bootstrap.RETIRED_TEMPORARY_ROLE_IDS, expected_retired_ids
        )
        self.assertEqual(len(expected_retired_ids), 16)

        self.assertFalse(
            set(self.plan["temporaryAccess"]).intersection(
                bootstrap.TEMPORARY_ROLE_ID_FIELDS
            )
        )
        current_ids = list(
            bootstrap.derive_temporary_role_ids(self.plan, AUTH_ID).values()
        )
        self.assertEqual(len(current_ids), len(set(current_ids)))
        self.assertTrue(
            set(current_ids).isdisjoint(bootstrap.RETIRED_TEMPORARY_ROLE_IDS)
        )
        altered = copy.deepcopy(self.plan)
        altered["temporaryAccess"].update(
            bootstrap.derive_temporary_role_ids(self.plan, AUTH_ID)
        )
        altered["temporaryAccess"]["roleDefinitionId"] = sorted(
            bootstrap.RETIRED_TEMPORARY_ROLE_IDS
        )[0]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "retired-role-plan.json"
            path.write_bytes(bootstrap.canonical_json_bytes(altered))
            with (
                mock.patch.object(bootstrap, "PLAN_PATH", path),
                self.assertRaisesRegex(
                    bootstrap.BootstrapError,
                    "reviewed plan must not embed reusable temporary role IDs",
                ),
            ):
                bootstrap.load_plan()

    def test_temporary_role_ids_are_deterministic_and_disjoint_per_authorization(self):
        other_authorization_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        first = bootstrap.derive_temporary_role_ids(self.plan, AUTH_ID)
        repeated = bootstrap.derive_temporary_role_ids(self.plan, AUTH_ID)
        second = bootstrap.derive_temporary_role_ids(
            self.plan, other_authorization_id
        )
        self.assertEqual(first, repeated)
        self.assertEqual(set(first), set(bootstrap.TEMPORARY_ROLE_ID_FIELDS) | {"temporaryControllerRoleDefinitionId"})
        self.assertEqual(len(set(first.values())), 8)
        self.assertEqual(len(set(second.values())), 8)
        self.assertEqual(set(first.values()) & set(second.values()), {bootstrap.CONTROLLER_BUILTIN_ROLE_ID})
        self.assertTrue({first[k] for k in bootstrap.TEMPORARY_ROLE_ID_FIELDS}.isdisjoint(second[k] for k in bootstrap.TEMPORARY_ROLE_ID_FIELDS))
        self.assertTrue(
            set(first.values()).isdisjoint(bootstrap.RETIRED_TEMPORARY_ROLE_IDS)
        )
        self.assertTrue(
            set(second.values()).isdisjoint(bootstrap.RETIRED_TEMPORARY_ROLE_IDS)
        )
        first_bound = bootstrap.bind_temporary_role_ids(self.plan, AUTH_ID)
        second_bound = bootstrap.bind_temporary_role_ids(
            self.plan, other_authorization_id
        )
        self.assertEqual(
            [item["id"] for item in first_bound["resourceInventory"]],
            [item["id"] for item in second_bound["resourceInventory"]],
        )
        self.assertEqual(
            [item["id"] for item in first_bound["mutations"]],
            [item["id"] for item in second_bound["mutations"]],
        )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "do not match the authorization"
        ):
            bootstrap.bind_temporary_role_ids(first_bound, other_authorization_id)

    def test_residual_temporary_role_markers_fail_closed_in_exhaustive_inventories(self):
        execution_plan = bootstrap.bind_temporary_role_ids(self.plan, AUTH_ID)
        prior_authorization_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        prior_ids = bootstrap.derive_temporary_role_ids(
            self.plan, prior_authorization_id
        )
        metadata = bootstrap._temporary_role_metadata(
            prior_authorization_id, "uploader-package-role"
        )
        definition = {
            "id": (
                f"/subscriptions/{bootstrap.SUBSCRIPTION}/providers/"
                "Microsoft.Authorization/roleDefinitions/"
                + prior_ids["roleDefinitionId"]
            ),
            "properties": {
                "roleName": metadata["roleName"],
                "description": metadata["description"],
            },
        }
        assignment = {
            "properties": {
                "description": metadata["assignmentDescription"],
                "roleDefinitionId": definition["id"],
            }
        }
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "residual PaperDesk temporary role definition"
        ):
            bootstrap._reject_residual_temporary_role_definitions(
                [definition], label="test definition inventory"
            )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "residual PaperDesk temporary role assignment"
        ):
            bootstrap._reject_residual_temporary_role_assignments(
                [assignment],
                plan=execution_plan,
                label="test assignment inventory",
            )
        orphan_without_marker = copy.deepcopy(assignment)
        orphan_without_marker["properties"]["description"] = None
        orphan_without_marker["properties"]["roleDefinitionId"] = (
            f"/subscriptions/{bootstrap.SUBSCRIPTION}/providers/"
            "Microsoft.Authorization/roleDefinitions/"
            + execution_plan["temporaryAccess"]["roleDefinitionId"]
        )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "residual PaperDesk temporary role assignment"
        ):
            bootstrap._reject_residual_temporary_role_assignments(
                [orphan_without_marker],
                plan=execution_plan,
                label="test orphan assignment inventory",
            )

    def _temporary_role_transport_fixture(self, receipt):
        projection = build_projection(self.plan, self.package)
        authorization = build_authorization(
            self.plan, self.plan_sha, self.package, projection, receipt
        )
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=authorization,
            plan=self.plan,
            package=self.package,
            preflight={"projection": projection},
            clock=lambda: NOW,
            sleep=lambda _delay: None,
            session=mock.Mock(),
        )
        operation = next(
            item
            for item in self.plan["mutations"]
            if item["id"] == "addOwnedUploaderPackageRole"
        )
        definition_id = transport.plan["temporaryAccess"]["roleDefinitionId"]
        definition_resource = (
            f"/subscriptions/{bootstrap.SUBSCRIPTION}/providers/"
            f"Microsoft.Authorization/roleDefinitions/{definition_id}"
        )
        metadata = bootstrap._temporary_role_metadata(
            AUTH_ID, "uploader-package-role"
        )
        definition = {
            "id": definition_resource,
            "name": definition_id,
            "type": "Microsoft.Authorization/roleDefinitions",
            "properties": {
                "roleName": metadata["roleName"],
                "description": metadata["description"],
                "type": "CustomRole",
                "permissions": [
                    {
                        "actions": [],
                        "notActions": [],
                        "dataActions": transport.plan["temporaryAccess"][
                            "temporaryPackageDataActions"
                        ],
                        "notDataActions": [],
                    }
                ],
                "assignableScopes": [
                    f"/subscriptions/{bootstrap.SUBSCRIPTION}"
                ],
            },
        }
        return transport, operation, definition_resource, definition

    def _bind_temporary_role_test_ledger(self, transport, receipt):
        ledger = bootstrap.UseLedger(
            directory=receipt,
            authorization_id=AUTH_ID,
            authorization_sha256=bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(transport.authorization)
            ),
            source_sha=MERGE,
            plan_sha256=self.plan_sha,
            claimed_at=stamp(NOW),
        )
        ledger.claim()
        transport.bind_journal(ledger)
        return ledger

    def _temporary_package_assignment_document(self, transport, definition_resource):
        assignment_id = transport.plan["temporaryAccess"]["roleAssignmentId"]
        scope = next(
            item["resourceId"]
            for item in transport.plan["resourceInventory"]
            if item["id"] == "packageContainer"
        )
        assignment_resource = (
            f"{scope}/providers/Microsoft.Authorization/roleAssignments/"
            f"{assignment_id}"
        )
        metadata = bootstrap._temporary_role_metadata(
            AUTH_ID, "uploader-package-role"
        )
        return assignment_resource, {
            "id": assignment_resource,
            "name": assignment_id,
            "type": "Microsoft.Authorization/roleAssignments",
            "properties": {
                "principalId": transport.authorization["azure"]["accountObjectId"],
                "principalType": "User",
                "roleDefinitionId": definition_resource,
                "description": metadata["assignmentDescription"],
                "scope": scope,
                "condition": None,
                "conditionVersion": None,
                "delegatedManagedIdentityResourceId": None,
            },
        }

    def test_temporary_role_result_lost_is_provisionally_owned_and_compensated(self):
        with tempfile.TemporaryDirectory() as folder:
            receipt = Path(folder) / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
            transport, operation, definition_resource, definition = (
                self._temporary_role_transport_fixture(receipt)
            )
            responses = iter(
                [
                    bootstrap._RestResponse(404, b"", {}),
                    bootstrap._RestResponse(404, b"", {}),
                    bootstrap._RestResponse(
                        200, bootstrap.canonical_json_bytes(definition), {}
                    ),
                    bootstrap._RestResponse(404, b"", {}),
                    bootstrap._RestResponse(404, b"", {}),
                    bootstrap._RestResponse(404, b"", {}),
                ]
            )
            transport._active_operation_id = operation["id"]
            with (
                mock.patch.object(
                    transport,
                    "_read_request_with_transport_retry",
                    side_effect=lambda *_args, **_kwargs: next(responses),
                ),
                mock.patch.object(
                    transport,
                    "_mutation_request",
                    side_effect=bootstrap._MutationOwnershipAmbiguity(
                        "transport applied the PUT but lost its result"
                    ),
                ),
                self.assertRaises(bootstrap.OwnedTemporaryMutationError) as raised,
            ):
                transport._mutate_temporary_role_impl(operation["id"], {})
            proof = raised.exception.proof
            self.assertTrue(proof["owned"])
            self.assertTrue(proof["details"]["definitionAttempted"])
            self.assertFalse(proof["details"]["definitionCreated"])
            self.assertTrue(proof["details"]["definitionAmbiguous"])
            state = {"proofs": {operation["id"]: proof}}

            def absent_assignment(*_args, **_kwargs):
                transport._last_guarded_assignment_was_present = False
                return bootstrap._expected_deletion_lock_proof(
                    "removeOwnedUploaderPackageRole"
                )

            with (
                mock.patch.object(
                    transport,
                    "_read_request_with_transport_retry",
                    side_effect=lambda *_args, **_kwargs: next(responses),
                ),
                mock.patch.object(
                    transport,
                    "_guarded_assignment_delete",
                    side_effect=absent_assignment,
                ),
                mock.patch.object(
                    transport, "_verify_cleanup_lock_inventory"
                ),
                mock.patch.object(transport, "_arm_delete") as delete,
                mock.patch.object(
                    transport,
                    "_prove_temporary_role_marker_inventories_absent",
                    return_value="0" * 64,
                ),
                mock.patch.object(transport, "_prove_probe_ids", return_value=[]),
            ):
                cleanup = transport.compensate_temporary(operation, proof, state)
            self.assertEqual(cleanup["status"], "removed-exact")
            delete.assert_called_once_with(definition_resource, "2022-04-01")

    def test_temporary_role_result_journal_failure_retains_provisional_ownership(self):
        with tempfile.TemporaryDirectory() as folder:
            receipt = Path(folder) / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
            transport, operation, _definition_resource, definition = (
                self._temporary_role_transport_fixture(receipt)
            )

            class AppliedSession:
                def __init__(self):
                    self.calls = []

                def request(self, method, url, **kwargs):
                    self.calls.append((method, url, kwargs))
                    if method == "GET":
                        return bootstrap._RestResponse(404, b"", {})
                    return bootstrap._RestResponse(
                        201,
                        bootstrap.canonical_json_bytes(definition),
                        {"ETag": '"created"'},
                    )

            transport.session = AppliedSession()
            ledger = bootstrap.UseLedger(
                directory=receipt,
                authorization_id=AUTH_ID,
                authorization_sha256=bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes(transport.authorization)
                ),
                source_sha=MERGE,
                plan_sha256=self.plan_sha,
                claimed_at=stamp(NOW),
            )
            ledger.claim()
            transport.bind_journal(ledger)
            transport._active_operation_id = operation["id"]
            with (
                mock.patch.object(
                    transport,
                    "_record_mutation",
                    side_effect=OSError("result journal fsync failed"),
                ),
                self.assertRaises(bootstrap.OwnedTemporaryMutationError) as raised,
            ):
                transport._mutate_temporary_role_impl(operation["id"], {})
            proof = raised.exception.proof
            self.assertTrue(proof["owned"])
            self.assertTrue(proof["details"]["definitionAttempted"])
            self.assertFalse(proof["details"]["definitionCreated"])
            self.assertEqual(len(ledger.unresolved_intents()), 1)

    def test_definition_500_then_late_exact_is_owned_and_removed_once(self):
        with tempfile.TemporaryDirectory() as folder:
            receipt = Path(folder) / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
            transport, operation, definition_resource, definition = (
                self._temporary_role_transport_fixture(receipt)
            )
            assignment_resource, _assignment = (
                self._temporary_package_assignment_document(
                    transport, definition_resource
                )
            )
            definition_url = transport._arm_url(
                definition_resource, "2022-04-01"
            )
            assignment_url = transport._arm_url(
                assignment_resource, "2022-04-01"
            )

            class Definition500Session:
                def __init__(self):
                    self.definition_gets = 0
                    self.definition_present = False
                    self.definition_pending = False
                    self.calls = []

                def request(self, method, url, **_kwargs):
                    self.calls.append((method, url))
                    if url == assignment_url and method == "GET":
                        return bootstrap._RestResponse(404, b"", {})
                    if url != definition_url:
                        raise AssertionError(f"unexpected role URL: {url}")
                    if method == "GET":
                        self.definition_gets += 1
                        if self.definition_pending and self.definition_gets >= 3:
                            self.definition_present = True
                        return (
                            bootstrap._RestResponse(
                                200,
                                bootstrap.canonical_json_bytes(definition),
                                {},
                            )
                            if self.definition_present
                            else bootstrap._RestResponse(404, b"", {})
                        )
                    if method == "PUT":
                        self.definition_pending = True
                        return bootstrap._RestResponse(500, b"", {})
                    if method == "DELETE":
                        self.definition_present = False
                        self.definition_pending = False
                        return bootstrap._RestResponse(204, b"", {})
                    raise AssertionError(f"unexpected role method: {method}")

            current = [NOW]
            transport.clock = lambda: current[0]
            transport.sleep = lambda seconds: current.__setitem__(
                0, current[0] + dt.timedelta(seconds=seconds)
            )
            session = Definition500Session()
            transport.session = session
            self._bind_temporary_role_test_ledger(transport, receipt)
            transport._active_operation_id = operation["id"]
            with self.assertRaises(
                bootstrap.OwnedTemporaryMutationError
            ) as raised:
                transport._mutate_temporary_role_impl(operation["id"], {})
            proof = raised.exception.proof
            self.assertTrue(proof["details"]["definitionAmbiguous"])
            self.assertFalse(proof["details"]["definitionCreated"])
            state = {"proofs": {operation["id"]: proof}}
            with (
                mock.patch.object(transport, "_verify_cleanup_lock_inventory"),
                mock.patch.object(
                    transport,
                    "_prove_temporary_role_marker_inventories_absent",
                    return_value="0" * 64,
                ),
                mock.patch.object(transport, "_prove_probe_ids", return_value=[]),
            ):
                cleanup = transport.compensate_temporary(
                    operation, proof, state
                )
            self.assertEqual(cleanup["status"], "removed-exact")
            self.assertEqual(
                [call for call in session.calls if call[0] == "DELETE"],
                [("DELETE", definition_url)],
            )

    def test_assignment_500_then_late_exact_is_owned_and_removed_once(self):
        with tempfile.TemporaryDirectory() as folder:
            receipt = Path(folder) / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
            transport, operation, definition_resource, definition = (
                self._temporary_role_transport_fixture(receipt)
            )
            assignment_resource, assignment = (
                self._temporary_package_assignment_document(
                    transport, definition_resource
                )
            )
            definition_url = transport._arm_url(
                definition_resource, "2022-04-01"
            )
            assignment_url = transport._arm_url(
                assignment_resource, "2022-04-01"
            )

            class Assignment500Session:
                def __init__(self):
                    self.definition_present = False
                    self.assignment_gets = 0
                    self.assignment_pending = False
                    self.assignment_present = False
                    self.calls = []

                def request(self, method, url, **_kwargs):
                    self.calls.append((method, url))
                    if url == definition_url:
                        if method == "GET":
                            return (
                                bootstrap._RestResponse(
                                    200,
                                    bootstrap.canonical_json_bytes(definition),
                                    {},
                                )
                                if self.definition_present
                                else bootstrap._RestResponse(404, b"", {})
                            )
                        if method == "PUT":
                            self.definition_present = True
                            return bootstrap._RestResponse(201, b"", {})
                        if method == "DELETE":
                            self.definition_present = False
                            return bootstrap._RestResponse(204, b"", {})
                    if url == assignment_url:
                        if method == "GET":
                            self.assignment_gets += 1
                            if self.assignment_pending and self.assignment_gets >= 3:
                                self.assignment_present = True
                            return (
                                bootstrap._RestResponse(
                                    200,
                                    bootstrap.canonical_json_bytes(assignment),
                                    {},
                                )
                                if self.assignment_present
                                else bootstrap._RestResponse(404, b"", {})
                            )
                        if method == "PUT":
                            self.assignment_pending = True
                            return bootstrap._RestResponse(500, b"", {})
                    raise AssertionError(f"unexpected role request: {method} {url}")

            current = [NOW]
            transport.clock = lambda: current[0]
            transport.sleep = lambda seconds: current.__setitem__(
                0, current[0] + dt.timedelta(seconds=seconds)
            )
            session = Assignment500Session()
            transport.session = session
            self._bind_temporary_role_test_ledger(transport, receipt)
            transport._active_operation_id = operation["id"]
            with self.assertRaises(
                bootstrap.OwnedTemporaryMutationError
            ) as raised:
                transport._mutate_temporary_role_impl(operation["id"], {})
            proof = raised.exception.proof
            self.assertTrue(proof["details"]["definitionCreated"])
            self.assertTrue(proof["details"]["assignmentAmbiguous"])
            self.assertFalse(proof["details"]["assignmentCreated"])
            state = {"proofs": {operation["id"]: proof}}

            def delete_exact_assignment(*_args, **_kwargs):
                session.assignment_present = False
                session.assignment_pending = False
                transport._last_guarded_assignment_was_present = True
                return bootstrap._expected_deletion_lock_proof(
                    "removeOwnedUploaderPackageRole"
                )

            with (
                mock.patch.object(
                    transport,
                    "_guarded_assignment_delete",
                    side_effect=delete_exact_assignment,
                ) as guarded_delete,
                mock.patch.object(
                    transport,
                    "_prove_temporary_role_marker_inventories_absent",
                    return_value="0" * 64,
                ),
                mock.patch.object(transport, "_prove_probe_ids", return_value=[]),
            ):
                cleanup = transport.compensate_temporary(
                    operation, proof, state
                )
            self.assertEqual(cleanup["status"], "removed-exact")
            guarded_delete.assert_called_once()
            self.assertEqual(
                [call for call in session.calls if call[0] == "DELETE"],
                [("DELETE", definition_url)],
            )

    def test_definition_201_stale_readback_settles_late_exact_before_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            receipt = Path(folder) / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
            transport, operation, definition_resource, definition = (
                self._temporary_role_transport_fixture(receipt)
            )
            assignment_resource, _assignment = (
                self._temporary_package_assignment_document(
                    transport, definition_resource
                )
            )
            definition_url = transport._arm_url(
                definition_resource, "2022-04-01"
            )
            assignment_url = transport._arm_url(
                assignment_resource, "2022-04-01"
            )
            current = [NOW]
            visible_at = NOW + dt.timedelta(
                seconds=bootstrap.TEMPORARY_ROLE_CREATE_SETTLEMENT_SECONDS
            )
            alignment_jitter = dt.timedelta(milliseconds=1)

            class Definition201StaleSession:
                def __init__(self):
                    self.pending = False
                    self.present = False
                    self.calls = []

                def request(self, method, url, **kwargs):
                    self.calls.append(
                        (method, url, kwargs.get("deadline"), current[0])
                    )
                    if url == assignment_url and method == "GET":
                        return bootstrap._RestResponse(404, b"", {})
                    if url != definition_url:
                        raise AssertionError(f"unexpected role URL: {url}")
                    if method == "GET":
                        if (
                            self.pending
                            and not self.present
                            and kwargs.get("deadline")
                            == visible_at
                            and current[0] < visible_at
                        ):
                            # A long pre-boundary GET returns a stale 404. The
                            # settlement loop must still reserve a new GET that
                            # begins at the boundary.
                            current[0] += dt.timedelta(
                                seconds=(
                                    bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS
                                    - 1
                                )
                            )
                        if self.pending and current[0] >= visible_at:
                            self.present = True
                        return (
                            bootstrap._RestResponse(
                                200,
                                bootstrap.canonical_json_bytes(definition),
                                {},
                            )
                            if self.present
                            else bootstrap._RestResponse(404, b"", {})
                        )
                    if method == "PUT":
                        self.pending = True
                        return bootstrap._RestResponse(201, b"", {})
                    if method == "DELETE":
                        self.pending = False
                        self.present = False
                        return bootstrap._RestResponse(204, b"", {})
                    raise AssertionError(f"unexpected role method: {method}")

            transport.clock = lambda: current[0]
            transport.sleep = lambda seconds: current.__setitem__(
                0,
                current[0]
                + dt.timedelta(seconds=seconds)
                + alignment_jitter,
            )
            session = Definition201StaleSession()
            transport.session = session
            self._bind_temporary_role_test_ledger(transport, receipt)
            transport._active_operation_id = operation["id"]
            with self.assertRaises(
                bootstrap.OwnedTemporaryMutationError
            ) as raised:
                transport._mutate_temporary_role_impl(operation["id"], {})
            proof = raised.exception.proof
            self.assertTrue(proof["details"]["definitionCreated"])
            self.assertFalse(proof["details"]["definitionReadbackExact"])
            self.assertFalse(proof["details"]["assignmentAttempted"])
            state = {"proofs": {operation["id"]: proof}}
            with (
                mock.patch.object(transport, "_verify_cleanup_lock_inventory"),
                mock.patch.object(
                    transport,
                    "_prove_temporary_role_marker_inventories_absent",
                    return_value="0" * 64,
                ) as marker_proof,
                mock.patch.object(transport, "_prove_probe_ids", return_value=[]),
            ):
                cleanup = transport.compensate_temporary(
                    operation, proof, state
                )
            self.assertEqual(cleanup["status"], "removed-exact")
            self.assertEqual(
                [call[:2] for call in session.calls if call[0] == "DELETE"],
                [("DELETE", definition_url)],
            )
            self.assertTrue(
                any(
                    method == "GET"
                    and url == definition_url
                    and observed_at == visible_at + alignment_jitter
                    and deadline
                    == observed_at
                    + dt.timedelta(
                        seconds=bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS
                    )
                    for method, url, deadline, observed_at in session.calls
                )
            )
            marker_proof.assert_called_once()

    def test_assignment_201_stale_readback_settles_late_exact_before_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            receipt = Path(folder) / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
            transport, operation, definition_resource, definition = (
                self._temporary_role_transport_fixture(receipt)
            )
            assignment_resource, assignment = (
                self._temporary_package_assignment_document(
                    transport, definition_resource
                )
            )
            definition_url = transport._arm_url(
                definition_resource, "2022-04-01"
            )
            assignment_url = transport._arm_url(
                assignment_resource, "2022-04-01"
            )
            current = [NOW]
            visible_at = NOW + dt.timedelta(
                seconds=bootstrap.TEMPORARY_ROLE_CREATE_SETTLEMENT_SECONDS
            )

            class Assignment201StaleSession:
                def __init__(self):
                    self.definition_present = False
                    self.assignment_pending = False
                    self.assignment_present = False
                    self.calls = []

                def request(self, method, url, **kwargs):
                    self.calls.append((method, url, kwargs.get("deadline")))
                    if url == definition_url:
                        if method == "GET":
                            return (
                                bootstrap._RestResponse(
                                    200,
                                    bootstrap.canonical_json_bytes(definition),
                                    {},
                                )
                                if self.definition_present
                                else bootstrap._RestResponse(404, b"", {})
                            )
                        if method == "PUT":
                            self.definition_present = True
                            return bootstrap._RestResponse(201, b"", {})
                        if method == "DELETE":
                            self.definition_present = False
                            return bootstrap._RestResponse(204, b"", {})
                    if url == assignment_url:
                        if method == "GET":
                            if self.assignment_pending and current[0] >= visible_at:
                                self.assignment_present = True
                            return (
                                bootstrap._RestResponse(
                                    200,
                                    bootstrap.canonical_json_bytes(assignment),
                                    {},
                                )
                                if self.assignment_present
                                else bootstrap._RestResponse(404, b"", {})
                            )
                        if method == "PUT":
                            self.assignment_pending = True
                            return bootstrap._RestResponse(201, b"", {})
                    raise AssertionError(
                        f"unexpected role request: {method} {url}"
                    )

            transport.clock = lambda: current[0]
            transport.sleep = lambda seconds: current.__setitem__(
                0, current[0] + dt.timedelta(seconds=seconds)
            )
            session = Assignment201StaleSession()
            transport.session = session
            self._bind_temporary_role_test_ledger(transport, receipt)
            transport._active_operation_id = operation["id"]
            with self.assertRaises(
                bootstrap.OwnedTemporaryMutationError
            ) as raised:
                transport._mutate_temporary_role_impl(operation["id"], {})
            proof = raised.exception.proof
            self.assertTrue(proof["details"]["definitionReadbackExact"])
            self.assertTrue(proof["details"]["assignmentCreated"])
            self.assertFalse(proof["details"]["assignmentReadbackExact"])
            state = {"proofs": {operation["id"]: proof}}

            def delete_exact_assignment(*_args, **_kwargs):
                session.assignment_pending = False
                session.assignment_present = False
                transport._last_guarded_assignment_was_present = True
                return bootstrap._expected_deletion_lock_proof(
                    "removeOwnedUploaderPackageRole"
                )

            with (
                mock.patch.object(
                    transport,
                    "_guarded_assignment_delete",
                    side_effect=delete_exact_assignment,
                ) as guarded_delete,
                mock.patch.object(
                    transport,
                    "_prove_temporary_role_marker_inventories_absent",
                    return_value="0" * 64,
                ) as marker_proof,
                mock.patch.object(transport, "_prove_probe_ids", return_value=[]),
            ):
                cleanup = transport.compensate_temporary(
                    operation, proof, state
                )
            self.assertEqual(cleanup["status"], "removed-exact")
            guarded_delete.assert_called_once()
            self.assertEqual(
                [call[:2] for call in session.calls if call[0] == "DELETE"],
                [("DELETE", definition_url)],
            )
            marker_proof.assert_called_once()

    def test_pending_definition_final_get_cannot_enter_cleanup_reserve(self):
        with tempfile.TemporaryDirectory() as folder:
            receipt = Path(folder) / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
            transport, operation, definition_resource, definition = (
                self._temporary_role_transport_fixture(receipt)
            )
            assignment_resource, _assignment = (
                self._temporary_package_assignment_document(
                    transport, definition_resource
                )
            )
            definition_url = transport._arm_url(
                definition_resource, "2022-04-01"
            )
            assignment_url = transport._arm_url(
                assignment_resource, "2022-04-01"
            )
            start = transport._protected_role_deadline() - dt.timedelta(
                seconds=(
                    bootstrap.TEMPORARY_ROLE_CREATE_SETTLEMENT_SECONDS
                    + bootstrap.FINAL_OBSERVATION_ALIGNMENT_SLACK_SECONDS
                    + bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS
                )
            )
            current = [start]
            boundary = start + dt.timedelta(
                seconds=bootstrap.TEMPORARY_ROLE_CREATE_SETTLEMENT_SECONDS
            )
            final_request_deadline = boundary + dt.timedelta(
                seconds=bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS
            )

            class SlowFinalSettlementSession:
                def __init__(self):
                    self.calls = []

                def request(self, method, url, **kwargs):
                    self.calls.append((method, url, kwargs.get("deadline")))
                    if method != "GET":
                        raise AssertionError("settlement issued a mutation")
                    if url == assignment_url:
                        return bootstrap._RestResponse(404, b"", {})
                    if url != definition_url:
                        raise AssertionError(f"unexpected role URL: {url}")
                    if current[0] >= boundary:
                        current[0] += dt.timedelta(
                            seconds=(
                                bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS
                                + 1
                            )
                        )
                        return bootstrap._RestResponse(
                            200,
                            bootstrap.canonical_json_bytes(definition),
                            {},
                        )
                    return bootstrap._RestResponse(404, b"", {})

            transport.clock = lambda: current[0]
            transport.sleep = lambda seconds: current.__setitem__(
                0, current[0] + dt.timedelta(seconds=seconds)
            )
            session = SlowFinalSettlementSession()
            transport.session = session
            transport._active_protected_role_add = operation["id"]
            proof = {
                "operationId": operation["id"],
                "status": "applied-readback-pending",
                "owned": True,
                "cleanupKey": "uploader-package-role",
                "details": {
                    "cleanupKey": "uploader-package-role",
                    "definitionAttempted": True,
                    "definitionCreated": False,
                    "definitionReadbackExact": False,
                    "definitionAmbiguous": True,
                    "assignmentAttempted": False,
                    "assignmentCreated": False,
                    "assignmentReadbackExact": False,
                },
            }
            state = {"proofs": {operation["id"]: proof}}
            with (
                mock.patch.object(transport, "_arm_delete") as delete,
                self.assertRaisesRegex(
                    bootstrap.BootstrapError,
                    "read-only response crossed the protected request deadline",
                ),
            ):
                transport.compensate_temporary(operation, proof, state)
            delete.assert_not_called()
            self.assertEqual(
                session.calls[-1][2],
                final_request_deadline,
            )
            self.assertTrue(
                all(
                    deadline <= transport._protected_role_deadline()
                    for _method, _url, deadline in session.calls
                )
            )
            self.assertGreater(current[0], final_request_deadline)

    def test_pending_definition_rejects_alignment_overshoot_beyond_slack(self):
        with tempfile.TemporaryDirectory() as folder:
            receipt = Path(folder) / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
            transport, operation, definition_resource, definition = (
                self._temporary_role_transport_fixture(receipt)
            )
            definition_url = transport._arm_url(
                definition_resource, "2022-04-01"
            )
            current = [NOW]
            settlement_boundary = NOW + dt.timedelta(
                seconds=bootstrap.TEMPORARY_ROLE_CREATE_SETTLEMENT_SECONDS
            )
            overshoot = dt.timedelta(
                seconds=(
                    bootstrap.FINAL_OBSERVATION_ALIGNMENT_SLACK_SECONDS
                    + 0.001
                )
            )

            class AbsentDefinitionSession:
                def __init__(self):
                    self.calls = []

                def request(self, method, url, **kwargs):
                    self.calls.append(
                        (method, url, kwargs.get("deadline"), current[0])
                    )
                    if method != "GET" or url != definition_url:
                        raise AssertionError(
                            f"unexpected role request: {method} {url}"
                        )
                    return bootstrap._RestResponse(404, b"", {})

            transport.clock = lambda: current[0]
            transport.sleep = lambda seconds: current.__setitem__(
                0,
                current[0] + dt.timedelta(seconds=seconds) + overshoot,
            )
            session = AbsentDefinitionSession()
            transport.session = session
            transport._active_protected_role_add = operation["id"]
            proof = {
                "operationId": operation["id"],
                "status": "applied-readback-pending",
                "owned": True,
                "cleanupKey": "uploader-package-role",
                "details": {
                    "cleanupKey": "uploader-package-role",
                    "definitionAttempted": True,
                    "definitionCreated": False,
                    "definitionReadbackExact": False,
                    "definitionAmbiguous": True,
                    "assignmentAttempted": False,
                    "assignmentCreated": False,
                    "assignmentReadbackExact": False,
                },
            }
            state = {"proofs": {operation["id"]: proof}}
            with (
                mock.patch.object(transport, "_arm_delete") as delete,
                self.assertRaisesRegex(
                    bootstrap.BootstrapError,
                    "settlement clock is invalid",
                ),
            ):
                transport.compensate_temporary(operation, proof, state)
            delete.assert_not_called()
            self.assertTrue(session.calls)
            self.assertTrue(
                all(observed_at < settlement_boundary for *_, observed_at in session.calls)
            )

    def test_definition_409_412_and_200_are_unowned_and_never_deleted(self):
        for status in (409, 412, 200):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as folder:
                receipt = Path(folder) / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
                transport, operation, definition_resource, _definition = (
                    self._temporary_role_transport_fixture(receipt)
                )
                definition_url = transport._arm_url(
                    definition_resource, "2022-04-01"
                )

                class DefinitionStatusSession:
                    def __init__(self):
                        self.calls = []

                    def request(self, method, url, **_kwargs):
                        self.calls.append((method, url))
                        if method == "GET" and url == definition_url:
                            return bootstrap._RestResponse(404, b"", {})
                        if method == "PUT" and url == definition_url:
                            return bootstrap._RestResponse(status, b"", {})
                        raise AssertionError(f"unexpected role request: {method} {url}")

                session = DefinitionStatusSession()
                transport.session = session
                self._bind_temporary_role_test_ledger(transport, receipt)
                transport._active_operation_id = operation["id"]
                with self.assertRaises(bootstrap.BootstrapError) as raised:
                    transport._mutate_temporary_role_impl(operation["id"], {})
                self.assertNotIsInstance(
                    raised.exception, bootstrap.OwnedTemporaryMutationError
                )
                self.assertNotIsInstance(
                    raised.exception, bootstrap._MutationOwnershipAmbiguity
                )
                self.assertEqual(
                    [call for call in session.calls if call[0] == "DELETE"], []
                )

    def test_assignment_409_412_and_200_preserve_unowned_assignment_and_definition(self):
        for status in (409, 412, 200):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as folder:
                receipt = Path(folder) / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
                transport, operation, definition_resource, definition = (
                    self._temporary_role_transport_fixture(receipt)
                )
                assignment_resource, assignment = (
                    self._temporary_package_assignment_document(
                        transport, definition_resource
                    )
                )
                definition_url = transport._arm_url(
                    definition_resource, "2022-04-01"
                )
                assignment_url = transport._arm_url(
                    assignment_resource, "2022-04-01"
                )

                class AssignmentStatusSession:
                    def __init__(self):
                        self.definition_present = False
                        self.assignment_present = False
                        self.calls = []

                    def request(self, method, url, **_kwargs):
                        self.calls.append((method, url))
                        if url == definition_url:
                            if method == "GET":
                                return (
                                    bootstrap._RestResponse(
                                        200,
                                        bootstrap.canonical_json_bytes(definition),
                                        {},
                                    )
                                    if self.definition_present
                                    else bootstrap._RestResponse(404, b"", {})
                                )
                            if method == "PUT":
                                self.definition_present = True
                                return bootstrap._RestResponse(201, b"", {})
                        if url == assignment_url:
                            if method == "GET":
                                return (
                                    bootstrap._RestResponse(
                                        200,
                                        bootstrap.canonical_json_bytes(assignment),
                                        {},
                                    )
                                    if self.assignment_present
                                    else bootstrap._RestResponse(404, b"", {})
                                )
                            if method == "PUT":
                                # The explicit non-create response is modeled as
                                # a concurrent exact assignment. This request
                                # never owns it and cleanup must not delete it or
                                # the referenced definition.
                                self.assignment_present = True
                                return bootstrap._RestResponse(status, b"", {})
                        raise AssertionError(
                            f"unexpected role request: {method} {url}"
                        )

                session = AssignmentStatusSession()
                transport.session = session
                self._bind_temporary_role_test_ledger(transport, receipt)
                transport._active_operation_id = operation["id"]
                with self.assertRaises(
                    bootstrap.OwnedTemporaryMutationError
                ) as raised:
                    transport._mutate_temporary_role_impl(operation["id"], {})
                proof = raised.exception.proof
                self.assertTrue(proof["details"]["definitionCreated"])
                self.assertFalse(proof["details"]["assignmentCreated"])
                self.assertNotIn("assignmentAmbiguous", proof["details"])
                with self.assertRaisesRegex(
                    bootstrap.BootstrapError,
                    "unowned temporary role assignment is present",
                ):
                    transport.compensate_temporary(
                        operation,
                        proof,
                        {"proofs": {operation["id"]: proof}},
                    )
                self.assertEqual(
                    [call for call in session.calls if call[0] == "DELETE"], []
                )
                self.assertTrue(session.definition_present)
                self.assertTrue(session.assignment_present)

    def test_temporary_role_provisional_compensation_accepts_absence_and_rejects_third_state(self):
        with tempfile.TemporaryDirectory() as folder:
            receipt = Path(folder) / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
            transport, operation, _definition_resource, definition = (
                self._temporary_role_transport_fixture(receipt)
            )
            proof = {
                "operationId": operation["id"],
                "status": "applied-readback-pending",
                "owned": True,
                "cleanupKey": "uploader-package-role",
                "details": {
                    "cleanupKey": "uploader-package-role",
                    "definitionAttempted": True,
                    "definitionCreated": False,
                    "definitionAmbiguous": True,
                    "assignmentAttempted": False,
                    "assignmentCreated": False,
                },
            }
            state = {"proofs": {operation["id"]: proof}}

            def absent_assignment(*_args, **_kwargs):
                transport._last_guarded_assignment_was_present = False
                return bootstrap._expected_deletion_lock_proof(
                    "removeOwnedUploaderPackageRole"
                )

            transport._active_protected_role_add = operation["id"]
            absent_responses = iter(
                [bootstrap._RestResponse(404, b"", {}) for _ in range(4)]
            )
            with (
                mock.patch.object(
                    bootstrap, "TEMPORARY_ROLE_CREATE_SETTLEMENT_SECONDS", 0
                ),
                mock.patch.object(
                    transport,
                    "_read_request_with_transport_retry",
                    side_effect=lambda *_args, **_kwargs: next(absent_responses),
                ),
                mock.patch.object(
                    transport,
                    "_guarded_assignment_delete",
                    side_effect=absent_assignment,
                ),
                mock.patch.object(
                    transport, "_verify_cleanup_lock_inventory"
                ),
                mock.patch.object(transport, "_arm_delete") as delete,
                mock.patch.object(
                    transport,
                    "_prove_temporary_role_marker_inventories_absent",
                    return_value="0" * 64,
                ),
                mock.patch.object(transport, "_prove_probe_ids", return_value=[]),
            ):
                cleanup = transport.compensate_temporary(operation, proof, state)
            self.assertEqual(cleanup["status"], "removed-exact")
            delete.assert_not_called()

            drifted = copy.deepcopy(definition)
            drifted["properties"]["description"] = "marker-drifted"
            transport._active_protected_role_add = operation["id"]
            drifted_responses = iter(
                [
                    bootstrap._RestResponse(
                        200, bootstrap.canonical_json_bytes(drifted), {}
                    ),
                ]
            )
            with (
                mock.patch.object(
                    bootstrap, "TEMPORARY_ROLE_CREATE_SETTLEMENT_SECONDS", 0
                ),
                mock.patch.object(
                    transport,
                    "_read_request_with_transport_retry",
                    side_effect=lambda *_args, **_kwargs: next(drifted_responses),
                ),
                mock.patch.object(
                    transport,
                    "_guarded_assignment_delete",
                    side_effect=absent_assignment,
                ),
                mock.patch.object(
                    transport, "_verify_cleanup_lock_inventory"
                ),
                mock.patch.object(transport, "_arm_delete") as delete,
                self.assertRaisesRegex(bootstrap.BootstrapError, "third state"),
            ):
                transport.compensate_temporary(operation, proof, state)
            delete.assert_not_called()

    def _retired_role_gate_fixture(self):
        resources = {item["id"]: item for item in self.plan["resourceInventory"]}
        retired_urls = []
        for spec in bootstrap.RETIRED_TEMPORARY_ROLE_SPECS:
            scope = resources[spec["scopeResourceKey"]]["resourceId"]
            retired_urls.extend(
                (
                    (
                        "definition",
                        "https://management.azure.com/subscriptions/"
                        f"{bootstrap.SUBSCRIPTION}/providers/"
                        "Microsoft.Authorization/roleDefinitions/"
                        f"{spec['definitionId']}?api-version=2022-04-01",
                    ),
                    (
                        "assignment",
                        "https://management.azure.com"
                        f"{scope}/providers/Microsoft.Authorization/roleAssignments/"
                        f"{spec['assignmentId']}?api-version=2022-04-01",
                    ),
                )
            )

        class Session:
            def __init__(self):
                self.calls = []
                self.present_urls = set()
                self.marker_documents = {}

            def request(self, method, url, **kwargs):
                if method != "GET" or kwargs.get("body") is not None:
                    raise AssertionError("retired-role gate lost its read-only shape")
                marker_urls = {
                    item["url"]
                    for item in bootstrap._temporary_role_marker_inventory_requests()
                }
                if url in marker_urls:
                    self.calls.append(url)
                    return bootstrap._RestResponse(
                        200,
                        bootstrap.canonical_json_bytes(
                            self.marker_documents.get(url, {"value": []})
                        ),
                        {"content-type": "application/json"},
                    )
                if url not in {item[1] for item in retired_urls}:
                    raise AssertionError(f"unexpected retired-role gate URL: {url}")
                self.calls.append(url)
                status = 200 if url in self.present_urls else 404
                return bootstrap._RestResponse(
                    status=status,
                    body=bootstrap.canonical_json_bytes(
                        {
                            "error": {
                                "code": "RetiredRoleStillPresent"
                                if status == 200
                                else "NotFound"
                            }
                        }
                    ),
                    headers={"content-type": "application/json"},
                )

        session = Session()
        preflight = {
            "projection": {
                "operationAdmissions": [],
                "postconditionAdmissions": [],
                "probes": [],
                "productionBoundaryObservation": {
                    "probeIds": [],
                    "sourceProjection": {},
                },
            }
        }
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization={
                "authorizationId": AUTH_ID,
                "validity": {
                    "expiresAt": stamp(NOW + dt.timedelta(minutes=30))
                }
            },
            plan=self.plan,
            package={},
            preflight=preflight,
            clock=lambda: NOW,
            session=session,
        )
        transport._collect_production_boundary = lambda: ({}, {})
        return transport, session, retired_urls

    def test_retired_temporary_role_gate_accepts_all_exact_404s(self):
        transport, session, retired_urls = self._retired_role_gate_fixture()
        self.assertEqual(len(retired_urls), 16)
        self.assertEqual(len({url for _kind, url in retired_urls}), 16)

        transport.collect_preflight(self.plan)

        self.assertEqual(
            session.calls,
            [
                item["url"]
                for item in bootstrap._temporary_role_marker_inventory_requests()
            ]
            + [url for _kind, url in retired_urls],
        )
        self.assertEqual(
            len(transport._retired_role_absence_preflight), len(retired_urls)
        )
        self.assertTrue(
            all(
                item["status"] == 404
                for item in transport._retired_role_absence_preflight
            )
        )

    def test_authorized_retired_role_absence_rejects_non_exact_projection(self):
        base = build_projection(self.plan, self.package)
        field = base["productionBoundaryObservation"][
            "retiredTemporaryRoleAbsence"
        ]
        variants = {}
        omitted = copy.deepcopy(base)
        omitted["productionBoundaryObservation"][
            "retiredTemporaryRoleAbsence"
        ].pop()
        variants["omitted-resource"] = omitted
        duplicate = copy.deepcopy(base)
        duplicate_field = duplicate["productionBoundaryObservation"][
            "retiredTemporaryRoleAbsence"
        ]
        duplicate_field[1] = copy.deepcopy(duplicate_field[0])
        variants["duplicate-resource"] = duplicate
        replacement = copy.deepcopy(base)
        replacement["productionBoundaryObservation"][
            "retiredTemporaryRoleAbsence"
        ][0]["url"] = field[1]["url"]
        variants["replacement-resource"] = replacement
        status_drift = copy.deepcopy(base)
        status_drift["productionBoundaryObservation"][
            "retiredTemporaryRoleAbsence"
        ][0]["status"] = 200
        variants["status-drift"] = status_drift
        timestamp_drift = copy.deepcopy(base)
        timestamp_drift["productionBoundaryObservation"][
            "retiredTemporaryRoleAbsence"
        ][0]["observedAt"] = stamp(NOW + dt.timedelta(seconds=1))
        variants["timestamp-drift"] = timestamp_drift
        missing_digest = copy.deepcopy(base)
        del missing_digest["productionBoundaryObservation"][
            "retiredTemporaryRoleAbsence"
        ][0]["responseSha256"]
        variants["missing-digest"] = missing_digest

        for name, projection in variants.items():
            with self.subTest(variant=name), tempfile.TemporaryDirectory() as folder:
                authorization = build_authorization(
                    self.plan,
                    self.plan_sha,
                    self.package,
                    projection,
                    Path(folder) / "receipt",
                )
                preflight = {
                    "schemaVersion": 1,
                    "status": "observed-read-only",
                    "observedAt": authorization["observedPreflight"]["observedAt"],
                    "projection": projection,
                    "projectionSha256": authorization["observedPreflight"]["sha256"],
                }
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_preflight_evidence(
                        preflight, authorization, self.plan
                    )

    def test_any_retired_temporary_role_blocks_fresh_preflight(self):
        for kind, present_url in self._retired_role_gate_fixture()[2]:
            with self.subTest(kind=kind, url=present_url):
                transport, session, _retired_urls = self._retired_role_gate_fixture()
                session.present_urls.add(present_url)
                with self.assertRaisesRegex(
                    bootstrap.BootstrapError,
                    f"fresh preflight found a retired temporary role {kind}",
                ):
                    transport.collect_preflight(self.plan)
                self.assertIn(present_url, session.calls)

    def test_any_retired_temporary_role_reappearance_blocks_terminal_boundary(self):
        for kind, present_url in self._retired_role_gate_fixture()[2]:
            with self.subTest(kind=kind, url=present_url):
                transport, session, _retired_urls = self._retired_role_gate_fixture()
                transport.collect_preflight(self.plan)
                session.calls.clear()
                session.present_urls.add(present_url)
                with self.assertRaisesRegex(
                    bootstrap.BootstrapError,
                    f"terminal boundary found a retired temporary role {kind}",
                ):
                    transport.observe_production_boundary()
                self.assertIn(present_url, session.calls)

    def test_prior_authorization_marker_blocks_fresh_and_terminal_inventories(self):
        prior_authorization_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        prior_metadata = bootstrap._temporary_role_metadata(
            prior_authorization_id, "uploader-package-role"
        )
        marker_requests = {
            item["kind"]: item["url"]
            for item in bootstrap._temporary_role_marker_inventory_requests()
        }
        documents = [
            (
                "definitionInventory",
                {
                "value": [
                    {
                        "id": (
                            f"/subscriptions/{bootstrap.SUBSCRIPTION}/providers/"
                            "Microsoft.Authorization/roleDefinitions/"
                            "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
                        ),
                        "properties": {
                            "roleName": prior_metadata["roleName"],
                            "description": prior_metadata["description"],
                        },
                    }
                ]
                },
            )
        ]
        for kind, marker_url in marker_requests.items():
            if not kind.startswith("assignmentInventory:"):
                continue
            scope_url = marker_url.split(
                "/providers/Microsoft.Authorization/roleAssignments?", 1
            )[0]
            scope_resource_id = scope_url.removeprefix(
                "https://management.azure.com"
            )
            documents.append(
                (
                    kind,
                    {
                        "value": [
                            {
                                "id": (
                                    f"{scope_resource_id}/providers/"
                                    "Microsoft.Authorization/roleAssignments/"
                                    "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
                                ),
                                "properties": {
                                    "description": prior_metadata[
                                        "assignmentDescription"
                                    ],
                                    "roleDefinitionId": (
                                        f"/subscriptions/{bootstrap.SUBSCRIPTION}/providers/"
                                        "Microsoft.Authorization/roleDefinitions/"
                                        "ffffffff-ffff-4fff-8fff-ffffffffffff"
                                    ),
                                },
                            }
                        ]
                    },
                )
            )
        for phase in ("fresh", "terminal"):
            for kind, document in documents:
                with self.subTest(phase=phase, kind=kind):
                    transport, session, _retired_urls = self._retired_role_gate_fixture()
                    if phase == "terminal":
                        transport.collect_preflight(self.plan)
                        session.calls.clear()
                    marker_url = marker_requests[kind]
                    session.marker_documents[marker_url] = document
                    residual_kind = (
                        "definition" if kind == "definitionInventory" else "assignment"
                    )
                    with self.assertRaisesRegex(
                        bootstrap.BootstrapError,
                        f"residual PaperDesk temporary role {residual_kind}",
                    ):
                        if phase == "fresh":
                            transport.collect_preflight(self.plan)
                        else:
                            transport.observe_production_boundary()
                    self.assertIn(marker_url, session.calls)

    def test_transport_terminal_source_builder_uses_raw_reviewed_plan(self):
        transport, _session, _retired_urls = self._retired_role_gate_fixture()
        raw_temporary = transport.reviewed_plan["temporaryAccess"]
        bound_temporary = transport.plan["temporaryAccess"]
        self.assertNotIn("roleDefinitionId", raw_temporary)
        self.assertIn("roleDefinitionId", bound_temporary)
        self.assertEqual(transport.reviewed_plan, self.plan)

        transport.collect_preflight(self.plan)
        transport.observe_production_boundary()
        transport._package_readback_bytes = b"exact-package"
        transport._validated_source_projections = []
        state = {
            "operationStatuses": {},
            "operationObservedAt": {},
            "postconditionProjections": [],
            "productionBoundaryPostExecution": {},
        }
        with (
            mock.patch.object(
                transport,
                "_journal_source_projection",
                return_value={"mutationJournal": []},
            ),
            mock.patch.object(
                bootstrap,
                "build_terminal_source_evidence",
                return_value={"status": "sentinel"},
            ) as builder,
        ):
            result = transport.finalize_terminal_source_evidence(
                state,
                claimed_at=stamp(NOW),
                observed_at=stamp(NOW + dt.timedelta(seconds=1)),
            )

        self.assertEqual(result, {"status": "sentinel"})
        supplied_plan = builder.call_args.kwargs["plan"]
        self.assertEqual(supplied_plan, self.plan)
        self.assertNotIn("roleDefinitionId", supplied_plan["temporaryAccess"])

    def test_plan_keeps_protected_role_lifecycles_non_overlapping(self):
        mutation_ids = [item["id"] for item in self.plan["mutations"]]
        expected_phase = [
            "addOwnedOperatorControllerCanaryRole",
            "proveControllerLockContainerEmpty",
            "createControllerLeaseCanaryBlob",
            "exerciseControllerLeaseCanary",
            "removeControllerLeaseCanaryBlob",
            "removeOwnedOperatorControllerCanaryRole",
            "addOwnedUploaderPackageRole",
            "uploadVersionedBridgePackage",
            "removeOwnedUploaderPackageRole",
            "addOwnedOperatorKeyReadRole",
            "readBackExactSigningPublicJwk",
            "removeOwnedOperatorKeyReadRole",
            "addOwnedOperatorFenceBootstrapRole",
            "createInitialIdleActivationFence",
            "removeOwnedOperatorFenceBootstrapRole",
        ]
        self.assertEqual(
            [item for item in mutation_ids if item in set(expected_phase)],
            expected_phase,
        )
        active = None
        maximum_active = 0
        for mutation_id in mutation_ids:
            if mutation_id in bootstrap.PROTECTED_ROLE_LIFECYCLES:
                self.assertIsNone(active)
                active = mutation_id
            elif mutation_id in bootstrap.PROTECTED_ROLE_LIFECYCLES.values():
                self.assertIsNotNone(active)
                self.assertEqual(
                    bootstrap.PROTECTED_ROLE_LIFECYCLES[active], mutation_id
                )
                active = None
            maximum_active = max(maximum_active, int(active is not None))
        self.assertIsNone(active)
        self.assertEqual(maximum_active, 1)

    def test_existing_registry_role_metadata_is_canonical_without_authority_drift(self):
        definitions = bootstrap._custom_role_definition_specs(self.plan)
        cases = {
            "b5d9d7c7-9367-4ac0-9d41-28b71e0d517d": {
                "roleName": "PaperDesk Accepted Release Blob Append Writer",
                "description": (
                    "PaperDesk accepted-release registry: create-only blob "
                    "data-plane permission at an exact container assignment scope."
                ),
                "dataAction": (
                    "Microsoft.Storage/storageAccounts/blobServices/containers/"
                    "blobs/add/action"
                ),
            },
            "e005b62b-037b-4989-b492-932669ec0842": {
                "roleName": "PaperDesk Accepted Release Blob Reader",
                "description": (
                    "PaperDesk accepted-release registry: read-only blob "
                    "data-plane permission at an exact container assignment scope."
                ),
                "dataAction": (
                    "Microsoft.Storage/storageAccounts/blobServices/containers/"
                    "blobs/read"
                ),
            },
        }
        for definition_id, expected in cases.items():
            with self.subTest(definition_id=definition_id):
                projection = definitions[definition_id]
                properties = projection["properties"]
                self.assertEqual(properties["roleName"], expected["roleName"])
                self.assertEqual(properties["description"], expected["description"])
                self.assertEqual(properties["type"], "CustomRole")
                self.assertEqual(
                    properties["permissions"],
                    [
                        {
                            "actions": [],
                            "notActions": [],
                            "dataActions": [expected["dataAction"]],
                            "notDataActions": [],
                        }
                    ],
                )
                self.assertEqual(
                    properties["assignableScopes"],
                    [f"/subscriptions/{bootstrap.SUBSCRIPTION}"],
                )

    def test_role_assignment_inventory_uses_supported_unfiltered_collection(self):
        url = bootstrap._operation_readback_url(
            "createExactRoleAssignments", self.plan, {}
        )
        self.assertEqual(
            url,
            "https://management.azure.com/subscriptions/"
            f"{bootstrap.SUBSCRIPTION}/providers/Microsoft.Authorization/"
            "roleAssignments?api-version=2022-04-01",
        )
        self.assertNotIn("atScopeAndBelow", url)

    def test_service_principal_readback_expands_app_role_assignments(self):
        url = bootstrap._operation_readback_url(
            "createPublisherServicePrincipal", self.plan, {}
        )
        self.assertIn(
            "&$expand=appRoleAssignments($select=id,principalId,resourceId,appRoleId)",
            url,
        )
        self.assertNotIn("keyCredentials,appRoleAssignments", url)
        self.assertEqual(
            url,
            bootstrap._operation_readback_url(
                "grantPublisherGraphApplicationReadAll", self.plan, {}
            ),
        )

    def test_graph_assignment_id_accepts_live_shape_and_rejects_noncanonical_forms(self):
        assignment_id = CANONICAL_GRAPH_ASSIGNMENT_ID
        resource_id = "33333333-3333-4333-8333-333333333333"
        legacy_guid = "22222222-2222-4222-8222-222222222222"
        self.assertEqual(len(assignment_id), 43)
        self.assertEqual(
            len(base64.urlsafe_b64decode(assignment_id + "=")),
            32,
        )
        self.assertEqual(
            bootstrap._graph_app_role_assignment_id(
                assignment_id, "live publisher Graph assignment ID"
            ),
            assignment_id,
        )
        self.assertEqual(
            bootstrap._graph_app_role_assignment_id(
                legacy_guid, "legacy publisher Graph assignment ID"
            ),
            legacy_guid,
        )
        context = {
            "executionDecision": "adopt-exact",
            "adopted": {
                "assignmentId": assignment_id,
                "resourceId": resource_id,
            },
        }
        self.assertEqual(
            bootstrap._validate_operation_context(
                "grantPublisherGraphApplicationReadAll",
                context,
                {},
            ),
            context,
        )

        malformed = {
            "short": assignment_id[:-1],
            "long": assignment_id + "A",
            "padded": assignment_id + "=",
            "alphabet": assignment_id[:-1] + "+",
            # The low padding bits differ. Python can decode this to the same
            # 32 bytes, but canonical re-encoding produces the original token.
            "noncanonical": assignment_id[:-1] + "9",
        }
        self.assertEqual(
            base64.urlsafe_b64decode(malformed["noncanonical"] + "="),
            base64.urlsafe_b64decode(assignment_id + "="),
        )
        for variant, value in malformed.items():
            with self.subTest(variant=variant), self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "not an exact Microsoft Graph assignment ID",
            ):
                bootstrap._graph_app_role_assignment_id(value, "assignment ID")
            invalid_context = copy.deepcopy(context)
            invalid_context["adopted"]["assignmentId"] = value
            with self.subTest(context_variant=variant), self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "not an exact Microsoft Graph assignment ID",
            ):
                bootstrap._validate_operation_context(
                    "grantPublisherGraphApplicationReadAll",
                    invalid_context,
                    {},
                )

    def test_if_match_etag_serialization_remains_strict_for_supported_resources(self):
        self.assertEqual(
            bootstrap._if_match_etag("1DD39E07D4DEF60", "raw ARM ETag"),
            '"1DD39E07D4DEF60"',
        )
        self.assertEqual(
            bootstrap._if_match_etag('"already-quoted"', "quoted ETag"),
            '"already-quoted"',
        )
        for malformed in ("", "abc", 'W/"weak"', '"unterminated'):
            with self.subTest(malformed=malformed), self.assertRaisesRegex(
                bootstrap.BootstrapError, "strong ETag token"
            ):
                bootstrap._if_match_etag(malformed, "malformed ETag")

        source = inspect.getsource(
            bootstrap.AzureCliBootstrapTransport._mutate
        )
        self.assertEqual(source.count("_if_match_etag("), 5)
        self.assertNotIn('"If-Match": str(', source)
        self.assertNotIn('"If-Match": current_etag', source)

    def test_supported_bridge_resource_write_uses_etag_but_app_settings_uses_no_fake_cas(self):
        projection = build_projection(self.plan, self.package)
        configure_context = next(
            item["context"]
            for item in projection["operationAdmissions"]
            if item["operationId"]
            == "configureBridgeExactVersionedPackageAndCriticalSettings"
        )
        receipt = Path("C:/outside") / (
            f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
        )
        authorization = build_authorization(
            self.plan, self.plan_sha, self.package, projection, receipt
        )

        class Session:
            def __init__(self):
                self.requests = []

            def request(self, method, url, *, body=None, headers=None):
                self.requests.append((method, url, body, dict(headers or {})))
                return bootstrap._RestResponse(
                    200,
                    bootstrap.canonical_json_bytes({"properties": {}}),
                    {"ETag": "1DD39E07D4DEF60"},
                )

        session = Session()
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=authorization,
            plan=self.plan,
            package=self.package,
            preflight={"projection": projection},
            clock=lambda: NOW,
            session=session,
        )
        resources = {
            item["id"]: item for item in self.plan["resourceInventory"]
        }
        state = {
            "proofs": {
                "createStoppedPrivateBridge": {
                    "details": {"etag": "1DD39E07D4DEF60"}
                },
                "createBridgeIdentity": {
                    "details": {
                        "resourceId": resources["bridgeIdentity"]["resourceId"]
                    }
                },
                "createSignerIdentity": {
                    "details": {
                        "resourceId": resources["signerIdentity"]["resourceId"]
                    }
                },
                "createProductionActivationIdentity": {
                    "details": {
                        "resourceId": resources[
                            "productionActivationIdentity"
                        ]["resourceId"]
                    }
                },
            },
            "authorizationSha256": "a" * 64,
            "planSha256": self.plan_sha,
            "package": self.package,
        }
        attach = next(
            item
            for item in self.plan["mutations"]
            if item["id"] == "attachFiveUamisOnlyToBridge"
        )
        attach_response = bootstrap._RestResponse(
            200,
            bootstrap.canonical_json_bytes(
                {
                    "identity": {
                        "type": "UserAssigned",
                        "userAssignedIdentities": {
                            resources[key]["resourceId"]: {}
                            for key in (
                                "bridgeIdentity",
                                "registryWriterIdentity",
                                "registryReaderIdentity",
                                "signerIdentity",
                                "productionActivationIdentity",
                            )
                        },
                    }
                }
            ),
            {"ETag": "1DD39E07D4DEF61"},
        )
        with mock.patch.object(
            transport, "_mutation_request", return_value=attach_response
        ) as request:
            transport._mutate(attach, state)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(
            request.call_args.kwargs["headers"]["If-Match"],
            '"1DD39E07D4DEF60"',
        )
        with mock.patch.object(
            transport,
            "_mutation_request",
            return_value=bootstrap._RestResponse(
                412, bootstrap.canonical_json_bytes({"error": "precondition"}), {}
            ),
        ) as rejected:
            with self.assertRaises(bootstrap.BootstrapError):
                transport._mutate(attach, state)
        self.assertEqual(rejected.call_count, 1)

        configure = next(
            item
            for item in self.plan["mutations"]
            if item["id"]
            == "configureBridgeExactVersionedPackageAndCriticalSettings"
        )
        state["proofs"]["uploadVersionedBridgePackage"] = {
            "details": {
                "url": "https://example.invalid/package.zip",
                "versionId": "version-1",
            }
        }
        with (
            mock.patch.object(
                bootstrap,
                "_bootstrap_self_test_control",
                return_value={"schemaVersion": 1, "issuedAt": stamp(NOW), "expiresAt": stamp(NOW + dt.timedelta(seconds=900))},
            ),
            mock.patch.object(
                transport,
                "_arm_put",
                return_value={"id": resources["bridgeSite"]["resourceId"]},
            ) as arm_put,
        ):
            transport._mutate(configure, state)
        self.assertNotIn("headers", arm_put.call_args.kwargs)

    def test_recovered_exact_five_attachment_is_get_proved_without_patch(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)
        projection = copy.deepcopy(fixture["preflightProjection"])
        prior = {
            item["operationId"]: item["sourceProjection"]
            for item in fixture["sourceEvidence"]["allOperationProjections"]
        }
        attached_projection = prior["attachFiveUamisOnlyToBridge"]["projection"]
        identity = attached_projection["identity"]
        identity_ids = sorted(item.lower() for item in identity["userAssignedIdentities"])
        # Azure Web Apps commonly returns the strong hexadecimal ETag without
        # HTTP quotes.  The observer retains that exact raw token.
        etag = "1DD3A097267B9E0"
        identity_digest = bootstrap.sha256_bytes(bootstrap.canonical_json_bytes(identity))
        create_admission = next(
            item for item in projection["operationAdmissions"]
            if item["operationId"] == "createStoppedPrivateBridge"
        )
        create_admission["status"] = "exact"
        create_admission["context"] = {
            "executionDecision": "adopt-exact",
            "adopted": {
                "resourceId": attached_projection["id"],
                "name": attached_projection["name"],
                "etag": etag,
                "bridgeIdentityMode": "exact-five-user-assigned",
                "identityResourceIds": identity_ids,
                "identityProjectionSha256": identity_digest,
            },
        }
        attach_admission = next(
            item
            for item in projection["operationAdmissions"]
            if item["operationId"] == "attachFiveUamisOnlyToBridge"
        )
        attach_admission["status"] = "exact"
        attach_admission["context"] = {
            "executionDecision": "adopt-exact",
            "adopted": {
                "identityResourceIds": identity_ids,
                "expectedEtag": etag,
                "identityProjectionSha256": identity_digest,
            },
        }
        receipt = Path("C:/outside") / (
            f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
        )
        authorization = build_authorization(
            self.plan, self.plan_sha, self.package, projection, receipt
        )
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=authorization,
            plan=self.plan,
            package=self.package,
            preflight={"projection": projection},
            clock=lambda: NOW,
            session=mock.Mock(),
        )
        bootstrap.validate_preflight_evidence(
            {
                "schemaVersion": 1,
                "status": "observed-read-only",
                "observedAt": authorization["observedPreflight"]["observedAt"],
                "projection": projection,
                "projectionSha256": bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes(projection)
                ),
            },
            authorization,
            self.plan,
        )
        transport._validated_source_projections.update(prior)
        body = {
            "id": attached_projection["id"],
            "name": attached_projection["name"],
            "type": "Microsoft.Web/sites",
            "kind": attached_projection["kind"],
            "identity": identity,
            "properties": {
                key: attached_projection[key]
                for key in (
                    "httpsOnly", "state", "publicNetworkAccess", "serverFarmId",
                    "virtualNetworkSubnetId", "outboundVnetRouting",
                )
            },
        }
        transport.session.request.return_value = bootstrap._RestResponse(
            200, bootstrap.canonical_json_bytes(body), {"ETag": etag}
        )
        attach = next(
            item
            for item in self.plan["mutations"]
            if item["id"] == "attachFiveUamisOnlyToBridge"
        )
        with mock.patch.object(transport, "_mutate") as mutate:
            result = transport.apply_operation(attach, {})
        mutate.assert_not_called()
        self.assertEqual(transport.session.request.call_count, 1)
        self.assertEqual(transport.session.request.call_args.args[0], "GET")
        self.assertEqual(result["status"], "adopted-exact")
        self.assertFalse(result["owned"])
        expected = transport.probes[attach_admission["desiredProbeIds"][0]]
        for authorized_etag, live_etag in (
            (f'"{etag}"', f'"{etag}"'),
            (etag, f'"{etag}"'),
            (f'"{etag}"', etag),
        ):
            facts = copy.deepcopy(attach_admission["context"]["adopted"])
            facts["expectedEtag"] = authorized_etag
            response = bootstrap._RestResponse(
                200, bootstrap.canonical_json_bytes(body), {"ETag": live_etag}
            )
            with self.subTest(
                authorized_etag=authorized_etag, live_etag=live_etag
            ):
                transport._validate_readback_response(
                    expected, response, runtime_facts=facts
                )
        invalid_responses = {}
        unsafe = copy.deepcopy(body)
        unsafe["properties"]["httpsOnly"] = False
        invalid_responses["unsafe posture"] = bootstrap._RestResponse(
            200, bootstrap.canonical_json_bytes(unsafe), {"ETag": etag}
        )
        malformed = copy.deepcopy(body)
        first = next(iter(malformed["identity"]["userAssignedIdentities"]))
        malformed["identity"]["userAssignedIdentities"][first]["clientId"] = "not-a-guid"
        invalid_responses["malformed identity metadata"] = bootstrap._RestResponse(
            200, bootstrap.canonical_json_bytes(malformed), {"ETag": etag}
        )
        invalid_responses["etag drift"] = bootstrap._RestResponse(
            200, bootstrap.canonical_json_bytes(body),
            {"ETag": etag[:-1] + ("1" if etag[-1] != "1" else "2")},
        )
        for label, response in invalid_responses.items():
            with self.subTest(label=label), self.assertRaises(bootstrap.BootstrapError):
                transport._validate_readback_response(
                    expected, response,
                    runtime_facts=attach_admission["context"]["adopted"],
                )

    def test_recovered_bridge_preflight_cross_binding_rejects_every_tamper(self):
        projection = build_projection(self.plan, self.package)
        resources = {item["id"]: item for item in self.plan["resourceInventory"]}
        identity_ids = sorted(
            resources[key]["resourceId"] for key in (
                "bridgeIdentity", "registryWriterIdentity", "registryReaderIdentity",
                "signerIdentity", "productionActivationIdentity",
            )
        )
        create = next(item for item in projection["operationAdmissions"] if item["operationId"] == "createStoppedPrivateBridge")
        attach = next(item for item in projection["operationAdmissions"] if item["operationId"] == "attachFiveUamisOnlyToBridge")
        create["status"] = "exact"
        create["context"] = {"executionDecision": "adopt-exact", "adopted": {
            "resourceId": resources["bridgeSite"]["resourceId"],
            "name": resources["bridgeSite"]["name"], "etag": '"recovery"',
            "bridgeIdentityMode": "exact-five-user-assigned",
            "identityResourceIds": identity_ids, "identityProjectionSha256": "a" * 64,
        }}
        attach["status"] = "exact"
        attach["context"] = {"executionDecision": "adopt-exact", "adopted": {
            "identityResourceIds": identity_ids, "expectedEtag": '"recovery"',
            "identityProjectionSha256": "a" * 64,
        }}
        receipt = Path("C:/outside") / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"

        def validate(candidate):
            authorization = build_authorization(
                self.plan, self.plan_sha, self.package, candidate, receipt
            )
            document = {
                "schemaVersion": 1, "status": "observed-read-only",
                "observedAt": authorization["observedPreflight"]["observedAt"],
                "projection": candidate,
                "projectionSha256": bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes(candidate)
                ),
            }
            return bootstrap.validate_preflight_evidence(document, authorization, self.plan)

        validate(copy.deepcopy(projection))
        for label, mutate in {
            "mode": lambda c, a: c["context"]["adopted"].__setitem__("bridgeIdentityMode", "pristine-no-identity"),
            "decision": lambda c, a: a["context"].__setitem__("executionDecision", "apply-exact"),
            "list": lambda c, a: a["context"]["adopted"].__setitem__("identityResourceIds", list(reversed(identity_ids))),
            "etag": lambda c, a: a["context"]["adopted"].__setitem__("expectedEtag", '"other"'),
            "digest": lambda c, a: a["context"]["adopted"].__setitem__("identityProjectionSha256", "b" * 64),
        }.items():
            candidate = copy.deepcopy(projection)
            candidate_create = next(item for item in candidate["operationAdmissions"] if item["operationId"] == "createStoppedPrivateBridge")
            candidate_attach = next(item for item in candidate["operationAdmissions"] if item["operationId"] == "attachFiveUamisOnlyToBridge")
            mutate(candidate_create, candidate_attach)
            with self.subTest(label=label), self.assertRaises(bootstrap.BootstrapError):
                validate(candidate)

    def test_pristine_attachment_patches_once_then_get_proves_same_etag_and_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)
        projection = build_projection(self.plan, self.package)
        receipt = Path("C:/outside") / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
        authorization = build_authorization(
            self.plan, self.plan_sha, self.package, projection, receipt
        )
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=authorization, plan=self.plan, package=self.package,
            preflight={"projection": projection}, clock=lambda: NOW,
            session=mock.Mock(),
        )
        prior = {
            item["operationId"]: item["sourceProjection"]
            for item in fixture["sourceEvidence"]["allOperationProjections"]
        }
        transport._validated_source_projections.update(prior)
        attached = prior["attachFiveUamisOnlyToBridge"]["projection"]
        body = {
            "id": attached["id"], "name": attached["name"],
            "type": "Microsoft.Web/sites", "kind": attached["kind"],
            "identity": attached["identity"],
            "properties": {key: attached[key] for key in (
                "httpsOnly", "state", "publicNetworkAccess", "serverFarmId",
                "virtualNetworkSubnetId", "outboundVnetRouting",
            )},
        }
        response = bootstrap._RestResponse(
            200, bootstrap.canonical_json_bytes(body), {"ETag": '"after-attach"'}
        )
        transport.session.request.return_value = response
        state = {"proofs": {"createStoppedPrivateBridge": {"details": {"etag": '"before-attach"'}}}}
        for operation_id, resource_key in (
            ("createBridgeIdentity", "bridgeIdentity"),
            ("adoptExistingRegistryWriterIdentity", "registryWriterIdentity"),
            ("adoptExistingRegistryReaderIdentity", "registryReaderIdentity"),
            ("createSignerIdentity", "signerIdentity"),
            ("createProductionActivationIdentity", "productionActivationIdentity"),
        ):
            resource = next(item for item in self.plan["resourceInventory"] if item["id"] == resource_key)
            state["proofs"][operation_id] = {"details": {"resourceId": resource["resourceId"]}}
        attach = next(item for item in self.plan["mutations"] if item["id"] == "attachFiveUamisOnlyToBridge")
        with mock.patch.object(transport, "_mutation_request", return_value=response) as patch:
            result = transport.apply_operation(attach, state)
        patch.assert_called_once()
        self.assertEqual(patch.call_args.args[0], "PATCH")
        self.assertEqual(patch.call_args.kwargs["headers"]["If-Match"], '"before-attach"')
        self.assertEqual(transport.session.request.call_count, 1)
        self.assertEqual(result["details"]["expectedEtag"], '"after-attach"')
        self.assertEqual(
            result["details"]["identityProjectionSha256"],
            bootstrap.sha256_bytes(bootstrap.canonical_json_bytes(attached["identity"])),
        )

    def _custom_role_retry_transport(self, member_state, responses):
        projection = build_projection(self.plan, self.package)
        receipt = Path("C:/outside") / (
            f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
        )
        authorization = build_authorization(
            self.plan, self.plan_sha, self.package, projection, receipt
        )
        specs = bootstrap._custom_role_definition_specs(self.plan)
        definition_id = sorted(specs)[0]
        expected = specs[definition_id]

        class Session:
            def __init__(self, queue):
                self.queue = list(queue)
                self.requests = []

            def request(self, method, url, *, body=None, headers=None):
                self.requests.append((method, url, body, dict(headers or {})))
                result = self.queue.pop(0)
                if isinstance(result, Exception):
                    raise result
                return result

        session = Session(responses)
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=authorization,
            plan=self.plan,
            package=self.package,
            preflight={"projection": projection},
            clock=lambda: NOW,
            sleep=lambda _delay: None,
            session=session,
        )
        transport.admissions["createCustomRoleDefinitions"]["context"] = {
            "executionDecision": "apply-exact",
            "memberStates": {definition_id: member_state},
        }
        operation = next(
            item
            for item in self.plan["mutations"]
            if item["id"] == "createCustomRoleDefinitions"
        )
        exact = bootstrap._RestResponse(
            200, bootstrap.canonical_json_bytes(expected), {}
        )
        created = bootstrap._RestResponse(
            201, bootstrap.canonical_json_bytes(expected), {}
        )
        return transport, operation, session, exact, created, {definition_id: expected}

    def test_role_reconciliation_retries_transient_precondition_get(self):
        transient = bootstrap.BootstrapError("Azure REST transport failed closed")
        transport, operation, session, exact, _created, specs = (
            self._custom_role_retry_transport("exact", [transient])
        )
        session.queue.extend([exact, exact])
        with (
            mock.patch.object(
                bootstrap, "_custom_role_definition_specs", return_value=specs
            ),
            mock.patch.object(transport, "_mutation_request") as mutation,
        ):
            result = transport._mutate(operation, {})
        self.assertEqual(len(result["roleDefinitions"]), 1)
        self.assertEqual([item[0] for item in session.requests], ["GET", "GET", "GET"])
        mutation.assert_not_called()

    def test_role_reconciliation_exhausts_only_bounded_get_retries(self):
        failures = [
            bootstrap.BootstrapError("Azure REST transport failed closed")
            for _ in range(3)
        ]
        transport, operation, session, _exact, _created, specs = (
            self._custom_role_retry_transport("exact", failures)
        )
        with (
            mock.patch.object(
                bootstrap, "_custom_role_definition_specs", return_value=specs
            ),
            mock.patch.object(transport, "_mutation_request") as mutation,
            self.assertRaisesRegex(
                bootstrap.BootstrapError, "Azure REST transport failed closed"
            ),
        ):
            transport._mutate(operation, {})
        self.assertEqual([item[0] for item in session.requests], ["GET"] * 3)
        mutation.assert_not_called()

    def test_role_reconciliation_retries_post_put_readback_without_replaying_put(self):
        transient = bootstrap.BootstrapError("Azure REST transport failed closed")
        absent = bootstrap._RestResponse(404, b"", {})
        transport, operation, session, exact, created, specs = (
            self._custom_role_retry_transport("absent", [absent])
        )
        session.queue.extend([transient, exact])
        with (
            mock.patch.object(
                bootstrap, "_custom_role_definition_specs", return_value=specs
            ),
            mock.patch.object(
                transport, "_mutation_request", return_value=created
            ) as mutation,
        ):
            result = transport._mutate(operation, {})
        self.assertEqual(len(result["roleDefinitions"]), 1)
        mutation.assert_called_once()
        self.assertEqual(mutation.call_args.args[0], "PUT")
        self.assertEqual([item[0] for item in session.requests], ["GET", "GET", "GET"])

    def test_role_reconciliation_never_retries_direct_mutation_failure(self):
        absent = bootstrap._RestResponse(404, b"", {})
        transport, operation, session, _exact, _created, specs = (
            self._custom_role_retry_transport("absent", [absent])
        )
        with (
            mock.patch.object(
                bootstrap, "_custom_role_definition_specs", return_value=specs
            ),
            mock.patch.object(
                transport,
                "_mutation_request",
                side_effect=bootstrap.BootstrapError(
                    "Azure REST transport failed closed"
                ),
            ) as mutation,
            self.assertRaisesRegex(
                bootstrap.BootstrapError, "Azure REST transport failed closed"
            ),
        ):
            transport._mutate(operation, {})
        mutation.assert_called_once()
        self.assertEqual([item[0] for item in session.requests], ["GET"])

    def test_both_role_reconciliation_loops_own_only_bounded_get_retries(self):
        source = inspect.getsource(bootstrap.AzureCliBootstrapTransport._mutate)
        custom = source.split(
            'if operation_id == "createCustomRoleDefinitions":', 1
        )[1].split('if operation_id == "createExactRoleAssignments":', 1)[0]
        assignments = source.split(
            'if operation_id == "createExactRoleAssignments":', 1
        )[1].split('if operation_id == "createStoppedPrivateBridge":', 1)[0]
        for label, block in (("custom roles", custom), ("role assignments", assignments)):
            with self.subTest(loop=label):
                self.assertEqual(
                    block.count('_read_request_with_transport_retry("GET", url)'),
                    2,
                )
                self.assertNotIn('self.session.request("GET", url)', block)
                self.assertEqual(block.count("self._mutation_request("), 1)

    def test_storage_acl_normalization_preserves_supported_optional_boundaries(self):
        subnet = (
            f"/subscriptions/{bootstrap.SUBSCRIPTION}/resourceGroups/"
            "rg-master-data-structure-sea/providers/Microsoft.Network/"
            "virtualNetworks/vnet-master-data-structure-sea/subnets/"
            "snet-appservice-integration"
        )
        live_shape = {
            "defaultAction": "Deny",
            "bypass": "None",
            "ipRules": [],
            "ipv6Rules": [],
            "virtualNetworkRules": [
                {"id": subnet, "action": "Allow", "state": "Succeeded"}
            ],
        }
        normalized = bootstrap._normalize_storage_acl_prestate(live_shape)
        self.assertEqual(normalized["resourceAccessRules"], [])
        self.assertEqual(normalized["ipv6Rules"], [])
        self.assertEqual(
            bootstrap._validate_storage_acl_prestate(
                live_shape, adding=True, uploader="203.0.113.10/32"
            ),
            normalized,
        )
        nonempty_ipv6 = copy.deepcopy(live_shape)
        nonempty_ipv6["ipv6Rules"] = [
            {"value": "2001:db8::/64", "action": "Allow"}
        ]
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "exact reviewed topology"
        ):
            bootstrap._validate_storage_acl_prestate(
                nonempty_ipv6, adding=True, uploader="203.0.113.10/32"
            )
        unknown = copy.deepcopy(live_shape)
        unknown["futureAclFamily"] = []
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "fields are not exact"
        ):
            bootstrap._normalize_storage_acl_prestate(unknown)

    def test_storage_acl_readback_normalizes_optional_empty_families_before_digest(self):
        projection = build_projection(self.plan, self.package)
        receipt = Path("C:/outside") / (
            f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
        )
        authorization = build_authorization(
            self.plan, self.plan_sha, self.package, projection, receipt
        )
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=authorization,
            plan=self.plan,
            package=self.package,
            preflight={"projection": projection},
            session=object(),
        )

        def expected_and_facts(operation_id):
            admission = next(
                item
                for item in projection["operationAdmissions"]
                if item["operationId"] == operation_id
            )
            expected = transport.probes[admission["desiredProbeIds"][0]]
            if operation_id == "addOwnedUploaderIpv4Rule":
                desired = copy.deepcopy(admission["context"]["preNetworkAcls"])
                desired["ipRules"] = [
                    {"value": "203.0.113.10", "action": "Allow"}
                ]
                digest_key = "addedNetworkAclsSha256"
            else:
                desired = copy.deepcopy(admission["context"]["restoreNetworkAcls"])
                digest_key = "restoredNetworkAclsSha256"
            facts = {
                digest_key: bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes(desired)
                )
            }
            return expected, desired, facts

        def response(expected, acl):
            contract = expected["validatorContract"]
            return bootstrap._RestResponse(
                200,
                bootstrap.canonical_json_bytes(
                    {
                        "id": contract["targetResourceId"],
                        "name": contract["targetName"],
                        "type": "Microsoft.Storage/storageAccounts",
                        "properties": {"networkAcls": acl},
                    }
                ),
                {},
            )

        for operation_id in (
            "addOwnedUploaderIpv4Rule",
            "removeOwnedUploaderIpv4Rule",
        ):
            expected, desired, facts = expected_and_facts(operation_id)
            for omitted in (
                ("resourceAccessRules",),
                ("ipv6Rules",),
                ("resourceAccessRules", "ipv6Rules"),
            ):
                azure_shape = copy.deepcopy(desired)
                for field in omitted:
                    azure_shape.pop(field)
                with self.subTest(operation_id=operation_id, omitted=omitted):
                    transport._validate_readback_response(
                        expected, response(expected, azure_shape), facts
                    )

        expected, desired, facts = expected_and_facts(
            "addOwnedUploaderIpv4Rule"
        )
        drifted = copy.deepcopy(desired)
        drifted["ipRules"].append(
            {"value": "198.51.100.40", "action": "Allow"}
        )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "storage network ACL readback is not exact"
        ):
            transport._validate_readback_response(
                expected, response(expected, drifted), facts
            )
        unknown = copy.deepcopy(desired)
        unknown["futureAclFamily"] = []
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "fields are not exact"
        ):
            transport._validate_readback_response(
                expected, response(expected, unknown), facts
            )

    def test_operation_context_rejects_any_nonempty_bridge_app_settings(self):
        projection = build_projection(self.plan, self.package)
        receipt = Path("C:/outside") / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
        authorization = build_authorization(
            self.plan, self.plan_sha, self.package, projection, receipt
        )
        context = copy.deepcopy(
            next(
                item["context"]
                for item in projection["operationAdmissions"]
                if item["operationId"]
                == "configureBridgeExactVersionedPackageAndCriticalSettings"
            )
        )
        context["preAppSettings"] = {"VISIBLE_NONSECRET_SETTING": "value"}
        context["preAppSettingsSha256"] = bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(context["preAppSettings"])
        )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "app-settings prestate"
        ):
            bootstrap._validate_operation_context(
                "configureBridgeExactVersionedPackageAndCriticalSettings",
                context,
                authorization,
            )

    def test_controller_lock_handcrafted_adoption_is_rejected_by_policy_and_preflight(self):
        projection = build_projection(self.plan, self.package)
        receipt = Path("C:/outside") / (
            f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
        )
        authorization = build_authorization(
            self.plan, self.plan_sha, self.package, projection, receipt
        )
        operation_id = "createPrivateControllerLockContainer"
        handcrafted = {"executionDecision": "adopt-exact", "adopted": {}}
        with self.assertRaisesRegex(
            bootstrap.BootstrapError,
            "may not be skipped or adopted",
        ):
            bootstrap._validate_operation_context(
                operation_id, handcrafted, authorization
            )

        altered_projection = copy.deepcopy(projection)
        admission = next(
            item
            for item in altered_projection["operationAdmissions"]
            if item["operationId"] == operation_id
        )
        admission["status"] = "exact"
        admission["context"] = handcrafted
        digest = bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(altered_projection)
        )
        altered_authorization = copy.deepcopy(authorization)
        altered_authorization["observedPreflight"]["sha256"] = digest
        preflight = {
            "schemaVersion": 1,
            "status": "observed-read-only",
            "observedAt": altered_authorization["observedPreflight"]["observedAt"],
            "projection": altered_projection,
            "projectionSha256": digest,
        }
        with self.assertRaisesRegex(
            bootstrap.BootstrapError,
            "may not be skipped or adopted",
        ):
            bootstrap.validate_preflight_evidence(
                preflight, altered_authorization, self.plan
            )

    def test_controller_empty_inventory_is_strictly_zero_blob_and_unpaginated(self):
        resource = next(
            item
            for item in self.plan["resourceInventory"]
            if item["id"] == "controllerLockContainer"
        )
        posture = {
            "id": resource["resourceId"],
            "name": resource["name"],
            "type": "Microsoft.Storage/storageAccounts/blobServices/containers",
            "publicAccess": "None",
        }
        exact = (
            b'<EnumerationResults>'
            b'<Prefix/><Marker/><MaxResults>5000</MaxResults><Delimiter/>'
            b'<Blobs/><NextMarker/></EnumerationResults>'
        )

        def response(body, content_type="application/xml"):
            return bootstrap._RestResponse(
                status=200,
                body=body,
                headers={"content-type": content_type},
            )

        inventory = bootstrap._strict_empty_controller_inventory(
            response(exact),
            plan=self.plan,
            observed_at=stamp(NOW),
            private_container_posture=posture,
            controller_container_decision="apply-exact",
        )
        self.assertEqual(inventory["blobNames"], [])
        self.assertEqual(inventory["nextMarker"], "")
        malformed = [
            b"<EnumerationResults><Blobs><Blob/></Blobs><NextMarker/></EnumerationResults>",
            b"<EnumerationResults><Blobs><BlobPrefix/></Blobs><NextMarker/></EnumerationResults>",
            b"<EnumerationResults><Blobs/><Blobs/><NextMarker/></EnumerationResults>",
            b"<EnumerationResults><Blobs/><NextMarker>page-2</NextMarker></EnumerationResults>",
            b"<EnumerationResults><Unknown/><Blobs/><NextMarker/></EnumerationResults>",
            b"<EnumerationResults><Blobs/>",
        ]
        for body in malformed:
            with self.subTest(body=body), self.assertRaises(bootstrap.BootstrapError):
                bootstrap._strict_empty_controller_inventory(
                    response(body),
                    plan=self.plan,
                    observed_at=stamp(NOW),
                    private_container_posture=posture,
                    controller_container_decision="apply-exact",
                )
        for body, content_type in (
            (exact, "application/json"),
            (b"x" * 1_000_001, "application/xml"),
        ):
            with self.subTest(content_type=content_type), self.assertRaises(
                bootstrap.BootstrapError
            ):
                bootstrap._strict_empty_controller_inventory(
                    response(body, content_type),
                    plan=self.plan,
                    observed_at=stamp(NOW),
                    private_container_posture=posture,
                    controller_container_decision="apply-exact",
                )

    def test_controller_empty_proof_retries_only_recognized_authorization_403(self):
        projection = build_projection(self.plan, self.package)
        with tempfile.TemporaryDirectory() as folder:
            receipt = Path(folder) / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
            authorization = build_authorization(
                self.plan, self.plan_sha, self.package, projection, receipt
            )
            fixture = _TerminalEvidenceFixture(
                self.plan, self.plan_sha, self.package, receipt
            )
        resource = next(
            item
            for item in self.plan["resourceInventory"]
            if item["id"] == "controllerLockContainer"
        )
        controller = fixture.envelope(
            "createPrivateControllerLockContainer",
            {
                "id": resource["resourceId"],
                "name": resource["name"],
                "type": "Microsoft.Storage/storageAccounts/blobServices/containers",
                "publicAccess": "None",
            },
        )
        exact_xml = (
            b"<EnumerationResults><Prefix/><Marker/><MaxResults>5000</MaxResults>"
            b"<Delimiter/><Blobs/><NextMarker/></EnumerationResults>"
        )

        class Session:
            def __init__(self, responses, *, repeat=False):
                self.responses = list(responses)
                self.repeat = repeat
                self.requests = []

            def request(self, method, url, **kwargs):
                self.requests.append((method, url, kwargs))
                if self.repeat:
                    return self.responses[0]
                return self.responses.pop(0)

        def storage_error(code):
            return bootstrap._RestResponse(
                403,
                f"<Error><Code>{code}</Code></Error>".encode("ascii"),
                {"content-type": "application/xml"},
            )

        exact_response = bootstrap._RestResponse(
            200, exact_xml, {"content-type": "application/xml"}
        )

        def transport_for(session, *, jump=False):
            current = [NOW]

            def clock():
                return current[0]

            def sleep(seconds):
                current[0] += dt.timedelta(seconds=601 if jump else seconds)

            transport = bootstrap.AzureCliBootstrapTransport(
                authorization=authorization,
                plan=self.plan,
                package=self.package,
                preflight={"projection": projection},
                clock=clock,
                sleep=sleep,
                session=session,
            )
            transport._validated_source_projections[
                "createPrivateControllerLockContainer"
            ] = controller
            return transport

        session = Session(
            [storage_error("AuthorizationPermissionMismatch"), exact_response]
        )
        transport = transport_for(session)
        admission = transport.admissions["proveControllerLockContainerEmpty"]
        proof = transport._prove_controller_lock_container_empty(
            admission["desiredProbeIds"]
        )[0]
        self.assertEqual(proof["attempts"], 2)
        self.assertEqual(len(session.requests), 2)
        self.assertEqual(
            proof["sourceProjection"]["family"],
            "controller-lock-initial-empty-proof",
        )

        unrecognized = Session([storage_error("AuthenticationFailed")])
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "not recognized RBAC propagation"
        ):
            transport_for(unrecognized)._prove_controller_lock_container_empty(
                admission["desiredProbeIds"]
            )
        self.assertEqual(len(unrecognized.requests), 1)

        never_converges = Session(
            [storage_error("AuthorizationFailure")], repeat=True
        )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "window expired|did not converge"
        ):
            transport_for(
                never_converges, jump=True
            )._prove_controller_lock_container_empty(admission["desiredProbeIds"])
        self.assertEqual(len(never_converges.requests), 1)

    def test_pending_empty_proof_decision_is_controller_only(self):
        pending = {"executionDecision": "adopt-pending-execution-empty-proof"}
        self.assertEqual(
            bootstrap._validate_operation_context(
                "createPrivateControllerLockContainer", pending, {}
            ),
            pending,
        )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "outside the controller container"
        ):
            bootstrap._validate_operation_context(
                "createMailboxResourceGroup", pending, {}
            )

    def test_pending_empty_proof_admission_status_and_decision_are_exactly_paired(self):
        base = build_projection(self.plan, self.package)
        receipt = Path("C:/outside") / (
            f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
        )
        cases = (
            "createMailboxResourceGroup",
            "createPrivateControllerLockContainer",
        )
        for operation_id in cases:
            with self.subTest(operation_id=operation_id):
                projection = copy.deepcopy(base)
                admission = next(
                    item
                    for item in projection["operationAdmissions"]
                    if item["operationId"] == operation_id
                )
                admission["status"] = "adopt-pending-execution-empty-proof"
                authorization = build_authorization(
                    self.plan,
                    self.plan_sha,
                    self.package,
                    projection,
                    receipt,
                )
                preflight = {
                    "schemaVersion": 1,
                    "status": "observed-read-only",
                    "observedAt": authorization["observedPreflight"]["observedAt"],
                    "projection": projection,
                    "projectionSha256": authorization["observedPreflight"]["sha256"],
                }
                with self.assertRaisesRegex(
                    bootstrap.BootstrapError,
                    "pending empty-container status lacks its exact execution decision",
                ):
                    bootstrap.validate_preflight_evidence(
                        preflight, authorization, self.plan
                    )

    def test_adopted_signing_key_expiry_is_nested_fresh_and_readback_exact(self):
        projection = build_projection(self.plan, self.package)
        with tempfile.TemporaryDirectory() as folder:
            authorization = build_authorization(
                self.plan,
                self.plan_sha,
                self.package,
                projection,
                Path(folder) / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}",
            )
        key_uri = (
            "https://kv-mds-sea-9c4e0d0d.vault.azure.net/keys/"
            "paperdesk-release-result-signing/" + "c" * 32
        )
        minimum = bootstrap.parse_time(
            authorization["validity"]["expiresAt"], "authorization expiry"
        ) + dt.timedelta(days=30)
        valid = {
            "executionDecision": "adopt-exact",
            "adopted": {
                "keyUriWithVersion": key_uri,
                "expiresAt": stamp(minimum),
            },
        }
        self.assertEqual(
            bootstrap._validate_operation_context(
                "createSigningKeyVersion", valid, authorization
            ),
            valid,
        )
        missing = copy.deepcopy(valid)
        del missing["adopted"]["expiresAt"]
        too_short = copy.deepcopy(valid)
        too_short["adopted"]["expiresAt"] = stamp(minimum - dt.timedelta(seconds=1))
        for context in (missing, too_short):
            with self.subTest(context=context), self.assertRaises(
                bootstrap.BootstrapError
            ):
                bootstrap._validate_operation_context(
                    "createSigningKeyVersion", context, authorization
                )
        contract = bootstrap._validator_contract(
            "operation:createSigningKeyVersion", self.plan, authorization
        )
        mismatch = {
            "schemaVersion": 1,
            "operationId": "createSigningKeyVersion",
            "family": "signing-key-posture",
            "method": contract["expectedMethod"],
            "url": contract["expectedUrl"],
            "status": contract["expectedStatus"],
            "target": contract["target"],
            "targetResourceId": contract.get("targetResourceId"),
            "responseSha256": "a" * 64,
            "headers": {},
            "projection": {
                "keyUriWithVersion": key_uri,
                "kty": "RSA",
                "keySize": 3072,
                "keyOps": ["sign", "verify"],
                "enabled": True,
                "exportable": False,
                "expiresAt": int(minimum.timestamp()) + 1,
                "releasePolicy": None,
            },
        }
        with self.assertRaisesRegex(bootstrap.BootstrapError, "unsafe"):
            bootstrap._validate_operation_source_projection(
                mismatch,
                operation_id="createSigningKeyVersion",
                plan=self.plan,
                authorization=authorization,
                prior={},
                operation_context=valid,
            )

    def test_preflight_requires_fresh_temporary_role_definition_absence(self):
        projection = build_projection(self.plan, self.package)
        operation_id = "addOwnedUploaderPackageRole"
        definition_url = bootstrap._temporary_role_definition_readback_url(
            operation_id, bootstrap.bind_temporary_role_ids(self.plan, AUTH_ID)
        )
        self.assertIsNotNone(definition_url)
        admission = next(
            item
            for item in projection["operationAdmissions"]
            if item["operationId"] == operation_id
        )
        definition_probe_id = next(
            probe_id
            for probe_id in admission["probeIds"]
            if next(
                probe
                for probe in projection["probes"]
                if probe["id"] == probe_id
            )["url"]
            == definition_url
        )
        admission["probeIds"].remove(definition_probe_id)
        projection["probes"] = [
            probe
            for probe in projection["probes"]
            if probe["id"] != definition_probe_id
        ]
        receipt = Path("C:/outside") / (
            f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
        )
        authorization = build_authorization(
            self.plan,
            self.plan_sha,
            self.package,
            projection,
            receipt,
        )
        preflight = {
            "schemaVersion": 1,
            "status": "observed-read-only",
            "observedAt": authorization["observedPreflight"]["observedAt"],
            "projection": projection,
            "projectionSha256": authorization["observedPreflight"]["sha256"],
        }
        with self.assertRaisesRegex(
            bootstrap.BootstrapError,
            "temporary role definition absence",
        ):
            bootstrap.validate_preflight_evidence(
                preflight, authorization, self.plan
            )

    def fixture(self, folder):
        projection = build_projection(self.plan, self.package)
        receipt = Path(folder) / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
        auth = build_authorization(self.plan, self.plan_sha, self.package, projection, receipt)
        auth_path = Path(folder) / "authorization.json"
        preflight_path = Path(folder) / "preflight.json"
        canonical_file(auth_path, auth)
        preflight = {
            "schemaVersion": 1,
            "status": "observed-read-only",
            "observedAt": auth["observedPreflight"]["observedAt"],
            "projection": projection,
            "projectionSha256": auth["observedPreflight"]["sha256"],
        }
        canonical_file(preflight_path, preflight)
        validated = bootstrap.validate_authorization(
            auth_path,
            plan=self.plan,
            plan_sha256=self.plan_sha,
            package=self.package,
            confirmation_phrase=PHRASE,
            now=NOW,
        )
        validated_preflight, _ = bootstrap.validate_preflight_document(
            preflight_path, validated.document, self.plan
        )
        return auth, validated, validated_preflight, projection, receipt

    def test_deletion_lock_residual_acceptance_exact_reviewed_wording(self):
        self.assertEqual(bootstrap.DELETION_LOCK_RESIDUAL_ACCEPTANCE,
                         EXPECTED_DELETION_LOCK_RESIDUAL_ACCEPTANCE)

    def test_bridge_config_hard_death_acceptance_exact_reviewed_wording(self):
        self.assertEqual(
            bootstrap.BRIDGE_CONFIG_HARD_DEATH_RESIDUAL_ACCEPTANCE,
            EXPECTED_BRIDGE_CONFIG_HARD_DEATH_RESIDUAL_ACCEPTANCE,
        )

    def test_previous_two_lock_confirmation_cannot_authorize_three_lock_plan(self):
        with tempfile.TemporaryDirectory() as folder:
            projection = build_projection(self.plan, self.package)
            receipt = Path(folder) / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
            authorization = build_authorization(
                self.plan, self.plan_sha, self.package, projection, receipt
            )
            previous_phrase = PHRASE.replace(
                "only the three reviewed", "only the two reviewed"
            ).replace("all three exact locks restored", "both exact locks restored")
            authorization["confirmation"]["phraseSha256"] = bootstrap.sha256_bytes(
                previous_phrase.encode("utf-8")
            )
            path = Path(folder) / "previous-two-lock-confirmation.json"
            canonical_file(path, authorization)
            with self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "does not explicitly authorize exact deletion-lock suspension",
            ):
                bootstrap.validate_authorization(
                    path, plan=self.plan, plan_sha256=self.plan_sha,
                    package=self.package, confirmation_phrase=previous_phrase, now=NOW,
                )

    def test_authorization_requires_explicit_storage_acl_residual_acceptance(self):
        self.assertEqual(
            bootstrap.STORAGE_ACL_AND_RECOVERY_RESIDUAL_ACCEPTANCE,
            EXPECTED_STORAGE_ACL_AND_RECOVERY_RESIDUAL_ACCEPTANCE,
        )
        with tempfile.TemporaryDirectory() as folder:
            projection = build_projection(self.plan, self.package)
            receipt = (
                Path(folder)
                / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
            )
            authorization = build_authorization(
                self.plan, self.plan_sha, self.package, projection, receipt
            )
            incomplete_phrase = "Authorize the exact one-shot PaperDesk V2 bootstrap plan."
            authorization["confirmation"]["phraseSha256"] = bootstrap.sha256_bytes(
                incomplete_phrase.encode("utf-8")
            )
            path = Path(folder) / "authorization-without-residual-acceptance.json"
            canonical_file(path, authorization)
            with self.assertRaisesRegex(
                bootstrap.BootstrapError, "does not explicitly accept"
            ):
                bootstrap.validate_authorization(
                    path,
                    plan=self.plan,
                    plan_sha256=self.plan_sha,
                    package=self.package,
                    confirmation_phrase=incomplete_phrase,
                    now=NOW,
                )

    def test_residual_acceptance_does_not_bypass_whole_phrase_hash(self):
        with tempfile.TemporaryDirectory() as folder:
            projection = build_projection(self.plan, self.package)
            receipt = (
                Path(folder)
                / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
            )
            authorization = build_authorization(
                self.plan, self.plan_sha, self.package, projection, receipt
            )
            path = Path(folder) / "authorization-exact-phrase-hash.json"
            canonical_file(path, authorization)
            with self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "confirmation phrase does not match",
            ):
                bootstrap.validate_authorization(
                    path,
                    plan=self.plan,
                    plan_sha256=self.plan_sha,
                    package=self.package,
                    confirmation_phrase=PHRASE + " ",
                    now=NOW,
                )

    def terminal_fixture(self, folder):
        return build_valid_terminal_source_evidence_fixture(
            Path(folder)
            / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}",
            plan=self.plan,
            plan_sha=self.plan_sha,
            package=self.package,
        )

    @staticmethod
    def source(_authorization):
        return {
            "repository": bootstrap.REPOSITORY,
            "headSha": MERGE,
            "treeSha": TREE,
            "soleParentSha": PARENT,
            "originMainSha": MERGE,
        }

    def executor(self, validated, preflight, transport):
        if isinstance(transport, FakeTransport):
            terminal_fixture = build_complete_terminal_receipt_input_fixture(
                Path(validated.document["singleUse"]["receiptDirectory"])
            )
            self.assertEqual(terminal_fixture["authorization"], validated.document)
            self.assertEqual(
                terminal_fixture["preflightProjection"], preflight["projection"]
            )
            transport.bind_terminal_fixture(terminal_fixture)

        def clock():
            if (
                isinstance(transport, FakeTransport)
                and transport.calls
                and transport.calls[-1][0] == "production-boundary"
            ):
                return NOW + dt.timedelta(minutes=7)
            return NOW

        return bootstrap.BootstrapExecutor(
            plan=self.plan,
            plan_sha256=self.plan_sha,
            package=self.package,
            authorization=validated,
            preflight=preflight,
            transport=transport,
            now=clock,
            source_validator=self.source,
        )

    def test_default_describe_never_constructs_transport(self):
        constructed = []
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = bootstrap.main([], transport_factory=lambda: constructed.append(True))
        self.assertEqual(result, 0)
        self.assertEqual(constructed, [])
        self.assertIn("read-only-no-Azure-transport-constructed", stdout.getvalue())

    def test_package_artifact_retains_the_exact_authorized_bytes(self):
        descriptor, body = bootstrap.build_package_artifact()
        self.assertEqual(descriptor, bootstrap.build_package_descriptor())
        self.assertEqual(bootstrap.sha256_bytes(body), descriptor["sha256"])
        self.assertEqual(len(body), descriptor["size"])

    def test_ledger_artifact_writer_is_create_only_canonical_and_confined(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ledger = bootstrap.UseLedger(
                directory=root / "receipt",
                authorization_id=AUTH_ID,
                authorization_sha256="a" * 64,
                source_sha=MERGE,
                plan_sha256=self.plan_sha,
                claimed_at=stamp(NOW),
            )
            ledger.claim()
            body = bootstrap.canonical_json_bytes(
                {"schemaVersion": 1, "status": "source-only-test"}
            )
            target = ledger.write_create_only_artifact(
                "evidence/private-release-bootstrap-receipt-bundle.json", body
            )
            self.assertEqual(target.read_bytes(), body)
            self.assertTrue(target.is_relative_to(ledger.directory))
            resumed = ledger.write_create_only_artifact(
                "evidence/private-release-bootstrap-receipt-bundle.json", body
            )
            self.assertEqual(resumed, target)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "conflicts"):
                ledger.write_create_only_artifact(
                    "evidence/private-release-bootstrap-receipt-bundle.json",
                    bootstrap.canonical_json_bytes(
                        {"schemaVersion": 1, "status": "conflicting-test"}
                    ),
                )
            for unsafe in (
                "../escape.json",
                "/absolute.json",
                "evidence\\windows.json",
                "execution-terminal.json",
            ):
                with self.subTest(unsafe=unsafe):
                    with self.assertRaises(bootstrap.BootstrapError):
                        ledger.write_create_only_artifact(unsafe, body)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "canonical"):
                ledger.write_create_only_artifact(
                    "evidence/noncanonical.json", b'{"status": "spaced"}\n'
                )

    def test_finalization_artifacts_resume_prefix_and_write_terminal_last(self):
        paths = [f"evidence/source-{index}.json" for index in range(1, 6)]
        files = {
            path: bootstrap.canonical_json_bytes(
                {"schemaVersion": 1, "sequence": index}
            )
            for index, path in enumerate(paths, 1)
        }
        terminal_path = "evidence/private-release-bootstrap-receipt-bundle.json"
        terminal_body = bootstrap.canonical_json_bytes(
            {"schemaVersion": 1, "status": "succeeded-terminal"}
        )
        for completed_prefix in range(6):
            with self.subTest(completed_prefix=completed_prefix), tempfile.TemporaryDirectory() as folder:
                ledger = bootstrap.UseLedger(
                    directory=Path(folder) / "receipt",
                    authorization_id=AUTH_ID,
                    authorization_sha256="a" * 64,
                    source_sha=MERGE,
                    plan_sha256=self.plan_sha,
                    claimed_at=stamp(NOW),
                )
                ledger.claim()
                original = ledger.write_create_only_artifact
                evidence_calls = 0

                def crash_after_prefix(path, body):
                    nonlocal evidence_calls
                    if evidence_calls == completed_prefix:
                        raise RuntimeError("injected local crash")
                    target = original(path, body)
                    evidence_calls += 1
                    return target

                ledger.write_create_only_artifact = crash_after_prefix
                with self.assertRaisesRegex(RuntimeError, "injected local crash"):
                    ledger.persist_finalization_artifacts(
                        expected_s2_paths=paths,
                        s2_evidence_files=files,
                        terminal_bundle_path=terminal_path,
                        terminal_bundle_body=terminal_body,
                    )
                self.assertFalse((ledger.directory / terminal_path).exists())
                self.assertEqual(
                    sum((ledger.directory / path).is_file() for path in paths),
                    completed_prefix,
                )
                ledger.write_create_only_artifact = original
                result = ledger.persist_finalization_artifacts(
                    expected_s2_paths=paths,
                    s2_evidence_files=files,
                    terminal_bundle_path=terminal_path,
                    terminal_bundle_body=terminal_body,
                )
                self.assertEqual(
                    result[terminal_path]["phase"], "terminal-bundle-last"
                )
                self.assertEqual(
                    (ledger.directory / terminal_path).read_bytes(), terminal_body
                )

    def test_finalization_snapshot_is_bound_and_identical_resume_only(self):
        with tempfile.TemporaryDirectory() as folder:
            ledger = bootstrap.UseLedger(
                directory=Path(folder) / "receipt",
                authorization_id=AUTH_ID,
                authorization_sha256="a" * 64,
                source_sha=MERGE,
                plan_sha256=self.plan_sha,
                claimed_at=stamp(NOW),
            )
            ledger.claim()
            s2_files = {
                f"evidence/source-{index}.json": bootstrap.canonical_json_bytes(
                    {"schemaVersion": 1, "sequence": index}
                )
                for index in range(1, 6)
            }
            snapshot = bootstrap.UseLedger.build_finalization_snapshot(
                authorization_id=AUTH_ID,
                authorization_sha256="a" * 64,
                source_sha=MERGE,
                plan_sha256=self.plan_sha,
                started_at=stamp(NOW),
                completed_at=stamp(NOW + dt.timedelta(minutes=7)),
                s2_evidence_files=s2_files,
                terminal_bundle_path=(
                    "evidence/private-release-bootstrap-receipt-bundle.json"
                ),
                terminal_bundle_body=bootstrap.canonical_json_bytes(
                    {"schemaVersion": 1, "status": "succeeded-terminal"}
                ),
            )
            first = ledger.persist_finalization_snapshot(snapshot)
            second = ledger.persist_finalization_snapshot(copy.deepcopy(snapshot))
            self.assertEqual(first, second)
            self.assertEqual(ledger.load_finalization_snapshot(), snapshot)
            reopened = bootstrap.UseLedger.open_consumed(
                directory=ledger.directory,
                authorization_id=AUTH_ID,
                authorization_sha256="a" * 64,
                source_sha=MERGE,
                plan_sha256=self.plan_sha,
            )
            self.assertEqual(reopened.load_finalization_snapshot(), snapshot)
            conflicting = copy.deepcopy(snapshot)
            conflicting["completedAt"] = stamp(NOW + dt.timedelta(minutes=8))
            with self.assertRaisesRegex(bootstrap.BootstrapError, "conflicts"):
                ledger.persist_finalization_snapshot(conflicting)

    def test_apply_without_inputs_fails_before_transport(self):
        constructed = []
        with contextlib.redirect_stderr(io.StringIO()):
            result = bootstrap.main(["apply"], transport_factory=lambda: constructed.append(True))
        self.assertEqual(result, 1)
        self.assertEqual(constructed, [])

    def test_resume_finalization_cli_never_constructs_transport(self):
        with tempfile.TemporaryDirectory() as folder:
            _auth, _validated, _preflight, _projection, _receipt = self.fixture(
                folder
            )
            constructed = []
            expected = {
                "status": "complete-local-finalization-only",
                "azureMutationCount": 0,
            }
            with mock.patch.object(
                bootstrap,
                "resume_local_finalization_from_snapshot",
                return_value=expected,
            ) as resume, contextlib.redirect_stdout(io.StringIO()):
                status = bootstrap.main(
                    [
                        "resume-finalization",
                        "--authorization",
                        str(Path(folder) / "authorization.json"),
                        "--preflight",
                        str(Path(folder) / "preflight.json"),
                    ],
                    transport_factory=lambda: constructed.append(True),
                )
            self.assertEqual(status, 0)
            self.assertEqual(constructed, [])
            resume.assert_called_once()

    def test_exact_reviewer_ids_are_required(self):
        with tempfile.TemporaryDirectory() as folder:
            auth, _, _, projection, receipt = self.fixture(folder)
            auth["source"]["reviewedHead"]["reviews"][0]["userId"] = 322025901
            path = Path(folder) / "wrong-reviewer.json"
            canonical_file(path, auth)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "review"):
                bootstrap.validate_authorization(path, plan=self.plan, plan_sha256=self.plan_sha, package=self.package, confirmation_phrase=PHRASE, now=NOW)

    def test_reviewed_head_cannot_equal_merged_commit(self):
        with tempfile.TemporaryDirectory() as folder:
            auth, _, _, _, _ = self.fixture(folder)
            auth["source"]["mergedMain"]["commitSha"] = HEAD
            auth["source"]["mergedMain"]["verificationApiUrl"] = f"https://api.github.com/repos/{bootstrap.REPOSITORY}/commits/{HEAD}"
            path = Path(folder) / "direct-push.json"
            canonical_file(path, auth)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "merged-main"):
                bootstrap.validate_authorization(path, plan=self.plan, plan_sha256=self.plan_sha, package=self.package, confirmation_phrase=PHRASE, now=NOW)

    def test_pure_authorization_evidence_rejects_forged_trust_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            auth, _validated, _preflight, _projection, _receipt = self.fixture(folder)
        variants = []
        unsigned = copy.deepcopy(auth)
        unsigned["source"]["reviewedHead"]["signatureVerified"] = False
        variants.append(unsigned)
        no_reviews = copy.deepcopy(auth)
        no_reviews["source"]["reviewedHead"]["requiredApprovals"] = 0
        no_reviews["source"]["reviewedHead"]["reviews"] = []
        variants.append(no_reviews)
        failed_check = copy.deepcopy(auth)
        failed_check["source"]["reviewedHead"]["requiredCheck"][
            "conclusion"
        ] = "failure"
        variants.append(failed_check)
        unverified_merge = copy.deepcopy(auth)
        unverified_merge["source"]["mergedMain"][
            "githubVerificationVerified"
        ] = False
        variants.append(unverified_merge)
        for forged in variants:
            with self.subTest(forged=forged):
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_authorization_evidence(
                        forged,
                        plan=self.plan,
                        plan_sha256=self.plan_sha,
                        package=self.package,
                    )

    def test_merge_must_bind_same_pull_request(self):
        with tempfile.TemporaryDirectory() as folder:
            auth, _, _, _, _ = self.fixture(folder)
            auth["source"]["mergedMain"]["mergedPullRequestNumber"] = 20
            auth["source"]["mergedMain"]["mergedPullRequestUrl"] = f"https://github.com/{bootstrap.REPOSITORY}/pull/20"
            path = Path(folder) / "wrong-pr.json"
            canonical_file(path, auth)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "merged-main"):
                bootstrap.validate_authorization(path, plan=self.plan, plan_sha256=self.plan_sha, package=self.package, confirmation_phrase=PHRASE, now=NOW)

    def test_stale_review_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            auth, _, _, _, _ = self.fixture(folder)
            auth["source"]["reviewedHead"]["reviews"][0]["submittedAt"] = auth["source"]["reviewedHead"]["pushedAt"]
            path = Path(folder) / "stale-review.json"
            canonical_file(path, auth)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "predates"):
                bootstrap.validate_authorization(path, plan=self.plan, plan_sha256=self.plan_sha, package=self.package, confirmation_phrase=PHRASE, now=NOW)

    def test_local_reviewed_head_requires_exact_ssh_signer_and_key(self):
        with tempfile.TemporaryDirectory() as folder:
            auth, _, _, _, _ = self.fixture(folder)

        signature_args = (
            "-c",
            "gpg.format=ssh",
            "-c",
            f"gpg.ssh.allowedSignersFile={bootstrap.ALLOWED_SIGNERS_PATH}",
        )
        outputs = {
            ("status", "--porcelain=v1"): "",
            ("symbolic-ref", "--short", "HEAD"): "main\n",
            ("config", "--get", "remote.origin.url"): "https://github.com/Sethvirak/paperdesk-release-verifier.git\n",
            ("rev-parse", "HEAD"): MERGE + "\n",
            ("rev-parse", "HEAD^{tree}"): TREE + "\n",
            ("rev-parse", "refs/remotes/origin/main"): MERGE + "\n",
            ("rev-list", "--parents", "-n", "1", "HEAD"): f"{MERGE} {PARENT}\n",
            ("cat-file", "-e", f"{HEAD}^{{commit}}"): "",
            (*signature_args, "verify-commit", HEAD): "",
            (*signature_args, "log", "-1", "--format=%G?%x00%GS%x00%GK", HEAD): (
                f"G\x00{bootstrap.SIGNING_PRINCIPAL}\x00{bootstrap.SIGNING_FINGERPRINT}\n"
            ),
        }

        def runner(command, **_kwargs):
            key = tuple(command[1:])
            return __import__("subprocess").CompletedProcess(command, 0, outputs[key], "")

        source = bootstrap.validate_local_source(auth, git_runner=runner)
        self.assertEqual(source["reviewedHeadSigningKeyFingerprint"], bootstrap.SIGNING_FINGERPRINT)

        wrong = dict(outputs)
        wrong[(*signature_args, "log", "-1", "--format=%G?%x00%GS%x00%GK", HEAD)] = (
            "G\x00wrong-principal\x00SHA256:wrong\n"
        )

        def wrong_runner(command, **_kwargs):
            key = tuple(command[1:])
            return __import__("subprocess").CompletedProcess(command, 0, wrong[key], "")

        with self.assertRaisesRegex(bootstrap.BootstrapError, "exact allowed principal"):
            bootstrap.validate_local_source(auth, git_runner=wrong_runner)

    def test_fresh_preflight_drift_fails_before_claim_or_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            _, validated, preflight, projection, receipt = self.fixture(folder)
            transport = FakeTransport(projection, drift=True)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "preflight drifted"):
                self.executor(validated, preflight, transport).run()
            self.assertFalse(receipt.exists())
            self.assertFalse(any(kind == "apply" for kind, _ in transport.calls))

    def test_partial_operation_drift_fails_before_claim_or_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            _, validated, preflight, projection, receipt = self.fixture(folder)
            transport = FakeTransport(projection, reject_operation="createPublisherApplication")
            with self.assertRaisesRegex(bootstrap.BootstrapError, "partial or drifted"):
                self.executor(validated, preflight, transport).run()
            self.assertFalse(receipt.exists())
            self.assertFalse(any(kind == "apply" for kind, _ in transport.calls))

    def test_exact_plan_executes_claim_first_and_fic_last(self):
        with tempfile.TemporaryDirectory() as folder:
            _, validated, preflight, projection, receipt = self.fixture(folder)
            transport = FakeTransport(projection)
            result = self.executor(validated, preflight, transport).run()
            applied = [value for kind, value in transport.calls if kind == "apply"]
            self.assertEqual(applied[0], "claimAzureSingleUseAuthorization")
            self.assertEqual(applied[-1], "createSolePublisherFicToSignedBootstrapSource")
            self.assertEqual(result.status, "complete")
            self.assertEqual(result.temporary_cleanup, [])
            self.assertNotIn(
                "configureBridgeExactVersionedPackageAndCriticalSettings",
                [
                    value
                    for kind, value in transport.calls
                    if kind == "compensate"
                ],
            )
            self.assertEqual(
                result.terminal_bundle_path,
                self.plan["evidenceOutputs"]["terminalBundlePath"],
            )
            self.assertRegex(result.terminal_bundle_sha256, r"^[0-9a-f]{64}$")
            self.assertTrue((receipt / "single-use-state.json").is_file())
            self.assertTrue((receipt / "execution-terminal.json").is_file())
            for path in (
                self.plan["evidenceOutputs"]["provisioningEvidencePath"],
                self.plan["evidenceOutputs"]["bridgeRuntimeReceiptPath"],
                self.plan["evidenceOutputs"][
                    "temporaryAccessCleanupReceiptPath"
                ],
                self.plan["evidenceOutputs"]["activationFenceReceiptPath"],
                self.plan["evidenceOutputs"]["bridgeCanaryReceiptPath"],
                self.plan["evidenceOutputs"]["terminalBundlePath"],
            ):
                self.assertTrue((receipt / path).is_file(), path)

    def test_executor_crash_prefix_resumes_local_only_without_cloud_replay(self):
        with tempfile.TemporaryDirectory() as folder:
            _, validated, preflight, projection, receipt = self.fixture(folder)
            transport = FakeTransport(projection)
            executor = self.executor(validated, preflight, transport)
            crash_path = self.plan["evidenceOutputs"]["bridgeRuntimeReceiptPath"]
            original = bootstrap.UseLedger.write_create_only_artifact
            crashed = False

            def crash_after_exact_prefix(ledger, path, body):
                nonlocal crashed
                target = original(ledger, path, body)
                if path == crash_path and not crashed:
                    crashed = True
                    raise OSError("injected evidence-prefix crash")
                return target

            with mock.patch.object(
                bootstrap.UseLedger,
                "write_create_only_artifact",
                new=crash_after_exact_prefix,
            ):
                with self.assertRaisesRegex(OSError, "evidence-prefix crash"):
                    executor.run()
            self.assertTrue(crashed)
            terminal_path = self.plan["evidenceOutputs"]["terminalBundlePath"]
            self.assertFalse((receipt / terminal_path).exists())
            failed_summary, _ = bootstrap.load_json(
                receipt / "execution-terminal.json", require_canonical=True
            )
            self.assertEqual(failed_summary["status"], "failed")
            apply_calls = [
                value for kind, value in transport.calls if kind == "apply"
            ]
            self.assertNotIn(
                "configureBridgeExactVersionedPackageAndCriticalSettings",
                [
                    value
                    for kind, value in transport.calls
                    if kind == "compensate"
                ],
            )

            resumed = bootstrap.resume_local_finalization_from_snapshot(
                plan=self.plan,
                plan_sha256=self.plan_sha,
                package=self.package,
                authorization=validated.document,
                preflight=preflight,
            )
            self.assertEqual(
                resumed["status"], "complete-local-finalization-only"
            )
            self.assertEqual(resumed["azureMutationCount"], 0)
            self.assertEqual(resumed["terminalBundlePath"], terminal_path)
            self.assertTrue((receipt / terminal_path).is_file())
            self.assertEqual(
                [value for kind, value in transport.calls if kind == "apply"],
                apply_calls,
            )

    def test_executor_crash_before_output_snapshot_rebuilds_from_retained_source(self):
        with tempfile.TemporaryDirectory() as folder:
            _, validated, preflight, projection, receipt = self.fixture(folder)
            transport = FakeTransport(projection)
            executor = self.executor(validated, preflight, transport)
            with mock.patch.object(
                bootstrap.UseLedger,
                "persist_finalization_snapshot",
                side_effect=OSError("injected pre-output-snapshot crash"),
            ):
                with self.assertRaisesRegex(OSError, "pre-output-snapshot crash"):
                    executor.run()
            self.assertTrue(
                (receipt / "local-terminal-source-input.json").is_file()
            )
            self.assertFalse(
                (receipt / "local-finalization-input.json").exists()
            )
            terminal_path = self.plan["evidenceOutputs"]["terminalBundlePath"]
            self.assertFalse((receipt / terminal_path).exists())
            apply_calls = [
                value for kind, value in transport.calls if kind == "apply"
            ]
            self.assertNotIn(
                "configureBridgeExactVersionedPackageAndCriticalSettings",
                [
                    value
                    for kind, value in transport.calls
                    if kind == "compensate"
                ],
            )
            resumed = bootstrap.resume_local_finalization_from_snapshot(
                plan=self.plan,
                plan_sha256=self.plan_sha,
                package=self.package,
                authorization=validated.document,
                preflight=preflight,
            )
            self.assertEqual(resumed["azureMutationCount"], 0)
            self.assertTrue((receipt / terminal_path).is_file())
            self.assertEqual(
                [value for kind, value in transport.calls if kind == "apply"],
                apply_calls,
            )

    def test_failure_before_terminal_source_snapshot_rolls_back_bridge_settings(self):
        with tempfile.TemporaryDirectory() as folder:
            _, validated, preflight, projection, receipt = self.fixture(folder)
            transport = FakeTransport(projection)
            executor = self.executor(validated, preflight, transport)
            with mock.patch.object(
                bootstrap.UseLedger,
                "persist_terminal_source_input",
                side_effect=OSError("injected terminal-source fsync failure"),
            ):
                with self.assertRaisesRegex(
                    OSError, "terminal-source fsync failure"
                ):
                    executor.run()
            self.assertFalse(
                (receipt / "local-terminal-source-input.json").exists()
            )
            self.assertEqual(
                [
                    value
                    for kind, value in transport.calls
                    if kind == "compensate"
                ],
                ["configureBridgeExactVersionedPackageAndCriticalSettings"],
            )

    def test_local_finalization_resume_rejects_conflicting_prefix_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            _, validated, preflight, _projection, receipt = self.fixture(folder)
            complete = build_complete_terminal_receipt_input_fixture(
                Path(validated.document["singleUse"]["receiptDirectory"])
            )
            ledger = bootstrap.UseLedger(
                directory=validated.receipt_directory,
                authorization_id=validated.document["authorizationId"],
                authorization_sha256=validated.sha256,
                source_sha=MERGE,
                plan_sha256=self.plan_sha,
                claimed_at=complete["startedAt"],
            )
            ledger.claim()
            terminal_path, terminal_body = next(
                iter(complete["completeReceipt"]["s2TerminalBundle"].items())
            )
            snapshot = bootstrap.UseLedger.build_finalization_snapshot(
                authorization_id=validated.document["authorizationId"],
                authorization_sha256=validated.sha256,
                source_sha=MERGE,
                plan_sha256=self.plan_sha,
                started_at=complete["startedAt"],
                completed_at=complete["completedAt"],
                s2_evidence_files=complete["s2Documents"],
                terminal_bundle_path=terminal_path,
                terminal_bundle_body=terminal_body,
            )
            ledger.persist_finalization_snapshot(snapshot)
            first_path = self.plan["evidenceOutputs"]["provisioningEvidencePath"]
            ledger.write_create_only_artifact(
                first_path,
                bootstrap.canonical_json_bytes(
                    {"schemaVersion": 1, "status": "conflicting-local-file"}
                ),
            )
            with self.assertRaisesRegex(bootstrap.BootstrapError, "conflicts"):
                bootstrap.resume_local_finalization_from_snapshot(
                    plan=self.plan,
                    plan_sha256=self.plan_sha,
                    package=self.package,
                    authorization=validated.document,
                    preflight=preflight,
                )
            self.assertFalse((receipt / terminal_path).exists())

    def test_local_finalization_resume_rejects_canonical_rehashed_source_tamper(self):
        with tempfile.TemporaryDirectory() as folder:
            _, validated, preflight, _projection, _receipt = self.fixture(folder)
            complete = build_complete_terminal_receipt_input_fixture(
                Path(validated.document["singleUse"]["receiptDirectory"])
            )
            terminal_path, terminal_body = next(
                iter(complete["completeReceipt"]["s2TerminalBundle"].items())
            )
            terminal_document = json.loads(terminal_body.decode("utf-8"))
            terminal_document["executionReceipt"]["sourceEvidence"][
                "productionBoundary"
            ]["journaledProductionWriteCount"] = 1
            tampered_terminal_body = bootstrap.canonical_json_bytes(
                terminal_document
            )
            ledger = bootstrap.UseLedger(
                directory=validated.receipt_directory,
                authorization_id=validated.document["authorizationId"],
                authorization_sha256=validated.sha256,
                source_sha=MERGE,
                plan_sha256=self.plan_sha,
                claimed_at=complete["startedAt"],
            )
            ledger.claim()
            snapshot = bootstrap.UseLedger.build_finalization_snapshot(
                authorization_id=validated.document["authorizationId"],
                authorization_sha256=validated.sha256,
                source_sha=MERGE,
                plan_sha256=self.plan_sha,
                started_at=complete["startedAt"],
                completed_at=complete["completedAt"],
                s2_evidence_files=complete["s2Documents"],
                terminal_bundle_path=terminal_path,
                terminal_bundle_body=tampered_terminal_body,
            )
            ledger.persist_finalization_snapshot(snapshot)
            with self.assertRaisesRegex(
                bootstrap.BootstrapError, "full terminal validation"
            ):
                bootstrap.resume_local_finalization_from_snapshot(
                    plan=self.plan,
                    plan_sha256=self.plan_sha,
                    package=self.package,
                    authorization=validated.document,
                    preflight=preflight,
                )
            self.assertFalse((ledger.directory / terminal_path).exists())

    def test_real_transport_methods_are_concrete_not_protocol_stubs(self):
        for name, required in (
            ("apply_operation", "desiredProbeIds"),
            ("compensate_temporary", "temporary compensation"),
            ("verify_postcondition", "probeSetSha256"),
        ):
            method = bootstrap.AzureCliBootstrapTransport.__dict__.get(name)
            self.assertIsNotNone(method, name)
            self.assertIn(required, inspect.getsource(method))

    def test_storage_acl_post_read_failure_records_owned_cleanup_obligation(self):
        with tempfile.TemporaryDirectory() as folder:
            projection = build_projection(self.plan, self.package)
            receipt = (
                Path(folder)
                / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
            )
            authorization = build_authorization(
                self.plan,
                self.plan_sha,
                self.package,
                projection,
                receipt,
            )
            operation = next(
                item
                for item in self.plan["mutations"]
                if item["id"] == "addOwnedUploaderIpv4Rule"
            )
            context = next(
                item["context"]
                for item in projection["operationAdmissions"]
                if item["operationId"] == operation["id"]
            )
            before = copy.deepcopy(context["preNetworkAcls"])
            after = copy.deepcopy(before)
            after["ipRules"] = [
                {"value": "203.0.113.10", "action": "Allow"}
            ]

            class Session:
                def __init__(self):
                    self.requests = []
                    self.get_count = 0

                def request(
                    self, method, url, *, body=None, headers=None, deadline=None
                ):
                    self.requests.append(
                        (method, url, body, dict(headers or {}))
                    )
                    if method == "PATCH":
                        return bootstrap._RestResponse(
                            200, bootstrap.canonical_json_bytes({}), {}
                        )
                    self.get_count += 1
                    if self.get_count == 1:
                        return bootstrap._RestResponse(
                            200,
                            bootstrap.canonical_json_bytes(
                                {"properties": {"networkAcls": before}}
                            ),
                            {},
                        )
                    return bootstrap._RestResponse(
                        503, bootstrap.canonical_json_bytes({}), {}
                    )

            ledger = bootstrap.UseLedger(
                directory=receipt,
                authorization_id=AUTH_ID,
                authorization_sha256=bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes(authorization)
                ),
                source_sha=MERGE,
                plan_sha256=self.plan_sha,
                claimed_at=stamp(NOW),
            )
            ledger.claim()
            session = Session()
            transport = bootstrap.AzureCliBootstrapTransport(
                authorization=authorization,
                plan=self.plan,
                package=self.package,
                preflight={"projection": projection},
                clock=lambda: NOW,
                session=session,
            )
            transport.bind_journal(ledger)
            transport._active_operation_id = operation["id"]
            with self.assertRaisesRegex(
                bootstrap.OwnedTemporaryMutationError,
                "exact post-readback failed",
            ) as raised:
                transport._mutate(operation, {})

            patch_request = next(
                item for item in session.requests if item[0] == "PATCH"
            )
            self.assertEqual(
                json.loads(patch_request[2]),
                {
                    "properties": {
                        "networkAcls": {"ipRules": after["ipRules"]}
                    }
                },
            )
            self.assertEqual(
                patch_request[3], {"Content-Type": "application/json"}
            )
            self.assertNotIn("If-Match", patch_request[3])
            proof = raised.exception.proof
            self.assertTrue(proof["owned"])
            self.assertEqual(proof["cleanupKey"], "uploader-ipv4-rule")
            self.assertEqual(
                proof["details"]["addedNetworkAclsSha256"],
                bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes(after)
                ),
            )
            journal = ledger.read_cloud_mutations()
            self.assertEqual([item["phase"] for item in journal], ["intent", "result"])
            self.assertEqual(ledger.unresolved_intents(), [])
            self.assertEqual(journal[0]["operationId"], operation["id"])
            self.assertEqual(
                journal[0]["requestBodySha256"],
                bootstrap.sha256_bytes(patch_request[2]),
            )

    def test_storage_acl_cleanup_refuses_digest_drift_without_patch(self):
        projection = build_projection(self.plan, self.package)
        receipt = Path("C:/outside") / (
            f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
        )
        authorization = build_authorization(
            self.plan,
            self.plan_sha,
            self.package,
            projection,
            receipt,
        )
        operation = next(
            item
            for item in self.plan["mutations"]
            if item["id"] == "removeOwnedUploaderIpv4Rule"
        )
        context = next(
            item["context"]
            for item in projection["operationAdmissions"]
            if item["operationId"] == operation["id"]
        )
        added = copy.deepcopy(context["restoreNetworkAcls"])
        added["ipRules"] = [
            {"value": "203.0.113.10", "action": "Allow"}
        ]
        drifted = copy.deepcopy(added)
        drifted["ipRules"].append(
            {"value": "198.51.100.40", "action": "Allow"}
        )

        class Session:
            def __init__(self):
                self.requests = []

            def request(self, method, url, *, body=None, headers=None):
                self.requests.append((method, url, body, dict(headers or {})))
                return bootstrap._RestResponse(
                    200,
                    bootstrap.canonical_json_bytes(
                        {"properties": {"networkAcls": drifted}}
                    ),
                    {},
                )

        session = Session()
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=authorization,
            plan=self.plan,
            package=self.package,
            preflight={"projection": projection},
            clock=lambda: NOW,
            session=session,
        )
        state = {
            "proofs": {
                "addOwnedUploaderIpv4Rule": {
                    "details": {
                        "cleanupKey": "uploader-ipv4-rule",
                        "addedNetworkAclsSha256": bootstrap.sha256_bytes(
                            bootstrap.canonical_json_bytes(added)
                        ),
                    }
                }
            }
        }
        with self.assertRaisesRegex(
            bootstrap.BootstrapError,
            "concurrent drift; manual cleanup is required",
        ):
            transport._mutate(operation, state)
        self.assertEqual([item[0] for item in session.requests], ["GET"])

    def test_storage_acl_result_journal_failure_leaves_bound_unresolved_intent(self):
        with tempfile.TemporaryDirectory() as folder:
            projection = build_projection(self.plan, self.package)
            receipt = (
                Path(folder)
                / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
            )
            authorization = build_authorization(
                self.plan,
                self.plan_sha,
                self.package,
                projection,
                receipt,
            )
            operation = next(
                item
                for item in self.plan["mutations"]
                if item["id"] == "addOwnedUploaderIpv4Rule"
            )
            context = next(
                item["context"]
                for item in projection["operationAdmissions"]
                if item["operationId"] == operation["id"]
            )
            before = copy.deepcopy(context["preNetworkAcls"])

            class Session:
                def __init__(self):
                    self.requests = []

                def request(
                    self, method, url, *, body=None, headers=None, deadline=None
                ):
                    self.requests.append((method, url, body, dict(headers or {})))
                    if method == "GET":
                        return bootstrap._RestResponse(
                            200,
                            bootstrap.canonical_json_bytes(
                                {"properties": {"networkAcls": before}}
                            ),
                            {},
                        )
                    return bootstrap._RestResponse(
                        200, bootstrap.canonical_json_bytes({}), {}
                    )

            ledger = bootstrap.UseLedger(
                directory=receipt,
                authorization_id=AUTH_ID,
                authorization_sha256=bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes(authorization)
                ),
                source_sha=MERGE,
                plan_sha256=self.plan_sha,
                claimed_at=stamp(NOW),
            )
            ledger.claim()
            session = Session()
            transport = bootstrap.AzureCliBootstrapTransport(
                authorization=authorization,
                plan=self.plan,
                package=self.package,
                preflight={"projection": projection},
                clock=lambda: NOW,
                session=session,
            )
            transport.bind_journal(ledger)
            transport._active_operation_id = operation["id"]
            with mock.patch.object(
                transport,
                "_record_mutation",
                side_effect=OSError("simulated result fsync failure"),
            ):
                with self.assertRaisesRegex(
                    bootstrap._MutationOwnershipAmbiguity,
                    "could not be durably journaled",
                ) as raised:
                    transport._mutate(operation, {})
            self.assertIsInstance(raised.exception.__cause__, OSError)
            unresolved = ledger.unresolved_intents()
            self.assertEqual(len(unresolved), 1)
            self.assertEqual(unresolved[0]["operationId"], operation["id"])
            self.assertEqual(unresolved[0]["method"], "PATCH")
            self.assertEqual(
                unresolved[0]["targetUrl"],
                next(item[1] for item in session.requests if item[0] == "PATCH"),
            )
            self.assertEqual(
                unresolved[0]["requestBodySha256"],
                bootstrap.sha256_bytes(
                    next(item[2] for item in session.requests if item[0] == "PATCH")
                ),
            )

    def test_expiry_mid_run_blocks_next_mutation_but_allows_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            _, validated, preflight, projection, _ = self.fixture(folder)
            transport = FakeTransport(projection)

            def clock():
                applied = [value for kind, value in transport.calls if kind == "apply"]
                if "addOwnedUploaderIpv4Rule" in applied:
                    return validated.expires_at + dt.timedelta(seconds=1)
                return NOW

            executor = bootstrap.BootstrapExecutor(
                plan=self.plan,
                plan_sha256=self.plan_sha,
                package=self.package,
                authorization=validated,
                preflight=preflight,
                transport=transport,
                now=clock,
                source_validator=self.source,
            )
            with self.assertRaisesRegex(bootstrap.BootstrapError, "authorization expired"):
                executor.run()
            applied = [value for kind, value in transport.calls if kind == "apply"]
            self.assertEqual(applied[-1], "addOwnedUploaderIpv4Rule")
            self.assertEqual(
                [value for kind, value in transport.calls if kind == "compensate"],
                ["addOwnedUploaderIpv4Rule"],
            )

    def test_expiry_clipped_readiness_failure_compensates_before_expiry(self):
        with tempfile.TemporaryDirectory() as folder:
            _, validated, preflight, projection, _ = self.fixture(folder)
            transport = FakeTransport(projection)
            current = [NOW]
            original_apply = transport.apply_operation
            original_compensate = transport.compensate_temporary

            def apply(operation, state):
                if operation["id"] == "addOwnedOperatorControllerCanaryRole":
                    proof = original_apply(operation, state)
                    current[0] = validated.expires_at - dt.timedelta(
                        seconds=(
                            bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS
                            + bootstrap.PROTECTED_ROLE_ASSIGNMENT_DELETE_RESERVE_SECONDS
                        )
                    )
                    return proof
                if operation["id"] == "proveControllerLockContainerEmpty":
                    transport.calls.append(("apply", operation["id"]))
                    # The last GET begins before the work deadline and consumes
                    # its entire CLI+HTTP request envelope.
                    current[0] = validated.expires_at - dt.timedelta(
                        seconds=(
                            bootstrap.PROTECTED_ROLE_ASSIGNMENT_DELETE_RESERVE_SECONDS
                            + bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS
                        )
                    )
                    current[0] += dt.timedelta(
                        seconds=bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS
                    )
                    raise bootstrap.ControllerReadinessError(
                        "controller lock proof did not converge",
                        elapsed_seconds=bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS,
                        attempts=38,
                        status=403,
                        error_code="AuthorizationPermissionMismatch",
                        stop_reason="authorization-expired",
                    )
                return original_apply(operation, state)

            def compensate(operation, proof, state):
                self.assertGreaterEqual(
                    (validated.expires_at - current[0]).total_seconds(),
                    bootstrap.PROTECTED_ROLE_ASSIGNMENT_DELETE_RESERVE_SECONDS,
                )
                return original_compensate(operation, proof, state)

            executor = bootstrap.BootstrapExecutor(
                plan=self.plan,
                plan_sha256=self.plan_sha,
                package=self.package,
                authorization=validated,
                preflight=preflight,
                transport=transport,
                now=lambda: current[0],
                source_validator=self.source,
            )
            with (
                mock.patch.object(transport, "apply_operation", side_effect=apply),
                mock.patch.object(
                    transport, "compensate_temporary", side_effect=compensate
                ),
                self.assertRaises(bootstrap.ControllerReadinessError),
            ):
                executor.run()
            self.assertEqual(
                [value for kind, value in transport.calls if kind == "compensate"],
                [
                    "addOwnedOperatorControllerCanaryRole",
                    "addOwnedUploaderIpv4Rule",
                ],
            )

    def test_failure_compensates_only_owned_temporary_state(self):
        with tempfile.TemporaryDirectory() as folder:
            _, validated, preflight, projection, _ = self.fixture(folder)
            transport = FakeTransport(projection, fail_operation="uploadVersionedBridgePackage")
            with self.assertRaisesRegex(bootstrap.BootstrapError, "injected permanent failure"):
                self.executor(validated, preflight, transport).run()
            compensated = [value for kind, value in transport.calls if kind == "compensate"]
            self.assertEqual(
                compensated,
                [
                    "addOwnedUploaderPackageRole",
                    "addOwnedUploaderIpv4Rule",
                ],
            )
            self.assertNotIn("createPrivatePackageContainer", compensated)

    def test_empty_proof_failure_compensates_controller_role_then_ip(self):
        with tempfile.TemporaryDirectory() as folder:
            _, validated, preflight, projection, _ = self.fixture(folder)
            transport = FakeTransport(
                projection, fail_operation="proveControllerLockContainerEmpty"
            )
            with self.assertRaisesRegex(
                bootstrap.BootstrapError, "injected permanent failure"
            ):
                self.executor(validated, preflight, transport).run()
            self.assertEqual(
                [value for kind, value in transport.calls if kind == "compensate"],
                [
                    "addOwnedOperatorControllerCanaryRole",
                    "addOwnedUploaderIpv4Rule",
                ],
            )

    def test_controller_readiness_failure_retains_only_safe_diagnostics_after_cleanup(self):
        secret = "Bearer private-token 203.0.113.19 raw-message-secret"
        for code, expected in (
            ("AuthorizationPermissionMismatch", "AuthorizationPermissionMismatch"),
            (secret, "unknown"),
        ):
            with self.subTest(code=expected), tempfile.TemporaryDirectory() as folder:
                _, validated, preflight, projection, receipt = self.fixture(folder)
                transport = FakeTransport(projection)
                original_apply = transport.apply_operation

                def apply(operation, state):
                    if operation["id"] == "proveControllerLockContainerEmpty":
                        transport.calls.append(("apply", operation["id"]))
                        raise bootstrap.ControllerReadinessError(
                            "controller lock proof did not converge",
                            elapsed_seconds=600, attempts=44, status=403, error_code=code,
                            attempt_records=[{
                                "attempt": 44,
                                "startedAt": "2026-09-02T00:09:15.000Z",
                                "completedAt": "2026-09-02T00:09:15.125Z",
                                "durationMs": 125,
                                "clientRequestId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                                "status": 403, "errorCode": code,
                                "requestId": None, "serverDate": None,
                                "outcome": "response", "rawResponse": secret,
                            }],
                        )
                    return original_apply(operation, state)

                with mock.patch.object(transport, "apply_operation", side_effect=apply):
                    with self.assertRaises(bootstrap.ControllerReadinessError):
                        self.executor(validated, preflight, transport).run()
                terminal, raw = bootstrap.load_json(
                    receipt / "execution-terminal.json", require_canonical=True
                )
                self.assertEqual(terminal["status"], "failed")
                self.assertTrue(terminal["consumed"])
                self.assertIsNone(terminal["terminalBundlePath"])
                self.assertEqual(terminal["failureDiagnostic"], {
                    "stage": "controller-lock-empty-proof", "elapsedSeconds": 600,
                    "attempts": 44, "status": 403, "errorCode": expected,
                    "stopReason": "unknown", "requestId": None, "serverDate": None,
                    "credential": None, "roleReadback": None,
                    "attemptRecords": [{
                        "attempt": 44,
                        "startedAt": "2026-09-02T00:09:15.000Z",
                        "completedAt": "2026-09-02T00:09:15.125Z",
                        "durationMs": 125,
                        "clientRequestId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                        "status": 403, "errorCode": expected,
                        "requestId": None, "serverDate": None,
                        "outcome": "response",
                    }],
                })
                self.assertNotIn(secret.encode(), raw)
                self.assertNotIn(b"private-token", raw)
                self.assertEqual(
                    [value for kind, value in transport.calls if kind == "compensate"],
                    ["addOwnedOperatorControllerCanaryRole", "addOwnedUploaderIpv4Rule"],
                )

    def test_terminal_write_failure_does_not_mask_original_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            _, validated, preflight, projection, _ = self.fixture(folder)
            transport = FakeTransport(projection, fail_operation="createMailboxResourceGroup")
            with mock.patch.object(bootstrap.UseLedger, "write_terminal", side_effect=OSError("disk")):
                with self.assertRaisesRegex(bootstrap.BootstrapError, "injected permanent failure"):
                    self.executor(validated, preflight, transport).run()

    def test_authorization_specific_azure_claim_is_first_and_persistent(self):
        self.assertEqual(self.plan["mutations"][0]["id"], "claimAzureSingleUseAuthorization")
        claim = self.plan["resourceInventory"][0]
        self.assertEqual(claim["id"], "azureSingleUseClaim")
        self.assertIn("201-only-never-delete", claim["policy"])
        self.assertNotIn("claimAzureSingleUseAuthorization", [item["id"] for item in self.plan["mutations"] if item["temporary"]])

    def test_azure_claim_requires_http_201_without_conditional_header(self):
        operation = self.plan["mutations"][0]

        class Session:
            def __init__(self, status):
                self.status = status
                self.requests = []

            def request(
                self, method, url, *, body=None, headers=None, deadline=None
            ):
                self.requests.append((method, url, body, dict(headers or {})))
                return bootstrap._RestResponse(
                    self.status,
                    bootstrap.canonical_json_bytes({"name": "claim"}),
                    {},
                )

        def transport(status):
            class Journal:
                def __init__(self): self.items = []
                def append_cloud_mutation(self, item):
                    self.items.append(item)
                    return Path(f"cloud-mutation-{len(self.items):04d}.json")

            value = object.__new__(bootstrap.AzureCliBootstrapTransport)
            value.authorization = {
                "authorizationId": AUTH_ID,
                "source": {"mergedMain": {"commitSha": MERGE}},
                "plan": {"sha256": self.plan_sha},
                "validity": {
                    "notBefore": stamp(NOW - dt.timedelta(minutes=1)),
                    "expiresAt": stamp(NOW + dt.timedelta(minutes=2)),
                },
                "singleUse": {
                    "azureClaimResourceId": (
                        f"/subscriptions/{bootstrap.SUBSCRIPTION}/providers/"
                        f"Microsoft.Resources/deployments/paperdesk-v2-bootstrap-{AUTH_ID}"
                    )
                },
            }
            value.plan = self.plan
            value.package = self.package
            value.resources = {item["id"]: item for item in self.plan["resourceInventory"]}
            value.admissions = {operation["id"]: {"context": {}}}
            value.session = Session(status)
            value._ledger = Journal()
            value._active_operation_id = operation["id"]
            value.clock = lambda: NOW
            return value

        state = {
            "authorizationSha256": "1" * 64,
            "planSha256": self.plan_sha,
            "package": self.package,
        }
        created = transport(201)
        result = created._mutate(operation, state)
        self.assertEqual(result["deploymentName"], "claim")
        request = created.session.requests[0]
        self.assertEqual(request[0], "PUT")
        self.assertEqual(request[3], {"Content-Type": "application/json"})
        self.assertNotIn("If-None-Match", request[3])

        replay = transport(200)
        with self.assertRaisesRegex(bootstrap.BootstrapError, "unexpected HTTP status 200"):
            replay._mutate(operation, state)
        self.assertEqual(replay.session.requests[0][3], {"Content-Type": "application/json"})

    def test_bridge_canary_binds_fresh_terminal_success_and_stops_in_finally(self):
        with tempfile.TemporaryDirectory() as folder:
            _, validated, _, _, _ = self.fixture(folder)
            operation = next(
                item
                for item in self.plan["mutations"]
                if item["id"] == "startBridgeForBoundedCanary"
            )
            site = next(
                item
                for item in self.plan["resourceInventory"]
                if item["id"] == "bridgeSite"
            )
            job = "paperdesk-accepted-release-registry"
            history_id = (
                site["resourceId"]
                + f"/triggeredwebjobs/{job}/history/fresh-run"
            )

            class Journal:
                def __init__(self):
                    self.items = []

                def append_cloud_mutation(self, item):
                    self.items.append(copy.deepcopy(item))
                    return Path(f"cloud-mutation-{len(self.items):04d}.json")

            class Session:
                def __init__(self, terminal_status="Success"):
                    self.requests = []
                    self.site_states = ["Stopped", "Running", "Stopped"]
                    self.history_reads = 0
                    self.terminal_status = terminal_status

                def request(
                    self, method, url, *, body=None, headers=None, deadline=None
                ):
                    self.requests.append((method, url, body, dict(headers or {})))
                    response_headers = {"Content-Type": "application/json"}
                    if "/triggeredwebjobs/" in url and "/history?" in url:
                        self.history_reads += 1
                        values = []
                        if self.history_reads > 1:
                            values = [
                                {
                                    "id": history_id,
                                    "properties": {
                                        "runs": [
                                            {
                                                "web_job_name": job,
                                                "web_job_id": "fresh-run",
                                                "status": self.terminal_status,
                                                "start_time": stamp(NOW),
                                                "end_time": stamp(
                                                    NOW + dt.timedelta(seconds=2)
                                                ),
                                                "output_url": (
                                                    "https://paperdesk-release-registry-bridge-v2-"
                                                    "9c4e0d0d.scm.azurewebsites.net/vfs/data/jobs/"
                                                    "triggered/paperdesk-accepted-release-registry/"
                                                    "fresh-run/output_log.txt"
                                                ),
                                            }
                                        ]
                                    },
                                }
                            ]
                        return bootstrap._RestResponse(
                            200,
                            bootstrap.canonical_json_bytes({"value": values}),
                            response_headers,
                        )
                    if method == "GET" and url.startswith(
                        f"https://management.azure.com{site['resourceId']}?"
                    ):
                        state = self.site_states.pop(0)
                        return bootstrap._RestResponse(
                            200,
                            bootstrap.canonical_json_bytes(
                                {
                                    "id": site["resourceId"],
                                    "name": site["name"],
                                    "properties": {"state": state},
                                }
                            ),
                            response_headers,
                        )
                    return bootstrap._RestResponse(202, b"", {})

            def build_transport(session):
                transport = object.__new__(bootstrap.AzureCliBootstrapTransport)
                transport.authorization = validated.document
                transport.plan = self.plan
                transport.package = self.package
                transport.resources = {
                    item["id"]: item for item in self.plan["resourceInventory"]
                }
                transport.admissions = {
                    operation["id"]: {
                        "context": {"executionDecision": "apply-exact"}
                    }
                }
                transport.session = session
                transport._ledger = Journal()
                transport._active_operation_id = operation["id"]
                transport.clock = lambda: NOW + dt.timedelta(seconds=3)
                transport.sleep = lambda _seconds: None
                return transport

            state = {
                "proofs": {
                    "configureBridgeExactVersionedPackageAndCriticalSettings": {
                        "details": {
                            "settingsSha256": "5" * 64,
                            "bootstrapSelfTestControlSha256": "6" * 64,
                            "bootstrapSelfTestIssuedAt": stamp(NOW),
                            "bootstrapSelfTestExpiresAt": stamp(NOW + dt.timedelta(seconds=900)),
                        }
                    },
                    "uploadVersionedBridgePackage": {
                        "details": {
                            "blob": f"v2/control/{MERGE}/paperdesk-private-release-bridge.zip",
                            "etag": '"package"',
                            "versionId": "version-1",
                            "url": "https://mdspdbak2608089c4e.blob.core.windows.net/paperdesk-deployment-packages/x",
                            "sha256": self.package["sha256"],
                            "size": self.package["size"],
                        }
                    },
                    "createInitialIdleActivationFence": {
                        "details": {
                            "url": "https://mdspdbak2608089c4e.blob.core.windows.net/paperdesk-release-activation-control/v2/production-activation-fence.json",
                            "etag": '"fence"',
                            "versionId": "fence-version",
                            "sha256": "7" * 64,
                        }
                    },
                }
            }
            success_session = Session()
            proof = build_transport(success_session)._mutate(operation, state)
            self.assertTrue(proof["selfCleaned"])
            self.assertEqual(proof["terminalHistory"]["status"], "Success")
            self.assertEqual(proof["stopped"]["state"], "Stopped")
            self.assertIn("not observed", proof["proofBoundary"])
            methods_and_paths = [
                (method, url.split("?", 1)[0])
                for method, url, _body, _headers in success_session.requests
            ]
            self.assertEqual(
                sum(path.endswith("/stop") for _method, path in methods_and_paths),
                1,
            )

            failed_session = Session(terminal_status="Failed")
            with self.assertRaisesRegex(
                bootstrap.BootstrapError, "before terminal Success"
            ):
                build_transport(failed_session)._mutate(operation, state)
            self.assertEqual(
                sum(
                    url.split("?", 1)[0].endswith("/stop")
                    for _method, url, _body, _headers in failed_session.requests
                ),
                1,
            )

    def test_full_terminal_source_evidence_public_validator_accepts_exact_fixture(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)
        validated = bootstrap.validate_terminal_source_evidence(
            plan=fixture["plan"],
            authorization=fixture["authorization"],
            preflight_projection=fixture["preflightProjection"],
            evidence=fixture["sourceEvidence"],
        )
        self.assertEqual(validated, fixture["sourceEvidence"])

    @staticmethod
    def _terminal_journal_validation_inputs(fixture):
        contexts = {
            item["operationId"]: item["context"]
            for item in fixture["preflightProjection"]["operationAdmissions"]
        }
        return {
            "plan": fixture["plan"],
            "authorization": fixture["authorization"],
            "operation_projections": fixture["operationProjections"],
            "operation_contexts": contexts,
        }

    def test_cleanup_terminal_proofs_reject_missing_or_drifted_restored_lock(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)
        inputs = self._terminal_journal_validation_inputs(fixture)
        protected = [operation_id for operation_id in fixture["operationProjections"]
                     if bootstrap._expected_deletion_lock_proof(operation_id) is not None]
        self.assertEqual(len(protected), 8)
        for operation_id in protected:
            original = fixture["operationProjections"][operation_id]
            for field, value in (("restored", False), ("assignmentAbsent", False),
                                 ("resourceId", "/subscriptions/unrelated"),
                                 ("properties", {"level": "ReadOnly"}), (None, None)):
                with self.subTest(operation=operation_id, field=field):
                    altered = copy.deepcopy(original)
                    if field is None:
                        altered["projection"].pop("deletionLock")
                    else:
                        altered["projection"]["deletionLock"][field] = value
                    with self.assertRaises(bootstrap.BootstrapError):
                        bootstrap._validate_operation_source_projection(
                            altered, operation_id=operation_id, plan=fixture["plan"],
                            authorization=fixture["authorization"],
                            prior=fixture["operationProjections"],
                            operation_context=inputs["operation_contexts"][operation_id],
                            runtime_facts={},
                        )

    def test_cleanup_terminal_journal_requires_nested_exact_lock_mutations(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)
        inputs = self._terminal_journal_validation_inputs(fixture)
        original = fixture["sourceEvidence"]["productionBoundary"]["mutationJournal"]
        operation_id = "removeOwnedUploaderPackageRole"
        entries = [item for item in original if item["operationId"] == operation_id]
        intents = [item for item in entries if item["phase"] == "intent"]
        self.assertEqual([item["method"] for item in intents], ["DELETE", "DELETE", "PUT", "DELETE"])
        self.assertIn("/locks/", intents[0]["targetUrl"].lower())
        self.assertEqual(intents[0]["targetUrl"], intents[2]["targetUrl"])
        for mode in ("omit-restore", "restore-before-assignment", "definition-before-restore"):
            with self.subTest(mode=mode):
                pairs = [entries[i:i + 2] for i in range(0, len(entries), 2)]
                if mode == "omit-restore":
                    pairs.pop(2)
                elif mode == "restore-before-assignment":
                    pairs[1], pairs[2] = pairs[2], pairs[1]
                else:
                    pairs[2], pairs[3] = pairs[3], pairs[2]
                replacement = [item for pair in pairs for item in pair]
                altered = []
                inserted = False
                for item in original:
                    if item["operationId"] == operation_id:
                        if not inserted:
                            altered.extend(copy.deepcopy(replacement))
                            inserted = True
                    else:
                        altered.append(copy.deepcopy(item))
                for index, item in enumerate(altered):
                    item["sequence"] = index + 1
                    item["recordedAt"] = stamp(NOW + dt.timedelta(milliseconds=(index + 1) * 10))
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap._validate_sanitized_mutation_journal(altered, **inputs)

    def test_terminal_journal_covers_every_mutating_outcome_and_keeps_adoption_no_write(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)
        journal = fixture["sourceEvidence"]["productionBoundary"][
            "mutationJournal"
        ]
        validated = bootstrap._validate_sanitized_mutation_journal(
            journal, **self._terminal_journal_validation_inputs(fixture)
        )
        self.assertEqual(validated, journal)
        adopted = {
            "adoptExistingRegistryWriterIdentity",
            "adoptExistingRegistryReaderIdentity",
        }
        self.assertFalse(
            any(item["operationId"] in adopted for item in journal)
        )
        permanent = {
            item["mutationId"]: item
            for item in fixture["sourceEvidence"]["permanentMutationProjections"]
        }
        self.assertTrue(
            all(permanent[item]["outcome"] == "adopted-exact" for item in adopted)
        )

    def test_terminal_journal_rejects_attach_patch_when_preflight_adopts_exact(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)
        inputs = self._terminal_journal_validation_inputs(fixture)
        attach_projection = next(
            item["sourceProjection"] for item in fixture["sourceEvidence"]["allOperationProjections"]
            if item["operationId"] == "attachFiveUamisOnlyToBridge"
        )
        identity = attach_projection["projection"]["identity"]
        inputs["operation_contexts"]["attachFiveUamisOnlyToBridge"] = {
            "executionDecision": "adopt-exact",
            "adopted": {
                "identityResourceIds": sorted(identity["userAssignedIdentities"], key=str.lower),
                "expectedEtag": '"adopted-attach"',
                "identityProjectionSha256": bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes(identity)
                ),
            },
        }
        journal = fixture["sourceEvidence"]["productionBoundary"]["mutationJournal"]
        self.assertTrue(any(
            item["operationId"] == "attachFiveUamisOnlyToBridge" for item in journal
        ))
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap._validate_sanitized_mutation_journal(journal, **inputs)

    def test_terminal_journal_rejects_omitted_duplicate_or_failed_mutation_result(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)
        inputs = self._terminal_journal_validation_inputs(fixture)
        journal = fixture["sourceEvidence"]["productionBoundary"][
            "mutationJournal"
        ]

        omitted = copy.deepcopy(journal[:-2])
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "coverage drifted"
        ):
            bootstrap._validate_sanitized_mutation_journal(omitted, **inputs)

        duplicate = copy.deepcopy(journal)
        original_intent = next(
            item
            for item in journal
            if item["phase"] == "intent"
            and item["operationId"] == "createMailboxResourceGroup"
        )
        original_result = next(
            item
            for item in journal
            if item["phase"] == "result"
            and item["intentId"] == original_intent["intentId"]
        )
        duplicate_intent = copy.deepcopy(original_intent)
        duplicate_intent.update(
            {
                "sequence": len(duplicate) + 1,
                "intentId": f"cloud-mutation-{len(duplicate) + 1:04d}",
                "recordedAt": stamp(NOW + dt.timedelta(minutes=3)),
            }
        )
        duplicate_result = copy.deepcopy(original_result)
        duplicate_result.update(
            {
                "sequence": len(duplicate) + 2,
                "intentId": duplicate_intent["intentId"],
                "recordedAt": stamp(
                    NOW + dt.timedelta(minutes=3, milliseconds=1)
                ),
            }
        )
        duplicate.extend((duplicate_intent, duplicate_result))
        with self.assertRaisesRegex(bootstrap.BootstrapError, "coverage drifted"):
            bootstrap._validate_sanitized_mutation_journal(duplicate, **inputs)

        failed = copy.deepcopy(journal)
        next(
            item
            for item in failed
            if item["phase"] == "result"
            and item["operationId"] == "createMailboxResourceGroup"
        )["status"] = 500
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "non-success result"
        ):
            bootstrap._validate_sanitized_mutation_journal(failed, **inputs)

    def test_exact_rbac_children_are_not_release_writes_but_drift_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)
        journal = fixture["sourceEvidence"]["productionBoundary"][
            "mutationJournal"
        ]
        resources = {
            item["id"]: item for item in fixture["plan"]["resourceInventory"]
        }
        contexts = self._terminal_journal_validation_inputs(fixture)[
            "operation_contexts"
        ]
        reviewed = [
            item
            for item in journal
            if item["phase"] == "intent"
            and item["operationId"] == "createExactRoleAssignments"
            and (
                resources["productionSite"]["resourceId"].lower()
                in item["targetUrl"].lower()
                or resources["acceptedContainer"]["resourceId"].lower()
                in item["targetUrl"].lower()
            )
        ]
        self.assertGreaterEqual(len(reviewed), 2)
        for item in reviewed:
            self.assertEqual(
                bootstrap._forbidden_release_mutation_classes(
                    item["method"], item["targetUrl"], fixture["plan"]
                ),
                (False, False),
            )
            self.assertTrue(
                bootstrap._mutation_target_allowed(
                    item["operationId"],
                    item["method"],
                    item["targetUrl"],
                    plan=fixture["plan"],
                    authorization_id=fixture["authorization"]["authorizationId"],
                    source_sha=fixture["authorization"]["source"]["mergedMain"][
                        "commitSha"
                    ],
                    operation_projections=fixture["operationProjections"],
                    operation_contexts=contexts,
                )
            )
        assignment_prefix, assignment_suffix = reviewed[0]["targetUrl"].split(
            "roleassignments/", 1
        )
        replacement = "0" if assignment_suffix[0] != "0" else "1"
        drifted = (
            assignment_prefix
            + "roleassignments/"
            + replacement
            + assignment_suffix[1:]
        )
        self.assertFalse(
            bootstrap._mutation_target_allowed(
                "createExactRoleAssignments",
                "PUT",
                drifted,
                plan=fixture["plan"],
                authorization_id=fixture["authorization"]["authorizationId"],
                source_sha=fixture["authorization"]["source"]["mergedMain"][
                    "commitSha"
                ],
                operation_projections=fixture["operationProjections"],
                operation_contexts=contexts,
            )
        )
        production_config = (
            "https://management.azure.com"
            + resources["productionSite"]["resourceId"]
            + "/config/appsettings?api-version=2025-03-01"
        )
        accepted_blob = (
            "https://mdspdbak2608089c4e.blob.core.windows.net/"
            + resources["acceptedContainer"]["name"]
            + "/release.json"
        )
        self.assertEqual(
            bootstrap._forbidden_release_mutation_classes(
                "PUT", production_config, fixture["plan"]
            ),
            (True, False),
        )
        self.assertEqual(
            bootstrap._forbidden_release_mutation_classes(
                "PUT", accepted_blob, fixture["plan"]
            ),
            (False, True),
        )

    def test_production_lock_exception_is_exact_and_does_not_allow_site_writes(self):
        spec = self.plan["deletionProtection"]["locks"]["productionApp"]
        lock_url = "https://management.azure.com" + spec["resourceId"] + "?api-version=2016-09-01"
        site_url = "https://management.azure.com" + next(
            item["resourceId"] for item in self.plan["resourceInventory"]
            if item["id"] == "productionSite"
        )
        for method in ("DELETE", "PUT"):
            self.assertEqual(bootstrap._forbidden_release_mutation_classes(
                method, lock_url, self.plan), (False, False))
        forbidden = [
            ("PATCH", lock_url), ("POST", lock_url),
            ("DELETE", lock_url.replace("protect-app-delete", "other-lock")),
            ("DELETE", lock_url + "&extra=true"),
            ("DELETE", lock_url + "#fragment"),
            ("DELETE", lock_url.replace("2016-09-01", "2025-03-01")),
            ("DELETE", site_url + "?api-version=2025-03-01"),
            ("PUT", site_url + "/config/appsettings?api-version=2025-03-01"),
            ("POST", site_url + "/restart?api-version=2025-03-01"),
        ]
        for method, url in forbidden:
            with self.subTest(method=method, url=url):
                self.assertEqual(bootstrap._forbidden_release_mutation_classes(
                    method, url, self.plan), (True, False))

    def test_public_terminal_source_builder_produces_one_valid_complete_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)
        descriptor, package_bytes = bootstrap.build_package_artifact()
        self.assertEqual(descriptor, self.package)
        mutations = {
            item["id"]: item
            for item in self.plan["mutations"]
            if item["kind"] != "local-create-only-canonical-evidence"
        }
        statuses = {}
        for operation_id, mutation in mutations.items():
            if operation_id == "readBackExactSigningPublicJwk":
                status = "verified-exact"
            elif mutation["kind"].startswith(
                ("delete-", "remove-", "temporary-remove")
            ):
                status = "removed-exact"
            elif "adopt-existing" in mutation["kind"]:
                status = "adopted-exact"
            elif mutation["kind"].startswith(
                ("create-", "azure-global-create", "azure-ad-create")
            ):
                status = "created"
            else:
                status = "applied-exact"
            statuses[operation_id] = status
        observed = {
            operation_id: stamp(NOW + dt.timedelta(minutes=1))
            for operation_id in mutations
        }
        source = fixture["sourceEvidence"]
        built = bootstrap.build_terminal_source_evidence(
            plan=self.plan,
            authorization=fixture["authorization"],
            preflight_projection=fixture["preflightProjection"],
            operation_projections=fixture["operationProjections"],
            operation_statuses=statuses,
            operation_observed_at=observed,
            postcondition_projections=source["postconditionProjections"],
            mutation_journal=source["productionBoundary"]["mutationJournal"],
            package_readback_bytes=package_bytes,
            production_boundary_post_execution=source["productionBoundary"][
                "postExecutionProjection"
            ],
            retired_role_absence_fresh_preflight=source["productionBoundary"][
                "freshPreflightRetiredRoleAbsence"
            ],
            retired_role_absence_post_execution=source["productionBoundary"][
                "postExecutionRetiredRoleAbsence"
            ],
            claimed_at=stamp(NOW),
            observed_at=stamp(NOW + dt.timedelta(minutes=7)),
        )
        self.assertEqual(
            bootstrap.validate_terminal_source_evidence(
                plan=self.plan,
                authorization=fixture["authorization"],
                preflight_projection=fixture["preflightProjection"],
                evidence=built,
            ),
            built,
        )
        self.assertFalse(
            built["managedIdentityFetchResponseProjection"][
                "directPackageBytesObservedByExecutor"
            ]
        )

    def test_retired_role_absence_source_rejects_omission_duplicate_replacement_and_status_drift(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)
        source = fixture["sourceEvidence"]

        def rejected(candidate):
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.validate_terminal_source_evidence(
                    plan=self.plan,
                    authorization=fixture["authorization"],
                    preflight_projection=fixture["preflightProjection"],
                    evidence=candidate,
                )

        for field in (
            "freshPreflightRetiredRoleAbsence",
            "postExecutionRetiredRoleAbsence",
        ):
            variants = {}
            omitted = copy.deepcopy(source)
            omitted["productionBoundary"][field].pop()
            variants["omitted-resource"] = omitted
            duplicate = copy.deepcopy(source)
            duplicate["productionBoundary"][field][1] = copy.deepcopy(
                duplicate["productionBoundary"][field][0]
            )
            variants["duplicate-resource"] = duplicate
            replacement = copy.deepcopy(source)
            replacement["productionBoundary"][field][0]["resourceId"] = (
                "/subscriptions/"
                + bootstrap.SUBSCRIPTION
                + "/providers/Microsoft.Authorization/roleDefinitions/"
                + "00000000-0000-4000-8000-000000000001"
            )
            variants["replacement-resource"] = replacement
            status_drift = copy.deepcopy(source)
            status_drift["productionBoundary"][field][0]["status"] = 200
            variants["status-drift"] = status_drift
            missing_digest = copy.deepcopy(source)
            del missing_digest["productionBoundary"][field][0]["responseSha256"]
            variants["missing-digest"] = missing_digest
            missing_timestamp = copy.deepcopy(source)
            del missing_timestamp["productionBoundary"][field][0]["observedAt"]
            variants["missing-timestamp"] = missing_timestamp
            for name, candidate in variants.items():
                with self.subTest(field=field, variant=name):
                    rejected(candidate)

        missing_phase = copy.deepcopy(source)
        del missing_phase["productionBoundary"][
            "freshPreflightRetiredRoleAbsence"
        ]
        rejected(missing_phase)

        swapped = copy.deepcopy(source)
        boundary = swapped["productionBoundary"]
        (
            boundary["freshPreflightRetiredRoleAbsence"],
            boundary["postExecutionRetiredRoleAbsence"],
        ) = (
            boundary["postExecutionRetiredRoleAbsence"],
            boundary["freshPreflightRetiredRoleAbsence"],
        )
        rejected(swapped)

    def test_terminal_receipt_component_builder_uses_full_validated_source_universe(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)
        source = fixture["sourceEvidence"]
        components = bootstrap.build_terminal_receipt_components(
            plan=fixture["plan"],
            authorization=fixture["authorization"],
            preflight_projection=fixture["preflightProjection"],
            source_evidence=source,
            started_at=source["claimReceipt"]["claimedAt"],
            completed_at=source["observedAt"],
        )
        self.assertEqual(
            set(components),
            {
                "permanentMutationLedger",
                "temporaryAccessCleanup",
                "activationFenceBootstrap",
                "packageReadback",
                "managedIdentityFetchSelfTest",
                "bridgeEvidence",
                "leaseCanaryEvidence",
                "wormProjections",
            },
        )
        temporary = components["temporaryAccessCleanup"]
        self.assertTrue(temporary["packageIpv4Rule"]["createdByAuthorization"])
        for name in (
            "packageUploaderRole",
            "operatorKeyReadRole",
            "operatorFenceRole",
            "operatorControllerRole",
        ):
            self.assertTrue(temporary[name]["createdByAuthorization"])
            self.assertEqual(temporary[name]["roleDefinitionCreatedByAuthorization"], name != "operatorControllerRole")
            self.assertEqual(temporary[name]["roleDefinitionPresentAfterCleanup"], name == "operatorControllerRole")
        self.assertEqual(
            components["activationFenceBootstrap"]["leaseState"], "Available"
        )
        self.assertEqual(
            components["activationFenceBootstrap"]["leaseStatus"], "Unlocked"
        )
        self.assertEqual(
            components["activationFenceBootstrap"]["provisioningOutcome"],
            "created-by-authorization",
        )
        self.assertEqual(
            components["packageReadback"]["provisioningOutcome"],
            "created-by-authorization",
        )
        self.assertEqual(
            components["leaseCanaryEvidence"]["status"],
            "direct-controller-and-source-derived-activation-proof-complete",
        )
        self.assertEqual(
            components["bridgeEvidence"]["status"],
            "terminal-success-with-source-derived-boundaries-complete",
        )
        self.assertEqual(
            components["wormProjections"]["status"],
            "locked-at-least-91-days",
        )

    def test_complete_terminal_receipt_input_fixture_is_one_valid_round_trip(self):
        with tempfile.TemporaryDirectory() as folder:
            value = build_complete_terminal_receipt_input_fixture(
                Path(folder)
                / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
            )
        self.assertEqual(
            value["completeReceipt"]["bundle"]["executionReceipt"]["status"],
            "succeeded-terminal",
        )
        self.assertEqual(
            value["completeReceipt"]["s2EvidenceFiles"], value["s2Documents"]
        )
        terminal = value["completeReceipt"]["s2TerminalBundle"]
        self.assertEqual(
            set(terminal),
            {value["plan"]["evidenceOutputs"]["terminalBundlePath"]},
        )
        self.assertEqual(
            value["components"]["managedIdentityFetchSelfTest"]["status"],
            "source-derived-terminal-success",
        )

    def test_terminal_receipts_do_not_claim_current_creation_for_exact_adoption(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = build_valid_terminal_source_evidence_fixture(
                Path(folder)
                / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}",
                plan=self.plan,
                plan_sha=self.plan_sha,
                package=self.package,
                adopt_operations={
                    "uploadVersionedBridgePackage",
                    "createInitialIdleActivationFence",
                },
            )
        source = fixture["sourceEvidence"]
        components = bootstrap.build_terminal_receipt_components(
            plan=fixture["plan"],
            authorization=fixture["authorization"],
            preflight_projection=fixture["preflightProjection"],
            source_evidence=source,
            started_at=source["claimReceipt"]["claimedAt"],
            completed_at=source["observedAt"],
        )
        for name in ("activationFenceBootstrap", "packageReadback"):
            with self.subTest(name=name):
                self.assertEqual(
                    components[name]["provisioningOutcome"], "adopted-exact"
                )
                self.assertIsNone(components[name]["createCondition"])
                self.assertIsNone(components[name]["createHttpStatus"])

    def test_terminal_operation_and_postcondition_times_are_inside_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)
        before_claim = copy.deepcopy(fixture["sourceEvidence"])
        before_claim["allOperationProjections"][0]["observedAt"] = stamp(
            NOW - dt.timedelta(minutes=1)
        )
        with self.assertRaisesRegex(bootstrap.BootstrapError, "actual execution"):
            bootstrap.validate_terminal_source_evidence(
                plan=fixture["plan"],
                authorization=fixture["authorization"],
                preflight_projection=fixture["preflightProjection"],
                evidence=before_claim,
            )

        after_completion = copy.deepcopy(fixture["sourceEvidence"])
        after_completion["postconditionProjections"][0]["observedAt"] = stamp(
            NOW + dt.timedelta(minutes=8)
        )
        with self.assertRaisesRegex(bootstrap.BootstrapError, "actual execution"):
            bootstrap.validate_terminal_source_evidence(
                plan=fixture["plan"],
                authorization=fixture["authorization"],
                preflight_projection=fixture["preflightProjection"],
                evidence=after_completion,
            )

    def test_versioned_create_journal_headers_are_exact_readback_headers(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)
        source = fixture["sourceEvidence"]
        journal = copy.deepcopy(source["productionBoundary"]["mutationJournal"])
        result = next(
            item
            for item in journal
            if item["phase"] == "result"
            and item["operationId"] == "uploadVersionedBridgePackage"
        )
        result["etag"] = '"different-versioned-etag"'
        operation_projections = {
            item["operationId"]: item["sourceProjection"]
            for item in source["allOperationProjections"]
        }
        operation_contexts = {
            item["operationId"]: item["context"]
            for item in fixture["preflightProjection"]["operationAdmissions"]
        }
        with self.assertRaisesRegex(bootstrap.BootstrapError, "cross-bound"):
            bootstrap._validate_sanitized_mutation_journal(
                journal,
                plan=fixture["plan"],
                authorization=fixture["authorization"],
                operation_projections=operation_projections,
                operation_contexts=operation_contexts,
                execution_started_at=NOW,
                execution_completed_at=NOW + dt.timedelta(minutes=7),
            )

    def test_worm_lock_post_cardinality_follows_put_state(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)
        source = fixture["sourceEvidence"]
        operation_projections = {
            item["operationId"]: copy.deepcopy(item["sourceProjection"])
            for item in source["allOperationProjections"]
        }
        operation_contexts = {
            item["operationId"]: item["context"]
            for item in fixture["preflightProjection"]["operationAdmissions"]
        }
        operation_id = "lockPackageRetentionAt91Days"
        required, optional = bootstrap._expected_terminal_mutation_targets(
            operation_id,
            plan=fixture["plan"],
            authorization_id=AUTH_ID,
            source_sha=MERGE,
            operation_projections=operation_projections,
            operation_contexts=operation_contexts,
        )
        self.assertEqual(sum(required.values()), 1)
        self.assertFalse(optional)

        operation_projections[operation_id]["projection"]["stateAfterPut"] = (
            "Unlocked"
        )
        operation_projections[operation_id]["projection"]["lockPostIssued"] = True
        required, optional = bootstrap._expected_terminal_mutation_targets(
            operation_id,
            plan=fixture["plan"],
            authorization_id=AUTH_ID,
            source_sha=MERGE,
            operation_projections=operation_projections,
            operation_contexts=operation_contexts,
        )
        self.assertEqual(sum(required.values()), 2)
        self.assertFalse(optional)

        operation_projections[operation_id]["projection"]["lockPostIssued"] = False
        with self.assertRaisesRegex(bootstrap.BootstrapError, "WORM mutation path"):
            bootstrap._expected_terminal_mutation_targets(
                operation_id,
                plan=fixture["plan"],
                authorization_id=AUTH_ID,
                source_sha=MERGE,
                operation_projections=operation_projections,
                operation_contexts=operation_contexts,
            )

    def test_full_terminal_source_evidence_rejects_operation_tamper(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)
        altered = copy.deepcopy(fixture["sourceEvidence"])
        bridge = next(
            item
            for item in altered["permanentMutationProjections"]
            if item["mutationId"] == "createStoppedPrivateBridge"
        )
        bridge["sourceProjection"]["projection"]["publicNetworkAccess"] = "Enabled"
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.validate_terminal_source_evidence(
                plan=fixture["plan"],
                authorization=fixture["authorization"],
                preflight_projection=fixture["preflightProjection"],
                evidence=altered,
            )

    def test_terminal_attach_projection_rejects_unsafe_nonidentity_posture(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)
        for field, value in (
            ("kind", "app"),
            ("httpsOnly", False),
            ("serverFarmId", "/subscriptions/invalid/serverfarm"),
            ("virtualNetworkSubnetId", "/subscriptions/invalid/subnet"),
            ("outboundVnetRouting", {"allTraffic": False, "applicationTraffic": False}),
        ):
            altered = copy.deepcopy(fixture["sourceEvidence"])
            projection = next(
                item["sourceProjection"]["projection"]
                for item in altered["permanentMutationProjections"]
                if item["mutationId"] == "attachFiveUamisOnlyToBridge"
            )
            projection[field] = value
            with self.subTest(field=field), self.assertRaises(bootstrap.BootstrapError):
                bootstrap.validate_terminal_source_evidence(
                    plan=fixture["plan"], authorization=fixture["authorization"],
                    preflight_projection=fixture["preflightProjection"], evidence=altered,
                )

    def test_terminal_bridge_uami_inventory_accepts_populated_arm_metadata_case_insensitively(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)
        evidence = fixture["sourceEvidence"]
        source_projection = copy.deepcopy(next(
            item
            for item in evidence["allOperationProjections"]
            if item["operationId"] == "attachFiveUamisOnlyToBridge"
        )["sourceProjection"])
        attachment = source_projection["projection"]["identity"][
            "userAssignedIdentities"
        ]
        resource_id, metadata = next(iter(attachment.items()))
        del attachment[resource_id]
        attachment[resource_id.upper()] = metadata
        prior = {
            item["operationId"]: item["sourceProjection"]
            for item in evidence["allOperationProjections"]
        }
        operation_context = next(
            item["context"]
            for item in fixture["preflightProjection"]["operationAdmissions"]
            if item["operationId"] == "attachFiveUamisOnlyToBridge"
        )
        bootstrap._validate_operation_source_projection(
            source_projection,
            operation_id="attachFiveUamisOnlyToBridge",
            plan=fixture["plan"],
            authorization=fixture["authorization"],
            prior=prior,
            operation_context=operation_context,
            runtime_facts={},
        )

    def test_terminal_bridge_uami_inventory_rejects_malformed_or_unbound_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)

        def altered_attachment():
            altered = copy.deepcopy(fixture["sourceEvidence"])
            attachment = next(
                item
                for item in altered["permanentMutationProjections"]
                if item["mutationId"] == "attachFiveUamisOnlyToBridge"
            )["sourceProjection"]["projection"]["identity"]["userAssignedIdentities"]
            return altered, attachment

        mutations = {
            "non-object": lambda attachment, key: attachment.__setitem__(key, []),
            "missing principalId": lambda attachment, key: attachment[key].pop(
                "principalId"
            ),
            "mismatched clientId": lambda attachment, key: attachment[key].__setitem__(
                "clientId", str(uuid.uuid5(uuid.UUID(AUTH_ID), "wrong-client"))
            ),
            "unknown nested field": lambda attachment, key: attachment[key].__setitem__(
                "tenantId", bootstrap.TENANT
            ),
            "duplicate case-variant identity": lambda attachment, key: attachment.__setitem__(
                key.upper(), copy.deepcopy(attachment[key])
            ),
            "extra identity": lambda attachment, _key: attachment.__setitem__(
                "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/extra/providers/Microsoft.ManagedIdentity/userAssignedIdentities/extra",
                {
                    "clientId": str(uuid.uuid5(uuid.UUID(AUTH_ID), "extra-client")),
                    "principalId": str(
                        uuid.uuid5(uuid.UUID(AUTH_ID), "extra-principal")
                    ),
                },
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                altered, attachment = altered_attachment()
                mutate(attachment, next(iter(attachment)))
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_terminal_source_evidence(
                        plan=fixture["plan"],
                        authorization=fixture["authorization"],
                        preflight_projection=fixture["preflightProjection"],
                        evidence=altered,
                    )

    def test_full_terminal_source_evidence_rejects_postcondition_tamper(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)
        altered = copy.deepcopy(fixture["sourceEvidence"])
        postcondition = next(
            item
            for item in altered["postconditionProjections"]
            if item["postconditionId"] == "packageExactVersionReadback"
        )
        postcondition["sourceProjection"]["localProjection"][
            "requiredOperationProjectionCount"
        ] = 0
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.validate_terminal_source_evidence(
                plan=fixture["plan"],
                authorization=fixture["authorization"],
                preflight_projection=fixture["preflightProjection"],
                evidence=altered,
            )

    def test_full_terminal_source_evidence_rejects_journal_target_tamper(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)
        altered = copy.deepcopy(fixture["sourceEvidence"])
        journal_postcondition = next(
            item
            for item in altered["postconditionProjections"]
            if item["postconditionId"] == "vaultNotDowngraded"
        )
        journal = journal_postcondition["sourceProjection"]["localProjection"][
            "mutationJournal"
        ]
        production = self.plan["resourceInventory"][5]["resourceId"]
        for item in journal:
            item["targetUrl"] = (
                f"https://management.azure.com{production}/restart"
                "?api-version=2025-03-01"
            )
        journal_postcondition["sourceProjection"]["localProjection"][
            "journalSha256"
        ] = bootstrap.sha256_bytes(bootstrap.canonical_json_bytes(journal))
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.validate_terminal_source_evidence(
                plan=fixture["plan"],
                authorization=fixture["authorization"],
                preflight_projection=fixture["preflightProjection"],
                evidence=altered,
            )

    def test_terminal_source_rejects_journal_outside_execution_and_reversed_pair(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.terminal_fixture(folder)

        def mutate_all_journals(evidence, mutate):
            journals = [evidence["productionBoundary"]["mutationJournal"]]
            for postcondition in evidence["postconditionProjections"]:
                local = postcondition["sourceProjection"]["localProjection"]
                if isinstance(local, dict) and "mutationJournal" in local:
                    journals.append(local["mutationJournal"])
            for journal in journals:
                mutate(journal)
            for postcondition in evidence["postconditionProjections"]:
                local = postcondition["sourceProjection"]["localProjection"]
                if isinstance(local, dict) and "mutationJournal" in local:
                    local["journalSha256"] = bootstrap.sha256_bytes(
                        bootstrap.canonical_json_bytes(local["mutationJournal"])
                    )

        variants = []
        before_start = copy.deepcopy(fixture["sourceEvidence"])
        mutate_all_journals(
            before_start,
            lambda journal: journal[0].update(
                {"recordedAt": stamp(NOW - dt.timedelta(seconds=1))}
            ),
        )
        variants.append(before_start)

        after_complete = copy.deepcopy(fixture["sourceEvidence"])
        mutate_all_journals(
            after_complete,
            lambda journal: journal[1].update(
                {"recordedAt": stamp(NOW + dt.timedelta(minutes=8))}
            ),
        )
        variants.append(after_complete)

        reversed_pair = copy.deepcopy(fixture["sourceEvidence"])
        mutate_all_journals(
            reversed_pair,
            lambda journal: (
                journal[0].update(
                    {"recordedAt": stamp(NOW + dt.timedelta(seconds=2))}
                ),
                journal[1].update(
                    {"recordedAt": stamp(NOW + dt.timedelta(seconds=1))}
                ),
            ),
        )
        variants.append(reversed_pair)

        for altered in variants:
            with self.subTest(recorded=altered["productionBoundary"]["mutationJournal"]):
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_terminal_source_evidence(
                        plan=fixture["plan"],
                        authorization=fixture["authorization"],
                        preflight_projection=fixture["preflightProjection"],
                        evidence=altered,
                    )

    def test_preflight_rejects_sas_and_mutating_probe(self):
        self.assertFalse(bootstrap._preflight_url_allowed("GET", "https://mdspdbak2608089c4e.blob.core.windows.net/paperdesk-deployment-packages/x?sig=secret"))
        self.assertFalse(bootstrap._preflight_url_allowed("PUT", f"https://management.azure.com/subscriptions/{bootstrap.SUBSCRIPTION}/resourceGroups/x?api-version=2022-09-01"))

    def test_synthetic_inaccessible_statuses_are_operation_specific(self):
        base_projection = build_projection(self.plan, self.package)
        receipt = Path(
            "C:/fixture/"
            f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
        )
        base_authorization = build_authorization(
            self.plan,
            self.plan_sha,
            self.package,
            base_projection,
            receipt,
        )
        for status in (
            "network-inaccessible",
            "temporary-access-inaccessible",
        ):
            with self.subTest(status=status):
                projection = copy.deepcopy(base_projection)
                admission = next(
                    item
                    for item in projection["operationAdmissions"]
                    if item["operationId"] == "createPublisherApplication"
                )
                admission["status"] = status
                digest = bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes(projection)
                )
                authorization = copy.deepcopy(base_authorization)
                authorization["observedPreflight"]["sha256"] = digest
                preflight = {
                    "schemaVersion": 1,
                    "status": "observed-read-only",
                    "observedAt": authorization["observedPreflight"]["observedAt"],
                    "projection": projection,
                    "projectionSha256": digest,
                }
                with self.assertRaisesRegex(
                    bootstrap.BootstrapError, "outside .* boundary"
                ):
                    bootstrap.validate_preflight_evidence(
                        preflight, authorization, self.plan
                    )

    def test_graph_and_key_inventory_readbacks_reject_partial_or_malformed_pages(self):
        with tempfile.TemporaryDirectory() as folder:
            _auth, validated, preflight, _projection, _receipt = self.fixture(folder)
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=validated.document,
            plan=self.plan,
            package=self.package,
            preflight=preflight,
            session=object(),
        )

        def expected(operation_id):
            return next(
                item
                for item in preflight["projection"]["probes"]
                if item.get("validatorId") == f"operation:{operation_id}"
            )

        publisher_id = "11111111-1111-4111-8111-111111111111"
        assignment_id = "22222222-2222-4222-8222-222222222222"
        resource_id = "33333333-3333-4333-8333-333333333333"
        service = {
            "id": publisher_id,
            "appId": "44444444-4444-4444-8444-444444444444",
            "displayName": "paperdesk-release-publisher-v2-9c4e0d0d",
            "accountEnabled": True,
            "servicePrincipalType": "Application",
            "passwordCredentials": [],
            "keyCredentials": [],
            "appRoleAssignments": [
                {
                    "id": assignment_id,
                    "principalId": publisher_id,
                    "resourceId": resource_id,
                    "appRoleId": bootstrap.AzureCliBootstrapTransport.GRAPH_APPLICATION_READ_ALL,
                }
            ],
            "appRoleAssignments@odata.nextLink": (
                "https://graph.microsoft.com/v1.0/next"
            ),
        }
        graph_response = bootstrap._RestResponse(
            status=200,
            body=bootstrap.canonical_json_bytes({"value": [service]}),
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "assignment is not sole and exact"
        ):
            transport._validate_readback_response(
                expected("grantPublisherGraphApplicationReadAll"),
                graph_response,
                {
                    "assignmentId": assignment_id,
                    "resourceId": resource_id,
                },
            )

        kid = (
            "https://kv-mds-sea-9c4e0d0d.vault.azure.net/keys/"
            "paperdesk-release-result-signing/" + "c" * 32
        )
        attributes = {
            "enabled": True,
            "nbf": int(NOW.timestamp()),
            "exp": int((NOW + dt.timedelta(days=60)).timestamp()),
            "created": int(NOW.timestamp()),
            "updated": int((NOW + dt.timedelta(seconds=1)).timestamp()),
            "recoveryLevel": "Recoverable+Purgeable",
            "recoverableDays": 90,
            "exportable": False,
        }
        modulus = base64.urlsafe_b64encode(
            b"\x80" + b"\x00" * 383
        ).decode().rstrip("=")
        facts = {
            "kid": kid,
            "kty": "RSA",
            "n": modulus,
            "e": "AQAB",
            "key_ops": ["sign", "verify"],
            "attributes": attributes,
        }
        transport._validated_source_projections["createSigningKeyVersion"] = {
            "projection": {
                "keyUriWithVersion": kid,
                "expiresAt": attributes["exp"],
            }
        }

        def key_response(values, next_link=None):
            return bootstrap._RestResponse(
                status=200,
                body=bootstrap.canonical_json_bytes(
                    {"value": values, "nextLink": next_link}
                ),
                headers={"Content-Type": "application/json"},
            )

        valid_version = {"kid": kid, "attributes": attributes}
        transport._validate_readback_response(
            expected("readBackExactSigningPublicJwk"),
            key_response([valid_version]),
            facts,
        )
        variants = (
            key_response(
                [valid_version],
                "https://kv-mds-sea-9c4e0d0d.vault.azure.net/next",
            ),
            key_response([valid_version, copy.deepcopy(valid_version)]),
            key_response([valid_version, "junk"]),
        )
        for response in variants:
            with self.subTest(body=response.body):
                with self.assertRaises(bootstrap.BootstrapError):
                    transport._validate_readback_response(
                        expected("readBackExactSigningPublicJwk"),
                        response,
                        facts,
                    )

    def test_terminal_secret_scan_rejects_percent_encoded_sas_and_jose(self):
        values = [
            "https://example.invalid/blob?%73ig=capability",
            "https://example.invalid/blob?%53%49%47=capability",
            "https://example.invalid/blob?foo=1&%73v=1&%73ig=capability",
            "https://example.invalid/x?value=eyJhbGciOiJIUzI1NiJ9%2EeyJzdWIiOiIxMjM0NTY3ODkwIn0%2Ec2lnbmF0dXJl",
        ]
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap._reject_terminal_secret_material({"value": value})

    def test_role_scopes_cover_declared_operations_and_key_audit_uses_vault(self):
        transport = object.__new__(bootstrap.AzureCliBootstrapTransport)
        transport.resources = {item["id"]: item for item in self.plan["resourceInventory"]}
        for role in self.plan["roleMatrix"]:
            scope = transport._resource_scope(role["scope"])
            self.assertTrue(scope.startswith(f"/subscriptions/{bootstrap.SUBSCRIPTION}"))
        key_audit = next(item for item in self.plan["roleMatrix"] if item["name"] == "publisherKeyPostureAudit")
        self.assertEqual(key_audit["scope"], "signingVault")
        self.assertIn("Microsoft.KeyVault/vaults/read", key_audit["actions"])

    def test_bootstrap_has_no_pre_s2_production_mutation(self):
        text = bootstrap.canonical_json_bytes(self.plan).decode()
        self.assertNotIn("setProductionRouteAll", text)
        production_mutations = [
            item for item in self.plan["mutations"] if item.get("target") == "productionSite"
        ]
        self.assertEqual(production_mutations, [])
        post = next(item for item in self.plan["postconditions"] if item["id"] == "productionRoutingObservedNotMutated")
        self.assertIn("allTraffic false", post["predicate"])


if __name__ == "__main__":
    unittest.main()
