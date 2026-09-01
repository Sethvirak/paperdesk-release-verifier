from __future__ import annotations

import base64
import copy
import datetime as dt
import tempfile
import unittest
import urllib.parse
from pathlib import Path

from scripts import private_release_v2_bootstrap as bootstrap


AUTHORIZATION_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
OPERATOR_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
SOURCE_SHA = "2" * 40
TREE_SHA = "3" * 40
OBSERVED_AT = dt.datetime(2026, 8, 30, 4, 0, tzinfo=dt.timezone.utc)
CANONICAL_GRAPH_ASSIGNMENT_ID = (
    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
)
OTHER_CANONICAL_GRAPH_ASSIGNMENT_ID = (
    "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"
)


def stamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


class BootstrapSemanticRegressionTests(unittest.TestCase):
    """Fail-closed source-evidence tests, separate from executor happy paths."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan, cls.plan_sha = bootstrap.load_plan()
        cls.resources = {item["id"]: item for item in cls.plan["resourceInventory"]}
        cls.operations = {item["id"]: item for item in cls.plan["mutations"]}
        cls.authorization = {
            "authorizationId": AUTHORIZATION_ID,
            "source": {
                "mergedMain": {"commitSha": SOURCE_SHA, "treeSha": TREE_SHA},
            },
            "plan": {
                "path": "contracts/private_release_bootstrap_plan.json",
                "sha256": cls.plan_sha,
                "bridgePackageSourceSha": SOURCE_SHA,
                "bridgePackageSha256": "4" * 64,
                "bridgePackageSize": 4096,
            },
            "azure": {
                "tenantId": bootstrap.TENANT,
                "accountObjectId": OPERATOR_ID,
                "accountType": "user",
            },
            "validity": {
                "notBefore": stamp(OBSERVED_AT - dt.timedelta(minutes=2)),
                "expiresAt": stamp(OBSERVED_AT + dt.timedelta(minutes=20)),
            },
            "singleUse": {
                "azureClaimResourceId": (
                    f"/subscriptions/{bootstrap.SUBSCRIPTION}/providers/"
                    f"Microsoft.Resources/deployments/paperdesk-v2-bootstrap-{AUTHORIZATION_ID}"
                )
            },
        }

    def envelope(self, operation_id: str, body, *, headers=None):
        contract = bootstrap._validator_contract(
            f"operation:{operation_id}", self.plan, self.authorization
        )
        operation = self.operations[operation_id]
        return {
            "schemaVersion": 1,
            "operationId": operation_id,
            "family": bootstrap._operation_projection_family(operation_id),
            "method": contract["expectedMethod"],
            "url": contract["expectedUrl"],
            "status": contract["expectedStatus"],
            "target": operation["target"],
            "targetResourceId": contract.get("targetResourceId"),
            "responseSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(body)
            ),
            "headers": dict(headers or {}),
            "projection": copy.deepcopy(body),
        }

    def validate(
        self,
        operation_id: str,
        projection,
        *,
        prior=None,
        operation_context=None,
        runtime_facts=None,
    ):
        return bootstrap._validate_operation_source_projection(
            projection,
            operation_id=operation_id,
            plan=self.plan,
            authorization=self.authorization,
            prior=prior or {},
            operation_context=operation_context or {},
            runtime_facts=runtime_facts or {},
        )

    def test_bridge_posture_rejects_public_or_running_site(self):
        operation_id = "createStoppedPrivateBridge"
        contract = bootstrap._validator_contract(
            f"operation:{operation_id}", self.plan, self.authorization
        )
        body = {
            "id": contract["targetResourceId"],
            "name": contract["targetName"],
            "kind": "app,linux",
            "httpsOnly": True,
            "state": "Stopped",
            "publicNetworkAccess": "Disabled",
            "serverFarmId": self.resources["bridgeAppServicePlan"]["resourceId"],
            "virtualNetworkSubnetId": self.resources["integrationSubnet"]["resourceId"],
            "outboundVnetRouting": {"allTraffic": True, "applicationTraffic": True},
            "identity": {"type": "None", "userAssignedIdentities": {}},
        }
        valid = self.envelope(operation_id, body)
        self.assertEqual(self.validate(operation_id, valid), valid)
        for field, unsafe in (
            ("publicNetworkAccess", "Enabled"),
            ("state", "Running"),
            ("httpsOnly", False),
        ):
            with self.subTest(field=field):
                altered = copy.deepcopy(valid)
                altered["projection"][field] = unsafe
                with self.assertRaises(bootstrap.BootstrapError):
                    self.validate(operation_id, altered)

    def test_bridge_posture_accepts_known_rp_enrichment_and_null_identity(self):
        operation_id = "createStoppedPrivateBridge"
        contract = bootstrap._validator_contract(
            f"operation:{operation_id}", self.plan, self.authorization
        )
        body = {
            "id": contract["targetResourceId"],
            "name": contract["targetName"],
            "kind": "app,linux",
            "httpsOnly": True,
            "state": "Stopped",
            "publicNetworkAccess": "Disabled",
            "serverFarmId": self.resources["bridgeAppServicePlan"]["resourceId"],
            "virtualNetworkSubnetId": self.resources["integrationSubnet"][
                "resourceId"
            ],
            "outboundVnetRouting": {
                "allTraffic": True,
                "applicationTraffic": True,
                "backupRestoreTraffic": True,
                "contentShareTraffic": True,
                "imagePullTraffic": True,
                "managedIdentityTraffic": True,
            },
            "identity": None,
        }
        valid = self.envelope(operation_id, body)
        self.assertEqual(self.validate(operation_id, valid), valid)

    def test_bridge_posture_rejects_unsafe_rp_enrichment_or_identity(self):
        operation_id = "createStoppedPrivateBridge"
        contract = bootstrap._validator_contract(
            f"operation:{operation_id}", self.plan, self.authorization
        )
        body = {
            "id": contract["targetResourceId"],
            "name": contract["targetName"],
            "kind": "app,linux",
            "httpsOnly": True,
            "state": "Stopped",
            "publicNetworkAccess": "Disabled",
            "serverFarmId": self.resources["bridgeAppServicePlan"]["resourceId"],
            "virtualNetworkSubnetId": self.resources["integrationSubnet"][
                "resourceId"
            ],
            "outboundVnetRouting": {
                "allTraffic": True,
                "applicationTraffic": True,
                "contentShareTraffic": True,
            },
            "identity": None,
        }
        variants = []

        false_extra = copy.deepcopy(body)
        false_extra["outboundVnetRouting"]["contentShareTraffic"] = False
        variants.append(("false-extra", false_extra))

        wrong_type = copy.deepcopy(body)
        wrong_type["outboundVnetRouting"]["contentShareTraffic"] = "true"
        variants.append(("wrong-type", wrong_type))

        unknown_extra = copy.deepcopy(body)
        unknown_extra["outboundVnetRouting"]["futureTraffic"] = True
        variants.append(("unknown-extra", unknown_extra))

        system_identity = copy.deepcopy(body)
        system_identity["identity"] = {
            "type": "SystemAssigned",
            "principalId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            "tenantId": bootstrap.TENANT,
        }
        variants.append(("system-identity", system_identity))

        user_identity = copy.deepcopy(body)
        user_identity["identity"] = {
            "type": "UserAssigned",
            "userAssignedIdentities": {
                self.resources["bridgeIdentity"]["resourceId"]: {}
            },
        }
        variants.append(("user-identity", user_identity))

        for variant, altered in variants:
            with self.subTest(variant=variant), self.assertRaises(
                bootstrap.BootstrapError
            ):
                self.validate(operation_id, self.envelope(operation_id, altered))

    def test_live_bridge_readback_projects_properties_https_and_rp_enrichment(self):
        operation_id = "createStoppedPrivateBridge"
        contract = bootstrap._validator_contract(
            f"operation:{operation_id}", self.plan, self.authorization
        )
        outbound = {
            "allTraffic": True,
            "applicationTraffic": True,
            "backupRestoreTraffic": True,
            "contentShareTraffic": True,
            "imagePullTraffic": True,
            "managedIdentityTraffic": True,
        }
        document = {
            "id": contract["targetResourceId"],
            "name": contract["targetName"],
            "type": "Microsoft.Web/sites",
            "kind": "app,linux",
            "identity": None,
            "properties": {
                "httpsOnly": True,
                "state": "Stopped",
                "publicNetworkAccess": "Disabled",
                "serverFarmId": self.resources["bridgeAppServicePlan"][
                    "resourceId"
                ],
                "virtualNetworkSubnetId": self.resources["integrationSubnet"][
                    "resourceId"
                ],
                "outboundVnetRouting": outbound,
            },
        }
        response = bootstrap._RestResponse(
            status=200,
            body=bootstrap.canonical_json_bytes(document),
            headers={
                "Content-Type": "application/json",
                "ETag": '\"bridge-etag\"',
            },
        )
        expected = {
            "id": "readback-create-stopped-private-bridge",
            "validatorId": f"operation:{operation_id}",
            "method": contract["expectedMethod"],
            "url": contract["expectedUrl"],
            "validatorContract": contract,
        }
        transport = object.__new__(bootstrap.AzureCliBootstrapTransport)
        transport.plan = self.plan
        transport.authorization = self.authorization
        transport.resources = self.resources
        transport.admissions = {operation_id: {"context": {}}}
        transport._validated_source_projections = {}
        transport._package_readback_bytes = None

        validated = transport._validate_readback_response(expected, response, {})
        projection = validated["sourceProjection"]["projection"]
        self.assertIs(projection["httpsOnly"], True)
        self.assertEqual(projection["outboundVnetRouting"], outbound)
        self.assertIsNone(projection["identity"])

    def test_all_private_container_terminal_projections_use_arm_leaf_name_and_exact_shape(self):
        operation_ids = (
            "createPrivatePackageContainer",
            "createPrivateControllerLockContainer",
            "createPrivateActivationFenceContainer",
        )
        for operation_id in operation_ids:
            operation = self.operations[operation_id]
            resource = self.resources[operation["target"]]
            body = {
                "id": resource["resourceId"],
                "name": resource["name"],
                "type": "Microsoft.Storage/storageAccounts/blobServices/containers",
                "publicAccess": "None",
            }
            valid = self.envelope(operation_id, body)
            with self.subTest(operation_id=operation_id, variant="exact"):
                self.assertEqual(self.validate(operation_id, valid), valid)

            variants = []
            wrong_id = copy.deepcopy(valid)
            wrong_id["projection"]["id"] = self.resources["storageAccount"][
                "resourceId"
            ]
            variants.append(("id", wrong_id))
            wrong_name = copy.deepcopy(valid)
            wrong_name["projection"]["name"] = f"default/{resource['name']}"
            variants.append(("name", wrong_name))
            wrong_type = copy.deepcopy(valid)
            wrong_type["projection"]["type"] = "Microsoft.Storage/storageAccounts"
            variants.append(("type", wrong_type))
            public = copy.deepcopy(valid)
            public["projection"]["publicAccess"] = "Container"
            variants.append(("publicAccess", public))
            missing = copy.deepcopy(valid)
            missing["projection"].pop("publicAccess")
            variants.append(("missing", missing))
            extra = copy.deepcopy(valid)
            extra["projection"]["unexpected"] = True
            variants.append(("extra", extra))

            for variant, altered in variants:
                with self.subTest(operation_id=operation_id, variant=variant), self.assertRaises(
                    bootstrap.BootstrapError
                ):
                    self.validate(operation_id, altered)

    def _identity_priors(self):
        values = {
            "createPublisherApplication": {
                "projection": {
                    "id": "10000000-0000-4000-8000-000000000001",
                    "appId": "10000000-0000-4000-8000-000000000002",
                }
            },
            "createPublisherServicePrincipal": {
                "projection": {
                    "id": "10000000-0000-4000-8000-000000000003",
                    "appId": "10000000-0000-4000-8000-000000000002",
                }
            },
            "createBridgeIdentity": {
                "projection": {
                    "id": self.resources["bridgeIdentity"]["resourceId"],
                    "clientId": "10000000-0000-4000-8000-000000000004",
                    "principalId": "10000000-0000-4000-8000-000000000005",
                }
            },
            "createSignerIdentity": {
                "projection": {
                    "id": self.resources["signerIdentity"]["resourceId"],
                    "clientId": "10000000-0000-4000-8000-000000000006",
                    "principalId": "10000000-0000-4000-8000-000000000007",
                }
            },
            "createProductionActivationIdentity": {
                "projection": {
                    "id": self.resources["productionActivationIdentity"]["resourceId"],
                    "clientId": "10000000-0000-4000-8000-000000000008",
                    "principalId": "10000000-0000-4000-8000-000000000009",
                }
            },
        }
        return values

    def test_publisher_graph_terminal_projection_is_cross_bound_to_exact_assignment(self):
        operation_id = "grantPublisherGraphApplicationReadAll"
        publisher_id = "10000000-0000-4000-8000-000000000003"
        publisher_app_id = "10000000-0000-4000-8000-000000000002"
        assignment_id = CANONICAL_GRAPH_ASSIGNMENT_ID
        graph_resource_id = "10000000-0000-4000-8000-000000000011"
        service = {
            "id": publisher_id,
            "appId": publisher_app_id,
            "displayName": self.resources["publisherServicePrincipal"]["name"],
            "accountEnabled": True,
            "servicePrincipalType": "Application",
            "passwordCredentials": [],
            "keyCredentials": [],
            "appRoleAssignments": [],
        }
        assignment = {
            "id": assignment_id,
            "principalId": publisher_id,
            "resourceId": graph_resource_id,
            "appRoleId": bootstrap.AzureCliBootstrapTransport.GRAPH_APPLICATION_READ_ALL,
        }
        granted = copy.deepcopy(service)
        granted["appRoleAssignments"] = [assignment]
        prior = {"createPublisherServicePrincipal": {"projection": service}}
        runtime_facts = {
            "assignmentId": assignment_id,
            "resourceId": graph_resource_id,
        }
        valid = self.envelope(operation_id, granted)
        self.assertEqual(
            self.validate(
                operation_id,
                valid,
                prior=prior,
                operation_context={"executionDecision": "apply-exact"},
                runtime_facts=runtime_facts,
            ),
            valid,
        )

        adopted_prior = copy.deepcopy(prior)
        adopted_prior["createPublisherServicePrincipal"]["projection"][
            "appRoleAssignments"
        ] = [copy.deepcopy(assignment)]
        adopted_context = {
            "executionDecision": "adopt-exact",
            "adopted": copy.deepcopy(runtime_facts),
        }
        self.assertEqual(
            self.validate(
                operation_id,
                valid,
                prior=adopted_prior,
                operation_context=adopted_context,
            ),
            valid,
        )

        nonempty_prior = copy.deepcopy(prior)
        nonempty_prior["createPublisherServicePrincipal"]["projection"][
            "appRoleAssignments"
        ] = [copy.deepcopy(assignment)]
        with self.assertRaisesRegex(
            bootstrap.BootstrapError,
            "publisher Graph permission is not Application.Read.All",
        ):
            self.validate(
                operation_id,
                valid,
                prior=nonempty_prior,
                operation_context={"executionDecision": "apply-exact"},
                runtime_facts=runtime_facts,
            )

        variants = []
        wrong_publisher = copy.deepcopy(valid)
        wrong_publisher["projection"]["id"] = (
            "10000000-0000-4000-8000-000000000012"
        )
        variants.append(("publisher", wrong_publisher, runtime_facts))
        wrong_assignment_id = copy.deepcopy(valid)
        wrong_assignment_id["projection"]["appRoleAssignments"][0]["id"] = (
            OTHER_CANONICAL_GRAPH_ASSIGNMENT_ID
        )
        variants.append(("assignment-id", wrong_assignment_id, runtime_facts))
        wrong_principal = copy.deepcopy(valid)
        wrong_principal["projection"]["appRoleAssignments"][0]["principalId"] = (
            "10000000-0000-4000-8000-000000000014"
        )
        variants.append(("principal", wrong_principal, runtime_facts))
        wrong_resource = copy.deepcopy(valid)
        wrong_resource["projection"]["appRoleAssignments"][0]["resourceId"] = (
            "10000000-0000-4000-8000-000000000015"
        )
        variants.append(("resource", wrong_resource, runtime_facts))
        wrong_role = copy.deepcopy(valid)
        wrong_role["projection"]["appRoleAssignments"][0]["appRoleId"] = (
            "10000000-0000-4000-8000-000000000016"
        )
        variants.append(("role", wrong_role, runtime_facts))
        duplicate = copy.deepcopy(valid)
        duplicate["projection"]["appRoleAssignments"].append(
            copy.deepcopy(assignment)
        )
        variants.append(("duplicate", duplicate, runtime_facts))

        for variant, altered, facts in variants:
            with self.subTest(variant=variant), self.assertRaises(
                bootstrap.BootstrapError
            ):
                self.validate(
                    operation_id,
                    altered,
                    prior=prior,
                    operation_context={"executionDecision": "apply-exact"},
                    runtime_facts=facts,
                )

    def test_role_assignment_inventory_rejects_one_altered_scope(self):
        operation_id = "createExactRoleAssignments"
        prior = self._identity_priors()

        def principal_id(name: str) -> str:
            fixed = self.resources.get(name, {}).get("principalId")
            if isinstance(fixed, str):
                return fixed
            dependency = {
                "publisherServicePrincipal": "createPublisherServicePrincipal",
                "bridgeIdentity": "createBridgeIdentity",
                "signerIdentity": "createSignerIdentity",
                "productionActivationIdentity": "createProductionActivationIdentity",
            }[name]
            body = prior[dependency]["projection"]
            return body["id"] if name == "publisherServicePrincipal" else body["principalId"]

        assignments = sorted(
            (
                bootstrap._role_assignment_spec(
                    self.plan, role, principal_id(role["principal"])
                )
                for role in self.plan["roleMatrix"]
            ),
            key=lambda item: str(item["id"]).lower(),
        )
        valid = self.envelope(operation_id, {"roleAssignments": assignments})
        self.assertEqual(self.validate(operation_id, valid, prior=prior), valid)
        altered = copy.deepcopy(valid)
        altered["projection"]["roleAssignments"][0]["properties"]["scope"] = (
            self.resources["productionSite"]["resourceId"]
        )
        with self.assertRaises(bootstrap.BootstrapError):
            self.validate(operation_id, altered, prior=prior)

    def test_public_jwk_rejects_wrong_key_or_undersized_modulus(self):
        operation_id = "readBackExactSigningPublicJwk"
        key_uri = (
            "https://kv-mds-sea-9c4e0d0d.vault.azure.net/keys/"
            "paperdesk-release-result-signing/" + "c" * 32
        )
        modulus = base64.urlsafe_b64encode(b"\x80" + b"\x00" * 383).decode().rstrip("=")
        key_expiry = int((OBSERVED_AT + dt.timedelta(days=31)).timestamp())
        body = {
            "kid": key_uri,
            "kty": "RSA",
            "n": modulus,
            "e": "AQAB",
            "key_ops": ["sign", "verify"],
            "attributes": {
                "enabled": True,
                "nbf": int(OBSERVED_AT.timestamp()),
                "exp": key_expiry,
                "created": int(OBSERVED_AT.timestamp()),
                "updated": int((OBSERVED_AT + dt.timedelta(seconds=1)).timestamp()),
                "recoveryLevel": "Recoverable+Purgeable",
                "recoverableDays": 90,
                "exportable": False,
            },
        }
        prior = {
            "createSigningKeyVersion": {
                "projection": {
                    "keyUriWithVersion": key_uri,
                    "expiresAt": key_expiry,
                }
            }
        }
        valid = self.envelope(operation_id, body)
        self.assertEqual(self.validate(operation_id, valid, prior=prior), valid)
        variants = []
        wrong_key = copy.deepcopy(valid)
        wrong_key["projection"]["kid"] = key_uri[:-1] + "d"
        variants.append(wrong_key)
        undersized = copy.deepcopy(valid)
        undersized["projection"]["n"] = base64.urlsafe_b64encode(
            b"\x80" + b"\x00" * 255
        ).decode().rstrip("=")
        variants.append(undersized)
        for altered in variants:
            with self.subTest(kid=altered["projection"]["kid"], n=len(altered["projection"]["n"])):
                with self.assertRaises(bootstrap.BootstrapError):
                    self.validate(operation_id, altered, prior=prior)

    def _temporary_key_role_body(self):
        temporary = self.plan["temporaryAccess"]
        definition_id = temporary["temporaryKeyReadRoleDefinitionId"]
        assignment_id = temporary["temporaryKeyReadRoleAssignmentId"]
        scope = self.resources["signingKey"]["resourceId"]
        definition_resource = (
            f"/subscriptions/{bootstrap.SUBSCRIPTION}/providers/"
            f"Microsoft.Authorization/roleDefinitions/{definition_id}"
        )
        assignment_resource = (
            f"{scope}/providers/Microsoft.Authorization/roleAssignments/{assignment_id}"
        )
        return {
            "definitionResourceId": definition_resource,
            "assignmentResourceId": assignment_resource,
            "definitionCreated": True,
            "assignmentCreated": True,
            "cleanupKey": "operator-key-read-role",
            "definition": {
                "id": definition_resource,
                "name": definition_id,
                "type": "Microsoft.Authorization/roleDefinitions",
                "properties": {
                    "roleName": "PaperDesk V2 temporary operator-key-read-role",
                    "description": "Single-use bootstrap temporary role; exact cleanup required",
                    "type": "CustomRole",
                    "permissions": [
                        {
                            "actions": [],
                            "notActions": [],
                            "dataActions": temporary["temporaryKeyReadDataActions"],
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
                    "principalId": OPERATOR_ID,
                    "principalType": "User",
                    "roleDefinitionId": definition_resource,
                    "scope": scope,
                    "condition": None,
                    "conditionVersion": None,
                    "delegatedManagedIdentityResourceId": None,
                },
            },
        }

    def test_temporary_role_rejects_added_permission_or_altered_principal(self):
        operation_id = "addOwnedOperatorKeyReadRole"
        valid = self.envelope(operation_id, self._temporary_key_role_body())
        self.assertEqual(self.validate(operation_id, valid), valid)
        added_action = copy.deepcopy(valid)
        added_action["projection"]["definition"]["properties"]["permissions"][0][
            "dataActions"
        ].append("Microsoft.KeyVault/vaults/keys/sign/action")
        altered_principal = copy.deepcopy(valid)
        altered_principal["projection"]["assignment"]["properties"]["principalId"] = (
            "10000000-0000-4000-8000-000000000099"
        )
        for altered in (added_action, altered_principal):
            with self.assertRaises(bootstrap.BootstrapError):
                self.validate(operation_id, altered)

    def test_versioned_blob_requires_both_etag_and_version_id(self):
        operation_id = "createInitialIdleActivationFence"
        contract = bootstrap._validator_contract(
            f"operation:{operation_id}", self.plan, self.authorization
        )
        body = {
            "url": contract["expectedUrl"],
            "etag": '"fence-etag"',
            "versionId": "2026-08-30T04:00:00.0000000Z",
            "sha256": contract["expectedBodySha256"],
            "bodySha256": contract["expectedBodySha256"],
            "bodySize": contract["expectedBodySize"],
        }
        valid = self.envelope(
            operation_id,
            body,
            headers={
                "etag": body["etag"],
                "versionId": body["versionId"],
                "leaseState": "Available",
                "leaseStatus": "Unlocked",
            },
        )
        self.assertEqual(self.validate(operation_id, valid), valid)
        for location, field in (
            ("projection", "etag"),
            ("projection", "versionId"),
            ("headers", "etag"),
            ("headers", "versionId"),
        ):
            with self.subTest(location=location, field=field):
                altered = copy.deepcopy(valid)
                del altered[location][field]
                with self.assertRaises(bootstrap.BootstrapError):
                    self.validate(operation_id, altered)

    def _app_settings_priors(self):
        fence_contract = bootstrap._validator_contract(
            "operation:createInitialIdleActivationFence", self.plan, self.authorization
        )
        package_url = bootstrap._validator_contract(
            "operation:uploadVersionedBridgePackage", self.plan, self.authorization
        )["expectedUrl"]
        return {
            "createBridgeIdentity": {
                "projection": {
                    "id": self.resources["bridgeIdentity"]["resourceId"],
                    "clientId": "10000000-0000-4000-8000-000000000004",
                    "principalId": "10000000-0000-4000-8000-000000000005",
                }
            },
            "createInitialIdleActivationFence": {
                "projection": {
                    "etag": '"fence-etag"',
                    "versionId": "2026-08-30T04:00:00.0000000Z",
                    "sha256": fence_contract["expectedBodySha256"],
                }
            },
            "uploadVersionedBridgePackage": {
                "projection": {
                    "url": package_url,
                    "versionId": "2026-08-30T04:00:00.0000000Z",
                }
            },
        }

    def test_app_settings_digest_rejects_false_binding(self):
        operation_id = "configureBridgeExactVersionedPackageAndCriticalSettings"
        prior = self._app_settings_priors()
        pre_settings = {"KEEP_ME": "unchanged"}
        context = {
            "preAppSettings": pre_settings,
            "preAppSettingsSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(pre_settings)
            ),
        }
        control = bootstrap._bootstrap_self_test_control_from_projections(
            self.authorization, prior
        )
        upload = prior["uploadVersionedBridgePackage"]["projection"]
        package_url = upload["url"] + "?versionid=" + urllib.parse.quote(
            upload["versionId"], safe=""
        )
        desired = dict(pre_settings)
        desired.update(
            {
                "WEBSITE_RUN_FROM_PACKAGE": package_url,
                "WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID": self.resources[
                    "registryReaderIdentity"
                ]["resourceId"],
                "WEBSITE_SKIP_RUNNING_KUDUAGENT": "false",
                "PAPERDESK_BRIDGE_PACKAGE_SHA256": self.authorization["plan"][
                    "bridgePackageSha256"
                ],
                "PAPERDESK_BRIDGE_BOOTSTRAP_SELF_TEST_JSON": bootstrap.canonical_json_bytes(
                    control
                ).decode("utf-8"),
            }
        )
        body = {
            "preAppSettingsSha256": context["preAppSettingsSha256"],
            "settingsSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(desired)
            ),
            "bootstrapSelfTestControlSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(control)
            ),
            "packageUrl": package_url,
            "packageVersionId": upload["versionId"],
        }
        valid = self.envelope(operation_id, body)
        self.assertEqual(
            self.validate(operation_id, valid, prior=prior, operation_context=context),
            valid,
        )
        for field in (
            "preAppSettingsSha256",
            "settingsSha256",
            "bootstrapSelfTestControlSha256",
        ):
            with self.subTest(field=field):
                altered = copy.deepcopy(valid)
                altered["projection"][field] = "f" * 64
                with self.assertRaises(bootstrap.BootstrapError):
                    self.validate(
                        operation_id,
                        altered,
                        prior=prior,
                        operation_context=context,
                    )

    def test_worm_policy_rejects_target_type_or_etag_drift(self):
        operation_id = "lockPackageRetentionAt91Days"
        target_id = self.resources[self.operations[operation_id]["target"]]["resourceId"]
        body = {
            "id": target_id + "/immutabilityPolicies/default",
            "name": "default",
            "type": (
                "Microsoft.Storage/storageAccounts/blobServices/containers/"
                "immutabilityPolicies"
            ),
            "etag": '"worm-etag"',
            "properties": {
                "state": "Locked",
                "immutabilityPeriodSinceCreationInDays": 91,
                "allowProtectedAppendWrites": False,
                "allowProtectedAppendWritesAll": False,
            },
            "stateAfterPut": "Locked",
            "lockPostIssued": False,
        }
        valid = self.envelope(operation_id, body)
        self.assertEqual(self.validate(operation_id, valid), valid)
        stricter = copy.deepcopy(valid)
        stricter["projection"]["properties"][
            "immutabilityPeriodSinceCreationInDays"
        ] = 120
        self.assertEqual(self.validate(operation_id, stricter), stricter)
        variants = []
        wrong_target = copy.deepcopy(valid)
        wrong_target["projection"]["id"] = (
            self.resources["resultContainer"]["resourceId"]
            + "/immutabilityPolicies/default"
        )
        variants.append(wrong_target)
        wrong_type = copy.deepcopy(valid)
        wrong_type["projection"]["type"] = "Microsoft.Storage/storageAccounts"
        variants.append(wrong_type)
        bad_etag = copy.deepcopy(valid)
        bad_etag["projection"]["etag"] = "unquoted"
        variants.append(bad_etag)
        for altered in variants:
            with self.assertRaises(bootstrap.BootstrapError):
                self.validate(operation_id, altered)

    def test_deleted_worm_tombstone_is_never_terminal_success(self):
        operation_id = "lockPackageRetentionAt91Days"
        target_id = self.resources[self.operations[operation_id]["target"]]["resourceId"]
        tombstone = self.envelope(
            operation_id,
            {
                "id": target_id + "/immutabilityPolicies/default",
                "name": "default",
                "type": (
                    "Microsoft.Storage/storageAccounts/blobServices/containers/"
                    "immutabilityPolicies"
                ),
                "etag": "",
                "properties": {
                    "state": "Deleted",
                    "immutabilityPeriodSinceCreationInDays": 0,
                    "allowProtectedAppendWrites": False,
                    "allowProtectedAppendWritesAll": False,
                },
                "stateAfterPut": "Locked",
                "lockPostIssued": False,
            },
        )

        with self.assertRaises(bootstrap.BootstrapError):
            self.validate(operation_id, tombstone)

    def test_deleted_worm_tombstone_is_never_successful_executor_readback(self):
        operation_id = "lockPackageRetentionAt91Days"
        contract = bootstrap._validator_contract(
            f"operation:{operation_id}", self.plan, self.authorization
        )
        expected = {
            "id": "readback-package-worm",
            "validatorId": f"operation:{operation_id}",
            "method": contract["expectedMethod"],
            "url": contract["expectedUrl"],
            "validatorContract": contract,
        }
        response = bootstrap._RestResponse(
            status=200,
            body=bootstrap.canonical_json_bytes(
                {
                    "id": (
                        self.resources["packageContainer"]["resourceId"]
                        + "/immutabilityPolicies/default"
                    ),
                    "name": "default",
                    "type": (
                        "Microsoft.Storage/storageAccounts/blobServices/containers/"
                        "immutabilityPolicies"
                    ),
                    "etag": "",
                    "properties": {
                        "state": "Deleted",
                        "immutabilityPeriodSinceCreationInDays": 0,
                    },
                }
            ),
            headers={"Content-Type": "application/json"},
        )
        transport = object.__new__(bootstrap.AzureCliBootstrapTransport)
        transport.plan = self.plan
        transport.authorization = self.authorization
        transport.resources = self.resources

        with self.assertRaisesRegex(
            bootstrap.BootstrapError,
            "WORM policy readback is not Locked for at least 91 days",
        ):
            transport._validate_readback_response(
                expected,
                response,
                {
                    "stateAfterPut": "Locked",
                    "lockPostIssued": False,
                },
            )

    def test_absent_package_worm_execution_keeps_create_only_if_none_match(self):
        operation_id = "lockPackageRetentionAt91Days"
        operation = self.operations[operation_id]
        transport = object.__new__(bootstrap.AzureCliBootstrapTransport)
        transport.authorization = copy.deepcopy(self.authorization)
        transport.plan = self.plan
        transport.resources = self.resources
        transport.admissions = {
            operation_id: {
                "context": {
                    "executionDecision": "apply-exact",
                    "etag": None,
                }
            }
        }
        calls = []

        def arm_put(resource_id, api_version, body, *, headers=None, expected=None):
            calls.append(
                {
                    "resourceId": resource_id,
                    "apiVersion": api_version,
                    "body": copy.deepcopy(body),
                    "headers": copy.deepcopy(headers),
                    "expected": copy.deepcopy(expected),
                }
            )
            return {
                "properties": {
                    "state": "Locked",
                    "immutabilityPeriodSinceCreationInDays": 91,
                    "allowProtectedAppendWrites": False,
                    "allowProtectedAppendWritesAll": False,
                }
            }

        transport._arm_put = arm_put
        result = transport._mutate(operation, {})

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["headers"], {"If-None-Match": "*"})
        self.assertEqual(
            calls[0]["body"],
            {
                "properties": {
                    "immutabilityPeriodSinceCreationInDays": 91,
                    "allowProtectedAppendWrites": False,
                    "allowProtectedAppendWritesAll": False,
                }
            },
        )
        self.assertEqual(result["stateAfterPut"], "Locked")
        self.assertFalse(result["lockPostIssued"])

    def test_signing_key_posture_rejects_stale_expiry_even_if_context_matches(self):
        operation_id = "createSigningKeyVersion"
        stale = OBSERVED_AT - dt.timedelta(days=1)
        body = {
            "keyUriWithVersion": (
                "https://kv-mds-sea-9c4e0d0d.vault.azure.net/keys/"
                "paperdesk-release-result-signing/" + "c" * 32
            ),
            "kty": "RSA",
            "keySize": 3072,
            "keyOps": ["sign", "verify"],
            "enabled": True,
            "exportable": False,
            "expiresAt": int(stale.timestamp()),
            "releasePolicy": None,
        }
        altered = self.envelope(operation_id, body)
        with self.assertRaises(bootstrap.BootstrapError):
            self.validate(
                operation_id,
                altered,
                operation_context={"expiresAt": stamp(stale)},
            )

    def _valid_sanitized_journal(self):
        resource_id = self.authorization["singleUse"]["azureClaimResourceId"]
        url = f"https://management.azure.com{resource_id}?api-version=2022-09-01"
        intent = {
            "sequence": 1,
            "phase": "intent",
            "intentId": "cloud-mutation-0001",
            "operationId": "claimAzureSingleUseAuthorization",
            "temporary": False,
            "method": "PUT",
            "targetUrl": url,
            "requestBodySha256": "5" * 64,
            "status": None,
            "responseBodySha256": None,
            "etag": None,
            "versionId": None,
            "recordedAt": stamp(OBSERVED_AT),
        }
        result = copy.deepcopy(intent)
        result.update(
            {
                "sequence": 2,
                "phase": "result",
                "status": 201,
                "responseBodySha256": "6" * 64,
            }
        )
        return [intent, result]

    def _complete_terminal_journal_inputs(self):
        # Import lazily so this regression module remains independently
        # runnable while consuming the one deterministic whole-evidence
        # fixture owned by the bootstrap suite.
        from tests.test_private_release_v2_bootstrap import (
            AUTH_ID,
            build_valid_terminal_source_evidence_fixture,
        )

        with tempfile.TemporaryDirectory() as folder:
            receipt_directory = (
                Path(folder) / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
            )
            fixture = build_valid_terminal_source_evidence_fixture(
                receipt_directory
            )
        contexts = {
            item["operationId"]: item["context"]
            for item in fixture["preflightProjection"]["operationAdmissions"]
        }
        return (
            copy.deepcopy(
                fixture["sourceEvidence"]["productionBoundary"]["mutationJournal"]
            ),
            fixture["plan"],
            fixture["authorization"],
            fixture["operationProjections"],
            contexts,
        )

    def _claim_prior(self):
        operation_id = "claimAzureSingleUseAuthorization"
        authorization_sha = bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(self.authorization)
        )
        resource_id = self.authorization["singleUse"]["azureClaimResourceId"]
        body = {
            "resourceId": resource_id,
            "deploymentName": resource_id.rsplit("/", 1)[-1],
            "provisioningState": "Succeeded",
            "claim": {
                "authorizationId": AUTHORIZATION_ID,
                "authorizationSha256": authorization_sha,
                "sourceSha": SOURCE_SHA,
                "planSha256": self.plan_sha,
                "packageSha256": self.authorization["plan"]["bridgePackageSha256"],
            },
        }
        projection = self.envelope(operation_id, body)
        self.assertEqual(self.validate(operation_id, projection), projection)
        return {operation_id: projection}

    def _postcondition_body(self, postcondition_id, prior, local_projection):
        postcondition = next(
            item for item in self.plan["postconditions"] if item["id"] == postcondition_id
        )
        policy = bootstrap._postcondition_semantic_policy(postcondition_id, self.plan)
        probe_id = f"probe-{postcondition_id}"
        claim = prior["claimAzureSingleUseAuthorization"]
        body = {
            "schemaVersion": 1,
            "postconditionId": postcondition_id,
            "predicateSha256": bootstrap.sha256_bytes(
                postcondition["predicate"].encode("utf-8")
            ),
            "semanticPolicy": policy,
            "claimPersistenceProbes": [
                {
                    "id": probe_id,
                    "validatorId": f"postcondition:{postcondition_id}",
                    "status": 200,
                    "responseSha256": claim["responseSha256"],
                    "sourceProjection": None,
                    "attempts": 1,
                    "startedAt": stamp(OBSERVED_AT),
                    "observedAt": stamp(OBSERVED_AT + dt.timedelta(seconds=1)),
                }
            ],
            "requiredOperationProjections": [
                {
                    "operationId": operation_id,
                    "sourceProjections": [copy.deepcopy(prior[operation_id])],
                }
                for operation_id in policy["requiredOperationIds"]
            ],
            "localProjection": copy.deepcopy(local_projection),
        }
        return body, [probe_id]

    def _validate_postcondition(
        self,
        postcondition_id,
        body,
        probe_ids,
        prior,
        *,
        expected_journal=None,
    ):
        return bootstrap._validate_postcondition_source_projection(
            body,
            postcondition_id=postcondition_id,
            plan=self.plan,
            authorization=self.authorization,
            prior=prior,
            operation_contexts={},
            expected_probe_ids=probe_ids,
            expected_journal=expected_journal,
        )

    def test_postcondition_rejects_arbitrary_claim_probe(self):
        postcondition_id = "azureSingleUseClaimPersists"
        prior = self._claim_prior()
        body, probe_ids = self._postcondition_body(
            postcondition_id,
            prior,
            {"requiredOperationProjectionCount": 1},
        )
        validated, journal = self._validate_postcondition(
            postcondition_id, body, probe_ids, prior
        )
        self.assertEqual(validated, body)
        self.assertIsNone(journal)
        arbitrary = copy.deepcopy(body)
        arbitrary["claimPersistenceProbes"][0]["sourceProjection"] = {
            "fabricated": True
        }
        arbitrary["claimPersistenceProbes"][0]["responseSha256"] = "f" * 64
        with self.assertRaises(bootstrap.BootstrapError):
            self._validate_postcondition(
                postcondition_id, arbitrary, probe_ids, prior
            )

    def _identity_postcondition_prior(self):
        prior = self._claim_prior()
        application_id = "20000000-0000-4000-8000-000000000001"
        application_client = "20000000-0000-4000-8000-000000000002"
        app_operation = "createPublisherApplication"
        app_body = {
            "id": application_id,
            "appId": application_client,
            "displayName": self.resources["publisherApplication"]["name"],
            "signInAudience": "AzureADMyOrg",
            "passwordCredentials": [],
            "keyCredentials": [],
        }
        app_projection = self.envelope(app_operation, app_body)
        self.validate(app_operation, app_projection, prior=prior)
        prior[app_operation] = app_projection

        sp_operation = "createPublisherServicePrincipal"
        sp_body = {
            "id": "20000000-0000-4000-8000-000000000003",
            "appId": application_client,
            "displayName": self.resources["publisherServicePrincipal"]["name"],
            "accountEnabled": True,
            "servicePrincipalType": "Application",
            "passwordCredentials": [],
            "keyCredentials": [],
            "appRoleAssignments": [],
        }
        sp_projection = self.envelope(sp_operation, sp_body)
        self.validate(sp_operation, sp_projection, prior=prior)
        prior[sp_operation] = sp_projection

        for offset, (operation_id, resource_id) in enumerate(
            (
                ("createBridgeIdentity", "bridgeIdentity"),
                ("adoptExistingRegistryWriterIdentity", "registryWriterIdentity"),
                ("adoptExistingRegistryReaderIdentity", "registryReaderIdentity"),
                ("createSignerIdentity", "signerIdentity"),
                ("createProductionActivationIdentity", "productionActivationIdentity"),
            ),
            10,
        ):
            contract = bootstrap._validator_contract(
                f"operation:{operation_id}", self.plan, self.authorization
            )
            body = {
                "id": contract["targetResourceId"],
                "name": contract["targetName"],
                "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                "clientId": f"20000000-0000-4000-8000-{offset:012d}",
                "principalId": f"20000000-0000-4000-8001-{offset:012d}",
                "tenantId": bootstrap.TENANT,
            }
            projection = self.envelope(operation_id, body)
            self.validate(operation_id, projection, prior=prior)
            prior[operation_id] = projection
        return prior

    def test_postcondition_rejects_arbitrary_distinct_identity_inventory(self):
        postcondition_id = "allAutomationIdentitiesDistinct"
        prior = self._identity_postcondition_prior()
        policy = bootstrap._postcondition_semantic_policy(postcondition_id, self.plan)
        identities = []
        for operation_id in policy["requiredOperationIds"]:
            candidate = prior[operation_id]["projection"]
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
        identities.append(
            {
                "operationId": "fixedProductionSystemIdentity",
                "clientId": self.resources["productionSystemIdentity"]["clientId"],
                "principalId": self.resources["productionSystemIdentity"]["principalId"],
            }
        )
        body, probe_ids = self._postcondition_body(
            postcondition_id,
            prior,
            {"identities": identities, "pairwiseDistinct": True},
        )
        self._validate_postcondition(postcondition_id, body, probe_ids, prior)
        arbitrary = copy.deepcopy(body)
        for index, item in enumerate(arbitrary["localProjection"]["identities"], 1):
            item["clientId"] = f"30000000-0000-4000-8000-{index:012d}"
            item["principalId"] = f"30000000-0000-4000-8001-{index:012d}"
        with self.assertRaises(bootstrap.BootstrapError):
            self._validate_postcondition(
                postcondition_id, arbitrary, probe_ids, prior
            )

    def _role_postcondition_prior(self):
        prior = self._identity_postcondition_prior()
        definition_operation = "createCustomRoleDefinitions"
        definitions = [
            item
            for _key, item in sorted(
                bootstrap._custom_role_definition_specs(self.plan).items()
            )
        ]
        definition_projection = self.envelope(
            definition_operation, {"roleDefinitions": definitions}
        )
        self.validate(definition_operation, definition_projection, prior=prior)
        prior[definition_operation] = definition_projection

        def principal_id(name: str) -> str:
            fixed = self.resources.get(name, {}).get("principalId")
            if isinstance(fixed, str):
                return fixed
            dependency = {
                "publisherServicePrincipal": "createPublisherServicePrincipal",
                "bridgeIdentity": "createBridgeIdentity",
                "signerIdentity": "createSignerIdentity",
                "productionActivationIdentity": "createProductionActivationIdentity",
            }[name]
            candidate = prior[dependency]["projection"]
            return candidate["id"] if name == "publisherServicePrincipal" else candidate[
                "principalId"
            ]

        assignments = sorted(
            (
                bootstrap._role_assignment_spec(
                    self.plan, role, principal_id(role["principal"])
                )
                for role in self.plan["roleMatrix"]
            ),
            key=lambda item: str(item["id"]).lower(),
        )
        assignment_operation = "createExactRoleAssignments"
        assignment_projection = self.envelope(
            assignment_operation, {"roleAssignments": assignments}
        )
        self.validate(assignment_operation, assignment_projection, prior=prior)
        prior[assignment_operation] = assignment_projection
        return prior

    def test_postcondition_rejects_count_only_role_inventory(self):
        postcondition_id = "exactTwentyFiveRoleRecords"
        prior = self._role_postcondition_prior()
        definitions = prior["createCustomRoleDefinitions"]["projection"][
            "roleDefinitions"
        ]
        assignments = prior["createExactRoleAssignments"]["projection"][
            "roleAssignments"
        ]
        body, probe_ids = self._postcondition_body(
            postcondition_id,
            prior,
            {
                "expectedRoleRecordCount": len(self.plan["roleMatrix"]),
                "roleDefinitions": definitions,
                "roleAssignments": assignments,
            },
        )
        self._validate_postcondition(postcondition_id, body, probe_ids, prior)
        count_only = copy.deepcopy(body)
        count_only["localProjection"]["roleDefinitions"] = [
            {"countOnly": index} for index, _item in enumerate(definitions)
        ]
        count_only["localProjection"]["roleAssignments"] = [
            {"countOnly": index} for index, _item in enumerate(assignments)
        ]
        with self.assertRaises(bootstrap.BootstrapError):
            self._validate_postcondition(
                postcondition_id, count_only, probe_ids, prior
            )

    def _journal_postcondition_body(self, journal):
        local = {
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
        prior = self._claim_prior()
        body, probe_ids = self._postcondition_body(
            "noProductionReleaseMutation", prior, local
        )
        return body, probe_ids, prior

    def test_postcondition_rejects_relabelled_or_hidden_forbidden_write(self):
        from tests.test_private_release_v2_bootstrap import (
            AUTH_ID,
            build_valid_terminal_source_evidence_fixture,
        )

        with tempfile.TemporaryDirectory() as folder:
            fixture = build_valid_terminal_source_evidence_fixture(
                Path(folder)
                / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
            )
        source = fixture["sourceEvidence"]
        self.assertEqual(
            bootstrap.validate_terminal_source_evidence(
                plan=fixture["plan"],
                authorization=fixture["authorization"],
                preflight_projection=fixture["preflightProjection"],
                evidence=source,
            ),
            source,
        )
        production = next(
            item["resourceId"]
            for item in fixture["plan"]["resourceInventory"]
            if item["id"] == "productionSite"
        )
        accepted = next(
            item["name"]
            for item in fixture["plan"]["resourceInventory"]
            if item["id"] == "acceptedContainer"
        )
        postcondition = next(
            item
            for item in source["postconditionProjections"]
            if item["postconditionId"] == "noProductionReleaseMutation"
        )
        variants = []
        relabelled = copy.deepcopy(source)
        relabelled_postcondition = next(
            item
            for item in relabelled["postconditionProjections"]
            if item["postconditionId"] == "noProductionReleaseMutation"
        )
        relabelled_postcondition["sourceProjection"]["localProjection"][
            "mutationJournal"
        ][0]["phase"] = "observation"
        variants.append(relabelled)
        for target in (
            f"https://management.azure.com{production}/restart?api-version=2025-03-01",
            (
                "https://mdspdbak2608089c4e.blob.core.windows.net/"
                f"{accepted}/hidden-release.json"
            ),
        ):
            hidden = copy.deepcopy(source)
            hidden_postcondition = next(
                item
                for item in hidden["postconditionProjections"]
                if item["postconditionId"] == "noProductionReleaseMutation"
            )
            hidden_journal = hidden_postcondition["sourceProjection"][
                "localProjection"
            ]["mutationJournal"]
            hidden_journal[0]["targetUrl"] = target
            hidden_journal[1]["targetUrl"] = target
            variants.append(hidden)
        for altered in variants:
            altered_postcondition = next(
                item
                for item in altered["postconditionProjections"]
                if item["postconditionId"] == "noProductionReleaseMutation"
            )
            altered_local = altered_postcondition["sourceProjection"][
                "localProjection"
            ]
            altered_journal = altered_local["mutationJournal"]
            altered_local["journalSha256"] = bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(altered_journal)
            )
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.validate_terminal_source_evidence(
                    plan=fixture["plan"],
                    authorization=fixture["authorization"],
                    preflight_projection=fixture["preflightProjection"],
                    evidence=altered,
                )

    def test_terminal_controller_empty_proof_binds_inner_digest_and_time(self):
        from tests.test_private_release_v2_bootstrap import (
            AUTH_ID,
            build_valid_terminal_source_evidence_fixture,
        )

        with tempfile.TemporaryDirectory() as folder:
            fixture = build_valid_terminal_source_evidence_fixture(
                Path(folder) / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}"
            )
        source = fixture["sourceEvidence"]
        entry = next(
            item
            for item in source["allOperationProjections"]
            if item["operationId"] == "proveControllerLockContainerEmpty"
        )
        variants = []
        digest_drift = copy.deepcopy(source)
        digest_entry = next(
            item
            for item in digest_drift["allOperationProjections"]
            if item["operationId"] == "proveControllerLockContainerEmpty"
        )
        digest_entry["sourceProjection"]["projection"]["responseSha256"] = "f" * 64
        variants.append(digest_drift)
        time_drift = copy.deepcopy(source)
        time_entry = next(
            item
            for item in time_drift["allOperationProjections"]
            if item["operationId"] == "proveControllerLockContainerEmpty"
        )
        outer = bootstrap.parse_time(
            time_entry["observedAt"], "proof wrapper observedAt"
        )
        time_entry["sourceProjection"]["projection"]["observedAt"] = stamp(
            outer + dt.timedelta(seconds=1)
        )
        variants.append(time_drift)
        for altered in variants:
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.validate_terminal_source_evidence(
                    plan=fixture["plan"],
                    authorization=fixture["authorization"],
                    preflight_projection=fixture["preflightProjection"],
                    evidence=altered,
                )

    def test_journal_rejects_relabelled_mutation_phase(self):
        valid, plan, authorization, operations, contexts = (
            self._complete_terminal_journal_inputs()
        )
        self.assertEqual(
            bootstrap._validate_sanitized_mutation_journal(
                valid,
                plan=plan,
                authorization=authorization,
                operation_projections=operations,
                operation_contexts=contexts,
            ),
            valid,
        )
        relabelled = copy.deepcopy(valid)
        relabelled[0]["phase"] = "observation"
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap._validate_sanitized_mutation_journal(
                relabelled,
                plan=plan,
                authorization=authorization,
                operation_projections=operations,
                operation_contexts=contexts,
            )

    def test_journal_rejects_hidden_production_or_accepted_container_write(self):
        valid, plan, authorization, operations, contexts = (
            self._complete_terminal_journal_inputs()
        )
        resources = {item["id"]: item for item in plan["resourceInventory"]}
        production = resources["productionSite"]["resourceId"]
        accepted_name = resources["acceptedContainer"]["name"]
        forbidden_urls = (
            (
                f"https://management.azure.com{production}/config/appsettings"
                "?api-version=2025-03-01"
            ),
            (
                "https://mdspdbak2608089c4e.blob.core.windows.net/"
                f"{accepted_name}/hidden-release.json"
            ),
        )
        for forbidden_url in forbidden_urls:
            with self.subTest(target=forbidden_url):
                hidden = copy.deepcopy(valid)
                hidden[0]["targetUrl"] = forbidden_url
                hidden[1]["targetUrl"] = forbidden_url
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap._validate_sanitized_mutation_journal(
                        hidden,
                        plan=plan,
                        authorization=authorization,
                        operation_projections=operations,
                        operation_contexts=contexts,
                    )

    def test_journal_rejects_unrelated_dynamic_graph_object_target(self):
        journal, plan, authorization, operations, contexts = (
            self._complete_terminal_journal_inputs()
        )
        unrelated_service_principal = "90000000-0000-4000-8000-000000000099"
        target = (
            "https://graph.microsoft.com/v1.0/servicePrincipals/"
            f"{unrelated_service_principal}/appRoleAssignments"
        )
        intent = {
            "sequence": 3,
            "phase": "intent",
            "intentId": "cloud-mutation-0003",
            "operationId": "grantPublisherGraphApplicationReadAll",
            "temporary": False,
            "method": "POST",
            "targetUrl": target,
            "requestBodySha256": "7" * 64,
            "status": None,
            "responseBodySha256": None,
            "etag": None,
            "versionId": None,
            "recordedAt": stamp(OBSERVED_AT),
        }
        result = copy.deepcopy(intent)
        result.update(
            {
                "sequence": 4,
                "phase": "result",
                "status": 201,
                "responseBodySha256": "8" * 64,
            }
        )
        journal.extend((intent, result))
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap._validate_sanitized_mutation_journal(
                journal,
                plan=plan,
                authorization=authorization,
                operation_projections=operations,
                operation_contexts=contexts,
            )


if __name__ == "__main__":
    unittest.main()
