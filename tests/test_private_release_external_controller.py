import base64
import datetime as dt
import json
import types
import unittest
from unittest import mock

from scripts import private_release_external_controller as controller
from scripts import private_release_mailbox as core
from tests import private_release_v2_fixture as fixture


CID = "11111111-1111-1111-1111-111111111111"
PID = "22222222-2222-2222-2222-222222222222"
TID = "33333333-3333-3333-3333-333333333333"
NOW = 2_000_000_000


def b64(value):
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).rstrip(b"=").decode()


def jwt(**changes):
    claims = {"aud": "https://management.azure.com/", "appid": CID, "azp": CID, "oid": PID,
              "sub": PID, "idtyp": "app", "tid": TID, "iss": f"https://sts.windows.net/{TID}/",
              "nbf": NOW - 1, "exp": NOW + 1000}
    claims.update(changes)
    return "x." + b64(claims) + ".x"


class LiveProvisioning:
    """Canonical action-time ARM/Graph projection for the activated fixture."""
    def __init__(self, document, evidence):
        self.document = document
        self.evidence = evidence
        self.activation = document["activation"]
        self.roles = evidence["roles"]
        self.assignments = [fixture.assignment_projection(role) for role in self.roles.values()]
        self.definitions = {}
        for name, role in self.roles.items():
            resource_id = role["roleDefinitionResourceId"].lower()
            self.definitions[resource_id] = {
                "id": resource_id, "name": resource_id.rsplit("/", 1)[1],
                "type": "Microsoft.Authorization/roleDefinitions", "properties": {
                    "roleName": "fixture-" + name,
                    "type": "BuiltInRole" if role["assignableScopes"] == ["/"] else "CustomRole",
                    "assignableScopes": role["assignableScopes"],
                    "permissions": [{
                        key: role[key]
                        for key in ("actions", "notActions", "dataActions", "notDataActions")
                    }],
                },
            }
        self.calls = []
        self.drift_worm = False
        self.extra_effective_assignment = False
        self.extra_bridge_setting = False

    @staticmethod
    def response(value, status=200):
        return core.Response(status, "", core.canonical(value) if value is not None else b"", {})

    def graph(self, method, url, headers, body):
        self.calls.append(("graph", method, url))
        source = self.evidence["publisherIdentity"]
        if url == source["applicationQuery"]:
            return self.response({"id": source["applicationObjectId"], "appId": self.activation["mailboxPublisherClientId"], "signInAudience": "AzureADMyOrg", "passwordCredentials": [], "keyCredentials": []})
        if url == source["servicePrincipalQuery"]:
            return self.response({"id": self.activation["mailboxPublisherPrincipalId"], "appId": self.activation["mailboxPublisherClientId"], "accountEnabled": True, "servicePrincipalType": "Application", "passwordCredentials": [], "keyCredentials": []})
        if url == source["federatedIdentityCredentialsQuery"]:
            policy = source["federatedIdentityCredentialPolicy"]
            value = policy["claimsMatchingExpressionTemplate"]["value"].replace("{controlWorkflowRef}", f"{core.CONTROL_REPOSITORY}/{core.CONTROL_WORKFLOW_PATH}@{fixture.WORKFLOW_SHA}")
            return self.response({"value": [{"id": policy["id"], "name": policy["name"], "issuer": policy["issuer"], "audiences": policy["audiences"], "subject": None, "claimsMatchingExpression": {"languageVersion": 1, "value": value}}]})
        if url == source["appRoleAssignmentsQuery"]:
            return self.response({"value": [source["graphApplicationReadAllAppRoleAssignment"]]})
        raise AssertionError((method, url))

    def arm(self, method, url, headers, body):
        self.calls.append(("arm", method, url))
        base = "https://management.azure.com"
        runtime = self.evidence["bridgeRuntime"]
        bridge_id = runtime["siteResourceId"]
        production_id = self.activation["productionActivationRoleAssignmentScope"]
        # Fully paginated assignment inventories (single page in the fixture).
        if "/providers/microsoft.authorization/roleassignments?api-version=2022-04-01" in url.lower():
            if "$filter=principalId" in url:
                principal = url.split("%27", 1)[1].split("%27", 1)[0]
                values = [item for item in self.assignments if item["properties"]["principalId"] == principal.lower()]
            elif "$filter=assignedTo" in url:
                principal = url.split("%27", 1)[1].split("%27", 1)[0]
                values = [item for item in self.assignments if item["properties"]["principalId"] == principal.lower()]
                if self.extra_effective_assignment and values:
                    extra = json.loads(json.dumps(values[0]))
                    extra["id"] = extra["id"].rsplit("/", 1)[0] + "/ffffffff-ffff-4fff-8fff-ffffffffffff"
                    extra["name"] = "ffffffff-ffff-4fff-8fff-ffffffffffff"
                    values = values + [extra]
            else:
                marker = "/providers/microsoft.authorization/roleassignments"
                target_scope = url.removeprefix(base)[:url.lower().index(marker) - len(base)].lower()
                if target_scope == f"/subscriptions/{core.SUBSCRIPTION}".lower():
                    values = list(self.assignments)
                else:
                    values = [
                        item for item in self.assignments
                        if target_scope == item["properties"]["scope"]
                        or target_scope.startswith(item["properties"]["scope"] + "/")
                    ]
            return self.response({"value": values})
        if "/providers/microsoft.authorization/roledefinitions/" in url.lower():
            resource_id = url.removeprefix(base).split("?", 1)[0].lower()
            return self.response(self.definitions[resource_id])
        # UAMI resources.
        if "Microsoft.ManagedIdentity/userAssignedIdentities" in url and "roleAssignments" not in url:
            resource_id = url.removeprefix(base).split("?", 1)[0]
            role = next(role for role in self.roles.values() if isinstance(role["identityResourceId"], str) and role["identityResourceId"].lower() == resource_id.lower())
            return self.response({"id": resource_id, "type": "Microsoft.ManagedIdentity/userAssignedIdentities", "properties": {"tenantId": role["tenantId"], "clientId": role["identityClientId"], "principalId": role["principalId"]}})
        posture = runtime["sitePosture"]
        sensitive_roles = {}
        for role in self.roles.values():
            resource = role["identityResourceId"]
            if isinstance(resource, str) and resource.lower() != production_id.lower():
                sensitive_roles.setdefault(resource, {"clientId": role["identityClientId"], "principalId": role["principalId"]})
        bridge_document = {"id": bridge_id, "name": posture["name"], "type": posture["type"], "kind": posture["kind"], "httpsOnly": posture["httpsOnly"], "identity": {"type": "UserAssigned", "userAssignedIdentities": sensitive_roles}, "properties": {"state": "Stopped", "serverFarmId": posture["serverFarmId"], "publicNetworkAccess": posture["publicNetworkAccess"], "virtualNetworkSubnetId": posture["virtualNetworkSubnetId"], "outboundVnetRouting": posture["outboundVnetRouting"]}}
        if url == base + bridge_id + "?api-version=2025-03-01":
            return self.response(bridge_document)
        if url == base + bridge_id + "/config/appsettings/list?api-version=2025-03-01":
            settings = dict(runtime["criticalAppSettings"])
            if self.extra_bridge_setting:
                settings["PAPERDESK_UNREVIEWED_EXECUTION_MODE"] = "enabled"
            return self.response({"properties": settings})
        if url == base + bridge_id + "/config/web?api-version=2025-03-01":
            return self.response({"properties": posture["webConfig"]})
        if url == base + bridge_id + "/basicPublishingCredentialsPolicies/ftp?api-version=2025-03-01":
            return self.response({"properties": {"allow": False}})
        if url == base + bridge_id + "/basicPublishingCredentialsPolicies/scm?api-version=2025-03-01":
            return self.response({"properties": {"allow": False}})
        if url == base + bridge_id + "/sourcecontrols/web?api-version=2025-03-01":
            return self.response(None, 404)
        if url == runtime["siteInventoryQuery"]:
            return self.response({"value": [bridge_document]})
        legacy = runtime["legacyBridgeRetirement"]
        if url == base + legacy["siteResourceId"] + "?api-version=2025-03-01":
            return self.response({"id": legacy["siteResourceId"], "type": "Microsoft.Web/sites", "identity": {"type": "None", "userAssignedIdentities": {}}, "properties": {"state": "Stopped", "publicNetworkAccess": "Disabled"}})
        if url == base + legacy["siteResourceId"] + "/config/appsettings/list?api-version=2025-03-01":
            return self.response({"properties": {}})
        # Production identity and network topology share one site resource.
        production_role = self.roles["productionSystemPackageRead"]
        topology = runtime["networkTopology"]
        if url == base + production_id + "?api-version=2025-03-01":
            return self.response({"id": production_id, "type": "Microsoft.Web/sites", "identity": {"type": "SystemAssigned", "tenantId": production_role["tenantId"], "principalId": production_role["principalId"], "userAssignedIdentities": {}}, "properties": {"virtualNetworkSubnetId": topology["productionSite"]["virtualNetworkSubnetId"], "outboundVnetRouting": topology["productionSite"]["outboundVnetRouting"]}})
        if url == base + production_id + "/config/web?api-version=2025-03-01":
            return self.response({"properties": {"vnetRouteAllEnabled": topology["productionSite"]["legacyVnetRouteAllEnabled"]}})
        for name, item in topology.items():
            if name == "mode" or url != base + item["resourceId"] + "?api-version=" + item["apiVersion"]:
                continue
            if name == "virtualNetwork":
                return self.response({"id": item["resourceId"], "type": "Microsoft.Network/virtualNetworks", "properties": {"addressSpace": {"addressPrefixes": item["addressSpacePrefixes"]}}})
            if name == "integrationSubnet":
                return self.response({"id": item["resourceId"], "type": "Microsoft.Network/virtualNetworks/subnets", "properties": {"delegations": [{"properties": {"serviceName": value}} for value in item["delegations"]], "serviceEndpoints": item["serviceEndpoints"], "routeTable": None, "networkSecurityGroup": None}})
            if name == "packageStorageAccount":
                return self.response({"id": item["resourceId"], "type": "Microsoft.Storage/storageAccounts", "properties": {"publicNetworkAccess": item["publicNetworkAccess"], "allowBlobPublicAccess": item["allowBlobPublicAccess"], "networkAcls": {"defaultAction": item["defaultAction"], "bypass": item["bypass"], "ipRules": item["ipRules"], "resourceAccessRules": item["resourceAccessRules"], "virtualNetworkRules": item["virtualNetworkRules"]}}})
        key = self.evidence["keyVaultBoundary"]
        if url == base + key["vaultResourceId"] + "?api-version=" + key["vaultApiVersion"]:
            projection = key["vaultProjection"]
            return self.response({"id": projection["id"], "name": projection["name"], "type": projection["type"], "location": projection["location"], "properties": projection["properties"]})
        if url == base + key["keyResourceId"] + "?api-version=" + key["keyApiVersion"]:
            projection = key["keyProjection"]
            properties = dict(projection["properties"])
            properties["attributes"] = {"enabled": True, "exportable": False, "exp": properties["attributes"]["expiresOn"]}
            properties["release_policy"] = properties.pop("releasePolicy")
            return self.response({"id": projection["id"], "name": projection["name"], "type": projection["type"], "properties": properties})
        lock = self.evidence["controllerLockContainer"]
        if url == base + lock["scope"] + "?api-version=2025-06-01":
            return self.response({"id": lock["scope"], "name": "default/" + core.FIXED_COORDS["controllerLockContainer"], "type": "Microsoft.Storage/storageAccounts/blobServices/containers", "properties": {"publicAccess": None}})
        for policy in self.evidence["wormPolicies"].values():
            if url == base + policy["scope"] + "?api-version=2025-06-01":
                return self.response({"id": policy["scope"], "name": "default/" + policy["scope"].rsplit("/", 1)[1], "type": "Microsoft.Storage/storageAccounts/blobServices/containers", "properties": {"publicAccess": None}})
            if url == base + policy["policyResourceId"] + "?api-version=2025-06-01":
                days = 90 if self.drift_worm and policy is self.evidence["wormPolicies"]["packages"] else policy["immutabilityPeriodSinceCreationInDays"]
                return self.response({"id": policy["policyResourceId"], "name": "default", "type": "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies", "etag": policy["etag"], "properties": {"state": policy["state"], "immutabilityPeriodSinceCreationInDays": days, "allowProtectedAppendWrites": False, "allowProtectedAppendWritesAll": False}})
        raise AssertionError((method, url))


class Tests(unittest.TestCase):
    def test_registry_preflight_cannot_enter_activation_path(self):
        document, evidence, receipt = fixture.activated_bundle()
        now = dt.datetime.now(dt.timezone.utc)
        request = {
            "schemaVersion": 2, "requestType": "paperdesk-private-release-request",
            "operation": "registry-bridge-preflight", "repositoryId": core.OWNER_REPOSITORY_ID,
            "ownerId": core.OWNER_ID, "controlWorkflowSha": fixture.WORKFLOW_SHA,
            "sourceSha": "9" * 40, "sourceRunId": "44", "sourceRunAttempt": "1",
            "candidateRunId": None, "candidateRunAttempt": None,
            "artifactId": "", "artifactSha256": "", "artifactMember": "",
            "artifactMemberSha256": "", "acceptanceRunId": "44",
            "acceptanceRunAttempt": "1", "logicalOperationId": None, "nonce": "e" * 32,
            "issuedAt": controller._stamp(now),
            "expiresAt": controller._stamp(now + dt.timedelta(minutes=15)),
            "acceptedBaseline": None, "pendingRelease": None, "consumedMarker": None,
            "rollbackPreparation": None, "activationPlan": None, "activationProof": None,
        }
        with mock.patch.object(controller, "_run_bridge") as run_bridge:
            with self.assertRaisesRegex(core.MailboxError, "external-read-only-operation"):
                controller.execute(
                    request, document,
                    activation_raw=core.canonical(document).decode(),
                    runtime_workflow_sha=fixture.WORKFLOW_SHA,
                    package_sha=fixture.PACKAGE_SHA, provisioning_evidence=evidence,
                    bridge_runtime_receipt=receipt, github_token="g" * 20,
                    transport=lambda *args: None, activate=True,
                )
        run_bridge.assert_not_called()

        carried = dict(request)
        carried.update({"candidateRunId": "45", "candidateRunAttempt": "2"})
        followed = controller._followup(
            carried, "registry-bridge-preflight", now=now
        )
        self.assertIsNone(followed["candidateRunId"])
        self.assertIsNone(followed["candidateRunAttempt"])
        self.assertEqual(core.validate_request(followed, now=now)[0], followed)

        with mock.patch.object(controller, "_run_bridge") as run_bridge:
            with self.assertRaisesRegex(core.MailboxError, "activation-document-canonical"):
                controller.execute(
                    request, document,
                    activation_raw=json.dumps(document, indent=2),
                    runtime_workflow_sha=fixture.WORKFLOW_SHA,
                    package_sha=fixture.PACKAGE_SHA, provisioning_evidence=evidence,
                    bridge_runtime_receipt=receipt, github_token="g" * 20,
                    transport=lambda *args: None,
                )
        run_bridge.assert_not_called()

    def test_live_provisioning_inventory_succeeds_and_worm_drift_fails_closed(self):
        document, evidence, receipt = fixture.activated_bundle()
        activation = fixture.activation()
        live = LiveProvisioning(document, evidence)
        result = controller.ProvisioningVerifier(live.arm, activation, receipt, graph_transport=live.graph).verify()
        self.assertEqual(result["status"], "verified")
        self.assertTrue(any("assignedTo" in url for plane, method, url in live.calls if plane == "arm"))
        live.drift_worm = True
        with self.assertRaisesRegex(core.MailboxError, "provisioning-live-worm-packages"):
            controller.ProvisioningVerifier(live.arm, activation, receipt, graph_transport=live.graph).verify()

    def test_live_provisioning_rejects_transitive_or_inherited_assignment_drift(self):
        document, evidence, receipt = fixture.activated_bundle()
        live = LiveProvisioning(document, evidence)
        live.extra_effective_assignment = True
        with self.assertRaisesRegex(core.MailboxError, "provisioning-live-inventory-"):
            controller.ProvisioningVerifier(
                live.arm, fixture.activation(), receipt, graph_transport=live.graph
            ).verify()

    def test_live_provisioning_rejects_unexpected_bridge_app_setting(self):
        document, evidence, receipt = fixture.activated_bundle()
        live = LiveProvisioning(document, evidence)
        live.extra_bridge_setting = True
        with self.assertRaisesRegex(core.MailboxError, "provisioning-bridge-settings"):
            controller.ProvisioningVerifier(
                live.arm, fixture.activation(), receipt, graph_transport=live.graph
            ).verify()

    def test_bridge_lease_rejects_extra_setting_before_transient_put(self):
        document, _, receipt = fixture.activated_bundle()
        activation = fixture.activation()
        settings = dict(activation.provisioning_evidence["bridgeRuntime"]["criticalAppSettings"])
        settings["PAPERDESK_UNREVIEWED_EXECUTION_MODE"] = "enabled"

        class Settings:
            put_calls = 0

            def read(self):
                return dict(settings), core.digest(core.canonical(settings))

            def put_if_digest(self, *args, **kwargs):
                self.put_calls += 1

        controller_lease = types.SimpleNamespace(renew=lambda force=False: None)
        lease = controller.BridgeLease(
            lambda *args: None,
            activation,
            core.canonical(document).decode(),
            receipt,
            "g" * 20,
            "pdreq-5-1-" + "d" * 32,
            {},
            controller_lease,
        )
        lease.assert_stopped = lambda: None
        lease.settings = Settings()
        with self.assertRaisesRegex(core.MailboxError, "bridge-durable-settings-drift"):
            lease.acquire()
        self.assertEqual(lease.settings.put_calls, 0)
        self.assertFalse(lease.owns_transient)

    def test_cli_publisher_token_binds_client_principal_tenant_issuer_and_app_type(self):
        activation = types.SimpleNamespace(tenant_id=TID, publisher_client_id=CID, publisher_principal_id=PID)

        def provider(token):
            completed = types.SimpleNamespace(returncode=0, stdout=json.dumps({"accessToken": token}))
            with mock.patch.object(controller.subprocess, "run", return_value=completed):
                return controller.CliTokens(activation, clock=lambda: NOW).get("https://management.azure.com/")

        self.assertEqual(provider(jwt()), jwt())
        for changes in ({"appid": TID}, {"azp": TID}, {"oid": CID}, {"sub": CID}, {"idtyp": "user"},
                        {"tid": CID}, {"iss": f"https://sts.windows.net/{CID}/"}, {"exp": NOW + 299}):
            with self.subTest(changes=changes), self.assertRaises(core.MailboxError):
                provider(jwt(**changes))

    def test_appsettings_pre_digest_and_lost_lease_block_put(self):
        calls = []

        def transport(method, url, headers, body):
            calls.append(method)
            return core.Response(200, url, core.canonical({"properties": {"A": "1"}}), {})

        boundary = controller.AppSettingsBoundary(transport, "https://management.azure.com/site")
        with self.assertRaisesRegex(core.MailboxError, "appsettings-pre-drift"):
            boundary.put_if_digest({"A": "2"}, "0" * 64)
        self.assertEqual(calls, ["POST"])
        with self.assertRaisesRegex(core.MailboxError, "lease-lost"):
            boundary.put_if_digest({"A": "2"}, core.digest(core.canonical({"A": "1"})),
                                   pre_mutation=lambda: (_ for _ in ()).throw(core.MailboxError("lease-lost")))
        self.assertEqual(calls, ["POST", "POST"])

    def test_cleanup_controller_busy_retries_across_full_lease_and_uses_fresh_instances(self):
        outcomes = iter((False, False, True))
        instances = []
        sleeps = []

        class Lease:
            def __init__(self, transport, owner):
                self.identity = len(instances)
                instances.append(self)

            def acquire(self):
                return next(outcomes)

        acquired = controller.acquire_cleanup_controller_lease(
            object(), "owner", attempts=3, interval_seconds=31, sleep=sleeps.append, lease_factory=Lease)
        self.assertIs(acquired, instances[2])
        self.assertEqual(len({id(value) for value in instances}), 3)
        self.assertEqual(sleeps, [31, 31])

    def test_cleanup_controller_permanent_busy_is_failure_not_success(self):
        class Busy:
            def __init__(self, transport, owner):
                pass

            def acquire(self):
                return False

        with self.assertRaisesRegex(core.MailboxError, "controller-cleanup-lease-busy"):
            controller.acquire_cleanup_controller_lease(
                object(), "owner", attempts=3, interval_seconds=31, sleep=lambda _: None, lease_factory=Busy)

    def test_controller_lease_ids_are_random_per_attempt(self):
        one = controller.ControllerLease(lambda *args: None, "same-owner")
        two = controller.ControllerLease(lambda *args: None, "same-owner")
        self.assertNotEqual(one.lease_id, two.lease_id)

    def test_github_liveness_binds_exact_workflow_path_event_and_head(self):
        record = {"runId": "7", "runAttempt": "1", "repository": core.OWNER_REPOSITORY,
                  "repositoryId": core.OWNER_REPOSITORY_ID, "ownerId": core.OWNER_ID,
                  "workflowId": core.OWNER_WORKFLOW_ID, "workflowName": core.OWNER_WORKFLOW_NAME,
                  "workflowPath": core.OWNER_WORKFLOW_PATH, "event": "push", "headBranch": "main",
                  "callerSha": "a" * 40}
        document = {"id": 7, "run_attempt": 1, "status": "completed", "conclusion": "success",
                    "workflow_id": int(core.OWNER_WORKFLOW_ID), "name": core.OWNER_WORKFLOW_NAME,
                    "path": core.OWNER_WORKFLOW_PATH, "event": "push", "head_branch": "main",
                    "head_sha": "a" * 40, "repository": {"id": int(core.OWNER_REPOSITORY_ID),
                    "full_name": core.OWNER_REPOSITORY, "owner": {"id": int(core.OWNER_ID)}}}
        reader = controller.GitHubRunLiveness("x" * 20,
            lambda *args: core.Response(200, "", core.canonical(document), {}))
        self.assertEqual(reader(record)["status"], "completed")
        wrong = dict(document)
        wrong["path"] = ".github/workflows/other.yml"
        with self.assertRaisesRegex(core.MailboxError, "cleanup-run-active-or-drift"):
            controller.GitHubRunLiveness("x" * 20,
                lambda *args: core.Response(200, "", core.canonical(wrong), {}))(record)


if __name__ == "__main__":
    unittest.main()
