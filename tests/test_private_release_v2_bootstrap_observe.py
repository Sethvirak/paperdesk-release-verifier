import contextlib
import copy
import datetime as dt
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
import uuid

from scripts import private_release_v2_bootstrap as bootstrap
from scripts import private_release_v2_bootstrap_observe as observe


NOW = dt.datetime(2026, 8, 30, 8, 0, tzinfo=dt.timezone.utc)
AUTHORIZATION_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
ACCOUNT_OBJECT_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
LEGACY_FIC_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
GRAPH_SERVICE_PRINCIPAL_ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
CANONICAL_GRAPH_ASSIGNMENT_ID = (
    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
)
REVIEWED_SHA = "1" * 40
MERGED_SHA = "2" * 40
TREE_SHA = "3" * 40
PARENT_SHA = "4" * 40
PHRASE = (
    "Authorize the separately reviewed exact PaperDesk V2 bootstrap. "
    + bootstrap.STORAGE_ACL_AND_RECOVERY_RESIDUAL_ACCEPTANCE
    + " " + bootstrap.DELETION_LOCK_RESIDUAL_ACCEPTANCE
    + " " + bootstrap.BRIDGE_CONFIG_HARD_DEATH_RESIDUAL_ACCEPTANCE
)


def stamp(value):
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def source_evidence():
    pushed = NOW - dt.timedelta(minutes=8)
    first_review = NOW - dt.timedelta(minutes=7)
    second_review = NOW - dt.timedelta(minutes=6)
    checked = NOW - dt.timedelta(minutes=5)
    merged = NOW - dt.timedelta(minutes=4)
    return {
        "reviewedHead": {
            "commitSha": REVIEWED_SHA,
            "treeSha": TREE_SHA,
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
                    "submittedAt": stamp(first_review),
                    "commitSha": REVIEWED_SHA,
                },
                {
                    "login": "jecebella169-cmyk",
                    "userId": 322025901,
                    "reviewId": 9002,
                    "state": "APPROVED",
                    "submittedAt": stamp(second_review),
                    "commitSha": REVIEWED_SHA,
                },
            ],
            "requiredCheck": {
                "name": "test",
                "runId": "12345",
                "headSha": REVIEWED_SHA,
                "conclusion": "success",
                "completedAt": stamp(checked),
            },
        },
        "mergedMain": {
            "commitSha": MERGED_SHA,
            "treeSha": TREE_SHA,
            "soleParentSha": PARENT_SHA,
            "treeEqualsReviewedHead": True,
            "githubVerificationVerified": True,
            "githubVerificationReason": "valid",
            "mergedPullRequestNumber": 19,
            "mergedPullRequestUrl": f"https://github.com/{bootstrap.REPOSITORY}/pull/19",
            "mergedAt": stamp(merged),
            "verificationApiUrl": (
                f"https://api.github.com/repos/{bootstrap.REPOSITORY}/commits/{MERGED_SHA}"
            ),
            "verificationRetrievedAt": stamp(merged + dt.timedelta(seconds=30)),
        },
    }


def package_worm_deleted_tombstone(plan):
    resources = {item["id"]: item for item in plan["resourceInventory"]}
    return {
        "id": (
            resources["packageContainer"]["resourceId"]
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


class FakeReadOnlySession:
    def __init__(
        self,
        plan,
        *,
        drift=False,
        credential=False,
        opaque_secret=False,
        role_authority_drift=False,
    ):
        self.plan = bootstrap.bind_temporary_role_ids(plan, AUTHORIZATION_ID)
        self.drift = drift
        self.credential = credential
        self.opaque_secret = opaque_secret
        self.role_authority_drift = role_authority_drift
        self.requests = []
        self.envelopes = {}
        self.resources = {item["id"]: item for item in plan["resourceInventory"]}

    def account(self):
        return {
            "cloud": "AzureCloud",
            "subscriptionId": bootstrap.SUBSCRIPTION,
            "tenantId": bootstrap.TENANT,
            "accountId": "operator@example.invalid",
            "accountObjectId": ACCOUNT_OBJECT_ID,
            "accountType": "user",
        }

    def _network_acls(self):
        subnet = self.resources["integrationSubnet"]["resourceId"]
        return {
            "defaultAction": "Deny",
            "bypass": "None",
            "ipRules": [],
            "resourceAccessRules": [],
            "virtualNetworkRules": [
                {"id": subnet, "action": "Allow", "state": "Succeeded"}
            ],
        }

    def read(self, request):
        self.requests.append(request)
        self.assert_read_only(request)
        method = "GET" if self.drift else request.method
        url = request.url + "&drift=true" if self.drift else request.url
        status = 404
        headers = {}
        body = {}

        writer = self.resources["registryWriterIdentity"]
        reader = self.resources["registryReaderIdentity"]
        production_requests = {
            item["id"]: item for item in bootstrap._production_boundary_requests(self.plan)
        }
        production_match = next(
            (
                request_id
                for request_id, spec in production_requests.items()
                if request.method == spec["method"] and request.url == spec["url"]
            ),
            None,
        )
        if request.url == bootstrap._cleanup_lock_inventory_url():
            status = 200
            body = {"value": [
                {"id": lock["resourceId"], "name": lock["resourceId"].rsplit("/", 1)[-1],
                 "type": "Microsoft.Authorization/locks", "properties": copy.deepcopy(lock["properties"])}
                for lock in bootstrap._expected_cleanup_lock_inventory()["locks"]
            ]}
        elif production_match == "production-boundary-site":
            site = self.resources["productionSite"]
            status = 200
            body = {
                "id": site["resourceId"],
                "name": site["name"],
                "type": "Microsoft.Web/sites",
                "identity": {
                    "type": "SystemAssigned",
                    "tenantId": bootstrap.TENANT,
                    "principalId": self.resources["productionSystemIdentity"]["principalId"],
                    "userAssignedIdentities": None,
                },
                "properties": {
                    "state": "Running",
                    "outboundVnetRouting": {
                        "allTraffic": False,
                        "applicationTraffic": True,
                    },
                },
            }
        elif production_match == "production-boundary-web-config":
            status = 200
            body = {
                "properties": {
                    "virtualNetworkSubnetId": self.resources["integrationSubnet"]["resourceId"],
                    "vnetRouteAllEnabled": True,
                }
            }
        elif production_match == "production-boundary-app-settings":
            site = self.resources["productionSite"]
            status = 200
            body = {
                "id": site["resourceId"] + "/config/appsettings",
                "location": "Southeast Asia",
                "name": "appsettings",
                "properties": {
                    "FIXTURE_SECRET_SETTING_NAME": "fixture-secret-setting-value"
                },
                "tags": {"fixture": "redacted-before-projection"},
                "type": "Microsoft.Web/sites/config",
            }
        elif production_match == "production-boundary-deployments":
            site = self.resources["productionSite"]
            deployment_id = "fixture-deployment"
            status = 200
            body = {
                "value": [
                    {
                        "id": f"{site['resourceId']}/deployments/{deployment_id}",
                        "name": f"{site['name']}/{deployment_id}",
                        "type": "Microsoft.Web/sites/deployments",
                        "properties": {
                            "id": deployment_id,
                            "active": True,
                            "complete": True,
                            "status": 4,
                            "deployer": "OneDeploy",
                            "received_time": "2026-08-29T00:00:00Z",
                            "start_time": "2026-08-29T00:00:01Z",
                            "end_time": "2026-08-29T00:00:02Z",
                            "last_success_end_time": "2026-08-29T00:00:02Z",
                            "is_readonly": True,
                            "is_temp": False,
                            "site_name": site["name"],
                        },
                    }
                ],
                "nextLink": None,
            }
        elif production_match == "production-boundary-onedeploy":
            site = self.resources["productionSite"]
            operation_id = "11111111-1111-4111-8111-111111111111"
            status = 200
            body = {
                "value": [
                    {
                        "id": f"{site['resourceId']}/extensions/onedeploy/{operation_id}",
                        "name": f"{site['name']}/onedeploy",
                        "type": f"Microsoft.Web/sites/extensions/{operation_id}",
                        "properties": {
                            "id": operation_id,
                            "deployer": "OneDeploy",
                            "complete": True,
                            "status": 4,
                            "received_time": "2026-08-29T00:00:00Z",
                            "start_time": "2026-08-29T00:00:01Z",
                            "end_time": "2026-08-29T00:00:02Z",
                        },
                    }
                ],
                "nextLink": None,
            }
        elif request.url.startswith(
            f"https://management.azure.com{writer['resourceId']}?"
        ):
            status = 200
            body = {
                "id": writer["resourceId"],
                "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                "properties": {
                    "tenantId": bootstrap.TENANT,
                    "clientId": writer["clientId"],
                    "principalId": writer["principalId"],
                },
            }
        elif request.url.startswith(
            f"https://management.azure.com{reader['resourceId']}?"
        ):
            status = 200
            body = {
                "id": reader["resourceId"],
                "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                "properties": {
                    "tenantId": bootstrap.TENANT,
                    "clientId": reader["clientId"],
                    "principalId": reader["principalId"],
                },
            }
        elif request.url.startswith(
            f"https://management.azure.com{self.resources['storageAccount']['resourceId']}?"
        ):
            status = 200
            headers = {"ETag": '"storage-etag"'}
            body = {"properties": {"networkAcls": self._network_acls()}}
        elif request.url.startswith(
            f"https://management.azure.com{self.resources['legacyBridgeSite']['resourceId']}?"
        ):
            status = 200
            headers = {"ETag": '"legacy-etag"'}
            body = {
                "id": self.resources["legacyBridgeSite"]["resourceId"],
                "name": "paperdesk-release-registry-bridge-9c4e0d0d",
                "properties": {"state": "Stopped"},
            }
        elif request.url == (
            "https://management.azure.com"
            + self.resources["bridgeSite"]["resourceId"]
            + "/config/appsettings/list?api-version=2025-03-01"
        ):
            status = 200
            headers = {}
            body = {
                "id": (
                    self.resources["bridgeSite"]["resourceId"]
                    + "/config/appsettings"
                ),
                "name": "appsettings",
                "type": "Microsoft.Web/sites/config",
                "properties": {},
            }
        elif request.url == (
            "https://kv-mds-sea-9c4e0d0d.vault.azure.net/keys/"
            "paperdesk-release-result-signing/versions?api-version=7.4"
        ):
            status = 403
            body = {
                "error": {
                    "code": "Forbidden",
                    "innererror": {"code": "ForbiddenByRbac"},
                }
            }
        elif request.url == self.resources["activationFenceBlob"]["resourceId"]:
            status = 403
            body = {"storageErrorCode": "AuthorizationPermissionMismatch"}
        elif request.url.startswith(
            "https://mdspdbak2608089c4e.blob.core.windows.net/"
            "paperdesk-release-controller-lock/v2/bootstrap-canary/"
        ):
            status = 403
            body = {"storageErrorCode": "AuthorizationPermissionMismatch"}
        elif (
            "/paperdesk-deployment-packages/immutabilityPolicies/default?"
            in request.url
        ):
            status = 404
            body = {"error": {"code": "ContainerOperationFailure"}}
        elif "/immutabilityPolicies/default?" in request.url:
            status = 200
            headers = {"ETag": '"retention-etag"'}
            body = {
                "id": request.url.split(
                    "https://management.azure.com", 1
                )[1].split("?", 1)[0],
                "name": "default",
                "type": (
                    "Microsoft.Storage/storageAccounts/blobServices/containers/"
                    "immutabilityPolicies"
                ),
                "properties": {
                    "allowProtectedAppendWrites": False,
                    "allowProtectedAppendWritesAll": False,
                    "immutabilityPeriodSinceCreationInDays": 30,
                    "state": "Locked",
                },
            }
        elif request.url.endswith("/federatedIdentityCredentials"):
            status = 200
            body = {"value": [{"id": LEGACY_FIC_ID, "name": "legacy"}]}
        elif (
            request.url.startswith("https://graph.microsoft.com/")
            and "displayName%20eq%20'paperdesk-release-publisher-v2-9c4e0d0d'"
            in request.url
        ):
            # Real Graph collection queries represent absence as HTTP 200 with
            # an exact empty value list, not HTTP 404.
            status = 200
            body = {"value": []}
        elif request.url == bootstrap._microsoft_graph_service_principal_inventory_url():
            status = 200
            body = {
                "value": [
                    {
                        "id": GRAPH_SERVICE_PRINCIPAL_ID,
                        "appId": bootstrap.AzureCliBootstrapTransport.GRAPH_APP_ID,
                    }
                ]
            }
        elif re.search(
            r"/providers/Microsoft\.Authorization/roleDefinitions/"
            r"([0-9a-f-]{36})\?",
            request.url,
            re.IGNORECASE,
        ):
            match = re.search(
                r"/providers/Microsoft\.Authorization/roleDefinitions/"
                r"([0-9a-f-]{36})\?",
                request.url,
                re.IGNORECASE,
            )
            definition_id = match.group(1).lower()
            temporary_definition_ids = {
                str(self.plan["temporaryAccess"][key]).lower()
                for key in (
                    "roleDefinitionId",
                    "temporaryKeyReadRoleDefinitionId",
                    "temporaryFenceRoleDefinitionId",
                    "temporaryControllerRoleDefinitionId",
                )
            }
            temporary_definition_ids.update(
                str(spec["definitionId"]).lower()
                for spec in bootstrap.RETIRED_TEMPORARY_ROLE_SPECS
            )
            if definition_id in temporary_definition_ids:
                status = 404
                body = {}
                matching = []
            else:
                matching = [
                    role
                    for role in self.plan["roleMatrix"]
                    if role.get("definitionKind") == "BuiltInRole"
                    and role["definitionId"].lower() == definition_id
                ]
            if definition_id not in temporary_definition_ids and not matching:
                raise AssertionError("unexpected built-in role-definition read")
            if matching:
                status = 200
                body = {
                    "id": (
                        f"/subscriptions/{bootstrap.SUBSCRIPTION}/providers/"
                        "Microsoft.Authorization/roleDefinitions/"
                        f"{definition_id}"
                    ),
                    "name": definition_id,
                    "type": "Microsoft.Authorization/roleDefinitions",
                    "properties": {
                        "roleName": "fixture built-in role",
                        "description": "full canonical observer fixture",
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
        elif "/providers/Microsoft.Authorization/roleDefinitions?" in request.url:
            status = 200
            definitions = bootstrap._custom_role_definition_specs(self.plan)
            values = [
                copy.deepcopy(definitions[definition_id])
                for definition_id in (
                    "b5d9d7c7-9367-4ac0-9d41-28b71e0d517d",
                    "e005b62b-037b-4989-b492-932669ec0842",
                )
            ]
            if self.role_authority_drift:
                values[0]["properties"]["permissions"][0]["dataActions"].append(
                    "Microsoft.Storage/storageAccounts/blobServices/containers/"
                    "blobs/delete"
                )
            body = {
                "value": values
            }
        elif "/providers/Microsoft.Authorization/roleAssignments?" in request.url:
            status = 200
            body = {"value": []}
        elif (
            request.url.startswith(
                "https://mdspdbak2608089c4e.blob.core.windows.net/"
                "paperdesk-deployment-packages/v2/control/"
            )
            and request.url.endswith("/paperdesk-private-release-bridge.zip")
        ):
            status = 403
            body = {"storageErrorCode": "AuthorizationPermissionMismatch"}
        elif any(
            assignment.lower() in request.url.lower()
            for assignment in (
                *self.plan["legacyPublisherRetirement"]["roleAssignmentResourceIds"],
                self.plan["legacyPublisherRetirement"][
                    "legacyWriterResultAssignmentResourceId"
                ],
                self.plan["legacyPublisherRetirement"][
                    "legacyReaderResultAssignmentResourceId"
                ],
            )
        ):
            status = 200
            body = {"properties": {"principalId": ACCOUNT_OBJECT_ID}}

        if self.credential:
            body = {"token": "Bearer secret-material"}
            status = 200
        if self.opaque_secret:
            body = {"access_token": "opaque-secret-material"}
            status = 200
        response = observe.ReadResponse(
            method=method,
            url=url,
            status=status,
            headers=headers,
            body=body,
        )
        if not self.drift and not self.credential:
            normalized_headers = {key.lower(): value for key, value in headers.items()}
            self.envelopes[(request.method, request.url)] = {
                "method": request.method,
                "url": request.url,
                "status": status,
                "headers": normalized_headers,
                "body": copy.deepcopy(body),
            }
        return response

    def assert_read_only(self, request):
        if request.method not in {"GET", "POST"}:
            raise AssertionError(f"mutation method reached fake session: {request.method}")
        if request.method == "POST" and not request.url.split("?", 1)[0].endswith(
            "/config/appsettings/list"
        ):
            raise AssertionError("non-read POST reached fake session")
        if request.body:
            raise AssertionError("read-only request carried a body")


class ResidualPublisherSession(FakeReadOnlySession):
    APP_OBJECT_ID = "11111111-1111-4111-8111-111111111111"
    APP_ID = "22222222-2222-4222-8222-222222222222"
    SERVICE_OBJECT_ID = "33333333-3333-4333-8333-333333333333"

    def __init__(
        self,
        plan,
        *,
        application_present=True,
        service_app_id=None,
        assignments=None,
        graph_services=None,
        graph_next_link=None,
    ):
        super().__init__(plan)
        self.application_present = application_present
        self.service_app_id = service_app_id or self.APP_ID
        self.assignments = [] if assignments is None else assignments
        self.graph_services = (
            [
                {
                    "id": GRAPH_SERVICE_PRINCIPAL_ID,
                    "appId": bootstrap.AzureCliBootstrapTransport.GRAPH_APP_ID,
                }
            ]
            if graph_services is None
            else graph_services
        )
        self.graph_next_link = graph_next_link

    def _response(self, request, body):
        self.requests.append(request)
        self.assert_read_only(request)
        response = observe.ReadResponse(
            method=request.method,
            url=request.url,
            status=200,
            headers={"content-type": "application/json"},
            body=body,
        )
        self.envelopes[(request.method, request.url)] = {
            "method": request.method,
            "url": request.url,
            "status": 200,
            "headers": {"content-type": "application/json"},
            "body": copy.deepcopy(body),
        }
        return response

    def read(self, request):
        if request.url == bootstrap._microsoft_graph_service_principal_inventory_url():
            body = {"value": copy.deepcopy(self.graph_services)}
            if self.graph_next_link is not None:
                body["@odata.nextLink"] = self.graph_next_link
            return self._response(request, body)
        if request.url.startswith("https://graph.microsoft.com/v1.0/applications?"):
            values = []
            if self.application_present:
                values.append(
                    {
                        "id": self.APP_OBJECT_ID,
                        "appId": self.APP_ID,
                        "displayName": self.resources["publisherApplication"]["name"],
                        "signInAudience": "AzureADMyOrg",
                        "passwordCredentials": [],
                        "keyCredentials": [],
                    }
                )
            return self._response(request, {"value": values})
        if request.url.startswith(
            "https://graph.microsoft.com/v1.0/servicePrincipals?"
        ) and "paperdesk-release-publisher-v2-9c4e0d0d" in request.url:
            return self._response(
                request,
                {
                    "value": [
                        {
                            "id": self.SERVICE_OBJECT_ID,
                            "appId": self.service_app_id,
                            "displayName": self.resources[
                                "publisherServicePrincipal"
                            ]["name"],
                            "accountEnabled": True,
                            "servicePrincipalType": "Application",
                            "passwordCredentials": [],
                            "keyCredentials": [],
                            "appRoleAssignments": copy.deepcopy(self.assignments),
                        }
                    ]
                },
            )
        if request.url.startswith("https://graph.microsoft.com/beta/applications?"):
            values = []
            if self.application_present:
                values.append(
                    {
                        "id": self.APP_OBJECT_ID,
                        "appId": self.APP_ID,
                        "displayName": self.resources["publisherApplication"]["name"],
                        "federatedIdentityCredentials": [],
                    }
                )
            return self._response(request, {"value": values})
        return super().read(request)


class ExistingPrivateContainerSession(FakeReadOnlySession):
    def __init__(self, plan, operation_id, *, projection=None):
        super().__init__(plan)
        self.operation_id = operation_id
        operation = next(item for item in plan["mutations"] if item["id"] == operation_id)
        resource = self.resources[operation["target"]]
        self.projection = projection or {
            "id": resource["resourceId"],
            "name": resource["name"],
            "type": "Microsoft.Storage/storageAccounts/blobServices/containers",
            "properties": {"publicAccess": "None"},
        }
        self.url = bootstrap._operation_readback_url(operation_id, plan, {})

    def _response(self, request, body):
        self.requests.append(request)
        self.assert_read_only(request)
        response = observe.ReadResponse(
            method=request.method,
            url=request.url,
            status=200,
            headers={"content-type": "application/json"},
            body=body,
        )
        self.envelopes[(request.method, request.url)] = {
            "method": request.method,
            "url": request.url,
            "status": 200,
            "headers": {"content-type": "application/json"},
            "body": copy.deepcopy(body),
        }
        return response

    def read(self, request):
        if request.url == self.url:
            return self._response(request, copy.deepcopy(self.projection))
        return super().read(request)


class PackageWormDeletedTombstoneSession(FakeReadOnlySession):
    def __init__(self, plan):
        super().__init__(plan)
        self.url = bootstrap._operation_readback_url(
            "lockPackageRetentionAt91Days",
            self.plan,
            {"authorizationId": AUTHORIZATION_ID},
        )

    def read(self, request):
        if request.url != self.url:
            return super().read(request)
        self.requests.append(request)
        self.assert_read_only(request)
        body = package_worm_deleted_tombstone(self.plan)
        headers = {"content-type": "application/json"}
        response = observe.ReadResponse(
            method=request.method,
            url=request.url,
            status=200,
            headers=headers,
            body=body,
        )
        self.envelopes[(request.method, request.url)] = {
            "method": request.method,
            "url": request.url,
            "status": 200,
            "headers": copy.deepcopy(headers),
            "body": copy.deepcopy(body),
        }
        return response


class ObserveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.plan_sha = bootstrap.load_plan()

    def build(self, folder, session=None):
        receipt = (
            Path(folder)
            / f"paperdesk-private-release-v2-bootstrap-{AUTHORIZATION_ID}"
        )
        selected = session or FakeReadOnlySession(self.plan)
        preflight, template = observe.build_read_only_observation(
            selected,
            source=source_evidence(),
            authorization_id=AUTHORIZATION_ID,
            receipt_directory=receipt,
            observed_at=NOW,
            uploader_ipv4="203.0.113.10/32",
        )
        return selected, preflight, template

    def promote_template(self, template):
        return {
            "schemaVersion": 1,
            "authorizationType": "paperdesk-private-release-v2-bootstrap-one-shot",
            "authorizationId": template["authorizationId"],
            "repository": template["repository"],
            "source": template["source"],
            "executor": template["executor"],
            "plan": template["plan"],
            "azure": template["azure"],
            "observedPreflight": template["observedPreflight"],
            "validity": template["proposedValidity"],
            "confirmation": {
                "encoding": "utf-8-exact-no-newline",
                "phraseSha256": bootstrap.sha256_bytes(PHRASE.encode("utf-8")),
            },
            "singleUse": template["singleUse"],
        }

    def test_end_to_end_is_read_only_exact_and_non_executable(self):
        with tempfile.TemporaryDirectory() as folder:
            session, preflight, template = self.build(folder)

            self.assertTrue(session.requests)
            self.assertTrue(all(item.method in {"GET", "POST"} for item in session.requests))
            self.assertFalse(
                any(item.method in {"PUT", "PATCH", "DELETE"} for item in session.requests)
            )

            self.assertEqual(template["executable"], False)
            self.assertEqual(template["status"], observe.TEMPLATE_STATUS)
            self.assertNotIn("authorizationType", template)
            self.assertNotIn("validity", template)
            self.assertNotIn("confirmation", template)
            self.assertEqual(
                template["requiredResidualRiskAcceptance"],
                {
                    "id": "temporary-storage-lock-and-bridge-config-residuals",
                    "exactConfirmationText": (
                        bootstrap.STORAGE_ACL_AND_RECOVERY_RESIDUAL_ACCEPTANCE
                        + " " + bootstrap.DELETION_LOCK_RESIDUAL_ACCEPTANCE
                        + " "
                        + bootstrap.BRIDGE_CONFIG_HARD_DEATH_RESIDUAL_ACCEPTANCE
                    ),
                },
            )
            self.assertIn(
                "App Service App Settings exposes no supported conditional ETag",
                template["requiredResidualRiskAcceptance"]["exactConfirmationText"],
            )
            self.assertEqual(
                template["ceremonyRequirements"],
                [
                    "independently-review-canonical-preflight",
                    "obtain-fresh-explicit-user-authorization",
                    "promote-proposedValidity-to-validity-within-freshness-window",
                    "add-exact-confirmation-phrase-sha256",
                    "include-exact-storage-acl-concurrency-residual-acceptance-in-confirmation",
                    "include-exact-bridge-app-settings-concurrency-residual-acceptance-in-confirmation",
                    "include-exact-bridge-config-hard-death-residual-acceptance-in-confirmation",
                    "emit-separate-canonical-executable-authorization",
                ],
            )

            projection = preflight["projection"]
            boundary = projection["productionBoundaryObservation"]
            self.assertEqual(
                boundary["probeIds"],
                [item["id"] for item in bootstrap._production_boundary_requests(self.plan)],
            )
            self.assertEqual(
                bootstrap._validate_production_boundary_projection(
                    boundary["sourceProjection"], self.plan
                ),
                boundary["sourceProjection"],
            )
            retired_absence = boundary["retiredTemporaryRoleAbsence"]
            preflight_schema = json.loads(
                bootstrap.PREFLIGHT_SCHEMA_PATH.read_text(encoding="utf-8")
            )
            retired_schema = preflight_schema["properties"]["projection"][
                "properties"
            ]["productionBoundaryObservation"]["properties"][
                "retiredTemporaryRoleAbsence"
            ]
            self.assertEqual(
                len(retired_absence),
                retired_schema["minItems"],
            )
            self.assertEqual(
                len(retired_absence),
                retired_schema["maxItems"],
            )
            item_schema = retired_schema["items"]
            required_fields = set(item_schema["required"])
            allowed_fields = set(item_schema["properties"])
            for item in retired_absence:
                self.assertEqual(set(item), required_fields)
                self.assertEqual(set(item), allowed_fields)
                self.assertRegex(
                    item["temporaryRoleMarkerInventorySha256"],
                    r"^[0-9a-f]{64}$",
                )
            self.assertEqual(
                bootstrap._validate_retired_temporary_role_absence_projection(
                    retired_absence,
                    self.plan,
                    label="test observer retired role absence",
                    expected_observed_at=preflight["observedAt"],
                ),
                retired_absence,
            )
            expected_retired_requests = (
                bootstrap._retired_temporary_role_absence_requests(self.plan)
            )
            self.assertEqual(
                [
                    request.url
                    for request in session.requests
                    if request.url
                    in {item["url"] for item in expected_retired_requests}
                ],
                [item["url"] for item in expected_retired_requests],
            )
            serialized_projection = json.dumps(projection, sort_keys=True)
            self.assertNotIn("FIXTURE_SECRET_SETTING_NAME", serialized_projection)
            self.assertNotIn("fixture-secret-setting-value", serialized_projection)
            self.assertFalse(
                any(
                    urllib.parse.urlsplit(request.url).hostname
                    == "mdspdbak2608089c4e.blob.core.windows.net"
                    and urllib.parse.urlsplit(request.url).path.startswith(
                        "/paperdesk-accepted-releases"
                    )
                    for request in session.requests
                )
            )
            probes = {item["id"]: item for item in projection["probes"]}
            admissions = projection["operationAdmissions"]
            admissions_by_id = {item["operationId"]: item for item in admissions}
            lock_probe = probes["preflight-cleanup-lock-inventory"]
            self.assertEqual(lock_probe["method"], "GET")
            self.assertEqual(lock_probe["url"], bootstrap._cleanup_lock_inventory_url())
            self.assertEqual(lock_probe["status"], 200)
            self.assertEqual(lock_probe["responseSha256"], bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(bootstrap._expected_cleanup_lock_inventory())))
            self.assertIn("preflight-cleanup-lock-inventory",
                          admissions_by_id["claimAzureSingleUseAuthorization"]["probeIds"])
            for operation_id in (
                "createPublisherApplication",
                "createPublisherServicePrincipal",
                "grantPublisherGraphApplicationReadAll",
                "createSolePublisherFicToSignedBootstrapSource",
            ):
                self.assertEqual(admissions_by_id[operation_id]["status"], "absent")
                self.assertEqual(
                    admissions_by_id[operation_id]["context"],
                    {"executionDecision": "apply-exact"},
                )

            role_admission = admissions_by_id["createCustomRoleDefinitions"]
            self.assertEqual(role_admission["status"], "owned-present")
            member_states = role_admission["context"]["memberStates"]
            self.assertEqual(
                member_states["b5d9d7c7-9367-4ac0-9d41-28b71e0d517d"],
                "exact",
            )
            self.assertEqual(
                member_states["e005b62b-037b-4989-b492-932669ec0842"],
                "exact",
            )
            self.assertEqual(
                sum(state == "absent" for state in member_states.values()),
                len(member_states) - 2,
            )
            self.assertEqual(
                admissions_by_id["uploadVersionedBridgePackage"]["status"],
                "network-inaccessible",
            )
            self.assertEqual(
                admissions_by_id["readBackExactSigningPublicJwk"]["status"],
                "temporary-access-inaccessible",
            )
            for operation_id in (
                "createInitialIdleActivationFence",
                "createControllerLeaseCanaryBlob",
                "exerciseControllerLeaseCanary",
                "removeControllerLeaseCanaryBlob",
            ):
                self.assertEqual(
                    admissions_by_id[operation_id]["status"],
                    "temporary-access-inaccessible",
                )
            package_worm = admissions_by_id["lockPackageRetentionAt91Days"]
            self.assertEqual(package_worm["status"], "absent")
            self.assertEqual(
                package_worm["context"],
                {"executionDecision": "apply-exact", "etag": None},
            )
            for operation_id in (
                "extendAcceptedRetentionFrom30To91Days",
                "extendResultRetentionFrom30To91Days",
            ):
                self.assertEqual(admissions_by_id[operation_id]["status"], "exact")
                self.assertEqual(
                    admissions_by_id[operation_id]["context"],
                    {
                        "executionDecision": "apply-exact",
                        "etag": '"retention-etag"',
                    },
                )
            operations = [
                item
                for item in self.plan["mutations"]
                if item["kind"] != "local-create-only-canonical-evidence"
            ]
            self.assertEqual([item["operationId"] for item in admissions], [item["id"] for item in operations])
            policy = {
                "authorizationId": template["authorizationId"],
                "source": template["source"],
                "plan": template["plan"],
                "azure": template["azure"],
                "validity": template["proposedValidity"],
                "singleUse": template["singleUse"],
            }
            for index, (operation, admission) in enumerate(zip(operations, admissions)):
                pre_probe = probes[f"preflight-{index:02d}"]
                read_probe = probes[f"readback-{index:02d}"]
                contract = bootstrap._validator_contract(
                    f"operation:{operation['id']}", self.plan, policy
                )
                context_policy = bootstrap._operation_context_policy(
                    operation["id"], self.plan, policy
                )
                self.assertEqual(
                    contract["preflightContextPolicy"], context_policy
                )
                self.assertEqual(read_probe["url"], contract["expectedUrl"])
                self.assertEqual(read_probe["method"], contract["expectedMethod"])
                self.assertEqual(read_probe["validatorContract"], contract)
                envelope = session.envelopes[(pre_probe["method"], pre_probe["url"])]
                self.assertEqual(pre_probe["responseSha256"], observe.response_digest(envelope))
                self.assertEqual(
                    pre_probe["responseSha256"],
                    bootstrap._response_sha256(
                        bootstrap._RestResponse(
                            status=envelope["status"],
                            body=bootstrap.canonical_json_bytes(envelope["body"]),
                            headers={"content-type": "application/json"},
                        )
                    ),
                )
                decision = admission["context"]["executionDecision"]
                if decision == "apply-exact":
                    self.assertEqual(
                        set(admission["context"]),
                        {"executionDecision", *context_policy["observedApplyFields"]},
                    )
                else:
                    self.assertEqual(
                        set(admission["context"]["adopted"]),
                        set(context_policy["adoptedProjectionFields"]),
                    )
                # Dynamic post-create coordinates must never be invented by observation.
                serialized = json.dumps(admission["context"], sort_keys=True)
                if admission["context"]["executionDecision"] == "apply-exact":
                    self.assertNotIn("versionId", serialized)
                    self.assertNotIn("principalId", serialized)
                    self.assertNotIn("keyUriWithVersion", serialized)

            digest = bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(projection)
            )
            self.assertEqual(preflight["projectionSha256"], digest)
            self.assertEqual(template["observedPreflight"]["sha256"], digest)
            self.assertEqual(template["plan"]["sha256"], self.plan_sha)
            self.assertEqual(
                template["plan"]["bridgePackageSha256"],
                bootstrap.build_package_descriptor()["sha256"],
            )

            template_path = Path(folder) / "authorization-template.json"
            observe.write_canonical(template_path, template)
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.validate_authorization(
                    template_path,
                    plan=self.plan,
                    plan_sha256=self.plan_sha,
                    package=bootstrap.build_package_descriptor(),
                    confirmation_phrase="not-an-authorization",
                    now=NOW,
                )

            authorization = self.promote_template(template)
            authorization_path = Path(folder) / "authorization-after-ceremony.json"
            preflight_path = Path(folder) / "preflight.json"
            observe.write_canonical(authorization_path, authorization)
            observe.write_canonical(preflight_path, preflight)
            validated = bootstrap.validate_authorization(
                authorization_path,
                plan=self.plan,
                plan_sha256=self.plan_sha,
                package=bootstrap.build_package_descriptor(),
                confirmation_phrase=PHRASE,
                now=NOW,
            )
            validated_preflight, validated_digest = bootstrap.validate_preflight_document(
                preflight_path, validated.document, self.plan
            )
            self.assertEqual(validated_preflight, preflight)
            self.assertEqual(validated_digest, digest)

    def test_previous_bridge_phrase_cannot_authorize_no_cas_settings_put(self):
        with tempfile.TemporaryDirectory() as folder:
            _session, _preflight, template = self.build(folder)
            authorization = self.promote_template(template)
            self.assertEqual(
                authorization["confirmation"]["phraseSha256"],
                bootstrap.sha256_bytes(PHRASE.encode("utf-8")),
            )
            old_phrase = (
                "Authorize the separately reviewed exact PaperDesk V2 bootstrap. "
                + bootstrap.STORAGE_ACL_AND_RECOVERY_RESIDUAL_ACCEPTANCE
                + " "
                + bootstrap.DELETION_LOCK_RESIDUAL_ACCEPTANCE
                + " I accept that process death after the bridge configuration or "
                "site-start request can leave a consumed use ledger and durable "
                "unresolved mutation intent while the bridge site remains changed or "
                "running. Recovery may require an exact site stop and conditional "
                "restoration of the source-bound prestate under a separate explicit "
                "authorization; every fresh apply must stop until that durable intent "
                "and live state are fully resolved."
            )
            authorization["confirmation"]["phraseSha256"] = (
                bootstrap.sha256_bytes(old_phrase.encode("utf-8"))
            )
            authorization_path = Path(folder) / "old-phrase-authorization.json"
            observe.write_canonical(authorization_path, authorization)

            with self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "bridge App Settings concurrency and hard-death recovery residuals",
            ):
                bootstrap.validate_authorization(
                    authorization_path,
                    plan=self.plan,
                    plan_sha256=self.plan_sha,
                    package=bootstrap.build_package_descriptor(),
                    confirmation_phrase=old_phrase,
                    now=NOW,
                )

    def test_read_only_observer_blocks_any_present_retired_role(self):
        expected = bootstrap._retired_temporary_role_absence_requests(self.plan)

        for present in expected:
            with self.subTest(kind=present["kind"], resourceId=present["resourceId"]):
                class PresentRetiredRoleSession(FakeReadOnlySession):
                    def read(inner_self, request):
                        response = super(PresentRetiredRoleSession, inner_self).read(
                            request
                        )
                        if request.url == present["url"]:
                            return observe.ReadResponse(
                                method=request.method,
                                url=request.url,
                                status=200,
                                headers={},
                                body={"id": present["resourceId"]},
                            )
                        return response

                with tempfile.TemporaryDirectory() as folder:
                    with self.assertRaisesRegex(
                        observe.ObserveError, "found a retired temporary role"
                    ):
                        self.build(folder, PresentRetiredRoleSession(self.plan))

    def test_exact_five_bridge_recovery_is_jointly_admitted_without_attach_write(self):
        with tempfile.TemporaryDirectory() as folder:
            _session, _preflight, template = self.build(folder)
        authorization = self.promote_template(template)
        resources = {item["id"]: item for item in self.plan["resourceInventory"]}
        dependency_facts = {}
        attached = {}
        for dependency, key in (
            ("createBridgeIdentity", "bridgeIdentity"),
            ("adoptExistingRegistryWriterIdentity", "registryWriterIdentity"),
            ("adoptExistingRegistryReaderIdentity", "registryReaderIdentity"),
            ("createSignerIdentity", "signerIdentity"),
            ("createProductionActivationIdentity", "productionActivationIdentity"),
        ):
            resource = resources[key]
            client_id = resource.get("clientId") or str(
                uuid.uuid5(uuid.UUID(AUTHORIZATION_ID), key + ":client")
            )
            principal_id = resource.get("principalId") or str(
                uuid.uuid5(uuid.UUID(AUTHORIZATION_ID), key + ":principal")
            )
            dependency_facts[dependency] = {
                "resourceId": resource["resourceId"],
                "clientId": client_id,
                "principalId": principal_id,
            }
            attached[resource["resourceId"]] = {
                "clientId": client_id,
                "principalId": principal_id,
            }
        bridge = resources["bridgeSite"]
        envelope = {
            "status": 200,
            "headers": {"etag": '"bridge-recovery-etag"'},
            "body": {
                "id": bridge["resourceId"],
                "name": bridge["name"],
                "type": "Microsoft.Web/sites",
                "kind": "app,linux",
                "identity": {
                    "type": "UserAssigned",
                    "principalId": None,
                    "tenantId": None,
                    "userAssignedIdentities": attached,
                },
                "properties": {
                    "state": "Stopped",
                    "httpsOnly": True,
                    "publicNetworkAccess": "Disabled",
                    "serverFarmId": resources["bridgeAppServicePlan"]["resourceId"],
                    "virtualNetworkSubnetId": resources["integrationSubnet"]["resourceId"],
                    "outboundVnetRouting": {
                        "allTraffic": True,
                        "applicationTraffic": True,
                    },
                },
            },
        }
        operations = {item["id"]: item for item in self.plan["mutations"]}
        create_policy = bootstrap._operation_context_policy(
            "createStoppedPrivateBridge", self.plan, authorization
        )
        _status, create_context = observe._operation_admission(
            operations["createStoppedPrivateBridge"], envelope, self.plan,
            authorization, NOW, "203.0.113.10/32", create_policy,
            dependency_facts,
        )
        self.assertEqual(
            create_context["adopted"]["bridgeIdentityMode"],
            "exact-five-user-assigned",
        )
        dependency_facts["createStoppedPrivateBridge"] = create_context["adopted"]
        attach_policy = bootstrap._operation_context_policy(
            "attachFiveUamisOnlyToBridge", self.plan, authorization
        )
        _status, attach_context = observe._operation_admission(
            operations["attachFiveUamisOnlyToBridge"], envelope, self.plan,
            authorization, NOW, "203.0.113.10/32", attach_policy,
            dependency_facts,
        )
        self.assertEqual(attach_context["executionDecision"], "adopt-exact")
        self.assertEqual(
            attach_context["adopted"]["identityResourceIds"],
            create_context["adopted"]["identityResourceIds"],
        )

        invalid = {}
        missing = copy.deepcopy(envelope)
        missing["body"]["identity"]["userAssignedIdentities"].pop(
            next(iter(attached))
        )
        invalid["missing identity"] = missing
        extra = copy.deepcopy(envelope)
        extra["body"]["identity"]["userAssignedIdentities"][
            "/subscriptions/00000000-0000-0000-0000-000000000000/"
            "resourceGroups/extra/providers/Microsoft.ManagedIdentity/"
            "userAssignedIdentities/extra"
        ] = {
            "clientId": "11111111-1111-4111-8111-111111111111",
            "principalId": "22222222-2222-4222-8222-222222222222",
        }
        invalid["extra identity"] = extra
        mixed = copy.deepcopy(envelope)
        mixed["body"]["identity"]["type"] = "SystemAssigned, UserAssigned"
        invalid["mixed system identity"] = mixed
        malformed = copy.deepcopy(envelope)
        first = next(iter(malformed["body"]["identity"]["userAssignedIdentities"]))
        malformed["body"]["identity"]["userAssignedIdentities"][first][
            "clientId"
        ] = "not-a-guid"
        invalid["malformed client metadata"] = malformed
        malformed_principal = copy.deepcopy(envelope)
        first = next(iter(malformed_principal["body"]["identity"]["userAssignedIdentities"]))
        malformed_principal["body"]["identity"]["userAssignedIdentities"][first][
            "principalId"
        ] = "not-a-guid"
        invalid["malformed principal metadata"] = malformed_principal
        for label, candidate in invalid.items():
            with self.subTest(label=label), self.assertRaises(
                (observe.ObserveError, bootstrap.BootstrapError)
            ):
                observe._operation_admission(
                    operations["createStoppedPrivateBridge"], candidate,
                    self.plan, authorization, NOW, "203.0.113.10/32",
                    create_policy, dependency_facts,
                )

    def test_full_observer_recovers_exact_five_from_live_fixed_identity_projections(self):
        class ExactFiveBridgeSession(FakeReadOnlySession):
            def __init__(self, plan):
                super().__init__(plan)
                self.live_ids = {}
                for key in (
                    "bridgeIdentity", "registryWriterIdentity",
                    "registryReaderIdentity", "signerIdentity",
                    "productionActivationIdentity",
                ):
                    resource = self.resources[key]
                    self.live_ids[key] = {
                        "clientId": resource.get("clientId") or str(
                            uuid.uuid5(uuid.UUID(AUTHORIZATION_ID), key + ":client")
                        ),
                        "principalId": resource.get("principalId") or str(
                            uuid.uuid5(uuid.UUID(AUTHORIZATION_ID), key + ":principal")
                        ),
                    }

            def read(self, request):
                response = super().read(request)
                for key, ids in self.live_ids.items():
                    resource = self.resources[key]
                    if request.url.startswith(
                        f"https://management.azure.com{resource['resourceId']}?"
                    ):
                        return observe.ReadResponse(
                            method=response.method, url=response.url, status=200,
                            headers={}, body={
                                "id": resource["resourceId"],
                                "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                                "properties": {
                                    "tenantId": bootstrap.TENANT, **ids,
                                },
                            },
                        )
                bridge = self.resources["bridgeSite"]
                expected_url = bootstrap._operation_readback_url(
                    "createStoppedPrivateBridge", self.plan, {}
                )
                if request.method == "GET" and request.url == expected_url:
                    attached = {}
                    for key in (
                        "bridgeIdentity", "registryWriterIdentity",
                        "registryReaderIdentity", "signerIdentity",
                        "productionActivationIdentity",
                    ):
                        identity = self.resources[key]
                        attached[identity["resourceId"]] = {
                            **self.live_ids[key],
                        }
                    return observe.ReadResponse(
                        method=response.method, url=response.url, status=200,
                        headers={"ETag": '"live-exact-five"'},
                        body={
                            "id": bridge["resourceId"], "name": bridge["name"],
                            "type": "Microsoft.Web/sites", "kind": "app,linux",
                            "identity": {
                                "type": "UserAssigned", "principalId": None,
                                "tenantId": None,
                                "userAssignedIdentities": attached,
                            },
                            "properties": {
                                "state": "Stopped", "httpsOnly": True,
                                "publicNetworkAccess": "Disabled",
                                "serverFarmId": self.resources["bridgeAppServicePlan"]["resourceId"],
                                "virtualNetworkSubnetId": self.resources["integrationSubnet"]["resourceId"],
                                "outboundVnetRouting": {
                                    "allTraffic": True, "applicationTraffic": True,
                                },
                            },
                        },
                    )
                return response

        with tempfile.TemporaryDirectory() as folder:
            _session, preflight, template = self.build(
                folder, ExactFiveBridgeSession(self.plan)
            )
        admissions = {
            item["operationId"]: item
            for item in preflight["projection"]["operationAdmissions"]
        }
        self.assertEqual(
            admissions["adoptExistingRegistryWriterIdentity"]["context"],
            {"executionDecision": "adopt-exact", "adopted": {}},
        )
        self.assertEqual(
            admissions["adoptExistingRegistryReaderIdentity"]["context"],
            {"executionDecision": "adopt-exact", "adopted": {}},
        )
        self.assertEqual(
            admissions["createStoppedPrivateBridge"]["context"]["adopted"]["bridgeIdentityMode"],
            "exact-five-user-assigned",
        )
        self.assertEqual(
            admissions["attachFiveUamisOnlyToBridge"]["context"]["executionDecision"],
            "adopt-exact",
        )
        bootstrap.validate_preflight_evidence(
            preflight, self.promote_template(template), self.plan
        )

    def test_full_observer_rejects_fixed_registry_live_identity_id_drift(self):
        for field in ("clientId", "principalId"):
            class DriftedRegistryIdentitySession(FakeReadOnlySession):
                def read(inner_self, request):
                    response = super(DriftedRegistryIdentitySession, inner_self).read(request)
                    writer = inner_self.resources["registryWriterIdentity"]
                    if request.url.startswith(
                        f"https://management.azure.com{writer['resourceId']}?"
                    ):
                        body = copy.deepcopy(response.body)
                        body["properties"][field] = (
                            "33333333-3333-4333-8333-333333333333"
                        )
                        return observe.ReadResponse(
                            method=response.method, url=response.url,
                            status=response.status, headers=response.headers,
                            body=body,
                        )
                    return response

            with self.subTest(field=field), tempfile.TemporaryDirectory() as folder:
                with self.assertRaisesRegex(
                    observe.ObserveError, "fixed registry identity live projection drifted"
                ):
                    self.build(folder, DriftedRegistryIdentitySession(self.plan))

    def test_live_identity_dependency_rejects_missing_or_unsafe_arm_projection(self):
        resource = next(
            item for item in self.plan["resourceInventory"]
            if item["id"] == "registryWriterIdentity"
        )
        exact = {
            "status": 200,
            "body": {
                "id": resource["resourceId"],
                "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                "properties": {
                    "tenantId": bootstrap.TENANT,
                    "clientId": resource["clientId"],
                    "principalId": resource["principalId"],
                },
            },
        }
        variants = {}
        for field in ("clientId", "principalId"):
            missing = copy.deepcopy(exact)
            missing["body"]["properties"].pop(field)
            variants[f"missing {field}"] = missing
            null = copy.deepcopy(exact)
            null["body"]["properties"][field] = None
            variants[f"null {field}"] = null
            malformed = copy.deepcopy(exact)
            malformed["body"]["properties"][field] = "not-a-guid"
            variants[f"malformed {field}"] = malformed
        wrong_resource = copy.deepcopy(exact)
        wrong_resource["body"]["id"] += "-other"
        variants["wrong resource"] = wrong_resource
        wrong_type = copy.deepcopy(exact)
        wrong_type["body"]["type"] = "Microsoft.Web/sites"
        variants["wrong type"] = wrong_type
        wrong_tenant = copy.deepcopy(exact)
        wrong_tenant["body"]["properties"]["tenantId"] = (
            "44444444-4444-4444-8444-444444444444"
        )
        variants["wrong tenant"] = wrong_tenant
        absent = copy.deepcopy(exact)
        absent["status"] = 404
        variants["404 cannot use plan metadata"] = absent
        for label, envelope in variants.items():
            with self.subTest(label=label), self.assertRaisesRegex(
                observe.ObserveError,
                "managed identity adoption response drifted from the fixed resource",
            ):
                observe._identity_adopted(envelope, resource["resourceId"])

    def test_residual_publisher_application_and_service_principal_are_adopted(self):
        with tempfile.TemporaryDirectory() as folder:
            session = ResidualPublisherSession(self.plan)
            _session, preflight, template = self.build(folder, session)

        admissions = {
            item["operationId"]: item
            for item in preflight["projection"]["operationAdmissions"]
        }
        self.assertEqual(
            admissions["createPublisherApplication"]["context"],
            {
                "executionDecision": "adopt-exact",
                "adopted": {
                    "objectId": session.APP_OBJECT_ID,
                    "appId": session.APP_ID,
                },
            },
        )
        self.assertEqual(
            admissions["createPublisherServicePrincipal"]["context"],
            {
                "executionDecision": "adopt-exact",
                "adopted": {
                    "objectId": session.SERVICE_OBJECT_ID,
                    "appId": session.APP_ID,
                    "principalId": session.SERVICE_OBJECT_ID,
                },
            },
        )
        self.assertEqual(
            admissions["grantPublisherGraphApplicationReadAll"]["status"],
            "absent",
        )
        self.assertEqual(
            admissions["grantPublisherGraphApplicationReadAll"]["context"],
            {"executionDecision": "apply-exact"},
        )
        authorization = self.promote_template(template)
        validated, _digest = bootstrap.validate_preflight_evidence(
            preflight, authorization, self.plan
        )
        self.assertEqual(validated, preflight)

    def test_residual_service_principal_must_match_an_adopted_application(self):
        cases = (
            ResidualPublisherSession(
                self.plan,
                service_app_id="44444444-4444-4444-8444-444444444444",
            ),
            ResidualPublisherSession(self.plan, application_present=False),
        )
        for session in cases:
            with self.subTest(
                application_present=session.application_present,
                service_app_id=session.service_app_id,
            ), tempfile.TemporaryDirectory() as folder:
                with self.assertRaisesRegex(
                    observe.ObserveError,
                    "publisher service principal is not bound to the adopted application",
                ):
                    self.build(folder, session)

    def test_preexisting_exact_publisher_graph_assignment_is_adopted_without_graph_post(self):
        assignment = {
            "id": CANONICAL_GRAPH_ASSIGNMENT_ID,
            "principalId": ResidualPublisherSession.SERVICE_OBJECT_ID,
            "resourceId": GRAPH_SERVICE_PRINCIPAL_ID,
            "appRoleId": bootstrap.AzureCliBootstrapTransport.GRAPH_APPLICATION_READ_ALL,
        }
        session = ResidualPublisherSession(self.plan, assignments=[assignment])
        with tempfile.TemporaryDirectory() as folder:
            _session, preflight, template = self.build(folder, session)
        admission = next(
            item
            for item in preflight["projection"]["operationAdmissions"]
            if item["operationId"] == "grantPublisherGraphApplicationReadAll"
        )
        self.assertEqual(admission["status"], "exact")
        self.assertEqual(
            admission["context"],
            {
                "executionDecision": "adopt-exact",
                "adopted": {
                    "assignmentId": assignment["id"],
                    "resourceId": GRAPH_SERVICE_PRINCIPAL_ID,
                },
            },
        )
        authorization = self.promote_template(template)
        validated, _digest = bootstrap.validate_preflight_evidence(
            preflight, authorization, self.plan
        )
        self.assertEqual(validated, preflight)
        self.assertFalse(
            any(
                request.method == "POST"
                and urllib.parse.urlsplit(request.url).hostname
                == "graph.microsoft.com"
                for request in session.requests
            )
        )
        transport = object.__new__(bootstrap.AzureCliBootstrapTransport)
        transport.admissions = {
            "grantPublisherGraphApplicationReadAll": admission
        }
        mutations = []
        transport._mutate = lambda operation, state: mutations.append(
            (operation, state)
        )
        transport._prove_probe_ids = (
            lambda probe_ids, label, *, runtime_facts: []
        )
        result = transport.apply_operation(
            {"id": "grantPublisherGraphApplicationReadAll"}, {}
        )
        self.assertEqual(result["status"], "adopted-exact")
        self.assertEqual(mutations, [])

    def test_publisher_graph_service_principal_inventory_must_be_fixed_unique_and_complete(self):
        assignment = {
            "id": "55555555-5555-4555-8555-555555555555",
            "principalId": ResidualPublisherSession.SERVICE_OBJECT_ID,
            "resourceId": GRAPH_SERVICE_PRINCIPAL_ID,
            "appRoleId": bootstrap.AzureCliBootstrapTransport.GRAPH_APPLICATION_READ_ALL,
        }
        exact = {
            "id": GRAPH_SERVICE_PRINCIPAL_ID,
            "appId": bootstrap.AzureCliBootstrapTransport.GRAPH_APP_ID,
        }
        cases = (
            ([], None, "must resolve to exactly one Graph object"),
            (
                [exact, copy.deepcopy(exact)],
                None,
                "must resolve to exactly one Graph object",
            ),
            (
                [exact],
                "https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=next",
                "Graph collection is partial or invalid",
            ),
            (
                [
                    {
                        "id": GRAPH_SERVICE_PRINCIPAL_ID,
                        "appId": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
                    }
                ],
                None,
                "inventory is not exact",
            ),
        )
        for graph_services, next_link, message in cases:
            with self.subTest(
                count=len(graph_services),
                next_link=next_link,
                app_id=(graph_services[0]["appId"] if graph_services else None),
            ), tempfile.TemporaryDirectory() as folder, self.assertRaisesRegex(
                (observe.ObserveError, bootstrap.BootstrapError), message
            ):
                self.build(
                    folder,
                    ResidualPublisherSession(
                        self.plan,
                        assignments=[assignment],
                        graph_services=graph_services,
                        graph_next_link=next_link,
                    ),
                )

    def test_publisher_graph_assignment_must_be_sole_and_exact(self):
        exact = {
            "id": CANONICAL_GRAPH_ASSIGNMENT_ID,
            "principalId": ResidualPublisherSession.SERVICE_OBJECT_ID,
            "resourceId": GRAPH_SERVICE_PRINCIPAL_ID,
            "appRoleId": bootstrap.AzureCliBootstrapTransport.GRAPH_APPLICATION_READ_ALL,
        }
        variants = []
        wrong_principal = copy.deepcopy(exact)
        wrong_principal["principalId"] = "66666666-6666-4666-8666-666666666666"
        variants.append([wrong_principal])
        wrong_resource = copy.deepcopy(exact)
        wrong_resource["resourceId"] = "77777777-7777-4777-8777-777777777777"
        variants.append([wrong_resource])
        wrong_role = copy.deepcopy(exact)
        wrong_role["appRoleId"] = "88888888-8888-4888-8888-888888888888"
        variants.append([wrong_role])
        malformed_ids = (
            CANONICAL_GRAPH_ASSIGNMENT_ID[:-1],
            CANONICAL_GRAPH_ASSIGNMENT_ID + "A",
            CANONICAL_GRAPH_ASSIGNMENT_ID + "=",
            CANONICAL_GRAPH_ASSIGNMENT_ID[:-1] + "+",
            CANONICAL_GRAPH_ASSIGNMENT_ID[:-1] + "9",
        )
        for value in malformed_ids:
            malformed_id = copy.deepcopy(exact)
            malformed_id["id"] = value
            variants.append([malformed_id])
        missing_id = copy.deepcopy(exact)
        missing_id.pop("id")
        variants.append([missing_id])
        extra_key = copy.deepcopy(exact)
        extra_key["unexpected"] = True
        variants.append([extra_key])
        variants.append([exact, copy.deepcopy(exact)])
        for assignments in variants:
            with self.subTest(assignments=assignments), tempfile.TemporaryDirectory() as folder, self.assertRaisesRegex(
                (observe.ObserveError, bootstrap.BootstrapError),
                "not sole and exact|adoption is not sole|not an exact Microsoft Graph assignment ID",
            ):
                self.build(
                    folder,
                    ResidualPublisherSession(self.plan, assignments=assignments),
                )

    def test_existing_package_and_activation_containers_are_adopted_only_when_exact_private(self):
        for operation_id in (
            "createPrivatePackageContainer",
            "createPrivateActivationFenceContainer",
        ):
            with self.subTest(operation_id=operation_id), tempfile.TemporaryDirectory() as folder:
                _session, preflight, template = self.build(
                    folder, ExistingPrivateContainerSession(self.plan, operation_id)
                )
            admission = next(
                item
                for item in preflight["projection"]["operationAdmissions"]
                if item["operationId"] == operation_id
            )
            self.assertEqual(admission["status"], "exact")
            self.assertEqual(
                admission["context"],
                {"executionDecision": "adopt-exact", "adopted": {}},
            )
            bootstrap.validate_preflight_evidence(
                preflight, self.promote_template(template), self.plan
            )

    def test_existing_private_container_rejects_any_identity_or_privacy_drift(self):
        operation_id = "createPrivatePackageContainer"
        operation = next(
            item for item in self.plan["mutations"] if item["id"] == operation_id
        )
        resource = next(
            item
            for item in self.plan["resourceInventory"]
            if item["id"] == operation["target"]
        )
        exact = {
            "id": resource["resourceId"],
            "name": resource["name"],
            "type": "Microsoft.Storage/storageAccounts/blobServices/containers",
            "properties": {"publicAccess": "None"},
        }
        variants = []
        wrong_id = copy.deepcopy(exact)
        wrong_id["id"] = next(
            item["resourceId"]
            for item in self.plan["resourceInventory"]
            if item["id"] == "storageAccount"
        )
        variants.append(wrong_id)
        wrong_name = copy.deepcopy(exact)
        wrong_name["name"] = f"default/{resource['name']}"
        variants.append(wrong_name)
        wrong_type = copy.deepcopy(exact)
        wrong_type["type"] = "Microsoft.Storage/storageAccounts"
        variants.append(wrong_type)
        public = copy.deepcopy(exact)
        public["properties"]["publicAccess"] = "Container"
        variants.append(public)
        for projection in variants:
            with self.subTest(projection=projection), tempfile.TemporaryDirectory() as folder, self.assertRaisesRegex(
                (observe.ObserveError, bootstrap.BootstrapError),
                "terminal container is not private and exact",
            ):
                self.build(
                    folder,
                    ExistingPrivateContainerSession(
                        self.plan, operation_id, projection=projection
                    ),
                )

    def test_existing_controller_lock_container_is_pending_execution_empty_proof(self):
        with tempfile.TemporaryDirectory() as folder:
            _session, preflight, template = self.build(
                folder,
                ExistingPrivateContainerSession(
                    self.plan, "createPrivateControllerLockContainer"
                ),
            )
        admission = next(
            item
            for item in preflight["projection"]["operationAdmissions"]
            if item["operationId"] == "createPrivateControllerLockContainer"
        )
        self.assertEqual(
            admission,
            {
                "operationId": "createPrivateControllerLockContainer",
                "status": "adopt-pending-execution-empty-proof",
                "probeIds": admission["probeIds"],
                "desiredProbeIds": admission["desiredProbeIds"],
                "context": {
                    "executionDecision": "adopt-pending-execution-empty-proof"
                },
            },
        )
        bootstrap.validate_preflight_evidence(
            preflight, self.promote_template(template), self.plan
        )

    def test_adopted_signing_key_context_retains_live_expiry(self):
        operation = next(
            item
            for item in self.plan["mutations"]
            if item["id"] == "createSigningKeyVersion"
        )
        expiry = NOW + dt.timedelta(days=60)
        envelope = {
            "headers": {},
            "body": {
                "properties": {
                    "keyUriWithVersion": (
                        "https://kv-mds-sea-9c4e0d0d.vault.azure.net/keys/"
                        "paperdesk-release-result-signing/" + "c" * 32
                    ),
                    "attributes": {"exp": int(expiry.timestamp())},
                }
            },
        }
        policy = bootstrap._operation_context_policy(
            operation["id"], self.plan, {}
        )
        adopted = observe._adopted_projection(
            operation, envelope, self.plan, {}, policy
        )
        self.assertEqual(adopted["expiresAt"], observe._stamp(expiry))
        missing = copy.deepcopy(envelope)
        del missing["body"]["properties"]["attributes"]["exp"]
        with self.assertRaisesRegex(observe.ObserveError, "live expiry"):
            observe._adopted_projection(
                operation, missing, self.plan, {}, policy
            )

    def test_apply_context_still_cannot_author_executor_dependency(self):
        policy = copy.deepcopy(
            bootstrap._operation_context_policy(
                "createPublisherServicePrincipal", self.plan, {}
            )
        )
        policy["observedApplyFields"] = ["appId"]
        with self.assertRaisesRegex(
            observe.ObserveError,
            "preflight authors executor-derived dependency",
        ):
            observe._policy_checked_context(
                "createPublisherServicePrincipal",
                policy,
                {
                    "executionDecision": "apply-exact",
                    "appId": ResidualPublisherSession.APP_ID,
                },
            )

    def test_service_principal_readback_requires_materialized_unpaginated_assignments(self):
        with tempfile.TemporaryDirectory() as folder:
            _session, preflight, template = self.build(folder)
        authorization = self.promote_template(template)
        probes = {
            item["validatorContract"]["operationId"]: item
            for item in preflight["projection"]["probes"]
            if item["phase"] == "readback"
            and isinstance(item.get("validatorContract"), dict)
            and item["validatorContract"].get("kind")
            == "source-operation-invariants-v1"
        }

        class NoRequestSession:
            def request(self, *_args, **_kwargs):
                raise AssertionError("direct readback validation attempted a request")

        def response(document):
            return bootstrap._RestResponse(
                status=200,
                body=bootstrap.canonical_json_bytes(document),
                headers={"content-type": "application/json"},
            )

        def transport_with_application():
            transport = bootstrap.AzureCliBootstrapTransport(
                authorization=authorization,
                plan=self.plan,
                package=bootstrap.build_package_descriptor(),
                preflight=preflight,
                clock=lambda: NOW,
                sleep=lambda _seconds: None,
                session=NoRequestSession(),
            )
            application = {
                "id": ResidualPublisherSession.APP_OBJECT_ID,
                "appId": ResidualPublisherSession.APP_ID,
                "displayName": next(
                    item["name"]
                    for item in self.plan["resourceInventory"]
                    if item["id"] == "publisherApplication"
                ),
                "signInAudience": "AzureADMyOrg",
                "passwordCredentials": [],
                "keyCredentials": [],
            }
            transport._validate_readback_response(
                probes["createPublisherApplication"],
                response({"value": [application]}),
                runtime_facts={
                    "objectId": application["id"],
                    "appId": application["appId"],
                },
            )
            return transport

        service = {
            "id": ResidualPublisherSession.SERVICE_OBJECT_ID,
            "appId": ResidualPublisherSession.APP_ID,
            "displayName": next(
                item["name"]
                for item in self.plan["resourceInventory"]
                if item["id"] == "publisherServicePrincipal"
            ),
            "accountEnabled": True,
            "servicePrincipalType": "Application",
            "passwordCredentials": [],
            "keyCredentials": [],
            "appRoleAssignments": [],
            "appRoleAssignments@odata.context": "https://graph.microsoft.com/v1.0/$metadata#appRoleAssignments",
            "tags": [],
        }
        facts = {
            "objectId": service["id"],
            "appId": service["appId"],
            "principalId": service["id"],
        }
        proof = transport_with_application()._validate_readback_response(
            probes["createPublisherServicePrincipal"],
            response(
                {
                    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#servicePrincipals",
                    "value": [service],
                }
            ),
            runtime_facts=facts,
        )
        self.assertEqual(
            set(proof["sourceProjection"]["projection"]),
            {
                "id",
                "appId",
                "displayName",
                "accountEnabled",
                "servicePrincipalType",
                "passwordCredentials",
                "keyCredentials",
                "appRoleAssignments",
            },
        )

        broken = []
        omitted = copy.deepcopy(service)
        omitted.pop("appRoleAssignments")
        broken.append(omitted)
        null_relationship = copy.deepcopy(service)
        null_relationship["appRoleAssignments"] = None
        broken.append(null_relationship)
        paginated = copy.deepcopy(service)
        paginated["appRoleAssignments@odata.nextLink"] = (
            "https://graph.microsoft.com/v1.0/next"
        )
        broken.append(paginated)
        nonempty = copy.deepcopy(service)
        nonempty["appRoleAssignments"] = [
            {
                "id": "55555555-5555-4555-8555-555555555555",
                "principalId": ResidualPublisherSession.SERVICE_OBJECT_ID,
                "resourceId": "66666666-6666-4666-8666-666666666666",
                "appRoleId": bootstrap.AzureCliBootstrapTransport.GRAPH_APPLICATION_READ_ALL,
            }
        ]
        broken.append(nonempty)
        for candidate in broken:
            with self.subTest(keys=sorted(candidate)), self.assertRaises(
                bootstrap.BootstrapError
            ):
                transport_with_application()._validate_readback_response(
                    probes["createPublisherServicePrincipal"],
                    response({"value": [candidate]}),
                    runtime_facts=facts,
                )

    def test_observed_production_boundary_matches_executor_fresh_preflight(self):
        with tempfile.TemporaryDirectory() as folder:
            session, preflight, _template = self.build(folder)

        class BoundaryRestSession:
            def request(
                self, method, url, *, body=None, headers=None, deadline=None
            ):
                self.assert_request(method, url, body, headers)
                envelope = session.envelopes[(method, url)]
                return bootstrap._RestResponse(
                    status=envelope["status"],
                    body=bootstrap.canonical_json_bytes(envelope["body"]),
                    headers={"content-type": "application/json"},
                )

            @staticmethod
            def assert_request(method, url, body, headers):
                if method == "POST":
                    if body != b"":
                        raise AssertionError("app-settings boundary read lost its empty body")
                elif method != "GET" or body is not None:
                    raise AssertionError("production boundary request shape drifted")
                if headers is not None:
                    raise AssertionError("production boundary read added unexpected headers")

        transport = bootstrap.AzureCliBootstrapTransport(
            authorization={"authorizationId": AUTHORIZATION_ID, "azure": {}},
            plan=self.plan,
            package={},
            preflight=preflight,
            session=BoundaryRestSession(),
        )
        fresh_source, fresh_probes = transport._collect_production_boundary()
        observed = preflight["projection"]["productionBoundaryObservation"]
        observed_probes = {
            item["id"]: item
            for item in preflight["projection"]["probes"]
            if item["id"] in observed["probeIds"]
        }
        self.assertEqual(fresh_source, observed["sourceProjection"])
        self.assertEqual(fresh_probes, observed_probes)
        app_settings_probe = fresh_probes["production-boundary-app-settings"]
        self.assertEqual(
            app_settings_probe["responseSha256"],
            bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(
                    {"properties": {"FIXTURE_SECRET_SETTING_NAME": "fixture-secret-setting-value"}}
                )
            ),
        )

    def test_output_is_deterministic_for_identical_read_state(self):
        with tempfile.TemporaryDirectory() as folder:
            _, preflight_a, template_a = self.build(folder)
            _, preflight_b, template_b = self.build(folder)
        self.assertEqual(
            bootstrap.canonical_json_bytes(preflight_a),
            bootstrap.canonical_json_bytes(preflight_b),
        )
        self.assertEqual(
            bootstrap.canonical_json_bytes(template_a),
            bootstrap.canonical_json_bytes(template_b),
        )

    def test_builtin_role_definitions_are_full_preflight_bound_and_exact(self):
        with tempfile.TemporaryDirectory() as folder:
            session, preflight, _template = self.build(folder)
        admission = next(
            item
            for item in preflight["projection"]["operationAdmissions"]
            if item["operationId"] == "createCustomRoleDefinitions"
        )
        bodies = admission["context"]["builtInRoleDefinitionProjections"]
        self.assertEqual(
            bootstrap._validate_builtin_role_definition_projections(
                bodies, self.plan
            ),
            bodies,
        )
        self.assertEqual(len(bodies), 2)
        built_in_ids = {
            role["definitionId"].lower()
            for role in self.plan["roleMatrix"]
            if role.get("definitionKind") == "BuiltInRole"
        }
        self.assertEqual(
            len(
                [
                    request
                    for request in session.requests
                    if any(
                        f"/roledefinitions/{definition_id}?" in request.url.lower()
                        for definition_id in built_in_ids
                    )
                ]
            ),
            2,
        )
        variants = []
        missing = copy.deepcopy(bodies)
        missing.pop(next(iter(missing)))
        variants.append(missing)
        extra = copy.deepcopy(bodies)
        extra["00000000-0000-4000-8000-000000000001"] = copy.deepcopy(
            next(iter(bodies.values()))
        )
        variants.append(extra)
        drifted = copy.deepcopy(bodies)
        drifted[next(iter(drifted))]["properties"]["type"] = "CustomRole"
        variants.append(drifted)
        for candidate in variants:
            with self.subTest(keys=sorted(candidate)):
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap._validate_builtin_role_definition_projections(
                        candidate, self.plan
                    )

    def test_production_boundary_rejects_malformed_or_paginated_inventories(self):
        with tempfile.TemporaryDirectory() as folder:
            _session, preflight, _template = self.build(folder)
        projection = preflight["projection"]["productionBoundaryObservation"][
            "sourceProjection"
        ]
        variants = []
        bad_site = copy.deepcopy(projection)
        bad_site["sitePosture"]["outboundVnetRouting"]["allTraffic"] = True
        variants.append(bad_site)
        duplicate_deployment = copy.deepcopy(projection)
        duplicate_deployment["deploymentInventory"].append(
            copy.deepcopy(duplicate_deployment["deploymentInventory"][0])
        )
        variants.append(duplicate_deployment)
        bad_onedeploy = copy.deepcopy(projection)
        bad_onedeploy["oneDeployInventory"][0]["name"] = "wrong/onedeploy"
        variants.append(bad_onedeploy)
        for candidate in variants:
            with self.subTest(candidate=candidate):
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap._validate_production_boundary_projection(
                        candidate, self.plan
                    )

    def test_production_subnet_may_use_current_site_level_representation(self):
        class SiteLevelSubnetSession(FakeReadOnlySession):
            def read(self, request):
                response = super().read(request)
                site = self.resources["productionSite"]
                if request.url == (
                    "https://management.azure.com"
                    + site["resourceId"]
                    + "?api-version=2025-03-01"
                ):
                    body = copy.deepcopy(response.body)
                    body["properties"]["virtualNetworkSubnetId"] = self.resources[
                        "integrationSubnet"
                    ]["resourceId"]
                    return observe.ReadResponse(
                        method=response.method,
                        url=response.url,
                        status=response.status,
                        headers=response.headers,
                        body=body,
                    )
                if request.url == (
                    "https://management.azure.com"
                    + site["resourceId"]
                    + "/config/web?api-version=2025-03-01"
                ):
                    body = copy.deepcopy(response.body)
                    body["properties"]["virtualNetworkSubnetId"] = None
                    return observe.ReadResponse(
                        method=response.method,
                        url=response.url,
                        status=response.status,
                        headers=response.headers,
                        body=body,
                    )
                return response

        with tempfile.TemporaryDirectory() as folder:
            _session, preflight, _template = self.build(
                folder, SiteLevelSubnetSession(self.plan)
            )
        posture = preflight["projection"]["productionBoundaryObservation"][
            "sourceProjection"
        ]["sitePosture"]
        self.assertEqual(
            posture["virtualNetworkSubnetId"],
            next(
                item["resourceId"]
                for item in self.plan["resourceInventory"]
                if item["id"] == "integrationSubnet"
            ),
        )

    def test_session_method_or_url_drift_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(observe.ObserveError, "drifted"):
                self.build(folder, FakeReadOnlySession(self.plan, drift=True))

    def test_authentication_failure_is_not_admitted_as_temporary_storage_rbac(self):
        class AuthenticationFailedPackageSession(FakeReadOnlySession):
            def read(self, request):
                response = super().read(request)
                if (
                    request.url.startswith(
                        "https://mdspdbak2608089c4e.blob.core.windows.net/"
                        "paperdesk-deployment-packages/v2/control/"
                    )
                    and request.url.endswith(
                        "/paperdesk-private-release-bridge.zip"
                    )
                ):
                    return observe.ReadResponse(
                        method=response.method,
                        url=response.url,
                        status=403,
                        headers=response.headers,
                        body={"storageErrorCode": "AuthenticationFailed"},
                    )
                return response

        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(
                observe.ObserveError,
                "package blob preflight is not blocked by temporary access",
            ):
                self.build(folder, AuthenticationFailedPackageSession(self.plan))

    def test_credential_shaped_observation_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(observe.ObserveError, "credential-shaped"):
                self.build(folder, FakeReadOnlySession(self.plan, credential=True))
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(observe.ObserveError, "secret material"):
                self.build(folder, FakeReadOnlySession(self.plan, opaque_secret=True))
        for key in (
            "MY_API_KEY",
            "PAPERDESK_SIGNING_KEY",
            "PAPERDESK_SERVICE_TOKEN",
            "PRIVATE_SECRET",
        ):
            with self.subTest(key=key):
                with self.assertRaisesRegex(observe.ObserveError, "secret material"):
                    observe._safe_json({key: "opaque-value"}, "fixture")

    def test_existing_bridge_settings_are_rejected_before_preflight_persistence(self):
        class ExistingBridgeSettingsSession(FakeReadOnlySession):
            def read(self, request):
                response = super().read(request)
                bridge = self.resources["bridgeSite"]
                if request.url == (
                    "https://management.azure.com"
                    + bridge["resourceId"]
                    + "/config/appsettings/list?api-version=2025-03-01"
                ):
                    return observe.ReadResponse(
                        method=response.method,
                        url=response.url,
                        status=200,
                        headers={},
                        body={"properties": {"VISIBLE_NONSECRET_SETTING": "value"}},
                    )
                return response

        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(
                observe.ObserveError, "prestate must be empty"
            ):
                self.build(folder, ExistingBridgeSettingsSession(self.plan))

    def test_empty_bridge_settings_accept_absent_or_irrelevant_etag_metadata(self):
        class AppSettingsEtagVariantSession(FakeReadOnlySession):
            def __init__(self, plan, *, headers, body_etag=None):
                super().__init__(plan)
                self.settings_headers = headers
                self.body_etag = body_etag

            def read(self, request):
                response = super().read(request)
                bridge = self.resources["bridgeSite"]
                if request.url != (
                    "https://management.azure.com"
                    + bridge["resourceId"]
                    + "/config/appsettings/list?api-version=2025-03-01"
                ):
                    return response
                body = copy.deepcopy(response.body)
                if self.body_etag is not None:
                    body["etag"] = self.body_etag
                headers = dict(self.settings_headers)
                self.envelopes[(request.method, request.url)] = {
                    "method": request.method,
                    "url": request.url,
                    "status": response.status,
                    "headers": {key.lower(): value for key, value in headers.items()},
                    "body": copy.deepcopy(body),
                }
                return observe.ReadResponse(
                    method=response.method,
                    url=response.url,
                    status=response.status,
                    headers=headers,
                    body=body,
                )

        variants = (
            ("absent", {}, None),
            ("weak-header", {"ETag": 'W/"unsupported-token"'}, None),
            ("body-only", {}, '"unsupported-body-token"'),
        )
        for label, headers, body_etag in variants:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as folder:
                _session, preflight, _template = self.build(
                    folder,
                    AppSettingsEtagVariantSession(
                        self.plan, headers=headers, body_etag=body_etag
                    ),
                )
            admission = next(
                item
                for item in preflight["projection"]["operationAdmissions"]
                if item["operationId"]
                == "configureBridgeExactVersionedPackageAndCriticalSettings"
            )
            self.assertEqual(admission["status"], "exact")
            self.assertEqual(admission["context"]["preAppSettings"], {})
            self.assertEqual(
                admission["context"]["preAppSettingsSha256"],
                bootstrap.sha256_bytes(bootstrap.canonical_json_bytes({})),
            )
            self.assertNotIn("preAppSettingsEtag", admission["context"])

    def test_retained_uploader_acl_blocks_any_fresh_release_observation(self):
        class RetainedUploaderAclSession(FakeReadOnlySession):
            def _network_acls(self):
                value = super()._network_acls()
                value["ipRules"] = [
                    {"value": "203.0.113.10", "action": "Allow"}
                ]
                return value

        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(
                observe.ObserveError,
                "temporary uploader IPv4 access is already present",
            ):
                self.build(folder, RetainedUploaderAclSession(self.plan))

    def test_retained_temporary_role_definition_blocks_fresh_observation(self):
        bound_plan = bootstrap.bind_temporary_role_ids(
            self.plan, AUTHORIZATION_ID
        )
        definition_url = bootstrap._temporary_role_definition_readback_url(
            "addOwnedUploaderPackageRole", bound_plan
        )
        self.assertIsNotNone(definition_url)

        class RetainedTemporaryRoleDefinitionSession(FakeReadOnlySession):
            def read(self, request):
                response = super().read(request)
                if request.url == definition_url:
                    return observe.ReadResponse(
                        method=response.method,
                        url=response.url,
                        status=200,
                        headers={},
                        body={
                            "id": definition_url.split("?", 1)[0].removeprefix(
                                "https://management.azure.com"
                            )
                        },
                    )
                return response

        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(
                observe.ObserveError,
                "temporary role definition is already present before bootstrap",
            ):
                self.build(
                    folder,
                    RetainedTemporaryRoleDefinitionSession(self.plan),
                )

    def test_existing_registry_role_authority_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(
                observe.ObserveError,
                "createCustomRoleDefinitions member is a third state",
            ):
                self.build(
                    folder,
                    FakeReadOnlySession(self.plan, role_authority_drift=True),
                )

    def test_mutation_methods_are_impossible_at_request_boundary(self):
        with self.assertRaisesRegex(observe.ObserveError, "mutation-capable"):
            observe.ReadRequest(
                "PUT",
                "https://management.azure.com/subscriptions/"
                f"{bootstrap.SUBSCRIPTION}/resourceGroups/example?api-version=2022-09-01",
            )
        with self.assertRaisesRegex(observe.ObserveError, "read-only app-settings"):
            observe.ReadRequest(
                "POST",
                "https://management.azure.com/subscriptions/"
                f"{bootstrap.SUBSCRIPTION}/resourceGroups/example?api-version=2022-09-01",
            )

    def test_concrete_read_only_session_retries_only_transport_failures(self):
        url = (
            "https://management.azure.com/subscriptions/"
            f"{bootstrap.SUBSCRIPTION}?api-version=2022-09-01"
        )

        class FlakyReadSession:
            def __init__(self):
                self.calls = 0

            def request(self, method, request_url):
                self.calls += 1
                if self.calls < 3:
                    raise bootstrap.BootstrapError(
                        "Azure REST transport failed closed"
                    )
                return bootstrap._RestResponse(
                    status=200,
                    body=b"{}",
                    headers={"Content-Type": "application/json"},
                )

        sleeps = []
        transport = FlakyReadSession()
        session = observe.AzureCliReadOnlySession(sleeper=sleeps.append)
        session._session = transport
        response = session.read(observe.ReadRequest("GET", url))
        self.assertEqual(response.status, 200)
        self.assertEqual(transport.calls, 3)
        self.assertEqual(sleeps, [0.5, 1.0])

        class PermanentFailureSession:
            def __init__(self):
                self.calls = 0

            def request(self, _method, _request_url):
                self.calls += 1
                raise bootstrap.BootstrapError("permanent read failure")

        permanent = PermanentFailureSession()
        sleeps = []
        session = observe.AzureCliReadOnlySession(sleeper=sleeps.append)
        session._session = permanent
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "permanent read failure"
        ):
            session.read(observe.ReadRequest("GET", url))
        self.assertEqual(permanent.calls, 1)
        self.assertEqual(sleeps, [])

        exhausted = FlakyReadSession()
        exhausted.request = lambda _method, _request_url: (_ for _ in ()).throw(
            bootstrap.BootstrapError("Azure REST transport failed closed")
        )
        sleeps = []
        session = observe.AzureCliReadOnlySession(sleeper=sleeps.append)
        session._session = exhausted
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "Azure REST transport failed closed"
        ):
            session.read(observe.ReadRequest("GET", url))
        self.assertEqual(sleeps, [0.5, 1.0])

    def test_executor_preflight_retries_only_read_transport_failures(self):
        with tempfile.TemporaryDirectory() as folder:
            _session, preflight, template = self.build(folder)
        authorization = self.promote_template(template)
        url = (
            "https://management.azure.com/subscriptions/"
            f"{bootstrap.SUBSCRIPTION}?api-version=2022-09-01"
        )

        class FlakySession:
            def __init__(
                self,
                error="Azure REST transport failed closed",
                failures_before_success=2,
            ):
                self.calls = 0
                self.error = error
                self.failures_before_success = failures_before_success

            def request(self, _method, _url, *, body=None, headers=None):
                self.calls += 1
                if self.calls <= self.failures_before_success:
                    raise bootstrap.BootstrapError(self.error)
                return bootstrap._RestResponse(
                    status=200,
                    body=b"{}",
                    headers={"Content-Type": "application/json"},
                )

        sleeps = []
        flaky = FlakySession()
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=authorization,
            plan=self.plan,
            package=bootstrap.build_package_descriptor(),
            preflight=preflight,
            sleep=sleeps.append,
            session=flaky,
        )
        response = transport._read_request_with_transport_retry("GET", url)
        self.assertEqual(response.status, 200)
        self.assertEqual(flaky.calls, 3)
        self.assertEqual(sleeps, [0.5, 1.0])

        permanent = FlakySession("permanent read failure")
        sleeps = []
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=authorization,
            plan=self.plan,
            package=bootstrap.build_package_descriptor(),
            preflight=preflight,
            sleep=sleeps.append,
            session=permanent,
        )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "permanent read failure"
        ):
            transport._read_request_with_transport_retry("GET", url)
        self.assertEqual(permanent.calls, 1)
        self.assertEqual(sleeps, [])

        exhausted = FlakySession(failures_before_success=3)
        sleeps = []
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=authorization,
            plan=self.plan,
            package=bootstrap.build_package_descriptor(),
            preflight=preflight,
            sleep=sleeps.append,
            session=exhausted,
        )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "Azure REST transport failed closed"
        ):
            transport._read_request_with_transport_retry("GET", url)
        self.assertEqual(exhausted.calls, 3)
        self.assertEqual(sleeps, [0.5, 1.0])

        app_settings_urls = [
            next(
                request["url"]
                for request in bootstrap._production_boundary_requests(self.plan)
                if request["method"] == "POST"
            ),
            bootstrap._operation_readback_url(
                "configureBridgeExactVersionedPackageAndCriticalSettings",
                self.plan,
                authorization,
            ),
        ]
        for app_settings_url in app_settings_urls:
            allowed_post = FlakySession()
            post_sleeps = []
            transport = bootstrap.AzureCliBootstrapTransport(
                authorization=authorization,
                plan=self.plan,
                package=bootstrap.build_package_descriptor(),
                preflight=preflight,
                sleep=post_sleeps.append,
                session=allowed_post,
            )
            self.assertEqual(
                transport._read_request_with_transport_retry(
                    "POST", app_settings_url, body=b""
                ).status,
                200,
            )
            self.assertEqual(allowed_post.calls, 3)
            self.assertEqual(post_sleeps, [0.5, 1.0])

        http_failure = FlakySession(failures_before_success=0)
        http_failure.request = lambda _method, _url, *, body=None, headers=None: (
            setattr(http_failure, "calls", http_failure.calls + 1)
            or bootstrap._RestResponse(
                status=503,
                body=b"{}",
                headers={"Content-Type": "application/json"},
            )
        )
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=authorization,
            plan=self.plan,
            package=bootstrap.build_package_descriptor(),
            preflight=preflight,
            sleep=lambda _delay: self.fail("HTTP responses must not be retried"),
            session=http_failure,
        )
        self.assertEqual(
            transport._read_request_with_transport_retry("GET", url).status,
            503,
        )
        self.assertEqual(http_failure.calls, 1)

        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "mutation-capable"
        ):
            transport._read_request_with_transport_retry(
                "PATCH", url, body=b"{}"
            )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "mutation-capable"
        ):
            transport._read_request_with_transport_retry("GET", url, body=b"")
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "mutation-capable"
        ):
            transport._read_request_with_transport_retry(
                "POST", url, body=b""
            )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "mutation-capable"
        ):
            transport._read_request_with_transport_retry(
                "POST", app_settings_urls[0], body=b"{}"
            )
        self.assertEqual(http_failure.calls, 1)

    def test_executor_mutation_readback_retries_transport_failures(self):
        with tempfile.TemporaryDirectory() as folder:
            _session, preflight, template = self.build(folder)
        authorization = self.promote_template(template)
        admission = next(
            item
            for item in preflight["projection"]["operationAdmissions"]
            if item["operationId"] == "createMailboxResourceGroup"
        )
        probe_id = admission["desiredProbeIds"][0]
        expected_probe = next(
            item
            for item in preflight["projection"]["probes"]
            if item["id"] == probe_id
        )
        resource = next(
            item
            for item in self.plan["resourceInventory"]
            if item["id"] == "mailboxResourceGroup"
        )
        location = self.plan["azure"]["location"]

        class FlakyReadbackSession:
            def __init__(self):
                self.calls = []

            def request(
                self, method, url, *, body=None, headers=None, deadline=None
            ):
                self.calls.append((method, url, body, headers))
                if len(self.calls) <= 2:
                    raise bootstrap.BootstrapError(
                        "Azure REST transport failed closed"
                    )
                return bootstrap._RestResponse(
                    status=200,
                    body=bootstrap.canonical_json_bytes(
                        {
                            "id": resource["resourceId"],
                            "name": resource["name"],
                            "type": "Microsoft.Resources/resourceGroups",
                            "location": location,
                        }
                    ),
                    headers={"Content-Type": "application/json"},
                )

        session = FlakyReadbackSession()
        sleeps = []
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=authorization,
            plan=self.plan,
            package=bootstrap.build_package_descriptor(),
            preflight=preflight,
            clock=lambda: NOW + dt.timedelta(seconds=1),
            sleep=sleeps.append,
            session=session,
        )
        proofs = transport._prove_probe_ids(
            [probe_id], "createMailboxResourceGroup mutation"
        )

        self.assertEqual([item["id"] for item in proofs], [probe_id])
        self.assertEqual(proofs[0]["attempts"], 1)
        self.assertEqual(len(session.calls), 3)
        self.assertTrue(
            all(
                method == "GET" and url == expected_probe["url"] and body is None
                for method, url, body, _headers in session.calls
            )
        )
        self.assertEqual(sleeps, [0.5, 1.0])

    def test_executor_mutation_readback_retries_fixed_read_only_post(self):
        with tempfile.TemporaryDirectory() as folder:
            _session, preflight, template = self.build(folder)
        authorization = self.promote_template(template)
        admission = next(
            item
            for item in preflight["projection"]["operationAdmissions"]
            if item["operationId"]
            == "configureBridgeExactVersionedPackageAndCriticalSettings"
        )
        probe_id = admission["desiredProbeIds"][0]
        expected_probe = next(
            item
            for item in preflight["projection"]["probes"]
            if item["id"] == probe_id
        )
        self.assertEqual(expected_probe["method"], "POST")

        class FlakyReadbackSession:
            def __init__(self):
                self.calls = []

            def request(
                self, method, url, *, body=None, headers=None, deadline=None
            ):
                self.calls.append((method, url, body, headers))
                if len(self.calls) <= 2:
                    raise bootstrap.BootstrapError(
                        "Azure REST transport failed closed"
                    )
                return bootstrap._RestResponse(
                    status=200,
                    body=b"{}",
                    headers={"Content-Type": "application/json"},
                )

        session = FlakyReadbackSession()
        sleeps = []
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=authorization,
            plan=self.plan,
            package=bootstrap.build_package_descriptor(),
            preflight=preflight,
            clock=lambda: NOW + dt.timedelta(seconds=1),
            sleep=sleeps.append,
            session=session,
        )
        transport._validate_readback_response = (
            lambda expected, response, *, runtime_facts=None: {
                "id": expected["id"],
                "validatorId": expected["validatorId"],
                "status": response.status,
                "responseSha256": bootstrap._response_sha256(response),
                "sourceProjection": {"runtimeFactsProvided": runtime_facts is not None},
            }
        )
        proofs = transport._prove_probe_ids(
            [probe_id],
            "configureBridgeExactVersionedPackageAndCriticalSettings mutation",
            runtime_facts={},
        )

        self.assertEqual([item["id"] for item in proofs], [probe_id])
        self.assertEqual(proofs[0]["attempts"], 1)
        self.assertEqual(len(session.calls), 3)
        self.assertTrue(
            all(
                method == "POST" and url == expected_probe["url"] and body == b""
                for method, url, body, _headers in session.calls
            )
        )
        self.assertEqual(sleeps, [0.5, 1.0])

    def test_worm_admission_accepts_only_supported_exact_prestates(self):
        with tempfile.TemporaryDirectory() as folder:
            _session, _preflight, template = self.build(folder)
        authorization = {
            "authorizationId": template["authorizationId"],
            "source": template["source"],
            "plan": template["plan"],
            "azure": template["azure"],
            "validity": template["proposedValidity"],
            "singleUse": template["singleUse"],
        }
        resources = {item["id"]: item for item in self.plan["resourceInventory"]}

        def envelope(target, *, status=200, state="Locked", days=91):
            return {
                "status": status,
                "headers": {"etag": '"worm-etag"'} if status == 200 else {},
                "body": (
                    {
                        "id": resources[target]["resourceId"]
                        + "/immutabilityPolicies/default",
                        "name": "default",
                        "type": (
                            "Microsoft.Storage/storageAccounts/blobServices/"
                            "containers/immutabilityPolicies"
                        ),
                        "properties": {
                            "allowProtectedAppendWrites": False,
                            "allowProtectedAppendWritesAll": False,
                            "immutabilityPeriodSinceCreationInDays": days,
                            "state": state,
                        },
                    }
                    if status == 200
                    else {}
                ),
            }

        package_policy = bootstrap._operation_context_policy(
            "lockPackageRetentionAt91Days", self.plan, authorization
        )
        status, context = observe._worm_policy_admission(
            "lockPackageRetentionAt91Days",
            envelope("packageContainer"),
            self.plan,
            package_policy,
        )
        self.assertEqual(status, "exact")
        self.assertEqual(
            context, {"executionDecision": "adopt-exact", "adopted": {}}
        )

        accepted_policy = bootstrap._operation_context_policy(
            "extendAcceptedRetentionFrom30To91Days", self.plan, authorization
        )
        with self.assertRaisesRegex(
            observe.ObserveError, "required existing WORM policy is absent"
        ):
            observe._worm_policy_admission(
                "extendAcceptedRetentionFrom30To91Days",
                envelope("acceptedContainer", status=404),
                self.plan,
                accepted_policy,
            )
        with self.assertRaisesRegex(
            observe.ObserveError, "not an exact locked 30-day policy"
        ):
            observe._worm_policy_admission(
                "extendAcceptedRetentionFrom30To91Days",
                envelope("acceptedContainer", state="Unlocked", days=30),
                self.plan,
                accepted_policy,
            )
        missing_etag = envelope("acceptedContainer", state="Locked", days=30)
        missing_etag["headers"] = {}
        with self.assertRaisesRegex(observe.ObserveError, "strong ETag"):
            observe._worm_policy_admission(
                "extendAcceptedRetentionFrom30To91Days",
                missing_etag,
                self.plan,
                accepted_policy,
            )
        append_enabled = envelope(
            "acceptedContainer", state="Locked", days=30
        )
        append_enabled["body"]["properties"][
            "allowProtectedAppendWrites"
        ] = True
        with self.assertRaisesRegex(observe.ObserveError, "prestate drifted"):
            observe._worm_policy_admission(
                "extendAcceptedRetentionFrom30To91Days",
                append_enabled,
                self.plan,
                accepted_policy,
            )

    def test_exact_package_deleted_tombstone_normalizes_only_to_absent_apply(self):
        with tempfile.TemporaryDirectory() as folder:
            _session, _preflight, template = self.build(folder)
        authorization = self.promote_template(template)
        policy = bootstrap._operation_context_policy(
            "lockPackageRetentionAt91Days", self.plan, authorization
        )
        envelope = {
            "status": 200,
            "headers": {"content-type": "application/json"},
            "body": package_worm_deleted_tombstone(self.plan),
        }

        status, context = observe._worm_policy_admission(
            "lockPackageRetentionAt91Days", envelope, self.plan, policy
        )

        self.assertEqual(status, "absent")
        self.assertEqual(
            context,
            {"executionDecision": "apply-exact", "etag": None},
        )

    def test_package_deleted_tombstone_rejects_every_identity_etag_and_shape_drift(self):
        with tempfile.TemporaryDirectory() as folder:
            _session, _preflight, template = self.build(folder)
        authorization = self.promote_template(template)
        policy = bootstrap._operation_context_policy(
            "lockPackageRetentionAt91Days", self.plan, authorization
        )

        def exact_envelope():
            return {
                "status": 200,
                "headers": {"content-type": "application/json"},
                "body": package_worm_deleted_tombstone(self.plan),
            }

        variants = {}

        value = exact_envelope()
        value["body"]["etag"] = '"live-etag"'
        variants["body-etag"] = value

        value = exact_envelope()
        value["headers"]["ETag"] = '"live-etag"'
        variants["header-etag"] = value

        value = exact_envelope()
        value["body"]["id"] = (
            next(
                item["resourceId"]
                for item in self.plan["resourceInventory"]
                if item["id"] == "resultContainer"
            )
            + "/immutabilityPolicies/default"
        )
        variants["wrong-id"] = value

        value = exact_envelope()
        value["body"]["name"] = "other"
        variants["wrong-name"] = value

        value = exact_envelope()
        value["body"]["type"] = "Microsoft.Storage/storageAccounts"
        variants["wrong-type"] = value

        value = exact_envelope()
        value["body"]["unexpected"] = True
        variants["extra-body-field"] = value

        value = exact_envelope()
        del value["body"]["properties"]["state"]
        variants["missing-state"] = value

        value = exact_envelope()
        del value["body"]["properties"][
            "immutabilityPeriodSinceCreationInDays"
        ]
        variants["missing-days"] = value

        for append_field in (
            "allowProtectedAppendWrites",
            "allowProtectedAppendWritesAll",
        ):
            for append_value in (False, True):
                value = exact_envelope()
                value["body"]["properties"][append_field] = append_value
                variants[f"extra-{append_field}-{append_value}"] = value

        for state in ("Locked", "Unlocked"):
            value = exact_envelope()
            value["body"]["properties"]["state"] = state
            variants[f"state-{state}"] = value

        for days in (-1, 1, False, True):
            value = exact_envelope()
            value["body"]["properties"][
                "immutabilityPeriodSinceCreationInDays"
            ] = days
            variants[f"days-{days!r}"] = value

        for label, altered in variants.items():
            with self.subTest(label=label), self.assertRaises(
                observe.ObserveError
            ):
                observe._worm_policy_admission(
                    "lockPackageRetentionAt91Days",
                    altered,
                    self.plan,
                    policy,
                )

    def test_deleted_tombstone_is_never_absence_for_accepted_or_result_policy(self):
        with tempfile.TemporaryDirectory() as folder:
            _session, _preflight, template = self.build(folder)
        authorization = self.promote_template(template)
        resources = {item["id"]: item for item in self.plan["resourceInventory"]}
        targets = {
            "extendAcceptedRetentionFrom30To91Days": "acceptedContainer",
            "extendResultRetentionFrom30To91Days": "resultContainer",
        }
        for operation_id, target in targets.items():
            envelope = {
                "status": 200,
                "headers": {"content-type": "application/json"},
                "body": package_worm_deleted_tombstone(self.plan),
            }
            envelope["body"]["id"] = (
                resources[target]["resourceId"]
                + "/immutabilityPolicies/default"
            )
            policy = bootstrap._operation_context_policy(
                operation_id, self.plan, authorization
            )
            with self.subTest(operation_id=operation_id), self.assertRaises(
                observe.ObserveError
            ):
                observe._worm_policy_admission(
                    operation_id, envelope, self.plan, policy
                )

    def test_preflight_replay_accepts_only_404_or_exact_200_package_absence(self):
        observed = []
        sessions = (
            (FakeReadOnlySession(self.plan), 404),
            (PackageWormDeletedTombstoneSession(self.plan), 200),
        )
        for session, expected_package_status in sessions:
            with self.subTest(package_status=expected_package_status), tempfile.TemporaryDirectory() as folder:
                _selected, preflight, template = self.build(folder, session)
            admissions = {
                item["operationId"]: item
                for item in preflight["projection"]["operationAdmissions"]
            }
            probes = {
                item["id"]: item for item in preflight["projection"]["probes"]
            }
            package = admissions["lockPackageRetentionAt91Days"]
            self.assertEqual(package["status"], "absent")
            self.assertEqual(
                package["context"],
                {"executionDecision": "apply-exact", "etag": None},
            )
            self.assertEqual(
                probes[package["probeIds"][0]]["status"],
                expected_package_status,
            )
            for operation_id in (
                "extendAcceptedRetentionFrom30To91Days",
                "extendResultRetentionFrom30To91Days",
            ):
                admission = admissions[operation_id]
                self.assertEqual(admission["status"], "exact")
                self.assertEqual(probes[admission["probeIds"][0]]["status"], 200)
            authorization = self.promote_template(template)
            validated, _digest = bootstrap.validate_preflight_evidence(
                preflight, authorization, self.plan
            )
            self.assertEqual(validated, preflight)
            observed.append((preflight, authorization))

        preflight, authorization = observed[-1]
        admissions = {
            item["operationId"]: item
            for item in preflight["projection"]["operationAdmissions"]
        }
        for operation_id, forged_statuses in (
            ("lockPackageRetentionAt91Days", (201, 204, 409)),
            ("extendAcceptedRetentionFrom30To91Days", (404,)),
            ("extendResultRetentionFrom30To91Days", (404,)),
        ):
            for forged_status in forged_statuses:
                altered = copy.deepcopy(preflight)
                altered_authorization = copy.deepcopy(authorization)
                altered_admissions = {
                    item["operationId"]: item
                    for item in altered["projection"]["operationAdmissions"]
                }
                probe_id = altered_admissions[operation_id]["probeIds"][0]
                probe = next(
                    item
                    for item in altered["projection"]["probes"]
                    if item["id"] == probe_id
                )
                probe["status"] = forged_status
                digest = bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes(altered["projection"])
                )
                altered["projectionSha256"] = digest
                altered_authorization["observedPreflight"]["sha256"] = digest
                with self.subTest(
                    operation_id=operation_id, status=forged_status
                ), self.assertRaisesRegex(
                    bootstrap.BootstrapError,
                    "WORM admission is not bound to one supported HTTP prestate",
                ):
                    bootstrap.validate_preflight_evidence(
                        altered, altered_authorization, self.plan
                    )

    def test_preflight_replay_rejects_arbitrary_200_package_tombstone_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            _session, preflight, template = self.build(
                folder, PackageWormDeletedTombstoneSession(self.plan)
            )
        authorization = self.promote_template(template)
        altered = copy.deepcopy(preflight)
        altered_authorization = copy.deepcopy(authorization)
        admission = next(
            item
            for item in altered["projection"]["operationAdmissions"]
            if item["operationId"] == "lockPackageRetentionAt91Days"
        )
        probe = next(
            item
            for item in altered["projection"]["probes"]
            if item["id"] == admission["probeIds"][0]
        )
        self.assertEqual(probe["status"], 200)
        probe["responseSha256"] = "0" * 64
        digest = bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(altered["projection"])
        )
        altered["projectionSha256"] = digest
        altered_authorization["observedPreflight"]["sha256"] = digest

        with self.assertRaisesRegex(
            bootstrap.BootstrapError,
            "not bound to the exact deleted tombstone",
        ):
            bootstrap.validate_preflight_evidence(
                altered, altered_authorization, self.plan
            )

    def test_package_tombstone_preflight_digest_binds_response_etag_header(self):
        bound_plan = bootstrap.bind_temporary_role_ids(
            self.plan, AUTHORIZATION_ID
        )
        url = bootstrap._operation_readback_url(
            "lockPackageRetentionAt91Days",
            bound_plan,
            {"authorizationId": AUTHORIZATION_ID},
        )
        body = package_worm_deleted_tombstone(self.plan)
        encoded = bootstrap.canonical_json_bytes(body)
        without_etag = bootstrap._preflight_response_sha256(
            "GET",
            url,
            bootstrap._RestResponse(
                status=200,
                body=encoded,
                headers={"content-type": "application/json"},
            ),
        )
        with_empty_etag = bootstrap._preflight_response_sha256(
            "GET",
            url,
            bootstrap._RestResponse(
                status=200,
                body=encoded,
                headers={"content-type": "application/json", "ETag": ""},
            ),
        )
        with_etag = bootstrap._preflight_response_sha256(
            "GET",
            url,
            bootstrap._RestResponse(
                status=200,
                body=encoded,
                headers={"content-type": "application/json", "ETag": '"new"'},
            ),
        )
        self.assertEqual(without_etag, with_empty_etag)
        self.assertNotEqual(without_etag, with_etag)
        self.assertIn(
            without_etag,
            bootstrap._package_worm_deleted_tombstone_response_sha256s(
                bound_plan
            ),
        )

        envelope = {
            "method": "GET",
            "url": url,
            "status": 200,
            "headers": {"content-type": "application/json"},
            "body": body,
            "responseSha256": without_etag,
        }
        self.assertEqual(observe.response_digest(envelope), without_etag)
        envelope["responseSha256"] = with_etag
        with self.assertRaisesRegex(
            observe.ObserveError,
            "drifted from its exact projection",
        ):
            observe.response_digest(envelope)

    def test_graph_fic_inventory_rejects_partial_duplicate_and_drifted_state(self):
        with tempfile.TemporaryDirectory() as folder:
            _session, _preflight, template = self.build(folder)
        authorization = {
            "source": template["source"],
        }
        resources = {item["id"]: item for item in self.plan["resourceInventory"]}
        application = {
            "id": "11111111-1111-4111-8111-111111111111",
            "appId": "22222222-2222-4222-8222-222222222222",
            "displayName": resources["publisherApplication"]["name"],
            "federatedIdentityCredentials": [],
        }
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "Graph collection is partial"
        ):
            bootstrap._publisher_fic_inventory(
                {
                    "value": [copy.deepcopy(application)],
                    "@odata.nextLink": "https://graph.microsoft.com/beta/next",
                },
                self.plan,
                authorization,
                "publisher inventory",
            )
        nested = copy.deepcopy(application)
        nested["federatedIdentityCredentials@odata.nextLink"] = (
            "https://graph.microsoft.com/beta/next-fic"
        )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "publisher application inventory drifted"
        ):
            bootstrap._publisher_fic_inventory(
                {"value": [nested]},
                self.plan,
                authorization,
                "publisher inventory",
            )

        resource = resources["publisherFederatedCredential"]
        credential = {
            "id": "33333333-3333-4333-8333-333333333333",
            "name": resource["name"],
            "issuer": resource["issuer"],
            "audiences": resource["audiences"],
            "subject": None,
            "claimsMatchingExpression": {
                "languageVersion": resource[
                    "claimsMatchingExpressionLanguageVersion"
                ],
                "value": resource["claimsMatchingExpressionTemplate"].replace(
                    "${authorization.source.mergedMain.commitSha}",
                    authorization["source"]["mergedMain"]["commitSha"],
                ),
            },
        }
        self.assertEqual(
            bootstrap._validate_exact_publisher_fic(
                credential, self.plan, authorization, "publisher inventory"
            )["id"],
            credential["id"],
        )
        duplicate = copy.deepcopy(application)
        duplicate["federatedIdentityCredentials"] = [credential, credential]
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "publisher FIC inventory is not sole"
        ):
            bootstrap._publisher_fic_inventory(
                {"value": [duplicate]},
                self.plan,
                authorization,
                "publisher inventory",
            )

    def test_publisher_graph_assignment_nested_pagination_fails_closed(self):
        class NestedPaginationSession(FakeReadOnlySession):
            def read(self, request):
                if "$expand=appRoleAssignments" in request.url:
                    body = {
                        "value": [
                            {
                                "id": "11111111-1111-4111-8111-111111111111",
                                "appId": "22222222-2222-4222-8222-222222222222",
                                "displayName": (
                                    self.resources["publisherServicePrincipal"][
                                        "name"
                                    ]
                                ),
                                "accountEnabled": True,
                                "servicePrincipalType": "Application",
                                "passwordCredentials": [],
                                "keyCredentials": [],
                                "appRoleAssignments": [],
                                "appRoleAssignments@odata.nextLink": (
                                    "https://graph.microsoft.com/v1.0/next"
                                ),
                            }
                        ]
                    }
                    return observe.ReadResponse(
                        method=request.method,
                        url=request.url,
                        status=200,
                        headers={},
                        body=body,
                    )
                return super().read(request)

        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(
                observe.ObserveError,
                "publisher Graph assignment inventory is partial",
            ):
                self.build(folder, NestedPaginationSession(self.plan))

    def test_blob_xml_or_binary_body_is_digest_bound_without_parsing(self):
        blob_url = (
            "https://mdspdbak2608089c4e.blob.core.windows.net/"
            "paperdesk-deployment-packages/v2/control/"
            + "a" * 40
            + "/paperdesk-private-release-bridge.zip"
        )

        class BinaryBlobSession:
            def request(self, method, url, *, headers=None):
                self.requested = (method, url, headers)
                return bootstrap._RestResponse(
                    status=404,
                    body=b"\xef\xbb\xbf<Error><Code>BlobNotFound</Code></Error>",
                    headers={"Content-Type": "application/xml"},
                )

        session = observe.AzureCliReadOnlySession()
        session._session = BinaryBlobSession()
        response = session.read(observe.ReadRequest("GET", blob_url))
        self.assertEqual(
            session._session.requested[2],
            {"x-ms-version": "2023-11-03"},
        )
        self.assertEqual(response.body, {"storageErrorCode": "BlobNotFound"})
        self.assertEqual(
            response.response_sha256,
            bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(
                    {"storageErrorCode": "BlobNotFound"}
                )
            ),
        )
        envelope = observe._normalize_response(
            observe.ReadRequest("GET", blob_url), response
        )
        self.assertEqual(observe.response_digest(envelope), response.response_sha256)

        session = observe.AzureCliReadOnlySession()
        session._session = BinaryBlobSession()
        with self.assertRaisesRegex(
            observe.ObserveError, "outside the package blob boundary"
        ):
            session.read(
                observe.ReadRequest(
                    "GET",
                    "https://management.azure.com/subscriptions/"
                    f"{bootstrap.SUBSCRIPTION}?api-version=2022-09-01",
                )
            )

    def test_arm_storage_absence_digest_excludes_request_id_and_time(self):
        base_url = (
            "https://management.azure.com/subscriptions/"
            f"{bootstrap.SUBSCRIPTION}/resourceGroups/"
            "rg-paperdesk-rollback-sea-20260808/providers/Microsoft.Storage/"
            "storageAccounts/mdspdbak2608089c4e/blobServices/default/containers/"
        )
        container_urls = [
            base_url + name + "?api-version=2025-06-01"
            for name in (
                "paperdesk-deployment-packages",
                "paperdesk-release-controller-lock",
                "paperdesk-release-activation-control",
            )
        ]
        container_url = container_urls[0]
        policy_url = (
            base_url
            + "paperdesk-deployment-packages/immutabilityPolicies/default"
            + "?api-version=2025-06-01"
        )

        def response(code, request_id, observed_at, *, extra=None):
            error = {
                "code": code,
                "message": (
                    "The specified container does not exist.\n"
                    f"RequestId:{request_id}\nTime:{observed_at}"
                ),
            }
            if extra is not None:
                error["extra"] = extra
            return bootstrap._RestResponse(
                status=404,
                body=bootstrap.canonical_json_bytes({"error": error}),
                headers={"Content-Type": "application/json"},
            )

        first = response(
            "ContainerNotFound",
            "3a8d9ee8-501e-0044-2ead-38837b000000",
            "2026-08-30T18:28:25.2401069Z",
        )
        second = response(
            "ContainerNotFound",
            "4b9eaff9-612f-1155-3fbe-49948c111111",
            "2026-08-30T18:29:26.1Z",
        )
        first_digest = bootstrap._preflight_response_sha256(
            "GET", container_url, first
        )
        self.assertEqual(
            first_digest,
            bootstrap._preflight_response_sha256("GET", container_url, second),
        )
        for exact_container_url in container_urls[1:]:
            self.assertEqual(
                first_digest,
                bootstrap._preflight_response_sha256(
                    "GET", exact_container_url, second
                ),
            )
        self.assertEqual(
            first_digest,
            bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(
                    {
                        "armStorageErrorCode": "ContainerNotFound",
                        "armStorageErrorMessage": (
                            "The specified container does not exist."
                        ),
                    }
                )
            ),
        )
        policy_digest = bootstrap._preflight_response_sha256(
            "GET",
            policy_url,
            response(
                "ContainerOperationFailure",
                "5caeb00a-7230-2266-40cf-5aa59d222222",
                "2026-08-30T18:30:27.123Z",
            ),
        )
        self.assertNotEqual(first_digest, policy_digest)

        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "not exact"
        ):
            bootstrap._preflight_response_sha256(
                "GET",
                container_url,
                response(
                    "ContainerOperationFailure",
                    "3a8d9ee8-501e-0044-2ead-38837b000000",
                    "2026-08-30T18:28:25.2401069Z",
                ),
            )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "fields drifted"
        ):
            bootstrap._preflight_response_sha256(
                "GET",
                container_url,
                response(
                    "ContainerNotFound",
                    "3a8d9ee8-501e-0044-2ead-38837b000000",
                    "2026-08-30T18:28:25.2401069Z",
                    extra="unexpected",
                ),
            )

        class ArmStorageAbsenceSession:
            def request(self, method, url):
                self.requested = (method, url)
                return first

        session = observe.AzureCliReadOnlySession()
        session._session = ArmStorageAbsenceSession()
        observed = session.read(observe.ReadRequest("GET", container_url))
        self.assertEqual(observed.body["error"]["code"], "ContainerNotFound")
        self.assertEqual(observed.response_sha256, first_digest)
        envelope = observe._normalize_response(
            observe.ReadRequest("GET", container_url), observed
        )
        self.assertEqual(observe.response_digest(envelope), first_digest)

        for invalid_url in (
            container_url.replace("https://", "http://", 1),
            container_url.replace(
                "management.azure.com", "user@management.azure.com", 1
            ),
            container_url.replace(
                "management.azure.com", "management.azure.com:443", 1
            ),
            container_url.replace(
                "management.azure.com", "management.example.com", 1
            ),
            container_url.replace(
                "paperdesk-deployment-packages", "unreviewed-container", 1
            ),
            container_url.replace("api-version=2025-06-01", "api-version=2024-01-01"),
        ):
            self.assertIsNone(
                bootstrap._arm_storage_absence_error_projection(
                    "GET", invalid_url, first
                )
            )

        non_absence = bootstrap._RestResponse(
            status=503,
            body=first.body,
            headers=first.headers,
        )
        self.assertIsNone(
            bootstrap._arm_storage_absence_error_projection(
                "GET", container_url, non_absence
            )
        )
        non_json = bootstrap._RestResponse(
            status=404,
            body=first.body,
            headers={"Content-Type": "text/plain"},
        )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "not exact JSON"
        ):
            bootstrap._preflight_response_sha256("GET", container_url, non_json)
        wrong_message = bootstrap._RestResponse(
            status=404,
            body=bootstrap.canonical_json_bytes(
                {
                    "error": {
                        "code": "ContainerNotFound",
                        "message": "A different container error",
                    }
                }
            ),
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "not exact"
        ):
            bootstrap._preflight_response_sha256(
                "GET", container_url, wrong_message
            )

    def test_key_vault_forbidden_preflight_digest_excludes_volatile_message(self):
        url = (
            "https://kv-mds-sea-9c4e0d0d.vault.azure.net/keys/"
            "paperdesk-release-result-signing/versions?api-version=7.4"
        )

        def response(message):
            return bootstrap._RestResponse(
                status=403,
                body=bootstrap.canonical_json_bytes(
                    {
                        "error": {
                            "code": "Forbidden",
                            "message": message,
                            "innererror": {"code": "ForbiddenByRbac"},
                        }
                    }
                ),
                headers={"Content-Type": "application/json"},
            )

        first = bootstrap._preflight_response_sha256(
            "GET", url, response("request-id-one")
        )
        second = bootstrap._preflight_response_sha256(
            "GET", url, response("request-id-two")
        )
        self.assertEqual(first, second)
        self.assertEqual(
            first,
            bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(
                    {
                        "keyVaultErrorCode": "Forbidden",
                        "keyVaultInnerErrorCode": "ForbiddenByRbac",
                    }
                )
            ),
        )
    def test_source_and_observation_tampering_change_or_fail_bindings(self):
        with tempfile.TemporaryDirectory() as folder:
            _, preflight, template = self.build(folder)
        tampered = copy.deepcopy(preflight)
        tampered["projection"]["probes"][0]["url"] += "&tampered=true"
        self.assertNotEqual(
            bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(tampered["projection"])
            ),
            template["observedPreflight"]["sha256"],
        )
        bad_source = source_evidence()
        bad_source["mergedMain"]["commitSha"] = "not-a-sha"
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(observe.ObserveError, "commit SHA"):
                observe.build_read_only_observation(
                    FakeReadOnlySession(self.plan),
                    source=bad_source,
                    authorization_id=AUTHORIZATION_ID,
                    receipt_directory=(
                        Path(folder)
                        / f"paperdesk-private-release-v2-bootstrap-{AUTHORIZATION_ID}"
                    ),
                    observed_at=NOW,
                    uploader_ipv4="203.0.113.10/32",
                )

    def test_cli_writes_exact_read_only_outputs_with_injected_session(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            source_path = root / "source-evidence.json"
            source_path.write_bytes(
                bootstrap.canonical_json_bytes(source_evidence())
            )
            preflight_path = root / "preflight.json"
            template_path = root / "authorization-template.json"
            receipt = (
                root
                / f"paperdesk-private-release-v2-bootstrap-{AUTHORIZATION_ID}"
            )
            session = FakeReadOnlySession(self.plan)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = observe.main(
                    [
                        "--source-evidence",
                        str(source_path),
                        "--authorization-id",
                        AUTHORIZATION_ID,
                        "--receipt-directory",
                        str(receipt),
                        "--uploader-ipv4",
                        "203.0.113.10/32",
                        "--preflight-output",
                        str(preflight_path),
                        "--authorization-template-output",
                        str(template_path),
                    ],
                    session_factory=lambda: session,
                    clock=lambda: NOW,
                )
            self.assertEqual(status, 0)
            self.assertTrue(session.requests)
            self.assertTrue(
                all(request.method in {"GET", "POST"} for request in session.requests)
            )
            preflight, preflight_raw = bootstrap.load_json(
                preflight_path, require_canonical=True
            )
            template, template_raw = bootstrap.load_json(
                template_path, require_canonical=True
            )
            self.assertEqual(preflight["status"], "observed-read-only")
            self.assertFalse(template["executable"])
            result = json.loads(stdout.getvalue())
            self.assertEqual(
                result["preflight"]["sha256"],
                bootstrap.sha256_bytes(preflight_raw),
            )
            self.assertEqual(
                result["authorizationTemplate"]["sha256"],
                bootstrap.sha256_bytes(template_raw),
            )

    def test_documented_direct_script_invocation_loads_before_argument_parsing(self):
        repository_root = Path(__file__).resolve().parents[1]
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(
                    repository_root
                    / "scripts"
                    / "private_release_v2_bootstrap_observe.py"
                ),
                "--help",
            ],
            cwd=repository_root,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("--source-evidence", completed.stdout)
        self.assertNotIn("ModuleNotFoundError", completed.stderr)

    def test_cli_invalid_local_outputs_fail_before_session_construction(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            source_path = root / "source-evidence.json"
            source_path.write_bytes(
                bootstrap.canonical_json_bytes(source_evidence())
            )
            existing = root / "existing.json"
            existing.write_bytes(b"{}")
            constructed = []
            with contextlib.redirect_stderr(io.StringIO()):
                status = observe.main(
                    [
                        "--source-evidence",
                        str(source_path),
                        "--authorization-id",
                        AUTHORIZATION_ID,
                        "--receipt-directory",
                        str(
                            root
                            / f"paperdesk-private-release-v2-bootstrap-{AUTHORIZATION_ID}"
                        ),
                        "--uploader-ipv4",
                        "203.0.113.10/32",
                        "--preflight-output",
                        str(existing),
                        "--authorization-template-output",
                        str(root / "template.json"),
                    ],
                    session_factory=lambda: constructed.append(True),
                    clock=lambda: NOW,
                )
            self.assertEqual(status, 1)
            self.assertEqual(constructed, [])


if __name__ == "__main__":
    unittest.main()
