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

from scripts import private_release_v2_bootstrap as bootstrap
from scripts import private_release_v2_bootstrap_observe as observe


NOW = dt.datetime(2026, 8, 30, 8, 0, tzinfo=dt.timezone.utc)
AUTHORIZATION_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
ACCOUNT_OBJECT_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
LEGACY_FIC_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
REVIEWED_SHA = "1" * 40
MERGED_SHA = "2" * 40
TREE_SHA = "3" * 40
PARENT_SHA = "4" * 40
PHRASE = (
    "Authorize the separately reviewed exact PaperDesk V2 bootstrap. "
    + bootstrap.STORAGE_ACL_AND_RECOVERY_RESIDUAL_ACCEPTANCE
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
        self.plan = plan
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
        if production_match == "production-boundary-site":
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
                "properties": {
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
                "properties": {
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
            body = {"storageErrorCode": "AuthenticationFailed"}
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
                    "id": "temporary-storage-ip-rules-and-recovery-residuals",
                    "exactConfirmationText": (
                        bootstrap.STORAGE_ACL_AND_RECOVERY_RESIDUAL_ACCEPTANCE
                    ),
                },
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

    def test_observed_production_boundary_matches_executor_fresh_preflight(self):
        with tempfile.TemporaryDirectory() as folder:
            session, preflight, _template = self.build(folder)

        class BoundaryRestSession:
            def request(self, method, url, *, body=None, headers=None):
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
            authorization={"azure": {}},
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
        definition_url = bootstrap._temporary_role_definition_readback_url(
            "addOwnedUploaderPackageRole", self.plan
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
            def request(self, method, url):
                self.requested = (method, url)
                return bootstrap._RestResponse(
                    status=404,
                    body=b"<Error><Code>BlobNotFound</Code></Error>",
                    headers={"Content-Type": "application/xml"},
                )

        session = observe.AzureCliReadOnlySession()
        session._session = BinaryBlobSession()
        response = session.read(observe.ReadRequest("GET", blob_url))
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
