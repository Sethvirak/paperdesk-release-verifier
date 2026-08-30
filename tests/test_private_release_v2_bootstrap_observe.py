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
PHRASE = "Authorize the separately reviewed exact PaperDesk V2 bootstrap."


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
    def __init__(self, plan, *, drift=False, credential=False, opaque_secret=False):
        self.plan = plan
        self.drift = drift
        self.credential = credential
        self.opaque_secret = opaque_secret
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
            status = 200
            body = {
                "properties": {
                    "FIXTURE_SECRET_SETTING_NAME": "fixture-secret-setting-value"
                }
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
        elif "/immutabilityPolicies/default?" in request.url:
            status = 200
            headers = {"ETag": '"retention-etag"'}
            body = {"properties": {"immutabilityPeriodSinceCreationInDays": 30}}
        elif request.url.endswith("/federatedIdentityCredentials"):
            status = 200
            body = {"value": [{"id": LEGACY_FIC_ID, "name": "legacy"}]}
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
            matching = [
                role
                for role in self.plan["roleMatrix"]
                if role.get("definitionKind") == "BuiltInRole"
                and role["definitionId"].lower() == definition_id
            ]
            if not matching:
                raise AssertionError("unexpected built-in role-definition read")
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
            body = {"value": []}
        elif "/providers/Microsoft.Authorization/roleAssignments?" in request.url:
            status = 200
            body = {"value": []}
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
        self.assertEqual(
            len(
                [
                    request
                    for request in session.requests
                    if "/roleDefinitions/" in request.url
                    and "?api-version=2022-04-01" in request.url
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
