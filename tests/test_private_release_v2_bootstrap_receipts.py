import copy
import datetime as dt
import unittest
from pathlib import Path

from scripts import private_release_v2_bootstrap as bootstrap
from scripts import private_release_v2_bootstrap_receipts as receipts
from tests.test_private_release_v2_bootstrap import (
    build_authorization,
    build_complete_terminal_receipt_input_fixture,
)


ROOT = Path(__file__).resolve().parents[1]
RECEIPT_DIRECTORY = (
    ROOT.parent
    / "paperdesk-private-release-v2-bootstrap-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
).resolve()
H = lambda value: receipts.sha256_hex(str(value).encode("utf-8"))


def resource(plan, name):
    return next(item for item in plan["resourceInventory"] if item["id"] == name)


def complete_fixture(*, adopt_operations=()):
    return build_complete_terminal_receipt_input_fixture(
        RECEIPT_DIRECTORY,
        adopt_operations=adopt_operations,
    )


def rebuild(fixture, **overrides):
    arguments = {
        "authorization": fixture["authorization"],
        "plan": fixture["plan"],
        "components": fixture["components"],
        "s2_documents": fixture["s2Documents"],
        "source_evidence": fixture["sourceEvidence"],
        "authorized_preflight_projection": fixture["preflightProjection"],
        "package_bytes": fixture["packageBytes"],
        "started_at": fixture["startedAt"],
        "completed_at": fixture["completedAt"],
        "now": fixture["now"],
    }
    arguments.update(overrides)
    return receipts.build_complete_receipt_bundle(**arguments)


def validate_bundle(fixture, bundle, *, now=None):
    body = receipts.canonical_json_bytes(bundle)
    return receipts.validate_receipt_bundle(
        bundle,
        authorization=fixture["authorization"],
        plan=fixture["plan"],
        s2_documents=fixture["s2Documents"],
        terminal_bundle_path=receipts.S2_TERMINAL_BUNDLE_PATH,
        terminal_bundle_body=body,
        authorized_preflight_projection=fixture["preflightProjection"],
        package_bytes=fixture["packageBytes"],
        now=fixture["now"] if now is None else now,
    )


def reviewed_authorization(plan, plan_sha256):
    package = bootstrap.build_package_descriptor()
    preflight = {"schemaVersion": 1, "evidenceType": "test-preflight"}
    value = build_authorization(
        plan,
        plan_sha256,
        package,
        preflight,
        RECEIPT_DIRECTORY,
    )
    value["observedPreflight"]["observedAt"] = "2026-08-30T02:01:00.000Z"
    value["validity"] = {
        "notBefore": "2026-08-30T01:55:00.000Z",
        "expiresAt": "2026-08-30T02:25:00.000Z",
        "maximumLifetimeSeconds": 1800,
    }
    return value


class ReceiptDirectoryFixturePortabilityTests(unittest.TestCase):
    def test_fixture_path_is_absolute_external_and_authorization_specific(self):
        self.assertTrue(RECEIPT_DIRECTORY.is_absolute())
        self.assertEqual(
            RECEIPT_DIRECTORY.name,
            "paperdesk-private-release-v2-bootstrap-"
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        )
        self.assertNotIn(ROOT, RECEIPT_DIRECTORY.parents)


class CompleteReceiptBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = complete_fixture()

    def fresh(self):
        return copy.deepcopy(self.fixture)

    def assert_invalid_bundle(self, mutate, expected=None):
        fixture = self.fresh()
        bundle = copy.deepcopy(fixture["completeReceipt"]["bundle"])
        mutate(bundle, fixture)
        with self.assertRaises(receipts.BootstrapReceiptError) as caught:
            validate_bundle(fixture, bundle)
        if expected is not None:
            self.assertIn(expected, str(caught.exception))

    def test_complete_bundle_is_canonical_and_round_trips(self):
        fixture = self.fresh()
        result = fixture["completeReceipt"]
        bundle = result["bundle"]
        validated = validate_bundle(fixture, bundle)
        self.assertEqual(validated, bundle)
        terminal = result["s2TerminalBundle"][receipts.S2_TERMINAL_BUNDLE_PATH]
        self.assertEqual(terminal, receipts.canonical_json_bytes(bundle))
        self.assertEqual(
            receipts.load_canonical_json_bytes(
                terminal,
                label="terminal receipt bundle",
                maximum_bytes=16 * 1024 * 1024,
            ),
            bundle,
        )
        self.assertEqual(bundle["executionReceipt"]["status"], "succeeded-terminal")
        self.assertEqual(bundle["executionReceipt"]["failures"], [])
        self.assertEqual(bundle["executionReceipt"]["pendingHousekeeping"], [])

    def test_s2_files_are_exact_canonical_create_only_bodies(self):
        fixture = self.fresh()
        expected_paths = receipts.load_model()["requiredS2EvidencePaths"]
        self.assertEqual(list(fixture["s2Documents"]), expected_paths)
        self.assertEqual(
            fixture["completeReceipt"]["s2EvidenceFiles"],
            fixture["s2Documents"],
        )
        for path, body in fixture["s2Documents"].items():
            self.assertIsInstance(body, bytes)
            self.assertEqual(
                receipts.canonical_json_bytes(
                    receipts.load_canonical_json_bytes(body, label=path)
                ),
                body,
            )
        files = fixture["completeReceipt"]["bundle"]["s2OutputMetadata"]["files"]
        self.assertEqual([item["path"] for item in files], expected_paths)
        self.assertEqual(
            [item["sha256"] for item in files],
            [receipts.sha256_hex(fixture["s2Documents"][path]) for path in expected_paths],
        )

    def test_component_descriptor_uses_exact_canonical_digest(self):
        bridge = self.fixture["completeReceipt"]["bundle"]["bridgeEvidence"]
        descriptor = receipts.canonical_receipt_descriptor(
            receipts.S2_EVIDENCE_COMPONENT_PATHS["bridgeEvidence"],
            bridge,
            observed_at=bridge["observedAt"],
        )
        self.assertEqual(descriptor["sha256"], receipts.sha256_hex(bridge))

    def test_missing_bundle_component_fails(self):
        self.assert_invalid_bundle(
            lambda bundle, _fixture: bundle.pop("bridgeEvidence"),
            "missing=bridgeEvidence",
        )

    def test_unknown_component_field_fails(self):
        self.assert_invalid_bundle(
            lambda bundle, _fixture: bundle["wormProjections"].update(
                {"unexpected": True}
            ),
            "extra=unexpected",
        )

    def test_wrong_package_hash_fails(self):
        self.assert_invalid_bundle(
            lambda bundle, _fixture: bundle["packageReadback"].update(
                {"readbackSha256": "f" * 64}
            )
        )

    def test_duplicate_permanent_mutation_fails(self):
        def mutate(bundle, _fixture):
            entries = bundle["permanentMutationLedger"]["entries"]
            entries[1]["mutationId"] = entries[0]["mutationId"]

        self.assert_invalid_bundle(mutate)

    def test_pending_housekeeping_fails(self):
        self.assert_invalid_bundle(
            lambda bundle, _fixture: bundle["executionReceipt"].update(
                {"pendingHousekeeping": ["stop-bridge"]}
            ),
            "terminal-clean",
        )

    def test_wrong_one_shot_claim_fails(self):
        self.assert_invalid_bundle(
            lambda bundle, _fixture: bundle["executionReceipt"]["singleUse"].update(
                {
                    "azureClaimResourceId": (
                        "/subscriptions/9c4e0d0d-602f-4cde-84bd-337250e5b64c/"
                        "providers/Microsoft.Resources/deployments/"
                        "paperdesk-v2-bootstrap-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
                    )
                }
            ),
            "terminally consumed",
        )

    def test_temporary_access_still_present_fails(self):
        self.assert_invalid_bundle(
            lambda bundle, _fixture: bundle["temporaryAccessCleanup"][
                "packageUploaderRole"
            ].update({"presentAfterCleanup": True})
        )

    def test_stale_terminal_time_fails(self):
        fixture = self.fresh()
        bundle = fixture["completeReceipt"]["bundle"]
        stale_now = fixture["now"] + dt.timedelta(seconds=301)
        with self.assertRaisesRegex(receipts.BootstrapReceiptError, "stale"):
            validate_bundle(fixture, bundle, now=stale_now)

    def test_noncanonical_json_fails(self):
        with self.assertRaisesRegex(receipts.BootstrapReceiptError, "not canonical"):
            receipts.load_canonical_json_bytes(b'{"b":1,"a":2}\n')

    def test_raw_ipv4_and_secret_material_fail_closed(self):
        self.assert_invalid_bundle(
            lambda bundle, _fixture: bundle["temporaryAccessCleanup"][
                "packageIpv4Rule"
            ].update({"armIpRuleSha256": "198.51.100.7/32"}),
            "raw public IPv4",
        )
        self.assert_invalid_bundle(
            lambda bundle, _fixture: bundle["packageReadback"].update(
                {
                    "versionedUrl": bundle["packageReadback"]["versionedUrl"]
                    + "&sig=not-a-real-signature"
                }
            ),
            "secret or capability",
        )

    def test_wrong_component_cross_binding_fails(self):
        self.assert_invalid_bundle(
            lambda bundle, _fixture: bundle["bridgeEvidence"].update(
                {"leaseCanaryEvidenceSha256": "e" * 64}
            )
        )

    def test_noncanonical_s2_bytes_fail_before_terminal_assembly(self):
        fixture = self.fresh()
        documents = copy.deepcopy(fixture["s2Documents"])
        path = receipts.S2_EVIDENCE_COMPONENT_PATHS["bridgeEvidence"]
        documents[path] = b" " + documents[path]
        with self.assertRaisesRegex(receipts.BootstrapReceiptError, "not canonical"):
            rebuild(fixture, s2_documents=documents)

    def test_rich_s2_schema_rejects_unknown_fields(self):
        fixture = self.fresh()
        documents = copy.deepcopy(fixture["s2Documents"])
        path = receipts.S2_EVIDENCE_COMPONENT_PATHS["provisioningEvidence"]
        provisioning = receipts.load_canonical_json_bytes(
            documents[path], label="provisioning"
        )
        provisioning["unexpected"] = True
        documents[path] = receipts.canonical_json_bytes(provisioning)
        with self.assertRaisesRegex(
            receipts.BootstrapReceiptError,
            "rich mailbox S2 evidence is invalid",
        ):
            rebuild(fixture, s2_documents=documents)

    def test_pre_s2_activation_accepts_only_source_derived_provisional_evidence(self):
        fixture = self.fresh()
        self.assertEqual(
            fixture["authorization"]["plan"]["bridgePackageSourceSha"],
            fixture["authorization"]["source"]["mergedMain"]["commitSha"],
        )
        documents = copy.deepcopy(fixture["s2Documents"])
        path = receipts.S2_EVIDENCE_COMPONENT_PATHS["provisioningEvidence"]
        provisioning = receipts.load_canonical_json_bytes(
            documents[path], label="provisioning"
        )
        provisioning["bridgeRuntime"]["packageBlob"] = (
            "v2/control/ffffffffffffffffffffffffffffffffffffffff/"
            "paperdesk-private-release-bridge.zip"
        )
        documents[path] = receipts.canonical_json_bytes(provisioning)
        with self.assertRaisesRegex(
            receipts.BootstrapReceiptError,
            "package source binding",
        ):
            rebuild(fixture, s2_documents=documents)

    def test_component_cannot_impersonate_bridge_runtime_s2(self):
        fixture = self.fresh()
        documents = copy.deepcopy(fixture["s2Documents"])
        path = receipts.S2_EVIDENCE_COMPONENT_PATHS["bridgeRuntimeReceipt"]
        documents[path] = receipts.canonical_json_bytes(
            fixture["components"]["bridgeEvidence"]
        )
        with self.assertRaises(receipts.BootstrapReceiptError):
            rebuild(fixture, s2_documents=documents)

    def test_publisher_runtime_lease_remains_explicitly_deferred(self):
        self.assert_invalid_bundle(
            lambda bundle, _fixture: bundle["leaseCanaryEvidence"][
                "publisherControllerRuntimeLeaseGate"
            ].update({"status": "complete"}),
            "explicitly deferred",
        )

    def test_terminal_statuses_do_not_overstate_direct_observation(self):
        components = self.fixture["components"]
        self.assertEqual(
            components["activationFenceBootstrap"]["status"],
            "initial-idle-fence-exact-created-or-adopted",
        )
        self.assertEqual(
            components["managedIdentityFetchSelfTest"]["status"],
            "source-derived-terminal-success",
        )
        self.assertEqual(
            components["bridgeEvidence"]["status"],
            "terminal-success-with-source-derived-boundaries-complete",
        )
        self.assertEqual(
            components["leaseCanaryEvidence"]["status"],
            "direct-controller-and-source-derived-activation-proof-complete",
        )


class SourceBindingRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = complete_fixture()

    def fresh(self):
        return copy.deepcopy(self.fixture)

    def test_create_and_adopt_paths_are_truthful_and_distinct(self):
        created = self.fixture["components"]
        adopted = complete_fixture(
            adopt_operations=(
                "uploadVersionedBridgePackage",
                "createInitialIdleActivationFence",
            )
        )["components"]
        for name in ("packageReadback", "activationFenceBootstrap"):
            with self.subTest(name=name):
                self.assertEqual(
                    created[name]["provisioningOutcome"],
                    "created-by-authorization",
                )
                self.assertEqual(created[name]["createCondition"], "If-None-Match:*")
                self.assertEqual(created[name]["createHttpStatus"], 201)
                self.assertEqual(adopted[name]["provisioningOutcome"], "adopted-exact")
                self.assertIsNone(adopted[name]["createCondition"])
                self.assertIsNone(adopted[name]["createHttpStatus"])

    def test_permanent_ledger_semantics_are_overwritten_from_source(self):
        fixture = self.fresh()
        original = fixture["components"]["permanentMutationLedger"]["entries"][0]
        components = copy.deepcopy(fixture["components"])
        altered = components["permanentMutationLedger"]["entries"][0]
        altered.update(
            {
                "target": "wrong-target",
                "kind": "wrong-kind",
                "outcome": "deleted-exact",
                "observedAt": fixture["completedAt"],
            }
        )
        rebuilt = rebuild(fixture, components=components)["bundle"]
        entry = rebuilt["permanentMutationLedger"]["entries"][0]
        for field in ("mutationId", "target", "kind", "outcome", "observedAt"):
            self.assertEqual(entry[field], original[field])

    def test_worm_semantics_are_overwritten_from_source(self):
        fixture = self.fresh()
        original = fixture["components"]["wormProjections"]["containers"][
            "acceptedReleases"
        ]
        components = copy.deepcopy(fixture["components"])
        altered = components["wormProjections"]["containers"]["acceptedReleases"]
        altered.update(
            {
                "state": "Unlocked",
                "retentionDays": 999,
                "allowProtectedAppendWrites": True,
                "allowProtectedAppendWritesAll": True,
                "etag": '"wrong-etag"',
                "observedAt": fixture["completedAt"],
            }
        )
        rebuilt = rebuild(fixture, components=components)["bundle"]
        item = rebuilt["wormProjections"]["containers"]["acceptedReleases"]
        for field in (
            "state",
            "retentionDays",
            "allowProtectedAppendWrites",
            "allowProtectedAppendWritesAll",
            "etag",
            "observedAt",
        ):
            self.assertEqual(item[field], original[field])

    def test_package_fence_and_bridge_semantic_contradictions_fail_closed(self):
        fixture = self.fresh()
        components = copy.deepcopy(fixture["components"])
        components["packageReadback"].update(
            {
                "provisioningOutcome": "adopted-exact",
                "createCondition": None,
                "createHttpStatus": None,
                "etag": '"wrong-package"',
                "versionId": "wrong-package-version",
                "observedAt": fixture["completedAt"],
            }
        )
        components["activationFenceBootstrap"].update(
            {
                "provisioningOutcome": "adopted-exact",
                "createCondition": None,
                "createHttpStatus": None,
                "etag": '"wrong-fence"',
                "versionId": "wrong-fence-version",
                "observedAt": fixture["completedAt"],
            }
        )
        components["bridgeEvidence"]["settings"].update(
            {
                "desiredSha256": "a" * 64,
                "afterSha256": "a" * 64,
            }
        )
        components["bridgeEvidence"]["observedAt"] = fixture["startedAt"]
        with self.assertRaises(receipts.BootstrapReceiptError):
            rebuild(fixture, components=components)

    def test_operation_observation_outside_claim_window_fails(self):
        fixture = self.fresh()
        source = copy.deepcopy(fixture["sourceEvidence"])
        source["allOperationProjections"][0]["observedAt"] = (
            "2026-08-30T03:59:59.999Z"
        )
        with self.assertRaises(receipts.BootstrapReceiptError):
            rebuild(fixture, source_evidence=source)

    def test_versioned_blob_journal_etag_and_version_are_cross_bound(self):
        fixture = self.fresh()
        source = copy.deepcopy(fixture["sourceEvidence"])
        for entry in source["productionBoundary"]["mutationJournal"]:
            if (
                entry["phase"] == "result"
                and entry["operationId"] == "uploadVersionedBridgePackage"
            ):
                entry["versionId"] = "wrong-version"
                break
        else:
            self.fail("uploadVersionedBridgePackage result is missing")
        with self.assertRaises(receipts.BootstrapReceiptError):
            rebuild(fixture, source_evidence=source)


class ProductionBoundaryClassifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = complete_fixture()

    @staticmethod
    def entry(method, target_url, *, phase="intent"):
        return {"phase": phase, "method": method, "targetUrl": target_url}

    def test_exact_accepted_blob_and_container_root_writes_are_forbidden(self):
        for url in (
            "https://mdspdbak2608089c4e.blob.core.windows.net/"
            "paperdesk-accepted-releases/v2/releases/receipt.json",
            "https://mdspdbak2608089c4e.blob.core.windows.net/"
            "paperdesk-accepted-releases?restype=container",
        ):
            with self.subTest(url=url):
                self.assertTrue(
                    receipts._is_accepted_container_data_plane_write(
                        self.entry("PUT", url),
                        "paperdesk-accepted-releases",
                    )
                )

    def test_authorized_arm_immutability_put_is_not_blob_persistence(self):
        url = (
            "https://management.azure.com/subscriptions/"
            "9c4e0d0d-602f-4cde-84bd-337250e5b64c/resourceGroups/"
            "rg-paperdesk-rollback-sea-20260808/providers/Microsoft.Storage/"
            "storageAccounts/mdspdbak2608089c4e/blobServices/default/containers/"
            "paperdesk-accepted-releases/immutabilityPolicies/default"
            "?api-version=2025-06-01"
        )
        self.assertFalse(
            receipts._is_accepted_container_data_plane_write(
                self.entry("PUT", url),
                "paperdesk-accepted-releases",
            )
        )

    def test_plan_exact_production_and_accepted_role_assignments_are_allowed(self):
        matching = []
        for entry in self.fixture["sourceEvidence"]["productionBoundary"][
            "mutationJournal"
        ]:
            if (
                entry["phase"] == "intent"
                and "roleassignments" in entry["targetUrl"].lower()
                and (
                    "master-data-structure-sea-9c4e0d0d" in entry["targetUrl"].lower()
                    or "paperdesk-accepted-releases" in entry["targetUrl"].lower()
                )
            ):
                matching.append(entry)
                self.assertEqual(
                    bootstrap._forbidden_release_mutation_classes(
                        entry["method"], entry["targetUrl"], self.fixture["plan"]
                    ),
                    (False, False),
                )
        self.assertTrue(matching)

    def test_unknown_role_assignment_target_still_fails_exact_journal_validation(self):
        fixture = copy.deepcopy(self.fixture)
        source = fixture["sourceEvidence"]
        changed = False
        for entry in source["productionBoundary"]["mutationJournal"]:
            if (
                entry["operationId"] == "createExactRoleAssignments"
                and "master-data-structure-sea-9c4e0d0d" in entry["targetUrl"].lower()
                and "roleassignments" in entry["targetUrl"].lower()
            ):
                prefix = entry["targetUrl"].lower().split("/roleassignments/", 1)[0]
                entry["targetUrl"] = (
                    prefix
                    + "/roleassignments/ffffffff-ffff-4fff-8fff-ffffffffffff"
                    + "?api-version=2022-04-01"
                )
                changed = True
        self.assertTrue(changed)
        with self.assertRaises(receipts.BootstrapReceiptError):
            rebuild(fixture, source_evidence=source)

    def test_site_config_and_accepted_blob_mutations_are_forbidden(self):
        plan = self.fixture["plan"]
        production = resource(plan, "productionSite")["resourceId"]
        cases = (
            (
                "PUT",
                "https://management.azure.com"
                + production
                + "/config/web?api-version=2025-03-01",
                (True, False),
            ),
            (
                "PUT",
                "https://mdspdbak2608089c4e.blob.core.windows.net/"
                "paperdesk-accepted-releases/v2/receipt.json",
                (False, True),
            ),
        )
        for method, url, expected in cases:
            with self.subTest(url=url):
                self.assertEqual(
                    bootstrap._forbidden_release_mutation_classes(method, url, plan),
                    expected,
                )

    def test_host_path_method_and_phase_must_all_be_exact(self):
        cases = (
            self.entry("PUT", "https://evil.invalid/paperdesk-accepted-releases/x"),
            self.entry(
                "PUT",
                "https://mdspdbak2608089c4e.blob.core.windows.net/"
                "paperdesk-accepted-releases-evil/blob.json",
            ),
            self.entry(
                "GET",
                "https://mdspdbak2608089c4e.blob.core.windows.net/"
                "paperdesk-accepted-releases/blob.json",
            ),
            self.entry(
                "PUT",
                "https://mdspdbak2608089c4e.blob.core.windows.net/"
                "paperdesk-accepted-releases/blob.json",
                phase="result",
            ),
        )
        for entry in cases:
            with self.subTest(entry=entry):
                self.assertFalse(
                    receipts._is_accepted_container_data_plane_write(
                        entry, "paperdesk-accepted-releases"
                    )
                )


class ReceiptByteBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = complete_fixture()

    def test_execution_receipt_rejects_more_than_16_mib(self):
        document = copy.deepcopy(
            self.fixture["completeReceipt"]["bundle"]["executionReceipt"]
        )
        document["sourceEvidence"]["oversizeTestOnly"] = "x" * (16 * 1024 * 1024)
        with self.assertRaisesRegex(
            receipts.BootstrapReceiptError, "invalid byte boundary"
        ):
            receipts._build_component("executionReceipt", document)

    def test_non_execution_component_rejects_more_than_1_mib(self):
        document = copy.deepcopy(self.fixture["components"]["permanentMutationLedger"])
        document["entries"][0]["target"] = "x" * (1024 * 1024)
        with self.assertRaisesRegex(
            receipts.BootstrapReceiptError, "invalid byte boundary"
        ):
            receipts._build_component("permanentMutationLedger", document)


class ReviewedPlanDigestTests(unittest.TestCase):
    def test_context_uses_exact_reviewed_plan_file_bytes(self):
        plan, plan_sha256 = bootstrap.load_plan()
        auth = reviewed_authorization(plan, plan_sha256)
        context = receipts._context(auth, plan)
        self.assertEqual(context["planSha256"], plan_sha256)
        self.assertEqual(plan_sha256, receipts.sha256_hex(receipts.PLAN_PATH.read_bytes()))

    def test_canonical_reserialization_is_not_reviewed_file_digest(self):
        plan, plan_sha256 = bootstrap.load_plan()
        canonical_digest = receipts.sha256_hex(plan)
        self.assertNotEqual(canonical_digest, plan_sha256)
        auth = reviewed_authorization(plan, plan_sha256)
        auth["plan"]["sha256"] = canonical_digest
        with self.assertRaisesRegex(
            receipts.BootstrapReceiptError, "reviewed plan file bytes"
        ):
            receipts._context(auth, plan)

    def test_alternate_plan_object_is_rejected(self):
        plan, plan_sha256 = bootstrap.load_plan()
        auth = reviewed_authorization(plan, plan_sha256)
        altered = copy.deepcopy(plan)
        altered["status"] = "alternate"
        with self.assertRaisesRegex(
            receipts.BootstrapReceiptError,
            "does not equal the reviewed source plan",
        ):
            receipts._context(auth, altered)


class ImmutableAuthorizationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.plan, self.plan_sha256 = bootstrap.load_plan()
        self.authorization = reviewed_authorization(self.plan, self.plan_sha256)

    def assert_rejected(self, mutate):
        altered = copy.deepcopy(self.authorization)
        mutate(altered)
        with self.assertRaisesRegex(
            receipts.BootstrapReceiptError,
            "immutable authorization evidence is invalid",
        ):
            receipts._context(altered, self.plan)

    def test_forged_signature_verification_is_rejected(self):
        self.assert_rejected(
            lambda value: value["source"]["reviewedHead"].__setitem__(
                "signatureVerified", False
            )
        )

    def test_forged_exact_head_review_is_rejected(self):
        self.assert_rejected(
            lambda value: value["source"]["reviewedHead"]["reviews"][0].__setitem__(
                "commitSha", "f" * 40
            )
        )

    def test_forged_required_check_is_rejected(self):
        self.assert_rejected(
            lambda value: value["source"]["reviewedHead"][
                "requiredCheck"
            ].__setitem__("conclusion", "failure")
        )

    def test_forged_merged_commit_verification_is_rejected(self):
        self.assert_rejected(
            lambda value: value["source"]["mergedMain"].__setitem__(
                "githubVerificationVerified", False
            )
        )


class SecretMaterialTests(unittest.TestCase):
    def test_plain_and_percent_encoded_sas_keys_are_rejected(self):
        values = (
            "https://example.invalid/blob?sig=secret",
            "https://example.invalid/blob?%73ig=secret",
            "https://example.invalid/blob?%2573ig=secret",
            "https://example.invalid/blob%3Fsv=2026-01-01%26sig=secret",
        )
        for value in values:
            with self.subTest(value=value), self.assertRaisesRegex(
                receipts.BootstrapReceiptError, "secret or capability"
            ):
                receipts._reject_secret_material(value, "test")

    def test_percent_encoded_sas_object_key_is_rejected(self):
        with self.assertRaisesRegex(receipts.BootstrapReceiptError, "forbidden field"):
            receipts._reject_secret_material({"%73ig": "secret"}, "test")

    def test_percent_encoded_compact_jose_delimiters_are_rejected(self):
        segment = "A" * 40
        for value in (
            f"{segment}%2E{segment}%2E{segment}",
            f"{segment}%252E{segment}%252E{segment}",
        ):
            with self.subTest(value=value), self.assertRaisesRegex(
                receipts.BootstrapReceiptError, "compact JOSE"
            ):
                receipts._reject_secret_material(value, "test")


class SourceDerivedTruthfulnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = complete_fixture()

    def test_activation_lease_is_exactly_source_bound(self):
        source = self.fixture["sourceEvidence"]
        proof = copy.deepcopy(source["leaseCanaryProofs"]["activationFenceLease"])
        component = copy.deepcopy(
            self.fixture["components"]["leaseCanaryEvidence"][
                "activationFenceLease"
            ]
        )
        webjob = copy.deepcopy(source["bridgeCanaryProof"]["webJobTerminal"])
        result = receipts._validate_activation_lease_source_proof(
            proof,
            component_lease=component,
            webjob_terminal=webjob,
            expected_marker_sha256=H("unused-marker"),
            context={},
            plan=self.fixture["plan"],
            started_at=dt.datetime.fromisoformat(
                self.fixture["startedAt"].replace("Z", "+00:00")
            ),
            completed_at=dt.datetime.fromisoformat(
                self.fixture["completedAt"].replace("Z", "+00:00")
            ),
        )
        self.assertEqual(result, proof)

    def test_activation_lease_actor_cannot_be_rebound(self):
        source = self.fixture["sourceEvidence"]
        proof = copy.deepcopy(source["leaseCanaryProofs"]["activationFenceLease"])
        component = copy.deepcopy(
            self.fixture["components"]["leaseCanaryEvidence"][
                "activationFenceLease"
            ]
        )
        proof["actor"]["actorResourceId"] = "/wrong/identity"
        with self.assertRaises(receipts.BootstrapReceiptError):
            receipts._validate_activation_lease_source_proof(
                proof,
                component_lease=component,
                webjob_terminal=source["bridgeCanaryProof"]["webJobTerminal"],
                expected_marker_sha256=H("unused-marker"),
                context={},
                plan=self.fixture["plan"],
                started_at=self.fixture["now"],
                completed_at=self.fixture["now"],
            )

    def test_managed_identity_source_claim_has_no_fetched_bytes(self):
        component = self.fixture["components"]["managedIdentityFetchSelfTest"]
        self.assertFalse(component["directPackageBytesObservedByExecutor"])
        self.assertNotIn("fetchedBytesSha256", component)
        self.assertNotIn("fetchedSize", component)
        self.assertNotIn("httpStatus", component)

    def test_managed_identity_direct_byte_claim_is_rejected(self):
        fixture = copy.deepcopy(self.fixture)
        document = copy.deepcopy(
            fixture["components"]["managedIdentityFetchSelfTest"]
        )
        document["directPackageBytesObservedByExecutor"] = True
        context = receipts._context(fixture["authorization"], fixture["plan"])
        started = dt.datetime.fromisoformat(
            fixture["startedAt"].replace("Z", "+00:00")
        )
        completed = dt.datetime.fromisoformat(
            fixture["completedAt"].replace("Z", "+00:00")
        )
        with self.assertRaisesRegex(
            receipts.BootstrapReceiptError, "not exact and truthful"
        ):
            receipts._validate_managed_identity_fetch(
                document,
                context,
                fixture["plan"],
                started_at=started,
                completed_at=completed,
                derived_response_sha256=document["responseProjectionSha256"],
            )


if __name__ == "__main__":
    unittest.main()
