"""Offline candidate grammar tests; fixture pins are synthetic, never evidence."""

import copy
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.control_lifecycle_offline_boundary import external_access_blocked

with external_access_blocked() as IMPORT_ATTEMPTS:
    from scripts import private_release_mailbox as mailbox
    from scripts import watchdog_evidence as evidence
    from scripts import watchdog_users_closed_baseline_candidate as candidate
    from provider import watchdog_state_provider as provider
    from scripts import check_deadline, watchdog_rollback_control
    from tests.test_watchdog_evidence import initial_baseline


PREPARED = "2026-10-02T10:00:00.000Z"
OBSERVED = "2026-10-02T09:00:00.000Z"
CONTROL_SHA = "b" * 40


def descriptor(blob):
    return {"blob": blob, "sha256": "1" * 64, "size": 128,
            "etag": '"fixture-etag"', "versionId": "2026-10-02T09:00:00.0000000Z"}


def fixture():
    """Complete declared metadata only; no corresponding cloud objects exist."""
    source = candidate.SOURCE_SHA
    result = {
        "schemaVersion": 1,
        "candidateType": candidate.CANDIDATE_TYPE,
        "baselineType": candidate.BASELINE_TYPE,
        "sourceRepository": copy.deepcopy(candidate.SOURCE_IDENTITY),
        "historicalSource": copy.deepcopy(candidate.HISTORICAL_SOURCE),
        "acceptedBaseline": descriptor(f"v2/accepted/{source}/bootstrap-consumed/manifest.json"),
        "deploymentBundle": descriptor(f"v1/accepted/{source}/bootstrap/deployment.zip"),
        "bootstrapConsumedMarker": descriptor("v2/bootstrap/current-production/consumed.json"),
        "historicalParityEvidence": descriptor(candidate.EVIDENCE_PREFIX + "parity.json"),
        "controlTrust": {
            "repository": evidence.WATCHDOG_REPOSITORY,
            "sourceSha": CONTROL_SHA, "treeSha": "c" * 40,
            "workflowRef": evidence.BASELINE_WORKFLOW_REF, "workflowSha": CONTROL_SHA,
            "providerPackageSha256": "2" * 64,
            "providerPackageManifestSha256": "3" * 64,
            "evidence": descriptor(candidate.EVIDENCE_PREFIX + "control.json"),
        },
        "custody": {},
        "independentDecisions": [],
        "closedIngress": {
            "admission": "users-closed", "policySha256": "4" * 64,
            "callbackPolicySha256": "5" * 64,
            "evidence": descriptor(candidate.EVIDENCE_PREFIX + "ingress.json"),
        },
        "preparedAt": PREPARED,
    }
    for purpose, (container, minimum) in candidate.CUSTODY_CONTAINERS.items():
        result["custody"][purpose] = {
            "resourceId": f"{candidate.STORAGE_RESOURCE}/blobServices/default/containers/{container}",
            "policyState": "Locked", "retentionDays": minimum,
            "policyETag": '"fixture-policy-etag"', "policySha256": "6" * 64,
            "observedAt": OBSERVED,
            "evidence": descriptor(candidate.EVIDENCE_PREFIX + purpose + "-custody.json"),
        }
    for index, login in enumerate(sorted(candidate.REVIEWERS)):
        result["independentDecisions"].append({
            "login": login, "decision": "approve", "controlSourceSha": CONTROL_SHA,
            "designSha256": "7" * 64, "sourceReviewId": str(20 + index),
            "sourceReviewSubmittedAt": OBSERVED, "designDecisionCommentId": str(30 + index),
            "designDecisionSubmittedAt": OBSERVED,
            "evidence": descriptor(candidate.EVIDENCE_PREFIX + login + "-decision.json"),
        })
    return result


def at(document, path):
    result = document
    for key in path:
        result = result[key]
    return result


def object_paths(document, path=()):
    if isinstance(document, dict):
        yield path
        for key, value in document.items():
            yield from object_paths(value, path + (key,))
    elif isinstance(document, list):
        for index, value in enumerate(document):
            yield from object_paths(value, path + (index,))


class UsersClosedBaselineCandidateTests(unittest.TestCase):
    def validate(self, document):
        with external_access_blocked() as attempts:
            try:
                return candidate.validate_users_closed_bootstrap_baseline_candidate(document)
            finally:
                self.assertEqual(attempts, [], "candidate crossed an external boundary")

    def reject(self, document):
        with self.assertRaises(candidate.CandidateError):
            self.validate(document)

    def test_import_and_complete_result_are_explicitly_non_authorizing(self):
        self.assertEqual(IMPORT_ATTEMPTS, [])
        document = fixture()
        original = copy.deepcopy(document)
        result = self.validate(document)
        expected = {
            "schemaVersion": 1, "status": "source-candidate-validated",
            "candidateType": candidate.CANDIDATE_TYPE, "baselineType": candidate.BASELINE_TYPE,
            "candidateSha256": hashlib.sha256(evidence.canonical_json(document)).hexdigest(),
            "authorizationAvailable": False, "providerStateInitializationAllowed": False,
            "liveActivationAllowed": False,
        }
        self.assertEqual(result, expected)
        self.assertEqual(document, original)
        document["acceptedBaseline"]["sha256"] = "8" * 64
        changed = self.validate(document)
        self.assertNotEqual(changed["candidateSha256"], result["candidateSha256"])
        self.assertFalse(changed["authorizationAvailable"])

    def test_historical_pins_equal_existing_owner_without_inventing_acceptance(self):
        self.assertEqual(candidate.HISTORICAL_SOURCE, mailbox.BOOTSTRAP_BASELINE)
        historical = fixture()["historicalSource"]
        self.assertEqual(historical["sourceRunId"], "31845287909")
        self.assertEqual(historical["readinessHttpStatus"], 503)
        self.assertFalse(any("acceptance" in name.lower() for name in historical))

    def test_all_nested_objects_reject_each_missing_and_extra_field(self):
        document = fixture()
        for path in object_paths(document):
            for name in at(document, path):
                with self.subTest(path=path, missing=name):
                    changed = copy.deepcopy(document)
                    del at(changed, path)[name]
                    self.reject(changed)
            with self.subTest(path=path, extra=True):
                changed = copy.deepcopy(document)
                at(changed, path)["unexpected"] = True
                self.reject(changed)

    def test_schema_types_and_fixed_historical_pins_are_exact(self):
        for path, value in (
            (("schemaVersion",), True), (("schemaVersion",), 1.0), (("schemaVersion",), 2),
            (("candidateType",), "watchdog-initial-rollback-baseline"),
            (("baselineType",), "strict"), (("sourceRepository", "ref"), "refs/heads/other"),
            (("historicalSource", "sourceSha"), "a" * 40),
            (("historicalSource", "sourceRunId"), "1"),
            (("historicalSource", "artifactId"), "1"),
            (("historicalSource", "servedIndexSha256"), "a" * 64),
            (("historicalSource", "readinessHttpStatus"), 200),
            (("historicalSource", "oneDeployInvariant", "deploymentCount"), 10.0),
            (("historicalSource", "localEvidenceSha256"), "a" * 64),
        ):
            with self.subTest(path=path, value=value):
                changed = fixture()
                at(changed, path[:-1])[path[-1]] = value
                self.reject(changed)

    def test_fixed_descriptor_paths_cannot_alias_strict_or_unconsumed_baselines(self):
        for name, value in (
            ("acceptedBaseline", f"v2/accepted/{candidate.SOURCE_SHA}/bootstrap/manifest.json"),
            ("acceptedBaseline", f"v2/accepted/{candidate.SOURCE_SHA}/manifest.json"),
            ("acceptedBaseline", "v1/releases/sha/source/acceptance/registry-manifest.json"),
            ("deploymentBundle", f"v1/pending/{candidate.SOURCE_SHA}/deployment.zip"),
            ("bootstrapConsumedMarker", "v2/bootstrap/other/consumed.json"),
        ):
            with self.subTest(name=name, value=value):
                changed = fixture()
                changed[name]["blob"] = value
                self.reject(changed)

    def test_each_descriptor_rejects_malformed_metadata_and_paths(self):
        document = fixture()
        paths = [path for path in object_paths(document)
                 if set(at(document, path)) == candidate.DESCRIPTOR_FIELDS]
        for path in paths:
            for key, value in (
                ("blob", "/absolute.json"), ("blob", "v2//empty.json"),
                ("blob", candidate.EVIDENCE_PREFIX + "../escape.json"),
                ("blob", candidate.EVIDENCE_PREFIX + "./dot.json"),
                ("blob", candidate.EVIDENCE_PREFIX + "%2e%2e/escape.json"),
                ("blob", "C:\\private\\file.json"), ("blob", "https://example.invalid/file.json"),
                ("blob", candidate.EVIDENCE_PREFIX + "file.json?query"),
                ("sha256", "0" * 64), ("sha256", "A" * 64), ("sha256", "1" * 63),
                ("size", True), ("size", 0), ("size", 1.0), ("size", candidate.MAX_PACKAGE_BYTES + 1),
                ("etag", "unquoted"), ("etag", '"0"'), ("etag", '"null"'),
                ("etag", '"pending"'), ("etag", '"bad\nvalue"'),
                ("etag", '"bad\tvalue"'), ("etag", '""'), ("versionId", "pending"),
                ("versionId", "0"), ("versionId", "null"), ("versionId", ""),
                ("versionId", "bad\nversion"),
            ):
                with self.subTest(path=path, key=key, value=value):
                    changed = copy.deepcopy(document)
                    at(changed, path)[key] = value
                    self.reject(changed)

    def test_descriptor_positive_limits_remain_non_authorizing(self):
        document = fixture()
        document["deploymentBundle"]["size"] = candidate.MAX_PACKAGE_BYTES
        result = self.validate(document)
        self.assertFalse(result["liveActivationAllowed"])
        document["historicalParityEvidence"]["size"] = candidate.MAX_CANDIDATE_BYTES
        self.assertFalse(self.validate(document)["providerStateInitializationAllowed"])
        document["historicalParityEvidence"]["size"] += 1
        self.reject(document)

    def test_control_trust_cannot_use_branch_or_mismatched_workflow_pins(self):
        for key, value in (
            ("repository", evidence.SOURCE_REPOSITORY), ("sourceSha", "main"),
            ("sourceSha", "0" * 40), ("treeSha", "0" * 40),
            ("workflowSha", "d" * 40), ("workflowRef", evidence.WATCHDOG_WORKFLOW_REF),
            ("providerPackageSha256", "0" * 64),
            ("providerPackageManifestSha256", "0" * 64),
        ):
            with self.subTest(key=key):
                changed = fixture()
                changed["controlTrust"][key] = value
                self.reject(changed)

    def test_custody_uses_distinct_existing_scopes_and_retention_boundaries(self):
        for purpose, (_, minimum) in candidate.CUSTODY_CONTAINERS.items():
            for key, value in (
                ("retentionDays", minimum - 1), ("retentionDays", True),
                ("retentionDays", float(minimum)), ("policyState", "Unlocked"),
                ("resourceId", candidate.STORAGE_RESOURCE), ("policyETag", '"pending"'),
                ("policySha256", "0" * 64), ("observedAt", "2026-10-02T11:00:00.000Z"),
            ):
                with self.subTest(purpose=purpose, key=key):
                    changed = fixture()
                    changed["custody"][purpose][key] = value
                    self.reject(changed)
            changed = fixture()
            changed["custody"][purpose]["retentionDays"] = minimum + 1
            self.assertFalse(self.validate(changed)["authorizationAvailable"])

    def test_independent_decision_pins_cannot_alias_or_invent_review_coordinates(self):
        for key, value in (
            ("login", "Sethvirak"), ("decision", "commented"),
            ("controlSourceSha", "d" * 40), ("designSha256", "8" * 64),
            ("sourceReviewId", "0"), ("sourceReviewId", 20),
            ("designDecisionCommentId", "0"), ("designDecisionCommentId", True),
            ("sourceReviewSubmittedAt", "2026-10-02T11:00:00.000Z"),
            ("designDecisionSubmittedAt", "2026-10-02T09:00:00Z"),
        ):
            with self.subTest(key=key):
                changed = fixture()
                changed["independentDecisions"][0][key] = value
                self.reject(changed)
        changed = fixture()
        changed["independentDecisions"][1] = copy.deepcopy(changed["independentDecisions"][0])
        self.reject(changed)
        for decisions in ([], [fixture()["independentDecisions"][0]], tuple(fixture()["independentDecisions"])):
            changed = fixture()
            changed["independentDecisions"] = decisions
            self.reject(changed)

    def test_fabricated_acceptance_fields_and_http403_cannot_be_closure_proof(self):
        for name in ("sourceRunId", "acceptanceRunId", "acceptanceRunAttempt", "acceptedReleasePrefix"):
            changed = fixture()
            changed[name] = "99"
            self.reject(changed)
        changed = fixture()
        changed["historicalSource"]["acceptanceRunId"] = "99"
        self.reject(changed)
        for key, value in (("admission", "users-open"), ("policySha256", "0" * 64),
                           ("callbackPolicySha256", "0" * 64), ("status", 403), ("proof", True)):
            changed = fixture()
            changed["closedIngress"][key] = value
            self.reject(changed)

    def test_distinct_reviewers_cannot_alias_the_same_human_decision_record(self):
        for name in ("sourceReviewId", "designDecisionCommentId"):
            changed = fixture()
            changed["independentDecisions"][1][name] = changed["independentDecisions"][0][name]
            self.reject(changed)

    def test_ordinary_admission_still_rejects_the_new_type_before_transport(self):
        with external_access_blocked() as attempts:
            ordinary = initial_baseline()
            self.assertEqual(evidence.validate_initial_baseline(ordinary), ordinary)
            with self.assertRaises(evidence.EvidenceError):
                evidence.validate_initial_baseline(fixture())
            with self.assertRaises(evidence.EvidenceError):
                evidence.initialize_baseline_with_token(
                    raw_baseline=evidence.canonical_json(fixture()), token="unused-fixture")
            self.assertEqual(attempts, [])
        self.reject(ordinary)

    def test_preparation_timestamp_and_non_json_values_fail_locally(self):
        for value in (True, None, "2026-10-02T10:00:00Z", "2026-02-30T10:00:00.000Z"):
            changed = fixture()
            changed["preparedAt"] = value
            self.reject(changed)
        for value in (None, [], "raw-json-is-not-an-admitted-object"):
            self.reject(value)
        for value in (float("nan"), float("inf"), object()):
            changed = fixture()
            changed["historicalSource"]["oneDeployInvariant"]["deploymentCount"] = value
            self.reject(changed)


def projection_fixture(declared=None):
    """Synthetic B1 projection/receipt; never create canonical admission files."""
    declared = fixture() if declared is None else copy.deepcopy(declared)
    review = {
        "workflowRef": evidence.BASELINE_WORKFLOW_REF, "workflowSha": CONTROL_SHA,
        "runId": "700", "runAttempt": "1", "environment": evidence.BASELINE_ENVIRONMENT,
        "preparedAt": PREPARED,
    }
    blob = candidate.EVIDENCE_PREFIX + "700/1/initial.json"
    candidate_sha = hashlib.sha256(evidence.canonical_json(declared)).hexdigest()
    body = {
        "schemaVersion": 1, "receiptType": "watchdog-users-closed-baseline-candidate-receipt",
        "recordedAt": PREPARED, "sourceRepository": copy.deepcopy(declared["sourceRepository"]),
        "candidateSha256": candidate_sha, "candidate": declared,
        "review": review, "evidencePath": blob,
    }
    raw = evidence.canonical_json(body)
    receipt_descriptor = descriptor(blob)
    receipt_descriptor.update(sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    projection = {
        "schemaVersion": 1, "baselineType": candidate.BASELINE_TYPE,
        "candidateSha256": candidate_sha, "candidate": declared,
        "baselineReceipt": receipt_descriptor, "review": review,
    }
    record = provider.WormRecord(document=body, raw=raw, sha256=receipt_descriptor["sha256"],
                                 path=blob, etag=receipt_descriptor["etag"],
                                 version_id=receipt_descriptor["versionId"], created=False)
    return projection, record


class UsersClosedBaselineProjectionTests(unittest.TestCase):
    def blocked(self, operation, *args):
        with external_access_blocked() as attempts:
            try:
                return operation(*args)
            finally:
                self.assertEqual(attempts, [], "B1 crossed an external boundary")

    def validate(self, document):
        return self.blocked(candidate.validate_users_closed_baseline_projection, document)

    def inspect(self, document, record):
        return self.blocked(candidate.inspect_users_closed_baseline_receipt, document, record)

    def reject(self, document, record=None):
        with self.assertRaises(candidate.CandidateError):
            if record is None:
                self.validate(document)
            else:
                self.inspect(document, record)

    def test_complete_projection_and_actual_worm_record_inspection_are_non_authorizing(self):
        projection, record = projection_fixture()
        before = copy.deepcopy(projection)
        projection_sha = hashlib.sha256(evidence.canonical_json(projection)).hexdigest()
        shared = {
            "schemaVersion": 1, "baselineType": candidate.BASELINE_TYPE,
            "candidateSha256": projection["candidateSha256"], "projectionSha256": projection_sha,
            "baselineReceiptSha256": projection["baselineReceipt"]["sha256"],
            "authorizationAvailable": False, "providerStateInitializationAllowed": False,
            "liveActivationAllowed": False,
        }
        self.assertEqual(self.validate(projection), {
            **shared, "status": "source-projection-validated", "receiptScope": "declared-pins-only",
        })
        self.assertEqual(self.inspect(projection, record), {
            **shared, "status": "source-baseline-receipt-inspected",
            "receiptScope": "caller-supplied-bytes-only",
        })
        self.assertEqual(projection, before)
        self.assertFalse(record.created)
        self.assertEqual(self.inspect(projection, replace(record, created=True)), self.inspect(projection, record))
        self.assertEqual(candidate.MAX_CANDIDATE_BYTES, provider.MAX_BODY)

    def test_fresh_provider_import_reads_no_environment_and_constructs_no_clients(self):
        attempts = []

        class NoEnvironment(dict):
            def denied(self, *args, **kwargs):
                attempts.append("environment access")
                raise AssertionError("B1 import consulted the environment")

            __getitem__ = __contains__ = __iter__ = get = items = keys = values = denied

        module_name = "provider._b1_pure_import_probe"
        spec = importlib.util.spec_from_file_location(module_name, ROOT / "provider/watchdog_state_provider.py")
        module = importlib.util.module_from_spec(spec)
        prior_profile = sys.getprofile()

        def reject_construction(frame, event, arg):
            if (event == "call" and frame.f_globals.get("__name__") == module_name
                    and frame.f_code.co_name == "__init__"):
                attempts.append("owner object construction")
                raise AssertionError("B1 import constructed an owner object")

        with external_access_blocked() as external_attempts:
            try:
                with mock.patch.object(os, "environ", NoEnvironment()), mock.patch.dict(sys.modules, {module_name: module}):
                    sys.setprofile(reject_construction)
                    spec.loader.exec_module(module)
            finally:
                sys.setprofile(prior_profile)
            self.assertEqual(external_attempts, [])
        self.assertEqual(attempts, [])
        self.assertEqual(module.MAX_BODY, provider.MAX_BODY)
        self.assertIsNot(module.WormRecord, provider.WormRecord)

    def test_every_nested_projection_object_rejects_missing_or_extra_fields(self):
        document, record = projection_fixture()
        for path in object_paths(document):
            for name in at(document, path):
                with self.subTest(path=path, missing=name):
                    changed = copy.deepcopy(document)
                    del at(changed, path)[name]
                    self.reject(changed)
                    self.reject(changed, record)
            with self.subTest(path=path, extra=True):
                changed = copy.deepcopy(document)
                at(changed, path)["unexpected"] = True
                self.reject(changed)
                self.reject(changed, record)

    def test_schema_candidate_and_review_coordinates_bind_before_inspection(self):
        document, record = projection_fixture()
        for path, value in (
            (("schemaVersion",), True), (("schemaVersion",), 1.0), (("schemaVersion",), 2),
            (("baselineType",), "watchdog-initial-rollback-baseline"),
            (("candidateSha256",), "0" * 64), (("candidateSha256",), "8" * 64),
            (("candidate", "historicalSource", "sourceSha"), "8" * 40),
            (("candidate", "independentDecisions", 0, "sourceReviewId"), "999"),
            (("review", "workflowRef"), evidence.WATCHDOG_WORKFLOW_REF),
            (("review", "workflowSha"), "d" * 40),
            (("review", "environment"), "production"), (("review", "runId"), "0"),
            (("review", "runId"), 700), (("review", "runAttempt"), True),
            (("review", "runAttempt"), "0"), (("review", "runId"), "701"),
            (("review", "preparedAt"), "2026-10-02T09:00:00.000Z"),
            (("review", "preparedAt"), "2026-10-02T10:00:00Z"),
        ):
            with self.subTest(path=path, value=value):
                changed = copy.deepcopy(document)
                at(changed, path[:-1])[path[-1]] = value
                self.reject(changed)
                self.reject(changed, record)

    def test_receipt_descriptor_is_exact_bounded_and_bound_to_expected_body(self):
        document, record = projection_fixture()
        for name, value in (
            ("blob", "v2/baselines/700/1/initial.json"),
            ("blob", candidate.EVIDENCE_PREFIX + "701/1/initial.json"),
            ("blob", candidate.EVIDENCE_PREFIX + "700/1/../initial.json"),
            ("blob", candidate.EVIDENCE_PREFIX + "700/1/initial.json?version=1"),
            ("blob", candidate.EVIDENCE_PREFIX + "700\\1\\initial.json"),
            ("sha256", "0" * 64), ("sha256", "8" * 64), ("sha256", "1" * 63),
            ("size", True), ("size", 0), ("size", len(record.raw) + 1),
            ("size", candidate.MAX_CANDIDATE_BYTES + 1),
            ("etag", '"pending"'), ("etag", '"0"'), ("etag", "fixture-etag"), ("etag", '""'),
            ("versionId", "pending"), ("versionId", "0"), ("versionId", "version/id"),
        ):
            with self.subTest(name=name, value=value):
                changed = copy.deepcopy(document)
                changed["baselineReceipt"][name] = value
                self.reject(changed)
                self.reject(changed, record)

    def test_other_valid_etag_or_version_remains_unverified_until_exact_record_match(self):
        document, record = projection_fixture()
        for name, value in (("etag", '"other-etag"'), ("versionId", "other-version")):
            with self.subTest(name=name):
                changed = copy.deepcopy(document)
                changed["baselineReceipt"][name] = value
                self.assertFalse(self.validate(changed)["authorizationAvailable"])
                self.reject(changed, record)

    def test_actual_owner_record_rejects_type_subclass_and_malformed_field_types(self):
        document, record = projection_fixture()

        class OtherRecord:
            pass

        class DerivedRecord(provider.WormRecord):
            pass

        derived = DerivedRecord(**record.__dict__)
        for other in (OtherRecord(), derived, record.__dict__):
            with self.subTest(type=type(other).__name__):
                self.reject(document, other)
        for name, value in (
            ("raw", bytearray(record.raw)), ("raw", record.raw.decode("utf-8")),
            ("document", []), ("document", None), ("created", 1), ("created", None),
            ("sha256", 1), ("path", None), ("etag", None), ("version_id", True),
        ):
            with self.subTest(name=name):
                self.reject(document, replace(record, **{name: value}))

    def test_record_digest_path_metadata_and_document_cannot_disagree(self):
        document, record = projection_fixture()
        other_body = copy.deepcopy(record.document)
        other_body["review"]["runId"] = "701"
        for name, value in (
            ("sha256", "8" * 64), ("path", candidate.EVIDENCE_PREFIX + "701/1/initial.json"),
            ("etag", '"other-etag"'), ("version_id", "other-version"),
            ("raw", record.raw[:-1]), ("document", other_body),
        ):
            with self.subTest(name=name):
                self.reject(document, replace(record, **{name: value}))

    def test_actual_canonical_owner_rejects_duplicate_noncanonical_invalid_and_oversize_bytes(self):
        document, record = projection_fixture()
        bodies = (
            json.dumps(record.document, indent=2).encode("utf-8"),
            b'{"schemaVersion":1,' + record.raw[1:], record.raw + b'{}',
            record.raw[:-2], b'\xff', b'[]\n', b'{"value":NaN}\n',
            b'{}\n' + b' ' * candidate.MAX_CANDIDATE_BYTES,
        )
        for raw in bodies:
            with self.subTest(length=len(raw), prefix=raw[:24]):
                self.reject(document, replace(record, raw=raw, sha256=hashlib.sha256(raw).hexdigest()))

    def test_recomputed_foreign_body_or_review_pins_still_cannot_match_the_projection(self):
        document, record = projection_fixture()
        for path, value in (
            (("schemaVersion",), 2), (("receiptType",), "watchdog-initial-rollback-baseline"),
            (("review", "runAttempt"), "2"), (("review", "workflowSha"), "e" * 40),
            (("candidate", "independentDecisions", 0, "sourceReviewId"), "999"),
            (("evidencePath",), candidate.EVIDENCE_PREFIX + "700/2/initial.json"),
        ):
            with self.subTest(path=path):
                changed_body = copy.deepcopy(record.document)
                at(changed_body, path[:-1])[path[-1]] = value
                raw = evidence.canonical_json(changed_body)
                changed = copy.deepcopy(document)
                digest = hashlib.sha256(raw).hexdigest()
                changed["baselineReceipt"].update(sha256=digest, size=len(raw))
                foreign = replace(record, document=changed_body, raw=raw, sha256=digest)
                self.reject(changed)
                self.reject(changed, foreign)

    def test_valid_candidate_cannot_hide_an_oversize_wrapped_projection(self):
        declared = fixture()
        base_length = len(evidence.canonical_json(declared))
        declared["independentDecisions"][0]["sourceReviewId"] = "9" * (
            candidate.MAX_CANDIDATE_BYTES - base_length + 2)
        self.assertEqual(len(evidence.canonical_json(declared)), candidate.MAX_CANDIDATE_BYTES)
        self.assertFalse(self.blocked(candidate.validate_users_closed_bootstrap_baseline_candidate, declared)[
            "authorizationAvailable"])
        document, record = projection_fixture(declared)
        self.assertGreater(len(record.raw), provider.MAX_BODY)
        self.reject(document)
        self.reject(document, record)

    def test_cross_type_and_ordinary_state_initialization_reject_before_storage_or_dispatch(self):
        document, record = projection_fixture()
        for other in (initial_baseline(), fixture(), None, [], "{}"):
            self.reject(other)
            self.reject(other, record)
        machine = provider.state_contract.load_contract()
        state = {"schemaVersion": 2, "generatedAt": PREPARED,
                 "sourceRepository": copy.deepcopy(candidate.SOURCE_IDENTITY),
                 "rollbackBaseline": document, "pendingCandidate": None}
        claims = {
            "repository": evidence.WATCHDOG_REPOSITORY,
            "repository_id": provider.WATCHDOG_REPOSITORY_ID,
            "repository_owner_id": provider.WATCHDOG_OWNER_ID,
            "workflow_ref": evidence.BASELINE_WORKFLOW_REF, "environment": evidence.BASELINE_ENVIRONMENT,
            "sha": CONTROL_SHA, "workflow_sha": CONTROL_SHA, "run_id": "700", "run_attempt": "1",
        }
        for ordinary_call, args in (
            (evidence.validate_initial_baseline, (document,)),
            (provider._validate_baseline, (document,)), (provider.validate_state, (state, machine)),
            (provider.WatchdogProvider.initialize_baseline, (object(), document, claims)),
        ):
            with self.subTest(operation=ordinary_call.__name__):
                with self.assertRaises((evidence.EvidenceError, provider.ProviderError)):
                    self.blocked(ordinary_call, *args)

    def test_candidate_retention_grammar_does_not_weaken_provider_exact90_predicate(self):
        document, record = projection_fixture()
        document["candidate"]["custody"]["watchdog"]["retentionDays"] = 91
        document, record = projection_fixture(document["candidate"])
        self.assertFalse(self.inspect(document, record)["providerStateInitializationAllowed"])
        policy = {
            "state": "Locked", "immutabilityPeriodSinceCreationInDays": 90,
            "allowProtectedAppendWrites": False, "allowProtectedAppendWritesAll": False,
            "etag": '"policy-etag"', "observedAt": PREPARED,
        }

        def supplied_policy(container):
            self.assertEqual(container, provider.EVIDENCE_CONTAINER)
            return policy

        owner = SimpleNamespace(storage=SimpleNamespace(policy=supplied_policy),
                                _now=lambda: provider.parse_canonical_time(PREPARED, "synthetic test clock"))
        self.blocked(provider.WatchdogProvider._require_worm_policy, owner)
        policy["immutabilityPeriodSinceCreationInDays"] = 91
        with self.assertRaises(provider.ProviderError) as caught:
            self.blocked(provider.WatchdogProvider._require_worm_policy, owner)
        self.assertEqual(caught.exception.code, "worm-policy-invalid")


def recovery_fixture(baseline_projection=None, record=None):
    """Source-only declared recovery pins, never state or dispatch input."""
    if baseline_projection is None:
        baseline_projection, record = projection_fixture()
    declared = baseline_projection["candidate"]
    recovery = {
        "schemaVersion": 1,
        "projectionType": "paperdesk-watchdog-users-closed-recovery-projection",
        "baselineType": candidate.BASELINE_TYPE,
        "baselineProjectionSha256": hashlib.sha256(evidence.canonical_json(baseline_projection)).hexdigest(),
        "baselineReceipt": copy.deepcopy(baseline_projection["baselineReceipt"]),
        **{name: copy.deepcopy(declared[name]) for name in (
            "sourceRepository", "historicalSource", "acceptedBaseline", "deploymentBundle",
            "bootstrapConsumedMarker", "closedIngress",
        )},
        "settlementPolicy": {
            "historicalReadinessStatus": 503,
            "historicalReadinessCode": "attachment-malware-ingestion-not-ready",
            "classification": "users-closed-degraded",
            "healthy": False, "accepted": False, "userAdmissionAllowed": False,
            "scanWindowAllowed": False,
        },
    }
    return recovery, baseline_projection, record


class UsersClosedRecoveryProjectionTests(unittest.TestCase):
    def blocked(self, operation, *args, **kwargs):
        with external_access_blocked() as attempts:
            try:
                return operation(*args, **kwargs)
            finally:
                self.assertEqual(attempts, [], "B2 crossed an external boundary")

    def validate(self, document, baseline, record):
        return self.blocked(candidate.validate_users_closed_recovery_projection, document, baseline, record)

    def reject(self, document, baseline, record):
        with self.assertRaises(candidate.CandidateError):
            self.validate(document, baseline, record)

    def test_complete_recovery_projection_is_degraded_closed_and_non_authorizing(self):
        recovery, baseline, record = recovery_fixture()
        original = copy.deepcopy((recovery, baseline, record))
        expected = {
            "schemaVersion": 1, "status": "source-recovery-projection-validated",
            "projectionType": "paperdesk-watchdog-users-closed-recovery-projection",
            "baselineType": candidate.BASELINE_TYPE, "receiptScope": "caller-supplied-bytes-only",
            "settlementScope": "declared-historical-policy-only",
            "baselineProjectionSha256": recovery["baselineProjectionSha256"],
            "recoveryProjectionSha256": hashlib.sha256(evidence.canonical_json(recovery)).hexdigest(),
            "baselineReceiptSha256": recovery["baselineReceipt"]["sha256"],
            "settlementClassification": "users-closed-degraded",
            "healthy": False, "accepted": False, "userAdmissionAllowed": False,
            "scanWindowAllowed": False, "authorizationAvailable": False,
            "providerStateInitializationAllowed": False, "liveActivationAllowed": False,
        }
        self.assertEqual(self.validate(recovery, baseline, record), expected)
        self.assertEqual((recovery, baseline, record), original)

    def test_all_nested_recovery_fields_are_exact(self):
        document, baseline, record = recovery_fixture()
        for path in object_paths(document):
            for name in at(document, path):
                with self.subTest(path=path, missing=name):
                    changed = copy.deepcopy(document)
                    del at(changed, path)[name]
                    self.reject(changed, baseline, record)
            with self.subTest(path=path, extra=True):
                changed = copy.deepcopy(document)
                at(changed, path)["unexpected"] = True
                self.reject(changed, baseline, record)

    def test_schema_cross_type_and_full_projection_hash_are_exact(self):
        document, baseline, record = recovery_fixture()
        for name, value in (
            ("schemaVersion", True), ("schemaVersion", 1.0), ("schemaVersion", 2),
            ("projectionType", candidate.CANDIDATE_TYPE),
            ("projectionType", "rollback-accepted-release"), ("baselineType", "strict"),
            ("baselineProjectionSha256", "0" * 64), ("baselineProjectionSha256", "8" * 64),
            ("baselineProjectionSha256", "A" * 64), ("baselineProjectionSha256", "1" * 63),
        ):
            with self.subTest(name=name, value=value):
                changed = copy.deepcopy(document)
                changed[name] = value
                self.reject(changed, baseline, record)
        for other in (initial_baseline(), fixture(), baseline, None, [], "{}"):
            self.reject(other, baseline, record)
        for other in (initial_baseline(), fixture(), document, None, []):
            self.reject(document, other, record)

    def test_every_historical_pin_and_source_identity_binds_to_complete_b1(self):
        document, baseline, record = recovery_fixture()
        for path, value in (
            (("sourceRepository", "repository"), "Sethvirak/other"),
            (("sourceRepository", "repositoryId"), "1"),
            (("historicalSource", "sourceSha"), "8" * 40),
            (("historicalSource", "sourceRunId"), "1"),
            (("historicalSource", "sourceRunAttempt"), "2"),
            (("historicalSource", "artifactId"), "1"),
            (("historicalSource", "artifactSha256"), "8" * 64),
            (("historicalSource", "artifactMemberSha256"), "8" * 64),
            (("historicalSource", "servedIndexSha256"), "8" * 64),
            (("historicalSource", "localEvidenceSha256"), "8" * 64),
            (("historicalSource", "oneDeployInvariant", "deploymentCount"), 10.0),
            (("historicalSource", "oneDeployInvariant", "historicalActiveDeploymentId"), "other"),
            (("historicalSource", "oneDeployInvariant", "propertyIdSetSha256"), "8" * 64),
        ):
            with self.subTest(path=path):
                changed = copy.deepcopy(document)
                at(changed, path[:-1])[path[-1]] = value
                self.reject(changed, baseline, record)

    def test_every_complete_descriptor_rejects_metadata_or_path_alias(self):
        document, baseline, record = recovery_fixture()
        paths = [path for path in object_paths(document)
                 if set(at(document, path)) == candidate.DESCRIPTOR_FIELDS]
        self.assertEqual(len(paths), 5)
        for path in paths:
            for name, value in (
                ("blob", candidate.EVIDENCE_PREFIX + "other.json"),
                ("blob", "/absolute.json"), ("blob", "v2/../escape.json"),
                ("sha256", "0" * 64), ("sha256", "8" * 64),
                ("size", 0), ("size", True), ("size", at(document, path)["size"] + 1),
                ("etag", '"other-etag"'), ("etag", '"pending"'),
                ("versionId", "other-version"), ("versionId", "0"),
            ):
                with self.subTest(path=path, name=name):
                    changed = copy.deepcopy(document)
                    at(changed, path)[name] = value
                    self.reject(changed, baseline, record)

    def test_settlement_cannot_claim_health_acceptance_ingress_or_scan_window(self):
        document, baseline, record = recovery_fixture()
        for name, value in (
            ("historicalReadinessStatus", 200), ("historicalReadinessStatus", 503.0),
            ("historicalReadinessCode", ""), ("classification", "healthy-no-pending"),
            ("classification", "accepted"),
            *((name, value) for name in ("healthy", "accepted", "userAdmissionAllowed", "scanWindowAllowed")
              for value in (True, 0, None, "false")),
        ):
            with self.subTest(name=name, value=value):
                changed = copy.deepcopy(document)
                changed["settlementPolicy"][name] = value
                self.reject(changed, baseline, record)

    def test_closed_ingress_and_callback_pins_cannot_be_replaced_by_http_or_boolean_claims(self):
        document, baseline, record = recovery_fixture()
        for name, value in (
            ("admission", "users-open"), ("policySha256", "8" * 64),
            ("callbackPolicySha256", "8" * 64), ("status", 403), ("proof", True),
        ):
            with self.subTest(name=name):
                changed = copy.deepcopy(document)
                changed["closedIngress"][name] = value
                self.reject(changed, baseline, record)

    def test_acceptance_aliases_and_stage_c_or_d_fields_are_never_admitted(self):
        document, baseline, record = recovery_fixture()
        for name, value in (
            ("acceptanceRunId", "999"), ("acceptanceRunAttempt", "1"),
            ("acceptedReleasePrefix", "v1/releases/source/1/2/"),
            ("pendingCandidate", None), ("armedAt", PREPARED), ("hardDeadline", PREPARED),
            ("attemptId", "fixture"), ("acceptedReceiptPresent", True),
            ("authorizationAvailable", True), ("dispatchInputs", {}),
        ):
            for path in ((), ("historicalSource",), ("settlementPolicy",)):
                with self.subTest(name=name, path=path):
                    changed = copy.deepcopy(document)
                    at(changed, path)[name] = value
                    self.reject(changed, baseline, record)

    def test_binding_includes_full_review_custody_and_control_not_only_copied_recovery_facets(self):
        document, baseline, record = recovery_fixture()
        for path, value in (
            (("custody", "watchdog", "policySha256"), "9" * 64),
            (("independentDecisions", 0, "sourceReviewId"), "999"),
            (("controlTrust", "treeSha"), "d" * 40),
        ):
            with self.subTest(path=path):
                changed_candidate = copy.deepcopy(baseline["candidate"])
                at(changed_candidate, path[:-1])[path[-1]] = value
                changed_baseline, changed_record = projection_fixture(changed_candidate)
                self.reject(document, changed_baseline, changed_record)
                rebound, _, _ = recovery_fixture(changed_baseline, changed_record)
                self.assertNotEqual(rebound["baselineProjectionSha256"], document["baselineProjectionSha256"])
                self.assertFalse(self.validate(rebound, changed_baseline, changed_record)["authorizationAvailable"])

    def test_actual_owner_record_is_inspected_instead_of_accepting_a_b1_result_claim(self):
        document, baseline, record = recovery_fixture()
        alleged_result = self.blocked(candidate.inspect_users_closed_baseline_receipt, baseline, record)
        for other in (record.__dict__, alleged_result, object()):
            self.reject(document, baseline, other)
        for name, value in (
            ("etag", '"other-etag"'), ("version_id", "other-version"),
            ("sha256", "8" * 64), ("raw", record.raw[:-1]), ("document", {}), ("created", 1),
        ):
            with self.subTest(name=name):
                self.reject(document, baseline, replace(record, **{name: value}))
        self.assertEqual(self.validate(document, baseline, replace(record, created=True)),
                         self.validate(document, baseline, record))

    def test_large_complete_b1_is_bound_and_oversize_recovery_or_nonfinite_input_fails(self):
        declared = fixture()
        declared["independentDecisions"][0]["sourceReviewId"] = "9" * 50000
        baseline, record = projection_fixture(declared)
        self.assertLess(len(evidence.canonical_json(baseline)), candidate.MAX_CANDIDATE_BYTES)
        document, _, _ = recovery_fixture(baseline, record)
        self.assertFalse(self.validate(document, baseline, record)["scanWindowAllowed"])
        changed = copy.deepcopy(document)
        changed["settlementPolicy"]["historicalReadinessCode"] = "x" * candidate.MAX_CANDIDATE_BYTES
        with self.assertRaisesRegex(candidate.CandidateError, "byte bound"):
            self.validate(changed, baseline, record)
        for value in (float("nan"), float("inf"), object()):
            changed = copy.deepcopy(document)
            changed["settlementPolicy"]["historicalReadinessStatus"] = value
            self.reject(changed, baseline, record)

    def test_ordinary_initialization_state_deadline_and_rollback_receiver_reject_before_boundaries(self):
        document, baseline, record = recovery_fixture()
        machine = provider.state_contract.load_contract()
        state = {"schemaVersion": 2, "generatedAt": PREPARED,
                 "sourceRepository": copy.deepcopy(candidate.SOURCE_IDENTITY),
                 "rollbackBaseline": document, "pendingCandidate": None}
        state_digest = hashlib.sha256(evidence.canonical_json(state)).hexdigest()
        claims = {
            "repository": evidence.WATCHDOG_REPOSITORY,
            "repository_id": provider.WATCHDOG_REPOSITORY_ID,
            "repository_owner_id": provider.WATCHDOG_OWNER_ID,
            "workflow_ref": evidence.BASELINE_WORKFLOW_REF, "environment": evidence.BASELINE_ENVIRONMENT,
            "sha": CONTROL_SHA, "workflow_sha": CONTROL_SHA, "run_id": "700", "run_attempt": "1",
        }
        for ordinary_call, args in (
            (evidence.validate_initial_baseline, (document,)),
            (provider._validate_baseline, (document,)), (provider.validate_state, (state, machine)),
            (provider.WatchdogProvider.initialize_baseline, (object(), document, claims)),
            (check_deadline.decide, (state, provider.parse_canonical_time(PREPARED, "synthetic clock"),
                                    candidate.SOURCE_IDENTITY["repository"], "700", "1", state_digest,
                                    f'"{state_digest}"', baseline["baselineReceipt"]["sha256"])),
        ):
            with self.subTest(operation=ordinary_call.__name__):
                with self.assertRaises((evidence.EvidenceError, provider.ProviderError)):
                    self.blocked(ordinary_call, *args)
        with self.assertRaises(evidence.EvidenceError):
            self.blocked(evidence.initialize_baseline_with_token,
                         raw_baseline=evidence.canonical_json(document), token="unused-synthetic-token")
        callbacks = []

        def not_invoked(*args):
            callbacks.append("forbidden operation")
            self.fail("ordinary receiver reached an operational callback")

        with self.assertRaises(watchdog_rollback_control.RollbackControlError):
            self.blocked(watchdog_rollback_control.execute, document,
                         fetch_state=not_invoked, transition=not_invoked, observe_live=not_invoked,
                         deploy_onedeploy=not_invoked, verify_live=not_invoked, completed_at=PREPARED)
        self.assertEqual(callbacks, [])


if __name__ == "__main__":
    unittest.main()
