"""Offline Stage B provider readback; synthetic records never grant authority."""

import copy
from dataclasses import replace
import hashlib
import json
import unittest
from unittest import mock

from tests.control_lifecycle_offline_boundary import external_access_blocked

with external_access_blocked() as IMPORT_ATTEMPTS:
    from provider import watchdog_state_provider as provider
    from scripts import watchdog_contract
    from scripts import watchdog_users_closed_baseline_candidate as candidate
    from tests import test_watchdog_provider as provider_fixtures
    from tests import test_watchdog_users_closed_baseline_candidate as declarations


AUTHORITY_FIELDS = (
    "healthy", "accepted", "userAdmissionAllowed", "scanWindowAllowed",
    "authorizationAvailable", "providerStateInitializationAllowed", "liveActivationAllowed",
    "providerEvidenceAuthenticated", "protectedCustodyVerified", "recoveryCompletenessProved",
)


class UsersClosedProviderReadbackTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(IMPORT_ATTEMPTS, [])
        self.assertEqual(declarations.IMPORT_ATTEMPTS, [])

    def fixture(self):
        with external_access_blocked() as attempts:
            try:
                baseline, record = declarations.projection_fixture()
                storage = provider_fixtures.MemoryStorage()
                key = (provider.EVIDENCE_CONTAINER, record.path)
                storage.seed(*key, record.raw, {"paperdesk_sha256": record.sha256})
                actual = storage.blobs[key]
                baseline["baselineReceipt"].update(etag=actual.etag, versionId=actual.version_id)
                recovery, _, _ = declarations.recovery_fixture(baseline)
                dispatcher = provider_fixtures.FakeDispatcher()
                service = provider.WatchdogProvider(
                    storage, dispatcher, contract=watchdog_contract.load_contract(),
                    clock=lambda: provider_fixtures.NOW,
                )
                return storage, service, baseline, recovery, key
            finally:
                self.assertEqual(attempts, [], "fixture construction crossed an external boundary")

    def inspect(self, storage, service, baseline, recovery, reads=1):
        forbidden = []
        expected_blob = baseline["baselineReceipt"]["blob"]

        def reject_operation(*unused, **unused_keywords):
            forbidden.append("forbidden operation")
            raise AssertionError("readback reached a write, policy, clock or dispatch callback")

        with external_access_blocked() as attempts, \
                mock.patch.object(storage, "put_create", side_effect=reject_operation), \
                mock.patch.object(storage, "put_replace", side_effect=reject_operation), \
                mock.patch.object(storage, "policy", side_effect=reject_operation), \
                mock.patch.object(storage, "security_posture", side_effect=reject_operation), \
                mock.patch.object(service.dispatcher, "dispatch", side_effect=reject_operation), \
                mock.patch.object(service, "_write_worm", side_effect=reject_operation), \
                mock.patch.object(service, "_replace_state", side_effect=reject_operation), \
                mock.patch.object(service, "initialize_baseline", side_effect=reject_operation), \
                mock.patch.object(service, "clock", side_effect=reject_operation):
            try:
                return service.inspect_users_closed_baseline_readback(baseline, recovery)
            finally:
                self.assertEqual(attempts, [], "readback crossed an external boundary")
                self.assertEqual(forbidden, [], "readback invoked a forbidden owner callback")
                self.assertEqual(storage.events, [
                    ("get", provider.EVIDENCE_CONTAINER, expected_blob)
                ] if reads else [], "readback must perform only its one exact backend read")
                self.assertEqual(service.dispatcher.calls, [])
                self.assertNotIn((provider.STATE_CONTAINER, provider.STATE_BLOB), storage.blobs)

    def test_exact_backend_record_is_read_once_and_remains_degraded_closed(self):
        storage, service, baseline, recovery, _ = self.fixture()
        before = copy.deepcopy(storage.blobs)
        result = self.inspect(storage, service, baseline, recovery)
        self.assertEqual(result["status"], "users-closed-baseline-readback-inspected")
        self.assertEqual(result["receiptScope"], "provider-backend-readback-only")
        self.assertEqual(result["settlementClassification"], "users-closed-degraded")
        self.assertEqual(result["settlementScope"], "declared-historical-policy-only")
        self.assertIs(result["providerRecordReadback"], True)
        for name in AUTHORITY_FIELDS:
            self.assertIs(result[name], False, name)
        self.assertEqual(result["baselineReceiptSha256"], baseline["baselineReceipt"]["sha256"])
        self.assertEqual(result["baselineProjectionSha256"], recovery["baselineProjectionSha256"])
        self.assertEqual(storage.blobs, before)
        self.assertNotIn(baseline["baselineReceipt"]["blob"], json.dumps(result))

    def test_missing_backend_receipt_cannot_be_replaced_by_declarations(self):
        storage, service, baseline, recovery, key = self.fixture()
        del storage.blobs[key]
        with self.assertRaises(provider.ProviderError) as caught:
            self.inspect(storage, service, baseline, recovery)
        self.assertEqual((caught.exception.status, caught.exception.code),
                         (409, "users-closed-baseline-missing"))

    def test_malformed_complete_b1_is_rejected_before_backend_read(self):
        for field, value in (("schemaVersion", True), ("baselineType", "healthy-no-pending"),
                             ("authorizationAvailable", True)):
            with self.subTest(field=field):
                storage, service, baseline, recovery, _ = self.fixture()
                baseline[field] = value
                with self.assertRaises(provider.ProviderError) as caught:
                    self.inspect(storage, service, baseline, recovery, reads=0)
                self.assertEqual((caught.exception.status, caught.exception.code),
                                 (400, "users-closed-projection-invalid"))

    def test_every_receipt_descriptor_coordinate_is_enforced(self):
        for field, replacement, reads in (
            ("blob", candidate.EVIDENCE_PREFIX + "701/1/initial.json", 0),
            ("sha256", "0" * 64, 0), ("size", 1, 0),
            ("etag", '"different-etag"', 1), ("versionId", "different-version", 1),
        ):
            with self.subTest(field=field):
                storage, service, baseline, _, _ = self.fixture()
                baseline["baselineReceipt"][field] = replacement
                recovery, _, _ = declarations.recovery_fixture(baseline)
                with self.assertRaises(provider.ProviderError) as caught:
                    self.inspect(storage, service, baseline, recovery, reads=reads)
                self.assertEqual(caught.exception.code,
                                 "users-closed-baseline-conflict" if reads else "users-closed-projection-invalid")

    def test_different_canonical_backend_body_is_not_reviewed_b1_evidence(self):
        storage, service, baseline, recovery, key = self.fixture()
        storage.blobs[key] = replace(storage.blobs[key], body=provider.canonical_json({"status": "reviewed"}))
        with self.assertRaises(provider.ProviderError) as caught:
            self.inspect(storage, service, baseline, recovery)
        self.assertEqual(caught.exception.code, "users-closed-baseline-conflict")

    def test_noncanonical_backend_bytes_use_actual_owner_refusal(self):
        storage, service, baseline, recovery, key = self.fixture()
        storage.blobs[key] = replace(storage.blobs[key], body=storage.blobs[key].body + b"\n")
        with self.assertRaises(provider.ProviderError) as caught:
            self.inspect(storage, service, baseline, recovery)
        self.assertEqual((caught.exception.status, caught.exception.code), (503, "durable-data-invalid"))

    def test_full_b2_linkage_and_closed_settlement_are_required(self):
        for change in ("baseline-digest", "missing-package", "healthy", "scan-window", "c0-field"):
            with self.subTest(change=change):
                storage, service, baseline, recovery, _ = self.fixture()
                if change == "baseline-digest":
                    recovery["baselineProjectionSha256"] = "0" * 64
                elif change == "missing-package":
                    del recovery["deploymentBundle"]
                elif change == "healthy":
                    recovery["settlementPolicy"]["healthy"] = True
                elif change == "scan-window":
                    recovery["settlementPolicy"]["scanWindowAllowed"] = True
                else:
                    recovery["armGeneration"] = "not-a-stage-b-field"
                with self.assertRaises(provider.ProviderError) as caught:
                    self.inspect(storage, service, baseline, recovery)
                self.assertEqual(caught.exception.code, "users-closed-baseline-conflict")

    def test_nonfinite_or_oversize_recovery_is_refused_before_read(self):
        for value in (float("nan"), float("inf"), "x" * (candidate.MAX_CANDIDATE_BYTES + 1)):
            with self.subTest(value_type=type(value).__name__):
                storage, service, baseline, recovery, _ = self.fixture()
                recovery["untrusted"] = value
                with self.assertRaises(provider.ProviderError) as caught:
                    self.inspect(storage, service, baseline, recovery, reads=0)
                self.assertEqual(caught.exception.code, "users-closed-projection-invalid")

    def test_matching_later_b1_b2_cannot_replace_inputs_during_read(self):
        storage, service, baseline, recovery, key = self.fixture()
        original_get = storage.get_blob

        def changed_read(container, path, maximum):
            body = json.loads(storage.blobs[key].body)
            later = "2026-10-02T11:00:00.000Z"
            baseline["review"]["preparedAt"] = later
            body["review"]["preparedAt"] = later
            body["recordedAt"] = later
            raw = provider.canonical_json(body)
            baseline["baselineReceipt"].update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            later_recovery, _, _ = declarations.recovery_fixture(baseline)
            recovery.clear()
            recovery.update(later_recovery)
            storage.blobs[key] = replace(storage.blobs[key], body=raw)
            return original_get(container, path, maximum)

        with mock.patch.object(storage, "get_blob", side_effect=changed_read):
            with self.assertRaises(provider.ProviderError) as caught:
                self.inspect(storage, service, baseline, recovery)
        self.assertEqual(caught.exception.code, "users-closed-projection-drift")

    def test_caller_locator_mutated_after_validation_cannot_steer_backend_read(self):
        storage, service, baseline, recovery, key = self.fixture()
        validated_blob = key[1]
        outside_blob = "v2/not-the-validated-users-closed-receipt/private.json"
        actual_validator = candidate.validate_users_closed_baseline_projection

        def validate_then_mutate_caller(snapshot):
            self.assertIsNot(snapshot, baseline)
            self.assertIsNot(snapshot["baselineReceipt"], baseline["baselineReceipt"])
            result = actual_validator(snapshot)
            baseline["baselineReceipt"]["blob"] = outside_blob
            return result

        with mock.patch.object(candidate, "validate_users_closed_baseline_projection",
                               side_effect=validate_then_mutate_caller):
            with self.assertRaises(provider.ProviderError) as caught:
                self.inspect(storage, service, baseline, recovery)
        self.assertEqual(caught.exception.code, "users-closed-projection-drift")
        self.assertEqual(storage.events, [("get", provider.EVIDENCE_CONTAINER, validated_blob)])
        self.assertFalse(any(event[2] == outside_blob for event in storage.events))

    def test_malformed_caller_mutation_after_read_is_refused_without_live_dictionary_use(self):
        for change in ("missing-locator", "nonfinite-recovery", "non-json-baseline"):
            with self.subTest(change=change):
                storage, service, baseline, recovery, _ = self.fixture()
                original_get = storage.get_blob

                def read_then_mutate(container, path, maximum):
                    record = original_get(container, path, maximum)
                    if change == "missing-locator":
                        del baseline["baselineReceipt"]
                    elif change == "nonfinite-recovery":
                        recovery["untrusted"] = float("nan")
                    else:
                        baseline["untrusted"] = object()
                    return record

                with mock.patch.object(storage, "get_blob", side_effect=read_then_mutate):
                    with self.assertRaises(provider.ProviderError) as caught:
                        self.inspect(storage, service, baseline, recovery)
                self.assertEqual((caught.exception.status, caught.exception.code),
                                 (409, "users-closed-projection-drift"))

    def test_upstream_authority_flag_cannot_escape_the_readback_owner(self):
        storage, service, baseline, recovery, key = self.fixture()
        actual = storage.blobs[key]
        record = provider.WormRecord(
            document=json.loads(actual.body), raw=actual.body,
            sha256=hashlib.sha256(actual.body).hexdigest(), path=key[1],
            etag=actual.etag, version_id=actual.version_id, created=False,
        )
        with external_access_blocked() as attempts:
            inspected = candidate.validate_users_closed_recovery_projection(recovery, baseline, record)
            self.assertEqual(attempts, [])
        inspected["authorizationAvailable"] = True
        with mock.patch.object(candidate, "validate_users_closed_recovery_projection", return_value=inspected):
            with self.assertRaises(provider.ProviderError) as caught:
                self.inspect(storage, service, baseline, recovery)
        self.assertEqual((caught.exception.status, caught.exception.code),
                         (503, "users-closed-inspection-authority"))


if __name__ == "__main__":
    unittest.main()
