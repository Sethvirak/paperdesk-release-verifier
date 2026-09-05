"""Controller GET readiness against the real transport and source validator."""

import datetime as dt
import json
from pathlib import Path
import unittest

from scripts import private_release_v2_bootstrap as bootstrap
from tests.test_private_release_v2_bootstrap import AUTH_ID, NOW, _TerminalEvidenceFixture
from tests.test_private_release_v2_package_readiness import MemoryJournal


EMPTY = b"<EnumerationResults><Prefix/><Marker/><MaxResults>5000</MaxResults><Delimiter/><Blobs/><NextMarker/></EnumerationResults>"
SECRET = "Bearer private-token 203.0.113.19 raw-message-secret"
REQUEST_ID = "11111111-2222-f333-4444-555555555555"
SERVER_DATE = "Wed, 02 Sep 2026 04:29:31 GMT"


def denied(code="AuthorizationPermissionMismatch", status=403, headers=None):
    return bootstrap._RestResponse(status,
        f"<Error><Code>{code}</Code><Message>{SECRET}</Message></Error>".encode(),
        {"Content-Type": "application/xml", **(headers or {})})


def empty():
    return bootstrap._RestResponse(200, EMPTY, {"Content-Type": "application/xml"})


class ControllerSession:
    def __init__(self, callback):
        self.callback = callback
        self.requests = []

    def request(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs))
        return self.callback(len(self.requests))


class ControllerReadinessTests(unittest.TestCase):
    def make(self, callback):
        plan, digest = bootstrap.load_plan()
        fixture = _TerminalEvidenceFixture(plan, digest, {"sha256": "a" * 64, "size": 4096},
            Path(__file__).resolve().parents[2] / ("paperdesk-private-release-v2-bootstrap-" + AUTH_ID))
        resource = fixture.resources["controllerLockContainer"]
        posture = fixture.envelope("createPrivateControllerLockContainer", {
            "id": resource["resourceId"], "name": resource["name"],
            "type": "Microsoft.Storage/storageAccounts/blobServices/containers", "publicAccess": "None"})
        self.current = NOW
        self.sleeps = []
        def sleep(seconds):
            self.sleeps.append(seconds)
            self.current += dt.timedelta(seconds=seconds)
        session = ControllerSession(callback)
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=fixture.authorization, plan=plan, package=fixture.package,
            preflight={"projection": fixture.projection}, session=session,
            clock=lambda: self.current, sleep=sleep)
        transport._validated_source_projections["createPrivateControllerLockContainer"] = posture
        journal = MemoryJournal()
        transport.bind_journal(journal)
        ids = transport.admissions["proveControllerLockContainerEmpty"]["desiredProbeIds"]
        return transport, session, journal, ids

    def assert_sanitized(self, error):
        self.assertIsInstance(error, bootstrap.ControllerReadinessError)
        for label in ("stage=", "elapsedSeconds=", "attempts=", "status=", "errorCode=", "stopReason="):
            self.assertIn(label, str(error))
        for text in (str(error), json.dumps(error.diagnostic)):
            for secret in (SECRET, "private-token", "203.0.113.19", "raw-message-secret", "<Error>"):
                self.assertNotIn(secret, text)
        records = error.diagnostic["attemptRecords"]
        self.assertEqual(len(records), error.diagnostic["attempts"])
        self.assertEqual(
            [item["attempt"] for item in records],
            list(range(1, error.diagnostic["attempts"] + 1)),
        )
        client_ids = [item["clientRequestId"] for item in records]
        self.assertTrue(all(bootstrap.GUID.fullmatch(value) for value in client_ids))
        self.assertEqual(len(client_ids), len(set(client_ids)))
        for item in records:
            self.assertEqual(set(item), {
                "attempt", "startedAt", "completedAt", "durationMs",
                "clientRequestId", "status", "errorCode", "requestId",
                "serverDate", "outcome",
            })

    def assert_no_credential_or_role_snapshot(self, error):
        self.assertIsNone(error.diagnostic["credential"])
        self.assertIsNone(error.diagnostic["roleReadback"])

    def test_recognized_403_converges_after_120_seconds_to_validated_empty_200(self):
        for code in ("AuthorizationFailure", "AuthorizationPermissionMismatch"):
            with self.subTest(code=code):
                transport, session, journal, ids = self.make(
                    lambda _: denied(code) if (self.current - NOW).total_seconds() < 135 else empty())
                proof = transport._prove_controller_lock_container_empty(ids)[0]
                elapsed = (self.current - NOW).total_seconds()
                self.assertGreater(elapsed, 120)
                self.assertLess(elapsed, 600)
                self.assertEqual(self.sleeps[:5], [1, 2, 4, 8, 15])
                self.assertTrue(all(0 < delay <= 15 for delay in self.sleeps))
                self.assertEqual(proof["attempts"], len(session.requests))
                self.assertEqual(proof["sourceProjection"]["family"], "controller-lock-initial-empty-proof")
                self.assertTrue(all(method == "GET" and url == transport.probes[ids[0]]["url"]
                                    for method, url, _ in session.requests))
                request_ids = [item[2]["headers"]["x-ms-client-request-id"]
                               for item in session.requests]
                self.assertEqual(len(request_ids), len(set(request_ids)))
                self.assertEqual(journal.records, [])

    def test_expiry_and_600_second_readiness_window_clip_waits_without_writes(self):
        for deadline in (37, 600):
            with self.subTest(deadline=deadline):
                transport, session, journal, ids = self.make(lambda _: denied())
                if deadline == 37:
                    transport.authorization["validity"]["expiresAt"] = (NOW + dt.timedelta(seconds=37)).isoformat().replace("+00:00", "Z")
                with self.assertRaises(bootstrap.BootstrapError) as error:
                    transport._prove_controller_lock_container_empty(ids)
                self.assert_sanitized(error.exception)
                if deadline < bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS:
                    self.assertEqual(error.exception.diagnostic["stopReason"], "expired-before-get")
                    self.assertEqual(error.exception.diagnostic["attempts"], 0)
                    self.assertEqual(self.current, NOW)
                    self.assertEqual(session.requests, [])
                    self.assertEqual(self.sleeps, [])
                    self.assertEqual(journal.records, [])
                    continue
                self.assertEqual(error.exception.diagnostic["stopReason"], "readiness-timeout")
                self.assertIsNone(error.exception.diagnostic["requestId"])
                self.assertIsNone(error.exception.diagnostic["serverDate"])
                self.assert_no_credential_or_role_snapshot(error.exception)
                expected_elapsed = deadline
                self.assertEqual((self.current - NOW).total_seconds(), expected_elapsed)
                self.assertLessEqual(len(session.requests), 64)
                self.assertTrue(all(0 < delay <= 15 for delay in self.sleeps))
                self.assertEqual(
                    error.exception.diagnostic["attemptRecords"][-1]["startedAt"],
                    (NOW + dt.timedelta(seconds=deadline))
                    .isoformat(timespec="milliseconds")
                    .replace("+00:00", "Z"),
                )
                self.assertTrue(all(item[0] == "GET" for item in session.requests))
                self.assertEqual(journal.records, [])

    def test_deadline_adjacent_final_get_can_validate_empty_container(self):
        final_at = NOW + dt.timedelta(
            seconds=bootstrap.MAX_STORAGE_DATA_PLANE_READINESS_SECONDS
        )
        transport, session, journal, ids = self.make(
            lambda _: empty() if self.current == final_at else denied()
        )
        proof = transport._prove_controller_lock_container_empty(ids)[0]
        self.assertEqual(self.current, final_at)
        self.assertEqual(proof["attempts"], len(session.requests))
        request_ids = [item[2]["headers"]["x-ms-client-request-id"]
                       for item in session.requests]
        self.assertEqual(len(request_ids), len(set(request_ids)))
        self.assertTrue(all(bootstrap.GUID.fullmatch(value) for value in request_ids))
        self.assertTrue(all(item[2]["deadline"] == NOW + dt.timedelta(
            seconds=(
                bootstrap.MAX_STORAGE_DATA_PLANE_READINESS_SECONDS
                + bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS
            )
        ) for item in session.requests))
        self.assertEqual(journal.records, [])

    def test_invalid_response_is_terminal_and_diagnostics_do_not_leak(self):
        variants = [denied("AuthenticationFailed"), denied("raw-message-secret"), denied(status=401),
            bootstrap._RestResponse(403, denied().body, {"Content-Type": "application/xml", "x-ms-error-code": "AuthorizationFailure"}),
            bootstrap._RestResponse(403, ("malformed " + SECRET).encode(), {"Content-Type": "application/xml"}),
            bootstrap._RestResponse(403, b"<Error><Code>AuthorizationFailure</Code><Code>AuthorizationPermissionMismatch</Code></Error>", {"Content-Type": "application/xml"}),
            bootstrap._RestResponse(200, EMPTY.replace(b"<Blobs/>", b"<Blobs><Blob><Name>private-token</Name></Blob></Blobs>"), {"Content-Type": "application/xml"}),
            bootstrap._RestResponse(200, SECRET.encode(), {"Content-Type": "application/xml"}),
        ]
        for index, value in enumerate(variants):
            with self.subTest(index=index):
                transport, session, journal, ids = self.make(lambda _: value)
                with self.assertRaises(bootstrap.BootstrapError) as error:
                    transport._prove_controller_lock_container_empty(ids)
                self.assert_sanitized(error.exception)
                self.assertEqual(len(session.requests), 1)
                self.assertEqual(self.sleeps, [])
                self.assertEqual(journal.records, [])

    def test_wrong_target_rejected_before_any_request(self):
        transport, session, journal, ids = self.make(lambda _: empty())
        transport.probes[ids[0]]["url"] = "https://example.invalid/private-token"
        with self.assertRaises(bootstrap.BootstrapError) as error:
            transport._prove_controller_lock_container_empty(ids)
        self.assert_sanitized(error.exception)
        self.assertEqual(error.exception.diagnostic["stopReason"], "invalid-target")
        self.assert_no_credential_or_role_snapshot(error.exception)
        self.assertEqual(session.requests, [])
        self.assertEqual(journal.records, [])

    def test_slow_response_at_readiness_envelope_deadline_cannot_be_accepted(self):
        def slow(_):
            self.current = NOW + dt.timedelta(
                seconds=(
                    bootstrap.MAX_STORAGE_DATA_PLANE_READINESS_SECONDS
                    + bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS
                )
            )
            return empty()
        transport, session, journal, ids = self.make(slow)
        with self.assertRaises(bootstrap.BootstrapError) as error:
            transport._prove_controller_lock_container_empty(ids)
        self.assert_sanitized(error.exception)
        self.assertEqual(error.exception.diagnostic["stopReason"], "expired-during-get")
        self.assertEqual(len(session.requests), 1)
        self.assertEqual(journal.records, [])

    def test_frozen_clock_still_stops_at_64_attempts(self):
        transport, session, journal, ids = self.make(lambda _: denied())
        transport.sleep = lambda seconds: self.sleeps.append(seconds)
        with self.assertRaises(bootstrap.BootstrapError) as error:
            transport._prove_controller_lock_container_empty(ids)
        self.assert_sanitized(error.exception)
        self.assertEqual(error.exception.diagnostic["stopReason"], "attempt-limit")
        self.assertEqual(len(session.requests), 64)
        self.assertEqual(len(self.sleeps), 63)
        self.assertTrue(all(0 < delay <= 15 for delay in self.sleeps))
        self.assertEqual(journal.records, [])

    def test_ambiguous_get_fails_once_without_replaying_or_exposing_exception(self):
        def broken(_):
            raise RuntimeError(SECRET)
        transport, session, journal, ids = self.make(broken)
        with self.assertRaises(bootstrap.BootstrapError) as error:
            transport._prove_controller_lock_container_empty(ids)
        self.assert_sanitized(error.exception)
        self.assertEqual(error.exception.diagnostic["stopReason"], "transport-error")
        self.assertIsNone(error.exception.diagnostic["status"])
        self.assertIsNone(error.exception.diagnostic["requestId"])
        self.assertIsNone(error.exception.diagnostic["serverDate"])
        self.assertEqual(error.exception.diagnostic["attemptRecords"][-1]["outcome"],
                         "transport-error")
        self.assertIsNone(error.exception.diagnostic["attemptRecords"][-1]["status"])
        self.assert_no_credential_or_role_snapshot(error.exception)
        self.assertEqual(len(session.requests), 1)
        self.assertEqual(self.sleeps, [])
        self.assertEqual(journal.records, [])

    def test_zero_attempt_outside_authorization_window_has_no_response_metadata(self):
        for offset in (-1, bootstrap.MAX_AUTHORIZATION_SECONDS):
            with self.subTest(offset=offset):
                transport, session, journal, ids = self.make(lambda _: empty())
                self.current = NOW + dt.timedelta(seconds=offset)
                transport.authorization["validity"]["notBefore"] = NOW.isoformat().replace("+00:00", "Z")
                transport.authorization["validity"]["expiresAt"] = (
                    NOW
                    + dt.timedelta(seconds=bootstrap.MAX_AUTHORIZATION_SECONDS)
                ).isoformat().replace("+00:00", "Z")
                with self.assertRaises(bootstrap.ControllerReadinessError) as error:
                    transport._prove_controller_lock_container_empty(ids)
                self.assert_sanitized(error.exception)
                self.assertEqual(error.exception.diagnostic["stopReason"], "expired-before-get")
                self.assertEqual(error.exception.diagnostic["attempts"], 0)
                self.assertIsNone(error.exception.diagnostic["status"])
                self.assertIsNone(error.exception.diagnostic["requestId"])
                self.assertIsNone(error.exception.diagnostic["serverDate"])
                self.assert_no_credential_or_role_snapshot(error.exception)
                self.assertEqual(session.requests, [])
                self.assertEqual(self.sleeps, [])
                self.assertEqual(journal.records, [])

    def test_invalid_authorization_window_stops_without_gets_or_writes(self):
        for expiry in ("not-a-timestamp", NOW.isoformat().replace("+00:00", "Z")):
            with self.subTest(expiry=expiry):
                transport, session, journal, ids = self.make(lambda _: empty())
                transport.authorization["validity"]["notBefore"] = NOW.isoformat().replace("+00:00", "Z")
                transport.authorization["validity"]["expiresAt"] = expiry
                with self.assertRaises(bootstrap.ControllerReadinessError) as error:
                    transport._prove_controller_lock_container_empty(ids)
                self.assert_sanitized(error.exception)
                self.assertEqual(error.exception.diagnostic["stopReason"], "invalid-authorization-window")
                self.assertEqual(session.requests, [])
                self.assertEqual(self.sleeps, [])
                self.assertEqual(journal.records, [])

    def test_response_reason_classification_does_not_change_retry_admission(self):
        variants = [
            (denied("AuthenticationFailed"), "unsupported-denial"),
            (denied(status=401), "unsupported-status"),
            (denied(headers={"x-ms-error-code": "AuthorizationFailure"}), "error-code-mismatch"),
            (bootstrap._RestResponse(403, ("malformed " + SECRET).encode(), {"Content-Type": "application/xml"}), "malformed-xml"),
            (bootstrap._RestResponse(403, b"<!DOCTYPE Error><Error/>", {"Content-Type": "application/xml"}), "unsafe-xml"),
            (bootstrap._RestResponse(403, b"<Error><Code>AuthorizationFailure</Code><Code>AuthorizationPermissionMismatch</Code></Error>", {"Content-Type": "application/xml"}), "invalid-error-shape"),
            (bootstrap._RestResponse(200, EMPTY.replace(b"<Blobs/>", b"<Blobs><Blob><Name>private-token</Name></Blob></Blobs>"), {"Content-Type": "application/xml"}), "invalid-empty-proof"),
        ]
        for response, reason in variants:
            with self.subTest(reason=reason):
                transport, session, journal, ids = self.make(lambda _: response)
                with self.assertRaises(bootstrap.ControllerReadinessError) as error:
                    transport._prove_controller_lock_container_empty(ids)
                self.assert_sanitized(error.exception)
                self.assertEqual(error.exception.diagnostic["stopReason"], reason)
                self.assertEqual(len(session.requests), 1)
                self.assertEqual(self.sleeps, [])
                self.assertEqual(journal.records, [])

    def test_missing_private_posture_cannot_be_replaced_by_empty_response(self):
        transport, session, journal, ids = self.make(lambda _: empty())
        transport._validated_source_projections.pop("createPrivateControllerLockContainer")
        with self.assertRaises(bootstrap.ControllerReadinessError) as error:
            transport._prove_controller_lock_container_empty(ids)
        self.assert_sanitized(error.exception)
        self.assertEqual(error.exception.diagnostic["stopReason"], "missing-private-posture")
        self.assertEqual(error.exception.diagnostic["status"], 200)
        self.assertEqual(len(session.requests), 1)
        self.assertEqual(self.sleeps, [])
        self.assertEqual(journal.records, [])

    def test_canonical_request_id_and_date_survive_terminal_denial(self):
        transport, session, journal, ids = self.make(lambda _: denied(status=401, headers={
            "X-Ms-Request-Id": REQUEST_ID, "dAtE": SERVER_DATE}))
        with self.assertRaises(bootstrap.ControllerReadinessError) as error:
            transport._prove_controller_lock_container_empty(ids)
        self.assert_sanitized(error.exception)
        self.assertEqual(error.exception.diagnostic["requestId"], REQUEST_ID)
        self.assertEqual(error.exception.diagnostic["serverDate"], SERVER_DATE)
        self.assertEqual(error.exception.diagnostic["stopReason"], "unsupported-status")
        self.assertEqual(len(session.requests), 1)
        self.assertEqual(journal.records, [])

    def test_hostile_headers_are_null_in_diagnostics_and_never_replayed(self):
        variants = [
            {"x-ms-request-id": SECRET, "Date": SECRET},
            {"x-ms-request-id": REQUEST_ID + "\r\n" + SECRET, "Date": SERVER_DATE + "\r\n" + SECRET},
            {"x-ms-request-id": "https://example.invalid/private-token", "Date": "Thu, 02 Sep 2026 04:29:31 GMT"},
        ]
        for headers in variants:
            with self.subTest(headers=headers):
                transport, session, journal, ids = self.make(lambda _: denied(status=401, headers=headers))
                with self.assertRaises(bootstrap.ControllerReadinessError) as error:
                    transport._prove_controller_lock_container_empty(ids)
                self.assert_sanitized(error.exception)
                self.assertIsNone(error.exception.diagnostic["requestId"])
                self.assertIsNone(error.exception.diagnostic["serverDate"])
                self.assertEqual(len(session.requests), 1)
                self.assertEqual(self.sleeps, [])
                self.assertEqual(journal.records, [])

    def test_later_headerless_response_clears_previous_response_headers(self):
        def callback(attempt):
            return (denied(headers={"x-ms-request-id": REQUEST_ID, "Date": SERVER_DATE})
                    if attempt == 1 else denied(status=401))
        transport, session, journal, ids = self.make(callback)
        with self.assertRaises(bootstrap.ControllerReadinessError) as error:
            transport._prove_controller_lock_container_empty(ids)
        self.assert_sanitized(error.exception)
        self.assertEqual(error.exception.diagnostic["status"], 401)
        self.assertIsNone(error.exception.diagnostic["requestId"])
        self.assertIsNone(error.exception.diagnostic["serverDate"])
        self.assertEqual(len(session.requests), 2)
        self.assertEqual(self.sleeps, [1])
        self.assertEqual(journal.records, [])

    def test_later_transport_failure_retains_last_response_headers_not_exception(self):
        credential = {
            "source": "azure-cli-request",
            "tokenIssuedAtUnix": int(NOW.timestamp()) - 60,
            "tokenExpiresAtUnix": int(NOW.timestamp()) + 3600,
            "tokenObservedAtUnix": int(NOW.timestamp()),
            "accountBindingVerified": True,
        }
        expected_credential = dict(credential)
        credential_observations = []

        def diagnostic():
            credential_observations.append(len(session.requests))
            return credential

        def callback(attempt):
            if attempt == 1:
                return denied(headers={"x-ms-request-id": REQUEST_ID, "Date": SERVER_DATE})
            # Transport may have attempted to use a different credential before
            # failing. It must not be paired with the earlier safe HTTP response.
            credential["source"] = "process-cache"
            credential["tokenObservedAtUnix"] += 1
            raise RuntimeError(SECRET)
        transport, session, journal, ids = self.make(callback)
        session.storage_credential_diagnostic = diagnostic
        with self.assertRaises(bootstrap.ControllerReadinessError) as error:
            transport._prove_controller_lock_container_empty(ids)
        self.assert_sanitized(error.exception)
        self.assertEqual(error.exception.diagnostic["stopReason"], "transport-error")
        self.assertEqual(error.exception.diagnostic["status"], 403)
        self.assertEqual(error.exception.diagnostic["errorCode"], "AuthorizationPermissionMismatch")
        self.assertEqual(error.exception.diagnostic["requestId"], REQUEST_ID)
        self.assertEqual(error.exception.diagnostic["serverDate"], SERVER_DATE)
        self.assertEqual(error.exception.diagnostic["credential"], expected_credential)
        self.assertEqual(credential_observations, [1])
        self.assertEqual(len(session.requests), 2)
        self.assertEqual(self.sleeps, [1])
        self.assertEqual(journal.records, [])

    def test_credential_metadata_is_observed_only_after_an_actual_response(self):
        observations = []

        def broken(_):
            raise RuntimeError(SECRET)

        def diagnostic():
            observations.append(True)
            raise AssertionError("must not inspect credentials after ambiguous transport")

        transport, session, journal, ids = self.make(broken)
        session.storage_credential_diagnostic = diagnostic
        with self.assertRaises(bootstrap.ControllerReadinessError) as error:
            transport._prove_controller_lock_container_empty(ids)
        self.assert_sanitized(error.exception)
        self.assertEqual(error.exception.diagnostic["stopReason"], "transport-error")
        self.assertIsNone(error.exception.diagnostic["credential"])
        self.assertEqual(observations, [])
        self.assertEqual(len(session.requests), 1)
        self.assertEqual(journal.records, [])

    def test_latest_response_replaces_prior_credential_even_when_metadata_is_missing(self):
        credential = {
            "source": "azure-cli-request",
            "tokenIssuedAtUnix": int(NOW.timestamp()) - 60,
            "tokenExpiresAtUnix": int(NOW.timestamp()) + 3600,
            "tokenObservedAtUnix": int(NOW.timestamp()),
            "accountBindingVerified": True,
        }
        observations = []

        def diagnostic():
            observations.append(len(session.requests))
            return credential if len(session.requests) == 1 else None

        def callback(attempt):
            return (denied(headers={"x-ms-request-id": REQUEST_ID, "Date": SERVER_DATE})
                    if attempt == 1 else denied(status=401))

        transport, session, journal, ids = self.make(callback)
        session.storage_credential_diagnostic = diagnostic
        with self.assertRaises(bootstrap.ControllerReadinessError) as error:
            transport._prove_controller_lock_container_empty(ids)
        self.assert_sanitized(error.exception)
        self.assertEqual(error.exception.diagnostic["status"], 401)
        self.assertIsNone(error.exception.diagnostic["requestId"])
        self.assertIsNone(error.exception.diagnostic["serverDate"])
        self.assertIsNone(error.exception.diagnostic["credential"])
        self.assertEqual(observations, [1, 2])
        self.assertEqual(len(session.requests), 2)
        self.assertEqual(journal.records, [])

    def test_unavailable_diagnostic_observer_does_not_change_readiness_admission(self):
        def broken_diagnostic():
            raise RuntimeError(SECRET)

        transport, session, journal, ids = self.make(lambda _: denied(status=401))
        session.storage_credential_diagnostic = broken_diagnostic
        with self.assertRaises(bootstrap.ControllerReadinessError) as error:
            transport._prove_controller_lock_container_empty(ids)
        self.assert_sanitized(error.exception)
        self.assertEqual(error.exception.diagnostic["stopReason"], "unsupported-status")
        self.assertIsNone(error.exception.diagnostic["credential"])
        self.assertEqual(len(session.requests), 1)
        self.assertEqual(journal.records, [])

    def test_role_hashes_come_from_validated_readback_not_expected_plan(self):
        definition = {"id": "fixture-role", "properties": {"roleName": "private-token"}}
        assignment = {"id": "fixture-assignment", "properties": {"principalId": "fixture-principal"}}
        transport, session, journal, ids = self.make(lambda _: denied(status=401))
        transport._validated_source_projections["addOwnedOperatorControllerCanaryRole"] = {
            "family": "temporary-role-projection",
            "projection": {"definition": definition, "assignment": assignment},
        }
        with self.assertRaises(bootstrap.ControllerReadinessError) as error:
            transport._prove_controller_lock_container_empty(ids)
        self.assert_sanitized(error.exception)
        self.assertEqual(error.exception.diagnostic["roleReadback"], {
            "definitionSha256": bootstrap.sha256_bytes(bootstrap.canonical_json_bytes(definition)),
            "assignmentSha256": bootstrap.sha256_bytes(bootstrap.canonical_json_bytes(assignment)),
        })
        self.assertNotIn("fixture-principal", str(error.exception))
        self.assertEqual(len(session.requests), 1)
        self.assertEqual(journal.records, [])


if __name__ == "__main__":
    unittest.main()
