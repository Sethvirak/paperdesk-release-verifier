"""Controller GET readiness against the real transport and source validator."""

import datetime as dt
from pathlib import Path
import unittest

from scripts import private_release_v2_bootstrap as bootstrap
from tests.test_private_release_v2_bootstrap import AUTH_ID, NOW, _TerminalEvidenceFixture
from tests.test_private_release_v2_package_readiness import MemoryJournal


EMPTY = b"<EnumerationResults><Prefix/><Marker/><MaxResults>5000</MaxResults><Delimiter/><Blobs/><NextMarker/></EnumerationResults>"
SECRET = "Bearer private-token 203.0.113.19 raw-message-secret"


def denied(code="AuthorizationPermissionMismatch", status=403):
    return bootstrap._RestResponse(status,
        f"<Error><Code>{code}</Code><Message>{SECRET}</Message></Error>".encode(),
        {"Content-Type": "application/xml"})


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
        text = str(error)
        for label in ("stage=", "elapsedSeconds=", "attempts=", "status=", "errorCode="):
            self.assertIn(label, text)
        for secret in (SECRET, "private-token", "203.0.113.19", "raw-message-secret", "<Error>"):
            self.assertNotIn(secret, text)

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
                self.assertEqual(journal.records, [])

    def test_expiry_and_600_second_cap_clip_waits_without_writes(self):
        for deadline in (37, 600):
            with self.subTest(deadline=deadline):
                transport, session, journal, ids = self.make(lambda _: denied())
                if deadline == 37:
                    transport.authorization["validity"]["expiresAt"] = (NOW + dt.timedelta(seconds=37)).isoformat().replace("+00:00", "Z")
                with self.assertRaises(bootstrap.BootstrapError) as error:
                    transport._prove_controller_lock_container_empty(ids)
                self.assert_sanitized(error.exception)
                self.assertEqual((self.current - NOW).total_seconds(), deadline)
                self.assertLessEqual(len(session.requests), 64)
                self.assertTrue(all(0 < delay <= 15 for delay in self.sleeps))
                self.assertTrue(all(item[0] == "GET" for item in session.requests))
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
        self.assertEqual(session.requests, [])
        self.assertEqual(journal.records, [])

    def test_slow_response_at_expiry_cannot_be_accepted(self):
        def slow(_):
            self.current = NOW + dt.timedelta(seconds=600)
            return empty()
        transport, session, journal, ids = self.make(slow)
        with self.assertRaises(bootstrap.BootstrapError) as error:
            transport._prove_controller_lock_container_empty(ids)
        self.assert_sanitized(error.exception)
        self.assertEqual(len(session.requests), 1)
        self.assertEqual(journal.records, [])

    def test_frozen_clock_still_stops_at_64_attempts(self):
        transport, session, journal, ids = self.make(lambda _: denied())
        transport.sleep = lambda seconds: self.sleeps.append(seconds)
        with self.assertRaises(bootstrap.BootstrapError) as error:
            transport._prove_controller_lock_container_empty(ids)
        self.assert_sanitized(error.exception)
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
        self.assertEqual(len(session.requests), 1)
        self.assertEqual(self.sleeps, [])
        self.assertEqual(journal.records, [])


if __name__ == "__main__":
    unittest.main()
