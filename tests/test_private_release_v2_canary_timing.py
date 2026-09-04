"""Just-in-time canary authority stays bound to one exact settings mutation."""
import copy
import datetime as dt
from pathlib import Path
import unittest
from unittest import mock

from scripts import private_release_v2_bootstrap as b
from tests.test_private_release_v2_bootstrap import AUTH_ID, NOW, stamp, _TerminalEvidenceFixture
from tests.test_private_release_v2_package_readiness import MemoryJournal, Session
from tests.test_private_release_bridge_bootstrap_canary import FenceService, Tokens, LEASE_ID, ETAG, VERSION, BODY_SHA
from provider import private_release_bridge_azure as azure
from scripts import private_release_mailbox as core

CONFIGURE = "configureBridgeExactVersionedPackageAndCriticalSettings"


class CanaryTimingTests(unittest.TestCase):
    def setUp(self):
        plan, digest = b.load_plan()
        self.fixture = _TerminalEvidenceFixture(plan, digest, {"sha256": "a" * 64, "size": 4096},
            Path(__file__).resolve().parents[2] / ("paperdesk-private-release-v2-bootstrap-" + AUTH_ID))
        self.auth = self.fixture.authorization
        self.fixture.build_operations()

    def test_static_preflight_has_no_premature_concrete_times(self):
        static = b._bootstrap_self_test_static_control(self.auth)
        self.assertNotIn("issuedAt", static)
        self.assertNotIn("expiresAt", static)

    def test_late_issuance_and_outer_expiry_clipping(self):
        late = (
            b.parse_time(self.auth["validity"]["expiresAt"], "expiry")
            - dt.timedelta(seconds=600)
        )
        timing = b._bootstrap_self_test_timing(self.auth, stamp(late))
        self.assertEqual(timing["issuedAt"], stamp(late))
        self.assertEqual(timing["expiresAt"], self.auth["validity"]["expiresAt"])
        early = b._bootstrap_self_test_timing(self.auth, stamp(NOW + dt.timedelta(seconds=10)))
        self.assertEqual(b.parse_time(early["expiresAt"], "expiry") - b.parse_time(early["issuedAt"], "issued"), dt.timedelta(seconds=900))
        for value in (b.parse_time(self.auth["validity"]["notBefore"], "start") - dt.timedelta(seconds=1), b.parse_time(self.auth["validity"]["expiresAt"], "expiry")):
            with self.assertRaises(b.BootstrapError):
                b._bootstrap_self_test_timing(self.auth, stamp(value))

    def transport(self, *, expire_during_precondition=False, put_error=None):
        f = self.fixture
        self.current = NOW + dt.timedelta(seconds=1000)
        def advance():
            if expire_during_precondition:
                self.current = b.parse_time(self.auth["validity"]["expiresAt"], "expiry")
        pre_settings_etag = next(
            item["context"]["preAppSettingsEtag"]
            for item in f.projection["operationAdmissions"]
            if item["operationId"] == CONFIGURE
        )
        session = Session([
            b._RestResponse(200, b.canonical_json_bytes({"properties": {}}), {"ETag": pre_settings_etag}),
            put_error or b._RestResponse(200, b.canonical_json_bytes({"id": f.resources["bridgeSite"]["resourceId"]}), {}),
        ], after_request=advance)
        transport = b.AzureCliBootstrapTransport(authorization=self.auth, plan=f.plan, package=f.package,
            preflight={"projection": f.projection}, session=session, clock=lambda: self.current, sleep=lambda _: None)
        journal = MemoryJournal()
        transport.bind_journal(journal)
        transport._active_operation_id = CONFIGURE
        bridge = f.operations["createBridgeIdentity"]["projection"]
        fence = f.operations["createInitialIdleActivationFence"]["projection"]
        upload = f.operations["uploadVersionedBridgePackage"]["projection"]
        state = {"proofs": {
            "createBridgeIdentity": {"details": {"resourceId": bridge["id"], "clientId": bridge["clientId"], "principalId": bridge["principalId"]}},
            "createInitialIdleActivationFence": {"details": fence},
            "uploadVersionedBridgePackage": {"details": upload},
        }}
        return transport, session, journal, state

    def test_real_settings_put_issues_after_readiness_and_binds_exact_bytes(self):
        transport, session, journal, state = self.transport()
        after_precondition = self.current + dt.timedelta(seconds=11)
        session.after_request = lambda: setattr(self, "current", after_precondition)
        result = transport._mutate(self.fixture.mutations[CONFIGURE], state)
        self.assertEqual([request[0] for request in session.requests], ["POST", "PUT"])
        self.assertEqual(result["bootstrapSelfTestIssuedAt"], stamp(self.current))
        self.assertEqual(
            result["bootstrapSelfTestExpiresAt"],
            stamp(self.current + dt.timedelta(seconds=900)),
        )
        self.assertEqual(result["settingsRequestBodySha256"], b.sha256_bytes(session.requests[-1][2]))
        self.assertEqual(len(journal.records), 2)
        for item in journal.records:
            self.assertEqual(item["requestBodySha256"], result["settingsRequestBodySha256"])

    def test_precondition_expiry_causes_no_put_and_ambiguous_put_not_replayed(self):
        for expire, error, expected in ((True, None, ["POST"]), (False, RuntimeError("transport ambiguous"), ["POST", "PUT"])):
            transport, session, journal, state = self.transport(expire_during_precondition=expire, put_error=error)
            with self.assertRaises(Exception):
                transport._mutate(self.fixture.mutations[CONFIGURE], state)
            self.assertEqual([request[0] for request in session.requests], expected)

    def test_retained_timing_and_journal_tampering_fail(self):
        f = self.fixture
        prior = f.operations
        projection = prior[CONFIGURE]["projection"]
        control = b._bootstrap_self_test_control_from_projections(self.auth, prior)
        self.assertEqual(b.sha256_bytes(b.canonical_json_bytes(control)), projection["bootstrapSelfTestControlSha256"])
        tampered = dict(projection, bootstrapSelfTestExpiresAt=stamp(NOW + dt.timedelta(seconds=901)))
        with self.assertRaises(b.BootstrapError):
            b._bootstrap_self_test_control_from_projections(self.auth, prior, tampered)
        journal = f.mutation_journal()
        def validate(records):
            b._validate_terminal_mutation_coverage(records, plan=f.plan, authorization_id=AUTH_ID,
                source_sha=self.auth["source"]["mergedMain"]["commitSha"], operation_projections=prior, operation_contexts=f.contexts)
        validate(journal)
        for field, value in (("requestBodySha256", "f" * 64), ("recordedAt", stamp(NOW + dt.timedelta(seconds=31)))):
            changed = copy.deepcopy(journal)
            next(item for item in changed if item["operationId"] == CONFIGURE and item["phase"] == "intent")[field] = value
            with self.assertRaises(b.BootstrapError):
                validate(changed)

    def test_expired_control_never_starts_site(self):
        transport, session, journal, state = self.transport()
        state["proofs"][CONFIGURE] = {"details": self.fixture.operations[CONFIGURE]["projection"]}
        transport._active_operation_id = "startBridgeForBoundedCanary"
        with self.assertRaises(b.BootstrapError):
            transport._mutate(self.fixture.mutations["startBridgeForBoundedCanary"], state)
        self.assertEqual(session.requests, [])
        self.assertEqual(journal.records, [])

    def test_terminal_retains_existing_five_second_start_skew_but_not_expired_success(self):
        f = self.fixture
        operation = "startBridgeForBoundedCanary"
        original = f.operations[operation]["projection"]
        for started, ended, accepted in ((NOW + dt.timedelta(minutes=5, seconds=2), NOW + dt.timedelta(minutes=5, seconds=6), True),
                                         (NOW + dt.timedelta(minutes=5, seconds=2), NOW + dt.timedelta(seconds=900), False)):
            body = copy.deepcopy(original)
            body["terminalHistory"].update(startedAt=stamp(started), endedAt=stamp(ended))
            body["terminalHistoryEntriesSha256"] = b.sha256_bytes(b.canonical_json_bytes([body["terminalHistory"]]))
            if accepted:
                f.envelope(operation, body)
            else:
                with self.assertRaises(b.BootstrapError):
                    f.envelope(operation, body)

    def test_expiry_while_starting_never_triggers_and_still_stops(self):
        transport, _session, journal, state = self.transport()
        self.current = NOW + dt.timedelta(seconds=10)
        session = Session([b._RestResponse(202, b"", {}), b._RestResponse(202, b"", {})])
        transport.session = session
        state["proofs"][CONFIGURE] = {"details": self.fixture.operations[CONFIGURE]["projection"]}
        transport._active_operation_id = "startBridgeForBoundedCanary"
        def site_state(**kwargs):
            if kwargs["expected_state"] == "Running":
                self.current = NOW + dt.timedelta(seconds=901)
            return {"state": kwargs["expected_state"]}
        with mock.patch.object(transport, "_wait_for_site_state", side_effect=site_state), mock.patch.object(transport, "_read_webjob_history", return_value={}):
            with self.assertRaises(b.BootstrapError):
                transport._mutate(self.fixture.mutations["startBridgeForBoundedCanary"], state)
        self.assertEqual(len(session.requests), 2)
        self.assertIn("/start?", session.requests[0][1])
        self.assertIn("/stop?", session.requests[1][1])
        self.assertFalse(any("/run?" in request[1] for request in session.requests))

    def test_provider_deadline_blocks_acquire_and_renew_but_allows_finally_release(self):
        base = dt.datetime(2026, 8, 30, tzinfo=dt.timezone.utc)
        for initially_expired in (True, False):
            service = FenceService()
            calls = []
            def http(method, url, headers, body=None):
                calls.append(headers.get("x-ms-lease-action", method))
                return service(method, url, headers, body)
            ticks = iter([base, base, base + dt.timedelta(seconds=3)] + [base + dt.timedelta(seconds=3)] * 20)
            fence = azure.BlobActivationFence(core.FIXED_COORDS["packageAccount"], core.FIXED_COORDS["activationFenceContainer"],
                core.FIXED_COORDS["activationFenceBlob"], Tokens(), http,
                clock=(lambda: base + dt.timedelta(seconds=3)) if initially_expired else lambda: next(ticks))
            with self.assertRaises(core.MailboxError):
                fence.bootstrap_canary(lease_id=LEASE_ID, duration_seconds=60, renewal_count=1,
                    expected_etag=ETAG, expected_version_id=VERSION, expected_body_sha256=BODY_SHA,
                    deadline="2026-08-30T00:00:02.000Z")
            if initially_expired:
                self.assertEqual(calls, [])
            else:
                self.assertIn("acquire", calls)
                self.assertIn("release", calls)
                self.assertNotIn("renew", calls)


if __name__ == "__main__":
    unittest.main()
