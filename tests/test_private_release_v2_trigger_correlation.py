"""Adversarial WebJob trigger-correlation and final-census regressions."""

import base64
import copy
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import private_release_v2_bootstrap as bootstrap
from tests.test_private_release_v2_bootstrap import (
    build_valid_terminal_source_evidence_fixture,
)
from tests.test_private_release_v2_package_readiness import MemoryJournal, Session


NOW = dt.datetime(2026, 9, 14, 9, 0, tzinfo=dt.timezone.utc)
SITE_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/"
    "resourceGroups/paperdesk-release/providers/Microsoft.Web/"
    "sites/paperdesk-release-registry-bridge-v2-9c4e0d0d"
)
SITE_NAME = "paperdesk-release-registry-bridge-v2-9c4e0d0d"
PROBE_SITE_ID = SITE_ID.replace(
    "00000000-0000-0000-0000-000000000000", bootstrap.SUBSCRIPTION
)
JOB_NAME = "paperdesk-accepted-release-registry"
AUTHORIZATION_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
REQUEST_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
USER_AGENT = f"PaperDeskV2Bootstrap/{AUTHORIZATION_ID}.{REQUEST_ID}"
EXPECTED_TRIGGER_SHA256 = bootstrap.sha256_bytes(
    ("External - " + USER_AGENT).encode("utf-8")
)


def stamp(value):
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def history_entry(run_id, *, trigger_sha256=EXPECTED_TRIGGER_SHA256, status="Success"):
    started = NOW + dt.timedelta(seconds=2)
    terminal = status in {"Success", "Failed", "Aborted"}
    return {
        "historyId": f"{SITE_ID}/triggeredwebjobs/{JOB_NAME}/history/{run_id}",
        "webJobsRunId": run_id,
        "triggerSha256": trigger_sha256,
        "status": status,
        "startedAt": stamp(started),
        "endedAt": stamp(started + dt.timedelta(seconds=1)) if terminal else None,
        "outputUrlMetadata": (
            {
                "scheme": "https",
                "host": SITE_NAME + ".scm.azurewebsites.net",
                "pathSha256": "c" * 64,
                "queryPresent": False,
            }
            if terminal
            else None
        ),
    }


def history_observation(entries, *, observed_at=None, http_status=200):
    projected = sorted(copy.deepcopy(entries), key=lambda item: item["historyId"])
    return {
        "observedAt": stamp(observed_at or (NOW + dt.timedelta(seconds=5))),
        "entries": projected,
        "entriesSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(projected)
        ),
        "responseSha256": "d" * 64,
        "httpStatus": http_status,
        "boundaryState": "history-present",
    }


def bare_transport(*, clock=lambda: NOW, sleep=lambda _seconds: None):
    transport = object.__new__(bootstrap.AzureCliBootstrapTransport)
    transport.clock = clock
    transport.sleep = sleep
    transport.authorization = {
        "validity": {"expiresAt": stamp(NOW + dt.timedelta(minutes=10))}
    }
    return transport


class TriggerCorrelationMetadataTests(unittest.TestCase):
    def metadata(self, response):
        return bootstrap.AzureCliBootstrapTransport._webjob_trigger_correlation_metadata(
            response,
            site_name=SITE_NAME,
            job_name=JOB_NAME,
            user_agent=USER_AGENT,
            observed_at=stamp(NOW),
        )

    def test_exact_arm_200_empty_body_without_location_uses_history_trigger(self):
        result = self.metadata(bootstrap._RestResponse(200, b"", {}))

        self.assertEqual(
            result,
            {
                "mode": "arm-200-empty-body-history-trigger",
                "userAgent": USER_AGENT,
                "expectedHistoryTriggerSha256": EXPECTED_TRIGGER_SHA256,
                "responseBodySha256": bootstrap.sha256_bytes(b""),
                "responseObservedAt": stamp(NOW),
                "location": None,
            },
        )

    def test_valid_location_requires_both_location_and_history_trigger(self):
        location = (
            f"https://{SITE_NAME}.scm.azurewebsites.net/api/triggeredwebjobs/"
            f"{JOB_NAME}/history/run-123"
        )
        result = self.metadata(
            bootstrap._RestResponse(200, b"", {"Location": location})
        )

        self.assertEqual(result["mode"], "location-header-and-history-trigger")
        self.assertEqual(result["userAgent"], USER_AGENT)
        self.assertEqual(
            result["expectedHistoryTriggerSha256"], EXPECTED_TRIGGER_SHA256
        )
        self.assertEqual(result["location"]["runId"], "run-123")

    def test_only_exact_200_empty_body_can_use_missing_location_fallback(self):
        for response in (
            bootstrap._RestResponse(201, b"", {}),
            bootstrap._RestResponse(202, b"", {}),
            bootstrap._RestResponse(200, b"{}", {}),
            bootstrap._RestResponse(200, b"\n", {}),
        ):
            with self.subTest(status=response.status, body=response.body):
                with self.assertRaises(bootstrap.BootstrapError):
                    self.metadata(response)

    def test_present_empty_malformed_or_duplicate_location_never_falls_back(self):
        valid = (
            f"https://{SITE_NAME}.scm.azurewebsites.net/api/triggeredwebjobs/"
            f"{JOB_NAME}/history/run-123"
        )
        cases = (
            bootstrap._RestResponse(200, b"", {"Location": ""}),
            bootstrap._RestResponse(200, b"", {"Location": " "}),
            bootstrap._RestResponse(
                200,
                b"",
                {"Location": "https://evil.example/history/run-123"},
            ),
            bootstrap._RestResponse(
                200,
                b"",
                {},
                header_items=(("Location", valid), ("location", valid)),
            ),
        )
        for response in cases:
            with self.subTest(headers=response.header_items or response.headers):
                with self.assertRaises(bootstrap.BootstrapError):
                    self.metadata(response)

    def test_user_agent_shape_is_strict(self):
        for value in (
            "curl/8.0",
            f"PaperDeskV2Bootstrap/{AUTHORIZATION_ID}",
            f"PaperDeskV2Bootstrap/{AUTHORIZATION_ID}.not-a-uuid",
            f"PaperDeskV2Bootstrap/{AUTHORIZATION_ID}.{REQUEST_ID}\r\nforged",
            f"PaperDeskV2Bootstrap/{AUTHORIZATION_ID}/{REQUEST_ID}",
        ):
            with self.subTest(user_agent=value):
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.AzureCliBootstrapTransport._webjob_trigger_correlation_metadata(
                        bootstrap._RestResponse(200, b"", {}),
                        site_name=SITE_NAME,
                        job_name=JOB_NAME,
                        user_agent=value,
                        observed_at=stamp(NOW),
                    )


class FinalHistoryCensusTests(unittest.TestCase):
    def setUp(self):
        self.old = history_entry(
            "old-run", trigger_sha256=bootstrap.sha256_bytes(b"External - old")
        )
        self.terminal = history_entry("fresh-run")
        self.canary = {
            "historyBoundary": {"entries": [self.old]},
            "terminalHistory": self.terminal,
        }

    def read(self, observed, *, clock=lambda: NOW, deadline=None):
        transport = bare_transport(clock=clock)
        transport._read_webjob_history = mock.Mock(return_value=observed)
        result = transport._read_final_webjob_history(
            site_resource_id=SITE_ID,
            job_name=JOB_NAME,
            canary=self.canary,
            deadline=deadline or (NOW + dt.timedelta(seconds=60)),
        )
        return result, transport._read_webjob_history

    def test_exact_stopped_census_is_accepted_with_one_bounded_read(self):
        observed = history_observation([self.old, self.terminal])
        result, reader = self.read(observed)

        self.assertEqual(result, observed)
        reader.assert_called_once_with(
            site_resource_id=SITE_ID,
            job_name=JOB_NAME,
            deadline=NOW + dt.timedelta(seconds=60),
            retry_delays=bootstrap.CANARY_READ_TRANSPORT_RETRY_DELAYS_SECONDS,
            failure_context="final-history-census",
        )

    def test_added_removed_or_changed_history_fails_closed(self):
        added = history_entry("late-run")
        removed = [self.terminal]
        changed = copy.deepcopy(self.terminal)
        changed["status"] = "Failed"
        for entries in (
            [self.old, self.terminal, added],
            removed,
            [self.old, changed],
        ):
            with self.subTest(entries=[item["webJobsRunId"] for item in entries]):
                with self.assertRaisesRegex(
                    bootstrap.BootstrapError,
                    "final WebJob history census drifted or contains an extra run",
                ):
                    self.read(history_observation(entries))

    def test_non_200_or_absent_history_fails_closed(self):
        for observed in (
            None,
            history_observation([self.old, self.terminal], http_status=404),
        ):
            with self.subTest(observed=observed):
                with self.assertRaises(bootstrap.BootstrapError):
                    self.read(observed)

    def test_response_crossing_deadline_fails_closed(self):
        times = iter((NOW, NOW + dt.timedelta(seconds=61)))
        with self.assertRaisesRegex(
            bootstrap.BootstrapError,
            "final WebJob history census response crossed its deadline",
        ):
            self.read(
                history_observation([self.old, self.terminal]),
                clock=lambda: next(times),
            )


class FreshHistoryPollingTests(unittest.TestCase):
    def call(self, observations, *, boundary_entries, current=None, sleep=None):
        current = current or [NOW]
        transport = bare_transport(
            clock=lambda: current[0],
            sleep=sleep or (lambda seconds: current.__setitem__(0, current[0] + dt.timedelta(seconds=seconds))),
        )
        transport._read_webjob_history = mock.Mock(side_effect=observations)
        return transport._wait_for_fresh_webjob_success(
            site_resource_id=SITE_ID,
            job_name=JOB_NAME,
            boundary={"entries": copy.deepcopy(boundary_entries)},
            trigger_requested_at=NOW,
            expected_trigger_sha256=EXPECTED_TRIGGER_SHA256,
            deadline=NOW + dt.timedelta(seconds=3),
        )

    def test_no_fresh_history_never_succeeds(self):
        current = [NOW]
        transport = bare_transport(
            clock=lambda: current[0],
            sleep=lambda seconds: current.__setitem__(
                0, current[0] + dt.timedelta(seconds=seconds)
            ),
        )
        unchanged = history_observation([])
        transport._read_webjob_history = mock.Mock(return_value=unchanged)

        with self.assertRaises(bootstrap.BootstrapError):
            transport._wait_for_fresh_webjob_success(
                site_resource_id=SITE_ID,
                job_name=JOB_NAME,
                boundary={"entries": []},
                trigger_requested_at=NOW,
                expected_trigger_sha256=EXPECTED_TRIGGER_SHA256,
                deadline=NOW + dt.timedelta(seconds=3),
            )

    def test_multiple_fresh_histories_are_ambiguous(self):
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "ambiguous fresh history set"
        ):
            self.call(
                [history_observation([history_entry("one"), history_entry("two")])],
                boundary_entries=[],
            )

    def test_changed_boundary_fails_closed(self):
        old = history_entry(
            "old-run", trigger_sha256=bootstrap.sha256_bytes(b"External - old")
        )
        changed = copy.deepcopy(old)
        changed["status"] = "Failed"
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "pre-run WebJob history boundary drifted"
        ):
            self.call(
                [history_observation([changed, history_entry("fresh-run")])],
                boundary_entries=[old],
            )

    def test_unique_fresh_history_requires_exact_user_agent_trigger(self):
        wrong = history_entry(
            "fresh-run", trigger_sha256=bootstrap.sha256_bytes(b"External - other")
        )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "does not match the request trigger token"
        ):
            self.call([history_observation([wrong])], boundary_entries=[])

    def test_exact_failed_history_retains_bounded_run_evidence(self):
        for status in ("Failed", "Aborted"):
            with self.subTest(status=status):
                with self.assertRaises(bootstrap.WebJobCanaryFailure) as caught:
                    self.call(
                        [history_observation([history_entry("failed-run", status=status)])],
                        boundary_entries=[],
                    )
                diagnostic = caught.exception.diagnostic
                self.assertEqual(diagnostic["status"], status)
                self.assertEqual(diagnostic["runId"], "failed-run")
                self.assertEqual(diagnostic["historyResponseSha256"], "d" * 64)
                self.assertEqual(diagnostic["outputPathSha256"], "c" * 64)
                self.assertNotIn("trigger", json.dumps(diagnostic).lower())
                self.assertNotIn("scm.azurewebsites.net", json.dumps(diagnostic))


class FailedWebJobLogProbeTests(unittest.TestCase):
    def transport(self, runner, *, site_id=PROBE_SITE_ID):
        transport = bare_transport()
        transport.resources = {
            "bridgeSite": {"resourceId": PROBE_SITE_ID, "name": SITE_NAME}
        }
        transport.session = mock.Mock()
        transport.session._tokens = {
            "https://management.azure.com/": (
                "ARM-TOKEN",
                int((NOW + dt.timedelta(minutes=2)).timestamp()),
            )
        }
        transport.session._exchange_runner = runner
        return transport._probe_failed_webjob_log(
            site_resource_id=site_id,
            job_name=JOB_NAME,
            run_id="failed-run",
            deadline=NOW + dt.timedelta(minutes=1),
        )

    def test_reads_only_exact_run_files_once_and_retains_no_raw_log_or_credentials(self):
        calls = []
        secret = "private-diagnostic-secret"
        error = (
            "MailboxError: entry-bootstrap-self-test-identity\n" + secret
        ).encode()

        def runner(request, timeout):
            calls.append((request.full_url, request.get_method(), timeout,
                          request.get_header("Authorization")))
            if len(calls) == 1:
                return bootstrap._RestResponse(
                    200,
                    json.dumps({"properties": {
                        "publishingUserName": "user",
                        "publishingPassword": "password",
                    }}).encode(),
                    {},
                )
            if len(calls) == 2:
                return bootstrap._RestResponse(200, error, {})
            return bootstrap._RestResponse(404, b"missing", {})

        diagnostic = self.transport(runner)

        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[0][1:], ("POST", 6.0, "Bearer ARM-TOKEN"))
        self.assertEqual(calls[1][1:3], ("GET", 6.0))
        self.assertEqual(calls[2][1:3], ("GET", 6.0))
        self.assertEqual(
            base64.b64decode(calls[1][3].removeprefix("Basic ")),
            b"user:password",
        )
        self.assertTrue(calls[0][0].endswith(
            PROBE_SITE_ID + "/config/publishingcredentials/list?api-version=2025-05-01"
        ))
        for kind, call in zip(("error", "output"), calls[1:]):
            self.assertEqual(
                call[0],
                f"https://{SITE_NAME}.scm.azurewebsites.net/api/vfs/data/jobs/"
                f"triggered/{JOB_NAME}/failed-run/{kind}_failed-run.log",
            )
        self.assertEqual(diagnostic["error"]["markerHint"],
                         "entry-bootstrap-self-test-identity")
        self.assertEqual(diagnostic["error"]["sha256"],
                         bootstrap.sha256_bytes(error))
        self.assertEqual(diagnostic["output"],
                         {"state": "http-error", "httpStatus": 404})
        self.assertNotIn(secret, json.dumps(diagnostic))
        self.assertNotIn("password", json.dumps(diagnostic))
        self.assertNotIn("ARM-TOKEN", json.dumps(diagnostic))

    def test_wrong_site_or_transport_error_never_retries(self):
        runner = mock.Mock(side_effect=RuntimeError("secret transport detail"))
        wrong = self.transport(runner, site_id=PROBE_SITE_ID + "/other")
        self.assertEqual(wrong, {"state": "unavailable", "reason": "target"})
        runner.assert_not_called()

        failed = self.transport(runner)
        self.assertEqual(failed,
                         {"state": "unavailable", "reason": "credential-transport"})
        runner.assert_called_once()
        self.assertNotIn("secret", json.dumps(failed))

    def test_short_deadline_skips_all_credential_and_log_requests(self):
        runner = mock.Mock()
        transport = bare_transport()
        transport.resources = {
            "bridgeSite": {"resourceId": PROBE_SITE_ID, "name": SITE_NAME}
        }
        transport.session = mock.Mock()
        transport.session._exchange_runner = runner
        diagnostic = transport._probe_failed_webjob_log(
            site_resource_id=PROBE_SITE_ID,
            job_name=JOB_NAME,
            run_id="failed-run",
            deadline=NOW + dt.timedelta(seconds=24),
        )
        self.assertEqual(diagnostic,
                         {"state": "unavailable", "reason": "deadline"})
        runner.assert_not_called()

    def test_marker_is_only_a_source_owned_hint(self):
        classify = bootstrap.AzureCliBootstrapTransport._safe_webjob_failure_marker
        self.assertEqual(classify(b"paperdesk-bridge-startup:python-version\n"),
                         "paperdesk-bridge-startup:python-version")
        self.assertEqual(classify(b"MailboxError: fence-canary-acquire\n"),
                         "fence-canary-acquire")
        self.assertIsNone(classify(b"secret token: abcdef\n"))
        self.assertIsNone(classify(b"x" * (64 * 1024 + 1)))


class TriggerCorrelationEvidenceBindingTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        receipt = Path(self.folder.name) / (
            "paperdesk-private-release-v2-bootstrap-" + AUTHORIZATION_ID
        )
        self.fixture = build_valid_terminal_source_evidence_fixture(
            receipt,
            package={"sha256": "a" * 64, "size": 4096},
        )
        self.operation_id = "startBridgeForBoundedCanary"

    def tearDown(self):
        self.folder.cleanup()

    def journal_inputs(self, *, operation_projections=None):
        contexts = {
            item["operationId"]: item["context"]
            for item in self.fixture["preflightProjection"]["operationAdmissions"]
        }
        return {
            "plan": self.fixture["plan"],
            "authorization": self.fixture["authorization"],
            "operation_projections": (
                operation_projections
                if operation_projections is not None
                else self.fixture["operationProjections"]
            ),
            "operation_contexts": contexts,
        }

    def journal(self):
        return copy.deepcopy(
            self.fixture["sourceEvidence"]["productionBoundary"]["mutationJournal"]
        )

    @staticmethod
    def replacement_user_agent():
        return (
            f"PaperDeskV2Bootstrap/{AUTHORIZATION_ID}."
            "22222222-2222-4222-8222-222222222222"
        )

    def test_journal_trigger_token_must_match_source_projection(self):
        journal = self.journal()
        trigger_records = [
            item
            for item in journal
            if item["operationId"] == self.operation_id
            and item["targetUrl"].split("?", 1)[0].endswith("/run")
        ]
        self.assertEqual(len(trigger_records), 2)
        for item in trigger_records:
            item["webJobTriggerUserAgent"] = self.replacement_user_agent()

        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "User-Agent.*cross-bound|cross-bound.*User-Agent"
        ):
            bootstrap._validate_sanitized_mutation_journal(
                journal, **self.journal_inputs()
            )

    def test_webjob_token_is_required_only_on_the_exact_run_pair(self):
        valid_token = self.replacement_user_agent()

        missing = self.journal()
        for item in missing:
            if item["operationId"] == self.operation_id and item[
                "targetUrl"
            ].split("?", 1)[0].endswith("/run"):
                item.pop("webJobTriggerUserAgent")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap._validate_sanitized_mutation_journal(
                missing, **self.journal_inputs()
            )

        extra = self.journal()
        non_run = next(
            item
            for item in extra
            if not item["targetUrl"].split("?", 1)[0].endswith("/run")
        )
        non_run["webJobTriggerUserAgent"] = valid_token
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap._validate_sanitized_mutation_journal(
                extra, **self.journal_inputs()
            )

    def test_recomputed_projection_token_and_history_digest_cannot_diverge_from_journal(self):
        projections = copy.deepcopy(self.fixture["operationProjections"])
        projection = projections[self.operation_id]["projection"]
        token = self.replacement_user_agent()
        trigger_sha = bootstrap.sha256_bytes(
            ("External - " + token).encode("utf-8")
        )
        projection["triggerCorrelation"]["userAgent"] = token
        projection["triggerCorrelation"]["expectedHistoryTriggerSha256"] = trigger_sha
        projection["terminalHistory"]["triggerSha256"] = trigger_sha
        boundary_entries = projection["historyBoundary"]["entries"]
        terminal_entries = [*boundary_entries, projection["terminalHistory"]]
        terminal_entries.sort(key=lambda item: item["historyId"])
        projection["terminalHistoryEntriesSha256"] = bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(terminal_entries)
        )
        projection["finalHistoryCensus"]["entries"] = copy.deepcopy(terminal_entries)
        projection["finalHistoryCensus"]["entriesSha256"] = bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(terminal_entries)
        )

        # The projection is internally coherent; only the durable HTTP intent/result
        # pair proves which token was actually sent.
        bootstrap._validate_operation_source_projection(
            projections[self.operation_id],
            operation_id=self.operation_id,
            plan=self.fixture["plan"],
            authorization=self.fixture["authorization"],
            prior=projections,
            operation_context=self.journal_inputs()["operation_contexts"][
                self.operation_id
            ],
            runtime_facts={},
        )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "User-Agent.*cross-bound|cross-bound.*User-Agent"
        ):
            bootstrap._validate_sanitized_mutation_journal(
                self.journal(),
                **self.journal_inputs(operation_projections=projections),
            )

    def test_final_census_cannot_be_replaced_by_a_rehashed_extra_entry(self):
        projections = copy.deepcopy(self.fixture["operationProjections"])
        projection = projections[self.operation_id]["projection"]
        extra = copy.deepcopy(projection["terminalHistory"])
        extra["historyId"] = extra["historyId"].replace("fresh-run", "later-run")
        extra["webJobsRunId"] = "later-run"
        census_entries = [*projection["finalHistoryCensus"]["entries"], extra]
        census_entries.sort(key=lambda item: item["historyId"])
        projection["finalHistoryCensus"]["entries"] = census_entries
        projection["finalHistoryCensus"]["entriesSha256"] = bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(census_entries)
        )

        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "final WebJob history census"
        ):
            bootstrap._validate_operation_source_projection(
                projections[self.operation_id],
                operation_id=self.operation_id,
                plan=self.fixture["plan"],
                authorization=self.fixture["authorization"],
                prior=projections,
                operation_context=self.journal_inputs()["operation_contexts"][
                    self.operation_id
                ],
                runtime_facts={},
            )

    def test_mutation_request_sends_one_exact_user_agent_and_rejects_caller_header(self):
        response = bootstrap._RestResponse(200, b"", {})
        session = Session([response])
        execution_now = bootstrap.parse_time(
            self.fixture["authorization"]["validity"]["notBefore"],
            "fixture authorization notBefore",
        ) + dt.timedelta(seconds=1)
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=self.fixture["authorization"],
            plan=self.fixture["plan"],
            package=self.fixture["package"],
            preflight={"projection": self.fixture["preflightProjection"]},
            session=session,
            clock=lambda: execution_now,
            sleep=lambda _seconds: None,
        )
        ledger = MemoryJournal()
        transport.bind_journal(ledger)
        transport._active_operation_id = self.operation_id
        bridge_site_id = next(
            item["resourceId"]
            for item in self.fixture["plan"]["resourceInventory"]
            if item["id"] == "bridgeSite"
        )
        run_url = transport._arm_url(
            bridge_site_id,
            "2025-05-01",
            f"/triggeredwebjobs/{JOB_NAME}/run",
        )

        transport._mutation_request(
            "POST",
            run_url,
            body=b"",
            expected={200},
            webjob_trigger_user_agent=USER_AGENT,
        )
        self.assertEqual(len(session.requests), 1)
        self.assertEqual(session.requests[0][3], {"User-Agent": USER_AGENT})
        self.assertEqual(len(ledger.records), 2)
        self.assertTrue(
            all(item["webJobTriggerUserAgent"] == USER_AGENT for item in ledger.records)
        )

        blocked_session = Session([response])
        blocked = bootstrap.AzureCliBootstrapTransport(
            authorization=self.fixture["authorization"],
            plan=self.fixture["plan"],
            package=self.fixture["package"],
            preflight={"projection": self.fixture["preflightProjection"]},
            session=blocked_session,
            clock=lambda: execution_now,
            sleep=lambda _seconds: None,
        )
        blocked_ledger = MemoryJournal()
        blocked.bind_journal(blocked_ledger)
        blocked._active_operation_id = self.operation_id
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "caller-supplied User-Agent"
        ):
            blocked._mutation_request(
                "POST",
                run_url,
                body=b"",
                headers={"User-Agent": USER_AGENT, "user-agent": USER_AGENT},
                expected={200},
                webjob_trigger_user_agent=USER_AGENT,
            )
        self.assertEqual(blocked_session.requests, [])
        self.assertEqual(blocked_ledger.records, [])


if __name__ == "__main__":
    unittest.main()
