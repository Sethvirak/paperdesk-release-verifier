"""Live-shape regressions for the ARM triggered-WebJob history collection."""

import datetime as dt
import copy
import unittest
from unittest import mock

from scripts import private_release_v2_bootstrap as bootstrap


NOW = dt.datetime(2026, 9, 14, 11, 0, tzinfo=dt.timezone.utc)
SITE_ID = (
    f"/subscriptions/{bootstrap.SUBSCRIPTION}/"
    "resourceGroups/paperdesk-release/providers/Microsoft.Web/"
    "sites/paperdesk-release-registry-bridge-v2-9c4e0d0d"
)
SITE_NAME = "paperdesk-release-registry-bridge-v2-9c4e0d0d"
JOB_NAME = "paperdesk-accepted-release-registry"
COLLECTION_ID = f"{SITE_ID}/triggeredwebjobs/{JOB_NAME}/history"


def stamp(value):
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def run(run_id, *, offset=0):
    started = NOW + dt.timedelta(seconds=offset)
    return {
        "web_job_name": JOB_NAME,
        "web_job_id": run_id,
        "trigger": "External - PaperDeskV2Bootstrap/test",
        "status": "Success",
        "start_time": stamp(started),
        "end_time": stamp(started + dt.timedelta(seconds=1)),
        "output_url": (
            f"https://{SITE_NAME}.scm.azurewebsites.net/vfs/data/jobs/"
            f"triggered/{JOB_NAME}/{run_id}/output_log.txt"
        ),
    }


def transport():
    value = object.__new__(bootstrap.AzureCliBootstrapTransport)
    value.clock = lambda: NOW
    return value


class WebJobHistoryCollectionTests(unittest.TestCase):
    def test_exact_collection_resource_can_represent_pristine_empty_history(self):
        projected = transport()._project_webjob_history_item(
            {"id": COLLECTION_ID, "properties": {"runs": []}},
            site_resource_id=SITE_ID,
            job_name=JOB_NAME,
        )
        self.assertEqual(projected, [])

    def test_collection_runs_are_flattened_to_exact_child_history_ids(self):
        projected = transport()._project_webjob_history_item(
            {
                "id": COLLECTION_ID,
                "properties": {"runs": [run("run-1"), run("run-2", offset=3)]},
            },
            site_resource_id=SITE_ID,
            job_name=JOB_NAME,
        )
        self.assertEqual(
            [item["historyId"] for item in projected],
            [COLLECTION_ID + "/run-1", COLLECTION_ID + "/run-2"],
        )
        self.assertEqual(
            [item["webJobsRunId"] for item in projected], ["run-1", "run-2"]
        )

    def test_child_resource_remains_one_run_and_must_bind_its_run_id(self):
        projected = transport()._project_webjob_history_item(
            {
                "id": COLLECTION_ID + "/run-1",
                "properties": {"runs": [run("run-1")]},
            },
            site_resource_id=SITE_ID,
            job_name=JOB_NAME,
        )
        self.assertEqual(projected[0]["historyId"], COLLECTION_ID + "/run-1")

        for invalid in (
            {"id": COLLECTION_ID + "/run-1", "properties": {"runs": []}},
            {
                "id": COLLECTION_ID + "/other-run",
                "properties": {"runs": [run("run-1")]},
            },
        ):
            with self.assertRaises(bootstrap.BootstrapError):
                transport()._project_webjob_history_item(
                    invalid,
                    site_resource_id=SITE_ID,
                    job_name=JOB_NAME,
                )

    def test_direct_child_run_properties_require_the_same_exact_identity(self):
        projected = transport()._project_webjob_history_item(
            {"id": COLLECTION_ID + "/run-1", "properties": run("run-1")},
            site_resource_id=SITE_ID,
            job_name=JOB_NAME,
        )
        self.assertEqual(projected[0]["historyId"], COLLECTION_ID + "/run-1")
        self.assertEqual(projected[0]["status"], "Success")

        for invalid in (
            {"id": COLLECTION_ID + "/other-run", "properties": run("run-1")},
            {"id": COLLECTION_ID + "/run-1", "properties": {"status": "Success"}},
        ):
            with self.assertRaises(bootstrap.BootstrapError):
                transport()._project_webjob_history_item(
                    invalid,
                    site_resource_id=SITE_ID,
                    job_name=JOB_NAME,
                )

    def test_nonterminal_default_end_time_is_unset_without_proving_success(self):
        for status in ("Initializing", "Running"):
            for end_time in (
                "0001-01-01T00:00:00",
                "0001-01-01T00:00:00Z",
                "0001-01-01T00:00:00.0000000+00:00",
            ):
                with self.subTest(status=status, end_time=end_time):
                    item = run("run-1")
                    item["status"] = status
                    item["end_time"] = end_time
                    projected = transport()._project_webjob_history_item(
                        {"id": COLLECTION_ID + "/run-1", "properties": item},
                        site_resource_id=SITE_ID,
                        job_name=JOB_NAME,
                    )
                    self.assertEqual(projected[0]["status"], status)
                    self.assertIsNone(projected[0]["endedAt"])
                    self.assertIsNone(projected[0]["outputUrlMetadata"])

    def test_nonterminal_real_or_malformed_end_time_fails_without_value_leak(self):
        for end_time, expected_class in (
            (stamp(NOW + dt.timedelta(seconds=1)), "nondefault-string"),
            ("0001-01-01T00:00:01", "nondefault-string"),
            ("secret-provider-value", "nondefault-string"),
            (42, "nonstring"),
            ({"secret-provider-key": "secret-provider-value"}, "nonstring"),
        ):
            with self.subTest(end_time=end_time):
                item = run("run-1")
                item["status"] = "Running"
                item["end_time"] = end_time
                with self.assertRaises(bootstrap.BootstrapError) as raised:
                    transport()._project_webjob_history_item(
                        {"id": COLLECTION_ID + "/run-1", "properties": item},
                        site_resource_id=SITE_ID,
                        job_name=JOB_NAME,
                    )
                diagnostic = str(raised.exception)
                self.assertIn("status=Running", diagnostic)
                self.assertIn("endClass=" + expected_class, diagnostic)
                self.assertNotIn(str(end_time), diagnostic)
                self.assertNotIn("secret-provider-value", diagnostic)

    def test_terminal_success_rejects_default_end_time(self):
        item = run("run-1")
        item["end_time"] = "0001-01-01T00:00:00Z"
        with self.assertRaises(bootstrap.BootstrapError):
            transport()._project_webjob_history_item(
                {"id": COLLECTION_ID + "/run-1", "properties": item},
                site_resource_id=SITE_ID,
                job_name=JOB_NAME,
            )

    def test_invalid_entry_reports_only_nonsecret_shape(self):
        for entry, expected in (
            (
                {"id": COLLECTION_ID, "properties": {"runs": None}},
                "idClass=collection, runsClass=null, runsCount=n/a",
            ),
            (
                {"id": SITE_ID + "/unexpected/secret-run-id", "properties": {"runs": []}},
                "idClass=other-site-child, runsClass=list, runsCount=0",
            ),
            (
                {"id": COLLECTION_ID + "/secret-run-id", "properties": {"runs": []}},
                "idClass=child, runsClass=list, runsCount=0",
            ),
        ):
            with self.subTest(expected=expected):
                with self.assertRaises(bootstrap.BootstrapError) as raised:
                    transport()._project_webjob_history_item(
                        entry,
                        site_resource_id=SITE_ID,
                        job_name=JOB_NAME,
                    )
                self.assertIn(expected, str(raised.exception))
                self.assertNotIn("secret-run-id", str(raised.exception))

    def test_incomplete_direct_child_reports_only_fixed_field_presence(self):
        entry = {
            "id": COLLECTION_ID + "/secret-run-id",
            "properties": {
                "job_name": JOB_NAME,
                "web_job_id": "secret-run-id",
                "status": "Success",
                "trigger": "secret-trigger-value",
                "start_time": stamp(NOW),
                "secret-provider-key": "secret-provider-value",
            },
        }
        with self.assertRaises(bootstrap.BootstrapError) as raised:
            transport()._project_webjob_history_item(
                entry,
                site_resource_id=SITE_ID,
                job_name=JOB_NAME,
            )
        diagnostic = str(raised.exception)
        self.assertIn("idClass=child, runsClass=missing, runsCount=n/a", diagnostic)
        self.assertIn("directFieldPresence=01111100", diagnostic)
        for secret in (
            "secret-run-id",
            "secret-trigger-value",
            "secret-provider-key",
            "secret-provider-value",
        ):
            self.assertNotIn(secret, diagnostic)

    def test_history_read_accepts_documented_collection_shape_and_binds_digest(self):
        document = {
            "value": [
                {
                    "id": COLLECTION_ID,
                    "properties": {"runs": [run("run-2"), run("run-1")]},
                }
            ],
            "nextLink": None,
        }
        response = bootstrap._RestResponse(
            200,
            bootstrap.canonical_json_bytes(document),
            {"Content-Type": "application/json"},
        )
        value = transport()
        value._read_request_with_transport_retry = mock.Mock(return_value=response)
        observed = value._read_webjob_history(
            site_resource_id=SITE_ID,
            job_name=JOB_NAME,
            deadline=NOW + dt.timedelta(seconds=30),
        )
        self.assertEqual(
            [item["webJobsRunId"] for item in observed["entries"]],
            ["run-1", "run-2"],
        )
        self.assertEqual(observed["responseSha256"], bootstrap._response_sha256(response))
        self.assertEqual(
            observed["entriesSha256"],
            bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(observed["entries"])
            ),
        )

    def test_history_read_accepts_exact_direct_child_shape(self):
        document = {
            "value": [
                {"id": COLLECTION_ID + "/run-2", "properties": run("run-2", offset=3)},
                {"id": COLLECTION_ID + "/run-1", "properties": run("run-1")},
            ],
            "nextLink": None,
        }
        response = bootstrap._RestResponse(
            200,
            bootstrap.canonical_json_bytes(document),
            {"Content-Type": "application/json"},
        )
        value = transport()
        value._read_request_with_transport_retry = mock.Mock(return_value=response)
        observed = value._read_webjob_history(
            site_resource_id=SITE_ID,
            job_name=JOB_NAME,
            deadline=NOW + dt.timedelta(seconds=30),
        )
        self.assertEqual(
            [item["webJobsRunId"] for item in observed["entries"]],
            ["run-1", "run-2"],
        )

    def test_incomplete_list_child_requires_exact_documented_detail(self):
        listing = bootstrap._RestResponse(
            200,
            bootstrap.canonical_json_bytes({
                "value": [{
                    "id": COLLECTION_ID + "/run-1",
                    "properties": {"status": "Success"},
                }],
            }),
            {"Content-Type": "application/json"},
        )
        detail = bootstrap._RestResponse(
            200,
            bootstrap.canonical_json_bytes({
                "id": COLLECTION_ID + "/run-1",
                "properties": {"runs": [run("run-1")]},
            }),
            {"Content-Type": "application/json"},
        )
        value = transport()
        value._read_request_with_transport_retry = mock.Mock(
            side_effect=[listing, detail]
        )
        observed = value._read_webjob_history(
            site_resource_id=SITE_ID,
            job_name=JOB_NAME,
            deadline=NOW + dt.timedelta(minutes=3),
        )
        self.assertEqual(observed["entries"][0]["webJobsRunId"], "run-1")
        self.assertEqual(
            observed["detailResponseSha256s"],
            [bootstrap._response_sha256(detail)],
        )
        detail_call = value._read_request_with_transport_retry.call_args_list[1]
        self.assertEqual(detail_call.args[0], "GET")
        self.assertEqual(
            detail_call.args[1],
            "https://management.azure.com" + COLLECTION_ID
            + "/run-1?api-version=2025-05-01",
        )
        self.assertEqual(detail_call.kwargs["retry_delays"], (None,))

    def test_detail_only_flattened_identity_binds_exact_child_run(self):
        alternate = {
            key: value for key, value in run("run-1").items()
            if key not in {"web_job_name", "web_job_id"}
        }
        alternate["job_name"] = JOB_NAME
        listing = bootstrap._RestResponse(
            200,
            bootstrap.canonical_json_bytes({
                "value": [{
                    "id": COLLECTION_ID + "/run-1",
                    "properties": alternate,
                }],
            }),
            {"Content-Type": "application/json"},
        )

        def read_with_detail(properties):
            detail = bootstrap._RestResponse(
                200,
                bootstrap.canonical_json_bytes({
                    "id": COLLECTION_ID + "/run-1",
                    "properties": properties,
                }),
                {"Content-Type": "application/json"},
            )
            value = transport()
            value._read_request_with_transport_retry = mock.Mock(
                side_effect=[listing, detail]
            )
            return value, detail

        value, detail = read_with_detail(alternate)
        observed = value._read_webjob_history(
            site_resource_id=SITE_ID,
            job_name=JOB_NAME,
            deadline=NOW + dt.timedelta(minutes=3),
        )
        self.assertEqual(observed["entries"][0]["webJobsRunId"], "run-1")
        self.assertEqual(
            observed["entries"][0]["historyId"], COLLECTION_ID + "/run-1"
        )
        self.assertEqual(
            observed["detailResponseSha256s"],
            [bootstrap._response_sha256(detail)],
        )
        self.assertEqual(value._read_request_with_transport_retry.call_count, 2)

        for detail_properties in (
            alternate | {"job_name": "another-job"},
            alternate | {"web_job_id": "another-run"},
            alternate | {"web_job_name": "another-job"},
        ):
            with self.subTest(detail_properties=detail_properties):
                value, _ = read_with_detail(detail_properties)
                with self.assertRaises(bootstrap.BootstrapError):
                    value._read_webjob_history(
                        site_resource_id=SITE_ID,
                        job_name=JOB_NAME,
                        deadline=NOW + dt.timedelta(minutes=3),
                    )

        contradicting_listing = bootstrap._RestResponse(
            200,
            bootstrap.canonical_json_bytes({
                "value": [{
                    "id": COLLECTION_ID + "/run-1",
                    "properties": alternate | {"status": "Failed"},
                }],
            }),
            {"Content-Type": "application/json"},
        )
        value, detail = read_with_detail(alternate)
        value._read_request_with_transport_retry.side_effect = [
            contradicting_listing, detail,
        ]
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "contradicts its detail"
        ):
            value._read_webjob_history(
                site_resource_id=SITE_ID,
                job_name=JOB_NAME,
                deadline=NOW + dt.timedelta(minutes=3),
            )

    def test_history_detail_mismatch_and_invalid_child_path_fail_closed(self):
        listing = bootstrap._RestResponse(
            200,
            bootstrap.canonical_json_bytes({
                "value": [{
                    "id": COLLECTION_ID + "/run-1",
                    "properties": {"status": "Success"},
                }],
            }),
            {"Content-Type": "application/json"},
        )
        wrong_detail = bootstrap._RestResponse(
            200,
            bootstrap.canonical_json_bytes({
                "id": COLLECTION_ID + "/run-2",
                "properties": {"runs": [run("run-2")]},
            }),
            {"Content-Type": "application/json"},
        )
        value = transport()
        value._read_request_with_transport_retry = mock.Mock(
            side_effect=[listing, wrong_detail]
        )
        with self.assertRaises(bootstrap.BootstrapError):
            value._read_webjob_history(
                site_resource_id=SITE_ID,
                job_name=JOB_NAME,
                deadline=NOW + dt.timedelta(minutes=3),
            )

        collection_detail = bootstrap._RestResponse(
            200,
            bootstrap.canonical_json_bytes({
                "id": COLLECTION_ID,
                "properties": {"runs": [run("run-1")]},
            }),
            {"Content-Type": "application/json"},
        )
        value = transport()
        value._read_request_with_transport_retry = mock.Mock(
            side_effect=[listing, collection_detail]
        )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "resource ID differs from list child"
        ):
            value._read_webjob_history(
                site_resource_id=SITE_ID,
                job_name=JOB_NAME,
                deadline=NOW + dt.timedelta(minutes=3),
            )

        contradicting_detail = bootstrap._RestResponse(
            200,
            bootstrap.canonical_json_bytes({
                "id": COLLECTION_ID + "/run-1",
                "properties": {"runs": [run("run-1") | {"status": "Failed"}]},
            }),
            {"Content-Type": "application/json"},
        )
        value = transport()
        value._read_request_with_transport_retry = mock.Mock(
            side_effect=[listing, contradicting_detail]
        )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "contradicts its detail"
        ):
            value._read_webjob_history(
                site_resource_id=SITE_ID,
                job_name=JOB_NAME,
                deadline=NOW + dt.timedelta(minutes=3),
            )

        malformed_listing = bootstrap._RestResponse(
            200,
            bootstrap.canonical_json_bytes({
                "value": [{
                    "id": COLLECTION_ID + "/..",
                    "properties": {"status": "Success"},
                }],
            }),
            {"Content-Type": "application/json"},
        )
        value = transport()
        value._read_request_with_transport_retry = mock.Mock(
            return_value=malformed_listing
        )
        with self.assertRaises(bootstrap.BootstrapError):
            value._read_webjob_history(
                site_resource_id=SITE_ID,
                job_name=JOB_NAME,
                deadline=NOW + dt.timedelta(minutes=3),
            )
        self.assertEqual(value._read_request_with_transport_retry.call_count, 1)

    def test_history_detail_reads_are_bounded_before_any_detail_request(self):
        listing = bootstrap._RestResponse(
            200,
            bootstrap.canonical_json_bytes({
                "value": [
                    {
                        "id": COLLECTION_ID + f"/run-{index}",
                        "properties": {"status": "Success"},
                    }
                    for index in range(bootstrap.MAX_WEBJOB_HISTORY_DETAIL_READS + 1)
                ],
            }),
            {"Content-Type": "application/json"},
        )
        value = transport()
        value._read_request_with_transport_retry = mock.Mock(return_value=listing)
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "too many detail reads"
        ):
            value._read_webjob_history(
                site_resource_id=SITE_ID,
                job_name=JOB_NAME,
                deadline=NOW + dt.timedelta(minutes=3),
            )
        self.assertEqual(value._read_request_with_transport_retry.call_count, 1)

    def test_duplicate_source_resources_and_duplicate_runs_fail_closed(self):
        duplicate_source = {
            "value": [
                {"id": COLLECTION_ID, "properties": {"runs": []}},
                {"id": COLLECTION_ID.upper(), "properties": {"runs": []}},
            ]
        }
        duplicate_run = {
            "value": [
                {
                    "id": COLLECTION_ID,
                    "properties": {"runs": [run("run-1"), run("run-1")]},
                }
            ]
        }
        for document in (duplicate_source, duplicate_run):
            value = transport()
            value._read_request_with_transport_retry = mock.Mock(
                return_value=bootstrap._RestResponse(
                    200,
                    bootstrap.canonical_json_bytes(document),
                    {"Content-Type": "application/json"},
                )
            )
            with self.assertRaises(bootstrap.BootstrapError):
                value._read_webjob_history(
                    site_resource_id=SITE_ID,
                    job_name=JOB_NAME,
                    deadline=NOW + dt.timedelta(seconds=30),
                )


class SharedCanaryHistoryDetailBudgetTests(unittest.TestCase):
    def budget(self):
        return bootstrap._HistoryDetailBudget(
            site_resource_id=SITE_ID, job_name=JOB_NAME,
            error_type=bootstrap.BootstrapError,
        )

    def history_transport(self, documents, *, current=None):
        current = current or [NOW]
        value = transport()
        value.clock = lambda: current[0]
        value.sleep = lambda seconds: current.__setitem__(
            0, current[0] + dt.timedelta(seconds=seconds)
        )
        value.resources = {"bridgeSite": {"name": SITE_NAME}}
        value.authorization = {"validity": {"expiresAt": stamp(NOW + dt.timedelta(seconds=900))}}
        value._read_triggered_webjob_metadata = mock.Mock(return_value={"latestRunPresent": True})
        documents = iter(documents)
        active = {}
        reads = []

        def request(method, url, **kwargs):
            self.assertEqual(method, "GET")
            reads.append((url, kwargs))
            if url.split("?", 1)[0].endswith("/history"):
                definitions, sparse = next(documents)
                active.clear()
                active.update({entry["web_job_id"]: entry for entry in definitions})
                body = {"value": [
                    {"id": COLLECTION_ID + "/" + entry["web_job_id"],
                     "properties": {} if sparse else entry}
                    for entry in definitions
                ]}
            else:
                run_id = url.split("?", 1)[0].rsplit("/", 1)[-1]
                body = {"id": COLLECTION_ID + "/" + run_id, "properties": active[run_id]}
                self.assertEqual(kwargs["retry_delays"], (None,))
            return bootstrap._RestResponse(200, bootstrap.canonical_json_bytes(body), {})

        value._read_request_with_transport_retry = mock.Mock(side_effect=request)
        return value, reads

    def read(self, value, budget, stage="history-boundary"):
        return value._read_webjob_history(
            site_resource_id=SITE_ID, job_name=JOB_NAME,
            deadline=NOW + dt.timedelta(seconds=300),
            failure_context=stage, detail_budget=budget,
        )

    def test_growing_history_rereads_every_old_child_at_all_three_phases(self):
        for old_count in (4, 5):
            with self.subTest(old_count=old_count):
                old = [run(f"old-{index}", offset=-20-index*2) for index in range(old_count)]
                fresh = run("fresh", offset=-1)
                expected = bootstrap.sha256_bytes(fresh["trigger"].encode())
                value, reads = self.history_transport([
                    (old, True), (old + [fresh], True), (old + [fresh], True),
                ])
                budget = self.budget()
                boundary = value._wait_for_webjob_history_boundary(
                    site_resource_id=SITE_ID, job_name=JOB_NAME,
                    deadline=NOW + dt.timedelta(seconds=710), detail_budget=budget,
                )
                budget.seal_boundary(boundary)
                canary = value._wait_for_fresh_webjob_success(
                    site_resource_id=SITE_ID, job_name=JOB_NAME, boundary=boundary,
                    trigger_requested_at=NOW, expected_trigger_sha256=expected,
                    deadline=NOW + dt.timedelta(seconds=300), detail_budget=budget,
                )
                final = value._read_final_webjob_history(
                    site_resource_id=SITE_ID, job_name=JOB_NAME, canary=canary,
                    deadline=NOW + dt.timedelta(seconds=180), detail_budget=budget,
                )
                self.assertEqual(len(final["entries"]), old_count + 1)
                self.assertEqual(len(reads), 3 + old_count + 2*(old_count + 1))
                self.assertEqual(budget._remaining, 728 - old_count - 2*(old_count + 1))
                for entry in old:
                    self.assertEqual(sum(
                        url.split("?", 1)[0].endswith("/" + entry["web_job_id"])
                        for url, _ in reads
                    ), 3)
                before = len(reads)
                with self.assertRaises(bootstrap.BootstrapError):
                    value._read_final_webjob_history(
                        site_resource_id=SITE_ID, job_name=JOB_NAME, canary=canary,
                        deadline=NOW + dt.timedelta(seconds=180), detail_budget=budget,
                    )
                self.assertEqual(len(reads), before)

    def test_full_boundary_universe_reserves_headroom_even_when_list_is_complete(self):
        old = [run(f"old-{index}", offset=-index*2-20) for index in range(364)]
        value, reads = self.history_transport([(old, False)])
        budget = self.budget()
        boundary = self.read(value, budget)
        self.assertEqual(len(reads), 1)
        with self.assertRaisesRegex(bootstrap.BootstrapError, "pre-trigger census headroom"):
            budget.seal_boundary(boundary)
        self.assertEqual(budget._remaining, 728)

    def test_oversized_census_is_rejected_before_any_detail_transport(self):
        old = [run(f"old-{index}", offset=-index*2-20) for index in range(729)]
        value, reads = self.history_transport([(old, True)])
        with self.assertRaisesRegex(bootstrap.BootstrapError, "shared detail read budget"):
            self.read(value, self.budget())
        self.assertEqual(len(reads), 1)

    def test_terminal_polls_cannot_spend_the_final_reserved_census(self):
        old = [run(f"old-{index}", offset=-20-index*2) for index in range(4)]
        fresh = run("fresh", offset=-1)
        value, reads = self.history_transport(
            [(old, True)] + [(old + [fresh], True)] * 145
        )
        budget = self.budget()
        boundary = self.read(value, budget)
        budget.seal_boundary(boundary)
        for _ in range(143):
            self.read(value, budget, "terminal-history")
        self.assertEqual(budget._remaining, 9)
        before = len(reads)
        with self.assertRaisesRegex(bootstrap.BootstrapError, "shared detail read budget"):
            self.read(value, budget, "terminal-history")
        self.assertEqual(len(reads), before + 1)
        final = self.read(value, budget, "final-history-census")
        self.assertEqual(len(final["entries"]), 5)
        self.assertEqual(budget._remaining, 4)

    def test_foreign_targets_wrong_phases_and_unsealed_poll_fail_before_collection(self):
        for kwargs in (
            {"site_resource_id": SITE_ID + "-other", "failure_context": "history-boundary"},
            {"job_name": "other", "failure_context": "history-boundary"},
            {"failure_context": "terminal-history"},
            {"failure_context": "final-history-census"},
            {"failure_context": None},
        ):
            value = transport()
            value._read_request_with_transport_retry = mock.Mock()
            args = {"site_resource_id": SITE_ID, "job_name": JOB_NAME,
                    "failure_context": "history-boundary", **kwargs}
            with self.subTest(kwargs=kwargs), self.assertRaises(bootstrap.BootstrapError):
                value._read_webjob_history(
                    **args, deadline=NOW + dt.timedelta(seconds=300), detail_budget=self.budget(),
                )
            value._read_request_with_transport_retry.assert_not_called()

    def test_empty_pristine_and_throttled_boundary_do_not_consume_detail_credits(self):
        budget = self.budget()
        value = transport()
        value.sleep = mock.Mock()
        value._read_request_with_transport_retry = mock.Mock(side_effect=[
            bootstrap._RestResponse(429, b"", {"Retry-After": "1"}),
            bootstrap._RestResponse(404, b"", {}),
        ])
        args = {"site_resource_id": SITE_ID, "job_name": JOB_NAME,
                "deadline": NOW + dt.timedelta(seconds=300),
                "failure_context": "history-boundary", "detail_budget": budget,
                "allow_pristine_absence": True, "allow_transient_rate_limit": True}
        self.assertIsNone(value._read_webjob_history(**args))
        boundary = value._read_webjob_history(**args)
        budget.seal_boundary(boundary)
        self.assertEqual(budget._remaining, 728)
        self.assertEqual(budget._final_reserve, 1)
        with self.assertRaises(bootstrap.BootstrapError):
            budget.seal_boundary(boundary)
        with self.assertRaises(bootstrap.BootstrapError):
            value._read_webjob_history(**args)
        self.assertEqual(value._read_request_with_transport_retry.call_count, 2)

    def test_detail_timeout_and_malformed_response_never_refund_or_reset(self):
        body = {"value": [{"id": COLLECTION_ID + "/one", "properties": {}}]}
        for outcome in (
            bootstrap._RestTotalTimeout("synthetic timeout"),
            bootstrap._RestResponse(200, b"{}\n", {}),
        ):
            value = transport()
            value._read_request_with_transport_retry = mock.Mock(side_effect=[
                bootstrap._RestResponse(200, bootstrap.canonical_json_bytes(body), {}), outcome,
            ])
            budget = self.budget()
            with self.subTest(outcome=type(outcome).__name__), self.assertRaises(bootstrap.BootstrapError):
                self.read(value, budget)
            self.assertEqual(budget._remaining, 727)
            with self.assertRaises(bootstrap.BootstrapError):
                self.read(value, budget)
            self.assertEqual(value._read_request_with_transport_retry.call_count, 2)

    def test_budget_does_not_relax_old_history_drift_or_ambiguous_fresh_runs(self):
        old = [run(f"old-{index}", offset=-20-index*2) for index in range(5)]
        fresh = run("fresh", offset=-1)
        changed = copy.deepcopy(old)
        changed[0]["trigger"] = "External - changed"
        for terminal in (changed + [fresh], old + [fresh, run("extra", offset=-1)], old[1:] + [fresh]):
            value, _ = self.history_transport([(old, True), (terminal, True)])
            budget = self.budget()
            boundary = self.read(value, budget)
            budget.seal_boundary(boundary)
            with self.subTest(terminal_count=len(terminal)), self.assertRaises(bootstrap.BootstrapError):
                value._wait_for_fresh_webjob_success(
                    site_resource_id=SITE_ID, job_name=JOB_NAME, boundary=boundary,
                    trigger_requested_at=NOW,
                    expected_trigger_sha256=bootstrap.sha256_bytes(fresh["trigger"].encode()),
                    deadline=NOW + dt.timedelta(seconds=300), detail_budget=budget,
                )


if __name__ == "__main__":
    unittest.main()
