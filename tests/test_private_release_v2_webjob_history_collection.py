"""Live-shape regressions for the ARM triggered-WebJob history collection."""

import datetime as dt
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


if __name__ == "__main__":
    unittest.main()
