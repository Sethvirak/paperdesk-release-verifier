"""Real bootstrap upload transport with isolated, deterministic HTTP responses."""

import copy
import datetime as dt
from pathlib import Path
import unittest
from unittest import mock

from scripts import private_release_v2_bootstrap as bootstrap


NOW = dt.datetime(2026, 9, 2, tzinfo=dt.timezone.utc)
SOURCE = "2" * 40
OPERATION = "uploadVersionedBridgePackage"


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def storage_error(status, code):
    return bootstrap._RestResponse(
        status,
        f"<Error><Code>{code}</Code><Message>bounded fixture</Message></Error>".encode(),
        {"Content-Type": "application/xml"},
    )


class Session:
    def __init__(self, responses, *, repeat=False, after_request=None):
        self.responses = list(responses)
        self.repeat = repeat
        self.after_request = after_request
        self.requests = []

    def request(self, method, url, *, body=None, headers=None):
        self.requests.append((method, url, body, headers))
        if self.after_request:
            self.after_request()
        response = self.responses[0] if self.repeat else self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class MemoryJournal:
    """Keep real mutation intent/result calls observable without disk receipts."""

    def __init__(self):
        self.records = []

    def append_cloud_mutation(self, value):
        self.records.append(copy.deepcopy(value))
        return Path(f"cloud-mutation-{len(self.records):04d}.json")


class PackageReadinessTests(unittest.TestCase):
    def setUp(self):
        self.plan, self.plan_sha = bootstrap.load_plan()
        self.operation = next(item for item in self.plan["mutations"] if item["id"] == OPERATION)
        self.body = b"exact authorized package fixture"
        self.package = {"sha256": bootstrap.sha256_bytes(self.body), "size": len(self.body)}
        self.current = NOW
        self.sleeps = []
        self.authorization = {
            "source": {"mergedMain": {"commitSha": SOURCE}},
            "plan": {"sha256": self.plan_sha},
            "validity": {
                "notBefore": stamp(NOW - dt.timedelta(seconds=1)),
                "expiresAt": stamp(NOW + dt.timedelta(minutes=30)),
            },
        }
        self.url = bootstrap._operation_readback_url(OPERATION, self.plan, self.authorization)

    def transport(self, responses, **session_options):
        session = Session(responses, **session_options)

        def sleep(seconds):
            self.sleeps.append(seconds)
            self.current += dt.timedelta(seconds=seconds)

        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=self.authorization,
            plan=self.plan,
            package=self.package,
            preflight={"projection": {
                "operationAdmissions": [{
                    "operationId": OPERATION,
                    "context": {"executionDecision": "apply-exact"},
                }],
                "postconditionAdmissions": [],
                "probes": [],
                "productionBoundaryObservation": {},
            }},
            session=session,
            clock=lambda: self.current,
            sleep=sleep,
        )
        transport._active_operation_id = OPERATION
        journal = MemoryJournal()
        transport.bind_journal(journal)
        return transport, session, journal

    def upload(self, transport):
        def build(path):
            path.write_bytes(self.body)

        with mock.patch.object(bootstrap.package_builder, "build", side_effect=build):
            return transport._mutate(self.operation, {})

    @staticmethod
    def created():
        return bootstrap._RestResponse(201, b"", {"ETag": '"exact"', "x-ms-version-id": "version-1"})

    def test_recognized_denial_converges_to_absence_before_exactly_one_put(self):
        for code in ("AuthorizationFailure", "AuthorizationPermissionMismatch"):
            with self.subTest(code=code):
                transport, session, journal = self.transport([
                    storage_error(403, code), storage_error(404, "BlobNotFound"), self.created(),
                ])
                result = self.upload(transport)
                self.assertEqual([item[0] for item in session.requests], ["GET", "GET", "PUT"])
                self.assertTrue(all(item[1] == self.url for item in session.requests))
                self.assertTrue(all(item[2] is None for item in session.requests[:-1]))
                self.assertEqual(session.requests[-1][2], self.body)
                self.assertEqual(session.requests[-1][3]["If-None-Match"], "*")
                self.assertEqual(session.requests[-1][3]["x-ms-version"], "2023-11-03")
                self.assertEqual([item["phase"] for item in journal.records], ["intent", "result"])
                self.assertEqual(journal.records[-1]["status"], 201)
                self.assertEqual(result["versionId"], "version-1")

    def test_immediate_exact_blob_not_found_permits_one_put(self):
        transport, session, journal = self.transport([storage_error(404, "BlobNotFound"), self.created()])
        self.upload(transport)
        self.assertEqual([item[0] for item in session.requests], ["GET", "PUT"])
        self.assertEqual(len(journal.records), 2)
        self.assertEqual(self.sleeps, [])

    def test_invalid_error_status_or_shape_never_reaches_put(self):
        cases = [
            storage_error(403, "AuthenticationFailed"),
            storage_error(403, "BlobNotFound"),
            storage_error(404, "AuthorizationPermissionMismatch"),
            storage_error(403, "UnexpectedError"),
            bootstrap._RestResponse(200, self.body, {}),
            bootstrap._RestResponse(401, b"", {}),
            bootstrap._RestResponse(429, b"", {}),
            bootstrap._RestResponse(500, b"", {}),
            bootstrap._RestResponse(404, b"", {}),
            bootstrap._RestResponse(404, b"<Error><Code>BlobNotFound</Code>", {"content-type": "application/xml"}),
            bootstrap._RestResponse(404, b"<Error><Code>BlobNotFound</Code><Code>BlobNotFound</Code></Error>", {"content-type": "application/xml"}),
            bootstrap._RestResponse(404, b"<Other><Code>BlobNotFound</Code></Other>", {"content-type": "application/xml"}),
            bootstrap._RestResponse(404, b"<Error><Nested><Code>BlobNotFound</Code></Nested></Error>", {"content-type": "application/xml"}),
            bootstrap._RestResponse(404, b"<Error><Code>BlobNotFound</Code></Error>", {"content-type": "application/json"}),
            bootstrap._RestResponse(404, b"<Error><Code>BlobNotFound</Code></Error>", {"content-type": "application/xml", "x-ms-error-code": "AuthorizationFailure"}),
            bootstrap._RestResponse(404, b"<!DOCTYPE Error><Error><Code>BlobNotFound</Code></Error>", {"content-type": "application/xml"}),
            bootstrap._RestResponse(404, b"x" * 65537, {"content-type": "application/xml"}),
        ]
        for response in cases:
            with self.subTest(status=response.status, body=response.body[:70]):
                transport, session, journal = self.transport([response])
                with self.assertRaises(bootstrap.BootstrapError):
                    self.upload(transport)
                self.assertEqual([item[0] for item in session.requests], ["GET"])
                self.assertEqual(journal.records, [])

    def test_helper_rejects_non_source_target_before_request(self):
        for url in (self.url + "?versionid=other", self.url.replace(SOURCE, "3" * 40), self.url.replace("https://", "http://")):
            with self.subTest(url=url):
                transport, session, journal = self.transport([])
                with self.assertRaisesRegex(bootstrap.BootstrapError, "exact source-derived"):
                    transport._prove_package_upload_ready(url)
                self.assertEqual(session.requests, [])
                self.assertEqual(journal.records, [])

    def test_authorization_window_blocks_reads_before_start_and_at_expiry(self):
        for current in (NOW - dt.timedelta(seconds=2), NOW + dt.timedelta(minutes=30)):
            with self.subTest(current=current):
                self.current = current
                transport, session, journal = self.transport([])
                with self.assertRaisesRegex(bootstrap.BootstrapError, "window expired"):
                    self.upload(transport)
                self.assertEqual(session.requests, [])
                self.assertEqual(journal.records, [])

    def test_get_completing_at_deadline_cannot_authorize_put(self):
        def expire():
            self.current = NOW + dt.timedelta(minutes=30)

        transport, session, journal = self.transport([storage_error(404, "BlobNotFound")], after_request=expire)
        with self.assertRaisesRegex(bootstrap.BootstrapError, "window expired during GET"):
            self.upload(transport)
        self.assertEqual([item[0] for item in session.requests], ["GET"])
        self.assertEqual(journal.records, [])

    def test_authorization_expiry_and_600_second_cap_bound_only_gets(self):
        self.assertEqual(bootstrap.MAX_STORAGE_DATA_PLANE_READINESS_SECONDS, 600)
        for expiry_seconds in (3, 1800):
            with self.subTest(expiry_seconds=expiry_seconds):
                self.current = NOW
                self.authorization["validity"]["expiresAt"] = stamp(NOW + dt.timedelta(seconds=expiry_seconds))
                transport, session, journal = self.transport([storage_error(403, "AuthorizationPermissionMismatch")], repeat=True)
                with self.assertRaisesRegex(bootstrap.BootstrapError, "deadline|window expired"):
                    self.upload(transport)
                self.assertLessEqual(len(session.requests), 64)
                self.assertTrue(all(item[0] == "GET" for item in session.requests))
                self.assertLessEqual((self.current - NOW).total_seconds(), min(expiry_seconds, 600))
                self.assertEqual(journal.records, [])

    def test_put_error_and_transport_ambiguity_are_never_replayed(self):
        for response in (
            storage_error(403, "AuthorizationPermissionMismatch"),
            bootstrap.BootstrapError("Azure REST transport failed closed"),
        ):
            with self.subTest(response=response):
                transport, session, journal = self.transport([storage_error(404, "BlobNotFound"), response])
                with self.assertRaises(bootstrap.BootstrapError):
                    self.upload(transport)
                self.assertEqual([item[0] for item in session.requests], ["GET", "PUT"])
                self.assertEqual(journal.records[0]["phase"], "intent")
                self.assertEqual(len(journal.records), 1 if isinstance(response, BaseException) else 2)

    def test_ambiguous_read_fails_without_mutation(self):
        transport, session, journal = self.transport([bootstrap.BootstrapError("Azure REST transport failed closed")])
        with self.assertRaisesRegex(bootstrap.BootstrapError, "transport failed closed"):
            self.upload(transport)
        self.assertEqual([item[0] for item in session.requests], ["GET"])
        self.assertEqual(journal.records, [])


if __name__ == "__main__":
    unittest.main()
