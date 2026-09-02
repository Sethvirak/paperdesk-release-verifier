"""Real bootstrap upload transport with isolated, deterministic HTTP responses."""

import copy
import datetime as dt
from pathlib import Path
import traceback
import unittest
from unittest import mock

from scripts import private_release_v2_bootstrap as bootstrap


NOW = dt.datetime(2026, 9, 2, tzinfo=dt.timezone.utc)
SOURCE = "2" * 40
OPERATION = "uploadVersionedBridgePackage"
SECRET = "Bearer package-private-token 203.0.113.41 package-raw-secret"


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

    @staticmethod
    def private_error(status=403, code="AuthorizationPermissionMismatch", *, headers=None):
        return bootstrap._RestResponse(
            status,
            f"<Error><Code>{code}</Code><Message>{SECRET}</Message></Error>".encode(),
            headers or {"Content-Type": "application/xml"},
        )

    def assert_package_diagnostic(self, error, *, attempts, status, code, elapsed,
                                  reason, request_id=None, server_date=None,
                                  credential=None, role_readback=None):
        self.assertEqual(type(error).__name__, "PackageReadinessError")
        self.assertEqual(error.diagnostic, {
            "stage": "package-upload-readiness", "elapsedSeconds": elapsed,
            "attempts": attempts, "status": status, "errorCode": code,
            "stopReason": reason, "requestId": request_id, "serverDate": server_date,
            "credential": credential, "roleReadback": role_readback,
        })
        rendered = str(error) + "".join(traceback.format_exception(error))
        for field in ("stage=", "elapsedSeconds=", "attempts=", "status=", "errorCode=",
                      "stopReason=", "requestId=", "serverDate="):
            self.assertIn(field, str(error))
        for secret in (SECRET, "package-private-token", "203.0.113.41", "package-raw-secret", "<Error>", "https://"):
            self.assertNotIn(secret, rendered)

    def test_timeout_diagnostic_preserves_last_denial_and_clips_exact_deadline(self):
        for deadline in (37, 600):
            for code in ("AuthorizationFailure", "AuthorizationPermissionMismatch"):
                with self.subTest(deadline=deadline, code=code):
                    self.current = NOW
                    self.sleeps = []
                    self.authorization["validity"]["expiresAt"] = stamp(NOW + dt.timedelta(seconds=deadline))
                    transport, session, journal = self.transport([self.private_error(code=code)], repeat=True)
                    with self.assertRaises(bootstrap.BootstrapError) as error:
                        transport._prove_package_upload_ready(self.url)
                    self.assert_package_diagnostic(error.exception, attempts=len(session.requests),
                        status=403, code=code, elapsed=deadline, reason="deadline")
                    self.assertEqual((self.current - NOW).total_seconds(), deadline)
                    self.assertLessEqual(len(session.requests), 64)
                    self.assertEqual(self.sleeps[:5], [1, 2, 4, 8, 15])
                    self.assertTrue(all(0 < seconds <= 15 for seconds in self.sleeps))
                    self.assertTrue(all(method == "GET" and url == self.url and body is None
                                        for method, url, body, _ in session.requests))
                    self.assertEqual(journal.records, [])

    def test_frozen_clock_stops_at_64_gets_with_safe_final_diagnostic(self):
        transport, session, journal = self.transport([self.private_error()], repeat=True)
        transport.sleep = self.sleeps.append
        with self.assertRaises(bootstrap.BootstrapError) as error:
            transport._prove_package_upload_ready(self.url)
        self.assert_package_diagnostic(error.exception, attempts=64, status=403,
            code="AuthorizationPermissionMismatch", elapsed=0, reason="attempt-limit")
        self.assertEqual(len(session.requests), 64)
        self.assertEqual(len(self.sleeps), 63)
        self.assertTrue(all(0 < seconds <= 15 for seconds in self.sleeps))
        self.assertTrue(all(item[0] == "GET" and item[1] == self.url for item in session.requests))
        self.assertEqual(journal.records, [])

    def test_wrong_target_has_safe_zero_attempt_diagnostic_without_http(self):
        for target in (self.url + "?versionid=package-private-token",
                       self.url.replace(SOURCE, "3" * 40),
                       "https://example.invalid/package-private-token"):
            with self.subTest(target=target):
                transport, session, journal = self.transport([])
                with self.assertRaises(bootstrap.BootstrapError) as error:
                    transport._prove_package_upload_ready(target)
                self.assert_package_diagnostic(error.exception, attempts=0,
                    status=None, code="unknown", elapsed=0, reason="invalid-target")
                self.assertEqual(session.requests, [])
                self.assertEqual(journal.records, [])

    def test_untrusted_response_diagnostics_fail_closed_without_leaking(self):
        variants = [
            (self.private_error(code="AuthenticationFailed"), "AuthenticationFailed", "unsupported-denial"),
            (self.private_error(code="ContainerNotFound"), "ContainerNotFound", "unsupported-denial"),
            (self.private_error(status=404, code="ContainerNotFound"), "ContainerNotFound", "unexpected-absence-code"),
            (self.private_error(code="BlobNotFound"), "BlobNotFound", "unsupported-denial"),
            (self.private_error(status=404), "AuthorizationPermissionMismatch", "unexpected-absence-code"),
            (self.private_error(code=SECRET), "unknown", "unsupported-denial"),
            (self.private_error(headers={"Content-Type": "application/xml",
                "x-ms-error-code": "AuthorizationFailure"}), "unknown", "error-code-mismatch"),
            (self.private_error(status=404, code="BlobNotFound", headers={"Content-Type": "application/xml",
                "x-ms-error-code": SECRET}), "unknown", "error-code-mismatch"),
            (self.private_error(headers={"Content-Type": "application/json"}), "unknown", "unsafe-xml"),
            (bootstrap._RestResponse(403, SECRET.encode(), {"Content-Type": "application/xml"}), "unknown", "malformed-xml"),
            (bootstrap._RestResponse(403, b"<Error><Code>AuthorizationFailure</Code><Code>AuthorizationFailure</Code></Error>",
                {"Content-Type": "application/xml"}), "unknown", "invalid-error-shape"),
            (bootstrap._RestResponse(403, b"<!DOCTYPE Error><Error><Code>AuthorizationFailure</Code></Error>",
                {"Content-Type": "application/xml"}), "unknown", "unsafe-xml"),
            (bootstrap._RestResponse(403, b"x" * 65537, {"Content-Type": "application/xml"}), "unknown", "unsafe-xml"),
            (bootstrap._RestResponse(200, SECRET.encode(), {}), "unknown", "unsupported-status"),
            (self.private_error(status=401), "unknown", "unsupported-status"),
            (self.private_error(status=429), "unknown", "unsupported-status"),
            (self.private_error(status=500), "unknown", "unsupported-status"),
        ]
        for index, (response, code, reason) in enumerate(variants):
            with self.subTest(index=index, status=response.status):
                transport, session, journal = self.transport([response])
                with self.assertRaises(bootstrap.BootstrapError) as error:
                    transport._prove_package_upload_ready(self.url)
                self.assert_package_diagnostic(error.exception, attempts=1,
                    status=response.status, code=code, elapsed=0, reason=reason)
                self.assertEqual(len(session.requests), 1)
                self.assertEqual(session.requests[0][:3], ("GET", self.url, None))
                self.assertEqual(self.sleeps, [])
                self.assertEqual(journal.records, [])

    def test_ambiguous_get_retains_last_safe_observation_without_retry(self):
        for previous in (False, True):
            with self.subTest(previous=previous):
                self.current = NOW
                self.sleeps = []
                responses = [self.private_error(code="AuthorizationFailure")] if previous else []
                responses.append(RuntimeError(SECRET))
                transport, session, journal = self.transport(responses)
                with self.assertRaises(bootstrap.BootstrapError) as error:
                    transport._prove_package_upload_ready(self.url)
                self.assert_package_diagnostic(error.exception, attempts=2 if previous else 1,
                    status=403 if previous else None,
                    code="AuthorizationFailure" if previous else "unknown", elapsed=1 if previous else 0,
                    reason="transport-error")
                self.assertEqual(len(session.requests), 2 if previous else 1)
                self.assertEqual(self.sleeps, [1] if previous else [])
                self.assertEqual(journal.records, [])

    def test_late_blob_not_found_retains_status_but_cannot_admit_put(self):
        def expire():
            self.current = NOW + dt.timedelta(seconds=600)

        transport, session, journal = self.transport(
            [storage_error(404, "BlobNotFound")], after_request=expire)
        with self.assertRaises(bootstrap.BootstrapError) as error:
            self.upload(transport)
        self.assert_package_diagnostic(error.exception, attempts=1,
            status=404, code="unknown", elapsed=600, reason="expired-during-get")
        self.assertEqual([item[0] for item in session.requests], ["GET"])
        self.assertEqual(journal.records, [])

    def test_delayed_exact_absence_admits_one_create_only_put(self):
        responses = [self.private_error()] * 13 + [storage_error(404, "BlobNotFound"), self.created()]
        transport, session, journal = self.transport(responses)
        result = self.upload(transport)
        self.assertGreater((self.current - NOW).total_seconds(), 120)
        self.assertLess((self.current - NOW).total_seconds(), 600)
        self.assertEqual([item[0] for item in session.requests], ["GET"] * 14 + ["PUT"])
        self.assertTrue(all(item[1] == self.url for item in session.requests))
        self.assertEqual(session.requests[-1][3]["If-None-Match"], "*")
        self.assertEqual(len(journal.records), 2)
        self.assertEqual(result["versionId"], "version-1")

    def test_failed_put_is_not_reclassified_as_retryable_readiness(self):
        for failure in (self.private_error(), bootstrap.BootstrapError("PUT transport failed closed")):
            with self.subTest(failure=type(failure).__name__):
                transport, session, journal = self.transport([storage_error(404, "BlobNotFound"), failure])
                with self.assertRaises(bootstrap.BootstrapError) as error:
                    self.upload(transport)
                self.assertNotEqual(type(error.exception).__name__, "PackageReadinessError")
                self.assertFalse(hasattr(error.exception, "diagnostic"))
                self.assertEqual([item[0] for item in session.requests], ["GET", "PUT"])
                self.assertEqual(len(journal.records), 1 if isinstance(failure, BaseException) else 2)

    def test_valid_request_headers_persist_from_last_response_through_transport_failure(self):
        request_id = "ABCDEF12-3456-0789-ABCD-123456789ABC"
        server_date = "Wed, 02 Sep 2026 00:00:00 GMT"
        response = self.private_error(code="AuthorizationFailure", headers={
            "Content-Type": "application/xml", "X-Ms-Error-Code": "AuthorizationFailure",
            "X-Ms-Request-Id": request_id, "Date": server_date,
        })
        transport, session, journal = self.transport([response, RuntimeError(SECRET)])
        with self.assertRaises(bootstrap.BootstrapError) as error:
            transport._prove_package_upload_ready(self.url)
        self.assert_package_diagnostic(error.exception, attempts=2, status=403,
            code="AuthorizationFailure", elapsed=1, reason="transport-error",
            request_id=request_id, server_date=server_date)
        self.assertEqual([item[0] for item in session.requests], ["GET", "GET"])
        self.assertEqual(self.sleeps, [1])
        self.assertEqual(journal.records, [])

    def test_hostile_or_noncanonical_request_headers_are_dropped(self):
        headers = [
            (SECRET, SECRET),
            ("00000000-0000-0000-0000-000000000000\r\n" + SECRET,
             "Wed, 02 Sep 2026 00:00:00 GMT\r\n" + SECRET),
            ("00000000000000000000000000000000", "Wed, 2 Sep 2026 00:00:00 GMT"),
            ("00000000-0000-0000-0000-00000000000g", "Thu, 02 Sep 2026 00:00:00 GMT"),
        ]
        for request_id, server_date in headers:
            with self.subTest(request_id=request_id):
                transport, session, journal = self.transport([self.private_error(
                    code="AuthenticationFailed", headers={
                        "Content-Type": "application/xml", "x-ms-error-code": "AuthenticationFailed",
                        "x-ms-request-id": request_id, "date": server_date,
                    })])
                with self.assertRaises(bootstrap.BootstrapError) as error:
                    transport._prove_package_upload_ready(self.url)
                self.assert_package_diagnostic(error.exception, attempts=1, status=403,
                    code="AuthenticationFailed", elapsed=0, reason="unsupported-denial")
                self.assertEqual([item[0] for item in session.requests], ["GET"])
                self.assertEqual(self.sleeps, [])
                self.assertEqual(journal.records, [])

    def test_credential_snapshot_stays_paired_with_last_observed_response(self):
        observed = {
            "source": "azure-cli-request", "tokenIssuedAtUnix": int(NOW.timestamp()) - 60,
            "tokenExpiresAtUnix": int(NOW.timestamp()) + 3600,
            "tokenObservedAtUnix": int(NOW.timestamp()), "accountBindingVerified": True,
        }
        response = self.private_error(headers={
            "Content-Type": "application/xml", "x-ms-request-id": "12345678-1234-0123-ABCD-123456789ABC",
        })
        transport, session, journal = self.transport([response, RuntimeError(SECRET)])
        snapshots = iter([observed, {"source": "process-cache"}])
        session.storage_credential_diagnostic = lambda: next(snapshots)
        with self.assertRaises(bootstrap.PackageReadinessError) as error:
            transport._prove_package_upload_ready(self.url)
        self.assert_package_diagnostic(error.exception, attempts=2, status=403,
            code="AuthorizationPermissionMismatch", elapsed=1, reason="transport-error",
            request_id="12345678-1234-0123-ABCD-123456789ABC", credential=observed)
        self.assertEqual(next(snapshots), {"source": "process-cache"})
        self.assertEqual(len(session.requests), 2)
        self.assertEqual(journal.records, [])

    def test_package_role_diagnostics_hash_only_validated_observed_projections(self):
        transport, session, journal = self.transport([self.private_error(code="AuthenticationFailed")])
        definition, assignment = {"permissions": ["read"]}, {"scope": "exact"}
        transport._validated_source_projections["addOwnedUploaderPackageRole"] = {
            "family": "temporary-role-projection",
            "projection": {"definition": definition, "assignment": assignment},
        }
        expected = {
            "definitionSha256": bootstrap.sha256_bytes(bootstrap.canonical_json_bytes(definition)),
            "assignmentSha256": bootstrap.sha256_bytes(bootstrap.canonical_json_bytes(assignment)),
        }
        with self.assertRaises(bootstrap.PackageReadinessError) as error:
            transport._prove_package_upload_ready(self.url)
        self.assert_package_diagnostic(error.exception, attempts=1, status=403,
            code="AuthenticationFailed", elapsed=0, reason="unsupported-denial", role_readback=expected)
        self.assertEqual(len(session.requests), 1)
        self.assertEqual(journal.records, [])


if __name__ == "__main__":
    unittest.main()
