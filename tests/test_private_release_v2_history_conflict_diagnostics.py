"""Offline diagnostics for strict WebJob list/detail conflicts; never retry/admit."""

import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import private_release_v2_bootstrap as bootstrap
from scripts import private_release_v2_history_conflict_diagnostics as diagnostic
from tests import test_private_release_v2_bootstrap as fixtures
from tests import test_private_release_v2_webjob_history_collection as history
from tests.test_private_release_v2_package_readiness import MemoryJournal

SECRET = "sensitive-value-token-203.0.113.41-not-for-output"
START = "startBridgeForBoundedCanary"
CONFIGURE = "configureBridgeExactVersionedPackageAndCriticalSettings"


def response(value):
    return bootstrap._RestResponse(
        200, bootstrap.canonical_json_bytes(value), {"Content-Type": "application/json"},
    )


def pair(properties, *, flattened=False):
    child = history.COLLECTION_ID + "/run-1"
    detail = history.run("run-1")
    detail["job_name"] = history.JOB_NAME
    if flattened:
        detail.pop("web_job_name")
        detail.pop("web_job_id")
    return (
        response({"value": [{"id": child, "properties": properties}]}),
        response({"id": child, "properties": detail if flattened else {"runs": [detail]}}),
    )


def read_pair(properties, *, flattened=False, read_stage="terminal-history"):
    transport = history.transport()
    transport.sleep = mock.Mock(side_effect=AssertionError("no conflict retry"))
    responses = pair(properties, flattened=flattened)
    with mock.patch.object(transport, "_read_request_with_transport_retry",
                           side_effect=responses) as reads:
        try:
            result = transport._read_webjob_history(
                site_resource_id=history.SITE_ID, job_name=history.JOB_NAME,
                deadline=history.NOW + dt.timedelta(minutes=10),
                failure_context=read_stage,
            )
        except bootstrap.WebJobHistoryConflictError as error:
            return error, reads.call_args_list, responses
    return result, reads.call_args_list, responses


class HistoryConflictReaderTests(unittest.TestCase):
    def test_every_fixed_field_conflict_is_rejected_with_exact_one_bit_and_two_gets(self):
        for index, field in enumerate(diagnostic.FIELDS):
            for flattened in (False, True):
                with self.subTest(field=field, flattened=flattened):
                    error, reads, responses = read_pair({field: SECRET}, flattened=flattened)
                    self.assertIsInstance(error, bootstrap.WebJobHistoryConflictError)
                    self.assertNotIsInstance(error, bootstrap.WebJobCanaryFailure)
                    self.assertEqual(error.diagnostic["mismatchBits"],
                                     "0" * index + "1" + "0" * (7 - index))
                    self.assertEqual(error.diagnostic["fieldOrder"], list(diagnostic.FIELDS))
                    self.assertEqual(error.diagnostic["listResponseSha256"],
                                     bootstrap._response_sha256(responses[0]))
                    self.assertEqual(error.diagnostic["detailResponseSha256"],
                                     bootstrap._response_sha256(responses[1]))
                    self.assertEqual(len(reads), 2)
                    self.assertEqual([call.args[0] for call in reads], ["GET", "GET"])
                    self.assertEqual(reads[1].kwargs["retry_delays"], (None,))
                    self.assertEqual(reads[1].kwargs["deadline"], history.NOW + dt.timedelta(seconds=180))
                    raw = json.dumps(error.diagnostic)
                    self.assertNotIn(SECRET, raw + str(error))
                    self.assertNotIn(history.COLLECTION_ID, raw)
                    self.assertNotIn("run-1", raw)
                    self.assertNotIn("validatedWebJobFailure", raw)
                    self.assertLess(len(raw.encode()), 2048)

    def test_running_to_success_transition_is_still_conflict_without_poll_retry(self):
        properties = {"status": "Running", "end_time": None, "output_url": None}
        error, reads, _ = read_pair(properties)
        self.assertIsInstance(error, bootstrap.WebJobHistoryConflictError)
        self.assertEqual(error.diagnostic["mismatchBits"], "00010011")
        self.assertEqual(error.diagnostic["listValueClasses"][3], "nonterminal-status")
        self.assertEqual(error.diagnostic["detailValueClasses"][3], "success-status")
        self.assertEqual(len(reads), 2)

    def test_list_status_classes_never_claim_a_validated_terminal_outcome(self):
        for status, expected in (
            ("Initializing", "nonterminal-status"), ("Running", "nonterminal-status"),
            ("Failed", "failure-status"), ("Aborted", "failure-status"),
            (SECRET, "other-string"),
        ):
            with self.subTest(value_class=expected):
                error, reads, _ = read_pair({"status": status})
                self.assertIsInstance(error, bootstrap.WebJobHistoryConflictError)
                self.assertNotIsInstance(error, bootstrap.WebJobCanaryFailure)
                self.assertEqual(error.diagnostic["listValueClasses"][3], expected)
                self.assertEqual(error.diagnostic["mismatchBits"], "00010000")
                self.assertEqual(len(reads), 2)

    def test_duplicate_json_and_invalid_detail_still_fail_before_conflict_diagnostics(self):
        transport = history.transport()
        listed, detailed = pair({"trigger": SECRET})
        duplicate = bootstrap._RestResponse(
            200, b'{"value":[],"value":[]}', {"Content-Type": "application/json"},
        )
        invalid_detail = response({"id": history.COLLECTION_ID + "/wrong-id", "properties": {}})
        for responses in ((duplicate,), (listed, invalid_detail)):
            with self.subTest(count=len(responses)):
                with (mock.patch.object(transport, "_read_request_with_transport_retry",
                                        side_effect=responses) as reads,
                      self.assertRaises(bootstrap.BootstrapError) as raised):
                    transport._read_webjob_history(
                        site_resource_id=history.SITE_ID, job_name=history.JOB_NAME,
                        deadline=history.NOW + dt.timedelta(minutes=10),
                    )
                self.assertNotIsInstance(raised.exception, bootstrap.WebJobHistoryConflictError)
                self.assertIsNone(diagnostic.from_failure(raised.exception, bootstrap.WebJobHistoryConflictError))
                self.assertEqual(reads.call_count, len(responses))

    def test_sensitive_json_shapes_and_extra_properties_never_enter_retained_diagnostic(self):
        cases = (
            (None, "null"), (True, "boolean"), (7, "integer"), (1.5, "number"),
            (SECRET, "string"), ({SECRET: [SECRET]}, "object"), ([SECRET], "array"),
            (SECRET * 5000, "string"),
        )
        for value, expected in cases:
            with self.subTest(value_class=expected):
                error, reads, _ = read_pair({"trigger": value, SECRET: SECRET})
                self.assertIsInstance(error, bootstrap.WebJobHistoryConflictError)
                self.assertEqual(error.diagnostic["listValueClasses"][4], expected)
                self.assertEqual(error.diagnostic["mismatchBits"], "00001000")
                self.assertNotIn(SECRET, json.dumps(error.diagnostic) + str(error))
                self.assertEqual(len(reads), 2)

    def test_equal_missing_null_and_python_scalar_equality_preserve_old_predicate(self):
        # The original owner compares list-present values to detail.get(); absent
        # and None therefore remain equal. False/0 equality is also unchanged.
        for properties in ({}, {"unexpected": SECRET}, {"unused": None}):
            value, reads, _ = read_pair(properties)
            self.assertIsInstance(value, dict)
            self.assertEqual(len(value["entries"]), 1)
            self.assertEqual(len(reads), 2)
        details = {"status": "Success"}
        for listing in ({"job_name": None}, {"job_name": None, "unused": SECRET}):
            with self.assertRaises(ValueError):
                diagnostic.build(
                    list_properties=listing, detail_run=details,
                    list_response_sha256="a" * 64, detail_response_sha256="b" * 64,
                    history_id=history.COLLECTION_ID + "/run-1", run_id="run-1",
                    read_stage="terminal-history",
                )
        error, _, _ = read_pair({"status": "Success"})
        self.assertIsInstance(error, dict)
        # A mismatch elsewhere allows observing equality without admitting anything.
        built = diagnostic.build(
            list_properties={"trigger": SECRET, "job_name": None, "end_time": False},
            detail_run={"trigger": "different", "end_time": 0},
            list_response_sha256="a" * 64, detail_response_sha256="b" * 64,
            history_id=history.COLLECTION_ID + "/run-1", run_id="run-1", read_stage=None,
        )
        self.assertEqual(built["mismatchBits"], "00001000")
        self.assertEqual(built["readStage"], "unspecified")

    def test_identity_and_stage_hashes_bind_run_and_known_stage_without_raw_identity(self):
        error, _, _ = read_pair({"trigger": SECRET}, read_stage="history-boundary")
        built = error.diagnostic
        expected = bootstrap.sha256_bytes(bootstrap.canonical_json_bytes({
            "historyId": (history.COLLECTION_ID + "/run-1").lower(), "runId": "run-1",
        }))
        self.assertEqual(built["historyIdentitySha256"], expected)
        self.assertEqual(built["stageIdentitySha256"], bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes({"stage": diagnostic.STAGE,
                "readStage": "history-boundary", "historyIdentitySha256": expected})))
        other, _, _ = read_pair({"trigger": SECRET}, read_stage="final-history-census")
        self.assertEqual(other.diagnostic["historyIdentitySha256"], expected)
        self.assertNotEqual(other.diagnostic["stageIdentitySha256"], built["stageIdentitySha256"])
        unknown, _, _ = read_pair({"trigger": SECRET}, read_stage=SECRET)
        self.assertEqual(unknown.diagnostic["readStage"], "unspecified")


class HistoryDiagnosticSanitizerTests(unittest.TestCase):
    def setUp(self):
        self.valid = read_pair({"trigger": SECRET})[0].diagnostic

    def test_unknown_invalid_nonliteral_and_oversized_metadata_are_rejected(self):
        class PretendAllowed(str):
            def __new__(cls, allowed):
                item = super().__new__(cls, SECRET)
                item.allowed = allowed
                return item

            def __hash__(self):
                return hash(self.allowed)

            def __eq__(self, other):
                return other == self.allowed

        class MutableList(list):
            def __iter__(self):
                return iter([SECRET] * 8)

        class MutableDict(dict):
            def __getitem__(self, key):
                return SECRET if key == "readStage" else super().__getitem__(key)

        invalid = [None, [], {**self.valid, "headers": SECRET}, MutableDict(self.valid)]
        for name, values in {
            "schemaVersion": (True, 2), "stage": ([], SECRET),
            "readStage": ([], SECRET, PretendAllowed("terminal-history")),
            "fieldOrder": (None, list(reversed(diagnostic.FIELDS))),
            "mismatchBits": ("00000000", "1" * 9, [], SECRET),
            "listValueClasses": ([SECRET] * 8, [[]] * 8, ["string"] * 7,
                                 [PretendAllowed("string")] * 8, MutableList(["string"] * 8)),
            "detailValueClasses": ([SECRET] * 8,),
            "listResponseSha256": ("A" * 64, "a" * 63, [], PretendAllowed("a" * 64)),
            "detailResponseSha256": (SECRET,), "historyIdentitySha256": (SECRET,),
            "stageIdentitySha256": ("0" * 64,),
        }.items():
            for value in values:
                invalid.append({**self.valid, name: value})
        for value in invalid:
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaisesRegex(ValueError, "diagnostic is invalid"):
                    diagnostic.validate(value)
                with self.assertRaisesRegex(bootstrap.BootstrapError, "diagnostic is invalid"):
                    bootstrap.WebJobHistoryConflictError(value)
        copied = diagnostic.validate(self.valid)
        copied["listValueClasses"][0] = "other"
        self.assertNotEqual(copied, self.valid)

    def test_builder_rejects_bad_bindings_and_nonconflicts_without_raw_error_text(self):
        arguments = {
            "list_properties": {"trigger": SECRET}, "detail_run": {"trigger": "different"},
            "list_response_sha256": "a" * 64, "detail_response_sha256": "b" * 64,
            "history_id": history.COLLECTION_ID + "/run-1", "run_id": "run-1",
            "read_stage": "terminal-history",
        }
        for name, value in (
            ("history_id", "wrong-child"), ("history_id", SECRET * 2000),
            ("run_id", "wrong-run"), ("run_id", "../run-1"), ("run_id", []),
            ("list_response_sha256", SECRET), ("detail_response_sha256", "A" * 64),
            ("list_properties", {"trigger": "different"}), ("list_properties", []),
            ("detail_run", []),
        ):
            with self.subTest(field=name):
                with self.assertRaises(ValueError) as raised:
                    diagnostic.build(**{**arguments, name: value})
                self.assertEqual(str(raised.exception), "WebJob history conflict diagnostic is invalid")
                self.assertNotIn(SECRET, str(raised.exception))
        all_fields = diagnostic.build(**{**arguments,
            "list_properties": {field: SECRET for field in diagnostic.FIELDS},
            "detail_run": {field: None for field in diagnostic.FIELDS},
        })
        self.assertEqual(all_fields["mismatchBits"], "11111111")
        self.assertNotIn(SECRET, json.dumps(all_fields))

    def test_bounded_explicit_cause_walk_ignores_context_spoofing_cycles_and_malformed_error(self):
        error = bootstrap.WebJobHistoryConflictError(self.valid)
        wrapper = bootstrap.BootstrapError(SECRET)
        wrapper.__context__ = error
        wrapper.diagnostic = self.valid
        self.assertIsNone(diagnostic.from_failure(wrapper, bootstrap.WebJobHistoryConflictError))
        wrapper.__cause__ = error
        self.assertEqual(diagnostic.from_failure(wrapper, bootstrap.WebJobHistoryConflictError), self.valid)
        error.diagnostic = {**self.valid, "secret": SECRET}
        self.assertIsNone(diagnostic.from_failure(wrapper, bootstrap.WebJobHistoryConflictError))
        wrapper.__cause__ = wrapper
        self.assertIsNone(diagnostic.from_failure(wrapper, bootstrap.WebJobHistoryConflictError))
        error = bootstrap.WebJobHistoryConflictError(self.valid)
        chain = error
        for _ in range(7):
            wrapper = bootstrap.BootstrapError(SECRET)
            wrapper.__cause__ = chain
            chain = wrapper
        self.assertEqual(diagnostic.from_failure(chain, bootstrap.WebJobHistoryConflictError), self.valid)
        outer = bootstrap.BootstrapError(SECRET)
        outer.__cause__ = chain
        self.assertIsNone(diagnostic.from_failure(outer, bootstrap.WebJobHistoryConflictError))


class HistoryConflictCanaryAndReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.plan_sha = bootstrap.load_plan()
        cls.package = bootstrap.build_package_descriptor()

    source = staticmethod(fixtures.BootstrapTests.source)
    fixture = fixtures.BootstrapTests.fixture
    executor = fixtures.BootstrapTests.executor

    def real_canary_error(self, authorization, *, cleanup_fails=False):
        transport = object.__new__(bootstrap.AzureCliBootstrapTransport)
        transport.authorization = authorization
        transport.plan = self.plan
        transport.package = self.package
        transport.resources = {item["id"]: item for item in self.plan["resourceInventory"]}
        transport.admissions = {START: {"context": {"executionDecision": "apply-exact"}}}
        transport._active_operation_id = START
        transport._ledger = MemoryJournal()
        transport.clock = lambda: fixtures.NOW
        transport.sleep = mock.Mock(side_effect=AssertionError("no conflict retry"))
        state = {"proofs": {CONFIGURE: {"details": {
            "bootstrapSelfTestIssuedAt": fixtures.stamp(fixtures.NOW),
            "bootstrapSelfTestExpiresAt": fixtures.stamp(fixtures.NOW + dt.timedelta(seconds=900)),
        }}}}
        posture = {"state": "Stopped", "publicNetworkAccess": "Disabled", "allow": False}
        mutations = []
        responses = pair({"status": "Running", "trigger": SECRET})

        def mutate(method, url, *, body=None, cleanup=False, **_kwargs):
            path = url.split("?", 1)[0]
            mutations.append((method, path.rsplit("/", 1)[-1], cleanup))
            if method == "PATCH":
                posture["publicNetworkAccess"] = json.loads(body)["properties"]["publicNetworkAccess"]
            elif method == "PUT":
                posture["allow"] = json.loads(body)["properties"]["allow"]
            elif path.endswith("/start"):
                posture["state"] = "Running"
            elif path.endswith("/stop"):
                if cleanup and cleanup_fails:
                    raise bootstrap.BootstrapError("synthetic cleanup failure")
                posture["state"] = "Stopped"
            return bootstrap._RestResponse(200 if path.endswith("/run") else 202, b"", {})

        def site_state(*, expected_state, **_kwargs):
            if posture["state"] != expected_state:
                raise bootstrap.BootstrapError("synthetic state mismatch")
            return {"state": posture["state"], "observedAt": fixtures.stamp(fixtures.NOW)}

        def scm(*, expected_allow, **_kwargs):
            if expected_allow is not None and posture["allow"] != expected_allow:
                raise bootstrap.BootstrapError("synthetic SCM mismatch")
            return {"allow": posture["allow"]}

        def network(*, expected_access, expected_state, **_kwargs):
            if expected_access is not None and posture["publicNetworkAccess"] != expected_access:
                raise bootstrap.BootstrapError("synthetic network mismatch")
            if expected_state is not None and posture["state"] != expected_state:
                raise bootstrap.BootstrapError("synthetic network state mismatch")
            return {"publicNetworkAccess": posture["publicNetworkAccess"], "state": posture["state"]}

        def fresh_history(**kwargs):
            return transport._read_webjob_history(
                site_resource_id=history.SITE_ID, job_name=history.JOB_NAME,
                deadline=kwargs["deadline"], failure_context="terminal-history",
            )

        operation = next(item for item in self.plan["mutations"] if item["id"] == START)
        with (mock.patch.object(transport, "_mutation_request", side_effect=mutate),
              mock.patch.object(transport, "_await_arm_async_operation", return_value={}),
              mock.patch.object(transport, "_wait_for_site_state", side_effect=site_state),
              mock.patch.object(transport, "_read_scm_basic_auth_policy", side_effect=scm),
              mock.patch.object(transport, "_read_site_public_network_access", side_effect=network),
              mock.patch.object(transport, "_wait_for_webjob_history_boundary", return_value={}),
              mock.patch.object(transport, "_wait_for_fresh_webjob_success", side_effect=fresh_history),
              mock.patch.object(transport, "_read_request_with_transport_retry", side_effect=responses) as reads,
              mock.patch.object(transport, "_probe_failed_webjob_log") as log_probe,
              self.assertRaises(bootstrap.BootstrapError) as raised):
            transport._mutate(operation, state)
        log_probe.assert_not_called()
        self.assertEqual(len(reads.call_args_list), 2, str(raised.exception))
        self.assertEqual(sum(path == "run" for _, path, _ in mutations), 1)
        self.assertEqual(sum(path == "start" for _, path, _ in mutations), 1)
        self.assertEqual(sum(method == "PATCH" for method, _, _ in mutations), 2)
        self.assertEqual(sum(method == "PUT" for method, _, _ in mutations), 2)
        self.assertEqual(posture["publicNetworkAccess"], "Disabled")
        self.assertFalse(posture["allow"])
        if not cleanup_fails:
            self.assertEqual(posture["state"], "Stopped")
            self.assertEqual(transport._ledger.unresolved_public_network_incidents, [])
        else:
            self.assertNotEqual(transport._ledger.unresolved_public_network_incidents, [])
        self.assertNotIsInstance(raised.exception, bootstrap.WebJobCanaryFailure)
        self.assertNotIn(SECRET, str(raised.exception))
        self.assertIsInstance(raised.exception.__cause__, bootstrap.WebJobHistoryConflictError)
        return raised.exception

    def test_real_canary_wrappers_cleanup_and_consumed_failed_receipt_keep_only_safe_diagnostic(self):
        for cleanup_fails in (False, True):
            with self.subTest(cleanup_fails=cleanup_fails), tempfile.TemporaryDirectory() as folder:
                _, validated, preflight, projection, receipt = self.fixture(folder)
                error = self.real_canary_error(validated.document, cleanup_fails=cleanup_fails)
                transport = fixtures.FakeTransport(projection)
                original = transport.apply_operation

                def apply(operation, state):
                    if operation["id"] == START:
                        raise error
                    return original(operation, state)

                with mock.patch.object(transport, "apply_operation", side_effect=apply):
                    with self.assertRaises(bootstrap.BootstrapError) as raised:
                        self.executor(validated, preflight, transport).run()
                self.assertIs(raised.exception, error)
                terminal, raw = bootstrap.load_json(receipt / "execution-terminal.json", require_canonical=True)
                self.assertEqual(terminal["status"], "failed")
                self.assertTrue(terminal["consumed"])
                self.assertEqual(terminal["failureType"], "BootstrapError")
                self.assertIsNone(terminal["terminalBundlePath"])
                self.assertIsNone(terminal["terminalBundleSha256"])
                self.assertEqual(terminal["failureDiagnostic"]["mismatchBits"], "00011000")
                self.assertEqual(terminal["failureDiagnostic"]["readStage"], "terminal-history")
                self.assertEqual(terminal["failureDiagnostic"],
                                 diagnostic.from_failure(error, bootstrap.WebJobHistoryConflictError))
                self.assertNotIn("validatedWebJobFailure", json.dumps(terminal))
                self.assertNotIn(SECRET.encode(), raw)
                self.assertNotIn(history.COLLECTION_ID.encode(), raw)
                self.assertNotIn("run-1", json.dumps(terminal["failureDiagnostic"]))

    def test_failed_terminal_write_does_not_mask_original_conflict(self):
        with tempfile.TemporaryDirectory() as folder:
            _, validated, preflight, projection, _receipt = self.fixture(folder)
            error = self.real_canary_error(validated.document)
            transport = fixtures.FakeTransport(projection)
            original = transport.apply_operation

            def apply(operation, state):
                if operation["id"] == START:
                    raise error
                return original(operation, state)

            with (mock.patch.object(transport, "apply_operation", side_effect=apply),
                  mock.patch.object(bootstrap.UseLedger, "write_terminal", side_effect=OSError(SECRET)),
                  self.assertRaises(bootstrap.BootstrapError) as raised):
                self.executor(validated, preflight, transport).run()
            self.assertIs(raised.exception, error)
            self.assertNotIn(SECRET, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
