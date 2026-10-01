"""Offline transport diagnostics must not authorize retries or infer server arrival."""

import base64
import contextlib
import datetime as dt
import io
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
import urllib.error
import urllib.request

from scripts import private_release_v2_bootstrap as bootstrap
from tests import test_private_release_v2_bootstrap as fixtures


SECRET = "sensitive-sentinel-not-for-output"
ARM_URL = "https://management.azure.com/offline-test"
DIAGNOSTIC = {"stage": "exchange-open", "category": "connection-reset"}


class Response:
    status = 201
    headers = {}

    def read(self, _limit):
        return b"{}"

    def close(self):
        pass


class TransportDiagnosticTests(unittest.TestCase):
    def run_child(self, *, payload=None, response=None, open_error=None,
                  request_error=None, opener_error=None):
        if payload is None:
            payload = json.dumps({
                "method": "PUT", "url": ARM_URL,
                "body": base64.b64encode(SECRET.encode()).decode(),
                "headers": [["Authorization", SECRET]], "socketTimeout": 1,
            }).encode()
        output = io.BytesIO()
        opener = mock.Mock()
        if open_error is not None:
            opener.open.side_effect = open_error
        else:
            opener.open.return_value = response or Response()
        request_patch = (
            mock.patch.object(urllib.request, "Request", side_effect=request_error)
            if request_error is not None else contextlib.nullcontext()
        )
        opener_patch = mock.patch.object(
            urllib.request, "build_opener",
            **({"side_effect": opener_error} if opener_error is not None
               else {"return_value": opener}),
        )
        with (
            mock.patch.object(sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(payload))),
            mock.patch.object(sys, "stdout", types.SimpleNamespace(buffer=output)),
            request_patch, opener_patch,
        ):
            exec(bootstrap._AZURE_REST_EXCHANGE_CHILD, {})
        return json.loads(output.getvalue()), output.getvalue(), opener.open.call_count

    def test_child_pre_open_failures_remain_transport_errors(self):
        cases = (
            ({"payload": b"not-json"}, "request-envelope", "invalid-value"),
            ({"payload": b"{}"}, "request-envelope", "invalid-value"),
            ({"request_error": ValueError(SECRET)}, "request-construction", "invalid-value"),
            ({"opener_error": OSError(SECRET)}, "request-construction", "os-error"),
        )
        for arguments, stage, category in cases:
            with self.subTest(stage=stage, category=category):
                value, raw, opens = self.run_child(**arguments)
                self.assertEqual(value, {
                    "kind": "transport-error", "stage": stage, "category": category,
                })
                self.assertEqual(opens, 0)
                self.assertNotIn(SECRET.encode(), raw)

    def test_child_open_failures_classify_types_without_exception_text(self):
        cases = (
            (urllib.error.URLError(socket.gaierror(-2, SECRET)), "name-resolution"),
            (urllib.error.URLError(ssl.SSLCertVerificationError(SECRET)), "tls-verification"),
            (urllib.error.URLError(ssl.SSLError(SECRET)), "tls"),
            (urllib.error.URLError(TimeoutError(SECRET)), "socket-timeout"),
            (ConnectionResetError(SECRET), "connection-reset"),
            (ConnectionRefusedError(SECRET), "connection-refused"),
            (ConnectionAbortedError(SECRET), "connection-aborted"),
            (OSError(SECRET), "os-error"),
            (urllib.error.URLError(SECRET), "url-error"),
            (RuntimeError(SECRET), "unknown"),
        )
        for error, category in cases:
            with self.subTest(category=category):
                value, raw, opens = self.run_child(open_error=error)
                self.assertEqual(value, {
                    "kind": "transport-error", "stage": "exchange-open", "category": category,
                })
                self.assertEqual(bootstrap._rest_transport_error_category(error), category)
                self.assertEqual(opens, 1)
                self.assertNotIn(SECRET.encode(), raw)

    def test_child_response_failures_keep_only_fixed_stage_and_category(self):
        class BrokenStatus(Response):
            status = SECRET

        class BrokenRead(Response):
            def read(self, _limit):
                raise ConnectionResetError(SECRET)

        class BrokenHeaders(Response):
            class Headers:
                def items(self):
                    raise RuntimeError(SECRET)
            headers = Headers()

        class OversizedHeaders(Response):
            headers = {SECRET: SECRET * 20000}

        class BrokenClose(Response):
            def close(self):
                raise OSError(SECRET)

        cases = (
            (BrokenStatus(), "response-status", "invalid-value"),
            (BrokenRead(), "response-body", "connection-reset"),
            (BrokenHeaders(), "response-headers", "unknown"),
            (OversizedHeaders(), "response-validation", "invalid-value"),
            (BrokenClose(), "response-close", "os-error"),
        )
        for response, stage, category in cases:
            with self.subTest(stage=stage):
                value, raw, opens = self.run_child(response=response)
                self.assertEqual(value, {
                    "kind": "transport-error", "stage": stage, "category": category,
                })
                self.assertEqual(opens, 1)
                self.assertNotIn(SECRET.encode(), raw)

    def test_child_success_and_http_error_response_shapes_are_unchanged(self):
        expected = {"kind": "response", "status": 201, "body": "e30=", "headers": []}
        value, _, opens = self.run_child()
        self.assertEqual(value, expected)
        self.assertEqual(opens, 1)
        error = urllib.error.HTTPError(ARM_URL, 403, SECRET, {}, io.BytesIO(b"denied"))
        value, _, opens = self.run_child(open_error=error)
        self.assertEqual(value, {
            "kind": "response", "status": 403,
            "body": base64.b64encode(b"denied").decode(), "headers": [],
        })
        self.assertEqual(opens, 1)

    def parent_error(self, completed=None, *, side_effect=None):
        request = urllib.request.Request(ARM_URL, data=SECRET.encode(),
                                         headers={"Authorization": SECRET}, method="PUT")
        with mock.patch.object(
            bootstrap.subprocess, "run",
            **({"side_effect": side_effect} if side_effect is not None
               else {"return_value": completed}),
        ) as runner:
            with self.assertRaises(bootstrap._RestTransportAmbiguity) as raised:
                bootstrap.AzureCliRestSession._run_exchange_subprocess(request, 1)
        runner.assert_called_once()
        self.assertNotIn(SECRET, str(raised.exception))
        self.assertNotIn(SECRET, json.dumps(raised.exception.transport_diagnostic))
        return raised.exception

    def test_parent_process_failures_never_emit_stdout_stderr_or_exception_text(self):
        cases = (
            (OSError(SECRET), None, "exchange-launch", "os-error"),
            (subprocess.SubprocessError(SECRET), None, "exchange-launch", "subprocess-error"),
            (subprocess.TimeoutExpired([SECRET], 1, output=SECRET.encode(), stderr=SECRET.encode()),
             None, "exchange-wait", "total-timeout"),
            (None, subprocess.CompletedProcess([], 1, SECRET.encode(), SECRET.encode()),
             "exchange-output", "child-exit"),
            (None, subprocess.CompletedProcess([], 0, b"", SECRET.encode()),
             "exchange-output", "empty-output"),
            (None, subprocess.CompletedProcess([], 0, b"{}", b"z" * (1024 * 1024 + 1)),
             "exchange-output", "output-limit"),
        )
        for error, completed, stage, category in cases:
            with self.subTest(category=category):
                caught = self.parent_error(completed, side_effect=error)
                self.assertEqual(caught.transport_diagnostic, {"stage": stage, "category": category})
                self.assertEqual(isinstance(caught, bootstrap._RestTotalTimeout), category == "total-timeout")

    def test_parent_decoder_accepts_only_fixed_error_envelopes(self):
        malformed = (
            {"kind": "transport-error", **DIAGNOSTIC, "message": SECRET},
            {"kind": "transport-error", "stage": SECRET, "category": "connection-reset"},
            {"kind": "transport-error", "stage": "exchange-open", "category": SECRET},
            {"kind": "transport-error", "stage": [], "category": "connection-reset"},
            {"kind": "transport-error", "stage": "exchange-open", "category": True},
            {"kind": "transport-error", "stage": "exchange-open"},
            [SECRET],
        )
        for value in malformed:
            with self.subTest(value_type=type(value).__name__):
                caught = self.parent_error(subprocess.CompletedProcess(
                    [], 0, json.dumps(value).encode(), SECRET.encode(),
                ))
                self.assertEqual(caught.transport_diagnostic, {
                    "stage": "exchange-decode", "category": "invalid-envelope",
                })
        for envelope, expected in (
            ({"kind": "transport-error", **DIAGNOSTIC}, DIAGNOSTIC),
            ({"kind": "transport-error"}, {"stage": "unknown", "category": "unknown"}),
        ):
            caught = self.parent_error(subprocess.CompletedProcess([], 0, json.dumps(envelope).encode(), b""))
            self.assertEqual(caught.transport_diagnostic, expected)

    def test_parent_decode_and_existing_hook_error_classifications_are_preserved(self):
        cases = (
            (b"\xff", "invalid-utf8"),
            (b"not-json", "invalid-json"),
            (b'{"kind":"response","status":201,"body":"!","headers":[]}', "invalid-base64"),
        )
        for output, category in cases:
            with self.subTest(category=category):
                caught = self.parent_error(subprocess.CompletedProcess([], 0, output, b""))
                self.assertEqual(caught.transport_diagnostic, {"stage": "exchange-decode", "category": category})
        # These parser hooks already raise ordinary BootstrapError. Changing their
        # type would expand read retries/ownership; diagnostics must not do that.
        for output in (b'{"kind":1,"kind":2}', b'{"kind":NaN}'):
            request = urllib.request.Request(ARM_URL, method="PUT")
            with mock.patch.object(bootstrap.subprocess, "run", return_value=
                                   subprocess.CompletedProcess([], 0, output, b"")):
                with self.assertRaises(bootstrap.BootstrapError) as raised:
                    bootstrap.AzureCliRestSession._run_exchange_subprocess(request, 1)
            self.assertNotIsInstance(raised.exception, bootstrap._RestTransportAmbiguity)
            self.assertIsNone(bootstrap._transport_failure_diagnostic(raised.exception))

    def test_injected_runner_and_credential_failures_keep_existing_behavior(self):
        now = fixtures.NOW
        for error, category in (
            (urllib.error.URLError(socket.gaierror(-2, SECRET)), "name-resolution"),
            (TimeoutError(SECRET), "socket-timeout"),
            (ConnectionResetError(SECRET), "connection-reset"),
        ):
            session = bootstrap.AzureCliRestSession({}, clock=lambda: now,
                                                    exchange_runner=mock.Mock(side_effect=error))
            with mock.patch.object(session, "_token", return_value=SECRET):
                with self.assertRaises(bootstrap._RestTransportAmbiguity) as raised:
                    session.request("PUT", ARM_URL)
            self.assertEqual(raised.exception.transport_diagnostic, {
                "stage": "exchange-open", "category": category,
            })
            self.assertNotIn(SECRET, str(raised.exception))
            session._exchange_runner.assert_called_once()
        runner = mock.Mock()
        session = bootstrap.AzureCliRestSession({}, clock=lambda: now, exchange_runner=runner)
        with mock.patch.object(session, "_token", side_effect=bootstrap.BootstrapError("credential failed")):
            with self.assertRaises(bootstrap.BootstrapError) as raised:
                session.request("PUT", ARM_URL)
        self.assertNotIsInstance(raised.exception, bootstrap._RestTransportAmbiguity)
        self.assertIsNone(bootstrap._transport_failure_diagnostic(raised.exception))
        runner.assert_not_called()

    def test_sanitizer_and_bounded_cause_walk_ignore_untrusted_metadata(self):
        class PretendAllowed(str):
            def __hash__(self):
                return hash("exchange-open")

            def __eq__(self, other):
                return other == "exchange-open"

        self.assertEqual(bootstrap._safe_rest_transport_diagnostic(DIAGNOSTIC), DIAGNOSTIC)
        for value in (None, [], {**DIAGNOSTIC, "body": SECRET},
                      {"stage": [], "category": "unknown"}, {"stage": SECRET, "category": "unknown"},
                      {"stage": PretendAllowed(SECRET), "category": "unknown"}):
            self.assertIsNone(bootstrap._safe_rest_transport_diagnostic(value))
        error = bootstrap._RestTransportAmbiguity(SECRET, **DIAGNOSTIC)
        error.transport_diagnostic = {**DIAGNOSTIC, "headers": SECRET}
        self.assertIsNone(bootstrap._transport_failure_diagnostic(error))
        error = bootstrap._RestTransportAmbiguity(SECRET, **DIAGNOSTIC)
        ordinary = bootstrap.BootstrapError(SECRET)
        ordinary.__context__ = error
        ordinary.transport_diagnostic = DIAGNOSTIC
        self.assertIsNone(bootstrap._transport_failure_diagnostic(ordinary))
        ordinary.__cause__ = error
        self.assertEqual(bootstrap._transport_failure_diagnostic(ordinary), DIAGNOSTIC)
        cycle = bootstrap.BootstrapError(SECRET)
        cycle.__cause__ = cycle
        self.assertIsNone(bootstrap._transport_failure_diagnostic(cycle))
        chain = error
        for _ in range(8):
            wrapper = bootstrap.BootstrapError(SECRET)
            wrapper.__cause__ = chain
            chain = wrapper
        self.assertIsNone(bootstrap._transport_failure_diagnostic(chain))


class MutationReceiptDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.plan_sha = bootstrap.load_plan()
        cls.package = bootstrap.build_package_descriptor()

    source = staticmethod(fixtures.BootstrapTests.source)

    def fixture(self, folder):
        return fixtures.BootstrapTests.fixture(self, folder)

    def executor(self, validated, preflight, transport):
        return fixtures.BootstrapTests.executor(self, validated, preflight, transport)

    def mutation_transport(self, receipt, operation_id, error):
        transport = object.__new__(bootstrap.AzureCliBootstrapTransport)
        transport._active_operation_id = operation_id
        transport.plan = {"mutations": [{"id": operation_id, "kind": "temporary-add", "temporary": True}]}
        transport.authorization = {
            "validity": {"notBefore": fixtures.stamp(fixtures.NOW - dt.timedelta(minutes=1)),
                         "expiresAt": fixtures.stamp(fixtures.NOW + dt.timedelta(hours=1))},
            "source": {"mergedMain": {"commitSha": fixtures.MERGE}},
            "plan": {"sha256": self.plan_sha},
        }
        ledger = bootstrap.UseLedger(
            directory=receipt, authorization_id=fixtures.AUTH_ID,
            authorization_sha256=bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(transport.authorization)
            ),
            source_sha=fixtures.MERGE, plan_sha256=self.plan_sha,
            claimed_at=fixtures.stamp(fixtures.NOW),
        )
        ledger.claim()
        transport._ledger = ledger
        transport.package = self.package
        transport.clock = lambda: fixtures.NOW
        transport._request_deadline = lambda: None
        transport._require_full_request_envelope = lambda *_args: None
        transport.session = types.SimpleNamespace(request=mock.Mock(side_effect=error))
        return transport, ledger

    def test_arm_and_storage_transport_failures_remain_one_call_unresolved_intents(self):
        cases = (
            ("addOwnedOperatorControllerCanaryRole", ARM_URL, bootstrap._MutationOwnershipAmbiguity),
            ("uploadVersionedBridgePackage", "https://mdspdbak2608089c4e.blob.core.windows.net/offline-test",
             bootstrap.StorageOperationError),
        )
        for operation_id, url, expected_type in cases:
            with self.subTest(operation=operation_id), tempfile.TemporaryDirectory() as folder:
                error = bootstrap._RestTransportAmbiguity("Azure REST transport failed closed", **DIAGNOSTIC)
                transport, ledger = self.mutation_transport(Path(folder) / "receipt", operation_id, error)
                with self.assertRaises(expected_type) as raised:
                    transport._mutation_request("PUT", url, body=SECRET.encode(), expected={201})
                transport.session.request.assert_called_once()
                self.assertEqual(bootstrap._transport_failure_diagnostic(raised.exception), DIAGNOSTIC)
                self.assertEqual(len(ledger.unresolved_intents()), 1)
                records = ledger.read_cloud_mutations()
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]["phase"], "intent")
                self.assertNotIn("transportFailureDiagnostic", records[0])
                self.assertNotIn(SECRET, json.dumps(records))
                if expected_type is bootstrap.StorageOperationError:
                    self.assertIsNone(raised.exception.__cause__)
                    self.assertEqual(raised.exception.diagnostic["stopReason"], "transport-error")
                    self.assertNotIn("transportFailureDiagnostic", raised.exception.diagnostic)

    def test_nested_owned_failure_and_cleanup_metadata_survive_only_in_failed_terminal(self):
        with tempfile.TemporaryDirectory() as folder:
            _, validated, preflight, projection, receipt = self.fixture(folder)
            transport = fixtures.FakeTransport(projection)
            original_apply = transport.apply_operation
            original_compensate = transport.compensate_temporary

            def apply(operation, state):
                proof = original_apply(operation, state)
                if operation["id"] == "addOwnedOperatorControllerCanaryRole":
                    transport_error = bootstrap._RestTransportAmbiguity(SECRET, **DIAGNOSTIC)
                    mutation_error = bootstrap._MutationOwnershipAmbiguity(
                        "mutation transport outcome is ambiguous", transport_diagnostic=DIAGNOSTIC,
                    )
                    mutation_error.__cause__ = transport_error
                    owned_error = bootstrap.OwnedTemporaryMutationError("owned mutation failed", proof)
                    owned_error.__cause__ = mutation_error
                    raise owned_error
                return proof

            def compensate(operation, proof, state):
                if operation["id"] == "addOwnedOperatorControllerCanaryRole":
                    transport.calls.append(("compensate", operation["id"]))
                    error = bootstrap.BootstrapError("cleanup failed")
                    error.__cause__ = bootstrap._RestTransportAmbiguity(
                        SECRET, stage="response-body", category="connection-reset",
                    )
                    raise error
                return original_compensate(operation, proof, state)

            with (mock.patch.object(transport, "apply_operation", side_effect=apply),
                  mock.patch.object(transport, "compensate_temporary", side_effect=compensate),
                  self.assertRaises(bootstrap.BootstrapError)):
                self.executor(validated, preflight, transport).run()
            terminal, raw = bootstrap.load_json(receipt / "execution-terminal.json", require_canonical=True)
            self.assertEqual(terminal["status"], "failed")
            self.assertTrue(terminal["consumed"])
            self.assertIsNone(terminal["terminalBundlePath"])
            self.assertEqual(terminal["transportFailureDiagnostic"], DIAGNOSTIC)
            self.assertEqual(terminal["temporaryCleanup"][0], {
                "operationId": "addOwnedOperatorControllerCanaryRole", "status": "cleanup-failed",
                "errorType": "BootstrapError", "transportFailureDiagnostic": {
                    "stage": "response-body", "category": "connection-reset",
                },
            })
            self.assertEqual([value for kind, value in transport.calls if kind == "compensate"],
                             ["addOwnedOperatorControllerCanaryRole", "addOwnedUploaderIpv4Rule"])
            self.assertNotIn(SECRET.encode(), raw)

    def test_complete_terminal_schema_has_no_diagnostic_fields(self):
        with tempfile.TemporaryDirectory() as folder:
            _, validated, preflight, projection, receipt = self.fixture(folder)
            transport = fixtures.FakeTransport(projection)
            result = self.executor(validated, preflight, transport).run()
            self.assertEqual(result.status, "complete")
            terminal, _ = bootstrap.load_json(receipt / "execution-terminal.json", require_canonical=True)
            self.assertEqual(set(terminal), {
                "schemaVersion", "status", "authorizationId", "authorizationSha256",
                "sourceSha", "planSha256", "appliedMutationIds", "temporaryCleanup",
                "terminalBundlePath", "terminalBundleSha256", "failureType", "consumed",
            })
            self.assertNotIn("transportFailureDiagnostic", json.dumps(terminal))


if __name__ == "__main__":
    unittest.main()
