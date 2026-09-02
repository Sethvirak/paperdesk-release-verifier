"""Package readiness diagnostics survive bounded cleanup in local receipts."""

import tempfile
import unittest
from unittest import mock

from scripts import private_release_v2_bootstrap as bootstrap
from tests import test_private_release_v2_bootstrap as fixtures


SECRET = "Bearer package-receipt-private-token 203.0.113.51 raw-response-secret"
OPERATION = "uploadVersionedBridgePackage"
CLEANUP_ORDER = [
    "addOwnedOperatorFenceBootstrapRole",
    "addOwnedOperatorKeyReadRole",
    "addOwnedUploaderPackageRole",
    "addOwnedOperatorControllerCanaryRole",
    "addOwnedUploaderIpv4Rule",
]


class PackageFailureReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.plan_sha = bootstrap.load_plan()
        cls.package = bootstrap.build_package_descriptor()

    def setUp(self):
        # Compose the shared authorization fixture without inheriting its tests.
        self.harness = fixtures.BootstrapTests(methodName="runTest")
        self.harness.plan = self.plan
        self.harness.plan_sha = self.plan_sha
        self.harness.package = self.package

    def exercise_failure(self, *, hostile=False, failed_cleanup=None):
        with tempfile.TemporaryDirectory() as folder:
            _, validated, preflight, projection, receipt = self.harness.fixture(folder)
            transport = fixtures.FakeTransport(projection)
            executor = bootstrap.BootstrapExecutor(
                plan=self.plan, plan_sha256=self.plan_sha, package=self.package,
                authorization=validated, preflight=preflight, transport=transport,
                now=lambda: fixtures.NOW, source_validator=self.harness.source,
            )
            original_apply = transport.apply_operation
            original_compensate = transport.compensate_temporary
            code = SECRET if hostile else "AuthorizationPermissionMismatch"
            request_id = SECRET if hostile else "12345678-1234-0123-ABCD-123456789ABC"
            server_date = SECRET if hostile else "Wed, 02 Sep 2026 00:00:00 GMT"
            credential = SECRET if hostile else {
                "source": "process-cache", "tokenIssuedAtUnix": 1788307140,
                "tokenExpiresAtUnix": 1788310800, "tokenObservedAtUnix": 1788307200,
                "accountBindingVerified": True,
            }
            role_readback = {"definitionSha256": SECRET, "assignmentSha256": SECRET} if hostile else {
                "definitionSha256": "a" * 64, "assignmentSha256": "b" * 64,
            }
            failure = bootstrap.PackageReadinessError(
                "package data-plane readiness did not converge before its deadline",
                elapsed_seconds=600, attempts=43, status=403, error_code=code,
                stop_reason="deadline", request_id=request_id, server_date=server_date,
                credential=credential, role_readback=role_readback,
            )

            def apply(operation, state):
                if operation["id"] == OPERATION:
                    transport.calls.append(("apply", operation["id"]))
                    raise failure
                return original_apply(operation, state)

            def compensate(operation, proof, state):
                if operation["id"] == failed_cleanup:
                    transport.calls.append(("compensate", operation["id"]))
                    raise RuntimeError(SECRET)
                return original_compensate(operation, proof, state)

            with mock.patch.object(transport, "apply_operation", side_effect=apply), \
                    mock.patch.object(transport, "compensate_temporary", side_effect=compensate):
                with self.assertRaises(bootstrap.PackageReadinessError) as raised:
                    executor.run()
            self.assertIs(raised.exception, failure)
            terminal_path = receipt / "execution-terminal.json"
            terminal, raw = bootstrap.load_json(terminal_path, require_canonical=True)
            consumed_path = receipt / "single-use-state.json"
            consumed, consumed_raw = bootstrap.load_json(consumed_path, require_canonical=True)

            self.assertEqual(terminal["status"], "failed")
            self.assertTrue(terminal["consumed"])
            self.assertEqual(terminal["failureType"], "PackageReadinessError")
            self.assertIsNone(terminal["terminalBundlePath"])
            self.assertIsNone(terminal["terminalBundleSha256"])
            self.assertFalse((receipt / "evidence/private-release-bootstrap-receipt-bundle.json").exists())
            self.assertEqual(terminal["failureDiagnostic"], {
                "stage": "package-upload-readiness", "elapsedSeconds": 600,
                "attempts": 43, "status": 403,
                "errorCode": "unknown" if hostile else code,
                "stopReason": "deadline", "requestId": None if hostile else request_id,
                "serverDate": None if hostile else server_date,
                "credential": None if hostile else credential,
                "roleReadback": None if hostile else role_readback,
            })
            for value in (raw, consumed_raw):
                for secret in (SECRET, "package-receipt-private-token", "203.0.113.51", "raw-response-secret"):
                    self.assertNotIn(secret.encode(), value)
            self.assertEqual(consumed["status"], "consumed-before-first-Azure-mutation")
            self.assertEqual(consumed["authorizationSha256"], validated.sha256)
            for field in ("authorizationId", "authorizationSha256", "sourceSha", "planSha256"):
                self.assertEqual(terminal[field], consumed[field])
            self.assertEqual(
                [value for kind, value in transport.calls if kind == "compensate"],
                CLEANUP_ORDER,
            )
            self.assertEqual([item["operationId"] for item in terminal["temporaryCleanup"]], CLEANUP_ORDER)
            for cleanup in terminal["temporaryCleanup"]:
                if cleanup["operationId"] == failed_cleanup:
                    self.assertEqual(cleanup["status"], "cleanup-failed")
                    self.assertEqual(cleanup["errorType"], "RuntimeError")
                else:
                    self.assertEqual(cleanup["status"], "removed-exact")
            attempts = [value for kind, value in transport.calls if kind == "apply"]
            self.assertEqual(attempts[-1], OPERATION)
            self.assertNotIn(OPERATION, terminal["appliedMutationIds"])
            self.assertEqual(attempts[:-1], terminal["appliedMutationIds"])
            self.assertNotIn(("terminal-source", None), transport.calls)

            # A consumed local fixture cannot replay writes or replace its receipt.
            call_count = len(transport.calls)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "already consumed"):
                executor.run()
            self.assertFalse(any(kind in {"apply", "compensate"}
                                 for kind, _ in transport.calls[call_count:]))
            self.assertEqual(terminal_path.read_bytes(), raw)
            self.assertEqual(consumed_path.read_bytes(), consumed_raw)

    def test_package_failure_retains_only_safe_diagnostics_after_all_cleanup(self):
        for hostile in (False, True):
            with self.subTest(hostile=hostile):
                self.exercise_failure(hostile=hostile)

    def test_cleanup_failure_does_not_mask_package_diagnostic_or_claim_full_cleanup(self):
        self.exercise_failure(hostile=True, failed_cleanup="addOwnedOperatorKeyReadRole")


if __name__ == "__main__":
    unittest.main()
