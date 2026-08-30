import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
import accepted_release_registry as registry  # noqa: E402
import validate_registry_webjob_result as validator  # noqa: E402


CONTROL_SHA = "a" * 40
PACKAGE_SHA = "b" * 64
HELPER_SHA = "c" * 64
ARTIFACT_SHA = "d" * 64
REQUEST_SHA = "e" * 64
MANIFEST_SHA = "f" * 64
RUN_ID = "50001"
RUN_ATTEMPT = "2"
STARTED_AT = "2026-08-23T01:02:03Z"
ENDED_AT = "2026-08-23T01:02:04Z"
PREFIX = f"v1/releases/{'1' * 40}/60001/70001/"


def runtime_result():
    return {
        "schemaVersion": 1,
        "status": "runtime-ready",
        "python": "3.12",
        "isolated": True,
        "helperSha256": HELPER_SHA,
        "runnerSha256": registry.WEBJOB_RUNNER_SHA256,
        "settingsJobSha256": registry.WEBJOB_SETTINGS_SHA256,
        "writerClientId": registry.REGISTRY_WRITER_CLIENT_ID,
        "readerClientId": registry.REGISTRY_READER_CLIENT_ID,
    }


def storage_result(nonce):
    return {
        "schemaVersion": 1,
        "status": "storage-rbac-ready",
        "canaryBlob": (
            f"v1/canaries/storage-rbac/{RUN_ID}/{RUN_ATTEMPT}/{nonce}.json"
        ),
        "writerCreate": "passed",
        "readerRead": "passed",
        "writerUnconditionalOverwriteDenied": "passed",
        "writerReadDenied": "passed",
        "readerWriteDenied": "passed",
        "localPrefixGuard": "passed-before-network",
    }


def persistence_result(created, overwrite):
    return {
        "status": "complete",
        "prefix": PREFIX,
        "artifactZipSha256": ARTIFACT_SHA,
        "requestSha256": REQUEST_SHA,
        "manifestSha256": MANIFEST_SHA,
        "fileCount": 20,
        "createdBlobCount": created,
        "overwriteNegative": overwrite,
        "outOfPrefixNegative": "passed",
    }


def operation_for(purpose):
    return registry.RESULT_PURPOSES[purpose][0]


class RegistryWebJobResultValidatorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def make_case(
        self,
        purpose,
        execution,
        nonce,
        result,
        *,
        run_id=None,
    ):
        operation = operation_for(purpose)
        result_blob = validator.expected_result_blob(
            RUN_ID, RUN_ATTEMPT, purpose, execution, nonce
        )
        webjobs_run_id = run_id or f"webjob-{purpose}-{execution}"
        envelope = {
            "schema": registry.RESULT_ATTESTATION_SCHEMA,
            "status": "attested",
            "operation": operation,
            "purpose": purpose,
            "execution": execution,
            "nonce": nonce,
            "resultBlob": result_blob,
            "githubRunId": RUN_ID,
            "githubRunAttempt": RUN_ATTEMPT,
            "controlWorkflowSha": CONTROL_SHA,
            "packageSha256": PACKAGE_SHA,
            "helperSha256": HELPER_SHA,
            "webJobsName": "paperdesk-accepted-release-registry",
            "webJobsType": "triggered",
            "webJobsRunId": webjobs_run_id,
            "resultSha256": hashlib.sha256(registry.canonical_json(result)).hexdigest(),
            "result": result,
        }
        path = self.root / f"{purpose}-{execution}-{nonce}.json"
        path.write_bytes(registry.canonical_json(envelope))
        kwargs = {
            "operation": operation,
            "purpose": purpose,
            "execution": execution,
            "nonce": nonce,
            "result_blob": result_blob,
            "github_run_id": RUN_ID,
            "github_run_attempt": RUN_ATTEMPT,
            "control_workflow_sha": CONTROL_SHA,
            "package_sha256": PACKAGE_SHA,
            "helper_sha256": HELPER_SHA,
            "webjobs_run_id": webjobs_run_id,
            "history_id": f"/subscriptions/example/history/{webjobs_run_id}",
            "history_status": "Success",
            "started_at": STARTED_AT,
            "ended_at": ENDED_AT,
            "expected_prefix": PREFIX if operation == "persist-actions-artifact" else None,
            "artifact_zip_sha256": ARTIFACT_SHA if operation == "persist-actions-artifact" else None,
            "request_sha256": REQUEST_SHA if operation == "persist-actions-artifact" else None,
        }
        return path, envelope, kwargs

    def validate_case(self, *args, **kwargs):
        path, _, expected = self.make_case(*args, **kwargs)
        return validator.validate_envelope(path, **expected)

    def write_proof(self, name, proof):
        path = self.root / name
        path.write_bytes(registry.canonical_json(proof))
        return path

    def test_all_five_execution_contracts_validate(self):
        cases = [
            ("preflight-storage", 1, "1" * 32, storage_result("1" * 32)),
            ("preflight-runtime", 1, "2" * 32, runtime_result()),
            ("persistence-runtime", 1, "3" * 32, runtime_result()),
            (
                "persistence-result",
                1,
                "4" * 32,
                persistence_result(21, "passed"),
            ),
            (
                "persistence-result",
                2,
                "5" * 32,
                persistence_result(0, "not-run-completed"),
            ),
        ]
        for purpose, execution, nonce, result in cases:
            with self.subTest(purpose=purpose, execution=execution):
                proof = self.validate_case(purpose, execution, nonce, result)
                self.assertEqual(proof["schema"], validator.PROOF_SCHEMA)
                self.assertEqual(
                    proof["history"]["webJobsRunId"],
                    f"webjob-{purpose}-{execution}",
                )

    def test_noncanonical_and_duplicate_json_fail_closed(self):
        nonce = "1" * 32
        path, envelope, expected = self.make_case(
            "preflight-storage", 1, nonce, storage_result(nonce)
        )
        path.write_text(json.dumps(envelope), encoding="utf-8")
        with self.assertRaises(validator.ResultValidationError):
            validator.validate_envelope(path, **expected)
        path.write_text('{"schema":1,"schema":2}\n', encoding="utf-8")
        with self.assertRaises(validator.ResultValidationError):
            validator.validate_envelope(path, **expected)

    def test_extra_missing_and_boolean_execution_fields_fail_closed(self):
        nonce = "1" * 32
        for mutation in ("extra", "missing", "boolean"):
            path, envelope, expected = self.make_case(
                "preflight-storage", 1, nonce, storage_result(nonce)
            )
            if mutation == "extra":
                envelope["unexpected"] = "value"
            elif mutation == "missing":
                envelope.pop("status")
            else:
                envelope["execution"] = True
            path.write_bytes(registry.canonical_json(envelope))
            with self.subTest(mutation=mutation):
                with self.assertRaises(validator.ResultValidationError):
                    validator.validate_envelope(path, **expected)

    def test_every_immutable_envelope_coordinate_is_bound(self):
        nonce = "2" * 32
        path, original, expected = self.make_case(
            "preflight-runtime", 1, nonce, runtime_result()
        )
        mutations = {
            "operation": "storage-rbac-canary",
            "purpose": "persistence-runtime",
            "execution": 2,
            "nonce": "9" * 32,
            "resultBlob": original["resultBlob"].replace(nonce, "9" * 32),
            "githubRunId": "50002",
            "githubRunAttempt": "3",
            "controlWorkflowSha": "9" * 40,
            "packageSha256": "9" * 64,
            "helperSha256": "9" * 64,
            "webJobsName": "wrong-job",
            "webJobsType": "continuous",
            "webJobsRunId": "wrong-run",
        }
        for key, value in mutations.items():
            envelope = copy.deepcopy(original)
            envelope[key] = value
            path.write_bytes(registry.canonical_json(envelope))
            with self.subTest(key=key):
                with self.assertRaises(validator.ResultValidationError):
                    validator.validate_envelope(path, **expected)

    def test_wrong_arm_history_run_and_failed_status_are_rejected(self):
        path, _, expected = self.make_case(
            "preflight-runtime", 1, "2" * 32, runtime_result()
        )
        for key, value in (("webjobs_run_id", "other-run"), ("history_status", "Failed")):
            changed = dict(expected)
            changed[key] = value
            with self.subTest(key=key):
                with self.assertRaises(validator.ResultValidationError):
                    validator.validate_envelope(path, **changed)

    def test_arm_history_time_order_is_fail_closed(self):
        path, _, expected = self.make_case(
            "preflight-runtime", 1, "2" * 32, runtime_result()
        )
        expected["started_at"] = "2026-08-23T01:02:05Z"
        expected["ended_at"] = "2026-08-23T01:02:04Z"
        with self.assertRaises(validator.ResultValidationError):
            validator.validate_envelope(path, **expected)

    def test_nested_digest_and_storage_nonce_binding_are_rejected(self):
        nonce = "1" * 32
        path, envelope, expected = self.make_case(
            "preflight-storage", 1, nonce, storage_result(nonce)
        )
        envelope["resultSha256"] = "9" * 64
        path.write_bytes(registry.canonical_json(envelope))
        with self.assertRaises(validator.ResultValidationError):
            validator.validate_envelope(path, **expected)
        envelope["result"] = storage_result("8" * 32)
        envelope["resultSha256"] = hashlib.sha256(
            registry.canonical_json(envelope["result"])
        ).hexdigest()
        path.write_bytes(registry.canonical_json(envelope))
        with self.assertRaises(validator.ResultValidationError):
            validator.validate_envelope(path, **expected)

    def test_persistence_prefix_artifact_and_request_are_bound(self):
        path, _, expected = self.make_case(
            "persistence-result",
            1,
            "4" * 32,
            persistence_result(21, "passed"),
        )
        for key, value in (
            ("expected_prefix", f"v1/releases/{'2' * 40}/60001/70001/"),
            ("artifact_zip_sha256", "1" * 64),
            ("request_sha256", "2" * 64),
        ):
            changed = dict(expected)
            changed[key] = value
            with self.subTest(key=key):
                with self.assertRaises(validator.ResultValidationError):
                    validator.validate_envelope(path, **changed)

    def test_preflight_result_set_requires_exact_unique_matrix(self):
        storage = self.validate_case(
            "preflight-storage", 1, "1" * 32, storage_result("1" * 32)
        )
        runtime = self.validate_case(
            "preflight-runtime", 1, "2" * 32, runtime_result()
        )
        storage_path = self.write_proof("storage-proof.json", storage)
        runtime_path = self.write_proof("runtime-proof.json", runtime)
        result_set = validator.build_result_set(
            "preflight", [runtime_path, storage_path]
        )
        self.assertEqual(result_set["mode"], "preflight")
        self.assertIsNone(result_set["persistenceCase"])
        self.assertEqual(len(result_set["executions"]), 2)
        with self.assertRaises(validator.ResultValidationError):
            validator.build_result_set("preflight", [storage_path, storage_path])

    def test_result_set_rejects_noncanonical_top_level_digests(self):
        for field in ("packageSha256", "helperSha256", "envelopeSha256"):
            storage = self.validate_case(
                "preflight-storage", 1, "1" * 32, storage_result("1" * 32)
            )
            runtime = self.validate_case(
                "preflight-runtime", 1, "2" * 32, runtime_result()
            )
            storage[field] = f"sha256:{storage[field]}"
            storage_path = self.write_proof(f"storage-{field}.json", storage)
            runtime_path = self.write_proof(f"runtime-{field}.json", runtime)
            with self.subTest(field=field):
                with self.assertRaises(validator.ResultValidationError):
                    validator.build_result_set(
                        "preflight", [storage_path, runtime_path]
                    )

    def persistence_proofs(self, first_count, first_overwrite, second_count, second_overwrite):
        runtime = self.validate_case(
            "persistence-runtime", 1, "3" * 32, runtime_result()
        )
        first = self.validate_case(
            "persistence-result",
            1,
            "4" * 32,
            persistence_result(first_count, first_overwrite),
        )
        second = self.validate_case(
            "persistence-result",
            2,
            "5" * 32,
            persistence_result(second_count, second_overwrite),
        )
        return [
            self.write_proof("persistence-runtime.json", runtime),
            self.write_proof("persistence-first.json", first),
            self.write_proof("persistence-second.json", second),
        ]

    def test_both_allowed_persistence_idempotence_cases(self):
        paths = self.persistence_proofs(21, "passed", 0, "not-run-completed")
        result_set = validator.build_result_set("persistence", paths)
        self.assertEqual(
            result_set["persistenceCase"], "created-or-recovered-then-idempotent"
        )
        for path in paths:
            path.unlink()
        paths = self.persistence_proofs(
            0, "not-run-completed", 0, "not-run-completed"
        )
        result_set = validator.build_result_set("persistence", paths)
        self.assertEqual(
            result_set["persistenceCase"], "already-complete-before-both-executions"
        )

    def test_every_other_persistence_pair_relationship_is_rejected(self):
        invalid = (
            (1, "passed", 1, "passed"),
            (0, "not-run-completed", 1, "passed"),
        )
        for index, values in enumerate(invalid):
            with self.subTest(values=values):
                paths = self.persistence_proofs(*values)
                with self.assertRaises(validator.ResultValidationError):
                    validator.build_result_set("persistence", paths)
                if index != len(invalid) - 1:
                    for path in paths:
                        path.unlink()

    def test_persistence_pair_rejects_immutable_result_drift(self):
        paths = self.persistence_proofs(1, "passed", 0, "not-run-completed")
        second = validator.load_canonical_json(
            paths[2], "test proof", validator.MAX_PROOF_BYTES
        )
        second["result"]["manifestSha256"] = "8" * 64
        second["resultSha256"] = hashlib.sha256(
            registry.canonical_json(second["result"])
        ).hexdigest()
        paths[2].write_bytes(registry.canonical_json(second))
        with self.assertRaises(validator.ResultValidationError):
            validator.build_result_set("persistence", paths)


if __name__ == "__main__":
    unittest.main()
