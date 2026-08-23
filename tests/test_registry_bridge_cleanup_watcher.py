import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from provider import registry_bridge_cleanup_watcher as watcher

BUILDER_SPEC = importlib.util.spec_from_file_location(
    "build_registry_cleanup_watcher_package",
    ROOT / "scripts" / "build_registry_cleanup_watcher_package.py",
)
builder = importlib.util.module_from_spec(BUILDER_SPEC)
assert BUILDER_SPEC.loader is not None
BUILDER_SPEC.loader.exec_module(builder)


CONTROL_SHA = "a" * 40
TOKEN_SHA = "b" * 64
CONTROL_PRINCIPAL_ID = "11111111-1111-4111-8111-111111111111"
FEDERATED_CREDENTIAL_ID = (
    f"/subscriptions/{watcher.SUBSCRIPTION_ID}/resourcegroups/"
    "rg-master-data-structure-sea/providers/microsoft.managedidentity/"
    "userassignedidentities/control/federatedidentitycredentials/revoked"
)
MUTATING_ROLE_ASSIGNMENT_IDS = [
    f"/subscriptions/{watcher.SUBSCRIPTION_ID}/resourcegroups/"
    "rg-master-data-structure-sea/providers/microsoft.authorization/"
    "roleassignments/22222222-2222-4222-8222-222222222222"
]
FENCE_PRODUCER_SHA = "c" * 40
AUTHORITY_GENERATION_SHA = watcher.digest_bytes(watcher.canonical_json({
    "schema": watcher.AUTHORITY_GENERATION_SCHEMA,
    "contractId": watcher.CONTRACT_ID,
    "bridgeResourceId": watcher.BRIDGE_RESOURCE_ID,
    "controlWorkflowSha": CONTROL_SHA,
    "controlPrincipalObjectId": CONTROL_PRINCIPAL_ID,
    "federatedCredentialResourceId": FEDERATED_CREDENTIAL_ID,
    "mutatingRoleAssignmentIds": MUTATING_ROLE_ASSIGNMENT_IDS,
    "producerReviewedCommitSha": FENCE_PRODUCER_SHA,
}))
SECRET = "github_pat_secret-must-never-appear"


def runtime_result():
    return {
        "schemaVersion": 1,
        "status": "runtime-ready",
        "python": "3.12",
        "isolated": True,
        "helperSha256": watcher.HELPER_SHA256,
        "runnerSha256": watcher.RUNNER_SHA256,
        "settingsJobSha256": watcher.SETTINGS_SHA256,
        "writerClientId": "1a0d95c5-bbd5-4b57-bd6c-6d5645a50e16",
        "readerClientId": "a52c21e2-b465-4f01-88b8-44bb5fb8b306",
    }


def storage_result(execution):
    return {
        "schemaVersion": 1,
        "status": "storage-rbac-ready",
        "canaryBlob": f"v1/canaries/storage-rbac/101/2/{execution['nonce']}.json",
        "writerCreate": "passed",
        "readerRead": "passed",
        "writerUnconditionalOverwriteDenied": "passed",
        "writerReadDenied": "passed",
        "readerWriteDenied": "passed",
        "localPrefixGuard": "passed-before-network",
    }


def persistence_result(execution, created):
    return {
        "status": "complete",
        "prefix": execution["expectedPrefix"],
        "artifactZipSha256": execution["artifactZipSha256"],
        "requestSha256": execution["requestSha256"],
        "manifestSha256": "c" * 64,
        "fileCount": 19,
        "createdBlobCount": created,
        "overwriteNegative": "passed" if created else "not-run-completed",
        "outOfPrefixNegative": "passed",
    }


def expected_executions(mode="preflight", bound=True):
    rows = []
    prefix = f"v1/releases/{'d' * 40}/700/800/"
    for index, ((purpose, execution), operation) in enumerate(watcher.MATRICES[mode].items(), 1):
        nonce = f"{index:032x}"
        rows.append({
            "operation": operation,
            "purpose": purpose,
            "execution": execution,
            "nonce": nonce,
            "resultBlob": f"v1/results/101/2/{purpose}/{execution}/{nonce}.json",
            "historyId": f"{watcher.HISTORY_RESOURCE_PREFIX}history-{index}" if bound else None,
            "webJobsRunId": f"webjob-{index}" if bound else None,
            "expectedPrefix": prefix if operation == "persist-actions-artifact" else None,
            "artifactZipSha256": "e" * 64 if operation == "persist-actions-artifact" else None,
            "requestSha256": "f" * 64 if operation == "persist-actions-artifact" else None,
        })
    return rows


def make_session(phase="armed", mode="preflight", bound=True):
    return watcher.build_review_session(
        session_id="0123456789abcdef0123456789abcdef",
        fence=1,
        phase=phase,
        mode=mode,
        lease_owner="github-run-101-2",
        server_time="2026-08-23T00:00:00.000Z",
        github_run_id="101",
        github_run_attempt="2",
        control_workflow_sha=CONTROL_SHA,
        session_token_sha256=TOKEN_SHA,
        runner_authority_generation_sha256=AUTHORITY_GENERATION_SHA,
        expected_executions=expected_executions(mode, bound),
    )


def history_for(execution):
    return {
        "id": execution["historyId"],
        "web_job_name": watcher.WEBJOB_NAME,
        "web_job_id": execution["webJobsRunId"],
        "status": "Success",
        "start_time": "2026-08-23T00:01:00.123Z",
        "end_time": "2026-08-23T00:01:01.456Z",
    }


def envelope_for(execution, session, result):
    result_sha = hashlib.sha256(watcher.canonical_json(result)).hexdigest()
    return watcher.canonical_json({
        "schema": watcher.RESULT_SCHEMA,
        "status": "attested",
        "operation": execution["operation"],
        "purpose": execution["purpose"],
        "execution": execution["execution"],
        "nonce": execution["nonce"],
        "resultBlob": execution["resultBlob"],
        "githubRunId": session["githubRunId"],
        "githubRunAttempt": session["githubRunAttempt"],
        "controlWorkflowSha": session["controlWorkflowSha"],
        "packageSha256": watcher.PACKAGE_SHA256,
        "helperSha256": watcher.HELPER_SHA256,
        "webJobsName": watcher.WEBJOB_NAME,
        "webJobsType": "triggered",
        "webJobsRunId": execution["webJobsRunId"],
        "resultSha256": result_sha,
        "result": result,
    })


def sweep_review(boundary, reviewed_sha=CONTROL_SHA, claimant="watcher-a"):
    claim = watcher.claim_expired_session(boundary, claimant)
    if claim is None:
        return {"schema": watcher.RECEIPT_SCHEMA, "status": "idle"}
    receipt, _ = watcher.reconcile_claim(boundary, claim, reviewed_sha)
    return receipt


class FakeBoundary:
    def __init__(self, session=None, *, now="2026-08-23T00:11:00.000Z"):
        self.now = now
        self.state_body = watcher.canonical_json(session) if session is not None else None
        self.etag_number = 1
        self.settings = dict(watcher.PERSISTENT_SETTINGS)
        self.settings["PAPERDESK_REGISTRY_GITHUB_TOKEN"] = SECRET
        self.posture = dict(watcher.SEALED_POSTURE)
        self.posture["state"] = "Running"
        self.histories = {}
        self.results = {}
        self.evidence = {}
        self.operations = []
        self.failures = set()
        self.crash_after_evidence_create = False
        self.corrupt_evidence_on_create = False
        self._crashed = False

    @property
    def etag(self):
        return f'"etag-{self.etag_number}"'

    def _record(self):
        if self.state_body is None:
            return None
        return watcher.StateRecord(self.state_body, self.etag, self.now)

    def probe_server_time(self):
        self.operations.append("probe-server-time")
        return self.now

    def read_state(self):
        self.operations.append("read-state")
        return self._record()

    def create_state(self, body):
        self.operations.append("create-state")
        if self.state_body is not None:
            raise watcher.CleanupContractError("fake-create-conflict")
        watcher.strict_canonical_json(body, watcher.MAX_SESSION_BYTES, "test-state")
        self.state_body = body
        self.etag_number += 1
        return self._record()

    def replace_state(self, body, etag):
        self.operations.append("replace-state")
        if etag != self.etag:
            raise watcher.CleanupContractError("fake-etag-conflict")
        watcher.strict_canonical_json(body, watcher.MAX_SESSION_BYTES, "test-state")
        self.state_body = body
        self.etag_number += 1
        return self._record()

    def stop_bridge(self):
        self.operations.append("stop-bridge")
        if "stop" in self.failures:
            raise RuntimeError(SECRET)
        self.posture["state"] = "Stopped"

    def reseal_bridge(self):
        self.operations.append("reseal-bridge")
        if "reseal" in self.failures:
            raise RuntimeError(SECRET)
        for key, value in watcher.SEALED_POSTURE.items():
            if key != "state":
                self.posture[key] = value

    def delete_transient_settings(self, names):
        self.operations.append("delete-exact-transient-settings")
        if tuple(names) != watcher.TRANSIENT_SETTINGS:
            raise AssertionError("transient setting boundary widened")
        if "delete-settings" in self.failures:
            raise RuntimeError(SECRET)
        for name in names:
            self.settings.pop(name, None)

    def read_bridge(self):
        self.operations.append("read-bridge")
        if "read-bridge" in self.failures:
            raise RuntimeError(SECRET)
        posture = dict(self.posture)
        if "sabotage-postcondition" in self.failures:
            posture["linuxFxVersion"] = "NODE|24-lts"
        return watcher.BridgeSnapshot(
            watcher.BRIDGE_RESOURCE_ID,
            posture,
            dict(self.settings),
        )

    def read_webjob_history(self, history_id):
        self.operations.append("read-webjob-history")
        return copy.deepcopy(self.histories.get(history_id))

    def read_result(self, container, blob, maximum):
        self.operations.append("read-result")
        if container != watcher.RESULT_CONTAINER or maximum != watcher.MAX_RESULT_BYTES:
            raise AssertionError("result read boundary widened")
        return self.results.get(blob)

    def read_evidence_policy(self):
        self.operations.append("read-evidence-policy")
        if "bad-evidence-policy" in self.failures:
            return watcher.EvidencePolicy(watcher.EVIDENCE_CONTAINER, "Unlocked", 90)
        return watcher.EvidencePolicy(watcher.EVIDENCE_CONTAINER, "Locked", 90)

    def read_authority_fence(self, container, blob, maximum):
        self.operations.append("read-authority-fence")
        if (
            container != watcher.AUTHORITY_FENCE_CONTAINER
            or maximum != watcher.MAX_RECEIPT_BYTES
        ):
            raise AssertionError("authority fence read boundary widened")
        if "missing-authority-fence" in self.failures:
            return None
        session = watcher.strict_canonical_json(
            self.state_body, watcher.MAX_SESSION_BYTES, "test-state"
        )
        if blob != watcher.authority_fence_path(session):
            raise AssertionError("authority fence path widened")
        document = {
            "schema": watcher.AUTHORITY_FENCE_SCHEMA,
            "status": "runner-mutation-authority-fenced",
            "contractId": watcher.CONTRACT_ID,
            "sessionId": session["sessionId"],
            "fence": session["fence"],
            "claimId": session["claimId"],
            "claimedAt": session["claimedAt"],
            "githubRunId": session["githubRunId"],
            "githubRunAttempt": session["githubRunAttempt"],
            "controlWorkflowSha": session["controlWorkflowSha"],
            "runnerAuthorityGenerationSha256": session[
                "runnerAuthorityGenerationSha256"
            ],
            "bridgeResourceId": watcher.BRIDGE_RESOURCE_ID,
            "controlPrincipalObjectId": CONTROL_PRINCIPAL_ID,
            "federatedCredentialResourceId": FEDERATED_CREDENTIAL_ID,
            "mutatingRoleAssignmentIds": MUTATING_ROLE_ASSIGNMENT_IDS,
            "revokedAt": session["claimedAt"],
            "lastPossibleTokenExpiryAt": session["claimedAt"],
            "observedServerTime": session["claimedAt"],
            "producerReviewedCommitSha": FENCE_PRODUCER_SHA,
        }
        if "early-authority-fence" in self.failures:
            document["lastPossibleTokenExpiryAt"] = "2026-08-23T00:12:00.000Z"
        if "future-authority-fence" in self.failures:
            document["revokedAt"] = "2026-08-23T01:00:00.000Z"
            document["lastPossibleTokenExpiryAt"] = "2026-08-23T02:00:00.000Z"
            document["observedServerTime"] = "2026-08-23T02:00:00.000Z"
        if "wrong-authority-coordinates" in self.failures:
            document["controlPrincipalObjectId"] = (
                "33333333-3333-4333-8333-333333333333"
            )
        return watcher.canonical_json(document)

    def create_evidence(self, container, blob, body):
        self.operations.append("create-evidence")
        if container != watcher.EVIDENCE_CONTAINER:
            raise AssertionError("evidence container widened")
        created = blob not in self.evidence
        if created:
            self.evidence[blob] = body + b" " if self.corrupt_evidence_on_create else body
        if self.crash_after_evidence_create and not self._crashed:
            self._crashed = True
            raise RuntimeError("simulated-host-loss-after-create")
        return created

    def read_evidence(self, container, blob, maximum):
        self.operations.append("read-evidence")
        if container != watcher.EVIDENCE_CONTAINER or maximum != watcher.MAX_RECEIPT_BYTES:
            raise AssertionError("evidence read boundary widened")
        return self.evidence.get(blob)

    def install_valid_results(self, session):
        for item in session["expectedExecutions"]:
            self.histories[item["historyId"]] = history_for(item)
            if item["operation"] == "storage-rbac-canary":
                result = storage_result(item)
            elif item["operation"] == "runtime-canary":
                result = runtime_result()
            else:
                result = persistence_result(item, 5 if item["execution"] == 1 else 0)
            self.results[item["resultBlob"]] = envelope_for(item, session, result)


class RegistryBridgeCleanupWatcherTests(unittest.TestCase):
    def setUp(self):
        self.reviewed_sha = CONTROL_SHA

    def test_contract_is_explicitly_dormant_and_fixed(self):
        contract = watcher.load_contract(
            ROOT / "contracts" / "registry_bridge_cleanup_contract.json"
        )
        self.assertIsNone(contract["immutableExternalControl"]["mergedMutatingCommitSha"])
        self.assertEqual(contract["bridge"]["resourceId"], watcher.BRIDGE_RESOURCE_ID)
        self.assertEqual(contract["bridge"]["persistentSettings"], watcher.PERSISTENT_SETTINGS)
        self.assertEqual(contract["bridge"]["transientSettings"], list(watcher.TRANSIENT_SETTINGS))
        self.assertEqual(contract["storage"]["results"]["watcherAccess"], "read-only")
        self.assertEqual(
            contract["storage"]["runnerAuthorityFences"]["watcherAccess"],
            "read-only",
        )
        self.assertFalse(contract["storage"]["results"]["writesAllowed"])
        self.assertFalse(contract["storage"]["acceptedReleases"]["deletesAllowed"])
        with self.assertRaisesRegex(watcher.CleanupContractError, "activation-blocked-null-merged-sha"):
            watcher.CleanupWatcher.from_dormant_contract(FakeBoundary(make_session()))
        with self.assertRaisesRegex(watcher.CleanupContractError, "activation-factory-required"):
            watcher.CleanupWatcher(FakeBoundary(make_session()), CONTROL_SHA)

    def test_open_session_uses_server_time_and_never_replaces_unresolved_state(self):
        boundary = FakeBoundary(None, now="2026-08-23T00:00:00.000Z")
        record = watcher.open_session(
            boundary,
            reviewed_mutating_sha=CONTROL_SHA,
            session_id="abcdef0123456789abcdef0123456789",
            phase="armed",
            mode="preflight",
            lease_owner="github-run-101-2",
            github_run_id="101",
            github_run_attempt="2",
            session_token_sha256=TOKEN_SHA,
            runner_authority_generation_sha256=AUTHORITY_GENERATION_SHA,
            expected_executions=expected_executions("preflight", False),
        )
        session = watcher.read_session_record(record)
        self.assertEqual(session["leaseStartedAt"], boundary.now)
        self.assertEqual(session["fence"], 1)
        self.assertEqual(session["controlWorkflowSha"], CONTROL_SHA)
        self.assertIn("probe-server-time", boundary.operations)
        with self.assertRaisesRegex(watcher.CleanupContractError, "open-session-unresolved-prior"):
            watcher.open_session(
                boundary,
                reviewed_mutating_sha=CONTROL_SHA,
                session_id="fedcba9876543210fedcba9876543210",
                phase="armed",
                mode="preflight",
                lease_owner="github-run-102-1",
                github_run_id="102",
                github_run_attempt="1",
                session_token_sha256="1" * 64,
                runner_authority_generation_sha256="8" * 64,
                expected_executions=expected_executions("preflight", False),
            )

    def test_fenced_heartbeat_expiry_claim_and_reclaim(self):
        session = make_session(bound=False)
        boundary = FakeBoundary(session, now="2026-08-23T00:05:00.000Z")
        updated = copy.deepcopy(session["expectedExecutions"])
        updated[0]["historyId"] = f"{watcher.HISTORY_RESOURCE_PREFIX}history-new"
        updated[0]["webJobsRunId"] = "webjob-new"
        record = watcher.heartbeat_session(
            boundary,
            session_id=session["sessionId"],
            fence=1,
            lease_owner=session["leaseOwner"],
            phase="webjob-triggered",
            expected_executions=updated,
        )
        heartbeated = watcher.read_session_record(record)
        self.assertEqual(heartbeated["fence"], 1)
        self.assertEqual(heartbeated["phase"], "webjob-triggered")
        with self.assertRaisesRegex(watcher.CleanupContractError, "heartbeat-fenced"):
            watcher.heartbeat_session(
                boundary,
                session_id=session["sessionId"],
                fence=2,
                lease_owner=session["leaseOwner"],
                phase="webjob-triggered",
                expected_executions=updated,
            )
        boundary.now = "2026-08-23T00:16:00.000Z"
        with self.assertRaisesRegex(watcher.CleanupContractError, "heartbeat-expired"):
            watcher.heartbeat_session(
                boundary,
                session_id=session["sessionId"],
                fence=1,
                lease_owner=session["leaseOwner"],
                phase="result-observed",
                expected_executions=updated,
            )
        first = watcher.claim_expired_session(boundary, "watcher-a")
        self.assertIsNotNone(first)
        self.assertEqual(first.session["fence"], 2)
        retry = watcher.claim_expired_session(boundary, "watcher-a")
        self.assertEqual(retry.session["claimId"], first.session["claimId"])
        self.assertEqual(retry.session["fence"], first.session["fence"])
        self.assertIsNone(watcher.claim_expired_session(boundary, "watcher-b"))
        boundary.now = "2026-08-23T00:27:00.000Z"
        reclaimed = watcher.claim_expired_session(boundary, "watcher-b")
        self.assertEqual(reclaimed.session["fence"], 3)
        self.assertNotEqual(reclaimed.session["claimId"], first.session["claimId"])

    def test_every_runner_loss_phase_is_stopped_resealed_and_indeterminate_without_results(self):
        for phase in watcher.PHASES:
            with self.subTest(phase=phase):
                session = make_session(phase=phase, bound=False)
                boundary = FakeBoundary(session)
                receipt = sweep_review(boundary, self.reviewed_sha)
                self.assertEqual(receipt["status"], "sealed-indeterminate")
                self.assertEqual(receipt["session"]["phaseAtExpiry"], phase)
                self.assertEqual(receipt["bridge"]["assessment"]["bridgePostcondition"]["status"], "sealed")
                self.assertIn("stop-bridge", boundary.operations)
                self.assertIn("reseal-bridge", boundary.operations)
                self.assertIn("delete-exact-transient-settings", boundary.operations)
                self.assertEqual(set(boundary.settings), set(watcher.PERSISTENT_SETTINGS))
                self.assertNotIn(SECRET.encode(), next(iter(boundary.evidence.values())))

    def test_complete_preflight_requires_every_exact_history_and_envelope(self):
        session = make_session(phase="runner-complete", bound=True)
        boundary = FakeBoundary(session)
        boundary.install_valid_results(session)
        receipt = sweep_review(boundary, self.reviewed_sha)
        assessment = receipt["bridge"]["assessment"]
        self.assertEqual(receipt["status"], "sealed-reconciled")
        self.assertEqual(assessment["issues"], [])
        self.assertEqual(assessment["resultReconciliation"]["status"], "reconciled")
        self.assertEqual(
            [entry["status"] for entry in assessment["resultReconciliation"]["executions"]],
            ["valid", "valid"],
        )
        state = watcher.read_session_record(boundary._record())
        self.assertEqual(state["status"], "closed")
        evidence_body = next(iter(boundary.evidence.values()))
        self.assertEqual(evidence_body, watcher.canonical_json(json.loads(evidence_body)))
        self.assertEqual(
            receipt["authoritativeness"],
            "requires-matching-immutable-closure-marker",
        )
        self.assertEqual(len(boundary.evidence), 2)
        self.assertIn(watcher.closure_marker_path(state), boundary.evidence)
        fence_index = boundary.operations.index("read-authority-fence")
        stop_indexes = [
            index for index, operation in enumerate(boundary.operations)
            if operation == "stop-bridge"
        ]
        self.assertGreaterEqual(len(stop_indexes), 2)
        self.assertLess(fence_index, stop_indexes[-1])
        self.assertEqual(
            receipt["authorityFence"]["runnerAuthorityGenerationSha256"],
            AUTHORITY_GENERATION_SHA,
        )

    def test_reviewed_sha_must_match_session_before_cleanup_or_evidence(self):
        session = make_session(phase="runner-complete", bound=True)
        boundary = FakeBoundary(session)
        boundary.install_valid_results(session)
        claim = watcher.claim_expired_session(boundary, "watcher-a")
        with self.assertRaisesRegex(
            watcher.CleanupContractError, "reviewed-mutating-sha-mismatch"
        ):
            watcher.reconcile_claim(boundary, claim, "9" * 40)
        self.assertNotIn("stop-bridge", boundary.operations)
        self.assertEqual(boundary.evidence, {})

    def test_forged_or_stale_assessment_cannot_skip_fresh_cleanup(self):
        session = make_session(phase="runner-complete", bound=True)
        boundary = FakeBoundary(session)
        boundary.install_valid_results(session)
        claim = watcher.claim_expired_session(boundary, "watcher-a")
        with self.assertRaisesRegex(watcher.CleanupContractError, "assessment-not-fresh"):
            watcher.stage_assessment(boundary, claim, {"outcome": "complete"})
        self.assertIn("stop-bridge", boundary.operations)
        self.assertIn("reseal-bridge", boundary.operations)
        self.assertIn("delete-exact-transient-settings", boundary.operations)
        self.assertEqual(boundary.evidence, {})

        claim = watcher.claim_expired_session(boundary, "watcher-a")
        claim = watcher.stage_assessment(boundary, claim)
        missing_blob = claim.session["expectedExecutions"][0]["resultBlob"]
        boundary.results.pop(missing_blob)
        with self.assertRaisesRegex(
            watcher.CleanupContractError, "receipt-assessment-not-fresh"
        ):
            watcher.create_or_replay_receipt(boundary, claim, CONTROL_SHA)
        self.assertEqual(boundary.evidence, {})

    def test_expired_or_stolen_claim_cannot_create_evidence(self):
        for scenario in ("expired", "stolen"):
            with self.subTest(scenario=scenario):
                session = make_session(phase="runner-complete", bound=True)
                boundary = FakeBoundary(session)
                boundary.install_valid_results(session)
                claim = watcher.claim_expired_session(boundary, "watcher-a")
                claim = watcher.stage_assessment(boundary, claim)
                boundary.now = "2026-08-23T00:22:00.000Z"
                expected_error = "receipt-claim-expired"
                if scenario == "stolen":
                    replacement = watcher.claim_expired_session(boundary, "watcher-b")
                    self.assertGreater(replacement.session["fence"], claim.session["fence"])
                    expected_error = "authority-fence-fenced"
                with self.assertRaisesRegex(watcher.CleanupContractError, expected_error):
                    watcher.create_or_replay_receipt(boundary, claim, CONTROL_SHA)
                self.assertEqual(boundary.evidence, {})

    def test_missing_independent_authority_fence_prevents_any_receipt(self):
        session = make_session(phase="runner-complete", bound=True)
        boundary = FakeBoundary(session)
        boundary.install_valid_results(session)
        boundary.failures.add("missing-authority-fence")
        with self.assertRaisesRegex(watcher.CleanupContractError, "authority-fence-missing"):
            sweep_review(boundary)
        self.assertEqual(boundary.evidence, {})
        self.assertIn("read-authority-fence", boundary.operations)
        boundary = FakeBoundary(session)
        boundary.install_valid_results(session)
        boundary.failures.add("early-authority-fence")
        with self.assertRaisesRegex(watcher.CleanupContractError, "authority-fence-time-order"):
            sweep_review(boundary)
        self.assertEqual(boundary.evidence, {})
        boundary = FakeBoundary(session)
        boundary.install_valid_results(session)
        boundary.failures.add("future-authority-fence")
        with self.assertRaisesRegex(
            watcher.CleanupContractError,
            "authority-fence-not-yet-observed",
        ):
            sweep_review(boundary)
        self.assertEqual(boundary.evidence, {})
        boundary = FakeBoundary(session)
        boundary.install_valid_results(session)
        boundary.failures.add("wrong-authority-coordinates")
        with self.assertRaisesRegex(
            watcher.CleanupContractError,
            "authority-fence-generation-digest",
        ):
            sweep_review(boundary)
        self.assertEqual(boundary.evidence, {})

    def test_history_ids_runs_and_timestamps_are_distinct_and_bound(self):
        session = make_session(phase="runner-complete", bound=True)
        duplicate_history = copy.deepcopy(session)
        duplicate_history["expectedExecutions"][1]["historyId"] = (
            duplicate_history["expectedExecutions"][0]["historyId"]
        )
        with self.assertRaisesRegex(watcher.CleanupContractError, "session-execution-reuse"):
            watcher.validate_session(duplicate_history)

        duplicate_run = copy.deepcopy(session)
        duplicate_run["expectedExecutions"][1]["webJobsRunId"] = (
            duplicate_run["expectedExecutions"][0]["webJobsRunId"]
        )
        with self.assertRaisesRegex(watcher.CleanupContractError, "session-execution-reuse"):
            watcher.validate_session(duplicate_run)

        wrong_resource = copy.deepcopy(session)
        wrong_resource["expectedExecutions"][0]["historyId"] = (
            "/subscriptions/other/triggeredwebjobs/wrong/history/run-1"
        )
        with self.assertRaisesRegex(watcher.CleanupContractError, "session-history-id"):
            watcher.validate_session(wrong_resource)

        boundary = FakeBoundary(session)
        boundary.install_valid_results(session)
        first = session["expectedExecutions"][0]
        boundary.histories[first["historyId"]]["end_time"] = (
            "2026-08-23T00:00:59.999999999Z"
        )
        receipt = sweep_review(boundary)
        self.assertEqual(receipt["status"], "sealed-indeterminate")
        self.assertIn(
            "result:preflight-storage:1:history-time-order",
            receipt["bridge"]["assessment"]["issues"],
        )

    def test_missing_partial_and_webjob_id_mismatch_are_indeterminate(self):
        cases = ("missing", "partial", "mismatch")
        for case in cases:
            with self.subTest(case=case):
                session = make_session(phase="result-observed", bound=True)
                boundary = FakeBoundary(session)
                boundary.install_valid_results(session)
                second = session["expectedExecutions"][1]
                if case == "missing":
                    boundary.results.pop(second["resultBlob"])
                elif case == "partial":
                    boundary.histories.pop(second["historyId"])
                else:
                    boundary.histories[second["historyId"]]["web_job_id"] = "different-run"
                receipt = sweep_review(boundary, self.reviewed_sha)
                self.assertEqual(receipt["status"], "sealed-indeterminate")
                reconciliation = receipt["bridge"]["assessment"]["resultReconciliation"]
                self.assertEqual(reconciliation["status"], "indeterminate")
                self.assertIn("indeterminate", [entry["status"] for entry in reconciliation["executions"]])

    def test_persistence_pair_must_prove_create_then_idempotent_replay(self):
        session = make_session(phase="runner-complete", mode="persistence", bound=True)
        boundary = FakeBoundary(session)
        boundary.install_valid_results(session)
        receipt = sweep_review(boundary, self.reviewed_sha)
        reconciliation = receipt["bridge"]["assessment"]["resultReconciliation"]
        self.assertEqual(receipt["status"], "sealed-reconciled")
        self.assertEqual(reconciliation["persistenceCase"], "created-or-recovered-then-idempotent")

        invalid_session = make_session(phase="runner-complete", mode="persistence", bound=True)
        invalid_boundary = FakeBoundary(invalid_session)
        invalid_boundary.install_valid_results(invalid_session)
        second = invalid_session["expectedExecutions"][2]
        invalid = persistence_result(second, 4)
        invalid_boundary.results[second["resultBlob"]] = envelope_for(second, invalid_session, invalid)
        invalid_receipt = sweep_review(invalid_boundary, self.reviewed_sha)
        self.assertEqual(invalid_receipt["status"], "sealed-indeterminate")
        self.assertIsNone(
            invalid_receipt["bridge"]["assessment"]["resultReconciliation"]["persistenceCase"]
        )

    def test_unknown_setting_cleanup_failure_and_postcondition_failure_fail_closed(self):
        scenarios = ("unknown", "cleanup", "postcondition")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                session = make_session(phase="runner-complete", bound=True)
                boundary = FakeBoundary(session)
                boundary.install_valid_results(session)
                if scenario == "unknown":
                    boundary.settings["UNREVIEWED_SETTING"] = SECRET
                elif scenario == "cleanup":
                    boundary.failures.add("delete-settings")
                else:
                    boundary.failures.add("sabotage-postcondition")
                receipt = sweep_review(boundary, self.reviewed_sha)
                self.assertEqual(receipt["status"], "sealed-indeterminate")
                body = watcher.canonical_json(receipt)
                self.assertNotIn(SECRET.encode(), body)
                self.assertNotIn(b"UNREVIEWED_SETTING", body)
                self.assertTrue(receipt["bridge"]["assessment"]["issues"])

    def test_cleanup_exceptions_are_reduced_to_safe_codes(self):
        session = make_session(phase="bridge-started", bound=False)
        boundary = FakeBoundary(session)
        boundary.failures.update({"stop", "reseal", "delete-settings", "read-bridge"})
        receipt = sweep_review(boundary, self.reviewed_sha)
        body = watcher.canonical_json(receipt)
        self.assertEqual(receipt["status"], "sealed-indeterminate")
        self.assertNotIn(SECRET.encode(), body)
        self.assertIn(b"cleanup:stop:failed", body)
        self.assertIn(b"bridge-postcondition-unavailable", body)

    def test_crash_after_create_replays_exact_receipt_and_closes_state(self):
        session = make_session(phase="runner-complete", bound=True)
        boundary = FakeBoundary(session)
        boundary.install_valid_results(session)
        boundary.crash_after_evidence_create = True
        with self.assertRaisesRegex(RuntimeError, "simulated-host-loss-after-create"):
            sweep_review(boundary, self.reviewed_sha)
        self.assertEqual(len(boundary.evidence), 1)
        first_path, first_body = next(iter(boundary.evidence.items()))
        staged = watcher.read_session_record(boundary._record())
        self.assertEqual(staged["status"], "cleanup-claimed")
        self.assertIsNotNone(staged["assessment"])
        replay = sweep_review(boundary, self.reviewed_sha)
        self.assertEqual(replay["status"], "sealed-reconciled")
        self.assertEqual(boundary.evidence[first_path], first_body)
        self.assertIn("read-evidence", boundary.operations)
        closed = watcher.read_session_record(boundary._record())
        self.assertEqual(closed["status"], "closed")
        self.assertEqual(closed["receipt"]["sha256"], hashlib.sha256(first_body).hexdigest())
        self.assertEqual(len(boundary.evidence), 2)

    def test_immutable_closure_marker_survives_next_singleton_session(self):
        session = make_session(phase="runner-complete", bound=True)
        boundary = FakeBoundary(session)
        boundary.install_valid_results(session)
        sweep_review(boundary)
        closed_record = boundary._record()
        closed = watcher.read_session_record(closed_record)
        marker_path = watcher.closure_marker_path(closed)
        marker_body = boundary.evidence[marker_path]
        boundary.now = "2026-08-23T01:00:00.000Z"
        next_executions = expected_executions("preflight", False)
        for item in next_executions:
            item["resultBlob"] = (
                f'v1/results/202/1/{item["purpose"]}/{item["execution"]}/'
                f'{item["nonce"]}.json'
            )
        with self.assertRaisesRegex(
            watcher.CleanupContractError,
            "open-session-authority-generation-reuse",
        ):
            watcher.open_session(
                boundary,
                reviewed_mutating_sha=CONTROL_SHA,
                session_id="abcdef0123456789abcdef0123456789",
                phase="armed",
                mode="preflight",
                lease_owner="github-run-202-1",
                github_run_id="202",
                github_run_attempt="1",
                session_token_sha256="7" * 64,
                runner_authority_generation_sha256=AUTHORITY_GENERATION_SHA,
                expected_executions=next_executions,
            )
        opened = watcher.open_session(
            boundary,
            reviewed_mutating_sha=CONTROL_SHA,
            session_id="abcdef0123456789abcdef0123456789",
            phase="armed",
            mode="preflight",
            lease_owner="github-run-202-1",
            github_run_id="202",
            github_run_attempt="1",
            session_token_sha256="7" * 64,
            runner_authority_generation_sha256="8" * 64,
            expected_executions=next_executions,
        )
        self.assertEqual(boundary.evidence[marker_path], marker_body)
        opened_session = watcher.read_session_record(opened)
        self.assertEqual(opened_session["leaseStartedAt"], boundary.now)
        marker = watcher.strict_canonical_json(
            marker_body, watcher.MAX_RECEIPT_BYTES, "test-closure"
        )
        self.assertEqual(marker["closedStateSha256"], watcher.digest_bytes(closed_record.body))

    def test_existing_different_receipt_is_a_hard_idempotency_conflict(self):
        session = make_session(phase="runner-complete", bound=True)
        boundary = FakeBoundary(session)
        boundary.install_valid_results(session)
        claim = watcher.claim_expired_session(boundary, "watcher-a")
        assessment = watcher.assess_cleanup(boundary, claim.session)
        claim = watcher.stage_assessment(boundary, claim, assessment)
        path = watcher.receipt_path(claim.session)
        boundary.evidence[path] = b'{"different":true}\n'
        with self.assertRaisesRegex(watcher.CleanupContractError, "receipt-idempotency-conflict"):
            watcher.reconcile_claim(boundary, claim, self.reviewed_sha)

    def test_first_evidence_create_is_always_read_back_exactly(self):
        session = make_session(phase="runner-complete", bound=True)
        boundary = FakeBoundary(session)
        boundary.install_valid_results(session)
        boundary.corrupt_evidence_on_create = True
        with self.assertRaisesRegex(
            watcher.CleanupContractError, "receipt-idempotency-conflict"
        ):
            sweep_review(boundary)
        self.assertIn("read-evidence", boundary.operations)
        staged = watcher.read_session_record(boundary._record())
        self.assertEqual(staged["status"], "cleanup-claimed")
        self.assertIsNone(staged["receipt"])

    def test_closed_receipt_reference_is_exact_and_assessment_bound(self):
        session = make_session(phase="runner-complete", bound=True)
        boundary = FakeBoundary(session)
        boundary.install_valid_results(session)
        sweep_review(boundary)
        closed = watcher.read_session_record(boundary._record())
        forged = copy.deepcopy(closed)
        forged["receipt"]["unexpected"] = True
        with self.assertRaisesRegex(watcher.CleanupContractError, "session-receipt-fields"):
            watcher.validate_session(forged)
        forged = copy.deepcopy(closed)
        forged["receipt"]["status"] = "sealed-indeterminate"
        with self.assertRaisesRegex(watcher.CleanupContractError, "session-receipt-binding"):
            watcher.validate_session(forged)

    def test_unlocked_evidence_policy_prevents_receipt_write(self):
        session = make_session(phase="runner-complete", bound=True)
        boundary = FakeBoundary(session)
        boundary.install_valid_results(session)
        boundary.failures.add("bad-evidence-policy")
        with self.assertRaisesRegex(watcher.CleanupContractError, "evidence-policy-invalid"):
            sweep_review(boundary, self.reviewed_sha)
        self.assertEqual(boundary.evidence, {})

    def test_authority_surface_has_no_start_run_deploy_role_or_blob_delete(self):
        session = make_session(phase="runner-complete", bound=True)
        boundary = FakeBoundary(session)
        boundary.install_valid_results(session)
        sweep_review(boundary, self.reviewed_sha)
        allowed = {
            "read-state",
            "replace-state",
            "stop-bridge",
            "reseal-bridge",
            "delete-exact-transient-settings",
            "read-bridge",
            "read-webjob-history",
            "read-result",
            "read-evidence-policy",
            "read-authority-fence",
            "create-evidence",
            "read-evidence",
            "probe-server-time",
            "create-state",
        }
        self.assertLessEqual(set(boundary.operations), allowed)
        self.assertNotIn(watcher.ACCEPTED_RELEASE_CONTAINER, " ".join(boundary.operations))
        source = (ROOT / "provider" / "registry_bridge_cleanup_watcher.py").read_text(encoding="utf-8")
        protocol = source.split("class CleanupBoundary(Protocol):", 1)[1].split("def _expected_blob", 1)[0]
        for forbidden_method in (
            "start_bridge", "run_webjob", "deploy", "publish", "write_role",
            "write_result", "delete_blob", "delete_result", "delete_accepted",
        ):
            self.assertNotIn(f"def {forbidden_method}", protocol)

    def test_deterministic_package_has_exact_review_inventory(self):
        contract_path = ROOT / "contracts" / "registry_bridge_cleanup_contract.json"
        normalized_contract = contract_path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
        self.assertEqual(hashlib.sha256(normalized_contract).hexdigest(), watcher.CONTRACT_SHA256)
        self.assertEqual(builder.CONTRACT_SHA256, watcher.CONTRACT_SHA256)
        self.assertEqual(watcher.load_contract(contract_path)["contractId"], watcher.CONTRACT_ID)
        with self.assertRaisesRegex(builder.PackageError, "duplicate"):
            builder.validate_contract(b'{"schemaVersion":1,"schemaVersion":1}')
        with self.assertRaisesRegex(builder.PackageError, "digest"):
            builder.validate_contract(b'{"schemaVersion":1}')
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first.zip"
            second = Path(temporary) / "second.zip"
            manifest = builder.build(first)
            second_manifest = builder.build(second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(manifest["packageSha256"], hashlib.sha256(first.read_bytes()).hexdigest())
            self.assertEqual(manifest["packageSha256"], second_manifest["packageSha256"])
            self.assertEqual(manifest["status"], "built-source-ready-activation-blocked")
            self.assertIsNone(manifest["mergedMutatingCommitSha"])
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(archive.namelist(), [member for _, member, _, _ in builder.SOURCES])
                for info in archive.infolist():
                    self.assertEqual(info.date_time, builder.FIXED_TIMESTAMP)
                contract = json.loads(archive.read("contracts/registry_bridge_cleanup_contract.json"))
                self.assertIsNone(contract["immutableExternalControl"]["mergedMutatingCommitSha"])


if __name__ == "__main__":
    unittest.main()
