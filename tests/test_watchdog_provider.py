from datetime import datetime, timezone
import base64
import copy
import hashlib
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from provider import watchdog_state_provider as provider
from scripts import watchdog_contract
from tests.test_watchdog_contract import CONTROL_SHA, oidc_for, request_fixtures
from tests import test_provider_accepted_release_manifest as registry_fixture


NOW = datetime(2026, 8, 23, 1, 0, 0, tzinfo=timezone.utc)
SHA_A = "1" * 40
SHA_B = "2" * 40
SHA_C = "3" * 40
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
CLAIM_ID = "123e4567-e89b-42d3-a456-426614174000"


def baseline(source_sha=SHA_B, receipt_sha=DIGEST_A):
    return {
        "schemaVersion": 2,
        "receiptSha256": receipt_sha,
        "evidencePath": "v2/baselines/202/1/initial.json",
        "sourceSha": source_sha,
        "sourceRunId": "88",
        "sourceRunAttempt": "1",
        "acceptanceRunId": "99",
        "acceptanceRunAttempt": "1",
        "acceptedReleaseManifestSha256": DIGEST_B,
        "acceptedReleasePrefix": f"v1/releases/{source_sha}/88/99/",
        "reviewWorkflowRef": (
            "Sethvirak/paperdesk-release-verifier/.github/workflows/"
            "initialize-watchdog-rollback-baseline.yml@refs/heads/main"
        ),
        "reviewWorkflowSha": CONTROL_SHA,
        "reviewRunId": "202",
        "reviewRunAttempt": "1",
        "reviewEnvironment": "paperdesk-watchdog-baseline",
        "preparedAt": "2026-08-22T00:00:00.000Z",
    }


def guard(status="available", generation=1, **changes):
    value = {
        "status": status,
        "generation": generation,
        "claimId": None,
        "leaseExpiresAt": None,
        "watchdogRunId": None,
        "watchdogRunAttempt": None,
        "decisionReceiptSha256": None,
        "decisionEvidenceETag": None,
        "attemptReceiptSha256": None,
        "workflowRunId": None,
        "authorizationReceiptSha256": None,
    }
    if status != "available":
        value.update({
            "claimId": CLAIM_ID,
            "leaseExpiresAt": "2026-08-23T01:05:00.000Z",
            "watchdogRunId": "700",
            "watchdogRunAttempt": "1",
            "decisionReceiptSha256": DIGEST_B,
            "decisionEvidenceETag": '"decision-etag"',
        })
    if status in {"dispatching", "requested", "authorized"}:
        value["attemptReceiptSha256"] = DIGEST_C
    if status in {"requested", "authorized"}:
        value["workflowRunId"] = "303"
    if status == "authorized":
        value["authorizationReceiptSha256"] = DIGEST_A
    value.update(changes)
    return value


def pending(
    status="available",
    generation=1,
    *,
    completed_at="2026-08-23T00:00:00.000Z",
    deadline="2026-08-24T00:00:00.000Z",
    **guard_changes,
):
    return {
        "candidateSha": SHA_A,
        "candidateRunId": "101",
        "candidateRunAttempt": "2",
        "completedAt": completed_at,
        "deadline": deadline,
        "acceptedReceiptPresent": False,
        "liveSha": SHA_A,
        "dispatchGuard": guard(status, generation, **guard_changes),
        "rollback": {
            "sourceSha": SHA_B,
            "sourceRunId": "88",
            "sourceRunAttempt": "1",
            "acceptanceRunId": "99",
            "acceptanceRunAttempt": "1",
            "baselineReceiptSha256": DIGEST_A,
        },
    }


def state(pending_candidate=None, rollback_baseline=None):
    return {
        "schemaVersion": 2,
        "generatedAt": "2026-08-23T00:00:00.000Z",
        "sourceRepository": {
            "repository": "Sethvirak/MasterDataStructure",
            "repositoryId": "1287744543",
            "repositoryOwner": "Sethvirak",
            "repositoryOwnerId": "202535166",
            "ref": "refs/heads/main",
        },
        "rollbackBaseline": rollback_baseline or baseline(),
        "pendingCandidate": pending_candidate,
    }


class MemoryStorage(provider.StorageBackend):
    def __init__(self):
        self.blobs = {}
        self.counter = 0
        self.events = []
        self.fail_next_replace = False
        self.competing_replace_body = None
        self.competing_replace_metadata = None
        self.after_successful_replace = None

    def _record(self, body, metadata):
        self.counter += 1
        return provider.BlobRecord(
            body=bytes(body), etag=f'"blob-{self.counter}"',
            version_id=f"version-{self.counter}", metadata=dict(metadata),
        )

    def seed(self, container, path, body, metadata=None):
        if metadata is None and container == provider.STATE_CONTAINER:
            document = __import__("json").loads(body)
            metadata = {
                "paperdesk_sha256": hashlib.sha256(body).hexdigest(),
                "paperdesk_schema": "2",
                "paperdesk_initial_baseline_sha256": document["rollbackBaseline"]["receiptSha256"],
            }
        self.blobs[(container, path)] = self._record(body, metadata or {})

    def get_blob(self, container, path, maximum):
        self.events.append(("get", container, path))
        record = self.blobs.get((container, path))
        if record is not None and len(record.body) > maximum:
            raise AssertionError("bounded read exceeded")
        return record

    def put_create(self, container, path, body, metadata):
        self.events.append(("create", container, path))
        key = (container, path)
        if key in self.blobs:
            return False
        self.blobs[key] = self._record(body, metadata)
        return True

    def put_replace(self, container, path, body, expected_etag, metadata):
        self.events.append(("replace", container, path))
        key = (container, path)
        if self.fail_next_replace:
            self.fail_next_replace = False
            return None
        if self.competing_replace_body is not None:
            body = self.competing_replace_body
            self.competing_replace_body = None
            competing_metadata = self.competing_replace_metadata or {
                **metadata,
                "paperdesk_sha256": hashlib.sha256(body).hexdigest(),
                "paperdesk_last_transition_sha256": "e" * 64,
            }
            self.competing_replace_metadata = None
            self.blobs[key] = self._record(body, competing_metadata)
            return None
        current = self.blobs.get(key)
        if current is None or current.etag != expected_etag:
            return None
        written = self._record(body, metadata)
        self.blobs[key] = written
        callback = self.after_successful_replace
        if callback is not None:
            callback(written)
        return provider.BlobWriteReceipt(
            etag=written.etag,
            version_id=written.version_id,
        )

    def policy(self, container):
        return {
            "state": "Locked", "immutabilityPeriodSinceCreationInDays": 90,
            "allowProtectedAppendWrites": False, "allowProtectedAppendWritesAll": False,
            "etag": f'"policy-{container}"', "observedAt": "2026-08-23T01:00:00.000Z",
        }


class RegistryValidator:
    def __init__(self, promoted=None):
        self.promoted = promoted or baseline(SHA_A, DIGEST_C)
        self.calls = []

    def __call__(self, storage, request, pending_candidate, claims):
        self.calls.append((storage, copy.deepcopy(request), copy.deepcopy(pending_candidate), copy.deepcopy(claims)))
        return copy.deepcopy(self.promoted)


class FakeDispatcher:
    configured = True

    def __init__(self, run_id="303"):
        self.run_id = run_id
        self.calls = []
        self.after_dispatch = None

    def dispatch(self, attempt):
        self.calls.append(copy.deepcopy(attempt))
        if self.after_dispatch is not None:
            self.after_dispatch()
        return provider.GithubDispatchResult(
            workflow_run_id=self.run_id,
            workflow_run_api_url=f"https://api.github.com/repos/Sethvirak/MasterDataStructure/actions/runs/{self.run_id}",
            workflow_run_html_url=f"https://github.com/Sethvirak/MasterDataStructure/actions/runs/{self.run_id}",
            github_request_id="ABCD:1234",
        )


def watchdog_claims(run_id="700", run_attempt="1"):
    return {
        "repository": "Sethvirak/paperdesk-release-verifier",
        "repository_id": "1333353701", "repository_owner_id": "202535166",
        "workflow_ref": (
            "Sethvirak/paperdesk-release-verifier/.github/workflows/"
            "accepted-release-deadline-watchdog.yml@refs/heads/main"
        ),
        "workflow_sha": CONTROL_SHA, "sha": CONTROL_SHA,
        "run_id": run_id, "run_attempt": run_attempt,
        "environment": "paperdesk-watchdog",
    }


class FakeJWT:
    class PyJWTError(Exception):
        pass

    class PyJWK:
        @staticmethod
        def from_dict(_jwk, algorithm):
            if algorithm != "RS256":
                raise AssertionError("unexpected algorithm")
            return SimpleNamespace(key="public-key")

    def __init__(self, claims):
        self.claims = claims

    @staticmethod
    def get_unverified_header(_token):
        return {"alg": "RS256", "typ": "JWT", "kid": "test-key"}

    def decode(self, *_args, **_kwargs):
        return dict(self.claims)


def decision_receipt(current_sha):
    return {
        "schemaVersion": 2, "receiptType": "watchdog-decision",
        "decision": "dispatch-rollback", "sourceRepository": "Sethvirak/MasterDataStructure",
        "candidateSha": SHA_A, "candidateRunId": "101", "candidateRunAttempt": "2",
        "expectedCurrentLiveSha": SHA_A, "watchdogRunId": "700", "watchdogRunAttempt": "1",
        "observedStateSha256": current_sha, "decidedAt": "2026-08-23T01:00:00.000Z",
    }


class WatchdogProviderTransitionTests(unittest.TestCase):
    def setUp(self):
        self.machine = watchdog_contract.load_contract()
        self.storage = MemoryStorage()
        self.registry = RegistryValidator()
        self.dispatcher = FakeDispatcher()
        self.service = provider.WatchdogProvider(
            self.storage, self.dispatcher, registry_validator=self.registry,
            contract=self.machine, clock=lambda: NOW,
            uuid_factory=lambda: __import__("uuid").UUID(CLAIM_ID),
        )

    def seed_state(self, document):
        self.storage.seed(provider.STATE_CONTAINER, provider.STATE_BLOB, provider.canonical_json(document))
        return self.service.state_snapshot()

    def seed_guard_evidence(self, pending_document):
        guard_value = pending_document["dispatchGuard"]
        prefix = f"v2/watchdog-runs/{guard_value['watchdogRunId']}/{guard_value['watchdogRunAttempt']}/"
        decision_raw = provider.canonical_json({"kind": "decision", "claimId": guard_value["claimId"]})
        self.storage.seed(provider.EVIDENCE_CONTAINER, prefix + "decision.json", decision_raw)
        decision_record = self.storage.blobs[(provider.EVIDENCE_CONTAINER, prefix + "decision.json")]
        guard_value["decisionReceiptSha256"] = __import__("hashlib").sha256(decision_raw).hexdigest()
        guard_value["decisionEvidenceETag"] = decision_record.etag
        attempt_raw = provider.canonical_json({
            "claimId": guard_value["claimId"],
            "dispatchGuardGeneration": guard_value["generation"],
            "decisionReceiptSha256": guard_value["decisionReceiptSha256"],
        })
        self.storage.seed(provider.EVIDENCE_CONTAINER, prefix + "dispatch-attempt.json", attempt_raw)
        guard_value["attemptReceiptSha256"] = __import__("hashlib").sha256(attempt_raw).hexdigest()
        if guard_value.get("workflowRunId") is not None:
            self.storage.seed(
                provider.EVIDENCE_CONTAINER,
                prefix + "dispatch-requested.json",
                provider.canonical_json({"workflowRunId": guard_value["workflowRunId"]}),
            )

    def transition(self, request, claims=None):
        claims = claims or oidc_for(self.machine, request)
        return self.service.transition(
            provider.canonical_json(request), f'"{request["expectedStateSha256"]}"', claims,
        )

    def test_publish_writes_and_reads_worm_before_state_cas_then_exact_replay_is_200(self):
        snapshot = self.seed_state(state())
        request = request_fixtures()["publish-candidate"]
        request["expectedStateSha256"] = snapshot.sha256
        request["rollbackBaselineReceiptSha256"] = DIGEST_A
        first = self.transition(request)
        self.assertEqual(first.status_code, 201)
        self.assertEqual(first.document["status"], "candidate-published")
        self.assertEqual(self.service.state_snapshot().document["pendingCandidate"], pending())
        create_index = next(i for i, event in enumerate(self.storage.events) if event[0] == "create")
        replace_index = next(i for i, event in enumerate(self.storage.events) if event[0] == "replace")
        self.assertLess(create_index, replace_index)
        replace_count = sum(event[0] == "replace" for event in self.storage.events)
        replay = self.transition(request)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.document, first.document)
        self.assertEqual(sum(event[0] == "replace" for event in self.storage.events), replace_count)

        changed_replay = copy.deepcopy(request)
        changed_replay["verificationReceiptSha256"] = "f" * 64
        with self.assertRaises(provider.ProviderError) as caught:
            self.transition(changed_replay)
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(sum(event[0] == "replace" for event in self.storage.events), replace_count)

    def test_stale_state_etag_is_412_and_creates_no_evidence(self):
        self.seed_state(state())
        request = request_fixtures()["publish-candidate"]
        with self.assertRaises(provider.ProviderError) as caught:
            self.transition(request)
        self.assertEqual(caught.exception.status, 412)
        self.assertFalse(any(event[0] == "create" for event in self.storage.events))

    def test_cas_loss_fails_closed_after_durable_receipt_and_retry_finishes_same_transition(self):
        snapshot = self.seed_state(state())
        request = request_fixtures()["publish-candidate"]
        request["expectedStateSha256"] = snapshot.sha256
        request["rollbackBaselineReceiptSha256"] = DIGEST_A
        self.storage.fail_next_replace = True
        with self.assertRaises(provider.ProviderError) as caught:
            self.transition(request)
        self.assertEqual(caught.exception.status, 409)
        self.assertIsNone(self.service.state_snapshot().document["pendingCandidate"])
        self.assertTrue(any(event[0] == "create" for event in self.storage.events))
        recovered = self.transition(request)
        self.assertEqual(recovered.status_code, 201)
        self.assertEqual(self.service.state_snapshot().document["pendingCandidate"], pending())

    def test_competing_state_winner_never_becomes_a_false_200_replay(self):
        snapshot = self.seed_state(state())
        request = request_fixtures()["publish-candidate"]
        request["expectedStateSha256"] = snapshot.sha256
        request["rollbackBaselineReceiptSha256"] = DIGEST_A
        competing = state()
        competing["generatedAt"] = "2026-08-23T00:00:01.000Z"
        self.storage.competing_replace_body = provider.canonical_json(competing)
        with self.assertRaises(provider.ProviderError) as caught:
            self.transition(request)
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(self.service.state_snapshot().document, competing)
        with self.assertRaisesRegex(provider.ProviderError, "competing current state") as replay:
            self.transition(request)
        self.assertEqual(replay.exception.status, 409)

    def test_successful_transition_is_acknowledged_when_a_valid_successor_wins_before_readback(self):
        snapshot = self.seed_state(state())
        request = request_fixtures()["publish-candidate"]
        request["expectedStateSha256"] = snapshot.sha256
        request["rollbackBaselineReceiptSha256"] = DIGEST_A
        successor_result = None

        def commit_successor(_written):
            nonlocal successor_result
            self.storage.after_successful_replace = None
            published = self.service.state_snapshot()
            accept = request_fixtures()["accept-candidate"]
            accept["expectedStateSha256"] = published.sha256
            successor_result = self.transition(accept)

        self.storage.after_successful_replace = commit_successor
        published_result = self.transition(request)

        self.assertEqual(published_result.status_code, 201)
        self.assertEqual(published_result.document["status"], "candidate-published")
        self.assertIsNotNone(successor_result)
        self.assertEqual(successor_result.status_code, 201)
        self.assertEqual(successor_result.document["status"], "candidate-accepted")
        self.assertIsNone(self.service.state_snapshot().document["pendingCandidate"])
        self.assertNotEqual(
            published_result.document["stateSha256"],
            self.service.state_snapshot().sha256,
        )
        with self.assertRaisesRegex(provider.ProviderError, "competing current state") as replay:
            self.transition(request)
        self.assertEqual(replay.exception.status, 409)

    def test_same_millisecond_accept_race_requires_winning_transition_metadata(self):
        initial = state(pending())
        snapshot = self.seed_state(initial)
        request = request_fixtures()["accept-candidate"]
        request["expectedStateSha256"] = snapshot.sha256
        caller_a = oidc_for(self.machine, request)
        caller_b = {**caller_a, "run_id": "405"}

        accepted_a = self.transition(request, caller_a)
        self.assertEqual(accepted_a.status_code, 201)
        winning = self.storage.blobs[(provider.STATE_CONTAINER, provider.STATE_BLOB)]
        self.assertEqual(
            winning.metadata["paperdesk_last_transition_sha256"],
            accepted_a.document["transitionReceiptSha256"],
        )

        self.storage.seed(
            provider.STATE_CONTAINER,
            provider.STATE_BLOB,
            provider.canonical_json(initial),
        )
        self.storage.competing_replace_body = winning.body
        self.storage.competing_replace_metadata = winning.metadata
        with self.assertRaises(provider.ProviderError) as lost:
            self.transition(request, caller_b)
        self.assertEqual(lost.exception.status, 409)
        self.assertEqual(self.service.state_snapshot().raw, winning.body)

        with self.assertRaisesRegex(provider.ProviderError, "different transition receipt") as replay:
            self.transition(request, caller_b)
        self.assertEqual(replay.exception.status, 409)

    def test_accept_requires_available_unattempted_guard_and_promotes_registry_manifest(self):
        snapshot = self.seed_state(state(pending()))
        request = request_fixtures()["accept-candidate"]
        request["expectedStateSha256"] = snapshot.sha256
        result = self.transition(request)
        self.assertEqual(result.status_code, 201)
        current = self.service.state_snapshot().document
        self.assertIsNone(current["pendingCandidate"])
        self.assertEqual(current["rollbackBaseline"], self.registry.promoted)
        self.assertEqual(len(self.registry.calls), 1)

        for status in ("claimed", "dispatching", "requested", "authorized"):
            with self.subTest(status=status):
                storage = MemoryStorage()
                storage.seed(
                    provider.STATE_CONTAINER, provider.STATE_BLOB,
                    provider.canonical_json(state(pending(status, claimId=CLAIM_ID))),
                )
                service = provider.WatchdogProvider(
                    storage, self.dispatcher, registry_validator=self.registry,
                    contract=self.machine, clock=lambda: NOW,
                )
                current_snapshot = service.state_snapshot()
                changed = copy.deepcopy(request)
                changed["expectedStateSha256"] = current_snapshot.sha256
                with self.assertRaises(provider.ProviderError) as caught:
                    service.transition(
                        provider.canonical_json(changed), f'"{current_snapshot.sha256}"',
                        oidc_for(self.machine, changed),
                    )
                self.assertEqual(caught.exception.status, 409)

    def test_accept_with_real_locked_registry_validator_promotes_acceptance_provenance(self):
        class RegistryPolicyStorage(MemoryStorage):
            def policy(self, container):
                value = super().policy(container)
                if container == provider.REGISTRY_CONTAINER:
                    value["immutabilityPeriodSinceCreationInDays"] = 30
                return value

        storage = RegistryPolicyStorage()
        service = provider.WatchdogProvider(
            storage,
            self.dispatcher,
            contract=self.machine,
            clock=lambda: NOW,
        )
        candidate = pending()
        candidate.update({
            "candidateSha": registry_fixture.SHA,
            "candidateRunId": registry_fixture.SOURCE_RUN,
            "candidateRunAttempt": registry_fixture.SOURCE_ATTEMPT,
            "liveSha": registry_fixture.SHA,
        })
        storage.seed(
            provider.STATE_CONTAINER,
            provider.STATE_BLOB,
            provider.canonical_json(state(candidate)),
        )
        snapshot = service.state_snapshot()

        receipt_raw = provider.canonical_json({"schemaVersion": 2, "status": "accepted"})
        receipt_sha256 = hashlib.sha256(receipt_raw).hexdigest()
        manifest = registry_fixture.manifest_document()
        receipt_path = (
            f"receipts/paperdesk-production-acceptance-receipt-{registry_fixture.SHA}.json"
        )
        record = next(item for item in manifest["files"] if item["path"] == receipt_path)
        record.update({
            "size": len(receipt_raw),
            "sha256": receipt_sha256,
            "contentMd5": base64.b64encode(hashlib.md5(receipt_raw).digest()).decode("ascii"),
        })
        manifest["artifacts"]["productionAcceptanceReceipt"]["fileSha256"] = receipt_sha256
        manifest_raw = registry_fixture.canonical_json(manifest)
        request = registry_fixture.transition_request(manifest_raw)
        request.update({
            "expectedStateSha256": snapshot.sha256,
            "productionAcceptanceReceiptSha256": receipt_sha256,
            "acceptedReleaseManifestSha256": hashlib.sha256(manifest_raw).hexdigest(),
        })
        manifest_path = request["acceptedReleasePrefix"] + "registry-manifest.json"
        storage.blobs[(provider.REGISTRY_CONTAINER, manifest_path)] = provider.BlobRecord(
            body=manifest_raw,
            etag=registry_fixture.ETAG,
            version_id=registry_fixture.VERSION_ID,
            metadata={},
        )
        storage.blobs[(
            provider.REGISTRY_CONTAINER,
            request["acceptedReleasePrefix"] + receipt_path,
        )] = provider.BlobRecord(
            body=receipt_raw,
            etag='"receipt-etag"',
            version_id="receipt-version",
            metadata={},
        )

        result = service.transition(
            provider.canonical_json(request),
            f'"{snapshot.sha256}"',
            oidc_for(self.machine, request),
        )

        self.assertEqual(result.status_code, 201)
        promoted = service.state_snapshot().document["rollbackBaseline"]
        self.assertEqual(promoted["reviewWorkflowRef"], registry_fixture.ACCEPTANCE_WORKFLOW)
        self.assertEqual(promoted["reviewWorkflowSha"], registry_fixture.SHA)
        self.assertEqual(promoted["reviewEnvironment"], "production")
        self.assertEqual(promoted["preparedAt"], "2026-08-14T02:03:04.000Z")
        self.assertEqual(promoted["evidencePath"], request["acceptedReleasePrefix"] + receipt_path)

    def test_three_rollback_transitions_bind_same_claim_attempt_run_and_authorization(self):
        dispatching = pending(
            "dispatching", generation=7, claimId=CLAIM_ID,
            leaseExpiresAt="2026-08-23T01:05:00.000Z", watchdogRunId="700",
            watchdogRunAttempt="1", decisionReceiptSha256=DIGEST_B,
            decisionEvidenceETag='"decision-etag"', attemptReceiptSha256=DIGEST_C,
            workflowRunId="303",
        )
        self.seed_guard_evidence(dispatching)
        snapshot = self.seed_state(state(dispatching))
        requests = request_fixtures()
        observed = requests["rollback-workflow-observed"]
        observed.update({
            "expectedStateSha256": snapshot.sha256,
            "decisionReceiptSha256": dispatching["dispatchGuard"]["decisionReceiptSha256"],
            "decisionEvidenceETag": dispatching["dispatchGuard"]["decisionEvidenceETag"],
            "dispatchGuardGeneration": 7,
            "attemptReceiptSha256": dispatching["dispatchGuard"]["attemptReceiptSha256"],
            "workflowRunId": "303",
        })
        result = self.transition(observed)
        self.assertEqual(result.document["status"], "requested-recorded")
        self.assertEqual(self.service.state_snapshot().document["pendingCandidate"]["dispatchGuard"]["status"], "requested")

        authorize = requests["rollback-authorize"]
        authorize.update({
            "expectedStateSha256": result.document["stateSha256"],
            "decisionReceiptSha256": dispatching["dispatchGuard"]["decisionReceiptSha256"],
            "decisionEvidenceETag": dispatching["dispatchGuard"]["decisionEvidenceETag"],
            "dispatchGuardGeneration": 7,
            "attemptReceiptSha256": dispatching["dispatchGuard"]["attemptReceiptSha256"],
            "workflowRunId": "303",
        })
        authorized = self.transition(authorize)
        guard_value = self.service.state_snapshot().document["pendingCandidate"]["dispatchGuard"]
        self.assertEqual(guard_value["status"], "authorized")
        authorization_receipt_sha = guard_value["authorizationReceiptSha256"]
        self.assertRegex(authorization_receipt_sha, r"^[0-9a-f]{64}$")

        completed = requests["rollback-completed"]
        completed.update({
            "expectedStateSha256": authorized.document["stateSha256"],
            "dispatchGuardGeneration": 7,
            "attemptReceiptSha256": dispatching["dispatchGuard"]["attemptReceiptSha256"],
            "workflowRunId": "303",
            "authorizationReceiptSha256": authorization_receipt_sha,
            "rolledBackLiveSha": SHA_B,
        })
        finished = self.transition(completed)
        self.assertEqual(finished.document["status"], "rollback-completed")
        self.assertIsNone(self.service.state_snapshot().document["pendingCandidate"])

    def test_rollback_authorization_rejects_changed_kudu_live_sha_before_worm(self):
        requested = pending(
            "requested", generation=7, claimId=CLAIM_ID, watchdogRunId="700",
            watchdogRunAttempt="1", decisionReceiptSha256=DIGEST_B,
            decisionEvidenceETag='"decision-etag"', attemptReceiptSha256=DIGEST_C,
            workflowRunId="303",
        )
        snapshot = self.seed_state(state(requested))
        request = request_fixtures()["rollback-authorize"]
        request.update({
            "expectedStateSha256": snapshot.sha256, "decisionReceiptSha256": DIGEST_B,
            "decisionEvidenceETag": '"decision-etag"', "dispatchGuardGeneration": 7,
            "attemptReceiptSha256": DIGEST_C, "workflowRunId": "303",
            "kuduObservedLiveSha": SHA_C,
        })
        with self.assertRaisesRegex(ValueError, "Kudu observation"):
            self.transition(request)
        self.assertFalse(any(event[0] == "create" for event in self.storage.events))


class WatchdogInitialBaselineTests(unittest.TestCase):
    def baseline_fixture(self):
        value = baseline()
        receipt_raw = provider.canonical_json({
            "schemaVersion": 2,
            "receiptType": "watchdog-initial-rollback-baseline",
            "recordedAt": value["preparedAt"],
            "storageAccount": provider.STORAGE_ACCOUNT,
            "evidenceContainer": provider.EVIDENCE_CONTAINER,
            "evidencePath": value["evidencePath"],
            "sourceRepository": "Sethvirak/MasterDataStructure",
            "sourceSha": value["sourceSha"],
            "sourceRunId": value["sourceRunId"],
            "sourceRunAttempt": value["sourceRunAttempt"],
            "acceptanceRunId": value["acceptanceRunId"],
            "acceptanceRunAttempt": value["acceptanceRunAttempt"],
            "acceptedReleaseManifestSha256": value["acceptedReleaseManifestSha256"],
            "acceptedReleasePrefix": value["acceptedReleasePrefix"],
            "reviewWorkflowRef": value["reviewWorkflowRef"],
            "reviewWorkflowSha": value["reviewWorkflowSha"],
            "reviewRunId": value["reviewRunId"],
            "reviewRunAttempt": value["reviewRunAttempt"],
            "reviewEnvironment": value["reviewEnvironment"],
        })
        value["receiptSha256"] = hashlib.sha256(receipt_raw).hexdigest()
        claims = {
            **watchdog_claims(value["reviewRunId"], value["reviewRunAttempt"]),
            "workflow_ref": value["reviewWorkflowRef"],
            "environment": value["reviewEnvironment"],
            "sha": value["reviewWorkflowSha"],
            "workflow_sha": value["reviewWorkflowSha"],
        }
        return value, receipt_raw, claims

    def service_for(self, value, receipt_raw):
        storage = MemoryStorage()
        storage.seed(
            provider.EVIDENCE_CONTAINER,
            value["evidencePath"],
            receipt_raw,
        )
        service = provider.WatchdogProvider(
            storage,
            FakeDispatcher(),
            registry_validator=RegistryValidator(),
            contract=watchdog_contract.load_contract(),
            clock=lambda: NOW,
        )
        return storage, service

    def test_initial_baseline_provenance_is_bound_to_oidc_review_coordinates(self):
        value, receipt_raw, claims = self.baseline_fixture()
        _, service = self.service_for(value, receipt_raw)
        snapshot = service.initialize_baseline(value, claims)
        self.assertEqual(snapshot.document["rollbackBaseline"], value)

        for field, replacement in (
            ("reviewWorkflowSha", SHA_C),
            ("reviewRunId", "203"),
            ("reviewRunAttempt", "2"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(value)
                changed[field] = replacement
                _, isolated = self.service_for(changed, receipt_raw)
                with self.assertRaises(provider.ProviderError) as caught:
                    isolated.initialize_baseline(changed, claims)
                self.assertEqual(caught.exception.status, 403)
                self.assertEqual(caught.exception.code, "oidc-forbidden")

    def test_initial_baseline_rejects_unrelated_canonical_worm_document(self):
        value, _, claims = self.baseline_fixture()
        unrelated = provider.canonical_json({"schemaVersion": 2, "status": "reviewed"})
        value["receiptSha256"] = hashlib.sha256(unrelated).hexdigest()
        _, service = self.service_for(value, unrelated)
        with self.assertRaises(provider.ProviderError) as caught:
            service.initialize_baseline(value, claims)
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(caught.exception.code, "baseline-evidence-conflict")


class WatchdogDispatchLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.machine = watchdog_contract.load_contract()
        self.storage = MemoryStorage()
        self.dispatcher = FakeDispatcher()
        self.service = provider.WatchdogProvider(
            self.storage, self.dispatcher, registry_validator=RegistryValidator(),
            contract=self.machine, clock=lambda: NOW,
            uuid_factory=lambda: __import__("uuid").UUID(CLAIM_ID),
        )
        self.storage.seed(
            provider.STATE_CONTAINER, provider.STATE_BLOB,
            provider.canonical_json(state(pending(
                completed_at="2026-08-22T00:00:00.000Z",
                deadline="2026-08-23T00:00:00.000Z",
            ))),
        )

    def test_decision_worm_claim_attempt_worm_dispatching_cas_http_200_run_binding(self):
        snapshot = self.service.state_snapshot()
        decision = decision_receipt(snapshot.sha256)
        claim = self.service.claim_rollback(
            provider.canonical_json(decision), None, watchdog_claims(),
        )
        self.assertEqual(claim["status"], "claimed")
        state_after_claim = self.service.state_snapshot().document
        self.assertEqual(state_after_claim["pendingCandidate"]["dispatchGuard"]["claimId"], CLAIM_ID)
        outcome = self.service.dispatch_rollback(CLAIM_ID, watchdog_claims())
        self.assertEqual(outcome["status"], "requested")
        self.assertEqual(outcome["workflowRunId"], "303")
        self.assertEqual(len(self.dispatcher.calls), 1)
        current_guard = self.service.state_snapshot().document["pendingCandidate"]["dispatchGuard"]
        self.assertEqual(current_guard["status"], "dispatching")
        self.assertEqual(current_guard["workflowRunId"], "303")
        self.assertRegex(current_guard["attemptReceiptSha256"], r"^[0-9a-f]{64}$")
        replay = self.service.dispatch_rollback(CLAIM_ID, watchdog_claims())
        self.assertEqual(replay, outcome)
        self.assertEqual(len(self.dispatcher.calls), 1)

    def test_claim_lost_response_exact_retry_is_idempotent_but_never_false_replays(self):
        snapshot = self.service.state_snapshot()
        decision = decision_receipt(snapshot.sha256)
        raw = provider.canonical_json(decision)
        claims = watchdog_claims()

        first = self.service.claim_rollback(raw, None, claims)
        replace_count = sum(event[0] == "replace" for event in self.storage.events)
        create_count = sum(event[0] == "create" for event in self.storage.events)
        replay = self.service.claim_rollback(raw, None, claims)

        self.assertEqual(replay, first)
        self.assertEqual(
            sum(event[0] == "replace" for event in self.storage.events),
            replace_count,
        )
        self.assertEqual(
            sum(event[0] == "create" for event in self.storage.events),
            create_count,
        )

        changed_body = {**decision, "decidedAt": "2026-08-23T01:00:01.000Z"}
        with self.assertRaises(provider.ProviderError) as body_conflict:
            self.service.claim_rollback(
                provider.canonical_json(changed_body), None, claims,
            )
        self.assertEqual(body_conflict.exception.status, 409)

        with self.assertRaises(provider.ProviderError) as changed_run:
            self.service.claim_rollback(raw, None, watchdog_claims("701", "1"))
        self.assertEqual(changed_run.exception.status, 403)

        changed_caller = {
            **claims,
            "workflow_ref": (
                "Sethvirak/paperdesk-release-verifier/.github/workflows/"
                "reconcile-watchdog-dispatch.yml@refs/heads/main"
            ),
            "environment": "paperdesk-watchdog-reconciliation",
        }
        with self.assertRaises(provider.ProviderError) as caller_conflict:
            self.service.claim_rollback(raw, None, changed_caller)
        self.assertEqual(caller_conflict.exception.status, 403)

        changed_decision = {
            **decision,
            "watchdogRunId": "701",
        }
        with self.assertRaises(provider.ProviderError) as request_conflict:
            self.service.claim_rollback(
                provider.canonical_json(changed_decision),
                None,
                watchdog_claims("701", "1"),
            )
        self.assertEqual(request_conflict.exception.status, 409)

        state_record = self.storage.blobs[(provider.STATE_CONTAINER, provider.STATE_BLOB)]
        self.storage.seed(
            provider.STATE_CONTAINER,
            provider.STATE_BLOB,
            state_record.body,
            {
                **state_record.metadata,
                "paperdesk_last_transition_sha256": "e" * 64,
            },
        )
        with self.assertRaises(provider.ProviderError) as competing_state:
            self.service.claim_rollback(raw, None, claims)
        self.assertEqual(competing_state.exception.status, 409)

    def test_durable_dispatch_outcome_repairs_final_settle_cas_loss_before_replay_success(self):
        snapshot = self.service.state_snapshot()
        self.service.claim_rollback(
            provider.canonical_json(decision_receipt(snapshot.sha256)),
            None,
            watchdog_claims(),
        )
        self.dispatcher.after_dispatch = lambda: setattr(self.storage, "fail_next_replace", True)
        with self.assertRaises(provider.ProviderError) as first:
            self.service.dispatch_rollback(CLAIM_ID, watchdog_claims())
        self.assertEqual(first.exception.status, 409)
        held = self.service.state_snapshot().document["pendingCandidate"]["dispatchGuard"]
        self.assertEqual(held["status"], "dispatching")
        self.assertIsNone(held["workflowRunId"])
        self.assertEqual(len(self.dispatcher.calls), 1)

        self.dispatcher.after_dispatch = None
        recovered = self.service.dispatch_rollback(CLAIM_ID, watchdog_claims())
        self.assertEqual(recovered["status"], "requested")
        self.assertEqual(recovered["workflowRunId"], "303")
        settled = self.service.state_snapshot().document["pendingCandidate"]["dispatchGuard"]
        self.assertEqual(settled["workflowRunId"], "303")
        self.assertEqual(len(self.dispatcher.calls), 1)

    def test_automatic_reconciliation_releases_only_expired_claim_without_attempt(self):
        expired = pending(
            "claimed", claimId=CLAIM_ID, leaseExpiresAt="2026-08-23T00:59:00.000Z",
            watchdogRunId="700", watchdogRunAttempt="1",
            decisionReceiptSha256=DIGEST_B, decisionEvidenceETag='"decision-etag"',
        )
        self.storage.seed(
            provider.STATE_CONTAINER, provider.STATE_BLOB, provider.canonical_json(state(expired)),
        )
        result = self.service.reconcile(CLAIM_ID, watchdog_claims(), manual=False)
        self.assertEqual(result["status"], "released-unattempted-expired-claim")
        current = self.service.state_snapshot().document["pendingCandidate"]["dispatchGuard"]
        self.assertEqual(current, guard("available", 2))

    def test_automatic_reconciliation_recovers_same_worm_receipt_after_delayed_cas_retry(self):
        current_time = [NOW]
        self.service.clock = lambda: current_time[0]
        expired = pending(
            "claimed", claimId=CLAIM_ID, leaseExpiresAt="2026-08-23T00:59:00.000Z",
            watchdogRunId="700", watchdogRunAttempt="1",
            decisionReceiptSha256=DIGEST_B, decisionEvidenceETag='"decision-etag"',
        )
        self.storage.seed(
            provider.STATE_CONTAINER, provider.STATE_BLOB, provider.canonical_json(state(expired)),
        )
        self.storage.fail_next_replace = True
        with self.assertRaises(provider.ProviderError) as first:
            self.service.reconcile(CLAIM_ID, watchdog_claims(), manual=False)
        self.assertEqual(first.exception.status, 409)
        current_time[0] = datetime(2026, 8, 23, 1, 2, 0, tzinfo=timezone.utc)
        retry_claims = watchdog_claims()
        recovered = self.service.reconcile(CLAIM_ID, retry_claims, manual=False)
        self.assertEqual(recovered["status"], "released-unattempted-expired-claim")
        self.assertEqual(
            self.service.state_snapshot().document["pendingCandidate"]["dispatchGuard"],
            guard("available", 2),
        )
        auto_creates = [
            event for event in self.storage.events
            if event[:3] == (
                "create", provider.EVIDENCE_CONTAINER,
                f"v2/reconciliations/automatic/{CLAIM_ID}.json",
            )
        ]
        self.assertEqual(len(auto_creates), 1)
        self.assertEqual(
            self.service.reconcile(CLAIM_ID, watchdog_claims(), manual=False),
            recovered,
        )
        with self.assertRaises(provider.ProviderError) as changed_run:
            self.service.reconcile(CLAIM_ID, watchdog_claims("702", "1"), manual=False)
        self.assertEqual(changed_run.exception.status, 409)

    def test_attempt_present_never_auto_releases_and_manual_review_only_holds_known_run(self):
        snapshot = self.service.state_snapshot()
        decision = decision_receipt(snapshot.sha256)
        self.service.claim_rollback(
            provider.canonical_json(decision), None, watchdog_claims(),
        )
        self.service.dispatch_rollback(CLAIM_ID, watchdog_claims())
        with self.assertRaises(provider.ProviderError) as caught:
            self.service.reconcile(CLAIM_ID, watchdog_claims(), manual=False)
        self.assertEqual(caught.exception.status, 409)
        repaired = self.service.reconcile(
            CLAIM_ID,
            {
                **watchdog_claims(),
                "workflow_ref": (
                    "Sethvirak/paperdesk-release-verifier/.github/workflows/"
                    "reconcile-watchdog-dispatch.yml@refs/heads/main"
                ),
                "environment": "paperdesk-watchdog-reconciliation",
            },
            manual=True,
        )
        self.assertEqual(repaired["status"], "known-run-held-for-workflow-observation")
        self.assertEqual(
            self.service.state_snapshot().document["pendingCandidate"]["dispatchGuard"]["status"],
            "dispatching",
        )

    def test_manual_reconciliation_recovers_same_worm_receipt_after_delayed_cas_retry(self):
        current_time = [NOW]
        self.service.clock = lambda: current_time[0]
        snapshot = self.service.state_snapshot()
        self.service.claim_rollback(
            provider.canonical_json(decision_receipt(snapshot.sha256)),
            None,
            watchdog_claims(),
        )
        self.dispatcher.after_dispatch = lambda: setattr(self.storage, "fail_next_replace", True)
        with self.assertRaises(provider.ProviderError):
            self.service.dispatch_rollback(CLAIM_ID, watchdog_claims())
        self.dispatcher.after_dispatch = None

        manual_claims = {
            **watchdog_claims(),
            "workflow_ref": (
                "Sethvirak/paperdesk-release-verifier/.github/workflows/"
                "reconcile-watchdog-dispatch.yml@refs/heads/main"
            ),
            "environment": "paperdesk-watchdog-reconciliation",
        }
        self.storage.fail_next_replace = True
        with self.assertRaises(provider.ProviderError) as first:
            self.service.reconcile(CLAIM_ID, manual_claims, manual=True)
        self.assertEqual(first.exception.status, 409)
        current_time[0] = datetime(2026, 8, 23, 1, 3, 0, tzinfo=timezone.utc)
        retry_manual_claims = manual_claims
        recovered = self.service.reconcile(CLAIM_ID, retry_manual_claims, manual=True)
        self.assertEqual(recovered["status"], "known-run-held-for-workflow-observation")
        self.assertEqual(recovered["workflowRunId"], "303")
        self.assertEqual(
            self.service.state_snapshot().document["pendingCandidate"]["dispatchGuard"]["workflowRunId"],
            "303",
        )
        self.assertEqual(
            self.service.reconcile(CLAIM_ID, manual_claims, manual=True),
            recovered,
        )
        with self.assertRaises(provider.ProviderError) as changed_run:
            self.service.reconcile(
                CLAIM_ID,
                {**manual_claims, "run_id": "702", "run_attempt": "1"},
                manual=True,
            )
        self.assertEqual(changed_run.exception.status, 409)


class WatchdogOIDCLifetimeTests(unittest.TestCase):
    def test_base_verifier_rejects_expiration_equal_to_current_epoch(self):
        epoch = int(NOW.timestamp())
        claims = {
            "iss": provider.OIDC_ISSUER,
            "aud": provider.evidence.OIDC_AUDIENCE,
            "sub": "repo:Sethvirak/paperdesk-release-verifier:environment:paperdesk-watchdog",
            "repository": "Sethvirak/paperdesk-release-verifier",
            "repository_owner": "Sethvirak",
            "repository_id": "1333353701",
            "repository_owner_id": "202535166",
            "ref": "refs/heads/main",
            "sha": SHA_A,
            "workflow_ref": provider.WATCHDOG_WORKFLOW_REF,
            "environment": provider.WATCHDOG_ENVIRONMENT,
            "run_id": "700",
            "run_attempt": "1",
            "iat": epoch - 60,
            "nbf": epoch - 60,
            "exp": epoch,
        }
        verifier = provider.OIDCVerifier(SHA_A, SHA_B, clock=lambda: NOW)
        verifier._load_keys = lambda: {"test-key": {"kty": "RSA"}}

        with mock.patch.object(provider, "jwt_module", return_value=FakeJWT(claims)):
            with self.assertRaisesRegex(provider.ProviderError, "lifetime is invalid") as caught:
                verifier.verify("header.payload.signature", "state")

        self.assertEqual(caught.exception.status, 401)


if __name__ == "__main__":
    unittest.main()
