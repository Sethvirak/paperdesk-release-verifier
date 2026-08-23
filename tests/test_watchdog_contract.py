import copy
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import watchdog_contract as contract


SHA_A = "1" * 40
SHA_B = "2" * 40
SHA_C = "3" * 40
CONTROL_SHA = "4" * 40
DIGESTS = {letter: letter * 64 for letter in "abcdef"}
CLAIM_ID = "123e4567-e89b-42d3-a456-426614174000"


def request_fixtures():
    return {
        "publish-candidate": {
            "schemaVersion": 2,
            "requestType": "watchdog-state-transition",
            "operation": "publish-candidate",
            "expectedStateSha256": DIGESTS["a"],
            "candidateSha": SHA_A,
            "candidateRunId": "101",
            "candidateRunAttempt": "2",
            "completedAt": "2026-08-23T00:00:00.000Z",
            "deadline": "2026-08-24T00:00:00.000Z",
            "liveSha": SHA_A,
            "verificationReceiptSha256": DIGESTS["b"],
            "productionControlReceiptSha256": DIGESTS["c"],
            "rollbackBaselineReceiptSha256": DIGESTS["d"],
        },
        "accept-candidate": {
            "schemaVersion": 2,
            "requestType": "watchdog-state-transition",
            "operation": "accept-candidate",
            "expectedStateSha256": DIGESTS["a"],
            "candidateSha": SHA_A,
            "candidateRunId": "101",
            "candidateRunAttempt": "2",
            "acceptanceRunId": "202",
            "acceptanceRunAttempt": "1",
            "productionAcceptanceReceiptSha256": DIGESTS["b"],
            "acceptedReleaseManifestSha256": DIGESTS["c"],
            "acceptedReleasePrefix": f"v1/releases/{SHA_A}/101/202/",
            "registryManifestETag": '"0x8DABC123"',
            "registryManifestVersionId": "2026-08-23T00:00:00.0000000Z",
        },
        "rollback-workflow-observed": {
            "schemaVersion": 2,
            "requestType": "watchdog-state-transition",
            "operation": "rollback-workflow-observed",
            "expectedStateSha256": DIGESTS["a"],
            "decisionReceiptSha256": DIGESTS["b"],
            "decisionEvidenceETag": '"0x8DDECISION"',
            "claimId": CLAIM_ID,
            "dispatchGuardGeneration": 7,
            "attemptReceiptSha256": DIGESTS["c"],
            "expectedCurrentLiveSha": SHA_A,
            "workflowRunId": "303",
        },
        "rollback-authorize": {
            "schemaVersion": 2,
            "requestType": "watchdog-state-transition",
            "operation": "rollback-authorize",
            "expectedStateSha256": DIGESTS["a"],
            "decisionReceiptSha256": DIGESTS["b"],
            "decisionEvidenceETag": '"0x8DDECISION"',
            "claimId": CLAIM_ID,
            "dispatchGuardGeneration": 7,
            "attemptReceiptSha256": DIGESTS["c"],
            "workflowRunId": "303",
            "expectedCurrentLiveSha": SHA_A,
            "kuduObservedLiveSha": SHA_A,
            "kuduObservedAt": "2026-08-23T00:10:00.000Z",
            "kuduRequestSha256": DIGESTS["d"],
            "kuduResponseSha256": DIGESTS["e"],
        },
        "rollback-completed": {
            "schemaVersion": 2,
            "requestType": "watchdog-state-transition",
            "operation": "rollback-completed",
            "expectedStateSha256": DIGESTS["a"],
            "claimId": CLAIM_ID,
            "dispatchGuardGeneration": 7,
            "attemptReceiptSha256": DIGESTS["c"],
            "workflowRunId": "303",
            "authorizationReceiptSha256": DIGESTS["d"],
            "expectedCurrentLiveSha": SHA_A,
            "rolledBackLiveSha": SHA_B,
            "liveVerificationReceiptSha256": DIGESTS["e"],
            "completedAt": "2026-08-23T00:20:00.000Z",
        },
    }


def oidc_for(machine, request):
    transition = machine["transitions"][request["operation"]]
    publish = request["operation"] == "publish-candidate"
    rollback = request["operation"].startswith("rollback-")
    caller_sha = request["candidateSha"] if publish else SHA_C
    return {
        "iss": machine["provider"]["issuer"],
        "aud": machine["provider"]["audience"],
        "sub": machine["oidc"]["subject"],
        "repository": machine["sourceRepository"]["repository"],
        "repository_owner": machine["sourceRepository"]["repositoryOwner"],
        "repository_id": machine["sourceRepository"]["repositoryId"],
        "repository_owner_id": machine["sourceRepository"]["repositoryOwnerId"],
        "ref": machine["sourceRepository"]["ref"],
        "sha": caller_sha,
        "workflow_ref": (
            f'{machine["sourceRepository"]["repository"]}/'
            f'{transition["callerWorkflow"]}@{machine["sourceRepository"]["ref"]}'
        ),
        "workflow_sha": caller_sha,
        "event_name": "workflow_dispatch" if publish or rollback else "workflow_run",
        "run_id": request["candidateRunId"] if publish else (
            request["workflowRunId"] if rollback else "404"
        ),
        "run_attempt": request["candidateRunAttempt"] if publish else (
            "1"
        ),
        "environment": machine["oidc"]["environment"],
        "job_workflow_ref": (
            f'{machine["immutableExternalControl"]["repository"]}/'
            f'{machine["immutableExternalControl"]["workflowPath"]}@{CONTROL_SHA}'
        ),
        "job_workflow_sha": CONTROL_SHA,
        "iat": 1_777_000_000,
        "nbf": 1_777_000_000,
        "exp": 1_777_000_600,
    }


class WatchdogContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.machine = contract.load_contract()
        cls.requests = request_fixtures()

    def test_exact_five_operations_and_dormancy(self):
        self.assertEqual(list(self.machine["transitions"]), [
            "publish-candidate",
            "accept-candidate",
            "rollback-workflow-observed",
            "rollback-authorize",
            "rollback-completed",
        ])
        self.assertIsNone(self.machine["immutableExternalControl"]["mergedMutatingCommitSha"])
        self.assertEqual(self.machine["state"]["dispatchGuardFields"], [
            "status", "generation", "claimId", "leaseExpiresAt", "watchdogRunId",
            "watchdogRunAttempt", "decisionReceiptSha256", "decisionEvidenceETag",
            "attemptReceiptSha256", "workflowRunId", "authorizationReceiptSha256",
        ])
        self.assertEqual(self.machine["state"]["dispatchGuardStatuses"], [
            "available", "claimed", "dispatching", "requested", "authorized",
        ])
        self.assertEqual(self.machine["oidc"]["runBinding"], contract.EXPECTED_RUN_BINDING)
        self.assertNotIn("workflowRunIdMustEqualOidcRunId", self.machine["oidc"])
        self.assertNotIn("workflowRunAttemptComesOnlyFromOidc", self.machine["oidc"])

    def test_all_requests_and_oidc_bindings(self):
        for operation, request in self.requests.items():
            with self.subTest(operation=operation):
                self.assertEqual(
                    contract.validate_transition_request(
                        self.machine,
                        request,
                        if_match=f'"{request["expectedStateSha256"]}"',
                    ),
                    request,
                )
                claims = oidc_for(self.machine, request)
                self.assertEqual(
                    contract.validate_oidc_binding(self.machine, request, claims)["run_id"],
                    claims["run_id"],
                )

    def test_rejects_drift_and_bad_generation(self):
        request = self.requests["rollback-workflow-observed"]
        for generation in (0, -1, "7", DIGESTS["a"]):
            changed = {**request, "dispatchGuardGeneration": generation}
            with self.subTest(generation=generation), self.assertRaisesRegex(ValueError, "positive integer"):
                contract.validate_transition_request(self.machine, changed)
        changed = {**self.requests["publish-candidate"], "operation": "candidate-published"}
        with self.assertRaisesRegex(ValueError, "unsupported"):
            contract.validate_transition_request(self.machine, changed)
        changed = {**self.requests["accept-candidate"], "unexpected": True}
        with self.assertRaisesRegex(ValueError, "fields must be exact"):
            contract.validate_transition_request(self.machine, changed)

    def test_machine_contract_rejects_every_exact_leaf_surface(self):
        mutations = (
            ("top-level inventory", lambda value: value.__setitem__("unexpected", True)),
            (
                "source workflow",
                lambda value: value["sourceRepository"].__setitem__("productionWorkflow", "wrong.yml"),
            ),
            (
                "provider status",
                lambda value: value["provider"]["acceptedStatuses"].__setitem__("created", 200),
            ),
            ("OIDC subject", lambda value: value["oidc"].__setitem__("subject", "wrong")),
            (
                "control atomicity",
                lambda value: value["immutableExternalControl"].__setitem__("rollbackAtomicityRule", "weaker"),
            ),
            (
                "transition precondition",
                lambda value: value["transitions"]["accept-candidate"]["preconditions"].__setitem__(0, "weaker"),
            ),
            (
                "state rollback fields",
                lambda value: value["state"]["rollbackFields"].pop(),
            ),
            (
                "reconciliation idempotency",
                lambda value: value["reconciliation"].__setitem__("idempotency", "weaker"),
            ),
        )
        for label, mutate in mutations:
            changed = copy.deepcopy(self.machine)
            mutate(changed)
            with self.subTest(label=label), self.assertRaises(ValueError):
                contract.validate_machine_contract(changed)

    def test_rollback_oidc_requires_run_and_immutable_job(self):
        request = self.requests["rollback-authorize"]
        claims = oidc_for(self.machine, request)
        claims["run_id"] = "999"
        with self.assertRaisesRegex(ValueError, "run_id"):
            contract.validate_oidc_binding(self.machine, request, claims)
        claims = oidc_for(self.machine, request)
        claims["job_workflow_sha"] = SHA_B
        with self.assertRaisesRegex(ValueError, "immutable external control"):
            contract.validate_oidc_binding(self.machine, request, claims)

    def test_accept_oidc_is_distinct_workflow_run(self):
        request = self.requests["accept-candidate"]
        claims = oidc_for(self.machine, request)
        self.assertNotEqual(claims["run_id"], request["acceptanceRunId"])
        self.assertEqual(contract.validate_oidc_binding(self.machine, request, claims), claims)
        claims["run_id"] = request["acceptanceRunId"]
        with self.assertRaisesRegex(ValueError, "distinct persistence workflow run"):
            contract.validate_oidc_binding(self.machine, request, claims)

    def test_oidc_expiration_must_be_strictly_after_iat_and_nbf(self):
        request = self.requests["publish-candidate"]
        for label, mutate in (
            ("equal iat", lambda claims: claims.__setitem__("exp", claims["iat"])),
            ("equal nbf", lambda claims: (
                claims.__setitem__("iat", claims["nbf"] - 1),
                claims.__setitem__("exp", claims["nbf"]),
            )),
            ("over maximum", lambda claims: claims.__setitem__("exp", claims["iat"] + 901)),
        ):
            claims = oidc_for(self.machine, request)
            mutate(claims)
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, "lifetime"):
                contract.validate_oidc_binding(self.machine, request, claims)

    def test_canonical_json_is_sorted_compact_and_newline_terminated(self):
        self.assertEqual(contract.canonical_json({"z": 1, "a": {"y": 2, "b": 3}}), b'{"a":{"b":3,"y":2},"z":1}\n')


if __name__ == "__main__":
    unittest.main()
