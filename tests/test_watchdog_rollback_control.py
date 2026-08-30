import copy
import unittest

from scripts import watchdog_rollback_control as control


class RollbackControlTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.state = {"pendingCandidate": {"candidateSha": "a" * 40,
            "rollback": {"sourceSha": "b" * 40}, "dispatchGuard": {
                "status": "dispatching", "claimId": "11111111-1111-4111-8111-111111111111",
                "generation": 7, "attemptReceiptSha256": "c" * 64,
                "workflowRunId": "303", "decisionReceiptSha256": "d" * 64,
                "decisionEvidenceETag": '"decision"', "authorizationReceiptSha256": None}}}
        self.coords = {"claimId": "11111111-1111-4111-8111-111111111111",
            "dispatchGuardGeneration": 7, "attemptReceiptSha256": "c" * 64,
            "decisionReceiptSha256": "d" * 64, "decisionEvidenceETag": '"decision"',
            "workflowRunId": "303"}

    def fetch(self):
        self.calls.append("fetch")
        return copy.deepcopy(self.state)

    def transition(self, request):
        self.calls.append(request["operation"])
        guard = self.state["pendingCandidate"]["dispatchGuard"]
        if request["operation"] == "rollback-workflow-observed": guard["status"] = "requested"
        elif request["operation"] == "rollback-authorize":
            guard["status"] = "authorized"; guard["authorizationReceiptSha256"] = "e" * 64
            return {"operationReceiptSha256": "e" * 64}
        elif request["operation"] == "rollback-completed": self.state["pendingCandidate"] = None
        return {"status": "ok"}

    def test_full_authorized_sequence_precedes_one_deploy_and_completion(self):
        result = control.execute(self.coords, fetch_state=self.fetch, transition=self.transition,
            observe_live=lambda: (self.calls.append("observe") or {"liveSha": "a" * 40,
                "observedAt": "2026-08-29T00:00:00.000Z", "requestSha256": "f" * 64,
                "responseSha256": "1" * 64}),
            deploy_onedeploy=lambda sha: (self.calls.append("deploy") or {"sha": sha}),
            verify_live=lambda sha: (self.calls.append("verify") or {"receiptSha256": "2" * 64}),
            completed_at="2026-08-29T00:01:00.000Z")
        self.assertEqual(self.calls, ["fetch", "rollback-workflow-observed", "fetch", "observe",
                                      "rollback-authorize", "fetch", "deploy", "verify", "rollback-completed"])
        self.assertEqual(result["deployment"]["sha"], "b" * 40)

    def test_drift_or_attempt_mismatch_never_reaches_deploy(self):
        for mutation in ("attempt", "live"):
            with self.subTest(mutation=mutation):
                self.setUp(); deployed = []
                if mutation == "attempt": self.state["pendingCandidate"]["dispatchGuard"]["attemptReceiptSha256"] = "9" * 64
                observe = lambda: {"liveSha": "9" * 40 if mutation == "live" else "a" * 40,
                    "observedAt": "2026-08-29T00:00:00.000Z", "requestSha256": "f" * 64,
                    "responseSha256": "1" * 64}
                with self.assertRaises(control.RollbackControlError):
                    control.execute(self.coords, fetch_state=self.fetch, transition=self.transition,
                        observe_live=observe, deploy_onedeploy=lambda sha: deployed.append(sha),
                        verify_live=lambda sha: {}, completed_at="2026-08-29T00:01:00.000Z")
                self.assertEqual(deployed, [])


if __name__ == "__main__": unittest.main()
