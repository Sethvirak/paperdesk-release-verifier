from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import check_deadline as watchdog

SHA_A = "a" * 40
SHA_B = "b" * 40
NOW = datetime(2026, 8, 13, 3, 0, 0, tzinfo=timezone.utc)


def state(deadline="2026-08-13T02:00:00.000Z", accepted=False, live=SHA_A):
    return {
        "schemaVersion": 1,
        "generatedAt": "2026-08-13T02:59:00.000Z",
        "sourceRepository": "Sethvirak/MasterDataStructure",
        "pendingCandidate": {
            "candidateSha": SHA_A,
            "candidateRunId": "10",
            "candidateRunAttempt": "1",
            "completedAt": "2026-08-12T02:00:00.000Z",
            "deadline": deadline,
            "acceptedReceiptPresent": accepted,
            "liveSha": live,
            "rollback": {"sourceSha": SHA_B, "sourceRunId": "8", "acceptanceRunId": "9"},
        },
    }


class DeadlineTests(unittest.TestCase):
    def decide(self, document):
        return watchdog.decide(document, NOW, "Sethvirak/MasterDataStructure", "owner/repo/workflow@sha", "20", "1")

    def test_overdue_live_candidate_dispatches(self):
        self.assertEqual(self.decide(state())["decision"], "dispatch-rollback")

    def test_accepted_candidate_does_not_dispatch(self):
        self.assertEqual(self.decide(state(accepted=True))["decision"], "accepted")

    def test_candidate_already_not_live_does_not_dispatch(self):
        self.assertEqual(self.decide(state(live=SHA_B))["decision"], "already-not-live")

    def test_non_24_hour_deadline_fails(self):
        with self.assertRaisesRegex(ValueError, "exactly 24 hours"):
            self.decide(state(deadline="2026-08-13T02:01:00.000Z"))

    def test_state_url_requires_exact_host_and_no_query(self):
        watchdog.validate_https_url("https://registry.example.test/state.json", "registry.example.test", "state URL")
        with self.assertRaisesRegex(ValueError, "credential-free HTTPS"):
            watchdog.validate_https_url("https://registry.example.test/state.json?token=secret", "registry.example.test", "state URL")
        with self.assertRaisesRegex(ValueError, "credential-free HTTPS"):
            watchdog.validate_https_url("https://other.example.test/state.json", "registry.example.test", "state URL")


if __name__ == "__main__":
    unittest.main()
