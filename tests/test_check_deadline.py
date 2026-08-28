from datetime import datetime, timezone
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from provider import watchdog_state_provider as provider
from scripts import check_deadline as watchdog
from tests.test_watchdog_provider import baseline, pending, state


NOW = datetime(2026, 8, 23, 1, 0, 0, tzinfo=timezone.utc)
SOURCE = "Sethvirak/MasterDataStructure"


def fresh(document):
    document["generatedAt"] = "2026-08-23T00:59:00.000Z"
    return document


def overdue(status="available", **guard_changes):
    return fresh(state(pending(
        status,
        completed_at="2026-08-22T00:00:00.000Z",
        deadline="2026-08-23T00:00:00.000Z",
        **guard_changes,
    )))


def evaluate(document):
    raw = provider.canonical_json(document)
    state_sha256 = hashlib.sha256(raw).hexdigest()
    return watchdog.decide(
        document,
        NOW,
        SOURCE,
        "700",
        "1",
        state_sha256,
        f'"{state_sha256}"',
        document["rollbackBaseline"]["receiptSha256"],
    )


class DeadlineTests(unittest.TestCase):
    def test_overdue_available_candidate_dispatches_with_flat_exact_receipt(self):
        receipt = evaluate(overdue())
        self.assertEqual(receipt["decision"], "dispatch-rollback")
        self.assertEqual(set(receipt), set(provider.DECISION_FIELDS))
        self.assertEqual(receipt["candidateSha"], "1" * 40)
        self.assertEqual(receipt["expectedCurrentLiveSha"], "1" * 40)
        self.assertEqual(receipt["watchdogRunId"], "700")

    def test_guard_statuses_are_fail_closed_and_never_redispatch(self):
        cases = {
            "claimed": "rollback-claim-active",
            "dispatching": "rollback-dispatch-reconciliation-required",
            "requested": "rollback-workflow-observation-recorded",
            "authorized": "rollback-authorized",
        }
        common = {
            "claimId": "123e4567-e89b-42d3-a456-426614174000",
            "watchdogRunId": "700",
            "watchdogRunAttempt": "1",
            "decisionReceiptSha256": "b" * 64,
            "decisionEvidenceETag": '"decision-etag"',
        }
        for status, expected in cases.items():
            changes = dict(common)
            if status == "claimed":
                changes["leaseExpiresAt"] = "2026-08-23T01:05:00.000Z"
            else:
                changes["attemptReceiptSha256"] = "c" * 64
            if status in {"requested", "authorized"}:
                changes["workflowRunId"] = "303"
            if status == "authorized":
                changes["authorizationReceiptSha256"] = "d" * 64
            with self.subTest(status=status):
                self.assertEqual(evaluate(overdue(status, **changes))["decision"], expected)

        expired = dict(common)
        expired["leaseExpiresAt"] = "2026-08-23T00:59:59.000Z"
        self.assertEqual(
            evaluate(overdue("claimed", **expired))["decision"],
            "rollback-claim-expired-unattempted",
        )

    def test_accepted_awaiting_and_no_pending_do_not_dispatch(self):
        accepted = overdue()
        accepted["pendingCandidate"]["acceptedReceiptPresent"] = True
        self.assertEqual(evaluate(accepted)["decision"], "accepted")
        self.assertEqual(
            evaluate(fresh(state(pending(
                completed_at="2026-08-22T02:00:00.000Z",
                deadline="2026-08-23T02:00:00.000Z",
            ))))["decision"],
            "awaiting-acceptance",
        )
        healthy = evaluate(fresh(state()))
        self.assertEqual(healthy["decision"], "healthy-no-pending")
        self.assertIsNone(healthy["candidateSha"])

    def test_state_digest_etag_baseline_and_freshness_are_all_bound(self):
        document = overdue()
        raw = provider.canonical_json(document)
        digest = hashlib.sha256(raw).hexdigest()
        arguments = [document, NOW, SOURCE, "700", "1", digest, f'"{digest}"', baseline()["receiptSha256"]]
        for index, changed, error in (
            (5, "f" * 64, "ETag"),
            (6, '"' + "f" * 64 + '"', "ETag"),
            (7, "f" * 64, "baseline"),
        ):
            values = list(arguments)
            values[index] = changed
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, error):
                watchdog.decide(*values)
        stale = overdue()
        stale["generatedAt"] = "2026-08-23T00:44:59.000Z"
        with self.assertRaisesRegex(ValueError, "fresh 15-minute"):
            evaluate(stale)

    def test_state_file_requires_exact_canonical_bytes(self):
        document = overdue()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_bytes(provider.canonical_json(document))
            loaded, digest = watchdog.read_state(path)
            self.assertEqual(loaded, document)
            self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
            path.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "canonical JSON"):
                watchdog.read_state(path)

    def test_state_url_requires_exact_host_and_no_query(self):
        watchdog.validate_https_url(watchdog.WATCHDOG_STATE_URL, watchdog.WATCHDOG_PROVIDER_HOST, "state URL")
        with self.assertRaisesRegex(ValueError, "credential-free HTTPS"):
            watchdog.validate_https_url(
                watchdog.WATCHDOG_STATE_URL + "?token=secret",
                watchdog.WATCHDOG_PROVIDER_HOST,
                "state URL",
            )
        with self.assertRaisesRegex(ValueError, "credential-free HTTPS"):
            watchdog.validate_https_url(
                "https://other.example.test/api/watchdog-state/v2",
                watchdog.WATCHDOG_PROVIDER_HOST,
                "state URL",
            )


if __name__ == "__main__":
    unittest.main()
