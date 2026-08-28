from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from provider import watchdog_state_provider as provider


NOW = datetime(2026, 8, 23, 3, 0, 0, tzinfo=timezone.utc)
CLAIM_ID = "123e4567-e89b-42d3-a456-426614174000"


class FakeResponse:
    def __init__(self, status, document, headers=()):
        self.status = status
        self.body = json.dumps(document, separators=(",", ":")).encode("utf-8")
        self.headers = list(headers)

    def read(self, _amount=-1):
        return self.body

    def getheaders(self):
        return list(self.headers)


class FakeConnection:
    def __init__(self, response):
        self.response = response
        self.requests = []
        self.closed = False

    def request(self, method, path, body=None, headers=None):
        self.requests.append((method, path, body, dict(headers or {})))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


def attempt():
    return {
        "schemaVersion": 2,
        "receiptType": "watchdog-rollback-dispatch-attempt",
        "recordedAt": "2026-08-23T03:00:00.000Z",
        "claimId": CLAIM_ID,
        "dispatchGuardGeneration": 7,
        "watchdogRunId": "700",
        "watchdogRunAttempt": "1",
        "decisionReceiptSha256": "a" * 64,
        "decisionEvidenceETag": '"decision"',
        "expectedCurrentLiveSha": "1" * 40,
        "candidateSha": "1" * 40,
        "candidateRunId": "101",
        "candidateRunAttempt": "2",
        "rollback": {
            "sourceSha": "2" * 40,
            "sourceRunId": "88",
            "sourceRunAttempt": "1",
            "acceptanceRunId": "99",
            "acceptanceRunAttempt": "1",
            "baselineReceiptSha256": "b" * 64,
        },
    }


def token_response():
    return {
        "token": "installation-token-value-1234567890",
        "expires_at": (NOW + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
        "permissions": {"actions": "write", "metadata": "read"},
        "repositories": [{"id": 1287744543, "full_name": "Sethvirak/MasterDataStructure"}],
    }


class GithubAppDispatchTests(unittest.TestCase):
    def dispatcher(self, responses):
        connections = [FakeConnection(response) for response in responses]

        def factory():
            return connections.pop(0)

        dispatcher = provider.GithubAppDispatcher(
            "123", "456", "not-read-because-jwt-is-patched",
            connection_factory=factory, clock=lambda: NOW,
        )
        return dispatcher, connections

    def test_token_scope_and_2026_03_10_dispatch_body_and_run_binding_are_exact(self):
        token_connection = FakeConnection(FakeResponse(201, token_response()))
        dispatch_connection = FakeConnection(FakeResponse(
            200,
            {
                "workflow_run_id": 303,
                "run_url": (
                    "https://api.github.com/repos/Sethvirak/MasterDataStructure/actions/runs/303"
                ),
                "html_url": (
                    "https://github.com/Sethvirak/MasterDataStructure/actions/runs/303"
                ),
            },
            [("X-GitHub-Request-Id", "ABCD:1234")],
        ))
        queue = [token_connection, dispatch_connection]
        dispatcher = provider.GithubAppDispatcher(
            "123", "456", "private-key",
            connection_factory=lambda: queue.pop(0), clock=lambda: NOW,
        )
        with patch.object(provider, "github_app_jwt", return_value="app-jwt"):
            result = dispatcher.dispatch(attempt())
        self.assertEqual(result.workflow_run_id, "303")
        self.assertEqual(result.github_request_id, "ABCD:1234")

        token_method, token_path, token_body, token_headers = token_connection.requests[0]
        self.assertEqual((token_method, token_path), ("POST", "/app/installations/456/access_tokens"))
        self.assertEqual(json.loads(token_body), {
            "permissions": {"actions": "write", "metadata": "read"},
            "repository_ids": [1287744543],
        })
        self.assertEqual(token_headers["X-GitHub-Api-Version"], "2026-03-10")

        method, path, body, headers = dispatch_connection.requests[0]
        self.assertEqual(method, "POST")
        self.assertEqual(
            path,
            "/repos/Sethvirak/MasterDataStructure/actions/workflows/"
            "manual-azure-production-rollback.yml/dispatches",
        )
        document = json.loads(body)
        self.assertEqual(set(document), {"ref", "inputs"})
        self.assertEqual(document["ref"], "main")
        self.assertNotIn("return_run_details", document)
        self.assertEqual(set(document["inputs"]), {
            "confirmation", "expected_current_live_sha", "rollback_source_sha",
            "rollback_source_run_id", "rollback_source_run_attempt",
            "rollback_acceptance_run_id", "rollback_acceptance_run_attempt",
            "rollback_baseline_receipt_sha256", "watchdog_claim_id",
            "watchdog_attempt_receipt_sha256",
        })
        self.assertEqual(document["inputs"]["watchdog_claim_id"], CLAIM_ID)
        self.assertEqual(headers["X-GitHub-Api-Version"], "2026-03-10")
        self.assertTrue(token_connection.closed)
        self.assertTrue(dispatch_connection.closed)

    def test_any_non_200_or_inexact_run_details_is_indeterminate(self):
        cases = (
            (204, {}, "indeterminate"),
            (200, {"workflow_run_id": 303}, "run details"),
            (200, {
                "workflow_run_id": 303,
                "run_url": "https://api.github.com/wrong",
                "html_url": "https://github.com/wrong",
            }, "run details"),
        )
        for status, document, message in cases:
            with self.subTest(status=status, document=document):
                token_connection = FakeConnection(FakeResponse(201, token_response()))
                dispatch_connection = FakeConnection(FakeResponse(
                    status, document, [("X-GitHub-Request-Id", "ABCD:1234")],
                ))
                queue = [token_connection, dispatch_connection]
                dispatcher = provider.GithubAppDispatcher(
                    "123", "456", "private-key",
                    connection_factory=lambda: queue.pop(0), clock=lambda: NOW,
                )
                with patch.object(provider, "github_app_jwt", return_value="app-jwt"):
                    with self.assertRaisesRegex(provider.ProviderError, message) as caught:
                        dispatcher.dispatch(attempt())
                self.assertEqual(caught.exception.status, 503)


if __name__ == "__main__":
    unittest.main()
