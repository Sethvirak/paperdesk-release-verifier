import copy
from pathlib import Path
import tempfile
import unittest
import urllib.parse

from scripts import private_release_v2_bootstrap as bootstrap
from tests.test_private_release_v2_bootstrap import (
    AUTH_ID,
    build_valid_terminal_source_evidence_fixture,
)


class StorageJournalClientRequestIdTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.plan_sha = bootstrap.load_plan()
        cls.package = bootstrap.build_package_descriptor()

    def fixture(self, folder):
        return build_valid_terminal_source_evidence_fixture(
            Path(folder) / f"paperdesk-private-release-v2-bootstrap-{AUTH_ID}",
            plan=self.plan,
            plan_sha=self.plan_sha,
            package=self.package,
        )

    @staticmethod
    def _storage_intent_pairs(journal):
        pairs = []
        for intent in journal:
            if intent["phase"] != "intent":
                continue
            if (
                urllib.parse.urlsplit(intent["targetUrl"]).hostname or ""
            ).lower() != "mdspdbak2608089c4e.blob.core.windows.net":
                continue
            result = next(
                item
                for item in journal
                if item["phase"] == "result"
                and item["intentId"] == intent["intentId"]
            )
            pairs.append((intent, result))
        return pairs

    @staticmethod
    def _raw_journal(fixture, sanitized):
        authorization = fixture["authorization"]
        authorization_sha = bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(authorization)
        )
        source_sha = authorization["source"]["mergedMain"]["commitSha"]
        records = []
        for item in sanitized:
            record = {
                "schemaVersion": 1,
                "phase": item["phase"],
                "operationId": item["operationId"],
                "temporary": item["temporary"],
                "method": item["method"],
                "targetUrl": item["targetUrl"],
                "requestBodySha256": item["requestBodySha256"],
                "clientRequestId": item["clientRequestId"],
                "authorizationSha256": authorization_sha,
                "sourceSha": source_sha,
                "planSha256": fixture["planSha256"],
                "packageSha256": fixture["package"]["sha256"],
                "recordedAt": item["recordedAt"],
                "sequence": item["sequence"],
            }
            if item["phase"] == "result":
                record.update(
                    {
                        "intentId": item["intentId"],
                        "status": item["status"],
                        "responseBodySha256": item["responseBodySha256"],
                        "etag": item["etag"],
                        "versionId": item["versionId"],
                        "requestId": item["requestId"],
                        "serverDate": item["serverDate"],
                        "storageErrorCode": item["storageErrorCode"],
                    }
                )
            records.append(record)
        return records

    def test_sanitized_journal_rejects_client_request_id_reused_by_two_intents(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.fixture(folder)
        journal = copy.deepcopy(
            fixture["sourceEvidence"]["productionBoundary"]["mutationJournal"]
        )
        pairs = self._storage_intent_pairs(journal)
        self.assertGreaterEqual(len(pairs), 2)
        first_id = pairs[0][0]["clientRequestId"]
        pairs[1][0]["clientRequestId"] = first_id
        pairs[1][1]["clientRequestId"] = first_id
        contexts = {
            item["operationId"]: item["context"]
            for item in fixture["preflightProjection"]["operationAdmissions"]
        }

        with self.assertRaisesRegex(
            bootstrap.BootstrapError,
            "reuses a Storage client request ID",
        ):
            bootstrap._validate_sanitized_mutation_journal(
                journal,
                plan=fixture["plan"],
                authorization=fixture["authorization"],
                operation_projections=fixture["operationProjections"],
                operation_contexts=contexts,
            )

    def test_raw_journal_rejects_client_request_id_reused_by_two_intents(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.fixture(folder)
        sanitized = copy.deepcopy(
            fixture["sourceEvidence"]["productionBoundary"]["mutationJournal"]
        )
        pairs = self._storage_intent_pairs(sanitized)
        self.assertGreaterEqual(len(pairs), 2)
        first_id = pairs[0][0]["clientRequestId"]
        pairs[1][0]["clientRequestId"] = first_id
        pairs[1][1]["clientRequestId"] = first_id
        raw = self._raw_journal(fixture, sanitized)
        authorization = fixture["authorization"]
        contexts = {
            item["operationId"]: item["context"]
            for item in fixture["preflightProjection"]["operationAdmissions"]
        }

        with self.assertRaisesRegex(
            bootstrap.BootstrapError,
            "reuses a Storage client request ID",
        ):
            bootstrap._sanitize_mutation_journal(
                raw,
                plan=fixture["plan"],
                authorization_id=authorization["authorizationId"],
                authorization_sha256=bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes(authorization)
                ),
                source_sha=authorization["source"]["mergedMain"]["commitSha"],
                plan_sha256=fixture["planSha256"],
                package_sha256=fixture["package"]["sha256"],
                operation_projections=fixture["operationProjections"],
                operation_contexts=contexts,
            )


if __name__ == "__main__":
    unittest.main()
