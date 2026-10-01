"""Offline canary/receipt handoff qualification, not live release evidence."""

import copy
import datetime as dt
import tempfile
import unittest
import os
import uuid
import socket
import subprocess
from pathlib import Path
from unittest import mock

from tests.control_lifecycle_offline_boundary import external_access_blocked

with external_access_blocked() as _import_attempts:
    from scripts import private_release_v2_bootstrap as bootstrap
    from scripts import private_release_v2_bootstrap_receipts as receipts
    from scripts import private_release_v2_terminal_s2 as terminal_s2
    from scripts import private_release_v2_webjob_evidence as webjob_evidence
    from tests import test_private_release_v2_bootstrap as reference
    from tests.control_lifecycle_qualification_helper import (
        CANARY, CONFIGURE, ConnectedTerminalFixture, PersistentCanaryProvider,
    )
if _import_attempts:
    raise AssertionError("qualification imports attempted external access")


class ConnectedControlLifecycleQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with external_access_blocked() as attempts:
            cls.plan, cls.plan_sha = bootstrap.load_plan()
            cls.package, cls.package_bytes = bootstrap.build_package_artifact()
            cls.site = next(item for item in cls.plan["resourceInventory"] if item["id"] == "bridgeSite")
        if attempts:
            raise AssertionError("qualification fixture setup attempted external access")

    def setUp(self):
        self._boundary = external_access_blocked()
        self._external_attempts = self._boundary.__enter__()

    def tearDown(self):
        self._boundary.__exit__(None, None, None)
        self.assertEqual(self._external_attempts, [])

    def fixture(self, root, provider, *, fault=None):
        root.mkdir(parents=True, exist_ok=True)
        return ConnectedTerminalFixture(
            self.plan, self.plan_sha, self.package,
            root / f"paperdesk-private-release-v2-bootstrap-{reference.AUTH_ID}",
            provider, fault=fault,
        )

    def validate_handoff(self, fixture, evidence):
        source = bootstrap.validate_terminal_source_evidence(
            plan=fixture.plan, authorization=fixture.authorization,
            preflight_projection=fixture.projection, evidence=evidence,
        )
        started = source["claimReceipt"]["claimedAt"]
        completed = source["observedAt"]
        components = bootstrap.build_terminal_receipt_components(
            plan=fixture.plan, authorization=fixture.authorization,
            preflight_projection=fixture.projection, source_evidence=source,
            started_at=started, completed_at=completed,
        )
        documents = terminal_s2.build_terminal_s2_documents(
            plan=fixture.plan, authorization=fixture.authorization,
            preflight_projection=fixture.projection, source_evidence=source,
            components=components, started_at=started, completed_at=completed,
        )
        complete = receipts.build_complete_receipt_bundle(
            authorization=fixture.authorization, plan=fixture.plan,
            components=components, s2_documents=documents, source_evidence=source,
            authorized_preflight_projection=fixture.projection, package_bytes=self.package_bytes,
            started_at=started, completed_at=completed,
            now=bootstrap.parse_time(completed, "synthetic completion"),
        )
        return source, components, documents, complete

    def assert_private_clean(self, fixture, provider):
        self.assertEqual(provider.state, "Stopped")
        self.assertEqual(provider.public, "Disabled")
        self.assertFalse(provider.scm)
        self.assertFalse((fixture.ledger.directory / bootstrap.UNRESOLVED_PUBLIC_NETWORK_ENABLE_FILENAME).exists())
        self.assertEqual(fixture.ledger.unresolved_intents(), [])

    def test_two_persistent_history_attempts_emit_and_validate_real_canary_handoffs(self):
        provider = PersistentCanaryProvider(self.site)
        original_now = reference.NOW
        synthetic_ids = tuple(str(uuid.UUID(bytes=bytes([value]) * 16, version=4)) for value in (0xaa, 0xee))
        self.assertEqual(len(set(synthetic_ids)), 2)
        self.assertTrue(all(uuid.UUID(value).version == 4 for value in synthetic_ids))
        agents = []
        with tempfile.TemporaryDirectory() as folder:
            for index in range(2):
                with self.subTest(attempt=index + 1), mock.patch.multiple(
                    reference, NOW=original_now + dt.timedelta(minutes=10 * index),
                    AUTH_ID=synthetic_ids[index],
                ):
                    fixture = self.fixture(Path(folder) / f"attempt-{index}", provider)
                    old_ids = set(provider.runs)
                    old_records = copy.deepcopy(provider.runs)
                    evidence = fixture.build_evidence()
                    source, components, documents, complete = self.validate_handoff(fixture, evidence)
                    self.assertEqual(fixture.session.trigger_count, 1)
                    agents.append(fixture.operations[CANARY]["projection"]["triggerCorrelation"]["userAgent"])
                    self.assertTrue(agents[-1].startswith(bootstrap.WEBJOB_TRIGGER_USER_AGENT_PREFIX + synthetic_ids[index] + "."))
                    self.assertEqual(fixture.ledger.authorization_id, synthetic_ids[index])
                    with self.assertRaisesRegex(bootstrap.BootstrapError, "already consumed"):
                        fixture.ledger.claim()
                    self.assertEqual(len(provider.runs), 5 + index)
                    self.assertEqual(len(fixture.session.collections), 3)
                    for name in old_ids:
                        self.assertEqual(fixture.session.detail_reads[name], 3)
                        self.assertEqual(provider.runs[name], old_records[name])
                    new_id = fixture.operations[CANARY]["projection"]["terminalHistory"]["webJobsRunId"]
                    self.assertEqual(fixture.session.detail_reads[new_id], 2)
                    self.assertEqual(len(fixture.emitted_budgets), 1)
                    self.assertEqual(fixture.emitted_budgets[0]._remaining,
                                     728 - len(old_ids) - 2 * (len(old_ids) + 1))
                    self.assertEqual(len(fixture.session.collections[-1]), 5 + index)
                    self.assertEqual(source, evidence)
                    self.assertEqual(complete["bundle"]["executionReceipt"]["status"], "succeeded-terminal")
                    self.assertEqual(len(documents), 5)
                    self.assertEqual(components["bridgeEvidence"]["status"], "terminal-success-with-source-derived-boundaries-complete")
                    self.assertEqual(fixture.session.settings_put_count, 1)
                    emitted_fields = set(fixture.emitted_runtime_facts[CANARY]["historyBoundary"])
                    self.assertNotIn("detailResponseSha256s", emitted_fields)
                    for actual in fixture.emitted_sanitized_journal:
                        candidates = [row for row in source["productionBoundary"]["mutationJournal"]
                                      if row["operationId"] == actual["operationId"]
                                      and row["phase"] == actual["phase"]
                                      and row["recordedAt"] == actual["recordedAt"]]
                        self.assertEqual(len(candidates), 1)
                        self.assertEqual(
                            {key: item for key, item in candidates[0].items() if key not in {"sequence", "intentId"}},
                            {key: item for key, item in actual.items() if key not in {"sequence", "intentId"}},
                        )
                    self.assert_private_clean(fixture, provider)
                    # Success preserves the exact configured settings, as the owner requires.
                    self.assertIn("PAPERDESK_BRIDGE_BOOTSTRAP_SELF_TEST_JSON", provider.settings)
        self.assertEqual(len(agents), 2)
        self.assertNotEqual(agents[0], agents[1])

    def test_history_failure_keeps_real_cleanup_and_blocks_receipt_handoff(self):
        for fault in ("old-drift", "extra-run", "malformed-final"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as folder:
                provider = PersistentCanaryProvider(self.site)
                fixture = self.fixture(Path(folder), provider, fault=fault)
                with self.assertRaises(bootstrap.BootstrapError):
                    fixture.build_evidence()
                self.assertEqual(fixture.session.trigger_count, 1)
                self.assertNotIn(CANARY, fixture.operations)
                self.assert_private_clean(fixture, provider)
                cleanup = fixture.compensate_settings()
                self.assertEqual(cleanup["status"], "removed-exact")
                self.assertEqual(provider.settings, {})
                self.assertEqual(fixture.session.settings_put_count, 2)
                self.assert_private_clean(fixture, provider)
                if fault == "malformed-final":
                    self.assertEqual(len(fixture.session.collections), 3)
                self.assertFalse((fixture.ledger.directory / fixture.plan["evidenceOutputs"]["terminalBundlePath"]).exists())

    def test_handoff_rejects_tampered_emitted_canary_proof(self):
        with tempfile.TemporaryDirectory() as folder:
            provider = PersistentCanaryProvider(self.site)
            fixture = self.fixture(Path(folder), provider)
            evidence = fixture.build_evidence()
            self.validate_handoff(fixture, evidence)
            changed = copy.deepcopy(evidence)
            row = next(item for item in changed["allOperationProjections"] if item["operationId"] == CANARY)
            row["sourceProjection"]["projection"]["finalHistoryCensus"]["entries"] = []
            with self.assertRaises(bootstrap.BootstrapError):
                self.validate_handoff(fixture, changed)

    def test_receipt_adapter_removes_only_internal_field_without_mutating_reader(self):
        raw = {"entries": [], "detailResponseSha256s": ["a" * 64], "unexpected": "preserved"}
        before = copy.deepcopy(raw)
        adapted = webjob_evidence.receipt(raw)
        self.assertEqual(adapted, {"entries": [], "unexpected": "preserved"})
        self.assertEqual(raw, before)
        self.assertIsNot(raw, adapted)

    def test_unknown_receipt_field_still_fails_strict_handoff(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.fixture(Path(folder), PersistentCanaryProvider(self.site))
            evidence = fixture.build_evidence()
            for field in ("historyBoundary", "finalHistoryCensus"):
                with self.subTest(field=field):
                    changed = copy.deepcopy(evidence)
                    row = next(item for item in changed["allOperationProjections"] if item["operationId"] == CANARY)
                    row["sourceProjection"]["projection"][field]["unexpected"] = "still-rejected"
                    with self.assertRaisesRegex(bootstrap.BootstrapError, "fields are not exact"):
                        self.validate_handoff(fixture, changed)

    def test_connected_credit_and_request_reserve_failures_keep_owned_cleanup(self):
        for fault, old_count in (("credit-exhaustion", 200), ("slow-detail", 4)):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as folder:
                provider = PersistentCanaryProvider(self.site, old_count=old_count)
                fixture = self.fixture(Path(folder), provider, fault=fault)
                expected = "shared detail read budget" if fault == "credit-exhaustion" else "protected cleanup reserve"
                with self.assertRaisesRegex(bootstrap.BootstrapError, expected):
                    fixture.build_evidence()
                self.assertEqual(fixture.session.trigger_count, 1)
                self.assertEqual(len(fixture.emitted_budgets), 1)
                self.assert_private_clean(fixture, provider)
                self.assertNotIn(CANARY, fixture.operations)
                if fault == "credit-exhaustion":
                    budget = fixture.emitted_budgets[0]
                    self.assertEqual(budget._remaining, 728 - 200 - 201)
                    self.assertEqual(budget._final_reserve, 201)
                    # The next whole census is rejected before any of its detail requests.
                    self.assertEqual(sum(fixture.session.detail_reads.values()), 401)
                else:
                    # One slow detail spends a credit; the next has no full 90-second envelope.
                    self.assertEqual(sum(fixture.session.detail_reads.values()), 5)
                    self.assertEqual(fixture.emitted_budgets[0]._remaining, 728 - 6)
                cleanup = fixture.compensate_settings()
                self.assertEqual(cleanup["status"], "removed-exact")
                self.assertEqual(provider.settings, {})
                self.assert_private_clean(fixture, provider)

    def test_expired_canary_control_never_triggers_and_owned_settings_restore(self):
        with tempfile.TemporaryDirectory() as folder:
            provider = PersistentCanaryProvider(self.site)
            fixture = self.fixture(Path(folder), provider, fault="expired-control")
            with self.assertRaisesRegex(bootstrap.BootstrapError, "control is no longer live"):
                fixture.build_evidence()
            self.assertEqual(fixture.session.trigger_count, 0)
            self.assertEqual(fixture.session.stop_count, 0)
            self.assert_private_clean(fixture, provider)
            cleanup = fixture.compensate_settings()
            self.assertEqual(cleanup["status"], "removed-exact")
            self.assertEqual(provider.settings, {})
            self.assertEqual(fixture.session.settings_put_count, 2)

    def test_settings_compensation_preserves_concurrent_third_state(self):
        with tempfile.TemporaryDirectory() as folder:
            provider = PersistentCanaryProvider(self.site)
            fixture = self.fixture(Path(folder), provider, fault="old-drift")
            with self.assertRaises(bootstrap.BootstrapError):
                fixture.build_evidence()
            self.assert_private_clean(fixture, provider)
            third_state = {"UNRELATED_ADMIN_SETTING": "preserve"}
            provider.settings = copy.deepcopy(third_state)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "concurrent third state"):
                fixture.compensate_settings()
            self.assertEqual(provider.settings, third_state)
            self.assertEqual(fixture.session.settings_put_count, 1)
            self.assert_private_clean(fixture, provider)

    def test_offline_boundary_denies_network_process_and_credential_cache(self):
        names = ("SYNTHETIC_TOKEN", "SYNTHETIC_SECRET", "SYNTHETIC_PASSWORD", "SYNTHETIC_CONNECTION_STRING",
                 "DATABASE_URL", "AZURE_CLIENT_ID", "ARM_CLIENT_ID", "PGHOST", "PGUSER", "SSH_AUTH_SOCK")
        with mock.patch.dict(os.environ, {name: "synthetic-unused" for name in names}), external_access_blocked() as attempted:
            self.assertTrue(all(name not in os.environ for name in names))
            with self.assertRaisesRegex(AssertionError, "network"):
                socket.create_connection(("example.invalid", 443))
            with self.assertRaisesRegex(AssertionError, "child process"):
                subprocess.run(["az", "account", "get-access-token"])
            with self.assertRaisesRegex(AssertionError, "credential-cache"):
                Path.home().joinpath(".azure", "msal_token_cache.bin").read_bytes()
            for cache_path in ((".ssh", "id_ed25519"), (".netrc",)):
                with self.assertRaisesRegex(AssertionError, "credential-cache"):
                    Path.home().joinpath(*cache_path).read_bytes()
        self.assertEqual(attempted, ["network", "child process", *["credential-cache access"] * 3])


if __name__ == "__main__":
    unittest.main()
