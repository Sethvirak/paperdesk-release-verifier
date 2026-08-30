import copy
import tempfile
import unittest
from pathlib import Path

from scripts import private_release_v2_bootstrap as bootstrap
from scripts import private_release_v2_bootstrap_receipts as receipts
from scripts.private_release_v2_terminal_s2 import build_terminal_s2_documents
from tests.test_private_release_v2_bootstrap import (
    build_complete_terminal_receipt_input_fixture,
)


AUTHORIZATION_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


class TerminalS2BuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory()
        cls.fixture = build_complete_terminal_receipt_input_fixture(
            Path(cls._temporary.name)
            / f"paperdesk-private-release-v2-bootstrap-{AUTHORIZATION_ID}"
        )

    @classmethod
    def tearDownClass(cls):
        cls._temporary.cleanup()

    def build(self, **overrides):
        inputs = {
            "plan": self.fixture["plan"],
            "authorization": self.fixture["authorization"],
            "preflight_projection": self.fixture["preflightProjection"],
            "source_evidence": self.fixture["sourceEvidence"],
            "components": self.fixture["components"],
            "started_at": self.fixture["startedAt"],
            "completed_at": self.fixture["completedAt"],
        }
        inputs.update(overrides)
        return build_terminal_s2_documents(**inputs)

    def test_production_builder_matches_all_five_reference_bodies_byte_for_byte(self):
        built = self.build()
        self.assertEqual(list(built), list(self.fixture["s2Documents"]))
        self.assertEqual(built, self.fixture["s2Documents"])
        for path, body in built.items():
            self.assertIs(type(body), bytes)
            self.assertEqual(
                receipts.load_canonical_json_bytes(
                    body, label=f"test terminal S2 body {path}"
                ),
                receipts.load_canonical_json_bytes(
                    self.fixture["s2Documents"][path],
                    label=f"reference terminal S2 body {path}",
                ),
            )

    def test_exact_claim_and_terminal_times_are_derived_when_omitted(self):
        built = self.build(started_at=None, completed_at=None)
        self.assertEqual(built, self.fixture["s2Documents"])

    def test_caller_cannot_replace_a_source_owned_component_fact(self):
        components = copy.deepcopy(self.fixture["components"])
        components["bridgeEvidence"]["settings"]["afterSha256"] = "f" * 64
        with self.assertRaisesRegex(
            receipts.BootstrapReceiptError, "exact source-owned rebuild"
        ):
            self.build(components=components)

    def test_caller_cannot_replace_validated_terminal_source_identity(self):
        source = copy.deepcopy(self.fixture["sourceEvidence"])
        source["managedIdentityFetchResponseProjection"]["identityClientId"] = (
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        )
        with self.assertRaises(bootstrap.BootstrapError):
            self.build(source_evidence=source)

    def test_caller_cannot_expand_the_exact_execution_window(self):
        with self.assertRaisesRegex(
            receipts.BootstrapReceiptError, "execution start"
        ):
            self.build(started_at="2026-08-30T00:00:00Z")
        with self.assertRaisesRegex(
            receipts.BootstrapReceiptError, "execution completion"
        ):
            self.build(completed_at="2026-08-30T23:59:59Z")

    def test_created_and_adopted_exact_paths_have_identical_s2_derivation(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = build_complete_terminal_receipt_input_fixture(
                Path(folder)
                / f"paperdesk-private-release-v2-bootstrap-{AUTHORIZATION_ID}",
                adopt_operations={
                    "uploadVersionedBridgePackage",
                    "createInitialIdleActivationFence",
                },
            )
        built = build_terminal_s2_documents(
            plan=fixture["plan"],
            authorization=fixture["authorization"],
            preflight_projection=fixture["preflightProjection"],
            source_evidence=fixture["sourceEvidence"],
            components=fixture["components"],
            started_at=fixture["startedAt"],
            completed_at=fixture["completedAt"],
        )
        self.assertEqual(built, fixture["s2Documents"])
        self.assertEqual(
            fixture["components"]["packageReadback"]["provisioningOutcome"],
            "adopted-exact",
        )
        self.assertEqual(
            fixture["components"]["activationFenceBootstrap"][
                "provisioningOutcome"
            ],
            "adopted-exact",
        )


if __name__ == "__main__":
    unittest.main()
