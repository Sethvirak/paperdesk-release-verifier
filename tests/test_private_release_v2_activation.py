import copy
import json
from pathlib import Path
import tempfile
import unittest

from scripts import private_release_v2_activation as activation
from scripts import private_release_v2_fic_repin as repin
from tests.test_private_release_v2_fic_repin import Fixture, PHRASE, S2_MERGE


class OfflineActivationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fx = Fixture(self.temp.name)
        self.terminal = self.fx.apply()
        self.receipt_path = self.fx.receipt_directory / "06-terminal-receipt.json"

    def build(self):
        return activation.build_offline_activation(
            bootstrap_authorization_path=self.fx.bootstrap_authorization,
            bootstrap_preflight_path=self.fx.bootstrap_preflight,
            repin_receipt_path=self.receipt_path,
            repo_root=self.fx.repo,
            git_runner=self.fx.git,
        )

    def test_happy_path_builds_strict_distinct_s2_activation(self):
        output = self.build()
        contract = output["activationDocument"]["activation"]
        self.assertEqual(contract["mergedControlWorkflowSha"], S2_MERGE)
        self.assertEqual(contract["bridgePackageSourceSha"], self.fx.bundle["s1Sha"])
        self.assertNotEqual(
            contract["mergedControlWorkflowSha"], contract["bridgePackageSourceSha"]
        )
        self.assertEqual(output["package"]["sha256"], self.fx.bundle["package"]["sha256"])

    def test_wrong_activation_s2_binding_is_rejected(self):
        receipt = json.loads(self.receipt_path.read_text(encoding="utf-8"))
        receipt["source"]["binding"]["s2MergedSha"] = self.fx.bundle["s1Sha"]
        self.receipt_path.write_bytes(repin.canonical_json_bytes(receipt))
        with self.assertRaises((repin.RepinError, activation.ActivationError)):
            self.build()

    def test_wrong_repin_final_fic_is_rejected(self):
        receipt = json.loads(self.receipt_path.read_text(encoding="utf-8"))
        receipt["publisher"]["finalFederatedIdentityCredentials"] = [
            repin.expected_fic(
                self.fx.bundle["s1Sha"],
                credential_id="33333333-3333-4333-8333-333333333333",
            )
        ]
        self.receipt_path.write_bytes(repin.canonical_json_bytes(receipt))
        with self.assertRaisesRegex(repin.RepinError, "sole-S2"):
            self.build()

    def test_missing_evidence_is_rejected(self):
        path = self.fx.repo / Path(*self.fx.bundle["paths"][0].split("/"))
        path.unlink()
        with self.assertRaisesRegex(repin.RepinError, "required S2 evidence"):
            self.build()

    def test_altered_evidence_is_rejected(self):
        path = self.fx.repo / Path(*self.fx.bundle["paths"][1].split("/"))
        value = json.loads(path.read_text(encoding="utf-8"))
        value["status"] = "altered"
        path.write_bytes(repin.canonical_json_bytes(value))
        with self.assertRaises(repin.RepinError):
            self.build()

    def test_builder_rejects_s1_equals_s2(self):
        evidence = self.fx.bundle["provisioningEvidence"]
        paths = repin.receipts.S2_EVIDENCE_COMPONENT_PATHS
        runtime = repin.receipts.load_canonical_json_bytes(
            self.fx.bundle["s2Bodies"][paths["bridgeRuntimeReceipt"]],
            label="runtime",
        )
        fence = repin.receipts.load_canonical_json_bytes(
            self.fx.bundle["s2Bodies"][paths["activationFenceBootstrap"]],
            label="fence",
        )
        with self.assertRaisesRegex(activation.ActivationError, "S1 and S2"):
            activation._build_activation_document(
                s1_sha=self.fx.bundle["s1Sha"],
                s2_sha=self.fx.bundle["s1Sha"],
                package_sha256=self.fx.bundle["package"]["sha256"],
                provisioning_evidence=evidence,
                bridge_runtime_receipt=runtime,
                activation_fence_receipt=fence,
            )


if __name__ == "__main__":
    unittest.main()
