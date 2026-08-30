import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import validate_watchdog_baseline_bootstrap as bootstrap
from scripts import watchdog_evidence


SHA = "b" * 40


def baseline():
    source_sha = "9" * 40
    return {
        "schemaVersion": 2,
        "receiptSha256": "1" * 64,
        "evidencePath": "v2/baselines/99/1/initial.json",
        "sourceSha": source_sha,
        "sourceRunId": "88",
        "sourceRunAttempt": "1",
        "acceptanceRunId": "99",
        "acceptanceRunAttempt": "1",
        "acceptedReleaseManifestSha256": "2" * 64,
        "acceptedReleasePrefix": f"v1/releases/{source_sha}/88/99/",
        "reviewWorkflowRef": watchdog_evidence.BASELINE_WORKFLOW_REF,
        "reviewWorkflowSha": SHA,
        "reviewRunId": "700",
        "reviewRunAttempt": "1",
        "reviewEnvironment": watchdog_evidence.BASELINE_ENVIRONMENT,
        "preparedAt": "2026-08-23T03:00:00.000Z",
    }


class WatchdogBaselineBootstrapTests(unittest.TestCase):
    def test_checked_in_contract_is_dormant_and_admission_is_blocked_before_files(self):
        contract = bootstrap.load_contract()
        self.assertIsNone(
            contract["immutableExternalControl"]["mergedAdmissionCommitSha"]
        )
        self.assertTrue(contract["admission"]["oneTimeOnly"])
        self.assertTrue(contract["admission"]["providerStateMustBeAbsent"])
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(
            bootstrap.BaselineBootstrapError,
            "activation-blocked-null-merged-sha",
        ):
            bootstrap.validate_admission(
                contract,
                root=Path(temporary),
                expected_merged_sha=SHA,
            )

    def test_future_admission_requires_both_truthful_canonical_files_and_exact_sha(self):
        contract = copy.deepcopy(bootstrap.load_contract())
        contract["immutableExternalControl"]["mergedAdmissionCommitSha"] = SHA
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / contract["admission"]["evidenceFile"]
            checksum = root / contract["admission"]["evidenceChecksumFile"]
            evidence.parent.mkdir(parents=True)
            raw = watchdog_evidence.canonical_json(baseline())
            evidence.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            checksum.write_text(f"{digest}  {evidence.name}\n", encoding="ascii")

            result = bootstrap.validate_admission(
                contract,
                root=root,
                expected_merged_sha=SHA,
            )

            self.assertEqual(result["status"], "admission-source-validated")
            self.assertEqual(result["baselineReceiptSha256"], digest)
            self.assertTrue(result["oneTimeOnly"])
            with self.assertRaisesRegex(
                bootstrap.BaselineBootstrapError,
                "invoked workflow SHA",
            ):
                bootstrap.validate_admission(
                    contract,
                    root=root,
                    expected_merged_sha="c" * 40,
                )

    def test_noncanonical_or_checksum_drift_is_rejected(self):
        contract = copy.deepcopy(bootstrap.load_contract())
        contract["immutableExternalControl"]["mergedAdmissionCommitSha"] = SHA
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / contract["admission"]["evidenceFile"]
            checksum = root / contract["admission"]["evidenceChecksumFile"]
            evidence.parent.mkdir(parents=True)
            raw = json.dumps(baseline(), indent=2).encode("utf-8")
            evidence.write_bytes(raw)
            checksum.write_text(
                f"{hashlib.sha256(raw).hexdigest()}  {evidence.name}\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                bootstrap.BaselineBootstrapError,
                "not canonical JSON",
            ):
                bootstrap.validate_admission(
                    contract,
                    root=root,
                    expected_merged_sha=SHA,
                )


if __name__ == "__main__":
    unittest.main()
