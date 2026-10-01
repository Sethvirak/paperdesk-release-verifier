import copy
import datetime as dt
import hashlib
import json
import unittest
from pathlib import Path
from unittest import mock

from scripts import provisional_defender_canary_stage as stage


NOW = dt.datetime(2026, 9, 30, 0, 8, tzinfo=dt.timezone.utc)
OBSERVED = "2026-09-30T00:04:00.000Z"
DEPLOYED = "2026-09-30T00:00:00.000Z"
SOURCE = "a" * 40
TREE = "b" * 40
VERIFIER = "c" * 40
VERIFIER_TREE = "d" * 40
BASELINE = "e" * 40


def fixture():
    policy = copy.deepcopy(stage.load_policy())
    policy["status"] = "reviewed-allowlist-proposal"
    candidate = {
        "sourceSha": SOURCE,
        "sourceTreeSha": TREE,
        "verifierWorkflowSha": VERIFIER,
        "verifierTreeSha": VERIFIER_TREE,
        "verifiedArchiveSha256": "1" * 64,
        "deploymentPackageSha256": "2" * 64,
        "verificationReceiptSha256": "0" * 64,
        "sourceRunId": "101",
        "sourceRunAttempt": "1",
        "candidateRunId": "202",
        "candidateRunAttempt": "1",
        "artifactId": "303",
        "packageBlob": f"v1/pending/{SOURCE}/101-1-303/deployment.zip",
        "servedIndexSha256": "3" * 64,
        "rollbackBaselineSourceSha": BASELINE,
        "rollbackBaselineManifestSha256": "4" * 64,
        "reviewedOwnerRole": "paperdesk_visibility_owner",
        "ownerProbeLoginRole": "paperdesk_owner_probe",
        "ownerInventorySha256": "e" * 64,
        "ownerInventoryMenuRows": 5200,
    }
    policy["allowedCandidates"] = [candidate]
    receipt = {
        "schemaVersion": 1,
        "status": "candidate-verified",
        "candidateSha": SOURCE,
        "sourceRunId": "101",
        "sourceRunAttempt": "1",
        "sourceArtifactName": f"paperdesk-azure-runtime-unverified-{SOURCE}",
        "verifiedArtifactName": f"paperdesk-azure-runtime-verified-{SOURCE}",
        "verifierRunId": "111",
        "verifierRunAttempt": "1",
        "verifierWorkflow": (
            "Sethvirak/paperdesk-release-verifier/.github/workflows/verify-candidate.yml@"
            + VERIFIER
        ),
        "verifierJob": "verify_candidate",
        "archiveSha256": "1" * 64,
        "inputManifestSha256": "5" * 64,
        "runtimeManifestSha256": "6" * 64,
        "releaseMaterialsSha256": "7" * 64,
        "rootSbomSha256": "8" * 64,
        "widgetSbomSha256": "9" * 64,
        "provenanceSha256": "f" * 64,
    }
    raw = stage.canonical_json(receipt)
    candidate["verificationReceiptSha256"] = hashlib.sha256(raw).hexdigest()
    ready_body = {
        "ok": False,
        "status": "not-ready",
        "code": "service-not-ready",
        "attachmentMalware": {
            "required": True,
            "ingestionReady": False,
            "code": "attachment-malware-ingestion-not-ready",
        },
    }
    ready_raw = stage.canonical_json({
        **ready_body, "checkedAt": OBSERVED, "retryAfterSeconds": 2,
        "encryption": False,
    })
    evidence = {
        "schemaVersion": 1,
        "candidateSha": SOURCE,
        "deploymentRunId": "202",
        "deploymentRunAttempt": "1",
        "deployedAt": DEPLOYED,
        "packageReadback": {
            "blob": candidate["packageBlob"],
            "sha256": "2" * 64,
            "versionId": "2026-09-30T00:00:00.0000000Z",
            "etag": '"0x8D123456"',
            "lockState": "Locked",
            "publicAccess": "None",
            "observedAt": OBSERVED,
        },
        "acceptedBaseline": {
            "sourceSha": BASELINE,
            "manifestSha256": "4" * 64,
            "status": "accepted",
            "observedAt": OBSERVED,
        },
        "http": {
            "observedAt": OBSERVED,
            "sourceSha": SOURCE,
            "runtimeRelease": {"status": 200, "value": SOURCE},
            "index": {"status": 200, "sha256": "3" * 64},
            "live": {"status": 200, "ok": True},
            "ready": {
                "status": 503,
                "body": ready_body,
                "rawBodySha256": hashlib.sha256(ready_raw).hexdigest(),
            },
            "appHealth": {"status": 200, "ok": True},
            "securityInfo": {"status": 200, "ok": True},
        },
        "independent": {
            "postgres": {
                "source": "postgres-repository-readiness-readonly",
                "observedAt": OBSERVED,
                "probeContract": "app-kv-visibility-policy-v2",
                "appKvReachable": True,
                "visibilityReady": True,
                "visibilityPolicyVersion": 2,
                "result": True,
                "latencyMs": 21,
                "probeId": "401",
                "runtimeConfiguredRole": "paperdesk_app",
                "sessionRole": "paperdesk_app",
                "rowSecurityActive": True,
                "roleAttributes": {
                    "canLogin": True,
                    "superuser": False,
                    "bypassRls": False,
                    "createRole": False,
                    "createDb": False,
                    "replication": False,
                    "canCreateDatabaseObjects": False,
                    "canCreateTemporaryObjects": False,
                    "canCreatePublicSchemaObjects": False,
                    "ownedTables": [],
                    "ownedFunctions": [],
                    "ownerRoleMemberships": [],
                    "privilegedRoleMemberships": [],
                },
                "rolePreflightSha256": "d" * 64,
            },
            "ownerView": {
                "source": "postgres-reviewed-owner-readonly",
                "observedAt": OBSERVED,
                "sessionLoginRole": "paperdesk_owner_probe",
                "sessionRole": "paperdesk_visibility_owner",
                "roleTransition": "SET ROLE",
                "roleTransitionProofSha256": "f" * 64,
                "roleAttributes": {
                    "canLogin": False,
                    "superuser": False,
                    "bypassRls": False,
                    "createDb": False,
                    "createRole": False,
                    "replication": False,
                    "privilegedRoleMemberships": [],
                },
                "ownsMenuRows": True,
                "forceRls": True,
                "rowSecurityActive": True,
                "completePolicyCoverage": True,
                "visibilityPolicyVersion": 2,
                "visibleMenuRows": 5200,
                "badVisibilityRows": 0,
                "inventorySha256": "e" * 64,
                "probeId": "404",
            },
            "maintenance": {
                "source": "maintenance-gate-readonly",
                "observedAt": OBSERVED,
                "maintenance": False,
                "probeId": "402",
                "snapshotSha256": "b" * 64,
            },
            "capacity": {
                "source": "azure-monitor-readonly",
                "observedAt": OBSERVED,
                "saturated": False,
                "appCpuPercent5m": 20,
                "appMemoryPercent5m": 30,
                "postgresStorageUsedPercent": 40,
                "probeId": "403",
                "snapshotSha256": "c" * 64,
            },
        },
    }
    return policy, evidence, raw, ready_raw


class ProvisionalDefenderCanaryStageTests(unittest.TestCase):
    def evaluate(self, policy, evidence, raw, ready_raw, now=NOW):
        with mock.patch.object(stage, "verify_signed_commit") as signature:
            result = stage.evaluate_proposal(
                policy=policy, evidence=evidence, verification_receipt_raw=raw,
                ready_response_raw=ready_raw,
                app_repo=Path("app"), verifier_repo=Path("verifier"), now=now,
            )
        return result, signature

    def test_source_policy_is_dormant_and_has_no_candidates(self):
        policy = stage.load_policy()
        self.assertEqual(policy["status"], "source-dormant")
        self.assertEqual(policy["allowedCandidates"], [])
        with self.assertRaisesRegex(stage.ProvisionalCanaryError, "source-dormant"):
            self.evaluate(policy, {}, b"", b"")

    def test_exact_proposal_remains_unaccepted_and_non_activating(self):
        policy, evidence, raw, ready_raw = fixture()
        result, signature = self.evaluate(policy, evidence, raw, ready_raw)
        self.assertEqual(result["status"], "provisional-unaccepted-plan-only")
        self.assertEqual(result["rollbackDeadline"], "2026-10-01T00:00:00.000Z")
        self.assertTrue(result["provisionalMarkerPath"].startswith("v2/provisional/"))
        self.assertFalse(result["activationAllowed"])
        self.assertFalse(result["candidateConsumeAllowed"])
        self.assertFalse(result["acceptedRegistryWriteAllowed"])
        self.assertEqual(result["requiredRuntimeDatabaseRole"], "paperdesk_app")
        self.assertEqual(result["reviewedOwnerRole"], "paperdesk_visibility_owner")
        self.assertEqual(result["ownerProbeLoginRole"], "paperdesk_owner_probe")
        self.assertEqual(signature.call_count, 2)

    def test_no_policy_can_enable_activation_or_accepted_write(self):
        policy, evidence, raw, ready_raw = fixture()
        for field in ("activationAllowed", "candidateConsumeAllowed", "acceptedRegistryWriteAllowed"):
            altered = copy.deepcopy(policy)
            altered[field] = True
            with self.subTest(field=field), self.assertRaisesRegex(stage.ProvisionalCanaryError, "policy-boundary"):
                self.evaluate(altered, evidence, raw, ready_raw)

    def test_wrong_candidate_package_or_receipt_is_rejected(self):
        policy, evidence, raw, ready_raw = fixture()
        for path, value in (
            (("candidateSha",), BASELINE),
            (("packageReadback", "sha256"), "f" * 64),
            (("packageReadback", "blob"), "v2/accepted/forged/manifest.json"),
            (("acceptedBaseline", "manifestSha256"), "f" * 64),
        ):
            altered = copy.deepcopy(evidence)
            target = altered
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(stage.ProvisionalCanaryError):
                self.evaluate(policy, altered, raw, ready_raw)
        with self.assertRaisesRegex(stage.ProvisionalCanaryError, "verification-receipt-digest"):
            self.evaluate(policy, evidence, raw + b" ", ready_raw)

    def test_rehashed_receipt_cannot_change_source_artifact_or_verifier_job(self):
        policy, evidence, raw, ready_raw = fixture()
        for field, forged_value in (
            ("sourceArtifactName", "paperdesk-azure-runtime-unverified-forged"),
            ("verifierJob", "forged_verify_candidate"),
        ):
            forged_receipt = json.loads(raw)
            forged_receipt[field] = forged_value
            forged_raw = stage.canonical_json(forged_receipt)
            forged_policy = copy.deepcopy(policy)
            forged_policy["allowedCandidates"][0]["verificationReceiptSha256"] = (
                hashlib.sha256(forged_raw).hexdigest()
            )
            with self.subTest(field=field), self.assertRaisesRegex(
                stage.ProvisionalCanaryError, "verification-receipt-binding"
            ):
                self.evaluate(forged_policy, evidence, forged_raw, ready_raw)

    def test_owner_and_probe_roles_must_be_exact_reviewed_paperdesk_names(self):
        policy, evidence, raw, ready_raw = fixture()
        for field, bad_name in (
            ("reviewedOwnerRole", "paperdeskadmin"),
            ("reviewedOwnerRole", "azure_pg_admin"),
            ("reviewedOwnerRole", "paperdesk_azure_owner"),
            ("reviewedOwnerRole", "paperdesk_admin_owner"),
            ("reviewedOwnerRole", "paperdesk_visibility_probe"),
            ("ownerProbeLoginRole", "paperdeskadmin"),
            ("ownerProbeLoginRole", "paperdesk_admin_probe"),
            ("ownerProbeLoginRole", "paperdesk_app"),
        ):
            altered = copy.deepcopy(policy)
            altered["allowedCandidates"][0][field] = bad_name
            with self.subTest(field=field, bad_name=bad_name), self.assertRaises(
                stage.ProvisionalCanaryError
            ):
                self.evaluate(altered, evidence, raw, ready_raw)

    def test_only_exact_503_reason_is_proposed(self):
        policy, evidence, raw, ready_raw = fixture()
        for path, value in (
            (("http", "ready", "status"), 200),
            (("http", "ready", "body", "attachmentMalware", "code"), "database-down"),
            (("http", "ready", "body", "attachmentMalware", "ingestionReady"), True),
            (("http", "live", "ok"), False),
            (("http", "appHealth", "status"), 503),
            (("http", "securityInfo", "status"), 503),
        ):
            altered = copy.deepcopy(evidence)
            target = altered
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(stage.ProvisionalCanaryError):
                self.evaluate(policy, altered, raw, ready_raw)
        with self.assertRaisesRegex(stage.ProvisionalCanaryError, "ready-body-readback-digest"):
            self.evaluate(policy, evidence, raw, ready_raw + b" ")
        stale_ready_raw = stage.canonical_json({
            **evidence["http"]["ready"]["body"],
            "checkedAt": "2026-09-29T23:59:00.000Z",
            "retryAfterSeconds": 2,
            "encryption": False,
        })
        stale = copy.deepcopy(evidence)
        stale["http"]["ready"]["rawBodySha256"] = hashlib.sha256(stale_ready_raw).hexdigest()
        with self.assertRaisesRegex(stage.ProvisionalCanaryError, "ready-response-stale"):
            self.evaluate(policy, stale, raw, stale_ready_raw)

    def test_independent_health_and_freshness_fail_closed(self):
        policy, evidence, raw, ready_raw = fixture()
        for path, value in (
            (("independent", "postgres", "result"), False),
            (("independent", "postgres", "appKvReachable"), False),
            (("independent", "postgres", "visibilityReady"), False),
            (("independent", "postgres", "visibilityPolicyVersion"), 1),
            (("independent", "postgres", "runtimeConfiguredRole"), "paperdeskadmin"),
            (("independent", "postgres", "sessionRole"), "paperdeskadmin"),
            (("independent", "postgres", "rowSecurityActive"), False),
            (("independent", "postgres", "roleAttributes", "bypassRls"), True),
            (("independent", "postgres", "roleAttributes", "replication"), True),
            (("independent", "postgres", "roleAttributes", "canCreateDatabaseObjects"), True),
            (("independent", "postgres", "roleAttributes", "canCreateTemporaryObjects"), True),
            (("independent", "postgres", "roleAttributes", "canCreatePublicSchemaObjects"), True),
            (("independent", "postgres", "roleAttributes", "ownedTables"), ["menu_rows"]),
            (("independent", "postgres", "roleAttributes", "ownedFunctions"), ["paperdesk_admin"]),
            (("independent", "postgres", "roleAttributes", "ownerRoleMemberships"), ["paperdesk_owner"]),
            (("independent", "postgres", "roleAttributes", "privilegedRoleMemberships"), ["azure_pg_admin"]),
            (("independent", "ownerView", "sessionLoginRole"), "paperdeskadmin"),
            (("independent", "ownerView", "sessionRole"), "paperdeskadmin"),
            (("independent", "ownerView", "roleTransition"), "none"),
            (("independent", "ownerView", "roleTransitionProofSha256"), "unverified"),
            (("independent", "ownerView", "roleAttributes", "canLogin"), True),
            (("independent", "ownerView", "roleAttributes", "superuser"), True),
            (("independent", "ownerView", "roleAttributes", "bypassRls"), True),
            (("independent", "ownerView", "roleAttributes", "createDb"), True),
            (("independent", "ownerView", "roleAttributes", "createRole"), True),
            (("independent", "ownerView", "roleAttributes", "replication"), True),
            (("independent", "ownerView", "roleAttributes", "privilegedRoleMemberships"), ["azure_pg_admin"]),
            (("independent", "ownerView", "forceRls"), False),
            (("independent", "ownerView", "rowSecurityActive"), False),
            (("independent", "ownerView", "completePolicyCoverage"), False),
            (("independent", "ownerView", "visibleMenuRows"), 5199),
            (("independent", "ownerView", "badVisibilityRows"), 1),
            (("independent", "ownerView", "inventorySha256"), "0" * 64),
            (("independent", "maintenance", "maintenance"), True),
            (("independent", "capacity", "saturated"), True),
            (("independent", "capacity", "appCpuPercent5m"), 71),
            (("independent", "capacity", "postgresStorageUsedPercent"), 81),
            (("independent", "postgres", "observedAt"), "2026-09-29T23:59:00.000Z"),
            (("independent", "capacity", "probeId"), "401"),
            (("independent", "ownerView", "probeId"), "401"),
        ):
            altered = copy.deepcopy(evidence)
            target = altered
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(stage.ProvisionalCanaryError):
                self.evaluate(policy, altered, raw, ready_raw)
        with self.assertRaisesRegex(stage.ProvisionalCanaryError, "rollback-window"):
            self.evaluate(policy, evidence, raw, ready_raw, NOW + dt.timedelta(hours=24))

    def test_privileged_membership_proofs_are_required_not_optional(self):
        policy, evidence, raw, ready_raw = fixture()
        for proof in ("postgres", "ownerView"):
            altered = copy.deepcopy(evidence)
            altered["independent"][proof]["roleAttributes"].pop("privilegedRoleMemberships")
            with self.subTest(proof=proof), self.assertRaises(stage.ProvisionalCanaryError):
                self.evaluate(policy, altered, raw, ready_raw)

    def test_signed_source_verifies_exact_principal_key_tree_and_remote(self):
        outputs = [
            "https://github.com/Sethvirak/MasterDataStructure.git",
            TREE,
            "",
            f"G\x00{stage.SIGNING_PRINCIPAL}\x00{stage.SIGNING_FINGERPRINT}",
        ]
        with mock.patch.object(stage, "_git", side_effect=outputs) as git:
            stage.verify_signed_commit(Path("app"), SOURCE, TREE, stage.APP_REMOTES)
        self.assertEqual(git.call_count, 4)
        self.assertIn("verify-commit", git.call_args_list[2].args)
        outputs[-1] = "N\x00\x00"
        with mock.patch.object(stage, "_git", side_effect=outputs):
            with self.assertRaisesRegex(stage.ProvisionalCanaryError, "signed-source-principal"):
                stage.verify_signed_commit(Path("app"), SOURCE, TREE, stage.APP_REMOTES)
        outputs[0] = "https://example.invalid/forged.git"
        with mock.patch.object(stage, "_git", side_effect=outputs):
            with self.assertRaisesRegex(stage.ProvisionalCanaryError, "signed-source-remote"):
                stage.verify_signed_commit(Path("app"), SOURCE, TREE, stage.APP_REMOTES)


if __name__ == "__main__":
    unittest.main()
