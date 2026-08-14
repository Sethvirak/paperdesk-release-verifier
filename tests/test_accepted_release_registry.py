import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "accepted_release_registry", ROOT / "scripts" / "accepted_release_registry.py"
)
registry = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(registry)

SHA = "a" * 40
SOURCE_RUN = "41001"
SOURCE_ATTEMPT = "2"
ACCEPTANCE_RUN = "42001"
ACCEPTANCE_ATTEMPT = "1"
EVIDENCE_RUN = "42000"
EVIDENCE_ATTEMPT = "3"
SOURCE_WORKFLOW = registry.PAPERDESK_SOURCE_WORKFLOW_REF
ACCEPTANCE_WORKFLOW = (
    "Sethvirak/MasterDataStructure/.github/workflows/"
    f"main_master-data-structure-sea-9c4e0d0d.yml@{SHA}"
)
VERIFIER_WORKFLOW = f"Sethvirak/paperdesk-release-verifier/.github/workflows/verify-candidate.yml@{'b' * 40}"
EVIDENCE_NAME = f"paperdesk-production-acceptance-evidence-post-deploy-{SHA}"


def hex_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class RegistryFixture:
    def __init__(self, root: Path):
        self.root = root
        self.verified = root / "verified"
        self.verified.mkdir()
        inventory = registry.expected_verified_inventory(SHA)
        for relative in inventory:
            path = self.verified / Path(*Path(relative).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            if relative.endswith(".provenance.json"):
                body = json.dumps({
                    "commit": SHA,
                    "repository": "Sethvirak/MasterDataStructure",
                    "workflow": SOURCE_WORKFLOW,
                    "runId": SOURCE_RUN,
                    "runAttempt": SOURCE_ATTEMPT,
                }).encode()
            else:
                body = (relative + "\n").encode()
            path.write_bytes(body)
        archive_name = f"paperdesk-azure-runtime-{SHA}.tar.gz"
        archive = self.verified / archive_name
        archive.write_bytes(b"bounded verified runtime archive")
        (self.verified / f"{archive_name}.sha256").write_text(
            f"{registry.sha256_file(archive)}  {archive_name}\n", encoding="ascii"
        )

        self.verification = root / f"paperdesk-candidate-verification-receipt-{SHA}.json"
        verification = {
            "schemaVersion": 1,
            "status": "candidate-verified",
            "candidateSha": SHA,
            "sourceRunId": SOURCE_RUN,
            "sourceRunAttempt": SOURCE_ATTEMPT,
            "sourceArtifactName": f"paperdesk-azure-runtime-unverified-{SHA}",
            "verifiedArtifactName": f"paperdesk-azure-runtime-verified-{SHA}",
            "verifierRunId": "41111",
            "verifierRunAttempt": "1",
            "verifierWorkflow": VERIFIER_WORKFLOW,
            "verifierJob": "verify_candidate",
            "archiveSha256": "1" * 64,
            "inputManifestSha256": "2" * 64,
            "runtimeManifestSha256": "3" * 64,
            "releaseMaterialsSha256": "4" * 64,
            "rootSbomSha256": "5" * 64,
            "widgetSbomSha256": "6" * 64,
            "provenanceSha256": "7" * 64,
        }
        self.verification.write_text(json.dumps(verification), encoding="utf-8")
        self.acceptance = root / f"paperdesk-production-acceptance-receipt-{SHA}.json"
        self.worm = {
            "resourceId": (
                "/subscriptions/9c4e0d0d-602f-4cde-84bd-337250e5b64c/resourceGroups/"
                f"{registry.STORAGE_RESOURCE_GROUP}/providers/Microsoft.Storage/storageAccounts/{registry.ACCOUNT}"
                f"/blobServices/default/containers/{registry.CONTAINER}/immutabilityPolicies/default"
            ),
            "storageAccount": registry.ACCOUNT,
            "container": registry.CONTAINER,
            "state": "Locked",
            "immutabilityPeriodSinceCreationInDays": 30,
            "allowProtectedAppendWrites": False,
            "allowProtectedAppendWritesAll": False,
            "etag": '"fixed-policy-etag"',
            "observedAt": "2026-08-14T01:02:03Z",
        }
        acceptance = json.loads(
            (ROOT / "tests" / "fixtures" / "paperdesk-fully-accepted-receipt-v1.json").read_text(
                encoding="utf-8"
            )
        )
        acceptance["evidenceContractSha256"] = registry.sha256_file(
            self.verified / f"paperdesk-azure-runtime-{SHA}.acceptance-contract.json"
        )
        self.acceptance.write_text(json.dumps(acceptance), encoding="utf-8")
        (self.root / "worm-snapshot.json").write_text(json.dumps(self.worm), encoding="utf-8")

    def args(self, output: Path) -> argparse.Namespace:
        return argparse.Namespace(
            source_sha=SHA,
            source_run_id=SOURCE_RUN,
            source_run_attempt=SOURCE_ATTEMPT,
            acceptance_run_id=ACCEPTANCE_RUN,
            acceptance_run_attempt=ACCEPTANCE_ATTEMPT,
            acceptance_workflow_ref=ACCEPTANCE_WORKFLOW,
            evidence_run_id=EVIDENCE_RUN,
            evidence_run_attempt=EVIDENCE_ATTEMPT,
            evidence_artifact_id="93001",
            evidence_artifact_name=EVIDENCE_NAME,
            evidence_bundle_sha256="8" * 64,
            verified_artifact_id="93002",
            verified_artifact_digest="9" * 64,
            verification_artifact_id="93003",
            verification_artifact_digest="c" * 64,
            acceptance_artifact_id="93004",
            acceptance_artifact_digest="d" * 64,
            verified_artifact_dir=str(self.verified),
            verification_receipt=str(self.verification),
            acceptance_receipt=str(self.acceptance),
            worm_snapshot=str(self.root / "worm-snapshot.json"),
            output=str(output),
        )


class FakeStorage:
    def __init__(self):
        self.blobs = {}
        self.events = []

    def get(self, blob_name, prefix, maximum):
        registry.blob_url(blob_name, prefix)
        self.events.append(("get", blob_name))
        if blob_name not in self.blobs:
            return 404, b"", {}
        body = self.blobs[blob_name]
        return 200, body, {
            "content-md5": base64.b64encode(hashlib.md5(body, usedforsecurity=False).digest()).decode("ascii")
        }

    def put_create_only(self, blob_name, prefix, path, content_md5):
        registry.blob_url(blob_name, prefix)
        self.events.append(("put", blob_name))
        if blob_name in self.blobs:
            return 403, "UnauthorizedBlobOverwrite"
        body = path.read_bytes()
        self.blobs[blob_name] = body
        return 201, ""

    def put_bytes_create_only(self, blob_name, prefix, body):
        registry.blob_url(blob_name, prefix)
        self.events.append(("put", blob_name))
        if blob_name in self.blobs:
            return 403, "UnauthorizedBlobOverwrite"
        self.blobs[blob_name] = body
        return 201, ""


class AcceptedReleaseRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = RegistryFixture(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def build(self, name="request.tar.gz"):
        output = self.root / name
        result = registry.build_request(self.fixture.args(output))
        return output, result

    def test_request_is_deterministic_and_preserves_exact_nineteen_files(self):
        first, first_result = self.build("first.tar.gz")
        second, second_result = self.build("second.tar.gz")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first_result["requestSha256"], second_result["requestSha256"])
        self.assertEqual(first_result["fileCount"], 19)
        extracted = self.root / "extracted"
        request, files = registry.extract_request(first, extracted)
        self.assertEqual(len(files), 19)
        self.assertEqual(
            request["registry"]["prefix"],
            f"v1/releases/{SHA}/{SOURCE_RUN}/{ACCEPTANCE_RUN}/",
        )
        self.assertEqual(request["wormSnapshot"]["state"], "Locked")
        self.assertEqual(request["artifacts"]["verified"]["id"], "93002")

    def test_manifest_is_uploaded_last_after_readback_and_negative_checks(self):
        request, _ = self.build()
        storage = FakeStorage()
        result = registry.persist_request(request, storage)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["fileCount"], 19)
        self.assertEqual(result["overwriteNegative"], "passed")
        self.assertEqual(result["outOfPrefixNegative"], "passed")
        put_names = [name for operation, name in storage.events if operation == "put"]
        self.assertTrue(put_names[-1].endswith("/registry-manifest.json"))
        manifest = json.loads(storage.blobs[put_names[-1]])
        self.assertEqual(manifest["schema"], registry.MANIFEST_SCHEMA)
        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(len(manifest["files"]), 19)
        # A retry is read-only/idempotent and validates the same sole marker.
        event_count = len(storage.events)
        retried = registry.persist_request(request, storage)
        self.assertEqual(retried["manifestSha256"], result["manifestSha256"])
        self.assertEqual(retried["overwriteNegative"], "not-run-completed")
        self.assertFalse(any(op == "put" for op, _ in storage.events[event_count:]))

    def test_interrupted_all_payloads_without_manifest_proves_overwrite_before_completion(self):
        request, _ = self.build("interrupted.tar.gz")
        storage = FakeStorage()
        first = registry.persist_request(request, storage)
        del storage.blobs[first["manifestBlob"]]
        storage.events.clear()

        recovered = registry.persist_request(request, storage)
        self.assertEqual(recovered["overwriteNegative"], "passed")
        self.assertEqual(recovered["createdBlobCount"], 1)
        put_names = [name for operation, name in storage.events if operation == "put"]
        self.assertEqual(len(put_names), 2)
        self.assertFalse(put_names[0].endswith("/registry-manifest.json"))
        self.assertTrue(put_names[-1].endswith("/registry-manifest.json"))

    def test_tampered_payload_fails_before_any_storage_write(self):
        request, _ = self.build()
        extracted = self.root / "mutate"
        metadata, files = registry.extract_request(request, extracted)
        first = next(iter(files.values()))
        first.write_bytes(first.read_bytes() + b"tamper")
        with self.assertRaises(registry.RegistryError):
            registry.validate_request(metadata, extracted)

    def test_completed_entry_with_missing_payload_fails_without_repair_write(self):
        request, _ = self.build()
        storage = FakeStorage()
        result = registry.persist_request(request, storage)
        manifest = result["manifestBlob"]
        missing = next(name for name in storage.blobs if name != manifest)
        del storage.blobs[missing]
        event_count = len(storage.events)
        with self.assertRaises(registry.RegistryError):
            registry.persist_request(request, storage)
        self.assertFalse(any(op == "put" for op, _ in storage.events[event_count:]))

    def test_out_of_prefix_and_traversal_are_rejected(self):
        prefix = f"v1/releases/{SHA}/{SOURCE_RUN}/{ACCEPTANCE_RUN}/"
        with self.assertRaises(registry.RegistryError):
            registry.blob_url(f"v1/releases/{SHA}/outside", prefix)
        hostile = self.root / "hostile.tar.gz"
        with tarfile.open(hostile, "w:gz") as archive:
            info = tarfile.TarInfo("../escape")
            info.size = 1
            archive.addfile(info, fileobj=__import__("io").BytesIO(b"x"))
        with self.assertRaises(registry.RegistryError):
            registry.extract_request(hostile, self.root / "hostile-output")
        self.assertFalse((self.root / "escape").exists())

    def test_actions_artifact_safe_extractor_rejects_escape(self):
        hostile = self.root / "hostile.zip"
        with zipfile.ZipFile(hostile, "w") as archive:
            archive.writestr("../escape", b"x")
        with self.assertRaises(registry.RegistryError):
            registry.safe_extract_actions_zip(hostile, self.root / "zip-output")
        self.assertFalse((self.root / "escape").exists())

    def test_worm_policy_must_be_locked_and_exact(self):
        snapshot = self.root / "worm-snapshot.json"
        document = json.loads(snapshot.read_text(encoding="utf-8"))
        document["state"] = "Unlocked"
        snapshot.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(registry.RegistryError):
            registry.build_request(self.fixture.args(self.root / "rejected.tar.gz"))

    def test_storage_and_bridge_resource_groups_are_fixed_and_not_interchangeable(self):
        self.assertEqual(registry.STORAGE_RESOURCE_GROUP, "rg-paperdesk-rollback-sea-20260808")
        self.assertEqual(registry.BRIDGE_RESOURCE_GROUP, "rg-master-data-structure-sea")
        self.assertNotEqual(registry.STORAGE_RESOURCE_GROUP, registry.BRIDGE_RESOURCE_GROUP)
        output, _ = self.build("resource-groups.tar.gz")
        request, _ = registry.extract_request(output, self.root / "resource-groups")
        self.assertEqual(request["registry"]["bridgeResourceGroup"], registry.BRIDGE_RESOURCE_GROUP)

        tampered_root = self.root / "tampered-request"
        metadata, _ = registry.extract_request(output, tampered_root)
        metadata["registry"]["bridgeResourceGroup"] = registry.STORAGE_RESOURCE_GROUP
        with self.assertRaises(registry.RegistryError):
            registry.validate_request(metadata, tampered_root)

        snapshot = self.root / "worm-snapshot.json"
        document = json.loads(snapshot.read_text(encoding="utf-8"))
        document["resourceId"] = document["resourceId"].replace(
            registry.STORAGE_RESOURCE_GROUP, registry.BRIDGE_RESOURCE_GROUP
        )
        snapshot.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(registry.RegistryError):
            registry.build_request(self.fixture.args(self.root / "cross-wired-groups.tar.gz"))

    def test_exact_paperdesk_fully_accepted_receipt_schema_is_required(self):
        document = json.loads(self.fixture.acceptance.read_text(encoding="utf-8"))
        document["status"] = "production-accepted"
        self.fixture.acceptance.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(registry.RegistryError):
            registry.build_request(self.fixture.args(self.root / "wrong-receipt.tar.gz"))

    def test_source_provenance_uses_protected_main_ref_with_sha_bound_separately(self):
        output, _ = self.build("source-ref.tar.gz")
        request, _ = registry.extract_request(output, self.root / "source-ref")
        self.assertEqual(request["candidate"]["workflowRef"], registry.PAPERDESK_SOURCE_WORKFLOW_REF)
        self.assertEqual(request["candidate"]["sha"], SHA)

    def test_overwrite_negative_rejects_unbounded_403_error_code(self):
        class WrongForbiddenStorage(FakeStorage):
            def put_create_only(self, blob_name, prefix, path, content_md5):
                if blob_name in self.blobs:
                    self.events.append(("put", blob_name))
                    return 403, "AuthorizationPermissionMismatch"
                return super().put_create_only(blob_name, prefix, path, content_md5)

        request, _ = self.build("wrong-forbidden.tar.gz")
        with self.assertRaises(registry.RegistryError):
            registry.persist_request(request, WrongForbiddenStorage())

    def test_blob_put_target_condition_error_is_bounded(self):
        source = (ROOT / "scripts" / "accepted_release_registry.py").read_text(encoding="utf-8")
        self.assertIn('(412, "TargetConditionNotMet")', source)
        self.assertNotIn('(412, "ConditionNotMet")', source)

    def test_bridge_contract_uses_distinct_identities_and_create_only_put(self):
        source = (ROOT / "scripts" / "accepted_release_registry.py").read_text(encoding="utf-8")
        for required in (
            'BRIDGE_PATH = "/internal/v1/persist-accepted-release"',
            '"If-None-Match": "*"',
            'PAPERDESK_REGISTRY_WRITER_CLIENT_ID',
            'PAPERDESK_REGISTRY_READER_CLIENT_ID',
            'writer_id == reader_id',
            'PAPERDESK_BRIDGE_SESSION_TOKEN_SHA256',
            'manifest_name = prefix + "registry-manifest.json"',
        ):
            self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()
