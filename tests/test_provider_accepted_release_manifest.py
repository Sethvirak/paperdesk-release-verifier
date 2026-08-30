import copy
import hashlib
import json
import unittest
from unittest import mock

from provider import accepted_release_manifest as validator
from scripts import accepted_release_registry as producer


SHA = "a" * 40
SOURCE_RUN = "41001"
SOURCE_ATTEMPT = "2"
DEPLOYMENT_RUN = "41501"
DEPLOYMENT_ATTEMPT = "4"
ACCEPTANCE_RUN = "42001"
ACCEPTANCE_ATTEMPT = "1"
RECEIPT_SHA256 = "b" * 64
DEPLOYMENT_RECEIPT_SHA256 = "9" * 64
ETAG = '"registry-manifest-etag"'
VERSION_ID = "2026-08-14T02:03:04.0000000Z"
ACCEPTANCE_WORKFLOW = (
    "Sethvirak/MasterDataStructure/.github/workflows/"
    f"main_master-data-structure-sea-9c4e0d0d.yml@{SHA}"
)
DEPLOYMENT_WORKFLOW = ACCEPTANCE_WORKFLOW


def canonical_json(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def manifest_document():
    verification_path = f"receipts/paperdesk-candidate-verification-receipt-{SHA}.json"
    production_path = f"receipts/paperdesk-production-acceptance-receipt-{SHA}.json"
    deployment_coordinate_path = f"receipts/paperdesk-deployment-coordinate-receipt-{SHA}.json"
    maximums = {
        f"verified-artifact/{relative}": maximum
        for relative, maximum in producer.expected_verified_inventory(SHA).items()
    }
    maximums[verification_path] = 8192
    maximums[production_path] = 65536
    maximums[deployment_coordinate_path] = 4096
    records = []
    for index, path in enumerate(sorted(maximums), start=1):
        records.append({
            "path": path,
            "size": 1,
            "sha256": f"{index:064x}",
            "contentMd5": "ndTkYSaMgDT1yFZOFVxnpg==",
        })
    next(record for record in records if record["path"] == verification_path)["sha256"] = "c" * 64
    next(record for record in records if record["path"] == production_path)["sha256"] = RECEIPT_SHA256
    next(
        record for record in records if record["path"] == deployment_coordinate_path
    )["sha256"] = DEPLOYMENT_RECEIPT_SHA256
    return {
        "schema": producer.MANIFEST_SCHEMA,
        "status": "complete",
        "persistedAt": "2026-08-14T02:03:04Z",
        "environment": producer.ENVIRONMENT,
        "registry": {
            "storageAccount": producer.ACCOUNT,
            "container": producer.CONTAINER,
            "bridgeApp": producer.BRIDGE_APP,
            "bridgeResourceGroup": producer.BRIDGE_RESOURCE_GROUP,
            "prefix": f"v1/releases/{SHA}/{SOURCE_RUN}/{ACCEPTANCE_RUN}/",
        },
        "source": {
            "repository": producer.PAPERDESK_REPOSITORY,
            "sha": SHA,
            "runId": SOURCE_RUN,
            "runAttempt": SOURCE_ATTEMPT,
            "workflowRef": producer.PAPERDESK_SOURCE_WORKFLOW_REF,
        },
        "deployment": {
            "runId": DEPLOYMENT_RUN,
            "runAttempt": DEPLOYMENT_ATTEMPT,
            "workflowRef": DEPLOYMENT_WORKFLOW,
        },
        "acceptance": {
            "runId": ACCEPTANCE_RUN,
            "runAttempt": ACCEPTANCE_ATTEMPT,
            "workflowRef": ACCEPTANCE_WORKFLOW,
            "acceptedAt": "2026-08-13T01:30:00.000Z",
            "candidateCompletedAt": "2026-08-13T01:00:00.000Z",
            "candidateFinalizeDeadline": "2026-08-14T01:00:00.000Z",
            "candidateRuntimeSha256": "d" * 64,
            "evidenceContractSha256": "e" * 64,
            "releaseScope": "controlled-non-ha-pilot",
            "environmentId": "paperdesk-production",
        },
        "evidence": {
            "runId": "42000",
            "runAttempt": "3",
            "artifactId": "93001",
            "artifactName": f"paperdesk-production-acceptance-evidence-post-deploy-{SHA}",
            "bundleSha256": "f" * 64,
        },
        "artifacts": {
            "verified": {
                "id": "93002",
                "name": f"paperdesk-azure-runtime-verified-{SHA}",
                "digest": "1" * 64,
            },
            "verificationReceipt": {
                "id": "93003",
                "name": f"paperdesk-candidate-verification-receipt-{SHA}",
                "digest": "2" * 64,
                "fileSha256": "c" * 64,
            },
            "productionAcceptanceReceipt": {
                "id": "93004",
                "name": f"paperdesk-production-acceptance-receipt-{SHA}",
                "digest": "3" * 64,
                "fileSha256": RECEIPT_SHA256,
            },
            "deploymentCoordinateReceipt": {
                "id": "93005",
                "name": f"paperdesk-deployment-coordinate-receipt-{SHA}",
                "digest": "5" * 64,
                "fileSha256": DEPLOYMENT_RECEIPT_SHA256,
            },
        },
        "verifier": {
            "workflowRef": (
                "Sethvirak/paperdesk-release-verifier/.github/workflows/"
                f"verify-candidate.yml@{'4' * 40}"
            ),
            "job": "verify_candidate",
            "runId": "41111",
            "runAttempt": "1",
        },
        "wormSnapshot": {
            "resourceId": (
                "/subscriptions/9c4e0d0d-602f-4cde-84bd-337250e5b64c/resourceGroups/"
                f"{producer.STORAGE_RESOURCE_GROUP}/providers/Microsoft.Storage/storageAccounts/"
                f"{producer.ACCOUNT}/blobServices/default/containers/{producer.CONTAINER}/"
                "immutabilityPolicies/default"
            ),
            "storageAccount": producer.ACCOUNT,
            "container": producer.CONTAINER,
            "state": "Locked",
            "immutabilityPeriodSinceCreationInDays": 91,
            "allowProtectedAppendWrites": False,
            "allowProtectedAppendWritesAll": False,
            "etag": '"fixed-policy-etag"',
            "observedAt": "2026-08-14T01:02:03Z",
        },
        "files": records,
    }


def transition_request(raw):
    return {
        "schemaVersion": 3,
        "requestType": "watchdog-state-transition",
        "operation": "accept-candidate",
        "expectedStateSha256": "5" * 64,
        "candidateSha": SHA,
        "sourceRunId": SOURCE_RUN,
        "sourceRunAttempt": SOURCE_ATTEMPT,
        "candidateRunId": DEPLOYMENT_RUN,
        "candidateRunAttempt": DEPLOYMENT_ATTEMPT,
        "acceptanceRunId": ACCEPTANCE_RUN,
        "acceptanceRunAttempt": ACCEPTANCE_ATTEMPT,
        "productionAcceptanceReceiptSha256": RECEIPT_SHA256,
        "acceptedReleaseManifestSha256": hashlib.sha256(raw).hexdigest(),
        "acceptedReleasePrefix": f"v1/releases/{SHA}/{SOURCE_RUN}/{ACCEPTANCE_RUN}/",
        "registryManifestETag": ETAG,
        "registryManifestVersionId": VERSION_ID,
    }


class ProviderAcceptedReleaseManifestTests(unittest.TestCase):
    def validate(self, raw, request):
        return validator.validate_accept_candidate_manifest(
            raw,
            request,
            actual_registry_etag=ETAG,
            actual_registry_version_id=VERSION_ID,
        )

    def test_exact_manifest_projects_only_final_contract_baseline_fields(self):
        manifest = manifest_document()
        raw = canonical_json(manifest)
        request = transition_request(raw)

        baseline = self.validate(raw, request)

        receipt_path = f"receipts/paperdesk-production-acceptance-receipt-{SHA}.json"
        self.assertEqual(set(baseline), validator.ROLLBACK_BASELINE_FIELDS)
        self.assertEqual(baseline, {
            "schemaVersion": 2,
            "receiptSha256": RECEIPT_SHA256,
            "evidencePath": request["acceptedReleasePrefix"] + receipt_path,
            "sourceSha": SHA,
            "sourceRunId": SOURCE_RUN,
            "sourceRunAttempt": SOURCE_ATTEMPT,
            "acceptanceRunId": ACCEPTANCE_RUN,
            "acceptanceRunAttempt": ACCEPTANCE_ATTEMPT,
            "acceptedReleaseManifestSha256": hashlib.sha256(raw).hexdigest(),
            "acceptedReleasePrefix": request["acceptedReleasePrefix"],
            "reviewWorkflowRef": ACCEPTANCE_WORKFLOW,
            "reviewWorkflowSha": SHA,
            "reviewRunId": ACCEPTANCE_RUN,
            "reviewRunAttempt": ACCEPTANCE_ATTEMPT,
            "reviewEnvironment": producer.ENVIRONMENT,
            "preparedAt": "2026-08-14T02:03:04.000Z",
        })

    def test_blob_etag_version_and_raw_sha_are_bound_to_same_readback(self):
        raw = canonical_json(manifest_document())
        request = transition_request(raw)
        for arguments in (
            {"actual_registry_etag": '"different"', "actual_registry_version_id": VERSION_ID},
            {"actual_registry_etag": ETAG, "actual_registry_version_id": "different"},
        ):
            with self.subTest(arguments=arguments), self.assertRaises(validator.AcceptedReleaseManifestError):
                validator.validate_accept_candidate_manifest(raw, request, **arguments)
        request["acceptedReleaseManifestSha256"] = "0" * 64
        with self.assertRaises(validator.AcceptedReleaseManifestError):
            self.validate(raw, request)

    def test_only_bounded_canonical_exact_manifest_json_is_accepted(self):
        manifest = manifest_document()
        raw = canonical_json(manifest)
        request = transition_request(raw)
        noncanonical = json.dumps(manifest, indent=2).encode("utf-8")
        request["acceptedReleaseManifestSha256"] = hashlib.sha256(noncanonical).hexdigest()
        with self.assertRaises(validator.AcceptedReleaseManifestError):
            self.validate(noncanonical, request)
        with mock.patch.object(validator, "MAX_ACCEPTED_MANIFEST_BYTES", len(raw) - 1):
            request["acceptedReleaseManifestSha256"] = hashlib.sha256(raw).hexdigest()
            with self.assertRaises(validator.AcceptedReleaseManifestError):
                self.validate(raw, request)
        manifest["unexpected"] = True
        extra_raw = canonical_json(manifest)
        with self.assertRaises(validator.AcceptedReleaseManifestError):
            self.validate(extra_raw, transition_request(extra_raw))

    def test_manifest_coordinates_and_production_receipt_digest_fail_closed(self):
        base = manifest_document()
        receipt_path = f"receipts/paperdesk-production-acceptance-receipt-{SHA}.json"
        deployment_coordinate_path = (
            f"receipts/paperdesk-deployment-coordinate-receipt-{SHA}.json"
        )
        mutations = (
            lambda value: value["registry"].__setitem__("storageAccount", "other"),
            lambda value: value["registry"].__setitem__("container", "other"),
            lambda value: value["registry"].__setitem__("prefix", "v1/releases/other/"),
            lambda value: value["source"].__setitem__("sha", "6" * 40),
            lambda value: value["source"].__setitem__("runId", "999"),
            lambda value: value["source"].__setitem__("runAttempt", "999"),
            lambda value: value["deployment"].__setitem__("runId", "999"),
            lambda value: value["deployment"].__setitem__("runAttempt", "999"),
            lambda value: value["deployment"].__setitem__("workflowRef", ACCEPTANCE_WORKFLOW.replace(SHA, "6" * 40)),
            lambda value: value["acceptance"].__setitem__("runId", "999"),
            lambda value: value["acceptance"].__setitem__("runAttempt", "999"),
            lambda value: value["artifacts"]["productionAcceptanceReceipt"].__setitem__("fileSha256", "7" * 64),
            lambda value: next(
                record for record in value["files"] if record["path"] == receipt_path
            ).__setitem__("sha256", "7" * 64),
            lambda value: value["artifacts"]["deploymentCoordinateReceipt"].__setitem__(
                "fileSha256", "7" * 64
            ),
            lambda value: next(
                record for record in value["files"]
                if record["path"] == deployment_coordinate_path
            ).__setitem__("sha256", "7" * 64),
        )
        for mutate in mutations:
            manifest = copy.deepcopy(base)
            mutate(manifest)
            raw = canonical_json(manifest)
            with self.assertRaises(validator.AcceptedReleaseManifestError):
                self.validate(raw, transition_request(raw))

    def test_exact_request_shape_and_exact_sorted_file_inventory_are_required(self):
        manifest = manifest_document()
        raw = canonical_json(manifest)
        request = transition_request(raw)
        request["unexpected"] = True
        with self.assertRaises(validator.AcceptedReleaseManifestError):
            self.validate(raw, request)
        manifest["files"] = list(reversed(manifest["files"]))
        changed_raw = canonical_json(manifest)
        with self.assertRaises(validator.AcceptedReleaseManifestError):
            self.validate(changed_raw, transition_request(changed_raw))

    def test_transition_source_deployment_attempts_and_run_swaps_fail_closed(self):
        raw = canonical_json(manifest_document())
        mutations = (
            lambda value: value.__setitem__("sourceRunId", DEPLOYMENT_RUN),
            lambda value: value.__setitem__("sourceRunAttempt", "99"),
            lambda value: value.__setitem__("candidateRunId", SOURCE_RUN),
            lambda value: value.__setitem__("candidateRunAttempt", "99"),
        )
        for mutate in mutations:
            request = transition_request(raw)
            mutate(request)
            with self.assertRaises(validator.AcceptedReleaseManifestError):
                self.validate(raw, request)

    def test_evidence_run_cannot_equal_source_deployment_or_acceptance(self):
        for run_id in (SOURCE_RUN, DEPLOYMENT_RUN, ACCEPTANCE_RUN):
            manifest = manifest_document()
            manifest["evidence"]["runId"] = run_id
            raw = canonical_json(manifest)
            with self.assertRaisesRegex(
                validator.AcceptedReleaseManifestError, "must be distinct"
            ):
                self.validate(raw, transition_request(raw))


if __name__ == "__main__":
    unittest.main()
