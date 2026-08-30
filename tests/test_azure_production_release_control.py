import hashlib
import json
import unittest
import uuid

from scripts import azure_production_release_control as control
from tests import test_provider_accepted_release_manifest as registry_fixture


SHA = registry_fixture.SHA
DEPLOYMENT_ONE = "11111111-1111-4111-8111-111111111111"
DEPLOYMENT_TWO = "22222222-2222-4222-8222-222222222222"
PACKAGE_URI = (
    "https://paperdeskstage.blob.core.windows.net/releases/candidate.zip"
    "?sp=r&spr=https&sr=b&sv=2026-01-01&se=2026-08-30T00%3A00%3A00Z&sig=secret"
)


def response(request, document=None, *, status=200, body=None):
    if body is None:
        body = control.canonical_json(document)
    return control.HttpResponse(status=status, url=request.url, headers={}, body=body)


def deployment(name, status=4, complete=True):
    return {
        "id": f"{control.APP_RESOURCE_ID}/deployments/{name}",
        "name": name,
        "type": "Microsoft.Web/sites/deployments",
        "properties": {
            "active": True,
            "complete": complete,
            "deployer": "OneDeploy",
            "status": status,
            "received_time": "2026-08-29T01:00:00Z",
            "start_time": "2026-08-29T01:00:01.000Z",
            "end_time": "2026-08-29T01:00:02.0000000Z",
        },
    }


def collection(*entries):
    return {"value": list(entries)}


class AzureProductionReleaseControlTests(unittest.TestCase):
    def package(self):
        return control.DeploymentPackage(
            source_sha=SHA,
            package_uri=PACKAGE_URI,
            package_sha256="d" * 64,
            package_size=12345,
        )

    def test_selected_artifact_requires_fresh_successful_merged_main_provenance(self):
        digest = "a" * 64
        run = {
            "id": 123,
            "head_sha": SHA,
            "head_branch": "main",
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "repository": {"full_name": control.SOURCE_REPOSITORY},
            "head_repository": {"full_name": control.SOURCE_REPOSITORY},
        }
        artifact = {
            "id": 456,
            "name": "verified-runtime",
            "expired": False,
            "digest": f"sha256:{digest}",
            "size_in_bytes": 42,
            "workflow_run": {"id": 123, "head_sha": SHA},
        }
        result = control.validate_merged_main_artifact_provenance(
            run=run,
            artifacts={"artifacts": [artifact]},
            source_sha=SHA,
            source_run_id="123",
            artifact_name="verified-runtime",
            artifact_id="456",
            artifact_digest=digest,
        )
        self.assertEqual(result["artifactId"], "456")

        adversarial = (
            ({**run, "head_branch": "feature"}, {"artifacts": [artifact]}),
            ({**run, "event": "pull_request"}, {"artifacts": [artifact]}),
            ({**run, "conclusion": "failure"}, {"artifacts": [artifact]}),
            (run, {"artifacts": [{**artifact, "id": 999}]}),
            (run, {"artifacts": [{**artifact, "digest": f"sha256:{'b' * 64}"}]}),
            (run, {"artifacts": [{**artifact, "expired": True}]}),
        )
        for bad_run, bad_artifacts in adversarial:
            with self.subTest(bad_run=bad_run, bad_artifacts=bad_artifacts), self.assertRaises(
                control.ReleaseControlError
            ):
                control.validate_merged_main_artifact_provenance(
                    run=bad_run,
                    artifacts=bad_artifacts,
                    source_sha=SHA,
                    source_run_id="123",
                    artifact_name="verified-runtime",
                    artifact_id="456",
                    artifact_digest=digest,
                )

    def test_deploy_candidate_uses_one_fixed_put_and_returns_secret_free_canonical_receipt(self):
        requests = []
        responses = [
            collection(deployment(DEPLOYMENT_ONE)),
            {"accepted": True},
            collection(deployment(DEPLOYMENT_ONE), deployment(DEPLOYMENT_TWO, 1, False)),
            collection(deployment(DEPLOYMENT_ONE), deployment(DEPLOYMENT_TWO)),
            collection(deployment(DEPLOYMENT_ONE), deployment(DEPLOYMENT_TWO)),
        ]

        def transport(request):
            requests.append(request)
            return response(request, responses.pop(0))

        receipt = control.deploy_candidate(
            self.package(),
            transport,
            sleep=lambda _: None,
            request_id_factory=lambda: uuid.UUID("33333333-3333-4333-8333-333333333333"),
        )

        self.assertEqual([item.method for item in requests], ["GET", "PUT", "GET", "GET", "GET"])
        self.assertTrue(all(item.url == control.ONEDEPLOY_URL for item in requests))
        self.assertEqual(sum(item.method == "PUT" for item in requests), 1)
        put = requests[1]
        self.assertTrue(put.sensitive)
        self.assertNotIn(PACKAGE_URI, repr(put))
        self.assertEqual(
            json.loads(put.body),
            {
                "properties": {
                    "clean": True,
                    "ignorestack": False,
                    "packageUri": PACKAGE_URI,
                    "restart": True,
                    "type": "zip",
                }
            },
        )
        self.assertEqual(receipt["liveDeployment"]["deploymentId"], DEPLOYMENT_TWO)
        serialized = control.canonical_json(receipt)
        self.assertNotIn(PACKAGE_URI.encode(), serialized)
        self.assertEqual(serialized, control.canonical_json(json.loads(serialized)))
        self.assertEqual(receipt["target"]["resourceId"], control.APP_RESOURCE_ID)

    def test_deploy_candidate_never_retries_ambiguous_put_and_rejects_invalid_status(self):
        requests = []

        def ambiguous(request):
            requests.append(request)
            if request.method == "GET":
                return response(request, collection())
            raise TimeoutError(PACKAGE_URI)

        with self.assertRaisesRegex(control.ReleaseControlError, "transport failed") as raised:
            control.deploy_candidate(self.package(), ambiguous, sleep=lambda _: None)
        self.assertNotIn(PACKAGE_URI, str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertTrue(raised.exception.__suppress_context__)
        self.assertEqual(sum(item.method == "PUT" for item in requests), 1)

        responses = [collection(), {}, collection(deployment(DEPLOYMENT_TWO, 3, True))]

        def failed(request):
            return response(request, responses.pop(0))

        with self.assertRaisesRegex(control.ReleaseControlError, "did not succeed"):
            control.deploy_candidate(self.package(), failed, sleep=lambda _: None)

    def test_local_file_deploy_mutates_once_and_requires_arm_identity_settlement(self):
        requests, mutations = [], []
        responses = [collection(deployment(DEPLOYMENT_ONE)),
                     collection(deployment(DEPLOYMENT_ONE), deployment(DEPLOYMENT_TWO)),
                     collection(deployment(DEPLOYMENT_ONE), deployment(DEPLOYMENT_TWO))]
        def transport(request):
            requests.append(request); return response(request, responses.pop(0))
        package = control.LocalDeploymentPackage(
            source_sha=SHA, path="/runner/deploy.zip", package_sha256="d" * 64, package_size=42)
        receipt = control.deploy_local_file_candidate(
            package, transport, mutations.append, sleep=lambda _: None)
        self.assertEqual(mutations, ["/runner/deploy.zip"])
        self.assertEqual(receipt["liveDeployment"]["deploymentId"], DEPLOYMENT_TWO)
        self.assertEqual([item.method for item in requests], ["GET", "GET", "GET"])

        mutations.clear()
        def ambiguous(_):
            mutations.append("called"); raise TimeoutError("unknown")
        with self.assertRaisesRegex(control.ReleaseControlError, "ambiguously"):
            control.deploy_local_file_candidate(package,
                lambda request: response(request, collection()), ambiguous, sleep=lambda _: None)
        self.assertEqual(mutations, ["called"])

    def test_deploy_candidate_rejects_non_readonly_or_leaking_package_uri(self):
        for uri in (
            PACKAGE_URI.replace("sp=r", "sp=rw"),
            PACKAGE_URI + "&sip=203.0.113.1",
            PACKAGE_URI.replace("https://", "http://"),
            "https://user:password@paperdeskstage.blob.core.windows.net/a?sp=r&spr=https&sr=b&sig=x",
        ):
            package = dataclasses_replace(self.package(), package_uri=uri)
            with self.subTest(uri=uri), self.assertRaises(control.ReleaseControlError):
                control.deploy_candidate(package, lambda request: response(request, collection()), sleep=lambda _: None)

    def test_registry_rollback_reads_only_manifest_bound_archive(self):
        archive = b"verified runtime archive"
        manifest = registry_fixture.manifest_document()
        archive_path = f"verified-artifact/paperdesk-azure-runtime-{SHA}.tar.gz"
        record = next(item for item in manifest["files"] if item["path"] == archive_path)
        record["size"] = len(archive)
        record["sha256"] = hashlib.sha256(archive).hexdigest()
        raw = registry_fixture.canonical_json(manifest)
        transition = registry_fixture.transition_request(raw)
        expected_prefix = transition["acceptedReleasePrefix"]
        requests = []

        def transport(request):
            requests.append(request)
            return response(request, status=200, body=archive)

        result = control.retrieve_accepted_rollback_archive(
            accepted_release_prefix=expected_prefix,
            raw_manifest=raw,
            manifest_etag=registry_fixture.ETAG,
            manifest_version_id=registry_fixture.VERSION_ID,
            transition_request=transition,
            archive_blob=expected_prefix + archive_path,
            transport=transport,
        )

        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].method, "GET")
        self.assertEqual(
            requests[0].url,
            f"{control.REGISTRY_ORIGIN}/{control.REGISTRY_CONTAINER}/{expected_prefix}{archive_path}",
        )
        self.assertEqual(requests[0].maximum_response_bytes, len(archive))
        self.assertEqual(result.source_sha, SHA)
        self.assertEqual(result.body, archive)
        self.assertNotIn(archive.decode(), repr(result))

    def test_registry_rollback_rejects_prefix_manifest_and_archive_drift(self):
        manifest = registry_fixture.manifest_document()
        raw = registry_fixture.canonical_json(manifest)
        transition = registry_fixture.transition_request(raw)
        prefix = transition["acceptedReleasePrefix"]
        with self.assertRaisesRegex(control.ReleaseControlError, "prefix"):
            control.retrieve_accepted_rollback_archive(
                accepted_release_prefix=prefix.replace(SHA, "9" * 40),
                raw_manifest=raw,
                manifest_etag=registry_fixture.ETAG,
                manifest_version_id=registry_fixture.VERSION_ID,
                transition_request=transition,
                archive_blob=prefix + f"verified-artifact/paperdesk-azure-runtime-{SHA}.tar.gz",
                transport=lambda request: response(request, body=b"x"),
            )
        with self.assertRaisesRegex(control.ReleaseControlError, "manifest binding"):
            control.retrieve_accepted_rollback_archive(
                accepted_release_prefix=prefix,
                raw_manifest=raw,
                manifest_etag='"wrong"',
                manifest_version_id=registry_fixture.VERSION_ID,
                transition_request=transition,
                archive_blob=prefix + f"verified-artifact/paperdesk-azure-runtime-{SHA}.tar.gz",
                transport=lambda request: response(request, body=b"x"),
            )
        with self.assertRaisesRegex(control.ReleaseControlError, "archive bytes"):
            control.retrieve_accepted_rollback_archive(
                accepted_release_prefix=prefix,
                raw_manifest=raw,
                manifest_etag=registry_fixture.ETAG,
                manifest_version_id=registry_fixture.VERSION_ID,
                transition_request=transition,
                archive_blob=prefix + f"verified-artifact/paperdesk-azure-runtime-{SHA}.tar.gz",
                transport=lambda request: response(request, body=b"x"),
            )

    def test_finalize_verifies_exact_sha_and_all_health_security_predicates(self):
        requests = []
        documents = {
            "/api/health/live": {"ok": True, "status": "live"},
            "/api/health/ready": {
                "ok": True,
                "status": "ready",
                "attachmentMalware": {
                    "required": True,
                    "ingestionReady": True,
                    "code": "attachment-malware-scan-ready",
                },
            },
            "/api/app-health": {"ok": True, "diagnostics": "restricted"},
            "/api/security-info": {
                "ok": True,
                "requiresConfiguredUsers": True,
                "diagnostics": "restricted",
            },
        }

        def transport(request):
            requests.append(request)
            path = request.url.removeprefix(control.LIVE_ORIGIN)
            if path == "/api/runtime-release-sha":
                return response(request, status=200, body=SHA.encode())
            return response(request, documents[path])

        receipt = control.finalize_live_release(SHA, transport)
        self.assertEqual(
            [request.url.removeprefix(control.LIVE_ORIGIN) for request in requests],
            [
                "/api/runtime-release-sha",
                "/api/health/live",
                "/api/health/ready",
                "/api/app-health",
                "/api/security-info",
            ],
        )
        self.assertEqual(receipt["status"], "verified")
        self.assertEqual(set(receipt["probes"]), {
            "runtimeReleaseSha", "liveness", "readiness", "appHealth", "securityInfo"
        })
        self.assertEqual(control.canonical_json(receipt), control.canonical_json(json.loads(control.canonical_json(receipt))))

    def test_finalize_fails_closed_on_each_critical_predicate(self):
        good = {
            "/api/health/live": {"ok": True, "status": "live"},
            "/api/health/ready": {
                "ok": True,
                "status": "ready",
                "attachmentMalware": {
                    "required": True,
                    "ingestionReady": True,
                    "code": "attachment-malware-scan-ready",
                },
            },
            "/api/app-health": {"ok": True, "diagnostics": "restricted"},
            "/api/security-info": {"ok": True, "requiresConfiguredUsers": True, "diagnostics": "restricted"},
        }
        mutations = (
            ("/api/runtime-release-sha", "bad-sha"),
            ("/api/health/live", {"ok": False, "status": "live"}),
            ("/api/health/ready", {**good["/api/health/ready"], "attachmentMalware": {"required": True, "ingestionReady": False, "code": "not-ready"}}),
            ("/api/app-health", {"ok": False, "diagnostics": "restricted"}),
            ("/api/security-info", {**good["/api/security-info"], "dataDir": "must-not-escape"}),
        )
        for broken_path, broken_value in mutations:
            def transport(request, broken_path=broken_path, broken_value=broken_value):
                path = request.url.removeprefix(control.LIVE_ORIGIN)
                if path == "/api/runtime-release-sha":
                    body = (broken_value if broken_path == path else SHA).encode()
                    return response(request, body=body)
                value = broken_value if broken_path == path else good[path]
                return response(request, value)

            with self.subTest(path=broken_path), self.assertRaises(control.ReleaseControlError):
                control.finalize_live_release(SHA, transport)


def dataclasses_replace(value, **changes):
    # Local wrapper keeps the production helper free of test-only mutation APIs.
    import dataclasses

    return dataclasses.replace(value, **changes)


if __name__ == "__main__":
    unittest.main()
