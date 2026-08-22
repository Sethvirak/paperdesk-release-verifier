import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest import mock
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


def signed_artifact_url(host, *, remaining_seconds=60, permissions="r", resource="b"):
    expires = (
        registry.dt.datetime.now(registry.dt.timezone.utc)
        + registry.dt.timedelta(seconds=remaining_seconds)
    ).isoformat(timespec="seconds").replace("+00:00", "Z")
    query = registry.urllib.parse.urlencode({
        "sig": "secret",
        "sp": permissions,
        "spr": "https",
        "sr": resource,
        "se": expires,
    })
    return (
        f"https://{host}/actions-results/11111111-1111-4111-8111-111111111111/"
        "workflow-job-run-22222222-2222-4222-8222-222222222222/artifacts/"
        f"{'3' * 64}.zip?{query}"
    )


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


class FakeRbacCanaryStorage:
    def __init__(self):
        self.blobs = {}
        self.events = []

    def writer_put_canary_create_only(self, blob_name, body):
        self.events.append(("writer-put", blob_name))
        if blob_name in self.blobs:
            return 403, "UnauthorizedBlobOverwrite"
        self.blobs[blob_name] = body
        return 201, ""

    def reader_get_canary(self, blob_name, maximum):
        self.events.append(("reader-get", blob_name))
        body = self.blobs[blob_name]
        return 200, body[:maximum], {}, ""

    def writer_get_canary(self, blob_name, maximum):
        self.events.append(("writer-get", blob_name))
        return 403, b"", {}, "AuthorizationPermissionMismatch"

    def reader_put_canary_create_only(self, blob_name, body):
        self.events.append(("reader-put", blob_name))
        return 403, "AuthorizationPermissionMismatch"

    def writer_put_canary_unconditional(self, blob_name, body):
        self.events.append(("writer-overwrite", blob_name))
        return 403, "UnauthorizedBlobOverwrite"


class FakeDownloadResponse:
    def __init__(self, body, url, status=200, headers=None):
        self.body = io.BytesIO(body)
        self.url = url
        self.status = status
        self.headers = {
            "Content-Length": str(len(body)),
            **({} if headers is None else headers),
        }
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def geturl(self):
        return self.url

    def read(self, size=-1):
        return self.body.read(size)

    def close(self):
        self.closed = True


class FakeDownloadOpener:
    def __init__(self, response):
        self.responses = list(response) if isinstance(response, (list, tuple)) else [response]
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout, dict(request.header_items())))
        if not self.responses:
            raise AssertionError("fake opener received an unexpected request")
        return self.responses.pop(0)


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

    def actions_zip(self, request_path, *extra_members):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr(registry.ACTIONS_REQUEST_NAME, request_path.read_bytes())
            for name, body in extra_members:
                archive.writestr(name, body)
        return buffer.getvalue()

    def one_shot_environment(self, artifact_body, request_path, expected_prefix=None):
        return {
            registry.ACTIONS_GITHUB_TOKEN_ENV: "github-read-token-for-tests",
            registry.ACTIONS_GITHUB_ARTIFACT_ID_ENV: "95001",
            registry.ACTIONS_ARTIFACT_ZIP_SHA256_ENV: hex_digest(artifact_body),
            registry.ACTIONS_REQUEST_SHA256_ENV: registry.sha256_file(request_path),
            registry.EXPECTED_PREFIX_ENV: (
                expected_prefix
                if expected_prefix is not None
                else f"v1/releases/{SHA}/{SOURCE_RUN}/{ACCEPTANCE_RUN}/"
            ),
        }

    def one_shot_opener(self, artifact_body, artifact_id="95001"):
        host = "productionresultssa0.blob.core.windows.net"
        signed_url = signed_artifact_url(host)
        api_url = registry.github_actions_artifact_api_url(artifact_id)
        return FakeDownloadOpener([
            FakeDownloadResponse(b"", api_url, status=302, headers={"Location": signed_url}),
            FakeDownloadResponse(artifact_body, signed_url),
        ])

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

    def test_one_shot_url_is_exact_https_blob_host_with_bounded_signed_query(self):
        host = "productionresultssa0.blob.core.windows.net"
        valid = signed_artifact_url(host)
        self.assertEqual(registry.validate_actions_artifact_url(valid, host), valid)
        valid_query = registry.urllib.parse.urlsplit(valid).query
        invalid = (
            f"http://{host}/actions-results/request.zip?{valid_query}",
            f"https://{host}/actions-results/request.zip?{valid_query}",
            f"https://user@{host}/actions-results/request.zip?{valid_query}",
            f"https://{host}:443/actions-results/request.zip?{valid_query}",
            f"https://{host}:invalid/actions-results/request.zip?{valid_query}",
            f"https://other.blob.core.windows.net/actions-results/request.zip?{valid_query}",
            f"https://{host}/actions-results/request.zip?{valid_query}#fragment",
            f"https://{host}/actions-results/request.zip",
            valid.replace(
                "11111111-1111-4111-8111-111111111111",
                "111111111111111111111111111111111111",
            ),
            f"{valid}&sig=second",
            f"{valid}&unexpected=value",
            valid.replace("&spr=https", ""),
            signed_artifact_url(host, permissions="rw"),
            signed_artifact_url(host, resource="c"),
            signed_artifact_url(host, remaining_seconds=5),
            signed_artifact_url(host, remaining_seconds=301),
        )
        for url in invalid:
            with self.subTest(url=url):
                with self.assertRaises(registry.RegistryError):
                    registry.validate_actions_artifact_url(url, host)
        with self.assertRaises(registry.RegistryError):
            registry.validate_actions_artifact_url(
                "https://artifact.example.test/request.zip?sig=secret&sp=r&sr=b&se=2099-01-01T00%3A00%3A00Z",
                "artifact.example.test",
            )

    def test_one_shot_download_is_single_hop_bounded_and_digest_bound(self):
        body = b"bounded Actions artifact"
        host = "productionresultssa0.blob.core.windows.net"
        url = signed_artifact_url(host)
        output = self.root / "download.zip"
        opener = FakeDownloadOpener(FakeDownloadResponse(body, url))
        actual = registry.download_actions_artifact(url, host, hex_digest(body), output, opener)
        self.assertEqual(actual, hex_digest(body))
        self.assertEqual(output.read_bytes(), body)
        self.assertEqual(opener.requests[0][1], 900)

        redirected = self.root / "redirected.zip"
        with self.assertRaises(registry.RegistryError):
            registry.download_actions_artifact(
                url,
                host,
                hex_digest(body),
                redirected,
                FakeDownloadOpener(FakeDownloadResponse(body, url, status=302)),
            )
        self.assertFalse(redirected.exists())
        self.assertIsNone(
            registry.RejectRedirectHandler().redirect_request(None, None, 302, "", {}, url)
        )

        mismatched = self.root / "mismatched.zip"
        with self.assertRaises(registry.RegistryError):
            registry.download_actions_artifact(
                url,
                host,
                "0" * 64,
                mismatched,
                FakeDownloadOpener(FakeDownloadResponse(body, url)),
            )
        self.assertFalse(mismatched.exists())

        excessive = self.root / "excessive.zip"
        with mock.patch.object(registry, "MAX_ACTIONS_ARTIFACT_BYTES", len(body) - 1):
            with self.assertRaises(registry.RegistryError):
                registry.download_actions_artifact(
                    url,
                    host,
                    hex_digest(body),
                    excessive,
                    FakeDownloadOpener(FakeDownloadResponse(body, url)),
                )
        self.assertFalse(excessive.exists())

    def test_github_artifact_resolution_is_one_redirect_and_never_forwards_authorization(self):
        artifact_id = "95001"
        token = "github-read-token-for-tests"
        host = "productionresultssa0.blob.core.windows.net"
        signed_url = signed_artifact_url(host)
        api_url = registry.github_actions_artifact_api_url(artifact_id)
        opener = FakeDownloadOpener(
            FakeDownloadResponse(b"", api_url, status=302, headers={"Location": signed_url})
        )
        resolved_url, resolved_host = registry.resolve_github_actions_artifact_url(
            artifact_id, token, opener
        )
        self.assertEqual((resolved_url, resolved_host), (signed_url, host))
        request, timeout, sent_headers = opener.requests[0]
        self.assertEqual(timeout, 30)
        self.assertEqual(request.full_url, api_url)
        self.assertEqual(sent_headers["X-github-api-version"], "2026-03-10")
        self.assertEqual(sent_headers.get("Authorization"), f"Bearer {token}")
        self.assertIsNone(request.get_header("Authorization"))

        body = b"bounded Actions artifact"
        download_opener = FakeDownloadOpener(FakeDownloadResponse(body, signed_url))
        output = self.root / "authorization-boundary.zip"
        registry.download_actions_artifact(
            signed_url, host, hex_digest(body), output, download_opener
        )
        blob_request = download_opener.requests[0][0]
        self.assertIsNone(blob_request.get_header("Authorization"))
        self.assertNotIn(token, repr(blob_request.header_items()))

        invalid_redirects = (
            "https://attacker.example.test/request.zip?sig=x&sp=r&spr=https&sr=b&se=2099-01-01T00%3A00%3A00Z",
            signed_url + "#fragment",
            signed_url.replace("https://", "https://user@"),
        )
        for location in invalid_redirects:
            with self.subTest(location=location):
                with self.assertRaises(registry.RegistryError):
                    registry.resolve_github_actions_artifact_url(
                        artifact_id,
                        token,
                        FakeDownloadOpener(FakeDownloadResponse(
                            b"", api_url, status=302, headers={"Location": location}
                        )),
                    )

        with self.assertRaises(registry.RegistryError):
            registry.resolve_github_actions_artifact_url(
                artifact_id,
                token,
                FakeDownloadOpener(FakeDownloadResponse(b"", api_url, status=200)),
            )

        class DuplicateLocationHeaders(dict):
            def get_all(self, name):
                return [signed_url, signed_url] if name.lower() == "location" else None

        duplicate_response = FakeDownloadResponse(b"", api_url, status=302)
        duplicate_response.headers = DuplicateLocationHeaders(Location=signed_url)
        with self.assertRaises(registry.RegistryError):
            registry.resolve_github_actions_artifact_url(
                artifact_id, token, FakeDownloadOpener(duplicate_response)
            )

    def test_signed_artifact_and_managed_identity_openers_disable_environment_proxies(self):
        sentinel = object()
        with mock.patch.object(
            registry.urllib.request, "build_opener", return_value=sentinel
        ) as factory:
            self.assertIs(registry.build_direct_artifact_opener(), sentinel)
        artifact_handlers = factory.call_args.args
        self.assertTrue(any(
            isinstance(handler, registry.urllib.request.ProxyHandler) and handler.proxies == {}
            for handler in artifact_handlers
        ))
        self.assertTrue(any(
            isinstance(handler, registry.RejectRedirectHandler)
            for handler in artifact_handlers
        ))
        self.assertTrue(any(
            isinstance(handler, registry.urllib.request.HTTPSHandler)
            for handler in artifact_handlers
        ))

        with mock.patch.object(
            registry.urllib.request, "build_opener", return_value=sentinel
        ) as factory:
            self.assertIs(registry.build_direct_identity_opener(), sentinel)
        identity_handlers = factory.call_args.args
        self.assertTrue(any(
            isinstance(handler, registry.urllib.request.ProxyHandler) and handler.proxies == {}
            for handler in identity_handlers
        ))
        self.assertTrue(any(
            isinstance(handler, registry.RejectRedirectHandler)
            for handler in identity_handlers
        ))

    def test_managed_identity_endpoint_is_local_and_errors_are_redacted(self):
        valid = (
            "http://127.0.0.1:41741/MSI/token/",
            "http://169.254.129.1:41741/MSI/token/",
            "http://localhost:41741/MSI/token/",
            "http://[::1]:41741/MSI/token/",
            "http://[fe80::1]:41741/MSI/token/",
        )
        for endpoint in valid:
            with self.subTest(endpoint=endpoint):
                self.assertEqual(registry.validate_identity_endpoint(endpoint), endpoint)
        invalid = (
            "https://127.0.0.1:41741/MSI/token/",
            "http://example.com:41741/MSI/token/",
            "http://10.0.0.4:41741/MSI/token/",
            "http://user@127.0.0.1:41741/MSI/token/",
            "http://127.0.0.1/MSI/token/",
            "http://127.0.0.1:41741/internal/admin",
            "http://127.0.0.1:99999/MSI/token/",
            "http://127.0.0.1:41741/MSI/token/?secret=value",
            "http://127.0.0.1:41741/MSI/token/#fragment",
        )
        for endpoint in invalid:
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(registry.RegistryError):
                    registry.validate_identity_endpoint(endpoint)

        class RaisingIdentityOpener:
            def open(self, request, timeout):
                raise registry.urllib.error.URLError("secret-endpoint-context")

        with mock.patch.dict(registry.os.environ, {
            "IDENTITY_ENDPOINT": valid[0],
            "IDENTITY_HEADER": "secret-platform-header",
        }, clear=True), mock.patch.object(
            registry, "build_direct_identity_opener", return_value=RaisingIdentityOpener()
        ):
            with self.assertRaises(registry.RegistryError) as caught:
                registry.identity_token(registry.REGISTRY_WRITER_CLIENT_ID)
        self.assertNotIn("secret", str(caught.exception))
        self.assertEqual(str(caught.exception), "managed-identity token acquisition failed")

    def test_actions_artifact_inventory_is_exactly_one_registry_request(self):
        request, _ = self.build("artifact-request.tar.gz")
        exact = self.root / "exact.zip"
        exact.write_bytes(self.actions_zip(request))
        extracted = registry.extract_actions_request(exact, self.root / "exact-output")
        self.assertEqual(extracted.name, registry.ACTIONS_REQUEST_NAME)
        self.assertEqual(extracted.read_bytes(), request.read_bytes())

        extra = self.root / "extra.zip"
        extra.write_bytes(self.actions_zip(request, ("unexpected.txt", b"not allowed")))
        rejected_output = self.root / "extra-output"
        with mock.patch.object(registry, "safe_extract_actions_zip") as extractor:
            with self.assertRaises(registry.RegistryError):
                registry.extract_actions_request(extra, rejected_output)
            extractor.assert_not_called()
        self.assertFalse(rejected_output.exists())

    def test_expected_prefix_is_checked_before_any_storage_get_or_write(self):
        request, _ = self.build("prefix-bound.tar.gz")
        storage = FakeStorage()
        wrong_prefix = f"v1/releases/{SHA}/{SOURCE_RUN}/99999/"
        with self.assertRaises(registry.RegistryError):
            registry.persist_request(request, storage, expected_prefix=wrong_prefix)
        self.assertEqual(storage.events, [])

    def test_one_shot_uses_fixed_identities_and_emits_only_bounded_safe_json(self):
        request, _ = self.build("one-shot-request.tar.gz")
        artifact_body = self.actions_zip(request)
        environment = self.one_shot_environment(artifact_body, request)
        opener = self.one_shot_opener(artifact_body)
        storage = FakeStorage()
        tokens = {
            registry.REGISTRY_WRITER_CLIENT_ID: "fixed-writer-token",
            registry.REGISTRY_READER_CLIENT_ID: "fixed-reader-token",
        }
        with mock.patch.object(
            registry, "identity_token", side_effect=lambda client_id: tokens[client_id]
        ) as token_provider, mock.patch.object(
            registry, "StorageClient", return_value=storage
        ) as client_factory:
            result = registry.persist_actions_artifact(
                environment,
                opener,
            )

        self.assertEqual(
            [call.args[0] for call in token_provider.call_args_list],
            [registry.REGISTRY_WRITER_CLIENT_ID, registry.REGISTRY_READER_CLIENT_ID],
        )
        client_factory.assert_called_once_with("fixed-writer-token", "fixed-reader-token")
        self.assertNotEqual(registry.REGISTRY_WRITER_CLIENT_ID, registry.REGISTRY_READER_CLIENT_ID)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["fileCount"], 19)
        serialized = registry.canonical_json(result)
        self.assertLessEqual(len(serialized), registry.MAX_ONE_SHOT_RESULT_BYTES)
        self.assertNotIn(b"secret", serialized)
        self.assertNotIn(b"token", serialized)
        self.assertNotIn(b"https://", serialized)
        self.assertNotIn(registry.ACTIONS_GITHUB_TOKEN_ENV, environment)
        self.assertEqual(opener.requests[0][2].get("Authorization"), "Bearer github-read-token-for-tests")
        self.assertIsNone(opener.requests[0][0].get_header("Authorization"))
        self.assertNotIn("Authorization", opener.requests[1][2])

    def test_bad_inner_digest_or_prefix_never_acquires_identity_or_storage_client(self):
        request, _ = self.build("pre-storage-request.tar.gz")
        artifact_body = self.actions_zip(request)
        base_environment = self.one_shot_environment(artifact_body, request)

        bad_artifact_digest = dict(base_environment)
        bad_artifact_digest[registry.ACTIONS_ARTIFACT_ZIP_SHA256_ENV] = "0" * 64
        with mock.patch.object(registry, "identity_token") as token_provider, mock.patch.object(
            registry, "StorageClient"
        ) as client_factory:
            with self.assertRaises(registry.RegistryError):
                registry.persist_actions_artifact(
                    bad_artifact_digest,
                    self.one_shot_opener(artifact_body),
                )
            token_provider.assert_not_called()
            client_factory.assert_not_called()

        bad_digest = dict(base_environment)
        bad_digest[registry.ACTIONS_REQUEST_SHA256_ENV] = "0" * 64
        with mock.patch.object(registry, "identity_token") as token_provider, mock.patch.object(
            registry, "StorageClient"
        ) as client_factory:
            with self.assertRaises(registry.RegistryError):
                registry.persist_actions_artifact(
                    bad_digest,
                    self.one_shot_opener(artifact_body),
                )
            token_provider.assert_not_called()
            client_factory.assert_not_called()

        bad_prefix = dict(base_environment)
        bad_prefix[registry.EXPECTED_PREFIX_ENV] = f"v1/releases/{SHA}/{SOURCE_RUN}/99999/"
        with mock.patch.object(registry, "identity_token") as token_provider, mock.patch.object(
            registry, "StorageClient"
        ) as client_factory:
            with self.assertRaises(registry.RegistryError):
                registry.persist_actions_artifact(
                    bad_prefix,
                    self.one_shot_opener(artifact_body),
                )
            token_provider.assert_not_called()
            client_factory.assert_not_called()

    def test_github_credential_is_discarded_even_when_resolution_fails(self):
        request, _ = self.build("credential-discard-request.tar.gz")
        artifact_body = self.actions_zip(request)
        environment = self.one_shot_environment(artifact_body, request)
        api_url = registry.github_actions_artifact_api_url(
            environment[registry.ACTIONS_GITHUB_ARTIFACT_ID_ENV]
        )
        opener = FakeDownloadOpener(FakeDownloadResponse(b"", api_url, status=500))
        with self.assertRaises(registry.RegistryError) as caught:
            registry.persist_actions_artifact(environment, opener)
        self.assertEqual(
            str(caught.exception),
            "GitHub Actions artifact resolution did not return one exact redirect",
        )
        self.assertNotIn(registry.ACTIONS_GITHUB_TOKEN_ENV, environment)
        self.assertNotIn("github-read-token-for-tests", str(caught.exception))

    def test_runtime_canary_requires_python_312_isolation_and_no_github_credential(self):
        job_directory = ROOT / "webjobs" / "paperdesk-accepted-release-registry"
        with mock.patch.object(registry.sys, "version_info", (3, 12, 13)), mock.patch.object(
            registry.sys, "flags", mock.Mock(isolated=1)
        ), mock.patch.dict(registry.os.environ, {}, clear=True):
            result = registry.runtime_canary(job_directory)
        self.assertEqual(result["status"], "runtime-ready")
        self.assertEqual(result["python"], "3.12")
        self.assertTrue(result["isolated"])
        self.assertEqual(result["helperSha256"], registry.sha256_file(
            ROOT / "scripts" / "accepted_release_registry.py"
        ))
        self.assertEqual(result["runnerSha256"], registry.WEBJOB_RUNNER_SHA256)
        self.assertEqual(result["settingsJobSha256"], registry.WEBJOB_SETTINGS_SHA256)

        for version, isolated, environment in (
            ((3, 11, 9), 1, {}),
            ((3, 12, 13), 0, {}),
            ((3, 12, 13), 1, {registry.ACTIONS_GITHUB_TOKEN_ENV: "must-not-be-present"}),
        ):
            with self.subTest(version=version, isolated=isolated, environment=environment), mock.patch.object(
                registry.sys, "version_info", version
            ), mock.patch.object(registry.sys, "flags", mock.Mock(isolated=isolated)), mock.patch.dict(
                registry.os.environ, environment, clear=True
            ):
                with self.assertRaises(registry.RegistryError):
                    registry.runtime_canary(job_directory)

    def test_storage_rbac_canary_proves_fixed_identity_boundaries_and_unique_prefix(self):
        blob_name = (
            "v1/canaries/storage-rbac/51001/2/"
            "0123456789abcdef0123456789abcdef.json"
        )
        environment = {registry.RBAC_CANARY_BLOB_ENV: blob_name}
        storage = FakeRbacCanaryStorage()

        result = registry.storage_rbac_canary(environment, storage)

        self.assertEqual(result["status"], "storage-rbac-ready")
        self.assertEqual(result["canaryBlob"], blob_name)
        self.assertEqual(result["writerCreate"], "passed")
        self.assertEqual(result["readerRead"], "passed")
        self.assertEqual(result["writerUnconditionalOverwriteDenied"], "passed")
        self.assertEqual(result["writerReadDenied"], "passed")
        self.assertEqual(result["readerWriteDenied"], "passed")
        self.assertEqual(result["localPrefixGuard"], "passed-before-network")
        self.assertNotIn(registry.RBAC_CANARY_BLOB_ENV, environment)
        self.assertEqual(
            [event[0] for event in storage.events],
            ["writer-put", "reader-get", "writer-overwrite", "writer-get", "reader-put"],
        )
        self.assertTrue(all(name.startswith("v1/canaries/storage-rbac/") for _, name in storage.events))

    def test_storage_rbac_canary_rejects_invalid_or_overprivileged_boundaries(self):
        storage = FakeRbacCanaryStorage()
        with self.assertRaises(registry.RegistryError):
            registry.storage_rbac_canary(
                {registry.RBAC_CANARY_BLOB_ENV: "v1/releases/outside.json"}, storage
            )
        self.assertEqual(storage.events, [])

        class OverprivilegedReaderStorage(FakeRbacCanaryStorage):
            def reader_put_canary_create_only(self, blob_name, body):
                return 201, ""

        with self.assertRaises(registry.RegistryError):
            registry.storage_rbac_canary(
                {
                    registry.RBAC_CANARY_BLOB_ENV: (
                        "v1/canaries/storage-rbac/51001/3/"
                        "fedcba9876543210fedcba9876543210.json"
                    )
                },
                OverprivilegedReaderStorage(),
            )

        with self.assertRaises(registry.RegistryError):
            registry.storage_rbac_canary({
                registry.RBAC_CANARY_BLOB_ENV: (
                    "v1/canaries/storage-rbac/51001/4/"
                    "00112233445566778899aabbccddeeff.json"
                ),
                registry.ACTIONS_GITHUB_TOKEN_ENV: "must-not-be-present",
            }, FakeRbacCanaryStorage())

        class OversizedErrorResponse:
            status = 403

            def read(self, size):
                return b"x" * size

            def getheaders(self):
                return [("x-ms-error-code", "AuthorizationPermissionMismatch")]

        class OversizedErrorConnection:
            def request(self, *args, **kwargs):
                return None

            def getresponse(self):
                return OversizedErrorResponse()

            def close(self):
                return None

        client = registry.StorageClient("writer-token", "reader-token")
        with mock.patch.object(client, "_connection", return_value=OversizedErrorConnection()):
            with self.assertRaises(registry.RegistryError):
                client.writer_get_canary(
                    "v1/canaries/storage-rbac/51001/5/"
                    "ffeeddccbbaa99887766554433221100.json",
                    64 * 1024,
                )

    def test_runtime_canary_rejects_tampered_runner_or_settings(self):
        source = ROOT / "webjobs" / "paperdesk-accepted-release-registry"
        for filename in (registry.WEBJOB_RUNNER_NAME, registry.WEBJOB_SETTINGS_NAME):
            with self.subTest(filename=filename):
                job_directory = self.root / f"tampered-{filename.replace('.', '-')}"
                job_directory.mkdir()
                for member in (registry.WEBJOB_RUNNER_NAME, registry.WEBJOB_SETTINGS_NAME):
                    shutil.copy2(source / member, job_directory / member)
                target = job_directory / filename
                target.write_bytes(target.read_bytes() + b"#tampered\n")
                with mock.patch.object(
                    registry.sys, "version_info", (3, 12, 13)
                ), mock.patch.object(
                    registry.sys, "flags", mock.Mock(isolated=1)
                ), mock.patch.dict(registry.os.environ, {}, clear=True):
                    with self.assertRaises(registry.RegistryError):
                        registry.runtime_canary(job_directory)

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
            'headers["If-None-Match"] = "*"',
            'PAPERDESK_REGISTRY_WRITER_CLIENT_ID',
            'PAPERDESK_REGISTRY_READER_CLIENT_ID',
            'writer_id == reader_id',
            'PAPERDESK_BRIDGE_SESSION_TOKEN_SHA256',
            'manifest_name = prefix + "registry-manifest.json"',
        ):
            self.assertIn(required, source)
        unconditional = source.split("def writer_put_canary_unconditional", 1)[1].split(
            "def email_date", 1
        )[0]
        self.assertIn("False,", unconditional)
        self.assertNotIn("If-None-Match", unconditional)


if __name__ == "__main__":
    unittest.main()
