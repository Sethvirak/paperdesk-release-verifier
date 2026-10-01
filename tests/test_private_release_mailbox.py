import datetime as dt
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from tests.control_lifecycle_offline_boundary import external_access_blocked

with external_access_blocked() as _import_attempts:
    from scripts import private_release_mailbox as box
    from tests import private_release_v2_fixture as fixture
    from tests import test_accepted_release_registry as registry_fixture
if _import_attempts:
    raise AssertionError("mailbox test imports attempted external access")


NOW = dt.datetime(2026, 8, 29, tzinfo=dt.timezone.utc)
SHA = "a" * 40


def descriptor(blob="v2/accepted/" + SHA + "/x/manifest.json", sha="1" * 64):
    return {"blob": blob, "sha256": sha, "size": 1, "etag": '"e"', "versionId": "v1"}


def request(operation="prepare-candidate"):
    return {
        "schemaVersion": 2, "requestType": "paperdesk-private-release-request", "operation": operation,
        "repositoryId": "1", "ownerId": "2", "controlWorkflowSha": fixture.WORKFLOW_SHA,
        "sourceSha": SHA, "sourceRunId": "3", "sourceRunAttempt": "1",
        "candidateRunId": "4" if operation == "persist-accepted-release" else None,
        "candidateRunAttempt": "2" if operation == "persist-accepted-release" else None, "artifactId": "4",
        "artifactSha256": "c" * 64, "artifactMember": "runtime.tar.gz", "artifactMemberSha256": "d" * 64,
        "acceptanceRunId": "5", "acceptanceRunAttempt": "1", "logicalOperationId": None,
        "nonce": "e" * 32, "issuedAt": "2026-08-29T00:00:00.000Z", "expiresAt": "2026-08-29T00:15:00.000Z",
        "acceptedBaseline": descriptor(), "pendingRelease": None, "consumedMarker": None,
        "rollbackPreparation": None, "activationPlan": None, "activationProof": None,
    }


def preflight_request(source_sha=SHA):
    value = request("registry-bridge-preflight")
    value.update({
        "sourceSha": source_sha, "artifactId": "", "artifactSha256": "",
        "artifactMember": "", "artifactMemberSha256": "", "acceptedBaseline": None,
    })
    return value


def archive(index=b"<html>ok</html>"):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as target:
        for name, body in (("index.html", index), ("server/app.js", b"ok")):
            info = tarfile.TarInfo(name)
            info.size = len(body)
            target.addfile(info, io.BytesIO(body))
    return output.getvalue()


def accepted_transfer(runtime=None):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = registry_fixture.RegistryFixture(root)
        runtime_name = f"paperdesk-azure-runtime-{SHA}.tar.gz"
        runtime = archive() if runtime is None else runtime
        runtime_sha = hashlib.sha256(runtime).hexdigest()
        (source.verified / runtime_name).write_bytes(runtime)
        (source.verified / f"{runtime_name}.sha256").write_text(
            f"{runtime_sha}  {runtime_name}\n", encoding="ascii")
        materials = source.verified / "paperdesk-prebuild-release-materials"
        stem = f"paperdesk-azure-runtime-{SHA}"
        for suffix, relative in {
            ".root-package.json": "package.json",
            ".root-package-lock.json": "package-lock.json",
            ".widget-package.json": "widget-showcase/package.json",
            ".widget-package-lock.json": "widget-showcase/package-lock.json",
            ".acceptance-contract.json": "architecture/production_acceptance_evidence_contract.json",
        }.items():
            (source.verified / (stem + suffix)).write_bytes((materials / relative).read_bytes())
        verification = json.loads(source.verification.read_text(encoding="utf-8"))
        verification["archiveSha256"] = runtime_sha
        for field, suffix in {
            "inputManifestSha256": ".package-input.json",
            "runtimeManifestSha256": ".runtime-files.json",
            "rootSbomSha256": ".cdx.json",
            "widgetSbomSha256": ".widget.cdx.json",
            "provenanceSha256": ".provenance.json",
        }.items():
            verification[field] = hashlib.sha256(
                (source.verified / (stem + suffix)).read_bytes()
            ).hexdigest()
        material_records = [
            {"path": path, "bytes": (materials / path).stat().st_size,
             "sha256": hashlib.sha256((materials / path).read_bytes()).hexdigest()}
            for path in sorted(registry_fixture.registry.RELEASE_MATERIAL_PATHS,
                               key=lambda item: item.encode("utf-8"))
        ]
        verification["releaseMaterialsSha256"] = hashlib.sha256(
            (json.dumps(material_records, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        ).hexdigest()
        source.verification.write_text(json.dumps(verification), encoding="utf-8")
        acceptance = json.loads(source.acceptance.read_text(encoding="utf-8"))
        acceptance["candidateRuntimeSha256"] = runtime_sha
        acceptance["evidenceContractSha256"] = hashlib.sha256(
            (source.verified / (stem + ".acceptance-contract.json")).read_bytes()
        ).hexdigest()
        source.acceptance.write_text(json.dumps(acceptance), encoding="utf-8")
        coordinate = json.loads(source.deployment_coordinate.read_text(encoding="utf-8"))
        coordinate["candidateRuntimeSha256"] = runtime_sha
        source.deployment_coordinate.write_text(json.dumps(coordinate), encoding="utf-8")
        output = root / "accepted-release-request.tar.gz"
        registry_fixture.registry.build_request(source.args(output))
        return output.read_bytes()


def activation_fence(release, pre="2" * 64, desired="3" * 64, source_sha=SHA):
    return {"blob": box.FIXED_COORDS["activationFenceBlob"], "leaseId": "22222222-2222-4222-8222-222222222222", "stateVersion": "1", "release": release, "preSettingsSha256": pre, "desiredSettingsSha256": desired, "etag": '"f"', "operation": "candidate", "sourceSha": source_sha}


class Worm:
    def __init__(self, lose_first_create=False):
        self.data = {}
        self.counter = 0
        self.lose_first_create = lose_first_create

    def create(self, name, body, if_none_match):
        if name in self.data:
            raise box.MailboxError("exists")
        self.counter += 1
        value = box.WormRecord(name, body, f'"e{self.counter}"', f"v{self.counter}")
        self.data[name] = value
        if self.lose_first_create:
            self.lose_first_create = False
            raise OSError("lost create response")
        return value

    def read(self, name, version_id):
        value = self.data[name]
        if value.version_id != version_id:
            raise box.MailboxError("version")
        return value

    def read_current(self, name):
        if name not in self.data:
            raise box.MailboxError("blob-not-found")
        return self.data[name]


def seed_accepted(registry, packages, source_sha=SHA, *, mode="strict", path=None):
    bundle = packages.create(
        f"v1/accepted/{source_sha}/fixture/deployment.zip", b"deployment", "*"
    )
    if mode == "bootstrap":
        consumed = registry.create(
            "v2/bootstrap/current-production/consumed.json",
            box.canonical({"schemaVersion": 1, "lifecycle": "bootstrap-consumed", "sourceSha": source_sha}),
            "*",
        )
        artifact = {}
        schema_version = 1
        release_coordinates = None
    else:
        pending_bundle = packages.create(f"v1/pending/{source_sha}/3-1-4/deployment.zip", b"deployment", "*")
        baseline = descriptor(f"v2/accepted/{'b' * 40}/manifest.json", "2" * 64)
        pending_body = box.canonical({
            "schemaVersion": 1, "lifecycle": "pending", "sourceSha": source_sha,
            "execution": {"repositoryId": "1", "ownerId": "2", "sourceRunId": "3", "sourceRunAttempt": "1", "artifactId": "4"},
            "deploymentCoordinates": {"candidateRunId": "4", "candidateRunAttempt": "2"},
            "artifact": {"outerSha256": "3" * 64, "member": "runtime.tar.gz", "memberSha256": "4" * 64},
            "acceptedBaseline": baseline, "servedIndexSha256": "8" * 64,
            "oneDeployInvariant": box.BOOTSTRAP_BASELINE["oneDeployInvariant"],
            "deploymentBundle": box._worm_descriptor(pending_bundle),
        })
        pending = registry.create(f"v2/pending/{source_sha}/3-1-4/manifest.json", pending_body, "*")
        pending_desc = box._worm_descriptor(pending)
        consumed = registry.create(
            f"v2/pending/{source_sha}/3-1-4/consumed.json",
            box.canonical({"schemaVersion": 1, "lifecycle": "candidate-consumed",
                "pendingRelease": pending_desc, "acceptedBaseline": baseline, "sourceSha": source_sha,
                "deploymentCoordinates": {"candidateRunId": "4", "candidateRunAttempt": "2"},
                "activationFence": activation_fence(pending_desc, source_sha=source_sha), "activationProof": {}}),
            "*",
        )
        transfer = registry.create(
            f"v2/accepted/{source_sha}/4-2/5-1/accepted-release-transfer.tar.gz", b"transfer", "*"
        )
        artifact = {"id": "4", "outerSha256": "5" * 64, "member": "accepted.tar.gz",
            "memberSha256": "6" * 64, "pendingRelease": pending_desc,
            "acceptedTransfer": box._worm_descriptor(transfer)}
        schema_version = 2
        release_coordinates = {"sourceRunId": "3", "sourceRunAttempt": "1", "candidateRunId": "4",
            "candidateRunAttempt": "2", "acceptanceRunId": "5", "acceptanceRunAttempt": "1"}
    health = (
        {"readyStatus": box.BOOTSTRAP_BASELINE["readinessHttpStatus"],
         "readyCode": box.BOOTSTRAP_BASELINE["readinessCode"], "runtimeMarkerRequired": False}
        if mode == "bootstrap"
        else {"readyStatus": 200, "readyCode": "", "runtimeMarkerRequired": True}
    )
    manifest_document = {
        "schemaVersion": schema_version, "lifecycle": "accepted", "baselineMode": mode,
        "sourceSha": source_sha, "artifact": artifact,
        "servedIndexSha256": box.BOOTSTRAP_BASELINE["servedIndexSha256"] if mode == "bootstrap" else "8" * 64,
        "oneDeployInvariant": box.BOOTSTRAP_BASELINE["oneDeployInvariant"],
        "healthPolicy": health, "deploymentBundle": box._worm_descriptor(bundle),
        "consumedMarker": box._worm_descriptor(consumed),
    }
    if release_coordinates is not None:
        manifest_document["releaseCoordinates"] = release_coordinates
    manifest_body = box.canonical(manifest_document)
    manifest_path = path or (
        f"v2/accepted/{source_sha}/bootstrap-consumed/manifest.json"
        if mode == "bootstrap" else f"v2/accepted/{source_sha}/manifest.json"
    )
    return registry.create(manifest_path, manifest_body, "*")


def transient_control(operation, source_sha=SHA):
    policy = box.bridge_owner_policy(operation)
    return {
        "schemaVersion": 1, "state": "transient", "repository": box.OWNER_REPOSITORY,
        "repositoryId": box.OWNER_REPOSITORY_ID, "ownerId": box.OWNER_ID, "callerSha": source_sha,
        "workflowId": policy["workflowId"], "workflowName": policy["workflowName"],
        "workflowPath": policy["workflowPath"], "workflowRef": policy["workflowRef"],
        "event": sorted(policy["events"])[0], "headBranch": "main", "runId": "3", "runAttempt": "1",
        "operation": operation, "sourceSha": source_sha, "requestName": "pdreq-3-1-" + "e" * 32,
        "originalSettingsSha256": "4" * 64, "githubTokenSha256": "5" * 64,
        "provisioningEvidenceSha256": "6" * 64, "bridgeRuntimeReceiptSha256": "7" * 64,
        "acquiredAt": "2026-08-29T00:00:00.000Z", "expiresAt": "2026-08-29T02:00:00.000Z",
    }


class ClosedInitializationRejectionTests(unittest.TestCase):
    """Synthetic rejection evidence only; no provider or acceptance authority."""

    def test_untyped_v2_bootstrap_projection_cannot_claim_v1_watchdog_baseline(self):
        with external_access_blocked() as attempts:
            from scripts import watchdog_evidence
            from tests.test_watchdog_evidence import initial_baseline

            ordinary = initial_baseline()
            self.assertEqual(watchdog_evidence.validate_initial_baseline(ordinary), ordinary)
            projected = {
                **ordinary,
                "sourceSha": box.BOOTSTRAP_BASELINE["sourceSha"],
                "acceptedReleasePrefix": (
                    "v2/accepted/" + box.BOOTSTRAP_BASELINE["sourceSha"]
                    + "/bootstrap-consumed/"
                ),
            }
            before = json.loads(json.dumps(projected))
            with self.assertRaisesRegex(
                watchdog_evidence.EvidenceError,
                "watchdog baseline accepted-release prefix is invalid",
            ):
                watchdog_evidence.validate_initial_baseline(projected)
            self.assertEqual(projected, before)
            self.assertEqual(attempts, [])

    def test_unready_first_candidate_restores_exact_settings_without_consumption(self):
        with external_access_blocked() as attempts:
            registry, packages = Worm(), Worm()
            baseline_record = seed_accepted(
                registry, packages, box.BOOTSTRAP_BASELINE["sourceSha"], mode="bootstrap"
            )
            candidate = request("prepare-candidate")
            candidate["acceptedBaseline"] = box._worm_descriptor(baseline_record)
            prepared = box.prepare_candidate(
                registry, candidate, archive(), now=NOW, package_boundary=packages
            )
            pending_desc = prepared["records"]["pendingRelease"]
            pending = json.loads(registry.read(
                pending_desc["blob"], pending_desc["versionId"]
            ).body)
            _, baseline, _, _ = box._load_accepted(
                registry, candidate["acceptedBaseline"], packages
            )
            target = {
                "sourceSha": SHA, "baselineMode": "strict",
                "servedIndexSha256": pending["servedIndexSha256"],
                "oneDeployInvariant": pending["oneDeployInvariant"],
                "deploymentBundle": pending["deploymentBundle"],
            }
            # This property is synthetic state, not a real users-closed fence.
            original = {"SYNTHETIC_USER_ADMISSION": "closed"}
            state = [dict(original)]
            desired = {
                **original, "WEBSITE_RUN_FROM_PACKAGE": box.package_url(target["deploymentBundle"]),
                "WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID": "SystemAssigned",
            }
            fence = activation_fence(
                pending_desc, box.digest(box.canonical(original)), box.digest(box.canonical(desired))
            )
            writes, restarts, probes, consumes, aborts = [], [], [], [], []
            registry_before, packages_before = dict(registry.data), dict(packages.data)

            def config_read():
                return dict(state[0]), box.digest(box.canonical(state[0]))

            def config_put(values, expected):
                self.assertEqual(expected, box.digest(box.canonical(state[0])))
                writes.append(dict(values))
                state[0] = dict(values)
                return box.digest(box.canonical(state[0]))

            def probe(profile):
                probes.append(profile["sourceSha"])
                # Represents missing strict readiness; no malware/provider payload
                # is inspected. The actual owner must not consume this result.
                return {"sourceSha": profile["sourceSha"], "healthy": profile["sourceSha"] != SHA}

            def consume(settlement):
                consumes.append(settlement)
                raise AssertionError("unready candidate must not reach consumption")

            def abort(settlement):
                aborts.append(settlement)
                return {"status": "complete"}

            result = box.activate_run_from_package(
                source_sha=SHA, baseline=baseline, target=target, activation_fence=fence,
                system_identity_principal=box.PRODUCTION_SYSTEM_PRINCIPAL_ID,
                config_read=config_read, config_put=config_put,
                restart=lambda: restarts.append(True), probe=probe, consume=consume, abort=abort,
            )
            self.assertEqual(result["status"], "aborted")
            self.assertEqual(result["errorCode"], "activation-settlement")
            self.assertEqual(writes, [desired, original])
            self.assertEqual(len(restarts), 2)
            self.assertEqual(probes, [baseline["sourceSha"], SHA, baseline["sourceSha"]])
            self.assertEqual(consumes, [])
            self.assertEqual(len(aborts), 1)
            self.assertEqual(state[0], original)
            self.assertEqual(registry.data, registry_before)
            self.assertEqual(packages.data, packages_before)
            self.assertEqual(pending["lifecycle"], "pending")
            self.assertNotIn(str(box.PurePosixPath(pending_desc["blob"]).parent / "consumed.json"), registry.data)
            self.assertNotIn(f"v2/accepted/{SHA}/manifest.json", registry.data)
            self.assertEqual(attempts, [])

    def test_actual_readiness_parser_rejections_restore_without_consumption(self):
        cases = (
            ("http-503", 503, b'{"ok":true}', ""),
            ("malformed-json", 200, b'{"ok":', ""),
            ("failed-readiness", 200, box.canonical({
                "ok": False, "attachmentMalware": {"code": "attachment-malware-ingestion-not-ready"},
            }), "attachment-malware-ingestion-not-ready"),
            ("missing-ok", 200, b'{}', ""),
            ("nonboolean-ok", 200, b'{"ok":"true"}', ""),
            ("nonobject-payload", 200, b'null', ""),
        )
        for name, readiness_status, readiness_body, expected_code in cases:
            with self.subTest(name=name), external_access_blocked() as attempts:
                from provider import private_release_bridge_azure as azure

                registry, packages = Worm(), Worm()
                baseline_record = seed_accepted(
                    registry, packages, box.BOOTSTRAP_BASELINE["sourceSha"], mode="bootstrap"
                )
                candidate = request("prepare-candidate")
                candidate["acceptedBaseline"] = box._worm_descriptor(baseline_record)
                prepared = box.prepare_candidate(
                    registry, candidate, archive(), now=NOW, package_boundary=packages
                )
                pending_desc = prepared["records"]["pendingRelease"]
                pending = json.loads(registry.read(
                    pending_desc["blob"], pending_desc["versionId"]
                ).body)
                _, baseline, _, _ = box._load_accepted(
                    registry, candidate["acceptedBaseline"], packages
                )
                target = {key: pending[key] for key in (
                    "sourceSha", "servedIndexSha256", "oneDeployInvariant", "deploymentBundle"
                )}
                target["baselineMode"] = "strict"
                # Synthetic settings are not a real users-closed admission fence.
                original = {"SYNTHETIC_USER_ADMISSION": "closed"}
                state = [dict(original)]
                desired = {
                    **original, "WEBSITE_RUN_FROM_PACKAGE": box.package_url(target["deploymentBundle"]),
                    "WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID": "SystemAssigned",
                }
                fence = activation_fence(
                    pending_desc, box.digest(box.canonical(original)), box.digest(box.canonical(desired))
                )
                writes, restarts, probes, consumes, aborts = [], [], [], [], []
                requests, reads, sleeps, lease_checks, transport_calls = [], [], [], [], []
                parsed_ready, target_results, one_checks, http_errors = [], [], [], []
                registry_before, packages_before = dict(registry.data), dict(packages.data)

                def config_read():
                    return dict(state[0]), box.digest(box.canonical(state[0]))

                def config_put(values, expected):
                    self.assertEqual(expected, box.digest(box.canonical(state[0])))
                    writes.append(dict(values))
                    state[0] = dict(values)
                    return box.digest(box.canonical(state[0]))

                def denied_transport(*args, **kwargs):
                    transport_calls.append((args, kwargs))
                    raise AssertionError("synthetic readiness must not call provider transport")

                observer = azure.ProductionActivation(denied_transport, fixture.activation(), sleep=sleeps.append)

                class SyntheticFence:
                    def assert_held(self, receipt):
                        lease_checks.append(receipt)

                observer.bind_fence(SyntheticFence(), fence)
                limits = {
                    "/api/runtime-release-sha": 1024, "/index.html": 2 * 1024 * 1024,
                    "/api/health/live": 65536, "/api/health/ready": 65536,
                    "/api/app-health": 65536, "/api/security-info": 65536,
                }
                responses = {path: (200, b'{"ok":true}') for path in limits}
                responses["/api/runtime-release-sha"] = (200, SHA.encode("ascii"))
                responses["/index.html"] = (200, b"<html>ok</html>")
                responses["/api/health/ready"] = (readiness_status, readiness_body)
                self.assertEqual(hashlib.sha256(responses["/index.html"][1]).hexdigest(), target["servedIndexSha256"])

                class SyntheticBody(io.BytesIO):
                    def __init__(self, path, body):
                        super().__init__(body)
                        self.path = path

                    def read(self, maximum=-1):
                        reads.append((self.path, maximum))
                        return super().read(maximum)

                class SyntheticResponse(SyntheticBody):
                    def __init__(self, path, status, body):
                        super().__init__(path, body)
                        self.status = status

                class SyntheticOpener:
                    def open(self, http_request, timeout):
                        path = http_request.full_url.removeprefix(observer.origin)
                        requests.append((http_request.full_url, http_request.get_method(),
                                         dict(http_request.header_items()), timeout))
                        status, body = responses[path]
                        if status >= 400:
                            http_errors.append(path)
                            raise urllib.error.HTTPError(
                                http_request.full_url, status, "synthetic", {}, SyntheticBody(path, body)
                            )
                        return SyntheticResponse(path, status, body)

                real_parse = observer._probe_item

                def parse(status, body):
                    item = real_parse(status, body)
                    if status == readiness_status and body == readiness_body:
                        parsed_ready.append(item)
                    return item

                def synthetic_one(guarded):
                    one_checks.append(guarded)
                    # Fixed historical identity is an explicit fixture, not ARM evidence.
                    return {**target["oneDeployInvariant"], "historicalActiveDeployment": {
                        "id": target["oneDeployInvariant"]["historicalActiveDeploymentId"],
                        "status": 4, "complete": True, "deployer": "OneDeploy",
                    }}

                def probe(profile):
                    probes.append(profile["sourceSha"])
                    if profile["sourceSha"] != SHA:
                        # The known historical baseline remains a synthetic settlement.
                        return {"sourceSha": profile["sourceSha"], "healthy": True}
                    self.assertEqual(state[0], desired)
                    observed = observer.probe(profile)
                    target_results.append(observed)
                    return observed

                def consume(settlement):
                    consumes.append(settlement)
                    raise AssertionError("failed HTTP readiness must not consume authority")

                def abort(settlement):
                    aborts.append(settlement)
                    return {"status": "complete"}

                with mock.patch.object(azure.urllib.request, "build_opener", return_value=SyntheticOpener()), \
                        mock.patch.object(observer, "_one_deploy_invariant", side_effect=synthetic_one), \
                        mock.patch.object(observer, "_probe_item", side_effect=parse):
                    result = box.activate_run_from_package(
                        source_sha=SHA, baseline=baseline, target=target, activation_fence=fence,
                        system_identity_principal=box.PRODUCTION_SYSTEM_PRINCIPAL_ID,
                        config_read=config_read, config_put=config_put,
                        restart=lambda: restarts.append(True), probe=probe, consume=consume, abort=abort,
                    )

                self.assertEqual(target_results, [{"sourceSha": "", "healthy": False}])
                self.assertEqual(len(requests), 60 * len(limits))
                expected_order = list(limits) * 60
                self.assertEqual([url for url, _, _, _ in requests], [observer.origin + path for path in expected_order])
                self.assertTrue(all(method == "GET" and headers == {
                    "Accept": "application/json", "Cache-control": "no-store"
                } and timeout == 30 for _, method, headers, timeout in requests))
                self.assertEqual(reads, [(path, limits[path] + 1) for path in expected_order])
                self.assertEqual(http_errors, ["/api/health/ready"] * (60 if readiness_status == 503 else 0))
                self.assertEqual(sleeps, [5] * 59)
                self.assertEqual(lease_checks, [fence] * 60)
                self.assertEqual(one_checks, [True] * 60)
                self.assertEqual(parsed_ready, [{
                    "status": readiness_status, "bodySha256": hashlib.sha256(readiness_body).hexdigest(),
                    "ok": name == "http-503", "code": expected_code,
                }] * 60)
                self.assertEqual(result["status"], "aborted")
                self.assertEqual(result["errorCode"], "activation-settlement")
                self.assertEqual(result["configDigest"], box.digest(box.canonical(original)))
                self.assertEqual(writes, [desired, original])
                self.assertEqual(len(restarts), 2)
                self.assertEqual(probes, [baseline["sourceSha"], SHA, baseline["sourceSha"]])
                self.assertEqual(consumes, [])
                self.assertEqual(len(aborts), 1)
                self.assertEqual(state[0], original)
                self.assertEqual(registry.data, registry_before)
                self.assertEqual(packages.data, packages_before)
                self.assertEqual(pending["lifecycle"], "pending")
                self.assertNotIn(str(box.PurePosixPath(pending_desc["blob"]).parent / "consumed.json"), registry.data)
                self.assertNotIn(f"v2/accepted/{SHA}/manifest.json", registry.data)
                self.assertEqual(transport_calls, [])
                self.assertEqual(attempts, [])


class Tests(unittest.TestCase):
    def test_registry_preflight_request_uses_exact_production_caller_and_no_descriptor_input(self):
        value = preflight_request()
        self.assertEqual(box.validate_request(value, now=NOW)[0], value)
        policy = box.bridge_owner_policy("registry-bridge-preflight")
        self.assertEqual(policy["workflowId"], box.OWNER_WORKFLOW_ID)
        self.assertEqual(policy["workflowPath"], box.OWNER_WORKFLOW_PATH)
        self.assertEqual(policy["events"], box.OWNER_WORKFLOW_EVENTS)
        value["acceptedBaseline"] = descriptor()
        with self.assertRaisesRegex(box.MailboxError, "request-unexpected-accepted-baseline"):
            box.validate_request(value, now=NOW)

    def test_registry_preflight_rejects_proofless_historical_strict_current_manifest(self):
        registry, packages = Worm(), Worm()
        expected = seed_accepted(registry, packages)
        before = (registry.counter, packages.counter)
        observed, document, _, _ = box._load_accepted(registry, box._worm_descriptor(expected), packages)
        self.assertEqual(observed, expected)
        self.assertEqual(document["baselineMode"], "strict")
        self.assertEqual(document["schemaVersion"], 2)
        with self.assertRaisesRegex(box.MailboxError, "accepted-current-proof-required"):
            box.resolve_current_accepted(registry, SHA, packages)
        self.assertEqual((registry.counter, packages.counter), before)
        self.assertEqual(box._worm_descriptor(observed)["blob"], f"v2/accepted/{SHA}/manifest.json")

    def test_registry_preflight_uses_only_exact_bootstrap_fallback(self):
        registry, packages = Worm(), Worm()
        source_sha = box.BOOTSTRAP_BASELINE["sourceSha"]
        expected = seed_accepted(registry, packages, source_sha, mode="bootstrap")
        observed, document, _, _ = box.resolve_current_accepted(registry, source_sha, packages)
        self.assertEqual(observed, expected)
        self.assertEqual(document["baselineMode"], "bootstrap")
        wrong_registry, wrong_packages = Worm(), Worm()
        seed_accepted(wrong_registry, wrong_packages, SHA, mode="bootstrap")
        with self.assertRaisesRegex(box.MailboxError, "accepted-current-binding"):
            box.resolve_current_accepted(wrong_registry, SHA, wrong_packages)

    def test_registry_preflight_rejects_absent_ambiguous_and_source_mismatch(self):
        with self.assertRaisesRegex(box.MailboxError, "accepted-current-absent"):
            box.resolve_current_accepted(Worm(), SHA, Worm())

        registry, packages = Worm(), Worm()
        seed_accepted(registry, packages)
        # The conflicting fallback does not need to be internally valid:
        # existence of both exact coordinates is already ambiguous.
        registry.create(
            f"v2/accepted/{SHA}/bootstrap-consumed/manifest.json", b"{}\n", "*"
        )
        with self.assertRaisesRegex(box.MailboxError, "accepted-current-ambiguous"):
            box.resolve_current_accepted(registry, SHA, packages)

        registry, packages = Worm(), Worm()
        seed_accepted(
            registry, packages, "b" * 40,
            path=f"v2/accepted/{SHA}/manifest.json",
        )
        with self.assertRaisesRegex(box.MailboxError, "accepted-current-binding"):
            box.resolve_current_accepted(registry, SHA, packages)

    def test_result_rejects_missing_or_extra_preflight_descriptors(self):
        req = preflight_request()
        records = {name: None for name in box.RESULT_RECORD_FIELDS}
        records["acceptedBaseline"] = descriptor(f"v2/accepted/{SHA}/manifest.json")
        proof = {
            "schemaVersion": 1, "phase": "candidate", "sourceSha": SHA,
            "runtimeRelease": {"status": 200, "value": SHA, "bodySha256": "1" * 64},
            "index": {"status": 200, "sha256": "8" * 64, "size": 1},
            "oneDeployInvariant": {**box.BOOTSTRAP_BASELINE["oneDeployInvariant"],
                "historicalActiveDeployment": {"id": box.BOOTSTRAP_BASELINE["oneDeployInvariant"]["historicalActiveDeploymentId"], "status": 4, "complete": True, "deployer": "OneDeploy"}},
            "live": {"status": 200, "bodySha256": "2" * 64, "ok": True, "code": ""},
            "ready": {"status": 200, "bodySha256": "3" * 64, "ok": True, "code": ""},
            "appHealth": {"status": 200, "bodySha256": "4" * 64, "ok": True, "code": ""},
            "securityInfo": {"status": 200, "bodySha256": "5" * 64, "ok": True, "code": ""},
            "observedAt": "2026-08-29T00:00:00.000Z",
        }
        result = {
            "schemaVersion": 1, "resultType": "paperdesk-private-release-result", "status": "complete",
            "requestSha256": box.digest(box.canonical(req)), "operation": req["operation"],
            "nonce": req["nonce"], "controlWorkflowSha": req["controlWorkflowSha"],
            "sourceSha": SHA, "webJobHistoryId": "history", "webJobRunId": "run",
            "records": records, "metadata": {"schemaVersion": 1, "operation": req["operation"],
                "sourceSha": SHA, "baselineMode": "strict", "servedIndexSha256": "8" * 64,
                "oneDeployInvariant": box.BOOTSTRAP_BASELINE["oneDeployInvariant"],
                "currentProductionProof": proof}, "observedAt": "2026-08-29T00:00:00.000Z",
        }
        self.assertTrue(box.validate_result(result, req))
        missing = json.loads(json.dumps(result)); missing["records"]["acceptedBaseline"] = None
        with self.assertRaisesRegex(box.MailboxError, "result-record-set"):
            box.validate_result(missing, req)
        extra = json.loads(json.dumps(result)); extra["records"]["pendingRelease"] = descriptor(f"v2/pending/{SHA}/x/manifest.json")
        with self.assertRaisesRegex(box.MailboxError, "result-record-set"):
            box.validate_result(extra, req)
        malformed = json.loads(json.dumps(result)); malformed["records"]["acceptedBaseline"]["extra"] = True
        with self.assertRaisesRegex(box.MailboxError, "result-acceptedBaseline"):
            box.validate_result(malformed, req)

    def test_request_is_exact_and_has_no_live_derived_expected_sha(self):
        value = request()
        value["acceptedBaseline"] = descriptor()
        observed, raw, sha = box.validate_request(value, now=NOW)
        self.assertEqual(observed, value)
        self.assertEqual(sha, hashlib.sha256(raw).hexdigest())
        self.assertNotIn("expectedLiveSha", value)
        bad = dict(value)
        bad["extra"] = 1
        with self.assertRaisesRegex(box.MailboxError, "request-fields"):
            box.validate_request(bad, now=NOW)

    def test_request_v2_candidate_coordinates_are_persist_only_and_distinct(self):
        value = request("persist-accepted-release")
        value.update({"acceptedBaseline": None,
            "pendingRelease": descriptor(f"v2/pending/{SHA}/3-1-4/manifest.json"),
            "consumedMarker": descriptor(f"v2/pending/{SHA}/3-1-4/consumed.json")})
        self.assertEqual(box.validate_request(value, now=NOW)[0], value)

        missing = dict(value)
        missing.pop("candidateRunId")
        with self.assertRaisesRegex(box.MailboxError, "request-fields"):
            box.validate_request(missing, now=NOW)

        for operation in sorted(box.OPERATIONS - {"persist-accepted-release"}):
            wrong_operation = request()
            wrong_operation.update({"operation": operation, "candidateRunId": "4"})
            with self.subTest(operation=operation), self.assertRaisesRegex(
                box.MailboxError, "request-unexpected-candidate-coordinate"
            ):
                box.validate_request(wrong_operation, now=NOW)

        reused = dict(value)
        reused["candidateRunId"] = reused["sourceRunId"]
        with self.assertRaisesRegex(box.MailboxError, "request-run-identity-reuse"):
            box.validate_request(reused, now=NOW)

        bad_attempt = dict(value)
        bad_attempt["candidateRunAttempt"] = "0"
        with self.assertRaisesRegex(box.MailboxError, "request-candidateRunAttempt"):
            box.validate_request(bad_attempt, now=NOW)

    def test_contract_fixed_coordinates_are_generated_from_source_constant(self):
        document = json.loads(Path("contracts/private_release_mailbox_contract.json").read_text(encoding="utf-8"))
        self.assertEqual(document["fixed"], box.FIXED_COORDS)
        self.assertNotIn("activeOneDeployId", document["fixed"]["bootstrapBaseline"])

    def test_mailbox_requires_201_and_exact_creator_readback(self):
        creator = "11111111-1111-1111-1111-111111111111"
        saved = [None]

        def transport(method, url, headers, body):
            name = url.split("/deployments/")[1].split("?")[0]
            if method == "PUT":
                saved[0] = json.loads(body)["properties"]["template"]["outputs"]["envelope"]["value"]
                return box.Response(201, url, b"", {})
            document = {"id": f"/subscriptions/{box.SUBSCRIPTION}/resourceGroups/rg/providers/Microsoft.Resources/deployments/{name}", "name": name, "type": "Microsoft.Resources/deployments", "systemData": {"createdBy": creator, "lastModifiedBy": creator, "createdByType": "Application", "lastModifiedByType": "Application", "createdAt": "x", "lastModifiedAt": "x"}, "properties": {"provisioningState": "Succeeded", "outputs": {"envelope": {"type": "Object", "value": saved[0]}}}}
            return box.Response(200, url, json.dumps(document).encode(), {})

        box.MailboxClient("rg", transport, request_creator=creator, result_creator=creator).put_create("pdreq-3-1-" + "e" * 32, request())
        with self.assertRaisesRegex(box.MailboxError, "mailbox-creator-required"):
            box.MailboxClient("rg", transport).put_create("pdreq-3-1-" + "e" * 32, request())

    def test_deterministic_package_binds_served_index(self):
        body, metadata = box.deterministic_deploy_zip(archive(), SHA)
        again, _ = box.deterministic_deploy_zip(archive(), SHA)
        self.assertEqual(body, again)
        self.assertEqual(metadata["servedIndexSha256"], hashlib.sha256(b"<html>ok</html>").hexdigest())

    def test_consume_records_actual_deploy_run_and_recovers_exactly(self):
        registry, packages = Worm(), Worm()
        baseline = seed_accepted(
            registry, packages, box.BOOTSTRAP_BASELINE["sourceSha"], mode="bootstrap"
        )
        candidate = request("prepare-candidate")
        candidate.update({"acceptedBaseline": box._worm_descriptor(baseline),
            "acceptanceRunId": "4", "acceptanceRunAttempt": "2"})
        prepared = box.prepare_candidate(
            registry, candidate, archive(), now=NOW, package_boundary=packages
        )
        pending_desc = prepared["records"]["pendingRelease"]
        fence = activation_fence(pending_desc)
        consume = request("consume-candidate")
        consume.update({"artifactId": "", "artifactSha256": "", "artifactMember": "",
            "artifactMemberSha256": "", "acceptedBaseline": box._worm_descriptor(baseline),
            "pendingRelease": pending_desc, "acceptanceRunId": "4", "acceptanceRunAttempt": "2",
            "activationPlan": box.activation_plan_from_fence(fence)})
        historical = box.BOOTSTRAP_BASELINE["oneDeployInvariant"]
        proof = {
            "schemaVersion": 1, "phase": "candidate", "sourceSha": SHA,
            "runtimeRelease": {"status": 200, "value": SHA, "bodySha256": "1" * 64},
            "index": {"status": 200, "sha256": prepared["metadata"]["servedIndexSha256"], "size": 1},
            "oneDeployInvariant": {**historical, "historicalActiveDeployment": {
                "id": historical["historicalActiveDeploymentId"], "status": 4,
                "complete": True, "deployer": "OneDeploy"}},
            "live": {"status": 200, "bodySha256": "2" * 64, "ok": True, "code": ""},
            "ready": {"status": 200, "bodySha256": "3" * 64, "ok": True, "code": ""},
            "appHealth": {"status": 200, "bodySha256": "4" * 64, "ok": True, "code": ""},
            "securityInfo": {"status": 200, "bodySha256": "5" * 64, "ok": True, "code": ""},
            "observedAt": "2026-08-29T00:00:00.000Z",
        }
        changed_run = dict(consume)
        changed_run["acceptanceRunAttempt"] = "3"
        before = (registry.counter, packages.counter)
        with self.assertRaisesRegex(box.MailboxError, "candidate-pending-binding"):
            box.consume_candidate(
                registry, changed_run, now=NOW, activation_proof=proof, activation_fence=fence
            )
        self.assertEqual((registry.counter, packages.counter), before)
        consumed = box.consume_candidate(
            registry, consume, now=NOW, activation_proof=proof, activation_fence=fence
        )
        consumed_desc = consumed["records"]["consumedMarker"]
        consumed_doc = json.loads(registry.read(consumed_desc["blob"], consumed_desc["versionId"]).body)
        self.assertEqual(consumed_doc["deploymentCoordinates"],
            {"candidateRunId": "4", "candidateRunAttempt": "2"})
        recovered = box.prepare_candidate(
            registry, candidate, archive(), now=NOW, package_boundary=packages
        )
        self.assertEqual(recovered["records"]["consumedMarker"], consumed_desc)
        self.assertEqual(recovered["metadata"]["terminalState"], "consumed")

    def test_persisted_release_binds_source_candidate_acceptance_and_recovers_exactly(self):
        registry, packages = Worm(), Worm()
        candidate_runtime = archive()
        baseline = seed_accepted(
            registry, packages, box.BOOTSTRAP_BASELINE["sourceSha"], mode="bootstrap"
        )
        candidate = request("prepare-candidate")
        candidate.update({"acceptedBaseline": box._worm_descriptor(baseline),
            "sourceRunId": registry_fixture.SOURCE_RUN,
            "sourceRunAttempt": registry_fixture.SOURCE_ATTEMPT,
            "acceptanceRunId": registry_fixture.DEPLOYMENT_RUN,
            "acceptanceRunAttempt": registry_fixture.DEPLOYMENT_ATTEMPT,
            "artifactMemberSha256": hashlib.sha256(candidate_runtime).hexdigest()})
        prepared = box.prepare_candidate(
            registry, candidate, candidate_runtime, now=NOW, package_boundary=packages
        )
        pending_desc = prepared["records"]["pendingRelease"]
        pending = registry.read(pending_desc["blob"], pending_desc["versionId"])
        pending_document = json.loads(pending.body)
        self.assertEqual(pending_document["deploymentCoordinates"],
            {"candidateRunId": registry_fixture.DEPLOYMENT_RUN,
             "candidateRunAttempt": registry_fixture.DEPLOYMENT_ATTEMPT})
        consumed = registry.create(
            str(box.PurePosixPath(pending.blob).parent / "consumed.json"),
            box.canonical({"schemaVersion": 1, "lifecycle": "candidate-consumed",
                "pendingRelease": pending_desc, "acceptedBaseline": box._worm_descriptor(baseline),
                "sourceSha": SHA, "deploymentCoordinates": pending_document["deploymentCoordinates"],
                "activationFence": activation_fence(pending_desc),
                "activationProof": {}}),
            "*",
        )
        transfer_tar = accepted_transfer(candidate_runtime)
        persist = request("persist-accepted-release")
        persist.update({"acceptedBaseline": None, "pendingRelease": pending_desc,
            "consumedMarker": box._worm_descriptor(consumed),
            "sourceRunId": registry_fixture.SOURCE_RUN,
            "sourceRunAttempt": registry_fixture.SOURCE_ATTEMPT,
            "candidateRunId": registry_fixture.DEPLOYMENT_RUN,
            "candidateRunAttempt": registry_fixture.DEPLOYMENT_ATTEMPT,
            "acceptanceRunId": registry_fixture.ACCEPTANCE_RUN,
            "acceptanceRunAttempt": registry_fixture.ACCEPTANCE_ATTEMPT,
            "artifactMember": "paperdesk-accepted-release-request.tar.gz",
            "artifactMemberSha256": hashlib.sha256(transfer_tar).hexdigest()})

        mismatched_source = dict(persist)
        mismatched_source["sourceRunId"] = "6"
        before = (registry.counter, packages.counter)
        with self.assertRaisesRegex(box.MailboxError, "accepted-pending-coordinate-binding"):
            box.persist_accepted_release(
                registry, mismatched_source, transfer_tar, now=NOW, package_boundary=packages
            )
        self.assertEqual((registry.counter, packages.counter), before)

        mismatched_candidate = dict(persist)
        mismatched_candidate["candidateRunId"] = "6"
        with self.assertRaisesRegex(box.MailboxError, "accepted-pending-coordinate-binding"):
            box.persist_accepted_release(
                registry, mismatched_candidate, transfer_tar, now=NOW, package_boundary=packages
            )
        self.assertEqual((registry.counter, packages.counter), before)

        mismatched_candidate_attempt = dict(persist)
        mismatched_candidate_attempt["candidateRunAttempt"] = "3"
        with self.assertRaisesRegex(box.MailboxError, "accepted-pending-coordinate-binding"):
            box.persist_accepted_release(
                registry, mismatched_candidate_attempt, transfer_tar, now=NOW, package_boundary=packages
            )
        self.assertEqual((registry.counter, packages.counter), before)

        invalid_tar = b"not a transfer archive"
        invalid_request = dict(persist, artifactMemberSha256=hashlib.sha256(invalid_tar).hexdigest())
        with self.assertRaisesRegex(box.MailboxError, "accepted-transfer-proof"):
            box.persist_accepted_release(
                registry, invalid_request, invalid_tar, now=NOW, package_boundary=packages
            )
        self.assertEqual((registry.counter, packages.counter), before)

        durable = box.persist_accepted_release(
            registry, persist, transfer_tar, now=NOW, package_boundary=packages
        )
        manifest_desc = durable["records"]["acceptedBaseline"]
        manifest = json.loads(registry.read(manifest_desc["blob"], manifest_desc["versionId"]).body)
        expected_coordinates = {field: persist[field] for field in box.RELEASE_COORDINATE_FIELDS}
        self.assertEqual(manifest["schemaVersion"], 3)
        self.assertEqual(manifest["releaseCoordinates"], expected_coordinates)
        self.assertEqual(manifest["artifact"]["pendingRelease"], pending_desc)
        self.assertEqual(manifest["consumedMarker"], box._worm_descriptor(consumed))
        self.assertIn(f"/{registry_fixture.DEPLOYMENT_RUN}-{registry_fixture.DEPLOYMENT_ATTEMPT}/{registry_fixture.ACCEPTANCE_RUN}-{registry_fixture.ACCEPTANCE_ATTEMPT}/", manifest["deploymentBundle"]["blob"])
        proof_desc = manifest["acceptedProof"]
        proof_doc = json.loads(registry.read(proof_desc["blob"], proof_desc["versionId"]).body)
        with tarfile.open(fileobj=io.BytesIO(transfer_tar), mode="r:gz") as transfer:
            receipt = transfer.extractfile(
                f"payload/receipts/paperdesk-production-acceptance-receipt-{SHA}.json"
            ).read()
        self.assertEqual(proof_doc["productionAcceptanceReceiptSha256"], hashlib.sha256(receipt).hexdigest())
        self.assertEqual(proof_doc["releaseCoordinates"], expected_coordinates)
        resolved, resolved_doc, resolved_bundle, _ = box.resolve_current_accepted(registry, SHA, packages)
        self.assertEqual(box._worm_descriptor(resolved), manifest_desc)
        self.assertEqual(resolved_doc["schemaVersion"], 3)
        self.assertEqual(box._worm_descriptor(resolved_bundle), manifest["deploymentBundle"])

        signed_records = dict(durable["records"])
        signed_records["cleanupObligation"] = descriptor(
            f"v2/cleanup-obligations/{SHA}/{'7' * 64}.json"
        )
        signed_result = {"schemaVersion": 1, "resultType": "paperdesk-private-release-result",
            "status": "complete", "requestSha256": box.digest(box.canonical(persist)),
            "operation": persist["operation"], "nonce": persist["nonce"],
            "controlWorkflowSha": persist["controlWorkflowSha"], "sourceSha": SHA,
            "webJobHistoryId": "history", "webJobRunId": "run", "records": signed_records,
            "metadata": durable["metadata"], "observedAt": "2026-08-29T00:00:00.000Z"}
        self.assertTrue(box.validate_result(signed_result, persist))
        tampered_result = json.loads(json.dumps(signed_result))
        tampered_result["metadata"]["releaseCoordinates"]["candidateRunAttempt"] = "3"
        with self.assertRaisesRegex(box.MailboxError, "result-release-coordinate-binding"):
            box.validate_result(tampered_result, persist)
        misplaced_proof = json.loads(json.dumps(signed_result))
        misplaced_proof["metadata"]["acceptedProof"]["blob"] = f"v2/accepted/{SHA}/other/accepted-proof.json"
        with self.assertRaisesRegex(box.MailboxError, "result-accepted-proof-coordinate"):
            box.validate_result(misplaced_proof, persist)

        before = (registry.counter, packages.counter)
        recovered = box.persist_accepted_release(
            registry, persist, transfer_tar, now=NOW, package_boundary=packages
        )
        self.assertEqual(recovered["records"]["acceptedBaseline"], manifest_desc)
        self.assertEqual((registry.counter, packages.counter), before)

        competing_acceptance = dict(persist, acceptanceRunId="99999")
        with self.assertRaisesRegex(box.MailboxError, "accepted-recovery-coordinate-binding"):
            box.persist_accepted_release(
                registry, competing_acceptance, transfer_tar, now=NOW,
                package_boundary=packages,
            )
        self.assertEqual((registry.counter, packages.counter), before)

        tampered_attempt = dict(persist)
        tampered_attempt["candidateRunAttempt"] = "3"
        with self.assertRaisesRegex(box.MailboxError, "accepted-pending-coordinate-binding"):
            box.persist_accepted_release(
                registry, tampered_attempt, transfer_tar, now=NOW, package_boundary=packages
            )
        self.assertEqual((registry.counter, packages.counter), before)

        rollback = request("prepare-rollback")
        rollback.update({"artifactId": "", "artifactSha256": "", "artifactMember": "",
            "artifactMemberSha256": "", "acceptedBaseline": manifest_desc,
            "logicalOperationId": "7" * 64})
        prepared_rollback = box.prepare_rollback(
            registry, rollback, now=NOW, package_boundary=packages
        )
        self.assertEqual(prepared_rollback["records"]["acceptedBaseline"], manifest_desc)
        self.assertEqual(prepared_rollback["records"]["deploymentBundle"], manifest["deploymentBundle"])

        registry.data[proof_desc["blob"]] = box.WormRecord(
            proof_desc["blob"], box.canonical({**proof_doc, "candidateRuntimeSha256": "0" * 64}),
            proof_desc["etag"], proof_desc["versionId"],
        )
        with self.assertRaisesRegex(box.MailboxError, "accepted-proof-readback"):
            box._load_accepted(registry, manifest_desc, packages)

    def test_persist_rejects_consumed_deployment_coordinate_tamper_before_write(self):
        registry, packages = Worm(), Worm()
        baseline = seed_accepted(
            registry, packages, box.BOOTSTRAP_BASELINE["sourceSha"], mode="bootstrap"
        )
        candidate = request("prepare-candidate")
        candidate.update({"acceptedBaseline": box._worm_descriptor(baseline),
            "acceptanceRunId": "4", "acceptanceRunAttempt": "2"})
        prepared = box.prepare_candidate(
            registry, candidate, archive(), now=NOW, package_boundary=packages
        )
        pending_desc = prepared["records"]["pendingRelease"]
        consumed = registry.create(
            str(box.PurePosixPath(pending_desc["blob"]).parent / "consumed.json"),
            box.canonical({"schemaVersion": 1, "lifecycle": "candidate-consumed",
                "pendingRelease": pending_desc, "acceptedBaseline": box._worm_descriptor(baseline),
                "sourceSha": SHA,
                "deploymentCoordinates": {"candidateRunId": "6", "candidateRunAttempt": "2"},
                "activationFence": activation_fence(pending_desc), "activationProof": {}}),
            "*",
        )
        transfer_tar = b"accepted release transfer"
        persist = request("persist-accepted-release")
        persist.update({"acceptedBaseline": None, "pendingRelease": pending_desc,
            "consumedMarker": box._worm_descriptor(consumed),
            "artifactMemberSha256": hashlib.sha256(transfer_tar).hexdigest()})
        before = (registry.counter, packages.counter)
        with self.assertRaisesRegex(box.MailboxError, "accepted-consumed-coordinate-binding"):
            box.persist_accepted_release(
                registry, persist, transfer_tar, now=NOW, package_boundary=packages
            )
        self.assertEqual((registry.counter, packages.counter), before)

    def test_activated_fixture_and_live_key_expiry_are_exact(self):
        activation = fixture.activation()
        self.assertNotEqual(activation.bridge_package_source_sha, activation.workflow_sha)
        self.assertEqual(activation.bridge_package_source_sha, fixture.BOOTSTRAP_SOURCE_SHA)
        package_blob = activation.provisioning_evidence["bridgeRuntime"]["packageBlob"]
        self.assertEqual(
            package_blob,
            f"v2/control/{fixture.BOOTSTRAP_SOURCE_SHA}/paperdesk-private-release-bridge.zip",
        )
        projection = activation.provisioning_evidence["keyVaultBoundary"]["keyDataPlaneProjection"]
        self.assertEqual(box.validate_live_signing_key(projection, activation, now=NOW), projection)
        late = dt.datetime.fromtimestamp(fixture.KEY_EXPIRES - box.KEY_RECOVERY_HORIZON_SECONDS + 1, tz=dt.timezone.utc)
        with self.assertRaisesRegex(box.MailboxError, "live-key-expiry"):
            box.validate_live_signing_key(projection, activation, now=late)

    def test_activation_document_requires_exact_activated_canonical_root(self):
        document, evidence, _ = fixture.activated_bundle()
        dormant = json.loads(json.dumps(document))
        dormant["status"] = "source-dormant"
        with self.assertRaisesRegex(box.MailboxError, "activation-document"):
            box.load_activation_document(
                dormant,
                runtime_workflow_sha=fixture.WORKFLOW_SHA,
                observed_bridge_package_sha256=fixture.PACKAGE_SHA,
                provisioning_evidence=evidence,
            )
        unexpected = json.loads(json.dumps(document))
        unexpected["clientSecret"] = "must-never-be-accepted"
        with self.assertRaisesRegex(box.MailboxError, "activation-document"):
            box.load_activation_document(
                unexpected,
                runtime_workflow_sha=fixture.WORKFLOW_SHA,
                observed_bridge_package_sha256=fixture.PACKAGE_SHA,
                provisioning_evidence=evidence,
            )
        with self.assertRaisesRegex(box.MailboxError, "activation-document-canonical"):
            box.load_activation_document(
                document,
                runtime_workflow_sha=fixture.WORKFLOW_SHA,
                observed_bridge_package_sha256=fixture.PACKAGE_SHA,
                provisioning_evidence=evidence,
                raw_document=json.dumps(document, indent=2),
            )

    def test_activation_rejects_bridge_package_built_from_merged_workflow(self):
        document, evidence, _ = fixture.activated_bundle()
        document["activation"]["bridgePackageSourceSha"] = fixture.WORKFLOW_SHA
        with self.assertRaisesRegex(box.MailboxError, "activation-package-source-sha"):
            box.load_activation_document(
                document,
                runtime_workflow_sha=fixture.WORKFLOW_SHA,
                observed_bridge_package_sha256=fixture.PACKAGE_SHA,
                provisioning_evidence=evidence,
            )

    def test_pre_s2_mode_cannot_validate_a_completed_distinct_source_activation(self):
        document, evidence, _ = fixture.activated_bundle()
        with self.assertRaisesRegex(box.MailboxError, "activation-pre-s2-source"):
            box.load_activation_document(
                document,
                runtime_workflow_sha=fixture.WORKFLOW_SHA,
                observed_bridge_package_sha256=fixture.PACKAGE_SHA,
                provisioning_evidence=evidence,
                pre_s2_evidence_validation=True,
            )

    def test_package_path_is_bound_to_bootstrap_source_not_s2_workflow(self):
        document, evidence, _ = fixture.activated_bundle()
        document["activation"]["bridgePackageSourceSha"] = "c" * 40
        with self.assertRaisesRegex(box.MailboxError, "activation-bridge-runtime"):
            box.load_activation_document(
                document,
                runtime_workflow_sha=fixture.WORKFLOW_SHA,
                observed_bridge_package_sha256=fixture.PACKAGE_SHA,
                provisioning_evidence=evidence,
            )

    def _terminal_durable(self, operation="consume-candidate"):
        records = {name: None for name in box.RESULT_RECORD_FIELDS}
        records["claim"] = descriptor(f"v2/pending/{SHA}/3-1-4/claim.json")
        records["result"] = descriptor(f"v2/pending/{SHA}/3-1-4/result.json")
        records["pendingRelease"] = descriptor(f"v2/pending/{SHA}/3-1-4/manifest.json")
        records["consumedMarker"] = descriptor(f"v2/pending/{SHA}/3-1-4/consumed.json")
        return {"records": records, "metadata": {"schemaVersion": 1, "operation": operation, "sourceSha": SHA,
                "activationProof": {"nonSecret": True}, "terminalActivationFence": activation_fence(records["pendingRelease"])}}

    def test_cleanup_obligation_is_create_or_read_exact_and_bound_to_owner(self):
        boundary = Worm(lose_first_create=True)
        req = request("consume-candidate")
        req.update({"artifactId": "", "artifactSha256": "", "artifactMember": "", "artifactMemberSha256": "",
                    "pendingRelease": descriptor(f"v2/pending/{SHA}/3-1-4/manifest.json"),
                    "activationPlan": {"blob": box.FIXED_COORDS["activationFenceBlob"], "operation": "candidate", "sourceSha": SHA,
                                       "release": descriptor(f"v2/pending/{SHA}/3-1-4/manifest.json"),
                                       "preSettingsSha256": "2" * 64, "desiredSettingsSha256": "3" * 64}})
        control = transient_control("consume-candidate")
        with self.assertRaisesRegex(OSError, "lost create response"):
            box.attach_cleanup_obligation(boundary, req, self._terminal_durable(), control)
        recovered = box.attach_cleanup_obligation(boundary, req, self._terminal_durable(), control)
        obligation = recovered["records"]["cleanupObligation"]
        self.assertTrue(obligation["blob"].startswith(f"v2/cleanup-obligations/{SHA}/"))
        stored = json.loads(boundary.read(obligation["blob"], obligation["versionId"]).body)
        self.assertEqual(stored["transientOwner"]["workflowId"], box.OWNER_WORKFLOW_ID)
        self.assertEqual(stored["transientExpiresAt"], control["expiresAt"])
        self.assertEqual(stored["cleanupCaller"]["workflowId"], box.CLEANUP_WORKFLOW_ID)
        altered = transient_control("consume-candidate")
        altered["expiresAt"] = "2026-08-29T03:00:00.000Z"
        with self.assertRaisesRegex(box.MailboxError, "worm-existing-drift"):
            box.attach_cleanup_obligation(boundary, req, self._terminal_durable(), altered)

    def test_ambiguous_settings_put_reconciles_desired_state(self):
        release = descriptor(f"v2/pending/{SHA}/3-1-4/manifest.json")
        base = {"X": "1", "WEBSITE_RUN_FROM_PACKAGE": box.package_url(descriptor("v1/accepted/b/deployment.zip")), "WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID": "SystemAssigned"}
        state = [dict(base)]
        target = {"sourceSha": SHA, "baselineMode": "strict", "servedIndexSha256": "2" * 64, "oneDeployInvariant": box.BOOTSTRAP_BASELINE["oneDeployInvariant"], "deploymentBundle": descriptor("v1/pending/a/deployment.zip")}
        baseline = {"sourceSha": "b" * 40, "baselineMode": "strict", "servedIndexSha256": "1" * 64, "oneDeployInvariant": box.BOOTSTRAP_BASELINE["oneDeployInvariant"], "deploymentBundle": descriptor("v1/accepted/b/deployment.zip")}
        desired = dict(base)
        desired["WEBSITE_RUN_FROM_PACKAGE"] = box.package_url(target["deploymentBundle"])

        def put(values, expected):
            state[0] = dict(values)
            raise OSError("lost response")

        result = box.activate_run_from_package(source_sha=SHA, baseline=baseline, target=target,
            activation_fence=activation_fence(release, box.digest(box.canonical(base)), box.digest(box.canonical(desired))),
            system_identity_principal=box.PRODUCTION_SYSTEM_PRINCIPAL_ID,
            config_read=lambda: (dict(state[0]), box.digest(box.canonical(state[0]))), config_put=put,
            restart=lambda: None, probe=lambda profile: {"sourceSha": profile["sourceSha"], "healthy": True},
            consume=lambda proof: {"status": "complete"}, abort=lambda proof: {"status": "complete"})
        self.assertEqual(result["sourceSha"], SHA)

    def test_third_state_is_never_overwritten(self):
        release = descriptor(f"v2/pending/{SHA}/3-1-4/manifest.json")
        base = {"X": "1"}
        target = {"sourceSha": SHA, "baselineMode": "strict", "servedIndexSha256": "2" * 64, "oneDeployInvariant": box.BOOTSTRAP_BASELINE["oneDeployInvariant"], "deploymentBundle": descriptor("v1/pending/a/deployment.zip")}
        baseline = {"sourceSha": "b" * 40, "baselineMode": "bootstrap", "servedIndexSha256": "1" * 64, "oneDeployInvariant": box.BOOTSTRAP_BASELINE["oneDeployInvariant"], "deploymentBundle": descriptor("v1/accepted/b/deployment.zip")}
        desired = dict(base)
        desired.update({"WEBSITE_RUN_FROM_PACKAGE": box.package_url(target["deploymentBundle"]), "WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID": "SystemAssigned"})
        state = [dict(base)]
        writes = []

        def put(values, expected):
            writes.append(dict(values))
            state[0] = {"OUT_OF_BAND": "owner"}
            raise OSError("ambiguous")

        with self.assertRaisesRegex(box.MailboxError, "activation-indeterminate"):
            box.activate_run_from_package(source_sha=SHA, baseline=baseline, target=target,
                activation_fence=activation_fence(release, box.digest(box.canonical(base)), box.digest(box.canonical(desired))),
                system_identity_principal=box.PRODUCTION_SYSTEM_PRINCIPAL_ID,
                config_read=lambda: (dict(state[0]), box.digest(box.canonical(state[0]))), config_put=put,
                restart=lambda: None, probe=lambda profile: {"sourceSha": profile["sourceSha"], "healthy": True},
                consume=lambda proof: {"status": "complete"}, abort=lambda proof: {"status": "complete"})
        self.assertEqual(len(writes), 1)
        self.assertEqual(state[0], {"OUT_OF_BAND": "owner"})


if __name__ == "__main__":
    unittest.main()
