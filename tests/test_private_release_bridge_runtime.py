import datetime as dt
import hashlib
import io
import tarfile
import unittest

from provider import private_release_bridge_runtime as bridge
from scripts import private_release_mailbox as box
from tests import private_release_v2_fixture as fixture


NOW = dt.datetime(2026, 8, 29, tzinfo=dt.timezone.utc)


def archive(index=b"index"):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as target:
        info = tarfile.TarInfo("index.html")
        info.size = len(index)
        target.addfile(info, io.BytesIO(index))
    return output.getvalue()


def bootstrap_request(payload):
    value = {
        "schemaVersion": 2, "requestType": "paperdesk-private-release-request",
        "operation": "bootstrap-prepare", "repositoryId": box.BOOTSTRAP_BASELINE["repositoryId"],
        "ownerId": box.BOOTSTRAP_BASELINE["ownerId"], "controlWorkflowSha": fixture.WORKFLOW_SHA,
        "sourceSha": box.BOOTSTRAP_BASELINE["sourceSha"], "sourceRunId": box.BOOTSTRAP_BASELINE["sourceRunId"],
        "sourceRunAttempt": box.BOOTSTRAP_BASELINE["sourceRunAttempt"], "candidateRunId": None,
        "candidateRunAttempt": None, "artifactId": box.BOOTSTRAP_BASELINE["artifactId"],
        "artifactSha256": box.BOOTSTRAP_BASELINE["artifactSha256"], "artifactMember": box.BOOTSTRAP_BASELINE["artifactMember"],
        "artifactMemberSha256": hashlib.sha256(payload).hexdigest(), "acceptanceRunId": "5", "acceptanceRunAttempt": "1",
        "logicalOperationId": None, "nonce": "d" * 32, "issuedAt": "2026-08-29T00:00:00.000Z",
        "expiresAt": "2026-08-29T00:15:00.000Z", "acceptedBaseline": None, "pendingRelease": None,
        "consumedMarker": None, "rollbackPreparation": None, "activationPlan": None, "activationProof": None,
    }
    return value


def preflight_request():
    value = bootstrap_request(b"")
    value.update({
        "operation": "registry-bridge-preflight", "repositoryId": box.OWNER_REPOSITORY_ID,
        "ownerId": box.OWNER_ID, "sourceSha": "a" * 40, "sourceRunId": "3",
        "sourceRunAttempt": "1", "artifactId": "", "artifactSha256": "",
        "artifactMember": "", "artifactMemberSha256": "", "acceptedBaseline": None,
    })
    return value


class Worm:
    def __init__(self):
        self.data = {}
        self.counter = 0

    def create(self, name, body, if_none_match):
        if name in self.data:
            raise box.MailboxError("blob-exists")
        self.counter += 1
        value = box.WormRecord(name, body, f'"e{self.counter}"', f"v{self.counter}")
        self.data[name] = value
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


class Arm:
    def __init__(self, request, events):
        self.request = request
        self.events = events
        self.created = []

    def get(self, name):
        self.events.append("mailbox")
        return self.request

    def put_create_or_read_exact(self, name, envelope):
        self.events.append("result")
        self.created.append((name, envelope))


class Tests(unittest.TestCase):
    def _run(self, *, bad_key=False, request_name=None, authorized=False):
        activation = fixture.activation()
        payload = archive()
        request = bootstrap_request(payload)
        events = []
        arm = Arm(request, events)
        signing = []
        saved = dict(box.BOOTSTRAP_BASELINE)
        box.BOOTSTRAP_BASELINE["artifactMemberSha256"] = hashlib.sha256(payload).hexdigest()
        box.BOOTSTRAP_BASELINE["servedIndexSha256"] = hashlib.sha256(b"index").hexdigest()
        try:
            key = dict(activation.provisioning_evidence["keyVaultBoundary"]["keyDataPlaneProjection"])
            if bad_key:
                key["n"] = "B" * 384

            def key_reader():
                events.append("key")
                return key

            def artifact_reader(_):
                events.append("artifact")
                return payload

            name = request_name or f"pdreq-{request['sourceRunId']}-{request['sourceRunAttempt']}-{request['nonce']}"
            boundaries = dict(
                activation=activation, now=NOW, arm_mailbox=arm, transient_control={},
                registry_worm=Worm(), package_worm=Worm(), activation_fence=object(),
                production_activation=object(), key_reader=key_reader, artifact_reader=artifact_reader,
                signer=lambda raw, **kwargs: (signing.append(kwargs) or "AA"),
                signing_key_id=activation.signing_key_id, signing_key_version=activation.signing_key_version,
                webjob_history_id="history-1", webjob_run_id="run-1")
            if authorized:
                boundaries.pop("transient_control")
                outcome = bridge.process_authorized(
                    {"requestName": name, "operation": request["operation"], "sourceSha": request["sourceSha"]},
                    **boundaries,
                )
                envelope = outcome["envelope"]
            else:
                envelope = bridge.process_request(name, **boundaries)
            return envelope, events, signing
        finally:
            box.BOOTSTRAP_BASELINE.clear()
            box.BOOTSTRAP_BASELINE.update(saved)

    def test_live_key_is_first_and_bootstrap_result_binds_exact_signer(self):
        envelope, events, signing = self._run()
        self.assertEqual(events[:3], ["key", "mailbox", "artifact"])
        self.assertEqual(events[-1], "result")
        self.assertEqual(envelope["result"]["webJobRunId"], "run-1")
        self.assertEqual(signing[0]["key_version"], fixture.KEY_VERSION)
        self.assertIsNotNone(envelope["result"]["records"]["acceptedBaseline"])

    def test_live_key_drift_fails_before_mailbox_artifact_or_storage(self):
        with self.assertRaisesRegex(box.MailboxError, "live-key-projection"):
            self._run(bad_key=True)

    def test_authorized_entry_validates_key_then_reads_mailbox_once(self):
        _, events, _ = self._run(authorized=True)
        self.assertEqual(events[:3], ["key", "mailbox", "artifact"])
        self.assertEqual(events.count("mailbox"), 1)

    def test_wrong_mailbox_coordinate_stops_before_artifact(self):
        with self.assertRaisesRegex(box.MailboxError, "bridge-request-coordinate"):
            self._run(request_name="pdreq-4-1-" + "d" * 32)

    def test_registry_preflight_exact_reads_and_live_observation_have_no_release_mutation(self):
        activation = fixture.activation()
        request = preflight_request()
        events = []
        registry, packages = Worm(), Worm()
        bundle = packages.create("v1/accepted/" + request["sourceSha"] + "/x/deployment.zip", b"zip", "*")
        pending_bundle = packages.create("v1/pending/" + request["sourceSha"] + "/3-1-4/deployment.zip", b"zip", "*")
        baseline = {"blob": "v2/accepted/" + "b" * 40 + "/manifest.json", "sha256": "6" * 64,
                    "size": 1, "etag": '"baseline"', "versionId": "baseline-v1"}
        pending = registry.create(
            "v2/pending/" + request["sourceSha"] + "/3-1-4/manifest.json",
            box.canonical({"schemaVersion": 1, "lifecycle": "pending", "sourceSha": request["sourceSha"],
                "execution": {"repositoryId": box.OWNER_REPOSITORY_ID, "ownerId": box.OWNER_ID,
                    "sourceRunId": "3", "sourceRunAttempt": "1", "artifactId": "4"},
                "deploymentCoordinates": {"candidateRunId": "4", "candidateRunAttempt": "2"},
                "artifact": {"outerSha256": "3" * 64, "member": "runtime.tar.gz", "memberSha256": "4" * 64},
                "acceptedBaseline": baseline, "servedIndexSha256": "8" * 64,
                "oneDeployInvariant": box.BOOTSTRAP_BASELINE["oneDeployInvariant"],
                "deploymentBundle": box._worm_descriptor(pending_bundle)}),
            "*",
        )
        pending_desc = box._worm_descriptor(pending)
        fence = {"blob": box.FIXED_COORDS["activationFenceBlob"], "leaseId": "22222222-2222-4222-8222-222222222222",
            "stateVersion": "1", "release": pending_desc, "preSettingsSha256": "2" * 64,
            "desiredSettingsSha256": "3" * 64, "etag": '"f"', "operation": "candidate",
            "sourceSha": request["sourceSha"]}
        consumed = registry.create(
            "v2/pending/" + request["sourceSha"] + "/3-1-4/consumed.json",
            box.canonical({"schemaVersion": 1, "lifecycle": "candidate-consumed", "sourceSha": request["sourceSha"],
                "pendingRelease": pending_desc, "acceptedBaseline": baseline,
                "deploymentCoordinates": {"candidateRunId": "4", "candidateRunAttempt": "2"},
                "activationFence": fence, "activationProof": {}}),
            "*",
        )
        transfer = registry.create(
            "v2/accepted/" + request["sourceSha"] + "/4-2/5-1/accepted-release-transfer.tar.gz",
            b"transfer", "*",
        )
        manifest = registry.create(
            "v2/accepted/" + request["sourceSha"] + "/manifest.json",
            box.canonical({
                "schemaVersion": 2, "lifecycle": "accepted", "baselineMode": "strict",
                "sourceSha": request["sourceSha"],
                "releaseCoordinates": {"sourceRunId": "3", "sourceRunAttempt": "1",
                    "candidateRunId": "4", "candidateRunAttempt": "2",
                    "acceptanceRunId": "5", "acceptanceRunAttempt": "1"},
                "artifact": {"id": "4", "outerSha256": "5" * 64, "member": "accepted.tar.gz",
                    "memberSha256": "6" * 64, "pendingRelease": pending_desc,
                    "acceptedTransfer": box._worm_descriptor(transfer)}, "servedIndexSha256": "8" * 64,
                "oneDeployInvariant": box.BOOTSTRAP_BASELINE["oneDeployInvariant"],
                "healthPolicy": {"readyStatus": 200, "readyCode": "", "runtimeMarkerRequired": True},
                "deploymentBundle": box._worm_descriptor(bundle), "consumedMarker": box._worm_descriptor(consumed),
            }),
            "*",
        )
        counters = (registry.counter, packages.counter)
        historical = box.BOOTSTRAP_BASELINE["oneDeployInvariant"]
        proof = {
            "schemaVersion": 1, "phase": "candidate", "sourceSha": request["sourceSha"],
            "runtimeRelease": {"status": 200, "value": request["sourceSha"], "bodySha256": "1" * 64},
            "index": {"status": 200, "sha256": "8" * 64, "size": 1},
            "oneDeployInvariant": {**historical, "historicalActiveDeployment": {"id": historical["historicalActiveDeploymentId"], "status": 4, "complete": True, "deployer": "OneDeploy"}},
            "live": {"status": 200, "bodySha256": "2" * 64, "ok": True, "code": ""},
            "ready": {"status": 200, "bodySha256": "3" * 64, "ok": True, "code": ""},
            "appHealth": {"status": 200, "bodySha256": "4" * 64, "ok": True, "code": ""},
            "securityInfo": {"status": 200, "bodySha256": "5" * 64, "ok": True, "code": ""},
            "observedAt": "2026-08-29T00:00:00.000Z",
        }

        class Production:
            def observe(self, profile):
                events.append("observe")
                self.profile = profile
                return {"sourceSha": request["sourceSha"], "healthy": True, "proof": proof}

            def __getattr__(self, name):
                raise AssertionError("preflight attempted production mutation: " + name)

        class Forbidden:
            def __getattr__(self, name):
                raise AssertionError("preflight attempted activation-fence access: " + name)

        arm = Arm(request, events)
        key = activation.provisioning_evidence["keyVaultBoundary"]["keyDataPlaneProjection"]
        name = f"pdreq-{request['sourceRunId']}-{request['sourceRunAttempt']}-{request['nonce']}"
        envelope = bridge.process_request(
            name, activation=activation, now=NOW, arm_mailbox=arm, transient_control={},
            registry_worm=registry, package_worm=packages, activation_fence=Forbidden(),
            production_activation=Production(), key_reader=lambda: (events.append("key") or key),
            artifact_reader=lambda _: (_ for _ in ()).throw(AssertionError("artifact read")),
            signer=lambda raw, **kwargs: "AA", signing_key_id=activation.signing_key_id,
            signing_key_version=activation.signing_key_version, webjob_history_id="history-1",
            webjob_run_id="run-1",
        )
        self.assertEqual(events, ["key", "mailbox", "observe", "result"])
        self.assertEqual((registry.counter, packages.counter), counters)
        self.assertEqual(envelope["result"]["records"]["acceptedBaseline"], box._worm_descriptor(manifest))
        self.assertIsNone(envelope["result"]["records"]["pendingRelease"])
        self.assertIsNone(envelope["result"]["records"]["consumedMarker"])


if __name__ == "__main__":
    unittest.main()
