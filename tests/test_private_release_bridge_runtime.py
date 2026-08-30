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
        "schemaVersion": 1, "requestType": "paperdesk-private-release-request",
        "operation": "bootstrap-prepare", "repositoryId": box.BOOTSTRAP_BASELINE["repositoryId"],
        "ownerId": box.BOOTSTRAP_BASELINE["ownerId"], "controlWorkflowSha": fixture.WORKFLOW_SHA,
        "sourceSha": box.BOOTSTRAP_BASELINE["sourceSha"], "sourceRunId": box.BOOTSTRAP_BASELINE["sourceRunId"],
        "sourceRunAttempt": box.BOOTSTRAP_BASELINE["sourceRunAttempt"], "artifactId": box.BOOTSTRAP_BASELINE["artifactId"],
        "artifactSha256": box.BOOTSTRAP_BASELINE["artifactSha256"], "artifactMember": box.BOOTSTRAP_BASELINE["artifactMember"],
        "artifactMemberSha256": hashlib.sha256(payload).hexdigest(), "acceptanceRunId": "5", "acceptanceRunAttempt": "1",
        "logicalOperationId": None, "nonce": "d" * 32, "issuedAt": "2026-08-29T00:00:00.000Z",
        "expiresAt": "2026-08-29T00:15:00.000Z", "acceptedBaseline": None, "pendingRelease": None,
        "consumedMarker": None, "rollbackPreparation": None, "activationPlan": None, "activationProof": None,
    }
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
    def _run(self, *, bad_key=False, request_name=None):
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

            envelope = bridge.process_request(
                request_name or f"pdreq-{request['sourceRunId']}-{request['sourceRunAttempt']}-{request['nonce']}",
                activation=activation, now=NOW, arm_mailbox=arm, transient_control={},
                registry_worm=Worm(), package_worm=Worm(), activation_fence=object(),
                production_activation=object(), key_reader=key_reader, artifact_reader=artifact_reader,
                signer=lambda raw, **kwargs: (signing.append(kwargs) or "AA"),
                signing_key_id=activation.signing_key_id, signing_key_version=activation.signing_key_version,
                webjob_history_id="history-1", webjob_run_id="run-1")
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

    def test_wrong_mailbox_coordinate_stops_before_artifact(self):
        with self.assertRaisesRegex(box.MailboxError, "bridge-request-coordinate"):
            self._run(request_name="pdreq-4-1-" + "d" * 32)


if __name__ == "__main__":
    unittest.main()
