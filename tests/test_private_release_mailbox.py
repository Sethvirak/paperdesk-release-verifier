import datetime as dt
import hashlib
import io
import json
import tarfile
import unittest
from pathlib import Path

from scripts import private_release_mailbox as box
from tests import private_release_v2_fixture as fixture


NOW = dt.datetime(2026, 8, 29, tzinfo=dt.timezone.utc)
SHA = "a" * 40


def descriptor(blob="v2/accepted/" + SHA + "/x/manifest.json", sha="1" * 64):
    return {"blob": blob, "sha256": sha, "size": 1, "etag": '"e"', "versionId": "v1"}


def request(operation="prepare-candidate"):
    return {
        "schemaVersion": 1, "requestType": "paperdesk-private-release-request", "operation": operation,
        "repositoryId": "1", "ownerId": "2", "controlWorkflowSha": fixture.WORKFLOW_SHA,
        "sourceSha": SHA, "sourceRunId": "3", "sourceRunAttempt": "1", "artifactId": "4",
        "artifactSha256": "c" * 64, "artifactMember": "runtime.tar.gz", "artifactMemberSha256": "d" * 64,
        "acceptanceRunId": "5", "acceptanceRunAttempt": "1", "logicalOperationId": None,
        "nonce": "e" * 32, "issuedAt": "2026-08-29T00:00:00.000Z", "expiresAt": "2026-08-29T00:15:00.000Z",
        "acceptedBaseline": descriptor(), "pendingRelease": None, "consumedMarker": None,
        "rollbackPreparation": None, "activationPlan": None, "activationProof": None,
    }


def archive(index=b"<html>ok</html>"):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as target:
        for name, body in (("index.html", index), ("server/app.js", b"ok")):
            info = tarfile.TarInfo(name)
            info.size = len(body)
            target.addfile(info, io.BytesIO(body))
    return output.getvalue()


def activation_fence(release, pre="2" * 64, desired="3" * 64):
    return {"blob": box.FIXED_COORDS["activationFenceBlob"], "leaseId": "22222222-2222-4222-8222-222222222222", "stateVersion": "1", "release": release, "preSettingsSha256": pre, "desiredSettingsSha256": desired, "etag": '"f"', "operation": "candidate", "sourceSha": SHA}


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


class Tests(unittest.TestCase):
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

    def test_activated_fixture_and_live_key_expiry_are_exact(self):
        activation = fixture.activation()
        projection = activation.provisioning_evidence["keyVaultBoundary"]["keyDataPlaneProjection"]
        self.assertEqual(box.validate_live_signing_key(projection, activation, now=NOW), projection)
        late = dt.datetime.fromtimestamp(fixture.KEY_EXPIRES - box.KEY_RECOVERY_HORIZON_SECONDS + 1, tz=dt.timezone.utc)
        with self.assertRaisesRegex(box.MailboxError, "live-key-expiry"):
            box.validate_live_signing_key(projection, activation, now=late)

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
