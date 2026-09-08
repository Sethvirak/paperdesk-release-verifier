import datetime as dt
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from scripts import private_release_v2_bootstrap as bootstrap
from scripts import private_release_v2_bridge_settings_recovery as recovery


NOW = dt.datetime(2026, 9, 8, 10, 0, tzinfo=dt.timezone.utc)
ACCOUNT = {
    "cloud": "AzureCloud",
    "subscriptionId": recovery.SUBSCRIPTION,
    "tenantId": recovery.TENANT,
    "accountId": recovery.ACCOUNT_ID,
    "accountObjectId": recovery.ACCOUNT_OBJECT_ID,
    "accountType": "user",
}
AUTHORIZATION = {
    "authorizationId": recovery.INCIDENT_AUTHORIZATION_ID,
    "azure": dict(ACCOUNT),
    "plan": {
        "bridgePackageSha256": "5ca95116ec8267594d40806b40aca91b1cd1801109e6cd5021d8742a25a667e3",
        "sha256": "dfb157e70d85361e19e8e64b8d80f35c3ed97f9f0de6e0e30a5b885e4bca6fb8",
        "bridgePackageSourceSha": "c7a3d37f2e630503153ff468b132e66fc38b4a32",
    },
    "source": {
        "mergedMain": {"commitSha": "c7a3d37f2e630503153ff468b132e66fc38b4a32"}
    },
}
INCIDENT = {
    "authorization": AUTHORIZATION,
    "authorizationSha256": recovery.INCIDENT_AUTHORIZATION_SHA256,
    "terminalSha256": recovery.INCIDENT_TERMINAL_SHA256,
    "packageVersionId": "2026-09-08T09:19:07.6399776Z",
    "fenceEtag": '"0x8DF0D8A624E66BD"',
    "fenceVersionId": "2026-09-08T09:20:11.5852989Z",
    "fenceBodySha256": "e702656b5000a83cfc389f74196e49fee03184d78f9cf007bd1b7a477406b40f",
    "attemptedRequestSha256": recovery.ATTEMPTED_REQUEST_SHA256,
}
IDENTITY = {
    "id": recovery.BRIDGE_IDENTITY_ID,
    "properties": {
        "clientId": "22222222-2222-4222-8222-222222222222",
        "principalId": "33333333-3333-4333-8333-333333333333",
    },
}


def settings_fixture():
    control = bootstrap._bootstrap_self_test_static_control(AUTHORIZATION)
    control.update(
        {
            "authorizationSha256": recovery.INCIDENT_AUTHORIZATION_SHA256,
            "bridgeIdentityResourceId": IDENTITY["id"],
            "bridgeClientId": IDENTITY["properties"]["clientId"],
            "bridgePrincipalId": IDENTITY["properties"]["principalId"],
            "activationFenceEtag": INCIDENT["fenceEtag"],
            "activationFenceVersionId": INCIDENT["fenceVersionId"],
            "activationFenceBodySha256": INCIDENT["fenceBodySha256"],
            "issuedAt": "2026-09-08T09:20:19.724Z",
            "expiresAt": "2026-09-08T09:35:19.724Z",
        }
    )
    raw_control = bootstrap.canonical_app_setting_json(control)
    settings = {
        "WEBSITE_RUN_FROM_PACKAGE": (
            "https://mdspdbak2608089c4e.blob.core.windows.net/"
            "paperdesk-deployment-packages/v2/control/"
            "c7a3d37f2e630503153ff468b132e66fc38b4a32/"
            "paperdesk-private-release-bridge.zip?versionid="
            "2026-09-08T09%3A19%3A07.6399776Z"
        ),
        "WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID": (
            f"/subscriptions/{recovery.SUBSCRIPTION}/resourceGroups/"
            "rg-master-data-structure-sea/providers/Microsoft.ManagedIdentity/"
            "userAssignedIdentities/uami-paperdesk-accepted-release-reader"
        ),
        "WEBSITE_SKIP_RUNNING_KUDUAGENT": "false",
        "PAPERDESK_BRIDGE_PACKAGE_SHA256": AUTHORIZATION["plan"]["bridgePackageSha256"],
        "PAPERDESK_BRIDGE_BOOTSTRAP_SELF_TEST_JSON": raw_control,
    }
    digests = {
        "NORMALIZED_CONTROL_SHA256": hashlib.sha256(raw_control.encode()).hexdigest(),
        "ATTEMPTED_CONTROL_SHA256": hashlib.sha256(
            bootstrap.canonical_json_bytes(control)
        ).hexdigest(),
        "NORMALIZED_MAP_SHA256": recovery.digest(settings),
        "NORMALIZED_WRAPPER_SHA256": recovery.digest({"properties": settings}),
    }
    return settings, digests


class FakeSession:
    def __init__(self, settings, *, put_status=200, apply_put=True):
        self.settings = dict(settings)
        self.put_count = 0
        self.put_status = put_status
        self.apply_put = apply_put

    def account(self):
        return dict(ACCOUNT)

    @staticmethod
    def response(status, value):
        return SimpleNamespace(
            status=status,
            body=json.dumps(value, sort_keys=True, separators=(",", ":")).encode(),
            headers={},
        )

    def request(self, method, url, *, body=None, headers=None, deadline=None):
        if method == "PUT":
            self.put_count += 1
            if url != recovery.APP_SETTINGS_URL or body != recovery.EMPTY_REQUEST:
                raise AssertionError("unexpected recovery mutation")
            if self.apply_put:
                self.settings = {}
            return self.response(self.put_status, {"properties": dict(self.settings)})
        if url == recovery.APP_SETTINGS_LIST_URL:
            return self.response(200, {"properties": dict(self.settings)})
        if url == recovery.SITE_URL:
            return self.response(
                200,
                {
                    "id": recovery.SITE_ID,
                    "kind": "app,linux",
                    "properties": {
                        "state": "Stopped",
                        "enabled": True,
                        "httpsOnly": True,
                        "publicNetworkAccess": "Disabled",
                    },
                    "identity": {
                        "type": "UserAssigned",
                        "userAssignedIdentities": {
                            value: {} for value in recovery.EXPECTED_UAMIS
                        },
                    },
                },
            )
        if url == recovery.STORAGE_URL:
            return self.response(
                200,
                {
                    "id": recovery.STORAGE_ID,
                    "type": "Microsoft.Storage/storageAccounts",
                    "properties": {
                        "networkAcls": {
                            "bypass": "None",
                            "defaultAction": "Deny",
                            "ipRules": [],
                            "ipv6Rules": [],
                            "virtualNetworkRules": [
                                {
                                    "action": "Allow",
                                    "id": recovery.EXPECTED_VNET_RULE,
                                    "state": "Succeeded",
                                }
                            ],
                        }
                    },
                },
            )
        if url == recovery.BRIDGE_IDENTITY_URL:
            return self.response(200, IDENTITY)
        if "/roleAssignments/" in url or recovery.TEMP_KEY_DEFINITION_ID in url:
            code = (
                "RoleDefinitionDoesNotExist"
                if recovery.TEMP_KEY_DEFINITION_ID in url
                else "RoleAssignmentNotFound"
            )
            return self.response(404, {"error": {"code": code, "message": "absent"}})
        for resource_id, notes in recovery.LOCKS.values():
            if resource_id in url:
                return self.response(
                    200,
                    {
                        "id": resource_id,
                        "name": resource_id.rsplit("/", 1)[-1],
                        "type": "Microsoft.Authorization/locks",
                        "properties": {
                            "level": "CanNotDelete", "notes": notes, "owners": []
                        },
                    },
                )
        raise AssertionError((method, url))


class BridgeSettingsRecoveryTests(unittest.TestCase):
    def patches(self, digests):
        return mock.patch.multiple(recovery, **digests)

    @staticmethod
    def write_confirmation(observation, artifact, confirmed_at=NOW):
        preflight, _ = recovery.load_json(observation / "recovery-preflight.json")
        phrase = (observation / "confirmation-request.txt").read_text(encoding="utf-8")
        recovery.write_new(
            artifact,
            {
                "schemaVersion": 1,
                "type": "paperdesk-v2-bridge-settings-recovery-user-confirmation",
                "status": "USER_CONFIRMED_EXACT_PHRASE",
                "authorizationId": preflight["authorizationId"],
                "reviewCommitmentSha256": preflight["reviewCommitmentSha256"],
                "confirmationPhrase": phrase,
                "confirmationPhraseSha256": hashlib.sha256(phrase.encode()).hexdigest(),
                "confirmedAt": recovery.stamp(confirmed_at),
            },
        )

    def test_app_setting_json_removes_only_file_terminal_lf(self):
        self.assertEqual(bootstrap.canonical_json_bytes({"b": 2, "a": 1}), b'{"a":1,"b":2}\n')
        self.assertEqual(bootstrap.canonical_app_setting_json({"b": 2, "a": 1}), '{"a":1,"b":2}')

    def test_exact_normalized_incident_is_accepted_and_one_byte_drift_fails(self):
        settings, digests = settings_fixture()
        with self.patches(digests):
            projection = recovery.observe_safety(
                FakeSession(settings), INCIDENT, expect_empty=False
            )
            self.assertEqual(
                projection["settings"]["control"]["normalization"],
                "one-terminal-lf-removed-no-parsed-field-change",
            )
            changed = dict(settings)
            changed["WEBSITE_SKIP_RUNNING_KUDUAGENT"] = "False"
            with self.assertRaisesRegex(recovery.RecoveryError, "not the exact normalized"):
                recovery.observe_safety(FakeSession(changed), INCIDENT, expect_empty=False)

    def test_apply_issues_one_put_and_persists_exact_empty_readback(self):
        settings, digests = settings_fixture()
        session = FakeSession(settings)
        source = {
            "repository": recovery.REPOSITORY,
            "commitSha": "4" * 40,
            "treeSha": "5" * 40,
            "executorSha256": "6" * 64,
            "bootstrapSha256": "7" * 64,
            "bridgeEntrySha256": "8" * 64,
        }
        with self.patches(digests), mock.patch.object(
            recovery, "source_projection", return_value=source
        ), mock.patch.object(
            recovery, "incident_projection", return_value=INCIDENT
        ), tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            observation = root / "observation"
            receipt = root / "receipt"
            artifact = root / "confirmation.json"
            with mock.patch.object(
                recovery, "recovery_ledger_directory", return_value=receipt
            ), mock.patch.object(
                recovery, "confirmation_artifact_path", return_value=artifact
            ):
                recovery.observe(observation, session, NOW)
                self.write_confirmation(observation, artifact)
                bound = recovery.RecoveryBoundSession(session, allow_mutation=True)
                result = recovery.apply(
                    observation, bound, NOW + dt.timedelta(seconds=1)
                )
            self.assertEqual(result["status"], "complete")
            self.assertEqual(session.put_count, 1)
            self.assertEqual(session.settings, {})
            terminal, _ = recovery.load_json(receipt / "terminal.json")
            self.assertEqual(terminal["final"]["settings"]["state"], "empty-source-prestate")
            with mock.patch.object(
                recovery, "recovery_ledger_directory", return_value=receipt
            ), mock.patch.object(
                recovery, "confirmation_artifact_path", return_value=artifact
            ), self.assertRaisesRegex(recovery.RecoveryError, "already exists"):
                recovery.apply(observation, bound, NOW + dt.timedelta(seconds=2))
            self.assertEqual(session.put_count, 1)

    def test_request_boundary_rejects_every_unreviewed_mutation(self):
        settings, _ = settings_fixture()
        session = FakeSession(settings)
        bound = recovery.RecoveryBoundSession(session, allow_mutation=False)
        with self.assertRaisesRegex(recovery.RecoveryError, "allowlist"):
            bound.request("POST", recovery.SITE_URL)
        with self.assertRaisesRegex(recovery.RecoveryError, "exact boundary"):
            bound.request(
                "PUT", recovery.APP_SETTINGS_URL,
                body=bootstrap.canonical_json_bytes({"properties": {"x": "y"}}),
                headers={"Content-Type": "application/json"}, deadline=NOW,
            )
        self.assertEqual(session.put_count, 0)
        mutable = recovery.RecoveryBoundSession(session, allow_mutation=True)
        mutable.request(
            "PUT", recovery.APP_SETTINGS_URL, body=recovery.EMPTY_REQUEST,
            headers={"Content-Type": "application/json"}, deadline=NOW,
        )
        with self.assertRaisesRegex(recovery.RecoveryError, "exact boundary"):
            mutable.request(
                "PUT", recovery.APP_SETTINGS_URL, body=recovery.EMPTY_REQUEST,
                headers={"Content-Type": "application/json"}, deadline=NOW,
            )
        self.assertEqual(session.put_count, 1)

    def test_storage_normalizes_only_optional_empty_fields_and_rejects_drift(self):
        network = {
            "bypass": "None",
            "defaultAction": "Deny",
            "ipRules": [],
            "ipv6Rules": [],
            "virtualNetworkRules": [
                {
                    "action": "Allow",
                    "id": recovery.EXPECTED_VNET_RULE,
                    "state": "Succeeded",
                }
            ],
        }
        document = {
            "id": recovery.STORAGE_ID,
            "type": "Microsoft.Storage/storageAccounts",
            "properties": {"networkAcls": network},
        }
        projection = recovery.validate_storage(document)
        self.assertEqual(projection["networkAcls"]["resourceAccessRules"], [])
        drifted = json.loads(json.dumps(document))
        drifted["properties"]["networkAcls"]["resourceAccessRules"] = [
            {"resourceId": "/subscriptions/unreviewed", "tenantId": recovery.TENANT}
        ]
        with self.assertRaisesRegex(recovery.RecoveryError, "Storage recovery boundary"):
            recovery.validate_storage(drifted)

    def test_confirmation_request_is_not_an_executable_confirmation(self):
        settings, digests = settings_fixture()
        session = FakeSession(settings)
        source = {
            "repository": recovery.REPOSITORY, "commitSha": "4" * 40,
            "treeSha": "5" * 40, "executorSha256": "6" * 64,
            "bootstrapSha256": "7" * 64, "bridgeEntrySha256": "8" * 64,
        }
        with self.patches(digests), mock.patch.object(
            recovery, "source_projection", return_value=source
        ), mock.patch.object(
            recovery, "incident_projection", return_value=INCIDENT
        ), tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            observation, receipt, artifact = (
                root / "observation", root / "receipt", root / "confirmation.json"
            )
            with mock.patch.object(
                recovery, "recovery_ledger_directory", return_value=receipt
            ), mock.patch.object(
                recovery, "confirmation_artifact_path", return_value=artifact
            ):
                recovery.observe(observation, session, NOW)
                self.assertTrue((observation / "confirmation-request.txt").is_file())
                with self.assertRaisesRegex(recovery.RecoveryError, "not one regular JSON"):
                    recovery.apply(observation, session, NOW + dt.timedelta(seconds=1))
            self.assertFalse(receipt.exists())
            self.assertEqual(session.put_count, 0)

    def test_reviewed_times_cannot_be_rewritten_under_same_phrase(self):
        settings, digests = settings_fixture()
        session = FakeSession(settings)
        source = {
            "repository": recovery.REPOSITORY, "commitSha": "4" * 40,
            "treeSha": "5" * 40, "executorSha256": "6" * 64,
            "bootstrapSha256": "7" * 64, "bridgeEntrySha256": "8" * 64,
        }
        with self.patches(digests), mock.patch.object(
            recovery, "source_projection", return_value=source
        ), mock.patch.object(
            recovery, "incident_projection", return_value=INCIDENT
        ), tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            observation, receipt, artifact = (
                root / "observation", root / "receipt", root / "confirmation.json"
            )
            with mock.patch.object(
                recovery, "recovery_ledger_directory", return_value=receipt
            ), mock.patch.object(
                recovery, "confirmation_artifact_path", return_value=artifact
            ):
                recovery.observe(observation, session, NOW)
                preflight_path = observation / "recovery-preflight.json"
                template_path = observation / "authorization-template.json"
                preflight, _ = recovery.load_json(preflight_path)
                template, _ = recovery.load_json(template_path)
                preflight = dict(preflight)
                template = dict(template)
                preflight["observedAt"] = recovery.stamp(NOW + dt.timedelta(minutes=1))
                preflight["expiresAt"] = recovery.stamp(NOW + dt.timedelta(minutes=31))
                preflight["reviewCommitmentSha256"] = recovery.review_commitment(preflight)
                template["observedAt"] = preflight["observedAt"]
                template["expiresAt"] = preflight["expiresAt"]
                template["reviewCommitmentSha256"] = preflight["reviewCommitmentSha256"]
                template["preflightSha256"] = recovery.digest(preflight)
                preflight_path.write_bytes(bootstrap.canonical_json_bytes(preflight))
                template_path.write_bytes(bootstrap.canonical_json_bytes(template))
                with self.assertRaisesRegex(recovery.RecoveryError, "phrase binding"):
                    recovery.apply(
                        observation, session, NOW + dt.timedelta(minutes=1)
                    )
            self.assertFalse(receipt.exists())
            self.assertEqual(session.put_count, 0)

    def test_directory_barrier_failure_stops_before_put(self):
        settings, digests = settings_fixture()
        session = FakeSession(settings)
        source = {
            "repository": recovery.REPOSITORY, "commitSha": "4" * 40,
            "treeSha": "5" * 40, "executorSha256": "6" * 64,
            "bootstrapSha256": "7" * 64, "bridgeEntrySha256": "8" * 64,
        }
        with self.patches(digests), mock.patch.object(
            recovery, "source_projection", return_value=source
        ), mock.patch.object(
            recovery, "incident_projection", return_value=INCIDENT
        ), tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            observation, receipt, artifact = (
                root / "observation", root / "receipt", root / "confirmation.json"
            )
            with mock.patch.object(
                recovery, "recovery_ledger_directory", return_value=receipt
            ), mock.patch.object(
                recovery, "confirmation_artifact_path", return_value=artifact
            ):
                recovery.observe(observation, session, NOW)
                self.write_confirmation(observation, artifact)
                bound = recovery.RecoveryBoundSession(session, allow_mutation=True)
                with mock.patch.object(
                    bootstrap.UseLedger, "_fsync_directory",
                    side_effect=recovery.RecoveryError("barrier failed"),
                ), self.assertRaisesRegex(recovery.RecoveryError, "barrier failed"):
                    recovery.apply(
                        observation, bound, NOW + dt.timedelta(seconds=1)
                    )
            self.assertEqual(session.put_count, 0)

    def test_non_200_put_is_classified_without_retry(self):
        settings, digests = settings_fixture()
        session = FakeSession(settings, put_status=500, apply_put=False)
        source = {
            "repository": recovery.REPOSITORY, "commitSha": "4" * 40,
            "treeSha": "5" * 40, "executorSha256": "6" * 64,
            "bootstrapSha256": "7" * 64, "bridgeEntrySha256": "8" * 64,
        }
        with self.patches(digests), mock.patch.object(
            recovery, "source_projection", return_value=source
        ), mock.patch.object(
            recovery, "incident_projection", return_value=INCIDENT
        ), tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            observation, receipt, artifact = (
                root / "observation", root / "receipt", root / "confirmation.json"
            )
            with mock.patch.object(
                recovery, "recovery_ledger_directory", return_value=receipt
            ), mock.patch.object(
                recovery, "confirmation_artifact_path", return_value=artifact
            ):
                recovery.observe(observation, session, NOW)
                self.write_confirmation(observation, artifact)
                bound = recovery.RecoveryBoundSession(session, allow_mutation=True)
                with self.assertRaisesRegex(recovery.RecoveryError, "unresolved"):
                    recovery.apply(
                        observation, bound, NOW + dt.timedelta(seconds=1)
                    )
            terminal, _ = recovery.load_json(receipt / "terminal.json")
            self.assertEqual(terminal["status"], "unresolved-non-200-after-recovery-put")
            self.assertEqual(
                terminal["classification"]["settings"]["state"],
                "exact-azure-normalized-incident-map",
            )
            self.assertEqual(session.put_count, 1)

    def test_absence_requires_resource_specific_error_code(self):
        response = FakeSession.response(
            404, {"error": {"code": "NotFound", "message": "wrong"}}
        )
        with self.assertRaisesRegex(recovery.RecoveryError, "code is not exact"):
            recovery.require_absence(response, "RoleAssignmentNotFound", "assignment")

    def test_main_rebinds_rest_session_to_exact_observed_account(self):
        constructed = []
        observed_sessions = []

        class CliSession:
            def __init__(self, authorization):
                constructed.append(authorization)

            def account(self):
                return dict(ACCOUNT)

        def fake_observe(_directory, session, _now):
            observed_sessions.append(session)
            return {"status": "observed"}

        with tempfile.TemporaryDirectory() as folder, mock.patch.object(
            recovery.bootstrap, "AzureCliRestSession", CliSession
        ), mock.patch.object(
            recovery, "observe", side_effect=fake_observe
        ):
            code = recovery.main([
                "observe", "--output-directory", str(Path(folder) / "observation")
            ])
        self.assertEqual(code, 0)
        self.assertEqual(constructed, [{}, {"azure": ACCOUNT}])
        self.assertEqual(len(observed_sessions), 1)
        self.assertIs(observed_sessions[0].allow_mutation, False)


if __name__ == "__main__":
    unittest.main()
