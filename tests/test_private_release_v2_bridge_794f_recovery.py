import json
import datetime as dt
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from scripts import private_release_v2_bridge_794f_recovery as recovery


class FakeSession:
    def __init__(self):
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return SimpleNamespace(status=200, body=b"{}", headers={})


class StatefulAzure:
    def __init__(self):
        self.state = "Running"
        self.public = "Enabled"
        self.scm = True
        self.settings = {key: "fixture" for key in recovery.SETTING_KEYS}
        self.mutations = []

    def account(self):
        return {
            "cloud": "AzureCloud", "subscriptionId": recovery.SUBSCRIPTION,
            "tenantId": recovery.TENANT, "accountId": recovery.ACCOUNT,
            "accountObjectId": recovery.ACCOUNT_OBJECT, "accountType": "user",
        }

    def request(self, method, url, *, body=None, headers=None, deadline=None):
        if method == "GET" and url == recovery.SITE:
            value = {
                "id": recovery.SITE_ID, "kind": "app,linux",
                "identity": {
                    "type": "UserAssigned",
                    "userAssignedIdentities": {identity: {} for identity in recovery.UAMI_IDS},
                },
                "properties": {
                    "state": self.state, "publicNetworkAccess": self.public,
                    "enabled": True, "httpsOnly": True,
                    "serverFarmId": recovery.PLAN_ID,
                    "virtualNetworkSubnetId": recovery.SUBNET_ID,
                    "outboundVnetRouting": {"allTraffic": True, "applicationTraffic": True},
                    "siteConfig": {"webJobsEnabled": True},
                },
            }
        elif method == "GET" and url == recovery.SCM:
            value = {
                "id": recovery.SITE_ID + "/basicPublishingCredentialsPolicies/scm",
                "properties": {"allow": self.scm},
            }
        elif method == "POST" and url == recovery.SETTINGS_LIST:
            value = {"properties": self.settings}
        else:
            self.mutations.append((method, url))
            if (method, url) == ("POST", recovery.STOP):
                self.state = "Stopped"
            elif (method, url) == ("PUT", recovery.SCM):
                self.scm = False
                self.state = "Running"
            elif (method, url) == ("PATCH", recovery.SITE):
                self.public = "Disabled"
                self.state = "Running"
            elif (method, url) == ("PUT", recovery.SETTINGS):
                self.settings = {}
                self.state = "Running"
            else:
                raise AssertionError("unexpected Azure request")
            value = {}
        return SimpleNamespace(
            status=200,
            body=recovery.bootstrap.canonical_json_bytes(value),
            headers={},
        )


class RecoveryBoundaryTests(unittest.TestCase):
    def test_observation_cannot_issue_any_mutation(self):
        inner = FakeSession()
        session = recovery.BoundSession(inner, False)
        with self.assertRaises(recovery.RecoveryError):
            session.request("PATCH", recovery.SITE, recovery.PUBLIC_BODY)
        self.assertEqual(inner.calls, [])

    def test_exact_mutation_body_and_single_attempt(self):
        inner = FakeSession()
        session = recovery.BoundSession(inner, True)
        with self.assertRaises(recovery.RecoveryError):
            session.request("PATCH", recovery.SITE, b'{"properties":{"publicNetworkAccess":"Enabled"}}')
        session.request("PATCH", recovery.SITE, recovery.PUBLIC_BODY)
        with self.assertRaises(recovery.RecoveryError):
            session.request("PATCH", recovery.SITE, recovery.PUBLIC_BODY)
        self.assertEqual(len(inner.calls), 1)

    def test_stop_budget_is_bounded_and_unrelated_site_is_rejected(self):
        inner = FakeSession()
        session = recovery.BoundSession(inner, True)
        for _ in range(4):
            session.request("POST", recovery.STOP, recovery.STOP_BODY)
        with self.assertRaises(recovery.RecoveryError):
            session.request("POST", recovery.STOP, recovery.STOP_BODY)
        with self.assertRaises(recovery.RecoveryError):
            session.request("POST", recovery.STOP.replace("bridge-v2", "other"), recovery.STOP_BODY)
        self.assertEqual(len(inner.calls), 4)

    def test_public_async_url_must_be_subscription_bound(self):
        inner = FakeSession()
        session = recovery.BoundSession(inner, False)
        response = SimpleNamespace(
            status=202,
            headers={"Azure-AsyncOperation": "https://evil.example/subscriptions/other?x=1"},
        )
        with self.assertRaises(recovery.RecoveryError):
            recovery.await_result(session, response, "public disable")
        self.assertEqual(inner.calls, [])

    def test_settings_digest_uses_canonical_newline(self):
        self.assertEqual(
            recovery.sha(recovery.bootstrap.canonical_json_bytes({})),
            recovery.EMPTY_SETTINGS_SHA,
        )
        self.assertEqual(json.loads(recovery.EMPTY_SETTINGS_BODY), {"properties": {}})

    def test_prepare_rejects_a_nonmatching_user_confirmation(self):
        source = {"commitSha": "a" * 40, "treeSha": "b" * 40, "executorSha256": "c" * 64}
        identifier = "34716470-903c-4d8b-b01a-45852c70eb27"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            template = root / "template.json"
            recovery.write_new(template, {
                "schemaVersion": 1, "recoveryAuthorizationId": identifier,
                "preflightSha256": "d" * 64, "source": source,
                "expiresAt": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=20)).isoformat(),
                "exactConfirmationText": recovery.phrase(identifier, "d" * 64, source["commitSha"]),
                "executable": False,
            })
            confirmation = root / "confirmation.txt"
            confirmation.write_text("I approve something else", encoding="utf-8")
            output = root / "authorization.json"
            with mock.patch.object(recovery, "source", return_value=source):
                with self.assertRaises(recovery.RecoveryError):
                    recovery.prepare(template, confirmation, output)
            self.assertFalse(output.exists())

    def test_recovery_stops_after_each_restart_and_archives_only_after_empty_readback(self):
        azure = StatefulAzure()
        settings_sha = recovery.sha(recovery.bootstrap.canonical_json_bytes(azure.settings))
        source = {"commitSha": "a" * 40, "treeSha": "b" * 40, "executorSha256": "c" * 64}
        incident = {"authorizationId": recovery.INCIDENT, "sourceSha": recovery.SOURCE_SHA, "markerSha256": "d" * 64}
        now = dt.datetime.now(dt.timezone.utc)
        identifier = "34716470-903c-4d8b-b01a-45852c70eb27"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            incident_dir = root / "incident"
            incident_dir.mkdir()
            marker = incident_dir / "unresolved-public-network-enable.json"
            recovery.write_new(marker, {"status": "unresolved-public-network-enable"})
            marker_sha = recovery.sha(marker.read_bytes())
            incident["markerSha256"] = marker_sha
            observed = {
                "site": {"state": "Running", "publicNetworkAccess": "Enabled", "httpsOnly": True, "identityCount": 5},
                "scmAllow": True, "settings": {"count": 5, "sha256": settings_sha},
            }
            preflight = {
                "schemaVersion": 1, "recoveryAuthorizationId": identifier,
                "observedAt": now.isoformat(),
                "expiresAt": (now + dt.timedelta(minutes=30)).isoformat(),
                "source": source, "incident": incident,
                "azure": azure.account(), "live": observed,
                "plan": recovery.RECOVERY_PLAN,
            }
            preflight_path = root / "preflight.json"
            recovery.write_new(preflight_path, preflight)
            preflight_sha = recovery.sha(preflight_path.read_bytes())
            with mock.patch.object(recovery, "SETTINGS_SHA", settings_sha):
                phrase = recovery.phrase(identifier, preflight_sha, source["commitSha"])
            authorization_path = root / "authorization.json"
            recovery.write_new(authorization_path, {
                "schemaVersion": 1, "recoveryAuthorizationId": identifier,
                "preflightSha256": preflight_sha, "source": source,
                "expiresAt": preflight["expiresAt"],
                "exactConfirmationText": phrase, "executable": True,
            })
            confirmation_path = root / "confirmation.txt"
            confirmation_path.write_text(phrase + "\n", encoding="utf-8")
            with (
                mock.patch.object(recovery, "CEREMONY", root),
                mock.patch.object(recovery, "INCIDENT_DIR", incident_dir),
                mock.patch.object(recovery, "MARKER", marker),
                mock.patch.object(recovery, "MARKER_SHA", marker_sha),
                mock.patch.object(recovery, "SETTINGS_SHA", settings_sha),
                mock.patch.object(recovery, "source", return_value=source),
                mock.patch.object(recovery, "incident", return_value=incident),
                mock.patch.object(recovery.bootstrap, "AzureCliRestSession", return_value=azure),
            ):
                result = recovery.apply(preflight_path, authorization_path, confirmation_path)
            self.assertEqual(result["status"], "recovered")
            self.assertEqual(azure.state, "Stopped")
            self.assertEqual(azure.public, "Disabled")
            self.assertFalse(azure.scm)
            self.assertEqual(azure.settings, {})
            self.assertFalse(marker.exists())
            self.assertEqual(
                azure.mutations,
                [
                    ("POST", recovery.STOP), ("PUT", recovery.SCM),
                    ("POST", recovery.STOP), ("PATCH", recovery.SITE),
                    ("POST", recovery.STOP), ("PUT", recovery.SETTINGS),
                    ("POST", recovery.STOP),
                ],
            )


if __name__ == "__main__":
    unittest.main()
