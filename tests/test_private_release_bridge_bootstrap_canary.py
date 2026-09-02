import datetime as dt
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest import mock

from provider import private_release_bridge_azure as azure
from provider import private_release_bridge_entry as entry
from scripts import private_release_mailbox as core


LEASE_ID = entry.BOOTSTRAP_FENCE_LEASE_ID
ETAG = '"fence-etag"'
VERSION = "2026-08-30T00:00:00.0000000Z"
BODY_SHA = core.digest(core.canonical(azure.BlobActivationFence.INITIAL_IDLE))
CLIENT_ID = "11111111-1111-4111-8111-111111111111"
PRINCIPAL_ID = "22222222-2222-4222-8222-222222222222"


class Tokens:
    def get(self, resource):
        if resource != azure.STORAGE:
            raise AssertionError(resource)
        return "token"


class Clock:
    def __init__(self):
        self.count = 0

    def __call__(self):
        self.count += 1
        return dt.datetime(2026, 8, 30, tzinfo=dt.timezone.utc) + dt.timedelta(
            seconds=self.count
        )


class FenceService:
    def __init__(self, *, drift_first_get=False, renew_status=200):
        self.lease = None
        self.calls = []
        self.drift_first_get = drift_first_get
        self.renew_status = renew_status
        self.get_count = 0

    @staticmethod
    def _response(status, body=b"", **headers):
        return core.Response(
            status,
            "",
            body,
            {
                "ETag": ETAG,
                "x-ms-version-id": VERSION,
                "x-ms-meta-sha256": core.digest(body),
                **headers,
            },
        )

    def __call__(self, method, url, headers, body):
        action = headers.get("x-ms-lease-action")
        self.calls.append((method, url, dict(headers), body))
        if url.endswith("?comp=lease") and action == "acquire":
            self.assertEqualHeader(headers, "x-ms-proposed-lease-id", LEASE_ID)
            self.assertEqualHeader(headers, "x-ms-lease-duration", "60")
            if self.lease is not None:
                return self._response(409)
            self.lease = LEASE_ID
            return self._response(201)
        if url.endswith("?comp=lease") and action == "renew":
            self.assertEqualHeader(headers, "x-ms-lease-id", self.lease)
            return self._response(self.renew_status)
        if url.endswith("?comp=lease") and action == "release":
            self.assertEqualHeader(headers, "x-ms-lease-id", self.lease)
            self.lease = None
            return self._response(200)
        if method == "HEAD":
            return self._response(
                200,
                **{
                    "x-ms-lease-state": "available" if self.lease is None else "leased",
                    "x-ms-lease-status": "unlocked" if self.lease is None else "locked",
                },
            )
        if method == "GET":
            if headers.get("x-ms-lease-id") is not None and headers["x-ms-lease-id"] != self.lease:
                return self._response(412)
            self.get_count += 1
            state = dict(azure.BlobActivationFence.INITIAL_IDLE)
            if self.drift_first_get and self.get_count == 1:
                state["stateVersion"] = 1
            return self._response(200, core.canonical(state))
        raise AssertionError((method, url, headers, body))

    @staticmethod
    def assertEqualHeader(headers, key, expected):
        if headers.get(key) != expected:
            raise AssertionError((key, headers.get(key), expected))


class Tests(unittest.TestCase):
    def fence(self, service):
        return azure.BlobActivationFence(
            core.FIXED_COORDS["packageAccount"],
            core.FIXED_COORDS["activationFenceContainer"],
            core.FIXED_COORDS["activationFenceBlob"],
            Tokens(),
            service,
            clock=Clock(),
        )

    def run_canary(self, service):
        return self.fence(service).bootstrap_canary(
            lease_id=LEASE_ID,
            duration_seconds=60,
            renewal_count=1,
            expected_etag=ETAG,
            expected_version_id=VERSION,
            expected_body_sha256=BODY_SHA,
            deadline="2026-08-30T00:15:00.000Z",
        )

    def test_canary_uses_one_finite_lease_without_writing_fence_state(self):
        service = FenceService()
        proof = self.run_canary(service)
        lease_actions = [
            call[2].get("x-ms-lease-action")
            for call in service.calls
            if call[1].endswith("?comp=lease")
        ]
        self.assertEqual(lease_actions, ["acquire", "renew", "release"])
        self.assertFalse(
            any(call[0] == "PUT" and not call[1].endswith("?comp=lease") for call in service.calls)
        )
        self.assertEqual(proof["leaseId"], LEASE_ID)
        self.assertEqual(proof["leaseDurationSeconds"], 60)
        self.assertEqual(proof["renewalCount"], 1)
        self.assertEqual(proof["acquireHttpStatus"], 201)
        self.assertEqual(proof["renewHttpStatus"], 200)
        self.assertEqual(proof["releaseHttpStatus"], 200)
        self.assertEqual(proof["finalLeaseState"], "Available")
        self.assertEqual(proof["finalLeaseStatus"], "Unlocked")
        self.assertEqual(proof["finalReadbackBodySha256"], BODY_SHA)
        self.assertIsNone(service.lease)

    def test_idle_drift_fails_but_releases_and_proves_available(self):
        service = FenceService(drift_first_get=True)
        with self.assertRaisesRegex(core.MailboxError, "fence-canary-idle-drift"):
            self.run_canary(service)
        self.assertIsNone(service.lease)
        self.assertIn("release", [call[2].get("x-ms-lease-action") for call in service.calls])
        self.assertEqual([call[0] for call in service.calls][-2:], ["HEAD", "GET"])

    def test_renew_failure_still_releases_and_reads_back(self):
        service = FenceService(renew_status=412)
        with self.assertRaisesRegex(core.MailboxError, "fence-canary-renew"):
            self.run_canary(service)
        self.assertIsNone(service.lease)
        self.assertEqual(
            [call[2].get("x-ms-lease-action") for call in service.calls if call[1].endswith("?comp=lease")],
            ["acquire", "renew", "release"],
        )
        self.assertEqual([call[0] for call in service.calls][-2:], ["HEAD", "GET"])

    @staticmethod
    def control():
        now = dt.datetime.now(dt.timezone.utc)
        issued = now - dt.timedelta(seconds=1)
        expires = now + dt.timedelta(minutes=5)
        stamp = lambda value: value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"
        return {
            "schemaVersion": 1,
            "mode": "package-fetch-self-test",
            "authorizationId": "33333333-3333-4333-8333-333333333333",
            "authorizationSha256": "e" * 64,
            "siteName": core.FIXED_COORDS["bridgeApp"],
            "packageSha256": "a" * 64,
            "nonce": "b" * 32,
            "issuedAt": stamp(issued),
            "expiresAt": stamp(expires),
            "planSha256": "c" * 64,
            "bridgePackageSourceSha": "d" * 40,
            "tenantId": entry.BOOTSTRAP_TENANT_ID,
            "bridgeIdentityResourceId": entry.BOOTSTRAP_BRIDGE_IDENTITY_RESOURCE_ID,
            "bridgeClientId": CLIENT_ID,
            "bridgePrincipalId": PRINCIPAL_ID,
            "activationFenceAccount": core.FIXED_COORDS["packageAccount"],
            "activationFenceContainer": core.FIXED_COORDS["activationFenceContainer"],
            "activationFenceBlob": core.FIXED_COORDS["activationFenceBlob"],
            "activationFenceEtag": ETAG,
            "activationFenceVersionId": VERSION,
            "activationFenceBodySha256": BODY_SHA,
            "activationFenceLeaseId": LEASE_ID,
            "leaseDurationSeconds": 60,
            "leaseRenewalCount": 1,
        }

    def test_entry_constructs_only_bridge_identity_and_fence_clients(self):
        control = self.control()
        raw = core.canonical(control).decode()
        token_instances = []
        fence_instances = []

        class Identity:
            def __init__(self, **kwargs):
                token_instances.append(kwargs)

            def identity_projection(self, resource):
                self_resource = resource
                if self_resource != azure.STORAGE:
                    raise AssertionError(resource)
                return {
                    "clientId": CLIENT_ID,
                    "principalId": PRINCIPAL_ID,
                    "tenantId": entry.BOOTSTRAP_TENANT_ID,
                    "audience": azure.STORAGE,
                }

        class Fence:
            INITIAL_IDLE = azure.BlobActivationFence.INITIAL_IDLE

            def __init__(self, *args):
                fence_instances.append(args)

            def bootstrap_canary(self, **kwargs):
                self_kwargs = kwargs
                self_outer.assertEqual(self_kwargs["lease_id"], LEASE_ID)
                return {
                    "completedAt": "2026-08-30T00:00:04.000Z",
                    "acquiredAt": "2026-08-30T00:00:01.000Z",
                    "renewedAt": "2026-08-30T00:00:02.000Z",
                    "releasedAt": "2026-08-30T00:00:03.000Z",
                }

        self_outer = self
        env = {
            "WEBSITE_SITE_NAME": core.FIXED_COORDS["bridgeApp"],
            "PAPERDESK_BRIDGE_PACKAGE_SHA256": control["packageSha256"],
            "IDENTITY_ENDPOINT": "http://127.0.0.1/MSI/token",
            "IDENTITY_HEADER": "header",
        }
        forbidden = (
            "ArmTransport",
            "BlobWorm",
            "GitHubArtifactReader",
            "ProductionActivation",
            "KeyVaultKeyReader",
            "KeyVaultSigner",
        )
        patches = [mock.patch.object(entry.azure, name, side_effect=AssertionError(name)) for name in forbidden]
        with mock.patch.dict(entry.os.environ, env, clear=True), mock.patch.object(
            entry.azure, "ManagedIdentityTokens", Identity
        ), mock.patch.object(entry.azure, "BlobActivationFence", Fence):
            for patch in patches:
                patch.start()
            try:
                output = io.StringIO()
                with redirect_stdout(output):
                    marker = entry.run_bootstrap_self_test(raw)
            finally:
                for patch in reversed(patches):
                    patch.stop()
        self.assertEqual(len(token_instances), 1)
        self.assertEqual(len(fence_instances), 1)
        self.assertEqual(marker["control"], control)
        self.assertEqual(marker["control"]["authorizationId"], control["authorizationId"])
        self.assertEqual(
            marker["control"]["authorizationSha256"], control["authorizationSha256"]
        )
        self.assertEqual(marker["bridgeIdentity"]["clientId"], CLIENT_ID)
        self.assertEqual(marker["bridgeIdentity"]["principalId"], PRINCIPAL_ID)
        self.assertEqual(marker["packageExecution"]["sourceSha"], control["bridgePackageSourceSha"])
        self.assertEqual(json.loads(output.getvalue()), marker)

    def test_entry_rejects_non_exact_control_before_client_construction(self):
        control = self.control()
        control["activationFenceLeaseId"] = "99999999-9999-4999-8999-999999999999"
        with mock.patch.dict(
            entry.os.environ,
            {
                "WEBSITE_SITE_NAME": core.FIXED_COORDS["bridgeApp"],
                "PAPERDESK_BRIDGE_PACKAGE_SHA256": control["packageSha256"],
            },
            clear=True,
        ), mock.patch.object(
            entry.azure, "ManagedIdentityTokens", side_effect=AssertionError("constructed")
        ):
            with self.assertRaisesRegex(core.MailboxError, "entry-bootstrap-self-test"):
                entry.run_bootstrap_self_test(core.canonical(control).decode())

    def test_entry_rejects_unbound_authorization_before_client_construction(self):
        for field, value in (
            ("authorizationId", "not-an-authorization-id"),
            ("authorizationSha256", "0" * 63),
        ):
            with self.subTest(field=field):
                control = self.control()
                control[field] = value
                with mock.patch.dict(
                    entry.os.environ,
                    {
                        "WEBSITE_SITE_NAME": core.FIXED_COORDS["bridgeApp"],
                        "PAPERDESK_BRIDGE_PACKAGE_SHA256": control["packageSha256"],
                    },
                    clear=True,
                ), mock.patch.object(
                    entry.azure,
                    "ManagedIdentityTokens",
                    side_effect=AssertionError("constructed"),
                ):
                    with self.assertRaisesRegex(
                        core.MailboxError, "entry-bootstrap-self-test"
                    ):
                        entry.run_bootstrap_self_test(core.canonical(control).decode())


if __name__ == "__main__":
    unittest.main()
