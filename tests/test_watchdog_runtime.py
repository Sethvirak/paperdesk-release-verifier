import copy
from datetime import datetime, timezone
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from provider import runtime
from scripts import watchdog_contract


CONTROL_SHA = "4" * 40
NOW = datetime(2026, 8, 23, 1, 0, tzinfo=timezone.utc)


class FakeJWT:
    class PyJWTError(Exception):
        pass

    class PyJWK:
        @staticmethod
        def from_dict(_jwk, algorithm):
            if algorithm != "RS256":
                raise AssertionError("unexpected algorithm")
            return SimpleNamespace(key="public-key")

    def __init__(self, claims):
        self.claims = claims

    @staticmethod
    def get_unverified_header(_token):
        return {"alg": "RS256", "kid": "test-key"}

    def decode(self, *_args, **_kwargs):
        return dict(self.claims)


def active_machine():
    machine = copy.deepcopy(watchdog_contract.load_contract())
    machine["immutableExternalControl"]["mergedMutatingCommitSha"] = CONTROL_SHA
    return machine


def environment():
    subscription = "00000000-0000-4000-8000-000000000001"
    values = {
        "WEBSITE_SITE_NAME": "paperdesk-watchdog-state-9c4e0d0d",
        "PAPERDESK_WATCHDOG_AZURE_SUBSCRIPTION_ID": subscription,
        "PAPERDESK_WATCHDOG_ALLOWED_WORKFLOW_SHA": "1" * 40,
        "PAPERDESK_WATCHDOG_ALLOWED_BASELINE_WORKFLOW_SHA": "2" * 40,
        "PAPERDESK_WATCHDOG_ALLOWED_RECONCILIATION_WORKFLOW_SHA": "3" * 40,
        "PAPERDESK_WATCHDOG_CONTROL_WORKFLOW_SHA": CONTROL_SHA,
        "PAPERDESK_WATCHDOG_PACKAGE_SHA256": "5" * 64,
        "PAPERDESK_WATCHDOG_GITHUB_APP_ID": "12345",
        "PAPERDESK_WATCHDOG_GITHUB_APP_INSTALLATION_ID": "67890",
        "PAPERDESK_WATCHDOG_GITHUB_APP_PRIVATE_KEY_PEM": "x" * 512,
    }
    prefixes = ("STATE", "EVIDENCE_WRITER", "EVIDENCE_READER", "REGISTRY_READER", "POLICY_READER")
    for index, prefix in enumerate(prefixes, start=10):
        values[f"PAPERDESK_WATCHDOG_{prefix}_IDENTITY_CLIENT_ID"] = f"00000000-0000-4000-8000-{index:012d}"
        values[f"PAPERDESK_WATCHDOG_{prefix}_IDENTITY_PRINCIPAL_ID"] = f"00000000-0000-4000-8001-{index:012d}"
        values[f"PAPERDESK_WATCHDOG_{prefix}_ROLE_ASSIGNMENT_ID"] = f"00000000-0000-4000-8002-{index:012d}"
        values[f"PAPERDESK_WATCHDOG_{prefix}_ROLE_DEFINITION_ID"] = f"00000000-0000-4000-8003-{index:012d}"
        values[f"PAPERDESK_WATCHDOG_{prefix}_IDENTITY_RESOURCE_ID"] = (
            f"/subscriptions/{subscription}/resourceGroups/rg-paperdesk-rollback-sea-20260808/providers/"
            f"Microsoft.ManagedIdentity/userAssignedIdentities/paperdesk-{prefix.lower()}"
        )
    return values


class WatchdogRuntimeConfigTests(unittest.TestCase):
    def test_exact_five_distinct_identity_bindings_and_scopes(self):
        config = runtime.ProviderConfig.from_environment(environment(), active_machine())
        self.assertEqual(set(config.identity_bindings), {
            "state-read-write", "evidence-create-only", "evidence-read-only",
            "registry-read-only", "arm-policy-read-only",
        })
        self.assertEqual(len({value.client_id for value in config.identity_bindings.values()}), 5)
        self.assertTrue(config.identity_bindings["state-read-write"].scope.endswith(
            "/blobServices/default/containers/paperdesk-watchdog-state"
        ))
        self.assertTrue(config.identity_bindings["evidence-create-only"].scope.endswith(
            "/blobServices/default/containers/paperdesk-watchdog-evidence"
        ))
        self.assertTrue(config.identity_bindings["registry-read-only"].scope.endswith(
            "/blobServices/default/containers/paperdesk-accepted-releases"
        ))
        clients = runtime.build_identity_clients(config, environment())
        self.assertEqual(set(clients), set(config.identity_bindings))
        for role, (tokens, binding) in clients.items():
            self.assertEqual(tokens.client_id, binding.client_id, role)
        self.assertEqual(config.github_app_id, "12345")
        self.assertEqual(config.github_app_installation_id, "67890")
        self.assertEqual(config.github_app_private_key_pem, "x" * 512)

    def test_real_runtime_remains_dormant_while_machine_contract_has_no_merged_control_sha(self):
        with self.assertRaisesRegex(runtime.ProviderError, "dormant"):
            runtime.ProviderConfig.from_environment(environment())
        values = environment()
        for name in (
            "PAPERDESK_WATCHDOG_GITHUB_APP_ID",
            "PAPERDESK_WATCHDOG_GITHUB_APP_INSTALLATION_ID",
            "PAPERDESK_WATCHDOG_GITHUB_APP_PRIVATE_KEY_PEM",
        ):
            del values[name]
        with self.assertRaisesRegex(runtime.ProviderError, "dormant"):
            runtime.ProviderConfig.from_environment(values)

    def test_active_contract_requires_all_three_github_app_settings(self):
        values = environment()
        for name in (
            "PAPERDESK_WATCHDOG_GITHUB_APP_ID",
            "PAPERDESK_WATCHDOG_GITHUB_APP_INSTALLATION_ID",
            "PAPERDESK_WATCHDOG_GITHUB_APP_PRIVATE_KEY_PEM",
        ):
            del values[name]

        with self.assertRaisesRegex(runtime.ProviderError, "required") as caught:
            runtime.ProviderConfig.from_environment(values, active_machine())

        self.assertEqual(caught.exception.status, 500)
        self.assertEqual(caught.exception.code, "provider-config-invalid")

    def test_duplicate_identity_or_partial_github_app_fails_closed(self):
        values = environment()
        values["PAPERDESK_WATCHDOG_EVIDENCE_WRITER_IDENTITY_CLIENT_ID"] = values[
            "PAPERDESK_WATCHDOG_STATE_IDENTITY_CLIENT_ID"
        ]
        with self.assertRaisesRegex(runtime.ProviderError, "distinct"):
            runtime.ProviderConfig.from_environment(values, active_machine())
        values = environment()
        del values["PAPERDESK_WATCHDOG_GITHUB_APP_PRIVATE_KEY_PEM"]
        with self.assertRaisesRegex(runtime.ProviderError, "partial"):
            runtime.ProviderConfig.from_environment(values, active_machine())

    def test_control_sha_must_equal_the_independently_merged_machine_contract_sha(self):
        values = environment()
        values["PAPERDESK_WATCHDOG_CONTROL_WORKFLOW_SHA"] = "6" * 40
        with self.assertRaisesRegex(runtime.ProviderError, "control workflow SHA"):
            runtime.ProviderConfig.from_environment(values, active_machine())

    def test_transition_verifier_rejects_expiration_equal_to_current_epoch(self):
        epoch = int(NOW.timestamp())
        claims = {
            "iat": epoch - 60,
            "nbf": epoch - 60,
            "exp": epoch,
        }
        config = runtime.ProviderConfig.from_environment(environment(), active_machine())
        verifier = runtime.ProviderOIDCVerifier(config, clock=lambda: NOW)
        verifier._load_keys = lambda: {"test-key": {"kty": "RSA"}}

        with mock.patch.object(runtime, "jwt_module", return_value=FakeJWT(claims)):
            with self.assertRaisesRegex(runtime.ProviderError, "lifetime is invalid") as caught:
                verifier._decode_all_claims("header.payload.signature")

        self.assertEqual(caught.exception.status, 401)


if __name__ == "__main__":
    unittest.main()
