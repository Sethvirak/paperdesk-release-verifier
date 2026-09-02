"""Storage credential/proof diagnostics use only synthetic tokens and cached facts."""

import base64
import copy
import datetime as dt
import json
import unittest
from unittest import mock

from scripts import private_release_v2_bootstrap as bootstrap


NOW = dt.datetime(2026, 9, 2, 4, 0, tzinfo=dt.timezone.utc)
NOW_UNIX = int(NOW.timestamp())
ACCOUNT = "11111111-2222-4333-8444-555555555555"
STORAGE = "https://storage.azure.com/"
ARM = "https://management.azure.com/"
SECRET = "Bearer synthetic-private-token 203.0.113.77 raw-private-claim"
DIAGNOSTIC_KEYS = {
    "source", "tokenIssuedAtUnix", "tokenExpiresAtUnix",
    "tokenObservedAtUnix", "accountBindingVerified",
}


def jwt_for(**changes):
    claims = {
        "aud": STORAGE,
        "exp": NOW_UNIX + 3600,
        "iat": NOW_UNIX - 600,
        "nbf": NOW_UNIX - 30,
        "oid": ACCOUNT,
        "tid": bootstrap.TENANT,
        "privateFixture": SECRET,
    }
    claims.update(changes)
    payload = base64.urlsafe_b64encode(
        json.dumps(claims, separators=(",", ":")).encode()
    ).decode("ascii").rstrip("=")
    return f"synthetic-header.{payload}.synthetic-signature"


class StorageCredentialDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.current = NOW
        self.session = bootstrap.AzureCliRestSession(
            {"azure": {"accountObjectId": ACCOUNT}},
            clock=lambda: self.current,
        )

    def diagnostic(self, **changes):
        value = {
            "source": "azure-cli-request",
            "tokenIssuedAtUnix": NOW_UNIX - 600,
            "tokenExpiresAtUnix": NOW_UNIX + 3600,
            "tokenObservedAtUnix": int(self.current.timestamp()),
            "accountBindingVerified": True,
        }
        value.update(changes)
        return value

    def assert_private(self, value, token=None):
        rendered = json.dumps(value, sort_keys=True)
        for forbidden in (SECRET, ACCOUNT, bootstrap.TENANT, STORAGE,
                          "synthetic-header", "synthetic-signature",
                          "privateFixture", "accessToken", "refreshToken"):
            self.assertNotIn(forbidden, rendered)
        if token is not None:
            self.assertNotIn(token, rendered)

    def test_initial_snapshot_has_no_credential_side_effect(self):
        with mock.patch.object(self.session, "_run_az_json") as runner:
            self.assertIsNone(self.session.storage_credential_diagnostic())
        runner.assert_not_called()
        self.assertEqual(self.session._tokens, {})

    def test_cli_request_snapshot_is_fixed_and_defensively_copied(self):
        token = jwt_for()
        with mock.patch.object(self.session, "_run_az_json",
                               return_value={"accessToken": token}) as runner:
            self.assertEqual(self.session._token(STORAGE), token)
            first = self.session.storage_credential_diagnostic()
            self.assertEqual(first, self.diagnostic())
            self.assertEqual(set(first), DIAGNOSTIC_KEYS)
            first["source"] = SECRET
            first["unexpected"] = SECRET
            self.assertEqual(self.session.storage_credential_diagnostic(), self.diagnostic())
        runner.assert_called_once_with(
            ["account", "get-access-token", "--resource", STORAGE,
             "--subscription", bootstrap.SUBSCRIPTION],
            "access token request",
        )
        self.assert_private(self.session.storage_credential_diagnostic(), token)

    def test_cache_threshold_stays_strictly_greater_than_300_seconds(self):
        original = jwt_for()
        refreshed = jwt_for(exp=NOW_UNIX + 6900)
        with mock.patch.object(self.session, "_run_az_json", side_effect=[
            {"accessToken": original}, {"accessToken": refreshed},
        ]) as runner:
            self.assertEqual(self.session._token(STORAGE), original)
            self.current = NOW + dt.timedelta(seconds=3299)
            self.assertEqual(self.session._token(STORAGE), original)
            self.assertEqual(runner.call_count, 1)
            self.assertEqual(self.session.storage_credential_diagnostic(),
                             self.diagnostic(source="process-cache"))
            self.current = NOW + dt.timedelta(seconds=3300)
            self.assertEqual(self.session._token(STORAGE), refreshed)
            self.assertEqual(runner.call_count, 2)
            self.assertEqual(self.session.storage_credential_diagnostic(),
                             self.diagnostic(tokenExpiresAtUnix=NOW_UNIX + 6900))

    def test_cli_request_never_claims_fresh_issuance_from_old_iat(self):
        token = jwt_for(iat=NOW_UNIX - 86400)
        with mock.patch.object(self.session, "_run_az_json",
                               return_value={"accessToken": token}):
            self.session._token(STORAGE)
        result = self.session.storage_credential_diagnostic()
        self.assertEqual(result, self.diagnostic(tokenIssuedAtUnix=NOW_UNIX - 86400))
        self.assertEqual(set(result), DIAGNOSTIC_KEYS)
        self.assertNotIn("fresh", json.dumps(result))

    def test_non_storage_credentials_never_create_or_replace_storage_snapshot(self):
        with mock.patch.object(self.session, "_run_az_json", side_effect=[
            {"accessToken": jwt_for(aud=ARM)}, {"accessToken": jwt_for()},
        ]) as runner:
            self.session._token(ARM)
            self.assertIsNone(self.session.storage_credential_diagnostic())
            self.session._token(STORAGE)
            expected = self.session.storage_credential_diagnostic()
            self.current += dt.timedelta(seconds=10)
            self.session._token(ARM)
            self.assertEqual(self.session.storage_credential_diagnostic(), expected)
            self.assertEqual(runner.call_count, 2)

    def test_optional_issued_at_is_diagnostic_only_and_does_not_change_acceptance(self):
        cases = [None, True, str(NOW_UNIX), -1, 4102444801, NOW_UNIX + 31]
        for issued_at in cases:
            with self.subTest(issued_at=issued_at):
                session = bootstrap.AzureCliRestSession(
                    {"azure": {"accountObjectId": ACCOUNT}}, clock=lambda: NOW)
                token = jwt_for(iat=issued_at)
                with mock.patch.object(session, "_run_az_json",
                                       return_value={"accessToken": token}) as runner:
                    self.assertEqual(session._token(STORAGE), token)
                runner.assert_called_once()
                result = session.storage_credential_diagnostic()
                self.assertIsNone(result["tokenIssuedAtUnix"])
                self.assertTrue(result["accountBindingVerified"])
                self.assert_private(result, token)

    def test_issued_at_accepts_exact_30_second_clock_skew(self):
        with mock.patch.object(self.session, "_run_az_json", return_value={
            "accessToken": jwt_for(iat=NOW_UNIX + 30),
        }):
            self.session._token(STORAGE)
        self.assertEqual(self.session.storage_credential_diagnostic(),
                         self.diagnostic(tokenIssuedAtUnix=NOW_UNIX + 30))

    def test_out_of_diagnostic_range_expiry_does_not_add_an_authentication_gate(self):
        token = jwt_for(exp=4102444801)
        with mock.patch.object(self.session, "_run_az_json",
                               return_value={"accessToken": token}):
            self.assertEqual(self.session._token(STORAGE), token)
        self.assertEqual(self.session.storage_credential_diagnostic(),
                         self.diagnostic(tokenExpiresAtUnix=None))

    def test_existing_token_binding_checks_remain_fail_closed(self):
        cases = [
            {"aud": "https://example.invalid/"},
            {"tid": ACCOUNT},
            {"oid": bootstrap.TENANT},
            {"exp": NOW_UNIX + 300},
            {"exp": str(NOW_UNIX + 3600)},
            {"exp": True},
            {"nbf": NOW_UNIX + 31},
            {"nbf": str(NOW_UNIX - 30)},
        ]
        for changes in cases:
            with self.subTest(changes=changes):
                session = bootstrap.AzureCliRestSession(
                    {"azure": {"accountObjectId": ACCOUNT}}, clock=lambda: NOW)
                with mock.patch.object(session, "_run_az_json", return_value={
                    "accessToken": jwt_for(**changes),
                }) as runner:
                    with self.assertRaises(bootstrap.BootstrapError):
                        session._token(STORAGE)
                runner.assert_called_once()
                self.assertEqual(session._tokens, {})
                self.assertIsNone(session.storage_credential_diagnostic())

    def test_sanitizer_drops_unknown_fields_and_untrusted_values(self):
        value = self.diagnostic(source=SECRET, tokenIssuedAtUnix=True,
                                tokenExpiresAtUnix="3600", accountBindingVerified=1)
        value.update(accessToken=SECRET, rawClaims={"oid": ACCOUNT})
        result = bootstrap._safe_storage_credential_diagnostic(value)
        self.assertEqual(result, self.diagnostic(
            source=None, tokenIssuedAtUnix=None, tokenExpiresAtUnix=None,
            accountBindingVerified=None,
        ))
        self.assertEqual(set(result), DIAGNOSTIC_KEYS)
        self.assert_private(result)

    def test_sanitizer_epoch_bounds_and_missing_observation(self):
        for value in (-1, 4102444801, True, 1.5, "123", None):
            with self.subTest(value=value):
                result = bootstrap._safe_storage_credential_diagnostic(self.diagnostic(
                    tokenIssuedAtUnix=value, tokenExpiresAtUnix=value,
                    tokenObservedAtUnix=value,
                ))
                self.assertEqual(result, self.diagnostic(
                    tokenIssuedAtUnix=None, tokenExpiresAtUnix=None,
                    tokenObservedAtUnix=None,
                ))
        for value in (0, 4102444800):
            with self.subTest(bound=value):
                result = bootstrap._safe_storage_credential_diagnostic(self.diagnostic(
                    tokenIssuedAtUnix=value, tokenExpiresAtUnix=value,
                    tokenObservedAtUnix=value,
                ))
                self.assertEqual(result["tokenIssuedAtUnix"], value)
                self.assertEqual(result["tokenExpiresAtUnix"], value)
                self.assertEqual(result["tokenObservedAtUnix"], value)
        result = bootstrap._safe_storage_credential_diagnostic(self.diagnostic(
            tokenObservedAtUnix=None))
        self.assertIsNone(result["tokenIssuedAtUnix"])

    def test_sanitizer_non_mapping_input_is_unavailable(self):
        for value in (None, SECRET, [], 42, True):
            with self.subTest(value=type(value).__name__):
                self.assertIsNone(bootstrap._safe_storage_credential_diagnostic(value))


class StorageTransportDiagnosticTests(unittest.TestCase):
    @staticmethod
    def transport(session=None, projections=None):
        # Exercise only cached diagnostic access, with no transport construction.
        transport = object.__new__(bootstrap.AzureCliBootstrapTransport)
        transport.session = session
        transport._validated_source_projections = projections or {}
        return transport

    def test_credential_snapshot_never_requests_or_acquires_credentials(self):
        value = {
            "source": "process-cache", "tokenIssuedAtUnix": NOW_UNIX - 600,
            "tokenExpiresAtUnix": NOW_UNIX + 3600,
            "tokenObservedAtUnix": NOW_UNIX, "accountBindingVerified": True,
            "rawResponse": SECRET,
        }
        session = mock.Mock(spec=["storage_credential_diagnostic", "request", "_token"])
        session.storage_credential_diagnostic.return_value = value
        transport = self.transport(session=session)
        result = transport._storage_credential_snapshot()
        self.assertEqual(set(result), DIAGNOSTIC_KEYS)
        self.assertNotIn(SECRET, json.dumps(result))
        result["source"] = SECRET
        self.assertEqual(value["source"], "process-cache")
        session.storage_credential_diagnostic.assert_called_once_with()
        session.request.assert_not_called()
        session._token.assert_not_called()

    def test_missing_or_failed_snapshot_is_unavailable_without_fallback_requests(self):
        self.assertIsNone(self.transport(session=object())._storage_credential_snapshot())
        session = mock.Mock(spec=["storage_credential_diagnostic", "request", "_token"])
        session.storage_credential_diagnostic.side_effect = RuntimeError(SECRET)
        self.assertIsNone(self.transport(session=session)._storage_credential_snapshot())
        session.request.assert_not_called()
        session._token.assert_not_called()

    def test_role_snapshot_hashes_only_cached_validated_definition_and_assignment(self):
        operation = "addOwnedOperatorControllerCanaryRole"
        definition = {"properties": {"permissions": [{"dataActions": ["fixture/read"]}]}}
        assignment = {"properties": {"principalId": ACCOUNT, "condition": None}}
        envelope = {
            "family": "temporary-role-projection",
            "projection": {"definition": definition, "assignment": assignment,
                           "unrelatedPrivateValue": SECRET},
        }
        session = mock.Mock(spec=["request", "_token"])
        transport = self.transport(session, {operation: copy.deepcopy(envelope)})
        result = transport._storage_role_readback_snapshot(operation)
        self.assertEqual(result, {
            "definitionSha256": bootstrap.sha256_bytes(bootstrap.canonical_json_bytes(definition)),
            "assignmentSha256": bootstrap.sha256_bytes(bootstrap.canonical_json_bytes(assignment)),
        })
        self.assertNotIn(ACCOUNT, json.dumps(result))
        self.assertNotIn(SECRET, json.dumps(result))
        result["definitionSha256"] = SECRET
        self.assertEqual(transport._validated_source_projections[operation], envelope)
        session.request.assert_not_called()
        session._token.assert_not_called()

    def test_absent_wrong_family_or_malformed_role_projection_is_unavailable(self):
        operation = "addOwnedOperatorControllerCanaryRole"
        cases = [
            {},
            {operation: None},
            {operation: {"family": "unvalidated", "projection": {
                "definition": {}, "assignment": {},
            }}},
            {operation: {"family": "temporary-role-projection", "projection": None}},
            {operation: {"family": "temporary-role-projection", "projection": {}}},
            {operation: {"family": "temporary-role-projection", "projection": {
                "definition": SECRET, "assignment": {},
            }}},
        ]
        for projections in cases:
            with self.subTest(projections=projections):
                self.assertIsNone(self.transport(projections=projections)
                                  ._storage_role_readback_snapshot(operation))


if __name__ == "__main__":
    unittest.main()
