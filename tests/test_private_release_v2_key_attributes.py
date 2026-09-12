"""Provider-shaped optional key attributes and bounded readback diagnostics."""

import base64
import copy
import datetime as dt
import unittest
from unittest import mock

from provider import private_release_bridge_azure as azure
from scripts import private_release_mailbox as core
from scripts import private_release_v2_bootstrap as bootstrap
from tests import private_release_v2_fixture as fixture


NOW = dt.datetime(2026, 8, 30, 4, tzinfo=dt.timezone.utc)
OPERATION = "readBackExactSigningPublicJwk"


class KeyAttributeTests(unittest.TestCase):
    def setUp(self):
        self.plan, _ = bootstrap.load_plan()
        self.document, self.evidence, _ = fixture.activated_bundle()
        self.key = copy.deepcopy(self.evidence["keyVaultBoundary"]["keyDataPlaneProjection"])
        self.key["n"] = base64.urlsafe_b64encode(b"\x80" + b"\x00" * 383).decode().rstrip("=")
        self.key["attributes"]["nbf"] = None
        self.current = NOW
        self.authorization = {
            "authorizationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "source": {"mergedMain": {"commitSha": "2" * 40}},
            "validity": {
                "notBefore": (NOW - dt.timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
                "expiresAt": (NOW + dt.timedelta(minutes=65)).isoformat().replace("+00:00", "Z"),
            },
        }

    def activation(self, key):
        evidence = copy.deepcopy(self.evidence)
        boundary = evidence["keyVaultBoundary"]
        boundary["keyDataPlaneProjection"] = copy.deepcopy(key)
        boundary["keyDataPlaneProjectionSha256"] = core.digest(core.canonical(key))
        document = copy.deepcopy(self.document)
        document["activation"]["signingPublicJwk"]["n"] = key["n"]
        document["activation"]["provisioningEvidenceSha256"] = core.digest(core.canonical(evidence))
        return core.load_activation_document(
            document, runtime_workflow_sha=fixture.WORKFLOW_SHA,
            observed_bridge_package_sha256=fixture.PACKAGE_SHA,
            provisioning_evidence=evidence,
        )

    def bridge_read(self, key, *, omit_nbf=False):
        document = {
            "key": {name: key[name] for name in ("kid", "kty", "key_ops", "n", "e")},
            "attributes": copy.deepcopy(key["attributes"]),
        }
        if omit_nbf:
            document["attributes"].pop("nbf")
        calls = []

        class Tokens:
            def get(self, audience):
                return "fixture-token"

        def http(method, url, headers, body):
            calls.append((method, body))
            return core.Response(200, url, core.canonical(document), {})

        result = azure.KeyVaultKeyReader(Tokens(), fixture.activation(), http)()
        self.assertEqual(calls, [("GET", None)])
        return result

    def transport(self, session=None):
        contract = bootstrap._validator_contract("operation:" + OPERATION, self.plan, self.authorization)
        probe = {
            "id": "key-versions", "phase": "readback",
            "method": contract["expectedMethod"], "url": contract["expectedUrl"],
            "validatorId": "operation:" + OPERATION, "validatorContract": contract,
        }

        def sleep(seconds):
            self.current += dt.timedelta(seconds=seconds)

        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=self.authorization, plan=self.plan, package={},
            preflight={"projection": {
                "operationAdmissions": [{"operationId": OPERATION, "context": {}}],
                "postconditionAdmissions": [], "probes": [probe],
                "productionBoundaryObservation": {},
            }},
            session=session or object(), clock=lambda: self.current, sleep=sleep,
        )
        transport._active_operation_id = OPERATION
        transport._validated_source_projections["createSigningKeyVersion"] = {
            "projection": {"keyUriWithVersion": self.key["kid"], "expiresAt": self.key["attributes"]["exp"]},
        }
        return transport, probe

    def inventory(self, key, *, omit_nbf=False):
        attributes = copy.deepcopy(key["attributes"])
        if omit_nbf:
            attributes.pop("nbf")
        return bootstrap._RestResponse(200, core.canonical({
            "value": [{"kid": key["kid"], "attributes": attributes}],
            "nextLink": None,
        }), {})

    def bootstrap_read(self, key):
        transport, probe = self.transport()
        return transport._validate_readback_response(probe, self.inventory(key), runtime_facts=key)

    def test_omitted_provider_nbf_survives_bootstrap_activation_and_live_check(self):
        projected = self.bridge_read(self.key, omit_nbf=True)
        self.assertIsNone(projected["attributes"]["nbf"])
        self.assertEqual(projected, self.key)
        transport, probe = self.transport()
        proof = transport._validate_readback_response(
            probe, self.inventory(self.key, omit_nbf=True), runtime_facts=projected,
        )
        self.assertEqual(proof["sourceProjection"]["projection"], projected)
        activation = self.activation(projected)
        self.assertEqual(core.validate_live_signing_key(projected, activation, now=NOW), projected)

    def test_numeric_not_before_remains_valid_when_no_later_than_creation(self):
        for nbf in (self.key["attributes"]["created"], self.key["attributes"]["created"] - 1):
            with self.subTest(nbf=nbf):
                key = copy.deepcopy(self.key)
                key["attributes"]["nbf"] = nbf
                self.bootstrap_read(key)
                self.activation(key)
                self.assertEqual(self.bridge_read(key), key)

    def test_malformed_or_late_not_before_fails_all_three_boundaries(self):
        for nbf in (True, False, "1700000000", 1700000000.0, [], {}, self.key["attributes"]["created"] + 1):
            with self.subTest(nbf=nbf):
                key = copy.deepcopy(self.key)
                key["attributes"]["nbf"] = nbf
                with self.assertRaises(bootstrap.BootstrapError):
                    self.bootstrap_read(key)
                with self.assertRaises(core.MailboxError):
                    self.activation(key)
                with self.assertRaises(core.MailboxError):
                    self.bridge_read(key)

    def test_other_required_attributes_remain_required(self):
        for name in ("exp", "created", "updated", "recoverableDays", "enabled", "exportable"):
            with self.subTest(name=name):
                key = copy.deepcopy(self.key)
                key["attributes"][name] = None
                with self.assertRaises(bootstrap.BootstrapError):
                    self.bootstrap_read(key)
                with self.assertRaises(core.MailboxError):
                    self.activation(key)
                with self.assertRaises(core.MailboxError):
                    self.bridge_read(key)

    def test_projection_must_retain_explicit_null_field(self):
        key = copy.deepcopy(self.key)
        del key["attributes"]["nbf"]
        with self.assertRaises(bootstrap.BootstrapError):
            self.bootstrap_read(key)
        with self.assertRaises(core.MailboxError):
            self.activation(key)

    def test_inventory_and_live_projection_drift_are_still_rejected(self):
        changed = copy.deepcopy(self.key)
        changed["attributes"]["nbf"] = changed["attributes"]["created"]
        transport, probe = self.transport()
        with self.assertRaisesRegex(bootstrap.BootstrapError, "versions readback is not exact"):
            transport._validate_readback_response(probe, self.inventory(changed), runtime_facts=self.key)
        with self.assertRaisesRegex(core.MailboxError, "live-key-projection"):
            core.validate_live_signing_key(changed, self.activation(self.key), now=NOW)

    def test_readback_envelope_stop_preserves_preceding_validation_error(self):
        calls = []
        owner = self

        class Session:
            def request(self, method, url, **kwargs):
                calls.append((method, kwargs["deadline"]))
                owner.current += dt.timedelta(seconds=31)
                return bootstrap._RestResponse(403, b'private response body', {})

        transport, probe = self.transport(Session())
        with self.assertRaises(bootstrap.BootstrapError) as raised:
            transport._prove_probe_ids([probe["id"]], OPERATION, runtime_facts=self.key)
        message = str(raised.exception)
        self.assertIn("key-versions", message)
        self.assertIn("readback status is not the source-defined invariant", message)
        self.assertIn("readback stopped: protected cleanup reserve", message)
        self.assertNotIn("private response body", message)
        self.assertEqual(calls, [("GET", NOW + dt.timedelta(seconds=120))])
        self.assertLess(self.current, NOW + dt.timedelta(seconds=32))

    def test_first_transport_failure_gets_probe_context_without_extra_retry(self):
        calls = []

        class Session:
            def request(self, method, url, **kwargs):
                calls.append(method)
                raise bootstrap.BootstrapError("Azure REST transport failed closed")

        transport, probe = self.transport(Session())
        with self.assertRaisesRegex(bootstrap.BootstrapError, "key-versions: Azure REST transport failed closed"):
            transport._prove_probe_ids([probe["id"]], OPERATION, runtime_facts=self.key)
        self.assertEqual(calls, ["GET"] * 3)
        self.assertEqual(self.current, NOW + dt.timedelta(seconds=1.5))

    def test_adopt_readback_keeps_a_full_retry_envelope_after_one_timeout(self):
        calls = []
        owner = self

        class Session:
            def request(self, method, url, **kwargs):
                calls.append((method, kwargs["deadline"]))
                if len(calls) == 1:
                    owner.current += dt.timedelta(
                        seconds=bootstrap.AZURE_REST_RESPONSE_TIMEOUT_SECONDS
                    )
                    raise bootstrap._RestTransportAmbiguity(
                        "Azure REST transport failed closed"
                    )
                return owner.inventory(owner.key, omit_nbf=True)

        transport, probe = self.transport(Session())
        transport._active_operation_id = None
        proof = transport._prove_adopt_probe_ids(
            [probe["id"]],
            "adopted signing key",
            runtime_facts=self.key,
        )[0]

        expected_deadline = NOW + dt.timedelta(
            seconds=bootstrap.MAX_ADOPT_READBACK_CONVERGENCE_SECONDS
        )
        self.assertEqual(proof["attempts"], 1)
        self.assertEqual(calls, [("GET", expected_deadline)] * 2)
        self.assertEqual(
            self.current,
            NOW
            + dt.timedelta(
                seconds=bootstrap.AZURE_REST_RESPONSE_TIMEOUT_SECONDS + 0.5
            ),
        )
        self.assertEqual(bootstrap.MAX_READBACK_CONVERGENCE_SECONDS, 120)
        self.assertEqual(bootstrap.MAX_ADOPT_READBACK_CONVERGENCE_SECONDS, 300)

    def test_adopt_operation_selects_the_extended_readback_window(self):
        transport, probe = self.transport()
        transport.admissions[OPERATION]["context"] = {
            "executionDecision": "adopt-exact",
            "adopted": {},
        }
        transport.admissions[OPERATION]["desiredProbeIds"] = [probe["id"]]
        with mock.patch.object(
            transport, "_prove_probe_ids", return_value=[]
        ) as prove:
            result = transport.apply_operation({"id": OPERATION}, {})

        self.assertEqual(result["status"], "adopted-exact")
        prove.assert_called_once()
        self.assertEqual(
            prove.call_args.args,
            ([probe["id"]], f"{OPERATION} adopt"),
        )
        self.assertFalse(transport._adopt_readback_active)

    def test_valid_readback_can_still_converge_within_original_window(self):
        calls = []
        owner = self

        class Session:
            def request(self, method, url, **kwargs):
                calls.append(method)
                if len(calls) == 1:
                    return bootstrap._RestResponse(403, b'', {})
                return owner.inventory(owner.key, omit_nbf=True)

        transport, probe = self.transport(Session())
        proof = transport._prove_probe_ids([probe["id"]], OPERATION, runtime_facts=self.key)[0]
        self.assertEqual(proof["attempts"], 2)
        self.assertEqual(calls, ["GET", "GET"])
        self.assertEqual(self.current, NOW + dt.timedelta(seconds=0.25))


if __name__ == "__main__":
    unittest.main()
