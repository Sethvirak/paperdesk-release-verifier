"""Cloud-free byte/crypto negatives; synthetic RSA material lives only in memory."""
import base64
import copy
import datetime as dt
import hashlib
import json
import math
from pathlib import Path
import secrets
import unittest
from unittest import mock

from scripts import private_release_mailbox as box
from scripts import provisional_defender_authorization as reader
from scripts import build_private_release_bridge_package as package_builder


NOW = dt.datetime(2026, 10, 1, 0, 5, tzinfo=dt.timezone.utc)
KEY_ID = "https://synthetic-test-vault.vault.azure.net/keys/synthetic-test-key"
KEY_VERSION = "a" * 32


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _prime(bits):
    # Test-only probable primes, never exported or used as production keys.
    small = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
             59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
             127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
             191, 193, 197, 199)
    while True:
        value = secrets.randbits(bits) | (3 << (bits - 2)) | 1
        if any(value % p == 0 for p in small) or math.gcd(value - 1, 65537) != 1:
            continue
        odd, count = value - 1, 0
        while odd % 2 == 0:
            odd //= 2
            count += 1
        for _ in range(24):
            witness = pow(2 + secrets.randbelow(value - 3), odd, value)
            if witness in (1, value - 1):
                continue
            for _ in range(count - 1):
                witness = pow(witness, 2, value)
                if witness == value - 1:
                    break
            else:
                break
        else:
            return value


def descriptor(blob, sha="1" * 64):
    return {"blob": blob, "sha256": sha, "size": 64, "etag": '"synthetic-etag"', "versionId": "synthetic-v1"}


def candidate():
    value = {
        "schemaVersion": 1, "kind": "paperdesk-private-defender-authorization",
        "domain": reader.DOMAIN, "audience": reader.AUDIENCE,
        "operationId": "synthetic-test-operation-20261001", "operationDigestSha256": "0" * 64,
        "bindingSha256": "0" * 64, "issuedAt": "2026-10-01T00:00:00.000Z",
        "startedAt": "2026-10-01T00:00:00.000Z", "deadlineAt": "2026-10-01T01:00:00.000Z",
        "approvalReceiptSha256": "2" * 64,
        "candidate": {"repository": "Sethvirak/MasterDataStructure", "sourceSha": "a" * 40,
                      "treeSha": "b" * 40, "sourceRunId": "101", "sourceRunAttempt": "1", "artifactId": "102",
                      "archiveSha256": "3" * 64, "packageSha256": "4" * 64,
                      "verificationReceiptSha256": "5" * 64, "servedIndexSha256": "6" * 64,
                      "package": descriptor(f"v1/pending/{'a' * 40}/101-1-102/deployment.zip", "4" * 64)},
        "control": {"repository": "Sethvirak/paperdesk-release-verifier", "sourceSha": "c" * 40,
                    "treeSha": "d" * 40, "runId": "103", "runAttempt": "1", "workflowId": "104",
                    "bootstrapReceiptSha256": "7" * 64, "activationEvidenceSha256": "8" * 64,
                    "sourceReviewEvidenceSha256": "9" * 64, "bridgePackageSha256": "a" * 64},
        "rollback": {"sourceSha": "e" * 40, "acceptedManifest": descriptor(f"v2/accepted/{'e' * 40}/manifest.json"),
                     "packageSha256": "b" * 64, "proofSha256": "c" * 64},
        "database": {"migrationSha256": "d" * 64, "schemaSha256": "e" * 64,
                     "rolePolicySha256": "f" * 64, "checkpointSha256": "1" * 64,
                     "writerFenceSha256": "2" * 64, "ownerRole": "paperdesk_provisional_owner",
                     "transitionRole": "paperdesk_provisional_transition"},
        "provider": {"storageAccountResourceId": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/synthetic-rg/providers/Microsoft.Storage/storageAccounts/synthetictest",
                     "accountUrl": "https://synthetictest.blob.core.windows.net", "container": "synthetic-test", "blobName": "pending",
                     "storageReferenceHmac": "hmac-sha256:" + "3" * 64, "referenceKeyId": "synthetic-reference-key",
                     "referenceKeyGenerationSha256": "4" * 64,
                     "systemTopicResourceId": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/synthetic-rg/providers/Microsoft.EventGrid/systemTopics/synthetic-topic",
                     "topicHash": "sha256:" + "5" * 64, "storageScopeSha256": "6" * 64,
                     "fixtureSha256": "7" * 64, "fixtureSize": 32},
        "principals": {"tenantId": "22222222-2222-2222-2222-222222222222",
                       "signerObjectId": "33333333-3333-3333-3333-333333333333",
                       "canaryObjectId": "44444444-4444-4444-4444-444444444444",
                       "eventGridObjectId": "55555555-5555-5555-5555-555555555555",
                       "canaryClientId": "66666666-6666-6666-6666-666666666666",
                       "eventGridClientId": "77777777-7777-7777-7777-777777777777",
                       "canaryAudience": "api://66666666-6666-6666-6666-666666666666",
                       "eventGridAudience": "api://77777777-7777-7777-7777-777777777777",
                       "issuer": "https://sts.windows.net/22222222-2222-2222-2222-222222222222/"},
        "evidence": {key: descriptor(f"v2/provisional-evidence/synthetic/{key}.json") for key in (
            "repository", "maintenance", "capacity", "ingress", "cohortDrain", "rollbackDeadline", "providerBinding", "deliveryProvenance")},
        "lifecycle": copy.deepcopy(reader.LIFECYCLE),
    }
    return rebind(value)


def rebind(value):
    value["operationDigestSha256"] = reader.operation_digest(value)
    target = box.digest(json.dumps(["paperdesk-provisional-defender-object-v1", value["operationDigestSha256"]], separators=(",", ":")).encode())[:32]
    value["provider"]["blobName"] = f"__paperdesk-defender-canary/v1/{target}.txt"
    value["bindingSha256"] = reader.binding_digest(value)
    return value


class AuthorizationReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p, q = _prime(1536), _prime(1536)
        while p == q:
            q = _prime(1536)
        cls.modulus = p * q
        cls.exponent = pow(65537, -1, (p - 1) * (q - 1))
        cls.jwk = {"kty": "RSA", "kid": KEY_ID + "/" + KEY_VERSION,
                   "n": b64(cls.modulus.to_bytes(384, "big")), "e": "AQAB", "key_ops": ["sign", "verify"]}

    def sign(self, marker):
        message = box.canonical(marker)
        salt = secrets.token_bytes(32)
        hashed = hashlib.sha256(b"\0" * 8 + hashlib.sha256(message).digest() + salt).digest()
        db = b"\0" * 318 + b"\x01" + salt
        masked = bytearray(a ^ b for a, b in zip(db, box._mgf1(hashed, len(db))))
        masked[0] &= 0x7f
        encoded = bytes(masked) + hashed + b"\xbc"
        return b64(pow(int.from_bytes(encoded, "big"), self.exponent, self.modulus).to_bytes(384, "big"))

    def fixture(self, marker=None):
        marker = candidate() if marker is None else marker
        envelope = {"authorization": marker, "signature": {"algorithm": "PS256", "keyId": KEY_ID,
                    "keyVersion": KEY_VERSION, "value": self.sign(marker)}}
        raw = box.canonical(envelope)
        record = box.WormRecord(f"v2/provisional/{marker['operationDigestSha256']}/authorization.json", raw, '"marker-etag"', "marker-v1")
        pins = {"schemaVersion": 1, "purpose": "candidate-inspection-only", "signing": {"keyId": KEY_ID,
                "keyVersion": KEY_VERSION, "publicJwk": copy.deepcopy(self.jwk)},
                "markerDescriptor": box._worm_descriptor(record), "expectedAuthorization": copy.deepcopy(marker)}
        return envelope, record, pins

    def inspect(self, record, pins, now=NOW):
        return reader.inspect_candidate_record(record, pins_raw=box.canonical(pins), now=now)

    def reject(self, record, pins, code=None, now=NOW):
        with self.assertRaisesRegex(reader.AuthorizationCandidateError, code or ".+"):
            self.inspect(record, pins, now)

    def edited_record(self, record, pins, raw):
        result = box.WormRecord(record.blob, raw, record.etag, record.version_id)
        pins["markerDescriptor"] = box._worm_descriptor(result)
        return result

    def test_real_ps256_candidate_receipt_remains_path_free_non_authoritative(self):
        envelope, record, pins = self.fixture()
        receipt = self.inspect(record, pins)
        self.assertEqual(receipt["status"], "cryptographic-candidate-only")
        self.assertTrue(receipt["signatureValidForSuppliedKey"])
        for field in ("externalAuthorityVerified", "providerReadbackVerified", "oneUseStateVerified", "authorizationAdmissionAllowed", "activationAllowed", "candidateConsumeAllowed", "acceptedRegistryWriteAllowed"):
            self.assertIs(receipt[field], False)
        self.assertNotIn("https://", box.canonical(receipt).decode())
        self.assertNotIn("synthetic-test-operation", box.canonical(receipt).decode())
        # Same candidate may be inspected twice; no durable claim is created.
        self.assertEqual(receipt, self.inspect(record, pins))

    def test_authorization_admission_rejects_before_any_argument_work(self):
        class Hostile:
            def __getattribute__(self, name):
                raise AssertionError("must not inspect caller object")
        callback = mock.Mock(side_effect=AssertionError("must not call provider"))
        with mock.patch.object(box, "verify_ps256", callback):
            for inputs in ({}, {"verified": True, "role": "paperdesk_provisional_transition", "provider": callback, "context": Hostile()}):
                with self.assertRaisesRegex(reader.AuthorizationCandidateError, "ADMISSION_UNAVAILABLE"):
                    reader.admit_authorization(**inputs)
        callback.assert_not_called()

    def test_policy_empty_allowlist_and_all_false_fences(self):
        reader.validate_policy()
        for field in ("allowedCandidates", "activationAllowed", "authorizationAdmissionAllowed"):
            policy = copy.deepcopy(reader.POLICY)
            policy[field] = ["synthetic-candidate"] if field == "allowedCandidates" else True
            with mock.patch.object(Path, "read_bytes", return_value=box.canonical(policy)):
                with self.assertRaisesRegex(reader.AuthorizationCandidateError, "policy-dormant"):
                    reader.validate_policy()
        policy = copy.deepcopy(reader.POLICY)
        policy["schemaVersion"] = True
        with mock.patch.object(Path, "read_bytes", return_value=box.canonical(policy)):
            with self.assertRaisesRegex(reader.AuthorizationCandidateError, "policy-dormant"):
                reader.validate_policy()

    def test_duplicate_noncanonical_unknown_and_oversize_bytes(self):
        envelope, record, pins = self.fixture()
        raws = (box.canonical(envelope).replace(b'{"authorization":', b'{"authorization":{},"authorization":', 1),
                box.canonical(envelope).replace(b'"fixtureSize":32', b'"fixtureSize":32,"fixtureSize":32'),
                json.dumps(envelope, indent=2).encode(), box.canonical(envelope)[:-1],
                b"\xef\xbb\xbf" + box.canonical(envelope), b"{\"x\":NaN}\n", b"{\"x\":1e999}\n", b"{}\n" + b" " * reader.MAX_MARKER_BYTES)
        for raw in raws:
            with self.subTest(raw=raw[:15]):
                current_pins = copy.deepcopy(pins)
                self.reject(self.edited_record(record, current_pins, raw), current_pins)
        for location in ("envelope", "signature", "authorization", "provider", "lifecycle"):
            value = copy.deepcopy(envelope)
            owner = value if location == "envelope" else value[location] if location in {"signature", "authorization"} else value["authorization"][location]
            owner["verified"] = True
            current_pins = copy.deepcopy(pins)
            self.reject(self.edited_record(record, current_pins, box.canonical(value)), current_pins)

    def test_unknown_pins_and_private_jwk_material_do_not_supply_trust(self):
        _, record, pins = self.fixture()
        for field in ("trusted", "activation", "issuerVerified", "provider"):
            value = copy.deepcopy(pins)
            value[field] = True
            self.reject(record, value, "inspection-pins-fields")
        for field in ("d", "p", "q", "dp", "dq", "qi", "oth", "alg", "x5u", "jku"):
            value = copy.deepcopy(pins)
            value["signing"]["publicJwk"][field] = "AA"
            self.reject(record, value, "public-jwk-fields")

    def test_key_algorithm_version_and_rsa_strength_negatives(self):
        envelope, record, pins = self.fixture()
        for field, content in (("algorithm", "RS256"), ("algorithm", "none"), ("keyId", "http://invalid/keys/test"), ("keyVersion", "b" * 32)):
            value = copy.deepcopy(envelope)
            value["signature"][field] = content
            current_pins = copy.deepcopy(pins)
            self.reject(self.edited_record(record, current_pins, box.canonical(value)), current_pins, "marker-signature-key")
        for field, content in (("kty", "EC"), ("key_ops", ["verify"]), ("e", "AQ"), ("e", "AQAB="), ("n", b64(b"\xff" * 256)), ("n", b64((self.modulus - 1).to_bytes(384, "big"))), ("n", b64(b"\0" + self.modulus.to_bytes(384, "big")))):
            value = copy.deepcopy(pins)
            value["signing"]["publicJwk"][field] = content
            self.reject(record, value)

    def test_wrong_signature_tamper_and_noncanonical_range(self):
        envelope, record, pins = self.fixture()
        for signature in (b64(b"\0" * 384), b64(self.modulus.to_bytes(384, "big")), "AA", envelope["signature"]["value"] + "="):
            value = copy.deepcopy(envelope)
            value["signature"]["value"] = signature
            current_pins = copy.deepcopy(pins)
            self.reject(self.edited_record(record, current_pins, box.canonical(value)), current_pins)
        value = copy.deepcopy(envelope)
        value["authorization"]["control"]["treeSha"] = "f" * 40
        rebind(value["authorization"])
        current_pins = copy.deepcopy(pins)
        current_pins["expectedAuthorization"] = copy.deepcopy(value["authorization"])
        self.reject(self.edited_record(record, current_pins, box.canonical(value)), current_pins, "signature-invalid")

    def test_all_external_tuple_mismatches_reject_before_crypto(self):
        _, record, pins = self.fixture()
        cases = (("candidate", "sourceSha", "f" * 40), ("candidate", "treeSha", "f" * 40),
                 ("candidate", "archiveSha256", "f" * 64), ("candidate", "verificationReceiptSha256", "f" * 64),
                 ("control", "runId", "999"), ("control", "runAttempt", "2"), ("control", "sourceReviewEvidenceSha256", "f" * 64),
                 ("rollback", "proofSha256", "f" * 64), ("database", "migrationSha256", "f" * 64),
                 ("provider", "referenceKeyGenerationSha256", "f" * 64), ("provider", "topicHash", "sha256:" + "f" * 64),
                 ("principals", "signerObjectId", "99999999-9999-9999-9999-999999999999"))
        for section, field, content in cases:
            with self.subTest(section=section, field=field):
                value = copy.deepcopy(pins)
                value["expectedAuthorization"][section][field] = content
                rebind(value["expectedAuthorization"])
                with mock.patch.object(box, "verify_ps256", side_effect=AssertionError("must reject before crypto")):
                    self.reject(record, value)

    def test_wrong_worm_version_etag_digest_size_name_rejected_before_crypto(self):
        _, record, pins = self.fixture()
        for field, content in (("blob", "v2/accepted/unsafe/manifest.json"), ("etag", '"different"'), ("versionId", "new-version"), ("sha256", "f" * 64), ("size", True), ("size", 1)):
            value = copy.deepcopy(pins)
            value["markerDescriptor"][field] = content
            with mock.patch.object(box, "verify_ps256", side_effect=AssertionError("must reject before crypto")):
                self.reject(record, value)

    def test_worm_metadata_types_and_http_etag_controls_are_strict(self):
        _, record, pins = self.fixture()
        equality = mock.Mock()
        class Hostile:
            def __eq__(self, other):
                equality()
                return True
        for value in (None, "", 123, Hostile()):
            for field in ("blob", "etag", "version_id"):
                fields = {"blob": record.blob, "body": record.body, "etag": record.etag, "version_id": record.version_id}
                fields[field] = value
                self.reject(box.WormRecord(**fields), pins, "marker-record")
        equality.assert_not_called()
        for byte in (*range(32), 127):
            marker = candidate()
            marker["evidence"]["ingress"]["etag"] = '"unsafe' + chr(byte) + '"'
            _, changed_record, changed_pins = self.fixture(rebind(marker))
            self.reject(changed_record, changed_pins, "evidence-ingress")
        for value in ("a", "ab", "bad--container", "Uppercase"):
            marker = candidate()
            marker["provider"]["container"] = value
            _, changed_record, changed_pins = self.fixture(rebind(marker))
            self.reject(changed_record, changed_pins, "container")

    def test_domain_time_and_lifecycle_refuse_activation_or_cleanup(self):
        for field, content in (("domain", "normal-release"), ("audience", "ordinary-attachment"),
                               ("schemaVersion", True), ("issuedAt", "2026-09-30T23:00:00.000Z"),
                               ("startedAt", "2026-10-01T00:00:00Z"), ("deadlineAt", "2026-10-02T01:00:00.000Z")):
            value = candidate()
            value[field] = content
            _, record, pins = self.fixture(rebind(value))
            self.reject(record, pins)
        for field in ("cleanupAllowed", "restartAllowed", "ordinaryEvidenceWritesAllowed"):
            value = candidate()
            value["lifecycle"][field] = True
            _, record, pins = self.fixture(rebind(value))
            self.reject(record, pins, "lifecycle")
        _, record, pins = self.fixture()
        for now in (NOW.replace(tzinfo=None), NOW - dt.timedelta(minutes=6), NOW.replace(minute=45), NOW.replace(hour=1)):
            self.reject(record, pins, "clock|window", now)

    def test_signed_conflicting_bytes_and_wrong_bootstrap_rollback_still_close(self):
        _, record, pins = self.fixture()
        changed = candidate()
        changed["control"]["activationEvidenceSha256"] = "f" * 64
        _, conflicting_record, _ = self.fixture(rebind(changed))
        self.assertEqual(record.blob, conflicting_record.blob)
        self.reject(conflicting_record, pins, "marker-readback")
        changed = candidate()
        changed["rollback"]["acceptedManifest"]["blob"] = f"v2/accepted/{'e' * 40}/bootstrap-consumed/manifest.json"
        _, record, pins = self.fixture(rebind(changed))
        self.reject(record, pins, "rollback-bootstrap-source")

    def test_no_provider_source_or_runtime_wiring(self):
        source = Path(reader.__file__).read_text(encoding="utf-8")
        for forbidden in ("subprocess", "urllib", "KeyVaultSigner", "BlobWorm(", "_create_read_exact(", "_load_accepted(", "resolve_current_accepted("):
            self.assertNotIn(forbidden, source)
        self.assertFalse(any("provisional_defender_authorization" in item[0] for item in package_builder.SOURCES))
        workflow = Path(reader.__file__).resolve().parents[1] / ".github" / "workflows"
        for path in workflow.glob("*.yml"):
            self.assertNotIn("provisional_defender_authorization", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
