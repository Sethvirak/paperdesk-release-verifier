"""Exact V2 custody proof from a real producer-built transfer archive."""

import base64
import datetime as dt
import gzip
import hashlib
import io
import json
import tarfile
import unittest
from unittest import mock

from scripts import private_release_mailbox as box
from scripts import private_release_v2_accepted_proof as proof
from tests.test_private_release_mailbox import accepted_transfer, archive
from tests import test_accepted_release_registry as producer_fixture


def descriptor(blob, body=b"bundle"):
    return {"blob": blob, "sha256": hashlib.sha256(body).hexdigest(),
            "size": len(body), "etag": '"exact"', "versionId": "version-1"}


def rewrite_archive(raw, *, remove=None, duplicate=None, transform=None, pax_headers=None):
    entries = []
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as source:
        for member in source:
            if member.name == remove:
                continue
            body = source.extractfile(member).read()
            if transform is not None:
                body = transform(member.name, body)
            entries.append((member.name, body))
    if duplicate is not None:
        entries.append((duplicate, b"duplicate"))
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT,
                      pax_headers=pax_headers) as target:
        for name, body in entries:
            member = tarfile.TarInfo(name)
            member.size = len(body)
            member.mode = 0o600
            member.mtime = member.uid = member.gid = 0
            target.addfile(member, io.BytesIO(body))
    return output.getvalue()


class AcceptedProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime = archive()
        cls.transfer = accepted_transfer(runtime)
        cls.runtime_sha256 = hashlib.sha256(runtime).hexdigest()

    def values(self, raw=None):
        raw = self.transfer if raw is None else raw
        sha = producer_fixture.SHA
        pending = descriptor(f"v2/pending/{sha}/41001-2-93002/manifest.json")
        consumed = descriptor(f"v2/pending/{sha}/41001-2-93002/consumed.json")
        pending_bundle = descriptor(f"v1/pending/{sha}/41001-2-93002/deployment.zip")
        accepted_bundle = descriptor(f"v1/accepted/{sha}/41501-4/42001-1/deployment.zip")
        request = {
            "sourceSha": sha, "sourceRunId": producer_fixture.SOURCE_RUN,
            "sourceRunAttempt": producer_fixture.SOURCE_ATTEMPT,
            "candidateRunId": producer_fixture.DEPLOYMENT_RUN,
            "candidateRunAttempt": producer_fixture.DEPLOYMENT_ATTEMPT,
            "acceptanceRunId": producer_fixture.ACCEPTANCE_RUN,
            "acceptanceRunAttempt": producer_fixture.ACCEPTANCE_ATTEMPT,
            "artifactMember": "paperdesk-accepted-release-request.tar.gz",
            "artifactMemberSha256": hashlib.sha256(raw).hexdigest(),
        }
        return raw, request, pending, consumed, pending_bundle, accepted_bundle

    def validate(self, raw=None):
        raw, request, pending, consumed, pending_bundle, accepted_bundle = self.values(raw)
        evidence = proof.validate_transfer(raw, request=request, pending_release=pending,
            consumed_marker=consumed, pending_bundle=pending_bundle,
            candidate_runtime_sha256=self.runtime_sha256,
            now=dt.datetime(2026, 8, 29, tzinfo=dt.timezone.utc))
        sealed = proof.seal_proof(evidence, accepted_bundle)
        return sealed, (request, pending, consumed, accepted_bundle)

    def test_real_producer_archive_seals_exact_compact_v2_proof(self):
        sealed, (request, pending, consumed, bundle) = self.validate()
        self.assertEqual(sealed["sourceSha"], producer_fixture.SHA)
        self.assertEqual(sealed["releaseCoordinates"]["acceptanceRunId"], producer_fixture.ACCEPTANCE_RUN)
        self.assertEqual(sealed["pendingRelease"], pending)
        self.assertEqual(sealed["consumedMarker"], consumed)
        self.assertEqual(sealed["deploymentBundle"], bundle)
        self.assertEqual(sealed["acceptedTransferSha256"], request["artifactMemberSha256"])
        self.assertEqual(proof.validate_proof(sealed, source_sha=request["sourceSha"],
            coordinates=sealed["releaseCoordinates"], pending_release=pending,
            consumed_marker=consumed, accepted_bundle=bundle,
            transfer_sha256=request["artifactMemberSha256"]), sealed)

    def test_missing_duplicate_and_altered_members_are_rejected(self):
        receipt = f"payload/receipts/paperdesk-production-acceptance-receipt-{producer_fixture.SHA}.json"
        cases = {
            "missing": rewrite_archive(self.transfer, remove=receipt),
            "duplicate": rewrite_archive(self.transfer, duplicate=receipt),
            "altered-receipt": rewrite_archive(self.transfer, transform=lambda name, body: body + b" " if name == receipt else body),
        }
        for label, raw in cases.items():
            with self.subTest(label=label), self.assertRaises(proof.AcceptedProofError):
                self.validate(raw)

    def test_cross_wired_run_and_duplicate_json_key_are_rejected(self):
        def wrong_run(name, body):
            if name != "request.json":
                return body
            value = json.loads(body)
            value["deployment"]["runId"] = "99999"
            return proof.canonical(value)

        duplicate_key = lambda name, body: body.replace(b'"source":', b'"source":{},"source":', 1) if name == "request.json" else body
        for label, transform in (("wrong-run", wrong_run), ("duplicate-key", duplicate_key)):
            with self.subTest(label=label), self.assertRaises(proof.AcceptedProofError):
                self.validate(rewrite_archive(self.transfer, transform=transform))

    def test_reindexed_but_forged_acceptance_receipt_is_rejected(self):
        receipt_path = f"receipts/paperdesk-production-acceptance-receipt-{producer_fixture.SHA}.json"
        with tarfile.open(fileobj=io.BytesIO(self.transfer), mode="r:gz") as transfer:
            request = json.loads(transfer.extractfile("request.json").read())
            receipt = json.loads(transfer.extractfile("payload/" + receipt_path).read())
        receipt["candidateRunId"] = "99999"
        receipt_raw = json.dumps(receipt).encode("utf-8")
        record = next(item for item in request["files"] if item["path"] == receipt_path)
        record.update({"size": len(receipt_raw), "sha256": hashlib.sha256(receipt_raw).hexdigest(),
                       "contentMd5": base64.b64encode(hashlib.md5(receipt_raw, usedforsecurity=False).digest()).decode("ascii")})
        request["artifacts"]["productionAcceptanceReceipt"]["fileSha256"] = record["sha256"]
        replacements = {"request.json": proof.canonical(request), "payload/" + receipt_path: receipt_raw}
        altered = rewrite_archive(self.transfer, transform=lambda name, body: replacements.get(name, body))
        with self.assertRaisesRegex(proof.AcceptedProofError, "accepted-transfer-receipt-binding"):
            self.validate(altered)

    def test_reindexed_member_cannot_keep_stale_verification_digest(self):
        sha = producer_fixture.SHA
        stem = f"verified-artifact/paperdesk-azure-runtime-{sha}"
        cases = {
            "inputManifestSha256": stem + ".package-input.json",
            "runtimeManifestSha256": stem + ".runtime-files.json",
            "rootSbomSha256": stem + ".cdx.json",
            "widgetSbomSha256": stem + ".widget.cdx.json",
            "releaseMaterialsSha256": "verified-artifact/paperdesk-prebuild-release-materials/package.json",
        }
        with tarfile.open(fileobj=io.BytesIO(self.transfer), mode="r:gz") as transfer:
            original_request = json.loads(transfer.extractfile("request.json").read())
            original_members = {path: transfer.extractfile("payload/" + path).read()
                                for path in cases.values()}
        for field, path in cases.items():
            with self.subTest(field=field):
                request = json.loads(json.dumps(original_request))
                member = "payload/" + path
                changed = original_members[path] + b"forged-but-reindexed\n"
                record = next(item for item in request["files"] if item["path"] == path)
                record.update({"size": len(changed), "sha256": hashlib.sha256(changed).hexdigest(),
                               "contentMd5": base64.b64encode(hashlib.md5(changed, usedforsecurity=False).digest()).decode("ascii")})
                # Reindex the transfer's own inventory, leaving the verifier's
                # receipt claim intact. A file-list-only check used to accept it.
                replacements = {member: changed, "request.json": proof.canonical(request)}
                forged = rewrite_archive(self.transfer, transform=lambda name, body: replacements.get(name, body))
                expected = ("accepted-transfer-verification-material-binding" if field == "releaseMaterialsSha256"
                            else "accepted-transfer-verification-member-binding-" + field)
                with self.assertRaisesRegex(proof.AcceptedProofError, expected):
                    self.validate(forged)

    def test_v2_transfer_size_is_below_bridge_zip_intake(self):
        class ReportedSize(bytes):
            def __len__(self):
                return proof.MAX_TRANSFER + 1

        self.assertEqual(proof.MAX_TRANSFER + 64 * 1024, box.MAX_ZIP)
        self.assertLess(proof.MAX_TRANSFER, producer_fixture.registry.MAX_REQUEST_BYTES)
        with self.assertRaisesRegex(proof.AcceptedProofError, "accepted-transfer-size"):
            self.validate(ReportedSize(b"small malformed archive"))

    def test_transfer_archive_rejects_uninventoried_framing(self):
        cases = {
            "raw-trailer": self.transfer + b"EXTRA_UNVALIDATED",
            "second-gzip-member": self.transfer + gzip.compress(b"", mtime=0),
            "extra-tar-plaintext": gzip.compress(gzip.decompress(self.transfer) + b"EXTRA_UNVALIDATED", mtime=0),
            "global-pax-header": rewrite_archive(self.transfer, pax_headers={"ignored": "x" * 100}),
        }
        for label, raw in cases.items():
            with self.subTest(label=label), self.assertRaises(proof.AcceptedProofError):
                self.validate(raw)

    def test_alternate_gzip_compression_of_exact_tar_is_accepted(self):
        alternate = gzip.compress(gzip.decompress(self.transfer), compresslevel=1, mtime=0)
        self.assertEqual(self.validate(alternate)[0]["acceptedTransferSha256"], hashlib.sha256(alternate).hexdigest())

    def test_large_hidden_pax_header_is_rejected_before_allocation(self):
        header = tarfile.TarInfo("untrusted-pax")
        header.type = tarfile.XHDTYPE
        header.size = 512 * 1024 * 1024
        small_archive = gzip.compress(header.tobuf(format=tarfile.PAX_FORMAT) + b"\0" * 1024, mtime=0)
        with self.assertRaisesRegex(proof.AcceptedProofError, "accepted-transfer-pax-header"):
            self.validate(small_archive)

    def test_gzip_output_boundary_waits_for_next_input_chunk(self):
        class BoundaryInflater:
            eof = False
            unused_data = b""
            unconsumed_tail = b""

            def __init__(self):
                self.calls = 0

            def decompress(self, data, output_size):
                self.calls += 1
                if self.calls == 1:
                    self.assert_chunk(data, 64 * 1024)
                    return b"a" * output_size
                if self.calls == 2:
                    self.assert_chunk(data, 0)
                    return b""
                self.assert_chunk(data, 1)
                self.eof = True
                return b""

            @staticmethod
            def assert_chunk(data, size):
                if len(data) != size:
                    raise AssertionError("unexpected compressed input boundary")

        with mock.patch.object(proof.zlib, "decompressobj", return_value=BoundaryInflater()):
            observed = proof._strict_gzip_tar_digest(b"x" * (64 * 1024 + 1))
        self.assertEqual(observed.size, 1024 * 1024)

    def test_wrong_package_or_proof_descriptor_is_rejected(self):
        sealed, (request, pending, consumed, bundle) = self.validate()
        different = dict(bundle, sha256="0" * 64)
        raw, request, pending, consumed, pending_bundle, _ = self.values()
        evidence = proof.validate_transfer(raw, request=request, pending_release=pending,
            consumed_marker=consumed, pending_bundle=pending_bundle,
            candidate_runtime_sha256=self.runtime_sha256,
            now=dt.datetime(2026, 8, 29, tzinfo=dt.timezone.utc))
        with self.assertRaises(proof.AcceptedProofError):
            proof.seal_proof(evidence, different)
        changed = dict(sealed, consumedMarker=dict(consumed, versionId="wrong-version"))
        with self.assertRaises(proof.AcceptedProofError):
            proof.validate_proof(changed, source_sha=request["sourceSha"],
                coordinates=sealed["releaseCoordinates"], pending_release=pending,
                consumed_marker=consumed, accepted_bundle=bundle,
                transfer_sha256=request["artifactMemberSha256"])


if __name__ == "__main__":
    unittest.main()
