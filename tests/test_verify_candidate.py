import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_candidate as verifier


MASTER_SIDE_RELEASE_MATERIALS_VECTOR = [
    {"path": "widget-showcase/package.json", "bytes": 648, "sha256": "e" * 64},
    {"path": "package.json", "bytes": 120154, "sha256": "d" * 64},
    {
        "path": "architecture/production_acceptance_evidence_contract.json",
        "bytes": 7196,
        "sha256": "a" * 64,
    },
    {"path": "widget-showcase/package-lock.json", "bytes": 249372, "sha256": "c" * 64},
    {"path": "package-lock.json", "bytes": 421162, "sha256": "b" * 64},
]
MASTER_SIDE_RELEASE_MATERIALS_STABLE_JSON = b'''[
  {
    "bytes": 7196,
    "path": "architecture/production_acceptance_evidence_contract.json",
    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  {
    "bytes": 421162,
    "path": "package-lock.json",
    "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  },
  {
    "bytes": 120154,
    "path": "package.json",
    "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  },
  {
    "bytes": 249372,
    "path": "widget-showcase/package-lock.json",
    "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  },
  {
    "bytes": 648,
    "path": "widget-showcase/package.json",
    "sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  }
]
'''
MASTER_SIDE_RELEASE_MATERIALS_SHA256 = "da17069e35c6e72c6f5d0e011bab35985d16a6c61be93ff493f7efed1a3f5b8c"


class ReleaseMaterialsDirectoryDigestTests(unittest.TestCase):
    def test_stable_json_matches_master_side_key_order_and_format(self):
        records = sorted(
            MASTER_SIDE_RELEASE_MATERIALS_VECTOR,
            key=lambda record: record["path"].encode("utf-8"),
        )

        self.assertEqual(verifier.stable_json(records), MASTER_SIDE_RELEASE_MATERIALS_STABLE_JSON)
        self.assertEqual(
            verifier.sha256_bytes(MASTER_SIDE_RELEASE_MATERIALS_STABLE_JSON),
            MASTER_SIDE_RELEASE_MATERIALS_SHA256,
        )

    def test_directory_digest_matches_master_side_five_path_vector(self):
        tree_records = [
            {"path": record["path"], "size": record["bytes"], "sha256": record["sha256"]}
            for record in MASTER_SIDE_RELEASE_MATERIALS_VECTOR
        ]

        with mock.patch.object(verifier, "tree_records", return_value=tree_records):
            self.assertEqual(
                verifier.directory_digest(Path("unused-by-golden-vector")),
                MASTER_SIDE_RELEASE_MATERIALS_SHA256,
            )

    def test_directory_digest_matches_master_side_real_prefix_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "a").mkdir()
            (root / "a" / "x.txt").write_bytes(b"nested\n")
            (root / "a.txt").write_bytes(b"sibling\n")
            (root / "z.txt").write_bytes(b"last\n")

            self.assertEqual(
                verifier.directory_digest(root),
                "b845fa346d5cabafc2b85c44994cfeba2c013e41ef991fc0e34fea79b4b41edb",
            )


class ArchiveVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.expected = self.root / "expected"
        (self.expected / "nested").mkdir(parents=True)
        (self.expected / "nested" / "file.txt").write_text("trusted bytes\n", encoding="utf-8")
        self.archive = self.root / "candidate.tar.gz"
        with tarfile.open(self.archive, "w:gz") as handle:
            handle.add(self.expected, arcname=".")

    def tearDown(self):
        self.temporary.cleanup()

    def test_exact_archive_passes(self):
        verifier.verify_archive(self.archive, self.expected)

    def test_link_member_fails(self):
        hostile = self.root / "link.tar.gz"
        with tarfile.open(hostile, "w:gz") as handle:
            directory = tarfile.TarInfo("nested")
            directory.type = tarfile.DIRTYPE
            directory.mode = stat.S_IMODE((self.expected / "nested").stat().st_mode)
            handle.addfile(directory)
            link = tarfile.TarInfo("nested/file.txt")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../outside"
            handle.addfile(link)
        with self.assertRaisesRegex(ValueError, "linked member"):
            verifier.verify_archive(hostile, self.expected)

    def test_changed_bytes_fail(self):
        hostile = self.root / "changed.tar.gz"
        payload = b"hostile bytes\n"
        with tarfile.open(hostile, "w:gz") as handle:
            directory = tarfile.TarInfo("nested")
            directory.type = tarfile.DIRTYPE
            directory.mode = stat.S_IMODE((self.expected / "nested").stat().st_mode)
            handle.addfile(directory)
            member = tarfile.TarInfo("nested/file.txt")
            member.size = len(payload)
            member.mode = stat.S_IMODE((self.expected / "nested" / "file.txt").stat().st_mode)
            handle.addfile(member, io.BytesIO(payload))
        with self.assertRaisesRegex(ValueError, "size differs|bytes differ"):
            verifier.verify_archive(hostile, self.expected)


class ManifestModeContractTests(unittest.TestCase):
    @staticmethod
    def record(path, mode="0644", **extra):
        result = {"path": path, "size": 1, "sha256": "a" * 64}
        if mode is not None:
            result["mode"] = mode
        result.update(extra)
        return result

    def test_package_input_modes_are_required_and_path_authorized(self):
        records = [
            self.record(verifier.EXECUTABLE_PACKAGE_SOURCE, "0755"),
            self.record("app.js", generatedOwner="generated-shadcn"),
        ]
        verifier.validate_records(
            records,
            "package input files",
            require_mode=True,
            allow_generated_owner=True,
        )
        for record in (
            self.record("app.js", None),
            self.record("app.js", 0o644),
            self.record("app.js", "0777"),
            self.record("app.js", "0755"),
            self.record(verifier.EXECUTABLE_PACKAGE_SOURCE, "0644"),
        ):
            with self.subTest(record=record), self.assertRaisesRegex(ValueError, "invalid record|unauthorized mode"):
                verifier.validate_records(
                    [record],
                    "package input files",
                    require_mode=True,
                    allow_generated_owner=True,
                )

    def test_record_schemas_are_context_specific(self):
        release = self.record(verifier.RELEASE_MATERIALS[0])
        verifier.validate_records([release], "release materials", require_mode=True)
        dependency = self.record("dependency/package.json", mode=None)
        verifier.validate_records([dependency], "production dependencies")
        runtime = self.record("server/paperdesk-release-sha.txt")
        verifier.validate_records([runtime], "runtime files", require_mode=True)
        release_without_mode = {key: value for key, value in release.items() if key != "mode"}
        runtime_without_mode = {key: value for key, value in runtime.items() if key != "mode"}
        for record, label, options in (
            (release_without_mode, "release materials", {"require_mode": True}),
            ({**release, "mode": "0755"}, "release materials", {"require_mode": True}),
            ({**release, "generatedOwner": "unexpected"}, "release materials", {"require_mode": True}),
            ({**dependency, "mode": "0644"}, "production dependencies", {}),
            (runtime_without_mode, "runtime files", {"require_mode": True}),
            ({**runtime, "generatedOwner": "unexpected"}, "runtime files", {"require_mode": True}),
        ):
            with self.subTest(label=label, record=record), self.assertRaisesRegex(ValueError, "invalid record|unauthorized mode"):
                verifier.validate_records([record], label, **options)

    def test_manifest_boundaries_accept_exact_modes_and_reject_runtime_tamper(self):
        source_sha = "b" * 40
        with tempfile.TemporaryDirectory() as temporary:
            runtime_root = Path(temporary)
            source_files = {
                verifier.EXECUTABLE_PACKAGE_SOURCE: b"#!/bin/sh\n",
                "app.js": b"trusted\n",
            }
            for relative, body in source_files.items():
                path = runtime_root.joinpath(*relative.split("/"))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(body)
                if os.name != "nt":
                    path.chmod(0o755 if relative == verifier.EXECUTABLE_PACKAGE_SOURCE else 0o644)

            input_records = []
            for relative in sorted(source_files):
                path = runtime_root.joinpath(*relative.split("/"))
                input_records.append({
                    "path": relative,
                    "size": path.stat().st_size,
                    "sha256": verifier.sha256_file(path),
                    "mode": verifier.authorized_file_mode(relative),
                })
            release_records = [self.record(path) for path in verifier.RELEASE_MATERIALS]
            input_document = {
                "schema": "paperdesk-azure-package-input-manifest-v1",
                "repositoryCommit": source_sha,
                "files": input_records,
                "releaseMaterials": release_records,
                "productionDependencies": [],
            }
            embedded_input = runtime_root / verifier.RUNTIME_INPUT
            embedded_input.parent.mkdir(parents=True, exist_ok=True)
            embedded_input.write_text(json.dumps(input_document), encoding="utf-8")
            release_marker = runtime_root / verifier.RELEASE_SHA
            release_marker.write_text(f"{source_sha}\n", encoding="utf-8")
            if os.name != "nt":
                embedded_input.chmod(0o644)
                release_marker.chmod(0o644)

            runtime_records = verifier.tree_records(runtime_root)
            runtime_records = [
                {**record, "mode": verifier.authorized_file_mode(record["path"])}
                for record in runtime_records
            ]
            runtime_document = {
                "schema": "paperdesk-azure-runtime-file-manifest-v1",
                "repositoryCommit": source_sha,
                "releaseSha": source_sha,
                "selfExcludedPath": verifier.RUNTIME_MANIFEST,
                "inputManifest": {
                    "path": verifier.RUNTIME_INPUT,
                    "sha256": verifier.sha256_file(embedded_input),
                },
                "files": runtime_records,
            }
            verifier.verify_manifest_boundaries(input_document, runtime_document, source_sha, runtime_root)
            tampered = {**runtime_document, "files": [dict(record) for record in runtime_records]}
            executable = next(
                record for record in tampered["files"] if record["path"] == verifier.EXECUTABLE_PACKAGE_SOURCE
            )
            executable["mode"] = "0644"
            with self.assertRaisesRegex(ValueError, "unauthorized mode"):
                verifier.verify_manifest_boundaries(input_document, tampered, source_sha, runtime_root)

    @unittest.skipIf(os.name == "nt", "POSIX mode evidence is enforced on the Linux verifier runner")
    def test_reconstructed_package_source_mode_downgrade_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            canary = root.joinpath(*verifier.EXECUTABLE_PACKAGE_SOURCE.split("/"))
            canary.parent.mkdir(parents=True)
            canary.write_text("#!/bin/sh\n", encoding="utf-8")
            canary.chmod(0o644)
            record = {
                "path": verifier.EXECUTABLE_PACKAGE_SOURCE,
                "size": canary.stat().st_size,
                "sha256": verifier.sha256_file(canary),
                "mode": "0755",
            }
            with self.assertRaisesRegex(ValueError, "reconstructed package source mode"):
                verifier.verify_package_source_modes(root, [record])


if __name__ == "__main__":
    unittest.main()
