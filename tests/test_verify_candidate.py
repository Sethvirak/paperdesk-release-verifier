import io
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


if __name__ == "__main__":
    unittest.main()
