import io
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_candidate as verifier


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
