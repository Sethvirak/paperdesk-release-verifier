import hashlib
import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_registry_webjob", ROOT / "scripts" / "build_registry_webjob.py"
)
builder = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(builder)


class RegistryWebJobPackageTests(unittest.TestCase):
    def test_package_is_deterministic_and_has_exact_fixed_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first.zip"
            second = root / "second.zip"
            first_result = builder.build(first)
            second_result = builder.build(second)

            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(
                first_result["packageSha256"],
                hashlib.sha256(first.read_bytes()).hexdigest(),
            )
            self.assertEqual(first_result["packageSha256"], second_result["packageSha256"])
            self.assertEqual(first_result["status"], "built-dormant")

            expected_root = "App_Data/jobs/triggered/paperdesk-accepted-release-registry"
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(
                    archive.namelist(),
                    [
                        f"{expected_root}/run.sh",
                        f"{expected_root}/accepted_release_registry.py",
                    ],
                )
                for info in archive.infolist():
                    self.assertEqual(info.date_time, builder.FIXED_TIMESTAMP)
                    self.assertEqual(info.compress_type, zipfile.ZIP_STORED)
                    self.assertEqual(info.create_system, 3)
                    self.assertTrue(stat.S_ISREG(info.external_attr >> 16))
                runner = archive.read(f"{expected_root}/run.sh").decode("utf-8")
                helper = archive.read(f"{expected_root}/accepted_release_registry.py")

            self.assertIn("python3 -I", runner)
            self.assertIn("persist-actions-artifact", runner)
            self.assertNotIn("PAPERDESK_REGISTRY_WRITER_CLIENT_ID", runner)
            self.assertEqual(
                helper,
                (ROOT / "scripts" / "accepted_release_registry.py")
                .read_text(encoding="utf-8")
                .replace("\r\n", "\n")
                .replace("\r", "\n")
                .encode("utf-8"),
            )

    def test_source_inventory_is_fixed_and_rejects_existing_output(self):
        self.assertEqual(len(builder.SOURCES), 2)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.zip"
            target.write_bytes(b"existing")
            with self.assertRaises(builder.PackageError):
                builder.build(target)
            link = root / "link.zip"
            try:
                link.symlink_to(target)
            except OSError:
                return
            else:
                with self.assertRaises(builder.PackageError):
                    builder.build(link)


if __name__ == "__main__":
    unittest.main()
