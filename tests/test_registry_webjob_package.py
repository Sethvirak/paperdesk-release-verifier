import hashlib
import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
CONTROL = ROOT / ".github" / "workflows" / "azure-production-control.yml"
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
            self.assertEqual(first_result["status"], "built-source-ready")

            expected_root = "App_Data/jobs/triggered/paperdesk-accepted-release-registry"
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(
                    archive.namelist(),
                    [
                        f"{expected_root}/run.sh",
                        f"{expected_root}/settings.job",
                        f"{expected_root}/accepted_release_registry.py",
                    ],
                )
                for info in archive.infolist():
                    self.assertEqual(info.date_time, builder.FIXED_TIMESTAMP)
                    self.assertEqual(info.compress_type, zipfile.ZIP_STORED)
                    self.assertEqual(info.create_system, 3)
                    self.assertTrue(stat.S_ISREG(info.external_attr >> 16))
                self.assertEqual(
                    [oct((info.external_attr >> 16) & 0o777) for info in archive.infolist()],
                    ["0o755", "0o644", "0o644"],
                )
                runner = archive.read(f"{expected_root}/run.sh").decode("utf-8")
                settings = archive.read(f"{expected_root}/settings.job")
                helper = archive.read(f"{expected_root}/accepted_release_registry.py")

            self.assertIn("python3 -I", runner)
            self.assertIn("persist-actions-artifact", runner)
            self.assertIn("runtime-canary", runner)
            self.assertNotIn("PAPERDESK_REGISTRY_WRITER_CLIENT_ID", runner)
            self.assertIn(hashlib.sha256(helper).hexdigest(), runner)
            self.assertEqual(
                settings,
                b'{\n  "is_singleton": true,\n  "stopping_wait_time": 60,\n  "shutdownGraceTimeLimit": 120\n}\n',
            )
            self.assertEqual(
                helper,
                (ROOT / "scripts" / "accepted_release_registry.py")
                .read_text(encoding="utf-8")
                .replace("\r\n", "\n")
                .replace("\r", "\n")
                .encode("utf-8"),
            )

            workflow = CONTROL.read_text(encoding="utf-8")
            file_digests = {record["path"]: record["sha256"] for record in first_result["files"]}
            expected_hashes = {
                "EXPECTED_PACKAGE_SHA256": first_result["packageSha256"],
                "EXPECTED_RUNNER_SHA256": file_digests[f"{expected_root}/run.sh"],
                "EXPECTED_HELPER_SHA256": file_digests[
                    f"{expected_root}/accepted_release_registry.py"
                ],
            }
            for setting, expected_digest in expected_hashes.items():
                self.assertEqual(
                    workflow.count(f"{setting}: {expected_digest}"),
                    2,
                    f"{setting} must bind both persistence and always-seal steps",
                )

    def test_source_inventory_is_fixed_and_rejects_existing_output(self):
        self.assertEqual(len(builder.SOURCES), 3)
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
