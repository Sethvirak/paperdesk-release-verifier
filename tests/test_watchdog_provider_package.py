import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_watchdog_provider_package as package


class WatchdogProviderPackageTests(unittest.TestCase):
    def test_dependency_lock_is_pinned_and_hash_bound(self):
        body = (ROOT / "provider" / "requirements.lock").read_bytes()
        package.validate_dependency_lock(body)
        source = (ROOT / "provider" / "watchdog_state_provider.py").read_text(encoding="utf-8")
        self.assertIn("jwt.decode(", source)
        self.assertIn("jwt.PyJWK.from_dict", source)
        self.assertNotIn("def rsa_verify_rs256", source)
        self.assertNotIn("pow(int.from_bytes", source)
        self.assertNotIn("82148ec5bddac30b51a5b3c1945075f896fa022cb93f8e4a01e9f6ee95292c5f", body.decode("utf-8"))
        self.assertIn("06a32a980526a6ab9a4b9bf8f7385800791e2bb960903cb6b530e4817509a3b7", body.decode("utf-8"))
        self.assertIn("gunicorn==23.0.0", body.decode("utf-8"))
        self.assertIn("packaging==24.2", body.decode("utf-8"))

    def test_startup_is_python_312_gunicorn_wsgi_only(self):
        source = (ROOT / "provider" / "startup.sh").read_text(encoding="utf-8")
        self.assertIn("sys.version_info[:2] == (3, 12)", source)
        self.assertIn("python3 -m gunicorn", source)
        self.assertIn("provider.wsgi:application", source)
        self.assertNotIn("watchdog_state_provider.py serve", source)

    def test_provider_package_is_deterministic_and_has_exact_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first.zip"
            second = Path(temporary) / "second.zip"
            manifest = package.build(first)
            second_manifest = package.build(second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(manifest["packageSha256"], hashlib.sha256(first.read_bytes()).hexdigest())
            self.assertEqual(manifest["packageSha256"], second_manifest["packageSha256"])
            self.assertEqual(manifest["status"], "built-source-ready-activation-blocked")
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(
                    archive.namelist(),
                    [member for _, member, _, _ in package.SOURCES],
                )
                requirements = archive.read("requirements.txt").decode("utf-8")
                self.assertIn("cryptography==50.0.0", requirements)
                self.assertIn("PyJWT==2.13.0", requirements)
                self.assertIn("gunicorn==23.0.0", requirements)
                self.assertEqual(archive.read("contracts/production_release_watchdog_contract.json"), (
                    ROOT / "contracts" / "production_release_watchdog_contract.json"
                ).read_bytes())


if __name__ == "__main__":
    unittest.main()
