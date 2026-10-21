import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock
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

    def test_lazy_baseline_grammar_is_packaged_with_exact_bounded_bytes(self):
        member = "scripts/watchdog_users_closed_baseline_candidate.py"
        registrations = [entry for entry in package.SOURCES if entry[1] == member]
        self.assertEqual(len(registrations), 1)
        source, _, mode, maximum = registrations[0]
        self.assertEqual(source, ROOT / member)
        self.assertEqual((mode, maximum), (0o644, 65536))
        expected = package.source_bytes(source, maximum)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "provider.zip"
            manifest = package.build(output)
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(archive.read(member), expected)
            record = next(item for item in manifest["files"] if item["path"] == member)
            self.assertEqual(record["size"], len(expected))
            self.assertEqual(record["sha256"], hashlib.sha256(expected).hexdigest())
            oversize = Path(temporary) / "oversize-grammar.py"
            oversize.write_bytes(b"x" * (maximum + 1))
            sources = tuple((oversize if path == source else path, name, source_mode, bound)
                            for path, name, source_mode, bound in package.SOURCES)
            refused = Path(temporary) / "oversize-refused.zip"
            with mock.patch.object(package, "SOURCES", sources):
                with self.assertRaisesRegex(package.PackageError, "exceeds its bound"):
                    package.build(refused)
            self.assertFalse(refused.exists())

    def test_packaged_provider_lazy_import_has_no_checkout_fallback_or_external_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "provider.zip"
            extracted = Path(temporary) / "isolated-package"
            package.build(output)
            with zipfile.ZipFile(output) as archive:
                archive.extractall(extracted)
            code = textwrap.dedent("""
                from contextlib import ExitStack
                import os
                from pathlib import Path
                import socket
                import subprocess
                import sys
                import urllib.request
                from unittest import mock

                root = Path(sys.argv[1]).resolve()
                sys.path.insert(0, str(root))
                attempts = []
                def blocked(*args, **kwargs):
                    attempts.append("external-access")
                    raise AssertionError("packaged readback import crossed an external boundary")
                with ExitStack() as guards:
                    for owner, name in (
                        (socket.socket, "connect"), (socket.socket, "connect_ex"),
                        (socket, "create_connection"), (urllib.request, "urlopen"),
                        (urllib.request.OpenerDirector, "open"),
                        (subprocess, "Popen"), (os, "system"),
                    ):
                        guards.enter_context(mock.patch.object(owner, name, new=blocked))
                    from provider import watchdog_state_provider as provider
                    assert Path(provider.__file__).resolve() == root / "provider/watchdog_state_provider.py"
                    try:
                        provider.WatchdogProvider.inspect_users_closed_baseline_readback(object(), {}, {})
                    except provider.ProviderError as error:
                        assert (error.status, error.code) == (400, "users-closed-projection-invalid")
                    else:
                        raise AssertionError("invalid declarations must not reach backend readback")
                    grammar = sys.modules["scripts.watchdog_users_closed_baseline_candidate"]
                    assert Path(grammar.__file__).resolve() == root / "scripts/watchdog_users_closed_baseline_candidate.py"
                assert attempts == []
                print("packaged-lazy-grammar-import-closure-ok")
            """)
            environment = {name: os.environ[name] for name in ("SystemRoot", "TEMP", "TMP")
                           if name in os.environ}
            result = subprocess.run(
                [sys.executable, "-I", "-B", "-c", code, str(extracted)],
                cwd=extracted, env=environment, capture_output=True, text=True, timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "packaged-lazy-grammar-import-closure-ok")
            self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
