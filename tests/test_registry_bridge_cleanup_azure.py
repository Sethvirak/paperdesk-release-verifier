import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from provider import registry_bridge_cleanup_azure as azure
from provider import registry_bridge_cleanup_runtime as runtime
from provider import registry_bridge_cleanup_watcher as watcher


class FakeCredential:
    def __init__(self, role):
        self.role = role
        self.resources = []

    def get(self, resource):
        self.resources.append(resource)
        return "t" * 120


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def request(self, method, host, target, headers, body, maximum):
        self.requests.append((method, host, target, dict(headers), body, maximum))
        if not self.responses:
            raise AssertionError("unexpected transport request")
        response = self.responses.pop(0)
        if callable(response):
            response = response(self.requests[-1])
        return response


def response(status, body=b"", **headers):
    return azure.HttpResponse(status=status, body=body, headers=headers)


def credentials():
    return {role: FakeCredential(role) for role in azure.IDENTITY_ROLES}


class CleanupAzureBoundaryTests(unittest.TestCase):
    def test_dormant_entry_runs_under_isolated_python_without_search_path(self):
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                str(ROOT / "provider" / "registry_bridge_cleanup_runtime.py"),
                "--once",
            ],
            cwd=ROOT,
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )

        self.assertEqual(completed.returncode, 78)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(
            json.loads(completed.stdout),
            {
                "schemaVersion": 1,
                "status": "source-dormant",
                "reason": "activation-blocked-null-merged-sha",
                "mergedMutatingCommitSha": None,
            },
        )

    def test_dormant_runtime_returns_before_credential_or_boundary_construction(self):
        calls = []

        def forbidden(*args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("dormant runtime crossed credential boundary")

        result = runtime.run_once(
            {},
            credential_loader=forbidden,
            boundary_factory=forbidden,
            contract_path=ROOT / "contracts" / "registry_bridge_cleanup_contract.json",
        )

        self.assertEqual(result, {
            "schemaVersion": 1,
            "status": "source-dormant",
            "reason": "activation-blocked-null-merged-sha",
            "mergedMutatingCommitSha": None,
        })
        self.assertEqual(calls, [])

    def test_contract_has_seven_distinct_future_identity_slots_and_loader_rejects_nulls(self):
        contract = watcher.load_contract(
            ROOT / "contracts" / "registry_bridge_cleanup_contract.json"
        )
        slots = contract["watcher"]["managedIdentityClientIds"]
        self.assertEqual(set(slots), azure.IDENTITY_ROLES)
        self.assertTrue(all(value is None for value in slots.values()))
        with self.assertRaisesRegex(
            watcher.CleanupContractError, "watcher-identities-not-activated"
        ):
            azure.build_managed_identity_credentials(contract, {})

        activated = json.loads(json.dumps(contract))
        activated["watcher"]["managedIdentityClientIds"] = {
            role: f"00000000-0000-4000-8000-{index:012d}"
            for index, role in enumerate(sorted(azure.IDENTITY_ROLES), start=1)
        }
        credentials = azure.build_managed_identity_credentials(activated, {})
        self.assertTrue(all(identity.environment == {} for identity in credentials.values()))

    def test_managed_identity_endpoint_rejects_nonlocal_and_resource_is_fixed(self):
        identity = azure.AppServiceManagedIdentity(
            "00000000-0000-4000-8000-000000000001",
            {
                "IDENTITY_ENDPOINT": "http://example.com:8080/MSI/token",
                "IDENTITY_HEADER": "secret",
            },
        )
        with self.assertRaisesRegex(
            watcher.CleanupContractError, "managed-identity-endpoint-not-local"
        ):
            identity.get(azure.STORAGE_RESOURCE)
        with self.assertRaisesRegex(
            watcher.CleanupContractError, "managed-identity-resource-not-fixed"
        ):
            identity.get("https://vault.azure.net/")

    def test_state_create_replace_and_clock_are_etag_cas_with_storage_date(self):
        date = "Sat, 29 Aug 2026 10:20:30 GMT"
        first = watcher.canonical_json({"value": 1})
        second = watcher.canonical_json({"value": 2})
        transport = FakeTransport([
            response(404, date=date),
            response(201, date=date, etag='"ignored"'),
            response(200, first, date=date, etag='"one"'),
            response(201, date=date, etag='"ignored"'),
            response(200, second, date=date, etag='"two"'),
        ])
        boundary = azure.AzureCleanupBoundary(credentials(), transport)

        self.assertEqual(boundary.probe_server_time(), "2026-08-29T10:20:30.000Z")
        created = boundary.create_state(first)
        replaced = boundary.replace_state(second, created.etag)

        self.assertEqual(created.etag, '"one"')
        self.assertEqual(replaced.etag, '"two"')
        put_requests = [request for request in transport.requests if request[0] == "PUT"]
        self.assertEqual(put_requests[0][3]["If-None-Match"], "*")
        self.assertEqual(put_requests[1][3]["If-Match"], '"one"')
        self.assertTrue(all(request[1] == azure.STORAGE_HOST for request in transport.requests))

    def test_evidence_writer_is_create_only_and_readback_uses_distinct_identity(self):
        body = watcher.canonical_json({"status": "sealed"})
        transport = FakeTransport([
            response(201),
            response(200, body),
        ])
        creds = credentials()
        boundary = azure.AzureCleanupBoundary(creds, transport)

        self.assertTrue(boundary.create_evidence(
            watcher.EVIDENCE_CONTAINER,
            "v1/registry-bridge-cleanup/session/1.json",
            body,
        ))
        self.assertEqual(
            boundary.read_evidence(
                watcher.EVIDENCE_CONTAINER,
                "v1/registry-bridge-cleanup/session/1.json",
                8192,
            ),
            body,
        )
        self.assertEqual(transport.requests[0][3]["If-None-Match"], "*")
        self.assertEqual(creds["evidence-create-only"].resources, [azure.STORAGE_RESOURCE])
        self.assertEqual(creds["evidence-read-only"].resources, [azure.STORAGE_RESOURCE])

    def test_transient_cleanup_removes_only_exact_names_and_preserves_unknowns(self):
        original = {
            **watcher.PERSISTENT_SETTINGS,
            watcher.TRANSIENT_SETTINGS[0]: "sensitive",
            "UNKNOWN_SETTING": "preserved-for-indeterminate-receipt",
        }
        retained = {
            **watcher.PERSISTENT_SETTINGS,
            "UNKNOWN_SETTING": "preserved-for-indeterminate-receipt",
        }
        transport = FakeTransport([
            response(200, json.dumps({"properties": original}).encode("utf-8"), etag='"settings-v1"'),
            response(200, b"{}"),
            response(200, json.dumps({"properties": retained}).encode("utf-8"), etag='"settings-v2"'),
        ])
        boundary = azure.AzureCleanupBoundary(credentials(), transport)

        boundary.delete_transient_settings(watcher.TRANSIENT_SETTINGS)

        written = json.loads(transport.requests[1][4].decode("utf-8"))
        self.assertEqual(written, {"properties": retained})
        self.assertNotIn(watcher.TRANSIENT_SETTINGS[0], written["properties"])
        self.assertIn("UNKNOWN_SETTING", written["properties"])
        self.assertEqual(transport.requests[1][3]["If-Match"], '"settings-v1"')

    def test_transient_cleanup_fails_closed_on_etag_conflict_without_retry(self):
        original = {
            **watcher.PERSISTENT_SETTINGS,
            watcher.TRANSIENT_SETTINGS[0]: "sensitive",
        }
        transport = FakeTransport([
            response(200, json.dumps({"properties": original}).encode("utf-8"), etag='"settings-v1"'),
            response(412, b"{}"),
        ])
        boundary = azure.AzureCleanupBoundary(credentials(), transport)

        with self.assertRaisesRegex(
            watcher.CleanupContractError, "bridge-settings-cleanup-conflict"
        ):
            boundary.delete_transient_settings(watcher.TRANSIENT_SETTINGS)

        self.assertEqual(len(transport.requests), 2)
        self.assertEqual(transport.requests[1][3]["If-Match"], '"settings-v1"')

    def test_transient_cleanup_requires_a_strong_settings_etag_before_put(self):
        original = {
            **watcher.PERSISTENT_SETTINGS,
            watcher.TRANSIENT_SETTINGS[0]: "sensitive",
        }
        transport = FakeTransport([
            response(200, json.dumps({"properties": original}).encode("utf-8")),
        ])
        boundary = azure.AzureCleanupBoundary(credentials(), transport)

        with self.assertRaisesRegex(
            watcher.CleanupContractError, "bridge-settings-etag"
        ):
            boundary.delete_transient_settings(watcher.TRANSIENT_SETTINGS)
        self.assertEqual(len(transport.requests), 1)

    def test_adapter_has_no_bridge_start_webjob_run_deploy_role_write_or_delete(self):
        source = (ROOT / "provider" / "registry_bridge_cleanup_azure.py").read_text(
            encoding="utf-8"
        )
        class_source = source.split("class AzureCleanupBoundary:", 1)[1]
        for forbidden in (
            "def start_bridge",
            "def run_webjob",
            "def deploy",
            "def publish",
            "def write_role",
            "def delete_blob",
            "accepted_release",
        ):
            self.assertNotIn(forbidden, class_source.lower())


if __name__ == "__main__":
    unittest.main()
