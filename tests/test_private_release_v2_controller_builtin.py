"""Controller grants preserve provider definitions across success and recovery."""
import copy
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import private_release_v2_bootstrap as bootstrap
from tests import test_private_release_v2_bootstrap as fixtures

ADD = "addOwnedOperatorControllerCanaryRole"
REMOVE = "removeOwnedOperatorControllerCanaryRole"


class ControllerBuiltinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.plan_sha = bootstrap.load_plan()
        cls.package = bootstrap.build_package_descriptor()

    def fixture(self, folder, *, ambiguous=False):
        receipt = Path(folder) / ("paperdesk-private-release-v2-bootstrap-" + fixtures.AUTH_ID)
        projection = fixtures.build_projection(self.plan, self.package)
        authorization = fixtures.build_authorization(self.plan, self.plan_sha, self.package, projection, receipt)
        current = [fixtures.NOW]
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=authorization, plan=self.plan, package=self.package,
            preflight={"projection": projection}, clock=lambda: current[0],
            sleep=lambda seconds: current.__setitem__(0, current[0] + dt.timedelta(seconds=seconds)),
            session=mock.Mock(),
        )
        definition = fixtures.build_builtin_role_definition_projections(self.plan)[bootstrap.CONTROLLER_BUILTIN_ROLE_ID]
        definition_url = transport._arm_url(definition["id"], "2022-04-01")
        assignment_id = transport.plan["temporaryAccess"]["temporaryControllerRoleAssignmentId"]
        scope = transport.resources["controllerLockContainer"]["resourceId"]
        assignment_resource = scope + "/providers/Microsoft.Authorization/roleAssignments/" + assignment_id
        assignment_url = transport._arm_url(assignment_resource, "2022-04-01")
        assignment = {
            "id": assignment_resource, "name": assignment_id, "type": "Microsoft.Authorization/roleAssignments",
            "properties": {
                "principalId": fixtures.ACCOUNT_OBJECT, "principalType": "User", "roleDefinitionId": definition["id"],
                "scope": scope, "condition": None, "conditionVersion": None, "delegatedManagedIdentityResourceId": None,
                "description": bootstrap._temporary_role_marker(fixtures.AUTH_ID, "operator-controller-canary-role"),
            },
        }

        class Session:
            def __init__(self):
                self.definition = copy.deepcopy(definition)
                self.present = False
                self.calls = []
                self.drift_on_put = False

            def request(self, method, url, **kwargs):
                self.calls.append((method, url))
                if url == definition_url:
                    if method != "GET":
                        raise AssertionError("Attempted to mutate Microsoft-owned definition")
                    return bootstrap._RestResponse(200, bootstrap.canonical_json_bytes(self.definition), {})
                if url != assignment_url:
                    raise AssertionError("Request escaped exact controller assignment scope")
                if method == "GET":
                    return bootstrap._RestResponse(200, bootstrap.canonical_json_bytes(assignment), {}) if self.present else bootstrap._RestResponse(404, b"", {})
                if method == "PUT":
                    if self.present:
                        raise AssertionError("Assignment mutation was retried")
                    expected = {k: assignment["properties"][k] for k in ("principalId", "principalType", "roleDefinitionId", "description")}
                    if json.loads(kwargs["body"])["properties"] != expected:
                        raise AssertionError("Assignment body escaped reviewed principal or role")
                    self.present = True
                    if self.drift_on_put:
                        self.definition["properties"]["permissions"][0]["dataActions"].append("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/write")
                    return bootstrap._RestResponse(500 if ambiguous else 201, b"", {})
                if method == "DELETE":
                    self.present = False
                    return bootstrap._RestResponse(204, b"", {})
                raise AssertionError("Unexpected assignment method")

        session = Session()
        transport.session = session
        ledger = bootstrap.UseLedger(directory=receipt, authorization_id=fixtures.AUTH_ID,
            authorization_sha256=bootstrap.sha256_bytes(bootstrap.canonical_json_bytes(authorization)),
            source_sha=fixtures.MERGE, plan_sha256=self.plan_sha, claimed_at=fixtures.stamp(fixtures.NOW))
        ledger.claim()
        transport.bind_journal(ledger)
        transport._active_operation_id = ADD
        return transport, session, assignment, definition, assignment_url, definition_url

    def cleanup(self, transport, assignment, details):
        def guarded_delete(operation_id, resource_id, expected_projection):
            self.assertEqual(operation_id, REMOVE)
            self.assertEqual(resource_id, assignment["id"])
            self.assertEqual(expected_projection, bootstrap._project_role_assignment(assignment))
            transport._arm_delete(resource_id, "2022-04-01")
            transport._last_guarded_assignment_was_present = True
            return bootstrap._expected_deletion_lock_proof(REMOVE)

        transport._active_operation_id = REMOVE
        with mock.patch.object(transport, "_guarded_assignment_delete", side_effect=guarded_delete) as guard, mock.patch.object(
            transport, "_prove_temporary_role_marker_inventories_absent", return_value="0" * 64
        ):
            result = transport._mutate_temporary_role_impl(REMOVE, {"proofs": {ADD: {"details": details}}})
        guard.assert_called_once()
        return result

    def test_success_creates_and_deletes_only_assignment_and_preserves_definition(self):
        with tempfile.TemporaryDirectory() as folder:
            transport, session, assignment, definition, assignment_url, definition_url = self.fixture(folder)
            details = transport._mutate_temporary_role_impl(ADD, {})
            self.assertFalse(details["definitionAttempted"])
            self.assertFalse(details["definitionCreated"])
            self.assertTrue(details["assignmentReadbackExact"])
            cleanup = self.cleanup(transport, assignment, details)
            self.assertFalse(cleanup["definitionRemoved"])
            self.assertNotIn("definitionAbsenceProjection", cleanup)
            self.assertEqual(cleanup["definitionPreservationProjection"], {"resourceId": definition["id"], "present": True, "projection": definition})
            self.assertEqual([call for call in session.calls if call[0] != "GET"], [("PUT", assignment_url), ("DELETE", assignment_url)])
            self.assertTrue(all(method == "GET" for method, url in session.calls if url == definition_url))

    def test_ambiguous_assignment_create_recovers_without_owning_builtin_definition(self):
        with tempfile.TemporaryDirectory() as folder:
            transport, session, assignment, definition, assignment_url, _ = self.fixture(folder, ambiguous=True)
            with self.assertRaises(bootstrap.OwnedTemporaryMutationError) as raised:
                transport._mutate_temporary_role_impl(ADD, {})
            details = raised.exception.proof["details"]
            self.assertTrue(details["assignmentAmbiguous"])
            self.assertFalse(details["definitionCreated"])
            cleanup = self.cleanup(transport, assignment, details)
            self.assertTrue(cleanup["assignmentRemoved"])
            self.assertEqual(cleanup["definitionPreservationProjection"]["projection"], definition)
            self.assertEqual([call for call in session.calls if call[0] != "GET"], [("PUT", assignment_url), ("DELETE", assignment_url)])

    def test_live_builtin_permission_drift_blocks_assignment_creation(self):
        with tempfile.TemporaryDirectory() as folder:
            transport, session, _, _, _, _ = self.fixture(folder)
            session.definition["properties"]["permissions"][0]["dataActions"].append("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/write")
            with self.assertRaisesRegex(bootstrap.BootstrapError, "authorization-bound built-in"):
                transport._mutate_temporary_role_impl(ADD, {})
            self.assertTrue(all(method == "GET" for method, _ in session.calls))

    def test_cleanup_rejects_fabricated_builtin_ownership(self):
        with tempfile.TemporaryDirectory() as folder:
            transport, session, _, _, _, _ = self.fixture(folder)
            details = transport._mutate_temporary_role_impl(ADD, {})
            details["definitionCreated"] = True
            transport._active_operation_id = REMOVE
            with self.assertRaisesRegex(bootstrap.BootstrapError, "cannot be executor-owned"):
                transport._mutate_temporary_role_impl(REMOVE, {"proofs": {ADD: {"details": details}}})
            self.assertFalse(any(method == "DELETE" for method, _ in session.calls))

    def test_builtin_change_during_grant_retains_owned_assignment_for_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            transport, session, _, _, assignment_url, _ = self.fixture(folder)
            session.drift_on_put = True
            with self.assertRaises(bootstrap.OwnedTemporaryMutationError) as raised:
                transport._mutate_temporary_role_impl(ADD, {})
            self.assertTrue(raised.exception.proof["details"]["assignmentCreated"])
            self.assertFalse(raised.exception.proof["details"]["definitionCreated"])
            self.assertEqual([c for c in session.calls if c[0] != "GET"], [("PUT", assignment_url)])

    def test_mutation_allowlist_rejects_builtin_definition_and_wrong_assignment_scope(self):
        with tempfile.TemporaryDirectory() as folder:
            _, _, _, _, assignment_url, definition_url = self.fixture(folder)
            for operation, method in ((ADD, "PUT"), (REMOVE, "DELETE")):
                def allowed(url):
                    return bootstrap._mutation_target_allowed(operation, method, url, plan=self.plan, authorization_id=fixtures.AUTH_ID, source_sha=fixtures.MERGE)
                self.assertTrue(allowed(assignment_url))
                self.assertFalse(allowed(definition_url))
                self.assertFalse(allowed(assignment_url.replace("paperdesk-release-controller-lock", "paperdesk-deployment-packages")))

    def test_marker_inventory_allows_permanent_builtin_but_rejects_owned_assignment(self):
        with tempfile.TemporaryDirectory() as folder:
            transport, _, assignment, definition, _, _ = self.fixture(folder)
            permanent = {"id": "/unrelated/permanent-assignment", "properties": {"roleDefinitionId": definition["id"], "description": None}}
            bootstrap._reject_residual_temporary_role_assignments([permanent], plan=transport.plan, label="permanent control")
            unmarked = copy.deepcopy(assignment)
            unmarked["properties"]["description"] = None
            with self.assertRaisesRegex(bootstrap.BootstrapError, "residual PaperDesk temporary"):
                bootstrap._reject_residual_temporary_role_assignments([unmarked], plan=transport.plan, label="owned control")


if __name__ == "__main__":
    unittest.main()
