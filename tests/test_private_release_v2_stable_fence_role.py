import copy
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from scripts import private_release_v2_bootstrap as bootstrap
from tests import test_private_release_v2_bootstrap as fixtures
from tests.test_private_release_v2_package_readiness import MemoryJournal


ADD = "addOwnedOperatorFenceBootstrapRole"
REMOVE = "removeOwnedOperatorFenceBootstrapRole"


class StableFenceRoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.plan_sha = bootstrap.load_plan()
        cls.package = bootstrap.build_package_descriptor()

    def fixture(self, folder):
        receipt = Path(folder) / (
            "paperdesk-private-release-v2-bootstrap-" + fixtures.AUTH_ID
        )
        projection = fixtures.build_projection(self.plan, self.package)
        authorization = fixtures.build_authorization(
            self.plan,
            self.plan_sha,
            self.package,
            projection,
            receipt,
        )
        current = [fixtures.NOW]
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=authorization,
            plan=self.plan,
            package=self.package,
            preflight={"projection": projection},
            clock=lambda: current[0],
            sleep=lambda seconds: current.__setitem__(
                0, current[0] + dt.timedelta(seconds=seconds)
            ),
        )
        fence = bootstrap._stable_fence_role_spec(transport.plan)
        definition = copy.deepcopy(fence["definitionProjection"])
        definition_url = transport._arm_url(
            fence["definitionResourceId"], "2022-04-01"
        )
        assignment_url = transport._arm_url(
            fence["assignmentResourceId"], "2022-04-01"
        )
        metadata = bootstrap._temporary_role_metadata(
            fixtures.AUTH_ID, "operator-fence-bootstrap-role"
        )
        assignment = {
            "id": fence["assignmentResourceId"],
            "name": fence["assignmentId"],
            "type": "Microsoft.Authorization/roleAssignments",
            "properties": {
                "principalId": fixtures.ACCOUNT_OBJECT,
                "principalType": "User",
                "roleDefinitionId": fence["definitionResourceId"],
                "scope": transport.resources["activationFenceContainer"][
                    "resourceId"
                ],
                "condition": None,
                "conditionVersion": None,
                "delegatedManagedIdentityResourceId": None,
                "description": metadata["assignmentDescription"],
            },
        }

        class Session:
            def __init__(self):
                self.definition = copy.deepcopy(definition)
                self.assignment_present = False
                self.calls = []
                self.drift_after_assignment_precheck = False
                self.drift_on_put = False

            def drift_definition(self):
                self.definition["properties"]["permissions"][0][
                    "dataActions"
                ].append(
                    "Microsoft.Storage/storageAccounts/blobServices/"
                    "containers/blobs/tags/write"
                )

            def request(self, method, url, **kwargs):
                self.calls.append((method, url))
                if url == definition_url:
                    if method != "GET":
                        raise AssertionError(
                            "stable fence definition must never be mutated"
                        )
                    return bootstrap._RestResponse(
                        200,
                        bootstrap.canonical_json_bytes(self.definition),
                        {},
                    )
                if url != assignment_url:
                    raise AssertionError(
                        "request escaped the exact fence assignment scope"
                    )
                if method == "GET":
                    if not self.assignment_present:
                        response = bootstrap._RestResponse(404, b"", {})
                        if self.drift_after_assignment_precheck:
                            self.drift_after_assignment_precheck = False
                            self.drift_definition()
                        return response
                    return bootstrap._RestResponse(
                        200,
                        bootstrap.canonical_json_bytes(assignment),
                        {},
                    )
                if method == "PUT":
                    expected = {
                        key: assignment["properties"][key]
                        for key in (
                            "principalId",
                            "principalType",
                            "roleDefinitionId",
                            "description",
                        )
                    }
                    if json.loads(kwargs["body"])["properties"] != expected:
                        raise AssertionError(
                            "fence assignment body escaped reviewed authority"
                        )
                    self.assignment_present = True
                    if self.drift_on_put:
                        self.drift_definition()
                    return bootstrap._RestResponse(201, b"", {})
                raise AssertionError("unexpected fence assignment method")

        session = Session()
        transport.session = session
        journal = MemoryJournal()
        transport.bind_journal(journal)
        transport._active_operation_id = ADD
        return transport, session, journal, assignment_url, definition_url

    def test_final_definition_reread_blocks_toctou_before_assignment_put(self):
        with tempfile.TemporaryDirectory() as folder:
            transport, session, journal, assignment_url, definition_url = (
                self.fixture(folder)
            )
            session.drift_after_assignment_precheck = True
            with self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "source-bound stable fence definition",
            ):
                transport._mutate_temporary_role_impl(ADD, {})
            self.assertEqual(
                session.calls,
                [
                    ("GET", definition_url),
                    ("GET", definition_url),
                    ("GET", assignment_url),
                    ("GET", definition_url),
                ],
            )
            self.assertFalse(session.assignment_present)
            self.assertEqual(journal.records, [])

    def test_definition_drift_after_put_surfaces_owned_assignment_for_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            transport, session, journal, assignment_url, _definition_url = (
                self.fixture(folder)
            )
            session.drift_on_put = True
            with self.assertRaises(
                bootstrap.OwnedTemporaryMutationError
            ) as raised:
                transport._mutate_temporary_role_impl(ADD, {})
            details = raised.exception.proof["details"]
            self.assertTrue(details["assignmentCreated"])
            self.assertFalse(details["definitionCreated"])
            self.assertTrue(session.assignment_present)
            self.assertEqual(
                [call for call in session.calls if call[0] != "GET"],
                [("PUT", assignment_url)],
            )
            self.assertEqual(
                [item["phase"] for item in journal.records],
                ["intent", "result"],
            )

    def test_success_mutates_only_authorization_owned_assignment(self):
        with tempfile.TemporaryDirectory() as folder:
            transport, session, journal, assignment_url, definition_url = (
                self.fixture(folder)
            )
            details = transport._mutate_temporary_role_impl(ADD, {})
            self.assertTrue(details["assignmentReadbackExact"])
            self.assertFalse(details["definitionAttempted"])
            self.assertFalse(details["definitionCreated"])
            self.assertEqual(
                [call for call in session.calls if call[0] != "GET"],
                [("PUT", assignment_url)],
            )
            self.assertTrue(
                all(
                    method == "GET"
                    for method, url in session.calls
                    if url == definition_url
                )
            )
            self.assertEqual(
                [item["phase"] for item in journal.records],
                ["intent", "result"],
            )

    def test_temporary_operations_have_no_definition_mutation_authority(self):
        with tempfile.TemporaryDirectory() as folder:
            transport, _session, _journal, assignment_url, definition_url = (
                self.fixture(folder)
            )
            source_sha = transport.authorization["source"]["mergedMain"][
                "commitSha"
            ]
            for operation_id in (ADD, REMOVE):
                for method in ("PUT", "DELETE"):
                    with self.subTest(
                        operation=operation_id, method=method
                    ):
                        self.assertFalse(
                            bootstrap._mutation_target_allowed(
                                operation_id,
                                method,
                                definition_url,
                                plan=self.plan,
                                authorization_id=fixtures.AUTH_ID,
                                source_sha=source_sha,
                            )
                        )
            self.assertTrue(
                bootstrap._mutation_target_allowed(
                    ADD,
                    "PUT",
                    assignment_url,
                    plan=self.plan,
                    authorization_id=fixtures.AUTH_ID,
                    source_sha=source_sha,
                )
            )
            self.assertTrue(
                bootstrap._mutation_target_allowed(
                    REMOVE,
                    "DELETE",
                    assignment_url,
                    plan=self.plan,
                    authorization_id=fixtures.AUTH_ID,
                    source_sha=source_sha,
                )
            )
            self.assertTrue(
                bootstrap._mutation_target_allowed(
                    "createCustomRoleDefinitions",
                    "PUT",
                    definition_url,
                    plan=self.plan,
                    authorization_id=fixtures.AUTH_ID,
                    source_sha=source_sha,
                )
            )


if __name__ == "__main__":
    unittest.main()
