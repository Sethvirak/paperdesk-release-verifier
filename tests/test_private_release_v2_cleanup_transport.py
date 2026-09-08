"""No-network integration tests of the real bootstrap cleanup transport."""

import copy
import datetime as dt
from pathlib import Path
import unittest
from unittest import mock

from scripts import private_release_v2_bootstrap as bootstrap
from tests.test_private_release_v2_bootstrap import (
    ACCOUNT_OBJECT, AUTH_ID, NOW, _TerminalEvidenceFixture,
)
from tests.test_private_release_v2_package_readiness import MemoryJournal


TEMPORARY = (
    "removeOwnedOperatorKeyReadRole", "removeOwnedOperatorFenceBootstrapRole",
    "removeOwnedOperatorControllerCanaryRole", "removeOwnedUploaderPackageRole",
)
LEGACY = (
    "removeLegacyWriterResultAssignment", "removeLegacyReaderResultAssignment",
    "retireLegacyPublisherResultReadAssignment",
    "retireLegacyPublisherSitesReadAssignment",
)


def response(status, document=None):
    return bootstrap._RestResponse(status,
        bootstrap.canonical_json_bytes(document or {}), {"Content-Type": "application/json"})


class CleanupSession:
    def __init__(self, assignment, definition=None):
        self.assignment = copy.deepcopy(assignment)
        self.definition = copy.deepcopy(definition)
        self.assignment_url = self.arm(assignment["id"], "2022-04-01")
        self.definition_url = self.arm(definition["id"], "2022-04-01") if definition else None
        self.locks = {self.arm(item["resourceId"], "2016-09-01"): {
            "id": item["resourceId"], "name": item["resourceId"].rsplit("/", 1)[-1],
            "type": "Microsoft.Authorization/locks", "properties": copy.deepcopy(item["properties"]),
        } for item in bootstrap._expected_cleanup_lock_inventory()["locks"]}
        self.original_locks = copy.deepcopy(self.locks)
        self.requests = []
        self.assignment_reads = 0
        self.replace_on_read = None
        self.assignment_failure = None
        self.third_state_on_delete = False
        self.definition_deleted = False
        self.definition_delay = 0
        self.definition_failure = None

    @staticmethod
    def arm(resource_id, version):
        return "https://management.azure.com" + resource_id + "?api-version=" + version

    def request(self, method, url, *, body=None, headers=None, deadline=None):
        self.requests.append((method, url, body))
        if method == "GET" and url == bootstrap._cleanup_lock_inventory_url():
            return response(200, {"value": list(self.locks.values())})
        if url in self.original_locks:
            if method == "GET":
                return response(200, self.locks[url]) if url in self.locks else response(404)
            if method == "DELETE":
                self.locks.pop(url, None)
                return response(204)
            if method == "PUT":
                expected = bootstrap.canonical_json_bytes({"properties": self.original_locks[url]["properties"]})
                if body != expected:
                    raise AssertionError("non-exact restoration body")
                self.locks[url] = copy.deepcopy(self.original_locks[url])
                return response(200, self.locks[url])
        if url == self.assignment_url:
            if method == "GET":
                self.assignment_reads += 1
                if self.assignment_reads == self.replace_on_read:
                    self.assignment["properties"]["principalId"] = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
                return response(200, self.assignment) if self.assignment else response(404)
            if method == "DELETE":
                if self.third_state_on_delete:
                    missing = next(key for key in self.original_locks if key not in self.locks)
                    self.locks[missing] = copy.deepcopy(self.original_locks[missing])
                    self.locks[missing]["properties"]["level"] = "ReadOnly"
                if isinstance(self.assignment_failure, BaseException):
                    self.assignment = None  # Ambiguous transport after Azure applied deletion.
                    raise self.assignment_failure
                if self.assignment_failure:
                    return response(self.assignment_failure)
                self.assignment = None
                return response(204)
        if url == self.definition_url:
            if method == "GET":
                if self.definition_deleted:
                    if self.definition_delay:
                        self.definition_delay -= 1
                    else:
                        return response(404)
                return response(200, self.definition)
            if method == "DELETE":
                if self.definition["properties"]["type"] == "BuiltInRole":
                    raise AssertionError("Built-in role definition must never be deleted")
                if self.definition_failure:
                    return response(self.definition_failure)
                self.definition_deleted = True
                return response(204)
        raise AssertionError(f"unexpected request: {method} {url}")

    def mutations(self):
        return [(method, url) for method, url, _ in self.requests if method != "GET"]


class PackageCleanupSession(CleanupSession):
    def __init__(self, assignments, definitions):
        super().__init__(assignments["packageAdd"], definitions["packageAdd"])
        self.assignments = copy.deepcopy(assignments)
        self.definitions = copy.deepcopy(definitions)
        self.assignment_urls = {
            name: self.arm(item["id"], "2022-04-01")
            for name, item in self.assignments.items()
        }
        self.definition_urls = {
            name: self.arm(item["id"], "2022-04-01")
            for name, item in self.definitions.items()
        }

    def request(self, method, url, *, body=None, headers=None, deadline=None):
        self.requests.append((method, url, body))
        if method == "GET" and url == bootstrap._cleanup_lock_inventory_url():
            return response(200, {"value": list(self.locks.values())})
        if url in self.original_locks:
            if method == "GET":
                return response(200, self.locks[url]) if url in self.locks else response(404)
            if method == "DELETE":
                self.locks.pop(url, None)
                return response(204)
            if method == "PUT":
                expected = bootstrap.canonical_json_bytes(
                    {"properties": self.original_locks[url]["properties"]}
                )
                if body != expected:
                    raise AssertionError("non-exact restoration body")
                self.locks[url] = copy.deepcopy(self.original_locks[url])
                return response(200, self.locks[url])
        for name, assignment_url in self.assignment_urls.items():
            if url == assignment_url:
                if method == "GET":
                    item = self.assignments.get(name)
                    return response(200, item) if item is not None else response(404)
                if method == "DELETE":
                    self.assignments[name] = None
                    return response(204)
        for name, definition_url in self.definition_urls.items():
            if url == definition_url:
                if method == "GET":
                    return response(200, self.definitions[name])
                raise AssertionError("stable package definition must never be mutated")
        raise AssertionError(f"unexpected request: {method} {url}")


class PackageAddSession:
    def __init__(self, assignments, definitions, *, ambiguous_member=None):
        self.expected_assignments = copy.deepcopy(assignments)
        self.assignments = {name: None for name in assignments}
        self.definitions = copy.deepcopy(definitions)
        self.assignment_urls = {
            name: CleanupSession.arm(item["id"], "2022-04-01")
            for name, item in assignments.items()
        }
        self.definition_urls = {
            name: CleanupSession.arm(item["id"], "2022-04-01")
            for name, item in definitions.items()
        }
        self.ambiguous_member = ambiguous_member
        self.requests = []
        self.put_headers = {}

    def request(self, method, url, *, body=None, headers=None, deadline=None):
        self.requests.append((method, url, body))
        for name, definition_url in self.definition_urls.items():
            if url == definition_url:
                if method != "GET":
                    raise AssertionError("stable package definition must never be mutated")
                return response(200, self.definitions[name])
        for name, assignment_url in self.assignment_urls.items():
            if url != assignment_url:
                continue
            if method == "GET":
                item = self.assignments[name]
                return response(200, item) if item is not None else response(404)
            if method == "PUT":
                expected = self.expected_assignments[name]
                expected_body = bootstrap.canonical_json_bytes(
                    {
                        "properties": {
                            key: expected["properties"][key]
                            for key in (
                                "principalId",
                                "principalType",
                                "roleDefinitionId",
                                "description",
                            )
                        }
                    }
                )
                if body != expected_body:
                    raise AssertionError("package assignment PUT body is not exact")
                self.put_headers[name] = dict(headers or {})
                self.assignments[name] = copy.deepcopy(expected)
                if name == self.ambiguous_member:
                    return response(500)
                return response(201)
        raise AssertionError(f"unexpected request: {method} {url}")

    def mutations(self):
        return [(method, url) for method, url, _ in self.requests if method != "GET"]


class CleanupTransportTests(unittest.TestCase):
    def make(self, operation_id):
        plan, plan_sha = bootstrap.load_plan()
        fixture = _TerminalEvidenceFixture(plan, plan_sha, {"sha256": "a" * 64, "size": 4096},
            Path(__file__).resolve().parents[2] / ("paperdesk-private-release-v2-bootstrap-" + AUTH_ID))
        authorization = fixture.authorization
        state = {"proofs": {}}
        if operation_id in TEMPORARY:
            added = operation_id.replace("remove", "add", 1)
            role = fixture.temp_role(added)
            if operation_id == "removeOwnedUploaderPackageRole":
                session = PackageCleanupSession(
                    role["assignments"], role["definitions"]
                )
                state["proofs"][added] = {
                    "details": {
                        **copy.deepcopy(role),
                        "assignmentStates": {
                            name: {
                                "attempted": True,
                                "created": True,
                                "readbackExact": True,
                                "ambiguous": False,
                            }
                            for name in role["assignments"]
                        },
                    }
                }
            else:
                session = CleanupSession(role["assignment"], role["definition"])
                state["proofs"][added] = {
                    "details": {
                        "cleanupKey": role["cleanupKey"],
                        "definitionCreated": role["definitionCreated"],
                        "definitionReadbackExact": True,
                        "assignmentCreated": True,
                        "assignmentReadbackExact": True,
                    }
                }
        else:
            resource_id = bootstrap._cleanup_assignment_resources(plan)[operation_id][0]
            assignment = {"id": resource_id, "name": resource_id.rsplit("/", 1)[-1],
                "type": "Microsoft.Authorization/roleAssignments", "properties": {
                    "principalId": ACCOUNT_OBJECT, "principalType": "User",
                    "roleDefinitionId": f"/subscriptions/{bootstrap.SUBSCRIPTION}/providers/Microsoft.Authorization/roleDefinitions/11111111-1111-4111-8111-111111111111",
                    "scope": resource_id.rsplit("/providers/Microsoft.Authorization/roleAssignments/", 1)[0],
                    "condition": None, "conditionVersion": None,
                    "delegatedManagedIdentityResourceId": None,
                }}
            session = CleanupSession(assignment)
        probe_assignment = (
            session.assignments["packageAdd"]
            if isinstance(session, PackageCleanupSession)
            else session.assignment
        )
        probe_url = (
            session.assignment_urls["packageAdd"]
            if isinstance(session, PackageCleanupSession)
            else session.assignment_url
        )
        probe = {"id": "authorized-assignment", "method": "GET", "url": probe_url,
            "status": 200, "responseSha256": bootstrap._preflight_response_sha256(
                "GET", probe_url, response(200, probe_assignment))}
        current = [NOW]
        sleeps = []
        def sleep(seconds):
            sleeps.append(seconds)
            current[0] += dt.timedelta(seconds=seconds)
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=authorization, plan=plan, package=fixture.package,
            preflight={"projection": {"operationAdmissions": [{"operationId": operation_id,
                "context": {"executionDecision": "apply-exact"}, "probeIds": [probe["id"]]}],
                "postconditionAdmissions": [], "probes": [probe], "productionBoundaryObservation": {}}},
            session=session, clock=lambda: current[0], sleep=sleep)
        if operation_id in bootstrap.CONTROLLER_ROLE_OPERATIONS:
            transport.admissions[operation_id]["context"]["builtInRoleDefinitionProjection"] = copy.deepcopy(role["definition"])
        if operation_id in bootstrap.PACKAGE_ROLE_OPERATIONS:
            transport.admissions[operation_id]["context"][
                "stablePackageRoleDefinitionProjections"
            ] = copy.deepcopy(role["definitions"])
        transport._active_operation_id = operation_id
        if operation_id in TEMPORARY:
            transport._active_protected_role_add = operation_id.replace(
                "remove", "add", 1
            )
            transport._protected_work_deadline = transport._protected_role_deadline()
        journal = MemoryJournal()
        transport.bind_journal(journal)
        operation = next(item for item in plan["mutations"] if item["id"] == operation_id)
        return transport, session, journal, operation, state, current, sleeps

    def make_package_add(self, *, ambiguous_member=None):
        plan, plan_sha = bootstrap.load_plan()
        fixture = _TerminalEvidenceFixture(
            plan,
            plan_sha,
            {"sha256": "a" * 64, "size": 4096},
            Path(__file__).resolve().parents[2]
            / ("paperdesk-private-release-v2-bootstrap-" + AUTH_ID),
        )
        role = fixture.temp_role("addOwnedUploaderPackageRole")
        session = PackageAddSession(
            role["assignments"],
            role["definitions"],
            ambiguous_member=ambiguous_member,
        )
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=fixture.authorization,
            plan=plan,
            package=fixture.package,
            preflight={"projection": fixture.projection},
            session=session,
            clock=lambda: NOW,
            sleep=lambda _seconds: None,
        )
        journal = MemoryJournal()
        transport.bind_journal(journal)
        transport._active_operation_id = "addOwnedUploaderPackageRole"
        return transport, session, journal, role

    def test_package_add_creates_both_exact_assignments_and_preserves_definitions(self):
        transport, session, journal, role = self.make_package_add()
        result = transport._mutate_temporary_role_impl(
            "addOwnedUploaderPackageRole", {}
        )
        self.assertEqual(result["definitions"], role["definitions"])
        self.assertEqual(result["assignments"], role["assignments"])
        self.assertEqual(
            [url for method, url in session.mutations() if method == "PUT"],
            [
                session.assignment_urls["packageAdd"],
                session.assignment_urls["packageRead"],
            ],
        )
        self.assertFalse(
            any(
                method != "GET" and url in session.definition_urls.values()
                for method, url, _ in session.requests
            )
        )
        for name in ("packageAdd", "packageRead"):
            self.assertEqual(
                session.put_headers[name],
                {"Content-Type": "application/json", "If-None-Match": "*"},
            )
            self.assertEqual(
                result["assignmentStates"][name],
                {
                    "attempted": True,
                    "created": True,
                    "readbackExact": True,
                    "ambiguous": False,
                },
            )
        self.assertEqual(
            [item["phase"] for item in journal.records],
            ["intent", "result", "intent", "result"],
        )

    def test_package_add_partial_and_ambiguous_states_fail_closed(self):
        for member in ("packageAdd", "packageRead"):
            with self.subTest(member=member):
                transport, session, _journal, _role = self.make_package_add(
                    ambiguous_member=member
                )
                with self.assertRaises(
                    bootstrap.OwnedTemporaryMutationError
                ) as raised:
                    transport._mutate_temporary_role_impl(
                        "addOwnedUploaderPackageRole", {}
                    )
                states = raised.exception.proof["details"]["assignmentStates"]
                self.assertTrue(states[member]["attempted"])
                self.assertFalse(states[member]["created"])
                self.assertTrue(states[member]["ambiguous"])
                if member == "packageRead":
                    self.assertTrue(states["packageAdd"]["readbackExact"])
                else:
                    self.assertFalse(states["packageRead"]["attempted"])
                self.assertFalse(
                    any(
                        method != "GET" and url in session.definition_urls.values()
                        for method, url, _ in session.requests
                    )
                )

    def test_successful_package_add_expands_deadline_only_after_desired_readback(self):
        transport, _session, _journal, _role = self.make_package_add()
        operation = next(
            item
            for item in transport.plan["mutations"]
            if item["id"] == "addOwnedUploaderPackageRole"
        )
        settlement_deadline = transport._protected_role_deadline(
            bootstrap.TEMPORARY_ROLE_CREATE_SETTLEMENT_SECONDS
            + bootstrap.FINAL_OBSERVATION_ALIGNMENT_SLACK_SECONDS
            + bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS
        )
        full_work_deadline = transport._protected_role_deadline()
        self.assertGreater(full_work_deadline, settlement_deadline)
        result = transport.apply_operation(operation, {"proofs": {}})
        self.assertEqual(result["status"], "applied-exact")
        self.assertEqual(transport._protected_work_deadline, full_work_deadline)
        self.assertTrue(result["details"]["readbackProjections"])

    def test_failed_package_add_never_expands_create_settlement_deadline(self):
        operation_id = "addOwnedUploaderPackageRole"
        for failure in ("ambiguous-put", "desired-readback"):
            with self.subTest(failure=failure):
                transport, _session, _journal, _role = self.make_package_add(
                    ambiguous_member=("packageRead" if failure == "ambiguous-put" else None)
                )
                operation = next(
                    item
                    for item in transport.plan["mutations"]
                    if item["id"] == operation_id
                )
                settlement_deadline = transport._protected_role_deadline(
                    bootstrap.TEMPORARY_ROLE_CREATE_SETTLEMENT_SECONDS
                    + bootstrap.FINAL_OBSERVATION_ALIGNMENT_SLACK_SECONDS
                    + bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS
                )
                if failure == "desired-readback":
                    prove = mock.patch.object(
                        transport,
                        "_prove_probe_ids",
                        side_effect=bootstrap.BootstrapError(
                            "desired readback failed"
                        ),
                    )
                else:
                    prove = mock.patch.object(
                        transport,
                        "_prove_probe_ids",
                        wraps=transport._prove_probe_ids,
                    )
                with prove:
                    with self.assertRaises(bootstrap.OwnedTemporaryMutationError):
                        transport.apply_operation(operation, {"proofs": {}})
                self.assertEqual(
                    transport._protected_work_deadline,
                    settlement_deadline,
                )
                self.assertNotEqual(
                    transport._protected_work_deadline,
                    transport._protected_role_deadline(),
                )

    def test_stable_package_definitions_have_zero_mutation_authority(self):
        plan, plan_sha = bootstrap.load_plan()
        fixture = _TerminalEvidenceFixture(
            plan,
            plan_sha,
            {"sha256": "a" * 64, "size": 4096},
            Path(__file__).resolve().parents[2]
            / ("paperdesk-private-release-v2-bootstrap-" + AUTH_ID),
        )
        for spec in bootstrap._stable_package_role_specs(fixture.execution_plan):
            url = CleanupSession.arm(spec["definitionResourceId"], "2022-04-01")
            for operation_id in (
                "createCustomRoleDefinitions",
                "addOwnedUploaderPackageRole",
                "removeOwnedUploaderPackageRole",
            ):
                for method in ("PUT", "DELETE"):
                    with self.subTest(
                        definition=spec["name"],
                        operation=operation_id,
                        method=method,
                    ):
                        self.assertFalse(
                            bootstrap._mutation_target_allowed(
                                operation_id,
                                method,
                                url,
                                plan=plan,
                                authorization_id=AUTH_ID,
                                source_sha=fixture.authorization["source"][
                                    "mergedMain"
                                ]["commitSha"],
                                operation_projections={},
                                operation_contexts=fixture.contexts,
                            )
                        )

    def test_legacy_per_authorization_package_ids_remain_residuals(self):
        plan, _ = bootstrap.load_plan()
        execution_plan = bootstrap.bind_temporary_role_ids(plan, AUTH_ID)
        temporary = execution_plan["temporaryAccess"]
        scope = bootstrap._resource_scope_from_plan(plan, "packageContainer")
        definition_id = temporary["legacyPackageRoleDefinitionId"]
        assignment_id = temporary["legacyPackageRoleAssignmentId"]
        definition = {
            "id": (
                f"/subscriptions/{bootstrap.SUBSCRIPTION}/providers/"
                f"Microsoft.Authorization/roleDefinitions/{definition_id}"
            ),
            "properties": {"roleName": "marker removed", "description": None},
        }
        assignment = {
            "id": (
                f"{scope}/providers/Microsoft.Authorization/roleAssignments/"
                f"{assignment_id}"
            ),
            "properties": {
                "description": None,
                "roleDefinitionId": definition["id"],
            },
        }
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "residual PaperDesk temporary role definition"
        ):
            bootstrap._reject_residual_temporary_role_definitions(
                [definition], label="legacy definition", plan=execution_plan
            )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "residual PaperDesk temporary role assignment"
        ):
            bootstrap._reject_residual_temporary_role_assignments(
                [assignment], plan=execution_plan, label="legacy assignment"
            )

    def test_all_four_temporary_roles_use_exact_guarded_mutation_order(self):
        for operation_id in TEMPORARY:
            with self.subTest(operation=operation_id):
                transport, session, journal, operation, state, _, _ = self.make(operation_id)
                result = transport._mutate(operation, state)
                lock = session.arm(bootstrap._expected_deletion_lock_proof(operation_id)["resourceId"], "2016-09-01")
                if operation_id == "removeOwnedUploaderPackageRole":
                    expected_mutations = [
                        ("DELETE", lock),
                        ("DELETE", session.assignment_urls["packageAdd"]),
                        ("DELETE", session.assignment_urls["packageRead"]),
                        ("PUT", lock),
                    ]
                else:
                    expected_mutations = [("DELETE", lock), ("DELETE", session.assignment_url), ("PUT", lock)]
                if operation_id not in bootstrap.CONTROLLER_ROLE_OPERATIONS | bootstrap.PACKAGE_ROLE_OPERATIONS:
                    expected_mutations.append(("DELETE", session.definition_url))
                self.assertEqual(session.mutations(), expected_mutations)
                self.assertEqual(result["deletionLock"], bootstrap._expected_deletion_lock_proof(operation_id))
                self.assertEqual(session.locks, session.original_locks)
                self.assertEqual(len(journal.records), 2 * len(expected_mutations))

    def test_controller_definition_drift_stops_after_assignment_removal_and_lock_restoration(self):
        operation_id = "removeOwnedOperatorControllerCanaryRole"
        transport, session, _, operation, state, _, _ = self.make(operation_id)
        session.definition["properties"]["permissions"][0]["dataActions"].append("unreviewed/action")
        with self.assertRaisesRegex(bootstrap.BootstrapError, "authorization-bound built-in"):
            transport._mutate(operation, state)
        self.assertIsNone(session.assignment)
        self.assertEqual(session.locks, session.original_locks)
        self.assertEqual([method for method, _ in session.mutations()], ["DELETE", "DELETE", "PUT"])
        self.assertFalse(session.definition_deleted)
        requests = list(session.requests)
        with self.assertRaises(bootstrap.BootstrapError):
            transport._mutate(operation, state)
        self.assertEqual(session.requests, requests)

    def test_definition_absence_delay_retries_only_get_after_single_delete(self):
        transport, session, _, operation, state, _, sleeps = self.make(TEMPORARY[0])
        session.definition_delay = 3
        transport._mutate(operation, state)
        self.assertEqual(session.mutations().count(("DELETE", session.definition_url)), 1)
        self.assertEqual(len(sleeps), 3)
        last_delete = next(i for i, item in enumerate(session.requests)
                           if item[:2] == ("DELETE", session.definition_url))
        self.assertTrue(all(item[0] == "GET" and item[1] in {session.definition_url, session.assignment_url}
                            for item in session.requests[last_delete + 1:]))

    def test_failed_cleanup_latches_same_and_other_operations_without_more_http(self):
        for failure_at in ("assignment", "definition"):
            with self.subTest(failure_at=failure_at):
                transport, session, _, operation, state, _, _ = self.make(TEMPORARY[0])
                if failure_at == "assignment":
                    session.assignment_failure = 500
                else:
                    session.definition_failure = 500
                with self.assertRaises(bootstrap.BootstrapError):
                    transport._mutate(operation, state)
                before = list(session.requests)
                for subsequent_id in (TEMPORARY[0], TEMPORARY[1], LEGACY[0]):
                    subsequent = next(item for item in transport.plan["mutations"] if item["id"] == subsequent_id)
                    transport.admissions.setdefault(subsequent_id, {"operationId": subsequent_id,
                        "context": {"executionDecision": "apply-exact"}, "probeIds": []})
                    transport._active_operation_id = subsequent_id
                    with self.assertRaises(bootstrap.BootstrapError):
                        transport._mutate(subsequent, state)
                    self.assertEqual(session.requests, before)

    def test_assignment_failure_or_ambiguity_restores_without_definition_delete_or_replay(self):
        for failure in (500, RuntimeError("ambiguous assignment transport")):
            with self.subTest(failure=failure):
                transport, session, _, operation, state, _, _ = self.make(TEMPORARY[0])
                session.assignment_failure = failure
                with self.assertRaises((bootstrap.BootstrapError, RuntimeError)):
                    transport._mutate(operation, state)
                self.assertEqual([item[0] for item in session.mutations()], ["DELETE", "DELETE", "PUT"])
                self.assertEqual(session.locks, session.original_locks)
                self.assertFalse(session.definition_deleted)

    def test_expiry_before_suspension_permits_no_mutation(self):
        transport, session, _, operation, state, current, _ = self.make(TEMPORARY[0])
        current[0] = bootstrap.parse_time(transport.authorization["validity"]["expiresAt"], "expiry")
        with self.assertRaisesRegex(bootstrap.BootstrapError, "expired"):
            transport._mutate(operation, state)
        self.assertEqual(session.mutations(), [])

    def test_principal_replacement_after_policy_read_stops_before_lock_delete(self):
        transport, session, _, operation, state, _, _ = self.make(TEMPORARY[0])
        session.replace_on_read = 1
        with self.assertRaisesRegex(bootstrap.BootstrapError, "drifted"):
            transport._mutate(operation, state)
        self.assertEqual(session.mutations(), [])

    def test_assignment_policy_drift_before_first_cleanup_read_never_mutates(self):
        changes = {
            "scope": "/subscriptions/another-scope",
            "condition": "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEqualsIgnoreCase temporary",
            "conditionVersion": "2.0",
            "delegatedManagedIdentityResourceId": "/subscriptions/another/managedIdentity",
            "description": "not-the-authorization-owned-marker",
        }
        for operation_id in TEMPORARY:
            for field, changed_value in changes.items():
                member_names = (
                    ("packageAdd", "packageRead")
                    if operation_id == "removeOwnedUploaderPackageRole"
                    else (None,)
                )
                for member_name in member_names:
                    with self.subTest(
                        operation=operation_id,
                        member=member_name,
                        field=field,
                    ):
                        transport, session, journal, operation, state, _, _ = self.make(operation_id)
                        assignment = (
                            session.assignments[member_name]
                            if member_name is not None
                            else session.assignment
                        )
                        assignment["properties"][field] = changed_value
                        with self.assertRaisesRegex(bootstrap.BootstrapError, "source-authorized assignment"):
                            transport._mutate(operation, state)
                        self.assertEqual(session.mutations(), [])
                        self.assertEqual(journal.records, [])
                        self.assertEqual(session.locks, session.original_locks)

    def test_cleanup_readback_failure_latches_compensation_without_more_http(self):
        for failure in (bootstrap.BootstrapError("post-cleanup readback failure"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                transport, session, _, operation, state, _, _ = self.make(TEMPORARY[0])
                transport.admissions[operation["id"]]["desiredProbeIds"] = []
                with mock.patch.object(transport, "_prove_probe_ids", side_effect=failure):
                    with self.assertRaises(type(failure)):
                        transport.apply_operation(operation, state)
                self.assertEqual(len(session.mutations()), 4)
                self.assertEqual(session.locks, session.original_locks)
                before = list(session.requests)
                added_id = operation["id"].replace("remove", "add", 1)
                added_operation = next(item for item in transport.plan["mutations"] if item["id"] == added_id)
                proof = {"owned": True, "cleanupKey": state["proofs"][added_id]["details"]["cleanupKey"]}
                with self.assertRaisesRegex(bootstrap.BootstrapError, "NO-GO"):
                    transport.compensate_temporary(added_operation, proof, state)
                self.assertEqual(session.requests, before)

    def test_definition_absence_get_completing_after_deadline_fails_closed(self):
        transport, session, _, operation, state, current, _ = self.make(TEMPORARY[0])
        real_request = session.request

        def delayed_absence(method, url, **kwargs):
            result = real_request(method, url, **kwargs)
            if method == "GET" and url == session.definition_url and result.status == 404:
                current[0] += dt.timedelta(seconds=601)
            return result

        with mock.patch.object(session, "request", side_effect=delayed_absence):
            with self.assertRaisesRegex(bootstrap.BootstrapError, "exceeded its readback window"):
                transport._mutate(operation, state)
        self.assertEqual(session.mutations().count(("DELETE", session.definition_url)), 1)
        self.assertEqual(session.locks, session.original_locks)
        self.assertTrue(transport._protected_cleanup_blocked)

    def test_modeled_cleanup_reserve_reaches_assignment_delete_before_expiry(self):
        transport, session, _, operation, state, current, _ = self.make(TEMPORARY[0])
        expiry = bootstrap.parse_time(
            transport.authorization["validity"]["expiresAt"], "expiry"
        )
        current[0] = expiry - dt.timedelta(
            seconds=bootstrap.PROTECTED_ROLE_ASSIGNMENT_DELETE_RESERVE_SECONDS
        )
        real_request = session.request
        assignment_delete_started = []
        lock_delete_seen = [False]
        lock_url = session.arm(
            bootstrap._expected_deletion_lock_proof(operation["id"])["resourceId"],
            "2016-09-01",
        )

        def bounded_request(method, url, **kwargs):
            started = current[0]
            deadline = kwargs.get("deadline")
            if method == "DELETE" and url == session.assignment_url:
                assignment_delete_started.append(started)
            if method == "DELETE" and url == lock_url:
                lock_delete_seen[0] = True
            if (
                method == "GET"
                and url == lock_url
                and lock_delete_seen[0]
                and deadline is not None
                and deadline < expiry
                and started
                < deadline
                - dt.timedelta(
                    seconds=bootstrap.cleanup_locks.LOCK_FINAL_OBSERVATION_SECONDS
                )
            ):
                # ARM retains the exact deleted lock for the complete 120s
                # propagation boundary.
                result = response(200, session.original_locks[lock_url])
            else:
                result = real_request(method, url, **kwargs)
            duration = bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS
            if (
                method == "GET"
                and url == lock_url
                and lock_delete_seen[0]
                and deadline is not None
                and started
                == deadline
                - dt.timedelta(
                    seconds=bootstrap.cleanup_locks.LOCK_FINAL_OBSERVATION_SECONDS
                )
            ):
                # A response may use almost all of its reserved envelope; the
                # strict deadline still requires it to finish before the bound.
                duration -= 1
            current[0] += dt.timedelta(
                seconds=duration
            )
            return result

        with mock.patch.object(session, "request", side_effect=bounded_request):
            result = transport._mutate(operation, state)
        self.assertTrue(result["assignmentRemoved"])
        self.assertEqual(len(assignment_delete_started), 1)
        self.assertGreaterEqual(
            (expiry - assignment_delete_started[0]).total_seconds(),
            bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS,
        )
        self.assertEqual(session.locks, session.original_locks)

    def test_third_state_restoration_never_overwrites_or_deletes_definition(self):
        transport, session, _, operation, state, _, _ = self.make(TEMPORARY[0])
        session.third_state_on_delete = True
        with self.assertRaises(bootstrap.BootstrapError):
            transport._mutate(operation, state)
        self.assertEqual([item[0] for item in session.mutations()], ["DELETE", "DELETE"])
        self.assertFalse(session.definition_deleted)
        self.assertTrue(any(item["properties"]["level"] == "ReadOnly" for item in session.locks.values()))

    def test_all_protected_legacy_deletes_require_authorized_exact_preflight(self):
        for operation_id in LEGACY:
            for change in (None, "missing-probe", "digest", "principal"):
                with self.subTest(operation=operation_id, change=change):
                    transport, session, _, operation, state, _, _ = self.make(operation_id)
                    if change == "missing-probe":
                        transport.admissions[operation_id]["probeIds"] = []
                    elif change == "digest":
                        transport.probes["authorized-assignment"]["responseSha256"] = "f" * 64
                    elif change == "principal":
                        session.assignment["properties"]["principalId"] = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
                    if change:
                        with self.assertRaisesRegex(bootstrap.BootstrapError, "authorized preflight"):
                            transport._mutate(operation, state)
                        self.assertEqual(session.mutations(), [])
                    else:
                        result = transport._mutate(operation, state)
                        self.assertEqual([item[0] for item in session.mutations()], ["DELETE", "DELETE", "PUT"])
                        self.assertEqual(result["deletionLock"], bootstrap._expected_deletion_lock_proof(operation_id))
                        self.assertEqual(session.locks, session.original_locks)


if __name__ == "__main__":
    unittest.main()
