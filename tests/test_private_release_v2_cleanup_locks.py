import copy
import datetime as dt
import json
from types import SimpleNamespace
import unittest

from scripts import private_release_v2_cleanup_locks as locks


class GuardFailure(RuntimeError):
    pass


def fail(message):
    raise GuardFailure(message)


class Fixture:
    def __init__(self, operation="removeOwnedUploaderPackageRole"):
        self.operation = operation
        self.key = locks.applicable_cleanup_lock(operation)
        self.spec = copy.deepcopy(locks.REVIEWED_CLEANUP_LOCKS[self.key])
        self.lock_url = locks.ARM_ROOT + self.spec["resourceId"] + "?api-version=2016-09-01"
        scope = self.spec["resourceId"].rsplit("/providers/Microsoft.Authorization/locks/", 1)[0]
        self.assignment = {
            "id": scope + "/providers/Microsoft.Authorization/roleAssignments/39989cff-44ef-596e-8b46-0a433bb5c0e2",
            "properties": {"principalId": "operator", "roleDefinitionId": "exact-definition"},
        }
        self.expected = copy.deepcopy(self.assignment)
        self.assignment_url = self.assignment["id"]
        self.assignment_url = locks.ARM_ROOT + self.assignment_url + "?api-version=2022-04-01"
        self.lock = self.lock_document()
        self.now = dt.datetime(2026, 9, 2, tzinfo=dt.timezone.utc)
        self.requests = []
        self.mutations = []
        self.inventory_calls = []
        self.before_read = None
        self.after_mutation = None
        self.inventory_error = None
        self.auth_calls = 0
        self.expire_on_auth = None
        self.assignment_delay = 0
        self.pending_assignment_delete = False

    def lock_document(self):
        return {
            "id": self.spec["resourceId"],
            "name": self.spec["resourceId"].rsplit("/", 1)[-1],
            "type": "Microsoft.Authorization/locks",
            "properties": copy.deepcopy(self.spec["properties"]),
        }

    def response(self, value):
        return SimpleNamespace(
            status=404 if value is None else 200,
            body=json.dumps(value or {}).encode(), headers={},
        )

    def read(self, method, url):
        self.requests.append((method, url))
        if self.before_read:
            result = self.before_read(method, url)
            if result is not None:
                return result
        if url == self.lock_url:
            return self.response(self.lock)
        if url != self.assignment_url:
            raise AssertionError("unexpected URL")
        if self.pending_assignment_delete:
            if self.assignment_delay:
                self.assignment_delay -= 1
            else:
                self.assignment = None
        return self.response(self.assignment)

    def mutate(self, method, url, *, body, expected, restore):
        self.mutations.append((method, url, body, expected, restore))
        if method == "DELETE" and url == self.lock_url:
            self.lock = None
        elif method == "DELETE" and url == self.assignment_url:
            self.pending_assignment_delete = True
            if not self.assignment_delay:
                self.assignment = None
        elif method == "PUT" and url == self.lock_url:
            self.lock = self.lock_document()
            self.lock["properties"] = json.loads(body)["properties"]
        else:
            raise AssertionError("unexpected mutation")
        if self.after_mutation:
            self.after_mutation(method, url)
        return SimpleNamespace(status=200, body=b"{}", headers={})

    def inventory(self, operation, key):
        self.inventory_calls.append((operation, key))
        if self.inventory_error:
            raise GuardFailure(self.inventory_error)

    def auth(self):
        self.auth_calls += 1
        if self.expire_on_auth == self.auth_calls:
            raise GuardFailure("authorization expired")

    def sleep(self, seconds):
        self.now += dt.timedelta(seconds=seconds)

    def guard(self):
        return locks.CleanupLockGuard(
            read_request=self.read, mutate_request=self.mutate,
            verify_lock_inventory=self.inventory, clock=lambda: self.now,
            sleep=self.sleep, fail=fail, require_live_authorization=self.auth,
        )

    def run(self, **kwargs):
        args = dict(
            operation_id=self.operation, assignment_url=self.assignment_url,
            expected_assignment_projection=self.expected,
            project_assignment=lambda document: copy.deepcopy(document),
        )
        args.update(kwargs)
        return self.guard().delete_assignment(**args)


class CleanupLockTests(unittest.TestCase):
    def test_exact_seven_operation_mapping(self):
        self.assertEqual(len(locks.REVIEWED_OPERATION_LOCKS), 7)
        self.assertEqual(list(locks.REVIEWED_OPERATION_LOCKS.values()).count("rollback"), 6)
        self.assertEqual(locks.applicable_cleanup_lock("removeOwnedOperatorKeyReadRole"), "signingVault")
        self.assertIsNone(locks.applicable_cleanup_lock("retireLegacyPublisherMutatorAssignment"))

    def test_exact_properties_include_no_extra_owner_or_changed_note(self):
        fixture = Fixture()
        for change in ("notes", "level", "owners", "id", "name", "type"):
            value = fixture.lock_document()
            if change in {"notes", "level", "owners"}:
                value["properties"][change] = "changed"
            else:
                value[change] = "changed"
            with self.subTest(change=change), self.assertRaises(GuardFailure):
                locks.validate_lock_document(value, fixture.spec, fail)

    def test_harmless_arm_owners_omission_null_or_empty_is_canonical(self):
        fixture = Fixture()
        expected = {"resourceId": fixture.spec["resourceId"], "properties": fixture.spec["properties"]}
        for owners in (None, []):
            value = fixture.lock_document()
            value["properties"]["owners"] = owners
            self.assertEqual(locks.validate_lock_document(value, fixture.spec, fail), expected)
        value["properties"]["unreviewed"] = None
        with self.assertRaises(GuardFailure):
            locks.validate_lock_document(value, fixture.spec, fail)

    def test_all_seven_operations_restore_exact_lock_with_three_mutations(self):
        for operation in locks.REVIEWED_OPERATION_LOCKS:
            fixture = Fixture(operation)
            proof = fixture.run()
            with self.subTest(operation=operation):
                self.assertEqual(proof, {
                    "resourceId": fixture.spec["resourceId"],
                    "properties": fixture.spec["properties"],
                    "restored": True, "assignmentAbsent": True,
                })
                self.assertEqual([(x[0], x[1]) for x in fixture.mutations], [
                    ("DELETE", fixture.lock_url), ("DELETE", fixture.assignment_url),
                    ("PUT", fixture.lock_url),
                ])
                self.assertEqual([x[4] for x in fixture.mutations], [False, False, True])
                self.assertEqual(json.loads(fixture.mutations[-1][2]), {"properties": fixture.spec["properties"]})
                self.assertEqual(fixture.lock, fixture.lock_document())

    def test_absent_assignment_still_checks_inventory_and_exact_lock(self):
        fixture = Fixture()
        fixture.assignment = None
        self.assertTrue(fixture.run()["assignmentAbsent"])
        self.assertEqual(fixture.mutations, [])
        self.assertEqual(fixture.inventory_calls, [(fixture.operation, fixture.key)])
        self.assertIn(("GET", fixture.lock_url), fixture.requests)

    def test_absent_assignment_does_not_accept_missing_lock(self):
        fixture = Fixture()
        fixture.assignment = fixture.lock = None
        with self.assertRaisesRegex(GuardFailure, "absent before suspension"):
            fixture.run()
        self.assertEqual(fixture.mutations, [])

    def test_changed_assignment_and_unknown_inherited_lock_fail_before_mutation(self):
        fixture = Fixture()
        fixture.assignment["properties"]["principalId"] = "other"
        with self.assertRaisesRegex(GuardFailure, "changed assignment"):
            fixture.run()
        self.assertEqual(fixture.mutations, [])
        fixture = Fixture()
        fixture.inventory_error = "unknown inherited lock"
        with self.assertRaisesRegex(GuardFailure, "unknown inherited lock"):
            fixture.run()
        self.assertEqual(fixture.mutations, [])

    def test_assignment_drift_after_suspension_restores_without_assignment_delete(self):
        fixture = Fixture()
        def drift(method, url):
            if method == "DELETE" and url == fixture.lock_url:
                fixture.assignment["properties"]["principalId"] = "other"
        fixture.after_mutation = drift
        with self.assertRaisesRegex(GuardFailure, "changed assignment"):
            fixture.run()
        self.assertEqual([x[0] for x in fixture.mutations], ["DELETE", "PUT"])
        self.assertEqual(fixture.lock, fixture.lock_document())

    def test_assignment_drift_during_lock_inventory_fails_before_suspension(self):
        fixture = Fixture()
        def inventory(operation, key):
            fixture.assignment["properties"]["principalId"] = "other"
        fixture.inventory = inventory
        with self.assertRaisesRegex(GuardFailure, "changed assignment"):
            fixture.run()
        self.assertEqual(fixture.mutations, [])

    def test_assignment_created_during_absent_noop_inventory_fails_without_mutation(self):
        fixture = Fixture()
        fixture.assignment = None
        def inventory(operation, key):
            fixture.assignment = copy.deepcopy(fixture.expected)
        fixture.inventory = inventory
        with self.assertRaisesRegex(GuardFailure, "precondition changed"):
            fixture.run()
        self.assertEqual(fixture.mutations, [])

    def test_scope_locked_assignment_delete_is_not_retried_and_lock_is_restored(self):
        fixture = Fixture()
        def failure(method, url):
            if url == fixture.assignment_url:
                fixture.assignment = copy.deepcopy(fixture.expected)
                fixture.pending_assignment_delete = False
                raise GuardFailure("ScopeLocked")
        fixture.after_mutation = failure
        with self.assertRaisesRegex(GuardFailure, "ScopeLocked"):
            fixture.run()
        self.assertEqual(len(fixture.mutations), 3)
        self.assertEqual(fixture.lock, fixture.lock_document())

    def test_ambiguous_lock_delete_and_journal_failure_restore_without_assignment_delete(self):
        for message in ("ambiguous transport", "result fsync failure"):
            fixture = Fixture()
            def failure(method, url):
                if method == "DELETE" and url == fixture.lock_url:
                    raise OSError(message)
            fixture.after_mutation = failure
            with self.subTest(message=message), self.assertRaisesRegex(OSError, message):
                fixture.run()
            self.assertEqual([x[0] for x in fixture.mutations], ["DELETE", "PUT"])
            self.assertEqual(fixture.lock, fixture.lock_document())

    def test_ambiguous_assignment_delete_restores_and_preserves_failure(self):
        fixture = Fixture()
        def failure(method, url):
            if method == "DELETE" and url == fixture.assignment_url:
                raise OSError("ambiguous assignment transport")
        fixture.after_mutation = failure
        with self.assertRaisesRegex(OSError, "ambiguous assignment transport"):
            fixture.run()
        self.assertEqual(len(fixture.mutations), 3)
        self.assertEqual(fixture.lock, fixture.lock_document())

    def test_third_state_lock_in_finally_is_never_overwritten(self):
        fixture = Fixture()
        def drift(method, url):
            if url == fixture.assignment_url:
                fixture.lock = fixture.lock_document()
                fixture.lock["properties"]["notes"] = "another administrator changed it"
        fixture.after_mutation = drift
        with self.assertRaisesRegex(GuardFailure, "exact reviewed projection"):
            fixture.run()
        self.assertEqual([x[0] for x in fixture.mutations], ["DELETE", "DELETE"])

    def test_exact_concurrent_restore_requires_no_put(self):
        fixture = Fixture()
        def restore(method, url):
            if url == fixture.assignment_url:
                fixture.lock = fixture.lock_document()
        fixture.after_mutation = restore
        self.assertTrue(fixture.run()["restored"])
        self.assertEqual([x[0] for x in fixture.mutations], ["DELETE", "DELETE"])

    def test_restore_transport_ambiguity_is_not_retried_or_reported_successful(self):
        fixture = Fixture()
        def failure(method, url):
            if method == "PUT":
                raise OSError("ambiguous restoration")
        fixture.after_mutation = failure
        with self.assertRaisesRegex(OSError, "ambiguous restoration"):
            fixture.run()
        self.assertEqual(len(fixture.mutations), 3)
        self.assertEqual(fixture.lock, fixture.lock_document())

    def test_delayed_assignment_absence_uses_only_get_retries(self):
        fixture = Fixture()
        fixture.assignment_delay = 4
        self.assertTrue(fixture.run()["assignmentAbsent"])
        self.assertEqual(len(fixture.mutations), 3)
        self.assertEqual(fixture.now.second, 8)

    def test_assignment_absence_timeout_restores_lock(self):
        fixture = Fixture()
        fixture.assignment_delay = 1000
        with self.assertRaisesRegex(GuardFailure, "did not converge"):
            fixture.run()
        self.assertEqual(len(fixture.mutations), 3)
        self.assertEqual(fixture.lock, fixture.lock_document())
        self.assertEqual(fixture.now.minute, 10)

    def test_lock_absence_timeout_never_deletes_assignment_or_retries_mutation(self):
        fixture = Fixture()
        def no_convergence(method, url):
            if method == "DELETE" and url == fixture.lock_url:
                fixture.lock = fixture.lock_document()
        fixture.after_mutation = no_convergence
        with self.assertRaisesRegex(GuardFailure, "did not converge"):
            fixture.run()
        self.assertEqual([x[0] for x in fixture.mutations], ["DELETE"])
        self.assertEqual(fixture.now.minute, 2)
        self.assertEqual(fixture.assignment, fixture.expected)

    def test_lock_restore_timeout_remains_failure_without_second_put(self):
        fixture = Fixture()
        def no_convergence(method, url):
            if method == "PUT":
                fixture.lock = None
        fixture.after_mutation = no_convergence
        with self.assertRaisesRegex(GuardFailure, "did not converge"):
            fixture.run()
        self.assertEqual([x[0] for x in fixture.mutations], ["DELETE", "DELETE", "PUT"])
        self.assertEqual(fixture.now.minute, 2)

    def test_assignment_absence_read_error_restores_lock(self):
        fixture = Fixture()
        def read_error(method, url):
            if url == fixture.assignment_url and fixture.pending_assignment_delete:
                return SimpleNamespace(status=403, body=b"{}", headers={})
        fixture.before_read = read_error
        with self.assertRaisesRegex(GuardFailure, "unexpected HTTP status 403"):
            fixture.run()
        self.assertEqual(fixture.lock, fixture.lock_document())
        self.assertEqual(len(fixture.mutations), 3)

    def test_keyboard_interrupt_after_lock_delete_still_restores(self):
        fixture = Fixture()
        def interrupt(method, url):
            if method == "DELETE" and url == fixture.lock_url:
                raise KeyboardInterrupt()
        fixture.after_mutation = interrupt
        with self.assertRaises(KeyboardInterrupt):
            fixture.run()
        self.assertEqual([x[0] for x in fixture.mutations], ["DELETE", "PUT"])
        self.assertEqual(fixture.lock, fixture.lock_document())

    def test_expiry_before_lock_delete_does_nothing(self):
        fixture = Fixture()
        fixture.expire_on_auth = 1
        with self.assertRaisesRegex(GuardFailure, "authorization expired"):
            fixture.run()
        self.assertEqual(fixture.mutations, [])

    def test_expiry_after_lock_delete_permits_only_exact_restoration(self):
        fixture = Fixture()
        fixture.expire_on_auth = 2
        with self.assertRaisesRegex(GuardFailure, "authorization expired"):
            fixture.run()
        self.assertEqual([x[0] for x in fixture.mutations], ["DELETE", "PUT"])
        self.assertTrue(fixture.mutations[-1][4])
        self.assertEqual(fixture.lock, fixture.lock_document())

    def test_wrong_url_and_unknown_operation_fail_without_requests(self):
        fixture = Fixture()
        with self.assertRaisesRegex(GuardFailure, "outside its exact reviewed lock scope"):
            fixture.run(assignment_url=fixture.assignment_url + "&extra=1")
        self.assertEqual(fixture.requests, [])
        with self.assertRaisesRegex(GuardFailure, "no reviewed deletion-protection lock"):
            fixture.run(operation_id="other")
        self.assertEqual(fixture.requests, [])

    def test_assignment_disappearance_during_suspension_is_drift_and_restores(self):
        fixture = Fixture()
        def disappear(method, url):
            if method == "DELETE" and url == fixture.lock_url:
                fixture.assignment = None
        fixture.after_mutation = disappear
        with self.assertRaisesRegex(GuardFailure, "disappeared"):
            fixture.run()
        self.assertEqual([x[0] for x in fixture.mutations], ["DELETE", "PUT"])


if __name__ == "__main__":
    unittest.main()
