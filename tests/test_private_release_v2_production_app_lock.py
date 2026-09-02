"""Exact production-app RBAC cleanup; never production-site mutation."""

import copy
import unittest

from scripts import private_release_v2_bootstrap as bootstrap
from tests import test_private_release_v2_cleanup_transport as cleanup_transport
from tests.test_private_release_v2_cleanup_transport import response


OPERATION = "retireLegacyPublisherSitesReadAssignment"
ASSIGNMENT = "784fb5eb-c6ac-41ca-902a-cdae92334ade"
PRESERVED = "b24a4ca5-de40-47c8-90d8-caf08759dfb2"
SUB = "/subscriptions/9c4e0d0d-602f-4cde-84bd-337250e5b64c"
APP_LOCK = (SUB + "/resourceGroups/rg-master-data-structure-sea/providers/Microsoft.Web/sites/"
    "master-data-structure-sea-9c4e0d0d/providers/Microsoft.Authorization/locks/paperdesk-protect-app-delete")
APP_NOTES = ("PaperDesk production App Service deletion protection. Remove only for an approved delete, "
    "replacement, RBAC cleanup, or diagnostic cleanup.")


def lock_document(resource_id, notes):
    return {"id": resource_id, "name": resource_id.rsplit("/", 1)[-1],
        "type": "Microsoft.Authorization/locks",
        "properties": {"level": "CanNotDelete", "notes": notes, "owners": None}}


def observed_five_lock_inventory():
    documents = [lock_document(item["resourceId"], item["properties"]["notes"])
                 for item in bootstrap._expected_cleanup_lock_inventory()["locks"]
                 if item["resourceId"] != APP_LOCK]
    documents.append(lock_document(APP_LOCK, APP_NOTES))
    for provider, name, title in (
        ("Microsoft.Storage/storageAccounts/mdspaperdesksea9c4e", "paperdesk-protect-storage-delete", "Storage"),
        ("Microsoft.DBforPostgreSQL/flexibleServers/psql-master-data-structure-sea-9c4e0d0d", "paperdesk-protect-postgres-delete", "PostgreSQL"),
    ):
        documents.append(lock_document(
            SUB + "/resourcegroups/rg-master-data-structure-sea/providers/" + provider
            + "/providers/Microsoft.Authorization/locks/" + name,
            f"PaperDesk production {title} deletion protection. Remove only for an approved delete, "
            "replacement, RBAC cleanup, or diagnostic cleanup."))
    return {"value": documents}


class ProductionAppLockTests(unittest.TestCase):
    def make(self):
        return cleanup_transport.CleanupTransportTests.make(self, OPERATION)

    def assert_exact_mutations(self, transport, session, *, present=True):
        proof = bootstrap._expected_deletion_lock_proof(OPERATION)
        lock_url = session.arm(proof["resourceId"], "2016-09-01")
        expected = [("DELETE", lock_url), ("DELETE", session.assignment_url), ("PUT", lock_url)] if present else []
        self.assertEqual(session.mutations(), expected)
        self.assertTrue(session.assignment_url.endswith("/" + ASSIGNMENT + "?api-version=2022-04-01"))
        self.assertFalse(any(PRESERVED in item[1] for item in session.requests))
        site = transport.resources["productionSite"]["resourceId"]
        for method, url in session.mutations():
            self.assertNotEqual(url.split("?", 1)[0], "https://management.azure.com" + site)
            self.assertNotIn("/config/", url)
            self.assertNotIn("/extensions/", url)

    def test_plan_binds_only_exact_production_app_assignment_to_new_lock(self):
        plan, _ = bootstrap.load_plan()
        protection = plan["deletionProtection"]
        self.assertEqual(set(protection["locks"]), {"rollback", "signingVault", "productionApp"})
        self.assertEqual({key for key, value in protection["operationLocks"].items() if value == "productionApp"}, {OPERATION})
        self.assertEqual(len(protection["operationLocks"]), 8)
        self.assertEqual(protection["locks"]["productionApp"], {
            "resourceId": APP_LOCK, "properties": {"level": "CanNotDelete", "notes": APP_NOTES}})
        self.assertTrue(bootstrap._cleanup_assignment_resources(plan)[OPERATION].endswith("/" + ASSIGNMENT))
        self.assertTrue(plan["legacyPublisherRetirement"]["preservedUntilLaterActivationAssignmentResourceId"].endswith("/" + PRESERVED))

    def test_exact_production_assignment_cleanup_restores_lock_without_site_write(self):
        transport, session, journal, operation, state, _, _ = self.make()
        result = transport._mutate(operation, state)
        self.assert_exact_mutations(transport, session)
        self.assertEqual(session.locks, session.original_locks)
        self.assertEqual(result["deletionLock"], bootstrap._expected_deletion_lock_proof(OPERATION))
        self.assertEqual(len(journal.records), 6)

    def test_absent_authorized_assignment_preserves_lock_without_mutation(self):
        transport, session, journal, operation, state, _, _ = self.make()
        session.assignment = None
        probe = transport.probes["authorized-assignment"]
        probe["status"] = 404
        probe["responseSha256"] = bootstrap._preflight_response_sha256("GET", session.assignment_url, response(404))
        result = transport._mutate(operation, state)
        self.assert_exact_mutations(transport, session, present=False)
        self.assertEqual(session.locks, session.original_locks)
        self.assertTrue(result["deletionLock"]["restored"])
        self.assertEqual(journal.records, [])

    def test_realistic_five_lock_inventory_accepts_three_and_ignores_two_irrelevant(self):
        plan, _ = bootstrap.load_plan()
        inventory = observed_five_lock_inventory()
        self.assertEqual(len(inventory["value"]), 5)
        projected = bootstrap._cleanup_lock_inventory_projection(inventory, plan)
        self.assertEqual(projected, bootstrap._expected_cleanup_lock_inventory())
        self.assertEqual(len(projected["locks"]), 3)

    def test_inventory_rejects_missing_drifted_duplicate_and_extra_inherited_lock(self):
        plan, _ = bootstrap.load_plan()
        expected_ids = {item["resourceId"] for item in bootstrap._expected_cleanup_lock_inventory()["locks"]}
        for resource_id in expected_ids:
            for variant in ("missing", "notes", "level", "owners", "duplicate"):
                with self.subTest(resource=resource_id, variant=variant):
                    inventory = observed_five_lock_inventory()
                    entry = next(item for item in inventory["value"] if item["id"] == resource_id)
                    if variant == "missing":
                        inventory["value"].remove(entry)
                    elif variant == "duplicate":
                        inventory["value"].append(copy.deepcopy(entry))
                    elif variant == "owners":
                        entry["properties"]["owners"] = [{"applicationId": "unreviewed"}]
                    else:
                        entry["properties"][variant] = "drift"
                    with self.assertRaises(bootstrap.BootstrapError):
                        bootstrap._cleanup_lock_inventory_projection(inventory, plan)
        for scope in (SUB, SUB + "/resourceGroups/rg-master-data-structure-sea"):
            inventory = observed_five_lock_inventory()
            inventory["value"].append(lock_document(scope + "/providers/Microsoft.Authorization/locks/extra-inherited", "unreviewed"))
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap._cleanup_lock_inventory_projection(inventory, plan)

    def test_ambiguous_assignment_delete_restores_exact_lock_without_replay(self):
        transport, session, _, operation, state, _, _ = self.make()
        session.assignment_failure = RuntimeError("ambiguous exact RBAC delete")
        with self.assertRaises(RuntimeError):
            transport._mutate(operation, state)
        self.assert_exact_mutations(transport, session)
        self.assertEqual(session.locks, session.original_locks)
        before = list(session.requests)
        with self.assertRaises(bootstrap.BootstrapError):
            transport._mutate(operation, state)
        self.assertEqual(session.requests, before)

    def test_expired_authority_never_suspends_production_lock(self):
        transport, session, journal, operation, state, current, _ = self.make()
        current[0] = bootstrap.parse_time(transport.authorization["validity"]["expiresAt"], "expiry")
        with self.assertRaisesRegex(bootstrap.BootstrapError, "expired"):
            transport._mutate(operation, state)
        self.assert_exact_mutations(transport, session, present=False)
        self.assertEqual(session.locks, session.original_locks)
        self.assertEqual(journal.records, [])


if __name__ == "__main__":
    unittest.main()
