"""Real no-network transport coverage of temporary-cleanup 404 projections."""

import copy
import unittest

from scripts import private_release_v2_bootstrap as bootstrap
from tests import test_private_release_v2_cleanup_transport as support


class CleanupProjectionTests(unittest.TestCase):
    def make(self, operation_id):
        result = support.CleanupTransportTests().make(operation_id)
        transport, session, journal, operation, state, current, sleeps = result
        contract = bootstrap._validator_contract(
            "operation:" + operation_id, transport.plan, transport.authorization)
        probe = {
            "id": "cleanup-readback", "phase": "readback",
            "validatorId": "operation:" + operation_id,
            "validatorContract": contract,
            "method": contract["expectedMethod"], "url": contract["expectedUrl"],
        }
        transport.probes[probe["id"]] = probe
        transport.admissions[operation_id]["desiredProbeIds"] = [probe["id"]]
        return result, probe

    def test_all_four_real_cleanup_404s_use_specific_projection(self):
        for operation_id in support.TEMPORARY:
            with self.subTest(operation=operation_id):
                (transport, session, _, operation, state, _, _), probe = self.make(operation_id)
                facts = transport._mutate(operation, state)
                readback = session.request("GET", probe["url"])
                self.assertEqual(readback.status, 404)
                proof = transport._validate_readback_response(probe, readback, facts)
                projection = proof["sourceProjection"]
                self.assertEqual(projection["family"], "temporary-role-cleanup-absence")
                body = projection["projection"]
                self.assertEqual(body["assignmentAbsenceProjection"],
                                 {"resourceId": facts["assignmentResourceId"], "absent": True})
                self.assertEqual(body["definitionAbsenceProjection"],
                                 {"resourceId": facts["definitionResourceId"], "absent": True})
                self.assertEqual(body["deletionLock"], bootstrap._expected_deletion_lock_proof(operation_id))
                self.assertEqual(session.locks, session.original_locks)

    def test_all_four_real_compensations_accept_exact_404_facts(self):
        for operation_id in support.TEMPORARY:
            with self.subTest(operation=operation_id):
                (transport, session, _, _, state, _, sleeps), _ = self.make(operation_id)
                added_id = operation_id.replace("remove", "add", 1)
                added = next(item for item in transport.plan["mutations"] if item["id"] == added_id)
                owned = {"owned": True, **state["proofs"][added_id]["details"]}
                result = transport.compensate_temporary(added, owned, state)
                self.assertEqual(result["status"], "removed-exact")
                self.assertTrue(result["owned"])
                self.assertEqual(session.locks, session.original_locks)
                self.assertEqual(sleeps, [])
                self.assertEqual(len(session.mutations()), 4)
                production_lock = next(url for url in session.original_locks
                                       if "paperdesk-protect-app-delete" in url)
                self.assertFalse(any(url == production_lock for _, url in session.mutations()))

    def test_missing_or_malformed_role_and_lock_facts_never_accept_404(self):
        for operation_id in support.TEMPORARY:
            (transport, session, _, operation, state, _, _), probe = self.make(operation_id)
            facts = transport._mutate(operation, state)
            readback = session.request("GET", probe["url"])
            variants = [("all missing", None)]
            for field in ("cleanupKey", "assignmentResourceId", "definitionResourceId",
                          "assignmentRemoved", "definitionRemoved", "assignmentAbsenceProjection",
                          "definitionAbsenceProjection", "deletionLock"):
                missing = copy.deepcopy(facts)
                missing.pop(field)
                variants.append(("missing " + field, missing))
                malformed = copy.deepcopy(facts)
                malformed[field] = "unrelated"
                variants.append(("malformed " + field, malformed))
            for field in ("assignmentAbsenceProjection", "definitionAbsenceProjection"):
                changed = copy.deepcopy(facts)
                changed[field]["absent"] = False
                variants.append(("present " + field, changed))
            changed = copy.deepcopy(facts)
            changed["deletionLock"]["restored"] = False
            variants.append(("lock not restored", changed))
            changed = copy.deepcopy(facts)
            changed["deletionLock"]["properties"]["notes"] = "unreviewed lock"
            variants.append(("lock properties drift", changed))
            changed = copy.deepcopy(facts)
            changed["deletionLock"]["resourceId"] = "unrelated-lock"
            variants.append(("unrelated lock", changed))
            for label, candidate in variants:
                with self.subTest(operation=operation_id, variant=label):
                    with self.assertRaises(bootstrap.BootstrapError):
                        transport._validate_readback_response(probe, readback, candidate)

    def test_wrong_url_or_status_is_not_an_exact_absence(self):
        for operation_id in support.TEMPORARY:
            (transport, _, _, operation, state, _, _), probe = self.make(operation_id)
            facts = transport._mutate(operation, state)
            wrong = copy.deepcopy(probe)
            wrong["url"] += "&unrelated=true"
            with self.subTest(operation=operation_id, variant="unrelated404"):
                with self.assertRaises(bootstrap.BootstrapError):
                    transport._validate_readback_response(wrong, support.response(404), facts)
            for status in (200, 403, 500):
                with self.subTest(operation=operation_id, status=status):
                    with self.assertRaises(bootstrap.BootstrapError):
                        transport._validate_readback_response(probe, support.response(status), facts)


if __name__ == "__main__":
    unittest.main()
