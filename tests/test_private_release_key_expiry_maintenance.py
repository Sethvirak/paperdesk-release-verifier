"""Offline contract/fault tests for the separately approved key maintenance helper.

No fixture is real key material or live Azure evidence. Every provider request
in these tests must use an injected fake session.
"""
from __future__ import annotations

import base64
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
PLAN_PATH = BASE / "contracts" / "private_release_key_expiry_maintenance_plan.json"
HELPER_PATH = BASE / "scripts" / "private_release_key_expiry_maintenance.py"
spec = importlib.util.spec_from_file_location("paperdesk_key_expiry_maintenance_offline", HELPER_PATH)
helper = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = helper
spec.loader.exec_module(helper)


def plan_fixture():
    return json.loads(PLAN_PATH.read_text(encoding="utf-8"))


def public_fixture(plan, renewed=False):
    # Arbitrary public-looking bytes: no RSA key generation or private material.
    modulus = bytes([0x80]) + bytes([0x01]) * 383
    return {
        "key": {
            "kid": plan["fixed"]["keyVersionUri"],
            "kty": "RSA",
            "key_ops": ["sign", "verify"],
            "n": base64.urlsafe_b64encode(modulus).decode("ascii").rstrip("="),
            "e": "AQAB",
        },
        "attributes": {
            "enabled": True,
            "exportable": False,
            "exp": plan["keyValidation"]["afterExpiryUnixSeconds" if renewed else "beforeExpiryUnixSeconds"],
            "nbf": None,
            "created": 1790000000,
            "updated": 1790000001 + int(renewed),
            "recoverableDays": 90,
            "recoveryLevel": "Recoverable+Purgeable",
        },
        "tags": {"synthetic": "offline-only"},
    }


def arm_fixture(plan, renewed=False):
    return {
        "id": plan["fixed"]["keyResourceId"],
        "properties": {
            "keyUriWithVersion": plan["fixed"]["keyVersionUri"],
            "kty": "RSA",
            "keySize": 3072,
            "keyOps": ["sign", "verify"],
            "attributes": {
                "enabled": True,
                "exportable": False,
                "exp": plan["keyValidation"]["afterExpiryUnixSeconds" if renewed else "beforeExpiryUnixSeconds"],
            },
            "release_policy": None,
        },
    }


class OfflineCase(unittest.TestCase):
    def setUp(self):
        self.plan = plan_fixture()
        self.temp = tempfile.TemporaryDirectory(prefix="paperdesk-key-maintenance-offline-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        # An accidental live provider call must fail, never silently become evidence.
        self.network_guard = mock.patch.object(socket.socket, "connect", side_effect=AssertionError("offline test attempted network access"))
        self.network_guard.start()
        self.addCleanup(self.network_guard.stop)

    def reject_key(self, document=None, arm=None, before=None):
        document = document if document is not None else public_fixture(self.plan)
        arm = arm if arm is not None else arm_fixture(self.plan)
        with self.assertRaises(Exception):
            helper.validate_public_key(document, self.plan, arm, before=before)


class PlanAndBudgetTests(OfflineCase):
    def test_reviewed_plan_is_accepted(self):
        helper.validate_plan(self.plan)

    def test_body_scope_and_call_budget_drift_are_rejected(self):
        variants = []
        value = copy.deepcopy(self.plan)
        value["createBodies"]["keyExpiryPatch"]["attributes"]["enabled"] = True
        variants.append(value)
        value = copy.deepcopy(self.plan)
        value["createBodies"]["roleDefinition"]["properties"]["permissions"][0]["dataActions"].append("Microsoft.KeyVault/vaults/keys/sign/action")
        variants.append(value)
        value = copy.deepcopy(self.plan)
        value["createBodies"]["roleDefinition"]["properties"]["assignableScopes"] = ["/subscriptions/" + value["fixed"]["subscriptionId"]]
        variants.append(value)
        value = copy.deepcopy(self.plan)
        value["bounds"]["keyVaultDataPlaneGetAttemptsMaximum"] = 3
        variants.append(value)
        value = copy.deepcopy(self.plan)
        value["fixed"]["ownerPrincipalId"] = "00000000-0000-4000-8000-000000000000"
        variants.append(value)
        for value in variants:
            with self.subTest(case=variants.index(value)), self.assertRaises(Exception):
                helper.validate_plan(value)

    def test_phase_budget_fits_only_reviewed_authorization_window(self):
        budget = helper.phase_budget(self.plan)
        self.assertIsInstance(budget, dict)
        self.assertIn("normal", budget)
        self.assertIn("ambiguous", budget)
        for label in ("normal", "ambiguous"):
            self.assertIs(type(budget[label]), int)
            self.assertGreater(budget[label], 0)
            self.assertLessEqual(budget[label], self.plan["bounds"]["ceremonyAuthorizationMaximumSeconds"])
        shortened = copy.deepcopy(self.plan)
        shortened["bounds"]["ceremonyAuthorizationMaximumSeconds"] = 3600
        with self.assertRaises(Exception):
            helper.validate_plan(shortened)


class PublicKeyTests(OfflineCase):
    def test_exact_public_key_and_expiry_only_update_are_accepted(self):
        before = helper.validate_public_key(public_fixture(self.plan), self.plan, arm_fixture(self.plan))
        after = helper.validate_public_key(public_fixture(self.plan, renewed=True), self.plan, arm_fixture(self.plan, renewed=True), before=before)
        self.assertIsInstance(before, dict)
        self.assertIsInstance(after, dict)
        self.assertNotIn('"d":', json.dumps(after))

    def test_same_second_updated_timestamp_is_allowed(self):
        initial = public_fixture(self.plan)
        before = helper.validate_public_key(initial, self.plan, arm_fixture(self.plan))
        changed = public_fixture(self.plan, renewed=True)
        changed["attributes"]["updated"] = initial["attributes"]["updated"]
        helper.validate_public_key(changed, self.plan, arm_fixture(self.plan, renewed=True), before=before)

    def test_exact_identity_posture_integer_types_and_modulus_are_required(self):
        variants = []
        for key, value in (("kid", self.plan["fixed"]["keyVersionUri"][:-1] + "2"), ("kty", "RSA-HSM"), ("e", "Aw"), ("key_ops", ["sign", "verify", "decrypt"])):
            document = public_fixture(self.plan)
            document["key"][key] = value
            variants.append(document)
        for key, value in (("enabled", False), ("exportable", True), ("exp", True), ("created", True), ("recoverableDays", 30), ("nbf", 1790000010)):
            document = public_fixture(self.plan)
            document["attributes"][key] = value
            variants.append(document)
        for modulus in (bytes([0x80]) + bytes([1]) * 382, bytes([0x40]) + bytes([1]) * 383):
            document = public_fixture(self.plan)
            document["key"]["n"] = base64.urlsafe_b64encode(modulus).decode("ascii").rstrip("=")
            variants.append(document)
        document = public_fixture(self.plan)
        document["key"]["n"] += "="
        variants.append(document)
        for index, document in enumerate(variants):
            with self.subTest(case=index):
                self.reject_key(document)

    def test_arm_identity_and_release_policy_are_required(self):
        for field, value in (("keyUriWithVersion", self.plan["fixed"]["keyVersionUri"][:-1] + "2"), ("keySize", 2048), ("release_policy", {"data": "synthetic"}), ("releasePolicy", {"data": "synthetic"})):
            arm = arm_fixture(self.plan)
            arm["properties"][field] = value
            with self.subTest(field=field):
                self.reject_key(arm=arm)

    def test_private_key_members_are_rejected_before_projection(self):
        for member in ("d", "p", "q", "dp", "dq", "qi", "k"):
            document = public_fixture(self.plan)
            document["key"][member] = "SYNTHETIC-NOT-A-SECRET"
            with self.subTest(member=member):
                self.reject_key(document)

    def test_nested_private_member_and_release_policy_are_rejected(self):
        for extra in ({"unexpected": {"d": "SYNTHETIC"}}, {"release_policy": {"data": "synthetic"}}):
            document = public_fixture(self.plan)
            document.update(extra)
            self.reject_key(document)

    def test_non_expiry_changes_and_tag_presence_drift_are_rejected(self):
        before = helper.validate_public_key(public_fixture(self.plan), self.plan, arm_fixture(self.plan))
        for location, field, value in (("key", "n", base64.urlsafe_b64encode(bytes([0x80]) + bytes([3]) * 383).decode("ascii")), ("attributes", "created", 1790000001), ("tags", "synthetic", "changed")):
            document = public_fixture(self.plan, renewed=True)
            document[location][field] = value
            with self.subTest(field=field):
                self.reject_key(document, arm_fixture(self.plan, renewed=True), before)
        document = public_fixture(self.plan, renewed=True)
        del document["tags"]
        self.reject_key(document, arm_fixture(self.plan, renewed=True), before)


class JournalTests(OfflineCase):
    def make_journal(self):
        return helper.Journal(self.directory / "write-journal.jsonl", self.directory / "claimed.json")

    def test_claim_is_create_only_across_new_journal_instances(self):
        first = self.make_journal()
        document = {"ceremonyId": self.plan["ceremonyId"], "status": "synthetic-offline-claim"}
        first.claim(document)
        original = (self.directory / "claimed.json").read_bytes()
        with self.assertRaises(Exception):
            self.make_journal().claim(document)
        self.assertEqual((self.directory / "claimed.json").read_bytes(), original)

    def test_journal_records_are_durable_and_parse_as_individual_json(self):
        journal = self.make_journal()
        journal.claim({"ceremonyId": self.plan["ceremonyId"]})
        with mock.patch.object(os, "fsync", wraps=os.fsync) as fsync:
            journal.record({"phase": "intent", "synthetic": True})
            journal.record({"phase": "result", "synthetic": True})
        self.assertGreaterEqual(fsync.call_count, 2)
        records = [json.loads(line) for line in (self.directory / "write-journal.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual([item["phase"] for item in records], ["intent", "result"])

    def test_claim_fsync_failure_still_consumes_claim(self):
        journal = self.make_journal()
        with mock.patch.object(os, "fsync", side_effect=OSError("synthetic-fsync-failure")), self.assertRaises(Exception):
            journal.claim({"ceremonyId": self.plan["ceremonyId"]})
        self.assertTrue((self.directory / "claimed.json").exists())
        with self.assertRaises(Exception):
            self.make_journal().claim({"ceremonyId": self.plan["ceremonyId"]})

    def test_journal_fsync_failure_is_not_reported_successful(self):
        journal = self.make_journal()
        journal.claim({"ceremonyId": self.plan["ceremonyId"]})
        with mock.patch.object(os, "fsync", side_effect=OSError("synthetic-result-fsync-failure")), self.assertRaises(Exception):
            journal.record({"phase": "result", "synthetic": True})


class SyntheticClock:
    def __init__(self):
        self.value = dt.datetime(2026, 10, 1, 3, 0, tzinfo=dt.timezone.utc)

    def __call__(self):
        return self.value

    def sleep(self, seconds):
        self.value += dt.timedelta(seconds=seconds)


class SyntheticAmbiguity(RuntimeError):
    pass


class FakeSession:
    """Duck-typed injected transport; never constructs a real Azure session."""
    def __init__(self, response=None, responder=None):
        self.calls = []
        self.response = response or SimpleNamespace(status=200, body=b"{}", headers={})
        self.responder = responder

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        return self.responder(method, url, **kwargs) if self.responder else self.response

    def account(self):
        return {"subscriptionId": helper.SUB, "tenantId": helper.TENANT,
                "accountObjectId": helper.OWNER, "accountType": "user", "cloud": "AzureCloud"}


class RequestGateTests(OfflineCase):
    def setup_maintenance(self, response=None, responder=None):
        self.clock = SyntheticClock()
        self.journal = helper.Journal(self.directory / "write-journal.jsonl", self.directory / "claimed.json")
        self.journal.claim({"ceremonyId": self.plan["ceremonyId"], "synthetic": True})
        auth = {"validity": {"notBefore": self.clock().isoformat().replace("+00:00", "Z"),
                              "expiresAt": (self.clock() + dt.timedelta(seconds=self.plan["bounds"]["ceremonyAuthorizationMaximumSeconds"])).isoformat().replace("+00:00", "Z")}}
        self.session = FakeSession(response=response, responder=responder)
        return helper.Maintenance(self.plan, auth, self.session, self.journal, self.clock, self.clock.sleep)

    def test_get_exact_scope_normal_envelope_and_guard_boundary_allowance(self):
        maintenance = self.setup_maintenance()
        url = self.plan["preflight"]["requiredArmKeyGetUrl"]
        for method, target, deadline in (("POST", url, None), ("GET", url + "&extra=1", None),
                                         ("GET", url, self.clock() + dt.timedelta(seconds=87))):
            with self.subTest(method=method, target=target), self.assertRaises(Exception):
                maintenance.read(method, target, deadline=deadline)
        self.assertEqual(self.session.calls, [])
        maintenance.phase_deadline = self.clock() + dt.timedelta(seconds=self.plan["bounds"]["restResponseAndTokenEnvelopeSeconds"] - 1)
        with self.assertRaises(Exception):
            maintenance.read("GET", url)
        self.assertEqual(self.session.calls, [])
        maintenance.phase_deadline = maintenance.end
        # The unchanged source guard's logical90s final read retains its completion
        # bound; only its transport admission receives the separately reviewed2s.
        maintenance.read("GET", url, deadline=self.clock() + dt.timedelta(seconds=90))
        self.assertEqual(len(self.session.calls), 1)
        self.assertEqual(self.session.calls[0]["deadline"], self.clock() + dt.timedelta(seconds=90 + self.plan["bounds"]["transportAdmissionBoundaryAllowanceSeconds"]))

    def test_key_get_and_control_get_budgets_count_wire_attempts(self):
        maintenance = self.setup_maintenance(response=SimpleNamespace(status=403, body=b"{}", headers={}))
        self.clock.sleep(480)
        key_url = self.plan["dataPlaneSequence"][0]["url"]
        maintenance.read("GET", key_url)
        maintenance.read("GET", key_url)
        with self.assertRaises(Exception):
            maintenance.read("GET", key_url)
        self.assertEqual(len(self.session.calls), 2)
        maintenance.control_gets = self.plan["bounds"]["controlPlaneGetAttemptsMaximum"]
        with self.assertRaises(Exception):
            maintenance.read("GET", self.plan["preflight"]["requiredArmKeyGetUrl"])
        self.assertEqual(len(self.session.calls), 2)

    def test_duplicate_and_nonfinite_json_rejected_before_read_journal(self):
        url = self.plan["preflight"]["requiredArmKeyGetUrl"]
        for body in (b'{"properties":{},"properties":{"ignored":true}}', b'{"value":NaN}'):
            maintenance = self.setup_maintenance(response=SimpleNamespace(status=200, body=body, headers={}))
            with self.assertRaises(Exception):
                maintenance.read("GET", url)
            self.assertEqual(len(self.session.calls), 1)
            self.assertFalse((self.directory / "write-journal.jsonl").exists())
            # Use distinct local claim paths for each independent synthetic fixture.
            self.temp.cleanup()
            self.temp = tempfile.TemporaryDirectory(prefix="paperdesk-key-maintenance-offline-")
            self.addCleanup(self.temp.cleanup)
            self.directory = Path(self.temp.name)

    def test_clock_regression_stops_calls(self):
        maintenance = self.setup_maintenance()
        self.clock.sleep(-1)
        with self.assertRaises(Exception):
            maintenance.read("GET", self.plan["preflight"]["requiredArmKeyGetUrl"])
        self.assertEqual(self.session.calls, [])

    def test_expired_authorization_never_admits_role_or_key_writes(self):
        maintenance = self.setup_maintenance()
        self.clock.sleep(self.plan["bounds"]["ceremonyAuthorizationMaximumSeconds"])
        for step in (self.plan["mutationAttemptOrder"][2], self.plan["mutationAttemptOrder"][4], self.plan["mutationAttemptOrder"][6]):
            body = helper.canonical(self.plan["createBodies"]["keyExpiryPatch"]) if step["method"] == "PATCH" else None
            with self.subTest(step=step["id"]), self.assertRaises(Exception):
                maintenance.mutate(step["method"], step["url"], body, expected=set(step["successStatuses"]))
        self.assertEqual(self.session.calls, [])

    def test_first_and_second_key_get_late_cutoffs_stop_before_wire(self):
        maintenance = self.setup_maintenance(response=SimpleNamespace(status=403, body=b"{}", headers={}))
        key_url = self.plan["dataPlaneSequence"][0]["url"]
        self.clock.sleep(601)
        with self.assertRaises(Exception):
            maintenance.read("GET", key_url)
        self.assertEqual(self.session.calls, [])
        # Model exactly one consumed first GET; no extra provider call is made.
        maintenance.key_gets = 1
        self.clock.sleep(180)
        with self.assertRaises(Exception):
            maintenance.read("GET", key_url)
        self.assertEqual(self.session.calls, [])

    def test_positive_sleep_with_frozen_clock_is_rejected(self):
        maintenance = self.setup_maintenance()
        maintenance._sleep = lambda seconds: None
        with self.assertRaises(Exception):
            maintenance.sleep(2)

    def test_grant_cutoff_and_body_expansion_stop_before_intent(self):
        maintenance = self.setup_maintenance()
        step = self.plan["mutationAttemptOrder"][0]
        body = copy.deepcopy(self.plan["createBodies"]["roleDefinition"])
        body["properties"]["permissions"][0]["actions"] = ["*"]
        with self.assertRaises(Exception):
            maintenance.mutate("PUT", step["url"], helper.canonical(body), expected={201})
        self.clock.sleep(211)
        with self.assertRaises(Exception):
            maintenance.mutate("PUT", step["url"], helper.canonical(self.plan["createBodies"]["roleDefinition"]), expected={201})
        self.assertEqual(self.session.calls, [])
        self.assertFalse(maintenance.owned_role)

    def test_mutation_has_json_content_type_and_is_one_use(self):
        maintenance = self.setup_maintenance(response=SimpleNamespace(status=201, body=b"{}", headers={}))
        step = self.plan["mutationAttemptOrder"][0]
        body = helper.canonical(self.plan["createBodies"]["roleDefinition"])
        maintenance.mutate("PUT", step["url"], body, expected={201})
        self.assertEqual(self.session.calls[0].get("headers"), {"Content-Type": "application/json"})
        with self.assertRaises(Exception):
            maintenance.mutate("PUT", step["url"], body, expected={201})
        self.assertEqual(len(self.session.calls), 1)

    def test_intent_fsync_failure_never_calls_provider_or_grants_ownership(self):
        maintenance = self.setup_maintenance()
        step = self.plan["mutationAttemptOrder"][0]
        body = helper.canonical(self.plan["createBodies"]["roleDefinition"])
        with mock.patch.object(self.journal, "record", side_effect=OSError("synthetic-intent-fsync")), self.assertRaises(Exception):
            maintenance.mutate("PUT", step["url"], body, expected={201})
        self.assertEqual(self.session.calls, [])
        self.assertFalse(maintenance.owned_role)
        with self.assertRaises(Exception):
            maintenance.mutate("PUT", step["url"], body, expected={201})
        self.assertEqual(self.session.calls, [])

    def test_patch_ambiguity_never_allows_a_second_patch(self):
        def ambiguous(method, url, **kwargs):
            raise SyntheticAmbiguity("synthetic-provider-outcome-unknown")
        maintenance = self.setup_maintenance(responder=ambiguous)
        step = self.plan["mutationAttemptOrder"][2]
        body = helper.canonical(self.plan["createBodies"]["keyExpiryPatch"])
        with self.assertRaises(Exception):
            maintenance.mutate("PATCH", step["url"], body, expected={200})
        with self.assertRaises(Exception):
            maintenance.mutate("PATCH", step["url"], body, expected={200})
        self.assertEqual(len(self.session.calls), 1)

    def test_result_journal_failure_consumes_mutation(self):
        maintenance = self.setup_maintenance(response=SimpleNamespace(status=201, body=b"{}", headers={}))
        step = self.plan["mutationAttemptOrder"][0]
        original = self.journal.record
        def fail_result(document):
            if document.get("kind") == "result":
                raise OSError("synthetic-result-fsync")
            original(document)
        with mock.patch.object(self.journal, "record", side_effect=fail_result), self.assertRaises(Exception):
            maintenance.mutate("PUT", step["url"], helper.canonical(self.plan["createBodies"]["roleDefinition"]), expected={201})
        with self.assertRaises(Exception):
            maintenance.mutate("PUT", step["url"], helper.canonical(self.plan["createBodies"]["roleDefinition"]), expected={201})
        self.assertEqual(len(self.session.calls), 1)
        self.assertTrue(maintenance.owned_role)

    def test_owned_assignment_projection_drift_stops_deletion(self):
        document = helper.expected_assignment(self.plan)
        document["properties"]["description"] = "foreign-owner"
        maintenance = self.setup_maintenance(response=SimpleNamespace(status=200, body=helper.canonical(document), headers={}))
        with self.assertRaises(Exception):
            maintenance.prove_owned(self.plan["mutationAttemptOrder"][1]["url"], "assignment")
        self.assertTrue(all(call["method"] == "GET" for call in self.session.calls))


class InventoryTests(OfflineCase):
    def test_partial_paginated_or_duplicate_resource_inventory_is_rejected(self):
        for document in ({"value": [], "nextLink": "https://foreign.invalid/next"},
                         {"value": {}}, {"value": [{"id": "SYNTHETIC"}, {"id": "synthetic"}]},
                         {"value": [{"properties": {}}]}):
            with self.subTest(document=document), self.assertRaises(Exception):
                helper.complete_inventory(document)

    def test_permission_exclusion_is_per_entry_and_data_permissions_remain_separate(self):
        action = "Microsoft.Authorization/roleAssignments/delete"
        rows = [{"actions": ["*"], "notActions": [action], "dataActions": [], "notDataActions": []}]
        self.assertFalse(helper.listed_permission(rows, action))
        rows.append({"actions": [action], "notActions": [], "dataActions": [], "notDataActions": []})
        self.assertTrue(helper.listed_permission(rows, action))
        self.assertFalse(helper.listed_permission(rows, "Microsoft.KeyVault/vaults/keys/update/action", data=True))


class FakeAzure(FakeSession):
    """Small stateful provider model for cleanup, never a production adapter."""
    def __init__(self, plan, clock, key_get_403=False, patch_ambiguous=False, assignment_drift=False):
        super().__init__()
        self.plan, self.clock = plan, clock
        self.role = self.assignment = None
        self.lock = {"id": helper.LOCK, "name": "paperdesk-protect-keyvault-delete",
                     "type": "Microsoft.Authorization/locks",
                     "properties": copy.deepcopy(plan["createBodies"]["exactLockRestoration"]["properties"])}
        self.public = public_fixture(plan)
        self.arm_key = arm_fixture(plan)
        self.vault = {"id": helper.VAULT, "properties": {
            "enableRbacAuthorization": True, "enableSoftDelete": True,
            "enablePurgeProtection": True, "publicNetworkAccess": "Enabled",
            "networkAcls": {"defaultAction": "Allow", "bypass": "None"}}}
        self.permissions = {"value": [{"actions": ["*"], "notActions": [], "dataActions": [], "notDataActions": []}]}
        self.key_get_403, self.patch_ambiguous, self.assignment_drift = key_get_403, patch_ambiguous, assignment_drift
        self.key_gets = 0

    def initial_snapshot(self):
        return {"roleDefinition": {"status": 404}, "assignment": {"status": 404},
                "locks": [copy.deepcopy(self.lock)], "roleDefinitions": [], "assignments": [],
                "lock": copy.deepcopy(self.lock), "vault": copy.deepcopy(self.vault), "armKey": copy.deepcopy(self.arm_key)}

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        # Small deterministic elapsed time makes synthetic polling monotonic.
        self.clock.sleep(0.001)
        pre = self.plan["preflight"]
        status, value = 200, {}
        if method == "GET":
            if url == helper.arm_url(helper.ROLE_ID):
                status, value = (200, self.role) if self.role else (404, {})
            elif url == helper.arm_url(helper.ASSIGNMENT_ID):
                status, value = (200, self.assignment) if self.assignment else (404, {})
            elif url == pre["requiredCompleteInventoryUrls"][0]:
                value = {"value": [self.lock] if self.lock else []}
            elif url == pre["requiredCompleteInventoryUrls"][1]:
                value = {"value": [self.role] if self.role else []}
            elif url == pre["requiredCompleteInventoryUrls"][2]:
                value = {"value": [self.assignment] if self.assignment else []}
            elif url == pre["requiredExactLockGetUrl"]:
                status, value = (200, self.lock) if self.lock else (404, {})
            elif url == pre["requiredVaultGetUrl"]:
                value = self.vault
            elif url == pre["requiredArmKeyGetUrl"]:
                value = self.arm_key
            elif url == pre["freshCallerKeyPermissionsGetUrl"]:
                value = self.permissions
            elif url == helper.KID + "?api-version=2025-07-01":
                self.key_gets += 1
                status, value = (403, {}) if self.key_get_403 else (200, self.public)
                if self.assignment_drift and self.key_gets == 2:
                    self.assignment["properties"]["description"] = "foreign-owner"
            else:
                raise AssertionError("unplanned synthetic GET")
        elif method == "PUT" and url == helper.arm_url(helper.ROLE_ID):
            self.role, status = copy.deepcopy(helper.expected_role(self.plan)), 201
            value = self.role
        elif method == "PUT" and url == helper.arm_url(helper.ASSIGNMENT_ID):
            self.assignment, status = copy.deepcopy(helper.expected_assignment(self.plan)), 201
            value = self.assignment
        elif method == "PATCH" and url == helper.KID + "?api-version=2025-07-01":
            self.public = public_fixture(self.plan, renewed=True)
            self.arm_key = arm_fixture(self.plan, renewed=True)
            if self.patch_ambiguous:
                raise SyntheticAmbiguity("synthetic-PATCH-applied-no-response")
            value = self.public
        elif method == "DELETE" and url == helper.arm_url(helper.LOCK, "2016-09-01"):
            self.lock = None
        elif method == "PUT" and url == helper.arm_url(helper.LOCK, "2016-09-01"):
            self.lock = {"id": helper.LOCK, "name": "paperdesk-protect-keyvault-delete",
                         "type": "Microsoft.Authorization/locks",
                         "properties": copy.deepcopy(self.plan["createBodies"]["exactLockRestoration"]["properties"])}
            value = self.lock
        elif method == "DELETE" and url == helper.arm_url(helper.ASSIGNMENT_ID):
            self.assignment, status = None, 204
        elif method == "DELETE" and url == helper.arm_url(helper.ROLE_ID):
            self.role, status = None, 204
        else:
            raise AssertionError("unplanned synthetic mutation")
        return SimpleNamespace(status=status, body=helper.canonical(value), headers={"Content-Type": "application/json"})


class EndToEndFaultTests(OfflineCase):
    def setup_run(self, **faults):
        self.clock = SyntheticClock()
        self.journal = helper.Journal(self.directory / "write-journal.jsonl", self.directory / "claimed.json")
        self.session = FakeAzure(self.plan, self.clock, **faults)
        primitive_path = BASE / "scripts" / "private_release_v2_cleanup_locks.py"
        cleanup_spec = importlib.util.spec_from_file_location("paperdesk_cleanup_locks_offline", primitive_path)
        cleanup = importlib.util.module_from_spec(cleanup_spec)
        cleanup_spec.loader.exec_module(cleanup)
        # Synthetic approval has no cloud authority and exists only in this temp run.
        auth = {"ceremonyId": helper.CEREMONY, "maintenancePlanSha256": helper.digest(PLAN_PATH.read_bytes()),
                "executorSha256": helper.digest(HELPER_PATH.read_bytes()), "operatorHost": "SYNTHETIC-OFFLINE-HOST",
                "validity": {"notBefore": self.clock().isoformat().replace("+00:00", "Z"),
                             "expiresAt": (self.clock() + dt.timedelta(seconds=self.plan["bounds"]["ceremonyAuthorizationMaximumSeconds"])).isoformat().replace("+00:00", "Z")}}
        maintenance = helper.Maintenance(self.plan, auth, self.session, self.journal, self.clock, self.clock.sleep, cleanup_module=cleanup)
        timestamp = self.clock().isoformat().replace("+00:00", "Z")
        preflight = {"kind": "paperdesk-key-expiry-maintenance-preflight", "ceremonyId": helper.CEREMONY,
                     "observedAt": timestamp, "completedAt": timestamp,
                     "snapshot": self.session.initial_snapshot(), "callerPermissions": copy.deepcopy(self.session.permissions)}
        return maintenance, preflight

    def assert_cleanup(self):
        self.assertIsNone(self.session.role)
        self.assertIsNone(self.session.assignment)
        self.assertIsNotNone(self.session.lock)
        self.assertEqual(self.session.lock["properties"], self.plan["createBodies"]["exactLockRestoration"]["properties"])
        writes = [call for call in self.session.calls if call["method"] != "GET"]
        self.assertLessEqual(len(writes), 7)
        self.assertEqual(len({(call["method"], call["url"]) for call in writes}), len(writes))

    def test_clean_path_renews_once_cleans_grant_and_does_not_claim_release_go(self):
        maintenance, preflight = self.setup_run()
        receipt = maintenance.run(preflight)
        self.assertEqual(receipt["overall"], "PASS")
        self.assertEqual(receipt["renewal"], "PASS")
        self.assertEqual(receipt["keyVaultGetAttempts"], 2)
        self.assertIs(receipt["bootstrapS2"], False)
        self.assertIs(receipt["releaseGo"], False)
        self.assert_cleanup()

    def test_first_public_get_403_never_patches_and_cleans_up(self):
        maintenance, preflight = self.setup_run(key_get_403=True)
        receipt = maintenance.run(preflight)
        self.assertEqual(receipt["overall"], "NO_GO")
        self.assertEqual(receipt["keyVaultGetAttempts"], 1)
        self.assertFalse(any(call["method"] == "PATCH" for call in self.session.calls))
        self.assert_cleanup()

    def test_ambiguous_patch_reconciles_once_preserves_failure_and_cleans_up(self):
        maintenance, preflight = self.setup_run(patch_ambiguous=True)
        receipt = maintenance.run(preflight)
        self.assertEqual(receipt["overall"], "NO_GO")
        self.assertEqual(receipt["keyVaultGetAttempts"], 2)
        self.assertEqual(sum(call["method"] == "PATCH" for call in self.session.calls), 1)
        self.assert_cleanup()

    def test_foreign_assignment_marker_is_never_deleted(self):
        maintenance, preflight = self.setup_run(assignment_drift=True)
        with self.assertRaises(Exception):
            maintenance.run(preflight)
        self.assertIsNotNone(self.session.assignment)
        self.assertIsNotNone(self.session.lock)
        self.assertFalse(any(call["method"] == "DELETE" and call["url"] == helper.arm_url(helper.ASSIGNMENT_ID) for call in self.session.calls))

    def test_lock_delete_result_journal_failure_still_restores_exact_lock(self):
        maintenance, preflight = self.setup_run()
        original = self.journal.record
        failed = []
        def fail_lock_result(document):
            if document.get("kind") == "result" and document.get("id") == self.plan["mutationAttemptOrder"][3]["id"] and not failed:
                failed.append(True)
                raise OSError("synthetic-lock-result-fsync-failure")
            original(document)
        with mock.patch.object(self.journal, "record", side_effect=fail_lock_result), self.assertRaises(Exception):
            maintenance.run(preflight)
        self.assertTrue(failed)
        self.assertIsNotNone(self.session.lock)
        self.assertEqual(self.session.lock["properties"], self.plan["createBodies"]["exactLockRestoration"]["properties"])
        self.assertEqual(sum(call["method"] == "DELETE" and call["url"] == helper.arm_url(helper.LOCK, "2016-09-01") for call in self.session.calls), 1)
        self.assertEqual(sum(call["method"] == "PUT" and call["url"] == helper.arm_url(helper.LOCK, "2016-09-01") for call in self.session.calls), 1)


class TickingClock(SyntheticClock):
    def __call__(self):
        # Real time advances between outer helper admission and source admission.
        self.value += dt.timedelta(milliseconds=10)
        return self.value


class ReviewedTransportIntegrationTests(OfflineCase):
    @classmethod
    def setUpClass(cls):
        # Local Git/file validation only; importing these primitives performs no Azure work.
        cls.bootstrap, cls.cleanup_module = helper.load_primitives(BASE)

    def setup_transport(self, exchange=None):
        self.clock = TickingClock()
        origin = self.clock.value
        auth = {"azure": {"accountObjectId": helper.OWNER}, "validity": {
            "notBefore": origin.isoformat().replace("+00:00", "Z"),
            "expiresAt": (origin + dt.timedelta(seconds=self.plan["bounds"]["ceremonyAuthorizationMaximumSeconds"])).isoformat().replace("+00:00", "Z")}}
        self.exchanges, self.synthetic_token_calls = [], []
        def fake_exchange(request, timeout):
            self.exchanges.append({"method": request.get_method(), "url": request.full_url, "timeout": timeout})
            if exchange:
                return exchange(request, timeout)
            status = 201 if request.get_method() == "PUT" else 200
            return self.bootstrap._RestResponse(status, b"{}", {"Content-Type": "application/json"})
        session = self.bootstrap.AzureCliRestSession(auth, clock=self.clock, exchange_runner=fake_exchange)
        def synthetic_token(arguments, label):
            # This is intentionally not a real credential or signing operation.
            self.assertEqual(arguments[:2], ["account", "get-access-token"])
            resource = arguments[arguments.index("--resource") + 1]
            claims = {"tid": helper.TENANT, "oid": helper.OWNER, "aud": resource,
                      "exp": int(self.clock.value.timestamp()) + 10000,
                      "nbf": int(self.clock.value.timestamp()) - 1,
                      "iat": int(self.clock.value.timestamp())}
            def encode(value):
                return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
            self.synthetic_token_calls.append(resource)
            return {"accessToken": encode({"alg": "none", "typ": "JWT"}) + "." + encode(claims) + ".SYNTHETIC-NOT-A-CREDENTIAL"}
        self.token_guard = mock.patch.object(session, "_run_az_json", side_effect=synthetic_token)
        self.token_guard.start()
        self.addCleanup(self.token_guard.stop)
        self.journal = helper.Journal(self.directory / "write-journal.jsonl", self.directory / "claimed.json")
        self.journal.claim({"ceremonyId": helper.CEREMONY, "synthetic": True})
        maintenance = helper.Maintenance(self.plan, auth, session, self.journal, self.clock, self.clock.sleep,
                                         cleanup_module=self.cleanup_module)
        return maintenance, session

    def test_advancing_clock_real_transport_reaches_fake_get_and_put_exchange(self):
        maintenance, session = self.setup_transport()
        with mock.patch.object(session, "request", wraps=session.request) as requests:
            maintenance.read("GET", self.plan["preflight"]["requiredArmKeyGetUrl"])
            step = self.plan["mutationAttemptOrder"][0]
            maintenance.mutate("PUT", step["url"], helper.canonical(self.plan["createBodies"]["roleDefinition"]), expected={201})
        self.assertEqual([call["method"] for call in self.exchanges], ["GET", "PUT"])
        self.assertTrue(self.synthetic_token_calls)
        self.assertTrue(all(0 < call["timeout"] <= 45 for call in self.exchanges))
        for call in requests.call_args_list:
            self.assertLessEqual(call.kwargs["deadline"], maintenance.end)
            self.assertLessEqual((call.kwargs["deadline"] - maintenance.start).total_seconds(), 95)

    def test_guard_final_logical_ninety_second_deadline_is_not_extended_by_transport_slack(self):
        baseline = helper.parse_time("2026-10-01T03:00:00Z")
        convergence = baseline + dt.timedelta(seconds=120)
        logical_end = convergence + dt.timedelta(seconds=90)
        late_final_exchange = []
        lock = {"id": helper.LOCK, "name": "paperdesk-protect-keyvault-delete", "type": "Microsoft.Authorization/locks",
                "properties": copy.deepcopy(self.plan["createBodies"]["exactLockRestoration"]["properties"])}
        def exchange(request, timeout):
            if self.clock.value >= convergence:
                self.clock.value = logical_end + dt.timedelta(milliseconds=20)
                late_final_exchange.append(True)
                return self.bootstrap._RestResponse(404, b"{}", {})
            return self.bootstrap._RestResponse(200, helper.canonical(lock), {})
        maintenance, _ = self.setup_transport(exchange)
        guard = self.cleanup_module.CleanupLockGuard(
            read_request=maintenance.read, mutate_request=maintenance.mutate,
            verify_lock_inventory=lambda *args: None, clock=maintenance.now, sleep=maintenance.sleep,
            fail=helper.fail, require_live_authorization=lambda: None)
        validate = lambda document: self.cleanup_module.validate_lock_document(
            document, self.cleanup_module.REVIEWED_CLEANUP_LOCKS["signingVault"], helper.fail)
        with self.assertRaises(Exception):
            guard._poll_state(helper.arm_url(helper.LOCK, "2016-09-01"), "absent", validate,
                              "synthetic final logical boundary", 120, final_observation_seconds=90)
        self.assertTrue(late_final_exchange, "test must reach the fake final exchange rather than pass by admission failure")

    def test_ambiguous_creation_reconciliation_never_restarts_original_window(self):
        def exchange(request, timeout):
            raise SyntheticAmbiguity("synthetic-create-outcome-unknown")
        maintenance, _ = self.setup_transport(exchange)
        step = self.plan["mutationAttemptOrder"][0]
        with self.assertRaises(Exception):
            maintenance.mutate("PUT", step["url"], helper.canonical(self.plan["createBodies"]["roleDefinition"]), expected={201})
        self.assertEqual(len(self.exchanges), 1, "creation ambiguity must come from the fake exchange")
        boundary = maintenance.creation_settlement_boundaries["role"]
        self.clock.value = boundary + dt.timedelta(seconds=95)
        previous_calls = len(self.exchanges)
        with self.assertRaises(Exception):
            maintenance.reconcile_creation("role")
        self.assertEqual(maintenance.creation_settlement_boundaries["role"], boundary)
        self.assertEqual(len(self.exchanges), previous_calls)


class ExceptionalRestorationTests(OfflineCase):
    setup_run = EndToEndFaultTests.setup_run

    def test_post_expiry_only_exact_previously_suspended_lock_can_restore(self):
        maintenance, _ = self.setup_run()
        self.journal.claim({"ceremonyId": helper.CEREMONY, "synthetic": True})
        maintenance.owned_assignment = True
        suspension = self.plan["mutationAttemptOrder"][3]
        maintenance.mutate("DELETE", suspension["url"], expected=set(suspension["successStatuses"]))
        self.assertIsNone(self.session.lock)
        self.clock.value = maintenance.end + dt.timedelta(seconds=1)
        maintenance.phase_deadline = maintenance.end + dt.timedelta(seconds=900)
        # Simulate the reviewed guard's protected restoration callback only.
        maintenance.source_guard_restoration_context = True
        guard = maintenance.cleanup_module.CleanupLockGuard(
            read_request=maintenance.read, post_delete_read_request=maintenance.read,
            mutate_request=maintenance.mutate, verify_lock_inventory=lambda *args: None,
            clock=maintenance.now, sleep=maintenance.sleep, fail=helper.fail,
            require_live_authorization=lambda: maintenance._admit(maintenance.end))
        guard._restore_lock(helper.arm_url(helper.LOCK, "2016-09-01"),
                            maintenance.cleanup_module.REVIEWED_CLEANUP_LOCKS["signingVault"])
        self.assertEqual(self.session.lock["properties"], self.plan["createBodies"]["exactLockRestoration"]["properties"])
        call_count = len(self.session.calls)
        with self.assertRaises(Exception):
            maintenance.mutate("DELETE", helper.arm_url(helper.ROLE_ID), expected={200, 204})
        self.assertEqual(len(self.session.calls), call_count)


class SourceAdmissionTests(OfflineCase):
    def committed_blob(self, relative):
        # Local Git reads only: preserve bytes rather than shell/text newline conversion.
        return helper.subprocess.run(["git", "-C", str(BASE), "show", "HEAD:" + relative],
                                     check=True, capture_output=True).stdout

    def test_committed_bootstrap_plan_lf_blob_has_exact_historical_crlf_projection(self):
        raw = self.committed_blob("contracts/private_release_bootstrap_plan.json")
        self.assertNotIn(b"\r", raw)
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertIn(b"\n", raw)
        self.assertEqual(helper.digest(raw), helper.BOOTSTRAP_PLAN_GIT_BLOB_SHA)
        self.assertEqual(helper.digest(raw), self.plan["source"]["unchangedBootstrapPlanGitBlobSha256"])
        projected = raw.replace(b"\n", b"\r\n")
        self.assertEqual(helper.digest(projected), helper.BOOTSTRAP_PLAN_SHA)
        self.assertEqual(helper.digest(projected), self.plan["source"]["unchangedBootstrapPlanSha256"].lower())

    def test_crlf_bom_and_content_drift_stop_before_import(self):
        relative_paths = ("contracts/private_release_bootstrap_plan.json", "scripts/private_release_v2_bootstrap.py",
                          "scripts/private_release_v2_cleanup_locks.py",
                          "scripts/private_release_v2_history_conflict_diagnostics.py",
                          "scripts/private_release_v2_history_detail_budget.py")
        originals = {(BASE / relative).resolve(): self.committed_blob(relative) for relative in relative_paths}
        original_read, original_import = Path.read_bytes, __import__
        for relative in relative_paths:
            hostile_path = (BASE / relative).resolve()
            raw = originals[hostile_path]
            variants = {"CRLF": raw.replace(b"\n", b"\r\n"), "BOM": b"\xef\xbb\xbf" + raw,
                        "content": raw + b"\nsynthetic content drift\n"}
            for label, altered in variants.items():
                attempted_imports = []

                def synthetic_read(path):
                    resolved = path.resolve()
                    if resolved == hostile_path:
                        return altered
                    return originals[resolved] if resolved in originals else original_read(path)

                def clean_git(arguments, **kwargs):
                    if "rev-parse" in arguments:
                        return SimpleNamespace(stdout="1" * 40)
                    if "diff" in arguments:
                        return SimpleNamespace(stdout="")
                    raise AssertionError("unexpected local Git metadata request")

                def no_primitive_import(name, *args, **kwargs):
                    if name in ("private_release_v2_bootstrap", "private_release_v2_cleanup_locks",
                                "private_release_v2_history_conflict_diagnostics", "private_release_v2_history_detail_budget"):
                        attempted_imports.append(name)
                        raise AssertionError("drifted primitive import was reached")
                    return original_import(name, *args, **kwargs)

                with self.subTest(relative=relative, drift=label), \
                        mock.patch.object(Path, "read_bytes", synthetic_read), \
                        mock.patch.object(helper.subprocess, "run", side_effect=clean_git), \
                        mock.patch("builtins.__import__", side_effect=no_primitive_import), \
                        self.assertRaises(helper.MaintenanceError):
                    helper.load_primitives(BASE)
                self.assertEqual(attempted_imports, [])

    def test_reviewed_primitive_map_binds_exact_four_committed_lf_dependencies(self):
        names = ("private_release_v2_bootstrap.py", "private_release_v2_cleanup_locks.py",
                 "private_release_v2_history_conflict_diagnostics.py", "private_release_v2_history_detail_budget.py")
        self.assertEqual(set(self.plan["source"]["pinnedPrimitiveHashes"]), set(names))
        for name in names:
            raw = self.committed_blob("scripts/" + name)
            with self.subTest(primitive=name):
                self.assertNotIn(b"\r", raw)
                self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
                self.assertEqual(helper.digest(raw), self.plan["source"]["pinnedPrimitiveHashes"][name])
                self.assertNotEqual(helper.digest(raw.replace(b"\n", b"\r\n")),
                                    self.plan["source"]["pinnedPrimitiveHashes"][name])

    def test_cached_history_dependency_outside_reviewed_checkout_is_rejected(self):
        original_read, original_import = Path.read_bytes, __import__
        paths = ("contracts/private_release_bootstrap_plan.json", "scripts/private_release_v2_bootstrap.py",
                 "scripts/private_release_v2_cleanup_locks.py", "scripts/private_release_v2_history_conflict_diagnostics.py",
                 "scripts/private_release_v2_history_detail_budget.py")
        baseline = {(BASE / relative).resolve(): self.committed_blob(relative) for relative in paths}
        fake_locks = SimpleNamespace(__file__=str(BASE / "scripts/private_release_v2_cleanup_locks.py"))
        def synthetic_read(path):
            return baseline[path.resolve()] if path.resolve() in baseline else original_read(path)
        def clean_git(arguments, **kwargs):
            if "rev-parse" in arguments:
                return SimpleNamespace(stdout="1" * 40)
            if "diff" in arguments:
                return SimpleNamespace(stdout="")
            raise AssertionError("unexpected local Git metadata request")
        def cached_import(name, *args, **kwargs):
            if name == "private_release_v2_bootstrap":
                return fake_bootstrap
            if name == "private_release_v2_cleanup_locks":
                return fake_locks
            return original_import(name, *args, **kwargs)
        for foreign_owner in ("history_conflict", "history_detail_budget"):
            fake_bootstrap = SimpleNamespace(__file__=str(BASE / "scripts/private_release_v2_bootstrap.py"),
                history_conflict=SimpleNamespace(__file__=str(BASE / "scripts/private_release_v2_history_conflict_diagnostics.py")),
                history_detail_budget=SimpleNamespace(__file__=str(BASE / "scripts/private_release_v2_history_detail_budget.py")))
            setattr(fake_bootstrap, foreign_owner, SimpleNamespace(__file__=str(self.directory / "foreign_dependency.py")))
            with self.subTest(owner=foreign_owner), mock.patch.object(Path, "read_bytes", synthetic_read), \
                    mock.patch.object(helper.subprocess, "run", side_effect=clean_git), \
                    mock.patch("builtins.__import__", side_effect=cached_import), \
                    self.assertRaisesRegex(helper.MaintenanceError, "cached primitive module resolves outside"):
                helper.load_primitives(BASE)

    def test_missing_or_redirected_history_dependency_stops_before_bootstrap_import(self):
        original_read, original_resolve, original_is_file, original_import = (
            Path.read_bytes, Path.resolve, Path.is_file, __import__)
        source_plan = BASE / "contracts/private_release_bootstrap_plan.json"
        plan_bytes = self.committed_blob("contracts/private_release_bootstrap_plan.json")
        def clean_git(arguments, **kwargs):
            if "rev-parse" in arguments:
                return SimpleNamespace(stdout="1" * 40)
            if "diff" in arguments:
                return SimpleNamespace(stdout="")
            raise AssertionError("unexpected local Git metadata request")
        def synthetic_read(path):
            return plan_bytes if path == source_plan else original_read(path)
        def no_bootstrap_import(name, *args, **kwargs):
            if name == "private_release_v2_bootstrap":
                raise AssertionError("missing/redirected diagnostic reached bootstrap import")
            return original_import(name, *args, **kwargs)
        for dependency_name, state in (
            (name, state) for name in ("private_release_v2_history_conflict_diagnostics.py", "private_release_v2_history_detail_budget.py")
            for state in ("missing", "redirected")
        ):
            diagnostic_path = BASE / "scripts" / dependency_name
            def resolved(path, *args, **kwargs):
                if path == diagnostic_path and state == "redirected":
                    return self.directory / "foreign_diagnostic.py"
                return original_resolve(path, *args, **kwargs)
            def is_file(path):
                return False if path == diagnostic_path and state == "missing" else original_is_file(path)
            with self.subTest(dependency=dependency_name, state=state), \
                    mock.patch.object(Path, "read_bytes", synthetic_read), \
                    mock.patch.object(Path, "resolve", resolved), \
                    mock.patch.object(Path, "is_file", is_file), \
                    mock.patch.object(helper.subprocess, "run", side_effect=clean_git), \
                    mock.patch("builtins.__import__", side_effect=no_bootstrap_import), \
                    self.assertRaisesRegex(helper.MaintenanceError, "dependency path.*before import"):
                helper.load_primitives(BASE)

    def test_history_dependency_reparse_flags_stop_before_bootstrap_import(self):
        original_read, original_lstat, original_import = Path.read_bytes, Path.lstat, __import__
        paths = ("contracts/private_release_bootstrap_plan.json", "scripts/private_release_v2_bootstrap.py",
                 "scripts/private_release_v2_cleanup_locks.py", "scripts/private_release_v2_history_conflict_diagnostics.py",
                 "scripts/private_release_v2_history_detail_budget.py")
        baseline = {(BASE / relative).resolve(): self.committed_blob(relative) for relative in paths}
        def synthetic_read(path):
            return baseline[path.resolve()] if path.resolve() in baseline else original_read(path)
        def clean_git(arguments, **kwargs):
            if "rev-parse" in arguments:
                return SimpleNamespace(stdout="1" * 40)
            if "diff" in arguments:
                return SimpleNamespace(stdout="")
            raise AssertionError("unexpected local Git metadata request")
        def no_bootstrap_import(name, *args, **kwargs):
            if name == "private_release_v2_bootstrap":
                raise AssertionError("reparse dependency reached bootstrap import")
            return original_import(name, *args, **kwargs)
        for reparse_path in (BASE / "scripts/private_release_v2_history_detail_budget.py", BASE / "scripts"):
            def synthetic_lstat(path, *args, **kwargs):
                actual = original_lstat(path, *args, **kwargs)
                if path == reparse_path:
                    return SimpleNamespace(st_mode=actual.st_mode, st_file_attributes=0x400)
                return actual
            with self.subTest(path=reparse_path.name), \
                    mock.patch.object(Path, "read_bytes", synthetic_read), \
                    mock.patch.object(Path, "lstat", synthetic_lstat), \
                    mock.patch.object(helper.subprocess, "run", side_effect=clean_git), \
                    mock.patch("builtins.__import__", side_effect=no_bootstrap_import), \
                    self.assertRaisesRegex(helper.MaintenanceError, "link or reparse point before import"):
                helper.load_primitives(BASE)

    def test_foreign_cached_history_dependency_aliases_stop_before_bootstrap_import(self):
        original_read, original_import = Path.read_bytes, __import__
        paths = ("contracts/private_release_bootstrap_plan.json", "scripts/private_release_v2_bootstrap.py",
                 "scripts/private_release_v2_cleanup_locks.py", "scripts/private_release_v2_history_conflict_diagnostics.py",
                 "scripts/private_release_v2_history_detail_budget.py")
        baseline = {(BASE / relative).resolve(): self.committed_blob(relative) for relative in paths}
        def synthetic_read(path):
            return baseline[path.resolve()] if path.resolve() in baseline else original_read(path)
        def clean_git(arguments, **kwargs):
            if "rev-parse" in arguments:
                return SimpleNamespace(stdout="1" * 40)
            if "diff" in arguments:
                return SimpleNamespace(stdout="")
            raise AssertionError("unexpected local Git metadata request")
        def no_bootstrap_import(name, *args, **kwargs):
            if name == "private_release_v2_bootstrap":
                raise AssertionError("foreign cached diagnostic reached bootstrap import")
            return original_import(name, *args, **kwargs)
        for alias in ("scripts.private_release_v2_history_conflict_diagnostics",
                      "private_release_v2_history_conflict_diagnostics",
                      "scripts.private_release_v2_history_detail_budget", "private_release_v2_history_detail_budget"):
            for foreign in (SimpleNamespace(__file__=str(self.directory / "foreign.py")), SimpleNamespace()):
                with self.subTest(alias=alias, foreign=foreign), \
                        mock.patch.object(Path, "read_bytes", synthetic_read), \
                        mock.patch.object(helper.subprocess, "run", side_effect=clean_git), \
                        mock.patch.dict(sys.modules, {alias: foreign}), \
                        mock.patch("builtins.__import__", side_effect=no_bootstrap_import), \
                        self.assertRaisesRegex(helper.MaintenanceError, "cached (diagnostic|history detail budget).*before import"):
                    helper.load_primitives(BASE)

    def test_authorization_rejects_missing_or_wrong_history_dependency_pin(self):
        auth, evidence, preflight = self.authorization_fixture()
        for dependency, variant in (
            (name, variant) for name in ("private_release_v2_history_conflict_diagnostics.py", "private_release_v2_history_detail_budget.py")
            for variant in ("missing", "wrong")
        ):
            changed = copy.deepcopy(auth)
            if variant == "missing":
                changed["primitiveHashes"].pop(dependency)
            else:
                changed["primitiveHashes"][dependency] = "0" * 64
            with self.subTest(dependency=dependency, variant=variant), self.assertRaisesRegex(helper.MaintenanceError, "reviewed primitive bytes changed"):
                helper.validate_authorization(changed, PLAN_PATH.read_bytes(), HELPER_PATH.read_bytes(),
                                              BASE, evidence, preflight)

    def acceptance_fixture(self):
        # These strings are synthetic assertions, never provider review evidence.
        merged, final = "1" * 40, "2" * 40
        return {"repository": "Sethvirak/paperdesk-release-verifier", "mergedMainSha": merged,
                "sourcePrNumber": 1000001, "finalPrHeadSha": final,
                "exactHeadCi": {"headSha": final, "conclusion": "success"},
                "exactMergedMainCi": {"headSha": merged, "conclusion": "success"},
                "independentSourceReviews": [
                    {"login": login, "commitSha": final, "state": "APPROVED", "submittedByHuman": True}
                    for login in ("jecebella168-cmyk", "jecebella169-cmyk")]}

    def authorization_fixture(self):
        evidence = self.directory / "synthetic-human-evidence.json"
        preflight = self.directory / "synthetic-preflight.json"
        evidence.write_bytes(helper.canonical({"approved": True, "ceremonyId": helper.CEREMONY,
                                              "source": "direct-human-user-reply"}))
        preflight.write_bytes(helper.canonical({"kind": "paperdesk-key-expiry-maintenance-preflight",
                                               "ceremonyId": helper.CEREMONY}))
        auth = {"schemaVersion": 1, "kind": "paperdesk-key-expiry-maintenance-authorization",
                "ceremonyId": helper.CEREMONY,
                "maintenancePlanSha256": helper.digest(PLAN_PATH.read_bytes()),
                "executorSha256": helper.digest(HELPER_PATH.read_bytes()),
                "verifierSourceSha": "1" * 40,
                "primitiveHashes": {name: helper.digest((BASE / "scripts" / name).read_bytes()) for name in
                                    ("private_release_v2_bootstrap.py", "private_release_v2_cleanup_locks.py",
                                     "private_release_v2_history_conflict_diagnostics.py", "private_release_v2_history_detail_budget.py")},
                "azure": {"subscriptionId": helper.SUB, "tenantId": helper.TENANT,
                          "accountObjectId": helper.OWNER, "accountType": "User"},
                "validity": {"notBefore": "2026-10-01T03:00:00Z", "expiresAt": "2026-10-01T04:35:00Z"},
                "operatorHost": helper.platform.node(),
                "userApprovalEvidenceSha256": helper.digest(evidence.read_bytes()),
                "freshPreflightSha256": helper.digest(preflight.read_bytes()),
                "allowExecution": True, "sourceAcceptance": self.acceptance_fixture()}
        evidence_document = json.loads(evidence.read_bytes())
        evidence_document["approvedBindings"] = {
            "maintenancePlanSha256": auth["maintenancePlanSha256"], "executorSha256": auth["executorSha256"],
            "verifierSourceSha": auth["verifierSourceSha"],
            "sourceAcceptanceSha256": helper.digest(helper.canonical(auth["sourceAcceptance"]))}
        evidence.write_bytes(helper.canonical(evidence_document))
        preflight_document = json.loads(preflight.read_bytes())
        preflight_document.update(sourceSha=auth["verifierSourceSha"], maintenancePlanSha256=auth["maintenancePlanSha256"])
        preflight.write_bytes(helper.canonical(preflight_document))
        auth["userApprovalEvidenceSha256"] = helper.digest(evidence.read_bytes())
        auth["freshPreflightSha256"] = helper.digest(preflight.read_bytes())
        return auth, evidence, preflight

    def test_source_acceptance_requires_both_genuine_exact_final_head_reviews_and_ci(self):
        acceptance = self.acceptance_fixture()
        auth = {"verifierSourceSha": acceptance["mergedMainSha"]}
        helper.validate_source_acceptance(acceptance, auth)
        mutations = [
            lambda value: value["independentSourceReviews"].pop(),
            lambda value: value["independentSourceReviews"][0].update(submittedByHuman=False),
            lambda value: value["independentSourceReviews"][1].update(commitSha="3" * 40),
            lambda value: value["independentSourceReviews"][1].update(login="Sethvirak"),
            lambda value: value["independentSourceReviews"][1].update(state="COMMENTED"),
            lambda value: value["exactHeadCi"].update(conclusion="pending"),
            lambda value: value["exactMergedMainCi"].update(headSha="4" * 40),
            lambda value: value.update(mergedMainSha="4" * 40),
            lambda value: value.update(sourcePrNumber=True),
        ]
        for mutate in mutations:
            changed = copy.deepcopy(acceptance)
            mutate(changed)
            with self.subTest(changed=changed), self.assertRaises(Exception):
                helper.validate_source_acceptance(changed, auth)

    def test_authorization_binds_local_bytes_host_approval_and_exact_ninety_five_minutes(self):
        auth, evidence, preflight = self.authorization_fixture()
        validate = lambda document: helper.validate_authorization(
            document, PLAN_PATH.read_bytes(), HELPER_PATH.read_bytes(), BASE, evidence, preflight)
        self.assertEqual(validate(auth)["ceremonyId"], helper.CEREMONY)
        mutations = [lambda value: value.update(allowExecution=False),
                     lambda value: value.update(executorSha256="0" * 64),
                     lambda value: value.update(maintenancePlanSha256="0" * 64),
                     lambda value: value.update(userApprovalEvidenceSha256="0" * 64),
                     lambda value: value.update(freshPreflightSha256="0" * 64),
                     lambda value: value.update(operatorHost="FOREIGN-SYNTHETIC-HOST"),
                     lambda value: value["validity"].update(expiresAt="2026-10-01T04:30:00Z"),
                     lambda value: value.update(verifierSourceSha="branch-name")]
        for mutate in mutations:
            changed = copy.deepcopy(auth)
            mutate(changed)
            with self.subTest(changed=changed), self.assertRaises(Exception):
                validate(changed)

    def test_externally_approved_source_sha_must_equal_local_checkout_head(self):
        with mock.patch.object(helper.subprocess, "run", return_value=SimpleNamespace(stdout="3" * 40)), self.assertRaises(Exception):
            helper.load_primitives(BASE, expected_head="1" * 40, require_merged=True)

    def test_approval_and_preflight_content_must_bind_source_plan_and_acceptance(self):
        for document_kind, field in (("evidence", "maintenancePlanSha256"), ("evidence", "executorSha256"),
                                     ("evidence", "verifierSourceSha"), ("evidence", "sourceAcceptanceSha256"),
                                     ("preflight", "sourceSha"), ("preflight", "maintenancePlanSha256")):
            auth, evidence, preflight = self.authorization_fixture()
            path = evidence if document_kind == "evidence" else preflight
            document = json.loads(path.read_bytes())
            if document_kind == "evidence":
                document["approvedBindings"][field] = "0" * (40 if field == "verifierSourceSha" else 64)
            else:
                document[field] = "0" * (40 if field == "sourceSha" else 64)
            path.write_bytes(helper.canonical(document))
            auth["userApprovalEvidenceSha256" if document_kind == "evidence" else "freshPreflightSha256"] = helper.digest(path.read_bytes())
            with self.subTest(document_kind=document_kind, field=field), self.assertRaises(helper.MaintenanceError):
                helper.validate_authorization(auth, PLAN_PATH.read_bytes(), HELPER_PATH.read_bytes(), BASE, evidence, preflight)

    def test_exact_local_head_must_also_equal_origin_main(self):
        results = [SimpleNamespace(stdout="1" * 40), SimpleNamespace(stdout="3" * 40)]
        with mock.patch.object(helper.subprocess, "run", side_effect=results), self.assertRaises(Exception):
            helper.load_primitives(BASE, expected_head="1" * 40, require_merged=True)

    def test_helper_and_plan_must_equal_committed_bytes_before_transport_loading(self):
        for mismatched in ("scripts/private_release_key_expiry_maintenance.py",
                           "contracts/private_release_key_expiry_maintenance_plan.json"):
            def git_response(arguments, **kwargs):
                if arguments[-1] in ("HEAD", "refs/remotes/origin/main"):
                    return SimpleNamespace(stdout="1" * 40)
                relative = arguments[-1].removeprefix("HEAD:")
                if relative == mismatched:
                    return SimpleNamespace(stdout=b"synthetic mismatched committed bytes")
                return SimpleNamespace(stdout=(BASE / relative).read_bytes())
            with self.subTest(mismatched=mismatched), mock.patch.object(helper.subprocess, "run", side_effect=git_response), self.assertRaises(Exception):
                helper.load_primitives(BASE, expected_head="1" * 40, require_merged=True)

    def test_local_validation_and_incomplete_execute_never_load_provider_primitives(self):
        with mock.patch.object(helper, "load_primitives", side_effect=AssertionError("provider primitive loading forbidden")) as loader:
            with mock.patch.object(sys, "argv", [str(HELPER_PATH), "--plan", str(PLAN_PATH)]), mock.patch("builtins.print"):
                helper.main()
            with mock.patch.object(sys, "argv", [str(HELPER_PATH), "--plan", str(PLAN_PATH), "--execute"]), self.assertRaises(helper.MaintenanceError):
                helper.main()
            loader.assert_not_called()

    def test_hostile_primitive_bytes_stop_before_import_in_observation_and_execution_loaders(self):
        original_read, original_import = Path.read_bytes, __import__
        committed = {relative: (BASE / relative).read_bytes() for relative in
                     ("scripts/private_release_key_expiry_maintenance.py",
                      "contracts/private_release_key_expiry_maintenance_plan.json")}
        baseline = {(BASE / relative).resolve(): self.committed_blob(relative) for relative in
                    ("contracts/private_release_bootstrap_plan.json", "scripts/private_release_v2_bootstrap.py",
                     "scripts/private_release_v2_cleanup_locks.py",
                     "scripts/private_release_v2_history_conflict_diagnostics.py", "scripts/private_release_v2_history_detail_budget.py")}
        for primitive in ("private_release_v2_bootstrap.py", "private_release_v2_cleanup_locks.py",
                          "private_release_v2_history_conflict_diagnostics.py", "private_release_v2_history_detail_budget.py"):
            variants = {"CRLF": baseline[(BASE / "scripts" / primitive).resolve()].replace(b"\n", b"\r\n"),
                        "BOM": b"\xef\xbb\xbf" + baseline[(BASE / "scripts" / primitive).resolve()],
                        "content": b"# hostile synthetic primitive bytes; never imported\n"}
            for require_merged in (False, True):
                for drift, altered in variants.items():
                    hostile_path = (BASE / "scripts" / primitive).resolve()
                    attempted_imports = []

                    def synthetic_read(path):
                        resolved = path.resolve()
                        if resolved == hostile_path:
                            return altered
                        return baseline[resolved] if resolved in baseline else original_read(path)

                    def clean_git(arguments, **kwargs):
                        if "rev-parse" in arguments:
                            return SimpleNamespace(stdout="1" * 40)
                        if "diff" in arguments:
                            return SimpleNamespace(stdout="")
                        if "show" in arguments:
                            return SimpleNamespace(stdout=committed[arguments[-1].removeprefix("HEAD:")])
                        raise AssertionError("unexpected local Git metadata request")

                    def no_primitive_import(name, *args, **kwargs):
                        if name in ("private_release_v2_bootstrap", "private_release_v2_cleanup_locks",
                                    "private_release_v2_history_conflict_diagnostics", "private_release_v2_history_detail_budget"):
                            attempted_imports.append(name)
                            raise AssertionError("hostile primitive import was reached")
                        return original_import(name, *args, **kwargs)

                    with self.subTest(primitive=primitive, require_merged=require_merged, drift=drift), \
                            mock.patch.object(Path, "read_bytes", synthetic_read), \
                            mock.patch.object(helper.subprocess, "run", side_effect=clean_git), \
                            mock.patch("builtins.__import__", side_effect=no_primitive_import), \
                            self.assertRaisesRegex(helper.MaintenanceError, "provider primitives differ.*before import"):
                        helper.load_primitives(BASE, expected_head="1" * 40, require_merged=require_merged)
                    self.assertEqual(attempted_imports, [])

    def test_cli_observation_refuses_unmerged_source_before_journal_or_output_creation(self):
        output = self.directory / "forbidden-observation-output.json"
        arguments = [str(HELPER_PATH), "--plan", str(PLAN_PATH), "--verifier", str(BASE),
                     "--observe-preflight", "--output", str(output)]
        with mock.patch.object(sys, "argv", arguments), \
                mock.patch.object(helper, "load_primitives", side_effect=helper.MaintenanceError("synthetic unmerged observation head")) as loader, \
                mock.patch.object(helper, "Journal", side_effect=AssertionError("journal creation forbidden")) as journal, \
                self.assertRaises(helper.MaintenanceError):
            helper.main()
        loader.assert_called_once_with(str(BASE), require_merged=True)
        journal.assert_not_called()
        self.assertFalse(output.exists())
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_synthetic_approval_cannot_bypass_merged_source_gate_or_create_journal(self):
        auth, evidence, preflight = self.authorization_fixture()
        auth_path = self.directory / "synthetic-authorization.json"
        auth_path.write_bytes(helper.canonical(auth))
        arguments = [str(HELPER_PATH), "--plan", str(PLAN_PATH), "--verifier", str(BASE),
                     "--authorization", str(auth_path), "--approval-evidence", str(evidence),
                     "--preflight", str(preflight), "--execute"]
        with mock.patch.object(sys, "argv", arguments), \
                mock.patch.object(helper, "load_primitives", side_effect=helper.MaintenanceError("synthetic unmerged head")) as loader, \
                mock.patch.object(helper, "Journal", side_effect=AssertionError("journal creation forbidden")) as journal, \
                self.assertRaises(helper.MaintenanceError):
            helper.main()
        loader.assert_called_once_with(str(BASE), expected_head="1" * 40, require_merged=True)
        journal.assert_not_called()


class RestorationReserveTests(OfflineCase):
    setup_maintenance = RequestGateTests.setup_maintenance
    setup_run = EndToEndFaultTests.setup_run

    def exhaust_ordinary(self, maintenance):
        maintenance.ordinary_control_gets = self.plan["bounds"]["ordinaryControlPlaneGetAttemptsMaximum"]
        maintenance.control_gets = maintenance.ordinary_control_gets

    def test_ordinary_lock_reads_cannot_borrow_reserved_reads_or_post_expiry_time(self):
        maintenance = self.setup_maintenance()
        self.exhaust_ordinary(maintenance)
        maintenance.owned_assignment = maintenance.suspension_intent_durable = True
        maintenance.phase_deadline = maintenance.end + dt.timedelta(seconds=900)
        with self.assertRaises(helper.MaintenanceError):
            maintenance.read("GET", helper.arm_url(helper.LOCK, "2016-09-01"))
        self.assertEqual(self.session.calls, [])
        self.assertEqual(maintenance.restoration_control_gets, 0)

    def test_reserve_requires_each_owned_durable_guard_prerequisite(self):
        maintenance = self.setup_maintenance()
        self.exhaust_ordinary(maintenance)
        for missing in ("owned_assignment", "suspension_intent_durable", "source_guard_restoration_context"):
            maintenance.owned_assignment = maintenance.suspension_intent_durable = maintenance.source_guard_restoration_context = True
            setattr(maintenance, missing, False)
            with self.subTest(missing=missing), self.assertRaises(helper.MaintenanceError):
                maintenance.read("GET", helper.arm_url(helper.LOCK, "2016-09-01"))
            restoration = self.plan["mutationAttemptOrder"][5]
            with self.subTest(missing=missing, operation="PUT"), self.assertRaises(helper.MaintenanceError):
                maintenance.mutate("PUT", restoration["url"],
                                   helper.canonical(self.plan["createBodies"]["exactLockRestoration"]),
                                   expected=set(restoration["successStatuses"]), restore=True)
            self.assertEqual(self.session.calls, [])
            self.assertEqual(maintenance.restoration_control_gets, 0)
            self.assertNotIn(restoration["id"], maintenance.attempts)

    def test_owned_guard_reserve_is_exact_lock_only_and_bounded(self):
        maintenance = self.setup_maintenance()
        self.exhaust_ordinary(maintenance)
        maintenance.owned_assignment = maintenance.suspension_intent_durable = maintenance.source_guard_restoration_context = True
        forbidden = [("GET", helper.arm_url(helper.ROLE_ID)),
                     ("GET", helper.arm_url(helper.ASSIGNMENT_ID)),
                     ("GET", self.plan["preflight"]["requiredVaultGetUrl"]),
                     ("GET", helper.arm_url(helper.LOCK, "2016-09-01") + "&unreviewed=true"),
                     ("POST", helper.arm_url(helper.LOCK, "2016-09-01"))]
        for method, url in forbidden:
            with self.subTest(method=method, url=url), self.assertRaises(helper.MaintenanceError):
                maintenance.read(method, url)
        self.assertEqual(self.session.calls, [])
        lock_url = helper.arm_url(helper.LOCK, "2016-09-01")
        for _ in range(self.plan["bounds"]["exactOwnedLockRestorationGetAttemptsReservedMaximum"]):
            maintenance.read("GET", lock_url)
        self.assertEqual(maintenance.restoration_control_gets, 63)
        self.assertEqual(maintenance.control_gets, 1250)
        with self.assertRaises(helper.MaintenanceError):
            maintenance.read("GET", lock_url)
        self.assertEqual(len(self.session.calls), 63)

    def test_failed_suspension_intent_never_arms_read_or_put_restoration_reserve(self):
        maintenance = self.setup_maintenance()
        maintenance.owned_assignment = True
        step = self.plan["mutationAttemptOrder"][3]
        with mock.patch.object(self.journal, "record", side_effect=OSError("synthetic suspension intent fsync failure")), self.assertRaises(OSError):
            maintenance.mutate("DELETE", step["url"], expected=set(step["successStatuses"]))
        self.assertFalse(maintenance.suspension_intent_durable)
        self.assertEqual(self.session.calls, [])
        self.exhaust_ordinary(maintenance)
        maintenance.source_guard_restoration_context = True
        with self.assertRaises(helper.MaintenanceError):
            maintenance.read("GET", helper.arm_url(helper.LOCK, "2016-09-01"))
        restoration = self.plan["mutationAttemptOrder"][5]
        with self.assertRaises(helper.MaintenanceError):
            maintenance.mutate("PUT", restoration["url"],
                               helper.canonical(self.plan["createBodies"]["exactLockRestoration"]),
                               expected=set(restoration["successStatuses"]), restore=True)
        self.assertNotIn(restoration["id"], maintenance.attempts)
        self.assertEqual(self.session.calls, [])

    def test_exhaustion_during_suspension_still_restores_through_source_guard(self):
        maintenance, preflight = self.setup_run()
        original = self.session.request
        lock_url = helper.arm_url(helper.LOCK, "2016-09-01")

        def exhaust_after_suspension(method, url, **kwargs):
            response = original(method, url, **kwargs)
            if method == "DELETE" and url == lock_url:
                self.exhaust_ordinary(maintenance)
            return response

        with mock.patch.object(self.session, "request", side_effect=exhaust_after_suspension), self.assertRaises(helper.MaintenanceError):
            maintenance.run(preflight)
        self.assertIsNotNone(self.session.assignment)
        self.assertIsNotNone(self.session.role)
        self.assertEqual(self.session.lock["properties"], self.plan["createBodies"]["exactLockRestoration"]["properties"])
        self.assertEqual(maintenance.restoration_control_gets, 2)
        self.assertEqual(maintenance.control_gets, 1189)
        self.assertFalse(maintenance.source_guard_restoration_context)
        self.assertEqual(sum(call["method"] == "PUT" and call["url"] == lock_url for call in self.session.calls), 1)
        self.assertFalse(any(call["method"] == "DELETE" and call["url"] in
                             (helper.arm_url(helper.ASSIGNMENT_ID), helper.arm_url(helper.ROLE_ID))
                             for call in self.session.calls))


class ExtendedCleanupFaultTests(OfflineCase):
    setup_run = EndToEndFaultTests.setup_run
    assert_cleanup = EndToEndFaultTests.assert_cleanup

    def test_combined_delayed_creation_and_cleanup_fits_partitioned_get_budget(self):
        maintenance, preflight = self.setup_run()
        original = self.session.request
        role_url, assignment_url = helper.arm_url(helper.ROLE_ID), helper.arm_url(helper.ASSIGNMENT_ID)
        lock_url = helper.arm_url(helper.LOCK, "2016-09-01")
        created, deleted, restored, saved = {}, {}, [], {}

        def delayed_provider(method, url, **kwargs):
            if method == "DELETE":
                saved[url] = copy.deepcopy(self.session.lock if url == lock_url else
                                           self.session.assignment if url == assignment_url else self.session.role)
            response = original(method, url, **kwargs)
            now = self.clock.value
            if method == "PUT" and url in (role_url, assignment_url):
                created[url] = now
                if url == assignment_url:
                    raise SyntheticAmbiguity("synthetic assignment created response lost")
            elif method == "DELETE" and url in (role_url, assignment_url, lock_url):
                deleted[url] = now
                if url != role_url:
                    response.status = 202
            elif method == "PUT" and url == lock_url:
                restored.append(now)
            elif method == "GET":
                if url == role_url and url in created and url not in deleted and now < created[url] + dt.timedelta(seconds=190):
                    return SimpleNamespace(status=404, body=b"{}", headers={})
                if url == assignment_url and url in created and url not in deleted and now < created[url] + dt.timedelta(seconds=598):
                    return SimpleNamespace(status=404, body=b"{}", headers={})
                if url in deleted and (url != lock_url or not restored):
                    delay = 118 if url == lock_url else 598
                    if now < deleted[url] + dt.timedelta(seconds=delay):
                        return SimpleNamespace(status=200, body=helper.canonical(saved[url]), headers={})
                # The unchanged guard gives restoration a strict120s window;
                # full90s admission requires this observation before32s.
                if url == lock_url and restored and now < restored[0] + dt.timedelta(seconds=28):
                    return SimpleNamespace(status=404, body=b"{}", headers={})
            return response

        with mock.patch.object(self.session, "request", side_effect=delayed_provider):
            receipt = maintenance.run(preflight)
        self.assertEqual(receipt["overall"], "NO_GO")
        self.assertEqual(receipt["keyVaultGetAttempts"], 0)
        self.assertGreater(maintenance.ordinary_control_gets, 900)
        self.assertLessEqual(maintenance.ordinary_control_gets, 1187)
        self.assertLessEqual(maintenance.restoration_control_gets, 63)
        self.assertEqual(maintenance.control_gets, maintenance.ordinary_control_gets + maintenance.restoration_control_gets)
        self.assertLessEqual(maintenance.control_gets, 1250)
        measured = sum(call["method"] == "GET" and call["url"].startswith(helper.ARM + "/")
                       for call in self.session.calls)
        self.assertEqual(measured, maintenance.control_gets)
        self.measured_get_counts = {"total": maintenance.control_gets, "ordinary": maintenance.ordinary_control_gets,
                                    "restoration": maintenance.restoration_control_gets}
        self.assert_cleanup()

    def test_delayed_ambiguous_creation_uses_original_absolute_settlement_window(self):
        maintenance, preflight = self.setup_run()
        original = self.session.request
        role_url = helper.arm_url(helper.ROLE_ID)
        observed = []
        created_at = []

        def delayed(method, url, **kwargs):
            response = original(method, url, **kwargs)
            if method == "PUT" and url == role_url:
                created_at.append(self.clock.value)
                raise SyntheticAmbiguity("synthetic-role-created-response-lost")
            if method == "GET" and url == role_url and created_at:
                observed.append(self.clock.value)
                if self.session.role and self.clock.value < created_at[0] + dt.timedelta(seconds=690):
                    return SimpleNamespace(status=404, body=b"{}", headers={})
            return response

        with mock.patch.object(self.session, "request", side_effect=delayed):
            receipt = maintenance.run(preflight)
        boundary = maintenance.creation_settlement_boundaries["role"]
        self.assertEqual(receipt["overall"], "NO_GO")
        self.assertEqual(receipt["keyVaultGetAttempts"], 0)
        self.assertLessEqual((boundary - created_at[0]).total_seconds(), 692)
        self.assertTrue(any(created_at[0] + dt.timedelta(seconds=690) <= value <= boundary + dt.timedelta(seconds=94)
                            for value in observed))
        self.assertEqual(sum(call["method"] == "PUT" and call["url"] == role_url for call in self.session.calls), 1)
        self.assert_cleanup()

    def test_assignment_delete_202_requires_following_404_before_role_delete(self):
        maintenance, preflight = self.setup_run()
        original = self.session.request
        assignment_url = helper.arm_url(helper.ASSIGNMENT_ID)
        lock_url = helper.arm_url(helper.LOCK, "2016-09-01")
        absent_observations = []

        def accepted_async(method, url, **kwargs):
            response = original(method, url, **kwargs)
            if method == "DELETE" and url in (assignment_url, lock_url):
                response.status = 202
            if method == "GET" and url == assignment_url and response.status == 404:
                absent_observations.append(len(self.session.calls) - 1)
            return response

        with mock.patch.object(self.session, "request", side_effect=accepted_async):
            receipt = maintenance.run(preflight)
        self.assertEqual(receipt["overall"], "PASS")
        deleted_assignment = next(index for index, call in enumerate(self.session.calls)
                                  if call["method"] == "DELETE" and call["url"] == assignment_url)
        deleted_role = next(index for index, call in enumerate(self.session.calls)
                            if call["method"] == "DELETE" and call["url"] == helper.arm_url(helper.ROLE_ID))
        self.assertTrue(any(deleted_assignment < index < deleted_role for index in absent_observations))
        self.assert_cleanup()

    def test_assignment_delete_202_without_absence_proof_restores_lock_and_fails(self):
        maintenance, preflight = self.setup_run()
        original = self.session.request
        assignment_url = helper.arm_url(helper.ASSIGNMENT_ID)

        def accepted_but_pending(method, url, **kwargs):
            saved_assignment = copy.deepcopy(self.session.assignment)
            response = original(method, url, **kwargs)
            if method == "DELETE" and url == assignment_url:
                self.session.assignment = saved_assignment
                response.status = 202
            return response

        with mock.patch.object(self.session, "request", side_effect=accepted_but_pending), self.assertRaises(Exception):
            maintenance.run(preflight)
        self.assertIsNotNone(self.session.assignment)
        self.assertEqual(self.session.lock["properties"], self.plan["createBodies"]["exactLockRestoration"]["properties"])
        self.assertEqual(sum(call["method"] == "DELETE" and call["url"] == assignment_url for call in self.session.calls), 1)
        self.assertFalse(any(call["method"] == "DELETE" and call["url"] == helper.arm_url(helper.ROLE_ID)
                             for call in self.session.calls))

    def test_expiry_after_lock_suspension_restores_lock_and_stops_grant_deletions(self):
        maintenance, preflight = self.setup_run()
        original = self.session.request
        lock_url = helper.arm_url(helper.LOCK, "2016-09-01")

        def expire_after_suspension(method, url, **kwargs):
            response = original(method, url, **kwargs)
            if method == "DELETE" and url == lock_url:
                self.clock.value = maintenance.end + dt.timedelta(seconds=1)
            return response

        with mock.patch.object(self.session, "request", side_effect=expire_after_suspension), self.assertRaises(Exception):
            maintenance.run(preflight)
        self.assertIsNotNone(self.session.assignment)
        self.assertIsNotNone(self.session.role)
        self.assertEqual(self.session.lock["properties"], self.plan["createBodies"]["exactLockRestoration"]["properties"])
        self.assertEqual(sum(call["method"] == "PUT" and call["url"] == lock_url for call in self.session.calls), 1)
        self.assertFalse(any(call["method"] == "DELETE" and call["url"] in
                             (helper.arm_url(helper.ASSIGNMENT_ID), helper.arm_url(helper.ROLE_ID))
                             for call in self.session.calls))

    def test_failed_restoration_preserves_failure_and_consumes_one_exact_put(self):
        maintenance, preflight = self.setup_run()
        original = self.session.request
        lock_url = helper.arm_url(helper.LOCK, "2016-09-01")

        def restored_but_response_lost(method, url, **kwargs):
            response = original(method, url, **kwargs)
            if method == "PUT" and url == lock_url:
                raise SyntheticAmbiguity("synthetic-lock-restored-response-lost")
            return response

        with mock.patch.object(self.session, "request", side_effect=restored_but_response_lost), self.assertRaises(Exception):
            maintenance.run(preflight)
        self.assertEqual(maintenance.primary_failure, "SyntheticAmbiguity")
        self.assertEqual(self.session.lock["properties"], self.plan["createBodies"]["exactLockRestoration"]["properties"])
        self.assertEqual(sum(call["method"] == "PUT" and call["url"] == lock_url for call in self.session.calls), 1)
        self.assertFalse(any(call["method"] == "DELETE" and call["url"] == helper.arm_url(helper.ROLE_ID)
                             for call in self.session.calls))

    def test_late_restoration_result_cannot_pass_or_retry(self):
        maintenance, preflight = self.setup_run()
        original = self.session.request
        lock_url = helper.arm_url(helper.LOCK, "2016-09-01")

        def late_restore(method, url, **kwargs):
            response = original(method, url, **kwargs)
            if method == "PUT" and url == lock_url:
                self.clock.value = kwargs["deadline"] + dt.timedelta(milliseconds=1)
            return response

        with mock.patch.object(self.session, "request", side_effect=late_restore), self.assertRaises(Exception):
            maintenance.run(preflight)
        self.assertEqual(maintenance.primary_failure, "MaintenanceError")
        self.assertEqual(self.session.lock["properties"], self.plan["createBodies"]["exactLockRestoration"]["properties"])
        self.assertEqual(sum(call["method"] == "PUT" and call["url"] == lock_url for call in self.session.calls), 1)

    def test_delayed_restoration_visibility_fails_closed_without_second_put(self):
        maintenance, preflight = self.setup_run()
        original = self.session.request
        lock_url = helper.arm_url(helper.LOCK, "2016-09-01")
        restored = []

        def delayed_restore_visibility(method, url, **kwargs):
            response = original(method, url, **kwargs)
            if method == "PUT" and url == lock_url:
                restored.append(self.clock.value)
            elif method == "GET" and url == lock_url and restored and self.clock.value < restored[0] + dt.timedelta(seconds=118):
                return SimpleNamespace(status=404, body=b"{}", headers={})
            return response

        with mock.patch.object(self.session, "request", side_effect=delayed_restore_visibility), self.assertRaises(helper.MaintenanceError):
            maintenance.run(preflight)
        self.assertEqual(maintenance.primary_failure, "MaintenanceError")
        self.assertEqual(self.session.lock["properties"], self.plan["createBodies"]["exactLockRestoration"]["properties"])
        self.assertIsNotNone(self.session.role)
        self.assertLessEqual(maintenance.restoration_control_gets, 63)
        self.assertFalse(maintenance.source_guard_restoration_context)
        self.assertEqual(sum(call["method"] == "PUT" and call["url"] == lock_url for call in self.session.calls), 1)


def large_role_inventory_bytes(target_size=1_251_119):
    """978 synthetic metadata rows; no live Azure response or customer data."""
    rows = [{"id": f"/subscriptions/{helper.SUB}/providers/Microsoft.Authorization/roleDefinitions/{index:032x}",
             "properties": {"roleName": f"offline-role-{index}", "description": "",
                            "type": "BuiltInRole", "permissions": [{"actions": ["Microsoft.Resources/subscriptions/read"],
                            "notActions": [], "dataActions": [], "notDataActions": []}]}}
            for index in range(978)]
    document = {"value": rows}
    remaining = target_size - len(helper.canonical(document))
    if remaining < 0:
        raise AssertionError("synthetic inventory target too small")
    per_row, extra = divmod(remaining, len(rows))
    for index, row in enumerate(rows):
        row["properties"]["description"] = "x" * (per_row + (index < extra))
    raw = helper.canonical(document)
    if len(raw) != target_size:
        raise AssertionError("synthetic inventory byte size differs")
    return raw


class InventoryResponseBoundTests(OfflineCase):
    setup_maintenance = RequestGateTests.setup_maintenance

    def test_complete_realistic_inventory_passes_read_and_object_same_exact_dispatch(self):
        raw = large_role_inventory_bytes()
        url = helper.ROLE_DEFINITIONS_INVENTORY_URL
        self.assertEqual(url, self.plan["preflight"]["requiredCompleteInventoryUrls"][1])
        maintenance = self.setup_maintenance(response=SimpleNamespace(status=200, body=raw, headers={}))
        with mock.patch.object(helper, "strict_response_json", wraps=helper.strict_response_json) as parser:
            self.assertEqual(maintenance.read("GET", url).body, raw)
            self.assertEqual(len(helper.complete_inventory(maintenance.object(url))), 978)
        self.assertEqual(parser.call_count, 3)
        self.assertEqual({call.args[1] for call in parser.call_args_list}, {url})
        self.assertEqual(len(self.session.calls), 2)
        with self.assertRaises(helper.MaintenanceError):
            helper.strict_json(raw)

    def test_exact_two_mib_inventory_passes_and_one_more_byte_fails_both_reparses(self):
        url = helper.ROLE_DEFINITIONS_INVENTORY_URL
        raw = large_role_inventory_bytes(2 * 1024 * 1024)
        self.assertEqual(len(helper.complete_inventory(helper.strict_response_json(raw, url))), 978)
        oversized = raw + b" "
        maintenance = self.setup_maintenance(response=SimpleNamespace(status=200, body=oversized, headers={}))
        for operation in (lambda: maintenance.read("GET", url), lambda: maintenance.object(url)):
            with self.assertRaises(helper.MaintenanceError):
                operation()
        self.assertEqual(len(self.session.calls), 2)
        self.assertFalse((self.directory / "write-journal.jsonl").exists())

    def test_one_mib_remains_default_for_other_allowed_inputs_and_key_data(self):
        raw = b"{}" + b" " * (1024 * 1024 - 1)
        self.assertEqual(len(raw), 1024 * 1024 + 1)
        for url in self.plan["preflight"]["requiredCompleteInventoryUrls"] + [
                self.plan["preflight"]["requiredArmKeyGetUrl"], self.plan["dataPlaneSequence"][0]["url"]]:
            if url != helper.ROLE_DEFINITIONS_INVENTORY_URL:
                with self.subTest(url=url), self.assertRaises(helper.MaintenanceError):
                    helper.strict_response_json(raw, url)
        with self.assertRaises(helper.MaintenanceError):
            helper.strict_json(raw)
        maintenance = self.setup_maintenance(response=SimpleNamespace(status=200, body=raw, headers={}))
        self.clock.sleep(480)
        key_url = self.plan["dataPlaneSequence"][0]["url"]
        for operation in (lambda: maintenance.read("GET", key_url), lambda: maintenance.object(key_url)):
            with self.assertRaises(helper.MaintenanceError):
                operation()
        self.assertEqual(maintenance.key_gets, 2)
        self.assertFalse((self.directory / "write-journal.jsonl").exists())

    def test_similar_foreign_path_and_query_urls_never_get_larger_limit_or_wire_access(self):
        exact = helper.ROLE_DEFINITIONS_INVENTORY_URL
        raw = large_role_inventory_bytes()
        variants = [exact.replace("management.azure.com", "management.azure.com.foreign.invalid"),
                    exact.replace("/roleDefinitions?", "/roleDefinitions/foreign?"),
                    exact + "&extra=1", exact.replace("2022-04-01", "2022-04-02"),
                    exact.replace("https://", "http://"), exact.replace("roleDefinitions", "RoleDefinitions")]
        maintenance = self.setup_maintenance(response=SimpleNamespace(status=200, body=raw, headers={}))
        for url in variants:
            with self.subTest(url=url):
                with self.assertRaises(helper.MaintenanceError):
                    helper.strict_response_json(raw, url)
                with self.assertRaises(helper.MaintenanceError):
                    maintenance.read("GET", url)
        self.assertEqual(self.session.calls, [])
        self.assertEqual(maintenance.control_gets, 0)

    def test_enlarged_inventory_still_rejects_duplicates_nonfinite_objects_and_partial_pages(self):
        invalid = [b'{"value":[],"value":[]}', b'{"value":[],"metadata":NaN}',
                   b'{"value":[],"metadata":Infinity}', b'[]', b'{"value":{}}',
                   b'{"value":[],"nextLink":"https://foreign.invalid/next"}',
                   b'{"value":[{"id":"SYNTHETIC"},{"id":"synthetic"}]}',
                   b'{"value":[{"properties":{}}]}']
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(helper.MaintenanceError):
                helper.strict_response_json(raw, helper.ROLE_DEFINITIONS_INVENTORY_URL)


class PreflightArtifactBoundTests(OfflineCase):
    acceptance_fixture = SourceAdmissionTests.acceptance_fixture
    authorization_fixture = SourceAdmissionTests.authorization_fixture

    def large_authorization_fixture(self):
        auth, evidence, preflight_path = self.authorization_fixture()
        model = FakeAzure(self.plan, SyntheticClock())
        snapshot = model.initial_snapshot()
        snapshot["roleDefinitions"] = helper.complete_inventory(
            helper.strict_response_json(large_role_inventory_bytes(), helper.ROLE_DEFINITIONS_INVENTORY_URL))
        document = {"schemaVersion": 1, "kind": "paperdesk-key-expiry-maintenance-preflight",
                    "ceremonyId": helper.CEREMONY, "sourceSha": auth["verifierSourceSha"],
                    "maintenancePlanSha256": auth["maintenancePlanSha256"],
                    "observedAt": "2026-10-01T03:00:00Z", "completedAt": "2026-10-01T03:00:01Z",
                    "snapshot": snapshot, "callerPermissions": model.permissions,
                    "controlPlaneReadEvents": [{"synthetic": True, "ordinal": index} for index in range(9)],
                    "keyVaultDataPlaneOperations": 0, "azureMutations": 0}
        raw = helper.canonical(document)
        self.assertGreater(len(raw), 1024 * 1024)
        self.assertLess(len(raw), helper.PREFLIGHT_ARTIFACT_MAX_BYTES)
        preflight_path.write_bytes(raw)
        auth["freshPreflightSha256"] = helper.digest(raw)
        return auth, evidence, preflight_path, document

    def validate_fixture(self, auth, evidence, path):
        return helper.validate_authorization(auth, PLAN_PATH.read_bytes(), HELPER_PATH.read_bytes(), BASE, evidence, path)

    def test_realistic_complete_inventory_artifact_roundtrips_actual_authorization_and_snapshot_gate(self):
        auth, evidence, path, document = self.large_authorization_fixture()
        result = self.validate_fixture(auth, evidence, path)
        self.assertEqual(result, document)
        self.assertEqual(len(result["snapshot"]["roleDefinitions"]), 978)
        _, locks = helper.load_primitives(BASE)
        runner = helper.Maintenance(self.plan, auth, None, None, cleanup_module=locks)
        runner.validate_preflight(result["snapshot"], helper.permission_page(result["callerPermissions"]))
        with self.assertRaises(helper.MaintenanceError):
            helper.strict_json(path.read_bytes())

    def test_exact_four_mib_artifact_passes_and_one_more_byte_fails_actual_authorization(self):
        auth, evidence, path, _ = self.large_authorization_fixture()
        original = path.read_bytes()
        boundary = original + b" " * (4 * 1024 * 1024 - len(original))
        path.write_bytes(boundary)
        auth["freshPreflightSha256"] = helper.digest(boundary)
        self.validate_fixture(auth, evidence, path)
        path.write_bytes(boundary + b" ")
        auth["freshPreflightSha256"] = helper.digest(path.read_bytes())
        with self.assertRaises(helper.MaintenanceError):
            self.validate_fixture(auth, evidence, path)

    def test_wrong_preflight_kind_ceremony_source_and_plan_still_reject_after_matching_raw_digest(self):
        auth, evidence, path, document = self.large_authorization_fixture()
        variants = [("kind", "foreign-preflight"), ("ceremonyId", "foreign-ceremony"),
                    ("sourceSha", "3" * 40), ("maintenancePlanSha256", "3" * 64)]
        for key, value in variants:
            changed = copy.deepcopy(document)
            changed[key] = value
            raw = helper.canonical(changed)
            path.write_bytes(raw)
            auth["freshPreflightSha256"] = helper.digest(raw)
            with self.subTest(key=key), self.assertRaises(helper.MaintenanceError):
                self.validate_fixture(auth, evidence, path)

    def test_artifact_duplicate_nonfinite_and_nonobject_json_reject_with_matching_digest(self):
        auth, evidence, path, _ = self.large_authorization_fixture()
        prefix = f'{{"kind":"paperdesk-key-expiry-maintenance-preflight","ceremonyId":"{helper.CEREMONY}"'.encode()
        invalid = [prefix + b',"kind":"foreign"}', prefix + b',"metadata":NaN}',
                   prefix + b',"metadata":Infinity}', b'[]']
        for raw in invalid:
            path.write_bytes(raw)
            auth["freshPreflightSha256"] = helper.digest(raw)
            with self.subTest(raw=raw), self.assertRaises(helper.MaintenanceError):
                self.validate_fixture(auth, evidence, path)

    def test_raw_digest_and_source_acceptance_mismatch_stop_before_large_artifact_parser(self):
        auth, evidence, path, _ = self.large_authorization_fixture()
        original_hash = auth["freshPreflightSha256"]
        auth["freshPreflightSha256"] = "0" * 64
        with mock.patch.object(helper, "strict_preflight_json", side_effect=AssertionError("unbound artifact parsed")) as parser:
            with self.assertRaises(helper.MaintenanceError):
                self.validate_fixture(auth, evidence, path)
            parser.assert_not_called()
        auth["freshPreflightSha256"] = original_hash
        auth["sourceAcceptance"]["exactMergedMainCi"]["headSha"] = "3" * 40
        with mock.patch.object(helper, "strict_preflight_json", side_effect=AssertionError("unreviewed source artifact parsed")) as parser:
            with self.assertRaises(helper.MaintenanceError):
                self.validate_fixture(auth, evidence, path)
            parser.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
