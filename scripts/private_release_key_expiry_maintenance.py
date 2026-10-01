"""Separate, one-use existing-key expiry maintenance harness.

Preparation only. No operation runs at import or without an explicit command.
Never substitutes for bootstrap authorization/S2. Original bootstrap transport
and its readiness/retry helpers are intentionally not used.
"""
from __future__ import annotations

import argparse
import base64
import copy
import datetime as dt
import fnmatch
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time
from types import SimpleNamespace
from typing import Any

SOURCE_SHA = "426438a699306c639a580e268a7f9330b70c4ebf"
BOOTSTRAP_PLAN_SHA = "49f2977345bbbb25a26a42049af0267603261c4f03909131cc30ffb1dbd8f760"
BOOTSTRAP_PLAN_GIT_BLOB_SHA = "b6a834f1bb00f10312d28a4b88cee7cc28fb9796a7f38384ca7245f0765bed76"
REVIEWED_PLAN_CANONICAL_SHA = "23233c89809480f4337599d80173bb9387638b82add12390cc5c2600dea88fab"
SUB = "9c4e0d0d-602f-4cde-84bd-337250e5b64c"
TENANT = "aba83bd8-3e5c-4a87-9eb1-7bca070685b2"
OWNER = "b97bfa13-b375-4b27-93d7-141029dbc05b"
CEREMONY = "28a41fb1-7080-44b6-85f5-bd41871b1f1e"
ROLE = "515f2f22-13a5-4405-891d-3a4426418d86"
ASSIGNMENT = "99ef3a3e-c48b-410c-a42c-3d77f5fb99c0"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-master-data-structure-sea"
VAULT = RG + "/providers/Microsoft.KeyVault/vaults/kv-mds-sea-9c4e0d0d"
KEY = VAULT + "/keys/paperdesk-release-result-signing"
KID = "https://kv-mds-sea-9c4e0d0d.vault.azure.net/keys/paperdesk-release-result-signing/60c5e54e98e64ef0b909cb8105ca2401"
LOCK = VAULT + "/providers/Microsoft.Authorization/locks/paperdesk-protect-keyvault-delete"
ROLE_ID = f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/{ROLE}"
ASSIGNMENT_ID = KEY + "/providers/Microsoft.Authorization/roleAssignments/" + ASSIGNMENT
MARKER = "paperdesk-private-release-v2-temporary:maintenance-key-expiry-renewal:" + CEREMONY
DATA_ACTIONS = ["Microsoft.KeyVault/vaults/keys/read", "Microsoft.KeyVault/vaults/keys/update/action"]
LOCK_NOTES = "PaperDesk production Key Vault deletion protection. Remove only for an approved delete, replacement, RBAC cleanup, or diagnostic cleanup."
PRIVATE_MEMBERS = {"d", "p", "q", "dp", "dq", "qi", "k"}
ARM = "https://management.azure.com"
UTC = dt.timezone.utc
REQUEST_ENVELOPE_SECONDS = 92
SOURCE_RESERVE_SECONDS = 90
BOUNDARY_ALLOWANCE_SECONDS = 2
ROLE_DEFINITIONS_INVENTORY_URL = ARM + f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
ROLE_DEFINITIONS_RESPONSE_MAX_BYTES = 2 * 1024 * 1024
PREFLIGHT_ARTIFACT_MAX_BYTES = 4 * 1024 * 1024
# The narrowly documented source exception is dormant until this helper is
# merged, independently reviewed, exact-head CI passes, and external single-use
# approval binds that final merged head. No source SHA is self-referential.
REVIEWED_SOURCE_ADMITS_MAINTENANCE = True


class MaintenanceError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise MaintenanceError(message)


def canonical(document: Any) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw: bytes | str | dict) -> dict:
    if isinstance(raw, bytes) and len(raw) > 1024 * 1024:
        fail("JSON response exceeds bounded size")
    return _json_object(raw)


def strict_response_json(raw: bytes, url: str) -> dict:
    # Only this source-pinned, complete role inventory has a larger wire bound.
    # No caller can provide a maximum or transfer it to another endpoint.
    if url != ROLE_DEFINITIONS_INVENTORY_URL:
        return strict_json(raw)
    if not isinstance(raw, bytes) or len(raw) > ROLE_DEFINITIONS_RESPONSE_MAX_BYTES:
        fail("exact role inventory response exceeds bounded size or is not bytes")
    result = _json_object(raw)
    complete_inventory(result)
    return result


def strict_preflight_json(raw: bytes) -> dict:
    # The canonical artifact aggregates the bounded inventory and other evidence.
    # Its exact raw digest is checked before this parser is called by authorization.
    if not isinstance(raw, bytes) or len(raw) > PREFLIGHT_ARTIFACT_MAX_BYTES:
        fail("preflight artifact exceeds bounded size or is not bytes")
    result = _json_object(raw)
    if result.get("kind") != "paperdesk-key-expiry-maintenance-preflight" or result.get("ceremonyId") != CEREMONY:
        fail("preflight boundary changed")
    return result


def _json_object(raw: bytes | str | dict) -> dict:
    if isinstance(raw, dict):
        return copy.deepcopy(raw)

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                fail("duplicate JSON member")
            value[key] = item
        return value

    def invalid_constant(_):
        fail("nonfinite JSON constant")

    try:
        result = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
    except (ValueError, TypeError, UnicodeError):
        fail("invalid bounded JSON")
    if not isinstance(result, dict):
        fail("JSON must be an object")
    return result


def parse_time(value: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail("time must be UTC with Z")
    try:
        result = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        fail("invalid UTC time")
    if result.utcoffset() != dt.timedelta(0):
        fail("time must be UTC")
    return result


def arm_url(resource: str, version="2022-04-01") -> str:
    return ARM + resource + "?api-version=" + version


def validate_plan(plan: dict) -> None:
    # Pin the complete reviewed semantic document, including all read URLs,
    # cardinalities, call/phase limits, and local evidence/claim paths.
    # New facts/scope/UUIDs require a new independently reviewed plan+helper.
    if digest(canonical(plan)) != REVIEWED_PLAN_CANONICAL_SHA:
        fail("complete reviewed maintenance plan changed")
    fixed = plan["fixed"]
    exact = {"subscriptionId": SUB, "tenantId": TENANT, "ownerPrincipalId": OWNER,
             "ownerPrincipalType": "User", "resourceGroupId": RG,
             "vaultResourceId": VAULT, "keyResourceId": KEY, "keyVersionUri": KID,
             "roleDefinitionId": ROLE, "roleDefinitionResourceId": ROLE_ID,
             "roleAssignableScope": RG, "assignmentId": ASSIGNMENT,
             "assignmentResourceId": ASSIGNMENT_ID, "lockResourceId": LOCK,
             "ownershipMarker": MARKER}
    if fixed != exact or plan["ceremonyId"] != CEREMONY:
        fail("maintenance identities/scope changed")
    if plan["source"]["verifierMain"] != SOURCE_SHA or plan["source"]["unchangedBootstrapPlanSha256"].lower() != BOOTSTRAP_PLAN_SHA:
        fail("reviewed source/bootstrap plan drifted")
    role = {"properties": {"roleName": "PaperDesk V2 temporary maintenance-key-expiry-renewal " + CEREMONY,
            "description": MARKER, "type": "CustomRole",
            "permissions": [{"actions": [], "notActions": [], "dataActions": DATA_ACTIONS, "notDataActions": []}],
            "assignableScopes": [RG]}}
    assignment = {"properties": {"principalId": OWNER, "principalType": "User",
            "roleDefinitionId": ROLE_ID, "description": MARKER}}
    bodies = {"roleDefinition": role, "roleAssignment": assignment,
              "keyExpiryPatch": {"attributes": {"exp": 1798761600}},
              "exactLockRestoration": {"properties": {"level": "CanNotDelete", "notes": LOCK_NOTES}}}
    if plan["createBodies"] != bodies:
        fail("reviewed bodies expanded")
    expected = [("PUT", arm_url(ROLE_ID)), ("PUT", arm_url(ASSIGNMENT_ID)),
                ("PATCH", KID + "?api-version=2025-07-01"),
                ("DELETE", arm_url(LOCK, "2016-09-01")),
                ("DELETE", arm_url(ASSIGNMENT_ID)),
                ("PUT", arm_url(LOCK, "2016-09-01")), ("DELETE", arm_url(ROLE_ID))]
    if [(s["method"], s["url"]) for s in plan["mutationAttemptOrder"]] != expected:
        fail("mutation boundary changed")
    statuses = [[201], [201], [200], [200, 202, 204], [200, 202, 204], [200, 201], [200, 204]]
    if [s["successStatuses"] for s in plan["mutationAttemptOrder"]] != statuses:
        fail("mutation statuses changed")
    if any(s["maximumAttempts"] != 1 for s in plan["mutationAttemptOrder"]):
        fail("retry expansion")
    bounds = plan["bounds"]
    if (bounds["keyVaultDataPlaneGetAttemptsMaximum"], bounds["keyVaultDataPlanePatchAttemptsMaximum"],
            bounds["keyVaultMeteredOperationAttemptsMaximum"], bounds["azureMutationAttemptsMaximum"],
            bounds["automaticMutationRetries"], bounds["transportRetries"]) != (2, 1, 3, 7, 0, 0):
        fail("attempt budget changed")
    if (bounds["ceremonyAuthorizationMaximumSeconds"], bounds["grantCreationMutationLastAdmitSecondsFromStart"],
            bounds["grantSetupMaximumSeconds"], bounds["allKeyWorkMustFinishSecondsFromStart"],
            bounds["cleanupReservedSeconds"], bounds["restResponseAndTokenEnvelopeSeconds"]) != (5700, 208, 600, 900, 4800, 92):
        fail("phase boundary changed")
    if plan["expiry"] != {"historicalBefore": "2026-10-31T07:00:24Z", "desired": "2027-01-01T00:00:00Z", "desiredUnixSeconds": 1798761600}:
        fail("expiry boundary changed")
    phase_budget(plan)


def phase_budget(plan: dict) -> dict:
    schedule = plan["deadlineSchedule"]
    # 8 fixed guard envelopes + one conservative extra boundary envelope.
    guard = 9 * 92 + (120 + 2 + 90 + 2) + (600 + 2 + 90 + 2) + (120 + 2)
    definition = 3 * 92 + (600 + 2 + 92)
    final = 2 * 8 * 92 + 120
    cleanup = guard + definition + final
    normal = 900 + cleanup
    ambiguous = 300 + (600 + 2 + 92) + guard + definition + final
    if cleanup > 4800 or normal > 5700 or ambiguous > 5700:
        fail("conservative cleanup does not fit authorization")
    if schedule["normalCleanupMaximumSeconds"] != cleanup or schedule["ambiguousAssignmentPathCompleteLatestOffsetSeconds"] != ambiguous:
        fail("reviewed deadline arithmetic drifted")
    return {"guard": guard, "definition": definition, "final": final,
            "cleanup": cleanup, "normal": normal, "ambiguous": ambiguous}


def _reject_private(value):
    if isinstance(value, dict):
        if any(key in PRIVATE_MEMBERS for key in value):
            fail("private key member returned; no persistence")
        for item in value.values():
            _reject_private(item)
    elif isinstance(value, list):
        for item in value:
            _reject_private(item)


def validate_public_key(document: bytes | dict, plan: dict, arm_key: dict, before=None) -> dict:
    document = strict_json(document)
    _reject_private(document)
    value = document.get("key")
    attributes = document.get("attributes")
    arm_props = arm_key.get("properties", {})
    if not isinstance(value, dict) or not isinstance(attributes, dict):
        fail("public key/attributes missing")
    if (any(document.get(field) is not None for field in ("release_policy", "releasePolicy")) or
        any(arm_props.get(field) is not None for field in ("release_policy", "releasePolicy"))):
        fail("release policy is not approved")
    if value.get("kid") != KID or arm_props.get("keyUriWithVersion") != KID:
        fail("exact key version changed")
    if (arm_props.get("kty"), arm_props.get("keySize"), arm_props.get("keyOps")) != ("RSA", 3072, ["sign", "verify"]):
        fail("ARM key posture changed")
    if (value.get("kty"), value.get("e"), value.get("key_ops")) != ("RSA", "AQAB", ["sign", "verify"]):
        fail("public key posture changed")
    modulus = value.get("n")
    if not isinstance(modulus, str) or "=" in modulus:
        fail("modulus is not canonical base64url")
    try:
        raw = base64.urlsafe_b64decode(modulus + "=" * (-len(modulus) % 4))
    except (ValueError, TypeError):
        fail("modulus is invalid")
    if len(raw) != 384 or int.from_bytes(raw, "big").bit_length() != 3072 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != modulus:
        fail("RSA modulus is not exactly3072bits")
    if attributes.get("enabled") is not True or attributes.get("exportable") is not False or attributes.get("recoverableDays") != 90:
        fail("key attributes changed")
    if any(type(attributes.get(k)) is not int for k in ("exp", "created", "updated", "recoverableDays")):
        fail("key integer attributes invalid")
    if not isinstance(attributes.get("recoveryLevel"), str) or not attributes["recoveryLevel"]:
        fail("key recovery posture missing")
    nbf = attributes.get("nbf")
    if nbf is not None and (type(nbf) is not int or nbf > attributes["created"]):
        fail("key not-before posture invalid")
    if attributes["created"] > attributes["updated"]:
        fail("provider key times invalid")
    exp = plan["keyValidation"]["afterExpiryUnixSeconds" if before is not None else "beforeExpiryUnixSeconds"]
    if attributes["exp"] != exp:
        fail("key expiry differs from exact approved value")
    projection = copy.deepcopy(document)
    if before is not None:
        old = copy.deepcopy(before)
        new = copy.deepcopy(projection)
        if attributes["updated"] < old["attributes"]["updated"]:
            fail("updated timestamp went backwards")
        old["attributes"].pop("exp")
        old["attributes"].pop("updated")
        new["attributes"].pop("exp")
        new["attributes"].pop("updated")
        if new != old:
            fail("non-expiry key fields drifted")
    return projection


class Journal:
    """Local, same-host single-use claim, not an Azure distributed replay claim."""
    def __init__(self, path, claim_path):
        self.path = Path(path)
        self.claim_path = Path(claim_path)
        self.claimed = False

    def claim(self, document):
        self.claim_path.parent.mkdir(parents=True, exist_ok=True)
        with self.claim_path.open("xb") as handle:
            handle.write(canonical(document))
            handle.flush()
            os.fsync(handle.fileno())
        self.claimed = True

    def record(self, document):
        if not self.claimed:
            fail("durable claim required")
        with self.path.open("ab") as handle:
            handle.write(canonical(document))
            handle.flush()
            os.fsync(handle.fileno())


def project_role(document: dict) -> dict:
    p = document.get("properties", {})
    return {"id": document.get("id"), "name": document.get("name"), "type": document.get("type"),
            "properties": {k: p.get(k) for k in ("roleName", "description", "type", "permissions", "assignableScopes")}}


def project_assignment(document: dict) -> dict:
    p = document.get("properties", {})
    return {"id": document.get("id"), "name": document.get("name"), "type": document.get("type"),
            "properties": {k: p.get(k) for k in ("principalId", "principalType", "roleDefinitionId", "scope",
              "condition", "conditionVersion", "delegatedManagedIdentityResourceId", "description")}}


def expected_role(plan):
    return {"id": ROLE_ID, "name": ROLE, "type": "Microsoft.Authorization/roleDefinitions",
            "properties": plan["createBodies"]["roleDefinition"]["properties"]}


def expected_assignment(plan):
    p = dict(plan["createBodies"]["roleAssignment"]["properties"])
    p.update(scope=KEY, condition=None, conditionVersion=None, delegatedManagedIdentityResourceId=None)
    return {"id": ASSIGNMENT_ID, "name": ASSIGNMENT, "type": "Microsoft.Authorization/roleAssignments", "properties": p}


def complete_inventory(document):
    document = strict_json(document)
    if document.get("nextLink") not in (None, "") or not isinstance(document.get("value"), list):
        fail("inventory incomplete or paginated")
    rows = document["value"]
    if any(not isinstance(row, dict) or not isinstance(row.get("id"), str) for row in rows):
        fail("inventory entries invalid")
    ids = [row["id"].lower() for row in rows]
    if len(ids) != len(set(ids)):
        fail("duplicate inventory resource")
    return rows


def inventory_projection(rows):
    return sorted(copy.deepcopy(rows), key=lambda row: row["id"].lower())


def listed_permission(rows, action, data=False):
    key, exclusion = ("dataActions", "notDataActions") if data else ("actions", "notActions")
    wanted = action.lower()
    def matches(pattern):
        if not isinstance(pattern, str) or any(c in pattern for c in "?[]"):
            fail("unsupported permission pattern")
        return re.fullmatch(re.escape(pattern.lower()).replace(r"\*", ".*"), wanted) is not None
    return any(any(matches(p) for p in row.get(key, []))
               and not any(matches(p) for p in row.get(exclusion, []))
               for row in rows)


def permission_page(document):
    document = strict_json(document)
    if document.get("nextLink") not in (None, "") or not isinstance(document.get("value"), list) or not document["value"]:
        fail("caller permission page incomplete")
    fields = {"actions", "notActions", "dataActions", "notDataActions"}
    for row in document["value"]:
        if not isinstance(row, dict) or set(row) - fields:
            fail("caller permission entry not exact")
        if any(not isinstance(row.get(field, []), list) or any(not isinstance(pattern, str) or not pattern or
                 any(c in pattern for c in "?[]") for pattern in row.get(field, [])) for field in fields):
            fail("caller permission entry invalid")
    return document["value"]


class Maintenance:
    def __init__(self, plan, authorization, session, journal, clock=None, sleep=None, cleanup_module=None):
        validate_plan(plan)
        self.plan, self.auth, self.session, self.journal = plan, authorization, session, journal
        self.clock = clock or (lambda: dt.datetime.now(UTC))
        self._sleep = sleep or time.sleep
        self.sleep = self.bounded_sleep
        self.cleanup_module = cleanup_module
        self.start = parse_time(authorization["validity"]["notBefore"])
        self.end = parse_time(authorization["validity"]["expiresAt"])
        self.last_clock = self.start
        self.attempts = set()
        self.key_gets = self.control_gets = 0
        self.ordinary_control_gets = self.restoration_control_gets = 0
        self.suspension_intent_durable = False
        self.source_guard_restoration_context = False
        self.owned_role = self.owned_assignment = False
        self.uncertain_creations = set()
        self.creation_settlement_boundaries = {}
        self.pending_read_events = []
        self.baseline = None
        self.phase_deadline = self.end
        self.primary_failure = None
        self.allowed_reads = set(plan["preflight"]["requiredCompleteInventoryUrls"])
        self.allowed_reads.update(plan["preflight"]["requiredAbsentResourceGetUrls"])
        self.allowed_reads.update(plan["preflight"][k] for k in ("requiredExactLockGetUrl", "requiredVaultGetUrl",
                "requiredArmKeyGetUrl", "freshCallerKeyPermissionsGetUrl"))
        self.allowed_reads.add(KID + "?api-version=2025-07-01")

    def now(self):
        value = self.clock()
        if value.tzinfo is None or value < self.last_clock:
            fail("maintenance clock invalid or regressed")
        self.last_clock = value
        return value

    def bounded_sleep(self, seconds):
        if not isinstance(seconds, (int, float)) or seconds < 0:
            fail("sleep boundary invalid")
        before = self.now()
        self._sleep(seconds)
        after = self.now()
        if seconds > 0 and after < before + dt.timedelta(seconds=max(0, seconds - 0.05)):
            fail("sleep did not advance maintenance clock")

    def deadline(self, requested=None, restore=False):
        hard = self.end + dt.timedelta(seconds=900) if restore else self.end
        end = min(hard, self.phase_deadline)
        if requested is not None:
            end = min(end, requested)
        return end

    def _admit(self, end, seconds=REQUEST_ENVELOPE_SECONDS):
        now = self.now()
        if now < self.start or now + dt.timedelta(seconds=seconds) > end:
            fail("request lacks live authorization/full92s adapter envelope")
        return now

    def read(self, method, url, deadline=None):
        if method != "GET" or url not in self.allowed_reads:
            fail("read is outside exact maintenance allowlist")
        # Only source-owned exact-lock restoration reads may use its90s envelope
        # after the general role/key authorization has ended.
        restoration_read = (url == arm_url(LOCK, "2016-09-01") and self.source_guard_restoration_context and
                            self.suspension_intent_durable and self.owned_assignment)
        # Unchanged CleanupLockGuard sometimes supplies a final logical90s
        # envelope. Allow2s solely for the later session admission clock, while
        # still rejecting completion after the original logical deadline.
        logical = self.deadline(deadline, restore=restoration_read)
        hard = self.deadline(restore=restoration_read)
        transport_end = min(hard, logical + dt.timedelta(seconds=BOUNDARY_ALLOWANCE_SECONDS)) if deadline is not None else hard
        started = self._admit(transport_end, seconds=SOURCE_RESERVE_SECONDS if deadline is not None else REQUEST_ENVELOPE_SECONDS)
        data = url.startswith(KID + "?")
        if data:
            offset = (started - self.start).total_seconds()
            if offset > (600 if self.key_gets == 0 else 780):
                fail("exact ordinal KeyVault GET admission cutoff passed")
            if self.key_gets >= 2:
                fail("two-KeyVault-GET budget exhausted")
            self.key_gets += 1
        else:
            if self.control_gets >= 1250:
                fail("control-plane read budget exhausted")
            if restoration_read:
                if self.restoration_control_gets >= 63:
                    fail("exact owned lock-restoration read reserve exhausted")
                self.restoration_control_gets += 1
            else:
                if self.ordinary_control_gets >= 1187:
                    fail("ordinary control-plane read budget exhausted; restoration reserve cannot be borrowed")
                self.ordinary_control_gets += 1
            self.control_gets += 1
        request_end = min(transport_end, started + dt.timedelta(seconds=REQUEST_ENVELOPE_SECONDS))
        response = self.session.request("GET", url, deadline=request_end)
        if self.now() > logical:
            fail("read completed after original logical deadline")
        if response.status == 200:
            parsed = strict_response_json(response.body, url)
            if data:
                _reject_private(parsed)
            # Source CleanupLockGuard uses json.loads; parsing here rejects duplicates first.
        event = {"kind": "read", "method": "GET", "url": url, "status": response.status,
                 "observedAt": self.now().isoformat(), "responseSha256": digest(response.body)}
        if self.journal.claimed:
            self.journal.record(event)
        else:
            self.pending_read_events.append(event)
        if self.now() > logical:
            fail("read/result journal exceeded original logical deadline")
        return response

    def mutate(self, method, url, body=None, expected=None, restore=False):
        if not self.journal.claimed:
            fail("exact durable maintenance claim required before mutation")
        matches = [step for step in self.plan["mutationAttemptOrder"] if step["method"] == method and step["url"] == url]
        if len(matches) != 1:
            fail("mutation outside exact allowlist")
        step = matches[0]
        if step["id"] in self.attempts:
            fail("mutation already consumed; no retry")
        actual = None if body is None else strict_json(body)
        desired = self.plan["createBodies"][step["bodyReference"].split(".")[-1]] if "bodyReference" in step else None
        if actual != desired or (expected is not None and set(expected) != set(step["successStatuses"])):
            fail("mutation body/status scope changed")
        if restore != (step["step"] == 6):
            fail("restoration exception is exact lock PUT only")
        if restore and not (self.source_guard_restoration_context and self.suspension_intent_durable and self.owned_assignment):
            fail("restoration PUT lacks source guard owned suspension context")
        end = self.deadline(restore=restore)
        now = self._admit(end)
        offset = (now - self.start).total_seconds()
        if step["step"] in (1, 2) and offset > 208:
            fail("grant-create admission cutoff passed")
        if step["step"] == 3 and (offset > 690 or (self.end - now).total_seconds() < 4800):
            fail("key PATCH admission/reserve failed")
        if step["step"] in (4, 5, 7) and now >= self.end:
            fail("no role deletion after authorization expiry")
        # Consume memory state before durable intent, then call exactly once.
        self.attempts.add(step["id"])
        self.journal.record({"kind": "intent", "step": step["step"], "id": step["id"],
                             "method": method, "url": url, "bodySha256": None if body is None else digest(body),
                             "at": now.isoformat(), "restore": restore})
        if step["step"] == 4:
            self.suspension_intent_durable = True
        request_end = min(end, now + dt.timedelta(seconds=REQUEST_ENVELOPE_SECONDS))
        wire_now = self.now()
        if wire_now + dt.timedelta(seconds=SOURCE_RESERVE_SECONDS) > request_end:
            fail("intent journal consumed transport admission allowance")
        if step["step"] in (1, 2) and (wire_now - self.start).total_seconds() > 208:
            fail("grant-create wire admission cutoff passed")
        if step["step"] == 3 and (wire_now - self.start).total_seconds() > 690:
            fail("key PATCH wire admission cutoff passed")
        if step["step"] == 1:
            self.owned_role = True
            self.creation_settlement_boundaries["role"] = now + dt.timedelta(seconds=692)
        if step["step"] == 2:
            self.owned_assignment = True
            self.creation_settlement_boundaries["assignment"] = now + dt.timedelta(seconds=692)
        try:
            response = self.session.request(method, url, body=body,
                      headers=None if body is None else {"Content-Type": "application/json"},
                      deadline=request_end)
            self.journal.record({"kind": "result", "id": step["id"], "status": response.status,
                                 "responseSha256": digest(response.body), "at": self.now().isoformat()})
            if self.now() > request_end:
                fail("mutation/result journal exceeded adapter request envelope")
        except BaseException as exc:
            # No untrusted exception text, credential or response body is stored.
            try:
                self.journal.record({"kind": "ambiguous", "id": step["id"],
                                     "exceptionType": type(exc).__name__, "at": self.now().isoformat()})
            except BaseException:
                pass
            raise
        if response.status not in step["successStatuses"]:
            fail("mutation returned unapproved status; attempt remains consumed")
        return response

    def object(self, url, status=200):
        response = self.read("GET", url)
        if response.status != status:
            fail("read returned unexpected status")
        return strict_response_json(response.body, url) if status == 200 else None

    def effective_locks(self, rows, scope):
        return [r for r in rows if scope.lower().startswith(r["id"].lower().rsplit("/providers/microsoft.authorization/locks/", 1)[0] + "/")]

    def verify_locks(self, operation_id="", lock_key=""):
        rows = complete_inventory(self.object(self.plan["preflight"]["requiredCompleteInventoryUrls"][0]))
        effective = self.effective_locks(rows, ASSIGNMENT_ID)
        if len(effective) != 1 or effective[0]["id"].lower() != LOCK.lower():
            fail("unreviewed inherited lock at key assignment")
        self.cleanup_module.validate_lock_document(effective[0], self.cleanup_module.REVIEWED_CLEANUP_LOCKS["signingVault"], fail)
        if self.effective_locks(rows, ROLE_ID):
            fail("inherited lock blocks temporary definition cleanup")
        return rows

    def snapshot(self):
        pre = self.plan["preflight"]
        result = {}
        for label, url in (("roleDefinition", arm_url(ROLE_ID)), ("assignment", arm_url(ASSIGNMENT_ID))):
            response = self.read("GET", url)
            result[label] = {"status": response.status}
            if response.status == 200:
                result[label]["document"] = strict_json(response.body)
            elif response.status != 404:
                fail("exact role/assignment preflight read failed")
        names = ("locks", "roleDefinitions", "assignments")
        for label, url in zip(names, pre["requiredCompleteInventoryUrls"]):
            result[label] = complete_inventory(self.object(url))
        result["lock"] = self.object(pre["requiredExactLockGetUrl"])
        result["vault"] = self.object(pre["requiredVaultGetUrl"])
        result["armKey"] = self.object(pre["requiredArmKeyGetUrl"])
        return result

    def validate_preflight(self, snapshot, permissions):
        if snapshot["roleDefinition"]["status"] != 404 or snapshot["assignment"]["status"] != 404:
            fail("preexisting role/assignment is never adopted")
        if any((row.get("properties", {}).get("roleName") or "").startswith("PaperDesk V2 temporary ") or
               (row.get("properties", {}).get("description") or "").startswith("paperdesk-private-release-v2-temporary:")
               for label in ("roleDefinitions", "assignments") for row in snapshot[label]):
            fail("prior same-ceremony marker present")
        self.cleanup_module.validate_lock_document(snapshot["lock"], self.cleanup_module.REVIEWED_CLEANUP_LOCKS["signingVault"], fail)
        effective = self.effective_locks(snapshot["locks"], ASSIGNMENT_ID)
        if len(effective) != 1 or effective[0]["id"].lower() != LOCK.lower() or self.effective_locks(snapshot["locks"], ROLE_ID):
            fail("inherited cleanup locks differ")
        p = snapshot["vault"].get("properties", {})
        if (p.get("enableRbacAuthorization") is not True or p.get("publicNetworkAccess") != "Enabled" or
            p.get("enableSoftDelete") is not True or p.get("enablePurgeProtection") is not True or
            p.get("networkAcls", {}).get("defaultAction") != "Allow" or p.get("networkAcls", {}).get("bypass") != "None"):
            fail("vault RBAC/network posture differs")
        if snapshot["armKey"].get("properties", {}).get("keyUriWithVersion") != KID:
            fail("ARM signing key version differs")
        props = snapshot["armKey"].get("properties", {})
        attrs = props.get("attributes", {})
        if (props.get("kty"), props.get("keySize"), props.get("keyOps")) != ("RSA", 3072, ["sign", "verify"]):
            fail("ARM signing key posture differs")
        if (attrs.get("enabled") is not True or attrs.get("exportable", False) is not False or
            attrs.get("exp") != self.plan["keyValidation"]["beforeExpiryUnixSeconds"] or
            any(props.get(field) is not None for field in ("release_policy", "releasePolicy"))):
            fail("ARM signing key baseline attributes differ")
        if any(not listed_permission(permissions, action) for action in self.plan["preflight"]["requiredControlPlaneAuthority"]):
            fail("listed required control-plane authority missing")
        if any(listed_permission(permissions, action, True) for action in DATA_ACTIONS):
            fail("baseline key permissions drifted; do not grant redundant access")

    def prove_owned(self, url, kind):
        response = self.read("GET", url)
        if response.status == 404:
            return False
        if response.status != 200:
            fail("owned resource read failed")
        document = strict_json(response.body)
        projector = project_role if kind == "role" else project_assignment
        wanted = expected_role(self.plan) if kind == "role" else expected_assignment(self.plan)
        if projector(document) != wanted:
            fail("owned resource projection changed; never delete third state")
        return True

    def settle(self, url, kind, desired_absent, seconds=600):
        boundary = min(self.now() + dt.timedelta(seconds=seconds), self.end - dt.timedelta(seconds=92))
        previous_deadline = self.phase_deadline
        self.phase_deadline = min(previous_deadline, boundary + dt.timedelta(seconds=94))
        try:
            while True:
                if self.now() + dt.timedelta(seconds=92) >= boundary:
                    wait = (boundary - self.now()).total_seconds()
                    if wait > 0:
                        self.sleep(wait)
                present = self.prove_owned(url, kind)
                if desired_absent and not present:
                    return
                if not desired_absent and present:
                    return
                if self.now() >= boundary:
                    fail("owned resource did not settle by deadline")
                self.sleep(2)
        finally:
            self.phase_deadline = previous_deadline

    def create(self, step, kind):
        # Adjacent404, exact owned marker and same-host claim are ownership gates,
        # not a documented CAS promise against concurrent administrators.
        self.object(step["url"], 404)
        body = canonical(self.plan["createBodies"][step["bodyReference"].split(".")[-1]])
        try:
            self.mutate("PUT", step["url"], body, expected={201})
        except BaseException:
            if step["id"] in self.attempts and (self.owned_role if kind == "role" else self.owned_assignment):
                self.uncertain_creations.add(kind)
            raise
        try:
            self.settle(step["url"], kind, desired_absent=False)
        except BaseException:
            self.uncertain_creations.add(kind)
            raise

    def reconcile_creation(self, kind):
        url = arm_url(ROLE_ID if kind == "role" else ASSIGNMENT_ID)
        # Reuse the original wire-attempt settlement window; a setup visibility
        # failure must not start a second600s propagation window.
        convergence = self.creation_settlement_boundaries[kind]
        if self.now() > convergence + dt.timedelta(seconds=94):
            fail("original creation settlement window exhausted")
        previous = self.phase_deadline
        self.phase_deadline = min(self.end, convergence + dt.timedelta(seconds=94))
        try:
            while True:
                if self.now() + dt.timedelta(seconds=92) >= convergence:
                    wait = (convergence - self.now()).total_seconds()
                    if wait > 0:
                        self.sleep(wait)
                present = self.prove_owned(url, kind)
                if present:
                    return True
                if self.now() >= convergence:
                    return False
                self.sleep(2)
        finally:
            self.phase_deadline = previous

    def cleanup(self):
        self.phase_deadline = self.end
        # A first404 after an ambiguous creation is not a convergence proof.
        if "role" in self.uncertain_creations and not self.reconcile_creation("role"):
            self.owned_role = False
        if "assignment" in self.uncertain_creations and not self.reconcile_creation("assignment"):
            self.owned_assignment = False
        if self.owned_assignment:
            guard = self.cleanup_module.CleanupLockGuard(read_request=self.read, mutate_request=self.mutate,
                    verify_lock_inventory=self.verify_locks, clock=self.now, sleep=self.sleep, fail=fail,
                    require_live_authorization=lambda: self._admit(self.end),
                    post_delete_read_request=self.read)
            # Callback wrapper expands only exact original-lock restoration deadline.
            original_mutate = guard.mutate_request
            original_post_read = guard.post_delete_read_request
            def restoration_mutate(method, url, **kwargs):
                old = self.phase_deadline
                old_context = self.source_guard_restoration_context
                if kwargs.get("restore"):
                    self.phase_deadline = self.end + dt.timedelta(seconds=900)
                    self.source_guard_restoration_context = self.suspension_intent_durable and self.owned_assignment
                try:
                    return original_mutate(method, url, **kwargs)
                finally:
                    self.phase_deadline = old
                    self.source_guard_restoration_context = old_context
            def protected_read(method, url, **kwargs):
                old = self.phase_deadline
                old_context = self.source_guard_restoration_context
                if url == arm_url(LOCK, "2016-09-01") and self.suspension_intent_durable and self.owned_assignment:
                    self.phase_deadline = self.end + dt.timedelta(seconds=900)
                    self.source_guard_restoration_context = True
                try:
                    return original_post_read(method, url, **kwargs)
                finally:
                    self.phase_deadline = old
                    self.source_guard_restoration_context = old_context
            guard.mutate_request = restoration_mutate
            guard.post_delete_read_request = protected_read
            guard.delete_assignment(operation_id="removeOwnedOperatorKeyReadRole",
                    assignment_url=arm_url(ASSIGNMENT_ID),
                    expected_assignment_projection=expected_assignment(self.plan),
                    project_assignment=project_assignment)
        if self.owned_role:
            # If an assignment existed, the reviewed guard just proved its404
            # and exact lock restoration. Otherwise no lock was suspended.
            # The complete reference inventory below must also be empty.
            present = self.prove_owned(arm_url(ROLE_ID), "role")
            refs = complete_inventory(self.object(self.plan["preflight"]["requiredCompleteInventoryUrls"][2]))
            if any(r.get("properties", {}).get("roleDefinitionId", "").lower() == ROLE_ID.lower() for r in refs):
                fail("role definition still referenced")
            if present:
                self.mutate("DELETE", arm_url(ROLE_ID), expected={200, 204})
                self.settle(arm_url(ROLE_ID), "role", desired_absent=True)

    def final_proof(self, renewal):
        first = self.snapshot()
        completed = self.now()
        self.sleep(120)
        second = self.snapshot()
        if self.now() < completed + dt.timedelta(seconds=120):
            fail("final proof separation invalid")
        for snap in (first, second):
            if snap["roleDefinition"]["status"] != 404 or snap["assignment"]["status"] != 404:
                fail("temporary grant cleanup incomplete")
            for label in ("roleDefinitions", "assignments"):
                if any((row.get("properties", {}).get("roleName") or "").startswith("PaperDesk V2 temporary ") or
                       (row.get("properties", {}).get("description") or "").startswith("paperdesk-private-release-v2-temporary:")
                       for row in snap[label]):
                    fail("temporary marker remains")
            for label in ("locks", "roleDefinitions", "assignments", "vault", "lock"):
                left = inventory_projection(snap[label]) if isinstance(snap[label], list) else snap[label]
                right = inventory_projection(self.baseline[label]) if isinstance(snap[label], list) else self.baseline[label]
                if left != right:
                    fail("unrelated control-plane metadata changed")
            arm_old, arm_new = copy.deepcopy(self.baseline["armKey"]), copy.deepcopy(snap["armKey"])
            post_exp = arm_new.get("properties", {}).get("attributes", {}).get("exp")
            if renewal == "PASS" and post_exp != 1798761600:
                fail("renewed ARM expiry changed during cleanup")
            if renewal != "PASS" and post_exp not in (self.plan["keyValidation"]["beforeExpiryUnixSeconds"], 1798761600):
                fail("unapproved ARM expiry during cleanup")
            for arm_key in (arm_old, arm_new):
                attrs = arm_key.get("properties", {}).get("attributes", {})
                attrs.pop("exp", None)
                attrs.pop("updated", None)
            if arm_old != arm_new:
                fail("ARM key non-expiry metadata changed")
        return {"cleanup": "PASS", "snapshots": 2, "separatedSecondsAtLeast": 120,
                "armAbsenceDoesNotProveCachedDataPlaneRevocation": True}

    def run(self, supplied_preflight=None):
        if self.cleanup_module is None:
            fail("reviewed cleanup primitive required")
        account = self.session.account()
        if any(account.get(k) != v for k, v in {"subscriptionId": SUB, "tenantId": TENANT,
                "accountObjectId": OWNER, "accountType": "user", "cloud": "AzureCloud"}.items()):
            fail("caller identity drifted")
        fresh = self.snapshot()
        permissions_doc = self.object(self.plan["preflight"]["freshCallerKeyPermissionsGetUrl"])
        permissions = permission_page(permissions_doc)
        self.validate_preflight(fresh, permissions)
        if supplied_preflight is None or supplied_preflight["snapshot"] != fresh:
            fail("fresh preflight differs from separately observed approved baseline")
        completed = parse_time(supplied_preflight["completedAt"])
        observed = parse_time(supplied_preflight["observedAt"])
        if not observed <= completed <= self.now() or self.now() - completed > dt.timedelta(seconds=300):
            fail("approved preflight expired")
        if supplied_preflight.get("callerPermissions") != permissions_doc:
            fail("caller permissions drifted since fresh approved preflight")
        if self.now() + dt.timedelta(seconds=92) > self.start + dt.timedelta(seconds=208):
            fail("claim/preflight delay leaves insufficient grant admission window")
        self.journal.claim({"ceremonyId": CEREMONY, "authorizationSha256": digest(canonical(self.auth)),
                   "maintenancePlanSha256": self.auth["maintenancePlanSha256"], "executorSha256": self.auth["executorSha256"],
                   "operatorHost": self.auth["operatorHost"], "claimedAt": self.now().isoformat()})
        for event in self.pending_read_events:
            self.journal.record(event)
        self.pending_read_events.clear()
        self.baseline = fresh
        self.journal.record({"kind": "preflight-admitted", "sha256": digest(canonical(fresh)), "at": self.now().isoformat()})
        renewal = "NOT_ATTEMPTED"
        try:
            self.phase_deadline = self.start + dt.timedelta(seconds=600)
            self.create(self.plan["mutationAttemptOrder"][0], "role")
            self.create(self.plan["mutationAttemptOrder"][1], "assignment")
            # Bounded read-only propagation wait, with no provider readiness GET.
            # ARM visibility does not establish data-plane permission.
            wait_until = self.start + dt.timedelta(seconds=480)
            if self.now() < wait_until:
                self.sleep((wait_until - self.now()).total_seconds())
            self.phase_deadline = self.start + dt.timedelta(seconds=900)
            before = validate_public_key(self.object(KID + "?api-version=2025-07-01"), self.plan, fresh["armKey"])
            try:
                response = self.mutate("PATCH", KID + "?api-version=2025-07-01",
                          canonical(self.plan["createBodies"]["keyExpiryPatch"]), expected={200})
                # PATCH body is only a hash in journal; validate returned public material too.
                validate_public_key(response.body, self.plan, fresh["armKey"], before)
                renewal = "PATCH_ACCEPTED"
            except BaseException as exc:
                self.primary_failure = type(exc).__name__
                renewal = "PATCH_FAILED_OR_AMBIGUOUS"
            after = self.object(KID + "?api-version=2025-07-01")
            validate_public_key(after, self.plan, fresh["armKey"], before)
            if renewal == "PATCH_ACCEPTED":
                renewal = "PASS"
        except BaseException as exc:
            self.primary_failure = self.primary_failure or type(exc).__name__
        finally:
            try:
                self.cleanup()
            except BaseException as exc:
                self.primary_failure = self.primary_failure or type(exc).__name__
                self.journal.record({"kind": "cleanup-failure", "exceptionType": type(exc).__name__, "at": self.now().isoformat()})
        proof = self.final_proof(renewal)
        result = {"schemaVersion": 1, "kind": "existing-key-expiry-maintenance-receipt",
                  "ceremonyId": CEREMONY, "renewal": renewal, "cleanup": proof,
                  "overall": "PASS" if renewal == "PASS" and self.primary_failure is None else "NO_GO",
                  "preservedFailureType": self.primary_failure, "keyVaultGetAttempts": self.key_gets,
                  "controlPlaneGets": self.control_gets, "ordinaryControlPlaneGets": self.ordinary_control_gets,
                  "exactLockRestorationGets": self.restoration_control_gets,
                  "mutationAttemptIds": sorted(self.attempts), "bootstrapS2": False, "releaseGo": False}
        self.journal.record({"kind": "final-receipt", **result})
        return result


def load_primitives(verifier, expected_head=None, require_merged=False):
    verifier = Path(verifier).resolve()
    head = subprocess.run(["git", "-C", str(verifier), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    if expected_head is not None and head != expected_head:
        fail("externally approved verifier checkout head drifted")
    if require_merged:
        merged = subprocess.run(["git", "-C", str(verifier), "rev-parse", "refs/remotes/origin/main"],
                    check=True, capture_output=True, text=True).stdout.strip()
        if merged != head:
            fail("maintenance source is not pinned to exact merged origin/main")
        if Path(__file__).resolve() != verifier / "scripts/private_release_key_expiry_maintenance.py":
            fail("execution helper is outside the exact reviewed checkout")
        for relative in ("scripts/private_release_key_expiry_maintenance.py", "contracts/private_release_key_expiry_maintenance_plan.json"):
            committed = subprocess.run(["git", "-C", str(verifier), "show", "HEAD:" + relative],
                      check=True, capture_output=True).stdout
            if committed != (verifier / relative).read_bytes():
                fail("maintenance files differ from exact merged source")
    dirty = subprocess.run(["git", "-C", str(verifier), "diff", "--name-only", "HEAD"], check=True, capture_output=True, text=True).stdout
    if dirty.strip():
        fail("verifier tracked source dirty")
    source_plan = verifier / "contracts/private_release_bootstrap_plan.json"
    source_plan_raw = source_plan.read_bytes()
    if digest(source_plan_raw) != BOOTSTRAP_PLAN_GIT_BLOB_SHA:
        fail("original bootstrap plan committed LF bytes drifted")
    if b"\r" in source_plan_raw or digest(source_plan_raw.replace(b"\n", b"\r\n")) != BOOTSTRAP_PLAN_SHA:
        fail("historical bootstrap CRLF presentation differs from approval bytes")
    maintenance_plan = strict_json((verifier / "contracts/private_release_key_expiry_maintenance_plan.json").read_bytes())
    validate_plan(maintenance_plan)
    primitive_hashes = {name: digest((verifier / "scripts" / name).read_bytes()) for name in (
                        "private_release_v2_bootstrap.py", "private_release_v2_cleanup_locks.py")}
    if primitive_hashes != maintenance_plan["source"]["pinnedPrimitiveHashes"]:
        fail("provider primitives differ from the reviewed maintenance plan before import")
    # Bootstrap imports both top-level sibling modules and the scripts package.
    # Resolve both from the exact verified checkout, independently of caller CWD.
    sys.path[0:0] = [str(verifier), str(verifier / "scripts")]
    import private_release_v2_bootstrap as bootstrap
    import private_release_v2_cleanup_locks as locks
    if (Path(bootstrap.__file__).resolve() != verifier / "scripts/private_release_v2_bootstrap.py" or
        Path(locks.__file__).resolve() != verifier / "scripts/private_release_v2_cleanup_locks.py"):
        fail("cached primitive module resolves outside reviewed checkout")
    return bootstrap, locks


def validate_authorization(auth, plan_raw, helper_raw, verifier, evidence_path, preflight_path):
    expected = {"schemaVersion", "kind", "ceremonyId", "maintenancePlanSha256", "executorSha256",
                "verifierSourceSha", "primitiveHashes", "azure", "validity", "operatorHost",
                "userApprovalEvidenceSha256", "freshPreflightSha256", "allowExecution", "sourceAcceptance"}
    if set(auth) != expected or auth["schemaVersion"] != 1 or auth["kind"] != "paperdesk-key-expiry-maintenance-authorization":
        fail("separate authorization schema invalid")
    if auth["allowExecution"] is not True or auth["ceremonyId"] != CEREMONY:
        fail("fresh maintenance execution approval required")
    if (auth["maintenancePlanSha256"] != digest(plan_raw) or auth["executorSha256"] != digest(helper_raw) or
        not isinstance(auth["verifierSourceSha"], str) or re.fullmatch(r"[0-9a-f]{40}", auth["verifierSourceSha"]) is None):
        fail("authorization does not bind reviewed exact bytes")
    validate_source_acceptance(auth["sourceAcceptance"], auth)
    if auth["azure"] != {"subscriptionId": SUB, "tenantId": TENANT, "accountObjectId": OWNER, "accountType": "User"}:
        fail("approval caller boundary changed")
    if auth["operatorHost"] != platform.node():
        fail("same-host single-use approval boundary changed")
    duration = (parse_time(auth["validity"]["expiresAt"]) - parse_time(auth["validity"]["notBefore"])).total_seconds()
    if set(auth["validity"]) != {"notBefore", "expiresAt"} or duration != 5700:
        fail("approval must cover exact95min bounded ceremony")
    actual = {name: digest((Path(verifier) / "scripts" / name).read_bytes()) for name in (
              "private_release_v2_bootstrap.py", "private_release_v2_cleanup_locks.py")}
    if auth["primitiveHashes"] != actual:
        fail("reviewed primitive bytes changed")
    if actual != strict_json(plan_raw)["source"]["pinnedPrimitiveHashes"]:
        fail("primitive bytes differ from independently reviewed maintenance plan")
    evidence_raw = Path(evidence_path).read_bytes()
    if digest(evidence_raw) != auth["userApprovalEvidenceSha256"]:
        fail("human approval evidence digest mismatch")
    evidence = strict_json(evidence_raw)
    if evidence.get("approved") is not True or evidence.get("ceremonyId") != CEREMONY or evidence.get("source") != "direct-human-user-reply":
        fail("direct human approval evidence required; root must verify its provenance")
    expected_bindings = {"maintenancePlanSha256": auth["maintenancePlanSha256"], "executorSha256": auth["executorSha256"],
                         "verifierSourceSha": auth["verifierSourceSha"], "sourceAcceptanceSha256": digest(canonical(auth["sourceAcceptance"]))}
    if evidence.get("approvedBindings") != expected_bindings:
        fail("human approval evidence does not bind exact source acceptance/plan/helper")
    preflight_raw = Path(preflight_path).read_bytes()
    if digest(preflight_raw) != auth["freshPreflightSha256"]:
        fail("fresh preflight digest mismatch")
    preflight = strict_preflight_json(preflight_raw)
    if preflight.get("kind") != "paperdesk-key-expiry-maintenance-preflight" or preflight.get("ceremonyId") != CEREMONY:
        fail("preflight boundary changed")
    if preflight.get("sourceSha") != auth["verifierSourceSha"] or preflight.get("maintenancePlanSha256") != auth["maintenancePlanSha256"]:
        fail("preflight source/plan binding differs from final reviewed maintenance head")
    return preflight


def validate_source_acceptance(acceptance, auth):
    # Primary-provider observations are prepared and provenance-verified by the
    # operator before requesting fresh human approval. They are external to
    # source, hash-bound by that approval, and cannot be filled from this code.
    fields = {"repository", "mergedMainSha", "sourcePrNumber", "finalPrHeadSha",
              "exactHeadCi", "exactMergedMainCi", "independentSourceReviews"}
    if not isinstance(acceptance, dict) or set(acceptance) != fields:
        fail("source acceptance fields are not exact")
    if acceptance["repository"] != "Sethvirak/paperdesk-release-verifier" or acceptance["mergedMainSha"] != auth["verifierSourceSha"]:
        fail("source acceptance repository/merged head differs")
    final = acceptance["finalPrHeadSha"]
    if type(acceptance["sourcePrNumber"]) is not int or acceptance["sourcePrNumber"] <= 0 or not isinstance(final, str) or re.fullmatch(r"[0-9a-f]{40}", final) is None:
        fail("source acceptance PR/head invalid")
    if acceptance["exactHeadCi"] != {"headSha": final, "conclusion": "success"} or acceptance["exactMergedMainCi"] != {"headSha": auth["verifierSourceSha"], "conclusion": "success"}:
        fail("exact reviewed head/main CI did not pass")
    reviews = acceptance["independentSourceReviews"]
    if not isinstance(reviews, list) or len(reviews) != 2:
        fail("both independent human source reviews required")
    expected = {"jecebella168-cmyk", "jecebella169-cmyk"}
    if {row.get("login") for row in reviews if isinstance(row, dict)} != expected:
        fail("independent reviewer identities differ")
    for row in reviews:
        if set(row) != {"login", "commitSha", "state", "submittedByHuman"} or row["commitSha"] != final or row["state"] != "APPROVED" or row["submittedByHuman"] is not True:
            fail("genuine exact-head human review evidence incomplete")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    parser.add_argument("--verifier")
    parser.add_argument("--authorization")
    parser.add_argument("--approval-evidence")
    parser.add_argument("--preflight")
    parser.add_argument("--observe-preflight", action="store_true")
    parser.add_argument("--output")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    raw = Path(args.plan).read_bytes()
    plan = strict_json(raw)
    validate_plan(plan)
    if args.observe_preflight and args.execute:
        fail("observe and execute modes are exclusive")
    if not args.execute and not args.observe_preflight:
        print(json.dumps({"status": "LOCAL_VALIDATION_ONLY_NO_CLOUD", "planSha256": digest(raw), "budget": phase_budget(plan)}))
        return
    if args.execute and not REVIEWED_SOURCE_ADMITS_MAINTENANCE:
        fail("current reviewed pre-S2 source admits only bootstrap; separate maintenance source exception required")
    if args.observe_preflight:
        if not args.verifier or not args.output:
            fail("explicit verifier/output required for free-control-plane-only observation")
        bootstrap, locks = load_primitives(args.verifier, require_merged=True)
        observed = dt.datetime.now(UTC)
        observation_auth = {"azure": {"accountObjectId": OWNER}, "validity": {
                  "notBefore": observed.isoformat().replace("+00:00", "Z"),
                  "expiresAt": (observed + dt.timedelta(seconds=300)).isoformat().replace("+00:00", "Z")}}
        # No claim, role, key data GET or mutation exists in observation mode.
        journal = Journal(Path(args.output).with_suffix(".unused-journal"), Path(args.output).with_suffix(".unused-claim"))
        runner = Maintenance(plan, observation_auth, bootstrap.AzureCliRestSession(observation_auth),
                             journal, cleanup_module=locks)
        runner.phase_deadline = observed + dt.timedelta(seconds=300)
        account = runner.session.account()
        if any(account.get(k) != v for k, v in {"subscriptionId": SUB, "tenantId": TENANT,
                "accountObjectId": OWNER, "accountType": "user", "cloud": "AzureCloud"}.items()):
            fail("observation caller identity drifted")
        snapshot = runner.snapshot()
        permission_doc = runner.object(plan["preflight"]["freshCallerKeyPermissionsGetUrl"])
        runner.validate_preflight(snapshot, permission_page(permission_doc))
        artifact = {"schemaVersion": 1, "kind": "paperdesk-key-expiry-maintenance-preflight",
                    "ceremonyId": CEREMONY, "maintenancePlanSha256": digest(raw), "sourceSha": subprocess.run(
                       ["git", "-C", str(Path(args.verifier).resolve()), "rev-parse", "HEAD"], check=True,
                       capture_output=True, text=True).stdout.strip(),
                    "observedAt": observed.isoformat().replace("+00:00", "Z"),
                    "completedAt": runner.now().isoformat().replace("+00:00", "Z"),
                    "snapshot": snapshot, "callerPermissions": permission_doc,
                    "controlPlaneReadEvents": runner.pending_read_events,
                    "keyVaultDataPlaneOperations": 0, "azureMutations": 0}
        output = Path(args.output)
        with output.open("xb") as handle:
            handle.write(canonical(artifact)); handle.flush(); os.fsync(handle.fileno())
        print(json.dumps({"status": "CONTROL_PLANE_PREFLIGHT_ONLY", "path": str(output)}))
        return
    if not all((args.verifier, args.authorization, args.approval_evidence, args.preflight)):
        fail("all separate maintenance approval and preflight artifacts required")
    auth = strict_json(Path(args.authorization).read_bytes())
    supplied = validate_authorization(auth, raw, Path(__file__).read_bytes(), args.verifier,
                                      args.approval_evidence, args.preflight)
    if Path(args.plan).resolve() != Path(args.verifier).resolve() / "contracts/private_release_key_expiry_maintenance_plan.json":
        fail("execution plan is outside exact reviewed checkout")
    bootstrap, locks = load_primitives(args.verifier, expected_head=auth["verifierSourceSha"], require_merged=True)
    paths = plan["journaling"]
    journal = Journal(paths["journalPath"], paths["localClaimPath"])
    # Session is constructed only after exact approval/source/claim gates. It has no
    # bootstrap transport or ready-loop; all requests use the wrapper above.
    session = bootstrap.AzureCliRestSession(auth)
    receipt = Maintenance(plan, auth, session, journal, cleanup_module=locks).run(supplied)
    receipt_path = Path(paths["finalReceiptPath"])
    with receipt_path.open("xb") as handle:
        handle.write(canonical(receipt)); handle.flush(); os.fsync(handle.fileno())
    print(json.dumps({"status": receipt["overall"], "receiptPath": str(receipt_path)}))


if __name__ == "__main__":
    try:
        main()
    except BaseException as exc:
        print(json.dumps({"status": "FAILED_CLOSED", "exceptionType": type(exc).__name__}), file=sys.stderr)
        raise SystemExit(1)
