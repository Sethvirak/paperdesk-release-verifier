"""Exact, callback-driven deletion-protection choreography for V2 bootstrap.

This module constructs no credentials and performs no I/O by itself.  Its caller
owns signed-plan validation, exhaustive inherited-lock inventory, exact assignment
policy, authorization admission, and durable mutation journaling.  In particular,
``restore=True`` is an instruction to the caller to admit only the exact reviewed
lock restoration after authorization expiry; it is not a general cleanup bypass.
"""

from __future__ import annotations

import copy
import datetime as dt
import json
from typing import Any, Callable, Mapping
import urllib.parse


ARM_ROOT = "https://management.azure.com"
LOCK_API_VERSION = "2016-09-01"
LOCK_CONVERGENCE_SECONDS = 120
LOCK_FINAL_OBSERVATION_SECONDS = 90
FINAL_OBSERVATION_ALIGNMENT_SLACK_SECONDS = 1
ASSIGNMENT_ABSENCE_SECONDS = 600
POLL_SECONDS = 2
SUBSCRIPTION = "9c4e0d0d-602f-4cde-84bd-337250e5b64c"

REVIEWED_CLEANUP_LOCKS = {
    "productionApp": {
        "resourceId": (
            f"/subscriptions/{SUBSCRIPTION}/resourceGroups/"
            "rg-master-data-structure-sea/providers/Microsoft.Web/sites/"
            "master-data-structure-sea-9c4e0d0d/providers/Microsoft.Authorization/locks/"
            "paperdesk-protect-app-delete"
        ),
        "properties": {
            "level": "CanNotDelete",
            "notes": (
                "PaperDesk production App Service deletion protection. Remove only "
                "for an approved delete, replacement, RBAC cleanup, or diagnostic cleanup."
            ),
        },
    },
    "rollback": {
        "resourceId": (
            f"/subscriptions/{SUBSCRIPTION}/resourceGroups/"
            "rg-paperdesk-rollback-sea-20260808/providers/"
            "Microsoft.Authorization/locks/paperdesk-rollback-cannot-delete"
        ),
        "properties": {
            "level": "CanNotDelete",
            "notes": (
                "Protects verified PaperDesk pre-migration attachment rollback copy; "
                "remove lock explicitly before authorized retirement."
            ),
        },
    },
    "signingVault": {
        "resourceId": (
            f"/subscriptions/{SUBSCRIPTION}/resourceGroups/"
            "rg-master-data-structure-sea/providers/Microsoft.KeyVault/vaults/"
            "kv-mds-sea-9c4e0d0d/providers/Microsoft.Authorization/locks/"
            "paperdesk-protect-keyvault-delete"
        ),
        "properties": {
            "level": "CanNotDelete",
            "notes": (
                "PaperDesk production Key Vault deletion protection. Remove only "
                "for an approved delete, replacement, RBAC cleanup, or diagnostic cleanup."
            ),
        },
    },
}

REVIEWED_OPERATION_LOCKS = {
    "removeOwnedOperatorControllerCanaryRole": "rollback",
    "removeOwnedOperatorFenceBootstrapRole": "rollback",
    "removeOwnedUploaderPackageRole": "rollback",
    "removeOwnedOperatorKeyReadRole": "signingVault",
    "removeLegacyWriterResultAssignment": "rollback",
    "removeLegacyReaderResultAssignment": "rollback",
    "retireLegacyPublisherResultReadAssignment": "rollback",
    "retireLegacyPublisherSitesReadAssignment": "productionApp",
}


def applicable_cleanup_lock(operation_id: str) -> str | None:
    return REVIEWED_OPERATION_LOCKS.get(operation_id)


def _reject(fail: Callable[[str], Any], message: str) -> None:
    fail(message)
    raise RuntimeError("failure callback returned: " + message)


def validate_lock_document(
    document: Mapping[str, Any],
    spec: Mapping[str, Any],
    fail: Callable[[str], Any],
) -> dict[str, Any]:
    """Validate all restorable properties, returning a stable source projection."""
    resource_id = spec.get("resourceId")
    raw_properties = document.get("properties") if isinstance(document, Mapping) else None
    properties = dict(raw_properties) if isinstance(raw_properties, Mapping) else None
    if properties is not None:
        owners = properties.pop("owners", None)
        if owners is not None and owners != []:
            _reject(fail, "cleanup deletion-protection lock has unreviewed owners")
    if (
        not isinstance(resource_id, str)
        or spec not in REVIEWED_CLEANUP_LOCKS.values()
        or not isinstance(document, Mapping)
        or str(document.get("id", "")).lower() != resource_id.lower()
        or document.get("name") != resource_id.rsplit("/", 1)[-1]
        or str(document.get("type", "")).lower()
        != "microsoft.authorization/locks"
        or properties != spec.get("properties")
    ):
        _reject(fail, "cleanup deletion-protection lock is not the exact reviewed projection")
    return {
        "resourceId": resource_id,
        "properties": copy.deepcopy(spec["properties"]),
    }


class CleanupLockGuard:
    """Suspend one exact lock solely around one exact assignment DELETE.

    Response objects are duck-typed ``.status/.body/.headers`` like bootstrap's
    ``_RestResponse``.  ``mutate_request`` accepts method/url plus body, expected,
    and restore keyword arguments and must reject unexpected HTTP responses.
    ``verify_lock_inventory`` must freshly reject every unreviewed effective lock.
    No mutation is retried, including restoration after ambiguous transport.
    """

    def __init__(
        self,
        *,
        read_request: Callable[..., Any],
        mutate_request: Callable[..., Any],
        verify_lock_inventory: Callable[[str, str], Any],
        clock: Callable[[], dt.datetime],
        sleep: Callable[[float], None],
        fail: Callable[[str], Any],
        require_live_authorization: Callable[[], Any],
        post_delete_read_request: Callable[..., Any] | None = None,
    ) -> None:
        self.read_request = read_request
        self.post_delete_read_request = post_delete_read_request or read_request
        self.mutate_request = mutate_request
        self.verify_lock_inventory = verify_lock_inventory
        self.clock = clock
        self.sleep = sleep
        self.fail = fail
        self.require_live_authorization = require_live_authorization
        self.assignment_was_present: bool | None = None

    def _now(self) -> dt.datetime:
        value = self.clock()
        if not isinstance(value, dt.datetime) or value.tzinfo is None:
            _reject(self.fail, "cleanup lock clock is not timezone-aware")
        return value.astimezone(dt.timezone.utc)

    def _document(self, response: Any, label: str) -> Mapping[str, Any]:
        try:
            value = json.loads(response.body)
        except (ValueError, TypeError, UnicodeError) as exc:
            _reject(self.fail, f"{label} returned invalid JSON: {type(exc).__name__}")
        if not isinstance(value, dict):
            _reject(self.fail, f"{label} did not return one object")
        return value

    def _read_state(
        self,
        url: str,
        validate: Callable[[Mapping[str, Any]], Any],
        label: str,
        *,
        read_request: Callable[..., Any] | None = None,
        deadline: dt.datetime | None = None,
    ) -> str:
        request_kwargs = {} if deadline is None else {"deadline": deadline}
        response = (read_request or self.read_request)(
            "GET", url, **request_kwargs
        )
        if response.status == 404:
            return "absent"
        if response.status != 200:
            _reject(self.fail, f"{label} returned unexpected HTTP status {response.status}")
        validate(self._document(response, label))
        return "exact"

    def _poll_state(
        self,
        url: str,
        desired: str,
        validate: Callable[[Mapping[str, Any]], Any],
        label: str,
        seconds: int,
        *,
        read_request: Callable[..., Any] | None = None,
        final_observation_seconds: int = 0,
    ) -> None:
        started = self._now()
        convergence_boundary = started + dt.timedelta(seconds=seconds)
        alignment_slack = (
            FINAL_OBSERVATION_ALIGNMENT_SLACK_SECONDS
            if final_observation_seconds > 0
            else 0
        )
        hard_deadline = convergence_boundary + dt.timedelta(
            seconds=alignment_slack + final_observation_seconds
        )
        previous = started
        # The attempt cap also bounds callers with a frozen or faulty test clock.
        for _ in range(seconds // POLL_SECONDS + 1):
            before = self._now()
            if before < previous or before > hard_deadline:
                _reject(self.fail, f"{label} exceeded its bounded readback window")
            if (
                final_observation_seconds > 0
                and before < convergence_boundary
                and before
                + dt.timedelta(seconds=final_observation_seconds)
                >= convergence_boundary
            ):
                # Do not spend the one final transport envelope on a request
                # that begins before the propagation boundary and can return a
                # stale response after it.  Start that final observation at the
                # boundary itself.
                self.sleep((convergence_boundary - before).total_seconds())
                aligned = self._now()
                if (
                    aligned < convergence_boundary
                    or aligned
                    > convergence_boundary
                    + dt.timedelta(seconds=alignment_slack)
                ):
                    _reject(
                        self.fail,
                        f"{label} settlement clock is invalid",
                    )
                before = aligned
            final_observation = (
                final_observation_seconds > 0
                and before >= convergence_boundary
            )
            request_deadline = (
                before + dt.timedelta(seconds=final_observation_seconds)
                if final_observation
                else convergence_boundary
            )
            if request_deadline > hard_deadline:
                _reject(self.fail, f"{label} exceeded its bounded readback window")
            state = self._read_state(
                url,
                validate,
                label,
                read_request=read_request,
                deadline=request_deadline,
            )
            after = self._now()
            if after < before or after > request_deadline:
                _reject(self.fail, f"{label} exceeded its bounded readback window")
            if state == desired:
                return
            # A caller may reserve one full transport envelope after the
            # propagation boundary.  The first observation completing at or
            # after that boundary is final; the extra envelope is read time,
            # never a longer convergence allowance.
            if final_observation or after >= convergence_boundary:
                break
            remaining = (convergence_boundary - after).total_seconds()
            if remaining <= 0:
                break
            previous = after
            self.sleep(min(POLL_SECONDS, remaining))
        _reject(self.fail, f"{label} did not converge to {desired}")

    def _restore_lock(self, url: str, spec: Mapping[str, Any]) -> None:
        validate = lambda document: validate_lock_document(document, spec, self.fail)
        state = self._read_state(
            url,
            validate,
            "cleanup lock restoration precondition",
            read_request=self.post_delete_read_request,
        )
        if state == "exact":
            return
        body = json.dumps(
            {"properties": spec["properties"]},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8") + b"\n"
        # Only this exact source-owned PUT carries the restoration exception.
        # On transport ambiguity, retain the exception even if a fresh read proves
        # restoration; never issue a second PUT or report the operation successful.
        try:
            self.mutate_request(
                "PUT", url, body=body, expected={200, 201}, restore=True
            )
        except BaseException:
            self._poll_state(
                url, "exact", validate, "cleanup lock ambiguous restoration",
                LOCK_CONVERGENCE_SECONDS,
                read_request=self.post_delete_read_request,
            )
            raise
        self._poll_state(
            url, "exact", validate, "cleanup lock restoration",
            LOCK_CONVERGENCE_SECONDS,
            read_request=self.post_delete_read_request,
        )

    def delete_assignment(
        self,
        *,
        operation_id: str,
        assignment_url: str,
        expected_assignment_projection: Mapping[str, Any],
        project_assignment: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    ) -> dict[str, Any]:
        lock_key = applicable_cleanup_lock(operation_id)
        if lock_key is None:
            _reject(self.fail, "assignment cleanup has no reviewed deletion-protection lock")
        spec = copy.deepcopy(REVIEWED_CLEANUP_LOCKS[lock_key])
        lock_url = ARM_ROOT + spec["resourceId"] + "?api-version=" + LOCK_API_VERSION
        expected = copy.deepcopy(dict(expected_assignment_projection))
        assignment_id = expected.get("id")
        parsed = urllib.parse.urlsplit(assignment_url)
        scope = spec["resourceId"].rsplit("/providers/Microsoft.Authorization/locks/", 1)[0]
        if (
            not isinstance(assignment_id, str)
            or not assignment_id.lower().startswith(scope.lower() + "/")
            or "/providers/microsoft.authorization/roleassignments/" not in assignment_id.lower()
            or parsed.scheme != "https"
            or parsed.netloc != "management.azure.com"
            or parsed.path != assignment_id
            or parsed.query != "api-version=2022-04-01"
            or parsed.fragment
        ):
            _reject(self.fail, "assignment cleanup URL is outside its exact reviewed lock scope")

        def validate_assignment(document: Mapping[str, Any]) -> None:
            if project_assignment(document) != expected:
                _reject(
                    self.fail,
                    "temporary assignment drifted: changed assignment no longer matches the source-authorized assignment",
                )

        self.verify_lock_inventory(operation_id, lock_key)
        validate_lock = lambda document: validate_lock_document(document, spec, self.fail)
        if self._read_state(lock_url, validate_lock, "cleanup lock precondition") != "exact":
            _reject(self.fail, "reviewed cleanup lock is absent before suspension")
        initial = self._read_state(
            assignment_url, validate_assignment, "assignment cleanup precondition"
        )
        self.assignment_was_present = initial == "exact"
        proof = {
            "resourceId": spec["resourceId"],
            "properties": copy.deepcopy(spec["properties"]),
            "restored": True,
            "assignmentAbsent": True,
        }
        if initial == "absent":
            return proof

        self.require_live_authorization()
        # Enter finally before the request: an ambiguous DELETE or a result-journal
        # failure can already have removed the lock despite raising an exception.
        try:
            self.mutate_request(
                "DELETE", lock_url, body=None, expected={200, 202, 204}, restore=False
            )
            self._poll_state(
                lock_url, "absent", validate_lock, "cleanup lock suspension",
                LOCK_CONVERGENCE_SECONDS,
                final_observation_seconds=LOCK_FINAL_OBSERVATION_SECONDS,
            )
            if self._read_state(
                assignment_url, validate_assignment, "assignment cleanup suspended precondition"
            ) != "exact":
                _reject(self.fail, "assignment disappeared after cleanup lock suspension")
            self.require_live_authorization()
            self.mutate_request(
                "DELETE", assignment_url, body=None, expected={200, 202, 204}, restore=False
            )
            self._poll_state(
                assignment_url, "absent", validate_assignment, "assignment cleanup absence",
                ASSIGNMENT_ABSENCE_SECONDS,
                read_request=self.post_delete_read_request,
                final_observation_seconds=LOCK_FINAL_OBSERVATION_SECONDS,
            )
        finally:
            self._restore_lock(lock_url, spec)
        return proof
