"""Pure, source-bound validation of the bootstrap WebJob canary evidence.

No network, credentials, or mutation code lives here. The bootstrap supplies its
canonical validation primitives so retained evidence has one shared contract.
"""
from __future__ import annotations

import datetime as dt
import re
from typing import Any, Callable, Mapping
import urllib.parse


def validate_canary_projection(
    body: Any, *, resources: Mapping[str, Any], prior: Mapping[str, Any],
    authorization: Mapping[str, Any], control_timing: Mapping[str, Any],
    fail: Callable[[str], Any], exact_keys: Callable[..., Any],
    parse_time: Callable[..., dt.datetime], canonical_json_bytes: Callable[..., bytes],
    sha256_bytes: Callable[[bytes], str], validate_sha256: Callable[..., str],
    max_final_history_seconds: int, azure_request_envelope_seconds: int,
    user_agent_prefix: str,
) -> None:
    _exact_keys = exact_keys
    _sha256 = validate_sha256
    required = {
        "resourceId",
        "cleanupKey",
        "selfCleaned",
        "initialStopped",
        "running",
        "triggerStatus",
        "triggerCorrelation",
        "preScmRestoreStopped",
        "finalHistoryCensus",
        "scmBasicAuthInitial",
        "scmBasicAuthPrePublicNetwork",
        "scmBasicAuthEnabled",
        "scmBasicAuthRestored",
        "scmBasicAuthSelfCleaned",
        "scmDisableMutationIssued",
        "publicNetworkAccessInitial",
        "publicNetworkAccessEnabled",
        "publicNetworkAccessEnableAsyncOperation",
        "publicNetworkAccessRestored",
        "publicNetworkAccessDisableAsyncOperation",
        "publicNetworkAccessSelfCleaned",
        "publicNetworkAccessDisableMutationIssued",
        "postRestoreStopMutationIssued",
        "triggerRequestedAt",
        "historyBoundary",
        "terminalHistory",
        "terminalHistoryObservedAt",
        "terminalHistoryEntriesSha256",
        "terminalHistoryResponseSha256",
        "pollAttempts",
        "stopped",
        "package",
        "settingsSha256",
        "bootstrapSelfTestControlSha256",
        "activationFence",
        "proofBoundary",
    }
    body = _exact_keys(body, required, "bridge WebJob canary projection")
    site_id = resources["bridgeSite"]["resourceId"]
    upload = prior.get("uploadVersionedBridgePackage", {}).get("projection", {})
    configure = prior.get(
        "configureBridgeExactVersionedPackageAndCriticalSettings", {}
    ).get("projection", {})
    fence = prior.get("createInitialIdleActivationFence", {}).get("projection", {})
    auth_start = parse_time(authorization["validity"]["notBefore"], "authorization notBefore")
    auth_end = parse_time(authorization["validity"]["expiresAt"], "authorization expiresAt")

    control_start = parse_time(control_timing["issuedAt"], "canary control issuedAt")
    control_end = parse_time(control_timing["expiresAt"], "canary control expiresAt")

    def site_state(value: Any, expected_state: str, label: str) -> Mapping[str, Any]:
        item = _exact_keys(
            value,
            {"attempts", "observedAt", "resourceId", "state", "projectionSha256"},
            label,
        )
        stamp = parse_time(item["observedAt"], f"{label} observedAt")
        expected_projection = {
            "id": site_id,
            "name": resources["bridgeSite"]["name"],
            "state": expected_state,
        }
        if (
            type(item["attempts"]) is not int
            or not 1 <= item["attempts"] <= 64
            or str(item["resourceId"]).lower() != site_id.lower()
            or item["state"] != expected_state
            or item["projectionSha256"]
            != sha256_bytes(canonical_json_bytes(expected_projection))
            or not auth_start <= stamp <= auth_end
        ):
            fail(f"{label} is not an exact site-state readback")
        return item

    initial = site_state(body["initialStopped"], "Stopped", "initial bridge state")
    running = site_state(body["running"], "Running", "running bridge state")
    stopped = site_state(body["stopped"], "Stopped", "final bridge state")
    pre_scm_stopped = site_state(
        body["preScmRestoreStopped"], "Stopped", "pre-census bridge state"
    )

    def scm_policy(
        value: Any, expected_allow: bool, label: str
    ) -> Mapping[str, Any]:
        item = _exact_keys(
            value,
            {"resourceId", "allow", "observedAt", "responseSha256"},
            label,
        )
        expected_id = site_id + "/basicPublishingCredentialsPolicies/scm"
        observed = parse_time(item["observedAt"], f"{label} observedAt")
        if (
            str(item["resourceId"]).lower() != expected_id.lower()
            or item["allow"] is not expected_allow
            or not auth_start <= observed <= auth_end
        ):
            fail(f"{label} is not exact")
        _sha256(item["responseSha256"], f"{label} response digest")
        return item

    scm_initial = scm_policy(
        body["scmBasicAuthInitial"], False, "initial SCM basic-auth policy"
    )
    scm_pre_public_network = scm_policy(
        body["scmBasicAuthPrePublicNetwork"],
        False,
        "pre-public-network SCM basic-auth policy",
    )
    scm_enabled = scm_policy(
        body["scmBasicAuthEnabled"], True, "enabled SCM basic-auth policy"
    )
    scm_restored = scm_policy(
        body["scmBasicAuthRestored"], False, "restored SCM basic-auth policy"
    )
    def public_network(
        value: Any,
        expected_access: str,
        expected_state: str | None,
        label: str,
    ) -> Mapping[str, Any]:
        item = _exact_keys(
            value,
            {
                "resourceId",
                "publicNetworkAccess",
                "state",
                "observedAt",
                "responseSha256",
            },
            label,
        )
        observed = parse_time(item["observedAt"], f"{label} observedAt")
        if (
            str(item["resourceId"]).lower() != site_id.lower()
            or item["publicNetworkAccess"] != expected_access
            or item["state"] not in {"Running", "Stopped"}
            or (
                expected_state is not None
                and item["state"] != expected_state
            )
            or not auth_start <= observed <= auth_end
        ):
            fail(f"{label} is not exact")
        _sha256(item["responseSha256"], f"{label} response digest")
        return item

    public_initial = public_network(
        body["publicNetworkAccessInitial"],
        "Disabled",
        "Stopped",
        "initial bridge public-network access",
    )
    public_enabled = public_network(
        body["publicNetworkAccessEnabled"],
        "Enabled",
        "Stopped",
        "enabled bridge public-network access",
    )
    public_restored = public_network(
        body["publicNetworkAccessRestored"],
        "Disabled",
        None,
        "restored bridge public-network access",
    )

    def arm_async_operation(value: Any, label: str) -> Mapping[str, Any]:
        item = _exact_keys(
            value,
            {
                "mode",
                "responseStatus",
                "monitorHeaderName",
                "monitorUrl",
                "pollAttempts",
                "terminalStatus",
                "terminalObservedAt",
                "terminalResponseSha256",
            },
            label,
        )
        if item["responseStatus"] == 200:
            if item != {
                "mode": "synchronous",
                "responseStatus": 200,
                "monitorHeaderName": None,
                "monitorUrl": None,
                "pollAttempts": 0,
                "terminalStatus": None,
                "terminalObservedAt": None,
                "terminalResponseSha256": None,
            }:
                fail(f"{label} synchronous evidence is not exact")
            return item
        if item["responseStatus"] != 202 or item["mode"] != "arm-async":
            fail(f"{label} response status is not exact")
        if item["monitorHeaderName"] != "Azure-AsyncOperation":
            fail(f"{label} monitor header name is not exact")
        monitor_url = item["monitorUrl"]
        if not isinstance(monitor_url, str):
            fail(f"{label} monitor URL is not exact")
        parsed = urllib.parse.urlsplit(monitor_url)
        try:
            monitor_port = parsed.port
        except ValueError:
            fail(f"{label} monitor URL is outside Azure ARM")
        if (
            parsed.scheme != "https"
            or (parsed.hostname or "").lower() != "management.azure.com"
            or monitor_port not in {None, 443}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or not parsed.path.startswith("/")
            or not parsed.query
            or len(monitor_url) > 8192
            or type(item["pollAttempts"]) is not int
            or not 1 <= item["pollAttempts"] <= 64
            or item["terminalStatus"] != "Succeeded"
        ):
            fail(f"{label} asynchronous evidence is not exact")
        terminal_at = parse_time(
            item["terminalObservedAt"], f"{label} terminal observedAt"
        )
        if not auth_start <= terminal_at <= auth_end:
            fail(f"{label} terminal observedAt is outside authorization")
        _sha256(
            item["terminalResponseSha256"], f"{label} terminal response digest"
        )
        return item

    public_enable_async = arm_async_operation(
        body["publicNetworkAccessEnableAsyncOperation"],
        "public-network enable operation",
    )
    public_disable_async = None
    if body["publicNetworkAccessDisableMutationIssued"] is True:
        public_disable_async = arm_async_operation(
            body["publicNetworkAccessDisableAsyncOperation"],
            "public-network disable operation",
        )
    elif body["publicNetworkAccessDisableAsyncOperation"] is not None:
        fail("public-network disable operation exists without a mutation")
    boundary = _exact_keys(
        body["historyBoundary"],
        {
            "jobMetadata",
            "observedAt",
            "entries",
            "entriesSha256",
            "responseSha256",
            "httpStatus",
            "boundaryState",
        },
        "WebJob history boundary",
    )
    if not isinstance(boundary["entries"], list):
        fail("WebJob history boundary entries are invalid")

    job = _exact_keys(
        boundary["jobMetadata"],
        {
            "observedAt",
            "resourceId",
            "name",
            "type",
            "runCommand",
            "latestRunPresent",
            "urlMetadata",
            "historyUrlMetadata",
            "settingsSha256",
            "responseSha256",
        },
        "triggered WebJob discovery metadata",
    )
    expected_job_id = (
        site_id
        + "/triggeredwebjobs/paperdesk-accepted-release-registry"
    )
    expected_job_path = (
        "/api/triggeredwebjobs/paperdesk-accepted-release-registry"
    )
    expected_job_host = resources["bridgeSite"]["name"] + ".scm.azurewebsites.net"

    def job_url(value: Any, expected_path: str, label: str) -> None:
        item = _exact_keys(
            value,
            {"scheme", "host", "path", "queryPresent"},
            label,
        )
        if (
            item["scheme"] != "https"
            or item["host"] != expected_job_host
            or item["path"] != expected_path
            or item["queryPresent"] is not False
        ):
            fail(f"{label} is not exact")

    job_url(job["urlMetadata"], expected_job_path, "triggered WebJob URL")
    job_url(
        job["historyUrlMetadata"],
        expected_job_path + "/history",
        "triggered WebJob history URL",
    )
    job_observed = parse_time(
        job["observedAt"], "triggered WebJob discovery observedAt"
    )
    if (
        str(job["resourceId"]).lower() != expected_job_id.lower()
        or job["name"] != "paperdesk-accepted-release-registry"
        or job["type"] != "triggered"
        or job["runCommand"] != "run.sh"
        or type(job["latestRunPresent"]) is not bool
        or job["settingsSha256"]
        != sha256_bytes(
            canonical_json_bytes(
                {"is_singleton": True, "stopping_wait_time": 30}
            )
        )
        or not auth_start <= job_observed <= auth_end
    ):
        fail("triggered WebJob discovery projection is not exact")
    _sha256(job["responseSha256"], "triggered WebJob response digest")

    def history_item(value: Any, label: str) -> Mapping[str, Any]:
        item = _exact_keys(
            value,
            {
                "historyId",
                "webJobsRunId",
                "triggerSha256",
                "status",
                "startedAt",
                "endedAt",
                "outputUrlMetadata",
            },
            label,
        )
        expected_prefix = (
            site_id + "/triggeredwebjobs/paperdesk-accepted-release-registry/history/"
        ).lower()
        if (
            not isinstance(item["historyId"], str)
            or not item["historyId"].lower().startswith(expected_prefix)
            or not isinstance(item["webJobsRunId"], str)
            or re.fullmatch(r"[A-Za-z0-9._:-]{1,256}", item["webJobsRunId"])
            is None
            or item["status"]
            not in {"Initializing", "Running", "Success", "Failed", "Aborted"}
        ):
            fail(f"{label} identity or state is invalid")
        started = parse_time(item["startedAt"], f"{label} startedAt")
        _sha256(item["triggerSha256"], f"{label} trigger digest")
        if item["status"] in {"Success", "Failed", "Aborted"}:
            ended = parse_time(item["endedAt"], f"{label} endedAt")
            output = _exact_keys(
                item["outputUrlMetadata"],
                {"scheme", "host", "pathSha256", "queryPresent"},
                f"{label} output URL metadata",
            )
            if (
                ended < started
                or output["scheme"] != "https"
                or not str(output["host"]).endswith(".scm.azurewebsites.net")
                or output["queryPresent"] is not False
            ):
                fail(f"{label} terminal/output projection is invalid")
            _sha256(output["pathSha256"], f"{label} output path digest")
        elif item["endedAt"] is not None or item["outputUrlMetadata"] is not None:
            fail(f"{label} nonterminal projection contains terminal fields")
        return item

    boundary_entries = [
        history_item(item, f"WebJob history boundary entry {index}")
        for index, item in enumerate(boundary["entries"])
    ]
    terminal = history_item(body["terminalHistory"], "fresh WebJob terminal history")
    correlation = _exact_keys(
        body["triggerCorrelation"],
        {"mode", "responseBodySha256", "responseObservedAt", "userAgent", "expectedHistoryTriggerSha256", "location"},
        "WebJob trigger correlation",
    )
    trigger_response_at = parse_time(
        correlation["responseObservedAt"], "WebJob trigger response observedAt"
    )
    user_agent = correlation["userAgent"]
    expected_agent_prefix = (
        user_agent_prefix + authorization["authorizationId"] + "."
    )
    if (
        not isinstance(user_agent, str)
        or not user_agent.startswith(expected_agent_prefix)
        or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            user_agent[len(expected_agent_prefix):],
        ) is None
    ):
        fail("WebJob trigger User-Agent is not one authorization-bound random token")
    expected_trigger_sha = sha256_bytes(("External - " + user_agent).encode("utf-8"))
    if (
        correlation["responseBodySha256"] != sha256_bytes(b"")
        or correlation["expectedHistoryTriggerSha256"] != expected_trigger_sha
        or terminal["triggerSha256"] != expected_trigger_sha
        or terminal["historyId"].lower()
        != (expected_job_id + "/history/" + terminal["webJobsRunId"]).lower()
    ):
        fail("WebJob trigger response and terminal history are not exact")
    if correlation["mode"] == "arm-200-empty-body-history-trigger":
        if correlation["location"] is not None:
            fail("ARM history correlation must not fabricate a Location")
    elif correlation["mode"] == "location-header-and-history-trigger":
        trigger_location = _exact_keys(
            correlation["location"],
            {"scheme", "host", "path", "runId", "queryPresent"},
            "WebJob trigger Location",
        )
        expected_trigger_prefix = (
            "/api/triggeredwebjobs/paperdesk-accepted-release-registry/history/"
        )
        if (
            trigger_location["scheme"] != "https"
            or trigger_location["host"] != expected_job_host
            or trigger_location["queryPresent"] is not False
            or trigger_location["runId"] != terminal["webJobsRunId"]
            or trigger_location["path"]
            != expected_trigger_prefix + terminal["webJobsRunId"]
        ):
            fail("WebJob trigger Location and terminal history are not exact")
    else:
        fail("WebJob trigger correlation mode is not exact")
    if len({item["historyId"] for item in boundary_entries}) != len(boundary_entries):
        fail("WebJob history boundary contains duplicate entries")
    trigger_at = parse_time(body["triggerRequestedAt"], "WebJob trigger requestedAt")
    boundary_at = parse_time(boundary["observedAt"], "WebJob history boundary observedAt")
    if (
        type(boundary["httpStatus"]) is not int
        or boundary["httpStatus"] not in {200, 404}
        or boundary["boundaryState"]
        != (
            "history-present"
            if boundary["httpStatus"] == 200
            else "pristine-history-absent"
        )
        or (
            boundary["httpStatus"] == 404
            and (
                job["latestRunPresent"] is not False
                or boundary_entries
            )
        )
        or (
            boundary["httpStatus"] == 200
            and bool(boundary_entries) is not job["latestRunPresent"]
        )
        or not job_observed <= boundary_at
    ):
        fail("WebJob pre-trigger history boundary is not exact")
    terminal_started = parse_time(terminal["startedAt"], "fresh WebJob start")
    terminal_ended = parse_time(terminal["endedAt"], "fresh WebJob end")
    terminal_observed = parse_time(
        body["terminalHistoryObservedAt"], "fresh WebJob observedAt"
    )
    combined_entries = sorted(
        [*boundary_entries, terminal], key=lambda item: item["historyId"]
    )
    census = _exact_keys(
        body["finalHistoryCensus"],
        {"observedAt", "entries", "entriesSha256", "responseSha256", "httpStatus", "boundaryState"},
        "final WebJob history census",
    )
    census_at = parse_time(census["observedAt"], "final history census observedAt")
    if (
        type(census["httpStatus"]) is not int
        or census["httpStatus"] != 200
        or census["boundaryState"] != "history-present"
        or census["entries"] != combined_entries
        or census["entriesSha256"] != sha256_bytes(canonical_json_bytes(combined_entries))
        or not (
            terminal_observed
            <= parse_time(pre_scm_stopped["observedAt"], "pre-census stopped observedAt")
            <= census_at
            <= parse_time(scm_restored["observedAt"], "restored SCM observedAt")
        )
        or census_at > terminal_observed + dt.timedelta(
            seconds=azure_request_envelope_seconds
            + max_final_history_seconds
        )
    ):
        fail("final WebJob history census is not exact or freshly stopped")
    _sha256(census["responseSha256"], "final WebJob history response digest")
    expected_package = {
        key: upload.get(key)
        for key in ("blob", "etag", "versionId", "url", "sha256", "size")
    }
    expected_fence = {
        key: fence.get(key) for key in ("url", "etag", "versionId", "sha256")
    }
    expected_boundary_text = (
        "terminal Success proves execution of the exact source/package-pinned "
        "bootstrap branch; HTTP health and literal stdout marker bytes were not observed"
    )
    if (
        body["resourceId"] != site_id
        or body["cleanupKey"] != "bounded-bridge-canary-start"
        or body["selfCleaned"] is not True
        or body["scmBasicAuthSelfCleaned"] is not True
        or type(body["scmDisableMutationIssued"]) is not bool
        or body["publicNetworkAccessSelfCleaned"] is not True
        or type(body["publicNetworkAccessDisableMutationIssued"]) is not bool
        or (
            public_enable_async["responseStatus"] == 202
            and not (
                parse_time(
                    public_initial["observedAt"],
                    "initial public-network observedAt",
                )
                <= parse_time(
                    public_enable_async["terminalObservedAt"],
                    "public-network enable terminal observedAt",
                )
                <= parse_time(
                    public_enabled["observedAt"],
                    "enabled public-network observedAt",
                )
            )
        )
        or (
            public_disable_async is not None
            and public_disable_async["responseStatus"] == 202
            and not (
                parse_time(
                    scm_restored["observedAt"],
                    "restored SCM policy observedAt",
                )
                <= parse_time(
                    public_disable_async["terminalObservedAt"],
                    "public-network disable terminal observedAt",
                )
                <= parse_time(
                    public_restored["observedAt"],
                    "restored public-network observedAt",
                )
            )
        )
        or type(body["postRestoreStopMutationIssued"]) is not bool
        or body["postRestoreStopMutationIssued"]
        is not (public_restored["state"] == "Running")
        or type(body["triggerStatus"]) is not int
        or body["triggerStatus"] != 200
        or boundary["entriesSha256"]
        != sha256_bytes(canonical_json_bytes(boundary_entries))
        or _sha256(boundary["responseSha256"], "WebJob boundary response digest")
        != boundary["responseSha256"]
        or terminal["historyId"]
        in {item["historyId"] for item in boundary_entries}
        or terminal["status"] != "Success"
        or body["terminalHistoryEntriesSha256"]
        != sha256_bytes(canonical_json_bytes(combined_entries))
        or _sha256(
            body["terminalHistoryResponseSha256"],
            "WebJob terminal response digest",
        )
        != body["terminalHistoryResponseSha256"]
        or type(body["pollAttempts"]) is not int
        or not 1 <= body["pollAttempts"] <= 180
        or body["package"] != expected_package
        or body["settingsSha256"] != configure.get("settingsSha256")
        or body["bootstrapSelfTestControlSha256"]
        != configure.get("bootstrapSelfTestControlSha256")
        or body["activationFence"] != expected_fence
        or body["proofBoundary"] != expected_boundary_text
        or not (
            auth_start
            <= parse_time(initial["observedAt"], "initial bridge observedAt")
            <= parse_time(
                scm_pre_public_network["observedAt"],
                "pre-public-network SCM policy observedAt",
            )
            <= parse_time(public_initial["observedAt"], "initial public-network observedAt")
            <= parse_time(public_enabled["observedAt"], "enabled public-network observedAt")
            <= parse_time(scm_initial["observedAt"], "initial SCM policy observedAt")
            <= parse_time(scm_enabled["observedAt"], "enabled SCM policy observedAt")
            <= parse_time(running["observedAt"], "running bridge observedAt")
            <= job_observed
            <= boundary_at
            <= trigger_at
            <= trigger_response_at
            <= terminal_observed
        )
        or terminal_started < trigger_at - dt.timedelta(seconds=5)
        or not control_start <= trigger_at < control_end
        or not control_start <= terminal_started <= terminal_ended < control_end
        or terminal_ended > terminal_observed + dt.timedelta(seconds=5)
        or parse_time(stopped["observedAt"], "stopped bridge observedAt")
        < terminal_observed
        or parse_time(scm_restored["observedAt"], "restored SCM policy observedAt")
        < terminal_observed
        or parse_time(public_restored["observedAt"], "restored public-network observedAt")
        < parse_time(scm_restored["observedAt"], "restored SCM policy observedAt")
        or parse_time(stopped["observedAt"], "stopped bridge observedAt")
        < parse_time(public_restored["observedAt"], "restored public-network observedAt")
        or parse_time(stopped["observedAt"], "stopped bridge observedAt")
        > auth_end
        or parse_time(scm_restored["observedAt"], "restored SCM policy observedAt")
        > auth_end
        or parse_time(public_restored["observedAt"], "restored public-network observedAt")
        > auth_end
    ):
        fail(
            "bridge terminal canary did not succeed, finally stop, and restore "
            "disabled SCM basic authentication and public-network access"
        )
