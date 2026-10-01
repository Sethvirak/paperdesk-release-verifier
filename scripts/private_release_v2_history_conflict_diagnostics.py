"""Local-only, non-authorizing diagnostics for a rejected WebJob history pair.

No arbitrary provider values or extra field names enter the retained projection. This module
performs no I/O and is deliberately outside the bridge deployment package.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

FIELDS = (
    "web_job_name", "job_name", "web_job_id", "status",
    "trigger", "start_time", "end_time", "output_url",
)
STAGE = "bridge-webjob-history-list-detail-conflict"
READ_STAGES = frozenset({
    "history-boundary", "terminal-history", "final-history-census", "unspecified",
})
CLASSES = frozenset({
    "absent", "null", "boolean", "integer", "number", "string", "object",
    "array", "other", "nonterminal-status", "success-status", "failure-status",
    "other-string",
})
HASH = re.compile(r"[0-9a-f]{64}")
KEYS = {
    "schemaVersion", "stage", "readStage", "fieldOrder", "mismatchBits",
    "listValueClasses", "detailValueClasses", "listResponseSha256",
    "detailResponseSha256", "historyIdentitySha256", "stageIdentitySha256",
}


def _invalid() -> None:
    raise ValueError("WebJob history conflict diagnostic is invalid")


def _hash(value: Any) -> str:
    return hashlib.sha256(
        (json.dumps(value, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    ).hexdigest()


def _value_class(properties: Mapping[str, Any], field: str) -> str:
    if field not in properties:
        return "absent"
    value = properties[field]
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) is int:
        return "integer"
    if type(value) is float:
        return "number"
    if isinstance(value, str):
        if field == "status":
            if value in {"Initializing", "Running"}:
                return "nonterminal-status"
            if value == "Success":
                return "success-status"
            if value in {"Failed", "Aborted"}:
                return "failure-status"
            return "other-string"
        return "string"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, list):
        return "array"
    return "other"


def validate(value: Any) -> dict[str, Any]:
    """Rebuild an exact bounded projection; never retain arbitrary mappings."""
    if type(value) is not dict or set(value) != KEYS:
        _invalid()
    if (type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
            or value["stage"] != STAGE
            or type(value["readStage"]) is not str
            or value["readStage"] not in READ_STAGES
            or type(value["fieldOrder"]) is not list
            or any(type(item) is not str for item in value["fieldOrder"])
            or value["fieldOrder"] != list(FIELDS)):
        _invalid()
    bits = value["mismatchBits"]
    if type(bits) is not str or re.fullmatch(r"[01]{8}", bits) is None or "1" not in bits:
        _invalid()
    result = {
        "schemaVersion": 1, "stage": STAGE, "readStage": value["readStage"],
        "fieldOrder": list(FIELDS), "mismatchBits": bits,
    }
    for name in ("listValueClasses", "detailValueClasses"):
        classes = value[name]
        if (type(classes) is not list or len(classes) != len(FIELDS)
                or any(type(item) is not str or item not in CLASSES for item in classes)):
            _invalid()
        result[name] = list(classes)
    for name in ("listResponseSha256", "detailResponseSha256",
                 "historyIdentitySha256", "stageIdentitySha256"):
        if type(value[name]) is not str or HASH.fullmatch(value[name]) is None:
            _invalid()
        result[name] = value[name]
    expected_stage = _hash({
        "stage": STAGE, "readStage": result["readStage"],
        "historyIdentitySha256": result["historyIdentitySha256"],
    })
    if result["stageIdentitySha256"] != expected_stage:
        _invalid()
    if len(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()) > 2048:
        _invalid()
    return result


def build(*, list_properties: Mapping[str, Any], detail_run: Mapping[str, Any],
          list_response_sha256: str, detail_response_sha256: str,
          history_id: str, run_id: str, read_stage: Any) -> dict[str, Any]:
    """Describe the already-rejected exact comparison, without accepting it."""
    if (type(list_properties) is not dict or type(detail_run) is not dict
            or type(history_id) is not str or not 1 <= len(history_id) <= 8192
            or type(run_id) is not str or not 1 <= len(run_id) <= 256
            or re.fullmatch(r"[A-Za-z0-9._:-]+", run_id) is None
            or run_id in {".", ".."}
            or not history_id.lower().endswith("/" + run_id.lower())):
        _invalid()
    # The admission owner has already evaluated this same list-present/get
    # predicate. None versus an absent detail remains equal, exactly as before.
    bits = "".join(
        "1" if field in list_properties and list_properties[field] != detail_run.get(field)
        else "0" for field in FIELDS
    )
    selected_stage = read_stage if type(read_stage) is str and read_stage in READ_STAGES else "unspecified"
    identity = _hash({"historyId": history_id.lower(), "runId": run_id})
    return validate({
        "schemaVersion": 1, "stage": STAGE, "readStage": selected_stage,
        "fieldOrder": list(FIELDS), "mismatchBits": bits,
        "listValueClasses": [_value_class(list_properties, field) for field in FIELDS],
        "detailValueClasses": [_value_class(detail_run, field) for field in FIELDS],
        "listResponseSha256": list_response_sha256,
        "detailResponseSha256": detail_response_sha256,
        "historyIdentitySha256": identity,
        "stageIdentitySha256": _hash({
            "stage": STAGE, "readStage": selected_stage, "historyIdentitySha256": identity,
        }),
    })


def from_failure(error: BaseException | None, error_type: type) -> dict[str, Any] | None:
    """Follow only eight explicit causes, as the existing transport owner does."""
    seen: set[int] = set()
    for _ in range(8):
        if not isinstance(error, BaseException) or id(error) in seen:
            break
        seen.add(id(error))
        if isinstance(error, error_type):
            try:
                return validate(error.diagnostic)
            except (AttributeError, ValueError, TypeError):
                return None
        error = error.__cause__
    return None
