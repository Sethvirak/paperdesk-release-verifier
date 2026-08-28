#!/usr/bin/env python3
"""Evaluate the exact v2 provider state without holding a dispatch credential."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from provider.watchdog_state_provider import validate_state
from scripts import watchdog_contract


WATCHDOG_REPOSITORY = "Sethvirak/paperdesk-release-verifier"
WATCHDOG_WORKFLOW_REF = (
    f"{WATCHDOG_REPOSITORY}/.github/workflows/"
    "accepted-release-deadline-watchdog.yml@refs/heads/main"
)
BASELINE_WORKFLOW_REF = (
    f"{WATCHDOG_REPOSITORY}/.github/workflows/"
    "initialize-watchdog-rollback-baseline.yml@refs/heads/main"
)
BASELINE_ENVIRONMENT = "paperdesk-watchdog-baseline"
WATCHDOG_PROVIDER_HOST = "paperdesk-watchdog-state-9c4e0d0d.azurewebsites.net"
WATCHDOG_STATE_URL = f"https://{WATCHDOG_PROVIDER_HOST}/api/watchdog-state/v2"
MAX_STATE_BYTES = 65536
POSITIVE = re.compile(r"^[1-9][0-9]*$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ETAG = re.compile(r'^"[0-9a-f]{64}"$')
CANONICAL_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def fail(message: str) -> None:
    raise ValueError(message)


def canonical_json(document: Any) -> bytes:
    return watchdog_contract.canonical_json(document)


def parse_time(value: object, label: str) -> datetime:
    text = str(value or "")
    if not CANONICAL_UTC.fullmatch(text):
        fail(f"{label} must be canonical millisecond UTC")
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        fail(f"{label} is invalid: {exc}")
    if parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z") != text:
        fail(f"{label} is not canonical millisecond UTC")
    return parsed


def validate_https_url(value: str, expected_host: str | None, label: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        fail(f"{label} must be credential-free HTTPS on the configured exact host")
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or (expected_host is not None and parsed.hostname.lower() != expected_host)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port not in (None, 443)
        or parsed.netloc != parsed.hostname
        or not parsed.path.startswith("/")
        or "//" in parsed.path
        or len(value) > 2048
    ):
        fail(f"{label} must be credential-free HTTPS on the configured exact host")
    return value


def read_state(path: Path) -> tuple[dict[str, Any], str]:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or not 2 <= metadata.st_size <= MAX_STATE_BYTES
    ):
        fail("watchdog state must be one bounded regular non-symlink file")
    raw = path.read_bytes()
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"watchdog state is not valid UTF-8 JSON: {exc}")
    if not isinstance(document, dict) or canonical_json(document) != raw:
        fail("watchdog state must use exact canonical JSON bytes")
    return document, hashlib.sha256(raw).hexdigest()


def positive(value: object, label: str) -> str:
    if not isinstance(value, str) or not POSITIVE.fullmatch(value):
        fail(f"{label} must be a positive-integer string")
    return value


def full_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA40.fullmatch(value):
        fail(f"{label} must be a full lowercase commit SHA")
    return value


def digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        fail(f"{label} must be a lowercase SHA-256")
    return value


def create_only(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(canonical_json(document))


def decide(
    document: object,
    now: datetime,
    source_repository: str,
    run_id: str,
    run_attempt: str,
    state_sha256: str,
    state_etag: str,
    expected_baseline_receipt_sha256: str,
) -> dict[str, object]:
    machine = watchdog_contract.load_contract()
    validate_state(document, machine)
    if source_repository != machine["sourceRepository"]["repository"]:
        fail("watchdog source repository is not exact")
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        fail("watchdog observation clock must be UTC")
    generated = parse_time(document["generatedAt"], "watchdog state generatedAt")
    if generated > now + timedelta(minutes=5) or now - generated > timedelta(minutes=15):
        fail("watchdog state is outside the fresh 15-minute observation window")
    state_digest = digest(state_sha256, "watchdog state digest")
    if not isinstance(state_etag, str) or not ETAG.fullmatch(state_etag) or state_etag != f'"{state_digest}"':
        fail("watchdog state ETag must equal the quoted raw state digest")
    baseline = document["rollbackBaseline"]
    expected_baseline = digest(
        expected_baseline_receipt_sha256,
        "configured rollback baseline receipt digest",
    )
    if baseline["receiptSha256"] != expected_baseline:
        fail("watchdog rollback baseline differs from the independently reviewed digest")
    watchdog_run_id = positive(run_id, "watchdog run ID")
    watchdog_run_attempt = positive(run_attempt, "watchdog run attempt")
    pending = document["pendingCandidate"]
    if pending is None:
        return {
            "schemaVersion": 2,
            "receiptType": "watchdog-decision",
            "decision": "healthy-no-pending",
            "sourceRepository": source_repository,
            "candidateSha": None,
            "candidateRunId": None,
            "candidateRunAttempt": None,
            "expectedCurrentLiveSha": None,
            "watchdogRunId": watchdog_run_id,
            "watchdogRunAttempt": watchdog_run_attempt,
            "observedStateSha256": state_digest,
            "decidedAt": now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        }
    deadline = parse_time(pending["deadline"], "pending candidate deadline")
    guard = pending["dispatchGuard"]
    if pending["acceptedReceiptPresent"]:
        decision = "accepted"
    elif now <= deadline:
        decision = "awaiting-acceptance"
    elif guard["status"] == "available":
        decision = "dispatch-rollback"
    elif guard["status"] == "claimed":
        lease_expires = parse_time(guard["leaseExpiresAt"], "dispatch claim leaseExpiresAt")
        decision = (
            "rollback-claim-expired-unattempted"
            if now > lease_expires
            else "rollback-claim-active"
        )
    elif guard["status"] == "dispatching":
        decision = "rollback-dispatch-reconciliation-required"
    elif guard["status"] == "requested":
        decision = "rollback-workflow-observation-recorded"
    else:
        decision = "rollback-authorized"
    return {
        "schemaVersion": 2,
        "receiptType": "watchdog-decision",
        "decision": decision,
        "sourceRepository": source_repository,
        "candidateSha": pending["candidateSha"],
        "candidateRunId": pending["candidateRunId"],
        "candidateRunAttempt": pending["candidateRunAttempt"],
        "expectedCurrentLiveSha": pending["liveSha"],
        "watchdogRunId": watchdog_run_id,
        "watchdogRunAttempt": watchdog_run_attempt,
        "observedStateSha256": state_digest,
        "decidedAt": now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state")
    parser.add_argument("--state-url", required=True)
    parser.add_argument("--state-host", required=True)
    parser.add_argument("--state-etag")
    parser.add_argument("--runbook-url", required=True)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--watchdog-workflow-ref", required=True)
    parser.add_argument("--watchdog-workflow-sha", required=True)
    parser.add_argument("--control-checkout-sha", required=True)
    parser.add_argument("--watchdog-run-id", required=True)
    parser.add_argument("--watchdog-run-attempt", required=True)
    parser.add_argument("--baseline-receipt-sha256", required=True)
    parser.add_argument("--output")
    parser.add_argument("--now")
    parser.add_argument("--github-output")
    parser.add_argument("--validate-config-only", action="store_true")
    args = parser.parse_args()
    if args.state_host != WATCHDOG_PROVIDER_HOST or args.state_url != WATCHDOG_STATE_URL:
        fail("state URL and host must be the fixed dedicated watchdog provider")
    validate_https_url(args.state_url, args.state_host, "state URL")
    validate_https_url(args.runbook_url, None, "runbook URL")
    if args.source_repository != "Sethvirak/MasterDataStructure":
        fail("source repository is not exact")
    if args.watchdog_workflow_ref != WATCHDOG_WORKFLOW_REF:
        fail("watchdog workflow ref is not exact")
    workflow_sha = full_sha(args.watchdog_workflow_sha, "watchdog workflow SHA")
    checkout_sha = full_sha(args.control_checkout_sha, "control checkout SHA")
    if workflow_sha != checkout_sha:
        fail("watchdog control checkout must equal workflow source SHA")
    positive(args.watchdog_run_id, "watchdog run ID")
    positive(args.watchdog_run_attempt, "watchdog run attempt")
    digest(args.baseline_receipt_sha256, "baseline receipt digest")
    if args.validate_config_only:
        print("Watchdog v2 configuration and immutable identity boundary passed.")
        return 0
    if not args.state or not args.output or not args.state_etag:
        fail("state, state ETag, and output are required for deadline evaluation")
    document, state_sha256 = read_state(Path(args.state))
    now = parse_time(args.now, "now") if args.now else datetime.now(timezone.utc)
    receipt = decide(
        document,
        now,
        args.source_repository,
        args.watchdog_run_id,
        args.watchdog_run_attempt,
        state_sha256,
        args.state_etag,
        args.baseline_receipt_sha256,
    )
    create_only(Path(args.output), receipt)
    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(f"decision={receipt['decision']}\n")
            handle.write(f"state_sha256={receipt['observedStateSha256']}\n")
            if receipt["candidateSha"] is not None:
                handle.write(f"expected_current_live_sha={receipt['expectedCurrentLiveSha']}\n")
                guard = document["pendingCandidate"]["dispatchGuard"]
                if guard["claimId"] is not None:
                    handle.write(f"claim_id={guard['claimId']}\n")
    print(f"Watchdog decision: {receipt['decision']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"Watchdog validation failed: {error}")
