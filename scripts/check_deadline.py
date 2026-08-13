#!/usr/bin/env python3
"""Validate pending-candidate deadline state and emit a bounded decision receipt."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

SHA40 = re.compile(r"^[0-9a-f]{40}$")
POSITIVE = re.compile(r"^[1-9][0-9]*$")
CANONICAL_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def fail(message: str) -> None:
    raise ValueError(message)


def parse_time(value: object, label: str) -> datetime:
    text = str(value or "")
    if not CANONICAL_UTC.fullmatch(text):
        fail(f"{label} must be canonical UTC")
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        fail(f"{label} is invalid: {error}")
    rendered = parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if rendered != text:
        fail(f"{label} is not canonical UTC")
    return parsed


def validate_https_url(value: str, expected_host: str | None, label: str) -> None:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https" or not parsed.hostname
        or expected_host is not None and parsed.hostname.lower() != expected_host
        or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment
        or parsed.port not in (None, 443)
    ):
        fail(f"{label} must be credential-free HTTPS on the configured exact host")


def read_json(path: Path) -> object:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_size <= 0 or metadata.st_size > 65536:
        fail("watchdog state must be a bounded regular non-symlink file")
    return json.loads(path.read_text(encoding="utf-8"))


def positive(value: object, label: str) -> str:
    text = str(value or "")
    if not POSITIVE.fullmatch(text):
        fail(f"{label} must be a positive integer string")
    return text


def sha(value: object, label: str) -> str:
    text = str(value or "")
    if not SHA40.fullmatch(text):
        fail(f"{label} must be a full lowercase commit SHA")
    return text


def create_only(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(document, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def decide(document: object, now: datetime, source_repository: str, workflow_ref: str, run_id: str, run_attempt: str) -> dict[str, object]:
    if not isinstance(document, dict) or set(document) != {"schemaVersion", "generatedAt", "sourceRepository", "pendingCandidate"}:
        fail("watchdog state fields must be exact")
    if document.get("schemaVersion") != 1 or document.get("sourceRepository") != source_repository:
        fail("watchdog state identity is invalid")
    generated_at = parse_time(document.get("generatedAt"), "generatedAt")
    if generated_at > now + timedelta(minutes=5) or now - generated_at > timedelta(minutes=15):
        fail("watchdog state is outside the fresh observation window")
    pending = document.get("pendingCandidate")
    base = {
        "schemaVersion": 1,
        "watchdogWorkflowRef": workflow_ref,
        "watchdogRunId": positive(run_id, "watchdog run ID"),
        "watchdogRunAttempt": positive(run_attempt, "watchdog run attempt"),
        "sourceRepository": source_repository,
        "observedAt": now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "stateGeneratedAt": document["generatedAt"],
    }
    if pending is None:
        return {**base, "decision": "healthy-no-pending", "candidate": None, "rollback": None}
    expected_keys = {"candidateSha", "candidateRunId", "candidateRunAttempt", "completedAt", "deadline", "acceptedReceiptPresent", "liveSha", "rollback"}
    if not isinstance(pending, dict) or set(pending) != expected_keys or not isinstance(pending.get("acceptedReceiptPresent"), bool):
        fail("pending candidate fields must be exact")
    candidate_sha = sha(pending.get("candidateSha"), "candidate SHA")
    live_sha = sha(pending.get("liveSha"), "live SHA")
    completed = parse_time(pending.get("completedAt"), "candidate completedAt")
    deadline = parse_time(pending.get("deadline"), "candidate deadline")
    if deadline != completed + timedelta(hours=24):
        fail("candidate deadline must be exactly 24 hours after completion")
    rollback = pending.get("rollback")
    if not isinstance(rollback, dict) or set(rollback) != {"sourceSha", "sourceRunId", "acceptanceRunId"}:
        fail("rollback coordinates must be exact")
    normalized_rollback = {
        "sourceSha": sha(rollback.get("sourceSha"), "rollback source SHA"),
        "sourceRunId": positive(rollback.get("sourceRunId"), "rollback source run ID"),
        "acceptanceRunId": positive(rollback.get("acceptanceRunId"), "rollback acceptance run ID"),
    }
    candidate = {
        "sha": candidate_sha,
        "runId": positive(pending.get("candidateRunId"), "candidate run ID"),
        "runAttempt": positive(pending.get("candidateRunAttempt"), "candidate run attempt"),
        "completedAt": pending["completedAt"],
        "deadline": pending["deadline"],
        "liveSha": live_sha,
    }
    if pending["acceptedReceiptPresent"]:
        decision = "accepted"
    elif live_sha != candidate_sha:
        decision = "already-not-live"
    elif now <= deadline:
        decision = "awaiting-acceptance"
    else:
        decision = "dispatch-rollback"
    return {**base, "decision": decision, "candidate": candidate, "rollback": normalized_rollback}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state")
    parser.add_argument("--state-url", required=True)
    parser.add_argument("--state-host", required=True)
    parser.add_argument("--runbook-url", required=True)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--watchdog-workflow-ref", required=True)
    parser.add_argument("--watchdog-run-id", required=True)
    parser.add_argument("--watchdog-run-attempt", required=True)
    parser.add_argument("--output")
    parser.add_argument("--now")
    parser.add_argument("--github-output")
    parser.add_argument("--validate-config-only", action="store_true")
    args = parser.parse_args()
    if not REPOSITORY.fullmatch(args.source_repository):
        fail("source repository is invalid")
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", args.state_host) or args.state_host.startswith(".") or args.state_host.endswith("."):
        fail("state host is invalid")
    validate_https_url(args.state_url, args.state_host, "state URL")
    validate_https_url(args.runbook_url, None, "runbook URL")
    if args.validate_config_only:
        print("Watchdog configuration URL boundary passed.")
        return
    if not args.state or not args.output:
        fail("state and output are required for deadline evaluation")
    now = parse_time(args.now, "now") if args.now else datetime.now(timezone.utc)
    receipt = decide(read_json(Path(args.state)), now, args.source_repository, args.watchdog_workflow_ref, args.watchdog_run_id, args.watchdog_run_attempt)
    create_only(Path(args.output), receipt)
    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(f"decision={receipt['decision']}\n")
            if receipt["rollback"]:
                handle.write(f"rollback_source_sha={receipt['rollback']['sourceSha']}\n")
                handle.write(f"rollback_source_run_id={receipt['rollback']['sourceRunId']}\n")
                handle.write(f"rollback_acceptance_run_id={receipt['rollback']['acceptanceRunId']}\n")
    print(f"Watchdog decision: {receipt['decision']}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"Watchdog validation failed: {error}")
