#!/usr/bin/env python3
"""Validate the dormant one-time watchdog baseline-bootstrap admission."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping

try:
    from scripts import watchdog_evidence
except ModuleNotFoundError:  # direct ``python scripts/...`` execution
    import watchdog_evidence  # type: ignore


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "watchdog_initial_baseline_bootstrap_contract.json"
CONTRACT_SHA256 = "91cca04791b4f70ab76e43145dcb23ac374864b1f1cbe6d4a18c75286ad17ada"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class BaselineBootstrapError(ValueError):
    pass


def fail(message: str) -> None:
    raise BaselineBootstrapError(message)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("baseline bootstrap contract contains duplicate JSON fields")
        result[key] = value
    return result


def _canonical(document: Any) -> bytes:
    return (
        json.dumps(document, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def load_contract(path: Path = CONTRACT) -> Mapping[str, Any]:
    if not path.is_file() or path.is_symlink():
        fail("baseline bootstrap contract is not one regular file")
    raw = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    if hashlib.sha256(raw).hexdigest() != CONTRACT_SHA256:
        fail("baseline bootstrap contract digest is not reviewed")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaselineBootstrapError("baseline bootstrap contract is invalid JSON") from exc
    expected_root = {
        "schemaVersion", "contractId", "status", "immutableExternalControl",
        "admission", "prohibitions",
    }
    immutable = document.get("immutableExternalControl") if isinstance(document, dict) else None
    admission = document.get("admission") if isinstance(document, dict) else None
    prohibitions = document.get("prohibitions") if isinstance(document, dict) else None
    if (
        not isinstance(document, dict)
        or set(document) != expected_root
        or document.get("schemaVersion") != 1
        or document.get("contractId") != "paperdesk-watchdog-initial-baseline-bootstrap-v1"
        or document.get("status") != "dormant-pending-truthful-immutable-evidence"
        or immutable != {
            "repository": "Sethvirak/paperdesk-release-verifier",
            "workflowPath": ".github/workflows/initialize-watchdog-rollback-baseline.yml",
            "mergedAdmissionCommitSha": None,
        }
        or not isinstance(admission, dict)
        or admission.get("oneTimeOnly") is not True
        or admission.get("providerStateMustBeAbsent") is not True
        or admission.get("evidenceFile") != "evidence/watchdog-initial-rollback-baseline.json"
        or admission.get("evidenceChecksumFile")
        != "evidence/watchdog-initial-rollback-baseline.json.sha256"
        or admission.get("evidenceValidator")
        != "scripts.watchdog_evidence.validate_initial_baseline exact v2 projection"
        or admission.get("reviewEnvironment") != "paperdesk-watchdog-baseline"
        or not isinstance(prohibitions, dict)
        or set(prohibitions.values()) != {True}
    ):
        fail("baseline bootstrap dormant admission contract is not exact")
    worm = admission.get("requiredWorm")
    if worm != {
        "storageAccount": "mdspdbak2608089c4e",
        "container": "paperdesk-watchdog-evidence",
        "state": "Locked",
        "minimumRetentionDays": 90,
        "writeMode": "create-only-exact-byte-readback",
    }:
        fail("baseline bootstrap WORM boundary is not exact")
    return document


def validate_admission(
    contract: Mapping[str, Any],
    *,
    root: Path = ROOT,
    expected_merged_sha: str | None = None,
) -> Mapping[str, Any]:
    immutable = contract["immutableExternalControl"]
    merged = immutable.get("mergedAdmissionCommitSha")
    if merged is None:
        fail("baseline-bootstrap-activation-blocked-null-merged-sha")
    if not isinstance(merged, str) or not SHA40.fullmatch(merged):
        fail("baseline bootstrap merged admission SHA is invalid")
    if expected_merged_sha is None or merged != expected_merged_sha:
        fail("baseline bootstrap merged admission SHA is not the invoked workflow SHA")
    admission = contract["admission"]
    evidence = root / admission["evidenceFile"]
    checksum = root / admission["evidenceChecksumFile"]
    if (
        not evidence.is_file()
        or evidence.is_symlink()
        or not checksum.is_file()
        or checksum.is_symlink()
    ):
        fail("baseline bootstrap truthful evidence is absent")
    raw = evidence.read_bytes()
    checksum_text = checksum.read_text(encoding="ascii")
    digest = hashlib.sha256(raw).hexdigest()
    if checksum_text != f"{digest}  {evidence.name}\n" or not SHA256.fullmatch(digest):
        fail("baseline bootstrap evidence checksum is not exact")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaselineBootstrapError("baseline bootstrap evidence is invalid JSON") from exc
    if raw != _canonical(document):
        fail("baseline bootstrap evidence is not canonical JSON")
    try:
        watchdog_evidence.validate_initial_baseline(document)
    except watchdog_evidence.EvidenceError as exc:
        raise BaselineBootstrapError(str(exc)) from exc
    return {
        "schemaVersion": 1,
        "status": "admission-source-validated",
        "mergedAdmissionCommitSha": merged,
        "baselineReceiptSha256": digest,
        "evidenceFile": admission["evidenceFile"],
        "oneTimeOnly": True,
        "providerStateMustBeAbsent": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("validate-source", "validate-admission"))
    parser.add_argument("--expected-merged-sha", default="")
    args = parser.parse_args(argv)
    try:
        contract = load_contract()
        if args.mode == "validate-source":
            result = {
                "schemaVersion": 1,
                "status": "source-dormant",
                "mergedAdmissionCommitSha": None,
            }
        else:
            result = validate_admission(
                contract,
                expected_merged_sha=args.expected_merged_sha or None,
            )
    except (OSError, BaselineBootstrapError) as exc:
        print(f"watchdog baseline bootstrap error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
