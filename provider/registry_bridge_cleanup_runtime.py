#!/usr/bin/env python3
"""Independent scheduled entry for the registry bridge cleanup watcher.

The checked-in contract is intentionally dormant.  ``run_once`` validates the
contract and returns before credential construction while the merged mutating
commit or any reviewed managed-identity coordinate is absent.  A later
activation commit must update the core, contract, deterministic package, and
retained bootstrap evidence together.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Callable, Mapping

def _load_packaged_sibling(name: str) -> Any:
    """Load one exact adjacent package member under ``python -I``.

    Isolated mode deliberately removes the script directory from ``sys.path``.
    The WebJob still needs its two reviewed sibling modules, so the fallback
    resolves only the regular files beside this entry and registers their fixed
    module names explicitly.  It never searches the current directory, user
    site-packages, or ``PYTHONPATH``.
    """

    path = Path(__file__).resolve().with_name(f"{name}.py")
    if not path.is_file() or path.is_symlink():
        raise ModuleNotFoundError(f"cleanup watcher package member is unavailable: {name}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ModuleNotFoundError(f"cleanup watcher package member cannot load: {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


try:
    from provider import registry_bridge_cleanup_azure as azure
    from provider import registry_bridge_cleanup_watcher as watcher
except ModuleNotFoundError as exc:  # deterministic isolated WebJob package
    if exc.name != "provider":
        raise
    watcher = _load_packaged_sibling("registry_bridge_cleanup_watcher")
    azure = _load_packaged_sibling("registry_bridge_cleanup_azure")


SITE_NAME = "paperdesk-registry-cleanup-watcher-9c4e0d0d"
CONTRACT_NAME = "registry_bridge_cleanup_contract.json"
INSTANCE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,256}$")


def _contract_path() -> Path:
    packaged = Path(__file__).resolve().with_name(CONTRACT_NAME)
    if packaged.is_file():
        return packaged
    return Path(__file__).resolve().parents[1] / "contracts" / CONTRACT_NAME


def _claimant(environment: Mapping[str, str]) -> str:
    site = str(environment.get("WEBSITE_SITE_NAME") or "")
    instance = str(environment.get("WEBSITE_INSTANCE_ID") or "")
    if site != SITE_NAME or not INSTANCE_RE.fullmatch(instance):
        raise watcher.CleanupContractError("cleanup-runtime-instance-invalid")
    return f"azure-webjob:{hashlib.sha256(instance.encode('utf-8')).hexdigest()[:32]}"


def _activation_gate(contract: Mapping[str, Any]) -> str:
    immutable = contract.get("immutableExternalControl")
    identities = contract.get("watcher", {}).get("managedIdentityClientIds")
    reviewed_sha = immutable.get("mergedMutatingCommitSha") if isinstance(immutable, dict) else None
    if reviewed_sha is None or watcher.MERGED_MUTATING_COMMIT_SHA is None:
        return "activation-blocked-null-merged-sha"
    if reviewed_sha != watcher.MERGED_MUTATING_COMMIT_SHA:
        raise watcher.CleanupContractError("cleanup-runtime-reviewed-sha-mismatch")
    if not isinstance(identities, dict) or any(value is None for value in identities.values()):
        return "activation-blocked-null-managed-identities"
    return "active"


def run_once(
    environment: Mapping[str, str] | None = None,
    *,
    credential_loader: Callable[..., Mapping[str, azure.AppServiceManagedIdentity]] = (
        azure.build_managed_identity_credentials
    ),
    boundary_factory: Callable[..., watcher.CleanupBoundary] = azure.AzureCleanupBoundary,
    contract_path: Path | None = None,
) -> dict[str, Any]:
    env = os.environ if environment is None else environment
    contract = watcher.load_contract(contract_path or _contract_path())
    gate = _activation_gate(contract)
    if gate != "active":
        return {
            "schemaVersion": 1,
            "status": "source-dormant",
            "reason": gate,
            "mergedMutatingCommitSha": None,
        }
    credentials = credential_loader(contract, env)
    boundary = boundary_factory(credentials)
    engine = watcher.CleanupWatcher.from_dormant_contract(boundary)
    return engine.sweep(_claimant(env))


def _schedule_seconds(contract_path: Path) -> int:
    contract = watcher.load_contract(contract_path)
    value = contract.get("watcher", {}).get("scheduleMaximumSeconds")
    if type(value) is not int or not 1 <= value <= 60:
        raise watcher.CleanupContractError("cleanup-runtime-schedule-invalid")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--once", action="store_true")
    mode.add_argument("--continuous", action="store_true")
    args = parser.parse_args(argv)
    path = _contract_path()
    try:
        if args.once:
            result = run_once(contract_path=path)
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 78 if result.get("status") == "source-dormant" else 0
        interval = _schedule_seconds(path)
        while True:
            result = run_once(contract_path=path)
            if result.get("status") == "source-dormant":
                print(json.dumps(result, sort_keys=True, separators=(",", ":")), file=sys.stderr)
                return 78
            time.sleep(interval)
    except watcher.CleanupContractError as exc:
        print(f"registry cleanup watcher error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
