#!/usr/bin/env python3
"""Fail-closed local bootstrap admission for PaperDesk private release V2.

The default command is a local, read-only description.  It never constructs an
Azure transport.  ``apply`` is intentionally difficult to reach: one external
canonical authorization must bind the reviewed PR head, protected merge, local
executor bytes, plan bytes, deterministic bridge package, fresh Azure
preflight, local Azure account, finite validity, and an exact confirmation
phrase.  A local use receipt is exclusively created before the first Azure
mutation and is never removed, including after a crash.

The executor is transport-injected.  The production transport uses only Azure
CLI and ``az rest``; tests use a fake transport and never contact Azure.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from collections import Counter
import copy
import dataclasses
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Mapping, Protocol, Sequence
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

try:
    from scripts import build_private_release_bridge_package as package_builder
except ModuleNotFoundError:  # direct ``python scripts/...`` execution
    import build_private_release_bridge_package as package_builder  # type: ignore


ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / "contracts" / "private_release_bootstrap_plan.json"
AUTHORIZATION_SCHEMA_PATH = (
    ROOT / "contracts" / "private_release_bootstrap_authorization_schema.json"
)
PREFLIGHT_SCHEMA_PATH = ROOT / "contracts" / "private_release_bootstrap_preflight_schema.json"
EVIDENCE_MODEL_PATH = ROOT / "contracts" / "private_release_bootstrap_evidence_model.json"
ACTIVATION_CONTRACT_PATH = ROOT / "contracts" / "private_release_mailbox_contract.json"
EXECUTOR_PATH = ROOT / "scripts" / "private_release_v2_bootstrap.py"
ALLOWED_SIGNERS_PATH = ROOT / "contracts" / "paperdesk_release_signing_allowed_signers"
REPOSITORY = "Sethvirak/paperdesk-release-verifier"
REMOTE_URLS = {
    "https://github.com/Sethvirak/paperdesk-release-verifier.git",
    "git@github.com:Sethvirak/paperdesk-release-verifier.git",
}
SUBSCRIPTION = "9c4e0d0d-602f-4cde-84bd-337250e5b64c"
TENANT = "aba83bd8-3e5c-4a87-9eb1-7bca070685b2"
SIGNING_PRINCIPAL = "paperdesk-release-signing-2026-08-30"
SIGNING_FINGERPRINT = "SHA256:nOONZLlhHx9b03fmAPkCqfhYzp0CFZuHfLPc1T0rfA4"
TRUSTED_REVIEWERS = {
    "jecebella168-cmyk": 316989178,
    "jecebella169-cmyk": 322025901,
}
MAX_AUTHORIZATION_SECONDS = 1800
MAX_PREFLIGHT_AGE_SECONDS = 300
MAX_READBACK_CONVERGENCE_SECONDS = 120
MAX_CANARY_CONVERGENCE_SECONDS = 300
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
TEMPORARY_ACCESS_INACCESSIBLE_OPERATIONS = frozenset(
    {
        "readBackExactSigningPublicJwk",
        "createInitialIdleActivationFence",
        "createControllerLeaseCanaryBlob",
        "exerciseControllerLeaseCanary",
        "removeControllerLeaseCanaryBlob",
    }
)
STORAGE_ACL_AND_RECOVERY_RESIDUAL_ACCEPTANCE = (
    "I accept that Azure Storage exposes no ETag for this account update, so the "
    "temporary uploader ipRules PATCH cannot atomically exclude an unrelated "
    "concurrent administrator change during its bounded pre-read/PATCH/post-read window. "
    "I also accept that process death after the PATCH, an ambiguous successful transport, "
    "or a local result-journal/fsync failure can leave the exact uploader /32 in place; "
    "execution and any later release must stop until a fresh live read proves the /32 and "
    "all related temporary roles absent, and manual cleanup may be required."
)


class BootstrapError(RuntimeError):
    """A source, authorization, preflight, or execution boundary failed closed."""


class OwnedTemporaryMutationError(BootstrapError):
    """A temporary mutation succeeded but its readback failed.

    The provisional proof is retained so the executor can compensate the
    exact executor-owned mutation before surfacing the failure.
    """

    def __init__(self, message: str, proof: Mapping[str, Any]) -> None:
        super().__init__(message)
        self.proof = dict(proof)


def fail(message: str) -> None:
    raise BootstrapError(message)


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BootstrapError("document is not canonical-JSON representable") from exc


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _duplicate_safe_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def load_json(path: Path, *, require_canonical: bool = False) -> tuple[Any, bytes]:
    if not path.is_file() or path.is_symlink():
        fail(f"not one regular file: {path}")
    raw = path.read_bytes()
    if not raw or len(raw) > 16 * 1024 * 1024:
        fail(f"JSON file size is invalid: {path}")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_duplicate_safe_pairs,
            parse_constant=lambda value: fail(f"invalid JSON constant: {value}"),
        )
    except UnicodeDecodeError as exc:
        raise BootstrapError(f"JSON is not UTF-8: {path}") from exc
    except json.JSONDecodeError as exc:
        raise BootstrapError(f"JSON is invalid: {path}") from exc
    if require_canonical and raw != canonical_json_bytes(value):
        fail(f"JSON is not exact canonical bytes: {path}")
    return value, raw


def _exact_keys(value: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} fields are not exact")
    return value


def _sha40(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA40.fullmatch(value):
        fail(f"{label} is not an exact commit SHA")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        fail(f"{label} is not an exact SHA-256")
    return value


def _guid(value: Any, label: str) -> str:
    if not isinstance(value, str) or not GUID.fullmatch(value):
        fail(f"{label} is not an exact GUID")
    return value


def parse_time(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"{label} is not an exact UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise BootstrapError(f"{label} is not an exact UTC timestamp") from exc
    if parsed.tzinfo != dt.timezone.utc:
        fail(f"{label} is not UTC")
    return parsed


def _mutation_target_allowed(
    operation_id: str,
    method: str,
    target_url: str,
    *,
    plan: Mapping[str, Any],
    authorization_id: str,
    source_sha: str,
    operation_projections: Mapping[str, Mapping[str, Any]] | None = None,
    operation_contexts: Mapping[str, Mapping[str, Any]] | None = None,
) -> bool:
    """Bind every journaled mutating request to one reviewed target family."""

    resources = {item["id"]: item for item in plan["resourceInventory"]}
    parsed = urllib.parse.urlsplit(target_url)
    host = parsed.hostname or ""
    path = parsed.path
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    production_name = resources["productionSite"]["name"].lower()
    accepted_name = resources["acceptedContainer"]["name"].lower()
    lowered_url = target_url.lower()
    # Bootstrap never writes production, accepted-release objects, mailbox
    # requests, or deployment release state.  The accepted WORM policy is the
    # sole accepted-container-name exception and is ARM control-plane only.
    production_rbac_operations = {
        "createExactRoleAssignments",
        "retireLegacyPublisherSitesReadAssignment",
    }
    if (
        production_name in lowered_url
        and operation_id not in production_rbac_operations
    ):
        return False
    accepted_control_plane_operations = {
        "createExactRoleAssignments",
        "extendAcceptedRetentionFrom30To91Days",
    }
    if (
        accepted_name in lowered_url
        and operation_id not in accepted_control_plane_operations
    ):
        return False
    if accepted_name in lowered_url and host != "management.azure.com":
        return False

    def arm(resource_id: str, *, suffix: str = "") -> bool:
        return (
            host == "management.azure.com"
            and path.lower() == (resource_id + suffix).lower()
            and set(query) == {"api-version"}
            and len(query["api-version"]) == 1
        )

    if operation_id == "claimAzureSingleUseAuthorization":
        claim_id = (
            f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Resources/"
            f"deployments/paperdesk-v2-bootstrap-{authorization_id}"
        )
        return method == "PUT" and arm(claim_id)
    if operation_id == "createMailboxResourceGroup":
        return method == "PUT" and arm(resources["mailboxResourceGroup"]["resourceId"])
    if operation_id in {"createPublisherApplication", "createPublisherServicePrincipal"}:
        expected_path = (
            "/v1.0/applications"
            if operation_id == "createPublisherApplication"
            else "/v1.0/servicePrincipals"
        )
        return host == "graph.microsoft.com" and method == "POST" and path == expected_path and not query
    if operation_id == "grantPublisherGraphApplicationReadAll":
        publisher = (operation_projections or {}).get(
            "createPublisherServicePrincipal", {}
        ).get("projection", {})
        publisher_id = publisher.get("id")
        return (
            isinstance(publisher_id, str)
            and GUID.fullmatch(publisher_id) is not None
            and host == "graph.microsoft.com"
            and method == "POST"
            and path
            == f"/v1.0/servicePrincipals/{publisher_id}/appRoleAssignments"
            and not query
        )
    if operation_id == "retireLegacyPublisherFic":
        context = (operation_contexts or {}).get(operation_id, {})
        fic_id = context.get("legacyFederatedCredentialId")
        legacy_application_id = plan["legacyPublisherRetirement"][
            "applicationObjectId"
        ]
        return (
            isinstance(fic_id, str)
            and GUID.fullmatch(fic_id) is not None
            and host == "graph.microsoft.com"
            and method == "DELETE"
            and path
            == (
                f"/beta/applications/{legacy_application_id}/"
                f"federatedIdentityCredentials/{fic_id}"
            )
            and not query
        )
    if operation_id == "createSolePublisherFicToSignedBootstrapSource":
        publisher = (operation_projections or {}).get(
            "createPublisherApplication", {}
        ).get("projection", {})
        publisher_id = publisher.get("id")
        return (
            isinstance(publisher_id, str)
            and GUID.fullmatch(publisher_id) is not None
            and host == "graph.microsoft.com"
            and method == "POST"
            and path
            == f"/beta/applications/{publisher_id}/federatedIdentityCredentials"
            and not query
        )
    assignment_ids = {
        "retireLegacyPublisherMutatorAssignment": plan["legacyPublisherRetirement"]["roleAssignmentResourceIds"][0],
        "retireLegacyPublisherSitesReadAssignment": plan["legacyPublisherRetirement"]["roleAssignmentResourceIds"][1],
        "retireLegacyPublisherResultReadAssignment": plan["legacyPublisherRetirement"]["roleAssignmentResourceIds"][2],
        "removeLegacyWriterResultAssignment": plan["legacyPublisherRetirement"]["legacyWriterResultAssignmentResourceId"],
        "removeLegacyReaderResultAssignment": plan["legacyPublisherRetirement"]["legacyReaderResultAssignmentResourceId"],
    }
    if operation_id in assignment_ids:
        return method == "DELETE" and arm(assignment_ids[operation_id])
    uami_target = {
        "createBridgeIdentity": "bridgeIdentity",
        "createSignerIdentity": "signerIdentity",
        "createProductionActivationIdentity": "productionActivationIdentity",
    }.get(operation_id)
    if uami_target is not None:
        return method == "PUT" and arm(resources[uami_target]["resourceId"])
    container_target = {
        "createPrivatePackageContainer": "packageContainer",
        "createPrivateControllerLockContainer": "controllerLockContainer",
        "createPrivateActivationFenceContainer": "activationFenceContainer",
    }.get(operation_id)
    if container_target is not None:
        return method == "PUT" and arm(resources[container_target]["resourceId"])
    if operation_id == "createSigningKeyVersion":
        return method == "PUT" and arm(resources["signingKey"]["resourceId"])
    if operation_id == "createCustomRoleDefinitions":
        valid = {
            str(item["id"]).lower()
            for item in _custom_role_definition_specs(plan).values()
        }
        resource_id = path
        return method == "PUT" and any(
            arm(item) and item.lower() == resource_id.lower() for item in valid
        )
    if operation_id == "createExactRoleAssignments":
        exact_assignment_paths = {
            (
                _resource_scope_from_plan(plan, item["scope"])
                + "/providers/Microsoft.Authorization/roleAssignments/"
                + item["assignmentId"]
            ).lower()
            for item in plan["roleMatrix"]
        }
        return (
            method == "PUT"
            and host == "management.azure.com"
            and path.lower() in exact_assignment_paths
            and set(query) == {"api-version"}
        )
    if operation_id in {
        "createStoppedPrivateBridge",
        "attachFiveUamisOnlyToBridge",
        "configureBridgeExactVersionedPackageAndCriticalSettings",
        "startBridgeForBoundedCanary",
    }:
        site_id = resources["bridgeSite"]["resourceId"]
        allowed_by_operation: dict[str, set[tuple[str, str]]] = {
            "createStoppedPrivateBridge": {
                ("PUT", site_id),
                ("PUT", site_id + "/basicPublishingCredentialsPolicies/ftp"),
                ("PUT", site_id + "/basicPublishingCredentialsPolicies/scm"),
                ("POST", site_id + "/stop"),
            },
            "attachFiveUamisOnlyToBridge": {("PATCH", site_id)},
            "configureBridgeExactVersionedPackageAndCriticalSettings": {
                ("PUT", site_id + "/config/appsettings")
            },
            "startBridgeForBoundedCanary": {
                ("POST", site_id + "/start"),
                (
                    "POST",
                    site_id
                    + "/triggeredwebjobs/paperdesk-accepted-release-registry/run",
                ),
                ("POST", site_id + "/stop"),
            },
        }
        allowed = allowed_by_operation[operation_id]
        return any(method == candidate_method and path.lower() == candidate_path.lower() for candidate_method, candidate_path in allowed) and set(query) == {"api-version"}
    if operation_id == "detachWriterAndReaderFromLegacyBridge":
        return method == "PATCH" and arm(resources["legacyBridgeSite"]["resourceId"])
    if operation_id in {"addOwnedUploaderIpv4Rule", "removeOwnedUploaderIpv4Rule"}:
        return method == "PATCH" and arm(resources["storageAccount"]["resourceId"])
    temp_role_ids = {
        "addOwnedUploaderPackageRole": (plan["temporaryAccess"]["roleDefinitionId"], plan["temporaryAccess"]["roleAssignmentId"]),
        "removeOwnedUploaderPackageRole": (plan["temporaryAccess"]["roleDefinitionId"], plan["temporaryAccess"]["roleAssignmentId"]),
        "addOwnedOperatorKeyReadRole": (plan["temporaryAccess"]["temporaryKeyReadRoleDefinitionId"], plan["temporaryAccess"]["temporaryKeyReadRoleAssignmentId"]),
        "removeOwnedOperatorKeyReadRole": (plan["temporaryAccess"]["temporaryKeyReadRoleDefinitionId"], plan["temporaryAccess"]["temporaryKeyReadRoleAssignmentId"]),
        "addOwnedOperatorFenceBootstrapRole": (plan["temporaryAccess"]["temporaryFenceRoleDefinitionId"], plan["temporaryAccess"]["temporaryFenceRoleAssignmentId"]),
        "removeOwnedOperatorFenceBootstrapRole": (plan["temporaryAccess"]["temporaryFenceRoleDefinitionId"], plan["temporaryAccess"]["temporaryFenceRoleAssignmentId"]),
        "addOwnedOperatorControllerCanaryRole": (plan["temporaryAccess"]["temporaryControllerRoleDefinitionId"], plan["temporaryAccess"]["temporaryControllerRoleAssignmentId"]),
        "removeOwnedOperatorControllerCanaryRole": (plan["temporaryAccess"]["temporaryControllerRoleDefinitionId"], plan["temporaryAccess"]["temporaryControllerRoleAssignmentId"]),
    }
    if operation_id in temp_role_ids:
        definition_id, assignment_id = temp_role_ids[operation_id]
        definition_path = f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/roleDefinitions/{definition_id}"
        is_add = operation_id.startswith("addOwned")
        return (
            (method == ("PUT" if is_add else "DELETE"))
            and host == "management.azure.com"
            and (
                path.lower() == definition_path.lower()
                or path.lower().endswith(
                    f"/providers/microsoft.authorization/roleassignments/{assignment_id.lower()}"
                )
            )
            and set(query) == {"api-version"}
        )
    if operation_id == "uploadVersionedBridgePackage":
        expected_path = (
            f"/{resources['packageContainer']['name']}/v2/control/{source_sha}/"
            "paperdesk-private-release-bridge.zip"
        )
        return method == "PUT" and host == "mdspdbak2608089c4e.blob.core.windows.net" and path == expected_path and not query
    if operation_id == "createInitialIdleActivationFence":
        return method == "PUT" and target_url == resources["activationFenceBlob"]["resourceId"]
    canary_path = (
        f"/{resources['controllerLockContainer']['name']}/"
        + plan["temporaryAccess"]["controllerCanaryBlobTemplate"].replace(
            "${authorization.authorizationId}", authorization_id
        )
    )
    if operation_id == "createControllerLeaseCanaryBlob":
        return method == "PUT" and host == "mdspdbak2608089c4e.blob.core.windows.net" and path == canary_path and not query
    if operation_id == "exerciseControllerLeaseCanary":
        return method == "PUT" and host == "mdspdbak2608089c4e.blob.core.windows.net" and path == canary_path and query == {"comp": ["lease"]}
    if operation_id == "removeControllerLeaseCanaryBlob":
        return method == "DELETE" and host == "mdspdbak2608089c4e.blob.core.windows.net" and path == canary_path and not query
    worm_target = {
        "lockPackageRetentionAt91Days": "packageContainer",
        "extendAcceptedRetentionFrom30To91Days": "acceptedContainer",
        "extendResultRetentionFrom30To91Days": "resultContainer",
    }.get(operation_id)
    if worm_target is not None:
        policy_id = resources[worm_target]["resourceId"] + "/immutabilityPolicies/default"
        return (method == "PUT" and arm(policy_id)) or (
            method == "POST" and arm(policy_id, suffix="/lock")
        )
    return False


def _normalized_mutation_target(method: str, target_url: str) -> str:
    """Return a comparison key for one already validated mutation target."""

    parsed = urllib.parse.urlsplit(target_url)
    query = urllib.parse.urlencode(
        sorted(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    )
    normalized = urllib.parse.urlunsplit(
        (
            parsed.scheme.lower(),
            (parsed.hostname or "").lower(),
            parsed.path.lower(),
            query,
            "",
        )
    )
    return f"{method.upper()} {normalized}"


def _forbidden_release_mutation_classes(
    method: str, target_url: str, plan: Mapping[str, Any]
) -> tuple[bool, bool]:
    """Classify forbidden production-runtime and accepted-blob writes.

    Exact Microsoft.Authorization children under the production site or
    accepted container are reviewed bootstrap RBAC mutations, not application
    release mutations.  Conversely, ARM site/config/deploy actions and Blob
    data-plane writes remain forbidden even when a caller relabels them with an
    otherwise permitted operation ID.
    """

    if method.upper() not in {"PUT", "POST", "PATCH", "DELETE"}:
        return False, False
    resources = {item["id"]: item for item in plan["resourceInventory"]}
    parsed = urllib.parse.urlsplit(target_url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower().rstrip("/")
    production_path = resources["productionSite"]["resourceId"].lower().rstrip(
        "/"
    )
    authorization_child = (
        production_path
        + "/providers/microsoft.authorization/roleassignments/"
    )
    production_site_write = (
        path == production_path
        or (
            path.startswith(production_path + "/")
            and not path.startswith(authorization_child)
        )
        or host
        in {
            resources["productionSite"]["name"].lower() + ".azurewebsites.net",
            resources["productionSite"]["name"].lower()
            + ".scm.azurewebsites.net",
        }
    )
    accepted_name = resources["acceptedContainer"]["name"].lower()
    accepted_blob_path = "/" + accepted_name
    accepted_blob_write = (
        host == "mdspdbak2608089c4e.blob.core.windows.net"
        and (path == accepted_blob_path or path.startswith(accepted_blob_path + "/"))
    )
    return production_site_write, accepted_blob_write


def _expected_terminal_mutation_targets(
    operation_id: str,
    *,
    plan: Mapping[str, Any],
    authorization_id: str,
    source_sha: str,
    operation_projections: Mapping[str, Mapping[str, Any]],
    operation_contexts: Mapping[str, Mapping[str, Any]],
) -> tuple[Counter[str], Counter[str]]:
    """Return required and optional exact write targets for one completed op.

    The terminal journal is not merely an allowlist.  Every source operation
    that selected ``apply-exact`` has a reviewed write cardinality.  Compound
    role, App Service, lease, and cleanup operations must therefore retain one
    successful result for every exact subcall and cannot hide an omitted member
    behind another allowed URL.  A WORM policy lock POST is the sole optional
    subcall: the provider returns either an already-Locked PUT projection or an
    Unlocked projection that requires exactly one subsequent lock POST.
    """

    resources = {item["id"]: item for item in plan["resourceInventory"]}
    context = operation_contexts.get(operation_id)
    if not isinstance(context, Mapping):
        fail(f"terminal journal lacks the exact context for {operation_id}")
    if context.get("executionDecision") == "adopt-exact":
        return Counter(), Counter()
    if context.get("executionDecision") != "apply-exact":
        fail(f"terminal journal operation decision is invalid: {operation_id}")

    def arm(resource_id: str, api_version: str, suffix: str = "") -> str:
        return (
            "https://management.azure.com"
            + resource_id
            + suffix
            + "?api-version="
            + api_version
        )

    def graph(path: str) -> str:
        return "https://graph.microsoft.com" + path

    def one(method: str, url: str) -> tuple[Counter[str], Counter[str]]:
        return Counter({_normalized_mutation_target(method, url): 1}), Counter()

    no_write_operations = {
        "adoptExistingRegistryWriterIdentity",
        "adoptExistingRegistryReaderIdentity",
        "readBackExactSigningPublicJwk",
    }
    if operation_id in no_write_operations:
        return Counter(), Counter()
    if operation_id == "claimAzureSingleUseAuthorization":
        claim_id = (
            f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Resources/"
            f"deployments/paperdesk-v2-bootstrap-{authorization_id}"
        )
        return one("PUT", arm(claim_id, "2022-09-01"))
    if operation_id == "createMailboxResourceGroup":
        return one(
            "PUT", arm(resources["mailboxResourceGroup"]["resourceId"], "2022-09-01")
        )
    if operation_id == "createPublisherApplication":
        return one("POST", graph("/v1.0/applications"))
    if operation_id == "createPublisherServicePrincipal":
        return one("POST", graph("/v1.0/servicePrincipals"))
    if operation_id == "grantPublisherGraphApplicationReadAll":
        service = operation_projections.get("createPublisherServicePrincipal", {}).get(
            "projection", {}
        )
        principal_id = _guid(service.get("id"), "journal publisher service principal")
        return one(
            "POST",
            graph(f"/v1.0/servicePrincipals/{principal_id}/appRoleAssignments"),
        )
    if operation_id == "retireLegacyPublisherFic":
        fic_id = _guid(
            context.get("legacyFederatedCredentialId"),
            "journal legacy federated credential",
        )
        app_id = plan["legacyPublisherRetirement"]["applicationObjectId"]
        return one(
            "DELETE",
            graph(
                f"/beta/applications/{app_id}/federatedIdentityCredentials/{fic_id}"
            ),
        )
    if operation_id == "createSolePublisherFicToSignedBootstrapSource":
        application = operation_projections.get("createPublisherApplication", {}).get(
            "projection", {}
        )
        object_id = _guid(application.get("id"), "journal publisher application")
        return one(
            "POST",
            graph(f"/beta/applications/{object_id}/federatedIdentityCredentials"),
        )

    legacy_assignments = {
        "retireLegacyPublisherMutatorAssignment": plan["legacyPublisherRetirement"][
            "roleAssignmentResourceIds"
        ][0],
        "retireLegacyPublisherSitesReadAssignment": plan["legacyPublisherRetirement"][
            "roleAssignmentResourceIds"
        ][1],
        "retireLegacyPublisherResultReadAssignment": plan["legacyPublisherRetirement"][
            "roleAssignmentResourceIds"
        ][2],
        "removeLegacyWriterResultAssignment": plan["legacyPublisherRetirement"][
            "legacyWriterResultAssignmentResourceId"
        ],
        "removeLegacyReaderResultAssignment": plan["legacyPublisherRetirement"][
            "legacyReaderResultAssignmentResourceId"
        ],
    }
    if operation_id in legacy_assignments:
        return one("DELETE", arm(legacy_assignments[operation_id], "2022-04-01"))

    uami_targets = {
        "createBridgeIdentity": "bridgeIdentity",
        "createSignerIdentity": "signerIdentity",
        "createProductionActivationIdentity": "productionActivationIdentity",
    }
    if operation_id in uami_targets:
        return one(
            "PUT",
            arm(resources[uami_targets[operation_id]]["resourceId"], "2023-01-31"),
        )
    container_targets = {
        "createPrivatePackageContainer": "packageContainer",
        "createPrivateControllerLockContainer": "controllerLockContainer",
        "createPrivateActivationFenceContainer": "activationFenceContainer",
    }
    if operation_id in container_targets:
        return one(
            "PUT",
            arm(
                resources[container_targets[operation_id]]["resourceId"],
                "2025-06-01",
            ),
        )
    if operation_id == "createSigningKeyVersion":
        return one("PUT", arm(resources["signingKey"]["resourceId"], "2023-07-01"))
    if operation_id == "createCustomRoleDefinitions":
        member_states = context.get("memberStates")
        if not isinstance(member_states, Mapping):
            fail("terminal custom-role journal lacks member states")
        required = Counter()
        for definition_id, state_name in member_states.items():
            if state_name == "absent":
                resource_id = (
                    f"/subscriptions/{SUBSCRIPTION}/providers/"
                    f"Microsoft.Authorization/roleDefinitions/{definition_id}"
                )
                required[_normalized_mutation_target(
                    "PUT", arm(resource_id, "2022-04-01")
                )] += 1
            elif state_name != "exact":
                fail("terminal custom-role member state is invalid")
        return required, Counter()
    if operation_id == "createExactRoleAssignments":
        member_states = context.get("memberStates")
        if not isinstance(member_states, Mapping):
            fail("terminal role-assignment journal lacks member states")
        required = Counter()
        for role in plan["roleMatrix"]:
            state_name = member_states.get(role["assignmentId"])
            if state_name == "absent":
                scope = _resource_scope_from_plan(plan, role["scope"])
                assignment_id = (
                    f"{scope}/providers/Microsoft.Authorization/roleAssignments/"
                    f"{role['assignmentId']}"
                )
                required[_normalized_mutation_target(
                    "PUT", arm(assignment_id, "2022-04-01")
                )] += 1
            elif state_name != "exact":
                fail("terminal role-assignment member state is invalid")
        return required, Counter()
    if operation_id == "createStoppedPrivateBridge":
        site_id = resources["bridgeSite"]["resourceId"]
        return Counter(
            _normalized_mutation_target(method, url)
            for method, url in (
                ("PUT", arm(site_id, "2025-03-01")),
                (
                    "PUT",
                    arm(
                        site_id + "/basicPublishingCredentialsPolicies/ftp",
                        "2025-03-01",
                    ),
                ),
                (
                    "PUT",
                    arm(
                        site_id + "/basicPublishingCredentialsPolicies/scm",
                        "2025-03-01",
                    ),
                ),
                ("POST", arm(site_id, "2025-03-01", "/stop")),
            )
        ), Counter()
    if operation_id == "attachFiveUamisOnlyToBridge":
        return one("PATCH", arm(resources["bridgeSite"]["resourceId"], "2025-03-01"))
    if operation_id == "detachWriterAndReaderFromLegacyBridge":
        return one(
            "PATCH", arm(resources["legacyBridgeSite"]["resourceId"], "2025-03-01")
        )
    if operation_id in {"addOwnedUploaderIpv4Rule", "removeOwnedUploaderIpv4Rule"}:
        return one("PATCH", arm(resources["storageAccount"]["resourceId"], "2025-06-01"))

    temp_role_ids = {
        "addOwnedUploaderPackageRole": (
            plan["temporaryAccess"]["roleDefinitionId"],
            plan["temporaryAccess"]["roleAssignmentId"],
            "packageContainer",
        ),
        "removeOwnedUploaderPackageRole": (
            plan["temporaryAccess"]["roleDefinitionId"],
            plan["temporaryAccess"]["roleAssignmentId"],
            "packageContainer",
        ),
        "addOwnedOperatorKeyReadRole": (
            plan["temporaryAccess"]["temporaryKeyReadRoleDefinitionId"],
            plan["temporaryAccess"]["temporaryKeyReadRoleAssignmentId"],
            "signingKey",
        ),
        "removeOwnedOperatorKeyReadRole": (
            plan["temporaryAccess"]["temporaryKeyReadRoleDefinitionId"],
            plan["temporaryAccess"]["temporaryKeyReadRoleAssignmentId"],
            "signingKey",
        ),
        "addOwnedOperatorFenceBootstrapRole": (
            plan["temporaryAccess"]["temporaryFenceRoleDefinitionId"],
            plan["temporaryAccess"]["temporaryFenceRoleAssignmentId"],
            "activationFenceContainer",
        ),
        "removeOwnedOperatorFenceBootstrapRole": (
            plan["temporaryAccess"]["temporaryFenceRoleDefinitionId"],
            plan["temporaryAccess"]["temporaryFenceRoleAssignmentId"],
            "activationFenceContainer",
        ),
        "addOwnedOperatorControllerCanaryRole": (
            plan["temporaryAccess"]["temporaryControllerRoleDefinitionId"],
            plan["temporaryAccess"]["temporaryControllerRoleAssignmentId"],
            "controllerLockContainer",
        ),
        "removeOwnedOperatorControllerCanaryRole": (
            plan["temporaryAccess"]["temporaryControllerRoleDefinitionId"],
            plan["temporaryAccess"]["temporaryControllerRoleAssignmentId"],
            "controllerLockContainer",
        ),
    }
    if operation_id in temp_role_ids:
        definition_id, assignment_id, scope_key = temp_role_ids[operation_id]
        definition_resource = (
            f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/"
            f"roleDefinitions/{definition_id}"
        )
        assignment_resource = (
            resources[scope_key]["resourceId"]
            + "/providers/Microsoft.Authorization/roleAssignments/"
            + assignment_id
        )
        method = "PUT" if operation_id.startswith("addOwned") else "DELETE"
        return Counter(
            {
                _normalized_mutation_target(
                    method, arm(definition_resource, "2022-04-01")
                ): 1,
                _normalized_mutation_target(
                    method, arm(assignment_resource, "2022-04-01")
                ): 1,
            }
        ), Counter()
    if operation_id == "uploadVersionedBridgePackage":
        blob = (
            f"https://mdspdbak2608089c4e.blob.core.windows.net/"
            f"{resources['packageContainer']['name']}/v2/control/{source_sha}/"
            "paperdesk-private-release-bridge.zip"
        )
        return one("PUT", blob)
    if operation_id == "createInitialIdleActivationFence":
        return one("PUT", resources["activationFenceBlob"]["resourceId"])
    canary_blob = plan["temporaryAccess"]["controllerCanaryBlobTemplate"].replace(
        "${authorization.authorizationId}", authorization_id
    )
    canary_url = (
        "https://mdspdbak2608089c4e.blob.core.windows.net/"
        f"{resources['controllerLockContainer']['name']}/{canary_blob}"
    )
    if operation_id == "createControllerLeaseCanaryBlob":
        return one("PUT", canary_url)
    if operation_id == "exerciseControllerLeaseCanary":
        return Counter(
            {
                _normalized_mutation_target("PUT", canary_url + "?comp=lease"): (
                    3 + int(plan["temporaryAccess"]["leaseRenewals"])
                )
            }
        ), Counter()
    if operation_id == "removeControllerLeaseCanaryBlob":
        return one("DELETE", canary_url)
    if operation_id == "configureBridgeExactVersionedPackageAndCriticalSettings":
        return one(
            "PUT",
            arm(
                resources["bridgeSite"]["resourceId"] + "/config/appsettings",
                "2025-03-01",
            ),
        )
    worm_targets = {
        "lockPackageRetentionAt91Days": "packageContainer",
        "extendAcceptedRetentionFrom30To91Days": "acceptedContainer",
        "extendResultRetentionFrom30To91Days": "resultContainer",
    }
    if operation_id in worm_targets:
        policy_id = (
            resources[worm_targets[operation_id]]["resourceId"]
            + "/immutabilityPolicies/default"
        )
        required, _ = one("PUT", arm(policy_id, "2025-06-01"))
        source_projection = operation_projections.get(operation_id, {}).get(
            "projection", {}
        )
        state_after_put = (
            source_projection.get("stateAfterPut")
            if isinstance(source_projection, Mapping)
            else None
        )
        lock_post_issued = (
            source_projection.get("lockPostIssued")
            if isinstance(source_projection, Mapping)
            else None
        )
        lock_target = _normalized_mutation_target(
            "POST", arm(policy_id, "2025-06-01", "/lock")
        )
        if state_after_put == "Unlocked" and lock_post_issued is True:
            required[lock_target] += 1
        elif state_after_put == "Locked" and lock_post_issued is False:
            pass
        else:
            fail(f"terminal WORM mutation path is not exact: {operation_id}")
        return required, Counter()
    if operation_id == "startBridgeForBoundedCanary":
        site_id = resources["bridgeSite"]["resourceId"]
        return Counter(
            _normalized_mutation_target(method, url)
            for method, url in (
                ("POST", arm(site_id, "2025-03-01", "/start")),
                (
                    "POST",
                    arm(
                        site_id,
                        "2025-05-01",
                        "/triggeredwebjobs/paperdesk-accepted-release-registry/run",
                    ),
                ),
                ("POST", arm(site_id, "2025-03-01", "/stop")),
            )
        ), Counter()
    fail(f"terminal journal has no exact write cardinality for {operation_id}")


def _validate_terminal_mutation_coverage(
    journal: Sequence[Mapping[str, Any]],
    *,
    plan: Mapping[str, Any],
    authorization_id: str,
    source_sha: str,
    operation_projections: Mapping[str, Mapping[str, Any]],
    operation_contexts: Mapping[str, Mapping[str, Any]],
) -> None:
    """Require every completed cloud write exactly once in the public journal."""

    results_by_operation: dict[str, Counter[str]] = {
        item["id"]: Counter()
        for item in plan["mutations"]
        if item["kind"] != "local-create-only-canonical-evidence"
    }
    for item in journal:
        if item.get("phase") != "result":
            continue
        status = item.get("status")
        if type(status) is not int or not 200 <= status <= 299:
            fail("terminal mutation journal contains a non-success result")
        results_by_operation[str(item["operationId"])][
            _normalized_mutation_target(str(item["method"]), str(item["targetUrl"]))
        ] += 1

    for operation_id, actual in results_by_operation.items():
        required, optional = _expected_terminal_mutation_targets(
            operation_id,
            plan=plan,
            authorization_id=authorization_id,
            source_sha=source_sha,
            operation_projections=operation_projections,
            operation_contexts=operation_contexts,
        )
        for target, count in required.items():
            if actual[target] != count:
                fail(
                    f"terminal mutation journal coverage drifted for {operation_id}"
                )
        extras = actual - required
        if any(extras[target] > optional[target] for target in extras):
            fail(f"terminal mutation journal contains an extra write for {operation_id}")
        missing_or_unexpected = set(actual) - set(required) - set(optional)
        if missing_or_unexpected:
            fail(f"terminal mutation journal contains an unknown write for {operation_id}")

    for operation_id in (
        "uploadVersionedBridgePackage",
        "createInitialIdleActivationFence",
    ):
        context = operation_contexts.get(operation_id, {})
        results = [
            item
            for item in journal
            if item.get("phase") == "result"
            and item.get("operationId") == operation_id
        ]
        if context.get("executionDecision") == "adopt-exact":
            if results:
                fail(f"adopted exact object has a current write: {operation_id}")
            continue
        projection = operation_projections.get(operation_id, {})
        headers = projection.get("headers")
        if (
            context.get("executionDecision") != "apply-exact"
            or len(results) != 1
            or results[0].get("status") != 201
            or not isinstance(headers, Mapping)
            or results[0].get("etag") != headers.get("etag")
            or results[0].get("versionId") != headers.get("versionId")
        ):
            fail(
                f"versioned create result is not cross-bound to exact readback: {operation_id}"
            )


def _expected_permanent_outcome(
    mutation: Mapping[str, Any], context: Mapping[str, Any]
) -> str:
    """Bind terminal outcome vocabulary to the authorized execution path."""

    decision = context.get("executionDecision")
    if decision == "adopt-exact":
        return "adopted-exact"
    if decision != "apply-exact":
        fail(f"terminal outcome lacks an exact decision for {mutation['id']}")
    kind = str(mutation["kind"])
    if kind.startswith(("delete-", "remove-", "temporary-remove")):
        return "deleted-exact"
    if kind.startswith("azure-ad-read"):
        return "read-back-exact"
    if kind.startswith(("create-", "azure-global-create", "azure-ad-create")):
        return "created"
    return "updated-exact"


def _sanitize_mutation_journal(
    records: Any,
    *,
    plan: Mapping[str, Any],
    authorization_id: str,
    authorization_sha256: str,
    source_sha: str,
    plan_sha256: str,
    package_sha256: str,
    operation_projections: Mapping[str, Mapping[str, Any]] | None = None,
    operation_contexts: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Validate the durable intent/result journal and retain nonsecret facts."""

    if not isinstance(records, list):
        fail("mutation journal is not one ordered list")
    mutation_by_id = {
        item["id"]: item
        for item in plan["mutations"]
        if item["kind"] != "local-create-only-canonical-evidence"
    }
    intents: dict[str, Mapping[str, Any]] = {}
    results: set[str] = set()
    sanitized: list[dict[str, Any]] = []
    for sequence, value in enumerate(records, 1):
        if not isinstance(value, dict) or value.get("sequence") != sequence:
            fail("mutation journal sequence is incomplete or reordered")
        phase = value.get("phase")
        expected_keys = {
            "schemaVersion",
            "phase",
            "operationId",
            "temporary",
            "method",
            "targetUrl",
            "requestBodySha256",
            "authorizationSha256",
            "sourceSha",
            "planSha256",
            "packageSha256",
            "recordedAt",
            "sequence",
        }
        if phase == "result":
            expected_keys |= {
                "intentId",
                "status",
                "responseBodySha256",
                "etag",
                "versionId",
            }
        if set(value) != expected_keys or value.get("schemaVersion") != 1:
            fail("mutation journal record fields are not exact")
        operation_id = value.get("operationId")
        operation = mutation_by_id.get(operation_id)
        if operation is None:
            fail("mutation journal references an unknown operation")
        if value.get("temporary") is not (operation.get("temporary") is True):
            fail("mutation journal temporary classification drifted")
        method = value.get("method")
        target_url = value.get("targetUrl")
        if method not in {"PUT", "POST", "PATCH", "DELETE"} or not isinstance(
            target_url, str
        ):
            fail("mutation journal method or target is invalid")
        parsed = urllib.parse.urlsplit(target_url)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.port not in {None, 443}
            or {key.lower() for key in query}.intersection(
                {"sig", "se", "sp", "sv", "spr", "srt", "ss", "token"}
            )
        ):
            fail("mutation journal contains a credential-bearing target")
        if not _mutation_target_allowed(
            str(operation_id),
            str(method),
            target_url,
            plan=plan,
            authorization_id=authorization_id,
            source_sha=source_sha,
            operation_projections=operation_projections,
            operation_contexts=operation_contexts,
        ):
            fail("mutation journal target is outside the source-owned operation contract")
        _sha256(value.get("requestBodySha256"), "mutation request body digest")
        if (
            value.get("authorizationSha256") != authorization_sha256
            or value.get("sourceSha") != source_sha
            or value.get("planSha256") != plan_sha256
            or value.get("packageSha256") != package_sha256
        ):
            fail("mutation journal source or authorization binding drifted")
        parse_time(value.get("recordedAt"), "mutation journal timestamp")
        intent_id: str | None = None
        status: int | None = None
        response_sha: str | None = None
        etag: str | None = None
        version_id: str | None = None
        if phase == "intent":
            intent_id = f"cloud-mutation-{sequence:04d}"
            intents[intent_id] = value
        elif phase == "result":
            intent_id = value.get("intentId")
            intent = intents.get(str(intent_id))
            if (
                intent is None
                or intent_id in results
                or value.get("operationId") != intent.get("operationId")
                or value.get("method") != intent.get("method")
                or value.get("targetUrl") != intent.get("targetUrl")
                or value.get("requestBodySha256") != intent.get("requestBodySha256")
                or value.get("temporary") is not intent.get("temporary")
            ):
                fail("mutation result is not bound to one prior intent")
            status = value.get("status")
            if type(status) is not int or not 200 <= status <= 599:
                fail("mutation result status is invalid")
            response_sha = _sha256(
                value.get("responseBodySha256"), "mutation response digest"
            )
            etag = value.get("etag")
            version_id = value.get("versionId")
            if etag is not None:
                _quoted_etag(etag, "mutation result ETag")
            if version_id is not None and (
                not isinstance(version_id, str) or not 1 <= len(version_id) <= 512
            ):
                fail("mutation result version ID is invalid")
            results.add(str(intent_id))
        else:
            fail("mutation journal phase is invalid")
        sanitized.append(
            {
                "sequence": sequence,
                "phase": phase,
                "intentId": intent_id,
                "operationId": operation_id,
                "temporary": value["temporary"],
                "method": method,
                "targetUrl": target_url,
                "requestBodySha256": value["requestBodySha256"],
                "status": status,
                "responseBodySha256": response_sha,
                "etag": etag,
                "versionId": version_id,
                "recordedAt": value["recordedAt"],
            }
        )
    unresolved = sorted(set(intents) - results)
    if unresolved:
        fail("mutation journal contains an intent without a result")
    if (operation_projections is None) is not (operation_contexts is None):
        fail("mutation journal semantic inputs must be supplied together")
    if operation_projections is not None and operation_contexts is not None:
        _validate_terminal_mutation_coverage(
            sanitized,
            plan=plan,
            authorization_id=authorization_id,
            source_sha=source_sha,
            operation_projections=operation_projections,
            operation_contexts=operation_contexts,
        )
    return sanitized


def _validate_sanitized_mutation_journal(
    value: Any,
    *,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    operation_projections: Mapping[str, Mapping[str, Any]] | None = None,
    operation_contexts: Mapping[str, Mapping[str, Any]] | None = None,
    execution_started_at: dt.datetime | None = None,
    execution_completed_at: dt.datetime | None = None,
) -> list[dict[str, Any]]:
    """Revalidate the public journal projection against exact source targets."""

    if not isinstance(value, list):
        fail("sanitized mutation journal is not one ordered list")
    mutation_by_id = {
        item["id"]: item
        for item in plan["mutations"]
        if item["kind"] != "local-create-only-canonical-evidence"
    }
    required = {
        "sequence",
        "phase",
        "intentId",
        "operationId",
        "temporary",
        "method",
        "targetUrl",
        "requestBodySha256",
        "status",
        "responseBodySha256",
        "etag",
        "versionId",
        "recordedAt",
    }
    intents: dict[str, Mapping[str, Any]] = {}
    intent_times: dict[str, dt.datetime] = {}
    completed: set[str] = set()
    not_before = parse_time(authorization["validity"]["notBefore"], "authorization notBefore")
    expires_at = parse_time(authorization["validity"]["expiresAt"], "authorization expiresAt")
    if (execution_started_at is None) is not (execution_completed_at is None):
        fail("sanitized journal execution bounds must be supplied together")
    if (
        execution_started_at is not None
        and execution_completed_at is not None
        and execution_completed_at < execution_started_at
    ):
        fail("sanitized journal execution bounds are reversed")
    canonical: list[dict[str, Any]] = []
    for sequence, raw in enumerate(value, 1):
        item = dict(_exact_keys(raw, required, "sanitized mutation journal record"))
        operation_id = item["operationId"]
        operation = mutation_by_id.get(operation_id)
        if (
            item["sequence"] != sequence
            or operation is None
            or item["temporary"] is not (operation.get("temporary") is True)
            or item["method"] not in {"PUT", "POST", "PATCH", "DELETE"}
            or not isinstance(item["targetUrl"], str)
            or not _mutation_target_allowed(
                operation_id,
                item["method"],
                item["targetUrl"],
                plan=plan,
                authorization_id=authorization["authorizationId"],
                source_sha=authorization["source"]["mergedMain"]["commitSha"],
                operation_projections=operation_projections,
                operation_contexts=operation_contexts,
            )
        ):
            fail("sanitized mutation journal target or operation classification drifted")
        _sha256(item["requestBodySha256"], "sanitized journal request digest")
        observed = parse_time(item["recordedAt"], "sanitized journal timestamp")
        if not not_before <= observed <= expires_at:
            fail("sanitized mutation journal timestamp is outside authorization")
        if (
            execution_started_at is not None
            and execution_completed_at is not None
            and not execution_started_at <= observed <= execution_completed_at
        ):
            fail("sanitized mutation journal timestamp is outside actual execution")
        intent_id = item["intentId"]
        if item["phase"] == "intent":
            expected_intent = f"cloud-mutation-{sequence:04d}"
            if (
                intent_id != expected_intent
                or item["status"] is not None
                or item["responseBodySha256"] is not None
                or item["etag"] is not None
                or item["versionId"] is not None
                or intent_id in intents
            ):
                fail("sanitized mutation intent is not exact")
            intents[intent_id] = item
            intent_times[intent_id] = observed
        elif item["phase"] == "result":
            intent = intents.get(str(intent_id))
            if (
                intent is None
                or intent_id in completed
                or any(
                    item[key] != intent[key]
                    for key in (
                        "operationId",
                        "temporary",
                        "method",
                        "targetUrl",
                        "requestBodySha256",
                    )
                )
                or type(item["status"]) is not int
                or not 200 <= item["status"] <= 599
            ):
                fail("sanitized mutation result is not bound to one exact intent")
            if observed < intent_times[str(intent_id)]:
                fail("sanitized mutation result predates its exact intent")
            _sha256(item["responseBodySha256"], "sanitized journal response digest")
            if item["etag"] is not None:
                _quoted_etag(item["etag"], "sanitized journal ETag")
            if item["versionId"] is not None and (
                not isinstance(item["versionId"], str)
                or not 1 <= len(item["versionId"]) <= 512
            ):
                fail("sanitized journal version ID is invalid")
            completed.add(str(intent_id))
        else:
            fail("sanitized mutation journal phase is invalid")
        canonical.append(item)
    if set(intents) != completed:
        fail("sanitized mutation journal has an unresolved intent")
    if (
        len(canonical) < 2
        or canonical[0]["phase"] != "intent"
        or canonical[0]["operationId"] != "claimAzureSingleUseAuthorization"
        or canonical[1]["phase"] != "result"
        or canonical[1]["intentId"] != canonical[0]["intentId"]
        or canonical[1]["status"] != 201
    ):
        fail("sanitized mutation journal lacks the first exact Azure claim create pair")
    if operation_projections is None or operation_contexts is None:
        fail("sanitized mutation journal lacks exact semantic inputs")
    _validate_terminal_mutation_coverage(
        canonical,
        plan=plan,
        authorization_id=authorization["authorizationId"],
        source_sha=authorization["source"]["mergedMain"]["commitSha"],
        operation_projections=operation_projections,
        operation_contexts=operation_contexts,
    )
    return canonical


def load_plan() -> tuple[dict[str, Any], str]:
    value, raw = load_json(PLAN_PATH)
    expected_root = {
        "schemaVersion",
        "planId",
        "status",
        "repository",
        "sourceRequirements",
        "azure",
        "resourceInventory",
        "roleMatrix",
        "mutations",
        "sourcePreparation",
        "orderingRules",
        "irreversibleMutationIds",
        "temporaryAccess",
        "legacyPublisherRetirement",
        "postconditions",
        "evidenceOutputs",
        "prohibitions",
    }
    plan = dict(_exact_keys(value, expected_root, "bootstrap plan"))
    if (
        plan["schemaVersion"] != 1
        or plan["planId"] != "paperdesk-private-release-v2-bootstrap-v1"
        or plan["status"] != "source-dormant"
        or plan["repository"] != REPOSITORY
    ):
        fail("bootstrap plan identity is not exact")

    azure = _exact_keys(
        plan["azure"],
        {
            "cloud",
            "subscriptionId",
            "tenantId",
            "location",
            "managementEndpoint",
            "graphEndpoint",
            "credentialBoundary",
        },
        "bootstrap plan Azure boundary",
    )
    if (
        azure["cloud"] != "AzureCloud"
        or azure["subscriptionId"] != SUBSCRIPTION
        or azure["tenantId"] != TENANT
        or azure["location"] != "southeastasia"
        or azure["managementEndpoint"] != "https://management.azure.com"
        or azure["graphEndpoint"] != "https://graph.microsoft.com"
        or azure["credentialBoundary"]
        != "azure-cli-current-account-after-one-shot-authorization-only"
    ):
        fail("bootstrap plan Azure boundary is not fixed")

    resources = plan["resourceInventory"]
    mutations = plan["mutations"]
    postconditions = plan["postconditions"]
    roles = plan["roleMatrix"]
    if not all(isinstance(item, dict) for item in resources):
        fail("bootstrap resources are invalid")
    if not all(isinstance(item, dict) for item in mutations):
        fail("bootstrap mutations are invalid")
    if not all(isinstance(item, dict) for item in postconditions):
        fail("bootstrap postconditions are invalid")
    if not all(isinstance(item, dict) for item in roles):
        fail("bootstrap role matrix is invalid")

    resource_ids = [item.get("id") for item in resources]
    mutation_ids = [item.get("id") for item in mutations]
    postcondition_ids = [item.get("id") for item in postconditions]
    role_names = [item.get("name") for item in roles]
    for values, label in (
        (resource_ids, "resource"),
        (mutation_ids, "mutation"),
        (postcondition_ids, "postcondition"),
        (role_names, "role"),
    ):
        if any(not isinstance(item, str) or not item for item in values):
            fail(f"bootstrap {label} IDs are invalid")
        if len(values) != len(set(values)):
            fail(f"bootstrap {label} IDs are not unique")

    expected_roles = {
        "publisherMailbox",
        "publisherBridgeController",
        "publisherControllerLock",
        "publisherAcceptedCustodyAudit",
        "publisherPackageCustodyAudit",
        "publisherResultCustodyAudit",
        "publisherAudit",
        "publisherWebIdentityAudit",
        "publisherKeyPostureAudit",
        "publisherUamiMetadataAudit",
        "publisherNetworkMetadataAudit",
        "publisherStorageMetadataAudit",
        "publisherProductionWebMetadataAudit",
        "bridgeMailboxResult",
        "bridgeActivationFence",
        "bridgeKeyRead",
        "writerRegistryAdd",
        "writerPackageAdd",
        "readerRegistryRead",
        "readerPackageRead",
        "signerKeySign",
        "productionActivation",
        "productionSystemPackageRead",
        "productionSystemAttachmentContributor",
        "productionSystemSecretsUser",
    }
    if set(role_names) != expected_roles or len(role_names) != 25:
        fail("bootstrap plan must define the exact 25 role records")

    irreversible = plan["irreversibleMutationIds"]
    expected_irreversible = {
        "extendAcceptedRetentionFrom30To91Days",
        "extendResultRetentionFrom30To91Days",
        "lockPackageRetentionAt91Days",
    }
    if set(irreversible) != expected_irreversible or len(irreversible) != 3:
        fail("irreversible mutation admission is not exact")
    for item in mutations:
        if item.get("id") in expected_irreversible:
            if item.get("irreversible") is not True or item.get("temporary") is not False:
                fail("irreversible mutation is not explicitly classified")
        elif item.get("irreversible") is not False:
            fail("unexpected irreversible mutation")

    def before(left: str, right: str) -> None:
        if mutation_ids.index(left) >= mutation_ids.index(right):
            fail(f"unsafe bootstrap ordering: {left} must precede {right}")

    if mutation_ids[0] != "claimAzureSingleUseAuthorization":
        fail("the Azure-global single-use claim is not the first cloud mutation")
    before("claimAzureSingleUseAuthorization", "createMailboxResourceGroup")
    before("retireLegacyPublisherFic", "createSolePublisherFicToSignedBootstrapSource")
    for legacy_assignment_operation in (
        "retireLegacyPublisherMutatorAssignment",
        "retireLegacyPublisherSitesReadAssignment",
        "retireLegacyPublisherResultReadAssignment",
        "removeLegacyWriterResultAssignment",
        "removeLegacyReaderResultAssignment",
    ):
        before(legacy_assignment_operation, "createSolePublisherFicToSignedBootstrapSource")
    before("uploadVersionedBridgePackage", "configureBridgeExactVersionedPackageAndCriticalSettings")
    before("createStoppedPrivateBridge", "createExactRoleAssignments")
    before("createExactRoleAssignments", "attachFiveUamisOnlyToBridge")
    before("attachFiveUamisOnlyToBridge", "detachWriterAndReaderFromLegacyBridge")
    before("addOwnedUploaderIpv4Rule", "createInitialIdleActivationFence")
    before("createControllerLeaseCanaryBlob", "exerciseControllerLeaseCanary")
    before("exerciseControllerLeaseCanary", "removeControllerLeaseCanaryBlob")
    before("createInitialIdleActivationFence", "removeOwnedUploaderIpv4Rule")
    before("removeControllerLeaseCanaryBlob", "removeOwnedOperatorControllerCanaryRole")
    before("configureBridgeExactVersionedPackageAndCriticalSettings", "startBridgeForBoundedCanary")
    before("removeOwnedUploaderPackageRole", "startBridgeForBoundedCanary")
    before("removeOwnedUploaderIpv4Rule", "startBridgeForBoundedCanary")
    before("removeOwnedOperatorKeyReadRole", "startBridgeForBoundedCanary")
    before("removeOwnedOperatorFenceBootstrapRole", "startBridgeForBoundedCanary")
    before("removeOwnedOperatorControllerCanaryRole", "startBridgeForBoundedCanary")
    before("configureBridgeExactVersionedPackageAndCriticalSettings", "lockPackageRetentionAt91Days")
    before("lockPackageRetentionAt91Days", "startBridgeForBoundedCanary")
    before("startBridgeForBoundedCanary", "extendAcceptedRetentionFrom30To91Days")
    before("startBridgeForBoundedCanary", "extendResultRetentionFrom30To91Days")
    before("extendAcceptedRetentionFrom30To91Days", "createSolePublisherFicToSignedBootstrapSource")
    before("extendResultRetentionFrom30To91Days", "createSolePublisherFicToSignedBootstrapSource")
    for legacy_operation in (
        "detachWriterAndReaderFromLegacyBridge",
        "removeLegacyWriterResultAssignment",
        "removeLegacyReaderResultAssignment",
        "retireLegacyPublisherFic",
        "retireLegacyPublisherMutatorAssignment",
        "retireLegacyPublisherSitesReadAssignment",
        "retireLegacyPublisherResultReadAssignment",
    ):
        before("extendAcceptedRetentionFrom30To91Days", legacy_operation)
        before("extendResultRetentionFrom30To91Days", legacy_operation)
    fic_index = mutation_ids.index("createSolePublisherFicToSignedBootstrapSource")
    later_azure = [
        item for item in mutations[fic_index + 1 :]
        if item.get("kind") != "local-create-only-canonical-evidence"
    ]
    if later_azure:
        fail("the sole new publisher FIC is not the final Azure mutation")
    if "setProductionRouteAll" in mutation_ids:
        fail("pre-S2 bootstrap must not mutate production routing")

    source_prep = _exact_keys(
        plan["sourcePreparation"],
        {
            "bridgePackageBuilder",
            "mode",
            "requiredAuthorizationBindings",
            "credentialConstructionForbidden",
        },
        "source preparation",
    )
    if (
        source_prep["bridgePackageBuilder"]
        != "scripts/build_private_release_bridge_package.py"
        or source_prep["mode"]
        != "local-create-only-deterministic-before-authorization"
        or source_prep["requiredAuthorizationBindings"]
        != ["bridgePackageSourceSha", "bridgePackageSha256", "bridgePackageSize"]
        or source_prep["credentialConstructionForbidden"] is not True
    ):
        fail("source preparation boundary is not exact")

    activation, _ = load_json(ACTIVATION_CONTRACT_PATH)
    if (
        not isinstance(activation, dict)
        or activation.get("status") != "source-dormant"
        or not isinstance(activation.get("activation"), dict)
        or not activation["activation"]
        or any(value is not None for value in activation["activation"].values())
    ):
        fail("committed activation contract is not source-dormant and all-null")

    if not AUTHORIZATION_SCHEMA_PATH.is_file():
        fail("machine-readable bootstrap authorization schema is absent")
    return plan, sha256_bytes(raw)


def build_package_artifact() -> tuple[dict[str, Any], bytes]:
    """Build the deterministic bridge package once and retain exact bytes.

    The authorization binds the descriptor, while successful terminal evidence
    binds a create-only upload and an in-memory exact-version readback.  Keeping
    the bytes beside the descriptor prevents a second build from silently
    becoming the evidence input.
    """

    with tempfile.TemporaryDirectory(prefix="paperdesk-v2-package-") as folder:
        target = Path(folder) / "paperdesk-private-release-bridge.zip"
        result = package_builder.build(target)
        raw = target.read_bytes()
        if result.get("packageSha256") != sha256_bytes(raw):
            fail("deterministic bridge package digest is inconsistent")
        descriptor = {
            "sha256": result["packageSha256"],
            "size": len(raw),
            "members": result["members"],
        }
        return descriptor, raw


def build_package_descriptor() -> dict[str, Any]:
    descriptor, _raw = build_package_artifact()
    return descriptor


def plan_coordinates(plan: Mapping[str, Any], plan_sha256: str) -> dict[str, Any]:
    package = build_package_descriptor()
    return {
        "schemaVersion": 1,
        "status": "read-only-no-Azure-transport-constructed",
        "repository": REPOSITORY,
        "executor": {
            "path": "scripts/private_release_v2_bootstrap.py",
            "sha256": sha256_bytes(EXECUTOR_PATH.read_bytes()),
        },
        "plan": {
            "path": "contracts/private_release_bootstrap_plan.json",
            "sha256": plan_sha256,
            "resourceIds": [item["id"] for item in plan["resourceInventory"]],
            "mutationIds": [item["id"] for item in plan["mutations"]],
            "irreversibleMutationIds": list(plan["irreversibleMutationIds"]),
            "postconditionIds": [item["id"] for item in plan["postconditions"]],
            "bridgePackageSourceSha": None,
            "bridgePackageSha256": package["sha256"],
            "bridgePackageSize": package["size"],
        },
        "azure": dict(plan["azure"]),
    }


@dataclasses.dataclass(frozen=True)
class ValidatedAuthorization:
    document: Mapping[str, Any]
    sha256: str
    receipt_directory: Path
    not_before: dt.datetime
    expires_at: dt.datetime


def _validate_authorization_document(
    value: Mapping[str, Any],
    raw: bytes,
    *,
    plan: Mapping[str, Any],
    plan_sha256: str,
    package: Mapping[str, Any],
    confirmation_phrase: str | None,
    now: dt.datetime | None,
) -> ValidatedAuthorization:
    root = dict(
        _exact_keys(
            value,
            {
                "schemaVersion",
                "authorizationType",
                "authorizationId",
                "repository",
                "source",
                "executor",
                "plan",
                "azure",
                "observedPreflight",
                "validity",
                "confirmation",
                "singleUse",
            },
            "bootstrap authorization",
        )
    )
    if (
        root["schemaVersion"] != 1
        or root["authorizationType"]
        != "paperdesk-private-release-v2-bootstrap-one-shot"
        or root["repository"] != REPOSITORY
    ):
        fail("bootstrap authorization identity is not exact")
    authorization_id = _guid(root["authorizationId"], "authorization ID")

    source = _exact_keys(root["source"], {"reviewedHead", "mergedMain"}, "source evidence")
    reviewed = _exact_keys(
        source["reviewedHead"],
        {
            "commitSha",
            "treeSha",
            "signatureVerified",
            "signingPrincipal",
            "signingKeyFingerprint",
            "pullRequestNumber",
            "pullRequestUrl",
            "reviewDecision",
            "requiredApprovals",
            "pushedAt",
            "reviews",
            "requiredCheck",
        },
        "reviewed head evidence",
    )
    reviewed_sha = _sha40(reviewed["commitSha"], "reviewed head SHA")
    reviewed_tree = _sha40(reviewed["treeSha"], "reviewed head tree")
    if (
        reviewed["signatureVerified"] is not True
        or reviewed["signingPrincipal"] != SIGNING_PRINCIPAL
        or reviewed["signingKeyFingerprint"] != SIGNING_FINGERPRINT
        or reviewed["reviewDecision"] != "APPROVED"
        or reviewed["requiredApprovals"] != 2
        or type(reviewed["pullRequestNumber"]) is not int
        or reviewed["pullRequestNumber"] <= 0
        or reviewed["pullRequestUrl"]
        != f"https://github.com/{REPOSITORY}/pull/{reviewed['pullRequestNumber']}"
    ):
        fail("reviewed head authorization evidence is not exact")
    pushed_at = parse_time(reviewed["pushedAt"], "reviewed head pushedAt")
    reviews = reviewed["reviews"]
    if not isinstance(reviews, list) or len(reviews) != 2:
        fail("two exact-head reviews are required")
    review_logins: set[str] = set()
    review_user_ids: set[int] = set()
    review_ids: set[int] = set()
    review_times: list[dt.datetime] = []
    for index, item in enumerate(reviews):
        review = _exact_keys(
            item,
            {"login", "userId", "reviewId", "state", "submittedAt", "commitSha"},
            f"review {index}",
        )
        if (
            review["login"] not in TRUSTED_REVIEWERS
            or review["userId"] != TRUSTED_REVIEWERS.get(review["login"])
            or type(review["reviewId"]) is not int
            or review["reviewId"] <= 0
            or review["state"] != "APPROVED"
            or review["commitSha"] != reviewed_sha
        ):
            fail("review is not exact-head approval evidence")
        submitted = parse_time(review["submittedAt"], "review submittedAt")
        if submitted <= pushed_at:
            fail("review predates or equals the reviewed head push")
        review_logins.add(review["login"])
        review_user_ids.add(review["userId"])
        review_ids.add(review["reviewId"])
        review_times.append(submitted)
    if (
        review_logins != set(TRUSTED_REVIEWERS)
        or len(review_user_ids) != 2
        or len(review_ids) != 2
    ):
        fail("reviewers are not the two distinct trusted accounts")

    required_check = _exact_keys(
        reviewed["requiredCheck"],
        {"name", "runId", "headSha", "conclusion", "completedAt"},
        "required check",
    )
    if (
        required_check["name"] != "test"
        or not isinstance(required_check["runId"], str)
        or not re.fullmatch(r"[1-9][0-9]*", required_check["runId"])
        or required_check["headSha"] != reviewed_sha
        or required_check["conclusion"] != "success"
    ):
        fail("required check is not bound to the exact reviewed head")
    check_completed = parse_time(required_check["completedAt"], "required check completedAt")
    if check_completed <= pushed_at:
        fail("required check predates or equals the reviewed head push")

    merged = _exact_keys(
        source["mergedMain"],
        {
            "commitSha",
            "treeSha",
            "soleParentSha",
            "treeEqualsReviewedHead",
            "githubVerificationVerified",
            "githubVerificationReason",
            "mergedPullRequestNumber",
            "mergedPullRequestUrl",
            "mergedAt",
            "verificationApiUrl",
            "verificationRetrievedAt",
        },
        "merged main evidence",
    )
    merged_sha = _sha40(merged["commitSha"], "merged main SHA")
    merged_tree = _sha40(merged["treeSha"], "merged main tree")
    _sha40(merged["soleParentSha"], "merged main sole parent")
    merged_at = parse_time(merged["mergedAt"], "mergedAt")
    verification_retrieved = parse_time(
        merged["verificationRetrievedAt"], "verificationRetrievedAt"
    )
    if (
        merged_sha == reviewed_sha
        or merged_tree != reviewed_tree
        or merged["treeEqualsReviewedHead"] is not True
        or merged["githubVerificationVerified"] is not True
        or merged["githubVerificationReason"] != "valid"
        or merged["mergedPullRequestNumber"] != reviewed["pullRequestNumber"]
        or merged["mergedPullRequestUrl"] != reviewed["pullRequestUrl"]
        or merged["verificationApiUrl"]
        != f"https://api.github.com/repos/{REPOSITORY}/commits/{merged_sha}"
        or merged_at < max([check_completed, *review_times])
        or verification_retrieved < merged_at
    ):
        fail("protected merged-main evidence is not exact")

    executor = _exact_keys(root["executor"], {"path", "sha256"}, "executor binding")
    if (
        executor["path"] != "scripts/private_release_v2_bootstrap.py"
        or executor["sha256"] != sha256_bytes(EXECUTOR_PATH.read_bytes())
    ):
        fail("authorization does not bind the exact executor bytes")

    authorized_plan = _exact_keys(
        root["plan"],
        {
            "path",
            "sha256",
            "resourceIds",
            "mutationIds",
            "irreversibleMutationIds",
            "postconditionIds",
            "bridgePackageSourceSha",
            "bridgePackageSha256",
            "bridgePackageSize",
        },
        "plan authorization",
    )
    expected_resources = [item["id"] for item in plan["resourceInventory"]]
    expected_mutations = [item["id"] for item in plan["mutations"]]
    expected_postconditions = [item["id"] for item in plan["postconditions"]]
    if (
        authorized_plan["path"] != "contracts/private_release_bootstrap_plan.json"
        or authorized_plan["sha256"] != plan_sha256
        or authorized_plan["resourceIds"] != expected_resources
        or authorized_plan["mutationIds"] != expected_mutations
        or authorized_plan["irreversibleMutationIds"]
        != plan["irreversibleMutationIds"]
        or authorized_plan["postconditionIds"] != expected_postconditions
        or authorized_plan["bridgePackageSourceSha"]
        != root["source"]["mergedMain"]["commitSha"]
        or authorized_plan["bridgePackageSha256"] != package["sha256"]
        or authorized_plan["bridgePackageSize"] != package["size"]
    ):
        fail("authorization does not bind the exact plan and package")

    azure = _exact_keys(
        root["azure"],
        {"cloud", "subscriptionId", "tenantId", "accountId", "accountObjectId", "accountType"},
        "Azure account authorization",
    )
    if (
        azure["cloud"] != "AzureCloud"
        or azure["subscriptionId"] != SUBSCRIPTION
        or azure["tenantId"] != TENANT
        or not isinstance(azure["accountId"], str)
        or not 3 <= len(azure["accountId"]) <= 256
        or azure["accountType"] not in {"user", "servicePrincipal"}
    ):
        fail("Azure account authorization is not exact")
    _guid(azure["accountObjectId"], "Azure account object ID")

    observed = _exact_keys(
        root["observedPreflight"],
        {"sha256", "observedAt", "maximumAgeSeconds"},
        "observed preflight",
    )
    _sha256(observed["sha256"], "observed preflight digest")
    observed_at = parse_time(observed["observedAt"], "observed preflight observedAt")
    if observed["maximumAgeSeconds"] != MAX_PREFLIGHT_AGE_SECONDS:
        fail("observed preflight maximum age is not exact")

    validity = _exact_keys(
        root["validity"],
        {"notBefore", "expiresAt", "maximumLifetimeSeconds"},
        "authorization validity",
    )
    not_before = parse_time(validity["notBefore"], "authorization notBefore")
    expires_at = parse_time(validity["expiresAt"], "authorization expiresAt")
    lifetime = (expires_at - not_before).total_seconds()
    if (
        validity["maximumLifetimeSeconds"] != MAX_AUTHORIZATION_SECONDS
        or not 0 < lifetime <= MAX_AUTHORIZATION_SECONDS
        or (now is not None and not not_before <= now <= expires_at)
    ):
        fail("authorization is outside its finite validity window")
    if now is not None and (
        observed_at > now
        or (now - observed_at).total_seconds() > MAX_PREFLIGHT_AGE_SECONDS
    ):
        fail("authorized preflight is stale or from the future")

    confirmation = _exact_keys(
        root["confirmation"], {"encoding", "phraseSha256"}, "confirmation binding"
    )
    if (
        confirmation["encoding"] != "utf-8-exact-no-newline"
        or _sha256(
            confirmation["phraseSha256"], "confirmation phrase digest"
        )
        != confirmation["phraseSha256"]
        or (
            confirmation_phrase is not None
            and (
                "\r" in confirmation_phrase
                or "\n" in confirmation_phrase
                or confirmation["phraseSha256"]
                != sha256_bytes(confirmation_phrase.encode("utf-8"))
            )
        )
    ):
        fail("confirmation phrase does not match the exact authorization")
    if (
        confirmation_phrase is not None
        and STORAGE_ACL_AND_RECOVERY_RESIDUAL_ACCEPTANCE not in confirmation_phrase
    ):
        fail("confirmation phrase does not explicitly accept the storage ACL and recovery residuals")

    single_use = _exact_keys(
        root["singleUse"],
        {"required", "receiptDirectory", "azureClaimResourceId"},
        "single-use binding",
    )
    receipt_directory = Path(single_use["receiptDirectory"])
    expected_name = f"paperdesk-private-release-v2-bootstrap-{authorization_id}"
    expected_claim = (
        f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Resources/deployments/"
        f"paperdesk-v2-bootstrap-{authorization_id}"
    )
    try:
        receipt_resolved = receipt_directory.resolve(strict=False)
        root_resolved = ROOT.resolve(strict=True)
    except OSError as exc:
        raise BootstrapError("single-use receipt path cannot be resolved") from exc
    if (
        single_use["required"] is not True
        or single_use["azureClaimResourceId"] != expected_claim
        or not receipt_directory.is_absolute()
        or receipt_resolved.name != expected_name
        or receipt_resolved == root_resolved
        or root_resolved in receipt_resolved.parents
    ):
        fail("single-use receipt directory is not exact authorization-specific external state")

    return ValidatedAuthorization(
        document=root,
        sha256=sha256_bytes(raw),
        receipt_directory=receipt_resolved,
        not_before=not_before,
        expires_at=expires_at,
    )


def validate_authorization_evidence(
    document: Mapping[str, Any],
    *,
    plan: Mapping[str, Any] | None = None,
    plan_sha256: str | None = None,
    package: Mapping[str, Any] | None = None,
) -> ValidatedAuthorization:
    """Pure immutable authorization-evidence validation for offline receipts.

    This replays every signature/review/check/merge, source, executor, plan,
    package, Azure, finite-validity, confirmation-digest and single-use-path
    invariant.  Only the live clock freshness check and plaintext confirmation
    comparison are intentionally omitted.
    """

    reviewed_plan, reviewed_plan_sha = load_plan()
    selected_plan = reviewed_plan if plan is None else plan
    selected_plan_sha = reviewed_plan_sha if plan_sha256 is None else plan_sha256
    if canonical_json_bytes(selected_plan) != canonical_json_bytes(reviewed_plan):
        fail("authorization evidence plan differs from the reviewed source plan")
    selected_package = build_package_descriptor() if package is None else package
    raw = canonical_json_bytes(document)
    if json.loads(raw.decode("utf-8")) != document:
        fail("authorization evidence is not canonical JSON")
    return _validate_authorization_document(
        document,
        raw,
        plan=selected_plan,
        plan_sha256=selected_plan_sha,
        package=selected_package,
        confirmation_phrase=None,
        now=None,
    )


def validate_authorization(
    path: Path,
    *,
    plan: Mapping[str, Any],
    plan_sha256: str,
    package: Mapping[str, Any],
    confirmation_phrase: str,
    now: dt.datetime,
) -> ValidatedAuthorization:
    value, raw = load_json(path, require_canonical=True)
    return _validate_authorization_document(
        value,
        raw,
        plan=plan,
        plan_sha256=plan_sha256,
        package=package,
        confirmation_phrase=confirmation_phrase,
        now=now,
    )


def validate_local_source(
    authorization: Mapping[str, Any],
    *,
    git_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    def git(*args: str, raw: bool = False) -> str:
        process = git_runner(
            ["git", *args],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        if process.returncode != 0:
            fail(f"local Git source inspection failed: {' '.join(args)}")
        return process.stdout if raw else process.stdout.strip()

    if git("status", "--porcelain=v1"):
        fail("local source worktree is not clean")
    if git("symbolic-ref", "--short", "HEAD") != "main":
        fail("local source is not checked out on main")
    if git("config", "--get", "remote.origin.url") not in REMOTE_URLS:
        fail("local source remote is not the exact verifier repository")
    head = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    origin = git("rev-parse", "refs/remotes/origin/main")
    parent_line = git("rev-list", "--parents", "-n", "1", "HEAD").split()
    reviewed = authorization["source"]["reviewedHead"]
    reviewed_sha = reviewed["commitSha"]
    if not ALLOWED_SIGNERS_PATH.is_file() or ALLOWED_SIGNERS_PATH.is_symlink():
        fail("local allowed-signers file is absent or unsafe")
    expected_signer_line = (
        f"{SIGNING_PRINCIPAL} ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIE162bAJ75rbh+Khk8orN39YWhNe/dlRC08rZHzPh+Dk\n"
    )
    if ALLOWED_SIGNERS_PATH.read_text(encoding="utf-8") != expected_signer_line:
        fail("local allowed-signers file drifted")
    git("cat-file", "-e", f"{reviewed_sha}^{{commit}}")
    signature_args = (
        "-c",
        "gpg.format=ssh",
        "-c",
        f"gpg.ssh.allowedSignersFile={ALLOWED_SIGNERS_PATH}",
    )
    git(*signature_args, "verify-commit", reviewed_sha)
    signature = git(
        *signature_args,
        "log",
        "-1",
        "--format=%G?%x00%GS%x00%GK",
        reviewed_sha,
        raw=True,
    ).rstrip("\r\n")
    if signature != f"G\x00{SIGNING_PRINCIPAL}\x00{SIGNING_FINGERPRINT}":
        fail("local reviewed head is not signed by the exact allowed principal and key")
    merged = authorization["source"]["mergedMain"]
    if (
        head != merged["commitSha"]
        or origin != head
        or tree != merged["treeSha"]
        or len(parent_line) != 2
        or parent_line[1] != merged["soleParentSha"]
    ):
        fail("local source is not the exact authorized protected merge")
    return {
        "repository": REPOSITORY,
        "headSha": head,
        "treeSha": tree,
        "soleParentSha": parent_line[1],
        "originMainSha": origin,
        "reviewedHeadSha": reviewed_sha,
        "reviewedHeadSigningPrincipal": SIGNING_PRINCIPAL,
        "reviewedHeadSigningKeyFingerprint": SIGNING_FINGERPRINT,
    }


def validate_local_account(
    account: Mapping[str, Any], authorization: Mapping[str, Any]
) -> dict[str, Any]:
    expected = authorization["azure"]
    projection = {
        "cloud": account.get("cloud"),
        "subscriptionId": str(account.get("subscriptionId", "")),
        "tenantId": str(account.get("tenantId", "")),
        "accountId": str(account.get("accountId", "")),
        "accountObjectId": str(account.get("accountObjectId", "")),
        "accountType": str(account.get("accountType", "")),
    }
    if projection != expected:
        fail("local Azure account is not the exact authorized account")
    return projection


def _preflight_url_allowed(method: str, url: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.port not in (None, 443)
    ):
        return False
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if any(key.lower() in {"sig", "se", "sp", "sv", "spr", "srt", "ss"} for key in query):
        return False
    host = (parsed.hostname or "").lower()
    subscription_prefix = f"/subscriptions/{SUBSCRIPTION}/"
    if host == "management.azure.com":
        if not parsed.path.lower().startswith(subscription_prefix.lower()):
            return False
        if method == "GET":
            return "api-version" in query
        return (
            method == "POST"
            and parsed.path.lower().endswith("/config/appsettings/list")
            and query == {"api-version": ["2025-03-01"]}
        )
    if host == "graph.microsoft.com":
        return method == "GET" and (
            parsed.path.startswith("/v1.0/") or parsed.path.startswith("/beta/")
        )
    if host == "mdspdbak2608089c4e.blob.core.windows.net":
        return method == "GET" and parsed.path.startswith(
            (
                "/paperdesk-deployment-packages/",
                "/paperdesk-release-activation-control/",
                "/paperdesk-release-controller-lock/",
            )
        )
    if host == "kv-mds-sea-9c4e0d0d.vault.azure.net":
        return method == "GET" and parsed.path.startswith(
            "/keys/paperdesk-release-result-signing/"
        )
    return False


def _production_boundary_requests(plan: Mapping[str, Any]) -> list[dict[str, str]]:
    """Return the five fixed read-only production-boundary requests.

    This list is part of the reviewed source policy.  The bootstrap never
    observes the accepted-release container; that later observation remains a
    post-S2 publisher gate.
    """

    resources = {item["id"]: item for item in plan["resourceInventory"]}
    site = resources["productionSite"]
    resource_id = site["resourceId"]
    root = "https://management.azure.com" + resource_id
    return [
        {
            "id": "production-boundary-site",
            "method": "GET",
            "url": f"{root}?api-version=2025-03-01",
        },
        {
            "id": "production-boundary-web-config",
            "method": "GET",
            "url": f"{root}/config/web?api-version=2025-03-01",
        },
        {
            "id": "production-boundary-app-settings",
            "method": "POST",
            "url": f"{root}/config/appsettings/list?api-version=2025-03-01",
        },
        {
            "id": "production-boundary-deployments",
            "method": "GET",
            "url": f"{root}/deployments?api-version=2025-03-01",
        },
        {
            "id": "production-boundary-onedeploy",
            "method": "GET",
            "url": f"{root}/extensions/onedeploy?api-version=2025-05-01",
        },
    ]


def _production_boundary_digest_document(
    method: str,
    url: str,
    document: Any,
) -> Any:
    """Return the canonical non-persisted body used by both preflight paths.

    The production app-settings response contains secret names and values.  Its
    exact ARM envelope is validated, but only the settings map participates in
    the in-memory digest document.  Keeping this projector in the shared
    executor module prevents the read-only observer and the mandatory fresh
    apply-time preflight from authorizing different response hashes.
    """

    if method != "POST":
        return document
    parsed = urllib.parse.urlsplit(url)
    if not parsed.path.lower().endswith("/config/appsettings/list"):
        fail("production boundary POST is outside the app-settings read boundary")
    expected_id = parsed.path.removesuffix("/list")
    if (
        not isinstance(document, Mapping)
        or set(document) != {"id", "location", "name", "properties", "tags", "type"}
        or str(document.get("id", "")).lower() != expected_id.lower()
        or document.get("name") != "appsettings"
        or str(document.get("type", "")).lower() != "microsoft.web/sites/config"
        or document.get("location") != "Southeast Asia"
        or not isinstance(document.get("tags"), Mapping)
        or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in document["tags"].items()
        )
    ):
        fail("production app-settings response fields are not exact")
    settings = document.get("properties")
    if (
        not isinstance(settings, Mapping)
        or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in settings.items()
        )
    ):
        fail("production app settings are not one exact string map")
    return {"properties": dict(settings)}


def _production_boundary_string_or_none(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 4096 or "\r" in value or "\n" in value:
        fail(f"{label} is not one bounded string or null")
    return value


def _project_production_deployment_inventory(
    value: Any,
    *,
    site_resource_id: str,
    site_name: str,
) -> list[dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) - {"value", "nextLink"}:
        fail("production deployment inventory response fields are not exact")
    if value.get("nextLink") not in {None, ""}:
        fail("production deployment inventory is paginated")
    members = value.get("value")
    if not isinstance(members, list) or len(members) > 1000:
        fail("production deployment inventory is invalid or oversized")
    projected: list[dict[str, Any]] = []
    expected_prefix = site_resource_id.lower() + "/deployments/"
    for index, member in enumerate(members):
        if not isinstance(member, Mapping):
            fail(f"production deployment {index} is not one object")
        resource_id = member.get("id")
        name = member.get("name")
        resource_type = member.get("type")
        properties = member.get("properties")
        deployment_id = properties.get("id") if isinstance(properties, Mapping) else None
        if (
            not isinstance(resource_id, str)
            or not resource_id.lower().startswith(expected_prefix)
            or not isinstance(deployment_id, str)
            or not deployment_id
            or resource_id.rsplit("/", 1)[-1] != deployment_id
            or name != f"{site_name}/{deployment_id}"
            or str(resource_type).lower() != "microsoft.web/sites/deployments"
            or not isinstance(properties, Mapping)
        ):
            fail(f"production deployment {index} identity is invalid")
        active = properties.get("active")
        complete = properties.get("complete")
        readonly = properties.get("is_readonly")
        temporary = properties.get("is_temp")
        if any(type(item) is not bool for item in (active, complete, readonly, temporary)):
            fail(f"production deployment {index} booleans are invalid")
        status = properties.get("status")
        if type(status) is not int:
            fail(f"production deployment {index} status is invalid")
        site_value = properties.get("site_name")
        if site_value not in {None, site_name}:
            fail(f"production deployment {index} site name drifted")
        projection = {
            "id": resource_id,
            "name": f"{site_name}/{deployment_id}",
            "type": "Microsoft.Web/sites/deployments",
            "properties": {
                "id": deployment_id,
                "active": active,
                "complete": complete,
                "status": status,
                "deployer": _production_boundary_string_or_none(
                    properties.get("deployer"), f"production deployment {index} deployer"
                ),
                "received_time": _production_boundary_string_or_none(
                    properties.get("received_time"), f"production deployment {index} received_time"
                ),
                "start_time": _production_boundary_string_or_none(
                    properties.get("start_time"), f"production deployment {index} start_time"
                ),
                "end_time": _production_boundary_string_or_none(
                    properties.get("end_time"), f"production deployment {index} end_time"
                ),
                "last_success_end_time": _production_boundary_string_or_none(
                    properties.get("last_success_end_time"),
                    f"production deployment {index} last_success_end_time",
                ),
                "is_readonly": readonly,
                "is_temp": temporary,
                "site_name": site_value,
            },
        }
        projected.append(projection)
    projected.sort(key=lambda item: item["id"].lower())
    if len({item["id"].lower() for item in projected}) != len(projected):
        fail("production deployment inventory contains duplicate IDs")
    return projected


def _project_production_onedeploy_inventory(
    value: Any,
    *,
    site_resource_id: str,
    site_name: str,
) -> list[dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) - {"value", "nextLink"}:
        fail("production OneDeploy response fields are not exact")
    if value.get("nextLink") not in {None, ""}:
        fail("production OneDeploy inventory is paginated")
    members = value.get("value")
    if not isinstance(members, list) or len(members) > 1000:
        fail("production OneDeploy inventory is invalid or oversized")
    projected: list[dict[str, Any]] = []
    expected_prefix = site_resource_id.lower() + "/extensions/onedeploy/"
    for index, member in enumerate(members):
        if not isinstance(member, Mapping):
            fail(f"production OneDeploy entry {index} is not one object")
        resource_id = member.get("id")
        name = member.get("name")
        resource_type = member.get("type")
        properties = member.get("properties")
        operation_id = properties.get("id") if isinstance(properties, Mapping) else None
        if (
            not isinstance(resource_id, str)
            or not resource_id.lower().startswith(expected_prefix)
            or not isinstance(operation_id, str)
            or resource_id.rsplit("/", 1)[-1].lower() != operation_id.lower()
            or name != f"{site_name}/onedeploy"
            or str(resource_type).lower()
            != f"microsoft.web/sites/extensions/{operation_id}".lower()
            or not isinstance(properties, Mapping)
        ):
            fail(f"production OneDeploy entry {index} identity is invalid")
        _guid(operation_id, f"production OneDeploy entry {index} operation ID")
        complete = properties.get("complete")
        if type(complete) is not bool:
            fail(f"production OneDeploy entry {index} completion is invalid")
        status = properties.get("status")
        if type(status) is not int:
            fail(f"production OneDeploy entry {index} status is invalid")
        projected.append(
            {
                "id": resource_id,
                "name": f"{site_name}/onedeploy",
                "type": f"Microsoft.Web/sites/extensions/{operation_id}",
                "properties": {
                    "id": operation_id,
                    "deployer": _production_boundary_string_or_none(
                        properties.get("deployer"), f"production OneDeploy {index} deployer"
                    ),
                    "complete": complete,
                    "status": status,
                    "received_time": _production_boundary_string_or_none(
                        properties.get("received_time"),
                        f"production OneDeploy {index} received_time",
                    ),
                    "start_time": _production_boundary_string_or_none(
                        properties.get("start_time"), f"production OneDeploy {index} start_time"
                    ),
                    "end_time": _production_boundary_string_or_none(
                        properties.get("end_time"), f"production OneDeploy {index} end_time"
                    ),
                },
            }
        )
    projected.sort(key=lambda item: item["id"].lower())
    if len({item["id"].lower() for item in projected}) != len(projected):
        fail("production OneDeploy inventory contains duplicate IDs")
    return projected


def _project_production_boundary_documents(
    documents: Mapping[str, Any],
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    expected_ids = {item["id"] for item in _production_boundary_requests(plan)}
    if not isinstance(documents, Mapping) or set(documents) != expected_ids:
        fail("production boundary response set is incomplete")
    resources = {item["id"]: item for item in plan["resourceInventory"]}
    site = resources["productionSite"]
    identity = resources["productionSystemIdentity"]
    subnet = resources["integrationSubnet"]
    site_document = documents["production-boundary-site"]
    web_document = documents["production-boundary-web-config"]
    settings_document = documents["production-boundary-app-settings"]
    if not all(isinstance(item, Mapping) for item in (site_document, web_document, settings_document)):
        fail("production boundary site, config, or settings response is invalid")
    site_properties = site_document.get("properties")
    web_properties = web_document.get("properties")
    settings = settings_document.get("properties")
    site_identity = site_document.get("identity")
    if not all(isinstance(item, Mapping) for item in (site_properties, web_properties, settings, site_identity)):
        fail("production boundary site, config, identity, or settings properties are invalid")
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in settings.items()):
        fail("production app settings are not an exact string map")
    user_assigned = site_identity.get("userAssignedIdentities")
    if user_assigned is not None and user_assigned != {}:
        fail("production site unexpectedly has user-assigned identities")
    routing = site_properties.get("outboundVnetRouting")
    if not isinstance(routing, Mapping):
        fail("production outbound routing projection is absent")
    expected_site_id = site["resourceId"]
    subnet_observations = [
        value
        for value in (
            site_properties.get("virtualNetworkSubnetId"),
            web_properties.get("virtualNetworkSubnetId"),
        )
        if value is not None and value != ""
    ]
    if (
        str(site_document.get("id", "")).lower() != expected_site_id.lower()
        or site_document.get("name") != site["name"]
        or str(site_document.get("type", "")).lower() != "microsoft.web/sites"
        or site_properties.get("state") != "Running"
        or site_identity.get("type") != "SystemAssigned"
        or site_identity.get("tenantId") != TENANT
        or site_identity.get("principalId") != identity["principalId"]
        or not subnet_observations
        or any(value != subnet["resourceId"] for value in subnet_observations)
        or routing.get("allTraffic") is not False
        or routing.get("applicationTraffic") is not True
        or web_properties.get("vnetRouteAllEnabled") is not True
    ):
        fail("production site posture is outside the reviewed bootstrap boundary")
    return {
        "sitePosture": {
            "id": expected_site_id,
            "name": site["name"],
            "type": "Microsoft.Web/sites",
            "state": "Running",
            "identity": {
                "type": "SystemAssigned",
                "tenantId": TENANT,
                "principalId": identity["principalId"],
                "userAssignedIdentityResourceIds": [],
            },
            "virtualNetworkSubnetId": subnet["resourceId"],
            "outboundVnetRouting": {
                "allTraffic": False,
                "applicationTraffic": True,
            },
            "legacyVnetRouteAllEnabled": True,
        },
        "appSettingsSha256": sha256_bytes(canonical_json_bytes(dict(settings))),
        "deploymentInventory": _project_production_deployment_inventory(
            documents["production-boundary-deployments"],
            site_resource_id=expected_site_id,
            site_name=site["name"],
        ),
        "oneDeployInventory": _project_production_onedeploy_inventory(
            documents["production-boundary-onedeploy"],
            site_resource_id=expected_site_id,
            site_name=site["name"],
        ),
    }


def _validate_production_boundary_projection(
    value: Any,
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    projection = dict(
        _exact_keys(
            value,
            {
                "sitePosture",
                "appSettingsSha256",
                "deploymentInventory",
                "oneDeployInventory",
            },
            "production boundary source projection",
        )
    )
    expected_resources = {item["id"]: item for item in plan["resourceInventory"]}
    site = expected_resources["productionSite"]
    identity = expected_resources["productionSystemIdentity"]
    subnet = expected_resources["integrationSubnet"]
    expected_posture = {
        "id": site["resourceId"],
        "name": site["name"],
        "type": "Microsoft.Web/sites",
        "state": "Running",
        "identity": {
            "type": "SystemAssigned",
            "tenantId": TENANT,
            "principalId": identity["principalId"],
            "userAssignedIdentityResourceIds": [],
        },
        "virtualNetworkSubnetId": subnet["resourceId"],
        "outboundVnetRouting": {"allTraffic": False, "applicationTraffic": True},
        "legacyVnetRouteAllEnabled": True,
    }
    if projection["sitePosture"] != expected_posture:
        fail("production boundary site posture is not exact")
    _sha256(projection["appSettingsSha256"], "production app-settings digest")
    deployment_property_keys = {
        "id",
        "active",
        "complete",
        "status",
        "deployer",
        "received_time",
        "start_time",
        "end_time",
        "last_success_end_time",
        "is_readonly",
        "is_temp",
        "site_name",
    }
    for index, item in enumerate(projection["deploymentInventory"]):
        if (
            not isinstance(item, Mapping)
            or set(item) != {"id", "name", "type", "properties"}
            or not isinstance(item.get("properties"), Mapping)
            or set(item["properties"]) != deployment_property_keys
        ):
            fail(f"production deployment projection {index} fields are not exact")
    onedeploy_property_keys = {
        "id",
        "deployer",
        "complete",
        "status",
        "received_time",
        "start_time",
        "end_time",
    }
    for index, item in enumerate(projection["oneDeployInventory"]):
        if (
            not isinstance(item, Mapping)
            or set(item) != {"id", "name", "type", "properties"}
            or not isinstance(item.get("properties"), Mapping)
            or set(item["properties"]) != onedeploy_property_keys
        ):
            fail(f"production OneDeploy projection {index} fields are not exact")
    # Re-run the source projectors over canonical projection-shaped envelopes.
    # This avoids accepting merely list-shaped deployment evidence.
    deployment_envelope = {
        "value": projection["deploymentInventory"],
        "nextLink": None,
    }
    onedeploy_envelope = {
        "value": projection["oneDeployInventory"],
        "nextLink": None,
    }
    if _project_production_deployment_inventory(
        deployment_envelope,
        site_resource_id=site["resourceId"],
        site_name=site["name"],
    ) != projection["deploymentInventory"]:
        fail("production deployment inventory is not canonical")
    if _project_production_onedeploy_inventory(
        onedeploy_envelope,
        site_resource_id=site["resourceId"],
        site_name=site["name"],
    ) != projection["oneDeployInventory"]:
        fail("production OneDeploy inventory is not canonical")
    return projection


def _quoted_etag(value: Any, label: str) -> str:
    if not isinstance(value, str) or not (
        re.fullmatch(r'"[^"\r\n]{1,256}"', value) is not None
        or re.fullmatch(r"[0-9A-Fa-f]{8,64}", value) is not None
    ):
        fail(f"{label} is not one exact strong ETag token")
    return value


def _unpaginated_graph_collection(
    value: Any, label: str
) -> list[Mapping[str, Any]]:
    if not isinstance(value, Mapping):
        fail(f"{label} Graph collection is not one object")
    items = value.get("value")
    if (
        not isinstance(items, list)
        or value.get("@odata.nextLink") not in {None, ""}
        or any(not isinstance(item, Mapping) for item in items)
    ):
        fail(f"{label} Graph collection is partial or invalid")
    return list(items)


def _publisher_fic_inventory(
    value: Any,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    label: str,
) -> tuple[Mapping[str, Any] | None, list[Mapping[str, Any]]]:
    applications = _unpaginated_graph_collection(value, label)
    if len(applications) > 1:
        fail(f"{label} resolves to more than one source-named application")
    if not applications:
        return None, []
    application = applications[0]
    resources = {item["id"]: item for item in plan["resourceInventory"]}
    if (
        application.get("displayName") != resources["publisherApplication"]["name"]
        or not GUID.fullmatch(str(application.get("id", "")))
        or not GUID.fullmatch(str(application.get("appId", "")))
        or application.get("federatedIdentityCredentials@odata.nextLink")
        not in {None, ""}
    ):
        fail(f"{label} publisher application inventory drifted")
    credentials = application.get("federatedIdentityCredentials")
    if not isinstance(credentials, list) or any(
        not isinstance(item, Mapping) for item in credentials
    ):
        fail(f"{label} expanded FIC inventory is partial or invalid")
    if len(credentials) > 1:
        fail(f"{label} publisher FIC inventory is not sole")
    return application, list(credentials)


def _validate_exact_publisher_fic(
    value: Any,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        fail(f"{label} publisher FIC is not one object")
    resources = {item["id"]: item for item in plan["resourceInventory"]}
    resource = resources["publisherFederatedCredential"]
    expression = resource["claimsMatchingExpressionTemplate"].replace(
        "${authorization.source.mergedMain.commitSha}",
        authorization["source"]["mergedMain"]["commitSha"],
    )
    expected = {
        "name": resource["name"],
        "issuer": resource["issuer"],
        "audiences": resource["audiences"],
        "subject": None,
        "claimsMatchingExpression": {
            "languageVersion": resource["claimsMatchingExpressionLanguageVersion"],
            "value": expression,
        },
    }
    _guid(value.get("id"), f"{label} publisher federated credential ID")
    projection = {key: value.get(key) for key in expected}
    if projection != expected:
        fail(f"{label} publisher FIC is not exact")
    return {"id": value["id"], **projection}


def _normalize_storage_acl_prestate(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        fail("storage ACL prestate is not one object")
    required = {"defaultAction", "bypass", "ipRules", "virtualNetworkRules"}
    allowed = required | {"resourceAccessRules", "ipv6Rules"}
    if not required.issubset(value) or not set(value).issubset(allowed):
        fail("storage ACL prestate fields are not exact")
    normalized = dict(value)
    normalized.setdefault("resourceAccessRules", [])
    normalized.setdefault("ipv6Rules", [])
    return normalized


def _validate_storage_acl_prestate(value: Any, *, adding: bool, uploader: str) -> dict[str, Any]:
    acl = _normalize_storage_acl_prestate(value)
    subnet = (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-master-data-structure-sea/"
        "providers/Microsoft.Network/virtualNetworks/vnet-master-data-structure-sea/"
        "subnets/snet-appservice-integration"
    )
    expected_rule = {"value": uploader.split("/", 1)[0], "action": "Allow"}
    if (
        acl["defaultAction"] != "Deny"
        or acl["bypass"] != "None"
        or acl["resourceAccessRules"] != []
        or acl["ipv6Rules"] != []
        or acl["virtualNetworkRules"]
        != [{"id": subnet, "action": "Allow", "state": "Succeeded"}]
        or acl["ipRules"] != ([] if adding else [expected_rule])
    ):
        fail("storage ACL prestate is not the exact reviewed topology")
    return dict(acl)


def _resource_scope_from_plan(plan: Mapping[str, Any], scope: str) -> str:
    if scope == "subscription":
        return f"/subscriptions/{SUBSCRIPTION}"
    if isinstance(scope, str) and scope.startswith("/subscriptions/"):
        return scope
    resource = next(
        (item for item in plan["resourceInventory"] if item["id"] == scope), None
    )
    if not isinstance(resource, Mapping) or not isinstance(resource.get("resourceId"), str):
        fail(f"role scope is not one fixed plan resource: {scope}")
    return str(resource["resourceId"])


def _custom_role_definition_specs(plan: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Return the exact canonical ARM projections for all reviewed custom roles."""

    # These two deterministic definitions already protect the accepted-release
    # registry in Azure.  Their authority is exactly the reviewed V2 authority,
    # so preserve their established human-readable metadata instead of turning
    # a harmless name/description difference into an Azure mutation.
    established_registry_metadata = {
        "b5d9d7c7-9367-4ac0-9d41-28b71e0d517d": {
            "roleName": "PaperDesk Accepted Release Blob Append Writer",
            "description": (
                "PaperDesk accepted-release registry: create-only blob "
                "data-plane permission at an exact container assignment scope."
            ),
        },
        "e005b62b-037b-4989-b492-932669ec0842": {
            "roleName": "PaperDesk Accepted Release Blob Reader",
            "description": (
                "PaperDesk accepted-release registry: read-only blob "
                "data-plane permission at an exact container assignment scope."
            ),
        },
    }
    grouped: dict[str, dict[str, Any]] = {}
    for role in plan["roleMatrix"]:
        if role.get("definitionKind") == "BuiltInRole":
            continue
        definition_id = role["definitionId"]
        permission = {
            "actions": list(role.get("actions", [])),
            "notActions": [],
            "dataActions": list(role.get("dataActions", [])),
            "notDataActions": [],
        }
        existing = grouped.get(definition_id)
        if existing is not None:
            if existing["properties"]["permissions"] != [permission]:
                fail("shared custom role definition has inconsistent permissions")
            continue
        resource_id = (
            f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/"
            f"roleDefinitions/{definition_id}"
        )
        metadata = established_registry_metadata.get(
            definition_id,
            {
                "roleName": f"PaperDesk V2 {role['name']}",
                "description": "PaperDesk private release V2 exact least-authority role",
            },
        )
        grouped[definition_id] = {
            "id": resource_id,
            "name": definition_id,
            "type": "Microsoft.Authorization/roleDefinitions",
            "properties": {
                "roleName": metadata["roleName"],
                "description": metadata["description"],
                "type": "CustomRole",
                "permissions": [permission],
                "assignableScopes": [f"/subscriptions/{SUBSCRIPTION}"],
            },
        }
    return grouped


def _role_assignment_spec(
    plan: Mapping[str, Any], role: Mapping[str, Any], principal_id: str
) -> dict[str, Any]:
    _guid(principal_id, f"{role['name']} principalId")
    scope = _resource_scope_from_plan(plan, role["scope"])
    definition_id = (
        f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/"
        f"roleDefinitions/{role['definitionId']}"
    )
    assignment_id = (
        f"{scope}/providers/Microsoft.Authorization/roleAssignments/"
        f"{role['assignmentId']}"
    )
    return {
        "id": assignment_id,
        "name": role["assignmentId"],
        "type": "Microsoft.Authorization/roleAssignments",
        "properties": {
            "principalId": principal_id,
            "principalType": "ServicePrincipal",
            "roleDefinitionId": definition_id,
            "scope": scope,
            "condition": None,
            "conditionVersion": None,
            "delegatedManagedIdentityResourceId": None,
        },
    }


def _project_role_definition(value: Mapping[str, Any]) -> dict[str, Any]:
    properties = value.get("properties")
    if not isinstance(properties, Mapping):
        fail("role definition has no properties")
    return {
        "id": value.get("id"),
        "name": value.get("name"),
        "type": value.get("type"),
        "properties": {
            key: properties.get(key)
            for key in (
                "roleName",
                "description",
                "type",
                "permissions",
                "assignableScopes",
            )
        },
    }


def _validate_builtin_role_definition_projections(
    value: Any, plan: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    """Validate the full read-only projection of every reviewed built-in role.

    Built-in role permissions are provider-owned and cannot be safely
    reconstructed from a well-known role GUID.  The observer therefore reads
    each exact role-definition resource and places its complete nonsecret
    projection in the authorization-bound preflight context.  This validator
    rejects missing, additional, truncated, or permission-incompatible bodies.
    """

    roles_by_definition: dict[str, list[Mapping[str, Any]]] = {}
    for role in plan["roleMatrix"]:
        if role.get("definitionKind") == "BuiltInRole":
            roles_by_definition.setdefault(str(role["definitionId"]), []).append(role)
    projections = _exact_keys(
        value,
        set(roles_by_definition),
        "built-in role-definition projections",
    )
    validated: dict[str, dict[str, Any]] = {}
    for definition_id, roles in roles_by_definition.items():
        candidate = projections[definition_id]
        if not isinstance(candidate, Mapping):
            fail("built-in role-definition projection is not one object")
        projected = _project_role_definition(candidate)
        properties = projected["properties"]
        expected_id = (
            f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/"
            f"roleDefinitions/{definition_id}"
        )
        permissions = properties["permissions"]
        if (
            projected != candidate
            or str(projected["id"]).lower() != expected_id.lower()
            or str(projected["name"]).lower() != definition_id.lower()
            or projected["type"] != "Microsoft.Authorization/roleDefinitions"
            or not isinstance(properties["roleName"], str)
            or not properties["roleName"]
            or properties["type"] != "BuiltInRole"
            or not isinstance(permissions, list)
            or not permissions
            or properties["assignableScopes"] != ["/"]
        ):
            fail("built-in role-definition identity or posture drifted")
        flattened_actions: set[str] = set()
        flattened_data_actions: set[str] = set()
        for permission in permissions:
            permission = _exact_keys(
                permission,
                {"actions", "notActions", "dataActions", "notDataActions"},
                "built-in role permission",
            )
            for field in ("actions", "notActions", "dataActions", "notDataActions"):
                items = permission[field]
                if not isinstance(items, list) or any(
                    not isinstance(item, str) or not item for item in items
                ):
                    fail("built-in role permission list is invalid")
            flattened_actions.update(permission["actions"])
            flattened_data_actions.update(permission["dataActions"])
        for role in roles:
            if not set(role.get("actions", [])).issubset(flattened_actions) or not set(
                role.get("dataActions", [])
            ).issubset(flattened_data_actions):
                fail("built-in role no longer covers the exact reviewed assignment")
        validated[definition_id] = dict(candidate)
    return validated


def _project_role_assignment(value: Mapping[str, Any]) -> dict[str, Any]:
    properties = value.get("properties")
    if not isinstance(properties, Mapping):
        fail("role assignment has no properties")
    return {
        "id": value.get("id"),
        "name": value.get("name"),
        "type": value.get("type"),
        "properties": {
            key: properties.get(key)
            for key in (
                "principalId",
                "principalType",
                "roleDefinitionId",
                "scope",
                "condition",
                "conditionVersion",
                "delegatedManagedIdentityResourceId",
            )
        },
    }


def _bootstrap_self_test_static_control(
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the authorization-bound, preflight-safe part of the canary input.

    Azure-created identity IDs and blob ETags/version IDs deliberately do not
    appear in the observed preflight.  They are joined only from exact executor
    readbacks immediately before the bridge settings full-map PUT.
    """

    not_before = parse_time(authorization["validity"]["notBefore"], "authorization notBefore")
    expires = parse_time(authorization["validity"]["expiresAt"], "authorization expiresAt")
    issued = not_before
    self_test_expires = min(expires, not_before + dt.timedelta(seconds=900))
    return {
        "schemaVersion": 1,
        "mode": "package-fetch-self-test",
        "authorizationId": authorization["authorizationId"],
        "siteName": "paperdesk-release-registry-bridge-v2-9c4e0d0d",
        "packageSha256": authorization["plan"]["bridgePackageSha256"],
        "planSha256": authorization["plan"]["sha256"],
        "bridgePackageSourceSha": authorization["plan"]["bridgePackageSourceSha"],
        "tenantId": authorization["azure"]["tenantId"],
        "activationFenceAccount": "mdspdbak2608089c4e",
        "activationFenceContainer": "paperdesk-release-activation-control",
        "activationFenceBlob": "v2/production-activation-fence.json",
        "activationFenceLeaseId": "c28f7730-431d-5c52-b885-8e43154d1ddb",
        "leaseDurationSeconds": 60,
        "leaseRenewalCount": 1,
        "nonce": authorization["authorizationId"].replace("-", ""),
        "issuedAt": issued.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "expiresAt": self_test_expires.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    }


def _bootstrap_self_test_control(
    authorization: Mapping[str, Any], state: Mapping[str, Any]
) -> dict[str, Any]:
    """Join dynamic, proven Azure facts into the exact bridge canary control."""

    def proof(operation_id: str) -> Mapping[str, Any]:
        value = state.get("proofs", {}).get(operation_id)
        details = value.get("details") if isinstance(value, Mapping) else None
        if not isinstance(details, Mapping):
            fail(f"bootstrap self-test dependency is not proven: {operation_id}")
        return details

    bridge = proof("createBridgeIdentity")
    fence = proof("createInitialIdleActivationFence")
    control = _bootstrap_self_test_static_control(authorization)
    control.update(
        {
            "authorizationSha256": sha256_bytes(
                canonical_json_bytes(authorization)
            ),
            "bridgeIdentityResourceId": bridge.get("resourceId"),
            "bridgeClientId": bridge.get("clientId"),
            "bridgePrincipalId": bridge.get("principalId"),
            "activationFenceEtag": fence.get("etag"),
            "activationFenceVersionId": fence.get("versionId"),
            "activationFenceBodySha256": fence.get("sha256"),
        }
    )
    expected_bridge = next(
        item for item in load_plan()[0]["resourceInventory"] if item["id"] == "bridgeIdentity"
    )["resourceId"]
    if (
        str(control["bridgeIdentityResourceId"]).lower() != expected_bridge.lower()
        or not GUID.fullmatch(str(control["bridgeClientId"]))
        or not GUID.fullmatch(str(control["bridgePrincipalId"]))
        or not re.fullmatch(r'"[^"\r\n]{1,256}"', str(control["activationFenceEtag"]))
        or not isinstance(control["activationFenceVersionId"], str)
        or not control["activationFenceVersionId"]
        or not SHA256.fullmatch(str(control["activationFenceBodySha256"]))
    ):
        fail("bootstrap self-test dynamic control is not exact")
    return control


def _bootstrap_self_test_control_from_projections(
    authorization: Mapping[str, Any],
    prior: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Derive the canary control only from already validated source projections."""

    bridge = prior.get("createBridgeIdentity", {}).get("projection")
    fence = prior.get("createInitialIdleActivationFence", {}).get("projection")
    if not isinstance(bridge, Mapping) or not isinstance(fence, Mapping):
        fail("bootstrap self-test source projections are incomplete")
    control = _bootstrap_self_test_static_control(authorization)
    control.update(
        {
            "authorizationSha256": sha256_bytes(
                canonical_json_bytes(authorization)
            ),
            "bridgeIdentityResourceId": bridge.get("id"),
            "bridgeClientId": bridge.get("clientId"),
            "bridgePrincipalId": bridge.get("principalId"),
            "activationFenceEtag": fence.get("etag"),
            "activationFenceVersionId": fence.get("versionId"),
            "activationFenceBodySha256": fence.get("sha256"),
        }
    )
    expected_bridge = next(
        item
        for item in load_plan()[0]["resourceInventory"]
        if item["id"] == "bridgeIdentity"
    )["resourceId"]
    if (
        str(control["bridgeIdentityResourceId"]).lower() != expected_bridge.lower()
        or not GUID.fullmatch(str(control["bridgeClientId"]))
        or not GUID.fullmatch(str(control["bridgePrincipalId"]))
        or not re.fullmatch(r'"[^"\r\n]{1,256}"', str(control["activationFenceEtag"]))
        or not isinstance(control["activationFenceVersionId"], str)
        or not control["activationFenceVersionId"]
        or not SHA256.fullmatch(str(control["activationFenceBodySha256"]))
    ):
        fail("bootstrap self-test source control is not exact")
    return control


def _temporary_role_definition_readback_url(
    operation_id: str,
    plan: Mapping[str, Any],
) -> str | None:
    temporary = plan["temporaryAccess"]
    definition_ids = {
        "addOwnedUploaderPackageRole": temporary["roleDefinitionId"],
        "removeOwnedUploaderPackageRole": temporary["roleDefinitionId"],
        "addOwnedOperatorKeyReadRole": temporary[
            "temporaryKeyReadRoleDefinitionId"
        ],
        "removeOwnedOperatorKeyReadRole": temporary[
            "temporaryKeyReadRoleDefinitionId"
        ],
        "addOwnedOperatorFenceBootstrapRole": temporary[
            "temporaryFenceRoleDefinitionId"
        ],
        "removeOwnedOperatorFenceBootstrapRole": temporary[
            "temporaryFenceRoleDefinitionId"
        ],
        "addOwnedOperatorControllerCanaryRole": temporary[
            "temporaryControllerRoleDefinitionId"
        ],
        "removeOwnedOperatorControllerCanaryRole": temporary[
            "temporaryControllerRoleDefinitionId"
        ],
    }
    definition_id = definition_ids.get(operation_id)
    if definition_id is None:
        return None
    return (
        "https://management.azure.com/subscriptions/"
        f"{SUBSCRIPTION}/providers/Microsoft.Authorization/"
        f"roleDefinitions/{definition_id}?api-version=2022-04-01"
    )


def _operation_readback_url(
    operation_id: str,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> str:
    resources = {item["id"]: item for item in plan["resourceInventory"]}

    def arm(resource_id: str, api_version: str, suffix: str = "") -> str:
        return f"https://management.azure.com{resource_id}{suffix}?api-version={api_version}"

    if operation_id == "claimAzureSingleUseAuthorization":
        return arm(authorization["singleUse"]["azureClaimResourceId"], "2022-09-01")
    if operation_id == "createPublisherApplication":
        return "https://graph.microsoft.com/v1.0/applications?$filter=displayName%20eq%20'paperdesk-release-publisher-v2-9c4e0d0d'&$select=id,appId,displayName,signInAudience,passwordCredentials,keyCredentials"
    if operation_id == "createPublisherServicePrincipal":
        return "https://graph.microsoft.com/v1.0/servicePrincipals?$filter=displayName%20eq%20'paperdesk-release-publisher-v2-9c4e0d0d'&$select=id,appId,displayName,accountEnabled,servicePrincipalType,passwordCredentials,keyCredentials,appRoleAssignments"
    if operation_id == "grantPublisherGraphApplicationReadAll":
        return "https://graph.microsoft.com/v1.0/servicePrincipals?$filter=displayName%20eq%20'paperdesk-release-publisher-v2-9c4e0d0d'&$select=id,appId,displayName,accountEnabled,servicePrincipalType,passwordCredentials,keyCredentials&$expand=appRoleAssignments($select=id,principalId,resourceId,appRoleId)"
    if operation_id in {"retireLegacyPublisherFic", "createSolePublisherFicToSignedBootstrapSource"}:
        if operation_id.startswith("retire"):
            app_id = plan["legacyPublisherRetirement"]["applicationObjectId"]
            return f"https://graph.microsoft.com/beta/applications/{app_id}/federatedIdentityCredentials"
        return "https://graph.microsoft.com/beta/applications?$filter=displayName%20eq%20'paperdesk-release-publisher-v2-9c4e0d0d'&$select=id,appId,displayName&$expand=federatedIdentityCredentials"
    legacy_assignments = {
        "retireLegacyPublisherMutatorAssignment": plan["legacyPublisherRetirement"]["roleAssignmentResourceIds"][0],
        "retireLegacyPublisherSitesReadAssignment": plan["legacyPublisherRetirement"]["roleAssignmentResourceIds"][1],
        "retireLegacyPublisherResultReadAssignment": plan["legacyPublisherRetirement"]["roleAssignmentResourceIds"][2],
        "removeLegacyWriterResultAssignment": plan["legacyPublisherRetirement"]["legacyWriterResultAssignmentResourceId"],
        "removeLegacyReaderResultAssignment": plan["legacyPublisherRetirement"]["legacyReaderResultAssignmentResourceId"],
    }
    if operation_id in legacy_assignments:
        return arm(legacy_assignments[operation_id], "2022-04-01")
    target_by_operation = {
        "createMailboxResourceGroup": ("mailboxResourceGroup", "2022-09-01"),
        "createBridgeIdentity": ("bridgeIdentity", "2023-01-31"),
        "adoptExistingRegistryWriterIdentity": ("registryWriterIdentity", "2023-01-31"),
        "adoptExistingRegistryReaderIdentity": ("registryReaderIdentity", "2023-01-31"),
        "detachWriterAndReaderFromLegacyBridge": ("legacyBridgeSite", "2025-03-01"),
        "createSignerIdentity": ("signerIdentity", "2023-01-31"),
        "createProductionActivationIdentity": ("productionActivationIdentity", "2023-01-31"),
        "createPrivatePackageContainer": ("packageContainer", "2025-06-01"),
        "createPrivateControllerLockContainer": ("controllerLockContainer", "2025-06-01"),
        "createPrivateActivationFenceContainer": ("activationFenceContainer", "2025-06-01"),
        "createSigningKeyVersion": ("signingKey", "2023-07-01"),
        "createStoppedPrivateBridge": ("bridgeSite", "2025-03-01"),
        "attachFiveUamisOnlyToBridge": ("bridgeSite", "2025-03-01"),
        "addOwnedUploaderIpv4Rule": ("storageAccount", "2025-06-01"),
        "removeOwnedUploaderIpv4Rule": ("storageAccount", "2025-06-01"),
        "configureBridgeExactVersionedPackageAndCriticalSettings": ("bridgeSite", "2025-03-01"),
        "startBridgeForBoundedCanary": ("bridgeSite", "2025-03-01"),
    }
    if operation_id in target_by_operation:
        target, api = target_by_operation[operation_id]
        suffix = "/config/appsettings/list" if operation_id == "configureBridgeExactVersionedPackageAndCriticalSettings" else ""
        return arm(resources[target]["resourceId"], api, suffix)
    if operation_id in {"createCustomRoleDefinitions", "createExactRoleAssignments"}:
        collection = "roleDefinitions" if operation_id.endswith("Definitions") else "roleAssignments"
        url = arm(
            f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/{collection}",
            "2022-04-01",
        )
        if collection == "roleAssignments":
            # The Authorization API's subscription-scoped collection already
            # includes assignments at descendant resource scopes.  Azure
            # rejects the formerly used atScopeAndBelow() expression; leaving
            # the collection unfiltered is the supported exact inventory read.
            return url
        filter_value = "type eq 'CustomRole'"
        return f"{url}&$filter={urllib.parse.quote(filter_value, safe='()')}"
    temporary_role_operations = {
        "addOwnedUploaderPackageRole": (plan["temporaryAccess"]["scope"], plan["temporaryAccess"]["roleAssignmentId"]),
        "removeOwnedUploaderPackageRole": (plan["temporaryAccess"]["scope"], plan["temporaryAccess"]["roleAssignmentId"]),
        "addOwnedOperatorKeyReadRole": (plan["temporaryAccess"]["temporaryKeyReadScope"], plan["temporaryAccess"]["temporaryKeyReadRoleAssignmentId"]),
        "removeOwnedOperatorKeyReadRole": (plan["temporaryAccess"]["temporaryKeyReadScope"], plan["temporaryAccess"]["temporaryKeyReadRoleAssignmentId"]),
        "addOwnedOperatorFenceBootstrapRole": (plan["temporaryAccess"]["temporaryFenceScope"], plan["temporaryAccess"]["temporaryFenceRoleAssignmentId"]),
        "removeOwnedOperatorFenceBootstrapRole": (plan["temporaryAccess"]["temporaryFenceScope"], plan["temporaryAccess"]["temporaryFenceRoleAssignmentId"]),
        "addOwnedOperatorControllerCanaryRole": (plan["temporaryAccess"]["temporaryControllerScope"], plan["temporaryAccess"]["temporaryControllerRoleAssignmentId"]),
        "removeOwnedOperatorControllerCanaryRole": (plan["temporaryAccess"]["temporaryControllerScope"], plan["temporaryAccess"]["temporaryControllerRoleAssignmentId"]),
    }
    if operation_id in temporary_role_operations:
        scope_key, assignment_id = temporary_role_operations[operation_id]
        scope = resources[scope_key]["resourceId"]
        return arm(f"{scope}/providers/Microsoft.Authorization/roleAssignments/{assignment_id}", "2022-04-01")
    if operation_id == "uploadVersionedBridgePackage":
        return (
            "https://mdspdbak2608089c4e.blob.core.windows.net/paperdesk-deployment-packages/"
            f"v2/control/{authorization['source']['mergedMain']['commitSha']}/paperdesk-private-release-bridge.zip"
        )
    if operation_id in {"lockPackageRetentionAt91Days", "extendAcceptedRetentionFrom30To91Days", "extendResultRetentionFrom30To91Days"}:
        target = {
            "lockPackageRetentionAt91Days": "packageContainer",
            "extendAcceptedRetentionFrom30To91Days": "acceptedContainer",
            "extendResultRetentionFrom30To91Days": "resultContainer",
        }[operation_id]
        return arm(resources[target]["resourceId"] + "/immutabilityPolicies/default", "2025-06-01")
    if operation_id == "readBackExactSigningPublicJwk":
        return "https://kv-mds-sea-9c4e0d0d.vault.azure.net/keys/paperdesk-release-result-signing/versions?api-version=7.4"
    if operation_id == "createInitialIdleActivationFence":
        return resources["activationFenceBlob"]["resourceId"]
    if operation_id in {
        "createControllerLeaseCanaryBlob",
        "exerciseControllerLeaseCanary",
        "removeControllerLeaseCanaryBlob",
    }:
        blob = plan["temporaryAccess"]["controllerCanaryBlobTemplate"].replace(
            "${authorization.authorizationId}", authorization["authorizationId"]
        )
        return (
            "https://mdspdbak2608089c4e.blob.core.windows.net/"
            f"{resources['controllerLockContainer']['name']}/{blob}"
        )
    fail(f"no exact source-owned readback URL exists for {operation_id}")


def _validator_contract(
    validator_id: str,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    resource_map = {item["id"]: item for item in plan["resourceInventory"]}
    if validator_id.startswith("operation:"):
        operation_id = validator_id.split(":", 1)[1]
        operation = next((item for item in plan["mutations"] if item["id"] == operation_id), None)
        if operation is None or operation["kind"] == "local-create-only-canonical-evidence":
            fail("readback validator operation is unknown")
        target = operation["target"]
        resource = resource_map.get(target, {})
        resource_id = resource.get("resourceId")
        if operation_id == "claimAzureSingleUseAuthorization":
            resource_id = authorization["singleUse"]["azureClaimResourceId"]
        absence_readbacks = {
            "retireLegacyPublisherMutatorAssignment",
            "retireLegacyPublisherSitesReadAssignment",
            "retireLegacyPublisherResultReadAssignment",
            "removeLegacyWriterResultAssignment",
            "removeLegacyReaderResultAssignment",
            "removeOwnedUploaderPackageRole",
            "removeOwnedOperatorKeyReadRole",
            "removeOwnedOperatorFenceBootstrapRole",
            "removeOwnedOperatorControllerCanaryRole",
            "removeControllerLeaseCanaryBlob",
        }
        expected_status = 404 if operation_id in absence_readbacks else 200
        expected_method = "POST" if operation_id == "configureBridgeExactVersionedPackageAndCriticalSettings" else "GET"
        dynamic_fields: list[str] = []
        if operation_id in {"createPublisherApplication", "createPublisherServicePrincipal"}:
            dynamic_fields = ["id:guid", "appId:guid"]
        elif operation_id in {
            "createBridgeIdentity",
            "createSignerIdentity",
            "createProductionActivationIdentity",
        }:
            dynamic_fields = ["properties.clientId:guid", "properties.principalId:guid"]
        elif operation_id == "createSigningKeyVersion":
            dynamic_fields = ["properties.keyUriWithVersion:key-version-uri"]
        elif operation_id in {
            "uploadVersionedBridgePackage",
            "createInitialIdleActivationFence",
            "createControllerLeaseCanaryBlob",
        }:
            dynamic_fields = ["header.etag:quoted-etag", "header.x-ms-version-id:nonempty"]
        contract = {
            "schemaVersion": 1,
            "kind": "source-operation-invariants-v1",
            "validatorId": validator_id,
            "operationId": operation_id,
            "target": target,
            "targetType": resource.get("type", "logical"),
            "targetResourceId": resource_id,
            "targetName": resource.get("name"),
            "expectedStatus": expected_status,
            "expectedMethod": expected_method,
            "expectedUrl": _operation_readback_url(operation_id, plan, authorization),
            "dynamicFields": dynamic_fields,
            "preflightContextPolicy": _operation_context_policy(
                operation_id, plan, authorization
            ),
        }
        if operation_id == "uploadVersionedBridgePackage":
            source_sha = authorization["source"]["mergedMain"]["commitSha"]
            contract.update(
                {
                    "expectedBodySha256": authorization["plan"]["bridgePackageSha256"],
                    "expectedBodySize": authorization["plan"]["bridgePackageSize"],
                }
            )
        elif operation_id == "createInitialIdleActivationFence":
            fence = {
                "schemaVersion": 1,
                "state": "idle",
                "stateVersion": 0,
                "operation": "",
                "sourceSha": "",
                "pendingRelease": None,
                "preSettingsSha256": "",
                "desiredSettingsSha256": "",
                "leaseId": "",
                "lastStatus": "bootstrap",
                "lastProofSha256": "0" * 64,
            }
            contract.update(
                {
                    "expectedBodySha256": sha256_bytes(canonical_json_bytes(fence)),
                    "expectedBodySize": len(canonical_json_bytes(fence)),
                }
            )
        elif operation_id == "createControllerLeaseCanaryBlob":
            canary = {
                "schemaVersion": 1,
                "mode": "controller-lock-finite-lease-canary",
                "authorizationId": authorization["authorizationId"],
                "sourceSha": authorization["source"]["mergedMain"]["commitSha"],
                "planSha256": authorization["plan"]["sha256"],
            }
            body = canonical_json_bytes(canary)
            contract.update(
                {
                    "expectedBodySha256": sha256_bytes(body),
                    "expectedBodySize": len(body),
                }
            )
        elif operation_id == "exerciseControllerLeaseCanary":
            contract["expectedLeaseState"] = "available"
        return contract
    if validator_id.startswith("postcondition:"):
        postcondition_id = validator_id.split(":", 1)[1]
        postcondition = next((item for item in plan["postconditions"] if item["id"] == postcondition_id), None)
        if postcondition is None:
            fail("readback validator postcondition is unknown")
        semantic_policy = _postcondition_semantic_policy(postcondition_id, plan)
        return {
            "schemaVersion": 1,
            "kind": "source-postcondition-invariants-v1",
            "validatorId": validator_id,
            "postconditionId": postcondition_id,
            "predicateSha256": sha256_bytes(postcondition["predicate"].encode("utf-8")),
            "semanticPolicy": semantic_policy,
            "expectedStatus": 200,
            "expectedMethod": "GET",
            "expectedUrl": (
                "https://management.azure.com/subscriptions/"
                f"{SUBSCRIPTION}/providers/Microsoft.Resources/deployments/"
                f"paperdesk-v2-bootstrap-{authorization['authorizationId']}?api-version=2022-09-01"
            ),
        }
    fail("readback validator ID is outside the source policy")


def _postcondition_semantic_policy(
    postcondition_id: str, plan: Mapping[str, Any]
) -> dict[str, Any]:
    """Return the exact source-owned proof family for one terminal predicate."""

    required: dict[str, tuple[str, list[str]]] = {
        "azureSingleUseClaimPersists": (
            "azure-claim-exact-readback",
            ["claimAzureSingleUseAuthorization"],
        ),
        "sourceContractRemainsNullDormant": ("local-source-dormancy", []),
        "oneSolePublisherFicPinsBootstrapSource": (
            "sole-s1-fic-graph-inventory",
            ["createSolePublisherFicToSignedBootstrapSource"],
        ),
        "allAutomationIdentitiesDistinct": (
            "pairwise-identity-inventory",
            [
                "createPublisherServicePrincipal",
                "createBridgeIdentity",
                "adoptExistingRegistryWriterIdentity",
                "adoptExistingRegistryReaderIdentity",
                "createSignerIdentity",
                "createProductionActivationIdentity",
            ],
        ),
        "exactTwentyFiveRoleRecords": (
            "role-definition-and-assignment-inventories",
            ["createCustomRoleDefinitions", "createExactRoleAssignments"],
        ),
        "bridgePrivateStoppedAfterCanary": (
            "private-five-uami-stopped-terminal-success",
            [
                "createStoppedPrivateBridge",
                "attachFiveUamisOnlyToBridge",
                "startBridgeForBoundedCanary",
            ],
        ),
        "legacyBridgeRetired": (
            "legacy-bridge-nonsecret-retirement",
            ["detachWriterAndReaderFromLegacyBridge"],
        ),
        "storageFinalNetworkExact": (
            "storage-service-endpoint-firewall-final",
            ["removeOwnedUploaderIpv4Rule"],
        ),
        "temporaryUploaderAccessAbsent": (
            "temporary-uploader-absence",
            ["removeOwnedUploaderPackageRole", "removeOwnedUploaderIpv4Rule"],
        ),
        "temporaryOperatorKeyReadAbsent": (
            "temporary-key-role-absence",
            ["removeOwnedOperatorKeyReadRole"],
        ),
        "temporaryOperatorFenceAccessAbsent": (
            "temporary-fence-role-absence",
            ["removeOwnedOperatorFenceBootstrapRole"],
        ),
        "temporaryControllerCanaryAccessAbsent": (
            "temporary-controller-role-and-blob-absence",
            [
                "removeControllerLeaseCanaryBlob",
                "removeOwnedOperatorControllerCanaryRole",
            ],
        ),
        "wormPoliciesLockedAtLeast91Days": (
            "three-private-locked-worm-projections",
            [
                "lockPackageRetentionAt91Days",
                "extendAcceptedRetentionFrom30To91Days",
                "extendResultRetentionFrom30To91Days",
            ],
        ),
        "vaultNotDowngraded": (
            "vault-posture-plus-no-journal-write",
            ["createSigningKeyVersion"],
        ),
        "signingKeyExact": (
            "exact-key-and-public-jwk",
            ["createSigningKeyVersion", "readBackExactSigningPublicJwk"],
        ),
        "packageExactVersionReadback": (
            "exact-versioned-package-bytes",
            ["uploadVersionedBridgePackage"],
        ),
        "managedIdentityPackageFetchCanary": (
            "fresh-webjob-terminal-success-no-http-claim",
            ["startBridgeForBoundedCanary"],
        ),
        "finiteLeaseAndCleanupCanaries": (
            "operator-controller-and-bridge-fence-lease-proof",
            ["exerciseControllerLeaseCanary", "startBridgeForBoundedCanary"],
        ),
        "initialFenceIdleAvailable": (
            "canonical-idle-fence-available",
            ["createInitialIdleActivationFence", "startBridgeForBoundedCanary"],
        ),
        "productionRoutingObservedNotMutated": (
            "production-pre-post-equality-and-zero-write-journal",
            [],
        ),
        "legacyPublisherRetired": (
            "legacy-publisher-exact-absence-and-preservation",
            [
                "retireLegacyPublisherFic",
                "retireLegacyPublisherMutatorAssignment",
                "retireLegacyPublisherSitesReadAssignment",
                "retireLegacyPublisherResultReadAssignment",
            ],
        ),
        "noProductionReleaseMutation": ("forbidden-target-journal-audit", []),
        "canonicalEvidenceReadyForS2": (
            "terminal-source-inputs-ready-for-local-assembly",
            [],
        ),
    }
    selected = required.get(postcondition_id)
    if selected is None:
        fail(f"postcondition has no source semantic policy: {postcondition_id}")
    family, operation_ids = selected
    mutation_ids = {item["id"] for item in plan["mutations"]}
    if any(operation_id not in mutation_ids for operation_id in operation_ids):
        fail(f"postcondition semantic policy references an unknown mutation: {postcondition_id}")
    return {
        "schemaVersion": 1,
        "postconditionId": postcondition_id,
        "family": family,
        "requiredOperationIds": operation_ids,
    }


def _operation_projection_family(operation_id: str) -> str:
    groups: tuple[tuple[set[str], str], ...] = (
        ({"claimAzureSingleUseAuthorization"}, "azure-single-use-claim"),
        (
            {
                "createPublisherApplication",
                "createPublisherServicePrincipal",
                "grantPublisherGraphApplicationReadAll",
            },
            "publisher-graph-projection",
        ),
        ({"createSolePublisherFicToSignedBootstrapSource"}, "sole-publisher-fic-inventory"),
        (
            {
                "createBridgeIdentity",
                "adoptExistingRegistryWriterIdentity",
                "adoptExistingRegistryReaderIdentity",
                "createSignerIdentity",
                "createProductionActivationIdentity",
            },
            "managed-identity-projection",
        ),
        ({"createCustomRoleDefinitions"}, "custom-role-definition-inventory"),
        ({"createExactRoleAssignments"}, "role-assignment-inventory"),
        (
            {
                "createPrivatePackageContainer",
                "createPrivateControllerLockContainer",
                "createPrivateActivationFenceContainer",
            },
            "private-container-projection",
        ),
        ({"createSigningKeyVersion"}, "signing-key-posture"),
        (
            {
                "createStoppedPrivateBridge",
                "attachFiveUamisOnlyToBridge",
                "detachWriterAndReaderFromLegacyBridge",
            },
            "webapp-nonsecret-posture",
        ),
        (
            {"addOwnedUploaderIpv4Rule", "removeOwnedUploaderIpv4Rule"},
            "storage-network-acl-redacted-projection",
        ),
        (
            {
                "addOwnedUploaderPackageRole",
                "addOwnedOperatorKeyReadRole",
                "addOwnedOperatorFenceBootstrapRole",
                "addOwnedOperatorControllerCanaryRole",
            },
            "temporary-role-projection",
        ),
        (
            {
                "removeOwnedUploaderPackageRole",
                "removeOwnedOperatorKeyReadRole",
                "removeOwnedOperatorFenceBootstrapRole",
                "removeOwnedOperatorControllerCanaryRole",
            },
            "temporary-role-cleanup-absence",
        ),
        (
            {
                "uploadVersionedBridgePackage",
                "createInitialIdleActivationFence",
                "createControllerLeaseCanaryBlob",
            },
            "versioned-blob-readback",
        ),
        ({"readBackExactSigningPublicJwk"}, "public-jwk-projection"),
        ({"exerciseControllerLeaseCanary"}, "controller-lease-canary"),
        (
            {"removeControllerLeaseCanaryBlob"},
            "controller-lock-empty-after-canary",
        ),
        (
            {"configureBridgeExactVersionedPackageAndCriticalSettings"},
            "app-settings-digest-only",
        ),
        (
            {"startBridgeForBoundedCanary"},
            "fresh-webjob-terminal-success-finally-stopped",
        ),
        (
            {
                "lockPackageRetentionAt91Days",
                "extendAcceptedRetentionFrom30To91Days",
                "extendResultRetentionFrom30To91Days",
            },
            "worm-policy-projection",
        ),
        ({"createMailboxResourceGroup"}, "resource-group-projection"),
        ({"retireLegacyPublisherFic"}, "legacy-publisher-fic-absence-inventory"),
        (
            {
                "retireLegacyPublisherMutatorAssignment",
                "retireLegacyPublisherSitesReadAssignment",
                "retireLegacyPublisherResultReadAssignment",
                "removeLegacyWriterResultAssignment",
                "removeLegacyReaderResultAssignment",
            },
            "exact-absence",
        ),
    )
    for operation_ids, family in groups:
        if operation_id in operation_ids:
            return family
    fail(f"operation has no terminal projection family: {operation_id}")


def _validate_operation_source_projection(
    value: Any,
    *,
    operation_id: str,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    prior: Mapping[str, Mapping[str, Any]],
    operation_context: Mapping[str, Any] | None = None,
    runtime_facts: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    projection = dict(
        _exact_keys(
            value,
            {
                "schemaVersion",
                "operationId",
                "family",
                "method",
                "url",
                "status",
                "target",
                "targetResourceId",
                "responseSha256",
                "headers",
                "projection",
            },
            f"terminal operation projection {operation_id}",
        )
    )
    operation = next(
        (
            item
            for item in plan["mutations"]
            if item["id"] == operation_id
            and item["kind"] != "local-create-only-canonical-evidence"
        ),
        None,
    )
    if operation is None:
        fail("terminal source projection references an unknown operation")
    contract = _validator_contract(f"operation:{operation_id}", plan, authorization)
    if (
        projection["schemaVersion"] != 1
        or projection["operationId"] != operation_id
        or projection["family"] != _operation_projection_family(operation_id)
        or projection["method"] != contract["expectedMethod"]
        or projection["url"] != contract["expectedUrl"]
        or projection["status"] != contract["expectedStatus"]
        or projection["target"] != operation["target"]
        or projection["targetResourceId"] != contract.get("targetResourceId")
    ):
        fail(f"terminal operation projection is not source-bound: {operation_id}")
    _sha256(projection["responseSha256"], f"{operation_id} response digest")
    headers = projection["headers"]
    if not isinstance(headers, dict) or not set(headers).issubset(
        {"etag", "versionId", "leaseState", "leaseStatus"}
    ):
        fail(f"{operation_id} retained response headers are not exact")
    for name, item in headers.items():
        if not isinstance(item, str) or not 1 <= len(item) <= 512:
            fail(f"{operation_id} retained {name} header is invalid")
    body = projection["projection"]
    family = projection["family"]
    resources = {item["id"]: item for item in plan["resourceInventory"]}
    context = dict(operation_context or {})
    facts = dict(runtime_facts or {})
    if family == "exact-absence":
        if body != {"absent": True} or projection["status"] != 404:
            fail(f"{operation_id} terminal absence proof is fabricated")
    elif family == "azure-single-use-claim":
        expected_claim = {
            "authorizationId": authorization["authorizationId"],
            "authorizationSha256": sha256_bytes(canonical_json_bytes(authorization)),
            "sourceSha": authorization["source"]["mergedMain"]["commitSha"],
            "planSha256": authorization["plan"]["sha256"],
            "packageSha256": authorization["plan"]["bridgePackageSha256"],
        }
        expected_body = {
            "resourceId": authorization["singleUse"]["azureClaimResourceId"],
            "deploymentName": authorization["singleUse"]["azureClaimResourceId"].rsplit("/", 1)[-1],
            "provisioningState": "Succeeded",
            "claim": expected_claim,
        }
        if body != expected_body:
            fail("terminal Azure claim projection is not exact")
    elif family == "publisher-graph-projection":
        if not isinstance(body, dict):
            fail("publisher Graph projection is invalid")
        if operation_id == "createPublisherApplication":
            required = {
                "id",
                "appId",
                "displayName",
                "signInAudience",
                "passwordCredentials",
                "keyCredentials",
            }
            if (
                set(body) != required
                or body["displayName"] != resources["publisherApplication"]["name"]
                or body["signInAudience"] != "AzureADMyOrg"
                or body["passwordCredentials"] != []
                or body["keyCredentials"] != []
            ):
                fail("publisher application terminal projection is not credentialless")
            _guid(body["id"], "publisher application object ID")
            _guid(body["appId"], "publisher application client ID")
        elif operation_id == "createPublisherServicePrincipal":
            required = {
                "id",
                "appId",
                "displayName",
                "accountEnabled",
                "servicePrincipalType",
                "passwordCredentials",
                "keyCredentials",
                "appRoleAssignments",
            }
            application = prior.get("createPublisherApplication", {}).get("projection", {})
            if (
                set(body) != required
                or body["displayName"] != resources["publisherServicePrincipal"]["name"]
                or body["accountEnabled"] is not True
                or body["servicePrincipalType"] != "Application"
                or body["passwordCredentials"] != []
                or body["keyCredentials"] != []
                or body["appId"] != application.get("appId")
                or not isinstance(body["appRoleAssignments"], list)
            ):
                fail("publisher service principal terminal projection is not exact")
            _guid(body["id"], "publisher service principal object ID")
        else:
            required = {
                "id",
                "appId",
                "displayName",
                "accountEnabled",
                "servicePrincipalType",
                "passwordCredentials",
                "keyCredentials",
                "appRoleAssignments",
            }
            if (
                set(body) != required
                or body["accountEnabled"] is not True
                or body["servicePrincipalType"] != "Application"
                or body["passwordCredentials"] != []
                or body["keyCredentials"] != []
                or len(body["appRoleAssignments"]) != 1
            ):
                fail("publisher Graph permission projection is not sole")
            assignment = body["appRoleAssignments"][0]
            if (
                not isinstance(assignment, Mapping)
                or assignment.get("principalId") != body["id"]
                or assignment.get("appRoleId")
                != AzureCliBootstrapTransport.GRAPH_APPLICATION_READ_ALL
            ):
                fail("publisher Graph permission is not Application.Read.All")
    elif family == "sole-publisher-fic-inventory":
        body = _exact_keys(
            body,
            {"applicationObjectId", "federatedIdentityCredentials"},
            "sole publisher FIC projection",
        )
        application = prior.get("createPublisherApplication", {}).get("projection", {})
        credentials = body["federatedIdentityCredentials"]
        if body["applicationObjectId"] != application.get("id") or not isinstance(
            credentials, list
        ) or len(credentials) != 1:
            fail("sole publisher FIC projection is not application-bound")
        resource = resources["publisherFederatedCredential"]
        expression = resource["claimsMatchingExpressionTemplate"].replace(
            "${authorization.source.mergedMain.commitSha}",
            authorization["source"]["mergedMain"]["commitSha"],
        )
        expected = {
            "name": resource["name"],
            "issuer": resource["issuer"],
            "audiences": resource["audiences"],
            "subject": None,
            "claimsMatchingExpression": {
                "languageVersion": resource[
                    "claimsMatchingExpressionLanguageVersion"
                ],
                "value": expression,
            },
        }
        if any(not isinstance(item, Mapping) for item in credentials):
            fail("publisher FIC projection contains a non-object")
        _guid(credentials[0].get("id"), "publisher federated credential ID")
        observed = {
            key: credentials[0].get(key)
            for key in expected
        }
        if observed != expected:
            fail("publisher FIC terminal projection is not S1-source pinned")
    elif family == "managed-identity-projection":
        body = _exact_keys(
            body,
            {"id", "name", "type", "clientId", "principalId", "tenantId"},
            f"{operation_id} managed-identity projection",
        )
        if (
            str(body["id"]).lower()
            != str(contract["targetResourceId"]).lower()
            or body["name"] != resources[operation["target"]]["name"]
            or body["type"] != "Microsoft.ManagedIdentity/userAssignedIdentities"
            or str(body["tenantId"]).lower() != TENANT
        ):
            fail("managed-identity terminal projection target is not exact")
        _guid(body["clientId"], f"{operation_id} client ID")
        _guid(body["principalId"], f"{operation_id} principal ID")
    elif family == "custom-role-definition-inventory":
        body = _exact_keys(body, {"roleDefinitions"}, "custom role definitions")
        expected = [
            item for _key, item in sorted(_custom_role_definition_specs(plan).items())
        ]
        if body["roleDefinitions"] != expected:
            fail("terminal custom role-definition inventory is not source exact")
    elif family == "role-assignment-inventory":
        body = _exact_keys(body, {"roleAssignments"}, "role assignments")
        values = body["roleAssignments"]
        if not isinstance(values, list) or len(values) != len(plan["roleMatrix"]):
            fail("terminal role-assignment inventory is incomplete")
        def principal_id(name: str) -> str:
            fixed = resources.get(name, {}).get("principalId")
            if isinstance(fixed, str):
                return fixed
            dependency = {
                "publisherServicePrincipal": "createPublisherServicePrincipal",
                "bridgeIdentity": "createBridgeIdentity",
                "signerIdentity": "createSignerIdentity",
                "productionActivationIdentity": "createProductionActivationIdentity",
            }.get(name)
            source_projection = prior.get(str(dependency), {}).get("projection", {})
            if name == "publisherServicePrincipal":
                candidate = source_projection.get("id")
            else:
                candidate = source_projection.get("principalId")
            return _guid(candidate, f"role assignment principal {name}")

        expected = sorted(
            (
                _role_assignment_spec(plan, role, principal_id(role["principal"]))
                for role in plan["roleMatrix"]
            ),
            key=lambda item: str(item["id"]).lower(),
        )
        if values != expected:
            fail("terminal role-assignment inventory contains a scope, principal, role, condition, or delegation drift")
    elif family == "private-container-projection":
        body = _exact_keys(
            body,
            {"id", "name", "type", "publicAccess"},
            "private container projection",
        )
        if (
            str(body["id"]).lower() != str(contract["targetResourceId"]).lower()
            or body["name"] != f"default/{resources[operation['target']]['name']}"
            or body["type"]
            != "Microsoft.Storage/storageAccounts/blobServices/containers"
            or body["publicAccess"] not in {None, "None"}
        ):
            fail("terminal container is not private and exact")
    elif family == "signing-key-posture":
        body = _exact_keys(
            body,
            {
                "keyUriWithVersion",
                "kty",
                "keySize",
                "keyOps",
                "enabled",
                "exportable",
                "expiresAt",
                "releasePolicy",
            },
            "signing key posture",
        )
        expected_expiry = int(
            parse_time(context.get("expiresAt"), "signing key authorized expiresAt").timestamp()
        )
        minimum_expiry = int(
            (
                parse_time(
                    authorization["validity"]["expiresAt"],
                    "authorization expiresAt",
                )
                + dt.timedelta(days=30)
            ).timestamp()
        )
        if (
            re.fullmatch(
                r"https://kv-mds-sea-9c4e0d0d\.vault\.azure\.net/keys/paperdesk-release-result-signing/[0-9a-f]{32}",
                str(body["keyUriWithVersion"]),
            )
            is None
            or body["kty"] != "RSA"
            or body["keySize"] != 3072
            or body["keyOps"] != ["sign", "verify"]
            or body["enabled"] is not True
            or body["exportable"] is not False
            or body["expiresAt"] != expected_expiry
            or expected_expiry < minimum_expiry
            or body["releasePolicy"] is not None
        ):
            fail("signing-key terminal projection is unsafe")
    elif family == "webapp-nonsecret-posture":
        required = {
            "id",
            "name",
            "kind",
            "httpsOnly",
            "state",
            "publicNetworkAccess",
            "serverFarmId",
            "virtualNetworkSubnetId",
            "outboundVnetRouting",
            "identity",
        }
        body = _exact_keys(body, required, f"{operation_id} webapp posture")
        if (
            str(body["id"]).lower() != str(contract["targetResourceId"]).lower()
            or body["name"] != contract["targetName"]
        ):
            fail("webapp terminal projection target is not exact")
        identity = body["identity"]
        if operation_id == "createStoppedPrivateBridge":
            if (
                body["kind"] != "app,linux"
                or body["httpsOnly"] is not True
                or body["state"] != "Stopped"
                or body["publicNetworkAccess"] != "Disabled"
                or str(body["serverFarmId"]).lower()
                != resources["bridgeAppServicePlan"]["resourceId"].lower()
                or str(body["virtualNetworkSubnetId"]).lower()
                != resources["integrationSubnet"]["resourceId"].lower()
                or body["outboundVnetRouting"]
                != {"allTraffic": True, "applicationTraffic": True}
                or not isinstance(identity, Mapping)
                or identity.get("type") not in {None, "None"}
                or identity.get("userAssignedIdentities") not in (None, {})
            ):
                fail("terminal bridge creation posture is unsafe")
        elif operation_id == "attachFiveUamisOnlyToBridge":
            attached = identity.get("userAssignedIdentities") if isinstance(identity, Mapping) else None
            expected_ids: set[str] = set()
            for target, dependency in (
                ("bridgeIdentity", "createBridgeIdentity"),
                ("registryWriterIdentity", "adoptExistingRegistryWriterIdentity"),
                ("registryReaderIdentity", "adoptExistingRegistryReaderIdentity"),
                ("signerIdentity", "createSignerIdentity"),
                ("productionActivationIdentity", "createProductionActivationIdentity"),
            ):
                candidate = prior.get(dependency, {}).get("projection", {}).get("id")
                if candidate is None:
                    candidate = resources.get(target, {}).get("resourceId")
                if not isinstance(candidate, str):
                    fail("terminal bridge UAMI dependency is absent")
                expected_ids.add(candidate.lower())
            if (
                body["state"] != "Stopped"
                or body["publicNetworkAccess"] != "Disabled"
                or not isinstance(identity, Mapping)
                or identity.get("type") != "UserAssigned"
                or not isinstance(attached, Mapping)
                or {str(item).lower() for item in attached} != expected_ids
                or any(value != {} for value in attached.values())
            ):
                fail("terminal bridge UAMI inventory is not sole and exact")
        elif operation_id == "detachWriterAndReaderFromLegacyBridge":
            if (
                body["state"] != "Stopped"
                or body["publicNetworkAccess"] != "Disabled"
                or not isinstance(identity, Mapping)
                or identity.get("type") not in {None, "None"}
                or identity.get("userAssignedIdentities") not in (None, {})
            ):
                fail("terminal legacy bridge retirement posture is unsafe")
    elif family == "storage-network-acl-redacted-projection":
        body = _exact_keys(
            body,
            {
                "networkAclsSha256",
                "defaultAction",
                "bypass",
                "ipRuleCount",
                "resourceAccessRuleCount",
                "virtualNetworkRules",
            },
            "storage ACL projection",
        )
        source_acl_name = (
            "preNetworkAcls"
            if operation_id == "addOwnedUploaderIpv4Rule"
            else "restoreNetworkAcls"
        )
        source_acl = context.get(source_acl_name)
        uploader = context.get("uploaderIpv4")
        if not isinstance(source_acl, Mapping) or not isinstance(uploader, str):
            fail("storage ACL terminal projection lacks its authorized context")
        expected_acl = dict(source_acl)
        if operation_id == "addOwnedUploaderIpv4Rule":
            network = ipaddress.ip_network(uploader, strict=True)
            expected_acl["ipRules"] = [
                {"value": str(network.network_address), "action": "Allow"}
            ]
        if (
            body["networkAclsSha256"]
            != sha256_bytes(canonical_json_bytes(expected_acl))
            or body["defaultAction"] != expected_acl["defaultAction"]
            or body["bypass"] != expected_acl["bypass"]
            or body["ipRuleCount"] != len(expected_acl["ipRules"])
            or body["resourceAccessRuleCount"]
            != len(expected_acl["resourceAccessRules"])
            or body["virtualNetworkRules"] != expected_acl["virtualNetworkRules"]
        ):
            fail("storage ACL terminal projection is not exact")
    elif family == "temporary-role-projection":
        if not isinstance(body, Mapping) or set(body) != {
            "definitionResourceId",
            "assignmentResourceId",
            "definitionCreated",
            "assignmentCreated",
            "cleanupKey",
            "definition",
            "assignment",
        }:
            fail("temporary role terminal projection is not exact")
        temporary = plan["temporaryAccess"]
        temp_specs = {
            "addOwnedUploaderPackageRole": (
                temporary["roleDefinitionId"],
                temporary["roleAssignmentId"],
                "packageContainer",
                "uploader-package-role",
                temporary["temporaryPackageDataActions"],
            ),
            "addOwnedOperatorKeyReadRole": (
                temporary["temporaryKeyReadRoleDefinitionId"],
                temporary["temporaryKeyReadRoleAssignmentId"],
                "signingKey",
                "operator-key-read-role",
                temporary["temporaryKeyReadDataActions"],
            ),
            "addOwnedOperatorFenceBootstrapRole": (
                temporary["temporaryFenceRoleDefinitionId"],
                temporary["temporaryFenceRoleAssignmentId"],
                "activationFenceContainer",
                "operator-fence-bootstrap-role",
                temporary["temporaryFenceDataActions"],
            ),
            "addOwnedOperatorControllerCanaryRole": (
                temporary["temporaryControllerRoleDefinitionId"],
                temporary["temporaryControllerRoleAssignmentId"],
                "controllerLockContainer",
                "operator-controller-canary-role",
                temporary["temporaryControllerDataActions"],
            ),
        }
        definition_id, assignment_id, scope_key, cleanup_key, data_actions = temp_specs[
            operation_id
        ]
        scope = resources[scope_key]["resourceId"]
        definition_resource = (
            f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/"
            f"roleDefinitions/{definition_id}"
        )
        assignment_resource = (
            f"{scope}/providers/Microsoft.Authorization/roleAssignments/{assignment_id}"
        )
        expected_definition = {
            "id": definition_resource,
            "name": definition_id,
            "type": "Microsoft.Authorization/roleDefinitions",
            "properties": {
                "roleName": f"PaperDesk V2 temporary {cleanup_key}",
                "description": "Single-use bootstrap temporary role; exact cleanup required",
                "type": "CustomRole",
                "permissions": [
                    {
                        "actions": [],
                        "notActions": [],
                        "dataActions": data_actions,
                        "notDataActions": [],
                    }
                ],
                "assignableScopes": [f"/subscriptions/{SUBSCRIPTION}"],
            },
        }
        principal_type = (
            "ServicePrincipal"
            if authorization["azure"]["accountType"] == "servicePrincipal"
            else "User"
        )
        expected_assignment = {
            "id": assignment_resource,
            "name": assignment_id,
            "type": "Microsoft.Authorization/roleAssignments",
            "properties": {
                "principalId": authorization["azure"]["accountObjectId"],
                "principalType": principal_type,
                "roleDefinitionId": definition_resource,
                "scope": scope,
                "condition": None,
                "conditionVersion": None,
                "delegatedManagedIdentityResourceId": None,
            },
        }
        if (
            body["definitionResourceId"] != definition_resource
            or body["assignmentResourceId"] != assignment_resource
            or body["definitionCreated"] is not True
            or body["assignmentCreated"] is not True
            or body["cleanupKey"] != cleanup_key
            or body["definition"] != expected_definition
            or body["assignment"] != expected_assignment
        ):
            fail("temporary role definition or assignment terminal projection drifted")
    elif family == "temporary-role-cleanup-absence":
        body = _exact_keys(
            body,
            {
                "cleanupKey",
                "assignmentResourceId",
                "definitionResourceId",
                "assignmentRemoved",
                "definitionRemoved",
                "assignmentAbsenceProjection",
                "definitionAbsenceProjection",
            },
            "temporary role cleanup projection",
        )
        temporary = plan["temporaryAccess"]
        cleanup_specs = {
            "removeOwnedUploaderPackageRole": (
                temporary["roleDefinitionId"],
                temporary["roleAssignmentId"],
                "packageContainer",
                "uploader-package-role",
            ),
            "removeOwnedOperatorKeyReadRole": (
                temporary["temporaryKeyReadRoleDefinitionId"],
                temporary["temporaryKeyReadRoleAssignmentId"],
                "signingKey",
                "operator-key-read-role",
            ),
            "removeOwnedOperatorFenceBootstrapRole": (
                temporary["temporaryFenceRoleDefinitionId"],
                temporary["temporaryFenceRoleAssignmentId"],
                "activationFenceContainer",
                "operator-fence-bootstrap-role",
            ),
            "removeOwnedOperatorControllerCanaryRole": (
                temporary["temporaryControllerRoleDefinitionId"],
                temporary["temporaryControllerRoleAssignmentId"],
                "controllerLockContainer",
                "operator-controller-canary-role",
            ),
        }
        definition_id, assignment_id, scope_key, cleanup_key = cleanup_specs[
            operation_id
        ]
        definition_resource = (
            f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/"
            f"roleDefinitions/{definition_id}"
        )
        assignment_resource = (
            f"{resources[scope_key]['resourceId']}/providers/"
            f"Microsoft.Authorization/roleAssignments/{assignment_id}"
        )
        if (
            body["cleanupKey"] != cleanup_key
            or body["definitionResourceId"] != definition_resource
            or body["assignmentResourceId"] != assignment_resource
            or type(body["assignmentRemoved"]) is not bool
            or type(body["definitionRemoved"]) is not bool
            or body["assignmentAbsenceProjection"]
            != {"resourceId": assignment_resource, "absent": True}
            or body["definitionAbsenceProjection"]
            != {"resourceId": definition_resource, "absent": True}
        ):
            fail("temporary role cleanup did not prove both exact absences")
    elif family == "versioned-blob-readback":
        if operation_id == "uploadVersionedBridgePackage":
            required_blob_fields = {
                "url", "blob", "etag", "versionId", "sha256", "size",
                "bodySha256", "bodySize",
            }
        elif operation_id == "createInitialIdleActivationFence":
            required_blob_fields = {
                "url", "etag", "versionId", "sha256", "bodySha256", "bodySize",
            }
        else:
            required_blob_fields = {
                "url", "etag", "versionId", "sha256", "cleanupKey",
                "bodySha256", "bodySize",
            }
        body = _exact_keys(body, required_blob_fields, "versioned blob terminal projection")
        if (
            body["etag"] != headers.get("etag")
            or body["versionId"] != headers.get("versionId")
            or _quoted_etag(body["etag"], "versioned blob ETag") != body["etag"]
            or not isinstance(body["versionId"], str)
            or not body["versionId"]
        ):
            fail("versioned blob terminal projection did not bind headers")
        if operation_id == "createInitialIdleActivationFence" and (
            headers.get("leaseState", "").lower() != "available"
            or headers.get("leaseStatus", "").lower() != "unlocked"
        ):
            fail("initial activation fence is not Available and Unlocked")
        if operation_id == "uploadVersionedBridgePackage" and (
            body["blob"]
            != f"v2/control/{authorization['source']['mergedMain']['commitSha']}/paperdesk-private-release-bridge.zip"
            or body.get("sha256") != authorization["plan"]["bridgePackageSha256"]
            or body.get("size") != authorization["plan"]["bridgePackageSize"]
            or body.get("url") != contract["expectedUrl"]
            or body.get("bodySha256") != authorization["plan"]["bridgePackageSha256"]
            or body.get("bodySize") != authorization["plan"]["bridgePackageSize"]
        ):
            fail("package terminal projection is not authorization-bound")
        if operation_id != "uploadVersionedBridgePackage" and (
            body.get("url") != contract["expectedUrl"]
            or body.get("bodySha256") != contract.get("expectedBodySha256")
            or body.get("bodySize") != contract.get("expectedBodySize")
            or body.get("sha256") != contract.get("expectedBodySha256")
        ):
            fail("bootstrap blob terminal body is not source exact")
    elif family == "public-jwk-projection":
        body = _exact_keys(
            body,
            {"kid", "kty", "n", "e", "key_ops", "attributes"},
            "public JWK",
        )
        attributes = _exact_keys(
            body["attributes"],
            {
                "enabled",
                "nbf",
                "exp",
                "created",
                "updated",
                "recoveryLevel",
                "recoverableDays",
                "exportable",
            },
            "public JWK attributes",
        )
        signing_key = prior.get("createSigningKeyVersion", {}).get("projection", {})
        modulus = body.get("n")
        try:
            decoded_modulus = base64.urlsafe_b64decode(
                str(modulus) + "=" * (-len(str(modulus)) % 4)
            )
        except (ValueError, TypeError) as exc:
            raise BootstrapError("public JWK modulus is not base64url") from exc
        if (
            body["kid"] != signing_key.get("keyUriWithVersion")
            or body["kty"] != "RSA"
            or body["e"] != "AQAB"
            or body["key_ops"] != ["sign", "verify"]
            or not isinstance(modulus, str)
            or "=" in modulus
            or len(decoded_modulus) != 384
            or int.from_bytes(decoded_modulus, "big").bit_length() != 3072
            or attributes["enabled"] is not True
            or attributes["exportable"] is not False
            or any(
                type(attributes[name]) is not int
                for name in ("nbf", "exp", "created", "updated", "recoverableDays")
            )
            or not isinstance(attributes["recoveryLevel"], str)
            or not attributes["recoveryLevel"]
            or attributes["recoverableDays"] != 90
            or attributes["exp"] != signing_key.get("expiresAt")
            or attributes["nbf"] > attributes["created"]
            or attributes["created"] > attributes["updated"]
        ):
            fail("public JWK terminal projection is not exact")
    elif family == "controller-lock-empty-after-canary":
        body = _exact_keys(
            body,
            {"absent", "controllerLockInventory"},
            "controller lock post-canary projection",
        )
        inventory = _exact_keys(
            body["controllerLockInventory"],
            {"containerUrl", "listUrl", "httpStatus", "blobNames", "blobCount", "nextMarker"},
            "controller lock post-canary inventory",
        )
        container_name = resources["controllerLockContainer"]["name"]
        expected_container_url = (
            "https://mdspdbak2608089c4e.blob.core.windows.net/" + container_name
        )
        expected_list_url = expected_container_url + "?restype=container&comp=list"
        if (
            body["absent"] is not True
            or inventory["containerUrl"] != expected_container_url
            or inventory["listUrl"] != expected_list_url
            or inventory["httpStatus"] != 200
            or inventory["blobNames"] != []
            or inventory["blobCount"] != 0
            or inventory["nextMarker"] != ""
        ):
            fail("controller lock container is not proven private and empty after canary cleanup")
    elif family == "controller-lease-canary":
        required = {
            "url",
            "leaseId",
            "durationSeconds",
            "renewals",
            "releaseStatus",
            "identity",
            "fastLane",
            "expiryFallback",
            "selfCleaned",
        }
        body = _exact_keys(body, required, "controller lease canary")
        temporary = plan["temporaryAccess"]
        canary_blob = temporary["controllerCanaryBlobTemplate"].replace(
            "${authorization.authorizationId}", authorization["authorizationId"]
        )
        expected_url = (
            "https://mdspdbak2608089c4e.blob.core.windows.net/"
            f"{resources['controllerLockContainer']['name']}/{canary_blob}"
        )
        fast_lane = _exact_keys(
            body["fastLane"],
            {"acquiredAt", "renewedAt", "releasedAt", "finalLeaseState"},
            "controller lease fast lane",
        )
        fallback = _exact_keys(
            body["expiryFallback"],
            {
                "leaseId",
                "acquiredAt",
                "releaseIntentionallyOmitted",
                "availableAt",
                "pollAttempts",
                "finalLeaseState",
            },
            "controller lease expiry fallback",
        )
        identity = _exact_keys(
            body["identity"], {"kind", "objectId"}, "controller lease identity"
        )
        renewed = fast_lane["renewedAt"]
        if not isinstance(renewed, list) or len(renewed) != temporary["leaseRenewals"]:
            fail("controller lease renewal evidence is incomplete")
        acquired_at = parse_time(fast_lane["acquiredAt"], "controller lease acquiredAt")
        renewed_at = [
            parse_time(item, "controller lease renewedAt") for item in renewed
        ]
        released_at = parse_time(fast_lane["releasedAt"], "controller lease releasedAt")
        fallback_acquired = parse_time(
            fallback["acquiredAt"], "controller expiry lease acquiredAt"
        )
        fallback_available = parse_time(
            fallback["availableAt"], "controller expiry lease availableAt"
        )
        auth_start = parse_time(authorization["validity"]["notBefore"], "authorization notBefore")
        auth_end = parse_time(authorization["validity"]["expiresAt"], "authorization expiresAt")
        ordered = [acquired_at, *renewed_at, released_at, fallback_acquired, fallback_available]
        if (
            body["url"] != expected_url
            or body["leaseId"] != temporary["controllerLeaseId"]
            or body["durationSeconds"] != temporary["leaseDurationSeconds"]
            or body["renewals"] != temporary["leaseRenewals"]
            or body["releaseStatus"] != 200
            or identity
            != {
                "kind": "authorized-local-azure-account",
                "objectId": authorization["azure"]["accountObjectId"],
            }
            or body["selfCleaned"] is not True
            or fast_lane["finalLeaseState"] != "available"
            or fallback["leaseId"] != temporary["controllerExpiryLeaseId"]
            or fallback["releaseIntentionallyOmitted"] is not True
            or type(fallback["pollAttempts"]) is not int
            or fallback["pollAttempts"] < 1
            or fallback["finalLeaseState"] != "available"
            or headers.get("leaseState", "").lower() != "available"
            or headers.get("leaseStatus", "").lower() != "unlocked"
            or ordered != sorted(ordered)
            or not auth_start <= ordered[0] <= ordered[-1] <= auth_end
        ):
            fail("controller lease terminal projection is incomplete")
    elif family == "app-settings-digest-only":
        required = {
            "preAppSettingsSha256",
            "settingsSha256",
            "bootstrapSelfTestControlSha256",
            "packageUrl",
            "packageVersionId",
        }
        body = _exact_keys(body, required, "app-settings terminal projection")
        upload = prior.get("uploadVersionedBridgePackage", {}).get("projection", {})
        if not isinstance(context.get("preAppSettings"), Mapping):
            fail("authorized pre-app-settings map is absent")
        control = _bootstrap_self_test_control_from_projections(authorization, prior)
        package_url = (
            f"{upload.get('url')}?versionid="
            + urllib.parse.quote(str(upload.get("versionId")), safe="")
        )
        desired = dict(context["preAppSettings"])
        desired.update(
            {
                "WEBSITE_RUN_FROM_PACKAGE": package_url,
                "WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID": resources[
                    "registryReaderIdentity"
                ]["resourceId"],
                "WEBSITE_SKIP_RUNNING_KUDUAGENT": "false",
                "PAPERDESK_BRIDGE_PACKAGE_SHA256": authorization["plan"][
                    "bridgePackageSha256"
                ],
                "PAPERDESK_BRIDGE_BOOTSTRAP_SELF_TEST_JSON": canonical_json_bytes(
                    control
                ).decode("utf-8"),
            }
        )
        expected_settings_sha = sha256_bytes(canonical_json_bytes(desired))
        expected_control_sha = sha256_bytes(canonical_json_bytes(control))
        if (
            body["preAppSettingsSha256"] != context.get("preAppSettingsSha256")
            or body["preAppSettingsSha256"]
            != sha256_bytes(canonical_json_bytes(context["preAppSettings"]))
            or body["settingsSha256"] != expected_settings_sha
            or body["bootstrapSelfTestControlSha256"] != expected_control_sha
            or body["packageUrl"] != package_url
            or body["packageVersionId"] != upload.get("versionId")
        ):
            fail("app-settings terminal projection is not exact")
    elif family == "fresh-webjob-terminal-success-finally-stopped":
        required = {
            "resourceId",
            "cleanupKey",
            "selfCleaned",
            "initialStopped",
            "running",
            "triggerStatus",
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
        boundary = _exact_keys(
            body["historyBoundary"],
            {"observedAt", "entries", "entriesSha256", "responseSha256"},
            "WebJob history boundary",
        )
        if not isinstance(boundary["entries"], list):
            fail("WebJob history boundary entries are invalid")

        def history_item(value: Any, label: str) -> Mapping[str, Any]:
            item = _exact_keys(
                value,
                {
                    "historyId",
                    "webJobsRunId",
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
        if len({item["historyId"] for item in boundary_entries}) != len(boundary_entries):
            fail("WebJob history boundary contains duplicate entries")
        trigger_at = parse_time(body["triggerRequestedAt"], "WebJob trigger requestedAt")
        boundary_at = parse_time(boundary["observedAt"], "WebJob history boundary observedAt")
        terminal_started = parse_time(terminal["startedAt"], "fresh WebJob start")
        terminal_ended = parse_time(terminal["endedAt"], "fresh WebJob end")
        terminal_observed = parse_time(
            body["terminalHistoryObservedAt"], "fresh WebJob observedAt"
        )
        combined_entries = sorted(
            [*boundary_entries, terminal], key=lambda item: item["historyId"]
        )
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
            or body["triggerStatus"] not in {200, 202, 204}
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
                <= parse_time(running["observedAt"], "running bridge observedAt")
                <= boundary_at
                <= trigger_at
            )
            or terminal_started < trigger_at - dt.timedelta(seconds=5)
            or terminal_ended > terminal_observed + dt.timedelta(seconds=5)
            or parse_time(stopped["observedAt"], "stopped bridge observedAt")
            < terminal_observed
            or parse_time(stopped["observedAt"], "stopped bridge observedAt")
            > auth_end
        ):
            fail("bridge terminal canary did not succeed and finally stop")
    elif family == "worm-policy-projection":
        body = _exact_keys(
            body,
            {
                "id",
                "name",
                "type",
                "etag",
                "properties",
                "stateAfterPut",
                "lockPostIssued",
            },
            "WORM projection",
        )
        properties = _exact_keys(
            body["properties"],
            {
                "state",
                "immutabilityPeriodSinceCreationInDays",
                "allowProtectedAppendWrites",
                "allowProtectedAppendWritesAll",
            },
            "WORM properties",
        )
        target_id = resources[operation["target"]]["resourceId"]
        expected_policy_id = target_id + "/immutabilityPolicies/default"
        if (
            str(body["id"]).lower() != expected_policy_id.lower()
            or body["name"] != "default"
            or body["type"]
            != "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies"
            or _quoted_etag(body["etag"], "WORM terminal ETag") != body["etag"]
            or properties["state"] != "Locked"
            or type(properties["immutabilityPeriodSinceCreationInDays"]) is not int
            or properties["immutabilityPeriodSinceCreationInDays"] < 91
            or properties["allowProtectedAppendWrites"] is not False
            or properties["allowProtectedAppendWritesAll"] is not False
            or body["stateAfterPut"] not in {"Locked", "Unlocked"}
            or body["lockPostIssued"] is not (body["stateAfterPut"] == "Unlocked")
        ):
            fail("terminal WORM projection is not locked at least 91 days")
    elif family == "resource-group-projection":
        body = _exact_keys(body, {"id", "name", "type", "location"}, "resource group")
        if (
            str(body["id"]).lower() != str(contract["targetResourceId"]).lower()
            or str(body["location"]).lower() != plan["azure"]["location"]
        ):
            fail("mailbox resource-group terminal projection is not exact")
    elif family == "legacy-publisher-fic-absence-inventory":
        body = _exact_keys(
            body,
            {
                "applicationObjectId",
                "removedFederatedCredentialId",
                "federatedIdentityCredentials",
            },
            "legacy publisher FIC absence inventory",
        )
        if (
            body["applicationObjectId"]
            != plan["legacyPublisherRetirement"]["applicationObjectId"]
            or body["removedFederatedCredentialId"]
            != context.get("legacyFederatedCredentialId")
            or not GUID.fullmatch(str(body["removedFederatedCredentialId"]))
            or body["federatedIdentityCredentials"] != []
        ):
            fail("legacy publisher FIC inventory is not exact empty state")
    else:  # pragma: no cover - the family map is exhaustive above
        fail(f"terminal operation projection family is unhandled: {family}")
    return projection


def _worm_final_policy_projection(value: Mapping[str, Any]) -> dict[str, Any]:
    """Strip executor path metadata from one already validated WORM proof."""

    return {
        key: json.loads(canonical_json_bytes(value[key]).decode("utf-8"))
        for key in ("id", "name", "type", "etag", "properties")
    }


def _reject_terminal_secret_material(value: Any, label: str = "sourceEvidence") -> None:
    jose = re.compile(r"(?:^|[^A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}(?:$|[^A-Za-z0-9_-])")

    def credential_key(key: str) -> bool:
        normalized = re.sub(r"[^a-z0-9]", "", key.lower())
        exact = {
            "token",
            "accesstoken",
            "refreshtoken",
            "secret",
            "password",
            "sas",
            "sharedkey",
            "connectionstring",
        }
        return (
            normalized in exact
            or normalized.startswith(
                (
                    "accesstoken",
                    "refreshtoken",
                    "secret",
                    "password",
                    "sharedkey",
                    "connectionstring",
                )
            )
            or normalized.endswith(
                ("token", "secret", "password", "sharedkey", "connectionstring")
            )
        )

    def inspect(item: Any, path: str) -> None:
        if isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str):
                    fail(f"{label} contains a non-string field")
                if credential_key(key) and child not in (
                    None,
                    "",
                    False,
                    [],
                    {},
                ):
                    fail(f"{label} contains secret-shaped material at {path}.{key}")
                inspect(child, f"{path}.{key}")
        elif isinstance(item, list):
            for index, child in enumerate(item):
                inspect(child, f"{path}[{index}]")
        elif isinstance(item, str):
            lowered = item.lower()
            decoded = urllib.parse.unquote(item)
            forbidden_query_keys: set[str] = set()
            try:
                parsed = urllib.parse.urlsplit(item)
                if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
                    forbidden_query_keys = {
                        urllib.parse.unquote(key).lower()
                        for key, _value in urllib.parse.parse_qsl(
                            parsed.query,
                            keep_blank_values=True,
                            strict_parsing=False,
                            max_num_fields=128,
                        )
                        if urllib.parse.unquote(key).lower()
                        in {"sig", "sv", "se", "sp", "spr", "srt", "ss"}
                    }
            except (ValueError, UnicodeError):
                forbidden_query_keys = {"invalid-url-encoding"}
            if (
                jose.search(" " + item + " ")
                or jose.search(" " + decoded + " ")
                or "bearer " in lowered
                or "?sig=" in lowered
                or "&sig=" in lowered
                or forbidden_query_keys
                or re.search(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}/32(?![0-9])", item)
            ):
                fail(f"{label} contains a credential-shaped value at {path}")

    inspect(value, label)


def _terminal_observed_at(
    value: Any, label: str, authorization: Mapping[str, Any]
) -> dt.datetime:
    observed = parse_time(value, label)
    not_before = parse_time(
        authorization["validity"]["notBefore"], "authorization notBefore"
    )
    expires_at = parse_time(
        authorization["validity"]["expiresAt"], "authorization expiresAt"
    )
    if not not_before <= observed <= expires_at:
        fail(f"{label} is outside the authorization window")
    return observed


def _validate_package_readback_source(
    value: Any,
    *,
    authorization: Mapping[str, Any],
    prior: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    body = dict(
        _exact_keys(
            value,
            {
                "blobName",
                "versionId",
                "etag",
                "httpStatus",
                "bytesObservedInMemory",
                "bytesSha256",
                "size",
                "metadataSha256",
                "observedAt",
            },
            "package readback source projection",
        )
    )
    upload = prior.get("uploadVersionedBridgePackage", {}).get("projection", {})
    if (
        body["blobName"] != upload.get("blob")
        or body["versionId"] != upload.get("versionId")
        or body["etag"] != upload.get("etag")
        or _quoted_etag(body["etag"], "package readback ETag") != body["etag"]
        or body["httpStatus"] != 200
        or body["bytesObservedInMemory"] is not True
        or body["bytesSha256"] != authorization["plan"]["bridgePackageSha256"]
        or body["size"] != authorization["plan"]["bridgePackageSize"]
        or body["metadataSha256"] != authorization["plan"]["bridgePackageSha256"]
    ):
        fail("package readback source projection is not the exact authorized version")
    _terminal_observed_at(body["observedAt"], "package readback observedAt", authorization)
    return body


def _validate_managed_identity_fetch_source(
    value: Any,
    *,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    prior: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    body = dict(
        _exact_keys(
            value,
            {
                "evidenceMode",
                "directPackageBytesObservedByExecutor",
                "identityResourceId",
                "identityClientId",
                "identityPrincipalId",
                "authentication",
                "packageBlobName",
                "packageVersionId",
                "expectedPackageSha256",
                "expectedPackageSize",
                "sourceControlSha256",
                "webJobInvocationId",
                "terminalStatus",
                "observedAt",
            },
            "managed-identity run-from-package source projection",
        )
    )
    reader = prior.get("adoptExistingRegistryReaderIdentity", {}).get(
        "projection", {}
    )
    upload = prior.get("uploadVersionedBridgePackage", {}).get("projection", {})
    configure = prior.get(
        "configureBridgeExactVersionedPackageAndCriticalSettings", {}
    ).get("projection", {})
    canary = prior.get("startBridgeForBoundedCanary", {}).get("projection", {})
    terminal = canary.get("terminalHistory")
    resources = {item["id"]: item for item in plan["resourceInventory"]}
    if (
        body["evidenceMode"]
        != "source-derived-from-terminal-success-not-directly-observed"
        or body["directPackageBytesObservedByExecutor"] is not False
        or str(body["identityResourceId"]).lower()
        != resources["registryReaderIdentity"]["resourceId"].lower()
        or body["identityResourceId"] != reader.get("id")
        or body["identityClientId"] != reader.get("clientId")
        or body["identityPrincipalId"] != reader.get("principalId")
        or body["authentication"]
        != "platform-run-from-package-managed-identity"
        or body["packageBlobName"] != upload.get("blob")
        or body["packageVersionId"] != upload.get("versionId")
        or body["expectedPackageSha256"]
        != authorization["plan"]["bridgePackageSha256"]
        or body["expectedPackageSize"]
        != authorization["plan"]["bridgePackageSize"]
        or body["sourceControlSha256"]
        != configure.get("bootstrapSelfTestControlSha256")
        or not isinstance(terminal, Mapping)
        or body["webJobInvocationId"] != terminal.get("webJobsRunId")
        or body["terminalStatus"] != "Success"
        or terminal.get("status") != "Success"
    ):
        fail("managed-identity run-from-package proof is not exact and truthful")
    _terminal_observed_at(
        body["observedAt"], "managed-identity run-from-package observedAt", authorization
    )
    return body


def _source_derived_bridge_marker(
    *,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    prior: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    resources = {item["id"]: item for item in plan["resourceInventory"]}
    upload = prior.get("uploadVersionedBridgePackage", {}).get("projection", {})
    return {
        "schemaVersion": 1,
        "evidenceType": (
            "paperdesk-private-release-v2-source-derived-bridge-canary-"
            "expectation-v1"
        ),
        "observationStatus": "expected-not-observed",
        "authorizationId": authorization["authorizationId"],
        "sourceSha": authorization["source"]["mergedMain"]["commitSha"],
        "packageSha256": authorization["plan"]["bridgePackageSha256"],
        "packageVersionId": upload.get("versionId"),
        "bridgeResourceId": resources["bridgeSite"]["resourceId"],
        "bridgeIdentityResourceId": resources["bridgeIdentity"]["resourceId"],
        "activationFenceBlobResourceId": resources["activationFenceBlob"][
            "resourceId"
        ],
        "expectedTerminalStatus": "Success",
        "literalStdoutMarkerObserved": False,
        "httpHealthObserved": False,
    }


def _validate_bridge_canary_source(
    value: Any,
    *,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    prior: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    body = dict(
        _exact_keys(
            value,
            {"webJobTerminal", "sourceDerivedExpectedMarker"},
            "bridge canary source proof",
        )
    )
    webjob = dict(
        _exact_keys(
            body["webJobTerminal"],
            {
                "status",
                "invocationId",
                "sourceSha",
                "packageSha256",
                "packageVersionId",
                "startedAt",
                "completedAt",
            },
            "bridge WebJob terminal projection",
        )
    )
    canary = prior.get("startBridgeForBoundedCanary", {}).get("projection", {})
    terminal = canary.get("terminalHistory")
    upload = prior.get("uploadVersionedBridgePackage", {}).get("projection", {})
    if not isinstance(terminal, Mapping):
        fail("bridge canary source proof lacks validated terminal history")
    if (
        webjob
        != {
            "status": "Success",
            "invocationId": terminal.get("webJobsRunId"),
            "sourceSha": authorization["source"]["mergedMain"]["commitSha"],
            "packageSha256": authorization["plan"]["bridgePackageSha256"],
            "packageVersionId": upload.get("versionId"),
            "startedAt": terminal.get("startedAt"),
            "completedAt": terminal.get("endedAt"),
        }
        or body["sourceDerivedExpectedMarker"]
        != _source_derived_bridge_marker(
            plan=plan, authorization=authorization, prior=prior
        )
    ):
        fail("bridge canary source proof is not source/package/auth exact")
    started = _terminal_observed_at(
        webjob["startedAt"], "bridge WebJob startedAt", authorization
    )
    completed = _terminal_observed_at(
        webjob["completedAt"], "bridge WebJob completedAt", authorization
    )
    if completed < started:
        fail("bridge WebJob terminal time order is invalid")
    return body


def _validate_cleanup_absence_sources(
    value: Any,
    *,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    prior: Mapping[str, Mapping[str, Any]],
    operation_contexts: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    sources = dict(
        _exact_keys(
            value,
            {
                "packageIpv4Rule",
                "packageUploaderRole",
                "operatorKeyReadRole",
                "operatorFenceRole",
                "operatorControllerRole",
            },
            "cleanup absence projections",
        )
    )
    operation_by_name = {
        "packageIpv4Rule": "removeOwnedUploaderIpv4Rule",
        "packageUploaderRole": "removeOwnedUploaderPackageRole",
        "operatorKeyReadRole": "removeOwnedOperatorKeyReadRole",
        "operatorFenceRole": "removeOwnedOperatorFenceBootstrapRole",
        "operatorControllerRole": "removeOwnedOperatorControllerCanaryRole",
    }
    validated_temp: dict[str, Mapping[str, Any]] = dict(prior)
    for name, operation_id in operation_by_name.items():
        item = dict(
            _exact_keys(
                sources[name],
                {"httpStatus", "present", "sanitizedProjection", "observedAt"},
                f"cleanup absence projection {name}",
            )
        )
        projection = _validate_operation_source_projection(
            item["sanitizedProjection"],
            operation_id=operation_id,
            plan=plan,
            authorization=authorization,
            prior=validated_temp,
            operation_context=operation_contexts.get(operation_id),
        )
        expected_status = 200 if name == "packageIpv4Rule" else 404
        if item["httpStatus"] != expected_status or item["present"] is not False:
            fail(f"cleanup absence projection {name} does not prove exact absence")
        _terminal_observed_at(
            item["observedAt"], f"cleanup absence {name} observedAt", authorization
        )
        validated_temp[operation_id] = projection
    return sources


def _validate_worm_sources(
    value: Any,
    *,
    plan: Mapping[str, Any],
    prior: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    sources = dict(
        _exact_keys(
            value,
            {"acceptedReleases", "webJobResults", "deploymentPackages"},
            "WORM source projections",
        )
    )
    resources = {item["id"]: item for item in plan["resourceInventory"]}
    mapping = {
        "acceptedReleases": (
            "acceptedContainer",
            "extendAcceptedRetentionFrom30To91Days",
        ),
        "webJobResults": ("resultContainer", "extendResultRetentionFrom30To91Days"),
        "deploymentPackages": ("packageContainer", "lockPackageRetentionAt91Days"),
    }
    for name, (resource_key, operation_id) in mapping.items():
        pair = _exact_keys(
            sources[name], {"container", "policy"}, f"WORM source {name}"
        )
        resource = resources[resource_key]
        expected_container = {
            "id": resource["resourceId"],
            "name": f"default/{resource['name']}",
            "type": "Microsoft.Storage/storageAccounts/blobServices/containers",
            "publicAccess": "None",
        }
        operation_policy = prior.get(operation_id, {}).get("projection")
        expected_policy = (
            _worm_final_policy_projection(operation_policy)
            if isinstance(operation_policy, Mapping)
            else None
        )
        if pair["container"] != expected_container or pair["policy"] != expected_policy:
            fail(f"WORM source {name} is not the exact private locked projection")
    return sources


def _normalized_role_assignment_projection(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return the canonical nonsecret assignment shape used by mailbox S2.

    ARM resource IDs are case-insensitive, while the downstream mailbox
    contract intentionally hashes one lower-case projection.  Normalize only
    after the live operation validator has proved the exact assignment body;
    this avoids two equivalent casings producing different evidence hashes.
    """

    def text(item: Any, label: str) -> str:
        if not isinstance(item, str) or not item or len(item) > 4096:
            fail(f"{label} is invalid")
        return item

    assignment = _exact_keys(
        value,
        {"id", "name", "type", "properties"},
        "normalized role assignment",
    )
    properties = _exact_keys(
        assignment["properties"],
        {
            "principalId",
            "principalType",
            "roleDefinitionId",
            "scope",
            "condition",
            "conditionVersion",
            "delegatedManagedIdentityResourceId",
        },
        "normalized role assignment properties",
    )
    resource_id = text(assignment["id"], "role assignment resource ID").lower()
    if (
        text(assignment["name"], "role assignment name").lower()
        != resource_id.rsplit("/", 1)[-1]
        or str(assignment["type"]).lower()
        != "microsoft.authorization/roleassignments"
        or properties["principalType"] != "ServicePrincipal"
        or properties["condition"] is not None
        or properties["conditionVersion"] is not None
        or properties["delegatedManagedIdentityResourceId"] is not None
    ):
        fail("role assignment cannot be normalized safely")
    return {
        "id": resource_id,
        "name": resource_id.rsplit("/", 1)[-1],
        "type": "Microsoft.Authorization/roleAssignments",
        "properties": {
            "principalId": _guid(
                properties["principalId"], "role assignment principal ID"
            ).lower(),
            "principalType": "ServicePrincipal",
            "roleDefinitionId": text(
                properties["roleDefinitionId"], "role definition resource ID"
            ).lower(),
            "scope": text(properties["scope"], "role assignment scope").lower(),
            "condition": None,
            "conditionVersion": None,
            "delegatedManagedIdentityResourceId": None,
        },
    }


def _validate_rich_provisioning_sources(
    value: Any,
    *,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    prior: Mapping[str, Mapping[str, Any]],
    operation_contexts: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    source = dict(
        _exact_keys(
            value,
            {
                "publisherApplication",
                "publisherServicePrincipal",
                "solePublisherFederatedCredentials",
                "roleDefinitions",
                "roleAssignments",
                "principalDirectAssignments",
                "principalEffectiveAssignments",
                "controllerLockContainer",
                "networkTopology",
            },
            "rich provisioning source projections",
        )
    )
    resources = {item["id"]: item for item in plan["resourceInventory"]}
    application = prior.get("createPublisherApplication", {}).get("projection", {})
    service = prior.get("createPublisherServicePrincipal", {}).get("projection", {})
    expected_application = {
        "id": application.get("id"),
        "appId": application.get("appId"),
        "signInAudience": application.get("signInAudience"),
        "passwordCredentialKeyIds": [],
        "keyCredentialKeyIds": [],
    }
    expected_service = {
        "id": service.get("id"),
        "appId": service.get("appId"),
        "accountEnabled": service.get("accountEnabled"),
        "servicePrincipalType": service.get("servicePrincipalType"),
        "passwordCredentialKeyIds": [],
        "keyCredentialKeyIds": [],
    }
    fic_projection = prior.get(
        "createSolePublisherFicToSignedBootstrapSource", {}
    ).get("projection", {})
    credentials = fic_projection.get("federatedIdentityCredentials")
    if (
        not isinstance(credentials, list)
        or len(credentials) != 1
        or not isinstance(credentials[0], Mapping)
    ):
        fail("rich publisher source lacks the sole concrete FIC")
    expected_fic = json.loads(canonical_json_bytes(credentials[0]).decode("utf-8"))
    if (
        source["publisherApplication"] != expected_application
        or source["publisherServicePrincipal"] != expected_service
        or source["solePublisherFederatedCredentials"] != [expected_fic]
        or fic_projection.get("applicationObjectId") != application.get("id")
    ):
        fail("rich publisher source projections are not credentialless and S1 pinned")

    custom_by_id = _custom_role_definition_specs(plan)
    assignment_inventory = prior.get("createExactRoleAssignments", {}).get(
        "projection", {}
    ).get("roleAssignments")
    if not isinstance(assignment_inventory, list):
        fail("rich role sources lack the validated assignment inventory")
    assignment_by_name = {
        str(item.get("name")).lower(): item
        for item in assignment_inventory
        if isinstance(item, Mapping)
    }
    expected_definitions: dict[str, Any] = {}
    expected_assignments: dict[str, Any] = {}
    custom_context = operation_contexts.get("createCustomRoleDefinitions")
    if not isinstance(custom_context, Mapping):
        fail("rich role sources lack the authorization-bound role context")
    built_in_definitions = _validate_builtin_role_definition_projections(
        custom_context.get("builtInRoleDefinitionProjections"), plan
    )
    for role in plan["roleMatrix"]:
        if role.get("definitionKind") == "BuiltInRole":
            definition = built_in_definitions[role["definitionId"]]
        else:
            definition = custom_by_id[role["definitionId"]]
        expected_definitions[role["name"]] = definition
        assignment = assignment_by_name.get(str(role["assignmentId"]).lower())
        if assignment is None:
            fail(f"rich role source lacks assignment {role['name']}")
        expected_assignments[role["name"]] = _normalized_role_assignment_projection(
            assignment
        )
    if (
        source["roleDefinitions"] != expected_definitions
        or source["roleAssignments"] != expected_assignments
    ):
        fail("rich role definition or assignment bodies are not source exact")

    principal_names = {
        "publisherServicePrincipal": "publisher",
        "bridgeIdentity": "bridge",
        "registryWriterIdentity": "registryWriter",
        "registryReaderIdentity": "registryReader",
        "signerIdentity": "signer",
        "productionActivationIdentity": "productionActivation",
        "productionSystemIdentity": "productionSystem",
    }
    expected_inventories: dict[str, list[Any]] = {}
    for resource_key, inventory_name in principal_names.items():
        principal = resources[resource_key].get("principalId")
        if principal is None:
            dependency = {
                "publisherServicePrincipal": "createPublisherServicePrincipal",
                "bridgeIdentity": "createBridgeIdentity",
                "signerIdentity": "createSignerIdentity",
                "productionActivationIdentity": "createProductionActivationIdentity",
            }.get(resource_key)
            candidate = prior.get(str(dependency), {}).get("projection", {})
            principal = (
                candidate.get("id")
                if resource_key == "publisherServicePrincipal"
                else candidate.get("principalId")
            )
        _guid(principal, f"rich principal inventory {inventory_name}")
        expected_inventories[inventory_name] = sorted(
            [
                _normalized_role_assignment_projection(item)
                for item in assignment_inventory
                if item.get("properties", {}).get("principalId") == principal
            ],
            key=lambda item: str(item["id"]).lower(),
        )
    if (
        source["principalDirectAssignments"] != expected_inventories
        or source["principalEffectiveAssignments"] != expected_inventories
    ):
        fail("rich direct/effective principal inventories are not exact")

    controller = prior.get("createPrivateControllerLockContainer", {}).get(
        "projection"
    )
    if source["controllerLockContainer"] != controller:
        fail("rich controller-lock source does not bind the exact private container")

    subnet_id = resources["integrationSubnet"]["resourceId"]
    vnet_id = resources["integrationVnet"]["resourceId"]
    expected_topology = {
        "virtualNetwork": {
            "id": vnet_id,
            "type": "Microsoft.Network/virtualNetworks",
            "addressSpacePrefixes": ["10.41.0.0/16"],
        },
        "integrationSubnet": {
            "id": subnet_id,
            "type": "Microsoft.Network/virtualNetworks/subnets",
            "virtualNetworkResourceId": vnet_id,
            "delegations": ["Microsoft.Web/serverFarms"],
            "serviceEndpoints": [
                {"service": "Microsoft.Storage", "provisioningState": "Succeeded"}
            ],
            "routeTableResourceId": None,
            "networkSecurityGroupResourceId": None,
        },
        "packageStorageAccount": {
            "id": resources["storageAccount"]["resourceId"],
            "type": "Microsoft.Storage/storageAccounts",
            "publicNetworkAccess": "Enabled",
            "allowBlobPublicAccess": False,
            "defaultAction": "Deny",
            "bypass": "None",
            "ipRules": [],
            "resourceAccessRules": [],
            "virtualNetworkRules": [
                {"id": subnet_id, "action": "Allow", "state": "Succeeded"}
            ],
        },
        "productionSite": {
            "id": resources["productionSite"]["resourceId"],
            "type": "Microsoft.Web/sites",
            "virtualNetworkSubnetId": subnet_id,
            "outboundVnetRouting": {
                "allTraffic": False,
                "applicationTraffic": True,
            },
            "legacyVnetRouteAllEnabled": True,
        },
    }
    if source["networkTopology"] != expected_topology:
        fail("rich network topology is not the exact non-mutating live topology")
    return source


def _validate_lease_canary_sources(
    value: Any,
    *,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    prior: Mapping[str, Mapping[str, Any]],
    operation_contexts: Mapping[str, Mapping[str, Any]],
    bridge_canary: Mapping[str, Any],
) -> dict[str, Any]:
    source = dict(
        _exact_keys(
            value,
            {
                "controllerLease",
                "activationFenceLease",
                "cleanupFastLane",
                "cleanupExpiryFallback",
            },
            "lease canary source proofs",
        )
    )
    controller = dict(
        _exact_keys(
            source["controllerLease"],
            {
                "observationStatus",
                "operationSourceProjection",
                "leaseIdSha256",
                "targetResourceId",
                "actor",
            },
            "controller lease source proof",
        )
    )
    controller_projection = _validate_operation_source_projection(
        controller["operationSourceProjection"],
        operation_id="exerciseControllerLeaseCanary",
        plan=plan,
        authorization=authorization,
        prior=prior,
        operation_context=operation_contexts.get("exerciseControllerLeaseCanary"),
    )
    controller_body = controller_projection["projection"]
    controller_actor = {
        "actorType": "authorized-local-operator",
        "actorObjectId": authorization["azure"]["accountObjectId"],
        "actorResourceId": "",
    }
    if (
        controller["observationStatus"] != "directly-observed"
        or controller["leaseIdSha256"]
        != sha256_bytes(plan["temporaryAccess"]["controllerLeaseId"].encode("utf-8"))
        or controller["targetResourceId"] != controller_body["url"]
        or controller["actor"] != controller_actor
    ):
        fail("controller lease source proof is not exact and operator-bound")

    resources = {item["id"]: item for item in plan["resourceInventory"]}
    bridge_identity = prior.get("createBridgeIdentity", {}).get("projection", {})
    configure = prior.get(
        "configureBridgeExactVersionedPackageAndCriticalSettings", {}
    ).get("projection", {})
    canary_operation = prior.get("startBridgeForBoundedCanary")
    activation = dict(
        _exact_keys(
            source["activationFenceLease"],
            {
                "observationStatus",
                "leaseIdSha256",
                "targetResourceId",
                "actor",
                "sourceControlSha256",
                "terminalOperationSourceProjectionSha256",
                "expectedActions",
                "expectedFinalLeaseState",
            },
            "activation-fence lease source proof",
        )
    )
    expected_activation_actor = {
        "actorType": "bridge-managed-identity",
        "actorObjectId": bridge_identity.get("principalId"),
        "actorResourceId": resources["bridgeIdentity"]["resourceId"],
    }
    if (
        activation["observationStatus"]
        != "source-derived-from-terminal-success-not-directly-observed"
        or activation["leaseIdSha256"]
        != sha256_bytes(
            plan["temporaryAccess"]["activationFenceLeaseId"].encode("utf-8")
        )
        or activation["targetResourceId"]
        != resources["activationFenceBlob"]["resourceId"]
        or activation["actor"] != expected_activation_actor
        or activation["sourceControlSha256"]
        != configure.get("bootstrapSelfTestControlSha256")
        or activation["terminalOperationSourceProjectionSha256"]
        != sha256_bytes(canonical_json_bytes(canary_operation))
        or activation["expectedActions"]
        != ["acquire", "read", "renew", "release", "head-available"]
        or activation["expectedFinalLeaseState"] != "Available"
        or bridge_canary["webJobTerminal"]["status"] != "Success"
        or bridge_canary["sourceDerivedExpectedMarker"]["observationStatus"]
        != "expected-not-observed"
    ):
        fail("activation-fence lease proof overclaims or is not source-derived")

    controller_sha = sha256_bytes(canonical_json_bytes(controller_projection))
    fast = dict(
        _exact_keys(
            source["cleanupFastLane"],
            {
                "observationStatus",
                "controllerOperationSourceProjectionSha256",
                "stateTransitions",
                "observedAt",
            },
            "controller cleanup fast-lane proof",
        )
    )
    fallback = dict(
        _exact_keys(
            source["cleanupExpiryFallback"],
            {
                "observationStatus",
                "controllerOperationSourceProjectionSha256",
                "deadlineSeconds",
                "stateTransitions",
                "observedAt",
            },
            "controller cleanup expiry-fallback proof",
        )
    )
    if (
        fast["observationStatus"] != "directly-observed"
        or fast["controllerOperationSourceProjectionSha256"] != controller_sha
        or fast["stateTransitions"] != controller_body["fastLane"]
        or fallback["observationStatus"] != "directly-observed"
        or fallback["controllerOperationSourceProjectionSha256"] != controller_sha
        or fallback["deadlineSeconds"]
        != plan["temporaryAccess"]["leaseDurationSeconds"]
        or fallback["stateTransitions"] != controller_body["expiryFallback"]
    ):
        fail("controller cleanup lease source proofs are not exact")
    _terminal_observed_at(
        fast["observedAt"], "controller cleanup fast-lane observedAt", authorization
    )
    _terminal_observed_at(
        fallback["observedAt"],
        "controller cleanup expiry-fallback observedAt",
        authorization,
    )
    return source


def sanitize_authorized_preflight_projection(
    projection: Mapping[str, Any],
) -> dict[str, Any]:
    """Remove the one raw operator address and secret-bearing settings map.

    The unsanitized canonical projection is transiently supplied so its digest
    can be checked against the external authorization.  Only this derived
    projection may be persisted in public S2 evidence.
    """

    sanitized = json.loads(canonical_json_bytes(projection).decode("utf-8"))
    admissions = sanitized.get("operationAdmissions")
    if not isinstance(admissions, list):
        fail("authorized preflight has no operation admissions")
    for admission in admissions:
        if not isinstance(admission, dict) or not isinstance(admission.get("context"), dict):
            fail("authorized preflight operation context is invalid")
        operation_id = admission.get("operationId")
        context = admission["context"]
        if operation_id in {"addOwnedUploaderIpv4Rule", "removeOwnedUploaderIpv4Rule"}:
            address = context.pop("uploaderIpv4", None)
            if not isinstance(address, str):
                fail("authorized uploader address is absent before sanitization")
            context["uploaderIpv4Sha256"] = sha256_bytes(address.encode("utf-8"))
        if operation_id == "configureBridgeExactVersionedPackageAndCriticalSettings":
            settings = context.pop("preAppSettings", None)
            if not isinstance(settings, dict):
                fail("authorized bridge settings prestate is absent before sanitization")
            if context.get("preAppSettingsSha256") != sha256_bytes(
                canonical_json_bytes(settings)
            ):
                fail("authorized bridge settings digest drifted before sanitization")
    _reject_terminal_secret_material(sanitized, "sanitized authorized preflight")
    return sanitized


def _validate_postcondition_source_projection(
    value: Any,
    *,
    postcondition_id: str,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    prior: Mapping[str, Mapping[str, Any]],
    operation_contexts: Mapping[str, Mapping[str, Any]],
    expected_probe_ids: Sequence[str],
    expected_journal: Sequence[Mapping[str, Any]] | None = None,
    validated_required_out: dict[str, Mapping[str, Any]] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]] | None]:
    """Purely validate one postcondition using exact operation and journal facts."""

    postcondition = next(
        (item for item in plan["postconditions"] if item["id"] == postcondition_id),
        None,
    )
    if postcondition is None:
        fail("terminal postcondition is outside the source plan")
    body = dict(
        _exact_keys(
            value,
            {
                "schemaVersion",
                "postconditionId",
                "predicateSha256",
                "semanticPolicy",
                "claimPersistenceProbes",
                "requiredOperationProjections",
                "localProjection",
            },
            f"terminal postcondition source projection {postcondition_id}",
        )
    )
    policy = _postcondition_semantic_policy(postcondition_id, plan)
    required = body["requiredOperationProjections"]
    claim_proofs = body["claimPersistenceProbes"]
    if (
        body["schemaVersion"] != 1
        or body["postconditionId"] != postcondition_id
        or body["predicateSha256"]
        != sha256_bytes(postcondition["predicate"].encode("utf-8"))
        or body["semanticPolicy"] != policy
        or not isinstance(claim_proofs, list)
        or len(claim_proofs) != len(expected_probe_ids)
        or not claim_proofs
        or not isinstance(required, list)
        or [
            candidate.get("operationId")
            for candidate in required
            if isinstance(candidate, Mapping)
        ]
        != policy["requiredOperationIds"]
    ):
        fail("terminal postcondition semantic source proof is incomplete")
    not_before = parse_time(authorization["validity"]["notBefore"], "authorization notBefore")
    expires_at = parse_time(authorization["validity"]["expiresAt"], "authorization expiresAt")
    claim_operation = prior.get("claimAzureSingleUseAuthorization")
    if not isinstance(claim_operation, Mapping):
        fail("terminal postcondition lacks the validated Azure claim")
    for index, (probe, probe_id) in enumerate(zip(claim_proofs, expected_probe_ids)):
        probe = _exact_keys(
            probe,
            {
                "id",
                "validatorId",
                "status",
                "responseSha256",
                "sourceProjection",
                "attempts",
                "startedAt",
                "observedAt",
            },
            f"terminal postcondition claim probe {index}",
        )
        if (
            probe["id"] != probe_id
            or probe["validatorId"] != f"postcondition:{postcondition_id}"
            or probe["status"] != 200
            or probe["responseSha256"] != claim_operation["responseSha256"]
            or probe["sourceProjection"] is not None
            or type(probe["attempts"]) is not int
            or not 1 <= probe["attempts"] <= 64
        ):
            fail("terminal postcondition claim persistence probe is fabricated")
        started = parse_time(probe["startedAt"], "postcondition claim probe startedAt")
        observed = parse_time(probe["observedAt"], "postcondition claim probe observedAt")
        if not not_before <= started <= observed <= expires_at:
            fail("terminal postcondition claim probe is outside authorization")

    for candidate in required:
        candidate = _exact_keys(
            candidate,
            {"operationId", "sourceProjections"},
            "terminal postcondition required operation",
        )
        projections = candidate["sourceProjections"]
        if not isinstance(projections, list) or len(projections) != 1:
            fail("terminal postcondition operation proof is not one exact readback")
        validated = _validate_operation_source_projection(
            projections[0],
            operation_id=candidate["operationId"],
            plan=plan,
            authorization=authorization,
            prior=prior,
            operation_context=operation_contexts.get(candidate["operationId"]),
        )
        permanent_projection = prior.get(candidate["operationId"])
        if permanent_projection is not None:
            for key in (
                "operationId",
                "family",
                "method",
                "url",
                "status",
                "target",
                "targetResourceId",
                "projection",
            ):
                if validated[key] != permanent_projection[key]:
                    fail("terminal postcondition readback drifted from the applied result")
        if validated_required_out is not None:
            prior_required = validated_required_out.get(candidate["operationId"])
            if prior_required is not None and any(
                validated[key] != prior_required[key]
                for key in (
                    "operationId",
                    "family",
                    "method",
                    "url",
                    "status",
                    "target",
                    "targetResourceId",
                    "projection",
                )
            ):
                fail("terminal postconditions disagree on an operation projection")
            validated_required_out[candidate["operationId"]] = validated

    resources = {item["id"]: item for item in plan["resourceInventory"]}
    local = body["localProjection"]
    family = policy["family"]
    journal: list[dict[str, Any]] | None = None
    if family == "local-source-dormancy":
        expected_contract, _ = load_json(ACTIVATION_CONTRACT_PATH)
        expected_local = {
            "contractPath": "contracts/private_release_mailbox_contract.json",
            "contractSha256": sha256_bytes(canonical_json_bytes(expected_contract)),
            "status": "source-dormant",
            "activationFieldCount": len(expected_contract["activation"]),
            "allActivationValuesNull": True,
        }
        if local != expected_local:
            fail("terminal source-dormancy postcondition is fabricated")
    elif family == "pairwise-identity-inventory":
        local = _exact_keys(local, {"identities", "pairwiseDistinct"}, "identity inventory")
        expected_identities: list[dict[str, Any]] = []
        for operation_id in policy["requiredOperationIds"]:
            candidate = prior.get(operation_id, {}).get("projection", {})
            expected_identities.append(
                {
                    "operationId": operation_id,
                    "clientId": (
                        candidate.get("appId")
                        if operation_id == "createPublisherServicePrincipal"
                        else candidate.get("clientId")
                    ),
                    "principalId": (
                        candidate.get("id")
                        if operation_id == "createPublisherServicePrincipal"
                        else candidate.get("principalId")
                    ),
                }
            )
        production = resources["productionSystemIdentity"]
        expected_identities.append(
            {
                "operationId": "fixedProductionSystemIdentity",
                "clientId": production["clientId"],
                "principalId": production["principalId"],
            }
        )
        clients = [item["clientId"] for item in expected_identities]
        principals = [item["principalId"] for item in expected_identities]
        if (
            local["identities"] != expected_identities
            or local["pairwiseDistinct"] is not True
            or len(set(clients)) != len(clients)
            or len(set(principals)) != len(principals)
        ):
            fail("terminal automation identity inventory is fabricated")
    elif family == "role-definition-and-assignment-inventories":
        local = _exact_keys(
            local,
            {"expectedRoleRecordCount", "roleDefinitions", "roleAssignments"},
            "role terminal inventory",
        )
        definitions = prior.get("createCustomRoleDefinitions", {}).get(
            "projection", {}
        ).get("roleDefinitions")
        assignments = prior.get("createExactRoleAssignments", {}).get(
            "projection", {}
        ).get("roleAssignments")
        if (
            local["expectedRoleRecordCount"] != len(plan["roleMatrix"])
            or local["roleDefinitions"] != definitions
            or local["roleAssignments"] != assignments
        ):
            fail("terminal role inventories are not exact source projections")
    elif family in {
        "production-pre-post-equality-and-zero-write-journal",
        "forbidden-target-journal-audit",
        "vault-posture-plus-no-journal-write",
    }:
        local = _exact_keys(
            local,
            {
                "schemaVersion",
                "recordCount",
                "mutationJournal",
                "journalSha256",
                "unresolvedIntentCount",
                "productionWriteCount",
                "acceptedContainerWriteJournal",
            },
            "terminal journal audit",
        )
        journal = _validate_sanitized_mutation_journal(
            local["mutationJournal"],
            plan=plan,
            authorization=authorization,
            operation_projections=prior,
            operation_contexts=operation_contexts,
        )
        if (
            local["schemaVersion"] != 1
            or local["recordCount"] != len(journal)
            or local["journalSha256"]
            != sha256_bytes(canonical_json_bytes(journal))
            or local["unresolvedIntentCount"] != 0
            or local["productionWriteCount"] != 0
            or local["acceptedContainerWriteJournal"] != []
            or (
                expected_journal is not None
                and list(expected_journal) != journal
            )
        ):
            fail("terminal journal audit is not exact")
    elif family == "terminal-source-inputs-ready-for-local-assembly":
        if expected_journal is None:
            fail("terminal source-input readiness lacks the validated journal")
        expected_outputs = plan["evidenceOutputs"]
        expected_local = {
            "status": "ready-for-create-only-local-terminal-assembly",
            "expectedOperationProofCount": len(
                [
                    item
                    for item in plan["mutations"]
                    if item["kind"] != "local-create-only-canonical-evidence"
                ]
            ),
            "expectedPriorPostconditionProofCount": next(
                index
                for index, item in enumerate(plan["postconditions"])
                if item["id"] == postcondition_id
            ),
            "mutationJournalSha256": sha256_bytes(
                canonical_json_bytes(list(expected_journal))
            ),
            "requiredS2EvidencePaths": [
                expected_outputs["provisioningEvidencePath"],
                expected_outputs["bridgeRuntimeReceiptPath"],
                expected_outputs["temporaryAccessCleanupReceiptPath"],
                expected_outputs["activationFenceReceiptPath"],
                expected_outputs["bridgeCanaryReceiptPath"],
            ],
            "terminalBundlePath": expected_outputs["terminalBundlePath"],
            "terminalBundleCreated": False,
        }
        if local != expected_local:
            fail("terminal source-input readiness is fabricated or circular")
    elif local != {
        "requiredOperationProjectionCount": len(policy["requiredOperationIds"])
    }:
        fail("terminal postcondition local proof is fabricated")
    return body, journal


def build_terminal_source_evidence(
    *,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    preflight_projection: Mapping[str, Any],
    operation_projections: Mapping[str, Mapping[str, Any]],
    operation_statuses: Mapping[str, str],
    operation_observed_at: Mapping[str, str],
    postcondition_projections: Sequence[Mapping[str, Any]],
    mutation_journal: Sequence[Mapping[str, Any]],
    package_readback_bytes: bytes | bytearray,
    production_boundary_post_execution: Mapping[str, Any],
    claimed_at: str,
    observed_at: str,
) -> dict[str, Any]:
    """Assemble one complete source-owned terminal snapshot from exact proofs.

    This function performs no I/O.  It is shared by the production executor and
    deterministic tests so receipt assembly never invents a second evidence
    vocabulary.  The returned object is passed back through
    :func:`validate_terminal_source_evidence` before any local S2 file is
    written.
    """

    reviewed_plan, plan_digest = load_plan()
    if canonical_json_bytes(plan) != canonical_json_bytes(reviewed_plan):
        fail("terminal source builder requires the exact reviewed plan")
    authorization_digest = sha256_bytes(canonical_json_bytes(authorization))
    if authorization["plan"]["sha256"] != plan_digest:
        fail("terminal source builder authorization does not bind the plan")
    raw_package = bytes(package_readback_bytes)
    if (
        sha256_bytes(raw_package) != authorization["plan"]["bridgePackageSha256"]
        or len(raw_package) != authorization["plan"]["bridgePackageSize"]
    ):
        fail("terminal package readback bytes are not the exact authorized package")

    resources = {item["id"]: item for item in plan["resourceInventory"]}
    admissions = preflight_projection.get("operationAdmissions")
    if not isinstance(admissions, list):
        fail("terminal source builder lacks exact operation admissions")
    contexts = {
        item.get("operationId"): item.get("context")
        for item in admissions
        if isinstance(item, Mapping)
    }
    if (
        len(contexts) != len(admissions)
        or any(not isinstance(value, Mapping) for value in contexts.values())
    ):
        fail("terminal source builder operation contexts are incomplete")

    expected_operation_ids = [
        item["id"]
        for item in plan["mutations"]
        if item["kind"] != "local-create-only-canonical-evidence"
    ]
    if set(operation_projections) != set(expected_operation_ids):
        fail("terminal source builder operation projection universe is incomplete")
    if set(operation_statuses) != set(expected_operation_ids):
        fail("terminal source builder operation status universe is incomplete")
    if set(operation_observed_at) != set(expected_operation_ids):
        fail("terminal source builder operation timestamps are incomplete")

    operations: dict[str, Mapping[str, Any]] = {}
    for operation_id in expected_operation_ids:
        # The full validator later replays prior-dependent semantics in plan
        # order.  Here we retain exact canonical copies only.
        candidate = json.loads(
            canonical_json_bytes(operation_projections[operation_id]).decode("utf-8")
        )
        if candidate.get("operationId") != operation_id:
            fail("terminal source builder operation identity drifted")
        operations[operation_id] = candidate
        _terminal_observed_at(
            operation_observed_at[operation_id],
            f"{operation_id} terminal observation",
            authorization,
        )

    journal = json.loads(canonical_json_bytes(list(mutation_journal)).decode("utf-8"))
    claim_results = [
        item
        for item in journal
        if item.get("phase") == "result"
        and item.get("operationId") == "claimAzureSingleUseAuthorization"
    ]
    if len(claim_results) != 1 or claim_results[0].get("status") != 201:
        fail("terminal source builder lacks the exact Azure 201 claim result")

    outcome_by_status = {
        "created": "created",
        "adopted-exact": "adopted-exact",
        "applied-exact": "updated-exact",
        "removed-exact": "deleted-exact",
        "verified-exact": "read-back-exact",
    }
    permanent_mutations = [
        item
        for item in plan["mutations"]
        if item.get("temporary") is not True
        and item["kind"] != "local-create-only-canonical-evidence"
    ]
    permanent: list[dict[str, Any]] = []
    for mutation in permanent_mutations:
        status = operation_statuses[mutation["id"]]
        outcome = outcome_by_status.get(status)
        if outcome is None:
            fail("terminal source builder operation status is not terminal exact")
        permanent.append(
            {
                "mutationId": mutation["id"],
                "target": mutation["target"],
                "kind": mutation["kind"],
                "outcome": outcome,
                "sourceProjection": operations[mutation["id"]],
                "observedAt": operation_observed_at[mutation["id"]],
            }
        )

    postconditions = json.loads(
        canonical_json_bytes(list(postcondition_projections)).decode("utf-8")
    )
    if [item.get("postconditionId") for item in postconditions] != [
        item["id"] for item in plan["postconditions"]
    ]:
        fail("terminal source builder postcondition universe is incomplete")

    def projection(operation_id: str) -> Mapping[str, Any]:
        value = operations[operation_id].get("projection")
        if not isinstance(value, Mapping):
            fail(f"terminal source builder projection is absent: {operation_id}")
        return value

    application = projection("createPublisherApplication")
    service = projection("createPublisherServicePrincipal")
    assignment_values = projection("createExactRoleAssignments").get(
        "roleAssignments"
    )
    if not isinstance(assignment_values, list):
        fail("terminal source builder lacks role assignments")
    assignment_by_name = {
        str(item.get("name", "")).lower(): item
        for item in assignment_values
        if isinstance(item, Mapping)
    }
    custom_definitions = _custom_role_definition_specs(plan)
    custom_context = contexts["createCustomRoleDefinitions"]
    built_in_definitions = _validate_builtin_role_definition_projections(
        custom_context.get("builtInRoleDefinitionProjections"), plan
    )
    role_definitions: dict[str, Any] = {}
    role_assignments: dict[str, Any] = {}
    for role in plan["roleMatrix"]:
        role_definitions[role["name"]] = (
            built_in_definitions[role["definitionId"]]
            if role.get("definitionKind") == "BuiltInRole"
            else custom_definitions[role["definitionId"]]
        )
        assignment = assignment_by_name.get(str(role["assignmentId"]).lower())
        if assignment is None:
            fail(f"terminal source builder lacks role assignment {role['name']}")
        role_assignments[role["name"]] = _normalized_role_assignment_projection(
            assignment
        )

    principal_sources = {
        "publisher": projection("createPublisherServicePrincipal").get("id"),
        "bridge": projection("createBridgeIdentity").get("principalId"),
        "registryWriter": projection("adoptExistingRegistryWriterIdentity").get(
            "principalId"
        ),
        "registryReader": projection("adoptExistingRegistryReaderIdentity").get(
            "principalId"
        ),
        "signer": projection("createSignerIdentity").get("principalId"),
        "productionActivation": projection(
            "createProductionActivationIdentity"
        ).get("principalId"),
        "productionSystem": resources["productionSystemIdentity"]["principalId"],
    }
    inventories: dict[str, list[Any]] = {}
    for name, principal_id in principal_sources.items():
        _guid(principal_id, f"terminal source builder {name} principal")
        inventories[name] = sorted(
            [
                _normalized_role_assignment_projection(item)
                for item in assignment_values
                if item.get("properties", {}).get("principalId") == principal_id
            ],
            key=lambda item: str(item["id"]).lower(),
        )

    sole_fic_inventory = projection(
        "createSolePublisherFicToSignedBootstrapSource"
    ).get("federatedIdentityCredentials")
    if (
        not isinstance(sole_fic_inventory, list)
        or len(sole_fic_inventory) != 1
        or not isinstance(sole_fic_inventory[0], Mapping)
    ):
        fail("terminal source builder lacks the sole concrete publisher FIC")
    sole_fic = json.loads(
        canonical_json_bytes(sole_fic_inventory[0]).decode("utf-8")
    )
    subnet_id = resources["integrationSubnet"]["resourceId"]
    vnet_id = resources["integrationVnet"]["resourceId"]
    rich_provisioning = {
        "publisherApplication": {
            "id": application.get("id"),
            "appId": application.get("appId"),
            "signInAudience": application.get("signInAudience"),
            "passwordCredentialKeyIds": [],
            "keyCredentialKeyIds": [],
        },
        "publisherServicePrincipal": {
            "id": service.get("id"),
            "appId": service.get("appId"),
            "accountEnabled": service.get("accountEnabled"),
            "servicePrincipalType": service.get("servicePrincipalType"),
            "passwordCredentialKeyIds": [],
            "keyCredentialKeyIds": [],
        },
        "solePublisherFederatedCredentials": [sole_fic],
        "roleDefinitions": role_definitions,
        "roleAssignments": role_assignments,
        "principalDirectAssignments": inventories,
        "principalEffectiveAssignments": json.loads(
            canonical_json_bytes(inventories).decode("utf-8")
        ),
        "controllerLockContainer": projection(
            "createPrivateControllerLockContainer"
        ),
        "networkTopology": {
            "virtualNetwork": {
                "id": vnet_id,
                "type": "Microsoft.Network/virtualNetworks",
                "addressSpacePrefixes": ["10.41.0.0/16"],
            },
            "integrationSubnet": {
                "id": subnet_id,
                "type": "Microsoft.Network/virtualNetworks/subnets",
                "virtualNetworkResourceId": vnet_id,
                "delegations": ["Microsoft.Web/serverFarms"],
                "serviceEndpoints": [
                    {
                        "service": "Microsoft.Storage",
                        "provisioningState": "Succeeded",
                    }
                ],
                "routeTableResourceId": None,
                "networkSecurityGroupResourceId": None,
            },
            "packageStorageAccount": {
                "id": resources["storageAccount"]["resourceId"],
                "type": "Microsoft.Storage/storageAccounts",
                "publicNetworkAccess": "Enabled",
                "allowBlobPublicAccess": False,
                "defaultAction": "Deny",
                "bypass": "None",
                "ipRules": [],
                "resourceAccessRules": [],
                "virtualNetworkRules": [
                    {"id": subnet_id, "action": "Allow", "state": "Succeeded"}
                ],
            },
            "productionSite": {
                "id": resources["productionSite"]["resourceId"],
                "type": "Microsoft.Web/sites",
                "virtualNetworkSubnetId": subnet_id,
                "outboundVnetRouting": {
                    "allTraffic": False,
                    "applicationTraffic": True,
                },
                "legacyVnetRouteAllEnabled": True,
            },
        },
    }

    cleanup_operations = {
        "packageIpv4Rule": "removeOwnedUploaderIpv4Rule",
        "packageUploaderRole": "removeOwnedUploaderPackageRole",
        "operatorKeyReadRole": "removeOwnedOperatorKeyReadRole",
        "operatorFenceRole": "removeOwnedOperatorFenceBootstrapRole",
        "operatorControllerRole": "removeOwnedOperatorControllerCanaryRole",
    }
    cleanup = {
        name: {
            "httpStatus": 200 if name == "packageIpv4Rule" else 404,
            "present": False,
            "sanitizedProjection": operations[operation_id],
            "observedAt": operation_observed_at[operation_id],
        }
        for name, operation_id in cleanup_operations.items()
    }

    worm_mapping = {
        "acceptedReleases": (
            "acceptedContainer",
            "extendAcceptedRetentionFrom30To91Days",
        ),
        "webJobResults": ("resultContainer", "extendResultRetentionFrom30To91Days"),
        "deploymentPackages": ("packageContainer", "lockPackageRetentionAt91Days"),
    }
    worm_sources = {
        name: {
            "container": {
                "id": resources[resource_key]["resourceId"],
                "name": f"default/{resources[resource_key]['name']}",
                "type": (
                    "Microsoft.Storage/storageAccounts/blobServices/containers"
                ),
                "publicAccess": "None",
            },
            "policy": _worm_final_policy_projection(
                operations[operation_id]["projection"]
            ),
        }
        for name, (resource_key, operation_id) in worm_mapping.items()
    }

    upload = projection("uploadVersionedBridgePackage")
    reader = projection("adoptExistingRegistryReaderIdentity")
    configure = projection(
        "configureBridgeExactVersionedPackageAndCriticalSettings"
    )
    canary_operation = operations["startBridgeForBoundedCanary"]
    canary = canary_operation["projection"]
    terminal = canary.get("terminalHistory")
    if not isinstance(terminal, Mapping) or terminal.get("status") != "Success":
        fail("terminal source builder lacks exact WebJob terminal Success")
    bridge_canary = {
        "webJobTerminal": {
            "status": "Success",
            "invocationId": terminal.get("webJobsRunId"),
            "sourceSha": authorization["source"]["mergedMain"]["commitSha"],
            "packageSha256": authorization["plan"]["bridgePackageSha256"],
            "packageVersionId": upload.get("versionId"),
            "startedAt": terminal.get("startedAt"),
            "completedAt": terminal.get("endedAt"),
        },
        "sourceDerivedExpectedMarker": _source_derived_bridge_marker(
            plan=plan, authorization=authorization, prior=operations
        ),
    }
    controller = operations["exerciseControllerLeaseCanary"]
    controller_body = projection("exerciseControllerLeaseCanary")
    controller_sha = sha256_bytes(canonical_json_bytes(controller))
    lease_sources = {
        "controllerLease": {
            "observationStatus": "directly-observed",
            "operationSourceProjection": controller,
            "leaseIdSha256": sha256_bytes(
                plan["temporaryAccess"]["controllerLeaseId"].encode("utf-8")
            ),
            "targetResourceId": controller_body["url"],
            "actor": {
                "actorType": "authorized-local-operator",
                "actorObjectId": authorization["azure"]["accountObjectId"],
                "actorResourceId": "",
            },
        },
        "activationFenceLease": {
            "observationStatus": (
                "source-derived-from-terminal-success-not-directly-observed"
            ),
            "leaseIdSha256": sha256_bytes(
                plan["temporaryAccess"]["activationFenceLeaseId"].encode("utf-8")
            ),
            "targetResourceId": resources["activationFenceBlob"]["resourceId"],
            "actor": {
                "actorType": "bridge-managed-identity",
                "actorObjectId": projection("createBridgeIdentity").get(
                    "principalId"
                ),
                "actorResourceId": resources["bridgeIdentity"]["resourceId"],
            },
            "sourceControlSha256": configure.get(
                "bootstrapSelfTestControlSha256"
            ),
            "terminalOperationSourceProjectionSha256": sha256_bytes(
                canonical_json_bytes(canary_operation)
            ),
            "expectedActions": [
                "acquire",
                "read",
                "renew",
                "release",
                "head-available",
            ],
            "expectedFinalLeaseState": "Available",
        },
        "cleanupFastLane": {
            "observationStatus": "directly-observed",
            "controllerOperationSourceProjectionSha256": controller_sha,
            "stateTransitions": controller_body["fastLane"],
            "observedAt": operation_observed_at["exerciseControllerLeaseCanary"],
        },
        "cleanupExpiryFallback": {
            "observationStatus": "directly-observed",
            "controllerOperationSourceProjectionSha256": controller_sha,
            "deadlineSeconds": plan["temporaryAccess"]["leaseDurationSeconds"],
            "stateTransitions": controller_body["expiryFallback"],
            "observedAt": operation_observed_at["exerciseControllerLeaseCanary"],
        },
    }

    claim_projection = projection("claimAzureSingleUseAuthorization")
    production_before = _validate_production_boundary_projection(
        preflight_projection["productionBoundaryObservation"]["sourceProjection"],
        plan,
    )
    production_after = _validate_production_boundary_projection(
        production_boundary_post_execution, plan
    )
    accepted_gate = {
        "status": "deferred-required-post-s2",
        "requiredAfter": "separately-authorized-publisher-fic-repin",
        "requiredBefore": "accepted-release-publication-or-production-deploy",
        "acceptedContainerResourceId": resources["acceptedContainer"]["resourceId"],
    }
    evidence = {
        "schemaVersion": 1,
        "evidenceType": "paperdesk-private-release-v2-bootstrap-source-evidence-v1",
        "authorizationId": authorization["authorizationId"],
        "authorizationSha256": authorization_digest,
        "mergedSourceSha": authorization["source"]["mergedMain"]["commitSha"],
        "treeSha": authorization["source"]["mergedMain"]["treeSha"],
        "planSha256": plan_digest,
        "authorizedPreflightProjection": sanitize_authorized_preflight_projection(
            preflight_projection
        ),
        "claimReceipt": {
            "schemaVersion": 1,
            "evidenceType": (
                "paperdesk-private-release-v2-bootstrap-one-shot-claim-proof-v1"
            ),
            "authorizationId": authorization["authorizationId"],
            "authorizationSha256": authorization_digest,
            "source": {
                "mergedSourceSha": authorization["source"]["mergedMain"][
                    "commitSha"
                ],
                "treeSha": authorization["source"]["mergedMain"]["treeSha"],
            },
            "plan": {
                "path": authorization["plan"]["path"],
                "sha256": plan_digest,
            },
            "package": {
                "sourceSha": authorization["plan"]["bridgePackageSourceSha"],
                "sha256": authorization["plan"]["bridgePackageSha256"],
                "size": authorization["plan"]["bridgePackageSize"],
            },
            "azureClaimResourceId": authorization["singleUse"][
                "azureClaimResourceId"
            ],
            "createHttpStatus": 201,
            "createResponseProjection": claim_projection,
            "readbackHttpStatus": operations[
                "claimAzureSingleUseAuthorization"
            ]["status"],
            "readbackProjection": json.loads(
                canonical_json_bytes(claim_projection).decode("utf-8")
            ),
            "claimedAt": claimed_at,
            "observedAt": operation_observed_at[
                "claimAzureSingleUseAuthorization"
            ],
        },
        "allOperationProjections": [
            {
                "operationId": operation_id,
                "sourceProjection": operations[operation_id],
                "observedAt": operation_observed_at[operation_id],
            }
            for operation_id in expected_operation_ids
        ],
        "permanentMutationProjections": permanent,
        "postconditionProjections": postconditions,
        "packageReadbackProjection": {
            "blobName": upload.get("blob"),
            "versionId": upload.get("versionId"),
            "etag": upload.get("etag"),
            "httpStatus": 200,
            "bytesObservedInMemory": True,
            "bytesSha256": sha256_bytes(raw_package),
            "size": len(raw_package),
            "metadataSha256": authorization["plan"]["bridgePackageSha256"],
            "observedAt": operation_observed_at["uploadVersionedBridgePackage"],
        },
        "managedIdentityFetchResponseProjection": {
            "evidenceMode": (
                "source-derived-from-terminal-success-not-directly-observed"
            ),
            "directPackageBytesObservedByExecutor": False,
            "identityResourceId": reader.get("id"),
            "identityClientId": reader.get("clientId"),
            "identityPrincipalId": reader.get("principalId"),
            "authentication": "platform-run-from-package-managed-identity",
            "packageBlobName": upload.get("blob"),
            "packageVersionId": upload.get("versionId"),
            "expectedPackageSha256": authorization["plan"][
                "bridgePackageSha256"
            ],
            "expectedPackageSize": authorization["plan"]["bridgePackageSize"],
            "sourceControlSha256": configure.get(
                "bootstrapSelfTestControlSha256"
            ),
            "webJobInvocationId": terminal.get("webJobsRunId"),
            "terminalStatus": "Success",
            "observedAt": operation_observed_at["startBridgeForBoundedCanary"],
        },
        "bridgeCanaryProof": bridge_canary,
        "leaseCanaryProofs": lease_sources,
        "richProvisioningSourceProjections": rich_provisioning,
        "cleanupAbsenceProjections": cleanup,
        "wormSourceProjections": worm_sources,
        "productionBoundary": {
            "authorizedPreflightProjection": production_before,
            "postExecutionProjection": production_after,
            "projectionsEqual": production_before == production_after,
            "journaledProductionWriteCount": 0,
            "acceptedContainerWriteJournal": [],
            "acceptedReleaseObservationGate": accepted_gate,
            "mutationJournal": journal,
            "observedAt": observed_at,
        },
        "observedAt": observed_at,
    }
    return validate_terminal_source_evidence(
        plan=plan,
        authorization=authorization,
        preflight_projection=preflight_projection,
        evidence=evidence,
    )


def validate_terminal_source_evidence(
    *,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    preflight_projection: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    """Purely revalidate every terminal source projection.

    Receipt construction calls this function before it can emit a successful
    bundle.  It deliberately reuses the executor's exact operation validator
    contracts and terminal postcondition semantic policies; ordered IDs and
    opaque digests are never sufficient.
    """

    validated_authorization = validate_authorization_evidence(
        authorization,
        plan=plan,
        plan_sha256=load_plan()[1],
        package={
            "sha256": authorization["plan"]["bridgePackageSha256"],
            "size": authorization["plan"]["bridgePackageSize"],
        },
    )
    if validated_authorization.document != authorization:
        fail("terminal source authorization evidence changed during validation")
    source = dict(
        _exact_keys(
            evidence,
            {
                "schemaVersion",
                "evidenceType",
                "authorizationId",
                "authorizationSha256",
                "mergedSourceSha",
                "treeSha",
                "planSha256",
                "authorizedPreflightProjection",
                "claimReceipt",
                "allOperationProjections",
                "permanentMutationProjections",
                "postconditionProjections",
                "packageReadbackProjection",
                "managedIdentityFetchResponseProjection",
                "bridgeCanaryProof",
                "leaseCanaryProofs",
                "richProvisioningSourceProjections",
                "cleanupAbsenceProjections",
                "wormSourceProjections",
                "productionBoundary",
                "observedAt",
            },
            "terminal source evidence",
        )
    )
    authorization_digest = sha256_bytes(canonical_json_bytes(authorization))
    reviewed_plan, plan_digest = load_plan()
    if canonical_json_bytes(plan) != canonical_json_bytes(reviewed_plan):
        fail("terminal source evidence was not validated against the reviewed plan file")
    if (
        source["schemaVersion"] != 1
        or source["evidenceType"]
        != "paperdesk-private-release-v2-bootstrap-source-evidence-v1"
        or source["authorizationId"] != authorization["authorizationId"]
        or source["authorizationSha256"] != authorization_digest
        or source["mergedSourceSha"]
        != authorization["source"]["mergedMain"]["commitSha"]
        or source["treeSha"] != authorization["source"]["mergedMain"]["treeSha"]
        or source["planSha256"] != plan_digest
        or authorization["plan"]["sha256"] != plan_digest
        or source["authorizedPreflightProjection"]
        != sanitize_authorized_preflight_projection(preflight_projection)
        or sha256_bytes(canonical_json_bytes(preflight_projection))
        != authorization["observedPreflight"]["sha256"]
    ):
        fail("terminal source evidence identity, plan, or preflight binding is invalid")
    observed_at = parse_time(source["observedAt"], "terminal source evidence observedAt")
    not_before = parse_time(authorization["validity"]["notBefore"], "authorization notBefore")
    expires_at = parse_time(authorization["validity"]["expiresAt"], "authorization expiresAt")
    if not not_before <= observed_at <= expires_at:
        fail("terminal source evidence falls outside the authorization window")

    claim = _exact_keys(
        source["claimReceipt"],
        {
            "schemaVersion",
            "evidenceType",
            "authorizationId",
            "authorizationSha256",
            "source",
            "plan",
            "package",
            "azureClaimResourceId",
            "createHttpStatus",
            "createResponseProjection",
            "readbackHttpStatus",
            "readbackProjection",
            "claimedAt",
            "observedAt",
        },
        "terminal Azure claim receipt",
    )
    expected_claim_projection = {
        "resourceId": authorization["singleUse"]["azureClaimResourceId"],
        "deploymentName": authorization["singleUse"]["azureClaimResourceId"].rsplit("/", 1)[-1],
        "provisioningState": "Succeeded",
        "claim": {
            "authorizationId": authorization["authorizationId"],
            "authorizationSha256": authorization_digest,
            "sourceSha": authorization["source"]["mergedMain"]["commitSha"],
            "planSha256": plan_digest,
            "packageSha256": authorization["plan"]["bridgePackageSha256"],
        },
    }
    if (
        claim["schemaVersion"] != 1
        or claim["evidenceType"]
        != "paperdesk-private-release-v2-bootstrap-one-shot-claim-proof-v1"
        or claim["authorizationId"] != authorization["authorizationId"]
        or claim["authorizationSha256"] != authorization_digest
        or claim["source"]
        != {
            "mergedSourceSha": authorization["source"]["mergedMain"]["commitSha"],
            "treeSha": authorization["source"]["mergedMain"]["treeSha"],
        }
        or claim["plan"]
        != {"path": authorization["plan"]["path"], "sha256": plan_digest}
        or claim["package"]
        != {
            "sourceSha": authorization["plan"]["bridgePackageSourceSha"],
            "sha256": authorization["plan"]["bridgePackageSha256"],
            "size": authorization["plan"]["bridgePackageSize"],
        }
        or claim["azureClaimResourceId"]
        != authorization["singleUse"]["azureClaimResourceId"]
        or claim["createHttpStatus"] != 201
        or claim["readbackHttpStatus"] != 200
        or claim["createResponseProjection"] != expected_claim_projection
        or claim["readbackProjection"] != expected_claim_projection
    ):
        fail("terminal Azure claim receipt is not exact")
    claim_times = {
        field: parse_time(claim[field], f"terminal claim {field}")
        for field in ("claimedAt", "observedAt")
    }
    for field, stamp in claim_times.items():
        if not not_before <= stamp <= expires_at:
            fail("terminal Azure claim timestamp is outside authorization")
    claimed_at = claim_times["claimedAt"]
    if not claimed_at <= claim_times["observedAt"] <= observed_at:
        fail("terminal Azure claim chronology is outside actual execution")

    expected_permanent = [
        item
        for item in plan["mutations"]
        if item.get("temporary") is not True
        and item["kind"] != "local-create-only-canonical-evidence"
    ]
    admissions = preflight_projection.get("operationAdmissions")
    if not isinstance(admissions, list):
        fail("terminal source evidence has no authorized operation admissions")
    operation_contexts: dict[str, Mapping[str, Any]] = {}
    for admission in admissions:
        if not isinstance(admission, Mapping):
            fail("terminal source evidence operation admission is invalid")
        operation_id = admission.get("operationId")
        context = admission.get("context")
        if (
            not isinstance(operation_id, str)
            or operation_id in operation_contexts
            or not isinstance(context, Mapping)
        ):
            fail("terminal source evidence operation admissions are duplicate or incomplete")
        operation_contexts[operation_id] = context
    resources = {item["id"]: item for item in plan["resourceInventory"]}
    expected_all_operations = [
        item
        for item in plan["mutations"]
        if item["kind"] != "local-create-only-canonical-evidence"
    ]
    all_values = source["allOperationProjections"]
    if not isinstance(all_values, list) or len(all_values) != len(
        expected_all_operations
    ):
        fail("terminal operation projection universe is incomplete")
    validated_operations: dict[str, Mapping[str, Any]] = {}
    for index, (item, mutation) in enumerate(
        zip(all_values, expected_all_operations)
    ):
        entry = _exact_keys(
            item,
            {"operationId", "sourceProjection", "observedAt"},
            f"terminal operation projection {index}",
        )
        if entry["operationId"] != mutation["id"]:
            fail("terminal operation projections are reordered")
        stamp = parse_time(entry["observedAt"], f"{mutation['id']} observedAt")
        if not claimed_at <= stamp <= observed_at:
            fail("terminal operation observation is outside actual execution")
        validated_operations[mutation["id"]] = (
            _validate_operation_source_projection(
                entry["sourceProjection"],
                operation_id=mutation["id"],
                plan=plan,
                authorization=authorization,
                prior=validated_operations,
                operation_context=operation_contexts.get(mutation["id"]),
            )
        )

    permanent = source["permanentMutationProjections"]
    if not isinstance(permanent, list) or len(permanent) != len(expected_permanent):
        fail("terminal permanent mutation projection universe is incomplete")
    allowed_outcomes = {
        "created",
        "adopted-exact",
        "updated-exact",
        "deleted-exact",
        "read-back-exact",
    }
    for index, (item, mutation) in enumerate(zip(permanent, expected_permanent)):
        entry = _exact_keys(
            item,
            {
                "mutationId",
                "target",
                "kind",
                "outcome",
                "sourceProjection",
                "observedAt",
            },
            f"terminal permanent mutation {index}",
        )
        if (
            entry["mutationId"] != mutation["id"]
            or entry["target"] != mutation["target"]
            or entry["kind"] != mutation["kind"]
            or entry["outcome"] not in allowed_outcomes
            or entry["outcome"]
            != _expected_permanent_outcome(
                mutation, operation_contexts.get(mutation["id"], {})
            )
        ):
            fail("terminal permanent mutation is not in exact plan order")
        stamp = parse_time(entry["observedAt"], f"{mutation['id']} observedAt")
        if not claimed_at <= stamp <= observed_at:
            fail("terminal permanent mutation observation is outside actual execution")
        if entry["sourceProjection"] != validated_operations[mutation["id"]]:
            fail("terminal permanent mutation differs from operation universe")

    postcondition_values = source["postconditionProjections"]
    if not isinstance(postcondition_values, list) or len(postcondition_values) != len(
        plan["postconditions"]
    ):
        fail("terminal postcondition projection universe is incomplete")
    postcondition_admissions = preflight_projection.get("postconditionAdmissions")
    if not isinstance(postcondition_admissions, list):
        fail("authorized preflight has no postcondition admissions")
    postcondition_admission_by_id = {
        item.get("postconditionId"): item
        for item in postcondition_admissions
        if isinstance(item, Mapping)
    }
    if len(postcondition_admission_by_id) != len(postcondition_admissions):
        fail("authorized postcondition admissions are duplicate or invalid")
    validated_journal: list[dict[str, Any]] | None = None
    validated_all_operations: dict[str, Mapping[str, Any]] = dict(
        validated_operations
    )
    for index, (item, postcondition) in enumerate(
        zip(postcondition_values, plan["postconditions"])
    ):
        entry = _exact_keys(
            item,
            {"postconditionId", "sourceProjection", "observedAt"},
            f"terminal postcondition {index}",
        )
        if entry["postconditionId"] != postcondition["id"]:
            fail("terminal postcondition projections are reordered")
        stamp = parse_time(entry["observedAt"], f"{postcondition['id']} observedAt")
        if not claimed_at <= stamp <= observed_at:
            fail("terminal postcondition observation is outside actual execution")
        authorized_postcondition = postcondition_admission_by_id.get(postcondition["id"])
        expected_probe_ids = (
            authorized_postcondition.get("probeIds")
            if isinstance(authorized_postcondition, Mapping)
            else None
        )
        if not isinstance(expected_probe_ids, list):
            fail("terminal postcondition is not bound to authorized probe IDs")
        _validated_postcondition, postcondition_journal = (
            _validate_postcondition_source_projection(
                entry["sourceProjection"],
                postcondition_id=postcondition["id"],
                plan=plan,
                authorization=authorization,
                prior=validated_operations,
                operation_contexts=operation_contexts,
                expected_probe_ids=expected_probe_ids,
                expected_journal=validated_journal,
                validated_required_out=validated_all_operations,
            )
        )
        if postcondition_journal is not None and validated_journal is None:
            validated_journal = postcondition_journal

    boundary = _exact_keys(
        source["productionBoundary"],
        {
            "authorizedPreflightProjection",
            "postExecutionProjection",
            "projectionsEqual",
            "journaledProductionWriteCount",
            "acceptedContainerWriteJournal",
            "acceptedReleaseObservationGate",
            "mutationJournal",
            "observedAt",
        },
        "terminal production boundary",
    )
    boundary_projection_keys = {
        "sitePosture",
        "appSettingsSha256",
        "deploymentInventory",
        "oneDeployInventory",
    }
    before_boundary = _exact_keys(
        boundary["authorizedPreflightProjection"],
        boundary_projection_keys,
        "authorized production preflight boundary",
    )
    after_boundary = _exact_keys(
        boundary["postExecutionProjection"],
        boundary_projection_keys,
        "post-execution production boundary",
    )
    expected_authorized_boundary = _validate_production_boundary_projection(
        preflight_projection["productionBoundaryObservation"]["sourceProjection"],
        plan,
    )
    before_boundary = _validate_production_boundary_projection(before_boundary, plan)
    after_boundary = _validate_production_boundary_projection(after_boundary, plan)
    if before_boundary != expected_authorized_boundary:
        fail("production boundary prestate is not the exact authorized observation")
    boundary_journal = _validate_sanitized_mutation_journal(
        boundary["mutationJournal"],
        plan=plan,
        authorization=authorization,
        operation_projections=validated_all_operations,
        operation_contexts=operation_contexts,
        execution_started_at=parse_time(
            claim["claimedAt"], "terminal execution claimedAt"
        ),
        execution_completed_at=observed_at,
    )
    if validated_journal is not None and boundary_journal != validated_journal:
        fail("production boundary journal differs from postcondition proof")
    production_writes = []
    accepted_blob_writes = []
    for candidate in boundary_journal:
        if candidate["phase"] != "intent":
            continue
        production_write, accepted_write = _forbidden_release_mutation_classes(
            candidate["method"], candidate["targetUrl"], plan
        )
        if production_write:
            production_writes.append(candidate)
        if accepted_write:
            accepted_blob_writes.append(candidate)
    expected_gate = {
        "status": "deferred-required-post-s2",
        "requiredAfter": "separately-authorized-publisher-fic-repin",
        "requiredBefore": "accepted-release-publication-or-production-deploy",
        "acceptedContainerResourceId": resources["acceptedContainer"]["resourceId"],
    }
    boundary_observed = parse_time(
        boundary["observedAt"], "production boundary observedAt"
    )
    if (
        before_boundary != after_boundary
        or boundary["projectionsEqual"] is not True
        or production_writes
        or accepted_blob_writes
        or boundary["journaledProductionWriteCount"] != 0
        or boundary["acceptedContainerWriteJournal"] != []
        or boundary["acceptedReleaseObservationGate"] != expected_gate
        or not not_before <= boundary_observed <= expires_at
    ):
        fail("terminal production boundary falsely claims an unchanged production state")

    package_source = _validate_package_readback_source(
        source["packageReadbackProjection"],
        authorization=authorization,
        prior=validated_all_operations,
    )
    managed_source = _validate_managed_identity_fetch_source(
        source["managedIdentityFetchResponseProjection"],
        plan=plan,
        authorization=authorization,
        prior=validated_all_operations,
    )
    bridge_source = _validate_bridge_canary_source(
        source["bridgeCanaryProof"],
        plan=plan,
        authorization=authorization,
        prior=validated_all_operations,
    )
    lease_source = _validate_lease_canary_sources(
        source["leaseCanaryProofs"],
        plan=plan,
        authorization=authorization,
        prior=validated_all_operations,
        operation_contexts=operation_contexts,
        bridge_canary=bridge_source,
    )
    rich_source = _validate_rich_provisioning_sources(
        source["richProvisioningSourceProjections"],
        plan=plan,
        authorization=authorization,
        prior=validated_all_operations,
        operation_contexts=operation_contexts,
    )
    cleanup_source = _validate_cleanup_absence_sources(
        source["cleanupAbsenceProjections"],
        plan=plan,
        authorization=authorization,
        prior=validated_all_operations,
        operation_contexts=operation_contexts,
    )
    worm_source = _validate_worm_sources(
        source["wormSourceProjections"], plan=plan, prior=validated_all_operations
    )
    if (
        package_source != source["packageReadbackProjection"]
        or managed_source != source["managedIdentityFetchResponseProjection"]
        or bridge_source != source["bridgeCanaryProof"]
        or lease_source != source["leaseCanaryProofs"]
        or rich_source != source["richProvisioningSourceProjections"]
        or cleanup_source != source["cleanupAbsenceProjections"]
        or worm_source != source["wormSourceProjections"]
    ):
        fail("terminal rich source validators changed a supplied projection")
    _reject_terminal_secret_material(source)
    # Canonical round-trip rejects Python-only types and normalizes no fields;
    # the receipt layer requires exact identity on return.
    if json.loads(canonical_json_bytes(source).decode("utf-8")) != source:
        fail("terminal source evidence is not canonical JSON")
    return source


def _terminal_receipt_header(
    model: Mapping[str, Any],
    component: str,
    status: str,
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    receipt_types = model.get("receiptTypes")
    if not isinstance(receipt_types, Mapping) or not isinstance(
        receipt_types.get(component), str
    ):
        fail(f"terminal receipt model lacks {component}")
    return {
        "schemaVersion": 1,
        "receiptType": receipt_types[component],
        "status": status,
        "authorizationId": authorization["authorizationId"],
        "mergedSourceSha": authorization["source"]["mergedMain"]["commitSha"],
        "planSha256": authorization["plan"]["sha256"],
    }


def _terminal_source_operation_map(
    source: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    values = source.get("allOperationProjections")
    if not isinstance(values, list):
        fail("terminal receipt components lack the exact operation universe")
    result: dict[str, Mapping[str, Any]] = {}
    for value in values:
        if not isinstance(value, Mapping):
            fail("terminal permanent source projection is not one object")
        operation_id = value.get("operationId")
        projection = value.get("sourceProjection")
        if (
            not isinstance(operation_id, str)
            or operation_id in result
            or not isinstance(projection, Mapping)
        ):
            fail("terminal operation source projection is duplicate or incomplete")
        result[operation_id] = projection
    return result


def _terminal_preflight_context(
    projection: Mapping[str, Any], operation_id: str
) -> Mapping[str, Any]:
    admissions = projection.get("operationAdmissions")
    if not isinstance(admissions, list):
        fail("terminal component builder lacks operation admissions")
    matches = [
        item
        for item in admissions
        if isinstance(item, Mapping) and item.get("operationId") == operation_id
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("context"), Mapping):
        fail(f"terminal component builder lacks context for {operation_id}")
    return matches[0]["context"]


def _terminal_successful_mutation_count(
    journal: Sequence[Mapping[str, Any]], operation_id: str
) -> int:
    count = sum(
        1
        for item in journal
        if item.get("phase") == "result"
        and item.get("operationId") == operation_id
        and type(item.get("status")) is int
        and 200 <= item["status"] <= 299
    )
    if count < 1:
        fail(f"terminal component ownership lacks {operation_id} mutation proof")
    return count


def _terminal_create_or_adopt_outcome(
    *,
    source: Mapping[str, Any],
    mutation_journal: Sequence[Mapping[str, Any]],
    operation_id: str,
) -> dict[str, Any]:
    """Return truthful create-only evidence for one create-or-adopt object.

    A pre-existing exact immutable object is useful for crash recovery, but it
    is not a create performed by the current authorization.  The public receipt
    therefore distinguishes the two cases and emits the create condition and
    HTTP status only when the terminal journal proves the current write.
    """

    entries = [
        item
        for item in source.get("permanentMutationProjections", [])
        if isinstance(item, Mapping) and item.get("mutationId") == operation_id
    ]
    if len(entries) != 1:
        fail(f"terminal create-or-adopt outcome is missing for {operation_id}")
    outcome = entries[0].get("outcome")
    successful_results = [
        item
        for item in mutation_journal
        if item.get("phase") == "result"
        and item.get("operationId") == operation_id
        and type(item.get("status")) is int
        and 200 <= item["status"] <= 299
    ]
    if (
        outcome == "created"
        and len(successful_results) == 1
        and successful_results[0]["status"] == 201
    ):
        return {
            "provisioningOutcome": "created-by-authorization",
            "createCondition": "If-None-Match:*",
            "createHttpStatus": 201,
        }
    if outcome == "adopted-exact" and not successful_results:
        return {
            "provisioningOutcome": "adopted-exact",
            "createCondition": None,
            "createHttpStatus": None,
        }
    fail(f"terminal create-or-adopt journal contradicts {operation_id} outcome")


def _terminal_temporary_role_component(
    *,
    definition_id: str,
    assignment_id: str,
    scope_resource_id: str,
    principal_id: str,
    add_mutation_id: str,
    remove_mutation_id: str,
    cleanup_source: Mapping[str, Any],
    mutation_journal: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    add_count = _terminal_successful_mutation_count(
        mutation_journal, add_mutation_id
    )
    remove_count = _terminal_successful_mutation_count(
        mutation_journal, remove_mutation_id
    )
    if add_count != 2 or remove_count != 2:
        fail("terminal temporary role ownership lacks both exact subcalls")
    body = {
        "roleDefinitionId": definition_id,
        "roleAssignmentId": assignment_id,
        "scopeResourceId": scope_resource_id,
        "principalObjectId": principal_id,
        "addMutationId": add_mutation_id,
        "removeMutationId": remove_mutation_id,
        "createdByAuthorization": add_count == 2,
        "removed": remove_count == 2,
        "presentAfterCleanup": False,
        "freshReadbackSha256": sha256_bytes(canonical_json_bytes(cleanup_source)),
        "observedAt": cleanup_source["observedAt"],
        "roleDefinitionCreatedByAuthorization": add_count == 2,
        "roleDefinitionRemoved": remove_count == 2,
        "roleDefinitionPresentAfterCleanup": False,
    }
    return body


def build_terminal_receipt_components(
    *,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    preflight_projection: Mapping[str, Any],
    source_evidence: Mapping[str, Any],
    started_at: str,
    completed_at: str,
) -> dict[str, dict[str, Any]]:
    """Build the eight nonterminal receipt components from validated proof.

    The safe receipt assembler independently validates these objects and then
    overwrites duplicated digests from the retained source bodies.  This pure
    builder exists so production and tests share one deterministic input
    vocabulary; it performs no filesystem, credential, or Azure operation.
    """

    source = validate_terminal_source_evidence(
        plan=plan,
        authorization=authorization,
        preflight_projection=preflight_projection,
        evidence=source_evidence,
    )
    started = parse_time(started_at, "terminal component execution startedAt")
    completed = parse_time(completed_at, "terminal component execution completedAt")
    source_observed = parse_time(source["observedAt"], "terminal source observedAt")
    if completed < started or source_observed != completed:
        fail("terminal component execution window is not exact")
    model, _model_raw = load_json(EVIDENCE_MODEL_PATH)
    if not isinstance(model, Mapping):
        fail("terminal evidence model is not one object")
    resources = {item["id"]: item for item in plan["resourceInventory"]}
    operations = _terminal_source_operation_map(source)

    permanent = _terminal_receipt_header(
        model, "permanentMutationLedger", "complete", authorization
    )
    mutation_by_id = {
        item["id"]: item
        for item in plan["mutations"]
        if item.get("temporary") is not True
        and item["kind"] != "local-create-only-canonical-evidence"
    }
    permanent["entries"] = [
        {
            "mutationId": item["mutationId"],
            "target": item["target"],
            "kind": item["kind"],
            "irreversible": mutation_by_id[item["mutationId"]]["irreversible"],
            "outcome": item["outcome"],
            "evidenceSha256": sha256_bytes(
                canonical_json_bytes(item["sourceProjection"])
            ),
            "observedAt": item["observedAt"],
        }
        for item in source["permanentMutationProjections"]
    ]
    permanent.update(
        {
            "failures": [],
            "pendingHousekeeping": [],
            "observedAt": completed_at,
        }
    )

    cleanup_source = source["cleanupAbsenceProjections"]
    mutation_journal = source["productionBoundary"]["mutationJournal"]
    uploader_add_count = _terminal_successful_mutation_count(
        mutation_journal, "addOwnedUploaderIpv4Rule"
    )
    uploader_remove_count = _terminal_successful_mutation_count(
        mutation_journal, "removeOwnedUploaderIpv4Rule"
    )
    if uploader_add_count != 1 or uploader_remove_count != 1:
        fail("terminal uploader IPv4 ownership lacks exact add/remove results")
    add_ip_context = _terminal_preflight_context(
        preflight_projection, "addOwnedUploaderIpv4Rule"
    )
    raw_cidr = add_ip_context.get("uploaderIpv4")
    try:
        network = ipaddress.ip_network(str(raw_cidr), strict=True)
    except ValueError as exc:
        raise BootstrapError("terminal component uploader IPv4 is invalid") from exc
    if network.version != 4 or network.prefixlen != 32:
        fail("terminal component uploader address is not one /32")
    cidr_sha = sha256_bytes(str(raw_cidr).encode("utf-8"))
    arm_rule_sha = sha256_bytes(
        canonical_json_bytes(
            {"value": str(network.network_address), "action": "Allow"}
        )
    )
    temporary = _terminal_receipt_header(
        model,
        "temporaryAccessCleanup",
        "complete-temporary-access-absent",
        authorization,
    )
    temporary["publicIpv4CidrSha256"] = cidr_sha
    temporary["packageIpv4Rule"] = {
        "addMutationId": "addOwnedUploaderIpv4Rule",
        "removeMutationId": "removeOwnedUploaderIpv4Rule",
        "cidrSha256": cidr_sha,
        "armIpRuleSha256": arm_rule_sha,
        "createdByAuthorization": uploader_add_count == 1,
        "removed": uploader_remove_count == 1,
        "presentAfterCleanup": False,
        "freshReadbackSha256": sha256_bytes(
            canonical_json_bytes(cleanup_source["packageIpv4Rule"])
        ),
        "observedAt": cleanup_source["packageIpv4Rule"]["observedAt"],
    }
    temporary_access = plan["temporaryAccess"]
    temporary["packageUploaderRole"] = _terminal_temporary_role_component(
        definition_id=temporary_access["roleDefinitionId"],
        assignment_id=temporary_access["roleAssignmentId"],
        scope_resource_id=resources[temporary_access["scope"]]["resourceId"],
        principal_id=authorization["azure"]["accountObjectId"],
        add_mutation_id="addOwnedUploaderPackageRole",
        remove_mutation_id="removeOwnedUploaderPackageRole",
        cleanup_source=cleanup_source["packageUploaderRole"],
        mutation_journal=mutation_journal,
    )
    temporary["operatorKeyReadRole"] = _terminal_temporary_role_component(
        definition_id=temporary_access["temporaryKeyReadRoleDefinitionId"],
        assignment_id=temporary_access["temporaryKeyReadRoleAssignmentId"],
        scope_resource_id=resources[temporary_access["temporaryKeyReadScope"]][
            "resourceId"
        ],
        principal_id=authorization["azure"]["accountObjectId"],
        add_mutation_id="addOwnedOperatorKeyReadRole",
        remove_mutation_id="removeOwnedOperatorKeyReadRole",
        cleanup_source=cleanup_source["operatorKeyReadRole"],
        mutation_journal=mutation_journal,
    )
    temporary["operatorFenceRole"] = _terminal_temporary_role_component(
        definition_id=temporary_access["temporaryFenceRoleDefinitionId"],
        assignment_id=temporary_access["temporaryFenceRoleAssignmentId"],
        scope_resource_id=resources[temporary_access["temporaryFenceScope"]][
            "resourceId"
        ],
        principal_id=authorization["azure"]["accountObjectId"],
        add_mutation_id="addOwnedOperatorFenceBootstrapRole",
        remove_mutation_id="removeOwnedOperatorFenceBootstrapRole",
        cleanup_source=cleanup_source["operatorFenceRole"],
        mutation_journal=mutation_journal,
    )
    temporary["operatorControllerRole"] = _terminal_temporary_role_component(
        definition_id=temporary_access["temporaryControllerRoleDefinitionId"],
        assignment_id=temporary_access["temporaryControllerRoleAssignmentId"],
        scope_resource_id=resources[temporary_access["temporaryControllerScope"]][
            "resourceId"
        ],
        principal_id=authorization["azure"]["accountObjectId"],
        add_mutation_id="addOwnedOperatorControllerCanaryRole",
        remove_mutation_id="removeOwnedOperatorControllerCanaryRole",
        cleanup_source=cleanup_source["operatorControllerRole"],
        mutation_journal=mutation_journal,
    )
    temporary.update(
        {
            "failures": [],
            "pendingHousekeeping": [],
            "observedAt": completed_at,
        }
    )

    initial = model["initialActivationFenceDocument"]
    initial_bytes = canonical_json_bytes(initial)
    initial_sha = sha256_bytes(initial_bytes)
    fence_source = operations["createInitialIdleActivationFence"]
    fence_projection = fence_source["projection"]
    fence_headers = fence_source["headers"]
    fence = _terminal_receipt_header(
        model,
        "activationFenceBootstrap",
        "initial-idle-fence-exact-created-or-adopted",
        authorization,
    )
    fence.update(
        {
            "containerResourceId": resources["activationFenceContainer"][
                "resourceId"
            ],
            "blobResourceId": resources["activationFenceBlob"]["resourceId"],
            "blobName": resources["activationFenceBlob"]["name"],
            "canonicalInitialDocument": initial,
            "initialBodySha256": initial_sha,
            "size": len(initial_bytes),
            **_terminal_create_or_adopt_outcome(
                source=source,
                mutation_journal=mutation_journal,
                operation_id="createInitialIdleActivationFence",
            ),
            "etag": fence_projection["etag"],
            "versionId": fence_projection["versionId"],
            "metadataSha256": initial_sha,
            "readbackSha256": fence_projection["sha256"],
            "readbackHttpStatus": fence_source["status"],
            "leaseState": fence_headers["leaseState"],
            "leaseStatus": fence_headers["leaseStatus"],
            "temporaryAccessCleanupSha256": sha256_bytes(
                canonical_json_bytes(temporary)
            ),
            "observedAt": next(
                item["observedAt"]
                for item in source["permanentMutationProjections"]
                if item["mutationId"] == "createInitialIdleActivationFence"
            ),
        }
    )

    package_source = source["packageReadbackProjection"]
    upload = operations["uploadVersionedBridgePackage"]["projection"]
    versioned_url = upload["url"] + "?versionid=" + urllib.parse.quote(
        upload["versionId"], safe=""
    )
    package = _terminal_receipt_header(
        model, "packageReadback", "exact-version-read-back", authorization
    )
    package.update(
        {
            "containerResourceId": resources["packageContainer"]["resourceId"],
            "blobName": package_source["blobName"],
            "packageSha256": authorization["plan"]["bridgePackageSha256"],
            "size": authorization["plan"]["bridgePackageSize"],
            **_terminal_create_or_adopt_outcome(
                source=source,
                mutation_journal=mutation_journal,
                operation_id="uploadVersionedBridgePackage",
            ),
            "etag": package_source["etag"],
            "versionId": package_source["versionId"],
            "versionedUrl": versioned_url,
            "metadataSha256": package_source["metadataSha256"],
            "readbackSha256": package_source["bytesSha256"],
            "readbackSize": package_source["size"],
            "readbackHttpStatus": package_source["httpStatus"],
            "observedAt": package_source["observedAt"],
        }
    )

    managed_source = source["managedIdentityFetchResponseProjection"]
    managed = _terminal_receipt_header(
        model,
        "managedIdentityFetchSelfTest",
        "source-derived-terminal-success",
        authorization,
    )
    managed.update(json.loads(canonical_json_bytes(managed_source).decode("utf-8")))
    managed.update(
        {
            "responseProjectionSha256": sha256_bytes(
                canonical_json_bytes(managed_source)
            ),
            "packageReadbackSha256": sha256_bytes(canonical_json_bytes(package)),
        }
    )

    lease_source = source["leaseCanaryProofs"]
    lease = _terminal_receipt_header(
        model,
        "leaseCanaryEvidence",
        "direct-controller-and-source-derived-activation-proof-complete",
        authorization,
    )
    for name in (
        "controllerLease",
        "activationFenceLease",
        "cleanupFastLane",
        "cleanupExpiryFallback",
    ):
        lease[name] = json.loads(
            canonical_json_bytes(lease_source[name]).decode("utf-8")
        )
        lease[name]["evidenceSha256"] = sha256_bytes(
            canonical_json_bytes(lease_source[name])
        )
    lease.update(
        {
            "temporaryAccessCleanupSha256": sha256_bytes(
                canonical_json_bytes(temporary)
            ),
            "activationFenceBootstrapSha256": sha256_bytes(
                canonical_json_bytes(fence)
            ),
            "publisherControllerRuntimeLeaseGate": {
                "status": "deferred-required-post-s2",
                "requiredAfter": "separately-authorized-publisher-fic-repin",
                "requiredBefore": "caller-integration-and-production-deploy",
                "targetResourceId": resources["controllerLockContainer"][
                    "resourceId"
                ],
                "publisherIdentityResourceId": resources[
                    "publisherServicePrincipal"
                ]["resourceId"],
            },
            "failures": [],
            "pendingHousekeeping": [],
            "observedAt": completed_at,
        }
    )

    configure = operations[
        "configureBridgeExactVersionedPackageAndCriticalSettings"
    ]["projection"]
    canary = operations["startBridgeForBoundedCanary"]["projection"]
    bridge = _terminal_receipt_header(
        model,
        "bridgeEvidence",
        "terminal-success-with-source-derived-boundaries-complete",
        authorization,
    )
    bridge.update(
        {
            "bridgeResourceId": resources["bridgeSite"]["resourceId"],
            "finalState": canary["stopped"]["state"],
            "settings": {
                "beforeSha256": configure["preAppSettingsSha256"],
                "desiredSha256": configure["settingsSha256"],
                "afterSha256": configure["settingsSha256"],
                "fullMapReadbackExact": True,
            },
            "webJobTerminalProjectionSha256": sha256_bytes(
                canonical_json_bytes(source["bridgeCanaryProof"]["webJobTerminal"])
            ),
            "sourceDerivedExpectedMarkerSha256": sha256_bytes(
                canonical_json_bytes(
                    source["bridgeCanaryProof"]["sourceDerivedExpectedMarker"]
                )
            ),
            "packageReadbackSha256": sha256_bytes(canonical_json_bytes(package)),
            "managedIdentityFetchSelfTestSha256": sha256_bytes(
                canonical_json_bytes(managed)
            ),
            "leaseCanaryEvidenceSha256": sha256_bytes(
                canonical_json_bytes(lease)
            ),
            "productionBoundarySha256": sha256_bytes(
                canonical_json_bytes(source["productionBoundary"])
            ),
            "observedAt": completed_at,
        }
    )

    worm = _terminal_receipt_header(
        model, "wormProjections", "locked-at-least-91-days", authorization
    )
    worm["containers"] = {}
    for name in ("acceptedReleases", "webJobResults", "deploymentPackages"):
        pair = source["wormSourceProjections"][name]
        policy = pair["policy"]
        properties = policy["properties"]
        worm["containers"][name] = {
            "containerResourceId": pair["container"]["id"],
            "policyResourceId": policy["id"],
            "publicAccess": pair["container"]["publicAccess"],
            "state": properties["state"],
            "retentionDays": properties[
                "immutabilityPeriodSinceCreationInDays"
            ],
            "allowProtectedAppendWrites": properties[
                "allowProtectedAppendWrites"
            ],
            "allowProtectedAppendWritesAll": properties[
                "allowProtectedAppendWritesAll"
            ],
            "etag": policy["etag"],
            "containerProjectionSha256": sha256_bytes(
                canonical_json_bytes(pair["container"])
            ),
            "policyProjectionSha256": sha256_bytes(
                canonical_json_bytes(policy)
            ),
            "observedAt": next(
                item["observedAt"]
                for item in source["permanentMutationProjections"]
                if item["sourceProjection"] == operations[
                    {
                        "acceptedReleases": "extendAcceptedRetentionFrom30To91Days",
                        "webJobResults": "extendResultRetentionFrom30To91Days",
                        "deploymentPackages": "lockPackageRetentionAt91Days",
                    }[name]
                ]
            ),
        }
    worm["observedAt"] = completed_at

    components = {
        "permanentMutationLedger": permanent,
        "temporaryAccessCleanup": temporary,
        "activationFenceBootstrap": fence,
        "packageReadback": package,
        "managedIdentityFetchSelfTest": managed,
        "bridgeEvidence": bridge,
        "leaseCanaryEvidence": lease,
        "wormProjections": worm,
    }
    _reject_terminal_secret_material(components, "terminal receipt components")
    if json.loads(canonical_json_bytes(components).decode("utf-8")) != components:
        fail("terminal receipt components are not canonical JSON")
    return components


def _operation_context_policy(
    operation_id: str,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the single source-owned preflight/adoption policy for one mutation.

    The observer imports this policy.  Preflight may supply only the fields in
    ``observedApplyFields`` or one exact ``adoptedProjectionFields`` mapping.
    Values listed in ``executorDerivedDependencies`` must be obtained from
    validated mutation/readback facts during apply and are never authored into
    the preflight document.
    """
    operation = next(
        (item for item in plan["mutations"] if item["id"] == operation_id), None
    )
    if operation is None or operation["kind"] == "local-create-only-canonical-evidence":
        fail(f"operation context policy is unknown: {operation_id}")
    adopted_schemas: dict[str, set[str]] = {
        "createMailboxResourceGroup": set(),
        "createPublisherApplication": {"objectId", "appId"},
        "createPublisherServicePrincipal": {"objectId", "appId", "principalId"},
        "grantPublisherGraphApplicationReadAll": set(),
        "retireLegacyPublisherFic": set(),
        "retireLegacyPublisherMutatorAssignment": set(),
        "retireLegacyPublisherSitesReadAssignment": set(),
        "retireLegacyPublisherResultReadAssignment": set(),
        "createBridgeIdentity": {"resourceId", "clientId", "principalId"},
        "adoptExistingRegistryWriterIdentity": set(),
        "adoptExistingRegistryReaderIdentity": set(),
        "detachWriterAndReaderFromLegacyBridge": set(),
        "removeLegacyWriterResultAssignment": set(),
        "removeLegacyReaderResultAssignment": set(),
        "createSignerIdentity": {"resourceId", "clientId", "principalId"},
        "createProductionActivationIdentity": {"resourceId", "clientId", "principalId"},
        "createPrivatePackageContainer": set(),
        "createPrivateControllerLockContainer": set(),
        "createPrivateActivationFenceContainer": set(),
        "createStoppedPrivateBridge": {"resourceId", "name", "etag"},
        "createSigningKeyVersion": {"keyUriWithVersion"},
        "attachFiveUamisOnlyToBridge": set(),
        "uploadVersionedBridgePackage": {"blob", "etag", "versionId", "url"},
        "lockPackageRetentionAt91Days": set(),
        "createInitialIdleActivationFence": {"url", "etag", "versionId", "sha256"},
        "extendAcceptedRetentionFrom30To91Days": set(),
        "extendResultRetentionFrom30To91Days": set(),
        "createSolePublisherFicToSignedBootstrapSource": set(),
    }
    observed_fields: set[str] = set()
    if operation_id == "retireLegacyPublisherFic":
        observed_fields.add("legacyFederatedCredentialId")
    elif operation_id == "detachWriterAndReaderFromLegacyBridge":
        observed_fields.add("etag")
    elif operation_id == "createSigningKeyVersion":
        observed_fields.add("expiresAt")
    elif operation_id == "addOwnedUploaderIpv4Rule":
        observed_fields |= {"uploaderIpv4", "preNetworkAcls"}
    elif operation_id == "removeOwnedUploaderIpv4Rule":
        observed_fields |= {"uploaderIpv4", "restoreNetworkAcls"}
    elif operation_id == "configureBridgeExactVersionedPackageAndCriticalSettings":
        observed_fields |= {
            "preAppSettings",
            "preAppSettingsSha256",
            "bootstrapSelfTestStaticControl",
        }
    elif operation_id in {"createCustomRoleDefinitions", "createExactRoleAssignments"}:
        observed_fields.add("memberStates")
        if operation_id == "createCustomRoleDefinitions":
            observed_fields.add("builtInRoleDefinitionProjections")
    elif operation_id in {
        "lockPackageRetentionAt91Days",
        "extendAcceptedRetentionFrom30To91Days",
        "extendResultRetentionFrom30To91Days",
    }:
        observed_fields.add("etag")
    dependencies: dict[str, list[str]] = {
        "createPublisherServicePrincipal": ["createPublisherApplication.appId"],
        "grantPublisherGraphApplicationReadAll": ["createPublisherServicePrincipal.objectId"],
        "createExactRoleAssignments": [
            "createPublisherServicePrincipal.principalId",
            "createBridgeIdentity.principalId",
            "createSignerIdentity.principalId",
            "createProductionActivationIdentity.principalId",
        ],
        "attachFiveUamisOnlyToBridge": [
            "createStoppedPrivateBridge.currentEtag",
            "createBridgeIdentity.resourceId",
            "createSignerIdentity.resourceId",
            "createProductionActivationIdentity.resourceId",
        ],
        "removeOwnedUploaderIpv4Rule": [
            "addOwnedUploaderIpv4Rule.addedNetworkAclsSha256"
        ],
        "configureBridgeExactVersionedPackageAndCriticalSettings": [
            "uploadVersionedBridgePackage.url",
            "uploadVersionedBridgePackage.versionId",
        ],
        "readBackExactSigningPublicJwk": ["createSigningKeyVersion.keyUriWithVersion"],
        "exerciseControllerLeaseCanary": ["createControllerLeaseCanaryBlob.url"],
        "removeControllerLeaseCanaryBlob": [
            "createControllerLeaseCanaryBlob.url",
            "createControllerLeaseCanaryBlob.etag",
        ],
        "startBridgeForBoundedCanary": [
            "configureBridgeExactVersionedPackageAndCriticalSettings.settingsSha256",
            "createInitialIdleActivationFence.versionId",
        ],
        "createSolePublisherFicToSignedBootstrapSource": [
            "createPublisherApplication.objectId"
        ],
    }
    adopted_fields = adopted_schemas.get(operation_id)
    decisions = ["apply-exact"]
    if adopted_fields is not None:
        decisions.append("adopt-exact")
    return {
        "schemaVersion": 1,
        "operationId": operation_id,
        "operationKind": operation["kind"],
        "allowedDecisions": decisions,
        "observedApplyFields": sorted(observed_fields),
        "adoptedProjectionFields": (
            None if adopted_fields is None else sorted(adopted_fields)
        ),
        "executorDerivedDependencies": dependencies.get(operation_id, []),
    }


def _validate_operation_context(
    operation_id: str,
    value: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    plan, _ = load_plan()
    policy = _operation_context_policy(operation_id, plan, authorization)
    decision = value.get("executionDecision")
    if decision == "adopt-exact":
        if "adopt-exact" not in policy["allowedDecisions"]:
            fail(f"{operation_id} may not be skipped or adopted")
        context = _exact_keys(value, {"executionDecision", "adopted"}, f"{operation_id} context")
        adopted = context["adopted"]
        adopted_fields = set(policy["adoptedProjectionFields"] or [])
        adopted = _exact_keys(adopted, adopted_fields, f"{operation_id} adopted projection")
        if any(
            not isinstance(item, str)
            or len(item) > 2048
            or any(token in item.lower() for token in ("sig=", "?sv=", "bearer ", "password="))
            for item in adopted.values()
        ):
            fail(f"{operation_id} adopted projection contains an unsafe value")
        if operation_id in {"createPublisherApplication", "createPublisherServicePrincipal"}:
            for field in adopted_fields:
                _guid(adopted[field], f"{operation_id} adopted {field}")
            if operation_id == "createPublisherServicePrincipal" and adopted["objectId"] != adopted["principalId"]:
                fail("adopted publisher service-principal identity is inconsistent")
        identity_targets = {
            "createBridgeIdentity": "bridgeIdentity",
            "createSignerIdentity": "signerIdentity",
            "createProductionActivationIdentity": "productionActivationIdentity",
        }
        if operation_id in identity_targets:
            target = next(
                item for item in load_plan()[0]["resourceInventory"]
                if item["id"] == identity_targets[operation_id]
            )
            if adopted["resourceId"].lower() != target["resourceId"].lower():
                fail(f"{operation_id} adopted resource ID is outside the fixed plan")
            _guid(adopted["clientId"], f"{operation_id} adopted client ID")
            _guid(adopted["principalId"], f"{operation_id} adopted principal ID")
        if operation_id == "createStoppedPrivateBridge":
            expected_id = next(
                item["resourceId"] for item in load_plan()[0]["resourceInventory"]
                if item["id"] == "bridgeSite"
            )
            if adopted["resourceId"].lower() != expected_id.lower() or adopted["name"] != "paperdesk-release-registry-bridge-v2-9c4e0d0d":
                fail("adopted bridge is outside the fixed plan")
            _quoted_etag(adopted["etag"], "adopted bridge ETag")
        if operation_id == "createSigningKeyVersion" and re.fullmatch(
            r"https://kv-mds-sea-9c4e0d0d\.vault\.azure\.net/keys/paperdesk-release-result-signing/[0-9a-f]{32}",
            adopted["keyUriWithVersion"],
        ) is None:
            fail("adopted signing-key version URI is outside the fixed vault/key")
        if operation_id == "uploadVersionedBridgePackage":
            expected_url = _operation_readback_url(operation_id, load_plan()[0], authorization)
            if (
                adopted["url"] != expected_url
                or adopted["blob"] != f"v2/control/{authorization['source']['mergedMain']['commitSha']}/paperdesk-private-release-bridge.zip"
                or not isinstance(adopted["versionId"], str)
                or not adopted["versionId"]
            ):
                fail("adopted package is outside the exact source-keyed object")
            _quoted_etag(adopted["etag"], "adopted package ETag")
        if operation_id == "createInitialIdleActivationFence":
            if (
                adopted["url"] != "https://mdspdbak2608089c4e.blob.core.windows.net/paperdesk-release-activation-control/v2/production-activation-fence.json"
                or adopted["sha256"] != _validator_contract(
                    "operation:createInitialIdleActivationFence", load_plan()[0], authorization
                )["expectedBodySha256"]
                or not isinstance(adopted["versionId"], str)
                or not adopted["versionId"]
            ):
                fail("adopted activation fence is not the exact canonical idle fence")
            _quoted_etag(adopted["etag"], "adopted activation fence ETag")
        return dict(context)
    if decision != "apply-exact":
        fail(f"{operation_id} context has an invalid execution decision")

    required: set[str] = {"executionDecision", *policy["observedApplyFields"]}
    context = _exact_keys(value, required, f"{operation_id} context")

    if "etag" in required:
        if (
            operation_id == "lockPackageRetentionAt91Days"
            and context["etag"] is None
        ):
            pass
        else:
            _quoted_etag(context["etag"], f"{operation_id} context ETag")
    if operation_id == "retireLegacyPublisherFic" and not GUID.fullmatch(
        str(context["legacyFederatedCredentialId"])
    ):
        fail("legacy FIC context is not one exact object ID")
    if operation_id == "createSigningKeyVersion":
        expires = parse_time(context["expiresAt"], "signing key expiresAt")
        if not dt.timedelta(days=30) <= expires - parse_time(
            authorization["validity"]["notBefore"], "authorization notBefore"
        ) <= dt.timedelta(days=400):
            fail("signing key expiry is outside the reviewed 30-to-400-day window")
    if operation_id in {"addOwnedUploaderIpv4Rule", "removeOwnedUploaderIpv4Rule"}:
        try:
            network = ipaddress.ip_network(str(context["uploaderIpv4"]), strict=True)
        except ValueError as exc:
            raise BootstrapError("uploader IPv4 context is invalid") from exc
        if network.version != 4 or network.prefixlen != 32:
            fail("uploader IPv4 context is not one exact /32")
        _validate_storage_acl_prestate(
            context["preNetworkAcls"] if operation_id.startswith("add") else context["restoreNetworkAcls"],
            adding=True,
            uploader=str(network),
        )
    if operation_id == "configureBridgeExactVersionedPackageAndCriticalSettings":
        settings = context["preAppSettings"]
        if (
            not isinstance(settings, dict)
            or settings != {}
            or any(not isinstance(key, str) or not isinstance(item, str) for key, item in settings.items())
            or any(
                key in settings
                for key in (
                    "WEBSITE_RUN_FROM_PACKAGE",
                    "WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID",
                    "WEBSITE_SKIP_RUNNING_KUDUAGENT",
                    "PAPERDESK_BRIDGE_PACKAGE_SHA256",
                    "PAPERDESK_BRIDGE_BOOTSTRAP_SELF_TEST_JSON",
                    "PAPERDESK_PRIVATE_RELEASE_ACTIVATION_JSON",
                    "PAPERDESK_TRANSIENT_GITHUB_TOKEN",
                )
            )
            or context["preAppSettingsSha256"] != sha256_bytes(canonical_json_bytes(settings))
            or context["bootstrapSelfTestStaticControl"]
            != _bootstrap_self_test_static_control(authorization)
        ):
            fail("bridge app-settings prestate or self-test control is unsafe")
    if operation_id in {"createCustomRoleDefinitions", "createExactRoleAssignments"}:
        if operation_id == "createCustomRoleDefinitions":
            expected_members = {
                role["definitionId"] for role in load_plan()[0]["roleMatrix"]
                if role.get("definitionKind") != "BuiltInRole"
            }
        else:
            expected_members = {role["assignmentId"] for role in load_plan()[0]["roleMatrix"]}
        member_states = context["memberStates"]
        if (
            not isinstance(member_states, dict)
            or set(member_states) != expected_members
            or any(value not in {"absent", "exact"} for value in member_states.values())
        ):
            fail(f"{operation_id} member-state inventory is not exact")
        if operation_id == "createCustomRoleDefinitions":
            _validate_builtin_role_definition_projections(
                context["builtInRoleDefinitionProjections"], load_plan()[0]
            )
    return dict(context)


def validate_preflight_evidence(
    value: Mapping[str, Any],
    authorization: Mapping[str, Any],
    plan: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    document = _exact_keys(
        value,
        {"schemaVersion", "status", "observedAt", "projection", "projectionSha256"},
        "preflight document",
    )
    if document["schemaVersion"] != 1 or document["status"] != "observed-read-only":
        fail("preflight document identity is not exact")
    if document["observedAt"] != authorization["observedPreflight"]["observedAt"]:
        fail("preflight timestamp is not authorization-bound")
    if not isinstance(document["projection"], dict):
        fail("preflight projection is invalid")
    projection = _exact_keys(
        document["projection"],
        {
            "schemaVersion",
            "planId",
            "probes",
            "operationAdmissions",
            "postconditionAdmissions",
            "productionBoundaryObservation",
        },
        "preflight projection",
    )
    if (
        projection["schemaVersion"] != 1
        or projection["planId"] != plan["planId"]
        or not PREFLIGHT_SCHEMA_PATH.is_file()
    ):
        fail("preflight projection identity is not exact")
    probes = projection["probes"]
    if not isinstance(probes, list) or not 1 <= len(probes) <= 512:
        fail("preflight probes are invalid")
    probe_map: dict[str, Mapping[str, Any]] = {}
    for index, value in enumerate(probes):
        probe = _exact_keys(
            value,
            {
                "id", "phase", "method", "url", "requestBodySha256", "status",
                "responseSha256", "validatorId", "validatorContract",
            },
            f"preflight probe {index}",
        )
        probe_id = probe["id"]
        method = probe["method"]
        if (
            not isinstance(probe_id, str)
            or not re.fullmatch(r"[a-z][a-zA-Z0-9-]{1,95}", probe_id)
            or probe_id in probe_map
            or probe["phase"] not in {"preflight", "readback"}
            or method not in {"GET", "POST"}
            or not isinstance(probe["url"], str)
            or not _preflight_url_allowed(method, probe["url"])
            or probe["requestBodySha256"] not in {
                None,
                sha256_bytes(b""),
            }
            or (method == "GET" and probe["requestBodySha256"] is not None)
            or (method == "POST" and probe["requestBodySha256"] != sha256_bytes(b""))
            or type(probe["status"]) is not int
            or not 200 <= probe["status"] <= 599
        ):
            fail(f"preflight probe is not an exact allowed read: {probe_id}")
        if probe["phase"] == "preflight":
            if (
                not SHA256.fullmatch(str(probe["responseSha256"]))
                or probe["validatorId"] is not None
                or probe["validatorContract"] is not None
            ):
                fail(f"preflight probe does not bind one exact observed response: {probe_id}")
        elif (
            probe["responseSha256"] is not None
            or not isinstance(probe["validatorId"], str)
            or probe["validatorContract"]
            != _validator_contract(probe["validatorId"], plan, authorization)
            or probe["method"] != probe["validatorContract"]["expectedMethod"]
            or probe["url"] != probe["validatorContract"]["expectedUrl"]
            or probe["status"] != probe["validatorContract"]["expectedStatus"]
        ):
            fail(f"readback probe does not use the exact source validator: {probe_id}")
        probe_map[probe_id] = probe

    azure_mutation_ids = [
        item["id"]
        for item in plan["mutations"]
        if item["kind"] != "local-create-only-canonical-evidence"
    ]
    operation_map = {item["id"]: item for item in plan["mutations"]}
    admissions = projection["operationAdmissions"]
    if not isinstance(admissions, list) or len(admissions) != len(azure_mutation_ids):
        fail("preflight operation admissions are incomplete")
    admission_ids: list[str] = []
    for index, value in enumerate(admissions):
        admission = _exact_keys(
            value,
            {"operationId", "status", "probeIds", "desiredProbeIds", "context"},
            f"operation admission {index}",
        )
        operation_id = admission["operationId"]
        if (
            operation_id not in azure_mutation_ids
            or admission["status"]
            not in {
                "absent",
                "exact",
                "owned-present",
                "network-inaccessible",
                "temporary-access-inaccessible",
            }
            or not isinstance(admission["context"], dict)
            or admission["context"].get("executionDecision")
            not in {"adopt-exact", "apply-exact"}
            or len(canonical_json_bytes(admission["context"])) > 65536
        ):
            fail("operation admission is invalid")
        admission["context"] = _validate_operation_context(
            operation_id, admission["context"], authorization
        )
        decision = admission["context"]["executionDecision"]
        kind = operation_map[operation_id]["kind"]
        if (
            admission["status"] == "network-inaccessible"
            and operation_id != "uploadVersionedBridgePackage"
        ):
            fail("network-inaccessible status is outside the package upload boundary")
        if (
            admission["status"] == "temporary-access-inaccessible"
            and operation_id not in TEMPORARY_ACCESS_INACCESSIBLE_OPERATIONS
        ):
            fail("temporary-access-inaccessible status is outside a temporary RBAC boundary")
        if decision == "adopt-exact":
            expected_adopt_status = (
                "absent" if kind.startswith(("delete-", "remove-", "temporary-remove"))
                else "exact"
            )
            if admission["status"] != expected_adopt_status:
                fail("adopt decision is inconsistent with the observed operation state")
        elif admission["status"] == "temporary-access-inaccessible":
            # These exact reads are intentionally inaccessible until their
            # source-planned, authorization-owned temporary role is created.
            # Their subsequent writes are create-only or authorization-owned
            # canary operations and remain protected by exact readback.
            pass
        elif operation_id in {
            "lockPackageRetentionAt91Days",
            "extendAcceptedRetentionFrom30To91Days",
            "extendResultRetentionFrom30To91Days",
        }:
            etag = admission["context"].get("etag")
            if operation_id == "lockPackageRetentionAt91Days":
                valid_prestate = (
                    admission["status"] == "absent" and etag is None
                ) or (
                    admission["status"] == "exact"
                    and isinstance(etag, str)
                    and _quoted_etag(etag, "package WORM prestate ETag") == etag
                )
            else:
                valid_prestate = (
                    admission["status"] == "exact"
                    and isinstance(etag, str)
                    and _quoted_etag(etag, "existing WORM prestate ETag") == etag
                )
            if not valid_prestate:
                fail("WORM decision is not bound to one exact supported prestate")
        elif kind.startswith(("delete-", "remove-", "temporary-remove")):
            if admission["status"] not in {"exact", "owned-present"}:
                fail("delete decision is not bound to one observed existing target")
        elif kind.startswith(("azure-global-create-only", "azure-ad-create-only", "temporary-add")):
            expected_create_statuses = (
                {"absent", "network-inaccessible"}
                if operation_id == "uploadVersionedBridgePackage"
                else {"absent"}
            )
            if admission["status"] not in expected_create_statuses:
                fail("create-only decision is not bound to an absent target")
        elif (
            kind.startswith("create-or-adopt")
            and operation_id
            not in {"createCustomRoleDefinitions", "createExactRoleAssignments"}
            and admission["status"]
            not in (
                {"absent", "network-inaccessible"}
                if operation_id == "uploadVersionedBridgePackage"
                else {"absent"}
            )
        ):
            fail("create decision is not bound to an absent create-or-adopt target")
        elif operation_id in {
            "createCustomRoleDefinitions",
            "createExactRoleAssignments",
        } and admission["status"] not in {"absent", "exact", "owned-present"}:
            fail("role-matrix resume state is not source-owned")
        elif (
            operation_id == "readBackExactSigningPublicJwk"
            and admission["status"] != "temporary-access-inaccessible"
        ):
            fail("signing JWK read is not bound to the temporary RBAC boundary")
        for field, phase in (("probeIds", "preflight"), ("desiredProbeIds", "readback")):
            ids = admission[field]
            if (
                not isinstance(ids, list)
                or not ids
                or len(ids) != len(set(ids))
                or any(item not in probe_map or probe_map[item]["phase"] != phase for item in ids)
            ):
                fail("operation admission probe binding is invalid")
        temporary_definition_url = _temporary_role_definition_readback_url(
            operation_id, plan
        )
        if temporary_definition_url is not None:
            definition_probes = [
                probe_map[item]
                for item in admission["probeIds"]
                if probe_map[item]["method"] == "GET"
                and probe_map[item]["url"] == temporary_definition_url
            ]
            if (
                len(definition_probes) != 1
                or definition_probes[0]["status"] != 404
            ):
                fail(
                    "temporary role definition absence is not bound to the fresh preflight"
                )
        if any(
            probe_map[item]["validatorId"] != f"operation:{operation_id}"
            for item in admission["desiredProbeIds"]
        ):
            fail("operation readback validator is not bound to the exact operation")
        admission_ids.append(operation_id)
    if admission_ids != azure_mutation_ids:
        fail("operation admissions are not in exact mutation order")
    admission_map = {item["operationId"]: item for item in admissions}
    application_adopted = admission_map["createPublisherApplication"]["context"].get("adopted")
    service_principal_adopted = admission_map["createPublisherServicePrincipal"]["context"].get("adopted")
    if isinstance(service_principal_adopted, Mapping):
        if not isinstance(application_adopted, Mapping) or service_principal_adopted["appId"] != application_adopted["appId"]:
            fail("adopted publisher service principal is not bound to the adopted application")
    adopted_identity_ids: list[str] = []
    for operation_id in (
        "createBridgeIdentity",
        "createSignerIdentity",
        "createProductionActivationIdentity",
    ):
        adopted = admission_map[operation_id]["context"].get("adopted")
        if isinstance(adopted, Mapping):
            adopted_identity_ids.extend([adopted["clientId"], adopted["principalId"]])
    fixed_identity_ids = {
        value
        for resource in plan["resourceInventory"]
        for value in (resource.get("clientId"), resource.get("principalId"))
        if isinstance(value, str)
    }
    if len(adopted_identity_ids) != len(set(adopted_identity_ids)) or fixed_identity_ids.intersection(adopted_identity_ids):
        fail("adopted automation identities are not pairwise distinct from fixed identities")
    claim_admission = admissions[0]
    if (
        claim_admission["operationId"] != "claimAzureSingleUseAuthorization"
        or claim_admission["status"] != "absent"
        or claim_admission["context"].get("executionDecision") != "apply-exact"
    ):
        fail("Azure-global single-use claim is not proven absent")

    postconditions = projection["postconditionAdmissions"]
    expected_postconditions = [item["id"] for item in plan["postconditions"]]
    if not isinstance(postconditions, list) or len(postconditions) != len(expected_postconditions):
        fail("preflight postcondition admissions are incomplete")
    observed_postconditions: list[str] = []
    for index, value in enumerate(postconditions):
        admission = _exact_keys(
            value, {"postconditionId", "probeIds"}, f"postcondition admission {index}"
        )
        ids = admission["probeIds"]
        if (
            admission["postconditionId"] not in expected_postconditions
            or not isinstance(ids, list)
            or not ids
            or len(ids) != len(set(ids))
            or any(item not in probe_map or probe_map[item]["phase"] != "readback" for item in ids)
        ):
            fail("postcondition admission probe binding is invalid")
        if any(
            probe_map[item]["validatorId"]
            != f"postcondition:{admission['postconditionId']}"
            for item in ids
        ):
            fail("postcondition readback validator is not bound to the exact predicate")
        observed_postconditions.append(admission["postconditionId"])
    if observed_postconditions != expected_postconditions:
        fail("postcondition admissions are not in exact plan order")
    production_boundary = _exact_keys(
        projection["productionBoundaryObservation"],
        {"probeIds", "sourceProjection"},
        "production boundary observation",
    )
    boundary_specs = _production_boundary_requests(plan)
    expected_boundary_ids = [item["id"] for item in boundary_specs]
    if production_boundary["probeIds"] != expected_boundary_ids:
        fail("production boundary probe IDs are not exact")
    used_probe_ids = {
        probe_id
        for admission in admissions
        for field in ("probeIds", "desiredProbeIds")
        for probe_id in admission[field]
    }
    used_probe_ids.update(
        probe_id for admission in postconditions for probe_id in admission["probeIds"]
    )
    for request in boundary_specs:
        probe = probe_map.get(request["id"])
        if (
            not isinstance(probe, Mapping)
            or request["id"] in used_probe_ids
            or probe["phase"] != "preflight"
            or probe["method"] != request["method"]
            or probe["url"] != request["url"]
            or probe["status"] != 200
            or probe["validatorId"] is not None
            or probe["validatorContract"] is not None
        ):
            fail("production boundary read is not one exact dedicated preflight probe")
    _validate_production_boundary_projection(
        production_boundary["sourceProjection"], plan
    )
    projection_digest = sha256_bytes(canonical_json_bytes(document["projection"]))
    if (
        document["projectionSha256"] != projection_digest
        or authorization["observedPreflight"]["sha256"] != projection_digest
    ):
        fail("preflight projection digest is not authorization-bound")
    return dict(document), projection_digest


def validate_preflight_document(
    path: Path,
    authorization: Mapping[str, Any],
    plan: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    value, _ = load_json(path, require_canonical=True)
    return validate_preflight_evidence(value, authorization, plan)


class BootstrapTransport(Protocol):
    def account(self) -> Mapping[str, Any]: ...

    def collect_preflight(self, plan: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def inspect_operation(
        self,
        operation: Mapping[str, Any],
        state: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...

    def apply_operation(
        self,
        operation: Mapping[str, Any],
        state: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...

    def compensate_temporary(
        self,
        operation: Mapping[str, Any],
        proof: Mapping[str, Any],
        state: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...

    def verify_postcondition(
        self,
        postcondition: Mapping[str, Any],
        state: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...

    def observe_production_boundary(self) -> Mapping[str, Any]: ...

    def finalize_terminal_source_evidence(
        self,
        state: Mapping[str, Any],
        *,
        claimed_at: str,
        observed_at: str,
    ) -> Mapping[str, Any]: ...

    def terminal_package_readback_bytes(self) -> bytes: ...


@dataclasses.dataclass(frozen=True)
class _RestResponse:
    status: int
    body: bytes
    headers: Mapping[str, str]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class AzureCliRestSession:
    """Azure CLI credential boundary plus bounded direct REST requests.

    Construction is side-effect free.  Tokens are requested lazily only after
    the canonical external authorization, source, package, and phrase checks
    have completed.  Tokens are never printed, persisted, or accepted from an
    environment variable.
    """

    _RESOURCE_BY_HOST = {
        "management.azure.com": "https://management.azure.com/",
        "graph.microsoft.com": "https://graph.microsoft.com/",
        "mdspdbak2608089c4e.blob.core.windows.net": "https://storage.azure.com/",
        "kv-mds-sea-9c4e0d0d.vault.azure.net": "https://vault.azure.net",
    }

    def __init__(
        self,
        authorization: Mapping[str, Any],
        *,
        clock: Callable[[], dt.datetime] | None = None,
    ) -> None:
        self.authorization = authorization
        self.clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        self._tokens: dict[str, tuple[str, int]] = {}
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect()
        )

    @staticmethod
    def _azure_cli_executable() -> str:
        # The Azure CLI MSI exposes ``az.cmd`` on Windows.  ``subprocess`` does
        # not apply PATHEXT when resolving the extensionless ``az`` name, so
        # using that POSIX launcher fails before even the read-only preflight.
        return "az.cmd" if sys.platform == "win32" else "az"

    @staticmethod
    def _run_az_json(arguments: Sequence[str], label: str) -> Mapping[str, Any]:
        executable = AzureCliRestSession._azure_cli_executable()
        try:
            process = subprocess.run(
                [executable, *arguments, "--output", "json"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=45,
                text=True,
                encoding="utf-8",
            )
        except (OSError, subprocess.SubprocessError):
            fail(f"Azure CLI {label} failed")
        if process.returncode != 0 or not 1 <= len(process.stdout) <= 1024 * 1024:
            fail(f"Azure CLI {label} failed")
        try:
            document = json.loads(process.stdout)
        except json.JSONDecodeError as exc:
            raise BootstrapError(f"Azure CLI {label} returned invalid JSON") from exc
        if not isinstance(document, dict):
            fail(f"Azure CLI {label} returned an invalid object")
        return document

    def account(self) -> Mapping[str, Any]:
        account = self._run_az_json(["account", "show"], "account inspection")
        user = account.get("user")
        if not isinstance(user, dict):
            fail("Azure CLI account has no exact user boundary")
        account_type = user.get("type")
        account_id = user.get("name")
        if account_type == "user":
            identity = self._run_az_json(
                ["ad", "signed-in-user", "show"], "signed-in user inspection"
            )
        elif account_type == "servicePrincipal" and isinstance(account_id, str):
            identity = self._run_az_json(
                ["ad", "sp", "show", "--id", account_id],
                "service principal inspection",
            )
        else:
            fail("Azure CLI account type is unsupported")
        return {
            "cloud": account.get("environmentName"),
            "subscriptionId": account.get("id"),
            "tenantId": account.get("tenantId"),
            "accountId": account_id,
            "accountObjectId": identity.get("id"),
            "accountType": account_type,
        }

    @staticmethod
    def _decode_claims(token: str) -> Mapping[str, Any]:
        parts = token.split(".")
        if len(parts) != 3:
            fail("Azure CLI access token is not a JWT")
        try:
            payload = parts[1] + "=" * (-len(parts[1]) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BootstrapError("Azure CLI access token claims are invalid") from exc
        if not isinstance(claims, dict):
            fail("Azure CLI access token claims are invalid")
        return claims

    def _token(self, resource: str) -> str:
        now = int(self.clock().timestamp())
        cached = self._tokens.get(resource)
        if cached is not None and cached[1] - now > 300:
            return cached[0]
        document = self._run_az_json(
            [
                "account",
                "get-access-token",
                "--resource",
                resource,
                "--subscription",
                SUBSCRIPTION,
            ],
            "access token request",
        )
        token = document.get("accessToken")
        if not isinstance(token, str) or len(token) < 100 or any(c in token for c in "\r\n"):
            fail("Azure CLI access token is invalid")
        claims = self._decode_claims(token)
        audience = claims.get("aud")
        allowed_audiences = {resource, resource.rstrip("/")}
        if resource == "https://graph.microsoft.com/":
            allowed_audiences.add("00000003-0000-0000-c000-000000000000")
        if resource == "https://vault.azure.net":
            # Azure Public Cloud may issue Key Vault tokens with the service's
            # pre-registered application ID as ``aud`` instead of its resource
            # URI.  Both values identify the same fixed Key Vault audience.
            allowed_audiences.add("cfa8b339-82a2-471a-a3c9-0fc0be7a4093")
        if (
            claims.get("tid") != TENANT
            or claims.get("oid") != self.authorization["azure"]["accountObjectId"]
            or audience not in allowed_audiences
            or type(claims.get("exp")) is not int
            or claims["exp"] <= now + 300
            or type(claims.get("nbf", 0)) is not int
            or claims.get("nbf", 0) > now + 30
        ):
            fail("Azure CLI access token is not bound to the authorized account")
        self._tokens[resource] = (token, claims["exp"])
        return token

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> _RestResponse:
        try:
            parsed = urllib.parse.urlsplit(url)
        except ValueError as exc:
            raise BootstrapError("Azure REST URL is invalid") from exc
        host = (parsed.hostname or "").lower()
        resource = self._RESOURCE_BY_HOST.get(host)
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.port not in (None, 443)
            or resource is None
            or method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}
        ):
            fail("Azure REST request is outside the exact host/method boundary")
        bound = dict(headers or {})
        bound["Authorization"] = "Bearer " + self._token(resource)
        bound.setdefault("Accept", "application/json")
        if body is not None:
            bound.setdefault("Content-Length", str(len(body)))
        request = urllib.request.Request(url, data=body, headers=bound, method=method)
        try:
            with self._opener.open(request, timeout=45) as response:
                response_body = response.read(16 * 1024 * 1024 + 1)
                status = response.status
                response_headers = dict(response.headers)
        except urllib.error.HTTPError as error:
            response_body = error.read(16 * 1024 * 1024 + 1)
            status = error.code
            response_headers = dict(error.headers)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise BootstrapError("Azure REST transport failed closed") from exc
        if len(response_body) > 16 * 1024 * 1024:
            fail("Azure REST response exceeded the bounded size")
        return _RestResponse(status, response_body, response_headers)


def _response_sha256(response: _RestResponse) -> str:
    content_type = next(
        (value for key, value in response.headers.items() if key.lower() == "content-type"),
        "",
    )
    if response.body and ("json" in content_type.lower() or response.body[:1] in {b"{", b"["}):
        try:
            parsed = json.loads(
                response.body.decode("utf-8"),
                object_pairs_hook=_duplicate_safe_pairs,
                parse_constant=lambda value: fail(f"invalid JSON constant: {value}"),
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BootstrapError("Azure REST JSON response is invalid") from exc
        return sha256_bytes(canonical_json_bytes(parsed))
    return sha256_bytes(response.body)


def _package_blob_error_projection(
    method: str, url: str, response: _RestResponse
) -> dict[str, str] | None:
    parsed = urllib.parse.urlsplit(url)
    allowed_path = any(
        pattern.fullmatch(parsed.path) is not None
        for pattern in (
            re.compile(
                r"/paperdesk-deployment-packages/v2/control/[0-9a-f]{40}/"
                r"paperdesk-private-release-bridge\.zip"
            ),
            re.compile(
                r"/paperdesk-release-activation-control/"
                r"v2/production-activation-fence\.json"
            ),
            re.compile(
                r"/paperdesk-release-controller-lock/v2/bootstrap-canary/"
                r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
                r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json"
            ),
        )
    )
    if (
        method != "GET"
        or (parsed.hostname or "").lower()
        != "mdspdbak2608089c4e.blob.core.windows.net"
        or parsed.query
        or parsed.fragment
        or not allowed_path
        or not 400 <= response.status <= 499
    ):
        return None
    content_type = next(
        (
            value
            for key, value in response.headers.items()
            if key.lower() == "content-type"
        ),
        "",
    )
    matches = re.findall(rb"<Code>([A-Za-z0-9]+)</Code>", response.body)
    if "xml" not in content_type.lower() or len(matches) != 1:
        fail("storage blob error response is not one exact XML error")
    code = matches[0].decode("ascii")
    allowed = {
        "AuthenticationFailed",
        "AuthorizationFailure",
        "AuthorizationPermissionMismatch",
        "BlobNotFound",
    }
    if code not in allowed:
        fail("storage blob preflight returned an unsupported storage error")
    return {"storageErrorCode": code}


def _key_vault_preflight_error_projection(
    method: str, url: str, response: _RestResponse
) -> dict[str, str] | None:
    parsed = urllib.parse.urlsplit(url)
    if (
        method != "GET"
        or (parsed.hostname or "").lower()
        != "kv-mds-sea-9c4e0d0d.vault.azure.net"
        or parsed.path != "/keys/paperdesk-release-result-signing/versions"
        or urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        != {"api-version": ["7.4"]}
        or response.status != 403
    ):
        return None
    try:
        document = json.loads(
            response.body.decode("utf-8"),
            object_pairs_hook=_duplicate_safe_pairs,
            parse_constant=lambda value: fail(
                f"invalid JSON constant in Key Vault error: {value}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BootstrapError("Key Vault preflight error is not exact JSON") from exc
    error = document.get("error") if isinstance(document, Mapping) else None
    inner = error.get("innererror") if isinstance(error, Mapping) else None
    if (
        not isinstance(error, Mapping)
        or error.get("code") != "Forbidden"
        or not isinstance(inner, Mapping)
        or inner.get("code") != "ForbiddenByRbac"
    ):
        fail("Key Vault preflight is not blocked by the temporary RBAC boundary")
    return {
        "keyVaultErrorCode": "Forbidden",
        "keyVaultInnerErrorCode": "ForbiddenByRbac",
    }


def _arm_storage_absence_error_projection(
    method: str, url: str, response: _RestResponse
) -> dict[str, str] | None:
    """Bind stable fields from exact ARM storage-absence responses.

    Azure Storage management 404 bodies append a fresh RequestId and Time to
    every otherwise identical response.  The status and exact URL are already
    separate preflight fields, so retain the validated stable code/message and
    reject every other host, path, query, shape, or error.
    """

    parsed = urllib.parse.urlsplit(url)
    base_path = (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/"
        "rg-paperdesk-rollback-sea-20260808/providers/Microsoft.Storage/"
        "storageAccounts/mdspdbak2608089c4e/blobServices/default/containers/"
    )
    expected_codes = {
        base_path + "paperdesk-deployment-packages": "ContainerNotFound",
        base_path + "paperdesk-release-controller-lock": "ContainerNotFound",
        base_path + "paperdesk-release-activation-control": "ContainerNotFound",
        (
            base_path
            + "paperdesk-deployment-packages/immutabilityPolicies/default"
        ): "ContainerOperationFailure",
    }
    expected_code = expected_codes.get(parsed.path)
    if (
        method != "GET"
        or parsed.scheme != "https"
        or parsed.netloc.lower() != "management.azure.com"
        or parsed.query != "api-version=2025-06-01"
        or parsed.fragment
        or response.status != 404
        or expected_code is None
    ):
        return None
    content_type = next(
        (
            value
            for key, value in response.headers.items()
            if key.lower() == "content-type"
        ),
        "",
    )
    if "json" not in content_type.lower():
        fail("ARM storage absence response is not exact JSON")
    try:
        document = json.loads(
            response.body.decode("utf-8"),
            object_pairs_hook=_duplicate_safe_pairs,
            parse_constant=lambda value: fail(
                f"invalid JSON constant in ARM storage absence error: {value}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BootstrapError("ARM storage absence response is not exact JSON") from exc
    if not isinstance(document, Mapping) or set(document) != {"error"}:
        fail("ARM storage absence error envelope drifted")
    error = document["error"]
    if not isinstance(error, Mapping) or set(error) != {"code", "message"}:
        fail("ARM storage absence error fields drifted")
    stable_message = "The specified container does not exist."
    message = error.get("message")
    if (
        error.get("code") != expected_code
        or not isinstance(message, str)
        or re.fullmatch(
            re.escape(stable_message)
            + r"\nRequestId:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}\nTime:[0-9]{4}-[0-9]{2}-[0-9]{2}T"
            r"[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{1,7}Z",
            message,
        )
        is None
    ):
        fail("ARM storage absence error is not exact")
    return {
        "armStorageErrorCode": expected_code,
        "armStorageErrorMessage": stable_message,
    }


def _preflight_response_sha256(
    method: str, url: str, response: _RestResponse
) -> str:
    storage_error = _package_blob_error_projection(method, url, response)
    if storage_error is not None:
        # Azure includes volatile request IDs and timestamps in the XML body.
        # Bind the exact stable error code while status and URL remain separate
        # preflight fields.
        return sha256_bytes(canonical_json_bytes(storage_error))
    arm_storage_error = _arm_storage_absence_error_projection(method, url, response)
    if arm_storage_error is not None:
        return sha256_bytes(canonical_json_bytes(arm_storage_error))
    key_vault_error = _key_vault_preflight_error_projection(method, url, response)
    if key_vault_error is not None:
        return sha256_bytes(canonical_json_bytes(key_vault_error))
    return _response_sha256(response)


class AzureCliBootstrapTransport:
    """Exact, authorization-bound future Azure executor.

    The external preflight contains only digests of an explicitly allowed set
    of read probes.  It cannot supply a mutation request.  Mutation URLs and
    bodies are constructed below from the signed source plan and authorized
    runtime coordinates; each mutation is accepted only after its signed
    readback probes match.
    """

    GRAPH_ROOT = "https://graph.microsoft.com"
    ARM_ROOT = "https://management.azure.com"
    STORAGE_ROOT = "https://mdspdbak2608089c4e.blob.core.windows.net"
    GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
    GRAPH_APPLICATION_READ_ALL = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"

    def __init__(
        self,
        *,
        authorization: Mapping[str, Any],
        plan: Mapping[str, Any],
        package: Mapping[str, Any],
        preflight: Mapping[str, Any],
        clock: Callable[[], dt.datetime] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        session: AzureCliRestSession | None = None,
    ) -> None:
        self.authorization = authorization
        self.plan = plan
        self.package = package
        self.preflight = preflight
        self.clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        self.sleep = sleep
        self.session = session or AzureCliRestSession(authorization, clock=self.clock)
        self.resources = {item["id"]: item for item in plan["resourceInventory"]}
        self.admissions = {
            item["operationId"]: item
            for item in preflight["projection"]["operationAdmissions"]
        }
        self.postconditions = {
            item["postconditionId"]: item
            for item in preflight["projection"]["postconditionAdmissions"]
        }
        self.probes = {
            item["id"]: item for item in preflight["projection"]["probes"]
        }
        self.production_boundary = dict(
            preflight["projection"]["productionBoundaryObservation"]
        )
        self._fresh_projection: Mapping[str, Any] | None = None
        self._ledger: UseLedger | None = None
        self._active_operation_id: str | None = None
        self._validated_source_projections: dict[str, Mapping[str, Any]] = {}
        self._package_readback_bytes: bytes | None = None

    def bind_journal(self, ledger: "UseLedger") -> None:
        self._ledger = ledger

    def _record_mutation(
        self,
        method: str,
        url: str,
        response: _RestResponse,
        request_body: bytes | None,
        intent_id: str,
    ) -> None:
        if self._ledger is None or self._active_operation_id is None:
            fail("cloud mutation occurred before the durable journal was bound")
        operation = next(
            item for item in self.plan["mutations"]
            if item["id"] == self._active_operation_id
        )
        self._ledger.append_cloud_mutation(
            {
                "schemaVersion": 1,
                "phase": "result",
                "intentId": intent_id,
                "operationId": self._active_operation_id,
                "temporary": operation.get("temporary") is True,
                "method": method,
                "targetUrl": url,
                "requestBodySha256": sha256_bytes(request_body or b""),
                "status": response.status,
                "responseBodySha256": sha256_bytes(response.body),
                "etag": self._header(response, "ETag"),
                "versionId": self._header(response, "x-ms-version-id"),
                "authorizationSha256": sha256_bytes(canonical_json_bytes(self.authorization)),
                "sourceSha": self.authorization["source"]["mergedMain"]["commitSha"],
                "planSha256": self.authorization["plan"]["sha256"],
                "packageSha256": self.package["sha256"],
                "recordedAt": self.clock().astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            }
        )

    def _mutation_request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        expected: set[int],
        cleanup: bool = False,
    ) -> _RestResponse:
        if self._ledger is None or self._active_operation_id is None:
            fail("cloud mutation occurred before the durable journal was bound")
        operation = next(
            item for item in self.plan["mutations"]
            if item["id"] == self._active_operation_id
        )
        cleanup_operation = (
            operation["kind"].startswith("temporary-remove")
        )
        if not cleanup and not cleanup_operation:
            now = self.clock()
            not_before = parse_time(
                self.authorization["validity"]["notBefore"], "authorization notBefore"
            )
            expires = parse_time(
                self.authorization["validity"]["expiresAt"], "authorization expiresAt"
            )
            if not not_before <= now <= expires:
                fail("authorization expired before a cloud mutation subcall")
        intent_path = self._ledger.append_cloud_mutation(
            {
                "schemaVersion": 1,
                "phase": "intent",
                "operationId": self._active_operation_id,
                "temporary": operation.get("temporary") is True,
                "method": method,
                "targetUrl": url,
                "requestBodySha256": sha256_bytes(body or b""),
                "authorizationSha256": sha256_bytes(canonical_json_bytes(self.authorization)),
                "sourceSha": self.authorization["source"]["mergedMain"]["commitSha"],
                "planSha256": self.authorization["plan"]["sha256"],
                "packageSha256": self.package["sha256"],
                "recordedAt": self.clock().astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            }
        )
        intent_id = intent_path.stem
        response = self.session.request(method, url, body=body, headers=headers)
        self._record_mutation(method, url, response, body, intent_id)
        if response.status not in expected:
            fail(f"mutation request returned unexpected HTTP status {response.status}")
        return response

    @staticmethod
    def _json_response(response: _RestResponse, expected: set[int], label: str) -> Mapping[str, Any]:
        if response.status not in expected:
            fail(f"{label} returned unexpected HTTP status {response.status}")
        try:
            value = json.loads(response.body) if response.body else {}
        except json.JSONDecodeError as exc:
            raise BootstrapError(f"{label} returned invalid JSON") from exc
        if not isinstance(value, dict):
            fail(f"{label} returned an invalid object")
        return value

    @staticmethod
    def _header(response: _RestResponse, name: str) -> str | None:
        return next(
            (value for key, value in response.headers.items() if key.lower() == name.lower()),
            None,
        )

    @staticmethod
    def _timestamp(value: dt.datetime) -> str:
        return (
            value.astimezone(dt.timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )

    @staticmethod
    def _webjob_output_url_metadata(value: Any) -> Mapping[str, Any]:
        if not isinstance(value, str) or not value or len(value) > 4096:
            fail("WebJob output URL is absent or oversized")
        parsed = urllib.parse.urlsplit(value)
        host = (parsed.hostname or "").lower()
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in {None, 443}
            or not host.endswith(".scm.azurewebsites.net")
            or parsed.query
            or parsed.fragment
            or not parsed.path.startswith("/")
        ):
            fail("WebJob output URL is not nonsecret fixed-host metadata")
        return {
            "scheme": "https",
            "host": host,
            "pathSha256": sha256_bytes(parsed.path.encode("utf-8")),
            "queryPresent": False,
        }

    def _project_webjob_history_item(
        self,
        value: Any,
        *,
        site_resource_id: str,
        job_name: str,
    ) -> Mapping[str, Any]:
        if not isinstance(value, Mapping):
            fail("WebJob history entry is not one object")
        history_id = value.get("id")
        properties = value.get("properties")
        runs = properties.get("runs") if isinstance(properties, Mapping) else None
        if (
            not isinstance(history_id, str)
            or not history_id.lower().startswith(
                (
                    site_resource_id
                    + f"/triggeredwebjobs/{job_name}/history/"
                ).lower()
            )
            or not isinstance(runs, list)
            or len(runs) != 1
            or not isinstance(runs[0], Mapping)
        ):
            fail("WebJob history entry identity is not exact")
        run = runs[0]
        run_id = run.get("web_job_id")
        status = run.get("status")
        started_at = run.get("start_time")
        ended_at = run.get("end_time")
        if (
            run.get("web_job_name") != job_name
            or not isinstance(run_id, str)
            or not re.fullmatch(r"[A-Za-z0-9._:-]{1,256}", run_id)
            or status
            not in {"Initializing", "Running", "Success", "Failed", "Aborted"}
            or not isinstance(started_at, str)
        ):
            fail("WebJob history run projection is not exact")
        start = parse_time(started_at, "WebJob history start")
        terminal = status in {"Success", "Failed", "Aborted"}
        if terminal:
            end = parse_time(ended_at, "WebJob history end")
            if end < start:
                fail("WebJob history end precedes its start")
            output_metadata = self._webjob_output_url_metadata(run.get("output_url"))
        else:
            if ended_at not in {None, ""}:
                fail("nonterminal WebJob history unexpectedly has an end time")
            output_metadata = None
        return {
            "historyId": history_id,
            "webJobsRunId": run_id,
            "status": status,
            "startedAt": started_at,
            "endedAt": ended_at if terminal else None,
            "outputUrlMetadata": output_metadata,
        }

    def _read_webjob_history(
        self,
        *,
        site_resource_id: str,
        job_name: str,
    ) -> Mapping[str, Any]:
        url = self._arm_url(
            site_resource_id,
            "2025-05-01",
            f"/triggeredwebjobs/{job_name}/history",
        )
        response = self.session.request("GET", url)
        document = self._json_response(response, {200}, "WebJob history")
        values = document.get("value")
        if (
            not isinstance(values, list)
            or document.get("nextLink") not in {None, ""}
            or len(values) > 1000
        ):
            fail("WebJob history is partial, paginated, or oversized")
        projected = [
            self._project_webjob_history_item(
                item,
                site_resource_id=site_resource_id,
                job_name=job_name,
            )
            for item in values
        ]
        ids = [item["historyId"] for item in projected]
        run_ids = [item["webJobsRunId"] for item in projected]
        if len(ids) != len(set(ids)) or len(run_ids) != len(set(run_ids)):
            fail("WebJob history contains duplicate history or run IDs")
        projected.sort(key=lambda item: item["historyId"])
        observed_at = self.clock()
        return {
            "observedAt": self._timestamp(observed_at),
            "entries": projected,
            "entriesSha256": sha256_bytes(canonical_json_bytes(projected)),
            "responseSha256": _response_sha256(response),
        }

    def _wait_for_fresh_webjob_success(
        self,
        *,
        site_resource_id: str,
        job_name: str,
        boundary: Mapping[str, Any],
        trigger_requested_at: dt.datetime,
    ) -> Mapping[str, Any]:
        before_entries = boundary.get("entries")
        if not isinstance(before_entries, list):
            fail("WebJob history boundary is not exact")
        before = {
            item["historyId"]: item
            for item in before_entries
            if isinstance(item, Mapping) and isinstance(item.get("historyId"), str)
        }
        if len(before) != len(before_entries):
            fail("WebJob history boundary contains invalid or duplicate entries")
        expires = parse_time(
            self.authorization["validity"]["expiresAt"],
            "authorization expiresAt",
        )
        deadline = min(
            expires,
            trigger_requested_at
            + dt.timedelta(seconds=MAX_CANARY_CONVERGENCE_SECONDS),
        )
        attempts = 0
        while attempts < 180:
            before_request = self.clock()
            if before_request >= deadline:
                fail("WebJob canary did not converge before authorization expiry")
            attempts += 1
            observed = self._read_webjob_history(
                site_resource_id=site_resource_id,
                job_name=job_name,
            )
            after_response = self.clock()
            if after_response >= deadline:
                fail("WebJob history response crossed the authorization deadline")
            entries = observed["entries"]
            current = {item["historyId"]: item for item in entries}
            if any(current.get(key) != value for key, value in before.items()):
                fail("pre-run WebJob history boundary drifted")
            fresh_ids = set(current) - set(before)
            if len(fresh_ids) > 1:
                fail("WebJob canary produced an ambiguous fresh history set")
            if len(fresh_ids) == 1:
                fresh = current[next(iter(fresh_ids))]
                start = parse_time(fresh["startedAt"], "fresh WebJob start")
                if start < trigger_requested_at - dt.timedelta(seconds=5):
                    fail("fresh WebJob run predates the authorized trigger")
                if fresh["status"] in {"Failed", "Aborted"}:
                    fail("fresh WebJob canary reached a terminal failure")
                if fresh["status"] == "Success":
                    end = parse_time(fresh["endedAt"], "fresh WebJob end")
                    if end > after_response + dt.timedelta(seconds=5):
                        fail("fresh WebJob completion time is in the future")
                    return {
                        "historyBoundary": dict(boundary),
                        "terminalHistory": fresh,
                        "terminalHistoryObservedAt": observed["observedAt"],
                        "terminalHistoryEntriesSha256": observed["entriesSha256"],
                        "terminalHistoryResponseSha256": observed["responseSha256"],
                        "pollAttempts": attempts,
                    }
            delay = min(1.0 + attempts * 0.25, 3.0)
            if self.clock() + dt.timedelta(seconds=delay) >= deadline:
                fail("WebJob canary polling would cross the authorization deadline")
            self.sleep(delay)
        fail("WebJob canary exceeded the source-bounded polling attempts")

    def _wait_for_site_state(
        self,
        *,
        site_resource_id: str,
        expected_state: str,
        allow_expired_cleanup: bool,
    ) -> Mapping[str, Any]:
        started = self.clock()
        deadline = started + dt.timedelta(seconds=MAX_READBACK_CONVERGENCE_SECONDS)
        expires = parse_time(
            self.authorization["validity"]["expiresAt"],
            "authorization expiresAt",
        )
        if not allow_expired_cleanup:
            deadline = min(deadline, expires)
        attempts = 0
        while attempts < 64:
            now = self.clock()
            if now >= deadline:
                fail(f"bridge did not reach {expected_state} before the readback deadline")
            attempts += 1
            response = self.session.request(
                "GET", self._arm_url(site_resource_id, "2025-03-01")
            )
            document = self._json_response(
                response, {200}, f"bridge {expected_state} readback"
            )
            properties = document.get("properties")
            if (
                isinstance(properties, Mapping)
                and properties.get("state") == expected_state
            ):
                return {
                    "attempts": attempts,
                    "observedAt": self._timestamp(self.clock()),
                    "resourceId": document.get("id"),
                    "state": expected_state,
                    "projectionSha256": sha256_bytes(
                        canonical_json_bytes(
                            {
                                "id": document.get("id"),
                                "name": document.get("name"),
                                "state": properties.get("state"),
                            }
                        )
                    ),
                }
            self.sleep(min(0.25 * (2 ** (attempts - 1)), 2.0))
        fail(f"bridge did not reach {expected_state} within bounded attempts")

    def _read_request_with_transport_retry(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
    ) -> _RestResponse:
        """Retry only exact read-only transport failures before mutation.

        Mutation requests continue to call the underlying session directly, so
        an ambiguous PUT/PATCH/DELETE is never replayed.  The sole allowed POST
        is ARM's fixed app-settings list operation, which is read-only.
        """

        allowed_posts = {
            request["url"]
            for request in _production_boundary_requests(self.plan)
            if request["method"] == "POST"
        }
        allowed_posts.add(
            _operation_readback_url(
                "configureBridgeExactVersionedPackageAndCriticalSettings",
                self.plan,
                self.authorization,
            )
        )
        if not (
            (method == "GET" and body is None)
            or (method == "POST" and url in allowed_posts and body == b"")
        ):
            fail("read-only retry helper received a mutation-capable request")
        delays: tuple[float | None, ...] = (0.5, 1.0, None)
        for delay in delays:
            try:
                return self.session.request(method, url, body=body)
            except BootstrapError as error:
                if str(error) != "Azure REST transport failed closed" or delay is None:
                    raise
                self.sleep(delay)
        raise AssertionError("unreachable read-only retry loop")

    def account(self) -> Mapping[str, Any]:
        return self.session.account()

    def _execute_probe(self, probe: Mapping[str, Any]) -> dict[str, Any]:
        response = self._read_request_with_transport_retry(
            probe["method"],
            probe["url"],
            body=b"" if probe["method"] == "POST" else None,
        )
        return {
            **probe,
            "status": response.status,
            "responseSha256": _preflight_response_sha256(
                probe["method"], probe["url"], response
            ),
        }

    @staticmethod
    def _nested_value(document: Mapping[str, Any], dotted_path: str) -> Any:
        value: Any = document
        for part in dotted_path.split("."):
            if not isinstance(value, Mapping) or part not in value:
                fail(f"readback dynamic field is absent: {dotted_path}")
            value = value[part]
        return value

    def _source_operation_projection(
        self,
        *,
        contract: Mapping[str, Any],
        response: _RestResponse,
        document: Mapping[str, Any],
        projection_document: Mapping[str, Any],
        runtime_facts: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """Retain the exact non-secret facts that satisfied one validator.

        A response digest alone is not evidence.  This projection deliberately
        keeps the security-relevant body fields that were validated above,
        while replacing the two secret-bearing surfaces (the uploader address
        and the full App Service settings map) with exact canonical digests.
        The terminal source-evidence validator accepts only these source-owned
        projection families.
        """

        operation_id = str(contract["operationId"])
        facts = dict(runtime_facts or {})
        properties = projection_document.get("properties")
        headers = {
            "etag": self._header(response, "ETag"),
            "versionId": self._header(response, "x-ms-version-id"),
            "leaseState": self._header(response, "x-ms-lease-state"),
            "leaseStatus": self._header(response, "x-ms-lease-status"),
        }
        headers = {key: value for key, value in headers.items() if value is not None}

        if operation_id == "removeControllerLeaseCanaryBlob":
            inventory = facts.get("controllerLockInventory")
            retained = {
                "absent": response.status == 404,
                "controllerLockInventory": inventory,
            }
            family = "controller-lock-empty-after-canary"
        elif response.status == 404:
            family = "exact-absence"
            retained: Any = {"absent": True}
        elif operation_id == "claimAzureSingleUseAuthorization":
            outputs = properties.get("outputs") if isinstance(properties, Mapping) else None
            claim = outputs.get("claim") if isinstance(outputs, Mapping) else None
            retained = {
                "resourceId": projection_document.get("id"),
                "deploymentName": projection_document.get("name"),
                "provisioningState": (
                    properties.get("provisioningState")
                    if isinstance(properties, Mapping)
                    else None
                ),
                "claim": claim.get("value") if isinstance(claim, Mapping) else None,
            }
            family = "azure-single-use-claim"
        elif operation_id in {
            "createPublisherApplication",
            "createPublisherServicePrincipal",
            "grantPublisherGraphApplicationReadAll",
        }:
            retained = {
                key: projection_document.get(key)
                for key in (
                    "id",
                    "appId",
                    "displayName",
                    "signInAudience",
                    "accountEnabled",
                    "servicePrincipalType",
                    "passwordCredentials",
                    "keyCredentials",
                    "appRoleAssignments",
                )
                if key in projection_document
            }
            family = "publisher-graph-projection"
        elif operation_id == "createSolePublisherFicToSignedBootstrapSource":
            retained = {
                "applicationObjectId": projection_document.get("id"),
                "federatedIdentityCredentials": projection_document.get(
                    "federatedIdentityCredentials"
                ),
            }
            family = "sole-publisher-fic-inventory"
        elif operation_id in {
            "createBridgeIdentity",
            "adoptExistingRegistryWriterIdentity",
            "adoptExistingRegistryReaderIdentity",
            "createSignerIdentity",
            "createProductionActivationIdentity",
        }:
            retained = {
                "id": projection_document.get("id"),
                "name": projection_document.get("name"),
                "type": projection_document.get("type"),
                "clientId": properties.get("clientId") if isinstance(properties, Mapping) else None,
                "principalId": properties.get("principalId") if isinstance(properties, Mapping) else None,
                "tenantId": properties.get("tenantId") if isinstance(properties, Mapping) else None,
            }
            family = "managed-identity-projection"
        elif operation_id == "createCustomRoleDefinitions":
            retained = {"roleDefinitions": facts.get("roleDefinitions")}
            family = "custom-role-definition-inventory"
        elif operation_id == "createExactRoleAssignments":
            retained = {"roleAssignments": facts.get("roleAssignments")}
            family = "role-assignment-inventory"
        elif operation_id in {
            "createPrivatePackageContainer",
            "createPrivateControllerLockContainer",
            "createPrivateActivationFenceContainer",
        }:
            retained = {
                "id": projection_document.get("id"),
                "name": projection_document.get("name"),
                "type": projection_document.get("type"),
                "publicAccess": properties.get("publicAccess") if isinstance(properties, Mapping) else None,
            }
            family = "private-container-projection"
        elif operation_id == "createSigningKeyVersion":
            attributes = properties.get("attributes") if isinstance(properties, Mapping) else None
            retained = {
                "keyUriWithVersion": properties.get("keyUriWithVersion") if isinstance(properties, Mapping) else None,
                "kty": properties.get("kty") if isinstance(properties, Mapping) else None,
                "keySize": properties.get("keySize") if isinstance(properties, Mapping) else None,
                "keyOps": properties.get("keyOps") if isinstance(properties, Mapping) else None,
                "enabled": attributes.get("enabled") if isinstance(attributes, Mapping) else None,
                "exportable": attributes.get("exportable", False) if isinstance(attributes, Mapping) else None,
                "expiresAt": attributes.get("exp") if isinstance(attributes, Mapping) else facts.get("expiresAt"),
                "releasePolicy": properties.get("release_policy") if isinstance(properties, Mapping) else None,
            }
            family = "signing-key-posture"
        elif operation_id in {
            "createStoppedPrivateBridge",
            "attachFiveUamisOnlyToBridge",
            "detachWriterAndReaderFromLegacyBridge",
        }:
            outbound = properties.get("outboundVnetRouting") if isinstance(properties, Mapping) else None
            retained = {
                "id": projection_document.get("id"),
                "name": projection_document.get("name"),
                "kind": projection_document.get("kind"),
                "httpsOnly": projection_document.get("httpsOnly"),
                "state": properties.get("state") if isinstance(properties, Mapping) else None,
                "publicNetworkAccess": properties.get("publicNetworkAccess") if isinstance(properties, Mapping) else None,
                "serverFarmId": properties.get("serverFarmId") if isinstance(properties, Mapping) else None,
                "virtualNetworkSubnetId": properties.get("virtualNetworkSubnetId") if isinstance(properties, Mapping) else None,
                "outboundVnetRouting": outbound,
                "identity": projection_document.get("identity"),
            }
            family = "webapp-nonsecret-posture"
        elif operation_id in {"addOwnedUploaderIpv4Rule", "removeOwnedUploaderIpv4Rule"}:
            network_acls = properties.get("networkAcls") if isinstance(properties, Mapping) else None
            if not isinstance(network_acls, Mapping):
                fail("storage ACL source projection is absent")
            network_acls = _normalize_storage_acl_prestate(network_acls)
            retained = {
                "networkAclsSha256": sha256_bytes(canonical_json_bytes(network_acls)),
                "defaultAction": network_acls.get("defaultAction"),
                "bypass": network_acls.get("bypass"),
                "ipRuleCount": len(network_acls.get("ipRules", [])) if isinstance(network_acls.get("ipRules"), list) else None,
                "resourceAccessRuleCount": len(network_acls.get("resourceAccessRules", [])) if isinstance(network_acls.get("resourceAccessRules"), list) else None,
                "virtualNetworkRules": network_acls.get("virtualNetworkRules"),
            }
            family = "storage-network-acl-redacted-projection"
        elif operation_id in {
            "addOwnedUploaderPackageRole",
            "addOwnedOperatorKeyReadRole",
            "addOwnedOperatorFenceBootstrapRole",
            "addOwnedOperatorControllerCanaryRole",
        }:
            retained = {
                key: facts.get(key)
                for key in (
                    "definitionResourceId",
                    "assignmentResourceId",
                    "definitionCreated",
                    "assignmentCreated",
                    "cleanupKey",
                )
            }
            retained["definition"] = facts.get("definitionProjection")
            retained["assignment"] = facts.get("assignmentProjection")
            family = "temporary-role-projection"
        elif operation_id in {
            "uploadVersionedBridgePackage",
            "createInitialIdleActivationFence",
            "createControllerLeaseCanaryBlob",
        }:
            retained = {
                key: facts.get(key)
                for key in ("url", "blob", "etag", "versionId", "sha256", "size", "cleanupKey")
                if key in facts
            }
            retained.update(
                {
                    "bodySha256": contract.get("expectedBodySha256"),
                    "bodySize": contract.get("expectedBodySize"),
                }
            )
            family = "versioned-blob-readback"
        elif operation_id == "readBackExactSigningPublicJwk":
            retained = {
                key: facts.get(key)
                for key in ("kid", "kty", "n", "e", "key_ops", "attributes")
            }
            family = "public-jwk-projection"
        elif operation_id == "exerciseControllerLeaseCanary":
            retained = facts
            family = "controller-lease-canary"
        elif operation_id == "configureBridgeExactVersionedPackageAndCriticalSettings":
            retained = {
                key: facts.get(key)
                for key in (
                    "preAppSettingsSha256",
                    "settingsSha256",
                    "bootstrapSelfTestControlSha256",
                    "packageUrl",
                    "packageVersionId",
                )
                if key in facts
            }
            family = "app-settings-digest-only"
        elif operation_id == "startBridgeForBoundedCanary":
            retained = facts
            family = "fresh-webjob-terminal-success-finally-stopped"
        elif operation_id in {
            "lockPackageRetentionAt91Days",
            "extendAcceptedRetentionFrom30To91Days",
            "extendResultRetentionFrom30To91Days",
        }:
            retained = {
                "id": projection_document.get("id"),
                "name": projection_document.get("name"),
                "type": projection_document.get("type"),
                "etag": projection_document.get("etag") or headers.get("etag"),
                "properties": {
                    key: properties.get(key)
                    for key in (
                        "state",
                        "immutabilityPeriodSinceCreationInDays",
                        "allowProtectedAppendWrites",
                        "allowProtectedAppendWritesAll",
                    )
                }
                if isinstance(properties, Mapping)
                else None,
                "stateAfterPut": facts.get("stateAfterPut"),
                "lockPostIssued": facts.get("lockPostIssued"),
            }
            family = "worm-policy-projection"
        elif operation_id == "createMailboxResourceGroup":
            retained = {
                key: projection_document.get(key)
                for key in ("id", "name", "type", "location")
            }
            family = "resource-group-projection"
        elif operation_id == "retireLegacyPublisherFic":
            remaining_credentials = _unpaginated_graph_collection(
                document, "legacy publisher FIC terminal inventory"
            )
            retained = {
                "applicationObjectId": self.plan["legacyPublisherRetirement"][
                    "applicationObjectId"
                ],
                "removedFederatedCredentialId": facts.get(
                    "federatedCredentialId"
                ),
                "federatedIdentityCredentials": remaining_credentials,
            }
            family = "legacy-publisher-fic-absence-inventory"
        elif operation_id in {
            "retireLegacyPublisherMutatorAssignment",
            "retireLegacyPublisherSitesReadAssignment",
            "retireLegacyPublisherResultReadAssignment",
            "removeLegacyWriterResultAssignment",
            "removeLegacyReaderResultAssignment",
        }:
            retained = {"absent": response.status == 404}
            family = "exact-absence"
        elif operation_id in {
            "removeOwnedUploaderPackageRole",
            "removeOwnedOperatorKeyReadRole",
            "removeOwnedOperatorFenceBootstrapRole",
            "removeOwnedOperatorControllerCanaryRole",
        }:
            retained = {
                key: facts.get(key)
                for key in (
                    "cleanupKey",
                    "assignmentResourceId",
                    "definitionResourceId",
                    "assignmentRemoved",
                    "definitionRemoved",
                    "assignmentAbsenceProjection",
                    "definitionAbsenceProjection",
                )
            }
            family = "temporary-role-cleanup-absence"
        else:
            fail(f"operation lacks a source-evidence projection family: {operation_id}")

        return {
            "schemaVersion": 1,
            "operationId": operation_id,
            "family": family,
            "method": contract["expectedMethod"],
            "url": contract["expectedUrl"],
            "status": response.status,
            "target": contract["target"],
            "targetResourceId": contract.get("targetResourceId"),
            "responseSha256": _response_sha256(response),
            "headers": headers,
            "projection": retained,
        }

    def _validate_readback_response(
        self,
        expected: Mapping[str, Any],
        response: _RestResponse,
        runtime_facts: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        contract = expected["validatorContract"]
        if (
            not isinstance(contract, Mapping)
            or expected["method"] != contract["expectedMethod"]
            or expected["url"] != contract["expectedUrl"]
            or response.status != contract["expectedStatus"]
        ):
            fail("readback status is not the source-defined invariant")
        document: Mapping[str, Any] = {}
        expected_body_sha = contract.get("expectedBodySha256")
        if expected_body_sha is not None:
            if (
                expected["url"] != contract.get("expectedUrl")
                or sha256_bytes(response.body) != expected_body_sha
                or len(response.body) != contract.get("expectedBodySize")
            ):
                fail("readback body or URL is not the exact source-defined artifact")
        elif response.body:
            try:
                parsed = json.loads(
                    response.body.decode("utf-8"),
                    object_pairs_hook=_duplicate_safe_pairs,
                    parse_constant=lambda value: fail(f"invalid JSON constant: {value}"),
                )
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BootstrapError("readback body is not canonical JSON") from exc
            if not isinstance(parsed, Mapping):
                fail("readback body is not one JSON object")
            document = parsed
        if contract["kind"] == "source-operation-invariants-v1" and response.status != 404:
            operation_id = contract["operationId"]
            projection_document: Mapping[str, Any] = document
            if operation_id in {
                "createPublisherApplication",
                "createPublisherServicePrincipal",
                "grantPublisherGraphApplicationReadAll",
            }:
                values = _unpaginated_graph_collection(
                    document, f"{operation_id} readback"
                )
                if len(values) != 1:
                    fail("Graph readback is not one exact source-named object")
                projection_document = values[0]
            elif operation_id == "createSolePublisherFicToSignedBootstrapSource":
                application, _credentials = _publisher_fic_inventory(
                    document,
                    self.plan,
                    self.authorization,
                    f"{operation_id} readback",
                )
                if application is None:
                    fail("publisher FIC readback has no exact application")
                projection_document = application
            target_id = contract.get("targetResourceId")
            target_name = contract.get("targetName")
            direct_resource_operations = {
                "claimAzureSingleUseAuthorization",
                "createMailboxResourceGroup",
                "createBridgeIdentity",
                "adoptExistingRegistryWriterIdentity",
                "adoptExistingRegistryReaderIdentity",
                "createSignerIdentity",
                "createProductionActivationIdentity",
                "createPrivatePackageContainer",
                "createPrivateControllerLockContainer",
                "createPrivateActivationFenceContainer",
                "createStoppedPrivateBridge",
                "attachFiveUamisOnlyToBridge",
                "detachWriterAndReaderFromLegacyBridge",
                "addOwnedUploaderIpv4Rule",
                "removeOwnedUploaderIpv4Rule",
                "startBridgeForBoundedCanary",
            }
            if (
                operation_id in direct_resource_operations
                and isinstance(target_id, str)
                and target_id.startswith("/")
                and expected_body_sha is None
            ):
                observed_id = projection_document.get("id")
                if not isinstance(observed_id, str) or observed_id.lower() != target_id.lower():
                    fail("readback resource ID is outside the fixed target")
            if operation_id in direct_resource_operations and isinstance(target_name, str):
                observed_name = projection_document.get("name") or projection_document.get("displayName")
                if expected_body_sha is None and observed_name != target_name:
                    fail("readback resource name is outside the fixed target")
            for specification in contract["dynamicFields"]:
                dotted, kind = specification.rsplit(":", 1)
                if dotted.startswith("header."):
                    value = self._header(response, dotted.split(".", 1)[1])
                else:
                    value = self._nested_value(projection_document, dotted)
                if kind == "guid":
                    _guid(value, f"{contract['operationId']} dynamic {dotted}")
                elif kind == "quoted-etag":
                    _quoted_etag(value, f"{contract['operationId']} dynamic {dotted}")
                elif kind == "nonempty":
                    if not isinstance(value, str) or not value or len(value) > 512:
                        fail("readback dynamic version is invalid")
                elif kind == "key-version-uri":
                    if not isinstance(value, str) or re.fullmatch(
                        r"https://kv-mds-sea-9c4e0d0d\.vault\.azure\.net/keys/paperdesk-release-result-signing/[0-9a-f]{32}",
                        value,
                    ) is None:
                        fail("readback key version URI is outside the fixed key")
                else:
                    fail("readback dynamic-field kind is unknown")
            fact_paths = {
                "createPublisherApplication": {"objectId": "id", "appId": "appId"},
                "createPublisherServicePrincipal": {"objectId": "id", "principalId": "id", "appId": "appId"},
                "createBridgeIdentity": {"resourceId": "id", "clientId": "properties.clientId", "principalId": "properties.principalId"},
                "createSignerIdentity": {"resourceId": "id", "clientId": "properties.clientId", "principalId": "properties.principalId"},
                "createProductionActivationIdentity": {"resourceId": "id", "clientId": "properties.clientId", "principalId": "properties.principalId"},
                "createSigningKeyVersion": {"keyUriWithVersion": "properties.keyUriWithVersion"},
            }.get(operation_id, {})
            for fact_name, response_path in fact_paths.items():
                if runtime_facts is None or fact_name not in runtime_facts:
                    fail(f"dynamic readback lacks mutation fact: {operation_id}.{fact_name}")
                observed_value = self._nested_value(projection_document, response_path)
                expected_value = runtime_facts[fact_name]
                if fact_name == "resourceId":
                    if str(observed_value).lower() != str(expected_value).lower():
                        fail("dynamic resource ID did not cross-bind to the mutation response")
                elif observed_value != expected_value:
                    fail("dynamic readback did not cross-bind to the mutation response")
            if operation_id in {
                "uploadVersionedBridgePackage",
                "createInitialIdleActivationFence",
                "createControllerLeaseCanaryBlob",
            }:
                if runtime_facts is None:
                    fail("blob readback lacks the mutation response facts")
                if (
                    self._header(response, "ETag") != runtime_facts.get("etag")
                    or self._header(response, "x-ms-version-id") != runtime_facts.get("versionId")
                ):
                    fail("blob readback ETag/version did not cross-bind to the mutation response")

            properties = projection_document.get("properties")
            if operation_id == "claimAzureSingleUseAuthorization":
                outputs = properties.get("outputs") if isinstance(properties, Mapping) else None
                claim = outputs.get("claim") if isinstance(outputs, Mapping) else None
                value = claim.get("value") if isinstance(claim, Mapping) else None
                expected_claim = {
                    "authorizationId": self.authorization["authorizationId"],
                    "authorizationSha256": sha256_bytes(canonical_json_bytes(self.authorization)),
                    "sourceSha": self.authorization["source"]["mergedMain"]["commitSha"],
                    "planSha256": self.authorization["plan"]["sha256"],
                    "packageSha256": self.package["sha256"],
                }
                if (
                    value != expected_claim
                    or not isinstance(properties, Mapping)
                    or properties.get("provisioningState") != "Succeeded"
                ):
                    fail("Azure single-use claim readback is not exact")
            elif operation_id == "createCustomRoleDefinitions":
                values = document.get("value")
                if (
                    not isinstance(values, list)
                    or document.get("nextLink") not in {None, ""}
                    or runtime_facts is None
                ):
                    fail("custom role-definition inventory is partial")
                expected_definitions = _custom_role_definition_specs(self.plan)
                relevant: dict[str, Mapping[str, Any]] = {}
                for item in values:
                    if not isinstance(item, Mapping):
                        fail("custom role-definition inventory contains a non-object")
                    item_id = str(item.get("id", "")).lower()
                    matching = [
                        definition_id
                        for definition_id, projection in expected_definitions.items()
                        if str(projection["id"]).lower() == item_id
                    ]
                    if matching:
                        if matching[0] in relevant:
                            fail("custom role-definition inventory contains a duplicate")
                        relevant[matching[0]] = _project_role_definition(item)
                if relevant != expected_definitions:
                    fail("custom role-definition inventory is incomplete or drifted")
                expected_list = [
                    expected_definitions[key] for key in sorted(expected_definitions)
                ]
                if runtime_facts.get("roleDefinitions") != expected_list:
                    fail("custom role mutation facts differ from source policy")
            elif operation_id == "createExactRoleAssignments":
                values = document.get("value")
                expected_list = (
                    runtime_facts.get("roleAssignments")
                    if runtime_facts is not None
                    else None
                )
                if (
                    not isinstance(values, list)
                    or document.get("nextLink") not in {None, ""}
                    or not isinstance(expected_list, list)
                    or len(expected_list) != len(self.plan["roleMatrix"])
                ):
                    fail("role-assignment inventory is partial")
                expected_by_id = {
                    str(item.get("id", "")).lower(): item
                    for item in expected_list
                    if isinstance(item, Mapping)
                }
                if len(expected_by_id) != len(expected_list):
                    fail("role-assignment mutation facts contain duplicates")
                observed: dict[str, Mapping[str, Any]] = {}
                for item in values:
                    if not isinstance(item, Mapping):
                        fail("role-assignment inventory contains a non-object")
                    item_id = str(item.get("id", "")).lower()
                    if item_id in expected_by_id:
                        if item_id in observed:
                            fail("role-assignment inventory contains a duplicate")
                        observed[item_id] = _project_role_assignment(item)
                if observed != expected_by_id:
                    fail("role-assignment inventory is incomplete or drifted")
            elif operation_id == "createMailboxResourceGroup":
                if str(projection_document.get("location", "")).lower() != self.plan["azure"]["location"]:
                    fail("mailbox resource group location is not exact")
            elif operation_id == "createPublisherApplication":
                if (
                    projection_document.get("displayName") != self.resources["publisherApplication"]["name"]
                    or projection_document.get("signInAudience") != "AzureADMyOrg"
                    or projection_document.get("passwordCredentials") != []
                    or projection_document.get("keyCredentials") != []
                ):
                    fail("publisher application readback is not credentialless and exact")
            elif operation_id == "createPublisherServicePrincipal":
                if (
                    projection_document.get("displayName") != self.resources["publisherServicePrincipal"]["name"]
                    or projection_document.get("accountEnabled") is not True
                    or projection_document.get("servicePrincipalType") != "Application"
                    or projection_document.get("passwordCredentials") != []
                    or projection_document.get("keyCredentials") != []
                    or runtime_facts is None
                    or projection_document.get("appId") != runtime_facts.get("appId")
                ):
                    fail("publisher service-principal readback is not exact")
            elif operation_id == "grantPublisherGraphApplicationReadAll":
                assignments = projection_document.get("appRoleAssignments")
                publisher_id = projection_document.get("id")
                if (
                    runtime_facts is None
                    or projection_document.get(
                        "appRoleAssignments@odata.nextLink"
                    )
                    not in {None, ""}
                    or projection_document.get("accountEnabled") is not True
                    or projection_document.get("servicePrincipalType") != "Application"
                    or projection_document.get("passwordCredentials") != []
                    or projection_document.get("keyCredentials") != []
                    or not isinstance(assignments, list)
                    or len(assignments) != 1
                    or not isinstance(assignments[0], Mapping)
                    or assignments[0].get("id") != runtime_facts.get("assignmentId")
                    or assignments[0].get("principalId") != publisher_id
                    or assignments[0].get("resourceId") != runtime_facts.get("resourceId")
                    or assignments[0].get("appRoleId") != self.GRAPH_APPLICATION_READ_ALL
                ):
                    fail("publisher Graph Application.Read.All assignment is not sole and exact")
            elif operation_id == "retireLegacyPublisherFic":
                values = _unpaginated_graph_collection(
                    document, "legacy publisher FIC readback"
                )
                removed_id = runtime_facts.get("federatedCredentialId") if runtime_facts else None
                if (
                    not isinstance(values, list)
                    or values != []
                    or not GUID.fullmatch(str(removed_id))
                    or any(isinstance(item, Mapping) and item.get("id") == removed_id for item in values)
                ):
                    fail("legacy publisher FIC absence was not proven")
            elif operation_id in {
                "createBridgeIdentity",
                "createSignerIdentity",
                "createProductionActivationIdentity",
                "adoptExistingRegistryWriterIdentity",
                "adoptExistingRegistryReaderIdentity",
            }:
                if (
                    projection_document.get("type") != "Microsoft.ManagedIdentity/userAssignedIdentities"
                    or not isinstance(properties, Mapping)
                    or str(properties.get("tenantId", "")).lower() != TENANT
                ):
                    fail("managed identity readback posture is not exact")
                fixed_target = {
                    "adoptExistingRegistryWriterIdentity": "registryWriterIdentity",
                    "adoptExistingRegistryReaderIdentity": "registryReaderIdentity",
                }.get(operation_id)
                if fixed_target is not None:
                    fixed = self.resources[fixed_target]
                    if (
                        properties.get("clientId") != fixed["clientId"]
                        or properties.get("principalId") != fixed["principalId"]
                    ):
                        fail("adopted registry identity readback drifted")
            elif operation_id in {
                "createPrivatePackageContainer",
                "createPrivateControllerLockContainer",
                "createPrivateActivationFenceContainer",
            }:
                public_access = properties.get("publicAccess") if isinstance(properties, Mapping) else None
                if public_access not in {None, "None"}:
                    fail("bootstrap storage container is not private")
            elif operation_id == "createSigningKeyVersion":
                attributes = properties.get("attributes") if isinstance(properties, Mapping) else None
                if (
                    not isinstance(properties, Mapping)
                    or properties.get("kty") != "RSA"
                    or properties.get("keySize") != 3072
                    or properties.get("keyOps") != ["sign", "verify"]
                    or not isinstance(attributes, Mapping)
                    or attributes.get("enabled") is not True
                    or attributes.get("exportable", False) is not False
                    or runtime_facts is None
                    or attributes.get("exp")
                    != int(
                        parse_time(
                            self.admissions[operation_id]["context"].get("expiresAt"),
                            "signing key authorized expiresAt",
                        ).timestamp()
                    )
                    or properties.get("release_policy") is not None
                ):
                    fail("signing key version readback is not exact")
            elif operation_id == "createStoppedPrivateBridge":
                identity = projection_document.get("identity")
                outbound = properties.get("outboundVnetRouting") if isinstance(properties, Mapping) else None
                if (
                    projection_document.get("kind") != "app,linux"
                    or projection_document.get("httpsOnly") is not True
                    or not isinstance(properties, Mapping)
                    or properties.get("serverFarmId", "").lower()
                    != self.resources["bridgeAppServicePlan"]["resourceId"].lower()
                    or properties.get("publicNetworkAccess") != "Disabled"
                    or properties.get("virtualNetworkSubnetId", "").lower()
                    != self.resources["integrationSubnet"]["resourceId"].lower()
                    or outbound != {"allTraffic": True, "applicationTraffic": True}
                    or properties.get("state") != "Stopped"
                    or not isinstance(identity, Mapping)
                    or identity.get("type") not in {"None", None}
                    or identity.get("userAssignedIdentities") not in (None, {})
                ):
                    fail("stopped private bridge readback is not exact")
            elif operation_id == "attachFiveUamisOnlyToBridge":
                identity = projection_document.get("identity")
                attached = identity.get("userAssignedIdentities") if isinstance(identity, Mapping) else None
                expected_ids = runtime_facts.get("identityResourceIds") if runtime_facts else None
                if (
                    not isinstance(identity, Mapping)
                    or identity.get("type") != "UserAssigned"
                    or not isinstance(attached, Mapping)
                    or not isinstance(expected_ids, list)
                    or {str(item).lower() for item in attached}
                    != {str(item).lower() for item in expected_ids}
                ):
                    fail("bridge UAMI attachment readback is not exact")
            elif operation_id == "detachWriterAndReaderFromLegacyBridge":
                identity = projection_document.get("identity")
                if isinstance(identity, Mapping) and (
                    identity.get("type") not in {"None", None}
                    or identity.get("userAssignedIdentities") not in (None, {})
                ):
                    fail("legacy bridge still has a user-assigned identity")
            elif operation_id in {"addOwnedUploaderIpv4Rule", "removeOwnedUploaderIpv4Rule"}:
                network_acls = properties.get("networkAcls") if isinstance(properties, Mapping) else None
                expected_digest = (
                    runtime_facts.get("addedNetworkAclsSha256")
                    if operation_id.startswith("add")
                    else runtime_facts.get("restoredNetworkAclsSha256")
                    if runtime_facts
                    else None
                )
                if (
                    not isinstance(network_acls, Mapping)
                    or sha256_bytes(canonical_json_bytes(network_acls)) != expected_digest
                ):
                    fail("storage network ACL readback is not exact")
            elif operation_id in {
                "addOwnedUploaderPackageRole",
                "addOwnedOperatorKeyReadRole",
                "addOwnedOperatorFenceBootstrapRole",
                "addOwnedOperatorControllerCanaryRole",
            }:
                if (
                    not isinstance(properties, Mapping)
                    or runtime_facts is None
                    or str(projection_document.get("id", "")).lower()
                    != str(runtime_facts.get("assignmentResourceId", "")).lower()
                    or properties.get("principalId")
                    != self.authorization["azure"]["accountObjectId"]
                    or str(properties.get("roleDefinitionId", "")).lower()
                    != str(runtime_facts.get("definitionResourceId", "")).lower()
                    or properties.get("condition") is not None
                    or properties.get("delegatedManagedIdentityResourceId") is not None
                ):
                    fail("temporary role assignment readback is not exact")
            elif operation_id in {
                "lockPackageRetentionAt91Days",
                "extendAcceptedRetentionFrom30To91Days",
                "extendResultRetentionFrom30To91Days",
            }:
                if (
                    not isinstance(properties, Mapping)
                    or runtime_facts is None
                    or runtime_facts.get("stateAfterPut")
                    not in {"Locked", "Unlocked"}
                    or runtime_facts.get("lockPostIssued")
                    is not (runtime_facts.get("stateAfterPut") == "Unlocked")
                    or properties.get("state") != "Locked"
                    or type(properties.get("immutabilityPeriodSinceCreationInDays")) is not int
                    or properties["immutabilityPeriodSinceCreationInDays"] < 91
                    or properties.get("allowProtectedAppendWrites", False) is not False
                    or properties.get("allowProtectedAppendWritesAll", False) is not False
                ):
                    fail("WORM policy readback is not Locked for at least 91 days")
            elif operation_id == "configureBridgeExactVersionedPackageAndCriticalSettings":
                settings = document.get("properties")
                if (
                    not isinstance(settings, Mapping)
                    or runtime_facts is None
                    or sha256_bytes(canonical_json_bytes(settings))
                    != runtime_facts.get("settingsSha256")
                ):
                    fail("bridge full app-settings map readback is not exact")
            elif operation_id == "readBackExactSigningPublicJwk":
                values = document.get("value")
                kid = runtime_facts.get("kid") if runtime_facts else None
                if not isinstance(values, list) or any(
                    not isinstance(item, Mapping) for item in values
                ):
                    fail("public signing JWK versions inventory is invalid")
                matches = [item for item in values if item.get("kid") == kid]
                observed_attributes = (
                    matches[0].get("attributes") if len(matches) == 1 else None
                )
                retained_attributes = (
                    {
                        name: observed_attributes.get(name)
                        for name in (
                            "enabled",
                            "nbf",
                            "exp",
                            "created",
                            "updated",
                            "recoveryLevel",
                            "recoverableDays",
                            "exportable",
                        )
                    }
                    if isinstance(observed_attributes, Mapping)
                    else None
                )
                if (
                    runtime_facts is None
                    or document.get("nextLink") not in {None, ""}
                    or len(matches) != 1
                    or retained_attributes != runtime_facts.get("attributes")
                ):
                    fail("public signing JWK versions readback is not exact")
            elif operation_id == "exerciseControllerLeaseCanary":
                fast_lane = runtime_facts.get("fastLane") if runtime_facts else None
                expiry_fallback = runtime_facts.get("expiryFallback") if runtime_facts else None
                if (
                    runtime_facts is None
                    or runtime_facts.get("releaseStatus") != 200
                    or runtime_facts.get("renewals")
                    != self.plan["temporaryAccess"]["leaseRenewals"]
                    or runtime_facts.get("durationSeconds")
                    != self.plan["temporaryAccess"]["leaseDurationSeconds"]
                    or not isinstance(fast_lane, Mapping)
                    or fast_lane.get("finalLeaseState") != "available"
                    or not isinstance(expiry_fallback, Mapping)
                    or expiry_fallback.get("leaseId")
                    != self.plan["temporaryAccess"]["controllerExpiryLeaseId"]
                    or expiry_fallback.get("releaseIntentionallyOmitted") is not True
                    or expiry_fallback.get("finalLeaseState") != "available"
                    or str(self._header(response, "x-ms-lease-state") or "").lower()
                    != "available"
                ):
                    fail("controller lock lease canary did not release to Available")
            elif operation_id == "startBridgeForBoundedCanary":
                if (
                    runtime_facts is None
                    or runtime_facts.get("selfCleaned") is not True
                    or runtime_facts.get("terminalHistory", {}).get("status")
                    != "Success"
                    or not isinstance(properties, Mapping)
                    or properties.get("state") != "Stopped"
                ):
                    fail(
                        "bridge canary lacks fresh terminal Success or finally-stop readback"
                    )
            elif operation_id == "createSolePublisherFicToSignedBootstrapSource":
                credentials = projection_document.get("federatedIdentityCredentials")
                if not isinstance(credentials, list) or len(credentials) != 1 or not isinstance(credentials[0], Mapping):
                    fail("publisher FIC inventory is not sole")
                _validate_exact_publisher_fic(
                    credentials[0],
                    self.plan,
                    self.authorization,
                    "publisher FIC readback",
                )
        source_projection = self._source_operation_projection(
            contract=contract,
            response=response,
            document=document,
            projection_document=(
                projection_document
                if contract["kind"] == "source-operation-invariants-v1"
                and response.status != 404
                else document
            ),
            runtime_facts=runtime_facts,
        ) if contract["kind"] == "source-operation-invariants-v1" else None
        if source_projection is not None:
            operation_id = contract["operationId"]
            source_projection = _validate_operation_source_projection(
                source_projection,
                operation_id=operation_id,
                plan=self.plan,
                authorization=self.authorization,
                prior=self._validated_source_projections,
                operation_context=self.admissions[operation_id]["context"],
                runtime_facts=runtime_facts,
            )
            self._validated_source_projections[operation_id] = source_projection
            if operation_id == "uploadVersionedBridgePackage":
                package_bytes = bytes(response.body)
                if (
                    self._package_readback_bytes is not None
                    and self._package_readback_bytes != package_bytes
                ):
                    fail("package exact-version readback bytes changed during execution")
                self._package_readback_bytes = package_bytes
        return {
            "id": expected["id"],
            "validatorId": expected["validatorId"],
            "status": response.status,
            "responseSha256": _response_sha256(response),
            "sourceProjection": source_projection,
        }

    def _prove_probe_ids(
        self,
        ids: Sequence[str],
        label: str,
        *,
        runtime_facts: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        proofs: list[dict[str, Any]] = []
        for probe_id in ids:
            expected = self.probes[probe_id]
            if expected["phase"] != "readback":
                fail("readback proof referenced a preflight-only probe")
            started = self.clock()
            attempts = 0
            last_error: BootstrapError | None = None
            expires = parse_time(
                self.authorization["validity"]["expiresAt"],
                "authorization expiresAt",
            )
            not_before = parse_time(
                self.authorization["validity"]["notBefore"],
                "authorization notBefore",
            )
            deadline = min(expires, started + dt.timedelta(seconds=MAX_READBACK_CONVERGENCE_SECONDS))
            while attempts < 64:
                before_request = self.clock()
                if before_request < not_before or before_request >= deadline:
                    last_error = BootstrapError("authorization or convergence window expired before readback")
                    break
                attempts += 1
                response = self._read_request_with_transport_retry(
                    expected["method"],
                    expected["url"],
                    body=b"" if expected["method"] == "POST" else None,
                )
                after_response = self.clock()
                if after_response >= deadline:
                    last_error = BootstrapError("authorization or convergence window expired during readback")
                    break
                try:
                    observed = self._validate_readback_response(
                        expected, response, runtime_facts=runtime_facts
                    )
                except BootstrapError as exc:
                    last_error = exc
                    now = after_response
                    if attempts >= 64 or now >= deadline:
                        break
                    delay = min(0.25 * (2 ** (attempts - 1)), 2.0)
                    if now + dt.timedelta(seconds=delay) >= deadline:
                        break
                    self.sleep(delay)
                    continue
                observed.update(
                    {
                        "attempts": attempts,
                        "startedAt": started.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                        "observedAt": after_response.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                    }
                )
                proofs.append(observed)
                break
            else:  # pragma: no cover - loop exits through success/break
                last_error = BootstrapError("readback did not converge")
            if len(proofs) == 0 or proofs[-1]["id"] != probe_id:
                detail = str(last_error) if last_error is not None else "unknown drift"
                fail(f"{label} readback did not converge: {probe_id}: {detail}")
        return proofs

    def collect_preflight(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        if plan is not self.plan and canonical_json_bytes(plan) != canonical_json_bytes(self.plan):
            fail("Azure transport received a different plan")
        projection = json.loads(canonical_json_bytes(self.preflight["projection"]))
        boundary_ids = set(
            projection["productionBoundaryObservation"]["probeIds"]
        )
        for index, probe in enumerate(projection["probes"]):
            if probe["phase"] == "preflight" and probe["id"] not in boundary_ids:
                projection["probes"][index] = self._execute_probe(probe)
        boundary_projection, boundary_probes = self._collect_production_boundary()
        for index, probe in enumerate(projection["probes"]):
            if probe["id"] in boundary_probes:
                projection["probes"][index] = boundary_probes[probe["id"]]
        projection["productionBoundaryObservation"][
            "sourceProjection"
        ] = boundary_projection
        self._fresh_projection = projection
        return projection

    def _collect_production_boundary(
        self,
    ) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
        documents: dict[str, Any] = {}
        observed_probes: dict[str, dict[str, Any]] = {}
        for request in _production_boundary_requests(self.plan):
            response = self._read_request_with_transport_retry(
                request["method"],
                request["url"],
                body=b"" if request["method"] == "POST" else None,
            )
            document = self._json_response(
                response, {200}, f"production boundary {request['id']}"
            )
            documents[request["id"]] = document
            original = self.probes[request["id"]]
            digest_document = _production_boundary_digest_document(
                request["method"], request["url"], document
            )
            observed_probes[request["id"]] = {
                **original,
                "status": response.status,
                "responseSha256": sha256_bytes(canonical_json_bytes(digest_document)),
            }
        return (
            _project_production_boundary_documents(documents, self.plan),
            observed_probes,
        )

    def observe_production_boundary(self) -> Mapping[str, Any]:
        projection, _ = self._collect_production_boundary()
        return projection

    def inspect_operation(
        self, operation: Mapping[str, Any], state: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if self._fresh_projection is None:
            fail("operation inspection occurred before fresh preflight")
        admission = self.admissions.get(operation["id"])
        if admission is None:
            fail("operation is not in the authorized preflight")
        return {
            "operationId": operation["id"],
            "status": admission["status"],
            "preflightProbeIds": list(admission["probeIds"]),
            "admissionSha256": sha256_bytes(canonical_json_bytes(admission)),
        }

    def _arm_url(self, resource_id: str, api_version: str, suffix: str = "") -> str:
        if not resource_id.startswith(f"/subscriptions/{SUBSCRIPTION}/"):
            fail("ARM resource ID is outside the fixed subscription")
        return f"{self.ARM_ROOT}{resource_id}{suffix}?api-version={api_version}"

    def _arm_put(
        self,
        resource_id: str,
        api_version: str,
        body: Mapping[str, Any],
        *,
        headers: Mapping[str, str] | None = None,
        expected: set[int] = {200, 201},
    ) -> Mapping[str, Any]:
        body_bytes = canonical_json_bytes(body)
        response = self._mutation_request(
            "PUT",
            self._arm_url(resource_id, api_version),
            body=body_bytes,
            headers={"Content-Type": "application/json", **dict(headers or {})},
            expected=expected,
        )
        result = dict(self._json_response(response, expected, "ARM PUT"))
        etag = self._header(response, "ETag")
        if etag is not None:
            result["_responseEtag"] = etag
        return result

    def _arm_delete(self, resource_id: str, api_version: str) -> None:
        url = self._arm_url(resource_id, api_version)
        self._mutation_request("DELETE", url, expected={200, 202, 204})

    def _graph_json(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, Any] | None = None,
        expected: set[int],
    ) -> Mapping[str, Any]:
        if not path.startswith(("/v1.0/", "/beta/")) or ".." in path:
            fail("Graph request path is outside the exact boundary")
        body_bytes = canonical_json_bytes(body) if body is not None else None
        if method == "GET":
            response = self.session.request(
                method,
                self.GRAPH_ROOT + path,
                body=body_bytes,
                headers={"Content-Type": "application/json"} if body is not None else None,
            )
        else:
            response = self._mutation_request(
                method,
                self.GRAPH_ROOT + path,
                body=body_bytes,
                headers={"Content-Type": "application/json"} if body is not None else None,
                expected=expected,
            )
        return self._json_response(response, expected, "Graph request")

    def _proof_detail(self, state: Mapping[str, Any], operation_id: str) -> Mapping[str, Any]:
        proof = state.get("proofs", {}).get(operation_id)
        details = proof.get("details") if isinstance(proof, Mapping) else None
        if not isinstance(details, Mapping):
            fail(f"required mutation detail is absent: {operation_id}")
        return details

    def _admission_context(self, operation_id: str) -> Mapping[str, Any]:
        context = self.admissions[operation_id]["context"]
        if not isinstance(context, Mapping):
            fail("operation context is invalid")
        return context

    def _identity_detail(self, state: Mapping[str, Any], principal: str) -> Mapping[str, Any]:
        source = {
            "publisherServicePrincipal": "createPublisherServicePrincipal",
            "bridgeIdentity": "createBridgeIdentity",
            "signerIdentity": "createSignerIdentity",
            "productionActivationIdentity": "createProductionActivationIdentity",
        }.get(principal)
        if source is not None:
            return self._proof_detail(state, source)
        resource = self.resources.get(principal)
        if resource is None:
            fail(f"role principal is unknown: {principal}")
        principal_id = resource.get("principalId")
        if not isinstance(principal_id, str):
            fail(f"role principal ID is unbound: {principal}")
        return {"principalId": principal_id, "resourceId": resource.get("resourceId")}

    def _resource_scope(self, scope: str) -> str:
        if scope == "subscription":
            return f"/subscriptions/{SUBSCRIPTION}"
        if isinstance(scope, str) and scope.lower().startswith(
            f"/subscriptions/{SUBSCRIPTION}/".lower()
        ):
            return scope
        resource = self.resources.get(scope)
        if resource is None or not isinstance(resource.get("resourceId"), str):
            fail(f"role scope is unknown: {scope}")
        return resource["resourceId"]

    def _create_uami(self, operation_id: str, target: str) -> Mapping[str, Any]:
        resource = self.resources[target]
        result = self._arm_put(
            resource["resourceId"],
            "2023-01-31",
            {"location": self.plan["azure"]["location"]},
        )
        properties = result.get("properties")
        if not isinstance(properties, dict):
            fail("created UAMI has no exact identity properties")
        details = {
            "resourceId": str(result.get("id", "")).lower(),
            "clientId": properties.get("clientId"),
            "principalId": properties.get("principalId"),
        }
        if (
            details["resourceId"] != resource["resourceId"].lower()
            or not GUID.fullmatch(str(details["clientId"]))
            or not GUID.fullmatch(str(details["principalId"]))
        ):
            fail("created UAMI readback is invalid")
        return details

    def _mutate(self, operation: Mapping[str, Any], state: Mapping[str, Any]) -> Mapping[str, Any]:
        operation_id = operation["id"]
        context = self._admission_context(operation_id)
        authorization = self.authorization
        source_sha = authorization["source"]["mergedMain"]["commitSha"]

        if operation_id == "claimAzureSingleUseAuthorization":
            resource_id = authorization["singleUse"]["azureClaimResourceId"]
            body = {
                "location": self.plan["azure"]["location"],
                "properties": {
                    "mode": "Incremental",
                    "template": {
                        "$schema": "https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#",
                        "contentVersion": "1.0.0.0",
                        "parameters": {},
                        "resources": [],
                        "outputs": {
                            "claim": {
                                "type": "object",
                                "value": {
                                    "authorizationId": authorization["authorizationId"],
                                    "authorizationSha256": state["authorizationSha256"],
                                    "sourceSha": source_sha,
                                    "planSha256": state["planSha256"],
                                    "packageSha256": state["package"]["sha256"],
                                },
                            }
                        },
                    },
                    "parameters": {},
                },
            }
            result = self._arm_put(
                resource_id,
                "2022-09-01",
                body,
                # Subscription-scope deployments do not expose an
                # If-None-Match contract.  The authorized preflight proves the
                # deterministic name absent and HTTP 201 is required here;
                # HTTP 200 (update/replay) fails closed.
                expected={201},
            )
            return {"resourceId": resource_id, "deploymentName": result.get("name")}

        if operation_id == "createMailboxResourceGroup":
            resource = self.resources["mailboxResourceGroup"]
            return self._arm_put(
                resource["resourceId"],
                "2022-09-01",
                {"location": self.plan["azure"]["location"]},
            )

        if operation_id == "createPublisherApplication":
            result = self._graph_json(
                "POST",
                "/v1.0/applications",
                body={
                    "displayName": self.resources["publisherApplication"]["name"],
                    "signInAudience": "AzureADMyOrg",
                },
                expected={201},
            )
            if (
                result.get("displayName") != self.resources["publisherApplication"]["name"]
                or result.get("signInAudience") != "AzureADMyOrg"
                or result.get("passwordCredentials") not in (None, [])
                or result.get("keyCredentials") not in (None, [])
            ):
                fail("publisher application creation returned an unsafe projection")
            return {"objectId": result.get("id"), "appId": result.get("appId")}

        if operation_id == "createPublisherServicePrincipal":
            application = self._proof_detail(state, "createPublisherApplication")
            result = self._graph_json(
                "POST",
                "/v1.0/servicePrincipals",
                body={"appId": application["appId"], "accountEnabled": True},
                expected={201},
            )
            if result.get("appId") != application["appId"] or result.get("accountEnabled") is not True:
                fail("publisher service principal creation returned an unsafe projection")
            return {"objectId": result.get("id"), "appId": result.get("appId"), "principalId": result.get("id")}

        if operation_id == "grantPublisherGraphApplicationReadAll":
            publisher = self._proof_detail(state, "createPublisherServicePrincipal")
            graph = self._graph_json(
                "GET",
                f"/v1.0/servicePrincipals?$filter=appId%20eq%20'{self.GRAPH_APP_ID}'&$select=id,appId",
                expected={200},
            )
            values = _unpaginated_graph_collection(
                graph, "Microsoft Graph service principal inventory"
            )
            if len(values) != 1 or values[0].get("appId") != self.GRAPH_APP_ID:
                fail("Microsoft Graph service principal inventory is not unique")
            result = self._graph_json(
                "POST",
                f"/v1.0/servicePrincipals/{publisher['objectId']}/appRoleAssignments",
                body={
                    "principalId": publisher["objectId"],
                    "resourceId": values[0]["id"],
                    "appRoleId": self.GRAPH_APPLICATION_READ_ALL,
                },
                expected={201},
            )
            return {"assignmentId": result.get("id"), "resourceId": result.get("resourceId")}

        if operation_id == "retireLegacyPublisherFic":
            fic_id = context.get("legacyFederatedCredentialId")
            if not GUID.fullmatch(str(fic_id)):
                fail("legacy FIC ID is not exact authorization-bound context")
            target_url = (
                f"{self.GRAPH_ROOT}/beta/applications/"
                f"{self.plan['legacyPublisherRetirement']['applicationObjectId']}/"
                f"federatedIdentityCredentials/{fic_id}"
            )
            response = self._mutation_request(
                "DELETE",
                target_url,
                expected={204},
            )
            return {"federatedCredentialId": fic_id}

        legacy_assignment_operations = {
            "retireLegacyPublisherMutatorAssignment": self.plan["legacyPublisherRetirement"]["roleAssignmentResourceIds"][0],
            "retireLegacyPublisherSitesReadAssignment": self.plan["legacyPublisherRetirement"]["roleAssignmentResourceIds"][1],
            "retireLegacyPublisherResultReadAssignment": self.plan["legacyPublisherRetirement"]["roleAssignmentResourceIds"][2],
            "removeLegacyWriterResultAssignment": self.plan["legacyPublisherRetirement"]["legacyWriterResultAssignmentResourceId"],
            "removeLegacyReaderResultAssignment": self.plan["legacyPublisherRetirement"]["legacyReaderResultAssignmentResourceId"],
        }
        if operation_id in legacy_assignment_operations:
            resource_id = legacy_assignment_operations[operation_id]
            self._arm_delete(resource_id, "2022-04-01")
            return {"removedResourceId": resource_id}

        if operation_id in {
            "createBridgeIdentity",
            "createSignerIdentity",
            "createProductionActivationIdentity",
        }:
            target = {
                "createBridgeIdentity": "bridgeIdentity",
                "createSignerIdentity": "signerIdentity",
                "createProductionActivationIdentity": "productionActivationIdentity",
            }[operation_id]
            return self._create_uami(operation_id, target)

        if operation_id in {"adoptExistingRegistryWriterIdentity", "adoptExistingRegistryReaderIdentity"}:
            target = {
                "adoptExistingRegistryWriterIdentity": "registryWriterIdentity",
                "adoptExistingRegistryReaderIdentity": "registryReaderIdentity",
            }[operation_id]
            resource = self.resources[target]
            return {
                "resourceId": resource["resourceId"],
                "clientId": resource["clientId"],
                "principalId": resource["principalId"],
            }

        if operation_id == "detachWriterAndReaderFromLegacyBridge":
            legacy = self.resources["legacyBridgeSite"]
            target_url = self._arm_url(legacy["resourceId"], "2025-03-01")
            request_body = canonical_json_bytes({"identity": {"type": "None"}})
            response = self._mutation_request(
                "PATCH",
                target_url,
                body=request_body,
                headers={"Content-Type": "application/json", "If-Match": str(context.get("etag", ""))},
                expected={200},
            )
            self._json_response(response, {200}, "legacy bridge identity detach")
            return {"resourceId": legacy["resourceId"], "detached": ["registryWriterIdentity", "registryReaderIdentity"]}

        if operation_id in {
            "createPrivatePackageContainer",
            "createPrivateControllerLockContainer",
            "createPrivateActivationFenceContainer",
        }:
            target = {
                "createPrivatePackageContainer": "packageContainer",
                "createPrivateControllerLockContainer": "controllerLockContainer",
                "createPrivateActivationFenceContainer": "activationFenceContainer",
            }[operation_id]
            resource = self.resources[target]
            return self._arm_put(
                resource["resourceId"],
                "2025-06-01",
                {"properties": {"publicAccess": "None"}},
            )

        if operation_id == "createSigningKeyVersion":
            expires_at = parse_time(context.get("expiresAt"), "signing key expiresAt")
            if expires_at < parse_time(
                self.authorization["validity"]["expiresAt"],
                "authorization expiresAt",
            ) + dt.timedelta(days=30):
                fail("signing key authorization lifetime is too short")
            result = self._arm_put(
                self.resources["signingKey"]["resourceId"],
                "2023-07-01",
                {
                    "properties": {
                        "kty": "RSA",
                        "keySize": 3072,
                        "keyOps": ["sign", "verify"],
                        "attributes": {
                            "enabled": True,
                            "exportable": False,
                            "exp": int(expires_at.timestamp()),
                        },
                    }
                },
            )
            properties = result.get("properties")
            if not isinstance(properties, dict) or not isinstance(properties.get("keyUriWithVersion"), str):
                fail("signing key version readback is incomplete")
            return {"keyUriWithVersion": properties["keyUriWithVersion"]}

        if operation_id == "createCustomRoleDefinitions":
            specs = _custom_role_definition_specs(self.plan)
            observed: list[dict[str, Any]] = []
            for definition_id in sorted(specs):
                expected_projection = specs[definition_id]
                resource_id = expected_projection["id"]
                url = self._arm_url(resource_id, "2022-04-01")
                before = self.session.request("GET", url)
                state_name = "absent" if before.status == 404 else "exact"
                if before.status == 200:
                    current = self._json_response(
                        before, {200}, f"custom role {definition_id} precondition"
                    )
                    if _project_role_definition(current) != expected_projection:
                        fail(f"custom role definition is a third state: {definition_id}")
                elif before.status != 404:
                    fail(f"custom role definition precondition failed: {definition_id}")
                if context["memberStates"][definition_id] != state_name:
                    fail(f"custom role definition drifted after authorization: {definition_id}")
                if state_name == "absent":
                    response = self._mutation_request(
                        "PUT",
                        url,
                        body=canonical_json_bytes(
                            {"properties": expected_projection["properties"]}
                        ),
                        headers={"Content-Type": "application/json", "If-None-Match": "*"},
                        expected={201},
                    )
                    created = self._json_response(
                        response, {201}, f"custom role {definition_id} create"
                    )
                    if _project_role_definition(created) != expected_projection:
                        fail(f"custom role create response drifted: {definition_id}")
                readback = self._json_response(
                    self.session.request("GET", url),
                    {200},
                    f"custom role {definition_id} readback",
                )
                projection = _project_role_definition(readback)
                if projection != expected_projection:
                    fail(f"custom role definition readback drifted: {definition_id}")
                observed.append(projection)
            return {
                "roleDefinitions": observed,
                "roleDefinitionsSha256": sha256_bytes(canonical_json_bytes(observed)),
            }

        if operation_id == "createExactRoleAssignments":
            observed: list[dict[str, Any]] = []
            for role in self.plan["roleMatrix"]:
                principal = self._identity_detail(state, role["principal"])
                expected_projection = _role_assignment_spec(
                    self.plan, role, principal["principalId"]
                )
                assignment_id = expected_projection["id"]
                url = self._arm_url(assignment_id, "2022-04-01")
                before = self.session.request("GET", url)
                state_name = "absent" if before.status == 404 else "exact"
                if before.status == 200:
                    current = self._json_response(
                        before, {200}, f"role assignment {role['name']} precondition"
                    )
                    if _project_role_assignment(current) != expected_projection:
                        fail(f"role assignment is a third state: {role['name']}")
                elif before.status != 404:
                    fail(f"role assignment precondition failed: {role['name']}")
                if context["memberStates"][role["assignmentId"]] != state_name:
                    fail(f"role assignment drifted after authorization: {role['name']}")
                if state_name == "absent":
                    response = self._mutation_request(
                        "PUT",
                        url,
                        body=canonical_json_bytes(
                            {"properties": {
                                key: expected_projection["properties"][key]
                                for key in (
                                    "principalId", "principalType", "roleDefinitionId"
                                )
                            }}
                        ),
                        headers={"Content-Type": "application/json", "If-None-Match": "*"},
                        expected={201},
                    )
                    created = self._json_response(
                        response, {201}, f"role assignment {role['name']} create"
                    )
                    if _project_role_assignment(created) != expected_projection:
                        fail(f"role assignment create response drifted: {role['name']}")
                readback = self._json_response(
                    self.session.request("GET", url),
                    {200},
                    f"role assignment {role['name']} readback",
                )
                projection = _project_role_assignment(readback)
                if projection != expected_projection:
                    fail(f"role assignment readback drifted: {role['name']}")
                observed.append(projection)
            observed.sort(key=lambda item: str(item["id"]).lower())
            return {
                "roleAssignments": observed,
                "roleAssignmentsSha256": sha256_bytes(canonical_json_bytes(observed)),
            }

        if operation_id == "createStoppedPrivateBridge":
            site = self.resources["bridgeSite"]
            result = self._arm_put(
                site["resourceId"],
                "2025-03-01",
                {
                    "location": self.plan["azure"]["location"],
                    "kind": "app,linux",
                    "identity": {"type": "None"},
                    "properties": {
                        "serverFarmId": self.resources["bridgeAppServicePlan"]["resourceId"],
                        "httpsOnly": True,
                        "publicNetworkAccess": "Disabled",
                        "virtualNetworkSubnetId": self.resources["integrationSubnet"]["resourceId"],
                        "outboundVnetRouting": {"allTraffic": True, "applicationTraffic": True},
                        "siteConfig": {
                            "alwaysOn": True,
                            "linuxFxVersion": "PYTHON|3.12",
                            "ftpsState": "Disabled",
                            "minTlsVersion": "1.2",
                            "scmMinTlsVersion": "1.2",
                            "http20Enabled": True,
                            "vnetRouteAllEnabled": True,
                        },
                    },
                },
            )
            for policy in ("ftp", "scm"):
                self._arm_put(
                    site["resourceId"] + f"/basicPublishingCredentialsPolicies/{policy}",
                    "2025-03-01",
                    {"properties": {"allow": False}},
                )
            stop_url = self._arm_url(site["resourceId"], "2025-03-01", "/stop")
            stop = self._mutation_request(
                "POST", stop_url, body=b"", expected={200, 202}
            )
            current_response = self.session.request(
                "GET", self._arm_url(site["resourceId"], "2025-03-01")
            )
            current = self._json_response(current_response, {200}, "stopped bridge readback")
            if (
                str(current.get("id", "")).lower() != site["resourceId"].lower()
                or current.get("name") != site["name"]
                or current.get("properties", {}).get("state") != "Stopped"
            ):
                fail("new private bridge did not reach the exact stopped state")
            etag = self._header(current_response, "ETag") or current.get("etag")
            _quoted_etag(etag, "created bridge ETag")
            return {"resourceId": site["resourceId"], "name": result.get("name"), "etag": etag}

        if operation_id == "attachFiveUamisOnlyToBridge":
            site = self.resources["bridgeSite"]
            bridge = self._proof_detail(state, "createStoppedPrivateBridge")
            bridge_etag = _quoted_etag(bridge.get("etag"), "current bridge ETag")
            identity_ids = [
                self._identity_detail(state, name)["resourceId"]
                for name in (
                    "bridgeIdentity",
                    "registryWriterIdentity",
                    "registryReaderIdentity",
                    "signerIdentity",
                    "productionActivationIdentity",
                )
            ]
            target_url = self._arm_url(site["resourceId"], "2025-03-01")
            request_body = canonical_json_bytes(
                {
                    "identity": {
                        "type": "UserAssigned",
                        "userAssignedIdentities": {resource_id: {} for resource_id in identity_ids},
                    }
                }
            )
            response = self._mutation_request(
                "PATCH",
                target_url,
                body=request_body,
                headers={"Content-Type": "application/json", "If-Match": bridge_etag},
                expected={200},
            )
            self._json_response(response, {200}, "bridge UAMI attachment")
            return {"resourceId": site["resourceId"], "identityResourceIds": identity_ids}

        if operation_id in {"addOwnedUploaderIpv4Rule", "removeOwnedUploaderIpv4Rule"}:
            ip_value = context.get("uploaderIpv4")
            try:
                network = ipaddress.ip_network(str(ip_value), strict=True)
            except ValueError as exc:
                raise BootstrapError("uploader IPv4 is invalid") from exc
            if network.version != 4 or network.prefixlen != 32:
                fail("uploader IPv4 must be one exact /32")
            account = self.resources["storageAccount"]
            target_url = self._arm_url(account["resourceId"], "2025-06-01")

            def read_current_acl(label: str) -> dict[str, Any]:
                current_response = self.session.request("GET", target_url)
                current = self._json_response(current_response, {200}, label)
                properties = current.get("properties")
                network_acls = (
                    properties.get("networkAcls")
                    if isinstance(properties, Mapping)
                    else None
                )
                return _normalize_storage_acl_prestate(network_acls)

            if operation_id == "addOwnedUploaderIpv4Rule":
                restore = dict(context["preNetworkAcls"])
                if read_current_acl("storage ACL pre-mutation readback") != restore:
                    fail("storage ACL changed after authorization; re-observe before apply")
                desired = dict(restore)
                desired["ipRules"] = [{"value": str(network.network_address), "action": "Allow"}]
            else:
                add_proof = self._proof_detail(state, "addOwnedUploaderIpv4Rule")
                expected_added_sha = add_proof.get("addedNetworkAclsSha256")
                current_acl = read_current_acl("storage ACL cleanup readback")
                if (
                    sha256_bytes(canonical_json_bytes(current_acl))
                    != expected_added_sha
                ):
                    fail("storage ACL cleanup found concurrent drift; manual cleanup is required")
                restore = dict(context["restoreNetworkAcls"])
                desired = restore
            # Patch only the temporary IPv4 list.  Azure's Storage RP exposes
            # no storage-account ETag, so this is not an atomic compare/swap.
            # The exact pre/post reads and minimal PATCH bound the window but
            # cannot detect a same-window unrelated administrator ipRules
            # update that the PATCH overwrites.  The executable confirmation
            # phrase must explicitly accept this disclosed residual.
            request_body = canonical_json_bytes(
                {"properties": {"networkAcls": {"ipRules": desired["ipRules"]}}}
            )
            response = self._mutation_request(
                "PATCH",
                target_url,
                body=request_body,
                headers={"Content-Type": "application/json"},
                expected={200},
            )
            details = {
                "cleanupKey": "uploader-ipv4-rule",
                "uploaderIpv4": str(network),
                "addedNetworkAclsSha256": sha256_bytes(canonical_json_bytes(desired)) if operation_id.startswith("add") else None,
                "restoredNetworkAclsSha256": sha256_bytes(canonical_json_bytes(desired)) if operation_id.startswith("remove") else None,
            }
            try:
                self._json_response(response, {200}, "storage exact ACL mutation")
                if read_current_acl("storage ACL post-mutation readback") != desired:
                    fail("storage ACL mutation did not produce the exact reviewed topology")
            except BaseException as exc:
                if operation_id == "addOwnedUploaderIpv4Rule":
                    raise OwnedTemporaryMutationError(
                        "storage ACL add returned success but exact post-readback failed",
                        {
                            "operationId": operation_id,
                            "status": "applied-readback-pending",
                            "owned": True,
                            "cleanupKey": details["cleanupKey"],
                            "details": details,
                        },
                    ) from exc
                raise
            return details

        if operation_id in {
            "addOwnedUploaderPackageRole",
            "removeOwnedUploaderPackageRole",
            "addOwnedOperatorKeyReadRole",
            "removeOwnedOperatorKeyReadRole",
            "addOwnedOperatorFenceBootstrapRole",
            "removeOwnedOperatorFenceBootstrapRole",
            "addOwnedOperatorControllerCanaryRole",
            "removeOwnedOperatorControllerCanaryRole",
        }:
            return self._mutate_temporary_role(operation_id, state)

        if operation_id == "uploadVersionedBridgePackage":
            with tempfile.TemporaryDirectory(prefix="paperdesk-v2-apply-package-") as folder:
                target = Path(folder) / "paperdesk-private-release-bridge.zip"
                package_builder.build(target)
                body = target.read_bytes()
            if sha256_bytes(body) != self.package["sha256"] or len(body) != self.package["size"]:
                fail("bridge package bytes drifted after authorization")
            blob = f"v2/control/{source_sha}/paperdesk-private-release-bridge.zip"
            url = f"{self.STORAGE_ROOT}/{self.resources['packageContainer']['name']}/{blob}"
            response = self._mutation_request(
                "PUT",
                url,
                body=body,
                headers={
                    "Content-Type": "application/zip",
                    "x-ms-blob-type": "BlockBlob",
                    "x-ms-version": "2023-11-03",
                    "If-None-Match": "*",
                    "x-ms-meta-sha256": self.package["sha256"],
                },
                expected={201},
            )
            etag = self._header(response, "ETag")
            version_id = self._header(response, "x-ms-version-id")
            if not etag or not version_id:
                fail("versioned bridge package response lacks ETag/version")
            return {
                "blob": blob,
                "etag": etag,
                "versionId": version_id,
                "url": url,
                "sha256": self.package["sha256"],
                "size": self.package["size"],
            }

        if operation_id in {
            "lockPackageRetentionAt91Days",
            "extendAcceptedRetentionFrom30To91Days",
            "extendResultRetentionFrom30To91Days",
        }:
            target = {
                "lockPackageRetentionAt91Days": "packageContainer",
                "extendAcceptedRetentionFrom30To91Days": "acceptedContainer",
                "extendResultRetentionFrom30To91Days": "resultContainer",
            }[operation_id]
            container = self.resources[target]
            policy = container["resourceId"] + "/immutabilityPolicies/default"
            current_etag = context.get("etag")
            result = self._arm_put(
                policy,
                "2025-06-01",
                {
                    "properties": {
                        "immutabilityPeriodSinceCreationInDays": 91,
                        "allowProtectedAppendWrites": False,
                        "allowProtectedAppendWritesAll": False,
                    }
                },
                headers={"If-Match": str(current_etag)} if current_etag else {"If-None-Match": "*"},
            )
            properties = result.get("properties")
            state_name = properties.get("state") if isinstance(properties, dict) else None
            if state_name not in {"Locked", "Unlocked"}:
                fail("immutability policy PUT returned an unknown state")
            lock_post_issued = state_name == "Unlocked"
            if state_name != "Locked":
                lock_url = self._arm_url(policy, "2025-06-01", "/lock")
                response = self._mutation_request(
                    "POST", lock_url, body=b"", expected={200}
                )
                self._json_response(response, {200}, "immutability policy lock")
            return {
                "policyResourceId": policy,
                "days": 91,
                "stateAfterPut": state_name,
                "lockPostIssued": lock_post_issued,
            }

        if operation_id == "configureBridgeExactVersionedPackageAndCriticalSettings":
            upload = self._proof_detail(state, "uploadVersionedBridgePackage")
            desired = dict(context["preAppSettings"])
            expected_url = f"{upload['url']}?versionid={urllib.parse.quote(str(upload['versionId']), safe='') }"
            reader_id = self.resources["registryReaderIdentity"]["resourceId"]
            self_test_control = _bootstrap_self_test_control(
                self.authorization, state
            )
            self_test_control_bytes = canonical_json_bytes(self_test_control)
            critical = {
                "WEBSITE_RUN_FROM_PACKAGE": expected_url,
                "WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID": reader_id,
                "WEBSITE_SKIP_RUNNING_KUDUAGENT": "false",
                "PAPERDESK_BRIDGE_PACKAGE_SHA256": self.package["sha256"],
                "PAPERDESK_BRIDGE_BOOTSTRAP_SELF_TEST_JSON": (
                    self_test_control_bytes.decode("utf-8")
                ),
            }
            desired.update(critical)
            site = self.resources["bridgeSite"]
            current_response = self.session.request(
                "POST",
                self._arm_url(site["resourceId"], "2025-03-01", "/config/appsettings/list"),
                body=b"",
            )
            current = self._json_response(current_response, {200}, "bridge app-settings precondition")
            current_settings = current.get("properties")
            current_etag = self._header(current_response, "ETag") or current.get("etag")
            if (
                not isinstance(current_settings, dict)
                or current_settings != context["preAppSettings"]
                or sha256_bytes(canonical_json_bytes(current_settings))
                != context["preAppSettingsSha256"]
            ):
                fail("bridge app settings drifted after authorization")
            _quoted_etag(current_etag, "bridge app-settings precondition ETag")
            result = self._arm_put(
                site["resourceId"] + "/config/appsettings",
                "2025-03-01",
                {"properties": desired},
                headers={"If-Match": current_etag},
            )
            return {
                "resourceId": result.get("id"),
                "settingsSha256": sha256_bytes(canonical_json_bytes(desired)),
                "preAppSettingsSha256": context["preAppSettingsSha256"],
                "packageUrl": expected_url,
                "packageVersionId": upload["versionId"],
                "bootstrapSelfTestControl": self_test_control,
                "bootstrapSelfTestControlSha256": sha256_bytes(
                    self_test_control_bytes
                ),
            }

        if operation_id == "readBackExactSigningPublicJwk":
            key = self._proof_detail(state, "createSigningKeyVersion")
            url = key["keyUriWithVersion"] + "?api-version=7.4"
            response = self.session.request("GET", url)
            document = self._json_response(response, {200}, "Key Vault public key readback")
            value = document.get("key")
            attributes = document.get("attributes")
            if (
                not isinstance(value, dict)
                or value.get("kty") != "RSA"
                or value.get("key_ops") != ["sign", "verify"]
                or value.get("e") != "AQAB"
                or not isinstance(attributes, dict)
            ):
                fail("Key Vault public JWK is not exact")
            retained_attributes = {
                name: attributes.get(name)
                for name in (
                    "enabled",
                    "nbf",
                    "exp",
                    "created",
                    "updated",
                    "recoveryLevel",
                    "recoverableDays",
                    "exportable",
                )
            }
            return {
                "kid": value.get("kid"),
                "kty": value.get("kty"),
                "n": value.get("n"),
                "e": value.get("e"),
                "key_ops": value.get("key_ops"),
                "attributes": retained_attributes,
            }

        if operation_id == "createInitialIdleActivationFence":
            body = canonical_json_bytes(
                {
                    "schemaVersion": 1,
                    "state": "idle",
                    "stateVersion": 0,
                    "operation": "",
                    "sourceSha": "",
                    "pendingRelease": None,
                    "preSettingsSha256": "",
                    "desiredSettingsSha256": "",
                    "leaseId": "",
                    "lastStatus": "bootstrap",
                    "lastProofSha256": "0" * 64,
                }
            )
            url = self.resources["activationFenceBlob"]["resourceId"]
            response = self._mutation_request(
                "PUT",
                url,
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "x-ms-blob-type": "BlockBlob",
                    "x-ms-version": "2023-11-03",
                    "If-None-Match": "*",
                    "x-ms-meta-sha256": sha256_bytes(body),
                },
                expected={201},
            )
            return {"url": url, "etag": self._header(response, "ETag"), "versionId": self._header(response, "x-ms-version-id"), "sha256": sha256_bytes(body)}

        if operation_id == "createControllerLeaseCanaryBlob":
            blob = self.plan["temporaryAccess"]["controllerCanaryBlobTemplate"].replace(
                "${authorization.authorizationId}", self.authorization["authorizationId"]
            )
            url = (
                f"{self.STORAGE_ROOT}/{self.resources['controllerLockContainer']['name']}/"
                f"{blob}"
            )
            body = canonical_json_bytes(
                {
                    "schemaVersion": 1,
                    "mode": "controller-lock-finite-lease-canary",
                    "authorizationId": self.authorization["authorizationId"],
                    "sourceSha": source_sha,
                    "planSha256": self.authorization["plan"]["sha256"],
                }
            )
            response = self._mutation_request(
                "PUT",
                url,
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "x-ms-blob-type": "BlockBlob",
                    "x-ms-version": "2023-11-03",
                    "If-None-Match": "*",
                    "x-ms-meta-sha256": sha256_bytes(body),
                },
                expected={201},
            )
            etag = self._header(response, "ETag")
            version_id = self._header(response, "x-ms-version-id")
            _quoted_etag(etag, "controller canary blob ETag")
            if not isinstance(version_id, str) or not version_id:
                fail("controller canary blob lacks an exact version ID")
            return {
                "url": url,
                "etag": etag,
                "versionId": version_id,
                "sha256": sha256_bytes(body),
                "cleanupKey": "controller-lease-canary-blob",
            }

        if operation_id == "exerciseControllerLeaseCanary":
            created = self._proof_detail(state, "createControllerLeaseCanaryBlob")
            url = created["url"]
            lease_id = self.plan["temporaryAccess"]["controllerLeaseId"]
            expiry_lease_id = self.plan["temporaryAccess"]["controllerExpiryLeaseId"]
            duration = self.plan["temporaryAccess"]["leaseDurationSeconds"]
            identity = {
                "kind": "authorized-local-azure-account",
                "objectId": self.authorization["azure"]["accountObjectId"],
            }
            query_url = f"{url}?comp=lease"

            def observed_stamp() -> str:
                return self.clock().astimezone(dt.timezone.utc).isoformat(
                    timespec="milliseconds"
                ).replace("+00:00", "Z")

            def release(candidate: str) -> tuple[int, str]:
                response = self._mutation_request(
                    "PUT",
                    query_url,
                    body=b"",
                    headers={
                        "x-ms-version": "2023-11-03",
                        "x-ms-lease-action": "release",
                        "x-ms-lease-id": candidate,
                    },
                    expected={200},
                    cleanup=True,
                )
                return response.status, observed_stamp()

            fast_acquired = False
            fast_acquired_at = None
            fast_renewed_at: list[str] = []
            fast_release_status = None
            fast_released_at = None
            try:
                self._mutation_request(
                    "PUT",
                    query_url,
                    body=b"",
                    headers={
                        "x-ms-version": "2023-11-03",
                        "x-ms-proposed-lease-id": lease_id,
                        "x-ms-lease-duration": str(duration),
                        "x-ms-lease-action": "acquire",
                    },
                    expected={201},
                )
                fast_acquired = True
                fast_acquired_at = observed_stamp()
                for _ in range(self.plan["temporaryAccess"]["leaseRenewals"]):
                    self._mutation_request(
                        "PUT",
                        query_url,
                        body=b"",
                        headers={
                            "x-ms-version": "2023-11-03",
                            "x-ms-lease-action": "renew",
                            "x-ms-lease-id": lease_id,
                        },
                        expected={200},
                    )
                    fast_renewed_at.append(observed_stamp())
            finally:
                if fast_acquired:
                    fast_release_status, fast_released_at = release(lease_id)

            expiry_acquired_at = None
            try:
                self._mutation_request(
                    "PUT",
                    query_url,
                    body=b"",
                    headers={
                        "x-ms-version": "2023-11-03",
                        "x-ms-proposed-lease-id": expiry_lease_id,
                        "x-ms-lease-duration": str(duration),
                        "x-ms-lease-action": "acquire",
                    },
                    expected={201},
                )
                expiry_acquired_at = observed_stamp()
            except BaseException:
                # The request may have reached Storage even when the response
                # or local result-journal write was ambiguous.  The proposed
                # ID is deterministic, so cleanup first attempts an exact
                # release and then relies on finite expiry if release fails.
                try:
                    release(expiry_lease_id)
                except BaseException:
                    pass
                raise

            available_at = None
            attempts = 0
            maximum_attempts = duration // 2 + 20
            while attempts < maximum_attempts:
                attempts += 1
                response = self.session.request(
                    "GET",
                    url,
                    headers={"x-ms-version": "2023-11-03"},
                )
                if response.status != 200:
                    fail("controller lease expiry readback failed")
                state_name = str(self._header(response, "x-ms-lease-state") or "").lower()
                if state_name == "available":
                    available_at = observed_stamp()
                    break
                if state_name not in {"leased", "breaking", "broken", "expired"}:
                    fail("controller lease expiry reached an unknown state")
                self.sleep(2.0)
            if available_at is None:
                fail("controller lease did not reach Available after finite expiry")
            return {
                "url": url,
                "leaseId": lease_id,
                "durationSeconds": duration,
                "renewals": len(fast_renewed_at),
                "releaseStatus": fast_release_status,
                "identity": identity,
                "fastLane": {
                    "acquiredAt": fast_acquired_at,
                    "renewedAt": fast_renewed_at,
                    "releasedAt": fast_released_at,
                    "finalLeaseState": "available",
                },
                "expiryFallback": {
                    "leaseId": expiry_lease_id,
                    "acquiredAt": expiry_acquired_at,
                    "releaseIntentionallyOmitted": True,
                    "availableAt": available_at,
                    "pollAttempts": attempts,
                    "finalLeaseState": "available",
                },
                "selfCleaned": True,
            }

        if operation_id == "removeControllerLeaseCanaryBlob":
            created = self._proof_detail(state, "createControllerLeaseCanaryBlob")
            response = self._mutation_request(
                "DELETE",
                created["url"],
                body=None,
                headers={
                    "x-ms-version": "2023-11-03",
                    "If-Match": _quoted_etag(created["etag"], "controller canary cleanup ETag"),
                    "x-ms-delete-snapshots": "include",
                },
                expected={202},
            )
            container_url = (
                f"{self.STORAGE_ROOT}/{self.resources['controllerLockContainer']['name']}"
            )
            list_url = container_url + "?restype=container&comp=list"
            inventory_response = self.session.request(
                "GET",
                list_url,
                headers={"x-ms-version": "2023-11-03"},
            )
            if inventory_response.status != 200 or len(inventory_response.body) > 1_000_000:
                fail("controller lock post-canary inventory could not be read exactly")
            try:
                root = ET.fromstring(inventory_response.body)
            except ET.ParseError as exc:
                raise BootstrapError("controller lock post-canary inventory XML is invalid") from exc
            blobs_node = root.find("Blobs")
            next_marker_node = root.find("NextMarker")
            if blobs_node is None or next_marker_node is None:
                fail("controller lock post-canary inventory XML is incomplete")
            blob_names = [
                str(node.text or "")
                for node in blobs_node.findall("Blob/Name")
            ]
            if any(not name for name in blob_names) or blob_names != sorted(set(blob_names)):
                fail("controller lock post-canary blob inventory is invalid")
            inventory = {
                "containerUrl": container_url,
                "listUrl": list_url,
                "httpStatus": inventory_response.status,
                "blobNames": blob_names,
                "blobCount": len(blob_names),
                "nextMarker": str(next_marker_node.text or ""),
            }
            if blob_names or inventory["nextMarker"]:
                fail("controller lock container is not empty after canary cleanup")
            return {
                "url": created["url"],
                "cleanupKey": "controller-lease-canary-blob",
                "deleteStatus": response.status,
                "controllerLockInventory": inventory,
            }

        if operation_id == "startBridgeForBoundedCanary":
            site = self.resources["bridgeSite"]
            job = "paperdesk-accepted-release-registry"
            initial = self._wait_for_site_state(
                site_resource_id=site["resourceId"],
                expected_state="Stopped",
                allow_expired_cleanup=False,
            )
            start_url = self._arm_url(site["resourceId"], "2025-03-01", "/start")
            stop_url = self._arm_url(site["resourceId"], "2025-03-01", "/stop")
            run_url = self._arm_url(
                site["resourceId"],
                "2025-05-01",
                f"/triggeredwebjobs/{job}/run",
            )
            start_attempted = False
            primary_error: BaseException | None = None
            stop_error: BaseException | None = None
            canary: Mapping[str, Any] | None = None
            running: Mapping[str, Any] | None = None
            stopped: Mapping[str, Any] | None = None
            trigger_status: int | None = None
            trigger_requested_at: dt.datetime | None = None
            try:
                # Once the intent is durable, even an ambiguous transport
                # failure is followed by an exact stop in the cleanup path.
                start_attempted = True
                self._mutation_request(
                    "POST", start_url, body=b"", expected={200, 202}
                )
                running = self._wait_for_site_state(
                    site_resource_id=site["resourceId"],
                    expected_state="Running",
                    allow_expired_cleanup=False,
                )
                boundary = self._read_webjob_history(
                    site_resource_id=site["resourceId"],
                    job_name=job,
                )
                trigger_requested_at = self.clock()
                run = self._mutation_request(
                    "POST",
                    run_url,
                    body=b"",
                    expected={200, 202, 204},
                )
                trigger_status = run.status
                canary = self._wait_for_fresh_webjob_success(
                    site_resource_id=site["resourceId"],
                    job_name=job,
                    boundary=boundary,
                    trigger_requested_at=trigger_requested_at,
                )
            except BaseException as exc:
                primary_error = exc
            finally:
                if start_attempted:
                    try:
                        self._mutation_request(
                            "POST",
                            stop_url,
                            body=b"",
                            expected={200, 202},
                            cleanup=True,
                        )
                        stopped = self._wait_for_site_state(
                            site_resource_id=site["resourceId"],
                            expected_state="Stopped",
                            allow_expired_cleanup=True,
                        )
                    except BaseException as exc:
                        stop_error = exc
            if primary_error is not None:
                if stop_error is not None:
                    raise BootstrapError(
                        "bridge canary failed and exact finally-stop also failed; "
                        "the durable mutation journal requires operator recovery"
                    ) from primary_error
                raise BootstrapError(
                    f"bridge canary failed before terminal Success: {primary_error}"
                ) from primary_error
            if stop_error is not None:
                raise BootstrapError(
                    "bridge canary reached terminal Success but exact finally-stop failed"
                ) from stop_error
            if (
                canary is None
                or running is None
                or stopped is None
                or trigger_requested_at is None
                or trigger_status is None
            ):
                fail("bridge canary proof is incomplete")
            configure = self._proof_detail(
                state, "configureBridgeExactVersionedPackageAndCriticalSettings"
            )
            upload = self._proof_detail(state, "uploadVersionedBridgePackage")
            fence = self._proof_detail(state, "createInitialIdleActivationFence")
            return {
                "resourceId": site["resourceId"],
                "cleanupKey": "bounded-bridge-canary-start",
                "selfCleaned": True,
                "initialStopped": initial,
                "running": running,
                "triggerStatus": trigger_status,
                "triggerRequestedAt": self._timestamp(trigger_requested_at),
                "historyBoundary": canary["historyBoundary"],
                "terminalHistory": canary["terminalHistory"],
                "terminalHistoryObservedAt": canary[
                    "terminalHistoryObservedAt"
                ],
                "terminalHistoryEntriesSha256": canary[
                    "terminalHistoryEntriesSha256"
                ],
                "terminalHistoryResponseSha256": canary[
                    "terminalHistoryResponseSha256"
                ],
                "pollAttempts": canary["pollAttempts"],
                "stopped": stopped,
                "package": {
                    key: upload.get(key)
                    for key in ("blob", "etag", "versionId", "url", "sha256", "size")
                },
                "settingsSha256": configure.get("settingsSha256"),
                "bootstrapSelfTestControlSha256": configure.get(
                    "bootstrapSelfTestControlSha256"
                ),
                "activationFence": {
                    key: fence.get(key)
                    for key in ("url", "etag", "versionId", "sha256")
                },
                "proofBoundary": (
                    "terminal Success proves execution of the exact source/package-pinned "
                    "bootstrap branch; HTTP health and literal stdout marker bytes were "
                    "not observed"
                ),
            }

        if operation_id == "createSolePublisherFicToSignedBootstrapSource":
            application = self._proof_detail(state, "createPublisherApplication")
            resource = self.resources["publisherFederatedCredential"]
            expression = resource["claimsMatchingExpressionTemplate"].replace(
                "${authorization.source.mergedMain.commitSha}", source_sha
            )
            result = self._graph_json(
                "POST",
                f"/beta/applications/{application['objectId']}/federatedIdentityCredentials",
                body={
                    "name": resource["name"],
                    "issuer": resource["issuer"],
                    "audiences": resource["audiences"],
                    "subject": None,
                    "claimsMatchingExpression": {
                        "languageVersion": resource["claimsMatchingExpressionLanguageVersion"],
                        "value": expression,
                    },
                },
                expected={201},
            )
            return {"objectId": result.get("id"), "name": result.get("name"), "claimsMatchingExpression": result.get("claimsMatchingExpression")}

        fail(f"Azure transport has no mutation handler: {operation_id}")

    def _mutate_temporary_role(self, operation_id: str, state: Mapping[str, Any]) -> Mapping[str, Any]:
        add = operation_id.startswith("addOwned")
        if "UploaderPackage" in operation_id:
            assignment_id = self.plan["temporaryAccess"]["roleAssignmentId"]
            definition_id = self.plan["temporaryAccess"]["roleDefinitionId"]
            scope = self._resource_scope("packageContainer")
            cleanup_key = "uploader-package-role"
            data_actions = self.plan["temporaryAccess"]["temporaryPackageDataActions"]
        elif "OperatorKeyRead" in operation_id:
            assignment_id = self.plan["temporaryAccess"]["temporaryKeyReadRoleAssignmentId"]
            definition_id = self.plan["temporaryAccess"]["temporaryKeyReadRoleDefinitionId"]
            scope = self._resource_scope("signingKey")
            cleanup_key = "operator-key-read-role"
            data_actions = self.plan["temporaryAccess"]["temporaryKeyReadDataActions"]
        elif "OperatorFence" in operation_id:
            assignment_id = self.plan["temporaryAccess"]["temporaryFenceRoleAssignmentId"]
            definition_id = self.plan["temporaryAccess"]["temporaryFenceRoleDefinitionId"]
            scope = self._resource_scope("activationFenceContainer")
            cleanup_key = "operator-fence-bootstrap-role"
            data_actions = self.plan["temporaryAccess"]["temporaryFenceDataActions"]
        elif "OperatorController" in operation_id:
            assignment_id = self.plan["temporaryAccess"]["temporaryControllerRoleAssignmentId"]
            definition_id = self.plan["temporaryAccess"]["temporaryControllerRoleDefinitionId"]
            scope = self._resource_scope("controllerLockContainer")
            cleanup_key = "operator-controller-canary-role"
            data_actions = self.plan["temporaryAccess"]["temporaryControllerDataActions"]
        else:
            fail("temporary role operation is unknown")
        definition_resource = f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/roleDefinitions/{definition_id}"
        assignment_resource = f"{scope}/providers/Microsoft.Authorization/roleAssignments/{assignment_id}"
        definition_body = {
            "properties": {
                "roleName": f"PaperDesk V2 temporary {cleanup_key}",
                "description": "Single-use bootstrap temporary role; exact cleanup required",
                "type": "CustomRole",
                "permissions": [
                    {
                        "actions": [],
                        "notActions": [],
                        "dataActions": data_actions,
                        "notDataActions": [],
                    }
                ],
                "assignableScopes": [f"/subscriptions/{SUBSCRIPTION}"],
            }
        }
        principal_type = (
            "ServicePrincipal"
            if self.authorization["azure"]["accountType"] == "servicePrincipal"
            else "User"
        )
        assignment_body = {
            "properties": {
                "principalId": self.authorization["azure"]["accountObjectId"],
                "principalType": principal_type,
                "roleDefinitionId": definition_resource,
            }
        }

        exact_readbacks: dict[str, Mapping[str, Any]] = {}

        def read_exact(resource_id: str, expected_body: Mapping[str, Any], label: str) -> str:
            response = self.session.request(
                "GET", self._arm_url(resource_id, "2022-04-01")
            )
            if response.status == 404:
                return "absent"
            document = self._json_response(response, {200}, label)
            properties = document.get("properties")
            expected = expected_body["properties"]
            if not isinstance(properties, Mapping):
                fail(f"{label} lacks exact properties")
            if "permissions" in expected:
                projection = {
                    "roleName": properties.get("roleName"),
                    "description": properties.get("description"),
                    "type": properties.get("type"),
                    "permissions": properties.get("permissions"),
                    "assignableScopes": properties.get("assignableScopes"),
                }
                exact_readbacks[resource_id.lower()] = {
                    "id": document.get("id"),
                    "name": document.get("name"),
                    "type": document.get("type"),
                    "properties": projection,
                }
            else:
                projection = {
                    "principalId": properties.get("principalId"),
                    "principalType": properties.get("principalType"),
                    "roleDefinitionId": properties.get("roleDefinitionId"),
                }
                exact_readbacks[resource_id.lower()] = _project_role_assignment(document)
            if projection != expected:
                fail(f"{label} is a third state")
            return "exact"

        if add:
            details: dict[str, Any] = {
                "cleanupKey": cleanup_key,
                "assignmentResourceId": assignment_resource,
                "definitionResourceId": definition_resource,
                "definitionCreated": False,
                "assignmentCreated": False,
            }
            try:
                if read_exact(definition_resource, definition_body, "temporary role definition precondition") != "absent":
                    fail("temporary role definition already exists; recovery authorization is required")
                definition_response = self._mutation_request(
                    "PUT",
                    self._arm_url(definition_resource, "2022-04-01"),
                    body=canonical_json_bytes(definition_body),
                    headers={"Content-Type": "application/json", "If-None-Match": "*"},
                    expected={201},
                )
                details["definitionCreated"] = True
                details["definitionEtag"] = self._header(definition_response, "ETag")
                if read_exact(definition_resource, definition_body, "temporary role definition readback") != "exact":
                    fail("temporary role definition readback is not exact")
                if read_exact(assignment_resource, assignment_body, "temporary role assignment precondition") != "absent":
                    fail("temporary role assignment already exists; recovery authorization is required")
                assignment_response = self._mutation_request(
                    "PUT",
                    self._arm_url(assignment_resource, "2022-04-01"),
                    body=canonical_json_bytes(assignment_body),
                    headers={"Content-Type": "application/json", "If-None-Match": "*"},
                    expected={201},
                )
                details["assignmentCreated"] = True
                details["assignmentEtag"] = self._header(assignment_response, "ETag")
                if read_exact(assignment_resource, assignment_body, "temporary role assignment readback") != "exact":
                    fail("temporary role assignment readback is not exact")
                details["definitionProjection"] = exact_readbacks[
                    definition_resource.lower()
                ]
                details["assignmentProjection"] = exact_readbacks[
                    assignment_resource.lower()
                ]
                return details
            except BaseException as exc:
                if details["definitionCreated"] or details["assignmentCreated"]:
                    provisional = {
                        "operationId": operation_id,
                        "status": "applied-readback-pending",
                        "owned": True,
                        "cleanupKey": cleanup_key,
                        "details": details,
                    }
                    raise OwnedTemporaryMutationError(
                        f"temporary role mutation stopped after an owned subcall: {operation_id}: {exc}",
                        provisional,
                    ) from exc
                raise

        add_operation_id = operation_id.replace("remove", "add", 1)
        add_details = self._proof_detail(state, add_operation_id)
        if add_details.get("cleanupKey") != cleanup_key:
            fail("temporary role cleanup is not bound to its owned add proof")
        assignment_state = read_exact(
            assignment_resource, assignment_body, "temporary role assignment cleanup precondition"
        )
        if assignment_state == "exact":
            self._arm_delete(assignment_resource, "2022-04-01")
        definition_state = read_exact(
            definition_resource, definition_body, "temporary role definition cleanup precondition"
        )
        if definition_state == "exact":
            self._arm_delete(definition_resource, "2022-04-01")
        if read_exact(assignment_resource, assignment_body, "temporary role assignment cleanup readback") != "absent":
            fail("temporary role assignment cleanup did not reach absence")
        if read_exact(definition_resource, definition_body, "temporary role definition cleanup readback") != "absent":
            fail("temporary role definition cleanup did not reach absence")
        return {
            "cleanupKey": cleanup_key,
            "assignmentResourceId": assignment_resource,
            "definitionResourceId": definition_resource,
            "assignmentRemoved": assignment_state == "exact",
            "definitionRemoved": definition_state == "exact",
            "assignmentAbsenceProjection": {"resourceId": assignment_resource, "absent": True},
            "definitionAbsenceProjection": {"resourceId": definition_resource, "absent": True},
        }

    def apply_operation(
        self, operation: Mapping[str, Any], state: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        admission = self.admissions[operation["id"]]
        decision = admission["context"]["executionDecision"]
        if decision == "adopt-exact":
            details = dict(admission["context"].get("adopted", {}))
            readbacks = self._prove_probe_ids(
                admission["desiredProbeIds"],
                f"{operation['id']} adopt",
                runtime_facts=details,
            )
            details["readbackProjections"] = [
                item["sourceProjection"] for item in readbacks
            ]
            return {
                "operationId": operation["id"],
                "status": "adopted-exact",
                "owned": False,
                "details": details,
            }
        self._active_operation_id = operation["id"]
        try:
            details = dict(self._mutate(operation, state))
            try:
                readbacks = self._prove_probe_ids(
                    admission["desiredProbeIds"],
                    f"{operation['id']} mutation",
                    runtime_facts=details,
                )
                details["readbackProjections"] = [
                    item["sourceProjection"] for item in readbacks
                ]
            except BootstrapError as readback_error:
                cleanup_key = details.get("cleanupKey")
                if operation.get("temporary") is True and cleanup_key:
                    provisional = {
                        "operationId": operation["id"],
                        "status": "applied-readback-pending",
                        "owned": True,
                        "cleanupKey": cleanup_key,
                        "details": details,
                    }
                    raise OwnedTemporaryMutationError(
                        f"temporary mutation readback failed: {operation['id']}: {readback_error}",
                        provisional,
                    ) from readback_error
                raise
        finally:
            self._active_operation_id = None
        if operation["kind"].startswith(("delete-", "remove-", "temporary-remove")):
            status = "removed-exact"
        elif operation["kind"].startswith(("create-", "azure-global-create", "azure-ad-create")):
            status = "created"
        elif operation["kind"].startswith("azure-ad-read"):
            status = "verified-exact"
        else:
            status = "applied-exact"
        cleanup_key = details.get("cleanupKey")
        self_cleaned = details.get("selfCleaned") is True
        return {
            "operationId": operation["id"],
            "status": status,
            "owned": (
                operation.get("temporary") is True
                and status != "verified-exact"
                and not self_cleaned
            ),
            "cleanupKey": cleanup_key,
            "details": details,
        }

    def compensate_temporary(
        self,
        operation: Mapping[str, Any],
        proof: Mapping[str, Any],
        state: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        mapping = {
            "addOwnedUploaderIpv4Rule": "removeOwnedUploaderIpv4Rule",
            "addOwnedUploaderPackageRole": "removeOwnedUploaderPackageRole",
            "addOwnedOperatorKeyReadRole": "removeOwnedOperatorKeyReadRole",
            "addOwnedOperatorFenceBootstrapRole": "removeOwnedOperatorFenceBootstrapRole",
            "addOwnedOperatorControllerCanaryRole": "removeOwnedOperatorControllerCanaryRole",
            "createControllerLeaseCanaryBlob": "removeControllerLeaseCanaryBlob",
        }
        cleanup_id = mapping.get(operation["id"])
        if cleanup_id is None or proof.get("owned") is not True:
            fail("temporary compensation is not exact executor-owned state")
        cleanup_operation = next(
            (item for item in self.plan["mutations"] if item["id"] == cleanup_id), None
        )
        if cleanup_operation is None:
            fail("temporary compensation operation is absent")
        self._active_operation_id = cleanup_id
        try:
            details = dict(self._mutate(cleanup_operation, state))
        finally:
            self._active_operation_id = None
        self._prove_probe_ids(
            self.admissions[cleanup_id]["desiredProbeIds"],
            f"{cleanup_id} compensation",
            runtime_facts=details,
        )
        if details.get("cleanupKey") != proof.get("cleanupKey"):
            fail("temporary compensation cleanup key drifted")
        return {
            "operationId": operation["id"],
            "status": "removed-exact",
            "owned": True,
            "cleanupKey": proof.get("cleanupKey"),
            "details": details,
        }

    def _journal_source_projection(self) -> dict[str, Any]:
        if self._ledger is None:
            fail("postcondition verification occurred without a durable journal")
        records = self._ledger.read_cloud_mutations()
        sanitized = _sanitize_mutation_journal(
            records,
            plan=self.plan,
            authorization_id=self.authorization["authorizationId"],
            authorization_sha256=sha256_bytes(canonical_json_bytes(self.authorization)),
            source_sha=self.authorization["source"]["mergedMain"]["commitSha"],
            plan_sha256=self.authorization["plan"]["sha256"],
            package_sha256=self.package["sha256"],
            operation_projections=self._validated_source_projections,
            operation_contexts={
                operation_id: admission["context"]
                for operation_id, admission in self.admissions.items()
            },
        )
        forbidden: list[dict[str, Any]] = []
        accepted_writes: list[dict[str, Any]] = []
        for item in sanitized:
            if item.get("phase") != "intent":
                continue
            method = item.get("method")
            target = str(item.get("targetUrl", "")).lower()
            projection = {
                "sequence": item.get("sequence"),
                "operationId": item.get("operationId"),
                "method": method,
                "targetUrlSha256": sha256_bytes(target.encode("utf-8")),
            }
            production_write, accepted_write = _forbidden_release_mutation_classes(
                str(method), str(item.get("targetUrl", "")), self.plan
            )
            if production_write:
                forbidden.append(projection)
            if accepted_write:
                accepted_writes.append(projection)
        if forbidden or accepted_writes:
            fail("bootstrap journal contains a forbidden production or accepted-release write")
        return {
            "schemaVersion": 1,
            "recordCount": len(sanitized),
            "mutationJournal": sanitized,
            "journalSha256": sha256_bytes(canonical_json_bytes(sanitized)),
            "unresolvedIntentCount": 0,
            "productionWriteCount": 0,
            "acceptedContainerWriteJournal": [],
        }

    def finalize_terminal_source_evidence(
        self,
        state: Mapping[str, Any],
        *,
        claimed_at: str,
        observed_at: str,
    ) -> Mapping[str, Any]:
        """Return one pure, fully revalidated terminal source snapshot.

        Exact package bytes are captured only while the temporary read role is
        live and remain in memory.  They are never placed in a receipt.  The
        platform reader-UAMI proof remains truthful Option A: source-derived
        from fresh terminal WebJob Success, not a fabricated local byte fetch.
        """

        if self._package_readback_bytes is None:
            fail("terminal evidence lacks an in-memory exact package readback")
        statuses = state.get("operationStatuses")
        observed = state.get("operationObservedAt")
        postconditions = state.get("postconditionProjections")
        production_after = state.get("productionBoundaryPostExecution")
        if (
            not isinstance(statuses, Mapping)
            or not isinstance(observed, Mapping)
            or not isinstance(postconditions, list)
            or not isinstance(production_after, Mapping)
        ):
            fail("terminal executor state is incomplete")
        journal = self._journal_source_projection()["mutationJournal"]
        return build_terminal_source_evidence(
            plan=self.plan,
            authorization=self.authorization,
            preflight_projection=self.preflight["projection"],
            operation_projections=self._validated_source_projections,
            operation_statuses=statuses,
            operation_observed_at=observed,
            postcondition_projections=postconditions,
            mutation_journal=journal,
            package_readback_bytes=self._package_readback_bytes,
            production_boundary_post_execution=production_after,
            claimed_at=claimed_at,
            observed_at=observed_at,
        )

    def terminal_package_readback_bytes(self) -> bytes:
        if self._package_readback_bytes is None:
            fail("terminal package readback bytes are unavailable")
        return bytes(self._package_readback_bytes)

    def _local_postcondition_projection(
        self,
        policy: Mapping[str, Any],
        state: Mapping[str, Any],
    ) -> dict[str, Any]:
        family = policy["family"]
        if family == "local-source-dormancy":
            contract, _ = load_json(ACTIVATION_CONTRACT_PATH)
            activation = contract.get("activation") if isinstance(contract, Mapping) else None
            if (
                not isinstance(contract, Mapping)
                or contract.get("status") != "source-dormant"
                or not isinstance(activation, Mapping)
                or any(value is not None for value in activation.values())
            ):
                fail("committed activation contract is not exact source-dormant null state")
            return {
                "contractPath": "contracts/private_release_mailbox_contract.json",
                "contractSha256": sha256_bytes(canonical_json_bytes(contract)),
                "status": "source-dormant",
                "activationFieldCount": len(activation),
                "allActivationValuesNull": True,
            }
        if family == "pairwise-identity-inventory":
            operation_ids = list(policy["requiredOperationIds"])
            identities: list[dict[str, str]] = []
            for operation_id in operation_ids:
                details = self._proof_detail(state, operation_id)
                client_id = details.get("appId") if operation_id == "createPublisherServicePrincipal" else details.get("clientId")
                principal_id = details.get("principalId")
                _guid(client_id, f"{operation_id} client ID")
                _guid(principal_id, f"{operation_id} principal ID")
                identities.append(
                    {
                        "operationId": operation_id,
                        "clientId": client_id,
                        "principalId": principal_id,
                    }
                )
            production = self.resources["productionSystemIdentity"]
            identities.append(
                {
                    "operationId": "fixedProductionSystemIdentity",
                    "clientId": production["clientId"],
                    "principalId": production["principalId"],
                }
            )
            clients = [item["clientId"] for item in identities]
            principals = [item["principalId"] for item in identities]
            if len(set(clients)) != len(clients) or len(set(principals)) != len(principals):
                fail("automation identity terminal inventory is not pairwise distinct")
            return {"identities": identities, "pairwiseDistinct": True}
        if family == "role-definition-and-assignment-inventories":
            definitions = self._proof_detail(state, "createCustomRoleDefinitions").get(
                "roleDefinitions"
            )
            assignments = self._proof_detail(state, "createExactRoleAssignments").get(
                "roleAssignments"
            )
            if (
                not isinstance(definitions, list)
                or not isinstance(assignments, list)
                or len(assignments) != len(self.plan["roleMatrix"])
                or len(definitions)
                != len(
                    [
                        item
                        for item in self.plan["roleMatrix"]
                        if item.get("definitionKind") != "BuiltInRole"
                    ]
                )
            ):
                fail("terminal role inventories are incomplete")
            return {
                "expectedRoleRecordCount": len(self.plan["roleMatrix"]),
                "roleDefinitions": definitions,
                "roleAssignments": assignments,
            }
        if family in {
            "production-pre-post-equality-and-zero-write-journal",
            "forbidden-target-journal-audit",
            "vault-posture-plus-no-journal-write",
        }:
            return self._journal_source_projection()
        if family == "terminal-source-inputs-ready-for-local-assembly":
            journal = self._journal_source_projection()
            outputs = self.plan["evidenceOutputs"]
            return {
                "status": "ready-for-create-only-local-terminal-assembly",
                "expectedOperationProofCount": len(
                    [
                        item
                        for item in self.plan["mutations"]
                        if item["kind"] != "local-create-only-canonical-evidence"
                    ]
                ),
                "expectedPriorPostconditionProofCount": len(
                    [
                        key
                        for key in state.get("proofs", {})
                        if str(key).startswith("postcondition:")
                    ]
                ),
                "mutationJournalSha256": journal["journalSha256"],
                "requiredS2EvidencePaths": [
                    outputs["provisioningEvidencePath"],
                    outputs["bridgeRuntimeReceiptPath"],
                    outputs["temporaryAccessCleanupReceiptPath"],
                    outputs["activationFenceReceiptPath"],
                    outputs["bridgeCanaryReceiptPath"],
                ],
                "terminalBundlePath": outputs["terminalBundlePath"],
                "terminalBundleCreated": False,
            }
        return {"requiredOperationProjectionCount": len(policy["requiredOperationIds"])}

    def verify_postcondition(
        self, postcondition: Mapping[str, Any], state: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        admission = self.postconditions.get(postcondition["id"])
        if admission is None:
            fail("postcondition is not authorization-bound")
        policy = _postcondition_semantic_policy(postcondition["id"], self.plan)
        for probe_id in admission["probeIds"]:
            contract = self.probes[probe_id].get("validatorContract")
            if (
                not isinstance(contract, Mapping)
                or contract.get("semanticPolicy") != policy
            ):
                fail("postcondition semantic policy is not authorization-bound")
        claim_proofs = self._prove_probe_ids(
            admission["probeIds"], f"postcondition {postcondition['id']}"
        )
        operation_projections: list[dict[str, Any]] = []
        for operation_id in policy["requiredOperationIds"]:
            proof = state.get("proofs", {}).get(operation_id)
            if not isinstance(proof, Mapping) or not isinstance(proof.get("details"), Mapping):
                fail(f"postcondition lacks an exact operation proof: {operation_id}")
            details = proof["details"]
            admission_for_operation = self.admissions.get(operation_id)
            if not isinstance(admission_for_operation, Mapping):
                fail("postcondition references an unauthorized operation")
            readbacks = self._prove_probe_ids(
                admission_for_operation["desiredProbeIds"],
                f"postcondition {postcondition['id']} operation {operation_id}",
                runtime_facts=details,
            )
            operation_projections.append(
                {
                    "operationId": operation_id,
                    "sourceProjections": [item["sourceProjection"] for item in readbacks],
                }
            )
        local_projection = self._local_postcondition_projection(policy, state)
        source_projection = {
            "schemaVersion": 1,
            "postconditionId": postcondition["id"],
            "predicateSha256": sha256_bytes(postcondition["predicate"].encode("utf-8")),
            "semanticPolicy": policy,
            "claimPersistenceProbes": claim_proofs,
            "requiredOperationProjections": operation_projections,
            "localProjection": local_projection,
        }
        return {
            "postconditionId": postcondition["id"],
            "status": "verified",
            "probeSetSha256": sha256_bytes(canonical_json_bytes(claim_proofs)),
            "sourceProjection": source_projection,
        }

@dataclasses.dataclass
class UseLedger:
    directory: Path
    authorization_id: str
    authorization_sha256: str
    source_sha: str
    plan_sha256: str
    claimed_at: str

    @property
    def state_path(self) -> Path:
        return self.directory / "single-use-state.json"

    def claim(self) -> None:
        parent = self.directory.parent
        if not parent.is_dir() or parent.is_symlink():
            fail("authorized receipt parent must already exist as one real directory")
        try:
            self.directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        except FileExistsError as exc:
            raise BootstrapError("single-use authorization is already consumed") from exc
        self._fsync_directory(parent)
        document = {
            "schemaVersion": 1,
            "status": "consumed-before-first-Azure-mutation",
            "authorizationId": self.authorization_id,
            "authorizationSha256": self.authorization_sha256,
            "sourceSha": self.source_sha,
            "planSha256": self.plan_sha256,
            "claimedAt": self.claimed_at,
        }
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(self.state_path, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(canonical_json_bytes(document))
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            # The directory itself remains as the durable consumed marker.
            raise
        self._fsync_directory(self.directory)

    @classmethod
    def open_consumed(
        cls,
        *,
        directory: Path,
        authorization_id: str,
        authorization_sha256: str,
        source_sha: str,
        plan_sha256: str,
    ) -> "UseLedger":
        """Open an exact consumed ledger for local-only finalization resume."""

        if not directory.is_dir() or directory.is_symlink():
            fail("consumed receipt directory is absent or unsafe")
        state_path = directory / "single-use-state.json"
        if not state_path.is_file() or state_path.is_symlink():
            fail("consumed single-use state is absent or unsafe")
        value, raw = load_json(state_path, require_canonical=True)
        state = _exact_keys(
            value,
            {
                "schemaVersion",
                "status",
                "authorizationId",
                "authorizationSha256",
                "sourceSha",
                "planSha256",
                "claimedAt",
            },
            "consumed single-use state",
        )
        if (
            state["schemaVersion"] != 1
            or state["status"] != "consumed-before-first-Azure-mutation"
            or state["authorizationId"] != authorization_id
            or state["authorizationSha256"] != authorization_sha256
            or state["sourceSha"] != source_sha
            or state["planSha256"] != plan_sha256
            or canonical_json_bytes(dict(state)) != raw
        ):
            fail("consumed single-use state binding drifted")
        parse_time(state["claimedAt"], "consumed single-use claimedAt")
        return cls(
            directory=directory,
            authorization_id=authorization_id,
            authorization_sha256=authorization_sha256,
            source_sha=source_sha,
            plan_sha256=plan_sha256,
            claimed_at=state["claimedAt"],
        )

    def write_terminal(self, document: Mapping[str, Any]) -> Path:
        target = self.directory / "execution-terminal.json"
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json_bytes(document))
            handle.flush()
            os.fsync(handle.fileno())
        self._fsync_directory(self.directory)
        return target

    @staticmethod
    def _artifact_parts(relative_path: str) -> tuple[str, ...]:
        if (
            not isinstance(relative_path, str)
            or not relative_path
            or len(relative_path.encode("utf-8")) > 1024
            or relative_path.startswith(("/", "\\"))
            or "\\" in relative_path
        ):
            fail("receipt artifact path is not one bounded repository-relative path")
        parts = tuple(relative_path.split("/"))
        if any(part in {"", ".", ".."} for part in parts):
            fail("receipt artifact path contains an unsafe segment")
        if relative_path == "execution-terminal.json":
            fail("canonical evidence cannot overwrite the execution summary")
        return parts

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            create_file = kernel32.CreateFileW
            create_file.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ]
            create_file.restype = wintypes.HANDLE
            flush = kernel32.FlushFileBuffers
            flush.argtypes = [wintypes.HANDLE]
            flush.restype = wintypes.BOOL
            close = kernel32.CloseHandle
            close.argtypes = [wintypes.HANDLE]
            close.restype = wintypes.BOOL
            handle = create_file(
                str(path),
                0x40000000,  # GENERIC_WRITE: required to flush a directory.
                0x00000001 | 0x00000002 | 0x00000004,
                None,
                3,  # OPEN_EXISTING
                0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
                None,
            )
            invalid = ctypes.c_void_p(-1).value
            if handle in (None, invalid):
                fail("authorized receipt filesystem cannot open a directory durability barrier")
            try:
                if not flush(handle):
                    fail("authorized receipt filesystem cannot flush a directory durability barrier")
            finally:
                close(handle)
            return
        try:
            descriptor = os.open(path, os.O_RDONLY)
        except OSError as exc:
            raise BootstrapError(
                "authorized receipt filesystem cannot open a directory durability barrier"
            ) from exc
        try:
            try:
                os.fsync(descriptor)
            except OSError as exc:
                raise BootstrapError(
                    "authorized receipt filesystem cannot flush a directory durability barrier"
                ) from exc
        finally:
            os.close(descriptor)

    def write_create_only_artifact(
        self, relative_path: str, body: bytes | bytearray
    ) -> Path:
        """Persist one exact canonical evidence body below the consumed ledger.

        Paths are POSIX-style repository-relative paths because they are later
        copied verbatim into the evidence-only S2 commit.  Every parent is
        checked for symlinks, the final file uses exclusive create, and exact
        bytes are fsynced then read back before success is returned.
        """

        parts = self._artifact_parts(relative_path)
        if not isinstance(body, (bytes, bytearray)):
            fail("receipt artifact body must be exact bytes")
        raw = bytes(body)
        if not raw or len(raw) > 16 * 1024 * 1024:
            fail("receipt artifact size is invalid")
        try:
            parsed = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_duplicate_safe_pairs,
                parse_constant=lambda value: fail(
                    f"invalid JSON constant in receipt artifact: {value}"
                ),
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BootstrapError("receipt artifact is not canonical UTF-8 JSON") from exc
        if canonical_json_bytes(parsed) != raw:
            fail("receipt artifact bytes are not canonical JSON")

        if not self.directory.is_dir() or self.directory.is_symlink():
            fail("receipt artifact root is not the exact consumed directory")
        root = self.directory.resolve(strict=True)
        parent = self.directory
        for part in parts[:-1]:
            candidate = parent / part
            try:
                candidate.mkdir(mode=0o700, parents=False, exist_ok=False)
                self._fsync_directory(parent)
            except FileExistsError:
                pass
            if not candidate.is_dir() or candidate.is_symlink():
                fail("receipt artifact parent is not one real directory")
            resolved = candidate.resolve(strict=True)
            if root != resolved and root not in resolved.parents:
                fail("receipt artifact parent escaped the consumed directory")
            parent = candidate

        target = parent / parts[-1]
        try:
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError as exc:
            if (
                not target.is_file()
                or target.is_symlink()
                or target.read_bytes() != raw
            ):
                raise BootstrapError(
                    f"receipt artifact conflicts with retained bytes: {relative_path}"
                ) from exc
            resolved_target = target.resolve(strict=True)
            if root not in resolved_target.parents:
                fail("receipt artifact target escaped the consumed directory")
            return target
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            # Never remove a partial artifact after an ambiguous local write;
            # the authorization stays consumed and review must reconcile it.
            raise
        self._fsync_directory(parent)
        if target.is_symlink() or target.read_bytes() != raw:
            fail("receipt artifact readback differs from the exact written bytes")
        resolved_target = target.resolve(strict=True)
        if root not in resolved_target.parents:
            fail("receipt artifact target escaped the consumed directory")
        return target

    @property
    def finalization_snapshot_path(self) -> Path:
        return self.directory / "local-finalization-input.json"

    @property
    def terminal_source_input_path(self) -> Path:
        return self.directory / "local-terminal-source-input.json"

    def persist_terminal_source_input(self, document: Mapping[str, Any]) -> Path:
        """Retain the validated sanitized terminal source before assembly."""

        value = _exact_keys(
            document,
            {
                "schemaVersion",
                "snapshotType",
                "authorizationId",
                "authorizationSha256",
                "sourceSha",
                "planSha256",
                "startedAt",
                "completedAt",
                "sourceEvidence",
                "sourceEvidenceSha256",
            },
            "local terminal source input",
        )
        source_evidence = value["sourceEvidence"]
        if (
            value["schemaVersion"] != 1
            or value["snapshotType"]
            != "paperdesk-private-release-v2-local-terminal-source-input-v1"
            or value["authorizationId"] != self.authorization_id
            or value["authorizationSha256"] != self.authorization_sha256
            or value["sourceSha"] != self.source_sha
            or value["planSha256"] != self.plan_sha256
            or not isinstance(source_evidence, Mapping)
            or value["sourceEvidenceSha256"]
            != sha256_bytes(canonical_json_bytes(source_evidence))
        ):
            fail("local terminal source input binding is invalid")
        started = parse_time(value["startedAt"], "local terminal source startedAt")
        completed = parse_time(
            value["completedAt"], "local terminal source completedAt"
        )
        if value["startedAt"] != self.claimed_at or completed < started:
            fail("local terminal source execution window is invalid")
        _reject_terminal_secret_material(source_evidence)
        return self.write_create_only_artifact(
            "local-terminal-source-input.json",
            canonical_json_bytes(dict(value)),
        )

    def load_terminal_source_input(self) -> dict[str, Any]:
        path = self.terminal_source_input_path
        if not path.is_file() or path.is_symlink():
            fail("local terminal source input is absent or unsafe")
        value, raw = load_json(path, require_canonical=True)
        if not isinstance(value, Mapping) or canonical_json_bytes(value) != raw:
            fail("local terminal source input is not canonical")
        self.persist_terminal_source_input(value)
        return dict(value)

    @staticmethod
    def build_terminal_source_input(
        *,
        authorization_id: str,
        authorization_sha256: str,
        source_sha: str,
        plan_sha256: str,
        started_at: str,
        completed_at: str,
        source_evidence: Mapping[str, Any],
    ) -> dict[str, Any]:
        source = copy.deepcopy(dict(source_evidence))
        return {
            "schemaVersion": 1,
            "snapshotType": (
                "paperdesk-private-release-v2-local-terminal-source-input-v1"
            ),
            "authorizationId": authorization_id,
            "authorizationSha256": authorization_sha256,
            "sourceSha": source_sha,
            "planSha256": plan_sha256,
            "startedAt": started_at,
            "completedAt": completed_at,
            "sourceEvidence": source,
            "sourceEvidenceSha256": sha256_bytes(canonical_json_bytes(source)),
        }

    def persist_finalization_snapshot(self, document: Mapping[str, Any]) -> Path:
        """Durably retain the validated local-only recovery input first."""

        value = _exact_keys(
            document,
            {
                "schemaVersion",
                "snapshotType",
                "authorizationId",
                "authorizationSha256",
                "sourceSha",
                "planSha256",
                "startedAt",
                "completedAt",
                "s2EvidenceFiles",
                "terminalBundle",
            },
            "local finalization snapshot",
        )
        if (
            value["schemaVersion"] != 1
            or value["snapshotType"]
            != "paperdesk-private-release-v2-local-finalization-input-v1"
            or value["authorizationId"] != self.authorization_id
            or value["authorizationSha256"] != self.authorization_sha256
            or value["sourceSha"] != self.source_sha
            or value["planSha256"] != self.plan_sha256
            or not isinstance(value["s2EvidenceFiles"], Mapping)
            or not isinstance(value["terminalBundle"], Mapping)
        ):
            fail("local finalization snapshot binding is invalid")
        started = parse_time(value["startedAt"], "local finalization startedAt")
        completed = parse_time(value["completedAt"], "local finalization completedAt")
        if completed < started:
            fail("local finalization snapshot time order is invalid")

        def validate_artifact(path: Any, item: Any, label: str) -> bytes:
            parts = self._artifact_parts(path)
            body = _exact_keys(
                item,
                {"path", "bodyBase64", "sha256", "size"},
                label,
            )
            if body["path"] != path:
                fail(f"{label} path binding is invalid")
            try:
                raw = base64.b64decode(body["bodyBase64"], validate=True)
            except (ValueError, TypeError, binascii.Error) as exc:
                raise BootstrapError(f"{label} body is not canonical base64") from exc
            if (
                not raw
                or len(raw) > 16 * 1024 * 1024
                or body["size"] != len(raw)
                or body["sha256"] != sha256_bytes(raw)
            ):
                fail(f"{label} byte descriptor is invalid")
            try:
                parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicate_safe_pairs)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BootstrapError(f"{label} is not canonical JSON") from exc
            if canonical_json_bytes(parsed) != raw:
                fail(f"{label} is not canonical JSON")
            if not parts:
                fail(f"{label} path is empty")
            return raw

        evidence = value["s2EvidenceFiles"]
        if len(evidence) != 5:
            fail("local finalization snapshot does not contain five S2 files")
        for path, item in evidence.items():
            validate_artifact(path, item, f"local finalization S2 file {path}")
        terminal = value["terminalBundle"]
        terminal_path = terminal.get("path")
        validate_artifact(
            terminal_path, terminal, "local finalization terminal bundle"
        )
        if terminal_path in evidence:
            fail("local finalization terminal bundle aliases an S2 file")
        return self.write_create_only_artifact(
            "local-finalization-input.json", canonical_json_bytes(dict(value))
        )

    def load_finalization_snapshot(self) -> dict[str, Any]:
        """Load one exact retained snapshot without contacting Azure."""

        path = self.finalization_snapshot_path
        if not path.is_file() or path.is_symlink():
            fail("local finalization snapshot is absent or unsafe")
        value, raw = load_json(path, require_canonical=True)
        if not isinstance(value, Mapping) or canonical_json_bytes(value) != raw:
            fail("local finalization snapshot is not canonical")
        # Reuse the complete binding checks; identical persistence proves that
        # a restart cannot substitute a different authorization or source.
        self.persist_finalization_snapshot(value)
        return dict(value)

    @staticmethod
    def build_finalization_snapshot(
        *,
        authorization_id: str,
        authorization_sha256: str,
        source_sha: str,
        plan_sha256: str,
        started_at: str,
        completed_at: str,
        s2_evidence_files: Mapping[str, bytes | bytearray],
        terminal_bundle_path: str,
        terminal_bundle_body: bytes | bytearray,
    ) -> dict[str, Any]:
        def artifact(path: str, body: bytes | bytearray) -> dict[str, Any]:
            raw = bytes(body)
            return {
                "path": path,
                "bodyBase64": base64.b64encode(raw).decode("ascii"),
                "sha256": sha256_bytes(raw),
                "size": len(raw),
            }

        return {
            "schemaVersion": 1,
            "snapshotType": (
                "paperdesk-private-release-v2-local-finalization-input-v1"
            ),
            "authorizationId": authorization_id,
            "authorizationSha256": authorization_sha256,
            "sourceSha": source_sha,
            "planSha256": plan_sha256,
            "startedAt": started_at,
            "completedAt": completed_at,
            "s2EvidenceFiles": {
                path: artifact(path, body)
                for path, body in s2_evidence_files.items()
            },
            "terminalBundle": artifact(
                terminal_bundle_path, terminal_bundle_body
            ),
        }

    def persist_finalization_from_snapshot(
        self,
        snapshot: Mapping[str, Any],
        *,
        expected_s2_paths: Sequence[str],
        terminal_bundle_path: str,
    ) -> dict[str, dict[str, Any]]:
        self.persist_finalization_snapshot(snapshot)

        def decode(item: Mapping[str, Any]) -> bytes:
            return base64.b64decode(item["bodyBase64"], validate=True)

        evidence = snapshot["s2EvidenceFiles"]
        terminal = snapshot["terminalBundle"]
        if terminal.get("path") != terminal_bundle_path:
            fail("local finalization terminal path drifted")
        return self.persist_finalization_artifacts(
            expected_s2_paths=expected_s2_paths,
            s2_evidence_files={path: decode(evidence[path]) for path in evidence},
            terminal_bundle_path=terminal_bundle_path,
            terminal_bundle_body=decode(terminal),
        )

    def persist_finalization_artifacts(
        self,
        *,
        expected_s2_paths: Sequence[str],
        s2_evidence_files: Mapping[str, bytes | bytearray],
        terminal_bundle_path: str,
        terminal_bundle_body: bytes | bytearray,
    ) -> dict[str, dict[str, Any]]:
        """Persist five exact S2 files, then the terminal bundle last.

        Existing files are accepted only when their bytes are identical.  The
        method therefore resumes any local-only crash prefix without replaying
        Azure while a conflicting file fails closed.
        """

        ordered_paths = list(expected_s2_paths)
        if (
            len(ordered_paths) != 5
            or len(set(ordered_paths)) != 5
            or set(s2_evidence_files) != set(ordered_paths)
            or terminal_bundle_path in set(ordered_paths)
        ):
            fail("local finalization artifact path universe is not exact")
        self._artifact_parts(terminal_bundle_path)
        written: dict[str, dict[str, Any]] = {}
        for path in ordered_paths:
            body = bytes(s2_evidence_files[path])
            target = self.write_create_only_artifact(path, body)
            if target.read_bytes() != body:
                fail("S2 evidence artifact readback drifted")
            written[path] = {
                "path": path,
                "sha256": sha256_bytes(body),
                "size": len(body),
                "phase": "s2-evidence-before-terminal",
            }
        terminal_body = bytes(terminal_bundle_body)
        terminal_target = self.write_create_only_artifact(
            terminal_bundle_path, terminal_body
        )
        if terminal_target.read_bytes() != terminal_body:
            fail("terminal bundle artifact readback drifted")
        written[terminal_bundle_path] = {
            "path": terminal_bundle_path,
            "sha256": sha256_bytes(terminal_body),
            "size": len(terminal_body),
            "phase": "terminal-bundle-last",
        }
        for path, descriptor in written.items():
            target = self.directory.joinpath(*self._artifact_parts(path))
            if (
                not target.is_file()
                or target.is_symlink()
                or sha256_bytes(target.read_bytes()) != descriptor["sha256"]
            ):
                fail("local finalization artifact set is not fully readable")
        return written

    def append_cloud_mutation(self, document: Mapping[str, Any]) -> Path:
        existing = sorted(self.directory.glob("cloud-mutation-*.json"))
        sequence = len(existing) + 1
        target = self.directory / f"cloud-mutation-{sequence:04d}.json"
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json_bytes({**dict(document), "sequence": sequence}))
            handle.flush()
            os.fsync(handle.fileno())
        self._fsync_directory(self.directory)
        return target

    def read_cloud_mutations(self) -> list[dict[str, Any]]:
        """Read back the durable journal in exact sequence.

        This is intentionally strict: terminal policy must never reason from a
        partial, reordered, noncanonical, or authorization-mismatched journal.
        """

        result: list[dict[str, Any]] = []
        paths = sorted(self.directory.glob("cloud-mutation-*.json"))
        for sequence, path in enumerate(paths, 1):
            if path.name != f"cloud-mutation-{sequence:04d}.json" or path.is_symlink():
                fail("cloud mutation journal is missing or reordered")
            value, raw = load_json(path, require_canonical=True)
            if not isinstance(value, dict) or value.get("sequence") != sequence:
                fail("cloud mutation journal sequence is invalid")
            if (
                value.get("authorizationSha256") != self.authorization_sha256
                or value.get("sourceSha") != self.source_sha
                or value.get("planSha256") != self.plan_sha256
            ):
                fail("cloud mutation journal binding drifted")
            # Retain the exact canonical object rather than trusting the parsed
            # object identity supplied by the filesystem API.
            result.append(json.loads(raw.decode("utf-8")))
        return result

    def unresolved_intents(self) -> list[dict[str, Any]]:
        records = self.read_cloud_mutations()
        intents = {
            f"cloud-mutation-{item['sequence']:04d}": item
            for item in records
            if item.get("phase") == "intent"
        }
        results = {
            item.get("intentId")
            for item in records
            if item.get("phase") == "result"
        }
        return [item for key, item in intents.items() if key not in results]


@dataclasses.dataclass
class BootstrapResult:
    status: str
    receipt_directory: str
    authorization_sha256: str
    source_sha: str
    plan_sha256: str
    applied_mutation_ids: list[str]
    postcondition_ids: list[str]
    temporary_cleanup: list[Mapping[str, Any]]
    terminal_bundle_path: str = ""
    terminal_bundle_sha256: str = ""


def assemble_and_persist_terminal_evidence(
    *,
    ledger: UseLedger,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    preflight_projection: Mapping[str, Any],
    source_evidence: Mapping[str, Any],
    package_readback_bytes: bytes | bytearray,
    started_at: str,
    completed_at: str,
    now: dt.datetime,
) -> dict[str, Any]:
    """Build, validate, snapshot, and persist the exact terminal evidence set.

    No Azure transport is accepted here.  All six public evidence files are
    built in memory, the secret-free local recovery snapshot is fsynced first,
    the five S2 bodies are written next, and the terminal bundle is written
    last.  Existing byte-identical prefixes are resumed without replaying a
    cloud mutation.
    """

    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        fail("terminal evidence validation now is not timezone-aware")
    source = validate_terminal_source_evidence(
        plan=plan,
        authorization=authorization,
        preflight_projection=preflight_projection,
        evidence=source_evidence,
    )
    terminal_source_input = UseLedger.build_terminal_source_input(
        authorization_id=authorization["authorizationId"],
        authorization_sha256=sha256_bytes(canonical_json_bytes(authorization)),
        source_sha=authorization["source"]["mergedMain"]["commitSha"],
        plan_sha256=authorization["plan"]["sha256"],
        started_at=started_at,
        completed_at=completed_at,
        source_evidence=source,
    )
    ledger.persist_terminal_source_input(terminal_source_input)
    components = build_terminal_receipt_components(
        plan=plan,
        authorization=authorization,
        preflight_projection=preflight_projection,
        source_evidence=source,
        started_at=started_at,
        completed_at=completed_at,
    )
    try:
        from scripts import private_release_v2_terminal_s2 as terminal_s2
        from scripts import private_release_v2_bootstrap_receipts as receipts
    except ModuleNotFoundError:
        try:
            import private_release_v2_terminal_s2 as terminal_s2  # type: ignore[no-redef]
            import private_release_v2_bootstrap_receipts as receipts  # type: ignore[no-redef]
        except ModuleNotFoundError as exc:
            raise BootstrapError(
                "terminal S2 or receipt source module is unavailable"
            ) from exc
    s2_documents = terminal_s2.build_terminal_s2_documents(
        plan=plan,
        authorization=authorization,
        preflight_projection=preflight_projection,
        source_evidence=source,
        components=components,
        started_at=started_at,
        completed_at=completed_at,
    )
    complete = receipts.build_complete_receipt_bundle(
        authorization=authorization,
        plan=plan,
        components=components,
        s2_documents=s2_documents,
        source_evidence=source,
        authorized_preflight_projection=preflight_projection,
        package_bytes=bytes(package_readback_bytes),
        started_at=started_at,
        completed_at=completed_at,
        now=now,
    )
    complete = _exact_keys(
        complete,
        {"bundle", "s2EvidenceFiles", "s2TerminalBundle"},
        "complete terminal receipt output",
    )
    if complete["s2EvidenceFiles"] != s2_documents:
        fail("complete receipt changed the exact S2 document bodies")
    terminal_values = complete["s2TerminalBundle"]
    if not isinstance(terminal_values, Mapping) or len(terminal_values) != 1:
        fail("complete receipt lacks one exact terminal bundle")
    terminal_path, terminal_body = next(iter(terminal_values.items()))
    expected_outputs = plan["evidenceOutputs"]
    expected_s2_paths = [
        expected_outputs["provisioningEvidencePath"],
        expected_outputs["bridgeRuntimeReceiptPath"],
        expected_outputs["temporaryAccessCleanupReceiptPath"],
        expected_outputs["activationFenceReceiptPath"],
        expected_outputs["bridgeCanaryReceiptPath"],
    ]
    if terminal_path != expected_outputs["terminalBundlePath"]:
        fail("complete receipt terminal bundle path drifted from the plan")
    snapshot = UseLedger.build_finalization_snapshot(
        authorization_id=authorization["authorizationId"],
        authorization_sha256=sha256_bytes(canonical_json_bytes(authorization)),
        source_sha=authorization["source"]["mergedMain"]["commitSha"],
        plan_sha256=authorization["plan"]["sha256"],
        started_at=started_at,
        completed_at=completed_at,
        s2_evidence_files=s2_documents,
        terminal_bundle_path=terminal_path,
        terminal_bundle_body=terminal_body,
    )
    ledger.persist_finalization_snapshot(snapshot)
    persisted = ledger.persist_finalization_from_snapshot(
        snapshot,
        expected_s2_paths=expected_s2_paths,
        terminal_bundle_path=terminal_path,
    )
    return {
        "sourceEvidence": source,
        "components": components,
        "s2EvidenceFiles": dict(s2_documents),
        "terminalBundlePath": terminal_path,
        "terminalBundleSha256": sha256_bytes(bytes(terminal_body)),
        "persistedArtifacts": persisted,
    }


def resume_local_finalization_from_snapshot(
    *,
    plan: Mapping[str, Any],
    plan_sha256: str,
    package: Mapping[str, Any],
    authorization: Mapping[str, Any],
    preflight: Mapping[str, Any],
) -> dict[str, Any]:
    """Resume only the exact retained local evidence-file prefix.

    This entry point deliberately has no transport argument and performs no
    credential construction.  The single-use Azure authorization remains
    consumed; only byte-identical canonical files retained in the fsynced
    authorization-specific snapshot can be completed after a process crash.
    """

    validated = validate_authorization_evidence(
        authorization,
        plan=plan,
        plan_sha256=plan_sha256,
        package=package,
    )
    validated_preflight, _ = validate_preflight_evidence(
        preflight, authorization, plan
    )
    source_sha = authorization["source"]["mergedMain"]["commitSha"]
    ledger = UseLedger.open_consumed(
        directory=validated.receipt_directory,
        authorization_id=authorization["authorizationId"],
        authorization_sha256=validated.sha256,
        source_sha=source_sha,
        plan_sha256=plan_sha256,
    )
    if not ledger.finalization_snapshot_path.exists():
        source_input = ledger.load_terminal_source_input()
        source_started = parse_time(
            source_input["startedAt"], "local terminal source startedAt"
        )
        source_completed = parse_time(
            source_input["completedAt"], "local terminal source completedAt"
        )
        if (
            source_input["startedAt"] != ledger.claimed_at
            or source_started < validated.not_before
            or source_completed > validated.expires_at
        ):
            fail("local terminal source execution window is invalid")
        source_evidence = validate_terminal_source_evidence(
            plan=plan,
            authorization=authorization,
            preflight_projection=validated_preflight["projection"],
            evidence=source_input["sourceEvidence"],
        )
        if (
            sha256_bytes(canonical_json_bytes(source_evidence))
            != source_input["sourceEvidenceSha256"]
        ):
            fail("local terminal source evidence digest drifted")
        package_descriptor, package_bytes = build_package_artifact()
        if package_descriptor != package:
            fail("local terminal source deterministic package drifted")
        assembled = assemble_and_persist_terminal_evidence(
            ledger=ledger,
            plan=plan,
            authorization=authorization,
            preflight_projection=validated_preflight["projection"],
            source_evidence=source_evidence,
            package_readback_bytes=package_bytes,
            started_at=source_input["startedAt"],
            completed_at=source_input["completedAt"],
            now=source_completed,
        )
        return {
            "status": "complete-local-finalization-only",
            "receiptDirectory": str(ledger.directory),
            "authorizationSha256": validated.sha256,
            "sourceSha": source_sha,
            "planSha256": plan_sha256,
            "terminalBundlePath": assembled["terminalBundlePath"],
            "terminalBundleSha256": assembled["terminalBundleSha256"],
            "persistedArtifacts": assembled["persistedArtifacts"],
            "azureMutationCount": 0,
        }
    snapshot = ledger.load_finalization_snapshot()
    started = parse_time(snapshot["startedAt"], "local finalization startedAt")
    completed = parse_time(snapshot["completedAt"], "local finalization completedAt")
    if (
        snapshot["startedAt"] != ledger.claimed_at
        or started < validated.not_before
        or completed > validated.expires_at
    ):
        fail("local finalization snapshot execution window is invalid")

    outputs = plan["evidenceOutputs"]
    expected_s2_paths = [
        outputs["provisioningEvidencePath"],
        outputs["bridgeRuntimeReceiptPath"],
        outputs["temporaryAccessCleanupReceiptPath"],
        outputs["activationFenceReceiptPath"],
        outputs["bridgeCanaryReceiptPath"],
    ]
    terminal_path = outputs["terminalBundlePath"]
    if set(snapshot["s2EvidenceFiles"]) != set(expected_s2_paths):
        fail("local finalization snapshot S2 path universe drifted")
    terminal = snapshot["terminalBundle"]
    if terminal.get("path") != terminal_path:
        fail("local finalization snapshot terminal path drifted")
    try:
        terminal_raw = base64.b64decode(terminal["bodyBase64"], validate=True)
        terminal_document = json.loads(
            terminal_raw.decode("utf-8"), object_pairs_hook=_duplicate_safe_pairs
        )
    except (ValueError, TypeError, binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BootstrapError("local finalization terminal bundle is invalid") from exc
    if canonical_json_bytes(terminal_document) != terminal_raw:
        fail("local finalization terminal bundle is not canonical")
    if not isinstance(terminal_document, Mapping):
        fail("local finalization terminal bundle is not an object")
    execution = terminal_document.get("executionReceipt")
    if not isinstance(execution, Mapping):
        fail("local finalization terminal execution receipt is absent")
    source_binding = execution.get("source")
    plan_binding = execution.get("plan")
    single_use = execution.get("singleUse")
    if (
        execution.get("status") != "succeeded-terminal"
        or execution.get("authorizationId") != authorization["authorizationId"]
        or execution.get("authorizationSha256") != validated.sha256
        or not isinstance(source_binding, Mapping)
        or source_binding.get("mergedMainSha") != source_sha
        or not isinstance(plan_binding, Mapping)
        or plan_binding.get("sha256") != plan_sha256
        or plan_binding.get("document") != plan
        or execution.get("startedAt") != snapshot["startedAt"]
        or execution.get("completedAt") != snapshot["completedAt"]
        or execution.get("failures") != []
        or execution.get("pendingHousekeeping") != []
        or not isinstance(single_use, Mapping)
        or single_use.get("status") != "consumed-terminal"
        or single_use.get("claimedAt") != snapshot["startedAt"]
        or single_use.get("terminalAt") != snapshot["completedAt"]
    ):
        fail("local finalization terminal execution binding drifted")

    evidence_digests = execution.get("evidenceFileDigests")
    metadata = terminal_document.get("s2OutputMetadata")
    metadata_files = metadata.get("files") if isinstance(metadata, Mapping) else None
    expected_descriptors = [
        {
            "path": path,
            "sha256": snapshot["s2EvidenceFiles"][path]["sha256"],
            "size": snapshot["s2EvidenceFiles"][path]["size"],
            "canonicalJson": True,
        }
        for path in expected_s2_paths
    ]
    if (
        evidence_digests
        != {
            path: snapshot["s2EvidenceFiles"][path]["sha256"]
            for path in expected_s2_paths
        }
        or metadata_files != expected_descriptors
    ):
        fail("local finalization terminal S2 descriptor binding drifted")

    # A retained snapshot is recovery input, not authority by itself.  Replay
    # the full source-owned receipt validator over every decoded S2 body and
    # the terminal bundle before writing even one public artifact.  The exact
    # original authorized preflight is a required local input because its raw
    # temporary IP/app-settings observations are deliberately not persisted in
    # the secret-free snapshot.
    package_descriptor, package_bytes = build_package_artifact()
    if package_descriptor != package:
        fail("local finalization deterministic package descriptor drifted")
    s2_documents = {
        path: base64.b64decode(
            snapshot["s2EvidenceFiles"][path]["bodyBase64"], validate=True
        )
        for path in expected_s2_paths
    }
    try:
        from scripts import private_release_v2_bootstrap_receipts as receipts
    except ModuleNotFoundError:
        try:
            import private_release_v2_bootstrap_receipts as receipts  # type: ignore[no-redef]
        except ModuleNotFoundError as exc:
            raise BootstrapError(
                "terminal receipt source module is unavailable"
            ) from exc
    try:
        receipt_validated = receipts.validate_receipt_bundle(
            terminal_document,
            authorization=authorization,
            plan=plan,
            s2_documents=s2_documents,
            terminal_bundle_path=terminal_path,
            terminal_bundle_body=terminal_raw,
            authorized_preflight_projection=validated_preflight["projection"],
            package_bytes=package_bytes,
            now=completed,
        )
    except Exception as exc:
        if isinstance(exc, BootstrapError):
            raise
        raise BootstrapError(
            "local finalization full terminal validation failed"
        ) from exc
    if receipt_validated != terminal_document:
        fail("local finalization full terminal validation changed the bundle")

    persisted = ledger.persist_finalization_from_snapshot(
        snapshot,
        expected_s2_paths=expected_s2_paths,
        terminal_bundle_path=terminal_path,
    )
    terminal_descriptor = persisted[terminal_path]
    return {
        "status": "complete-local-finalization-only",
        "receiptDirectory": str(ledger.directory),
        "authorizationSha256": validated.sha256,
        "sourceSha": source_sha,
        "planSha256": plan_sha256,
        "terminalBundlePath": terminal_path,
        "terminalBundleSha256": terminal_descriptor["sha256"],
        "persistedArtifacts": persisted,
        "azureMutationCount": 0,
    }


class BootstrapExecutor:
    def __init__(
        self,
        *,
        plan: Mapping[str, Any],
        plan_sha256: str,
        package: Mapping[str, Any],
        authorization: ValidatedAuthorization,
        preflight: Mapping[str, Any],
        transport: BootstrapTransport,
        now: Callable[[], dt.datetime],
        source_validator: Callable[[Mapping[str, Any]], Mapping[str, Any]] = validate_local_source,
    ) -> None:
        self.plan = plan
        self.plan_sha256 = plan_sha256
        self.package = package
        self.authorization = authorization
        self.preflight = preflight
        self.transport = transport
        self.now = now
        self.source_validator = source_validator

    def run(self) -> BootstrapResult:
        current = self.now()
        if not self.authorization.not_before <= current <= self.authorization.expires_at:
            fail("authorization expired before execution admission")

        def require_live_authorization(label: str) -> None:
            observed = self.now()
            if not self.authorization.not_before <= observed <= self.authorization.expires_at:
                fail(f"authorization expired before {label}")

        def timestamp_now() -> str:
            return (
                self.now()
                .astimezone(dt.timezone.utc)
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
            )

        source = dict(self.source_validator(self.authorization.document))
        account = validate_local_account(
            self.transport.account(), self.authorization.document
        )
        fresh_projection = self.transport.collect_preflight(self.plan)
        fresh_digest = sha256_bytes(canonical_json_bytes(fresh_projection))
        expected_digest = self.authorization.document["observedPreflight"]["sha256"]
        if fresh_digest != expected_digest or fresh_projection != self.preflight["projection"]:
            fail("fresh Azure preflight drifted before mutation")

        state: dict[str, Any] = {
            "authorization": self.authorization.document,
            "authorizationSha256": self.authorization.sha256,
            "source": source,
            "account": account,
            "planSha256": self.plan_sha256,
            "package": dict(self.package),
            "preflight": dict(self.preflight),
            "proofs": {},
            "operationStatuses": {},
            "operationObservedAt": {},
            "postconditionProjections": [],
            "productionBoundaryAuthorizedPreflight": (
                _validate_production_boundary_projection(
                    fresh_projection["productionBoundaryObservation"][
                        "sourceProjection"
                    ],
                    self.plan,
                )
            ),
        }
        inspections: dict[str, Mapping[str, Any]] = {}
        for operation in self.plan["mutations"]:
            if operation["kind"] == "local-create-only-canonical-evidence":
                continue
            proof = self.transport.inspect_operation(operation, state)
            if (
                not isinstance(proof, Mapping)
                or proof.get("operationId") != operation["id"]
                or proof.get("status")
                not in {
                    "absent",
                    "exact",
                    "owned-present",
                    "network-inaccessible",
                    "temporary-access-inaccessible",
                }
            ):
                fail(f"operation preflight is partial or drifted: {operation['id']}")
            inspections[operation["id"]] = dict(proof)
        state["operationInspections"] = inspections

        claimed_at = (
            current.astimezone(dt.timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        ledger = UseLedger(
            directory=self.authorization.receipt_directory,
            authorization_id=self.authorization.document["authorizationId"],
            authorization_sha256=self.authorization.sha256,
            source_sha=source["headSha"],
            plan_sha256=self.plan_sha256,
            claimed_at=claimed_at,
        )
        ledger.claim()
        bind_journal = getattr(self.transport, "bind_journal", None)
        if callable(bind_journal):
            bind_journal(ledger)

        applied: list[str] = []
        temporary_owned: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
        cleanup_proofs: list[Mapping[str, Any]] = []
        terminal_status = "failed"
        failure: BaseException | None = None
        result: BootstrapResult | None = None
        try:
            for operation in self.plan["mutations"]:
                if operation["kind"] == "local-create-only-canonical-evidence":
                    continue
                require_live_authorization(f"mutation {operation['id']}")
                try:
                    proof = self.transport.apply_operation(operation, state)
                except OwnedTemporaryMutationError as owned_error:
                    provisional = dict(owned_error.proof)
                    state["proofs"][operation["id"]] = provisional
                    temporary_owned.append((operation, provisional))
                    raise BootstrapError(str(owned_error)) from owned_error
                if (
                    not isinstance(proof, Mapping)
                    or proof.get("operationId") != operation["id"]
                    or proof.get("status") not in {"created", "adopted-exact", "applied-exact", "removed-exact", "verified-exact"}
                ):
                    fail(f"mutation readback is not exact: {operation['id']}")
                proof = dict(proof)
                state["proofs"][operation["id"]] = proof
                state["operationStatuses"][operation["id"]] = proof["status"]
                state["operationObservedAt"][operation["id"]] = timestamp_now()
                applied.append(operation["id"])
                if operation.get("temporary") is True and proof.get("owned") is True:
                    temporary_owned.append((operation, proof))
                if proof.get("status") == "removed-exact" and proof.get("cleanupKey"):
                    temporary_owned = [
                        pair for pair in temporary_owned
                        if pair[1].get("cleanupKey") != proof.get("cleanupKey")
                    ]

            postcondition_ids: list[str] = []
            for postcondition in self.plan["postconditions"]:
                require_live_authorization(f"postcondition {postcondition['id']}")
                proof = self.transport.verify_postcondition(postcondition, state)
                if (
                    not isinstance(proof, Mapping)
                    or proof.get("postconditionId") != postcondition["id"]
                    or proof.get("status") != "verified"
                ):
                    fail(f"postcondition is not verified: {postcondition['id']}")
                state["proofs"][f"postcondition:{postcondition['id']}"] = dict(proof)
                state["postconditionProjections"].append(
                    {
                        "postconditionId": postcondition["id"],
                        "sourceProjection": proof.get("sourceProjection"),
                        "observedAt": timestamp_now(),
                    }
                )
                postcondition_ids.append(postcondition["id"])
            require_live_authorization("final production-boundary observation")
            final_production_boundary = _validate_production_boundary_projection(
                self.transport.observe_production_boundary(), self.plan
            )
            if (
                final_production_boundary
                != state["productionBoundaryAuthorizedPreflight"]
            ):
                fail("production boundary drifted during bootstrap execution")
            state["productionBoundaryPostExecution"] = final_production_boundary
            if temporary_owned:
                fail("executor-owned temporary state remains after nominal execution")
            completed_moment = self.now()
            if not (
                self.authorization.not_before
                <= completed_moment
                <= self.authorization.expires_at
            ):
                fail("authorization expired before terminal evidence finalization")
            completed_at = (
                completed_moment.astimezone(dt.timezone.utc)
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
            )
            terminal_source = self.transport.finalize_terminal_source_evidence(
                state,
                claimed_at=claimed_at,
                observed_at=completed_at,
            )
            package_readback_bytes = self.transport.terminal_package_readback_bytes()
            terminal_evidence = assemble_and_persist_terminal_evidence(
                ledger=ledger,
                plan=self.plan,
                authorization=self.authorization.document,
                preflight_projection=self.preflight["projection"],
                source_evidence=terminal_source,
                package_readback_bytes=package_readback_bytes,
                started_at=claimed_at,
                completed_at=completed_at,
                now=completed_moment,
            )
            terminal_status = "complete"
            result = BootstrapResult(
                status="complete",
                receipt_directory=str(ledger.directory),
                authorization_sha256=self.authorization.sha256,
                source_sha=source["headSha"],
                plan_sha256=self.plan_sha256,
                applied_mutation_ids=applied,
                postcondition_ids=postcondition_ids,
                temporary_cleanup=cleanup_proofs,
                terminal_bundle_path=terminal_evidence["terminalBundlePath"],
                terminal_bundle_sha256=terminal_evidence["terminalBundleSha256"],
            )
            return result
        except BaseException as exc:
            failure = exc
            for operation, proof in reversed(temporary_owned):
                try:
                    cleanup = self.transport.compensate_temporary(operation, proof, state)
                    if (
                        not isinstance(cleanup, Mapping)
                        or cleanup.get("operationId") != operation["id"]
                        or cleanup.get("status") != "removed-exact"
                        or cleanup.get("owned") is not True
                    ):
                        fail("temporary compensation did not prove exact owned removal")
                    cleanup_proofs.append(dict(cleanup))
                except BaseException as cleanup_error:
                    cleanup_proofs.append(
                        {
                            "operationId": operation["id"],
                            "status": "cleanup-failed",
                            "errorType": type(cleanup_error).__name__,
                        }
                    )
            raise
        finally:
            terminal = {
                "schemaVersion": 1,
                "status": terminal_status,
                "authorizationId": self.authorization.document["authorizationId"],
                "authorizationSha256": self.authorization.sha256,
                "sourceSha": source["headSha"],
                "planSha256": self.plan_sha256,
                "appliedMutationIds": applied,
                "temporaryCleanup": cleanup_proofs,
                "terminalBundlePath": (
                    result.terminal_bundle_path
                    if terminal_status == "complete" and result is not None
                    else None
                ),
                "terminalBundleSha256": (
                    result.terminal_bundle_sha256
                    if terminal_status == "complete" and result is not None
                    else None
                ),
                "failureType": None if failure is None else type(failure).__name__,
                "consumed": True,
            }
            # The authorization-specific directory and single-use-state.json
            # are the durable consumed boundary.  Terminal evidence is useful,
            # but a pre-existing file or disk failure must never mask the
            # original Azure/readback/cleanup exception.
            try:
                ledger.write_terminal(terminal)
            except BaseException as terminal_error:
                if failure is None:
                    raise BootstrapError(
                        "execution completed but terminal receipt could not be written"
                    ) from terminal_error


def _read_confirmation_from_stdin() -> str:
    if sys.stdin.isatty():
        print("Enter the exact authorized confirmation phrase, then press Enter:", file=sys.stderr)
    value = sys.stdin.readline()
    if value.endswith("\n"):
        value = value[:-1]
    if value.endswith("\r"):
        value = value[:-1]
    if not value:
        fail("confirmation phrase is required on stdin")
    return value


def main(
    argv: Sequence[str] | None = None,
    *,
    transport_factory: Callable[[], BootstrapTransport] | None = None,
    now: Callable[[], dt.datetime] | None = None,
) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        nargs="?",
        choices=("describe", "apply", "resume-finalization"),
        default="describe",
    )
    parser.add_argument("--authorization", type=Path)
    parser.add_argument("--preflight", type=Path)
    args = parser.parse_args(argv)
    clock = now or (lambda: dt.datetime.now(dt.timezone.utc))
    try:
        plan, plan_digest = load_plan()
        package = build_package_descriptor()
        if args.mode == "describe":
            if args.authorization is not None or args.preflight is not None:
                fail("read-only describe mode does not accept authorization or preflight inputs")
            print(json.dumps(plan_coordinates(plan, plan_digest), sort_keys=True, separators=(",", ":")))
            return 0
        if args.mode == "resume-finalization":
            if args.authorization is None or args.preflight is None:
                fail(
                    "resume-finalization requires the exact authorization and original authorized preflight files"
                )
            authorization_document, _ = load_json(
                args.authorization, require_canonical=True
            )
            preflight_document, _ = load_json(
                args.preflight, require_canonical=True
            )
            result = resume_local_finalization_from_snapshot(
                plan=plan,
                plan_sha256=plan_digest,
                package=package,
                authorization=authorization_document,
                preflight=preflight_document,
            )
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0
        if args.authorization is None or args.preflight is None:
            fail("apply requires external authorization and authorized preflight files")
        phrase = _read_confirmation_from_stdin()
        authorization = validate_authorization(
            args.authorization,
            plan=plan,
            plan_sha256=plan_digest,
            package=package,
            confirmation_phrase=phrase,
            now=clock(),
        )
        preflight, _ = validate_preflight_document(
            args.preflight, authorization.document, plan
        )
        # The transport is deliberately constructed only after every local
        # source/authorization/package/confirmation boundary above passes.
        transport = (
            transport_factory()
            if transport_factory is not None
            else AzureCliBootstrapTransport(
                authorization=authorization.document,
                plan=plan,
                package=package,
                preflight=preflight,
                clock=clock,
            )
        )
        result = BootstrapExecutor(
            plan=plan,
            plan_sha256=plan_digest,
            package=package,
            authorization=authorization,
            preflight=preflight,
            transport=transport,
            now=clock,
        ).run()
        print(json.dumps(dataclasses.asdict(result), sort_keys=True, separators=(",", ":")))
        return 0
    except (BootstrapError, OSError, subprocess.SubprocessError) as exc:
        print(f"private release V2 bootstrap error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
