#!/usr/bin/env python3
"""Pure offline builder for the strict PaperDesk V2 S2 activation document.

The builder has no Azure/GitHub transport and never mutates a repository or
cloud resource.  It revalidates the historical bootstrap authorization,
preflight, deterministic package, all five S2 evidence files, the terminal
bundle, the exact evidence-only S2 source relationship, and the sole-S2 FIC
repin terminal receipt.  Only then does it derive the activated mailbox
document with ``mergedControlWorkflowSha=S2`` and
``bridgePackageSourceSha=S1`` and run the normal strict production loader.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable, Mapping, Sequence

try:
    from scripts import private_release_mailbox as mailbox
    from scripts import private_release_v2_bootstrap_receipts as receipts
    from scripts import private_release_v2_fic_repin as repin
except ModuleNotFoundError:  # direct ``python scripts/...`` execution
    import private_release_mailbox as mailbox  # type: ignore
    import private_release_v2_bootstrap_receipts as receipts  # type: ignore
    import private_release_v2_fic_repin as repin  # type: ignore


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_SCHEMA_PATH = ROOT / "contracts" / "private_release_s2_activation_schema.json"
OUTPUT_TYPE = "paperdesk-private-release-v2-offline-activation-output"


class ActivationError(RuntimeError):
    """Offline S2 activation evidence is incomplete, noncanonical, or drifted."""


def fail(message: str) -> None:
    raise ActivationError(message)


def _resource_guid(value: Any, label: str) -> str:
    if not isinstance(value, str) or "/" not in value:
        fail(f"{label} is not one role resource ID")
    return repin._guid(value.rsplit("/", 1)[-1].lower(), label)


def _role(evidence: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    roles = evidence.get("roles")
    role = roles.get(name) if isinstance(roles, Mapping) else None
    if not isinstance(role, Mapping):
        fail(f"provisioning evidence lacks exact role {name}")
    return role


def _canonical_copy(value: Any, label: str) -> Any:
    raw = repin.canonical_json_bytes(value)
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=repin._duplicate_safe_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ActivationError(f"{label} is not canonical JSON") from exc
    if repin.canonical_json_bytes(result) != raw:
        fail(f"{label} changed during canonicalization")
    repin._reject_secrets(result, label)
    return result


def _build_activation_document(
    *,
    s1_sha: str,
    s2_sha: str,
    package_sha256: str,
    provisioning_evidence: Mapping[str, Any],
    bridge_runtime_receipt: Mapping[str, Any],
    activation_fence_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    if repin._sha40(s1_sha, "S1 SHA") == repin._sha40(s2_sha, "S2 SHA"):
        fail("strict production activation requires S1 and S2 to differ")
    repin._sha256(package_sha256, "bridge package digest")
    evidence = _canonical_copy(provisioning_evidence, "provisioning evidence")
    runtime = _canonical_copy(bridge_runtime_receipt, "bridge runtime receipt")
    fence_receipt = _canonical_copy(
        activation_fence_receipt, "activation-fence bootstrap receipt"
    )
    bridge_runtime = evidence.get("bridgeRuntime")
    key_boundary = evidence.get("keyVaultBoundary")
    if not isinstance(bridge_runtime, Mapping) or not isinstance(key_boundary, Mapping):
        fail("provisioning evidence lacks bridge/key boundaries")
    if (
        bridge_runtime.get("packageSha256") != package_sha256
        or bridge_runtime.get("packageBlob")
        != f"v2/control/{s1_sha}/paperdesk-private-release-bridge.zip"
    ):
        fail("provisioning evidence package source/bytes binding drifted")
    key_projection = key_boundary.get("keyDataPlaneProjection")
    if not isinstance(key_projection, Mapping):
        fail("provisioning evidence lacks key data-plane projection")
    kid = key_projection.get("kid")
    if not isinstance(kid, str) or "/" not in kid:
        fail("signing key URI is not exact and versioned")
    signing_key_id, signing_key_version = kid.rsplit("/", 1)

    mailbox_role = _role(evidence, "publisherMailbox")
    controller_role = _role(evidence, "publisherControllerLock")
    bridge_role = _role(evidence, "bridgeMailboxResult")
    fence_role = _role(evidence, "bridgeActivationFence")
    writer_role = _role(evidence, "writerRegistryAdd")
    writer_package_role = _role(evidence, "writerPackageAdd")
    reader_role = _role(evidence, "readerRegistryRead")
    reader_package_role = _role(evidence, "readerPackageRead")
    signer_role = _role(evidence, "signerKeySign")
    production_role = _role(evidence, "productionActivation")
    production_reader_role = _role(evidence, "productionSystemPackageRead")

    scope = mailbox_role.get("scope")
    if not isinstance(scope, str) or "/" not in scope:
        fail("publisher mailbox role scope is invalid")
    activation = {
        "mergedControlWorkflowSha": s2_sha,
        "mailboxResourceGroup": scope.rsplit("/", 1)[-1],
        "mailboxPublisherClientId": repin._guid(
            mailbox_role.get("identityClientId"), "publisher client ID"
        ),
        "mailboxPublisherPrincipalId": repin._guid(
            mailbox_role.get("principalId"), "publisher principal ID"
        ),
        "mailboxRoleDefinitionId": _resource_guid(
            mailbox_role.get("roleDefinitionResourceId"), "publisher mailbox role definition"
        ),
        "mailboxRoleAssignmentId": _resource_guid(
            mailbox_role.get("roleAssignmentResourceId"), "publisher mailbox role assignment"
        ),
        "controllerLockRoleDefinitionId": _resource_guid(
            controller_role.get("roleDefinitionResourceId"), "controller-lock role definition"
        ),
        "controllerLockRoleAssignmentId": _resource_guid(
            controller_role.get("roleAssignmentResourceId"), "controller-lock role assignment"
        ),
        "controllerLockRoleAssignmentScope": controller_role.get("scope"),
        "controllerLockRoleDefinitionActions": controller_role.get("actions"),
        "controllerLockForbiddenDataActions": controller_role.get("notDataActions"),
        "tenantId": mailbox.TENANT,
        "bridgeManagedIdentityClientId": bridge_role.get("identityClientId"),
        "bridgeManagedIdentityPrincipalId": bridge_role.get("principalId"),
        "bridgeManagedIdentityResourceId": bridge_role.get("identityResourceId"),
        "registryWriterManagedIdentityClientId": writer_role.get("identityClientId"),
        "registryWriterManagedIdentityPrincipalId": writer_role.get("principalId"),
        "registryWriterManagedIdentityResourceId": writer_role.get("identityResourceId"),
        "registryReaderManagedIdentityClientId": reader_role.get("identityClientId"),
        "registryReaderManagedIdentityPrincipalId": reader_role.get("principalId"),
        "registryReaderManagedIdentityResourceId": reader_role.get("identityResourceId"),
        "signerManagedIdentityClientId": signer_role.get("identityClientId"),
        "signerManagedIdentityPrincipalId": signer_role.get("principalId"),
        "signerManagedIdentityResourceId": signer_role.get("identityResourceId"),
        "signerRoleDefinitionId": _resource_guid(
            signer_role.get("roleDefinitionResourceId"), "signer role definition"
        ),
        "signerRoleAssignmentId": _resource_guid(
            signer_role.get("roleAssignmentResourceId"), "signer role assignment"
        ),
        "signerRoleAssignmentScope": signer_role.get("scope"),
        "signerRoleDefinitionDataActions": signer_role.get("dataActions"),
        "signerForbiddenRoleAssignments": [],
        "signingKeyId": signing_key_id,
        "signingKeyVersion": signing_key_version,
        "signingPublicJwk": {
            key: key_projection.get(key) for key in ("kid", "kty", "n", "e", "key_ops")
        },
        "bridgePackageSourceSha": s1_sha,
        "bridgePackageSha256": package_sha256,
        "productionActivationManagedIdentityClientId": production_role.get("identityClientId"),
        "productionActivationManagedIdentityPrincipalId": production_role.get("principalId"),
        "productionActivationManagedIdentityResourceId": production_role.get("identityResourceId"),
        "productionActivationRoleDefinitionId": _resource_guid(
            production_role.get("roleDefinitionResourceId"), "production activation role definition"
        ),
        "productionActivationRoleAssignmentId": _resource_guid(
            production_role.get("roleAssignmentResourceId"), "production activation role assignment"
        ),
        "productionActivationRoleAssignmentScope": production_role.get("scope"),
        "productionActivationRoleDefinitionActions": production_role.get("actions"),
        "productionActivationForbiddenRoleAssignments": [],
        "productionPackageReaderRoleAssignmentId": _resource_guid(
            production_reader_role.get("roleAssignmentResourceId"),
            "production package-reader role assignment",
        ),
        "productionPackageReaderRoleScope": production_reader_role.get("scope"),
        "productionForbiddenDataPlaneAssignments": [],
        "productionSystemIdentityClientId": production_reader_role.get("identityClientId"),
        "productionSystemIdentityPrincipalId": production_reader_role.get("principalId"),
        "packageWriterRoleAssignmentId": _resource_guid(
            writer_package_role.get("roleAssignmentResourceId"), "package writer role assignment"
        ),
        "packageReaderRoleAssignmentId": _resource_guid(
            reader_package_role.get("roleAssignmentResourceId"), "package reader role assignment"
        ),
        "activationFence": {
            "storageAccount": mailbox.FIXED_COORDS["packageAccount"],
            "container": mailbox.FIXED_COORDS["activationFenceContainer"],
            "blob": mailbox.FIXED_COORDS["activationFenceBlob"],
            "scope": fence_role.get("scope"),
            "bridgeRoleAssignmentId": _resource_guid(
                fence_role.get("roleAssignmentResourceId"),
                "bridge activation-fence role assignment",
            ),
            "bridgePrincipalId": fence_role.get("principalId"),
            "leaseDuration": receipts.load_model()["constants"]["finiteLeaseSeconds"],
            "publicAccess": "None",
            "bootstrapReceiptSha256": repin.sha256_bytes(
                repin.canonical_json_bytes(fence_receipt)
            ),
            "governanceBoundary": (
                "subscription-and-resource-group-owners-remain-out-of-band-and-"
                "third-state-is-never-overwritten"
            ),
        },
        "provisioningEvidenceSha256": repin.sha256_bytes(
            repin.canonical_json_bytes(evidence)
        ),
    }
    contract, _ = repin.load_json(
        ROOT / "contracts" / "private_release_mailbox_contract.json",
        require_canonical=False,
    )
    document = copy.deepcopy(contract)
    document["status"] = "activated"
    document["fixed"] = copy.deepcopy(mailbox.FIXED_COORDS)
    document["activation"] = activation
    # This is intentionally the default strict production path.  It never
    # supplies the bootstrap-only pre_s2_evidence_validation escape hatch.
    try:
        loaded = mailbox.load_activation_document(
            document,
            runtime_workflow_sha=s2_sha,
            observed_bridge_package_sha256=package_sha256,
            provisioning_evidence=evidence,
        )
        validated_runtime = mailbox.validate_bridge_runtime_receipt(runtime, loaded)
    except Exception as exc:
        raise ActivationError(f"strict S2 activation validation failed: {exc}") from exc
    if validated_runtime != runtime:
        fail("strict mailbox validator changed the bridge runtime receipt")
    if (
        document["activation"]["mergedControlWorkflowSha"]
        == document["activation"]["bridgePackageSourceSha"]
    ):
        fail("strict activation collapsed the S1/S2 trust boundary")
    repin._reject_secrets(document, "S2 activation document")
    return _canonical_copy(document, "S2 activation document")


def build_offline_activation(
    *,
    bootstrap_authorization_path: Path,
    bootstrap_preflight_path: Path,
    repin_receipt_path: Path,
    repo_root: Path = ROOT,
    git_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    repin_receipt, repin_receipt_raw = repin.load_json(repin_receipt_path)
    validated_repin = repin.validate_terminal_receipt(
        repin_receipt,
        repo_root=repo_root,
        bootstrap_authorization_path=bootstrap_authorization_path,
        bootstrap_preflight_path=bootstrap_preflight_path,
        git_runner=git_runner,
    )
    bundle = repin._load_bootstrap_bundle(
        repo_root=repo_root,
        bootstrap_authorization_path=bootstrap_authorization_path,
        bootstrap_preflight_path=bootstrap_preflight_path,
    )
    source = validated_repin["source"]["binding"]
    s1_sha = source["s1MergedSha"]
    s2_sha = source["s2MergedSha"]
    if s1_sha != bundle["s1Sha"] or s1_sha == s2_sha:
        fail("repin receipt does not bind distinct exact S1 and S2 sources")
    if repin.classify_fic_state(
        validated_repin["publisher"]["finalFederatedIdentityCredentials"],
        s1_sha,
        s2_sha,
    ) != "s2":
        fail("repin receipt does not prove exact sole-S2 publisher trust")
    provisioning_path = receipts.S2_EVIDENCE_COMPONENT_PATHS["provisioningEvidence"]
    runtime_path = receipts.S2_EVIDENCE_COMPONENT_PATHS["bridgeRuntimeReceipt"]
    fence_path = receipts.S2_EVIDENCE_COMPONENT_PATHS["activationFenceBootstrap"]
    provisioning = receipts.load_canonical_json_bytes(
        bundle["s2Bodies"][provisioning_path], label="activation provisioning evidence"
    )
    runtime = receipts.load_canonical_json_bytes(
        bundle["s2Bodies"][runtime_path], label="activation bridge runtime receipt"
    )
    fence = receipts.load_canonical_json_bytes(
        bundle["s2Bodies"][fence_path], label="activation fence receipt"
    )
    activation = _build_activation_document(
        s1_sha=s1_sha,
        s2_sha=s2_sha,
        package_sha256=bundle["package"]["sha256"],
        provisioning_evidence=provisioning,
        bridge_runtime_receipt=runtime,
        activation_fence_receipt=fence,
    )
    output = {
        "schemaVersion": 1,
        "outputType": OUTPUT_TYPE,
        "activationDocument": activation,
        "package": {
            "sourceSha": s1_sha,
            "sha256": bundle["package"]["sha256"],
            "size": bundle["package"]["size"],
            "members": copy.deepcopy(bundle["package"]["members"]),
        },
        "source": {
            "repository": repin.REPOSITORY,
            "s1MergedSha": s1_sha,
            "s2ReviewedHeadSha": source["s2ReviewedHeadSha"],
            "s2MergedSha": s2_sha,
            "s2TreeSha": source["s2TreeSha"],
            "s2SoleParentSha": source["s2SoleParentSha"],
            "requiredPaths": copy.deepcopy(source["requiredPaths"]),
        },
        "receiptBindings": {
            "bootstrapAuthorizationSha256": bundle["authorizationSha256"],
            "bootstrapPreflightSha256": bundle["preflightSha256"],
            "bootstrapTerminalBundleSha256": bundle["terminalSha256"],
            "repinTerminalReceiptSha256": repin.sha256_bytes(repin_receipt_raw),
        },
    }
    repin._reject_secrets(output, "offline S2 activation output")
    return _canonical_copy(output, "offline S2 activation output")


def _create_only(path: Path, value: Mapping[str, Any]) -> None:
    repin._create_only(path.resolve(), repin.canonical_json_bytes(value))


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootstrap-authorization", required=True, type=Path)
    parser.add_argument("--bootstrap-preflight", required=True, type=Path)
    parser.add_argument("--repin-receipt", required=True, type=Path)
    parser.add_argument("--activation-output", required=True, type=Path)
    parser.add_argument("--descriptor-output", required=True, type=Path)
    args = parser.parse_args(argv)
    output = build_offline_activation(
        bootstrap_authorization_path=args.bootstrap_authorization,
        bootstrap_preflight_path=args.bootstrap_preflight,
        repin_receipt_path=args.repin_receipt,
    )
    _create_only(args.activation_output, output["activationDocument"])
    descriptor = {
        key: copy.deepcopy(output[key])
        for key in ("schemaVersion", "outputType", "package", "source", "receiptBindings")
    }
    descriptor["activationDocumentSha256"] = repin.sha256_bytes(
        repin.canonical_json_bytes(output["activationDocument"])
    )
    _create_only(args.descriptor_output, descriptor)
    sys.stdout.buffer.write(repin.canonical_json_bytes({
        "status": "offline-activation-built-and-strictly-validated",
        "activationDocumentSha256": descriptor["activationDocumentSha256"],
        "descriptorSha256": repin.sha256_bytes(repin.canonical_json_bytes(descriptor)),
    }))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(_main())
    except (ActivationError, repin.RepinError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
