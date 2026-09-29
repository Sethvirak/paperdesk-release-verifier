#!/usr/bin/env python3
"""Offline, non-activating gate for a provisional Defender canary proposal.

This deliberately has no Azure/GitHub transport, workflow entry, or write path.
The source-controlled policy is dormant. Even a fully valid test proposal returns
``activationAllowed: false`` and cannot consume or accept a candidate.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "contracts" / "provisional_defender_canary_stage.json"
ALLOWED_SIGNERS_PATH = ROOT / "contracts" / "paperdesk_release_signing_allowed_signers"
SIGNING_PRINCIPAL = "paperdesk-release-signing-2026-08-30"
SIGNING_FINGERPRINT = "SHA256:nOONZLlhHx9b03fmAPkCqfhYzp0CFZuHfLPc1T0rfA4"
SIGNER_LINE = (
    "paperdesk-release-signing-2026-08-30 ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIE162bAJ75rbh+Khk8orN39YWhNe/dlRC08rZHzPh+Dk\n"
)
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
POSITIVE = re.compile(r"[1-9][0-9]*\Z")
OWNER_ROLE = re.compile(r"paperdesk_[a-z0-9_]{3,47}_owner\Z")
OWNER_PROBE_ROLE = re.compile(r"paperdesk_[a-z0-9_]{3,47}_probe\Z")
ETAG = re.compile(r'"[^"\r\n]{1,240}"\Z')
VERSION = re.compile(r"[A-Za-z0-9:._%+-]{1,192}\Z")
APP_REMOTES = frozenset({
    "https://github.com/Sethvirak/MasterDataStructure.git",
    "git@github.com:Sethvirak/MasterDataStructure.git",
})
VERIFIER_REMOTES = frozenset({
    "https://github.com/Sethvirak/paperdesk-release-verifier.git",
    "git@github.com:Sethvirak/paperdesk-release-verifier.git",
})
POLICY_FIELDS = frozenset({
    "schemaVersion", "stageId", "status", "sourceRepository", "verifierRepository",
    "requiredSigningPrincipal", "requiredSigningKeyFingerprint", "readinessException",
    "requiredRuntimeDatabaseRole",
    "allowedCandidates", "activationAllowed", "candidateConsumeAllowed",
    "acceptedRegistryWriteAllowed",
})
CANDIDATE_FIELDS = frozenset({
    "sourceSha", "sourceTreeSha", "verifierWorkflowSha", "verifierTreeSha",
    "verifiedArchiveSha256", "deploymentPackageSha256", "verificationReceiptSha256",
    "sourceRunId", "sourceRunAttempt", "candidateRunId", "candidateRunAttempt",
    "artifactId", "packageBlob", "servedIndexSha256", "rollbackBaselineSourceSha",
    "rollbackBaselineManifestSha256", "reviewedOwnerRole", "ownerInventorySha256",
    "ownerInventoryMenuRows", "ownerProbeLoginRole",
})


class ProvisionalCanaryError(ValueError):
    """The source-only proposal fails closed."""


def fail(code: str) -> None:
    raise ProvisionalCanaryError(code)


def exact(value: object, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        fail(f"{label}-fields")
    return value


def value_string(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        fail(label)
    return value


def sha40(value: object, label: str) -> str:
    return value_string(value, SHA40, label)


def sha256(value: object, label: str) -> str:
    return value_string(value, SHA256, label)


def positive(value: object, label: str) -> str:
    return value_string(value, POSITIVE, label)


def utc(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", value):
        fail(label)
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        fail(label)
    if parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z") != value:
        fail(label)
    return parsed


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate-json-key")
        result[key] = value
    return result


def load_policy() -> Mapping[str, Any]:
    if POLICY_PATH.is_symlink() or not POLICY_PATH.is_file():
        fail("policy-path")
    raw = POLICY_PATH.read_bytes()
    try:
        document = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("policy-json")
    return validate_policy(document)


def validate_policy(policy: object) -> Mapping[str, Any]:
    policy = exact(policy, POLICY_FIELDS, "policy")
    if (type(policy["schemaVersion"]) is not int or policy["schemaVersion"] != 1
            or policy["stageId"] != "paperdesk-provisional-defender-canary-v1"
            or policy["sourceRepository"] != "Sethvirak/MasterDataStructure"
            or policy["verifierRepository"] != "Sethvirak/paperdesk-release-verifier"
            or policy["requiredSigningPrincipal"] != SIGNING_PRINCIPAL
            or policy["requiredSigningKeyFingerprint"] != SIGNING_FINGERPRINT
            or policy["requiredRuntimeDatabaseRole"] != "paperdesk_app"
            or policy["activationAllowed"] is not False
            or policy["candidateConsumeAllowed"] is not False
            or policy["acceptedRegistryWriteAllowed"] is not False):
        fail("policy-boundary")
    exception = exact(policy["readinessException"], frozenset({
        "httpStatus", "topLevelCode", "attachmentMalwareCode",
        "maximumEvidenceAgeSeconds", "maximumRollbackHours",
    }), "readiness-exception")
    if (type(exception["httpStatus"]) is not int or exception["httpStatus"] != 503
            or exception["topLevelCode"] != "service-not-ready"
            or exception["attachmentMalwareCode"] != "attachment-malware-ingestion-not-ready"
            or type(exception["maximumEvidenceAgeSeconds"]) is not int
            or exception["maximumEvidenceAgeSeconds"] != 600
            or type(exception["maximumRollbackHours"]) is not int
            or exception["maximumRollbackHours"] != 24):
        fail("readiness-exception-boundary")
    candidates = policy["allowedCandidates"]
    if not isinstance(candidates, list):
        fail("candidate-allowlist")
    if policy["status"] == "source-dormant":
        if candidates:
            fail("dormant-candidate-allowlist")
    elif policy["status"] == "reviewed-allowlist-proposal":
        if len(candidates) != 1:
            fail("candidate-allowlist-count")
        candidate = exact(candidates[0], CANDIDATE_FIELDS, "candidate-allowlist")
        for field in ("sourceSha", "sourceTreeSha", "verifierWorkflowSha", "verifierTreeSha", "rollbackBaselineSourceSha"):
            sha40(candidate[field], field)
        for field in ("verifiedArchiveSha256", "deploymentPackageSha256", "verificationReceiptSha256", "servedIndexSha256", "rollbackBaselineManifestSha256", "ownerInventorySha256"):
            sha256(candidate[field], field)
        for field in ("sourceRunId", "sourceRunAttempt", "candidateRunId", "candidateRunAttempt", "artifactId"):
            positive(candidate[field], field)
        if candidate["sourceSha"] == candidate["rollbackBaselineSourceSha"]:
            fail("candidate-equals-baseline")
        owner_role = value_string(candidate["reviewedOwnerRole"], OWNER_ROLE, "reviewed-owner-role")
        probe_role = value_string(candidate["ownerProbeLoginRole"], OWNER_PROBE_ROLE, "owner-probe-login-role")
        if (any(word in owner_role or word in probe_role for word in ("admin", "azure", "postgres", "master"))
                or owner_role == probe_role
                or type(candidate["ownerInventoryMenuRows"]) is not int
                or candidate["ownerInventoryMenuRows"] < 1):
            fail("owner-inventory-allowlist")
        expected_blob = (f"v1/pending/{candidate['sourceSha']}/"
                         f"{candidate['sourceRunId']}-{candidate['sourceRunAttempt']}-{candidate['artifactId']}/deployment.zip")
        if candidate["packageBlob"] != expected_blob:
            fail("candidate-package-key")
    else:
        fail("policy-status")
    return policy


def _git(repo: Path, *args: str) -> str:
    try:
        result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                                text=True, timeout=15, check=True)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        fail("signed-source-git")
    return result.stdout.rstrip("\r\n")


def verify_signed_commit(repo: Path, commit_sha: str, tree_sha: str, remotes: frozenset[str]) -> None:
    """Verify exact local commit bytes; this does not prove GitHub review/run state."""
    if (ALLOWED_SIGNERS_PATH.is_symlink() or not ALLOWED_SIGNERS_PATH.is_file()
            or ALLOWED_SIGNERS_PATH.read_text(encoding="utf-8") != SIGNER_LINE):
        fail("allowed-signers-drift")
    if _git(repo, "config", "--get", "remote.origin.url") not in remotes:
        fail("signed-source-remote")
    if _git(repo, "rev-parse", f"{commit_sha}^{{tree}}") != tree_sha:
        fail("signed-source-tree")
    signature_args = (
        "-c", "gpg.format=ssh", "-c", f"gpg.ssh.allowedSignersFile={ALLOWED_SIGNERS_PATH}",
    )
    _git(repo, *signature_args, "verify-commit", commit_sha)
    signature = _git(repo, *signature_args, "log", "-1", "--format=%G?%x00%GS%x00%GK", commit_sha)
    if signature != f"G\x00{SIGNING_PRINCIPAL}\x00{SIGNING_FINGERPRINT}":
        fail("signed-source-principal")


def _fresh(value: object, label: str, deployed: dt.datetime, now: dt.datetime) -> None:
    checked = utc(value, f"{label}-time")
    if checked < deployed or checked > now or now - checked > dt.timedelta(minutes=10):
        fail(f"{label}-stale")


def evaluate_proposal(
    *, policy: object, evidence: object, verification_receipt_raw: bytes,
    ready_response_raw: bytes,
    app_repo: Path, verifier_repo: Path, now: dt.datetime,
) -> dict[str, Any]:
    """Validate a local evidence projection and return a non-executable plan."""
    policy = validate_policy(policy)
    if policy["status"] != "reviewed-allowlist-proposal":
        fail("source-dormant")
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        fail("clock")
    now = now.astimezone(dt.timezone.utc)
    allowed = policy["allowedCandidates"][0]
    evidence = exact(evidence, frozenset({
        "schemaVersion", "candidateSha", "deploymentRunId", "deploymentRunAttempt",
        "deployedAt", "packageReadback", "acceptedBaseline", "http", "independent",
    }), "evidence")
    if (type(evidence["schemaVersion"]) is not int or evidence["schemaVersion"] != 1
            or evidence["candidateSha"] != allowed["sourceSha"]
            or evidence["deploymentRunId"] != allowed["candidateRunId"]
            or evidence["deploymentRunAttempt"] != allowed["candidateRunAttempt"]):
        fail("deployment-binding")
    deployed = utc(evidence["deployedAt"], "deployed-at")
    deadline = deployed + dt.timedelta(hours=24)
    if deployed > now or now >= deadline - dt.timedelta(minutes=15):
        fail("rollback-window")
    package = exact(evidence["packageReadback"], frozenset({
        "blob", "sha256", "versionId", "etag", "lockState", "publicAccess", "observedAt",
    }), "package-readback")
    if (package["blob"] != allowed["packageBlob"]
            or package["sha256"] != allowed["deploymentPackageSha256"]
            or package["lockState"] != "Locked" or package["publicAccess"] != "None"):
        fail("package-readback-binding")
    value_string(package["versionId"], VERSION, "package-version")
    value_string(package["etag"], ETAG, "package-etag")
    _fresh(package["observedAt"], "package-readback", deployed, now)
    baseline = exact(evidence["acceptedBaseline"], frozenset({
        "sourceSha", "manifestSha256", "status", "observedAt",
    }), "accepted-baseline")
    if (baseline["sourceSha"] != allowed["rollbackBaselineSourceSha"]
            or baseline["manifestSha256"] != allowed["rollbackBaselineManifestSha256"]
            or baseline["status"] != "accepted"):
        fail("accepted-baseline-binding")
    _fresh(baseline["observedAt"], "accepted-baseline", deployed, now)
    if (not isinstance(verification_receipt_raw, bytes)
            or hashlib.sha256(verification_receipt_raw).hexdigest() != allowed["verificationReceiptSha256"]):
        fail("verification-receipt-digest")
    try:
        receipt = json.loads(verification_receipt_raw, object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("verification-receipt-json")
    receipt = exact(receipt, frozenset({
        "schemaVersion", "status", "candidateSha", "sourceRunId", "sourceRunAttempt",
        "sourceArtifactName", "verifiedArtifactName", "verifierRunId", "verifierRunAttempt",
        "verifierWorkflow", "verifierJob", "archiveSha256", "inputManifestSha256",
        "runtimeManifestSha256", "releaseMaterialsSha256", "rootSbomSha256",
        "widgetSbomSha256", "provenanceSha256",
    }), "verification-receipt")
    if (type(receipt["schemaVersion"]) is not int or receipt["schemaVersion"] != 1
            or receipt["status"] != "candidate-verified"
            or receipt["candidateSha"] != allowed["sourceSha"]
            or receipt["sourceRunId"] != allowed["sourceRunId"]
            or receipt["sourceRunAttempt"] != allowed["sourceRunAttempt"]
            or receipt["archiveSha256"] != allowed["verifiedArchiveSha256"]
            or receipt["sourceArtifactName"] != f"paperdesk-azure-runtime-unverified-{allowed['sourceSha']}"
            or receipt["verifiedArtifactName"] != f"paperdesk-azure-runtime-verified-{allowed['sourceSha']}"
            or receipt["verifierJob"] != "verify_candidate"
            or receipt["verifierWorkflow"] != (
                "Sethvirak/paperdesk-release-verifier/.github/workflows/verify-candidate.yml@"
                + allowed["verifierWorkflowSha"]
            )):
        fail("verification-receipt-binding")
    for field in ("verifierRunId", "verifierRunAttempt"):
        positive(receipt[field], f"receipt-{field}")
    for field in ("inputManifestSha256", "runtimeManifestSha256", "releaseMaterialsSha256",
                  "rootSbomSha256", "widgetSbomSha256", "provenanceSha256"):
        sha256(receipt[field], f"receipt-{field}")
    http = exact(evidence["http"], frozenset({
        "observedAt", "sourceSha", "runtimeRelease", "index", "live", "ready",
        "appHealth", "securityInfo",
    }), "http-proof")
    if http["sourceSha"] != allowed["sourceSha"]:
        fail("http-source")
    _fresh(http["observedAt"], "http", deployed, now)
    runtime = exact(http["runtimeRelease"], frozenset({"status", "value"}), "runtime-release")
    index = exact(http["index"], frozenset({"status", "sha256"}), "served-index")
    if (type(runtime["status"]) is not int or runtime["status"] != 200
            or runtime["value"] != allowed["sourceSha"]
            or type(index["status"]) is not int or index["status"] != 200
            or index["sha256"] != allowed["servedIndexSha256"]):
        fail("http-runtime")
    for name in ("live", "appHealth", "securityInfo"):
        probe = exact(http[name], frozenset({"status", "ok"}), f"http-{name}")
        if type(probe["status"]) is not int or probe["status"] != 200 or probe["ok"] is not True:
            fail(f"http-{name}-not-ready")
    ready = exact(http["ready"], frozenset({"status", "body", "rawBodySha256"}), "http-ready")
    body = exact(ready["body"], frozenset({"ok", "status", "code", "attachmentMalware"}), "http-ready-body")
    malware = exact(body["attachmentMalware"], frozenset({
        "required", "ingestionReady", "code",
    }), "http-ready-malware")
    if (type(ready["status"]) is not int or ready["status"] != 503
            or body["ok"] is not False or body["status"] != "not-ready"
            or body["code"] != "service-not-ready" or malware["required"] is not True
            or malware["ingestionReady"] is not False
            or malware["code"] != "attachment-malware-ingestion-not-ready"):
        fail("http-503-exception")
    sha256(ready["rawBodySha256"], "ready-body-digest")
    if (not isinstance(ready_response_raw, bytes)
            or hashlib.sha256(ready_response_raw).hexdigest() != ready["rawBodySha256"]):
        fail("ready-body-readback-digest")
    try:
        raw_ready = json.loads(ready_response_raw, object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("ready-body-json")
    if not isinstance(raw_ready, dict) or {
        key: raw_ready.get(key) for key in ("ok", "status", "code", "attachmentMalware")
    } != body:
        fail("ready-body-projection")
    _fresh(raw_ready.get("checkedAt"), "ready-response", deployed, now)
    independent = exact(evidence["independent"], frozenset({
        "postgres", "ownerView", "maintenance", "capacity",
    }), "independent")
    postgres = exact(independent["postgres"], frozenset({
        "source", "observedAt", "probeContract", "appKvReachable",
        "visibilityReady", "visibilityPolicyVersion", "result", "latencyMs", "probeId",
        "runtimeConfiguredRole", "sessionRole", "rowSecurityActive",
        "roleAttributes", "rolePreflightSha256",
    }), "postgres")
    owner_view = exact(independent["ownerView"], frozenset({
        "source", "observedAt", "sessionLoginRole", "sessionRole",
        "roleTransition", "roleTransitionProofSha256", "roleAttributes", "ownsMenuRows",
        "forceRls", "rowSecurityActive", "completePolicyCoverage",
        "visibilityPolicyVersion", "visibleMenuRows", "badVisibilityRows",
        "inventorySha256", "probeId",
    }), "owner-view")
    maintenance = exact(independent["maintenance"], frozenset({
        "source", "observedAt", "maintenance", "probeId", "snapshotSha256",
    }), "maintenance")
    capacity = exact(independent["capacity"], frozenset({
        "source", "observedAt", "saturated", "appCpuPercent5m",
        "appMemoryPercent5m", "postgresStorageUsedPercent", "probeId", "snapshotSha256",
    }), "capacity")
    for label, proof in (("postgres", postgres), ("owner-view", owner_view),
                         ("maintenance", maintenance), ("capacity", capacity)):
        _fresh(proof["observedAt"], label, deployed, now)
        positive(proof["probeId"], f"{label}-probe-id")
    if len({postgres["probeId"], owner_view["probeId"],
            maintenance["probeId"], capacity["probeId"]}) != 4:
        fail("independent-probe-reuse")
    if (postgres["source"] != "postgres-repository-readiness-readonly"
            or postgres["probeContract"] != "app-kv-visibility-policy-v2"
            or postgres["runtimeConfiguredRole"] != "paperdesk_app"
            or postgres["sessionRole"] != "paperdesk_app"
            or postgres["rowSecurityActive"] is not True
            or postgres["appKvReachable"] is not True
            or postgres["visibilityReady"] is not True
            or type(postgres["visibilityPolicyVersion"]) is not int
            or postgres["visibilityPolicyVersion"] != 2
            or postgres["result"] is not True
            or type(postgres["latencyMs"]) is not int or not 0 <= postgres["latencyMs"] <= 1000):
        fail("postgres-not-ready")
    role = exact(postgres["roleAttributes"], frozenset({
        "canLogin", "superuser", "bypassRls", "createRole", "createDb",
        "replication", "canCreateDatabaseObjects", "canCreateTemporaryObjects",
        "canCreatePublicSchemaObjects", "ownedTables", "ownedFunctions",
        "ownerRoleMemberships", "privilegedRoleMemberships",
    }), "postgres-role")
    if (role["canLogin"] is not True or role["superuser"] is not False
            or role["bypassRls"] is not False or role["createRole"] is not False
            or role["createDb"] is not False or role["replication"] is not False
            or role["canCreateDatabaseObjects"] is not False
            or role["canCreateTemporaryObjects"] is not False
            or role["canCreatePublicSchemaObjects"] is not False
            or role["ownedTables"] != [] or role["ownedFunctions"] != []
            or role["ownerRoleMemberships"] != []
            or role["privilegedRoleMemberships"] != []):
        fail("postgres-runtime-role-privileged")
    sha256(postgres["rolePreflightSha256"], "postgres-role-preflight-digest")
    owner_role = exact(owner_view["roleAttributes"], frozenset({
        "canLogin", "superuser", "bypassRls", "createDb", "createRole",
        "replication", "privilegedRoleMemberships",
    }), "owner-role")
    if (owner_view["source"] != "postgres-reviewed-owner-readonly"
            or owner_view["sessionLoginRole"] != allowed["ownerProbeLoginRole"]
            or owner_view["sessionRole"] != allowed["reviewedOwnerRole"]
            or owner_view["roleTransition"] != "SET ROLE"
            or owner_role["canLogin"] is not False
            or owner_role["superuser"] is not False
            or owner_role["bypassRls"] is not False
            or owner_role["createDb"] is not False
            or owner_role["createRole"] is not False
            or owner_role["replication"] is not False
            or owner_role["privilegedRoleMemberships"] != []
            or owner_view["ownsMenuRows"] is not True
            or owner_view["forceRls"] is not True
            or owner_view["rowSecurityActive"] is not True
            or owner_view["completePolicyCoverage"] is not True
            or type(owner_view["visibilityPolicyVersion"]) is not int
            or owner_view["visibilityPolicyVersion"] != 2
            or type(owner_view["visibleMenuRows"]) is not int
            or owner_view["visibleMenuRows"] != allowed["ownerInventoryMenuRows"]
            or type(owner_view["badVisibilityRows"]) is not int
            or owner_view["badVisibilityRows"] != 0
            or owner_view["inventorySha256"] != allowed["ownerInventorySha256"]):
        fail("owner-view-incomplete")
    sha256(owner_view["roleTransitionProofSha256"], "owner-role-transition-digest")
    if maintenance["source"] != "maintenance-gate-readonly" or maintenance["maintenance"] is not False:
        fail("maintenance-active")
    sha256(maintenance["snapshotSha256"], "maintenance-digest")
    if capacity["source"] != "azure-monitor-readonly" or capacity["saturated"] is not False:
        fail("capacity-saturated")
    for name, maximum in (("appCpuPercent5m", 70), ("appMemoryPercent5m", 80),
                          ("postgresStorageUsedPercent", 80)):
        number = capacity[name]
        if type(number) not in (int, float) or not 0 <= number <= maximum:
            fail(f"capacity-{name}")
    sha256(capacity["snapshotSha256"], "capacity-digest")
    verify_signed_commit(app_repo, allowed["sourceSha"], allowed["sourceTreeSha"], APP_REMOTES)
    verify_signed_commit(verifier_repo, allowed["verifierWorkflowSha"], allowed["verifierTreeSha"], VERIFIER_REMOTES)
    return {
        "schemaVersion": 1,
        "status": "provisional-unaccepted-plan-only",
        "candidateSha": allowed["sourceSha"],
        "deploymentPackageSha256": allowed["deploymentPackageSha256"],
        "verificationReceiptSha256": allowed["verificationReceiptSha256"],
        "provisionalMarkerPath": (
            f"v2/provisional/{allowed['sourceSha']}/"
            f"{allowed['candidateRunId']}-{allowed['candidateRunAttempt']}/manifest.json"
        ),
        "rollbackBaselineSourceSha": allowed["rollbackBaselineSourceSha"],
        "requiredRuntimeDatabaseRole": "paperdesk_app",
        "reviewedOwnerRole": allowed["reviewedOwnerRole"],
        "ownerProbeLoginRole": allowed["ownerProbeLoginRole"],
        "ownerInventorySha256": allowed["ownerInventorySha256"],
        "rollbackDeadline": deadline.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "activationAllowed": False,
        "candidateConsumeAllowed": False,
        "acceptedRegistryWriteAllowed": False,
    }
