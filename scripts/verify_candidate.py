#!/usr/bin/env python3
"""Independent, dependency-free verifier for a hostile PaperDesk candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
from typing import Any

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]*$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
WORKFLOW_REF = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml@[0-9a-f]{40}$"
)
RELEASE_MATERIALS = (
    "architecture/production_acceptance_evidence_contract.json",
    "package-lock.json",
    "package.json",
    "widget-showcase/package-lock.json",
    "widget-showcase/package.json",
)
PROVENANCE_MATERIALS = (
    "package.json",
    "package-lock.json",
    "widget-showcase/package.json",
    "widget-showcase/package-lock.json",
    "architecture/production_acceptance_evidence_contract.json",
)
RUNTIME_INPUT = "server/internal-manifests/package-input-manifest.json"
RUNTIME_MANIFEST = "server/internal-manifests/runtime-file-manifest.json"
RELEASE_SHA = "server/paperdesk-release-sha.txt"
EXECUTABLE_PACKAGE_SOURCE = "App_Data/jobs/triggered/paperdesk-defender-malware-canary/run.sh"


def fail(message: str) -> None:
    raise ValueError(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def regular(path: Path, label: str, maximum: int | None = None) -> Path:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        fail(f"{label} must be a regular non-symlink file: {path}")
    if maximum is not None and (metadata.st_size <= 0 or metadata.st_size > maximum):
        fail(f"{label} exceeds its bounded size: {path}")
    return path


def read_json(path: Path, label: str, maximum: int = 64 * 1024 * 1024) -> Any:
    regular(path, label, maximum)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid UTF-8 JSON: {error}")


def safe_relative(value: str, label: str) -> str:
    if not value or "\\" in value or value.startswith("/"):
        fail(f"{label} contains an unsafe path: {value!r}")
    parts = PurePosixPath(value).parts
    if any(part in ("", ".", "..") for part in parts):
        fail(f"{label} contains an unsafe path: {value!r}")
    return "/".join(parts)


def authorized_file_mode(path: str) -> str:
    return "0755" if path == EXECUTABLE_PACKAGE_SOURCE else "0644"


def validate_records(
    records: Any,
    label: str,
    allow_empty: bool = False,
    *,
    require_mode: bool = False,
    allow_generated_owner: bool = False,
) -> list[dict[str, Any]]:
    if not isinstance(records, list) or (not allow_empty and not records):
        fail(f"{label} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
    required_keys = {"path", "size", "sha256"}
    if require_mode:
        required_keys.add("mode")
    allowed_keys = set(required_keys)
    if allow_generated_owner:
        allowed_keys.add("generatedOwner")
    prior = ""
    for record in records:
        keys = set(record) if isinstance(record, dict) else set()
        if not isinstance(record, dict) or not required_keys.issubset(keys) or not keys.issubset(allowed_keys):
            fail(f"{label} contains an invalid record")
        path = safe_relative(str(record.get("path", "")), label)
        if prior and prior >= path:
            fail(f"{label} paths must be unique and sorted")
        prior = path
        if not isinstance(record.get("size"), int) or record["size"] < 0:
            fail(f"{label} contains an invalid size: {path}")
        if not SHA256.fullmatch(str(record.get("sha256", ""))):
            fail(f"{label} contains an invalid digest: {path}")
        if require_mode and record.get("mode") != authorized_file_mode(path):
            fail(f"{label} contains an unauthorized mode: {path}")
        if "generatedOwner" in record and not isinstance(record["generatedOwner"], str):
            fail(f"{label} contains an invalid generated owner: {path}")
    return records


def verify_package_source_modes(root: Path, records: list[dict[str, Any]]) -> None:
    if os.name == "nt":
        return
    for record in records:
        candidate = root.joinpath(*PurePosixPath(record["path"]).parts)
        metadata = candidate.lstat()
        actual_mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
        if not stat.S_ISREG(metadata.st_mode) or candidate.is_symlink() or actual_mode != record["mode"]:
            fail(
                "reconstructed package source mode differs from its authorized manifest mode: "
                f"{record['path']} (expected {record['mode']}, found {actual_mode})"
            )


def tree_records(root: Path, excluded: set[str] | None = None) -> list[dict[str, Any]]:
    excluded = excluded or set()
    records: list[dict[str, Any]] = []
    for candidate in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = candidate.relative_to(root).as_posix()
        metadata = candidate.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
            fail(f"tree contains a special or linked path: {relative}")
        if stat.S_ISREG(metadata.st_mode) and relative not in excluded:
            records.append({"path": relative, "size": metadata.st_size, "sha256": sha256_file(candidate)})
    return records


def stable_json(value: Any) -> bytes:
    """Match PaperDesk's recursively key-sorted, two-space stable JSON bytes."""
    return (json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


def directory_digest(root: Path) -> str:
    records = [
        {"path": record["path"], "bytes": record["size"], "sha256": record["sha256"]}
        for record in tree_records(root)
    ]
    if not records:
        fail("directory digest target must contain regular files")
    records.sort(key=lambda record: record["path"].encode("utf-8"))
    return sha256_bytes(stable_json(records))


def compare_file(actual: Path, expected: Path, label: str) -> None:
    regular(actual, label)
    regular(expected, f"expected {label}")
    if actual.read_bytes() != expected.read_bytes():
        fail(f"{label} differs from the isolated expected bytes")


def verify_release_materials(actual: Path, expected: Path) -> None:
    actual_records = tree_records(actual)
    expected_records = tree_records(expected)
    if actual_records != expected_records:
        fail("release-material inventory or bytes differ from isolated expected materials")
    if tuple(record["path"] for record in actual_records) != RELEASE_MATERIALS:
        fail("release-material inventory is not the exact five-file contract")


def expected_tree(root: Path) -> dict[str, tuple[str, int, int, str]]:
    result: dict[str, tuple[str, int, int, str]] = {}
    for candidate in root.rglob("*"):
        relative = candidate.relative_to(root).as_posix()
        metadata = candidate.lstat()
        if candidate.is_symlink() or not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
            fail(f"expected package contains a special or linked path: {relative}")
        if stat.S_ISREG(metadata.st_mode):
            result[relative] = ("file", stat.S_IMODE(metadata.st_mode), metadata.st_size, sha256_file(candidate))
        else:
            result[relative] = ("directory", stat.S_IMODE(metadata.st_mode), 0, "")
    if not result:
        fail("expected package is empty")
    return result


def normalized_member_name(name: str) -> str | None:
    if "\\" in name or name.startswith("/"):
        fail(f"unsafe candidate archive path: {name!r}")
    parts = [part for part in PurePosixPath(name).parts if part not in ("", ".")]
    if any(part == ".." for part in parts):
        fail(f"unsafe candidate archive path: {name!r}")
    if not parts:
        return None
    return "/".join(parts)


def verify_archive(archive: Path, expected_root: Path) -> None:
    regular(archive, "candidate archive", 1024 * 1024 * 1024)
    expected = expected_tree(expected_root)
    seen: set[str] = set()
    total_size = 0
    member_count = 0
    with tarfile.open(archive, mode="r:gz") as handle:
        for member in handle:
            member_count += 1
            if member_count > 200_000:
                fail("candidate archive member count is excessive")
            relative = normalized_member_name(member.name)
            if relative is None:
                continue
            if relative in seen:
                fail(f"duplicate candidate archive path: {relative}")
            seen.add(relative)
            if not (member.isfile() or member.isdir()):
                fail(f"candidate archive special or linked member rejected: {relative}")
            actual_kind = "file" if member.isfile() else "directory"
            expected_entry = expected.get(relative)
            if expected_entry is None:
                fail(f"candidate archive contains an unexpected path: {relative}")
            if expected_entry[0] != actual_kind or expected_entry[1] != member.mode:
                fail(f"candidate archive type or mode differs from expected package: {relative}")
            if member.isfile():
                if member.size < 0 or member.size > 512 * 1024 * 1024 or member.size != expected_entry[2]:
                    fail(f"candidate archive file size differs from expected package: {relative}")
                total_size += member.size
                if total_size > 2 * 1024 * 1024 * 1024:
                    fail("candidate archive expanded size is excessive")
                stream = handle.extractfile(member)
                digest = hashlib.sha256()
                if stream is None:
                    fail(f"candidate archive file cannot be read: {relative}")
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
                if digest.hexdigest() != expected_entry[3]:
                    fail(f"candidate archive file bytes differ from expected package: {relative}")
    if member_count == 0 or seen != set(expected):
        fail("candidate archive path inventory differs from expected package")


def verify_manifest_boundaries(input_document: Any, runtime_document: Any, source_sha: str, expected_runtime: Path) -> None:
    if not isinstance(input_document, dict) or input_document.get("schema") != "paperdesk-azure-package-input-manifest-v1":
        fail("package input manifest schema is invalid")
    if input_document.get("repositoryCommit") != source_sha:
        fail("package input manifest does not bind the source SHA")
    input_records = validate_records(
        input_document.get("files"),
        "package input files",
        require_mode=True,
        allow_generated_owner=True,
    )
    release_records = validate_records(
        input_document.get("releaseMaterials"),
        "release materials",
        require_mode=True,
    )
    if tuple(record["path"] for record in release_records) != RELEASE_MATERIALS:
        fail("package input release-material paths are invalid")
    validate_records(input_document.get("productionDependencies"), "production dependencies", allow_empty=True)

    if not isinstance(runtime_document, dict) or runtime_document.get("schema") != "paperdesk-azure-runtime-file-manifest-v1":
        fail("runtime file manifest schema is invalid")
    if runtime_document.get("repositoryCommit") != source_sha or runtime_document.get("releaseSha") != source_sha:
        fail("runtime file manifest does not bind the release SHA")
    if runtime_document.get("selfExcludedPath") != RUNTIME_MANIFEST:
        fail("runtime manifest self-exclusion boundary is invalid")
    input_boundary = runtime_document.get("inputManifest")
    embedded_input = expected_runtime / RUNTIME_INPUT
    if not isinstance(input_boundary, dict) or input_boundary != {"path": RUNTIME_INPUT, "sha256": sha256_file(embedded_input)}:
        fail("runtime manifest input-manifest boundary is invalid")
    records = validate_records(runtime_document.get("files"), "runtime files", require_mode=True)
    actual_records = tree_records(expected_runtime, {RUNTIME_MANIFEST})
    runtime_evidence = [
        {"path": record["path"], "size": record["size"], "sha256": record["sha256"]}
        for record in records
    ]
    if runtime_evidence != actual_records:
        fail("runtime manifest does not exactly reconcile to expected runtime files")
    verify_package_source_modes(expected_runtime, input_records)
    if (expected_runtime / RELEASE_SHA).read_text(encoding="utf-8") != f"{source_sha}\n":
        fail("runtime release marker does not exactly bind the source SHA")


def verify_provenance(
    document: Any,
    policy: Any,
    artifact_files: dict[str, Path],
    release_materials: Path,
    source_repository: str,
    source_sha: str,
    source_ref: str,
    source_event: str,
    source_workflow_ref: str,
    source_run_id: str,
    source_run_attempt: str,
) -> None:
    keys = {
        "schemaVersion", "predicateType", "buildType", "commit", "repository", "workflow", "runId",
        "runAttempt", "builderId", "sourceUri", "invocation", "toolchain", "sourceMaterials", "subjects",
    }
    if not isinstance(document, dict) or set(document) != keys:
        fail("provenance fields must be exact")
    evidence_policy = policy.get("evidencePolicy", {}) if isinstance(policy, dict) else {}
    toolchain_policy = policy.get("toolchain", {}) if isinstance(policy, dict) else {}
    expected_scalars = {
        "schemaVersion": 2,
        "predicateType": evidence_policy.get("provenancePredicateType"),
        "buildType": evidence_policy.get("provenanceBuildType"),
        "commit": source_sha,
        "repository": source_repository,
        "workflow": source_workflow_ref,
        "runId": source_run_id,
        "runAttempt": source_run_attempt,
        "builderId": f"https://github.com/{source_repository}/actions/runs/{source_run_id}/attempts/{source_run_attempt}",
        "sourceUri": f"git+https://github.com/{source_repository}.git@{source_sha}",
    }
    for field, expected in expected_scalars.items():
        if document.get(field) != expected:
            fail(f"provenance {field} does not bind trusted caller context")
    if document.get("invocation") != {"ref": source_ref, "eventName": source_event}:
        fail("provenance invocation is invalid")
    if document.get("toolchain") != {"node": toolchain_policy.get("nodeVersion"), "npm": toolchain_policy.get("npmVersion")}:
        fail("provenance toolchain is invalid")
    expected_materials = [
        {"path": relative, "sha256": sha256_file(release_materials / relative)} for relative in PROVENANCE_MATERIALS
    ]
    if document.get("sourceMaterials") != expected_materials:
        fail("provenance release materials are invalid")
    expected_subjects = sorted(
        ({"path": path.name, "sha256": sha256_file(path)} for path in artifact_files.values()),
        key=lambda entry: entry["path"],
    )
    if document.get("subjects") != expected_subjects:
        fail("provenance subjects do not bind the exact runtime and SBOMs")
    for label in ("root_sbom", "widget_sbom"):
        sbom = read_json(artifact_files[label], label)
        if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != evidence_policy.get("sbomSpecVersion"):
            fail(f"{label} identity is invalid")
        if "serialNumber" in sbom or isinstance(sbom.get("metadata"), dict) and "timestamp" in sbom["metadata"]:
            fail(f"{label} contains a forbidden nondeterministic identity")


def write_create_only(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(document, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def verify(args: argparse.Namespace) -> dict[str, Any]:
    source_sha = args.source_sha
    if not SHA40.fullmatch(source_sha):
        fail("source SHA must be a full lowercase Git commit")
    for value, label in ((args.source_run_id, "source run ID"), (args.source_run_attempt, "source run attempt"),
                         (args.verifier_run_id, "verifier run ID"), (args.verifier_run_attempt, "verifier run attempt")):
        if not POSITIVE_INTEGER.fullmatch(value):
            fail(f"{label} must be a positive integer")
    if not REPOSITORY.fullmatch(args.source_repository):
        fail("source repository is invalid")
    if not WORKFLOW_REF.fullmatch(args.verifier_workflow_ref):
        fail("verifier workflow must be pinned to a full external commit SHA")
    if args.verifier_job != "verify_candidate":
        fail("verifier job must be verify_candidate")
    expected_source_name = f"paperdesk-azure-runtime-unverified-{source_sha}"
    expected_verified_name = f"paperdesk-azure-runtime-verified-{source_sha}"
    if args.source_artifact_name != expected_source_name or args.verified_artifact_name != expected_verified_name:
        fail("candidate artifact coordinate is invalid")

    artifact_dir = Path(args.artifact_dir).resolve()
    expected_runtime = Path(args.expected_runtime_dir).resolve()
    expected_input = Path(args.expected_input_manifest).resolve()
    expected_runtime_manifest = Path(args.expected_runtime_manifest).resolve()
    expected_release_materials = Path(args.expected_release_materials).resolve()
    policy_path = Path(args.policy).resolve()
    if not artifact_dir.is_dir() or not expected_runtime.is_dir() or not expected_release_materials.is_dir():
        fail("artifact and expected roots must be directories")

    archive_name = f"paperdesk-azure-runtime-{source_sha}.tar.gz"
    names = {
        archive_name,
        f"{archive_name}.sha256",
        f"paperdesk-azure-runtime-{source_sha}.acceptance-contract.json",
        f"paperdesk-azure-runtime-{source_sha}.cdx.json",
        f"paperdesk-azure-runtime-{source_sha}.package-input.json",
        f"paperdesk-azure-runtime-{source_sha}.provenance.json",
        f"paperdesk-azure-runtime-{source_sha}.root-package-lock.json",
        f"paperdesk-azure-runtime-{source_sha}.root-package.json",
        f"paperdesk-azure-runtime-{source_sha}.runtime-files.json",
        f"paperdesk-azure-runtime-{source_sha}.widget-package-lock.json",
        f"paperdesk-azure-runtime-{source_sha}.widget-package.json",
        f"paperdesk-azure-runtime-{source_sha}.widget.cdx.json",
        "paperdesk-prebuild-release-materials",
    }
    entries = list(artifact_dir.iterdir())
    if {entry.name for entry in entries} != names or sum(entry.is_dir() for entry in entries) != 1:
        fail("hostile artifact top-level inventory is not exact")
    if any(entry.is_symlink() for entry in entries):
        fail("hostile artifact top-level contains a symbolic link")

    archive = artifact_dir / archive_name
    checksum = artifact_dir / f"{archive_name}.sha256"
    checksum_text = regular(checksum, "archive checksum", 256).read_text(encoding="ascii")
    if checksum_text != f"{sha256_file(archive)}  {archive_name}\n":
        fail("archive checksum is not exact")

    input_path = artifact_dir / f"paperdesk-azure-runtime-{source_sha}.package-input.json"
    runtime_manifest_path = artifact_dir / f"paperdesk-azure-runtime-{source_sha}.runtime-files.json"
    compare_file(input_path, expected_input, "package input manifest")
    compare_file(runtime_manifest_path, expected_runtime_manifest, "runtime file manifest")
    compare_file(expected_runtime / RUNTIME_INPUT, expected_input, "embedded package input manifest")
    compare_file(expected_runtime / RUNTIME_MANIFEST, expected_runtime_manifest, "embedded runtime file manifest")
    input_document = read_json(expected_input, "expected package input manifest")
    runtime_document = read_json(expected_runtime_manifest, "expected runtime file manifest")
    verify_manifest_boundaries(input_document, runtime_document, source_sha, expected_runtime)

    actual_materials = artifact_dir / "paperdesk-prebuild-release-materials"
    verify_release_materials(actual_materials, expected_release_materials)
    expected_top = {
        f"paperdesk-azure-runtime-{source_sha}.root-package.json": "package.json",
        f"paperdesk-azure-runtime-{source_sha}.root-package-lock.json": "package-lock.json",
        f"paperdesk-azure-runtime-{source_sha}.widget-package.json": "widget-showcase/package.json",
        f"paperdesk-azure-runtime-{source_sha}.widget-package-lock.json": "widget-showcase/package-lock.json",
        f"paperdesk-azure-runtime-{source_sha}.acceptance-contract.json": "architecture/production_acceptance_evidence_contract.json",
    }
    for actual_name, relative in expected_top.items():
        compare_file(artifact_dir / actual_name, expected_release_materials / relative, actual_name)

    root_sbom = artifact_dir / f"paperdesk-azure-runtime-{source_sha}.cdx.json"
    widget_sbom = artifact_dir / f"paperdesk-azure-runtime-{source_sha}.widget.cdx.json"
    compare_file(root_sbom, Path(args.expected_root_sbom).resolve(), "root SBOM")
    compare_file(widget_sbom, Path(args.expected_widget_sbom).resolve(), "widget SBOM")
    verify_archive(archive, expected_runtime)

    provenance_path = artifact_dir / f"paperdesk-azure-runtime-{source_sha}.provenance.json"
    provenance = read_json(provenance_path, "provenance")
    policy = read_json(policy_path, "supply-chain policy")
    verify_provenance(
        provenance,
        policy,
        {"archive": archive, "root_sbom": root_sbom, "widget_sbom": widget_sbom},
        expected_release_materials,
        args.source_repository,
        source_sha,
        args.source_ref,
        args.source_event_name,
        args.source_workflow_ref,
        args.source_run_id,
        args.source_run_attempt,
    )

    receipt = {
        "schemaVersion": 1,
        "status": "candidate-verified",
        "candidateSha": source_sha,
        "sourceRunId": args.source_run_id,
        "sourceRunAttempt": args.source_run_attempt,
        "sourceArtifactName": args.source_artifact_name,
        "verifiedArtifactName": args.verified_artifact_name,
        "verifierRunId": args.verifier_run_id,
        "verifierRunAttempt": args.verifier_run_attempt,
        "verifierWorkflow": args.verifier_workflow_ref,
        "verifierJob": args.verifier_job,
        "archiveSha256": sha256_file(archive),
        "inputManifestSha256": sha256_file(input_path),
        "runtimeManifestSha256": sha256_file(runtime_manifest_path),
        "releaseMaterialsSha256": directory_digest(actual_materials),
        "rootSbomSha256": sha256_file(root_sbom),
        "widgetSbomSha256": sha256_file(widget_sbom),
        "provenanceSha256": sha256_file(provenance_path),
    }
    write_create_only(Path(args.receipt_output).resolve(), receipt)
    return receipt


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    for name in (
        "artifact-dir", "expected-runtime-dir", "expected-input-manifest", "expected-runtime-manifest",
        "expected-release-materials", "expected-root-sbom", "expected-widget-sbom", "policy", "source-repository",
        "source-sha", "source-ref", "source-event-name", "source-workflow-ref", "source-run-id",
        "source-run-attempt", "source-artifact-name", "verified-artifact-name", "verifier-run-id",
        "verifier-run-attempt", "verifier-workflow-ref", "verifier-job", "receipt-output",
    ):
        result.add_argument(f"--{name}", required=True)
    return result


if __name__ == "__main__":
    try:
        generated = verify(parser().parse_args())
        print(f"Independent candidate verification passed: {generated['archiveSha256']}")
    except (OSError, ValueError, tarfile.TarError) as error:
        raise SystemExit(f"Candidate verification failed: {error}")
