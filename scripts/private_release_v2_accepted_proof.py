"""Pure, bounded validation of the V1-format transfer carried by V2 custody.

The transfer is evidence, not an accepted V1 registry entry.  The private V2
mailbox validates its bytes before committing a compact proof and the final
source-keyed V2 accepted manifest.  This module does no I/O or cloud work.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import tarfile
import zlib
from typing import Any, Mapping


SHA40 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
POSITIVE = re.compile(r"[1-9][0-9]*")
WORKFLOW = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml@[0-9a-f]{40}")
TRANSFER_SCHEMA = "paperdesk-accepted-release-registry-request-v2"
SOURCE_WORKFLOW = "Sethvirak/MasterDataStructure/.github/workflows/main_master-data-structure-sea-9c4e0d0d.yml@refs/heads/main"
RELEASE_COORDINATES = frozenset({"sourceRunId", "sourceRunAttempt", "candidateRunId", "candidateRunAttempt", "acceptanceRunId", "acceptanceRunAttempt"})
DESCRIPTOR_FIELDS = frozenset({"blob", "sha256", "size", "etag", "versionId"})
# The V2 bridge accepts an Actions ZIP no larger than 1 GiB. Leave room for
# the one transfer member's ZIP framing; the legacy producer's 1,280 MiB
# ceiling is not an admission promise for this private V2 path.
MAX_TRANSFER = 1024 * 1024 * 1024 - 64 * 1024
MAX_EXPANDED = 1200 * 1024 * 1024
MAX_MEMBER = 1024 * 1024 * 1024
MAX_OTHER = 64 * 1024 * 1024
RELEASE_MATERIAL_PATHS = (
    "architecture/production_acceptance_evidence_contract.json", "package-lock.json",
    "package.json", "widget-showcase/package-lock.json", "widget-showcase/package.json",
)
ACCEPTANCE_FIELDS = frozenset({
    "acceptanceWorkflowHeadSha", "acceptedAt", "acceptedByRunId", "candidateCompletedAt",
    "candidateFinalizeDeadline", "candidateRunAttempt", "candidateRunId", "candidateRuntimeSha256",
    "candidateSha", "environmentId", "evidenceArtifactId", "evidenceBundleSha256",
    "evidenceContractSha256", "evidenceRunId", "releaseScope", "schemaVersion", "status",
})


class AcceptedProofError(ValueError):
    """An accepted-transfer byte or coordinate is not exact."""


def fail(reason: str) -> None:
    raise AcceptedProofError(reason)


def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _object(value: Any, fields: set[str] | frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        fail(label)
    return value


def _match(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        fail(label)
    return value


def _json(raw: bytes, label: str, *, require_canonical: bool = False) -> Mapping[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                fail(label + "-duplicate-key")
            value[key] = item
        return value

    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                              parse_constant=lambda _: fail(label + "-nonfinite"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(label)
    if not isinstance(document, dict) or require_canonical and canonical(document) != raw:
        fail(label)
    return document


def _time(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", value):
        fail(label)
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        fail(label)
    if parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z") != value:
        fail(label)
    return parsed


def _expected_files(source_sha: str) -> dict[str, int]:
    stem = f"paperdesk-azure-runtime-{source_sha}"
    runtime = (
        f"{stem}.tar.gz", f"{stem}.tar.gz.sha256", f"{stem}.acceptance-contract.json",
        f"{stem}.cdx.json", f"{stem}.package-input.json", f"{stem}.provenance.json",
        f"{stem}.root-package-lock.json", f"{stem}.root-package.json",
        f"{stem}.runtime-files.json", f"{stem}.widget-package-lock.json",
        f"{stem}.widget-package.json", f"{stem}.widget.cdx.json",
    )
    expected = {f"verified-artifact/{name}": MAX_MEMBER if name.endswith(".tar.gz") else MAX_OTHER for name in runtime}
    expected.update({f"verified-artifact/paperdesk-prebuild-release-materials/{name}": MAX_OTHER for name in RELEASE_MATERIAL_PATHS})
    expected.update({
        f"receipts/paperdesk-candidate-verification-receipt-{source_sha}.json": 8192,
        f"receipts/paperdesk-production-acceptance-receipt-{source_sha}.json": 65536,
        f"receipts/paperdesk-deployment-coordinate-receipt-{source_sha}.json": 4096,
    })
    return expected


class _HashWriter:
    """Hash TAR framing without retaining another transfer-sized copy."""

    def __init__(self) -> None:
        self.sha256 = hashlib.sha256()
        self.size = 0

    def write(self, data: bytes) -> int:
        self.sha256.update(data)
        self.size += len(data)
        return len(data)

    def flush(self) -> None:
        pass

    def tell(self) -> int:
        return self.size


class _BoundedTarInfo(tarfile.TarInfo):
    """Bound extension headers before tarfile allocates or expands them."""

    def _proc_pax(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
        if self.type != tarfile.XHDTYPE or not 0 < self.size <= 4096:
            fail("accepted-transfer-pax-header")
        count = getattr(archive, "_paperdesk_pax_count", 0) + 1
        if count > 21:
            fail("accepted-transfer-pax-count")
        archive._paperdesk_pax_count = count
        return super()._proc_pax(archive)

    def _proc_gnulong(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
        fail("accepted-transfer-gnu-extension")

    def _proc_sparse(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
        fail("accepted-transfer-sparse-extension")

    def _proc_gnusparse_00(self, *args: Any) -> None:
        fail("accepted-transfer-sparse-extension")

    def _proc_gnusparse_01(self, *args: Any) -> None:
        fail("accepted-transfer-sparse-extension")

    def _proc_gnusparse_10(self, *args: Any) -> None:
        fail("accepted-transfer-sparse-extension")


def _strict_gzip_tar_digest(raw: bytes) -> _HashWriter:
    """Hash one complete gzip member's plaintext, rejecting appended data."""
    inflater = zlib.decompressobj(wbits=31)
    sink = _HashWriter()
    chunk_size = 64 * 1024
    output_size = 1024 * 1024
    # The 21 file payloads are capped separately. TAR headers, allowed
    # per-path PAX headers, member padding and record padding fit here.
    max_tar = MAX_EXPANDED + 256 * 1024
    try:
        for offset in range(0, len(raw), chunk_size):
            remaining = raw[offset:offset + chunk_size]
            while True:
                decoded = inflater.decompress(remaining, output_size)
                sink.write(decoded)
                if sink.size > max_tar:
                    fail("accepted-transfer-expanded-size")
                if inflater.eof:
                    if (inflater.unused_data or inflater.unconsumed_tail
                            or offset + chunk_size < len(raw)):
                        fail("accepted-transfer-gzip-trailing")
                    return sink
                tail = inflater.unconsumed_tail
                if not tail and len(decoded) < output_size:
                    break
                if not decoded and tail == remaining:
                    fail("accepted-transfer-gzip-stalled")
                remaining = tail
    except zlib.error as exc:
        raise AcceptedProofError("accepted-transfer-gzip") from exc
    fail("accepted-transfer-gzip-incomplete")


def _require_producer_archive(raw: bytes, names: list[str], observed: _HashWriter) -> None:
    """Reject bytes tarfile hides after TAR EOF or in extra PAX records.

    The source producer writes one gzip member containing a PAX TAR with these
    exact regular files. Compare the complete uncompressed TAR to a canonical
    re-encode; gzip DEFLATE bytes are allowed to vary across zlib versions.
    """
    canonical_tar = _HashWriter()
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r|gz", tarinfo=_BoundedTarInfo) as source:
            with tarfile.open(fileobj=canonical_tar, mode="w", format=tarfile.PAX_FORMAT) as target:
                seen = 0
                for member in source:
                    if seen >= len(names) or member.name != names[seen]:
                        fail("accepted-transfer-inventory")
                    stream = source.extractfile(member)
                    if stream is None:
                        fail("accepted-transfer-member")
                    info = tarfile.TarInfo(member.name)
                    info.size = member.size
                    info.mode = 0o600
                    info.mtime = info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    target.addfile(info, stream)
                    seen += 1
                if seen != len(names):
                    fail("accepted-transfer-inventory")
    except (tarfile.TarError, OSError, EOFError, zlib.error) as exc:
        raise AcceptedProofError("accepted-transfer-tar") from exc
    if observed.size != canonical_tar.size or observed.sha256.digest() != canonical_tar.sha256.digest():
        fail("accepted-transfer-noncanonical-framing")


def _archive_inventory(raw: bytes, source_sha: str) -> tuple[Mapping[str, Any], dict[str, dict[str, Any]], dict[str, bytes]]:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_TRANSFER:
        fail("accepted-transfer-size")
    observed_tar = _strict_gzip_tar_digest(raw)
    expected = _expected_files(source_sha)
    selected = {
        "request.json",
        f"payload/receipts/paperdesk-candidate-verification-receipt-{source_sha}.json",
        f"payload/receipts/paperdesk-production-acceptance-receipt-{source_sha}.json",
        f"payload/receipts/paperdesk-deployment-coordinate-receipt-{source_sha}.json",
        f"payload/verified-artifact/paperdesk-azure-runtime-{source_sha}.provenance.json",
        f"payload/verified-artifact/paperdesk-azure-runtime-{source_sha}.tar.gz.sha256",
    }
    bodies: dict[str, bytes] = {}
    records: dict[str, dict[str, Any]] = {}
    names: list[str] = []
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz", tarinfo=_BoundedTarInfo) as archive:
            for member in archive:
                name = member.name
                path = PurePosixPath(name)
                if (len(names) >= 21 or not member.isfile() or member.issym() or member.islnk()
                        or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts)
                        or name in names or member.mode != 0o600 or member.mtime != 0
                        or member.uid != 0 or member.gid != 0):
                    fail("accepted-transfer-member")
                maximum = 1024 * 1024 if name == "request.json" else expected.get(name.removeprefix("payload/")) if name.startswith("payload/") else None
                if maximum is None or not 0 < member.size <= maximum:
                    fail("accepted-transfer-member")
                total += member.size
                if total > MAX_EXPANDED:
                    fail("accepted-transfer-expanded-size")
                stream = archive.extractfile(member)
                if stream is None:
                    fail("accepted-transfer-member")
                sha = hashlib.sha256()
                md5 = hashlib.md5(usedforsecurity=False)
                count = 0
                capture = io.BytesIO() if name in selected else None
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > member.size:
                        fail("accepted-transfer-member-size")
                    sha.update(chunk)
                    md5.update(chunk)
                    if capture is not None:
                        capture.write(chunk)
                if count != member.size:
                    fail("accepted-transfer-member-size")
                names.append(name)
                records[name] = {"size": count, "sha256": sha.hexdigest(), "contentMd5": base64.b64encode(md5.digest()).decode("ascii")}
                if capture is not None:
                    bodies[name] = capture.getvalue()
    except (tarfile.TarError, OSError, EOFError, zlib.error) as exc:
        raise AcceptedProofError("accepted-transfer-tar") from exc
    if names != ["request.json", *(f"payload/{name}" for name in sorted(expected))]:
        fail("accepted-transfer-inventory")
    _require_producer_archive(raw, names, observed_tar)
    return _json(bodies["request.json"], "accepted-transfer-request-json", require_canonical=True), records, bodies


def _descriptor(value: Any, label: str) -> Mapping[str, Any]:
    item = _object(value, DESCRIPTOR_FIELDS, label)
    if (not isinstance(item["blob"], str) or PurePosixPath(item["blob"]).is_absolute()
            or ".." in PurePosixPath(item["blob"]).parts
            or not isinstance(item["size"], int) or isinstance(item["size"], bool) or item["size"] < 1
            or not re.fullmatch(r'"[^"\r\n]+"', str(item["etag"]))
            or not re.fullmatch(r"[A-Za-z0-9._=:+/-]{1,256}", str(item["versionId"]))):
        fail(label)
    _match(item["sha256"], SHA256, label)
    return item


def validate_transfer(
    transfer_tar: bytes, *, request: Mapping[str, Any], pending_release: Mapping[str, Any],
    consumed_marker: Mapping[str, Any], pending_bundle: Mapping[str, Any],
    candidate_runtime_sha256: str, now: dt.datetime,
) -> dict[str, Any]:
    """Return pre-write evidence only after every transfer member and receipt binds."""
    if not isinstance(transfer_tar, bytes) or not 0 < len(transfer_tar) <= MAX_TRANSFER:
        fail("accepted-transfer-size")
    source_sha = _match(request.get("sourceSha"), SHA40, "accepted-proof-source")
    _match(candidate_runtime_sha256, SHA256, "accepted-proof-runtime")
    if (request.get("artifactMember") != "paperdesk-accepted-release-request.tar.gz"
            or request.get("artifactMemberSha256") != hashlib.sha256(transfer_tar).hexdigest()):
        fail("accepted-transfer-artifact-binding")
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        fail("accepted-proof-now")
    coordinates = {name: request.get(name) for name in RELEASE_COORDINATES}
    if any(not isinstance(value, str) or not POSITIVE.fullmatch(value) for value in coordinates.values()):
        fail("accepted-proof-coordinates")
    if len({coordinates["sourceRunId"], coordinates["candidateRunId"], coordinates["acceptanceRunId"]}) != 3:
        fail("accepted-proof-run-alias")
    pending_release = _descriptor(pending_release, "accepted-proof-pending")
    consumed_marker = _descriptor(consumed_marker, "accepted-proof-consumed")
    pending_bundle = _descriptor(pending_bundle, "accepted-proof-pending-bundle")
    if (not pending_release["blob"].startswith(f"v2/pending/{source_sha}/")
            or consumed_marker["blob"] != str(PurePosixPath(pending_release["blob"]).parent / "consumed.json")
            or not pending_bundle["blob"].startswith(f"v1/pending/{source_sha}/")):
        fail("accepted-proof-descriptor-coordinate")
    transfer_request, member_records, bodies = _archive_inventory(transfer_tar, source_sha)
    _object(transfer_request, {
        "schema", "environment", "registry", "source", "deployment", "acceptance",
        "evidence", "artifacts", "verifier", "wormSnapshot", "files",
    }, "accepted-transfer-request-fields")
    if transfer_request["schema"] != TRANSFER_SCHEMA or transfer_request["environment"] != "production":
        fail("accepted-transfer-request-schema")
    source = _object(transfer_request["source"], {"repository", "sha", "runId", "runAttempt", "workflowRef"}, "accepted-transfer-source")
    deployment = _object(transfer_request["deployment"], {"runId", "runAttempt", "workflowRef"}, "accepted-transfer-deployment")
    acceptance = _object(transfer_request["acceptance"], {
        "runId", "runAttempt", "workflowRef", "acceptedAt", "candidateCompletedAt",
        "candidateFinalizeDeadline", "candidateRuntimeSha256", "evidenceContractSha256",
        "releaseScope", "environmentId",
    }, "accepted-transfer-acceptance")
    workflow_prefix = SOURCE_WORKFLOW.rsplit("@", 1)[0]
    pinned_workflow = f"{workflow_prefix}@{source_sha}"
    if (source != {"repository": "Sethvirak/MasterDataStructure", "sha": source_sha,
                   "runId": coordinates["sourceRunId"], "runAttempt": coordinates["sourceRunAttempt"],
                   "workflowRef": SOURCE_WORKFLOW}
            or deployment != {"runId": coordinates["candidateRunId"], "runAttempt": coordinates["candidateRunAttempt"], "workflowRef": pinned_workflow}
            or acceptance["runId"] != coordinates["acceptanceRunId"]
            or acceptance["runAttempt"] != coordinates["acceptanceRunAttempt"]
            or acceptance["workflowRef"] != pinned_workflow):
        fail("accepted-transfer-run-binding")
    registry = _object(transfer_request["registry"], {"storageAccount", "container", "bridgeApp", "bridgeResourceGroup", "prefix"}, "accepted-transfer-registry")
    if registry != {"storageAccount": "mdspdbak2608089c4e", "container": "paperdesk-accepted-releases",
                    "bridgeApp": "paperdesk-release-registry-bridge-9c4e0d0d", "bridgeResourceGroup": "rg-master-data-structure-sea",
                    "prefix": f"v1/releases/{source_sha}/{coordinates['sourceRunId']}/{coordinates['acceptanceRunId']}/"}:
        fail("accepted-transfer-evidence-prefix")
    snapshot = _object(transfer_request["wormSnapshot"], {
        "resourceId", "storageAccount", "container", "state", "immutabilityPeriodSinceCreationInDays",
        "allowProtectedAppendWrites", "allowProtectedAppendWritesAll", "etag", "observedAt",
    }, "accepted-transfer-worm-snapshot")
    suffix = ("/resourceGroups/rg-paperdesk-rollback-sea-20260808/providers/Microsoft.Storage/"
              "storageAccounts/mdspdbak2608089c4e/blobServices/default/containers/"
              "paperdesk-accepted-releases/immutabilityPolicies/default")
    if (not isinstance(snapshot["resourceId"], str) or not snapshot["resourceId"].lower().endswith(suffix.lower())
            or snapshot["storageAccount"] != registry["storageAccount"] or snapshot["container"] != registry["container"]
            or snapshot["state"] != "Locked" or type(snapshot["immutabilityPeriodSinceCreationInDays"]) is not int
            or snapshot["immutabilityPeriodSinceCreationInDays"] < 91
            or snapshot["allowProtectedAppendWrites"] is not False or snapshot["allowProtectedAppendWritesAll"] is not False):
        fail("accepted-transfer-worm-snapshot")
    expected = _expected_files(source_sha)
    listed = transfer_request["files"]
    if not isinstance(listed, list) or len(listed) != 20:
        fail("accepted-transfer-file-list")
    for listed_record, name in zip(listed, sorted(expected)):
        if (not isinstance(listed_record, dict) or set(listed_record) != {"path", "size", "sha256", "contentMd5"}
                or listed_record != {"path": name, **member_records[f"payload/{name}"]}):
            fail("accepted-transfer-file-binding")
    verification_path = f"receipts/paperdesk-candidate-verification-receipt-{source_sha}.json"
    acceptance_path = f"receipts/paperdesk-production-acceptance-receipt-{source_sha}.json"
    deployment_path = f"receipts/paperdesk-deployment-coordinate-receipt-{source_sha}.json"
    verification = _json(bodies[f"payload/{verification_path}"], "accepted-transfer-verification")
    receipt = _object(_json(bodies[f"payload/{acceptance_path}"], "accepted-transfer-receipt"), ACCEPTANCE_FIELDS, "accepted-transfer-receipt-fields")
    deployment_receipt = _json(bodies[f"payload/{deployment_path}"], "accepted-transfer-deployment-receipt")
    if (verification.get("schemaVersion") != 1 or verification.get("status") != "candidate-verified"
            or verification.get("candidateSha") != source_sha
            or verification.get("sourceRunId") != coordinates["sourceRunId"]
            or verification.get("sourceRunAttempt") != coordinates["sourceRunAttempt"]
            or verification.get("verifiedArtifactName") != f"paperdesk-azure-runtime-verified-{source_sha}"
            or verification.get("verifierJob") != "verify_candidate"):
        fail("accepted-transfer-verification-binding")
    for field in ("archiveSha256", "inputManifestSha256", "runtimeManifestSha256",
                  "releaseMaterialsSha256", "rootSbomSha256", "widgetSbomSha256", "provenanceSha256"):
        _match(verification.get(field), SHA256, "accepted-transfer-verification-" + field)
    stem = f"payload/verified-artifact/paperdesk-azure-runtime-{source_sha}"
    verified_members = {
        "inputManifestSha256": stem + ".package-input.json",
        "runtimeManifestSha256": stem + ".runtime-files.json",
        "rootSbomSha256": stem + ".cdx.json",
        "widgetSbomSha256": stem + ".widget.cdx.json",
        "provenanceSha256": stem + ".provenance.json",
    }
    for field, member in verified_members.items():
        if verification[field] != member_records[member]["sha256"]:
            fail("accepted-transfer-verification-member-binding-" + field)
    material_records = [
        {"path": path, "bytes": member_records[f"payload/verified-artifact/paperdesk-prebuild-release-materials/{path}"]["size"],
         "sha256": member_records[f"payload/verified-artifact/paperdesk-prebuild-release-materials/{path}"]["sha256"]}
        for path in sorted(RELEASE_MATERIAL_PATHS, key=lambda item: item.encode("utf-8"))
    ]
    material_bytes = (json.dumps(material_records, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    if verification["releaseMaterialsSha256"] != hashlib.sha256(material_bytes).hexdigest():
        fail("accepted-transfer-verification-material-binding")
    material_copies = {
        ".root-package.json": "package.json",
        ".root-package-lock.json": "package-lock.json",
        ".widget-package.json": "widget-showcase/package.json",
        ".widget-package-lock.json": "widget-showcase/package-lock.json",
        ".acceptance-contract.json": "architecture/production_acceptance_evidence_contract.json",
    }
    for suffix, path in material_copies.items():
        copy = member_records[stem + suffix]
        source_record = member_records[f"payload/verified-artifact/paperdesk-prebuild-release-materials/{path}"]
        if (copy["sha256"], copy["size"]) != (source_record["sha256"], source_record["size"]):
            fail("accepted-transfer-release-material-copy-binding")
    runtime_sha = _match(verification.get("archiveSha256"), SHA256, "accepted-transfer-runtime-sha")
    runtime_path = f"payload/verified-artifact/paperdesk-azure-runtime-{source_sha}.tar.gz"
    checksum_path = runtime_path + ".sha256"
    if (runtime_sha != candidate_runtime_sha256
            or runtime_sha != member_records[runtime_path]["sha256"]
            or bodies[checksum_path].replace(b"\r\n", b"\n")
            != f"{runtime_sha}  paperdesk-azure-runtime-{source_sha}.tar.gz\n".encode("ascii")):
        fail("accepted-transfer-runtime-binding")
    if receipt != {**receipt, "schemaVersion": 1, "status": "fully-accepted", "candidateSha": source_sha,
                   "candidateRunId": coordinates["candidateRunId"], "candidateRunAttempt": coordinates["candidateRunAttempt"],
                   "acceptedByRunId": coordinates["acceptanceRunId"], "acceptanceWorkflowHeadSha": source_sha,
                   "candidateRuntimeSha256": runtime_sha}:
        fail("accepted-transfer-receipt-binding")
    if deployment_receipt != {
        "schema": "paperdesk-deployment-coordinate-receipt-v1", "schemaVersion": 1,
        "candidateSha": source_sha, "candidateSourceRunId": coordinates["sourceRunId"],
        "candidateSourceRunAttempt": coordinates["sourceRunAttempt"],
        "deploymentRunId": coordinates["candidateRunId"], "deploymentRunAttempt": coordinates["candidateRunAttempt"],
        "verifiedArtifactName": f"paperdesk-azure-runtime-verified-{source_sha}", "candidateRuntimeSha256": runtime_sha,
    }:
        fail("accepted-transfer-deployment-receipt-binding")
    completed = _time(receipt["candidateCompletedAt"], "accepted-transfer-completed-time")
    deadline = _time(receipt["candidateFinalizeDeadline"], "accepted-transfer-deadline")
    accepted_at = _time(receipt["acceptedAt"], "accepted-transfer-accepted-time")
    if deadline != completed + dt.timedelta(hours=24) or not completed <= accepted_at <= deadline or accepted_at > now + dt.timedelta(minutes=5):
        fail("accepted-transfer-acceptance-window")
    expected_acceptance = {
        "runId": coordinates["acceptanceRunId"], "runAttempt": coordinates["acceptanceRunAttempt"],
        "workflowRef": pinned_workflow, "acceptedAt": receipt["acceptedAt"],
        "candidateCompletedAt": receipt["candidateCompletedAt"],
        "candidateFinalizeDeadline": receipt["candidateFinalizeDeadline"],
        "candidateRuntimeSha256": runtime_sha,
        "evidenceContractSha256": receipt["evidenceContractSha256"],
        "releaseScope": receipt["releaseScope"], "environmentId": receipt["environmentId"],
    }
    if acceptance != expected_acceptance:
        fail("accepted-transfer-acceptance-binding")
    if (receipt["evidenceContractSha256"] != member_records[f"payload/verified-artifact/paperdesk-azure-runtime-{source_sha}.acceptance-contract.json"]["sha256"]
            or receipt["releaseScope"] not in {"controlled-non-ha-pilot", "full-production"}
            or not isinstance(receipt["environmentId"], str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}", receipt["environmentId"])):
        fail("accepted-transfer-evidence-binding")
    evidence = _object(transfer_request["evidence"], {"runId", "runAttempt", "artifactId", "artifactName", "bundleSha256"}, "accepted-transfer-evidence")
    if (not isinstance(evidence["runId"], str) or not POSITIVE.fullmatch(evidence["runId"])
            or not isinstance(evidence["runAttempt"], str) or not POSITIVE.fullmatch(evidence["runAttempt"])
            or not isinstance(evidence["artifactId"], str) or not POSITIVE.fullmatch(evidence["artifactId"])
            or evidence["artifactName"] != f"paperdesk-production-acceptance-evidence-post-deploy-{source_sha}"
            or not isinstance(evidence["bundleSha256"], str) or not SHA256.fullmatch(evidence["bundleSha256"])
            or evidence["runId"] in {coordinates["sourceRunId"], coordinates["candidateRunId"], coordinates["acceptanceRunId"]}
            or receipt["evidenceRunId"] != evidence["runId"] or receipt["evidenceArtifactId"] != evidence["artifactId"]
            or receipt["evidenceBundleSha256"] != evidence["bundleSha256"]):
        fail("accepted-transfer-evidence-binding")
    artifacts = _object(transfer_request["artifacts"], {"verified", "verificationReceipt", "productionAcceptanceReceipt", "deploymentCoordinateReceipt"}, "accepted-transfer-artifacts")
    expected_names = {
        "verified": f"paperdesk-azure-runtime-verified-{source_sha}",
        "verificationReceipt": f"paperdesk-candidate-verification-receipt-{source_sha}",
        "productionAcceptanceReceipt": f"paperdesk-production-acceptance-receipt-{source_sha}",
        "deploymentCoordinateReceipt": f"paperdesk-deployment-coordinate-receipt-{source_sha}",
    }
    for label, expected_name in expected_names.items():
        artifact = artifacts[label]
        fields = {"id", "name", "digest"} | ({"fileSha256"} if label != "verified" else set())
        if not isinstance(artifact, dict) or set(artifact) != fields or artifact.get("name") != expected_name:
            fail("accepted-transfer-artifact-fields")
        _match(artifact["id"], POSITIVE, "accepted-transfer-artifact-id")
        _match(artifact["digest"], SHA256, "accepted-transfer-artifact-digest")
    for label, path in (("verificationReceipt", verification_path), ("productionAcceptanceReceipt", acceptance_path), ("deploymentCoordinateReceipt", deployment_path)):
        artifact = artifacts[label]
        if not isinstance(artifact, dict) or artifact.get("fileSha256") != member_records[f"payload/{path}"]["sha256"]:
            fail("accepted-transfer-artifact-receipt-binding")
    verifier = _object(transfer_request["verifier"], {"workflowRef", "job", "runId", "runAttempt"}, "accepted-transfer-verifier")
    if (verifier != {"workflowRef": verification.get("verifierWorkflow"), "job": "verify_candidate",
                     "runId": verification.get("verifierRunId"), "runAttempt": verification.get("verifierRunAttempt")}
            or not isinstance(verifier["workflowRef"], str) or not WORKFLOW.fullmatch(verifier["workflowRef"])):
        fail("accepted-transfer-verifier-binding")
    provenance = _json(bodies[f"payload/verified-artifact/paperdesk-azure-runtime-{source_sha}.provenance.json"], "accepted-transfer-provenance")
    if any((provenance.get("commit") != source_sha, provenance.get("repository") != source["repository"],
            str(provenance.get("runId")) != coordinates["sourceRunId"],
            str(provenance.get("runAttempt")) != coordinates["sourceRunAttempt"],
            provenance.get("workflow") != SOURCE_WORKFLOW)):
        fail("accepted-transfer-provenance-binding")
    if verification.get("provenanceSha256") != member_records[f"payload/verified-artifact/paperdesk-azure-runtime-{source_sha}.provenance.json"]["sha256"]:
        fail("accepted-transfer-provenance-binding")
    evidence = {
        "schemaVersion": 1, "proofType": "paperdesk-v2-accepted-release-proof",
        "sourceSha": source_sha, "releaseCoordinates": coordinates,
        "productionAcceptanceReceiptSha256": member_records[f"payload/{acceptance_path}"]["sha256"],
        "acceptedAt": receipt["acceptedAt"], "candidateRuntimeSha256": runtime_sha,
        "pendingRelease": dict(pending_release), "consumedMarker": dict(consumed_marker),
        "pendingBundle": dict(pending_bundle), "acceptedTransferSha256": hashlib.sha256(transfer_tar).hexdigest(),
        "transferRequestSha256": member_records["request.json"]["sha256"],
        "fileInventorySha256": hashlib.sha256(canonical(listed)).hexdigest(),
    }
    return evidence


def seal_proof(evidence: Mapping[str, Any], accepted_bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Bind prevalidated transfer evidence to the exact accepted package write."""
    bundle = _descriptor(accepted_bundle, "accepted-proof-bundle")
    source_sha = _match(evidence.get("sourceSha"), SHA40, "accepted-proof-source")
    coordinates = evidence.get("releaseCoordinates")
    if not isinstance(coordinates, dict) or set(coordinates) != RELEASE_COORDINATES:
        fail("accepted-proof-coordinates")
    expected_blob = (
        f"v1/accepted/{source_sha}/{coordinates['candidateRunId']}-{coordinates['candidateRunAttempt']}/"
        f"{coordinates['acceptanceRunId']}-{coordinates['acceptanceRunAttempt']}/deployment.zip"
    )
    pending = _descriptor(evidence.get("pendingBundle"), "accepted-proof-pending-bundle")
    if bundle["blob"] != expected_blob or (bundle["sha256"], bundle["size"]) != (pending["sha256"], pending["size"]):
        fail("accepted-proof-bundle-binding")
    proof = {**evidence, "deploymentBundle": dict(bundle)}
    validate_proof(proof, source_sha=source_sha, coordinates=coordinates,
                   pending_release=proof["pendingRelease"], consumed_marker=proof["consumedMarker"],
                   accepted_bundle=bundle, transfer_sha256=proof["acceptedTransferSha256"])
    return proof


def validate_proof(
    proof: Any, *, source_sha: str, coordinates: Mapping[str, Any],
    pending_release: Mapping[str, Any], consumed_marker: Mapping[str, Any],
    accepted_bundle: Mapping[str, Any], transfer_sha256: str,
) -> Mapping[str, Any]:
    """Validate the compact WORM proof against the final accepted manifest."""
    item = _object(proof, {
        "schemaVersion", "proofType", "sourceSha", "releaseCoordinates",
        "productionAcceptanceReceiptSha256", "acceptedAt", "candidateRuntimeSha256",
        "pendingRelease", "consumedMarker", "pendingBundle", "deploymentBundle", "acceptedTransferSha256",
        "transferRequestSha256", "fileInventorySha256",
    }, "accepted-proof-fields")
    if (item["schemaVersion"] != 1 or item["proofType"] != "paperdesk-v2-accepted-release-proof"
            or item["sourceSha"] != source_sha or item["releaseCoordinates"] != dict(coordinates)
            or item["pendingRelease"] != dict(pending_release) or item["consumedMarker"] != dict(consumed_marker)
            or item["deploymentBundle"] != dict(accepted_bundle) or item["acceptedTransferSha256"] != transfer_sha256):
        fail("accepted-proof-binding")
    pending_bundle = _descriptor(item["pendingBundle"], "accepted-proof-pending-bundle")
    if (not pending_bundle["blob"].startswith(f"v1/pending/{source_sha}/")
            or (pending_bundle["sha256"], pending_bundle["size"]) != (accepted_bundle["sha256"], accepted_bundle["size"])):
        fail("accepted-proof-bundle-binding")
    for field in ("productionAcceptanceReceiptSha256", "candidateRuntimeSha256", "acceptedTransferSha256", "transferRequestSha256", "fileInventorySha256"):
        _match(item[field], SHA256, "accepted-proof-" + field)
    _time(item["acceptedAt"], "accepted-proof-accepted-time")
    return item
