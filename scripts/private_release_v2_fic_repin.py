#!/usr/bin/env python3
"""One-shot, source-bound repin of the PaperDesk publisher FIC from S1 to S2.

``describe`` is the default and is credential-free. ``observe`` exposes only
read-only account, ARM-claim and Microsoft Graph projections and create-only
writes a preflight plus a deliberately non-executable authorization template.
``apply`` accepts one externally completed canonical authorization, consumes a
confirmation phrase from stdin, creates an authorization-specific global ARM
claim, removes the exact S1 FIC, proves an empty intermediate state, and only
then creates the exact sole S2 FIC.  There is never an overlapping credential.

The executor is deliberately transport-injected.  Unit tests use local fakes;
the production adapter reuses the bootstrap's no-redirect Azure REST session.
"""

from __future__ import annotations

import argparse
import copy
import dataclasses
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Callable, Mapping, Protocol, Sequence
import urllib.parse

try:
    from scripts import private_release_v2_bootstrap as bootstrap
    from scripts import private_release_v2_bootstrap_receipts as receipts
except ModuleNotFoundError:  # direct ``python scripts/...`` execution
    import private_release_v2_bootstrap as bootstrap  # type: ignore
    import private_release_v2_bootstrap_receipts as receipts  # type: ignore


ROOT = Path(__file__).resolve().parents[1]
EXECUTOR_PATH = ROOT / "scripts" / "private_release_v2_fic_repin.py"
AUTHORIZATION_SCHEMA_PATH = (
    ROOT / "contracts" / "private_release_s2_fic_repin_authorization_schema.json"
)
PREFLIGHT_SCHEMA_PATH = (
    ROOT / "contracts" / "private_release_s2_fic_repin_preflight_schema.json"
)
REPOSITORY = bootstrap.REPOSITORY
REMOTE_URLS = bootstrap.REMOTE_URLS
SUBSCRIPTION = bootstrap.SUBSCRIPTION
TENANT = bootstrap.TENANT
TRUSTED_REVIEWERS = bootstrap.TRUSTED_REVIEWERS
SIGNING_PRINCIPAL = bootstrap.SIGNING_PRINCIPAL
SIGNING_FINGERPRINT = bootstrap.SIGNING_FINGERPRINT
ALLOWED_SIGNERS_PATH = bootstrap.ALLOWED_SIGNERS_PATH
MAX_PREFLIGHT_AGE_SECONDS = 300
MAX_AUTHORIZATION_SECONDS = 1800
AUTHORIZATION_TYPE = "paperdesk-private-release-v2-s2-fic-repin-one-shot"
TEMPLATE_TYPE = "paperdesk-private-release-v2-s2-fic-repin-authorization-template"
PREFLIGHT_TYPE = "paperdesk-private-release-v2-s2-fic-repin-preflight"
RECEIPT_TYPE = "paperdesk-private-release-v2-s2-fic-repin-terminal-receipt"
FIC_NAME = "paperdesk-production-control-v2"
CLAIM_API_VERSION = "2022-09-01"
CLAIM_PREFIX = "paperdesk-v2-s2-fic-repin-"
MUTATION_UNIVERSE = [
    "createAuthorizationSpecificArmClaim",
    "deleteExactS1FederatedIdentityCredential",
    "createExactSoleS2FederatedIdentityCredential",
]
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
SENSITIVE_KEY = re.compile(
    r"(?:^|[_-])(?:access[-_]?token|refresh[-_]?token|client[-_]?secret|password|sas|connection[-_]?string|private[-_]?key)(?:$|[_-])",
    re.IGNORECASE,
)
SENSITIVE_TEXT = re.compile(
    r"(?:bearer\s+|client[_-]?secret\s*=|password\s*=|[?&]sig=)", re.IGNORECASE
)


class RepinError(RuntimeError):
    """The S2 source, authorization, Azure state, or receipt failed closed."""


def fail(message: str) -> None:
    raise RepinError(message)


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
        raise RepinError("document is not canonical-JSON representable") from exc


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _duplicate_safe_pairs(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def load_json(path: Path, *, require_canonical: bool = True) -> tuple[Any, bytes]:
    if not path.is_file() or path.is_symlink():
        fail(f"not one regular JSON file: {path}")
    raw = path.read_bytes()
    if not raw or len(raw) > 16 * 1024 * 1024:
        fail(f"JSON file size is invalid: {path}")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_duplicate_safe_pairs,
            parse_constant=lambda value: fail(f"invalid JSON constant: {value}"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RepinError(f"JSON is invalid UTF-8: {path}") from exc
    if require_canonical and raw != canonical_json_bytes(value):
        fail(f"JSON is not exact canonical bytes: {path}")
    return value, raw


def _exact(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} fields are not exact")
    return value


def _sha40(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA40.fullmatch(value):
        fail(f"{label} is not one lowercase commit SHA")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        fail(f"{label} is not one lowercase SHA-256")
    return value


def _guid(value: Any, label: str) -> str:
    if not isinstance(value, str) or not GUID.fullmatch(value):
        fail(f"{label} is not one lowercase GUID")
    return value


def parse_time(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"{label} is not one UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RepinError(f"{label} is not one UTC timestamp") from exc
    if parsed.tzinfo != dt.timezone.utc:
        fail(f"{label} is not UTC")
    return parsed


def stamp(value: dt.datetime) -> str:
    if value.tzinfo != dt.timezone.utc:
        fail("clock is not exact UTC")
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _reject_secrets(value: Any, label: str = "document") -> None:
    text = canonical_json_bytes(value).decode("utf-8")
    if SENSITIVE_TEXT.search(text):
        fail(f"{label} contains credential-shaped text")

    def walk(item: Any, path: str) -> None:
        if isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str):
                    fail(f"{label} contains a non-string key")
                lowered = key.lower()
                if (
                    SENSITIVE_KEY.search(lowered)
                    or lowered in {"authorization", "cookie", "set-cookie"}
                    or lowered in {"passwordcredentials", "keycredentials"}
                ) and child not in (None, "", [], {}):
                    fail(f"{label} contains secret material at {path}.{key}")
                walk(child, f"{path}.{key}")
        elif isinstance(item, list):
            for index, child in enumerate(item):
                walk(child, f"{path}[{index}]")

    walk(value, label)


def _validate_reviewed_source(source: Mapping[str, Any]) -> dict[str, Any]:
    source = _exact(source, {"reviewedHead", "mergedMain"}, "S2 source evidence")
    reviewed = _exact(
        source["reviewedHead"],
        {
            "commitSha", "treeSha", "signatureVerified", "signingPrincipal",
            "signingKeyFingerprint", "pullRequestNumber", "pullRequestUrl",
            "reviewDecision", "requiredApprovals", "pushedAt", "reviews",
            "requiredCheck",
        },
        "S2 reviewed head",
    )
    head = _sha40(reviewed["commitSha"], "S2 reviewed head")
    tree = _sha40(reviewed["treeSha"], "S2 reviewed tree")
    pushed = parse_time(reviewed["pushedAt"], "S2 reviewed pushedAt")
    if (
        reviewed["signatureVerified"] is not True
        or reviewed["signingPrincipal"] != SIGNING_PRINCIPAL
        or reviewed["signingKeyFingerprint"] != SIGNING_FINGERPRINT
        or reviewed["reviewDecision"] != "APPROVED"
        or reviewed["requiredApprovals"] != 2
        or type(reviewed["pullRequestNumber"]) is not int
        or reviewed["pullRequestNumber"] < 1
        or reviewed["pullRequestUrl"]
        != f"https://github.com/{REPOSITORY}/pull/{reviewed['pullRequestNumber']}"
    ):
        fail("S2 reviewed-head policy is not exact")
    reviews = reviewed["reviews"]
    if not isinstance(reviews, list) or len(reviews) != 2:
        fail("S2 requires exactly two reviews")
    seen: dict[str, int] = {}
    review_times: list[dt.datetime] = []
    review_ids: set[int] = set()
    for index, item in enumerate(reviews):
        review = _exact(
            item,
            {"login", "userId", "reviewId", "state", "submittedAt", "commitSha"},
            f"S2 review {index}",
        )
        if (
            review["login"] not in TRUSTED_REVIEWERS
            or review["userId"] != TRUSTED_REVIEWERS.get(review["login"])
            or type(review["reviewId"]) is not int
            or review["reviewId"] < 1
            or review["state"] != "APPROVED"
            or review["commitSha"] != head
        ):
            fail("S2 review is not an exact-head trusted approval")
        submitted = parse_time(review["submittedAt"], "S2 review submittedAt")
        if submitted <= pushed:
            fail("S2 review predates the exact-head push")
        seen[review["login"]] = review["userId"]
        review_ids.add(review["reviewId"])
        review_times.append(submitted)
    if seen != TRUSTED_REVIEWERS or len(review_ids) != 2:
        fail("S2 reviewers are not the exact two distinct trusted accounts")
    check = _exact(
        reviewed["requiredCheck"],
        {"name", "runId", "headSha", "conclusion", "completedAt"},
        "S2 required check",
    )
    checked_at = parse_time(check["completedAt"], "S2 check completedAt")
    if (
        check["name"] != "test"
        or not isinstance(check["runId"], str)
        or not re.fullmatch(r"[1-9][0-9]*", check["runId"])
        or check["headSha"] != head
        or check["conclusion"] != "success"
        or checked_at <= pushed
    ):
        fail("S2 required check is not exact-head success")
    merged = _exact(
        source["mergedMain"],
        {
            "commitSha", "treeSha", "soleParentSha", "treeEqualsReviewedHead",
            "githubVerificationVerified", "githubVerificationReason",
            "mergedPullRequestNumber", "mergedPullRequestUrl", "mergedAt",
            "verificationApiUrl", "verificationRetrievedAt",
        },
        "S2 merged main",
    )
    merged_sha = _sha40(merged["commitSha"], "S2 merged main")
    merged_tree = _sha40(merged["treeSha"], "S2 merged tree")
    parent = _sha40(merged["soleParentSha"], "S2 sole parent")
    merged_at = parse_time(merged["mergedAt"], "S2 mergedAt")
    retrieved = parse_time(merged["verificationRetrievedAt"], "S2 verification time")
    if (
        merged_sha == head
        or merged_tree != tree
        or merged["treeEqualsReviewedHead"] is not True
        or merged["githubVerificationVerified"] is not True
        or merged["githubVerificationReason"] != "valid"
        or merged["mergedPullRequestNumber"] != reviewed["pullRequestNumber"]
        or merged["mergedPullRequestUrl"] != reviewed["pullRequestUrl"]
        or merged["verificationApiUrl"]
        != f"https://api.github.com/repos/{REPOSITORY}/commits/{merged_sha}"
        or merged_at < max([checked_at, *review_times])
        or retrieved < merged_at
    ):
        fail("S2 protected merged-main evidence is not exact")
    return copy.deepcopy(dict(source))


def _git_text(
    arguments: Sequence[str],
    *,
    repo_root: Path,
    git_runner: Callable[..., subprocess.CompletedProcess[str]],
) -> str:
    process = git_runner(
        ["git", *arguments],
        cwd=repo_root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if process.returncode != 0:
        fail(f"local Git source inspection failed: {' '.join(arguments)}")
    return process.stdout.strip()


def validate_local_s2_source(
    source: Mapping[str, Any],
    *,
    repo_root: Path = ROOT,
    s1_sha: str,
    required_paths: Sequence[str],
    git_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    source = _validate_reviewed_source(source)
    reviewed = source["reviewedHead"]
    merged = source["mergedMain"]
    if merged["soleParentSha"] != s1_sha or merged["commitSha"] == s1_sha:
        fail("S2 does not have the exact accepted S1 merge as its sole parent")
    if _git_text(["status", "--porcelain=v1"], repo_root=repo_root, git_runner=git_runner):
        fail("local S2 source worktree is not clean")
    if _git_text(["symbolic-ref", "--short", "HEAD"], repo_root=repo_root, git_runner=git_runner) != "main":
        fail("local S2 source is not checked out on main")
    if _git_text(["config", "--get", "remote.origin.url"], repo_root=repo_root, git_runner=git_runner) not in REMOTE_URLS:
        fail("local S2 source remote is not the verifier repository")
    head = _git_text(["rev-parse", "HEAD"], repo_root=repo_root, git_runner=git_runner)
    origin = _git_text(["rev-parse", "refs/remotes/origin/main"], repo_root=repo_root, git_runner=git_runner)
    tree = _git_text(["rev-parse", "HEAD^{tree}"], repo_root=repo_root, git_runner=git_runner)
    parents = _git_text(["rev-list", "--parents", "-n", "1", "HEAD"], repo_root=repo_root, git_runner=git_runner).split()
    if (
        head != merged["commitSha"]
        or origin != head
        or tree != merged["treeSha"]
        or parents != [head, s1_sha]
    ):
        fail("local source is not the exact protected S2 merge")
    reviewed_sha = reviewed["commitSha"]
    _git_text(["cat-file", "-e", f"{reviewed_sha}^{{commit}}"], repo_root=repo_root, git_runner=git_runner)
    signature_args = [
        "-c", "gpg.format=ssh", "-c", f"gpg.ssh.allowedSignersFile={ALLOWED_SIGNERS_PATH}",
    ]
    _git_text([*signature_args, "verify-commit", reviewed_sha], repo_root=repo_root, git_runner=git_runner)
    signature = _git_text(
        [*signature_args, "log", "-1", "--format=%G?%x00%GS%x00%GK", reviewed_sha],
        repo_root=repo_root,
        git_runner=git_runner,
    )
    if signature != f"G\x00{SIGNING_PRINCIPAL}\x00{SIGNING_FINGERPRINT}":
        fail("S2 reviewed head does not have the exact SSH signature")
    names = [
        line for line in _git_text(
            ["diff", "--name-only", s1_sha, head, "--"],
            repo_root=repo_root,
            git_runner=git_runner,
        ).splitlines() if line
    ]
    expected = list(required_paths)
    if sorted(names) != sorted(expected) or len(names) != len(expected):
        fail("S2 merged-main diff is not exactly the six evidence paths")
    statuses = [
        line for line in _git_text(
            ["diff", "--name-status", s1_sha, head, "--"],
            repo_root=repo_root,
            git_runner=git_runner,
        ).splitlines() if line
    ]
    if len(statuses) != len(expected):
        fail("S2 diff status set is not exact")
    for line in statuses:
        parts = line.split("\t")
        if len(parts) != 2 or parts[0] not in {"A", "M"} or parts[1] not in expected:
            fail("S2 evidence commit contains delete, rename, copy, or extra source change")
    return {
        "repository": REPOSITORY,
        "s1MergedSha": s1_sha,
        "s2ReviewedHeadSha": reviewed_sha,
        "s2MergedSha": head,
        "s2TreeSha": tree,
        "s2SoleParentSha": s1_sha,
        "requiredPaths": expected,
    }


def _load_bootstrap_bundle(
    *,
    repo_root: Path,
    bootstrap_authorization_path: Path,
    bootstrap_preflight_path: Path,
) -> dict[str, Any]:
    plan, plan_sha = bootstrap.load_plan()
    authorization, authorization_raw = load_json(bootstrap_authorization_path)
    if not isinstance(authorization, Mapping):
        fail("original bootstrap authorization is not an object")
    package, package_bytes = bootstrap.build_package_artifact()
    try:
        validated_authorization = bootstrap.validate_authorization_evidence(
            authorization, plan=plan, plan_sha256=plan_sha, package=package
        )
    except Exception as exc:
        raise RepinError(f"original bootstrap authorization is invalid: {exc}") from exc
    preflight, preflight_raw = load_json(bootstrap_preflight_path)
    try:
        validated_preflight, _ = bootstrap.validate_preflight_evidence(
            preflight, authorization, plan
        )
    except Exception as exc:
        raise RepinError(f"original bootstrap preflight is invalid: {exc}") from exc
    model = receipts.load_model()
    paths = list(model["requiredS2EvidencePaths"])
    terminal_path = model["requiredS2TerminalBundlePath"]
    all_paths = [*paths, terminal_path]
    bodies: dict[str, bytes] = {}
    for relative in all_paths:
        path = repo_root / Path(*relative.split("/"))
        if not path.is_file() or path.is_symlink():
            fail(f"required S2 evidence path is absent or unsafe: {relative}")
        body = path.read_bytes()
        document = receipts.load_canonical_json_bytes(
            body, label=f"S2 evidence {relative}", maximum_bytes=16 * 1024 * 1024
        )
        if canonical_json_bytes(document) != body:
            fail(f"S2 evidence is not exact canonical JSON: {relative}")
        bodies[relative] = body
    terminal_document = receipts.load_canonical_json_bytes(
        bodies[terminal_path], label="S2 terminal bundle", maximum_bytes=16 * 1024 * 1024
    )
    completed_at = terminal_document.get("executionReceipt", {}).get("completedAt")
    if not isinstance(completed_at, str):
        fail("S2 terminal bundle lacks exact completion time")
    try:
        validated_terminal = receipts.validate_receipt_bundle(
            terminal_document,
            authorization=authorization,
            plan=plan,
            s2_documents={path: bodies[path] for path in paths},
            terminal_bundle_path=terminal_path,
            terminal_bundle_body=bodies[terminal_path],
            authorized_preflight_projection=validated_preflight["projection"],
            package_bytes=package_bytes,
            now=completed_at,
        )
    except Exception as exc:
        raise RepinError(f"S2 receipt bundle is invalid: {exc}") from exc
    descriptors = [
        {"path": path, "sha256": sha256_bytes(bodies[path]), "size": len(bodies[path])}
        for path in all_paths
    ]
    provisioning_path = receipts.S2_EVIDENCE_COMPONENT_PATHS["provisioningEvidence"]
    provisioning = receipts.load_canonical_json_bytes(
        bodies[provisioning_path], label="S2 provisioning evidence"
    )
    publisher = provisioning.get("publisherIdentity")
    roles = provisioning.get("roles")
    publisher_role = roles.get("publisherMailbox") if isinstance(roles, Mapping) else None
    if not isinstance(publisher, Mapping) or not isinstance(publisher_role, Mapping):
        fail("S2 provisioning evidence lacks publisher identity facts")
    application_object_id = _guid(
        publisher.get("applicationObjectId"), "publisher application object ID"
    )
    application_client_id = _guid(
        publisher_role.get("identityClientId"), "publisher application client ID"
    )
    s1_sha = authorization["source"]["mergedMain"]["commitSha"]
    if authorization["plan"]["bridgePackageSourceSha"] != s1_sha:
        fail("terminal bootstrap package source is not the exact S1 merge")
    return {
        "plan": plan,
        "planSha256": plan_sha,
        "authorization": authorization,
        "authorizationSha256": sha256_bytes(authorization_raw),
        "authorizationPath": str(bootstrap_authorization_path),
        "validatedAuthorization": validated_authorization,
        "preflight": validated_preflight,
        "preflightSha256": sha256_bytes(preflight_raw),
        "preflightPath": str(bootstrap_preflight_path),
        "package": package,
        "packageBytes": package_bytes,
        "s1Sha": s1_sha,
        "paths": all_paths,
        "s2Bodies": bodies,
        "terminal": validated_terminal,
        "terminalPath": terminal_path,
        "terminalSha256": sha256_bytes(bodies[terminal_path]),
        "descriptors": descriptors,
        "provisioningEvidence": provisioning,
        "applicationObjectId": application_object_id,
        "applicationClientId": application_client_id,
    }


def _fic_expression(source_sha: str) -> str:
    _sha40(source_sha, "FIC source SHA")
    plan, _ = bootstrap.load_plan()
    resources = {item["id"]: item for item in plan["resourceInventory"]}
    return resources["publisherFederatedCredential"]["claimsMatchingExpressionTemplate"].replace(
        "${authorization.source.mergedMain.commitSha}", source_sha
    )


def expected_fic(source_sha: str, *, credential_id: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "name": FIC_NAME,
        "issuer": "https://token.actions.githubusercontent.com",
        "audiences": ["api://AzureADTokenExchange"],
        "subject": None,
        "claimsMatchingExpression": {
            "languageVersion": 1,
            "value": _fic_expression(source_sha),
        },
    }
    if credential_id is not None:
        result = {"id": _guid(credential_id, "FIC ID"), **result}
    return result


def _normalize_fic(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        fail("federated identity credential is not an object")
    normalized = {
        "id": value.get("id"),
        "name": value.get("name"),
        "issuer": value.get("issuer"),
        "audiences": value.get("audiences"),
        "subject": value.get("subject"),
        "claimsMatchingExpression": value.get("claimsMatchingExpression"),
    }
    _guid(normalized["id"], "FIC ID")
    _reject_secrets(normalized, "FIC projection")
    return normalized


def _normalize_fic_list(document: Any) -> list[dict[str, Any]]:
    if not isinstance(document, Mapping) or set(document) - {"value", "@odata.context"}:
        fail("Graph FIC response fields are not exact")
    values = document.get("value")
    if not isinstance(values, list) or len(values) > 2:
        fail("Graph FIC inventory is invalid or exceeds the no-overlap boundary")
    result = [_normalize_fic(item) for item in values]
    if len({item["id"] for item in result}) != len(result):
        fail("Graph FIC inventory contains duplicate IDs")
    return result


def classify_fic_state(credentials: Sequence[Mapping[str, Any]], s1_sha: str, s2_sha: str) -> str:
    if s1_sha == s2_sha:
        fail("S1 and S2 must differ")
    if len(credentials) == 0:
        return "empty"
    if len(credentials) != 1:
        fail("publisher has overlapping or extra federated identity credentials")
    item = dict(credentials[0])
    if item == expected_fic(s1_sha, credential_id=item.get("id")):
        return "s1"
    if item == expected_fic(s2_sha, credential_id=item.get("id")):
        return "s2"
    fail("publisher credential is a third state")


@dataclasses.dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    headers: Mapping[str, str] = dataclasses.field(default_factory=dict)


class Session(Protocol):
    def account(self) -> Mapping[str, Any]: ...
    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Response: ...


class AzureCliSession:
    """Concrete no-redirect Azure session with account-bound lazy tokens."""

    def __init__(self, *, clock: Callable[[], dt.datetime] | None = None) -> None:
        self.clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        self._account: dict[str, Any] | None = None
        self._session: Any | None = None

    def account(self) -> Mapping[str, Any]:
        if self._account is None:
            probe = bootstrap.AzureCliRestSession({}, clock=self.clock)
            self._account = _account(probe.account())
            self._session = bootstrap.AzureCliRestSession(
                {"azure": self._account}, clock=self.clock
            )
        return copy.deepcopy(self._account)

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Response:
        if self._session is None:
            self.account()
        assert self._session is not None
        response = self._session.request(method, url, body=body, headers=headers)
        # AzureCliRestSession installs _NoRedirect.  Any 3xx therefore reaches
        # this boundary instead of forwarding an ARM or Graph bearer token.
        if 300 <= response.status <= 399:
            fail("privileged Azure request redirected and was rejected")
        return Response(response.status, response.body, dict(response.headers))


def _response_json(response: Any, expected: set[int], label: str) -> Mapping[str, Any]:
    if response.status not in expected:
        fail(f"{label} returned HTTP {response.status}")
    if not response.body:
        return {}
    try:
        value = json.loads(
            response.body.decode("utf-8"),
            object_pairs_hook=_duplicate_safe_pairs,
            parse_constant=lambda value: fail(f"invalid JSON constant: {value}"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RepinError(f"{label} returned invalid JSON") from exc
    if not isinstance(value, Mapping):
        fail(f"{label} returned a non-object")
    _reject_secrets(value, label)
    return value


def _claim_resource_id(authorization_id: str) -> str:
    _guid(authorization_id, "authorization ID")
    return (
        f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Resources/deployments/"
        f"{CLAIM_PREFIX}{authorization_id}"
    )


def _claim_url(authorization_id: str) -> str:
    return (
        "https://management.azure.com"
        + _claim_resource_id(authorization_id)
        + f"?api-version={CLAIM_API_VERSION}"
    )


def _graph_urls(application_object_id: str) -> tuple[str, str]:
    app_id = _guid(application_object_id, "publisher application object ID")
    root = f"https://graph.microsoft.com/beta/applications/{app_id}"
    return (
        root + "?$select=id,appId,displayName,passwordCredentials,keyCredentials",
        root + "/federatedIdentityCredentials",
    )


def _read_publisher(
    session: Session,
    *,
    application_object_id: str,
    application_client_id: str,
) -> dict[str, Any]:
    application_url, fic_url = _graph_urls(application_object_id)
    app_response = session.request("GET", application_url)
    app = _response_json(app_response, {200}, "publisher application read")
    projection = {
        "id": app.get("id"),
        "appId": app.get("appId"),
        "displayName": app.get("displayName"),
        "passwordCredentials": app.get("passwordCredentials"),
        "keyCredentials": app.get("keyCredentials"),
    }
    if (
        projection["id"] != application_object_id
        or projection["appId"] != application_client_id
        or not isinstance(projection["displayName"], str)
        or not projection["displayName"]
        or projection["passwordCredentials"] != []
        or projection["keyCredentials"] != []
    ):
        fail("publisher application is not exact and credentialless")
    fic_response = session.request("GET", fic_url)
    credentials = _normalize_fic_list(
        _response_json(fic_response, {200}, "publisher FIC inventory")
    )
    return {
        "applicationQuery": application_url,
        "application": projection,
        "federatedIdentityCredentialsQuery": fic_url,
        "federatedIdentityCredentials": credentials,
    }


def _account(value: Mapping[str, Any]) -> dict[str, Any]:
    value = _exact(
        value,
        {"cloud", "subscriptionId", "tenantId", "accountId", "accountObjectId", "accountType"},
        "Azure account",
    )
    result = dict(value)
    if (
        result["cloud"] != "AzureCloud"
        or result["subscriptionId"] != SUBSCRIPTION
        or result["tenantId"] != TENANT
        or not isinstance(result["accountId"], str)
        or not 3 <= len(result["accountId"]) <= 256
        or result["accountType"] not in {"user", "servicePrincipal"}
    ):
        fail("Azure account is outside the fixed tenant/subscription boundary")
    _guid(result["accountObjectId"], "Azure account object ID")
    return result


def build_source_binding(
    source_evidence: Mapping[str, Any],
    *,
    bundle: Mapping[str, Any],
    repo_root: Path = ROOT,
    git_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    local = validate_local_s2_source(
        source_evidence,
        repo_root=repo_root,
        s1_sha=bundle["s1Sha"],
        required_paths=bundle["paths"],
        git_runner=git_runner,
    )
    if local["s2MergedSha"] == bundle["s1Sha"]:
        fail("S2 equals S1")
    for descriptor in bundle["descriptors"]:
        path = repo_root / Path(*descriptor["path"].split("/"))
        raw = path.read_bytes()
        if len(raw) != descriptor["size"] or sha256_bytes(raw) != descriptor["sha256"]:
            fail(f"S2 source bytes drifted: {descriptor['path']}")
    return {
        "evidence": copy.deepcopy(dict(source_evidence)),
        "binding": {
            **local,
            "files": copy.deepcopy(bundle["descriptors"]),
            "terminalBundleSha256": bundle["terminalSha256"],
        },
    }


def _bootstrap_binding(bundle: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "originalAuthorization": {
            "sha256": bundle["authorizationSha256"],
            "authorizationId": bundle["authorization"]["authorizationId"],
        },
        "originalPreflight": {"sha256": bundle["preflightSha256"]},
        "package": {
            "sourceSha": bundle["s1Sha"],
            "sha256": bundle["package"]["sha256"],
            "size": bundle["package"]["size"],
        },
        "terminalBundle": {
            "path": bundle["terminalPath"],
            "sha256": bundle["terminalSha256"],
        },
    }


def build_preflight(
    *,
    authorization_id: str,
    source: Mapping[str, Any],
    bundle: Mapping[str, Any],
    session: Session,
    now: dt.datetime,
) -> dict[str, Any]:
    _guid(authorization_id, "authorization ID")
    account = _account(session.account())
    publisher = _read_publisher(
        session,
        application_object_id=bundle["applicationObjectId"],
        application_client_id=bundle["applicationClientId"],
    )
    if classify_fic_state(
        publisher["federatedIdentityCredentials"],
        bundle["s1Sha"],
        source["binding"]["s2MergedSha"],
    ) != "s1":
        fail("read-only repin preflight does not observe the exact sole S1 FIC")
    claim_response = session.request("GET", _claim_url(authorization_id))
    if claim_response.status != 404:
        fail("authorization-specific global ARM claim is not absent")
    projection = {
        "account": account,
        "source": copy.deepcopy(dict(source)),
        "bootstrap": _bootstrap_binding(bundle),
        "publisher": publisher,
        "azureClaim": {
            "resourceId": _claim_resource_id(authorization_id),
            "httpStatus": 404,
            "state": "absent",
        },
    }
    document = {
        "schemaVersion": 1,
        "preflightType": PREFLIGHT_TYPE,
        "status": "observed-read-only",
        "authorizationId": authorization_id,
        "observedAt": stamp(now),
        **projection,
        "projectionSha256": sha256_bytes(canonical_json_bytes(projection)),
    }
    _reject_secrets(document, "repin preflight")
    return document


def build_authorization_template(
    preflight: Mapping[str, Any], *, receipt_directory: Path
) -> dict[str, Any]:
    authorization_id = preflight["authorizationId"]
    return {
        "schemaVersion": 1,
        "templateType": TEMPLATE_TYPE,
        "status": "NON_EXECUTABLE_REQUIRES_EXPLICIT_AUTHORIZATION_CEREMONY",
        "authorizationId": authorization_id,
        "repository": REPOSITORY,
        "source": copy.deepcopy(preflight["source"]["evidence"]),
        "executor": {
            "path": "scripts/private_release_v2_fic_repin.py",
            "sha256": sha256_bytes(EXECUTOR_PATH.read_bytes()),
        },
        "bootstrap": copy.deepcopy(preflight["bootstrap"]),
        "azure": copy.deepcopy(preflight["account"]),
        "observedPreflight": {
            "sha256": sha256_bytes(canonical_json_bytes(preflight)),
            "observedAt": preflight["observedAt"],
            "maximumAgeSeconds": MAX_PREFLIGHT_AGE_SECONDS,
        },
        "proposedValidity": {"maximumLifetimeSeconds": MAX_AUTHORIZATION_SECONDS},
        "singleUse": {
            "required": True,
            "receiptDirectory": str(receipt_directory),
            "azureClaimResourceId": _claim_resource_id(authorization_id),
        },
        "missingExecutableFields": ["authorizationType", "validity", "confirmation"],
    }


def _create_only(path: Path, raw: bytes) -> None:
    if not path.is_absolute() or path.is_symlink():
        fail("create-only output path is not one absolute safe path")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise RepinError(f"create-only output already exists: {path}") from exc
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        raise
    if path.read_bytes() != raw:
        fail(f"create-only output readback drifted: {path}")


def observe(
    *,
    authorization_id: str,
    source_evidence: Mapping[str, Any],
    bootstrap_authorization_path: Path,
    bootstrap_preflight_path: Path,
    preflight_output: Path,
    template_output: Path,
    receipt_directory: Path,
    session: Session,
    now: dt.datetime,
    repo_root: Path = ROOT,
    git_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    outputs = (preflight_output, template_output)
    if (
        preflight_output == template_output
        or any(not path.is_absolute() or path.is_symlink() for path in outputs)
        or any(path.exists() for path in outputs)
    ):
        fail("observe outputs must be two distinct absent absolute create-only paths")
    bundle = _load_bootstrap_bundle(
        repo_root=repo_root,
        bootstrap_authorization_path=bootstrap_authorization_path,
        bootstrap_preflight_path=bootstrap_preflight_path,
    )
    source = build_source_binding(
        source_evidence, bundle=bundle, repo_root=repo_root, git_runner=git_runner
    )
    preflight = build_preflight(
        authorization_id=authorization_id,
        source=source,
        bundle=bundle,
        session=session,
        now=now,
    )
    template = build_authorization_template(preflight, receipt_directory=receipt_directory)
    _create_only(preflight_output, canonical_json_bytes(preflight))
    _create_only(template_output, canonical_json_bytes(template))
    return {"preflight": preflight, "authorizationTemplate": template}


@dataclasses.dataclass(frozen=True)
class ValidatedAuthorization:
    document: Mapping[str, Any]
    sha256: str
    receipt_directory: Path
    not_before: dt.datetime
    expires_at: dt.datetime


def validate_authorization(
    path: Path,
    *,
    preflight: Mapping[str, Any],
    preflight_raw: bytes,
    bundle: Mapping[str, Any],
    source: Mapping[str, Any],
    confirmation_phrase: str,
    now: dt.datetime,
) -> ValidatedAuthorization:
    document, raw = load_json(path)
    root = _exact(
        document,
        {
            "schemaVersion", "authorizationType", "authorizationId", "repository",
            "source", "executor", "bootstrap", "azure", "observedPreflight",
            "validity", "confirmation", "singleUse",
        },
        "repin authorization",
    )
    if (
        root["schemaVersion"] != 1
        or root["authorizationType"] != AUTHORIZATION_TYPE
        or root["authorizationId"] != preflight["authorizationId"]
        or root["repository"] != REPOSITORY
        or root["source"] != source["evidence"]
        or root["bootstrap"] != preflight["bootstrap"]
        or root["azure"] != preflight["account"]
    ):
        fail("repin authorization identity/source bindings are not exact")
    _guid(root["authorizationId"], "authorization ID")
    _validate_reviewed_source(root["source"])
    executor = _exact(root["executor"], {"path", "sha256"}, "repin executor")
    if (
        executor["path"] != "scripts/private_release_v2_fic_repin.py"
        or executor["sha256"] != sha256_bytes(EXECUTOR_PATH.read_bytes())
    ):
        fail("repin authorization does not bind the exact executor bytes")
    observed = _exact(
        root["observedPreflight"],
        {"sha256", "observedAt", "maximumAgeSeconds"},
        "repin observed preflight",
    )
    observed_at = parse_time(observed["observedAt"], "repin preflight observedAt")
    if (
        observed["sha256"] != sha256_bytes(preflight_raw)
        or observed["observedAt"] != preflight["observedAt"]
        or observed["maximumAgeSeconds"] != MAX_PREFLIGHT_AGE_SECONDS
        or observed_at > now
        or (now - observed_at).total_seconds() > MAX_PREFLIGHT_AGE_SECONDS
    ):
        fail("repin authorization preflight binding is stale or invalid")
    validity = _exact(
        root["validity"], {"notBefore", "expiresAt", "maximumLifetimeSeconds"},
        "repin validity",
    )
    not_before = parse_time(validity["notBefore"], "repin notBefore")
    expires_at = parse_time(validity["expiresAt"], "repin expiresAt")
    if (
        validity["maximumLifetimeSeconds"] != MAX_AUTHORIZATION_SECONDS
        or not 0 < (expires_at - not_before).total_seconds() <= MAX_AUTHORIZATION_SECONDS
        or not not_before <= now <= expires_at
    ):
        fail("repin authorization is outside its finite validity")
    confirmation = _exact(
        root["confirmation"], {"encoding", "phraseSha256"}, "repin confirmation"
    )
    if (
        confirmation["encoding"] != "utf-8-exact-no-newline"
        or "\r" in confirmation_phrase
        or "\n" in confirmation_phrase
        or confirmation["phraseSha256"]
        != sha256_bytes(confirmation_phrase.encode("utf-8"))
    ):
        fail("repin confirmation phrase does not match")
    single = _exact(
        root["singleUse"],
        {"required", "receiptDirectory", "azureClaimResourceId"},
        "repin single use",
    )
    receipt_directory = Path(single["receiptDirectory"])
    expected_name = f"{CLAIM_PREFIX}{root['authorizationId']}"
    try:
        resolved = receipt_directory.resolve(strict=False)
        repo_resolved = ROOT.resolve(strict=True)
    except OSError as exc:
        raise RepinError("repin receipt directory cannot be resolved") from exc
    if (
        single["required"] is not True
        or single["azureClaimResourceId"] != _claim_resource_id(root["authorizationId"])
        or not receipt_directory.is_absolute()
        or resolved.name != expected_name
        or resolved == repo_resolved
        or repo_resolved in resolved.parents
    ):
        fail("repin single-use paths are not exact authorization-specific state")
    if root["bootstrap"] != _bootstrap_binding(bundle):
        fail("repin authorization original bootstrap binding drifted")
    _reject_secrets(root, "repin authorization")
    return ValidatedAuthorization(
        document=copy.deepcopy(dict(root)),
        sha256=sha256_bytes(raw),
        receipt_directory=resolved,
        not_before=not_before,
        expires_at=expires_at,
    )


def validate_preflight(
    path: Path,
    *,
    bundle: Mapping[str, Any],
    source: Mapping[str, Any],
    now: dt.datetime,
) -> tuple[dict[str, Any], bytes]:
    document, raw = load_json(path)
    root = _exact(
        document,
        {
            "schemaVersion", "preflightType", "status", "authorizationId",
            "observedAt", "account", "source", "bootstrap", "publisher",
            "azureClaim", "projectionSha256",
        },
        "repin preflight",
    )
    projection = {
        key: root[key]
        for key in ("account", "source", "bootstrap", "publisher", "azureClaim")
    }
    if (
        root["schemaVersion"] != 1
        or root["preflightType"] != PREFLIGHT_TYPE
        or root["status"] != "observed-read-only"
        or root["source"] != source
        or root["bootstrap"] != _bootstrap_binding(bundle)
        or root["projectionSha256"] != sha256_bytes(canonical_json_bytes(projection))
        or root["azureClaim"]
        != {
            "resourceId": _claim_resource_id(root["authorizationId"]),
            "httpStatus": 404,
            "state": "absent",
        }
    ):
        fail("repin preflight source/projection bindings are not exact")
    _guid(root["authorizationId"], "repin preflight authorization ID")
    observed_at = parse_time(root["observedAt"], "repin preflight observedAt")
    if observed_at > now or (now - observed_at).total_seconds() > MAX_PREFLIGHT_AGE_SECONDS:
        fail("repin preflight is stale or from the future")
    account = _account(root["account"])
    publisher = root["publisher"]
    if not isinstance(publisher, Mapping):
        fail("repin preflight publisher projection is invalid")
    credentials = publisher.get("federatedIdentityCredentials")
    if not isinstance(credentials, list) or classify_fic_state(
        credentials, bundle["s1Sha"], source["binding"]["s2MergedSha"]
    ) != "s1":
        fail("repin preflight does not bind the exact sole S1 FIC")
    _reject_secrets(root, "repin preflight")
    return copy.deepcopy(dict(root)), raw


def _claim_body(validated: ValidatedAuthorization, preflight: Mapping[str, Any]) -> dict[str, Any]:
    source = preflight["source"]["binding"]
    return {
        "properties": {
            "mode": "Incremental",
            "template": {
                "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "contentVersion": "1.0.0.0",
                "resources": [],
            },
            "parameters": {},
        },
        "tags": {
            "paperdeskBoundary": "private-release-v2-s2-fic-repin",
            "authorizationId": validated.document["authorizationId"],
            "authorizationSha256": validated.sha256,
            "preflightSha256": validated.document["observedPreflight"]["sha256"],
            "s1SourceSha": source["s1MergedSha"],
            "s2SourceSha": source["s2MergedSha"],
        },
    }


def _claim_projection(document: Mapping[str, Any], expected_body: Mapping[str, Any]) -> dict[str, Any]:
    properties = document.get("properties")
    if not isinstance(properties, Mapping):
        fail("global ARM claim response lacks properties")
    if document.get("tags") != expected_body["tags"]:
        fail("global ARM claim tags are not authorization-exact")
    deployment_id = document.get("id")
    deployment_name = document.get("name")
    if (
        not isinstance(deployment_id, str)
        or deployment_id.lower()
        != _claim_resource_id(expected_body["tags"]["authorizationId"]).lower()
        or deployment_name != CLAIM_PREFIX + expected_body["tags"]["authorizationId"]
        or str(document.get("type", "")).lower() != "microsoft.resources/deployments"
        or properties.get("provisioningState") != "Succeeded"
    ):
        fail("global ARM claim identity/readback is not exact")
    projection = {
        "id": deployment_id,
        "name": deployment_name,
        "type": document.get("type"),
        "provisioningState": properties.get("provisioningState"),
        "timestamp": properties.get("timestamp"),
        "tags": copy.deepcopy(expected_body["tags"]),
    }
    _reject_secrets(projection, "global ARM claim projection")
    return projection


class Ledger:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        if self.directory.is_symlink():
            fail("repin ledger directory is a symlink")

    def path(self, name: str) -> Path:
        if not re.fullmatch(r"[0-9]{2}-[a-z0-9-]+\.json", name):
            fail("repin ledger filename is invalid")
        return self.directory / name

    def record(self, name: str, document: Mapping[str, Any]) -> dict[str, Any]:
        raw = canonical_json_bytes(document)
        path = self.path(name)
        if path.exists():
            existing, existing_raw = load_json(path)
            if existing_raw != raw:
                fail(f"repin ledger contains conflicting state: {name}")
            return copy.deepcopy(dict(existing))
        _create_only(path, raw)
        return copy.deepcopy(dict(document))


def _safe_live_fics(
    session: Session, *, application_object_id: str
) -> list[dict[str, Any]]:
    _app_url, fic_url = _graph_urls(application_object_id)
    response = session.request("GET", fic_url)
    return _normalize_fic_list(_response_json(response, {200}, "live FIC inventory"))


def _ensure_global_claim(
    session: Session,
    *,
    validated: ValidatedAuthorization,
    preflight: Mapping[str, Any],
    allow_create: bool,
) -> tuple[dict[str, Any], bool]:
    url = _claim_url(validated.document["authorizationId"])
    body = _claim_body(validated, preflight)
    observed = session.request("GET", url)
    created = False
    if observed.status == 404:
        if not allow_create:
            fail("resume requires the exact existing authorization-specific global ARM claim")
        created_response = session.request(
            "PUT",
            url,
            body=canonical_json_bytes(body),
            headers={"Content-Type": "application/json"},
        )
        created_document = _response_json(created_response, {201}, "global ARM claim create")
        _claim_projection(created_document, body)
        created = True
    elif observed.status != 200:
        fail(f"global ARM claim read returned HTTP {observed.status}")
    readback = session.request("GET", url)
    projection = _claim_projection(
        _response_json(readback, {200}, "global ARM claim readback"), body
    )
    return projection, created


def apply(
    *,
    authorization_path: Path,
    preflight_path: Path,
    bootstrap_authorization_path: Path,
    bootstrap_preflight_path: Path,
    confirmation_phrase: str,
    session: Session,
    now: dt.datetime,
    repo_root: Path = ROOT,
    git_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    bundle = _load_bootstrap_bundle(
        repo_root=repo_root,
        bootstrap_authorization_path=bootstrap_authorization_path,
        bootstrap_preflight_path=bootstrap_preflight_path,
    )
    preflight_document, _preflight_raw_initial = load_json(preflight_path)
    preliminary_source = preflight_document.get("source", {}).get("evidence")
    if not isinstance(preliminary_source, Mapping):
        fail("repin preflight lacks S2 source evidence")
    source = build_source_binding(
        preliminary_source, bundle=bundle, repo_root=repo_root, git_runner=git_runner
    )
    preflight, preflight_raw = validate_preflight(
        preflight_path, bundle=bundle, source=source, now=now
    )
    validated = validate_authorization(
        authorization_path,
        preflight=preflight,
        preflight_raw=preflight_raw,
        bundle=bundle,
        source=source,
        confirmation_phrase=confirmation_phrase,
        now=now,
    )
    account = _account(session.account())
    if account != preflight["account"] or account != validated.document["azure"]:
        fail("live Azure account is not the authorized account")
    ledger = Ledger(validated.receipt_directory)
    if ledger.path("06-terminal-receipt.json").exists():
        fail("repin authorization is already terminal and cannot be replayed")
    local_claim = {
        "schemaVersion": 1,
        "stateType": "paperdesk-private-release-v2-s2-fic-repin-local-claim",
        "authorizationId": validated.document["authorizationId"],
        "authorizationSha256": validated.sha256,
        "authorizationEvidence": copy.deepcopy(dict(validated.document)),
        "preflightSha256": sha256_bytes(preflight_raw),
        "s1SourceSha": bundle["s1Sha"],
        "s2SourceSha": source["binding"]["s2MergedSha"],
    }
    ledger.record("01-local-claim.json", local_claim)
    s1_sha = bundle["s1Sha"]
    s2_sha = source["binding"]["s2MergedSha"]
    application_id = bundle["applicationObjectId"]
    _app_url, fic_url = _graph_urls(application_id)
    credentials = _safe_live_fics(session, application_object_id=application_id)
    initial_state = classify_fic_state(credentials, s1_sha, s2_sha)
    if initial_state == "empty" and not ledger.path("02-global-claim.json").exists():
        fail("unbound empty-state replay is not an authorized same-host resume")
    if initial_state == "s2" and not ledger.path("04-empty-inventory.json").exists():
        fail("unbound S2-state replay is not an authorized same-host resume")
    claim_projection, _claim_created = _ensure_global_claim(
        session,
        validated=validated,
        preflight=preflight,
        allow_create=initial_state == "s1",
    )
    ledger.record(
        "02-global-claim.json",
        {
            "schemaVersion": 1,
            "stateType": "paperdesk-private-release-v2-s2-fic-repin-global-claim",
            "authorizationId": validated.document["authorizationId"],
            "createOrResumeStatus": "authorization-specific-claim-proven-exact",
            "projection": claim_projection,
            "projectionSha256": sha256_bytes(canonical_json_bytes(claim_projection)),
        },
    )
    operations: list[dict[str, Any]] = []
    if initial_state == "s1":
        credential = credentials[0]
        delete_url = fic_url + "/" + urllib.parse.quote(credential["id"], safe="")
        deleted = session.request("DELETE", delete_url)
        if deleted.status != 204 or deleted.body not in {b"", b"null"}:
            fail("exact S1 FIC delete did not return empty HTTP 204")
        operations.append(
            {
                "operationId": "deleteExactS1FederatedIdentityCredential",
                "credentialId": credential["id"],
                "sourceSha": s1_sha,
                "httpStatus": 204,
            }
        )
        ledger.record("03-s1-deleted.json", operations[-1])
        credentials = _safe_live_fics(session, application_object_id=application_id)
        if classify_fic_state(credentials, s1_sha, s2_sha) != "empty":
            fail("publisher FIC inventory did not reach the required empty state")
    elif initial_state == "empty":
        operations.append(
            {
                "operationId": "deleteExactS1FederatedIdentityCredential",
                "credentialId": preflight["publisher"]["federatedIdentityCredentials"][0]["id"],
                "sourceSha": s1_sha,
                "httpStatus": 204,
                "recoveredAfterAmbiguousDelete": True,
            }
        )
    elif initial_state == "s2":
        operations.append(
            {
                "operationId": "deleteExactS1FederatedIdentityCredential",
                "credentialId": preflight["publisher"]["federatedIdentityCredentials"][0]["id"],
                "sourceSha": s1_sha,
                "httpStatus": 204,
                "recoveredAfterAmbiguousDelete": True,
            }
        )
    else:  # pragma: no cover - classify is exhaustive or raises
        fail("unexpected FIC state")
    if initial_state != "s2":
        ledger.record(
            "04-empty-inventory.json",
            {
                "schemaVersion": 1,
                "stateType": "paperdesk-private-release-v2-s2-fic-repin-empty-inventory",
                "authorizationId": validated.document["authorizationId"],
                "applicationObjectId": application_id,
                "federatedIdentityCredentials": [],
                "noOverlap": True,
            },
        )
        create_body = expected_fic(s2_sha)
        created_response = session.request(
            "POST",
            fic_url,
            body=canonical_json_bytes(create_body),
            headers={"Content-Type": "application/json"},
        )
        created_document = _normalize_fic(
            _response_json(created_response, {201}, "exact S2 FIC create")
        )
        if created_document != expected_fic(s2_sha, credential_id=created_document["id"]):
            fail("created S2 FIC response is not exact")
        operations.append(
            {
                "operationId": "createExactSoleS2FederatedIdentityCredential",
                "credentialId": created_document["id"],
                "sourceSha": s2_sha,
                "httpStatus": 201,
            }
        )
    else:
        operations.append(
            {
                "operationId": "createExactSoleS2FederatedIdentityCredential",
                "credentialId": credentials[0]["id"],
                "sourceSha": s2_sha,
                "httpStatus": 201,
                "recoveredAfterAmbiguousCreate": True,
            }
        )
    final_credentials = _safe_live_fics(session, application_object_id=application_id)
    if classify_fic_state(final_credentials, s1_sha, s2_sha) != "s2":
        fail("final publisher credential inventory is not exact sole S2")
    ledger.record(
        "05-s2-created.json",
        {
            "schemaVersion": 1,
            "stateType": "paperdesk-private-release-v2-s2-fic-repin-s2-inventory",
            "authorizationId": validated.document["authorizationId"],
            "federatedIdentityCredentials": final_credentials,
            "noOverlap": True,
        },
    )
    terminal = {
        "schemaVersion": 1,
        "receiptType": RECEIPT_TYPE,
        "status": "succeeded",
        "authorizationId": validated.document["authorizationId"],
        "authorizationSha256": validated.sha256,
        "authorizationEvidence": copy.deepcopy(validated.document),
        "preflight": {
            "sha256": sha256_bytes(preflight_raw),
            "observedAt": preflight["observedAt"],
        },
        "bootstrap": copy.deepcopy(preflight["bootstrap"]),
        "source": copy.deepcopy(source),
        "azureAccount": account,
        "globalClaim": {
            "resourceId": _claim_resource_id(validated.document["authorizationId"]),
            "projection": claim_projection,
            "projectionSha256": sha256_bytes(canonical_json_bytes(claim_projection)),
        },
        "publisher": {
            "applicationObjectId": application_id,
            "applicationClientId": bundle["applicationClientId"],
            "preflightProjection": copy.deepcopy(preflight["publisher"]),
            "initialState": initial_state,
            "emptyIntermediateProved": initial_state != "s2" or ledger.path("04-empty-inventory.json").exists(),
            "finalFederatedIdentityCredentials": final_credentials,
            "noOverlap": True,
        },
        "mutationUniverse": list(MUTATION_UNIVERSE),
        "operations": operations,
        "callerAuthorityGranted": False,
        "activationAuthorityGranted": False,
        "deploymentAuthorityGranted": False,
        "registryAuthorityGranted": False,
        "completedAt": stamp(now),
    }
    _reject_secrets(terminal, "repin terminal receipt")
    validate_terminal_receipt(
        terminal,
        repo_root=repo_root,
        bootstrap_authorization_path=bootstrap_authorization_path,
        bootstrap_preflight_path=bootstrap_preflight_path,
        git_runner=git_runner,
    )
    ledger.record("06-terminal-receipt.json", terminal)
    return terminal


def validate_terminal_receipt(
    receipt: Mapping[str, Any],
    *,
    repo_root: Path,
    bootstrap_authorization_path: Path,
    bootstrap_preflight_path: Path,
    git_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    root = _exact(
        receipt,
        {
            "schemaVersion", "receiptType", "status", "authorizationId",
            "authorizationSha256", "authorizationEvidence", "preflight", "bootstrap", "source",
            "azureAccount", "globalClaim", "publisher", "mutationUniverse",
            "operations", "callerAuthorityGranted", "activationAuthorityGranted",
            "deploymentAuthorityGranted", "registryAuthorityGranted", "completedAt",
        },
        "repin terminal receipt",
    )
    if (
        root["schemaVersion"] != 1
        or root["receiptType"] != RECEIPT_TYPE
        or root["status"] != "succeeded"
        or root["mutationUniverse"] != MUTATION_UNIVERSE
        or any(
            root[field] is not False
            for field in (
                "callerAuthorityGranted", "activationAuthorityGranted",
                "deploymentAuthorityGranted", "registryAuthorityGranted",
            )
        )
    ):
        fail("repin terminal receipt identity/authority boundary is invalid")
    _guid(root["authorizationId"], "repin receipt authorization ID")
    _sha256(root["authorizationSha256"], "repin receipt authorization digest")
    completed_at = parse_time(root["completedAt"], "repin receipt completedAt")
    receipt_preflight = _exact(
        root["preflight"], {"sha256", "observedAt"}, "repin receipt preflight"
    )
    _sha256(receipt_preflight["sha256"], "repin receipt preflight digest")
    preflight_observed_at = parse_time(
        receipt_preflight["observedAt"], "repin receipt preflight observedAt"
    )
    bundle = _load_bootstrap_bundle(
        repo_root=repo_root,
        bootstrap_authorization_path=bootstrap_authorization_path,
        bootstrap_preflight_path=bootstrap_preflight_path,
    )
    source = root["source"]
    if not isinstance(source, Mapping) or set(source) != {"evidence", "binding"}:
        fail("repin receipt source binding is invalid")
    rebuilt = build_source_binding(
        source["evidence"], bundle=bundle, repo_root=repo_root, git_runner=git_runner
    )
    if rebuilt != source or root["bootstrap"] != _bootstrap_binding(bundle):
        fail("repin receipt source/bootstrap binding drifted")
    authorization_evidence = _exact(
        root["authorizationEvidence"],
        {
            "schemaVersion", "authorizationType", "authorizationId", "repository",
            "source", "executor", "bootstrap", "azure", "observedPreflight",
            "validity", "confirmation", "singleUse",
        },
        "embedded repin authorization evidence",
    )
    if (
        root["authorizationSha256"]
        != sha256_bytes(canonical_json_bytes(authorization_evidence))
        or authorization_evidence["schemaVersion"] != 1
        or authorization_evidence["authorizationType"] != AUTHORIZATION_TYPE
        or authorization_evidence["authorizationId"] != root["authorizationId"]
        or authorization_evidence["repository"] != REPOSITORY
        or authorization_evidence["source"] != source["evidence"]
        or authorization_evidence["bootstrap"] != root["bootstrap"]
        or authorization_evidence["azure"] != root["azureAccount"]
    ):
        fail("embedded repin authorization evidence is not receipt-bound")
    _validate_reviewed_source(authorization_evidence["source"])
    embedded_executor = _exact(
        authorization_evidence["executor"], {"path", "sha256"},
        "embedded repin executor",
    )
    if (
        embedded_executor["path"] != "scripts/private_release_v2_fic_repin.py"
        or embedded_executor["sha256"] != sha256_bytes(EXECUTOR_PATH.read_bytes())
    ):
        fail("embedded repin executor evidence drifted")
    embedded_preflight = _exact(
        authorization_evidence["observedPreflight"],
        {"sha256", "observedAt", "maximumAgeSeconds"},
        "embedded repin preflight evidence",
    )
    if (
        embedded_preflight["sha256"] != root["preflight"]["sha256"]
        or embedded_preflight["observedAt"] != root["preflight"]["observedAt"]
        or embedded_preflight["maximumAgeSeconds"] != MAX_PREFLIGHT_AGE_SECONDS
    ):
        fail("embedded repin preflight evidence drifted")
    validity = _exact(
        authorization_evidence["validity"],
        {"notBefore", "expiresAt", "maximumLifetimeSeconds"},
        "embedded repin validity",
    )
    not_before = parse_time(validity["notBefore"], "embedded repin notBefore")
    expires_at = parse_time(validity["expiresAt"], "embedded repin expiresAt")
    if (
        validity["maximumLifetimeSeconds"] != MAX_AUTHORIZATION_SECONDS
        or not 0 < (expires_at - not_before).total_seconds() <= MAX_AUTHORIZATION_SECONDS
        or not not_before <= completed_at <= expires_at
        or preflight_observed_at > completed_at
    ):
        fail("embedded repin validity/receipt time is not finite and ordered")
    confirmation = _exact(
        authorization_evidence["confirmation"],
        {"encoding", "phraseSha256"},
        "embedded repin confirmation",
    )
    if (
        confirmation["encoding"] != "utf-8-exact-no-newline"
        or not SHA256.fullmatch(str(confirmation["phraseSha256"]))
    ):
        fail("embedded repin confirmation binding is invalid")
    single = _exact(
        authorization_evidence["singleUse"],
        {"required", "receiptDirectory", "azureClaimResourceId"},
        "embedded repin single-use binding",
    )
    if (
        single["required"] is not True
        or single["azureClaimResourceId"] != _claim_resource_id(root["authorizationId"])
        or Path(single["receiptDirectory"]).name
        != CLAIM_PREFIX + root["authorizationId"]
    ):
        fail("embedded repin single-use binding drifted")
    publisher = _exact(
        root["publisher"],
        {
            "applicationObjectId", "applicationClientId", "preflightProjection", "initialState",
            "emptyIntermediateProved", "finalFederatedIdentityCredentials", "noOverlap",
        },
        "repin receipt publisher",
    )
    application_url, fic_url = _graph_urls(bundle["applicationObjectId"])
    preflight_publisher = _exact(
        publisher["preflightProjection"],
        {
            "applicationQuery", "application", "federatedIdentityCredentialsQuery",
            "federatedIdentityCredentials",
        },
        "repin receipt publisher preflight projection",
    )
    preflight_application = _exact(
        preflight_publisher["application"],
        {"id", "appId", "displayName", "passwordCredentials", "keyCredentials"},
        "repin receipt publisher application",
    )
    initial_credentials = preflight_publisher["federatedIdentityCredentials"]
    if (
        publisher["applicationObjectId"] != bundle["applicationObjectId"]
        or publisher["applicationClientId"] != bundle["applicationClientId"]
        or preflight_publisher["applicationQuery"] != application_url
        or preflight_publisher["federatedIdentityCredentialsQuery"] != fic_url
        or preflight_application["id"] != bundle["applicationObjectId"]
        or preflight_application["appId"] != bundle["applicationClientId"]
        or not isinstance(preflight_application["displayName"], str)
        or not preflight_application["displayName"]
        or preflight_application["passwordCredentials"] != []
        or preflight_application["keyCredentials"] != []
        or not isinstance(initial_credentials, list)
        or classify_fic_state(
            initial_credentials,
            bundle["s1Sha"],
            source["binding"]["s2MergedSha"],
        ) != "s1"
        or publisher["initialState"] not in {"s1", "empty", "s2"}
        or publisher["emptyIntermediateProved"] is not True
        or publisher["noOverlap"] is not True
        or classify_fic_state(
            publisher["finalFederatedIdentityCredentials"],
            bundle["s1Sha"],
            source["binding"]["s2MergedSha"],
        ) != "s2"
    ):
        fail("repin receipt does not prove exact sole-S2 final state")
    operations = root["operations"]
    if (
        not isinstance(operations, list)
        or [item.get("operationId") for item in operations]
        != MUTATION_UNIVERSE[1:]
    ):
        fail("repin receipt operation universe is not exact")
    initial_fic_id = initial_credentials[0]["id"]
    final_fic_id = publisher["finalFederatedIdentityCredentials"][0]["id"]
    delete_operation = operations[0]
    create_operation = operations[1]
    expected_delete_keys = {"operationId", "credentialId", "sourceSha", "httpStatus"}
    if publisher["initialState"] in {"empty", "s2"}:
        expected_delete_keys.add("recoveredAfterAmbiguousDelete")
    expected_create_keys = {"operationId", "credentialId", "sourceSha", "httpStatus"}
    if publisher["initialState"] == "s2":
        expected_create_keys.add("recoveredAfterAmbiguousCreate")
    if (
        not isinstance(delete_operation, Mapping)
        or set(delete_operation) != expected_delete_keys
        or delete_operation["operationId"] != MUTATION_UNIVERSE[1]
        or delete_operation["credentialId"] != initial_fic_id
        or delete_operation["sourceSha"] != bundle["s1Sha"]
        or delete_operation["httpStatus"] != 204
        or (
            "recoveredAfterAmbiguousDelete" in delete_operation
            and delete_operation["recoveredAfterAmbiguousDelete"] is not True
        )
        or not isinstance(create_operation, Mapping)
        or set(create_operation) != expected_create_keys
        or create_operation["operationId"] != MUTATION_UNIVERSE[2]
        or create_operation["credentialId"] != final_fic_id
        or create_operation["sourceSha"] != source["binding"]["s2MergedSha"]
        or create_operation["httpStatus"] != 201
        or (
            "recoveredAfterAmbiguousCreate" in create_operation
            and create_operation["recoveredAfterAmbiguousCreate"] is not True
        )
    ):
        fail("repin receipt operation evidence is not exact")
    global_claim = _exact(
        root["globalClaim"],
        {"resourceId", "projection", "projectionSha256"},
        "repin receipt global claim",
    )
    claim_projection = _exact(
        global_claim["projection"],
        {"id", "name", "type", "provisioningState", "timestamp", "tags"},
        "repin receipt global claim projection",
    )
    expected_claim_tags = {
        "paperdeskBoundary": "private-release-v2-s2-fic-repin",
        "authorizationId": root["authorizationId"],
        "authorizationSha256": root["authorizationSha256"],
        "preflightSha256": receipt_preflight["sha256"],
        "s1SourceSha": bundle["s1Sha"],
        "s2SourceSha": source["binding"]["s2MergedSha"],
    }
    if (
        global_claim["resourceId"] != _claim_resource_id(root["authorizationId"])
        or not isinstance(claim_projection["id"], str)
        or claim_projection["id"].lower()
        != _claim_resource_id(root["authorizationId"]).lower()
        or claim_projection["name"] != CLAIM_PREFIX + root["authorizationId"]
        or str(claim_projection["type"]).lower() != "microsoft.resources/deployments"
        or claim_projection["provisioningState"] != "Succeeded"
        or claim_projection["tags"] != expected_claim_tags
        or global_claim["projectionSha256"]
        != sha256_bytes(canonical_json_bytes(claim_projection))
    ):
        fail("repin receipt global claim binding is invalid")
    parse_time(claim_projection["timestamp"], "repin receipt global claim timestamp")
    _account(root["azureAccount"])
    _reject_secrets(root, "repin terminal receipt")
    if canonical_json_bytes(root) != canonical_json_bytes(receipt):
        fail("repin terminal receipt changed during validation")
    return copy.deepcopy(dict(root))


def describe() -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "status": "credential-free-no-Azure-transport-constructed",
        "operation": "repin exact sole publisher FIC from accepted S1 to accepted evidence-only S2",
        "mutationUniverse": list(MUTATION_UNIVERSE),
        "noOverlap": True,
        "sourceRequirements": {
            "trustedReviewers": copy.deepcopy(TRUSTED_REVIEWERS),
            "requiredCheck": "test",
            "requiredS2Paths": [
                *receipts.load_model()["requiredS2EvidencePaths"],
                receipts.load_model()["requiredS2TerminalBundlePath"],
            ],
        },
        "schemas": [
            str(PREFLIGHT_SCHEMA_PATH.relative_to(ROOT)).replace("\\", "/"),
            str(AUTHORIZATION_SCHEMA_PATH.relative_to(ROOT)).replace("\\", "/"),
        ],
    }


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("describe")
    observe_parser = commands.add_parser("observe")
    observe_parser.add_argument("--authorization-id", required=True)
    observe_parser.add_argument("--source-evidence", required=True, type=Path)
    observe_parser.add_argument("--bootstrap-authorization", required=True, type=Path)
    observe_parser.add_argument("--bootstrap-preflight", required=True, type=Path)
    observe_parser.add_argument("--preflight-output", required=True, type=Path)
    observe_parser.add_argument("--authorization-template-output", required=True, type=Path)
    observe_parser.add_argument("--receipt-directory", required=True, type=Path)
    apply_parser = commands.add_parser("apply")
    apply_parser.add_argument("--authorization", required=True, type=Path)
    apply_parser.add_argument("--preflight", required=True, type=Path)
    apply_parser.add_argument("--bootstrap-authorization", required=True, type=Path)
    apply_parser.add_argument("--bootstrap-preflight", required=True, type=Path)
    validate_parser = commands.add_parser("validate-receipt")
    validate_parser.add_argument("--receipt", required=True, type=Path)
    validate_parser.add_argument("--bootstrap-authorization", required=True, type=Path)
    validate_parser.add_argument("--bootstrap-preflight", required=True, type=Path)
    args = parser.parse_args(argv)
    command = args.command or "describe"
    if command == "describe":
        sys.stdout.buffer.write(canonical_json_bytes(describe()))
        return 0
    if command == "observe":
        source, _ = load_json(args.source_evidence)
        session = AzureCliSession()
        result = observe(
            authorization_id=args.authorization_id,
            source_evidence=source,
            bootstrap_authorization_path=args.bootstrap_authorization,
            bootstrap_preflight_path=args.bootstrap_preflight,
            preflight_output=args.preflight_output.resolve(),
            template_output=args.authorization_template_output.resolve(),
            receipt_directory=args.receipt_directory.resolve(),
            session=session,
            now=dt.datetime.now(dt.timezone.utc),
        )
        sys.stdout.buffer.write(canonical_json_bytes({
            "status": "observed-read-only",
            "preflightSha256": sha256_bytes(canonical_json_bytes(result["preflight"])),
            "authorizationTemplateSha256": sha256_bytes(canonical_json_bytes(result["authorizationTemplate"])),
        }))
        return 0
    if command == "apply":
        phrase = sys.stdin.readline()
        if not phrase or not phrase.endswith("\n") or sys.stdin.read(1):
            fail("confirmation input must be exactly one newline-terminated line")
        phrase = phrase[:-1]
        # Keep the concrete transport lazy until ``apply`` has validated the
        # canonical authorization, preflight, source and confirmation phrase.
        # The wrapper also rejects every 3xx response at the privilege boundary.
        session = AzureCliSession()
        result = apply(
            authorization_path=args.authorization,
            preflight_path=args.preflight,
            bootstrap_authorization_path=args.bootstrap_authorization,
            bootstrap_preflight_path=args.bootstrap_preflight,
            confirmation_phrase=phrase,
            session=session,
            now=dt.datetime.now(dt.timezone.utc),
        )
        sys.stdout.buffer.write(canonical_json_bytes({
            "status": result["status"],
            "authorizationId": result["authorizationId"],
            "terminalReceiptSha256": sha256_bytes(canonical_json_bytes(result)),
        }))
        return 0
    if command == "validate-receipt":
        value, _ = load_json(args.receipt)
        validated = validate_terminal_receipt(
            value,
            repo_root=ROOT,
            bootstrap_authorization_path=args.bootstrap_authorization,
            bootstrap_preflight_path=args.bootstrap_preflight,
        )
        sys.stdout.buffer.write(canonical_json_bytes({
            "status": "valid",
            "sha256": sha256_bytes(canonical_json_bytes(validated)),
        }))
        return 0
    fail("unsupported command")


if __name__ == "__main__":
    try:
        raise SystemExit(_main())
    except RepinError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
