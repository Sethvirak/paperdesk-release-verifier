import copy
import datetime as dt
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from scripts import private_release_v2_bootstrap as bootstrap
from scripts import private_release_v2_fic_repin as repin
from tests.test_private_release_v2_bootstrap import (
    AUTH_ID as BOOTSTRAP_AUTH_ID,
    build_complete_terminal_receipt_input_fixture,
)


S2_HEAD = "5" * 40
S2_MERGE = "6" * 40
S2_TREE = "7" * 40
REP_IN_AUTH_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
PHRASE = "Authorize exact sole S2 publisher FIC repin."
NOW = dt.datetime(2026, 8, 30, 5, 0, tzinfo=dt.timezone.utc)
S1_FIC_ID = "11111111-1111-4111-8111-111111111111"
S2_FIC_ID = "22222222-2222-4222-8222-222222222222"


def stamp(value):
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def source_evidence(s1_sha):
    pushed = NOW - dt.timedelta(minutes=40)
    first = NOW - dt.timedelta(minutes=35)
    second = NOW - dt.timedelta(minutes=34)
    checked = NOW - dt.timedelta(minutes=33)
    merged = NOW - dt.timedelta(minutes=30)
    return {
        "reviewedHead": {
            "commitSha": S2_HEAD,
            "treeSha": S2_TREE,
            "signatureVerified": True,
            "signingPrincipal": repin.SIGNING_PRINCIPAL,
            "signingKeyFingerprint": repin.SIGNING_FINGERPRINT,
            "pullRequestNumber": 19,
            "pullRequestUrl": f"https://github.com/{repin.REPOSITORY}/pull/19",
            "reviewDecision": "APPROVED",
            "requiredApprovals": 2,
            "pushedAt": stamp(pushed),
            "reviews": [
                {
                    "login": "jecebella168-cmyk",
                    "userId": 316989178,
                    "reviewId": 501,
                    "state": "APPROVED",
                    "submittedAt": stamp(first),
                    "commitSha": S2_HEAD,
                },
                {
                    "login": "jecebella169-cmyk",
                    "userId": 322025901,
                    "reviewId": 502,
                    "state": "APPROVED",
                    "submittedAt": stamp(second),
                    "commitSha": S2_HEAD,
                },
            ],
            "requiredCheck": {
                "name": "test",
                "runId": "9001",
                "headSha": S2_HEAD,
                "conclusion": "success",
                "completedAt": stamp(checked),
            },
        },
        "mergedMain": {
            "commitSha": S2_MERGE,
            "treeSha": S2_TREE,
            "soleParentSha": s1_sha,
            "treeEqualsReviewedHead": True,
            "githubVerificationVerified": True,
            "githubVerificationReason": "valid",
            "mergedPullRequestNumber": 19,
            "mergedPullRequestUrl": f"https://github.com/{repin.REPOSITORY}/pull/19",
            "mergedAt": stamp(merged),
            "verificationApiUrl": (
                f"https://api.github.com/repos/{repin.REPOSITORY}/commits/{S2_MERGE}"
            ),
            "verificationRetrievedAt": stamp(merged + dt.timedelta(minutes=1)),
        },
    }


class FakeGit:
    def __init__(self, *, s1_sha, paths, extra_path=None):
        self.s1_sha = s1_sha
        self.paths = list(paths) + ([extra_path] if extra_path else [])

    def __call__(self, command, **kwargs):
        args = command[1:]
        joined = " ".join(args)
        output = None
        if args[:2] == ["status", "--porcelain=v1"]:
            output = ""
        elif args[:2] == ["symbolic-ref", "--short"]:
            output = "main\n"
        elif args[:3] == ["config", "--get", "remote.origin.url"]:
            output = "https://github.com/Sethvirak/paperdesk-release-verifier.git\n"
        elif args[:2] == ["rev-parse", "HEAD"]:
            output = S2_MERGE + "\n"
        elif args[:2] == ["rev-parse", "refs/remotes/origin/main"]:
            output = S2_MERGE + "\n"
        elif args[:2] == ["rev-parse", "HEAD^{tree}"]:
            output = S2_TREE + "\n"
        elif args[:4] == ["rev-list", "--parents", "-n", "1"]:
            output = f"{S2_MERGE} {self.s1_sha}\n"
        elif "verify-commit" in args:
            output = ""
        elif "--format=%G?%x00%GS%x00%GK" in args:
            output = (
                "G\x00"
                + repin.SIGNING_PRINCIPAL
                + "\x00"
                + repin.SIGNING_FINGERPRINT
                + "\n"
            )
        elif args[:2] == ["cat-file", "-e"]:
            output = ""
        elif args[:2] == ["diff", "--name-only"]:
            output = "\n".join(self.paths) + "\n"
        elif args[:2] == ["diff", "--name-status"]:
            output = "\n".join(f"M\t{path}" for path in self.paths) + "\n"
        if output is None:
            raise AssertionError(f"unexpected git command: {joined}")
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")


class FakeSession:
    def __init__(self, bundle, s2_sha, *, crash_after=None):
        self.bundle = bundle
        self.s2_sha = s2_sha
        self.fics = [repin.expected_fic(bundle["s1Sha"], credential_id=S1_FIC_ID)]
        self.claim = None
        self.calls = []
        self.crash_after = crash_after
        self.crashed = False
        self.last_mutation = None

    def account(self):
        return {
            "cloud": "AzureCloud",
            "subscriptionId": repin.SUBSCRIPTION,
            "tenantId": repin.TENANT,
            "accountId": "operator@example.invalid",
            "accountObjectId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "accountType": "user",
        }

    @staticmethod
    def response(status, value=None):
        body = b"" if value is None else repin.canonical_json_bytes(value)
        return repin.Response(status, body, {"Content-Type": "application/json"})

    def request(self, method, url, *, body=None, headers=None):
        self.calls.append((method, url))
        if "management.azure.com" in url:
            if method == "GET":
                return self.response(404 if self.claim is None else 200, self.claim)
            if method == "PUT":
                submitted = json.loads(body.decode("utf-8"))
                auth_id = submitted["tags"]["authorizationId"]
                self.claim = {
                    "id": repin._claim_resource_id(auth_id),
                    "name": repin.CLAIM_PREFIX + auth_id,
                    "type": "Microsoft.Resources/deployments",
                    "tags": submitted["tags"],
                    "properties": {
                        "provisioningState": "Succeeded",
                        "timestamp": stamp(NOW),
                    },
                }
                return self.response(201, self.claim)
        app_url, fic_url = repin._graph_urls(self.bundle["applicationObjectId"])
        if method == "GET" and url == app_url:
            return self.response(
                200,
                {
                    "id": self.bundle["applicationObjectId"],
                    "appId": self.bundle["applicationClientId"],
                    "displayName": "paperdesk-release-publisher-v2-9c4e0d0d",
                    "passwordCredentials": [],
                    "keyCredentials": [],
                },
            )
        if method == "GET" and url == fic_url:
            if (
                self.crash_after is not None
                and self.crash_after == self.last_mutation
                and not self.crashed
            ):
                self.crashed = True
                raise repin.RepinError(f"fixture crash after {self.last_mutation}")
            return self.response(200, {"value": copy.deepcopy(self.fics)})
        if method == "DELETE" and url.startswith(fic_url + "/"):
            self.fics = []
            self.last_mutation = "delete"
            return self.response(204)
        if method == "POST" and url == fic_url:
            if self.fics:
                raise AssertionError("overlap attempted")
            created = {"id": S2_FIC_ID, **json.loads(body.decode("utf-8"))}
            self.fics = [created]
            self.last_mutation = "create"
            return self.response(201, created)
        raise AssertionError(f"unexpected request: {method} {url}")


class Fixture:
    def __init__(self, base):
        self.base = Path(base)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        receipt_dir = self.base / f"paperdesk-private-release-v2-bootstrap-{BOOTSTRAP_AUTH_ID}"
        self.fixture = build_complete_terminal_receipt_input_fixture(receipt_dir)
        complete = self.fixture["completeReceipt"]
        for relative, raw in {
            **complete["s2EvidenceFiles"],
            **complete["s2TerminalBundle"],
        }.items():
            path = self.repo / Path(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.bootstrap_authorization = self.base / "bootstrap-authorization.json"
        self.bootstrap_authorization.write_bytes(
            bootstrap.canonical_json_bytes(self.fixture["authorization"])
        )
        projection = self.fixture["preflightProjection"]
        preflight = {
            "schemaVersion": 1,
            "status": "observed-read-only",
            "observedAt": self.fixture["authorization"]["observedPreflight"]["observedAt"],
            "projection": projection,
            "projectionSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(projection)
            ),
        }
        self.bootstrap_preflight = self.base / "bootstrap-preflight.json"
        self.bootstrap_preflight.write_bytes(bootstrap.canonical_json_bytes(preflight))
        self.bundle = repin._load_bootstrap_bundle(
            repo_root=self.repo,
            bootstrap_authorization_path=self.bootstrap_authorization,
            bootstrap_preflight_path=self.bootstrap_preflight,
        )
        self.source_evidence = source_evidence(self.bundle["s1Sha"])
        self.git = FakeGit(s1_sha=self.bundle["s1Sha"], paths=self.bundle["paths"])
        self.source = repin.build_source_binding(
            self.source_evidence,
            bundle=self.bundle,
            repo_root=self.repo,
            git_runner=self.git,
        )
        self.session = FakeSession(self.bundle, S2_MERGE)
        self.preflight = repin.build_preflight(
            authorization_id=REP_IN_AUTH_ID,
            source=self.source,
            bundle=self.bundle,
            session=self.session,
            now=NOW,
        )
        self.preflight_path = self.base / "repin-preflight.json"
        self.preflight_path.write_bytes(repin.canonical_json_bytes(self.preflight))
        self.receipt_directory = self.base / f"{repin.CLAIM_PREFIX}{REP_IN_AUTH_ID}"
        template = repin.build_authorization_template(
            self.preflight, receipt_directory=self.receipt_directory
        )
        self.authorization = {
            "schemaVersion": 1,
            "authorizationType": repin.AUTHORIZATION_TYPE,
            "authorizationId": REP_IN_AUTH_ID,
            "repository": repin.REPOSITORY,
            "source": copy.deepcopy(template["source"]),
            "executor": copy.deepcopy(template["executor"]),
            "bootstrap": copy.deepcopy(template["bootstrap"]),
            "azure": copy.deepcopy(template["azure"]),
            "observedPreflight": copy.deepcopy(template["observedPreflight"]),
            "validity": {
                "notBefore": stamp(NOW - dt.timedelta(minutes=1)),
                "expiresAt": stamp(NOW + dt.timedelta(minutes=29)),
                "maximumLifetimeSeconds": repin.MAX_AUTHORIZATION_SECONDS,
            },
            "confirmation": {
                "encoding": "utf-8-exact-no-newline",
                "phraseSha256": repin.sha256_bytes(PHRASE.encode("utf-8")),
            },
            "singleUse": copy.deepcopy(template["singleUse"]),
        }
        self.authorization_path = self.base / "repin-authorization.json"
        self.authorization_path.write_bytes(repin.canonical_json_bytes(self.authorization))

    def apply(self, session=None):
        return repin.apply(
            authorization_path=self.authorization_path,
            preflight_path=self.preflight_path,
            bootstrap_authorization_path=self.bootstrap_authorization,
            bootstrap_preflight_path=self.bootstrap_preflight,
            confirmation_phrase=PHRASE,
            session=session or self.session,
            now=NOW,
            repo_root=self.repo,
            git_runner=self.git,
        )


class FicRepinTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fx = Fixture(self.temp.name)

    def test_describe_is_credential_free(self):
        result = repin.describe()
        self.assertEqual(
            result["status"], "credential-free-no-Azure-transport-constructed"
        )
        self.assertEqual(result["mutationUniverse"], repin.MUTATION_UNIVERSE)

    def test_authorization_template_is_deliberately_non_executable(self):
        template = repin.build_authorization_template(
            self.fx.preflight, receipt_directory=self.fx.receipt_directory
        )
        self.assertEqual(
            template["status"],
            "NON_EXECUTABLE_REQUIRES_EXPLICIT_AUTHORIZATION_CEREMONY",
        )
        self.assertEqual(
            template["missingExecutableFields"],
            ["authorizationType", "validity", "confirmation"],
        )
        for field in template["missingExecutableFields"]:
            self.assertNotIn(field, template)

    def test_observe_is_read_only_and_create_only_locally(self):
        session = FakeSession(self.fx.bundle, S2_MERGE)
        preflight_output = self.fx.base / "observed-repin-preflight.json"
        template_output = self.fx.base / "observed-repin-template.json"
        result = repin.observe(
            authorization_id=REP_IN_AUTH_ID,
            source_evidence=self.fx.source_evidence,
            bootstrap_authorization_path=self.fx.bootstrap_authorization,
            bootstrap_preflight_path=self.fx.bootstrap_preflight,
            preflight_output=preflight_output.resolve(),
            template_output=template_output.resolve(),
            receipt_directory=(self.fx.base / "fresh-receipts").resolve(),
            session=session,
            now=NOW,
            repo_root=self.fx.repo,
            git_runner=self.fx.git,
        )
        self.assertTrue(all(method == "GET" for method, _ in session.calls))
        self.assertEqual(
            preflight_output.read_bytes(),
            repin.canonical_json_bytes(result["preflight"]),
        )
        self.assertEqual(
            template_output.read_bytes(),
            repin.canonical_json_bytes(result["authorizationTemplate"]),
        )
        calls_before_conflict = list(session.calls)
        with self.assertRaisesRegex(repin.RepinError, "distinct absent absolute"):
            repin.observe(
                authorization_id=REP_IN_AUTH_ID,
                source_evidence=self.fx.source_evidence,
                bootstrap_authorization_path=self.fx.bootstrap_authorization,
                bootstrap_preflight_path=self.fx.bootstrap_preflight,
                preflight_output=preflight_output.resolve(),
                template_output=template_output.resolve(),
                receipt_directory=(self.fx.base / "fresh-receipts").resolve(),
                session=session,
                now=NOW,
                repo_root=self.fx.repo,
                git_runner=self.fx.git,
            )
        self.assertEqual(session.calls, calls_before_conflict)

    def test_production_transport_rejects_redirects(self):
        class RedirectTransport:
            @staticmethod
            def request(method, url, *, body=None, headers=None):
                return repin.Response(302, b"", {"Location": "https://example.invalid/"})

        session = repin.AzureCliSession()
        session._account = dict(self.fx.session.account())
        session._session = RedirectTransport()
        with self.assertRaisesRegex(repin.RepinError, "redirected"):
            session.request("GET", "https://graph.microsoft.com/v1.0/applications/x")

    def test_wrong_confirmation_fails_before_any_mutation(self):
        before = list(self.fx.session.calls)
        with self.assertRaisesRegex(repin.RepinError, "confirmation phrase"):
            repin.apply(
                authorization_path=self.fx.authorization_path,
                preflight_path=self.fx.preflight_path,
                bootstrap_authorization_path=self.fx.bootstrap_authorization,
                bootstrap_preflight_path=self.fx.bootstrap_preflight,
                confirmation_phrase="wrong",
                session=self.fx.session,
                now=NOW,
                repo_root=self.fx.repo,
                git_runner=self.fx.git,
            )
        self.assertEqual(self.fx.session.calls, before)

    def test_happy_path_never_overlaps_and_is_single_use(self):
        terminal = self.fx.apply()
        self.assertEqual(terminal["status"], "succeeded")
        self.assertTrue(terminal["publisher"]["noOverlap"])
        mutation_methods = [method for method, _ in self.fx.session.calls if method != "GET"]
        self.assertEqual(mutation_methods, ["PUT", "DELETE", "POST"])
        with self.assertRaisesRegex(repin.RepinError, "already terminal"):
            self.fx.apply()

    def test_terminal_semantic_evidence_cannot_be_rehashed_or_relabelled(self):
        terminal = self.fx.apply()
        forged_claim = copy.deepcopy(terminal)
        forged_claim["globalClaim"]["projection"]["tags"]["s1SourceSha"] = "9" * 40
        forged_claim["globalClaim"]["projectionSha256"] = repin.sha256_bytes(
            repin.canonical_json_bytes(forged_claim["globalClaim"]["projection"])
        )
        forged_operation = copy.deepcopy(terminal)
        forged_operation["operations"][0]["httpStatus"] = 200
        forged_credential_posture = copy.deepcopy(terminal)
        forged_credential_posture["publisher"]["preflightProjection"]["application"][
            "keyCredentials"
        ] = [{"keyId": "forged"}]
        for forged in (forged_claim, forged_operation, forged_credential_posture):
            with self.subTest(forged=forged):
                with self.assertRaises(repin.RepinError):
                    repin.validate_terminal_receipt(
                        forged,
                        repo_root=self.fx.repo,
                        bootstrap_authorization_path=self.fx.bootstrap_authorization,
                        bootstrap_preflight_path=self.fx.bootstrap_preflight,
                        git_runner=self.fx.git,
                    )

    def test_unbound_empty_or_s2_replay_fails_before_external_mutation(self):
        empty = FakeSession(self.fx.bundle, S2_MERGE)
        empty.fics = []
        with self.assertRaisesRegex(repin.RepinError, "unbound empty-state replay"):
            self.fx.apply(empty)
        self.assertFalse(any(method != "GET" for method, _ in empty.calls))

        terminal = self.fx.apply()
        self.assertEqual(terminal["status"], "succeeded")
        shutil.rmtree(self.fx.receipt_directory)
        before_mutations = sum(
            1 for method, _ in self.fx.session.calls if method != "GET"
        )
        with self.assertRaisesRegex(repin.RepinError, "unbound S2-state replay"):
            self.fx.apply()
        after_mutations = sum(
            1 for method, _ in self.fx.session.calls if method != "GET"
        )
        self.assertEqual(after_mutations, before_mutations)

    def test_crash_after_delete_resumes_from_empty_without_second_delete(self):
        session = FakeSession(self.fx.bundle, S2_MERGE, crash_after="delete")
        with self.assertRaisesRegex(repin.RepinError, "fixture crash after delete"):
            self.fx.apply(session)
        terminal = self.fx.apply(session)
        self.assertEqual(terminal["publisher"]["initialState"], "empty")
        self.assertEqual(sum(1 for method, _ in session.calls if method == "DELETE"), 1)
        self.assertEqual(sum(1 for method, _ in session.calls if method == "POST"), 1)

    def test_crash_after_create_resumes_from_exact_s2_without_second_create(self):
        session = FakeSession(self.fx.bundle, S2_MERGE, crash_after="create")
        with self.assertRaisesRegex(repin.RepinError, "fixture crash after create"):
            self.fx.apply(session)
        terminal = self.fx.apply(session)
        self.assertEqual(terminal["publisher"]["initialState"], "s2")
        self.assertEqual(sum(1 for method, _ in session.calls if method == "POST"), 1)

    def test_old_extra_overlap_and_s1_equals_s2_fail_closed(self):
        s1 = self.fx.bundle["s1Sha"]
        exact = repin.expected_fic(s1, credential_id=S1_FIC_ID)
        extra = repin.expected_fic(S2_MERGE, credential_id=S2_FIC_ID)
        with self.assertRaisesRegex(repin.RepinError, "overlapping or extra"):
            repin.classify_fic_state([exact, extra], s1, S2_MERGE)
        wrong = copy.deepcopy(exact)
        wrong["claimsMatchingExpression"]["value"] += " and claims['actor']='other'"
        with self.assertRaisesRegex(repin.RepinError, "third state"):
            repin.classify_fic_state([wrong], s1, S2_MERGE)
        with self.assertRaisesRegex(repin.RepinError, "S1 and S2 must differ"):
            repin.classify_fic_state([exact], s1, s1)

    def test_extra_s2_source_path_is_rejected(self):
        dirty_git = FakeGit(
            s1_sha=self.fx.bundle["s1Sha"],
            paths=self.fx.bundle["paths"],
            extra_path="scripts/evil.py",
        )
        with self.assertRaisesRegex(repin.RepinError, "exactly the six evidence paths"):
            repin.build_source_binding(
                self.fx.source_evidence,
                bundle=self.fx.bundle,
                repo_root=self.fx.repo,
                git_runner=dirty_git,
            )

    def test_altered_s2_evidence_is_rejected(self):
        path = self.fx.repo / Path(*self.fx.bundle["paths"][0].split("/"))
        document = json.loads(path.read_text(encoding="utf-8"))
        document["status"] = "tampered"
        path.write_bytes(repin.canonical_json_bytes(document))
        with self.assertRaises(repin.RepinError):
            repin._load_bootstrap_bundle(
                repo_root=self.fx.repo,
                bootstrap_authorization_path=self.fx.bootstrap_authorization,
                bootstrap_preflight_path=self.fx.bootstrap_preflight,
            )


if __name__ == "__main__":
    unittest.main()
