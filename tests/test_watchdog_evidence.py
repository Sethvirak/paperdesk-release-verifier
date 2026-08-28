import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import unittest
import urllib.parse


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import watchdog_evidence as evidence


WORKFLOW_SHA = "b" * 40
CLAIM_ID = "12345678-1234-4123-8123-123456789abc"


def decision_receipt():
    return {
        "schemaVersion": 2,
        "receiptType": "watchdog-decision",
        "decision": "dispatch-rollback",
        "sourceRepository": evidence.SOURCE_REPOSITORY,
        "candidateSha": "a" * 40,
        "candidateRunId": "10",
        "candidateRunAttempt": "1",
        "expectedCurrentLiveSha": "a" * 40,
        "watchdogRunId": "30",
        "watchdogRunAttempt": "1",
        "observedStateSha256": "d" * 64,
        "decidedAt": "2026-08-23T03:00:00.000Z",
    }


def initial_baseline():
    source_sha = "9" * 40
    return {
        "schemaVersion": 2,
        "receiptSha256": "1" * 64,
        "evidencePath": "v2/baselines/99/1/initial.json",
        "sourceSha": source_sha,
        "sourceRunId": "88",
        "sourceRunAttempt": "1",
        "acceptanceRunId": "99",
        "acceptanceRunAttempt": "1",
        "acceptedReleaseManifestSha256": "2" * 64,
        "acceptedReleasePrefix": f"v1/releases/{source_sha}/88/99/",
        "reviewWorkflowRef": evidence.BASELINE_WORKFLOW_REF,
        "reviewWorkflowSha": WORKFLOW_SHA,
        "reviewRunId": "700",
        "reviewRunAttempt": "1",
        "reviewEnvironment": evidence.BASELINE_ENVIRONMENT,
        "preparedAt": "2026-08-23T03:00:00.000Z",
    }


def claim_response():
    return {
        "status": "claimed",
        "claimId": CLAIM_ID,
        "dispatchGuardGeneration": 7,
        "decisionReceiptSha256": "e" * 64,
        "decisionEvidenceETag": '"decision-etag"',
    }


def dispatch_response():
    return {
        "status": "requested",
        "claimId": CLAIM_ID,
        "dispatchGuardGeneration": 7,
        "attemptReceiptSha256": "f" * 64,
        "workflowRunId": "303",
        "workflowRunApiUrl": (
            "https://api.github.com/repos/Sethvirak/MasterDataStructure/actions/runs/303"
        ),
        "workflowRunHtmlUrl": (
            "https://github.com/Sethvirak/MasterDataStructure/actions/runs/303"
        ),
        "githubRequestId": "ABCD:1234",
        "dispatchReceiptSha256": "9" * 64,
        "dispatchEvidenceETag": '"dispatch-etag"',
        "dispatchEvidenceVersionId": "2026-08-23T03:00:00.0000000Z",
    }


def token_claims(*, observed=None):
    epoch = int((observed or datetime.now(timezone.utc)).timestamp())
    return {
        "aud": evidence.OIDC_AUDIENCE,
        "iss": evidence.OIDC_ISSUER,
        "sub": (
            f"repo:{evidence.WATCHDOG_REPOSITORY}:environment:"
            f"{evidence.WATCHDOG_ENVIRONMENT}"
        ),
        "repository": evidence.WATCHDOG_REPOSITORY,
        "repository_owner": evidence.WATCHDOG_REPOSITORY_OWNER,
        "repository_id": evidence.WATCHDOG_REPOSITORY_ID,
        "repository_owner_id": evidence.WATCHDOG_REPOSITORY_OWNER_ID,
        "sha": WORKFLOW_SHA,
        "workflow_sha": WORKFLOW_SHA,
        "ref": "refs/heads/main",
        "workflow_ref": evidence.WATCHDOG_WORKFLOW_REF,
        "run_id": "30",
        "run_attempt": "1",
        "environment": evidence.WATCHDOG_ENVIRONMENT,
        "event_name": "schedule",
        "iat": epoch - 10,
        "nbf": epoch - 10,
        "exp": epoch + 590,
    }


def encode_token(claims):
    def part(value):
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return f"{part({'alg': 'RS256', 'kid': 'test'})}.{part(claims)}.signature"


class Headers(dict):
    def get_all(self, name):
        value = self.get(name)
        return [value] if value is not None else None


class FakeResponse:
    def __init__(
        self,
        status,
        url,
        document,
        headers=None,
        *,
        raw_body=None,
        include_content_length=True,
    ):
        self.status = status
        self._url = url
        self._body = evidence.canonical_json(document) if raw_body is None else raw_body
        response_headers = {
            "Content-Type": "application/json",
            "Content-Encoding": "identity",
        }
        if include_content_length:
            response_headers["Content-Length"] = str(len(self._body))
        response_headers.update(headers or {})
        self.headers = Headers(response_headers)

    def geturl(self):
        return self._url

    def read(self, _amount=-1):
        return self._body

    def close(self):
        return None


class FakeOpener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return self.responses.pop(0)


class WatchdogEvidenceTests(unittest.TestCase):
    def test_fixed_provider_urls_reject_queries_credentials_and_other_hosts(self):
        validators = (
            (evidence.validate_state_url, evidence.STATE_API_URL),
            (evidence.validate_claim_url, evidence.CLAIM_API_URL),
            (evidence.validate_dispatch_url, evidence.DISPATCH_API_URL),
        )
        for validate, url in validators:
            with self.subTest(url=url):
                self.assertEqual(validate(url), url)
                with self.assertRaisesRegex(evidence.EvidenceError, "fixed dedicated"):
                    validate(url + "?secret=x")
                with self.assertRaisesRegex(evidence.EvidenceError, "fixed dedicated"):
                    validate(url.replace(evidence.WATCHDOG_PROVIDER_HOST, "other.example.test"))

    def test_oidc_claims_bind_full_workflow_sha_ids_event_and_strict_lifetime(self):
        observed = datetime(2026, 8, 23, 3, 0, tzinfo=timezone.utc)
        claims = token_claims(observed=observed)
        token = encode_token(claims)
        actual = evidence.validate_oidc_claims(
            token,
            repository=evidence.WATCHDOG_REPOSITORY,
            caller_sha=WORKFLOW_SHA,
            ref="refs/heads/main",
            workflow_ref=evidence.WATCHDOG_WORKFLOW_REF,
            run_id="30",
            run_attempt="1",
            environment=evidence.WATCHDOG_ENVIRONMENT,
            event_name="schedule",
            observed_at=observed,
        )
        self.assertEqual(actual, claims)
        for label, update in (
            ("repository ID", {"repository_id": "1"}),
            ("workflow SHA", {"workflow_sha": "c" * 40}),
            ("event", {"event_name": "workflow_dispatch"}),
            ("exp equals iat", {"exp": claims["iat"]}),
            ("exp equals nbf", {"exp": claims["nbf"]}),
        ):
            changed = {**claims, **update}
            with self.subTest(label=label), self.assertRaises(evidence.EvidenceError):
                evidence.validate_oidc_claims(
                    encode_token(changed),
                    repository=evidence.WATCHDOG_REPOSITORY,
                    caller_sha=WORKFLOW_SHA,
                    ref="refs/heads/main",
                    workflow_ref=evidence.WATCHDOG_WORKFLOW_REF,
                    run_id="30",
                    run_attempt="1",
                    environment=evidence.WATCHDOG_ENVIRONMENT,
                    event_name="schedule",
                    observed_at=observed,
                )

    def test_transient_oidc_request_coordinates_are_popped_and_header_is_cleaned(self):
        token = encode_token(token_claims())
        request_url = "https://pipelines.actions.githubusercontent.com/token?x=1"
        response_url = request_url + "&" + urllib.parse.urlencode({"audience": evidence.OIDC_AUDIENCE})
        opener = FakeOpener([FakeResponse(200, response_url, {"value": token})])
        environment = {
            "ACTIONS_ID_TOKEN_REQUEST_URL": request_url,
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "ephemeral-request-token",
            "UNRELATED": "preserved",
        }
        actual = evidence.fetch_oidc_token(
            environment,
            repository=evidence.WATCHDOG_REPOSITORY,
            caller_sha=WORKFLOW_SHA,
            ref="refs/heads/main",
            workflow_ref=evidence.WATCHDOG_WORKFLOW_REF,
            run_id="30",
            run_attempt="1",
            environment_name=evidence.WATCHDOG_ENVIRONMENT,
            event_name="schedule",
            opener=opener,
        )
        self.assertEqual(actual, token)
        self.assertEqual(environment, {"UNRELATED": "preserved"})
        request, timeout = opener.requests[0]
        self.assertEqual(timeout, 30)
        self.assertIsNone(request.get_header("Authorization"))
        self.assertNotIn("ephemeral-request-token", request.full_url)

    def test_github_oidc_accepts_bounded_ordinary_json_without_content_length(self):
        token = encode_token(token_claims())
        request_url = "https://pipelines.actions.githubusercontent.com/token?x=1"
        response_url = request_url + "&" + urllib.parse.urlencode({
            "audience": evidence.OIDC_AUDIENCE,
        })
        ordinary_json = json.dumps({"value": token}, indent=2).encode("utf-8")
        opener = FakeOpener([FakeResponse(
            200,
            response_url,
            {"value": token},
            {"Transfer-Encoding": "chunked"},
            raw_body=ordinary_json,
            include_content_length=False,
        )])

        actual = evidence.fetch_oidc_token(
            {
                "ACTIONS_ID_TOKEN_REQUEST_URL": request_url,
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "ephemeral-request-token",
            },
            repository=evidence.WATCHDOG_REPOSITORY,
            caller_sha=WORKFLOW_SHA,
            ref="refs/heads/main",
            workflow_ref=evidence.WATCHDOG_WORKFLOW_REF,
            run_id="30",
            run_attempt="1",
            environment_name=evidence.WATCHDOG_ENVIRONMENT,
            event_name="schedule",
            opener=opener,
        )

        self.assertEqual(actual, token)

    def test_github_oidc_rejects_an_oversized_ordinary_json_response(self):
        token = encode_token(token_claims())
        request_url = "https://pipelines.actions.githubusercontent.com/token?x=1"
        response_url = request_url + "&" + urllib.parse.urlencode({
            "audience": evidence.OIDC_AUDIENCE,
        })
        oversized = b"{" + (b" " * evidence.MAX_OIDC_RESPONSE_BYTES) + b"}"
        opener = FakeOpener([FakeResponse(
            200,
            response_url,
            {"value": token},
            raw_body=oversized,
            include_content_length=False,
        )])

        with self.assertRaisesRegex(evidence.EvidenceError, "size is invalid"):
            evidence.fetch_oidc_token(
                {
                    "ACTIONS_ID_TOKEN_REQUEST_URL": request_url,
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "ephemeral-request-token",
                },
                repository=evidence.WATCHDOG_REPOSITORY,
                caller_sha=WORKFLOW_SHA,
                ref="refs/heads/main",
                workflow_ref=evidence.WATCHDOG_WORKFLOW_REF,
                run_id="30",
                run_attempt="1",
                environment_name=evidence.WATCHDOG_ENVIRONMENT,
                event_name="schedule",
                opener=opener,
            )

    def test_state_get_requires_canonical_bytes_and_quoted_raw_digest_etag(self):
        state = {"schemaVersion": 2, "status": "test"}
        raw = evidence.canonical_json(state)
        state_sha256 = hashlib.sha256(raw).hexdigest()
        opener = FakeOpener([FakeResponse(
            200, evidence.STATE_API_URL, state, {"ETag": f'"{state_sha256}"'},
        )])
        actual, etag = evidence.fetch_state_with_token(token="ephemeral", opener=opener)
        self.assertEqual(actual, raw)
        self.assertEqual(etag, f'"{state_sha256}"')
        request, _ = opener.requests[0]
        self.assertEqual(request.full_url, evidence.STATE_API_URL)
        self.assertIsNone(request.get_header("Authorization"))

        bad = FakeOpener([FakeResponse(200, evidence.STATE_API_URL, state, {"ETag": '"wrong"'})])
        with self.assertRaisesRegex(evidence.EvidenceError, "quoted raw digest"):
            evidence.fetch_state_with_token(token="ephemeral", opener=bad)

    def test_claim_posts_exact_decision_and_accepts_only_exact_201_response(self):
        decision = decision_receipt()
        raw = evidence.canonical_json(decision)
        opener = FakeOpener([FakeResponse(201, evidence.CLAIM_API_URL, claim_response())])
        actual = evidence.claim_with_token(raw_decision=raw, token="ephemeral", opener=opener)
        self.assertEqual(actual, claim_response())
        request, timeout = opener.requests[0]
        self.assertEqual(timeout, 60)
        self.assertEqual(request.full_url, evidence.CLAIM_API_URL)
        self.assertEqual(request.data, raw)
        self.assertIsNone(request.get_header("Authorization"))

        changed = {**decision, "unexpected": True}
        with self.assertRaisesRegex(evidence.EvidenceError, "fields are not exact"):
            evidence.claim_with_token(
                raw_decision=evidence.canonical_json(changed), token="ephemeral", opener=FakeOpener([]),
            )

    def test_initial_baseline_requires_reviewed_exact_file_and_state_etag(self):
        baseline = initial_baseline()
        raw = evidence.canonical_json(baseline)
        state_sha256 = "7" * 64
        opener = FakeOpener([FakeResponse(
            201,
            evidence.BASELINE_API_URL,
            {"schemaVersion": 2, "status": "baseline-initialized", "stateSha256": state_sha256},
            {"ETag": f'"{state_sha256}"'},
        )])
        actual = evidence.initialize_baseline_with_token(
            raw_baseline=raw, token="ephemeral", opener=opener,
        )
        self.assertEqual(actual["stateSha256"], state_sha256)
        request, _ = opener.requests[0]
        self.assertEqual(request.full_url, evidence.BASELINE_API_URL)
        self.assertEqual(request.data, raw)
        self.assertIsNone(request.get_header("Authorization"))

        changed = {**baseline, "reviewEnvironment": "production"}
        with self.assertRaisesRegex(evidence.EvidenceError, "review environment"):
            evidence.initialize_baseline_with_token(
                raw_baseline=evidence.canonical_json(changed), token="ephemeral", opener=FakeOpener([]),
            )

    def test_provider_dispatch_posts_only_claim_id_and_requires_http_200_run_binding(self):
        outcome = dispatch_response()
        opener = FakeOpener([FakeResponse(200, evidence.DISPATCH_API_URL, outcome)])
        actual = evidence.dispatch_with_token(
            claim=claim_response(), token="ephemeral", opener=opener,
        )
        self.assertEqual(actual, outcome)
        request, _ = opener.requests[0]
        self.assertEqual(json.loads(request.data), {
            "schemaVersion": 2,
            "requestType": "watchdog-provider-dispatch",
            "claimId": CLAIM_ID,
        })
        self.assertEqual(request.data, evidence.canonical_json(json.loads(request.data)))
        self.assertIsNone(request.get_header("Authorization"))

        changed = {**outcome, "workflowRunApiUrl": "https://api.github.com/wrong"}
        with self.assertRaisesRegex(evidence.EvidenceError, "run API URL"):
            evidence.dispatch_with_token(
                claim=claim_response(), token="ephemeral",
                opener=FakeOpener([FakeResponse(200, evidence.DISPATCH_API_URL, changed)]),
            )

    def test_reconciliation_response_cannot_claim_attempted_state_was_auto_released(self):
        automatic = {
            "status": "released-unattempted-expired-claim",
            "claimId": CLAIM_ID,
            "dispatchGuardGeneration": 8,
            "reconciliationReceiptSha256": "a" * 64,
        }
        actual = evidence.reconcile_with_token(
            claim_id=CLAIM_ID, manual=False, token="ephemeral",
            opener=FakeOpener([FakeResponse(200, evidence.RECONCILE_AUTO_API_URL, automatic)]),
        )
        self.assertEqual(actual, automatic)
        manual = {
            "status": "known-run-held-for-workflow-observation",
            "claimId": CLAIM_ID,
            "dispatchGuardGeneration": 7,
            "workflowRunId": "303",
        }
        self.assertEqual(
            evidence.reconcile_with_token(
                claim_id=CLAIM_ID, manual=True, token="ephemeral",
                opener=FakeOpener([FakeResponse(200, evidence.RECONCILE_MANUAL_API_URL, manual)]),
            ),
            manual,
        )

    def test_worm_policy_is_exact_separate_locked_90_day_container(self):
        policy = {
            "resourceId": (
                "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
                "rg-paperdesk-rollback-sea-20260808/providers/Microsoft.Storage/storageAccounts/"
                f"{evidence.EVIDENCE_ACCOUNT}/blobServices/default/containers/"
                f"{evidence.EVIDENCE_CONTAINER}/immutabilityPolicies/default"
            ),
            "state": "Locked",
            "immutabilityPeriodSinceCreationInDays": 90,
            "allowProtectedAppendWrites": False,
            "allowProtectedAppendWritesAll": False,
            "etag": '"policy"',
            "observedAt": "2026-08-23T03:00:00.000Z",
        }
        self.assertEqual(evidence.validate_policy(policy), policy)
        with self.assertRaisesRegex(evidence.EvidenceError, "90-day"):
            evidence.validate_policy({**policy, "immutabilityPeriodSinceCreationInDays": 30})


if __name__ == "__main__":
    unittest.main()
