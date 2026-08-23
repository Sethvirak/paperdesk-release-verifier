from io import BytesIO
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from provider import watchdog_state_provider as provider
from provider import wsgi
from scripts import watchdog_contract
from tests.test_watchdog_contract import oidc_for, request_fixtures
from tests.test_watchdog_provider import (
    FakeDispatcher,
    MemoryStorage,
    RegistryValidator,
    baseline,
    state,
)


class FakeVerifier:
    def __init__(self):
        self.calls = []
        self.failures = {}

    def _raise_if_configured(self, purpose):
        failure = self.failures.get(purpose)
        if failure is not None:
            raise failure

    def verify_state(self, token):
        self._raise_if_configured("state")
        self.calls.append(("state", token))
        return {"run_id": "1", "run_attempt": "1"}

    def verify_transition(self, token, request):
        self._raise_if_configured("transition")
        self.calls.append(("transition", token, request["operation"]))
        return oidc_for(watchdog_contract.load_contract(), request)

    def verify_internal(self, token, purpose):
        self._raise_if_configured(purpose)
        self.calls.append((purpose, token))
        return {"run_id": "1", "run_attempt": "1"}


class FakeProvider:
    def __init__(self):
        raw = provider.canonical_json(state(rollback_baseline=baseline()))
        digest = __import__("hashlib").sha256(raw).hexdigest()
        self.snapshot = provider.StateSnapshot(
            document=state(rollback_baseline=baseline()), raw=raw,
            sha256=digest, etag=f'"{digest}"', storage_etag='"blob"',
            metadata={
                "paperdesk_sha256": digest,
                "paperdesk_schema": "2",
                "paperdesk_initial_baseline_sha256": baseline()["receiptSha256"],
            },
        )
        self.calls = []
        self.transition_error = None

    def state_snapshot(self):
        return self.snapshot

    def transition(self, raw, if_match, claims):
        if self.transition_error is not None:
            raise self.transition_error
        request = __import__("json").loads(raw)
        self.calls.append((request, if_match, claims))
        return provider.HTTPResult(201, {
            "schemaVersion": 2, "status": "candidate-published",
            "operation": "publish-candidate",
            "previousStateSha256": request["expectedStateSha256"],
            "stateSha256": "b" * 64, "stateETag": f'"{"b" * 64}"',
            "transitionReceiptSha256": "c" * 64,
            "transitionEvidencePath": "v2/transitions/publish-candidate/1/1.json",
            "transitionEvidenceETag": '"evidence"',
            "transitionEvidenceVersionId": "version-1",
        })


def call(application, method, path, *, body=b"", headers=None, query="", scheme="https"):
    environment = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query,
        "SERVER_NAME": "paperdesk-watchdog-state-9c4e0d0d.azurewebsites.net",
        "SERVER_PORT": "443",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "wsgi.url_scheme": scheme,
        "wsgi.input": BytesIO(body),
        "HTTP_HOST": "paperdesk-watchdog-state-9c4e0d0d.azurewebsites.net",
        "HTTP_X_FORWARDED_PROTO": "https",
        "HTTP_AUTHORIZATION": "Bearer oidc-token",
    }
    if body:
        environment.update({
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": "application/json",
        })
    for name, value in (headers or {}).items():
        key = name.upper().replace("-", "_")
        if key in {"CONTENT_LENGTH", "CONTENT_TYPE"}:
            environment[key] = value
        else:
            environment["HTTP_" + key] = value
    captured = {}

    def start_response(status, response_headers):
        captured["status"] = status
        captured["headers"] = dict(response_headers)

    captured["body"] = b"".join(application(environment, start_response))
    return captured


class WatchdogWSGITests(unittest.TestCase):
    def setUp(self):
        self.verifier = FakeVerifier()
        self.provider = FakeProvider()
        self.application = wsgi.WatchdogWSGIApplication(self.provider, self.verifier)

    def test_get_state_returns_canonical_bytes_and_strong_logical_etag(self):
        response = call(self.application, "GET", "/api/watchdog-state/v2")
        self.assertEqual(response["status"], "200 OK")
        self.assertEqual(response["body"], self.provider.snapshot.raw)
        self.assertEqual(response["headers"]["ETag"], self.provider.snapshot.etag)
        self.assertEqual(response["headers"]["Cache-Control"], "no-store")
        self.assertEqual(self.verifier.calls, [("state", "oidc-token")])

    def test_app_service_http_wsgi_shape_trusts_only_exact_forwarded_https_boundary(self):
        response = call(
            self.application,
            "GET",
            "/api/watchdog-state/v2",
            scheme="http",
        )
        self.assertEqual(response["status"], "200 OK")

        for label, options in (
            ("missing forwarded proto", {"headers": {"X-Forwarded-Proto": ""}}),
            ("wrong forwarded proto", {"headers": {"X-Forwarded-Proto": "http"}}),
            ("forwarded proto list", {"headers": {"X-Forwarded-Proto": "https,http"}}),
            ("query", {"query": "unexpected=1"}),
        ):
            with self.subTest(label=label):
                rejected = call(
                    self.application,
                    "GET",
                    "/api/watchdog-state/v2",
                    scheme="http",
                    **options,
                )
                self.assertEqual(rejected["status"], "400 Bad Request")

    def test_transition_route_uses_bounded_body_if_match_and_returns_201(self):
        request = request_fixtures()["publish-candidate"]
        request["expectedStateSha256"] = self.provider.snapshot.sha256
        request["rollbackBaselineReceiptSha256"] = baseline()["receiptSha256"]
        raw = provider.canonical_json(request)
        response = call(
            self.application, "POST", "/api/watchdog-state/v2/transitions",
            body=raw, headers={"If-Match": f'"{self.provider.snapshot.sha256}"'},
        )
        self.assertEqual(response["status"], "201 Created")
        self.assertEqual(response["headers"]["Content-Type"], "application/json")
        self.assertEqual(self.provider.calls[0][1], f'"{self.provider.snapshot.sha256}"')
        self.assertEqual(self.verifier.calls[0][:2], ("transition", "oidc-token"))

    def test_wrong_host_transfer_encoding_and_missing_length_are_exact_400_without_secret_echo(self):
        cases = (
            {"Host": "attacker.example"},
            {"Transfer-Encoding": "chunked"},
            {"Content-Length": ""},
        )
        for headers in cases:
            with self.subTest(headers=headers):
                response = call(
                    self.application, "POST", "/api/watchdog-state/v2/transitions",
                    body=b"{}\n", headers=headers,
                )
                self.assertEqual(response["status"], "400 Bad Request")
                self.assertNotIn(b"oidc-token", response["body"])
                self.assertEqual(set(__import__("json").loads(response["body"])), {
                    "error", "schemaVersion", "status",
                })

    def test_transition_live_error_boundary_is_exact_400_401_403_409_412_503(self):
        request = request_fixtures()["publish-candidate"]
        request["expectedStateSha256"] = self.provider.snapshot.sha256
        request["rollbackBaselineReceiptSha256"] = baseline()["receiptSha256"]
        raw = provider.canonical_json(request)
        path = "/api/watchdog-state/v2/transitions"

        malformed = call(self.application, "POST", path, body=raw[:-1])
        self.assertEqual(malformed["status"], "400 Bad Request")

        unauthenticated = call(
            self.application, "POST", path, body=raw, headers={"Authorization": ""},
        )
        self.assertEqual(unauthenticated["status"], "401 Unauthorized")

        self.verifier.failures["transition"] = provider.ProviderError(
            "wrong caller", 403, "oidc-forbidden",
        )
        wrong_caller = call(self.application, "POST", path, body=raw)
        self.assertEqual(wrong_caller["status"], "403 Forbidden")
        self.verifier.failures.clear()

        for status, expected in (
            (409, "409 Conflict"),
            (412, "412 Precondition Failed"),
            (500, "503 Service Unavailable"),
            (503, "503 Service Unavailable"),
        ):
            self.provider.transition_error = provider.ProviderError(
                "provider rejection", status, "provider-rejection",
            )
            with self.subTest(status=status):
                response = call(self.application, "POST", path, body=raw)
                self.assertEqual(response["status"], expected)
                self.assertNotIn(b"provider rejection", response["body"])
        self.provider.transition_error = RuntimeError("secret internal detail")
        unavailable = call(self.application, "POST", path, body=raw)
        self.assertEqual(unavailable["status"], "503 Service Unavailable")
        self.assertNotIn(b"secret internal detail", unavailable["body"])

    def test_real_corrupt_persisted_state_is_503_not_caller_400(self):
        storage = MemoryStorage()
        storage.seed(
            provider.STATE_CONTAINER,
            provider.STATE_BLOB,
            b'{"schemaVersion":2}\n',
            metadata={},
        )
        service = provider.WatchdogProvider(
            storage,
            FakeDispatcher(),
            registry_validator=RegistryValidator(),
            contract=watchdog_contract.load_contract(),
            clock=lambda: __import__("datetime").datetime(
                2026, 8, 23, 1, 0, 0,
                tzinfo=__import__("datetime").timezone.utc,
            ),
        )
        application = wsgi.WatchdogWSGIApplication(service, self.verifier)
        response = call(application, "GET", "/api/watchdog-state/v2")
        self.assertEqual(response["status"], "503 Service Unavailable")
        self.assertEqual(__import__("json").loads(response["body"])["error"], "state-invalid")

    def test_real_corrupt_persisted_transition_worm_is_503_not_caller_400(self):
        storage = MemoryStorage()
        raw_state = provider.canonical_json(state(rollback_baseline=baseline()))
        storage.seed(provider.STATE_CONTAINER, provider.STATE_BLOB, raw_state)
        service = provider.WatchdogProvider(
            storage,
            FakeDispatcher(),
            registry_validator=RegistryValidator(),
            contract=watchdog_contract.load_contract(),
        )
        snapshot = service.state_snapshot()
        request = request_fixtures()["publish-candidate"]
        request["expectedStateSha256"] = snapshot.sha256
        request["rollbackBaselineReceiptSha256"] = baseline()["receiptSha256"]
        claims = oidc_for(watchdog_contract.load_contract(), request)
        path = f"v2/transitions/publish-candidate/{claims['run_id']}/{claims['run_attempt']}.json"
        storage.seed(provider.EVIDENCE_CONTAINER, path, b'{"schemaVersion":2}\n', metadata={})
        application = wsgi.WatchdogWSGIApplication(service, self.verifier)
        raw = provider.canonical_json(request)
        response = call(
            application,
            "POST",
            "/api/watchdog-state/v2/transitions",
            body=raw,
            headers={"If-Match": f'"{snapshot.sha256}"'},
        )
        self.assertEqual(response["status"], "503 Service Unavailable")
        self.assertEqual(
            __import__("json").loads(response["body"])["error"],
            "transition-receipt-invalid",
        )

    def test_exact_field_transition_worm_with_invalid_nested_state_is_503(self):
        storage = MemoryStorage()
        storage.seed(
            provider.STATE_CONTAINER,
            provider.STATE_BLOB,
            provider.canonical_json(state(rollback_baseline=baseline())),
        )
        service = provider.WatchdogProvider(
            storage,
            FakeDispatcher(),
            registry_validator=RegistryValidator(),
            contract=watchdog_contract.load_contract(),
            clock=lambda: __import__("datetime").datetime(
                2026, 8, 23, 1, 0, 0,
                tzinfo=__import__("datetime").timezone.utc,
            ),
        )
        snapshot = service.state_snapshot()
        request = request_fixtures()["publish-candidate"]
        request["expectedStateSha256"] = snapshot.sha256
        request["rollbackBaselineReceiptSha256"] = baseline()["receiptSha256"]
        claims = oidc_for(watchdog_contract.load_contract(), request)
        raw = provider.canonical_json(request)
        storage.fail_next_replace = True
        with self.assertRaises(provider.ProviderError):
            service.transition(raw, f'"{snapshot.sha256}"', claims)
        path = f"v2/transitions/publish-candidate/{claims['run_id']}/{claims['run_attempt']}.json"
        existing = storage.blobs[(provider.EVIDENCE_CONTAINER, path)]
        receipt = __import__("json").loads(existing.body)
        receipt["previousState"]["rollbackBaseline"]["sourceRunId"] = "0"
        storage.seed(
            provider.EVIDENCE_CONTAINER,
            path,
            provider.canonical_json(receipt),
            metadata=existing.metadata,
        )

        application = wsgi.WatchdogWSGIApplication(service, self.verifier)
        response = call(
            application,
            "POST",
            "/api/watchdog-state/v2/transitions",
            body=raw,
            headers={"If-Match": f'"{snapshot.sha256}"'},
        )
        self.assertEqual(response["status"], "503 Service Unavailable")
        self.assertEqual(
            __import__("json").loads(response["body"])["error"],
            "transition-receipt-invalid",
        )

    def test_malformed_provider_owned_worm_policy_proof_is_503(self):
        class InvalidPolicyStorage(MemoryStorage):
            def __init__(self, field, value):
                super().__init__()
                self.field = field
                self.value = value

            def policy(self, container):
                document = super().policy(container)
                document[self.field] = self.value
                return document

        for field, value in (("etag", "unquoted"), ("observedAt", "not-a-time")):
            with self.subTest(field=field):
                storage = InvalidPolicyStorage(field, value)
                storage.seed(
                    provider.STATE_CONTAINER,
                    provider.STATE_BLOB,
                    provider.canonical_json(state(rollback_baseline=baseline())),
                )
                service = provider.WatchdogProvider(
                    storage,
                    FakeDispatcher(),
                    registry_validator=RegistryValidator(),
                    contract=watchdog_contract.load_contract(),
                )
                snapshot = service.state_snapshot()
                request = request_fixtures()["publish-candidate"]
                request["expectedStateSha256"] = snapshot.sha256
                request["rollbackBaselineReceiptSha256"] = baseline()["receiptSha256"]
                raw = provider.canonical_json(request)
                application = wsgi.WatchdogWSGIApplication(service, self.verifier)
                response = call(
                    application,
                    "POST",
                    "/api/watchdog-state/v2/transitions",
                    body=raw,
                    headers={"If-Match": f'"{snapshot.sha256}"'},
                )
                self.assertEqual(response["status"], "503 Service Unavailable")
                self.assertEqual(
                    __import__("json").loads(response["body"])["error"],
                    "worm-policy-invalid",
                )

    def test_module_exposes_wsgi_application_and_no_raw_http_server(self):
        self.assertTrue(callable(wsgi.application))
        source = (ROOT / "provider" / "watchdog_state_provider.py").read_text(encoding="utf-8")
        self.assertNotIn("ProviderHTTPServer", source)
        self.assertNotIn("WatchdogRequestHandler", source)
        self.assertNotIn("http.server", source)


if __name__ == "__main__":
    unittest.main()
