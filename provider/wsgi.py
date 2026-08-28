"""Bounded Gunicorn WSGI boundary for the PaperDesk watchdog provider."""

from __future__ import annotations

from http import HTTPStatus
import json
import os
import re
import threading
from typing import Any, Callable, Iterable, Mapping

from provider import runtime
from provider.watchdog_state_provider import (
    APP_NAME,
    MAX_BODY,
    MAX_JWT,
    ProviderError,
    WatchdogProvider,
    canonical_json,
)


PROVIDER_HOST = f"{APP_NAME}.azurewebsites.net"
STATE_PATH = "/api/watchdog-state/v2"
TRANSITION_PATH = "/api/watchdog-state/v2/transitions"
BASELINE_PATH = "/api/watchdog-state/v2/initial-baseline"
CLAIM_PATH = "/api/watchdog-dispatch/v2/claim"
DISPATCH_PATH = "/api/watchdog-dispatch/v2"
RECONCILE_AUTO_PATH = "/api/watchdog-reconciliation/v2/automatic"
RECONCILE_MANUAL_PATH = "/api/watchdog-reconciliation/v2/manual"
POSITIVE = re.compile(r"^[1-9][0-9]*$")
UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)


def _canonical_request(raw: bytes, label: str) -> Mapping[str, Any]:
    if not 2 <= len(raw) <= MAX_BODY:
        raise ProviderError(f"{label} byte length is invalid", 400, "request-body-invalid")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProviderError(f"{label} is not valid UTF-8 JSON", 400, "request-body-invalid")
    if not isinstance(document, dict) or canonical_json(document) != raw:
        raise ProviderError(f"{label} must be canonical JSON", 400, "request-body-invalid")
    return document


class WatchdogWSGIApplication:
    def __init__(self, provider: WatchdogProvider, verifier: Any):
        self.provider = provider
        self.verifier = verifier

    @staticmethod
    def _boundary(environ: Mapping[str, Any]) -> None:
        if (
            environ.get("HTTP_HOST") != PROVIDER_HOST
            or environ.get("HTTP_X_FORWARDED_PROTO") != "https"
        ):
            raise ProviderError("request host or TLS boundary is not exact", 400, "request-boundary-invalid")
        if environ.get("QUERY_STRING") not in {None, ""}:
            raise ProviderError("request query string is forbidden", 400, "request-boundary-invalid")
        if environ.get("HTTP_TRANSFER_ENCODING") not in {None, ""}:
            raise ProviderError("request transfer encoding is forbidden", 400, "request-boundary-invalid")
        if environ.get("HTTP_CONTENT_ENCODING") not in {None, "", "identity"}:
            raise ProviderError("request content encoding is invalid", 400, "request-boundary-invalid")

    @staticmethod
    def _path(environ: Mapping[str, Any]) -> str:
        path = environ.get("PATH_INFO")
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or "//" in path
            or "\\" in path
            or "\x00" in path
        ):
            raise ProviderError("request path is invalid", 404, "not-found")
        return path

    @staticmethod
    def _token(environ: Mapping[str, Any]) -> str:
        authorization = environ.get("HTTP_AUTHORIZATION")
        if (
            not isinstance(authorization, str)
            or not authorization.startswith("Bearer ")
            or "," in authorization
        ):
            raise ProviderError("one GitHub OIDC bearer token is required", 401, "oidc-required")
        token = authorization[7:]
        if (
            not token
            or token != token.strip()
            or len(token) > MAX_JWT
            or "\r" in token
            or "\n" in token
        ):
            raise ProviderError("GitHub OIDC bearer token is invalid", 401, "oidc-invalid")
        return token

    @staticmethod
    def _body(environ: Mapping[str, Any]) -> bytes:
        length_text = environ.get("CONTENT_LENGTH")
        if not isinstance(length_text, str) or not POSITIVE.fullmatch(length_text):
            raise ProviderError("request Content-Length is required", 400, "request-body-invalid")
        length = int(length_text)
        if not 1 <= length <= MAX_BODY:
            raise ProviderError("request Content-Length is outside the fixed bound", 400, "request-body-invalid")
        if environ.get("CONTENT_TYPE") != "application/json":
            raise ProviderError("request Content-Type must be application/json", 400, "request-body-invalid")
        stream = environ.get("wsgi.input")
        if stream is None or not hasattr(stream, "read"):
            raise ProviderError("request body stream is unavailable", 400, "request-body-invalid")
        raw = stream.read(length + 1)
        if not isinstance(raw, bytes) or len(raw) != length:
            raise ProviderError("request body length is not exact", 400, "request-body-invalid")
        return raw

    @staticmethod
    def _respond(
        start_response: Callable[[str, list[tuple[str, str]]], Any],
        status: int,
        body: bytes,
        extra_headers: Mapping[str, str] | None = None,
    ) -> Iterable[bytes]:
        try:
            reason = HTTPStatus(status).phrase
        except ValueError:
            status, reason = 500, "Internal Server Error"
        headers = [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("Content-Encoding", "identity"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
        ]
        headers.extend((name, value) for name, value in (extra_headers or {}).items())
        start_response(f"{status} {reason}", headers)
        return (body,)

    def _json(
        self,
        start_response: Callable[[str, list[tuple[str, str]]], Any],
        status: int,
        document: Mapping[str, Any],
        extra_headers: Mapping[str, str] | None = None,
    ) -> Iterable[bytes]:
        return self._respond(start_response, status, canonical_json(document), extra_headers)

    def _dispatch_request(self, document: Mapping[str, Any]) -> str:
        if set(document) != {"schemaVersion", "requestType", "claimId"} or (
            document.get("schemaVersion") != 2
            or document.get("requestType") != "watchdog-provider-dispatch"
            or not isinstance(document.get("claimId"), str)
            or not UUID.fullmatch(document["claimId"])
        ):
            raise ProviderError("provider dispatch request fields are invalid", 400, "request-body-invalid")
        return document["claimId"]

    def _reconciliation_request(self, document: Mapping[str, Any]) -> str:
        if set(document) != {"schemaVersion", "requestType", "claimId"} or (
            document.get("schemaVersion") != 2
            or document.get("requestType") != "watchdog-dispatch-reconciliation"
            or not isinstance(document.get("claimId"), str)
            or not UUID.fullmatch(document["claimId"])
        ):
            raise ProviderError("reconciliation request fields are invalid", 400, "request-body-invalid")
        return document["claimId"]

    def __call__(
        self,
        environ: Mapping[str, Any],
        start_response: Callable[[str, list[tuple[str, str]]], Any],
    ) -> Iterable[bytes]:
        try:
            self._boundary(environ)
            method = str(environ.get("REQUEST_METHOD") or "")
            path = self._path(environ)
            token = self._token(environ)
            if method == "GET" and path == STATE_PATH:
                self.verifier.verify_state(token)
                snapshot = self.provider.state_snapshot()
                return self._respond(start_response, 200, snapshot.raw, {"ETag": snapshot.etag})
            if method == "POST" and path == TRANSITION_PATH:
                raw = self._body(environ)
                request = _canonical_request(raw, "transition request")
                claims = self.verifier.verify_transition(token, request)
                result = self.provider.transition(raw, environ.get("HTTP_IF_MATCH"), claims)
                return self._json(start_response, result.status_code, result.document)
            if method == "POST" and path == CLAIM_PATH:
                raw = self._body(environ)
                claims = self.verifier.verify_internal(token, "dispatch")
                result = self.provider.claim_rollback(
                    raw,
                    environ.get("HTTP_X_PAPERDESK_DECISION_EVIDENCE_ETAG"),
                    claims,
                )
                return self._json(start_response, 201, result)
            if method == "POST" and path == DISPATCH_PATH:
                document = _canonical_request(self._body(environ), "dispatch request")
                claim_id = self._dispatch_request(document)
                claims = self.verifier.verify_internal(token, "dispatch")
                return self._json(start_response, 200, self.provider.dispatch_rollback(claim_id, claims))
            if method == "POST" and path in {RECONCILE_AUTO_PATH, RECONCILE_MANUAL_PATH}:
                document = _canonical_request(self._body(environ), "reconciliation request")
                claim_id = self._reconciliation_request(document)
                manual = path == RECONCILE_MANUAL_PATH
                purpose = "reconcile-manual" if manual else "reconcile-auto"
                claims = self.verifier.verify_internal(token, purpose)
                return self._json(
                    start_response,
                    200,
                    self.provider.reconcile(claim_id, claims, manual=manual),
                )
            if method == "POST" and path == BASELINE_PATH:
                document = _canonical_request(self._body(environ), "initial baseline request")
                claims = self.verifier.verify_internal(token, "baseline")
                snapshot = self.provider.initialize_baseline(document, claims)
                return self._json(
                    start_response,
                    201,
                    {"schemaVersion": 2, "status": "baseline-initialized", "stateSha256": snapshot.sha256},
                    {"ETag": snapshot.etag},
                )
            if path in {
                STATE_PATH, TRANSITION_PATH, BASELINE_PATH, CLAIM_PATH, DISPATCH_PATH,
                RECONCILE_AUTO_PATH, RECONCILE_MANUAL_PATH,
            }:
                raise ProviderError("provider route method is not allowed", 405, "method-not-allowed")
            raise ProviderError("provider route does not exist", 404, "not-found")
        except ProviderError as error:
            return self._json(
                start_response,
                503 if error.status >= 500 else error.status,
                {"error": error.code, "schemaVersion": 2, "status": "rejected"},
            )
        except ValueError:
            return self._json(
                start_response,
                400,
                {"error": "contract-rejected", "schemaVersion": 2, "status": "rejected"},
            )
        except Exception:
            return self._json(
                start_response,
                503,
                {"error": "provider-failure", "schemaVersion": 2, "status": "rejected"},
            )


class LazyApplication:
    """Build the cloud runtime on first request without side effects on import."""

    def __init__(self):
        self._application: WatchdogWSGIApplication | None = None
        self._error: ProviderError | None = None
        self._lock = threading.Lock()

    def __call__(self, environ: Mapping[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        with self._lock:
            if self._application is None and self._error is None:
                try:
                    verifier, service = runtime.build_runtime(os.environ)
                    self._application = WatchdogWSGIApplication(service, verifier)
                except ProviderError as error:
                    self._error = error
                except Exception:
                    self._error = ProviderError("runtime assembly failed", 503, "provider-unavailable")
        if self._application is not None:
            return self._application(environ, start_response)
        body = canonical_json({
            "error": self._error.code if self._error is not None else "provider-unavailable",
            "schemaVersion": 2,
            "status": "rejected",
        })
        return WatchdogWSGIApplication._respond(start_response, 503, body)


application = LazyApplication()


__all__ = ["LazyApplication", "WatchdogWSGIApplication", "application"]
