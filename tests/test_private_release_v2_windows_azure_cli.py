import base64
import datetime as dt
import http.server
import json
import subprocess
import threading
import time
import unittest
import urllib.request
from unittest import mock

from scripts import private_release_v2_bootstrap as bootstrap


class AzureCliExecutableTests(unittest.TestCase):
    class HttpResponse:
        status = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        @staticmethod
        def read(_):
            return b""

    def run_az_json_for_platform(self, platform):
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout='{"status":"ok"}',
            stderr="",
        )
        with (
            mock.patch.object(bootstrap.sys, "platform", platform),
            mock.patch.object(
                bootstrap.subprocess, "run", return_value=completed
            ) as runner,
        ):
            document = bootstrap.AzureCliRestSession._run_az_json(
                ["account", "show"], "account inspection"
            )
        return document, runner.call_args

    def test_windows_uses_azure_cli_cmd_launcher(self):
        document, call = self.run_az_json_for_platform("win32")
        self.assertEqual(document, {"status": "ok"})
        self.assertEqual(
            call.args[0],
            ["az.cmd", "account", "show", "--output", "json"],
        )
        self.assertFalse(call.kwargs["check"])
        self.assertEqual(
            call.kwargs["timeout"], bootstrap.AZURE_CLI_REQUEST_TIMEOUT_SECONDS
        )

    def test_non_windows_keeps_extensionless_azure_cli_launcher(self):
        _, call = self.run_az_json_for_platform("linux")
        self.assertEqual(call.args[0][0], "az")

    def test_launch_failures_are_generic_and_never_fall_back(self):
        failures = (
            FileNotFoundError("sensitive local executable path"),
            subprocess.TimeoutExpired(["az.cmd"], 45, stderr="secret stderr"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                with (
                    mock.patch.object(bootstrap.sys, "platform", "win32"),
                    mock.patch.object(
                        bootstrap.subprocess, "run", side_effect=failure
                    ) as runner,
                    self.assertRaisesRegex(
                        bootstrap.BootstrapError,
                        "^Azure CLI account inspection failed$",
                    ),
                ):
                    bootstrap.AzureCliRestSession._run_az_json(
                        ["account", "show"], "account inspection"
                    )
                runner.assert_called_once()
                self.assertEqual(runner.call_args.args[0][0], "az.cmd")

    def test_nonzero_result_does_not_disclose_stderr(self):
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="sensitive Azure CLI diagnostic",
        )
        with (
            mock.patch.object(bootstrap.sys, "platform", "win32"),
            mock.patch.object(bootstrap.subprocess, "run", return_value=completed),
            self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "^Azure CLI token acquisition failed$",
            ),
        ):
            bootstrap.AzureCliRestSession._run_az_json(
                ["account", "get-access-token"], "token acquisition"
            )

    def test_token_request_selects_exact_subscription_without_redundant_tenant(self):
        observed_at = dt.datetime(2026, 8, 30, 12, 0, tzinfo=dt.timezone.utc)
        account_object_id = "b97bfa13-b375-4b27-93d7-141029dbc05b"
        claims = {
            "aud": "https://management.azure.com/",
            "exp": int(observed_at.timestamp()) + 3600,
            "nbf": int(observed_at.timestamp()) - 30,
            "oid": account_object_id,
            "tid": bootstrap.TENANT,
        }
        payload = base64.urlsafe_b64encode(
            json.dumps(claims, separators=(",", ":")).encode("utf-8")
        ).decode("ascii").rstrip("=")
        token = f"header.{payload}.signature"
        session = bootstrap.AzureCliRestSession(
            {"azure": {"accountObjectId": account_object_id}},
            clock=lambda: observed_at,
        )

        with mock.patch.object(
            session,
            "_run_az_json",
            return_value={"accessToken": token},
        ) as runner:
            self.assertEqual(
                session._token("https://management.azure.com/"),
                token,
            )

        runner.assert_called_once_with(
            [
                "account",
                "get-access-token",
                "--resource",
                "https://management.azure.com/",
                "--subscription",
                bootstrap.SUBSCRIPTION,
            ],
            "access token request",
        )
        self.assertNotIn("--tenant", runner.call_args.args[0])

    def test_key_vault_public_cloud_application_audience_is_exactly_allowed(self):
        observed_at = dt.datetime(2026, 8, 30, 12, 0, tzinfo=dt.timezone.utc)
        account_object_id = "b97bfa13-b375-4b27-93d7-141029dbc05b"

        def token_for(audience):
            claims = {
                "aud": audience,
                "exp": int(observed_at.timestamp()) + 3600,
                "nbf": int(observed_at.timestamp()) - 30,
                "oid": account_object_id,
                "tid": bootstrap.TENANT,
            }
            payload = base64.urlsafe_b64encode(
                json.dumps(claims, separators=(",", ":")).encode("utf-8")
            ).decode("ascii").rstrip("=")
            return f"header.{payload}.signature"

        session = bootstrap.AzureCliRestSession(
            {"azure": {"accountObjectId": account_object_id}},
            clock=lambda: observed_at,
        )
        accepted = token_for("cfa8b339-82a2-471a-a3c9-0fc0be7a4093")
        with mock.patch.object(
            session, "_run_az_json", return_value={"accessToken": accepted}
        ):
            self.assertEqual(session._token("https://vault.azure.net"), accepted)

        rejected_session = bootstrap.AzureCliRestSession(
            {"azure": {"accountObjectId": account_object_id}},
            clock=lambda: observed_at,
        )
        with (
            mock.patch.object(
                rejected_session,
                "_run_az_json",
                return_value={
                    "accessToken": token_for(
                        "11111111-1111-4111-8111-111111111111"
                    )
                },
            ),
            self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "access token is not bound",
            ),
        ):
            rejected_session._token("https://vault.azure.net")

    def test_storage_requests_receive_unique_canonical_client_request_ids(self):
        exchange = mock.Mock(
            side_effect=[
                bootstrap._RestResponse(200, b"", {}),
                bootstrap._RestResponse(200, b"", {}),
            ]
        )
        session = bootstrap.AzureCliRestSession(
            {"azure": {"accountObjectId": "b97bfa13-b375-4b27-93d7-141029dbc05b"}},
            exchange_runner=exchange,
        )
        with mock.patch.object(session, "_token", return_value="synthetic-token"):
            session.request(
                "GET", "https://mdspdbak2608089c4e.blob.core.windows.net/controller-locks?restype=container"
            )
            session.request(
                "PUT", "https://mdspdbak2608089c4e.blob.core.windows.net/packages/source.zip",
                body=b"fixture",
            )

        client_ids = []
        for call in exchange.call_args_list:
            request = call.args[0]
            headers = {key.lower(): value for key, value in request.header_items()}
            client_ids.append(headers["x-ms-client-request-id"])
            self.assertEqual(
                call.args[1], bootstrap.AZURE_REST_RESPONSE_TIMEOUT_SECONDS
            )
        self.assertEqual(len(client_ids), len(set(client_ids)))
        self.assertTrue(all(bootstrap.GUID.fullmatch(value) for value in client_ids))

    def test_storage_client_request_id_is_preserved_once_and_reuse_fails_closed(self):
        exchange = mock.Mock(return_value=bootstrap._RestResponse(200, b"", {}))
        session = bootstrap.AzureCliRestSession(
            {"azure": {"accountObjectId": "b97bfa13-b375-4b27-93d7-141029dbc05b"}},
            exchange_runner=exchange,
        )
        client_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        url = "https://mdspdbak2608089c4e.blob.core.windows.net/controller-locks?restype=container"
        with mock.patch.object(
            session, "_token", return_value="synthetic-token"
        ) as token:
            session.request("GET", url, headers={"X-Ms-Client-Request-Id": client_id})
            with self.assertRaisesRegex(bootstrap.BootstrapError, "was reused"):
                session.request("GET", url, headers={"x-ms-client-request-id": client_id})

        request = exchange.call_args.args[0]
        headers = {key.lower(): value for key, value in request.header_items()}
        self.assertEqual(headers["x-ms-client-request-id"], client_id)
        token.assert_called_once()
        exchange.assert_called_once()

    def test_invalid_or_ambiguous_storage_client_request_id_never_acquires_credentials(self):
        url = "https://mdspdbak2608089c4e.blob.core.windows.net/controller-locks?restype=container"
        variants = (
            {"x-ms-client-request-id": "not-a-guid"},
            {
                "x-ms-client-request-id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "X-Ms-Client-Request-Id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            },
        )
        for headers in variants:
            with self.subTest(headers=headers):
                session = bootstrap.AzureCliRestSession(
                    {"azure": {"accountObjectId": "b97bfa13-b375-4b27-93d7-141029dbc05b"}}
                )
                with (
                    mock.patch.object(session, "_token") as token,
                    self.assertRaises(bootstrap.BootstrapError),
                ):
                    session.request("GET", url, headers=headers)
                token.assert_not_called()
                self.assertEqual(len(session._storage_client_request_ids), 0)

    def test_storage_client_request_id_stays_reserved_after_token_failure(self):
        session = bootstrap.AzureCliRestSession(
            {"azure": {"accountObjectId": "b97bfa13-b375-4b27-93d7-141029dbc05b"}}
        )
        client_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        url = "https://mdspdbak2608089c4e.blob.core.windows.net/controller-locks?restype=container"
        with mock.patch.object(
            session,
            "_token",
            side_effect=bootstrap.BootstrapError("credential failure"),
        ) as token:
            with self.assertRaisesRegex(bootstrap.BootstrapError, "credential failure"):
                session.request(
                    "GET", url, headers={"x-ms-client-request-id": client_id}
                )
            with self.assertRaisesRegex(bootstrap.BootstrapError, "was reused"):
                session.request(
                    "GET", url, headers={"x-ms-client-request-id": client_id}
                )
        token.assert_called_once()

    def test_deadline_is_rechecked_after_storage_token_acquisition(self):
        started = dt.datetime(2026, 9, 4, 11, 0, tzinfo=dt.timezone.utc)
        current = [started]
        session = bootstrap.AzureCliRestSession(
            {"azure": {"accountObjectId": "b97bfa13-b375-4b27-93d7-141029dbc05b"}},
            clock=lambda: current[0],
        )

        def delayed_token(_):
            current[0] += dt.timedelta(
                seconds=bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS
            )
            return "synthetic-token"

        with (
            mock.patch.object(session, "_token", side_effect=delayed_token) as token,
            self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "deadline expired after credential acquisition",
            ),
        ):
            session.request(
                "GET",
                "https://mdspdbak2608089c4e.blob.core.windows.net/controller-locks?restype=container",
                deadline=started + dt.timedelta(
                    seconds=bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS
                ),
            )
        token.assert_called_once()

    def test_completed_storage_response_crossing_deadline_preserves_correlation(self):
        started = dt.datetime(2026, 9, 4, 11, 0, tzinfo=dt.timezone.utc)
        deadline = started + dt.timedelta(
            seconds=bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS
        )
        current = [started]
        client_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

        def delayed_exchange(_request, _timeout):
            current[0] = deadline
            return bootstrap._RestResponse(
                201,
                b'{"created":true}',
                {
                    "x-ms-request-id": "e408f7b5-201e-003c-185a-3c2083000000",
                    "Date": "Fri, 04 Sep 2026 11:01:30 GMT",
                    "ETag": '"created-etag"',
                },
            )

        session = bootstrap.AzureCliRestSession(
            {"azure": {"accountObjectId": "b97bfa13-b375-4b27-93d7-141029dbc05b"}},
            clock=lambda: current[0],
            exchange_runner=delayed_exchange,
        )

        with (
            mock.patch.object(session, "_token", return_value="synthetic-token"),
            self.assertRaises(bootstrap._LateRestResponse) as raised,
        ):
            session.request(
                "PUT",
                "https://mdspdbak2608089c4e.blob.core.windows.net/packages/source.zip",
                body=b"fixture",
                headers={"x-ms-client-request-id": client_id},
                deadline=deadline,
            )

        response = raised.exception.response
        self.assertEqual(response.status, 201)
        self.assertEqual(response.body, b'{"created":true}')
        self.assertEqual(response.client_request_id, client_id)
        self.assertEqual(
            response.headers["x-ms-request-id"],
            "e408f7b5-201e-003c-185a-3c2083000000",
        )

    def _assert_slow_response_body_is_killed(self, status):
        completed_body = threading.Event()
        disconnected = threading.Event()
        chunk = b"x" * (256 * 1024)
        chunk_count = 20

        class SlowBodyHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                self.send_response(status)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(chunk) * chunk_count))
                self.end_headers()
                try:
                    for _ in range(chunk_count):
                        self.wfile.write(chunk)
                        self.wfile.flush()
                        time.sleep(0.03)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    disconnected.set()
                    return
                completed_body.set()

            def log_message(self, *_args):
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SlowBodyHandler)
        server.daemon_threads = True
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}/slow",
                method="GET",
            )
            started = time.monotonic()
            with self.assertRaises(bootstrap._RestTotalTimeout):
                bootstrap.AzureCliRestSession._run_exchange_subprocess(
                    request, 0.15
                )
            self.assertLess(time.monotonic() - started, 2.0)
            disconnected.wait(1.0)
            self.assertFalse(completed_body.is_set())
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2.0)

    def test_total_timeout_kills_slow_success_body_exchange(self):
        self._assert_slow_response_body_is_killed(200)

    def test_total_timeout_kills_slow_http_error_body_exchange(self):
        self._assert_slow_response_body_is_killed(409)


if __name__ == "__main__":
    unittest.main()
