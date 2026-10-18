"""Offline response ownership tests for ProductionActivation._get.

These cases call the real observation method with an inert opener and retained
HTTPError bodies. They do not construct activation policy or credentials, open
network connections, or qualify proof authentication or transport deadlines.
The read-exception case assumes close itself completes normally; simultaneous
read and close failure is outside this focused test scope.
"""

import io
from types import SimpleNamespace
import unittest
from unittest import mock
import urllib.error
import urllib.request

from tests.control_lifecycle_offline_boundary import external_access_blocked

with external_access_blocked() as IMPORT_ATTEMPTS:
    from provider import private_release_bridge_azure as azure


class TrackedBody(io.BytesIO):
    def __init__(self, raw, read_failure=None):
        super().__init__(raw)
        self.requested_sizes = []
        self.close_calls = 0
        self.read_failure = read_failure

    def read(self, size=-1):
        self.requested_sizes.append(size)
        if self.read_failure is not None:
            raise self.read_failure
        return super().read(size)

    def close(self):
        self.close_calls += 1
        return super().close()


class NormalResponse:
    status = 200

    def __init__(self, body):
        self.body = body
        self.enters = 0
        self.exits = 0

    def __enter__(self):
        self.enters += 1
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.exits += 1
        self.body.close()

    def read(self, size):
        return self.body.read(size)


class ProductionActivationHttpErrorCleanupTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(IMPORT_ATTEMPTS, [])
        self.boundary = external_access_blocked()
        self.attempts = self.boundary.__enter__()
        self.addCleanup(self.finish_boundary)

    def finish_boundary(self):
        try:
            # Production code can catch a boundary assertion. Inspect the
            # recorded attempts even when the method returned a benign value.
            self.assertEqual(self.attempts, [])
        finally:
            self.boundary.__exit__(None, None, None)

    def invoke(self, response=None, failure=None, maximum=8):
        calls = []

        def fake_open(request, timeout):
            headers = {name.lower(): value for name, value in request.header_items()}
            self.assertEqual(headers, {"accept": "application/json", "cache-control": "no-store"})
            self.assertEqual(request.full_url, "https://offline.invalid/api/proof")
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(timeout, 30)
            calls.append({"method": "GET", "path": "/api/proof", "timeout": timeout,
                          "authorizationHeaderPresent": False})
            if failure is not None:
                raise failure
            return response

        def fake_builder(*handlers):
            self.assertEqual(len(handlers), 2)
            self.assertIsInstance(handlers[0], urllib.request.ProxyHandler)
            self.assertEqual(handlers[0].proxies, {})
            self.assertIsInstance(handlers[1], azure._NoRedirect)
            return SimpleNamespace(open=fake_open)

        # Exercise the actual method's observation seam without fabricating an
        # accepted activation object or invoking a production constructor.
        self_object = SimpleNamespace(origin="https://offline.invalid")
        with mock.patch.object(urllib.request, "build_opener", new=fake_builder):
            value = azure.ProductionActivation._get(self_object, "/api/proof", maximum)
        self.assertEqual(len(calls), 1)
        return value

    def error_case(self, raw, maximum, read_failure=None):
        body = TrackedBody(raw, read_failure)
        error = urllib.error.HTTPError("https://offline.invalid/api/proof", 503,
                                       "synthetic unavailable", {}, body)
        try:
            if read_failure is None:
                status, result = self.invoke(failure=error, maximum=maximum)
                self.assertEqual(status, 503)
                self.assertEqual(result, raw[:maximum + 1])
            else:
                with self.assertRaises(type(read_failure)) as captured:
                    self.invoke(failure=error, maximum=maximum)
                self.assertIs(captured.exception, read_failure)
            self.assertEqual(body.requested_sizes, [maximum + 1])
            self.assertTrue(body.closed, "HTTPError response body was not explicitly closed")
            self.assertEqual(body.close_calls, 1)
        finally:
            # Retain the error through the assertion, then close only this
            # inert fixture if the baseline owner failed the cleanup contract.
            if not body.closed:
                error.close()

    def test_01_error_response_closes_after_successful_read(self):
        self.error_case(b"pending", 8)

    def test_02_error_response_closes_after_bound_plus_one_read(self):
        self.error_case(b"0123456789abcdef", 8)

    def test_03_error_response_closes_and_preserves_read_exception(self):
        failure = RuntimeError("synthetic read failure")
        self.error_case(b"unused", 8, failure)

    def test_04_normal_response_context_and_request_controls(self):
        body = TrackedBody(b"healthy")
        response = NormalResponse(body)
        self.assertEqual(self.invoke(response=response), (200, b"healthy"))
        self.assertEqual((response.enters, response.exits), (1, 1))
        self.assertTrue(body.closed)
        self.assertEqual(body.close_calls, 1)
        self.assertEqual(body.requested_sizes, [9])

    def test_05_non_http_failure_keeps_existing_empty_observation(self):
        self.assertEqual(self.invoke(failure=urllib.error.URLError("synthetic unavailable")),
                         (0, b""))

    def test_06_redirect_handler_still_refuses_redirect(self):
        self.assertIsNone(azure._NoRedirect().redirect_request(
            None, None, 302, "synthetic redirect", {}, "https://redirect.invalid/"))


if __name__ == "__main__":
    unittest.main()
