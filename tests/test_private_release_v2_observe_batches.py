import concurrent.futures
import datetime as dt
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

from scripts import private_release_v2_bootstrap as bootstrap
from scripts import private_release_v2_bootstrap_observe as observe
from tests import test_private_release_v2_bootstrap_observe as fixtures


def requests(count):
    return [observe.ReadRequest("GET", (
        "https://management.azure.com/subscriptions/"
        f"{bootstrap.SUBSCRIPTION}/providers/Microsoft.Resources/deployments/"
        f"probe-{index}?api-version=2022-09-01"
    )) for index in range(count)]


class BatchTests(unittest.TestCase):
    def test_four_isolated_workers_return_input_order_despite_completion_order(self):
        batch = observe.AzureCliReadOnlySession()
        barrier = threading.Barrier(4, timeout=5)
        lock = threading.Lock()
        active = 0
        peak = 0
        completed = []

        class Worker:
            def __init__(self, index):
                self.index = index
                self.calls = 0
                self.busy = False

            def read(self, request):
                nonlocal active, peak
                with lock:
                    if self.busy:
                        raise AssertionError("a worker session was shared concurrently")
                    self.busy = True
                    active += 1
                    peak = max(peak, active)
                if self.calls == 0:
                    barrier.wait()
                self.calls += 1
                time.sleep((4 - self.index) * 0.003)
                with lock:
                    active -= 1
                    self.busy = False
                    completed.append(request.url)
                return observe.ReadResponse(request.method, request.url, 200, {}, {})

        batch._batch_sessions = [Worker(index) for index in range(4)]
        inputs = requests(12)
        responses = observe._read_many(batch, inputs)
        self.assertEqual([item.url for item in responses], [item.url for item in inputs])
        self.assertEqual(peak, 4)
        self.assertNotEqual(completed, [item.url for item in inputs])
        self.assertEqual([worker.calls for worker in batch._batch_sessions], [3] * 4)

    def test_invalid_batch_stops_before_account_or_http_access(self):
        batch = observe.AzureCliReadOnlySession()
        invalid = requests(1)[0]
        object.__setattr__(invalid, "method", "DELETE")
        with mock.patch.object(batch, "account", side_effect=AssertionError("account called")):
            for inputs in ([invalid], requests(129), [object()]):
                with self.assertRaises(observe.ObserveError):
                    batch.read_many(inputs)
            self.assertEqual(batch.read_many([]), [])

    def test_worker_failure_drains_inflight_and_stops_remaining_partition_reads(self):
        batch = observe.AzureCliReadOnlySession()
        barrier = threading.Barrier(4, timeout=5)
        released = threading.Event()
        completed = []

        class Worker:
            def __init__(self, index):
                self.index = index

            def read(self, request):
                barrier.wait()
                if self.index == 0:
                    released.set()
                    raise observe.ObserveError("fixture read failed")
                released.wait(5)
                time.sleep(0.01)
                completed.append(self.index)
                return observe.ReadResponse(request.method, request.url, 200, {}, {})

        batch._batch_sessions = [Worker(index) for index in range(4)]
        with self.assertRaisesRegex(observe.ObserveError, "fixture read failed"):
            batch.read_many(requests(20))
        self.assertEqual(sorted(completed), [1, 2, 3])

    def test_missing_or_reordered_batch_responses_fail_closed(self):
        inputs = requests(2)
        replies = [observe.ReadResponse(item.method, item.url, 200, {}, {}) for item in inputs]
        for output in (replies[:1], list(reversed(replies)), [object(), replies[1]]):
            batch = mock.Mock(read_many=mock.Mock(return_value=output))
            with self.assertRaises(observe.ObserveError):
                observe._read_many(batch, inputs)

    def test_worker_azure_cli_credential_operations_are_serialized(self):
        lock = threading.Lock()
        active = 0
        peak = 0

        def fake_cli(arguments, label):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            time.sleep(0.01)
            active -= 1
            return {"fixture": True}

        children = [observe._SerializedCredentialSession({}, clock=lambda: fixtures.NOW,
                    credential_lock=lock) for _ in range(4)]
        with mock.patch.object(bootstrap.AzureCliRestSession, "_run_az_json", side_effect=fake_cli):
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(lambda child: child._run_az_json([], "fixture"), children))
        self.assertEqual(peak, 1)
        self.assertEqual(results, [{"fixture": True}] * 4)

    def test_production_batch_workers_bind_the_exact_account_with_separate_rest_state(self):
        plan, _ = bootstrap.load_plan()
        account = dict(fixtures.FakeReadOnlySession(plan).account())
        batch = observe.AzureCliReadOnlySession(clock=lambda: fixtures.NOW)
        response = bootstrap._RestResponse(200, b"{}", {"Content-Type": "application/json"})
        with mock.patch.object(batch, "account", return_value=account) as inspect_account:
            with mock.patch.object(observe._SerializedCredentialSession, "request", return_value=response):
                self.assertEqual(len(batch.read_many(requests(8))), 8)
                self.assertEqual(len(batch.read_many(requests(4))), 4)
        inspect_account.assert_called_once()
        sessions = [child._session for child in batch._batch_sessions]
        self.assertEqual(len({id(session) for session in sessions}), 4)
        self.assertEqual(len({id(session._tokens) for session in sessions}), 4)
        self.assertEqual(len({id(session._storage_client_request_ids) for session in sessions}), 4)
        self.assertTrue(all(session.authorization == {"azure": account} for session in sessions))
        self.assertTrue(all(session._credential_lock is batch._credential_lock for session in sessions))

    def test_concurrent_full_observation_matches_serial_canonical_bytes_and_freshness(self):
        plan, _ = bootstrap.load_plan()
        batch = observe.AzureCliReadOnlySession(clock=lambda: fixtures.NOW)
        parent = fixtures.FakeReadOnlySession(plan)
        batch._account = dict(parent.account())
        batch._batch_sessions = [fixtures.FakeReadOnlySession(plan) for _ in range(4)]
        # The cleanup-lock inventory is deliberately still a direct serial read.
        batch.read = parent.read
        with tempfile.TemporaryDirectory() as folder:
            kwargs = dict(source=fixtures.source_evidence(), authorization_id=fixtures.AUTHORIZATION_ID,
                          receipt_directory=Path(folder) / ("paperdesk-private-release-v2-bootstrap-" + fixtures.AUTHORIZATION_ID),
                          observed_at=fixtures.NOW, uploader_ipv4="203.0.113.10/32")
            serial = observe.build_read_only_observation(fixtures.FakeReadOnlySession(plan), **kwargs)
            parallel = observe.build_read_only_observation(batch, **kwargs)
        self.assertEqual(bootstrap.canonical_json_bytes(serial), bootstrap.canonical_json_bytes(parallel))
        preflight, template = parallel
        self.assertEqual(bootstrap.parse_time(preflight["observedAt"], "observed"), fixtures.NOW)
        self.assertEqual(template["observedPreflight"]["maximumAgeSeconds"], 300)
        self.assertFalse(template["executable"])
        self.assertNotIn("validity", template)
        self.assertNotIn("confirmation", template)
        self.assertEqual(bootstrap.parse_time(template["proposedValidity"]["notBefore"], "start"), fixtures.NOW)
        self.assertEqual(bootstrap.parse_time(template["proposedValidity"]["expiresAt"], "end"),
                         fixtures.NOW + dt.timedelta(seconds=3900))


if __name__ == "__main__":
    unittest.main()
