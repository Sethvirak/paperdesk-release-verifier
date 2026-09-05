"""Focused controller-canary ownership and compensation regressions."""

import copy
import datetime as dt
from pathlib import Path
import tempfile
import unittest

from scripts import private_release_v2_bootstrap as bootstrap
from tests.test_private_release_v2_bootstrap import (
    AUTH_ID,
    ACCOUNT_OBJECT,
    FakeTransport,
    MERGE,
    NOW,
    PARENT,
    PHRASE,
    TREE,
    _TerminalEvidenceFixture,
    build_authorization,
    stamp,
)
from tests.test_private_release_v2_package_readiness import MemoryJournal, Session


CREATE = "createControllerLeaseCanaryBlob"
REMOVE = "removeControllerLeaseCanaryBlob"
CONFIGURE = "configureBridgeExactVersionedPackageAndCriticalSettings"
ETAG = '"controller-canary-etag"'
VERSION_ID = "2026-09-04T01:02:03.0000000Z"


def storage_error(status, code):
    return bootstrap._RestResponse(
        status,
        (
            '<?xml version="1.0" encoding="utf-8"?>'
            f"<Error><Code>{code}</Code>"
            "<Message>The specified blob does not exist.\n"
            "RequestId:11111111-2222-3333-4444-555555555555\n"
            "Time:2026-09-04T01:02:03.4567890Z</Message></Error>"
        ).encode("utf-8"),
        {"Content-Type": "application/xml", "x-ms-error-code": code},
    )


class ControllerCanaryFailureTests(unittest.TestCase):
    def setUp(self):
        plan, plan_sha = bootstrap.load_plan()
        package = {"sha256": "a" * 64, "size": 4096}
        self.fixture = _TerminalEvidenceFixture(
            plan,
            plan_sha,
            package,
            Path(__file__).resolve().parents[2]
            / ("paperdesk-private-release-v2-bootstrap-" + AUTH_ID),
        )
        self.plan_sha = plan_sha
        self.fixture.authorization["validity"] = {
            "notBefore": stamp(NOW),
            "expiresAt": stamp(
                NOW + dt.timedelta(seconds=bootstrap.MAX_AUTHORIZATION_SECONDS)
            ),
            "maximumLifetimeSeconds": bootstrap.MAX_AUTHORIZATION_SECONDS,
        }
        self.plan = plan
        self.authorization = self.fixture.authorization
        self.create_contract = bootstrap._validator_contract(
            f"operation:{CREATE}", plan, self.authorization
        )
        self.remove_contract = bootstrap._validator_contract(
            f"operation:{REMOVE}", plan, self.authorization
        )

    def canary_body(self):
        return bootstrap.canonical_json_bytes(
            {
                "schemaVersion": 1,
                "mode": "controller-lock-finite-lease-canary",
                "authorizationId": self.authorization["authorizationId"],
                "sourceSha": self.authorization["source"]["mergedMain"][
                    "commitSha"
                ],
                "planSha256": self.authorization["plan"]["sha256"],
            }
        )

    @staticmethod
    def settings_response(settings, etag=None, *, body_etag=None):
        document = {"properties": settings}
        if body_etag is not None:
            document["etag"] = body_etag
        headers = {"Content-Type": "application/json"}
        if etag is not None:
            headers["ETag"] = etag
        return bootstrap._RestResponse(
            200,
            bootstrap.canonical_json_bytes(document),
            headers,
        )

    def bridge_state(self):
        if not self.fixture.operations:
            self.fixture.build_operations()
        bridge = self.fixture.operations["createBridgeIdentity"]["projection"]
        fence = self.fixture.operations[
            "createInitialIdleActivationFence"
        ]["projection"]
        upload = self.fixture.operations["uploadVersionedBridgePackage"][
            "projection"
        ]
        return {
            "proofs": {
                "createBridgeIdentity": {
                    "details": {
                        "resourceId": bridge["id"],
                        "clientId": bridge["clientId"],
                        "principalId": bridge["principalId"],
                    }
                },
                "createInitialIdleActivationFence": {
                    "details": {
                        key: fence[key]
                        for key in ("url", "etag", "versionId", "sha256")
                    }
                },
                "uploadVersionedBridgePackage": {
                    "details": {
                        key: upload[key]
                        for key in ("blob", "etag", "versionId", "url")
                    }
                },
            }
        }

    def desired_bridge_settings(self, details):
        context = next(
            item["context"]
            for item in self.fixture.projection["operationAdmissions"]
            if item["operationId"] == CONFIGURE
        )
        desired = dict(context["preAppSettings"])
        desired.update(
            {
                "WEBSITE_RUN_FROM_PACKAGE": details["packageUrl"],
                "WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID": self.fixture.resources[
                    "registryReaderIdentity"
                ]["resourceId"],
                "WEBSITE_SKIP_RUNNING_KUDUAGENT": "false",
                "PAPERDESK_BRIDGE_PACKAGE_SHA256": self.fixture.package["sha256"],
                "PAPERDESK_BRIDGE_BOOTSTRAP_SELF_TEST_JSON": (
                    bootstrap.canonical_json_bytes(
                        details["bootstrapSelfTestControl"]
                    ).decode("utf-8")
                ),
            }
        )
        return desired

    def bridge_transport(self, responses, *, clock=None, journal=None):
        session = Session(responses)
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=self.authorization,
            plan=self.plan,
            package=self.fixture.package,
            preflight={"projection": self.fixture.projection},
            session=session,
            clock=clock or (lambda: NOW),
            sleep=lambda _seconds: None,
        )
        transport.bind_journal(journal or MemoryJournal())
        transport._active_operation_id = CONFIGURE
        return transport, session

    def transport(self, responses, operation_id, *, clock=None, sleep=None):
        session = Session(responses)
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=self.authorization,
            plan=self.plan,
            package=self.fixture.package,
            preflight={"projection": self.fixture.projection},
            session=session,
            clock=clock or (lambda: NOW),
            sleep=sleep or (lambda _seconds: None),
        )
        journal = MemoryJournal()
        transport.bind_journal(journal)
        transport._active_operation_id = operation_id
        if operation_id == CREATE:
            transport._active_protected_role_add = (
                "addOwnedOperatorControllerCanaryRole"
            )
        return transport, session, journal

    @staticmethod
    def source(_authorization):
        return {
            "repository": bootstrap.REPOSITORY,
            "headSha": MERGE,
            "treeSha": TREE,
            "soleParentSha": PARENT,
            "originMainSha": MERGE,
        }

    def validated_inputs(
        self,
        folder,
        *,
        projection=None,
        lifetime_seconds=None,
    ):
        projection = copy.deepcopy(projection or self.fixture.projection)
        receipt = (
            Path(folder)
            / ("paperdesk-private-release-v2-bootstrap-" + AUTH_ID)
        )
        authorization = build_authorization(
            self.plan,
            self.plan_sha,
            self.fixture.package,
            projection,
            receipt,
        )
        if lifetime_seconds is not None:
            authorization["validity"] = {
                "notBefore": stamp(NOW),
                "expiresAt": stamp(
                    NOW + dt.timedelta(seconds=lifetime_seconds)
                ),
                "maximumLifetimeSeconds": bootstrap.MAX_AUTHORIZATION_SECONDS,
            }
        authorization_path = Path(folder) / "authorization.json"
        authorization_path.write_bytes(
            bootstrap.canonical_json_bytes(authorization)
        )
        validated = bootstrap.validate_authorization(
            authorization_path,
            plan=self.plan,
            plan_sha256=self.plan_sha,
            package=self.fixture.package,
            confirmation_phrase=PHRASE,
            now=NOW,
        )
        return validated, {"projection": projection}, receipt

    def executor(self, validated, preflight, transport, now):
        return bootstrap.BootstrapExecutor(
            plan=self.plan,
            plan_sha256=self.plan_sha,
            package=self.fixture.package,
            authorization=validated,
            preflight=preflight,
            transport=transport,
            now=now,
            source_validator=self.source,
        )

    def test_definitive_409_create_does_not_reconcile_or_claim_ownership(self):
        transport, session, journal = self.transport(
            [storage_error(409, "BlobAlreadyExists")], CREATE
        )

        with self.assertRaises(bootstrap.StorageOperationError) as raised:
            transport._mutate(self.fixture.mutations[CREATE], {})

        self.assertNotIsInstance(
            raised.exception, bootstrap.OwnedTemporaryMutationError
        )
        self.assertEqual(raised.exception.diagnostic["status"], 409)
        self.assertEqual(
            raised.exception.diagnostic["stopReason"], "unexpected-status"
        )
        self.assertEqual([request[0] for request in session.requests], ["PUT"])
        self.assertEqual(
            [record["phase"] for record in journal.records], ["intent", "result"]
        )

    def test_201_result_journal_failure_reconciles_by_exact_get(self):
        body = self.canary_body()
        digest = bootstrap.sha256_bytes(body)
        created = bootstrap._RestResponse(
            201,
            b"",
            {"ETag": ETAG, "x-ms-version-id": VERSION_ID},
        )
        exact_get = bootstrap._RestResponse(
            200,
            body,
            {
                "Content-Type": "application/json",
                "ETag": ETAG,
                "x-ms-version-id": VERSION_ID,
                "x-ms-meta-sha256": digest,
                "x-ms-blob-type": "BlockBlob",
            },
        )
        transport, session, journal = self.transport([created, exact_get], CREATE)
        journal.fail_result = True

        with self.assertRaises(bootstrap.OwnedTemporaryMutationError) as raised:
            transport._mutate(self.fixture.mutations[CREATE], {})

        self.assertEqual([request[0] for request in session.requests], ["PUT", "GET"])
        self.assertEqual(session.requests[1][1], self.create_contract["expectedUrl"])
        self.assertEqual([record["phase"] for record in journal.records], ["intent"])
        self.assertTrue(raised.exception.proof["owned"])
        self.assertEqual(raised.exception.proof["details"]["etag"], ETAG)
        self.assertEqual(
            raised.exception.proof["details"]["versionId"], VERSION_ID
        )
        self.assertEqual(raised.exception.proof["details"]["sha256"], digest)
        self.assertIsInstance(raised.exception.__cause__, bootstrap.StorageOperationError)
        self.assertEqual(
            raised.exception.__cause__.diagnostic["stopReason"],
            "result-journal-error",
        )
        self.assertEqual(raised.exception.__cause__.diagnostic["status"], 201)

    def test_500_after_applied_create_reconciles_and_compensates_exactly(self):
        body = self.canary_body()
        digest = bootstrap.sha256_bytes(body)
        exact_get = bootstrap._RestResponse(
            200,
            body,
            {
                "Content-Type": "application/json",
                "ETag": ETAG,
                "x-ms-version-id": VERSION_ID,
                "x-ms-meta-sha256": digest,
                "x-ms-blob-type": "BlockBlob",
            },
        )
        empty_inventory = bootstrap._RestResponse(
            200,
            b"<EnumerationResults><Blobs/><NextMarker/></EnumerationResults>",
            {"Content-Type": "application/xml"},
        )
        transport, session, _journal = self.transport(
            [
                storage_error(500, "InternalError"),
                exact_get,
                bootstrap._RestResponse(202, b"", {}),
                empty_inventory,
                storage_error(404, "BlobNotFound"),
            ],
            CREATE,
        )
        controller = transport.resources["controllerLockContainer"]
        transport._validated_source_projections[
            "createPrivateControllerLockContainer"
        ] = {
            "projection": {
                "id": controller["resourceId"],
                "name": controller["name"],
                "type": (
                    "Microsoft.Storage/storageAccounts/blobServices/containers"
                ),
                "publicAccess": "None",
            }
        }

        with self.assertRaises(bootstrap.OwnedTemporaryMutationError) as raised:
            transport._mutate(self.fixture.mutations[CREATE], {})

        cleanup = transport.compensate_temporary(
            self.fixture.mutations[CREATE],
            raised.exception.proof,
            {"proofs": {CREATE: raised.exception.proof}},
        )
        self.assertEqual(cleanup["status"], "removed-exact")
        self.assertEqual(
            [request[0] for request in session.requests],
            ["PUT", "GET", "DELETE", "GET", "GET"],
        )
        self.assertEqual(session.requests[2][3]["If-Match"], ETAG)

    def test_500_create_immediate_absence_keeps_ownership_for_late_commit(self):
        body = self.canary_body()
        digest = bootstrap.sha256_bytes(body)
        late_exact_get = bootstrap._RestResponse(
            200,
            body,
            {
                "Content-Type": "application/json",
                "ETag": ETAG,
                "x-ms-version-id": VERSION_ID,
                "x-ms-meta-sha256": digest,
                "x-ms-blob-type": "BlockBlob",
            },
        )
        empty_inventory = bootstrap._RestResponse(
            200,
            b"<EnumerationResults><Blobs/><NextMarker/></EnumerationResults>",
            {"Content-Type": "application/xml"},
        )
        current = [NOW]
        observation_starts = []
        alignment_jitter = dt.timedelta(milliseconds=1)

        def slow_stale_absence():
            observation_starts.append(current[0])
            current[0] += dt.timedelta(
                seconds=bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS - 1
            )
            return storage_error(404, "BlobNotFound")

        def exact_after_boundary():
            observation_starts.append(current[0])
            return late_exact_get

        transport, session, _journal = self.transport(
            [
                storage_error(500, "InternalError"),
                storage_error(404, "BlobNotFound"),
                slow_stale_absence,
                exact_after_boundary,
                bootstrap._RestResponse(202, b"", {}),
                empty_inventory,
                storage_error(404, "BlobNotFound"),
            ],
            CREATE,
            clock=lambda: current[0],
            sleep=lambda seconds: current.__setitem__(
                0,
                current[0]
                + dt.timedelta(seconds=seconds)
                + alignment_jitter,
            ),
        )
        controller = transport.resources["controllerLockContainer"]
        transport._validated_source_projections[
            "createPrivateControllerLockContainer"
        ] = {
            "projection": {
                "id": controller["resourceId"],
                "name": controller["name"],
                "type": (
                    "Microsoft.Storage/storageAccounts/blobServices/containers"
                ),
                "publicAccess": "None",
            }
        }

        with self.assertRaises(bootstrap.OwnedTemporaryMutationError) as raised:
            transport._mutate(self.fixture.mutations[CREATE], {})

        self.assertEqual(
            raised.exception.__cause__.diagnostic["status"], 500
        )
        cleanup = transport.compensate_temporary(
            self.fixture.mutations[CREATE],
            raised.exception.proof,
            {"proofs": {CREATE: raised.exception.proof}},
        )
        self.assertEqual(cleanup["status"], "removed-exact")
        self.assertEqual(
            [request[0] for request in session.requests],
            ["PUT", "GET", "GET", "GET", "DELETE", "GET", "GET"],
        )
        self.assertEqual(
            observation_starts,
            [
                NOW,
                NOW
                + dt.timedelta(
                    seconds=bootstrap.CONTROLLER_CANARY_CREATE_SETTLEMENT_SECONDS
                )
                + alignment_jitter,
            ],
        )
        self.assertEqual(
            session.deadlines[2],
            NOW
            + dt.timedelta(
                seconds=bootstrap.CONTROLLER_CANARY_CREATE_SETTLEMENT_SECONDS
            ),
        )
        self.assertEqual(
            session.deadlines[3],
            observation_starts[-1]
            + dt.timedelta(
                seconds=bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS
            ),
        )
        self.assertEqual(session.requests[4][3]["If-Match"], ETAG)

    def test_ambiguous_create_rejects_alignment_overshoot_beyond_slack(self):
        current = [NOW]
        observation_starts = []
        overshoot = dt.timedelta(
            seconds=(
                bootstrap.FINAL_OBSERVATION_ALIGNMENT_SLACK_SECONDS
                + 0.001
            )
        )

        def slow_stale_absence():
            observation_starts.append(current[0])
            current[0] += dt.timedelta(
                seconds=bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS - 1
            )
            return storage_error(404, "BlobNotFound")

        transport, session, _journal = self.transport(
            [
                storage_error(500, "InternalError"),
                storage_error(404, "BlobNotFound"),
                slow_stale_absence,
            ],
            CREATE,
            clock=lambda: current[0],
            sleep=lambda seconds: current.__setitem__(
                0,
                current[0] + dt.timedelta(seconds=seconds) + overshoot,
            ),
        )
        controller = transport.resources["controllerLockContainer"]
        transport._validated_source_projections[
            "createPrivateControllerLockContainer"
        ] = {
            "projection": {
                "id": controller["resourceId"],
                "name": controller["name"],
                "type": (
                    "Microsoft.Storage/storageAccounts/blobServices/containers"
                ),
                "publicAccess": "None",
            }
        }

        with self.assertRaises(bootstrap.OwnedTemporaryMutationError) as raised:
            transport._mutate(self.fixture.mutations[CREATE], {})

        with self.assertRaisesRegex(
            bootstrap.BootstrapError,
            "controller canary create-settlement clock is invalid",
        ):
            transport.compensate_temporary(
                self.fixture.mutations[CREATE],
                raised.exception.proof,
                {"proofs": {CREATE: raised.exception.proof}},
            )
        self.assertEqual(observation_starts, [NOW])
        self.assertEqual(
            [request[0] for request in session.requests],
            ["PUT", "GET", "GET"],
        )

    def test_realistic_xml_blob_not_found_is_a_valid_final_absence_proof(self):
        transport, _session, _journal = self.transport([], REMOVE)
        container_url = (
            f"{transport.STORAGE_ROOT}/"
            f"{transport.resources['controllerLockContainer']['name']}"
        )
        inventory = {
            "containerUrl": container_url,
            "listUrl": container_url + "?restype=container&comp=list",
            "httpStatus": 200,
            "blobNames": [],
            "blobCount": 0,
            "nextMarker": "",
        }
        expected = {
            "id": "readback:remove-controller-canary",
            "validatorId": f"operation:{REMOVE}",
            "method": self.remove_contract["expectedMethod"],
            "url": self.remove_contract["expectedUrl"],
            "validatorContract": self.remove_contract,
        }

        proof = transport._validate_readback_response(
            expected,
            storage_error(404, "BlobNotFound"),
            runtime_facts={"controllerLockInventory": inventory},
        )

        self.assertEqual(proof["status"], 404)
        self.assertEqual(
            proof["sourceProjection"]["family"],
            "controller-lock-empty-after-canary",
        )
        self.assertEqual(
            proof["sourceProjection"]["projection"]["controllerLockInventory"],
            inventory,
        )

    def test_ambiguous_first_conditional_delete_is_retried_once(self):
        empty_inventory = bootstrap._RestResponse(
            200,
            b"<EnumerationResults><Blobs/><NextMarker/></EnumerationResults>",
            {"Content-Type": "application/xml"},
        )
        transport, session, journal = self.transport(
            [
                RuntimeError("simulated ambiguous conditional DELETE"),
                storage_error(404, "BlobNotFound"),
                empty_inventory,
            ],
            REMOVE,
        )
        controller = transport.resources["controllerLockContainer"]
        transport._validated_source_projections[
            "createPrivateControllerLockContainer"
        ] = {
            "projection": {
                "id": controller["resourceId"],
                "name": controller["name"],
                "type": (
                    "Microsoft.Storage/storageAccounts/blobServices/containers"
                ),
                "publicAccess": "None",
            }
        }
        state = {
            "proofs": {
                CREATE: {
                    "details": {
                        "url": self.create_contract["expectedUrl"],
                        "etag": ETAG,
                        "sha256": bootstrap.sha256_bytes(self.canary_body()),
                        "cleanupKey": "controller-lease-canary-blob",
                    }
                }
            }
        }

        result = transport._mutate(self.fixture.mutations[REMOVE], state)

        self.assertEqual([request[0] for request in session.requests], ["DELETE", "DELETE", "GET"])
        first_headers = session.requests[0][3]
        second_headers = session.requests[1][3]
        self.assertEqual(first_headers["If-Match"], ETAG)
        self.assertEqual(second_headers["If-Match"], ETAG)
        self.assertEqual(
            {
                key: value
                for key, value in first_headers.items()
                if key != "x-ms-client-request-id"
            },
            {
                key: value
                for key, value in second_headers.items()
                if key != "x-ms-client-request-id"
            },
        )
        self.assertNotEqual(
            first_headers["x-ms-client-request-id"],
            second_headers["x-ms-client-request-id"],
        )
        self.assertTrue(
            bootstrap.GUID.fullmatch(first_headers["x-ms-client-request-id"])
        )
        self.assertTrue(
            bootstrap.GUID.fullmatch(second_headers["x-ms-client-request-id"])
        )
        self.assertEqual(
            session.deadlines[:2],
            [
                transport._controller_canary_blob_delete_deadline(),
                transport._controller_canary_blob_delete_retry_deadline(),
            ],
        )
        self.assertEqual(
            [record["phase"] for record in journal.records],
            ["intent", "intent", "result"],
        )
        self.assertEqual(result["deleteStatus"], 404)
        self.assertEqual(result["controllerLockInventory"]["blobCount"], 0)
        self.assertTrue(result["_cleanupResolvedAfterAmbiguity"])

    def test_full_release_and_expiry_fallback_preserve_every_cleanup_envelope(self):
        current = [NOW]
        sleeps = []
        transport = None

        class TimelineSession:
            def __init__(self):
                self.requests = []
                self.delete_attempts = 0

            def request(
                self, method, url, *, body=None, headers=None, deadline=None
            ):
                request_headers = dict(headers or {})
                self.requests.append(
                    (method, url, body, request_headers, deadline)
                )
                action = request_headers.get("x-ms-lease-action")
                if action == "acquire":
                    current[0] = deadline - dt.timedelta(milliseconds=1)
                    return bootstrap._RestResponse(201, b"", {})
                if action == "renew":
                    current[0] = deadline - dt.timedelta(milliseconds=1)
                    return bootstrap._RestResponse(200, b"", {})
                if action == "release":
                    current[0] = deadline - dt.timedelta(milliseconds=1)
                    raise RuntimeError("simulated full-envelope release ambiguity")
                if method == "DELETE":
                    self.delete_attempts += 1
                    current[0] = deadline - dt.timedelta(milliseconds=1)
                    if self.delete_attempts == 1:
                        raise RuntimeError(
                            "simulated full-envelope conditional DELETE ambiguity"
                        )
                    return bootstrap._RestResponse(202, b"", {})
                if "restype=container&comp=list" in url:
                    current[0] = deadline - dt.timedelta(milliseconds=1)
                    return bootstrap._RestResponse(
                        200,
                        (
                            b"<EnumerationResults><Blobs/><NextMarker/>"
                            b"</EnumerationResults>"
                        ),
                        {"Content-Type": "application/xml"},
                    )
                if method == "GET" and url == self_outer.create_contract["expectedUrl"]:
                    current[0] = deadline - dt.timedelta(milliseconds=1)
                    return storage_error(404, "BlobNotFound")
                raise AssertionError(f"unexpected timeline request: {method} {url}")

        self_outer = self
        session = TimelineSession()

        def sleep(seconds):
            sleeps.append(seconds)
            current[0] += dt.timedelta(seconds=seconds)

        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=self.authorization,
            plan=self.plan,
            package=self.fixture.package,
            preflight={"projection": self.fixture.projection},
            session=session,
            clock=lambda: current[0],
            sleep=sleep,
        )
        journal = MemoryJournal()
        transport.bind_journal(journal)
        transport._active_protected_role_add = (
            "addOwnedOperatorControllerCanaryRole"
        )
        transport._protected_work_deadline = transport._protected_role_deadline(
            bootstrap.CONTROLLER_CANARY_CLEANUP_RESERVE_SECONDS
        )
        controller = transport.resources["controllerLockContainer"]
        transport._validated_source_projections[
            "createPrivateControllerLockContainer"
        ] = {
            "projection": {
                "id": controller["resourceId"],
                "name": controller["name"],
                "type": (
                    "Microsoft.Storage/storageAccounts/blobServices/containers"
                ),
                "publicAccess": "None",
            }
        }
        state = {
            "proofs": {
                CREATE: {
                    "details": {
                        "url": self.create_contract["expectedUrl"],
                        "etag": ETAG,
                        "sha256": bootstrap.sha256_bytes(self.canary_body()),
                        "cleanupKey": "controller-lease-canary-blob",
                    }
                }
            }
        }

        transport._active_operation_id = "exerciseControllerLeaseCanary"
        with self.assertRaises(bootstrap.StorageOperationError):
            transport._mutate(
                self.fixture.mutations["exerciseControllerLeaseCanary"], state
            )

        epsilon = dt.timedelta(milliseconds=1)
        self.assertEqual(
            current[0],
            transport._controller_canary_expiry_acquire_deadline()
            - dt.timedelta(seconds=30)
            - epsilon,
        )
        self.assertEqual(
            sleeps, [bootstrap.CONTROLLER_CANARY_LEASE_DURATION_SECONDS]
        )

        with self.assertRaises(
            bootstrap.CleanupResolvedMutationError
        ) as cleanup_resolved:
            transport.apply_operation(self.fixture.mutations[REMOVE], state)
        proof = cleanup_resolved.exception.proof

        release_request = next(
            request
            for request in session.requests
            if request[3].get("x-ms-lease-action") == "release"
        )
        delete_requests = [
            request for request in session.requests if request[0] == "DELETE"
        ]
        inventory_request = next(
            request
            for request in session.requests
            if "restype=container&comp=list" in request[1]
        )
        final_request = next(
            request
            for request in session.requests
            if request[0] == "GET"
            and request[1] == self.create_contract["expectedUrl"]
        )
        self.assertEqual(
            release_request[4], transport._controller_canary_release_deadline()
        )
        self.assertEqual(
            [request[4] for request in delete_requests],
            [
                transport._controller_canary_blob_delete_deadline(),
                transport._controller_canary_blob_delete_retry_deadline(),
            ],
        )
        self.assertEqual(
            inventory_request[4], transport._controller_canary_inventory_deadline()
        )
        self.assertEqual(
            final_request[4], transport._controller_canary_final_probe_deadline()
        )
        self.assertEqual(
            current[0], transport._controller_canary_final_probe_deadline() - epsilon
        )
        self.assertEqual(proof["status"], "cleanup-resolved-failure")
        self.assertEqual(
            proof["details"]["readbackProjections"][0]["projection"]["absent"],
            True,
        )

    def test_full_readiness_and_nominal_canary_keep_every_request_envelope(self):
        current = [NOW]
        sleeps = []
        epsilon = dt.timedelta(milliseconds=1)
        transport_box = {}

        class FullTimelineSession:
            def __init__(self):
                self.requests = []
                self.readiness_complete = False
                self.readiness_started = None
                self.deleted = False

            def request(
                self, method, url, *, body=None, headers=None, deadline=None
            ):
                request_headers = dict(headers or {})
                self.requests.append(
                    (method, url, body, request_headers, deadline)
                )
                transport = transport_box["transport"]
                action = request_headers.get("x-ms-lease-action")
                if "restype=container&comp=list" in url:
                    if not self.readiness_complete:
                        final_request_at = (
                            transport._controller_canary_readiness_deadline()
                            - dt.timedelta(
                                seconds=(
                                    bootstrap.STORAGE_REQUEST_DEADLINE_RESERVE_SECONDS
                                )
                            )
                        )
                        if current[0] < final_request_at - dt.timedelta(
                            seconds=15
                        ):
                            return bootstrap._RestResponse(
                                403,
                                (
                                    b"<Error><Code>AuthorizationPermissionMismatch</Code>"
                                    b"<Message>propagating</Message></Error>"
                                ),
                                {"Content-Type": "application/xml"},
                            )
                        current[0] = self.readiness_started + dt.timedelta(
                            seconds=590
                        )
                        self.readiness_complete = True
                    else:
                        current[0] = deadline - epsilon
                    return bootstrap._RestResponse(
                        200,
                        (
                            b"<EnumerationResults><Blobs/><NextMarker/>"
                            b"</EnumerationResults>"
                        ),
                        {"Content-Type": "application/xml"},
                    )
                if method == "PUT" and action is None:
                    current[0] = deadline - epsilon
                    return bootstrap._RestResponse(
                        201,
                        b"",
                        {"ETag": ETAG, "x-ms-version-id": VERSION_ID},
                    )
                if action is not None:
                    current[0] = deadline - epsilon
                    return bootstrap._RestResponse(
                        201 if action == "acquire" else 200,
                        b"",
                        {},
                    )
                if method == "DELETE":
                    current[0] = deadline - epsilon
                    self.deleted = True
                    return bootstrap._RestResponse(202, b"", {})
                if method == "GET" and url == self_outer.create_contract["expectedUrl"]:
                    current[0] = deadline - epsilon
                    if self.deleted:
                        return storage_error(404, "BlobNotFound")
                    return bootstrap._RestResponse(
                        200,
                        b"",
                        {
                            "x-ms-lease-state": "expired",
                            "x-ms-lease-status": "unlocked",
                            "x-ms-lease-duration": "fixed",
                        },
                    )
                raise AssertionError(
                    f"unexpected full-timeline request: {method} {url}"
                )

        self_outer = self
        session = FullTimelineSession()

        def sleep(seconds):
            sleeps.append(seconds)
            current[0] += dt.timedelta(seconds=seconds)

        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=self.authorization,
            plan=self.plan,
            package=self.fixture.package,
            preflight={"projection": self.fixture.projection},
            session=session,
            clock=lambda: current[0],
            sleep=sleep,
        )
        transport_box["transport"] = transport
        journal = MemoryJournal()
        transport.bind_journal(journal)
        controller = transport.resources["controllerLockContainer"]
        transport._validated_source_projections[
            "createPrivateControllerLockContainer"
        ] = {
            "projection": {
                "id": controller["resourceId"],
                "name": controller["name"],
                "type": (
                    "Microsoft.Storage/storageAccounts/blobServices/containers"
                ),
                "publicAccess": "None",
            }
        }

        current[0] = (
            transport._controller_canary_role_admission_start_deadline()
            - epsilon
        )
        transport._begin_protected_role_lifecycle(
            "addOwnedOperatorControllerCanaryRole"
        )
        current[0] += dt.timedelta(
            seconds=bootstrap.CONTROLLER_CANARY_ROLE_ADMISSION_ALLOWANCE_SECONDS
        )
        readiness_started = current[0]
        session.readiness_started = readiness_started
        ids = transport.admissions[
            "proveControllerLockContainerEmpty"
        ]["desiredProbeIds"]
        readiness = transport._prove_controller_lock_container_empty(ids)
        self.assertGreaterEqual(
            (current[0] - readiness_started).total_seconds(), 590
        )
        self.assertLess(
            (current[0] - readiness_started).total_seconds(), 600
        )
        self.assertEqual(readiness[0]["status"], 200)

        transport._active_operation_id = CREATE
        created = transport._mutate(self.fixture.mutations[CREATE], {})
        state = {
            "proofs": {
                CREATE: {
                    "operationId": CREATE,
                    "status": "created",
                    "owned": True,
                    "cleanupKey": "controller-lease-canary-blob",
                    "details": created,
                }
            }
        }
        transport._active_operation_id = "exerciseControllerLeaseCanary"
        exercised = transport._mutate(
            self.fixture.mutations["exerciseControllerLeaseCanary"], state
        )
        self.assertEqual(exercised["renewals"], 1)
        self.assertEqual(
            exercised["expiryFallback"]["finalLeaseState"], "expired"
        )
        transport._active_operation_id = None
        removed = transport.apply_operation(
            self.fixture.mutations[REMOVE], state
        )
        self.assertEqual(removed["status"], "removed-exact")
        self.assertEqual(current[0], transport._controller_canary_final_probe_deadline() - epsilon)

        create_requests = [
            request
            for request in session.requests
            if request[0] == "PUT"
            and request[1] == self.create_contract["expectedUrl"]
            and "x-ms-lease-action" not in request[3]
        ]
        self.assertEqual(len(create_requests), 1)
        self.assertEqual(
            create_requests[0][4], transport._controller_canary_create_deadline()
        )
        lease_deadlines = [
            request[4]
            for request in session.requests
            if request[3].get("x-ms-lease-action") is not None
        ]
        self.assertEqual(
            lease_deadlines,
            [
                transport._controller_canary_fast_acquire_deadline(),
                transport._controller_canary_fast_renew_deadline(),
                transport._controller_canary_release_deadline(),
                transport._controller_canary_expiry_acquire_deadline(),
            ],
        )
        self.assertIn(
            bootstrap.CONTROLLER_CANARY_LEASE_DURATION_SECONDS, sleeps
        )

    def test_finite_lease_poll_preserves_a_second_get_envelope(self):
        current = [NOW]
        sleeps = []

        class LeasePollSession:
            def __init__(self):
                self.requests = []
                self.expiry_reads = 0

            def request(
                self, method, url, *, body=None, headers=None, deadline=None
            ):
                request_headers = dict(headers or {})
                self.requests.append(
                    (method, url, body, request_headers, deadline)
                )
                action = request_headers.get("x-ms-lease-action")
                if action == "acquire":
                    return bootstrap._RestResponse(201, b"", {})
                if action == "renew":
                    return bootstrap._RestResponse(200, b"", {})
                if action == "release":
                    return bootstrap._RestResponse(200, b"", {})
                if method == "GET":
                    self.expiry_reads += 1
                    state_name = "leased" if self.expiry_reads == 1 else "expired"
                    return bootstrap._RestResponse(
                        200,
                        b"",
                        {
                            "x-ms-lease-state": state_name,
                            "x-ms-lease-status": (
                                "locked" if state_name == "leased" else "unlocked"
                            ),
                            "x-ms-lease-duration": "fixed",
                        },
                    )
                raise AssertionError(f"unexpected lease request: {method} {url}")

        def sleep(seconds):
            sleeps.append(seconds)
            current[0] += dt.timedelta(seconds=seconds)

        session = LeasePollSession()
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=self.authorization,
            plan=self.plan,
            package=self.fixture.package,
            preflight={"projection": self.fixture.projection},
            session=session,
            clock=lambda: current[0],
            sleep=sleep,
        )
        transport.bind_journal(MemoryJournal())
        transport._active_operation_id = "exerciseControllerLeaseCanary"
        transport._active_protected_role_add = (
            "addOwnedOperatorControllerCanaryRole"
        )
        state = {
            "proofs": {
                CREATE: {
                    "details": {
                        "url": self.create_contract["expectedUrl"],
                        "etag": ETAG,
                        "sha256": bootstrap.sha256_bytes(self.canary_body()),
                        "cleanupKey": "controller-lease-canary-blob",
                    }
                }
            }
        }

        result = transport._mutate(
            self.fixture.mutations["exerciseControllerLeaseCanary"], state
        )

        self.assertEqual(result["expiryFallback"]["pollAttempts"], 2)
        self.assertEqual(
            sleeps,
            [bootstrap.CONTROLLER_CANARY_LEASE_DURATION_SECONDS, 2.0],
        )
        expiry_gets = [
            request for request in session.requests if request[0] == "GET"
        ]
        self.assertEqual(len(expiry_gets), 2)
        self.assertEqual(
            [request[4] for request in expiry_gets],
            [transport._controller_canary_lease_expiry_deadline()] * 2,
        )

    def test_late_readiness_success_cannot_consume_the_canary_put_envelope(self):
        current = [NOW]
        transport_box = {}

        class LateSession:
            def __init__(self):
                self.requests = []

            def request(self, method, url, **kwargs):
                self.requests.append((method, url, kwargs))
                transport = transport_box["transport"]
                current[0] = (
                    transport._controller_canary_create_deadline()
                    - dt.timedelta(seconds=45)
                )
                return bootstrap._RestResponse(
                    200,
                    (
                        b"<EnumerationResults><Blobs/><NextMarker/>"
                        b"</EnumerationResults>"
                    ),
                    {"Content-Type": "application/xml"},
                )

        session = LateSession()
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=self.authorization,
            plan=self.plan,
            package=self.fixture.package,
            preflight={"projection": self.fixture.projection},
            session=session,
            clock=lambda: current[0],
            sleep=lambda seconds: current.__setitem__(
                0, current[0] + dt.timedelta(seconds=seconds)
            ),
        )
        transport_box["transport"] = transport
        controller = transport.resources["controllerLockContainer"]
        transport._validated_source_projections[
            "createPrivateControllerLockContainer"
        ] = {
            "projection": {
                "id": controller["resourceId"],
                "name": controller["name"],
                "type": (
                    "Microsoft.Storage/storageAccounts/blobServices/containers"
                ),
                "publicAccess": "None",
            }
        }
        journal = MemoryJournal()
        transport.bind_journal(journal)
        transport._active_protected_role_add = (
            "addOwnedOperatorControllerCanaryRole"
        )
        transport._protected_work_deadline = transport._protected_role_deadline()
        current[0] = (
            transport._controller_canary_readiness_deadline()
            - dt.timedelta(seconds=180)
        )
        ids = transport.admissions[
            "proveControllerLockContainerEmpty"
        ]["desiredProbeIds"]

        with self.assertRaises(bootstrap.ControllerReadinessError) as raised:
            transport._prove_controller_lock_container_empty(ids)

        self.assertEqual(
            raised.exception.diagnostic["stopReason"], "expired-during-get"
        )
        self.assertEqual(len(session.requests), 1)
        self.assertEqual(journal.records, [])

    def test_controller_role_start_cutoff_is_strict(self):
        current = [NOW]
        transport = bootstrap.AzureCliBootstrapTransport(
            authorization=self.authorization,
            plan=self.plan,
            package=self.fixture.package,
            preflight={"projection": self.fixture.projection},
            session=Session([]),
            clock=lambda: current[0],
            sleep=lambda _seconds: None,
        )
        current[0] = transport._controller_canary_role_admission_start_deadline()
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "controller role admission"
        ):
            transport._begin_protected_role_lifecycle(
                "addOwnedOperatorControllerCanaryRole"
            )

    def test_short_authorization_fails_before_claim_or_cloud_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            validated, preflight, receipt = self.validated_inputs(
                folder, lifetime_seconds=1800
            )
            transport = FakeTransport(preflight["projection"])

            with self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "insufficient remaining authorization budget",
            ):
                self.executor(
                    validated, preflight, transport, lambda: NOW
                ).run()

            self.assertFalse(receipt.exists())
            self.assertFalse(
                any(
                    kind in {"apply", "compensate"}
                    for kind, _value in transport.calls
                )
            )

    def test_exact_preclaim_budget_boundary_is_still_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            validated, preflight, receipt = self.validated_inputs(folder)
            transport = FakeTransport(preflight["projection"])
            boundary = validated.expires_at - dt.timedelta(
                seconds=(
                    bootstrap.CONTROLLER_CANARY_POST_ADMISSION_REQUIRED_SECONDS
                )
            )

            with self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "insufficient remaining authorization budget",
            ):
                self.executor(
                    validated, preflight, transport, lambda: boundary
                ).run()

            self.assertFalse(receipt.exists())
            self.assertFalse(
                any(
                    kind in {"apply", "compensate"}
                    for kind, _value in transport.calls
                )
            )

    def test_cleanup_resolved_delete_aborts_without_later_or_duplicate_mutation(self):
        class CleanupResolvedTransport(FakeTransport):
            def apply_operation(self, operation, state):
                if operation["id"] == REMOVE:
                    self.calls.append(("apply", operation["id"]))
                    raise bootstrap.CleanupResolvedMutationError(
                        "simulated exact DELETE retry resolution",
                        {
                            "operationId": REMOVE,
                            "status": "cleanup-resolved-failure",
                            "owned": False,
                            "cleanupKey": "controller-lease-canary-blob",
                            "details": {
                                "deleteStatus": 404,
                                "readbackProjections": [
                                    {
                                        "family": (
                                            "controller-lock-empty-after-canary"
                                        ),
                                        "projection": {"absent": True},
                                    }
                                ],
                            },
                        },
                    )
                return super().apply_operation(operation, state)

        with tempfile.TemporaryDirectory() as folder:
            validated, preflight, receipt = self.validated_inputs(folder)
            transport = CleanupResolvedTransport(preflight["projection"])

            with self.assertRaises(bootstrap.CleanupResolvedMutationError):
                self.executor(
                    validated, preflight, transport, lambda: NOW
                ).run()

            applied = [
                value for kind, value in transport.calls if kind == "apply"
            ]
            self.assertEqual(applied[-1], REMOVE)
            remove_index = next(
                index
                for index, operation in enumerate(self.plan["mutations"])
                if operation["id"] == REMOVE
            )
            if remove_index + 1 < len(self.plan["mutations"]):
                self.assertNotIn(
                    self.plan["mutations"][remove_index + 1]["id"], applied
                )
            compensated = [
                value
                for kind, value in transport.calls
                if kind == "compensate"
            ]
            self.assertNotIn(CREATE, compensated)

            terminal, _ = bootstrap.load_json(
                receipt / "execution-terminal.json", require_canonical=True
            )
            self.assertEqual(terminal["status"], "failed")
            self.assertEqual(
                terminal["failureType"], "CleanupResolvedMutationError"
            )
            self.assertFalse(
                any(
                    item["status"] == "cleanup-failed"
                    for item in terminal["temporaryCleanup"]
                )
            )
            canary_cleanup = [
                item
                for item in terminal["temporaryCleanup"]
                if item["operationId"] == CREATE
            ]
            self.assertEqual(len(canary_cleanup), 1)
            self.assertEqual(canary_cleanup[0]["status"], "removed-exact")

    def test_claim_timestamp_is_captured_after_advancing_fresh_preflight(self):
        projection = copy.deepcopy(self.fixture.projection)
        fresh_observed_at = stamp(NOW + dt.timedelta(seconds=120))
        retired = projection["productionBoundaryObservation"][
            "retiredTemporaryRoleAbsence"
        ]
        for item in retired:
            item["observedAt"] = fresh_observed_at
        current = [NOW]

        class AdvancingTransport(FakeTransport):
            def collect_preflight(self, plan):
                value = super().collect_preflight(plan)
                current[0] = NOW + dt.timedelta(seconds=300)
                return value

        with tempfile.TemporaryDirectory() as folder:
            validated, preflight, receipt = self.validated_inputs(
                folder, projection=projection
            )
            transport = AdvancingTransport(
                preflight["projection"],
                fail_operation="claimAzureSingleUseAuthorization",
            )

            with self.assertRaisesRegex(
                bootstrap.BootstrapError, "injected permanent failure"
            ):
                self.executor(
                    validated, preflight, transport, lambda: current[0]
                ).run()

            ledger, _ = bootstrap.load_json(
                receipt / "single-use-state.json", require_canonical=True
            )
            claimed_at = bootstrap.parse_time(
                ledger["claimedAt"], "claimedAt"
            )
            self.assertEqual(claimed_at, current[0])
            self.assertLessEqual(
                bootstrap.parse_time(fresh_observed_at, "fresh observedAt"),
                claimed_at,
            )

    def test_expiry_after_controller_cleans_owned_state_and_stops_before_next_write(self):
        with tempfile.TemporaryDirectory() as folder:
            validated, preflight, receipt = self.validated_inputs(folder)
            transport = FakeTransport(preflight["projection"])

            def clock():
                applied = [
                    value
                    for kind, value in transport.calls
                    if kind == "apply"
                ]
                if "removeOwnedOperatorControllerCanaryRole" in applied:
                    return validated.expires_at + dt.timedelta(seconds=1)
                return NOW

            with self.assertRaisesRegex(
                bootstrap.BootstrapError, "authorization expired"
            ):
                self.executor(validated, preflight, transport, clock).run()

            applied = [
                value for kind, value in transport.calls if kind == "apply"
            ]
            self.assertEqual(
                applied[-1], "removeOwnedOperatorControllerCanaryRole"
            )
            self.assertNotIn("addOwnedUploaderPackageRole", applied)
            self.assertEqual(
                [
                    value
                    for kind, value in transport.calls
                    if kind == "compensate"
                ],
                ["addOwnedUploaderIpv4Rule"],
            )
            terminal, _ = bootstrap.load_json(
                receipt / "execution-terminal.json", require_canonical=True
            )
            self.assertEqual(terminal["status"], "failed")
            self.assertFalse(
                any(
                    item["status"] == "cleanup-failed"
                    for item in terminal["temporaryCleanup"]
                )
            )
            permanent_prefix = [
                operation["id"]
                for operation in self.plan["mutations"]
                if operation["id"] in applied
                and operation.get("temporary") is not True
                and operation["kind"]
                != "local-create-only-canonical-evidence"
            ]
            self.assertTrue(permanent_prefix)
            self.assertEqual(
                permanent_prefix,
                [
                    operation["id"]
                    for operation in self.plan["mutations"][:18]
                    if operation.get("temporary") is not True
                ],
            )

    def test_configure_rejects_pre_read_map_and_digest_drift_without_put(self):
        state = self.bridge_state()
        transport, session = self.bridge_transport(
            [
                self.settings_response(
                    {"OUT_OF_BAND_SETTING": "drifted"},
                    body_etag='"irrelevant-body-etag"',
                )
            ]
        )

        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "drifted after authorization"
        ):
            transport._mutate(self.fixture.mutations[CONFIGURE], state)

        self.assertEqual(
            [request[0] for request in session.requests], ["POST"]
        )
        self.assertEqual(
            [request for request in session.requests if request[0] == "PUT"],
            [],
        )

    def test_configure_ignores_missing_weak_and_body_etags_and_puts_once(self):
        bridge = self.fixture.resources["bridgeSite"]
        settings_variants = (
            ("missing", self.settings_response({})),
            ("weak-header", self.settings_response({}, 'W/"weak"')),
            (
                "body-only",
                self.settings_response({}, body_etag='"body-only"'),
            ),
        )
        for label, pre_read in settings_variants:
            with self.subTest(etag=label):
                state = self.bridge_state()
                transport, session = self.bridge_transport(
                    [
                        pre_read,
                        bootstrap._RestResponse(
                            200,
                            bootstrap.canonical_json_bytes(
                                {
                                    "id": bridge["resourceId"]
                                    + "/config/appsettings",
                                    "etag": '"response-body-only"',
                                }
                            ),
                            {"ETag": 'W/"response-header"'},
                        ),
                    ]
                )

                details = transport._mutate(
                    self.fixture.mutations[CONFIGURE], state
                )

                settings_puts = [
                    request
                    for request in session.requests
                    if request[0] == "PUT"
                    and request[1].endswith(
                        "/config/appsettings?api-version=2025-03-01"
                    )
                ]
                self.assertEqual(len(settings_puts), 1)
                self.assertNotIn("If-Match", settings_puts[0][3])
                desired = self.desired_bridge_settings(details)
                self.assertEqual(
                    settings_puts[0][2],
                    bootstrap.canonical_json_bytes({"properties": desired}),
                )
                self.assertEqual(
                    bootstrap.sha256_bytes(
                        bootstrap.canonical_json_bytes(desired)
                    ),
                    details["settingsSha256"],
                )

    def test_configure_result_journal_failure_is_owned_and_exactly_rolled_back(self):
        class FailFirstResultJournal(MemoryJournal):
            def __init__(self):
                super().__init__()
                self.failed = False

            def append_cloud_mutation(self, value):
                if value.get("phase") == "result" and not self.failed:
                    self.failed = True
                    raise OSError("simulated ARM result-journal failure")
                return super().append_cloud_mutation(value)

        journal = FailFirstResultJournal()
        bridge = self.fixture.resources["bridgeSite"]
        state = self.bridge_state()
        transport, session = self.bridge_transport(
            [
                self.settings_response({}, 'W/"ignored-pre-read"'),
                bootstrap._RestResponse(
                    200,
                    bootstrap.canonical_json_bytes(
                        {
                            "id": bridge["resourceId"] + "/config/appsettings",
                            "etag": '"ignored-put-body-etag"',
                        }
                    ),
                    {},
                ),
            ],
            journal=journal,
        )

        with self.assertRaises(bootstrap.OwnedTemporaryMutationError) as raised:
            transport.apply_operation(self.fixture.mutations[CONFIGURE], state)

        proof = raised.exception.proof
        self.assertTrue(proof["owned"])
        self.assertEqual(
            proof["cleanupKey"], bootstrap.BRIDGE_SETTINGS_CLEANUP_KEY
        )
        desired = self.desired_bridge_settings(proof["details"])
        session.responses.extend(
            [
                bootstrap._RestResponse(
                    200,
                    bootstrap.canonical_json_bytes(
                        {
                            "id": bridge["resourceId"],
                            "name": bridge["name"],
                            "properties": {"state": "Stopped"},
                        }
                    ),
                    {},
                ),
                self.settings_response(desired, 'W/"ignored-desired"'),
                bootstrap._RestResponse(
                    200,
                    bootstrap.canonical_json_bytes(
                        {
                            "id": bridge["resourceId"] + "/config/appsettings",
                            "etag": '"ignored-rollback-body-etag"',
                        }
                    ),
                    {},
                ),
                self.settings_response({}, body_etag='"ignored-final"'),
            ]
        )

        cleanup = transport.compensate_temporary(
            self.fixture.mutations[CONFIGURE], proof, state
        )

        self.assertEqual(cleanup["status"], "removed-exact")
        self.assertTrue(cleanup["details"]["rollbackMutationIssued"])
        self.assertEqual(
            cleanup["details"]["finalSettingsSha256"],
            bootstrap.sha256_bytes(bootstrap.canonical_json_bytes({})),
        )
        settings_puts = [
            request
            for request in session.requests
            if request[0] == "PUT" and request[1].endswith(
                "/config/appsettings?api-version=2025-03-01"
            )
        ]
        self.assertEqual(len(settings_puts), 2)
        self.assertTrue(
            all("If-Match" not in request[3] for request in settings_puts)
        )
        self.assertEqual(
            settings_puts[1][2],
            bootstrap.canonical_json_bytes({"properties": {}}),
        )
        self.assertEqual(
            [record["phase"] for record in journal.records],
            ["intent", "intent", "result"],
        )
        self.assertEqual(
            {record["operationId"] for record in journal.records},
            {CONFIGURE},
        )

    def test_configure_expiry_crossing_is_journaled_then_rolled_back_after_expiry(self):
        current = [NOW]
        bridge = self.fixture.resources["bridgeSite"]
        state = self.bridge_state()

        def late_put():
            current[0] = bootstrap.parse_time(
                self.authorization["validity"]["expiresAt"], "expiresAt"
            )
            return bootstrap._RestResponse(
                200,
                bootstrap.canonical_json_bytes(
                    {"id": bridge["resourceId"] + "/config/appsettings"}
                ),
                {},
            )

        journal = MemoryJournal()
        transport, session = self.bridge_transport(
            [self.settings_response({}, body_etag='"ignored-pre-read"'), late_put],
            clock=lambda: current[0],
            journal=journal,
        )

        with self.assertRaises(bootstrap.OwnedTemporaryMutationError) as raised:
            transport.apply_operation(self.fixture.mutations[CONFIGURE], state)

        self.assertEqual(
            [record["phase"] for record in journal.records],
            ["intent", "result"],
        )
        self.assertEqual(
            session.deadlines[1],
            bootstrap.parse_time(
                self.authorization["validity"]["expiresAt"], "expiresAt"
            ),
        )
        desired = self.desired_bridge_settings(raised.exception.proof["details"])
        session.responses.extend(
            [
                bootstrap._RestResponse(
                    200,
                    bootstrap.canonical_json_bytes(
                        {
                            "id": bridge["resourceId"],
                            "name": bridge["name"],
                            "properties": {"state": "Stopped"},
                        }
                    ),
                    {},
                ),
                self.settings_response(desired, 'W/"ignored-desired"'),
                bootstrap._RestResponse(200, b"{}", {}),
                self.settings_response({}, body_etag='"ignored-final"'),
            ]
        )

        cleanup = transport.compensate_temporary(
            self.fixture.mutations[CONFIGURE], raised.exception.proof, state
        )

        self.assertEqual(cleanup["status"], "removed-exact")
        rollback_put_index = next(
            index
            for index, request in enumerate(session.requests)
            if index > 1
            and request[0] == "PUT"
            and request[1].endswith(
                "/config/appsettings?api-version=2025-03-01"
            )
        )
        self.assertIsNone(session.deadlines[rollback_put_index])
        self.assertNotIn("If-Match", session.requests[rollback_put_index][3])

    def test_configure_cleanup_accepts_exact_prestate_without_a_second_put(self):
        bridge = self.fixture.resources["bridgeSite"]
        state = self.bridge_state()
        transport, session = self.bridge_transport(
            [
                self.settings_response({}, body_etag='"ignored-pre-read"'),
                bootstrap._RestResponse(200, b"{}", {"ETag": 'W/"ignored"'}),
            ]
        )
        details = transport._mutate(self.fixture.mutations[CONFIGURE], state)
        proof = {
            "operationId": CONFIGURE,
            "status": "applied-readback-pending",
            "owned": True,
            "cleanupKey": bootstrap.BRIDGE_SETTINGS_CLEANUP_KEY,
            "details": details,
        }
        session.responses.extend(
            [
                bootstrap._RestResponse(
                    200,
                    bootstrap.canonical_json_bytes(
                        {
                            "id": bridge["resourceId"],
                            "name": bridge["name"],
                            "properties": {"state": "Stopped"},
                        }
                    ),
                    {},
                ),
                self.settings_response({}),
            ]
        )

        cleanup = transport.compensate_temporary(
            self.fixture.mutations[CONFIGURE], proof, state
        )

        self.assertFalse(cleanup["details"]["rollbackMutationIssued"])
        self.assertEqual(
            len([request for request in session.requests if request[0] == "PUT"]),
            1,
        )
        configure_put = next(
            request for request in session.requests if request[0] == "PUT"
        )
        self.assertNotIn("If-Match", configure_put[3])

    def test_configure_cleanup_refuses_concurrent_third_state(self):
        bridge = self.fixture.resources["bridgeSite"]
        state = self.bridge_state()
        transport, session = self.bridge_transport(
            [
                self.settings_response({}),
                bootstrap._RestResponse(
                    200, b"{}", {"ETag": 'W/"ignored-put"'}
                ),
            ]
        )
        details = transport._mutate(self.fixture.mutations[CONFIGURE], state)
        proof = {
            "operationId": CONFIGURE,
            "status": "applied-readback-pending",
            "owned": True,
            "cleanupKey": bootstrap.BRIDGE_SETTINGS_CLEANUP_KEY,
            "details": details,
        }
        session.responses.extend(
            [
                bootstrap._RestResponse(
                    200,
                    bootstrap.canonical_json_bytes(
                        {
                            "id": bridge["resourceId"],
                            "name": bridge["name"],
                            "properties": {"state": "Stopped"},
                        }
                    ),
                    {},
                ),
                self.settings_response(
                    {"CONCURRENT_OWNER": "must-not-overwrite"},
                    body_etag='"ignored-third-state"',
                ),
            ]
        )

        with self.assertRaisesRegex(bootstrap.BootstrapError, "third state"):
            transport.compensate_temporary(
                self.fixture.mutations[CONFIGURE], proof, state
            )

        self.assertEqual(
            len([request for request in session.requests if request[0] == "PUT"]),
            1,
        )

    def test_configure_cleanup_does_not_retry_an_ambiguous_rollback_put(self):
        bridge = self.fixture.resources["bridgeSite"]
        state = self.bridge_state()
        transport, session = self.bridge_transport(
            [
                self.settings_response({}, 'W/"ignored-pre-read"'),
                bootstrap._RestResponse(200, b"{}", {}),
            ]
        )
        details = transport._mutate(self.fixture.mutations[CONFIGURE], state)
        proof = {
            "operationId": CONFIGURE,
            "status": "applied-readback-pending",
            "owned": True,
            "cleanupKey": bootstrap.BRIDGE_SETTINGS_CLEANUP_KEY,
            "details": details,
        }
        desired = self.desired_bridge_settings(details)
        session.responses.extend(
            [
                bootstrap._RestResponse(
                    200,
                    bootstrap.canonical_json_bytes(
                        {
                            "id": bridge["resourceId"],
                            "name": bridge["name"],
                            "properties": {"state": "Stopped"},
                        }
                    ),
                    {},
                ),
                self.settings_response(desired, body_etag='"ignored-desired"'),
                RuntimeError("simulated ambiguous rollback PUT"),
            ]
        )

        with self.assertRaisesRegex(RuntimeError, "ambiguous rollback"):
            transport.compensate_temporary(
                self.fixture.mutations[CONFIGURE], proof, state
            )

        self.assertEqual(
            len([request for request in session.requests if request[0] == "PUT"]),
            2,
        )
        rollback_put = [
            request for request in session.requests if request[0] == "PUT"
        ][1]
        self.assertNotIn("If-Match", rollback_put[3])
        self.assertEqual(session.responses, [])

    def test_expiry_after_configure_rolls_back_owned_settings_before_failure(self):
        class SettingsOwnedTransport(FakeTransport):
            def apply_operation(self, operation, state):
                proof = dict(super().apply_operation(operation, state))
                if operation["id"] == CONFIGURE:
                    proof.update(
                        {
                            "status": "applied-exact",
                            "owned": True,
                            "cleanupKey": bootstrap.BRIDGE_SETTINGS_CLEANUP_KEY,
                        }
                    )
                return proof

        with tempfile.TemporaryDirectory() as folder:
            validated, preflight, receipt = self.validated_inputs(folder)
            transport = SettingsOwnedTransport(preflight["projection"])

            def clock():
                applied = [
                    value
                    for kind, value in transport.calls
                    if kind == "apply"
                ]
                if CONFIGURE in applied:
                    return validated.expires_at + dt.timedelta(seconds=1)
                return NOW

            with self.assertRaisesRegex(
                bootstrap.BootstrapError, "authorization expired"
            ):
                self.executor(validated, preflight, transport, clock).run()

            applied = [
                value for kind, value in transport.calls if kind == "apply"
            ]
            self.assertEqual(applied[-1], CONFIGURE)
            self.assertEqual(
                [
                    value
                    for kind, value in transport.calls
                    if kind == "compensate"
                ],
                [CONFIGURE],
            )
            terminal, _ = bootstrap.load_json(
                receipt / "execution-terminal.json", require_canonical=True
            )
            self.assertEqual(terminal["status"], "failed")
            self.assertEqual(
                terminal["temporaryCleanup"][0]["operationId"], CONFIGURE
            )
            self.assertEqual(
                terminal["temporaryCleanup"][0]["status"], "removed-exact"
            )

    def test_expiry_after_bridge_canary_still_rolls_back_owned_settings(self):
        canary_operation = "startBridgeForBoundedCanary"

        class SettingsOwnedTransport(FakeTransport):
            def apply_operation(self, operation, state):
                proof = dict(super().apply_operation(operation, state))
                if operation["id"] == CONFIGURE:
                    proof.update(
                        {
                            "status": "applied-exact",
                            "owned": True,
                            "cleanupKey": bootstrap.BRIDGE_SETTINGS_CLEANUP_KEY,
                        }
                    )
                return proof

        with tempfile.TemporaryDirectory() as folder:
            validated, preflight, receipt = self.validated_inputs(folder)
            transport = SettingsOwnedTransport(preflight["projection"])

            def clock():
                applied = [
                    value for kind, value in transport.calls if kind == "apply"
                ]
                if canary_operation in applied:
                    return validated.expires_at + dt.timedelta(seconds=1)
                return NOW

            with self.assertRaisesRegex(
                bootstrap.BootstrapError, "authorization expired"
            ):
                self.executor(validated, preflight, transport, clock).run()

            applied = [
                value for kind, value in transport.calls if kind == "apply"
            ]
            self.assertEqual(applied[-1], canary_operation)
            self.assertEqual(
                [
                    value
                    for kind, value in transport.calls
                    if kind == "compensate"
                ],
                [CONFIGURE],
            )
            terminal, _ = bootstrap.load_json(
                receipt / "execution-terminal.json", require_canonical=True
            )
            self.assertEqual(terminal["status"], "failed")
            self.assertEqual(
                terminal["temporaryCleanup"][0]["operationId"], CONFIGURE
            )
            self.assertEqual(
                terminal["temporaryCleanup"][0]["status"], "removed-exact"
            )

    def test_strict_storage_xml_accepts_only_one_optional_leading_utf8_bom(self):
        payload = (
            b'<?xml version="1.0" encoding="utf-8"?>'
            b"<Error><Code>BlobNotFound</Code><Message>missing</Message></Error>"
        )
        for body in (payload, b"\xef\xbb\xbf" + payload):
            with self.subTest(prefix="bom" if body != payload else "none"):
                root = bootstrap._strict_storage_xml_root(body, "fixture")
                self.assertEqual(root.tag, "Error")
                self.assertEqual(root.findtext("Code"), "BlobNotFound")

        rejected = (
            b"\xef\xbb\xbf\xef\xbb\xbf" + payload,
            b"<Error>\xef\xbb\xbf<Code>BlobNotFound</Code></Error>",
            payload.decode("utf-8").encode("utf-16"),
            b"\xef\xbb\xbf<!DOCTYPE Error><Error><Code>BlobNotFound</Code></Error>",
        )
        for body in rejected:
            with self.subTest(body_sha256=bootstrap.sha256_bytes(body)):
                with self.assertRaises(bootstrap._StrictStorageXmlError):
                    bootstrap._strict_storage_xml_root(body, "fixture")

    def test_strict_empty_inventory_rejects_malformed_duplicate_and_paging(self):
        valid = (
            b"\xef\xbb\xbf<EnumerationResults><Blobs/><NextMarker/>"
            b"</EnumerationResults>"
        )
        cases = {
            "malformed": b"<EnumerationResults><Blobs/><NextMarker>",
            "duplicate": (
                b"<EnumerationResults><Blobs/><Blobs/><NextMarker/>"
                b"</EnumerationResults>"
            ),
            "paging": (
                b"<EnumerationResults><Blobs/><NextMarker>continuation-token"
                b"</NextMarker></EnumerationResults>"
            ),
            "doctype-entity": (
                b"<!DOCTYPE EnumerationResults [<!ENTITY empty ''>]><EnumerationResults>"
                b"<Blobs>&empty;</Blobs><NextMarker>&empty;</NextMarker>"
                b"</EnumerationResults>"
            ),
            "utf16-doctype-entity": (
                "<!DOCTYPE EnumerationResults [<!ENTITY empty ''>]>"
                "<EnumerationResults><Blobs>&empty;</Blobs>"
                "<NextMarker>&empty;</NextMarker></EnumerationResults>"
            ).encode("utf-16"),
            "double-utf8-bom": (
                b"\xef\xbb\xbf\xef\xbb\xbf<EnumerationResults><Blobs/>"
                b"<NextMarker/></EnumerationResults>"
            ),
        }

        proof = bootstrap._strict_empty_controller_inventory(
            bootstrap._RestResponse(
                200, valid, {"Content-Type": "application/xml"}
            ),
            plan=self.plan,
            observed_at=stamp(NOW),
            private_container_posture={"publicAccess": "None"},
            controller_container_decision="apply-exact",
        )
        self.assertEqual(proof["blobNames"], [])
        self.assertEqual(proof["nextMarker"], "")
        self.assertEqual(proof["responseSha256"], bootstrap.sha256_bytes(valid))

        for name, body in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap._strict_empty_controller_inventory(
                        bootstrap._RestResponse(
                            200, body, {"Content-Type": "application/xml"}
                        ),
                        plan=self.plan,
                        observed_at=stamp(NOW),
                        private_container_posture={"publicAccess": "None"},
                        controller_container_decision="apply-exact",
                    )

    def test_post_delete_inventory_rejects_dtd_and_entity_expansion(self):
        bodies = [
            (
                b"<!DOCTYPE EnumerationResults [<!ENTITY empty ''>]><EnumerationResults>"
                b"<Blobs>&empty;</Blobs><NextMarker>&empty;</NextMarker>"
                b"</EnumerationResults>"
            ),
            (
                "<!DOCTYPE EnumerationResults [<!ENTITY empty ''>]>"
                "<EnumerationResults><Blobs>&empty;</Blobs>"
                "<NextMarker>&empty;</NextMarker></EnumerationResults>"
            ).encode("utf-16"),
        ]
        for body in bodies:
            with self.subTest(encoding="utf16" if body.startswith(b"\xff\xfe") else "utf8"):
                malicious_inventory = bootstrap._RestResponse(
                    200,
                    body,
                    {"Content-Type": "application/xml"},
                )
                transport, session, _journal = self.transport(
                    [bootstrap._RestResponse(202, b"", {}), malicious_inventory],
                    REMOVE,
                )
                controller = transport.resources["controllerLockContainer"]
                transport._validated_source_projections[
                    "createPrivateControllerLockContainer"
                ] = {
                    "projection": {
                        "id": controller["resourceId"],
                        "name": controller["name"],
                        "type": (
                            "Microsoft.Storage/storageAccounts/blobServices/containers"
                        ),
                        "publicAccess": "None",
                    }
                }
                state = {
                    "proofs": {
                        CREATE: {
                            "details": {
                                "url": self.create_contract["expectedUrl"],
                                "etag": ETAG,
                                "sha256": bootstrap.sha256_bytes(self.canary_body()),
                                "cleanupKey": "controller-lease-canary-blob",
                            }
                        }
                    }
                }

                with self.assertRaisesRegex(
                    bootstrap.BootstrapError, "bounded XML response"
                ):
                    transport._mutate(self.fixture.mutations[REMOVE], state)

                self.assertEqual(
                    [request[0] for request in session.requests], ["DELETE", "GET"]
                )

    def test_utf16_storage_entities_are_rejected_by_error_and_readiness_paths(self):
        malicious = (
            "<!DOCTYPE Error [<!ENTITY code 'BlobNotFound'>]>"
            "<Error><Code>&code;</Code><Message>hidden</Message></Error>"
        ).encode("utf-16")
        response = bootstrap._RestResponse(
            404,
            malicious,
            {
                "Content-Type": "application/xml",
                "x-ms-error-code": "BlobNotFound",
            },
        )

        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap._package_blob_error_projection(
                "GET", self.create_contract["expectedUrl"], response
            )
        self.assertEqual(
            bootstrap.AzureCliBootstrapTransport._storage_error_code(response),
            "unknown",
        )

        package_url = bootstrap._operation_readback_url(
            "uploadVersionedBridgePackage", self.plan, self.authorization
        )
        package_transport, _package_session = self.bridge_transport([response])
        with self.assertRaises(bootstrap.PackageReadinessError) as package_error:
            package_transport._prove_package_upload_ready(package_url)
        self.assertEqual(
            package_error.exception.diagnostic["stopReason"], "unsafe-xml"
        )

        fence_response = bootstrap._RestResponse(
            403,
            malicious,
            {
                "Content-Type": "application/xml",
                "x-ms-error-code": "AuthorizationPermissionMismatch",
            },
        )
        fence_transport, _fence_session = self.bridge_transport([fence_response])
        fence_transport._active_protected_role_add = (
            "addOwnedOperatorFenceBootstrapRole"
        )
        fence_url = bootstrap._operation_readback_url(
            "createInitialIdleActivationFence", self.plan, self.authorization
        )
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "unsafe or oversized"
        ):
            fence_transport._prove_fence_blob_create_ready(fence_url)

        controller_response = bootstrap._RestResponse(
            403,
            malicious,
            {
                "Content-Type": "application/xml",
                "x-ms-error-code": "AuthorizationPermissionMismatch",
            }
        )
        controller_transport, _controller_session, _journal = self.transport(
            [controller_response], "proveControllerLockContainerEmpty"
        )
        controller_transport._active_protected_role_add = (
            "addOwnedOperatorControllerCanaryRole"
        )
        controller_transport._protected_work_deadline = (
            controller_transport._controller_canary_create_deadline()
        )
        ids = controller_transport.admissions[
            "proveControllerLockContainerEmpty"
        ]["desiredProbeIds"]
        with self.assertRaises(bootstrap.ControllerReadinessError) as controller_error:
            controller_transport._prove_controller_lock_container_empty(ids)
        self.assertEqual(
            controller_error.exception.diagnostic["stopReason"], "unsafe-xml"
        )

    def test_utf16_storage_entity_never_becomes_a_journal_error_code(self):
        malicious = (
            "<!DOCTYPE Error [<!ENTITY code 'BlobAlreadyExists'>]>"
            "<Error><Code>&code;</Code><Message>hidden</Message></Error>"
        ).encode("utf-16")
        response = bootstrap._RestResponse(
            409,
            malicious,
            {
                "Content-Type": "application/xml",
                "x-ms-error-code": "BlobAlreadyExists",
            },
        )
        transport, _session, journal = self.transport([response], CREATE)

        result = transport._mutation_request(
            "PUT",
            self.create_contract["expectedUrl"],
            body=self.canary_body(),
            headers={"x-ms-version": "2023-11-03"},
            expected={409},
            deadline=transport._controller_canary_create_deadline(),
        )

        self.assertEqual(result.status, 409)
        self.assertEqual(journal.records[-1]["phase"], "result")
        self.assertEqual(journal.records[-1]["storageErrorCode"], "unknown")


if __name__ == "__main__":
    unittest.main()
