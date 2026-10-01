"""Test-only connected canary observations; never a provider or admission path.

The outer Azure resource universe comes from the existing synthetic fixture.
Only configure/start canary projections and their journal records below are
emitted by the production transport against this in-memory REST model.
"""

import copy
import datetime as dt
import json
import urllib.parse
from collections import Counter
from pathlib import Path

from scripts import private_release_v2_bootstrap as bootstrap
from tests import test_private_release_v2_bootstrap as reference


CONFIGURE = "configureBridgeExactVersionedPackageAndCriticalSettings"
CANARY = "startBridgeForBoundedCanary"
CONNECTED = {CONFIGURE, CANARY}
JOB = "paperdesk-accepted-release-registry"


class PersistentCanaryProvider:
    """A closed REST model with retained history and settings across attempts."""

    def __init__(self, site, *, old_count=4):
        self.site = site
        self.settings = {}
        self.state = "Stopped"
        self.public = "Disabled"
        self.scm = False
        self.runs = {}
        self.attempts = 0
        for index in range(old_count):
            self.runs[f"old-{index}"] = self.run(
                f"old-{index}", reference.NOW - dt.timedelta(minutes=index + 2),
                "External - unrelated-old-trigger",
            )

    def run(self, name, started, trigger):
        return {
            "web_job_name": JOB, "web_job_id": name,
            "trigger": trigger, "status": "Success",
            "start_time": reference.stamp(started),
            "end_time": reference.stamp(started + dt.timedelta(milliseconds=1)),
            "output_url": (
                "https://" + self.site["name"] + ".scm.azurewebsites.net"
                + f"/vfs/data/jobs/triggered/{JOB}/{name}/output_log.txt"
            ),
        }


class CanarySession:
    """Refuse every URL/method outside the exact synthetic canary surface."""

    def __init__(self, provider, current, *, fault=None):
        self.provider = provider
        self.current = current
        self.fault = fault
        self.requests = []
        self.collections = []
        self.detail_reads = Counter()
        self.trigger_count = 0
        self.stop_count = 0
        self.settings_put_count = 0
        self.fault_fired = False
        self.history_id = provider.site["resourceId"] + f"/triggeredwebjobs/{JOB}/history"

    def request(self, method, url, *, body=None, headers=None, deadline=None):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname != "management.azure.com":
            raise AssertionError("qualification attempted an unexpected provider host")
        self.requests.append((method, url, body, copy.deepcopy(headers or {}), deadline))
        self.current[0] += dt.timedelta(milliseconds=20)
        site_id = self.provider.site["resourceId"]
        path = parsed.path
        value = None
        status = 200
        response_headers = {"Content-Type": "application/json"}
        if path == site_id + "/config/appsettings/list" and method == "POST" and body == b"":
            value = {"properties": copy.deepcopy(self.provider.settings)}
        elif path == site_id + "/config/appsettings" and method == "PUT":
            self.settings_put_count += 1
            self.provider.settings = json.loads(body)["properties"]
            value = {"id": path, "properties": copy.deepcopy(self.provider.settings)}
        elif path == site_id + "/basicPublishingCredentialsPolicies/scm":
            if method == "PUT":
                self.provider.scm = json.loads(body)["properties"]["allow"]
            elif method != "GET":
                raise AssertionError("unexpected SCM request")
            value = {"id": path, "name": "scm", "type": "Microsoft.Web/sites/basicPublishingCredentialsPolicies",
                     "properties": {"allow": self.provider.scm}}
        elif path == site_id and method == "PATCH":
            self.provider.public = json.loads(body)["properties"]["publicNetworkAccess"]
            return bootstrap._RestResponse(200, b"", {})
        elif path == site_id and method == "GET":
            value = {"id": site_id, "name": self.provider.site["name"], "type": "Microsoft.Web/sites",
                     "properties": {"state": self.provider.state, "publicNetworkAccess": self.provider.public}}
        elif path in {site_id + "/start", site_id + "/stop"} and method == "POST" and body == b"":
            if path.endswith("/stop"):
                self.stop_count += 1
                self.provider.state = "Stopped"
            else:
                self.provider.state = "Running"
            return bootstrap._RestResponse(202, b"", {})
        elif path == site_id + f"/triggeredwebjobs/{JOB}" and method == "GET":
            root = "https://" + self.provider.site["name"] + f".scm.azurewebsites.net/api/triggeredwebjobs/{JOB}"
            value = {"id": path, "name": self.provider.site["name"] + "/" + JOB,
                     "type": "Microsoft.Web/sites/triggeredwebjobs", "properties": {
                         "name": JOB, "type": "triggered", "run_command": "run.sh",
                         "latest_run": copy.deepcopy(next(iter(self.provider.runs.values()), None)),
                         "url": root, "history_url": root + "/history",
                         "error": None, "using_sdk": False,
                         "settings": {"is_singleton": True, "stopping_wait_time": 30}}}
        elif path == self.history_id and method == "GET":
            self.collections.append(tuple(sorted(self.provider.runs)))
            if self.fault == "malformed-final" and self.trigger_count and self.stop_count >= 2:
                value = {"value": {}}
            else:
                value = {"value": [{"id": self.history_id + "/" + key, "properties": {}}
                                   for key in sorted(self.provider.runs)]}
        elif path.startswith(self.history_id + "/") and method == "GET":
            name = path.rsplit("/", 1)[-1]
            if name not in self.provider.runs:
                raise AssertionError("unexpected history child")
            self.detail_reads[name] += 1
            run = copy.deepcopy(self.provider.runs[name])
            if self.fault == "slow-detail" and self.trigger_count and not self.fault_fired:
                self.fault_fired = True
                self.current[0] += dt.timedelta(seconds=91)
            if self.fault == "old-drift" and self.trigger_count and name.startswith("old-"):
                run["trigger"] = "External - changed-old-trigger"
            value = {"id": path, "properties": run}
        elif path == site_id + f"/triggeredwebjobs/{JOB}/run" and method == "POST" and body == b"":
            self.trigger_count += 1
            if self.trigger_count != 1:
                raise AssertionError("qualification replayed its trigger")
            self.provider.attempts += 1
            name = f"qualification-run-{self.provider.attempts}"
            self.provider.runs[name] = self.provider.run(name, self.current[0], "External - " + headers["User-Agent"])
            if self.fault == "credit-exhaustion":
                self.provider.runs[name].update({
                    "status": "Running", "end_time": "0001-01-01T00:00:00", "output_url": None,
                })
            if self.fault == "extra-run":
                self.provider.runs["unrelated-new"] = self.provider.run(
                    "unrelated-new", self.current[0], "External - unrelated-new-trigger"
                )
            location = "https://" + self.provider.site["name"] + f".scm.azurewebsites.net/api/triggeredwebjobs/{JOB}/history/{name}"
            return bootstrap._RestResponse(200, b"", {"Location": location})
        else:
            raise AssertionError(f"unexpected qualification REST route: {method} {path}")
        return bootstrap._RestResponse(status, bootstrap.canonical_json_bytes(value), response_headers)


class ConnectedTerminalFixture(reference._TerminalEvidenceFixture):
    """Synthetic outer resources plus actual configure/canary emitted evidence."""

    def __init__(self, plan, plan_sha, package, receipt, provider, *, fault=None):
        super().__init__(plan, plan_sha, package, receipt)
        context = self.contexts[CONFIGURE]
        context["preAppSettings"] = copy.deepcopy(provider.settings)
        context["preAppSettingsSha256"] = bootstrap.sha256_bytes(bootstrap.canonical_json_bytes(provider.settings))
        self.authorization = reference.build_authorization(plan, plan_sha, package, self.projection, receipt)
        self.authorization_sha = bootstrap.sha256_bytes(bootstrap.canonical_json_bytes(self.authorization))
        self.current = [reference.NOW + dt.timedelta(seconds=20)]
        self.session = CanarySession(provider, self.current, fault=fault)
        self.transport = bootstrap.AzureCliBootstrapTransport(
            authorization=self.authorization, plan=plan, package=package,
            preflight={"projection": self.projection}, session=self.session,
            clock=lambda: self.current[0], sleep=self.advance,
        )
        self.ledger = bootstrap.UseLedger(
            directory=Path(receipt), authorization_id=reference.AUTH_ID,
            authorization_sha256=self.authorization_sha, source_sha=reference.MERGE,
            plan_sha256=plan_sha, claimed_at=reference.stamp(reference.NOW),
        )
        # This is a deterministic fixture-only local claim inside TemporaryDirectory.
        self.ledger.claim()
        self.transport.bind_journal(self.ledger)
        self.emitted_proofs = {}
        self.emitted_runtime_facts = {}
        self.emitted_budgets = []
        self.observed_connected = {}

    def advance(self, seconds):
        self.current[0] += dt.timedelta(seconds=seconds)

    def state(self):
        proofs = {}
        for operation_id, envelope in self.operations.items():
            details = copy.deepcopy(envelope["projection"])
            if "id" in details:
                details.setdefault("resourceId", details["id"])
            proofs[operation_id] = {"details": details}
        proofs.update(self.emitted_proofs)
        return {"proofs": proofs}

    def envelope(self, operation_id, body, *, headers=None, runtime_facts=None):
        if operation_id not in CONNECTED:
            return super().envelope(operation_id, body, headers=headers, runtime_facts=runtime_facts)
        if operation_id == CANARY:
            self.current[0] = (
                bootstrap.parse_time(self.emitted_proofs[CONFIGURE]["details"]["bootstrapSelfTestExpiresAt"], "synthetic control expiry")
                if self.session.fault == "expired-control"
                else reference.NOW + dt.timedelta(minutes=5)
            )
        self.transport._validated_source_projections.update(self.operations)
        original_mutate = self.transport._mutate
        def retain_emitted_facts(operation, state):
            details = original_mutate(operation, state)
            self.emitted_runtime_facts[operation_id] = copy.deepcopy(details)
            return details
        self.transport._mutate = retain_emitted_facts
        original_budget_init = bootstrap._HistoryDetailBudget.__init__
        def retain_budget(instance, **kwargs):
            original_budget_init(instance, **kwargs)
            self.emitted_budgets.append(instance)
        if operation_id == CANARY:
            bootstrap._HistoryDetailBudget.__init__ = retain_budget
        try:
            proof = self.transport.apply_operation(self.mutations[operation_id], self.state())
        finally:
            self.transport._mutate = original_mutate
            bootstrap._HistoryDetailBudget.__init__ = original_budget_init
        self.emitted_proofs[operation_id] = proof
        actual = copy.deepcopy(self.transport._validated_source_projections[operation_id])
        self.operations[operation_id] = actual
        self.observed_connected[operation_id] = reference.stamp(self.current[0])
        return actual

    def mutation_journal(self):
        synthetic = super().mutation_journal()
        # The outer fixture sorts assignment UUIDs alphabetically. Distinct
        # synthetic ceremonies must instead follow the source cleanup order.
        # Only synthetic outer pairs move; emitted connected rows stay exact.
        for operation_id, resources in bootstrap._cleanup_assignment_resources(self.execution_plan).items():
            lock = bootstrap._expected_deletion_lock_proof(operation_id)
            if lock is None or operation_id in CONNECTED:
                continue
            positions = [index for index, row in enumerate(synthetic)
                         if row["operationId"] == operation_id]
            rows = [synthetic[index] for index in positions]
            lock_url = "https://management.azure.com" + lock["resourceId"] + "?api-version=2016-09-01"
            order = [("DELETE", lock_url),
                     *(("DELETE", "https://management.azure.com" + resource + "?api-version=2022-04-01")
                       for resource in resources), ("PUT", lock_url)]
            order.extend(target for target in dict.fromkeys((row["method"], row["targetUrl"]) for row in rows)
                         if target not in order)
            rank = {target: index for index, target in enumerate(order)}
            rows.sort(key=lambda row: (rank[(row["method"], row["targetUrl"])],
                                       0 if row["phase"] == "intent" else 1))
            for index, row in zip(positions, rows):
                synthetic[index] = row
        actual = bootstrap._sanitize_mutation_journal(
            self.ledger.read_cloud_mutations(), plan=self.plan,
            authorization_id=reference.AUTH_ID, authorization_sha256=self.authorization_sha,
            source_sha=reference.MERGE, plan_sha256=self.plan_sha, package_sha256=self.package["sha256"],
        )
        result = []
        emitted = set()
        for row in synthetic:
            operation_id = row["operationId"]
            if operation_id in CONNECTED:
                if operation_id in emitted:
                    continue
                emitted.add(operation_id)
                result.extend(copy.deepcopy(item) for item in actual if item["operationId"] == operation_id)
            else:
                result.append(copy.deepcopy(row))
        # Renumber only the containing synthetic universe; preserve every emitted fact.
        # Rebind result references to their same intent after interleaving.
        intent_ids = {}
        for sequence, row in enumerate(result, 1):
            if row["phase"] == "intent":
                old_id = row["intentId"]
                new_id = f"cloud-mutation-{sequence:04d}"
                intent_ids[(row["operationId"], old_id)] = new_id
                row["intentId"] = new_id
            else:
                row["intentId"] = intent_ids[(row["operationId"], row["intentId"])]
            row["sequence"] = sequence
        self.emitted_sanitized_journal = actual
        return result

    def build_evidence(self):
        evidence = super().build_evidence()
        for rows_key in ("allOperationProjections", "permanentMutationProjections"):
            for row in evidence[rows_key]:
                operation_id = row.get("operationId", row.get("mutationId"))
                if operation_id in CONNECTED:
                    row["observedAt"] = self.observed_connected[operation_id]
        return evidence

    def compensate_settings(self):
        return self.transport.compensate_temporary(
            self.mutations[CONFIGURE], self.emitted_proofs[CONFIGURE], self.state()
        )
