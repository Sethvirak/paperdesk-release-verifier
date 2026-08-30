from pathlib import Path
import hashlib
import json
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONTROL = ROOT / ".github" / "workflows" / "azure-production-control.yml"
VERIFY = ROOT / ".github" / "workflows" / "verify-candidate.yml"
WATCHDOG = ROOT / ".github" / "workflows" / "accepted-release-deadline-watchdog.yml"
BASELINE = ROOT / ".github" / "workflows" / "initialize-watchdog-rollback-baseline.yml"
RECONCILIATION = ROOT / ".github" / "workflows" / "reconcile-watchdog-dispatch.yml"
CONTRACT = ROOT / "contracts" / "private_release_mailbox_contract.json"
PROVISIONING = ROOT / "evidence" / "private-release-provisioning-evidence.json"
MAILBOX = ROOT / "scripts" / "private_release_mailbox.py"
CONTROLLER = ROOT / "scripts" / "private_release_external_controller.py"
BRIDGE_RUNTIME = ROOT / "provider" / "private_release_bridge_runtime.py"
BRIDGE_AZURE = ROOT / "provider" / "private_release_bridge_azure.py"
V2_DOC = ROOT / "docs" / "private-release-mailbox-v2.md"
README = ROOT / "README.md"


MAPPING_ENTRY = re.compile(
    r"^(?P<indent> *)(?P<key>[A-Za-z0-9_-]+):(?:[ ]*(?P<value>.*))?$"
)


def mapping_block(source, path):
    """Return the bounds and indentation for one strict YAML mapping path."""
    lines = source.splitlines()
    start = 0
    end = len(lines)
    parent_indent = -2
    for key in path:
        expected_indent = parent_indent + 2
        matches = []
        for index in range(start, end):
            line = lines[index]
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if "\t" in line[: len(line) - len(line.lstrip(" \t"))]:
                raise AssertionError("workflow mappings must use spaces, not tabs")
            match = MAPPING_ENTRY.match(line)
            if (
                match
                and len(match.group("indent")) == expected_indent
                and match.group("key") == key
            ):
                matches.append((index, match))
        if len(matches) != 1:
            raise AssertionError(
                f"expected one mapping key {'/'.join(path)!r}; found {len(matches)} for {key!r}"
            )
        index, match = matches[0]
        if (match.group("value") or "").strip():
            raise AssertionError(f"workflow key {'/'.join(path)!r} must contain a mapping")
        block_end = end
        for candidate in range(index + 1, end):
            line = lines[candidate]
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if len(line) - len(line.lstrip(" ")) <= expected_indent:
                block_end = candidate
                break
        start = index + 1
        end = block_end
        parent_indent = expected_indent
    return lines, start, end, parent_indent


def direct_mapping(source, path, *, require_scalar_values=False):
    lines, start, end, parent_indent = mapping_block(source, path)
    result = {}
    child_indent = parent_indent + 2
    for index in range(start, end):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = MAPPING_ENTRY.match(line)
        if not match or len(match.group("indent")) != child_indent:
            continue
        key = match.group("key")
        if key in result:
            raise AssertionError(f"duplicate workflow mapping key {'/'.join((*path, key))!r}")
        value = (match.group("value") or "").strip()
        if require_scalar_values and not value:
            raise AssertionError(f"workflow mapping key {'/'.join((*path, key))!r} must be scalar")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        result[key] = value or None
    if not result:
        raise AssertionError(f"workflow mapping {'/'.join(path)!r} must not be empty")
    return result


def workflow_step(source, name):
    match = re.search(
        rf"(?s)^      - name: {re.escape(name)}\n.*?(?=^      - name:|\Z)",
        source,
        flags=re.M,
    )
    if match is None:
        raise AssertionError(f"workflow step {name!r} was not found")
    return match.group(0)


def function_source(source, name):
    match = re.search(
        rf"(?ms)^def {re.escape(name)}\(.*?(?=^def |^class |\Z)", source
    )
    if match is None:
        raise AssertionError(f"function {name!r} was not found")
    return match.group(0)


class WorkflowContractTests(unittest.TestCase):
    def workflow(self, path):
        source = path.read_text(encoding="utf-8")
        self.assertTrue(direct_mapping(source, ("jobs",)), path)
        return source

    def test_all_actions_are_immutable_full_sha_pinned(self):
        for path in (CONTROL, VERIFY, WATCHDOG, BASELINE, RECONCILIATION):
            source = self.workflow(path)
            actions = re.findall(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", source, flags=re.M)
            self.assertTrue(actions, path)
            for action in actions:
                self.assertRegex(action, r"^[^@\s]+@[0-9a-f]{40}$", action)

    def test_artifact_verifier_remains_read_only_and_cloud_free(self):
        source = self.workflow(VERIFY)
        self.assertEqual(
            direct_mapping(source, ("permissions",), require_scalar_values=True),
            {"actions": "read", "contents": "read"},
        )
        for forbidden in ("id-token", "azure/login", "environment:", "az ", "Microsoft.Web"):
            self.assertNotIn(forbidden, source)

    def test_candidate_receipt_verifier_ref_tracks_the_exact_control_workflow_sha(self):
        source = self.workflow(CONTROL)
        dynamic_ref = (
            "Sethvirak/paperdesk-release-verifier/.github/workflows/"
            "verify-candidate.yml@${{ job.workflow_sha }}"
        )
        self.assertEqual(source.count(dynamic_ref), 2)
        self.assertIsNone(
            re.search(
                r"verify-candidate\.yml@[0-9a-f]{40}",
                source,
            )
        )

    def test_registry_preflight_reuses_production_caller_and_exact_path_resolution(self):
        source = self.workflow(CONTROL)
        self.assertIn(
            "Release-state read-only registry bridge preflight", source
        )
        self.assertNotIn("description: Read-only registry bridge preflight", source)
        coordinate = workflow_step(
            source, "Validate immutable caller and operation coordinates before OIDC"
        )
        self.assertIn("registry-bridge-preflight)", coordinate)
        self.assertIn('test "${GITHUB_WORKFLOW_REF}" = "${production_workflow_ref}"', coordinate)
        self.assertEqual(
            set(re.findall(r'expected_caller_workflow_id="([0-9]+)"', coordinate)),
            {"306965591", "340547201", "334414600"},
        )

        mailbox = MAILBOX.read_text(encoding="utf-8")
        resolver = function_source(mailbox, "resolve_current_accepted")
        self.assertIn('strict_blob=f"v2/accepted/{source_sha}/manifest.json"', resolver)
        self.assertIn(
            'bootstrap_blob=f"v2/accepted/{source_sha}/bootstrap-consumed/manifest.json"',
            resolver,
        )
        self.assertEqual(resolver.count("_read_current("), 2)
        for forbidden in ("list_blobs", ".list(", "walk_blobs", "iter_blobs"):
            self.assertNotIn(forbidden, resolver.lower())
        self.assertIn("accepted-current-ambiguous", resolver)
        self.assertIn("accepted-current-absent", resolver)

        external = CONTROLLER.read_text(encoding="utf-8")
        self.assertIn(
            'request["operation"]=="registry-bridge-preflight" and activate', external
        )
        runtime = BRIDGE_RUNTIME.read_text(encoding="utf-8")
        preflight_branch = runtime.split(
            'if operation=="registry-bridge-preflight":', 1
        )[1].split('elif operation=="bootstrap-prepare":', 1)[0]
        self.assertIn("production_activation.observe", preflight_branch)
        self.assertNotIn("activation_fence", preflight_branch)

        for document in (
            README.read_text(encoding="utf-8"),
            V2_DOC.read_text(encoding="utf-8"),
        ):
            normalized_document = " ".join(document.split())
            self.assertIn("release-state read-only", normalized_document)
            for transient in (
                "controller lease",
                "mailbox request/result",
                "temporary bridge App Settings",
                "starts and stops the exact WebJob",
            ):
                self.assertIn(transient, normalized_document)

    def test_activation_variable_preserves_exact_canonical_bytes(self):
        source = self.workflow(CONTROL)
        exact_write = (
            "printf '%s' \"${PRIVATE_RELEASE_ACTIVATION_JSON}\" > \"${activation}\""
        )
        newline_write = (
            "printf '%s\\n' \"${PRIVATE_RELEASE_ACTIVATION_JSON}\" > \"${activation}\""
        )
        self.assertEqual(source.count(exact_write), 2)
        self.assertNotIn(newline_write, source)

        external = CONTROLLER.read_text(encoding="utf-8")
        self.assertIn(
            'activation_raw=Path(args.activation).read_text(encoding="utf-8")',
            external,
        )
        self.assertGreaterEqual(external.count("raw_document=activation_raw"), 2)

    def test_public_receipt_retains_exact_release_descriptors(self):
        source = self.workflow(CONTROL)
        receipt = workflow_step(source, "Create bounded control receipt")
        self.assertIn("--arg schemaVersion '6'", receipt)
        self.assertIn('--arg candidateRunId "${CANDIDATE_RUN_ID}"', receipt)
        self.assertIn('--arg candidateRunAttempt "${CANDIDATE_RUN_ATTEMPT}"', receipt)
        for field in ("acceptedBaseline", "pendingRelease", "consumedMarker"):
            self.assertIn(f"--argjson {field}", receipt)
            self.assertIn(field, receipt)
        self.assertIn('keys == ["acceptedBaseline","consumedMarker","pendingRelease"]', receipt)
        self.assertIn('keys == ["blob","etag","sha256","size","versionId"]', receipt)
        self.assertIn(
            "A successful registry operation must retain exact accepted/pending/consumed descriptors.",
            receipt,
        )
        self.assertIn("registry-bridge-preflight", receipt)
        self.assertIn("bootstrap-consumed/manifest.json", receipt)

    def test_persistence_keeps_source_deployment_acceptance_and_evidence_runs_distinct(self):
        source = self.workflow(CONTROL)
        inputs = direct_mapping(source, ("on", "workflow_call", "inputs"))
        self.assertIn("candidate_run_id", inputs)
        self.assertIn("candidate_run_attempt", inputs)

        coordinate = workflow_step(
            source, "Validate immutable caller and operation coordinates before OIDC"
        )
        for marker in (
            '[[ "${CANDIDATE_RUN_ID}" =~ ^[1-9][0-9]*$ ]]',
            '[[ "${CANDIDATE_RUN_ATTEMPT}" =~ ^[1-9][0-9]*$ ]]',
            'test "${CANDIDATE_RUN_ID}" != "${SOURCE_RUN_ID}"',
            'test "${CANDIDATE_RUN_ID}" != "${ACCEPTANCE_RUN_ID}"',
            'test "${EVIDENCE_RUN_ID}" != "${CANDIDATE_RUN_ID}"',
            'test "${GITHUB_RUN_ID}" != "${CANDIDATE_RUN_ID}"',
            'test -z "${CANDIDATE_RUN_ID}${CANDIDATE_RUN_ATTEMPT}"',
        ):
            self.assertIn(marker, coordinate)

        resolver = workflow_step(
            source, "Resolve exact accepted-release artifact identities and digests"
        )
        self.assertIn(
            'resolve_artifact "${CANDIDATE_RUN_ID}" "${CANDIDATE_RUN_ATTEMPT}" "paperdesk-deployment-coordinate-receipt-${SOURCE_SHA}" deployment',
            resolver,
        )
        self.assertIn("Deploy exact candidate pending final acceptance", resolver)

        deployment_download = workflow_step(
            source, "Download exact deployment-coordinate receipt"
        )
        self.assertIn("run-id: ${{ inputs.candidate_run_id }}", deployment_download)
        deployment_validation = workflow_step(
            source, "Validate deployment-coordinate receipt before registry bridge activation"
        )
        for field in (
            "candidateSourceRunId", "candidateSourceRunAttempt",
            "deploymentRunId", "deploymentRunAttempt", "candidateRuntimeSha256",
        ):
            self.assertIn(field, deployment_validation)
        self.assertIn('cmp --silent "${receipt}" "${expected}"', deployment_validation)

        acceptance_validation = workflow_step(
            source, "Validate production-acceptance receipt before registry bridge activation"
        )
        self.assertIn('and .candidateRunId == $candidateRunId', acceptance_validation)
        self.assertIn('and .candidateRunAttempt == $candidateRunAttempt', acceptance_validation)
        self.assertNotIn('and .candidateRunId == $sourceRunId', acceptance_validation)

        builder = workflow_step(source, "Build deterministic bounded registry transfer request")
        for flag in (
            "--candidate-run-id", "--candidate-run-attempt", "--deployment-workflow-ref",
            "--deployment-coordinate-receipt", "--deployment-coordinate-artifact-id",
            "--deployment-coordinate-artifact-name", "--deployment-coordinate-artifact-digest",
        ):
            self.assertIn(flag, builder)

        mailbox = workflow_step(
            source, "Persist or recover release exclusively through the signed private mailbox"
        )
        self.assertIn('"schemaVersion":2', mailbox)
        self.assertIn('"candidateRunId":os.environ["CANDIDATE_RUN_ID"] if operation=="persist-accepted-release" else None', mailbox)
        self.assertIn('"candidateRunAttempt":os.environ["CANDIDATE_RUN_ATTEMPT"] if operation=="persist-accepted-release" else None', mailbox)

    def test_private_release_v2_is_dormant_until_s2_evidence_and_fic_repin(self):
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        evidence = json.loads(PROVISIONING.read_text(encoding="utf-8"))
        self.assertEqual(contract["status"], "source-dormant")
        self.assertTrue(contract["activation"])
        self.assertTrue(all(value is None for value in contract["activation"].values()))
        self.assertIsNone(contract["activation"]["mergedControlWorkflowSha"])
        self.assertIsNone(contract["activation"]["bridgePackageSourceSha"])
        self.assertEqual(evidence["status"], "source-dormant")

        baseline = contract["fixed"]["bootstrapBaseline"]
        self.assertIn("oneDeployInvariant", baseline)
        self.assertNotIn("activeOneDeployId", baseline)

        source = self.workflow(CONTROL)
        coordinate = workflow_step(
            source, "Validate immutable caller and operation coordinates before OIDC"
        )
        login = source.index("      - name: Azure login from the immutable reusable-workflow identity")
        self.assertLess(source.index(coordinate), login)
        self.assertIn(".activation.mergedControlWorkflowSha == $workflowSha", coordinate)
        self.assertIn("([.activation[] | select(. == null)] | length) == 0", coordinate)
        self.assertIn("RUNTIME_CONTROL_WORKFLOW_SHA: ${{ job.workflow_sha }}", coordinate)

        readme = README.read_text(encoding="utf-8")
        operator = V2_DOC.read_text(encoding="utf-8")
        for document, heading in (
            (readme, "## Activation trust DAG"),
            (operator, "## Trust DAG and activation sequence"),
        ):
            for required in (
                "S1-prime",
                "S2",
                "sole pre-S2 Azure-mutation exception",
                "external single-use authorization",
                "reusable workflow",
                "mailbox",
                "production activation",
                "accepted-release",
                "caller integration",
            ):
                self.assertIn(required, document)
            sequence = document[document.index(heading):]
            self.assertLess(sequence.index("S1-prime"), sequence.index("S2"))
            self.assertLess(
                sequence.index("external single-use authorization"),
                sequence.index("S2"),
            )
            self.assertLess(sequence.index("S2"), sequence.index("repin"))

        contradictory = (
            "No Azure mutation is authorized before S2 evidence acceptance",
            "every mutating mode must stop before Azure login",
        )
        for phrase in contradictory:
            self.assertNotIn(phrase, readme)
            self.assertNotIn(phrase, operator)

    def test_public_evidence_exception_is_narrow_and_secret_material_is_forbidden(self):
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn("narrow exception", security)
        self.assertIn("canonical, non-secret", security)
        for forbidden_material in (
            "raw IP addresses",
            "bearer or refresh tokens",
            "SAS query strings",
            "Shared Key/account keys",
            "GitHub/OIDC claim tokens",
            "customer records",
        ):
            self.assertIn(forbidden_material, security)
        for receipt_boundary in (
            "operator-controlled, access-restricted real directory",
            "Same-privilege replacement",
            "file and directory durability barriers",
            "requires manual reconciliation",
        ):
            self.assertIn(receipt_boundary, security)

    def test_bootstrap_observe_apply_and_local_resume_are_real_fail_closed_paths(self):
        readme = README.read_text(encoding="utf-8")
        operator = V2_DOC.read_text(encoding="utf-8")
        executor = (ROOT / "scripts/private_release_v2_bootstrap.py").read_text(
            encoding="utf-8"
        )
        observer = (
            ROOT / "scripts/private_release_v2_bootstrap_observe.py"
        ).read_text(encoding="utf-8")
        for document in (readme, operator):
            for required in (
                "private_release_v2_bootstrap.py describe",
                "private_release_v2_bootstrap.py apply",
                "private_release_v2_bootstrap.py resume-finalization",
                "private_release_v2_bootstrap_observe.py",
                "deliberately non-executable authorization template",
                "original authorized preflight",
                "terminal bundle last",
                "zero Azure requests or mutations",
            ):
                self.assertIn(required, document)
        self.assertIn(
            'choices=("describe", "apply", "resume-finalization")', executor
        )
        self.assertIn("resume_local_finalization_from_snapshot(", executor)
        self.assertIn("receipts.validate_receipt_bundle(", executor)
        self.assertIn('READ_METHODS = {"GET", "POST"}', observer)
        self.assertIn("class AzureCliReadOnlySession:", observer)
        self.assertIn('if __name__ == "__main__":', observer)
        self.assertNotIn("Future apply", readme)
        self.assertNotIn("Future apply", operator)

    def test_s2_repin_and_offline_activation_are_documented_as_separate_gates(self):
        readme = README.read_text(encoding="utf-8")
        operator = V2_DOC.read_text(encoding="utf-8")
        for required in (
            "private_release_v2_fic_repin.py describe",
            "private_release_v2_fic_repin.py observe",
            "private_release_v2_fic_repin.py apply",
            "private_release_v2_fic_repin.py validate-receipt",
            "private_release_v2_activation.py",
            "deliberately non-executable",
            "empty intermediate",
            "mergedControlWorkflowSha",
            "bridgePackageSourceSha",
            "separately authorized caller-integration",
        ):
            self.assertIn(required, readme)
        for required in (
            "S2 repin and activation ceremony",
            "authorization-specific empty ARM deployment claim",
            "exact sole S2 credential",
            "06-terminal-receipt.json",
            "offline-only, create-only builder",
            "separate exact ledger",
            "caller-integration mutations require",
            "authorization after the activation output",
        ):
            self.assertIn(required, operator)
        self.assertNotIn("S1-prime and S2 credentials overlap", readme)
        self.assertNotIn("publishes the activation document", operator)

    def test_exact_callers_and_reusable_workflow_identity_are_cross_bound(self):
        source = self.workflow(CONTROL)
        coordinate = workflow_step(
            source, "Validate immutable caller and operation coordinates before OIDC"
        )
        for required in (
            'expected_caller_workflow_id="306965591"',
            'expected_caller_workflow_id="340547201"',
            'expected_caller_workflow_id="334414600"',
            'production_workflow_path=".github/workflows/main_master-data-structure-sea-9c4e0d0d.yml"',
            'persist_workflow_path=".github/workflows/persist-accepted-release.yml"',
            'cleanup_workflow_path=".github/workflows/production-oidc-canary.yml"',
            'test "${JOB_WORKFLOW_FILE_PATH}" = ".github/workflows/azure-production-control.yml"',
            'test "${JOB_WORKFLOW_REF}" = "${CONTROL_WORKFLOW_REF}"',
        ):
            self.assertIn(required, coordinate)

        claims = workflow_step(
            source, "Prove exact reusable-workflow and caller claims before Azure login"
        )
        for claim in (
            ".sub",
            ".job_workflow_ref",
            ".job_workflow_sha",
            ".repository_id",
            ".repository_owner_id",
            ".run_id",
            ".run_attempt",
        ):
            self.assertIn(claim, claims)

        controller = CONTROLLER.read_text(encoding="utf-8")
        for claim in (
            'claims.get("appid")!=self.activation.publisher_client_id',
            'claims.get("azp")!=self.activation.publisher_client_id',
            'claims.get("oid")!=self.activation.publisher_principal_id',
            'claims.get("sub")!=self.activation.publisher_principal_id',
        ):
            self.assertIn(claim, controller)

        revalidate = workflow_step(
            source, "Revalidate exact caller workflow identity before Azure login"
        )
        for field in (".workflow_id", ".name", ".path", ".head_sha", ".head_branch", ".event"):
            self.assertIn(field, revalidate)

    def test_runner_has_no_direct_storage_onedeploy_or_production_setting_mutation(self):
        source = self.workflow(CONTROL)
        for forbidden in (
            "az storage ",
            "az webapp deploy",
            "az webapp start",
            "az webapp stop",
            "az webapp restart",
            "az webapp config appsettings",
            "/extensions/onedeploy",
            "/config/appsettings?api-version=2025-03-01",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("scripts/private_release_external_controller.py", source)

    def test_bridge_token_is_transient_stopped_private_bridge_state(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        lease = source.split("class BridgeLease:", 1)[1].split("def _stamp", 1)[0]
        self.assertIn('"PAPERDESK_TRANSIENT_GITHUB_TOKEN"', lease)
        self.assertIn('"githubTokenSha256":core.digest(self.github_token.encode())', lease)
        self.assertIn("self.assert_stopped()", lease)
        self.assertLess(lease.index("self.assert_stopped()"), lease.index("self.settings.put_if_digest"))
        self.assertIn("bridge-transient-preexisting", lease)
        self.assertIn("bridge-settings-acquire-third-state", lease)
        for forbidden in ("sig=", "listKeys", "SharedKey"):
            self.assertNotIn(forbidden, source)

    def test_run_from_package_uses_versioned_worm_bytes_and_manifest_last(self):
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        baseline = contract["fixed"]["bootstrapBaseline"]
        invariant = baseline["oneDeployInvariant"]
        self.assertEqual(
            set(invariant),
            {
                "historicalActiveDeploymentId",
                "collectionSemanticProjectionSha256",
                "propertyIdSetSha256",
                "deploymentCount",
            },
        )

        mailbox = MAILBOX.read_text(encoding="utf-8")
        runtime = BRIDGE_RUNTIME.read_text(encoding="utf-8")
        self.assertIn("?versionid={descriptor['versionId']}", mailbox)
        self.assertIn('"WEBSITE_RUN_FROM_PACKAGE":package_url', mailbox)
        self.assertIn('"WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID":activation["registryReaderManagedIdentityResourceId"]', mailbox)
        self.assertIn('desired["WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID"]="SystemAssigned"', runtime)
        self.assertIn('item["immutabilityPeriodSinceCreationInDays"]<91', mailbox)

        persist = function_source(mailbox, "persist_accepted_release")
        self.assertLess(persist.index("accepted_bundle=_create_or_read_exact"), persist.index("manifest=_create_or_read_exact"))
        self.assertLess(persist.index("result=_create_or_read_exact"), persist.index("manifest=_create_or_read_exact"))
        self.assertIn('_load_accepted(boundary,request["acceptedBaseline"],package_boundary)', mailbox)

    def test_historical_onedeploy_is_full_collection_evidence_not_activation(self):
        mailbox = MAILBOX.read_text(encoding="utf-8")
        azure = BRIDGE_AZURE.read_text(encoding="utf-8")
        docs = V2_DOC.read_text(encoding="utf-8")
        for required in (
            "historicalActiveDeploymentId",
            "collectionSemanticProjectionSha256",
            "propertyIdSetSha256",
            "deploymentCount",
        ):
            self.assertIn(required, mailbox)
            self.assertIn(required, azure)
        self.assertNotIn("activeOneDeployId", mailbox)
        self.assertNotIn("active OneDeploy ID", docs)
        self.assertIn("historical full OneDeploy collection invariant", " ".join(docs.split()))

    def test_live_versioned_key_get_and_jwk_match_precede_privileged_work(self):
        runtime = BRIDGE_RUNTIME.read_text(encoding="utf-8")
        mailbox = MAILBOX.read_text(encoding="utf-8")
        azure = BRIDGE_AZURE.read_text(encoding="utf-8")
        process = function_source(runtime, "process_request")
        self.assertLess(process.index("live_key=key_reader()"), process.index("validate_request"))
        self.assertIn("validate_live_signing_key(live_key,activation,now=now)", process)
        self.assertIn("keyDataPlaneGetUrl", azure)
        self.assertIn("kv-read-coordinate", azure)
        for required in (
            "live-key-projection",
            "live-key-expiry",
            "live-key-jwk",
            'attributes.get("enabled") is not True',
            'attributes.get("exportable") is not False',
        ):
            self.assertIn(required, mailbox)

    def test_controller_and_activation_leases_are_finite_and_fail_closed(self):
        controller = CONTROLLER.read_text(encoding="utf-8")
        azure = BRIDGE_AZURE.read_text(encoding="utf-8")
        cleanup_acquire = function_source(controller, "acquire_cleanup_controller_lease")
        self.assertIn("attempts=8", cleanup_acquire)
        self.assertIn("interval_seconds=10", cleanup_acquire)
        self.assertIn("(attempts-1)*interval_seconds<=60", cleanup_acquire)
        self.assertIn('"leaseDuration":60', controller)
        self.assertIn("controller-lease-lost", controller)
        self.assertIn('properties.get("leaseStatus")!="Unlocked"', controller)

        fence = azure.split("class BlobActivationFence:", 1)[1].split("class ProductionActivation:", 1)[0]
        for required in (
            '"stateVersion"',
            '"pendingRelease"',
            '"preSettingsSha256"',
            '"desiredSettingsSha256"',
            '"x-ms-lease-duration":"60"',
            "fence-busy",
            "fence-completion-binding",
        ):
            self.assertIn(required, fence)

        mailbox = MAILBOX.read_text(encoding="utf-8")
        for required in (
            "activation-recovery-third-state",
            "activation-rollback-third-state",
            "rollback-third-state",
            "activation-consumption-indeterminate",
        ):
            self.assertIn(required, mailbox)

    def test_cleanup_has_exact_provenance_durable_obligation_and_runner_loss_path(self):
        source = self.workflow(CONTROL)
        controller = CONTROLLER.read_text(encoding="utf-8")
        mailbox = MAILBOX.read_text(encoding="utf-8")
        runtime = BRIDGE_RUNTIME.read_text(encoding="utf-8")

        cleanup = workflow_step(
            source, "Clean only exact terminal-owner private bridge transient state"
        )
        for required in (
            'OWNER_WORKFLOW_ID: ${{ github.event.workflow_run.workflow_id }}',
            'OWNER_RUN_ATTEMPT: ${{ github.event.workflow_run.run_attempt }}',
            'OWNER_HEAD_SHA: ${{ github.event.workflow_run.head_sha }}',
            'OWNER_PATH: ${{ github.event.workflow_run.path }}',
            'OWNER_EVENT: ${{ github.event.workflow_run.event }}',
            "--cleanup-stale",
        ):
            self.assertIn(required, cleanup)

        self.assertIn("acquire_cleanup_controller_lease", controller)
        self.assertIn("expired-owner-api-unavailable", controller)
        self.assertIn("controller-cleanup-active", controller)
        self.assertIn("controller-cleanup-third-state", controller)
        self.assertIn("attach_cleanup_obligation", runtime)
        self.assertIn('"cleanupState":"required-after-terminal-result"', mailbox)
        self.assertIn("external-cleanup-pending", controller)
        self.assertIn('all(.housekeeping[]; .status == "complete" and .failures == [])', source)

        workflow_names = {path.name for path in (ROOT / ".github" / "workflows").glob("*.yml")}
        self.assertNotIn("private-release-cleanup.yml", workflow_names)
        self.assertNotIn("cleanup-private-release.yml", workflow_names)

    def test_mailbox_logical_create_only_and_authenticated_provenance(self):
        source = MAILBOX.read_text(encoding="utf-8")
        mailbox_class = source.split("class MailboxClient:", 1)[1].split("def cleanup_mailbox", 1)[0]
        for required in (
            'if response.status!=201: fail("mailbox-create")',
            "mailbox-create-readback",
            'system.get("createdBy")!=expected',
            'system.get("lastModifiedBy")!=expected',
            'system.get("createdAt")!=system.get("lastModifiedAt")',
            'state!="Succeeded"',
        ):
            self.assertIn(required, mailbox_class)
        self.assertIn("HTTP 200 is an", mailbox_class)
        self.assertIn("update and is always rejected", mailbox_class)

    def test_authorization_decisions_are_derived_without_risky_negative_writes(self):
        mailbox = MAILBOX.read_text(encoding="utf-8")
        docs = V2_DOC.read_text(encoding="utf-8") + README.read_text(encoding="utf-8")
        self.assertIn("publisherAuthorizationDecisions", mailbox)
        self.assertIn('deny=evidence.get("publisherAuthorizationDecisions")', mailbox)
        self.assertNotIn("publisherDenyMatrix", mailbox)
        self.assertNotIn("live negative canary", docs)
        self.assertIn("derived authorization decisions", docs)
        self.assertIn("no risky negative write", docs)

    def test_package_url_is_bound_metadata_not_a_secret(self):
        docs = V2_DOC.read_text(encoding="utf-8") + README.read_text(encoding="utf-8")
        self.assertNotIn("runner never receives a package URL", docs)
        self.assertIn("package URL is not a secret", docs)
        self.assertIn("no SAS", docs)

    def test_watchdog_v2_workflows_remain_source_dormant(self):
        cases = (
            (WATCHDOG, "enforce_deadline", "Source-dormant hard stop before GitHub OIDC or provider calls"),
            (BASELINE, "initialize_baseline", "Source-dormant hard stop before baseline OIDC or state creation"),
            (RECONCILIATION, "reconcile_dispatch", "Source-dormant hard stop before protected reconciliation OIDC"),
        )
        for path, job, step_name in cases:
            with self.subTest(path=path.name):
                source = self.workflow(path)
                self.assertEqual(
                    direct_mapping(source, ("jobs", job, "permissions"), require_scalar_values=True),
                    {"contents": "read", "id-token": "write"},
                )
                self.assertIn("ref: ${{ github.workflow_sha }}", source)
                self.assertIn("exit 1", workflow_step(source, step_name))

    def test_watchdog_digest_bound_sources_match_checked_out_bytes(self):
        expected_paths = {
            WATCHDOG: {
                "scripts/check_deadline.py",
                "scripts/watchdog_evidence.py",
                "scripts/watchdog_contract.py",
                "provider/watchdog_state_provider.py",
                "provider/accepted_release_manifest.py",
                "contracts/production_release_watchdog_contract.json",
            },
            BASELINE: {
                "scripts/watchdog_evidence.py",
                "provider/watchdog_state_provider.py",
                "contracts/production_release_watchdog_contract.json",
            },
            RECONCILIATION: {
                "scripts/watchdog_evidence.py",
                "provider/watchdog_state_provider.py",
            },
        }
        for workflow_path, required in expected_paths.items():
            source = self.workflow(workflow_path)
            bindings = dict(
                re.findall(
                    r"echo '([0-9a-f]{64})  ([A-Za-z0-9_./-]+)' \| sha256sum --check --strict",
                    source,
                )
            )
            self.assertEqual(set(bindings.values()), required)
            by_path = {path: digest for digest, path in bindings.items()}
            for relative in required:
                actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
                self.assertEqual(by_path[relative], actual, relative)


if __name__ == "__main__":
    unittest.main()
