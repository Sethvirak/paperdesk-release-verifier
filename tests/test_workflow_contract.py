from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
CONTROL = ROOT / ".github" / "workflows" / "azure-production-control.yml"
VERIFY = ROOT / ".github" / "workflows" / "verify-candidate.yml"
WATCHDOG = ROOT / ".github" / "workflows" / "accepted-release-deadline-watchdog.yml"

MAPPING_ENTRY = re.compile(
    r"^(?P<indent> *)(?P<key>[A-Za-z0-9_-]+):(?:[ ]*(?P<value>.*))?$"
)


def mapping_block(source, path):
    """Return the line bounds and indentation for a strict YAML mapping path."""
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
            if line.startswith("\t") or line[: len(line) - len(line.lstrip(" \t"))].find("\t") >= 0:
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
                f"expected exactly one mapping key {'/'.join(path)!r}; found {len(matches)} for {key!r}"
            )

        index, match = matches[0]
        if (match.group("value") or "").strip():
            raise AssertionError(f"workflow key {'/'.join(path)!r} must contain a nested mapping")
        block_end = end
        for candidate in range(index + 1, end):
            line = lines[candidate]
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            indent = len(line) - len(line.lstrip(" "))
            if indent <= expected_indent:
                block_end = candidate
                break
        start = index + 1
        end = block_end
        parent_indent = expected_indent

    return lines, start, end, parent_indent


def direct_mapping(source, path, *, require_scalar_values=False):
    """Read direct children of a mapping without implementing general YAML."""
    lines, start, end, parent_indent = mapping_block(source, path)
    child_indent = parent_indent + 2
    result = {}
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
        raise AssertionError(f"workflow step {name!r} was not found exactly once")
    return match.group(0)


class WorkflowContractTests(unittest.TestCase):
    def workflow(self, path):
        source = path.read_text(encoding="utf-8")
        self.assertTrue(direct_mapping(source, ("jobs",)), path)
        return source

    def test_all_actions_are_full_sha_pinned(self):
        for path in (CONTROL, VERIFY, WATCHDOG):
            source = self.workflow(path)
            actions = re.findall(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", source, flags=re.M)
            self.assertTrue(actions, path)
            for action in actions:
                self.assertRegex(action, r"^[^@\s]+@[0-9a-f]{40}$", action)

    def test_artifact_verifier_has_no_oidc_or_azure(self):
        source = self.workflow(VERIFY)
        self.assertNotIn("id-token", source)
        self.assertNotIn("azure/login", source)
        self.assertNotIn("environment:", source)
        self.assertEqual(
            direct_mapping(source, ("permissions",), require_scalar_values=True),
            {"actions": "read", "contents": "read"},
        )

    def test_azure_login_lives_only_in_pinned_external_control(self):
        source = self.workflow(CONTROL)
        self.assertIn("id-token: write", source)
        self.assertIn("azure/login@532459ea530d8321f2fb9bb10d1e0bcf23869a43", source)
        self.assertIn("ACTIONS_ID_TOKEN_REQUEST_URL", source)
        self.assertIn("claims.job_workflow_ref", source)
        self.assertIn("claims.job_workflow_sha", source)
        self.assertIn("claims.workflow_ref", source)
        self.assertNotIn("${{ job.workflow_", source)
        self.assertIn("oidc-canary-read-resource", source)
        self.assertIn("az webapp show", source)
        self.assertIn("environment: paperdesk-production-control", source)
        self.assertEqual(
            direct_mapping(
                source,
                ("jobs", "azure_production_control", "permissions"),
                require_scalar_values=True,
            ),
            {"actions": "read", "contents": "read", "id-token": "write"},
        )

    def test_mutating_modes_remain_hard_stopped(self):
        source = self.workflow(CONTROL)
        coordinate_step = workflow_step(
            source, "Validate immutable caller and operation coordinates before OIDC"
        )
        self.assertIn("application-specific deployment action remains fail-closed", source)
        self.assertIn("this source receives independent review", coordinate_step)
        self.assertIn("the old workflow SHA is denied", coordinate_step)
        self.assertRegex(
            coordinate_step,
            r'if \[ "\$\{OPERATION\}" != "oidc-canary-read-resource" \]; then\n'
            r'.*?\n\s+exit 1\n\s+fi',
        )
        self.assertGreaterEqual(source.count("exit 1"), 3)

    def test_registry_contract_is_fixed_bounded_and_manifest_last(self):
        source = self.workflow(CONTROL)
        self.assertNotIn("registry_container_url", source)
        self.assertNotIn("accepted_release_coordinate", source)
        for required in (
            "mdspdbak2608089c4e",
            "paperdesk-accepted-releases",
            "paperdesk-release-registry-bridge-9c4e0d0d",
            "rg-paperdesk-rollback-sea-20260808",
            "rg-master-data-structure-sea",
            "accepted_release_registry.py build",
            "v1/releases/${SOURCE_SHA}/${SOURCE_RUN_ID}/${ACCEPTANCE_RUN_ID}/",
            "assert_bridge_stopped_and_sealed",
            "trap cleanup_bridge EXIT INT TERM",
            ".publicNetworkAccess",
            "properties.allow=false",
            "PAPERDESK_BRIDGE_SESSION_TOKEN_SHA256",
        ):
            self.assertIn(required, source)
        for transient_setting in (
            "PAPERDESK_REGISTRY_GITHUB_TOKEN",
            "PAPERDESK_REGISTRY_GITHUB_ARTIFACT_ID",
            "PAPERDESK_REGISTRY_ARTIFACT_ZIP_SHA256",
            "PAPERDESK_REGISTRY_REQUEST_SHA256",
            "PAPERDESK_REGISTRY_EXPECTED_PREFIX",
            "PAPERDESK_REGISTRY_OPERATION",
        ):
            self.assertGreaterEqual(source.count(transient_setting), 3)
        self.assertIn("actions: read", source)
        inputs = direct_mapping(source, ("on", "workflow_call", "inputs"))
        for required_input in (
            "caller_sha",
            "acceptance_run_id",
            "acceptance_run_attempt",
            "acceptance_workflow_ref",
            "production_acceptance_receipt_name",
            "production_acceptance_receipt_sha256",
            "evidence_run_id",
            "evidence_run_attempt",
            "evidence_artifact_name",
            "evidence_bundle_sha256",
            "registry_preflight_source_sha",
            "registry_preflight_run_id",
            "registry_preflight_run_attempt",
            "registry_preflight_receipt_sha256",
        ):
            self.assertIn(required_input, inputs)

    def test_registry_transport_is_single_flight_digest_bound_and_secret_safe(self):
        source = self.workflow(CONTROL)
        self.assertEqual(
            direct_mapping(
                source,
                ("jobs", "azure_production_control", "concurrency"),
                require_scalar_values=True,
            ),
            {
                "group": "paperdesk-immutable-azure-production-control",
                "cancel-in-progress": "false",
            },
        )

        upload_step = workflow_step(source, "Upload exact one-shot registry transfer artifact")
        for required in (
            "id: registry_transfer",
            "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f",
            "retention-days: 1",
            "compression-level: 0",
            "overwrite: false",
            "if-no-files-found: error",
        ):
            self.assertIn(required, upload_step)

        metadata_step = workflow_step(source, "Bind exact uploaded registry transfer metadata")
        for required in (
            "/actions/artifacts/${EXPECTED_ARTIFACT_ID}",
            ".id | tostring",
            ".name == $artifactName",
            ".expired == false",
            ".digest == $artifactDigest",
            ".workflow_run.id | tostring",
            ".workflow_run.head_sha == $headSha",
            '"sha256:${EXPECTED_ARTIFACT_DIGEST}"',
        ):
            self.assertIn(required, metadata_step)

        persistence_step = workflow_step(
            source, "Preflight and persist accepted-release material through fixed bridge"
        )
        for required in (
            'readonly web_api_version="2025-05-01"',
            'mktemp "${RUNNER_TEMP}/paperdesk-registry-settings.XXXXXX.json"',
            'chmod 600 "${transient_settings_file}"',
            '--settings "@${transient_settings_file}"',
            'rm -f "${transient_settings_file}"',
            "/triggeredwebjobs/${webjob_name}/run?api-version=${web_api_version}",
            "/triggeredwebjobs/${webjob_name}/history?api-version=${web_api_version}",
            "new_count > 1",
            "properties.runs | type == \"array\" and length == 1",
            "Success)",
            "stable_deadline=$((SECONDS + 15))",
            '.[0].properties.runs[0].status == "Success"',
            'test "$(jq -r \'.linuxFxVersion\' <<< "${config_json}")" = "PYTHON|3.12"',
            'test "$(jq -r \'.alwaysOn\' <<< "${config_json}")" = "true"',
            'test "$(jq -r \'.webJobsEnabled\' <<< "${config_json}")" = "true"',
            'and .properties.run_command == "run.sh"',
        ):
            self.assertIn(required, persistence_step)
        self.assertNotIn(
            'PAPERDESK_REGISTRY_GITHUB_TOKEN="${TRANSIENT_GITHUB_TOKEN}"',
            persistence_step,
        )
        self.assertNotIn('--arg githubToken "${TRANSIENT_GITHUB_TOKEN}"', persistence_step)
        self.assertIn("env.TRANSIENT_GITHUB_TOKEN", persistence_step)

        activation = persistence_step.split(
            "# This source-complete path remains unreachable behind the independent-review",
            1,
        )[1]
        self.assertIn(
            "independently reviewed canonical package-bootstrap receipt and checksum",
            activation,
        )
        self.assertEqual(activation.count("run_runtime_canary"), 1)
        self.assertEqual(activation.count("run_persistence_once"), 2)
        self.assertLess(activation.index("run_runtime_canary"), activation.index("run_persistence_once"))

        seal_step = workflow_step(source, "Seal fixed registry bridge after every bridge attempt")
        canonical_transient = (
            "PAPERDESK_BRIDGE_SESSION_TOKEN_SHA256",
            "PAPERDESK_REGISTRY_ARTIFACT_URL",
            "PAPERDESK_REGISTRY_ARTIFACT_HOST",
            "PAPERDESK_REGISTRY_GITHUB_TOKEN",
            "PAPERDESK_REGISTRY_GITHUB_ARTIFACT_ID",
            "PAPERDESK_REGISTRY_ARTIFACT_ZIP_SHA256",
            "PAPERDESK_REGISTRY_REQUEST_SHA256",
            "PAPERDESK_REGISTRY_EXPECTED_PREFIX",
            "PAPERDESK_REGISTRY_OPERATION",
        )
        for transient_setting in canonical_transient:
            self.assertIn(transient_setting, persistence_step)
            self.assertGreaterEqual(seal_step.count(transient_setting), 2)
        persistence_function = persistence_step.split("run_persistence_once() {", 1)[1].split(
            "trap cleanup_bridge", 1
        )[0]
        self.assertNotIn("PAPERDESK_REGISTRY_ARTIFACT_URL", persistence_function)
        self.assertNotIn("PAPERDESK_REGISTRY_ARTIFACT_HOST", persistence_function)
        self.assertNotIn("az webapp update", persistence_step)
        self.assertNotIn("az webapp update", seal_step)
        self.assertIn("cleanup_failed=0", seal_step)
        self.assertIn("site_id_valid=0", seal_step)
        self.assertIn('if [ "${site_id_valid}" -eq 1 ]; then', seal_step)
        delete_offset = seal_step.index("az webapp config appsettings delete")
        final_assert_offset = seal_step.index("site_json=", delete_offset)
        self.assertLess(delete_offset, final_assert_offset)
        self.assertIn('test "${cleanup_failed}" -eq 0', seal_step)

    def test_registry_storage_and_bridge_resource_groups_are_not_cross_wired(self):
        source = self.workflow(CONTROL)
        worm_step = re.search(
            r"(?s)      - name: Capture exact live locked WORM policy through Azure control identity.*?"
            r"(?=\n      - name:)",
            source,
        ).group(0)
        self.assertIn(
            "/resourceGroups/rg-paperdesk-rollback-sea-20260808/providers/Microsoft.Storage/",
            worm_step,
        )
        self.assertNotIn("/resourceGroups/rg-master-data-structure-sea/providers/Microsoft.Storage/", worm_step)

        for step_name in (
            "Preflight and persist accepted-release material through fixed bridge",
            "Seal fixed registry bridge after every bridge attempt",
        ):
            step = re.search(
                rf"(?s)      - name: {re.escape(step_name)}.*?(?=\n      - name:)",
                source,
            ).group(0)
            self.assertIn("BRIDGE_RESOURCE_GROUP: rg-master-data-structure-sea", step)
            self.assertNotIn("BRIDGE_RESOURCE_GROUP: rg-paperdesk-rollback-sea-20260808", step)

        self.assertNotIn("BRIDGE_RESOURCE_GROUP: rg-paperdesk-rollback-sea-20260808", source)

    def test_registry_preflight_is_dormant_retained_and_required_before_persistence(self):
        source = self.workflow(CONTROL)
        coordinate_step = workflow_step(
            source, "Validate immutable caller and operation coordinates before OIDC"
        )
        self.assertIn("registry-bridge-preflight)", coordinate_step)
        self.assertIn(
            ".github/workflows/production-registry-bridge-preflight.yml@refs/heads/main",
            coordinate_step,
        )
        self.assertIn(
            'if [ "${OPERATION}" != "oidc-canary-read-resource" ]; then',
            coordinate_step,
        )
        self.assertFalse(
            (ROOT / "evidence" / "registry-bridge-bootstrap-receipt.json").exists(),
            "the canonical bootstrap receipt must be added only by the later reviewed activation commit",
        )

        checkout_step = workflow_step(
            source, "Check out immutable registry control and bootstrap trust anchor"
        )
        self.assertIn("steps.immutable_coordinates.outputs.control_workflow_sha", checkout_step)
        self.assertIn("persist-credentials: false", checkout_step)
        anchor_step = workflow_step(
            source, "Verify canonical independently reviewed package bootstrap receipt"
        )
        for required in (
            'readonly receipt_name="registry-bridge-bootstrap-receipt.json"',
            'sha256sum --check --strict "${receipt_name}.sha256"',
            'keys == ["bootstrapAuthority", "bridge", "deployment", "package", "reviewedMergeSha", "reviewedSourceSha", "schemaVersion", "status", "webJob"]',
            '(.deployment | keys) == ["apiVersion", "liveDeployment", "resourceId"]',
            '.deployment.liveDeployment.statusCode == 4',
            '.deployment.liveDeployment.responseObjectSha256',
            'extensions/onedeploy"',
            'runCommand: "run.sh"',
            'mode: "0755", size: 746',
            'mode: "0644", size: 88',
            'mode: "0644", size: 82202',
            '"Microsoft.Web/sites/extensions/Write"',
            '"Microsoft.Web/sites/extensions/Read"',
            '"Microsoft.Web/sites/publish/Action"',
            '.bootstrapAuthority.verifiedAbsent == true',
            '.bootstrapAuthority.automationRedeployAudit.remainingDedicatedRedeployAssignments == []',
            '.bootstrapAuthority.automationRedeployAudit.temporaryBootstrapAssignmentDeleted == true',
            '.bootstrapAuthority.automationRedeployAudit.effectiveRoleAssignmentInventory',
            'inventory_sha256=',
            '.grantsRedeploy == false',
            'every-preflight-detects-onedeploy-drift',
            'deployment_completed_epoch <= authority_removed_epoch',
            'authority_removed_epoch <= authority_audit_epoch',
        ):
            self.assertIn(required, anchor_step)
        self.assertNotIn("actions/download-artifact", anchor_step)

        worm_step = workflow_step(
            source, "Capture exact live locked WORM policy through Azure control identity"
        )
        self.assertIn("inputs.operation == 'registry-bridge-preflight'", worm_step)
        download_step = workflow_step(
            source, "Download exact successful registry bridge preflight receipt"
        )
        self.assertIn(
            "actions/download-artifact@018cc2cf5baa6db3ef3c5f8a56943fffe632ef53",
            download_step,
        )
        self.assertIn("registry_preflight_run_id", download_step)
        verify_step = workflow_step(
            source, "Verify successful registry bridge preflight before persistence"
        )
        for required in (
            "/actions/runs/${PREFLIGHT_RUN_ID}",
            '.path == ".github/workflows/production-registry-bridge-preflight.yml"',
            '.conclusion == "success"',
            'test "$(sha256sum "${receipt}" | cut -d \' \' -f 1)" = "${PREFLIGHT_RECEIPT_SHA256}"',
            ".controlWorkflowRef == $controlWorkflowRef",
            ".registryBridgePreflight.packageBootstrap == {receiptSha256: $bootstrapReceiptSha256, receipt: $currentBootstrap[0]}",
            ".registryBridgePreflight.oneDeploy == $currentBootstrap[0].deployment",
            ".registryBridgePreflight.bridge == $currentBootstrap[0].bridge",
            '.registryBridgePreflight.webJob.runCommand == "run.sh"',
            '.registryBridgePreflight.webJob.runtimeCanaryAnchor == "independently-reviewed-package-bootstrap-receipt"',
            ".registryBridgePreflight.webJob.status == \"Success\"",
            ".registryBridgePreflight.wormPolicy.etag == $currentWorm[0].etag",
            "now_epoch - preflight_observed_epoch <= 86400",
        ):
            self.assertIn(required, verify_step)

        bridge_step = workflow_step(
            source, "Preflight and persist accepted-release material through fixed bridge"
        )
        self.assertIn('if [ "${OPERATION}" = "registry-bridge-preflight" ]; then', bridge_step)
        self.assertIn("write_preflight_proof", bridge_step)
        self.assertIn('test "${OPERATION}" = "persist-accepted-release"', bridge_step)
        self.assertLess(
            bridge_step.index('if [ "${OPERATION}" = "registry-bridge-preflight" ]; then'),
            bridge_step.index('test "${OPERATION}" = "persist-accepted-release"'),
        )
        self.assertIn(
            "TRANSIENT_GITHUB_TOKEN: ${{ inputs.operation == 'persist-accepted-release' && github.token || '' }}",
            bridge_step,
        )
        proof_function = bridge_step.split("write_preflight_proof() {", 1)[1].split(
            "run_persistence_once() {", 1
        )[0]
        self.assertIn('--slurpfile bootstrap "paperdesk-registry-control/evidence/registry-bridge-bootstrap-receipt.json"', proof_function)
        self.assertIn('packageBootstrap: {receiptSha256: $bootstrapReceiptSha256, receipt: $bootstrap[0]}', proof_function)
        self.assertIn('runtimeCanaryAnchor: "independently-reviewed-package-bootstrap-receipt"', proof_function)
        self.assertIn('test "${webjob_run_command}" = "run.sh"', proof_function)
        self.assertIn('--argjson liveOneDeploy "${live_onedeploy_deployment}"', proof_function)
        self.assertIn('and .oneDeploy == $bootstrap[0].deployment', proof_function)
        self.assertNotIn('--arg packageSha256 "${EXPECTED_PACKAGE_SHA256}"', proof_function)
        self.assertIn('select(.name == "PAPERDESK_REGISTRY_PACKAGE_SHA256")', proof_function)

        self.assertIn("verify_live_onedeploy_anchor() {", bridge_step)
        onedeploy_function = bridge_step.split("verify_live_onedeploy_anchor() {", 1)[1].split(
            "cleanup_bridge() {", 1
        )[0]
        for required in (
            '/extensions/onedeploy?api-version=${web_api_version}',
            '(.value | length) == 1',
            '(.nextLink // "") == ""',
            '.value[0].properties.status == 4',
            '.value[0].properties.active == true',
            "jq --sort-keys --compact-output '.value[0]'",
            "expected_live_deployment=",
            'test "${live_onedeploy_deployment}" = "${expected_live_deployment}"',
        ):
            self.assertIn(required, onedeploy_function)
        self.assertLess(
            bridge_step.index("verify_live_onedeploy_anchor\n          if"),
            bridge_step.index('if [ "${OPERATION}" = "registry-bridge-preflight" ]; then'),
        )

        runtime_canary_function = bridge_step.split("run_runtime_canary() {", 1)[1].split(
            "write_preflight_proof() {", 1
        )[0]
        persistence_function = bridge_step.split("run_persistence_once() {", 1)[1].split(
            "trap cleanup_bridge", 1
        )[0]
        for label, function in (
            ("runtime canary", runtime_canary_function),
            ("persistence", persistence_function),
        ):
            with self.subTest(webjob_wait=label):
                self.assertEqual(function.count("wait_for_fixed_webjob"), 1)
                self.assertLess(
                    function.index("az webapp start"),
                    function.index("wait_for_fixed_webjob"),
                )
                self.assertLess(
                    function.index("wait_for_fixed_webjob"),
                    function.index("trigger_fixed_webjob_and_wait"),
                )

        receipt_step = workflow_step(source, "Create bounded control receipt")
        self.assertIn("--arg schemaVersion '2'", receipt_step)
        self.assertIn("registryBridgePreflight: $registryBridgePreflight", receipt_step)
        self.assertIn("registryPreflightReceiptSha256", receipt_step)
        retained_step = workflow_step(source, "Retain immutable-control receipt")
        self.assertIn("retention-days: 90", retained_step)

    def test_caller_release_and_fixed_production_coordinates_are_separate(self):
        source = self.workflow(CONTROL)
        self.assertIn('test "${CALLER_SHA}" = "${GITHUB_SHA}"', source)
        self.assertNotIn('test "${SOURCE_SHA}" = "${GITHUB_SHA}"', source)
        self.assertIn(
            'test "${GITHUB_WORKFLOW_REF}" = "Sethvirak/MasterDataStructure/.github/workflows/'
            'persist-accepted-release.yml@refs/heads/main"',
            source,
        )
        for fixed_coordinate in (
            'test "${EXPECTED_APP_NAME}" = "master-data-structure-sea-9c4e0d0d"',
            'test "${EXPECTED_RESOURCE_GROUP}" = "rg-master-data-structure-sea"',
            'test "${EXPECTED_LIVE_URL}" = "https://master-data-structure-sea-9c4e0d0d.azurewebsites.net"',
        ):
            self.assertIn(fixed_coordinate, source)
        self.assertNotIn('[[ "${EXPECTED_APP_NAME}" =~', source)

    def test_receipts_and_registry_artifacts_bind_exact_workflow_runs(self):
        source = self.workflow(CONTROL)
        receipt_step = re.search(
            r"(?s)      - name: Verify exact receipt digest before any Azure mutation.*?"
            r"(?=\n      - name:)",
            source,
        ).group(0)
        verifier_env = (
            "VERIFIER_WORKFLOW_REF: Sethvirak/paperdesk-release-verifier/.github/workflows/"
            "verify-candidate.yml@23fc16fca795e0c6786f35aae863167fe80aa3cd"
        )

        def assert_receipt_step_contract(step_source):
            self.assertIn(verifier_env, step_source)
            self.assertIn(".verifierWorkflow == env.VERIFIER_WORKFLOW_REF", step_source)

        assert_receipt_step_contract(receipt_step)
        with self.assertRaises(AssertionError):
            assert_receipt_step_contract(receipt_step.replace(verifier_env, "", 1))
        for exact_check in (
            ".repository.full_name",
            ".head_repository.full_name",
            ".head_sha",
            ".head_branch",
            ".path",
            ".event",
            ".github/workflows/main_master-data-structure-sea-9c4e0d0d.yml",
            ".github/workflows/production-evidence-intake.yml",
            "main_master-data-structure-sea-9c4e0d0d.yml@refs/heads/main",
            "persist-accepted-release.yml@refs/heads/main",
            "source_event",
            ".workflow_run.repository_id",
            ".workflow_run.head_repository_id",
            'test "${ACCEPTANCE_RUN_ID}" != "${SOURCE_RUN_ID}"',
            'test "${EVIDENCE_RUN_ID}" != "${SOURCE_RUN_ID}"',
            'test "${EVIDENCE_RUN_ID}" != "${ACCEPTANCE_RUN_ID}"',
        ):
            self.assertIn(exact_check, source)

    def test_only_read_only_canary_reaches_oidc(self):
        source = self.workflow(CONTROL)
        hard_stop = source.index('if [ "${OPERATION}" != "oidc-canary-read-resource" ]; then')
        azure_login = source.index("      - name: Azure login from the immutable reusable-workflow identity")
        self.assertLess(hard_stop, azure_login)
        self.assertIn('test "${SOURCE_SHA}" = "${CALLER_SHA}"', source)
        self.assertIn('test "${SOURCE_RUN_ID}" = "${GITHUB_RUN_ID}"', source)
        self.assertIn('test "${SOURCE_RUN_ATTEMPT}" = "${GITHUB_RUN_ATTEMPT}"', source)


if __name__ == "__main__":
    unittest.main()
