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
        self.assertIn("application-specific deployment action remains fail-closed", source)
        self.assertIn("Bridge activation remains blocked", source)
        self.assertIn("independently verified artifact provenance", source)
        self.assertIn("ARM-triggerable in-VNet transport", source)
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
            "publicNetworkAccess=Disabled",
            "properties.allow=false",
            "PAPERDESK_BRIDGE_SESSION_TOKEN_SHA256",
        ):
            self.assertIn(required, source)
        for transient_setting in (
            "PAPERDESK_REGISTRY_ARTIFACT_URL",
            "PAPERDESK_REGISTRY_ARTIFACT_HOST",
            "PAPERDESK_REGISTRY_ARTIFACT_ZIP_SHA256",
            "PAPERDESK_REGISTRY_REQUEST_SHA256",
            "PAPERDESK_REGISTRY_EXPECTED_PREFIX",
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
        ):
            self.assertIn(required_input, inputs)

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
            "Persist accepted-release material through immutable Blob semantics",
            "Seal fixed registry bridge after every persistence attempt",
        ):
            step = re.search(
                rf"(?s)      - name: {re.escape(step_name)}.*?(?=\n      - name:)",
                source,
            ).group(0)
            self.assertIn("BRIDGE_RESOURCE_GROUP: rg-master-data-structure-sea", step)
            self.assertNotIn("BRIDGE_RESOURCE_GROUP: rg-paperdesk-rollback-sea-20260808", step)

        self.assertNotIn("BRIDGE_RESOURCE_GROUP: rg-paperdesk-rollback-sea-20260808", source)

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
