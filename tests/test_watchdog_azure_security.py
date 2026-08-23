import copy
from pathlib import Path
import sys
import unittest
import urllib.parse


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from provider import watchdog_state_provider as provider


SUBSCRIPTION_ID = "00000000-0000-4000-8000-000000000001"
SUBSCRIPTION_SCOPE = f"/subscriptions/{SUBSCRIPTION_ID}"
RESOURCE_GROUP_SCOPE = (
    f"{SUBSCRIPTION_SCOPE}/resourceGroups/{provider.STORAGE_RESOURCE_GROUP}"
)
ACCOUNT_SCOPE = (
    f"{RESOURCE_GROUP_SCOPE}/providers/Microsoft.Storage/storageAccounts/"
    f"{provider.STORAGE_ACCOUNT}"
)


def bindings():
    scopes = {
        "state-read-write": (
            f"{ACCOUNT_SCOPE}/blobServices/default/containers/{provider.STATE_CONTAINER}"
        ),
        "evidence-create-only": (
            f"{ACCOUNT_SCOPE}/blobServices/default/containers/{provider.EVIDENCE_CONTAINER}"
        ),
        "evidence-read-only": (
            f"{ACCOUNT_SCOPE}/blobServices/default/containers/{provider.EVIDENCE_CONTAINER}"
        ),
        "registry-read-only": (
            f"{ACCOUNT_SCOPE}/blobServices/default/containers/{provider.REGISTRY_CONTAINER}"
        ),
        "arm-policy-read-only": SUBSCRIPTION_SCOPE,
    }
    result = {}
    for index, role in enumerate(sorted(provider.AzureStorageBackend.ROLE_NAMES), start=10):
        result[role] = provider.AzureIdentityBinding(
            role=role,
            client_id=f"00000000-0000-4000-8001-{index:012d}",
            principal_id=f"00000000-0000-4000-8002-{index:012d}",
            identity_resource_id=(
                f"{RESOURCE_GROUP_SCOPE}/providers/Microsoft.ManagedIdentity/"
                f"userAssignedIdentities/paperdesk-{role}"
            ),
            assignment_id=f"00000000-0000-4000-8003-{index:012d}",
            definition_id=f"00000000-0000-4000-8004-{index:012d}",
            scope=scopes[role],
        )
    return result


class SecurityPostureFixture(provider.AzureStorageBackend):
    def __init__(self):
        self.bindings = bindings()
        super().__init__(
            SUBSCRIPTION_ID,
            {role: (object(), binding) for role, binding in self.bindings.items()},
        )
        self.assignment_lists = {
            binding.principal_id: [self.assignment(binding)]
            for binding in self.bindings.values()
        }
        self.definition_documents = {
            binding.definition_id: self.definition(role, binding)
            for role, binding in self.bindings.items()
        }
        self.next_links = {}
        self.role_list_requests = []

    @staticmethod
    def definition_resource(binding):
        return (
            f"{SUBSCRIPTION_SCOPE}/providers/Microsoft.Authorization/roleDefinitions/"
            f"{binding.definition_id}"
        )

    @classmethod
    def assignment(cls, binding, *, scope=None, assignment_id=None):
        scope = scope or binding.scope
        assignment_id = assignment_id or binding.assignment_id
        return {
            "id": (
                f"{scope}/providers/Microsoft.Authorization/roleAssignments/"
                f"{assignment_id}"
            ),
            "name": assignment_id,
            "type": "Microsoft.Authorization/roleAssignments",
            "properties": {
                "condition": None,
                "conditionVersion": None,
                "delegatedManagedIdentityResourceId": None,
                "principalId": binding.principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": cls.definition_resource(binding),
                "scope": scope,
            },
        }

    @staticmethod
    def expected_permissions(role):
        return {
            "state-read-write": (
                [],
                [provider.AzureStorageBackend.BLOB_READ, provider.AzureStorageBackend.BLOB_WRITE],
            ),
            "evidence-create-only": (
                [],
                [provider.AzureStorageBackend.BLOB_WRITE],
            ),
            "evidence-read-only": (
                [],
                [provider.AzureStorageBackend.BLOB_READ],
            ),
            "registry-read-only": (
                [],
                [provider.AzureStorageBackend.BLOB_READ],
            ),
            "arm-policy-read-only": (
                sorted(provider.AzureStorageBackend.ARM_POLICY_ACTIONS),
                [],
            ),
        }[role]

    @classmethod
    def definition(cls, role, binding):
        actions, data_actions = cls.expected_permissions(role)
        definition_resource = cls.definition_resource(binding)
        return {
            "id": definition_resource,
            "name": binding.definition_id,
            "type": "Microsoft.Authorization/roleDefinitions",
            "properties": {
                "type": "CustomRole",
                "assignableScopes": [SUBSCRIPTION_SCOPE],
                "permissions": [{
                    "actions": actions,
                    "notActions": [],
                    "dataActions": data_actions,
                    "notDataActions": [],
                }],
            },
        }

    def _arm_json(self, path):
        if path == f"{ACCOUNT_SCOPE}?api-version={provider.ARM_API_VERSION}":
            return {
                "properties": {
                    "allowSharedKeyAccess": False,
                    "allowBlobPublicAccess": False,
                    "publicNetworkAccess": "Disabled",
                }
            }
        for container in (
            provider.STATE_CONTAINER,
            provider.EVIDENCE_CONTAINER,
            provider.REGISTRY_CONTAINER,
        ):
            scope = f"{ACCOUNT_SCOPE}/blobServices/default/containers/{container}"
            if path == f"{scope}?api-version={provider.ARM_API_VERSION}":
                return {"properties": {"publicAccess": None}}
        for role, binding in self.bindings.items():
            if path == f"{binding.identity_resource_id}?api-version=2023-01-31":
                return {
                    "id": binding.identity_resource_id,
                    "properties": {
                        "clientId": binding.client_id,
                        "principalId": binding.principal_id,
                    },
                }
            definition_resource = self.definition_resource(binding)
            if path == f"{definition_resource}?api-version=2022-04-01":
                return copy.deepcopy(self.definition_documents[binding.definition_id])
        parsed = urllib.parse.urlsplit(path)
        expected_path = (
            f"{SUBSCRIPTION_SCOPE}/providers/Microsoft.Authorization/roleAssignments"
        )
        if parsed.path == expected_path:
            query = urllib.parse.parse_qs(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=True,
            )
            if set(query) != {"api-version", "$filter"}:
                raise AssertionError(f"unexpected role assignment query: {path}")
            if query["api-version"] != ["2022-04-01"]:
                raise AssertionError(f"unexpected role assignment API version: {path}")
            filter_value = query["$filter"]
            if len(filter_value) != 1 or not filter_value[0].startswith("principalId eq '"):
                raise AssertionError(f"unexpected role assignment filter: {path}")
            principal_id = filter_value[0].removeprefix("principalId eq '").removesuffix("'")
            if filter_value[0] != f"principalId eq '{principal_id}'":
                raise AssertionError(f"unexpected role assignment filter: {path}")
            if principal_id not in self.assignment_lists:
                raise AssertionError(f"unknown role assignment principal: {path}")
            self.role_list_requests.append(path)
            return {
                "value": copy.deepcopy(self.assignment_lists[principal_id]),
                "nextLink": self.next_links.get(principal_id),
            }
        raise AssertionError(f"unexpected ARM proof path: {path}")


class AzureSecurityPostureTests(unittest.TestCase):
    def assert_invalid(self, mutate, role="state-read-write"):
        backend = SecurityPostureFixture()
        binding = backend.bindings[role]
        mutate(backend, binding)
        with self.assertRaises(provider.ProviderError) as caught:
            backend._read_security_posture()
        self.assertEqual(caught.exception.status, 503)
        self.assertEqual(caught.exception.code, "rbac-proof-invalid")

    def test_subscription_scope_principal_filter_proves_exact_direct_assignments(self):
        backend = SecurityPostureFixture()

        posture = backend._read_security_posture()

        self.assertEqual(len(posture["assignments"]), 5)
        self.assertEqual(len(backend.role_list_requests), 5)
        expected_prefix = (
            f"{SUBSCRIPTION_SCOPE}/providers/Microsoft.Authorization/roleAssignments"
            "?api-version=2022-04-01&%24filter=principalId+eq+%27"
        )
        self.assertTrue(all(path.startswith(expected_prefix) for path in backend.role_list_requests))
        self.assertTrue(all("atScope" not in path for path in backend.role_list_requests))
        self.assertTrue(all("assignedTo" not in path for path in backend.role_list_requests))
        expected_filters = {
            f"principalId eq '{binding.principal_id}'"
            for binding in backend.bindings.values()
        }
        actual_filters = {
            urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)["$filter"][0]
            for path in backend.role_list_requests
        }
        self.assertEqual(actual_filters, expected_filters)

    def test_arm_resource_ids_guids_and_scopes_accept_valid_mixed_case(self):
        backend = SecurityPostureFixture()
        for binding in backend.bindings.values():
            assignment = backend.assignment_lists[binding.principal_id][0]
            assignment["id"] = assignment["id"].upper()
            assignment["name"] = assignment["name"].upper()
            assignment["properties"]["principalId"] = binding.principal_id.upper()
            assignment["properties"]["roleDefinitionId"] = assignment["properties"][
                "roleDefinitionId"
            ].upper()
            assignment["properties"]["scope"] = binding.scope.upper()
            definition = backend.definition_documents[binding.definition_id]
            definition["id"] = definition["id"].upper()
            definition["name"] = definition["name"].upper()
            definition["properties"]["assignableScopes"] = [SUBSCRIPTION_SCOPE.upper()]

        posture = backend._read_security_posture()

        self.assertEqual(len(posture["assignments"]), 5)

    def test_extra_assignment_at_parent_subscription_resource_group_child_or_other_scope_fails(self):
        state_scope = bindings()["state-read-write"].scope
        scopes = {
            "parent": ACCOUNT_SCOPE,
            "subscription": SUBSCRIPTION_SCOPE,
            "resource-group": RESOURCE_GROUP_SCOPE,
            "child": f"{state_scope}/providers/Microsoft.Authorization/locks/state-child",
            "other": (
                f"{RESOURCE_GROUP_SCOPE}/providers/Microsoft.Storage/storageAccounts/"
                "paperdesk-unexpected/blobServices/default/containers/unexpected"
            ),
        }
        for label, extra_scope in scopes.items():
            with self.subTest(label=label):
                def add_extra(backend, binding, scope=extra_scope):
                    backend.assignment_lists[binding.principal_id].append(
                        backend.assignment(
                            binding,
                            scope=scope,
                            assignment_id="00000000-0000-4000-8005-000000000099",
                        )
                    )

                self.assert_invalid(add_extra)

    def test_missing_wrong_id_role_or_scope_fails(self):
        mutations = {
            "missing": lambda backend, binding: backend.assignment_lists.__setitem__(
                binding.principal_id, []
            ),
            "wrong-id": lambda backend, binding: backend.assignment_lists[
                binding.principal_id
            ][0].__setitem__(
                "id",
                f"{binding.scope}/providers/Microsoft.Authorization/roleAssignments/"
                "00000000-0000-4000-8005-000000000098",
            ),
            "wrong-role": lambda backend, binding: backend.assignment_lists[
                binding.principal_id
            ][0]["properties"].__setitem__(
                "roleDefinitionId",
                f"{SUBSCRIPTION_SCOPE}/providers/Microsoft.Authorization/roleDefinitions/"
                "00000000-0000-4000-8005-000000000097",
            ),
            "wrong-scope": lambda backend, binding: backend.assignment_lists[
                binding.principal_id
            ][0]["properties"].__setitem__("scope", ACCOUNT_SCOPE),
            "wrong-principal": lambda backend, binding: backend.assignment_lists[
                binding.principal_id
            ][0]["properties"].__setitem__(
                "principalId", "00000000-0000-4000-8005-000000000093"
            ),
            "malformed-value": lambda backend, binding: backend.assignment_lists.__setitem__(
                binding.principal_id, {}
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                self.assert_invalid(mutate)

    def test_assignment_row_type_name_principal_type_and_unconditional_shape_are_exact(self):
        mutations = {
            "type": lambda row, binding: row.__setitem__(
                "type", "Microsoft.Authorization/roleDefinitions"
            ),
            "name": lambda row, binding: row.__setitem__(
                "name", "00000000-0000-4000-8005-000000000096"
            ),
            "principal-type": lambda row, binding: row["properties"].__setitem__(
                "principalType", "Group"
            ),
            "condition": lambda row, binding: row["properties"].__setitem__(
                "condition", "@Resource[Microsoft.Storage/storageAccounts:name] StringEquals 'x'"
            ),
            "condition-version": lambda row, binding: row["properties"].__setitem__(
                "conditionVersion", "2.0"
            ),
            "delegated": lambda row, binding: row["properties"].__setitem__(
                "delegatedManagedIdentityResourceId", binding.identity_resource_id
            ),
        }
        for label, mutate_row in mutations.items():
            with self.subTest(label=label):
                def mutate(backend, binding, apply=mutate_row):
                    apply(backend.assignment_lists[binding.principal_id][0], binding)

                self.assert_invalid(mutate)

    def test_absent_optional_condition_and_delegation_fields_are_unconditional(self):
        backend = SecurityPostureFixture()
        for binding in backend.bindings.values():
            properties = backend.assignment_lists[binding.principal_id][0]["properties"]
            properties.pop("condition")
            properties.pop("conditionVersion")
            properties.pop("delegatedManagedIdentityResourceId")

        posture = backend._read_security_posture()

        self.assertEqual(len(posture["assignments"]), 5)

    def test_role_assignment_pagination_fails_closed(self):
        def add_next_link(backend, binding):
            backend.next_links[binding.principal_id] = (
                "https://management.azure.com/subscriptions/next-page"
            )

        self.assert_invalid(add_next_link)

    def test_role_definition_identity_scope_and_permission_envelope_are_exact(self):
        def row(backend, binding):
            return backend.definition_documents[binding.definition_id]

        mutations = {
            "id": lambda document, binding: document.__setitem__(
                "id",
                f"{SUBSCRIPTION_SCOPE}/providers/Microsoft.Authorization/roleDefinitions/"
                "00000000-0000-4000-8005-000000000095",
            ),
            "name": lambda document, binding: document.__setitem__(
                "name", "00000000-0000-4000-8005-000000000094"
            ),
            "type": lambda document, binding: document.__setitem__(
                "type", "Microsoft.Authorization/roleAssignments"
            ),
            "custom-role-type": lambda document, binding: document["properties"].__setitem__(
                "type", "BuiltInRole"
            ),
            "assignable-scope-missing": lambda document, binding: document["properties"].__setitem__(
                "assignableScopes", []
            ),
            "assignable-scope-wrong": lambda document, binding: document["properties"].__setitem__(
                "assignableScopes", [RESOURCE_GROUP_SCOPE]
            ),
            "assignable-scope-extra": lambda document, binding: document["properties"].__setitem__(
                "assignableScopes", [SUBSCRIPTION_SCOPE, RESOURCE_GROUP_SCOPE]
            ),
            "permission-count": lambda document, binding: document["properties"]
            ["permissions"].append(copy.deepcopy(document["properties"]["permissions"][0])),
            "extra-action": lambda document, binding: document["properties"]
            ["permissions"][0]["actions"].append("Microsoft.Storage/storageAccounts/write"),
            "duplicate-action": lambda document, binding: document["properties"]
            ["permissions"][0]["actions"].append(
                document["properties"]["permissions"][0]["actions"][0]
            ),
            "extra-data-action": lambda document, binding: document["properties"]
            ["permissions"][0]["dataActions"].append(
                "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"
            ),
            "duplicate-data-action": lambda document, binding: document["properties"]
            ["permissions"][0]["dataActions"].append(
                document["properties"]["permissions"][0]["dataActions"][0]
            ),
            "not-action": lambda document, binding: document["properties"]
            ["permissions"][0]["notActions"].append("Microsoft.Storage/storageAccounts/write"),
            "not-action-null": lambda document, binding: document["properties"]
            ["permissions"][0].__setitem__("notActions", None),
            "not-data-action": lambda document, binding: document["properties"]
            ["permissions"][0]["notDataActions"].append(
                "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"
            ),
            "not-data-action-null": lambda document, binding: document["properties"]
            ["permissions"][0].__setitem__("notDataActions", None),
        }
        for label, mutate_document in mutations.items():
            with self.subTest(label=label):
                def mutate(backend, binding, apply=mutate_document):
                    apply(row(backend, binding), binding)

                role = "arm-policy-read-only" if label == "duplicate-action" else "state-read-write"
                self.assert_invalid(mutate, role=role)

    def test_readme_keeps_subscription_direct_assignment_and_entra_pim_boundary_explicit(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for phrase in (
            "subscription-scope ARM 2022-04-01 List For Scope",
            "`principalId eq '<principalId>'`",
            (
                "The proof covers direct role assignments at, above, and below the fixed "
                "approved subscription only; it cannot inventory unrelated sibling "
                "subscriptions, Entra group or transitive grants, or PIM eligibility or "
                "activation."
            ),
            "separate Entra/PIM audit identity and P2/Identity Governance coverage",
            "activation remains blocked",
        ):
            self.assertIn(phrase, readme)


if __name__ == "__main__":
    unittest.main()
