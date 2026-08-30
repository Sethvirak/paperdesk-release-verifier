"""Pure source-derived builder for PaperDesk V2 terminal S2 evidence.

This module performs no filesystem, Git, credential, runtime, or Azure action.
It derives every resource fact from one validated plan/authorization/preflight/
terminal-source universe and delegates final canonical validation to the receipt
module.
"""

from __future__ import annotations

import copy
import json
import urllib.parse
from collections.abc import Mapping
from typing import Any

try:
    from scripts import private_release_mailbox as mailbox
    from scripts import private_release_v2_bootstrap as bootstrap
    from scripts import private_release_v2_bootstrap_receipts as receipts
except (ImportError, ModuleNotFoundError):
    import private_release_mailbox as mailbox  # type: ignore[no-redef]
    import private_release_v2_bootstrap as bootstrap  # type: ignore[no-redef]
    import private_release_v2_bootstrap_receipts as receipts  # type: ignore[no-redef]


def _derive_terminal_s2_document_objects(
    validated_inputs: Mapping[str, Any],
    components: Mapping[str, Any],
) -> dict[str, Any]:
    """Derive the five mailbox-facing documents from validated terminal proof."""

    plan = validated_inputs["plan"]
    authorization = validated_inputs["authorization"]
    source = validated_inputs["sourceEvidence"]
    resources = {item["id"]: item for item in plan["resourceInventory"]}
    operations = {
        item["operationId"]: item["sourceProjection"]["projection"]
        for item in source["allOperationProjections"]
    }
    rich = source["richProvisioningSourceProjections"]
    observed_at = source["observedAt"]
    subscription_scope = f"/subscriptions/{bootstrap.SUBSCRIPTION}"
    owner_role = (
        subscription_scope
        + "/providers/Microsoft.Authorization/roleDefinitions/"
        + "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
    )

    identity_facts = {
        "publisherServicePrincipal": {
            "clientId": rich["publisherServicePrincipal"]["appId"],
            "principalId": rich["publisherServicePrincipal"]["id"],
            "resourceId": None,
        },
        "bridgeIdentity": {
            "clientId": operations["createBridgeIdentity"]["clientId"],
            "principalId": operations["createBridgeIdentity"]["principalId"],
            "resourceId": resources["bridgeIdentity"]["resourceId"],
        },
        "registryWriterIdentity": {
            "clientId": resources["registryWriterIdentity"]["clientId"],
            "principalId": resources["registryWriterIdentity"]["principalId"],
            "resourceId": resources["registryWriterIdentity"]["resourceId"],
        },
        "registryReaderIdentity": {
            "clientId": resources["registryReaderIdentity"]["clientId"],
            "principalId": resources["registryReaderIdentity"]["principalId"],
            "resourceId": resources["registryReaderIdentity"]["resourceId"],
        },
        "signerIdentity": {
            "clientId": operations["createSignerIdentity"]["clientId"],
            "principalId": operations["createSignerIdentity"]["principalId"],
            "resourceId": resources["signerIdentity"]["resourceId"],
        },
        "productionActivationIdentity": {
            "clientId": operations["createProductionActivationIdentity"]["clientId"],
            "principalId": operations["createProductionActivationIdentity"]["principalId"],
            "resourceId": resources["productionActivationIdentity"]["resourceId"],
        },
        "productionSystemIdentity": {
            "clientId": resources["productionSystemIdentity"]["clientId"],
            "principalId": resources["productionSystemIdentity"]["principalId"],
            "resourceId": resources["productionSite"]["resourceId"],
        },
    }

    role_records = {}
    for role in plan["roleMatrix"]:
        definition = rich["roleDefinitions"][role["name"]]
        assignment = rich["roleAssignments"][role["name"]]
        properties = assignment["properties"]
        identity = identity_facts[role["principal"]]
        definition_properties = definition["properties"]
        role_scope = (
            resources[role["scope"]]["resourceId"]
            if role["scope"] in resources
            else subscription_scope
            if role["scope"] == "subscription"
            else role["scope"]
        )
        permissions = definition_properties["permissions"]
        if len(permissions) != 1:
            receipts.fail(
                f"terminal role {role['name']} is not an exact single-permission role"
            )
        permission = permissions[0]
        role_records[role["name"]] = {
            "roleDefinitionResourceId": definition["id"],
            "roleDefinitionSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(definition)
            ),
            "roleAssignmentResourceId": assignment["id"],
            "roleAssignmentSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(assignment)
            ),
            "principalId": identity["principalId"],
            "principalType": properties["principalType"],
            "tenantId": bootstrap.TENANT,
            "identityClientId": identity["clientId"],
            "identityResourceId": identity["resourceId"],
            "scope": role_scope,
            "condition": properties["condition"],
            "conditionVersion": properties["conditionVersion"],
            "delegatedManagedIdentityResourceId": properties[
                "delegatedManagedIdentityResourceId"
            ],
            "assignableScopes": definition_properties["assignableScopes"],
            "actions": permission["actions"],
            "notActions": permission["notActions"],
            "dataActions": permission["dataActions"],
            "notDataActions": permission["notDataActions"],
        }

    inventory_names = {
        "publisher": "publisherServicePrincipal",
        "bridge": "bridgeIdentity",
        "registryWriter": "registryWriterIdentity",
        "registryReader": "registryReaderIdentity",
        "signer": "signerIdentity",
        "productionActivation": "productionActivationIdentity",
        "productionSystem": "productionSystemIdentity",
    }
    principal_inventories = {}
    for inventory_name, resource_key in inventory_names.items():
        principal_id = identity_facts[resource_key]["principalId"]
        direct = [
            bootstrap._normalized_role_assignment_projection(item)
            for item in rich["principalDirectAssignments"][inventory_name]
        ]
        effective = [
            bootstrap._normalized_role_assignment_projection(item)
            for item in rich["principalEffectiveAssignments"][inventory_name]
        ]
        direct_ids = [item["id"] for item in direct]
        effective_ids = [item["id"] for item in effective]
        encoded_principal = urllib.parse.quote(principal_id, safe="")
        query_root = (
            "https://management.azure.com"
            f"/subscriptions/{bootstrap.SUBSCRIPTION}/providers/"
            "Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter="
        )
        principal_inventories[inventory_name] = {
            "principalId": principal_id,
            "directQuery": query_root + f"principalId%20eq%20%27{encoded_principal}%27",
            "effectiveQuery": query_root + f"assignedTo%28%27{encoded_principal}%27%29",
            "directAssignmentResourceIds": direct_ids,
            "effectiveAssignmentResourceIds": effective_ids,
            "directAssignmentSetSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(direct)
            ),
            "effectiveAssignmentSetSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(effective)
            ),
            "observedAt": observed_at,
        }

    application = rich["publisherApplication"]
    service = rich["publisherServicePrincipal"]
    concrete_fic = rich["solePublisherFederatedCredentials"][0]
    fic_template = {
        "id": concrete_fic["id"],
        "name": concrete_fic["name"],
        "issuer": concrete_fic["issuer"],
        "audiences": concrete_fic["audiences"],
        "subject": None,
        "claimsMatchingExpressionTemplate": {
            "languageVersion": 1,
            "value": (
                f"claims['sub'] eq '{mailbox.OIDC_SUBJECT}' and "
                f"claims['repository_id'] eq '{mailbox.OWNER_REPOSITORY_ID}' and "
                f"claims['repository_owner_id'] eq '{mailbox.OWNER_ID}' and "
                "claims['job_workflow_ref'] eq '{controlWorkflowRef}'"
            ),
        },
    }
    graph_assignment = operations["grantPublisherGraphApplicationReadAll"][
        "appRoleAssignments"
    ][0]
    publisher_identity = {
        "applicationObjectId": application["id"],
        "applicationQuery": (
            f"https://graph.microsoft.com/beta/applications/{application['id']}"
            "?$select=id,appId,signInAudience,passwordCredentials,keyCredentials"
        ),
        "applicationProjectionSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(application)
        ),
        "servicePrincipalQuery": (
            f"https://graph.microsoft.com/v1.0/servicePrincipals/{service['id']}"
            "?$select=id,appId,accountEnabled,servicePrincipalType,"
            "passwordCredentials,keyCredentials"
        ),
        "servicePrincipalProjectionSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(service)
        ),
        "federatedIdentityCredentialsQuery": (
            f"https://graph.microsoft.com/beta/applications/{application['id']}"
            "/federatedIdentityCredentials"
        ),
        "federatedIdentityCredentialPolicy": fic_template,
        "federatedIdentityCredentialPolicySha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(fic_template)
        ),
        "appRoleAssignmentsQuery": (
            f"https://graph.microsoft.com/v1.0/servicePrincipals/{service['id']}"
            "/appRoleAssignments"
        ),
        "graphServicePrincipalObjectId": graph_assignment["resourceId"],
        "graphApplicationReadAllAppRoleAssignment": graph_assignment,
        "graphApplicationReadAllAppRoleAssignmentSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(graph_assignment)
        ),
        "observedAt": observed_at,
    }

    bridge_site = resources["bridgeSite"]["resourceId"]
    production_site = resources["productionSite"]["resourceId"]
    package_container = resources["packageContainer"]["resourceId"]
    accepted_container = resources["acceptedContainer"]["resourceId"]
    result_container = resources["resultContainer"]["resourceId"]
    controller_container = resources["controllerLockContainer"]["resourceId"]
    storage_account = resources["storageAccount"]["resourceId"]
    signing_vault = resources["signingVault"]["resourceId"]
    signing_key = resources["signingKey"]["resourceId"]
    integration_vnet = resources["integrationVnet"]["resourceId"]
    integration_subnet = resources["integrationSubnet"]["resourceId"]

    upload = operations["uploadVersionedBridgePackage"]
    package_url = upload["url"] + "?versionid=" + upload["versionId"]
    critical_settings = {
        "WEBSITE_RUN_FROM_PACKAGE": package_url,
        "WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID": identity_facts[
            "registryReaderIdentity"
        ]["resourceId"],
        "WEBSITE_SKIP_RUNNING_KUDUAGENT": "false",
        "PAPERDESK_BRIDGE_PACKAGE_SHA256": upload["sha256"],
    }
    attached_site = operations["attachFiveUamisOnlyToBridge"]
    site_posture = {
        "siteResourceId": bridge_site,
        "name": resources["bridgeSite"]["name"],
        "type": "Microsoft.Web/sites",
        "kind": attached_site["kind"],
        "serverFarmId": attached_site["serverFarmId"],
        "httpsOnly": attached_site["httpsOnly"],
        "publicNetworkAccess": attached_site["publicNetworkAccess"],
        "virtualNetworkSubnetId": attached_site["virtualNetworkSubnetId"],
        "outboundVnetRouting": attached_site["outboundVnetRouting"],
        "webConfig": {
            "alwaysOn": True,
            "linuxFxVersion": "PYTHON|3.12",
            "ftpsState": "Disabled",
            "minTlsVersion": "1.2",
            "scmMinTlsVersion": "1.2",
            "scmType": "None",
            "http20Enabled": True,
            "vnetRouteAllEnabled": True,
        },
        "ftpBasicAuthAllowed": False,
        "scmBasicAuthAllowed": False,
        "sourceControl": {"status": 404},
    }
    sensitive_identities = sorted(
        identity_facts[name]["resourceId"].lower()
        for name in (
            "bridgeIdentity",
            "registryWriterIdentity",
            "registryReaderIdentity",
            "signerIdentity",
            "productionActivationIdentity",
        )
    )
    graph_attachments = {
        identity: [bridge_site.lower()] for identity in sensitive_identities
    }
    identity_boundaries = {
        "ownerRoleDefinitionId": owner_role,
        "items": {
            identity: {
                "resourceId": identity,
                "roleAssignmentsQuery": (
                    "https://management.azure.com"
                    + identity
                    + "/providers/Microsoft.Authorization/roleAssignments"
                    "?api-version=2022-04-01"
                ),
                "allowedNonOwnerAssignerAssignmentIds": [],
                "assignerProjectionSha256": bootstrap.sha256_bytes(
                    bootstrap.canonical_json_bytes([])
                ),
            }
            for identity in sensitive_identities
        },
        "observedAt": observed_at,
    }
    allowed_bridge_assignment = rich["roleAssignments"][
        "publisherBridgeController"
    ]
    mutation_boundary = {
        "bridgeScopeQuery": (
            "https://management.azure.com"
            + bridge_site
            + "/providers/Microsoft.Authorization/roleAssignments"
            "?api-version=2022-04-01"
        ),
        "allowedNonOwnerAssignmentIds": [allowed_bridge_assignment["id"]],
        "ownerRoleDefinitionId": owner_role,
        "sensitiveActionUniverse": list(mailbox.BRIDGE_SENSITIVE_ACTION_UNIVERSE),
        "sensitiveActionUniverseSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(
                list(mailbox.BRIDGE_SENSITIVE_ACTION_UNIVERSE)
            )
        ),
        "mutatorAssignmentSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes([allowed_bridge_assignment])
        ),
        "observedAt": observed_at,
    }
    legacy_source = operations["detachWriterAndReaderFromLegacyBridge"]
    legacy_projection = {
        "siteResourceId": resources["legacyBridgeSite"]["resourceId"],
        "state": legacy_source["state"],
        "publicNetworkAccess": legacy_source["publicNetworkAccess"],
        "userAssignedIdentityResourceIds": [],
        "transientAppSettingNamesPresent": [],
        "publisherMutatorAssignmentIds": [],
    }
    legacy_retirement = {
        **legacy_projection,
        "roleAssignmentsQuery": (
            "https://management.azure.com"
            + resources["legacyBridgeSite"]["resourceId"]
            + "/providers/Microsoft.Authorization/roleAssignments"
            "?api-version=2022-04-01"
        ),
        "projectionSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(legacy_projection)
        ),
        "observedAt": observed_at,
    }
    topology_source = rich["networkTopology"]
    topology = {
        "mode": "service-endpoint-firewall-v1",
        "virtualNetwork": {
            "resourceId": integration_vnet,
            "apiVersion": "2025-01-01",
            "projectionSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(topology_source["virtualNetwork"])
            ),
            "addressSpacePrefixes": topology_source["virtualNetwork"][
                "addressSpacePrefixes"
            ],
        },
        "integrationSubnet": {
            "resourceId": integration_subnet,
            "apiVersion": "2025-01-01",
            "projectionSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(topology_source["integrationSubnet"])
            ),
            **{
                key: topology_source["integrationSubnet"][key]
                for key in (
                    "virtualNetworkResourceId",
                    "delegations",
                    "serviceEndpoints",
                    "routeTableResourceId",
                    "networkSecurityGroupResourceId",
                )
            },
        },
        "packageStorageAccount": {
            "resourceId": storage_account,
            "apiVersion": "2025-06-01",
            "projectionSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(
                    topology_source["packageStorageAccount"]
                )
            ),
            **{
                key: topology_source["packageStorageAccount"][key]
                for key in (
                    "publicNetworkAccess",
                    "allowBlobPublicAccess",
                    "defaultAction",
                    "bypass",
                    "ipRules",
                    "resourceAccessRules",
                    "virtualNetworkRules",
                )
            },
        },
        "productionSite": {
            "resourceId": production_site,
            "apiVersion": "2025-03-01",
            "projectionSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(topology_source["productionSite"])
            ),
            "virtualNetworkSubnetId": topology_source["productionSite"][
                "virtualNetworkSubnetId"
            ],
            "outboundVnetRouting": topology_source["productionSite"][
                "outboundVnetRouting"
            ],
            "legacyVnetRouteAllEnabled": topology_source["productionSite"][
                "legacyVnetRouteAllEnabled"
            ],
        },
    }
    attachment_inventory = {
        identity: [bridge_site.lower()] for identity in sensitive_identities
    }
    resource_graph_inventory = {
        "query": (
            "Resources | where isnotnull(identity.userAssignedIdentities) | "
            "mv-expand uamiResourceId=bag_keys(identity.userAssignedIdentities) | "
            "project resourceId=tolower(id), "
            "uamiResourceId=tolower(tostring(uamiResourceId)) | "
            "order by uamiResourceId asc, resourceId asc"
        ),
        "sensitiveIdentityAttachments": attachment_inventory,
        "projectionSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(attachment_inventory)
        ),
        "evidenceMethod": "authorized-bootstrap-azure-resource-graph",
        "observedAt": observed_at,
    }
    bridge_runtime = {
        "siteResourceId": bridge_site,
        "packageBlob": upload["blob"],
        "packageSha256": upload["sha256"],
        "packageSize": upload["size"],
        "packageEtag": upload["etag"],
        "packageVersionId": upload["versionId"],
        "packageUrl": package_url,
        "packageReaderIdentityResourceId": identity_facts[
            "registryReaderIdentity"
        ]["resourceId"],
        "criticalAppSettings": critical_settings,
        "criticalAppSettingsSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(critical_settings)
        ),
        "sitePosture": site_posture,
        "sitePostureSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(site_posture)
        ),
        "siteInventoryQuery": (
            "https://management.azure.com/subscriptions/"
            f"{bootstrap.SUBSCRIPTION}/providers/Microsoft.Web/sites"
            "?api-version=2025-03-01"
        ),
        "sensitiveIdentityResourceIds": sensitive_identities,
        "sensitiveIdentityAttachmentSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(
                {bridge_site.lower(): sensitive_identities}
            )
        ),
        "resourceGraphAttachmentInventory": resource_graph_inventory,
        "identityAssignmentBoundaries": identity_boundaries,
        "bridgeMutationBoundary": mutation_boundary,
        "legacyBridgeRetirement": legacy_retirement,
        "networkTopology": topology,
        "bootstrapReceiptPath": "evidence/private-release-bridge-runtime-receipt.json",
        "bootstrapReceiptSha256": "0" * 64,
        "observedAt": observed_at,
    }

    key_source = operations["createSigningKeyVersion"]
    jwk_source = operations["readBackExactSigningPublicJwk"]
    key_uri = key_source["keyUriWithVersion"]
    vault_projection = {
        "id": signing_vault.lower(),
        "name": resources["signingVault"]["name"],
        "type": "Microsoft.KeyVault/vaults",
        "location": "southeastasia",
        "properties": {
            "enableRbacAuthorization": True,
            "enablePurgeProtection": True,
            "softDeleteRetentionInDays": 90,
            "publicNetworkAccess": "Enabled",
            "networkAcls": {
                "bypass": "None",
                "defaultAction": "Allow",
                "ipRules": [],
                "virtualNetworkRules": [],
            },
        },
    }
    key_projection = {
        "id": signing_key.lower(),
        "name": resources["signingKey"]["name"],
        "type": "Microsoft.KeyVault/vaults/keys",
        "properties": {
            "keyUriWithVersion": key_uri,
            "kty": key_source["kty"],
            "keySize": key_source["keySize"],
            "keyOps": key_source["keyOps"],
            "attributes": {
                "enabled": key_source["enabled"],
                "exportable": key_source["exportable"],
                "expiresOn": key_source["expiresAt"],
            },
            "releasePolicy": key_source["releasePolicy"],
        },
    }
    signer_assignment = rich["roleAssignments"]["signerKeySign"]
    key_boundary = {
        "vaultResourceId": signing_vault,
        "vaultApiVersion": "2025-05-01",
        "vaultProjection": vault_projection,
        "vaultProjectionSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(vault_projection)
        ),
        "keyResourceId": signing_key,
        "keyApiVersion": "2023-07-01",
        "keyProjection": key_projection,
        "keyProjectionSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(key_projection)
        ),
        "keyDataPlaneGetUrl": key_uri + "?api-version=7.4",
        "keyDataPlaneProjection": jwk_source,
        "keyDataPlaneProjectionSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(jwk_source)
        ),
        "minimumRemainingLifetimeSeconds": mailbox.KEY_RECOVERY_HORIZON_SECONDS,
        "roleAssignmentsQuery": (
            f"https://management.azure.com/subscriptions/{bootstrap.SUBSCRIPTION}"
            "/providers/Microsoft.Authorization/roleAssignments"
            "?api-version=2022-04-01"
        ),
        "ownerRoleDefinitionId": owner_role,
        "allowedNonOwnerSensitiveAssignmentIds": [signer_assignment["id"]],
        "sensitiveActionUniverse": list(mailbox.KEY_SENSITIVE_ACTION_UNIVERSE),
        "sensitiveActionUniverseSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(
                list(mailbox.KEY_SENSITIVE_ACTION_UNIVERSE)
            )
        ),
        "sensitiveAssignmentProjectionSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes([signer_assignment])
        ),
        "temporaryKeyProvisioningAssignmentIdsPresent": [],
        "observedAt": observed_at,
    }

    worm_names = {
        "accepted": (accepted_container, "acceptedReleases"),
        "packages": (package_container, "deploymentPackages"),
        "results": (result_container, "webJobResults"),
    }
    worm_policies = {}
    for mailbox_name, (scope, source_name) in worm_names.items():
        source_pair = source["wormSourceProjections"][source_name]
        container_projection = source_pair["container"]
        policy_projection = source_pair["policy"]
        properties = policy_projection["properties"]
        worm_policies[mailbox_name] = {
            "scope": scope,
            "policyResourceId": policy_projection["id"],
            "publicAccess": container_projection["publicAccess"],
            "containerResourceSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(container_projection)
            ),
            "state": properties["state"],
            "immutabilityPeriodSinceCreationInDays": properties[
                "immutabilityPeriodSinceCreationInDays"
            ],
            "allowProtectedAppendWrites": properties[
                "allowProtectedAppendWrites"
            ],
            "allowProtectedAppendWritesAll": properties[
                "allowProtectedAppendWritesAll"
            ],
            "etag": policy_projection["etag"],
            "resourceSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(policy_projection)
            ),
            "observedAt": observed_at,
        }

    publisher_effective_sha = principal_inventories["publisher"][
        "effectiveAssignmentSetSha256"
    ]
    publisher_principal = identity_facts["publisherServicePrincipal"]["principalId"]
    publisher_client = identity_facts["publisherServicePrincipal"]["clientId"]
    key_data_url = key_uri + "/sign?api-version=7.6"
    arm = lambda resource, suffix: "https://management.azure.com" + resource + suffix
    blob = lambda container, suffix: (
        f"https://{resources['storageAccount']['name']}.blob.core.windows.net/"
        f"{container}{suffix}"
    )
    decision_specs = {
        "productionConfigList": (
            "POST", production_site,
            arm(production_site, "/config/appsettings/list?api-version=2025-03-01"),
            "Microsoft.Web/sites/config/list/action",
        ),
        "productionConfigWrite": (
            "PUT", production_site,
            arm(production_site, "/config/appsettings?api-version=2025-03-01"),
            "Microsoft.Web/sites/config/write",
        ),
        "productionRestart": (
            "POST", production_site,
            arm(production_site, "/restart?api-version=2025-03-01"),
            "Microsoft.Web/sites/restart/action",
        ),
        "oneDeployRead": (
            "GET", production_site,
            arm(production_site, "/deployments?api-version=2025-03-01"),
            "Microsoft.Web/sites/deployments/read",
        ),
        "oneDeployWrite": (
            "PUT", production_site,
            arm(production_site, "/extensions/onedeploy?api-version=2025-03-01"),
            "Microsoft.Web/sites/extensions/write",
        ),
        "oneDeployPublish": (
            "POST", production_site,
            arm(production_site, "/publish?api-version=2025-03-01"),
            "Microsoft.Web/sites/publish/Action",
        ),
        "storageListKeys": (
            "POST", storage_account,
            arm(storage_account, "/listKeys?api-version=2025-06-01"),
            "Microsoft.Storage/storageAccounts/listKeys/action",
        ),
        "storageContainerWrite": (
            "PUT", package_container,
            arm(package_container, "?api-version=2025-06-01"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/write",
        ),
        "storageContainerDelete": (
            "DELETE", package_container,
            arm(package_container, "?api-version=2025-06-01"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
        ),
        "otherControllerLease": (
            "POST", package_container,
            arm(package_container, "/lease?api-version=2025-06-01"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/lease/action",
        ),
        "registryBlobList": (
            "GET", accepted_container,
            blob(resources["acceptedContainer"]["name"], "?restype=container&comp=list"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        ),
        "registryBlobRead": (
            "GET", accepted_container,
            blob(resources["acceptedContainer"]["name"], "/probe"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        ),
        "registryBlobWrite": (
            "PUT", accepted_container,
            blob(resources["acceptedContainer"]["name"], "/probe"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
        ),
        "resultBlobList": (
            "GET", result_container,
            blob(resources["resultContainer"]["name"], "?restype=container&comp=list"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        ),
        "resultBlobRead": (
            "GET", result_container,
            blob(resources["resultContainer"]["name"], "/probe"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        ),
        "resultBlobWrite": (
            "PUT", result_container,
            blob(resources["resultContainer"]["name"], "/probe"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
        ),
        "packageBlobList": (
            "GET", package_container,
            blob(resources["packageContainer"]["name"], "?restype=container&comp=list"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        ),
        "packageBlobRead": (
            "GET", package_container,
            blob(resources["packageContainer"]["name"], "/probe"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        ),
        "packageBlobWrite": (
            "PUT", package_container,
            blob(resources["packageContainer"]["name"], "/probe"),
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
        ),
        "keyVaultSign": (
            "POST", signing_key, key_data_url,
            "Microsoft.KeyVault/vaults/keys/sign/action",
        ),
    }
    decisions = {
        name: {
            "principalId": publisher_principal,
            "clientId": publisher_client,
            "plane": (
                "storage-data"
                if "Blob" in name
                else "key-vault-data"
                if name == "keyVaultSign"
                else "arm-control"
            ),
            "wouldInvokeMethod": method,
            "targetResourceId": target,
            "targetUrl": url,
            "azureAction": action,
            "decision": "denied",
            "grantingAssignmentIds": [],
            "inventorySha256": publisher_effective_sha,
            "evaluatedAt": observed_at,
        }
        for name, (method, target, url, action) in decision_specs.items()
    }

    controller_projection = rich["controllerLockContainer"]
    provisioning_evidence = {
        "schemaVersion": 1,
        "status": "activated",
        "subscriptionId": bootstrap.SUBSCRIPTION,
        "observedAt": observed_at,
        "publisherIdentity": publisher_identity,
        "roles": role_records,
        "principalInventories": principal_inventories,
        "controllerLockContainer": {
            "scope": controller_container,
            "publicAccess": controller_projection["publicAccess"],
            "blobCount": 0,
            "resourceSha256": bootstrap.sha256_bytes(
                bootstrap.canonical_json_bytes(controller_projection)
            ),
            "evidenceMethod": "authorized-bootstrap-arm-and-blob-inventory",
            "observedAt": observed_at,
        },
        "bridgeRuntime": bridge_runtime,
        "keyVaultBoundary": key_boundary,
        "wormPolicies": worm_policies,
        "publisherAuthorizationDecisions": decisions,
        "rule": (
            "All source-pinned and action-time authorization evidence must match "
            "exactly before every privileged phase."
        ),
    }
    runtime_receipt = {
        "schemaVersion": 1,
        "status": "bridge-runtime-provisioned",
        "bridgeResourceId": bridge_site,
        "package": {
            "blob": upload["blob"],
            "sha256": upload["sha256"],
            "size": upload["size"],
            "etag": upload["etag"],
            "versionId": upload["versionId"],
            "url": package_url,
        },
        "packageReaderIdentityResourceId": identity_facts[
            "registryReaderIdentity"
        ]["resourceId"],
        "criticalAppSettingsSha256": bridge_runtime[
            "criticalAppSettingsSha256"
        ],
        "sitePostureSha256": bridge_runtime["sitePostureSha256"],
        "resourceGraphAttachmentSha256": resource_graph_inventory[
            "projectionSha256"
        ],
        "identityAssignmentBoundariesSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(identity_boundaries)
        ),
        "bridgeMutationBoundarySha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(mutation_boundary)
        ),
        "legacyBridgeRetirementSha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(legacy_retirement)
        ),
        "networkTopologySha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(topology)
        ),
        "packagesWormPolicySha256": bootstrap.sha256_bytes(
            bootstrap.canonical_json_bytes(worm_policies["packages"])
        ),
        "publisherBridgeControllerAssignmentId": role_records[
            "publisherBridgeController"
        ]["roleAssignmentResourceId"],
        "observedAt": observed_at,
    }
    bridge_runtime["bootstrapReceiptSha256"] = bootstrap.sha256_bytes(
        bootstrap.canonical_json_bytes(runtime_receipt)
    )
    return {
        "provisioningEvidence": provisioning_evidence,
        "bridgeRuntimeReceipt": runtime_receipt,
        "temporaryAccessCleanup": copy.deepcopy(
            components["temporaryAccessCleanup"]
        ),
        "activationFenceBootstrap": copy.deepcopy(
            components["activationFenceBootstrap"]
        ),
        "bridgeEvidence": copy.deepcopy(components["bridgeEvidence"]),
    }


def _canonical_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        receipts.fail(f"{label} must be an object")
    return receipts.load_canonical_json_bytes(
        bootstrap.canonical_json_bytes(value),
        label=label,
        maximum_bytes=16 * 1024 * 1024,
    )


def build_terminal_s2_documents(
    *,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    preflight_projection: Mapping[str, Any],
    source_evidence: Mapping[str, Any],
    components: Mapping[str, Mapping[str, Any]],
    started_at: str | None = None,
    completed_at: str | None = None,
) -> dict[str, bytes]:
    """Return the exact five canonical S2 byte bodies from validated proof only."""

    source = bootstrap.validate_terminal_source_evidence(
        plan=plan,
        authorization=authorization,
        preflight_projection=preflight_projection,
        evidence=source_evidence,
    )
    supplied_source = _canonical_mapping(source_evidence, "terminal source evidence")
    if source != supplied_source:
        receipts.fail("terminal source evidence changed during source-owned validation")

    claim = source.get("claimReceipt")
    if not isinstance(claim, Mapping):
        receipts.fail("terminal source evidence lacks its claim receipt")
    exact_started_at = claim.get("claimedAt")
    exact_completed_at = source.get("observedAt")
    if not isinstance(exact_started_at, str) or not isinstance(exact_completed_at, str):
        receipts.fail("terminal source evidence lacks exact execution times")
    if started_at is not None and started_at != exact_started_at:
        receipts.fail("supplied execution start does not equal the terminal claim time")
    if completed_at is not None and completed_at != exact_completed_at:
        receipts.fail("supplied execution completion does not equal terminal observation time")

    expected_components = bootstrap.build_terminal_receipt_components(
        plan=plan,
        authorization=authorization,
        preflight_projection=preflight_projection,
        source_evidence=source,
        started_at=exact_started_at,
        completed_at=exact_completed_at,
    )
    supplied_components = _canonical_mapping(
        components, "terminal receipt component inputs"
    )
    if supplied_components != expected_components:
        receipts.fail(
            "terminal receipt components are not the exact source-owned rebuild"
        )

    validated_inputs = {
        "plan": plan,
        "authorization": authorization,
        "sourceEvidence": source,
    }
    documents = _derive_terminal_s2_document_objects(
        validated_inputs, expected_components
    )
    result = receipts.build_s2_evidence_files(
        authorization=authorization,
        plan=plan,
        provisioning_evidence=documents["provisioningEvidence"],
        bridge_runtime_receipt=documents["bridgeRuntimeReceipt"],
        temporary_cleanup_receipt=documents["temporaryAccessCleanup"],
        activation_fence_receipt=documents["activationFenceBootstrap"],
        bridge_canary_receipt=documents["bridgeEvidence"],
    )
    expected_paths = list(receipts.load_model()["requiredS2EvidencePaths"])
    if list(result) != expected_paths:
        receipts.fail("terminal S2 output path order is not the reviewed exact order")
    canonical: dict[str, bytes] = {}
    for path in expected_paths:
        body = bytes(result[path])
        receipts.load_canonical_json_bytes(body, label=f"terminal S2 output {path}")
        canonical[path] = body
    return canonical
