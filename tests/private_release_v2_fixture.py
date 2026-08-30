"""Deterministic, internally consistent activated V2 trust fixture.

Production documents remain source-dormant. Tests use this builder so every
projection hash and receipt is recomputed from the same canonical bytes.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

from scripts import private_release_mailbox as box


STAMP = "2026-08-29T00:00:00.000Z"
WORKFLOW_SHA = "a" * 40
BOOTSTRAP_SOURCE_SHA = "b" * 40
PACKAGE_SHA = "b" * 64
KEY_VERSION = "c" * 32
JWK_N = "A" * 384
KEY_EXPIRES = 2_000_000_000


def gid(value: int) -> str:
    return f"{value:08x}-1111-4111-8111-{value:012x}"


def _ids():
    subscription = f"/subscriptions/{box.SUBSCRIPTION}"
    storage = (f"{subscription}/resourceGroups/rg-paperdesk-rollback-sea-20260808"
               f"/providers/Microsoft.Storage/storageAccounts/{box.FIXED_COORDS['packageAccount']}")
    containers = f"{storage}/blobServices/default/containers"
    bridge = (f"{subscription}/resourceGroups/{box.FIXED_COORDS['bridgeResourceGroup']}"
              f"/providers/Microsoft.Web/sites/{box.FIXED_COORDS['bridgeApp']}")
    production = (f"{subscription}/resourceGroups/{box.FIXED_COORDS['productionResourceGroup']}"
                  f"/providers/Microsoft.Web/sites/{box.FIXED_COORDS['productionApp']}")
    vault = (f"{subscription}/resourceGroups/{box.FIXED_COORDS['bridgeResourceGroup']}"
             f"/providers/Microsoft.KeyVault/vaults/{box.FIXED_COORDS['signingVault']}")
    return {
        "subscription": subscription, "storage": storage, "bridge": bridge,
        "masterRg": f"{subscription}/resourceGroups/{box.FIXED_COORDS['bridgeResourceGroup']}",
        "vnet": f"{subscription}/resourceGroups/{box.FIXED_COORDS['bridgeResourceGroup']}/providers/Microsoft.Network/virtualNetworks/vnet-master-data-structure-sea",
        "production": production, "mailbox": f"{subscription}/resourceGroups/mailbox-rg",
        "vault": vault, "key": f"{vault}/keys/{box.FIXED_COORDS['signingKeyName']}",
        "registry": f"{containers}/{box.FIXED_COORDS['registryContainer']}",
        "results": f"{containers}/{box.FIXED_COORDS['resultContainer']}",
        "packages": f"{containers}/{box.FIXED_COORDS['packageContainer']}",
        "lock": f"{containers}/{box.FIXED_COORDS['controllerLockContainer']}",
        "fence": f"{containers}/{box.FIXED_COORDS['activationFenceContainer']}",
        "attachments": f"{containers}/paperdesk-attachments",
    }


def assignment_projection(role):
    resource_id = role["roleAssignmentResourceId"].lower()
    return {"id": resource_id, "name": resource_id.rsplit("/", 1)[1],
            "type": "Microsoft.Authorization/roleAssignments", "properties": {
                "principalId": role["principalId"].lower(), "principalType": "ServicePrincipal",
                "roleDefinitionId": role["roleDefinitionResourceId"].lower(),
                "scope": role["scope"].lower(), "condition": None, "conditionVersion": None,
                "delegatedManagedIdentityResourceId": None}}


def activated_bundle():
    doc = json.loads(Path("contracts/private_release_mailbox_contract.json").read_text(encoding="utf-8"))
    doc["status"] = "activated"
    doc["fixed"] = copy.deepcopy(box.FIXED_COORDS)
    activation = doc["activation"]
    rid = _ids()
    clients = {"publisher": gid(1), "bridge": gid(2), "writer": gid(3), "reader": gid(4),
               "signer": gid(5), "productionActivation": gid(6),
               "productionSystem": box.PRODUCTION_SYSTEM_CLIENT_ID}
    principals = {"publisher": gid(11), "bridge": gid(12), "writer": gid(13), "reader": gid(14),
                  "signer": gid(15), "productionActivation": gid(16),
                  "productionSystem": box.PRODUCTION_SYSTEM_PRINCIPAL_ID}
    uami = {name: (f"{rid['subscription']}/resourceGroups/{box.FIXED_COORDS['bridgeResourceGroup']}"
                   f"/providers/Microsoft.ManagedIdentity/userAssignedIdentities/test-{name.lower()}")
            for name in ("bridge", "writer", "reader", "signer", "productionActivation")}
    key_id = f"https://{box.FIXED_COORDS['signingVault']}.vault.azure.net/keys/{box.FIXED_COORDS['signingKeyName']}"
    activation.update({
        "mergedControlWorkflowSha": WORKFLOW_SHA, "mailboxResourceGroup": "mailbox-rg",
        "mailboxPublisherClientId": clients["publisher"], "mailboxPublisherPrincipalId": principals["publisher"],
        "mailboxRoleDefinitionId": gid(101), "mailboxRoleAssignmentId": gid(201),
        "controllerLockRoleDefinitionId": gid(102), "controllerLockRoleAssignmentId": gid(202),
        "controllerLockRoleAssignmentScope": rid["lock"],
        "controllerLockRoleDefinitionActions": ["Microsoft.Storage/storageAccounts/blobServices/containers/read", "Microsoft.Storage/storageAccounts/blobServices/containers/lease/action"],
        "controllerLockForbiddenDataActions": [], "tenantId": box.TENANT,
        "bridgeManagedIdentityClientId": clients["bridge"], "bridgeManagedIdentityPrincipalId": principals["bridge"], "bridgeManagedIdentityResourceId": uami["bridge"],
        "registryWriterManagedIdentityClientId": clients["writer"], "registryWriterManagedIdentityPrincipalId": principals["writer"], "registryWriterManagedIdentityResourceId": uami["writer"],
        "registryReaderManagedIdentityClientId": clients["reader"], "registryReaderManagedIdentityPrincipalId": principals["reader"], "registryReaderManagedIdentityResourceId": uami["reader"],
        "signerManagedIdentityClientId": clients["signer"], "signerManagedIdentityPrincipalId": principals["signer"], "signerManagedIdentityResourceId": uami["signer"],
        "signerRoleDefinitionId": gid(103), "signerRoleAssignmentId": gid(203), "signerRoleAssignmentScope": rid["key"],
        "signerRoleDefinitionDataActions": ["Microsoft.KeyVault/vaults/keys/sign/action"], "signerForbiddenRoleAssignments": [],
        "signingKeyId": key_id, "signingKeyVersion": KEY_VERSION,
        "signingPublicJwk": {"kid": f"{key_id}/{KEY_VERSION}", "kty": "RSA", "n": JWK_N, "e": "AQAB", "key_ops": ["sign", "verify"]},
        "bridgePackageSourceSha": BOOTSTRAP_SOURCE_SHA, "bridgePackageSha256": PACKAGE_SHA,
        "productionActivationManagedIdentityClientId": clients["productionActivation"], "productionActivationManagedIdentityPrincipalId": principals["productionActivation"], "productionActivationManagedIdentityResourceId": uami["productionActivation"],
        "productionActivationRoleDefinitionId": gid(104), "productionActivationRoleAssignmentId": gid(204), "productionActivationRoleAssignmentScope": rid["production"],
        "productionActivationRoleDefinitionActions": ["Microsoft.Web/sites/config/list/action", "Microsoft.Web/sites/config/write", "Microsoft.Web/sites/deployments/read", "Microsoft.Web/sites/restart/action"],
        "productionActivationForbiddenRoleAssignments": [], "productionPackageReaderRoleAssignmentId": gid(205), "productionPackageReaderRoleScope": rid["packages"], "productionForbiddenDataPlaneAssignments": [],
        "productionSystemIdentityClientId": clients["productionSystem"], "productionSystemIdentityPrincipalId": principals["productionSystem"],
        "packageWriterRoleAssignmentId": gid(206), "packageReaderRoleAssignmentId": gid(207),
        "activationFence": {"storageAccount": box.FIXED_COORDS["packageAccount"], "container": box.FIXED_COORDS["activationFenceContainer"], "blob": box.FIXED_COORDS["activationFenceBlob"], "scope": rid["fence"], "bridgeRoleAssignmentId": gid(208), "bridgePrincipalId": principals["bridge"], "leaseDuration": 60, "publicAccess": "None", "bootstrapReceiptSha256": "d" * 64, "governanceBoundary": "subscription-and-resource-group-owners-remain-out-of-band-and-third-state-is-never-overwritten"},
    })

    bridge_actions = ["Microsoft.Web/sites/Read", "Microsoft.Web/sites/start/Action", "Microsoft.Web/sites/stop/Action", "Microsoft.Web/sites/config/list/Action", "Microsoft.Web/sites/config/Read", "Microsoft.Web/sites/config/Write", "Microsoft.Web/sites/basicPublishingCredentialsPolicies/Read", "Microsoft.Web/sites/sourcecontrols/read", "Microsoft.Web/sites/triggeredwebjobs/read", "Microsoft.Web/sites/triggeredwebjobs/history/read", "Microsoft.Web/sites/triggeredwebjobs/run/action"]
    custody = ["Microsoft.Storage/storageAccounts/blobServices/containers/read", "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/read"]
    specs = {
        "publisherMailbox": (gid(101), gid(201), "publisher", None, rid["mailbox"], ["Microsoft.Resources/deployments/read", "Microsoft.Resources/deployments/write", "Microsoft.Resources/deployments/delete"], []),
        "publisherBridgeController": (gid(105), gid(209), "publisher", None, rid["bridge"], bridge_actions, []),
        "publisherControllerLock": (gid(102), gid(202), "publisher", None, rid["lock"], activation["controllerLockRoleDefinitionActions"], []),
        "publisherAcceptedCustodyAudit": (gid(106), gid(210), "publisher", None, rid["registry"], custody, []),
        "publisherPackageCustodyAudit": (gid(116), gid(211), "publisher", None, rid["packages"], custody, []),
        "publisherResultCustodyAudit": (gid(117), gid(212), "publisher", None, rid["results"], custody, []),
        "publisherAudit": (gid(107), gid(213), "publisher", None, rid["subscription"], ["Microsoft.Authorization/roleAssignments/read", "Microsoft.Authorization/roleDefinitions/read"], []),
        "publisherWebIdentityAudit": (gid(113), gid(217), "publisher", None, rid["masterRg"], ["Microsoft.Web/sites/read"], []),
        "publisherKeyPostureAudit": (gid(114), gid(218), "publisher", None, rid["vault"], ["Microsoft.KeyVault/vaults/read", "Microsoft.KeyVault/vaults/keys/read"], []),
        "publisherUamiMetadataAudit": (gid(120), gid(222), "publisher", None, rid["masterRg"], ["Microsoft.ManagedIdentity/userAssignedIdentities/read"], []),
        "publisherNetworkMetadataAudit": (gid(121), gid(223), "publisher", None, rid["vnet"], ["Microsoft.Network/virtualNetworks/read", "Microsoft.Network/virtualNetworks/subnets/read"], []),
        "publisherStorageMetadataAudit": (gid(122), gid(224), "publisher", None, rid["storage"], ["Microsoft.Storage/storageAccounts/read"], []),
        "publisherProductionWebMetadataAudit": (gid(123), gid(225), "publisher", None, rid["production"], ["Microsoft.Web/sites/config/read"], []),
        "bridgeMailboxResult": (gid(108), gid(214), "bridge", uami["bridge"], rid["mailbox"], ["Microsoft.Resources/deployments/read", "Microsoft.Resources/deployments/write"], []),
        "bridgeActivationFence": (gid(109), gid(208), "bridge", uami["bridge"], rid["fence"], [], ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"]),
        "bridgeKeyRead": (gid(115), gid(219), "bridge", uami["bridge"], rid["key"], [], ["Microsoft.KeyVault/vaults/keys/read"]),
        "writerRegistryAdd": (gid(110), gid(220), "writer", uami["writer"], rid["registry"], [], ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action"]),
        "writerPackageAdd": (gid(118), gid(206), "writer", uami["writer"], rid["packages"], [], ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action"]),
        "readerRegistryRead": (gid(111), gid(221), "reader", uami["reader"], rid["registry"], [], ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"]),
        "readerPackageRead": (gid(119), gid(207), "reader", uami["reader"], rid["packages"], [], ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"]),
        "signerKeySign": (gid(103), gid(203), "signer", uami["signer"], rid["key"], [], ["Microsoft.KeyVault/vaults/keys/sign/action"]),
        "productionActivation": (gid(104), gid(204), "productionActivation", uami["productionActivation"], rid["production"], activation["productionActivationRoleDefinitionActions"], []),
        "productionSystemPackageRead": (gid(112), gid(205), "productionSystem", rid["production"], rid["packages"], [], ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"]),
        "productionSystemAttachmentContributor": ("ba92f5b4-2d11-453d-a403-e96b0029c9fe", "997c7c3c-ac72-4d56-8cc4-fdcfa5d7cee4", "productionSystem", rid["production"], rid["attachments"], [], ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"]),
        "productionSystemSecretsUser": ("4633458b-17de-408a-b874-0445c86b69e6", "c298e462-25d4-4f0f-812c-c7a3bbc68ef8", "productionSystem", rid["production"], rid["vault"], [], ["Microsoft.KeyVault/vaults/secrets/getSecret/action"]),
    }
    roles = {}
    for name, (definition_guid, assignment_guid, identity, identity_resource, scope, actions, data_actions) in specs.items():
        definition = f"{rid['subscription']}/providers/Microsoft.Authorization/roleDefinitions/{definition_guid}"
        assignment = f"{scope}/providers/Microsoft.Authorization/roleAssignments/{assignment_guid}"
        assignable = ["/"] if name in {"productionSystemAttachmentContributor", "productionSystemSecretsUser"} else [rid["subscription"]]
        definition_projection = {"id": definition.lower(), "name": definition_guid.lower(), "type": "Microsoft.Authorization/roleDefinitions", "properties": {"roleName": "fixture-" + name, "type": "BuiltInRole" if assignable == ["/"] else "CustomRole", "assignableScopes": assignable, "permissions": [{"actions": actions, "notActions": [], "dataActions": data_actions, "notDataActions": []}]}}
        role = {"roleDefinitionResourceId": definition, "roleDefinitionSha256": box.digest(box.canonical(definition_projection)), "roleAssignmentResourceId": assignment, "roleAssignmentSha256": "0" * 64, "principalId": principals[identity], "principalType": "ServicePrincipal", "tenantId": box.TENANT, "identityClientId": clients[identity], "identityResourceId": identity_resource, "scope": scope, "condition": None, "conditionVersion": None, "delegatedManagedIdentityResourceId": None, "assignableScopes": assignable, "actions": actions, "notActions": [], "dataActions": data_actions, "notDataActions": []}
        role["roleAssignmentSha256"] = box.digest(box.canonical(assignment_projection(role)))
        roles[name] = role

    inventories = {}
    inventory_names = {"publisher": "publisher", "bridge": "bridge", "writer": "registryWriter", "reader": "registryReader", "signer": "signer", "productionActivation": "productionActivation", "productionSystem": "productionSystem"}
    for identity, principal in principals.items():
        projections = sorted((assignment_projection(role) for role in roles.values() if role["principalId"] == principal), key=lambda item: item["id"])
        assignment_ids = [item["id"] for item in projections]
        inventories[inventory_names[identity]] = {"principalId": principal, "directQuery": f"https://management.azure.com/subscriptions/{box.SUBSCRIPTION}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=principalId%20eq%20%27{principal}%27", "effectiveQuery": f"https://management.azure.com/subscriptions/{box.SUBSCRIPTION}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=assignedTo%28%27{principal}%27%29", "directAssignmentResourceIds": assignment_ids, "effectiveAssignmentResourceIds": assignment_ids, "directAssignmentSetSha256": box.digest(box.canonical(projections)), "effectiveAssignmentSetSha256": box.digest(box.canonical(projections)), "observedAt": STAMP}

    worm = {}
    for name, scope in (("accepted", rid["registry"]), ("packages", rid["packages"]), ("results", rid["results"])):
        container_projection = {"id": scope.lower(), "name": "default/" + scope.rsplit("/", 1)[1], "type": "Microsoft.Storage/storageAccounts/blobServices/containers", "publicAccess": "None"}
        policy_id = scope + "/immutabilityPolicies/default"
        policy_projection = {"id": policy_id.lower(), "name": "default", "type": "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies", "etag": f'"policy-{name}"', "properties": {"state": "Locked", "immutabilityPeriodSinceCreationInDays": 91, "allowProtectedAppendWrites": False, "allowProtectedAppendWritesAll": False}}
        worm[name] = {"scope": scope, "policyResourceId": policy_id, "publicAccess": "None", "containerResourceSha256": box.digest(box.canonical(container_projection)), "state": "Locked", "immutabilityPeriodSinceCreationInDays": 91, "allowProtectedAppendWrites": False, "allowProtectedAppendWritesAll": False, "etag": f'"policy-{name}"', "resourceSha256": box.digest(box.canonical(policy_projection)), "observedAt": STAMP}

    package_blob = f"v2/control/{BOOTSTRAP_SOURCE_SHA}/paperdesk-private-release-bridge.zip"
    package_version = "2026-08-29T00:00:00.0000000Z"
    package_url = f"https://{box.FIXED_COORDS['packageAccount']}.blob.core.windows.net/{box.FIXED_COORDS['packageContainer']}/{package_blob}?versionid={package_version}"
    critical = {"WEBSITE_RUN_FROM_PACKAGE": package_url, "WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID": uami["reader"], "WEBSITE_SKIP_RUNNING_KUDUAGENT": "false", "PAPERDESK_BRIDGE_PACKAGE_SHA256": PACKAGE_SHA}
    subnet = f"{rid['subscription']}/resourceGroups/{box.FIXED_COORDS['bridgeResourceGroup']}/providers/Microsoft.Network/virtualNetworks/vnet-master-data-structure-sea/subnets/snet-appservice-integration".lower()
    vnet = subnet.rsplit("/subnets/", 1)[0]
    bridge_routing = {"allTraffic": True, "applicationTraffic": True}
    production_routing = {"allTraffic": False, "applicationTraffic": True}
    posture = {"siteResourceId": rid["bridge"], "name": box.FIXED_COORDS["bridgeApp"], "type": "Microsoft.Web/sites", "kind": "app,linux", "serverFarmId": f"{rid['subscription']}/resourceGroups/{box.FIXED_COORDS['bridgeResourceGroup']}/providers/Microsoft.Web/serverfarms/asp-master-data-structure-b1-sea", "httpsOnly": True, "publicNetworkAccess": "Disabled", "virtualNetworkSubnetId": subnet, "outboundVnetRouting": bridge_routing, "webConfig": {"alwaysOn": True, "linuxFxVersion": "PYTHON|3.12", "ftpsState": "Disabled", "minTlsVersion": "1.2", "scmMinTlsVersion": "1.2", "scmType": "None", "http20Enabled": True, "vnetRouteAllEnabled": True}, "ftpBasicAuthAllowed": False, "scmBasicAuthAllowed": False, "sourceControl": {"status": 404}}
    sensitive = sorted(value.lower() for value in uami.values())
    graph_attachments = {identity: [rid["bridge"].lower()] for identity in sensitive}
    owner_role = f"{rid['subscription']}/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
    identity_boundaries = {"ownerRoleDefinitionId": owner_role, "items": {identity: {"resourceId": identity, "roleAssignmentsQuery": f"https://management.azure.com{identity}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", "allowedNonOwnerAssignerAssignmentIds": [], "assignerProjectionSha256": box.digest(box.canonical([]))} for identity in sensitive}, "observedAt": STAMP}
    allowed_bridge = assignment_projection(roles["publisherBridgeController"])
    mutation = {"bridgeScopeQuery": f"https://management.azure.com{rid['bridge']}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", "allowedNonOwnerAssignmentIds": [allowed_bridge["id"]], "ownerRoleDefinitionId": owner_role, "sensitiveActionUniverse": list(box.BRIDGE_SENSITIVE_ACTION_UNIVERSE), "sensitiveActionUniverseSha256": box.digest(box.canonical(list(box.BRIDGE_SENSITIVE_ACTION_UNIVERSE))), "mutatorAssignmentSha256": box.digest(box.canonical([allowed_bridge])), "observedAt": STAMP}
    legacy_site = f"{rid['subscription']}/resourceGroups/{box.FIXED_COORDS['bridgeResourceGroup']}/providers/Microsoft.Web/sites/paperdesk-release-registry-bridge-9c4e0d0d"
    legacy_projection = {"siteResourceId": legacy_site, "state": "Stopped", "publicNetworkAccess": "Disabled", "userAssignedIdentityResourceIds": [], "transientAppSettingNamesPresent": [], "publisherMutatorAssignmentIds": []}
    legacy = {**legacy_projection, "roleAssignmentsQuery": f"https://management.azure.com{legacy_site}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", "projectionSha256": box.digest(box.canonical(legacy_projection)), "observedAt": STAMP}
    vnet_projection = {"id": vnet, "type": "Microsoft.Network/virtualNetworks", "addressSpacePrefixes": ["10.41.0.0/16"]}
    subnet_projection = {"id": subnet, "type": "Microsoft.Network/virtualNetworks/subnets", "virtualNetworkResourceId": vnet.lower(), "delegations": ["Microsoft.Web/serverFarms"], "serviceEndpoints": [{"service": "Microsoft.Storage", "provisioningState": "Succeeded"}], "routeTableResourceId": None, "networkSecurityGroupResourceId": None}
    storage_projection = {"id": rid["storage"].lower(), "type": "Microsoft.Storage/storageAccounts", "publicNetworkAccess": "Enabled", "allowBlobPublicAccess": False, "defaultAction": "Deny", "bypass": "None", "ipRules": [], "resourceAccessRules": [], "virtualNetworkRules": [{"id": subnet, "action": "Allow", "state": "Succeeded"}]}
    production_projection = {"id": rid["production"].lower(), "type": "Microsoft.Web/sites", "virtualNetworkSubnetId": subnet, "outboundVnetRouting": production_routing, "legacyVnetRouteAllEnabled": True}
    topology = {"mode": "service-endpoint-firewall-v1",
                "virtualNetwork": {"resourceId": vnet, "apiVersion": "2025-01-01", "projectionSha256": box.digest(box.canonical(vnet_projection)), "addressSpacePrefixes": vnet_projection["addressSpacePrefixes"]},
                "integrationSubnet": {"resourceId": subnet, "apiVersion": "2025-01-01", "projectionSha256": box.digest(box.canonical(subnet_projection)), **{key: subnet_projection[key] for key in ("virtualNetworkResourceId", "delegations", "serviceEndpoints", "routeTableResourceId", "networkSecurityGroupResourceId")}},
                "packageStorageAccount": {"resourceId": rid["storage"], "apiVersion": "2025-06-01", "projectionSha256": box.digest(box.canonical(storage_projection)), **{key: storage_projection[key] for key in ("publicNetworkAccess", "allowBlobPublicAccess", "defaultAction", "bypass", "ipRules", "resourceAccessRules", "virtualNetworkRules")}},
                "productionSite": {"resourceId": rid["production"], "apiVersion": "2025-03-01", "projectionSha256": box.digest(box.canonical(production_projection)), "virtualNetworkSubnetId": subnet, "outboundVnetRouting": production_routing, "legacyVnetRouteAllEnabled": True}}
    graph_inventory = {"query": "Resources | where isnotnull(identity.userAssignedIdentities) | mv-expand uamiResourceId=bag_keys(identity.userAssignedIdentities) | project resourceId=tolower(id), uamiResourceId=tolower(tostring(uamiResourceId)) | order by uamiResourceId asc, resourceId asc", "sensitiveIdentityAttachments": graph_attachments, "projectionSha256": box.digest(box.canonical(graph_attachments)), "evidenceMethod": "authorized-bootstrap-azure-resource-graph", "observedAt": STAMP}
    bridge_runtime = {"siteResourceId": rid["bridge"], "packageBlob": package_blob, "packageSha256": PACKAGE_SHA, "packageSize": 4096, "packageEtag": '"package"', "packageVersionId": package_version, "packageUrl": package_url, "packageReaderIdentityResourceId": uami["reader"], "criticalAppSettings": critical, "criticalAppSettingsSha256": box.digest(box.canonical(critical)), "sitePosture": posture, "sitePostureSha256": box.digest(box.canonical(posture)), "siteInventoryQuery": f"https://management.azure.com/subscriptions/{box.SUBSCRIPTION}/providers/Microsoft.Web/sites?api-version=2025-03-01", "sensitiveIdentityResourceIds": sensitive, "sensitiveIdentityAttachmentSha256": box.digest(box.canonical({rid['bridge'].lower(): sensitive})), "resourceGraphAttachmentInventory": graph_inventory, "identityAssignmentBoundaries": identity_boundaries, "bridgeMutationBoundary": mutation, "legacyBridgeRetirement": legacy, "networkTopology": topology, "bootstrapReceiptPath": "evidence/private-release-bridge-runtime-receipt.json", "bootstrapReceiptSha256": "0" * 64, "observedAt": STAMP}

    vault_projection = {"id": rid["vault"].lower(), "name": box.FIXED_COORDS["signingVault"], "type": "Microsoft.KeyVault/vaults", "location": "southeastasia", "properties": {"enableRbacAuthorization": True, "enablePurgeProtection": True, "softDeleteRetentionInDays": 90, "publicNetworkAccess": "Enabled", "networkAcls": {"bypass": "None", "defaultAction": "Allow", "ipRules": [], "virtualNetworkRules": []}}}
    key_uri = f"{key_id}/{KEY_VERSION}"
    key_projection = {"id": rid["key"].lower(), "name": box.FIXED_COORDS["signingKeyName"], "type": "Microsoft.KeyVault/vaults/keys", "properties": {"keyUriWithVersion": key_uri, "kty": "RSA", "keySize": 3072, "keyOps": ["sign", "verify"], "attributes": {"enabled": True, "exportable": False, "expiresOn": KEY_EXPIRES}, "releasePolicy": None}}
    key_data = {"kid": key_uri, "kty": "RSA", "key_ops": ["sign", "verify"], "n": JWK_N, "e": "AQAB", "attributes": {"enabled": True, "nbf": 1_700_000_000, "exp": KEY_EXPIRES, "created": 1_700_000_000, "updated": 1_700_000_001, "recoveryLevel": "Recoverable+Purgeable", "recoverableDays": 90, "exportable": False}}
    signer_projection = assignment_projection(roles["signerKeySign"])
    key_boundary = {"vaultResourceId": rid["vault"], "vaultApiVersion": "2025-05-01", "vaultProjection": vault_projection, "vaultProjectionSha256": box.digest(box.canonical(vault_projection)), "keyResourceId": rid["key"], "keyApiVersion": "2023-07-01", "keyProjection": key_projection, "keyProjectionSha256": box.digest(box.canonical(key_projection)), "keyDataPlaneGetUrl": key_uri + "?api-version=7.4", "keyDataPlaneProjection": key_data, "keyDataPlaneProjectionSha256": box.digest(box.canonical(key_data)), "minimumRemainingLifetimeSeconds": box.KEY_RECOVERY_HORIZON_SECONDS, "roleAssignmentsQuery": f"https://management.azure.com/subscriptions/{box.SUBSCRIPTION}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", "ownerRoleDefinitionId": owner_role, "allowedNonOwnerSensitiveAssignmentIds": [signer_projection["id"]], "sensitiveActionUniverse": list(box.KEY_SENSITIVE_ACTION_UNIVERSE), "sensitiveActionUniverseSha256": box.digest(box.canonical(list(box.KEY_SENSITIVE_ACTION_UNIVERSE))), "sensitiveAssignmentProjectionSha256": box.digest(box.canonical([signer_projection])), "temporaryKeyProvisioningAssignmentIdsPresent": [], "observedAt": STAMP}

    app_object, graph_sp = gid(301), gid(302)
    fic = {"id": gid(303), "name": "paperdesk-production-control-v2", "issuer": "https://token.actions.githubusercontent.com", "audiences": ["api://AzureADTokenExchange"], "subject": None, "claimsMatchingExpressionTemplate": {"languageVersion": 1, "value": f"claims['sub'] eq '{box.OIDC_SUBJECT}' and claims['repository_id'] eq '{box.OWNER_REPOSITORY_ID}' and claims['repository_owner_id'] eq '{box.OWNER_ID}' and claims['job_workflow_ref'] eq '{{controlWorkflowRef}}'"}}
    graph_assignment = {"id": gid(304), "principalId": principals["publisher"], "resourceId": graph_sp, "appRoleId": box.GRAPH_APPLICATION_READ_ALL_ROLE_ID}
    application_projection = {"id": app_object, "appId": clients["publisher"], "signInAudience": "AzureADMyOrg", "passwordCredentialKeyIds": [], "keyCredentialKeyIds": []}
    service_projection = {"id": principals["publisher"], "appId": clients["publisher"], "accountEnabled": True, "servicePrincipalType": "Application", "passwordCredentialKeyIds": [], "keyCredentialKeyIds": []}
    publisher_identity = {"applicationObjectId": app_object, "applicationQuery": f"https://graph.microsoft.com/beta/applications/{app_object}?$select=id,appId,signInAudience,passwordCredentials,keyCredentials", "applicationProjectionSha256": box.digest(box.canonical(application_projection)), "servicePrincipalQuery": f"https://graph.microsoft.com/v1.0/servicePrincipals/{principals['publisher']}?$select=id,appId,accountEnabled,servicePrincipalType,passwordCredentials,keyCredentials", "servicePrincipalProjectionSha256": box.digest(box.canonical(service_projection)), "federatedIdentityCredentialsQuery": f"https://graph.microsoft.com/beta/applications/{app_object}/federatedIdentityCredentials", "federatedIdentityCredentialPolicy": fic, "federatedIdentityCredentialPolicySha256": box.digest(box.canonical(fic)), "appRoleAssignmentsQuery": f"https://graph.microsoft.com/v1.0/servicePrincipals/{principals['publisher']}/appRoleAssignments", "graphServicePrincipalObjectId": graph_sp, "graphApplicationReadAllAppRoleAssignment": graph_assignment, "graphApplicationReadAllAppRoleAssignmentSha256": box.digest(box.canonical(graph_assignment)), "observedAt": STAMP}

    publisher_inventory = inventories["publisher"]["effectiveAssignmentSetSha256"]
    arm = lambda resource, suffix: "https://management.azure.com" + resource + suffix
    blob = lambda container, suffix: f"https://{box.FIXED_COORDS['packageAccount']}.blob.core.windows.net/{container}{suffix}"
    decisions_raw = {
        "productionConfigList": ("POST", rid["production"], arm(rid["production"], "/config/appsettings/list?api-version=2025-03-01"), "Microsoft.Web/sites/config/list/action"),
        "productionConfigWrite": ("PUT", rid["production"], arm(rid["production"], "/config/appsettings?api-version=2025-03-01"), "Microsoft.Web/sites/config/write"),
        "productionRestart": ("POST", rid["production"], arm(rid["production"], "/restart?api-version=2025-03-01"), "Microsoft.Web/sites/restart/action"),
        "oneDeployRead": ("GET", rid["production"], arm(rid["production"], "/deployments?api-version=2025-03-01"), "Microsoft.Web/sites/deployments/read"),
        "oneDeployWrite": ("PUT", rid["production"], arm(rid["production"], "/extensions/onedeploy?api-version=2025-03-01"), "Microsoft.Web/sites/extensions/write"),
        "oneDeployPublish": ("POST", rid["production"], arm(rid["production"], "/publish?api-version=2025-03-01"), "Microsoft.Web/sites/publish/Action"),
        "storageListKeys": ("POST", rid["storage"], arm(rid["storage"], "/listKeys?api-version=2025-06-01"), "Microsoft.Storage/storageAccounts/listKeys/action"),
        "storageContainerWrite": ("PUT", rid["packages"], arm(rid["packages"], "?api-version=2025-06-01"), "Microsoft.Storage/storageAccounts/blobServices/containers/write"),
        "storageContainerDelete": ("DELETE", rid["packages"], arm(rid["packages"], "?api-version=2025-06-01"), "Microsoft.Storage/storageAccounts/blobServices/containers/delete"),
        "otherControllerLease": ("POST", rid["packages"], arm(rid["packages"], "/lease?api-version=2025-06-01"), "Microsoft.Storage/storageAccounts/blobServices/containers/lease/action"),
        "registryBlobList": ("GET", rid["registry"], blob(box.FIXED_COORDS["registryContainer"], "?restype=container&comp=list"), "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"),
        "registryBlobRead": ("GET", rid["registry"], blob(box.FIXED_COORDS["registryContainer"], "/probe"), "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"),
        "registryBlobWrite": ("PUT", rid["registry"], blob(box.FIXED_COORDS["registryContainer"], "/probe"), "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"),
        "resultBlobList": ("GET", rid["results"], blob(box.FIXED_COORDS["resultContainer"], "?restype=container&comp=list"), "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"),
        "resultBlobRead": ("GET", rid["results"], blob(box.FIXED_COORDS["resultContainer"], "/probe"), "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"),
        "resultBlobWrite": ("PUT", rid["results"], blob(box.FIXED_COORDS["resultContainer"], "/probe"), "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"),
        "packageBlobList": ("GET", rid["packages"], blob(box.FIXED_COORDS["packageContainer"], "?restype=container&comp=list"), "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"),
        "packageBlobRead": ("GET", rid["packages"], blob(box.FIXED_COORDS["packageContainer"], "/probe"), "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"),
        "packageBlobWrite": ("PUT", rid["packages"], blob(box.FIXED_COORDS["packageContainer"], "/probe"), "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"),
        "keyVaultSign": ("POST", rid["key"], key_uri + "/sign?api-version=7.6", "Microsoft.KeyVault/vaults/keys/sign/action"),
    }
    decisions = {name: {"principalId": principals["publisher"], "clientId": clients["publisher"], "plane": "storage-data" if "Blob" in name else "key-vault-data" if name == "keyVaultSign" else "arm-control", "wouldInvokeMethod": method, "targetResourceId": target, "targetUrl": url, "azureAction": action, "decision": "denied", "grantingAssignmentIds": [], "inventorySha256": publisher_inventory, "evaluatedAt": STAMP} for name, (method, target, url, action) in decisions_raw.items()}
    lock_projection = {"id": rid["lock"].lower(), "name": "default/" + box.FIXED_COORDS["controllerLockContainer"], "type": "Microsoft.Storage/storageAccounts/blobServices/containers", "publicAccess": "None"}
    evidence = {"schemaVersion": 1, "status": "activated", "subscriptionId": box.SUBSCRIPTION, "observedAt": STAMP, "publisherIdentity": publisher_identity, "roles": roles, "principalInventories": inventories, "controllerLockContainer": {"scope": rid["lock"], "publicAccess": "None", "blobCount": 0, "resourceSha256": box.digest(box.canonical(lock_projection)), "evidenceMethod": "authorized-bootstrap-arm-and-blob-inventory", "observedAt": STAMP}, "bridgeRuntime": bridge_runtime, "keyVaultBoundary": key_boundary, "wormPolicies": worm, "publisherAuthorizationDecisions": decisions, "rule": "All source-pinned and action-time authorization evidence must match exactly before every privileged phase."}
    receipt = {"schemaVersion": 1, "status": "bridge-runtime-provisioned", "bridgeResourceId": rid["bridge"], "package": {"blob": package_blob, "sha256": PACKAGE_SHA, "size": 4096, "etag": '"package"', "versionId": package_version, "url": package_url}, "packageReaderIdentityResourceId": uami["reader"], "criticalAppSettingsSha256": bridge_runtime["criticalAppSettingsSha256"], "sitePostureSha256": bridge_runtime["sitePostureSha256"], "resourceGraphAttachmentSha256": graph_inventory["projectionSha256"], "identityAssignmentBoundariesSha256": box.digest(box.canonical(identity_boundaries)), "bridgeMutationBoundarySha256": box.digest(box.canonical(mutation)), "legacyBridgeRetirementSha256": box.digest(box.canonical(legacy)), "networkTopologySha256": box.digest(box.canonical(topology)), "packagesWormPolicySha256": box.digest(box.canonical(worm["packages"])), "publisherBridgeControllerAssignmentId": roles["publisherBridgeController"]["roleAssignmentResourceId"], "observedAt": STAMP}
    bridge_runtime["bootstrapReceiptSha256"] = box.digest(box.canonical(receipt))
    activation["provisioningEvidenceSha256"] = box.digest(box.canonical(evidence))
    return doc, evidence, receipt


def activated_pair():
    doc, evidence, _ = activated_bundle()
    return doc, evidence


def runtime_receipt():
    return activated_bundle()[2]


def activation():
    doc, evidence, receipt = activated_bundle()
    loaded = box.load_activation_document(doc, runtime_workflow_sha=WORKFLOW_SHA, observed_bridge_package_sha256=PACKAGE_SHA, provisioning_evidence=evidence)
    box.validate_bridge_runtime_receipt(receipt, loaded)
    return loaded


def clone_pair():
    doc, evidence = activated_pair()
    return copy.deepcopy(doc), copy.deepcopy(evidence)
