"""Dormant private release mailbox, WORM bundle, and activation contracts."""
from __future__ import annotations

import base64, dataclasses, datetime as dt, hashlib, io, json, re, stat, tarfile, zipfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

SHA40=re.compile(r"^[0-9a-f]{40}$"); SHA256=re.compile(r"^[0-9a-f]{64}$")
POSITIVE=re.compile(r"^[1-9][0-9]*$"); NONCE=re.compile(r"^[0-9a-f]{32}$")
UTC=re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
NAME=re.compile(r"^pd(req|res)-[1-9][0-9]*-[1-9][0-9]*-[0-9a-f]{32}$")
GUID=re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SUBSCRIPTION="9c4e0d0d-602f-4cde-84bd-337250e5b64c"; API="2025-04-01"
TENANT="aba83bd8-3e5c-4a87-9eb1-7bca070685b2"
PRODUCTION_SYSTEM_CLIENT_ID="a9935122-5592-467f-ba75-68844f46de1a"
PRODUCTION_SYSTEM_PRINCIPAL_ID="b856ea96-e96a-420a-9137-79e1e7a85ef4"
MAX_REQUEST=32768; MAX_RESULT=65536; MAX_ZIP=1073741824; MAX_MEMBERS=25000
KEY_RECOVERY_HORIZON_SECONDS=30*24*60*60
BOOTSTRAP_BASELINE={
    "sourceSha":"cef0242719d8f1ab19297c854f9d5e9c81dc3ead",
    "repositoryId":"1287744543","ownerId":"202535166",
    "sourceRunId":"31665623339","sourceRunAttempt":"1","artifactId":"9168291596",
    "artifactSha256":"e05a39a7e72521c67ed21b9b9e07d7f892c8979235ab1644c4b53304707a2623",
    "artifactMember":"paperdesk-azure-runtime-cef0242719d8f1ab19297c854f9d5e9c81dc3ead.tar.gz",
    "artifactMemberSha256":"f0094818699c6fda8184b6579cca814d5b56e27e0faef1927f0e7d7380599842",
    "servedIndexSha256":"20db1a82cb4fc6367b30e0e467f178130e833b8d739ed541587cc52da4dca031",
    # Historical no-drift signal only. Candidate identity is proven by the
    # exact versioned run-from-package URL, MI binding, runtime marker, index,
    # and health; no OneDeploy operation participates in V2 activation.
    "oneDeployInvariant":{
        "historicalActiveDeploymentId":"54214e75-d66c-4a62-8d04-17d5b48b6b52",
        "collectionSemanticProjectionSha256":"e51093a7b008224d50bb4d11b32aac0c59dc5a077f19cca559089106e37a92f3",
        "propertyIdSetSha256":"3f405fccf4cdd62eb17a7176ed4c89a88d568e4af2d014cb5608a9232fc8e8e9",
        "deploymentCount":10,
    },
    "readinessHttpStatus":503,"readinessCode":"attachment-malware-ingestion-not-ready",
    "localEvidenceSha256":"76057b91193ca671dde356da25a1c1c8f8775c32c63f53a747312dec22f81d4c",
}
FIXED_COORDS={"subscriptionId":SUBSCRIPTION,"bridgeResourceGroup":"rg-master-data-structure-sea","bridgeApp":"paperdesk-release-registry-bridge-v2-9c4e0d0d","bridgeWebJob":"paperdesk-accepted-release-registry","productionResourceGroup":"rg-master-data-structure-sea","productionApp":"master-data-structure-sea-9c4e0d0d","registryAccount":"mdspdbak2608089c4e","registryContainer":"paperdesk-accepted-releases","resultContainer":"paperdesk-registry-webjob-results","packageAccount":"mdspdbak2608089c4e","packageContainer":"paperdesk-deployment-packages","controllerLockResourceGroup":"rg-paperdesk-rollback-sea-20260808","controllerLockContainer":"paperdesk-release-controller-lock","activationFenceContainer":"paperdesk-release-activation-control","activationFenceBlob":"v2/production-activation-fence.json","signingVault":"kv-mds-sea-9c4e0d0d","signingKeyName":"paperdesk-release-result-signing","managementApiVersion":"2025-04-01","webApiVersion":"2025-05-01","bootstrapBaseline":BOOTSTRAP_BASELINE}
OWNER_REPOSITORY="Sethvirak/MasterDataStructure"; OWNER_REPOSITORY_ID="1287744543"; OWNER_ID="202535166"
OWNER_WORKFLOW_ID="306965591"
OWNER_WORKFLOW_NAME="Build and deploy Node.js app to Azure Web App: master-data-structure-sea-9c4e0d0d"
OWNER_WORKFLOW_PATH=".github/workflows/main_master-data-structure-sea-9c4e0d0d.yml"
OWNER_WORKFLOW_EVENTS={"push","workflow_dispatch"}
OWNER_WORKFLOW_REF=f"{OWNER_REPOSITORY}/{OWNER_WORKFLOW_PATH}@refs/heads/main"
PERSIST_WORKFLOW_ID="340547201"
PERSIST_WORKFLOW_NAME="Persist accepted PaperDesk release (dormant)"
PERSIST_WORKFLOW_PATH=".github/workflows/persist-accepted-release.yml"
PERSIST_WORKFLOW_REF=f"{OWNER_REPOSITORY}/{PERSIST_WORKFLOW_PATH}@refs/heads/main"
CLEANUP_WORKFLOW_ID="334414600"
CLEANUP_WORKFLOW_NAME="PaperDesk external-control OIDC canary"
CLEANUP_WORKFLOW_PATH=".github/workflows/production-oidc-canary.yml"
CLEANUP_WORKFLOW_REF=f"{OWNER_REPOSITORY}/{CLEANUP_WORKFLOW_PATH}@refs/heads/main"
CLEANUP_WORKFLOW_EVENTS={"workflow_run","schedule","workflow_dispatch"}
CONTROL_REPOSITORY="Sethvirak/paperdesk-release-verifier"
CONTROL_WORKFLOW_PATH=".github/workflows/azure-production-control.yml"
OIDC_SUBJECT="repo:Sethvirak/MasterDataStructure:environment:paperdesk-production-control"
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"
GRAPH_APPLICATION_READ_ALL_ROLE_ID="9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"

def bridge_owner_policy(operation):
    if operation in {"bootstrap-prepare","bootstrap-consume","prepare-candidate","consume-candidate","prepare-rollback","complete-rollback"}:
        events={"workflow_dispatch"} if operation in {"bootstrap-prepare","bootstrap-consume","prepare-rollback","complete-rollback"} else OWNER_WORKFLOW_EVENTS
        return {"workflowId":OWNER_WORKFLOW_ID,"workflowName":OWNER_WORKFLOW_NAME,"workflowPath":OWNER_WORKFLOW_PATH,"workflowRef":OWNER_WORKFLOW_REF,"events":events}
    if operation=="persist-accepted-release":
        return {"workflowId":PERSIST_WORKFLOW_ID,"workflowName":PERSIST_WORKFLOW_NAME,"workflowPath":PERSIST_WORKFLOW_PATH,"workflowRef":PERSIST_WORKFLOW_REF,"events":{"workflow_run"}}
    fail("bridge-owner-operation")

# Source-pinned provider-operation universe used when evaluating every role
# assignment that applies to the private V2 bridge.  It intentionally includes
# secret-bearing reads and deployment surfaces, not only obvious writes.  An
# unknown Microsoft.Web/sites operation is handled fail-closed by the live
# verifier; this list is the reviewable minimum, not an allowlist for new
# provider operations.
BRIDGE_SENSITIVE_ACTION_UNIVERSE=tuple(sorted({
    "Microsoft.Authorization/roleAssignments/delete",
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleDefinitions/delete",
    "Microsoft.Authorization/roleDefinitions/write",
    "Microsoft.Resources/deployments/delete",
    "Microsoft.Resources/deployments/write",
    "Microsoft.Web/sites/applySlotConfig/Action",
    "Microsoft.Web/sites/basicPublishingCredentialsPolicies/read",
    "Microsoft.Web/sites/basicPublishingCredentialsPolicies/write",
    "Microsoft.Web/sites/config/appsettings/delete",
    "Microsoft.Web/sites/config/appsettings/read",
    "Microsoft.Web/sites/config/appsettings/write",
    "Microsoft.Web/sites/config/connectionstrings/delete",
    "Microsoft.Web/sites/config/connectionstrings/read",
    "Microsoft.Web/sites/config/connectionstrings/write",
    "Microsoft.Web/sites/config/delete",
    "Microsoft.Web/sites/config/list/Action",
    "Microsoft.Web/sites/config/read",
    "Microsoft.Web/sites/config/web/appsettings/delete",
    "Microsoft.Web/sites/config/web/appsettings/read",
    "Microsoft.Web/sites/config/web/appsettings/write",
    "Microsoft.Web/sites/config/write",
    "Microsoft.Web/sites/continuouswebjobs/delete",
    "Microsoft.Web/sites/continuouswebjobs/start/action",
    "Microsoft.Web/sites/continuouswebjobs/stop/action",
    "Microsoft.Web/sites/continuouswebjobs/write",
    "Microsoft.Web/sites/delete",
    "Microsoft.Web/sites/deployments/delete",
    "Microsoft.Web/sites/deployments/read",
    "Microsoft.Web/sites/deployments/write",
    "Microsoft.Web/sites/extensions/delete",
    "Microsoft.Web/sites/extensions/read",
    "Microsoft.Web/sites/extensions/write",
    "Microsoft.Web/sites/publish/Action",
    "Microsoft.Web/sites/publishingCredentials/action",
    "Microsoft.Web/sites/publishxml/Action",
    "Microsoft.Web/sites/publishxml/read",
    "Microsoft.Web/sites/resetSlotConfig/Action",
    "Microsoft.Web/sites/restart/Action",
    "Microsoft.Web/sites/slots/applySlotConfig/Action",
    "Microsoft.Web/sites/slots/config/appsettings/delete",
    "Microsoft.Web/sites/slots/config/appsettings/read",
    "Microsoft.Web/sites/slots/config/appsettings/write",
    "Microsoft.Web/sites/slots/config/list/Action",
    "Microsoft.Web/sites/slots/config/read",
    "Microsoft.Web/sites/slots/config/write",
    "Microsoft.Web/sites/slots/delete",
    "Microsoft.Web/sites/slots/deployments/delete",
    "Microsoft.Web/sites/slots/deployments/read",
    "Microsoft.Web/sites/slots/deployments/write",
    "Microsoft.Web/sites/slots/publish/Action",
    "Microsoft.Web/sites/slots/publishxml/Action",
    "Microsoft.Web/sites/slots/publishxml/read",
    "Microsoft.Web/sites/slots/resetSlotConfig/Action",
    "Microsoft.Web/sites/slots/restart/Action",
    "Microsoft.Web/sites/slots/slotsswap/Action",
    "Microsoft.Web/sites/slots/sourcecontrols/delete",
    "Microsoft.Web/sites/slots/sourcecontrols/read",
    "Microsoft.Web/sites/slots/sourcecontrols/write",
    "Microsoft.Web/sites/slots/start/Action",
    "Microsoft.Web/sites/slots/stop/Action",
    "Microsoft.Web/sites/slots/triggeredwebjobs/delete",
    "Microsoft.Web/sites/slots/triggeredwebjobs/history/read",
    "Microsoft.Web/sites/slots/triggeredwebjobs/read",
    "Microsoft.Web/sites/slots/triggeredwebjobs/run/action",
    "Microsoft.Web/sites/slots/write",
    "Microsoft.Web/sites/sourcecontrols/delete",
    "Microsoft.Web/sites/sourcecontrols/read",
    "Microsoft.Web/sites/sourcecontrols/write",
    "Microsoft.Web/sites/start/Action",
    "Microsoft.Web/sites/stop/Action",
    "Microsoft.Web/sites/triggeredwebjobs/delete",
    "Microsoft.Web/sites/triggeredwebjobs/history/read",
    "Microsoft.Web/sites/triggeredwebjobs/read",
    "Microsoft.Web/sites/triggeredwebjobs/run/action",
    "Microsoft.Web/sites/triggeredwebjobs/write",
    "Microsoft.Web/sites/write",
},key=str.lower))
KEY_SENSITIVE_ACTION_UNIVERSE=tuple(sorted({
    "Microsoft.Authorization/roleAssignments/write","Microsoft.Authorization/roleAssignments/delete",
    "Microsoft.Authorization/roleDefinitions/write","Microsoft.Authorization/roleDefinitions/delete",
    "Microsoft.Resources/deployments/write","Microsoft.Resources/deployments/delete",
    "Microsoft.KeyVault/vaults/write","Microsoft.KeyVault/vaults/delete",
    "Microsoft.KeyVault/vaults/keys/write","Microsoft.KeyVault/vaults/keys/delete",
    "Microsoft.KeyVault/vaults/keys/backup/action","Microsoft.KeyVault/vaults/keys/restore/action",
    "Microsoft.KeyVault/vaults/keys/recover/action","Microsoft.KeyVault/vaults/keys/purge/action",
    "Microsoft.KeyVault/vaults/keys/import/action","Microsoft.KeyVault/vaults/keys/release/action",
    "Microsoft.KeyVault/vaults/keys/sign/action","Microsoft.KeyVault/vaults/keys/decrypt/action",
    "Microsoft.KeyVault/vaults/keys/encrypt/action","Microsoft.KeyVault/vaults/keys/wrap/action",
    "Microsoft.KeyVault/vaults/keys/unwrap/action","Microsoft.KeyVault/vaults/keys/export/action",
},key=str.lower))

class MailboxError(ValueError): pass
def fail(code): raise MailboxError(code)
def canonical(value):
    try: return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False)+"\n").encode()
    except (TypeError,ValueError): fail("canonical-json")
def digest(raw): return hashlib.sha256(raw).hexdigest()
def parse_time(value,label):
    if not isinstance(value,str) or not UTC.fullmatch(value): fail(label)
    return dt.datetime.strptime(value,"%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.timezone.utc)
def parse_arm_time(value,label):
    if not isinstance(value,str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z",value): fail(label)
    try: return dt.datetime.fromisoformat(value[:-1]+"+00:00")
    except ValueError: fail(label)
def b64u_decode(value,label):
    if not isinstance(value,str) or not re.fullmatch(r"[A-Za-z0-9_-]+",value): fail(label)
    try: return base64.urlsafe_b64decode(value+"="*((4-len(value)%4)%4))
    except Exception: fail(label)

ACTIVATION_FIELDS={"mergedControlWorkflowSha","mailboxResourceGroup","mailboxPublisherClientId","mailboxPublisherPrincipalId","mailboxRoleDefinitionId","mailboxRoleAssignmentId","controllerLockRoleDefinitionId","controllerLockRoleAssignmentId","controllerLockRoleAssignmentScope","controllerLockRoleDefinitionActions","controllerLockForbiddenDataActions","tenantId","bridgeManagedIdentityClientId","bridgeManagedIdentityPrincipalId","bridgeManagedIdentityResourceId","registryWriterManagedIdentityClientId","registryWriterManagedIdentityPrincipalId","registryWriterManagedIdentityResourceId","registryReaderManagedIdentityClientId","registryReaderManagedIdentityPrincipalId","registryReaderManagedIdentityResourceId","signerManagedIdentityClientId","signerManagedIdentityPrincipalId","signerManagedIdentityResourceId","signerRoleDefinitionId","signerRoleAssignmentId","signerRoleAssignmentScope","signerRoleDefinitionDataActions","signerForbiddenRoleAssignments","signingKeyId","signingKeyVersion","signingPublicJwk","bridgePackageSha256","productionActivationManagedIdentityClientId","productionActivationManagedIdentityPrincipalId","productionActivationManagedIdentityResourceId","productionActivationRoleDefinitionId","productionActivationRoleAssignmentId","productionActivationRoleAssignmentScope","productionActivationRoleDefinitionActions","productionActivationForbiddenRoleAssignments","productionPackageReaderRoleAssignmentId","productionPackageReaderRoleScope","productionForbiddenDataPlaneAssignments","productionSystemIdentityClientId","productionSystemIdentityPrincipalId","packageWriterRoleAssignmentId","packageReaderRoleAssignmentId","activationFence","provisioningEvidenceSha256"}
@dataclasses.dataclass(frozen=True)
class Activation:
    workflow_sha:str; mailbox_resource_group:str; tenant_id:str
    publisher_client_id:str; publisher_principal_id:str
    bridge_client_id:str; bridge_principal_id:str
    registry_writer_client_id:str; registry_writer_principal_id:str
    registry_reader_client_id:str; registry_reader_principal_id:str
    signer_client_id:str; signer_principal_id:str
    signing_key_id:str; signing_key_version:str; signing_public_jwk:dict
    bridge_package_sha256:str
    production_activation_client_id:str; production_activation_principal_id:str
    production_principal_id:str
    activation_fence:dict; provisioning_evidence:dict

def load_activation_document(doc,*,runtime_workflow_sha,observed_bridge_package_sha256,provisioning_evidence=None):
    if not isinstance(doc,dict) or doc.get("schemaVersion")!=1 or doc.get("fixed")!=FIXED_COORDS: fail("activation-fixed-coordinates")
    activation=doc.get("activation") if isinstance(doc,dict) else None
    if not isinstance(activation,dict) or set(activation)!=ACTIVATION_FIELDS or any(value is None for value in activation.values()): fail("activation-incomplete")
    rg=activation["mailboxResourceGroup"]
    if not isinstance(rg,str) or not re.fullmatch(r"[A-Za-z0-9._()-]{1,90}",rg): fail("activation-mailbox-rg")
    if not SHA40.fullmatch(str(runtime_workflow_sha)) or activation["mergedControlWorkflowSha"]!=runtime_workflow_sha: fail("activation-workflow-sha")
    if not SHA256.fullmatch(str(observed_bridge_package_sha256)) or activation["bridgePackageSha256"]!=observed_bridge_package_sha256: fail("activation-package-sha")
    for field in ("mailboxPublisherClientId","mailboxPublisherPrincipalId","mailboxRoleDefinitionId","mailboxRoleAssignmentId","controllerLockRoleDefinitionId","controllerLockRoleAssignmentId","tenantId","bridgeManagedIdentityClientId","bridgeManagedIdentityPrincipalId","registryWriterManagedIdentityClientId","registryWriterManagedIdentityPrincipalId","registryReaderManagedIdentityClientId","registryReaderManagedIdentityPrincipalId","signerManagedIdentityClientId","signerManagedIdentityPrincipalId","signerRoleDefinitionId","signerRoleAssignmentId","productionActivationManagedIdentityClientId","productionActivationManagedIdentityPrincipalId","productionActivationRoleDefinitionId","productionActivationRoleAssignmentId","productionPackageReaderRoleAssignmentId","productionSystemIdentityClientId","productionSystemIdentityPrincipalId","packageWriterRoleAssignmentId","packageReaderRoleAssignmentId"):
        if not GUID.fullmatch(str(activation[field])): fail("activation-id")
    if (activation["tenantId"]!=TENANT or activation["productionSystemIdentityClientId"]!=PRODUCTION_SYSTEM_CLIENT_ID
            or activation["productionSystemIdentityPrincipalId"]!=PRODUCTION_SYSTEM_PRINCIPAL_ID):fail("activation-fixed-identity")
    package_scope=f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-paperdesk-rollback-sea-20260808/providers/Microsoft.Storage/storageAccounts/{FIXED_COORDS['packageAccount']}/blobServices/default/containers/{FIXED_COORDS['packageContainer']}"
    account_scope=f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-paperdesk-rollback-sea-20260808/providers/Microsoft.Storage/storageAccounts/{FIXED_COORDS['packageAccount']}"
    if activation["productionPackageReaderRoleScope"]!=package_scope or activation["productionForbiddenDataPlaneAssignments"]!=[]: fail("activation-production-storage-scope")
    lock_scope=f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{FIXED_COORDS['controllerLockResourceGroup']}/providers/Microsoft.Storage/storageAccounts/{FIXED_COORDS['packageAccount']}/blobServices/default/containers/{FIXED_COORDS['controllerLockContainer']}"
    if (activation["controllerLockRoleAssignmentScope"]!=lock_scope
            or activation["controllerLockRoleDefinitionActions"]!=["Microsoft.Storage/storageAccounts/blobServices/containers/read","Microsoft.Storage/storageAccounts/blobServices/containers/lease/action"]
            or activation["controllerLockForbiddenDataActions"]!=[]):fail("activation-controller-lock-role")
    clients=[activation["mailboxPublisherClientId"],activation["bridgeManagedIdentityClientId"],activation["registryWriterManagedIdentityClientId"],activation["registryReaderManagedIdentityClientId"],activation["signerManagedIdentityClientId"],activation["productionActivationManagedIdentityClientId"],activation["productionSystemIdentityClientId"]]
    principals=[activation["mailboxPublisherPrincipalId"],activation["bridgeManagedIdentityPrincipalId"],activation["registryWriterManagedIdentityPrincipalId"],activation["registryReaderManagedIdentityPrincipalId"],activation["signerManagedIdentityPrincipalId"],activation["productionActivationManagedIdentityPrincipalId"],activation["productionSystemIdentityPrincipalId"]]
    if len(set(clients))!=len(clients) or len(set(principals))!=len(principals):fail("activation-identity-separation")
    identity_resource_fields=("bridgeManagedIdentityResourceId","registryWriterManagedIdentityResourceId","registryReaderManagedIdentityResourceId","signerManagedIdentityResourceId","productionActivationManagedIdentityResourceId")
    identity_resources=[]
    for field in identity_resource_fields:
        value=activation[field]
        if not isinstance(value,str) or not re.fullmatch(rf"/subscriptions/{SUBSCRIPTION}/resourceGroups/[A-Za-z0-9._()-]{{1,90}}/providers/Microsoft\.ManagedIdentity/userAssignedIdentities/[A-Za-z0-9._()-]{{1,128}}",value,re.I):fail("activation-identity-resource")
        identity_resources.append(value.lower())
    if len(set(identity_resources))!=len(identity_resources):fail("activation-identity-resource")
    key_scope=f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{FIXED_COORDS['bridgeResourceGroup']}/providers/Microsoft.KeyVault/vaults/{FIXED_COORDS['signingVault']}/keys/{FIXED_COORDS['signingKeyName']}"
    if (activation["signerRoleAssignmentScope"]!=key_scope
            or activation["signerRoleDefinitionDataActions"]!=["Microsoft.KeyVault/vaults/keys/sign/action"]
            or activation["signerForbiddenRoleAssignments"]!=[]): fail("activation-signer-role")
    production_scope=f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{FIXED_COORDS['productionResourceGroup']}/providers/Microsoft.Web/sites/{FIXED_COORDS['productionApp']}"
    production_actions=["Microsoft.Web/sites/config/list/action","Microsoft.Web/sites/config/write","Microsoft.Web/sites/deployments/read","Microsoft.Web/sites/restart/action"]
    if (activation["productionActivationRoleAssignmentScope"]!=production_scope
            or activation["productionActivationRoleDefinitionActions"]!=production_actions
            or activation["productionActivationForbiddenRoleAssignments"]!=[]):fail("activation-production-role")
    fence=activation["activationFence"]
    fence_scope=f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-paperdesk-rollback-sea-20260808/providers/Microsoft.Storage/storageAccounts/{FIXED_COORDS['packageAccount']}/blobServices/default/containers/{FIXED_COORDS['activationFenceContainer']}"
    if (not isinstance(fence,dict) or set(fence)!={"storageAccount","container","blob","scope","bridgeRoleAssignmentId","bridgePrincipalId","leaseDuration","publicAccess","bootstrapReceiptSha256","governanceBoundary"}
            or fence["storageAccount"]!=FIXED_COORDS["packageAccount"] or fence["container"]!=FIXED_COORDS["activationFenceContainer"] or fence["blob"]!=FIXED_COORDS["activationFenceBlob"]
            or fence["scope"]!=fence_scope or not GUID.fullmatch(str(fence["bridgeRoleAssignmentId"])) or fence["bridgePrincipalId"]!=activation["bridgeManagedIdentityPrincipalId"]
            or fence["leaseDuration"]!=60 or fence["publicAccess"]!="None" or not SHA256.fullmatch(str(fence["bootstrapReceiptSha256"]))
            or fence["governanceBoundary"]!="subscription-and-resource-group-owners-remain-out-of-band-and-third-state-is-never-overwritten"): fail("activation-fence")
    evidence=provisioning_evidence
    evidence_fields={"schemaVersion","status","subscriptionId","observedAt","publisherIdentity","roles","principalInventories","controllerLockContainer","bridgeRuntime","keyVaultBoundary","wormPolicies","publisherAuthorizationDecisions","rule"}
    if (not isinstance(evidence,dict) or set(evidence)!=evidence_fields or evidence.get("schemaVersion")!=1
            or evidence.get("status")!="activated" or evidence.get("subscriptionId")!=SUBSCRIPTION
            or not isinstance(evidence.get("rule"),str) or len(evidence["rule"])<32
            or digest(canonical(evidence))!=activation["provisioningEvidenceSha256"]):fail("activation-provisioning-evidence")
    parse_time(evidence.get("observedAt"),"activation-provisioning-observed")
    publisher_identity=evidence.get("publisherIdentity")
    publisher_fields={"applicationObjectId","applicationQuery","applicationProjectionSha256","servicePrincipalQuery","servicePrincipalProjectionSha256","federatedIdentityCredentialsQuery","federatedIdentityCredentialPolicy","federatedIdentityCredentialPolicySha256","appRoleAssignmentsQuery","graphServicePrincipalObjectId","graphApplicationReadAllAppRoleAssignment","graphApplicationReadAllAppRoleAssignmentSha256","observedAt"}
    app_object=publisher_identity.get("applicationObjectId") if isinstance(publisher_identity,dict) else None
    graph_sp=publisher_identity.get("graphServicePrincipalObjectId") if isinstance(publisher_identity,dict) else None
    fic=publisher_identity.get("federatedIdentityCredentialPolicy") if isinstance(publisher_identity,dict) else None
    app_role=publisher_identity.get("graphApplicationReadAllAppRoleAssignment") if isinstance(publisher_identity,dict) else None
    graph_root="https://graph.microsoft.com"
    application_query=f"{graph_root}/beta/applications/{app_object}?$select=id,appId,signInAudience,passwordCredentials,keyCredentials"
    service_query=f"{graph_root}/v1.0/servicePrincipals/{activation['mailboxPublisherPrincipalId']}?$select=id,appId,accountEnabled,servicePrincipalType,passwordCredentials,keyCredentials"
    fic_query=f"{graph_root}/beta/applications/{app_object}/federatedIdentityCredentials"
    app_role_query=f"{graph_root}/v1.0/servicePrincipals/{activation['mailboxPublisherPrincipalId']}/appRoleAssignments"
    expression_template=(f"claims['sub'] eq '{OIDC_SUBJECT}' and claims['repository_id'] eq '{OWNER_REPOSITORY_ID}' "
                         f"and claims['repository_owner_id'] eq '{OWNER_ID}' and claims['job_workflow_ref'] eq '{{controlWorkflowRef}}'")
    fic_fields={"id","name","issuer","audiences","subject","claimsMatchingExpressionTemplate"}
    app_role_fields={"id","principalId","resourceId","appRoleId"}
    if (not isinstance(publisher_identity,dict) or set(publisher_identity)!=publisher_fields or not GUID.fullmatch(str(app_object)) or not GUID.fullmatch(str(graph_sp))
            or publisher_identity.get("applicationQuery")!=application_query or not SHA256.fullmatch(str(publisher_identity.get("applicationProjectionSha256")))
            or publisher_identity.get("servicePrincipalQuery")!=service_query or not SHA256.fullmatch(str(publisher_identity.get("servicePrincipalProjectionSha256")))
            or publisher_identity.get("federatedIdentityCredentialsQuery")!=fic_query or not isinstance(fic,dict) or set(fic)!=fic_fields
            or not GUID.fullmatch(str(fic.get("id"))) or fic.get("name")!="paperdesk-production-control-v2"
            or fic.get("issuer")!="https://token.actions.githubusercontent.com" or fic.get("audiences")!=["api://AzureADTokenExchange"] or fic.get("subject") is not None
            or fic.get("claimsMatchingExpressionTemplate")!={"languageVersion":1,"value":expression_template}
            or publisher_identity.get("federatedIdentityCredentialPolicySha256")!=digest(canonical(fic))
            or publisher_identity.get("appRoleAssignmentsQuery")!=app_role_query or not isinstance(app_role,dict) or set(app_role)!=app_role_fields
            or not GUID.fullmatch(str(app_role.get("id"))) or app_role.get("principalId")!=activation["mailboxPublisherPrincipalId"]
            or app_role.get("resourceId")!=graph_sp or app_role.get("appRoleId")!=GRAPH_APPLICATION_READ_ALL_ROLE_ID
            or publisher_identity.get("graphApplicationReadAllAppRoleAssignmentSha256")!=digest(canonical(app_role))):fail("activation-publisher-identity")
    parse_time(publisher_identity.get("observedAt"),"activation-publisher-identity-observed")
    role_fields={"roleDefinitionResourceId","roleDefinitionSha256","roleAssignmentResourceId","roleAssignmentSha256","principalId","principalType","tenantId","identityClientId","identityResourceId","scope","condition","conditionVersion","delegatedManagedIdentityResourceId","assignableScopes","actions","notActions","dataActions","notDataActions"}
    roles=evidence.get("roles")
    expected_role_names={"publisherMailbox","publisherBridgeController","publisherControllerLock","publisherAcceptedCustodyAudit","publisherPackageCustodyAudit","publisherResultCustodyAudit","publisherAudit","publisherWebIdentityAudit","publisherKeyPostureAudit","bridgeMailboxResult","bridgeActivationFence","bridgeKeyRead","writerRegistryAdd","writerPackageAdd","readerRegistryRead","readerPackageRead","signerKeySign","productionActivation","productionSystemPackageRead","productionSystemAttachmentContributor","productionSystemSecretsUser"}
    if not isinstance(roles,dict) or set(roles)!=expected_role_names:fail("activation-provisioning-roles")
    mailbox_scope=f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{rg}"
    registry_scope=f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-paperdesk-rollback-sea-20260808/providers/Microsoft.Storage/storageAccounts/{FIXED_COORDS['registryAccount']}/blobServices/default/containers/{FIXED_COORDS['registryContainer']}"
    result_scope=f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-paperdesk-rollback-sea-20260808/providers/Microsoft.Storage/storageAccounts/{FIXED_COORDS['registryAccount']}/blobServices/default/containers/paperdesk-registry-webjob-results"
    bridge_scope=f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{FIXED_COORDS['bridgeResourceGroup']}/providers/Microsoft.Web/sites/{FIXED_COORDS['bridgeApp']}"
    subscription_scope=f"/subscriptions/{SUBSCRIPTION}"
    bridge_actions=["Microsoft.Web/sites/Read","Microsoft.Web/sites/start/Action","Microsoft.Web/sites/stop/Action","Microsoft.Web/sites/config/list/Action","Microsoft.Web/sites/config/Read","Microsoft.Web/sites/config/Write","Microsoft.Web/sites/basicPublishingCredentialsPolicies/Read","Microsoft.Web/sites/sourcecontrols/read","Microsoft.Web/sites/triggeredwebjobs/read","Microsoft.Web/sites/triggeredwebjobs/history/read","Microsoft.Web/sites/triggeredwebjobs/run/action"]
    audit_actions=["Microsoft.Authorization/roleAssignments/read","Microsoft.Authorization/roleDefinitions/read"]
    custody_actions=["Microsoft.Storage/storageAccounts/blobServices/containers/read","Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/read"]
    attachment_role=roles.get("productionSystemAttachmentContributor") if isinstance(roles,dict) else None
    secrets_role=roles.get("productionSystemSecretsUser") if isinstance(roles,dict) else None
    attachment_scope=attachment_role.get("scope") if isinstance(attachment_role,dict) else None
    secrets_scope=secrets_role.get("scope") if isinstance(secrets_role,dict) else None
    if (not isinstance(attachment_scope,str) or not re.fullmatch(rf"/subscriptions/{SUBSCRIPTION}/resourceGroups/[A-Za-z0-9._()-]+/providers/Microsoft\.Storage/storageAccounts/[a-z0-9]{{3,24}}/blobServices/default/containers/[a-z0-9-]{{3,63}}",attachment_scope,re.I)
            or attachment_scope.lower() in {scope.lower() for scope in (package_scope,registry_scope,fence_scope,lock_scope,result_scope) if isinstance(scope,str)}
            or not isinstance(secrets_scope,str) or not re.fullmatch(rf"/subscriptions/{SUBSCRIPTION}/resourceGroups/[A-Za-z0-9._()-]+/providers/Microsoft\.KeyVault/vaults/[A-Za-z0-9-]{{3,24}}",secrets_scope,re.I)):fail("activation-production-system-existing-scopes")
    role_specs={
        "publisherMailbox":(activation["mailboxRoleDefinitionId"],activation["mailboxRoleAssignmentId"],activation["mailboxPublisherPrincipalId"],activation["mailboxPublisherClientId"],None,mailbox_scope,["Microsoft.Resources/deployments/read","Microsoft.Resources/deployments/write","Microsoft.Resources/deployments/delete"],[]),
        "publisherBridgeController":(None,None,activation["mailboxPublisherPrincipalId"],activation["mailboxPublisherClientId"],None,bridge_scope,bridge_actions,[]),
        "publisherControllerLock":(activation["controllerLockRoleDefinitionId"],activation["controllerLockRoleAssignmentId"],activation["mailboxPublisherPrincipalId"],activation["mailboxPublisherClientId"],None,lock_scope,["Microsoft.Storage/storageAccounts/blobServices/containers/read","Microsoft.Storage/storageAccounts/blobServices/containers/lease/action"],[]),
        "publisherAcceptedCustodyAudit":(None,None,activation["mailboxPublisherPrincipalId"],activation["mailboxPublisherClientId"],None,registry_scope,custody_actions,[]),
        "publisherPackageCustodyAudit":(None,None,activation["mailboxPublisherPrincipalId"],activation["mailboxPublisherClientId"],None,package_scope,custody_actions,[]),
        "publisherResultCustodyAudit":(None,None,activation["mailboxPublisherPrincipalId"],activation["mailboxPublisherClientId"],None,result_scope,custody_actions,[]),
        "publisherAudit":(None,None,activation["mailboxPublisherPrincipalId"],activation["mailboxPublisherClientId"],None,subscription_scope,audit_actions,[]),
        "publisherWebIdentityAudit":(None,None,activation["mailboxPublisherPrincipalId"],activation["mailboxPublisherClientId"],None,subscription_scope,["Microsoft.Web/sites/read"],[]),
        "publisherKeyPostureAudit":(None,None,activation["mailboxPublisherPrincipalId"],activation["mailboxPublisherClientId"],None,key_scope,["Microsoft.KeyVault/vaults/read","Microsoft.KeyVault/vaults/keys/read"],[]),
        "bridgeMailboxResult":(None,None,activation["bridgeManagedIdentityPrincipalId"],activation["bridgeManagedIdentityClientId"],activation["bridgeManagedIdentityResourceId"],mailbox_scope,["Microsoft.Resources/deployments/read","Microsoft.Resources/deployments/write"],[]),
        "bridgeActivationFence":(None,fence["bridgeRoleAssignmentId"],activation["bridgeManagedIdentityPrincipalId"],activation["bridgeManagedIdentityClientId"],activation["bridgeManagedIdentityResourceId"],fence_scope,[],["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read","Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write","Microsoft.Storage/storageAccounts/blobServices/containers/blobs/lease/action"]),
        "bridgeKeyRead":(None,None,activation["bridgeManagedIdentityPrincipalId"],activation["bridgeManagedIdentityClientId"],activation["bridgeManagedIdentityResourceId"],key_scope,[],["Microsoft.KeyVault/vaults/keys/read"]),
        "writerRegistryAdd":(None,None,activation["registryWriterManagedIdentityPrincipalId"],activation["registryWriterManagedIdentityClientId"],activation["registryWriterManagedIdentityResourceId"],registry_scope,[],["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action"]),
        "writerPackageAdd":(None,activation["packageWriterRoleAssignmentId"],activation["registryWriterManagedIdentityPrincipalId"],activation["registryWriterManagedIdentityClientId"],activation["registryWriterManagedIdentityResourceId"],package_scope,[],["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action"]),
        "readerRegistryRead":(None,None,activation["registryReaderManagedIdentityPrincipalId"],activation["registryReaderManagedIdentityClientId"],activation["registryReaderManagedIdentityResourceId"],registry_scope,[],["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"]),
        "readerPackageRead":(None,activation["packageReaderRoleAssignmentId"],activation["registryReaderManagedIdentityPrincipalId"],activation["registryReaderManagedIdentityClientId"],activation["registryReaderManagedIdentityResourceId"],package_scope,[],["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"]),
        "signerKeySign":(activation["signerRoleDefinitionId"],activation["signerRoleAssignmentId"],activation["signerManagedIdentityPrincipalId"],activation["signerManagedIdentityClientId"],activation["signerManagedIdentityResourceId"],key_scope,[],["Microsoft.KeyVault/vaults/keys/sign/action"]),
        "productionActivation":(activation["productionActivationRoleDefinitionId"],activation["productionActivationRoleAssignmentId"],activation["productionActivationManagedIdentityPrincipalId"],activation["productionActivationManagedIdentityClientId"],activation["productionActivationManagedIdentityResourceId"],production_scope,production_actions,[]),
        "productionSystemPackageRead":(None,activation["productionPackageReaderRoleAssignmentId"],activation["productionSystemIdentityPrincipalId"],activation["productionSystemIdentityClientId"],production_scope,package_scope,[],["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"]),
        "productionSystemAttachmentContributor":("ba92f5b4-2d11-453d-a403-e96b0029c9fe",None,activation["productionSystemIdentityPrincipalId"],activation["productionSystemIdentityClientId"],production_scope,attachment_scope,attachment_role.get("actions"),attachment_role.get("dataActions")),
        "productionSystemSecretsUser":("4633458b-17de-408a-b874-0445c86b69e6",None,activation["productionSystemIdentityPrincipalId"],activation["productionSystemIdentityClientId"],production_scope,secrets_scope,secrets_role.get("actions"),secrets_role.get("dataActions")),
    }
    role_assignment_ids=[]
    for name,(definition_id,assignment_id,principal,client,identity_resource,scope,actions,data_actions) in role_specs.items():
        role=roles.get(name)
        if (not isinstance(role,dict) or set(role)!=role_fields or not re.fullmatch(rf"/subscriptions/{SUBSCRIPTION}/providers/Microsoft\.Authorization/roleDefinitions/[0-9a-f-]{{36}}",str(role.get("roleDefinitionResourceId")),re.I)
                or not SHA256.fullmatch(str(role.get("roleDefinitionSha256"))) or not re.fullmatch(r"/subscriptions/[^\r\n]+/providers/Microsoft\.Authorization/roleAssignments/[0-9a-f-]{36}",str(role.get("roleAssignmentResourceId")),re.I)
                or not SHA256.fullmatch(str(role.get("roleAssignmentSha256"))) or role["roleAssignmentResourceId"].lower()!=f"{scope}/providers/Microsoft.Authorization/roleAssignments/{role['roleAssignmentResourceId'].rsplit('/',1)[1]}".lower()
                or role.get("principalId")!=principal or role.get("principalType")!="ServicePrincipal"
                or role.get("tenantId")!=activation["tenantId"] or role.get("identityClientId")!=client or role.get("identityResourceId")!=identity_resource
                or role.get("scope")!=scope or role.get("condition") is not None or role.get("conditionVersion") is not None or role.get("delegatedManagedIdentityResourceId") is not None
                or role.get("assignableScopes")!=(["/"] if name in {"productionSystemAttachmentContributor","productionSystemSecretsUser"} else [subscription_scope]) or role.get("actions")!=actions or role.get("notActions")!=[]
                or role.get("dataActions")!=data_actions or role.get("notDataActions")!=[]):fail("activation-provisioning-role-"+name)
        observed_definition=role["roleDefinitionResourceId"].rsplit("/",1)[1].lower();observed_assignment=role["roleAssignmentResourceId"].rsplit("/",1)[1].lower()
        if definition_id is not None and observed_definition!=definition_id.lower():fail("activation-provisioning-role-"+name)
        if assignment_id is not None and observed_assignment!=assignment_id.lower():fail("activation-provisioning-role-"+name)
        role_assignment_ids.append(role["roleAssignmentResourceId"].lower())
    if len(set(role_assignment_ids))!=len(role_assignment_ids):fail("activation-provisioning-role-duplicate")
    inventory_fields={"principalId","directQuery","effectiveQuery","directAssignmentResourceIds","effectiveAssignmentResourceIds","directAssignmentSetSha256","effectiveAssignmentSetSha256","observedAt"}
    inventory_specs={
        "publisher":activation["mailboxPublisherPrincipalId"],"bridge":activation["bridgeManagedIdentityPrincipalId"],
        "registryWriter":activation["registryWriterManagedIdentityPrincipalId"],"registryReader":activation["registryReaderManagedIdentityPrincipalId"],
        "signer":activation["signerManagedIdentityPrincipalId"],"productionActivation":activation["productionActivationManagedIdentityPrincipalId"],
        "productionSystem":activation["productionSystemIdentityPrincipalId"],
    }
    inventories=evidence.get("principalInventories")
    if not isinstance(inventories,dict) or set(inventories)!=set(inventory_specs):fail("activation-provisioning-inventories")
    for name,principal in inventory_specs.items():
        item=inventories[name];principal_roles=[role for role in roles.values() if role["principalId"]==principal]
        expected_ids=sorted(role["roleAssignmentResourceId"].lower() for role in principal_roles)
        expected_projections=[]
        for role in principal_roles:
            assignment_id=role["roleAssignmentResourceId"].lower()
            expected_projections.append({"id":assignment_id,"name":assignment_id.rsplit("/",1)[1],"type":"Microsoft.Authorization/roleAssignments","properties":{
                "principalId":role["principalId"].lower(),"principalType":"ServicePrincipal","roleDefinitionId":role["roleDefinitionResourceId"].lower(),
                "scope":role["scope"].lower(),"condition":None,"conditionVersion":None,"delegatedManagedIdentityResourceId":None}})
        expected_projections.sort(key=lambda value:value["id"])
        direct=f"https://management.azure.com/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=principalId%20eq%20%27{principal}%27"
        effective=f"https://management.azure.com/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=assignedTo%28%27{principal}%27%29"
        if (not isinstance(item,dict) or set(item)!=inventory_fields or item.get("principalId")!=principal or item.get("directQuery")!=direct or item.get("effectiveQuery")!=effective
                or item.get("directAssignmentResourceIds")!=expected_ids or item.get("effectiveAssignmentResourceIds")!=expected_ids
                or item.get("directAssignmentSetSha256")!=digest(canonical(expected_projections)) or item.get("effectiveAssignmentSetSha256")!=digest(canonical(expected_projections))):fail("activation-provisioning-inventory-"+name)
        parse_time(item.get("observedAt"),"activation-provisioning-inventory-observed")
    lock_container=evidence.get("controllerLockContainer")
    if (not isinstance(lock_container,dict) or set(lock_container)!={"scope","publicAccess","blobCount","resourceSha256","evidenceMethod","observedAt"}
            or lock_container.get("scope")!=lock_scope or lock_container.get("publicAccess")!="None" or lock_container.get("blobCount")!=0
            or not SHA256.fullmatch(str(lock_container.get("resourceSha256"))) or lock_container.get("evidenceMethod")!="authorized-bootstrap-arm-and-blob-inventory"):fail("activation-controller-lock-container")
    parse_time(lock_container.get("observedAt"),"activation-controller-lock-observed")
    bridge_runtime=evidence.get("bridgeRuntime")
    bridge_runtime_fields={"siteResourceId","packageBlob","packageSha256","packageSize","packageEtag","packageVersionId","packageUrl","packageReaderIdentityResourceId","criticalAppSettings","criticalAppSettingsSha256","sitePosture","sitePostureSha256","siteInventoryQuery","sensitiveIdentityResourceIds","sensitiveIdentityAttachmentSha256","resourceGraphAttachmentInventory","identityAssignmentBoundaries","bridgeMutationBoundary","legacyBridgeRetirement","networkTopology","bootstrapReceiptPath","bootstrapReceiptSha256","observedAt"}
    expected_bridge_site=f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{FIXED_COORDS['bridgeResourceGroup']}/providers/Microsoft.Web/sites/{FIXED_COORDS['bridgeApp']}"
    package_blob=f"v2/control/{activation['bridgePackageSha256']}/paperdesk-private-release-bridge.zip"
    version=bridge_runtime.get("packageVersionId") if isinstance(bridge_runtime,dict) else None
    package_url=f"https://{FIXED_COORDS['packageAccount']}.blob.core.windows.net/{FIXED_COORDS['packageContainer']}/{package_blob}?versionid={version}"
    critical={"WEBSITE_RUN_FROM_PACKAGE":package_url,"WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID":activation["registryReaderManagedIdentityResourceId"],"WEBSITE_SKIP_RUNNING_KUDUAGENT":"false","PAPERDESK_BRIDGE_PACKAGE_SHA256":activation["bridgePackageSha256"]}
    posture=bridge_runtime.get("sitePosture") if isinstance(bridge_runtime,dict) else None
    posture_fields={"siteResourceId","name","type","kind","serverFarmId","httpsOnly","publicNetworkAccess","virtualNetworkSubnetId","outboundVnetRouting","webConfig","ftpBasicAuthAllowed","scmBasicAuthAllowed","sourceControl"}
    web_config={"alwaysOn":True,"linuxFxVersion":"PYTHON|3.12","ftpsState":"Disabled","minTlsVersion":"1.2","scmMinTlsVersion":"1.2","scmType":"None","http20Enabled":True,"vnetRouteAllEnabled":True}
    outbound_routing={"allTraffic":True,"applicationTraffic":True}
    site_inventory_query=f"https://management.azure.com/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Web/sites?api-version=2025-03-01"
    sensitive_ids=sorted(identity_resources)
    expected_attachments={expected_bridge_site.lower():sensitive_ids}
    mutation=bridge_runtime.get("bridgeMutationBoundary") if isinstance(bridge_runtime,dict) else None
    mutation_fields={"bridgeScopeQuery","allowedNonOwnerAssignmentIds","ownerRoleDefinitionId","sensitiveActionUniverse","sensitiveActionUniverseSha256","mutatorAssignmentSha256","observedAt"}
    bridge_scope_query=f"https://management.azure.com{expected_bridge_site}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
    owner_definition=f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
    allowed_bridge_assignment=roles["publisherBridgeController"]["roleAssignmentResourceId"].lower()
    allowed_role=roles["publisherBridgeController"]
    allowed_projection={"id":allowed_bridge_assignment,"name":allowed_bridge_assignment.rsplit("/",1)[1],"type":"Microsoft.Authorization/roleAssignments","properties":{"principalId":allowed_role["principalId"].lower(),"principalType":"ServicePrincipal","roleDefinitionId":allowed_role["roleDefinitionResourceId"].lower(),"scope":allowed_role["scope"].lower(),"condition":None,"conditionVersion":None,"delegatedManagedIdentityResourceId":None}}
    graph_inventory=bridge_runtime.get("resourceGraphAttachmentInventory") if isinstance(bridge_runtime,dict) else None
    graph_fields={"query","sensitiveIdentityAttachments","projectionSha256","evidenceMethod","observedAt"}
    graph_query="Resources | where isnotnull(identity.userAssignedIdentities) | mv-expand uamiResourceId=bag_keys(identity.userAssignedIdentities) | project resourceId=tolower(id), uamiResourceId=tolower(tostring(uamiResourceId)) | order by uamiResourceId asc, resourceId asc"
    graph_attachments={identity:[expected_bridge_site.lower()] for identity in sensitive_ids}
    identity_boundaries=bridge_runtime.get("identityAssignmentBoundaries") if isinstance(bridge_runtime,dict) else None
    boundary_fields={"ownerRoleDefinitionId","items","observedAt"};boundary_item_fields={"resourceId","roleAssignmentsQuery","allowedNonOwnerAssignerAssignmentIds","assignerProjectionSha256"}
    boundary_items=identity_boundaries.get("items") if isinstance(identity_boundaries,dict) else None
    legacy=bridge_runtime.get("legacyBridgeRetirement") if isinstance(bridge_runtime,dict) else None
    legacy_fields={"siteResourceId","roleAssignmentsQuery","state","publicNetworkAccess","userAssignedIdentityResourceIds","transientAppSettingNamesPresent","publisherMutatorAssignmentIds","projectionSha256","observedAt"}
    legacy_site=f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{FIXED_COORDS['bridgeResourceGroup']}/providers/Microsoft.Web/sites/paperdesk-release-registry-bridge-9c4e0d0d"
    legacy_projection={"siteResourceId":legacy_site,"state":"Stopped","publicNetworkAccess":"Disabled","userAssignedIdentityResourceIds":[],"transientAppSettingNamesPresent":[],"publisherMutatorAssignmentIds":[]}
    legacy_role_query=f"https://management.azure.com{legacy_site}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
    topology=bridge_runtime.get("networkTopology") if isinstance(bridge_runtime,dict) else None
    topology_fields={"mode","virtualNetwork","integrationSubnet","packageStorageAccount","productionSite"}
    topology_item_fields={"resourceId","apiVersion","projectionSha256"}
    if isinstance(topology,dict):
        vnet=topology.get("virtualNetwork");subnet=topology.get("integrationSubnet");storage_topology=topology.get("packageStorageAccount");production_topology=topology.get("productionSite")
    else:vnet=subnet=storage_topology=production_topology=None
    topology_extra={
        "virtualNetwork":{"addressSpacePrefixes"},
        "integrationSubnet":{"virtualNetworkResourceId","delegations","serviceEndpoints","routeTableResourceId","networkSecurityGroupResourceId"},
        "packageStorageAccount":{"publicNetworkAccess","allowBlobPublicAccess","defaultAction","bypass","ipRules","resourceAccessRules","virtualNetworkRules"},
        "productionSite":{"virtualNetworkSubnetId","outboundVnetRouting"},
    }
    topology_items={"virtualNetwork":vnet,"integrationSubnet":subnet,"packageStorageAccount":storage_topology,"productionSite":production_topology}
    topology_shape_ok=isinstance(topology,dict) and set(topology)==topology_fields and topology.get("mode")=="service-endpoint-firewall-v1"
    for topology_name,topology_item in topology_items.items():
        topology_shape_ok=(topology_shape_ok and isinstance(topology_item,dict) and set(topology_item)==topology_item_fields|topology_extra[topology_name]
            and isinstance(topology_item.get("resourceId"),str) and topology_item["resourceId"].startswith(f"/subscriptions/{SUBSCRIPTION}/")
            and isinstance(topology_item.get("apiVersion"),str) and re.fullmatch(r"20[2-9][0-9]-[0-1][0-9]-[0-3][0-9]",topology_item["apiVersion"]) is not None
            and SHA256.fullmatch(str(topology_item.get("projectionSha256"))) is not None)
    if (not isinstance(bridge_runtime,dict) or set(bridge_runtime)!=bridge_runtime_fields or bridge_runtime.get("siteResourceId")!=expected_bridge_site
            or bridge_runtime.get("packageBlob")!=package_blob or bridge_runtime.get("packageSha256")!=activation["bridgePackageSha256"]
            or type(bridge_runtime.get("packageSize")) is not int or bridge_runtime["packageSize"]<=0 or not re.fullmatch(r'"[^"\r\n]+"',str(bridge_runtime.get("packageEtag")))
            or not isinstance(version,str) or not re.fullmatch(r"[A-Za-z0-9._=:+/-]{1,256}",version) or bridge_runtime.get("packageUrl")!=package_url
            or bridge_runtime.get("packageReaderIdentityResourceId")!=activation["registryReaderManagedIdentityResourceId"]
            or bridge_runtime.get("criticalAppSettings")!=critical or bridge_runtime.get("criticalAppSettingsSha256")!=digest(canonical(critical))
            or not isinstance(posture,dict) or set(posture)!=posture_fields or posture.get("siteResourceId")!=expected_bridge_site
            or posture.get("name")!=FIXED_COORDS["bridgeApp"] or posture.get("type")!="Microsoft.Web/sites" or posture.get("kind")!="app,linux"
            or not isinstance(posture.get("serverFarmId"),str) or not re.fullmatch(rf"/subscriptions/{SUBSCRIPTION}/resourceGroups/[A-Za-z0-9._()-]+/providers/Microsoft\.Web/serverfarms/[A-Za-z0-9._()-]+",posture["serverFarmId"],re.I)
            or posture.get("httpsOnly") is not True or posture.get("publicNetworkAccess")!="Disabled"
            or not isinstance(posture.get("virtualNetworkSubnetId"),str) or not re.fullmatch(rf"/subscriptions/{SUBSCRIPTION}/resourceGroups/[A-Za-z0-9._()-]+/providers/Microsoft\.Network/virtualNetworks/[A-Za-z0-9._()-]+/subnets/[A-Za-z0-9._()-]+",posture["virtualNetworkSubnetId"],re.I)
            or posture.get("outboundVnetRouting")!=outbound_routing or posture.get("webConfig")!=web_config or posture.get("ftpBasicAuthAllowed") is not False or posture.get("scmBasicAuthAllowed") is not False
            or posture.get("sourceControl") not in ({"status":404},{"status":200,"repoUrl":None,"branch":None,"isManualIntegration":False})
            or bridge_runtime.get("sitePostureSha256")!=digest(canonical(posture))
            or bridge_runtime.get("siteInventoryQuery")!=site_inventory_query or bridge_runtime.get("sensitiveIdentityResourceIds")!=sensitive_ids
            or bridge_runtime.get("sensitiveIdentityAttachmentSha256")!=digest(canonical(expected_attachments))
            or not isinstance(graph_inventory,dict) or set(graph_inventory)!=graph_fields or graph_inventory.get("query")!=graph_query
            or graph_inventory.get("sensitiveIdentityAttachments")!=graph_attachments or graph_inventory.get("projectionSha256")!=digest(canonical(graph_attachments))
            or graph_inventory.get("evidenceMethod")!="authorized-bootstrap-azure-resource-graph"
            or not isinstance(identity_boundaries,dict) or set(identity_boundaries)!=boundary_fields or identity_boundaries.get("ownerRoleDefinitionId")!=owner_definition
            or not isinstance(boundary_items,dict) or set(boundary_items)!=set(sensitive_ids)
            or any(not isinstance(item,dict) or set(item)!=boundary_item_fields or item.get("resourceId")!=identity
                or item.get("roleAssignmentsQuery")!=f"https://management.azure.com{identity}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
                or item.get("allowedNonOwnerAssignerAssignmentIds")!=[] or item.get("assignerProjectionSha256")!=digest(canonical([])) for identity,item in boundary_items.items())
            or not isinstance(mutation,dict) or set(mutation)!=mutation_fields or mutation.get("bridgeScopeQuery")!=bridge_scope_query
            or mutation.get("allowedNonOwnerAssignmentIds")!=[allowed_bridge_assignment]
            or mutation.get("ownerRoleDefinitionId")!=owner_definition
            or mutation.get("sensitiveActionUniverse")!=list(BRIDGE_SENSITIVE_ACTION_UNIVERSE)
            or mutation.get("sensitiveActionUniverseSha256")!=digest(canonical(list(BRIDGE_SENSITIVE_ACTION_UNIVERSE)))
            or mutation.get("mutatorAssignmentSha256")!=digest(canonical([allowed_projection]))
            or not isinstance(legacy,dict) or set(legacy)!=legacy_fields or legacy.get("roleAssignmentsQuery")!=legacy_role_query or {key:legacy.get(key) for key in legacy_projection}!=legacy_projection
            or legacy.get("projectionSha256")!=digest(canonical(legacy_projection))
            or not topology_shape_ok
            or not isinstance(vnet.get("addressSpacePrefixes"),list) or not vnet["addressSpacePrefixes"]
            or subnet.get("virtualNetworkResourceId")!=vnet.get("resourceId") or subnet.get("resourceId")!=posture.get("virtualNetworkSubnetId")
            or subnet.get("delegations")!=["Microsoft.Web/serverFarms"]
            or subnet.get("serviceEndpoints")!=[{"service":"Microsoft.Storage","provisioningState":"Succeeded"}]
            or subnet.get("routeTableResourceId") not in {None,""} and not str(subnet.get("routeTableResourceId")).startswith(f"/subscriptions/{SUBSCRIPTION}/")
            or subnet.get("networkSecurityGroupResourceId") not in {None,""} and not str(subnet.get("networkSecurityGroupResourceId")).startswith(f"/subscriptions/{SUBSCRIPTION}/")
            or storage_topology.get("resourceId")!=account_scope or storage_topology.get("publicNetworkAccess")!="Enabled"
            or storage_topology.get("allowBlobPublicAccess") is not False or storage_topology.get("defaultAction")!="Deny" or storage_topology.get("bypass")!="None"
            or storage_topology.get("ipRules")!=[] or storage_topology.get("resourceAccessRules")!=[]
            or storage_topology.get("virtualNetworkRules")!=[{"id":subnet.get("resourceId"),"action":"Allow","state":"Succeeded"}]
            or production_topology.get("resourceId")!=production_scope or production_topology.get("virtualNetworkSubnetId")!=subnet.get("resourceId")
            or production_topology.get("outboundVnetRouting")!=outbound_routing
            or bridge_runtime.get("bootstrapReceiptPath")!="evidence/private-release-bridge-runtime-receipt.json"
            or not SHA256.fullmatch(str(bridge_runtime.get("bootstrapReceiptSha256")))):fail("activation-bridge-runtime")
    parse_time(graph_inventory.get("observedAt"),"activation-bridge-resource-graph-observed")
    parse_time(identity_boundaries.get("observedAt"),"activation-identity-boundaries-observed")
    parse_time(legacy.get("observedAt"),"activation-legacy-bridge-observed")
    parse_time(mutation.get("observedAt"),"activation-bridge-mutation-observed")
    parse_time(bridge_runtime.get("observedAt"),"activation-bridge-runtime-observed")
    key_boundary=evidence.get("keyVaultBoundary")
    key_boundary_fields={"vaultResourceId","vaultApiVersion","vaultProjection","vaultProjectionSha256","keyResourceId","keyApiVersion","keyProjection","keyProjectionSha256","keyDataPlaneGetUrl","keyDataPlaneProjection","keyDataPlaneProjectionSha256","minimumRemainingLifetimeSeconds","roleAssignmentsQuery","ownerRoleDefinitionId","allowedNonOwnerSensitiveAssignmentIds","sensitiveActionUniverse","sensitiveActionUniverseSha256","sensitiveAssignmentProjectionSha256","temporaryKeyProvisioningAssignmentIdsPresent","observedAt"}
    vault_scope=key_scope.rsplit("/keys/",1)[0]
    vault_projection=key_boundary.get("vaultProjection") if isinstance(key_boundary,dict) else None
    vault_projection_fields={"id","name","type","location","properties"};vault_properties_fields={"enableRbacAuthorization","enablePurgeProtection","softDeleteRetentionInDays","publicNetworkAccess","networkAcls"};network_acl_fields={"bypass","defaultAction","ipRules","virtualNetworkRules"}
    vault_properties=vault_projection.get("properties") if isinstance(vault_projection,dict) else None
    network_acls=vault_properties.get("networkAcls") if isinstance(vault_properties,dict) else None
    key_projection=key_boundary.get("keyProjection") if isinstance(key_boundary,dict) else None
    key_projection_fields={"id","name","type","properties"};key_properties_fields={"keyUriWithVersion","kty","keySize","keyOps","attributes","releasePolicy"};key_attribute_fields={"enabled","exportable","expiresOn"}
    key_properties=key_projection.get("properties") if isinstance(key_projection,dict) else None
    key_attributes=key_properties.get("attributes") if isinstance(key_properties,dict) else None
    expected_key_uri=f"{activation['signingKeyId']}/{activation['signingKeyVersion']}"
    key_data_url=expected_key_uri+"?api-version=7.4"
    key_data=key_boundary.get("keyDataPlaneProjection") if isinstance(key_boundary,dict) else None
    key_data_fields={"kid","kty","key_ops","n","e","attributes"}
    key_data_attribute_fields={"enabled","nbf","exp","created","updated","recoveryLevel","recoverableDays","exportable"}
    key_data_attributes=key_data.get("attributes") if isinstance(key_data,dict) else None
    owner_definition=f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
    key_assignment_query=f"https://management.azure.com/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
    signer_role=roles["signerKeySign"];signer_assignment_id=signer_role["roleAssignmentResourceId"].lower()
    signer_assignment_projection={"id":signer_assignment_id,"name":signer_assignment_id.rsplit("/",1)[1],"type":"Microsoft.Authorization/roleAssignments","properties":{"principalId":signer_role["principalId"].lower(),"principalType":"ServicePrincipal","roleDefinitionId":signer_role["roleDefinitionResourceId"].lower(),"scope":signer_role["scope"].lower(),"condition":None,"conditionVersion":None,"delegatedManagedIdentityResourceId":None}}
    if (not isinstance(key_boundary,dict) or set(key_boundary)!=key_boundary_fields
            or key_boundary.get("vaultResourceId")!=vault_scope or key_boundary.get("vaultApiVersion")!="2025-05-01"
            or not isinstance(vault_projection,dict) or set(vault_projection)!=vault_projection_fields or vault_projection.get("id")!=vault_scope.lower()
            or vault_projection.get("name")!=FIXED_COORDS["signingVault"] or vault_projection.get("type")!="Microsoft.KeyVault/vaults" or not isinstance(vault_projection.get("location"),str)
            or not isinstance(vault_properties,dict) or set(vault_properties)!=vault_properties_fields or vault_properties.get("enableRbacAuthorization") is not True
            or vault_properties.get("enablePurgeProtection") is not True or vault_properties.get("softDeleteRetentionInDays")!=90
            or vault_properties.get("publicNetworkAccess")!="Enabled" or not isinstance(network_acls,dict) or set(network_acls)!=network_acl_fields
            or network_acls.get("defaultAction")!="Allow" or network_acls.get("bypass") not in {"None","AzureServices"}
            or not isinstance(network_acls.get("ipRules"),list) or not isinstance(network_acls.get("virtualNetworkRules"),list)
            or key_boundary.get("vaultProjectionSha256")!=digest(canonical(vault_projection))
            or key_boundary.get("keyResourceId")!=key_scope or key_boundary.get("keyApiVersion")!="2023-07-01"
            or not isinstance(key_projection,dict) or set(key_projection)!=key_projection_fields or key_projection.get("id")!=key_scope.lower()
            or key_projection.get("name")!=FIXED_COORDS["signingKeyName"] or key_projection.get("type")!="Microsoft.KeyVault/vaults/keys"
            or not isinstance(key_properties,dict) or set(key_properties)!=key_properties_fields or key_properties.get("keyUriWithVersion")!=expected_key_uri
            or key_properties.get("kty")!="RSA" or key_properties.get("keySize")!=3072 or key_properties.get("keyOps")!=["sign","verify"]
            or not isinstance(key_attributes,dict) or set(key_attributes)!=key_attribute_fields or key_attributes.get("enabled") is not True or key_attributes.get("exportable") is not False
            or type(key_attributes.get("expiresOn")) is not int or key_attributes["expiresOn"]<=0 or key_properties.get("releasePolicy") is not None
            or key_boundary.get("keyProjectionSha256")!=digest(canonical(key_projection))
            or key_boundary.get("keyDataPlaneGetUrl")!=key_data_url
            or not isinstance(key_data,dict) or set(key_data)!=key_data_fields or key_data.get("kid")!=expected_key_uri
            or key_data.get("kty")!="RSA" or key_data.get("key_ops")!=["sign","verify"]
            or key_data.get("n")!=activation["signingPublicJwk"]["n"] or key_data.get("e")!=activation["signingPublicJwk"]["e"]
            or not isinstance(key_data_attributes,dict) or set(key_data_attributes)!=key_data_attribute_fields
            or key_data_attributes.get("enabled") is not True or key_data_attributes.get("exportable") is not False
            or any(type(key_data_attributes.get(name)) is not int for name in ("nbf","exp","created","updated","recoverableDays"))
            or not isinstance(key_data_attributes.get("recoveryLevel"),str) or not key_data_attributes["recoveryLevel"]
            or key_data_attributes["exp"]!=key_attributes["expiresOn"]
            or key_boundary.get("keyDataPlaneProjectionSha256")!=digest(canonical(key_data))
            or key_boundary.get("minimumRemainingLifetimeSeconds")!=KEY_RECOVERY_HORIZON_SECONDS
            or key_data_attributes["exp"]<int(parse_time(key_boundary.get("observedAt"),"activation-key-vault-observed").timestamp())+KEY_RECOVERY_HORIZON_SECONDS
            or key_boundary.get("roleAssignmentsQuery")!=key_assignment_query or key_boundary.get("ownerRoleDefinitionId")!=owner_definition
            or key_boundary.get("allowedNonOwnerSensitiveAssignmentIds")!=[signer_assignment_id]
            or key_boundary.get("sensitiveActionUniverse")!=list(KEY_SENSITIVE_ACTION_UNIVERSE)
            or key_boundary.get("sensitiveActionUniverseSha256")!=digest(canonical(list(KEY_SENSITIVE_ACTION_UNIVERSE)))
            or key_boundary.get("sensitiveAssignmentProjectionSha256")!=digest(canonical([signer_assignment_projection]))
            or key_boundary.get("temporaryKeyProvisioningAssignmentIdsPresent")!=[]):fail("activation-key-vault-boundary")
    parse_time(key_boundary.get("observedAt"),"activation-key-vault-observed")
    worm=evidence.get("wormPolicies");worm_fields={"scope","policyResourceId","publicAccess","containerResourceSha256","state","immutabilityPeriodSinceCreationInDays","allowProtectedAppendWrites","allowProtectedAppendWritesAll","etag","resourceSha256","observedAt"}
    worm_scopes={"accepted":registry_scope,"packages":package_scope,"results":result_scope}
    if not isinstance(worm,dict) or set(worm)!=set(worm_scopes):fail("activation-worm-policies")
    for name,scope in worm_scopes.items():
        item=worm[name];policy_id=scope+"/immutabilityPolicies/default"
        if (not isinstance(item,dict) or set(item)!=worm_fields or item.get("scope")!=scope or item.get("policyResourceId")!=policy_id
                or item.get("publicAccess")!="None" or not SHA256.fullmatch(str(item.get("containerResourceSha256")))
                or item.get("state")!="Locked" or type(item.get("immutabilityPeriodSinceCreationInDays")) is not int or item["immutabilityPeriodSinceCreationInDays"]<91
                or item.get("allowProtectedAppendWrites") is not False or item.get("allowProtectedAppendWritesAll") is not False
                or not re.fullmatch(r'"[^"\r\n]+"',str(item.get("etag"))) or not SHA256.fullmatch(str(item.get("resourceSha256")))):fail("activation-worm-policy-"+name)
        parse_time(item.get("observedAt"),"activation-worm-observed")
    deny=evidence.get("publisherAuthorizationDecisions")
    account_scope=f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-paperdesk-rollback-sea-20260808/providers/Microsoft.Storage/storageAccounts/{FIXED_COORDS['packageAccount']}"
    result_scope=account_scope+"/blobServices/default/containers/paperdesk-registry-webjob-results"
    arm=lambda resource,suffix:"https://management.azure.com"+resource+suffix
    blob=lambda container,suffix:f"https://{FIXED_COORDS['packageAccount']}.blob.core.windows.net/{container}{suffix}"
    deny_specs={
        "productionConfigList":("POST",production_scope,arm(production_scope,"/config/appsettings/list?api-version=2025-03-01"),"Microsoft.Web/sites/config/list/action"),
        "productionConfigWrite":("PUT",production_scope,arm(production_scope,"/config/appsettings?api-version=2025-03-01"),"Microsoft.Web/sites/config/write"),
        "productionRestart":("POST",production_scope,arm(production_scope,"/restart?api-version=2025-03-01"),"Microsoft.Web/sites/restart/action"),
        "oneDeployRead":("GET",production_scope,arm(production_scope,"/deployments?api-version=2025-03-01"),"Microsoft.Web/sites/deployments/read"),
        "oneDeployWrite":("PUT",production_scope,arm(production_scope,"/extensions/onedeploy?api-version=2025-03-01"),"Microsoft.Web/sites/extensions/write"),
        "oneDeployPublish":("POST",production_scope,arm(production_scope,"/publish?api-version=2025-03-01"),"Microsoft.Web/sites/publish/Action"),
        "storageListKeys":("POST",account_scope,arm(account_scope,"/listKeys?api-version=2025-06-01"),"Microsoft.Storage/storageAccounts/listKeys/action"),
        "storageContainerWrite":("PUT",package_scope,arm(package_scope,"?api-version=2025-06-01"),"Microsoft.Storage/storageAccounts/blobServices/containers/write"),
        "storageContainerDelete":("DELETE",package_scope,arm(package_scope,"?api-version=2025-06-01"),"Microsoft.Storage/storageAccounts/blobServices/containers/delete"),
        "otherControllerLease":("POST",package_scope,arm(package_scope,"/lease?api-version=2025-06-01"),"Microsoft.Storage/storageAccounts/blobServices/containers/lease/action"),
        "registryBlobList":("GET",registry_scope,blob(FIXED_COORDS["registryContainer"],"?restype=container&comp=list"),"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"),
        "registryBlobRead":("GET",registry_scope,blob(FIXED_COORDS["registryContainer"],"/probe"),"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"),
        "registryBlobWrite":("PUT",registry_scope,blob(FIXED_COORDS["registryContainer"],"/probe"),"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"),
        "resultBlobList":("GET",result_scope,blob("paperdesk-registry-webjob-results","?restype=container&comp=list"),"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"),
        "resultBlobRead":("GET",result_scope,blob("paperdesk-registry-webjob-results","/probe"),"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"),
        "resultBlobWrite":("PUT",result_scope,blob("paperdesk-registry-webjob-results","/probe"),"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"),
        "packageBlobList":("GET",package_scope,blob(FIXED_COORDS["packageContainer"],"?restype=container&comp=list"),"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"),
        "packageBlobRead":("GET",package_scope,blob(FIXED_COORDS["packageContainer"],"/probe"),"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"),
        "packageBlobWrite":("PUT",package_scope,blob(FIXED_COORDS["packageContainer"],"/probe"),"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"),
        "keyVaultSign":("POST",key_scope,activation["signingKeyId"]+"/"+activation["signingKeyVersion"]+"/sign?api-version=7.6","Microsoft.KeyVault/vaults/keys/sign/action"),
    }
    if not isinstance(deny,dict) or set(deny)!=set(deny_specs):fail("activation-publisher-authorization-decisions")
    deny_fields={"principalId","clientId","plane","wouldInvokeMethod","targetResourceId","targetUrl","azureAction","decision","grantingAssignmentIds","inventorySha256","evaluatedAt"}
    publisher_inventory=inventories["publisher"]["effectiveAssignmentSetSha256"]
    for name,(method,target,url,action) in deny_specs.items():
        item=deny[name]
        if (not isinstance(item,dict) or set(item)!=deny_fields or item.get("principalId")!=activation["mailboxPublisherPrincipalId"] or item.get("clientId")!=activation["mailboxPublisherClientId"]
                or item.get("plane")!=("storage-data" if "Blob" in name else "key-vault-data" if name=="keyVaultSign" else "arm-control") or item.get("wouldInvokeMethod")!=method or item.get("targetResourceId")!=target
                or item.get("targetUrl")!=url or item.get("azureAction")!=action or item.get("decision")!="denied" or item.get("grantingAssignmentIds")!=[]
                or item.get("inventorySha256")!=publisher_inventory):fail("activation-publisher-authorization-decision-"+name)
        parse_time(item.get("evaluatedAt"),"activation-publisher-authorization-evaluated")
    key_id=activation["signingKeyId"]; version=activation["signingKeyVersion"]
    expected_key_id="https://kv-mds-sea-9c4e0d0d.vault.azure.net/keys/paperdesk-release-result-signing"
    if key_id!=expected_key_id or not isinstance(version,str) or not re.fullmatch(r"[0-9a-f]{32}",version): fail("activation-key")
    jwk=activation["signingPublicJwk"]
    if (not isinstance(jwk,dict) or set(jwk)!={"kid","kty","n","e","key_ops"} or jwk.get("kid")!=key_id+"/"+version
            or jwk.get("kty")!="RSA" or jwk.get("e")!="AQAB" or not isinstance(jwk.get("n"),str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{384,1024}",jwk["n"]) or jwk.get("key_ops")!=["sign","verify"]): fail("activation-jwk")
    return Activation(runtime_workflow_sha,rg,activation["tenantId"],activation["mailboxPublisherClientId"],activation["mailboxPublisherPrincipalId"],activation["bridgeManagedIdentityClientId"],activation["bridgeManagedIdentityPrincipalId"],activation["registryWriterManagedIdentityClientId"],activation["registryWriterManagedIdentityPrincipalId"],activation["registryReaderManagedIdentityClientId"],activation["registryReaderManagedIdentityPrincipalId"],activation["signerManagedIdentityClientId"],activation["signerManagedIdentityPrincipalId"],key_id,version,jwk,observed_bridge_package_sha256,activation["productionActivationManagedIdentityClientId"],activation["productionActivationManagedIdentityPrincipalId"],activation["productionSystemIdentityPrincipalId"],dict(fence),dict(evidence))

def validate_bridge_runtime_receipt(receipt,activation):
    if not isinstance(activation,Activation):fail("bridge-runtime-receipt-activation")
    runtime=activation.provisioning_evidence["bridgeRuntime"]
    fields={"schemaVersion","status","bridgeResourceId","package","packageReaderIdentityResourceId","criticalAppSettingsSha256","sitePostureSha256","resourceGraphAttachmentSha256","identityAssignmentBoundariesSha256","bridgeMutationBoundarySha256","legacyBridgeRetirementSha256","networkTopologySha256","packagesWormPolicySha256","publisherBridgeControllerAssignmentId","observedAt"}
    package_fields={"blob","sha256","size","etag","versionId","url"}
    package=receipt.get("package") if isinstance(receipt,dict) else None
    expected_package={"blob":runtime["packageBlob"],"sha256":runtime["packageSha256"],"size":runtime["packageSize"],"etag":runtime["packageEtag"],"versionId":runtime["packageVersionId"],"url":runtime["packageUrl"]}
    if (not isinstance(receipt,dict) or set(receipt)!=fields or receipt.get("schemaVersion")!=1 or receipt.get("status")!="bridge-runtime-provisioned"
            or receipt.get("bridgeResourceId")!=runtime["siteResourceId"]
            or not isinstance(package,dict) or set(package)!=package_fields or package!=expected_package
            or receipt.get("packageReaderIdentityResourceId")!=runtime["packageReaderIdentityResourceId"]
            or receipt.get("criticalAppSettingsSha256")!=runtime["criticalAppSettingsSha256"]
            or receipt.get("sitePostureSha256")!=runtime["sitePostureSha256"]
            or receipt.get("resourceGraphAttachmentSha256")!=runtime["resourceGraphAttachmentInventory"]["projectionSha256"]
            or receipt.get("identityAssignmentBoundariesSha256")!=digest(canonical(runtime["identityAssignmentBoundaries"]))
            or receipt.get("bridgeMutationBoundarySha256")!=digest(canonical(runtime["bridgeMutationBoundary"]))
            or receipt.get("legacyBridgeRetirementSha256")!=digest(canonical(runtime["legacyBridgeRetirement"]))
            or receipt.get("networkTopologySha256")!=digest(canonical(runtime["networkTopology"]))
            or receipt.get("packagesWormPolicySha256")!=digest(canonical(activation.provisioning_evidence["wormPolicies"]["packages"]))
            or receipt.get("publisherBridgeControllerAssignmentId")!=activation.provisioning_evidence["roles"]["publisherBridgeController"]["roleAssignmentResourceId"]
            or digest(canonical(receipt))!=runtime["bootstrapReceiptSha256"]):fail("bridge-runtime-receipt")
    parse_time(receipt.get("observedAt"),"bridge-runtime-receipt-observed")
    return dict(receipt)

def validate_live_signing_key(projection,activation,*,now):
    """Validate the exact versioned Key Vault data-plane public-key response.

    The publisher's ARM key read does not expose the public modulus.  The
    private bridge therefore performs one versioned ``Get Key`` using its
    dedicated read-only key role before any release storage or production
    action.  The signing UAMI remains sign-only.
    """
    if not isinstance(activation,Activation):fail("live-key-activation")
    source=activation.provisioning_evidence["keyVaultBoundary"]
    expected=source["keyDataPlaneProjection"]
    if (not isinstance(projection,dict) or projection!=expected
            or digest(canonical(projection))!=source["keyDataPlaneProjectionSha256"]):fail("live-key-projection")
    attributes=projection.get("attributes")
    if (not isinstance(attributes,dict) or attributes.get("enabled") is not True or attributes.get("exportable") is not False
            or type(attributes.get("exp")) is not int or attributes["exp"]<int(now.timestamp())+source["minimumRemainingLifetimeSeconds"]):fail("live-key-expiry")
    jwk=activation.signing_public_jwk
    if {key:projection.get(key) for key in ("kid","kty","n","e","key_ops")}!=jwk:fail("live-key-jwk")
    return dict(projection)

def load_activation(path,*,runtime_workflow_sha,observed_bridge_package_sha256,provisioning_evidence_path=None):
    try: doc=json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception: fail("activation-contract")
    if provisioning_evidence_path is None:fail("activation-provisioning-evidence-required")
    try:evidence=json.loads(Path(provisioning_evidence_path).read_text(encoding="utf-8"))
    except Exception:fail("activation-provisioning-evidence")
    return load_activation_document(doc,runtime_workflow_sha=runtime_workflow_sha,observed_bridge_package_sha256=observed_bridge_package_sha256,provisioning_evidence=evidence)

DESCRIPTOR_FIELDS={"blob","sha256","size","etag","versionId"}
REQUEST_FIELDS={"schemaVersion","requestType","operation","repositoryId","ownerId","controlWorkflowSha","sourceSha","sourceRunId","sourceRunAttempt","artifactId","artifactSha256","artifactMember","artifactMemberSha256","acceptanceRunId","acceptanceRunAttempt","logicalOperationId","nonce","issuedAt","expiresAt","acceptedBaseline","pendingRelease","consumedMarker","rollbackPreparation","activationPlan","activationProof"}
OPERATIONS={"bootstrap-prepare","bootstrap-consume","prepare-candidate","consume-candidate","abort-candidate","persist-accepted-release","prepare-rollback","complete-rollback"}
TRANSIENT_CONTROL_FIELDS={"schemaVersion","state","repository","repositoryId","ownerId","callerSha","workflowId","workflowName","workflowPath","workflowRef","event","headBranch","runId","runAttempt","operation","sourceSha","requestName","originalSettingsSha256","githubTokenSha256","provisioningEvidenceSha256","bridgeRuntimeReceiptSha256","acquiredAt","expiresAt"}
TRANSIENT_LIFETIME_SECONDS=7200

def validate_transient_control(value,*,raw,github_token,now,activation):
    """Bind one bridge start to one current controller request and token.

    The control record is not an Azure mutex.  It is the exact fail-closed handoff
    written by the caller-repository serialized workflow.  The bridge processes
    only this request; other authenticated mailbox entries remain inert.
    """
    if not isinstance(activation,Activation):fail("transient-control-activation")
    try:owner_policy=bridge_owner_policy(value.get("operation")) if isinstance(value,dict) else None
    except MailboxError:owner_policy=None
    if (not isinstance(value,dict) or set(value)!=TRANSIENT_CONTROL_FIELDS or not isinstance(owner_policy,dict)
            or value.get("schemaVersion")!=1 or value.get("state")!="transient"
            or value.get("repository")!=OWNER_REPOSITORY or value.get("repositoryId")!=OWNER_REPOSITORY_ID
            or value.get("ownerId")!=OWNER_ID
            or not SHA40.fullmatch(str(value.get("callerSha")))
            or value.get("workflowId")!=owner_policy.get("workflowId") or value.get("workflowName")!=owner_policy.get("workflowName")
            or value.get("workflowPath")!=owner_policy.get("workflowPath") or value.get("workflowRef")!=owner_policy.get("workflowRef")
            or value.get("event") not in owner_policy.get("events",set()) or value.get("headBranch")!="main"
            or not POSITIVE.fullmatch(str(value.get("runId"))) or not POSITIVE.fullmatch(str(value.get("runAttempt")))
            or value.get("operation") not in OPERATIONS or not SHA40.fullmatch(str(value.get("sourceSha")))
            or not NAME.fullmatch(str(value.get("requestName"))) or not value["requestName"].startswith("pdreq-")
            or not SHA256.fullmatch(str(value.get("originalSettingsSha256")))
            or not SHA256.fullmatch(str(value.get("githubTokenSha256")))
            or value.get("provisioningEvidenceSha256")!=digest(canonical(activation.provisioning_evidence))
            or value.get("bridgeRuntimeReceiptSha256")!=activation.provisioning_evidence["bridgeRuntime"]["bootstrapReceiptSha256"]): fail("transient-control")
    if not isinstance(raw,str) or canonical(value).decode()!=raw: fail("transient-control-canonical")
    if (not isinstance(github_token,str) or len(github_token)<20
            or digest(github_token.encode())!=value["githubTokenSha256"]): fail("transient-control-token")
    if value["sourceSha"]=="" or value["operation"]=="": fail("transient-control-activation")
    acquired=parse_time(value["acquiredAt"],"transient-control-acquired")
    expires=parse_time(value["expiresAt"],"transient-control-expires")
    if (expires<=acquired or (expires-acquired).total_seconds()!=TRANSIENT_LIFETIME_SECONDS
            or now<acquired-dt.timedelta(seconds=30) or now>expires): fail("transient-control-time")
    return dict(value)

def validate_descriptor(item,label,*,prefix=None,suffix=None):
    if not isinstance(item,dict) or set(item)!=DESCRIPTOR_FIELDS: fail(label)
    if not SHA256.fullmatch(str(item["sha256"])) or type(item["size"]) is not int or item["size"]<1: fail(label)
    blob=item.get("blob"); path=PurePosixPath(blob) if isinstance(blob,str) else None
    if path is None or path.is_absolute() or any(part in {"",".",".."} for part in path.parts): fail(label)
    if prefix is not None and not blob.startswith(prefix): fail(label)
    if suffix is not None and not blob.endswith(suffix): fail(label)
    if not re.fullmatch(r'"[^"\r\n]+"',str(item.get("etag"))) or not re.fullmatch(r"[A-Za-z0-9._=:+/-]{1,256}",str(item.get("versionId"))): fail(label)
    return dict(item)

def _validate_probe_item(value,label):
    if (not isinstance(value,dict) or set(value)!={"status","bodySha256","ok","code"}
            or type(value["status"]) is not int or value["status"] not in {200,403,503}
            or not SHA256.fullmatch(str(value["bodySha256"])) or type(value["ok"]) is not bool
            or not isinstance(value["code"],str) or len(value["code"])>128): fail(label)

def validate_activation_proof(proof,request):
    fields={"schemaVersion","phase","sourceSha","runtimeRelease","index","oneDeployInvariant","live","ready","appHealth","securityInfo","observedAt"}
    if not isinstance(proof,dict) or set(proof)!=fields or proof["schemaVersion"]!=1 or proof["phase"] not in {"bootstrap","candidate"}: fail("request-activation-proof")
    if request["operation"]!="abort-candidate" and proof["sourceSha"]!=request["sourceSha"]: fail("request-activation-proof")
    runtime=proof["runtimeRelease"]
    if not isinstance(runtime,dict) or set(runtime)!={"status","value","bodySha256"} or type(runtime["status"]) is not int or runtime["status"] not in {200,403} or not isinstance(runtime["value"],str) or not SHA256.fullmatch(str(runtime["bodySha256"])): fail("request-runtime-proof")
    index=proof["index"]
    if not isinstance(index,dict) or set(index)!={"status","sha256","size"} or index["status"]!=200 or not SHA256.fullmatch(str(index["sha256"])) or type(index["size"]) is not int or index["size"]<1: fail("request-index-proof")
    one=proof["oneDeployInvariant"]
    one_fields={"historicalActiveDeploymentId","historicalActiveDeployment","collectionSemanticProjectionSha256","propertyIdSetSha256","deploymentCount"}
    active=one.get("historicalActiveDeployment") if isinstance(one,dict) else None
    if (not isinstance(one,dict) or set(one)!=one_fields or one!={**BOOTSTRAP_BASELINE["oneDeployInvariant"],"historicalActiveDeployment":{"id":BOOTSTRAP_BASELINE["oneDeployInvariant"]["historicalActiveDeploymentId"],"status":4,"complete":True,"deployer":"OneDeploy"}}
            or not isinstance(active,dict) or set(active)!={"id","status","complete","deployer"}):fail("request-onedeploy-invariant")
    for field in ("live","ready","appHealth","securityInfo"): _validate_probe_item(proof[field],"request-"+field+"-proof")
    parse_time(proof["observedAt"],"request-proof-observed")
    if proof["phase"]=="bootstrap" and request["operation"]=="bootstrap-consume":
        if (request["operation"]!="bootstrap-consume" or proof["sourceSha"]!=BOOTSTRAP_BASELINE["sourceSha"]
                or runtime!={"status":403,"value":"api-route-unmapped","bodySha256":runtime["bodySha256"]}
                or index["sha256"]!=BOOTSTRAP_BASELINE["servedIndexSha256"]
                or proof["live"]["status"]!=200 or proof["live"]["ok"] is not True
                or proof["ready"]["status"]!=BOOTSTRAP_BASELINE["readinessHttpStatus"] or proof["ready"]["code"]!=BOOTSTRAP_BASELINE["readinessCode"]
                or proof["appHealth"]["status"]!=200 or proof["appHealth"]["ok"] is not True
                or proof["securityInfo"]["status"]!=200 or proof["securityInfo"]["ok"] is not True): fail("request-bootstrap-proof")
    elif request["operation"]=="consume-candidate":
        if (request["operation"]!="consume-candidate" or runtime["status"]!=200 or runtime["value"]!=request["sourceSha"]
                or any(proof[field]["status"]!=200 or proof[field]["ok"] is not True for field in ("live","ready","appHealth","securityInfo"))): fail("request-candidate-proof")
    elif request["operation"] in {"abort-candidate","complete-rollback"}:
        if proof["phase"]=="candidate":
            if runtime["status"]!=200 or runtime["value"]!=proof["sourceSha"] or any(proof[field]["status"]!=200 or proof[field]["ok"] is not True for field in ("live","ready","appHealth","securityInfo")): fail("request-abort-proof")
        elif (runtime["status"]!=403 or runtime["value"]!="api-route-unmapped" or proof["ready"]["status"]!=BOOTSTRAP_BASELINE["readinessHttpStatus"] or proof["ready"]["code"]!=BOOTSTRAP_BASELINE["readinessCode"]): fail("request-abort-proof")
    else: fail("request-activation-proof-operation")
    return dict(proof)

def validate_activation_fence(value,label="request-activation-fence"):
    if (not isinstance(value,dict) or set(value)!={"blob","leaseId","stateVersion","release","preSettingsSha256","desiredSettingsSha256","etag","operation","sourceSha"}
            or value["blob"]!=FIXED_COORDS["activationFenceBlob"] or not GUID.fullmatch(str(value["leaseId"]))
            or not POSITIVE.fullmatch(str(value["stateVersion"])) or not SHA256.fullmatch(str(value["preSettingsSha256"]))
            or not SHA256.fullmatch(str(value["desiredSettingsSha256"])) or value["desiredSettingsSha256"]==value["preSettingsSha256"]
            or not re.fullmatch(r'"[^"\r\n]+"',str(value["etag"])) or value["operation"] not in {"candidate","rollback"}
            or not SHA40.fullmatch(str(value["sourceSha"]))): fail(label)
    validate_descriptor(value.get("release"),label+"-release")
    return dict(value)

def validate_activation_plan(value,label="request-activation-plan"):
    fields={"blob","operation","sourceSha","release","preSettingsSha256","desiredSettingsSha256"}
    if (not isinstance(value,dict) or set(value)!=fields or value.get("blob")!=FIXED_COORDS["activationFenceBlob"]
            or value.get("operation") not in {"candidate","rollback"} or not SHA40.fullmatch(str(value.get("sourceSha")))
            or not SHA256.fullmatch(str(value.get("preSettingsSha256"))) or not SHA256.fullmatch(str(value.get("desiredSettingsSha256")))
            or value.get("preSettingsSha256")==value.get("desiredSettingsSha256")):fail(label)
    validate_descriptor(value.get("release"),label+"-release")
    return dict(value)

def activation_plan_from_fence(fence):
    fence=validate_activation_fence(fence)
    return {"blob":fence["blob"],"operation":fence["operation"],"sourceSha":fence["sourceSha"],"release":dict(fence["release"]),
            "preSettingsSha256":fence["preSettingsSha256"],"desiredSettingsSha256":fence["desiredSettingsSha256"]}

def validate_request(value,*,now):
    if not isinstance(value,dict) or set(value)!=REQUEST_FIELDS: fail("request-fields")
    if value["schemaVersion"]!=1 or value["requestType"]!="paperdesk-private-release-request": fail("request-schema")
    if value["operation"] not in OPERATIONS: fail("request-operation")
    for key in ("sourceSha","controlWorkflowSha"):
        if not isinstance(value[key],str) or not SHA40.fullmatch(value[key]): fail("request-"+key)
    for key in ("sourceRunId","sourceRunAttempt","acceptanceRunId","acceptanceRunAttempt","repositoryId","ownerId"):
        if not isinstance(value[key],str) or not POSITIVE.fullmatch(value[key]): fail("request-"+key)
    if value["operation"] in {"prepare-rollback","complete-rollback"}:
        if not SHA256.fullmatch(str(value["logicalOperationId"])):fail("request-logical-operation")
    elif value["logicalOperationId"] is not None:fail("request-unexpected-logical-operation")
    artifact_ops={"bootstrap-prepare","prepare-candidate","persist-accepted-release"}
    if value["operation"] in artifact_ops:
        if (not isinstance(value["artifactId"],str) or not POSITIVE.fullmatch(value["artifactId"]) or not SHA256.fullmatch(str(value["artifactSha256"]))
                or not isinstance(value["artifactMember"],str) or len(value["artifactMember"])>256 or PurePosixPath(value["artifactMember"]).name!=value["artifactMember"]
                or not SHA256.fullmatch(str(value["artifactMemberSha256"]))): fail("request-artifact")
    elif any(value[field]!="" for field in ("artifactId","artifactSha256","artifactMember","artifactMemberSha256")): fail("request-unexpected-artifact")
    if not NONCE.fullmatch(str(value["nonce"])): fail("request-digest-nonce")
    accepted_ops={"bootstrap-consume","prepare-candidate","consume-candidate","abort-candidate","prepare-rollback","complete-rollback"}
    pending_ops={"consume-candidate","abort-candidate","persist-accepted-release"}
    consumed_ops={"persist-accepted-release"}
    if value["operation"] in accepted_ops: validate_descriptor(value["acceptedBaseline"],"request-accepted-baseline",prefix="v2/accepted/",suffix="/manifest.json")
    elif value["acceptedBaseline"] is not None: fail("request-unexpected-accepted-baseline")
    if value["operation"] in pending_ops: validate_descriptor(value["pendingRelease"],"request-pending-release",prefix=f"v2/pending/{value['sourceSha']}/",suffix="/manifest.json")
    elif value["pendingRelease"] is not None: fail("request-unexpected-pending-release")
    if value["operation"] in consumed_ops: validate_descriptor(value["consumedMarker"],"request-consumed-marker",prefix=f"v2/pending/{value['sourceSha']}/",suffix="/consumed.json")
    elif value["consumedMarker"] is not None: fail("request-unexpected-consumed-marker")
    if value["operation"]=="complete-rollback":validate_descriptor(value["rollbackPreparation"],"request-rollback-preparation",prefix=f"v2/rollback/{value['sourceSha']}/",suffix="/manifest.json")
    elif value["rollbackPreparation"] is not None:fail("request-unexpected-rollback-preparation")
    # Live proof is produced inside the private bridge by the dedicated
    # production-activation identity.  The publisher runner may not supply it.
    if value["activationProof"] is not None: fail("request-external-activation-proof")
    if value["operation"] in {"consume-candidate","abort-candidate","complete-rollback"}:
        plan=validate_activation_plan(value["activationPlan"])
        expected_operation="rollback" if value["operation"]=="complete-rollback" else "candidate"
        expected_release=value["rollbackPreparation"] if value["operation"]=="complete-rollback" else value["pendingRelease"]
        if plan["operation"]!=expected_operation or plan["sourceSha"]!=value["sourceSha"] or plan["release"]!=expected_release:fail("request-activation-plan-binding")
    elif value["activationPlan"] is not None: fail("request-unexpected-activation-plan")
    if value["operation"] in {"bootstrap-prepare","bootstrap-consume"}:
        for field in ("sourceSha","repositoryId","ownerId","sourceRunId","sourceRunAttempt"):
            if value[field]!=BOOTSTRAP_BASELINE[field]: fail("request-bootstrap-coordinate")
        if value["operation"]=="bootstrap-prepare":
            for field in ("artifactId","artifactSha256","artifactMember","artifactMemberSha256"):
                if value[field]!=BOOTSTRAP_BASELINE[field]: fail("request-bootstrap-artifact")
    issued=parse_time(value["issuedAt"],"request-issued"); expires=parse_time(value["expiresAt"],"request-expires")
    if expires<=issued or (expires-issued).total_seconds()>900 or now<issued-dt.timedelta(seconds=30) or now>expires: fail("request-time")
    raw=canonical(value)
    if len(raw)>MAX_REQUEST: fail("request-size")
    return dict(value),raw,digest(raw)

RESULT_FIELDS={"schemaVersion","resultType","status","requestSha256","operation","nonce","controlWorkflowSha","sourceSha","webJobHistoryId","webJobRunId","records","metadata","observedAt"}
RESULT_RECORD_FIELDS={"claim","result","manifest","deploymentBundle","acceptedBaseline","pendingRelease","consumedMarker","terminalMarker","cleanupObligation"}
def validate_result(value,request):
    if not isinstance(value,dict) or set(value)!=RESULT_FIELDS: fail("result-fields")
    if value["schemaVersion"]!=1 or value["resultType"]!="paperdesk-private-release-result" or value["status"] not in {"complete","indeterminate"}: fail("result-schema")
    req_raw=canonical(request)
    if value["requestSha256"]!=digest(req_raw) or value["operation"]!=request["operation"] or value["nonce"]!=request["nonce"] or value["controlWorkflowSha"]!=request["controlWorkflowSha"] or value["sourceSha"]!=request["sourceSha"]: fail("result-request-binding")
    for field in ("webJobHistoryId","webJobRunId"):
        if not isinstance(value[field],str) or not re.fullmatch(r"[A-Za-z0-9._:/()-]{1,1024}",value[field]): fail("result-"+field)
    records=value["records"]
    if not isinstance(records,dict) or set(records)!=RESULT_RECORD_FIELDS: fail("result-records")
    for field,item in records.items():
        if item is not None: validate_descriptor(item,"result-"+field)
    if records.get("cleanupObligation") is not None:
        validate_descriptor(records["cleanupObligation"],"result-cleanup-obligation",prefix=f"v2/cleanup-obligations/{request['sourceSha']}/",suffix=".json")
    metadata=value["metadata"]
    required={
        "bootstrap-prepare":{"claim","result","manifest","deploymentBundle","acceptedBaseline"},
        "bootstrap-consume":{"claim","result","manifest","acceptedBaseline","consumedMarker"},
        "prepare-candidate":{"claim","result","manifest","deploymentBundle","acceptedBaseline","pendingRelease"},
        "consume-candidate":{"claim","result","manifest","acceptedBaseline","pendingRelease","consumedMarker"},
        "abort-candidate":{"claim","result","manifest","acceptedBaseline","pendingRelease"},
        "complete-rollback":{"claim","result","manifest","acceptedBaseline","terminalMarker"},
        "persist-accepted-release":{"claim","result","manifest","deploymentBundle","acceptedBaseline","pendingRelease","consumedMarker"},
        "prepare-rollback":{"claim","result","manifest","deploymentBundle","acceptedBaseline"},
    }[request["operation"]]
    if request["operation"]=="prepare-candidate" and isinstance(metadata,dict) and metadata.get("terminalState")=="consumed":required=set(required)|{"consumedMarker","cleanupObligation"}
    if request["operation"]=="prepare-rollback" and isinstance(metadata,dict) and metadata.get("terminalState")=="completed":required=set(required)|{"terminalMarker","cleanupObligation"}
    if request["operation"] in {"bootstrap-consume","consume-candidate","abort-candidate","persist-accepted-release","complete-rollback"}:required=set(required)|{"cleanupObligation"}
    if request["operation"]=="consume-candidate" and isinstance(metadata,dict) and metadata.get("activationStatus")=="aborted":required={"claim","result","manifest","acceptedBaseline","pendingRelease","cleanupObligation"}
    if {key for key,item in records.items() if item is not None}!=required: fail("result-record-set")
    if not isinstance(metadata,dict) or metadata.get("schemaVersion")!=1 or metadata.get("operation")!=request["operation"]: fail("result-metadata")
    if request["operation"]=="prepare-candidate":
        terminal=metadata.get("terminalState")
        if terminal not in {"pending","consumed"}:fail("result-candidate-terminal")
        plan=validate_activation_plan(metadata.get("activationPlan"),"result-candidate-plan")
        if plan["operation"]!="candidate" or plan["sourceSha"]!=request["sourceSha"] or plan["release"]!=records["pendingRelease"]:fail("result-candidate-plan")
        if terminal=="pending":
            if metadata.get("terminalActivationFence") is not None or metadata.get("terminalActivationProof") is not None:fail("result-candidate-terminal")
        else:
            validate_activation_fence(metadata.get("terminalActivationFence"),"result-candidate-terminal-fence")
            if activation_plan_from_fence(metadata["terminalActivationFence"])!=plan:fail("result-candidate-terminal-fence")
            replay=dict(request);replay.update({"operation":"consume-candidate","artifactId":"","artifactSha256":"","artifactMember":"","artifactMemberSha256":"","pendingRelease":records["pendingRelease"],"activationPlan":plan,"activationProof":metadata.get("terminalActivationProof")})
            validate_activation_proof(metadata.get("terminalActivationProof"),replay)
    if request["operation"]=="prepare-rollback":
        terminal=metadata.get("terminalState")
        if terminal not in {"pending","completed"}:fail("result-rollback-terminal")
        plan=validate_activation_plan(metadata.get("activationPlan"),"result-rollback-plan")
        if plan["operation"]!="rollback" or plan["sourceSha"]!=request["sourceSha"] or plan["release"]!=records["manifest"]:fail("result-rollback-plan")
        if terminal=="pending":
            if metadata.get("terminalActivationFence") is not None or metadata.get("terminalActivationProof") is not None:fail("result-rollback-terminal")
        else:
            validate_activation_fence(metadata.get("terminalActivationFence"),"result-rollback-terminal-fence")
            if activation_plan_from_fence(metadata["terminalActivationFence"])!=plan:fail("result-rollback-terminal-fence")
            replay=dict(request);replay.update({"operation":"complete-rollback","artifactId":"","artifactSha256":"","artifactMember":"","artifactMemberSha256":"","rollbackPreparation":records["manifest"],"activationPlan":plan,"activationProof":metadata.get("terminalActivationProof")})
            validate_activation_proof(metadata.get("terminalActivationProof"),replay)
    if request["operation"]=="consume-candidate":
        status=metadata.get("activationStatus")
        if status not in {"consumed","aborted"}:fail("result-candidate-activation-status")
    parse_time(value["observedAt"],"result-observed")
    raw=canonical(value)
    if len(raw)>MAX_RESULT: fail("result-size")
    return raw

def _mgf1(seed,length):
    return b"".join(hashlib.sha256(seed+i.to_bytes(4,"big")).digest() for i in range((length+31)//32))[:length]
def verify_ps256(message,signature,jwk,expected_kid):
    if (not isinstance(jwk,dict) or set(jwk)!={"kty","kid","n","e","key_ops"}
            or jwk.get("kty")!="RSA" or jwk.get("key_ops")!=["sign","verify"]
            or jwk.get("kid")!=expected_kid): fail("jwk")
    n=int.from_bytes(b64u_decode(jwk["n"],"jwk-n"),"big"); e=int.from_bytes(b64u_decode(jwk["e"],"jwk-e"),"big")
    sig=b64u_decode(signature,"signature"); em_len=(n.bit_length()-1+7)//8
    if len(sig)!=(n.bit_length()+7)//8 or len(sig)>em_len: fail("signature-size")
    em=pow(int.from_bytes(sig,"big"),e,n).to_bytes(em_len,"big"); hlen=32
    if len(em)<2*hlen+2 or em[-1]!=0xbc: fail("signature")
    masked,observed_h=em[:-(hlen+1)],em[-(hlen+1):-1]; unused=8*em_len-(n.bit_length()-1)
    if unused and masked[0]>>(8-unused): fail("signature")
    db=bytes(a^b for a,b in zip(masked,_mgf1(observed_h,len(masked))))
    if unused: db=bytes([db[0]& (0xff>>unused)])+db[1:]
    salt_index=len(db)-hlen
    if db[:salt_index-1]!=b"\0"*(salt_index-1) or db[salt_index-1]!=1: fail("signature")
    expected=hashlib.sha256(b"\0"*8+hashlib.sha256(message).digest()+db[salt_index:]).digest()
    if observed_h!=expected: fail("signature")

def verify_signed_result(envelope,request,*,expected_key_id,expected_key_version,jwk):
    if not isinstance(envelope,dict) or set(envelope)!={"result","signature"}: fail("signed-result-fields")
    signing=envelope["signature"]
    if (not isinstance(signing,dict) or set(signing)!={"algorithm","keyId","keyVersion","value"}
            or signing.get("algorithm")!="PS256" or signing.get("keyId")!=expected_key_id
            or signing.get("keyVersion")!=expected_key_version): fail("signed-result-key")
    raw=validate_result(envelope["result"],request)
    verify_ps256(raw,signing.get("value"),jwk,expected_key_id+"/"+expected_key_version)
    return envelope["result"]

@dataclasses.dataclass(frozen=True)
class Response: status:int; url:str; body:bytes; headers:Mapping[str,str]
class MailboxClient:
    def __init__(self,rg,transport,request_creator=None,result_creator=None):
        if not isinstance(rg,str) or not re.fullmatch(r"[A-Za-z0-9._()-]{1,90}",rg): fail("mailbox-rg")
        for value in (request_creator,result_creator):
            if value is not None and not GUID.fullmatch(value): fail("mailbox-creator")
        self.rg=rg; self.transport=transport; self.request_creator=request_creator; self.result_creator=result_creator
    def url(self,name):
        if not NAME.fullmatch(name): fail("mailbox-name")
        return f"https://management.azure.com/subscriptions/{SUBSCRIPTION}/resourcegroups/{self.rg}/providers/Microsoft.Resources/deployments/{name}?api-version={API}"
    def put_create(self,name,envelope):
        expected=self.request_creator if name.startswith("pdreq-") else self.result_creator
        if expected is None: fail("mailbox-creator-required")
        body=canonical({"properties":{"mode":"Incremental","template":{"$schema":"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#","contentVersion":"1.0.0.0","parameters":{},"resources":[],"outputs":{"envelope":{"type":"object","value":envelope}}},"parameters":{}}})
        # ARM deployment CreateOrUpdate has no conditional-create header. A
        # fresh 128-bit request nonce makes the name unique; only HTTP 201 plus
        # exact readback and unchanged systemData is accepted. HTTP 200 is an
        # update and is always rejected.
        response=self.transport("PUT",self.url(name),{"Content-Type":"application/json"},body)
        if response.status!=201: fail("mailbox-create")
        if canonical(self.get(name))!=canonical(envelope): fail("mailbox-create-readback")
    def put_create_or_read_exact(self,name,envelope):
        """Recover an exact unique write after a lost HTTP response.

        This is not conditional ARM creation.  The bridge first accepts an
        existing resource only when immutable systemData and exact bytes match;
        otherwise it still requires a fresh HTTP 201 plus exact readback.
        """
        existing=self.get_optional(name)
        if existing is not None:
            if canonical(existing)!=canonical(envelope):fail("mailbox-existing-drift")
            return
        error=None
        try:self.put_create(name,envelope);return
        except MailboxError as exc:error=exc
        existing=self.get_optional(name)
        if existing is not None and canonical(existing)==canonical(envelope):return
        if existing is not None:fail("mailbox-existing-drift")
        raise error
    def _decode_get(self,name,response):
        if response.status!=200 or len(response.body)>MAX_RESULT*2: fail("mailbox-get")
        try: doc=json.loads(response.body)
        except Exception: fail("mailbox-json")
        expected_id=f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{self.rg}/providers/Microsoft.Resources/deployments/{name}"
        if doc.get("id")!=expected_id or doc.get("name")!=name or doc.get("type")!="Microsoft.Resources/deployments":fail("mailbox-resource-binding")
        outputs=doc.get("properties",{}).get("outputs",{})
        if set(outputs)!={"envelope"} or outputs["envelope"].get("type")!="Object": fail("mailbox-output")
        expected=self.request_creator if name.startswith("pdreq-") else self.result_creator
        system=doc.get("systemData"); state=doc.get("properties",{}).get("provisioningState")
        if expected is None or (not isinstance(system,dict) or system.get("createdBy")!=expected or system.get("lastModifiedBy")!=expected or system.get("createdByType") not in {"Application","ManagedIdentity"} or system.get("lastModifiedByType")!=system.get("createdByType") or system.get("createdAt")!=system.get("lastModifiedAt") or state!="Succeeded"): fail("mailbox-system-data")
        return outputs["envelope"].get("value")
    def get(self,name):
        response=self.transport("GET",self.url(name),{"Accept":"application/json"},None)
        return self._decode_get(name,response)
    def get_optional(self,name):
        response=self.transport("GET",self.url(name),{"Accept":"application/json"},None)
        if response.status==404:return None
        return self._decode_get(name,response)
    def delete(self,name):
        response=self.transport("DELETE",self.url(name),{"If-Match":"*"},None)
        if response.status not in {200,202,204,404}: fail("mailbox-delete")
    def list(self):
        url=f"https://management.azure.com/subscriptions/{SUBSCRIPTION}/resourcegroups/{self.rg}/providers/Microsoft.Resources/deployments?api-version={API}"
        response=self.transport("GET",url,{"Accept":"application/json"},None)
        if response.status!=200 or len(response.body)>MAX_RESULT*2000: fail("mailbox-list")
        try: doc=json.loads(response.body)
        except Exception: fail("mailbox-list-json")
        if not isinstance(doc,dict) or set(doc)-{"value"} or not isinstance(doc.get("value"),list): fail("mailbox-list-shape")
        return doc["value"]

def cleanup_mailbox(client,*,retain_pairs=200):
    if type(retain_pairs) is not int or retain_pairs<1 or retain_pairs>1000: fail("cleanup-retention")
    pairs={}
    for item in client.list():
        if not isinstance(item,dict) or not isinstance(item.get("name"),str): fail("cleanup-item")
        name=item["name"]
        match=NAME.fullmatch(name)
        if not match: continue
        parts=name.split("-"); key="-".join(parts[2:])
        timestamp=item.get("properties",{}).get("timestamp")
        if not isinstance(timestamp,str): fail("cleanup-timestamp")
        parse_arm_time(timestamp,"cleanup-timestamp")
        pairs.setdefault(key,[]).append((name,timestamp))
    ordered=sorted(pairs.items(),key=lambda pair:max(x[1] for x in pair[1]),reverse=True)
    removed=[]
    for _,members in ordered[retain_pairs:]:
        for name,_ in members:
            client.delete(name); removed.append(name)
    return removed

class WebJobClient:
    def __init__(self,resource_group,app,job,transport):
        for value,label in ((resource_group,"webjob-rg"),(app,"webjob-app"),(job,"webjob-name")):
            if not isinstance(value,str) or not re.fullmatch(r"[A-Za-z0-9._()-]{1,90}",value): fail(label)
        self.resource_group=resource_group; self.app=app; self.job=job; self.transport=transport
        self.base=(f"https://management.azure.com/subscriptions/{SUBSCRIPTION}/resourceGroups/{resource_group}"
                   f"/providers/Microsoft.Web/sites/{app}/triggeredwebjobs/{job}")
    def _history(self):
        response=self.transport("GET",self.base+"/history?api-version=2025-05-01",{"Accept":"application/json"},None)
        if response.status!=200 or len(response.body)>MAX_RESULT*100: fail("webjob-history")
        try: doc=json.loads(response.body)
        except Exception: fail("webjob-history-json")
        runs=doc.get("value") if isinstance(doc,dict) else None
        if not isinstance(runs,list): fail("webjob-history-shape")
        result={}
        for run in runs:
            if not isinstance(run,dict) or not isinstance(run.get("id"),str) or run["id"] in result: fail("webjob-history-item")
            result[run["id"]]=run
        return result
    def run_and_wait(self,request_name,*,polls=180,poll=None,pre_run=None):
        if not NAME.fullmatch(request_name) or not request_name.startswith("pdreq-"): fail("webjob-request-name")
        before=self._history()
        # The Microsoft.Web ARM run action has no body or caller-argument contract.
        # The singleton bridge discovers pending requests in the dedicated mailbox.
        # The finite controller lease is renewed after the last potentially slow
        # history read and immediately before the privileged run mutation.
        if pre_run is not None: pre_run()
        response=self.transport("POST",self.base+"/run?api-version=2025-05-01",{"Content-Type":"application/json"},b"")
        if response.status not in {200,202}: fail("webjob-run")
        if type(polls) is not int or polls<1 or polls>360: fail("webjob-polls")
        for attempt in range(polls):
            after=self._history(); new=set(after)-set(before)
            if len(new)>1: fail("webjob-ambiguous-run")
            if len(new)==1:
                item=after[new.pop()]; status=item.get("properties",{}).get("status")
                if status=="Success": return item
                if status in {"Failed","Aborted"}: fail("webjob-failed")
            if poll is not None: poll(attempt)
        fail("webjob-timeout")

def pending_request_names(deployments,*,limit=20):
    if type(limit) is not int or limit<1 or limit>100: fail("pending-limit")
    if not isinstance(deployments,list): fail("pending-list")
    requests={}; results=set(); order={}
    for item in deployments:
        if not isinstance(item,dict) or not isinstance(item.get("name"),str): fail("pending-item")
        name=item["name"]
        match=re.fullmatch(r"(pdreq|pdres)-([1-9]\d*)-([1-9]\d*)-([0-9a-f]{32})",name)
        if match is None: continue
        kind,run_id,attempt,nonce=match.groups();suffix=f"{run_id}-{attempt}-{nonce}"
        if kind=="pdreq":
            if suffix in requests: fail("pending-duplicate")
            requests[suffix]=name;order[suffix]=(int(run_id),int(attempt),nonce)
        else: results.add(suffix)
    pending=[requests[suffix] for suffix in set(requests)-results]
    # GitHub run IDs are monotonic. Process only the newest bounded window so a
    # stale/expired mailbox item can never starve a later legitimate request.
    pending.sort(key=lambda name:order["-".join(name.split("-")[1:])])
    return pending[-limit:]

@dataclasses.dataclass(frozen=True)
class WormRecord:
    blob:str; body:bytes; etag:str; version_id:str

def _worm_descriptor(record):
    if not isinstance(record,WormRecord) or not record.body or not record.etag or not record.version_id: fail("worm-record")
    return {"blob":record.blob,"sha256":digest(record.body),"size":len(record.body),"etag":record.etag,"versionId":record.version_id}

def _create_read_exact(boundary,blob,body):
    created=boundary.create(blob,body,if_none_match="*")
    observed=boundary.read(blob,version_id=created.version_id)
    if observed.blob!=blob or observed.body!=body or observed.etag!=created.etag or observed.version_id!=created.version_id: fail("worm-readback")
    return observed

def _read_exact(boundary,descriptor,label):
    descriptor=validate_descriptor(descriptor,label)
    observed=boundary.read(descriptor["blob"],version_id=descriptor["versionId"])
    if _worm_descriptor(observed)!=descriptor: fail(label+"-readback")
    return observed

def _read_json(boundary,descriptor,label):
    observed=_read_exact(boundary,descriptor,label)
    try: value=json.loads(observed.body)
    except Exception: fail(label+"-json")
    if canonical(value)!=observed.body: fail(label+"-canonical")
    return observed,value

def _read_current(boundary,blob):
    reader=getattr(boundary,"read_current",None)
    if reader is None: return None
    try: return reader(blob)
    except MailboxError as error:
        if str(error)=="blob-not-found": return None
        raise

def _create_or_read_exact(boundary,blob,body):
    existing=_read_current(boundary,blob)
    if existing is not None:
        if existing.blob!=blob or existing.body!=body: fail("worm-existing-drift")
        reread=boundary.read(blob,version_id=existing.version_id)
        if reread!=existing: fail("worm-existing-readback")
        return reread
    return _create_read_exact(boundary,blob,body)

def _empty_records(): return {field:None for field in RESULT_RECORD_FIELDS}
def _durable(records,metadata): return {"records":records,"metadata":{"schemaVersion":1,**metadata}}

def attach_cleanup_obligation(boundary,request,durable,control):
    """Create an immutable non-secret runner-loss recovery link.

    The bridge commits this record before signing/delivering the ARM result.
    It does not claim that cleanup already happened.  Instead it binds the
    exact terminal WORM records to the exact transient owner and the one
    source-pinned cleanup caller that can later reseal the bridge.
    """
    records=durable.get("records") if isinstance(durable,dict) else None;metadata=durable.get("metadata") if isinstance(durable,dict) else None
    terminal=(request.get("operation") in {"bootstrap-consume","consume-candidate","abort-candidate","persist-accepted-release","complete-rollback"}
              or request.get("operation")=="prepare-candidate" and isinstance(metadata,dict) and metadata.get("terminalState")=="consumed"
              or request.get("operation")=="prepare-rollback" and isinstance(metadata,dict) and metadata.get("terminalState")=="completed")
    if not terminal:return durable
    if (not isinstance(records,dict) or set(records)!=RESULT_RECORD_FIELDS or records.get("claim") is None or records.get("result") is None
            or records.get("cleanupObligation") is not None or not isinstance(control,dict) or set(control)!=TRANSIENT_CONTROL_FIELDS
            or control.get("operation")!=request.get("operation") or control.get("sourceSha")!=request.get("sourceSha")):fail("cleanup-obligation-input")
    request_sha=digest(canonical(request));control_sha=digest(canonical(control))
    terminal_records={name:value for name,value in records.items() if name!="cleanupObligation" and value is not None}
    proof=(metadata.get("activationProof") or metadata.get("terminalActivationProof")) if isinstance(metadata,dict) else None
    fence=metadata.get("terminalActivationFence") if isinstance(metadata,dict) else None
    plan=request.get("activationPlan")
    owner={key:control[key] for key in ("repository","repositoryId","ownerId","callerSha","workflowId","workflowName","workflowPath","workflowRef","event","headBranch","runId","runAttempt")}
    cleanup_caller={"workflowId":CLEANUP_WORKFLOW_ID,"workflowName":CLEANUP_WORKFLOW_NAME,"workflowPath":CLEANUP_WORKFLOW_PATH,"workflowRef":CLEANUP_WORKFLOW_REF,"events":sorted(CLEANUP_WORKFLOW_EVENTS)}
    body=canonical({"schemaVersion":1,"lifecycle":"bridge-cleanup-obligation","cleanupState":"required-after-terminal-result","sourceSha":request["sourceSha"],"operation":request["operation"],
        "requestSha256":request_sha,"requestClaim":records["claim"],"operationResult":records["result"],"terminalRecords":terminal_records,
        "transientOwner":owner,"transientControlSha256":control_sha,"transientExpiresAt":control["expiresAt"],"cleanupCaller":cleanup_caller,
        "activationPlanSha256":digest(canonical(plan)) if plan is not None else None,
        "activationFenceSha256":digest(canonical(fence)) if fence is not None else None,
        "activationProofSha256":digest(canonical(proof)) if proof is not None else None})
    blob=f"v2/cleanup-obligations/{request['sourceSha']}/{request_sha}.json"
    obligation=_create_or_read_exact(boundary,blob,body)
    records["cleanupObligation"]=_worm_descriptor(obligation)
    return durable

def _load_accepted(boundary,descriptor,package_boundary=None):
    manifest,doc=_read_json(boundary,descriptor,"accepted-manifest")
    expected={"schemaVersion","lifecycle","baselineMode","sourceSha","artifact","servedIndexSha256","oneDeployInvariant","healthPolicy","deploymentBundle","consumedMarker"}
    if not isinstance(doc,dict) or set(doc)!=expected or doc.get("schemaVersion")!=1 or doc.get("lifecycle")!="accepted" or doc.get("baselineMode") not in {"bootstrap","strict"}: fail("accepted-manifest-shape")
    if (not SHA40.fullmatch(str(doc["sourceSha"])) or not SHA256.fullmatch(str(doc["servedIndexSha256"]))
            or doc.get("oneDeployInvariant")!=BOOTSTRAP_BASELINE["oneDeployInvariant"]): fail("accepted-manifest-identity")
    bundle=validate_descriptor(doc["deploymentBundle"],"accepted-bundle",prefix="v1/accepted/",suffix="/deployment.zip")
    observed=(package_boundary or boundary).read(bundle["blob"],version_id=bundle["versionId"])
    if _worm_descriptor(observed)!=bundle: fail("accepted-bundle-readback")
    consumed=validate_descriptor(doc["consumedMarker"],"accepted-consumed",suffix="/consumed.json")
    consumed_record,consumed_doc=_read_json(boundary,consumed,"accepted-consumed")
    policy=doc["healthPolicy"]
    if doc["baselineMode"]=="bootstrap":
        if (doc["sourceSha"]!=BOOTSTRAP_BASELINE["sourceSha"] or doc["servedIndexSha256"]!=BOOTSTRAP_BASELINE["servedIndexSha256"]
                or doc["oneDeployInvariant"]!=BOOTSTRAP_BASELINE["oneDeployInvariant"]
                or policy!={"readyStatus":BOOTSTRAP_BASELINE["readinessHttpStatus"],"readyCode":BOOTSTRAP_BASELINE["readinessCode"],"runtimeMarkerRequired":False}
                or consumed_doc.get("lifecycle")!="bootstrap-consumed" or consumed_doc.get("sourceSha")!=doc["sourceSha"]): fail("accepted-bootstrap-binding")
    elif policy!={"readyStatus":200,"readyCode":"","runtimeMarkerRequired":True} or consumed_doc.get("lifecycle")!="candidate-consumed" or consumed_doc.get("sourceSha")!=doc["sourceSha"]: fail("accepted-strict-binding")
    return manifest,doc,observed,consumed_record

def prepare_bootstrap(boundary,request,tar_gz,*,now,package_boundary):
    request,raw,request_sha=validate_request(request,now=now)
    if request["operation"]!="bootstrap-prepare": fail("bootstrap-operation")
    bundle,base=deterministic_deploy_zip(tar_gz,request["sourceSha"])
    if base["servedIndexSha256"]!=BOOTSTRAP_BASELINE["servedIndexSha256"]: fail("bootstrap-index-digest")
    prefix=f"v2/accepted/{request['sourceSha']}/bootstrap"; records=_empty_records()
    claim=_create_or_read_exact(boundary,prefix+f"/requests/{request_sha}/claim.json",raw)
    bundle_record=_create_or_read_exact(package_boundary,f"v1/accepted/{request['sourceSha']}/bootstrap/deployment.zip",bundle)
    result_body=canonical({"schemaVersion":1,"operation":"bootstrap-prepare","requestSha256":request_sha,"sourceSha":request["sourceSha"],"artifactMemberSha256":request["artifactMemberSha256"],"deploymentZipSha256":digest(bundle)})
    result=_create_or_read_exact(boundary,prefix+f"/requests/{request_sha}/result.json",result_body)
    placeholder={"blob":"v2/bootstrap/current-production/consumed.json","sha256":"0"*64,"size":1,"etag":"\"pending\"","versionId":"pending"}
    manifest_body=canonical({"schemaVersion":1,"lifecycle":"accepted","baselineMode":"bootstrap","sourceSha":request["sourceSha"],"artifact":{"id":request["artifactId"],"outerSha256":request["artifactSha256"],"member":request["artifactMember"],"memberSha256":request["artifactMemberSha256"],"localEvidenceSha256":BOOTSTRAP_BASELINE["localEvidenceSha256"]},"servedIndexSha256":base["servedIndexSha256"],"oneDeployInvariant":BOOTSTRAP_BASELINE["oneDeployInvariant"],"healthPolicy":{"readyStatus":BOOTSTRAP_BASELINE["readinessHttpStatus"],"readyCode":BOOTSTRAP_BASELINE["readinessCode"],"runtimeMarkerRequired":False},"deploymentBundle":_worm_descriptor(bundle_record),"consumedMarker":placeholder})
    manifest=_create_or_read_exact(boundary,prefix+"/manifest.json",manifest_body)
    records.update({"claim":_worm_descriptor(claim),"result":_worm_descriptor(result),"manifest":_worm_descriptor(manifest),"deploymentBundle":_worm_descriptor(bundle_record),"acceptedBaseline":_worm_descriptor(manifest)})
    return _durable(records,{"operation":"bootstrap-prepare","sourceSha":request["sourceSha"],"baselineMode":"bootstrap","servedIndexSha256":base["servedIndexSha256"],"oneDeployInvariant":BOOTSTRAP_BASELINE["oneDeployInvariant"]})

def consume_bootstrap(boundary,request,*,now,activation_proof):
    request,raw,request_sha=validate_request(request,now=now)
    if request["operation"]!="bootstrap-consume": fail("bootstrap-consume-operation")
    accepted,doc=_read_json(boundary,request["acceptedBaseline"],"bootstrap-accepted")
    if doc.get("baselineMode")!="bootstrap" or doc.get("sourceSha")!=request["sourceSha"] or doc.get("deploymentBundle") is None: fail("bootstrap-accepted-binding")
    proof=activation_proof;proof_request=dict(request);proof_request["activationProof"]=proof
    validate_activation_proof(proof,proof_request)
    marker_blob="v2/bootstrap/current-production/consumed.json"
    existing=_read_current(boundary,marker_blob)
    if existing is None:
        marker_body=canonical({"schemaVersion":1,"lifecycle":"bootstrap-consumed","acceptedBaseline":_worm_descriptor(accepted),"sourceSha":request["sourceSha"],"activationProof":proof})
        marker=_create_or_read_exact(boundary,marker_blob,marker_body)
    else:
        marker,marker_doc=_read_json(boundary,_worm_descriptor(existing),"bootstrap-consumed-existing")
        if (not isinstance(marker_doc,dict) or set(marker_doc)!={"schemaVersion","lifecycle","acceptedBaseline","sourceSha","activationProof"}
                or marker_doc.get("schemaVersion")!=1 or marker_doc.get("lifecycle")!="bootstrap-consumed"
                or marker_doc.get("acceptedBaseline")!=_worm_descriptor(accepted) or marker_doc.get("sourceSha")!=request["sourceSha"]):fail("bootstrap-consumed-existing-binding")
        replay=dict(request);replay["activationProof"]=marker_doc["activationProof"]
        validate_activation_proof(marker_doc["activationProof"],replay)
    final_doc=dict(doc); final_doc["consumedMarker"]=_worm_descriptor(marker)
    final_body=canonical(final_doc)
    # The bootstrap manifest itself is immutable. Commit a final accepted manifest
    # whose fixed path is the only baseline accepted by normal release flows.
    final=_create_or_read_exact(boundary,f"v2/accepted/{request['sourceSha']}/bootstrap-consumed/manifest.json",final_body)
    prefix=f"v2/bootstrap/current-production/requests/{request_sha}"; claim=_create_or_read_exact(boundary,prefix+"/claim.json",raw)
    result=_create_or_read_exact(boundary,prefix+"/result.json",canonical({"schemaVersion":1,"operation":"bootstrap-consume","requestSha256":request_sha,"acceptedBaseline":_worm_descriptor(final),"consumedMarker":_worm_descriptor(marker)}))
    manifest=_create_or_read_exact(boundary,prefix+"/manifest.json",canonical({"schemaVersion":1,"request":_worm_descriptor(claim),"result":_worm_descriptor(result),"acceptedBaseline":_worm_descriptor(final),"consumedMarker":_worm_descriptor(marker)}))
    records=_empty_records();records.update({"claim":_worm_descriptor(claim),"result":_worm_descriptor(result),"manifest":_worm_descriptor(manifest),"acceptedBaseline":_worm_descriptor(final),"consumedMarker":_worm_descriptor(marker)})
    return _durable(records,{"operation":"bootstrap-consume","sourceSha":request["sourceSha"],"baselineMode":"bootstrap","servedIndexSha256":doc["servedIndexSha256"],"oneDeployInvariant":doc["oneDeployInvariant"]})

def prepare_candidate(boundary,request,tar_gz,*,now,package_boundary):
    request,raw,request_sha=validate_request(request,now=now)
    if request["operation"]!="prepare-candidate": fail("candidate-operation")
    accepted,baseline,bundle,_=_load_accepted(boundary,request["acceptedBaseline"],package_boundary)
    candidate_prefix=f"v2/pending/{request['sourceSha']}/{request['sourceRunId']}-{request['sourceRunAttempt']}-{request['artifactId']}"
    if _read_current(boundary,candidate_prefix+"/aborted.json") is not None: fail("candidate-replay-aborted")
    deploy,base=deterministic_deploy_zip(tar_gz,request["sourceSha"])
    claim=_create_or_read_exact(boundary,candidate_prefix+f"/requests/{request_sha}/claim.json",raw)
    deploy_record=_create_or_read_exact(package_boundary,f"v1/pending/{request['sourceSha']}/{request['sourceRunId']}-{request['sourceRunAttempt']}-{request['artifactId']}/deployment.zip",deploy)
    result=_create_or_read_exact(boundary,candidate_prefix+f"/requests/{request_sha}/result.json",canonical({"schemaVersion":1,"operation":"prepare-candidate","requestSha256":request_sha,"sourceSha":request["sourceSha"],"deploymentZipSha256":digest(deploy)}))
    manifest_body=canonical({"schemaVersion":1,"lifecycle":"pending","sourceSha":request["sourceSha"],"execution":{"repositoryId":request["repositoryId"],"ownerId":request["ownerId"],"sourceRunId":request["sourceRunId"],"sourceRunAttempt":request["sourceRunAttempt"],"artifactId":request["artifactId"]},"artifact":{"outerSha256":request["artifactSha256"],"member":request["artifactMember"],"memberSha256":request["artifactMemberSha256"]},"acceptedBaseline":_worm_descriptor(accepted),"servedIndexSha256":base["servedIndexSha256"],"oneDeployInvariant":baseline["oneDeployInvariant"],"deploymentBundle":_worm_descriptor(deploy_record)})
    manifest=_create_or_read_exact(boundary,candidate_prefix+"/manifest.json",manifest_body)
    records=_empty_records();records.update({"claim":_worm_descriptor(claim),"result":_worm_descriptor(result),"manifest":_worm_descriptor(manifest),"deploymentBundle":_worm_descriptor(deploy_record),"acceptedBaseline":_worm_descriptor(accepted),"pendingRelease":_worm_descriptor(manifest)})
    metadata={"operation":"prepare-candidate","sourceSha":request["sourceSha"],"baselineMode":baseline["baselineMode"],"servedIndexSha256":base["servedIndexSha256"],"oneDeployInvariant":baseline["oneDeployInvariant"],"baselineSourceSha":baseline["sourceSha"],"baselineServedIndexSha256":baseline["servedIndexSha256"],"baselineDeploymentBundle":baseline["deploymentBundle"],"terminalState":"pending","terminalActivationFence":None,"terminalActivationProof":None}
    consumed_current=_read_current(boundary,candidate_prefix+"/consumed.json")
    if consumed_current is not None:
        consumed,consumed_doc=_read_json(boundary,_worm_descriptor(consumed_current),"candidate-consumed-recovery")
        expected={"schemaVersion","lifecycle","pendingRelease","acceptedBaseline","sourceSha","activationFence","activationProof"}
        if (not isinstance(consumed_doc,dict) or set(consumed_doc)!=expected or consumed_doc.get("schemaVersion")!=1 or consumed_doc.get("lifecycle")!="candidate-consumed"
                or consumed_doc.get("pendingRelease")!=_worm_descriptor(manifest) or consumed_doc.get("acceptedBaseline")!=_worm_descriptor(accepted)
                or consumed_doc.get("sourceSha")!=request["sourceSha"]):fail("candidate-consumed-recovery-binding")
        validate_activation_fence(consumed_doc["activationFence"],"candidate-consumed-recovery-fence")
        replay=dict(request);replay.update({"operation":"consume-candidate","artifactId":"","artifactSha256":"","artifactMember":"","artifactMemberSha256":"","pendingRelease":_worm_descriptor(manifest),"activationPlan":activation_plan_from_fence(consumed_doc["activationFence"]),"activationProof":consumed_doc["activationProof"]})
        validate_activation_proof(consumed_doc["activationProof"],replay)
        records["consumedMarker"]=_worm_descriptor(consumed)
        metadata.update({"terminalState":"consumed","terminalActivationFence":consumed_doc["activationFence"],"terminalActivationProof":consumed_doc["activationProof"]})
    return _durable(records,metadata)

def consume_candidate(boundary,request,*,now,activation_proof,activation_fence):
    request,raw,request_sha=validate_request(request,now=now)
    if request["operation"]!="consume-candidate": fail("candidate-consume-operation")
    activation_fence=validate_activation_fence(activation_fence,"candidate-consume-fence")
    if activation_plan_from_fence(activation_fence)!=request["activationPlan"]:fail("candidate-consume-fence-plan")
    accepted,baseline=_read_json(boundary,request["acceptedBaseline"],"candidate-baseline")
    pending,pending_doc=_read_json(boundary,request["pendingRelease"],"candidate-pending")
    if pending_doc.get("lifecycle")!="pending" or pending_doc.get("sourceSha")!=request["sourceSha"] or pending_doc.get("acceptedBaseline")!=_worm_descriptor(accepted): fail("candidate-pending-binding")
    proof=activation_proof;proof_request=dict(request);proof_request["activationProof"]=proof
    validate_activation_proof(proof,proof_request)
    if proof["index"]["sha256"]!=pending_doc.get("servedIndexSha256") or proof["oneDeployInvariant"]!={**pending_doc.get("oneDeployInvariant",{}),"historicalActiveDeployment":{"id":BOOTSTRAP_BASELINE["oneDeployInvariant"]["historicalActiveDeploymentId"],"status":4,"complete":True,"deployer":"OneDeploy"}}: fail("candidate-proof-binding")
    marker_blob=str(PurePosixPath(pending.blob).parent/"consumed.json")
    if _read_current(boundary,str(PurePosixPath(pending.blob).parent/"aborted.json")) is not None:fail("candidate-terminal-conflict")
    marker_body=canonical({"schemaVersion":1,"lifecycle":"candidate-consumed","pendingRelease":_worm_descriptor(pending),"acceptedBaseline":_worm_descriptor(accepted),"sourceSha":request["sourceSha"],"activationFence":activation_fence,"activationProof":proof})
    marker=_create_or_read_exact(boundary,marker_blob,marker_body)
    prefix=str(PurePosixPath(pending.blob).parent/f"consume/{request_sha}");claim=_create_or_read_exact(boundary,prefix+"/claim.json",raw)
    result=_create_or_read_exact(boundary,prefix+"/result.json",canonical({"schemaVersion":1,"operation":"consume-candidate","requestSha256":request_sha,"pendingRelease":_worm_descriptor(pending),"consumedMarker":_worm_descriptor(marker)}))
    manifest=_create_or_read_exact(boundary,prefix+"/manifest.json",canonical({"schemaVersion":1,"request":_worm_descriptor(claim),"result":_worm_descriptor(result),"pendingRelease":_worm_descriptor(pending),"consumedMarker":_worm_descriptor(marker)}))
    records=_empty_records();records.update({"claim":_worm_descriptor(claim),"result":_worm_descriptor(result),"manifest":_worm_descriptor(manifest),"acceptedBaseline":_worm_descriptor(accepted),"pendingRelease":_worm_descriptor(pending),"consumedMarker":_worm_descriptor(marker)})
    return _durable(records,{"operation":"consume-candidate","sourceSha":request["sourceSha"],"baselineMode":baseline.get("baselineMode"),"servedIndexSha256":pending_doc["servedIndexSha256"],"oneDeployInvariant":pending_doc["oneDeployInvariant"]})

def abort_candidate(boundary,request,*,now,activation_proof,activation_fence):
    request,raw,request_sha=validate_request(request,now=now)
    if request["operation"]!="abort-candidate": fail("candidate-abort-operation")
    activation_fence=validate_activation_fence(activation_fence,"candidate-abort-fence")
    if activation_plan_from_fence(activation_fence)!=request["activationPlan"]:fail("candidate-abort-fence-plan")
    accepted,baseline=_read_json(boundary,request["acceptedBaseline"],"abort-baseline")
    pending,pending_doc=_read_json(boundary,request["pendingRelease"],"abort-pending")
    terminal_prefix=str(PurePosixPath(pending.blob).parent)
    if _read_current(boundary,terminal_prefix+"/consumed.json") is not None:fail("candidate-terminal-conflict")
    proof=activation_proof;proof_request=dict(request);proof_request["activationProof"]=proof
    validate_activation_proof(proof,proof_request)
    if (pending_doc.get("acceptedBaseline")!=_worm_descriptor(accepted) or proof["sourceSha"]!=baseline.get("sourceSha")
            or proof["index"]["sha256"]!=baseline.get("servedIndexSha256") or proof["oneDeployInvariant"]!={**baseline.get("oneDeployInvariant",{}),"historicalActiveDeployment":{"id":BOOTSTRAP_BASELINE["oneDeployInvariant"]["historicalActiveDeploymentId"],"status":4,"complete":True,"deployer":"OneDeploy"}}): fail("candidate-abort-binding")
    aborted=_create_or_read_exact(boundary,terminal_prefix+"/aborted.json",canonical({"schemaVersion":1,"lifecycle":"candidate-aborted","pendingRelease":_worm_descriptor(pending),"acceptedBaseline":_worm_descriptor(accepted),"sourceSha":request["sourceSha"],"activationFence":activation_fence,"activationProof":proof}))
    prefix=terminal_prefix+f"/abort/{request_sha}";claim=_create_or_read_exact(boundary,prefix+"/claim.json",raw)
    result=_create_or_read_exact(boundary,prefix+"/result.json",canonical({"schemaVersion":1,"operation":"abort-candidate","requestSha256":request_sha,"pendingRelease":_worm_descriptor(pending),"acceptedBaseline":_worm_descriptor(accepted),"abortedMarker":_worm_descriptor(aborted),"rollbackProofSha256":digest(canonical(proof))}))
    manifest=_create_or_read_exact(boundary,prefix+"/manifest.json",canonical({"schemaVersion":1,"request":_worm_descriptor(claim),"result":_worm_descriptor(result),"pendingRelease":_worm_descriptor(pending),"acceptedBaseline":_worm_descriptor(accepted),"abortedMarker":_worm_descriptor(aborted)}))
    records=_empty_records();records.update({"claim":_worm_descriptor(claim),"result":_worm_descriptor(result),"manifest":_worm_descriptor(manifest),"acceptedBaseline":_worm_descriptor(accepted),"pendingRelease":_worm_descriptor(pending)})
    return _durable(records,{"operation":"abort-candidate","sourceSha":request["sourceSha"],"baselineMode":baseline.get("baselineMode"),"servedIndexSha256":baseline["servedIndexSha256"],"oneDeployInvariant":baseline["oneDeployInvariant"]})

def persist_accepted_release(boundary,request,transfer_tar,*,now,package_boundary):
    request,raw,request_sha=validate_request(request,now=now)
    if request["operation"]!="persist-accepted-release": fail("accepted-operation")
    pending,pending_doc=_read_json(boundary,request["pendingRelease"],"accepted-pending")
    consumed,consumed_doc=_read_json(boundary,request["consumedMarker"],"accepted-consumed")
    if consumed_doc.get("lifecycle")!="candidate-consumed" or consumed_doc.get("pendingRelease")!=_worm_descriptor(pending) or pending_doc.get("sourceSha")!=request["sourceSha"]: fail("accepted-lifecycle-binding")
    bundle_desc=validate_descriptor(pending_doc.get("deploymentBundle"),"accepted-pending-bundle")
    bundle=_read_exact(package_boundary,bundle_desc,"accepted-pending-bundle")
    prefix=f"v2/accepted/{request['sourceSha']}/{request['acceptanceRunId']}-{request['acceptanceRunAttempt']}"
    # Promote the exact pending package into the accepted immutable namespace
    # before committing the manifest. Future candidate and rollback loaders
    # accept only v1/accepted/* package coordinates.
    accepted_bundle=_create_or_read_exact(package_boundary,f"v1/accepted/{request['sourceSha']}/{request['acceptanceRunId']}-{request['acceptanceRunAttempt']}/deployment.zip",bundle.body)
    claim=_create_or_read_exact(boundary,prefix+f"/requests/{request_sha}/claim.json",raw)
    transfer=_create_or_read_exact(boundary,prefix+"/accepted-release-transfer.tar.gz",transfer_tar)
    result=_create_or_read_exact(boundary,prefix+f"/requests/{request_sha}/result.json",canonical({"schemaVersion":1,"operation":"persist-accepted-release","requestSha256":request_sha,"pendingRelease":_worm_descriptor(pending),"consumedMarker":_worm_descriptor(consumed),"transferSha256":digest(transfer_tar)}))
    manifest_body=canonical({"schemaVersion":1,"lifecycle":"accepted","baselineMode":"strict","sourceSha":request["sourceSha"],"artifact":{"id":request["artifactId"],"outerSha256":request["artifactSha256"],"member":request["artifactMember"],"memberSha256":request["artifactMemberSha256"],"pendingRelease":_worm_descriptor(pending),"acceptedTransfer":_worm_descriptor(transfer)},"servedIndexSha256":pending_doc["servedIndexSha256"],"oneDeployInvariant":pending_doc["oneDeployInvariant"],"healthPolicy":{"readyStatus":200,"readyCode":"","runtimeMarkerRequired":True},"deploymentBundle":_worm_descriptor(accepted_bundle),"consumedMarker":_worm_descriptor(consumed)})
    manifest=_create_or_read_exact(boundary,prefix+"/manifest.json",manifest_body)
    records=_empty_records();records.update({"claim":_worm_descriptor(claim),"result":_worm_descriptor(result),"manifest":_worm_descriptor(manifest),"deploymentBundle":_worm_descriptor(accepted_bundle),"acceptedBaseline":_worm_descriptor(manifest),"pendingRelease":_worm_descriptor(pending),"consumedMarker":_worm_descriptor(consumed)})
    return _durable(records,{"operation":"persist-accepted-release","sourceSha":request["sourceSha"],"baselineMode":"strict","servedIndexSha256":pending_doc["servedIndexSha256"],"oneDeployInvariant":pending_doc["oneDeployInvariant"]})

def prepare_rollback(boundary,request,*,now,package_boundary):
    request,raw,request_sha=validate_request(request,now=now)
    if request["operation"]!="prepare-rollback": fail("rollback-operation")
    accepted,baseline,bundle,_=_load_accepted(boundary,request["acceptedBaseline"],package_boundary)
    if baseline["sourceSha"]!=request["sourceSha"]:fail("rollback-source-binding")
    prefix=f"v2/rollback/{request['sourceSha']}/{request['logicalOperationId']}";claim=_create_or_read_exact(boundary,prefix+f"/requests/{request_sha}/claim.json",raw)
    result=_create_or_read_exact(boundary,prefix+f"/requests/{request_sha}/result.json",canonical({"schemaVersion":1,"operation":"prepare-rollback","logicalOperationId":request["logicalOperationId"],"requestSha256":request_sha,"acceptedBaseline":_worm_descriptor(accepted),"deploymentZipSha256":digest(bundle.body)}))
    manifest=_create_or_read_exact(boundary,prefix+"/manifest.json",canonical({"schemaVersion":1,"lifecycle":"rollback-prepared","logicalOperationId":request["logicalOperationId"],"acceptedBaseline":_worm_descriptor(accepted),"deploymentBundle":_worm_descriptor(bundle)}))
    records=_empty_records();records.update({"claim":_worm_descriptor(claim),"result":_worm_descriptor(result),"manifest":_worm_descriptor(manifest),"deploymentBundle":_worm_descriptor(bundle),"acceptedBaseline":_worm_descriptor(accepted)})
    metadata={"operation":"prepare-rollback","sourceSha":request["sourceSha"],"baselineMode":baseline["baselineMode"],"servedIndexSha256":baseline["servedIndexSha256"],"oneDeployInvariant":baseline["oneDeployInvariant"],"baselineDeploymentBundle":baseline["deploymentBundle"],"terminalState":"pending","terminalActivationFence":None,"terminalActivationProof":None}
    terminal_current=_read_current(boundary,prefix+"/completed.json")
    if terminal_current is not None:
        terminal,terminal_doc=_read_json(boundary,_worm_descriptor(terminal_current),"rollback-completed-recovery")
        expected={"schemaVersion","lifecycle","logicalOperationId","rollbackPreparation","acceptedBaseline","sourceSha","activationFence","activationProof"}
        if (not isinstance(terminal_doc,dict) or set(terminal_doc)!=expected or terminal_doc.get("schemaVersion")!=1 or terminal_doc.get("lifecycle")!="rollback-completed"
                or terminal_doc.get("logicalOperationId")!=request["logicalOperationId"]
                or terminal_doc.get("rollbackPreparation")!=_worm_descriptor(manifest) or terminal_doc.get("acceptedBaseline")!=_worm_descriptor(accepted)
                or terminal_doc.get("sourceSha")!=request["sourceSha"]):fail("rollback-completed-recovery-binding")
        validate_activation_fence(terminal_doc["activationFence"],"rollback-completed-recovery-fence")
        replay=dict(request);replay.update({"operation":"complete-rollback","artifactId":"","artifactSha256":"","artifactMember":"","artifactMemberSha256":"","rollbackPreparation":_worm_descriptor(manifest),"activationPlan":activation_plan_from_fence(terminal_doc["activationFence"]),"activationProof":terminal_doc["activationProof"]})
        validate_activation_proof(terminal_doc["activationProof"],replay)
        records["terminalMarker"]=_worm_descriptor(terminal)
        metadata.update({"terminalState":"completed","terminalActivationFence":terminal_doc["activationFence"],"terminalActivationProof":terminal_doc["activationProof"]})
    return _durable(records,metadata)

def complete_rollback(boundary,request,*,now,activation_proof,activation_fence):
    request,raw,request_sha=validate_request(request,now=now)
    if request["operation"]!="complete-rollback":fail("rollback-complete-operation")
    activation_fence=validate_activation_fence(activation_fence,"rollback-complete-fence")
    if activation_plan_from_fence(activation_fence)!=request["activationPlan"]:fail("rollback-complete-fence-plan")
    accepted,baseline=_read_json(boundary,request["acceptedBaseline"],"rollback-complete-baseline")
    preparation,preparation_doc=_read_json(boundary,request["rollbackPreparation"],"rollback-complete-preparation")
    if (preparation_doc.get("lifecycle")!="rollback-prepared" or preparation_doc.get("logicalOperationId")!=request["logicalOperationId"]
            or preparation_doc.get("acceptedBaseline")!=_worm_descriptor(accepted)
            or preparation_doc.get("deploymentBundle")!=baseline.get("deploymentBundle")):fail("rollback-complete-preparation-binding")
    proof=activation_proof;proof_request=dict(request);proof_request["activationProof"]=proof
    validate_activation_proof(proof,proof_request)
    if proof["sourceSha"]!=baseline.get("sourceSha") or proof["index"]["sha256"]!=baseline.get("servedIndexSha256") or proof["oneDeployInvariant"]!={**baseline.get("oneDeployInvariant",{}),"historicalActiveDeployment":{"id":BOOTSTRAP_BASELINE["oneDeployInvariant"]["historicalActiveDeploymentId"],"status":4,"complete":True,"deployer":"OneDeploy"}}:fail("rollback-complete-binding")
    terminal_blob=str(PurePosixPath(preparation.blob).parent/"completed.json")
    terminal_body=canonical({"schemaVersion":1,"lifecycle":"rollback-completed","logicalOperationId":request["logicalOperationId"],"rollbackPreparation":_worm_descriptor(preparation),"acceptedBaseline":_worm_descriptor(accepted),"sourceSha":request["sourceSha"],"activationFence":activation_fence,"activationProof":proof})
    terminal=_create_or_read_exact(boundary,terminal_blob,terminal_body)
    prefix=f"v2/rollback/{request['sourceSha']}/complete/{request_sha}";claim=_create_or_read_exact(boundary,prefix+"/claim.json",raw)
    result=_create_or_read_exact(boundary,prefix+"/result.json",canonical({"schemaVersion":1,"operation":"complete-rollback","requestSha256":request_sha,"acceptedBaseline":_worm_descriptor(accepted),"proofSha256":digest(canonical(proof))}))
    manifest=_create_or_read_exact(boundary,prefix+"/manifest.json",canonical({"schemaVersion":1,"request":_worm_descriptor(claim),"result":_worm_descriptor(result),"acceptedBaseline":_worm_descriptor(accepted)}))
    records=_empty_records();records.update({"claim":_worm_descriptor(claim),"result":_worm_descriptor(result),"manifest":_worm_descriptor(manifest),"acceptedBaseline":_worm_descriptor(accepted),"terminalMarker":_worm_descriptor(terminal)})
    return _durable(records,{"operation":"complete-rollback","sourceSha":request["sourceSha"],"baselineMode":baseline["baselineMode"],"servedIndexSha256":baseline["servedIndexSha256"],"oneDeployInvariant":baseline["oneDeployInvariant"]})

def deterministic_deploy_zip(tar_gz,source_sha):
    if not SHA40.fullmatch(source_sha) or len(tar_gz)>MAX_ZIP: fail("bundle-input")
    output=io.BytesIO(); count=0
    try:
        archive=tarfile.open(fileobj=io.BytesIO(tar_gz),mode="r:gz")
        members=archive.getmembers()
        with zipfile.ZipFile(output,"w",zipfile.ZIP_DEFLATED,compresslevel=9) as target:
            names=set()
            index_body=None
            for member in sorted(members,key=lambda item:item.name):
                path=PurePosixPath(member.name)
                if member.issym() or member.islnk() or path.is_absolute() or any(x in {"",".",".."} for x in path.parts): fail("bundle-member")
                if member.isdir(): continue
                if not member.isfile() or member.name in names: fail("bundle-member")
                if member.size<0 or member.size>MAX_ZIP: fail("bundle-size")
                names.add(member.name); count+=1
                if count>MAX_MEMBERS: fail("bundle-count")
                source=archive.extractfile(member)
                if source is None: fail("bundle-read")
                body=source.read(MAX_ZIP+1)
                if len(body)>MAX_ZIP or output.tell()+len(body)>MAX_ZIP: fail("bundle-size")
                if member.name=="index.html": index_body=body
                info=zipfile.ZipInfo(member.name,(1980,1,1,0,0,0)); info.create_system=3; info.external_attr=(stat.S_IFREG|0o644)<<16; info.compress_type=zipfile.ZIP_DEFLATED
                target.writestr(info,body,compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
    except (tarfile.TarError,OSError,EOFError): fail("bundle-tar")
    body=output.getvalue()
    if not body or len(body)>MAX_ZIP: fail("bundle-size")
    if index_body is None:fail("bundle-index")
    return body,{"blob":f"deployment/paperdesk-azure-deploy-{source_sha}.zip","sha256":digest(body),"size":len(body),"servedIndexSha256":digest(index_body),"servedIndexSize":len(index_body)}

def package_url(descriptor):
    descriptor=validate_descriptor(descriptor,"activation-bundle",suffix="/deployment.zip")
    return f"https://{FIXED_COORDS['packageAccount']}.blob.core.windows.net/{FIXED_COORDS['packageContainer']}/{descriptor['blob']}?versionid={descriptor['versionId']}"

def _put_settings_reconciled(*,current,current_digest,desired,config_read,config_put,label):
    """Classify an unversioned Microsoft.Web PUT as old, desired, or third-state."""
    if current_digest!=digest(canonical(current)):fail(label+"-pre-digest")
    returned=None; mutation_error=None
    try: returned=config_put(desired,current_digest)
    except Exception as error: mutation_error=error
    observed,observed_digest=config_read()
    if observed==desired and observed_digest==digest(canonical(desired)):
        if returned is not None and returned!=observed_digest: fail(label+"-put-ambiguity")
        return observed_digest
    if observed==current:
        if mutation_error is not None: raise MailboxError(label+"-mutation-not-applied") from mutation_error
        fail(label+"-mutation-noop")
    fail(label+"-mutation-third-state")

def activate_run_from_package(*,source_sha,baseline,target,activation_fence,system_identity_principal,config_read,config_put,restart,probe,consume,abort):
    if not SHA40.fullmatch(source_sha) or not isinstance(baseline,dict) or not isinstance(target,dict): fail("activation-input")
    baseline_url=package_url(baseline["deploymentBundle"]); target_url=package_url(target["deploymentBundle"])
    fence=validate_activation_fence(activation_fence,"activation-fence")
    if fence["operation"]!="candidate" or fence["sourceSha"]!=source_sha:fail("activation-fence-binding")
    if not isinstance(system_identity_principal,str) or not GUID.fullmatch(system_identity_principal): fail("activation-principal")
    current,settings_digest=config_read()
    if not isinstance(current,dict) or settings_digest!=digest(canonical(current)): fail("activation-config")
    mode=current.get("WEBSITE_RUN_FROM_PACKAGE"); identity=current.get("WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID")
    if mode==target_url and identity=="SystemAssigned" and settings_digest==fence["desiredSettingsSha256"]:
        baseline_settings=dict(current)
        if baseline.get("baselineMode")=="bootstrap":
            baseline_settings.pop("WEBSITE_RUN_FROM_PACKAGE",None)
            baseline_settings.pop("WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID",None)
        else:
            baseline_settings["WEBSITE_RUN_FROM_PACKAGE"]=baseline_url
            baseline_settings["WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID"]="SystemAssigned"
        if digest(canonical(baseline_settings))!=fence["preSettingsSha256"]:fail("activation-recovery-third-state")
        # A prior controller may have lost the signed result after candidate
        # settings became live.  Retry the durable consume in place; never
        # restore baseline merely because result delivery was ambiguous.
        recovered_target=probe(target)
        if recovered_target.get("healthy") is not True or recovered_target.get("sourceSha")!=source_sha:fail("activation-recovery-settlement")
        try:consumed=consume(recovered_target)
        except Exception as original:raise MailboxError("activation-consumption-indeterminate") from original
        if not isinstance(consumed,dict) or consumed.get("status")!="complete":fail("activation-consume")
        return {"status":"consumed","sourceSha":source_sha,"packageUrlSha256":digest(target_url.encode()),"systemIdentityPrincipalId":system_identity_principal,"configDigest":settings_digest,"settlement":recovered_target,"consumption":consumed}
    elif settings_digest==fence["preSettingsSha256"] and ((mode==baseline_url and identity=="SystemAssigned") or (baseline.get("baselineMode")=="bootstrap" and mode in {None,"","1"} and identity in {None,""})):
        baseline_settings=dict(current)
    else: fail("activation-baseline-config")
    predeploy=probe(baseline)
    if not isinstance(predeploy,dict) or predeploy.get("sourceSha")!=baseline.get("sourceSha") or predeploy.get("healthy") is not True: fail("activation-predeploy")
    updated=dict(current); updated["WEBSITE_RUN_FROM_PACKAGE"]=target_url; updated["WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID"]="SystemAssigned"
    if digest(canonical(updated))!=fence["desiredSettingsSha256"]:fail("activation-target-digest")
    mutated=False;consume_started=False
    try:
        confirmed_digest=_put_settings_reconciled(current=current,current_digest=settings_digest,desired=updated,config_read=config_read,config_put=config_put,label="activation")
        mutated=True;restart(); observed=probe(target)
        if not isinstance(observed,dict) or observed.get("sourceSha")!=source_sha or observed.get("healthy") is not True: fail("activation-settlement")
        consume_started=True;consumed=consume(observed)
        if not isinstance(consumed,dict) or consumed.get("status")!="complete": fail("activation-consume")
    except Exception as original:
        if consume_started:raise MailboxError("activation-consumption-indeterminate") from original
        if not mutated and isinstance(original,MailboxError) and str(original)=="activation-mutation-not-applied": raise
        try:
            observed_settings,observed_digest=config_read()
            if observed_settings==updated:
                rollback_digest=_put_settings_reconciled(current=observed_settings,current_digest=observed_digest,desired=baseline_settings,config_read=config_read,config_put=config_put,label="activation-rollback")
            elif observed_settings==baseline_settings:rollback_digest=observed_digest
            else:fail("activation-rollback-third-state")
            restored_settings,restored_digest=config_read()
            if restored_settings!=baseline_settings or restored_digest!=rollback_digest: fail("activation-rollback-readback")
            restart()
            restored=probe(baseline)
            if not isinstance(restored,dict) or restored.get("sourceSha")!=baseline.get("sourceSha") or restored.get("healthy") is not True: fail("activation-rollback-settlement")
            aborted=abort(restored)
            if not isinstance(aborted,dict) or aborted.get("status")!="complete":fail("activation-abort")
        except Exception as rollback_error:
            raise MailboxError("activation-indeterminate") from rollback_error
        return {"status":"aborted","sourceSha":source_sha,"packageUrlSha256":digest(target_url.encode()),"systemIdentityPrincipalId":system_identity_principal,"configDigest":rollback_digest,"settlement":restored,"consumption":aborted,"errorCode":str(original)[:128]}
    return {"status":"consumed","sourceSha":source_sha,"packageUrlSha256":digest(target_url.encode()),"systemIdentityPrincipalId":system_identity_principal,"configDigest":confirmed_digest,"settlement":observed,"consumption":consumed}

def rollback_run_from_package(*,target,activation_fence,system_identity_principal,config_read,config_put,restart,probe,complete):
    if not isinstance(target,dict) or not SHA40.fullmatch(str(target.get("sourceSha"))):fail("rollback-input")
    fence=validate_activation_fence(activation_fence,"rollback-fence")
    if fence["operation"]!="rollback" or fence["sourceSha"]!=target["sourceSha"]:fail("rollback-fence-binding")
    if not GUID.fullmatch(str(system_identity_principal)):fail("rollback-principal")
    current,current_digest=config_read();target_url=package_url(target["deploymentBundle"])
    if not isinstance(current,dict) or current_digest!=digest(canonical(current)):fail("rollback-settings")
    if current_digest==fence["desiredSettingsSha256"] and current.get("WEBSITE_RUN_FROM_PACKAGE")==target_url and current.get("WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID")=="SystemAssigned":
        next_digest=current_digest
    elif current_digest==fence["preSettingsSha256"]:
        desired=dict(current);desired["WEBSITE_RUN_FROM_PACKAGE"]=target_url;desired["WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID"]="SystemAssigned"
        if digest(canonical(desired))!=fence["desiredSettingsSha256"]:fail("rollback-target-digest")
        next_digest=_put_settings_reconciled(current=current,current_digest=current_digest,desired=desired,config_read=config_read,config_put=config_put,label="rollback")
        restart()
    else:fail("rollback-third-state")
    settlement=probe(target)
    if not isinstance(settlement,dict) or settlement.get("sourceSha")!=target["sourceSha"] or settlement.get("healthy") is not True:fail("rollback-settlement")
    completion=complete(settlement)
    if not isinstance(completion,dict) or completion.get("status")!="complete":fail("rollback-completion")
    return {"status":"complete","sourceSha":target["sourceSha"],"packageUrlSha256":digest(package_url(target["deploymentBundle"]).encode()),"systemIdentityPrincipalId":system_identity_principal,"configDigest":next_digest,"settlement":settlement,"completion":completion}
