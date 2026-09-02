"""Triggered WebJob entry; dormant until the sealed activation document is exact."""
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, os, re, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
try:
    from scripts import private_release_mailbox as core
    from provider import private_release_bridge_azure as azure
    from provider import private_release_bridge_runtime as runtime
except ModuleNotFoundError:
    import private_release_mailbox as core
    import private_release_bridge_azure as azure
    import private_release_bridge_runtime as runtime
def load_env_json(name):
    value=os.environ.get(name,"")
    if not value or len(value)>131072: core.fail("entry-env-"+name.lower())
    try: return json.loads(value)
    except Exception: core.fail("entry-json-"+name.lower())
def verify_members():
    try: manifest=json.loads((ROOT/"private_release_bridge_members.json").read_text(encoding="utf-8"))
    except Exception: core.fail("entry-member-manifest")
    if not isinstance(manifest,dict) or set(manifest)!={"schemaVersion","members"} or manifest["schemaVersion"]!=1: core.fail("entry-member-manifest")
    for name,expected in manifest["members"].items():
        if not isinstance(name,str) or "/" in name or not core.SHA256.fullmatch(str(expected)): core.fail("entry-member")
        path=ROOT/name
        if not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=expected: core.fail("entry-member-drift")
BOOTSTRAP_TENANT_ID="aba83bd8-3e5c-4a87-9eb1-7bca070685b2"
BOOTSTRAP_BRIDGE_IDENTITY_RESOURCE_ID=(
    "/subscriptions/9c4e0d0d-602f-4cde-84bd-337250e5b64c/resourceGroups/rg-master-data-structure-sea/"
    "providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-paperdesk-release-bridge-v2"
)
BOOTSTRAP_FENCE_LEASE_ID="c28f7730-431d-5c52-b885-8e43154d1ddb"
def run_bootstrap_self_test(value):
    """Prove package execution and the bridge-identity fence boundary only.

    This branch runs before activation parsing.  It constructs only the bridge
    managed-identity token provider and the activation-fence client; production,
    GitHub, signer, writer, reader, mailbox and activation clients stay absent.
    """
    raw=value
    if len(raw)>4096:core.fail("entry-bootstrap-self-test")
    try:control=json.loads(raw)
    except Exception:core.fail("entry-bootstrap-self-test-json")
    fields={"schemaVersion","mode","authorizationId","authorizationSha256","siteName","packageSha256","nonce","issuedAt","expiresAt","planSha256","bridgePackageSourceSha",
            "tenantId","bridgeIdentityResourceId","bridgeClientId","bridgePrincipalId","activationFenceAccount","activationFenceContainer",
            "activationFenceBlob","activationFenceEtag","activationFenceVersionId","activationFenceBodySha256","activationFenceLeaseId",
            "leaseDurationSeconds","leaseRenewalCount"}
    idle_sha=hashlib.sha256(core.canonical(azure.BlobActivationFence.INITIAL_IDLE)).hexdigest()
    if (not isinstance(control,dict) or set(control)!=fields or control.get("schemaVersion")!=1 or control.get("mode")!="package-fetch-self-test"
            or not core.GUID.fullmatch(str(control.get("authorizationId"))) or not core.SHA256.fullmatch(str(control.get("authorizationSha256")))
            or control.get("siteName")!=core.FIXED_COORDS["bridgeApp"] or control.get("siteName")!=os.environ.get("WEBSITE_SITE_NAME")
            or not core.SHA256.fullmatch(str(control.get("packageSha256"))) or control.get("packageSha256")!=os.environ.get("PAPERDESK_BRIDGE_PACKAGE_SHA256")
            or not core.NONCE.fullmatch(str(control.get("nonce"))) or not core.SHA256.fullmatch(str(control.get("planSha256")))
            or not core.SHA40.fullmatch(str(control.get("bridgePackageSourceSha"))) or control.get("tenantId")!=BOOTSTRAP_TENANT_ID
            or control.get("bridgeIdentityResourceId")!=BOOTSTRAP_BRIDGE_IDENTITY_RESOURCE_ID
            or not core.GUID.fullmatch(str(control.get("bridgeClientId"))) or not core.GUID.fullmatch(str(control.get("bridgePrincipalId")))
            or control.get("bridgeClientId")==control.get("bridgePrincipalId")
            or control.get("activationFenceAccount")!=core.FIXED_COORDS["packageAccount"]
            or control.get("activationFenceContainer")!=core.FIXED_COORDS["activationFenceContainer"]
            or control.get("activationFenceBlob")!=core.FIXED_COORDS["activationFenceBlob"]
            or not isinstance(control.get("activationFenceEtag"),str) or re.fullmatch(r'"[^"\r\n]{1,256}"',control["activationFenceEtag"]) is None
            or not isinstance(control.get("activationFenceVersionId"),str) or re.fullmatch(r"[A-Za-z0-9._:-]{1,256}",control["activationFenceVersionId"]) is None
            or control.get("activationFenceBodySha256")!=idle_sha or control.get("activationFenceLeaseId")!=BOOTSTRAP_FENCE_LEASE_ID
            or control.get("leaseDurationSeconds")!=60 or control.get("leaseRenewalCount")!=1
            or core.canonical(control).decode()!=raw):core.fail("entry-bootstrap-self-test")
    issued=core.parse_time(control.get("issuedAt"),"entry-bootstrap-self-test-issued");expires=core.parse_time(control.get("expiresAt"),"entry-bootstrap-self-test-expires")
    now=dt.datetime.now(dt.timezone.utc)
    if expires<=issued or (expires-issued).total_seconds()>900 or now<issued-dt.timedelta(seconds=30) or now>=expires:core.fail("entry-bootstrap-self-test-time")
    forbidden=("PAPERDESK_PRIVATE_RELEASE_ACTIVATION_JSON","PAPERDESK_CONTROL_WORKFLOW_SHA","PAPERDESK_TRANSIENT_GITHUB_TOKEN",
               "PAPERDESK_PRIVATE_RELEASE_PROVISIONING_EVIDENCE_JSON","PAPERDESK_PRIVATE_RELEASE_PROVISIONING_EVIDENCE_SHA256",
               "PAPERDESK_PRIVATE_RELEASE_BRIDGE_RUNTIME_RECEIPT_JSON","PAPERDESK_PRIVATE_RELEASE_BRIDGE_RUNTIME_RECEIPT_SHA256",
               "PAPERDESK_PRIVATE_RELEASE_CONTROL_JSON")
    if any(os.environ.get(name) for name in forbidden):core.fail("entry-bootstrap-self-test-privileged-state")
    endpoint=os.environ.get("IDENTITY_ENDPOINT","");header=os.environ.get("IDENTITY_HEADER","")
    bridge_tokens=azure.ManagedIdentityTokens(client_id=control["bridgeClientId"],principal_id=control["bridgePrincipalId"],tenant_id=control["tenantId"],endpoint=endpoint,identity_header=header)
    identity=bridge_tokens.identity_projection(azure.STORAGE)
    if (not isinstance(identity,dict) or set(identity)!={"clientId","principalId","tenantId","audience"}
            or identity["clientId"]!=control["bridgeClientId"] or identity["principalId"]!=control["bridgePrincipalId"]
            or identity["tenantId"]!=control["tenantId"] or identity["audience"] not in {azure.STORAGE,azure.STORAGE.rstrip("/")}):core.fail("entry-bootstrap-self-test-identity")
    fence=azure.BlobActivationFence(control["activationFenceAccount"],control["activationFenceContainer"],control["activationFenceBlob"],bridge_tokens)
    canary=fence.bootstrap_canary(lease_id=control["activationFenceLeaseId"],duration_seconds=control["leaseDurationSeconds"],renewal_count=control["leaseRenewalCount"],
                                  expected_etag=control["activationFenceEtag"],expected_version_id=control["activationFenceVersionId"],expected_body_sha256=control["activationFenceBodySha256"],deadline=control["expiresAt"])
    marker={"schemaVersion":1,"status":"bootstrap-bridge-canary-complete","control":control,"controlSha256":hashlib.sha256(raw.encode()).hexdigest(),
            "packageExecution":{"status":"executed-from-exact-versioned-run-from-package","packageSha256":control["packageSha256"],"sourceSha":control["bridgePackageSourceSha"]},
            "bridgeIdentity":{"resourceId":control["bridgeIdentityResourceId"],**identity},"activationFenceCanary":canary,
            "startedAt":now.strftime("%Y-%m-%dT%H:%M:%S.")+f"{now.microsecond//1000:03d}Z","completedAt":canary["completedAt"]}
    sys.stdout.write(core.canonical(marker).decode());return marker
def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--process-pending",action="store_true",required=True); args=parser.parse_args()
    verify_members()
    bootstrap_control=os.environ.get("PAPERDESK_BRIDGE_BOOTSTRAP_SELF_TEST_JSON","")
    if bootstrap_control:
        run_bootstrap_self_test(bootstrap_control);return
    activation_raw=os.environ.get("PAPERDESK_PRIVATE_RELEASE_ACTIVATION_JSON","");activation_doc=load_env_json("PAPERDESK_PRIVATE_RELEASE_ACTIVATION_JSON")
    workflow_sha=os.environ.get("PAPERDESK_CONTROL_WORKFLOW_SHA",""); package_sha=os.environ.get("PAPERDESK_BRIDGE_PACKAGE_SHA256","")
    evidence_raw=os.environ.get("PAPERDESK_PRIVATE_RELEASE_PROVISIONING_EVIDENCE_JSON","")
    evidence_sha=os.environ.get("PAPERDESK_PRIVATE_RELEASE_PROVISIONING_EVIDENCE_SHA256","")
    if not evidence_raw or len(evidence_raw)>2*1024*1024 or not core.SHA256.fullmatch(evidence_sha) or hashlib.sha256(evidence_raw.encode()).hexdigest()!=evidence_sha:core.fail("entry-provisioning-evidence")
    try:provisioning_evidence=json.loads(evidence_raw)
    except Exception:core.fail("entry-provisioning-evidence")
    if core.canonical(provisioning_evidence).decode()!=evidence_raw:core.fail("entry-provisioning-evidence-canonical")
    activation=core.load_activation_document(activation_doc,runtime_workflow_sha=workflow_sha,observed_bridge_package_sha256=package_sha,provisioning_evidence=provisioning_evidence,raw_document=activation_raw)
    receipt_raw=os.environ.get("PAPERDESK_PRIVATE_RELEASE_BRIDGE_RUNTIME_RECEIPT_JSON","")
    receipt_sha=os.environ.get("PAPERDESK_PRIVATE_RELEASE_BRIDGE_RUNTIME_RECEIPT_SHA256","")
    if not receipt_raw or len(receipt_raw)>262144 or not core.SHA256.fullmatch(receipt_sha) or hashlib.sha256(receipt_raw.encode()).hexdigest()!=receipt_sha:core.fail("entry-bridge-runtime-receipt")
    try:bridge_runtime_receipt=json.loads(receipt_raw)
    except Exception:core.fail("entry-bridge-runtime-receipt")
    if core.canonical(bridge_runtime_receipt).decode()!=receipt_raw:core.fail("entry-bridge-runtime-receipt-canonical")
    core.validate_bridge_runtime_receipt(bridge_runtime_receipt,activation)
    endpoint=os.environ.get("IDENTITY_ENDPOINT",""); header=os.environ.get("IDENTITY_HEADER","")
    bridge_tokens=azure.ManagedIdentityTokens(client_id=activation.bridge_client_id,principal_id=activation.bridge_principal_id,tenant_id=activation.tenant_id,endpoint=endpoint,identity_header=header)
    writer_tokens=azure.ManagedIdentityTokens(client_id=activation.registry_writer_client_id,principal_id=activation.registry_writer_principal_id,tenant_id=activation.tenant_id,endpoint=endpoint,identity_header=header)
    reader_tokens=azure.ManagedIdentityTokens(client_id=activation.registry_reader_client_id,principal_id=activation.registry_reader_principal_id,tenant_id=activation.tenant_id,endpoint=endpoint,identity_header=header)
    signer_tokens=azure.ManagedIdentityTokens(client_id=activation.signer_client_id,principal_id=activation.signer_principal_id,tenant_id=activation.tenant_id,endpoint=endpoint,identity_header=header)
    production_tokens=azure.ManagedIdentityTokens(client_id=activation.production_activation_client_id,principal_id=activation.production_activation_principal_id,tenant_id=activation.tenant_id,endpoint=endpoint,identity_header=header)
    arm=core.MailboxClient(activation.mailbox_resource_group,azure.ArmTransport(bridge_tokens),request_creator=activation.publisher_principal_id,result_creator=activation.bridge_principal_id)
    fixed=activation_doc["fixed"]
    registry_worm=azure.BlobWorm(fixed["registryAccount"],fixed["registryContainer"],writer_tokens,reader_tokens)
    package_worm=azure.BlobWorm(fixed["packageAccount"],fixed["packageContainer"],writer_tokens,reader_tokens)
    activation_fence=azure.BlobActivationFence(fixed["packageAccount"],fixed["activationFenceContainer"],fixed["activationFenceBlob"],bridge_tokens)
    github_token=os.environ.get("PAPERDESK_TRANSIENT_GITHUB_TOKEN","")
    control_raw=os.environ.get("PAPERDESK_PRIVATE_RELEASE_CONTROL_JSON","")
    if not control_raw or len(control_raw)>32768:core.fail("entry-control")
    try:control_doc=json.loads(control_raw)
    except Exception:core.fail("entry-control-json")
    now=dt.datetime.now(dt.timezone.utc)
    control=core.validate_transient_control(control_doc,raw=control_raw,github_token=github_token,now=now,activation=activation)
    artifact=azure.GitHubArtifactReader(github_token,azure.NoRedirectHttp())
    run_id=os.environ.get("WEBJOBS_RUN_ID","")
    runtime.process_authorized(control,arm_mailbox=arm,activation=activation,now=now,registry_worm=registry_worm,package_worm=package_worm,activation_fence=activation_fence,production_activation=azure.ProductionActivation(azure.ArmTransport(production_tokens),activation),key_reader=azure.KeyVaultKeyReader(bridge_tokens,activation),artifact_reader=artifact,signer=azure.KeyVaultSigner(signer_tokens),signing_key_id=activation.signing_key_id,signing_key_version=activation.signing_key_version,webjob_history_id=run_id,webjob_run_id=run_id)
if __name__=="__main__": main()
