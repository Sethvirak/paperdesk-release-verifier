"""Dormant inside-VNet processor for the private release mailbox contract.

All network/storage/Key Vault boundaries are injected.  The deployed wrapper may
construct them only after the reviewed activation contract is complete; this
module itself neither acquires a credential nor contacts Azure.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

try: from scripts import private_release_mailbox as mailbox
except ModuleNotFoundError: import private_release_mailbox as mailbox


def utc_millis(value: dt.datetime) -> str:
    if value.tzinfo is None:
        mailbox.fail("bridge-timezone")
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]+"Z"


def result_name(request: dict[str, Any]) -> str:
    return f"pdres-{request['sourceRunId']}-{request['sourceRunAttempt']}-{request['nonce']}"


def process_request(
    request_name: str,
    *,
    activation: mailbox.Activation,
    now: dt.datetime,
    arm_mailbox: Any,
    transient_control: dict[str, Any],
    registry_worm: Any,
    package_worm: Any,
    activation_fence: Any,
    production_activation: Any,
    key_reader: Any,
    artifact_reader: Any,
    signer: Any,
    signing_key_id: str,
    signing_key_version: str,
    webjob_history_id: str,
    webjob_run_id: str,
) -> dict[str, Any]:
    """Read, execute, sign, and create one result deployment.

    `artifact_reader` returns the exact named artifact member after applying
    its own outer/member digest and provenance checks. `signer` is the Key Vault PS256
    boundary and receives only canonical result bytes plus the exact key version.
    """
    if not isinstance(activation,mailbox.Activation): mailbox.fail("bridge-not-activated")
    if signing_key_id!=activation.signing_key_id or signing_key_version!=activation.signing_key_version: mailbox.fail("bridge-signing-coordinate")
    if not mailbox.NAME.fullmatch(request_name) or not request_name.startswith("pdreq-"):
        mailbox.fail("bridge-request-name")
    # The exact versioned public key is proven through Key Vault's data plane
    # before the first mailbox, artifact, Storage, or production operation.
    # This read uses the bridge's keys/read-only role; the signer stays
    # independently sign-only.
    live_key=key_reader()
    mailbox.validate_live_signing_key(live_key,activation,now=now)
    raw_request=arm_mailbox.get(request_name)
    request,request_raw,request_sha=mailbox.validate_request(raw_request,now=now)
    if request["controlWorkflowSha"]!=activation.workflow_sha: mailbox.fail("bridge-control-sha")
    expected_name=f"pdreq-{request['sourceRunId']}-{request['sourceRunAttempt']}-{request['nonce']}"
    if request_name!=expected_name: mailbox.fail("bridge-request-coordinate")
    operation=request["operation"]
    if operation in {"bootstrap-prepare","prepare-candidate","persist-accepted-release"}:
        tar_gz=artifact_reader(request)
        if not isinstance(tar_gz,bytes) or mailbox.digest(tar_gz)!=request["artifactMemberSha256"]: mailbox.fail("bridge-artifact")
    if operation=="registry-bridge-preflight":
        durable=mailbox.registry_bridge_preflight(registry_worm,request,now=now,package_boundary=package_worm,production_observe=production_activation.observe)
    elif operation=="bootstrap-prepare": durable=mailbox.prepare_bootstrap(registry_worm,request,tar_gz,now=now,package_boundary=package_worm)
    elif operation=="bootstrap-consume":
        accepted,baseline=mailbox._read_json(registry_worm,request["acceptedBaseline"],"bootstrap-finalize-baseline")
        profile={"sourceSha":baseline["sourceSha"],"baselineMode":"bootstrap","servedIndexSha256":baseline["servedIndexSha256"],"oneDeployInvariant":baseline["oneDeployInvariant"],"deploymentBundle":baseline["deploymentBundle"]}
        settlement=production_activation.observe(profile)
        if settlement.get("healthy") is not True:mailbox.fail("bootstrap-live-proof")
        durable=mailbox.consume_bootstrap(registry_worm,request,now=now,activation_proof=settlement["proof"])
        durable["metadata"]["activationStatus"]="observed";durable["metadata"]["activationProof"]=settlement["proof"]
    elif operation=="prepare-candidate":
        durable=mailbox.prepare_candidate(registry_worm,request,tar_gz,now=now,package_boundary=package_worm)
        if durable["metadata"]["terminalState"]=="consumed":
            durable["metadata"]["activationPlan"]=mailbox.activation_plan_from_fence(durable["metadata"]["terminalActivationFence"])
        else:
            settings,settings_sha=production_activation.observe_settings()
            if not isinstance(settings,dict) or settings_sha!=mailbox.digest(mailbox.canonical(settings)):mailbox.fail("bridge-production-settings")
            orphan=activation_fence.recover_plan(operation="candidate",source_sha=request["sourceSha"],pending_release=durable["records"]["pendingRelease"])
            if orphan is not None:
                plan=mailbox.validate_activation_plan(orphan,"bridge-candidate-orphan-plan")
                if settings_sha not in {plan["preSettingsSha256"],plan["desiredSettingsSha256"]}:mailbox.fail("bridge-candidate-orphan-third-state")
                if settings_sha==plan["desiredSettingsSha256"] and (settings.get("WEBSITE_RUN_FROM_PACKAGE")!=mailbox.package_url(durable["records"]["deploymentBundle"]) or settings.get("WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID")!="SystemAssigned"):mailbox.fail("bridge-candidate-orphan-target")
                durable["metadata"]["activationPlan"]=plan
            else:
                desired=dict(settings);desired["WEBSITE_RUN_FROM_PACKAGE"]=mailbox.package_url(durable["records"]["deploymentBundle"]);desired["WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID"]="SystemAssigned"
                durable["metadata"]["activationPlan"]={"blob":mailbox.FIXED_COORDS["activationFenceBlob"],"operation":"candidate","sourceSha":request["sourceSha"],"release":durable["records"]["pendingRelease"],"preSettingsSha256":settings_sha,"desiredSettingsSha256":mailbox.digest(mailbox.canonical(desired))}
            mailbox.validate_activation_plan(durable["metadata"]["activationPlan"])
    elif operation=="consume-candidate":
        accepted,baseline,_,_=mailbox._load_accepted(registry_worm,request["acceptedBaseline"],package_worm)
        pending,pending_doc=mailbox._read_json(registry_worm,request["pendingRelease"],"activate-pending")
        baseline_profile={"sourceSha":baseline["sourceSha"],"baselineMode":baseline["baselineMode"],"servedIndexSha256":baseline["servedIndexSha256"],"oneDeployInvariant":baseline["oneDeployInvariant"],"deploymentBundle":baseline["deploymentBundle"]}
        target_profile={"sourceSha":pending_doc["sourceSha"],"baselineMode":"strict","servedIndexSha256":pending_doc["servedIndexSha256"],"oneDeployInvariant":pending_doc["oneDeployInvariant"],"deploymentBundle":pending_doc["deploymentBundle"]}
        terminal_blob=str(mailbox.PurePosixPath(pending.blob).parent/"consumed.json")
        terminal=mailbox._read_current(registry_worm,terminal_blob)
        if terminal is not None:
            _,terminal_doc=mailbox._read_json(registry_worm,mailbox._worm_descriptor(terminal),"activate-consumed-recovery")
            terminal_fence=mailbox.validate_activation_fence(terminal_doc.get("activationFence"),"activate-consumed-recovery-fence")
            if mailbox.activation_plan_from_fence(terminal_fence)!=request["activationPlan"]:mailbox.fail("activate-consumed-recovery-fence")
            settlement=production_activation.observe(target_profile)
            if settlement.get("healthy") is not True or settlement.get("sourceSha")!=request["sourceSha"]:mailbox.fail("activate-consumed-live-drift")
            proof=terminal_doc["activationProof"]
            durable=mailbox.consume_candidate(registry_worm,request,now=now,activation_proof=proof,activation_fence=terminal_fence)
            activation_fence.complete(terminal_fence,status="consumed",proof_sha256=mailbox.digest(mailbox.canonical(proof)))
            activation_result={"status":"consumed","sourceSha":request["sourceSha"],"configDigest":terminal_fence["desiredSettingsSha256"],"settlement":settlement,"consumption":{"status":"complete","durable":durable}}
            active_fence=terminal_fence
        else:
            plan=mailbox.validate_activation_plan(request["activationPlan"])
            observed,observed_sha=production_activation.observe_settings()
            if observed_sha==plan["preSettingsSha256"]:
                desired=dict(observed);desired["WEBSITE_RUN_FROM_PACKAGE"]=mailbox.package_url(pending_doc["deploymentBundle"]);desired["WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID"]="SystemAssigned"
                if mailbox.digest(mailbox.canonical(desired))!=plan["desiredSettingsSha256"]:mailbox.fail("activate-plan-drift")
            elif observed_sha==plan["desiredSettingsSha256"]:
                if observed.get("WEBSITE_RUN_FROM_PACKAGE")!=mailbox.package_url(pending_doc["deploymentBundle"]) or observed.get("WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID")!="SystemAssigned":mailbox.fail("activate-prestate-third-state")
            else:mailbox.fail("activate-prestate-third-state")
            active_fence=activation_fence.acquire(operation="candidate",source_sha=request["sourceSha"],pending_release=request["pendingRelease"],pre_settings_sha256=plan["preSettingsSha256"],desired_settings_sha256=plan["desiredSettingsSha256"])
            if mailbox.activation_plan_from_fence(active_fence)!=plan:mailbox.fail("activate-fence-plan")
            production_activation.bind_fence(activation_fence,active_fence)
            def consume(settlement):
                activation_fence.renew(active_fence)
                committed=mailbox.consume_candidate(registry_worm,request,now=now,activation_proof=settlement["proof"],activation_fence=active_fence)
                activation_fence.complete(active_fence,status="consumed",proof_sha256=mailbox.digest(mailbox.canonical(settlement["proof"])))
                return {"status":"complete","durable":committed}
            def abort(settlement):
                activation_fence.renew(active_fence)
                abort_request=dict(request);abort_request["operation"]="abort-candidate"
                aborted=mailbox.abort_candidate(registry_worm,abort_request,now=now,activation_proof=settlement["proof"],activation_fence=active_fence)
                activation_fence.complete(active_fence,status="aborted",proof_sha256=mailbox.digest(mailbox.canonical(settlement["proof"])))
                return {"status":"complete","durable":aborted}
            activation_result=mailbox.activate_run_from_package(source_sha=request["sourceSha"],baseline=baseline_profile,target=target_profile,activation_fence=active_fence,system_identity_principal=activation.production_principal_id,config_read=production_activation.read,config_put=production_activation.put,restart=production_activation.restart,probe=production_activation.probe,consume=consume,abort=abort)
            durable=activation_result["consumption"]["durable"]
        durable["metadata"].update({"operation":"consume-candidate","activationStatus":activation_result["status"],"preSettingsSha256":active_fence["preSettingsSha256"],"desiredSettingsSha256":active_fence["desiredSettingsSha256"],"finalSettingsSha256":activation_result["configDigest"],"activationProof":activation_result["settlement"].get("proof")})
    elif operation=="abort-candidate":mailbox.fail("bridge-external-abort-forbidden")
    elif operation=="persist-accepted-release": durable=mailbox.persist_accepted_release(registry_worm,request,tar_gz,now=now,package_boundary=package_worm)
    elif operation=="prepare-rollback":
        durable=mailbox.prepare_rollback(registry_worm,request,now=now,package_boundary=package_worm)
        if durable["metadata"]["terminalState"]=="completed":
            durable["metadata"]["activationPlan"]=mailbox.activation_plan_from_fence(durable["metadata"]["terminalActivationFence"])
        else:
            settings,settings_sha=production_activation.observe_settings()
            if not isinstance(settings,dict) or settings_sha!=mailbox.digest(mailbox.canonical(settings)):mailbox.fail("bridge-production-settings")
            orphan=activation_fence.recover_plan(operation="rollback",source_sha=request["sourceSha"],pending_release=durable["records"]["manifest"])
            if orphan is not None:
                plan=mailbox.validate_activation_plan(orphan,"bridge-rollback-orphan-plan")
                if settings_sha not in {plan["preSettingsSha256"],plan["desiredSettingsSha256"]}:mailbox.fail("bridge-rollback-orphan-third-state")
                if settings_sha==plan["desiredSettingsSha256"] and (settings.get("WEBSITE_RUN_FROM_PACKAGE")!=mailbox.package_url(durable["records"]["deploymentBundle"]) or settings.get("WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID")!="SystemAssigned"):mailbox.fail("bridge-rollback-orphan-target")
                durable["metadata"]["activationPlan"]=plan
            else:
                desired=dict(settings);desired["WEBSITE_RUN_FROM_PACKAGE"]=mailbox.package_url(durable["records"]["deploymentBundle"]);desired["WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID"]="SystemAssigned"
                durable["metadata"]["activationPlan"]={"blob":mailbox.FIXED_COORDS["activationFenceBlob"],"operation":"rollback","sourceSha":request["sourceSha"],"release":durable["records"]["manifest"],"preSettingsSha256":settings_sha,"desiredSettingsSha256":mailbox.digest(mailbox.canonical(desired))}
            mailbox.validate_activation_plan(durable["metadata"]["activationPlan"])
    elif operation=="complete-rollback":
        accepted,baseline,_,_=mailbox._load_accepted(registry_worm,request["acceptedBaseline"],package_worm)
        target={"sourceSha":baseline["sourceSha"],"baselineMode":baseline["baselineMode"],"servedIndexSha256":baseline["servedIndexSha256"],"oneDeployInvariant":baseline["oneDeployInvariant"],"deploymentBundle":baseline["deploymentBundle"]}
        terminal_blob=str(mailbox.PurePosixPath(request["rollbackPreparation"]["blob"]).parent/"completed.json")
        terminal=mailbox._read_current(registry_worm,terminal_blob)
        if terminal is not None:
            _,terminal_doc=mailbox._read_json(registry_worm,mailbox._worm_descriptor(terminal),"rollback-completed-recovery")
            if (terminal_doc.get("rollbackPreparation")!=request["rollbackPreparation"]
                    or terminal_doc.get("acceptedBaseline")!=mailbox._worm_descriptor(accepted)
                    or mailbox.activation_plan_from_fence(terminal_doc.get("activationFence"))!=request["activationPlan"]):mailbox.fail("rollback-completed-recovery-binding")
            terminal_fence=mailbox.validate_activation_fence(terminal_doc["activationFence"],"rollback-completed-recovery-fence")
            settlement=production_activation.observe(target)
            if settlement.get("healthy") is not True or settlement.get("sourceSha")!=request["sourceSha"]:mailbox.fail("rollback-completed-live-drift")
            proof=terminal_doc["activationProof"]
            durable=mailbox.complete_rollback(registry_worm,request,now=now,activation_proof=proof,activation_fence=terminal_fence)
            activation_fence.complete(terminal_fence,status="rollback-complete",proof_sha256=mailbox.digest(mailbox.canonical(proof)))
            activation_result={"status":"complete","sourceSha":request["sourceSha"],"configDigest":terminal_fence["desiredSettingsSha256"],"settlement":settlement,"completion":{"status":"complete","durable":durable}}
            active_fence=terminal_fence
        else:
            plan=mailbox.validate_activation_plan(request["activationPlan"])
            observed,observed_sha=production_activation.observe_settings()
            if observed_sha==plan["preSettingsSha256"]:
                desired=dict(observed);desired["WEBSITE_RUN_FROM_PACKAGE"]=mailbox.package_url(baseline["deploymentBundle"]);desired["WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID"]="SystemAssigned"
                if mailbox.digest(mailbox.canonical(desired))!=plan["desiredSettingsSha256"]:mailbox.fail("rollback-plan-drift")
            elif observed_sha==plan["desiredSettingsSha256"]:
                if observed.get("WEBSITE_RUN_FROM_PACKAGE")!=mailbox.package_url(baseline["deploymentBundle"]) or observed.get("WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID")!="SystemAssigned":mailbox.fail("rollback-third-state")
            else:mailbox.fail("rollback-third-state")
            active_fence=activation_fence.acquire(operation="rollback",source_sha=request["sourceSha"],pending_release=request["rollbackPreparation"],pre_settings_sha256=plan["preSettingsSha256"],desired_settings_sha256=plan["desiredSettingsSha256"])
            if mailbox.activation_plan_from_fence(active_fence)!=plan:mailbox.fail("rollback-fence-plan")
            production_activation.bind_fence(activation_fence,active_fence)
            def complete(settlement):
                activation_fence.renew(active_fence)
                committed=mailbox.complete_rollback(registry_worm,request,now=now,activation_proof=settlement["proof"],activation_fence=active_fence)
                activation_fence.complete(active_fence,status="rollback-complete",proof_sha256=mailbox.digest(mailbox.canonical(settlement["proof"])))
                return {"status":"complete","durable":committed}
            activation_result=mailbox.rollback_run_from_package(target=target,activation_fence=active_fence,system_identity_principal=activation.production_principal_id,config_read=production_activation.read,config_put=production_activation.put,restart=production_activation.restart,probe=production_activation.probe,complete=complete)
            durable=activation_result["completion"]["durable"]
        durable["metadata"].update({"operation":"complete-rollback","activationStatus":"complete","preSettingsSha256":active_fence["preSettingsSha256"],"desiredSettingsSha256":active_fence["desiredSettingsSha256"],"finalSettingsSha256":activation_result["configDigest"],"activationProof":activation_result["settlement"].get("proof")})
    else: mailbox.fail("bridge-operation")
    durable=mailbox.attach_cleanup_obligation(registry_worm,request,durable,transient_control)
    result={
        "schemaVersion":1,"resultType":"paperdesk-private-release-result","status":"complete",
        "requestSha256":request_sha,"operation":request["operation"],"nonce":request["nonce"],
        "controlWorkflowSha":request["controlWorkflowSha"],"sourceSha":request["sourceSha"],
        "webJobHistoryId":webjob_history_id,"webJobRunId":webjob_run_id,
        "records":durable["records"],"metadata":durable["metadata"],
        "observedAt":utc_millis(now),
    }
    result_raw=mailbox.validate_result(result,request)
    signature=signer(result_raw,key_id=signing_key_id,key_version=signing_key_version,algorithm="PS256")
    envelope={"result":result,"signature":{"algorithm":"PS256","keyId":signing_key_id,"keyVersion":signing_key_version,"value":signature}}
    arm_mailbox.put_create_or_read_exact(result_name(request),envelope)
    return envelope


def process_pending(*,arm_mailbox: Any, limit: int = 20, **boundaries: Any) -> list[dict[str, Any]]:
    """Process a bounded newest window; isolate rejected/stale requests.

    `arm_mailbox.get` still authenticates every request deployment's exact
    creator and immutable systemData before any artifact or storage access.
    Rejected requests are not silently deleted; the external controller owns
    deletion, while later run IDs continue to make progress.
    """
    names=mailbox.pending_request_names(arm_mailbox.list(),limit=limit)
    outcomes=[]
    for name in names:
        try:outcomes.append({"status":"complete","requestNameSha256":mailbox.digest(name.encode()),"envelope":process_request(name,arm_mailbox=arm_mailbox,**boundaries)})
        except mailbox.MailboxError as error:outcomes.append({"status":"rejected","requestNameSha256":mailbox.digest(name.encode()),"errorCode":str(error)[:128]})
        except Exception:outcomes.append({"status":"rejected","requestNameSha256":mailbox.digest(name.encode()),"errorCode":"unexpected-boundary-error"})
    return outcomes


class _AuthorizedMailbox:
    """Bind the single mailbox read to the transient control in-line.

    ``process_request`` retains ownership of the Key Vault-first ordering.  The
    proxy checks the control binding on that same subsequent ARM read and
    forwards the result write, avoiding the former pre-key duplicate read.
    """
    def __init__(self,delegate: Any,control: dict[str,Any]):
        self.delegate=delegate;self.control=control
    def get(self,name: str) -> dict[str,Any]:
        request=self.delegate.get(name)
        if (not isinstance(request,dict) or request.get("operation")!=self.control.get("operation")
                or request.get("sourceSha")!=self.control.get("sourceSha")):mailbox.fail("bridge-authorized-request-binding")
        return request
    def put_create_or_read_exact(self,name: str,envelope: dict[str,Any]):
        return self.delegate.put_create_or_read_exact(name,envelope)


def process_authorized(control: dict[str, Any], *, arm_mailbox: Any, **boundaries: Any) -> dict[str, Any]:
    """Process only the request named by the exact transient control record.

    Other authenticated mailbox entries are deliberately left inert.  This
    prevents a stale request from borrowing the current run's GitHub token or
    acquiring the production activation fence.
    """
    name=control.get("requestName") if isinstance(control,dict) else None
    if not isinstance(name,str) or not mailbox.NAME.fullmatch(name) or not name.startswith("pdreq-"):mailbox.fail("bridge-authorized-request")
    envelope=process_request(name,arm_mailbox=_AuthorizedMailbox(arm_mailbox,control),transient_control=control,**boundaries)
    return {"status":"complete","requestNameSha256":mailbox.digest(name.encode()),"envelope":envelope}
