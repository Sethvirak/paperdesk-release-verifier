"""Concrete standard-library Azure boundaries for the private VNet bridge."""
from __future__ import annotations
import base64, datetime as dt, hashlib, io, json, re, time, urllib.error, urllib.parse, urllib.request, uuid, zipfile
try: from scripts import private_release_mailbox as core
except ModuleNotFoundError: import private_release_mailbox as core

ARM="https://management.azure.com/"; STORAGE="https://storage.azure.com/"; VAULT="https://vault.azure.net"
def _json(raw,label):
    try: return json.loads(raw)
    except Exception: core.fail(label)
def _b64(value): return base64.urlsafe_b64encode(value).rstrip(b"=").decode()
def _header(response,name): return next((value for key,value in response.headers.items() if key.lower()==name.lower()),None)
def _claims(token):
    parts=token.split(".")
    if len(parts)!=3: core.fail("token-jwt")
    return _json(core.b64u_decode(parts[1],"token-claims"),"token-claims")

class Http:
    def __call__(self,method,url,headers,body=None):
        request=urllib.request.Request(url,data=body,headers=dict(headers),method=method)
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request,timeout=30) as response:
                return core.Response(response.status,url,response.read(core.MAX_RESULT*2000+1),dict(response.headers))
        except urllib.error.HTTPError as error:
            return core.Response(error.code,url,error.read(core.MAX_RESULT*2+1),dict(error.headers))

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl): return None
class NoRedirectHttp(Http):
    def __call__(self,method,url,headers,body=None):
        request=urllib.request.Request(url,data=body,headers=dict(headers),method=method)
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),_NoRedirect())
        try:
            with opener.open(request,timeout=30) as response: return core.Response(response.status,url,response.read(core.MAX_ZIP+1),dict(response.headers))
        except urllib.error.HTTPError as error: return core.Response(error.code,url,error.read(core.MAX_ZIP+1),dict(error.headers))

class ManagedIdentityTokens:
    def __init__(self,*,client_id,principal_id,tenant_id,endpoint,identity_header,transport=None,clock=time.time):
        if not core.GUID.fullmatch(client_id) or not core.GUID.fullmatch(principal_id) or not core.GUID.fullmatch(tenant_id): core.fail("identity-coordinate")
        parsed=urllib.parse.urlparse(endpoint)
        if parsed.scheme!="http" or parsed.hostname not in {"127.0.0.1","localhost","169.254.169.254"} or parsed.username or parsed.password: core.fail("identity-endpoint")
        if parsed.hostname!="169.254.169.254" and (not identity_header or "\r" in identity_header or "\n" in identity_header): core.fail("identity-header")
        self.client_id=client_id; self.principal_id=principal_id; self.tenant_id=tenant_id; self.endpoint=endpoint; self.header=identity_header; self.transport=transport or Http(); self.clock=clock; self.cache={}
    def get(self,resource):
        if resource not in {ARM,STORAGE,VAULT}: core.fail("token-resource")
        cached=self.cache.get(resource); now=int(self.clock())
        if cached and cached[1]-now>300: return cached[0]
        query=urllib.parse.urlencode({"api-version":"2019-08-01","resource":resource,"client_id":self.client_id})
        identity_headers={"Metadata":"true"} if urllib.parse.urlparse(self.endpoint).hostname=="169.254.169.254" else {"X-IDENTITY-HEADER":self.header}
        response=self.transport("GET",self.endpoint+("&" if "?" in self.endpoint else "?")+query,identity_headers,None)
        if response.status!=200 or len(response.body)>65536: core.fail("token-response")
        doc=_json(response.body,"token-json"); token=doc.get("access_token") if isinstance(doc,dict) else None
        claims=_claims(token) if isinstance(token,str) else {}
        if claims.get("aud") not in {resource.rstrip("/"),resource}: core.fail("token-audience")
        if (claims.get("tid")!=self.tenant_id or claims.get("appid")!=self.client_id
                or (claims.get("azp") is not None and claims.get("azp")!=self.client_id)
                or claims.get("oid")!=self.principal_id or claims.get("sub")!=self.principal_id
                or claims.get("idtyp")!="app"): core.fail("token-identity")
        exp=claims.get("exp"); nbf=claims.get("nbf",0)
        if type(exp) is not int or type(nbf) is not int or nbf>now+30 or exp<=now+300: core.fail("token-time")
        self.cache[resource]=(token,exp); return token

class ArmTransport:
    def __init__(self,tokens,http=None): self.tokens=tokens; self.http=http or Http()
    def __call__(self,method,url,headers,body=None):
        if not url.startswith("https://management.azure.com/"): core.fail("arm-url")
        bound=dict(headers); bound["Authorization"]="Bearer "+self.tokens.get(ARM)
        return self.http(method,url,bound,body)

class BlobWorm:
    def __init__(self,account,container,writer_tokens,reader_tokens,http=None):
        if not re.fullmatch(r"[a-z0-9]{3,24}",account) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?",container): core.fail("blob-coordinate")
        if writer_tokens is reader_tokens: core.fail("blob-identity-separation")
        self.base=f"https://{account}.blob.core.windows.net/{container}/"; self.writer_tokens=writer_tokens; self.reader_tokens=reader_tokens; self.http=http or Http()
    def _url(self,blob,version_id=None):
        path=urllib.parse.quote(blob,safe="/-._")
        if path!=blob or ".." in blob.split("/"): core.fail("blob-name")
        return self.base+path+("?versionid="+urllib.parse.quote(version_id,safe="") if version_id else "")
    def create(self,blob,body,if_none_match):
        if if_none_match!="*": core.fail("blob-create-condition")
        headers={"Authorization":"Bearer "+self.writer_tokens.get(STORAGE),"x-ms-version":"2023-11-03","x-ms-date":dt.datetime.now(dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT"),"x-ms-blob-type":"BlockBlob","If-None-Match":"*","Content-Type":"application/octet-stream","Content-Length":str(len(body)),"x-ms-meta-sha256":core.digest(body)}
        response=self.http("PUT",self._url(blob),headers,body)
        if response.status!=201: core.fail("blob-create")
        etag=_header(response,"ETag"); version=_header(response,"x-ms-version-id")
        if not etag or not version: core.fail("blob-create-proof")
        return core.WormRecord(blob,body,etag,version)
    def read(self,blob,version_id):
        headers={"Authorization":"Bearer "+self.reader_tokens.get(STORAGE),"x-ms-version":"2023-11-03","x-ms-date":dt.datetime.now(dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")}
        response=self.http("GET",self._url(blob,version_id),headers,None)
        if response.status!=200: core.fail("blob-read")
        observed=_header(response,"x-ms-version-id")
        if observed!=version_id or _header(response,"x-ms-meta-sha256")!=core.digest(response.body): core.fail("blob-version-digest")
        return core.WormRecord(blob,response.body,_header(response,"ETag") or "",observed)
    def read_current(self,blob):
        headers={"Authorization":"Bearer "+self.reader_tokens.get(STORAGE),"x-ms-version":"2023-11-03","x-ms-date":dt.datetime.now(dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")}
        response=self.http("GET",self._url(blob),headers,None)
        if response.status==404: core.fail("blob-not-found")
        if response.status!=200: core.fail("blob-read-current")
        version=_header(response,"x-ms-version-id")
        if not version or _header(response,"x-ms-meta-sha256")!=core.digest(response.body): core.fail("blob-current-digest")
        return core.WormRecord(blob,response.body,_header(response,"ETag") or "",version)

class BlobActivationFence:
    """Durable state plus a fresh finite lease for production mutations.

    A lease identifier is never derived from the release coordinate and a 409
    is never interpreted as ownership.  Terminal recovery may acquire a new
    finite lease only after the caller has validated the immutable terminal
    marker and supplies its exact proof digest to ``complete``.
    """
    def __init__(self,account,container,blob,tokens,http=None,uuid_factory=uuid.uuid4):
        if container!=core.FIXED_COORDS["activationFenceContainer"] or blob!=core.FIXED_COORDS["activationFenceBlob"]:core.fail("fence-coordinate")
        self.base=f"https://{account}.blob.core.windows.net/{container}/{blob}";self.blob=blob;self.tokens=tokens;self.http=http or Http();self.uuid_factory=uuid_factory
    def _headers(self):return {"Authorization":"Bearer "+self.tokens.get(STORAGE),"x-ms-version":"2023-11-03","x-ms-date":dt.datetime.now(dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")}
    def _read(self,lease_id=None):
        headers=self._headers()
        if lease_id:headers["x-ms-lease-id"]=lease_id
        response=self.http("GET",self.base,headers,None)
        if response.status!=200:core.fail("fence-read")
        if _header(response,"x-ms-meta-sha256")!=core.digest(response.body):core.fail("fence-digest")
        try:doc=json.loads(response.body)
        except Exception:core.fail("fence-json")
        if core.canonical(doc)!=response.body:core.fail("fence-canonical")
        etag=_header(response,"ETag")
        if not re.fullmatch(r'"[^"\r\n]+"',str(etag)):core.fail("fence-etag")
        return doc,etag
    def _write(self,doc,etag,lease_id):
        body=core.canonical(doc);headers=self._headers();headers.update({"x-ms-blob-type":"BlockBlob","x-ms-lease-id":lease_id,"If-Match":etag,"Content-Type":"application/json","Content-Length":str(len(body)),"x-ms-meta-sha256":core.digest(body)})
        response=self.http("PUT",self.base,headers,body)
        if response.status!=201:core.fail("fence-write")
        next_etag=_header(response,"ETag")
        observed,observed_etag=self._read(lease_id)
        if observed!=doc or observed_etag!=next_etag:core.fail("fence-write-readback")
        return observed_etag
    def _lease(self,action,lease_id):
        headers=self._headers();headers.update({"x-ms-lease-action":action,"x-ms-lease-id":lease_id})
        response=self.http("PUT",self.base+"?comp=lease",headers,b"")
        return response
    def _release_owned(self,lease_id):
        response=self._lease("release",lease_id)
        if response.status not in {200,202}:core.fail("fence-release")
    @staticmethod
    def _validate_state(state):
        required={"schemaVersion","state","stateVersion","operation","sourceSha","pendingRelease","preSettingsSha256","desiredSettingsSha256","leaseId","lastStatus","lastProofSha256"}
        if (not isinstance(state,dict) or set(state)!=required or state.get("schemaVersion")!=1
                or type(state.get("stateVersion")) is not int or state["stateVersion"]<0
                or state.get("state") not in {"idle","held"}):core.fail("fence-state")
        if state["state"]=="held":
            if (state.get("operation") not in {"candidate","rollback"} or not core.SHA40.fullmatch(str(state.get("sourceSha")))
                    or not core.GUID.fullmatch(str(state.get("leaseId"))) or not core.SHA256.fullmatch(str(state.get("preSettingsSha256")))
                    or not core.SHA256.fullmatch(str(state.get("desiredSettingsSha256"))) or state["preSettingsSha256"]==state["desiredSettingsSha256"]):core.fail("fence-state")
            core.validate_descriptor(state.get("pendingRelease"),"fence-state-release")
        elif any((state.get("operation"),state.get("sourceSha"),state.get("preSettingsSha256"),state.get("desiredSettingsSha256"),state.get("leaseId"))) or state.get("pendingRelease") is not None:
            core.fail("fence-state")
        return state
    def recover_plan(self,*,operation,source_sha,pending_release):
        """Return only an exact orphaned held plan; idle means no recovery."""
        state,_=self._read();self._validate_state(state)
        if state["state"]=="idle":return None
        if (state["operation"]!=operation or state["sourceSha"]!=source_sha or state["pendingRelease"]!=pending_release):core.fail("fence-busy")
        return {"blob":self.blob,"operation":operation,"sourceSha":source_sha,"release":dict(pending_release),
                "preSettingsSha256":state["preSettingsSha256"],"desiredSettingsSha256":state["desiredSettingsSha256"]}
    def assert_held(self,receipt):
        receipt=core.validate_activation_fence(receipt,"fence-renew-receipt")
        state,etag=self._read(receipt["leaseId"])
        if (state.get("state")!="held" or str(state.get("stateVersion"))!=receipt["stateVersion"]
                or state.get("operation")!=receipt["operation"] or state.get("sourceSha")!=receipt["sourceSha"]
                or state.get("pendingRelease")!=receipt["release"]
                or state.get("preSettingsSha256")!=receipt["preSettingsSha256"]
                or state.get("desiredSettingsSha256")!=receipt["desiredSettingsSha256"]
                or state.get("leaseId")!=receipt["leaseId"] or etag!=receipt["etag"]):core.fail("fence-state-lost")
        response=self._lease("renew",receipt["leaseId"])
        if response.status!=200:core.fail("fence-lease-lost")
        return receipt
    def renew(self,receipt):return self.assert_held(receipt)
    def acquire(self,*,operation,source_sha,pending_release,pre_settings_sha256,desired_settings_sha256):
        if (operation not in {"candidate","rollback"} or not core.SHA40.fullmatch(source_sha) or not core.SHA256.fullmatch(pre_settings_sha256)
                or not core.SHA256.fullmatch(desired_settings_sha256) or desired_settings_sha256==pre_settings_sha256):core.fail("fence-input")
        core.validate_descriptor(pending_release,"fence-release-coordinate")
        lease_id=str(self.uuid_factory())
        if not core.GUID.fullmatch(lease_id):core.fail("fence-lease-id")
        headers=self._headers();headers.update({"x-ms-lease-action":"acquire","x-ms-lease-duration":"60","x-ms-proposed-lease-id":lease_id})
        response=self.http("PUT",self.base+"?comp=lease",headers,b"")
        if response.status in {409,412}:core.fail("fence-busy")
        if response.status!=201:core.fail("fence-acquire")
        try:state,etag=self._read(lease_id)
        except Exception:
            self._release_owned(lease_id);raise
        try:self._validate_state(state)
        except Exception:
            self._release_owned(lease_id);raise
        if state["state"]=="held" and (state["operation"]!=operation or state["sourceSha"]!=source_sha
                or state["pendingRelease"]!=pending_release or state["preSettingsSha256"]!=pre_settings_sha256
                or state["desiredSettingsSha256"]!=desired_settings_sha256):
            self._release_owned(lease_id);core.fail("fence-busy")
        updated={"schemaVersion":1,"state":"held","stateVersion":state["stateVersion"]+1,"operation":operation,"sourceSha":source_sha,"pendingRelease":pending_release,"preSettingsSha256":pre_settings_sha256,"desiredSettingsSha256":desired_settings_sha256,"leaseId":lease_id,"lastStatus":state["lastStatus"],"lastProofSha256":state["lastProofSha256"]}
        try:etag=self._write(updated,etag,lease_id);state=updated
        except Exception:
            self._release_owned(lease_id);raise
        return {"blob":self.blob,"leaseId":lease_id,"stateVersion":str(state["stateVersion"]),"release":dict(state["pendingRelease"]),"preSettingsSha256":state["preSettingsSha256"],"desiredSettingsSha256":state["desiredSettingsSha256"],"etag":etag,"operation":operation,"sourceSha":source_sha}
    def complete(self,receipt,*,status,proof_sha256):
        receipt=core.validate_activation_fence(receipt,"fence-receipt")
        if status not in {"consumed","aborted","rollback-complete"} or not core.SHA256.fullmatch(proof_sha256):core.fail("fence-completion")
        state,etag=self._read()
        expected_version=int(receipt["stateVersion"])
        if state.get("state")=="held":
            if (str(state.get("stateVersion"))!=receipt["stateVersion"] or state.get("operation")!=receipt["operation"] or state.get("sourceSha")!=receipt["sourceSha"] or state.get("pendingRelease")!=receipt["release"] or state.get("preSettingsSha256")!=receipt["preSettingsSha256"] or state.get("desiredSettingsSha256")!=receipt["desiredSettingsSha256"] or state.get("leaseId")!=receipt["leaseId"]):core.fail("fence-completion-binding")
            active_lease=receipt["leaseId"]
            renewed=self._lease("renew",active_lease)
            if renewed.status!=200:
                # The original finite lease may have expired after the durable
                # terminal marker was committed.  Recover with a new random
                # lease; never reuse or join the old lease identifier.
                active_lease=str(self.uuid_factory())
                if not core.GUID.fullmatch(active_lease):core.fail("fence-lease-id")
                headers=self._headers();headers.update({"x-ms-lease-action":"acquire","x-ms-lease-duration":"60","x-ms-proposed-lease-id":active_lease})
                acquired=self.http("PUT",self.base+"?comp=lease",headers,b"")
                if acquired.status in {409,412}:core.fail("fence-busy")
                if acquired.status!=201:core.fail("fence-acquire")
                rebound,rebound_etag=self._read(active_lease)
                if rebound!=state or rebound_etag!=etag:
                    self._release_owned(active_lease);core.fail("fence-completion-drift")
            idle={"schemaVersion":1,"state":"idle","stateVersion":state["stateVersion"]+1,"operation":"","sourceSha":"","pendingRelease":None,"preSettingsSha256":"","desiredSettingsSha256":"","leaseId":"","lastStatus":status,"lastProofSha256":proof_sha256}
            self._write(idle,etag,active_lease)
            self._release_owned(active_lease)
        elif not (state.get("state")=="idle" and state.get("stateVersion")==expected_version+1
                and state.get("lastStatus")==status and state.get("lastProofSha256")==proof_sha256):
            core.fail("fence-completion-binding")
        check=self.http("HEAD",self.base,self._headers(),None)
        if check.status!=200 or _header(check,"x-ms-lease-state")!="available":core.fail("fence-release")

class ArmAppSettingsReader:
    def __init__(self,transport):
        self.transport=transport
        self.url=f"https://management.azure.com/subscriptions/{core.SUBSCRIPTION}/resourceGroups/{core.FIXED_COORDS['productionResourceGroup']}/providers/Microsoft.Web/sites/{core.FIXED_COORDS['productionApp']}/config/appsettings/list?api-version=2025-03-01"
    def __call__(self):
        response=self.transport("POST",self.url,{"Accept":"application/json"},b"")
        try:doc=json.loads(response.body)
        except Exception:core.fail("production-settings-json")
        values=doc.get("properties") if isinstance(doc,dict) else None
        if response.status!=200 or not isinstance(values,dict) or not all(isinstance(k,str) and isinstance(v,str) for k,v in values.items()):core.fail("production-settings-shape")
        return values

class ProductionActivation:
    """Exact production mutation boundary used only inside the private bridge."""
    def __init__(self,transport,activation,sleep=time.sleep):
        if not isinstance(activation,core.Activation):core.fail("production-activation-contract")
        self.t=transport;self.activation=activation;self.sleep=sleep;self.fence=None;self.fence_receipt=None
        self.site=f"https://management.azure.com/subscriptions/{core.SUBSCRIPTION}/resourceGroups/{core.FIXED_COORDS['productionResourceGroup']}/providers/Microsoft.Web/sites/{core.FIXED_COORDS['productionApp']}"
        self.origin="https://master-data-structure-sea-9c4e0d0d.azurewebsites.net"
    def bind_fence(self,fence,receipt):
        self.fence=fence;self.fence_receipt=core.validate_activation_fence(receipt,"production-fence")
    def clear_fence(self):self.fence=None;self.fence_receipt=None
    def _renew(self):
        if self.fence is None or self.fence_receipt is None:core.fail("production-fence-required")
        self.fence.assert_held(self.fence_receipt)
    def _read_settings(self,guarded):
        if guarded:self._renew()
        response=self.t("POST",self.site+"/config/appsettings/list?api-version=2025-03-01",{"Accept":"application/json"},b"")
        try:doc=json.loads(response.body)
        except Exception:core.fail("production-settings-json")
        values=doc.get("properties") if isinstance(doc,dict) else None
        if response.status!=200 or not isinstance(values,dict) or not all(isinstance(k,str) and isinstance(v,str) for k,v in values.items()):core.fail("production-settings-shape")
        return values,core.digest(core.canonical(values))
    def read(self):return self._read_settings(True)
    def observe_settings(self):return self._read_settings(False)
    def put(self,values,expected_digest):
        current,current_digest=self.read()
        if current_digest!=expected_digest:core.fail("production-settings-pre-drift")
        self._renew()
        response=self.t("PUT",self.site+"/config/appsettings?api-version=2025-03-01",{"Content-Type":"application/json"},core.canonical({"properties":values}))
        if response.status!=200:core.fail("production-settings-put-ambiguous")
        return core.digest(core.canonical(values))
    def restart(self):
        self._renew()
        response=self.t("POST",self.site+"/restart?api-version=2025-03-01",{},b"")
        if response.status not in {200,202}:core.fail("production-restart")
    def _get(self,path,maximum):
        request=urllib.request.Request(self.origin+path,headers={"Accept":"application/json","Cache-Control":"no-store"})
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),_NoRedirect())
        try:
            with opener.open(request,timeout=30) as response:return response.status,response.read(maximum+1)
        except urllib.error.HTTPError as error:return error.code,error.read(maximum+1)
        except Exception:return 0,b""
    @staticmethod
    def _probe_item(status,body):
        try:doc=json.loads(body)
        except Exception:doc={}
        code=doc.get("code","") if isinstance(doc,dict) else ""
        if isinstance(doc,dict) and isinstance(doc.get("attachmentMalware"),dict):code=doc["attachmentMalware"].get("code",code)
        return {"status":status,"bodySha256":hashlib.sha256(body).hexdigest(),"ok":doc.get("ok") is True if isinstance(doc,dict) else False,"code":code if isinstance(code,str) else ""}
    def _one_deploy_invariant(self,guarded=True):
        if guarded:self._renew()
        response=self.t("GET",self.site+"/deployments?api-version=2025-03-01",{"Accept":"application/json"},None)
        try:values=json.loads(response.body).get("value")
        except Exception:core.fail("production-onedeploy-json")
        if response.status!=200 or not isinstance(values,list):core.fail("production-onedeploy")
        projected=[]
        for item in values:
            props=item.get("properties") if isinstance(item,dict) else None
            if (not isinstance(props,dict) or not isinstance(item.get("id"),str) or not isinstance(item.get("name"),str)
                    or item.get("type")!="Microsoft.Web/sites/deployments" or not core.GUID.fullmatch(str(props.get("id")))
                    or type(props.get("active")) is not bool or type(props.get("complete")) is not bool
                    or type(props.get("status")) is not int or not isinstance(props.get("deployer"),str)
                    or type(props.get("is_readonly")) is not bool or type(props.get("is_temp")) is not bool
                    or not isinstance(props.get("site_name"),str)
                    or any(value is not None and not isinstance(value,str) for value in (props.get("received_time"),props.get("start_time"),props.get("end_time"),props.get("last_success_end_time")))):core.fail("production-onedeploy-entry")
            projected.append({"id":item["id"].lower(),"name":item["name"],"type":item["type"],"properties":{key:props.get(key) for key in ("id","active","complete","status","deployer","received_time","start_time","end_time","last_success_end_time","is_readonly","is_temp","site_name")}})
        projected.sort(key=lambda item:item["properties"]["id"])
        active=[item for item in projected if item["properties"]["active"] is True]
        if len(active)!=1:core.fail("production-onedeploy-active")
        active_properties=active[0]["properties"]
        return {"historicalActiveDeploymentId":active_properties["id"],
                "historicalActiveDeployment":{"id":active_properties["id"],"status":active_properties["status"],"complete":active_properties["complete"],"deployer":active_properties["deployer"]},
                "collectionSemanticProjectionSha256":core.digest(core.canonical(projected)),
                "propertyIdSetSha256":core.digest(core.canonical(sorted(item["properties"]["id"] for item in projected))),
                "deploymentCount":len(projected)}
    def _probe(self,profile,guarded):
        required={"sourceSha","baselineMode","servedIndexSha256","oneDeployInvariant","deploymentBundle"}
        if not isinstance(profile,dict) or set(profile)!=required or profile["baselineMode"] not in {"bootstrap","strict"}:core.fail("production-profile")
        if profile["oneDeployInvariant"]!=core.BOOTSTRAP_BASELINE["oneDeployInvariant"]:core.fail("production-onedeploy-invariant-profile")
        for attempt in range(60):
            if guarded:self._renew()
            runtime_status,runtime_body=self._get("/api/runtime-release-sha",1024);index_status,index_body=self._get("/index.html",2*1024*1024)
            live_status,live=self._get("/api/health/live",65536);ready_status,ready=self._get("/api/health/ready",65536);app_status,app=self._get("/api/app-health",65536);security_status,security=self._get("/api/security-info",65536);one=self._one_deploy_invariant(guarded)
            runtime_value=runtime_body.decode("utf-8","replace").strip()
            if runtime_status==403:
                try:runtime_value=json.loads(runtime_body).get("code","")
                except Exception:runtime_value=""
            observed=dt.datetime.now(dt.timezone.utc);stamp=observed.strftime("%Y-%m-%dT%H:%M:%S.")+f"{observed.microsecond//1000:03d}Z"
            proof={"schemaVersion":1,"phase":"bootstrap" if profile["baselineMode"]=="bootstrap" else "candidate","sourceSha":profile["sourceSha"],"runtimeRelease":{"status":runtime_status,"value":runtime_value,"bodySha256":hashlib.sha256(runtime_body).hexdigest()},"index":{"status":index_status,"sha256":hashlib.sha256(index_body).hexdigest(),"size":len(index_body)},"oneDeployInvariant":one,"live":self._probe_item(live_status,live),"ready":self._probe_item(ready_status,ready),"appHealth":self._probe_item(app_status,app),"securityInfo":self._probe_item(security_status,security),"observedAt":stamp}
            bootstrap_ok=profile["baselineMode"]=="bootstrap" and runtime_status==403 and runtime_value=="api-route-unmapped" and ready_status==core.BOOTSTRAP_BASELINE["readinessHttpStatus"] and proof["ready"]["code"]==core.BOOTSTRAP_BASELINE["readinessCode"]
            strict_ok=profile["baselineMode"]=="strict" and runtime_status==200 and runtime_value==profile["sourceSha"] and ready_status==200 and proof["ready"]["ok"] is True
            expected_one={**profile["oneDeployInvariant"],"historicalActiveDeployment":{"id":profile["oneDeployInvariant"]["historicalActiveDeploymentId"],"status":4,"complete":True,"deployer":"OneDeploy"}}
            common=index_status==200 and proof["index"]["sha256"]==profile["servedIndexSha256"] and one==expected_one and live_status==200 and proof["live"]["ok"] is True and app_status==200 and proof["appHealth"]["ok"] is True and security_status==200 and proof["securityInfo"]["ok"] is True
            if common and (bootstrap_ok or strict_ok):return {"sourceSha":profile["sourceSha"],"healthy":True,"attempt":attempt+1,"proof":proof}
            if attempt<59:self.sleep(5)
        return {"sourceSha":"","healthy":False}
    def probe(self,profile):return self._probe(profile,True)
    def observe(self,profile):return self._probe(profile,False)

class KeyVaultSigner:
    def __init__(self,tokens,http=None): self.tokens=tokens; self.http=http or Http()
    def __call__(self,body,*,key_id,key_version,algorithm):
        if algorithm!="PS256" or not key_id.startswith("https://") or not re.fullmatch(r"[0-9a-f]{32}",key_version): core.fail("kv-coordinate")
        url=key_id+"/"+key_version+"/sign?api-version=7.4"
        payload=core.canonical({"alg":"PS256","value":_b64(hashlib.sha256(body).digest())})
        response=self.http("POST",url,{"Authorization":"Bearer "+self.tokens.get(VAULT),"Content-Type":"application/json"},payload)
        if response.status!=200: core.fail("kv-sign")
        doc=_json(response.body,"kv-json")
        if set(doc)!={"kid","value"} or doc.get("kid")!=key_id+"/"+key_version or not isinstance(doc.get("value"),str): core.fail("kv-sign-binding")
        return doc["value"]

class KeyVaultKeyReader:
    """Read and project one exact public key version with the bridge read UAMI."""
    def __init__(self,tokens,activation,http=None):
        if not isinstance(activation,core.Activation):core.fail("kv-read-contract")
        self.tokens=tokens;self.activation=activation;self.http=http or Http()
        self.url=activation.signing_key_id+"/"+activation.signing_key_version+"?api-version=7.4"
        if self.url!=activation.provisioning_evidence["keyVaultBoundary"]["keyDataPlaneGetUrl"]:core.fail("kv-read-coordinate")
    def __call__(self):
        response=self.http("GET",self.url,{"Authorization":"Bearer "+self.tokens.get(VAULT),"Accept":"application/json"},None)
        if response.status!=200 or len(response.body)>131072:core.fail("kv-read")
        doc=_json(response.body,"kv-read-json");key=doc.get("key") if isinstance(doc,dict) else None;attributes=doc.get("attributes") if isinstance(doc,dict) else None
        if (not isinstance(key,dict) or not isinstance(attributes,dict) or doc.get("release_policy") is not None
                or key.get("kid")!=self.activation.signing_key_id+"/"+self.activation.signing_key_version
                or key.get("kty")!="RSA" or key.get("key_ops")!=["sign","verify"]
                or not isinstance(key.get("n"),str) or not isinstance(key.get("e"),str)
                or attributes.get("enabled") is not True or attributes.get("exportable") is not False):core.fail("kv-read-shape")
        projected_attributes={name:attributes.get(name) for name in ("enabled","nbf","exp","created","updated","recoveryLevel","recoverableDays","exportable")}
        if (any(type(projected_attributes[name]) is not int for name in ("nbf","exp","created","updated","recoverableDays"))
                or not isinstance(projected_attributes["recoveryLevel"],str) or not projected_attributes["recoveryLevel"]):core.fail("kv-read-attributes")
        return {"kid":key["kid"],"kty":key["kty"],"key_ops":key["key_ops"],"n":key["n"],"e":key["e"],"attributes":projected_attributes}

class GitHubArtifactReader:
    def __init__(self,token,http):
        if not isinstance(token,str) or len(token)<20 or any(x in token for x in "\r\n"): core.fail("github-token")
        self.token=token; self.http=http
    def __call__(self,request):
        url=f"https://api.github.com/repositories/{request['repositoryId']}/actions/artifacts/{request['artifactId']}/zip"
        first=self.http("GET",url,{"Authorization":"Bearer "+self.token,"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"},None)
        if first.status!=302: core.fail("artifact-redirect")
        location=_header(first,"Location") or ""; parsed=urllib.parse.urlparse(location)
        if parsed.scheme!="https" or not parsed.hostname or not parsed.hostname.endswith(".blob.core.windows.net") or parsed.username or parsed.password: core.fail("artifact-location")
        second=self.http("GET",location,{"Accept":"application/octet-stream"},None)
        if second.status!=200 or core.digest(second.body)!=request["artifactSha256"]: core.fail("artifact-digest")
        try:
            with zipfile.ZipFile(io.BytesIO(second.body)) as archive:
                infos=archive.infolist()
                if len(infos)<1 or len(infos)>core.MAX_MEMBERS: core.fail("artifact-members")
                names=[]
                for info in infos:
                    path=__import__("pathlib").PurePosixPath(info.filename)
                    if info.is_dir() or path.is_absolute() or any(part in {"",".",".."} for part in path.parts) or info.file_size<0 or info.file_size>core.MAX_ZIP: core.fail("artifact-members")
                    names.append(info.filename)
                if len(names)!=len(set(names)) or request["artifactMember"] not in names: core.fail("artifact-members")
                body=archive.read(request["artifactMember"])
                if len(body)>core.MAX_ZIP or core.digest(body)!=request["artifactMemberSha256"]: core.fail("artifact-member-digest")
        except (zipfile.BadZipFile,OSError): core.fail("artifact-zip")
        return body
