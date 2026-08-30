import base64, hashlib, http.server, io, json, threading, time, unittest, zipfile
from provider import private_release_bridge_azure as azure
from scripts import private_release_mailbox as core
from tests import private_release_v2_fixture as fixture

CID="11111111-1111-1111-1111-111111111111"; PID="33333333-3333-3333-3333-333333333333"; TID="22222222-2222-2222-2222-222222222222"; NOW=2000000000
def b64(value): return base64.urlsafe_b64encode(json.dumps(value,separators=(",",":")).encode()).rstrip(b"=").decode()
def jwt(**changes):
 claims={"aud":azure.ARM.rstrip("/"),"appid":CID,"azp":CID,"oid":PID,"sub":PID,"idtyp":"app","tid":TID,"nbf":NOW-1,"exp":NOW+1000}; claims.update(changes)
 return "x."+b64(claims)+".x"
class Tokens:
 def get(self,resource): return "token"
class Tests(unittest.TestCase):
 def assert_privileged_redirect_fails_closed(self,surface,headers):
  redirect_requests=[];sink_requests=[]
  class Handler(http.server.BaseHTTPRequestHandler):
   def do_GET(self):
    if self.path=="/redirect":
     redirect_requests.append((surface,dict(self.headers)))
     self.send_response(302);self.send_header("Location",f"http://127.0.0.1:{self.server.server_port}/sink");self.end_headers();return
    sink_requests.append((surface,self.path,dict(self.headers)));self.send_response(200);self.end_headers()
   def log_message(self,*args):pass
  server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
  try:
   response=azure.Http()("GET",f"http://127.0.0.1:{server.server_port}/redirect",headers,None)
   self.assertEqual(response.status,302);self.assertEqual(len(redirect_requests),1);self.assertEqual(sink_requests,[])
   observed_headers={name.lower():value for name,value in redirect_requests[0][1].items()}
   for name,value in headers.items():self.assertEqual(observed_headers.get(name.lower()),value)
  finally:
   server.shutdown();server.server_close();thread.join(timeout=5)
 def test_managed_identity_header_never_follows_redirect(self):
  self.assert_privileged_redirect_fails_closed("managed-identity",{"X-IDENTITY-HEADER":"identity-secret"})
 def test_arm_bearer_never_follows_redirect(self):
  self.assert_privileged_redirect_fails_closed("arm",{"Authorization":"Bearer arm-secret"})
 def test_storage_bearer_never_follows_redirect(self):
  self.assert_privileged_redirect_fails_closed("storage",{"Authorization":"Bearer storage-secret"})
 def test_vault_bearer_never_follows_redirect(self):
  self.assert_privileged_redirect_fails_closed("vault",{"Authorization":"Bearer vault-secret"})
 def provider(self,token):
  return azure.ManagedIdentityTokens(client_id=CID,principal_id=PID,tenant_id=TID,endpoint="http://127.0.0.1:41741/MSI/token",identity_header="secret",clock=lambda:NOW,transport=lambda *args:core.Response(200,"",json.dumps({"access_token":token}).encode(),{}))
 def test_token_is_bound_to_audience_client_tenant_and_expiry(self):
  self.assertEqual(self.provider(jwt()).get(azure.ARM),jwt())
  for changes in ({"aud":"https://storage.azure.com/"},{"appid":TID},{"azp":TID},{"oid":CID},{"sub":CID},{"idtyp":"user"},{"tid":CID},{"exp":NOW+299}):
   with self.assertRaises(core.MailboxError): self.provider(jwt(**changes)).get(azure.ARM)
 def test_token_cache_does_not_reuse_inside_expiry_fence(self):
  calls=[]; clock=[NOW]
  def transport(*args): calls.append(1); return core.Response(200,"",json.dumps({"access_token":jwt(exp=clock[0]+301)}).encode(),{})
  provider=azure.ManagedIdentityTokens(client_id=CID,principal_id=PID,tenant_id=TID,endpoint="http://169.254.169.254/metadata/identity/oauth2/token",identity_header="secret",clock=lambda:clock[0],transport=transport)
  provider.get(azure.ARM); clock[0]+=2; provider.get(azure.ARM); self.assertEqual(len(calls),2)
 def test_blob_create_is_conditional_and_version_readback_is_exact(self):
  calls=[]
  def http(method,url,headers,body):
   calls.append((method,url,headers)); return core.Response(201 if method=="PUT" else 200,url,body if method=="PUT" else b"ok",{"ETag":'"e"',"x-ms-version-id":"v1","x-ms-meta-sha256":core.digest(b"ok")})
  blob=azure.BlobWorm("account","container",Tokens(),Tokens(),http); created=blob.create("v2/x",b"ok","*"); observed=blob.read("v2/x",created.version_id)
  self.assertEqual(calls[0][2]["If-None-Match"],"*"); self.assertIn("versionid=v1",calls[1][1]); self.assertEqual(observed.body,b"ok")
 def test_blob_version_or_digest_drift_fails(self):
  blob=azure.BlobWorm("account","container",Tokens(),Tokens(),lambda *args:core.Response(200,"",b"changed",{"ETag":'"e"',"x-ms-version-id":"v2","x-ms-meta-sha256":"0"*64}))
  with self.assertRaisesRegex(core.MailboxError,"blob-version-digest"): blob.read("v2/x","v1")
 def test_key_vault_response_must_bind_exact_version_and_algorithm(self):
  def response(doc): return lambda *args:core.Response(200,"",json.dumps(doc).encode(),{})
  kid="https://vault.vault.azure.net/keys/release"; version="a"*32
  signer=azure.KeyVaultSigner(Tokens(),response({"kid":kid+"/"+version,"value":"AA"})); self.assertEqual(signer(b"x",key_id=kid,key_version=version,algorithm="PS256"),"AA")
  with self.assertRaisesRegex(core.MailboxError,"kv-sign-binding"): azure.KeyVaultSigner(Tokens(),response({"kid":kid+"/wrong","value":"AA"}))(b"x",key_id=kid,key_version=version,algorithm="PS256")
  with self.assertRaisesRegex(core.MailboxError,"kv-coordinate"): signer(b"x",key_id=kid,key_version=version,algorithm="RS256")
 def test_key_reader_projects_exact_versioned_public_key(self):
  activation=fixture.activation();expected=activation.provisioning_evidence["keyVaultBoundary"]["keyDataPlaneProjection"]
  doc={"key":{key:expected[key] for key in ("kid","kty","key_ops","n","e")},"attributes":expected["attributes"],"release_policy":None}
  calls=[]
  def http(method,url,headers,body):calls.append((method,url,headers));return core.Response(200,url,core.canonical(doc),{})
  self.assertEqual(azure.KeyVaultKeyReader(Tokens(),activation,http)(),expected)
  self.assertEqual(calls[0][0],"GET");self.assertEqual(calls[0][1],activation.provisioning_evidence["keyVaultBoundary"]["keyDataPlaneGetUrl"])
  bad=json.loads(json.dumps(doc));bad["attributes"]["enabled"]=False
  with self.assertRaisesRegex(core.MailboxError,"kv-read-shape"):azure.KeyVaultKeyReader(Tokens(),activation,lambda *args:core.Response(200,"",core.canonical(bad),{}))()
 def test_arm_transport_rejects_wrong_resource(self):
  transport=azure.ArmTransport(Tokens(),lambda *args:core.Response(200,"",b"",{}))
  with self.assertRaisesRegex(core.MailboxError,"arm-url"): transport("GET","https://example.com",{},None)
 def test_artifact_reader_strips_token_on_one_constrained_redirect(self):
  inner=b"tar"; output=io.BytesIO()
  with zipfile.ZipFile(output,"w") as archive: archive.writestr("paperdesk-accepted-release-request.tar.gz",inner)
  body=output.getvalue(); calls=[]
  def http(method,url,headers,payload):
   calls.append((url,headers)); return core.Response(302,url,b"",{"Location":"https://actionsresults.blob.core.windows.net/results/file?sig=x"}) if len(calls)==1 else core.Response(200,url,body,{})
  req={"repositoryId":"1","artifactId":"2","artifactSha256":hashlib.sha256(body).hexdigest(),"artifactMember":"paperdesk-accepted-release-request.tar.gz","artifactMemberSha256":hashlib.sha256(inner).hexdigest()}
  self.assertEqual(azure.GitHubArtifactReader("x"*20,http)(req),inner); self.assertIn("Authorization",calls[0][1]); self.assertNotIn("Authorization",calls[1][1])
 def test_artifact_reader_rejects_second_host_and_digest_drift(self):
  req={"repositoryId":"1","artifactId":"2","artifactSha256":"0"*64,"artifactMember":"x.tar.gz","artifactMemberSha256":"1"*64}
  reader=azure.GitHubArtifactReader("x"*20,lambda *args:core.Response(302,"",b"",{"Location":"https://evil.example/x"}))
  with self.assertRaisesRegex(core.MailboxError,"artifact-location"): reader(req)
 def test_activation_fence_active_busy_expired_exact_rebind_and_stale_receipt(self):
  class Service:
   def __init__(self):
    self.state={"schemaVersion":1,"state":"idle","stateVersion":0,"operation":"","sourceSha":"","pendingRelease":None,"preSettingsSha256":"","desiredSettingsSha256":"","leaseId":"","lastStatus":"bootstrap","lastProofSha256":"f"*64};self.etag=0;self.lease=None
   def response(self,status,body=b"",extra=None):
    headers={"ETag":f'"e{self.etag}"',"x-ms-meta-sha256":core.digest(body)};headers.update(extra or {});return core.Response(status,"",body,headers)
   def __call__(self,method,url,headers,body):
    action=headers.get("x-ms-lease-action")
    if url.endswith("?comp=lease") and action=="acquire":
     if self.lease is not None:return self.response(409)
     self.lease=headers["x-ms-proposed-lease-id"];return self.response(201)
    if url.endswith("?comp=lease") and action=="renew":return self.response(200 if headers.get("x-ms-lease-id")==self.lease else 412)
    if url.endswith("?comp=lease") and action=="release":
     if headers.get("x-ms-lease-id")!=self.lease:return self.response(412)
     self.lease=None;return self.response(200)
    if method=="HEAD":return self.response(200,extra={"x-ms-lease-state":"available" if self.lease is None else "leased"})
    if method=="GET":
     if headers.get("x-ms-lease-id") is not None and headers.get("x-ms-lease-id")!=self.lease:return self.response(412)
     return self.response(200,core.canonical(self.state))
    if method=="PUT":
     if headers.get("x-ms-lease-id")!=self.lease or headers.get("If-Match")!=f'"e{self.etag}"':raise AssertionError("write fence")
     self.state=dict(json.loads(body));self.etag+=1;return self.response(201,extra={"ETag":f'"e{self.etag}"'})
    raise AssertionError((method,url,headers))
  service=Service();ids=iter(("11111111-1111-4111-8111-111111111111","22222222-2222-4222-8222-222222222222","33333333-3333-4333-8333-333333333333","44444444-4444-4444-8444-444444444444","55555555-5555-4555-8555-555555555555"))
  fence=azure.BlobActivationFence(core.FIXED_COORDS["packageAccount"],core.FIXED_COORDS["activationFenceContainer"],core.FIXED_COORDS["activationFenceBlob"],Tokens(),service,uuid_factory=lambda:next(ids))
  release={"blob":"v2/pending/"+"a"*40+"/1-1-1/manifest.json","sha256":"b"*64,"size":1,"etag":'"m"',"versionId":"v1"}
  first=fence.acquire(operation="candidate",source_sha="a"*40,pending_release=release,pre_settings_sha256="c"*64,desired_settings_sha256="d"*64)
  with self.assertRaisesRegex(core.MailboxError,"fence-busy"):fence.acquire(operation="candidate",source_sha="a"*40,pending_release=release,pre_settings_sha256="c"*64,desired_settings_sha256="d"*64)
  service.lease=None
  rebound=fence.acquire(operation="candidate",source_sha="a"*40,pending_release=release,pre_settings_sha256="c"*64,desired_settings_sha256="d"*64)
  self.assertNotEqual(first["leaseId"],rebound["leaseId"]);self.assertEqual(rebound["stateVersion"],"2")
  with self.assertRaises(core.MailboxError):fence.assert_held(first)
  service.lease=None
  wrong=dict(release);wrong["versionId"]="v2"
  with self.assertRaisesRegex(core.MailboxError,"fence-busy"):fence.acquire(operation="candidate",source_sha="a"*40,pending_release=wrong,pre_settings_sha256="c"*64,desired_settings_sha256="d"*64)
  self.assertIsNone(service.lease)
  service.lease=None
  fence.complete(rebound,status="consumed",proof_sha256="e"*64);self.assertEqual(service.state["state"],"idle");self.assertIsNone(service.lease)
  fence.complete(rebound,status="consumed",proof_sha256="e"*64)
if __name__=="__main__": unittest.main()
