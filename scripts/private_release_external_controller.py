"""ARM-only runner controller for the private signed release bridge.

The runner receives no Storage data-plane token, production App Service role,
or OneDeploy role.  It may create/read the private ARM mailbox and temporarily
start the stopped bridge, but every production setting, restart, probe, package,
registry, signing, and activation-fence operation executes inside that bridge.
"""
from __future__ import annotations
import argparse, datetime as dt, fnmatch, hashlib, json, os, re, secrets, subprocess, time, uuid
import urllib.error, urllib.request
from pathlib import Path
from scripts import private_release_mailbox as core

class CliTokens:
    def __init__(self,activation,clock=time.time):self.activation=activation;self.clock=clock;self.cache={}
    def get(self,resource):
        if resource not in {"https://management.azure.com/","https://graph.microsoft.com/"}:core.fail("external-token-resource")
        now=int(self.clock());cached=self.cache.get(resource)
        if cached and cached[1]-now>300:return cached[0]
        run=subprocess.run(["az","account","get-access-token","--resource",resource,"--output","json"],capture_output=True,text=True,check=False,timeout=30)
        if run.returncode or len(run.stdout)>65536:core.fail("external-token")
        try:
            doc=json.loads(run.stdout);token=doc["accessToken"];parts=token.split(".")
            if len(parts)!=3:core.fail("external-token-json")
            claims=json.loads(core.b64u_decode(parts[1],"external-claims"))
        except core.MailboxError:raise
        except Exception:core.fail("external-token-json")
        expected_issuer=f"https://sts.windows.net/{self.activation.tenant_id}/"
        allowed_audiences={resource,resource.rstrip("/")}
        if resource=="https://graph.microsoft.com/":allowed_audiences.add(core.GRAPH_APP_ID)
        if (claims.get("aud") not in allowed_audiences or claims.get("tid")!=self.activation.tenant_id
                or claims.get("appid")!=self.activation.publisher_client_id or (claims.get("azp") is not None and claims.get("azp")!=self.activation.publisher_client_id)
                or claims.get("oid")!=self.activation.publisher_principal_id or claims.get("sub")!=self.activation.publisher_principal_id
                or claims.get("idtyp")!="app" or claims.get("iss")!=expected_issuer):core.fail("external-token-binding")
        exp=claims.get("exp");nbf=claims.get("nbf",0)
        if type(exp) is not int or type(nbf) is not int or nbf>now+30 or exp<=now+300:core.fail("external-token-expiry")
        self.cache[resource]=(token,exp);return token

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None
class Http:
    def __call__(self,method,url,headers,body=None):
        request=urllib.request.Request(url,data=body,headers=dict(headers),method=method);opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),_NoRedirect())
        try:
            with opener.open(request,timeout=30) as response:return core.Response(response.status,url,response.read(core.MAX_RESULT*2000+1),dict(response.headers))
        except urllib.error.HTTPError as error:return core.Response(error.code,url,error.read(core.MAX_RESULT*2+1),dict(error.headers))

class GitHubRunLiveness:
    """Read-only proof that the exact transient owner run is terminal."""
    def __init__(self,token,http=None):
        if not isinstance(token,str) or len(token)<20 or any(c in token for c in "\r\n"):core.fail("cleanup-github-token")
        self.token=token;self.http=http or Http()
    def __call__(self,record):
        url=("https://api.github.com/repos/Sethvirak/MasterDataStructure/actions/runs/"
             f"{record['runId']}/attempts/{record['runAttempt']}")
        try:response=self.http("GET",url,{"Authorization":"Bearer "+self.token,"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"},None)
        except (urllib.error.URLError,TimeoutError,OSError):
            return {"runId":record["runId"],"runAttempt":record["runAttempt"],"status":"unavailable","conclusion":""}
        if response.status in {408,429} or 500<=response.status<=599:
            return {"runId":record["runId"],"runAttempt":record["runAttempt"],"status":"unavailable","conclusion":""}
        try:doc=json.loads(response.body)
        except Exception:core.fail("cleanup-run-json")
        repo=doc.get("repository") if isinstance(doc,dict) else None
        if (response.status!=200 or str(doc.get("id"))!=record["runId"] or str(doc.get("run_attempt"))!=record["runAttempt"]
                or doc.get("status")!="completed" or not isinstance(doc.get("conclusion"),str)
                or not isinstance(repo,dict) or repo.get("full_name")!=record["repository"]
                or str(repo.get("id"))!=record["repositoryId"] or str(repo.get("owner",{}).get("id"))!=record["ownerId"]
                or str(doc.get("workflow_id"))!=record["workflowId"] or doc.get("name")!=record["workflowName"]
                or doc.get("path")!=record["workflowPath"] or doc.get("event")!=record["event"]
                or doc.get("head_branch")!=record["headBranch"] or doc.get("head_sha")!=record["callerSha"]):core.fail("cleanup-run-active-or-drift")
        return {"runId":record["runId"],"runAttempt":record["runAttempt"],"status":"completed","conclusion":doc["conclusion"],
                "repository":repo["full_name"],"repositoryId":str(repo["id"]),"ownerId":str(repo["owner"]["id"]),
                "workflowId":str(doc["workflow_id"]),"workflowName":doc["name"],"workflowPath":doc["path"],
                "event":doc["event"],"headBranch":doc["head_branch"],"headSha":doc["head_sha"]}
class Arm:
    def __init__(self,tokens,http=None):self.tokens=tokens;self.http=http or Http()
    def __call__(self,method,url,headers,body=None):
        if not url.startswith("https://management.azure.com/"):core.fail("external-arm-url")
        bound=dict(headers);bound["Authorization"]="Bearer "+self.tokens.get("https://management.azure.com/")
        return self.http(method,url,bound,body)

class Graph:
    def __init__(self,tokens,http=None):self.tokens=tokens;self.http=http or Http()
    def __call__(self,method,url,headers,body=None):
        if not url.startswith("https://graph.microsoft.com/"):core.fail("external-graph-url")
        bound=dict(headers);bound["Authorization"]="Bearer "+self.tokens.get("https://graph.microsoft.com/")
        return self.http(method,url,bound,body)

class ProvisioningVerifier:
    """Action-time exact RBAC/resource inventory for the source-pinned manifest.

    Both direct `principalId eq` and transitive `assignedTo` inventories are
    fully paginated at subscription scope.  Any missing, extra, inherited, or
    group-derived assignment fails before the controller lease or mailbox is
    touched.  Subscription/resource-group Owners remain an explicit
    out-of-band governance boundary.
    """
    def __init__(self,transport,activation,bootstrap_receipt,graph_transport=None):
        self.t=transport;self.a=activation
        self.bootstrap_receipt=core.validate_bridge_runtime_receipt(bootstrap_receipt,activation)
        self.graph=graph_transport or (Graph(transport.tokens) if hasattr(transport,"tokens") else None)
    def _json(self,response,label):
        if response.status!=200 or len(response.body)>4*1024*1024:core.fail(label)
        try:value=json.loads(response.body)
        except Exception:core.fail(label+"-json")
        if not isinstance(value,dict):core.fail(label+"-shape")
        return value
    def _pages(self,url,label):
        items=[];seen=set()
        for page in range(50):
            if (not isinstance(url,str) or not url.startswith("https://management.azure.com/subscriptions/"+core.SUBSCRIPTION+"/")
                    or url in seen):core.fail(label+"-next-link")
            seen.add(url);doc=self._json(self.t("GET",url,{"Accept":"application/json"},None),label)
            values=doc.get("value");next_link=doc.get("nextLink")
            if not isinstance(values,list) or any(not isinstance(item,dict) for item in values):core.fail(label+"-items")
            items.extend(values)
            if next_link in (None,""):return items
            url=next_link
        core.fail(label+"-pagination")
    def _graph_pages(self,url,label):
        if self.graph is None:core.fail("provisioning-graph-required")
        items=[];seen=set()
        for page in range(20):
            if (not isinstance(url,str) or not url.startswith("https://graph.microsoft.com/") or url in seen):core.fail(label+"-next-link")
            seen.add(url);doc=self._json(self.graph("GET",url,{"Accept":"application/json"},None),label)
            values=doc.get("value");next_link=doc.get("@odata.nextLink")
            if not isinstance(values,list) or any(not isinstance(item,dict) for item in values):core.fail(label+"-items")
            items.extend(values)
            if next_link in (None,""):return items
            url=next_link
        core.fail(label+"-pagination")
    def _verify_publisher_identity(self):
        if self.graph is None:core.fail("provisioning-graph-required")
        source=self.a.provisioning_evidence["publisherIdentity"]
        application=self._json(self.graph("GET",source["applicationQuery"],{"Accept":"application/json"},None),"provisioning-publisher-application")
        passwords=application.get("passwordCredentials");keys=application.get("keyCredentials")
        app_projection={"id":application.get("id"),"appId":application.get("appId"),"signInAudience":application.get("signInAudience"),
                        "passwordCredentialKeyIds":sorted(str(item.get("keyId")) for item in passwords) if isinstance(passwords,list) and all(isinstance(item,dict) for item in passwords) else None,
                        "keyCredentialKeyIds":sorted(str(item.get("keyId")) for item in keys) if isinstance(keys,list) and all(isinstance(item,dict) for item in keys) else None}
        if (app_projection["id"]!=source["applicationObjectId"] or app_projection["appId"]!=self.a.publisher_client_id
                or app_projection["signInAudience"]!="AzureADMyOrg" or app_projection["passwordCredentialKeyIds"]!=[] or app_projection["keyCredentialKeyIds"]!=[]
                or core.digest(core.canonical(app_projection))!=source["applicationProjectionSha256"]):core.fail("provisioning-publisher-application")
        service=self._json(self.graph("GET",source["servicePrincipalQuery"],{"Accept":"application/json"},None),"provisioning-publisher-service-principal")
        passwords=service.get("passwordCredentials");keys=service.get("keyCredentials")
        service_projection={"id":service.get("id"),"appId":service.get("appId"),"accountEnabled":service.get("accountEnabled"),"servicePrincipalType":service.get("servicePrincipalType"),
                            "passwordCredentialKeyIds":sorted(str(item.get("keyId")) for item in passwords) if isinstance(passwords,list) and all(isinstance(item,dict) for item in passwords) else None,
                            "keyCredentialKeyIds":sorted(str(item.get("keyId")) for item in keys) if isinstance(keys,list) and all(isinstance(item,dict) for item in keys) else None}
        if (service_projection["id"]!=self.a.publisher_principal_id or service_projection["appId"]!=self.a.publisher_client_id
                or service_projection["accountEnabled"] is not True or service_projection["servicePrincipalType"]!="Application"
                or service_projection["passwordCredentialKeyIds"]!=[] or service_projection["keyCredentialKeyIds"]!=[]
                or core.digest(core.canonical(service_projection))!=source["servicePrincipalProjectionSha256"]):core.fail("provisioning-publisher-service-principal")
        fics=self._graph_pages(source["federatedIdentityCredentialsQuery"],"provisioning-publisher-fic")
        fic_projection=[]
        for item in fics:
            if not isinstance(item,dict):core.fail("provisioning-publisher-fic")
            fic_projection.append({key:item.get(key) for key in ("id","name","issuer","audiences","subject","claimsMatchingExpression")})
        policy=source["federatedIdentityCredentialPolicy"]
        template=policy["claimsMatchingExpressionTemplate"]["value"]
        control_ref=f"{core.CONTROL_REPOSITORY}/{core.CONTROL_WORKFLOW_PATH}@{self.a.workflow_sha}"
        expected_fic={"id":policy["id"],"name":policy["name"],"issuer":policy["issuer"],"audiences":policy["audiences"],"subject":policy["subject"],
                      "claimsMatchingExpression":{"languageVersion":1,"value":template.replace("{controlWorkflowRef}",control_ref)}}
        if fic_projection!=[expected_fic]:core.fail("provisioning-publisher-fic")
        assignments=self._graph_pages(source["appRoleAssignmentsQuery"],"provisioning-publisher-graph-role")
        role_projection=[{key:item.get(key) for key in ("id","principalId","resourceId","appRoleId")} for item in assignments]
        if role_projection!=[source["graphApplicationReadAllAppRoleAssignment"]] or core.digest(core.canonical(role_projection[0]))!=source["graphApplicationReadAllAppRoleAssignmentSha256"]:core.fail("provisioning-publisher-graph-role")
        return {"application":app_projection,"servicePrincipal":service_projection,"federatedIdentityCredential":fic_projection[0],"graphAppRoleAssignment":role_projection[0]}
    @staticmethod
    def _assignment(document):
        properties=document.get("properties") if isinstance(document,dict) else None
        if (not isinstance(properties,dict) or document.get("type")!="Microsoft.Authorization/roleAssignments"
                or not isinstance(document.get("id"),str) or not isinstance(document.get("name"),str)):
            core.fail("provisioning-live-assignment")
        projection={"id":document["id"].lower(),"name":document["name"].lower(),"type":document["type"],"properties":{
            "principalId":str(properties.get("principalId") or "").lower(),"principalType":properties.get("principalType"),
            "roleDefinitionId":str(properties.get("roleDefinitionId") or "").lower(),"scope":str(properties.get("scope") or "").lower(),
            "condition":properties.get("condition"),"conditionVersion":properties.get("conditionVersion"),
            "delegatedManagedIdentityResourceId":properties.get("delegatedManagedIdentityResourceId")}}
        if (not core.GUID.fullmatch(projection["name"]) or not core.GUID.fullmatch(projection["properties"]["principalId"])
                or projection["properties"]["principalType"]!="ServicePrincipal" or projection["properties"]["condition"] is not None
                or projection["properties"]["conditionVersion"] is not None or projection["properties"]["delegatedManagedIdentityResourceId"] is not None):core.fail("provisioning-live-assignment")
        return projection
    @staticmethod
    def _definition(document):
        properties=document.get("properties") if isinstance(document,dict) else None
        permissions=properties.get("permissions") if isinstance(properties,dict) else None
        if (not isinstance(properties,dict) or document.get("type")!="Microsoft.Authorization/roleDefinitions"
                or not isinstance(document.get("id"),str) or not isinstance(document.get("name"),str)
                or properties.get("type") not in {"CustomRole","BuiltInRole"} or not isinstance(properties.get("roleName"),str)
                or not isinstance(properties.get("assignableScopes"),list) or not isinstance(permissions,list) or len(permissions)!=1
                or not isinstance(permissions[0],dict)):core.fail("provisioning-live-definition")
        permission=permissions[0]
        for key in ("actions","notActions","dataActions","notDataActions"):
            if not isinstance(permission.get(key),list) or any(not isinstance(value,str) for value in permission[key]) or len(permission[key])!=len(set(permission[key])):core.fail("provisioning-live-definition")
        return {"id":document["id"].lower(),"name":document["name"].lower(),"type":document["type"],"properties":{
            "roleName":properties["roleName"],"type":properties["type"],"assignableScopes":properties["assignableScopes"],
            "permissions":[{key:permission[key] for key in ("actions","notActions","dataActions","notDataActions")}]}}
    @staticmethod
    def _assignment_any(document):
        properties=document.get("properties") if isinstance(document,dict) else None
        if (not isinstance(properties,dict) or document.get("type")!="Microsoft.Authorization/roleAssignments"
                or not isinstance(document.get("id"),str) or not isinstance(document.get("name"),str)
                or not core.GUID.fullmatch(str(properties.get("principalId") or "")) or not isinstance(properties.get("principalType"),str)
                or not isinstance(properties.get("roleDefinitionId"),str) or not isinstance(properties.get("scope"),str)):core.fail("provisioning-bridge-assignment")
        return {"id":document["id"].lower(),"name":document["name"].lower(),"type":document["type"],"properties":{"principalId":properties["principalId"].lower(),"principalType":properties["principalType"],"roleDefinitionId":properties["roleDefinitionId"].lower(),"scope":properties["scope"].lower(),"condition":properties.get("condition"),"conditionVersion":properties.get("conditionVersion"),"delegatedManagedIdentityResourceId":properties.get("delegatedManagedIdentityResourceId")}}
    @staticmethod
    def _definition_any(document):
        properties=document.get("properties") if isinstance(document,dict) else None;permissions=properties.get("permissions") if isinstance(properties,dict) else None
        if (not isinstance(properties,dict) or document.get("type")!="Microsoft.Authorization/roleDefinitions" or not isinstance(document.get("id"),str)
                or not isinstance(permissions,list) or not permissions):core.fail("provisioning-bridge-definition")
        projected=[]
        for permission in permissions:
            if not isinstance(permission,dict):core.fail("provisioning-bridge-definition")
            values={}
            for key in ("actions","notActions","dataActions","notDataActions"):
                value=permission.get(key)
                if not isinstance(value,list) or any(not isinstance(item,str) for item in value):core.fail("provisioning-bridge-definition")
                values[key]=value
            projected.append(values)
        return {"id":document["id"].lower(),"type":document["type"],"permissions":projected}
    @staticmethod
    def _scope_covers_bridge(scope,bridge_resource):
        scope=scope.lower().rstrip("/");target=bridge_resource.lower()
        return scope.startswith("/providers/microsoft.management/managementgroups/") or target==scope or target.startswith(scope+"/")
    @staticmethod
    def _definition_grants(definition,sensitive):
        for permission in definition["permissions"]:
            for action in sensitive:
                granted=any(fnmatch.fnmatchcase(action.lower(),pattern.lower()) for pattern in permission["actions"])
                excluded=any(fnmatch.fnmatchcase(action.lower(),pattern.lower()) for pattern in permission["notActions"])
                if granted and not excluded:return True
        return False
    @staticmethod
    def _definition_mutates_bridge(definition,sensitive=None):
        sensitive=tuple(sensitive or core.BRIDGE_SENSITIVE_ACTION_UNIVERSE)
        if ProvisioningVerifier._definition_grants(definition,sensitive):return True
        # Provider operations evolve.  A new Microsoft.Web site operation is
        # not silently treated as harmless merely because it was absent from
        # the reviewed provider-operation snapshot.  The only universally safe
        # Web action here is the exact public site-resource read used by the
        # subscription inventory role. Secret/config/deployment reads remain
        # sensitive and are present in the universe above.
        for permission in definition["permissions"]:
            for pattern in permission["actions"]:
                value=pattern.lower()
                if value=="microsoft.web/sites/read":continue
                if value.startswith("microsoft.web/sites"):
                    return True
                if value.startswith("microsoft.authorization/roleassignments/") or value.startswith("microsoft.authorization/roledefinitions/"):
                    if not value.endswith("/read"):return True
                if value.startswith("microsoft.resources/deployments/") and not value.endswith("/read"):
                    return True
        return False
    @staticmethod
    def _definition_sensitive_key(definition,sensitive=None):
        sensitive=tuple(sensitive or core.KEY_SENSITIVE_ACTION_UNIVERSE)
        for permission in definition["permissions"]:
            for plane,excluded_plane in (("actions","notActions"),("dataActions","notDataActions")):
                for action in sensitive:
                    granted=any(fnmatch.fnmatchcase(action.lower(),pattern.lower()) for pattern in permission[plane])
                    excluded=any(fnmatch.fnmatchcase(action.lower(),pattern.lower()) for pattern in permission[excluded_plane])
                    if granted and not excluded:return True
                # Fail closed for provider additions that can alter or use key
                # material, or can escalate authority at a covering scope.
                for pattern in permission[plane]:
                    value=pattern.lower()
                    if value.startswith("microsoft.keyvault/vaults/keys/") and not value.endswith("/read") and not value.endswith("/verify/action"):
                        return True
                    if value.startswith("microsoft.keyvault/vaults/") and not value.endswith("/read") and "/secrets/" not in value:
                        return True
                    if value.startswith("microsoft.authorization/roleassignments/") or value.startswith("microsoft.authorization/roledefinitions/"):
                        if not value.endswith("/read"):return True
                    if value.startswith("microsoft.resources/deployments/") and not value.endswith("/read"):return True
        return False
    def verify(self):
        evidence=self.a.provisioning_evidence;roles=evidence["roles"];publisher_identity=self._verify_publisher_identity()
        live_by_id={}
        for name,inventory in evidence["principalInventories"].items():
            direct=self._pages(inventory["directQuery"],"provisioning-direct-"+name)
            effective=self._pages(inventory["effectiveQuery"],"provisioning-effective-"+name)
            direct_projection=[self._assignment(item) for item in direct];effective_projection=[self._assignment(item) for item in effective]
            direct_projection.sort(key=lambda item:item["id"]);effective_projection.sort(key=lambda item:item["id"])
            direct_ids=sorted(item["id"] for item in direct_projection);effective_ids=sorted(item["id"] for item in effective_projection)
            if (direct_ids!=inventory["directAssignmentResourceIds"] or effective_ids!=inventory["effectiveAssignmentResourceIds"]
                    or direct_projection!=effective_projection or core.digest(core.canonical(direct_projection))!=inventory["directAssignmentSetSha256"]
                    or core.digest(core.canonical(effective_projection))!=inventory["effectiveAssignmentSetSha256"]):core.fail("provisioning-live-inventory-"+name)
            for item in direct_projection:
                if item["id"] in live_by_id and live_by_id[item["id"]]!=item:core.fail("provisioning-live-assignment-duplicate")
                live_by_id[item["id"]]=item
        expected_ids={role["roleAssignmentResourceId"].lower() for role in roles.values()}
        if set(live_by_id)!=expected_ids:core.fail("provisioning-live-assignment-set")
        definitions={}
        for name,role in roles.items():
            assignment=live_by_id.get(role["roleAssignmentResourceId"].lower())
            if assignment is None or core.digest(core.canonical(assignment))!=role["roleAssignmentSha256"]:core.fail("provisioning-live-assignment-"+name)
            definition_id=role["roleDefinitionResourceId"].lower()
            if assignment["properties"]["roleDefinitionId"]!=definition_id or assignment["properties"]["principalId"]!=role["principalId"].lower() or assignment["properties"]["scope"]!=role["scope"].lower():core.fail("provisioning-live-assignment-"+name)
            if definition_id not in definitions:
                url="https://management.azure.com"+role["roleDefinitionResourceId"]+"?api-version=2022-04-01"
                definitions[definition_id]=self._definition(self._json(self.t("GET",url,{"Accept":"application/json"},None),"provisioning-definition"))
            definition=definitions[definition_id]
            if (core.digest(core.canonical(definition))!=role["roleDefinitionSha256"]
                    or definition["properties"]["assignableScopes"]!=role["assignableScopes"]
                    or definition["properties"]["permissions"]!=[{key:role[key] for key in ("actions","notActions","dataActions","notDataActions")}]):core.fail("provisioning-live-definition-"+name)
        identities={}
        production_resource=f"/subscriptions/{core.SUBSCRIPTION}/resourceGroups/{core.FIXED_COORDS['productionResourceGroup']}/providers/Microsoft.Web/sites/{core.FIXED_COORDS['productionApp']}"
        for role in roles.values():
            resource=role["identityResourceId"]
            if resource is None or resource.lower() in identities:continue
            if resource.lower()==production_resource.lower():
                document=self._json(self.t("GET","https://management.azure.com"+resource+"?api-version=2025-03-01",{"Accept":"application/json"},None),"provisioning-production-identity")
                identity=document.get("identity") if isinstance(document,dict) else None
                user_assigned=identity.get("userAssignedIdentities") if isinstance(identity,dict) else None
                projection={"id":str(document.get("id") or "").lower(),"type":document.get("type"),"identityType":identity.get("type") if isinstance(identity,dict) else None,"tenantId":str(identity.get("tenantId") or "").lower() if isinstance(identity,dict) else "","principalId":str(identity.get("principalId") or "").lower() if isinstance(identity,dict) else "","userAssignedIdentityResourceIds":sorted(str(key).lower() for key in user_assigned) if isinstance(user_assigned,dict) else []}
                if (projection["id"]!=resource.lower() or projection["type"]!="Microsoft.Web/sites" or projection["identityType"]!="SystemAssigned"
                        or projection["userAssignedIdentityResourceIds"]!=[] or projection["tenantId"]!=role["tenantId"].lower()
                        or projection["principalId"]!=role["principalId"].lower()):core.fail("provisioning-live-production-identity")
            else:
                document=self._json(self.t("GET","https://management.azure.com"+resource+"?api-version=2023-01-31",{"Accept":"application/json"},None),"provisioning-uami")
                properties=document.get("properties") if isinstance(document,dict) else None
                projection={"id":str(document.get("id") or "").lower(),"type":document.get("type"),"tenantId":str(properties.get("tenantId") or "").lower() if isinstance(properties,dict) else "","clientId":str(properties.get("clientId") or "").lower() if isinstance(properties,dict) else "","principalId":str(properties.get("principalId") or "").lower() if isinstance(properties,dict) else ""}
                if (projection["id"]!=resource.lower() or projection["type"]!="Microsoft.ManagedIdentity/userAssignedIdentities"
                        or projection["tenantId"]!=role["tenantId"].lower() or projection["clientId"]!=role["identityClientId"].lower()
                        or projection["principalId"]!=role["principalId"].lower()):core.fail("provisioning-live-uami")
            identities[resource.lower()]=projection
        expected_bridge_uamis={role["identityResourceId"].lower():(role["identityClientId"].lower(),role["principalId"].lower()) for role in roles.values()
                if isinstance(role.get("identityResourceId"),str) and role["identityResourceId"].lower()!=production_resource.lower()}
        bridge_resource=f"/subscriptions/{core.SUBSCRIPTION}/resourceGroups/{core.FIXED_COORDS['bridgeResourceGroup']}/providers/Microsoft.Web/sites/{core.FIXED_COORDS['bridgeApp']}"
        bridge_document=self._json(self.t("GET","https://management.azure.com"+bridge_resource+"?api-version=2025-03-01",{"Accept":"application/json"},None),"provisioning-bridge-identity")
        bridge_identity=bridge_document.get("identity") if isinstance(bridge_document,dict) else None
        attached=bridge_identity.get("userAssignedIdentities") if isinstance(bridge_identity,dict) else None
        if (str(bridge_document.get("id") or "").lower()!=bridge_resource.lower() or bridge_document.get("type")!="Microsoft.Web/sites"
                or not isinstance(bridge_identity,dict) or bridge_identity.get("type")!="UserAssigned" or not isinstance(attached,dict)
                or {str(key).lower() for key in attached}!=set(expected_bridge_uamis)):core.fail("provisioning-live-bridge-identities")
        bridge_projection={}
        for resource,value in attached.items():
            expected=expected_bridge_uamis.get(resource.lower())
            if (not isinstance(value,dict) or expected is None or str(value.get("clientId") or "").lower()!=expected[0]
                    or str(value.get("principalId") or "").lower()!=expected[1]):core.fail("provisioning-live-bridge-identities")
            bridge_projection[resource.lower()]={"clientId":expected[0],"principalId":expected[1]}
        identities[bridge_resource.lower()]={"id":bridge_resource.lower(),"type":"Microsoft.Web/sites","identityType":"UserAssigned","userAssignedIdentities":bridge_projection}
        runtime=evidence["bridgeRuntime"]
        settings_doc=self._json(self.t("POST","https://management.azure.com"+bridge_resource+"/config/appsettings/list?api-version=2025-03-01",{"Accept":"application/json"},b""),"provisioning-bridge-settings")
        settings=settings_doc.get("properties")
        # This is the complete source-owned durable map, not a subset check.
        # An unreviewed setting can change package execution just as surely as
        # drift in one of the four known anchors.
        if not isinstance(settings,dict) or settings!=runtime["criticalAppSettings"]:core.fail("provisioning-bridge-settings")
        critical={key:settings[key] for key in sorted(settings)}
        if core.digest(core.canonical(critical))!=runtime["criticalAppSettingsSha256"]:core.fail("provisioning-bridge-settings")
        site_properties=bridge_document.get("properties") if isinstance(bridge_document,dict) else None
        web=self._json(self.t("GET","https://management.azure.com"+bridge_resource+"/config/web?api-version=2025-03-01",{"Accept":"application/json"},None),"provisioning-bridge-web-config")
        web_properties=web.get("properties") if isinstance(web,dict) else None
        ftp=self._json(self.t("GET","https://management.azure.com"+bridge_resource+"/basicPublishingCredentialsPolicies/ftp?api-version=2025-03-01",{"Accept":"application/json"},None),"provisioning-bridge-ftp-policy")
        scm=self._json(self.t("GET","https://management.azure.com"+bridge_resource+"/basicPublishingCredentialsPolicies/scm?api-version=2025-03-01",{"Accept":"application/json"},None),"provisioning-bridge-scm-policy")
        source_response=self.t("GET","https://management.azure.com"+bridge_resource+"/sourcecontrols/web?api-version=2025-03-01",{"Accept":"application/json"},None)
        if source_response.status==404:source_control={"status":404}
        elif source_response.status==200:
            try:source_doc=json.loads(source_response.body)
            except Exception:core.fail("provisioning-bridge-source-control")
            source_properties=source_doc.get("properties") if isinstance(source_doc,dict) else None
            if not isinstance(source_properties,dict):core.fail("provisioning-bridge-source-control")
            source_control={"status":200,"repoUrl":source_properties.get("repoUrl"),"branch":source_properties.get("branch"),"isManualIntegration":source_properties.get("isManualIntegration",False)}
        else:core.fail("provisioning-bridge-source-control")
        outbound=site_properties.get("outboundVnetRouting") if isinstance(site_properties,dict) else None
        posture={"siteResourceId":bridge_resource,"name":bridge_document.get("name"),"type":bridge_document.get("type"),"kind":bridge_document.get("kind"),"serverFarmId":site_properties.get("serverFarmId") if isinstance(site_properties,dict) else None,"httpsOnly":bridge_document.get("httpsOnly"),"publicNetworkAccess":site_properties.get("publicNetworkAccess") if isinstance(site_properties,dict) else None,"virtualNetworkSubnetId":site_properties.get("virtualNetworkSubnetId") if isinstance(site_properties,dict) else None,"outboundVnetRouting":{"allTraffic":outbound.get("allTraffic"),"applicationTraffic":outbound.get("applicationTraffic")} if isinstance(outbound,dict) else None,"webConfig":{key:web_properties.get(key) if isinstance(web_properties,dict) else None for key in ("alwaysOn","linuxFxVersion","ftpsState","minTlsVersion","scmMinTlsVersion","scmType","http20Enabled","vnetRouteAllEnabled")},"ftpBasicAuthAllowed":ftp.get("properties",{}).get("allow"),"scmBasicAuthAllowed":scm.get("properties",{}).get("allow"),"sourceControl":source_control}
        if posture!=runtime["sitePosture"] or core.digest(core.canonical(posture))!=runtime["sitePostureSha256"]:core.fail("provisioning-bridge-posture")
        sites=self._pages(runtime["siteInventoryQuery"],"provisioning-site-inventory")
        sensitive=set(runtime["sensitiveIdentityResourceIds"]);attachments={}
        for site in sites:
            site_id=str(site.get("id") or "").lower();identity=site.get("identity") if isinstance(site,dict) else None
            user_assigned=identity.get("userAssignedIdentities") if isinstance(identity,dict) else None
            found=sorted(str(value).lower() for value in user_assigned if str(value).lower() in sensitive) if isinstance(user_assigned,dict) else []
            if found:attachments[site_id]=found
        if attachments!={bridge_resource.lower():sorted(sensitive)} or core.digest(core.canonical(attachments))!=runtime["sensitiveIdentityAttachmentSha256"]:core.fail("provisioning-sensitive-identity-attachment")
        # The source-pinned Resource Graph observation covers attachment-capable
        # resource types beyond App Service.  At action time, exact UAMI-scope
        # RBAC inventories prove that no non-Owner principal can attach one of
        # these identities after bootstrap.
        expected_graph={identity:[bridge_resource.lower()] for identity in sorted(sensitive)}
        graph_inventory=runtime["resourceGraphAttachmentInventory"]
        if (graph_inventory["sensitiveIdentityAttachments"]!=expected_graph
                or core.digest(core.canonical(expected_graph))!=graph_inventory["projectionSha256"]):core.fail("provisioning-resource-graph-attachment")
        assigner_boundaries={}
        owner_definition=runtime["identityAssignmentBoundaries"]["ownerRoleDefinitionId"].lower()
        for identity,boundary in runtime["identityAssignmentBoundaries"]["items"].items():
            documents=self._pages(boundary["roleAssignmentsQuery"],"provisioning-uami-scope-assignments")
            assigners=[];definition_cache={}
            for document in documents:
                assignment=self._assignment_any(document);definition_id=assignment["properties"]["roleDefinitionId"]
                if not self._scope_covers_bridge(assignment["properties"]["scope"],identity):continue
                if definition_id not in definition_cache:
                    definition_doc=self._json(self.t("GET","https://management.azure.com"+definition_id+"?api-version=2022-04-01",{"Accept":"application/json"},None),"provisioning-uami-definition")
                    definition_cache[definition_id]=self._definition_any(definition_doc)
                if definition_id==owner_definition:continue
                if self._definition_grants(definition_cache[definition_id],("Microsoft.ManagedIdentity/userAssignedIdentities/assign/action",)):
                    assigners.append(assignment)
            assigners.sort(key=lambda item:item["id"])
            if ([item["id"] for item in assigners]!=boundary["allowedNonOwnerAssignerAssignmentIds"]
                    or core.digest(core.canonical(assigners))!=boundary["assignerProjectionSha256"]):core.fail("provisioning-uami-assigner")
            assigner_boundaries[identity]=assigners
        legacy=runtime["legacyBridgeRetirement"]
        legacy_doc=self._json(self.t("GET","https://management.azure.com"+legacy["siteResourceId"]+"?api-version=2025-03-01",{"Accept":"application/json"},None),"provisioning-legacy-bridge")
        legacy_properties=legacy_doc.get("properties") if isinstance(legacy_doc,dict) else None;legacy_identity=legacy_doc.get("identity") if isinstance(legacy_doc,dict) else None
        legacy_uamis=legacy_identity.get("userAssignedIdentities") if isinstance(legacy_identity,dict) else None
        # The publisher deliberately has no permanent config/list authority on
        # the legacy site because that endpoint discloses secret app settings.
        # The exact empty transient-name projection is sealed by the immutable
        # signed bootstrap evidence/receipt; live checks below cover every
        # nonsecret site, identity, and RBAC property that can safely be read.
        transient_names=legacy.get("transientAppSettingNamesPresent")
        if transient_names!=[]:core.fail("provisioning-legacy-settings-sealed")
        legacy_assignments=self._pages(legacy["roleAssignmentsQuery"],"provisioning-legacy-role-assignments")
        publisher_mutators=[];legacy_definitions={}
        for document in legacy_assignments:
            assignment=self._assignment_any(document)
            if assignment["properties"]["principalId"]!=self.a.publisher_principal_id.lower():continue
            definition_id=assignment["properties"]["roleDefinitionId"]
            if definition_id not in legacy_definitions:
                definition_doc=self._json(self.t("GET","https://management.azure.com"+definition_id+"?api-version=2022-04-01",{"Accept":"application/json"},None),"provisioning-legacy-definition")
                legacy_definitions[definition_id]=self._definition_any(definition_doc)
            if self._definition_mutates_bridge(legacy_definitions[definition_id],runtime["bridgeMutationBoundary"]["sensitiveActionUniverse"]):publisher_mutators.append(assignment["id"])
        publisher_mutators.sort()
        legacy_projection={"siteResourceId":legacy["siteResourceId"],"state":legacy_properties.get("state") if isinstance(legacy_properties,dict) else None,
                           "publicNetworkAccess":legacy_properties.get("publicNetworkAccess") if isinstance(legacy_properties,dict) else None,
                           "userAssignedIdentityResourceIds":sorted(str(key).lower() for key in legacy_uamis) if isinstance(legacy_uamis,dict) else [],
                           "transientAppSettingNamesPresent":transient_names,"publisherMutatorAssignmentIds":publisher_mutators}
        if (legacy_projection!={key:legacy[key] for key in legacy_projection}
                or core.digest(core.canonical(legacy_projection))!=legacy["projectionSha256"]):core.fail("provisioning-legacy-bridge")
        topology=runtime["networkTopology"];network_live={"mode":topology["mode"]}
        for name,resource in topology.items():
            if name=="mode":continue
            document=self._json(self.t("GET","https://management.azure.com"+resource["resourceId"]+"?api-version="+resource["apiVersion"],{"Accept":"application/json"},None),"provisioning-network-"+name)
            properties=document.get("properties") if isinstance(document,dict) else None
            resource_id=str(document.get("id") or "").lower();resource_type=document.get("type")
            if resource_id!=resource["resourceId"].lower() or not isinstance(properties,dict):core.fail("provisioning-network-"+name)
            if name=="virtualNetwork":projection={"id":resource_id,"type":resource_type,"addressSpacePrefixes":sorted(properties.get("addressSpace",{}).get("addressPrefixes",[]))}
            elif name=="integrationSubnet":
                endpoints=[]
                for item in properties.get("serviceEndpoints",[]):
                    if not isinstance(item,dict):core.fail("provisioning-network-"+name)
                    endpoints.append({"service":item.get("service"),"provisioningState":item.get("provisioningState")})
                endpoints.sort(key=lambda item:str(item.get("service")))
                route_table=properties.get("routeTable");network_security_group=properties.get("networkSecurityGroup")
                if route_table is not None and not isinstance(route_table,dict):core.fail("provisioning-network-"+name)
                if network_security_group is not None and not isinstance(network_security_group,dict):core.fail("provisioning-network-"+name)
                projection={"id":resource_id,"type":resource_type,"virtualNetworkResourceId":resource["virtualNetworkResourceId"].lower(),
                    "delegations":sorted(item.get("properties",{}).get("serviceName") for item in properties.get("delegations",[]) if isinstance(item,dict)),
                    "serviceEndpoints":endpoints,
                    "routeTableResourceId":str((route_table or {}).get("id") or "") or None,
                    "networkSecurityGroupResourceId":str((network_security_group or {}).get("id") or "") or None}
            elif name=="packageStorageAccount":
                acls=properties.get("networkAcls") if isinstance(properties,dict) else None
                if not isinstance(acls,dict):core.fail("provisioning-network-"+name)
                vnet_rules=[]
                for item in acls.get("virtualNetworkRules",[]):
                    if not isinstance(item,dict):core.fail("provisioning-network-"+name)
                    vnet_rules.append({"id":str(item.get("id") or ""),"action":item.get("action"),"state":item.get("state")})
                vnet_rules.sort(key=lambda item:item["id"].lower())
                projection={"id":resource_id,"type":resource_type,"publicNetworkAccess":properties.get("publicNetworkAccess"),"allowBlobPublicAccess":properties.get("allowBlobPublicAccess"),"defaultAction":acls.get("defaultAction"),"bypass":acls.get("bypass"),"ipRules":acls.get("ipRules",[]),"resourceAccessRules":acls.get("resourceAccessRules",[]),"virtualNetworkRules":vnet_rules}
            elif name=="productionSite":
                routing=properties.get("outboundVnetRouting")
                config_document=self._json(self.t("GET","https://management.azure.com"+resource["resourceId"]+"/config/web?api-version="+resource["apiVersion"],{"Accept":"application/json"},None),"provisioning-network-productionSite-config")
                config_properties=config_document.get("properties") if isinstance(config_document,dict) else None
                if not isinstance(config_properties,dict):core.fail("provisioning-network-productionSite-config")
                projection={"id":resource_id,"type":resource_type,"virtualNetworkSubnetId":properties.get("virtualNetworkSubnetId"),"outboundVnetRouting":{"allTraffic":routing.get("allTraffic"),"applicationTraffic":routing.get("applicationTraffic")} if isinstance(routing,dict) else None,"legacyVnetRouteAllEnabled":config_properties.get("vnetRouteAllEnabled")}
            else:core.fail("provisioning-network-kind")
            expected={key:resource[key] for key in resource if key not in {"apiVersion","projectionSha256"}}
            expected={key:(value.lower() if key=="resourceId" else value) for key,value in expected.items()}
            observed={key:(projection.get("id") if key=="resourceId" else projection.get(key)) for key in expected}
            if observed!=expected or core.digest(core.canonical(projection))!=resource["projectionSha256"]:core.fail("provisioning-network-"+name)
            network_live[name]=projection
        mutation=runtime["bridgeMutationBoundary"]
        assignment_documents=self._pages(mutation["bridgeScopeQuery"],"provisioning-bridge-scope-assignments")
        assignment_map={}
        for document in assignment_documents:
            item=self._assignment_any(document)
            if item["id"] in assignment_map and assignment_map[item["id"]]!=item:core.fail("provisioning-bridge-assignment-duplicate")
            assignment_map[item["id"]]=item
        bridge_definition_cache={}
        mutators=[]
        owner_definition=mutation["ownerRoleDefinitionId"].lower()
        for assignment in assignment_map.values():
            if not self._scope_covers_bridge(assignment["properties"]["scope"],bridge_resource):continue
            definition_id=assignment["properties"]["roleDefinitionId"]
            if definition_id not in bridge_definition_cache:
                document=self._json(self.t("GET","https://management.azure.com"+definition_id+"?api-version=2022-04-01",{"Accept":"application/json"},None),"provisioning-bridge-definition")
                bridge_definition_cache[definition_id]=self._definition_any(document)
            if not self._definition_mutates_bridge(bridge_definition_cache[definition_id],mutation["sensitiveActionUniverse"]):continue
            if definition_id==owner_definition:continue
            if assignment["properties"]["condition"] is not None or assignment["properties"]["conditionVersion"] is not None or assignment["properties"]["delegatedManagedIdentityResourceId"] is not None:core.fail("provisioning-bridge-mutator")
            mutators.append(assignment)
        mutators.sort(key=lambda item:item["id"])
        if ([item["id"] for item in mutators]!=mutation["allowedNonOwnerAssignmentIds"]
                or core.digest(core.canonical(mutators))!=mutation["mutatorAssignmentSha256"]):core.fail("provisioning-bridge-mutator")
        key_boundary=evidence["keyVaultBoundary"]
        vault_document=self._json(self.t("GET","https://management.azure.com"+key_boundary["vaultResourceId"]+"?api-version="+key_boundary["vaultApiVersion"],{"Accept":"application/json"},None),"provisioning-key-vault")
        vault_properties=vault_document.get("properties") if isinstance(vault_document,dict) else None
        vault_acls=vault_properties.get("networkAcls") if isinstance(vault_properties,dict) else None
        vault_projection={"id":str(vault_document.get("id") or "").lower(),"name":vault_document.get("name"),"type":vault_document.get("type"),"location":vault_document.get("location"),"properties":{
            "enableRbacAuthorization":vault_properties.get("enableRbacAuthorization") if isinstance(vault_properties,dict) else None,
            "enablePurgeProtection":vault_properties.get("enablePurgeProtection") if isinstance(vault_properties,dict) else None,
            "softDeleteRetentionInDays":vault_properties.get("softDeleteRetentionInDays") if isinstance(vault_properties,dict) else None,
            "publicNetworkAccess":vault_properties.get("publicNetworkAccess") if isinstance(vault_properties,dict) else None,
            "networkAcls":{"bypass":vault_acls.get("bypass"),"defaultAction":vault_acls.get("defaultAction"),"ipRules":vault_acls.get("ipRules",[]),"virtualNetworkRules":vault_acls.get("virtualNetworkRules",[])} if isinstance(vault_acls,dict) else None}}
        if (vault_projection!=key_boundary["vaultProjection"] or core.digest(core.canonical(vault_projection))!=key_boundary["vaultProjectionSha256"]):core.fail("provisioning-key-vault")
        key_document=self._json(self.t("GET","https://management.azure.com"+key_boundary["keyResourceId"]+"?api-version="+key_boundary["keyApiVersion"],{"Accept":"application/json"},None),"provisioning-key")
        key_properties=key_document.get("properties") if isinstance(key_document,dict) else None
        key_attributes=key_properties.get("attributes") if isinstance(key_properties,dict) else None
        key_projection={"id":str(key_document.get("id") or "").lower(),"name":key_document.get("name"),"type":key_document.get("type"),"properties":{
            "keyUriWithVersion":key_properties.get("keyUriWithVersion") if isinstance(key_properties,dict) else None,
            "kty":key_properties.get("kty") if isinstance(key_properties,dict) else None,
            "keySize":key_properties.get("keySize") if isinstance(key_properties,dict) else None,
            "keyOps":key_properties.get("keyOps") if isinstance(key_properties,dict) else None,
            "attributes":{"enabled":key_attributes.get("enabled"),"exportable":key_attributes.get("exportable",False),"expiresOn":key_attributes.get("exp")} if isinstance(key_attributes,dict) else None,
            "releasePolicy":key_properties.get("release_policy") if isinstance(key_properties,dict) else None}}
        if (key_projection!=key_boundary["keyProjection"] or core.digest(core.canonical(key_projection))!=key_boundary["keyProjectionSha256"]):core.fail("provisioning-key")
        key_assignments={}
        for document in self._pages(key_boundary["roleAssignmentsQuery"],"provisioning-key-role-assignments"):
            assignment=self._assignment_any(document)
            if assignment["id"] in key_assignments and key_assignments[assignment["id"]]!=assignment:core.fail("provisioning-key-assignment-duplicate")
            key_assignments[assignment["id"]]=assignment
        key_definitions={};key_sensitive=[];owner_definition=key_boundary["ownerRoleDefinitionId"].lower();key_resource=key_boundary["keyResourceId"]
        for assignment in key_assignments.values():
            if not self._scope_covers_bridge(assignment["properties"]["scope"],key_resource):continue
            definition_id=assignment["properties"]["roleDefinitionId"]
            if definition_id not in key_definitions:
                document=self._json(self.t("GET","https://management.azure.com"+definition_id+"?api-version=2022-04-01",{"Accept":"application/json"},None),"provisioning-key-definition")
                key_definitions[definition_id]=self._definition_any(document)
            if definition_id==owner_definition:continue
            if not self._definition_sensitive_key(key_definitions[definition_id],key_boundary["sensitiveActionUniverse"]):continue
            if assignment["properties"]["condition"] is not None or assignment["properties"]["conditionVersion"] is not None or assignment["properties"]["delegatedManagedIdentityResourceId"] is not None:core.fail("provisioning-key-authority")
            key_sensitive.append(assignment)
        key_sensitive.sort(key=lambda item:item["id"])
        if ([item["id"] for item in key_sensitive]!=key_boundary["allowedNonOwnerSensitiveAssignmentIds"]
                or core.digest(core.canonical(key_sensitive))!=key_boundary["sensitiveAssignmentProjectionSha256"]
                or key_boundary["temporaryKeyProvisioningAssignmentIdsPresent"]!=[]):core.fail("provisioning-key-authority")
        lock=evidence["controllerLockContainer"];url="https://management.azure.com"+lock["scope"]+"?api-version=2025-06-01"
        container=self._json(self.t("GET",url,{"Accept":"application/json"},None),"provisioning-lock-container")
        properties=container.get("properties") if isinstance(container,dict) else None
        projection={"id":str(container.get("id") or "").lower(),"name":container.get("name"),"type":container.get("type"),"publicAccess":"None" if isinstance(properties,dict) and properties.get("publicAccess") in {None,"None"} else properties.get("publicAccess") if isinstance(properties,dict) else None}
        if projection["id"]!=lock["scope"].lower() or projection["publicAccess"]!="None" or core.digest(core.canonical(projection))!=lock["resourceSha256"]:core.fail("provisioning-live-lock-container")
        live_worm={}
        for name,policy in evidence["wormPolicies"].items():
            container_url="https://management.azure.com"+policy["scope"]+"?api-version=2025-06-01"
            container=self._json(self.t("GET",container_url,{"Accept":"application/json"},None),"provisioning-worm-container-"+name)
            container_properties=container.get("properties") if isinstance(container,dict) else None
            container_projection={"id":str(container.get("id") or "").lower(),"name":container.get("name"),"type":container.get("type"),"publicAccess":"None" if isinstance(container_properties,dict) and container_properties.get("publicAccess") in {None,"None"} else container_properties.get("publicAccess") if isinstance(container_properties,dict) else None}
            if (container_projection["id"]!=policy["scope"].lower() or container_projection["publicAccess"]!="None"
                    or core.digest(core.canonical(container_projection))!=policy["containerResourceSha256"]):core.fail("provisioning-live-worm-container-"+name)
            url="https://management.azure.com"+policy["policyResourceId"]+"?api-version=2025-06-01"
            document=self._json(self.t("GET",url,{"Accept":"application/json"},None),"provisioning-worm-"+name)
            properties=document.get("properties") if isinstance(document,dict) else None
            projection={"id":str(document.get("id") or "").lower(),"name":document.get("name"),"type":document.get("type"),"etag":document.get("etag"),"properties":{
                "state":properties.get("state") if isinstance(properties,dict) else None,
                "immutabilityPeriodSinceCreationInDays":properties.get("immutabilityPeriodSinceCreationInDays") if isinstance(properties,dict) else None,
                "allowProtectedAppendWrites":properties.get("allowProtectedAppendWrites",False) if isinstance(properties,dict) else None,
                "allowProtectedAppendWritesAll":properties.get("allowProtectedAppendWritesAll",False) if isinstance(properties,dict) else None}}
            if (projection["id"]!=policy["policyResourceId"].lower() or projection["etag"]!=policy["etag"] or projection["properties"]["state"]!="Locked"
                    or type(projection["properties"]["immutabilityPeriodSinceCreationInDays"]) is not int or projection["properties"]["immutabilityPeriodSinceCreationInDays"]<91
                    or projection["properties"]["allowProtectedAppendWrites"] is not False or projection["properties"]["allowProtectedAppendWritesAll"] is not False
                    or core.digest(core.canonical(projection))!=policy["resourceSha256"]):core.fail("provisioning-live-worm-"+name)
            live_worm[name]={"container":container_projection,"policy":projection}
        bridge_runtime_live={"criticalAppSettings":critical,"sitePosture":posture,"sensitiveIdentityAttachments":attachments,"uamiAssignerBoundaries":assigner_boundaries,"legacyBridge":legacy_projection,"nonOwnerMutators":mutators,"networkTopology":network_live}
        receipt={"schemaVersion":1,"status":"verified","evidenceSha256":core.digest(core.canonical(evidence)),"publisherIdentitySha256":core.digest(core.canonical(publisher_identity)),"assignmentInventorySha256":core.digest(core.canonical([live_by_id[key] for key in sorted(live_by_id)])),"definitionInventorySha256":core.digest(core.canonical([definitions[key] for key in sorted(definitions)])),"identityInventorySha256":core.digest(core.canonical([identities[key] for key in sorted(identities)])),"bridgeRuntimeSha256":core.digest(core.canonical(bridge_runtime_live)),"keyVaultBoundarySha256":core.digest(core.canonical({"vault":vault_projection,"key":key_projection,"sensitiveAssignments":key_sensitive})),"wormInventorySha256":core.digest(core.canonical(live_worm)),"lockContainerSha256":lock["resourceSha256"],"observedAt":_stamp()}
        return receipt

class AppSettingsBoundary:
    """Full-map App Settings read/PUT with digest reconciliation, not fake CAS."""
    def __init__(self,transport,site):self.t=transport;self.site=site
    def read(self):
        response=self.t("POST",self.site+"/config/appsettings/list?api-version=2025-03-01",{"Accept":"application/json"},b"")
        try:doc=json.loads(response.body)
        except Exception:core.fail("appsettings-json")
        values=doc.get("properties") if isinstance(doc,dict) else None
        if response.status!=200 or not isinstance(values,dict) or not all(isinstance(k,str) and isinstance(v,str) for k,v in values.items()):core.fail("appsettings-read")
        return values,core.digest(core.canonical(values))
    def put_if_digest(self,values,expected_digest,*,pre_mutation=None):
        current,current_digest=self.read()
        if current_digest!=expected_digest:core.fail("appsettings-pre-drift")
        # Microsoft.Web exposes no App Settings ETag/CAS.  The RP container
        # lease is therefore the supported legitimate-controller mutex.  It
        # must be renewed after the final full-map read and immediately before
        # the PUT; a lost lease prevents the mutation entirely.
        if pre_mutation is not None:pre_mutation()
        response=self.t("PUT",self.site+"/config/appsettings?api-version=2025-03-01",{"Content-Type":"application/json"},core.canonical({"properties":values}))
        if response.status!=200:core.fail("appsettings-put-ambiguous")
        return core.digest(core.canonical(values))

class ControllerLease:
    """Finite Azure Storage resource-provider lease; no blob data-plane access."""
    def __init__(self,transport,owner,clock=time.monotonic):
        if not isinstance(owner,str) or not owner or len(owner)>512:core.fail("controller-lease-owner")
        # A lease identity is a one-attempt capability, never a logical-owner
        # identifier.  Reusing a deterministic UUID would let a stale process
        # renew or release a later same-owner lease after its first lease had
        # expired and been reacquired.
        self.t=transport;self.clock=clock;self.lease_id=str(uuid.uuid4());self.held=False;self.last_renew=0.0
        self.container=(f"https://management.azure.com/subscriptions/{core.SUBSCRIPTION}/resourceGroups/{core.FIXED_COORDS['controllerLockResourceGroup']}"
                        f"/providers/Microsoft.Storage/storageAccounts/{core.FIXED_COORDS['packageAccount']}/blobServices/default/containers/{core.FIXED_COORDS['controllerLockContainer']}")
        self.url=self.container+"/lease?api-version=2025-06-01"
    def _action(self,action,extra=None,*,require_response_binding=True):
        body={"action":action,"breakPeriod":None,"leaseDuration":None,"leaseId":None,"proposedLeaseId":None};body.update(extra or {})
        response=self.t("POST",self.url,{"Content-Type":"application/json"},core.canonical(body))
        if response.status!=200:return response,None
        if not require_response_binding:return response,None
        try:doc=json.loads(response.body)
        except Exception:core.fail("controller-lease-json")
        if not isinstance(doc,dict) or doc.get("leaseId")!=self.lease_id:core.fail("controller-lease-binding")
        return response,doc
    def acquire(self):
        response,_=self._action("Acquire",{"leaseDuration":60,"proposedLeaseId":self.lease_id})
        if response.status in {409,412}:return False
        if response.status!=200:core.fail("controller-lease-acquire")
        self.held=True;self.last_renew=self.clock();return True
    def assert_held(self):
        if not self.held:core.fail("controller-lease-lost")
    def renew(self,force=False):
        self.assert_held()
        if not force and self.clock()-self.last_renew<20:return
        response,_=self._action("Renew",{"leaseId":self.lease_id})
        if response.status!=200:
            self.held=False;core.fail("controller-lease-lost")
        self.last_renew=self.clock()
    def release(self):
        if not self.held:return
        self.renew(force=True)
        # The documented Release response may omit leaseId.  The mutating
        # request is still bound to our fresh random capability, then a
        # control-plane container read must prove that no lease remains.
        response,_=self._action("Release",{"leaseId":self.lease_id},require_response_binding=False)
        if response.status!=200:core.fail("controller-lease-release")
        self.held=False
        observed=self.t("GET",self.container+"?api-version=2025-06-01",{"Accept":"application/json"},None)
        try:document=json.loads(observed.body)
        except Exception:core.fail("controller-lease-release-readback")
        properties=document.get("properties") if isinstance(document,dict) else None
        expected_id=self.container.removeprefix("https://management.azure.com")
        if (observed.status!=200 or str(document.get("id","")).lower()!=expected_id.lower()
                or document.get("name")!=core.FIXED_COORDS["controllerLockContainer"]
                or document.get("type")!="Microsoft.Storage/storageAccounts/blobServices/containers"
                or not isinstance(properties,dict) or properties.get("leaseStatus")!="Unlocked"
                or properties.get("leaseState")!="Available"):
            core.fail("controller-lease-release-readback")

def acquire_cleanup_controller_lease(transport,owner,*,attempts=8,interval_seconds=10,sleep=time.sleep,lease_factory=ControllerLease):
    """Retry with fresh random capabilities across more than one lease term."""
    if type(attempts) is not int or attempts<2 or interval_seconds<=0 or (attempts-1)*interval_seconds<=60:core.fail("controller-cleanup-retry-window")
    for attempt in range(attempts):
        lease=lease_factory(transport,owner)
        if lease.acquire():return lease
        if attempt<attempts-1:sleep(interval_seconds)
    core.fail("controller-cleanup-lease-busy")

class BridgeLease:
    """RP-lease-serialized, fail-closed transient bridge handoff.

    Microsoft.Web App Settings has no conditional update.  A finite Azure
    Storage resource-provider container lease is the real legitimate-actor
    mutex; caller-repository concurrency is defense in depth. Subscription and
    resource-group owners remain an explicit out-of-band governance boundary.
    """
    CONTROL="PAPERDESK_PRIVATE_RELEASE_CONTROL_JSON"
    EVIDENCE="PAPERDESK_PRIVATE_RELEASE_PROVISIONING_EVIDENCE_JSON"
    EVIDENCE_SHA="PAPERDESK_PRIVATE_RELEASE_PROVISIONING_EVIDENCE_SHA256"
    RECEIPT="PAPERDESK_PRIVATE_RELEASE_BRIDGE_RUNTIME_RECEIPT_JSON"
    RECEIPT_SHA="PAPERDESK_PRIVATE_RELEASE_BRIDGE_RUNTIME_RECEIPT_SHA256"
    TRANSIENT={"PAPERDESK_PRIVATE_RELEASE_ACTIVATION_JSON","PAPERDESK_CONTROL_WORKFLOW_SHA","PAPERDESK_TRANSIENT_GITHUB_TOKEN",EVIDENCE,EVIDENCE_SHA,RECEIPT,RECEIPT_SHA,CONTROL}
    CONTROL_FIELDS=core.TRANSIENT_CONTROL_FIELDS
    @staticmethod
    def durable_settings(activation):
        if not isinstance(activation,core.Activation):core.fail("bridge-durable-settings-contract")
        runtime=activation.provisioning_evidence.get("bridgeRuntime")
        values=runtime.get("criticalAppSettings") if isinstance(runtime,dict) else None
        if (not isinstance(values,dict) or not all(isinstance(key,str) and isinstance(value,str) for key,value in values.items())
                or core.digest(core.canonical(values))!=runtime.get("criticalAppSettingsSha256")):core.fail("bridge-durable-settings-contract")
        return dict(values)
    def __init__(self,transport,activation,activation_json,bootstrap_receipt,github_token,request_name,request,controller_lease,sleep=time.sleep):
        if not isinstance(github_token,str) or len(github_token)<20 or any(c in github_token for c in "\r\n"):core.fail("bridge-github-token")
        self.t=transport;self.a=activation;self.activation_json=activation_json;self.bootstrap_receipt=core.validate_bridge_runtime_receipt(bootstrap_receipt,activation);self.github_token=github_token;self.request_name=request_name;self.request=request;self.controller_lease=controller_lease;self.original=None;self.updated=None;self.owns_transient=False;self.started_by_this=False;self.sleep=sleep
        self.site=f"https://management.azure.com/subscriptions/{core.SUBSCRIPTION}/resourceGroups/{core.FIXED_COORDS['bridgeResourceGroup']}/providers/Microsoft.Web/sites/{core.FIXED_COORDS['bridgeApp']}";self.settings=AppSettingsBoundary(transport,self.site)
    def read_state(self):
        response=self.t("GET",self.site+"?api-version=2025-03-01",{"Accept":"application/json"},None)
        try:doc=json.loads(response.body)
        except Exception:core.fail("bridge-state-json")
        expected_id=f"/subscriptions/{core.SUBSCRIPTION}/resourceGroups/{core.FIXED_COORDS['bridgeResourceGroup']}/providers/Microsoft.Web/sites/{core.FIXED_COORDS['bridgeApp']}"
        if (response.status!=200 or str(doc.get("id","")).lower()!=expected_id.lower() or doc.get("name")!=core.FIXED_COORDS["bridgeApp"]
                or doc.get("type")!="Microsoft.Web/sites" or doc.get("properties",{}).get("state") not in {"Stopped","Running","Starting","Stopping"}):core.fail("bridge-state")
        return doc["properties"]["state"]
    def assert_stopped(self):
        if self.read_state()!="Stopped":core.fail("bridge-not-stopped")
    def _control(self,original_digest):
        if not isinstance(self.request,dict) or not core.NAME.fullmatch(str(self.request_name)) or not core.SHA256.fullmatch(original_digest):core.fail("bridge-control-input")
        now=dt.datetime.now(dt.timezone.utc);stamp=lambda value:value.strftime("%Y-%m-%dT%H:%M:%S.")+f"{value.microsecond//1000:03d}Z"
        repository=os.environ.get("GITHUB_REPOSITORY",core.OWNER_REPOSITORY)
        caller_sha=os.environ.get("GITHUB_SHA",self.request["controlWorkflowSha"])
        workflow_ref=os.environ.get("GITHUB_WORKFLOW_REF",core.OWNER_WORKFLOW_REF)
        workflow_name=os.environ.get("GITHUB_WORKFLOW",core.OWNER_WORKFLOW_NAME)
        event=os.environ.get("GITHUB_EVENT_NAME","workflow_dispatch")
        owner_policy=core.bridge_owner_policy(self.request["operation"])
        if (repository!=core.OWNER_REPOSITORY or os.environ.get("GITHUB_REPOSITORY_ID",core.OWNER_REPOSITORY_ID)!=core.OWNER_REPOSITORY_ID
                or os.environ.get("GITHUB_REPOSITORY_OWNER_ID",core.OWNER_ID)!=core.OWNER_ID or not core.SHA40.fullmatch(caller_sha)
                or workflow_ref!=owner_policy["workflowRef"] or workflow_name!=owner_policy["workflowName"]
                or event not in owner_policy["events"] or os.environ.get("GITHUB_REF_NAME","main")!="main"):core.fail("bridge-control-owner")
        return {"schemaVersion":1,"state":"transient","repository":repository,"repositoryId":core.OWNER_REPOSITORY_ID,"ownerId":core.OWNER_ID,
                "callerSha":caller_sha,"workflowId":owner_policy["workflowId"],"workflowName":workflow_name,"workflowPath":owner_policy["workflowPath"],
                "workflowRef":workflow_ref,"event":event,"headBranch":"main",
                "runId":os.environ.get("GITHUB_RUN_ID",self.request["acceptanceRunId"]),"runAttempt":os.environ.get("GITHUB_RUN_ATTEMPT",self.request["acceptanceRunAttempt"]),
                "operation":self.request["operation"],"sourceSha":self.request["sourceSha"],"requestName":self.request_name,
                "originalSettingsSha256":original_digest,"githubTokenSha256":core.digest(self.github_token.encode()),
                "provisioningEvidenceSha256":core.digest(core.canonical(self.a.provisioning_evidence)),
                "bridgeRuntimeReceiptSha256":core.digest(core.canonical(self.bootstrap_receipt)),"acquiredAt":stamp(now),"expiresAt":stamp(now+dt.timedelta(seconds=core.TRANSIENT_LIFETIME_SECONDS))}
    def acquire(self):
        self.controller_lease.renew(force=True)
        self.assert_stopped()
        values,digest=self.settings.read()
        present={name for name in self.TRANSIENT if name in values}
        if present or "PAPERDESK_BRIDGE_BOOTSTRAP_SELF_TEST_JSON" in values:core.fail("bridge-transient-preexisting")
        durable=self.durable_settings(self.a)
        if values!=durable:core.fail("bridge-durable-settings-drift")
        evidence_raw=core.canonical(self.a.provisioning_evidence).decode()
        receipt_raw=core.canonical(self.bootstrap_receipt).decode()
        control=self._control(digest);updated=dict(values);updated.update({"PAPERDESK_PRIVATE_RELEASE_ACTIVATION_JSON":self.activation_json,"PAPERDESK_CONTROL_WORKFLOW_SHA":self.a.workflow_sha,"PAPERDESK_TRANSIENT_GITHUB_TOKEN":self.github_token,self.EVIDENCE:evidence_raw,self.EVIDENCE_SHA:core.digest(evidence_raw.encode()),self.RECEIPT:receipt_raw,self.RECEIPT_SHA:core.digest(receipt_raw.encode()),self.CONTROL:core.canonical(control).decode()})
        self.original=values;self.updated=updated
        error=None
        try:self.settings.put_if_digest(updated,digest,pre_mutation=lambda:self.controller_lease.renew(force=True))
        except Exception as exc:error=exc
        observed,_=self.settings.read()
        if observed!=updated:
            if observed==values and error is not None:raise error
            core.fail("bridge-settings-acquire-third-state")
        self.owns_transient=True
    def action(self,name):
        if name not in {"start","stop"}:core.fail("bridge-action")
        if not self.owns_transient:core.fail("bridge-action-unowned")
        self.controller_lease.renew(force=True)
        before=self.read_state();expected="Running" if name=="start" else "Stopped"
        if name=="start" and before!="Stopped":core.fail("bridge-start-prestate")
        if name=="stop" and before=="Stopped":self.started_by_this=False;return
        self.controller_lease.renew(force=True)
        response=self.t("POST",self.site+f"/{name}?api-version=2025-03-01",{},b"")
        last=before
        for attempt in range(60):
            self.controller_lease.renew()
            last=self.read_state()
            if name=="start" and last!="Stopped":self.started_by_this=True
            if last==expected:
                self.started_by_this=(name=="start");return
            if attempt<59:self.sleep(1)
        if response.status not in {200,202} and last==before:core.fail("bridge-"+name+"-not-applied")
        core.fail("bridge-"+name+"-third-state")
    def emergency_stop_owned(self):
        """Stop only this invocation's exact injected bridge after reverify loss.

        No settings write is permitted here.  A changed transient map or a
        lost RP lease fails closed without stopping another controller.
        """
        if not self.owns_transient or not self.started_by_this or self.updated is None:core.fail("bridge-emergency-stop-unowned")
        self.controller_lease.renew(force=True)
        current,_=self.settings.read()
        if current!=self.updated:core.fail("bridge-emergency-stop-third-state")
        state=self.read_state()
        if state=="Stopped":self.started_by_this=False;return
        if state not in {"Running","Starting","Stopping"}:core.fail("bridge-emergency-stop-state")
        self.controller_lease.renew(force=True)
        response=self.t("POST",self.site+"/stop?api-version=2025-03-01",{},b"")
        if response.status not in {200,202}:core.fail("bridge-emergency-stop")
        for attempt in range(60):
            self.controller_lease.renew()
            if self.read_state()=="Stopped":self.started_by_this=False;return
            if attempt<59:self.sleep(1)
        core.fail("bridge-emergency-stop-timeout")
    def release(self):
        if not self.owns_transient or self.original is None:return
        self.controller_lease.renew(force=True)
        self.assert_stopped()
        current,digest=self.settings.read()
        if current==self.original:self.owns_transient=False;return
        if current!=self.updated:core.fail("bridge-settings-release-third-state")
        error=None
        try:self.settings.put_if_digest(self.original,digest,pre_mutation=lambda:self.controller_lease.renew(force=True))
        except Exception as exc:error=exc
        observed,_=self.settings.read()
        if observed!=self.original:
            if observed==self.updated and error is not None:raise error
            core.fail("bridge-settings-release-third-state")
        self.owns_transient=False

def _validate_cleanup_trigger(trigger,record):
    if not isinstance(trigger,dict) or trigger.get("schemaVersion")!=1 or trigger.get("mode") not in {"workflow-run-completed","scheduled-expiry","manual-expiry"}:core.fail("controller-cleanup-trigger")
    mode=trigger["mode"]
    if mode=="workflow-run-completed":
        fields={"schemaVersion","mode","runId","runAttempt","repository","repositoryId","ownerId","workflowId","workflowName","workflowPath","event","headBranch","headSha","status"}
        if (set(trigger)!=fields or trigger.get("status")!="completed" or trigger.get("runId")!=record["runId"]
                or trigger.get("runAttempt")!=record["runAttempt"] or trigger.get("repository")!=record["repository"]
                or trigger.get("repositoryId")!=record["repositoryId"] or trigger.get("ownerId")!=record["ownerId"]
                or trigger.get("workflowId")!=record["workflowId"] or trigger.get("workflowName")!=record["workflowName"]
                or trigger.get("workflowPath")!=record["workflowPath"] or trigger.get("event")!=record["event"]
                or trigger.get("headBranch")!=record["headBranch"] or trigger.get("headSha")!=record["callerSha"]):core.fail("controller-cleanup-trigger-owner")
    elif set(trigger)!={"schemaVersion","mode"}:core.fail("controller-cleanup-trigger")
    return mode

def cleanup_expired_transient(activation,transport,*,now=None,run_liveness=None,controller_lease=None,trigger=None,provisioning_verifier=None):
    """Remove only the exact expired transient state; never overwrite drift."""
    if controller_lease is None:core.fail("controller-cleanup-lease-required")
    if provisioning_verifier is None:core.fail("controller-cleanup-provisioning-required")
    provisioning_verifier.verify()
    controller_lease.renew(force=True)
    now=now or dt.datetime.now(dt.timezone.utc);site=f"https://management.azure.com/subscriptions/{core.SUBSCRIPTION}/resourceGroups/{core.FIXED_COORDS['bridgeResourceGroup']}/providers/Microsoft.Web/sites/{core.FIXED_COORDS['bridgeApp']}";settings=AppSettingsBoundary(transport,site)
    current,current_digest=settings.read();present={name for name in BridgeLease.TRANSIENT if name in current};durable=BridgeLease.durable_settings(activation)
    if "PAPERDESK_BRIDGE_BOOTSTRAP_SELF_TEST_JSON" in current:core.fail("controller-cleanup-third-state")
    if not present:
        if current!=durable:core.fail("controller-cleanup-third-state")
        return {"schemaVersion":1,"status":"clean","cleaned":False}
    if present!=BridgeLease.TRANSIENT or set(current)!=(set(durable)|BridgeLease.TRANSIENT):core.fail("controller-cleanup-third-state")
    try:record=json.loads(current[BridgeLease.CONTROL])
    except Exception:core.fail("controller-cleanup-control-json")
    try:owner_policy=core.bridge_owner_policy(record.get("operation")) if isinstance(record,dict) else None
    except core.MailboxError:owner_policy=None
    if (not isinstance(record,dict) or set(record)!=BridgeLease.CONTROL_FIELDS or record.get("schemaVersion")!=1 or record.get("state")!="transient" or not isinstance(owner_policy,dict)
            or record.get("repository")!=core.OWNER_REPOSITORY or record.get("repositoryId")!=core.OWNER_REPOSITORY_ID or record.get("ownerId")!=core.OWNER_ID
            or not core.SHA40.fullmatch(str(record.get("callerSha"))) or record.get("workflowId")!=owner_policy.get("workflowId")
            or record.get("workflowName")!=owner_policy.get("workflowName") or record.get("workflowPath")!=owner_policy.get("workflowPath")
            or record.get("workflowRef")!=owner_policy.get("workflowRef") or record.get("event") not in owner_policy.get("events",set()) or record.get("headBranch")!="main"
            or not core.POSITIVE.fullmatch(str(record.get("runId"))) or not core.POSITIVE.fullmatch(str(record.get("runAttempt")))
            or record.get("operation") not in {"registry-bridge-preflight","bootstrap-prepare","bootstrap-consume","prepare-candidate","consume-candidate","persist-accepted-release","prepare-rollback","complete-rollback"}
            or not core.SHA40.fullmatch(str(record.get("sourceSha"))) or not core.NAME.fullmatch(str(record.get("requestName")))
            or not core.SHA256.fullmatch(str(record.get("originalSettingsSha256"))) or not core.SHA256.fullmatch(str(record.get("githubTokenSha256")))
            or not core.SHA256.fullmatch(str(record.get("provisioningEvidenceSha256")))
            or not core.SHA256.fullmatch(str(record.get("bridgeRuntimeReceiptSha256")))
            or core.canonical(record).decode()!=current[BridgeLease.CONTROL]):core.fail("controller-cleanup-control")
    acquired=core.parse_time(record["acquiredAt"],"controller-cleanup-acquired");expires=core.parse_time(record["expiresAt"],"controller-cleanup-expires")
    if expires<=acquired or (expires-acquired).total_seconds()!=core.TRANSIENT_LIFETIME_SECONDS:core.fail("controller-cleanup-time")
    trigger_mode=_validate_cleanup_trigger(trigger,record)
    if run_liveness is None:core.fail("controller-cleanup-liveness-required")
    liveness=run_liveness(record)
    if (not isinstance(liveness,dict) or liveness.get("runId")!=record["runId"] or liveness.get("runAttempt")!=record["runAttempt"]):core.fail("controller-cleanup-liveness")
    if trigger_mode=="workflow-run-completed":
        if liveness.get("status")!="completed":core.fail("controller-cleanup-active")
        cleanup_mode="terminal-owner"
    else:
        if now<expires:core.fail("controller-cleanup-not-expired")
        if liveness.get("status")=="completed":cleanup_mode="expired-owner-completed"
        elif liveness.get("status")=="unavailable":cleanup_mode="expired-owner-api-unavailable"
        else:core.fail("controller-cleanup-active")
    try:
        activation_doc=json.loads(current["PAPERDESK_PRIVATE_RELEASE_ACTIVATION_JSON"])
        evidence_doc=json.loads(current[BridgeLease.EVIDENCE])
        observed_activation=core.load_activation_document(activation_doc,runtime_workflow_sha=activation.workflow_sha,observed_bridge_package_sha256=activation.bridge_package_sha256,provisioning_evidence=evidence_doc)
        receipt_doc=json.loads(current[BridgeLease.RECEIPT]);core.validate_bridge_runtime_receipt(receipt_doc,observed_activation)
    except Exception:core.fail("controller-cleanup-third-state")
    if (observed_activation!=activation or core.canonical(activation_doc).decode()!=current["PAPERDESK_PRIVATE_RELEASE_ACTIVATION_JSON"]
            or current["PAPERDESK_CONTROL_WORKFLOW_SHA"]!=activation.workflow_sha or current["PAPERDESK_BRIDGE_PACKAGE_SHA256"]!=activation.bridge_package_sha256
            or core.canonical(evidence_doc).decode()!=current[BridgeLease.EVIDENCE]
            or current[BridgeLease.EVIDENCE_SHA]!=record["provisioningEvidenceSha256"]
            or core.digest(current[BridgeLease.EVIDENCE].encode())!=record["provisioningEvidenceSha256"]
            or core.canonical(receipt_doc).decode()!=current[BridgeLease.RECEIPT]
            or current[BridgeLease.RECEIPT_SHA]!=record["bridgeRuntimeReceiptSha256"]
            or core.digest(current[BridgeLease.RECEIPT].encode())!=record["bridgeRuntimeReceiptSha256"]
            or core.digest(current["PAPERDESK_TRANSIENT_GITHUB_TOKEN"].encode())!=record["githubTokenSha256"]):core.fail("controller-cleanup-third-state")
    cleaned={key:value for key,value in current.items() if key not in BridgeLease.TRANSIENT}
    if cleaned!=durable or core.digest(core.canonical(cleaned))!=record["originalSettingsSha256"]:core.fail("controller-cleanup-third-state")
    controller_lease.renew(force=True)
    current_again,digest_again=settings.read()
    if current_again!=current or digest_again!=current_digest:core.fail("controller-cleanup-third-state")
    provisioning_verifier.verify()
    controller_lease.renew(force=True)
    stop=transport("POST",site+"/stop?api-version=2025-03-01",{},b"")
    if stop.status not in {200,202}:core.fail("controller-cleanup-stop")
    stopped=False
    for attempt in range(60):
        controller_lease.renew()
        state=transport("GET",site+"?api-version=2025-03-01",{"Accept":"application/json"},None)
        try:state_doc=json.loads(state.body)
        except Exception:core.fail("controller-cleanup-state-json")
        if state.status!=200 or state_doc.get("properties",{}).get("state") not in {"Running","Stopping","Stopped"}:core.fail("controller-cleanup-state")
        if state_doc["properties"]["state"]=="Stopped":stopped=True;break
        if attempt<59:time.sleep(1)
    if not stopped:core.fail("controller-cleanup-not-stopped")
    provisioning_verifier.verify()
    controller_lease.renew(force=True)
    error=None
    try:settings.put_if_digest(cleaned,current_digest,pre_mutation=lambda:controller_lease.renew(force=True))
    except Exception as exc:error=exc
    observed,observed_digest=settings.read()
    if observed!=cleaned or observed_digest!=record["originalSettingsSha256"]:
        if observed==current and error is not None:raise error
        core.fail("controller-cleanup-third-state")
    return {"schemaVersion":1,"status":"cleaned","cleaned":True,"cleanupMode":cleanup_mode,"sourceSha":record["sourceSha"],"operation":record["operation"],"requestNameSha256":core.digest(record["requestName"].encode()),"originalSettingsSha256":record["originalSettingsSha256"],"ownerRunConclusion":liveness.get("conclusion","") or liveness["status"]}

def _stamp(now=None):
    value=now or dt.datetime.now(dt.timezone.utc);return value.strftime("%Y-%m-%dT%H:%M:%S.")+f"{value.microsecond//1000:03d}Z"

def _followup(request,operation,*,accepted=None,pending=None,consumed=None,rollback=None,plan=None,now=None):
    now=now or dt.datetime.now(dt.timezone.utc);result=dict(request);result.update({"operation":operation,"candidateRunId":None,"candidateRunAttempt":None,"artifactId":"","artifactSha256":"","artifactMember":"","artifactMemberSha256":"","nonce":secrets.token_hex(16),"issuedAt":_stamp(now),"expiresAt":_stamp(now+dt.timedelta(minutes=15)),"acceptedBaseline":accepted,"pendingRelease":pending,"consumedMarker":consumed,"rollbackPreparation":rollback,"activationPlan":plan,"activationProof":None});return result

def _run_bridge(request,activation,activation_doc,github_token,transport,poll,provisioning_verifier):
    request,_,_=core.validate_request(request,now=dt.datetime.now(dt.timezone.utc));request_name=f"pdreq-{request['sourceRunId']}-{request['sourceRunAttempt']}-{request['nonce']}";result_name=f"pdres-{request['sourceRunId']}-{request['sourceRunAttempt']}-{request['nonce']}"
    mailbox=core.MailboxClient(activation.mailbox_resource_group,transport,request_creator=activation.publisher_principal_id,result_creator=activation.bridge_principal_id)
    owner="|".join((os.environ.get("GITHUB_REPOSITORY","Sethvirak/MasterDataStructure"),os.environ.get("GITHUB_RUN_ID",request["acceptanceRunId"]),os.environ.get("GITHUB_RUN_ATTEMPT",request["acceptanceRunAttempt"]),request_name))
    controller_lease=ControllerLease(transport,owner);lease=BridgeLease(transport,activation,core.canonical(activation_doc).decode(),provisioning_verifier.bootstrap_receipt,github_token,request_name,request,controller_lease)
    primary=None;result=None;cleanup=[];request_owned=False;controller_owned=False
    try:
        if provisioning_verifier is None:core.fail("external-provisioning-required")
        provisioning_verifier.verify()
        if not controller_lease.acquire():core.fail("controller-lease-busy")
        controller_owned=True;mailbox.put_create(request_name,request);request_owned=True;lease.acquire();lease.action("start")
        def guarded_poll(value):controller_lease.renew();poll(value)
        history=core.WebJobClient(core.FIXED_COORDS["bridgeResourceGroup"],core.FIXED_COORDS["bridgeApp"],core.FIXED_COORDS["bridgeWebJob"],transport).run_and_wait(request_name,poll=guarded_poll,pre_run=lambda:controller_lease.renew(force=True))
        envelope=None
        for attempt in range(180):
            try:envelope=mailbox.get(result_name);break
            except core.MailboxError:guarded_poll(attempt)
        if envelope is None:core.fail("external-result-timeout")
        result=core.verify_signed_result(envelope,request,expected_key_id=activation.signing_key_id,expected_key_version=activation.signing_key_version,jwk=activation.signing_public_jwk)
        observed_id=history.get("id");observed_run=history.get("properties",{}).get("web_job_id",observed_id)
        if result["webJobHistoryId"] not in {observed_id,observed_run} or result["webJobRunId"]!=observed_run:core.fail("external-history-result-binding")
    except Exception as error:primary=error
    cleanup_authorized=True
    try:provisioning_verifier.verify()
    except Exception as error:
        cleanup_authorized=False;cleanup.append(("provisioning-reverify",error))
    actions=[]
    if cleanup_authorized and lease.started_by_this:actions.append(("stop",lambda:lease.action("stop")))
    elif not cleanup_authorized and lease.started_by_this:actions.append(("emergency-stop",lease.emergency_stop_owned))
    if cleanup_authorized and lease.owns_transient:actions.append(("release",lease.release))
    if cleanup_authorized and request_owned:actions.append(("delete-request",lambda:(controller_lease.renew(force=True),mailbox.delete(request_name))[-1]))
    if controller_owned:actions.append(("release-controller-lease",controller_lease.release))
    for label,action in actions:
        try:action()
        except Exception as error:cleanup.append((label,error))
    # Retain every exact signed terminal result.  It is the immutable recovery
    # evidence when a response, later cleanup, or caller process is lost; the
    # separately bounded mailbox-retention operation prunes old request/result
    # pairs only after their authenticated provenance is independently known.
    if primary is not None:
        if cleanup and hasattr(primary,"add_note"):primary.add_note("cleanup failures: "+",".join(label for label,_ in cleanup))
        raise primary
    terminal=request["operation"] in {"bootstrap-consume","consume-candidate","abort-candidate","persist-accepted-release","complete-rollback"}
    if cleanup and not terminal:raise core.MailboxError("external-cleanup:"+",".join(label for label,_ in cleanup))
    return result,{"status":"complete" if not cleanup else "cleanup-pending","failures":[label for label,_ in cleanup]}

def execute(request,activation_doc,*,activation_raw,runtime_workflow_sha,package_sha,provisioning_evidence,bridge_runtime_receipt,github_token,transport,poll=lambda _:time.sleep(5),activate=False,provisioning_verifier=None):
    activation=core.load_activation_document(activation_doc,runtime_workflow_sha=runtime_workflow_sha,observed_bridge_package_sha256=package_sha,provisioning_evidence=provisioning_evidence,raw_document=activation_raw);request,_,_=core.validate_request(request,now=dt.datetime.now(dt.timezone.utc))
    if request["controlWorkflowSha"]!=activation.workflow_sha:core.fail("external-request-workflow")
    if request["operation"]=="registry-bridge-preflight" and activate:core.fail("external-read-only-operation")
    provisioning_verifier=provisioning_verifier or ProvisioningVerifier(transport,activation,bridge_runtime_receipt)
    housekeeping=[];prepared,prepared_cleanup=_run_bridge(request,activation,activation_doc,github_token,transport,poll,provisioning_verifier);housekeeping.append({"operation":request["operation"],**prepared_cleanup})
    if not activate:return {"bridgeResult":prepared,"activation":None,"housekeeping":housekeeping}
    if request["operation"]=="bootstrap-prepare":
        consumed,consumed_cleanup=_run_bridge(_followup(request,"bootstrap-consume",accepted=prepared["records"]["acceptedBaseline"]),activation,activation_doc,github_token,transport,poll,provisioning_verifier);housekeeping.append({"operation":"bootstrap-consume",**consumed_cleanup})
        return {"bridgeResult":prepared,"consumedBridgeResult":consumed,"activation":{"status":consumed["metadata"].get("activationStatus"),"sourceSha":request["sourceSha"],"settlement":{"sourceSha":request["sourceSha"],"healthy":True,"proof":consumed["metadata"].get("activationProof")},"consumption":{"status":"complete","bridgeResult":consumed}},"housekeeping":housekeeping}
    if request["operation"]=="prepare-candidate":
        plan=prepared["metadata"].get("activationPlan")
        consumed,cleanup=_run_bridge(_followup(request,"consume-candidate",accepted=prepared["records"]["acceptedBaseline"],pending=prepared["records"]["pendingRelease"],plan=plan),activation,activation_doc,github_token,transport,poll,provisioning_verifier);housekeeping.append({"operation":"consume-candidate",**cleanup})
        activated={"status":consumed["metadata"].get("activationStatus"),"sourceSha":request["sourceSha"],"configDigest":consumed["metadata"].get("finalSettingsSha256"),"settlement":{"sourceSha":request["sourceSha"],"healthy":True,"proof":consumed["metadata"].get("activationProof")},"consumption":{"status":"complete","bridgeResult":consumed}}
        return {"bridgeResult":prepared,"consumedBridgeResult":consumed,"activation":activated,"housekeeping":housekeeping}
    if request["operation"]=="prepare-rollback":
        plan=prepared["metadata"].get("activationPlan")
        completed,cleanup=_run_bridge(_followup(request,"complete-rollback",accepted=prepared["records"]["acceptedBaseline"],rollback=prepared["records"]["manifest"],plan=plan),activation,activation_doc,github_token,transport,poll,provisioning_verifier);housekeeping.append({"operation":"complete-rollback",**cleanup})
        activated={"status":completed["metadata"].get("activationStatus"),"sourceSha":request["sourceSha"],"configDigest":completed["metadata"].get("finalSettingsSha256"),"settlement":{"sourceSha":request["sourceSha"],"healthy":True,"proof":completed["metadata"].get("activationProof")},"completion":{"status":"complete","bridgeResult":completed}}
        return {"bridgeResult":prepared,"completedBridgeResult":completed,"activation":activated,"housekeeping":housekeeping}
    core.fail("external-activate-operation")

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--request");parser.add_argument("--activation",required=True);parser.add_argument("--provisioning-evidence",required=True);parser.add_argument("--bridge-runtime-receipt",required=True);parser.add_argument("--workflow-sha",required=True);parser.add_argument("--package-sha",required=True);parser.add_argument("--output",required=True);parser.add_argument("--activate",action="store_true");parser.add_argument("--cleanup-stale",action="store_true");args=parser.parse_args()
    if args.cleanup_stale and (args.request is not None or args.activate):parser.error("--cleanup-stale is exclusive")
    if not args.cleanup_stale and args.request is None:parser.error("--request is required")
    activation_raw=Path(args.activation).read_text(encoding="utf-8");activation_doc=json.loads(activation_raw);provisioning_evidence=json.loads(Path(args.provisioning_evidence).read_text());bridge_runtime_receipt=json.loads(Path(args.bridge_runtime_receipt).read_text());activation=core.load_activation_document(activation_doc,runtime_workflow_sha=args.workflow_sha,observed_bridge_package_sha256=args.package_sha,provisioning_evidence=provisioning_evidence,raw_document=activation_raw);core.validate_bridge_runtime_receipt(bridge_runtime_receipt,activation);tokens=CliTokens(activation);transport=Arm(tokens)
    if args.cleanup_stale:
        owner="cleanup|"+"|".join((os.environ.get("GITHUB_REPOSITORY",""),os.environ.get("GITHUB_RUN_ID",""),os.environ.get("GITHUB_RUN_ATTEMPT","")))
        verifier=ProvisioningVerifier(transport,activation,bridge_runtime_receipt);verifier.verify();controller_lease=acquire_cleanup_controller_lease(transport,owner)
        try:
            try:trigger=json.loads(os.environ.get("PAPERDESK_CLEANUP_TRIGGER_JSON",""))
            except Exception:core.fail("controller-cleanup-trigger-json")
            result=cleanup_expired_transient(activation,transport,run_liveness=GitHubRunLiveness(os.environ.get("GH_TOKEN","")),controller_lease=controller_lease,trigger=trigger,provisioning_verifier=verifier)
        finally:controller_lease.release()
    else:
        request=json.loads(Path(args.request).read_text());result=execute(request,activation_doc,activation_raw=activation_raw,runtime_workflow_sha=args.workflow_sha,package_sha=args.package_sha,provisioning_evidence=provisioning_evidence,bridge_runtime_receipt=bridge_runtime_receipt,github_token=os.environ.get("GH_TOKEN",""),transport=transport,activate=args.activate)
    Path(args.output).write_bytes(core.canonical(result))
    if isinstance(result,dict) and any(item.get("status")!="complete" for item in result.get("housekeeping",[]) if isinstance(item,dict)):
        core.fail("external-cleanup-pending")
if __name__=="__main__":main()
