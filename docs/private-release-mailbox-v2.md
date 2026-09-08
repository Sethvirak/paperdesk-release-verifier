# Private release mailbox V2 (dormant exact-SHA source)

Private release mailbox V2 is the proposed production-control path. It keeps
release bytes, Storage data-plane credentials, production configuration writes,
and result signing off the GitHub-hosted runner. The committed source is still
**dormant**: every activation value in
`contracts/private_release_mailbox_contract.json` is null, the provisioning
evidence is source-dormant, and the reusable workflow rejects that state before
Azure login.

No Azure mutation is authorized merely by merging this source. The sole pre-S2
Azure-mutation exception is a separately reviewed, external single-use
authorization for the exact local bootstrap plan from the superseding
**S1-prime** source. That exception does not authorize the reusable workflow,
mailbox or release operations, production activation or deployment,
accepted-release operations, or caller integration. Evidence commit, S2 review,
federated-identity credential (FIC) repin, activated environment document, and
exact caller pins remain separate gates.

## Immutable workflow and caller boundary

There is one externally reusable Azure control workflow:
`.github/workflows/azure-production-control.yml`. It owns normal operations and
`cleanup-transient`; there is no second independently trusted cleanup workflow.
Every caller uses an immutable 40-character workflow SHA and the workflow checks
its own `job.workflow_ref`, `job.workflow_sha`, repository, workflow file path,
environment, caller SHA, run ID, attempt, event, and protected-main ref.

The accepted caller identities are fixed:

- production workflow ID `306965591`, exact name and
  `.github/workflows/main_master-data-structure-sea-9c4e0d0d.yml`;
- accepted-release persistence workflow ID `340547201`, exact name and
  `.github/workflows/persist-accepted-release.yml`;
- cleanup caller workflow ID `334414600`, exact name and
  `.github/workflows/production-oidc-canary.yml`.

Before Azure login, the control workflow re-fetches the caller run and binds its
workflow ID/name/path, repository and owner IDs, event, branch, head SHA, run,
attempt, and status. It also proves the OIDC `appid`, `azp`, `oid`, `sub`,
`job_workflow_ref`, and `job_workflow_sha` claims against the exact activated
contract. The GitHub runner does not receive Storage data-plane authority,
OneDeploy authority, production App Settings write/restart authority, a signing
credential, a SAS, an account key, or Shared Key authorization.

## Trust DAG and activation sequence

The finite trust sequence avoids an impossible self-referential third commit:

1. **S1-prime** is the reviewed, dormant, exact-SHA source that supersedes the
   earlier S1. Merge S1-prime with null activation values.
2. A separate external single-use authorization may provision only the exact
   reviewed V2 resources. The local provisioner creates the source-addressed,
   versioned bridge package, completes the bounded canaries and cleanup, and
   creates the sole temporary publisher FIC to S1-prime as its final Azure
   mutation. This is the sole pre-S2 Azure-mutation exception; the reusable
   workflow remains unable to operate.
3. Commit the concrete, SHA-independent provisioning evidence and bootstrap
   receipt in **S2**. S2 must not silently change the reviewed resource policy or
   source logic.
4. After S2 evidence acceptance, explicitly repin the sole publisher FIC from
   S1-prime to S2. Action-time Graph and
   OIDC checks must observe only the exact S2 expression; stale or extra
   credentials fail closed.
5. After the FIC repin and independent evidence review, the main repository pins
   S2 and adds the exact production, persistence, and cleanup callers. Apart
   from the one-shot bootstrap in step 2, no Azure mutation is authorized until
   S2 evidence is accepted, the FIC is repinned, the activated environment
   document is exact/non-null, and the caller is pinned. Mailbox/release,
   accepted-release, production activation/deployment, and reusable-workflow
   operations remain forbidden before those gates.

No S3 self-reference is required. Any resource drift after S2 requires new
evidence and a new reviewed pin rather than editing a mutable environment value
around the source checks.

## One-shot bootstrap commands and local-only recovery

`scripts/private_release_v2_bootstrap.py describe` is credential-free and is
the default mode. The source-owned observation command is separate and
read-only: `scripts/private_release_v2_bootstrap_observe.py` permits only GET
and the exact App Settings list POST, then create-only writes a canonical
preflight and a deliberately non-executable authorization template. It never
promotes the template, supplies a confirmation phrase, or mutates Azure.

The concrete observer overlaps independent reads with at most four workers.
Each worker has a separate REST session, token cache and Storage request-ID
set; Azure CLI credential calls are serialized. Source-derived operation URLs
are validated before their batch starts, response bindings and admission
dependencies are still checked in canonical order, and a failed worker stops
further reads in the batch while in-flight reads drain. Individual HTTP/CLI
limits and read-only retry rules are unchanged; credential-queue time counts
against the original observation age. Production App Settings still pass through
their dedicated in-memory redaction before evidence is emitted. The timestamp
remains the start of observation, so batching neither resets the five-minute
freshness window nor changes authorization validity. Variable provider latency
or a slow approval can still make a preparation expire. This pool is never
used by the mutation executor.

After independent review and a separate authorization ceremony, the operator
runs `private_release_v2_bootstrap.py apply --authorization <canonical-auth>
--preflight <canonical-preflight>` and supplies the exact confirmation phrase on
standard input. Neither a GitHub credential nor an Azure credential is embedded
in either file. The executor validates all local source, signature, exact-head
review, package, plan, authorization, freshness and account boundaries before
constructing its Azure CLI transport.

The one-shot authorization has a maximum lifetime of 4,171 seconds (69 minutes
31 seconds): 15 minutes for observation, confirmation and pre-controller setup,
followed by a 3,271-second controller admission, readiness and cleanup reserve.
The additional 271 seconds covers the second package assignment inside the one
reviewed deletion-lock suspension and the one-second final-observation scheduler
alignment allowance. A response envelope or alignment allowance never adds RBAC
waiting beyond the applicable full data-plane readiness interval.
The preflight must still be at most five minutes old when apply validates it.
The executor rejects an already-exhausted setup window before adding the
temporary uploader firewall rule, and checks it again before controller-role
creation. A slower firewall mutation can still cross that boundary and require
cleanup. These limits do not extend a consumed authorization; each new attempt
requires a fresh source-bound authorization. FIC repin keeps its separate
1,800-second limit.

The temporary operator controller-canary assignment uses the built-in Storage
Blob Data Contributor definition `ba92f5b4-2d11-453d-a403-e96b0029c9fe`, scoped
only to `paperdesk-release-controller-lock`. Observation retains its full
provider projection in both controller admissions. Apply checks that projection
again before granting access, creates only the authorization-specific assignment,
and uses the existing guarded assignment deletion and lock restoration for
cleanup. It then proves the assignment absent and the built-in definition
unchanged. The built-in definition is never created, deleted, or treated as
executor-owned, including after an ambiguous assignment response.

The package upload uses the existing role-matrix custom definitions
`b5d9d7c7-9367-4ac0-9d41-28b71e0d517d` for blob add and
`e005b62b-037b-4989-b492-932669ec0842` for blob read. Observation requires both
full definitions to match the source projection and both authorization-specific
container assignments to be absent. Apply creates only those two assignments,
then cleanup removes both under one reviewed package-container lock suspension
and proves both assignments absent while both definitions remain exact. The
definitions are persistent role-matrix resources and are never classified as
temporary, deleted during package cleanup, or treated as owned by the current
authorization.

Activation-fence bootstrap uses the persistent role-matrix custom definition
`906cb3b2-2061-5f5d-b168-515287d3165a` (`bridgeActivationFence`). Observation
accepts that definition only as absent or exact, and its state must agree with
the `createCustomRoleDefinitions` member state. That permanent operation creates
the definition when absent or adopts it when exact. The temporary fence lifecycle
creates and deletes only the authorization-specific container assignment; it
never creates, updates, or deletes the definition. Apply checks the complete
source projection immediately before assignment creation, after grant, and after
cleanup, when the stable definition must be present and exact.

The built-in role replaces only the temporary controller role. It includes container
management and blob add/move permissions beyond the former custom controller
definition; that complete permission set is source-pinned and must pass review.
Package upload remains custom add-and-read only, the activation fence remains
custom read/write without delete, and key read remains separately scoped. The
temporary-access binding derives exactly six authorization-specific role IDs:
two package assignments, the key-read definition and assignment, the fence
assignment, and the controller assignment. It also carries two fixed preserved
definition bindings, for the role-matrix fence definition and provider-owned
controller definition. The two package definition IDs remain separately fixed
role-matrix resources, so the package, fence, and controller definitions are all
preserved while only the key-read definition belongs to the temporary lifecycle.
Terminal receipts name the corresponding booleans
`roleDefinitionCreatedByTemporaryLifecycle` and
`roleDefinitionRemovedByTemporaryLifecycle`; both are true only for key read and
false for every preserved definition. An isolated same-account
canary passed upload, exact readback, finite leases and conditional deletion
with this built-in role. That diagnostic result does not establish the behavior
of the other roles or authorize a bootstrap, activation, or production deployment.

The package, activation-fence, and controller-canary blobs are all created with
`If-None-Match: *`. Their preceding GET or container LIST proves read access and
absence but cannot prove that the exact create action has propagated. Each create
may therefore retry only after a durably journaled HTTP 403 whose strictly parsed
Storage code is `AuthorizationFailure` or `AuthorizationPermissionMismatch`.
Every attempt retains the exact target, body, metadata, API version, and
conditional header while using a fresh client request ID. A concurrent create
returns 409/412 and stops. Transport ambiguity, a late response, result-journal
failure, 5xx, malformed or mismatched XML, and every other denial also stop; no
GET or LIST is inserted between create attempts. Terminal evidence preserves
each serial intent/result denial pair as a no-effect prefix and still requires
exactly one final HTTP 201 with the ETag and version ID proven by readback.

The executor retains one canonical, secret-free local-finalization snapshot
only after Azure execution, cleanup, postconditions and the complete terminal
bundle have validated. It create-only writes the five S2 bodies first and the
separate terminal bundle last. A process crash may be completed with
`private_release_v2_bootstrap.py resume-finalization --authorization
<canonical-auth> --preflight <original-canonical-preflight>`. This recovery mode
requires that same original authorized preflight, has no transport parameter,
reconstructs the deterministic package bytes,
revalidates all five retained bodies and the full terminal bundle, performs zero Azure requests or mutations,
accepts only byte-identical existing prefixes, and
fails on any conflict. A pre-crash `execution-terminal.json` failure summary is
retained; it is not rewritten as success. The validated terminal bundle at the
reviewed terminal-bundle path is the local-finalization success authority.
The authorized receipt parent is an operator-controlled, access-restricted real
local directory, never a symlink, junction, shared workspace, or path writable
by another same-privilege process. Same-privilege parent replacement is outside
the evidence threat model. A partial file retained after an ambiguous write or
fsync failure is not removed or overwritten: retry fails on the conflict and
requires manual reconciliation while the authorization remains consumed.

## Controller serialization and private bridge handoff

Before any bridge App Settings or start operation, the controller acquires a
finite 60-second Azure Storage resource-provider lease on the dedicated empty,
private lock container. The publisher's lock role is scoped to that exact
container and contains only the required container read plus
`Microsoft.Storage/storageAccounts/blobServices/containers/lease/action`; it has
no blob DataActions and no container write/delete action. Every privileged phase
renews the lease. Lease loss fences the next read or mutation.

The cleanup entry retries with fresh random lease capabilities for eight
attempts at ten-second intervals. Its 70-second retry window exceeds one lease
term, so a completed `workflow_run` fast lane does not silently succeed merely
because an abandoned 60-second lease is still busy.

Only while the V2 bridge is proven Stopped does the controller write the exact
transient map: activation document, source-pinned provisioning evidence,
bootstrap receipt, workflow SHA, nonce-bound control record, and one short-lived
GitHub token. The control record stores the token digest and exact owner
provenance. The token itself exists only in the private stopped bridge's App
Settings; it is never printed, placed in a command argument, copied to a durable
receipt, or accepted by a different mailbox request. Full-map reread classifies
the bridge settings as exact original, exact owned transient state, or third
state. A third state is never overwritten.

ARM deployments form the mailbox. ARM deployment CreateOrUpdate lacks a
conditional-create operation, so logical creation requires a fresh 128-bit
nonce, HTTP 201, exact canonical readback, exact resource identity, Succeeded
state, and unchanged authenticated `systemData` creator/modifier and timestamps.
HTTP 200 is an update and fails. Existing stale mailboxes cannot borrow a later
token because request name, source, operation, owner run, token digest, and
expiry are cross-bound.

## Immutable bridge and release packages

The V2 bridge is a new private App Service created from the beginning with:

- `WEBSITE_RUN_FROM_PACKAGE` set to the exact private, content-addressed,
  **versioned** blob URL;
- `WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID` set to the exact package-reader
  user-assigned identity resource ID;
- package SHA-256, size, ETag, version ID, WORM policy, network posture, and
  critical full App Settings map committed in source-pinned evidence.

The package blob is addressed under
`v2/control/<merged-S1-prime-source-SHA>/paperdesk-private-release-bridge.zip`.
The activated contract binds that S1-prime package-source SHA separately from
the later S2 control-workflow SHA, so the evidence-only S2 commit neither copies
nor silently re-uploads the package. The package URL is not a secret. The GitHub runner validates the URL as bound
metadata in the exact S2 evidence, but it receives no SAS, Storage bearer token,
account key, or package-write permission. The package, accepted registry, and
result containers must each be private and Locked for at least 91 days.

Candidate and rollback package bytes are written create-only, read back through
the separate reader identity and exact version ID, and promoted into the
accepted namespace before its manifest. The accepted manifest is written last
and is the sole completeness marker. Production activation uses the system
identity with exact package-container read access and sets
`WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID=SystemAssigned`; it never uses a
SAS or a GitHub runner credential.

## Release-state read-only accepted-baseline registry preflight

The public production caller first observes the live release SHA and invokes
the release-state read-only `registry-bridge-preflight` operation through the
existing trusted production workflow.
This reuses the exact production caller ID, path, ref, event and run coordinates:
there is no fourth trusted caller and PaperDesk is not granted direct Azure or
Storage authority. The private bridge performs two deterministic exact reads,
never a list: `v2/accepted/<live-sha>/manifest.json` and the immutable initial
fallback `v2/accepted/<live-sha>/bootstrap-consumed/manifest.json`. The fallback
is valid only when the manifest source is the fixed bootstrap SHA. Both paths
present is ambiguity; neither present, any descriptor-chain mismatch, a third
state, or a live-production mismatch fails closed. Its bounded transport
transiently acquires the controller lease, creates the mailbox request/result,
installs temporary bridge App Settings, starts and stops the exact WebJob, and
cleans up its transient control state. It does not write the registry/package
stores, acquire the activation fence, or change production.

Normal strict persistence commits the canonical source-keyed accepted manifest
last. The public control receipt retains exact five-field `acceptedBaseline`,
`pendingRelease`, and `consumedMarker` descriptors (with exact nulls where the
operation does not produce one) under schema version 6. Those retained
descriptors recover runner-loss and cross-workflow handoff without depending on
the 90-day artifact window. Rollback dispatch is routed through the same existing
trusted production workflow, not a new caller.

The release pipeline carries four independent run identities. The source pair
selects the verified main-push artifact and provenance; the candidate pair
selects the successful deploy-candidate run and its exact deployment-coordinate
receipt; the acceptance pair selects the fully accepted receipt; and the
evidence pair selects post-deploy evidence. No pair may be reused. The durable
v2 accepted manifest stores separate `source` and `deployment` objects and the
source-keyed legacy registry address remains
`v1/releases/<sha>/<source-run-id>/<acceptance-run-id>/`. Private mailbox request
schema version 2 adds `candidateRunId` and `candidateRunAttempt`, requires them
only for `persist-accepted-release`, and requires exact nulls for every other
operation. The public-control receipt schema version 6 mirrors that distinction.

## Production activation fence and proof

App Service App Settings does not expose a supported conditional service ETag.
The production-activation UAMI therefore holds a separate finite blob lease on
the activation-fence blob. A held record binds operation, source SHA, exact
pending/accepted release descriptor, pre-settings digest, desired-settings
digest, lease ID, and monotonically increasing state version.

Every configuration read, full-map PUT, restart, and health probe is fenced.
Observed state is classified as old, desired, or third-state:

- old may advance to the exact desired map;
- desired may recover the same terminal consume/complete operation after lost
  result delivery;
- third-state fails closed and is never deliberately overwritten.

After an expired lease, only the exact same plan may rebind using a fresh random
lease ID and incremented state version. A different release, plan, descriptor,
or stale receipt fails. Rollback restores only the exact old map and never
clobbers an unknown third state.

The one-shot bootstrap runs before that production activation fence exists. Its
authorization binds the complete empty bridge-settings prestate and canonical
digest. The executor constructs the exact desired request, performs one final
full-map read/digest check, journals the durable intent, issues the configuration
PUT at most once, and requires an exact desired-map readback for definite
success. In-process rollback writes at most once and only from the exact
executor-owned desired map; definite success requires the exact old-map
readback. Old needs no write and every observed third state stops for manual recovery.
The confirmation phrase explicitly accepts that neither read/PUT window can
atomically exclude an out-of-band subscription or resource-group Owner.

Canonical repository JSON files end in one LF. A JSON document embedded in an
App Setting omits exactly that file delimiter because App Service normalizes a
terminal LF away. Bootstrap configuration, compensation, source projections,
and the bridge package all hash and compare the exact no-LF App Setting string.
The incident-specific recovery executor accepts only the proven PR55 normalized
five-setting digest and can restore only the source-bound empty map after a
separate exact authorization and final live read. It binds that authorization
to one ProgramData ledger path derived from the authorization ID, validates the
exact incident operator account, and rejects all Azure requests outside the
reviewed reads and the sole empty-map PUT. The confirmation phrase commits the
exact observation time, expiry, review digest, ledger path, and a separate
ProgramData confirmation-artifact path that `observe` proves absent and never
creates. Its emitted text request is structurally non-executable; `apply`
accepts only the later canonical user-confirmation JSON artifact at that bound
path. The ledger parent and each create-only ledger entry are durably flushed
before the mutation. Immediately before intent, the executor reads the stopped
site and then the exact incident settings map. The reviewed phrase explicitly
accepts the remaining cross-resource race in which an unrelated administrator
starts the site after that read; the executor never starts it, and final success
requires another stopped-site proof.

If the failed PR55 bootstrap's exact durable intent/result receipts remain
present with their source-pinned hashes, a later read-only observer may bind the
recorded idle activation fence as an `adopt-exact` candidate even though the
private data plane is inaccessible before the temporary fence role. Execution
still reads the live blob after that role is granted and requires the same
canonical body hash, metadata, ETag, and version ID. Missing receipt evidence
keeps the normal conditional-create path; partial or changed evidence, or any
live blob drift, fails closed without replacing the blob.

When a failed bootstrap has already created its exact source-keyed ZIP, retain
that object as incident evidence and continue from a new reviewed merge. The
new source SHA produces a distinct package key and follows the ordinary
conditional-create plus exact readback path. The new release must neither
overwrite nor reuse the package keyed to the earlier source.

Health proof binds the runtime marker, served index SHA-256, live, ready,
app-health and security responses, plus the historical full OneDeploy collection
invariant: historical deployment ID, canonical full-collection semantic digest,
property-ID-set digest, and deployment count. OneDeploy is historical evidence;
run-from-package and the exact versioned package are the activation mechanism.

## Key and authorization proof

Package-upload readiness alone permits an exact-target GET at up to 30 minutes,
plus its 90-second request envelope, to accommodate the upper propagation
allowance documented by [Azure Storage](https://learn.microsoft.com/en-us/azure/storage/blobs/authorize-access-azure-active-directory).
Its exponential backoff caps at 32 seconds and 64 GET attempts. The exact
4,171-second (69-minute 31-second) authorization and protected cleanup deadline
can shorten that window;
the wait never borrows cleanup time. Only exact `BlobNotFound` admits one
create-only PUT. Other readiness windows remain unchanged. A longer wait does
not establish propagation as the cause of a denial or guarantee convergence.

Activation-fence readiness separately preserves its complete 600-second RBAC
interval. A final exact GET may start at the 600-second boundary, with one
90-second response envelope and up to one second of scheduler-alignment slack.
The outer work and authorization deadlines, including two reserved follow-on
request envelopes for conditional creation and exact readback, may shorten this
window; neither envelope nor slack extends the RBAC waiting interval. Only the
two recognized Storage authorization-propagation 403 codes may retry, and only
exact `404 / BlobNotFound` admits the conditional create phase.

Bootstrap public-key readiness reads the exact version URI from the validated
`createSigningKeyVersion` projection while the dedicated temporary key-read role
is active. The separate version-list readback remains an inventory check; its
URL is not the target for `Get Key`. A missing proof, different version, key,
vault, or role fails before HTTP. Readiness deadlines and cleanup reserves are
unchanged.

Before any mailbox, Storage, production, or signing action, the bridge performs
an exact versioned Key Vault `Get Key` with a dedicated read-only identity. The
projection digest, `kid`, RSA modulus/exponent, key operations, enabled and
non-exportable attributes, exact version, and minimum remaining lifetime must
match S2 evidence and the sealed JWK. The signer identity remains separate and
has only `Microsoft.KeyVault/vaults/keys/sign/action` on that key version.

Azure's [`nbf` key attribute](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details#key-attributes)
is optional. An omitted or null value is retained as explicit `nbf: null` in the
canonical public-key projection; no timestamp is invented. A supplied value must
be an integer no later than the key's creation time. Bootstrap, activation
evidence, and the bridge reader enforce the same rule. Exact key/version,
projection digests, enabled/non-exportable status, required expiry and recovery
attributes, and the separate version-inventory comparison still apply.

If a later readback cannot fit its request envelope or exhausts its existing
transport retries, the failure includes the probe and preceding validation error
when available. This diagnostic handling does not extend the convergence window,
authorization, cleanup reserve, or request/retry limits, and retains no raw
response body.

Authorization evidence is produced by exhaustive, paginated subscription-scope
role-assignment inventories for each automation principal. Direct
`principalId eq` and effective `assignedTo(...)` projections must both equal the
source-pinned allowlist; every referenced role definition is fetched and
canonical-hashed. Inherited, conditional, delegated, group-effective,
overlapping, or extra non-Owner assignments fail. Subscription/resource-group
Owners remain an explicit out-of-band governance boundary.

The evidence field is named `publisherAuthorizationDecisions`. These are derived
authorization decisions from complete live inventories, not claimed observed
403 canaries. The verifier performs no risky negative write, delete, restart,
OneDeploy, listKeys, blob-write, or Key Vault sign solely to manufacture denial
evidence.

## Durable terminal results and cleanup

Before signing a terminal result, the bridge writes and reads back an immutable
cleanup obligation under `v2/cleanup-obligations/<source-sha>/...`. It binds the
terminal descriptors, exact transient control, owner workflow/run/attempt/SHA,
expiry, activation plan/proof, and cleanup caller. A terminal production result
does not make the workflow successful while housekeeping is pending: the CLI and
workflow require every housekeeping record to be `complete` with no failures.
The signed terminal result and cleanup obligation remain durable recovery input
for a rerun.

Normal cleanup runs through `cleanup-transient` on the same exact-SHA reusable
workflow. The main caller owns the shared `paperdesk-production` concurrency,
with `cancel-in-progress: false`, and invokes cleanup on exact completed
production/persistence `workflow_run` events. Schedule/manual fallback uses the
same path. Completed owner proof allows immediate cleanup. If the Actions API is
unavailable, fallback cleanup waits until the immutable owner record is at least
120 minutes old (beyond the enforced 90-minute job timeout), the bridge
self-deadline has elapsed, and every owner/transient field rereads exact. An
active owner, partial map, changed nonce, changed run attempt/SHA, or third state
always denies mutation.

Cleanup reacquires the RP lease, re-verifies provisioning, stops only the exact
owned bridge, removes only the exact owned transient keys, proves the original
full map by digest/readback, and releases its own fresh lease capability. If
post-operation provisioning verification fails, the bounded emergency exception
may only stop the exact bridge started by that controller while the lease remains
held; it may not inject new state, change production, or overwrite a third state.

## Operator activation checklist

Activation is blocked until all of the following are independently proven:

- S1 source review, exact resource provisioning, S2 evidence review, sole FIC
  repin to S2, and exact main caller pin;
- V2 bridge package upload by temporary bounded local authority, exact readback,
  removal of the owned temporary `/32` firewall rule and both exact custom-role
  assignments, proof both assignments are absent, and proof both stable package
  role definitions remain exact before bridge start;
- service-endpoint topology, private containers, default-deny Storage firewall,
  exact integration subnet, bridge `allTraffic=true` plus
  `applicationTraffic=true`, and the production routing projection observed as
  `applicationTraffic=true`, `allTraffic=false`, and legacy
  `vnetRouteAllEnabled=true` without a pre-S2 production mutation;
- exact live RBAC inventories and role definitions for publisher, bridge,
  writer, reader, signer, production activation, production system identity,
  and every audit-only assignment;
- at-least-91-day Locked policies for package, accepted, and result containers;
- exact versioned Key Vault key/JWK proof, bridge read-only key role, signer-only
  sign role, and no unexpected sensitive assignment;
- immutable bootstrap receipt and separate full canonical terminal bundle; one
  fresh source-and-package-pinned WebJob invocation after an exact pre-run
  history boundary reaching terminal `Success` under the exact canary control
  and settings; managed-identity package-fetch and activation-fence cleanup;
  finite-lease tests, cleanup fast lane plus expiry fallback, and durable
  retained receipts. Bootstrap does not claim HTTP index/live/ready/app-health/
  security or literal stdout-marker observation; those remain later
  activation/deployment proofs.

Until those gates pass, the null activation contract remains the controlling
state. The only mutating mode allowed before S2 is the exact separately
authorized one-shot bootstrap; every reusable-workflow, mailbox/release,
accepted-release, production activation/deployment, and caller-integration mode
must stop before Azure login.

## S2 repin and activation ceremony

The reviewed S2 source must differ from S1-prime only by the five evidence
components and terminal receipt bundle named by the evidence model. It must have
the exact two trusted exact-head approvals, successful `test` check, verified
signature and protected-main merge. The source-owned
`private_release_v2_fic_repin.py observe` command revalidates those facts, the
historical bootstrap authorization/preflight and all six canonical S2 files
before making only Graph and ARM reads. It writes a fresh preflight and
deliberately non-executable authorization template.

Under a new finite external single-use authorization,
`private_release_v2_fic_repin.py apply` first creates a permanent
authorization-specific empty ARM deployment claim. It then deletes only the
exact S1-prime federated identity credential, proves the credential collection
is empty, and creates the exact sole S2 credential. Extra credentials, altered
claims, a third state, authorization replay or S1/S2 equality fail closed. A
same-host retry may resume only from the proven empty or exact-S2 state; it never
creates overlapping credentials. The create-only `06-terminal-receipt.json`
must pass `private_release_v2_fic_repin.py validate-receipt`.

`private_release_v2_activation.py` is then an offline-only, create-only builder.
It validates the bootstrap history, the six S2 files and repin receipt, derives
`mergedControlWorkflowSha=S2` with `bridgePackageSourceSha=S1-prime`, and invokes
the normal strict production activation loader. It cannot publish environment
variables, update a GitHub secret, grant caller authority, call Azure or deploy.
Those caller-integration mutations require a separate exact ledger and explicit
authorization after the activation output has been independently reviewed.
