# PaperDesk release verifier

This public repository is an independent workflow and control root for PaperDesk
release verification. It contains no PaperDesk application source, production
artifact, customer record, persistent cloud credential, or production secret.

## Current status

| Surface | Status | Consequence |
| --- | --- | --- |
| Candidate verifier | Independently pinned, read-only | May verify a hostile producer artifact without cloud identity |
| Private release mailbox V2 | Source-dormant | Every activation field is null; every mutating operation stops before Azure login |
| Watchdog V2 | Source-dormant | Baseline, reconciliation, and deadline workflows stop before OIDC/provider calls |

Merging dormant source is not deployment authorization. The sole pre-S2 Azure-mutation exception
is the separately reviewed, one-shot local bootstrap
provisioning described below, executed from the exact merged **S1-prime** source
under an external single-use authorization. It does not authorize a reusable
workflow, mailbox or release operation, production activation or deployment,
accepted-release operation, or caller integration. Those remain blocked until
the exact S2 evidence is accepted, the sole FIC is explicitly repinned to S2,
the activated environment document is exact, and every main caller uses the
exact reviewed S2 SHA.

## Candidate verifier

The reusable verifier:

- runs with read-only caller permissions and no cloud identity;
- checks out the caller's exact release commit without persisted credentials;
- reconstructs the expected package before downloading the producer artifact;
- treats the downloaded artifact as hostile input;
- runs an independently versioned standard-library verifier over archives,
  manifests, release materials, SBOMs, and provenance;
- publishes only a verified artifact and digest-bound receipt into the caller's
  workflow run.

Actions and reusable workflows must always use full immutable commit SHAs. Never
call a production control from a branch or tag.

## Private release mailbox V2

The authoritative operator and security contract is
[`docs/private-release-mailbox-v2.md`](docs/private-release-mailbox-v2.md). The
single reusable entry is `.github/workflows/azure-production-control.yml`,
including `cleanup-transient`; no standalone cleanup workflow is trusted.

### Exact callers and OIDC

The workflow accepts only these source identities:

- production workflow ID `306965591` at
  `.github/workflows/main_master-data-structure-sea-9c4e0d0d.yml`;
- persistence workflow ID `340547201` at
  `.github/workflows/persist-accepted-release.yml`;
- cleanup workflow ID `334414600` at
  `.github/workflows/production-oidc-canary.yml`.

Name, path, repository/owner IDs, protected-main ref, event, head SHA, run ID,
attempt, source SHA, `job.workflow_ref`, and `job.workflow_sha` are all exact.
The Azure token must also bind exact `appid`, `azp`, `oid`, `sub`,
`job_workflow_ref`, and `job_workflow_sha` claims. The workflow refetches caller
run metadata before Azure login rather than trusting only event text.

### Runner boundary

The GitHub-hosted runner may use the publisher control identity only to validate
fixed control-plane evidence, publish/read the nonce-bound ARM mailbox, serialize
the private bridge, and recover its exact owned transient state. It has no
Storage blob DataActions, OneDeploy authority, production App Settings
write/restart authority, Key Vault sign authority, SAS, account key, or Shared
Key credential. It never directly runs `az storage`, OneDeploy, or a production
App Settings mutation.

The short-lived GitHub token is injected only into a proven-Stopped private V2
bridge, together with its digest-bound control record. The token is removed
during exact full-map cleanup and is never placed in process arguments or durable
receipts.

### Versioned run-from-package chain

The V2 bridge is a separately provisioned private App Service anchored from
creation to a private, content-addressed, versioned WORM package URL and exact
package-reader UAMI. Candidate and rollback deployment packages are create-only,
read back by exact version, and activated using App Service run-from-package.
Production uses its system identity with exact package-container read access.

The package URL is not a secret; it is source-pinned metadata. The runner may
validate it, but receives no SAS, Storage bearer token, account key, or package
write permission. Package, accepted-release, and result containers must be
private and Locked for at least 91 days. Accepted package promotion is complete
only after exact byte readback and a manifest-last commit.

### Release-state read-only accepted-baseline registry preflight

Before a later PaperDesk workflow prepares a candidate or rollback, it reads the
public live-release SHA and invokes the release-state read-only
`registry-bridge-preflight`
operation through the existing trusted production workflow. No fourth trusted
caller is added, and PaperDesk receives no direct Azure or Storage authority.
The private bridge probes exactly
`v2/accepted/<live-sha>/manifest.json` and, only for the immutable bootstrap
source, `v2/accepted/<live-sha>/bootstrap-consumed/manifest.json`; it never lists
the container or follows a mutable current pointer. Both present, neither
present, a source mismatch, an invalid descriptor chain, or a live-production
mismatch fails closed. Its bounded transport transiently acquires the controller
lease, creates the mailbox request/result, installs temporary bridge App
Settings, starts and stops the exact WebJob, and cleans up its transient control
state. Release-state read-only means that it does not mutate the registry,
package store, activation fence, or production configuration.

The retained public control receipt is schema version 6 and carries the exact
five-field `acceptedBaseline`, `pendingRelease`, and `consumedMarker`
descriptors (or operation-appropriate nulls). This makes runner loss and
cross-workflow handoff recoverable without relying on an expiring artifact.
Rollback dispatch is likewise routed through the existing trusted production
workflow; it does not introduce a fourth caller.

Accepted-release persistence never aliases run identities. `sourceRunId` and
`sourceRunAttempt` identify only the verified main-push artifact and provenance;
`candidateRunId` and `candidateRunAttempt` identify the successful production
deployment; acceptance and evidence retain their own run coordinates. The
source-keyed registry prefix remains
`v1/releases/<sha>/<source-run-id>/<acceptance-run-id>/`, while the strict v2
manifest carries separate `source` and `deployment` objects and durably retains
the deployment-coordinate receipt. The private mailbox request is schema
version 2 and exposes candidate coordinates only for accepted-release
persistence; all other operations require exact nulls.

The historical full OneDeploy collection invariant is evidence only. It binds
the historical deployment ID, canonical full-collection semantic digest,
property-ID-set digest, and deployment count. OneDeploy is not the V2 activation
mechanism.

### Production activation and recovery

A finite activation-fence blob lease binds the exact operation, source, release
descriptor, pre-settings digest, desired-settings digest, lease ID, and state
version. Every full-map read/write, restart, and probe renews that fence. State is
classified as old, desired, or third-state; third-state is never overwritten.
After lease expiry, only the exact same plan may rebind under a fresh random
lease and incremented state version. Desired-state recovery repeats only the
durable consume/complete action rather than restoring production because result
delivery was lost.

Before mailbox, Storage, production, or signing work, the bridge performs a live
versioned Key Vault `Get Key` and proves the exact JWK, attributes, version,
digest, and remaining lifetime. The bridge key identity is read-only; a distinct
signer UAMI has only sign permission.

### Cleanup and runner loss

The controller uses a finite 60-second Storage resource-provider container lease
with no blob DataActions. Cleanup retries eight times at ten-second intervals,
so its 70-second busy window exceeds a whole abandoned lease term.

Every terminal result includes a create-only/readback cleanup obligation. A
workflow is not successful while any housekeeping record is pending. Exact
completed-owner proof permits immediate cleanup. If the Actions API is
unavailable, fallback waits at least 120 minutes, beyond the 90-minute owner job
timeout, and still requires exact owner, nonce, run attempt/SHA, transient map,
self-deadline, and lease proof. Active owner, partial map, or third-state means no
mutation.

The main repository must route production, persistence, and cleanup callers
through one literal `paperdesk-production` concurrency group with
`cancel-in-progress: false`. The completed `workflow_run` path and schedule/manual
expiry fallback call the same exact-SHA reusable workflow.

### Authorization evidence

Action-time authorization proof uses the subscription-scope ARM 2022-04-01 List For Scope endpoint with the exact `principalId eq '<principalId>'` filter and the effective `assignedTo(...)` filter. The proof covers direct role assignments at, above, and below the fixed approved subscription only; it cannot inventory unrelated sibling subscriptions, Entra group or transitive grants, or PIM eligibility or activation. Where broader proof is required, use a separate Entra/PIM audit identity and P2/Identity Governance coverage; activation remains blocked until that proof is reviewed. The action-time checks exhaustively inventory both projections for every
automation principal, follows pagination, and canonical-hashes every referenced
role definition. Both inventories must equal the source-pinned allowlist.
Unexpected inherited, conditional, delegated, group-effective, overlapping, or
extra non-Owner access fails closed.

`publisherAuthorizationDecisions` are derived authorization decisions from that
complete inventory. They are not claimed 403 probes, and the system performs no
risky negative write, delete, restart, OneDeploy, listKeys, blob write, or Key
Vault sign merely to manufacture denial evidence. Subscription/resource-group
Owners remain an explicit out-of-band governance boundary.

## Activation trust DAG

The activation sequence is finite:

1. Supersede the earlier S1 with reviewed dormant exact-SHA source **S1-prime**,
   still with null activation.
2. Under a separate external single-use authorization, run only the exact local
   bootstrap plan and bind the sole temporary publisher FIC to S1-prime as its
   final mutation. This bounded provisioning action is the sole pre-S2
   Azure-mutation exception.
3. Commit only the independently reviewable evidence and bootstrap receipts in
   **S2**; its tree must not silently change S1-prime control logic.
4. After S2 evidence acceptance, explicitly repin the sole FIC from S1-prime to
   S2 and prove every stale or extra relevant FIC is absent.
5. Only after independent review, main pins S2 and receives its exact caller
   integration.

Apart from the exact one-shot bootstrap in step 2, no Azure mutation is
authorized before S2 evidence acceptance and FIC repin. In particular, the
bootstrap cannot run the reusable workflow, mailbox/release logic, production
activation/deployment, accepted-release operations, or caller integration. Main
pins S2 only after those gates. No impossible S3 self-reference is needed. Any
later drift requires fresh evidence and a new reviewed pin.

## Bootstrap boundary

`scripts/private_release_v2_bootstrap.py` is a separate, explicitly authorized
operator action, not a GitHub runner shortcut. Its default `describe` mode is
local and read-only and stops before credential construction. The source-owned
read-only `observe` path creates a canonical preflight and a deliberately
non-executable authorization template; only the separate `apply` path
requires a canonical external single-use authorization and canonical read-only
preflight bound to the exact reviewed S1-prime head and fresh post-push reviews,
the exact verified merged-main tree, executor and plan digests, deterministic
bridge package, Azure account/subscription/tenant, finite validity, confirmation
phrase digest, resources, mutations, and postconditions. It also consumes an
authorization-specific local directory before Azure and creates a deterministic
subscription-deployment claim as the first cloud mutation; only HTTP 201 is
accepted, HTTP 200 is a replay/update failure, and the claim is never deleted.

The exact plan may temporarily add only:

- the current host's exact public IPv4 `/32` Storage firewall rule; and
- an authorization-specific custom role on the exact package container with
  only create-new blob and exact readback DataActions;
- an exact metadata-only Key Vault read role needed to capture the public JWK;
  and
- an exact fence-bootstrap role limited to creating/reading the canonical idle
  activation-fence blob.

Package upload first performs bounded, read-only GET readiness checks against
the exact source-keyed blob. Only a matching `404 / BlobNotFound` admits the
single create-only PUT; recognized authorization-propagation 403s may wait for
up to ten minutes within the authorization window. Existing blobs, malformed
errors, authentication failures, and expiry fail closed. GET readiness proves
read/network access, not write permission: a failed or ambiguous PUT is never
replayed.

Failed package GET readiness retains a fixed stage and stop reason, elapsed
time, attempt count, last HTTP status, and an allowlisted Storage error code in
stderr and the local failed terminal receipt. An optional Storage request ID
must have the fixed hexadecimal UUID shape; an optional server date must be a
canonical GMT HTTP date. Missing, malformed, or hostile header values become
null. Raw response bodies/messages, URLs, IP addresses, credentials and transport
exception text are never retained. These facts diagnose a failed attempt; they
do not turn a denied or ambiguous request into permission to upload or retry.

The controller-container empty proof uses the same ten-minute Storage readiness
budget, bounded by the authorization expiry and 64 GET attempts, with backoff
capped at 15 seconds. Only the two recognized authorization-propagation 403s
may wait; malformed errors, authentication failures, transport ambiguity, a
different target, or a nonempty/paginated inventory stop immediately. Success
still requires the exact source-bound empty-container and private-posture proof.
Failure diagnostics retain a fixed stage, elapsed time, attempt count,
HTTP status, allowlisted Storage error code and stop reason in stderr and the
local failed terminal receipt. Controller errors distinguish the ten-minute
readiness limit from expiry of the outer authorization. Both Storage readiness
paths retain only shape-validated provider request IDs and canonical server
dates; response messages, raw bodies, IP addresses and tokens are never copied.

Both paths can additionally retain metadata from the credential used for the
last observed response: process-cache reuse versus an Azure CLI request,
bounded token issuance/expiry/observation Unix timestamps, and a successful
account-binding flag. A CLI request does not imply newly issued credentials;
the CLI can return its own cached token. Missing or invalid issuance metadata
stays unknown and does not change token acceptance. A later transport failure
does not pair earlier response headers with a newer credential snapshot.
Role-readback diagnostics contain only SHA-256 digests of the exact definition
and assignment already validated through ARM, not a planned-role declaration
or proof that the data plane has propagated that role. Missing observed
evidence stays null. This instrumentation makes no extra credential or Azure
requests, does not force token refresh, and never broadens permissions,
changes wait/retry limits, or authorizes another execution. Historical failed
receipts remain immutable; these facts are available only on a later freshly
authorized attempt.

The plan also binds exactly three existing `CanNotDelete` locks and the eight
role-assignment removals they protect. A fresh complete subscription lock
inventory must prove all three reviewed projections and reject any additional lock
affecting a planned deletion before the Azure claim. Each protected deletion
then rechecks that inventory and the authorized assignment, suspends only its
reviewed lock, deletes only its exact assignment, and restores the original
lock in `finally` before deleting a temporary role definition. The journal
binds exact targets, lock bodies, and this order. Only readbacks may retry;
assignment and definition absence have bounded convergence windows.
Temporary-role cleanup 404s retain the specific assignment/definition absence
proofs and exact lock-restoration evidence before generic absence handling; a
bare 404 cannot stand in for complete cleanup evidence.

The production App Service lock `paperdesk-protect-app-delete` is bound only
to retirement of legacy sites-read assignment
`784fb5eb-c6ac-41ca-902a-cdae92334ade`. Its suspension does not authorize deleting
or configuring the production site, touching the separately preserved
`b24a4ca5-de40-47c8-90d8-caf08759dfb2` assignment, or suspending the unrelated
production Storage/PostgreSQL locks. The exact app lock must be restored before
that assignment-retirement operation can succeed.

New lock suspension requires an unexpired authorization, including during
compensation. Only restoration of the exact suspended lock may proceed after
expiry. A changed lock is never overwritten. Fresh bootstrap authorization
must explicitly accept the lock-concurrency and interruption residuals in
addition to the existing Storage firewall residuals. If a process dies or a
request/journal result is ambiguous, deletion protection can remain absent;
execution stays NO-GO pending fresh proof and, where necessary, separately
authorized manual cleanup. Consumed authorizations and historical failure
receipts are never reused or rewritten.

It uses Azure AD create-only upload or adopts only an already-present exact
immutable source-keyed version. Evidence says which path occurred: only a
current-authorization create records `If-None-Match:*` and HTTP 201; adoption
records no current write. Both paths verify exact SHA-256/size/ETag/version ID,
then remove only the executor-owned `/32` rule and exact temporary assignment. Fresh
readback must prove both are absent before the V2 site starts. It may not use a
SAS, account key, Shared Key, broad CIDR, stale full-ACL restore, or public
container. A fresh exact source-and-package-pinned WebJob invocation must start
after the recorded pre-run history boundary and reach terminal `Success` under
the exact canary control and settings. Its ARM invocation ID/start/end/status
and output-URL metadata, package/version/control digests, managed-identity
package-fetch boundary, and activation-fence lease cleanup are retained. The
bootstrap does not claim HTTP index/live/ready/app-health/security responses or
literal stdout-marker bytes; those are later activation/deployment proofs. A
finite-lease canary and exact temporary-access cleanup must succeed through the
reviewed service-endpoint topology. The package container is locked before the
canary; one-way accepted/result retention extensions from 30 to 91 days occur
only after every reversible proof has passed and only when the authorization
explicitly names those mutations. The current production routing projection is
observed but not changed during bootstrap.

The canary's maximum 15-minute lifetime starts just in time after the final
settings precondition read, rather than at preflight preparation. Its expiry
is still clipped to the unchanged outer bootstrap authorization. Retained
issuance/expiry timestamps reconstruct the exact control and settings digests
and bind to the single settings-PUT journal entry. The control is never refreshed
or replayed; an expired retained control blocks bridge startup and WebJob
triggering. Lease acquisition and renewal also honor that same deadline, while
exact finally-release cleanup remains permitted after expiry.

The production command sequence is explicit. `describe` is the default local,
credential-free view. `observe` is a separate Azure read-only program: it accepts
only GET and the exact App Settings list POST, writes a canonical preflight and a
deliberately non-executable authorization template create-only, and cannot
promote that template into an authorization. After an independent ceremony
creates the separate canonical authorization, `apply` consumes both exact files:

```bash
python -B scripts/private_release_v2_bootstrap.py describe
python -B scripts/private_release_v2_bootstrap_observe.py \
  --source-evidence /external/reviewed-s1-prime-source.json \
  --authorization-id 00000000-0000-4000-8000-000000000000 \
  --receipt-directory /external/paperdesk-private-release-v2-bootstrap-00000000-0000-4000-8000-000000000000 \
  --uploader-ipv4 203.0.113.10/32 \
  --preflight-output /external/bootstrap-preflight.json \
  --authorization-template-output /external/bootstrap-authorization-template.json
python -B scripts/private_release_v2_bootstrap.py apply \
  --authorization /external/bootstrap-authorization.json \
  --preflight /external/bootstrap-preflight.json
```

If Azure execution and full terminal validation completed but the process died
while creating the five S2 files, local finalization may resume without a token,
transport, or credential construction and performs zero Azure requests or mutations. It requires the
same canonical authorization and original authorized preflight, revalidates all
five retained bodies and the full terminal bundle, accepts only byte-identical
existing prefixes, and writes the terminal bundle last:

```bash
python -B scripts/private_release_v2_bootstrap.py resume-finalization \
  --authorization /external/bootstrap-authorization.json \
  --preflight /external/bootstrap-preflight.json
```

The earlier `execution-terminal.json` failure summary is never overwritten after
a crash. A successful local-only resume is instead proven by the fully validated
canonical terminal bundle at the exact reviewed terminal-bundle path.
The authorized receipt parent must be an operator-controlled, access-restricted
real local directory, not a symlink, junction, shared workspace, or path writable
by another same-privilege process. A partial file after an ambiguous write/fsync
failure is retained and conflicts on retry; it requires manual reconciliation
and never reopens the consumed authorization.

## S2 FIC repin and offline activation

After the evidence-only S2 commit has the exact two trusted reviews, the `test`
check, a protected-main merge and the required six-path-only diff from
S1-prime, describe and observe the separate FIC repin ceremony:

```bash
python -B scripts/private_release_v2_fic_repin.py describe
python -B scripts/private_release_v2_fic_repin.py observe \
  --authorization-id 00000000-0000-4000-8000-000000000000 \
  --source-evidence /external/reviewed-s2-source.json \
  --bootstrap-authorization /external/bootstrap-authorization.json \
  --bootstrap-preflight /external/bootstrap-preflight.json \
  --preflight-output /external/s2-fic-repin-preflight.json \
  --authorization-template-output /external/s2-fic-repin-authorization-template.json \
  --receipt-directory /external/paperdesk-private-release-v2-s2-fic-repin-00000000-0000-4000-8000-000000000000
```

`observe` is read-only. It requires the exact sole S1-prime FIC and an absent
authorization-specific ARM claim, and the emitted template is deliberately
non-executable. A separate ceremony must create the finite canonical
authorization and confirmation phrase. The authorized mutation universe is
only the permanent single-use ARM claim, deletion of the exact S1-prime FIC,
and creation of the exact sole S2 FIC. The executor proves an empty intermediate
inventory, never overlaps S1-prime and S2 credentials, and resumes only the same
authorization from the empty or exact-S2 state after an ambiguous process loss:

```bash
printf '%s\n' "$CONFIRMATION_PHRASE" | \
  python -B scripts/private_release_v2_fic_repin.py apply \
    --authorization /external/s2-fic-repin-authorization.json \
    --preflight /external/s2-fic-repin-preflight.json \
    --bootstrap-authorization /external/bootstrap-authorization.json \
    --bootstrap-preflight /external/bootstrap-preflight.json
python -B scripts/private_release_v2_fic_repin.py validate-receipt \
  --receipt /external/paperdesk-private-release-v2-s2-fic-repin-00000000-0000-4000-8000-000000000000/06-terminal-receipt.json \
  --bootstrap-authorization /external/bootstrap-authorization.json \
  --bootstrap-preflight /external/bootstrap-preflight.json
```

Only after that terminal receipt validates, build the strict activation
document offline. This command has no Azure or GitHub transport and writes the
activation document and its descriptor create-only:

```bash
python -B scripts/private_release_v2_activation.py \
  --bootstrap-authorization /external/bootstrap-authorization.json \
  --bootstrap-preflight /external/bootstrap-preflight.json \
  --repin-receipt /external/paperdesk-private-release-v2-s2-fic-repin-00000000-0000-4000-8000-000000000000/06-terminal-receipt.json \
  --activation-output /external/paperdesk-private-release-v2-activation.json \
  --descriptor-output /external/paperdesk-private-release-v2-activation-descriptor.json
```

The strict document binds `mergedControlWorkflowSha` to S2 and
`bridgePackageSourceSha` to S1-prime; equality is rejected. Publishing its exact
bytes to the protected GitHub environment and switching the named publisher
client ID remain separately authorized caller-integration actions, not effects
of the offline builder.

## Local verification

Use a Python runtime with bytecode generation disabled when validating a shared
review checkout:

```bash
PYTHONDONTWRITEBYTECODE=1 python -B tests/test_workflow_contract.py
PYTHONDONTWRITEBYTECODE=1 python -B -m unittest \
  tests.test_private_release_bridge_package \
  tests.test_private_release_bridge_runtime \
  tests.test_private_release_bridge_azure \
  tests.test_private_release_external_controller
python -m py_compile \
  scripts/private_release_mailbox.py \
  scripts/private_release_external_controller.py \
  provider/private_release_bridge_runtime.py \
  provider/private_release_bridge_azure.py
```

`scripts/build_private_release_bridge_package.py` creates the deterministic V2
bridge package for byte-level review. Building the package is not permission to
upload it or mutate Azure.

## Watchdog V2

Watchdog V2 is a separate dormant system. Its deadline, baseline, and
reconciliation workflows stop before OIDC/provider calls. It binds immutable
source bytes, exact provider state, 1,440-minute acceptance deadline, WORM
decision-before-claim ordering, provider-owned rollback dispatch, and fail-closed
reconciliation. The watchdog evidence store's 90-day policy is separate from
the V2 package/accepted/result containers' minimum 91-day Locked policies.

Do not activate watchdog or private release control by filling a placeholder
SHA, weakening a test, broadening a role, adding a public bridge ingress, or
inserting a persistent secret. Activation requires its own exact evidence,
canaries, caller pin, and explicit review.
