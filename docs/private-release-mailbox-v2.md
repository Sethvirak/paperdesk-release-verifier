# Private release mailbox V2 (dormant exact-SHA source)

Private release mailbox V2 is the proposed production-control path. It keeps
release bytes, Storage data-plane credentials, production configuration writes,
and result signing off the GitHub-hosted runner. The committed source is still
**dormant**: every activation value in
`contracts/private_release_mailbox_contract.json` is null, the provisioning
evidence is source-dormant, and the reusable workflow rejects that state before
Azure login.

No Azure mutation is authorized by merging this source. Provisioning, evidence
commit, federated-identity credential (FIC) repin, caller integration, and an
explicit activation decision remain separate gates.

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

1. **S1** is the reviewed, dormant, exact-SHA reusable control source. Merge S1
   with null activation values.
2. Provision only the exact reviewed V2 resources and temporarily bind the one
   stable publisher FIC to S1. The local provisioner creates the versioned bridge
   package and exact evidence while the workflow remains unable to mutate.
3. Commit the concrete, SHA-independent provisioning evidence and bootstrap
   receipt in **S2**. S2 must not silently change the reviewed resource policy or
   source logic.
4. Explicitly repin the sole publisher FIC from S1 to S2. Action-time Graph and
   OIDC checks must observe only the exact S2 expression; stale or extra
   credentials fail closed.
5. After the FIC repin and independent evidence review, the main repository pins
   S2 and adds the exact production, persistence, and cleanup callers. No Azure
   mutation is authorized until S2 evidence is accepted, the FIC is repinned,
   the activation document is exact/non-null, and the caller is pinned.

No S3 self-reference is required. Any resource drift after S2 requires new
evidence and a new reviewed pin rather than editing a mutable environment value
around the source checks.

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

The package URL is not a secret. The GitHub runner validates the URL as bound
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

Health proof binds the runtime marker, served index SHA-256, live, ready,
app-health and security responses, plus the historical full OneDeploy collection
invariant: historical deployment ID, canonical full-collection semantic digest,
property-ID-set digest, and deployment count. OneDeploy is historical evidence;
run-from-package and the exact versioned package are the activation mechanism.

## Key and authorization proof

Before any mailbox, Storage, production, or signing action, the bridge performs
an exact versioned Key Vault `Get Key` with a dedicated read-only identity. The
projection digest, `kid`, RSA modulus/exponent, key operations, enabled and
non-exportable attributes, exact version, and minimum remaining lifetime must
match S2 evidence and the sealed JWK. The signer identity remains separate and
has only `Microsoft.KeyVault/vaults/keys/sign/action` on that key version.

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
  removal of the owned temporary `/32` firewall rule and Blob Data Contributor
  assignment, and proof both are absent before bridge start;
- service-endpoint topology, private containers, default-deny Storage firewall,
  exact integration subnet, and route-all outbound for bridge and production;
- exact live RBAC inventories and role definitions for publisher, bridge,
  writer, reader, signer, production activation, production system identity,
  and every audit-only assignment;
- at-least-91-day Locked policies for package, accepted, and result containers;
- exact versioned Key Vault key/JWK proof, bridge read-only key role, signer-only
  sign role, and no unexpected sensitive assignment;
- immutable bootstrap receipt, managed-identity package-fetch self-test, exact
  run-from-package marker/index/health proof, finite-lease tests, cleanup fast
  lane plus expiry fallback, and durable retained receipts.

Until those gates pass, the null activation contract remains the controlling
state and every mutating mode must stop before Azure login.
