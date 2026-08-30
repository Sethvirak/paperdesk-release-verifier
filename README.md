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

Merging dormant source is not deployment authorization. No Azure mutation is
authorized until the exact S2 evidence, FIC repin, activation contract, and main
caller integration described below have been separately reviewed and approved.

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

1. Merge dormant exact-SHA source **S1** with null activation.
2. Provision exact resources and temporarily bind the sole publisher FIC to S1.
3. Commit SHA-independent concrete evidence and the bootstrap receipt in **S2**.
4. Explicitly repin that sole FIC from S1 to S2 and prove no stale/extra FIC.
5. Only after independent review, main pins S2 and receives its exact caller
   integration.

No Azure mutation is authorized before S2 evidence acceptance and FIC repin, and
main pins S2 only after those gates. No impossible S3 self-reference is needed.
Any later drift requires fresh evidence and a new reviewed pin.

## Bootstrap boundary

The local bootstrap provisioner is a separate, explicitly authorized operator
action, not a GitHub runner shortcut. It may temporarily add only:

- the current host's exact public IPv4 `/32` Storage firewall rule; and
- Blob Data Contributor on the exact package container for the local uploader.

It uses Azure AD create-only upload, verifies exact SHA-256/size/ETag/version ID,
then removes only its owned `/32` rule and exact temporary assignment. Fresh
readback must prove both are absent before the V2 site starts. It may not use a
SAS, account key, Shared Key, broad CIDR, stale full-ACL restore, or public
container. Managed-identity package fetch must succeed through the reviewed
service-endpoint topology before WORM locking/activation is accepted.

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
