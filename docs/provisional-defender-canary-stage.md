# Provisional Defender canary stage (source-only)

This stage is an offline contract and planner, **not** an Azure operation. The
source-controlled policy at
`contracts/provisional_defender_canary_stage.json` is `source-dormant` with an
empty candidate allowlist. There is no workflow entry, provider adapter, cloud
login, blob write, production setting change, or deployment call. Even a test
proposal satisfying every local check returns `activationAllowed: false`,
`candidateConsumeAllowed: false`, and `acceptedRegistryWriteAllowed: false`.

The purpose is to define a narrow provisional path without changing the
existing `deploy-candidate` health rule. That rule requires `/api/health/ready`
HTTP 200 before the candidate is consumed. `persist-accepted-release` still
requires its existing production acceptance proof and WORM manifest. A 503
canary can never be interpreted as ordinary candidate success or a final
accepted release by this code.

## Proposed evidence boundary

An eventual independently reviewed policy would allowlist exactly one
application commit and tree, verifier workflow commit and tree, verified
archive digest, verification-receipt byte digest, deployment package digest,
source/deployment run coordinates, served index digest, immutable package key,
accepted rollback-baseline identity, and an exact reviewed `paperdesk_*_owner`
role, its exact `paperdesk_*_probe` login role, and the complete menu-row
inventory digest/count. The role names are confined to the PaperDesk namespace;
Azure, administrator, and PostgreSQL built-in role names are rejected. The
offline planner verifies both local commits against the pinned SSH signer
principal and key. It checks the
exact receipt bytes, source artifact name, verifier job, source/run/workflow
binding, package readback projection, and that the proposed marker key starts
under `v2/provisional/`, never
`v2/accepted/`.

The current historical `70f3ac...` source observation is not by itself an
accepted rollback baseline. Its exact V2 bootstrap accepted manifest and
receipt must exist and pass independent readback before this proposed stage
could have a rollback target.

The candidate health projection requires the exact runtime SHA and served
index digest, HTTP 200 from `/api/health/live`, `/api/app-health`, and
`/api/security-info`, and HTTP 503 from `/api/health/ready` with the nested
`attachment-malware-ingestion-not-ready` code. It checks the raw readiness
response digest and JSON projection. A separate read-only PostgreSQL probe
must match the app's `repository.probeReadiness()` contract: `app_kv`
reachability and no `menu_rows` row with `visibility_text_ready=false` or
`visibility_text_version<2`. The app-role query must report
`row_security_active('menu_rows')=true`. A separate, reviewed non-BYPASSRLS
owner-view query must show `FORCE ROW LEVEL SECURITY`, active row security,
complete policy coverage, the pinned full inventory digest/count, and zero
visibility-marker failures. A maintenance-gate snapshot must show
`maintenance=false`; bounded Azure Monitor CPU, memory, and PostgreSQL storage
headroom are also required. The four probe IDs must differ and all
observations must be fresh. The rollback deadline is exactly 24 hours after
deployment, with a 15-minute execution reserve. An expired window fails
closed.

The PostgreSQL preflight must run under the final configured `paperdesk_app`
login and prove it has no superuser, `BYPASSRLS`, `CREATEROLE`, or `CREATEDB`
attribute. It must also have no `REPLICATION`, database/TEMP/public-schema
CREATE, PaperDesk table/function ownership, or privileged owner-role
membership, including inherited privileged memberships. These match the app's
runtime-role preflight. The separately reviewed owner must be `NOLOGIN`,
`NOSUPERUSER`, `NOBYPASSRLS`, `NOCREATEDB`, `NOCREATEROLE`, and `NOREPLICATION`,
with no direct or inherited privileged role membership. An administrator
session, even if it can query `app_kv` and `menu_rows`, is not valid evidence.
The observed production `paperdeskadmin`
sessions and absent `paperdesk_app` role therefore block this proposed stage
until the role and application connection are corrected and independently
rechecked.

Because a `NOLOGIN` owner cannot be used for a direct login, its complete
owner-view probe requires a separately reviewed operator login and `SET ROLE`
transition. The future authenticated PostgreSQL adapter must attest the exact
`session_user` login role, effective `current_user` owner role after the
transition, authorization for that transition, role attributes and membership,
the complete query bytes and result, and a bound digest. If the identity or
transition cannot be proven, the proposal stops. A submitted role name or
digest alone is not authentication.

The app-role `NOT EXISTS` visibility query can see no rows hidden by RLS and
still report ready. The separate owner-view query is therefore a required
completeness check; it cannot be replaced by the app-role result or by an
administrator/BYPASSRLS query.

The reviewed `NOLOGIN` owner can also see a filtered subset under
`FORCE ROW LEVEL SECURITY`. Its `visibleMenuRows` and digest are not a
full-inventory proof on their own. A future authenticated adapter must bind the
allowlisted inventory to an independently attested, full-visibility operator
snapshot at the same matched database checkpoint as the owner-view probe, with
writers stopped. It must record the snapshot provenance and writer-stop proof
and compare the owner-visible count and digest against that complete snapshot.
If migration occurs, both views need a new matched-checkpoint comparison and
the allowlist needs independent review of the post-migration digest/count
before any provisional decision. The full-visibility operator snapshot proves
completeness only; it cannot substitute for the separate least-privilege app
role and reviewed owner probes. The current offline planner cannot authenticate
that checkpoint or provenance and remains dormant.

These local checks do not authenticate live HTTP, Azure Monitor, PostgreSQL,
Blob, GitHub Actions, or accepted-registry observations. The exact source
signature also does not prove independent PR approval or that a GitHub run
completed successfully. The public readiness 503 short-circuits before the
repository readiness query, so even its exact malware code does not establish
the sole cause of failure. The planner therefore never authorizes activation.

## Work required before any provisional deployment

1. Obtain independent source review of the exact allowlisted candidate and
   verifier changes. Validate the successful exact GitHub runs and the live
   package bytes against their retained receipts.
2. Implement read-only provider adapters that collect and authenticate the
   four HTTP responses, bounded PostgreSQL repository-equivalent readiness
   query under the final app role, complete reviewed owner-view query, matched
   full-visibility inventory snapshot with writer-stop and post-migration
   recheck evidence, maintenance snapshot, capacity metrics, package
   version/ETag, and accepted rollback baseline.
   Treat missing or contradictory evidence as a stop, including any additional
   cause of the readiness 503.
3. Add a distinct, reviewed OIDC operation and create-only, signed/WORM
   provisional marker with an atomic rollback deadline. It must not call the
   current candidate `consume` or accepted-registry write path. Specify the
   watchdog deadline, exact rollback target, idempotent recovery, and
   third-state behavior before granting production mutation authority.
4. Exercise the isolated source and provider negatives, one live canary, a
   timed rollback rehearsal, and final readiness HTTP 200 before any accepted
   release. Cloud usage for a live canary needs its own bounded cost approval.

Run the local checks with
`python -m unittest tests.test_provisional_defender_canary_stage -v`.
