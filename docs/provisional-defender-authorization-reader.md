# Dormant private Defender marker byte reader

`scripts/provisional_defender_authorization.py` is an offline candidate inspector.
It checks real PS256 signatures, canonical bytes and the separate private marker
schema. It does not authorize a PaperDesk operation. The source-owned contract
`contracts/provisional_defender_authorization_reader.json` has an empty candidate
allowlist and all admission, activation, consume and accepted-write flags false.
There is no issuer, cloud reader, transport, route, workflow entry, SQL interface
or durable one-use claim. The existing bridge package excludes this module by its
unchanged exact source list.

This boundary is adjacent to the existing provisional planning owner. It does
not require or merge the unmerged planner PR #104. It does not change the normal
mailbox request/result schemas, operations, candidate consumption, accepted
registry predicates, bootstrap plan, signing-key maintenance or activation DAG.
The existing mailbox `canonical`, `verify_ps256`, descriptor validator and
`WormRecord` projections supply the encoding, cryptography and record vocabulary.
`verify_signed_result` is deliberately not used: its normal result schema is
different. No signer or WORM write primitive is invoked.

## Candidate inspection interface

Call `inspect_candidate_record(record, pins_raw=..., now=...)` with an already
available `private_release_mailbox.WormRecord`, canonical comparison-pin bytes,
and an aware UTC inspection time. The inspector accepts no transport, provider
object or callback. The record's blob name, exact byte SHA-256 and size, ETag and
version ID must match the supplied five-field descriptor. Marker bytes are at
most 65,536 bytes; pin bytes at most 131,072. JSON is UTF-8, sorted, compact,
newline-terminated mailbox encoding. Duplicate keys, noncanonical encoding,
nonfinite numbers, excessive recursion, unknown fields and incorrectly typed
numbers/booleans are rejected. `schemaVersion: true` is not version 1.

The exact pin fields are `schemaVersion`, `purpose`, `signing`,
`markerDescriptor` and `expectedAuthorization`; purpose must be
`candidate-inspection-only`. The expected authorization contains the entire
expected tuple. A caller-supplied `verified`, approval, activation, trusted-key
or provider flag is an unknown field, not a shortcut. The signing comparison
contains only exact canonical HTTPS Key Vault key coordinates, a 32-hex version,
and the five-field public RSA JWK. RSA is exactly 3072 bits, exponent 65537,
`key_ops` is exactly `['sign', 'verify']`; private JWK fields and other algorithms
are rejected. Base64url must be unpadded and round-trip canonical; the signature
is exactly 384 bytes and less than the RSA modulus. Existing `verify_ps256`
checks SHA-256 PSS with its fixed 32-byte salt.

These inputs are **comparison pins, not admitted trust**. A caller can generate
its own key and fabricate a record and comparison tuple that satisfy inspection.
The receipt therefore says only `signatureValidForSuppliedKey: true` and
`status: cryptographic-candidate-only`. It always says external authority,
provider readback, one-use state and authorization admission are unverified;
all activation, consume and accepted-write flags remain false. Receipts contain
only bounded status/boolean fields and digests, no operation ID, URI, principal,
HMAC, raw marker or public key. Inspection can be repeated and creates no files
or claim. It does not imply that a provider was read or that a run, review,
accepted manifest, migration or delivery occurred.

`admit_authorization(...)` always raises
`PROVISIONAL_DEFENDER_AUTHORIZATION_ADMISSION_UNAVAILABLE` before inspecting its
arguments or doing crypto/provider work. A role name, signed candidate receipt,
caller boolean or fabricated context cannot open it.

## Exact signed byte contract

The envelope has exactly `authorization` and `signature`; signature fields are
`algorithm: PS256`, `keyId`, `keyVersion`, `value`. Signing covers the exact
canonical authorization bytes, including the following separate-domain tuple:

| Map | Required bindings |
| --- | --- |
| Authorization root | Typed schema version 1, fixed kind, domain `paperdesk:v2:provisional:defender:authorization`, audience `paperdesk-private-defender-transition`, operation ID, operation digest, full binding digest, approval receipt digest, issued/start/deadline timestamps |
| Candidate | Exact app repository, commit/tree, source run/attempt/artifact, archive/package/verification receipt/served-index digests, exact versioned pending-package descriptor |
| Control | Exact verifier repository, control commit/tree, run/attempt/workflow, bootstrap receipt, S2 activation evidence, independent source review evidence and bridge package digests |
| Rollback | Distinct source, exact source-keyed accepted-manifest descriptor, package and accepted proof digests |
| Database | Migration, schema, role policy, matched checkpoint and writer-fence digests, exact private owner and transition role |
| Provider | Exact account resource/HTTPS endpoint/container/reserved target, reference HMAC/key/generation, same-scope system topic, topic/scope and fixture digests/size |
| Principals | Exact tenant, separated signer/canary/Event Grid object IDs, distinct canary/Event Grid client IDs, exact audiences and tenant issuer |
| Evidence | Versioned descriptors for repository, maintenance, capacity, ingress, cohort/drain, deadline, provider binding and delivery provenance |
| Lifecycle | Private store only, no ordinary writes/restart/cleanup, one active operation, explicit ETag with optional version ID, one-use requirement and 900-second rollback execution reserve |

The candidate pending-package descriptor retains the existing exact
`v1/pending/<sha>/<source-run>-<attempt>-<artifact>/deployment.zip` coordinate;
its byte digest must equal the package digest. Rollback may name only the exact
`v2/accepted/<sha>/manifest.json` or existing bootstrap-consumed manifest path.
The bootstrap path additionally requires the existing source-pinned bootstrap SHA.
This is coordinate inspection, not the accepted proof-chain validation.
Evidence descriptors are under `v2/provisional-evidence/`. The marker itself is
under `v2/provisional/<operation-digest>/authorization.json`; it never uses the
normal accepted namespace.

The operation digest preserves the existing app `operationBinding` domain and
UTF-8 compact JSON-array encoding without a newline: operation ID, candidate,
rollback, approval receipt, start and deadline. The separately derived reserved
object label preserves the existing object domain and 32-hex canary run label.
It is a target label, not an operation proof. `bindingSha256` hashes the complete
canonical authorization with only that field omitted, binding every additional
control/provider/principal/evidence/lifecycle field. Both values are checked.
The full marker's descriptor additionally binds the signature and envelope bytes.
Conflicting bytes under the same supplied immutable descriptor fail readback;
this module does not independently establish provider immutability or inspect
other existing versions.

Issue time is at or before start and at most ten minutes earlier. The signed
window is greater than fifteen minutes and at most 24 hours. Inspection requires
start <= current UTC time < deadline minus the 15-minute rollback reserve. An
inspection clock is not database time or an external watchdog.

## Missing authority gates before integration

An authorization reader must not be connected to a trusted transition until
there is a genuinely independently admitted issuer and verification context.
The remaining prerequisites are:

1. Successful fresh bootstrap and immutable S2 evidence, independent exact-source
   reviews/runs, accepted evidence merge and exact caller/FIC identity repinning.
   Consumed failed bootstrap or maintenance receipts cannot substitute.
2. Independently read-back public key/version/attributes and signer separation;
   admitted verification pins must come from the accepted control boundary,
   never marker contents or caller input.
3. Authenticated bounded provider collectors, complete rollback descriptor/
   package/proof chain through the existing `_load_accepted`/resolution owners,
   exact WORM policy/version readback, live source and package comparisons,
   genuine run/review results and evidence freshness/provenance.
4. Independently reviewed database permissions and a proof-enforcing transition
   boundary denying raw DML, matched recovery, writer fences and catalog policy.
5. Durable one-use operation/marker identity, atomic private state/time/replay/
   incarnation checks, external deadline/watchdog, ingress and cohort/drain proof,
   and independently authenticated exact Event Grid delivery provenance.

The inspector does not fill any of these gates with asserted hashes. A later
issuer/reader integration needs its own exact source review and hostile tests.
No app/service/SQL/route/callback is wired by this tranche. Folio and unfinished
Meeting Workspace remain outside the first release.

Run the focused cloud-free checks:

```text
python -m unittest tests.test_provisional_defender_authorization tests.test_private_release_mailbox tests.test_private_release_bridge_package -v
```

Tests generate ephemeral synthetic RSA keys in memory and perform actual PS256
verification. They include hostile canonical/schema/key/signature/descriptor/
tuple/time/lifecycle cases, unconditional no-work admission rejection, dormant
policy and package/workflow exclusion. They make no Azure or database calls.
