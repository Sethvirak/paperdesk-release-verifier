# Security policy

Report security issues privately through GitHub's security-advisory interface. Do not open a public issue containing credentials, private repository contents, release artifacts, or production evidence.

This repository must contain only public verification/control code. PaperDesk
source, runtime artifacts, credentials, customer data, and unreviewed production
coordinates are prohibited.

A narrow exception permits committed V2 bootstrap/S2 evidence only when it is
canonical, non-secret, independently reviewable, and limited to the public
resource identifiers, cryptographic digests, ETags/version IDs, redacted posture
projections, and cleanup/canary receipts required by the V2 trust contract. It
must never contain raw IP addresses, bearer or refresh tokens, SAS query strings,
Shared Key/account keys, GitHub/OIDC claim tokens, passwords, customer records,
private repository content, release artifact bytes, or other credential
material. Evidence that cannot be safely redacted stays outside this repository.

The external bootstrap receipt parent is a trusted local boundary: it must be an
operator-controlled, access-restricted real directory that is not a symlink,
junction, shared workspace, or writable by another same-privilege process.
Same-privilege replacement of that parent is outside the evidence threat model.
The local filesystem must support file and directory durability barriers;
unsupported filesystems fail closed before the executor may rely on ordering.
The provisioner nevertheless uses exclusive-create files, canonical readback,
fsync, exact path confinement, and byte-identical resume. An ambiguous partial
file left by a write or fsync failure is intentionally never deleted or
overwritten; it conflicts on retry and requires manual reconciliation while the
single-use authorization remains consumed.
