# VRC publish: proof-of-possession in place of the issuer pin

Status: implemented — see `vtc-service/src/routes/relationships.rs`
Tracking: OpenVTC/verifiable-trust-infrastructure#1054, OpenVTC/openvtc#241
Upstream: trustoverip/dtgwg-cred-spec#21, trustoverip/dtgwg-cred-spec#9

## Why

`POST /v1/relationships` pins the VRC's `issuer` to the authenticated session
DID (`vtc-service/src/routes/relationships.rs:97-107`):

```rust
if auth.did != issuer_did { return Err(AppError::Forbidden(...)) }
```

That equality is what forces a member's membership DID (M-DID) into the durable,
publishable credential. Removing it is the change #1054 is blocking on. But the
pin is doing real work, and dropping it without a replacement removes a property
we want to keep.

## What the pin actually protects

Two properties are conflated in one line, and they need separating before
anything is replaced.

**P1 — the VRC was made by the party it names as issuer.** Provided already by
`verify_vc_proof` + `check_issuer_binding` (`relationships.rs:316-343`): the
data-integrity proof is verified against a verification method bound to the
`issuer` field. This holds whatever identifier the issuer used and is untouched
by anything below.

**P2 — the party publishing the VRC is the party that issued it.** This is what
the pin provides, and it is the property that needs a replacement.

P2 is worth keeping. Issuance and publication are distinct acts. A VRC handed
privately to a counterparty should not become an edge in the community graph
because the *counterparty* chose to upload it. Appearing in the graph is a
disclosure, and it should be the issuer's disclosure to make. Without P2 any
authenticated member could publish any VRC that ever reached them.

## Design

Replace the identity equality with a **publish-time proof of possession** of the
issuer's key, bound to the request. The session proves membership; the PoP proves
control of the issuing identifier; neither requires the two to be the same
string, and neither requires disclosing that they belong to one member.

### The authorization object

The client signs, with the private key of the VRC's `issuer`:

```json
{
  "type": "VrcPublishAuthorization",
  "vrc": "<sha-256 of the VRC, hex>",
  "aud": "<this VTC's C-DID>",
  "sessionId": "<the caller's authenticated session id>",
  "issuedAt": "2026-08-23T07:40:00Z"
}
```

Each field earns its place:

| Field | Prevents |
|---|---|
| `vrc` | replaying a captured PoP to authorize a *different* credential |
| `aud` | replaying a PoP made for one community at another |
| `sessionId` | replaying another member's PoP — this is the load-bearing binding |
| `issuedAt` | unbounded replay within a live session (accept a narrow window) |

`sessionId` is the field that does the real work. It ties "controls this R-DID"
to "is making this request" *inside the request*, rather than by naming the
member inside the credential. `AuthClaims.session_id`
(`vti-common/src/auth/extractor.rs:30`) is already carried through to handlers
for exactly this class of session-targeted operation, so nothing new is needed
to reach it.

The PoP is carried as a second field on `PublishBody`, which today is a single
`vrc` (`relationships.rs:57-65`).

### Canonicalization

The authorization object is signed with an `eddsa-jcs-2022` data-integrity
proof, so the signature is over RFC 8785 (JCS) canonical form and is reproducible
by any conforming implementation. This is the same `DataIntegrityProof` path the
VRC itself and the credential-exchange verifiers use, so no new machinery.

The `vrc` field of the authorization binds to the hash the handler computes with
its own `canonicalise` (`relationships.rs`), which is a recursive key sort only —
no number normalization, no string-escaping rules. That is adequate for the
idempotency key it was written for, and this change does not alter it, but it is
not a canonicalization a second implementation could reproduce from a
specification. It is a latent interop problem of the same kind
trustoverip/dtgwg-cred-spec#6 was filed about, and it now has a second consumer.
Worth a follow-up; deliberately out of scope here to keep the change reviewable.

### Verification order

1. Authenticate the session (unchanged). `auth.did` is a current member.
2. Extract `issuer` and `credentialSubject.id` from the VRC (unchanged).
3. **New, and it must stay here:** if no PoP was supplied and `issuer` is not the
   session DID, reject. This gate is before the resolver is touched, because the
   resolver is a *daemon-configuration* prerequisite — putting it first lets a
   missing resolver return 500 for what is really a 403, masking a caller error
   with an operator error. The original code ordered it this way deliberately
   ("Daemon-config prerequisites surface after caller validation"); an early
   draft of this change lost that, and the existing
   `publish_rejects_caller_not_issuer` test caught it.
4. Verify the VRC's data-integrity proof (unchanged) — **P1**.
5. Compute the VRC hash. Moves ahead of policy evaluation, since the PoP binds
   to it.
6. Verify the PoP signature against the `issuer` DID's verification method,
   reusing `DidVmResolver` and the same `check_issuer_binding` rule as step 4.
   Then check `type`, `vrc`, `aud`, `sessionId`, and the `issuedAt` freshness
   window — **P2**.
7. Evaluate policy against the new input shape (below).
8. Store, audit, respond (unchanged).

The `type` guard on the authorization object is not decoration: without it, any
object the member legitimately signed with the same key and which happens to
carry the right field names could be replayed as authorization to publish.

### The PoP is verified and discarded

**It must not be persisted, logged, or written to the audit trail.** The PoP
contains `sessionId`, and the session is attributable to an M-DID; storing it
would create exactly the durable M-DID-to-R-DID linkage this change exists to
remove. The ZKP task force made this point on trustoverip/dtgwg-cred-spec#9 —
"adding a visible field to make the association checkable would recreate exactly
the correlation surface you are flagging." A stored PoP is that field.

The `Relationship` row (`relationships.rs:167-176`) keeps only what it keeps
today, with R-DIDs in the two DID fields.

### Policy input

The current default policy asks whether both named parties are current members,
which is unanswerable once both are R-DIDs. The question it was really asking —
*is this publication authorized by a member of this community?* — is still
answerable, and more precisely than before:

```rego
package vtc.relationships
import rego.v1

default allow := false

allow if {
	input.action == "publish"
	input.authenticated_member.is_current   # the session is a live member
	input.issuer.pop_verified               # the caller controls the issuing DID
}
```

with input:

```json
{
  "vrc": { },
  "authenticated_member": { "did": "<M-DID>", "is_current": true },
  "issuer": { "did": "<R-DID>", "pop_verified": true },
  "subject": { "did": "<R-DID>" },
  "action": "publish"
}
```

`authenticated_member.did` is present for operator-authored policies that
legitimately need it (rate limits, per-member quotas, moderation holds). The
default policy does not read it, and the handler does not store it.

### The subject side

Today the handler requires the subject to be a current member
(`relationships.rs:120-134`). With R-DIDs that check is not merely unanswerable —
it is the wrong question, and the spec says so directly: "Community membership is
**not** a precondition for issuing, holding, or presenting a VRC"
(§Community-Anchored Zero-Knowledge Proof).

Drop it, and let the DTG edge model supply the consent it was standing in for.
Two VRCs, one in each direction, form a complete edge. Each half is published by
its own issuer under its own PoP. **The subject's consent to the edge is their
publication of the reciprocal VRC** — not the VTC's assertion that they exist.

This is the pattern the join flow already uses: the member-issued reciprocal VMC
in `trust-tasks/join-requests/accept/1.0/spec.md`, described upstream by the
spec editors as the member's *consent artifact*, on the reasoning that a
community can always assert someone is a member but cannot forge their
acknowledgement. The same logic applies one layer down.

Consequence: `GET /v1/relationships/graph` should distinguish half-edges from
complete edges, and the admin UI should show the difference. That is a better
graph than today's, which cannot tell a mutual relationship from a unilateral
claim. **Implemented** — see "The graph" below.

## Compatibility

Accept both forms for one release, keyed on what the credential contains:

- `issuer == auth.did` → the M-DID form. No PoP required; behaves as today.
  Emit a deprecation warning.
- `issuer != auth.did` → PoP required, verified as above.

Then flip the OpenVTC default (openvtc#241 has already landed the client half in
openvtc#254), then remove the legacy branch. This mirrors the `--generate-did`
no-op-that-warns approach openvtc#241 took, in the same direction.

## Tradeoffs to decide, not assume

**Audit attribution — decided.** The trail attributes a publication to the
**authenticated member**, not to the VRC's issuer. Under the pairwise form
those differ, and the issuing relationship DID names nobody, so recording it
would leave the trail unable to answer "which member published this edge" for
anyone, at any access level, ever.

This is a deliberate, narrow exception to the rule above that the
membership-to-relationship linkage must not be persisted, and the reasoning for
drawing it here and nowhere else:

- What #1054 set out to remove is *public, permanent, unavoidable* correlation
  — a membership DID welded into a credential anyone can retain and republish.
  The audit store is none of those things: `AuditEnvelope` HMACs the actor
  under a rotating key (`actor_did_hash`, covered by the tamper-evidence
  chain), keeps the plaintext in a field deliberately excluded from the chain
  digest so RTBF can null it without breaking verification
  (`actor_did_plain`), and the surface is admin-gated.
- Giving it up would buy little. `VrcPublishedData` carries `vrc_id`, `vrc_id`
  resolves to the row, and the row holds the relationship DIDs — so any trail
  that both references the edge and names the member creates the mapping
  transitively. There is no variant that attributes without linking.
- Moderation needs the reverse lookup. "This edge is abusive, who made it?" is
  the question an operator actually has; a hash-only variant answers only the
  forward one ("this member is suspect, what have they done?").

**The residual, stated plainly:** an operator with audit access can map every
pairwise edge to its member. That is the cost, it is accepted, and it is why
the linkage stops at the audit store — the `info!` on the publish path carries
the relationship DID and not the member, because logs have neither the
redaction machinery nor the access controls that make this trade defensible.

Note this decision is not VRC-specific. It answers "when a member acts under a
pairwise identifier, what does the audit trail record?", and it should hold for
every pairwise-capable operation added later.

**Admin revocation is unaffected.** It keys on row id, not issuer identity
(`relationships.rs`, revoke section), so moderation of a specific edge still
works.

**Accepted DID methods become policy.** If the issuer identifier is
method-independent — and it should be; nothing in this design reads a method
prefix, and neither does the current handler — the VTC cannot assume what members
mint R-DIDs under. `DIDCacheClient::new(DIDCacheConfigBuilder::default().build())`
(`vtc-service/src/server.rs:1715`) currently accepts whatever the library
default supports, which is permissive by accident. `vta-config` already has the
shape to copy: `allowed_did_methods` (`vta-config/src/lib.rs:497`), enforced at
`vta-service/src/auth/backend.rs:136-145`. The VTC's `validate_did` hook is the
no-op default (`vti-common/src/auth/backend.rs:284`). The criterion worth
enforcing is that resolving an R-DID must not disclose the relationship to a
third party; methods either meet it or do not, and the community should say which
it accepts.

## The graph — the remaining #1054 work

Two things were left open on the graph in #1054. One was built and one was
deliberately not, and the reasoning for the second is the more useful record.

### Half-edges vs complete edges — built

`GET /v1/relationships/graph` returned one entry per stored VRC, so a mutual
relationship and a unilateral claim rendered identically. It now groups by
unordered pair (`vtc-service/src/routes/relationships.rs`, `build_graph`) and
each edge carries `endpoints` (DID-sorted), `halves` (every VRC published
between them, oldest first) and `complete` (a VRC exists in both directions).
The admin UI draws a complete edge solid and double-headed, a half-edge dashed
and single-headed, and counts them separately
(`vtc-service/admin-ui/src/plugins/relationshipsGraph.tsx`).

This is a breaking response-shape change. It is worth taking because the
distinction is what the dropped subject-membership check was replaced *with*:
if consent to an edge is the counterparty's publication of the reciprocal VRC,
an operator who cannot see whether that VRC arrived cannot see consent at all.

Two rules that are easy to get wrong and are pinned by tests:

- **Several VRCs in the same direction do not complete an edge.** Idempotency is
  keyed on the credential hash, not the direction, so a member can publish three
  A→B VRCs. `complete` checks for a VRC in each direction, not for two rows.
- **A self-issued VRC (`issuer == subject`) is never complete.** It has no
  counterparty who could reciprocate, and the naive both-directions test matches
  the same row twice.

### Stored vs derived — not built, and why

The proposal on #1054 was item 3: "make the graph derived rather than stored…
without persisting an M-DID adjacency list." That is not built, on two grounds.

**The motivation was removed by #1061, not deferred.** The concern was a durable
*membership-DID* adjacency list — a correlation store the community holds and
the spec's Privacy Considerations are written to avoid. Since #1061 the stored
DIDs are the identifiers the member chose to publish under. Under the pairwise
form those are R-DIDs, which name nobody and correlate nothing beyond the single
relationship they were minted for; under the attributed form the member has
deliberately asserted a correlatable edge, which DTG Credentials permits
directly. Neither is the thing item 3 was written against.

**"Derived" has no source to derive from.** The relationships keyspace is the
only place a published VRC exists on the VTC side — `Relationship.vrc_jsonld`
holds the credential verbatim, and `issuer_did` / `subject_did` are projections
of fields inside it (`vtc-service/src/relationships/mod.rs`). Deriving the graph
from something else would mean not storing published VRCs at all, which deletes
`POST /v1/relationships` and the two read endpoints with it. What is actually
available is a narrower change — drop the two projected DID columns and re-read
them out of the stored credential on each scan — and that removes no
information, because the credential containing them is still the row.

**And nothing publishes.** `POST /v1/relationships` is the only production
writer to the keyspace, and as of this note no caller exists: not in this
workspace, not in `vta-sdk` (which has no relationship protocol module at all),
not in `vtc-client`, and not in `openvtc`. OpenVTC mints VRCs through
`DTGCredential::new_vrc` and exchanges them peer-to-peer over DIDComm
(`openvtc/src/state_handler/inbox_actions.rs`,
`openvtc/src/state_handler/main_page/mod.rs`), then retains them locally; it
speaks the VTC's join, ACL, credential-exchange and self-remove Trust Tasks but
never `relationships/publish`. So the graph is empty in every deployment that
exists, and reshaping its storage would be work against no data and no reader.

None of that makes the *question* wrong — a community that gets real publish
traffic under the attributed form does accumulate a correlatable edge set, by
design and with the members' assertion, and one that gets pairwise traffic
accumulates a set that is correlatable only to the operator holding the audit
trail (see "Audit attribution" above, which is where that residual was already
recorded). It makes it premature. The point to revisit it is when something
publishes, and the concrete decision then is whether to keep `issuer_did` and
`subject_did` as columns or read them from the credential — not whether to hold
the credentials.

## What this does not solve

The VTC still observes the session's M-DID and the R-DID in the same request. The
association is transient and unstored, which is a real improvement over today —
where the linkage *is* the stored credential field — but it is not zero.

Removing it needs the community-anchored ZKP construction (§Community-Anchored
Zero-Knowledge Proof), which needs the identity linkages raised in
trustoverip/dtgwg-cred-spec#9 to be defined first. The ZKP TF's position there is
that it is "a real dependency, not a blocker". This design is the shape that
takes that proof when it arrives: predicate `issuer.pop_verified` is replaced by
a ZK proof of the same predicate, and neither the policy input shape nor the
stored row changes.

## Test matrix

| Case | Expected |
|---|---|
| R-DID issuer, valid PoP, member session | 201, row stores R-DIDs |
| R-DID issuer, no PoP | 403 |
| PoP signed by a different key than `issuer` | 403 |
| PoP replayed with a different VRC | 403 (`vrc` mismatch) |
| PoP replayed by a different member's session | 403 (`sessionId` mismatch) |
| PoP replayed at another VTC | 403 (`aud` mismatch) |
| PoP outside the freshness window | 403 |
| Same VRC published twice | 200, idempotent, same id |
| Subject not a member | 201 — no longer an error |
| One direction only | edge shows as half, not complete |
| `issuer == auth.did`, no PoP | 201 + deprecation warning |
| Stored row and logs | contain no `sessionId` and no membership DID |
| Audit envelope | actor is the member, never the relationship DID |

The last row is the one that regresses silently if someone later adds a debug
log. It deserves an explicit assertion, not a review comment.
