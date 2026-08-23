# Personhood + relationships

The VTC ships two member-graph features in Phase 4:

- **Personhood** — an admin/issuer asserts that a member is a
  unique human (or human-equivalent agent), backed by witness
  evidence the operator's `personhood.rego` accepts.
- **VRC graph** — members self-issue Verifiable Relationship
  Credentials declaring trust edges to other members, forming a
  community-internal trust graph.

Both surfaces are optional. Communities that don't need them never
emit the underlying audit events.

## Personhood lifecycle

```mermaid
stateDiagram-v2
    [*] --> NoPersonhood : member joins
    NoPersonhood --> Challenged : POST /v1/members/{did}/personhood/challenge
    Challenged --> NoPersonhood : challenge expires (10 min)
    Challenged --> Asserted : POST /v1/members/{did}/personhood/assert<br/>(VP signed by member)
    Asserted --> Revoked : POST /v1/members/{did}/personhood/revoke<br/>(admin / self / renewal-policy)
    Revoked --> Challenged : new evidence
    Asserted --> Asserted : renewal re-evaluates
    Revoked --> [*] : member departs
```

The flag lives on the Member row alongside an `asserted_at`
timestamp; tombstoning a member wipes both fields.

### Assertion ceremony

```mermaid
sequenceDiagram
    participant M as Member (subject)
    participant A as Asserter (admin / issuer)
    participant VTC as VTC

    A->>VTC: POST /v1/members/{did}/personhood/challenge
    VTC->>VTC: Store nonce in passkey_ks<br/>(10-min TTL, single-use)
    VTC-->>A: { challenge, expiresAt }
    A->>M: Out-of-band — share nonce
    M->>M: Assemble VP with<br/>witness credentials
    M->>VTC: POST /v1/members/{did}/personhood/assert<br/>(VP, includes challenge nonce)
    VTC->>VTC: 1) Load Member row (404 if missing)
    VTC->>VTC: 2) Consume challenge<br/>(400 on missing/expired/wrong-DID)
    VTC->>VTC: 3) Verify VP.holder == path-DID
    VTC->>VTC: 4) Evaluate personhood.rego<br/>(WitnessCredential check by default)
    alt policy allows
        VTC->>VTC: Set personhood=true<br/>Set asserted_at=now
        VTC->>VTC: Re-mint VMC with new flag
        VTC->>VTC: Audit: PersonhoodAsserted
        VTC-->>M: 200 + new VMC bundle
    else policy denies
        VTC-->>M: 403 + reason
    end
```

**VP-only assert** (Phase 4 D2): the request body is purely a
Verifiable Presentation. The handler verifies the VP and discards
it — no `personhood_evidence` JSON field, no separate signed-blob
shape. The verify-then-discard semantics keep PII out of the
request log.

### Revocation

Three triggers:

| Trigger | Audit `reason` field |
|---|---|
| Admin via `DELETE /v1/members/{did}/personhood` | `"admin"` |
| Self via `DELETE /v1/members/me/personhood` | `"self"` |
| Renewal-policy downgrade (operator-configured) | `"renewal-policy"` |

The third is the operator-configurable failure mode discussed in
[`community-lifecycle.md`](community-lifecycle.md#renewal-failure-modes).

## VRC trust graph

A Verifiable Relationship Credential declares "I, member A, trust
member B in some specific way". The VTC stores the VRC if both
parties are current members (default policy); listing endpoints
strip VRCs naming a `Purge`-departed member.

```mermaid
graph LR
    A[Member A]
    B[Member B]
    C[Member C]

    A -->|VRC: 'trusts'| B
    B -->|VRC: 'trusts'| C
    C -->|VRC: 'trusts'| A
    A -->|VRC: 'recommends'| C

    classDef mem fill:#e9d7f7,stroke:#7e3fa6,color:#3a0a5a
    class A,B,C mem
```

### Publication

```mermaid
sequenceDiagram
    participant Issuer as Member A (issuer)
    participant VTC as VTC
    participant Subject as Member B

    Issuer->>Issuer: Mint VRC locally<br/>(sign with own key)
    Issuer->>VTC: POST /v1/relationships<br/>(VRC body)
    VTC->>VTC: Verify caller is issuer of VRC
    VTC->>VTC: Verify VRC proof against issuer's resolved DID
    VTC->>VTC: Evaluate relationships.rego<br/>(default: both parties current members)
    VTC->>VTC: Idempotent on SHA-256 of VRC body
    VTC->>VTC: Persist row (relationships keyspace)<br/>+ secondary index (relationships_by_did)
    VTC->>VTC: Audit: VrcPublished
    VTC-->>Issuer: 201 + relationship_id
    Note over Subject: B can query their incoming VRCs<br/>via GET /v1/members/{did}/relationships
```

The secondary index makes the per-DID lookup O(matched rows)
rather than scanning the entire VRC table.

### Listing + filtering

`GET /v1/members/{did}/relationships` returns every VRC where the
DID is issuer or subject. The handler strips VRCs whose **other
party** has departed with `Purge` disposition — the VRC's
counter-party is permanently anonymised, so the listing hides the
relationship to preserve the §12.3 spec invariant.

VRCs naming a `Tombstone` or `Historical` departure stay visible
(the counter-party's DID is still recoverable).

### Self-issued only (MVP)

Bilateral counter-signing (where B confirms A's VRC) is **v2**.
For Phase 4, every VRC is self-issued by the originator.

### The connections graph: half-edges vs complete edges

`GET /v1/relationships/graph` (admin-only) returns the whole edge
set for the admin UI's connections view. DTG Credentials defines a
DTG edge as **two** VRCs, one in each direction, so the response
groups by unordered pair rather than listing one entry per stored
credential:

```json
{
  "nodes": [{ "did": "did:key:zA" }, { "did": "did:key:zB" }],
  "edges": [{
    "endpoints": ["did:key:zA", "did:key:zB"],
    "halves": [
      { "id": "…", "issuerDid": "did:key:zA", "subjectDid": "did:key:zB", "createdAt": "…" },
      { "id": "…", "issuerDid": "did:key:zB", "subjectDid": "did:key:zA", "createdAt": "…" }
    ],
    "complete": true
  }]
}
```

`complete` is true only when a VRC exists in **both** directions.
A single-direction edge is a *half-edge* — one party's claim that
the other has not answered.

The distinction matters because it is what replaced a check.
Publishing used to require the subject to be a current member; that
check was the community asserting on the subject's behalf that the
edge was legitimate. #1061 dropped it, on the DTG rule that
"community membership is not a precondition for issuing, holding,
or presenting a VRC", and on the reasoning that the subject's
consent to an edge is *their publication of the reciprocal VRC*.
That consent signal is only visible to an operator if the graph
shows whether the reciprocal VRC arrived — which is what
`complete` is.

`endpoints` is DID-sorted so a pair has one identity whichever
half was published first. `halves` can hold more than two entries:
idempotency is keyed on the credential hash, not on direction, so a
party can publish several VRCs the same way round. That does not
make an edge complete — the check is for a VRC in each direction,
not for two credentials.

Design record:
[`../05-design-notes/vrc-publish-proof-of-possession.md`](../05-design-notes/vrc-publish-proof-of-possession.md).

## Custom endorsements

Phase 4 also adds operator-defined custom endorsements via an
in-process type registry. See [`credentials.md`](credentials.md)
for the issuance + revocation flow. Three pieces compose:

1. **Type registry** — admin uploads endorsement types
   (`POST /v1/endorsement-types`) with optional JSON schema for
   claim validation.
2. **Issuance** — Issuer role (or admin) calls
   `POST /v1/credentials/endorsements` with type + subject +
   claim.
3. **Revocation** — `DELETE /v1/credentials/endorsements/{id}`
   flips the shared status-list slot.

Reserved type URIs (`CommunityRole`) are blocked from operator
registration to keep the workspace's role taxonomy stable.

## Audit events

| Event | When emitted |
|---|---|
| `PersonhoodAsserted { reason, asserter_did_hash }` | Successful `assert` |
| `PersonhoodRevoked { reason, revoker_did_hash }` | Any revoke path |
| `VrcPublished { vrc_id, issuer_did_hash, subject_did_hash }` | `POST /v1/relationships` success |
| `VrcRevoked { vrc_id }` | `DELETE /v1/relationships/{id}` |
| `CustomEndorsementIssued { endorsement_id, type_uri, ... }` | Endorsement issuance |
| `CustomEndorsementRevoked { endorsement_id, type_uri }` | Endorsement revoke + paired `StatusListFlipped` |
| `EndorsementTypeRegistered { type_uri }` | Admin uploads type |
| `EndorsementTypeDeleted { type_uri }` | Admin deletes unused type |

All actor DIDs are HMAC-hashed per the §11.1 PII policy.

## CLI quick reference

```sh
# Personhood (admin / issuer view)
cnm members personhood challenge <did>
cnm members personhood assert <did> --vp ./evidence-vp.json
cnm members personhood revoke <did>

# Relationships (member view via pnm)
pnm vtc relationships list
pnm vtc relationships publish --subject did:key:zOther... --type 'trusts'
pnm vtc relationships revoke <id>
```

## See also

- [Community lifecycle](community-lifecycle.md) — personhood
  interacts with renewal failure modes.
- [Credentials](credentials.md) — VRC + custom endorsement
  status-list mechanics.
- [VTC MVP spec §6.4, §7, §12.3](../05-design-notes/vtc-mvp.md).
