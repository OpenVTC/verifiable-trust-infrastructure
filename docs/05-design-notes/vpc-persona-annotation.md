# VPC: the persona annotation on a relationship edge

Status: implemented (VTC half) — see `vtc-service/src/routes/relationships.rs`
Tracking: OpenVTC/verifiable-trust-infrastructure#1067
Upstream: trustoverip/dtgwg-cred-spec#9 (open — read §The binding, below)
Companion: `docs/05-design-notes/vrc-publish-proof-of-possession.md`

## Why

The proof-of-possession change gave a member two ways to publish a
relationship edge, and only two:

- **attributed** — the VRC is issued under the membership DID. Every edge
  names the member, and the graph correlates completely.
- **pairwise** — the VRC is issued under a relationship DID unique to one
  counterparty. No edge correlates with any other.

There is nothing between them, and DTG Credentials says there should be. Its
Privacy Considerations §3: "Correlation across relationships should occur only
through the holder's deliberate assertion of a persona (via a VPC) or an M-DID
— never as a side effect of credential structure." A member who wants three of
their pairwise edges to be recognisable as one party currently has one option
— republish all three under their M-DID — which correlates those three *and*
every other edge they have, forever, to anyone who retains the credential.

The VPC is the precise instrument the blunt one was standing in for. It had no
implementation anywhere in this stack: `PersonaCredential` appeared nowhere,
`DTGCredential::new_vpc` was never called, and — as #1067 records — the word
"persona" drifted onto the membership DID in the absence of anything to anchor
it.

## Scope: the VTC half only

The VPC is **self-issued by a person**, exactly like the VRC. Its `issuer` is a
persona DID (P-DID) the member controls; the VTC has no key that may
legitimately sign one, and `credentials/dtg.rs` therefore gained no
`issue_persona`. What the VTC owns is the other half: verifying a VPC presented
to it, deciding whether it may annotate an edge in this community's graph, and
surfacing the correlation it asserts.

Minting the VPC, choosing when to assert a persona, and reusing a P-DID across
communities are all client concerns (`openvtc`). None of that is here.

## Model

A VPC is a DTG **annotation** credential: "annotation credentials do not create
graph structure. They attach data to existing edges or parties." So there is no
"publish a VPC" endpoint. There is `POST` / `DELETE
/v1/relationships/{id}/persona`, and the annotation is stored as an optional
field on the edge row rather than in a keyspace of its own — there is no
persona record without an edge to hang it on, and deleting the edge deletes the
annotation with it.

One VRC is one *direction* of an edge, and the persona it carries belongs to
the party who issued it. The counterparty asserts their own persona on their
own reciprocal VRC. Neither party can put words in the other's mouth.

## The binding — and the assumption in it

**trustoverip/dtgwg-cred-spec#9 is open and asks exactly this question. Nothing
below is settled upstream, and none of it is proposed as an answer.**

A VPC names its persona (`issuer`) and the counterparty
(`credentialSubject.id`). It does *not* name the relationship DID the persona
used, so a VPC on its own does not identify an edge.

Rather than add a field to the credential and present it as the resolution, the
binding here is made at the **request** level, from three parts:

1. the caller names the edge, by id, in the URL;
2. the caller proves control of that edge's `issuerDid`, with the same
   proof-of-possession construction publishing the edge required;
3. the VPC's `credentialSubject.id` must equal the edge's `subjectDid`.

(2) is what makes it safe. The only party who could have published this edge is
the only party who can annotate it, so attaching a persona is exactly as
authorized as publishing the edge was — no new trust is extended. (3) is a
consistency check, not a binding: it rules out attaching a persona that was
asserted to some *other* counterparty.

The authorization object mirrors `VrcPublishAuthorization` field for field,
plus the edge it names:

```json
{
  "type": "VpcAttachAuthorization",
  "vpc": "<sha-256 of the VPC, hex>",
  "relationship": "<uuid of the edge>",
  "aud": "<this VTC's C-DID>",
  "sessionId": "<the caller's authenticated session id>",
  "issuedAt": "2026-08-23T07:40:00Z"
}
```

`VpcDetachAuthorization` is the same without `vpc`. The two `type` values are
distinct on purpose: a captured attach authorization must not let its holder
strip the persona it was made to assert.

Like the publish authorization, **it is verified and discarded** — it carries
`sessionId`, and persisting that would rebuild the membership-to-relationship
linkage the pairwise identifier exists to remove.

If #9 lands an in-credential binding — a `digest` over the VRC, as the VWC
already has — this endpoint can require that in addition, without changing the
stored shape or the authorization object.

### Known limitation

DTG Credentials says the VPC's subject is "typically the R-DID **or M-DID**
used in the relationship". A VPC whose subject is the counterparty's M-DID, on
an edge whose `subjectDid` is their R-DID, fails check (3) and is rejected.
That case is real. Accepting it needs the same #9 answer, and guessing at it
would mean accepting a VPC that names a party the VTC cannot tie to the edge —
which is the whole problem, restated.

## What the community learns

The P-DID lands on `GET /v1/relationships/graph` as `personaDid`. Two pairwise
edges carrying the same `personaDid` are the same party, said so by that party.
That is the deliberate correlation, and making it visible is the point — an
annotation nothing reads would leave #1067 in the state it describes.

**There is deliberately no uniqueness check on the P-DID**, in direct contrast
to the R-DID rule the publish path enforces unconditionally. A relationship DID
that recurs across counterparties is a defect; a persona DID that recurs is the
entire purpose of the credential.

There is also no `relationships_by_did` index entry for the P-DID, so there is
no "list every edge of persona P" query. The admin graph answers the same
question, and a per-persona lookup is an enumeration surface that deserves its
own design rather than falling out of an index write.

## Audit

`VpcAttached` / `VpcDetached` record the edge id and the P-DID, with the
**authenticated member** as actor — the same attribution decision the VRC
publish trail makes, for the same reason: under a pairwise identifier the edge
issuer names nobody, so a trail keyed on it could answer "who asserted this
persona" for no one, ever.

This does put an M-DID-to-P-DID mapping in the audit store. It is the same
accepted trade set out in `vrc-publish-proof-of-possession.md` §Audit
attribution — the store HMACs the actor under a rotating key, keeps the
plaintext in a field RTBF can null without breaking the tamper-evidence chain,
and is admin-gated — and it stops there. The `info!` on both paths carries the
persona and not the member.

Detach is audited too. Withdrawing a persona is as much a privacy act as
asserting one.

## What is not here

- **No policy purpose.** Attach is gated on a live member session plus proof of
  control of the edge's issuer. There is no `persona.rego`, because a community
  that can already decide whether an edge may be published has not obviously
  earned a second, separate say over what its issuer calls themselves. If that
  turns out to be wrong it is additive.
- **No ZKP.** The Pairwise Zero-Knowledge Proof discloses P-DIDs while hiding
  R-DIDs. It now has something to disclose, which was #1067's third point, but
  the construction itself waits on #9 as the ZKP task force has said.
- **No client.** `openvtc` still has to mint the VPC and rename its
  `persona_did` field, which is what made the word ambiguous in the first
  place.
- **No Trust Task spec.** `vtc/relationships/persona/0.1` is bound ahead of its
  publication in the upstream registry, and recorded as such in
  `UNPUBLISHED_CANONICAL_OK`. Authoring a payload schema now would mean
  encoding this request-level binding as if #9 were closed.

## Test matrix

| Case | Expected |
|---|---|
| VPC + valid authorization on a pairwise edge | 200, `personaDid` on the graph edge |
| Same P-DID on two edges under two R-DIDs | 200 both; graph groups them, issuers stay distinct |
| Authorization signed by a key other than the edge's issuer | 403 |
| No authorization, pairwise edge | 403 |
| Authorization naming a different edge | 403 |
| A VRC posted to the persona endpoint | 400 |
| VPC naming a counterparty other than the edge's subject | 400 |
| Detach | 200, persona gone, edge intact |
| Attach authorization replayed as a detach | 403 |
| Unknown edge | 404 |
| Stored row and audit envelopes | contain no `sessionId` and no membership DID |
