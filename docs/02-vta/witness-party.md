# The VTA as a witnessed party

**Witnessing** is a third party observing a relationship exchange and attesting, in
a Verifiable Witness Credential (VWC), that it took place. The participating party
opens a session with the witness under its relationship DID
(`witness/session/0.2`), presents its relationship credential bound to the
session's challenge (`witness/session/submit/0.2`), and receives the VWC.

A principal whose keys and credentials are held by a VTA cannot do that from a
client that holds neither. The `vta/witness/*` tasks make the VTA the party for its
principal: it **builds and signs every document as the relationship DID**, and
verifies and stores what the witness returns. The **client carries the documents**:
it sends each one to the witness *from the relationship DID* and hands each answer
back. The VTA never contacts the witness.

- Specifications: `vta/witness/{open,present,accept}/0.2` in the Trust Task
  registry, with the family's rules in `vta/_shared/0.6/CONVENTIONS.md`
  (trustoverip/dtgwg-trust-tasks-tf #779, #799). Only 0.2 is served: the 0.1
  tasks conducted the session under `witness/session/0.1` and carried the member
  presentation in a vendor extension, which 0.2 replaces with a spec member. A
  session is continued only by the version that opened it. `vta/witness/request/0.1`
  is retired and was never implemented.
- Design: [the witness as a host service](../05-design-notes/witness-host-service.md)
  §3.5; the witness itself is [`vti-witness`](../06-witness/README.md).
- Code: `vta-service/src/operations/witness.rs` (the engine) and
  `vta-service/src/trust_tasks/witness.rs` (the tasks).

## Why the client carries the messages

A witness checks that the transport-proven sender of each document is its
`issuer`, and replies to that sender. The relationship DID's one connection to its
mediator belongs to whoever holds the relationship — normally the client, which
already speaks for it — and the mediator allows one websocket per DID. A VTA that
sent as the relationship DID would have to take that connection over, and would
never see the witness's replies, which go to the client's socket. So the VTA does
what only it can (sign as the relationship DID, read the vault, verify) and the
client does what only it can (speak on the relationship DID's connection).

## The round

| Step | Who | Task |
|---|---|---|
| 1 | client → VTA | `vta/witness/open` — the VTA checks custody and the credentials, opens a session record, and returns the `witness/session` document signed as the relationship DID |
| 2 | client → witness | that document, sent from the relationship DID, unaltered |
| 3 | client → VTA | `vta/witness/present` — hand back the witness's session `#response`; the VTA verifies it is the witness's for this session, builds the presentations bound to its challenge and domain, and returns the signed `witness/session/submit` document |
| 4 | client → witness | that document, sent from the relationship DID; discard it once answered |
| 5 | client → VTA | `vta/witness/accept` — hand back the witness's submit `#response`; the VTA verifies the VWC and stores it with its evidence |

`vta/witness/accept` answers with `evidence: { session, outcome }`, the outcome
evidence of the session. Keep it with the VWC: a VTC counts a VWC only with that
evidence beside it, in `vtc/members/personhood/assert/0.2`'s
`outcomeEvidence`, and only from a witness it has listed as trusted ([trusted witnesses](../03-vtc/trusted-witnesses.md)).

## Reading back what was stored

`vta/witness/list/0.1` (trust-tasks-tf #800) returns the VWCs `accept` stored, each
with its evidence **exactly as stored** — never rebuilt or re-signed — so a client
that stopped before recording `accept`'s answer, or a second device of the same
principal, can rebuild its record of a witnessing at any time.

- **Filters**: `relationshipDid` (the VWC's subject) and `witness` (its issuer).
  Filter by `relationshipDid` when one relationship's are wanted: a listing of
  everything is a map of the principal's witnessed relationships.
- **Scope**: only active vault entries `accept` stored (under any version), in a
  context the caller may act in. A DID this VTA does not hold and one held where
  the caller cannot act answer the same empty page, never a refusal.
- **Paging**: oldest first (`acceptedAt`, then `credentialId`), `pageSize` 1–100
  (default 100), `truncated` with an opaque `cursor` to continue; a cursor the VTA
  cannot honour is `vta/witness/list:cursorInvalid` — list again from the start.
- Gated on `witness-request` like the rest of the family; audited with the caller
  and the count.

A refusal from the witness (`witness/session:refused`, `challengeMismatch`,
`presentationInvalid`) ends the session at the client and is not handed back. The
VTA's record simply expires; open a new session to try again.

```rust
use trust_tasks_rs::specs::vta::witness::{accept, open, present};

let opened = vta.witness_open(&open::v0_2::Payload::builder()
    .witness(witness_did)
    .relationship_did(relationship_did)
    .counterparty_did(counterparty_did)
    .relationship_thread_id(thread_id)
    .relationship_credential_id("vrc-alice-to-bob")
    .try_into()?).await?;
let answer = send_from_relationship_did(&opened.document).await?;   // the client's own socket
let submit = vta.witness_present(&present::v0_2::Payload::builder()
    .session_id(opened.session_id.clone())
    .response(answer)
    .try_into()?).await?;
let outcome = send_from_relationship_did(&submit.document).await?;
let stored = vta.witness_accept(&accept::v0_2::Payload::builder()
    .session_id(opened.session_id)
    .response(outcome)
    .try_into()?).await?;
```

There is no `pnm` command: `pnm` holds no relationship DID's connection, so it has
nothing to carry the documents on. The carrier is the client that holds the
relationship — a wallet or agent.

## Clients

- **Rust**: `VtaClient::witness_{open,present,accept,list}` (`vta_sdk::client`),
  taking and returning the generated `trust_tasks_rs::specs::vta::witness` types, as
  above.
- **Mobile**: `vta_mobile_core::witness`. The wallet's round:

  | Step | Engine call |
  |---|---|
  | open | `build_witness_task(env, WitnessTask::Open, payload, signer)` → the VTA; `parse_witness_response` → `{sessionId, document, expiresAt}` |
  | route | `resolve_witness_route(relationship_did, witness_did)` — TSP, else DIDComm, by service `type` in both DID documents; never REST |
  | carry | `check_witness_document(document, WitnessDocument::Session, sessionId, relationship_did, witness_did)`, then send it on the relationship DID's session (`TspMediatorSession` to the witness through its mediator, or a `MediatorSession` whose peer is the witness) |
  | answer | `classify_witness_reply(document, reply, witness_did)` — verified as the witness's, then `Answered { response_json }` or `Refused { refusal, code, … }` |
  | present | `WitnessTask::Present` with `{sessionId, response}` → the submit `document`; check it (`WitnessDocument::Submit`), carry it, classify the answer, **discard the submit document** |
  | accept | `WitnessTask::Accept` with `{sessionId, response}` → `{credentialId, witness, vwcDigestMultibase, evidence}` |
  | list | `WitnessTask::List` with `{relationshipDid?, witness?, pageSize?, cursor?}` → `{witnessings, truncated, cursor?}`, to rebuild a lost record |

  `Refused` carries the witness's code — `SessionRefused` (`witness/session:refused`:
  this witness will not witness the exchange), `ChallengeMismatch` (the session is
  spent or gone: open a new one), `PresentationInvalid` (the witness did not accept
  the credentials), `Other`. A refusal is never handed back to the VTA. The whole
  round is exercised against the real tasks and the real witness core in
  `vta-mobile-core/tests/witness_e2e.rs`.

  A relationship DID is usually a `did:peer:2`, whose signing key `V` and
  key-agreement key `E` are independent, so the session is opened with
  `connect_with_secrets` (on `MediatorSession` or `TspMediatorSession`) and the
  DID's keys as `HolderSecret`s, one per verification method — not `connect`,
  which derives both keys from one `did:key` seed. The engine checks each secret
  against the resolved document before any socket opens (every key is the one
  published at its id; an Ed25519 `authentication` key and an X25519
  `keyAgreement` key are both present), so a wrong key is refused by name rather
  than as a mediator authentication failure.

## What the VTA checks

**At open**, before the witness learns anything, so a session that cannot succeed
fails before it exists:

1. The caller holds `witness-request`, and this VTA holds a key of the
   relationship DID — and of the member DID, when named — in a context the caller
   acts in. Otherwise `permissionDenied`, the same whether the DID is unknown here
   or held for another context.
2. The relationship DID, the counterparty and the witness are three different DIDs,
   and a member DID is none of them (`malformedRequest`).
3. The credentials exist, are active and in the caller's contexts (`notFound`), and
   fit their roles (`credentialMismatch`): the relationship credential is a
   `RelationshipCredential` issued by the relationship DID naming the counterparty;
   the membership credential a community's `MembershipCredential` naming the member
   DID (or the relationship DID, without the member link); both in their validity
   windows.
4. The witness resolves (`witnessUnresolvable`, retryable).

**At present**: the record is `opened` or `presented` in the caller's contexts, and
was opened at 0.2 (`sessionUnknown` otherwise); the handed-back document is the
witness's `witness/session/0.2#response`, issued by the session's witness, addressed to the
relationship DID, on the session's thread, under the witness's proof
(`responseInvalid` otherwise — a challenge the VTA cannot attribute to the witness
is one it will not sign over); the credentials bound at open are still there
(`notFound`) and byte-identical and in their windows (`credentialMismatch`).

**At accept**: the record is `presented`; the answer passes the same checks against
`witness/session/submit/0.2#response`; and the VWC verifies against the session
(`vwcInvalid`, nothing stored): issued by the session's witness under its
`assertionMethod` proof, `taskContext` the session id and `taskDigestMultibase` the
digest of the session document the record holds, subject the relationship DID and
`object.digestMultibase` the relationship credential presented, and
`vwcDigestMultibase` the digest of the VWC as received, proof included.

`sessionUnknown` is one answer for an unknown, expired, out-of-scope or wrong-state
session, so it says nothing about sessions the caller cannot see.

## The member link

A witness may witness only members of communities it serves, and a community's
membership credential names the member's own DID, not the pairwise relationship
DID. Name the member DID in `membership.memberDid` and the VTA builds a second
presentation, by that DID, bound to the same challenge and domain, in the submit
payload's own `memberPresentation` (`witness/session/submit/0.2`, *The member
presentation*). The witness learns which member is behind the relationship DID;
that is why the member DID is never read off the credential, only taken from the
caller. Name it only for a witness whose policy asks for membership evidence: a
witness that asks for none may ignore it, and the member DID would have been
disclosed for nothing.

A membership credential naming the relationship DID rides in the relationship
presentation and needs no member link.

```toml
[witness]
session_ttl_secs = 600                       # default; 60–3600
```

`member_link_witnesses`, which named the witnesses known to read the old vendor
extension, is gone with that extension; a configuration that still sets it loads,
with a startup warning that the key is unknown and ignored.

## Authorization

`witness-request` (registered upstream as `witnessRequest`), derived by `admin` and
`initiator`, never by `application`. It is **not `sign`**, and `sign` does not
satisfy it: the tasks sign only documents and presentations the VTA builds itself,
bound to one session, and they read and write the credential vault. Each signature
goes through the VTA's gated signing oracle as protocol-defined input, so the
context's signing policy and the caller's key filter still apply.

Witnessing discloses the principal's credentials, in full, to a third party the
caller names. A deployment that wants a human to agree first can say so with the
approvals model, as for any task:

```sh
pnm approvals require https://trusttasks.org/spec/vta/witness/present/0.2 \
    --consent --set owners --min 1
```

## What is kept

| Kept | Where | For how long |
|---|---|---|
| The session record — the session document as signed, the DIDs, the credential handles and digests, the state | `witness_sessions` (encrypted at rest; **not** backed up) | until accepted or expired (`session_ttl_secs`); a sweeper deletes expired records |
| The accepted stub — session id, handle, VWC digest | `witness_sessions` | until the record's expiry, so a repeated accept is answered again |
| The VWC, with the session document and the submit `#response` | the credential vault, in the relationship key's context, tags `witness:session` / `witness:outcome` | the credential's life (backed up) |
| Either presentation, the challenge | nowhere | — |
| An audit row per step: caller, context, session id, witness | the audit log | its retention |

No audit row names a member DID or carries a presentation.

## Retries

Every step is safe to repeat (`RetrySafe`): a repeated open leaves an unsent
session that expires; a repeated present builds a fresh submit document, and the
witness spends its challenge on the first it accepts; a repeated accept of the same
outcome is answered again and stores nothing new. Never resend a document **to the
witness** under a new `id` — that is a second request, not a retry.
