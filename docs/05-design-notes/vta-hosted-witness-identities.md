# Hosted witness identities: a VTA that witnesses without exposing itself

Status: **proposed** — for review before implementation. Tracks #1068.

## 1. What is being decided

A VTA should be able to act as a **witness** under `witness/session/0.1` and
`witness/session/submit/0.1`. It opens a session for a participating party,
verifies that party's presentation of its relationship credential, and issues a
Verifiable Witness Credential (VWC). A VWC is a DTG `StatementCredential` under
the predicate `https://registry.trustoverip.org/dtg/vsc/witnessed/1`.

The library and verifier halves already exist. `dtg-credentials` 0.13 builds a
VWC (`DTGCredential::new_witnessed_vsc`, `with_task_citation`, `cites_task`), and
`vtc-service/src/credentials/witness.rs` verifies one. What is missing is the
**witness**, and the hard part is not the cryptography. It is the question of
**which identifier witnesses**, because the specifications make that identifier
public and the VTA's own DID must not be it.

## 2. The constraints

From `witness/session/0.1` and `witness/session/submit/0.1`:

- **W1.** The witness is the session document's `recipient`, and declares
  `identifierScope: public`. It has to be recognisable, so a verifier can tell
  that one witness attested both halves of an exchange.
- **W2.** The VWC's `issuer` is that same `recipient`. A verifier pairing the
  evidence checks that the VWC issuer, the session `recipient` and the signer of
  the `submit#response` are one party (submit §"This response is the outcome
  evidence" item 2; SPEC §4.9.4 check 4).
- **W3.** The `#response` proofs are REQUIRED and are made by the witness.

From the VTI specification:

- **VTI-KEY-007.** A durable node identifier is publicly resolvable and
  inherently correlatable. A node MUST NOT use its durable identifier for
  interactions in which correlation of the parties is not intended.
- **VTI-KEY-005.** A node SHOULD use a distinct identifier for each relationship
  it holds.
- **VTI-TRN-026.** Routing identifiers SHOULD differ per relationship, so an
  intermediary cannot link two of a principal's contexts by routing alone.
- **VTI-CMP-062.** A deployment MUST be able to identify the durable correlators
  it introduces, including those from naming, routing, lookup and session
  management.

From this workspace:

- The dispatch spine refuses a document whose `recipient` is not the VTA's DID
  (`validate_basic(now, vta_did)` in `trust_tasks::dispatch_trust_task_core`).
- The VTA holds **one** mediator session, for its own DID. The mediator permits
  one websocket per DID, and that socket carries both DIDComm and TSP.

## 3. Options rejected

**A. The VTA's own DID witnesses.** This is the simplest option and breaks
VTI-KEY-007 outright. Every party the VTA witnesses, every verifier shown a VWC,
and every holder of the outcome evidence (which VTI-CMP-064 says discloses both
parties' identifiers) would learn the VTA's durable identifier. That links the
witnessing role to everything else the node does under that DID: its
administration, its own relationships, its DID-hosting and mediator
registrations, its audit-visible activity. The witness is public by design (W1),
but its link to the operator's node is not intended.

**B. The task is addressed to the VTA and names the witness DID inside it** (in
`ext`, or as `DID#key`). This was proposed as a way to keep a single receiving
identity. It fails twice:

1. *It breaks the pairing.* W2 requires the VWC issuer to equal the session
   `recipient` and the `#response` signer. If the VTA is the recipient and a
   different DID issues the VWC, the verifier's §4.9.4 pairing fails. The spec
   records that it agrees with §4.9.4 "only because a witness both answers the
   session and issues the VWC". Making the two differ is a spec change, and a
   weaker one, because the response proof then no longer attributes the
   witnessing to the witness.
2. *It does not hide the VTA.* The parties still address, encrypt to and route to
   the VTA's DID. Every party and every mediator on the path learns that this VTA
   is the witness behind the named DID. The correlation option A creates is
   still there, now with an extra hop.

## 4. Proposal: hosted identities

A **hosted identity** is a DID the VTA mints and custodies like any other, and
also **answers as**. It has its own DID document, its own transport services, its
own mediator session and its own keys. Nothing about it is derivable from the
VTA's DID, and the VTA's DID never appears in any document, route or response the
hosted identity's correspondents see.

A witness is the first kind of hosted identity. The mechanism is general on
purpose: it is the same thing VTI-KEY-005 asks for whenever a node needs a
per-relationship identifier.

### 4.1 Minting

- **A new built-in DID template, `witness`.** It produces `did:webvh` with an
  Ed25519 `authentication` + `assertionMethod` key, an X25519 `keyAgreement` key,
  and `#tsp` / `#didcomm` services whose endpoint is a **mediator DID**. It has no
  `VTARest`. The template takes the mediator as a variable, so an operator can
  put witnesses behind a different mediator from the VTA's own.
- **Each hosted identity has a context of its own** (for example
  `witness/<name>`). Key custody rule 6 then confines its keys to its own
  derivation base, and the ACL and audit see it as a separate scope.
- **Hosting the DID log apart from the VTA's.** The `did.jsonl` is published on a
  DID host and path the operator chooses. A witness log served from the VTA's own
  public URL (`/.well-known/did.jsonl` beside the VTA's) would be a naming
  correlator (VTI-CMP-062). The template refuses the VTA's own domain unless the
  operator explicitly opts in with `--allow-shared-domain`.

### 4.2 Receiving

- **One mediator session per hosted identity.** Each gets its own ATM profile and
  websocket, supervised exactly as `MessagingConnect` supervises the VTA's: gate
  on self-resolution, connect with retry, reconnect with backoff, and
  `graceful_shutdown` on every error path. This respects the one-socket-per-DID
  rule, because each DID is distinct (VTI-TRN-026).
- **Inbound frames carry the identity they arrived for.** The receive loop knows
  which profile delivered a frame. That transport recipient becomes the
  **identity of record** for the dispatch.

### 4.3 Dispatching

A document received for a hosted identity goes through the same spine, with
three differences:

1. **The recipient check is against the identity of record.** `validate_basic`
   takes the hosted identity's DID, not the VTA's, and the two must agree: a
   document delivered to the witness's socket but addressed to the VTA is
   refused, and so is the reverse.
2. **Only the identity's own tasks are served.** A hosted identity has a fixed
   task set. For a witness that is `witness/session/0.1`,
   `witness/session/submit/0.1` and `trust-task-discovery`. Anything else is
   refused with `unsupportedType`, the same answer a node that serves nothing
   else would give, so a probe cannot tell that a full VTA sits behind it.
3. **No ambient authority.** The sender is never looked up in the ACL. Every
   dispatch runs on the zero-authority claim (`ceremony_claims`), whoever sends
   it. Otherwise an administrator who sends to the witness DID would carry admin
   standing into it, and the witness would answer differently for an
   administrator than for a stranger. That difference would be a correlator, and
   it would also be ambient authority through a side door.

The witness acts under its **own, narrow authority**: an `Admin` claim scoped to
its own context and nothing else, used only to reach its signing key. This is the
model of `credential_exchange::own_authority`, narrowed from the whole VTA to one
context.

### 4.4 Answering

- **Every response the hosted identity sends is signed by its own key**:
  `#response`, `trust-task-error` and discovery alike, with the
  `authentication` verification method for transport-level proofs and
  `assertionMethod` for the VWC. Nothing it emits is signed by the VTA.
- **Discovery reveals only the identity's tasks.** It carries no VTA version
  string or build fingerprint, and none of the VTA's own discovery fields.

### 4.5 The correlators that remain (VTI-CMP-062)

The design removes the identifier link. It cannot remove all of these, so the
operator documentation must name each one:

| Correlator | Where it shows | Mitigation |
|---|---|---|
| The witness DID itself | Every VWC and session | Intended: the witness is public by design (W1) |
| Co-located mediator sessions (same source address and timing) | The mediator | Put hosted identities behind a different mediator from the VTA's own |
| DID-host location | Anyone resolving the witness DID | A separate domain or path (§4.1) |
| Response timing and behaviour | Probing correspondents | Fixed task set and uniform refusals (§4.3); not fully eliminable |
| The VTA's audit log | The operator only | Audit rows are keyed to the hosted identity's context |

## 5. The witness role

On top of a hosted witness identity:

- **Configuration.** Each witness identity has an enable flag (off by default),
  an **allow-list** of party DIDs it will witness (exact DIDs, or `*` for
  anyone), a session time-to-live, and caps on open sessions in total and per
  party. A party outside the allow-list gets `witness/session:refused`. While
  identities are declared in configuration it is config-and-restart; managing
  them through Trust Tasks is §7's follow-up.
- **`witness/session/0.1`.** Apply the §7.2 pipeline, then:
  1. Check that `issuer` is one of `parties` (Conformance item 2), and refuse
     with `witness/session:refused` if not.
  2. Check the allow-list and the caps.
  3. Mint a fresh 32-byte challenge and a `domain`, and persist the session:
     the opener, `parties`, the challenge, the domain, the session document as
     received (its task digest is what the VWC cites), and an expiry.
  4. Return the `#response` signed by the witness.
- **`witness/session/submit/0.1`.**
  1. Check the binding first. The submit must be on a live session's thread,
     from the party that opened it, with the VP's proof bound to that
     session's `challenge` and `domain`. A failure is `challengeMismatch`
     (Conformance items 2–3).
  2. Verify the VP: its Data Integrity proof, and that its holder is the
     submitter.
  3. Verify the relationship credential inside it: the issuer's proof, and that
     the credential's `issuer` is the submitter, because the profile binds each
     VWC to one direction of the edge.
  4. Any failure in steps 2–3 is `presentationInvalid`.
  5. Build the VWC with `new_witnessed_vsc(...)`. Set `credentialSubject.id` to
     the submitter and the object digest to the relationship credential's
     digest. Call `with_task_citation(session document)`, which sets
     `taskContext` and `taskDigestMultibase`. Set `issuerScope: public`, then
     sign with the witness's `assertionMethod` key.
  6. Return `{ vwc, vwcDigestMultibase }`, where the digest is over the VWC
     including its proof, signed by the witness.
  7. Consume the session (single use). Discard the VP, as the spec says
     (Retention). Keep only an **attestation record** (VWC id, digest, the
     submitter, the session id, the time) for a later revocation.
- **Minting is automatic** once these checks pass. An operator who wants a human
  in the loop can put an approvals rule on the submit task URI, provided
  approvals can apply to a zero-authority caller; that has to be confirmed
  during implementation.
- **Storage.** A `witness_sessions` keyspace is excluded from backup, because
  sessions live for minutes and the documents can be re-requested, and a minute
  sweeper reaps expired sessions. A `witness_attestations` keyspace is backed up,
  because revocation needs it.

## 6. Phasing

1. **P1 — hosted identities.** The `witness` template; minting and
   configuration; per-identity mediator sessions; identity-of-record dispatch
   with the fixed task set and zero-authority claims; responses signed by the
   identity; discovery. Tested with an identity whose only task is
   `trust-task-discovery`.
2. **P2 — the witness role** (§5) on a hosted witness identity.
3. **P3 — management and revocation.** Trust Tasks for managing hosted
   identities and their allow-lists. That is a new task family, so the spec goes
   upstream first (dtgwg-trust-tasks-tf). Also VWC revocation through a status
   list.

No VTI specification change is expected. This is VTI-KEY-005 and VTI-KEY-007
applied, not a divergence. If review finds a requirement this conflicts with, it
goes in Appendix F before any code.

## 7. Open questions for review

1. **Mediator.** A separate mediator for hosted identities is a deployment
   choice (§4.5). Should the VTA *require* it for a witness, or only warn when a
   witness shares the VTA's mediator?
2. **HTTPS.** The witness template advertises no REST endpoint, so witnessing is
   TSP/DIDComm only. Is that acceptable for v1? An HTTPS door would need a
   hostname of its own to avoid a naming correlator.
3. **One witness or many.** The design allows several witness identities (per
   community, per purpose). Should v1 support many, or one?
4. **The allow-list key.** It names party DIDs, which are pairwise, so operators
   can only allow-list parties they already know. Is `*` plus caps the
   realistic default once enabled, or should the list name something more
   stable, such as the issuer of the relationship credential's community? The
   community is only known at submit, not when the session opens.
