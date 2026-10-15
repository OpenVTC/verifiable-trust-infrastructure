# The witness as a host service

Status: **accepted** (2026-10-15). Tracks #1068.

## 0. The need

A **relationship credential** (VRC) records that two parties formed a
relationship: each issues one to the other. It is bilateral and self-asserted.
Anyone evaluating it later has only the two parties' word that the exchange
happened, when it happened, and that the parties are who they claim to be.

That word is not enough wherever the relationship itself is the evidence:

- **Personhood and Sybil resistance.** One person can mint any number of
  pairwise DIDs and issue relationship credentials between them, building a
  convincing trust graph out of nothing. A community deciding whether an
  applicant is a real, distinct person cannot tell a genuine relationship from a
  manufactured one by looking at the credentials alone.
  `vtc-service/policies/default/personhood.rego` already accepts a witness
  statement as personhood evidence for exactly this reason.
- **Admission and reputation.** A community that admits members on the strength
  of existing relationships ("vouched for by two members") needs to know that
  those vouches came from real exchanges, not from credentials a party issued to
  itself.
- **Disputes after the fact.** If a party later denies a relationship, or claims
  one that never happened, the two parties' own records are the only evidence,
  and they disagree.

A **witness** closes the gap: an **independent third party** observes the
exchange and attests that it took place, in a Verifiable Witness Credential
(VWC). The attestation is bound to the exact relationship credential it saw
(by digest) and to the exact session in which it saw it (by task context and
task digest). A verifier who trusts the witness then holds evidence that the
relationship was formed in a witnessed exchange, not merely asserted by the two
parties.

The value rests on two properties, which shape every decision below:

1. **Independence.** A witness that is one of the parties, or acts for one,
   attests nothing a verifier can rely on.
2. **Verifiability.** A verifier must be able to check that one recognisable
   witness attested this specific edge in this specific session.

### The gap this note closes

The verification side already exists. `dtg-credentials` 0.13 builds and binds a
VWC, `vtc-service/src/credentials/witness.rs` verifies one against the edges a
community holds, and the personhood policy reasons over the result. **Nothing in
the workspace can act as a witness**, so no VWC is ever issued, and every
policy that accepts one is waiting on evidence that cannot yet exist (#1068,
audit finding F8).

## 1. What is being decided

`witness/session/0.1` and `witness/session/submit/0.1` define a **witness**. It
opens a session for a participating party, verifies that party's presentation of
its relationship credential, and issues a Verifiable Witness Credential (VWC). A
VWC is a DTG `StatementCredential` under the predicate
`https://registry.trustoverip.org/dtg/vsc/witnessed/1`.

The library and verifier halves already exist. `dtg-credentials` 0.13 builds a
VWC (`new_witnessed_vsc`, `with_task_citation`, `cites_task`), and
`vtc-service/src/credentials/witness.rs` verifies one. What is missing is a
witness. This note decides **what runs it and as whom**.

## 2. A witness is a host service, not a node role

The VTI specification places it there:

> **Host service** — An identifier-log host, **a witness**, a push gateway, or a
> room host — infrastructure a node depends on but does not embody.
> (`spec/02-architecture.md`, Conformance targets)

Three things follow, and together they rule out building the witness into the
VTA or the VTC:

- **Independence.** A witness attests that an exchange between *other* parties
  happened. If the parties' own VTA or community witnessed it, the attestation
  would be self-witnessing, and the VWC cannot reveal that to a verifier. A
  witness has value only as an independent third party.
- **Not everyone needs one.** Most VTAs and VTCs never witness anything. A
  witness built into them adds attack surface, configuration and an identity to
  every deployment so that a few can use it.
- **Its identity must not be the node's** (VTI-KEY-007). The witness is public by
  design: the session's `recipient`, declared `identifierScope: public`, and the
  VWC's `issuer`. A node's durable DID MUST NOT be used where correlation is not
  intended. A witness running as, or answering for, a VTA's DID would link
  everything it witnesses to everything else that node does.

A design that kept the witness inside the VTA as a separately keyed "hosted
identity" was considered and dropped. It met VTI-KEY-007, but only by making the
VTA receive and answer as additional DIDs, and it left the first two points
untouched.

## 3. The design

### 3.1 The service

A new binary, **`vti-witness`**, in this workspace (`publish = false`, like
`vtc-service`). It is deployed on its own, possibly by a different operator from
anyone it witnesses.

- **Its identity is provisioned, not self-minted.** It is set up like every other
  integration, with the two-phase `--setup-key-out` flow and a VTA grant (as for
  the VTC, mediator and did-hosting). Its DID and keys come from **its operator's**
  VTA through `provision-integration` and a new built-in **`dtg-witness`** DID
  template. That template produces `did:webvh` with an Ed25519
  `authentication` + `assertionMethod` key, an X25519 `keyAgreement` key, and
  `#tsp` / `#didcomm` services pointing at a mediator DID. It has no `VTARest`.
  It is named `dtg-witness`, not `witness`: `pnm did-templates init witness`
  is an existing alias for the did:webvh log witness's shape, `did-host-didcomm`.
  The operator's VTA is the key custodian. It is not a party to anything
  witnessed, and the witness never acts as it.
- **Up to 10 witness identities per service.** Each has its own DID, its own
  mediator session (one socket per DID, so no duelling) and its own policy.
  That gives one deployment separate witnesses per community or per purpose.
  The limit of 10 is enforced at configuration load.
- **Transport is TSP, then DIDComm.** v1 has no HTTPS door; HTTPS would need a
  hostname of its own to avoid a naming correlator. Mediator connection,
  readiness gate and reconnect reuse the shared pieces the VTC uses
  (`vti_common` / `vta_sdk` sessions), and honour the invariants in CLAUDE.md
  *Mediator connection*.
- **It serves exactly three tasks per identity:** `witness/session/0.1`,
  `witness/session/submit/0.1` and `trust-task-discovery`. Anything else is
  `unsupportedType`. There is no ACL and no administrator surface on the wire:
  the witness has no principal to administer it remotely, and its policy is the
  operator's configuration file.

### 3.2 Independence (conflict of interest)

A witness refuses to witness itself or its operator:

- **The parties.** A session whose `parties` include one of the service's own
  witness DIDs, or a DID listed in the operator's `[independence] exclude`
  (the operator's VTA DID, its community DIDs, its own relationship DIDs), is
  refused with `witness/session:refused`.
- **The credential.** At submit, a relationship credential *issued by*, or
  presented with membership evidence *issued by*, an excluded DID is refused the
  same way.

Pairwise relationship DIDs can still hide an operator's own participation, so
this is a floor, not a proof. The operator documentation says so, and says that
a deployment wanting stronger independence runs its witness under a separate
operator.

### 3.3 Who may be witnessed: eligibility on stable facts

Party DIDs are pairwise, so an allow-list of them names only parties the operator
already knows. Eligibility is therefore decided on **stable** facts, and in two
places:

- **When the session opens**, only cheap checks apply: the party is in
  `parties`, the independence rule, and caps (open sessions in total and per
  party, a session time-to-live). An optional exact-DID allow-list remains for
  closed deployments.
- **At submit**, the policy that matters. A witness identity names the
  **communities whose members it witnesses**, as VTC DIDs. The submitter's
  presentation must carry, beside the relationship credential, a valid
  membership credential (VMC) from one of those communities, whose subject is
  the submitter, or the member link of §3.3a, which bridges a VMC naming the
  member DID to the pairwise submitter. Without either the submit is
  `presentationInvalid`, and no VWC is minted.

That keys eligibility to something an operator can name in advance, the
communities it serves. It costs the parties a disclosure: the witness learns
which community the party belongs to. The operator documentation says so. A
witness configured with no communities witnesses anyone who passes the cheap
checks; that is an explicit `communities = ["*"]` in configuration, never the
default.

### 3.3a The member link: relationship DID to member DID

**The problem.** §3.3 asks for a VMC "whose subject is the submitter", but the
submitter is a **pairwise relationship DID** (VTI-KEY-005) and a community's VMC
names the **member's own DID**. They coincide only when a party relates from its
member DID, which VTI-KEY-007 discourages. Read literally, §3.3 would make
ordinary members unwitnessable.

**What is built (decided 2026-10-15: option 1).** The submit payload may carry a
second presentation, the **member presentation**, in the payload's vendor
extension `ext["org.openvtc.witness"].memberPresentation`
(`vti_witness::presentation::MEMBER_LINK_EXT`):

- a `VerifiablePresentation` whose `holder` is the member DID, signed for
  `authentication` by that DID;
- bound to the **same session**: its `nonce` (or `challenge`) is the session's
  challenge and its `domain` the session's domain. Only the party that opened the
  session received that challenge, so the member key has signed for this one
  session and cannot be replayed into another;
- carrying a VMC from one of the identity's communities that names the member
  DID. Every credential in it is checked as the relationship presentation's are:
  issuer proof, validity window, no excluded issuer.

The member DID may not be the session's other party (the counterparty's
membership does not make the submitter eligible) or an excluded DID. A failure is
`presentationInvalid` and leaves the session open. Any other member of the
`org.openvtc.witness` namespace is `malformedRequest`. A VMC naming the
relationship DID directly, in the relationship presentation, still counts. The
VWC names the relationship DID only; the member DID appears in no VWC, record or
log.

**Limitations and risks.**

| | What it means | Mitigation now |
|---|---|---|
| **Possession, not personhood** | The link proves that whoever holds the relationship key also held a member key *in this session*. It cannot prove they are one person: a member who signs a member presentation for someone else lends them their eligibility, and one member can lend it to many relationship DIDs. | None in the protocol. The witness does not count how often a member DID is used. A count would need the member DID stored, which would build the correlation table the link must not create. |
| **The witness learns the member DID** | The witness can link the pairwise relationship DID to the member's durable community identity, so it sees more than §3.3 alone discloses: *which member*, not just *which community*. | It is not stored or logged. The correlators table (§3.6) names it, and a deployment that will not disclose it uses `communities = ["*"]` or a witness it trusts with it. |
| **A vendor extension, not the spec** | `witness/session/submit/0.1` has no member for this, so the link rides `ext`. Another witness implementation will ignore it and refuse the submit for lack of membership. A verifier of the VWC cannot tell that eligibility rested on a link. | The namespace is closed (unknown members are refused), so it can be replaced cleanly. Standardising it is the first future option below. |
| **No revocation check** | A VMC revoked since issue still counts, as in §3.3 (P2 does not read `credentialStatus`). | Short VMC validity. Status checking is follow-up work. |
| **The VWC does not record eligibility** | A verifier sees *that* the witness attested the edge, not on what evidence it judged the party eligible. | Open question 4 to the credentials task force. |

**Options left for later.** Any of these can replace or sit beside the link.
None is built.

1. **Standardise the link upstream.** Add an optional `memberPresentation` (or a
   general `eligibility` presentation) to `witness/session/submit` in
   dtgwg-trust-tasks-tf, so any witness reads it and the `ext` carriage retires.
   This is the natural next step for the link itself.
2. **A pairwise membership credential.** The community issues the member a VMC,
   or a derived credential, naming the relationship DID, on request from the
   member's VTA. The witness then needs no link and never learns the member DID.
   This is the most private option, but needs a VTC issuance task (a spec first)
   and costs the community one issuance per relationship. That issuance shows the
   community the member's relationship DIDs, which moves the correlation from the
   witness to the community.
3. **A zero-knowledge membership proof.** The member proves "I hold a valid VMC
   from community C" without revealing the VMC or the member DID: a BBS+ derived
   proof, an anonymous credential, or the PCS hidden-vetting credentials
   (`docs/02-vta/pcs-engine.md`), which already give members unlinkable
   predicate proofs. This is the strongest privacy option, and the long-term
   answer to "no ZKP in v1".
4. **A DID-linkage assertion.** A standing credential, signed by the member DID,
   asserting control of the relationship DID, such as an `alsoKnownAs`-style
   link credential. It is reusable across sessions, so a party presents it
   without the member key being online. But a standing, replayable link is a
   durable correlator wherever it is shown, which the session-bound link avoids.
5. **Eligibility recorded in the VWC.** Record in `witnessContext` the kind of
   evidence checked (`membership`, `membership-linked`, `none`), so a verifier
   can weigh the attestation. This depends on the profile (question 4).
6. **Rate limits per member.** Bound how many relationship DIDs one member DID
   may link in a period, to blunt lending. This needs the member DID kept, at
   least as a keyed hash per witness, so it trades privacy against the lending
   risk and should be an operator choice, off by default.

### 3.4 The protocol

- **`witness/session/0.1`.** Apply the §7.2 pipeline, the checks of §3.2 and
  §3.3, mint a fresh 32-byte challenge and a `domain`, persist the session (the
  opener, `parties`, the challenge, the domain, the session document as
  received, and an expiry), and answer with a `#response` signed by the witness.
- **`witness/session/submit/0.1`.** Check the binding first: a live session's
  thread, its opener, and a VP proof bound to that challenge and domain. A
  failure is `challengeMismatch`. Then verify the VP (its proof, holder =
  submitter), the relationship credential (its issuer's proof, issuer =
  submitter), and the membership evidence (§3.3); any failure is
  `presentationInvalid`. Then build the VWC: `new_witnessed_vsc` (subject =
  submitter, object digest = the relationship credential's), then
  `with_task_citation(session document)`, `issuerScope: public`, signed with the
  witness's `assertionMethod` key. Answer `{ vwc, vwcDigestMultibase }` (the
  digest is over the VWC including its proof), signed by the witness. Consume the
  session, **discard the VP** (the spec's Retention section), and keep only an
  attestation record (VWC id, digest, submitter, session id, time) for later
  revocation.
- **Minting is automatic** once the checks pass. The checks are the witness's
  policy, and there is no human in the loop to wait for.

### 3.5 What the VTA and VTC do

They are **parties**, never witnesses:

- **The VTA as a participating party.** It acts for its principal's
  relationship DID with a chosen witness: it builds and signs the session
  document and the submission (a VP of the relationship credential, plus the
  membership evidence) as the relationship DID, and stores the returned VWC in
  the vault together with the session document and the `submit#response` (the
  outcome evidence the spec requires a holder to retain and ship). **The client
  carries the documents** (`vta/witness/{open,present,accept}`, trust-tasks-tf
  #779): the witness checks that each document's transport-proven sender is its
  issuer and replies to that sender, and the relationship DID's one mediator
  connection belongs to the client that holds the relationship. A first draft,
  `vta/witness/request/0.1`, had the VTA make both round trips itself; it would
  have needed a second socket for a DID the client already speaks for, and is
  retired unimplemented. Operator guide: [the VTA as a witnessed
  party](../02-vta/witness-party.md).
- **The VTC** already verifies VWCs. It keeps a configured list of the witness
  DIDs it trusts (`witnesses.trusted`, [trusted witnesses](../03-vtc/trusted-witnesses.md)),
  empty by default, and counts a VWC only from a listed witness and only with
  the outcome evidence of its session (VTI-CMP-023), carried beside the VWC in
  `ext["org.openvtc.witness"].outcomeEvidence`. The list is community
  configuration that criteria and policy read through the host's verdict, so it
  needs no Trust Task family of its own.
- **The `dtg-witness` DID template** ships with the other built-ins, so any operator
  can provision a witness from their VTA.

### 3.6 The correlators that remain (VTI-CMP-062)

| Correlator | Where it shows | Mitigation |
|---|---|---|
| The witness DID | Every VWC and session | Intended: the witness is public by design |
| Its mediator | The mediator sees the witness's sessions | Use a mediator other than the operator VTA's. Setup **warns** when they share one, naming it a possible correlation source; the operator may accept the risk |
| Its DID-log host | Anyone resolving the witness | Host the log apart from the operator's own domains (setup warns otherwise, as above) |
| Community membership | The witness, at submit (§3.3) | Inherent to community-keyed eligibility; documented |
| The member DID, under the member link | The witness, at submit (§3.3a) | Seen in full, linking the pairwise DID to the member's community identity; never stored or logged. Removed by options 2–3 of §3.3a |
| The attestation records | The witness operator | Kept only for revocation; no VP is kept |

## 4. Phasing

1. **P1 — the service skeleton.** The `dtg-witness` template; `vti-witness` setup
   (two-phase, VTA-provisioned, up to 10 identities); a mediator session per
   identity; the three-task dispatcher with discovery; the shared-mediator and
   shared-domain warnings.
2. **P2 — witnessing.** §3.2–§3.4, with storage (sessions excluded from backup;
   attestations kept), a sweeper, and an end-to-end test against the VTC's
   existing VWC verifier.
3. **P3 — the party side.** The VTA tasks that make it the party for its
   principal and store the VWC with its evidence (`vta/witness/*`,
   trust-tasks-tf #779 — done); the VTC's list of trusted witnesses and the
   outcome-evidence pairing (done; the join paths carry no evidence yet).
4. **Later.** VWC revocation through a status list.

No VTI specification change is expected: this implements the host-service role
the architecture already names. If review finds a requirement this conflicts
with, it goes in Appendix F before any code.

## 5. Decisions recorded (review of the first draft)

1. A witness sharing a mediator, or a DID-log domain, with its operator's VTA is
   **warned about as a possible correlation source**. It is not refused; the
   operator may accept the risk.
2. **TSP/DIDComm only** for v1; no HTTPS door.
3. **Multiple witness identities**, at most 10 per service.
4. Eligibility keys on **something more stable** than pairwise DIDs: the
   communities a witness serves (§3.3).
5. The witness is **a host service of its own**, not a role of the VTA or VTC
   (§2), because it must be independent and most deployments don't need it.

## 6. Resolved after review

1. **`vti-witness` lives in this workspace**, beside `vtc-service`, sharing
   `vti-common` and `vta-sdk` and covered by the same CI.
2. **What the witness sees depends on what it witnesses, and v1 has no
   zero-knowledge path.** The witness reads the presentation it is given in
   full: the relationship credential and, under §3.3, the membership evidence.
   The specification gives it no way to verify less (`vp` is an opaque object),
   and no ZKP presentation is implemented. A deployment therefore either
   **trusts the witness** with what it is shown, or designs a flow in which the
   witness adds value without seeing specifics: what is presented, and which
   eligibility evidence is asked for, are deployment decisions. The operator
   documentation states this plainly, and §3.3's community-membership check is
   the default policy, not a requirement the service imposes on every
   deployment. A witness may be configured with no membership requirement
   (`communities = ["*"]`), for a deployment that would rather trust the witness
   less with what it learns than gate who it serves.
