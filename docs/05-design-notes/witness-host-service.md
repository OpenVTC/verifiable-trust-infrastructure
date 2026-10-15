# The witness as a host service

Status: **accepted** (2026-10-15). Tracks #1068.

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
  VTA through `provision-integration` and a new built-in **`witness`** DID
  template. That template produces `did:webvh` with an Ed25519
  `authentication` + `assertionMethod` key, an X25519 `keyAgreement` key, and
  `#tsp` / `#didcomm` services pointing at a mediator DID. It has no `VTARest`.
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
  the submitter. Without one the submit is `presentationInvalid`, and no VWC is
  minted.

That keys eligibility to something an operator can name in advance, the
communities it serves. It costs the parties a disclosure: the witness learns
which community the party belongs to. The operator documentation says so. A
witness configured with no communities witnesses anyone who passes the cheap
checks; that is an explicit `communities = ["*"]` in configuration, never the
default.

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

- **The VTA as a participating party.** It opens a session with a chosen witness
  on behalf of its principal's relationship DID; submits a VP of the
  relationship credential plus the membership credential; and stores the
  returned VWC in the vault together with the session document and the
  `submit#response` (the outcome evidence the spec requires a holder to retain
  and ship). This is a Trust Task the VTA's client asks for, in the VTA's own
  surface.
- **The VTC** already verifies VWCs. It gains a configured list of witness DIDs
  it trusts, for its criteria to reference.
- **The `witness` DID template** ships with the other built-ins, so any operator
  can provision a witness from their VTA.

### 3.6 The correlators that remain (VTI-CMP-062)

| Correlator | Where it shows | Mitigation |
|---|---|---|
| The witness DID | Every VWC and session | Intended: the witness is public by design |
| Its mediator | The mediator sees the witness's sessions | Use a mediator other than the operator VTA's. Setup **warns** when they share one, naming it a possible correlation source; the operator may accept the risk |
| Its DID-log host | Anyone resolving the witness | Host the log apart from the operator's own domains (setup warns otherwise, as above) |
| Community membership | The witness, at submit (§3.3) | Inherent to community-keyed eligibility; documented |
| The attestation records | The witness operator | Kept only for revocation; no VP is kept |

## 4. Phasing

1. **P1 — the service skeleton.** The `witness` template; `vti-witness` setup
   (two-phase, VTA-provisioned, up to 10 identities); a mediator session per
   identity; the three-task dispatcher with discovery; the shared-mediator and
   shared-domain warnings.
2. **P2 — witnessing.** §3.2–§3.4, with storage (sessions excluded from backup;
   attestations kept), a sweeper, and an end-to-end test against the VTC's
   existing VWC verifier.
3. **P3 — the party side.** The VTA Trust Task that runs a witnessed session for
   its principal and stores the VWC with its evidence; the VTC's list of trusted
   witnesses. That is a new VTA task family, so its specification goes to
   dtgwg-trust-tasks-tf first.
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
