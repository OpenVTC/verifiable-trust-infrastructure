# Demo plan: automatic VTC join via Verifiable Invitation Credential (VIC)

## Demo narrative

An applicant runs **OpenVTC** (`~/devel/openvtc`), holding a **VIC**. They present it
inside a Verifiable Presentation **over DIDComm** to the VTC's join endpoint. The VTC
**verifies the VIC**, checks its **trust policy** ("do I trust this invitation's
issuer?"), and **auto-admits with no human approval** — issuing the VMC + role VEC back
to the applicant inline.

Two phases (per decision):
- **M1 — VTC self-issued VIC.** Issuer DID == the community's own DID → trivially trusted.
- **M2 — 3rd-party issued VIC.** An external issuer mints the VIC; the VTC is configured
  to trust that issuer DID.

Transport: **DIDComm first** (authcrypt; sender auth intrinsic). REST is a later add.

---

## What already exists (reuse, do not rebuild)

**VTC (`vtc-service`)**
- VIC *issuance* fully built — `credentials/invitation.rs` (`issue_invitation`, 7-day
  default, revocation status-list slot) + `credentials/dtg.rs` (`DTGCredential::new_vic`).
- Join over DIDComm — `join/orchestrate.rs::submit_inner(..., binding: None, ...)`;
  authcrypt envelope authenticates the sender.
- Policy engine — embedded `regorus`, purpose-gated `join.rego` (`policy/`).
- **Auto-admit already works** — `Verdict::Allow` → `EffectPlan::Admit` issues VMC + role
  VEC inline (`join/orchestrate.rs::realize_join_verdict`).
- `Facts.evidence.invitation: Option<Invitation { verified, issuer, issuer_role, scopes,
  consumed }>` already defined (`ceremony/facts.rs`).
- Verify-gate already rejects an unverified invitation (`ceremony/verify.rs:115`).

**OpenVTC (`~/devel/openvtc`)**
- Holds `did:webvh` personas, stores `DTGCredential`s per community
  (`openvtc-core/src/config/account.rs`).
- Speaks DIDComm fluently via ATM/authcrypt (`openvtc-core/src/lib.rs::pack_and_send`).
- 10-step join flow that already submits `JOIN_REQUEST_SUBMIT` over DIDComm
  (`openvtc/src/state_handler/join_flow.rs`, `openvtc-core/src/join.rs`).
- Depends on `vta-sdk` 0.12 + `dtg-credentials` + `affinidi-tdk` / `affinidi-data-integrity`.

**dtg-credentials** — `new_vic` constructor (fixes `@context`, `type`, subject shape).

---

## The delta — what's missing

The join path **hardcodes `evidence.invitation: None`** at
`join/orchestrate.rs:328`. A presented VIC is **never extracted, never verified, never
consumed**, the shipped `policies/default/join.rego` **doesn't reference invitations**, and
OpenVTC submits a **stub VP** (`join_flow.rs:658`). So the work is *wiring existing pieces
together*, not a ground-up build.

### A. VTC-side: verify + consume + trust the VIC (core)

1. **VIC extraction + verification** — new module
   `vtc-service/src/credentials/invitation_verify.rs`.
   - Extract the `InvitationCredential` from the submitted VP JSON.
   - Verify the Data-Integrity proof (`eddsa-jcs-2022`) against the **resolved issuer DID**,
     mirroring the reference typestate `verify_vta_authorization_credential`
     (`vta-sdk/src/provision_integration/credential.rs:204`).
   - Return a **`VerifiedInvitation`** typestate (CLAUDE.md typestate discipline).
   - Checks: type contains `InvitationCredential`; proof valid; `credentialSubject.id ==
     applicant_did` (holder binding); `validUntil`/`validFrom` window; revocation
     status-list bit not set; not already consumed (see A4).
   - VIC is a **Data-Integrity VC, not SD-JWT** — use `affinidi-data-integrity`, not the
     `present.rs` SD-JWT path.

2. **Issuer-trust resolution** — decide `Invitation.verified` *and* trust:
   - **M1**: issuer DID == community DID → trusted.
   - **M2**: issuer DID ∈ operator-configured trusted-invitation-issuers (see section B).
   - Surface as `Invitation.issuer_trusted` (new field, mirroring `Credential.issuer_trusted`
     already in `facts.rs`) so the policy can branch on it.

3. **Populate `Facts.evidence.invitation`** — replace the hardcoded `None` at
   `join/orchestrate.rs:328` with the `VerifiedInvitation` mapped into the `Invitation`
   facts struct. This is the single highest-leverage change.

4. **Single-use consumption** — new keyspace `consumed_invitations:<vic-id>`.
   - Check during verification (A1) → reject if present.
   - Write on `Verdict::Allow` in `realize_join_verdict` (atomic with the admit effects).

5. **Demo join policy** — ship a `join.rego` that auto-admits on a valid invitation:
   ```rego
   has_valid_invitation if {
       input.evidence.invitation.verified
       input.evidence.invitation.issuer_trusted
       not input.evidence.invitation.consumed
   }
   decision := {"effect": "allow", "with": {"role": "member"}} if { has_valid_invitation }
   ```
   The example already exists in `docs/05-design-notes/examples/join.rego`; promote it into a
   loadable policy (and optionally make it the demo default).

6. *(Optional)* **Manifest advertises invitation acceptance** — extend
   `routes/join_requests/manifest.rs` so an applicant tool can discover "this community
   auto-admits on a valid VIC."

### B. Trusted-issuer config — the "policy/config the VTC trusts" bullet

- **M1**: no config needed — community self-trust is implicit (issuer == community DID).
- **M2**: operator-managed **trusted-invitation-issuers** store + `cnm` CLI command
  (e.g. `cnm policies trusted-issuers add --did <issuer-did> --kind invitation`).
  Surfaced into Facts as `issuer_trusted` (A2). Prefer reusing the existing trust-registry /
  TRQP recognition path (`vtc-service/src/credentials/recognition.rs`) over a brand-new
  allowlist, if it fits — otherwise a small fjall-backed allowlist keyspace.

### C-pre. Where the VIC lives: the VTA credential vault

The VTA already has a purpose-built **credential vault** (`vta-service/src/vault/`)
designed to hold "credentials a holder holds (invitations, memberships, roles,
endorsements …)" with a first-class `CredentialPurpose::Invite` (`vault/model.rs:98`),
indexing by `{type, community_did, issuer_did, purpose, status}`, encryption-at-rest,
and `storage`/`receive`/`query`/`present`/`mint` layers already implemented.

- **Holder/recipient copy → VTA vault.** This is the architectural home for the
  applicant's received VIC. OpenVTC should store-on-receipt and load-at-join from
  the VTA vault rather than only its local `config.account.credentials` map.
- **Caveat:** the vault is a *library data plane* today — there are **no vault
  HTTP/DIDComm routes and no vta-sdk client method** yet. Driving it over the wire
  needs a thin route + SDK method (new task #8). For a first demo, OpenVTC can use
  its local credential map and we wire the VTA vault as the immediate follow-up —
  same join flow either way.
- **Issuer copy is NOT the vault's job** (the vault holds *held* creds). Issuer
  bookkeeping stays at the issuer: for M1 that's the VTC's revocation status-list
  slot + the new consumption store; a 3rd-party VTA issuer (M2) keeps its own
  issuance log via the `mint` layer.

### C. OpenVTC applicant-side: present a real VP with the VIC

1. **VP builder** — new `openvtc-core/src/presentation.rs`: build a signed
   `VerifiablePresentation` embedding the held VIC, signed by the persona key
   (`affinidi-tdk` / `affinidi-data-integrity`).
2. **Wire into join** — replace the stub VP at `openvtc/src/state_handler/join_flow.rs:658`
   with a call to the builder.
3. **Import a VIC** — a way to load a VIC into OpenVTC's per-community credential store
   for the demo (CLI/TUI import command), since OpenVTC doesn't receive VICs yet.

### D. VIC issuance + delivery for the demo

- **M1**: `cnm` command to issue a VIC for an applicant DID and deliver it (sealed bundle or
  file) → applicant imports into OpenVTC (C3). VIC issuance already exists; this adds the
  operator-facing surface + delivery.
- **M2**: a 3rd-party issuer mints the VIC. Cheapest demo path: a small standalone issuer
  using `dtg-credentials::new_vic` with its own Ed25519 key (or a second VTC instance).
  Register that issuer DID as trusted via B.

### E. Glue, tests, demo runbook

- E2E integration test: issue VIC → present over DIDComm → auto-admit (VMC+VEC returned) →
  **re-use rejected** (consumption) → **untrusted issuer rejected** (M2).
- Demo runbook: spin VTC, issue VIC, run OpenVTC, join, show admitted membership.

---

## Milestones

- **M1 (self-issued, DIDComm, demoable):** A1–A5, C1–C3, D(M1), E. Smallest path to a
  working "present VIC → auto-join" demo.
- **M2 (3rd-party trusted issuer):** B(M2), A2 trust branch, D(M2), plus the untrusted-issuer
  test. Adds the full "and/or 3rd party" story.
- **Optional polish:** A6 (manifest discovery), REST transport parity.

## Key design decisions (recommended defaults)

- VIC verification uses **Data-Integrity (`eddsa-jcs-2022`)**, typestate `VerifiedInvitation`,
  modeled on `verify_vta_authorization_credential`.
- **Holder binding** enforced: `VIC.credentialSubject.id == applicant_did`.
- **Single-use** via `consumed_invitations:<vic-id>` keyspace, written atomically on admit.
- **Revocation** honored by checking the VIC's status-list bit at verify time.
- Trust is **policy-driven** (Rego), fed by an `issuer_trusted` fact — no hardcoded issuer
  list in service code.
