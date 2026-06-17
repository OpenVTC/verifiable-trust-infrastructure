# Demo runbook — automatic VTC join via Verifiable Invitation Credential (VIC)

What this demonstrates: a community issues an **invitation** to a prospective
member; the applicant presents it when joining and is **auto-admitted with no
manual approval**.

Two repos / two worktrees:
- **VTC** (community + admin UI): `verifiable-trust-infrastructure` worktree
  `vtc-vic-join` (branch `worktree-vtc-vic-join`).
- **OpenVTC** (applicant tool): `openvtc` worktree
  `.claude/worktrees/vic-join` (branch `vic-join`).

---

## 0. One important binding caveat (read first)

A VIC is **holder-bound**: its `credentialSubject.id` must equal the DID the
applicant presents at join time. OpenVTC's join flow mints a *fresh* `did:webvh`
persona by default, whose DID can't be known in advance — so a VIC pre-issued to
it won't match.

**For the demo, present a DID you already know:**
- Use OpenVTC's **"reuse existing persona"** path so the persona DID is fixed and
  known before you issue the VIC, **or**
- Issue the VIC to a `did:key` the applicant controls and presents.

(Improvement for later: let the applicant tell OpenVTC "join as <DID>" / use the
VIC subject as the persona to present, so mint-fresh can be pre-bound. Tracked as
follow-up.)

---

## 1. Start the VTC (community)

```bash
cd <vtc-vic-join worktree>
cargo run -p vtc-service    # first run: `vtc setup` to mint the community + admin
```

The default `join.rego` already auto-admits on a valid, trusted, unconsumed
invitation (`vtc-service/policies/default/join.rego`) — no policy upload needed.

## 2. Get the applicant's persona DID

In OpenVTC, create (or pick) the persona the applicant will present, and note its
DID (the reuse path shows existing persona DIDs).

## 3. Operator issues the VIC

**Admin UI:** open the admin console → **Invitations** → enter the applicant's
DID → **Issue invitation** → **Copy** or **Download .json** (QR shown when the
credential is small enough to scan). Save it as `vic.json`.

**Or via REST:**
```bash
curl -sS -X POST https://<vtc>/v1/invitations \
  -H "Authorization: Bearer <admin-token>" \
  -H "Trust-Task: https://trusttasks.org/openvtc/vtc/invitations/issue/1.0" \
  -H "Content-Type: application/json" \
  -d '{"subjectDid":"<applicant-did>","validityDays":7}' \
  | jq .vic > vic.json
```

Hand `vic.json` to the applicant out-of-band.

## 4. Applicant joins, presenting the VIC

```bash
cd <openvtc vic-join worktree>
cargo run -p openvtc -- --invitation /path/to/vic.json
```

In the TUI: start **Join a community**. The entry page shows
**"✓ Invitation credential loaded — it will be presented to the community."**
Enter the VTC's DID and choose **reuse** the persona the VIC was issued to.

The join submits over DIDComm with the VIC embedded in the VP. The VTC verifies
it (issuer signature, holder-binding, validity, revocation, issuer trust) and the
default policy **auto-admits** — the VMC + role VEC are issued and delivered back.

## 5. Confirm

- OpenVTC: the join completes as **approved/active** (not pending review).
- Admin UI → **Members**: the new member shows the **invitation badge**
  (ticket icon). Re-presenting the same VIC is refused (single-use ledger).

---

## What's wired (this work)

VTC (`vtc-vic-join` worktree):
- VIC verification at join (`credentials/invitation_verify.rs`), threaded into
  the join decision (`join/orchestrate.rs`), single-use `consumed_invitations`
  ledger, `Invitation.issuer_trusted` fact.
- Default `join.rego` auto-admit branch.
- `POST /v1/invitations` issuance route + admin-UI **Invitations** plugin
  (issue → copy/download/QR) + member "joined via invitation" badge.
- Tests: 9 verify unit + 3 policy + 2 E2E + 3 route — all green.

OpenVTC (`vic-join` worktree):
- `openvtc_core::join::build_join_vp` (embeds the VIC) + 2 unit tests.
- `--invitation <file>` CLI arg → threaded into the join flow, replacing the VP
  stub; entry-page indicator + submit-time progress message.

## VTA credential vault (the VIC can live in the VTA)

The holder's VIC can be stored in and retrieved from the VTA credential vault via
a Trust-Task slice (`vault/credentials/{receive,query,get}/0.1`):
- `vta-service/src/trust_tasks/cred_vault.rs` — receive (verify + store, resolving
  the issuer key), query (DCQL-shaped, no-enumeration), get (full body).
- `vta-sdk` client: `cred_vault_receive` / `cred_vault_query` / `cred_vault_get`.
- A stored VIC is findable by `purpose = invite` (inferred from its type).

OpenVTC could store a received VIC here and load it at join time instead of the
`--invitation <file>` path (a follow-up wiring on the OpenVTC side).

## Third-party issuers (M2) — "and/or a 3rd party"

A VIC issued by a **third party** (not the VTC itself) auto-admits when the
community **trusts that issuer**. Trust is resolved per-verify by
`invitation_issuer_trusted`:
- issuer == the community's own DID → trusted (M1, self-issued); else
- `registry.recognise(issuer)` → trusted iff the issuer is in the community's
  **trust registry / recognition graph** (M2).

So the operator path for M2 is the *existing* recognition mechanism: add the
third-party issuer's DID to the community's trust registry (the same surface used
for cross-community credential trust). No bespoke trusted-invitation-issuer
config — the recognition graph *is* the config. Proven by
`invitation_verify::tests::third_party_issuer_trusted_via_registry`.

Demo variant: issue the VIC from a standalone issuer (its own `did:key` +
`dtg-credentials::new_vic`), register that issuer DID as recognised, then join —
the applicant is auto-admitted exactly as in the self-issued flow.

## Not done (deliberately deferred)

- Pre-binding a *mint-fresh* persona to the VIC subject (see §0) — for now use
  the reuse-persona path so the presented DID matches the VIC subject.
- Wiring OpenVTC to load the VIC from the VTA credential vault (above) instead of
  the `--invitation <file>` path.
