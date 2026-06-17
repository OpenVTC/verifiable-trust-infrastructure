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

## Not done (deliberately deferred)

- **#8 VTA credential-vault route + SDK** — so the holder's VIC lives in the VTA
  vault (`vta-service/src/vault/`, `CredentialPurpose::Invite`) instead of a file.
  The vault data plane exists; only the route + `vta-sdk` method are missing.
  Optional for this demo (the `--invitation` file path covers it).
- **M2 third-party trusted issuer** — the trust-resolution layer is already
  wired (`invitation_issuer_trusted` consults the registry); M2 just needs the
  operator-facing trusted-invitation-issuer config surfaced.
- Pre-binding a *mint-fresh* persona to the VIC subject (see §0).
