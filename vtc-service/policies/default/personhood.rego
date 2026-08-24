# Default `personhood` policy — minimal-allow (Phase 4 M4.2).
#
# This is the **default** personhood evaluator. Operators
# replace it via `POST /v1/policies` + `POST /v1/policies/{id}/activate`
# to express richer evidence requirements (proof-of-personhood,
# multi-witness, biometric attestation, etc).
#
# ## Minimal-allow semantics
#
# The policy returns `allow == true` on either of two evidence
# shapes:
#
#   - a `WitnessCredential` from a non-empty issuer — a third
#     party vouching for the applicant; or
#   - an `IdentityVerification` endorsement **this community
#     itself issued to this applicant** — the in-person vetting
#     ceremony, where an administrator met the person and issued
#     the record to the DID they presented.
#
# Both are intentionally permissive — operators with stricter
# requirements upload a custom rego. The default lets the
# workspace's integration tests exercise the assert flow without
# operator setup.
#
# ## Input shape
#
# Driven from two call sites:
#
# 1. **Assert endpoint** (M4.3):
#    {
#      "applicant_did": "<member-did>",
#      "community_did": "<this community's C-DID>",
#      "vp_claims": {
#        "holder": "<member-did>",
#        "credentials": [ { "type": [...], "issuer": "<did>", ... }, ... ]
#      }
#    }
#
# 2. **Renewal-time re-evaluation** (M4.2.2):
#    {
#      "applicant_did": "<did>",
#      "community_did": "<this community's C-DID>",
#      "current_personhood": <bool>,
#      "asserted_at_seconds_ago": <int | null>,
#      "vp_claims": { "holder": "<did>", "credentials": [] }
#    }
#
#    The default re-evaluator preserves an existing
#    `current_personhood == true` — assertions don't lapse on
#    renewal under the default policy. Operators wanting
#    time-based expiry override `asserted_within_max_age`.

package vtc.personhood

import rego.v1

# Default-deny when no rule below fires.
default allow := false

# `asserted` mirrors `allow` for legacy call sites that read
# the old name.
asserted if allow

# ── Assert path (default minimal-allow) ────────────────────

# Allow when the applicant presents at least one
# `WitnessCredential` from a non-empty issuer.
allow if {
	some i
	cred := input.vp_claims.credentials[i]
	"WitnessCredential" in cred.type
	cred.issuer != ""
}

# ── In-person vetting by this community ────────────────────

# Allow when the applicant presents an endorsement **this community
# itself issued** recording that a human verified their identity.
#
# This is the in-person ceremony: an administrator meets the person,
# satisfies themselves the DID in front of them is theirs, and issues
# an identity-verification endorsement to that DID
# (`vtc/endorsements/issue/0.1`). The member later presents it here,
# over a single-use challenge, and the community's own signature on the
# credential is the evidence.
#
# Three conditions, and each one is load-bearing:
#
#   1. `issuer == input.community_did` — otherwise any issuer anywhere
#      could mint a credential whose endorsement type happens to read
#      `IdentityVerification` and unlock personhood in this community.
#      The endorsement type is a *name*, not an authority.
#   2. `credentialSubject.id == input.applicant_did` — the credential
#      names the party asserting, not somebody else. The route's
#      holder-match already binds the presenter; this binds the
#      credential, so a member cannot present a vetting record issued
#      about another member.
#   3. the endorsement type is the identity-verification one — a role
#      VEC is also community-issued and also names the member, and must
#      not double as proof that someone met them.
#
# DTG Credentials §Identity Verification Credentials puts this squarely
# in scope: "IDVCs are **not** DTGCredential subtypes — any W3C VC
# satisfying a VTC/VTN's identity-proofing requirements". A community
# acting as its own identity-verification provider is the simplest case
# of that, and it needs no new credential type and no new Trust Task.
#
# Note what this rule does **not** establish. DTG Credentials
# §Personhood Credentials requires governance enforcing *both* real
# human personhood *and* exactly one membership per person. This rule
# is evidence for the first only — uniqueness is not something a
# credential presented by its own subject can demonstrate.
#
# The second half is **not** a policy rule and cannot be written as one.
# It lives at the route, gated on the community's own
# `personhood.singleMembership` declaration, and works by claiming a
# pseudonym issued by a provider the community published in
# `personhood.acceptedIdvps`. A rego rule cannot do it: deciding whether
# a pseudonym is already spoken for is a read against stored state, which
# a policy evaluated over one presentation has no access to.
#
# So a community wanting one-membership-per-person turns that flag on
# rather than editing this file — see
# `docs/03-vtc/personhood-and-graph.md`.
allow if {
	some i
	cred := input.vp_claims.credentials[i]
	"EndorsementCredential" in cred.type
	cred.issuer == input.community_did
	cred.credentialSubject.id == input.applicant_did
	cred.credentialSubject.endorsement.type == "IdentityVerification"
}

# ── Renewal-time re-eval (preserve existing assertion) ─────

# When renewal sees a member whose flag is already `true`,
# preserve it. Operators wanting time-based expiry override
# this rule with their own age check.
allow if {
	input.current_personhood == true
}
