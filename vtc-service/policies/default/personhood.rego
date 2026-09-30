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
#   - a witness statement — a DTG `StatementCredential` under the
#     predicate `https://registry.trustoverip.org/dtg/vsc/witnessed/1`
#     (a VWC) — from a non-empty issuer, whose digest the host has
#     bound to an edge this community holds — a third party vouching
#     for the applicant; or
#   - an `IdentityVerificationCredential` **this community itself
#     issued to this applicant** — the in-person vetting ceremony,
#     where an administrator met the person and issued the record to
#     the DID they presented. A plain W3C VC, deliberately not a DTG
#     credential.
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
#    Every `witnessed/1` statement entry also carries the host-computed
#    `"witness_binding": { "state": "bound" | "subjectMismatch" |
#    "unresolved" | "absent" | "malformed", "relationship_id": "<uuid>"
#    (bound and subjectMismatch only) }`. A statement under a predicate
#    the community does not accept never reaches this policy: the host
#    refuses the assertion first.
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

# Allow when the applicant presents at least one witness statement
# (`StatementCredential`, predicate `witnessed/1` — classified by the
# predicate, never by a type string) from a non-empty issuer **whose
# digest binds to an edge this community holds**.
#
# `witness_binding` is the host's verdict, not the presenter's: the
# daemon recomputes the VWC's `credentialSubject.object.digestMultibase`
# against every relationship credential it stores, comparing decoded
# digest bytes, checks the `witnessed/1` subject–object rule (the
# statement's subject is the issuer of the edge), and writes one of five
# states onto each witness entry (DTG Credentials Security
# Considerations 6, *Digest integrity* — without that recomputation a
# VWC is not evidence of which edge was witnessed):
#
#   - `bound`      — names an edge held here, issued by the statement's
#                    subject; carries `relationship_id`.
#   - `subjectMismatch` — names an edge held here that someone other than
#                    the statement's subject issued. Never evidence.
#   - `unresolved` — a well-formed digest naming no edge held here. Not
#                    forgery: a witness may attest an edge published on
#                    another community. Not accepted by this default,
#                    because this community cannot see what was
#                    witnessed; an operator who trusts foreign edges can
#                    accept it in a custom policy.
#   - `absent`     — no digest; the VWC witnesses nothing in particular.
#   - `malformed`  — a digest that is not a `sha2-256` multihash.
#
# Before the verdict existed this rule accepted any witness credential
# with a non-empty issuer (#1068).
allow if {
	some i
	cred := input.vp_claims.credentials[i]
	"StatementCredential" in cred.type
	cred.credentialSubject.predicate == "https://registry.trustoverip.org/dtg/vsc/witnessed/1"
	cred.issuer != ""
	cred.witness_binding.state == "bound"
}

# ── In-person vetting by this community ────────────────────

# Allow when the applicant presents an identity-verification credential
# **this community itself issued** recording that a human verified their
# identity.
#
# This is the in-person ceremony: an administrator meets the person,
# satisfies themselves the DID in front of them is theirs, and issues an
# `IdentityVerificationCredential` to that DID
# (`vtc/endorsements/issue/0.1` with `typeUri`
# `IdentityVerificationCredential`, the one reserved type that mints a
# plain W3C VC rather than a statement). The member later presents it
# here, over a single-use challenge, and the community's own signature on
# the credential is the evidence.
#
# Three conditions, and each one is load-bearing:
#
#   1. `issuer == input.community_did` — otherwise any issuer anywhere
#      could mint a credential whose type happens to read
#      `IdentityVerificationCredential` and unlock personhood in this
#      community. The type is a *name*, not an authority.
#   2. `credentialSubject.id == input.applicant_did` — the credential
#      names the party asserting, not somebody else. The route's
#      holder-match already binds the presenter; this binds the
#      credential, so a member cannot present a vetting record issued
#      about another member.
#   3. the type is the identity-verification one — a role VAC or a VMC
#      is also community-issued and also names the member, and must not
#      double as proof that someone met them.
#
# DTG Credentials §Identity Verification Credentials puts this squarely
# in scope: "IDVCs are **not** DTGCredential subtypes — any W3C VC
# satisfying a VTC/VTN's identity-proofing requirements". A community
# acting as its own identity-verification provider is the simplest case
# of that.
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
	"IdentityVerificationCredential" in cred.type
	not "DTGCredential" in cred.type
	cred.issuer == input.community_did
	cred.credentialSubject.id == input.applicant_did
}

# ── Renewal-time re-eval (preserve existing assertion) ─────

# When renewal sees a member whose flag is already `true`,
# preserve it. Operators wanting time-based expiry override
# this rule with their own age check.
allow if {
	input.current_personhood == true
}
