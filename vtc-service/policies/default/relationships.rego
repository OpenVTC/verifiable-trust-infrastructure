# Default `relationships` policy — store iff the caller is a
# current member of this community.
#
# A VRC names two parties (issuer + subject). Under the pairwise
# form neither is resolvable to a member, and is not meant to be:
# DTG Credentials §Community-Anchored ZKP is explicit that
# "community membership is not a precondition for issuing,
# holding, or presenting a VRC". So the question this policy asks
# is not "are both parties members?" but "is this publication
# authorized by a member of this community?".
#
# The handler answers that before the policy runs — the session
# is authenticated, and for a pairwise VRC the caller has proven
# control of the issuing DID. What is left for the policy is the
# membership check and whatever the community wants to add.
#
# ## Identifier form
#
# `identifier_form` is how the credential identifies its parties:
#
#   "attributed" — issued under the member's membership DID. The
#     edge names them; the graph is correlatable by design. A
#     public community (an open-source project, say) reasonably
#     wants this, and DTG Credentials permits it directly: "the
#     member may also assert the M-DID in any VRC where the
#     member wishes to assert a VTC relationship".
#
#   "pairwise" — issued under a relationship DID unique to one
#     counterparty. DTG Credentials RECOMMENDS this, and requires
#     the uniqueness the handler enforces.
#
# Both are permanent, supported forms. **The member chooses per
# relationship and this default policy accepts either.** The
# community *declares* which it expects in the community profile
# (`relationshipIdentifierDefault`), which clients read before
# minting — a declaration, not a gate.
#
# A community that wants to *require* one form enforces it here.
# To require attributed edges, replace the two rules below with:
#
#   allow if {
#     input.action == "publish"
#     input.authenticated_member.is_current
#     input.identifier_form == "attributed"
#   }
#
# Input shape (enriched by the handler):
#   { vrc,
#     authenticated_member: { did, is_current },
#     identifier_form: "attributed" | "pairwise",
#     issuer:  { did, is_current },
#     subject: { did, is_current },
#     action }
#
# `is_current` on the credential'"'"'s own parties is meaningful only
# for the attributed form; under pairwise identifiers neither
# party resolves to a member, and is not meant to.

package vtc.relationships

import rego.v1

default allow := false

# Pairwise: membership comes from the session; control of the
# relationship DID was proven to the handler, which also enforced
# that the DID is unique to this counterparty.
allow if {
	input.action == "publish"
	input.authenticated_member.is_current
	input.identifier_form == "pairwise"
}

# Attributed: the member issues under their own membership DID, so
# both named parties are community members and the historical
# both-parties-current check still applies.
allow if {
	input.action == "publish"
	input.identifier_form == "attributed"
	input.issuer.is_current
	input.subject.is_current
}
