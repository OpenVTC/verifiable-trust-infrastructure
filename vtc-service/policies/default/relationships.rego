# Default `relationships` policy — store iff the caller is a
# current member and has proven control of the issuing DID.
#
# A VRC names two parties (issuer + subject). Under pairwise
# relationship DIDs — which DTG Credentials recommends, and
# requires to be unique per counterparty — neither party is
# resolvable to a community member, and is not meant to be.
# Asking "are both parties current members?" is therefore no
# longer answerable, and per DTG Credentials §Community-Anchored
# ZKP it is also the wrong question: "community membership is
# not a precondition for issuing, holding, or presenting a VRC".
#
# The question that *is* answerable, and is the one this policy
# was really asking, is whether the publication is authorized by
# a member of this community. That splits in two:
#
#   authenticated_member.is_current — the session belongs to a
#     live, ACL-listed, non-tombstoned member.
#   issuer.pop_verified — the caller proved control of the key
#     behind the VRC's `issuer` (see `verify_publish_authorization`),
#     so this is the issuer publishing its own edge rather than a
#     third party republishing one it was handed.
#
# The subject's consent to the edge is their own publication of
# the reciprocal VRC — the two-VRC DTG edge model — not this
# community's assertion that they exist.
#
# Input shape (enriched by the handler):
#   { vrc,
#     authenticated_member: { did, is_current },
#     issuer:  { did, pop_verified },
#     subject: { did },
#     issuer_member:  { did, is_current },   # deprecated
#     subject_member: { did, is_current },   # deprecated
#     action }
#
# `issuer_member` / `subject_member` remain in the input for
# operator-authored policies written against the old shape. For a
# pairwise VRC both report `is_current: false`, so an un-updated
# operator policy denies the publish. That is deliberate — this
# change does not silently loosen a policy someone wrote.

package vtc.relationships

import rego.v1

default allow := false

# Pairwise form: membership comes from the session, control of the
# issuing DID from the publish authorization.
allow if {
	input.action == "publish"
	input.authenticated_member.is_current
	input.issuer.pop_verified
}

# Deprecated form: the VRC is issued under the member's own
# membership DID and carries no publish authorization. Accepted
# for one release; both named parties must be current members, as
# before.
allow if {
	input.action == "publish"
	not input.issuer.pop_verified
	input.issuer_member.is_current
	input.subject_member.is_current
}
