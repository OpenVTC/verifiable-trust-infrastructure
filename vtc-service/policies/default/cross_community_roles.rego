# Default `cross_community_roles` policy — deny-all
# (spec §7.1 + §8.4).
#
# Honouring a foreign VAC's role grant is a session-mint
# hardening hazard (spec §8.4): a malicious peer community
# could mint arbitrary VACs and have them confer admin in your
# community. Default-deny forces the operator to make an
# explicit allowlist before any cross-community grant takes
# effect.
#
# Input shape (spec §7.3 + M3.10):
#   {
#     "foreign_vac": {
#       "issuer": "<did>",
#       "role": "<foreign role string>",
#       "subject_did": "<did>"
#     },
#     "action": "mint_session"
#   }
#
# Output contract:
#   - `allow: bool`         — gate for "should we mint anything?".
#   - `mapped_role: string` — the local role to embed in the JWT.
#                             Only consulted when `allow` is true.
#                             Operators uploading custom policies
#                             can return e.g. "monitor" for any
#                             foreign role to grant read-only
#                             access regardless of foreign rank.

package vtc.cross_community_roles

import rego.v1

default allow := false

# `mapped_role` has no `default` rule by design: the route layer
# treats a missing value as "deny" even when `allow` is true. An
# operator upload that flips `allow := true` but forgets to set
# `mapped_role` therefore still denies — fail-closed.
