# Default `registry` policy — publish on join, default
# disposition `tombstone` (spec §7.1 + §8.2).
#
# The trust-registry publication path is Phase 3 — this policy
# ships now so spec §8.2's departure-disposition envelope is
# observable from day one. The handler that consumes it will
# land alongside `MembershipSyncer` in Phase 3.
#
# Output contract (consumed by §8.2's resolver):
#   - publish_on_join:        whether a member who CONSENTED to
#                             publication is published to the trust
#                             registry. The member's own consent
#                             (`publishConsent`, from `registryConsent`
#                             on join-requests/submit) is a floor the
#                             syncer enforces in code before consulting
#                             this rule: it can narrow publication, and
#                             can never publish a member who did not
#                             consent. Consulted on first publication.
#                             Input: { action: "publish",
#                             member: { did, publishConsent } }.
#   - default_departure:      the disposition that applies when the
#                             member does not request a specific one.
#   - departure_options:      the dispositions members are allowed
#                             to pick from.
#   - min_disposition:        the *floor* the operator is willing to
#                             accept. RTBF (member-initiated `purge`)
#                             always overrides this floor — see §8.2.
#
# Input shape (spec §7.3):
#   { member, action, requested_disposition? }

package vtc.registry

import rego.v1

default allow := false

default publish_on_join := true

default default_departure := "tombstone"

departure_options := ["purge", "tombstone", "historical"]

default min_disposition := "purge"

allow if input.action == "publish"
