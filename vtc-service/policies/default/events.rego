# Default `events` policy — the community's events (`vtc/events/*`, VTI-EVT-080).
#
# Evaluated after the community's own checks, over an event's creation, change
# and publication: the caller runs the calendar or hosts the event, the time,
# audience and registration settings are well formed, and a published event's
# roster setting is unchanged. Those are never this policy's to relax.
#
# This policy may refuse, and nothing else. It never makes anyone a host, a
# registrant or a holder of any authority (VTI-EVT-002).
#
# Input:
#   input.operation   "create" | "update" | "publish"
#   input.now         evaluation time
#   input.actor       { did, role, runsAll }
#                       runsAll: holds vtc.events.manage for the whole community
#   input.calendar    { calendarId, groupId, community }
#   input.event       { eventId, kind, status, listed, roster, audienceScope,
#                       mode, capacity, start, end }
#                       (eventId is empty on "create"; start and end are instants)
#
# Refuse with:
#   {"effect": "deny", "with": {"code": "...", "reason": "..."}}
# which the caller is shown as the task's `policyRefused`.
#
# The shipped posture allows whatever the community's checks allow. A
# community that keeps listed, community-wide events to its administrators,
# for example, uploads:
#
#   decision := {"effect": "deny", "with": {"code": "admins-only",
#       "reason": "only administrators publish events for everyone"}} if {
#       input.operation == "publish"
#       input.event.listed
#       input.event.audienceScope == "members"
#       not input.actor.runsAll
#   }

package vtc.events

import rego.v1

default decision := {"effect": "allow"}
