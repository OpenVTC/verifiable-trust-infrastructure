# Default `gitNamespace` policy — what this community allows inside the forge
# namespaces it governs (`git-ns/*` Trust Tasks).
#
# This policy can only NARROW. The VTC enforces the rights model's fixed rules
# in code before it asks this policy anything — scope containment, no
# escalation, `git.repo.create` not re-delegable, the last-owner and last-admin
# invariants, and namespace-level rights (`git.ns.admin`, `git.repo.create`) for
# current members only — and nothing written here can admit a request those
# rules refused. What a community decides here is everything the specification
# leaves to it: which forges and visibilities it allows, who may receive
# `git.repo.create`, whether people outside the community may sign commits, for
# how long, and on which repositories.
#
# The shipped posture is deliberately conservative: **members only, no external
# signers**. Every right goes to a current member of this community, so every
# right is reachable by the membership lifecycle that revokes it on departure.
# A community that wants outside contributors to sign commits says so by
# uploading a policy that admits them — for example, `git.commit.sign` only,
# with an `expiresAt` no more than 90 days out.
#
# Input (`input`):
#   now           RFC 3339 evaluation time
#   action        namespace.bind | namespace.unbind | repo.create | repo.adopt |
#                 repo.transfer | repo.archive | right.grant | right.revoke |
#                 namespace.reseat (a community administrator restoring an
#                 admin to a headless namespace) | drift.revert (an owner
#                 having the bridge undo a forge-side change; an adopted drift
#                 item is evaluated as the right.grant it is) |
#                 bridge.serviceGrant (the community granting its bridge
#                 `git.commit.sign` on a namespace it has just bound) |
#                 right.breakGlass (a member recording an elevated right for
#                 themselves with git-ns/right/break-glass — `subject` is the
#                 actor) | right.ratify (another administrator ratifying one
#                 with git-ns/right/ratify — `subject` is the one who broke it)
#                 | roles.reproject (a community administrator or namespace
#                 admin having the bridge re-apply a namespace's or a
#                 repository's forge roles; no right changes)
#   actor         { did, member, role?, rights[] }  — rights on `resource`
#   subject       { did, member, role?, rights[] }  — whoever receives or loses
#                 the right (grant, revoke, transfer, each adopted owner)
#   right         the right string, where the action concerns one
#   resource      forge-qualified, lowercase: `github.com/acme[/widgets]`
#   forge         the forge host
#   visibility    public | private, for repo.create
#   expiresAt     the grant's expiry, if any
#   capabilities  { bridge, botCanCreateRepos, kind?, bridgeDid? }
#   via           how the request arose, where that differs from `action`:
#                 "drift.adopt" on the `right.grant` an adopted drift item is
#                 evaluated as. Absent for a direct request. A community that
#                 never adopts forge-side changes denies
#                 `input.action == "right.grant"; input.via == "drift.adopt"`.
#
# Output: `decision` — {"effect": "allow"} or {"effect": "deny", "with": {code,
# reason}} — and `settings`, the community's choices the rights model names.

package vtc.git_namespace

import rego.v1

# The community's settings. All off by default:
#   maintainer_grants_commit  a `git.repo.maintain` holder may grant
#                             `git.commit.sign` on their repository
#   cascade_on_departure      a departed member's issued grants are revoked
#                             with them, instead of listed for review
#   role_drift                "report" (default) or "enforce": whether a forge
#                             role changed outside the VTC is put back
#
# Break-glass (git-ns/right/break-glass/0.1). Separation of duties stops anyone
# granting themselves git.ns.admin, git.repo.create or git.repo.own; break-glass
# is the explicit, passkey-gated, justified, loudly announced way to do it when
# nobody else can. A community may DISABLE or TIGHTEN it here. It cannot quieten
# it: the critical audit row, the notice to every other administrator and the
# console banner are applied in code whatever this policy says.
#   break_glass                          "enabled" (default) or "disabled"
#   break_glass_delay_seconds            the right takes effect this long after
#                                        it is recorded (at most a day); other
#                                        administrators can revoke it meanwhile.
#                                        0 (default): at once
#   break_glass_min_justification_chars  a shorter justification (counting
#                                        non-whitespace) is refused. 0 (default):
#                                        any non-blank justification
# A policy can also refuse `input.action == "right.breakGlass"` outright for any
# condition — some rights, some namespaces, anyone who is not a community
# administrator — with a deny decision.
settings := {
	"maintainer_grants_commit": false,
	"cascade_on_departure": false,
	"role_drift": "report",
	"break_glass": "enabled",
	"break_glass_delay_seconds": 0,
	"break_glass_min_justification_chars": 0,
}

default decision := {"effect": "deny", "with": {
	"code": "not-a-member",
	"reason": "this community governs its forge namespaces for its own members",
}}

# Receiving a right, or ownership, is for members unless the community opts in.
receives := {"right.grant", "repo.transfer", "repo.adopt", "namespace.reseat", "bridge.serviceGrant"}

# The one exception, and it is exact: the namespace's own bridge receives
# `git.commit.sign` on the namespace, granted by the community itself when the
# namespace is bound, so the commits it authors (re-signed Dependabot pull
# requests) pass the check. Any other resource, right or DID is refused below.
service_grant if {
	input.action == "bridge.serviceGrant"
	input.right == "git.commit.sign"
	input.subject.did == input.capabilities.bridgeDid
	count(split(input.resource, "/")) == 2
}

# Anyone may give up a right they hold — an external signer included, even
# though this policy never lets one be granted. Resigning only narrows.
resignation if {
	input.action == "right.revoke"
	input.subject.did == input.actor.did
}

decision := {"effect": "allow"} if {
	service_grant
} else := {"effect": "allow"} if {
	resignation
} else := {"effect": "deny", "with": {
	"code": "external-signers-not-enabled",
	"reason": "this community gives git rights only to its members; upload a gitNamespace policy that admits external signers to change that",
}} if {
	input.actor.member == true
	input.action in receives
	input.subject.member == false
} else := {"effect": "allow"} if {
	input.actor.member == true
	input.action != "bridge.serviceGrant"
}
