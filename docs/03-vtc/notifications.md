# A community's received notifications

A community receives `notifications/notify` and `notifications/relay` documents addressed to its
DID — an election another community puts to this community's members, for instance — on the
open door. It verifies every layer and holds a notification only from a party it has a
relationship with (VTI-NTF-034):

- a party holding a live ACL entry at the community;
- a party with which the community holds a relationship credential in force;
- a network the community is itself a member of, as its own record shows (an **acknowledged**
  membership, `vtc/networks/join`). A listing the community never acknowledged does not count.

Everything else is declined and answered with the same receipt (VTI-NTF-023). Holding a
notification tells nobody anything, members included (VTI-NTF-070). The rules are the
*Notifications* chapter of the [VTI specification](https://trustoverip.github.io/dtgwg-vti-spec/);
the VTA side is [`docs/02-vta/notifications.md`](../02-vta/notifications.md).

## Capabilities

| Capability | Gates | Qualifier |
|---|---|---|
| `vtc.notifications.read` | listing and reading what the community holds | — |
| `vtc.notifications.relay` | deciding a relay to members | `group:<groupId>` — only that group's members |

Both are inside `community-admin`'s ceiling and neither confers authority: a relay grants its
recipients nothing (VTI-NTF-004). They are apart so a community can let an administrator see what
it has been told without letting them pass it on.

## Tasks

| Task | Authority |
|---|---|
| `vtc/notifications/list/0.1` — filter by `kind`, `heldBy`; `includeLapsed`; paged | `vtc.notifications.read` |
| `vtc/notifications/show/0.1` — the record and the delivering document exactly as received | `vtc.notifications.read` |
| `vtc/notifications/relay/0.1` — relay one to `allMembers`, one `group`, or one `role` | `vtc.notifications.relay` for that selection |

Each item says whether the community may relay it now (`mayRelay`), what a relay discloses
(`relayDisclosure`) and the decisions already made — each as its selection and how many it
added, **never** whom it reached.

## Deciding a relay

- **Acknowledge the disclosure.** For a kind whose relay discloses something about the community
  (`election`: that the community is a member of the community holding it), a decision without
  `disclosureAcknowledged: true` is refused with `disclosureNotAcknowledged`, carrying the
  statement to show (VTI-NTF-046). The console shows it and requires the tick.
- **The selection** is resolved once, from the community's own records, to members whose
  membership is active (VTI-NTF-072). A member who joins later is not added without a new
  decision. The community never relays to itself, to the originator, or to any relayer the
  received chain names (VTI-NTF-047), nor twice to the same party; a repeat answers
  `recipientCount` 0.
- **Depth.** A relay is allowed while the chain the community received carries at most three
  relays, so that its own makes at most four (VTI-NTF-041); otherwise `notRelayable`.
- **Step-up.** A decision naming **all members** takes the requester's step-up bound to the
  document (passkey or approver device, as for other irreversible acts; VTI-NTF-074). A group or
  role decision does not.
- **Later revisions**, a withdrawal included, go to everyone a decision reached, without a further
  decision, until the notification's period ends (30 days without one; VTI-NTF-044).
- **Audit.** Each decision is audited as `NotificationRelayDecided`: the administrator, the
  notification, the revision, the selection, the count and the acknowledgement — never the
  parties reached (VTI-NTF-073).

Refusals: `notificationUnknown`, `notRelayable`, `lapsed`, `disclosureNotAcknowledged`,
`groupUnknown` (a group that does not exist or that the caller may not see), and
`permissionDenied` for a selection the caller's capability does not cover.

## Console

*Membership → Notifications* lists what the community holds, shows one with the document as
received, and — for holders of `vtc.notifications.relay` — offers **Relay to members** with the
choice of all members, one group or one role, and the disclosure acknowledgement.

## The election notice the community sends

As originator, the community notifies a member party of an election put to the party's members
([`elections.md`](elections.md)). Every revision that still offers the election is sent only while
the party is an active member (VTI-NTF-005); a withdrawal — on cancellation or an early close —
goes regardless and keeps the voting period of the revision it replaces (VTI-NTF-025, VTI-NTF-061).
