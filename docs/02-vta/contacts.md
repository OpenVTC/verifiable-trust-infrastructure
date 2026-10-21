# Contacts and your own marks on them

A VTA keeps its principal's **contacts**: what a peer disclosed, filed per
relationship (`persona/contact/*`). It also keeps what the principal thinks of
them — a **star**, a **petname**, the principal's own **lists**, and a link to the
community **directory entry** a contact was met through. These are the
*annotations* of `persona/contact/put/1.1`, and the lists are
`persona/contact/lists/*/1.0`.

## What is where

| Task | What it does |
|---|---|
| `persona/contact/put/1.1` | File a disclosure (as 1.0), and/or change annotations. Naming `contactId` and no document only annotates: no revision is appended, `rev` does not move |
| `persona/contact/get/1.1` | A contact with its current annotations, with any revision |
| `persona/contact/list/1.1` | Summaries — `starred` always, `petname`, `lists`, `directoryRef`, the contact's own `displayName` — filtered by persona, `changedSince`, `starred`, `listId` or `directoryVtcDid`, paged by a cursor bound to the filters |
| `persona/contact/lists/{put,list,show,delete}/1.0` | The principal's lists ("Mentors"): a name unique in the context, an optional colour, an order; deleting one takes it off every contact in the same write |

Every task is context-scoped. A list holds contacts known by any persona in its
context, and from any number of communities, but never one of another context.

## They never leave the VTA

A community never learns who its members star, list or name: if it stored them,
its operator would hold the graph of who watches whom. So the VTA keeps them, and
sends them nowhere — not to the contact, not to the community a `directoryRef`
names, not into anything it signs or presents. A petname, a note or a list name is
never written to a log or the audit trail; only that a contact or a list changed,
and when.

The member portal joins a community's directory with these on the member's own
device, through their wallet: stars first, petnames beside display names, lists as
filters. Neither the VTA nor the community sees the other half.

## Stored

Annotations sit beside the contact (`pca:<context>:<contactId>`), not inside its
revisions, and are discarded with it; lists are `pcl:<context>:<listId>`. Both are
in the persona keyspace and so in a backup. A petname and a note are kept exactly
as written — never case-folded or normalised.
