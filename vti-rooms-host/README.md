# vti-rooms-host

The `rooms/*` Trust Task handlers a data-room host serves, written once for every host.

A data room is served by a host: a community (`vtc-service`) or a standalone delivery service (`room-host`). A room moves between hosts without changing identity, so every host must answer every task the same way. This crate is the one copy of the handler layer both hosts run.

## What a host supplies

`RoomHost`, one object-safe async trait:

| Method | What |
|---|---|
| `rooms`, `records`, `epoch_links`, `revocations` | The keyspaces a room's state lives in |
| `files`, `watches` | The room-file host and the watches members armed |
| `resolver` | How a DID resolves, for the chain verifier and a nomination's check |
| `host_limits` | What `rooms/info/0.5` advertises (a community's 64 KiB record document limit, a standalone host's body cap) |
| `refuses_rewrites_by_others` | `rooms/records/put/0.5` Host item 15, a MAY |
| `charge` | Charge an authorized operation to the presenter's budget in the room (a community does; a standalone host charges nothing) |
| `register` | Decide whether to host a new room, and write it (a community asks its `rooms` policy; a standalone host holds creator rules and ceilings under one lock) |
| `owner_changed` | A room changed owner |
| `audit` | Record an operation. What may be recorded is decided by `vti_rooms::audit::for_operation`, never by the host |

## What a host calls

- `dispatch(host, doc, presenter)`: run one `rooms/*` document as `presenter`, the signer the host's spine proved. Fires the room's watches after a task that committed.
- `serves`, `served_uris`: the family's served Type URIs, read off the registrations.
- `is_consequential`: whether a task changes room state, so its answer is kept in the host's duplicate-id record. Also read off the registrations.

The host receives the document through its own `vti_trust_task_server::Spine`; this crate never sees a session, an ACL or a roster. A room operation is authorized by the signer and the chain the room issued, and nothing else.
