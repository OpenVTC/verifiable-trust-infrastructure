# ACL scope semantics — the two axes

**Status:** implemented (VTA + VTC).

An ACL entry answers two independent questions, and they must never be
conflated:

| Axis | Question | Type |
|---|---|---|
| **Act** | In which contexts may this DID *make* a change? | `ActScope` |
| **Approve** | In which contexts may this DID *bless* someone else's change? | `ApproveScope` |

Both live in `vta-sdk/src/acl.rs`, are three-valued, and share the same
variants, the same `covers()` predicate (segment-aware, so authority over a
parent context covers its subtree), and the same fail-closed default:

```rust
enum ActScope     { None, All, Contexts(Vec<String>) }   // default None
enum ApproveScope { None, All, Contexts(Vec<String>) }   // default None
```

An entry can hold either axis without the other. A **least-privilege approver**
is the shape that motivates the split: acts nowhere (`ActScope::None`), confers
via `ApproveScope::All` or `ApproveScope::Contexts([...])`. It carries authority
to authorize and none to act.

## The asymmetry: one is stored, one is computed

`ApproveScope` is a real serialized field with a pinned wire shape.

`ActScope` is **not stored and not sent**. The act axis is stored as
`(role, allowed_contexts)`, and `ActScope` is computed from that pair on read:

| `role` | `allowed_contexts` | `ActScope` |
|---|---|---|
| `Admin` | `[]` | `All` — this is how a super-admin is spelled |
| any other | `[]` | `None` — authorized nowhere |
| any | non-empty | `Contexts([...])` |

That decode is `vti_common::acl::act_scope_for`, reached in practice via
`AclEntry::act_scope()` / `AuthClaims::act_scope()`. Storage, JWT claims, and
every wire body are unchanged — this is a read-path abstraction, not a
migration.

The VTC shares the same decode: `VtcAclEntry::act_scope()` maps its own role
enum through `as_vti_role` and calls the same `act_scope_for`, so the two
services cannot disagree about what an empty scope set means.

The type and its `covers()` predicate live in `vta-sdk` beside `ApproveScope`,
so the two axes read as one model. The *decode* stays in `vti-common` because
it needs `Role`, which the SDK cannot see. Shape and predicate are shared;
authorization policy over them is server-side. Same split #768 used for
`ApproveScope` and `validate_approve_scope_grant`.

## The rule

**Never test `allowed_contexts.is_empty()` at a call site.** It is only
meaningful paired with the role, and every place that forgot the pairing has
been a bug:

- an ACL display that rendered a least-privilege approver as `(unrestricted)`,
  on a screen operators audit grants with (#746, fixed in #764);
- two `acl list --context` filters that disagreed on whether an empty list
  matches every context or none — and neither was right, since both also
  ignored ancestry (#770);
- a vault trust-task scope gate that read any empty list as super-admin scope,
  granting an authorized-nowhere entry credential-vault access in **every**
  context. `Role::Reader` derives `Capability::VaultRead`, so the
  least-privilege approver shape reached it; `Role::Initiator` derives
  `VaultWrite`, so it reached the write path too (#769).

Go through `act_scope()` — or `has_context_access` / `can_act_in` /
`is_super_admin`, which are built on it — and match on the result.

## The third axis: which *direction* a context filter reads

A context id names a subtree, so "the ACL entries relevant to context X" is two
questions, not one — and until #822 only the first was askable:

| direction | question | predicate |
|---|---|---|
| `acting-in` (default) | who may act **in** X? | entry scope `is_ancestor_or_self` of X |
| `subtree` | what is granted **beneath** X? | X `is_ancestor_or_self` of the entry scope |
| `any` | whose authority **touches** X's subtree? | either |

Both are pure segment comparisons over data already in the entry; `subtree` is
`acting-in`'s predicate with its arguments swapped
(`ActScope::acts_within` beside `ActScope::covers`).

**Why the gap mattered.** `?context=X` answered only the first, correctly — but
a caller sweeping a subtree to *revoke* it needs the second, and asking it with
the first's filter returns precisely the entries that are **not** being revoked
(the ancestors keeping their authority) while omitting every leaf-scoped grant
the sweep exists to cut. The wrong answer is short, not empty, so it looks
complete. Once sub-contexts exist the natural least-privilege layout is a leaf
per purpose (`<tenant>/<unit>/<purpose>` — partly because, without a per-key
actor grant (#818), a context of its own is the only way to scope a caller to
one key), which is exactly the layout that makes the omission total: every
principal's grant is a leaf. Cierge's kill switch hit this
(affinidi/cierge#49) — a gateway grant at `<domain>/attestation` survived a
sweep of `<domain>` and could keep signing while the kill report read
"succeeded".

This is the same lesson as `allowed_contexts.is_empty()` one level up: an
answer that is only meaningful paired with the question, and a call site that
could not say which question it meant.

### Two edges, both deliberate

- **An unrestricted (super-admin) entry is not in the `subtree` answer.** It
  names no context, so it is not a grant *of* the branch; it is authority
  everywhere, which `acting-in` already reports. Including it would hand a
  caller revoking a compromised branch its own super-admin to delete. `any` is
  where an auditor asks for it.
- **An entry naming contexts inside *and* outside the branch is in the
  `subtree` answer.** It does hold a grant inside, so omitting it would
  under-report — the failure mode being fixed. Whether to delete the entry or
  narrow its scope is then a decision made with the entry in hand.

### Fail-closed shape

Absent parameter = `acting-in`, byte for byte the pre-#822 behaviour (pinned by
tests at the scope, entry, and operation layers). An unparseable direction is
**refused with the valid set**, never defaulted — guessing which of two
opposite questions an operator meant is how a confidently-wrong answer gets
served. A direction with no context is refused too: it is inert, and silently
listing the whole ACL to a caller that asked to sweep a branch is the same
defect one level up.

Surfaces: `GET /acl?context=…&direction=…`, the `direction` member on the
`spec/vta/acl/list/1.0` payload (also the DIDComm `list-acl` body),
`pnm|cnm acl list --context … --direction …`, the offline `vta acl list`, and
`VtaClient::list_acl_in_direction` (`list_acl` stays `acting-in` exactly). The
CLI prints the question it asked next to the count, because two directions over
one `--context` produce two legitimate, differently-shaped lists.

### Why the VTC did not follow

The VTC has the same one-directional filter (`GET /acl?scope=…`, ancestry-aware
since the hierarchical-contexts work), but its listing is bound to the
**canonical** `acl/list/0.1` Trust Task, whose payload is
`additionalProperties: false` over `{cursor, ext, pageSize, role, scope,
subjectPrefix}`. A `direction` member there is an openvtc spec change (or an
`ext` member), not a local one, so adding it unilaterally would be exactly the
canonical-conformance drift the VTC migration exists to remove. Left as a
follow-up with the shape already decided here. Note for whoever picks it up:
the VTC list is **paginated**, and `direction` must join
`ListAclQuery::cursor_binding` — a cursor minted under one direction must not
resume under another, or a resumed sweep silently changes question mid-listing.

## Reading is not managing

Two predicates, deliberately separate:

| predicate | includes | gates |
|---|---|---|
| `is_acl_entry_visible` | act-scope overlap | update, delete |
| `is_acl_entry_auditable` | that, **plus** approve-scope reaching the caller | list, get |

A least-privilege approver names no context on the act axis, so it never
overlapped a context admin's scope — meaning an admin could not see who was
able to authorize a change in their own context. Conferral is authority, and
authority in your context should be auditable by its admin.

**Keeping them separate is load-bearing, not tidiness.** An entry can
administer *someone else's* context while conferring into yours. Folding
conferral into the single visibility predicate would have made that entry
deletable by you — `delete_acl`'s only other guard is
`validate_role_assignment`, which a context admin passes — turning a read
widening into privilege escalation. Pinned at both layers by
`auditable_does_not_confer_manage_authority` and
`delete_acl_refuses_an_entry_that_acts_outside_callers_contexts`.

A mutation refused on an entry the caller can nonetheless read returns
`Forbidden` explaining the split, rather than the usual `NotFound`: there is
nothing left to conceal about a row they can already list, and "not found"
would be a lie. Entries the caller cannot read at all still conflate to
`NotFound`, so the enumeration guard is intact.

The act axis is unchanged — an unrestricted (super-admin) entry still does not
surface to a context admin merely by being unrestricted.

## What this does *not* change

Both conflations `ActScope` was introduced to make resolvable have since been
resolved, each as its own reviewed change rather than folded into the refactor:

- **`validate_acl_modification` now takes the target's role**, so it decodes
  the target into an `ActScope` and distinguishes "grant nothing" (`None`) from
  "grant everything" (`All`). `All` stays super-admin-only; `None` — an
  acts-nowhere entry, which grants no authority to act — may be created by any
  caller who may manage the ACL. That is how a context admin mints a
  least-privilege approver for its own context; the *conferral* half is gated
  independently by `validate_approve_scope_grant`, so it still cannot confer a
  context it does not administer. Behaviour is otherwise unchanged: the scoped
  and unrestricted cases decide exactly as before.

- **The admin path in `delegated_any_approver_covers`** used exact membership
  where the approve-scope path beside it used ancestry; the admin path is
  ancestry-aware too now, matching the ACL-gate rule in
  `hierarchical-contexts.md`.

## Remaining work

- **`reader + All`** ("may read every context, admin nowhere") is expressible
  in the type but unreachable through the decode table, since `All` requires
  `Role::Admin`. If it is ever wanted it needs a stored representation — i.e.
  the migration this design deliberately avoided.
