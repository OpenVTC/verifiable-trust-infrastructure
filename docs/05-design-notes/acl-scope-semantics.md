# ACL scope semantics — the two axes

**Status:** implemented for the VTA. The VTC's parallel ACL surface still
decodes by hand — see [Remaining work](#remaining-work).

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

Two conflations are preserved deliberately, because removing either is a
change in authorization rather than in structure:

1. **`validate_acl_modification` still refuses an empty target to any
   non-super-admin.** It receives `target_contexts` without a role, so it
   cannot distinguish "grant nothing" (`None`) from "grant everything"
   (`All`) — and refuses both. The consequence is that only a super-admin can
   create a least-privilege approver, which is the very shape the CLI
   recommends.

2. **The admin path in `delegated_any_approver_covers` matches contexts with
   exact membership, not `covers()`.** The approve-scope path in the same
   function is ancestry-aware, so a context admin's conferral is narrower than
   an equivalent explicit `ApproveScope` grant. Probably an oversight, but
   widening it changes who may ratify a step-up.

Both are flagged where they occur.

## Remaining work

- **The two conflations above**, each as its own reviewed change. Note the
  first one interacts with the read/manage split: a context admin still cannot
  *create* the least-privilege approver that they can now *audit*.
- **The VTC.** `vtc-service` has a parallel ACL surface with the same idiom
  (`routes/acl.rs`, `acl_cli.rs`). It needs its own `act_scope()` accessor
  because `VtcAclEntry` is a distinct type with its own role enum, mapped via
  `as_vti_role`. Until then the two services can still drift on what an empty
  scope set means.
- **`reader + All`** ("may read every context, admin nowhere") is expressible
  in the type but unreachable through the decode table, since `All` requires
  `Role::Admin`. If it is ever wanted it needs a stored representation — i.e.
  the migration this design deliberately avoided.
