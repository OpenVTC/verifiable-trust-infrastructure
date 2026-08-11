### vta-sdk 0.21.20 / vta-service 0.14.32 — a typed `vault/upsert`, with an escape hatch (#931)

Option C, scoped to the one member of the pass-through family worth typing.

`VaultUpsertBody` names the members that exist today — `contextId`, `targets`,
`label`, `secretKind`, plus the optionals — and carries
`#[serde(flatten)] extra` for everything this build does not model.

**The hatch is the whole design.** Typing the body without it would mean an SDK
release before a caller could use *any* member the spec adds. That
forward-compatibility cost — not the typing effort — is why the rest of
`vault/*` stays a pass-through, and the hatch is what buys the coverage without
paying it. The trade is explicit rather than hidden: modelled members are
guarded by the null census, `extra` is not. It is greppable, and a member that
lands in it repeatedly is one that wants promoting into the struct.

**Additive, not breaking.** `vault_upsert` keeps its `Value` signature exactly
as it was; the new `vault_upsert_typed` sits beside it. Changing the existing
method would break every caller for a benefit they can opt into instead — and
the pass-through is no longer unguarded anyway, since #930 validates it against
the published schema before dispatch.

`sealedSecret` stays off the body and is inserted by the method, because sealing
needs the client's HPKE context rather than the caller's.

The `vault/upsert` witness is now built from the body — a minimal create with
every optional unset, plus the sealed envelope the method would add. Teeth
checked: reverting the skip on `tags` fails the sweep with `null is not of type
"array"`, which the old fixture could not have caught because it set `tags`.

That closes the design question from #930. Of the six genuine pass-throughs,
`vault_upsert` gets a typed body; the other five keep theirs, guarded by the
pre-dispatch check.
