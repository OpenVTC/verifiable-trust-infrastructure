### vta-sdk 0.21.19 / vta-service 0.14.31 — refuse a payload the recipient will reject (#930)

Option D from the pass-through design question, plus the one `vault/*` method
that turned out to be ordinary unfinished work rather than a design question.

**The client now validates a Trust Task payload against its published schema
before sending it.** The recipient already runs this exact check — the same
`validate_payload` on the dispatch spine — so it cannot reject anything a
*validating* recipient would have accepted. What changes is *where the operator
finds out*:

- **Locally, naming the member.** `keys/create` sending `"mnemonic": null`
  (#919) surfaced as a remote `malformedRequest` while the client reported a
  successful send. The payload never had to leave the process to be known bad.
- **On the pass-through surface especially.** `vault_list`, `vault_release`,
  `vault_proxy_login`, `vault_sign_trust_task`, `vault_upsert` and
  `device/list` take the whole payload as a caller-supplied `Value`. No body
  struct guards them, no census can walk them, no witness can be built from
  them. This is the only check they can have — which is why D was worth doing
  before C.

A task with **no** published schema still dispatches. `None` from the registry
means "we cannot know", not "anything goes", and refusing on that basis would
break every legacy `vta/*` task the registry has not caught up with. Both
directions are pinned by tests, and the refusal test asserts on the transport
sink rather than just the error — proving the payload never reaches the wire.

**`vault/delete` is folded.** It was miscategorised as a pass-through: it takes
typed parameters and built its payload with an inline `json!` plus a conditional
insert per optional, which is exactly the #919 shape. New
`protocols::vault_management::VaultDeleteBody`, producer rewired, witness built
from it with both optionals unset.

The rest of `vault/*` stays a pass-through deliberately. Modelling it means
tracking a large, still-moving surface and shipping an SDK release for every
member the spec adds — the forward-compatibility cost is the real one, not the
typing effort. `vault_upsert` alone is worth a typed body with a flatten escape
hatch (option C), and that follows separately.

**It found a live one immediately.** `change_acl_role` interpolated `req.reason`
— an `Option` — straight into an inline `json!`, so a role change with no
rationale sent `"reason": null` against a schema that types it `"string"`.
`ChangeRoleBody` already existed with the right `skip_serializing_if`; the
producer simply did not use it. Exactly #919's `keys/create` and #921's
`derive_and_sign_document`, a third time. Now built from the canonical body.

Worth being precise about what that reveals: the e2e covering this call passed
before, so *some* recipients accept the null. The claim is not "this rejects
only what would have failed everywhere" — it is "this rejects only what a
recipient running the published schema would reject". A tolerant recipient is
not a reason to send a non-conforming payload.

Two further `Option`-into-`json!` sites remain — `rotate_seed`'s `mnemonic` and
`list_dids_webvh`'s filters. Both are on tasks with **no published schema**, so
neither this check nor the recipient can see them, and there is no schema to
confirm the correct wire shape against. Left as-is deliberately rather than
changed blind; they become checkable the day those specs publish.
