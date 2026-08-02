### vta-sdk 0.21.5 / vta-service 0.14.6 — a partial webvh DID edit no longer serialises nulls the schema refuses (#895)

`pnm did-mgmt dids edit --did <DID> --label resync --no-confirm` could not run
at all:

```
✗ Protocol error: trust task failed [malformedRequest]: malformed request:
  payload does not conform to https://trusttasks.org/spec/vta/webvh/dids/update/1.0:
  payload failed schema validation: null is not of type "object";
  null is not of type "string"; null is not of type "integer";
  null is not of type "integer"; null is not of type "array"
```

`UpdateDidWebvhBody` carried **no** `skip_serializing_if`, so every field the
caller did not set serialised as an explicit `null`. The published schema types
each optional member by what it holds — object, string, integer, array — and
none of them are nullable, so the payload was refused once per unset field.

This was not specific to `--label`. Every partial edit failed, and adding flags
did not help: each one removed a single null and left the rest. The documented
non-interactive edit path did not work over the trust-task transport for any
combination of arguments.

Every sibling body in `did_management` already skipped its `None`s — `create.rs`
in 22 places, `servers.rs` in 6, `list.rs` in 2. `update.rs` was the sole
outlier at zero. `UpdateDidWebvhBody` and `RotateDidWebvhKeysBody` now skip
theirs, nine fields in total. `UpdateDidWebvhResultBody` has no optional members
and is unchanged.

## Why the existing tests did not catch it

Both of the obvious guards look like they cover this, and neither does.

The **conformance sweep** validates each witnessed task against its *generated
type*, and its `vta/webvh/dids/update/1.0` fixture sets every member. A fully
populated payload has no nulls to reject — and even a null-bearing one would
have passed, because `null` deserialises happily into `Option::None`. The sweep
tests the generated types; only the JSON-Schema validator types the members.

The **round-trip tests** serialise and deserialise the same struct, so a null
written on the way out is read straight back as `None` on the way in. That is
symmetric and wrong in exactly the way that survives a round trip.

## Testing

- `a_partial_edit_from_the_cli_validates` drives the CLI's real payload —
  **serialised from `UpdateDidWebvhBody`, not hand-written JSON** — through
  `validate_payload`. A literal would only encode what the author believed the
  type emits, which is precisely the gap that produced the bug.
  **Verified by mutation**: reverting the `skip_serializing_if` attributes fails
  it on the no-nulls assertion.
- `the_null_form_that_broke_the_cli_is_still_refused` puts the nulls back by
  hand and asserts the refusal, so the test above pins the serialisation rather
  than a schema that stopped typing its members.
- `an_unset_field_is_absent_from_the_wire_not_null` pins the wire shape at the
  SDK layer, including that an empty body is `{}` rather than seven nulls.
- `a_set_field_still_reaches_the_wire` guards the other direction: `Some(0)`
  (disable pre-rotation) and `Some(vec![])` (disable watchers) are meaningful
  values, not absences, and must survive the skip.

## Context

Third defect found in this flow, after #894's two. The first two wedged updates
that had already diverged; this one blocked the CLI path an operator would use
to *recover* from that state.
