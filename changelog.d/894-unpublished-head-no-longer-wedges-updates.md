### vta-service 0.14.5 — an unpublished local head no longer wedges every future update (#894)

A `did:webvh` DID could reach a state where **every** update failed, permanently,
with `concurrent update: … has been updated since you read it`. Observed in
production on `webvh.storm.ws`: an agent-name bind published a version the host
never received, and from then on the admin UI could neither show the new version
nor bind the name, retry after retry.

Two independent defects, one of which was hiding the other.

## 1. The reconciler sat below the check that made it necessary

`run_update` does its optimistic-concurrency check (step 4a) *before* the
reconciler that heals a failed publish (step 4b). Those two steps disagree about
what the caller's `expectedVersionId` means.

The caller reads that version from the **host**. 4a compares it against the
VTA's **local** log head. Those are the same value right up until a publish
fails — at which point the local head advances and the host does not, and the
comparison starts calling the caller stale for correctly reading the only thing
it can see.

Refusing there is what makes the state permanent. Step 4b exists precisely to
re-publish an unconfirmed local head, and its own comment says so: *"That is
what makes a failed attempt self-recover instead of wedging the DID."* It never
ran, because 4a returned first. Every retry died in the same place.

The consent flow makes it worse. There the refusal is raised by the **Plan**
dry-run, and 4b is `Mode::Execute`-only by design — a plan must not mutate. So a
delegated update could not self-heal even in principle: the task never got far
enough to try.

4a now consults `get_published_version` before declaring a conflict. If the
caller matches the last version we *confirmed* on the host, the caller is not
stale — we are — so the update proceeds and 4b reconciles. This grants no new
authority: the unpublished head was already signed under a prior authorization,
so it resumes an interrupted publish rather than smuggling in an unapproved
change.

The precondition is unchanged where it earns its keep. `None` (never confirmed)
still conflicts, because nothing proves the caller read anything real, and
serverless DIDs never set the marker — with no host, the local head is the only
truth and a mismatch really is a stale caller. `a_stale_caller_still_conflicts`
pins that.

## 2. REST silently dropped the precondition entirely

`update_did_handler` deserialised the request body straight into the op-layer
`UpdateDidWebvhOptions`. That struct is snake_case with no aliases; the wire body
`UpdateDidWebvhBody` is `rename_all = "camelCase"`. A caller sending
`expectedVersionId` — every SDK caller — matched no field, and with no
`deny_unknown_fields` nothing rejected it. It defaulted to `None`: **the
optimistic-concurrency precondition never applied to any REST update.**

This is the same defect `the_concurrency_precondition_is_read_from_the_wire`
was written to pin. That test fixed the SDK type; the REST route kept its own
shortcut and stayed broken. The doc comment on `UpdateDidWebvhOptions` already
said route handlers "deserialise the SDK body and convert to this struct at
intake" — the route simply wasn't doing it.

It now takes `UpdateDidWebvhBody` and converts via the same
`update_body_to_options` the trust-task dispatcher uses. One conversion, so the
two paths cannot drift.

A silently-ignored safety precondition is worse than an absent one: it reads, in
the caller's source, as though the lost update were handled. Per R3.6, a request
contract includes what you ignore.

## Testing

- `a_caller_pinned_to_the_host_version_recovers_a_failed_publish` reproduces the
  production wedge: land an update, fail the next publish, then re-submit pinned
  to the host's version the way the admin UI does. **Verified by mutation** —
  reverting the 4a change fails it with the exact `concurrent update` error.
- `a_stale_caller_still_conflicts` pins the other side, so the fix cannot
  quietly become "the precondition was deleted".
- The pre-existing `a_failed_publish_does_not_wedge_the_did_and_the_next_update_recovers`
  passed throughout — it sends no `expectedVersionId`, which is exactly why the
  wedge survived it. That gap is now covered.

Note that defect 2 was masking defect 1 in the test suite: until REST forwarded
the field, no integration test could reach 4a at all.
