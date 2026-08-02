### vta-service 0.14.7 — a DID with no confirmed-publish marker is no longer wedged (#896)

#894 unwedged DIDs whose local head had run ahead of the host, but only when
the confirmed-publish marker matched what the caller read. It left the case
that marker is *absent* still refusing — and absent is not rare, it is what
every DID carried until its first successful update. A DID in that state was
still uneditable through the admin UI, which is the surface that actually
implements the consent flow, so there was no route out at all.

## The marker was never written outside the update path

`set_published_version` had exactly two call sites, both in the update
orchestrator. Creation published the genesis log to the host and recorded
nothing; register-with-server pushed the log and recorded nothing. So "absent"
conflated two states that need opposite treatment — *hosted since creation,
host has our log* and *we have never confirmed a publish*.

Both publish sites now record what they published. Serverless creation
deliberately still does not: there is no host to confirm against, and its
marker is legitimately always absent.

## The precondition, stated properly

Step 4a now refuses only when the caller is genuinely stale. It excuses a
mismatch when **all** of:

- the DID is **hosted** — serverless has no host, so the local head is the only
  truth and a mismatch really is a stale caller;
- `expected` **names an entry in our own chain**, so the caller read a real
  past state rather than a value we never issued; and
- **nothing after it reached the host** — the marker is `expected`, or absent.

Absent has to count. The marker is written only on a successful publish, so a
genuine concurrent update would have set it; its absence alongside a moved
local head means a publish that never landed — the wedge itself. Seeding the
marker at the two publish sites makes absence rare going forward, but DIDs
already in the field have none, and they are exactly the ones stuck today.

The rule is extracted to `caller_is_merely_ahead_of_an_unpublished_head` so it
can be pinned as a truth table rather than inferred from control flow. Getting
it wrong is costly in both directions: too strict wedges a DID permanently
(the reconciler that would heal it sits *below* the check that refuses), too
loose silently drops the lost-update protection the check exists for.

## Testing

Five cases, one per branch of the rule:

- `a_caller_in_step_with_the_confirmed_publish_is_not_stale` — the #894 case.
- `an_absent_marker_counts_as_nothing_published_beyond` — the case #894 missed.
- `a_caller_behind_the_confirmed_publish_is_still_stale` — the protection the
  check exists for, so the relaxation cannot become "precondition deleted".
- `a_version_absent_from_our_chain_is_never_excused` — an invented version is
  not a past state anyone could have read.
- `a_serverless_did_is_never_excused` — both marker states.

The integration coverage from #894
(`a_caller_pinned_to_the_host_version_recovers_a_failed_publish`,
`a_stale_caller_still_conflicts`) continues to pin the end-to-end paths.

## Note on the register-with-server marker write

Best-effort, and deliberately so: by that point the DID is registered on the
host and the local record already flipped to hosted, so failing the operation
over a bookkeeping write would undo nothing while reporting failure for work
that succeeded. An absent marker is a state the update path now handles.
