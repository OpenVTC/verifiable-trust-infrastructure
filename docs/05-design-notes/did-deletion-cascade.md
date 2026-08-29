# Deleting a DID: what goes with it

**Status:** classification + census, blockers, revocation and the
authorization cascade shipped. Preview/confirm and the remaining cascades are
follow-ups — see *Not done yet*.

## The problem

`dids delete` removed the daemon-side DID, the local `webvh` record and log,
and the DID's key records. Nothing else. ACL entries, issued credentials,
sessions, contexts and per-DID state were left behind.

That is the same defect class as the VTC's ACL-revoke orphan (#1194, #1196),
one level up: **a surface owning part of a multi-part identity and knowing
nothing about the rest.** The VTC learned it the expensive way — an
`acl/revoke` aimed at a member left a live member row with no authorization and
credentials that still verified for anyone holding them, and the members-list
reader called the result "genuine out-of-band corruption" while the writer
produced it on request.

## Deleting a DID is four relationships, not one

Treating them alike gets one wrong in a way nobody notices until it matters.

| Relationship | Verb | Examples |
|---|---|---|
| The DID **owns** it | Cascade | keys, the webvh log, resolution cache |
| It **names the DID as a subject of authorization** | Cascade | ACL entry, sessions, passkey VMs, consent, vault |
| It **depends on the DID to function** | Blocks | a context acting as this DID, an advertised service, a policy or approver set naming it |
| The VTA **issued** it | Revoke | issued credentials |

The fourth is the one that cannot be "cleaned up" and the one most likely to be
got wrong, because it looks the most like a cascade. Third parties hold copies
of what the VTA issued. Deleting our record does not invalidate theirs — it
destroys the only means of revoking them, leaving every copy in the wild valid
forever. It is precisely the residue left on the VTC.

## Decisions

Three, settled deliberately:

1. **A deletion revokes what it cannot destroy.** Credentials the VTA issued to
   the DID are revoked, not deleted.
2. **A dependency refuses the deletion, and says what to unpick.** Not a
   cascade — cascading silently breaks a context. The refusal names the
   corrective command, per the workspace's "operator errors should suggest the
   fix" convention.
3. **No `--force`.** Same call as `would_violate_last_service`, for the same
   reason: the escape hatch is what gets used at 2am.

## Ordering

Revocation runs **first**, before any deletion, remote or local.

If anything later fails, the credentials are already dead and the DID still
exists — recoverable by re-running. The other order leaves live credentials for
a DID nobody can revoke through any more. When a partial failure is possible,
the surviving state should be the *over*-restrictive one.

The preflight is read-only, so a refusal leaves the VTA exactly as it found it.

## Why a census rather than a list in a function

The failure mode is not getting today's answers wrong. It is a keyspace added
next quarter that nobody classifies, whose rows then quietly outlive the DID
they belong to — which is how the original gap happened.

`vta_keyspaces::did_delete_effect` classifies every keyspace, and a census test
fails when one is unclassified. `Unrelated` is a fine answer; it just has to be
a *chosen* one. This rides the same rail as the existing backup-partition
census, and turns "we forgot" from an orphan found months later in a log into a
red test.

Two classifications are pinned explicitly because they are the ones a future
change is most likely to get wrong:

- `issued_credentials` is **never** `Cascade`.
- `audit` is **never** cascaded — the record that a DID was deleted is the one
  thing that must survive deleting it.

## A caller that cannot cascade cannot delete

`WebvhDeps::delete_cascade` is `None` on the paths that only read or publish.
That does not mean "skip the cascade" — `delete_did_webvh` refuses. Half a
deletion is the failure this exists to prevent, so it is not something a
construction site can opt into by omission.

## Not done yet

- **Preview/confirm.** Deletion is irreversible and now also revokes. The
  operator should see what is about to be destroyed and revoked before it
  happens, in the shape backup import's descriptor flow already uses.
- **The remaining cascades.** Classified but not yet executed: vault, consent,
  task_consent, app_state, memory, outbox, cache, passkey_vms, imported_secrets.
  The census names them; the code does not clear them yet.
- **The remaining blockers.** `service_state` / `service_prev_config`, `policy`
  and `consent_approvers` are classified `Blocks` but only the context and
  self-DID checks are implemented.
- **Resumability (R2.1).** The daemon delete still happens before local cleanup
  with no idempotency key, so a failure between them leaves the daemon-side
  orphan the code already warns about.
