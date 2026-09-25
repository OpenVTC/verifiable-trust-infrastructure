# Backup & restore

The VTC holds a community's irreplaceable social state — members, ACL,
endorsements, relationships, policies, the audit log, and the bitstring
**status lists** whose loss bricks every issued VMC's `credentialStatus`.
`POST /v1/backup/export` and `POST /v1/backup/import` capture and restore that
state in a single password-encrypted artifact.

Both endpoints are **super-admin only**.

## What's in a backup

A backup is a JSON envelope (`format: "vtc-backup-v1"`) whose `ciphertext` is the
AES-256-GCM encryption of:

- **Community state** — every backed-up keyspace, dumped row-for-row: `acl`,
  `community`, `members`, `join_requests`, `policies`, `active_policies`,
  `status_lists`, `relationships`, `relationships_by_did`, `endorsement_types`,
  `schemas`, `endorsements`, `vetting_revocations`, `vetter_profiles`, and
  `audit_key`. The `audit` log is included only
  when you pass `include_audit: true` — and when it is, its signed checkpoints
  (`audit_checkpoint`) come with it. That pairing is not optional: a log
  restored without its checkpoints holds fewer entries than every signed
  checkpoint attests to, so `cnm audit verify` would report the restore as
  **truncation**.
- **The signing key bundle** — so the backup is a *complete* disaster-recovery
  artifact: a restore re-establishes the VTC's ability to sign (status-list
  re-issue, VMC minting), not just its data.
- **An identity/config snapshot** — `vtc_did`, `vtc_name`, `vta_did`,
  `public_url`, messaging, and the JWT signing key.

> **The backup contains the signing key.** Treat the exported file like a
> secret: it is encrypted with your password (Argon2id + AES-256-GCM), but
> anyone who learns the password can sign as this community. Store it
> accordingly and use a strong password (minimum 15 characters).

**Not** in a backup (re-established after a restore, not carried): live
`sessions`, browser `passkey` credentials, one-shot `install` tokens, the
re-syncable `registry_records`, the `sync_queue`/`sync_cursor`, the `config`
keyspace overlay (its meaningful values ride in the identity snapshot above),
`accepted_ids` — the Trust Task replay record, whose whole horizon is the
minutes-long acceptance window, so a restored row is expired before it is read —
and `console_keys`, the admin console's signing-key delegations.

That last exclusion is a security decision rather than a housekeeping one. A
delegation names a browser profile on a particular machine; a restore — into a
rebuilt host, a staging clone, or a different operator's hands — must not hand
that browser the ability to sign as an administrator again. Operators re-enrol
from the browser they are actually sitting at, behind the same passkey step-up
the first enrolment cost. Nothing else is lost: the ACL rows, the passkeys and
the bearer login all come back with the backup.

## Export

`cnm backup` signs in to the VTC as the community profile's own DID, which must
hold a super-admin row in the VTC's ACL, and needs the profile to name the VTC
(`cnm community set-vtc <vtc-did>`). See the
[bootstrap runbook](bootstrap-runbook.md#cnm-needs-its-own-super-admin-row).

```sh
# Prompts for the encryption password (min 15 chars), writes
# vtc-backup-<slug>-<timestamp>.vtcbak.
cnm backup export [--include-audit] [--output FILE] [--force]
```

The file is created readable by its owner only (`0600` on Unix, an owner-only
ACL on Windows). An existing file is never overwritten unless you pass
`--force`.

Under the hood this is `POST /v1/backup/export` (super-admin) — to script it
directly:

```sh
curl -sS -X POST https://vtc.example.com/v1/backup/export \
  -H "Authorization: Bearer $SUPER_ADMIN_JWT" \
  -H 'Trust-Task: https://trusttasks.org/openvtc/vtc/backup/export/1.0' \
  -H 'Content-Type: application/json' \
  -d '{"password":"correct-horse-battery-staple","include_audit":true}' \
  > vtc-backup.json
```

## Restore

Restore is a two-step **preview → confirm** to prevent fat-finger overwrites.

```sh
# Shows the backup's metadata + per-keyspace row counts, then asks you to
# type "yes" before applying. `--preview` stops after the counts.
cnm backup import vtc-backup-<slug>-<timestamp>.vtcbak [--preview]
```

Equivalent REST (the CLI just drives these two calls):

```sh
# 1. Preview — decrypts, checks identity, returns per-keyspace row counts.
#    Mutates nothing.
curl -sS -X POST https://vtc.example.com/v1/backup/import \
  -H "Authorization: Bearer $SUPER_ADMIN_JWT" \
  -H 'Trust-Task: https://trusttasks.org/openvtc/vtc/backup/import/1.0' \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --slurpfile b vtc-backup.json \
        '{backup:$b[0], password:"correct-horse-battery-staple", confirm:false}')"

# 2. Apply — clears the backed-up keyspaces and replays the backup.
#    Same body with confirm:true.
```

After a successful import, **restart the daemon** so it serves the restored
identity.

### Identity guard

- A **fresh install** (no `vtc_did` configured yet) accepts any backup — this is
  the disaster-recovery path.
- A **configured VTC** accepts a backup only if its `vtc_did` matches. A backup
  from a different community is refused with **409 Conflict**. To deliberately
  migrate identity, clear `vtc_did` from the running config first.

### Recovering admin access

Browser passkeys are not restored. After a restore, authenticate with your admin
DID key (the admin entry is in the restored `acl`) over the CLI / DIDComm path,
then re-enrol a passkey for browser SPA access. Members' step-up passkeys
(`step_up_passkeys`) are not restored either. An administrator invites each
member who needs one to enrol again (Members → the member → *Step-up
passkeys*).

### Interrupted imports

The import stamps a sentinel before it starts clearing and removes it only on
success. If the process dies mid-import, the next boot **refuses to start** (the
datastore is half-restored) and tells you to re-run the import with the same
backup to finish it.

## Signed documents: the chunked `backup/*` transfer

The two routes above take a bearer token. The same export and restore are also
served as signed Trust Task documents at `POST /v1/trust-tasks` (and over
DIDComm and TSP), authorized by the signer's ACL entry — an unrestricted
administrator's. A backup is too large for one document, so it moves as a
**bundle**, in chunks (the node-neutral `backup/*` family, shared with the VTA):

| step | task | what it does |
|---|---|---|
| export | `backup/initiate-export/0.1` | encrypts the community (as `/backup/export` does) and returns a manifest: chunk size, count, one digest per chunk, the whole bundle's SHA-256 |
| | `backup/get-chunk/0.1` | one chunk by index; repeatable until the bundle ends |
| | `backup/complete-export/0.1` | releases the bundle and deletes its staged bytes |
| restore | `backup/initiate-import/0.1` | commits to a manifest before any byte moves |
| | `backup/put-chunk/0.1` | one chunk, checked against its committed digest; a repeat is `stored: false` |
| | `backup/finalize-import/0.1` | checks every chunk is present and the assembled bytes are the committed ones, then previews (`confirm` absent) or applies (`confirm: true`) exactly as `/backup/import` does |
| either | `backup/abort/0.1` | cancels an open bundle |

Every request asks for `algorithm: chunkedTrustTask`; `stream` needs an HTTPS
blob endpoint this service does not publish and is refused
`transportUnavailable`. Chunks are at most **32 KiB** — the largest whose
`put-chunk` document fits what the door accepts before it checks a proof — so a
bundle may be up to 128 MiB. A bundle belongs to the administrator who opened it,
lives five minutes past its last use (never more than an hour), and at most three
may be open per administrator at once. Staged bytes live under
`<data_dir>/backups`, owner-only, and are swept when a bundle ends or expires.

**Over REST the transfer is rate-limited.** `/v1/trust-tasks` sits behind the
per-IP limiter on the unauthenticated chain (a burst of 10, then one request
every 5 s), which is roughly 12 chunks a minute — about 384 KiB a minute at full
chunk size. DIDComm and TSP are not behind that limiter; chunk requests there are
bounded per administrator (50 a second). For a large community, restore over a
messaging transport or use the bearer route above.

## Limits

- Bearer import request body cap: **64 MiB**. A community with a very large
  audit log may exceed it — export with `include_audit: false` (the community
  state itself is far smaller), or use the chunked transfer above.
- Crypto: Argon2id (64 MiB / t=3 / p=4) + AES-256-GCM. Wrong password or a
  tampered envelope fails closed (401).

Design rationale + the keyspace partition: `docs/05-design-notes/vtc-backup-restore.md`.
