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
  `schemas`, `endorsements`, and `audit_key`. The `audit` log is included only
  when you pass `include_audit: true`.
- **The signing key bundle** — so the backup is a *complete* disaster-recovery
  artifact: a restore re-establishes the VTC's ability to sign (status-list
  re-issue, VMC minting), not just its data.
- **An identity/config snapshot** — `vtc_did`, `vtc_name`, `vta_did`,
  `public_url`, messaging, and the JWT signing key.

> **The backup contains the signing key.** Treat the exported file like a
> secret: it is encrypted with your password (Argon2id + AES-256-GCM), but
> anyone who learns the password can sign as this community. Store it
> accordingly and use a strong password (minimum 12 characters).

**Not** in a backup (re-established after a restore, not carried): live
`sessions`, browser `passkey` credentials, one-shot `install` tokens, the
re-syncable `registry_records`, the `sync_queue`/`sync_cursor`, and the `config`
keyspace overlay (its meaningful values ride in the identity snapshot above).

## Export

```sh
# Prompts for the encryption password (min 12 chars), writes
# vtc-backup-<slug>-<timestamp>.vtcbak.
cnm backup export [--include-audit] [--output FILE]
```

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
then re-enrol a passkey for browser SPA access.

### Interrupted imports

The import stamps a sentinel before it starts clearing and removes it only on
success. If the process dies mid-import, the next boot **refuses to start** (the
datastore is half-restored) and tells you to re-run the import with the same
backup to finish it.

## Limits

- Import request body cap: **64 MiB**. A community with a very large audit log
  may exceed it — export with `include_audit: false` (the community state itself
  is far smaller).
- Crypto: Argon2id (64 MiB / t=3 / p=4) + AES-256-GCM. Wrong password or a
  tampered envelope fails closed (401).

Design rationale + the keyspace partition: `docs/05-design-notes/vtc-backup-restore.md`.
