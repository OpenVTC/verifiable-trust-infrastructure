# Design note: a backup is the whole agent, and restores anywhere

Status: **Implemented**
Requirements: VTI-VTA-001, VTI-VTA-050, VTI-VTA-051, VTI-KEY-033
Related: `backup-descriptor-pattern.md` (the transfer), `tee-anti-rollback-anchor.md`
(P0.2), `tee-dual-unlock.md` §8, `internal-keys` (`docs/02-vta/internal-keys.md`)

## 1. What was wrong

Two defects, found together, each enough to make a backup worthless when it
matters.

**A backup was not the agent.** Export was a set of hand-written collectors for
six keyspaces (`keys`, `acl`, `contexts`, `audit`, `imported_secrets`, `webvh`).
`vta_keyspaces::BACKED_UP` meanwhile listed sixteen, and a census test held that
list complete — so the census passed while ten of the keyspaces it vouched for
(`audit_key`, `consent`, `consent_approvers`, `memory`, `room_groups`,
`room_invitations`, `app_state`, `persona`, `policy`, `task_consent`) were never
exported. Three more (`vault`, `did_templates`, `issued_credentials`) were
openly excluded as "known backup gaps". A restore came back without the holder's
vault, their persona, their room keys, their policy.

**A backup could not be restored into an enclave.** The import rewrote the live
store in place and then committed the restored seed. In a TEE (and a hardened
VTA) the at-rest storage key is *derived from the seed*, so:

- Both import paths passed `store: None`, and the step that re-sealed the seed
  under KMS only ran `if let Some(store)` — it never ran. The enclave rebooted
  into its **old** seed with the restored key records, which derive to nothing.
- Had it run, the restored rows were written under the *old* storage key and the
  reboot derived the *new* one: nothing decrypts.
- The re-seal rewrote three KMS ciphertext rows one at a time; a crash between
  them bricked the enclave.
- The restore overwrote the ACL but left a never-claimed Mode-B carve-out open.

Restoring a TEE backup onto a normal VTA, or the reverse, failed for the same
reasons plus a few of its own: identity written only into in-memory config
(lost at the next process restart), the enclave's identity rows (`tee:vta_did`)
carried to a VTA that ignores them, and the persona correlation index keyed by
a hash of the storage key, so every lookup missed on the target.

## 2. The backup: every row, by construction

Export walks `BACKED_UP` and dumps every row of every keyspace, decrypted, into
`BackupPayload::keyspaces` (format `vta-backup-v2`). No keyspace has its own
code path, so listing one is the same as backing it up, and
`every_backed_up_keyspace_survives_a_round_trip` plants a row in each keyspace
of `ALL` and asserts exactly the `BACKED_UP` ones come back.

The partition is now **inclusion by default**. Excluded, each for a stated
reason: `internal_keys` (§6), `sessions`, `cache`, `backup_bundles`,
`passkey_vms`, `bootstrap`, `outbox`, `idempotency`, `relationships`. Everything
else — including the vault, templates, issued credentials, service state, drains
and the sealed-bootstrap nonce log — travels.

Within a carried keyspace, a handful of rows belong to the *deployment* rather
than the agent (`ENVIRONMENT_BOUND_ROWS`): the enclave's identity mirror and
carve-out (`keys ▸ tee:*`), the hardened JWT row (`keys ▸ hardened:*`), restore
bookkeeping, cached daemon tokens, and the blinded persona indexes. Export leaves
them behind; the restore writes the target's own. An import refuses a payload
that carries one, or that names a keyspace outside `BACKED_UP` — a backup is
attacker-supplied input to a super-admin, and a dump naming `bootstrap` or
`internal_keys` would otherwise write straight into an enclave's boot material.

Rows are read key-by-key rather than in one scan: in an enclave the store is a
vsock proxy with a 16 MiB frame, which a long audit trail outgrows.

The v2 envelope binds its unencrypted metadata (format, source DID,
`includes_audit`, salt, nonce) into the AES-GCM associated data, so the fields
an operator reads before typing a password cannot be swapped onto another
backup. v1 backups still restore.

## 3. The restore: staged, committed, applied at boot

A restore cannot be applied in place, because the key every row must be written
under is a function of a seed the running process does not have yet. So an
import does three things and no more (`vta_support::restore_stage`):

1. **Stage** the decrypted payload in the unencrypted `bootstrap` keyspace,
   sealed under `HKDF(restored seed, restore id)`, in ≤1 MiB chunks.
2. **Commit** the restored seed the target's way (`RestoreCommitter`): the
   secret store for a plain or hardened VTA; for an enclave, one KMS-sealed row
   holding the data-key, seed and JWT ciphertexts.
3. **Reboot** — a re-exec of the binary, since nothing restarts an enclave's
   process from outside and a soft restart keeps the old storage key.

Each binary, as soon as it knows its seed and storage key and before anything
else reads the store, opens the stage under that seed and applies it: wipe every
keyspace but `bootstrap`, write the rows, write the deployment rows, rebuild the
persona indexes, drop the stage.

**Crash consistency needs no sentinel.** The stage opens only under the
restored seed, so it opens only after step 2. Interrupted before the commit: the
next boot cannot open it, discards it, and the VTA is untouched (the running
store was never written). Interrupted after: the stage opens and is applied;
applying is wipe-then-write and the stage is dropped last, so an interrupted
apply simply runs again. The enclave's secrets row is honoured only when the
stage opened under the seed *inside* that row names the row's digest in its
authenticated metadata; its adoption rewrites the regular ciphertext rows and is
repeated until the row is dropped.

**A stage is applied only by the kind of deployment it was committed for.** A
hardened stage booted as plain (config changed in between) refuses, rather than
writing the identity and JWT key where that deployment does not look.

## 4. What the target writes

| Target | Identity | JWT key | Also |
|---|---|---|---|
| plain | `config.toml` `vta_did` (saved) | `config.toml` | public URL, mediator from the backup |
| hardened | `config.toml` `vta_did` (saved) | `keys ▸ hardened:jwt_key` | as plain |
| TEE | `keys ▸ tee:vta_did`, `tee:did_log` (+ bootstrap copy) | KMS row, at commit | carve-out closed; manifest re-baselined |

An enclave's config is delivered by the parent at every boot and a stored
identity wins over it (`did_autogen`), so the store is the only place a restored
identity sticks. Its public URL and mediator come from its own overlay; if they
differ from the restored DID document, the document and the deployment disagree,
and fixing that is a deployment change.

## 5. Anti-rollback (TEE)

A staged restore sitting in the parent-controlled `bootstrap` keyspace is a
replay vector: keep a copy, put it back after the restored VTA has moved on, and
the next boot would "restore" the agent to the past. With the external counter
(P0.2b/c) configured:

- **At commit**, the counter for the restored identity is **reserved**: for the
  identity the enclave already runs as, by a final live seal (after which covered
  mutations are refused until the reboot); for another identity, by moving its
  counter on by one (or creating it). The reserved version goes into the stage's
  authenticated metadata.
- **At boot**, the restore leaves a re-baseline instruction in the encrypted
  `keys` keyspace, and `integrity::rebaseline_after_restore` seals the manifest
  at the reserved version — only if the counter is still exactly there. A replay
  finds it elsewhere and the boot refuses.

Without the counter (P0.2a), a consistent replay is the level's accepted
residual risk, exactly as for any snapshot.

A restore onto a different identity's enclave moves that identity's counter:
if the old enclave for it is somehow still running, its next covered mutation
fails closed. Two live instances of one identity is the thing to prevent.

## 6. Internal keys

Internal keys stay out of every backup. Their point is that nobody — including
whoever holds the mnemonic or a backup — can obtain them, and a backup that
carried them would make that false (the eIDAS sole-control position). Deriving
them from the seed was considered and rejected for the same reason: it would
make them ordinary derived keys.

What changed is that the loss is no longer silent. The backup lists the internal
keys it did not carry (`internal_keys_not_carried`); preview and the import
result name them; the restore reports them in its provenance. A restore onto the
VTA that took the backup keeps its internal keys (same storage key, material
still there); anywhere else the records come back without material and cannot
sign.

## 7. Identity replacement

Restoring a backup of DID *A* onto a VTA running as DID *B* is refused unless the
operator says `--replace-identity` (`ImportRequest::replace_identity`,
`ext["org.openvtc"].replaceIdentity` on the Trust Task). Disaster recovery needs
it — `vta setup` mints a DID, and an enclave with a DID template mints one at
first boot, so a fresh target always has an identity of its own. When it is
used, hosted-DID registrations are detached (they belong to the source's
server slot — `webvh-rest-auth-audit.md` §H3) and the provenance lists them.

## 8. Reporting (VTI-VTA-051)

The restore writes `keys ▸ restore:provenance` — when, from which DID and kind of
deployment, who committed it, what did not come back. The first boot with an
audit sink records a `backup.restore.applied` row (the trail is part of what the
restore replaced, so the restore cannot record itself), and
`GET /health/details` reports `restored`.

## 9. Not done

- **A restore is not an escrow.** Recovery from a lost KMS key or lost enclave
  storage needs a backup taken before the loss. The first-boot mnemonic export
  remains the other path.
- **Dual unlock** (`tee-dual-unlock.md`) is unaffected: the commit seals the
  seed KMS-only, as a fresh enclave does. That note's §8 constraint — a restore
  must not downgrade a dual-unlock enclave — binds whenever dual unlock lands.
