# Backing up and restoring a VTA

A backup is the whole agent: its master seed, JWT signing key, and every row of
every keyspace that is the agent's state — keys and contexts, ACL, audit trail
and its keys, the holder's vault and credentials, persona, memory, application
state, room keys, policy, consents, DID templates, issued credentials, hosted-DID
records and service state. It is encrypted with a password you choose
(Argon2id + AES-256-GCM, at least 15 characters) and is useless without it.

A backup restores into **any** kind of VTA from **any** kind:

| from ╲ to | plain | hardened | Nitro enclave |
|---|---|---|---|
| plain | ✓ | ✓ | ✓ |
| hardened | ✓ | ✓ | ✓ |
| Nitro enclave | ✓ | ✓ | ✓ |

## What is not in a backup

- **Internal keys** (`pnm keys create --internal`). They are generated inside the
  VTA and never leave it — not in a backup, not in the mnemonic. That is their
  whole point. Their records are restored; their material is not. Preview and the
  import result name them, and restoring onto any VTA other than the one that took
  the backup leaves them unable to sign. See [internal-keys.md](internal-keys.md).
- Runtime state that is re-established on its own: sessions, caches, in-flight
  backup transfers and passkey enrolments, the messaging outbox, idempotency
  records, TSP relationships.

## Taking a backup

```bash
pnm backup export --include-audit -o vta-backup.vtabak
```

`--include-audit` carries the audit trail. The file is written `0600`. Store it
and its password separately.

## Restoring

```bash
pnm backup import vta-backup.vtabak --preview   # decrypt and count, change nothing
pnm backup import vta-backup.vtabak
```

The import is committed, then **the VTA restarts itself** to apply it. The
restore takes effect on that boot, not before; the store is untouched until then.
Once it is back, `GET /health/details` reports `restored`: when, from which DID
and kind of deployment, and anything that did not come back.

### Onto a freshly set-up VTA (disaster recovery)

A fresh VTA already has a DID of its own — `vta setup` mints one, and an enclave
with a DID template mints one at first boot. A backup of a *different* DID is
refused unless you say so:

```bash
pnm backup import vta-backup.vtabak --replace-identity
```

The restored VTA then runs as the backup's DID. DIDs it hosted on a DID-hosting
server are detached from that server (the registration belongs to the old
instance); re-attach each with `pnm did-mgmt dids register --did <did> --server <id>`.

The restored DID document advertises the public URL and mediator the backup's VTA
used. A plain or hardened VTA takes both from the backup. An enclave takes them
from its own configuration — if they differ, update the deployment (or the DID)
so the two agree.

### Into a Nitro enclave

Nothing extra. The restored seed and JWT key are sealed under the enclave's KMS
key at import, and the enclave re-executes itself to apply them. On the next boot
it:

- adopts the sealed secrets,
- writes the restored identity into its store (where it wins over the
  parent-delivered config),
- closes the single-use Mode-B carve-out — the restored ACL is the authority,
- re-baselines its integrity manifest at the anti-rollback version reserved when
  the import was committed. A copy of that restore replayed later is refused.

If KMS is unreachable on that boot, the enclave refuses to boot rather than drop
a committed restore; restore KMS reachability and boot again.

### If the restore is interrupted

- **Before it is committed:** nothing changed. The staged data cannot be opened
  without the restored seed, and the next boot discards it.
- **After:** every boot applies it until it has been applied completely.

## Requirements

- `pnm` must reach the VTA over DIDComm or TSP. A backup export or import is
  refused over REST and over Trust Tasks on HTTPS, because the backup password
  would exist in plaintext wherever TLS terminates, next to the bundle it opens.
  Only the encrypted bundle bytes may move over HTTPS.
- A plain or hardened VTA must keep its seed in a store that survives a restart
  (keyring, a cloud secret manager, Vault, Kubernetes). A restore into one that
  cannot is refused before anything changes.
- A restore is applied only by the same kind of deployment it was committed on.
  Do not change `[hardened] enabled` or move to an enclave between the import and
  the restart.

Design and rationale: [backup-restore-portability.md](../05-design-notes/backup-restore-portability.md).
