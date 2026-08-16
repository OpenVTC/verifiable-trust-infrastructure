# Internal (non-extractable) keys

An **internal key** is a signing key the VTA generates from the system CSPRNG,
uses only as a signing oracle, and **never gives out** — not to an operator, not
to an admin, not to a backup, not to anyone holding your mnemonic.

It exists to make one sentence true:

> The private key can be used only by this VTA, and cannot be obtained by
> anybody, including whoever runs it.

That is the property eIDAS calls **sole control**, and it is the half the VTA
otherwise fails: an ordinary derived key can always be reconstructed from the
24-word mnemonic, which is exactly what makes the VTA recoverable *and* what
makes "the operator cannot obtain this key" false.

Internal keys buy that property at a price that is permanent and worth
understanding before you mint one.

---

## ⚠ An internal key cannot be recovered. Ever.

There is no derivation path, no backup copy, and no mnemonic that reproduces it.

- **Your BIP-39 mnemonic will not recover it.** It is not derived from the
  master seed. That is the entire point — if it were, anyone with the 24 words
  could reconstruct it offline and the guarantee would be decorative.
- **It is excluded from `pnm backup export`.** A backup that carried it would be
  an export of a key the VTA promises never to export, and restoring that backup
  elsewhere would silently clone a signer.
- **No surface returns it.** The key-export API refuses it, and so does the
  internal-authority path used by the VTA's own subsystems.

If this VTA's storage is lost, every signature that key was the sole authority
for becomes unproducible, permanently. Nothing recovers it.

**Plan for that before you mint one**, not after.

---

## When to use one

**Good fit** — losing the key costs you the ability to *produce new signatures*,
and the thing it signs can be re-issued or re-established:

- A signing `verificationMethod` published in a DID document.
- An issuer key whose credentials can be re-issued under a replacement key.
- A holder key for credentials that an issuer would re-issue.

**Wrong fit** — losing the key costs you *control of an identity*:

- **`did:webvh` log entries.** The VTA refuses this outright, and the refusal is
  enforced in code rather than left to guidance. WebVH is append-only: each
  entry is authorised by the update key the previous entry named. If an
  unrecoverable key were the update key and storage were lost, the DID could
  never be updated again *by anyone*, permanently, and every integration pinned
  to it would be stranded. Re-issuing something does not fix that.

The distinction is not "how important is this key" — it is **"if it vanishes, is
there a path back?"** Credentials have one. An append-only identity log does
not.

---

## Durability, and what actually protects you

Because there is no mnemonic path, durability comes entirely from the storage
the key lives in.

**In a TEE deployment**, keys are sealed to the enclave **measurement**, not the
enclave instance. A fresh enclave running the same image, with access to the
same KMS key, unseals the same storage — so replication and image upgrades work.
`deploy/nitro/setup-kms-policy.sh --old-pcr0 <hash>` authorises both the current
and previous measurement during a rolling upgrade, which is what makes a rebuild
an ops step rather than a data-loss event. This is the same shape as HSM-to-HSM
backup under a domain key: the key never exists in plaintext outside a boundary
of the same class.

The two things that genuinely destroy an internal key are therefore:

1. **Losing the KMS key.** Enable key-deletion protection; consider
   cross-region replication. Once keys cannot be re-derived from a mnemonic,
   this is your only copy.
2. **Losing sealed storage without a replica.**

**In a non-TEE deployment**, at-rest protection is whatever the keyspace
encryption is configured to be, and an operator with disk access is inside that
boundary. Internal keys still meaningfully raise the bar against *export* — no
API returns them and no backup carries them — but they do not by themselves make
a non-TEE VTA tamper-proof. Treat non-TEE internal keys as good hygiene, and TEE
internal keys as an enforceable property.

---

## Using them

```bash
pnm keys create --key-type ed25519 --internal --context my-app
```

The CLI prints the full warning and requires you to type the confirmation
phrase. `--yes` skips the prompt for automation — use it only where the
consequence is already understood and recorded.

An internal key **requires an explicit `--key-id`-equivalent identity**: it has
no derivation path to be named after, and minting an unrecoverable key under a
generated name the operator never chose is a good way to lose it.

Signing works exactly as it does for any other key:

```bash
pnm keys sign <key-id> --payload <data> --algorithm eddsa
```

Supported types are **ed25519** (EdDSA) and **p256** (ES256). X25519 is refused:
it is a key-agreement key, and an internal key that cannot sign would be
unusable *and* unrecoverable.

---

## What the VTA enforces

| Surface | Internal key |
|---|---|
| `keys/sign` (REST, DIDComm, Trust Task) | **Allowed** — the only use |
| Key export (`get_key_secret`) | **Refused**, including for super-admin |
| Internal-authority export | **Refused** |
| `pnm backup export` | **Excluded** — the keyspace is not backed up |
| `did:webvh` log entry signing | **Refused** |
| DID document `verificationMethod` | **Allowed** |

The export refusal is not a permission check. Admin is not a bypass, because the
whole value of the origin is that *no* caller holds this power — treating it as
an authorization question would be the wrong shape. Deleting both refusals does
not compile: the match over `KeyOrigin` becomes non-exhaustive, so an export
path cannot silently reopen.

---

## See also

- `vta-keys/src/internal.rs` — the storage and signing implementation, and why
  it is deliberately not built on the imported-key path (which wraps under a
  seed-derived KEK).
- `docs/02-vta/tee-architecture.md` — sealing, measurements, and KMS policy.
