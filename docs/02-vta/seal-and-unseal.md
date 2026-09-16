# Sealing and Unsealing the VTA

The **seal** is a single row in the VTA's fjall store (`vta:sealed` in
the `acl` keyspace) that the offline CLI checks before any state-
mutating command. While the seal is present, commands like `vta acl …`,
`vta keys …`, `vta import-did`, `vta contexts create`,
`vta contexts reprovision`, and `vta bootstrap provision-integration`
all refuse to run. Management has to flow through the running daemon's
REST or DIDComm API (which are gated by JWT auth, not by the seal — the
daemon ignores the marker entirely).

The seal is **not** a cryptographic lock. In non-TEE deployments anyone
with disk access to the data directory could delete the row by hand.
It's a deliberate "if you're here, you should be using the API, not the
offline CLI" gate — a guard against accidental or malicious offline
mutations after the deployment is supposed to be running through the
API. In TEE deployments the marker is AES-256-GCM encrypted with the
enclave's storage key, which gives the seal real teeth: an attacker on
the parent EC2 instance can't read or modify it.

## When the seal is set

Two paths set the seal automatically:

| Trigger | Resulting state |
|---|---|
| `vta setup --from <file>` **with `admin_did = "…"`** in the TOML | Setup mints DIDs, seeds the supplied DID as super-admin, then seals. |
| `vta bootstrap-admin --did <did:…>` after `vta setup` | Seeds a super-admin and seals as a separate step. |

If `admin_did` is omitted from the setup TOML (and `vta bootstrap-admin`
isn't run), the VTA finishes setup **unsealed with an empty ACL** — the
offline CLI remains fully usable. This is the recommended state for the
window where you're provisioning the mediator, did-hosting-daemon, or any
other integration that needs the VTA to mint keys and seal bundles.

## When the seal is in your way

Any of these would fail with `Error: configuration error: VTA is sealed
(by did:… on …)`:

- `vta contexts reprovision …` — sealing a bundle for the mediator's
  Phase 2.
- `vta bootstrap provision-integration …` — sealing a bundle for a
  did-hosting-daemon or other template-driven integration.
- `vta contexts create …`, `vta acl …`, `vta keys …`,
  `vta import-did …` — any state-mutating offline command.

The fix is either to unseal (below) or — much better — **don't seal
yet**: defer admin seeding until after you've finished offline
bootstrap work.

## Recommended bootstrap order: seal last

Set up the VTA without `admin_did`, do all the offline provisioning
while it's still open, *then* seed the admin and seal. This avoids the
unseal dance entirely:

1. `vta setup --from vta-setup.toml` with `admin_did` **omitted**
   → unsealed, ACL empty.
2. Provision the mediator: `mediator-setup` Phase 1 →
   `vta contexts reprovision …` → `mediator-setup` Phase 2.
3. Provision the did-hosting-daemon: `did-hosting-daemon setup-offline-prepare` →
   `vta contexts create webvh …` →
   `vta bootstrap provision-integration …` →
   `did-hosting-daemon setup-offline-complete`.
4. Provision any other integrations the same way.
5. Mint or import the admin identity (`pnm setup --name <slug>` is the
   common case) and register it: `vta import-did --did <admin> --role
   admin`. Or, if PNM lives on a different host, just `vta import-did`
   with the externally-supplied DID.
6. **Optionally** seal now: `vta bootstrap-admin --did <admin>`. Skip
   this if you're happy leaving the offline CLI usable; the running
   daemon's auth gates production work regardless of seal state.

This sequence is also why `pnm setup` doesn't have to be the first step.
PNM only matters once you want an authenticated client against the
running VTA — it doesn't participate in offline provisioning.

## If you do need to unseal

`vta unseal` runs an offline challenge-response: the VTA prints a random
32-byte challenge, the operator signs it with the super-admin's Ed25519
private key, pastes the signature back. The VTA verifies, removes the
marker.

```bash
cd /path/to/vta
vta unseal
```

The prompt looks like:

```
=== VTA Unseal Challenge ===

  Sealed by: did:key:z6Mk…
  Sealed at: 2026-05-13 11:42:08 +08:00

  Authorized super admin DIDs:
    - did:key:z6Mk… (pnm-bootstrap)

  Challenge (hex):
  9f3a1c…

  Sign this challenge with your super admin key. Either:

    pnm auth sign-challenge 9f3a1c…                                      # online: signs with PNM's stored admin key
    vta auth sign-challenge --did <admin-did> --challenge 9f3a1c…        # offline: signs from this VTA's local keystore

  Then paste the signature (hex) and your DID below.

  Admin DID:
```

Open a **second terminal** to produce the signature, paste it back into
the prompt, and `vta unseal` removes the seal.

### Which signer command to use

Pick the signer that has the admin's private key:

| Signer | Where the private key lives | When to use |
|---|---|---|
| `pnm auth sign-challenge <hex>` | PNM's OS keyring on this (or another) host. | The admin DID was minted by PNM (the common case for operator-driven setup). |
| `vta auth sign-challenge --did <did> --challenge <hex>` | This VTA's local fjall keystore. | The admin DID was minted by the VTA itself (e.g. `vta create-did-key --admin`). |
| Any external Ed25519 signer (Python script, `ssh-keygen -Y sign`, KMS, hardware token, …) | Wherever you keep it. | Air-gapped admin, no PNM, hardware-token deployments. |

The wire format is intentionally simple: **raw Ed25519 signature over the
32-byte challenge, hex-encoded.** No domain tag, no envelope. Any
Ed25519 signer with access to the admin private key can produce it:

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED_HEX))
print(sk.sign(bytes.fromhex(CHALLENGE_HEX)).hex())
```

### After unsealing

The VTA prints `Re-seal when done: vta bootstrap-admin --did <admin>` as
a hint. It's not mandatory — `vta bootstrap-admin` will refuse if a
super-admin already exists, so the literal re-seal command is actually a
different one (just clear the marker via a sealed/unseal cycle, or run
`vta bootstrap-admin` only after first running through the rest of the
admin lifecycle). In most production setups, once the daemon is up and
running you never touch the offline CLI again, so the seal state stops
mattering.

## Gotchas

### The admin private key has to be somewhere

`vta unseal` verifies a signature; it doesn't have one to give. The
private key for the super-admin DID has to live in PNM, in the VTA's
local fjall (only if the VTA itself minted the admin), in a hardware
token, or in some other signer you trust. If you sealed with an
externally-supplied `admin_did` (S08-style) **and** then lost the PNM
keyring on the host that minted it, the only path back is restoring
from a backup — `pnm backup import <file>` against the running VTA as a
super-admin — which doesn't traverse the seal. (There is no offline
`vta backup` command; restore always goes through a running VTA.)

### `vta auth sign-challenge` only works for `did:key:` admins minted by this VTA

The verifier behind `vta unseal` only accepts `did:key:` admin DIDs.
Beyond that, `vta auth sign-challenge` reads the key record from the
VTA's *own* fjall keystore — so it only works when the VTA was the
mint. Admin DIDs minted by PNM (which is the default when you write
`admin_did = "<pnm DID>"` in `vta-setup.toml`) live in PNM's keyring,
not the VTA's, and `vta auth sign-challenge` will fail with `no key
record found for <did> in this VTA's keystore`. Use
`pnm auth sign-challenge` instead, on whichever host PNM lives on.

### `vta unseal` and `vta auth sign-challenge` open the same data dir

fjall takes an exclusive lock on the data directory per process. Until
recently, `vta unseal` held that lock the whole time it was waiting for
the operator to paste a signature, which meant
`vta auth sign-challenge` in a second terminal failed immediately with
`FjallError: Locked`. The current implementation releases the lock for
the duration of the interactive prompt (read seal + ACL → drop → wait
on stdin → reopen → remove seal), so the two commands now coexist
cleanly. Older builds may still exhibit the conflict — workaround is to
use `pnm auth sign-challenge` (which lives in a different keyring and
never touches the VTA's fjall).

### The daemon ignores the seal — don't rely on it for live security

The seal only gates the *offline CLI*. While the VTA daemon is running,
all the same mutations are available via authenticated REST/DIDComm and
are gated by ACL roles, JWT expiry, and audit logging. Don't think of
the seal as part of live access control — it's a setup-time guardrail.

## Related

- [`non-interactive-setup.md`](non-interactive-setup.md) — `vta setup
  --from <file>`, including the `admin_did` field that triggers
  auto-seal.
- [`cold-start.md`](cold-start.md) — the interactive walkthrough, which
  reaches the same end state through prompts.
- [`provision-integration.md`](../02-vta/provision-integration.md)
  — the offline integration-provisioning flow whose `reprovision` /
  `provision-integration` subcommands trip the seal.
- [`security-model.md`](../01-concepts/security-model.md) — Layer 6 of
  the defense-in-depth model.
