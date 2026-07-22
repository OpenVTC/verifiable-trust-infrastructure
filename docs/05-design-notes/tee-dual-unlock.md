# Design note: dual-unlock for the TEE master seed

Status: **Draft — for review** (no code yet)
Owner: Glenn Gore
Last updated: 2026-07-22
Tracking: proposed follow-on to Phase-0 TEE hardening. Adjacent to **P0.2e**
(cross-account anchor, `tasks/vta-architecture-todo.md:110`) — same threat
actor, different asset. Sequenced after **P0.2c** (attestation-gated anchor
writer, #386 merged), because it reuses the same "seal a secret under the PCR
conditions" primitive.

Related code (current-state map, verified while writing this note):

- Seed/JWT/data-key ciphertexts: `vta-service/src/tee/kms_bootstrap.rs:72-75`
  (`bootstrap:data_key_ciphertext`, `bootstrap:seed_ciphertext`,
  `bootstrap:jwt_ciphertext`), written at `:184-191`, read at `:89-102`.
- **Storage-key derivation from the seed**: `kms_bootstrap.rs:110,199` →
  `derive_storage_key` (`:349-373`, HKDF-SHA256 over the KMS-decrypted seed).
  This is the main structural blocker — see §5.3.
- Bootstrap keyspace is **deliberately unencrypted**:
  `vta-service/src/keyspaces.rs:50-51` ("KMS-protected, unencrypted boot
  keyspace"). In enclave deployments it is fjall on EBS on the untrusted
  parent (`deploy/nitro/README.md:866`).
- Attested KMS calls: `kms_bootstrap.rs:477-530` (`kms_decrypt_data_key` /
  `kms_decrypt_attested`), `:568-629` (`kms_generate_data_key*`), recipient
  construction at `:398-425` (`nsm_attested_recipient`).
- KMS key policy generator: `deploy/nitro/setup-kms-policy.sh:140-186` —
  two statements only; `AllowKeyAdministration` grants `kms:Create*` and
  `kms:Put*` (`:150-165`), `AllowEnclaveAttestationOperations` is
  PCR0/PCR8-conditioned (`:168-184`).
- NSM attestation: `vta-service/src/tee/nitro.rs:58` (`NitroProvider::attest`,
  arbitrary `user_data` + `nonce`), `:165`
  (`request_nsm_attestation_for_kms`, currently `pub(crate)`).
- Attestation verification (client side): `vta-sdk/src/attestation/mod.rs:89`
  (`verify_nitro_assertion`), `:213` (`VerifiedAttestation::check_pcrs`,
  added by P3.4).
- HPKE seal/open + `Attested` producer assertion:
  `vta-sdk/src/sealed_transfer/` (`verify.rs:102-127` for the assertion
  variants).
- Existing `seal`/`unseal`: `vta-service/src/seal.rs` — an **authorization
  gate** on offline CLI commands, not a key split. See §3.
- Backup re-encrypt path: `kms_bootstrap.rs:217-253`
  (`re_encrypt_bootstrap_secrets`) — a silent-downgrade trap, see §8.
- One-shot timed secret export precedent: `vta-service/src/tee/mnemonic_guard.rs`
  (`new`/`empty`/`status`/`export`, zeroized on drop), gated on first boot
  only (`vta-enclave/src/main.rs:231-251`).
- Device side: `vta-mobile-core/src/push.rs:101` (`WakeHandle`);
  `keyspaces.rs` `PASSKEY_VMS`, `CONSENT_APPROVERS`.

---

## 1. Objective

Make the VTA master seed **unrecoverable from AWS KMS alone**, so that no
single administrative actor — specifically a KMS key administrator — can
extract it without a second, independently-held factor.

Concretely, after this work:

- A KMS key administrator who self-grants `kms:Decrypt` (via `kms:PutKeyPolicy`
  or `kms:CreateGrant`, both available to them today) and reads the bootstrap
  ciphertexts off the parent's EBS volume recovers **one share and nothing
  else**. The seed plaintext does not exist anywhere without the second share.
- Seed compromise stops being **silent**. An attacker in possession of the
  ciphertexts plus full KMS access must *interactively solicit* the second
  share, which produces an observable signal at a custodian the attacker does
  not control.
- Unattended enclave restart remains viable for the deployment shapes that
  need it (§5.6), rather than being traded away wholesale for confidentiality.

Non-objective: defending against AWS itself. The Nitro hardware root, the NSM
signing chain, and KMS's own validation of attestation documents remain
trusted. That floor is irreducible for anything running in someone else's TEE.

## 2. Background — the exact gap

The current chain (`kms_bootstrap.rs:81-205`):

```
seed (32B)  --AES-256-GCM(data_key)-->  bootstrap:seed_ciphertext
data_key    --KMS Encrypt----------->   bootstrap:data_key_ciphertext
storage_key = HKDF(seed, salt)          ← gates the entire fjall store
```

Both blobs sit in the `BOOTSTRAP` keyspace, which is intentionally unencrypted
(it is "KMS-protected"). In an enclave deployment that is a file on the
untrusted parent. Reading it is not an attack; it is expected.

So confidentiality of the seed reduces entirely to one question: *can anything
outside the enclave get KMS to decrypt `bootstrap:data_key_ciphertext`?*

For **root on the parent with the instance role**, the answer is no, and the
design is sound. `kms:Decrypt` is conditioned on `kms:RecipientAttestation:PCR0`
(+PCR8) (`setup-kms-policy.sh:168-184`); a bare `Decrypt` fails, and forging an
attestation document requires the AWS-signed NSM chain, unavailable outside a
real enclave. Re-running the genuine EIF does not help either: mnemonic export
requires `bootstrap.entropy` to be `Some`, which happens on **first boot only**
(`kms_bootstrap.rs:115` returns `entropy: None` on every subsequent boot), and
additionally requires a super-admin JWT (`routes/attestation.rs:161`).

For a **KMS key administrator**, the answer is yes, trivially. The
`AllowKeyAdministration` statement grants `kms:Create*` and `kms:Put*`, which
includes `kms:CreateGrant` and `kms:PutKeyPolicy`. Either is a self-grant of
unconditional `Decrypt`. Rotating `--pcr0` to an image of the attacker's
choosing works equally well. No attestation, no enclave, no VTA credentials,
and no interaction with the VTA at all.

This is not a defect in the key policy — it is inherent to KMS: whoever can set
the policy owns the key. `docs/02-vta/tee-architecture.md:499` already scopes
the guarantee correctly ("Holds within the operator's AWS-account trust root").
This note asks whether we can do better than that scoping.

Organizational controls (separate admin account + MFA, SCPs denying
`kms:PutKeyPolicy`/`kms:CreateGrant` on the key ARN, CloudTrail to an
append-only account) are strictly worth doing and are cheaper than everything
below — but each **relocates** the trusted party rather than removing it. This
note covers the cryptographic option.

## 3. The distinction that decides the design

There are two ways to build "the VTA needs a second thing to become fully
operational", and only one of them is worth building.

**Authorization gate.** KMS unwraps the full seed exactly as today; the VTA
boots into a restricted mode and refuses to serve until an operator presents a
token/signature/approval. This is the shape of the existing
`vta-service/src/seal.rs` (`require_unsealed`, challenge-response against a
super-admin key) — appropriate for what it does, which is deterring offline
CLI tampering.

Against the threat in §2 it is worth **nothing**. The attacker never runs our
binary. They read two files and call one API. A check placed in code the
adversary does not execute is not a control. Any variant that can be described
as "the VTA unlocks itself to full state" is this shape, and should be rejected.

**Cryptographic split.** The seed is not recoverable from the KMS share:

```
K_seed = HKDF-SHA256(IKM = kms_share ‖ device_share,
                     info = b"vta-dual-unlock/v1")
seed   = AES-256-GCM-open(K_seed, bootstrap:seed_ciphertext)
```

There is no gate to bypass because there is no plaintext to gate. A KMS
administrator obtains `kms_share` and 32 bytes of pseudorandom noise. Nothing
in the VTA's code participates in enforcing this.

**The rest of this note assumes the cryptographic split.** The "minimal VTA"
concept survives — but as a *consequence* of the split (some capabilities are
genuinely unavailable pre-unlock because their keys cannot be derived), never
as the mechanism.

## 4. Design space

### Option A — Authorization gate

Rejected, §3. Recorded here only so the distinction is on the record.

### Option B — Second share from an independent cloud/HSM

`device_share` is held in a second provider (GCP/Azure/Vault/on-prem HSM) and
fetched by the enclave at boot. `vti-secrets` already carries these backends
behind one factory, so the plumbing largely exists.

- **Pro**: fully unattended restart; no human in the boot path; scales to a
  fleet.
- **Con**: a second availability dependency on the enclave's critical boot
  path; only the AWS share is PCR-attested, so the second factor contributes
  confidentiality but not integrity; and it is still *an administrator*, just
  a different one — two colluding admins recover the seed, and the second
  provider's credentials live somewhere too.

### Option C — Device-held share, biometric-released, attestation-bound (recommended for high-value VTAs)

`device_share` lives in the operator's phone Secure Enclave / Android Keystore.
The booting VTA publishes an NSM attestation document; the device verifies it
(including pinned PCR0/PCR8), HPKE-seals the share to the ephemeral public key
committed in that document, and returns it. Biometric gates release of the
share from the device's secure hardware — the biometric is **not** key
material.

- **Pro**: the second custodian is a human with hardware-backed key storage,
  not another cloud administrator. Genuinely removes the single-administrator
  property. Turns silent compromise into an interactive one (§6).
- **Pro**: a ~2s FaceID prompt is operationally survivable in a way that
  "wake a custodian to fetch a Shamir share from a safe" is not. This is the
  distinction between HashiCorp Vault's manual unseal (which nobody tolerated
  in practice) and its auto-unseal (which reintroduces exactly the
  single-trust-root problem in §2).
- **Con**: one device is a single point of failure for VTA availability;
  needs k-of-n plus a genuinely offline escrow (§5.6).
- **Con**: introduces a prompt-phishing surface that must be closed by
  attestation binding, or the design is worse than useless (§7).

### Non-options (explicitly rejected)

- **Caching the device share on the parent** so restarts are unattended. The
  only storage surviving an enclave restart is the untrusted parent's disk;
  this returns us precisely to §2.
- **Auto-releasing escrow** (a Lambda/secret that hands over the share on
  request without human involvement). The escrow's credentials become the new
  single point — this is Option B with extra steps and worse honesty about it.
- **Deriving the second share from anything the enclave can recompute**
  (instance identity, PCR values, config). If the enclave can derive it, so
  can anyone holding the ciphertexts and the image.
- **Password/passphrase typed at boot.** Human-memorable entropy is a poor
  second factor against an attacker who has already exfiltrated the ciphertext
  and can grind offline at leisure.

## 5. Recommended design

Option C for high-value single VTAs, Option B for fleets. **They share one
primitive** — split-wrap of the seed — and differ only in who custodies
`device_share`. Build the primitive once; make the custodian pluggable.

### 5.1 Key hierarchy

Two tiers, rooted in two different secrets:

```
tier-1 root  = KMS data key (today's `bootstrap:data_key_ciphertext`)
                 ├── storage_key_t1  = HKDF(tier1_root, salt, info="storage/v1")
                 ├── jwt_signing_key (already a separate blob, :74)
                 └── transport identity key (see §5.4)

tier-2 root  = K_seed = HKDF(kms_share ‖ device_share, info="vta-dual-unlock/v1")
                 └── BIP-39/BIP-32 master seed
                       └── every context + signing key (m/26'/2'/…)
```

`kms_share` is the existing KMS-wrapped data key. Domain separation follows the
house convention (`CLAUDE.md`, sealed-transfer invariants): a new protocol gets
a **new info string**, never a version parameter.

### 5.2 Capability tiering

Pre-unlock, the VTA must be able to do exactly enough to receive the second
share, and no more:

| Capability | Tier | Rationale |
|---|---|---|
| Boot, bind listener, `/health` | 1 | must be reachable to be unlocked |
| Serve its NSM attestation document | 1 | this *is* its pre-unlock identity |
| Read/write non-sensitive keyspaces | 1 | needs `storage_key_t1` (§5.3) |
| Accept + open the sealed share | 1 | self-authenticating (§5.4) |
| Issue JWTs / authenticate operators | 1 | key already separate at `:74` |
| Derive any BIP-32 context key | **2** | the asset being protected |
| Sign as the VTA DID | **2** | unless transport identity split out (§5.4) |
| Provision integrations, issue VCs, sign oracle | **2** | all seed-derived |

A tier-1 VTA can prove *what it is* and cannot act *as itself*.

### 5.3 The storage-key problem (main structural blocker)

Today `storage_key = derive_storage_key(&seed, salt)` (`kms_bootstrap.rs:110,199`),
so the seed gates **every** keyspace. Under dual-unlock a pre-unlock VTA could
not read anything at all — including whatever it needs in order to be unlocked.

Required change: derive the storage key from the **tier-1** root, and wrap
tier-2-sensitive material under `K_seed` separately (either a key-wrapping
layer over the sensitive keyspaces, or per-keyspace tier assignment mirroring
the existing `BACKED_UP`/`EXCLUDED_FROM_BACKUP` partition in `keyspaces.rs`,
which is already pinned by a census test — the same pattern applies).

This is not a small change and it interacts with the anti-rollback anchor
(§8). It is the bulk of the implementation risk and should be sliced first.

### 5.4 Unlock protocol

The security boundary is **attestation binding**, not the transport. Two
transports, same cryptographic core:

1. Enclave generates an ephemeral X25519 keypair, requests an NSM attestation
   document over `user_data = H(ephemeral_pub ‖ vta_did ‖ unlock_nonce)`
   (`nitro.rs:58` accepts arbitrary `user_data`/`nonce` — reusable as-is;
   `request_nsm_attestation_for_kms` at `:165` is the closest existing shape
   and would be generalized rather than duplicated).
2. Enclave publishes the document and requests unlock (push via `WakeHandle`,
   `vta-mobile-core/src/push.rs:101`).
3. Device verifies the quote **and pins PCR0/PCR8** via
   `VerifiedAttestation::check_pcrs` (`vta-sdk/src/attestation/mod.rs:213`),
   displays what is being approved (VTA DID, PCR0, and prominently *whether
   PCR0 changed since last unlock*), and gates on biometric.
4. Device HPKE-seals `device_share` to `ephemeral_pub` — same suite as
   `sealed_transfer` (X25519-HKDF-SHA256 / ChaCha20-Poly1305), **new info
   string** `b"vta-dual-unlock/v1"`.
5. Enclave opens, computes `K_seed`, decrypts the seed, derives tier 2,
   zeroizes the share and the ephemeral private key.

Note `verify_nitro_assertion` (`attestation/mod.rs:89`) is currently bound to
the sealed-bootstrap triple `(client_ed25519_pub, nonce, producer_ed25519_pub)`.
The unlock flow commits to a different tuple, so this needs a generalized
verifier rather than a call-site reuse — flagged as concrete work, not a
blocker.

**A wrong share simply fails the AEAD tag.** No ACL lookup, no JWT, no
authorization decision is required pre-unlock. This dissolves the
chicken-and-egg of "authenticate the operator using keys that are still
locked", and is a direct consequence of choosing a key over a credential (§3).

**Transport choice.** `CLAUDE.md` mandates TSP > DIDComm > REST, and this flow
should honour it — but pre-unlock the VTA has no seed-derived DID keys. Two
sub-options:

- **Preferred**: put the VTA's *transport* identity (DIDComm/TSP VID) in
  tier 1, distinct from its seed-derived *issuing* identity. Unlock then runs
  over TSP/DIDComm like everything else, and the house rule is satisfied.
  Cost: the VTA DID's keys currently come from `did_autogen` off the seed;
  this needs a deliberate second identity.
- **Fallback**: an attestation-authenticated REST endpoint, needed regardless
  for first unlock and disaster recovery. This is a legitimate instance of the
  documented REST carve-out ("counterparties that can speak neither"), because
  pre-unlock the VTA genuinely cannot — but it must be justified in the PR,
  not assumed.

### 5.5 First boot and share generation

Mirror `MnemonicExportGuard` (`tee/mnemonic_guard.rs`): on first boot the
enclave generates both shares, seals `device_share` to the enrolling device,
and exposes it exactly once through a one-shot, time-boxed, zeroized-on-drop
guard. The existing guard's first-boot gating (`vta-enclave/src/main.rs:231-251`)
is the right precedent, including its `empty()` fallback so the code path
exists but yields nothing on subsequent boots.

### 5.6 Availability

Single-device custody makes one phone a single point of failure for the whole
VTA. Minimum viable: **2-of-3** over {primary device, secondary device, offline
escrow}. The escrow must be genuinely offline (sealed envelope, safe) — an
escrow that responds to requests is a non-option (§4).

Deployment guidance:

- **Single high-value VTA** (holds a community's issuing keys): Option C.
  Restarts are rare and planned; a human in the loop per restart is arguably a
  feature, and each unlock is an audit event.
- **Fleet** (`affinidi-vti-enm`): Option B, with humans only in the
  escrow/recovery path. Per-restart biometrics do not scale to N agents.

### 5.7 Config surface

Additions to `TeeKmsConfig` (`vta-service/src/config.rs:326-402`), following
the existing `allow_*` convention (`allow_unattested_fallback`,
`allow_kms_reinit`, `allow_fingerprint_init`, `allow_anchor_init`):

```toml
[tee.dual_unlock]
enabled = false                 # opt-in; default preserves today's behaviour
custodian = "device"            # "device" | "secret-store"
threshold = { k = 2, n = 3 }    # device custody only
unlock_timeout_secs = 900       # fail closed, do not serve degraded forever
allow_single_share_boot = false # break-glass; loud, refuses to stay quiet
```

`enabled = false` must be byte-compatible with today's on-disk layout, and
enabling it is a **migration** (§9 P1), not a flag flip.

## 6. What this changes in the threat model

New/changed rows for `docs/02-vta/tee-architecture.md:489`:

| Threat | Current | With dual-unlock |
|---|---|---|
| KMS key administrator self-grants `Decrypt` | **Seed recovered.** No VTA access needed | Recovers one share; seed remains sealed |
| CI/build role (`--build-admin`) rotates PCR0 to a hostile image | **Seed recovered** | Hostile image fails PCR pinning at the device; no share released |
| Root-on-parent with instance role | Already refused (attestation-gated) | Unchanged |
| Root-on-parent MITMs the unlock channel to steal the returned share | n/a (no such channel) | Refused — share is HPKE-sealed to a pubkey committed in an AWS-signed attestation document (§7.1) |
| Seed exfiltration is observable | **No** — silent and permanent | **Yes** — requires soliciting a custodian |

The last row is the qualitative change. Elsewhere in the TEE design, detection
is a real mitigation because attacks fail closed at the next boot (rollback,
tampering). Seed exfiltration is different: it is silent, permanent, and
monitoring only tells you when to begin rotating. Dual-unlock converts a
unilateral capability into one that cannot complete without producing a signal
at a party the attacker does not control.

## 7. Attacks on the unlock channel

The threat actor from §2 holds the bootstrap ciphertexts, full KMS access,
**and root on the parent** — which means they proxy every byte in and out of
the enclave over vsock. The unlock channel must therefore be designed as if
the transport is fully adversarial. It is.

### 7.0 Why KMS access gives no leverage here

The single most important structural property: **the unlock channel does not
involve KMS.** The two shares are protected by trust roots with no overlap.

| Share | Protected by | Administered by |
|---|---|---|
| `kms_share` | KMS key policy + PCR conditions | the customer — including a rogue KMS admin |
| `device_share` | NSM attestation chain + HPKE to an attested ephemeral key | **AWS hardware root — not customer-administrable at all** |

An attacker who owns the KMS key completely still faces the NSM signing chain,
and there is no policy, grant, or key-policy edit that weakens it. `kms:Decrypt`
is simply not a step in obtaining `device_share`.

### 7.1 Interception of the returned share

| Attempt | Why it fails |
|---|---|
| Passive MITM on the unlock channel | Share is HPKE-sealed to an X25519 key existing only in enclave memory. Attacker sees ciphertext. |
| **Substitute the ephemeral pubkey** in the attestation document before forwarding to the device | The pubkey is committed inside `user_data` of the **COSE-signed** NSM document (§5.4 step 1). Altering it invalidates an AWS signature the attacker cannot forge; device verification fails. This is why the binding is load-bearing, not decorative. |
| Replay a captured attestation document | The matching ephemeral private key was zeroized in enclave memory and never persisted. The document can be replayed; nothing sealed to it can be opened. |
| Replay the sealed share to a different enclave | Sealed to that instance's ephemeral key; a different enclave holds a different key. |
| Capture the sealed share and grind offline | Requires the ephemeral private key — memory-only, zeroized, never written to the store, never logged (§8). |

Two invariants follow, and both are fatal to violate:

- The ephemeral keypair is **memory-only**. Persisting it to survive a
  restart mid-unlock — an obvious-looking availability "fix" — hands the
  parent everything.
- The ephemeral private key and the opened share must never reach a log.
  Note `vsock-log` ships enclave logs **to the parent** (`deploy/nitro/README.md`,
  `FEATURES="…,vsock-log"`), so a stray `debug!` is a direct exfiltration path
  to the untrusted host.

### 7.2 Soliciting the share with a genuine image

The attacker has the EIF from the parent's disk, so they can boot a real
enclave producing a **legitimately signed quote with a matching PCR0**, and
solicit a share for it. They would receive one.

What they get is a fully-unlocked VTA they **cannot command**: no admin DID
private key, and mnemonic export requires first-boot entropy plus a super-admin
JWT (`kms_bootstrap.rs:115`, `routes/attestation.rs:161`). To obtain an image
that actually leaks the seed they must *modify* it — which changes PCR0.

Hence the pivotal control: **the device's PCR pin is a second, independent
policy that the KMS administrator cannot edit.**

> **Corollary (do not get this wrong).** The device's expected PCR0/PCR8 must be
> provisioned **out-of-band** and stored in hardware-backed storage, changeable
> only by explicit human approval. If the device ever sources the pin from the
> KMS key policy — or from anything else the KMS admin controls — the two
> trust roots collapse into one and the entire design is worthless. A rogue
> admin would simply rotate PCR0 to their own image in both places at once.

### 7.3 Rogue-VTA prompt phishing (the residual human factor)

Given §7.2, a prompt-phishing attack must present a **changed PCR0**. So the
attack reduces to: will the operator approve despite the warning?

This is the one path that cannot be closed cryptographically, and a naive
implementation makes it **worse than the status quo** — it adds a
social-engineering route to a secret that previously required AWS
administrative access. The mitigations are therefore part of the design, not
optional hardening:

1. **Unpinned attestation verification is insufficient.** A genuine-but-wrong
   image produces a perfectly valid quote — precisely the case `check_pcrs`
   was added for (P3.4). The pin is the control; the signature alone is not.
2. **Show the operator what changed.** A PCR0 differing from the last approved
   unlock must be visually distinct and require explicit acknowledgement.
   Legitimate image upgrades are rare and planned, so this is a low-noise,
   high-signal prompt.
3. **Fresh nonce per unlock**, rate limiting, and refusal of concurrent
   in-flight unlock requests, so an attacker cannot race a legitimate restart
   or grind for an inattentive approval.
4. **Treat an unexpected prompt as an incident.** An unlock request the
   operator did not initiate means someone holds the bootstrap ciphertexts —
   itself a high-value alarm, and one this design *creates* where none existed
   before (§6, last row).
5. **Approval fatigue is the irreducible residual.** It is a human factor and
   cannot be closed by protocol design; it is bounded by keeping unlock events
   rare (§5.6) so that each one is noteworthy.

## 8. Interactions and traps

- **`re_encrypt_bootstrap_secrets` (`kms_bootstrap.rs:217-253`)** — backup
  import re-wraps the seed under a fresh KMS data key. If it does not preserve
  the split, restoring a backup **silently downgrades a dual-unlock VTA to
  KMS-only**. Must fail closed rather than re-wrap single-share.
- **Backup export** (`POST /backup/export`, Argon2id + AES-256-GCM) exports the
  seed to an operator password. That is a different threat actor (needs
  super-admin, i.e. VTA access), but it is a parallel path out and should be
  reviewed alongside — dual-unlock protects the at-rest seed, not an
  authenticated super-admin.
- **Anti-rollback anchor (P0.2a/c)** MACs its integrity manifest under
  `HMAC-SHA256(HKDF(storage_key), …)`. Moving `storage_key` to tier 1 changes
  what that MAC is worth against an attacker holding tier-1 material. Needs
  explicit re-analysis, not an assumption that it carries over.
- **`vsock-log` ships enclave logs to the parent.** Any `debug!`/`trace!` that
  touches the ephemeral private key, the opened share, `K_seed`, or the seed is
  a direct exfiltration path to the untrusted host (§7.1). Worth a deny-list
  test rather than reviewer vigilance.
- **The ephemeral unlock keypair must never be persisted.** Storing it to make
  an interrupted unlock resumable is a plausible-looking availability fix that
  hands the parent the whole channel.
- **PCR pin provenance on the device** must be out-of-band and hardware-backed
  (§7.2 corollary). Never derived from, synced with, or defaulted to the KMS
  key policy — that collapses the two trust roots into one.
- **`allow_unattested_fallback`** must not be reachable in a way that
  reintroduces a single-share path.
- **Mnemonic export** already gates on first boot + super-admin; confirm it
  cannot be used to extract a tier-2 secret from a tier-1 VTA.
- **Restart triggers**: instance stop/start, host degradation, EIF upgrade, ASG
  replacement, crash. Each becomes an unlock event — quantify the real rate for
  the target deployment before committing to Option C.
- **`vta-service/src/seal.rs`** is unrelated and stays as-is; naming needs care
  in docs and CLI so "sealed/unsealed" (CLI gate) and "locked/unlocked" (key
  split) are not conflated by operators.

## 9. Phased implementation

- **P1 (L)** — Split `storage_key` off the seed onto the tier-1 root, with a
  migration for existing deployments. No behaviour change, no dual-unlock yet.
  This is the load-bearing slice and the one most likely to surface surprises.
- **P2 (M)** — Split-wrap primitive: `K_seed = HKDF(kms_share ‖ second_share)`,
  behind `enabled = false`. Custodian trait with a test/dev implementation only.
- **P3 (M)** — Option B custodian (secret-store second share) via `vti-secrets`.
  Delivers the security property for fleets with no device work.
- **P4 (L)** — Generalized attestation verifier + unlock protocol
  (§5.4 steps 1–5), attestation-authenticated REST path first.
- **P5 (L)** — Device custodian: `vta-mobile-core` enrolment, biometric-gated
  release, PCR pinning and change display, k-of-n.
- **P6 (S)** — Threat-model rows (§6), operator runbook, escrow procedure,
  `docs/02-vta/tee-architecture.md` updates.

P1–P3 deliver most of the security value and are independently useful; P4–P5
are what make Option C viable. A decision to stop after P3 is legitimate.

## 10. Residual risks / out of scope

- **AWS itself** remains trusted (Nitro root, NSM chain, KMS attestation
  validation). Not addressable from here.
- **Two colluding custodians** recover the seed by construction. k-of-n raises
  the bar; it does not change the shape.
- **An authenticated super-admin** can still export a backup. Different actor,
  different control.
- **Device compromise** puts `device_share` in the attacker's hands directly.
  The custodian device joins the TCB — hardware-backed key storage and a
  supported OS become security requirements, not preferences. k-of-n (§5.6)
  bounds single-device compromise; it does not bound a compromised *fleet* of
  the operator's devices.
- **Approval fatigue** (§7.3, item 5) is a human factor and cannot be fully
  closed by protocol design.
- **Loss of the PCR pin's integrity on the device** (malicious app update,
  jailbreak, pin sourced from an attacker-controlled channel) reduces the
  design to single-root. See the §7.2 corollary.
- **Availability regression** is real and is the primary cost. Option C should
  not be adopted for any VTA whose restart rate has not been measured.

## 11. Open questions for review

1. Is the **transport identity in tier 1** (§5.4) acceptable, or does splitting
   the VTA's transport DID from its issuing DID create operator confusion that
   outweighs keeping unlock on the REST carve-out?
2. Should P1 (storage-key split) proceed **independently** of dual-unlock? It
   is arguably better layering regardless, and it de-risks the rest.
3. For fleets, is Option B's "second cloud administrator" a meaningful
   improvement over one, or does it mostly add operational surface? Depends on
   whether the two providers' admin populations genuinely differ in practice.
4. Does this supersede, complement, or compete with **P0.2e** (cross-account)?
   Both address the same actor; cross-account is cheaper and weaker.
5. What is the acceptable `unlock_timeout_secs` before a tier-1 VTA gives up
   and exits, versus sitting indefinitely in a degraded state?
