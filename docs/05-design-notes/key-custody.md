# Key custody: who may reach the seed, and through which door

**Status:** implemented (VTA). Origin: FTL-29904 and the holes found beside it.

Every key the VTA holds is a pure function of the master seed and a BIP-32
derivation path. So **choosing a path is holding a key**. An authorization
check that asks "may this caller use a key in context X?" is worthless if the
caller also chose which key the record for context X names. This note records
the rules, the code that enforces them, and why each exists.

The rules themselves, stated for implementers, are the module documentation of
[`vta_keys::custody`](../../vta-keys/src/custody.rs). This note is the "why".

## What was wrong

FTL-29904 reported that a context-scoped admin (`role: admin` with a non-empty
context list) could list and rotate the instance-wide seed. Reviewing it turned
up four holes, all instances of one mistake: **a gate that asked about the
caller's role or context, never about the path or key the caller named.**

| # | Surface | What a context-scoped caller could do | Severity |
|---|---|---|---|
| 1 | `keys/seeds` list/rotate (REST, Trust Task **and** DIDComm) | Read the rotation history; rotate the whole instance's seed | High |
| 2 | `keys/create` with `derivationPath` | Derive **any** key (another tenant's, the VTA's own `did:webvh` update key), record it under its own context, then export it via `keys/export-secret`, whose scope check read the context the caller had just chosen | Critical |
| 3 | `keys/derive-and-sign`, `keys/derive-and-sign-document` | Sign as any path, including the VTA's update key (a new DID log entry) | Critical |
| 4 | `vault/proxy-login`, `vault/sign-trust-task` | Store a `did-self-issued` entry naming `{vta_did}#key-0` as its `signingKeyId`. The loader used `InternalAuthority` (no ACL) and signed as the VTA. Reachable with `VaultWrite` + `SignTrustTask`, which `initiator` holds | Critical |

The TEE deployment was spared #1's rotation only by a storage property: the KMS
seed store refuses a rotation (409), and that refusal came *after*
authorization had passed. #2–#4 were not blocked by anything.

## The rules

1. **Seed state is instance-wide.** Listing and rotating need unrestricted act
   authority (VTI-ACL-022). The specification assigns seed administration to no
   narrower authority, and where it is silent a node refuses (VTI-ACL-092).
2. **Root derivation material never leaves** except through backup
   (VTI-VTA-001, VTI-KEY-033). No door returns seed bytes or a BIP-32 root.
3. **A context's key is derived from that context's base and from no other**
   (VTI-KEY-030, VTI-KEY-032). A path belongs to the context with the *deepest*
   base strictly above it, because children nest under their parent
   (VTI-CTX-022).
4. **Only a super-admin chooses a path**, and a chosen path must still satisfy
   rule 3. Authority to choose is not authority to mislabel.
5. **`m/26'/9'` is the sign-only delegated-identity subtree.**
   `derive-and-sign*` may derive there and nowhere else; no key record may be
   created there.
6. **Checked at use, not only at creation.** A record that breaks rule 3
   (planted before the fix, or restored from a backup) is refused whenever it
   is derived, so it is inert.
7. **A key named by a context-scoped resource must be in that resource's
   subtree.** Loading "internally" is safe only when the VTA fixed the key id
   (`{vta_did}#key-0`). An id that came from stored caller data is held to the
   resource's context.

Every refusal is audited (`key.custody_violation`,
`authority.instance_required`, outcome `denied`, reason in `detail`;
VTI-AUD-003) and logged at `error!` with `security_alert = true`. Delegated
signatures are audited with the path and a SHA-256 of what was signed
(VTI-VTA-006), for every transport, not only Trust Tasks.

## Where it is enforced

| Door | Code | Rules |
|---|---|---|
| Pure checks + `RecordKey` (holds the root privately; derives only at the record's own path) | `vta-keys/src/custody.rs` | 3–7 |
| Instance authority, per-record derivation, explicit paths, delegated identities, referenced keys, boot scan, all audited | `vta-service/src/operations/key_custody.rs` | 1, 3–7 |
| Seed list/rotate gate (in the operation, shared by all three transports) | `operations/seeds.rs` | 1 |
| Every network-reachable derivation of a stored record (`get_key_secret`, `get_key_secret_internal`, `sign_payload`, holder keys, `did:webvh` key load) | `key_custody::derive_record_key` | 6 |
| Vault signing loaders + `vault/upsert` | `operations/vault/mod.rs`, `trust_tasks/vault.rs` | 7 |
| Boot-time scan (reports, never revokes) | `server.rs` → `key_custody::scan_key_custody` | 3 |
| Raw-access census | `vta-service/tests/key_custody_census.rs` | all |

**Gates live in operations, not transports.** The seed gate was an axum
extractor on REST, a role check on Trust Tasks and `Gate::Admin` on DIDComm:
three copies, all asking the wrong question, and none auditing a refusal. Now
each transport hands the authenticated claims to the operation, and the
operation decides and audits once.

## Rules for new code

- Never load the seed, build a BIP-32 root, or derive in network-reachable code
  except through `key_custody`. If no door fits, add one there. The census will
  otherwise fail and ask you to justify the raw call.
- Never accept a derivation path from a caller except through
  `authorize_explicit_key_path` (a record) or `derive_delegated_identity`
  (sign-only).
- Never pass a caller-influenced key id to `get_key_secret_internal` without
  `require_referenced_key_in_scope` first.
- Never compare derivation paths as strings: `m/26'/2'/1'` is a string prefix
  of `m/26'/2'/10'/0'`, which belongs to another context. Use
  `custody::is_strictly_within`.
- A role check (`require_admin`, `AdminAuth`, `Gate::Admin`) never answers a
  scope question. See also `acl-scope-semantics.md`.

## Known edges, deliberately left

- **A parent's allocated key can equal a child's base.** The parent allocator
  issues `{parent}/<n>'`, which is also child *n*'s base path. The key at that
  path is the parent's; the child's keys lie strictly below it. No export
  carries a chain code, so the child's keys cannot be derived from it. Tidying
  the allocators to use disjoint sub-branches would change every existing
  key's path and is not worth it.
- **The use-time check (rule 6) compares only against the record's own
  context's base**, not every descendant's. That is one lookup per signature
  instead of a full context scan. A record that breaks only the descendant half
  of rule 3 gives nobody new reach, because a parent's authority already covers
  its descendants (VTI-CTX-017). The creation check and the boot scan enforce
  the full rule.
- **Context-less key records** exist (keys a super-admin creates without a
  context, and some VTA-internal records) although VTI-CTX-001 says every key
  belongs to exactly one context. That divergence predates this
  work. Here, context-less records are reachable only by super-admin
  surfaces, and no context-less record may sit inside a context's subtree.
