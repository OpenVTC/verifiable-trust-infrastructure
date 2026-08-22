# Registry↔implementation drift — the per-URI triage (#854, phase 1)

**Status:** phase 1 shipped (reverse parity harness + constant rename pass);
dispositions below are the input to the next registry PRs.
**Tracking issue:** OpenVTC/verifiable-trust-infrastructure#854.
**Programme:** this slots into `canonical-task-reduction.md` — section references
(§A–§F) below are to that document's disposition classes. Where the two
disagree, this document is newer and reflects the pre-production policy:
**everything on defined trust tasks with defined specs, aligned and as minimal
as possible.** Nothing here has external consumers yet, so the preferred verbs
are *fold* and *delete*, not *alias*.

**Sibling streams (do not duplicate):**

- `task-consent/granted/0.1` is being specced upstream right now — it is
  excluded from this triage as in-flight. (It is an outbound producer URI in
  `vta-service/src/trust_tasks/consent_request.rs`, not a dispatched one, so it
  is also outside the harness's scope.)
- #851 — the did-templates global+context merge — shipped as
  `vta/did-templates/*/2.0` (specced upstream in
  trustoverip/dtgwg-trust-tasks-tf#162). The six 2.0 URIs sat in
  `UNSPECCED_DISPATCHED_URIS` as **publish-lag entries only**; the
  0.2.43 → 0.2.51 bump indexed them and the staleness check forced their
  removal, as designed. Never missing-spec debt — not part of this triage.
  The same bump put the six URIs back inside the conformance sweep's
  derived census (#866), which then required a witness for each.
- #856 — `acl/update`'s non-canonical body — is being fixed by another stream.
- #857 — the payload-conformance sweep (the *third* parity direction: served
  URIs whose published schema the handler's actual payload type does not
  satisfy) — is being implemented by another stream.

---

## What phase 1 shipped

1. **The reverse parity harness.** The dispatcher's test module
   (`vta-service/src/trust_tasks/mod.rs`) has always asserted every vta-sdk URI
   is served. It now also asserts the opposite:
   `every_served_uri_has_a_published_spec_or_is_tracked_debt` requires every
   URI this service serves — dispatched, REST-routed, feature-gated, or
   `wire_v0_2` edge-transformed — to resolve in the published registry via
   `trust_tasks_rs::schema_index` (the registry's index, vendored through the
   pinned `trust-tasks-rs` crate; the `trust-tasks/index.json` manifest in this
   repo is the *retired* `openvtc/vtc` authority and is not usable for this).
   The 56 known-unspecced URIs sit in `UNSPECCED_DISPATCHED_URIS`, per-URI and
   annotated; the harness fails on any NEW unspecced URI, on any entry whose
   spec has since been published (the list only shrinks), and on any entry no
   longer served. This complements — not replaces — the workspace-wide census
   in `vtc-service/tests/trust_task_manifest.rs` (#821), which scans source
   literals in four trees and counts per *family*; the new check is per *URI*,
   scoped to what the VTA dispatcher actually serves, and lives next to the
   forward harness so the two directions cannot drift apart.

   **Publish-lag entries are debt with an expiry date.** Both exception lists
   (`UNSPECCED_DISPATCHED_URIS` here, `UNPUBLISHED_CANONICAL_OK` in the census)
   sometimes carry a URI whose spec is *already authored upstream* but not yet
   in the pinned `trust-tasks-rs`. Those entries are not dispositions — they are
   waiting on a dependency bump, and the shrink-only assertions turn the bump
   into a hard failure until they are removed. So **every `trust-tasks-rs` bump
   is also an exception-list sweep**: run
   `cargo test -p vta-service --lib` and
   `cargo test -p vtc-service --test trust_task_manifest`, and delete whatever
   they flag. The 0.2.43 → 0.2.51 bump flushed seven such entries — the six
   `vta/did-templates/*/2.0` URIs (#851) and `vtc/join-requests/decide/0.1`
   (#853) — leaving the list back at its 56. Those 56 are unaffected by the
   bump: they are genuine unspecced surface, not lag.

   **Publish lag also shows up in prose, where nothing asserts.** The same
   bump had a third kind of lag to flush, and it had no failing test behind
   it: #866's conformance witnesses left `allowedKeys` (#818) absent with a
   comment saying the member was not in the published
   `acl/_shared/0.1/acl-entry` / `acl/update/0.1` schemas — true at 0.2.43,
   and 0.2.51 is where it stopped being true (0.2.50 does **not** carry it;
   registry PR #164 landed one release later). A comment cannot fail, so
   sweeping the two exception lists is not enough — grep the pinned crate for
   the member a comment claims is missing. Both witnesses now carry it.

2. **The `_1_0` constant rename pass** (previously "pending" in
   `vta-sdk/src/trust_tasks.rs`). Ten constants whose greppable name lied about
   the wire were renamed so suffix = URI version and verb stem = canonical
   slug: `TASK_ACL_{LIST,GRANT,SHOW,UPDATE,REVOKE,SWAP_KEY}_0_1`,
   `TASK_AUDIT_LIST_0_1`, `TASK_CONFIG_{SHOW,PATCH}_0_1`,
   `TASK_PROVISION_INTEGRATION_0_2`. A source-scanning guard test
   (`constant_suffix_matches_uri_version`) keeps every literal-assigned
   constant honest from now on.

3. Regenerating `trust-task-uri-registry.md` from the constants is **deferred
   to tranche 2** — see the last section.

## Corrections to the issue's enumeration (re-derived from main)

The issue's "~45" list was written against an older main. Re-derivation found
**56** unspecced *served* URIs (the census's counted exceptions agree: 44
`vta/` + 12 `vault/`), and four rows of the issue's list are not drift at all:

| Issue row | Reality | Action |
|---|---|---|
| `consent/approve-request/0.1` | No such URI anywhere. The real family is `task-consent/{request,granted}`; `request/0.1` **is published**. | None (enumeration error). |
| `vtc/auth/login/0.1` | Bound by no route. It survives only as a test-fixture/doc-example string in `vti-common/src/trust_task/{openapi,mod,router}.rs` (a tree the #821 census does not scan). | **Delete**: repoint the fixture strings at published tasks. |
| `vtc/install/claim/0.1\|0.2` | The monolithic shape exists only in the same `vti-common` fixtures/doc examples. `vtc-service` binds the published `vtc/install/claim/{start,finish}/0.1`. | Shape decision is already made by reality: **start/finish wins**. Scrub the stale monolithic fixture strings (same edit as the row above). |
| `task-consent/granted/0.1` | Real, outbound-only, spec in flight upstream. | Excluded — sibling stream. |

## The 56, with dispositions

Recommendation vocabulary: **spec** (author upstream, URI stays),
**fold** (repoint onto an existing/extended canonical task, then delete the
`vta/` URI — no alias window; pre-production), **delete** (remove the surface).

### `vta/contexts/*` — 7 × spec (§E)

| URI | Recommendation |
|---|---|
| `vta/contexts/{list,create,get,update,update-did,preview-delete,delete}/1.0` | **spec** under `vta/` — the BIP-32 context tree is genuinely VTA-shaped. One caveat: `get` vs `list` and `preview-delete` stay separate per the registry's read-one/read-many convention; do **not** collapse. |

### `vta/keys/*` — 8 × fold-to-new-canonical (§D)

| URI | Recommendation |
|---|---|
| `vta/keys/{list,create,get,rename,revoke,sign,derive-and-sign,derive-and-sign-document}/1.0` | **spec as top-level `keys/*` 0.1**, repoint, delete the `vta/` URIs. The signing-oracle surface is generic to any key-holding agent; publishing it under `vta/` would strand the next consumer. |

### `vta/seeds/*` — 3 × spec (§E)

| URI | Recommendation |
|---|---|
| `vta/seeds/{list,rotate,export-mnemonic}/1.0` | **spec** under `vta/` — meaningless to an agent that is not the key authority. `export-mnemonic` is the registry's first `discloses: secret` VTA task; write the Security section accordingly. |

### `vta/audit/*-retention` — 2 × fold-to-new-canonical

| URI | Recommendation |
|---|---|
| `vta/audit/{get,update}-retention/1.0` | **spec as `audit/retention/{show,update}/0.1`** extending the published `audit/` family, delete the `vta/` forms. Retention is not VTA-specific (VTC has the same knob ahead of it). |

### Singletons — diff first, then fold or delete

| URI | Recommendation |
|---|---|
| `vta/discovery/capabilities/1.0` | **RESOLVED — retired (#1039, #1043).** The original recommendation (fold) was right. `trust-task-discovery/0.1` now answers *"which tasks do you serve"*, from the dispatch table. Every other member had a better home: `features`/`services` at the DID document (authoritative for what a party speaks, and these could contradict it); `version` at `GET /health/details`, same auth, same `env!`; `webvhServers` at `webvh/servers/list/1.0`, a strict superset at the same auth; `didCreationModes` nowhere — it had no consumer and its vocabulary existed nowhere else in the codebase. |
| `vta/management/reload-services/1.0` | Diff against published `config/reload/0.1`. The VTA already folded `vta/config/*` onto `config/{show,patch}` (#840 phase A); reload is the same shape of thing. Expected outcome: **fold onto `config/reload/0.1`, delete**. |

### `vta/backup/*` — 5 × fold-to-new-canonical (§D)

| URI | Recommendation |
|---|---|
| `vta/backup/{initiate-export,complete-export,initiate-import,finalize-import,abort}/1.0` | **spec as top-level `backup/*` 0.1** (two-phase descriptor flow), repoint, delete `vta/` URIs. `vtc/backup/{export,import}` folds onto it in a later phase — design the family so that fold is possible (the descriptor pattern already is). |

### `vta/attestation/*` — 2 × spec (§E)

| URI | Recommendation |
|---|---|
| `vta/attestation/{status,report}/1.0` | **spec** under `vta/`. REST-routed and unauthenticated by design (attestation is what you check *before* trusting the VTA), which the spec must state — it is the registry's odd one out and undocumentable drift until published. |

### `vta/webvh/**` — 15, split by the two-ends-of-one-wire test (§B)

| URI | Recommendation |
|---|---|
| `vta/webvh/agent-name/{set,remove,disable,enable}/1.0` | Payload-diff against published `did-management/agent-name/{set,remove,disable,enable}/0.1`. Expected: **fold — one task dispatched twice** (operator→VTA and VTA→host are the same document). Delete the `vta/` forms. |
| `vta/webvh/agent-name/check/1.0` | Diff against `did-management/did/check-name/0.1`; expected **fold**. |
| `vta/webvh/agent-name/list/1.0` | No canonical counterpart (parked names are invisible in the DID doc). **spec** under `vta/`. |
| `vta/webvh/dids/{list,get,delete}/1.0` | Diff against `did-management/did/{list,info,delete}/0.1`; expected **fold** for list/delete; `get` vs `info` needs the diff before calling it. |
| `vta/webvh/dids/{create,rotate-keys,register-with-server}/1.0` | Genuinely VTA-side (local key material involved): **spec** under `vta/`. `dids/update` is already published — these join it. |
| `vta/webvh/servers/{list,register,remove}/1.0` | **spec** under `vta/` — the VTA's own registry of known hosts. `did-management/server/register` is the *host* registering itself: different subject, not a fold. |
| `vta/webvh/servers/reconcile/0.1` | **Resolved — the round trip this table exists to produce.** Bound ahead of its spec, specced upstream, released, cleared. Left in the table as the worked example. Original entry follows.<br><br>~~**Specced upstream — awaiting a release, not a decision.** Added after this table was written (host/VTA DID reconcile: which DIDs a host serves that the VTA has no record of, and the reverse). Not a fold candidate — `did-management/did/list/0.1` is the host's own listing, whereas this is the *comparison* of that listing against VTA-local records, and only the VTA can make it: the operator holds no host credentials, the host holds no VTA records. The spec is **merged as [dtgwg-trust-tasks-tf#210](https://github.com/trustoverip/dtgwg-trust-tasks-tf/pull/210)** and ships in `trust-tasks-rs` 0.6.1. It leaves both drift registers when this workspace moves off `trust-tasks-rs` 0.4 — a separate workspace event, since 0.4 → 0.6 crosses two leading-component bumps and `trust-tasks-{https,didcomm,proof,tsp,capability-client}` move with it.~~ |

### `vault/*` archival + credential store — 12 → 4 new specs (§C)

| URI | Recommendation |
|---|---|
| `vault/{archive,unarchive,restore,purge}/0.1` | **spec once, upstream, with a store discriminator** (`store: passwordVault \| credentialStore`, default `passwordVault` so existing callers keep their meaning). |
| `vault/credentials/{archive,unarchive,restore,purge}/0.1` | **fold** onto the four above via the discriminator; delete. |
| `vault/credentials/{get,query,receive,delete}/0.1` | **fold** onto published `vault/{get,list,upsert,delete}` at a new 0.3 carrying the discriminator; delete. |
| *(authorization caveat)* | The discriminator must not let a `VaultWrite` holder reach the credential store (#540 split `CredentialWrite` deliberately). The spec's Security section must bind the store value to the capability check; the PDP class stays per-store. |

**Net effect if every expected fold survives its payload diff:** 56 served
URIs → **~38 new specs** (7 contexts + 8 keys + 3 seeds + 2 audit-retention +
5 backup + 2 attestation + 3 webvh-servers + 3 webvh-dids + 1 agent-name-list
+ 4 vault-archival), the other ~18 folding onto tasks the registry already
publishes (or new versions of them) and their `vta/`/`vault/credentials/` URIs
deleted. That is consistent with `canonical-task-reduction.md`'s 67→~42
estimate — this census is the dispatcher-served subset of that one. The
`UNSPECCED_DISPATCHED_URIS` length is the progress metric; every registry PR
lowers it and the harness enforces the bookkeeping.

## Version straddles

| Straddle | State on main | Recommendation |
|---|---|---|
| `auth/step-up/approve-request` 0.1 vs 0.2 | Registry publishes both. The VTA *emits* 0.1 (`step_up.rs`, outbound push to the approver device) while `approve-response` dual-accepts 0.1\|0.2 in a single match arm. | Emit 0.2; keep accepting both responses through the existing arm until the mobile engine confirms, then drop 0.1. Pre-production: do it in one move with the mobile-core update. |
| `device/wipe/0.2` | Published; the only device 0.2 absent from `wire_v0_2::WIRE_V0_2_URIS` (register/heartbeat/list/set-wake are all there). | Add the `wire_v0_2` entry — it is the same enum-casing-only family the adapter exists for. One table row + one `WIRE_V0_2_URIS` line. Note the adapter stops growing once trustoverip/dtgwg-trust-tasks-tf#151 lands. |
| `policy/evaluate` 0.1/0.2/0.3, `policy/delete/0.1` | Published, referenced nowhere in VTI (comments only). | Registry-side housekeeping, not VTI work: retire 0.1/0.2 with `supersededBy` 0.3. Whether the VTA's PDP should *serve* `policy/evaluate/0.3` as its dry-run surface is a real question — take it as its own issue rather than speccing around it. |

## Tranche 2 (deliberately out of this PR)

- **Generate the URI doc from the constants.** `trust-task-uri-registry.md` is
  a 663-line Phase-0.2 design catalogue whose tables predate the canonical-URI
  migration — it hand-mirrors constants that no longer exist. Regenerating it
  mechanically means replacing its catalogue sections with a table derived from
  `vta_sdk::trust_tasks::ALL_URIS` / `REST_ROUTED_URIS` (+ the per-URI doc
  comments) and demoting the rest to a historical appendix. That is a doc
  rewrite, not a mechanical pass — scoped out of phase 1. The
  `constant_suffix_matches_uri_version` guard removes the worst hand-mirroring
  hazard in the meantime.
- The registry PRs implementing the dispositions above, in the
  `canonical-task-reduction.md` sequencing (folds first, new canonical families
  second, `vta/`-specific third, vault discriminator fourth, webvh last).
