# did:webs on KERI v2 — positions

**Status:** decided 2026-11-10, implementation not started. **The VTI `did:webs`
integration is alpha.** Expect breaking changes as the KERI, ACDC, CESR and
`did:webs` specifications settle the questions below. A `did:webs` identifier
created while the integration is alpha may have to be created again: its
designation schemas, its registry form and how it resolves can all change.
Don't use one for a trust relationship that must outlive that.

**Why now.** VTI has no `did:webs` identifiers deployed, and keripy 2.x defaults
to KERI v2 (`kering.py:24`, `Version = Versionage(major=2, minor=0)`).
Switching before anything exists costs no migration. Switching later means a
migration on every identifier, and the AID itself changes if it's re-incepted.
So VTI creates KERI v2 identifiers only, and reads v1 and mixed event streams
created elsewhere.

The `did:webs` specification says nothing about protocol versions. Its 28
example version strings are all v1, its alias mechanism is described with v1
registry events (`vcp`/`iss`), and its normative references point at the
unversioned KERI, ACDC and CESR specifications.
[kswg-did-method-webs-specification#216] asks the questions this note answers;
it was discussed on the 2026-10-20 `did:webs` call and is not settled. Where a
position below goes beyond #216, it's ours to propose there.

[kswg-did-method-webs-specification#216]: https://github.com/trustoverip/kswg-did-method-webs-specification/issues/216

---

## 1. Positions

Each position is what VTI implements, and what we'll argue for upstream.

### P1 — A stream states its version; a resolver never assumes one

*Adopts #216 Q1.* A resolver reads the version from the stream. A v2 stream
opens with the CESR genus-version counter, and every message body carries its
own version string. Nothing in the DID or its URLs carries a version. A stream
with no genus counter is v1, which is what every deployed `keri.cesr` is. A
resolver must not fall back on a parsing library's default: keripy's parser now
defaults to v2, so "read it from the stream" silently means v2 unless said
otherwise.

### P2 — One event log may mix versions, but only upward

*Adopts #216 Q2, all four rules.*

- A KEL may begin in v1 and continue in v2. **Attachments follow the stream's
  genus; each body carries its own version.** #216 proposed instead that a
  message's body version and attachment genus agree. keripy doesn't do that: it
  republishes a migrated log under a single v2 genus counter, so its v1 events
  carry v2 attachment groups (fixture `migrated-v1-to-v2`). That is what any
  keripy-based host publishes, so a reader must accept it, and the rule should
  be written that way.
- **Monotonic per KEL:** within one AID's KEL the protocol version never
  decreases. This is stricter than keripy, which accepts a v1 `ixn` after a v2
  `icp` (fixture `downgrade-v2-to-v1`). VTI refuses it, and records the
  divergence.
- **Genus switches are explicit:** a genus-version counter precedes the first
  message of each run in a different genus.
- **A credential and its registry share a version.** A v1 ACDC names a v1
  registry with `ri`; a v2 ACDC names a `rip`/`bup` registry with `rd`. Any other
  combination is allowed, such as a v1 KEL anchoring a v2 registry.

**VTI writes pure v2:** v2 KELs, v2 registries, v2 credentials. It never writes
a v1 event, so it never needs the migration rules for its own identifiers; it
needs them only to read other identifiers.

### P3 — A frame the resolver can't read fails resolution

*Adopts #216 Q2's last rule.* A v1-only reader that skips v2 frames would, on a
migrated KEL, derive the pre-migration key state, which has been rotated out. A
resolver that meets a message, counter or version it can't parse fails
resolution; it doesn't skip the frame. This is the same fail-closed rule as for
critical designations (P6): what a resolver doesn't understand never shrinks
silently into something it does.

### P4 — Every designation schema has a v2 form, derived mechanically

*Adopts #216 Q3, and extends it to our designations.* The v2 schema is derived
from the v1 schema:

1. `ri` becomes `rd`, with v1's definition.
2. `t` is added, required, exactly
   `{"description": "Message type", "type": "string", "const": "acm"}`.
3. Properties are ordered `v t d i rd s a r`, and `required` follows that
   order.
4. `version` becomes `2.0.0`.
5. Nothing else changes.

We reproduced the v2 designated-aliases SAID proposed in #216 by applying these
steps to GLEIF's v1 schema. Step 2 has to say exactly that `t` definition; #216
leaves it unstated, and with any other definition the SAID differs. Applied to
our schemas:

| Designation | v1 SAID | v2 SAID |
|---|---|---|
| Designated aliases (GLEIF) | `EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5` | `EF9Iy-vwD8GRKghnzHHGwAA6sC0VEWNtZ2Sf4tfd4IAA` |
| Key agreement | `EJZrf6N4vbhA1hQIujWiIiQmNi455EGS3iXdhxLSwvAi` | `EIW1ONwnh_dkiDZ3_xmUsBxh7X5u7luVOuCoRdCl3jPZ` |
| Service | `ELj0Sdf2Boi7BMiIFAEJ9_MSFJU8t-LavLN-gMb8oXM8` | `EJVZ789syil6R--yix7j8X4g_mHZCDIaSWM15MgkFQgG` |
| Key role | `EPulJFl5SEb8qb3ca5teXHRGiWmTsTkylGTrS2vB4ZQx` | `EBMCaUhHZqulCtix3fzRRsdW0_gfT3bMLsrp3c3ixpxx`, not derived mechanically; see below |

The key role schema changes in more than its version, because v2 is the
revision it was waiting for:

- **`critical`**, required, `const: true`, in its attribute block (P6).
- **`keyAssurance`**, optional, as VTI-KEY-197 shapes it:
  `{ "level": 1|2|3, "recoveryCommitment"?: <digest> | { "threshold", "commitments" } }`.
  The KEL's `n` lists digests without saying which one is the recovery key, so
  the designation names it. dtgwg-trust-tasks-tf#993's `did:webs` profile
  defers this attribute to "a revision"; this is that revision.

The specification should name every designation schema by SAID, so resolvers
stop depending on one implementation's resource file.

### P5 — Registry state is read from blindable updates, disclosed in the stream

*Adopts #216 Q4.* A v2 registry is `rip` plus `bup` events. Designations are
public, so each `bup` is published with its expanded blinded state attached
(`BlindedStateQuadruples`), and read the way keripy's `vetBinds` reads it.
**Each update uses a fresh UUID, even though the state is disclosed anyway.**
With the empty UUID of the ACDC specification's public mode, a re-issue's BLID
collides with the first issuance's, and keripy refuses it
(`UnverifiedBlindError`, fixture `v2-reissued-empty-uuid`). We read that case by
which update each disclosure is attached to, but VTI never writes it.

- Disclosures are matched to updates by BLID. Every update from the latest back
  to the latest non-vacuous one must be disclosed.
- **Unrevoked** means the latest non-vacuous update discloses `issued` for the
  credential. The state vocabulary is fixed to `issued` and `revoked`, and
  anything else fails.
- **Every registry event the AID's KEL anchors must be in `keri.cesr`.**
  Otherwise a stream that leaves out the revoking update resolves as issued.
  keripy does exactly that (fixture `v2-revocation-withheld`): it checks that
  what is presented is anchored, not that everything anchored is presented.
  `affinidi-keri-core`'s `registry` module fails resolution instead, for v1 and
  v2, and replaces the v1 reader in `designation.rs`, which had the same gap.
- Under `versionId`, "latest" means latest among the updates anchored at or
  before the limiting KEL event, judged by anchor position.
- **Don't depend on `upd`.** keripy main refuses it
  (`acdc/regeventing.py:121`: "The v2 ACDC TEL only supports registry inception
  and blind updates"), although the ACDC specification still lists it.

**Correction to an earlier claim.** Blinding gives a designation no privacy,
because a `did:webs` designation has to be disclosed for anyone to resolve the
DID. For `did:webs`, v2 registries are a format change, not a privacy gain. The
privacy benefit applies to VTI's other credentials, not to designations.

### P6 — Restricting designations are critical

*From kswg-did-method-webs-specification#224.* A designation that restricts
what the key state alone would put in the document (key roles) carries
`"critical": true`. A resolver that doesn't implement such a designation fails
with `unsupportedDesignation`, whatever `did.json` says. Designations that only
add content (aliases, key agreement, services) aren't critical. Comparing
`did.json` alone can't protect a restriction: a host that publishes the
key-state derivation would pass the comparison at every resolver that ignores
the restriction.

### P7 — Superseding recovery is reconciled, and takes its anchors with it

*From #214 and our comment there.* A rotation that validly supersedes events
under KERI's superseding rules is reconciled, not treated as a fork that fails
resolution. Anything whose only anchor is in the superseded branch is dropped:
aliases, designations, registry updates. This is what the recovery custodian
(`nt [["1/2","1"]]` over `[R′, K]`) is for. `affinidi-keri` doesn't yet accept
superseding events (`kever.rs` refuses any event whose sequence number isn't the
next one), and v2 work is the time to add it.

### P8 — VTI writes JSON bodies; native CESR bodies are read, not written

v2 allows JSON, CBOR, MessagePack and native CESR bodies. VTI writes JSON
bodies because they keep `keri.cesr` debuggable. Note that keripy's own default
is now native CESR (`Kind = 'CESR'`), so a stream from a keripy host with
default settings has native bodies. Reading native CESR bodies is required before the
integration leaves alpha, because a conforming stream may carry them.

---

## 2. Conformance: checked against keripy v2

keripy 2.x is the reference. "Works with our own resolver" isn't evidence:
every v2 piece is checked in both directions against keripy at a pinned
commit, starting with `b70986f` (2026-11-05, `2.1.0-dev1`).

- **keripy produces, we verify.** A script drives keripy to build v2 streams,
  and the fixtures are committed with the script that made them:
  - inception, rotation and interaction events;
  - a delegated identifier;
  - a weighted `nt` recovery rotation;
  - a superseding recovery;
  - a v1 → v2 migrated KEL;
  - `rip`/`bup` registries with disclosed state;
  - each v2 designation, revoked and not.

  `affinidi-keri` and `affinidi-did-webs` must accept each one and derive the
  same key state and registry state as keripy.
- **We produce, keripy verifies.** The same scenarios are built by our
  controller (`affinidi_keri::controller`) and `create_controlled`, and fed to
  keripy: `Kevery` for event logs, and `keri.acdc.regeventing` (`vet`,
  `vetBinds`) for v2 registries. keripy must accept them and agree on key state,
  registry state and SAIDs.
- **Field sets come from keripy, not memory.** Each message type's v2 fields are
  taken from `serdering.py` (`Serder.Fields`, v2: `rot` gains `c`; `rpy`, `qry`,
  `pro` and `bar` gain `i`, and `a` is a map; `exn` gains `ri` and `x`; `xip` is
  new). A test fails when ours and keripy's differ.
- **Disagreements are findings, not fixes.** Where keripy and the KERI or ACDC
  specification disagree (`upd` is one), we follow keripy for interop, record
  the disagreement here, and raise it upstream.
- **The fixtures** are in `affinidi-keri-rs`,
  `crates/affinidi-keri-core/tests/fixtures/keripy-v2/`, with the generator
  (`gen.py`) and the list of keripy behaviours a reader must know. keripy's
  parser defaults to v2, so the generator reads a counter-less v1 stream as v1
  only by saying so: P1 written into code.
- **Re-pin deliberately.** Moving to a newer keripy commit regenerates the
  fixtures; any diff is reviewed as a behaviour change.

---

## 3. Order of work

1. **`affinidi-keri-core`:** v2 version strings (19 characters), the genus
   counter, the v2 counter table (the mapping exists in `counter_table.rs`), v2
   field sets, SAID sizing, mixed-version KELs (P1–P3), superseding recovery
   (P7). Verified against keripy fixtures from the first commit.
2. **`affinidi-keri` controller:** emits v2 events. The public API stays as 0.5.1
   built it.
3. **Registries and ACDC v2** in `affinidi-keri-core`: `rip`/`bup` and
   `BlindedStateQuadruples` (P5). The v1 `vcp`/`iss`/`rev` handling moves there
   from `did-webs` (`designation.rs` says it belongs there).
4. **`affinidi-cesr`:** v2 counters and genus codes. Also fix the indexed
   signature codes, which are swapped against keripy and the CESR specification
   (`A`/`2A` are current-only here, `B`/`2B` both lists; it's the reverse).
5. **`affinidi-did-webs`:** v2 designation schemas (P4), critical designations
   (P6), stream-version detection, mixed streams, `rpy` `i`, every anchored
   registry event required (P5).
6. **VTA:** key-roles step 1 onward (`key-roles-implementation.md`) builds on
   v2 from the start.
7. **Upstream:** comment on #216 with P1–P5 (the reproduced SAID, the exact `t`
   definition, the extension to every designation schema), and add v2 wording
   to kswg-did-method-webs-specification#224, #225 and #226, which describe
   designations with v1 registry events.
