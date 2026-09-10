# Data rooms — the demo site

Status: **design, revision 1.** Nothing built. The feasibility question this
design turns on — can a browser be a real room member — was answered by
building, and §3.1 records what compiled.

Parent design: [`data-rooms.md`](data-rooms.md) (rev 3). Operator guide:
[`../02-vta/data-rooms.md`](../02-vta/data-rooms.md).

A **single public website** where somebody with no wallet, no agent and no
account can mint their own `did:key` in the browser, be admitted to a data room
named by a DID, and read, write and curate its records — for **any** room, not a
room the site was built around.

---

## 1. What this is for, and what it is not

Rooms are built. What is missing is a way for a person to *encounter* one. Every
existing client presumes a great deal: `pnm-cli` presumes a provisioned VTA and
a shell; the browser plugin presumes an installed extension and a wallet already
bound to an agent. Neither is something you can put in a link.

The demo site is the missing front door. Its job is to make the room's actual
properties visible in a browser tab within a minute of arriving:

- the visitor holds their own key, and the room's decisions are made about *that
  key*;
- the host stores ciphertext it cannot read;
- authority is a credential the room issued, not a row in the host's table;
- and access is scoped, expiring and revocable.

It is **not** a wallet, not a replacement for the plugin, and not a product
surface. It is a demonstration that has to be honest, because a demo that fakes
the properties demonstrates nothing.

---

## 2. The constraint everything follows from

A room member is defined by two things, and neither is a credential you can hold
in a cookie.

**One: the MLS group.** The key that opens a sealed record is derived from group
state at the epoch the record was written. Today that state lives in a VTA
keyspace — `vta-service/src/server.rs:458`, rows at `room-group:{roomId}`
(`vta-service/src/operations/room_groups.rs:43`).

**Two: an authority presentation.** Every host task takes one and nothing else
produces one. It is a `{membership, authority: [leaf, root]}` document where the
leaf is the member's *own* root VAC attenuated to a single action, bound to an
audience and a nonce, signed by the member's key, and good for four hours
(`vta-service/src/operations/room_oracle.rs:85`).

`pnm-cli` shows the client shape that follows (`pnm-cli/src/cli.rs:332`): it
holds nothing, takes `--room`, `--host` and `--host-did`, asks *its VTA* for
present/open/seal, and calls the *host* directly over REST. A website is the
same client. Unlike the plugin console it can talk to a host directly — the
console cannot, because `carrierParams` drops the recipient and every call lands
at the wallet's own agent, which is why `rooms/keys/backfill` and
`rooms/owner/register` had to exist at all.

So the only real question is **where the visitor's member-side capability comes
from**. Three answers were on the table: a VTA per visitor, a shared custodial
VTA, or the browser itself.

---

## 3. The decision: the browser is the member

A custodial VTA — one agent holding every visitor's room keys — is both a
demonstration of the wrong thing and **broken today**. `rooms/keys/open` is gated
on `Capability::RoomOpen` and nothing else
(`vta-service/src/trust_tasks/room_group.rs:562`), and the storage key carries no
principal. Two visitors in one VTA can open each other's rooms; two members of
the *same* room collide on one row. A VTA is one principal's agent, and rooms
are stored as though that is true, because it is.

A VTA per visitor is honest and unusable: minutes to provision, a container per
curious stranger.

**So the tab is the key holder.** This was the option that looked like weeks of
porting. It is not, and the reason is a property of the existing crate rather
than luck.

### 3.1 What was verified, and how

`vti-rooms` divides cleanly along exactly the line this needs. Its member half —
`mls.rs`, `sealed.rs`, `retention.rs`, plus `wire.rs`, `error.rs`,
`lifecycle.rs` — **imports nothing from `vti-common`**. Only `storage.rs`,
`authz.rs` and `audit.rs` do, and those are the *host's* concerns, which a member
never runs. `error.rs` says why in its own module doc: key material is
deliberately not a service concern, so `RoomKeyError` is deliberately not
`AppError`.

Three builds against `wasm32-unknown-unknown`:

| Probe | Result |
|---|---|
| `openmls` 0.9 + `openmls_rust_crypto` + `chacha20poly1305` + `chrono` | **builds** |
| `dtg-credentials` 0.7 (`default-features = false`) + `affinidi-data-integrity` 0.7 | **builds** |
| `vti-rooms`' member half, **sources unmodified**, host modules and `vti-common` removed | **builds** — 465 KB `.wasm` |

Since shipped as the `host` feature: `cargo check -p vti-rooms --lib
--no-default-features --features mls --target wasm32-unknown-unknown` passes in
the workspace, guarded by two steps in CI's `features` job.

Three facts worth not re-deriving:

- **`openmls` 0.9 ships a first-class `js` feature** (`dep:web-time`,
  `getrandom/wasm_js`). Without it the build fails on `use web_time::SystemTime`
  in `key_packages/lifetime.rs`, which reads like an unsupported target and is
  not.
- **Two `getrandom` majors are live in one graph.** The 0.4 is `vti-rooms`' own;
  the 0.2 arrives transitively under `openmls_rust_crypto`, through RustCrypto's
  elliptic-curve stack, so no feature the crate declares can reach it — it needs
  a direct `features = ["js"]` shim. Every failure here reports as a
  `compile_error!` naming one version, which reads like an unsupported target and
  is not.
- **No `RUSTFLAGS` are needed.** An early probe set
  `--cfg getrandom_backend="wasm_js"` and it was never removed to check; with
  both getrandoms declared per-target with their features, the build is clean
  without it. Worth stating because "you must also set RUSTFLAGS" is the kind of
  detail that gets copied into a Dockerfile and never questioned.
- **`dtg-credentials`' `affinidi-signing` feature is optional and default-on.**
  Turning it off drops `affinidi-secrets-resolver`, and `DTGCredential::sign`
  still works because `affinidi-data-integrity` takes a `Signer` **trait
  object** — the same seam `RoomKeySigner` uses server-side. The browser supplies
  its own.

This is a feature-gate change to `vti-rooms` plus a binding crate. It is not a
port.

### 3.2 The split: what is Rust, what is TypeScript

**In wasm (`vti-rooms-wasm`, a new crate):**

- MLS: mint a KeyPackage, join from a Welcome, apply a commit, current epoch.
- Sealing: seal and open a record at an epoch.
- The epoch key chain: store rungs, walk backwards, report
  `earliestReadableEpoch`.
- **Presentation minting**: `DTGCredential::attenuate` + sign. This belongs in
  Rust and not in TypeScript, because `attenuate` is what refuses to *widen*.
  Reimplementing that rule in JS would duplicate the one check that stops a
  member presenting more authority than the room gave them.

**In TypeScript (`@openvtc/pnm-core`, already written):**

- Trust Task documents and their `eddsa-jcs-2022` proofs
  (`trust-tasks/sign.ts`, `canonical.ts`).
- The `rooms/*` host calls (`rooms/index.ts`) — pointed at the host rather than
  a VTA, which is what `RoomsCaller.service` was always for.
- `did:key` derivation and verification-method shape (`did/`).

The seam is: **wasm holds secrets and produces bytes; TypeScript speaks the
wire.** Nothing that crosses the boundary is a private key.

### 3.3 Persistence

`IdentitySnapshot` and `GroupSnapshot` already externalise the whole OpenMLS
provider store as an opaque blob — a decision made server-side because OpenMLS
persists a group *through* its provider, and picking out "just the group" means
reimplementing its layout. That decision is what makes a browser member cheap:
the tab keeps the blob in IndexedDB and hands it back. No storage adapter, no
`openmls_sqlite_storage`, no new trait.

Kept per visitor, in IndexedDB:

| | |
|---|---|
| Ed25519 key | non-extractable `CryptoKey` where the browser allows it |
| `did:key` | derived, lexical — no resolution, no network |
| group snapshot | one blob per room |
| epoch-link rungs | the chain, per room |
| VMC + VAC | the room-issued credentials |

A cleared browser is a lost identity. The site must say so on the first screen
and offer an export, because a person who loses a demo identity silently learns
the wrong lesson about self-custody.

### 3.4 What this buys beyond the demo

The same artifact is the missing member-side library for any browser client, and
it removes a real limitation: `pnm-cli rooms put` is documented as `open` rooms
only, because sealing needed a VTA. A browser-native member seals locally and
writes to sealed rooms without asking anyone.

---

## 4. What the design actually runs into

Three things looked like gaps. **One was not** (§4.1) — the correction is kept
because the mistake is instructive and a reader will make it too. The other two
are real, and neither is demo scaffolding: each is a hole the demo is simply the
first thing to fall into.

> **Read §10 alongside this.** The site has since been built and run, and two of
> the conclusions below did not survive it: §4.2's premise that a browser cannot
> be addressed at all (it can, but only within a session), and §4.3's plan to
> close its gap as a Trust Task family (the wrong shape — see §10.3). Both are
> left standing here, with the corrections kept separate, because the reasoning
> is where the value is.

### 4.1 Host addressing is out-of-band, and that is deliberate

*This section began as a claimed gap. It is not one, and the correction matters
enough to keep rather than delete.*

A room's DID document names a mediator and nothing else
(`vta-sdk/templates/room.json`), so resolving a room DID does not yield a host.
That is **by design**, and the specification says so in as many words. From
`rooms/keys/backfill/0.1`:

> The host to fetch from, as a DID. **Named by the caller because nothing maps a
> room to its host**: a room is portable — re-point it and it has moved — so a
> remembered host is a value that goes stale […] A caller who names the wrong
> host learns so as a refusal from a party that does not serve this room, which
> is loud and immediate.

And from `rooms/owner/register/0.1`, the stronger reason: **a room may be
registered with more than one host** — "a mirror serves reads while its primary
takes writes". A single host pointer in the DID document would not be merely
stale; it would be *wrong*.

Host **endpoint** discovery does exist and is the normal mechanism: a caller
names the host by DID, and that DID resolves to a service endpoint
(`operations/room_host.rs`'s `send_room_task`, over `vta-sdk`'s
`ServiceCapabilities::from_did_document`). What is deliberately absent is only
the room→host link.

So `{roomDid, host}` in the site's URL is **not a workaround**. It is the same
addressing `pnm-cli` takes as `--room` and `--host`, and it is what the spec
asks a caller to supply. The demo carries the host in the invite link and in the
broker's catalogue, and a visitor who types a room DID with the wrong host gets
the refusal the spec designed for — which the site should render as "that host
does not serve this room", because it is an answer.

One genuine nit falls out of this. `room.json`'s description says a room is
portable because you can "re-point its service endpoint and the room has moved".
Given that nothing maps a room to its host, that sentence points at a mechanism
the document does not have, and reads exactly the way it misled this design on
its first pass. Worth rewording to say that portability comes from the room
issuing its own credentials, so a member simply names a different host.

### 4.2 Admission assumes the member is addressable

Today's ceremony is push-shaped, and every step presumes the member is an agent
the owner can reach: the owner calls `rooms/keys/key-package` **on the member's
VTA**, then sends the Welcome to it. A browser tab has no DIDComm address and no
inbox.

A browser member must **pull**. The ceremony inverts:

```
browser: mint KeyPackage locally (wasm)
browser → broker:  POST /join { did, keyPackage }
broker (as owner): rooms/owner/invite      → VIC for that did:key
broker (as owner): add the KeyPackage to the group, commit
broker → browser:  { welcome, epochLinks, membershipVc, authorityVc, roomDid, host, hostDid }
browser: apply the Welcome (wasm), store the chain and both credentials
```

Every credential is real and issued by the room; only the *carriage* changed.

### 4.3 Rooms have no join ceremony

The `rooms/*` family runs to twenty-two tasks — thirteen served by a member's
VTA, nine by a host — and not one of them is a join request. A VTC has
`join-requests/{submit,manifest,status}`; a room's admission is owner-only —
`owner/invite`, `keys/key-package`, `keys/welcome`, `owner/issue-membership`,
`owner/issue-authority`.

The broker's `POST /join` above is, in effect, an unspecified `rooms/join/*`
ceremony. Building it as a demo endpoint is fine; **pretending it is not a spec
gap is not.** The pull-shaped join is what any non-agent member needs — a
browser, a mobile app, a CI job — and it should go upstream as a Trust Task
family once the demo has shown its shape.

Worked out to the edge of that in
[`data-rooms-joining.md`](data-rooms-joining.md), which finds the mechanism
smaller than it looks — the room is *already* addressable, and `room.json` says
so — and finds the part worth waiting for: **what makes an applicant
admissible** is policy, differs per tier, and is the one thing a spec written now
would freeze wrongly.

---

## 5. The broker — the only backend, and how small it is

Because the browser is the member, the visitor needs **no VTA and no ACL entry**.
The self-enrolment problem disappears: `acl.rs:530` requires admin to grant, and
nothing needs granting.

What remains is the *owner* side, which is a real agent and must be:

- holds the demo rooms' owner identity (a VTA it drives);
- serves `POST /join` (§4.2) and auto-admits, per the room's policy;
- serves `GET /rooms` — the catalogue of demo rooms, each `{roomDid, host,
  hostDid, admission}`.

That is all. Every other call in the site is browser→host, direct.

**Auto-admit with the approval shown.** The site displays each of the five owner
acts as it happens — invitation issued, key package added, commit, membership
issued, authority issued — with the credential each produced. A demo that hides
admission behind a spinner demonstrates a login form. The governance *is* the
product.

The broker must be the only thing that can widen access. A visitor asks for a
room in the catalogue and gets exactly the authority that room's policy grants;
it never proxies an arbitrary host, and it never signs anything on a visitor's
behalf.

---

## 6. The site

A static SPA. One page per concern, nothing hardcoded per room.

| Route | What |
|---|---|
| `/` | who you are — mint or import a `did:key`, export it, the honest warning |
| `/rooms` | rooms this browser holds keys for, from local state + the catalogue |
| `/room/<did>?host=<hostDid>&at=<url>` | records: list, read, write, curate |
| `/room/<did>/join` | the admission ceremony, step by step |
| `/room/<did>/keys` | epochs, `earliestReadableEpoch`, the chain, what it means |

Two epoch numbers belong on screen wherever a room does, because they are
different repairs: an `epoch` behind the room's own means an undelivered commit;
`earliestReadableEpoch` equal to `epoch` means the chain has not arrived. Shown
as one number, "less history than I expected" reads as loss rather than as a
delivery that has not happened yet.

**A room is addressed, never configured.** The room list comes from local group
state; a room is `{roomDid, hostDid, endpoint}` off the URL. That is the whole
of "one site, any number of rooms" — including a room the site has never seen,
hosted by a VTC the site does not know, provided the visitor holds credentials
for it.

The host appears **twice** for the reason `pnm-cli` takes both `--host` and
`--host-did`: the DID is what a presentation is bound to, and the URL is where
the bytes go. Server-side, `send_room_task` derives the second from the first by
resolving the host's DID. A browser could do the same — `did:webvh` resolution
is plain HTTPS — and should, eventually, so a link carries one identifier rather
than an identifier plus a location. Until then the catalogue supplies both, and
`at=` is an override for a host the catalogue has never heard of. **A
presentation bound to no host is usable by anyone who observes it until it
expires**, so the site must never let `host` go unset merely because it only had
a URL.

**CORS is a deployment step, not a code change.** Both services already build a
configurable allow-origin layer — `vta-service/src/routes/mod.rs:233`,
`vtc-service/src/server.rs:1427`. The demo origin goes in both lists. A host
that has not added it is simply not reachable from the site, which is the
correct default and should be reported as such rather than as a network error.

**Reading a host's refusal correctly.** A host's `trust-task-error` is its
*answer*. Surface its code and reason as a refusal — "the room did not grant you
`curate`" — never as a failed request. This is the single most instructive thing
the demo can show, and rendering it as a 502 wastes it.

---

## 7. What the site must say out loud

- **Your key is in this browser.** Clearing site data destroys it. Export it.
- **This is a demo room.** Its owner admits anyone who asks. Real rooms do not.
- **The host cannot read this.** Show the ciphertext next to the plaintext once,
  on one record, because that is the claim everything else rests on.
- **Your authority expires.** The presentation is minted per action, for one
  action, for four hours. Show it, and show it being re-minted.

Deliberately *not* demonstrated: the `private` tier. Its subject-binding
verifier is a seam with no implementation and the ZK profile is still a
working-group decision. A demo tier that silently behaves like `sealed` would
misrepresent it.

---

## 8. Delivery sequence

| # | Repo | What | Depends on |
|---|---|---|---|
| 1 | vti | Gate `storage`/`authz`/`audit` behind a default-on `host` feature; `vti-common` becomes optional. `--no-default-features --features mls` builds for wasm32 | — |
| 2 | vti | `vti-rooms-wasm`: wasm-bindgen bindings — identity, key package, welcome, commit, seal, open, chain, present | 1 |
| 3 | vti | ~~Reword `room.json`'s portability sentence (§4.1)~~ — **done**; it now says portability comes from the room issuing its own credentials, and that a host pointer in the document would be wrong rather than stale | — |
| 4 | plugin | `@openvtc/pnm-core/rooms` host calls usable against a host base URL (they are already shaped for it); publish | — |
| 5 | new | The broker: catalogue + `POST /join` (§4.2), driving a demo-owner VTA | — |
| 6 | new | The site: identity → catalogue → join → read | 2, 4, 5 |
| 7 | new | Write, curate, and the keys/epoch pane | 6 |
| 8 | spec | ~~`rooms/join/*` as a Trust Task family~~ — **superseded, see §10.3.** The gap is real; a task family is the wrong shape for it, because a Trust Task is an instruction to your own agent and this is a stranger asking an owner to decide. A request protocol between two parties, closer to a VTC's `join-requests/*` | 5 |

1–2 are the ones with real risk and none of it is unknown; 3 is a paragraph.
6–7 are the demo.

**Where the site lives** is undecided: a new repo under OpenVTC, or `demo/`
inside vti. A new repo, on the grounds that it deploys on its own cadence and
depends on published artifacts rather than the workspace — but that is a call
worth making explicitly rather than by whoever runs `cargo new` first.

---

## 9. Open questions

- **Does the epoch key chain reach a browser member?** The three deliveries are
  owner→host, host→member (`rooms/epoch/chain`), member→their own VTA
  (`rooms/keys/chain`). A browser member has no third leg — it *is* the key
  holder. The rungs must arrive in the join response and from
  `rooms/epoch/chain`, which is host-served — so the leg exists. What needs
  confirming is that a host accepts it from a member presenting `read` with no
  VTA anywhere in the path, and that `rooms/keys/chain` then has no counterpart
  here at all rather than a browser-side stand-in.
- **Commit delivery.** A member who misses a commit is stuck at their last epoch
  and every later record fails to open — the symptom reads as corruption. Today
  commits reach a member's VTA. A browser member that has been closed for a week
  needs to catch up on open; where it fetches missed commits from is not
  designed.
- **Bundle size.** 465 KB is the crate before wasm-bindgen glue, `wasm-opt` or
  the credential half. Measure the real thing before promising a fast first
  paint.
- **Non-extractable keys and export are in tension.** Both matter here. Probably
  two modes, chosen at mint, and the choice explained rather than defaulted.
- **Does anything about a browser member weaken the pooling defence?** The rule
  is that the chain's *root* subject is what a host compares, and the root is
  the grant the room made. A browser member's root and leaf subject are the same
  DID, which is a case the server-side path never produces. Worth a test, not a
  redesign.

---

## 10. What building it changed

*Written after the site was built and run against a live mediator. Kept as an
addition rather than an edit, for the same reason §4.1 is: the reasoning that
turned out wrong is the useful part, and a reader arriving at this design fresh
will make the same two mistakes.*

### 10.1 §4.2's premise was wrong: a browser tab **can** have a DIDComm address

The note says a browser tab "has no DIDComm address and no inbox", and builds
the pull-shaped ceremony on that. The first half is false. A tab can mint a
`did:peer:2`, connect to a mediator, and be addressed at it for as long as it is
open — which is exactly what the site does now, over both DIDComm and TSP.

The conclusion survives, and that is the interesting part: the ceremony still
has to invert. But not because a browser cannot be addressed — because it cannot
be addressed **between sessions**. An owner that pushed a Welcome to a tab that
has since closed has pushed it nowhere, and the address it used will never exist
again. The pull is right; the reason given for it was not.

That distinction matters beyond the demo. "Cannot be reached" would mean a
browser member needs a permanent agent somewhere. "Cannot be reached between
sessions" means it needs a way to *ask for what it missed*, which is a much
smaller thing and is what §10.4 turned out to be.

### 10.2 A member holds two identities, and the split is forced

Not a demo convenience — neither key can do the other's job.

- The **room identity** (`did:key`, in wasm) is what credentials name and what
  signs every document a room or a host authenticates. Its whole reason for
  living in wasm is that its secret never enters a JavaScript heap or a
  `localStorage` string.
- The **transport identity** (`did:peer:2`, in JavaScript) is what a mediator
  addresses. DIDComm's authcrypt and TSP both need an X25519 secret *in the
  caller's hands* — which means in the page.

One key cannot satisfy both without giving up one of the properties. So the
transport identity is deliberately disposable: minted per session, nothing
issued to it, losing it costs a reconnect.

The consequence is that a request has to prove two different things about two
different keys, and **bind them together**:

1. the envelope proves the transport DID sent it;
2. an `eddsa-jcs-2022` proof inside the body proves the room DID authored it;
3. the body names the transport DID, so the two are one request.

Drop (3) and a signed request becomes a bearer artefact: anybody who saw one
could send it from their own connection and have the reply — the invitation —
delivered to them. The signature still verifies; it simply stops being about the
connection carrying it. This is not a hypothetical the way most such notes are:
it is one clause, it is easy to leave out, and nothing else in the exchange
catches its absence.

### 10.3 §4.3 and §8's item 8 point the wrong way: admission is **not** a Trust Task

§4.3 correctly identifies that `rooms/*` has no join request, and proposes
closing it as a `rooms/join/*` Trust Task family. Building it showed that is the
wrong shape.

A Trust Task is an instruction you give **your own agent**, authorised by your
control of it. `vta-service` gates `rooms/owner/{invite,issue-membership,
issue-authority}` on `CredentialWrite` and never asks who the subject is —
because the caller is the principal, and the subject is just a field. What a
would-be member sends is the opposite: a stranger asking an owner to *decide*
something about them. Expressed as a Trust Task, that says the stranger may
instruct the room's agent, which is exactly what must not be true.

The gap in §4.3 is real. It is a **request protocol** between two parties, not a
task family — closer to a VTC's `join-requests/*` than to `rooms/owner/*`, and
the resemblance is not a coincidence: a VTC has one for the same reason.

The demo implements it as a plain DIDComm/TSP protocol in its own namespace
(`https://dataroom.demo/admission/0.1`), with the two-proof binding of §10.2. It
is deliberately *not* dressed up as a Trust Task, and that is the finding to take
upstream rather than the endpoint shape.

### 10.4 Records needed no new protocol at all, and that is the contrast

The record path is the other half, and it went the other way with no design work
whatsoever — because a record operation genuinely *is* a Trust Task. It is a
member asking a host to act on something it holds, which is what the family is
for, and the framework already binds it to every carrier: DIDComm wraps the
document under one reserved envelope type, and TSP sends the document with **no
wrapper at all**, byte-identical to the HTTP body.

So `room-host` gained a carrier, not a protocol (`--mediator-did`, #1369). The
useful test is that one `dispatch` answers identically whichever wire brought the
bytes — which holds because nothing about *who is asking* comes from the carrier:
the presenter is the document's own proof, the authority is the chain the room
issued, and a transport that authenticates its sender confers nothing extra.

The contrast between §10.3 and this section is the whole lesson. **Asking a
service to act is a Trust Task; asking a person to decide is not.** Both travel
the same wires.

### 10.5 §9's open questions, answered

- **Does the epoch key chain reach a browser member?** Yes. `rooms/epoch/chain`
  is host-served and a member presenting `read` gets it with no VTA anywhere in
  the path. `rooms/keys/chain` has no counterpart in a browser and needs none —
  the member *is* the key holder. Watch `earliest readable` fall to 1 as the
  rungs arrive.
- **Commit delivery.** Answered by §10.1: the member asks the **owner** for what
  it missed since its own epoch, over the same mediator it was admitted through.
  Not the host — a host stores ciphertext and has no opinion about who is in a
  room, so it has no commits to give. The owner serves them only to DIDs it
  admitted: a commit confers nothing on a non-member, but how often a room's
  membership changes is the room's business.
  The first cut routed this on the demo's own room slug, which addressed rooms do
  not have — so a room you were handed a link to could join, fall behind at the
  next admission, and find records refusing to open with nothing to say why. That
  failure reads as corruption, which is what makes this the sharpest edge in the
  whole design.
- **Bundle size.** 874 KB gzipped for the wasm, plus 172 KB minified for the
  DIDComm/TSP bundle. Both are vendored build artifacts, neither is on the first
  paint's critical path.
- **Pooling defence.** Unweakened, and asserted rather than assumed: the chain's
  *root* subject is what a host compares, and a browser member's root and leaf
  being the same DID is a case the server-side path never produces but the
  comparison does not care about.
- **Non-extractable keys and export.** Still open, and still two modes.

### 10.6 The broker got smaller than §5 predicted

§5 gives the broker a catalogue and a `POST /join`. It now serves the catalogue
and the page, and nothing else: admission and commit delivery go over the
mediator, and records go to the host directly. There is no longer any path in the
demo where a backend stands in for something rather than being it.

One asymmetry is deliberate and worth keeping. The owner reaches the host by URL
while telling members its DID — because the owner is a server and can open a URL,
and a browser frequently cannot. One host serves both carriers at once and the
client picks, which is the shape a real deployment has.

### 10.7 A room says which carriers it serves

TSP is the higher-preference transport and a mediator multiplexes both onto the
one socket it permits per DID — so a client that always spoke TSP would usually
be right. It would also break against the first owner that served only DIDComm,
with nothing in that owner's document having changed to warn it.

So a room (and a host) advertises `DIDCommMessaging` **and** `TSPTransport` at its
mediator, and a member takes the better of what it is offered. What a party serves
is a thing it says, not a thing a client discovers by succeeding.
