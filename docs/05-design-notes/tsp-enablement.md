# Spec-Driven Design: TSP enablement across VTI (VTA, VTC, PNM, CNM)

**Status:** DRAFT for review — no code until approved.
**Owner:** Glenn Gore
**Created:** 2026-06-25
**Supersedes the decision in:** `docs/05-design-notes/messaging-routing-and-tsp.md`
(that note deferred TSP because the mediator lacked TSP routing/bridging and
`affinidi-tsp` was inert scaffolding; **both blockers have cleared** — see §1).

**Spec basis:** ToIP Trust Spanning Protocol Specification, Rev 2 (Nov 2025,
Experimental Implementer's Draft) — <https://trustoverip.github.io/tswg-tsp-specification/>.
**Upstream design:** `affinidi-tdk-rs` `tasks/tsp-didcomm-mediator-sdd.md`
(dual-protocol mediator + TSP↔DIDComm bridging).

---

## 0. Decisions locked (from review, 2026-06-25)

| # | Decision | Choice |
|---|----------|--------|
| D1 | Dependency posture | **Build now against published 0.x TSP crates.** TSP is active development; we do **not** wait for 1.0. Pin minor versions like other deps; crypto-adjacent crates pin a min patch. |
| D2 | First deliverable | **This SDD.** Code follows in stacked, individually-reviewable PRs once approved. |
| D3 | Protocol preference | **TSP > DIDComm > REST**, effective immediately in guidance (CLAUDE.md flipped in the same change as this note). DIDComm remains fully supported; TSP is strictly additive. |
| D4 | Authority for "is TSP in use?" | **The DID document.** Both source and destination capability is read from advertised services; the chosen protocol is the highest-preference one **present in both** parties' DID docs. No match → typed `NoMatchingProtocol` error. |
| D5 | Identity model | **DIDs are TSP VIDs (phase 1).** The VTA/VTC's existing Ed25519 (auth) + X25519 (keyAgreement) keys serve as the VID key material — no new keys minted. Non-DID VIDs out of scope. |
| D6 | Feature gating | **`tsp` cargo feature**, mirroring `didcomm`. Off by default in the first release, flipped to default-on once exercised in the field. |
| D7 | Full pack/routing | **Use upstream `send_nested` / opaque-carry bridge** (mediator-side); VTI calls it behind the existing send seams. We do **not** build routing ourselves. |
| D8 | TSP vs DIDComm mediator | **Same mediator.** A VTA's `#tsp` and `#didcomm` both bind the **same** `{MEDIATOR_DID}` — the published mediator is one dual-protocol node (both transports, one ACL keyspace), so a separate TSP mediator would be a second node / anti-pattern. **No separate TSP-mediator var or config field.** A distinct TSP mediator is a purely *additive*, non-breaking change if a concrete need ever lands — not built speculatively. |
| D9 | Service discovery key + id convention | **Discover/match services by `type`, never by `#id`.** The `#id` fragment is an arbitrary label; the authoritative match is the service `type` (`DIDCommMessaging` / `TSPTransport` / `VTARest`). **Emitted id convention drops the `vta-` prefix: `#didcomm`, `#tsp`, `#rest`** (was `#vta-didcomm` / `#vta-rest`). Because discovery is type-based, this rename is cosmetic and safe; legacy `#vta-*` ids are still read/removed correctly (found by type). All `id_matches_*` helpers become `type_matches_*`. |

---

## 1. Why this is now buildable (blocker recheck)

The prior decision record (`messaging-routing-and-tsp.md`, 2026-06-22) gave three
reasons to wait. State as of 2026-06-25:

| Blocker then | State now |
|---|---|
| Mediator had no TSP routing / no TSP↔DIDComm bridge (`affinidi-messaging-mediator` 0.16.3 = inert `tsp` flag) | **Resolved.** Published mediator now carries TSP identity, TSP authenticate handler, TSP delivery, nested-TSP-through-mediator, and TSP↔DIDComm bridging (opaque-carry). |
| `affinidi-tsp` was 0.1.x inert scaffolding | **Usable.** `affinidi-tsp` exposes `TspAgent` (`send`/`receive`/`send_routed`/`send_nested`/`forward_routed`/`relationship_*`) and a `did-resolver`-backed VID resolver. Still 0.x and moving, accepted per D1. |
| No metadata-privacy requirement | TSP is adopted as the **preferred** transport (D3), not solely for privacy — it gives metadata-private routing at bounded message size (CESR + HPKE, additive per-hop overhead vs DIDComm-nested's multiplicative blow-up). |

The transport-agnostic Trust Task spine (`dispatch_trust_task_core`) and the single
outbound seam (`send_to_member`) the prior note preserved are exactly the seams this
work plugs into.

### 1.1 Dependency pins (verify against crates.io at implementation time)

Reference versions observed in the local `affinidi-tdk-rs` checkout — confirm the
published numbers before pinning:

| Crate | VTI today | TSP-capable | Action |
|---|---|---|---|
| `affinidi-tdk` | `0.8` | `0.8.x` w/ `tsp` feature (`tsp = [dep:affinidi-tsp]`) | enable `tsp` feature |
| `affinidi-tsp` | — (transitive) | `0.1.6` (`did-resolver` default feature) | new direct dep behind `tsp` |
| `affinidi-messaging-sdk` | `0.18` | `0.18.34` (`tsp` feature, `protocols/tsp.rs`, `atm.tsp()`) | bump + enable `tsp` |
| `affinidi-messaging-mediator` | (test-mediator only) | `0.16.26` (bridging) | runtime dep of the mediator deployment, not VTI crates |
| `affinidi-messaging-didcomm-service` | `0.3` | `0.3.8` | bump |

Crypto-adjacent crates keep min-patch pins (per workspace versioning policy).

---

## 2. The canonical TSP service shape (authoritative)

From `affinidi-tsp::vid::did_resolver`:

```
pub const TSP_SERVICE_TYPE: &str = "TSPTransport";   // OWF reference-impl convention
```

**TSP mirrors the DIDComm mediator-indirection model exactly.** Just as a VTA's
`DIDCommMessaging` service points at its **mediator's DID** (`serviceEndpoint.uri =
{MEDIATOR_DID}`) and the actual transport URL is resolved from the mediator, a
VTA's **`#tsp` service points at its mediator's DID**, and the real REST/WebSocket
transport URL lives in the **mediator's** DID document.

There are therefore **two distinct DID-doc shapes**:

**(a) A consumer / VTA DID document** — `#tsp` points at the mediator's **DID** (VID):

```json
"service": [
  { "id": "{DID}#tsp",      "type": "TSPTransport",     "serviceEndpoint": "{MEDIATOR_DID}" },
  { "id": "{DID}#didcomm",  "type": "DIDCommMessaging", "serviceEndpoint": [ { "uri": "{MEDIATOR_DID}", "accept": "{ACCEPT}" } ] },
  { "id": "{DID}#rest",     "type": "VTARest",          "serviceEndpoint": "https://host.example/" }
]
```

**(b) The mediator's own DID document** — `TSPTransport` holds the actual transport URL(s):

```json
"service": [
  { "id": "{MEDIATOR_DID}#tsp", "type": "TSPTransport", "serviceEndpoint": "https://mediator.example/" }
]
```

Key facts that shape the rest of the design:

- **Service `type` is `TSPTransport`** (interop with any TSP party); **`id` fragment is `#tsp`**.
- **A VTA's `#tsp` `serviceEndpoint` is a DID** — its mediator's VID — *not* a URL.
  The URL is resolved one hop further, from the mediator's `TSPTransport` service.
  (This matches upstream `send_routed`, which takes the **mediator VID as the
  routing intermediary** the sender seals the outer hop to; the mediator's own
  `TSPTransport` URL is where bytes actually land. The OWF reference convention of
  a URL-valued `serviceEndpoint` is the *directly-reachable* case — i.e. the
  mediator's own doc, shape (b) — which `affinidi-tsp`'s resolver reads as `Url`.)
- **The VID keys come from the existing DID doc** — Ed25519 `authentication` key +
  X25519 `keyAgreement` key. The VTA already has both, used for the end-to-end seal
  to the final recipient. **No new VTA key material.** (D5) The **mediator** needs
  its own TSP VID keys + `TSPTransport` URL (deployment concern, upstream-provided).
- **`did:key` has no service block**, so a serverless `did:key` VTA cannot advertise
  a `#tsp` mediator pointer — the *same* constraint that already forces `did:key`
  VTAs to supply mediator/URL out-of-band for DIDComm/REST. TSP needs a
  `did:webvh`/`did:web` doc or an explicit mediator-DID override.

> ⚠️ **Correction (review round 2):** a VTA's `#tsp` `serviceEndpoint` is the
> **mediator DID**, not the VTA's own URL — TSP uses the same mediator indirection
> as DIDComm. Only the mediator's own doc carries a URL-valued `TSPTransport`.
> The service `type` is `TSPTransport` (not a bespoke `#tsp` type — `#tsp` is the `id`).

**Service `type` provenance (verified against the reference impl, review round 3).**
The type string is **`TSPTransport`** — established by the **OWF reference
implementation** (`openwallet-foundation-labs/tsp`, `tsp_sdk/src/vid/did/web.rs`
matches `service_type == "TSPTransport"`; all its example DID docs use it). The
**ToIP TSP spec does *not* define a DID-document service type** — it is transport-/
discovery-agnostic — so `TSPTransport` is a reference-impl convention, not a spec
mandate. `affinidi-tsp` follows it (`TSP_SERVICE_TYPE = "TSPTransport"`). **We use
`TSPTransport`.**

Two facts from the reference code:
- The reference uses `id` fragment **`#tsp-transport`**, Affinidi uses **`#tsp`** —
  same type, different id. Concrete proof that **the `#id` is arbitrary and
  discovery must key off `type`** (D9).
- The reference `serviceEndpoint` is a **direct transport URL** (Direct Mode,
  e.g. `"tcp://…"`). Our consumer-doc convention of putting a **mediator DID**
  there is a **Routed-Mode / VTI layering**, not the reference convention for that
  field. A bare `affinidi-tsp::DidVidResolver` would `Url::parse` the value, so
  VTI's capability/routing layer must branch on the value: **DID ⇒ Routed-Mode
  intermediary (resolve the mediator's own `TSPTransport` URL); URL ⇒ Direct
  Mode.** Confirm the Affinidi *mediator*'s recipient-intermediary discovery
  expects a DID here before finalizing the consumer-doc shape (open question §14).

---

## 3. Protocol matching — the load-bearing new logic (D4)

Today's transport selection is **one-directional and shape-sniffing**:
`vta-sdk/src/session.rs::resolve_vta_endpoint` walks a counterparty DID doc, and
`integration/auth.rs::decide_transport` picks DIDComm-if-mediator-DID-else-REST.
The WakeHandle convention treats *a DID as DIDComm, a URL as REST*.

That heuristic **breaks under TSP**: a TSP VID is also a DID, so "endpoint is a DID ⇒
DIDComm" is ambiguous. The fix is structural.

### 3.1 Capability discovery (read from the DID document)

Replace endpoint-shape sniffing with **service-`type` matching** (D9). Resolve the
counterparty DID doc once and build a capability set by walking `service[]` and
keying off each entry's **`type`** — **never** its `#id` fragment, which is an
arbitrary label a peer may name anything:

```rust
// vta-sdk/src/session.rs (or a new protocol::matching module)
struct PeerCapabilities {
    tsp:     Option<String>,   // service.type == "TSPTransport"     → serviceEndpoint = peer's MEDIATOR DID
    didcomm: Option<String>,   // service.type == "DIDCommMessaging" → mediator DID
    rest:    Option<String>,   // service.type == "VTARest"          → URL
}
```

For TSP, the `TSPTransport` value is the peer's **mediator DID**, not a transport
URL. Reaching the peer is then a second resolution hop: resolve that mediator
DID's own `TSPTransport` service (shape (b), §2) to get the actual delivery URL.
So discovery is two-level — peer doc → mediator DID → mediator doc → URL — exactly
as DIDComm resolves the `DIDCommMessaging` `uri` (a mediator DID) onward.

- `tsp` present iff a service of `type == "TSPTransport"` exists (reuse
  `affinidi_tsp`'s extractor so our parsing matches the wire stack exactly).
- `didcomm`/`rest` likewise selected by `type`, regardless of `#id`.

### 3.2 Selection (intersect, then prefer)

```
ours    = our advertised capabilities (from our own services config / DID doc)
theirs  = PeerCapabilities (resolved above)
chosen  = first protocol in [Tsp, Didcomm, Rest] present in BOTH ours and theirs
```

- Honour an explicit operator override (`TransportPreference`, extended below) but
  never select a protocol the peer doesn't advertise.
- Empty intersection → **`NoMatchingProtocol`** (§3.4).

### 3.3 `Transport` and `TransportPreference` (vta-sdk)

- `vta-sdk/src/client/mod.rs`: add `Transport::Tsp { agent, endpoint, our_vid, rest_* }`
  and a dispatch arm everywhere `match &self.transport` appears (notably
  `client/bootstrap.rs::provision_integration`, `rpc`, `rpc_void`, `rpc_tt`).
- `vta-sdk/src/integration/{mod,auth}.rs`: extend `TransportPreference`
  (`Auto` now = TSP→DIDComm→REST) and `decide_transport` / `TransportPlan` to a
  3-way plan with the new no-match terminal state.

### 3.4 The "No matching protocol" error (typed, both transports)

Per CLAUDE.md's "operator errors should suggest the fix" + typed-`VtaError` discipline:

- `vta-sdk/src/error.rs`:
  ```rust
  VtaError::NoMatchingProtocol {
      counterparty_did: String,
      ours:   Vec<Protocol>,   // what we advertise
      theirs: Vec<Protocol>,   // what they advertise
  }
  ```
- `vti-common/src/error.rs`: a matching `AppError` variant.
- Trust-Task / wire error code in the `e.p.msg.*` family (e.g.
  `e.p.msg.no_matching_protocol`) — distinct from `unauthorized`/`forbidden`.
- CLI renders both advertised sets so the operator sees *why* it failed and what to
  enable on either side.

---

## 4. Service-management surface (mirror REST/DIDComm exactly)

All in the established protocol-management pattern.

### 4.1 DID-document patchers — `vta-service/src/operations/protocol/document.rs`

- Constants: `TSP_SERVICE_FRAGMENT = "#tsp"` (emitted id), `TSP_SERVICE_TYPE = "TSPTransport"`.
- `with_tsp_service(doc, mediator_did)`, `without_tsp_service(doc)`,
  `current_tsp_service(doc) -> Option<TspServiceRef { id, mediator_did }>`. The patcher
  takes a **mediator DID** (the serviceEndpoint value), not a URL — symmetric with
  `with_didcomm_service(doc, mediator_did)`.
- **Match by `type`, not `id` (D9):** replace the `id_matches_didcomm/rest(id)` helpers with
  `type_matches_*(service)` keyed off the service `type` (`DIDCommMessaging` / `TSPTransport`
  / `VTARest`). `current_*` / `without_*` find their entry by `type` so a **legacy
  `#vta-didcomm` / `#vta-rest`** entry is still located, updated, and removed correctly.
- **Emitted-id convention (D9):** new docs emit `#didcomm` / `#tsp` / `#rest`. Renaming
  `DIDCOMM_SERVICE_FRAGMENT`/`REST_SERVICE_FRAGMENT` is cosmetic because nothing matches on
  the fragment any more. On the first service-management op after upgrade, an existing
  `#vta-didcomm` entry is found-by-type and re-emitted as `#didcomm` (idempotent).
- **`sort_services_canonical` reorder (D3):** sort by `type` — `TSP(0) > DIDComm(1) >
  REST(2) > WebAuthn(3)`. This changes the on-wire `service[]` ordering precedence — DID-Core
  resolvers walking the array now pick TSP first. Update the inline rationale comment
  (currently "DIDComm first") to match.

### 4.2 Operations — `vta-service/src/operations/protocol/`

New files mirroring `enable_rest.rs` etc.: `enable_tsp.rs`, `update_tsp.rs`,
`disable_tsp.rs`, `rollback_tsp.rs`. Wire into `mod.rs`, the `PROTOCOL_LOCK`,
`snapshot.rs` (per-kind rollback snapshot, fjall keyspace), and `invariant.rs`
(brick-prevention — TSP counts toward "≥1 transport advertised").

**Drain semantics:** TSP inter-mediator relay is stateless per-message (upstream SDD
D1), so TSP transitions need **no drain window** (unlike DIDComm mediator changes).
`enable/disable/update/rollback_tsp` skip the drain machinery. Document this asymmetry.

### 4.3 Wire types — `vta-sdk/src/protocol/services.rs`

- `ServiceState::Tsp { enabled: bool, mediator_did: Option<String> }` (mirrors
  `ServiceState::Didcomm`'s `mediator_did`, not the URL-shaped REST variant).
- `EnableTspRequest { mediator_did }`, `UpdateTspRequest { mediator_did }`, disable/rollback bodies.

### 4.4 Config — `vta-service/src/config.rs`

- `ServicesConfig { rest, didcomm, webauthn, tsp: bool }` (default `false` initially, D6).
- TSP mediator DID lives alongside the DIDComm mediator in `MessagingConfig` (it's a
  mediator pointer, same shape) rather than a separate URL-bearing config.

### 4.5 CLI — `vta-cli-common/src/commands/services.rs`

- `pnm/cnm services tsp {enable,update,disable,rollback}`.
- `services list` (`cmd_services_list`) prints `TSP: [on|off]` + endpoint.
- Offline `vta services …` surface gets the TSP verbs (direct fjall, no auth).
- Note: `enable_tsp` is reachable over both transports (unlike `enable_didcomm`
  which is REST-only because DIDComm isn't running yet) — TSP enable can ride REST
  *or* an already-running DIDComm session.

---

## 5. DID templates (`#tsp` service block)

Two template shapes, matching §2:

- **Consumer/VTA templates** (`vta-admin`, the `did-host-*` family): add a `TSPTransport`
  service whose `serviceEndpoint` is the **mediator DID** — reuse the **same**
  `{MEDIATOR_DID}` placeholder that the `DIDCommMessaging` block already binds (D8: one dual-protocol
  mediator, so no new var). When a template advertises DIDComm, advertising TSP is a
  second service block bound to the identical `{MEDIATOR_DID}`. Consider a
  `did-host-http-didcomm-tsp` built-in for the fully-dual shape.
- **The mediator template** (`didcomm-mediator`): add a `TSPTransport` service whose
  `serviceEndpoint` is the mediator's **transport URL** (shape (b)) — a new
  `{TSP_URL}` placeholder, plus the mediator's TSP VID keys if distinct.
- `vta-sdk/src/did_templates/{render,validate}.rs`: register any new placeholder in the
  token table + `requiredVars`/`optionalVars`; the renderer already owns var validation
  (reuse it — don't re-implement, per CLAUDE.md).
- Keep one-release **alias** discipline if any existing template id changes.

---

## 6. Inbound, auth, and the sealed envelope

### 6.1 TSP inbound listener — `vta-service/src/server.rs`

Add a TSP listener alongside the DIDComm one in `AppState` (gated on `tsp` + a running
endpoint), feeding the **same** `dispatch_trust_task_core` spine. Same restart-resilience
and shutdown-handle treatment DIDComm has. VTC mirrors this in
`messaging::run_didcomm_service`'s neighbourhood.

### 6.2 Auth — a third ingress on `handle_authenticate`

`vti_common::auth::handlers::handle_authenticate` already content-negotiates
(DI-signed Trust Task / DIDComm envelope). TSP adds a third inbound: the upstream
mediator mints **the same EdDSA `SessionClaims` JWT** after a TSP handshake (upstream
SDD D1). VTI side:

- Accept TSP-delivered authenticate Trust Tasks through the new listener; the proven
  signer is the unpacked TSP sender VID (a DID), exactly as DIDComm yields `msg.from`.
- **Audience isolation holds:** VTA vs VTC audiences must reject cross-audience TSP
  tokens identically to today.

### 6.3 Sealed-envelope `TspMessage` — wire the unseal path

`vta-service/src/trust_tasks/vault.rs` already *recognises* the `tsp-message`/`tspMessage`
envelope variant (`SealedEnvelope::TspMessage`) but returns `envelope_unsupported`.
Enabling TSP means implementing its unseal via `affinidi_tsp` so `vault/*` secret-bearing
Trust Tasks accept TSP-sealed payloads. (Note: `sealed_transfer` HPKE armor is a separate
format and is unchanged — this is only the Trust-Task cipher envelope.)

---

## 7. Outbound pack / routing / nesting (D7)

Behind the existing seams only:

- VTC: `vtc-service::server::AppState::send_to_member` — add a TSP arm. To reach a
  member behind a mediator: resolve the member's `#tsp` → **member's mediator DID**, then
  `send_routed(our_vid, final_vid = member_did, intermediaries = [member_mediator_did],
  payload)`. The inner is sealed end-to-end to the member; the outer routing hop is sealed
  to the mediator VID (whose `TSPTransport` URL is the actual delivery target). `send_nested`
  adds metadata-private wrapping where wanted.
- For a **TSP→DIDComm-only peer**, use the upstream **opaque-carry bridge** (SDD D3): the
  inner blob is a DIDComm `forward` to the final recipient, carried opaque inside TSP to
  the bridge mediator; content stays E2E, the bridge sees only routing metadata.
- VTA: the equivalent messaging send path.
- Selection of which arm — and the intermediary mediator DID — is driven entirely by §3
  (peer DID-doc capability match + the second-hop mediator resolution).

We do **not** implement onion construction ourselves — `send_nested` and the mediator
bridge own it.

### 7.1 Verified mediator/SDK routing mechanics (round 4)

Traced through `affinidi-messaging-mediator` (`messages/inbound.rs`) and
`affinidi-messaging-sdk` (`protocols/tsp.rs`). This is what makes the `#tsp` =
mediator-DID convention work, and the constraints to honour when building routes:

- **Who reads a consumer's `#tsp` value:** only the **VTI sender**. To reach member
  `M` served by mediator `Med`, the sender resolves `M`'s DID doc, reads the
  `TSPTransport` service (value = `Med`'s DID), and calls
  `atm.tsp().send_routed(route = [Med_did, M_did], payload)`. The SDK seals the inner
  end-to-end to `M`, seals the outer hop to `Med`, and **POSTs to the sender's *own*
  mediator `/inbound`** over the existing DIDComm-authenticated session (it does *not*
  dial the recipient's endpoint directly).
- **The mediator never URL-parses a consumer endpoint.** `Med` receives the routed
  message, `next_hop` yields `Forward{next = M, remaining = []}`, and
  `forward_to_next(M)` checks `account_exists(sha256(M))`. `M` is a **registered local
  account** at `Med`, so it takes the `deliver_opaque` local-pickup path — `M`'s own
  DID doc / `#tsp` value is never resolved or parsed.
- **`TSPTransport` is URL-parsed only on a *remote* hop.** `forward_tsp_remote` (used
  when the next hop is **not** a local account — i.e. another mediator) resolves that
  hop's DID via `DidVidResolver` and takes `endpoints.first()` (a URL) to POST to its
  `/inbound`. `DidVidResolver` URL-parses `TSPTransport` and **silently drops non-URL
  values**, so a remote hop with no URL endpoint fails with `message.tsp.no_endpoint`.
- **Keys always resolve regardless.** `DidVidResolver` extracts Ed25519/X25519 keys
  independently of the endpoint, so a consumer whose `#tsp` is a DID resolves fine for
  the end-to-end seal (empty `endpoints`, which is never used for a local recipient).

**Constraints this imposes (build routes accordingly):**
1. A VTA/consumer's `#tsp` value must be **a mediator DID at which that consumer is a
   registered account** — never the bare consumer as a remote hop (that would hit
   `forward_tsp_remote` → `no_endpoint`).
2. A **mediator's own** `#tsp` must be a **URL** (shape b) — it's the only place the
   stack URL-parses, on mediator→mediator forwarding.
3. VTI's capability layer (§3) still branches DID-vs-URL when reading a peer `#tsp`:
   a DID → use as `route[0]` intermediary; a URL → a directly-reachable Direct-Mode
   peer (the reference-impl shape). Both are valid inputs.

---

## 8. Reporting, health, telemetry

### 8.1 Reporting

- `vta-service/src/operations/protocol/list.rs`: emit `ServiceState::Tsp`.
- `report.rs` + `vti_common::telemetry::TelemetrySink`: generalise the mediator-inbound
  report to per-protocol counts (or add a TSP report); add a TSP telemetry event variant.
- `services.rs` CLI prints TSP rows in `list` and `report`.

### 8.2 Health checks

- `vta-service/src/routes/health.rs::health_details` and
  `vtc-service/src/routes/health.rs::diagnostics`: surface TSP listener status +
  endpoint alongside mediator URL/DID.
- `pnm-cli/src/commands/health.rs`: add a **TSP connectivity probe** parallel to the
  DIDComm `TrustPingSession` trust-ping (TSP ping / Trust-Tasks account-ping over TSP,
  per upstream). This is the one health item that's more than a field addition.

---

## 9. Setup wizards

- `vta-service/src/setup/interactive.rs`: add **TSP** to the services multiselect
  (`["REST API", "DIDComm Messaging", "TSP"]`, ≥1 required) and a TSP-config branch
  (endpoint URL / host) in the messaging section.
- `vta-service/src/setup/from_toml.rs`: `ServicesConfig.tsp` + a TSP variant of
  `MessagingInput`.
- `pnm-cli/src/setup.rs`, `cnm-cli/src/setup.rs`: these **discover** transport from the
  peer DID doc rather than prompting, so they inherit §3 with little new prompting; PNM
  persists a TSP analog next to `mediator_did` where relevant.

---

## 10. Cross-cutting items easy to miss

1. **WakeHandle / push-gateway ambiguity** (`vta-mobile-core::push::WakeHandle.gateway`):
   "DID ⇒ DIDComm, URL ⇒ REST" is now ambiguous (TSP VID is a DID). Add an explicit
   protocol tag rather than inferring from string shape. Update the CLAUDE.md
   push-gateway example.
2. **VTC backup census:** if TSP adds keyspaces (e.g. TSP relationship/session state,
   per-kind snapshot), classify them in `keyspaces::BACKED_UP` / `EXCLUDED_FROM_BACKUP`
   — the partition is pinned by a census test that will fail otherwise. Mirror the VTA
   backup export/import if its state must survive restore.
3. **`vta-mcp`** explicitly lists `didcomm` in its dep features — add `tsp`.
   **`didcomm-test`** harness → a TSP connectivity harness (or extend it).
4. **`vta-enclave` (TEE):** TSP endpoint reachability over the vsock bridge (SNI/host
   override) mirrors the existing mediator-host override; the offline `vta services …`
   TSP verbs are **not** for TEE deployments (direct fjall lock), same caveat as today.
5. **Service-id rename (D9):** the `#vta-didcomm` / `#vta-rest` ids become
   `#didcomm` / `#rest` everywhere they're *emitted* (templates, `document.rs`
   constants). Pure cosmetic given type-based discovery, but it touches existing
   DIDComm/REST code/templates — call it out in the DIDComm PRs, keep legacy ids
   readable for one release.
6. **Docs:** new `docs/02-vta/tsp.md` (operator guide), update
   `docs/02-vta/runtime-service-management.md` (TSP verbs), and mark
   `messaging-routing-and-tsp.md` as superseded by this note.

---

## 11. CLAUDE.md guidance flip (D3 + D9 — landed with this note)

- **"Prefer DIDComm transport wherever possible"** → **"Prefer TSP, then DIDComm,
  then REST."** TSP becomes the first-reach transport; DIDComm is the supported
  fallback for peers that don't yet speak TSP; REST is the last fallback.
- **Service ordering (§3.3 of CLAUDE.md):** "DIDComm comes first" → "TSP comes first,
  then DIDComm" (matches `sort_services_canonical`, §4.1).
- Authority statement: **the DID document is authoritative** for whether a party speaks
  TSP; protocol is chosen by matching both parties' advertised services (§3).
- **Discovery by `type`, not `#id` (D9):** services are matched on `type`
  (`DIDCommMessaging` / `TSPTransport` / `VTARest`); the `#id` is an arbitrary label.
  Emitted-id convention is `#didcomm` / `#tsp` / `#rest`.

---

## 12. Long-term DIDComm deprecation (phased)

TSP is additive now; DIDComm removal is a later, separate decision. Sketch:

1. **Phase A (this work):** advertise TSP + DIDComm; prefer TSP when both peers speak it.
2. **Phase B:** TSP default-on (flip D6); telemetry on DIDComm-only peers.
3. **Phase C:** warn when falling back to DIDComm; encourage peers to enable TSP.
4. **Phase D:** stop advertising DIDComm by default (operators can re-enable); keep the
   code path for legacy peers.
5. **Phase E:** remove — only once telemetry shows no DIDComm-only peers remain.

No peer is stranded mid-migration: the §3 matcher always picks a protocol both sides
share, and the brick-prevention invariant keeps ≥1 transport advertised throughout.

---

## 13. Suggested PR breakdown (stacked, individually reviewable)

1. **Feature flags** across all crates (`tsp`, off by default) + dep bumps/enables (§1.1, §4.4).
2. **Service primitives**: `document.rs` constants/patchers + `sort` reorder + `ServiceState::Tsp` (§4.1, §4.3).
3. **Matching engine**: capability discovery + 3-way selection + `NoMatchingProtocol` (§3) — *the design-risk PR*.
4. **DID templates**: `TSPTransport` blocks + renderer vars (§5).
5. **Service-management ops + CLI**: enable/update/disable/rollback + `services tsp` (§4.2, §4.5).
6. **Inbound listener + auth third path + sealed-envelope unseal** (§6).
7. **Outbound seams** (`send_to_member`, VTA send) using `send_nested`/bridge (§7).
8. **Reporting + health + telemetry** (§8).
9. **Setup wizards** (§9).
10. **Cross-cutting**: WakeHandle tag, backup census, vta-mcp/didcomm-test, TEE, docs (§10).
11. **CLAUDE.md flip** (§11) — lands early (with PR 1) so all subsequent code is TSP-first.

---

## 14. Open questions for review

1. ~~Endpoint vs mediator for TSP~~ **Resolved (round 2):** a VTA's `#tsp`
   serviceEndpoint is its **mediator's DID** (same indirection as DIDComm); only the
   mediator's own doc carries a URL-valued `TSPTransport`. A VTA does not host a direct
   TSP endpoint in the normal case.
2. ~~Same-mediator assumption~~ **Resolved (D8):** a VTA's `#tsp` and `#didcomm`
   bind the same `{MEDIATOR_DID}` (one dual-protocol mediator); no separate TSP-mediator
   var. A distinct TSP mediator is a future additive change only.
3. ~~`#tsp` on the mediator's own DID doc~~ **Resolved (round 3):** **not VTA's job.**
   Managing the mediator's own service endpoints is the **mediator DID controller's**
   responsibility. VTA provisioning does **not** patch the mediator's DID doc; it only
   *references* the mediator DID and trusts the controller to have advertised
   `TSPTransport` there.
4. ~~VTC member messaging default~~ **Resolved (round 3):** VTC→member **stays DIDComm
   until the Phase B flip** (§12). TSP is advertised/accepted before then, but VTC's
   outbound default does not switch to TSP until Phase B.
5. ~~Endpoint-shape vs reference impl~~ **Resolved (round 4, verified against the
   mediator + SDK source):** the consumer-doc convention (`#tsp` = mediator DID) is
   sound — see §7.1 for the verified mechanics. The mediator **never URL-parses a
   consumer's DID-valued endpoint**; consumer endpoints are read only by the *sender's*
   VTI routing layer to pick `route[0]`. Mediators' own `#tsp` is a URL (shape b), used
   only on remote mediator→mediator hops.
6. **Trust-Task error-code registration:** confirm `e.p.msg.no_matching_protocol` is the
   right slug against the openvtc error registry.
