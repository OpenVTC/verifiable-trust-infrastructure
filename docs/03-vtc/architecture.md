# VTC architecture

How `vtc-service` is laid out, what each module owns, and how it
maps onto the runtime surfaces an operator sees.

## At a glance

```mermaid
graph TB
    subgraph Transport["Transport surfaces"]
        REST["/v1/* (REST + JWT)"]
        DC["DIDComm v2 (mediator)"]
        ADMIN["/admin/* (cookie SPA)"]
        WEB["/ (public website)"]
        HEALTH["/health"]
    end

    subgraph Middleware["Middleware (Phase 5)"]
        HOST[host_dispatch]
        CSRF[csrf]
        CORS[cors]
        BODY[body cap<br/>+ governor]
        SH[security_headers]
    end

    subgraph Routes["routes/* — TrustTaskRouter handlers"]
        AUTH[auth]
        ACL[acl + admin/passkeys]
        MEMBERS[members]
        JR[join_requests]
        POL[policies]
        CRED[credentials<br/>endorsements]
        REL[relationships]
        REG[recognise + registry]
        SL[status_lists]
        WEBR[website mgmt]
        ADMINR[admin_ui]
    end

    subgraph Ops["Operations layer"]
        POLICY[policy engine<br/>regorus]
        MEM[member state]
        ISSUE[credential issuance<br/>VMC · VEC · VRC]
        STATUS[BitstringStatusList]
        SYNC[MembershipSyncer]
        WEBSVC[website serve<br/>+ bundle deploy]
    end

    subgraph Storage["fjall keyspaces"]
        KS[(sessions · acl · members<br/>policies · credentials<br/>status_lists · registry<br/>relationships · endorsements<br/>audit)]
    end

    REST --> HOST --> CSRF --> CORS --> BODY --> Routes
    DC --> Routes
    ADMIN --> SH --> Routes
    WEB --> SH --> WEBSVC
    HEALTH -.exempt.-> Routes

    Routes --> Ops
    Ops --> Storage
```

## Crate dependencies

The VTC is the leaf crate in the workspace — nothing depends on it.

```mermaid
graph LR
    vti-common --> vtc-service
    vta-sdk --> vtc-service
```

`vti-common` provides JWT auth, the `Store`/`KeyspaceHandle` enum,
audit envelopes, error types, config types, and the
`TrustTaskRouter` glue. `vta-sdk` provides the
`provision-integration` client (used at setup), VC/VP helpers,
sealed-transfer, and protocol types shared with the VTA.

## Module layout

| Module | Purpose |
|---|---|
| `acl/` | Role enum + per-DID ACL entries + storage. The VTC extends the shared `vti_common::acl::Role` with VTC-specific roles (Moderator, Issuer, Member, custom). |
| `admin_ui/` | `include_dir!`-baked admin SPA (HTML/CSS/JS at `vtc-service/admin-ui/`). |
| `auth/` | Session machinery + JWT keys + cookie + bearer extractors (`AuthClaims`, `ManageAuth`, `AdminAuth`). |
| `community/` | Profile CRUD + community-level config. |
| `config.rs` | All `AppConfig` types (server, routing, auth, registry, renewal, website, admin_ui, …). |
| `credentials/` | VMC / VEC / VRC / custom endorsement builders + `LocalSigner` (cached signer wrapping the VTA-minted key). |
| `did_key.rs` | `did:key` helpers (multibase + multicodec). |
| `endorsement_types/` | Operator-uploaded endorsement type registry. |
| `endorsements/` | Custom endorsement issuance + revocation + storage. |
| `install/` | Install token signer + state machine (one-shot WebAuthn ceremony). |
| `join/` | Join request lifecycle + retention. |
| `keys/` | Secret-store integration (keyring / AWS / GCP / Azure / inline / plaintext). |
| `members/` | Member row + relationships + personhood lifecycle + DID rotation. |
| `messaging.rs` | DIDComm thread + ATM wiring. |
| `policy/` | `regorus`-backed engine, policy-id storage, default policies, evaluation helpers. |
| `recognition/` | Foreign-credential verifier (status list + registry membership) for cross-community session minting. |
| `registry/` | Trust-registry client + `RegistryHealth` + `MembershipSyncer` + RTBF batching. |
| `relationships/` | VRC primary keyspace + per-DID secondary index. |
| `routes/` | All axum handlers; one file per resource. `routes/mod.rs` wires the `TrustTaskRouter`. |
| `routing/` | Phase 5 middleware: `host_dispatch`, `csrf`, `security_headers`. |
| `server.rs` | `AppState` + binary entry point + three OS threads (REST / DIDComm / storage). |
| `setup/` | `vtc setup` wizard + the sealed-bundle opener. |
| `status_list/` | BitstringStatusList minting + slot allocator + storage. |
| `webauthn.rs` | RP-ID + algorithm restriction + ceremony helpers. |
| `website/` | Public website surface — filesystem serve handler, bundle deploy, FD cache, path safety, default in-tree landing page. |

## AppState + fjall keyspaces

Every keyspace handle on `AppState` is opened once at boot and
cloned cheaply into handlers. The complete list:

| Keyspace | Purpose |
|---|---|
| `sessions` | Auth sessions + refresh-token reverse index |
| `acl` | Per-DID `VtcAclEntry` rows |
| `community` | Community profile singleton |
| `config` | Operator-mutable config overrides |
| `passkey` | WebAuthn enrolment state |
| `install` | Install token claim ceremony state |
| `members` | Member roster + personhood flag |
| `join_requests` | Pending + decided join requests |
| `policies` | Uploaded Rego policy revisions |
| `active_policies` | Per-purpose pointer to the active revision |
| `status_lists` | BitstringStatusList state per purpose |
| `registry_records` | Local mirror of published trust-registry rows |
| `sync_queue` | `MembershipSyncer` queue |
| `sync_cursor` | Audit-tail boot-replay cursor |
| `relationships` | VRC primary rows |
| `relationships_by_did` | VRC secondary index (`<did>:<vrc-id>`) |
| `endorsement_types` | Operator-uploaded type registry |
| `endorsements` | Issued custom endorsements |
| `audit` | HMAC-actor-hashing audit envelopes |
| `audit_key` | HMAC audit key + rotation history |

### Audit tamper-evidence

Every audit envelope from schema version 2 carries `prevHash` (its
predecessor's `entryHash`) and `entryHash` (a SHA-256 over its own
immutable content), so the log is a hash chain.

Verify it with either:

```bash
cnm audit verify              # exits non-zero on a break
curl -H "Authorization: Bearer $TOKEN" \
     -H "Trust-Task: https://trusttasks.org/openvtc/vtc/audit/verify/1.0" \
     "$VTC_URL/v1/audit/verify"
```

Both report `entriesExamined`, `entriesVerified`, `legacySkipped`,
`unparseableSkipped`, the chain `head`, and — when the chain is
broken — where.

**Read the skip counters.** Pre-v2 (`legacySkipped`) and
undeserializable (`unparseableSkipped`) rows are *not* checked; they
are stepped over. On a store written entirely by a current daemon both
should be zero, and a non-zero count is itself the finding rather than
a footnote to a passing result.

**What a pass proves.** Internal consistency — no reorder, drop,
duplicate, or content edit. It is **not** an authenticity proof: the
chain is unsigned (`chain_digest` takes no key), so an adversary with
write access to the `audit` keyspace can restamp a forged suffix, and
truncating the log to a valid prefix is undetectable. Closing that
needs signed checkpoints — see
[`vtc-audit-checkpoints.md`](../05-design-notes/vtc-audit-checkpoints.md).
Until then, treat `cnm audit verify` as detecting accident and
careless tampering, and verify an out-of-band copy when the answer
actually matters.

## Three-thread runtime

`vtc-service` runs three named OS threads, mirroring the VTA's
layout:

```mermaid
graph LR
    subgraph Process["vtc process"]
        REST_T[vtc-rest<br/>axum + tokio]
        DC_T[vtc-didcomm<br/>ATM + tokio]
        STORE_T[vtc-storage<br/>session sweeper + persist]
    end
    SHUTDOWN[shutdown_tx<br/>watch::Sender bool]
    SHUTDOWN -. broadcast .-> REST_T
    SHUTDOWN -. broadcast .-> DC_T
    SHUTDOWN -. broadcast .-> STORE_T
```

- **vtc-rest** serves HTTP on `0.0.0.0:8200`.
- **vtc-didcomm** runs the DIDComm mediator subscription + handler
  dispatch.
- **vtc-storage** runs the session sweeper and flushes fjall on
  shutdown.

A `tokio::sync::watch` channel coordinates graceful shutdown:
SIGINT/SIGTERM, REST-thread panic, or
`POST /v1/admin/config/restart` all flip the channel and every
thread drains.

## Relationship to the VTA

The VTC is **not** standalone — it's provisioned by a VTA at setup
and continues to depend on the VTA for key custody decisions like
rotation. The runtime relationship:

```mermaid
graph TB
    subgraph VTA["VTA (independent process)"]
        VTA_KEYS[Master seed + BIP-32]
        VTA_CTX[vtc-host context]
    end

    subgraph VTC["VTC (independent process)"]
        VTC_BUNDLE["VtcKeyBundle<br/>(cached at setup)"]
        VTC_SIGNER["LocalSigner<br/>(in-memory)"]
        VTC_CREDS[VMC / VEC / VRC issuance]
        VTC_BUNDLE --> VTC_SIGNER
        VTC_SIGNER --> VTC_CREDS
    end

    VTA -- "vtc setup" --> VTC_BUNDLE
    VTC -. "key rotation requests<br/>(optional, post-MVP)" .-> VTA

    classDef vta fill:#d4e6f9,stroke:#3a6fb0,color:#08305f
    classDef vtc fill:#e9d7f7,stroke:#7e3fa6,color:#3a0a5a
    class VTA,VTA_KEYS,VTA_CTX vta
    class VTC,VTC_BUNDLE,VTC_SIGNER,VTC_CREDS vtc
```

The `VtcKeyBundle` is sealed at the VTA and opened once at setup;
afterwards it lives in the configured secrets backend (OS keyring
by default). Every credential the VTC issues is signed in-process
with the cached signer.

## See also

- [VTC spec](../05-design-notes/vtc-mvp.md) — full §1–§19 design
  rationale.
- [Community lifecycle](community-lifecycle.md) — what the
  members/policies/credentials surfaces actually do.
- [VTA architecture](../01-concepts/architecture.md) — the shared
  workspace shape.
