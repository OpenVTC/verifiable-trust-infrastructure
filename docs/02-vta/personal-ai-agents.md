# Enabling personal AI agents against a VTA

A concrete runbook for letting personal AI agent runtimes — open-claw,
nano-claw, hermes, and the like — operate against an operator's VTA.

A personal AI agent is **not** a community and **not** a hand-rolled
integration. It maps onto the existing **Trust Tasks consumer model** as a
*Service* consumer with `consumerKind.serviceKind = "ai-agent"` (see
`vta-service/src/trust_tasks/wire_v0_2.rs`, `operations/device.rs`). The agent
gets a VTA-minted DID, is enrolled as a device, granted a least-privilege
capability set, reached over DIDComm through the operator's mediator, and woken
via the push gateway. Sensitive actions it initiates are gated behind operator
passkey step-up.

This doc covers the **VTA-minted-DID** path (the VTA mints and manages the
agent DID via the `ai-agent` template + provision-integration). The lighter
alternative — agent self-generates a `did:key` and enrolls via
`device/register` — skips steps 2–3 but gives up central revocation of the
agent identity.

## Layers of "service"

There are three distinct things to turn on, in order:

1. **Transports** you *enable* on the VTA (`pnm services …`).
2. **Integrations** you *provision* via DID templates (mediator, push gateway,
   the agent itself).
3. **Capabilities / Trust Task slices** you *grant* to the agent
   (least-privilege; set on the agent's `DeviceBinding`).

## Priority order (TL;DR)

1. DIDComm transport + a mediator — the agent's backbone (async, NAT-friendly,
   intrinsic sender auth). Keep REST enabled as the fallback.
2. Agent identity — provision the `ai-agent` template → VTA-minted agent DID +
   ACL entry.
3. Device enrollment + least-privilege capabilities (`SignTrustTask`,
   `VaultRead`, `FillRelease`).
4. Push gateway + `device/set-wake` — so the VTA can wake a sleeping agent.
5. Step-up + WebAuthn — human-in-the-loop guardrail on the agent's high-impact
   actions.
6. Credential exchange / sealed-transfer — only if the agent holds/presents VCs.

---

## Step 1 — Transports (operator, one-time)

The agent speaks Trust Tasks over DIDComm authcrypt: unpacking a message yields
a cryptographically-authenticated sender DID, so there's no bespoke signature
verification. Keep REST enabled as the fallback for a synchronous or REST-only
agent (the brick-prevention invariant requires ≥1 transport regardless).

```bash
pnm services list                       # see current REST / DIDComm / WebAuthn state
pnm services rest enable --url https://vta.example.com          # if not already on
pnm services didcomm enable --mediator-did <mediator-did>       # see Step 1a first
```

### Step 1a — Provision the mediator (if you don't have one)

```bash
# Author/keep the built-in mediator template, then provision it.
pnm bootstrap provision-request  --template didcomm-mediator --var URL=https://mediator.example.com
pnm bootstrap provision-integration --request <request.json> --out mediator-bundle.armor
# The minted mediator DID is what you pass to `services didcomm enable --mediator-did`.
```

## Step 2 — Agent identity via the `ai-agent` template (operator, per agent)

The `ai-agent` built-in template (shipped with the SDK) mints an agent DID whose
document carries a signing key (authentication + assertionMethod), a
key-agreement key (keyAgreement — for authcrypt + sealed-transfer), and a single
`DIDCommMessaging` service routing inbound traffic through the operator's
mediator.

To customize the shape (extra service entry, labels), fork it first:

```bash
pnm did-templates init agent > my-ai-agent.json   # 'agent' aliases 'ai-agent'
# edit my-ai-agent.json, then:
pnm did-templates create --file my-ai-agent.json
```

Provision one agent identity. `MEDIATOR_DID` is the only required variable; pass
`--create-context` to create the agent's isolation context inline if it doesn't
exist:

```bash
pnm bootstrap provision-request \
  --template ai-agent \
  --var MEDIATOR_DID=<mediator-did> \
  --var LABEL=nano-claw-laptop

pnm bootstrap provision-integration \
  --request <request.json> \
  --out nano-claw-bundle.armor \
  --create-context
# The agent runtime opens the sealed bundle to recover its DID + private keys.
```

The bundle is HPKE-sealed to the holder (agent) key, so the relayer running the
command can't read the agent's keys. Verify the out-of-band digest on open.

## Step 3 — ACL role + device enrollment + capabilities (per agent)

The agent DID must be in the ACL before it can register a device — provision
above adds it. Set its role/context scope:

```bash
pnm acl create --did <agent-did> --role member --contexts <ctx-id> --expires 30d
```

**Capabilities are not a `pnm acl` flag.** For a Service consumer they live on
the `DeviceBinding` and are set when the agent runtime calls `device/register`
(`operations/device.rs`). Grant the minimum:

| Capability        | Why an agent needs it                                              |
|-------------------|-------------------------------------------------------------------|
| `SignTrustTask`   | Per-envelope signing via `vault/sign-trust-task/0.1`. Smaller blast radius than `Sign`/`ProxyLogin`. Usually the only signing cap an agent needs. |
| `VaultRead`       | Read the specific secrets/API keys it needs (`vault/get`).        |
| `FillRelease`     | Release a stored secret into a sealed envelope (`vault/release`). |
| `ProxyLogin`      | *Only if* the agent must act **as the user** (mints a session).   |
| `Sign` / `KeyMint`| *Only if* the agent needs the generic signing oracle / to mint keys. |

Avoid `PolicyAdmin` / `DeviceAdmin` for an agent. The capability set an agent
derives from its **role** at provision time is usually sufficient — an
`application`-role consumer derives `VaultRead` + `ProxyLogin` + `FillRelease` +
`Sign` + `SignTrustTask`. Explicit *per-entry* capability overrides are a
deferred Phase-3 item (`CreateAclRequest` carries no `capabilities` field yet),
so pick the role whose derived set matches the least privilege you want.

### Driving device + vault from the CLI

`device/*` and `vault/*` are reachable from `pnm` (both transports — the same
commands work whether the client is on REST or DIDComm), so the operator can
enroll and manage an agent, and an agent runtime built on the SDK can drive the
same surface:

```bash
# Enroll the agent as an ai-agent Service consumer (DID already in ACL):
pnm device register --service-kind ai-agent --display-name "nano-claw" --platform linux
pnm device list --service-kind ai-agent          # see it
pnm device disable <device-id>                   # soft kill: blocks auth, keeps record
pnm device wipe <device-id> --reason "stolen" --scope full   # remote wipe for a compromised agent

# Store / read secrets the agent uses (sealed ops need DIDComm transport):
pnm vault list
pnm vault upsert --entry-file entry.json --secret-file secret.json   # secret sealed before send
pnm vault release <entry-id>                     # opens the sealed reply, prints cleartext
pnm vault sign-trust-task --file envelope.json   # sign as the entry's principal

# What did the agent do? (the agent's DID is the audit actor)
pnm audit --actor <agent-did>
```

`vault upsert` and `vault release` seal/open `didcomm-authcrypt` envelopes with
the caller's own keys, so they require the **DIDComm transport** (a REST-only
client returns a clear `UnsupportedTransport` error).

**Kill switches actually revoke access.** Both `device disable` and `device wipe`
set state that the VTA's auth path enforces — a disabled or wiped device's DID is
rejected at authentication (`check_acl`), not merely hidden from `device list`.
`wipe` additionally records the reason and marks the binding wiped (`--scope`:
`cache`, `cache-and-keys`, or `full`); a wiped device shows in `device list` only
with `--include-wiped --include-disabled`.

## Step 4 — Wake / push (operator + agent)

So the VTA can wake a sleeping personal agent when work or an inbound message
arrives.

```bash
# Operator: provision a push gateway (built-in template).
pnm bootstrap provision-request  --template push-gateway --var URL=https://push.example.com
pnm bootstrap provision-integration --request <request.json> --out push-bundle.armor
```

The agent runtime then calls `device/set-wake/0.2` with its opaque `WakeHandle`;
the VTA provisions the wake allowlist to the gateway over DIDComm
(`operations/device.rs::provision_gateway`).

## Step 5 — Step-up + WebAuthn (operator) — the guardrail

For an autonomous agent this is the safety valve, not polish. Gate the agent's
high-impact actions (large signs, ACL/role changes, context delete) behind a
human passkey approval.

```bash
pnm services webauthn enable --url https://vta.example.com
pnm step-up policy show
pnm step-up policy set --file step-up-policy.json   # auth/step-up/policy/0.2 shape
```

When a gated op is initiated, the agent's request returns a step-up challenge;
the operator approves with a passkey (`auth/passkey-login`), and the op proceeds.

## Step 6 — Credentials (optional)

If the agent must hold or present Verifiable Credentials, the
`credential_exchange` Trust Task slice + `sealed_transfer` are already available.
Lower priority unless your agents do credential work.

---

## What's a build item vs. already there

| Item                                   | Status                          |
|----------------------------------------|---------------------------------|
| `ai-agent` DID template                | **Added** (this change) — built-in |
| DIDComm/REST/WebAuthn transports       | Exists (`pnm services …`)        |
| Mediator / push-gateway templates      | Exists (built-in)               |
| Provision-integration (generic kind)   | Exists — treats `kind` as a free string, no enum to extend |
| Device + vault Trust Tasks             | Exist server-side (`trust_tasks/{device,vault}.rs`) |
| Capability vocabulary                  | Exists (`vti_common::acl::Capability`) |
| `pnm device …` / `pnm vault …` CLI     | **Added** (this change) — `VtaClient::{device_*,vault_*}` + `pnm` commands, both transports |
| Sealed vault upsert/release            | **Added** — `seal_vault_secret` / `open_sealed_secret` on the DIDComm session |
| `pnm acl --capabilities` flag          | **Gap** (deferred Phase 3) — capabilities derive from role / are set at `device/register` |

## References

- DID templates: `docs/02-vta/did-templates.md`, `vta-sdk/templates/ai-agent.json`
- Provision-integration: `docs/02-vta/provision-integration.md`
- Runtime service management: `docs/02-vta/runtime-service-management.md`
- Trust Tasks (device/vault/push): `vta-service/src/trust_tasks/`,
  `vta-sdk/src/trust_tasks.rs`
- Mobile/agent architecture (push topology): `docs/05-design-notes/mobile-agent-architecture.md`
