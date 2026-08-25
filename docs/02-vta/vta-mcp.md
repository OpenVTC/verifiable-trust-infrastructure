# vta-mcp — using a VTA from an MCP host

`vta-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server
that exposes a Verifiable Trust Agent as MCP tools, so any MCP-speaking host —
Claude Code, Claude Desktop, an IDE, an agent framework — can drive a VTA with
no custom integration code.

It is a **bridge, not an authority**. Every tool call becomes a Trust Task on an
authenticated `VtaClient`, and the VTA decides what actually happens. This
document is mostly about the consequences of that sentence.

- Crate: `vta-mcp/` (`publish = false`; build it yourself)
- Transport: **stdio** — the host spawns the binary and speaks JSON-RPC over
  stdin/stdout
- Related: [personal AI agents](personal-ai-agents.md) (how to provision the
  identity this bridge should run as), [approvals](approvals.md) (server-side
  gating), [example: agent memory + vta-mcp](examples/agent-memory-with-vta-mcp.md)

---

## 1. What it exposes

Two generic tools cover the entire VTA management surface, and the rest are
conveniences with typed schemas:

| Tool | What it does | Risk class |
|---|---|---|
| `vta_list_operations` | The catalog of every Trust Task URI `vta_call` can reach, each with its risk class **and this bridge's policy decision** | read-only |
| `vta_call` | Invoke any operation by URI with a JSON payload | *per operation* |
| `vta_status` | What this bridge is: identity, transports, policy, counters, recent calls | read-only |
| `vta_supported_tasks` | Which Trust Tasks the connected VTA actually serves (glob-filterable) | read-only |
| `list_keys` | The VTA's signing keys | read-only |
| `sign` | Sign UTF-8 text with a VTA-held key (the private key never leaves the VTA) | sensitive |
| `vault_list` / `vault_get` | Secrets-vault entry metadata — no secret material | read-only |
| `vault_release` | Release a secret sealed to this client and **return the cleartext** | sensitive |
| `device_heartbeat` | Check in; returns queued operations | mutating |
| `resolve_did` | Resolve any DID via the shared resolver cache | read-only |
| `issue_vp` | Build a holder-bound OID4VP `vp_token`, signed locally | sensitive |

Three read-only **resources** are published alongside them, so a host can read
the bridge's own state without spending a tool call:

| Resource | Contents |
|---|---|
| `vta://status` | The same document `vta_status` returns |
| `vta://operations` | The annotated operation catalog |
| `vta://calls/recent` | The last 100 calls this bridge served, redacted |

Every tool carries MCP **tool annotations** (`readOnlyHint`, `destructiveHint`,
`idempotentHint`, `openWorldHint`). Hosts render these, and some gate on them. A
test asserts each annotation agrees with the risk class of the operation the
tool actually calls, so they cannot quietly drift apart.

---

## 2. The security model

### 2.1 Four layers, and which one is load-bearing

1. **Process spawn is the authentication boundary.** stdio means no listener, no
   port, and no authentication *on the MCP channel itself*. Whoever can spawn
   the process — or read the host's MCP config — inherits the full authority of
   the configured identity.
2. **The connect ladder decides whose authority that is.** Four rungs (§4).
   The important distinction is *dedicated agent identity* versus *replayed
   operator login*.
3. **The VTA is the policy decision point.** Role, ACL, context scope, the
   `signable_keys` policy on each context, and — where
   `policy.enforcement = true` — the [approvals / DTTE](approvals.md) gate. None
   of that is reimplemented here.
4. **The bridge's own local policy** (§3) refuses or confirms individual
   operations before they are sent.

Layer 3 is the real one. Layers 1, 2 and 4 exist to keep layer 3's decisions
meaningful.

### 2.2 The gap layer 4 closes

**An MCP host approves a tool, not a call.** The moment an operator answers
"always allow" to `vta_call`, `contexts/delete/1.0` rides the same approval as
`contexts/list/1.0` — the host sees one tool name and cannot tell them apart.

So `vta-mcp` classifies each Trust Task URI itself and decides per call:

| Class | Meaning | Examples |
|---|---|---|
| `read-only` | Reads state | `acl/list`, `vta/contexts/get`, `vta/contexts/preview-delete` |
| `mutating` | Additive and reversible | `vta/contexts/create`, `device/register`, `vta/memory/put` |
| `sensitive` | Exercises key authority, emits secret material, or moves authority | `keys/sign`, `vault/release`, `acl/grant`, `vta/seeds/export-mnemonic` |
| `destructive` | Removes state or access | `vta/contexts/delete`, `acl/revoke`, `device/wipe`, `vta/seeds/rotate` |

A URI whose verb this build has never seen classifies as `mutating` — never
read-only. The catalog grows outside this crate; a `--read-only` bridge must not
pass through something it does not recognise. A census test fails the build when
a new verb appears, so "unknown" cannot become the common case.

The convenience tools are gated under the **URI they actually send**, so
`--read-only` cannot be walked around by calling `sign` instead of `vta_call`.
`issue_vp` is gated as `keys/sign` even though it never reaches the VTA — a
read-only bridge must not be a signing oracle by another name.

### 2.3 What the bridge does not protect you from

Stated plainly, because the mitigations are operational, not technical:

- **`vta_call` is a full gateway.** There is no built-in allowlist beyond what
  you configure. Point it at a `pnm` admin session and the model on the other
  end of the pipe holds admin. The mitigation is §2.4, not a flag.
- **Two paths move secret material out of the VTA.** `vault_release` returns
  cleartext as tool output — it enters the model's context and the host's
  transcript. `issue_vp` signs with `VTA_MCP_HOLDER_KEY`, a raw Ed25519 key held
  in process memory, outside the signing oracle entirely.
- **Least privilege is coarse.** Capabilities derive from the ACL **role** or
  are set at `device/register`; per-entry capability overrides are still a
  deferred gap. Pick the role whose derived set is closest to what you want.
- **A compromised host with a legitimate credential is a legitimate caller.**
  No authorization model fixes that; only splitting identities per process does.
  See `docs/05-design-notes/multi-tenant-signing.md` §Finding 2.

### 2.4 Run it as a dedicated agent, not as yourself

This is the single most important setting, and it is not a flag — it is which
identity you start the process with.

```bash
# 1. One context per agent. This is the isolation boundary.
pnm contexts create --id my-mcp-agent --name "MCP bridge"

# 2. Least privilege: role `application`, scoped to exactly one context.
#    NOT admin — for `admin` an empty allowed-contexts list means *unrestricted*;
#    for every other role it means authorized nowhere.
pnm acl create --did <agent did:key> --role application \
  --contexts my-mcp-agent --label vta-mcp --expires 30d

# 3. Run the bridge as that identity, over DIDComm.
VTA_MCP_AGENT_KEY=<multibase> vta-mcp \
  --agent-did did:key:z6Mk… \
  --vta-did did:webvh:example.com:vta \
  --mediator-did did:key:z6Mk… \
  --enroll
```

If the bridge needs the signing oracle at all, narrow it at the ACL rather than
here: `pnm acl create … --allowed-keys key-1,key-2` restricts which key ids that
DID may name in `keys/sign`. It intersects with `--contexts` — it can only
narrow, never widen — and unlike `--read-only` it is enforced by the VTA, so it
survives someone restarting the bridge with different flags.

`--enroll` registers the bridge as an `ai-agent` device, so it shows up in
`pnm device list` and `pnm device disable` / `pnm device wipe` revoke it — the
VTA enforces that at authentication, not just in the listing. **`--enroll` is
refused in session mode**, because the binding would attach to the *operator's*
ACL entry rather than the agent's.

Session mode still works and is convenient, but the bridge logs a warning at
every boot when it holds an operator credential rather than a scoped agent
identity. That warning is the whole of §2.3's first bullet, said out loud.

### 2.5 Key material on the command line

`--agent-key`, `--holder-key` and an inline `--agent-secrets` JSON blob are all
readable by any process on the machine via `ps` / `/proc/<pid>/cmdline`. The
flags stay supported, and the bridge warns when it sees one. Prefer the matching
`VTA_MCP_*` environment variable, or a **file path** for `--agent-secrets`.

---

## 3. Hardening flags

| Flag | Env | Effect |
|---|---|---|
| `--read-only` | `VTA_MCP_READ_ONLY` | Refuse anything not `read-only`, whatever the ACL permits |
| `--allow <glob>` | `VTA_MCP_ALLOW` | Permit only these slug globs. Repeatable; comma-separated in the env var. When set, everything else is refused |
| `--deny <glob>` | `VTA_MCP_DENY` | Always refuse these. Checked **before** `--allow`, so a deny cannot be undone by an allow |
| `--confirm <level>` | `VTA_MCP_CONFIRM` | Which classes need a human: `never`, `destructive` (default), `sensitive`, `always` |

Globs are deliberately minimal — `*`, a family (`acl/*`), or an exact slug.
Patterns match the **slug**, the part after `https://trusttasks.org/spec/`, so
you write `vta/memory/*`, not the full URI.

### Confirmation

`--confirm` puts the risky tail back in front of a person using **MCP
elicitation**: the host shows a yes/no prompt naming the operation and its risk
class, and the call proceeds only on an explicit yes.

Two behaviours worth knowing:

- **Read-only calls are never confirmed**, even at `--confirm always`. A bridge
  that prompts before every `list` gets its prompts clicked through unread.
- **If the host cannot ask, the call is refused**, not waved through — a
  confirmation gate that fails open is not a gate. Hosts that do not implement
  elicitation get an error naming `--confirm never` and `--allow` as the fixes.

The default is `destructive`, not `sensitive`, on the reasoning that the host
already prompts once per tool: the local gate earns its keep exactly where a
tool-level approval is too coarse to mean anything. Raise it to `sensitive` for
any bridge holding an operator session.

### Recipes

```bash
# Read-only inspection — the safest thing you can hand a model.
vta-mcp --vta my-vta --read-only

# A memory-only agent: three operations, nothing else reachable.
vta-mcp --agent-did … --allow 'vta/memory/*' --confirm never

# An operator session, hardened: keep the seed and backups off-limits entirely,
# and ask before anything that signs or moves authority.
vta-mcp --vta my-vta \
  --deny 'vta/seeds/*,vta/backup/*,acl/*' \
  --confirm sensitive
```

Invalid policy values are **fatal at startup** — a typo in `--confirm` must not
degrade to a permissive default. Connectivity failures are not fatal; see §5.

---

## 4. Authentication modes

The ladder lives in `vta_sdk::agent_connect::AgentConnect`, shared with every
other agent-side bridge. Highest precedence first:

| # | Mode | Flags | Notes |
|---|---|---|---|
| 1 | did:webvh bundle | `--agent-secrets <PATH\|JSON>` + `--vta-did` + `--mediator-did` | A `DidSecretsBundle`; `#key-0` signs, `#key-1` decrypts. Dedicated agent |
| 2 | did:key | `--agent-did` + `--agent-key` + `--vta-did` + `--mediator-did` | Scoped agent over DIDComm. Works against DIDComm-only VTAs with no REST endpoint. Dedicated agent |
| 3 | Token | `VTA_URL` + `VTA_TOKEN` | REST bearer token. No refresh; testing and short-lived use |
| 4 | Session | `--vta <slug>` | Replays an existing `pnm`/`cnm` login, auto-refreshing. **Operator authority** |

Two rules the ladder enforces rather than documents:

- The two DIDComm identity modes are **mutually exclusive** — passing both is an
  error, not a silent precedence win.
- A **half-configured** rung fails fast naming the missing field, never falling
  through to session mode. That fall-through is how a misconfigured bridge ends
  up authenticated as the operator instead of as the scoped agent it was meant
  to be.

> **Session slugs.** `pnm` stores sessions under the keyring key `vta:<slug>`;
> passing the bare slug used to find no session at all and report *"not
> authenticated"* to somebody who is. `--vta` adds the prefix for you, and an
> already-prefixed value still works.

Session mode needs the `keyring` feature, which is on by default. Building
`--no-default-features` is only for token or DIDComm mode.

---

## 5. Seeing what it is doing

The original complaint this section answers: an MCP server is a subprocess with
its stdout wired to the protocol, so by default you cannot see anything it does.

### stderr — the runtime log

**On by default at `info`.** (It previously used `EnvFilter::from_default_env()`
with no fallback, so an operator who had not set `RUST_LOG` got silence: no
startup line, no call log, no error.) Every call logs twice:

```
INFO vta_mcp::server: call start seq=3 tool="vta_call"
  operation="…/vta/contexts/delete/1.0" risk="destructive" decision="deny"
  args={"operation":"…","payload":{"id":"x"}}
WARN vta_mcp::server: call failed seq=3 … outcome="denied" duration_ms=0
  error="'vta/contexts/delete' is destructive and this bridge runs with --read-only…"
```

- `--log-level <level>` / `VTA_MCP_LOG_LEVEL` — `RUST_LOG` still wins when set.
- `--log-format json` — one JSON object per line, for a log pipeline.

In Claude Code, this lands in the MCP server logs (`/mcp` shows server state;
the logs are under `~/.cache/claude-cli-nodejs/<project>/mcp-logs-*`). Claude
Desktop writes them under its own logs directory.

### `--audit-log <path>` — the durable record

One redacted JSON object per line, appended, created **owner-only (0600)**:

```json
{"ts":"2026-08-25T03:30:20.963Z","seq":3,"tool":"vta_call",
 "operation":"https://trusttasks.org/spec/vta/contexts/delete/1.0",
 "risk":"destructive","decision":"confirm","outcome":"denied","durationMs":0,
 "args":{"operation":"…","payload":{"id":"x"}},"error":"…"}
```

`outcome` is one of `ok`, `error`, `denied` (local policy refused) or `declined`
(a human said no). The records name operations, DIDs, context ids and key ids —
not secrets, but a map of what this VTA holds and who touches it, which is worth
0600 on its own.

### `vta_status` and `vta://calls/recent` — from inside the session

The last 100 calls are kept in memory whether or not `--audit-log` was passed,
because by the time you want to know what the bridge has been doing, you will
not have passed it. Ask the model to call `vta_status`, or read the resource.

### Redaction

Both logs pass every payload through the same filter, whose rule is that
**strings are guilty until named innocent**. Numbers and booleans pass; strings
pass only under an allowlisted key name (`id`, `did`, `contextId`, `keyId`,
`role`, `limit`, …). So `text` (what `sign` signs), `mnemonic`, `privateKey`,
`jwe` and every field of a released credential are elided without this crate
needing to know those names exist.

### Degraded mode

If the bridge cannot connect — no credentials configured, a typo'd env var, an
unreachable mediator, an expired session — **it serves MCP anyway**. A server
that exits before speaking the protocol appears in the host as *no tools at
all*: the model cannot even report the problem, and the operator sees an empty
tool list with no explanation. Instead, `vta_status` answers with the failure
and every other tool returns it verbatim:

```
this vta-mcp bridge is not connected to its VTA: no usable VTA credentials:
… supply a session_key (an existing `pnm` login), url + token, or an agent
identity (agent_did + agent_key + vta_did + mediator_did). Fix the connection
and restart the MCP server; `vta_status` reports the configuration it tried.
```

Reconnection is not automatic — fix the configuration and restart the server.

---

## 6. Host configuration

Claude Code (`.mcp.json` in the project, or `claude mcp add`), Claude Desktop
(`claude_desktop_config.json`) and most other hosts take the same shape:

```json
{
  "mcpServers": {
    "vta": {
      "command": "vta-mcp",
      "args": [
        "--agent-did", "did:key:z6Mk…",
        "--vta-did", "did:webvh:example.com:vta",
        "--mediator-did", "did:key:z6Mk…",
        "--confirm", "sensitive",
        "--deny", "vta/seeds/*,vta/backup/*",
        "--audit-log", "/Users/me/.local/state/vta-mcp/audit.jsonl"
      ],
      "env": { "VTA_MCP_AGENT_KEY": "z3u2…" }
    }
  }
}
```

Keep the key in `env`, not `args` (§2.5). Everything configurable by flag has a
`VTA_MCP_*` environment equivalent if you would rather configure it that way.

---

## 7. MCP protocol surface

Built on `rmcp` 3.x, which negotiates up to protocol revision `2026-07-28`.
What is used, and what is deliberately not:

| Capability | Status |
|---|---|
| `tools` | Used, with full annotations |
| `resources` | Used — `vta://status`, `vta://operations`, `vta://calls/recent` |
| elicitation *(client capability)* | Used for `--confirm` |
| `logging` | **Deliberately not used** — deprecated by SEP-2577 and slated for removal. The runtime log goes to stderr, which hosts already capture, and the call record is readable as a resource |
| `completions` | Not used — MCP completions target prompt arguments and resource templates; there is no `ref/tool`, so `vta_call`'s `operation` argument cannot be completed |
| `prompts` | Not used |
| sampling / roots | Not used (also SEP-2577-deprecated) |
| tasks (SEP-2663) | Not used — no operation here is long-running enough to need it |

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| The host lists **no tools** | The server exited before speaking MCP — a bad `--confirm` value, an unopenable `--audit-log`, or a `--enroll` refusal | Read the host's MCP server log; those three are fatal by design |
| Every tool returns "not connected to its VTA" | Degraded mode (§5) | The message names the missing configuration; fix and restart |
| `'…' is not in this bridge's --allow list` | Local policy | Add the slug, or drop `--allow` |
| `this MCP host cannot ask you (it does not support elicitation)` | `--confirm` needs a prompt the host cannot show | `--confirm never`, or `--allow` the specific slug |
| A call fails as a transport timeout | The VTA does not serve that URI | Ask `vta_supported_tasks` first — an unserved URI times out rather than erroring cleanly |
| `vault_release` fails with `UnsupportedTransport` | It opens a `didcomm-authcrypt` envelope with this client's own keys | Use a DIDComm mode (rung 1 or 2), not REST/token |
| `issue_vp is unavailable` | No holder identity | Set `VTA_MCP_HOLDER_DID` + `VTA_MCP_HOLDER_KEY` |
| "Not authenticated" but `pnm auth status` is fine | Session store lookup | Pass the slug as `pnm` knows it; `--vta` handles the `vta:` prefix |

---

## 9. What this is not

- **Not a policy engine.** The VTA holds that. The local guard gates on URI
  shape only; duplicating the VTA's policy here would be a second source of
  truth that drifts.
- **Not a substitute for ACL scoping.** `--read-only` on a bridge holding an
  admin credential is one restart away from not being read-only. Scope the
  identity.
- **Not a place for a long-lived operator credential.** See §2.4.
