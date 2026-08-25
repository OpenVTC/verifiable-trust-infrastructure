# Worked example — `vta-agent-memory` and `vta-mcp` side by side

Two MCP servers, one VTA, two identities that cannot reach each other's data.

- **[`vta-agent-memory`](https://github.com/OpenVTC/vta-agent-memory)** gives an
  agent host durable memory — six `memory_*` tools plus a skill that says *when*
  to save and recall, four slash commands, and a `SessionStart` hook that loads
  memories before you type anything. It speaks exactly three Trust Tasks
  (`vta/memory/{put,list,delete}/0.1`).
- **[`vta-mcp`](../vta-mcp.md)** gives the same host the rest of the VTA —
  contexts, keys, ACL, DID management, vault, audit — through one generic
  `vta_call` gateway plus typed convenience tools.

They are separate on purpose, and the reason is the point of this guide.

---

## 1. Why two servers rather than one

`vta-mcp` can technically do memory: `vta_call` reaches
`vta/memory/put/0.1` like it reaches everything else. Running
`vta-agent-memory` anyway buys three things `vta_call` structurally cannot:

- **Retrieval.** `memory/list/0.1` returns *every entry in the context* — no
  prefix, no cursor, no search. Making that useful means structured keys,
  one-line descriptions, and ranking that returns summaries rather than bodies.
  That work lives on the client side, in `vta-agent-memory`. A raw `vta_call`
  would paste every body into the context window.
- **Policy about memory.** The `agent-memory` skill — what is worth saving, what
  must never go in — is most of the value. Tools are the easy part.
- **A different blast radius.** This is the real reason. Read on.

The inverse also holds: `vta-agent-memory` deliberately cannot do anything but
memory, so it is not a way to manage your VTA.

## 2. The identity model

Each server gets **its own `did:key`, in its own trust context**, with role
`application`. The trust context is the isolation boundary the VTA enforces —
`vta/memory/*` is gated on `require_context(contextId)`, the same check the
context-scoped key tasks use — so a memory agent scoped to `agent-memory`
physically cannot read `mcp-bridge` data, and vice versa.

```
                     ┌──────────────────────────────┐
   Claude Code ──────┤ vta-agent-memory             │
   (one host,        │  did:key:zMem…               │──┐
    two servers)     │  context: agent-memory       │  │
                     │  tools: memory_*             │  │   one VTA
                     └──────────────────────────────┘  │   two ACL entries
                     ┌──────────────────────────────┐  │   two contexts
                     ┤ vta-mcp                      │  │
                     │  did:key:zMcp…               │──┘
                     │  context: mcp-bridge         │
                     │  tools: vta_call, sign, …    │
                     └──────────────────────────────┘
```

What this buys you, concretely: revoking the memory agent is one
`pnm acl delete <did>` that does not touch the bridge, and a prompt-injection
that persuades the model to call `vta_call` cannot reach a single memory.

Do **not** give both servers the same identity, and do not give either one your
`pnm` operator login. `vta-mcp` warns at every boot when you do
([why](../vta-mcp.md#24-run-it-as-a-dedicated-agent-not-as-yourself)).

---

## 3. Set it up

### Prerequisites

- A running VTA whose DID you know, and which advertises a DIDComm mediator.
- Somebody who can run `pnm contexts create` and `pnm acl create` — **not
  necessarily on this machine**. Both tools are built so the grant can be made
  anywhere: another laptop, CI, a colleague reading it off a ticket.
- Rust 1.95+ to build both.

Identify the VTA by **DID**, never by its `pnm` slug. A slug is a nickname
chosen on one machine and means nothing on any other.

### 3.1 The memory server

`vta-agent-memory` has a two-phase flow so that the machine holding your
memories never needs an operator credential:

```bash
git clone https://github.com/OpenVTC/vta-agent-memory
cd vta-agent-memory && scripts/install.sh

bin/vta-agent-memory init \
  --vta-did did:webvh:abc:vta.example.com:mine \
  --context agent-memory
```

It mints a throwaway `did:key`, parks it in the OS keyring, and prints the grant
to run wherever you hold admin:

```bash
pnm contexts create --id agent-memory --name "Agent memory"
pnm acl create --did did:key:zTemp… --role application \
  --contexts agent-memory --label vta-agent-memory
```

Then, back on the agent machine:

```bash
bin/vta-agent-memory connect
```

`connect` rotates: on first successful authentication it swaps the throwaway key
for a fresh one, mirrors the ACL entry onto the new DID, and drops the temp
entry — so the DID that travelled through a ticket stops being an authenticator
once it has done its job. It then proves the rotated identity can actually read
the context before writing any config.

```bash
bin/vta-agent-memory doctor      # config, vta, context, identity, transport, count
```

### 3.2 The bridge

`vta-mcp` has no `init` of its own — mint its key with whatever you already use
for scoped agents (`pnm setup`-style ephemeral keys, a `did:webvh` bundle from
`vta create-did-webvh --export-secrets`, or the `ai-agent` DID template from
[personal AI agents](../personal-ai-agents.md#step-2--agent-identity-via-the-ai-agent-template-operator-per-agent)).
Whichever route, the ACL grant looks the same:

```bash
pnm contexts create --id mcp-bridge --name "MCP bridge"
pnm acl create --did did:key:zMcp… --role application \
  --contexts mcp-bridge --label vta-mcp --expires 30d
```

Build it and check it starts:

```bash
cargo build --release -p vta-mcp     # in the VTI workspace
```

### 3.3 Wire both into the host

Claude Code reads `.mcp.json` in the project (or `~/.claude.json` for user
scope); Claude Desktop uses `claude_desktop_config.json`. The shape is the same:

```json
{
  "mcpServers": {
    "vta-memory": {
      "command": "/Users/me/.cargo/bin/vta-agent-memory",
      "args": ["serve"]
    },
    "vta": {
      "command": "/Users/me/devel/verifiable-trust-infrastructure/target/release/vta-mcp",
      "args": [
        "--agent-did", "did:key:zMcp…",
        "--vta-did", "did:webvh:abc:vta.example.com:mine",
        "--mediator-did", "did:web:mediator.example.com",
        "--enroll",
        "--confirm", "sensitive",
        "--deny", "vta/seeds/*,vta/backup/*",
        "--audit-log", "/Users/me/.local/state/vta-mcp/audit.jsonl"
      ],
      "env": { "VTA_MCP_AGENT_KEY": "z3u2…" }
    }
  }
}
```

Notes on the `vta` block, each of which is doing something:

- `--enroll` puts the bridge in `pnm device list`, so
  `pnm device disable <id>` is a kill switch the VTA enforces at
  authentication.
- `--confirm sensitive` asks you before anything that signs, releases a secret,
  or moves authority — restoring per-call consent that the host's one-time
  "always allow **vta_call**" would otherwise give away.
- `--deny` keeps the master seed and full-state backups unreachable through this
  bridge regardless of what its ACL would permit.
- `--audit-log` is the only record that outlives the process.
- The key is in `env`, not `args`: command-line arguments are readable by every
  process on the machine.

If a plugin already provides `vta-agent-memory` (it ships one, with the hook and
slash commands), install it that way instead of hand-writing the first block:

```bash
claude plugin marketplace add OpenVTC/vta-agent-memory
claude plugin install vta-agent-memory@vta-agent-memory
```

---

## 4. Check it works

Restart the host, then ask for each in turn.

**The bridge, first — because it can tell you about itself:**

> Call `vta_status`.

```json
{
  "connected": true,
  "identity": { "mode": "did:key-didcomm", "agentDid": "did:key:zMcp…",
                "dedicatedAgent": true },
  "transports": { "trustTasks": "DIDComm", "protocolMessages": "DIDComm" },
  "policy": { "summary": "confirm=sensitive deny=[vta/seeds/*,vta/backup/*]" },
  "calls": { "ok": 1, "errors": 0, "denied": 0, "declined": 0 }
}
```

`"dedicatedAgent": true` is the line to look for. If it is `false`, the bridge
is running as you.

**Then the memory server:**

> Remember that this project pins its MCP servers in `.mcp.json`, not user scope.

…then in a fresh session:

> What do you know about this project's MCP setup?

**Then prove the isolation.** Ask the bridge to read the memory context:

> Call `vta_call` with operation
> `https://trusttasks.org/spec/vta/memory/list/0.1` and payload
> `{"contextId": "agent-memory"}`.

The VTA refuses it — the bridge's ACL entry names `mcp-bridge`, not
`agent-memory`. That refusal is the design working, and it comes from the VTA,
not from the bridge's local policy.

---

## 5. If you would rather run one server

You can serve memory through `vta-mcp` alone, at the cost of the retrieval and
policy layers in §1. Give the bridge the memory context and lock it to that
family:

```bash
vta-mcp --agent-did did:key:zMem… \
  --vta-did did:webvh:… --mediator-did did:web:… \
  --allow 'vta/memory/*' --confirm never
```

`--allow` makes everything outside `vta/memory/*` refused locally, so a
mis-scoped ACL entry does not become a mis-scoped bridge. This is a reasonable
setup for a machine that should only ever hold memory — but the model now has to
do its own ranking against a full context dump, and nothing tells it what is
worth remembering.

---

## 6. Revoking

| What | Command | Effect |
|---|---|---|
| The memory agent | `pnm acl delete did:key:zMem…` | Memory tools stop working at the next call; memories stay on the VTA |
| The bridge | `pnm acl delete did:key:zMcp…` | Every `vta-mcp` tool stops working |
| The bridge, temporarily | `pnm device disable <device-id>` | Enforced at authentication (`--enroll` is what puts it in `pnm device list`) |
| A stolen machine | `pnm device wipe <device-id> --reason "stolen" --scope full` | Records the reason and marks the binding wiped |

Neither revocation touches the other identity. That is the whole reason they are
two identities.

---

## 7. Auditing what happened

Three places, in increasing durability:

```bash
# 1. What the bridge did, from inside the session
#    → ask the model to call vta_status, or read `vta://calls/recent`

# 2. What the bridge did, on this machine, after the fact
jq -r 'select(.outcome != "ok") | [.ts, .tool, .operation, .outcome] | @tsv' \
  ~/.local/state/vta-mcp/audit.jsonl

# 3. What the VTA saw — the authoritative record, per identity
pnm audit list --actor did:key:zMcp…
pnm audit list --actor did:key:zMem…
```

The third is the one that matters in an incident: the bridge's own log is on the
machine you are trying to make claims about. The VTA's audit rows carry the
agent's DID as the actor, which is exactly why each server has its own.
