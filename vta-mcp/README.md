# vta-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes
a Verifiable Trust Agent's capabilities as MCP tools, so any MCP-speaking agent
host (Claude Code, Claude Desktop, an IDE, an agent framework) can use a VTA —
signing oracle, secrets vault, device check-in, the whole management surface —
with **no custom integration code**.

Transport is **stdio**: the host spawns the binary and speaks JSON-RPC over
stdin/stdout, so all logging goes to stderr.

> **Full documentation: [`docs/02-vta/vta-mcp.md`](../docs/02-vta/vta-mcp.md)** —
> the security model, every flag, the observability story, troubleshooting.
> Worked example running it alongside `vta-agent-memory`:
> [`docs/02-vta/examples/agent-memory-with-vta-mcp.md`](../docs/02-vta/examples/agent-memory-with-vta-mcp.md).

## Quick start

Run it as a **dedicated, context-scoped agent** — not as your operator login:

```bash
pnm contexts create --id my-mcp-agent --name "MCP bridge"
pnm acl create --did <agent did:key> --role application \
  --contexts my-mcp-agent --label vta-mcp --expires 30d

VTA_MCP_AGENT_KEY=<multibase> vta-mcp \
  --agent-did did:key:z6Mk… \
  --vta-did did:webvh:example.com:vta \
  --mediator-did did:key:z6Mk… \
  --enroll --confirm sensitive
```

In a host config:

```json
{
  "mcpServers": {
    "vta": {
      "command": "vta-mcp",
      "args": ["--vta", "my-vta", "--read-only"]
    }
  }
}
```

## Tools

The **full** VTA management surface is reachable through two generic tools, plus
convenience tools for the common operations and the client-side bits.

| Tool | What it does | Risk class |
|---|---|---|
| `vta_list_operations` | Every Trust Task URI `vta_call` can reach, with its risk class and this bridge's policy decision | read-only |
| `vta_call` | Invoke any operation by URI with a JSON payload | per operation |
| `vta_status` | Identity, transports, policy, call counters, recent calls | read-only |
| `vta_supported_tasks` | Which Trust Tasks the VTA actually serves (glob-filterable) | read-only |
| `list_keys` | The VTA's signing keys | read-only |
| `sign` | Sign UTF-8 text with a VTA-held key (private key never leaves the VTA) | sensitive |
| `vault_list` / `vault_get` | Vault entry metadata — no secret material | read-only |
| `vault_release` | Release a secret sealed to this client; returns cleartext | sensitive |
| `device_heartbeat` | Check in; returns queued operations | mutating |
| `resolve_did` | Resolve any DID via the resolver cache | read-only |
| `issue_vp` | Build a holder-bound OID4VP `vp_token`, signed locally | sensitive |

Plus three read-only resources: `vta://status`, `vta://operations`,
`vta://calls/recent`.

## Security

All access is bounded by the bridge identity's VTA **role / ACL** — scope that
role to what the agent should be allowed to do. On top of that the bridge
applies its own local policy, because **an MCP host approves a tool, not a
call**: once `vta_call` is approved, every operation rides that one approval.

| Flag | Effect |
|---|---|
| `--read-only` | Refuse anything not read-only, whatever the ACL permits |
| `--allow <glob>` | Permit only these slug globs (`vta/memory/*`, `acl/list`) |
| `--deny <glob>` | Always refuse these; checked before `--allow` |
| `--confirm <level>` | Ask a human via MCP elicitation: `never`, `destructive` (default), `sensitive`, `always` |

The convenience tools are gated under the URI they actually send, so
`--read-only` cannot be walked around by calling `sign` instead of `vta_call`.
If the host cannot show a confirmation prompt, the call is **refused**, not
waved through.

`--enroll` registers the bridge as an `ai-agent` device so `pnm device disable` /
`pnm device wipe` revoke it (enforced at authentication). It is refused in
session mode, where the binding would attach to the operator's ACL entry.

`vault_release` returns cleartext into the model's context; `issue_vp` signs with
a holder key held in this process. Both are deliberate, and both are the two
places where "secrets never leave the VTA" stops being true.

## Seeing what it does

- **stderr** — on by default at `info`; one line at call start, one at finish
  with outcome and duration. `--log-level`, `--log-format json`; `RUST_LOG` wins
  when set.
- **`--audit-log <path>`** — one redacted JSON object per line, appended, 0600.
- **`vta_status` / `vta://calls/recent`** — the last 100 calls, kept in memory
  whether or not an audit log was configured.
- Payloads pass through a redactor whose rule is that **strings are guilty until
  named innocent**, so signing input, mnemonics, private keys and JWEs are elided
  without this crate needing to know those field names.

If the bridge cannot connect it **serves MCP anyway**, in degraded mode: a server
that exits before speaking the protocol shows up in the host as *no tools at
all*, and then nothing can explain why.

## Auth

Four modes, highest precedence first (the ladder is
`vta_sdk::agent_connect::AgentConnect`, shared with every agent-side bridge):

1. **did:webvh bundle** — `--agent-secrets <PATH|JSON>` + `--vta-did` +
   `--mediator-did`.
2. **did:key** — `--agent-did` + `--agent-key` + `--vta-did` + `--mediator-did`.
   Works against DIDComm-only VTAs with no REST endpoint.
3. **Token** — `VTA_URL` + `VTA_TOKEN`. REST, no refresh; testing only.
4. **Session** — `--vta <slug>`, replaying a `pnm`/`cnm` login. **Operator
   authority** — the bridge warns at boot.

The two DIDComm modes are mutually exclusive, and a half-configured rung fails
fast naming the missing field rather than falling through to session mode.

`--vta` takes the slug from `pnm vta list`; `pnm` stores sessions as
`vta:<slug>` and the prefix is added for you.

Every flag has a `VTA_MCP_*` environment equivalent. Prefer the environment for
`--agent-key` / `--holder-key`: command-line arguments are readable by every
process on the machine, and the bridge warns when it sees one.

## Notes

- Build: `cargo build -p vta-mcp` (or `--release`). `publish = false`.
- **Session mode needs the `keyring` feature**, on by default — it is what
  compiles a session backend in. Build `--no-default-features` only for token or
  DIDComm mode.
- MCP surface: tools (fully annotated) + resources + elicitation. The MCP
  `logging` capability is deliberately unused — it is deprecated by SEP-2577.
- See [`docs/02-vta/personal-ai-agents.md`](../docs/02-vta/personal-ai-agents.md)
  for the broader agent-enablement story.
