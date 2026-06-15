# vta-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes
a Verifiable Trust Agent's capabilities as MCP tools, so any MCP-speaking agent
host (Claude Desktop, an agent framework, an IDE) can use a VTA — signing
oracle, secrets vault, device check-in, discovery — with **no custom
integration code**.

It's a thin bridge built on `vta_sdk::agent_session::AgentSession`: each tool
maps one-to-one onto the session's `VtaClient`. Transport is **stdio** (the host
spawns the binary and speaks JSON-RPC over stdin/stdout); all logging goes to
stderr.

## Tools

The **full** VTA management surface is reachable via two generic tools, plus
convenience tools for the most common operations and the client-side bits.

**Generic gateway (covers everything):**

| Tool | What it does |
|---|---|
| `vta_list_operations` | The catalog of every Trust Task operation URI (contexts, keys, acl, did-management, webvh, did-templates, device, vault, seeds, audit, backup, discovery, …) |
| `vta_call` | Invoke any operation by URI with a JSON payload — the gateway to the whole management surface |

**Convenience tools (typed, for common ops):**

| Tool | What it does | Capability required |
|---|---|---|
| `vta_capabilities` | Discover the VTA's features, services, WebVH servers, DID modes | any auth |
| `list_keys` | List the VTA's signing keys | any auth |
| `sign` | Sign UTF-8 text with a VTA-held key (private key never leaves the VTA) | `Sign` |
| `vault_list` | List secrets-vault entry metadata (no secrets) | `VaultRead` |
| `vault_get` | One entry's metadata by id (no secret) | `VaultRead` |
| `vault_release` | Release a secret sealed to this client; returns cleartext | `FillRelease` (DIDComm only) |
| `device_heartbeat` | Check the device in; returns queued operations | any auth |
| `resolve_did` | Resolve any DID to its DID document (via the resolver cache) | any auth |
| `issue_vp` | Build a holder-bound OID4VP `vp_token` from supplied held credentials, signed with the agent's holder key | holder identity configured |

All access is bounded by the bridge identity's VTA **role / ACL** — scope that
role to what the agent should be allowed to do (`vta_call` can reach destructive
operations like `contexts/delete` if the role permits them).

`vault_release` opens a `didcomm-authcrypt` envelope with the client's own keys,
so it requires the **DIDComm transport** (session mode); on a REST/token client
it returns a clear `UnsupportedTransport` error.

`issue_vp` signs locally with the agent's holder key — set `VTA_MCP_HOLDER_DID` +
`VTA_MCP_HOLDER_KEY` (multibase; optional `VTA_MCP_HOLDER_VM_FRAGMENT`, default
`key-0`). The key stays in the process and is never sent over MCP; without it the
tool returns a clear "not configured" error.

## Auth

Two modes:

- **Session (default)** — reuse an existing `pnm`/`cnm` login. The client
  auto-refreshes its token.
  ```bash
  vta-mcp --vta <slug>          # slug = the VTA you logged into with `pnm`
  ```
  Options: `--service-name` (default `pnm-cli`), `--sessions-dir` (default
  `~/.config/pnm`), `--url` (override the resolved REST URL). All have `VTA_MCP_*`
  env equivalents.

- **Token** — a REST client with a bearer token (simple; for testing /
  short-lived use; no auto-refresh):
  ```bash
  VTA_URL=https://vta.example.com VTA_TOKEN=<jwt> vta-mcp
  ```

## Use from Claude Desktop

Add to the host's MCP server config:

```json
{
  "mcpServers": {
    "vta": {
      "command": "vta-mcp",
      "args": ["--vta", "my-vta"]
    }
  }
}
```

## Enrolling the bridge as a managed device

Pass `--enroll` (or `VTA_MCP_ENROLL=1`) to register vta-mcp as an `ai-agent`
device at startup, so it shows up in `pnm device list` and can be revoked with
`pnm device disable` / `pnm device wipe` (the revocation is enforced at auth).
Set the binding name with `--device-name` (default `vta-mcp`).

Only use `--enroll` when vta-mcp runs as a **dedicated agent identity** — it
attaches a device binding to the authenticated DID's ACL entry, so don't point it
at an operator/admin login. Enrolment runs once before serving; the bridge does
not run a concurrent heartbeat/wake loop (that would race the tool RPCs on the
same DIDComm session).

## Notes

- Build: `cargo build -p vta-mcp` (or `--release`). `publish = false`.
- The agent's least-privilege capability set comes from its VTA **role** / ACL —
  the MCP server inherits whatever the authenticated identity is allowed to do.
- See `docs/02-vta/personal-ai-agents.md` for the broader agent-enablement story.
