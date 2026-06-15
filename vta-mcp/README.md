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

| Tool | What it does | Capability required |
|---|---|---|
| `vta_capabilities` | Discover the VTA's features, services, WebVH servers, DID modes | any auth |
| `list_keys` | List the VTA's signing keys | any auth |
| `sign` | Sign UTF-8 text with a VTA-held key (private key never leaves the VTA) | `Sign` |
| `vault_list` | List secrets-vault entry metadata (no secrets) | `VaultRead` |
| `vault_get` | One entry's metadata by id (no secret) | `VaultRead` |
| `vault_release` | Release a secret sealed to this client; returns cleartext | `FillRelease` (DIDComm only) |
| `device_heartbeat` | Check the device in; returns queued operations | any auth |

`vault_release` opens a `didcomm-authcrypt` envelope with the client's own keys,
so it requires the **DIDComm transport** (session mode); on a REST/token client
it returns a clear `UnsupportedTransport` error.

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
