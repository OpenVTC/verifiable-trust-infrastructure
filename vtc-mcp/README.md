# vtc-mcp — a Verifiable Trust Community from an MCP host

`vtc-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server
that exposes a Verifiable Trust Community (VTC) as MCP tools, so a member's or
an administrator's AI assistant — Claude Code, Claude Desktop, an IDE, an agent
framework — can configure a community, run its ceremonies and read its state
with no custom integration code.

It is a **native Trust Task client, not a wrapper around a CLI**. Every tool
call is one signed Trust Task document sent in-process, over the transport the
community's DID document advertises — TSP first, then DIDComm, then signed
documents over HTTPS when the community advertises neither. It never runs
`cnm` or `pnm`, and it never takes a CLI's stored login as its identity.

Design: `docs/05-design-notes/vtc-mcp.md`. Transport: stdio. `publish = false`.

## Tools

| Tool | What it does |
|---|---|
| `vtc_list_operations` | The catalog of every Trust Task `vtc_call` can send, read from the pinned specification bundles: description, risk class, this bridge's policy decision, and whether the community serves it; `detail: "full"` adds the payload schema and declared error codes |
| `vtc_call` | Send any pinned operation by Type URI with a JSON payload. A result with `status: "parked"` is not a failure: the community waits for other administrators' approval |
| `vtc_supported_tasks` | What the connected community serves (`trust-task-discovery/0.4`) |
| `vtc_whoami` | What the community knows of this identity (`auth/whoami`), beside the configured identity |
| `vtc_status` | What this bridge is: identity, community, transport, policy, counters, recent calls |

Resources: `vtc://status`, `vtc://operations`, `vtc://calls/recent`, and the
community's own operator guides as `vtc://guide/{groups, boards, elections,
rooms, rooms-quickstart, admission, lifecycle, vetting, directory,
admin-access}` — the workspace's `docs/03-vtc/*.md`, embedded at build time so
the assistant reads the guide this bridge's version was written against.

## Prompts

One per multi-step job, each an ordered brief: the preconditions to check,
the tasks to send in order, which of them park on the community's action list
for other administrators, what the member sees afterwards, and which guides to
read first. Every task a prompt names is one `vtc_call` can send (a test holds
each to the pinned specification index).

| Prompt | Arguments (all optional) |
|---|---|
| `setup-group` | `name`, `purpose` |
| `create-board` | `title`, `audience` |
| `run-election` | `question`, `roll` |
| `open-data-room` | `label`, `members` |
| `admit-member` | `subject`, `role` |
| `grant-administration` | `subject`, `role` |

## Identity

Exactly one, chosen by what is configured and never by falling through:

| Rung | Flags | Speaks as |
|---|---|---|
| 1 | `--agent-secrets <path or JSON>` + `--vtc-did` | A member's own persona: the `did:webvh` secrets bundle a VTA minted |
| 2 | `--agent-did` + `--agent-key` + `--vtc-did` | A dedicated agent entry an administrator enrolled with `acl/grant`, bounded by its role ceiling or listed capabilities |

Both given is an error; half of rung 2 is an error naming the missing field;
neither serves in degraded mode so `vtc_status` can say what is wrong.

## Policy

The community is the authority. In front of it, this bridge applies the same
local per-operation guard as `vta-mcp` (`vti-mcp-common`), because an MCP host
approves a *tool* and not a call: `--read-only`, `--allow` / `--deny` slug
globs, and `--confirm never|destructive|sensitive|always`, which puts the risky
tail back in front of a human through MCP elicitation. Every call is logged to
stderr and kept, redacted, in a ring the host can read back; `--audit-log`
appends a JSONL record.

## Example

```json
{
  "mcpServers": {
    "community": {
      "command": "vtc-mcp",
      "env": {
        "VTC_MCP_VTC_DID": "did:webvh:…:vtc.example.com",
        "VTC_MCP_AGENT_DID": "did:key:z6Mk…",
        "VTC_MCP_AGENT_KEY": "z3u2…",
        "VTC_MCP_CONFIRM": "sensitive"
      }
    }
  }
}
```
