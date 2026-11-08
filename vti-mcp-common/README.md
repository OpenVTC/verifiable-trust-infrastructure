# vti-mcp-common

What the Verifiable Trust Infrastructure's MCP bridges share.

An MCP bridge (`vta-mcp` for a VTA, `vtc-mcp` for a VTC) exposes a node's
Trust Task surface as MCP tools. The node stays the authority. Two things sit
in front of it on the bridge's own side, and they are the same for every
bridge:

- **`guard`** — the local per-operation gate. An MCP host approves a *tool*,
  not a call; once the generic "invoke any operation by URI" tool is approved,
  every Trust Task rides that one approval. The guard classifies each URI by
  risk (read-only, mutating, sensitive, destructive), applies the operator's
  allow/deny slug globs and `--read-only`, and puts the risky tail back in
  front of a human through MCP elicitation.
- **`observability`** — a start line and a finish line per call on stderr, a
  redacted record in a ring the host can read back without an audit file
  having been configured, and an optional owner-only JSONL audit file.

A census test holds every pinned Trust Task request URI to a classified verb,
so a new task cannot default to a class nobody decided.

Not published: shared only by the workspace's own bridges. See
`docs/02-vta/vta-mcp.md` for the operator's view of what these do.
