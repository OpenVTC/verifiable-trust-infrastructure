# CLAUDE.md — vta-mcp

Crate guidance. The workspace `CLAUDE.md` applies too.

## What this crate is

(The crate's full entry from the workspace `CLAUDE.md` crate map.)

Model Context Protocol server bridging a VTA's agent capabilities (signing oracle, vault, device, discovery) to MCP tools over stdio, so any MCP host (Claude Desktop, agent frameworks) can use a VTA with no custom code. Carries a **local per-operation guard** (`guard.rs`) because an MCP host approves a *tool*, not a call — once `vta_call` is approved every Trust Task URI rides that approval — plus stderr/JSONL call logging (`observability.rs`). Docs: `docs/02-vta/vta-mcp.md`. `publish = false`
