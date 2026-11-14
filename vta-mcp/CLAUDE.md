# CLAUDE.md — vta-mcp

Crate guidance. The workspace `CLAUDE.md` applies too.

## What this crate is

(The crate's full entry from the workspace `CLAUDE.md` crate map.)

Model Context Protocol server bridging a VTA's agent capabilities (signing oracle, vault, device, discovery) to MCP tools over stdio (or, with `--listen`, loopback HTTP shared by every host on the machine — `vti_mcp_common::listen`), so any MCP host (Claude Desktop, agent frameworks) can use a VTA with no custom code. Runs every call through the **local per-operation guard** and the call recorder from `vti-mcp-common` (shared with `vtc-mcp`), because an MCP host approves a *tool*, not a call — once `vta_call` is approved every Trust Task URI rides that approval. Its own half of the guard census (`src/census.rs`) holds every URI `vta_call` can dispatch to a classified verb. Docs: `docs/02-vta/vta-mcp.md`. `publish = false`

## Where the guard lives

The risk classifier, allow/deny globs, confirm levels and the redacting
recorder moved to `vti-mcp-common` (`vti-mcp-common/CLAUDE.md` has the rules).
A placement decision — this slug is sensitive, that verb only reads — goes in
that crate's one table, never in a copy here. This crate keeps what is the
VTA's alone: the tools, their annotations (asserted against the shared
classifier by `tool_annotations_agree_with_the_risk_classifier`), the connect
ladder, and the VTA dispatch-table census.

## Failures the model reads

Every failure of an operation — a `VtaError`, a guard refusal, an unserved URI —
is a `vti_mcp_common::tool_error::ToolError` returned as a tool result with
`isError: true` (#2594), its kind from the `VtaError` variant (`to_tool`).
`vta_call` checks its URI against the VTA's discovery answer (asked once,
remembered, never past a local policy that denies discovery) and answers
`notServed` instead of waiting out the reply timeout; when discovery cannot be
asked, the VTA answers. Never map a `VtaError` to `ErrorData`.
