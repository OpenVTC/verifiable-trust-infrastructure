# CLAUDE.md — vti-mcp-common

Crate guidance. The workspace `CLAUDE.md` applies too.

## What this crate is

What the workspace's MCP bridges share — `vta-mcp` and `vtc-mcp`
(`docs/05-design-notes/vtc-mcp.md`): the **local per-operation guard**
(`guard.rs`: the risk classifier, allow/deny slug globs, `--read-only`, the
confirm levels answered by MCP elicitation) and the **call recorder**
(`observability.rs`: stderr start/finish lines, the redacted ring a host reads
back, the optional owner-only JSONL audit file) and the **`--listen` server**
(`listen.rs`: one bridge serving every host on the machine over loopback HTTP
behind a bearer token, and the protocol versions a bridge that elicits may
serve). A bridge exists because an MCP
host approves a *tool*, not a call; these are the same for every bridge,
and a policy fix made here reaches all of them. `publish = false`.

## Rules

- **One classification table.** A slug is a slug whichever node serves it;
  `acl/grant` moves authority at a VTA and at a VTC alike. Place a task once,
  with the reason in its comment, and never fork the table per bridge.
- **Two censuses, both load-bearing.** This crate holds every pinned request
  Type URI (`vti_specs::schema_index::type_uris`) to an override or a known
  verb; each bridge holds every URI its generic tool can dispatch to the same
  (`vta-mcp/src/census.rs`, over the VTA's dispatch table, which also carries
  the unpinnable framework specifications). A new verb fails a census rather
  than defaulting to `Mutating` silently. Fix a red census by deciding what
  the task does, not by adding the verb to whichever list makes it green.
- **`ReadOnly` is the class `--read-only` permits.** It means "safe to call on
  a whim", not "a read": a read that returns key material or discloses the
  principal's standing is `Sensitive` (`vta/contexts/secrets`,
  `rooms/keys/browse`). The question is what one execution discloses or
  confers, not whether state changes — the opposite question from
  `vta_sdk::retry_safety`, which asks what a *second* execution costs.
- **Unknown classifies as `Mutating`, never `ReadOnly`**, so a URI this build
  has never seen cannot pass a `--read-only` bridge.
- **Redaction is an allowlist.** A string survives only under a `SAFE_KEYS`
  name; add a key only when its value can never be a secret, and never add a
  denylist. A task whose payload is a person's own text keeps no string at all
  (`carries_personal_text`).
- **A failed operation is a tool result, never a protocol error**
  (`tool_error.rs`, #2594). A node's refusal, a guard refusal, an operator's
  decline, an unserved URI: `ToolError` → `CallToolResult::error` with
  `{error, message, next, details}`, so the model reads it and can correct the
  call. `ErrorData` is only for what MCP itself defines as a protocol error (a
  request the bridge cannot parse, an unknown resource). Each bridge maps its
  own client error onto kinds; keep a kind's name stable once shipped.
- **Nothing here grants access.** The node is the authority; the guard is a
  second gate in front of it and never a substitute.
- **`listen` is loopback, a token and no browsers — none of it optional.** A
  bridge's `--listen` endpoint speaks with its identity, so `check_loopback`
  runs before binding with no flag to widen it, every request carries the
  bearer token (constant-time compare, an owner-only file refused when others
  can read it), and `Origin` is refused with `Host` held to loopback. A bridge
  that elicits returns `listen::supported_protocol_versions` from
  `ServerHandler::supported_protocol_versions`: `2026-07-28` forbids the
  request a confirmation is. Lift the cap here, for every bridge, and only
  once confirmation works on the newer protocol in the hosts in use.
