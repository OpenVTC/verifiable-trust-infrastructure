//! What the VTI MCP bridges share.
//!
//! An MCP bridge — `vta-mcp` for a VTA, `vtc-mcp` for a VTC — exposes a node's
//! Trust Task surface as MCP tools, and the node stays the authority: every
//! call is gated server-side on the bridge identity's standing there. Two
//! things sit in front of that on the bridge's own side, and they are the same
//! for every bridge, which is why they live here rather than in each one:
//!
//! - [`guard`] — the local per-operation gate. An MCP host approves a *tool*,
//!   not a call; once the generic "invoke any operation by URI" tool is
//!   approved, every Trust Task rides that one approval. The guard classifies
//!   each URI by risk, applies the operator's allow/deny globs and `--read-only`,
//!   and puts the risky tail back in front of a human.
//! - [`observability`] — a start line and a finish line per call on stderr, a
//!   redacted record in a ring the host can read back, and an optional JSONL
//!   audit file.
//! - [`listen`] — `--listen`: one bridge serving every MCP host on the machine
//!   over loopback HTTP behind a bearer token, since the mediator holds one
//!   socket per DID; and the protocol versions a bridge that asks the human
//!   may serve.
//!
//! A policy fix made here reaches every bridge. A bridge that copied these
//! would be a second thing to keep correct.
//!
//! Nothing here grants access. `publish = false`.

pub mod guard;
pub mod listen;
pub mod observability;
