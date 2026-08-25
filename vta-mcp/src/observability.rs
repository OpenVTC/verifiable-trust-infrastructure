//! Seeing what the bridge is doing.
//!
//! An MCP server is a subprocess with its stdout wired to the protocol. The
//! only channels back to a human are **stderr**, which the host captures into
//! its own log files, and whatever the server writes to disk itself. This
//! module owns both.
//!
//! Three separate things, on purpose:
//!
//! - **stderr tracing** — the runtime log. On by default at `info`, because the
//!   previous behaviour (`EnvFilter::from_default_env()` with no fallback) meant
//!   an operator who had not set `RUST_LOG` got *silence*: no startup line, no
//!   call log, no error. A bridge you cannot observe is a bridge you cannot
//!   trust.
//! - **the audit log** (`--audit-log`) — one JSON object per line per call,
//!   durable, owner-only, machine-readable. This is the record you read *after*
//!   something happened; stderr is what you watch while it happens.
//! - **redaction** — both of the above pass every payload through [`redact`]
//!   first. The bridge handles signing input, released secrets and holder keys,
//!   and none of that may reach a log file.
//!
//! ## Why not MCP's `logging` capability
//!
//! MCP has a server→client logging channel (`notifications/message`), and it
//! would put these lines in the host's UI. It is **deprecated** as of SEP-2577
//! and slated for removal — `rmcp` marks every logging type `#[deprecated]`.
//! Building the observability story on it would mean rebuilding it. stderr is
//! where MCP hosts already look, and the audit file is where an operator can
//! grep six months later.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Map, Value, json};

/// How the stderr log is rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// Human-readable lines. The default — a person is usually reading these
    /// out of a host's log pane.
    #[default]
    Text,
    /// One JSON object per line, for shipping into a log pipeline.
    Json,
}

impl LogFormat {
    /// Parse the `--log-format` flag.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "text" | "plain" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => Err(format!(
                "unknown --log-format value '{other}' (expected text or json)"
            )),
        }
    }
}

/// Install the stderr subscriber.
///
/// `RUST_LOG` still wins when set, so existing debugging habits keep working;
/// otherwise the filter is `vta_mcp=<level>` plus a quieter floor for the SDK,
/// whose DIDComm layer is chatty at `debug` and would bury the bridge's own
/// lines.
///
/// stdout is the MCP JSON-RPC channel. Nothing may ever be written there —
/// a single stray `println!` corrupts the stream and the host reports a broken
/// server with no further explanation.
pub fn init_tracing(level: &str, format: LogFormat) {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| {
        format!("vta_mcp={level},vta_sdk=warn,affinidi_messaging_sdk=warn,rmcp=warn")
    });
    let filter = tracing_subscriber::EnvFilter::new(filter);
    let builder = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .with_target(true);
    match format {
        LogFormat::Text => builder.init(),
        LogFormat::Json => builder.json().flatten_event(true).init(),
    }
}

/// Payload keys whose values are safe to record verbatim.
///
/// An allowlist, not a denylist: a denylist has to predict every name a secret
/// might arrive under, and `vta_call` takes arbitrary payloads for operations
/// this build has never heard of. Anything not named here is elided.
const SAFE_KEYS: &[&str] = &[
    "algorithm",
    "alg",
    "agentDid",
    "audience",
    "clientDid",
    "context",
    "contextId",
    "deviceId",
    "did",
    "displayName",
    "domain",
    "entryId",
    "format",
    "id",
    "keyId",
    "kind",
    "label",
    "limit",
    "name",
    "offset",
    "operation",
    "platform",
    "purpose",
    "reason",
    "role",
    "scope",
    "server",
    "serverId",
    "serviceKind",
    "status",
    "tag",
    "template",
    "type",
    "uri",
    "vtaDid",
];

/// How deep [`redact`] walks before collapsing a subtree.
const MAX_DEPTH: usize = 4;
/// How many array elements survive; the rest become a count marker.
const MAX_ARRAY: usize = 8;

/// Strip anything that could be secret out of a payload, keeping the shape.
///
/// The rule is that **strings are guilty until named innocent**. Numbers and
/// booleans pass — a key id's index or a `force: true` is worth having in the
/// log and neither can carry key material. Strings pass only under a
/// [`SAFE_KEYS`] name, so `text` (what `sign` signs), `secret`, `privateKey`,
/// `mnemonic`, `jwe` and every field of a released credential are elided
/// without this module needing to know they exist.
pub fn redact(value: &Value) -> Value {
    redact_at(value, 0, false)
}

fn redact_at(value: &Value, depth: usize, key_is_safe: bool) -> Value {
    if depth > MAX_DEPTH {
        return json!("<elided:depth>");
    }
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                let safe = SAFE_KEYS.contains(&k.as_str());
                out.insert(k.clone(), redact_at(v, depth + 1, safe));
            }
            Value::Object(out)
        }
        Value::Array(items) => {
            let mut out: Vec<Value> = items
                .iter()
                .take(MAX_ARRAY)
                .map(|v| redact_at(v, depth + 1, key_is_safe))
                .collect();
            if items.len() > MAX_ARRAY {
                out.push(json!(format!("<elided:{} more>", items.len() - MAX_ARRAY)));
            }
            Value::Array(out)
        }
        Value::String(_) if !key_is_safe => json!("<elided>"),
        other => other.clone(),
    }
}

/// One completed tool call, as recorded.
#[derive(Debug, Clone)]
pub struct CallRecord {
    /// Monotonic per-process call number, also emitted on the stderr line so
    /// the two logs can be joined.
    pub seq: u64,
    /// The MCP tool name.
    pub tool: &'static str,
    /// The Trust Task URI the call resolved to, where there is one.
    pub operation: Option<String>,
    /// The [`crate::guard::Risk`] label.
    pub risk: &'static str,
    /// The [`crate::guard::Decision`] label.
    pub decision: &'static str,
    /// `ok`, `error`, `denied` or `declined`.
    pub outcome: &'static str,
    /// Wall-clock duration of the call.
    pub duration_ms: u128,
    /// Redacted arguments.
    pub args: Value,
    /// The error message, when `outcome` is not `ok`.
    pub error: Option<String>,
}

impl CallRecord {
    fn to_json(&self, ts: String) -> Value {
        json!({
            "ts": ts,
            "seq": self.seq,
            "tool": self.tool,
            "operation": self.operation,
            "risk": self.risk,
            "decision": self.decision,
            "outcome": self.outcome,
            "durationMs": self.duration_ms,
            "args": self.args,
            "error": self.error,
        })
    }
}

/// Running totals, surfaced by the `vta_status` tool.
#[derive(Debug, Default)]
pub struct Counters {
    /// Calls that reached the VTA (or a local handler) and returned.
    pub ok: AtomicU64,
    /// Calls that reached the VTA and failed.
    pub errors: AtomicU64,
    /// Calls the local guard refused outright.
    pub denied: AtomicU64,
    /// Calls a human was asked about and declined.
    pub declined: AtomicU64,
}

impl Counters {
    /// Snapshot for rendering.
    pub fn snapshot(&self) -> Value {
        json!({
            "ok": self.ok.load(Ordering::Relaxed),
            "errors": self.errors.load(Ordering::Relaxed),
            "denied": self.denied.load(Ordering::Relaxed),
            "declined": self.declined.load(Ordering::Relaxed),
        })
    }

    /// Record one outcome by its label.
    pub fn record(&self, outcome: &str) {
        let counter = match outcome {
            "ok" => &self.ok,
            "denied" => &self.denied,
            "declined" => &self.declined,
            _ => &self.errors,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// An append-only JSONL record of every call.
///
/// Held behind a `std::sync::Mutex` rather than an async one: the critical
/// section is a `writeln!` of a few hundred bytes with no `.await` inside it,
/// which is the only shape of blocking lock that is safe on an async executor.
#[derive(Debug)]
pub struct AuditLog {
    file: Mutex<std::fs::File>,
    path: PathBuf,
}

impl AuditLog {
    /// Open (or create) the audit file, owner-only.
    ///
    /// The records name operations, DIDs, context ids and key ids — not
    /// secrets, but a map of what this VTA holds and who touches it. That is
    /// worth 0600 on its own.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        // `mode` only applies at creation; an existing file keeps whatever
        // permissions it had, so tighten it explicitly.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(Self {
            file: Mutex::new(file),
            path: path.to_path_buf(),
        })
    }

    /// Where this log is being written — reported by `vta_status` so an
    /// operator does not have to remember the flag they passed.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one already-rendered record. A failed write is logged and
    /// swallowed: losing an audit line is bad, but failing a VTA call because a
    /// disk filled up is worse, and the stderr log still carries the same event.
    pub fn append(&self, line: &Value) {
        let Ok(mut file) = self.file.lock() else {
            tracing::error!("audit log mutex poisoned; record dropped");
            return;
        };
        if let Err(e) = writeln!(file, "{line}") {
            tracing::error!(error = %e, "writing audit record");
        }
    }
}

/// UTC timestamp in RFC 3339, the format the VTA's own audit rows use.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Monotonic call ids, shared by the stderr and audit logs.
#[derive(Debug, Default)]
pub struct CallSeq(AtomicU64);

impl CallSeq {
    /// The next call id.
    pub fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed) + 1
    }
}

/// How many recent calls stay in memory for the `vta://calls/recent` resource.
const RING_CAPACITY: usize = 100;

/// Everything that remembers what the bridge did: the call counter, the
/// running totals, the in-memory ring the host can read back, and the optional
/// on-disk audit file.
///
/// The ring exists so that "what has this thing been doing?" is answerable
/// **without** the operator having thought to pass `--audit-log` beforehand —
/// which, by the time they are asking the question, they will not have.
#[derive(Debug, Default)]
pub struct Recorder {
    seq: CallSeq,
    counters: Counters,
    ring: Mutex<std::collections::VecDeque<Value>>,
    file: Option<AuditLog>,
}

impl Recorder {
    /// A recorder writing to `path` as well as memory.
    pub fn with_file(path: &Path) -> std::io::Result<Self> {
        Ok(Self {
            file: Some(AuditLog::open(path)?),
            ..Self::default()
        })
    }

    /// The next call id.
    pub fn next_seq(&self) -> u64 {
        self.seq.next()
    }

    /// Running totals.
    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    /// The audit file path, if one is configured.
    pub fn audit_path(&self) -> Option<&Path> {
        self.file.as_ref().map(AuditLog::path)
    }

    /// Record a completed call: totals, ring, and the file if configured.
    pub fn record(&self, record: &CallRecord) {
        self.counters.record(record.outcome);
        let line = record.to_json(now_rfc3339());
        if let Some(file) = &self.file {
            file.append(&line);
        }
        if let Ok(mut ring) = self.ring.lock() {
            if ring.len() == RING_CAPACITY {
                ring.pop_front();
            }
            ring.push_back(line);
        }
    }

    /// The most recent calls, newest last, capped at [`RING_CAPACITY`].
    pub fn recent(&self, limit: usize) -> Vec<Value> {
        let Ok(ring) = self.ring.lock() else {
            return Vec::new();
        };
        let skip = ring.len().saturating_sub(limit);
        ring.iter().skip(skip).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unnamed_strings_are_elided() {
        let out = redact(&json!({ "text": "sign me", "keyId": "key-1" }));
        assert_eq!(out["text"], json!("<elided>"));
        assert_eq!(out["keyId"], json!("key-1"));
    }

    #[test]
    fn numbers_and_booleans_survive() {
        let out = redact(&json!({ "limit": 50, "force": true, "offset": 0 }));
        assert_eq!(out["limit"], json!(50));
        assert_eq!(out["force"], json!(true));
        assert_eq!(out["offset"], json!(0));
    }

    #[test]
    fn secrets_are_elided_without_being_named() {
        // The point of the allowlist: none of these key names appear anywhere
        // in this crate, and all of them are still elided.
        let out = redact(&json!({
            "mnemonic": "abandon abandon …",
            "privateKeyMultibase": "z3u2…",
            "jwe": "eyJhbGciOi…",
            "password": "hunter2",
        }));
        for k in ["mnemonic", "privateKeyMultibase", "jwe", "password"] {
            assert_eq!(out[k], json!("<elided>"), "{k} leaked");
        }
    }

    #[test]
    fn nested_objects_are_walked_and_bounded() {
        let deep = json!({"a":{"b":{"c":{"d":{"e":{"f":"secret"}}}}}});
        let out = redact(&deep).to_string();
        assert!(!out.contains("secret"), "{out}");
    }

    #[test]
    fn long_arrays_are_truncated_with_a_count() {
        let out = redact(&json!({ "did": (0..20).map(|i| i.to_string()).collect::<Vec<_>>() }));
        let arr = out["did"].as_array().unwrap();
        assert_eq!(arr.len(), MAX_ARRAY + 1);
        assert_eq!(arr[MAX_ARRAY], json!("<elided:12 more>"));
    }

    #[test]
    fn a_safe_key_does_not_whitelist_its_whole_subtree() {
        // `name` is safe, but a nested `secret` under it is not — the flag is
        // recomputed per key on the way down, not inherited.
        let out = redact(&json!({ "name": { "secret": "no" } }));
        assert_eq!(out["name"]["secret"], json!("<elided>"));
    }

    #[test]
    fn counters_bucket_by_outcome() {
        let c = Counters::default();
        c.record("ok");
        c.record("denied");
        c.record("boom");
        let snap = c.snapshot();
        assert_eq!(snap["ok"], json!(1));
        assert_eq!(snap["denied"], json!(1));
        assert_eq!(snap["errors"], json!(1));
    }

    fn record(seq: u64) -> CallRecord {
        CallRecord {
            seq,
            tool: "vta_call",
            operation: Some("https://trusttasks.org/spec/acl/list/0.1".into()),
            risk: "read-only",
            decision: "allow",
            outcome: "ok",
            duration_ms: 12,
            args: redact(&json!({"text": "shh"})),
            error: None,
        }
    }

    #[test]
    fn audit_records_are_one_json_object_per_line() {
        let dir = std::env::temp_dir().join(format!("vta-mcp-audit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let recorder = Recorder::with_file(&path).unwrap();
        recorder.record(&record(1));
        recorder.record(&record(2));
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.lines().count(), 2);
        let parsed: Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["tool"], json!("vta_call"));
        assert_eq!(parsed["args"]["text"], json!("<elided>"));
        assert!(parsed["ts"].as_str().unwrap().ends_with('Z'));
        assert_eq!(recorder.counters().snapshot()["ok"], json!(2));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_ring_answers_without_an_audit_file() {
        // The case that matters: nobody passed --audit-log, and the operator
        // now wants to know what the bridge has been doing.
        let recorder = Recorder::default();
        assert!(recorder.audit_path().is_none());
        for seq in 1..=(RING_CAPACITY as u64 + 10) {
            recorder.record(&record(seq));
        }
        let recent = recorder.recent(5);
        assert_eq!(recent.len(), 5);
        // Newest last, and the oldest entries have aged out.
        assert_eq!(recent[4]["seq"], json!(RING_CAPACITY as u64 + 10));
        assert_eq!(recorder.recent(1_000).len(), RING_CAPACITY);
    }

    #[cfg(unix)]
    #[test]
    fn the_audit_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("vta-mcp-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        // Pre-create it world-readable: `mode()` applies only at creation, so
        // this is the case that needs the explicit set_permissions.
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _log = AuditLog::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "audit log left readable by others");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn log_format_parses() {
        assert_eq!(LogFormat::parse("json").unwrap(), LogFormat::Json);
        assert_eq!(LogFormat::parse("TEXT").unwrap(), LogFormat::Text);
        assert!(LogFormat::parse("xml").is_err());
    }
}
