//! A failed tool call, as the model reads it.
//!
//! MCP keeps two kinds of failure apart. A **protocol error** (a JSON-RPC
//! `error`) says the request itself could not be handled — an unknown tool,
//! arguments that do not deserialize. A **tool-execution error** is a
//! successful JSON-RPC response whose `CallToolResult` has `isError: true`:
//! the tool ran and the operation failed, and the text is for the model to
//! read and act on. Since `2025-11-25` (SEP-1303) input the tool itself finds
//! wrong is the second kind too, so a model can correct its own call.
//!
//! A bridge that answers a refused Trust Task with a protocol error hides the
//! refusal: hosts render JSON-RPC errors as a bridge fault ("internal error"),
//! and some never pass the message to the model at all. So every failure of
//! the *operation* — the node refused it, the local guard refused it, the
//! operator declined it, the node does not serve it — is a [`ToolError`],
//! returned as `Ok(CallToolResult::error(..))` with a small JSON body:
//!
//! ```json
//! { "error": "forbidden", "message": "…", "next": "call vta_status …" }
//! ```
//!
//! `error` is a stable kind a model (or a script reading the audit record) can
//! match on; `message` is the node's or the guard's own words; `next` is what
//! to do about it. `ErrorData` stays for what is genuinely the protocol's.

use rmcp::ErrorData;
use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::{Value, json};

/// A tool-execution failure: what went wrong, in a form the model can read.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolError {
    /// Stable kind, camelCase (`forbidden`, `notServed`, `deniedByLocalPolicy`).
    pub kind: String,
    /// The failure in words — the node's own message where there is one.
    pub message: String,
    /// What to do next, when there is something better than "give up".
    pub next: Option<String>,
    /// Structured facts the caller may need to act (served versions, a
    /// consent code, a retry-after instant).
    pub details: Option<Value>,
}

impl ToolError {
    /// A failure of `kind`, described by `message`.
    pub fn new(kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            message: message.into(),
            next: None,
            details: None,
        }
    }

    /// What the caller should do about it.
    #[must_use]
    pub fn with_next(mut self, next: impl Into<String>) -> Self {
        self.next = Some(next.into());
        self
    }

    /// Structured facts to act on.
    #[must_use]
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    /// The local guard refused the call before it reached the node.
    /// `outcome` is the recorder's label: `denied` or `declined`.
    pub fn refused_locally(outcome: &str, message: impl Into<String>, status_tool: &str) -> Self {
        match outcome {
            "declined" => Self::new("declinedByOperator", message).with_next(
                "the operator declined this call when asked. Do not send it again unless they \
                 ask you to.",
            ),
            _ => Self::new("deniedByLocalPolicy", message).with_next(format!(
                "this bridge's local policy refuses the operation; nothing was sent. Call \
                 {status_tool} to see the policy. Only the operator can change it, by \
                 restarting the bridge with different --allow / --deny / --read-only / \
                 --confirm settings."
            )),
        }
    }

    /// The JSON body the result carries.
    pub fn to_json(&self) -> Value {
        let mut body = json!({ "error": self.kind, "message": self.message });
        if let Some(next) = &self.next {
            body["next"] = json!(next);
        }
        if let Some(details) = &self.details {
            body["details"] = details.clone();
        }
        body
    }

    /// As a tool result with `isError: true`.
    pub fn into_call_result(self) -> CallToolResult {
        let text = serde_json::to_string_pretty(&self.to_json())
            .unwrap_or_else(|_| format!("{}: {}", self.kind, self.message));
        CallToolResult::error(vec![ContentBlock::text(text)])
    }
}

/// Why a tool call did not produce a result: an operation failure the model
/// reads ([`ToolError`]), or a protocol error ([`ErrorData`]).
#[derive(Debug, Clone)]
pub enum CallFailure {
    /// The operation failed; returned as `isError: true`.
    Tool(ToolError),
    /// The request could not be handled at all; returned as a JSON-RPC error.
    Protocol(ErrorData),
}

impl CallFailure {
    /// The text the call recorder keeps.
    pub fn message(&self) -> String {
        match self {
            Self::Tool(e) => format!("{}: {}", e.kind, e.message),
            Self::Protocol(e) => e.message.to_string(),
        }
    }

    /// What the tool handler returns.
    pub fn into_result(self) -> Result<CallToolResult, ErrorData> {
        match self {
            Self::Tool(e) => Ok(e.into_call_result()),
            Self::Protocol(e) => Err(e),
        }
    }
}

impl From<ToolError> for CallFailure {
    fn from(e: ToolError) -> Self {
        Self::Tool(e)
    }
}

impl From<ErrorData> for CallFailure {
    fn from(e: ErrorData) -> Self {
        Self::Protocol(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(result: &CallToolResult) -> Value {
        let text = result.content[0].as_text().expect("text content");
        serde_json::from_str(&text.text).expect("a JSON body")
    }

    #[test]
    fn a_tool_error_is_a_result_flagged_as_an_error() {
        let result = ToolError::new("forbidden", "role reader may not")
            .with_next("ask the operator")
            .with_details(json!({ "x": 1 }))
            .into_call_result();
        assert_eq!(result.is_error, Some(true));
        let body = body(&result);
        assert_eq!(body["error"], "forbidden");
        assert_eq!(body["message"], "role reader may not");
        assert_eq!(body["next"], "ask the operator");
        assert_eq!(body["details"]["x"], 1);
    }

    #[test]
    fn absent_members_are_absent_not_null() {
        let body = ToolError::new("conflict", "exists").to_json();
        assert!(body.get("next").is_none());
        assert!(body.get("details").is_none());
    }

    #[test]
    fn local_refusals_say_nothing_was_sent_and_who_can_change_it() {
        let denied = ToolError::refused_locally("denied", "read-only", "vta_status");
        assert_eq!(denied.kind, "deniedByLocalPolicy");
        assert!(denied.next.as_deref().unwrap().contains("vta_status"));
        let declined = ToolError::refused_locally("declined", "no", "vta_status");
        assert_eq!(declined.kind, "declinedByOperator");
    }

    #[test]
    fn a_protocol_failure_stays_a_protocol_error() {
        let failure = CallFailure::from(ErrorData::invalid_params("bad", None));
        assert_eq!(failure.message(), "bad");
        assert!(failure.into_result().is_err());
        let failure = CallFailure::from(ToolError::new("notFound", "gone"));
        assert_eq!(failure.message(), "notFound: gone");
        assert!(failure.into_result().is_ok());
    }
}
