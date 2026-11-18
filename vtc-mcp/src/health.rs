//! Whether the bridge can reach its community, read from the calls it makes
//! rather than latched at connect.
//!
//! `vtc_status` used to answer `connected: true` whenever a session had once
//! been opened, so a bridge whose mediator socket had been closed for hours
//! said it was connected while every call failed (the R6.2 failure:
//! a health flag must be driven by a signal that can go false again). Every
//! community call now reports its result here: a transport failure turns
//! `connected` false, and the next answer from the community — a success, a
//! refusal, a parked action — turns it true again.

use std::sync::Mutex;

use serde_json::{Value, json};
use vtc_client::VtcError;

/// What one call's result says about the way to the community.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signal {
    /// The community answered, whatever it said.
    Reached,
    /// The session or HTTPS transport failed: nothing reached the community.
    Unreachable,
    /// Refused locally before anything was sent: says nothing either way.
    None,
}

fn signal(error: Option<&VtcError>) -> Signal {
    let Some(error) = error else {
        return Signal::Reached;
    };
    match error {
        VtcError::Http { .. }
        | VtcError::NotFound { .. }
        | VtcError::SignIn { .. }
        | VtcError::Refused { .. }
        | VtcError::Parked { .. } => Signal::Reached,
        VtcError::Session(_) | VtcError::Transport(_) | VtcError::NoTransport { .. } => {
            Signal::Unreachable
        }
        // Local refusals (an unpinned URI, a payload that fails its schema, a
        // document that could not be signed) and anything this bridge does not
        // yet know how to read: no evidence about the transport.
        _ => Signal::None,
    }
}

#[derive(Debug, Default)]
struct State {
    last_reached_at: Option<String>,
    last_failure_at: Option<String>,
    last_failure: Option<String>,
    /// A transport failure is the latest signal.
    failing: bool,
}

/// The bridge's view of its way to the community, shared by every MCP session.
#[derive(Debug, Default)]
pub(crate) struct TransportHealth {
    state: Mutex<State>,
}

impl TransportHealth {
    /// Record what `result` says about the transport, and hand it back.
    pub(crate) fn observe<T>(&self, result: Result<T, VtcError>) -> Result<T, VtcError> {
        self.record(signal(result.as_ref().err()), result.as_ref().err());
        result
    }

    fn record(&self, signal: Signal, error: Option<&VtcError>) {
        if signal == Signal::None {
            return;
        }
        let now = vti_mcp_common::observability::now_rfc3339();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        match signal {
            Signal::Reached => {
                state.last_reached_at = Some(now);
                state.failing = false;
            }
            Signal::Unreachable => {
                state.last_failure_at = Some(now);
                state.last_failure = error.map(ToString::to_string);
                state.failing = true;
            }
            Signal::None => {}
        }
    }

    /// No transport failure since the community last answered.
    pub(crate) fn reachable(&self) -> bool {
        !self.state.lock().unwrap_or_else(|p| p.into_inner()).failing
    }

    pub(crate) fn to_json(&self) -> Value {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        json!({
            "lastReachedAt": state.last_reached_at,
            "lastFailureAt": state.last_failure_at,
            "lastFailure": state.last_failure,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transport_failure_turns_it_false_and_the_next_answer_back() {
        let health = TransportHealth::default();
        assert!(health.reachable(), "nothing has failed yet");

        let _ = health.observe::<Value>(Err(VtcError::Session(
            "TSP websocket closed by the mediator".into(),
        )));
        assert!(!health.reachable());
        let json = health.to_json();
        assert!(
            json["lastFailure"]
                .as_str()
                .unwrap()
                .contains("closed by the mediator")
        );
        assert!(json["lastFailureAt"].is_string());

        // A refusal is the community answering: the transport works.
        let _ = health.observe::<Value>(Err(VtcError::Refused {
            document: "{}".into(),
        }));
        assert!(health.reachable());
        assert!(health.to_json()["lastReachedAt"].is_string());
    }

    /// Every call this bridge makes to its community goes through
    /// `health.observe`, or `connected` would miss the failures of the calls
    /// that skip it. A census over the sources: a `client.<method>(…)` that
    /// is awaited must be the argument of an `observe(`.
    #[test]
    fn every_community_call_is_observed() {
        // Not calls to the community: accessors and teardown.
        const LOCAL: &[&str] = &["transport", "shutdown", "clone", "is_some", "as_ref"];
        let sources = [
            ("server.rs", include_str!("server.rs")),
            ("signin.rs", include_str!("signin.rs")),
            ("workflows.rs", include_str!("workflows.rs")),
            ("main.rs", include_str!("main.rs")),
            ("listen.rs", include_str!("listen.rs")),
        ];
        let mut unobserved = Vec::new();
        for (file, source) in sources {
            let mut at = 0;
            while let Some(found) = source[at..].find("client.") {
                let start = at + found;
                at = start + "client.".len();
                let method: String = source[at..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if method.is_empty() || LOCAL.contains(&method.as_str()) {
                    continue;
                }
                // Awaited before the statement ends: a call to the community.
                let rest = &source[at..];
                let end = rest.find(';').unwrap_or(rest.len());
                if !rest[..end].contains(".await") {
                    continue;
                }
                let before = &source[start.saturating_sub(40)..start];
                if !before.contains("observe(") {
                    let line = source[..start].lines().count();
                    unobserved.push(format!("{file}:{line} client.{method}"));
                }
            }
        }
        assert!(
            unobserved.is_empty(),
            "community calls that skip `self.health.observe(…)`: {unobserved:?}"
        );
    }

    #[test]
    fn a_local_refusal_says_nothing_about_the_transport() {
        let health = TransportHealth::default();
        let _ = health.observe::<Value>(Err(VtcError::Session("down".into())));
        let _ = health.observe::<Value>(Err(VtcError::InvalidPayload("bad".into())));
        assert!(!health.reachable(), "a schema failure sent nothing");
        let _ = health.observe(Ok(json!({})));
        assert!(health.reachable());
    }
}
