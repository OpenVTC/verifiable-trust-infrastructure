//! A transport that hands each Trust Task straight back to the caller.
//!
//! ## What this is for
//!
//! Every other transport needs something on the far end — a running VTA, a
//! mediator, a websocket. That cost is why the SDK's *producer* side went
//! untested: the only way to see the bytes a client method emits was to stand
//! up the whole stack, so nothing did, and payload defects were found in
//! production instead. `keys/create` sent `"mnemonic": null` on every call for
//! a month (#919); `vta/webvh/dids/update` did the same before it (#895).
//!
//! A loopback transport removes the far end. The client method runs its real
//! body-building code, `dispatch_trust_task` wraps the real envelope, and the
//! bytes arrive at a [`LoopbackSink`] the test controls. What the test does
//! with them — validate against the published schema, feed a real dispatcher,
//! assert on a member — is its business.
//!
//! This is deliberately *not* a mock of the VTA. It asserts nothing and
//! implements no behaviour; it is a tap on the wire.
//!
//! ## What it does not cover
//!
//! Framing. TSP sealing, DIDComm authcrypt, mediator routing and the
//! addressing in [`VtaClient::address_trust_task`] all sit below this point,
//! so a defect in any of them is invisible here. Those need a transport
//! harness with a real mediator. What this does cover is the layer where the
//! two shipped defects actually lived: the payload a client method builds.

use std::sync::Arc;

use serde_json::Value;

use crate::error::VtaError;

/// The far end of a [`Transport::Loopback`](super::Transport) client.
///
/// Called once per dispatched Trust Task, with the task's type URI and the
/// payload the client method built. The returned value is handed back to the
/// client method as the task's response payload — return whatever shape that
/// method expects, or an error to exercise its failure path.
///
/// A test that only cares about requests may return `Value::Null` and ignore
/// every client method's return value; the payload has already been captured
/// by then.
pub trait LoopbackSink: Send + Sync {
    /// Receive one dispatched task. `payload` is the exact value that would
    /// have gone on the wire.
    fn dispatch(&self, type_uri: &str, payload: &Value) -> Result<Value, VtaError>;
}

/// A [`LoopbackSink`] that records every task and answers with a fixed value.
///
/// The common case: drive the producers, then inspect what they emitted.
#[derive(Default)]
pub struct RecordingSink {
    seen: std::sync::Mutex<Vec<(String, Value)>>,
    reply: Option<Value>,
}

impl RecordingSink {
    /// A sink that answers every task with `Value::Null`.
    ///
    /// Most client methods will fail to deserialize that into their response
    /// type and return `Err` — which is fine and expected. The request was
    /// captured before the response was parsed, so a test that is asking "what
    /// did we send?" can discard the return value entirely.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A sink that answers every task with `reply`.
    #[must_use]
    pub fn replying_with(reply: Value) -> Self {
        Self {
            seen: std::sync::Mutex::new(Vec::new()),
            reply: Some(reply),
        }
    }

    /// Every `(type_uri, payload)` dispatched so far, in order.
    #[must_use]
    pub fn recorded(&self) -> Vec<(String, Value)> {
        self.seen
            .lock()
            .expect("sink mutex is not poisoned")
            .clone()
    }
}

impl LoopbackSink for RecordingSink {
    fn dispatch(&self, type_uri: &str, payload: &Value) -> Result<Value, VtaError> {
        self.seen
            .lock()
            .expect("sink mutex is not poisoned")
            .push((type_uri.to_string(), payload.clone()));
        Ok(self.reply.clone().unwrap_or(Value::Null))
    }
}

impl super::VtaClient {
    /// A client whose Trust-Task surface is answered in-process by `sink`.
    ///
    /// The sink is consulted *ahead of* the transport, so only the Trust-Task
    /// surface is intercepted. The REST routes and the DIDComm
    /// protocol-message surface ([`rpc`](super::VtaClient::rpc)) fall through
    /// to the transport underneath, which is a REST client pointed at an
    /// unroutable address — reaching one from a loopback client is a test bug,
    /// and it should fail rather than quietly succeed against something real.
    #[must_use]
    pub fn loopback(sink: Arc<dyn LoopbackSink>) -> Self {
        Self {
            transport: super::Transport::Rest {
                client: crate::http::rest_client(),
                base_url: "http://loopback.invalid".to_string(),
                auth: Arc::new(tokio::sync::Mutex::new(super::RestAuth {
                    token: None,
                    expires_at: None,
                    refresh_token: None,
                    refresh_expires_at: None,
                    credential: None,
                })),
            },
            loopback: Some(sink),
        }
    }
}
