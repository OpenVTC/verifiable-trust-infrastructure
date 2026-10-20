//! The ballot box over TSP and DIDComm: `vti_common::host_session`, with [`dispatch::answer`] as
//! the responder.
//!
//! The service's identity holds one mediator socket, both protocols on it. The transport proves
//! the sender, and the dispatcher holds the document's `issuer` to it, so a community's
//! registration, close and cancel arrive authenticated twice over — by the transport and by the
//! document's own proof — and a cast from a one-time key is held to that key.

use std::sync::Arc;

use serde_json::Value;
pub use vti_common::host_session::{IdentitySession, Shared, supervise};

use crate::dispatch::{self, AppState};

/// The ballot box as a [`vti_common::host_session::Responder`].
#[derive(Debug)]
pub struct BallotBoxResponder {
    state: Arc<AppState>,
}

impl BallotBoxResponder {
    pub fn new(state: Arc<AppState>) -> Arc<Self> {
        Arc::new(Self { state })
    }
}

#[async_trait::async_trait]
impl vti_common::host_session::Responder for BallotBoxResponder {
    fn name(&self) -> &str {
        "ballot-box"
    }

    fn did(&self) -> &str {
        &self.state.identity.did
    }

    async fn answer(&self, sender: &str, document: &[u8]) -> Option<Value> {
        dispatch::answer(&self.state, document, Some(sender))
            .await
            .doc
    }
}
