//! Building and signing `vtn/*` Trust Task requests, with or without the HTTP client.

use chrono::Utc;
use serde_json::Value;
use trust_tasks_rs::{Payload, TrustTask};

use crate::error::{Result, VtnError};
use crate::identity::Party;
use crate::verify::AUTHENTICATION;

/// An unsigned request from `issuer` to `network_did` carrying `payload`: a fresh
/// `urn:uuid:` id and `issuedAt` now (a network accepts it for ten minutes, A20).
pub fn request_document<P: Payload>(
    issuer: Option<&str>,
    network_did: &str,
    payload: &P,
) -> Result<Value> {
    let type_uri = P::TYPE_URI
        .parse()
        .map_err(|e| VtnError::Internal(format!("{}: {e}", P::TYPE_URI)))?;
    let payload = serde_json::to_value(payload)?;
    let mut doc: TrustTask<Value> = TrustTask::new(
        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        type_uri,
        payload,
    );
    doc.issuer = issuer.map(str::to_string);
    doc.recipient = Some(network_did.to_string());
    doc.issued_at = Some(Utc::now());
    Ok(serde_json::to_value(&doc)?)
}

/// `payload` as a request signed by `who` for `network_did`, for `authentication`.
pub async fn sign_request<P: Payload>(
    who: &dyn Party,
    network_did: &str,
    payload: &P,
) -> Result<Value> {
    let doc = request_document(Some(who.did()), network_did, payload)?;
    who.sign_for(doc, AUTHENTICATION).await
}
