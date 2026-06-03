//! `credential-exchange/*` Trust Task family — Phase 3 (spec §6).
//!
//! The **Trust Task is the transport / auth / threading / relayer envelope**;
//! the **body is OID4VCI** (issuance) or **OID4VP + DCQL** (presentation). This
//! module is the *message-type layer* both sides build on: the versioned URIs +
//! the request/response body shapes. Handlers (issuer/verifier on the VTC,
//! holder on the VTA) land in later Phase 3 slices.
//!
//! ```text
//! Issuance (OID4VCI):
//!   issuer → holder    credential-exchange/offer/1.0     { credential_offer }
//!   holder → issuer    credential-exchange/request/1.0   { credential_request }   (key-binding proof)
//!   issuer → holder    credential-exchange/issue/1.0     { credential_response | sealed }
//!
//! Presentation (OID4VP + DCQL):
//!   verifier → holder  credential-exchange/query/1.0     { dcql_query, nonce, purpose }
//!   holder → verifier  credential-exchange/present/1.0   { vp_token }
//! ```
//!
//! **Format-agnostic** (spec D4): the issued `credential` and the `vp_token`
//! carry whichever credential format — SD-JWT-VC, W3C Data-Integrity, or BBS+ —
//! the DCQL `format` selector negotiated. Nothing here is format-specific.
//!
//! `purpose` on a [`QueryBody`] is **mandatory** and shown to the holder
//! (purpose binding): a verifier cannot ask for a credential without stating
//! why.

use affinidi_openid4vci::{CredentialOffer, CredentialRequest, CredentialResponse};
use affinidi_openid4vp::DcqlQuery;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Canonical Trust Task URIs (trusttasks.org/spec form) ──

/// issuer → holder: a credential offer.
pub const OFFER: &str = "https://trusttasks.org/spec/credential-exchange/offer/1.0";
/// holder → issuer: a credential request.
pub const REQUEST: &str = "https://trusttasks.org/spec/credential-exchange/request/1.0";
/// issuer → holder: the issued credential.
pub const ISSUE: &str = "https://trusttasks.org/spec/credential-exchange/issue/1.0";
/// verifier → holder: a DCQL query.
pub const QUERY: &str = "https://trusttasks.org/spec/credential-exchange/query/1.0";
/// holder → verifier: a presentation.
pub const PRESENT: &str = "https://trusttasks.org/spec/credential-exchange/present/1.0";

/// `offer/1.0` — issuer → holder. An OID4VCI credential offer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferBody {
    pub credential_offer: CredentialOffer,
}

/// `request/1.0` — holder → issuer. An OID4VCI credential request carrying the
/// holder's key-binding proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestBody {
    pub credential_request: CredentialRequest,
}

/// `issue/1.0` — issuer → holder. Exactly one of:
///
/// - `credential_response` — the cleartext OID4VCI response (the issued
///   credential), for a known holder over an authenticated channel; or
/// - `sealed` — an armored [`crate::sealed_transfer`] bundle, when the
///   credential is secret-bearing or issued to an **unknown holder** (the
///   invite / air-gap case): only the holder can open it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_response: Option<CredentialResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<String>,
}

/// `query/1.0` — verifier → holder. A DCQL query + freshness nonce + a
/// **mandatory** `purpose` shown to the holder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryBody {
    pub dcql_query: DcqlQuery,
    pub nonce: String,
    /// The verifier's stated reason for the request — shown to the holder
    /// (purpose binding). Never optional.
    pub purpose: String,
}

/// `present/1.0` — holder → verifier. The OID4VP `vp_token` carrying the
/// selectively-disclosed, holder-bound presentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentBody {
    pub vp_token: Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn query_body_round_trips_with_a_dcql_query() {
        let dcql = DcqlQuery::from_json(&json!({
            "credentials": [{
                "id": "membership",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://openvtc.org/credentials/MembershipCredential"] }
            }]
        }))
        .unwrap();
        let body = QueryBody {
            dcql_query: dcql,
            nonce: "n-123".into(),
            purpose: "join the Acme community".into(),
        };
        let wire = serde_json::to_string(&body).unwrap();
        let back: QueryBody = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.nonce, "n-123");
        assert_eq!(back.purpose, "join the Acme community");
        assert_eq!(back.dcql_query.credentials.len(), 1);
    }

    #[test]
    fn issue_body_carries_a_sealed_bundle() {
        let body = IssueBody {
            credential_response: None,
            sealed: Some("-----BEGIN VTA SEALED-----\n…\n-----END VTA SEALED-----".into()),
        };
        let wire = serde_json::to_value(&body).unwrap();
        assert!(wire.get("sealed").is_some());
        assert!(
            wire.get("credentialResponse").is_none() && wire.get("credential_response").is_none(),
            "absent cleartext response is omitted: {wire}"
        );
        let back: IssueBody = serde_json::from_value(wire).unwrap();
        assert!(back.sealed.is_some() && back.credential_response.is_none());
    }

    #[test]
    fn present_body_round_trips() {
        let body = PresentBody {
            vp_token: json!("<jws>~<disclosure>~<kb-jwt>"),
        };
        let back: PresentBody =
            serde_json::from_str(&serde_json::to_string(&body).unwrap()).unwrap();
        assert_eq!(back.vp_token, json!("<jws>~<disclosure>~<kb-jwt>"));
    }

    #[test]
    fn uris_are_versioned_and_distinct() {
        let all = [OFFER, REQUEST, ISSUE, QUERY, PRESENT];
        for u in all {
            assert!(u.starts_with("https://trusttasks.org/spec/credential-exchange/"));
            assert!(u.ends_with("/1.0"));
        }
        // all distinct
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
