//! Sign-in links: how a browser page hands a VTN sign-in to a wallet (A13).
//!
//! ```text
//! vtn-signin:?network=<network DID>&endpoint=<VTN base URL>&challenge=<challenge>
//! ```
//!
//! The wallet signs `{ type: "VtnAdminAuthentication", did, challenge, audience: network }`
//! for `authentication` and posts it to `<endpoint>/v1/auth/session`. The page that showed
//! the link collects the session with the poll secret only it holds.

use crate::identity::Identity;
use crate::verify::AUTHENTICATION;
use serde_json::{Value, json};

use crate::client::{ClientError, VtnClient, encode_query};

pub const SCHEME: &str = "vtn-signin:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInLink {
    pub network: String,
    pub endpoint: String,
    pub challenge: String,
}

fn decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

impl SignInLink {
    pub fn to_uri(&self) -> String {
        format!(
            "{SCHEME}?network={}&endpoint={}&challenge={}",
            encode_query(&self.network),
            encode_query(&self.endpoint),
            encode_query(&self.challenge)
        )
    }

    pub fn parse(uri: &str) -> Result<Self, ClientError> {
        let bad = |why: &str| ClientError::Unexpected(format!("not a sign-in link: {why}"));
        let query = uri
            .strip_prefix(SCHEME)
            .ok_or_else(|| bad("wrong scheme"))?
            .trim_start_matches("//")
            .trim_start_matches('?');
        let mut network = None;
        let mut endpoint = None;
        let mut challenge = None;
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=').ok_or_else(|| bad("malformed query"))?;
            let v = decode(v).ok_or_else(|| bad("bad encoding"))?;
            match k {
                "network" => network = Some(v),
                "endpoint" => endpoint = Some(v),
                "challenge" => challenge = Some(v),
                _ => {}
            }
        }
        let link = Self {
            network: network.ok_or_else(|| bad("no network"))?,
            endpoint: endpoint.ok_or_else(|| bad("no endpoint"))?,
            challenge: challenge.ok_or_else(|| bad("no challenge"))?,
        };
        if !link.network.starts_with("did:") {
            return Err(bad("network is not a DID"));
        }
        if !(link.endpoint.starts_with("https://") || link.endpoint.starts_with("http://")) {
            return Err(bad("endpoint is not an http(s) URL"));
        }
        Ok(link)
    }

    /// Sign the link's challenge as `who` (optionally presenting a membership credential),
    /// and post it. Before signing, checks that the endpoint answers as the link's network,
    /// so a link cannot send a signature to a network other than the one it names.
    pub async fn complete(
        &self,
        who: &Identity,
        membership: Option<Value>,
    ) -> Result<Value, ClientError> {
        let client = VtnClient::new(&self.endpoint);
        let answering = client.network_did().await?;
        if answering != self.network {
            return Err(ClientError::Unexpected(format!(
                "{} answers as {answering}, not {}",
                self.endpoint, self.network
            )));
        }
        let document = who
            .sign_document_for(
                json!({
                    "type": "VtnAdminAuthentication",
                    "did": who.did(),
                    "challenge": self.challenge,
                    "audience": self.network,
                }),
                AUTHENTICATION,
            )
            .await
            .map_err(|e| ClientError::Unexpected(format!("sign the authentication: {e}")))?;
        let mut body = json!({ "authentication": document });
        if let Some(m) = membership {
            body["membership"] = m;
        }
        client.post("/v1/auth/session", &body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let link = SignInLink {
            network: "did:webvh:Qm1:whn.example.org".into(),
            endpoint: "https://whn.example.org".into(),
            challenge: "ab12".into(),
        };
        assert_eq!(SignInLink::parse(&link.to_uri()).unwrap(), link);
        assert!(SignInLink::parse("https://x").is_err());
        assert!(SignInLink::parse("vtn-signin:?network=x&endpoint=https://a&challenge=c").is_err());
    }
}
