//! Connecting to a community over the transport its DID document advertises.
//!
//! The workspace rule is TSP, then DIDComm, then HTTPS, and **the DID document
//! is authoritative for which a party speaks**: both sides' capability is read
//! from the advertised services, matched on service `type`, never on the `#id`
//! fragment and never on endpoint shape. [`VtcClient::connect_resolved`] is
//! that rule for a community:
//!
//! - `TSPTransport` advertised → a TSP session (the TSP leg of the one
//!   mediator socket, for an identity that holds a secrets bundle).
//! - Else `DIDCommMessaging` advertised → a DIDComm session.
//! - Else → signed documents posted to the `VTCRest` endpoint, when one is
//!   advertised (or given).
//!
//! A session that was advertised but could not be opened is an error, not a
//! downgrade: the community said it speaks TSP or DIDComm, so answering it
//! over HTTPS instead would be the bridge deciding the community's transport.
//! `TransportChoice::Rest` is the operator's explicit way to do that for a
//! diagnosis, and it says so in the error that recommends it.

use vta_sdk::did_secrets::DidSecretsBundle;
use vta_sdk::keys::KeyType;
#[cfg(feature = "didcomm")]
use vta_sdk::session::{TransportChoice, VtaEndpoint};

#[cfg(feature = "didcomm")]
use crate::VtcClient;
use crate::{HolderKey, VtcError};

/// The identity a session client speaks as.
#[non_exhaustive]
pub enum SessionIdentity {
    /// An Ed25519 `did:key`, with its private key (multibase).
    DidKey {
        /// The DID.
        did: String,
        /// The Ed25519 private key, multibase-encoded.
        private_key_multibase: String,
    },
    /// A `did:webvh` (or other hosted DID) secrets bundle — what a persona
    /// minted by a VTA has: `#key-0` signs, `#key-1` decrypts.
    Bundle(DidSecretsBundle),
}

/// Written by hand so the private key never reaches a log: a derived `Debug`
/// would print it.
impl std::fmt::Debug for SessionIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DidKey { did, .. } => f
                .debug_struct("DidKey")
                .field("did", did)
                .field("private_key_multibase", &"<redacted>")
                .finish(),
            Self::Bundle(bundle) => f
                .debug_struct("Bundle")
                .field("did", &bundle.did)
                .field("secrets", &bundle.secrets.len())
                .finish(),
        }
    }
}

impl SessionIdentity {
    /// The DID this identity speaks as.
    pub fn did(&self) -> &str {
        match self {
            Self::DidKey { did, .. } => did,
            Self::Bundle(bundle) => &bundle.did,
        }
    }

    /// The key that signs a document posted over HTTPS: the `did:key` itself,
    /// or the bundle's Ed25519 verification method (`#key-0` by preference).
    #[cfg_attr(not(feature = "didcomm"), allow(dead_code))]
    fn holder_key(&self) -> Result<HolderKey, VtcError> {
        let signing =
            |e: vta_sdk::trust_task_sign::TrustTaskSignError| VtcError::Signing(e.to_string());
        match self {
            Self::DidKey {
                did,
                private_key_multibase,
            } => HolderKey::from_did_key(did, private_key_multibase.clone()).map_err(signing),
            Self::Bundle(bundle) => {
                let ed25519 = bundle
                    .secrets
                    .iter()
                    .filter(|s| matches!(s.key_type, KeyType::Ed25519))
                    .collect::<Vec<_>>();
                let entry = ed25519
                    .iter()
                    .find(|s| s.key_id.ends_with("#key-0"))
                    .or_else(|| ed25519.first())
                    .ok_or_else(|| {
                        VtcError::Signing(format!(
                            "the secrets bundle for {} holds no Ed25519 key to sign with",
                            bundle.did
                        ))
                    })?;
                HolderKey::new(entry.key_id.clone(), entry.private_key_multibase.clone())
                    .map_err(signing)
            }
        }
    }
}

/// What a community's DID document advertises, by service type.
#[cfg(feature = "didcomm")]
#[derive(Debug, Default)]
struct Advertised {
    /// The mediator behind `TSPTransport`.
    tsp_mediator: Option<String>,
    /// The mediator behind `DIDCommMessaging`.
    didcomm_mediator: Option<String>,
    /// The `VTCRest` API base.
    rest: Option<String>,
}

#[cfg(feature = "didcomm")]
impl Advertised {
    fn names(&self) -> String {
        let mut have = Vec::new();
        if self.tsp_mediator.is_some() {
            have.push("TSP");
        }
        if self.didcomm_mediator.is_some() {
            have.push("DIDComm");
        }
        if self.rest.is_some() {
            have.push("HTTPS");
        }
        if have.is_empty() {
            "nothing".to_string()
        } else {
            have.join(", ")
        }
    }
}

/// Read the community's advertised transports, matched on service type.
#[cfg(feature = "didcomm")]
async fn advertised_by(vtc_did: &str) -> Result<Advertised, VtcError> {
    let resolve = |e: String| VtcError::NoTransport {
        vtc_did: vtc_did.to_string(),
        detail: format!("could not resolve the community's DID: {e}"),
    };
    let mut out = Advertised::default();
    // The messaging transports, through the SDK's one implementation of
    // "which protocols does this party speak".
    match vta_sdk::session::resolve_vta_endpoint(vtc_did)
        .await
        .map_err(|e| resolve(e.to_string()))?
    {
        VtaEndpoint::Tsp {
            mediator_did,
            didcomm_mediator_did,
            ..
        } => {
            out.tsp_mediator = Some(mediator_did);
            out.didcomm_mediator = didcomm_mediator_did;
        }
        VtaEndpoint::DIDComm { mediator_did, .. } => out.didcomm_mediator = Some(mediator_did),
        _ => {}
    }
    // The community's REST door is `VTCRest`, not the VTA's `VTARest` the
    // SDK read above, so it is read from the document itself.
    let resolver = vta_sdk::resolver::shared_did_resolver_from_env()
        .await
        .map_err(|e| resolve(e.to_string()))?;
    let resolved = resolver
        .resolve(vtc_did)
        .await
        .map_err(|e| resolve(e.to_string()))?;
    let doc = serde_json::to_value(&resolved.doc).map_err(|e| resolve(e.to_string()))?;
    out.rest = crate::api_base_from_did_document(&doc);
    Ok(out)
}

#[cfg(feature = "didcomm")]
impl VtcClient {
    /// Connect to the community `vtc_did` as `identity`, over the transport
    /// its DID document advertises: TSP, else DIDComm, else signed documents
    /// over HTTPS — or the one `choice` pins.
    ///
    /// `rest_url` overrides the advertised `VTCRest` base; without either,
    /// HTTPS is not available. A session client holds a live mediator socket:
    /// close it with [`VtcClient::shutdown`].
    ///
    /// # Errors
    ///
    /// [`VtcError::NoTransport`] when the community advertises no transport
    /// `choice` permits, or advertises one that could not be opened — a
    /// session the community advertises is never silently replaced by HTTPS.
    /// [`VtcError::Signing`] when `identity` holds no usable signing key.
    pub async fn connect_resolved(
        identity: SessionIdentity,
        vtc_did: &str,
        rest_url: Option<&str>,
        choice: TransportChoice,
    ) -> Result<Self, VtcError> {
        let no_transport = |detail: String| VtcError::NoTransport {
            vtc_did: vtc_did.to_string(),
            detail,
        };
        let advertised = advertised_by(vtc_did).await?;
        let rest = rest_url
            .map(|u| u.trim_end_matches('/').to_string())
            .or_else(|| advertised.rest.clone());
        let signer = identity.holder_key()?;
        let https = |rest: &Option<String>| -> Result<Self, VtcError> {
            let base = rest.as_deref().ok_or_else(|| {
                no_transport(
                    "the community advertises no `VTCRest` endpoint and none was given, so \
                     there is no HTTPS door to post signed documents to"
                        .into(),
                )
            })?;
            Ok(Self::with_key(base, vtc_did, signer.clone()))
        };

        let try_tsp = matches!(choice, TransportChoice::Auto | TransportChoice::Tsp);
        let try_didcomm = matches!(choice, TransportChoice::Auto | TransportChoice::Didcomm);
        if choice == TransportChoice::Rest {
            return https(&rest);
        }

        let mut failed: Vec<String> = Vec::new();
        if try_tsp && let Some(tsp) = &advertised.tsp_mediator {
            match Self::session_tsp(
                &signer,
                &identity,
                vtc_did,
                tsp,
                advertised.didcomm_mediator.as_deref(),
                rest.as_deref(),
            )
            .await
            {
                Ok(client) => return Ok(client),
                Err(e) => failed.push(format!("TSP via {tsp}: {e}")),
            }
        }
        if try_didcomm && let Some(didcomm) = &advertised.didcomm_mediator {
            match Self::session_didcomm(&signer, &identity, vtc_did, didcomm, rest.as_deref()).await
            {
                Ok(client) => return Ok(client),
                Err(e) => failed.push(format!("DIDComm via {didcomm}: {e}")),
            }
        }

        let wanted = match choice {
            TransportChoice::Tsp => "TSP",
            TransportChoice::Didcomm => "DIDComm",
            _ => "TSP or DIDComm",
        };
        if !failed.is_empty() {
            return Err(no_transport(format!(
                "the community advertises {wanted} but no session could be opened ({}). Signed \
                 documents over HTTPS are not substituted for a transport the community \
                 advertises; pass transport = rest to do that for a diagnosis",
                failed.join("; ")
            )));
        }
        match choice {
            TransportChoice::Auto => https(&rest),
            pinned => Err(no_transport(format!(
                "the community advertises {} and {} is pinned",
                advertised.names(),
                match pinned {
                    TransportChoice::Tsp => "TSP",
                    _ => "DIDComm",
                }
            ))),
        }
    }

    /// A TSP session as `identity`. A `did:key` gets a TSP-only client; a
    /// bundle gets a DIDComm session with the TSP leg, on the DIDComm
    /// mediator where the community names one and on the TSP mediator
    /// otherwise — either way one mediator socket per DID.
    async fn session_tsp(
        signer: &HolderKey,
        identity: &SessionIdentity,
        vtc_did: &str,
        tsp_mediator: &str,
        didcomm_mediator: Option<&str>,
        rest: Option<&str>,
    ) -> Result<Self, VtcError> {
        #[cfg(not(feature = "tsp"))]
        {
            let _ = (
                signer,
                identity,
                vtc_did,
                tsp_mediator,
                didcomm_mediator,
                rest,
            );
            Err(VtcError::Unsupported(
                "this build has no TSP transport (feature `tsp`)",
            ))
        }
        #[cfg(feature = "tsp")]
        {
            let session = |e: vta_sdk::error::VtaError| VtcError::Session(e.to_string());
            match identity {
                SessionIdentity::DidKey {
                    did,
                    private_key_multibase,
                } => {
                    Self::connect_tsp(did, private_key_multibase, vtc_did, tsp_mediator, rest).await
                }
                SessionIdentity::Bundle(bundle) => {
                    let mediator = didcomm_mediator.unwrap_or(tsp_mediator);
                    let mut documents = vta_sdk::client::VtaClient::connect_didcomm_bundle(
                        bundle,
                        vtc_did,
                        mediator,
                        rest.map(str::to_string),
                    )
                    .await
                    .map_err(session)?;
                    if let Err(e) = documents.enable_tsp_trust_tasks(tsp_mediator) {
                        documents.shutdown().await;
                        return Err(session(e));
                    }
                    Ok(Self::over_session(
                        documents,
                        &bundle.did,
                        vtc_did,
                        rest,
                        Some(signer.clone()),
                    ))
                }
            }
        }
    }

    /// A DIDComm session as `identity`.
    async fn session_didcomm(
        signer: &HolderKey,
        identity: &SessionIdentity,
        vtc_did: &str,
        mediator: &str,
        rest: Option<&str>,
    ) -> Result<Self, VtcError> {
        match identity {
            SessionIdentity::DidKey {
                did,
                private_key_multibase,
            } => Self::connect_didcomm(did, private_key_multibase, vtc_did, mediator, rest).await,
            SessionIdentity::Bundle(bundle) => {
                let documents = vta_sdk::client::VtaClient::connect_didcomm_bundle(
                    bundle,
                    vtc_did,
                    mediator,
                    rest.map(str::to_string),
                )
                .await
                .map_err(|e| VtcError::Session(e.to_string()))?;
                Ok(Self::over_session(
                    documents,
                    &bundle.did,
                    vtc_did,
                    rest,
                    Some(signer.clone()),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_did_key_identity_signs_as_itself() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let did = format!(
            "did:key:{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&signing.verifying_key().to_bytes())
        );
        let identity = SessionIdentity::DidKey {
            did: did.clone(),
            private_key_multibase: multibase::encode(
                multibase::Base::Base58Btc,
                signing.to_bytes(),
            ),
        };
        assert_eq!(identity.did(), did);
        let key = identity.holder_key().unwrap();
        assert!(key.verification_method().starts_with(&did));
    }

    #[test]
    fn a_bundle_signs_with_its_key_0_and_refuses_without_an_ed25519_key() {
        use vta_sdk::did_secrets::SecretEntry;
        let did = "did:webvh:abc:example.com:agent";
        let entry = |key_id: &str, key_type: KeyType| SecretEntry {
            key_id: key_id.to_string(),
            key_type,
            private_key_multibase: "z3u2placeholder".to_string(),
        };
        let bundle = DidSecretsBundle {
            did: did.to_string(),
            secrets: vec![
                entry(&format!("{did}#key-1"), KeyType::X25519),
                entry(&format!("{did}#key-0"), KeyType::Ed25519),
            ],
        };
        let key = SessionIdentity::Bundle(bundle).holder_key().unwrap();
        assert_eq!(key.verification_method(), format!("{did}#key-0"));

        let only_x = DidSecretsBundle {
            did: did.to_string(),
            secrets: vec![entry(&format!("{did}#key-1"), KeyType::X25519)],
        };
        assert!(matches!(
            SessionIdentity::Bundle(only_x).holder_key(),
            Err(VtcError::Signing(_))
        ));
    }

    #[cfg(feature = "didcomm")]
    #[test]
    fn advertised_names_what_it_holds() {
        assert_eq!(Advertised::default().names(), "nothing");
        let both = Advertised {
            tsp_mediator: Some("did:key:zTsp".into()),
            didcomm_mediator: None,
            rest: Some("https://vtc.example.com/v1".into()),
        };
        assert_eq!(both.names(), "TSP, HTTPS");
    }
}
