//! Reaching the community itself — the VTC — rather than the community's VTA.
//!
//! `cnm vetting`, `cnm audit`, `cnm backup` and `cnm did-log` are community
//! administration: they drive routes the VTC serves, not the VTA. They
//! authenticate *to the VTC* as this community profile's own identity, with
//! **the VTC's DID as the audience**.
//!
//! That last part is the whole reason this module exists. The profile's stored
//! session (`vta_sdk::session::SessionStore`) is bound to the community *VTA*:
//! its challenge-response addresses the VTA's DID (the DIDComm authenticate
//! envelope is encrypted to it) and its token cache and key rotation are the
//! VTA's. Pointed at a VTC, it produced an envelope the VTC cannot open, so every
//! one of these commands failed to authenticate. The audience is therefore
//! explicit here: a [`VtcTarget`] always names the VTC's DID, and nothing in
//! this module can fall back to the VTA's.

use vta_cli_common::render::bin_name;
use vtc_client::{VtcClient, VtcError};

use crate::auth;

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The community to authenticate to: its DID (the audience) and its REST API
/// base, including the mount (`https://vtc.example.com/v1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtcTarget {
    pub did: String,
    pub base: String,
}

/// Name the VTC from what the operator supplied.
///
/// The DID comes from the operator — `--vtc-did`, else the community profile's
/// `vtc_did` — and never from the server. The DID is the audience the
/// authenticate document is signed for; if it were read from whatever answers
/// at the URL, that server could name another community's DID and relay the
/// signed document there. So the direction is DID to URL, as it is for the VTA:
/// `--url` when given, otherwise the `VTCRest` endpoint the DID's own document
/// advertises.
pub async fn resolve_target(vtc_did: Option<&str>, url: Option<&str>) -> CliResult<VtcTarget> {
    let did = vtc_did
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .ok_or_else(|| missing_vtc_did_message(bin_name()))?;
    if !did.starts_with("did:") {
        return Err(format!("`{did}` is not a DID; the VTC's DID starts with `did:`").into());
    }
    let base = match url {
        Some(u) => u.trim_end_matches('/').to_string(),
        None => advertised_api_base(did).await?,
    };
    Ok(VtcTarget {
        did: did.to_string(),
        base,
    })
}

/// The operator-facing message when no VTC DID is configured.
fn missing_vtc_did_message(bin: &str) -> String {
    format!(
        "this command talks to the community's VTC, and this community profile does not \
         name it.\nRecord the VTC's DID once:\n  {bin} community set-vtc <vtc-did>\nor pass \
         it for one command:\n  {bin} --vtc-did <vtc-did> …\nThe DID is the one `vtc setup` \
         printed for the community (`VTC DID`)."
    )
}

/// The `VTCRest` API base the DID's own document advertises.
async fn advertised_api_base(did: &str) -> CliResult<String> {
    let fix = |why: String| -> Box<dyn std::error::Error> {
        format!(
            "{why}\nPass the VTC's API base before the subcommand instead:\n  {bin} --url \
             https://<vtc-host>/v1 …",
            bin = bin_name()
        )
        .into()
    };
    let resolver = vta_sdk::resolver::shared_did_resolver_from_env()
        .await
        .map_err(|e| fix(format!("could not start the DID resolver: {e}")))?;
    let resolved = resolver
        .resolve(did)
        .await
        .map_err(|e| fix(format!("could not resolve the VTC's DID {did}: {e}")))?;
    let doc = serde_json::to_value(&resolved.doc)
        .map_err(|e| fix(format!("could not read {did}'s DID document: {e}")))?;
    let base = vtc_client::api_base_from_did_document(&doc).ok_or_else(|| {
        fix(format!(
            "{did}'s DID document advertises no `{}` service, so it names no API to call.",
            vtc_client::REST_SERVICE_TYPE
        ))
    })?;
    // Same endpoint policy as a VTA's advertised REST URL: public HTTPS (or
    // loopback), unless the operator opted in with --allow-private-endpoints.
    vta_sdk::http::guard_vta_endpoint(&base, vta_sdk::http::EndpointPolicy::process_default())
        .map_err(|e| format!("refusing the REST endpoint {did} advertises: {e}"))?;
    Ok(base)
}

/// An authenticated VTC client and the DID it authenticated as — the DID an
/// error names when the VTC then refuses a call.
#[derive(Debug)]
pub struct Connected {
    pub client: VtcClient,
    pub client_did: String,
}

/// Authenticate to `target` as this community profile's stored identity.
///
/// The identity is the profile's DID and key; the session's VTA binding and
/// token cache are not used, because they belong to the VTA.
pub async fn connect(keyring_key: &str, target: &VtcTarget) -> CliResult<Connected> {
    let session = auth::loaded_session(keyring_key).ok_or_else(|| {
        format!(
            "no stored identity for this community profile. Run `{} setup` first.",
            bin_name()
        )
    })?;
    connect_as(target, &session.client_did, &session.private_key_multibase).await
}

/// [`connect`] for an identity in hand.
async fn connect_as(
    target: &VtcTarget,
    client_did: &str,
    private_key_multibase: &str,
) -> CliResult<Connected> {
    let client = VtcClient::connect(&target.base, &target.did, client_did, private_key_multibase)
        .await
        .map_err(|e| authentication_guidance(&e, target, client_did, bin_name()))?;
    Ok(Connected {
        client,
        client_did: client_did.to_string(),
    })
}

/// Connect to `target` over a channel confidential end-to-end — TSP when the
/// VTC advertises it, else DIDComm — as this community profile's identity.
///
/// For the verbs the VTC serves only end to end (a community backup, whose
/// password and bundle would otherwise exist in plaintext wherever TLS
/// terminates). There is no REST fallback: a VTC that advertises neither
/// transport cannot be backed up from here, and the error says so.
pub async fn connect_end_to_end(keyring_key: &str, target: &VtcTarget) -> CliResult<Connected> {
    use vta_sdk::session::VtaEndpoint;
    let session = auth::loaded_session(keyring_key).ok_or_else(|| {
        format!(
            "no stored identity for this community profile. Run `{} setup` first.",
            bin_name()
        )
    })?;
    let (did, key) = (&session.client_did, &session.private_key_multibase);
    let endpoint = vta_sdk::session::resolve_vta_endpoint(&target.did)
        .await
        .map_err(|e| format!("could not resolve the VTC's DID {}: {e}", target.did))?;
    let session_error = |e: VtcError| -> Box<dyn std::error::Error> {
        format!("could not open a session to the VTC {}: {e}", target.did).into()
    };
    let client = match endpoint {
        VtaEndpoint::Tsp {
            mediator_did,
            didcomm_mediator_did,
            ..
        } => match VtcClient::connect_tsp(did, key, &target.did, &mediator_did, Some(&target.base))
            .await
        {
            Ok(c) => c,
            Err(e) => {
                let Some(m) = didcomm_mediator_did else {
                    return Err(session_error(e));
                };
                eprintln!("warning: TSP to the VTC failed ({e}); using DIDComm via {m}");
                VtcClient::connect_didcomm(did, key, &target.did, &m, Some(&target.base))
                    .await
                    .map_err(session_error)?
            }
        },
        VtaEndpoint::DIDComm { mediator_did, .. } => {
            VtcClient::connect_didcomm(did, key, &target.did, &mediator_did, Some(&target.base))
                .await
                .map_err(session_error)?
        }
        _ => {
            return Err(format!(
                "{} advertises no DIDComm or TSP service. A community backup moves only over \
                 a channel confidential end-to-end, and the VTC refuses it over REST.",
                target.did
            )
            .into());
        }
    };
    Ok(Connected {
        client,
        client_did: did.to_string(),
    })
}

/// What to tell the operator when the VTC does not accept the profile's DID.
///
/// A VTC answers every authentication failure the same way, whether or not the
/// DID is enrolled (VTI-SES-007), so a refusal here cannot say which it was.
/// The usual cause is the missing ACL row, and that is the fix printed.
pub fn authentication_guidance(
    err: &VtcError,
    target: &VtcTarget,
    client_did: &str,
    bin: &str,
) -> String {
    let refused = matches!(
        err,
        VtcError::Auth(e) if e.is_auth()
    ) || matches!(
        err,
        VtcError::Http {
            status: 401 | 403,
            ..
        }
    );
    if refused {
        format!(
            "the community at {base} ({vtc}) did not accept {client_did}.\n\n`{bin}` \
             authenticates to the VTC as this community profile's own DID, which needs a \
             super-admin entry in the VTC's ACL. On the VTC host, with the daemon stopped:\n  \
             vtc --config <config.toml> acl add --did {client_did} --role admin --label {bin}\n\
             or, in the admin console, Access control → Add entry: that DID, role admin, no \
             contexts.\n\n({err})",
            base = target.base,
            vtc = target.did,
        )
    } else {
        format!(
            "could not authenticate to the community at {base} ({vtc}) as {client_did}: {err}\n\
             Check the VTC is up and that {vtc} is its DID.",
            base = target.base,
            vtc = target.did,
        )
    }
}

/// An operator error for a failed super-admin call (`what` names it) on an
/// authenticated client.
///
/// The VTC's error body is kept verbatim: it carries the actionable part (a
/// short password, a backup for another community). A 403 here means the DID
/// authenticated but is not a *super*-admin — an admin scoped to contexts —
/// and gets the same ACL fix as a refusal at sign-in.
pub fn super_admin_call_error(what: &str, err: VtcError, client_did: &str, bin: &str) -> String {
    match err {
        VtcError::Http { status: 403, body } => format!(
            "{what} needs a super-admin, and the VTC refused {client_did} (403): {body}\n\
             Give that DID an unscoped admin entry. On the VTC host, with the daemon stopped:\n  \
             vtc --config <config.toml> acl add --did {client_did} --role admin --label {bin}"
        ),
        VtcError::Http { status: 429, body } => format!(
            "the VTC rate-limited {what} (429): {body}\nWait a moment and re-run it; retrying \
             at once only extends the wait."
        ),
        VtcError::Http { status, body } => format!("{what} failed ({status}): {body}"),
        other => format!("{what} failed: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> VtcTarget {
        VtcTarget {
            did: "did:webvh:Qm:vtc.example.com".into(),
            base: "https://vtc.example.com/v1".into(),
        }
    }

    #[tokio::test]
    async fn no_vtc_did_names_both_ways_to_supply_one() {
        let err = resolve_target(None, Some("https://vtc.example.com/v1"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("community set-vtc <vtc-did>"), "{err}");
        assert!(err.contains("--vtc-did <vtc-did>"), "{err}");
    }

    #[tokio::test]
    async fn an_explicit_url_is_used_as_given_with_the_operators_did() {
        let t = resolve_target(
            Some("did:webvh:Qm:vtc.example.com"),
            Some("https://vtc.example.com/v1/"),
        )
        .await
        .unwrap();
        assert_eq!(t, target());
        assert!(
            resolve_target(Some("vtc.example.com"), Some("https://x/v1"))
                .await
                .is_err()
        );
    }

    /// The authenticate document `cnm` sends a VTC is addressed to the VTC's
    /// DID — not the VTA's, which is what the profile's session would have
    /// used — and a refusal of it prints the ACL fix.
    #[tokio::test]
    async fn the_authenticate_document_is_addressed_to_the_vtc_did() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/auth/challenge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "challenge": "c2VjcmV0LWNoYWxsZW5nZQ",
                "sessionId": "s-1",
                "expiresAt": "2099-01-01T00:00:00Z",
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/auth/"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .mount(&server)
            .await;

        let seed = [0x42u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let did = format!(
            "did:key:{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
        );
        let mut buf = vec![0x80, 0x26];
        buf.extend_from_slice(&seed);
        let key = multibase::encode(multibase::Base::Base58Btc, &buf);

        let target = VtcTarget {
            did: "did:webvh:QmVtc:vtc.example.com".into(),
            base: format!("{}/v1", server.uri()),
        };
        let err = connect_as(&target, &did, &key)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(&format!("acl add --did {did} --role admin")),
            "{err}"
        );

        let requests = server.received_requests().await.unwrap();
        let auth = requests
            .iter()
            .find(|r| r.url.path() == "/v1/auth/")
            .expect("an authenticate request was sent");
        let doc: serde_json::Value = serde_json::from_slice(&auth.body).unwrap();
        assert_eq!(doc["recipient"], "did:webvh:QmVtc:vtc.example.com");
        assert_eq!(doc["issuer"], did.as_str());
        assert!(doc["proof"].is_object(), "the document is signed: {doc}");
    }

    /// The refusal a VTC gives a DID with no ACL row prints the `vtc acl add`
    /// that fixes it, with the DID filled in.
    #[test]
    fn a_refusal_prints_the_acl_command_for_the_profiles_did() {
        for err in [
            VtcError::Auth(vta_sdk::error::VtaError::Forbidden("nope".into())),
            VtcError::Auth(vta_sdk::error::VtaError::Auth("nope".into())),
            VtcError::Http {
                status: 403,
                body: String::new(),
            },
        ] {
            let msg = authentication_guidance(&err, &target(), "did:key:z6MkOp", "cnm");
            assert!(
                msg.contains(
                    "vtc --config <config.toml> acl add --did did:key:z6MkOp --role admin"
                ),
                "{msg}"
            );
        }
        let other = authentication_guidance(
            &VtcError::Url("bad".into()),
            &target(),
            "did:key:z6MkOp",
            "cnm",
        );
        assert!(!other.contains("acl add"), "{other}");
    }
}
