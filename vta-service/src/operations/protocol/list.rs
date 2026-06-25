//! `list_services` operation — read-only.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §3.7
//! and §10 (resolved). Returns the operator-facing read view of
//! the VTA's currently-advertised transport services. One entry
//! per kind, in canonical order (DIDComm before REST when both
//! are advertised, matching spec §3.3).
//!
//! Source of truth: the on-chain DID document. `AppConfig.services`
//! is checked but the published `service[]` array drives the
//! returned URL / mediator DID — these can briefly disagree
//! around a mid-mutation crash, and the doc is what SDK consumers
//! actually resolve against.
//!
//! Unlike the mutation ops, `list_services` does NOT take
//! `PROTOCOL_LOCK` — it's a read-only query. A mutation in flight
//! may produce a transient view; that's fine for an inspect
//! operation.

use std::sync::Arc;

use thiserror::Error;
use tokio::sync::RwLock;

use vta_sdk::protocol::services::{ServiceState, ServicesListResponse};

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::operations::protocol::document::{
    current_didcomm_service, current_rest_service, current_tsp_service, current_webauthn_service,
};
use crate::store::KeyspaceHandle;
use crate::webvh_store;

#[derive(Debug, Error)]
pub enum ListServicesError {
    #[error("VTA DID is not configured — run `vta setup` first")]
    VtaDidNotConfigured,
    #[error("VTA DID `{0}` has no webvh record")]
    VtaDidRecordMissing(String),
    #[error("VTA DID `{0}` has no published log")]
    VtaDidLogMissing(String),
    #[error("VTA DID log is empty")]
    EmptyLog,
    #[error("auth: {0}")]
    Auth(String),
    #[error("storage error: {0}")]
    Storage(String),
}

impl From<AppError> for ListServicesError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

/// Read the VTA's current service-advertisement state.
///
/// Returns one [`ServiceState`] entry per transport kind. When a
/// kind is enabled, its kind-specific fields (REST `url` /
/// DIDComm `mediator_did`) are populated from the on-chain DID
/// document.
pub async fn list_services(
    config: &Arc<RwLock<AppConfig>>,
    webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
) -> Result<ServicesListResponse, ListServicesError> {
    auth.require_super_admin()
        .map_err(|e| ListServicesError::Auth(e.to_string()))?;

    let cfg_view = {
        let cfg = config.read().await;
        ConfigView {
            rest_enabled: cfg.services.rest,
            didcomm_enabled: cfg.services.didcomm,
            webauthn_enabled: cfg.services.webauthn,
            tsp_enabled: cfg.services.tsp,
            vta_did: cfg.vta_did.clone(),
            mediator_did: cfg
                .messaging
                .as_ref()
                .map(|m| m.mediator_did.clone())
                .filter(|did| !did.is_empty()),
            public_url: cfg.public_url.clone(),
        }
    };

    let vta_did = cfg_view
        .vta_did
        .ok_or(ListServicesError::VtaDidNotConfigured)?;

    // For non-webvh DIDs (e.g. did:key), there is no on-chain DID document
    // to inspect. Report service state from config only.
    if !vta_did.starts_with("did:webvh:") {
        // TSP uses the same mediator as DIDComm (D8 — one dual-protocol
        // mediator), so its endpoint mirrors the DIDComm `mediator_did`.
        let services = vec![
            ServiceState::Tsp {
                enabled: cfg_view.tsp_enabled && cfg_view.mediator_did.is_some(),
                mediator_did: cfg_view.mediator_did.clone(),
            },
            ServiceState::Didcomm {
                enabled: cfg_view.didcomm_enabled && cfg_view.mediator_did.is_some(),
                mediator_did: cfg_view.mediator_did,
                routing_keys: Vec::new(),
            },
            ServiceState::Rest {
                enabled: cfg_view.rest_enabled,
                url: cfg_view.public_url.clone(),
            },
            ServiceState::Webauthn {
                enabled: cfg_view.webauthn_enabled,
                url: None,
            },
        ];
        return Ok(ServicesListResponse { services });
    }

    let _record = webvh_store::get_did(webvh_ks, &vta_did)
        .await?
        .ok_or_else(|| ListServicesError::VtaDidRecordMissing(vta_did.clone()))?;
    let did_log = webvh_store::get_did_log(webvh_ks, &vta_did)
        .await?
        .ok_or_else(|| ListServicesError::VtaDidLogMissing(vta_did.clone()))?;
    let current_doc = crate::operations::protocol::document::current_document_from_log(&did_log)?;

    // Pull the kind-specific config from the on-chain doc — it's
    // the source of truth for what SDK consumers will resolve.
    let rest_url = current_rest_service(&current_doc).map(|s| s.url);
    let webauthn_url = current_webauthn_service(&current_doc).map(|s| s.url);
    let tsp_mediator = current_tsp_service(&current_doc).map(|s| s.mediator_did);
    let didcomm = current_didcomm_service(&current_doc);
    let (didcomm_mediator, didcomm_routing_keys) = match didcomm {
        Some(svc) => (Some(svc.mediator_did), svc.routing_keys),
        None => (None, Vec::new()),
    };

    // Canonical order: TSP first when present, then DIDComm, REST,
    // WebAuthn (spec §3.3). Empty kinds (disabled in both config and
    // the doc) still appear so the operator gets a uniform shape.
    let services = vec![
        ServiceState::Tsp {
            enabled: cfg_view.tsp_enabled && tsp_mediator.is_some(),
            mediator_did: tsp_mediator,
        },
        ServiceState::Didcomm {
            enabled: cfg_view.didcomm_enabled && didcomm_mediator.is_some(),
            mediator_did: didcomm_mediator,
            routing_keys: didcomm_routing_keys,
        },
        ServiceState::Rest {
            enabled: cfg_view.rest_enabled && rest_url.is_some(),
            url: rest_url,
        },
        ServiceState::Webauthn {
            enabled: cfg_view.webauthn_enabled && webauthn_url.is_some(),
            url: webauthn_url,
        },
    ];

    Ok(ServicesListResponse { services })
}

struct ConfigView {
    rest_enabled: bool,
    didcomm_enabled: bool,
    webauthn_enabled: bool,
    tsp_enabled: bool,
    vta_did: Option<String>,
    mediator_did: Option<String>,
    public_url: Option<String>,
}

impl From<crate::operations::protocol::document::CurrentDocumentError> for ListServicesError {
    fn from(value: crate::operations::protocol::document::CurrentDocumentError) -> Self {
        use crate::operations::protocol::document::CurrentDocumentError as E;
        match value {
            E::EmptyLog => Self::EmptyLog,
            E::Parse(s) => Self::Storage(s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use vti_common::config::StoreConfig as VtiStoreConfig;

    /// `list_services` rejects callers without super-admin role —
    /// drives the production code path with a non-super-admin
    /// `AuthClaims` and asserts the typed `Auth` error variant
    /// fires before any storage I/O.
    #[tokio::test]
    async fn rejects_non_super_admin() {
        use crate::test_support::test_app_config;
        use vti_common::acl::Role;

        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_app_config(dir.path().into());
        cfg.services.rest = true;
        cfg.services.didcomm = true;
        cfg.vta_did = Some("did:webvh:scid:host:vta".into());
        cfg.config_path = dir.path().join("vta.toml");
        let config = Arc::new(RwLock::new(cfg));
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let webvh_ks = store.keyspace(crate::keyspaces::WEBVH).unwrap();
        let context_admin = AuthClaims {
            did: "did:key:z6Mk-context-admin".into(),
            role: Role::Admin,
            allowed_contexts: vec!["vta".into()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };

        let err = list_services(&config, &webvh_ks, &context_admin)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ListServicesError::Auth(_)),
            "expected Auth rejection, got {err:?}"
        );
    }

    /// Exercises the precondition check: a config without a VTA
    /// DID returns the typed `VtaDidNotConfigured` variant.
    #[tokio::test]
    async fn rejects_when_vta_did_not_configured() {
        use crate::test_support::test_app_config;

        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_app_config(dir.path().into());
        cfg.services.rest = true;
        cfg.services.didcomm = true;
        cfg.vta_did = None;
        cfg.config_path = dir.path().join("vta.toml");
        let config = Arc::new(RwLock::new(cfg));
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let webvh_ks = store.keyspace(crate::keyspaces::WEBVH).unwrap();
        let super_admin = AuthClaims::unsafe_local_cli_super_admin("test");

        let err = list_services(&config, &webvh_ks, &super_admin)
            .await
            .unwrap_err();
        assert!(matches!(err, ListServicesError::VtaDidNotConfigured));
    }

    /// `list_services` succeeds for did:key VTAs (no webvh record)
    /// by returning service state from config only.
    #[tokio::test]
    async fn returns_config_state_for_did_key_vta() {
        use crate::test_support::test_app_config;

        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_app_config(dir.path().into());
        cfg.services.rest = false;
        cfg.services.didcomm = true;
        cfg.services.webauthn = false;
        cfg.vta_did = Some("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into());
        cfg.public_url = Some("https://vta.example.com".into());
        cfg.messaging = Some(crate::config::MessagingConfig {
            mediator_did: "did:peer:2.MEDIATOR".into(),
            mediator_url: "ws://mediator:7037".into(),
            mediator_host: None,
        });
        cfg.config_path = dir.path().join("vta.toml");
        let config = Arc::new(RwLock::new(cfg));
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let webvh_ks = store.keyspace(crate::keyspaces::WEBVH).unwrap();
        let super_admin = AuthClaims::unsafe_local_cli_super_admin("test");

        let response = list_services(&config, &webvh_ks, &super_admin)
            .await
            .unwrap();

        assert_eq!(response.services.len(), 4);
        // TSP first (canonical order); disabled here (config `tsp` is off
        // by default) though it carries the same mediator as DIDComm.
        match &response.services[0] {
            ServiceState::Tsp {
                enabled,
                mediator_did,
            } => {
                assert!(!enabled, "TSP is off by default in config");
                assert_eq!(mediator_did.as_deref(), Some("did:peer:2.MEDIATOR"));
            }
            other => panic!("expected TSP first; got {other:?}"),
        }
        match &response.services[1] {
            ServiceState::Didcomm {
                enabled,
                mediator_did,
                ..
            } => {
                assert!(enabled);
                assert_eq!(mediator_did.as_deref(), Some("did:peer:2.MEDIATOR"));
            }
            other => panic!("expected DIDComm second; got {other:?}"),
        }
        match &response.services[2] {
            ServiceState::Rest { enabled, url } => {
                assert!(!enabled, "REST is disabled in config");
                assert_eq!(url.as_deref(), Some("https://vta.example.com"));
            }
            other => panic!("expected REST third; got {other:?}"),
        }
        match &response.services[3] {
            ServiceState::Webauthn { enabled, url } => {
                assert!(!enabled);
                assert!(url.is_none());
            }
            other => panic!("expected WebAuthn fourth; got {other:?}"),
        }
    }

    /// Drives production `list_services` end-to-end against an
    /// on-disk DID-doc fixture; asserts the response array's
    /// canonical order (DIDComm first, REST second per spec §3.3)
    /// and that the kind-specific config (mediator DID, REST URL)
    /// is correctly extracted from the on-chain document. Replaces
    /// the prior hand-rolled response assertion that bypassed the
    /// production code path entirely.
    #[tokio::test]
    async fn list_services_returns_didcomm_first_rest_second() {
        use crate::test_support::test_app_config;

        let dir = tempfile::tempdir().unwrap();
        let vta_did = "did:webvh:scid:host:vta";
        let mut cfg = test_app_config(dir.path().into());
        cfg.services.rest = true;
        cfg.services.didcomm = true;
        cfg.vta_did = Some(vta_did.into());
        cfg.config_path = dir.path().join("vta.toml");
        let config = Arc::new(RwLock::new(cfg));
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let webvh_ks = store.keyspace(crate::keyspaces::WEBVH).unwrap();

        // Stage a webvh record + log line so list_services can read
        // the on-chain document. Service array deliberately puts
        // REST first to verify the response renders in the
        // canonical DIDComm-first order regardless of input.
        let log_line = serde_json::json!({
            "versionId": "1-test",
            "versionTime": "2026-05-06T00:00:00Z",
            "parameters": {},
            "state": {
                "id": vta_did,
                "service": [
                    {
                        "id": format!("{vta_did}#vta-rest"),
                        "type": "VTARest",
                        "serviceEndpoint": "https://vta.example/api",
                    },
                    {
                        "id": format!("{vta_did}#vta-didcomm"),
                        "type": "DIDCommMessaging",
                        "serviceEndpoint": {
                            "uri": "did:peer:2.MEDIATOR",
                            "accept": ["didcomm/v2"],
                            "routingKeys": [],
                        },
                    },
                ],
            },
        });
        let log = serde_json::to_string(&log_line).unwrap();
        let now = chrono::Utc::now();
        let record = vta_sdk::webvh::WebvhDidRecord {
            did: vta_did.into(),
            server_id: "test-server".into(),
            mnemonic: String::new(),
            scid: "scid".into(),
            context_id: "vta".into(),
            portable: false,
            log_entry_count: 1,
            pre_rotation_count: 0,
            next_fragment_id: 1,
            created_at: now,
            updated_at: now,
        };
        webvh_store::store_did(&webvh_ks, &record).await.unwrap();
        webvh_store::store_did_log(&webvh_ks, vta_did, &log)
            .await
            .unwrap();

        let super_admin = AuthClaims::unsafe_local_cli_super_admin("test");
        let response = list_services(&config, &webvh_ks, &super_admin)
            .await
            .unwrap();

        assert_eq!(
            response.services.len(),
            4,
            "expected one entry per kind (TSP + DIDComm + REST + WebAuthn); got {response:?}"
        );
        // Canonical order: TSP first. The fixture publishes no `#tsp`
        // service, so it's disabled with no mediator.
        match &response.services[0] {
            ServiceState::Tsp {
                enabled,
                mediator_did,
            } => {
                assert!(!enabled);
                assert!(mediator_did.is_none());
            }
            other => panic!("expected TSP first; got {other:?}"),
        }
        match &response.services[1] {
            ServiceState::Didcomm {
                enabled,
                mediator_did,
                ..
            } => {
                assert!(enabled);
                assert_eq!(mediator_did.as_deref(), Some("did:peer:2.MEDIATOR"));
            }
            other => panic!("expected DIDComm second; got {other:?}"),
        }
        match &response.services[2] {
            ServiceState::Rest { enabled, url } => {
                assert!(enabled);
                assert_eq!(url.as_deref(), Some("https://vta.example/api"));
            }
            other => panic!("expected REST third; got {other:?}"),
        }
        match &response.services[3] {
            ServiceState::Webauthn { enabled, url } => {
                // Test fixture doesn't publish a WebAuthn service
                // entry; assert the "disabled, no URL" baseline.
                assert!(!enabled);
                assert!(url.is_none());
            }
            other => panic!("expected WebAuthn fourth; got {other:?}"),
        }
    }
}
