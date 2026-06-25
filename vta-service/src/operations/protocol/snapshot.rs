//! Per-kind previous-config snapshot for fail-forward rollback.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §3.5a.
//!
//! The snapshot captures a service kind's pre-mutation state — the
//! configuration that was in effect *before* the most recent
//! successful mutation of that kind. `services {kind} rollback`
//! consumes the snapshot via [`read`], dispatches into the
//! equivalent forward operation, and the new mutation's pre-state
//! then replaces the snapshot via [`write`]. There is no "rewind"
//! of the WebVH chain — every mutation, rollback or otherwise,
//! appends a new LogEntry.
//!
//! ## Storage
//!
//! * Keyspace: [`KEYSPACE_NAME`] (`service_prev_config`).
//! * Key: `rest` or `didcomm` — exactly one entry per kind.
//! * Value: serialized [`ServiceConfigSnapshot`]. The variant tag
//!   in the serialized form mirrors the kind, so a misdirected
//!   write (e.g. storing a `Didcomm` payload under the `rest` key)
//!   is caught by [`read`] before it reaches the rollback dispatch.
//!
//! ## Order discipline
//!
//! Per spec §3.5a, the operation layer is responsible for writing
//! the snapshot **before** the runtime mutation. A crash between
//! snapshot persist and runtime mutation leaves the snapshot
//! describing the current state — a subsequent rollback would find
//! snapshot ≡ current and is a no-op (handled in T3.1/T3.2). A
//! crash between runtime mutation and LogEntry publication uses the
//! existing transactional-rollback pattern from `update_didcomm`.

use serde::{Deserialize, Serialize};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// Fjall keyspace name for snapshots. Callers fetch the
/// [`KeyspaceHandle`] via [`vti_common::store::Store::keyspace`]
/// once at startup (or in tests) and pass it to [`read`] / [`write`]
/// / [`clear`].
pub const KEYSPACE_NAME: &str = crate::keyspaces::SNAPSHOT;

/// Identifier for which transport kind a snapshot pertains to.
///
/// Lives in this module rather than in `vta_sdk` because the
/// snapshot store is server-side only — the SDK doesn't need it.
/// The CLI / wire-type layers use their own kind discriminator
/// (the `code` field on `TypedErrorPayload`); both stay in sync
/// because the kebab-case strings match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceKind {
    Rest,
    Didcomm,
    Webauthn,
    Tsp,
}

impl ServiceKind {
    /// Storage key for this kind. Stable wire form — changing this
    /// invalidates every persisted snapshot.
    pub(crate) fn storage_key(self) -> &'static str {
        match self {
            ServiceKind::Rest => "rest",
            ServiceKind::Didcomm => "didcomm",
            ServiceKind::Webauthn => "webauthn",
            ServiceKind::Tsp => "tsp",
        }
    }
}

/// Snapshot of a single transport's pre-mutation state.
///
/// The variant tag (`kind`) doubles as a self-validation marker:
/// [`read`] checks it against the requested kind and surfaces an
/// internal error on mismatch rather than handing the rollback
/// dispatcher a payload that doesn't fit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ServiceConfigSnapshot {
    Rest(RestSnapshot),
    Didcomm(DidcommSnapshot),
    Webauthn(WebauthnSnapshot),
    Tsp(TspSnapshot),
}

impl ServiceConfigSnapshot {
    pub fn kind(&self) -> ServiceKind {
        match self {
            ServiceConfigSnapshot::Rest(_) => ServiceKind::Rest,
            ServiceConfigSnapshot::Didcomm(_) => ServiceKind::Didcomm,
            ServiceConfigSnapshot::Webauthn(_) => ServiceKind::Webauthn,
            ServiceConfigSnapshot::Tsp(_) => ServiceKind::Tsp,
        }
    }
}

/// Pre-mutation state for the REST kind.
///
/// `Disabled` is meaningful — when the most recent mutation was
/// `services rest enable`, the snapshot records that REST was
/// previously off so rollback knows to re-disable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum RestSnapshot {
    Enabled { url: String },
    Disabled,
}

/// Pre-mutation state for the DIDComm kind. `routing_keys` is
/// optional and elided from the wire form when empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum DidcommSnapshot {
    Enabled {
        mediator_did: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        routing_keys: Vec<String>,
    },
    Disabled,
}

/// Pre-mutation state for the WebAuthn-RP kind. Mirrors
/// [`RestSnapshot`] — the WebAuthn surface has the same single-URL
/// shape on the DID document, just under a different fragment and
/// type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum WebauthnSnapshot {
    Enabled { url: String },
    Disabled,
}

/// Pre-mutation state for the TSP (`TSPTransport`) kind. Mirrors
/// [`RestSnapshot`] — the TSP surface has the same single-value shape on
/// the DID document — but the advertised value is the **mediator DID**
/// (the VTA's TSP VID), not a URL, so the field is named `mediator_did`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum TspSnapshot {
    Enabled { mediator_did: String },
    Disabled,
}

/// Read the snapshot for `kind`, or [`None`] if no prior mutation
/// has been recorded.
///
/// Returns [`AppError::Internal`] when the persisted variant tag
/// doesn't match the requested kind — that's a programmer error
/// (someone wrote the wrong kind under this key) and should
/// surface loudly rather than corrupt a rollback dispatch.
pub async fn read(
    ks: &KeyspaceHandle,
    kind: ServiceKind,
) -> Result<Option<ServiceConfigSnapshot>, AppError> {
    let key = kind.storage_key().as_bytes().to_vec();
    let snap: Option<ServiceConfigSnapshot> = ks.get(key).await?;
    if let Some(s) = &snap {
        let stored_kind = s.kind();
        if stored_kind != kind {
            return Err(AppError::Internal(format!(
                "snapshot kind mismatch under key {key:?}: stored {stored_kind:?}, \
                 requested {kind:?}",
                key = kind.storage_key(),
            )));
        }
    }
    Ok(snap)
}

/// Replace the snapshot for `snapshot.kind()` with the supplied
/// payload. Overwrites any existing snapshot for that kind. The
/// kind is derived from the payload — there is no separate kind
/// argument because the variant already carries it.
pub async fn write(ks: &KeyspaceHandle, snapshot: ServiceConfigSnapshot) -> Result<(), AppError> {
    let key = snapshot.kind().storage_key().as_bytes().to_vec();
    ks.insert(key, &snapshot).await
}

/// Remove the snapshot for `kind`. No-op if no snapshot is
/// present.
pub async fn clear(ks: &KeyspaceHandle, kind: ServiceKind) -> Result<(), AppError> {
    let key = kind.storage_key().as_bytes().to_vec();
    ks.remove(key).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    /// Allocates a fresh on-disk fjall store + a handle on the
    /// snapshot keyspace. Returns the `TempDir` so the caller can
    /// keep it alive for the duration of the test.
    async fn empty_snapshot_keyspace() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().into(),
        })
        .expect("open store");
        let ks = store.keyspace(KEYSPACE_NAME).expect("keyspace");
        (dir, ks)
    }

    #[tokio::test]
    async fn read_returns_none_when_no_snapshot_present() {
        let (_dir, ks) = empty_snapshot_keyspace().await;

        assert!(read(&ks, ServiceKind::Rest).await.unwrap().is_none());
        assert!(read(&ks, ServiceKind::Didcomm).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn write_then_read_round_trips_rest_enabled() {
        let (_dir, ks) = empty_snapshot_keyspace().await;

        let snap = ServiceConfigSnapshot::Rest(RestSnapshot::Enabled {
            url: "https://vta.example.com".into(),
        });
        write(&ks, snap.clone()).await.unwrap();

        let restored = read(&ks, ServiceKind::Rest).await.unwrap().unwrap();
        assert_eq!(restored, snap);
    }

    #[tokio::test]
    async fn write_then_read_round_trips_rest_disabled() {
        let (_dir, ks) = empty_snapshot_keyspace().await;

        let snap = ServiceConfigSnapshot::Rest(RestSnapshot::Disabled);
        write(&ks, snap.clone()).await.unwrap();

        let restored = read(&ks, ServiceKind::Rest).await.unwrap().unwrap();
        assert_eq!(restored, snap);
    }

    #[tokio::test]
    async fn write_then_read_round_trips_didcomm_enabled_with_routing_keys() {
        let (_dir, ks) = empty_snapshot_keyspace().await;

        let snap = ServiceConfigSnapshot::Didcomm(DidcommSnapshot::Enabled {
            mediator_did: "did:peer:2.Vz...mediator".into(),
            routing_keys: vec!["did:peer:2.Vz...key1".into(), "did:peer:2.Vz...key2".into()],
        });
        write(&ks, snap.clone()).await.unwrap();

        let restored = read(&ks, ServiceKind::Didcomm).await.unwrap().unwrap();
        assert_eq!(restored, snap);
    }

    #[tokio::test]
    async fn write_then_read_round_trips_didcomm_enabled_no_routing_keys() {
        let (_dir, ks) = empty_snapshot_keyspace().await;

        let snap = ServiceConfigSnapshot::Didcomm(DidcommSnapshot::Enabled {
            mediator_did: "did:peer:2.Vz...mediator".into(),
            routing_keys: vec![],
        });
        write(&ks, snap.clone()).await.unwrap();

        let restored = read(&ks, ServiceKind::Didcomm).await.unwrap().unwrap();
        assert_eq!(restored, snap);
    }

    #[tokio::test]
    async fn write_then_read_round_trips_didcomm_disabled() {
        let (_dir, ks) = empty_snapshot_keyspace().await;

        let snap = ServiceConfigSnapshot::Didcomm(DidcommSnapshot::Disabled);
        write(&ks, snap.clone()).await.unwrap();

        let restored = read(&ks, ServiceKind::Didcomm).await.unwrap().unwrap();
        assert_eq!(restored, snap);
    }

    #[tokio::test]
    async fn write_then_read_round_trips_tsp_enabled() {
        let (_dir, ks) = empty_snapshot_keyspace().await;

        let snap = ServiceConfigSnapshot::Tsp(TspSnapshot::Enabled {
            mediator_did: "did:webvh:scid:host:mediator".into(),
        });
        write(&ks, snap.clone()).await.unwrap();

        let restored = read(&ks, ServiceKind::Tsp).await.unwrap().unwrap();
        assert_eq!(restored, snap);
    }

    #[tokio::test]
    async fn write_then_read_round_trips_tsp_disabled() {
        let (_dir, ks) = empty_snapshot_keyspace().await;

        let snap = ServiceConfigSnapshot::Tsp(TspSnapshot::Disabled);
        write(&ks, snap.clone()).await.unwrap();

        let restored = read(&ks, ServiceKind::Tsp).await.unwrap().unwrap();
        assert_eq!(restored, snap);
    }

    #[tokio::test]
    async fn second_write_overwrites_first_for_same_kind() {
        let (_dir, ks) = empty_snapshot_keyspace().await;

        let first = ServiceConfigSnapshot::Rest(RestSnapshot::Enabled {
            url: "https://old.example.com".into(),
        });
        write(&ks, first).await.unwrap();

        let second = ServiceConfigSnapshot::Rest(RestSnapshot::Enabled {
            url: "https://new.example.com".into(),
        });
        write(&ks, second.clone()).await.unwrap();

        let restored = read(&ks, ServiceKind::Rest).await.unwrap().unwrap();
        assert_eq!(restored, second);
    }

    #[tokio::test]
    async fn clear_removes_snapshot() {
        let (_dir, ks) = empty_snapshot_keyspace().await;

        write(
            &ks,
            ServiceConfigSnapshot::Rest(RestSnapshot::Enabled {
                url: "https://vta.example.com".into(),
            }),
        )
        .await
        .unwrap();

        clear(&ks, ServiceKind::Rest).await.unwrap();
        assert!(read(&ks, ServiceKind::Rest).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn clear_is_a_noop_when_nothing_is_present() {
        let (_dir, ks) = empty_snapshot_keyspace().await;
        clear(&ks, ServiceKind::Rest).await.unwrap();
        clear(&ks, ServiceKind::Didcomm).await.unwrap();
    }

    /// REST and DIDComm snapshots live under different storage keys
    /// and must not affect each other.
    #[tokio::test]
    async fn rest_and_didcomm_snapshots_are_independent() {
        let (_dir, ks) = empty_snapshot_keyspace().await;

        let rest = ServiceConfigSnapshot::Rest(RestSnapshot::Enabled {
            url: "https://vta.example.com".into(),
        });
        let didcomm = ServiceConfigSnapshot::Didcomm(DidcommSnapshot::Enabled {
            mediator_did: "did:peer:2.Vz...mediator".into(),
            routing_keys: vec![],
        });

        write(&ks, rest.clone()).await.unwrap();
        write(&ks, didcomm.clone()).await.unwrap();

        assert_eq!(read(&ks, ServiceKind::Rest).await.unwrap().unwrap(), rest,);
        assert_eq!(
            read(&ks, ServiceKind::Didcomm).await.unwrap().unwrap(),
            didcomm,
        );

        // Clearing one leaves the other intact.
        clear(&ks, ServiceKind::Rest).await.unwrap();
        assert!(read(&ks, ServiceKind::Rest).await.unwrap().is_none());
        assert_eq!(
            read(&ks, ServiceKind::Didcomm).await.unwrap().unwrap(),
            didcomm,
        );
    }

    /// The wire form's discriminator (`kind` outer tag, `state`
    /// inner tag) is part of the persisted contract. Pin it so a
    /// `serde(rename)` change can't silently drop existing
    /// snapshots after an upgrade.
    #[test]
    fn snapshot_wire_form_is_stable() {
        // REST enabled
        let snap = ServiceConfigSnapshot::Rest(RestSnapshot::Enabled {
            url: "https://vta.example.com".into(),
        });
        let json = serde_json::to_value(&snap).unwrap();
        assert_eq!(json["kind"], "rest");
        assert_eq!(json["state"], "enabled");
        assert_eq!(json["url"], "https://vta.example.com");

        // DIDComm enabled with routing keys
        let snap = ServiceConfigSnapshot::Didcomm(DidcommSnapshot::Enabled {
            mediator_did: "did:peer:2.M".into(),
            routing_keys: vec!["did:peer:2.K".into()],
        });
        let json = serde_json::to_value(&snap).unwrap();
        assert_eq!(json["kind"], "didcomm");
        assert_eq!(json["state"], "enabled");
        assert_eq!(json["mediator_did"], "did:peer:2.M");
        assert_eq!(json["routing_keys"][0], "did:peer:2.K");

        // DIDComm disabled — no extra fields
        let snap = ServiceConfigSnapshot::Didcomm(DidcommSnapshot::Disabled);
        let json = serde_json::to_value(&snap).unwrap();
        assert_eq!(json["kind"], "didcomm");
        assert_eq!(json["state"], "disabled");

        // TSP enabled — advertises a mediator DID, not a URL
        let snap = ServiceConfigSnapshot::Tsp(TspSnapshot::Enabled {
            mediator_did: "did:webvh:scid:host:mediator".into(),
        });
        let json = serde_json::to_value(&snap).unwrap();
        assert_eq!(json["kind"], "tsp");
        assert_eq!(json["state"], "enabled");
        assert_eq!(json["mediator_did"], "did:webvh:scid:host:mediator");

        // TSP disabled — no extra fields
        let snap = ServiceConfigSnapshot::Tsp(TspSnapshot::Disabled);
        let json = serde_json::to_value(&snap).unwrap();
        assert_eq!(json["kind"], "tsp");
        assert_eq!(json["state"], "disabled");
    }

    /// Storing a payload under a key whose [`ServiceKind`] doesn't
    /// match the payload's variant must surface as `Internal` on
    /// the next [`read`] — never as a silent type confusion.
    #[tokio::test]
    async fn read_rejects_kind_mismatch() {
        let (_dir, ks) = empty_snapshot_keyspace().await;

        // Manually write a DIDComm payload under the REST key. This
        // should never happen in practice — `write` always uses the
        // payload-derived kind — but the read path defends against
        // it as a bug-detector.
        let didcomm_payload = ServiceConfigSnapshot::Didcomm(DidcommSnapshot::Disabled);
        let bytes = serde_json::to_vec(&didcomm_payload).unwrap();
        ks.insert_raw(ServiceKind::Rest.storage_key().as_bytes().to_vec(), bytes)
            .await
            .unwrap();

        let err = read(&ks, ServiceKind::Rest).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("kind mismatch"),
            "expected kind-mismatch error, got: {msg}",
        );
    }
}
