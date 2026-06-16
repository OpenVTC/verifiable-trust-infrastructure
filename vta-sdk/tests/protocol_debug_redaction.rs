//! Regression tests for `Debug` redaction on every secret-bearing
//! vta-sdk wire type. The check is uniform:
//!
//!  1. Construct an instance with a *distinctive* secret value (a long,
//!     unmistakeable marker string).
//!  2. `format!("{x:?}")` the value.
//!  3. Assert the marker is NOT present (Debug must redact).
//!  4. Assert `<redacted>` IS present.
//!  5. Where the type also has `Serialize`, assert the serialised form
//!     still carries the marker — redacting on Serialize would break
//!     persistence / wire round-trips.
//!
//! If any of these regress (e.g. someone re-derives Debug on a hardened
//! type), tests fail with a diff that names the leaked field.

use chrono::Utc;
use vta_sdk::protocols::auth::TokenBundle;
use vta_sdk::protocols::backup_management::types::{
    BackupConfig, BackupEnvelope, BackupPayload, EncryptionParams, ExportRequest, ImportRequest,
    ImportedSecretBackup, KdfParams, SeedRecordBackup,
};
use vta_sdk::protocols::did_management::create::CreateDidWebvhResultBody;
use vta_sdk::protocols::key_management::create::CreateKeyBody;
use vta_sdk::protocols::key_management::secret::GetKeySecretResultBody;
use vta_sdk::protocols::seed_management::rotate::RotateSeedBody;

const MARKER: &str = "MARKER_SECRET_VALUE_MUST_NOT_LEAK";

fn assert_redacted<T: std::fmt::Debug>(value: &T, label: &str) {
    let dbg = format!("{value:?}");
    assert!(
        !dbg.contains(MARKER),
        "{label} Debug leaked the secret marker: {dbg}"
    );
    assert!(
        dbg.contains("<redacted>"),
        "{label} Debug missing <redacted> marker: {dbg}"
    );
}

fn assert_serializes_marker<T: serde::Serialize>(value: &T, label: &str) {
    let json = serde_json::to_string(value).expect("serialize");
    assert!(
        json.contains(MARKER),
        "{label} Serialize must NOT redact (wire/persistence breakage): {json}"
    );
}

#[test]
fn token_bundle_debug_redacts_access_and_refresh_tokens() {
    let bundle = TokenBundle {
        access_token: MARKER.into(),
        refresh_token: Some(MARKER.into()),
        token_type: "Bearer".into(),
        expires_in: 900,
        refresh_expires_in: Some(86400),
        scope: Vec::new(),
    };
    assert_redacted(&bundle, "TokenBundle");
    assert_serializes_marker(&bundle, "TokenBundle");
}

#[test]
fn create_did_webvh_result_body_debug_redacts_mnemonic() {
    let result = CreateDidWebvhResultBody {
        did: "did:webvh:example.com:abc".into(),
        context_id: "ctx".into(),
        server_id: Some("prod".into()),
        mnemonic: Some(MARKER.into()),
        scid: "QmTest".into(),
        portable: false,
        signing_key_id: "k0".into(),
        ka_key_id: "k1".into(),
        pre_rotation_key_count: 0,
        created_at: Utc::now(),
        did_document: None,
        log_entry: None,
    };
    assert_redacted(&result, "CreateDidWebvhResultBody");
    assert_serializes_marker(&result, "CreateDidWebvhResultBody");
}

#[test]
fn create_key_body_debug_redacts_mnemonic() {
    let body = CreateKeyBody {
        key_type: vta_sdk::keys::KeyType::Ed25519,
        derivation_path: "m/0'".into(),
        mnemonic: Some(MARKER.into()),
        label: Some("test".into()),
        context_id: Some("ctx".into()),
    };
    assert_redacted(&body, "CreateKeyBody");
    assert_serializes_marker(&body, "CreateKeyBody");
}

#[test]
fn get_key_secret_result_body_debug_redacts_private_key() {
    let body = GetKeySecretResultBody {
        key_id: "k0".into(),
        key_type: vta_sdk::keys::KeyType::Ed25519,
        public_key_multibase: "zPublicMultibase".into(),
        private_key_multibase: MARKER.into(),
    };
    assert_redacted(&body, "GetKeySecretResultBody");
    assert_serializes_marker(&body, "GetKeySecretResultBody");
}

#[test]
fn rotate_seed_body_debug_redacts_mnemonic() {
    let body = RotateSeedBody {
        mnemonic: Some(MARKER.into()),
    };
    assert_redacted(&body, "RotateSeedBody");
    assert_serializes_marker(&body, "RotateSeedBody");
}

#[test]
fn export_request_debug_redacts_password() {
    let req = ExportRequest {
        password: MARKER.into(),
        include_audit: true,
    };
    assert_redacted(&req, "ExportRequest");
    assert_serializes_marker(&req, "ExportRequest");
}

#[test]
fn import_request_debug_redacts_password() {
    let req = ImportRequest {
        backup: BackupEnvelope {
            version: 1,
            format: "vta-backup-v1".into(),
            created_at: Utc::now(),
            source_did: None,
            source_version: "0.0.0".into(),
            kdf: KdfParams {
                algorithm: "argon2id".into(),
                salt: "AA".into(),
                m_cost: 65536,
                t_cost: 3,
                p_cost: 4,
            },
            encryption: EncryptionParams {
                algorithm: "aes-256-gcm".into(),
                nonce: "AA".into(),
            },
            includes_audit: false,
            ciphertext: "AA".into(),
        },
        password: MARKER.into(),
        confirm: false,
    };
    assert_redacted(&req, "ImportRequest");
    assert_serializes_marker(&req, "ImportRequest");
}

#[test]
fn imported_secret_backup_debug_redacts_private_key_hex() {
    let s = ImportedSecretBackup {
        key_id: "k0".into(),
        private_key_hex: MARKER.into(),
    };
    assert_redacted(&s, "ImportedSecretBackup");
    assert_serializes_marker(&s, "ImportedSecretBackup");
}

#[test]
fn seed_record_backup_debug_redacts_seed_hex() {
    let s = SeedRecordBackup {
        id: 1,
        seed_hex: Some(MARKER.into()),
        seed_enc: None,
        created_at: Utc::now(),
        retired_at: None,
    };
    assert_redacted(&s, "SeedRecordBackup");
    assert_serializes_marker(&s, "SeedRecordBackup");
}

#[test]
fn backup_payload_debug_redacts_active_seed_and_jwt_signing_key() {
    let payload = BackupPayload {
        active_seed_hex: MARKER.into(),
        active_seed_id: 1,
        seed_records: Vec::new(),
        jwt_signing_key: Some(MARKER.into()),
        key_records: Vec::new(),
        context_records: Vec::new(),
        context_counter: 0,
        path_counters: Vec::new(),
        subcontext_counters: Vec::new(),
        acl_entries: Vec::new(),
        acl_entries_full: Vec::new(),
        seal: None,
        webvh_servers: Vec::new(),
        webvh_dids: Vec::new(),
        webvh_logs: Vec::new(),
        config: BackupConfig {
            vta_did: None,
            vta_name: None,
            public_url: None,
            mediator_url: None,
            mediator_did: None,
        },
        audit_logs: Vec::new(),
        imported_secrets: Vec::new(),
        imported_kek_salt: None,
    };
    let dbg = format!("{payload:?}");
    assert!(
        !dbg.contains(MARKER),
        "BackupPayload Debug leaked the secret marker: {dbg}"
    );
    assert!(
        dbg.contains("<redacted>"),
        "BackupPayload Debug missing <redacted> marker: {dbg}"
    );
    // Serialize path must still emit the secrets verbatim — the
    // backup file is the encrypted envelope around this payload, so
    // the inner JSON legitimately contains the seed material.
    let json = serde_json::to_string(&payload).expect("serialize");
    assert!(
        json.contains(MARKER),
        "BackupPayload Serialize must not redact: {json}"
    );
}
