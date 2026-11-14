//! A chain written before the vocabulary moved out of `vti-common` (#2568)
//! still verifies, and still reads back to the bytes that were stored.
//!
//! `fixtures/vtc_chain.json` was produced by `vti_common::audit::AuditWriter`
//! on `main` at `792db16a5`, when `AuditEvent` was still
//! `vti_common::audit::AuditEvent`: the raw keyspace rows (key and value), and
//! the audit key they were hashed under. Nothing in it may be regenerated —
//! the point is that it predates the move.

use vtc_audit::{AuditEnvelope, AuditEvent, ChainVerifier, verify_chain};

struct Row {
    key: String,
    value: String,
}

fn fixture() -> (Vec<Row>, [u8; 32]) {
    let raw: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/vtc_chain.json")).expect("fixture parses");
    let rows = raw["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|r| Row {
            key: r["key"].as_str().expect("key").to_string(),
            value: r["value"].as_str().expect("value").to_string(),
        })
        .collect();
    let key: [u8; 32] = hex::decode(raw["auditKeys"][0]["key"].as_str().expect("audit key"))
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    (rows, key)
}

fn envelopes(rows: &[Row]) -> Vec<AuditEnvelope> {
    rows.iter()
        .map(|r| serde_json::from_str(&r.value).expect("a stored envelope parses"))
        .collect()
}

#[test]
fn a_chain_stored_before_the_move_verifies() {
    let (rows, _) = fixture();
    let chain = envelopes(&rows);
    assert_eq!(chain.len(), 6);
    verify_chain(&chain).expect("the stored chain verifies under the moved vocabulary");

    let mut v = ChainVerifier::new();
    for env in &chain {
        v.push(env).expect("incremental verification agrees");
    }
    assert_eq!(v.verified(), 6);
    assert_eq!(v.skipped_legacy(), 0);
}

#[test]
fn every_stored_envelope_re_serializes_byte_for_byte() {
    // The chain commits to the event's serde_json encoding, so the moved
    // vocabulary must produce exactly the bytes the old one stored — `type`
    // and `data` tags, field names, field order and omitted optionals alike.
    let (rows, _) = fixture();
    for (row, env) in rows.iter().zip(envelopes(&rows)) {
        let again = serde_json::to_string(&env).expect("serializes");
        assert_eq!(again, row.value, "row {} changed shape", row.key);
        // And the storage key the writer derives is the one it stored under.
        assert_eq!(
            String::from_utf8(vti_common::audit::writer::envelope_storage_key(&env))
                .expect("utf-8"),
            row.key
        );
    }
}

#[test]
fn the_stored_events_read_as_the_variants_they_were_written_as() {
    let (rows, _) = fixture();
    let chain = envelopes(&rows);
    let names: Vec<&str> = chain.iter().map(|e| e.event.variant_name()).collect();
    assert_eq!(
        names,
        [
            "CommunityInstalled",
            "CommunityProfileUpdated",
            "ConfigChanged",
            "RoomOperation",
            "GitNsOperation",
            "SingleAdminMode",
        ]
    );
    assert!(matches!(chain[3].event, AuditEvent::RoomOperation(_)));
}

#[test]
fn a_tampered_stored_event_is_still_caught() {
    let (rows, _) = fixture();
    let mut chain = envelopes(&rows);
    let AuditEvent::CommunityProfileUpdated(data) = &mut chain[1].event else {
        panic!("row 1 is a profile update");
    };
    data.fields_changed.push("forged".into());
    assert!(matches!(
        verify_chain(&chain),
        Err(vtc_audit::ChainBreak::TamperedEntry { index: 1, .. })
    ));
}

#[test]
fn the_stored_actor_hashes_verify_under_the_stored_key() {
    // The HMAC actor hashing stayed in vti-common; the hashes stored before
    // the move are the HMAC of the plaintext actor under the stored key.
    use hmac_check::hmac;
    let (rows, key) = fixture();
    for env in envelopes(&rows) {
        let actor = env.actor_did_plain.as_deref().expect("plaintext actor");
        assert_eq!(hmac(&key, actor), env.actor_did_hash);
    }
}

mod hmac_check {
    use hmac::{Hmac, KeyInit, Mac};
    pub fn hmac(key: &[u8; 32], did: &str) -> [u8; 32] {
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("32-byte key");
        mac.update(did.as_bytes());
        mac.finalize().into_bytes().into()
    }
}
