//! A VTA chain written before `VtaOperation` moved out of `vti-common`
//! (#2568) still verifies, and reads back to the bytes that were stored.
//!
//! `fixtures/vta_chain.json` was produced by `vti_common::audit::AuditWriter`
//! on `main` at `792db16a5`, keyed as `ChainedKeyspaceAuditSink` keys a VTA's
//! rows, when the event was still `vti_common::audit::AuditEvent::VtaOperation`.
//! Nothing in it may be regenerated — the point is that it predates the move.

use vta_audit::{VtaAuditEnvelope, VtaAuditEvent};
use vti_common::audit::verify_chain;

fn rows() -> Vec<(String, String)> {
    let raw: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/vta_chain.json")).expect("fixture parses");
    raw["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|r| {
            (
                r["key"].as_str().expect("key").to_string(),
                r["value"].as_str().expect("value").to_string(),
            )
        })
        .collect()
}

#[test]
fn a_vta_chain_stored_before_the_move_verifies_and_round_trips() {
    let rows = rows();
    let chain: Vec<VtaAuditEnvelope> = rows
        .iter()
        .map(|(_, v)| serde_json::from_str(v).expect("a stored envelope parses"))
        .collect();
    assert_eq!(chain.len(), 2);
    verify_chain(&chain).expect("the stored chain verifies under the moved vocabulary");

    for ((key, value), env) in rows.iter().zip(&chain) {
        assert_eq!(
            &serde_json::to_string(env).expect("serializes"),
            value,
            "row {key} changed shape"
        );
        assert_eq!(env.event.variant_name(), "VtaOperation");
    }
    let VtaAuditEvent::VtaOperation(op) = &chain[1].event else {
        panic!("row 1 is a VTA operation");
    };
    assert_eq!(op.action, "acl.create");
    assert_eq!(op.context_id.as_deref(), Some("ctx"));
}
