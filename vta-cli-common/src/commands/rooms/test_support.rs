//! Fixtures the `pnm rooms` tests share: targets, offers, and the refusals a
//! VTA or host answers with.

use super::*;
use serde_json::json;

pub(super) fn prune_target() -> RoomTarget<'static> {
    RoomTarget {
        host_url: "https://host.example",
        host_did: Some("did:web:host.example"),
        room_id: "did:webvh:Qm:example.com:rooms:northwind",
    }
}

pub(super) fn rejected(code: &str, details: Value) -> VtaError {
    VtaError::Rejected {
        code: code.into(),
        message: "refused".into(),
        details: Some(details),
    }
}

pub(super) fn minted(authority: Value) -> Value {
    json!({
        "presentation": {
            "membership": "vmc-blob",
            "authority": authority,
        },
        "expiresAt": "2026-09-07T16:00:00Z",
    })
}

pub(super) fn vtc_target() -> RoomTarget<'static> {
    RoomTarget {
        host_url: "https://community.example/v1",
        host_did: Some("did:webvh:community.example"),
        room_id: "did:webvh:example.com:rooms:northwind",
    }
}

pub(super) const CATCH_UP: &str = "pnm rooms keys commit --room did:webvh:example.com:rooms:northwind \
                        --host https://community.example/v1 --host-did did:webvh:community.example";

pub(super) fn offer_v2(description: Option<&str>) -> Value {
    let mut o = json!({
        "roomId": "did:webvh:Qm3:vtc.example:room-dids:ab12",
        "host": "did:webvh:Qm1:vtc.example",
        "label": "Board\u{1b}[2J papers",
        "visibility": "private",
        "actions": ["read", "write"],
        "validUntil": "2026-12-01T00:00:00Z",
        "offeredAt": "2026-10-01T00:00:00Z",
        "state": "open",
        "credentials": {
            "membership": "{}",
            "authority": "{}",
            "invitation": "inv"
        }
    });
    if let Some(d) = description {
        o["description"] = json!(d);
    }
    o
}

pub(super) fn offer_target() -> OfferTarget<'static> {
    OfferTarget {
        vtc_url: "https://vtc.example/v1",
        vtc_did: "did:webvh:Qm1:vtc.example",
        member: "did:webvh:Qm2:alice.example",
    }
}

pub(super) fn open_rejected(reason: &str, extra: Value) -> VtaError {
    let mut details = json!({ "reason": reason });
    details
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    VtaError::Rejected {
        code: "rooms/keys/open:unknownEpoch".into(),
        message: "record is sealed under epoch 4".into(),
        details: Some(details),
    }
}

pub(super) fn file_key_rejected(reason: &str, message: &str) -> VtaError {
    VtaError::Rejected {
        code: "rooms/keys/file-key:unknownEpoch".into(),
        message: message.into(),
        details: Some(json!({ "reason": reason })),
    }
}

pub(super) fn stated() -> RecordProvenance {
    RecordProvenance {
        basis: Some(vtc_client::rooms::body::RecordBasis::Inferred),
        basis_named: true,
        confidence: Some(0.6),
        cite_records: vec!["meetings/q3@3".into()],
        cite_credentials: vec!["urn:uuid:1".into()],
        purposes: vec!["https://w3id.org/dpv#ServicePersonalisation".into()],
        use_note: Some("renewal only".into()),
        valid_until: Some("2026-12-31T23:59:59Z".into()),
    }
}
