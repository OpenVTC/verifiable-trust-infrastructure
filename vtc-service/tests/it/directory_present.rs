//! Integration coverage for credential-sourced directory fields
//! (`vtc/directory/card/present/0.1`).
//!
//! Each declared error code is driven here and asserted on (#1600), which is
//! what the error-code census reads.

use axum::http::StatusCode;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use vti_rooms_dtg::test_support::{Party, sign_as};

use crate::common::second_party::GatedAdmin;
use crate::common::signed::{assert_conforms, call, post, seed_role};
use vtc_service::acl::VtcRole;
use vtc_service::members::{Member, store_member};
use vtc_service::policy::default::install_defaults;
use vtc_service::test_support::TestVtc;

use trust_tasks_rs::specs::vtc::directory::card::present::v0_1::error_codes as codes;

const PRESENT_ERR_NOT_MEMBER: &str = codes::NOT_MEMBER.code;
const PRESENT_ERR_FIELD_UNKNOWN: &str = codes::FIELD_UNKNOWN.code;
const PRESENT_ERR_FIELD_NOT_WRITABLE: &str = codes::FIELD_NOT_WRITABLE.code;
const PRESENT_ERR_PRESENTATION_INVALID: &str = codes::PRESENTATION_INVALID.code;
const PRESENT_ERR_ISSUER_NOT_ACCEPTED: &str = codes::ISSUER_NOT_ACCEPTED.code;
const PRESENT_ERR_CLAIM_MISSING: &str = codes::CLAIM_MISSING.code;

const SPEC: &str = "https://trusttasks.org/spec/vtc/directory";
const FIELD: &str = "org.example.registration";
const TYPE: &str = "ProfessionalRegistration";

fn task(name: &str) -> String {
    format!("{SPEC}/{name}/0.1")
}

fn tt_error_code(body: &Value) -> &str {
    body["payload"]["code"].as_str().unwrap_or_default()
}

struct Fixture {
    vtc: TestVtc,
    member: Party,
    issuer: Party,
    community: String,
}

async fn fixture() -> Fixture {
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_public_url("https://vtc.example.com")
        .build()
        .await;
    install_defaults(&vtc.state.policies_ks, &vtc.state.active_policies_ks)
        .await
        .unwrap();
    let admin = GatedAdmin::new(&vtc).await;
    let issuer = Party::new();
    let (status, body) = admin
        .call(
            &vtc,
            &task("fields/define"),
            json!({ "field": {
                "key": FIELD, "label": "Registration", "type": "claim", "source": "credential",
                "ceiling": "members", "defaultVisibility": "members",
                "constraints": { "claim": {
                    "credentialType": TYPE, "claimPath": "/registration", "issuers": [issuer.did],
                } },
            } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let member = Party::new();
    seed_role(&vtc, &member.did, VtcRole::Member, &[]).await;
    store_member(&vtc.state.members_ks, &Member::fresh(&member.did))
        .await
        .unwrap();
    let community = vtc.state.config.read().await.vtc_did.clone().unwrap();
    Fixture {
        vtc,
        member,
        issuer,
        community,
    }
}

/// A credential `issuer` signs about `subject`.
async fn credential(issuer: &Party, subject: &str, claims: Value, valid_days: i64) -> Value {
    let mut subject_claims = claims;
    subject_claims["id"] = json!(subject);
    sign_as(
        issuer,
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", TYPE],
            "issuer": issuer.did,
            "validFrom": (Utc::now() - Duration::days(1)).to_rfc3339(),
            "validUntil": (Utc::now() + Duration::days(valid_days)).to_rfc3339(),
            "credentialSubject": subject_claims,
        }),
    )
    .await
}

/// `holder`'s presentation of `vcs`, bound to `nonce` and `domain`.
async fn presentation(holder: &Party, vcs: Vec<Value>, nonce: &str, domain: &str) -> Value {
    let vp = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "holder": holder.did,
        "verifiableCredential": vcs,
        "nonce": nonce,
        "domain": domain,
    });
    let proof = affinidi_data_integrity::DataIntegrityProof::sign(
        &vp,
        &holder.secret,
        affinidi_data_integrity::SignOptions::new().with_proof_purpose("authentication"),
    )
    .await
    .unwrap();
    let mut vp = vp;
    vp["proof"] = serde_json::to_value(proof).unwrap();
    vp
}

/// How the presentation in a request is built from that request's own id.
enum Holder<'a> {
    /// The signer presents, bound to this document and community.
    Signer,
    /// The signer sends a presentation bound to another nonce.
    WrongNonce,
    /// The signer sends someone else's presentation.
    Other(&'a Party),
}

impl Fixture {
    /// `from` presents `vcs` for `fields`: the reply's status and document.
    async fn present(
        &self,
        from: &Party,
        fields: &[&str],
        vcs: Vec<Value>,
        holder: Holder<'_>,
        clear: bool,
    ) -> (StatusCode, Value) {
        let type_uri = task("card/present");
        let mut doc = vta_sdk::trust_task_sign::build_unsigned(
            &type_uri,
            json!({ "fields": fields, "presentation": {} }),
            &from.did,
            &self.community,
        )
        .unwrap();
        let id = doc.id.clone();
        let vp = match holder {
            Holder::Signer => presentation(from, vcs, &id, &self.community).await,
            Holder::WrongNonce => {
                presentation(from, vcs, "urn:uuid:another", &self.community).await
            }
            Holder::Other(p) => presentation(p, vcs, &id, &self.community).await,
        };
        doc.payload = json!({ "fields": fields, "presentation": vp, "clear": clear });
        let key =
            vta_sdk::trust_task_sign::HolderKey::from_did_key(&from.did, &from.secret_multibase)
                .unwrap();
        vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
            .await
            .unwrap();
        let (status, reply) = post(&self.vtc, &serde_json::to_value(doc).unwrap()).await;
        if reply["type"].as_str() == Some(format!("{type_uri}#response").as_str()) {
            assert_conforms(&type_uri, &reply);
        }
        (status, reply)
    }

    async fn registration(&self, value: &str) -> Value {
        credential(
            &self.issuer,
            &self.member.did,
            json!({ "registration": value }),
            30,
        )
        .await
    }

    async fn card(&self) -> Value {
        let (status, doc) = call(&self.vtc, &self.member, &task("card/show"), json!({})).await;
        assert_eq!(status, StatusCode::OK, "{doc}");
        doc["payload"]["card"].clone()
    }
}

#[tokio::test]
async fn a_member_fills_a_field_from_a_credential_they_present() {
    let fix = fixture().await;
    let vc = fix.registration("REG-48213").await;
    let (status, doc) = fix
        .present(&fix.member, &[FIELD], vec![vc], Holder::Signer, false)
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let verified = &doc["payload"]["verified"][FIELD];
    assert_eq!(verified["value"], "REG-48213");
    assert_eq!(verified["issuer"], fix.issuer.did.as_str());
    assert_eq!(verified["credentialType"], TYPE);
    assert!(verified["validUntil"].is_string(), "{verified}");

    // Item 5: stored as the verified value, the member's choices untouched.
    let card = fix.card().await;
    assert_eq!(card["values"][FIELD], *verified);
    assert!(card["visibility"].get(FIELD).is_none(), "{card}");
    // Item 6: nothing else of the credential is kept.
    let stored = card["values"].to_string();
    assert!(!stored.contains("proof"), "{stored}");
}

#[tokio::test]
async fn present_refuses_what_its_specification_declares() {
    let fix = fixture().await;
    let vc = fix.registration("REG-1").await;

    let stranger = Party::new();
    let (_, b) = fix
        .present(&stranger, &[FIELD], vec![vc.clone()], Holder::Signer, false)
        .await;
    assert_eq!(tt_error_code(&b), PRESENT_ERR_NOT_MEMBER, "{b}");

    let (_, b) = fix
        .present(
            &fix.member,
            &["org.example.nothing"],
            vec![vc.clone()],
            Holder::Signer,
            false,
        )
        .await;
    assert_eq!(tt_error_code(&b), PRESENT_ERR_FIELD_UNKNOWN, "{b}");

    let (_, b) = fix
        .present(
            &fix.member,
            &["displayName"],
            vec![vc.clone()],
            Holder::Signer,
            false,
        )
        .await;
    assert_eq!(tt_error_code(&b), PRESENT_ERR_FIELD_NOT_WRITABLE, "{b}");

    // Not bound to this document.
    let (_, b) = fix
        .present(
            &fix.member,
            &[FIELD],
            vec![vc.clone()],
            Holder::WrongNonce,
            false,
        )
        .await;
    assert_eq!(tt_error_code(&b), PRESENT_ERR_PRESENTATION_INVALID, "{b}");

    // Another member's presentation, of a credential about this one.
    let other = Party::new();
    let (_, b) = fix
        .present(
            &fix.member,
            &[FIELD],
            vec![vc.clone()],
            Holder::Other(&other),
            false,
        )
        .await;
    assert_eq!(tt_error_code(&b), PRESENT_ERR_PRESENTATION_INVALID, "{b}");

    // A credential about someone else, presented by this member.
    let theirs = credential(&fix.issuer, &other.did, json!({ "registration": "X" }), 30).await;
    let (_, b) = fix
        .present(&fix.member, &[FIELD], vec![theirs], Holder::Signer, false)
        .await;
    assert_eq!(tt_error_code(&b), PRESENT_ERR_PRESENTATION_INVALID, "{b}");

    let forger = Party::new();
    let unaccepted = credential(&forger, &fix.member.did, json!({ "registration": "X" }), 30).await;
    let (_, b) = fix
        .present(
            &fix.member,
            &[FIELD],
            vec![unaccepted],
            Holder::Signer,
            false,
        )
        .await;
    assert_eq!(tt_error_code(&b), PRESENT_ERR_ISSUER_NOT_ACCEPTED, "{b}");
    assert_eq!(b["payload"]["details"]["field"], FIELD, "{b}");

    let silent = credential(&fix.issuer, &fix.member.did, json!({ "other": "X" }), 30).await;
    let (_, b) = fix
        .present(&fix.member, &[FIELD], vec![silent], Holder::Signer, false)
        .await;
    assert_eq!(tt_error_code(&b), PRESENT_ERR_CLAIM_MISSING, "{b}");
    assert_eq!(b["payload"]["details"]["field"], FIELD, "{b}");

    // Nothing above wrote anything.
    assert!(fix.card().await["values"].get(FIELD).is_none());
}

#[tokio::test]
async fn clear_withdraws_a_field_the_presentation_does_not_answer() {
    let fix = fixture().await;
    let (status, _) = fix
        .present(
            &fix.member,
            &[FIELD],
            vec![fix.registration("REG-1").await],
            Holder::Signer,
            false,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let silent = credential(&fix.issuer, &fix.member.did, json!({ "other": "X" }), 30).await;
    let (status, doc) = fix
        .present(&fix.member, &[FIELD], vec![silent], Holder::Signer, true)
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert!(doc["payload"]["verified"].get(FIELD).is_none(), "{doc}");
    assert!(fix.card().await["values"].get(FIELD).is_none());
}

/// Item 7: a value whose credential lapsed is shown to nobody, and the
/// directory's pass withdraws it.
#[tokio::test]
async fn a_lapsed_verified_value_is_withdrawn() {
    let fix = fixture().await;
    let (status, _) = fix
        .present(
            &fix.member,
            &[FIELD],
            vec![fix.registration("REG-1").await],
            Holder::Signer,
            false,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // The credential's end passes.
    let ks = fix.vtc.state.directory.ks();
    let before = vtc_service::directory::cards::by_did(ks, &fix.member.did)
        .await
        .unwrap()
        .unwrap();
    let mut lapsed = before.clone();
    lapsed.values.get_mut(FIELD).unwrap()["validUntil"] =
        json!((Utc::now() - Duration::minutes(1)).to_rfc3339());
    let applied = vtc_service::directory::cards::Applied {
        card: lapsed,
        changed: vec![FIELD.into()],
        widens: false,
    };
    assert!(
        vtc_service::directory::cards::commit(ks, &before, &applied)
            .await
            .unwrap()
    );

    let viewer = Party::new();
    seed_role(&fix.vtc, &viewer.did, VtcRole::Member, &[]).await;
    store_member(&fix.vtc.state.members_ks, &Member::fresh(&viewer.did))
        .await
        .unwrap();
    let (_, doc) = call(
        &fix.vtc,
        &viewer,
        &task("entries/show"),
        json!({ "entryId": before.entry_id }),
    )
    .await;
    assert!(
        doc["payload"].to_string().find(FIELD).is_none(),
        "a lapsed value is shown to nobody: {doc}"
    );

    let withdrawn = vtc_service::directory::sweep::withdraw_lapsed(&fix.vtc.state)
        .await
        .unwrap();
    assert_eq!(withdrawn, 1);
    let after = vtc_service::directory::cards::by_did(ks, &fix.member.did)
        .await
        .unwrap()
        .unwrap();
    assert!(!after.values.contains_key(FIELD));
}
