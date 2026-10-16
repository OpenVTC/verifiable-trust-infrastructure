//! A room's revocation list, end to end at a host: real keys, real signatures, real chains
//! (`rooms/revocations/put/0.1`, trust-tasks-tf #804).
//!
//! Every test delivers a list the room signed through [`revocation_tasks::put`] — the path
//! both hosts serve — and then asks [`authz::authorize`] what it still admits.

use std::time::Duration as StdDuration;

use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use chrono::{Duration, Utc};
use dtg_credentials::{DTGCredential, IssuerScope};
use serde_json::{Value, json};
use vti_common::error::AppError;
use vti_rooms::authz::{self, Action};
use vti_rooms::blob_tasks::Refusal;
use vti_rooms::revocation::test_keyspace;
use vti_rooms::revocation_tasks;
use vti_rooms::wire::AuthorityPresentation;
use vti_rooms::{Room, Visibility};
use vti_rooms_dtg::test_support::{Party, RoomFixture};
use vti_rooms_dtg::{DtgChainVerifier, VerificationKeys};

/// Resolves a `did:key` method to its own key.
struct DidKeys;

#[async_trait::async_trait]
impl VerificationKeys for DidKeys {
    async fn public_key(
        &self,
        vm: &str,
        _purpose: vti_common::auth::ProofPurpose,
    ) -> Result<Vec<u8>, AppError> {
        let did = vm.split('#').next().unwrap_or_default();
        let mb = did
            .strip_prefix("did:key:")
            .ok_or_else(|| AppError::NotFound(format!("not a did:key: {did}")))?;
        vta_sdk::did_key::decode_ed25519_public_key_multibase(mb)
            .map(|k| k.to_vec())
            .map_err(|e| AppError::NotFound(e.to_string()))
    }
}

fn verifier() -> DtgChainVerifier {
    DtgChainVerifier::without_zk(Box::new(DidKeys))
}

fn now() -> u64 {
    Utc::now().timestamp() as u64
}

fn rfc(t: chrono::DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A list signed by `signer` (the room, unless a test says otherwise).
async fn signed_list(room: &Room, signer: &Party, sequence: u64, entries: Vec<Value>) -> Value {
    let mut doc = json!({
        "roomId": room.room_id,
        "sequence": sequence,
        "issuedAt": rfc(Utc::now()),
        "entries": entries,
    });
    let proof = DataIntegrityProof::sign(&doc, &signer.secret, SignOptions::new())
        .await
        .expect("sign the list");
    doc["proof"] = serde_json::to_value(proof).expect("proof");
    doc
}

fn withdraw(subject: &str, at: chrono::DateTime<Utc>) -> Value {
    json!({ "kind": "subject", "subject": subject, "revokedAt": rfc(at) })
}

async fn deliver(
    _f: &RoomFixture,
    room: &Room,
    by: &AuthorityPresentation,
    presenter: &str,
    list: Value,
) -> Result<Value, Refusal> {
    let payload = json!({ "roomId": room.room_id, "presentation": by, "list": list });
    revocation_tasks::put(room, presenter, &payload, &verifier(), test_keyspace())
        .await
        .map(|(body, _)| body)
}

fn code(r: &Refusal) -> String {
    match r {
        Refusal::Declared { code, .. } => code.code.to_string(),
        Refusal::App(e) => format!("app:{e}"),
        other => format!("{other:?}"),
    }
}

async fn read_as(f: &RoomFixture, p: &AuthorityPresentation, who: &str) -> Result<(), AppError> {
    authz::authorize(
        &f.room,
        p,
        Action::Read,
        who,
        now(),
        &verifier(),
        test_keyspace(),
    )
    .await
    .map(|_| ())
}

/// A member's VMC and a `read` VAC from the room, issued at `from`.
async fn fresh_credentials(
    f: &RoomFixture,
    member: &Party,
    from: chrono::DateTime<Utc>,
) -> AuthorityPresentation {
    let mut vac = DTGCredential::new_vac(
        f.room_key.did.clone(),
        IssuerScope::Public,
        member.did.clone(),
        f.room_key.did.clone(),
        vec!["read".into()],
        from,
        Utc::now() + Duration::days(1),
    )
    .expect("VAC")
    .with_id(format!("urn:uuid:{}", uuid_ish()));
    vac.sign(&f.room_key.secret, None).await.expect("sign");
    let mut vmc = DTGCredential::new_vmc(
        f.room_key.did.clone(),
        member.did.clone(),
        from,
        Some(Utc::now() + Duration::days(1)),
        false,
    );
    vmc.sign(&f.room_key.secret, None).await.expect("sign");
    AuthorityPresentation {
        membership: serde_json::to_string(&vmc).unwrap(),
        authority: vec![serde_json::to_string(&vac).unwrap()],
        subject_binding: None,
    }
}

fn uuid_ish() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("random");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// *Enforcement* item 1: from acceptance the withdrawn member is refused, and so is the
/// agent they delegated to — matched as issuer — with the framework's opaque
/// `permissionDenied`. Everybody else is untouched.
#[tokio::test]
async fn a_withdrawn_member_and_their_agent_are_refused_at_once() {
    let f = RoomFixture::new(Visibility::Attributed).await;
    read_as(&f, &f.as_agent(), &f.agent.did)
        .await
        .expect("the agent reads before");
    read_as(&f, &f.as_successor(), &f.successor.did)
        .await
        .expect("another member reads");

    let list = signed_list(
        &f.room,
        &f.room_key,
        1,
        vec![withdraw(&f.owner.did, Utc::now())],
    )
    .await;
    let body = deliver(&f, &f.room, &f.as_owner(), &f.owner.did, list)
        .await
        .expect("the room's own list is accepted");
    assert_eq!(body["head"]["sequence"], 1);
    assert!(body["inForceAt"].is_string());

    for (p, who) in [(f.as_owner(), &f.owner.did), (f.as_agent(), &f.agent.did)] {
        let err = read_as(&f, &p, who).await.expect_err("withdrawn");
        assert!(matches!(err, AppError::Forbidden(_)), "{err}");
        let text = err.to_string();
        assert!(
            !text.contains("revok") && !text.contains("withdr"),
            "the refusal must not say why: {text}"
        );
    }
    read_as(&f, &f.as_successor(), &f.successor.did)
        .await
        .expect("a member nobody withdrew is untouched");
}

/// Keyed on time, so a party can come back: fresh credentials issued after the withdrawal
/// verify, and nothing in the list had to be undone.
#[tokio::test]
async fn re_admission_after_a_subject_withdrawal_works() {
    let f = RoomFixture::new(Visibility::Attributed).await;
    let at = Utc::now() - Duration::seconds(30);
    let list = signed_list(
        &f.room,
        &f.room_key,
        1,
        vec![withdraw(&f.successor.did, at)],
    )
    .await;
    deliver(&f, &f.room, &f.as_owner(), &f.owner.did, list)
        .await
        .expect("accepted");

    read_as(&f, &f.as_successor(), &f.successor.did)
        .await
        .expect_err("the credentials issued before the withdrawal");
    let fresh = fresh_credentials(&f, &f.successor, at + Duration::seconds(5)).await;
    read_as(&f, &fresh, &f.successor.did)
        .await
        .expect("credentials issued after it verify");
}

/// Item 2: a list is the room's statement or nothing — a list signed by anybody else,
/// however well, is `listInvalid`, and nothing changes.
#[tokio::test]
async fn a_list_signed_by_anyone_but_the_room_is_invalid() {
    let f = RoomFixture::new(Visibility::Attributed).await;
    let forged = signed_list(
        &f.room,
        &f.owner,
        1,
        vec![withdraw(&f.successor.did, Utc::now())],
    )
    .await;
    let err = deliver(&f, &f.room, &f.as_owner(), &f.owner.did, forged)
        .await
        .expect_err("not the room's");
    assert_eq!(code(&err), "rooms/revocations/put:listInvalid");
    read_as(&f, &f.as_successor(), &f.successor.did)
        .await
        .expect("nothing was withdrawn");
}

/// Item 1: only `admin` delivers; a `read` agent is the standard `permissionDenied`.
#[tokio::test]
async fn only_an_administrator_delivers() {
    let f = RoomFixture::new(Visibility::Attributed).await;
    let list = signed_list(&f.room, &f.room_key, 1, vec![]).await;
    let err = deliver(&f, &f.room, &f.as_agent(), &f.agent.did, list)
        .await
        .expect_err("read is not admin");
    assert!(
        matches!(err, Refusal::App(AppError::Forbidden(_))),
        "{err:?}"
    );
}

/// Item 4: a higher sequence only; a repeat is accepted with its first `inForceAt`; one
/// sequence, two lists, is a conflict; a dropped live entry is `notAppendOnly`.
#[tokio::test]
async fn the_sequence_and_append_only_rules_hold() {
    let f = RoomFixture::new(Visibility::Open).await;
    let a = withdraw("did:key:z6MkA", Utc::now());
    let first = signed_list(&f.room, &f.room_key, 2, vec![a.clone()]).await;
    let accepted = deliver(&f, &f.room, &f.as_owner(), &f.owner.did, first.clone())
        .await
        .expect("accepted");
    tokio::time::sleep(StdDuration::from_millis(1100)).await;
    let repeat = deliver(&f, &f.room, &f.as_owner(), &f.owner.did, first)
        .await
        .expect("a repeat is accepted");
    assert_eq!(repeat["inForceAt"], accepted["inForceAt"]);
    assert_eq!(repeat["head"], accepted["head"]);

    let stale = signed_list(&f.room, &f.room_key, 1, vec![a.clone()]).await;
    let err = deliver(&f, &f.room, &f.as_owner(), &f.owner.did, stale)
        .await
        .unwrap_err();
    assert_eq!(code(&err), "rooms/revocations/put:stale");
    assert!(matches!(&err, Refusal::Declared { details: Some(d), .. } if d["heldSequence"] == 2));

    let fork = signed_list(&f.room, &f.room_key, 2, vec![]).await;
    let err = deliver(&f, &f.room, &f.as_owner(), &f.owner.did, fork)
        .await
        .unwrap_err();
    assert_eq!(code(&err), "rooms/revocations/put:sequenceConflict");

    let dropped = signed_list(&f.room, &f.room_key, 3, vec![]).await;
    let err = deliver(&f, &f.room, &f.as_owner(), &f.owner.did, dropped)
        .await
        .unwrap_err();
    assert_eq!(code(&err), "rooms/revocations/put:notAppendOnly");

    let next = signed_list(
        &f.room,
        &f.room_key,
        3,
        vec![a, withdraw("did:key:z6MkB", Utc::now())],
    )
    .await;
    let body = deliver(&f, &f.room, &f.as_owner(), &f.owner.did, next)
        .await
        .expect("forward");
    assert_eq!(body["head"]["sequence"], 3);

    // `get` returns it unaltered.
    let (got, _) = revocation_tasks::get(
        &f.room,
        &f.owner.did,
        &json!({ "roomId": f.room.room_id, "presentation": f.as_owner() }),
        &verifier(),
        test_keyspace(),
    )
    .await
    .expect("get");
    assert_eq!(got["list"]["sequence"], 3);
    assert_eq!(
        vti_rooms::revocation::digest_multibase(&got["list"]),
        body["head"]["digest"].as_str().unwrap()
    );
}

/// *Enforcement* item 3: a list accepted while an operation is authorized waits for that
/// operation to finish, and everything authorized after it sees the list.
#[tokio::test]
async fn acceptance_waits_for_what_was_authorized_before_it() {
    let f = RoomFixture::new(Visibility::Attributed).await;
    let held = authz::authorize(
        &f.room,
        &f.as_successor(),
        Action::Read,
        &f.successor.did,
        now(),
        &verifier(),
        test_keyspace(),
    )
    .await
    .expect("authorized before the list");

    let list = signed_list(
        &f.room,
        &f.room_key,
        1,
        vec![withdraw(&f.successor.did, Utc::now())],
    )
    .await;
    let room = f.room.clone();
    let owner = f.as_owner();
    let owner_did = f.owner.did.clone();
    let mut delivery = tokio::spawn(async move {
        let payload = json!({ "roomId": room.room_id, "presentation": owner, "list": list });
        revocation_tasks::put(&room, &owner_did, &payload, &verifier(), test_keyspace())
            .await
            .map(|(b, _)| b)
    });
    assert!(
        tokio::time::timeout(StdDuration::from_millis(300), &mut delivery)
            .await
            .is_err(),
        "a list must not be accepted while an operation authorized before it is uncommitted"
    );
    drop(held);
    delivery
        .await
        .expect("join")
        .expect("accepted once the operation committed");
    read_as(&f, &f.as_successor(), &f.successor.did)
        .await
        .expect_err("and from then on it is enforced");
}

/// The list binds every host serving the room, a read mirror included.
#[tokio::test]
async fn a_mirror_accepts_the_list() {
    let f = RoomFixture::new(Visibility::Attributed).await;
    let mirror = Room {
        mirror_of: Some("https://primary.example".into()),
        ..f.room.clone()
    };
    let list = signed_list(
        &mirror,
        &f.room_key,
        1,
        vec![withdraw(&f.successor.did, Utc::now())],
    )
    .await;
    deliver(&f, &mirror, &f.as_owner(), &f.owner.did, list)
        .await
        .expect("a mirror holds it too");
}

/// Succession is a task a list governs: a nomination the room withdrew redeems nothing.
#[tokio::test]
async fn a_withdrawn_nomination_is_refused() {
    let f = RoomFixture::new(Visibility::Attributed).await;
    let nomination = f.nominate(&f.successor.did, 24).await;
    let verified =
        vti_rooms_dtg::nomination::verify(&nomination, &f.room.room_id, &f.successor.did, &DidKeys)
            .await
            .expect("a nomination");
    let list = signed_list(
        &f.room,
        &f.room_key,
        1,
        vec![json!({ "kind": "credential", "credentialId": "urn:uuid:vac-nomination", "revokedAt": rfc(Utc::now()) })],
    )
    .await;
    deliver(&f, &f.room, &f.as_owner(), &f.owner.did, list)
        .await
        .expect("accepted");
    let authorized = authz::authorize(
        &f.room,
        &f.as_successor(),
        Action::Read,
        &f.successor.did,
        now(),
        &verifier(),
        test_keyspace(),
    )
    .await
    .expect("the successor still reads");
    assert!(authorized.also_unrevoked(verified.facts()).is_err());
}
