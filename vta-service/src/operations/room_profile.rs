//! A room's own profile — `rooms/keys/profile/{read,write}/0.1` and
//! `RoomProfileStatement` (`rooms/_shared/0.1`).
//!
//! A room's name, description, tags and emoji live **inside the room**: one record per epoch,
//! at a key derived from that epoch's storage key ([`vti_rooms::profile`]), sealed like any
//! record on the `attributed` and `private` tiers, so the host stores one more opaque record
//! and cannot tell which one names the room. On an `open` room it is the record at
//! `room-profile`, its signed body in `cleartext.body`.
//!
//! # Readers decide who may name the room
//!
//! A host stores the profile record under `write`, like any record, because it cannot tell
//! the profile from anything else. So every member able to write could put a record at the
//! profile's location, and what stops them renaming the room is [`check_statement`]: the
//! statement carries its author's authority chain, and a reader accepts it only if that
//! chain confers `curate` or `admin` on the author at the statement's own `issuedAt`, and
//! the `issuedAt` sits within the window the host's `updatedAt` allows. A profile that fails
//! any check is ignored — the one before it is still the room's — and reported, because a
//! profile somebody wrote without the standing to is somebody trying to rename the room.
//!
//! The orchestration — the walk down the epochs, the fetches, the writes and their version
//! races — is the dispatch handler's (`trust_tasks::room_profile`); everything here is a pure
//! decision over what was fetched, so it can be held to every rule without a host.

use std::future::Future;

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;
use vti_common::error::AppError;

/// The members a `SealedRecordBody` may carry (`rooms/_shared/0.1/room.schema.json`).
const BODY_MEMBERS: &[&str] = &[
    "roomId",
    "key",
    "version",
    "author",
    "title",
    "description",
    "body",
    "tags",
    "file",
    "basis",
    "confidence",
    "evidence",
    "validFor",
    "validUntil",
    "roomProfile",
    "proof",
];

/// The members a profile record must **not** carry: it is how the room describes itself,
/// not one of its records (`RoomProfileStatement` item 1).
const RECORD_MEMBERS: &[&str] = &[
    "title",
    "description",
    "body",
    "tags",
    "file",
    "basis",
    "confidence",
    "evidence",
    "validFor",
    "validUntil",
];

/// The members a `RoomProfileStatement` may carry.
const STATEMENT_MEMBERS: &[&str] = &["profile", "issuedAt", "authority", "padding", "ext"];

/// The suites a body may be signed with: `eddsa-jcs-2022`, which every writer supports, and
/// `ecdsa-jcs-2019`, for a hardware-backed signer.
const ACCEPTED_SUITES: [&str; 2] = ["eddsa-jcs-2022", "ecdsa-jcs-2019"];

/// Why a reader ignored a record at a profile location — the response's `rejected[].reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// Not a `SealedRecordBody`, an unknown member, a profile that breaks its schema, or a
    /// record that does not open.
    Malformed,
    /// Opened and signed, but not a profile: no `roomProfile`, or a record's members beside it.
    NotProfile,
    /// The body's proof is missing, does not verify for `assertionMethod`, or is not
    /// `author`'s.
    Signature,
    /// Signed for another room, key or version than the one it was read from.
    Location,
    /// On an `attributed` room, signed by someone other than the author the host recorded.
    AuthorMismatch,
    /// Sealed under another epoch than the one whose key located it.
    EpochMismatch,
    /// The statement's chain does not confer `curate` or `admin` on its author at
    /// `issuedAt` — most often a member holding only `write`.
    NoAuthority,
    /// `issuedAt` outside `[updatedAt − 1h, updatedAt + 5m]`.
    Timing,
    /// A link of the chain was revoked at or before `issuedAt`.
    Revoked,
}

impl Rejection {
    /// The wire form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::NotProfile => "notProfile",
            Self::Signature => "signature",
            Self::Location => "location",
            Self::AuthorMismatch => "authorMismatch",
            Self::EpochMismatch => "epochMismatch",
            Self::NoAuthority => "noAuthority",
            Self::Timing => "timing",
            Self::Revoked => "revoked",
        }
    }

    /// Whether this is somebody writing what the room is called without the standing to —
    /// the reasons `rooms/keys/profile/read` asks a member's surface to tell them about.
    pub fn is_attempted_rename(self) -> bool {
        matches!(self, Self::NoAuthority | Self::Timing | Self::Revoked)
    }
}

/// A record at a profile location that a reader ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    pub reason: Rejection,
    /// The body's author, once its signature showed it is theirs; otherwise the author the
    /// host recorded, where the tier discloses one.
    pub author: Option<String>,
}

impl Rejected {
    fn new(reason: Rejection, author: Option<&str>) -> Self {
        Self {
            reason,
            author: author.map(str::to_string),
        }
    }
}

/// Where a record was read from, and what its host said about it.
#[derive(Debug, Clone)]
pub struct ReadAt<'a> {
    pub room_id: &'a str,
    pub key: &'a str,
    pub version: u64,
    /// On a sealed tier, the epoch whose storage key located the record; `None` on `open`.
    pub located_at: Option<u32>,
    /// On a sealed tier, the epoch the record says it was sealed under.
    pub sealed_epoch: Option<u32>,
    /// The author the host recorded (`attributed`, `open`); `None` on `private`.
    pub host_author: Option<&'a str>,
    /// The host's `updatedAt` for the record, RFC 3339.
    pub updated_at: &'a str,
}

/// A profile a reader accepted.
#[derive(Debug, Clone, PartialEq)]
pub struct Accepted {
    /// The `RoomProfile`, exactly as signed.
    pub profile: Value,
    pub author: String,
    /// RFC 3339.
    pub issued_at: String,
}

/// Every check `RoomProfileStatement` sets, on a record already opened (`plaintext` is the
/// signed body's UTF-8 JSON) — the `SealedRecordBody` reading rules (1)–(4) and items 1–5.
///
/// `resolver` resolves the author's key for the body's proof; `keys` resolves each link's
/// issuer key for the authority chain. Item 5 (revocation) applies only to a reader holding a
/// `RevocationList` for the room, and this VTA holds none, so it never refuses as `revoked`.
pub async fn check_statement(
    plaintext: &[u8],
    at: &ReadAt<'_>,
    resolver: &(dyn vta_sdk::trust_task_proof::PurposeVmResolver + '_),
    keys: &dyn vti_rooms_dtg::VerificationKeys,
) -> Result<Accepted, Rejected> {
    let host_author = at.host_author;
    // Rule (1): a `SealedRecordBody`, no unknown member.
    let signed: Value = serde_json::from_slice(plaintext)
        .map_err(|_| Rejected::new(Rejection::Malformed, host_author))?;
    let Some(obj) = signed.as_object() else {
        return Err(Rejected::new(Rejection::Malformed, host_author));
    };
    if obj.keys().any(|k| !BODY_MEMBERS.contains(&k.as_str())) {
        return Err(Rejected::new(Rejection::Malformed, host_author));
    }
    let author = obj.get("author").and_then(Value::as_str);
    let (Some(author), Some(room_id), Some(key), Some(version)) = (
        author.filter(|a| a.starts_with("did:")),
        obj.get("roomId").and_then(Value::as_str),
        obj.get("key").and_then(Value::as_str),
        obj.get("version").and_then(Value::as_u64),
    ) else {
        return Err(Rejected::new(Rejection::Malformed, host_author));
    };

    // Rule (2): the author's proof, for `assertionMethod`, in an accepted suite.
    let verified = vta_sdk::trust_task_proof::verify_proof_set(
        &signed,
        vta_sdk::trust_task_proof::ProofPurpose::AssertionMethod,
        resolver,
    )
    .await
    .map_err(|_| Rejected::new(Rejection::Signature, host_author))?;
    let suites_ok = verified.proofs().iter().all(|p| {
        serde_json::to_value(p.cryptosuite)
            .ok()
            .and_then(|v| v.as_str().map(|s| ACCEPTED_SUITES.contains(&s)))
            .unwrap_or(false)
    });
    if !suites_ok || verified.signer() != author {
        return Err(Rejected::new(Rejection::Signature, host_author));
    }
    // From here the author is proven, so it is the one a rejection names.
    let named = Some(author);

    // Rule (3): signed for where it was read from.
    if room_id != at.room_id || key != at.key || version != at.version {
        return Err(Rejected::new(Rejection::Location, named));
    }
    // Rule (4): on a tier where the host records an author, the same one.
    if let Some(recorded) = host_author
        && recorded != author
    {
        return Err(Rejected::new(Rejection::AuthorMismatch, named));
    }

    // Item 1: a profile, and nothing a record carries.
    let Some(statement) = obj.get("roomProfile") else {
        return Err(Rejected::new(Rejection::NotProfile, named));
    };
    if RECORD_MEMBERS.iter().any(|m| obj.contains_key(*m)) {
        return Err(Rejected::new(Rejection::NotProfile, named));
    }
    let Some(st) = statement.as_object() else {
        return Err(Rejected::new(Rejection::Malformed, named));
    };
    if st.keys().any(|k| !STATEMENT_MEMBERS.contains(&k.as_str())) {
        return Err(Rejected::new(Rejection::Malformed, named));
    }
    let Some(profile) = st.get("profile") else {
        return Err(Rejected::new(Rejection::Malformed, named));
    };
    // The profile against its own schema, through the generated type.
    if serde_json::from_value::<
        trust_tasks_rs::specs::rooms::keys::profile::read::v0_1::RoomProfile,
    >(profile.clone())
    .is_err()
    {
        return Err(Rejected::new(Rejection::Malformed, named));
    }
    let Some(issued_at) = st
        .get("issuedAt")
        .and_then(Value::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc))
    else {
        return Err(Rejected::new(Rejection::Malformed, named));
    };
    let authority: Option<Vec<String>> = st.get("authority").and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(|l| l.as_str().map(str::to_string))
            .collect()
    });
    let Some(authority) = authority.filter(|a| {
        !a.is_empty()
            && Some(a.len()) == st["authority"].as_array().map(Vec::len)
            && a.len() <= vti_rooms::profile::MAX_AUTHORITY_LINKS
    }) else {
        return Err(Rejected::new(Rejection::Malformed, named));
    };
    if st.get("padding").is_some_and(|p| {
        p.as_str()
            .is_none_or(|s| s.len() > vti_rooms::profile::MAX_PADDING)
    }) {
        return Err(Rejected::new(Rejection::Malformed, named));
    }

    // Item 2: on a sealed tier, sealed under the epoch whose key located it.
    if at.located_at != at.sealed_epoch {
        return Err(Rejected::new(Rejection::EpochMismatch, named));
    }

    // Item 4: `issuedAt` within the window the host's `updatedAt` allows, so the statement
    // cannot be back-dated into a grant its author no longer holds.
    let Some(updated) = DateTime::parse_from_rfc3339(at.updated_at)
        .ok()
        .map(|d| d.timestamp())
    else {
        return Err(Rejected::new(Rejection::Timing, named));
    };
    if !vti_rooms::profile::issued_within_window(issued_at.timestamp(), updated) {
        return Err(Rejected::new(Rejection::Timing, named));
    }

    // Item 3: the chain confers `curate` or `admin` on the author, rooted in the room, every
    // link valid at `issuedAt`.
    if vti_rooms_dtg::profile::verify_profile_authority(
        &authority, at.room_id, author, issued_at, keys,
    )
    .await
    .is_err()
    {
        return Err(Rejected::new(Rejection::NoAuthority, named));
    }

    Ok(Accepted {
        profile: profile.clone(),
        author: author.to_string(),
        issued_at: issued_at.to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

/// The unsigned `SealedRecordBody` carrying `profile` as its author's statement — what
/// `rooms/keys/profile/write` signs and seals (sealed tiers) or stores as `cleartext.body`
/// (`open`). `authority` is the author's chain conferring `curate` or `admin`, leaf first.
pub fn statement_body(
    room_id: &str,
    key: &str,
    version: u64,
    author: &str,
    profile: &Value,
    issued_at: DateTime<Utc>,
    authority: Vec<String>,
) -> Value {
    serde_json::json!({
        "roomId": room_id,
        "key": key,
        "version": version,
        "author": author,
        "roomProfile": {
            "profile": profile,
            "issuedAt": issued_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            "authority": authority,
            "padding": "",
        },
    })
}

/// Sign `body` with `sign` (which returns the signed body's UTF-8 JSON), padding it so the
/// signed bytes are a multiple of [`vti_rooms::profile::PADDING_BLOCK`] — so a host comparing
/// ciphertext lengths learns nothing about how long the name or the description is.
///
/// A proof's length varies by a byte or two from one signature to the next, so the padding
/// is measured on what was signed and corrected; after a few attempts the closest result is
/// kept, because padding is a SHOULD and refusing to name the room over it would be worse.
pub async fn sign_padded<F, Fut>(mut body: Value, sign: F) -> Result<Vec<u8>, AppError>
where
    F: Fn(Value) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, AppError>>,
{
    use vti_rooms::profile::{MAX_PADDING, PADDING_BLOCK};
    const ATTEMPTS: usize = 8;
    let mut signed = sign(body.clone()).await?;
    let mut target = signed.len().div_ceil(PADDING_BLOCK) * PADDING_BLOCK;
    let mut padding = 0usize;
    for _ in 0..ATTEMPTS {
        let len = signed.len();
        if len % PADDING_BLOCK == 0 {
            break;
        }
        // A longer proof than last time can overshoot the block: aim for the next one.
        if len > target {
            target += PADDING_BLOCK;
        }
        padding = (padding + (target - len)).min(MAX_PADDING);
        body["roomProfile"]["padding"] = Value::String(" ".repeat(padding));
        signed = sign(body.clone()).await?;
        if padding == MAX_PADDING {
            break;
        }
    }
    Ok(signed)
}

/// What a reader found at the profile's locations, in the walk's order — the response of
/// `rooms/keys/profile/read`, before it is put on the wire.
#[derive(Debug, Clone, Default)]
pub struct Resolution {
    /// `found`, `cleared` or `absent`.
    pub status: &'static str,
    pub accepted: Option<Accepted>,
    /// Where the returned profile (or the retraction) was: epoch and version.
    pub epoch: Option<u32>,
    pub version: Option<u64>,
    /// Whether the profile returned was found below the epoch the reader is at.
    pub stale: bool,
    /// The epochs searched, from and to; `None` on an `open` room.
    pub searched: Option<(u32, u32)>,
    /// Each record ignored, newest first, at most eight: (epoch, version, rejection).
    pub rejected: Vec<(Option<u32>, u64, Rejected)>,
}

/// The most rejections a response lists (its schema's `maxItems`).
pub const MAX_REJECTED: usize = 8;

impl Resolution {
    /// The response payload of `rooms/keys/profile/read/0.1`, less `verification`, which the
    /// handler adds from the host's reply.
    pub fn to_payload(&self, room_id: &str) -> Value {
        let mut out = serde_json::json!({ "roomId": room_id, "status": self.status });
        if let Some(a) = &self.accepted {
            out["profile"] = a.profile.clone();
            out["author"] = Value::String(a.author.clone());
            out["issuedAt"] = Value::String(a.issued_at.clone());
        }
        if let Some(e) = self.epoch {
            out["epoch"] = serde_json::json!(e);
        }
        if let Some(v) = self.version {
            out["version"] = serde_json::json!(v);
        }
        // `stale` is a statement about epochs: absent on an `open` room (which searched
        // none), and whenever nothing was found.
        if self.status == "found" && self.searched.is_some() {
            out["stale"] = Value::Bool(self.stale);
        }
        if let Some((from, to)) = self.searched {
            out["searched"] = serde_json::json!({ "fromEpoch": from, "toEpoch": to });
        }
        if !self.rejected.is_empty() {
            out["rejected"] = Value::Array(
                self.rejected
                    .iter()
                    .take(MAX_REJECTED)
                    .map(|(epoch, version, r)| {
                        let mut item = serde_json::json!({
                            "version": version,
                            "reason": r.reason.as_str(),
                        });
                        if let Some(e) = epoch {
                            item["epoch"] = serde_json::json!(e);
                        }
                        if let Some(a) = &r.author {
                            item["author"] = Value::String(a.clone());
                        }
                        item
                    })
                    .collect(),
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtg_credentials::{DTGCredential, IssuerScope};
    use vta_sdk::trust_task_proof::TrustTaskVmResolver;
    use vti_rooms_dtg::test_support::Party;

    /// `did:key` resolution for the chain: a key is its own document.
    struct DidKeys;

    #[async_trait::async_trait]
    impl vti_rooms_dtg::VerificationKeys for DidKeys {
        async fn public_key(
            &self,
            vm: &str,
            _purpose: vti_common::auth::ProofPurpose,
        ) -> Result<Vec<u8>, AppError> {
            let did = vm.split('#').next().unwrap_or_default();
            let mb = did
                .strip_prefix("did:key:")
                .ok_or_else(|| AppError::NotFound(did.to_string()))?;
            vta_sdk::did_key::decode_ed25519_public_key_multibase(mb)
                .map(|k| k.to_vec())
                .map_err(|e| AppError::NotFound(e.to_string()))
        }
    }

    const KEY: &str = "Qm4c8XkR2pVt7sLw0aJbYg";

    struct Fx {
        room: Party,
        curator: Party,
        writer: Party,
        curator_chain: Vec<String>,
        writer_chain: Vec<String>,
    }

    async fn grant(room: &Party, subject: &str, actions: &[&str]) -> String {
        let now = Utc::now();
        let mut vac = DTGCredential::new_vac(
            room.did.clone(),
            IssuerScope::Public,
            subject.into(),
            room.did.clone(),
            actions.iter().map(|a| a.to_string()).collect(),
            now - chrono::Duration::days(1),
            now + chrono::Duration::days(1),
        )
        .unwrap()
        .with_id(format!("urn:example:{subject}"));
        vac.sign(&room.secret, None).await.unwrap();
        serde_json::to_string(&vac).unwrap()
    }

    async fn fx() -> Fx {
        let room = Party::new();
        let curator = Party::new();
        let writer = Party::new();
        let curator_chain = vec![grant(&room, &curator.did, &["read", "write", "curate"]).await];
        let writer_chain = vec![grant(&room, &writer.did, &["read", "write"]).await];
        Fx {
            room,
            curator,
            writer,
            curator_chain,
            writer_chain,
        }
    }

    fn holder(p: &Party) -> vta_sdk::trust_task_sign::HolderKey {
        vta_sdk::trust_task_sign::HolderKey::from_did_key(&p.did, p.secret_multibase.clone())
            .expect("a did:key holder")
    }

    async fn signed(by: &Party, body: Value) -> Vec<u8> {
        let key = holder(by);
        sign_padded(body, |b| {
            let key = key.clone();
            async move {
                let mut b = b;
                vta_sdk::trust_task_sign::sign_object_for_assertion(&mut b, &key)
                    .await
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                Ok(serde_json::to_vec(&b).unwrap())
            }
        })
        .await
        .unwrap()
    }

    fn name(n: &str) -> Value {
        serde_json::json!({ "name": n, "description": "Papers for the board", "tags": ["board"], "emoji": "📋" })
    }

    fn at<'a>(f: &'a Fx, host_author: Option<&'a str>, updated: &'a str) -> ReadAt<'a> {
        ReadAt {
            room_id: &f.room.did,
            key: KEY,
            version: 7,
            located_at: Some(3),
            sealed_epoch: Some(3),
            host_author,
            updated_at: updated,
        }
    }

    async fn check(_f: &Fx, plaintext: &[u8], at: &ReadAt<'_>) -> Result<Accepted, Rejected> {
        check_statement(
            plaintext,
            at,
            &TrustTaskVmResolver::did_key_only(),
            &DidKeys,
        )
        .await
    }

    fn now_s() -> String {
        Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
    }

    #[tokio::test]
    async fn a_curators_profile_is_accepted_and_padded_to_a_block() {
        let f = fx().await;
        let body = statement_body(
            &f.room.did,
            KEY,
            7,
            &f.curator.did,
            &name("Board pack"),
            Utc::now(),
            f.curator_chain.clone(),
        );
        let bytes = signed(&f.curator, body).await;
        assert_eq!(bytes.len() % 1024, 0, "padded to a 1 KiB multiple");
        // A proof's length varies from one signature to the next; the padding converges on
        // a block whatever the name's length.
        for n in 0..24 {
            let b = statement_body(
                &f.room.did,
                KEY,
                7,
                &f.curator.did,
                &name(&"x".repeat(1 + n * 5)),
                Utc::now(),
                f.curator_chain.clone(),
            );
            assert_eq!(
                signed(&f.curator, b).await.len() % 1024,
                0,
                "name of {}",
                1 + n * 5
            );
        }
        let now = now_s();
        let ok = check(&f, &bytes, &at(&f, Some(&f.curator.did), &now))
            .await
            .expect("accepted");
        assert_eq!(ok.profile, name("Board pack"));
        assert_eq!(ok.author, f.curator.did);
    }

    /// **The forged rename.** A member holding `write` stores a record at the profile's
    /// location, signed by them with their own chain: readers ignore it as `noAuthority` and
    /// name them.
    #[tokio::test]
    async fn a_write_only_members_rename_is_rejected_as_no_authority() {
        let f = fx().await;
        let body = statement_body(
            &f.room.did,
            KEY,
            7,
            &f.writer.did,
            &name("Mallory's room"),
            Utc::now(),
            f.writer_chain.clone(),
        );
        let bytes = signed(&f.writer, body).await;
        let now = now_s();
        let r = check(&f, &bytes, &at(&f, Some(&f.writer.did), &now))
            .await
            .expect_err("write alone never names the room");
        assert_eq!(r.reason, Rejection::NoAuthority);
        assert_eq!(r.author.as_deref(), Some(f.writer.did.as_str()));
        assert!(r.reason.is_attempted_rename());

        // Carrying the curator's chain instead does not help: the leaf is not theirs.
        let body = statement_body(
            &f.room.did,
            KEY,
            7,
            &f.writer.did,
            &name("Mallory's room"),
            Utc::now(),
            f.curator_chain.clone(),
        );
        let bytes = signed(&f.writer, body).await;
        let r = check(&f, &bytes, &at(&f, Some(&f.writer.did), &now))
            .await
            .unwrap_err();
        assert_eq!(r.reason, Rejection::NoAuthority);
    }

    /// The curator's body signed by somebody else is a signature failure, and one the host
    /// attributes to another member an author mismatch.
    #[tokio::test]
    async fn the_body_must_be_signed_by_its_author_and_match_the_host() {
        let f = fx().await;
        let body = statement_body(
            &f.room.did,
            KEY,
            7,
            &f.curator.did,
            &name("Board"),
            Utc::now(),
            f.curator_chain.clone(),
        );
        let forged = signed(&f.writer, body.clone()).await;
        let now = now_s();
        assert_eq!(
            check(&f, &forged, &at(&f, None, &now))
                .await
                .unwrap_err()
                .reason,
            Rejection::Signature
        );

        let honest = signed(&f.curator, body).await;
        assert_eq!(
            check(&f, &honest, &at(&f, Some(&f.writer.did), &now))
                .await
                .unwrap_err()
                .reason,
            Rejection::AuthorMismatch,
            "an attributed host recorded somebody else as the author"
        );
        // On `private` the host records nobody, and the signature is the attribution.
        check(&f, &honest, &at(&f, None, &now))
            .await
            .expect("private");
    }

    /// Copied to another key or version, or found under another epoch's key: refused.
    #[tokio::test]
    async fn a_relocated_profile_is_refused() {
        let f = fx().await;
        let body = statement_body(
            &f.room.did,
            KEY,
            7,
            &f.curator.did,
            &name("Board"),
            Utc::now(),
            f.curator_chain.clone(),
        );
        let bytes = signed(&f.curator, body).await;
        let now = now_s();
        let mut moved = at(&f, None, &now);
        moved.version = 8;
        assert_eq!(
            check(&f, &bytes, &moved).await.unwrap_err().reason,
            Rejection::Location
        );
        let mut other_epoch = at(&f, None, &now);
        other_epoch.sealed_epoch = Some(2);
        assert_eq!(
            check(&f, &bytes, &other_epoch).await.unwrap_err().reason,
            Rejection::EpochMismatch
        );
    }

    /// `issuedAt` within `[updatedAt − 1h, updatedAt + 5m]`: a statement back-dated past the
    /// window, or dated well after the host stored it, is refused as `timing`.
    #[tokio::test]
    async fn issued_at_is_bounded_by_the_hosts_updated_at() {
        let f = fx().await;
        let now = Utc::now();
        for (issued, ok) in [
            (now - chrono::Duration::minutes(59), true),
            (now - chrono::Duration::minutes(61), false),
            (now + chrono::Duration::minutes(4), true),
            (now + chrono::Duration::minutes(6), false),
        ] {
            let body = statement_body(
                &f.room.did,
                KEY,
                7,
                &f.curator.did,
                &name("Board"),
                issued,
                f.curator_chain.clone(),
            );
            let bytes = signed(&f.curator, body).await;
            let updated = now.to_rfc3339_opts(SecondsFormat::Secs, true);
            let got = check(&f, &bytes, &at(&f, None, &updated)).await;
            match ok {
                true => {
                    got.expect("inside the window");
                }
                false => assert_eq!(got.unwrap_err().reason, Rejection::Timing),
            }
        }
    }

    /// A record — not a profile — at the location, or a profile carrying record members, is
    /// `notProfile`; an unknown member or a profile breaking its schema is `malformed`.
    #[tokio::test]
    async fn shape_failures_are_named() {
        let f = fx().await;
        let now = now_s();
        // A record body, signed directly: `sign_padded` pads a statement.
        let mut plain = serde_json::json!({
            "roomId": f.room.did, "key": KEY, "version": 7, "author": f.curator.did,
            "title": "a record",
        });
        vta_sdk::trust_task_sign::sign_object_for_assertion(&mut plain, &holder(&f.curator))
            .await
            .unwrap();
        assert_eq!(
            check(
                &f,
                &serde_json::to_vec(&plain).unwrap(),
                &at(&f, None, &now)
            )
            .await
            .unwrap_err()
            .reason,
            Rejection::NotProfile
        );

        let mut both = statement_body(
            &f.room.did,
            KEY,
            7,
            &f.curator.did,
            &name("Board"),
            Utc::now(),
            f.curator_chain.clone(),
        );
        both["title"] = Value::String("and a record".into());
        let bytes = signed(&f.curator, both).await;
        assert_eq!(
            check(&f, &bytes, &at(&f, None, &now))
                .await
                .unwrap_err()
                .reason,
            Rejection::NotProfile
        );

        let mut unknown = statement_body(
            &f.room.did,
            KEY,
            7,
            &f.curator.did,
            &name("Board"),
            Utc::now(),
            f.curator_chain.clone(),
        );
        unknown["surprise"] = Value::Bool(true);
        let bytes = signed(&f.curator, unknown).await;
        assert_eq!(
            check(&f, &bytes, &at(&f, None, &now))
                .await
                .unwrap_err()
                .reason,
            Rejection::Malformed
        );

        let bad_profile = statement_body(
            &f.room.did,
            KEY,
            7,
            &f.curator.did,
            &serde_json::json!({ "name": "" }),
            Utc::now(),
            f.curator_chain.clone(),
        );
        let bytes = signed(&f.curator, bad_profile).await;
        assert_eq!(
            check(&f, &bytes, &at(&f, None, &now))
                .await
                .unwrap_err()
                .reason,
            Rejection::Malformed,
            "an empty name breaks RoomProfile"
        );

        assert_eq!(
            check(&f, b"not json", &at(&f, None, &now))
                .await
                .unwrap_err()
                .reason,
            Rejection::Malformed
        );
    }

    #[test]
    fn the_payload_lists_at_most_eight_rejections_and_only_what_it_has() {
        let mut r = Resolution {
            status: "absent",
            searched: Some((9, 9)),
            ..Default::default()
        };
        assert_eq!(
            r.to_payload("did:example:room"),
            serde_json::json!({
                "roomId": "did:example:room", "status": "absent",
                "searched": { "fromEpoch": 9, "toEpoch": 9 },
            })
        );
        for v in 0..12 {
            r.rejected.push((
                Some(9),
                v + 1,
                Rejected::new(Rejection::NoAuthority, Some("did:example:m")),
            ));
        }
        assert_eq!(
            r.to_payload("did:example:room")["rejected"]
                .as_array()
                .unwrap()
                .len(),
            8
        );
    }
}
