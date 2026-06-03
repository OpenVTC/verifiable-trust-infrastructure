//! Consent records — ISO/IEC 27560 consent receipts expressed with the W3C
//! DPV vocabulary (task 1.3.5,
//! `docs/05-design-notes/vti-credential-architecture.md` §7a).
//!
//! Consent is a **first-class, persisted, signed, withdrawable, auditable
//! record** — not an ephemeral parameter. Every disclosure the VTA makes on
//! the holder's behalf is gated by one of these records. The shape follows a
//! pragmatic 27560/DPV subset: a `dpv:ConsentRecord` naming the holder as
//! `dpv:hasDataSubject`, a `dpv:hasProcess` describing *what* (the reveal set
//! `dpv:hasPersonalData`), *to whom* (`dpv:hasRecipient`), *why*
//! (`dpv:hasPurpose`), *how* (`dpv:hasProcessing = dpv:Disclose`), and *until
//! when* (`dpv:hasStorageCondition.dct:valid`), plus a `dpv:hasStatus` event
//! log (`dpv:ConsentGiven`, later possibly `dpv:ConsentWithdrawn`).
//!
//! ## Non-repudiation from day one
//!
//! Every record carries a holder `eddsa-jcs-2022` Data Integrity proof,
//! signed with the holder's VTA-managed key. So a consent record is a
//! **signed consent receipt**: the holder cannot later deny it, and any party
//! can verify it offline. The proof is the non-repudiation anchor — [`get`]
//! re-verifies it on every read, and [`authorizes`] is only ever called on a
//! record that [`get`] has already verified.
//!
//! ## Storage
//!
//! Records live in the existing `vault` keyspace under the disjoint
//! `consent:<id>` key namespace — mirroring the `cred:<id>` (primary) and
//! `idx:<…>` (secondary index) namespaces the credential store already uses,
//! and the `vault:<id>` namespace the password-manager `VaultEntry` records
//! use. The whole record value (which carries the holder DID, the verifier
//! DID, and the reveal set) is encrypted at rest by the keyspace's
//! AES-256-GCM wrapper.
//!
//! ## Security / privacy invariants (`vti-credential-architecture.md` §14)
//!
//! - [`list`] / [`get`] are the **holder's own local audit surface** — never
//!   a cross-trust-boundary enumeration. They scan only this VTA's own
//!   `consent:` namespace; there is no wire endpoint that returns them.
//! - [`authorizes`] returns `true` **only** for a record that is given
//!   (latest status `dpv:ConsentGiven`, not withdrawn), unexpired
//!   (`dct:valid > now`), whose `dpv:hasRecipient` matches the verifier, and
//!   whose `dpv:hasPersonalData` is a superset of the requested claims. An
//!   expired or withdrawn record authorizes **nothing**.
//! - [`withdraw`] appends a re-signed `dpv:ConsentWithdrawn` status event;
//!   the record stays for audit but no longer authorizes disclosure.

use affinidi_crypto::did_key as did_key_helpers;
use affinidi_data_integrity::{
    DataIntegrityProof, SignOptions, VerifyOptions, crypto_suites::CryptoSuite,
};
use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// The DPV `@context` URL. The pragmatic 27560/DPV subset uses DPV terms
/// (`dpv:…`) and Dublin Core terms (`dct:…`).
const DPV_CONTEXT: &str = "https://w3id.org/dpv";
/// Dublin Core terms context — supplies `dct:identifier`, `dct:conformsTo`,
/// `dct:valid`, `dct:date`.
const DCT_CONTEXT: &str = "http://purl.org/dc/terms/";
/// The schema the record conforms to (`dct:conformsTo`). Names the
/// 27560/DPV consent-record guide this shape is a subset of.
const CONFORMS_TO: &str = "https://w3c.github.io/dpv/guides/consent-27560";

/// Primary-key prefix for consent records. Disjoint from `cred:` /
/// `idx:` (the credential store) and `vault:` (the password manager).
const RECORD_PREFIX: &str = "consent:";

/// `consent:<id>` — the primary key for one consent record.
fn record_key(id: &str) -> Vec<u8> {
    format!("{RECORD_PREFIX}{id}").into_bytes()
}

/// A single `dpv:hasStatus` event. The status log is append-only: the record
/// is born with `dpv:ConsentGiven` and may later gain a `dpv:ConsentWithdrawn`
/// event. The *latest* event is authoritative for [`authorizes`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentStatusEvent {
    /// `dpv:ConsentGiven` or `dpv:ConsentWithdrawn`.
    #[serde(rename = "@type")]
    pub event_type: ConsentStatusType,
    /// RFC-3339 timestamp of the event (`dct:date`).
    #[serde(rename = "dct:date")]
    pub date: String,
}

/// The lifecycle status of a consent record's latest event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentStatusType {
    /// Consent has been given and (subject to expiry) authorizes disclosure.
    #[serde(rename = "dpv:ConsentGiven")]
    ConsentGiven,
    /// Consent has been withdrawn; the record is retained for audit but no
    /// longer authorizes any disclosure.
    #[serde(rename = "dpv:ConsentWithdrawn")]
    ConsentWithdrawn,
}

/// The `dpv:hasStorageCondition` — currently just the validity window
/// (`dct:valid`, an RFC-3339 expiry). An expired record authorizes nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageCondition {
    /// RFC-3339 expiry. `authorizes` requires `now < dct:valid`.
    #[serde(rename = "dct:valid")]
    pub valid: String,
}

/// The `dpv:hasProcess` block — the *what / to whom / why / how / until*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentProcess {
    #[serde(rename = "@type")]
    pub type_: ProcessType,
    /// The verifier's stated purpose, shown to the holder (purpose binding).
    #[serde(rename = "dpv:hasPurpose")]
    pub purpose: String,
    /// The reveal set — the exact claim names being disclosed.
    #[serde(rename = "dpv:hasPersonalData")]
    pub personal_data: Vec<String>,
    /// The verifier DID the disclosure is authorized *to*.
    #[serde(rename = "dpv:hasRecipient")]
    pub recipient: String,
    /// Always `dpv:Disclose` for a presentation-consent record.
    #[serde(rename = "dpv:hasProcessing")]
    pub processing: ProcessingType,
    /// Validity / storage condition (carries `dct:valid`).
    #[serde(rename = "dpv:hasStorageCondition")]
    pub storage_condition: StorageCondition,
}

/// `@type` of the process block. Fixed to `dpv:Process`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessType {
    #[serde(rename = "dpv:Process")]
    Process,
}

/// The processing operation. Fixed to `dpv:Disclose` for disclosure consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessingType {
    #[serde(rename = "dpv:Disclose")]
    Disclose,
}

/// `@type` of the record. Fixed to `dpv:ConsentRecord`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordType {
    #[serde(rename = "dpv:ConsentRecord")]
    ConsentRecord,
}

/// An ISO/IEC 27560 consent record (W3C DPV shape) — a signed consent
/// receipt. Serializes to the JSON-LD shape in
/// `vti-credential-architecture.md` §7a. The `proof` is an `eddsa-jcs-2022`
/// Data Integrity proof by the holder over the record with `proof` removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRecord {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "@type")]
    pub type_: RecordType,
    /// Local record id (`dct:identifier`). Primary key under `consent:<id>`.
    #[serde(rename = "dct:identifier")]
    pub identifier: String,
    #[serde(rename = "dct:conformsTo")]
    pub conforms_to: String,
    /// The holder DID — the data subject whose claims are being disclosed.
    #[serde(rename = "dpv:hasDataSubject")]
    pub data_subject: String,
    #[serde(rename = "dpv:hasProcess")]
    pub process: ConsentProcess,
    /// The status event log, oldest first. Always begins with
    /// `dpv:ConsentGiven`; the *last* element is the authoritative status.
    #[serde(rename = "dpv:hasStatus")]
    pub status: Vec<ConsentStatusEvent>,
    /// Holder `eddsa-jcs-2022` Data Integrity proof. `Value::Null` only on
    /// the transient unsigned form used internally before signing.
    pub proof: Value,
}

impl ConsentRecord {
    /// The authoritative (latest) status event, or `None` if the log is empty
    /// (which a well-formed record never is — it is born with
    /// `dpv:ConsentGiven`).
    fn latest_status(&self) -> Option<&ConsentStatusEvent> {
        self.status.last()
    }

    /// True when the latest status is `dpv:ConsentGiven` (i.e. not withdrawn).
    pub fn is_given(&self) -> bool {
        matches!(
            self.latest_status().map(|s| s.event_type),
            Some(ConsentStatusType::ConsentGiven)
        )
    }

    /// Serialize the record with the `proof` field removed — the exact shape
    /// the holder signs / a verifier re-derives. JCS is sensitive to field
    /// presence, so sign-time and verify-time must both strip `proof`.
    fn signing_doc(&self) -> Result<Value, AppError> {
        let mut doc = serde_json::to_value(self)
            .map_err(|e| AppError::Internal(format!("serialize consent record: {e}")))?;
        if let Some(obj) = doc.as_object_mut() {
            obj.remove("proof");
        }
        Ok(doc)
    }

    /// Re-sign the record in place with the holder key. Used by [`create`]
    /// (first signature) and [`withdraw`] (re-signature after the status log
    /// changes). The `proof` field is excluded from the signed bytes.
    async fn sign_with(&mut self, holder_key: &Secret) -> Result<(), AppError> {
        self.proof = Value::Null;
        let signing_doc = self.signing_doc()?;
        let proof = DataIntegrityProof::sign(
            &signing_doc,
            holder_key,
            SignOptions::new()
                .with_proof_purpose("assertionMethod")
                .with_cryptosuite(CryptoSuite::EddsaJcs2022),
        )
        .await
        .map_err(|e| AppError::Internal(format!("sign consent record: {e}")))?;
        self.proof = serde_json::to_value(&proof)
            .map_err(|e| AppError::Internal(format!("serialize consent proof: {e}")))?;
        Ok(())
    }

    /// Verify the holder Data Integrity proof — the non-repudiation anchor.
    ///
    /// Checks: the proof is `eddsa-jcs-2022`; its `verificationMethod` lives
    /// under the `dpv:hasDataSubject` (holder) DID — so a proof by some other
    /// key cannot be smuggled in behind a forged `hasDataSubject`; and the
    /// signature verifies over the record with `proof` stripped.
    pub fn verify_proof(&self) -> Result<(), AppError> {
        let proof: DataIntegrityProof = serde_json::from_value(self.proof.clone())
            .map_err(|e| AppError::Validation(format!("parse consent proof: {e}")))?;

        if !matches!(proof.cryptosuite, CryptoSuite::EddsaJcs2022) {
            return Err(AppError::Validation(format!(
                "unsupported consent cryptosuite {:?} (expected eddsa-jcs-2022)",
                proof.cryptosuite
            )));
        }

        // The proof's verificationMethod DID must be the holder DID. Without
        // this, a valid proof by an unrelated key would verify against a
        // record whose hasDataSubject was set to the holder.
        let vm_did = proof
            .verification_method
            .split_once('#')
            .map(|(d, _)| d)
            .ok_or_else(|| {
                AppError::Validation("consent proof verificationMethod missing '#'".into())
            })?;
        if vm_did != self.data_subject {
            return Err(AppError::Validation(format!(
                "consent proof verificationMethod DID '{vm_did}' does not match dataSubject '{}'",
                self.data_subject
            )));
        }

        let holder_pub = did_key_helpers::did_key_to_ed25519_pub(&self.data_subject)
            .map_err(|e| AppError::Validation(format!("consent dataSubject not a did:key: {e}")))?;

        let signing_doc = self.signing_doc()?;
        proof
            .verify_with_public_key(&signing_doc, &holder_pub, VerifyOptions::new())
            .map_err(|e| AppError::Validation(format!("consent proof verification failed: {e}")))?;
        Ok(())
    }
}

/// Inputs to [`create`] — the holder's captured authorization decision. The
/// device / plugin gathers these; the VTA constructs, signs, and stores the
/// record.
#[derive(Debug, Clone)]
pub struct ConsentGrant<'a> {
    /// The holder DID — `dpv:hasDataSubject`. Must be a `did:key` (the holder
    /// key signs the receipt).
    pub holder_did: &'a str,
    /// The verifier DID the disclosure is authorized to — `dpv:hasRecipient`.
    pub verifier_did: &'a str,
    /// The verifier's stated purpose — `dpv:hasPurpose`.
    pub purpose: &'a str,
    /// The exact claim names being disclosed — `dpv:hasPersonalData`.
    pub claims: Vec<String>,
    /// Expiry of the consent (`dct:valid`). After this instant the record
    /// authorizes nothing.
    pub valid_until: DateTime<Utc>,
}

/// Build, sign, and store a consent record on the holder's authorization.
///
/// The record is born with a single `dpv:ConsentGiven` status event, signed
/// with the holder key (`holder_key`, a VTA-managed `Secret`), and persisted
/// under `consent:<id>`. Returns the stored, signed record.
///
/// `holder_key`'s verification method must be under `grant.holder_did` — the
/// signed proof's `verificationMethod` is what [`verify_proof`] binds to the
/// `dataSubject`.
///
/// [`verify_proof`]: ConsentRecord::verify_proof
pub async fn create(
    vault: &KeyspaceHandle,
    grant: &ConsentGrant<'_>,
    holder_key: &Secret,
) -> Result<ConsentRecord, AppError> {
    if grant.holder_did.trim().is_empty() {
        return Err(AppError::Validation(
            "consent holder_did must be non-empty".into(),
        ));
    }
    if grant.verifier_did.trim().is_empty() {
        return Err(AppError::Validation(
            "consent verifier_did must be non-empty".into(),
        ));
    }
    if grant.claims.is_empty() {
        return Err(AppError::Validation(
            "consent claims must be non-empty (default-deny: an empty reveal set authorizes nothing)"
                .into(),
        ));
    }

    let now = Utc::now();
    let id = format!("urn:uuid:{}", uuid::Uuid::new_v4());

    let mut record = ConsentRecord {
        context: vec![DPV_CONTEXT.to_string(), DCT_CONTEXT.to_string()],
        type_: RecordType::ConsentRecord,
        identifier: id.clone(),
        conforms_to: CONFORMS_TO.to_string(),
        data_subject: grant.holder_did.to_string(),
        process: ConsentProcess {
            type_: ProcessType::Process,
            purpose: grant.purpose.to_string(),
            personal_data: grant.claims.clone(),
            recipient: grant.verifier_did.to_string(),
            processing: ProcessingType::Disclose,
            storage_condition: StorageCondition {
                valid: rfc3339(grant.valid_until),
            },
        },
        status: vec![ConsentStatusEvent {
            event_type: ConsentStatusType::ConsentGiven,
            date: rfc3339(now),
        }],
        proof: Value::Null,
    };

    record.sign_with(holder_key).await?;

    // Belt-and-braces: never store a record we cannot ourselves verify.
    record.verify_proof()?;

    vault.insert(record_key(&id), &record).await?;
    Ok(record)
}

/// Fetch a consent record by id, **re-verifying its holder proof** (the
/// non-repudiation anchor) before returning it. Returns `Ok(None)` for an
/// absent id. A stored record whose proof no longer verifies (tampering,
/// corruption) is surfaced as an error, never silently returned.
///
/// This is the holder's own local audit surface — there is no
/// cross-trust-boundary variant.
pub async fn get(vault: &KeyspaceHandle, id: &str) -> Result<Option<ConsentRecord>, AppError> {
    let Some(record): Option<ConsentRecord> = vault.get(record_key(id)).await? else {
        return Ok(None);
    };
    record.verify_proof()?;
    Ok(Some(record))
}

/// Append a re-signed `dpv:ConsentWithdrawn` status event to the record. The
/// record is retained (audit trail) but [`authorizes`] now returns `false`
/// for it. Re-signs with the holder key so the withdrawn state is itself
/// non-repudiable. Returns `Ok(None)` if no such record exists.
///
/// Idempotent in effect: withdrawing an already-withdrawn record appends a
/// further `dpv:ConsentWithdrawn` event (still not authorizing) — but callers
/// should not rely on a specific event count.
pub async fn withdraw(
    vault: &KeyspaceHandle,
    id: &str,
    holder_key: &Secret,
) -> Result<Option<ConsentRecord>, AppError> {
    let Some(mut record) = get(vault, id).await? else {
        return Ok(None);
    };

    record.status.push(ConsentStatusEvent {
        event_type: ConsentStatusType::ConsentWithdrawn,
        date: rfc3339(Utc::now()),
    });
    record.sign_with(holder_key).await?;
    record.verify_proof()?;

    vault.insert(record_key(id), &record).await?;
    Ok(Some(record))
}

/// List the holder's own consent records (the holder's local audit surface).
///
/// This scans only this VTA's own `consent:` namespace — it is **not** a
/// cross-trust-boundary enumeration (`vti-credential-architecture.md` §14):
/// there is no wire endpoint that returns it, and it only ever sees the
/// holder's own receipts. Each record's holder proof is re-verified; a record
/// whose proof fails is skipped (it cannot be trusted as a receipt) rather
/// than wedging the whole listing.
pub async fn list(vault: &KeyspaceHandle) -> Result<Vec<ConsentRecord>, AppError> {
    let rows = vault
        .prefix_iter_raw(RECORD_PREFIX.as_bytes().to_vec())
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (_key, value) in rows {
        let record: ConsentRecord = match serde_json::from_slice(&value) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if record.verify_proof().is_ok() {
            out.push(record);
        }
    }
    Ok(out)
}

/// The disclosure-gating decision. Returns `true` **only** when *all* hold:
///
/// 1. The record is **given** — latest status is `dpv:ConsentGiven`, not
///    withdrawn.
/// 2. The record is **unexpired** — `dpv:hasStorageCondition.dct:valid > now`.
/// 3. The **recipient matches** — `dpv:hasRecipient == verifier_did`.
/// 4. The requested claims are a **subset** of `dpv:hasPersonalData` — the
///    verifier cannot extract a claim the holder did not consent to.
///
/// Default-deny: any malformed timestamp, a recipient mismatch, a withdrawn
/// or expired record, or a single out-of-scope requested claim returns
/// `false`. The caller is responsible for having obtained the record via
/// [`get`] (which verifies the holder proof) — `authorizes` decides
/// *authority*, not *authenticity*.
pub fn authorizes(
    record: &ConsentRecord,
    verifier_did: &str,
    requested_claims: &[String],
    now: DateTime<Utc>,
) -> bool {
    // 1. Given, not withdrawn.
    if !record.is_given() {
        return false;
    }

    // 2. Unexpired. A non-parseable validity is treated as expired
    //    (default-deny) rather than authorizing.
    let valid_until = match record
        .process
        .storage_condition
        .valid
        .parse::<DateTime<Utc>>()
    {
        Ok(t) => t,
        Err(_) => return false,
    };
    if now >= valid_until {
        return false;
    }

    // 3. Recipient match.
    if record.process.recipient != verifier_did {
        return false;
    }

    // 4. Requested claims ⊆ consented reveal set. An empty request is not a
    //    licence to disclose anything; but it also discloses nothing, so it
    //    is trivially within scope — callers that disclose nothing need no
    //    consent. We still require the request be a subset.
    requested_claims
        .iter()
        .all(|c| record.process.personal_data.contains(c))
}

/// RFC-3339 with second precision and a `Z` suffix — the timestamp shape used
/// throughout the credential plane.
fn rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    /// A fresh tempdir-backed store plus a `vault` keyspace handle.
    fn fresh_vault() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let ks = store.keyspace("vault").expect("vault keyspace");
        (dir, store, ks)
    }

    /// A holder `did:key` + its signing `Secret`, both derived from a fixed
    /// seed so the verification method lands under the returned DID.
    fn holder_identity(seed: [u8; 32]) -> (String, Secret) {
        // Derive the public key the same way the SDK does, so the did:key and
        // the Secret agree.
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(&seed);
        let pub_bytes = sk.verifying_key().to_bytes();
        let did = did_key_helpers::ed25519_pub_to_did_key(&pub_bytes);
        let vm = format!(
            "{did}#{}",
            did.strip_prefix("did:key:").expect("did:key prefix")
        );
        let mut secret = Secret::generate_ed25519(Some(&vm), Some(&seed));
        secret.id = vm;
        (did, secret)
    }

    fn grant<'a>(
        holder: &'a str,
        verifier: &'a str,
        claims: Vec<String>,
        valid_until: DateTime<Utc>,
    ) -> ConsentGrant<'a> {
        ConsentGrant {
            holder_did: holder,
            verifier_did: verifier,
            purpose: "join the Acme community",
            claims,
            valid_until,
        }
    }

    #[tokio::test]
    async fn create_signs_a_verifiable_record_with_all_fields() {
        let (_dir, _store, vault) = fresh_vault();
        let (holder, key) = holder_identity([1u8; 32]);
        let verifier = "did:web:acme-verifier.example";
        let valid_until = Utc::now() + Duration::hours(1);

        let g = grant(
            &holder,
            verifier,
            vec!["givenName".into(), "memberSince".into()],
            valid_until,
        );
        let rec = create(&vault, &g, &key).await.unwrap();

        // The DI proof verifies (non-repudiation anchor).
        rec.verify_proof().expect("proof must verify");

        // Carries dataSubject / recipient / purpose / personalData / validity.
        assert_eq!(rec.data_subject, holder);
        assert_eq!(rec.process.recipient, verifier);
        assert_eq!(rec.process.purpose, "join the Acme community");
        assert_eq!(
            rec.process.personal_data,
            vec!["givenName".to_string(), "memberSince".to_string()]
        );
        assert_eq!(rec.process.storage_condition.valid, rfc3339(valid_until));
        assert!(rec.is_given());
        assert_eq!(rec.status.len(), 1);
        assert_eq!(rec.status[0].event_type, ConsentStatusType::ConsentGiven);

        // It serializes to the 27560/DPV JSON-LD shape.
        let json = serde_json::to_value(&rec).unwrap();
        assert_eq!(json["@type"], "dpv:ConsentRecord");
        assert_eq!(json["dpv:hasDataSubject"], holder);
        assert_eq!(json["dpv:hasProcess"]["@type"], "dpv:Process");
        assert_eq!(json["dpv:hasProcess"]["dpv:hasProcessing"], "dpv:Disclose");
        assert_eq!(json["dpv:hasProcess"]["dpv:hasRecipient"], verifier);
        assert_eq!(
            json["dpv:hasStatus"][0]["@type"], "dpv:ConsentGiven",
            "status log opens with ConsentGiven"
        );
        assert!(json["proof"].is_object(), "carries a DI proof");
        assert_eq!(json["dct:conformsTo"], CONFORMS_TO);

        // Round-trips through storage (get re-verifies the proof).
        let got = get(&vault, &rec.identifier)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got, rec);
        assert!(get(&vault, "urn:uuid:nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn authorizes_only_when_given_unexpired_recipient_and_claims_subset() {
        let (_dir, _store, vault) = fresh_vault();
        let (holder, key) = holder_identity([2u8; 32]);
        let verifier = "did:web:acme-verifier.example";
        let now = Utc::now();
        let valid_until = now + Duration::hours(1);

        let g = grant(
            &holder,
            verifier,
            vec!["givenName".into(), "memberSince".into()],
            valid_until,
        );
        let rec = create(&vault, &g, &key).await.unwrap();

        // Positive: given, unexpired, right verifier, subset of claims.
        assert!(authorizes(&rec, verifier, &["givenName".into()], now));
        assert!(authorizes(
            &rec,
            verifier,
            &["givenName".into(), "memberSince".into()],
            now
        ));

        // NEGATIVE — a verifier outside the record is refused.
        assert!(
            !authorizes(&rec, "did:web:evil.example", &["givenName".into()], now),
            "a different verifier must not be authorized"
        );

        // NEGATIVE — a claim outside the consented reveal set is refused.
        assert!(
            !authorizes(&rec, verifier, &["dateOfBirth".into()], now),
            "a claim outside hasPersonalData must not be authorized"
        );
        assert!(
            !authorizes(
                &rec,
                verifier,
                &["givenName".into(), "dateOfBirth".into()],
                now
            ),
            "a request that mixes in an out-of-scope claim must be refused as a whole"
        );
    }

    #[tokio::test]
    async fn expired_record_authorizes_nothing() {
        let (_dir, _store, vault) = fresh_vault();
        let (holder, key) = holder_identity([3u8; 32]);
        let verifier = "did:web:acme-verifier.example";
        // Valid window already closed.
        let valid_until = Utc::now() - Duration::minutes(1);

        let g = grant(&holder, verifier, vec!["givenName".into()], valid_until);
        let rec = create(&vault, &g, &key).await.unwrap();

        // Even with the right verifier and an in-scope claim, expiry denies.
        assert!(
            !authorizes(&rec, verifier, &["givenName".into()], Utc::now()),
            "an expired record must authorize nothing"
        );
    }

    #[tokio::test]
    async fn withdraw_flips_latest_status_and_revokes_authority() {
        let (_dir, _store, vault) = fresh_vault();
        let (holder, key) = holder_identity([4u8; 32]);
        let verifier = "did:web:acme-verifier.example";
        let now = Utc::now();
        let valid_until = now + Duration::hours(1);

        let g = grant(&holder, verifier, vec!["givenName".into()], valid_until);
        let rec = create(&vault, &g, &key).await.unwrap();
        // Authorized before withdrawal.
        assert!(authorizes(&rec, verifier, &["givenName".into()], now));

        let withdrawn = withdraw(&vault, &rec.identifier, &key)
            .await
            .unwrap()
            .expect("record exists");

        // Latest status flipped to ConsentWithdrawn, and re-signed (verifies).
        assert!(!withdrawn.is_given());
        assert_eq!(
            withdrawn.status.last().unwrap().event_type,
            ConsentStatusType::ConsentWithdrawn
        );
        assert_eq!(
            withdrawn.status.first().unwrap().event_type,
            ConsentStatusType::ConsentGiven,
            "the original ConsentGiven event is retained for audit"
        );
        withdrawn
            .verify_proof()
            .expect("withdrawn record must be re-signed and verify");

        // authorizes() now returns false even though unexpired + right verifier.
        assert!(
            !authorizes(&withdrawn, verifier, &["givenName".into()], now),
            "a withdrawn record must authorize nothing"
        );

        // Persisted: a fresh get reflects the withdrawn state.
        let reloaded = get(&vault, &rec.identifier)
            .await
            .unwrap()
            .expect("present");
        assert!(!reloaded.is_given());

        // Withdrawing an absent record is Ok(None).
        assert!(
            withdraw(&vault, "urn:uuid:nope", &key)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn tampered_record_fails_proof_on_get() {
        let (_dir, _store, vault) = fresh_vault();
        let (holder, key) = holder_identity([5u8; 32]);
        let verifier = "did:web:acme-verifier.example";
        let valid_until = Utc::now() + Duration::hours(1);

        let g = grant(&holder, verifier, vec!["givenName".into()], valid_until);
        let mut rec = create(&vault, &g, &key).await.unwrap();

        // Tamper with the reveal set *after* signing, then store raw (bypass
        // create's sign+verify). get must reject it.
        rec.process.personal_data.push("dateOfBirth".into());
        vault
            .insert(record_key(&rec.identifier), &rec)
            .await
            .unwrap();

        let err = get(&vault, &rec.identifier).await.unwrap_err();
        assert!(
            matches!(err, AppError::Validation(_)),
            "a tampered record must fail proof verification on get"
        );
    }

    #[tokio::test]
    async fn proof_by_unrelated_key_is_rejected() {
        // A record whose dataSubject is the holder but whose proof is by a
        // different key must not verify — guards against a forged
        // hasDataSubject.
        let (_dir, _store, _vault) = fresh_vault();
        let (holder, _holder_key) = holder_identity([6u8; 32]);
        let (_attacker_did, attacker_key) = holder_identity([7u8; 32]);
        let verifier = "did:web:acme-verifier.example";
        let valid_until = Utc::now() + Duration::hours(1);

        // Hand-build a record claiming `holder` as dataSubject, sign with the
        // attacker key.
        let mut rec = ConsentRecord {
            context: vec![DPV_CONTEXT.to_string(), DCT_CONTEXT.to_string()],
            type_: RecordType::ConsentRecord,
            identifier: "urn:uuid:forged".into(),
            conforms_to: CONFORMS_TO.to_string(),
            data_subject: holder.clone(),
            process: ConsentProcess {
                type_: ProcessType::Process,
                purpose: "steal".into(),
                personal_data: vec!["givenName".into()],
                recipient: verifier.to_string(),
                processing: ProcessingType::Disclose,
                storage_condition: StorageCondition {
                    valid: rfc3339(valid_until),
                },
            },
            status: vec![ConsentStatusEvent {
                event_type: ConsentStatusType::ConsentGiven,
                date: rfc3339(Utc::now()),
            }],
            proof: Value::Null,
        };
        rec.sign_with(&attacker_key).await.unwrap();

        let err = rec.verify_proof().unwrap_err();
        assert!(
            matches!(err, AppError::Validation(_)),
            "a proof whose verificationMethod is not the dataSubject must be rejected"
        );
    }

    #[tokio::test]
    async fn list_is_local_audit_surface_over_consent_namespace() {
        let (_dir, _store, vault) = fresh_vault();
        let (holder, key) = holder_identity([8u8; 32]);
        let verifier = "did:web:acme-verifier.example";
        let valid_until = Utc::now() + Duration::hours(1);

        let a = create(
            &vault,
            &grant(&holder, verifier, vec!["givenName".into()], valid_until),
            &key,
        )
        .await
        .unwrap();
        let b = create(
            &vault,
            &grant(&holder, verifier, vec!["memberSince".into()], valid_until),
            &key,
        )
        .await
        .unwrap();

        let mut ids = list(&vault)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.identifier)
            .collect::<Vec<_>>();
        ids.sort();
        let mut want = vec![a.identifier, b.identifier];
        want.sort();
        assert_eq!(ids, want);
    }
}
