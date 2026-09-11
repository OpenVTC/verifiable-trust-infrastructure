//! Is a credential revoked? The applicant's check of a `credentialStatus`.
//!
//! [`crate::vetting::eligibility::verify_eligibility_vp`] proves a vetter's role
//! credential was issued by the community and leaves its status to the caller
//! — resolution needs the network. [`check_credential_status`] is that step: it
//! fetches the `BitstringStatusListCredential` the entry names through a fetch
//! function the **caller** supplies (the caller owns transport, SSRF guards and
//! timeouts), verifies the list's Data Integrity proof and that its issuer is
//! the credential's issuer, decodes the bitstring and reads the entry's bit.
//!
//! The bitstring format is the one a VTC publishes
//! (`vtc-service/src/status_list/credential.rs`) and a VTA vault reads
//! (`vta-vault/src/status.rs`): GZIP, base64url without padding, most
//! significant bit first — decoded with the same `affinidi-status-list` crate.
//! A W3C multibase `u` prefix is accepted as well.
//!
//! ## What the answer means
//!
//! - [`StatusCheck::Active`] — every revocation or suspension entry was read
//!   from a list the issuer signed, and no bit is set.
//! - [`StatusCheck::Revoked`] — a revocation or suspension bit is set. A
//!   suspended credential is not currently valid, so it reads as revoked here.
//! - [`StatusCheck::Unknown`] — anything else: no usable entry, the fetch
//!   failed, the list did not verify, or it could not be decoded. The string is
//!   for the log. A caller deciding whether to rely on a credential treats
//!   `Unknown` as "not established", never as `Active`.
//!
//! Nothing here panics on hostile input: every length, index and decompressed
//! size is bounded before it is used.

use std::future::Future;

use affinidi_status_list::{BitstringStatusList, StatusPurpose};
use chrono::{DateTime, Utc};
use serde_json::Value;

use super::card::CLOCK_SKEW;
use super::{did_of, verify_attached_proof};
use crate::trust_task_proof::TrustTaskVmResolver;

/// The outcome of a status check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusCheck {
    /// Not revoked or suspended, read from a verified list.
    Active,
    /// A revocation or suspension bit is set.
    Revoked,
    /// Could not be established; the string says why, for the log.
    Unknown(String),
}

/// `type` of a status entry this check reads.
pub const BITSTRING_STATUS_LIST_ENTRY_TYPE: &str = "BitstringStatusListEntry";
/// `type` the fetched list credential must carry.
pub const BITSTRING_STATUS_LIST_CREDENTIAL_TYPE: &str = "BitstringStatusListCredential";

/// The largest status list read, in bits (8 MiB decompressed). A W3C list is at
/// least 131,072 bits; an index past this bound is refused before any fetch,
/// and it also bounds how far a hostile GZIP stream is inflated.
pub const MAX_STATUS_LIST_BITS: u64 = 1 << 26;
/// Longest `encodedList` read, in characters.
pub const MAX_ENCODED_LIST_CHARS: usize = 1 << 22;
/// Most status entries read from one `credentialStatus`.
pub const MAX_STATUS_ENTRIES: usize = 8;
/// Longest `statusListCredential` URL read.
pub const MAX_STATUS_LIST_URL_CHARS: usize = 2048;

const LIST_WHAT: &str = "status list credential";
const LIST_PROOF_PURPOSE: &str = "assertionMethod";
/// base64url of the GZIP magic bytes: a multibase `u` followed by this is a
/// prefixed list, not a list whose first character happens to be `u`.
const GZIP_BASE64URL_PREFIX: &str = "H4sI";

/// Check a credential's `credentialStatus` against the issuer's status list.
///
/// `credential_status` is the credential's `credentialStatus` member (one
/// entry or an array of entries). `issuer` is the credential's issuer: the
/// status list must be signed by it. `fetch` returns the JSON body at a URL;
/// the caller bounds it. `resolver` resolves the list's verification method.
///
/// Entries whose `statusPurpose` is neither `revocation` nor `suspension` are
/// ignored. Each list URL is fetched once.
pub async fn check_credential_status(
    credential_status: &Value,
    issuer: &str,
    fetch: impl AsyncFn(&str) -> Result<Value, String>,
    resolver: &TrustTaskVmResolver,
) -> StatusCheck {
    check_at(credential_status, issuer, fetch, resolver, Utc::now()).await
}

async fn check_at(
    credential_status: &Value,
    issuer: &str,
    fetch: impl AsyncFn(&str) -> Result<Value, String>,
    resolver: &TrustTaskVmResolver,
    now: DateTime<Utc>,
) -> StatusCheck {
    let entries: Vec<&Value> = match credential_status {
        Value::Array(items) => items.iter().collect(),
        Value::Object(_) => vec![credential_status],
        _ => return unknown("credentialStatus is not an object or array"),
    };
    if entries.len() > MAX_STATUS_ENTRIES {
        return unknown("credentialStatus has too many entries");
    }

    let mut parsed = Vec::new();
    for entry in entries {
        match parse_entry(entry) {
            Ok(Some(e)) => parsed.push(e),
            Ok(None) => {}
            Err(reason) => return StatusCheck::Unknown(reason),
        }
    }
    if parsed.is_empty() {
        return unknown("no revocation or suspension status entry");
    }

    // One fetch per list URL: two entries on one list cost one request.
    let mut lists: Vec<(String, Result<Value, String>)> = Vec::new();
    let mut first_unknown = None;
    for entry in &parsed {
        if !lists.iter().any(|(url, _)| *url == entry.url) {
            let body = fetch(&entry.url).await;
            lists.push((entry.url.clone(), body));
        }
        let body = lists
            .iter()
            .find(|(url, _)| *url == entry.url)
            .map(|(_, body)| body);
        let outcome = match body {
            Some(Ok(list)) => read_bit(list, entry, issuer, resolver, now).await,
            Some(Err(e)) => Err(format!("status list fetch failed: {e}")),
            None => Err("status list was not fetched".to_string()),
        };
        match outcome {
            Ok(true) => return StatusCheck::Revoked,
            Ok(false) => {}
            Err(reason) => {
                first_unknown.get_or_insert(reason);
            }
        }
    }
    match first_unknown {
        Some(reason) => StatusCheck::Unknown(reason),
        None => StatusCheck::Active,
    }
}

fn unknown(reason: &str) -> StatusCheck {
    StatusCheck::Unknown(reason.to_string())
}

struct Entry {
    url: String,
    index: usize,
    purpose: StatusPurpose,
}

/// `Ok(None)` for an entry of a purpose this check does not read.
fn parse_entry(entry: &Value) -> Result<Option<Entry>, String> {
    let obj = entry
        .as_object()
        .ok_or_else(|| "a status entry is not an object".to_string())?;
    if !has_type(obj.get("type"), BITSTRING_STATUS_LIST_ENTRY_TYPE) {
        return Ok(None);
    }
    let purpose = match obj.get("statusPurpose").and_then(Value::as_str) {
        Some("revocation") => StatusPurpose::Revocation,
        Some("suspension") => StatusPurpose::Suspension,
        Some(_) => return Ok(None),
        None => return Err("a status entry has no statusPurpose".into()),
    };
    let url = obj
        .get("statusListCredential")
        .and_then(Value::as_str)
        .filter(|u| !u.is_empty() && u.chars().count() <= MAX_STATUS_LIST_URL_CHARS)
        .ok_or_else(|| "a status entry has no usable statusListCredential".to_string())?;
    let index = parse_index(obj.get("statusListIndex"))?;
    Ok(Some(Entry {
        url: url.to_string(),
        index,
        purpose,
    }))
}

/// W3C writes `statusListIndex` as a string of digits; a JSON integer is read
/// too. Bounded by [`MAX_STATUS_LIST_BITS`].
fn parse_index(value: Option<&Value>) -> Result<usize, String> {
    let n = match value {
        Some(Value::String(s))
            if !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()) =>
        {
            s.parse::<u64>().ok()
        }
        Some(Value::Number(n)) => n.as_u64(),
        _ => None,
    }
    .ok_or_else(|| "statusListIndex is not a non-negative integer".to_string())?;
    if n >= MAX_STATUS_LIST_BITS {
        return Err("statusListIndex is past the largest status list read".into());
    }
    usize::try_from(n).map_err(|_| "statusListIndex does not fit this platform".to_string())
}

fn has_type(value: Option<&Value>, wanted: &str) -> bool {
    match value {
        Some(Value::String(t)) => t == wanted,
        Some(Value::Array(types)) => types.iter().any(|t| t.as_str() == Some(wanted)),
        _ => false,
    }
}

/// `true` when the entry's bit is set in a list this issuer signed.
async fn read_bit(
    list: &Value,
    entry: &Entry,
    issuer: &str,
    resolver: &TrustTaskVmResolver,
    now: DateTime<Utc>,
) -> Result<bool, String> {
    let obj = list
        .as_object()
        .ok_or_else(|| "the status list is not a JSON object".to_string())?;
    if !has_type(obj.get("type"), BITSTRING_STATUS_LIST_CREDENTIAL_TYPE) {
        return Err("the fetched document is not a BitstringStatusListCredential".into());
    }
    // The list names itself: a list served at one URL cannot stand in for the
    // list at another, even one the same issuer signed.
    if obj.get("id").and_then(Value::as_str) != Some(entry.url.as_str()) {
        return Err("the status list's id is not the URL it was fetched from".into());
    }
    let list_issuer = match obj.get("issuer") {
        Some(Value::String(s)) => Some(s.as_str()),
        Some(Value::Object(o)) => o.get("id").and_then(Value::as_str),
        _ => None,
    }
    .ok_or_else(|| "the status list has no issuer".to_string())?;
    if list_issuer != issuer {
        return Err("the status list's issuer is not the credential's issuer".into());
    }
    check_window(obj, now)?;

    let signer = verify_attached_proof(LIST_WHAT, list, LIST_PROOF_PURPOSE, resolver)
        .await
        .map_err(|e| format!("{e}: {}", e.cause().unwrap_or_default()))?;
    if did_of(&signer) != issuer {
        return Err("the status list is not signed by its issuer".into());
    }

    let subject = obj
        .get("credentialSubject")
        .and_then(Value::as_object)
        .ok_or_else(|| "the status list has no credentialSubject".to_string())?;
    let subject_purpose = subject.get("statusPurpose").and_then(Value::as_str);
    if subject_purpose != Some(purpose_str(entry.purpose)) {
        return Err("the status list's purpose is not the entry's".into());
    }
    let encoded = subject
        .get("encodedList")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= MAX_ENCODED_LIST_CHARS)
        .ok_or_else(|| "the status list has no usable encodedList".to_string())?;
    let encoded = match encoded.strip_prefix('u') {
        Some(rest) if rest.starts_with(GZIP_BASE64URL_PREFIX) => rest,
        _ => encoded,
    };

    // Decode only as far as the entry's bit: the decoder inflates at most
    // `size / 8 + 1` bytes, so a GZIP bomb cannot cost more than the index
    // allows, and a list too short to hold the index fails here.
    let size = entry.index.saturating_add(1);
    let decoded = BitstringStatusList::decode(encoded, size, entry.purpose)
        .map_err(|e| format!("the status list does not decode as far as the entry: {e}"))?;
    decoded
        .get(entry.index)
        .map_err(|e| format!("statusListIndex is outside the status list: {e}"))
}

fn check_window(obj: &serde_json::Map<String, Value>, now: DateTime<Utc>) -> Result<(), String> {
    let read = |member: &str| -> Result<Option<DateTime<Utc>>, String> {
        match obj.get(member) {
            None => Ok(None),
            Some(Value::String(s)) => DateTime::parse_from_rfc3339(s)
                .map(|t| Some(t.with_timezone(&Utc)))
                .map_err(|_| format!("the status list's {member} is not a timestamp")),
            Some(_) => Err(format!("the status list's {member} is not a timestamp")),
        }
    };
    if read("validFrom")?.is_some_and(|from| from > now + CLOCK_SKEW) {
        return Err("the status list is not yet valid".into());
    }
    if read("validUntil")?.is_some_and(|until| until + CLOCK_SKEW < now) {
        return Err("the status list has expired".into());
    }
    Ok(())
}

fn purpose_str(purpose: StatusPurpose) -> &'static str {
    match purpose {
        StatusPurpose::Revocation => "revocation",
        StatusPurpose::Suspension => "suspension",
    }
}

// Keeps the public signature's future `Send` when the caller's fetch is:
// asserted by a test, so a change that captures a non-`Send` value is caught
// here rather than in a consumer that spawns the check.
#[allow(dead_code)]
fn assert_send<F: Future + Send>(_: F) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vetting::test_support::{did, secret};
    use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
    use affinidi_secrets_resolver::secrets::Secret;
    use chrono::Duration;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const URL: &str = "https://vtc.example.com/v1/status-lists/revocation";
    const SIZE: usize = 131_072;

    fn entry(index: &str, purpose: &str) -> Value {
        json!({
            "id": format!("{URL}#{index}"),
            "type": BITSTRING_STATUS_LIST_ENTRY_TYPE,
            "statusPurpose": purpose,
            "statusListIndex": index,
            "statusListCredential": URL,
        })
    }

    fn encoded(set: &[usize], purpose: StatusPurpose) -> String {
        let mut list = BitstringStatusList::new(SIZE, purpose);
        for &i in set {
            list.set(i, true).unwrap();
        }
        list.encode().unwrap()
    }

    fn unsigned_list(issuer: &str, purpose: &str, encoded_list: &str) -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": URL,
            "type": ["VerifiableCredential", BITSTRING_STATUS_LIST_CREDENTIAL_TYPE],
            "issuer": issuer,
            "validFrom": (Utc::now() - Duration::days(1)).to_rfc3339(),
            "credentialSubject": {
                "id": format!("{URL}#list"),
                "type": "BitstringStatusList",
                "statusPurpose": purpose,
                "encodedList": encoded_list,
            }
        })
    }

    async fn sign(mut doc: Value, key: &Secret, purpose: &str) -> Value {
        let proof =
            DataIntegrityProof::sign(&doc, key, SignOptions::new().with_proof_purpose(purpose))
                .await
                .unwrap();
        doc["proof"] = serde_json::to_value(proof).unwrap();
        doc
    }

    async fn signed_list(key: &Secret, set: &[usize]) -> Value {
        sign(
            unsigned_list(
                &did(key),
                "revocation",
                &encoded(set, StatusPurpose::Revocation),
            ),
            key,
            "assertionMethod",
        )
        .await
    }

    async fn check(status: &Value, issuer: &str, list: Value) -> StatusCheck {
        check_credential_status(
            status,
            issuer,
            async |_url: &str| Ok(list.clone()),
            &TrustTaskVmResolver::did_key_only(),
        )
        .await
    }

    fn is_unknown(s: &StatusCheck) -> bool {
        matches!(s, StatusCheck::Unknown(_))
    }

    #[tokio::test]
    async fn a_clear_bit_is_active_and_a_set_bit_is_revoked() {
        let community = secret(0xC0);
        let list = signed_list(&community, &[7]).await;
        assert_eq!(
            check(&entry("6", "revocation"), &did(&community), list.clone()).await,
            StatusCheck::Active
        );
        assert_eq!(
            check(&entry("7", "revocation"), &did(&community), list.clone()).await,
            StatusCheck::Revoked
        );
        // The last bit of the list, and a JSON-number index.
        let last = signed_list(&community, &[SIZE - 1]).await;
        let mut numeric = entry("0", "revocation");
        numeric["statusListIndex"] = json!(SIZE - 1);
        assert_eq!(
            check(&numeric, &did(&community), last).await,
            StatusCheck::Revoked
        );
    }

    #[tokio::test]
    async fn the_vtc_list_format_reads_back() {
        // Written the way `vtc-service` writes it: MSB-first, base64url, no prefix.
        let community = secret(0xC0);
        let list = signed_list(&community, &[0, 9, 130_000]).await;
        for (index, revoked) in [("0", true), ("1", false), ("9", true), ("130000", true)] {
            let got = check(&entry(index, "revocation"), &did(&community), list.clone()).await;
            assert_eq!(
                got == StatusCheck::Revoked,
                revoked,
                "index {index}: {got:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_multibase_prefixed_list_is_read() {
        let community = secret(0xC0);
        let prefixed = format!("u{}", encoded(&[3], StatusPurpose::Revocation));
        let list = sign(
            unsigned_list(&did(&community), "revocation", &prefixed),
            &community,
            "assertionMethod",
        )
        .await;
        assert_eq!(
            check(&entry("3", "revocation"), &did(&community), list).await,
            StatusCheck::Revoked
        );
    }

    #[tokio::test]
    async fn a_list_from_anyone_but_the_issuer_is_not_trusted() {
        let (community, mallory) = (secret(0xC0), secret(0x66));
        // Mallory signs a list claiming the community as issuer.
        let forged = sign(
            unsigned_list(
                &did(&community),
                "revocation",
                &encoded(&[], StatusPurpose::Revocation),
            ),
            &mallory,
            "assertionMethod",
        )
        .await;
        assert!(is_unknown(
            &check(&entry("7", "revocation"), &did(&community), forged).await
        ));
        // Mallory's own list, honestly issued, for the community's credential.
        let own = signed_list(&mallory, &[]).await;
        assert!(is_unknown(
            &check(&entry("7", "revocation"), &did(&community), own).await
        ));
    }

    #[tokio::test]
    async fn a_tampered_unsigned_or_wrongly_purposed_list_is_not_trusted() {
        let community = secret(0xC0);
        let mut tampered = signed_list(&community, &[7]).await;
        tampered["credentialSubject"]["encodedList"] =
            json!(encoded(&[], StatusPurpose::Revocation));
        assert!(is_unknown(
            &check(&entry("7", "revocation"), &did(&community), tampered).await
        ));

        let unsigned = unsigned_list(
            &did(&community),
            "revocation",
            &encoded(&[], StatusPurpose::Revocation),
        );
        assert!(is_unknown(
            &check(&entry("7", "revocation"), &did(&community), unsigned).await
        ));

        let auth = sign(
            unsigned_list(
                &did(&community),
                "revocation",
                &encoded(&[], StatusPurpose::Revocation),
            ),
            &community,
            "authentication",
        )
        .await;
        assert!(is_unknown(
            &check(&entry("7", "revocation"), &did(&community), auth).await
        ));
    }

    #[tokio::test]
    async fn a_list_for_another_purpose_or_url_does_not_answer() {
        let community = secret(0xC0);
        let list = signed_list(&community, &[]).await;
        // A suspension entry read against the revocation list.
        assert!(is_unknown(
            &check(&entry("7", "suspension"), &did(&community), list.clone()).await
        ));
        let mut elsewhere = entry("7", "revocation");
        elsewhere["statusListCredential"] = json!("https://vtc.example.com/other");
        assert!(is_unknown(&check(&elsewhere, &did(&community), list).await));
    }

    #[tokio::test]
    async fn a_suspended_credential_reads_as_revoked() {
        let community = secret(0xC0);
        let list = sign(
            unsigned_list(
                &did(&community),
                "suspension",
                &encoded(&[4], StatusPurpose::Suspension),
            ),
            &community,
            "assertionMethod",
        )
        .await;
        assert_eq!(
            check(&entry("4", "suspension"), &did(&community), list).await,
            StatusCheck::Revoked
        );
    }

    #[tokio::test]
    async fn an_expired_or_future_list_is_not_trusted() {
        let community = secret(0xC0);
        let mut doc = unsigned_list(
            &did(&community),
            "revocation",
            &encoded(&[], StatusPurpose::Revocation),
        );
        doc["validUntil"] = json!((Utc::now() - Duration::days(1)).to_rfc3339());
        let expired = sign(doc, &community, "assertionMethod").await;
        assert!(is_unknown(
            &check(&entry("1", "revocation"), &did(&community), expired).await
        ));
        let mut doc = unsigned_list(
            &did(&community),
            "revocation",
            &encoded(&[], StatusPurpose::Revocation),
        );
        doc["validFrom"] = json!((Utc::now() + Duration::days(1)).to_rfc3339());
        let future = sign(doc, &community, "assertionMethod").await;
        assert!(is_unknown(
            &check(&entry("1", "revocation"), &did(&community), future).await
        ));
    }

    #[tokio::test]
    async fn any_revoked_entry_wins_and_any_unreadable_one_is_unknown() {
        let community = secret(0xC0);
        let list = signed_list(&community, &[2]).await;
        let both = json!([entry("1", "revocation"), entry("2", "revocation")]);
        assert_eq!(
            check(&both, &did(&community), list.clone()).await,
            StatusCheck::Revoked
        );
        let mut broken = entry("1", "suspension");
        broken["statusListCredential"] =
            json!("https://vtc.example.com/v1/status-lists/suspension");
        let mixed = json!([entry("1", "revocation"), broken]);
        assert!(is_unknown(&check(&mixed, &did(&community), list).await));
    }

    #[tokio::test]
    async fn each_list_is_fetched_once_and_a_fetch_failure_is_unknown() {
        let community = secret(0xC0);
        let list = signed_list(&community, &[]).await;
        let calls = AtomicUsize::new(0);
        let status = json!([entry("1", "revocation"), entry("2", "revocation")]);
        let got = check_credential_status(
            &status,
            &did(&community),
            async |_url: &str| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(list.clone())
            },
            &TrustTaskVmResolver::did_key_only(),
        )
        .await;
        assert_eq!(got, StatusCheck::Active);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let failed = check_credential_status(
            &entry("1", "revocation"),
            &did(&community),
            async |_url: &str| Err("timed out".to_string()),
            &TrustTaskVmResolver::did_key_only(),
        )
        .await;
        assert!(matches!(failed, StatusCheck::Unknown(r) if r.contains("timed out")));
    }

    #[tokio::test]
    async fn hostile_entries_never_panic_and_never_read_as_active() {
        let community = secret(0xC0);
        let list = signed_list(&community, &[]).await;
        let issuer = did(&community);
        let too_many: Vec<Value> = (0..=MAX_STATUS_ENTRIES)
            .map(|i| entry(&i.to_string(), "revocation"))
            .collect();
        for status in [
            json!(null),
            json!("revoked"),
            json!(42),
            json!([]),
            json!({}),
            json!([null]),
            Value::Array(too_many),
            json!({ "type": BITSTRING_STATUS_LIST_ENTRY_TYPE, "statusPurpose": "revocation" }),
            json!({ "type": BITSTRING_STATUS_LIST_ENTRY_TYPE, "statusListIndex": "1", "statusListCredential": URL }),
            json!({ "type": "StatusList2021Entry", "statusPurpose": "revocation", "statusListIndex": "1", "statusListCredential": URL }),
            json!({ "type": BITSTRING_STATUS_LIST_ENTRY_TYPE, "statusPurpose": "message", "statusListIndex": "1", "statusListCredential": URL }),
            {
                let mut e = entry("1", "revocation");
                e["statusListIndex"] = json!("-1");
                e
            },
            {
                let mut e = entry("1", "revocation");
                e["statusListIndex"] = json!(-1);
                e
            },
            {
                let mut e = entry("1", "revocation");
                e["statusListIndex"] = json!(1.5);
                e
            },
            {
                let mut e = entry("1", "revocation");
                e["statusListIndex"] = json!("1e3");
                e
            },
            {
                let mut e = entry("1", "revocation");
                e["statusListIndex"] = json!("99999999999999999999999");
                e
            },
            {
                let mut e = entry("1", "revocation");
                e["statusListIndex"] = json!(MAX_STATUS_LIST_BITS.to_string());
                e
            },
            {
                let mut e = entry("1", "revocation");
                e["statusListCredential"] = json!("x".repeat(MAX_STATUS_LIST_URL_CHARS + 1));
                e
            },
            {
                let mut e = entry("1", "revocation");
                e["statusListCredential"] = json!(7);
                e
            },
            // Past the end of a 131,072-bit list.
            entry(&SIZE.to_string(), "revocation"),
        ] {
            let got = check(&status, &issuer, list.clone()).await;
            assert!(is_unknown(&got), "{status} read as {got:?}");
        }
    }

    #[tokio::test]
    async fn hostile_lists_never_panic_and_never_read_as_active() {
        let community = secret(0xC0);
        let issuer = did(&community);
        let e = entry("1", "revocation");
        let base = signed_list(&community, &[]).await;
        let mut cases = vec![
            json!(null),
            json!([]),
            json!("list"),
            json!({ "type": "VerifiableCredential" }),
        ];
        for (pointer, value) in [
            ("/type", json!("VerifiableCredential")),
            ("/id", json!("https://elsewhere.example/list")),
            ("/issuer", json!({ "name": "no id" })),
            ("/issuer", json!(7)),
            ("/validUntil", json!("yesterday")),
            ("/credentialSubject", json!("subject")),
            ("/credentialSubject/encodedList", json!(7)),
            ("/credentialSubject/encodedList", json!("")),
            ("/credentialSubject/encodedList", json!("!!!not base64!!!")),
            ("/credentialSubject/encodedList", json!("AAAA")),
            ("/proof", json!("proof")),
        ] {
            let mut doc = base.clone();
            let (parent, member) = pointer.rsplit_once('/').unwrap();
            doc.pointer_mut(parent)
                .and_then(Value::as_object_mut)
                .unwrap()
                .insert(member.to_string(), value);
            cases.push(doc);
        }
        let mut no_proof = base.clone();
        no_proof.as_object_mut().unwrap().remove("proof");
        cases.push(no_proof);

        for list in cases {
            let got = check(&e, &issuer, list.clone()).await;
            assert!(is_unknown(&got), "{list} read as {got:?}");
        }
    }

    #[tokio::test]
    async fn a_short_or_oversized_encoding_is_bounded() {
        let community = secret(0xC0);
        // A list of 16 bits cannot answer for index 100.
        let mut tiny = BitstringStatusList::new(16, StatusPurpose::Revocation);
        tiny.set(1, true).unwrap();
        let short = sign(
            unsigned_list(&did(&community), "revocation", &tiny.encode().unwrap()),
            &community,
            "assertionMethod",
        )
        .await;
        assert!(is_unknown(
            &check(&entry("100", "revocation"), &did(&community), short.clone()).await
        ));
        assert_eq!(
            check(&entry("1", "revocation"), &did(&community), short).await,
            StatusCheck::Revoked
        );

        // A huge list of zeros compresses to little; reading bit 5 inflates only
        // the first bytes of it.
        let bomb =
            BitstringStatusList::new(MAX_STATUS_LIST_BITS as usize, StatusPurpose::Revocation)
                .encode()
                .unwrap();
        let signed = sign(
            unsigned_list(&did(&community), "revocation", &bomb),
            &community,
            "assertionMethod",
        )
        .await;
        assert_eq!(
            check(&entry("5", "revocation"), &did(&community), signed).await,
            StatusCheck::Active
        );

        let oversized = "A".repeat(MAX_ENCODED_LIST_CHARS + 1);
        let signed = sign(
            unsigned_list(&did(&community), "revocation", &oversized),
            &community,
            "assertionMethod",
        )
        .await;
        assert!(is_unknown(
            &check(&entry("5", "revocation"), &did(&community), signed).await
        ));
    }

    #[test]
    fn the_check_future_is_send_when_the_fetch_is() {
        let status = entry("1", "revocation");
        let resolver = TrustTaskVmResolver::did_key_only();
        assert_send(check_credential_status(
            &status,
            "did:key:z",
            async |_url: &str| Err::<Value, String>("offline".into()),
            &resolver,
        ));
    }
}
