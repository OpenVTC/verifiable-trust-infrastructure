//! Secondary index over the credential vault, keyed by
//! `{type, community_did, issuer_did, purpose, status}` (task 1.1).
//!
//! ## Design: key-only index rows
//!
//! The `vault` keyspace is encrypted at rest (AES-256-GCM on the *value*),
//! but fjall **keys stay plaintext** so prefix scans work. We exploit that:
//! each index entry is a key-only row whose key encodes
//! `idx:<field>:<value>:<id>` and whose value is a single sentinel byte.
//! A prefix scan on `idx:<field>:<value>:` therefore yields the ids of
//! every credential indexed under that `(field, value)` pair — without
//! decrypting (or even touching) any credential body.
//!
//! The credential body and its metadata live only in the primary record
//! (`super::storage`, key `cred:<id>`), which *is* value-encrypted. The
//! index keys carry only routing metadata (a DID, a type tag, a status
//! token), never the body — consistent with the privacy invariants in
//! `vti-credential-architecture.md` §14.
//!
//! ## Key namespace, and why it is disjoint from the password vault
//!
//! The same `vault` keyspace already holds the password-manager
//! `VaultEntry` records under the `vault:` prefix
//! (`vti_common::vault`). The credential store uses the disjoint prefixes
//! `cred:` (primary) and `idx:` (this index), so the two never collide.
//! See [`super::storage`] for the primary-key helpers.

use vti_common::error::AppError;
use vti_common::store::{Batch, KeyspaceHandle};

use super::model::{IndexField, StoredCredential};

/// Prefix for every secondary-index row in the credential vault. Disjoint
/// from `cred:` (primary records) and `vault:` (password manager).
pub(crate) const INDEX_PREFIX: &str = "idx:";

/// Single-byte sentinel stored as the value of every index row. The row's
/// information content is entirely in its key; the value exists only
/// because fjall requires one.
const SENTINEL: &[u8] = b"1";

/// Byte that separates the `value` segment from the `id` segment in an
/// index key. A NUL is used deliberately: it cannot appear in a DID, a VC
/// type tag, or a status/purpose token, so it is an unambiguous boundary
/// even when one value is a colon-extended prefix of another (e.g.
/// `did:web:acme` vs `did:web:acme:team`). Using `:` here would let the
/// former's scan prefix falsely match the latter's rows.
const VALUE_ID_SEP: u8 = 0x00;

/// `idx:<field>:<value>\0<id>` — the full key for one index entry.
///
/// `field` is a fixed token; `value` is caller data (a type tag, a DID, a
/// status token) and may itself contain `:`. The `\0` boundary
/// ([`VALUE_ID_SEP`]) makes the `(field, value)` prefix exact regardless of
/// the `value`'s contents. The id is appended last so two credentials
/// sharing a `(field, value)` get distinct keys.
fn index_key(field: IndexField, value: &str, id: &str) -> Vec<u8> {
    let mut k = format!("{INDEX_PREFIX}{}:{value}", field.token()).into_bytes();
    k.push(VALUE_ID_SEP);
    k.extend_from_slice(id.as_bytes());
    k
}

/// `idx:<field>:<value>\0` — the prefix that selects exactly the ids indexed
/// under `(field, value)`. The trailing `\0` is load-bearing: it pins the
/// end of the `value` segment, so `did:web:acme` never matches
/// `did:web:acme:team`'s rows (those start with `…acme:team\0`).
fn scan_prefix(field: IndexField, value: &str) -> Vec<u8> {
    let mut p = format!("{INDEX_PREFIX}{}:{value}", field.token()).into_bytes();
    p.push(VALUE_ID_SEP);
    p
}

/// Recover the trailing `<id>` segment from a full index key produced by
/// [`index_key`] — everything after the `\0` boundary.
fn id_from_index_key(key: &[u8]) -> Option<String> {
    let sep = key.iter().rposition(|&b| b == VALUE_ID_SEP)?;
    let id = &key[sep + 1..];
    if id.is_empty() {
        return None;
    }
    std::str::from_utf8(id).ok().map(|s| s.to_string())
}

/// Every index key `cred` produces.
fn index_keys(cred: &StoredCredential) -> std::collections::BTreeSet<Vec<u8>> {
    cred.index_terms()
        .into_iter()
        .map(|(field, value)| index_key(field, &value, &cred.id))
        .collect()
}

/// Stage into `batch` the index changes that take `prev`'s entries to
/// `next`'s: delete the entries only `prev` had, write every entry `next`
/// has. `None` on either side is "no record". Committed in the same batch as
/// the primary record, so the record and its index entries change together
/// — a crash or a concurrent writer can never leave an index row pointing at
/// this credential under a value it no longer holds, nor a record missing
/// one of its rows.
pub(crate) fn stage_reindex(
    batch: &mut Batch,
    prev: Option<&StoredCredential>,
    next: Option<&StoredCredential>,
) {
    let old = prev.map(index_keys).unwrap_or_default();
    let new = next.map(index_keys).unwrap_or_default();
    for key in old.difference(&new) {
        batch.remove(key.clone());
    }
    for key in new {
        batch.insert_raw(key, SENTINEL.to_vec());
    }
}

/// Scan the index for every credential id stored under `(field, value)`.
///
/// This is the **only** discovery primitive the vault exposes: it requires
/// an explicit field *and* value — there is no "give me everything" mode.
/// That is deliberate (no-wallet-enumeration, §14): a caller must already
/// know what it is looking for, mirroring the DCQL-targeted discovery model
/// the later tasks build on top of this index.
///
/// Returns ids in fjall key order; duplicates are not possible (the id is
/// part of the unique key). The credential bodies are **not** touched —
/// callers resolve ids to records via [`super::storage::get`] only for the
/// ids they actually need.
pub(crate) async fn scan(
    vault: &KeyspaceHandle,
    field: IndexField,
    value: &str,
) -> Result<Vec<String>, AppError> {
    let rows = vault.prefix_iter_raw(scan_prefix(field, value)).await?;
    let mut ids = Vec::with_capacity(rows.len());
    for (key, _sentinel) in rows {
        if let Some(id) = id_from_index_key(&key) {
            ids.push(id);
        }
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_key_layout_is_field_value_nul_id() {
        let k = index_key(IndexField::IssuerDid, "did:web:acme", "cred-1");
        let mut expected = b"idx:issuer:did:web:acme".to_vec();
        expected.push(0x00);
        expected.extend_from_slice(b"cred-1");
        assert_eq!(k, expected);
    }

    #[test]
    fn scan_prefix_pins_value_with_nul() {
        let p = scan_prefix(IndexField::CommunityDid, "did:web:acme");
        let mut expected = b"idx:community:did:web:acme".to_vec();
        expected.push(0x00);
        assert_eq!(p, expected);
    }

    #[test]
    fn colon_extended_value_is_not_a_false_prefix_match() {
        // `did:web:acme` must NOT prefix-match `did:web:acme:team`'s key.
        let scan = scan_prefix(IndexField::CommunityDid, "did:web:acme");
        let sibling = index_key(IndexField::CommunityDid, "did:web:acme:team", "x");
        assert!(!sibling.starts_with(&scan));
    }

    #[test]
    fn id_recovered_after_nul_even_when_value_has_colons() {
        let k = index_key(IndexField::CommunityDid, "did:web:acme:team", "ulid-xyz");
        assert_eq!(id_from_index_key(&k).as_deref(), Some("ulid-xyz"));
    }
}
