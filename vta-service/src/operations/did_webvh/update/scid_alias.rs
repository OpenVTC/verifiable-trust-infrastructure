//! Listing or removing the did:scid alias of an existing log
//! (`vta/webvh/dids/update/1.1`, `scidAlsoKnownAs`; VTI-KEY-164, VTI-KEY-166).
//!
//! Every did:webvh log is also `did:scid:vh:1:<scid>`. The two forms are one
//! subject only while the did:webvh document lists
//! `did:scid:vh:1:<scid>?src=<source>` in `alsoKnownAs`. `create/1.2` lists it
//! at creation; this is how a log created before it, or without it, gets it —
//! and how one that has it drops it.
//!
//! The DID URL is derived by [`vta_sdk::did_scid::scid_forms`], the same
//! derivation `create/1.2` and the resolver use, so there is one spelling of
//! the source in the workspace: the part after `did:webvh:<scid>:`, `:` → `/`,
//! percent-encoding kept (update 1.1, "Listing the did:scid alias" item 1).

use serde_json::Value;

use super::errors::UpdateDidWebvhError;
use crate::operations::did_webvh::presentation;
use crate::store::KeyspaceHandle;
use crate::webvh_store;

/// Whether `entry` is a did:scid DID of the log with bare did:scid DID `bare`,
/// with or without a `src`, at any location.
fn names_this_scid(entry: &Value, bare: &str) -> bool {
    entry
        .as_str()
        .is_some_and(|a| vta_sdk::did_scid::is_scid(a) && vta_sdk::did_scid::identity(a) == bare)
}

/// Whether `entry` is this log's did:scid DID URL at its *current* location.
/// The `src` is compared as a locator (VTI-KEY-160), exactly as
/// [`presentation::document_lists_alias`] does, so a URL naming the log's
/// location in another accepted spelling counts as listed.
fn names_current_location(entry: &Value, bare: &str, webvh_did: &str) -> bool {
    names_this_scid(entry, bare)
        && entry.as_str().is_some_and(|a| {
            vta_sdk::did_scid::src(a).is_some()
                && vta_sdk::did_scid::webvh_did(a).as_deref() == Some(webvh_did)
        })
}

/// Apply `scidAlsoKnownAs` to `document`, the did:webvh document of
/// `webvh_did` (update 1.1 items 3 and 4).
///
/// - `list == true`: the current DID URL is added after the entries already
///   there, unless it is already listed. A did:scid entry for this SCID naming
///   another `src` — the log's location before a move — is replaced by the
///   current one, in place, never kept beside it.
/// - `list == false`: every did:scid entry for this SCID, with or without a
///   `src`, is removed; every other entry is left as it was. An `alsoKnownAs`
///   emptied by the removal is dropped.
///
/// Returns the DID URL. `None` (and `document` untouched) when `webvh_did` is
/// not a `did:webvh:<scid>:<host>…` DID.
pub(super) fn apply(document: &mut Value, webvh_did: &str, list: bool) -> Option<String> {
    let (bare, url) = vta_sdk::did_scid::scid_forms(webvh_did)?;
    let obj = document.as_object_mut()?;
    if list {
        let entries = obj
            .entry("alsoKnownAs")
            .or_insert_with(|| Value::Array(Vec::new()));
        if !entries.is_array() {
            // Not a list we can extend without discarding what is there; the
            // document validator refuses it below if it is malformed.
            return Some(url);
        }
        let list = entries.as_array_mut().expect("checked above");
        let current_listed = list
            .iter()
            .any(|e| names_current_location(e, &bare, webvh_did));
        let mut placed = current_listed;
        let mut out = Vec::with_capacity(list.len() + 1);
        for entry in list.drain(..) {
            if !names_this_scid(&entry, &bare) || names_current_location(&entry, &bare, webvh_did) {
                out.push(entry);
            } else if !placed {
                // A stale location: the current URL takes its place.
                out.push(Value::String(url.clone()));
                placed = true;
            }
            // Any further stale entry is dropped.
        }
        if !placed {
            out.push(Value::String(url.clone()));
        }
        *list = out;
    } else if let Some(Value::Array(list)) = obj.get_mut("alsoKnownAs") {
        let before = list.len();
        list.retain(|e| !names_this_scid(e, &bare));
        if list.is_empty() && before > 0 {
            obj.remove("alsoKnownAs");
        }
    }
    Some(url)
}

/// Whether the VTA presents `webvh_did`'s identity in the did:scid form — the
/// case in which the alias may not be removed (VTI-KEY-166; update 1.1 item 4).
///
/// Two sources, either sufficient:
///
/// - the [`webvh_store::ScidIdentity`] recorded for the log, whose `presented`
///   is set when it was created with `didMethod` `scid` (`create/1.2`, and the
///   VTA's own DID through setup); and
/// - `vta_did`, the VTA's configured DID, when it is this log's did:scid DID:
///   an identity "configured so since" its creation.
pub(super) async fn presented_as_scid(
    webvh_ks: &KeyspaceHandle,
    webvh_did: &str,
    vta_did: Option<&str>,
) -> Result<bool, UpdateDidWebvhError> {
    if let (Some(vta_did), Some((bare, _))) = (vta_did, vta_sdk::did_scid::scid_forms(webvh_did))
        && vta_sdk::did_scid::is_scid(vta_did)
        && vta_sdk::did_scid::identity(vta_did) == bare
    {
        return Ok(true);
    }
    let identity = webvh_store::get_scid_identity(webvh_ks, webvh_did)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_scid_identity: {e}")))?;
    Ok(identity.is_some_and(|i| i.presented))
}

/// Keep the recorded did:scid identity in step with the document just
/// published, so every `webvh/dids` task takes the did:scid DID exactly while
/// the forms are one subject (VTI-KEY-164: from the version that lists the
/// alias, and no longer once a version removes it).
///
/// A presented identity always keeps its record (it cannot lose its alias —
/// [`presented_as_scid`] refuses that first).
pub(super) async fn record_identity(
    webvh_ks: &KeyspaceHandle,
    webvh_did: &str,
    published: &Value,
) -> Result<(), UpdateDidWebvhError> {
    let persistence =
        |e: crate::error::AppError| UpdateDidWebvhError::Persistence(format!("scid identity: {e}"));
    let listed = presentation::document_lists_alias(published);
    let existing = webvh_store::get_scid_identity(webvh_ks, webvh_did)
        .await
        .map_err(persistence)?;
    match existing {
        Some(identity) if identity.alias_listed == listed => Ok(()),
        Some(identity) if !listed && !identity.presented => {
            webvh_store::delete_scid_identity(webvh_ks, &identity.scid_did)
                .await
                .map_err(persistence)
        }
        Some(mut identity) => {
            identity.alias_listed = listed;
            webvh_store::store_scid_identity(webvh_ks, &identity)
                .await
                .map_err(persistence)
        }
        None if listed => match webvh_store::ScidIdentity::of(webvh_did, false, true) {
            Some(identity) => webvh_store::store_scid_identity(webvh_ks, &identity)
                .await
                .map_err(persistence),
            None => Ok(()),
        },
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const WEBVH: &str = "did:webvh:QmScid:example.com%3A8443:acme:ops";
    const URL: &str = "did:scid:vh:1:QmScid?src=example.com%3A8443/acme/ops";

    fn doc(aliases: Value) -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": WEBVH,
            "alsoKnownAs": aliases,
        })
    }

    /// Item 1: `:` → `/`, the port's percent-encoding kept.
    #[test]
    fn the_source_keeps_its_percent_encoding() {
        let mut d = json!({ "id": WEBVH });
        assert_eq!(apply(&mut d, WEBVH, true).as_deref(), Some(URL));
        assert_eq!(d["alsoKnownAs"], json!([URL]));
        assert!(presentation::document_lists_alias(&d));
    }

    /// Item 3: after the existing entries, once.
    #[test]
    fn listing_appends_after_existing_entries_and_is_idempotent() {
        let mut d = doc(json!(["https://example.com/@acme"]));
        apply(&mut d, WEBVH, true);
        assert_eq!(d["alsoKnownAs"], json!(["https://example.com/@acme", URL]));
        let once = d.clone();
        apply(&mut d, WEBVH, true);
        assert_eq!(d, once, "an already-listed alias is not listed twice");
    }

    /// Item 3: a moved log's old location is replaced, not kept beside.
    #[test]
    fn a_stale_location_is_replaced_in_place() {
        let stale = "did:scid:vh:1:QmScid?src=old.example/acme";
        let mut d = doc(json!([
            "https://example.com/@acme",
            stale,
            "did:scid:vh:1:QmScid?src=older.example",
            "did:web:other.example"
        ]));
        apply(&mut d, WEBVH, true);
        assert_eq!(
            d["alsoKnownAs"],
            json!(["https://example.com/@acme", URL, "did:web:other.example"])
        );
    }

    /// Item 4: every entry for this SCID, with or without `src`; nothing else.
    #[test]
    fn removal_drops_every_form_of_this_scid_and_nothing_else() {
        let mut d = doc(json!([
            URL,
            "did:scid:vh:1:QmScid",
            "did:scid:vh:1:QmScid?src=old.example",
            "did:scid:vh:1:QmOther?src=example.com",
            "https://example.com/@acme"
        ]));
        apply(&mut d, WEBVH, false);
        assert_eq!(
            d["alsoKnownAs"],
            json!([
                "did:scid:vh:1:QmOther?src=example.com",
                "https://example.com/@acme"
            ])
        );
        let mut only = doc(json!([URL]));
        apply(&mut only, WEBVH, false);
        assert!(
            only.get("alsoKnownAs").is_none(),
            "an emptied list is dropped"
        );
        let mut none = json!({ "id": WEBVH });
        apply(&mut none, WEBVH, false);
        assert_eq!(
            none,
            json!({ "id": WEBVH }),
            "nothing to remove changes nothing"
        );
    }

    #[test]
    fn a_non_webvh_did_is_left_alone() {
        let mut d = json!({ "id": "did:key:z6Mk" });
        assert_eq!(apply(&mut d, "did:key:z6Mk", true), None);
        assert_eq!(d, json!({ "id": "did:key:z6Mk" }));
    }
}
