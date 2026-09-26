//! Pure validators for caller-supplied input to the update path:
//! DID document shape, watcher URLs, witness configuration.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use didwebvh_rs::witness::Witnesses;
use serde_json::Value;

use super::errors::UpdateDidWebvhError;
use super::options::WITNESS_RESOLVE_TIMEOUT;

/// Validate a caller-supplied DID document for update.
///
/// Checks:
/// 1. `document.id` equals `existing_did` — operators cannot rename a DID
///    via update; the DID is immutable for the lifetime of the document.
/// 2. `@context` is present (JSON-LD shape).
/// 3. `verificationMethod`, if present, is an array; every entry has the
///    minimum required fields (`id`, `type`, `controller`,
///    `publicKeyMultibase`). Externally-hosted public keys are allowed —
///    the VTA does not require it to have minted them — but the entry's
///    shape has to be well-formed.
///
/// Returns the document unchanged so callers can chain.
pub(in crate::operations::did_webvh) fn validate_document_for_update(
    document: Value,
    existing_did: &str,
) -> Result<Value, UpdateDidWebvhError> {
    let obj = document.as_object().ok_or_else(|| {
        UpdateDidWebvhError::InvalidDocument("document must be a JSON object".into())
    })?;

    let id = obj
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| UpdateDidWebvhError::InvalidDocument("document missing `id`".into()))?;
    if id != existing_did {
        return Err(UpdateDidWebvhError::InvalidDocument(format!(
            "document.id `{id}` does not match existing DID `{existing_did}`"
        )));
    }

    if obj.get("@context").is_none() {
        return Err(UpdateDidWebvhError::InvalidDocument(
            "document missing `@context`".into(),
        ));
    }

    // Every method the document *defines* — in `verificationMethod` or
    // embedded in a relationship — must be this DID's own (`{did}#…`, or a
    // relative `#…`). A method id naming another DID is refused: key records
    // are addressed by method id, so a document that defines
    // `<other DID>#key-0` makes that DID's record — another context's key —
    // look like one of this DID's, and rotate-keys would rewrite it. A
    // relationship may still *reference* another DID's method by string.
    let own_prefix = format!("{existing_did}#");
    let mut defined: Vec<(&str, &Value)> = Vec::new();
    for (field, value) in obj {
        let Some(entries) = value.as_array() else {
            continue;
        };
        let embeds = field == "verificationMethod"
            || matches!(
                field.as_str(),
                "authentication"
                    | "assertionMethod"
                    | "keyAgreement"
                    | "capabilityInvocation"
                    | "capabilityDelegation"
            );
        if embeds {
            defined.extend(
                entries
                    .iter()
                    .filter(|e| e.is_object())
                    .map(|e| (field.as_str(), e)),
            );
        }
    }
    for (field, entry) in &defined {
        let Some(id) = entry.get("id").and_then(Value::as_str) else {
            continue;
        };
        if !(id.starts_with('#') || id.starts_with(&own_prefix)) {
            return Err(UpdateDidWebvhError::InvalidDocument(format!(
                "{field} defines method `{id}`, which is not a method of {existing_did}; a \
                 document may only define its own DID's verification methods"
            )));
        }
    }

    if let Some(vm) = obj.get("verificationMethod") {
        let vms = vm.as_array().ok_or_else(|| {
            UpdateDidWebvhError::InvalidDocument("verificationMethod must be an array".into())
        })?;
        for (i, entry) in vms.iter().enumerate() {
            let entry_obj = entry.as_object().ok_or_else(|| {
                UpdateDidWebvhError::InvalidDocument(format!(
                    "verificationMethod[{i}] is not a JSON object"
                ))
            })?;
            for required in ["id", "type", "controller", "publicKeyMultibase"] {
                if !entry_obj.contains_key(required) {
                    return Err(UpdateDidWebvhError::InvalidDocument(format!(
                        "verificationMethod[{i}] missing `{required}`"
                    )));
                }
            }
        }
    }

    Ok(document)
}

/// Validate caller-supplied watcher URLs.
///
/// Watchers must be `https://` URLs in production builds (`http://` is
/// allowed under `cfg(debug_assertions)` for local dev). Empty list is
/// accepted as the "disable watchers" instruction.
pub(in crate::operations::did_webvh) fn validate_watchers(
    urls: &[String],
) -> Result<(), UpdateDidWebvhError> {
    for url_str in urls {
        let url = url::Url::parse(url_str).map_err(|e| {
            UpdateDidWebvhError::InvalidWatcher(format!("watcher URL `{url_str}`: {e}"))
        })?;
        let scheme_ok =
            matches!(url.scheme(), "https") || (cfg!(debug_assertions) && url.scheme() == "http");
        if !scheme_ok {
            return Err(UpdateDidWebvhError::InvalidWatcher(format!(
                "watcher URL `{url_str}` must use https"
            )));
        }
        if url.fragment().is_some() {
            return Err(UpdateDidWebvhError::InvalidWatcher(format!(
                "watcher URL `{url_str}` must not contain a fragment"
            )));
        }
        if url.query().is_some() {
            return Err(UpdateDidWebvhError::InvalidWatcher(format!(
                "watcher URL `{url_str}` must not contain a query string"
            )));
        }
    }
    Ok(())
}

/// Validate a caller-supplied witness configuration.
///
/// `Witnesses::Empty {}` is the library's "disable witnesses" instruction
/// and is always accepted. `Witnesses::Value` requires every witness's
/// `did:key` to resolve through the cache resolver within
/// [`WITNESS_RESOLVE_TIMEOUT`]; an empty witness list with a non-zero
/// threshold is rejected as nonsensical (the underlying library rejects
/// it too on intake, but failing fast here gives a typed
/// `InvalidWitness` instead of a `Library`).
pub(in crate::operations::did_webvh) async fn validate_witnesses(
    new: &Witnesses,
    did_resolver: &DIDCacheClient,
) -> Result<(), UpdateDidWebvhError> {
    let (witnesses, threshold) = match new {
        // Caller is disabling witnesses on this update. No DIDs to
        // resolve; nothing to validate.
        Witnesses::Empty {} => return Ok(()),
        Witnesses::Value {
            witnesses,
            threshold,
        } => (witnesses, *threshold),
    };

    if witnesses.is_empty() {
        return Err(UpdateDidWebvhError::InvalidWitness(format!(
            "witness configuration has threshold {threshold} but no witnesses listed"
        )));
    }
    if (witnesses.len() as u32) < threshold {
        return Err(UpdateDidWebvhError::InvalidWitness(format!(
            "threshold {threshold} exceeds witness count {}",
            witnesses.len()
        )));
    }

    for w in witnesses {
        let did = w.as_did();
        match tokio::time::timeout(WITNESS_RESOLVE_TIMEOUT, did_resolver.resolve(&did)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                return Err(UpdateDidWebvhError::InvalidWitness(format!(
                    "witness {did} did not resolve: {e}"
                )));
            }
            Err(_) => {
                return Err(UpdateDidWebvhError::InvalidWitness(format!(
                    "witness {did} resolution timed out ({}s)",
                    WITNESS_RESOLVE_TIMEOUT.as_secs()
                )));
            }
        }
    }
    Ok(())
}
