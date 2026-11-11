//! Which identifier methods a party resolves, and the rule for acting as an
//! identity of an optional one (VTI-KEY-003, VTI-KEY-008, VTI-KEY-009).
//!
//! Every node resolves the *required* methods: `did:webvh`, `did:scid:vh:1`
//! and `did:key`. Anything further is an *optional* method, and `did:webs` is
//! the one VTI-KEY-001 admits to the durable position. A node MUST NOT
//! initiate an exchange as a durable identity of an optional method unless the
//! peer has declared, in a top-level `resolvedMethods` member of its own
//! verified current document, that it resolves that method — and when it has
//! not, the node sends nothing and fails with `methodNotDeclared`, never
//! acting under another identifier in its place.
//!
//! These are string and JSON rules only, so every consumer of this crate can
//! apply them without a DID library: what this build resolves, what a peer has
//! declared, whether an initiation is permitted, and how a node declares in
//! its own document. Where a check runs is the caller's: at each seam that
//! resolves a peer's document before it sends (the same seams that match
//! transports, [`crate::protocol::matching`]).
//!
//! Replies are not initiations. A party that addressed the node under its
//! identity has shown it resolves that method (VTI-KEY-008), so a reply to it
//! needs no declaration and never comes through [`require_declared`].

use std::collections::BTreeSet;

use serde_json::Value;

/// The top-level DID-document member a party declares its optional methods
/// in (VTI-KEY-008).
pub const RESOLVED_METHODS_MEMBER: &str = "resolvedMethods";

/// The JSON-LD IRI of [`RESOLVED_METHODS_MEMBER`]. A document processed as
/// JSON-LD defines the term with this IRI and `@type: @json` (VTI-KEY-008);
/// [`declare`] adds that definition to the document's `@context`.
pub const RESOLVED_METHODS_IRI: &str = "https://w3id.org/vti#resolvedMethods";

/// The required methods (VTI-KEY-003), by method name: every node resolves
/// them, so none needs declaring, and a declaration that omits one never
/// withdraws it.
pub const REQUIRED_METHODS: &[&str] = &["webvh", "scid", "key"];

/// The optional methods this build resolves and declares in its own
/// documents. `did:webs` is resolved from its host through
/// `affinidi-did-resolver-cache-sdk`'s `did-webs` feature, which the workspace
/// turns on; this list and that feature move together.
///
/// Only methods a peer could meet as a durable identity are declared:
/// `did:web` and `did:peer` are resolved too ([`RESOLVED_HERE`]) but are
/// never a node's durable identity, so declaring them would tell a peer
/// nothing it acts on.
pub const OPTIONAL_METHODS_DECLARED: &[&str] = &["webs"];

/// Every method this build resolves, required or not: the receive side's
/// answer to "can I rely on material that needs this method resolved?"
/// (VTI-KEY-009). A method absent here is refused as `unsupportedDidMethod`
/// before any resolver is asked.
pub const RESOLVED_HERE: &[&str] = &["webvh", "scid", "key", "webs", "web", "peer"];

/// The method-name component of `did` (`"webs"` for `did:webs:…`), or `None`
/// for anything that is not a DID.
///
/// Method names are lowercase letters and digits (DID Core §3.1); a
/// component outside that grammar is not a method name.
#[must_use]
pub fn method_name(did: &str) -> Option<&str> {
    let rest = did.strip_prefix("did:")?;
    let (method, tail) = rest.split_once(':')?;
    if method.is_empty()
        || tail.is_empty()
        || !method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return None;
    }
    Some(method)
}

/// Whether `method` is a required method (VTI-KEY-003).
#[must_use]
pub fn is_required(method: &str) -> bool {
    REQUIRED_METHODS.contains(&method)
}

/// Whether this build resolves `method` ([`RESOLVED_HERE`]).
#[must_use]
pub fn resolves(method: &str) -> bool {
    RESOLVED_HERE.contains(&method)
}

/// The optional methods `doc` declares in `resolvedMethods`.
///
/// Read leniently, because the declaration is the peer's: a member that is not
/// an array, or an entry that is not a method name, declares nothing; a
/// duplicate counts once. A required method listed there is dropped, since it
/// needs no declaration. The caller passes the peer's **verified current**
/// document — the resolver's answer, never a document from any other source
/// (VTI-KEY-008).
#[must_use]
pub fn declared(doc: &Value) -> BTreeSet<String> {
    doc.get(RESOLVED_METHODS_MEMBER)
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .filter(|m| method_name(&format!("did:{m}:x")) == Some(*m))
                .filter(|m| !is_required(m))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Initiating an exchange as an identity of an optional method toward a peer
/// that has not declared it (VTI-KEY-008). Carries what the refusal names:
/// the method and the peer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "methodNotDeclared: `{peer}` has not declared that it resolves did:{method}, so this \
     identity cannot act toward it (VTI-KEY-008); nothing was sent"
)]
pub struct MethodNotDeclared {
    /// The optional method of the identity that would have acted.
    pub method: String,
    /// The peer that has not declared it.
    pub peer: String,
}

/// Permit or refuse an initiation as `own_did` toward `peer_did`, whose
/// verified current document is `peer_doc` (VTI-KEY-008).
///
/// Always `Ok` when `own_did` is of a required method. For an optional one,
/// `Ok` only when `peer_doc` declares it; otherwise [`MethodNotDeclared`], and
/// the caller sends nothing and does not fall back to another identifier
/// (VTI-KEY-009). A sender to itself needs no declaration.
///
/// # Errors
/// [`MethodNotDeclared`] as above.
pub fn require_declared(
    own_did: &str,
    peer_did: &str,
    peer_doc: &Value,
) -> Result<(), MethodNotDeclared> {
    let Some(method) = method_name(own_did) else {
        return Ok(());
    };
    if is_required(method) || base(own_did) == base(peer_did) {
        return Ok(());
    }
    if declared(peer_doc).contains(method) {
        return Ok(());
    }
    Err(MethodNotDeclared {
        method: method.to_string(),
        peer: base(peer_did).to_string(),
    })
}

/// Declare [`OPTIONAL_METHODS_DECLARED`] in `doc`, this node's own document:
/// set `resolvedMethods`, and define the term in `@context` when the document
/// has one (VTI-KEY-008), so a JSON-LD processor does not drop the member.
///
/// Idempotent: a document already declaring them, with the term already
/// defined, is left as it is. A non-object `doc` is left alone.
pub fn declare(doc: &mut Value) {
    let Some(map) = doc.as_object_mut() else {
        return;
    };
    map.insert(
        RESOLVED_METHODS_MEMBER.to_string(),
        Value::Array(
            OPTIONAL_METHODS_DECLARED
                .iter()
                .map(|m| Value::String((*m).to_string()))
                .collect(),
        ),
    );
    let term = serde_json::json!({
        RESOLVED_METHODS_MEMBER: { "@id": RESOLVED_METHODS_IRI, "@type": "@json" }
    });
    match map.get_mut("@context") {
        Some(Value::Array(entries)) => {
            if !entries.iter().any(defines_term) {
                entries.push(term);
            }
        }
        // A single context, by IRI or inline: becomes an array with the term.
        Some(ctx @ (Value::String(_) | Value::Object(_))) if !defines_term(ctx) => {
            let first = ctx.take();
            *ctx = Value::Array(vec![first, term]);
        }
        _ => {}
    }
}

/// Whether a `@context` entry defines `resolvedMethods`.
fn defines_term(entry: &Value) -> bool {
    entry
        .get(RESOLVED_METHODS_MEMBER)
        .is_some_and(|t| t.get("@id").and_then(Value::as_str) == Some(RESOLVED_METHODS_IRI))
}

/// `did` without its fragment or query: the identity a DID URL names.
fn base(did: &str) -> &str {
    let end = did.find(['#', '?', '/']).unwrap_or(did.len());
    &did[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const WEBS: &str = "did:webs:example.com:nodes:EAbc";
    const PEER: &str = "did:webvh:Qm123:peer.example";

    #[test]
    fn method_names_follow_the_did_grammar() {
        assert_eq!(method_name(WEBS), Some("webs"));
        assert_eq!(method_name("did:scid:vh:1:Qm"), Some("scid"));
        assert_eq!(method_name("did:key:z6Mk"), Some("key"));
        assert_eq!(method_name("did:WEBS:x"), None);
        assert_eq!(method_name("did:webs"), None);
        assert_eq!(method_name("did::x"), None);
        assert_eq!(method_name("https://example.com"), None);
    }

    /// VTI-KEY-008: an optional-method identity acts only toward a peer that
    /// declared the method.
    #[test]
    fn vti_key_008_an_optional_identity_needs_the_peers_declaration() {
        let silent = json!({ "id": PEER });
        let refused = require_declared(WEBS, PEER, &silent).unwrap_err();
        assert_eq!(refused.method, "webs");
        assert_eq!(refused.peer, PEER);
        assert!(refused.to_string().starts_with("methodNotDeclared"));

        let declaring = json!({ "id": PEER, "resolvedMethods": ["webs"] });
        require_declared(WEBS, PEER, &declaring).unwrap();
        // By key id too: the declaration is of the method, not the key.
        require_declared(
            &format!("{WEBS}#Dkey"),
            &format!("{PEER}#key-0"),
            &declaring,
        )
        .unwrap();

        // Another optional method declared is not this one.
        let other = json!({ "id": PEER, "resolvedMethods": ["ethr"] });
        assert!(require_declared(WEBS, PEER, &other).is_err());
    }

    /// The required methods need no declaration, and a declaration omitting
    /// them withdraws nothing (VTI-KEY-008).
    #[test]
    fn vti_key_008_required_methods_need_no_declaration() {
        let declaring_nothing = json!({ "id": PEER, "resolvedMethods": [] });
        for own in [
            "did:webvh:Qm1:a.example",
            "did:scid:vh:1:Qm1?src=a.example",
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        ] {
            require_declared(own, PEER, &declaring_nothing).unwrap();
        }
    }

    #[test]
    fn acting_toward_itself_needs_no_declaration() {
        require_declared(WEBS, &format!("{WEBS}#Dkey"), &json!({})).unwrap();
    }

    /// The peer's declaration is read leniently and never as a withdrawal.
    #[test]
    fn a_malformed_declaration_declares_nothing() {
        for doc in [
            json!({}),
            json!({ "resolvedMethods": "webs" }),
            json!({ "resolvedMethods": [1, null, "WEBS", "did:webs", ""] }),
        ] {
            assert!(declared(&doc).is_empty(), "{doc}");
        }
        assert_eq!(
            declared(&json!({ "resolvedMethods": ["webs", "webs", "webvh", "key"] })),
            BTreeSet::from(["webs".to_string()])
        );
    }

    /// A node's own document declares what it resolves, with the JSON-LD
    /// term VTI-KEY-008 gives, and declaring twice changes nothing.
    #[test]
    fn vti_key_008_a_node_declares_with_the_json_ld_term() {
        let mut doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:Qm1:a.example",
        });
        declare(&mut doc);
        assert_eq!(doc[RESOLVED_METHODS_MEMBER], json!(["webs"]));
        assert_eq!(
            doc["@context"][1],
            json!({ "resolvedMethods": { "@id": RESOLVED_METHODS_IRI, "@type": "@json" } })
        );
        let once = doc.clone();
        declare(&mut doc);
        assert_eq!(doc, once);
        assert_eq!(declared(&doc), BTreeSet::from(["webs".to_string()]));

        let mut single = json!({ "@context": "https://www.w3.org/ns/did/v1", "id": "x" });
        declare(&mut single);
        assert_eq!(single["@context"].as_array().map(Vec::len), Some(2));

        let mut bare = json!({ "id": "x" });
        declare(&mut bare);
        assert!(bare.get("@context").is_none());
        assert_eq!(bare[RESOLVED_METHODS_MEMBER], json!(["webs"]));
    }

    #[test]
    fn every_declared_and_required_method_is_resolved_here() {
        for m in REQUIRED_METHODS.iter().chain(OPTIONAL_METHODS_DECLARED) {
            assert!(resolves(m), "{m}");
        }
        assert!(!resolves("ethr"));
    }
}
