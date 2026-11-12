//! Which identifier methods a party resolves (VTI-KEY-003, VTI-KEY-009).
//!
//! Every node resolves the *required* methods: `did:webvh`, `did:scid:vh:1`,
//! `did:webs` and `did:key` (VTI-KEY-003). So a node never requires a peer to
//! use a particular durable method (VTI-KEY-001): a `did:webs` node acts
//! toward any peer exactly as a `did:webvh` node does, and there is nothing to
//! declare. The `resolvedMethods` declaration and its gate (VTI-KEY-008) are
//! withdrawn; a document or template that still carries the member is not
//! refused for it, and nothing reads it.
//!
//! What remains is the receive side (VTI-KEY-009): a party that can rely on
//! material only by resolving a method it does not resolve refuses it as
//! `unsupportedDidMethod`, naming the method, and never processes it as
//! unauthenticated or falls back to another identifier. These are string
//! rules only, so every consumer of this crate can apply them without a DID
//! library.

/// The required methods (VTI-KEY-003), by method name: every node resolves
/// them. `did:webs` is resolved from its host through
/// `affinidi-did-resolver-cache-sdk`'s `did-webs` feature, which the workspace
/// turns on for every resolver it builds; this list and that feature move
/// together.
pub const REQUIRED_METHODS: &[&str] = &["webvh", "scid", "webs", "key"];

/// Whether `did` names a node's durable identity (VTI-KEY-001): a
/// `did:webvh`, a `did:scid:vh:1` or a `did:webs`.
///
/// Wider than [`crate::did_scid::is_durable`], which means "has a `did:webvh`
/// log" and stays that.
#[must_use]
pub fn is_durable_identity(did: &str) -> bool {
    crate::did_scid::is_durable(did) || method_name(did) == Some("webs")
}

/// Every method this build resolves, required or not: the receive side's
/// answer to "can I rely on material that needs this method resolved?"
/// (VTI-KEY-009). A method absent here is refused as `unsupportedDidMethod`
/// before any resolver is asked.
pub const RESOLVED_HERE: &[&str] = &["webvh", "scid", "webs", "key", "web", "peer"];

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

#[cfg(test)]
mod tests {
    use super::*;

    const WEBS: &str = "did:webs:example.com:nodes:EAbc";

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

    #[test]
    fn durable_identities_are_webvh_scid_and_webs() {
        assert!(is_durable_identity("did:webvh:Qm1:a.example"));
        assert!(is_durable_identity("did:scid:vh:1:Qm1?src=a.example"));
        assert!(is_durable_identity(WEBS));
        assert!(!is_durable_identity("did:key:z6Mk"));
        assert!(!is_durable_identity("did:web:a.example"));
        assert!(!is_durable_identity("did:peer:2.Vz6Mk"));
    }

    /// VTI-KEY-003: did:webs is a required method, so the VTI-KEY-009
    /// receiver refusal never fires for it.
    #[test]
    fn vti_key_003_every_required_method_is_resolved_here() {
        assert!(is_required("webs"));
        for m in REQUIRED_METHODS {
            assert!(resolves(m), "{m}");
        }
        assert!(!resolves("ethr"));
    }
}
