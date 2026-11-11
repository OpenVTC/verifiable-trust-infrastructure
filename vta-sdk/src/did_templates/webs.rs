//! What a DID template may describe for a `did:webs` DID
//! (`vta/webs/_shared/0.2` CONVENTIONS.md §9.2).
//!
//! A `did:webs` document is not authored: the host derives it from the key
//! event log and its designations. So a template is **read**, member by member,
//! against what that derivation can express — one Ed25519 signing key in
//! `authentication` and `assertionMethod`, one designated X25519 key agreement
//! key, designated services and designated aliases — and refused where it
//! describes anything else, before a key is derived or anything published.
//!
//! [`map_webs_document`] is that check, as a pure function of the template, its
//! rendered document, the DID and the two keys the document was rendered with.
//! On success it returns what to designate ([`WebsDesignations`]); on refusal
//! the first rule (§9.2 table row) that failed and the JSON Pointers — into the
//! template, with its rendered `document` — of every member that rule refused.
//! [`check_key_shape`] is the part that needs no rendering, for a caller that
//! wants to refuse before deriving anything at all.
//!
//! Nothing here reaches a store or a key: the VTA's `vta/webs/dids/create/0.2`
//! uses it, and provision-integration can share it.

use serde_json::Value;

use super::{DidTemplate, KeyPurpose, SLOT_KA, SLOT_SIGNING};

/// The algorithm a level-1 `did:webs` key state holds its one signing key in.
const SIGNING_ALGORITHM: &str = "ed25519";
/// The algorithm of the designated key agreement key.
const KEY_AGREEMENT_ALGORITHM: &str = "x25519";
/// The most services one designation carries (the payload's own bound).
pub const MAX_DESIGNATED_SERVICES: usize = 32;

/// The document members the derivation renders or (`@context`,
/// `resolvedMethods`) ignores. Anything else is `documentMember`.
///
/// `resolvedMethods` is ignored, not refused (CONVENTIONS.md 0.2 §9.2,
/// trustoverip/dtgwg-trust-tasks-tf#1170): a did:webs node declares did:webs
/// by using it, and the derivation renders no declaration of further methods
/// (VTI-KEY-008), so a node template written for any method carries it.
const DOCUMENT_MEMBERS: &[&str] = &[
    "@context",
    "resolvedMethods",
    "id",
    "controller",
    "verificationMethod",
    "authentication",
    "assertionMethod",
    "keyAgreement",
    "capabilityInvocation",
    "capabilityDelegation",
    "service",
    "alsoKnownAs",
];

/// Why a template is not representable: the `details.reason` of
/// `vta/webs/dids/create:templateNotRepresentable`, one per §9.2 rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotRepresentableReason {
    /// A `schemaVersion` 3 (key-role) template.
    KeyRoleTemplate,
    /// A key slot or algorithm the key state cannot hold.
    KeyAlgorithm,
    /// `id` is not the DID.
    DocumentId,
    /// `controller` is not the DID.
    Controller,
    /// A verification method the derivation does not render.
    VerificationMethod,
    /// A verification relationship the derivation does not render.
    VerificationRelationship,
    /// No key agreement key.
    KeyAgreementRequired,
    /// A service the services designation cannot carry.
    Service,
    /// An alias that is not a DID.
    Alias,
    /// A member the derivation does not render at all.
    DocumentMember,
}

impl NotRepresentableReason {
    /// The wire spelling (`keyRoleTemplate`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeyRoleTemplate => "keyRoleTemplate",
            Self::KeyAlgorithm => "keyAlgorithm",
            Self::DocumentId => "documentId",
            Self::Controller => "controller",
            Self::VerificationMethod => "verificationMethod",
            Self::VerificationRelationship => "verificationRelationship",
            Self::KeyAgreementRequired => "keyAgreementRequired",
            Self::Service => "service",
            Self::Alias => "alias",
            Self::DocumentMember => "documentMember",
        }
    }
}

impl std::fmt::Display for NotRepresentableReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A template the `did:webs` derivation cannot reproduce.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NotRepresentable {
    /// The first rule that failed.
    pub reason: NotRepresentableReason,
    /// JSON Pointers into the template (its rendered document under
    /// `/document`) of every member that rule refused.
    pub members: Vec<String>,
    /// What to tell the operator.
    pub message: String,
}

impl NotRepresentable {
    fn new(
        reason: NotRepresentableReason,
        members: Vec<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            reason,
            members,
            message: message.into(),
        }
    }

    /// `details` as `templateNotRepresentable` declares it.
    pub fn details(&self) -> Value {
        serde_json::json!({ "reason": self.reason.as_str(), "members": self.members })
    }
}

/// Why [`map_webs_document`] refused a template.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WebsTemplateRefusal {
    /// `templateNotRepresentable`.
    NotRepresentable(NotRepresentable),
    /// Two services share an id (`vta/webs/dids:serviceIdConflict`).
    ServiceIdConflict {
        /// The id, as a fragment.
        id: String,
    },
}

impl From<NotRepresentable> for WebsTemplateRefusal {
    fn from(e: NotRepresentable) -> Self {
        Self::NotRepresentable(e)
    }
}

/// One of the two keys a document was rendered with, in the forms the
/// renderer substituted: a verification method publishes it when its
/// `publicKeyMultibase` or its `publicKeyJwk` is one of these.
#[derive(Debug, Clone)]
pub struct RenderedKey {
    pub multibase: String,
    pub jwk: Option<Value>,
}

impl RenderedKey {
    fn published_by(&self, vm: &serde_json::Map<String, Value>) -> bool {
        vm.get("publicKeyMultibase").and_then(Value::as_str) == Some(self.multibase.as_str())
            || self
                .jwk
                .as_ref()
                .is_some_and(|jwk| vm.get("publicKeyJwk") == Some(jwk))
    }
}

/// The keys a template was rendered with: the key state's one signing key and
/// the designated key agreement key.
#[derive(Debug, Clone)]
pub struct WebsRenderedKeys {
    pub signing: RenderedKey,
    pub key_agreement: RenderedKey,
}

/// What a representable template designates.
#[derive(Debug, Clone, PartialEq, Default)]
#[non_exhaustive]
pub struct WebsDesignations {
    /// Each service entry with its id reduced to the fragment (`#didcomm`), in
    /// the template's order.
    pub services: Vec<Value>,
    /// The aliases after the DID itself, in the template's order, the DID
    /// itself left out.
    pub also_known_as: Vec<String>,
}

/// A JSON Pointer segment, escaped (RFC 6901).
fn escape(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

fn doc_ptr(member: &str) -> String {
    format!("/document/{}", escape(member))
}

fn doc_ptr_at(member: &str, index: usize) -> String {
    format!("/document/{}/{index}", escape(member))
}

/// The §9.2 `schemaVersion` and `keys` rules, which need no rendering: a
/// level-1 key-state template declares exactly one published `signing` slot
/// that may be Ed25519 and exactly one `keyAgreement` slot that may be X25519.
///
/// # Errors
/// `keyRoleTemplate` for `schemaVersion` 3 or later; `keyAlgorithm` naming
/// every slot refused; `keyAgreementRequired` for no key agreement slot.
pub fn check_key_shape(template: &DidTemplate) -> Result<(), NotRepresentable> {
    if template.schema_version >= 3 {
        return Err(NotRepresentable::new(
            NotRepresentableReason::KeyRoleTemplate,
            vec!["/schemaVersion".into()],
            format!(
                "template '{}' is a key-role template (schemaVersion {}); a key-role identity \
                 is created by vta/dids/create with the webs profile",
                template.name, template.schema_version
            ),
        ));
    }
    let slots = template.key_slots();
    let primary = |purpose: KeyPurpose, preferred: &str| -> Option<String> {
        if slots.get(preferred).is_some_and(|s| s.purpose == purpose) {
            return Some(preferred.to_string());
        }
        slots
            .iter()
            .find(|(_, s)| s.purpose == purpose)
            .map(|(n, _)| n.clone())
    };
    let signing = primary(KeyPurpose::Signing, SLOT_SIGNING);
    let ka = primary(KeyPurpose::KeyAgreement, SLOT_KA);

    let mut refused = Vec::new();
    let mut why = Vec::new();
    for (name, slot) in &slots {
        let ptr = format!("/keys/{}", escape(name));
        let (is_primary, algorithm) = match slot.purpose {
            KeyPurpose::Signing => (signing.as_deref() == Some(name), SIGNING_ALGORITHM),
            KeyPurpose::KeyAgreement => (ka.as_deref() == Some(name), KEY_AGREEMENT_ALGORITHM),
        };
        if !is_primary {
            why.push(format!("a second {:?} slot '{name}'", slot.purpose));
            refused.push(ptr);
        } else if !slot.publish {
            why.push(format!("an unpublished slot '{name}'"));
            refused.push(ptr);
        } else if !slot.algorithms.iter().any(|a| a == algorithm) {
            why.push(format!(
                "slot '{name}' allows {:?}, not {algorithm}",
                slot.algorithms
            ));
            refused.push(ptr);
        }
    }
    if signing.is_none() {
        why.push("no signing slot".into());
        refused.push("/keys".into());
    }
    if !refused.is_empty() {
        return Err(NotRepresentable::new(
            NotRepresentableReason::KeyAlgorithm,
            refused,
            format!(
                "template '{}' needs {}; a did:webs key state holds one published Ed25519 \
                 signing key and one X25519 key agreement key. Create this identity as did:webvh.",
                template.name,
                why.join(", ")
            ),
        ));
    }
    if ka.is_none() {
        return Err(NotRepresentable::new(
            NotRepresentableReason::KeyAgreementRequired,
            vec!["/keys".into()],
            format!(
                "template '{}' declares no key agreement key; every did:webs DID designates one",
                template.name
            ),
        ));
    }
    Ok(())
}

/// Which of the two keys a verification method entry publishes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Publishes {
    Signing,
    KeyAgreement,
}

/// Map `rendered` — `template`'s document rendered for `did` with `keys` —
/// onto the designations a `did:webs` derivation expresses
/// (CONVENTIONS.md §9.2), checking every member.
///
/// The rules run in the order of the §9.2 table, and the first that fails is
/// the refusal; within it, every member that rule refuses is named.
///
/// # Errors
/// [`WebsTemplateRefusal::NotRepresentable`] for a member the derivation
/// cannot reproduce; [`WebsTemplateRefusal::ServiceIdConflict`] for two
/// services with one id.
pub fn map_webs_document(
    template: &DidTemplate,
    rendered: &Value,
    did: &str,
    keys: &WebsRenderedKeys,
) -> Result<WebsDesignations, WebsTemplateRefusal> {
    use NotRepresentableReason as R;
    check_key_shape(template)?;
    let name = &template.name;
    let refuse = |reason: R, members: Vec<String>, what: String| {
        WebsTemplateRefusal::NotRepresentable(NotRepresentable::new(
            reason,
            members,
            format!("template '{name}' {what}, which a did:webs derivation does not render"),
        ))
    };
    let doc = rendered.as_object().ok_or_else(|| {
        refuse(
            R::DocumentId,
            vec!["/document".into()],
            "is not an object".into(),
        )
    })?;

    // id, controller
    if doc.get("id").and_then(Value::as_str) != Some(did) {
        return Err(refuse(
            R::DocumentId,
            vec![doc_ptr("id")],
            "does not give `{DID}` as the document id".into(),
        ));
    }
    if let Some(c) = doc.get("controller")
        && c.as_str() != Some(did)
    {
        return Err(refuse(
            R::Controller,
            vec![doc_ptr("controller")],
            "names a controller other than the DID".into(),
        ));
    }

    // verificationMethod: one entry per key, each key once, nothing else.
    let mut vm_ids: Vec<(String, Publishes)> = Vec::new();
    let mut refused = Vec::new();
    let vms = match doc.get("verificationMethod") {
        None => &Vec::new(),
        Some(Value::Array(a)) => a,
        Some(_) => {
            return Err(refuse(
                R::VerificationMethod,
                vec![doc_ptr("verificationMethod")],
                "gives verificationMethod as something other than a list".into(),
            ));
        }
    };
    let publishes = |vm: &serde_json::Map<String, Value>| {
        if keys.signing.published_by(vm) {
            Some(Publishes::Signing)
        } else if keys.key_agreement.published_by(vm) {
            Some(Publishes::KeyAgreement)
        } else {
            None
        }
    };
    let mut seen_signing = false;
    let mut seen_ka = false;
    for (i, vm) in vms.iter().enumerate() {
        let Some(obj) = vm.as_object() else {
            refused.push(doc_ptr_at("verificationMethod", i));
            continue;
        };
        let controller_ok = obj
            .get("controller")
            .is_none_or(|c| c.as_str() == Some(did));
        match (publishes(obj), controller_ok) {
            (Some(Publishes::Signing), true) if !seen_signing => {
                seen_signing = true;
                if let Some(id) = obj.get("id").and_then(Value::as_str) {
                    vm_ids.push((id.to_string(), Publishes::Signing));
                }
            }
            (Some(Publishes::KeyAgreement), true) if !seen_ka => {
                seen_ka = true;
                if let Some(id) = obj.get("id").and_then(Value::as_str) {
                    vm_ids.push((id.to_string(), Publishes::KeyAgreement));
                }
            }
            _ => refused.push(doc_ptr_at("verificationMethod", i)),
        }
    }
    if !refused.is_empty() {
        return Err(refuse(
            R::VerificationMethod,
            refused,
            "describes a verification method other than the signing key and the key agreement \
             key, or one of them twice"
                .into(),
        ));
    }
    if !seen_signing {
        return Err(refuse(
            R::VerificationMethod,
            vec![doc_ptr("verificationMethod")],
            "does not publish the signing key, which the derivation always does".into(),
        ));
    }

    // A relationship entry, as the key it names: a reference to a
    // verification method above (absolute or relative to the DID), or an
    // embedded one.
    let entry_key = |entry: &Value| -> Option<Publishes> {
        match entry {
            Value::String(r) => {
                let absolute = if r.starts_with('#') {
                    format!("{did}{r}")
                } else {
                    r.clone()
                };
                vm_ids.iter().find_map(|(id, p)| {
                    let id_abs = if id.starts_with('#') {
                        format!("{did}{id}")
                    } else {
                        id.clone()
                    };
                    (id_abs == absolute).then_some(*p)
                })
            }
            Value::Object(o) if o.get("controller").is_none_or(|c| c.as_str() == Some(did)) => {
                publishes(o)
            }
            _ => None,
        }
    };
    // `member` lists exactly `want`, once: the members it refuses, or `None`
    // when it is absent.
    let relationship = |member: &str, want: Publishes| -> Option<Vec<String>> {
        let list = doc.get(member)?;
        let Some(items) = list.as_array() else {
            return Some(vec![doc_ptr(member)]);
        };
        let mut bad = Vec::new();
        let mut found = false;
        for (i, e) in items.iter().enumerate() {
            match entry_key(e) {
                Some(p) if p == want && !found => found = true,
                _ => bad.push(doc_ptr_at(member, i)),
            }
        }
        if !found && bad.is_empty() {
            bad.push(doc_ptr(member));
        }
        Some(bad)
    };

    // authentication, assertionMethod: the signing key, in both.
    let mut refused = Vec::new();
    for member in ["authentication", "assertionMethod"] {
        match relationship(member, Publishes::Signing) {
            None => refused.push(doc_ptr(member)),
            Some(bad) => refused.extend(bad),
        }
    }
    if !refused.is_empty() {
        return Err(refuse(
            R::VerificationRelationship,
            refused,
            "does not list exactly the signing key in authentication and assertionMethod".into(),
        ));
    }

    // keyAgreement: the key agreement key.
    if !seen_ka || doc.get("keyAgreement").is_none() {
        return Err(WebsTemplateRefusal::NotRepresentable(
            NotRepresentable::new(
                R::KeyAgreementRequired,
                vec![doc_ptr(if seen_ka {
                    "keyAgreement"
                } else {
                    "verificationMethod"
                })],
                format!(
                    "template '{name}' publishes no key agreement key; every did:webs DID designates \
                 one"
                ),
            ),
        ));
    }
    if let Some(bad) = relationship("keyAgreement", Publishes::KeyAgreement)
        && !bad.is_empty()
    {
        return Err(refuse(
            R::VerificationRelationship,
            bad,
            "lists something other than the key agreement key in keyAgreement".into(),
        ));
    }

    // capabilityInvocation, capabilityDelegation: never.
    let refused: Vec<String> = ["capabilityInvocation", "capabilityDelegation"]
        .into_iter()
        .filter(|m| doc.contains_key(*m))
        .map(doc_ptr)
        .collect();
    if !refused.is_empty() {
        return Err(refuse(
            R::VerificationRelationship,
            refused,
            "uses capabilityInvocation or capabilityDelegation".into(),
        ));
    }

    // service: each a designated service, its id a fragment of this DID.
    let mut services = Vec::new();
    match doc.get("service") {
        None => {}
        Some(Value::Array(entries)) => {
            let mut refused = Vec::new();
            if entries.len() > MAX_DESIGNATED_SERVICES {
                refused.push(doc_ptr("service"));
            }
            for (i, entry) in entries.iter().enumerate() {
                let fragment = entry.as_object().and_then(|o| {
                    if !o.contains_key("type") || !o.contains_key("serviceEndpoint") {
                        return None;
                    }
                    let id = o.get("id")?.as_str()?;
                    let frag = id.strip_prefix(did).unwrap_or(id);
                    (frag.starts_with('#') && frag.len() > 1).then(|| frag.to_string())
                });
                match fragment {
                    Some(frag) => {
                        let mut s = entry.clone();
                        s["id"] = Value::String(frag);
                        services.push(s);
                    }
                    None => refused.push(doc_ptr_at("service", i)),
                }
            }
            if !refused.is_empty() {
                return Err(refuse(
                    R::Service,
                    refused,
                    "describes a service the services designation cannot carry (an id naming \
                     another DID or not a fragment, an entry without `type` or \
                     `serviceEndpoint`, or more than 32 entries)"
                        .into(),
                ));
            }
            let mut ids = std::collections::BTreeSet::new();
            for s in &services {
                let id = s["id"].as_str().unwrap_or_default();
                if !ids.insert(id.to_string()) {
                    return Err(WebsTemplateRefusal::ServiceIdConflict { id: id.to_string() });
                }
            }
        }
        Some(_) => {
            return Err(refuse(
                R::Service,
                vec![doc_ptr("service")],
                "gives service as something other than a list".into(),
            ));
        }
    }

    // alsoKnownAs: DIDs, after the DID itself.
    let mut also_known_as = Vec::new();
    match doc.get("alsoKnownAs") {
        None => {}
        Some(Value::Array(entries)) => {
            let mut refused = Vec::new();
            for (i, e) in entries.iter().enumerate() {
                match e.as_str() {
                    Some(d) if d == did => {}
                    Some(d) if is_did(d) => {
                        if !also_known_as.iter().any(|a| a == d) {
                            also_known_as.push(d.to_string());
                        }
                    }
                    _ => refused.push(doc_ptr_at("alsoKnownAs", i)),
                }
            }
            if !refused.is_empty() {
                return Err(refuse(
                    R::Alias,
                    refused,
                    "lists an alias that is not a DID".into(),
                ));
            }
        }
        Some(_) => {
            return Err(refuse(
                R::Alias,
                vec![doc_ptr("alsoKnownAs")],
                "gives alsoKnownAs as something other than a list".into(),
            ));
        }
    }

    // Any other member: never (see `DOCUMENT_MEMBERS`, and #1164).
    let refused: Vec<String> = doc
        .keys()
        .filter(|k| !DOCUMENT_MEMBERS.contains(&k.as_str()))
        .map(|k| doc_ptr(k))
        .collect();
    if !refused.is_empty() {
        return Err(refuse(
            R::DocumentMember,
            refused,
            "carries a document member the derivation is not given".into(),
        ));
    }

    Ok(WebsDesignations {
        services,
        also_known_as,
    })
}

/// `did:<method>:<rest>`, the alias grammar of `alsoKnownAs` in the payload.
fn is_did(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("did:") else {
        return false;
    };
    let Some((method, tail)) = rest.split_once(':') else {
        return false;
    };
    !method.is_empty()
        && method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && !tail.is_empty()
}

/// Template kinds this VTA knows to be a node's or a service's identity: a
/// DID made from one is a `service` DID, and a VTA MAY refuse it under another
/// class (CONVENTIONS.md §9.2, `didClassConflict`).
///
/// Only the built-in kinds that can name nothing but a node are listed; a kind
/// that may be a person's or a relationship's (`ai-agent`, `room`, `group`,
/// `admin`, …) is not.
pub fn is_node_kind(kind: &str) -> bool {
    matches!(
        kind,
        "mediator"
            | "dtg-witness"
            | "push-gateway"
            | "trust-registry"
            | "vtc-host"
            | "room-host"
            | "ballot-box"
    ) || kind.starts_with("did-host-")
}

#[cfg(test)]
#[path = "webs_tests.rs"]
mod tests;
