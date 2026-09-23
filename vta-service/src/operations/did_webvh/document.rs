//! DID document construction for the did:webvh flow.
//!
//! Pure functions that take derived key material + config and emit a
//! DID document as `serde_json::Value`. No I/O, no keystore access —
//! tested in isolation and reused by both `create_did_webvh` (for the
//! integration's own doc) and the TEE enclave bootstrap path (for the
//! VTA's own doc, which additionally carries `#sealed-transfer-0`).
//!
//! `{DID}` placeholders in the output are substituted by the caller
//! once the webvh log has minted the self-certifying identifier; that
//! final stamping is not this module's concern.

use serde_json::json;

use crate::config::AppConfig;
use crate::keys::{self};
use vta_sdk::protocol::matching::DIDCOMM_SERVICE_TYPE;

use crate::error::AppError;
use crate::operations::protocol::document::{TSP_SERVICE_FRAGMENT, TSP_SERVICE_TYPE};

/// Append a `#tsp` (`TSPTransport`) entry to `additional` when the caller asked
/// for one **and** this VTA can actually carry TSP.
///
/// TSP advertises the *same* mediator as DIDComm (tsp-enablement.md D8), so the
/// endpoint is that mediator's DID — the transport URL lives in the mediator's
/// own document. Same fragment and type the setup path and the runtime `services
/// tsp enable` patcher emit, so a document minted here, one minted at setup, and
/// one patched later are the same shape.
///
/// Both gates matter and neither is redundant:
///
/// - **`add_tsp_service`** is the caller's. A DID advertising a transport its
///   *holder* cannot decode is unreachable over that transport, and only the
///   caller knows whether the client behind this DID reads TSP frames. That is
///   why this is opt-in rather than implied by `add_mediator_service`.
/// - **`services.tsp` + a configured mediator** is ours. Publishing `#tsp` from
///   a VTA whose own stack does not run TSP would mint the exact defect this
///   whole change exists to stop, one document at a time.
///
/// A caller that already hand-built a `TSPTransport` entry keeps theirs — two
/// `#tsp` services would be a malformed document, and theirs is the more
/// specific intent.
/// Resolve the three-state `addTspService` into the answer the document paths
/// take: an explicit request wins, and silence asks what this VTA and its
/// mediator can carry (Keyring VTI-Q11, #1652).
pub(crate) async fn resolve_add_tsp_service(
    requested: Option<bool>,
    config: &AppConfig,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
) -> bool {
    match requested {
        Some(explicit) => explicit,
        None => mediator_carries_tsp(config, resolver).await,
    }
}

/// Whether `#tsp` should be published for a DID whose caller did not say
/// (Keyring VTI-Q11, #1652).
///
/// The rule is the one VTA setup already applies to the VTA's own document:
/// this VTA must be built with TSP *and* the mediator it names must advertise
/// `TSPTransport`. A persona is minted through this path without the wire
/// field, so this is what decides it — and a persona behind a mediator that
/// does not route TSP stays DIDComm-only rather than advertising a transport
/// its peers cannot reach it on.
///
/// Unlike setup, an unresolvable mediator answers **no**. There the operator
/// named the mediator deliberately and the answer is a warning; here nobody
/// asked for `#tsp` at all, so the quiet default must be the one that cannot
/// publish a dead transport.
pub(crate) async fn mediator_carries_tsp(
    config: &AppConfig,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
) -> bool {
    if !config.services.tsp {
        return false;
    }
    let Some(mediator_did) = config
        .messaging
        .as_ref()
        .map(|m| m.mediator_did.trim())
        .filter(|did| !did.is_empty())
    else {
        return false;
    };

    let resolved = match resolver.resolve(mediator_did).await {
        Ok(r) => r,
        Err(e) => {
            tracing::info!(
                mediator = %mediator_did, error = %e,
                "could not resolve the mediator to see whether it carries TSP; \
                 minting this DID without `#tsp`",
            );
            return false;
        }
    };
    match serde_json::to_value(&resolved.doc) {
        Ok(doc) => vta_sdk::protocol::matching::ServiceCapabilities::from_did_document(&doc)
            .tsp
            .is_some(),
        Err(e) => {
            tracing::info!(
                mediator = %mediator_did, error = %e,
                "could not read the mediator's DID document; minting without `#tsp`",
            );
            false
        }
    }
}

pub(crate) fn with_tsp_service(
    add_tsp_service: bool,
    config: &AppConfig,
    additional: Option<Vec<serde_json::Value>>,
) -> Option<Vec<serde_json::Value>> {
    if !add_tsp_service || !config.services.tsp {
        return additional;
    }
    let Some(mediator_did) = config
        .messaging
        .as_ref()
        .map(|m| m.mediator_did.trim())
        .filter(|did| !did.is_empty())
    else {
        return additional;
    };

    let mut services = additional.unwrap_or_default();
    if services.iter().any(is_tsp_service) {
        return Some(services);
    }
    services.push(json!({
        "id": format!("{{DID}}{TSP_SERVICE_FRAGMENT}"),
        "type": TSP_SERVICE_TYPE,
        "serviceEndpoint": mediator_did,
    }));
    Some(services)
}

/// Whether a service entry advertises TSP. Matched on the service `type`, never
/// the `#id` fragment — the fragment is an arbitrary label (the OWF reference
/// implementation writes `#tsp-transport` where we write `#tsp`). DID-Core
/// permits `type` to be a string or an array of them.
fn is_tsp_service(service: &serde_json::Value) -> bool {
    match service.get("type") {
        Some(serde_json::Value::String(t)) => t == TSP_SERVICE_TYPE,
        Some(serde_json::Value::Array(types)) => {
            types.iter().any(|t| t.as_str() == Some(TSP_SERVICE_TYPE))
        }
        _ => false,
    }
}

/// Add a `#tsp` entry to a **template-rendered** document when the caller asked
/// for one, at the mediator the document's own DIDComm entry names.
///
/// A rendered template never reaches the builder [`with_tsp_service`] feeds —
/// `create_did_webvh` treats it as a caller-supplied document — so until this,
/// `addTspService` was accepted on the wire and silently dropped for every DID
/// minted from a template. A room, a room host, or any other templated identity
/// could not advertise TSP however it was asked, and nothing said so.
///
/// Two deliberate differences from [`with_tsp_service`]:
///
/// - **The endpoint is the document's mediator, not this VTA's.** A template
///   names its own (`MEDIATOR_DID`), and TSP binds the same mediator DIDComm
///   does (tsp-enablement.md D8, §14 Q2). Advertising this VTA's mediator on a
///   document routed elsewhere would give one DID a different mediator per
///   protocol.
/// - **`services.tsp` is not consulted.** That gate stops this VTA claiming a
///   transport *its own stack* cannot carry, on documents that route to its own
///   mediator. A templated DID's holder is usually something else — a room host
///   serving at its own `--mediator-did`, a community — and whether *that*
///   decodes TSP is the caller's claim, exactly as `SERVICE_TSP` is at
///   provisioning (see `vta_sdk::did_templates::transports`).
///
/// Refused rather than skipped when the document names no DIDComm mediator: a
/// TSP entry advertises a mediator DID, so there is nothing to point it at, and
/// minting without the entry the caller asked for is the defect this replaces.
/// A document that already carries a `TSPTransport` entry keeps it.
pub(crate) fn with_tsp_in_rendered_document(
    add_tsp_service: bool,
    document: &mut serde_json::Value,
) -> Result<(), AppError> {
    if !add_tsp_service {
        return Ok(());
    }
    let services = document
        .get("service")
        .and_then(serde_json::Value::as_array);
    if services.is_some_and(|s| s.iter().any(is_tsp_service)) {
        return Ok(());
    }
    let Some(mediator_did) = services.and_then(|s| s.iter().find_map(didcomm_mediator)) else {
        return Err(AppError::Validation(
            "addTspService: this document names no DIDComm mediator, and a TSP entry \
             advertises the same mediator DIDComm uses — there is nothing to point it at"
                .into(),
        ));
    };
    let entry = vta_sdk::did_templates::tsp_service(&mediator_did)
        .map_err(|e| AppError::Validation(format!("addTspService: {e}")))?;
    if let Some(services) = document
        .get_mut("service")
        .and_then(serde_json::Value::as_array_mut)
    {
        services.push(entry);
    }
    // Same ordering every other path that adds a transport ends with, so a
    // templated document and a built one agree on TSP > DIDComm > REST.
    crate::operations::protocol::document::sort_services_canonical(document);
    Ok(())
}

/// The mediator DID a `DIDCommMessaging` entry routes through.
///
/// DID-Core and DIDComm v2 allow three `serviceEndpoint` shapes — a bare
/// string, an object carrying `uri`, or an array of either — and templates use
/// the array form. Only a DID counts: a URL there is not a mediator a TSP entry
/// could name.
fn didcomm_mediator(service: &serde_json::Value) -> Option<String> {
    let is_didcomm = match service.get("type") {
        Some(serde_json::Value::String(t)) => t == DIDCOMM_SERVICE_TYPE,
        Some(serde_json::Value::Array(types)) => types
            .iter()
            .any(|t| t.as_str() == Some(DIDCOMM_SERVICE_TYPE)),
        _ => false,
    };
    if !is_didcomm {
        return None;
    }
    let uri = match service.get("serviceEndpoint")? {
        serde_json::Value::Array(items) => items.iter().find_map(endpoint_uri),
        other => endpoint_uri(other),
    };
    uri.map(str::trim)
        .filter(|u| u.starts_with("did:"))
        .map(str::to_owned)
}

fn endpoint_uri(endpoint: &serde_json::Value) -> Option<&str> {
    match endpoint {
        serde_json::Value::String(s) => Some(s),
        serde_json::Value::Object(o) => o.get("uri").and_then(serde_json::Value::as_str),
        _ => None,
    }
}

/// Build a DID document with the given keys.
///
/// When `include_ka` is true (default for VTA-derived keys), adds a
/// keyAgreement verification method. When false (signing-only DID),
/// the document contains only authentication/assertion.
pub fn build_did_document(
    derived: &keys::DerivedEntityKeys,
    config: &AppConfig,
    add_mediator_service: bool,
    additional_services: &Option<Vec<serde_json::Value>>,
) -> serde_json::Value {
    build_did_document_inner(
        derived,
        None,
        config,
        true,
        add_mediator_service,
        additional_services,
    )
}

/// Build a DID document for the VTA's own DID, which additionally
/// exposes `#sealed-transfer-0` as a distinct verification method.
///
/// Use this only when minting the VTA's own did:webvh — template-
/// provisioned integration DIDs should use [`build_did_document`].
pub fn build_vta_did_document_with_sealed_transfer(
    derived: &keys::DerivedEntityKeys,
    sealed_transfer: &keys::DerivedSealedTransferKey,
    config: &AppConfig,
    add_mediator_service: bool,
    additional_services: &Option<Vec<serde_json::Value>>,
) -> serde_json::Value {
    build_did_document_inner(
        derived,
        Some(sealed_transfer),
        config,
        true,
        add_mediator_service,
        additional_services,
    )
}

/// Build a DID document with optional keyAgreement support.
pub(crate) fn build_did_document_with_options(
    derived: &keys::DerivedEntityKeys,
    config: &AppConfig,
    include_ka: bool,
    add_mediator_service: bool,
    additional_services: &Option<Vec<serde_json::Value>>,
) -> serde_json::Value {
    build_did_document_inner(
        derived,
        None,
        config,
        include_ka,
        add_mediator_service,
        additional_services,
    )
}

fn build_did_document_inner(
    derived: &keys::DerivedEntityKeys,
    sealed_transfer: Option<&keys::DerivedSealedTransferKey>,
    config: &AppConfig,
    include_ka: bool,
    add_mediator_service: bool,
    additional_services: &Option<Vec<serde_json::Value>>,
) -> serde_json::Value {
    let mut vm = vec![json!({
        "id": "{DID}#key-0",
        "type": "Multikey",
        "controller": "{DID}",
        "publicKeyMultibase": &derived.signing_pub
    })];

    let mut assertion_method = vec![json!("{DID}#key-0")];

    let mut did_document = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://www.w3.org/ns/cid/v1"
        ],
        "id": "{DID}",
        "authentication": ["{DID}#key-0"]
    });

    if include_ka {
        vm.push(json!({
            "id": "{DID}#key-1",
            "type": "Multikey",
            "controller": "{DID}",
            "publicKeyMultibase": &derived.ka_pub
        }));
        did_document["keyAgreement"] = json!(["{DID}#key-1"]);
    }

    if let Some(st) = sealed_transfer {
        vm.push(json!({
            "id": "{DID}#sealed-transfer-0",
            "type": "Multikey",
            "controller": "{DID}",
            "publicKeyMultibase": &st.public_key
        }));
        // Sealed-transfer signatures are assertion-flavoured (the VTA
        // asserting "I produced this bundle"), so the key appears in
        // assertionMethod alongside `#key-0`.
        assertion_method.push(json!("{DID}#sealed-transfer-0"));
    }

    did_document["assertionMethod"] = json!(assertion_method);
    did_document["verificationMethod"] = json!(vm);

    // Optionally add mediator DIDComm service
    if add_mediator_service && let Some(ref msg) = config.messaging {
        let services = did_document
            .as_object_mut()
            .unwrap()
            .entry("service")
            .or_insert_with(|| json!([]));
        services.as_array_mut().unwrap().push(json!({
            "id": "{DID}#vta-didcomm",
            "type": "DIDCommMessaging",
            "serviceEndpoint": [{
                "accept": ["didcomm/v2"],
                "uri": msg.mediator_did
            }]
        }));
    }

    // Append any additional services
    if let Some(svcs) = additional_services {
        let services = did_document
            .as_object_mut()
            .unwrap()
            .entry("service")
            .or_insert_with(|| json!([]));
        for svc in svcs {
            services.as_array_mut().unwrap().push(svc.clone());
        }
    }

    // Add TeeAttestation service when TEE is active and embed_in_did is enabled
    #[cfg(feature = "tee")]
    if config.tee.embed_in_did
        && let Some(ref public_url) = config.public_url
    {
        let services = did_document
            .as_object_mut()
            .unwrap()
            .entry("service")
            .or_insert_with(|| json!([]));
        services.as_array_mut().unwrap().push(json!({
            "id": "{DID}#tee-attestation",
            "type": "TeeAttestation",
            "serviceEndpoint": format!("{}/attestation/report", public_url.trim_end_matches('/'))
        }));
    }

    // `service[]` order is what tells a resolver which transport to
    // prefer (TSP > DIDComm > REST > WebAuthn — runtime-service-
    // management spec §3.3), and the entries above are appended in
    // construction order, not preference order: DIDComm before the
    // caller's `additional_services`, which is where `#tsp` arrives.
    // Sort through the same helper every runtime `with_*_service`
    // patcher ends with, so a document minted here and one patched by
    // `services … enable` agree.
    crate::operations::protocol::document::sort_services_canonical(&mut did_document);

    did_document
}

/// The highest `#key-N` any of a document's verification methods publishes.
///
/// Its own function because a rotation allocates from one past it, and create
/// and the realign repair must agree on what "one past" means — a rotation that
/// reuses a live method id republishes that name under different key material.
/// `None` for a document that numbers its methods some other way (`vta-admin`
/// names one after its own key), where there is no numbering to collide with.
pub(crate) fn highest_key_fragment(document: &serde_json::Value) -> Option<u32> {
    document
        .get("verificationMethod")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|vm| vm.get("id").and_then(serde_json::Value::as_str))
        .filter_map(|id| id.rsplit_once("#key-"))
        .filter_map(|(_, n)| n.parse::<u32>().ok())
        .max()
}

/// The verification-method ids a created document actually publishes, for the
/// two keys the DID was minted with.
///
/// ## Why this is read back rather than assumed
///
/// A key record's id **is** a verification-method id — `save_entity_key_records`
/// says so, and [`vta_sdk::did_secrets::select_secret_kid`] rule 1 depends on
/// it: the kid a mediator matches inbound JWE recipients against is the record
/// id, on the reasoning that "the DID document decided what the key is called".
///
/// Create did not read the document to find out. It named the records
/// `{did}#key-0` and `{did}#key-1` while the document was whatever the caller
/// or the template said — and the `room` and `room-host` built-in templates
/// number their methods from `#key-1`. So on every room and room host:
///
/// - the document's `#key-1` is the **signing** key and the keystore's `#key-1`
///   is the **x25519** one. One name, two keys, and no error anywhere;
/// - the document's `keyAgreement` (`#key-2`) matches no record, so an authcrypt
///   message addressed to it unpacks to `No local secret matches any JWE
///   recipient` — the storm.ws outage of PR #337, reached from the other side;
/// - `next_fragment_id` was stored as 2, so the first rotation allocates
///   `#key-2` over the id the key-agreement key already published under.
///
/// Matching on `publicKeyMultibase` rather than on position or on a `#key-N`
/// shape is what makes this total: it is right for a template that numbers from
/// 1, for `vta-admin` (whose method id is `{DID}#{SIGNING_KEY_MB}`), and for a
/// document an operator wrote by hand. Anything the document does not name
/// falls back to the historical `#key-0` / `#key-1`, which is the best available
/// answer for a document that does not carry the key at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MintedVmIds {
    /// The id the signing key is published under.
    pub signing: String,
    /// The id the key-agreement key is published under, when there is one.
    pub key_agreement: Option<String>,
    /// One past the highest `#key-N` the document declares — what a rotation
    /// may allocate from without colliding with a published method.
    pub next_fragment_id: u32,
    /// The id each additional signing slot is published under, by slot name.
    ///
    /// Found the same way as the other two — by matching `publicKeyMultibase`,
    /// not by position or by a `#key-N` shape — so a template that numbers its
    /// methods any way it likes still gets records named what its own document
    /// says. A slot the document does not carry is absent here rather than
    /// falling back to a guessed fragment: there is no historical name for a
    /// slot that has no history, and storing a record under an id nothing
    /// publishes is the exact failure this function exists to prevent.
    pub additional_signing: std::collections::BTreeMap<String, String>,
}

/// Read [`MintedVmIds`] out of a document, substituting `{DID}` for `did`.
///
/// `signing_pub` / `ka_pub` are the multibase public halves this DID was minted
/// with; a method carrying one of them is that key, whatever it is called.
pub(crate) fn minted_vm_ids(
    document: &serde_json::Value,
    did: &str,
    signing_pub: &str,
    ka_pub: Option<&str>,
    additional_signing: &[(String, String)],
) -> MintedVmIds {
    let methods = document
        .get("verificationMethod")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();

    let id_carrying = |public_key: &str| -> Option<String> {
        methods
            .iter()
            .find(|vm| {
                vm.get("publicKeyMultibase")
                    .and_then(serde_json::Value::as_str)
                    == Some(public_key)
            })
            .and_then(|vm| vm.get("id"))
            .and_then(serde_json::Value::as_str)
            .map(|id| id.replace("{DID}", did))
    };

    let highest = highest_key_fragment(document);

    MintedVmIds {
        signing: id_carrying(signing_pub).unwrap_or_else(|| format!("{did}#key-0")),
        key_agreement: ka_pub.and_then(id_carrying),
        // No numeric fragment anywhere is a document naming its methods some
        // other way, and 2 is what create has always stored — there is nothing
        // to collide with, so this stays as it was rather than inventing a
        // number from the method count.
        next_fragment_id: highest.map_or(2, |n| n + 1),
        additional_signing: additional_signing
            .iter()
            .filter_map(|(slot, public_key)| id_carrying(public_key).map(|id| (slot.clone(), id)))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use affinidi_tdk::secrets_resolver::secrets::Secret;

    use super::*;
    use crate::config::MessagingConfig;

    /// Deterministic key material — this module only reads the public
    /// multibase strings out of it.
    fn fake_keys() -> keys::DerivedEntityKeys {
        let signing_secret = Secret::generate_ed25519(None, Some(&[7u8; 32]));
        let ka_secret = Secret::generate_ed25519(None, Some(&[9u8; 32]))
            .to_x25519()
            .expect("x25519 conversion");
        keys::DerivedEntityKeys {
            signing_pub: signing_secret.get_public_keymultibase().unwrap(),
            signing_secret,
            signing_path: "m/26'/2'/0'/0'".into(),
            signing_priv: String::new(),
            signing_label: "signing".into(),
            ka_pub: ka_secret.get_public_keymultibase().unwrap(),
            ka_secret,
            ka_path: "m/26'/2'/0'/1'".into(),
            ka_priv: String::new(),
            ka_label: "ka".into(),
            signing_key_type: vta_sdk::keys::KeyType::Ed25519,
            ka_key_type: vta_sdk::keys::KeyType::X25519,
            additional_signing: Vec::new(),
        }
    }

    /// `service[]` order encodes transport preference to a resolver, and
    /// the entries are appended here in construction order — DIDComm
    /// before the caller's `additional_services`, which is where `#tsp`
    /// and `#vta-rest` arrive. The builder must leave them canonically
    /// ordered (TSP > DIDComm > REST) regardless.
    #[test]
    fn services_are_published_in_canonical_transport_order() {
        let mut config = crate::test_support::test_app_config(std::path::PathBuf::from("/tmp/x"));
        config.messaging = Some(MessagingConfig {
            mediator_url: "https://mediator.example.com".into(),
            mediator_did: "did:webvh:mediator.example.com:mediator".into(),
            mediator_host: None,
            setup_acl: false,
            drain_inbox_on_start: false,
        });

        // The order the setup path hands them over: TSP then REST, both
        // *after* the DIDComm entry this builder pushes itself.
        let additional = Some(vec![
            json!({
                "id": "{DID}#tsp",
                "type": "TSPTransport",
                "serviceEndpoint": "did:webvh:mediator.example.com:mediator",
            }),
            json!({
                "id": "{DID}#vta-rest",
                "type": "VTARest",
                "serviceEndpoint": "https://vta.example.com",
            }),
        ]);

        let doc = build_did_document(&fake_keys(), &config, true, &additional);
        let types: Vec<&str> = doc["service"]
            .as_array()
            .expect("service array")
            .iter()
            .map(|s| s["type"].as_str().unwrap())
            .collect();
        assert_eq!(types, ["TSPTransport", "DIDCommMessaging", "VTARest"]);
    }

    const MEDIATOR: &str = "did:webvh:mediator.example.com:mediator";

    /// A VTA config with a mediator and `services.tsp` set as asked.
    pub(super) fn config_with(tsp: bool, mediator: Option<&str>) -> crate::config::AppConfig {
        let mut config = crate::test_support::test_app_config(std::path::PathBuf::from("/tmp/x"));
        config.services.tsp = tsp;
        config.messaging = mediator.map(|did| MessagingConfig {
            mediator_url: "https://mediator.example.com".into(),
            mediator_did: did.into(),
            mediator_host: None,
            setup_acl: false,
            drain_inbox_on_start: false,
        });
        config
    }

    fn tsp_endpoints(services: &Option<Vec<serde_json::Value>>) -> Vec<&str> {
        services
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter(|s| super::is_tsp_service(s))
            .map(|s| s["serviceEndpoint"].as_str().unwrap())
            .collect()
    }

    /// The point of the field: a minted DID can now advertise the same mediator
    /// for TSP that it already advertises for DIDComm, so a peer's both-ends
    /// transport match can actually land on TSP.
    #[test]
    fn tsp_is_added_at_the_didcomm_mediator_when_asked() {
        let out = with_tsp_service(true, &config_with(true, Some(MEDIATOR)), None);
        assert_eq!(tsp_endpoints(&out), [MEDIATOR]);
    }

    /// Opt-in: the flag off mints exactly what it did before this field existed.
    #[test]
    fn tsp_is_absent_unless_the_caller_asks() {
        let out = with_tsp_service(false, &config_with(true, Some(MEDIATOR)), None);
        assert!(out.is_none());
    }

    /// The gate that stops this change spreading the defect it was written for:
    /// a VTA not running TSP must not mint documents claiming it does, however
    /// insistently the caller asks.
    #[test]
    fn a_vta_without_tsp_enabled_never_advertises_it() {
        let out = with_tsp_service(true, &config_with(false, Some(MEDIATOR)), None);
        assert!(out.is_none(), "services.tsp = false must veto the entry");
    }

    /// TSP advertises a *mediator*, so with no mediator configured there is
    /// nothing to point at — and an endpoint-less `#tsp` is worse than none.
    #[test]
    fn no_mediator_means_no_tsp_entry() {
        let out = with_tsp_service(true, &config_with(true, None), None);
        assert!(out.is_none());
    }

    /// A caller who hand-built their own `TSPTransport` keeps it: two `#tsp`
    /// services would be a malformed document. Matched on `type`, so the OWF
    /// reference spelling of the fragment is recognised too.
    #[test]
    fn a_caller_supplied_tsp_service_is_not_duplicated() {
        let caller = json!({
            "id": "{DID}#tsp-transport",
            "type": "TSPTransport",
            "serviceEndpoint": "did:webvh:other.example:mediator",
        });
        let out = with_tsp_service(true, &config_with(true, Some(MEDIATOR)), Some(vec![caller]));
        assert_eq!(
            tsp_endpoints(&out),
            ["did:webvh:other.example:mediator"],
            "the caller's entry must survive, and must be the only one"
        );
    }

    /// Existing entries are preserved alongside the injected one — this appends,
    /// it does not replace.
    #[test]
    fn other_additional_services_are_preserved() {
        let rest = json!({
            "id": "{DID}#vta-rest",
            "type": "VTARest",
            "serviceEndpoint": "https://vta.example.com",
        });
        let out = with_tsp_service(true, &config_with(true, Some(MEDIATOR)), Some(vec![rest]))
            .expect("services");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["type"], "VTARest");
        assert_eq!(tsp_endpoints(&Some(out)), [MEDIATOR]);
    }

    // ── Template-rendered documents ─────────────────────────────────────────
    //
    // Rendered from the real built-ins, the way `create_did_webvh` renders them,
    // so a template that changes its service block is caught here rather than
    // at the first mint.

    const ROOM_MEDIATOR: &str = "did:webvh:QmRoomMediator:mediator.example.com";

    fn render_builtin(name: &str, extra: &[(&str, &str)]) -> serde_json::Value {
        let template = vta_sdk::did_templates::load_embedded(name).expect("builtin template");
        let mut vars = vta_sdk::did_templates::TemplateVars::new();
        vars.insert_string("DID", "{DID}");
        vars.insert_string("SIGNING_KEY_MB", "z6MkSigningExample");
        vars.insert_string("KA_KEY_MB", "z6LSkaExample");
        for (k, v) in extra {
            vars.insert_string(*k, *v);
        }
        template.render(&vars).expect("render")
    }

    fn service_types(doc: &serde_json::Value) -> Vec<&str> {
        doc["service"]
            .as_array()
            .expect("service array")
            .iter()
            .map(|s| s["type"].as_str().expect("type"))
            .collect()
    }

    /// The defect: a room minted from its template could not advertise TSP at
    /// all. Asked, it now does — at the room's own mediator, first.
    #[test]
    fn a_templated_room_advertises_tsp_at_its_own_mediator_when_asked() {
        let mut doc = render_builtin(
            "room",
            &[("WEBVH_SERVER", "prod"), ("MEDIATOR_DID", ROOM_MEDIATOR)],
        );
        with_tsp_in_rendered_document(true, &mut doc).expect("tsp added");
        assert_eq!(service_types(&doc), ["TSPTransport", "DIDCommMessaging"]);
        assert_eq!(doc["service"][0]["id"], "{DID}#tsp");
        assert_eq!(doc["service"][0]["serviceEndpoint"], ROOM_MEDIATOR);
    }

    /// A room host carries REST beside DIDComm. TSP joins them in canonical
    /// order and the REST entry — the one the agent calls a host on — survives.
    #[test]
    fn a_templated_room_host_keeps_its_rest_entry_in_canonical_order() {
        let mut doc = render_builtin(
            "room-host",
            &[
                ("WEBVH_SERVER", "prod"),
                ("URL", "https://rooms.example.com"),
                ("MEDIATOR_DID", ROOM_MEDIATOR),
            ],
        );
        with_tsp_in_rendered_document(true, &mut doc).expect("tsp added");
        assert_eq!(
            service_types(&doc),
            ["TSPTransport", "DIDCommMessaging", "VTARest"]
        );
        assert_eq!(doc["service"][0]["serviceEndpoint"], ROOM_MEDIATOR);
    }

    /// Opt-in: not asked, the rendered document is exactly what the template
    /// produced.
    #[test]
    fn a_rendered_document_is_untouched_unless_the_caller_asks() {
        let rendered = render_builtin(
            "room",
            &[("WEBVH_SERVER", "prod"), ("MEDIATOR_DID", ROOM_MEDIATOR)],
        );
        let mut doc = rendered.clone();
        with_tsp_in_rendered_document(false, &mut doc).expect("no-op");
        assert_eq!(doc, rendered);
    }

    /// `ai-agent` already publishes `#tsp`. Asking again must not produce a
    /// second entry — two `#tsp` services would be a malformed document.
    #[test]
    fn a_template_that_already_advertises_tsp_is_not_duplicated() {
        let mut doc = render_builtin("ai-agent", &[("MEDIATOR_DID", ROOM_MEDIATOR)]);
        with_tsp_in_rendered_document(true, &mut doc).expect("left as is");
        let tsp = service_types(&doc)
            .into_iter()
            .filter(|t| *t == "TSPTransport")
            .count();
        assert_eq!(tsp, 1);
    }

    /// `did-host-http` names no mediator. A TSP entry advertises one, so the
    /// request is refused rather than quietly minting without it.
    #[test]
    fn asking_for_tsp_on_a_document_with_no_mediator_is_refused() {
        let mut doc = render_builtin("did-host-http", &[("URL", "https://host.example.com")]);
        let err = with_tsp_in_rendered_document(true, &mut doc).expect_err("refused");
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
    }

    /// All three `serviceEndpoint` shapes resolve to the mediator, and a URL in
    /// any of them does not.
    #[test]
    fn the_didcomm_mediator_is_found_in_every_endpoint_shape() {
        for endpoint in [
            json!(ROOM_MEDIATOR),
            json!({ "uri": ROOM_MEDIATOR }),
            json!([{ "uri": ROOM_MEDIATOR, "accept": ["didcomm/v2"] }]),
        ] {
            let svc = json!({ "type": "DIDCommMessaging", "serviceEndpoint": endpoint });
            assert_eq!(didcomm_mediator(&svc).as_deref(), Some(ROOM_MEDIATOR));
        }
        let url = json!({ "type": "DIDCommMessaging", "serviceEndpoint": "https://m.example.com" });
        assert_eq!(didcomm_mediator(&url), None);
    }

    // ── The names a created DID's key records take ──────────────────────────
    //
    // Every one of these is driven through the **real** built-in templates
    // rather than a hand-written document. The defect was not a bug in reading
    // a document — it was never reading one, so a test against a fixture of my
    // own choosing would have agreed with the broken code.

    const DID: &str = "did:webvh:QmScid:example.com:rooms:northwind";

    fn rendered(template: &str, derived: &keys::DerivedEntityKeys) -> serde_json::Value {
        let tpl = vta_sdk::did_templates::load_embedded(template)
            .unwrap_or_else(|e| panic!("built-in `{template}` failed to load: {e}"));
        let mut vars = vta_sdk::did_templates::TemplateVars::new();
        vars.insert_string("DID", "{DID}");
        vars.insert_string("SIGNING_KEY_MB", derived.signing_pub.clone());
        vars.insert_string("KA_KEY_MB", derived.ka_pub.clone());
        vars.insert_string("WEBVH_SERVER", "https://webvh.example.com");
        vars.insert_string("URL", "https://rooms.example.com/");
        vars.insert_string("MEDIATOR_DID", "did:webvh:QmMed:example.com:mediator");
        vars.insert_string("VTA_DID", "did:webvh:QmVta:example.com");
        vars.insert_string("VTA_URL", "https://vta.example.com");
        vars.insert_string("CONTEXT_ID", "rooms");
        vars.insert_string("NOW", "2026-09-14T00:00:00Z");
        tpl.render(&vars)
            .unwrap_or_else(|e| panic!("built-in `{template}` failed to render: {e}"))
    }

    /// The floor: nothing about a document this crate builds changes.
    #[test]
    fn the_builders_own_document_still_names_key_0_and_key_1() {
        let derived = fake_keys();
        let config = crate::test_support::test_app_config(std::path::PathBuf::from("/tmp/x"));
        let doc = build_did_document(&derived, &config, false, &None);

        let ids = minted_vm_ids(&doc, DID, &derived.signing_pub, Some(&derived.ka_pub), &[]);
        assert_eq!(ids.signing, format!("{DID}#key-0"));
        assert_eq!(ids.key_agreement.as_deref(), Some(&*format!("{DID}#key-1")));
        assert_eq!(ids.next_fragment_id, 2);
    }

    /// The bug, at the two templates that carry it. A room's records were
    /// stored as `#key-0` / `#key-1` while its published document said `#key-1`
    /// / `#key-2` — so one name, `#key-1`, meant the signing key to every
    /// resolver and the x25519 key to the agent holding it.
    #[test]
    fn a_template_numbering_its_methods_from_one_is_followed() {
        let derived = fake_keys();
        for template in ["room", "room-host"] {
            let doc = rendered(template, &derived);
            let ids = minted_vm_ids(&doc, DID, &derived.signing_pub, Some(&derived.ka_pub), &[]);

            // Read off the document rather than asserted as `#key-1`: the point
            // is that the records follow whatever it says, so renumbering the
            // template later must not make this test lie.
            let published = |public_key: &str| -> String {
                doc["verificationMethod"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|vm| vm["publicKeyMultibase"] == public_key)
                    .map(|vm| vm["id"].as_str().unwrap().replace("{DID}", DID))
                    .unwrap_or_else(|| panic!("`{template}` publishes no method for that key"))
            };
            assert_eq!(ids.signing, published(&derived.signing_pub), "{template}");
            assert_eq!(
                ids.key_agreement.as_deref(),
                Some(&*published(&derived.ka_pub)),
                "{template}",
            );

            // And the two are never the same record, which is what the old
            // pairing produced the moment the document's signing method landed
            // on the id the keystore had given the x25519 key.
            assert_ne!(
                ids.signing,
                ids.key_agreement.clone().unwrap(),
                "{template}"
            );
        }
    }

    /// A rotation allocates from `next_fragment_id`. Stored as a constant 2, a
    /// room's first rotation would have minted `#key-2` — the id its own
    /// key-agreement method was already published under.
    #[test]
    fn next_fragment_id_clears_every_method_the_document_published() {
        let derived = fake_keys();
        let doc = rendered("room-host", &derived);
        let ids = minted_vm_ids(&doc, DID, &derived.signing_pub, Some(&derived.ka_pub), &[]);

        let highest = doc["verificationMethod"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|vm| vm["id"].as_str())
            .filter_map(|id| id.rsplit_once("#key-"))
            .filter_map(|(_, n)| n.parse::<u32>().ok())
            .max()
            .expect("room-host numbers its methods");
        assert!(
            ids.next_fragment_id > highest,
            "a rotation would allocate #key-{} over a published method",
            ids.next_fragment_id,
        );
    }

    /// `vta-admin` names its method `{DID}#{SIGNING_KEY_MB}`. Matching on the
    /// public key rather than on a `#key-N` shape is what makes that work — and
    /// is why there is no fragment-numbering rule anywhere in this function.
    #[test]
    fn a_method_named_by_its_own_key_is_still_found() {
        let derived = fake_keys();
        let doc = rendered("vta-admin", &derived);
        let ids = minted_vm_ids(&doc, DID, &derived.signing_pub, None, &[]);

        assert_eq!(ids.signing, format!("{DID}#{}", derived.signing_pub));
        assert_eq!(
            ids.key_agreement, None,
            "vta-admin publishes no keyAgreement"
        );
        assert!(
            !ids.signing.contains("{DID}"),
            "the sentinel was not stamped"
        );
    }

    /// A document that does not carry the key says nothing about what it is
    /// called, so the historical name is the best answer there is — and is
    /// still better than storing nothing.
    #[test]
    fn a_document_that_names_neither_key_falls_back_to_the_old_pair() {
        let derived = fake_keys();
        let doc = json!({ "id": "{DID}", "verificationMethod": [] });
        let ids = minted_vm_ids(&doc, DID, &derived.signing_pub, Some(&derived.ka_pub), &[]);

        assert_eq!(ids.signing, format!("{DID}#key-0"));
        assert_eq!(ids.key_agreement, None);
        assert_eq!(ids.next_fragment_id, 2);
    }
}

#[cfg(test)]
mod mediator_capability_tests {
    use super::tests::config_with;
    use super::{mediator_carries_tsp, resolve_add_tsp_service};
    use affinidi_did_resolver_cache_sdk::DIDCacheClient;
    use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
    use affinidi_tdk::dids::{PeerService, PeerServiceEndpoint};

    async fn resolver() -> DIDCacheClient {
        DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("resolver")
    }

    /// A did:peer that really resolves, advertising exactly the services given
    /// — the mediator under test.
    fn mediator_did(services: Vec<PeerService>) -> String {
        let (did, _secrets) = crate::operations::did_peer::mint_did_peer_with_services(services)
            .expect("mint did:peer");
        did
    }

    fn tsp_service() -> PeerService {
        PeerService {
            type_: "TSPTransport".into(),
            endpoint: PeerServiceEndpoint::Uri("https://mediator.example.com".into()),
            id: Some("#tsp".into()),
        }
    }

    fn didcomm_service() -> PeerService {
        PeerService {
            type_: "dm".into(),
            endpoint: PeerServiceEndpoint::Uri("https://mediator.example.com".into()),
            id: None,
        }
    }

    /// Keyring VTI-Q11 (#1652): the quiet default publishes `#tsp` only when
    /// this VTA carries TSP *and* its mediator advertises it.
    #[tokio::test]
    async fn tsp_is_advertised_only_when_the_vta_and_its_mediator_both_carry_it() {
        let r = resolver().await;

        let carries = mediator_did(vec![tsp_service(), didcomm_service()]);
        assert!(
            mediator_carries_tsp(&config_with(true, Some(&carries)), &r).await,
            "a TSP VTA behind a TSP mediator advertises #tsp"
        );

        let didcomm_only = mediator_did(vec![didcomm_service()]);
        assert!(
            !mediator_carries_tsp(&config_with(true, Some(&didcomm_only)), &r).await,
            "a mediator that does not route TSP leaves the DID DIDComm-only"
        );

        assert!(
            !mediator_carries_tsp(&config_with(false, Some(&carries)), &r).await,
            "a VTA not built with TSP never advertises it, whatever the mediator carries"
        );

        assert!(
            !mediator_carries_tsp(&config_with(true, None), &r).await,
            "no mediator, nothing to advertise through"
        );

        // Unresolvable: the conservative answer, unlike setup's warn-and-proceed —
        // nobody asked for `#tsp` here, so it must not publish a dead transport.
        assert!(
            !mediator_carries_tsp(&config_with(true, Some("did:web:nonexistent.invalid")), &r)
                .await,
            "a mediator that cannot be resolved does not get #tsp by default"
        );
    }

    /// What the wire field means once it reaches the mint: silence asks the
    /// mediator, and an explicit answer is obeyed either way.
    #[tokio::test]
    async fn an_explicit_request_wins_over_the_capability_default() {
        let r = resolver().await;
        let carries = mediator_did(vec![tsp_service(), didcomm_service()]);
        let capable = config_with(true, Some(&carries));
        let not_capable = config_with(false, Some(&carries));

        // Silence: the persona case. The capability decides.
        assert!(resolve_add_tsp_service(None, &capable, &r).await);
        assert!(!resolve_add_tsp_service(None, &not_capable, &r).await);

        // `false` still means no, however capable the stack is — a holder that
        // cannot decode TSP frames says so and is believed.
        assert!(!resolve_add_tsp_service(Some(false), &capable, &r).await);

        // `true` is passed through; `with_tsp_service` still applies its own
        // `services.tsp` + mediator gates downstream.
        assert!(resolve_add_tsp_service(Some(true), &not_capable, &r).await);
    }
}
