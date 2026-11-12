//! `did:webs` DIDs: create, get, list, update, rotate and delete (the last
//! three in [`lifecycle`]), and this VTA's own did:webs identity's first
//! publication ([`publish_own_identity`]).
//!
//! A relationship, persona or service DID is level 1 (one Ed25519 signing
//! key, `kt 1`, and one pre-rotated successor, `nt 1`); a node's durable
//! identity is a key-role identity (`key_roles`, VTI-KEY-173). KERI v2 with
//! JSON bodies, through `affinidi-did-webs`' controller API. Design:
//! `docs/05-design-notes/did-webs-in-the-vta.md`. **Alpha**, and off at
//! runtime unless `[dids] webs_enabled`.
//!
//! VTI-KEY-001 admits `did:webs` as an optional method for a node's durable
//! identity. This VTA takes one at setup (`vta_did` kind `create_webs`),
//! never by a create addressed to its own context
//! ([`WebsRefusal::NodeIdentityContext`]). A `create/0.2` states the DID's
//! class (CONVENTIONS.md 0.2 §1), records it, and may make a level-1 service
//! DID where `[dids] webs_service_dids` allows; it may also be shaped by a DID
//! template ([`template`], §9).
//!
//! # Keys
//!
//! The signing key, the key agreement key and the successor are derived from
//! the seed at paths allocated under the context's base, exactly as
//! `did:webvh` creation derives its keys. The signing key's private half is
//! held only for the inception and the designations signed with it, inside a
//! `affinidi_keri_crypto::Signer` that zeroizes it on drop. Later events sign
//! through `key_custody::derive_record_key`, from the key record.
//!
//! # Publication
//!
//! The DID is `did:webs:{domain}[:{path}]:{AID}`, which is what the hosting
//! service builds from the slot `{path}/{AID}`. The stream is published
//! before any key record or row is written (R2.1): a failed publish leaves
//! only allocated derivation paths behind, never a record of a DID that does
//! not resolve.

use std::future::Future;

use affinidi_did_webs::key_roles::{KeyRoles, VerificationKey};
use affinidi_did_webs::{CreateConfig, DesignatedService, KeyAgreementKey, create_controlled};
use affinidi_keri::controller::{Inception, KeySigner, NextKey};
use affinidi_keri_core::threshold::Threshold;
use affinidi_keri_crypto::{Signer, Verfer};
use serde_json::json;
use zeroize::Zeroizing;

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::keys::seed_store::SeedStore;
use crate::keys::seeds::{get_active_seed_id, load_seed_bytes};
use crate::keys::{self, KeyType};
use crate::operations::protocol::document::{TSP_SERVICE_FRAGMENT, TSP_SERVICE_TYPE};
use crate::store::KeyspaceHandle;
use crate::webs_store::{self, WebsDidClass, WebsDidRecord, WebsTemplateUse};
use crate::webvh_host::RequestUriResponse;
use vta_sdk::protocol::matching::DIDCOMM_SERVICE_TYPE;

/// The id of a designated DIDComm service: the emitted convention
/// (`#didcomm`), matched by peers on its `type`, never on this fragment.
pub const DIDCOMM_FRAGMENT: &str = "#didcomm";

/// What a create needs from the store and the node.
pub struct WebsDeps<'a> {
    pub keys_ks: &'a KeyspaceHandle,
    pub contexts_ks: &'a KeyspaceHandle,
    pub webvh_ks: &'a KeyspaceHandle,
    pub webs_ks: &'a KeyspaceHandle,
    /// The stored DID templates, for a create from a template; `None` where no
    /// template is read (setup), and a create naming one then fails.
    pub did_templates_ks: Option<&'a KeyspaceHandle>,
    /// For the `KeyMint` gate; `None` only for offline callers (as for
    /// `did:webvh` creation).
    pub acl_ks: Option<&'a KeyspaceHandle>,
    pub audit: &'a vta_audit::SharedAuditSink,
    pub seed_store: &'a dyn SeedStore,
    pub config: &'a AppConfig,
    pub did_resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
}

impl<'a> WebsDeps<'a> {
    /// The deps of a request served by `s`, under its config `config`.
    pub fn from_app_state(
        s: &'a crate::server::AppState,
        config: &'a AppConfig,
        did_resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
    ) -> Self {
        Self {
            keys_ks: &s.keys_ks,
            contexts_ks: &s.contexts_ks,
            webvh_ks: &s.webvh_ks,
            webs_ks: &s.webs_ks,
            did_templates_ks: Some(&s.did_templates_ks),
            acl_ks: Some(&s.acl_ks),
            audit: &s.audit_sink,
            seed_store: &*s.seed_store,
            config,
            did_resolver,
        }
    }
}

/// A did-hosting service, as a create needs it.
///
/// The real one is [`crate::webvh_host::WebvhHostClient`]; tests publish to a
/// recording fake.
pub trait WebsHost {
    /// The domain to publish on: `requested` if the host serves it for this
    /// VTA, otherwise the host's default. A `Validation` error when it serves
    /// neither.
    fn resolve_domain(
        &self,
        requested: Option<&str>,
    ) -> impl Future<Output = Result<String, AppError>> + Send;

    /// Publish `keri_cesr` to `mnemonic` (`{path}/{AID}`), claiming the slot
    /// if it is free.
    fn publish(
        &self,
        mnemonic: &str,
        keri_cesr: &str,
        domain: Option<&str>,
    ) -> impl Future<Output = Result<RequestUriResponse, AppError>> + Send;

    /// Remove the slot `mnemonic` (`did/delete/0.1`).
    fn delete(
        &self,
        mnemonic: &str,
        domain: Option<&str>,
    ) -> impl Future<Output = Result<(), AppError>> + Send;
}

/// A borrowed host is a host: the handler lends one it owns.
impl<T: WebsHost + Sync> WebsHost for &T {
    fn resolve_domain(
        &self,
        requested: Option<&str>,
    ) -> impl Future<Output = Result<String, AppError>> + Send {
        (**self).resolve_domain(requested)
    }

    fn publish(
        &self,
        mnemonic: &str,
        keri_cesr: &str,
        domain: Option<&str>,
    ) -> impl Future<Output = Result<RequestUriResponse, AppError>> + Send {
        (**self).publish(mnemonic, keri_cesr, domain)
    }

    fn delete(
        &self,
        mnemonic: &str,
        domain: Option<&str>,
    ) -> impl Future<Output = Result<(), AppError>> + Send {
        (**self).delete(mnemonic, domain)
    }
}

impl WebsHost for crate::webvh_host::WebvhHostClient<'_> {
    async fn resolve_domain(&self, requested: Option<&str>) -> Result<String, AppError> {
        let domains = self.my_domains().await?.domains;
        let mut active = domains
            .iter()
            .filter(|d| d.status.to_string() == "active")
            .collect::<Vec<_>>();
        if let Some(requested) = requested {
            return active
                .iter()
                .find(|d| d.name == requested)
                .map(|d| d.name.clone())
                .ok_or_else(|| {
                    AppError::Validation(format!(
                        "the hosting server does not serve the domain {requested} for this VTA"
                    ))
                });
        }
        if let Some(d) = active.iter().find(|d| d.default_domain == Some(true)) {
            return Ok(d.name.clone());
        }
        match active.len() {
            1 => Ok(active.remove(0).name.clone()),
            0 => Err(AppError::Validation(
                "the hosting server serves no active domain to publish a did:webs on".into(),
            )),
            _ => Err(AppError::Validation(
                "the hosting server serves several domains and marks none default: name one \
                 with `domain`"
                    .into(),
            )),
        }
    }

    async fn publish(
        &self,
        mnemonic: &str,
        keri_cesr: &str,
        domain: Option<&str>,
    ) -> Result<RequestUriResponse, AppError> {
        self.publish_webs(mnemonic, keri_cesr, domain).await
    }

    async fn delete(&self, mnemonic: &str, domain: Option<&str>) -> Result<(), AppError> {
        self.delete_did(mnemonic, domain).await
    }
}

/// A create request, as the `vta/webs/dids/create` handler will pass it.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct CreateDidWebsParams {
    /// The trust context the DID and its keys belong to.
    pub context_id: String,
    /// The did-hosting server to publish on (a registered webvh server).
    pub server_id: String,
    /// Slot path before the AID, `/`-separated (`people/alice`); `None`
    /// publishes at the domain's top level.
    pub path: Option<String>,
    /// The host domain; `None` takes the server's default.
    pub domain: Option<String>,
    pub label: Option<String>,
    /// Designate `#didcomm` through this VTA's mediator.
    pub add_mediator_service: bool,
    /// Designate `#tsp`; `None` asks whether this VTA and its mediator carry
    /// TSP, as `did:webvh` creation does.
    pub add_tsp_service: Option<bool>,
    /// Further `alsoKnownAs` identifiers to designate.
    pub also_known_as: Vec<String>,
    /// Make the new DID its context's primary DID. Refused where that primary
    /// is a node's service identity (VTI-KEY-001).
    pub set_primary: bool,
    /// Further designated services, beside `#didcomm` and `#tsp`.
    pub additional_services: Vec<DesignatedService>,
    /// Make it a key-role identity (VTI-KEY-070, VTI-KEY-173): distinct
    /// `attestation` and `operational` Ed25519 keys and a `messaging` X25519
    /// key, designated by the key-role extension, with the key event log's
    /// own key in no relationship. What a node's durable identity needs
    /// (design note did-webs-in-the-vta §4, decision 2). Off: one key event
    /// log key for every relationship, and a designated key agreement key.
    pub key_roles: bool,
    /// Mint and record the DID without reaching its host: for setup, which is
    /// offline and whose VTA has no standing at the host yet. `domain` must be
    /// given (the host is not asked for its default), and the record is left
    /// unpublished for [`publish_own_identity`] at first boot, which
    /// registers it on its own authority (design note §4, decision 3).
    pub defer_publish: bool,
    /// The DID class (`create/0.2`'s `didClass`), recorded with the DID.
    /// `None` is a `create/0.1` request, which states none: none is recorded
    /// and none inferred, and the class rules of CONVENTIONS.md 0.2 §1.2 do
    /// not apply to it.
    pub did_class: Option<WebsDidClass>,
    /// Shape the services and aliases from a DID template instead of the
    /// explicit members above (`add_mediator_service`, `add_tsp_service`,
    /// `also_known_as`, `additional_services`), which must then be left unset
    /// (CONVENTIONS.md 0.2 §9.3).
    pub template: Option<WebsTemplateRequest>,
}

/// A DID template to shape a create from (`template`, `templateContext`,
/// `templateVars`).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct WebsTemplateRequest {
    pub name: String,
    /// The context scope to look in first; then global, then the built-ins.
    pub context: Option<String>,
    /// The caller's variables, checked against the template's declarations.
    pub vars: std::collections::BTreeMap<String, serde_json::Value>,
}

impl WebsTemplateRequest {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }
}

impl CreateDidWebsParams {
    pub fn new(context_id: impl Into<String>, server_id: impl Into<String>) -> Self {
        Self {
            context_id: context_id.into(),
            server_id: server_id.into(),
            ..Self::default()
        }
    }
}

/// What a create made.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CreateDidWebsResult {
    pub did: String,
    pub aid: String,
    pub mnemonic: String,
    pub domain: String,
    pub signing_key_id: String,
    pub next_key_id: String,
    pub key_agreement_key_id: String,
    /// The `attestation` key's record, for a key-role identity.
    pub attestation_key_id: Option<String>,
    /// The `operational` key's record, for a key-role identity.
    pub operational_key_id: Option<String>,
    /// The sequence number of the latest event: the inception, then one
    /// interaction event per designation registry event.
    pub sn: u64,
    /// The class it was created in, as recorded.
    pub did_class: Option<WebsDidClass>,
    /// The template it was shaped from, as recorded.
    pub template: Option<WebsTemplateUse>,
}

/// `did:webs:` + this, + `:{AID}`, is the DID: the domain's port separator
/// percent-encoded, then each path segment.
pub(crate) fn did_host_label(domain: &str, path: Option<&str>) -> String {
    let mut label = domain.replace(':', "%3A");
    if let Some(path) = path {
        for segment in path.split('/') {
            label.push(':');
            label.push_str(segment);
        }
    }
    label
}

/// A slot path is the host's to validate in full; refuse here only what would
/// make the DID and the slot disagree.
pub fn check_path(path: &str) -> Result<(), AppError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains("//")
        || path.contains(':')
        || path.contains('%')
    {
        return Err(AppError::Validation(format!(
            "path {path:?} is not a slot path: `/`-separated segments, no `:` or `%`"
        )));
    }
    Ok(())
}

/// An Ed25519 public key in multibase (`z` + multicodec `0xed01`), as key
/// records hold it, in CESR (`D…`), as a key event holds it.
pub(crate) fn ed25519_qb64(public_multibase: &str) -> Result<String, AppError> {
    let raw = ed25519_raw(public_multibase)?;
    Verfer::new("D", raw.to_vec())
        .and_then(|v| v.qb64())
        .map_err(|e| AppError::Internal(format!("encode an Ed25519 key in CESR: {e}")))
}

/// The raw 32 bytes of an Ed25519 public key in multibase (`z` + `0xed01`).
pub(crate) fn ed25519_raw(public_multibase: &str) -> Result<[u8; 32], AppError> {
    let (_, bytes) = multibase::decode(public_multibase)
        .map_err(|e| AppError::Internal(format!("public key {public_multibase}: {e}")))?;
    bytes
        .strip_prefix(&[0xed, 0x01][..])
        .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
        .ok_or_else(|| AppError::Internal(format!("{public_multibase} is not an Ed25519 key")))
}

/// A KERI signer over an Ed25519 private key the VTA derived. The bytes are
/// copied into the signer, which zeroizes them on drop.
/// The active seed, for keys minted fresh at paths allocated under a context's
/// base: create's three keys, and an update's or rotation's new successor or
/// key agreement key. The one raw seed access of this module (key custody
/// census): no caller names a path or a key id, and a key a record already
/// names is re-derived through `key_custody::derive_record_key` instead.
async fn active_seed(deps: &WebsDeps<'_>) -> Result<(Zeroizing<Vec<u8>>, u32), AppError> {
    let active_seed_id = get_active_seed_id(deps.keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let seed = load_seed_bytes(deps.keys_ks, deps.seed_store, Some(active_seed_id))
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    Ok((seed, active_seed_id))
}

/// A fresh Ed25519 key at a path allocated under `base`: a successor, or the
/// Ed25519 key whose X25519 image is a new key agreement key.
async fn fresh_key(
    deps: &WebsDeps<'_>,
    base: &str,
    label: &str,
) -> Result<(keys::PreRotationKeyData, u32), AppError> {
    let (seed, seed_id) = active_seed(deps).await?;
    let (_, mut derived) =
        keys::derivation::derive_pre_rotation_keys(&seed, base, label, deps.keys_ks, 1).await?;
    drop(seed);
    let key = derived
        .pop()
        .ok_or_else(|| AppError::Internal("no key was derived".into()))?;
    Ok((key, seed_id))
}

pub(crate) fn ed25519_signer(private: &[u8]) -> Result<Signer, AppError> {
    if private.len() != 32 {
        return Err(AppError::Internal(
            "an Ed25519 private key is 32 bytes".into(),
        ));
    }
    Signer::new("A", private.to_vec())
        .map_err(|e| AppError::Internal(format!("build a KERI signer: {e}")))
}

/// Create a `did:webs` in `params.context_id`, publish it and record it.
///
/// # Order (CONVENTIONS.md 0.2 §9.1, conformance items 1–7)
///
/// 1. The gates that need nothing derived: `KeyMint` and the context,
///    `methodDisabled`, `serviceDidNotPermitted`, the path, `serverNotFound`
///    and the class rules (`didClassConflict`).
/// 2. With a template: resolve it (`templateNotFound`), check its variables
///    (`templateVarsInvalid`), and render it once with placeholder keys and DID
///    to check every member (`templateNotRepresentable`) — all before a key is
///    derived, so a refused template leaves nothing at all.
/// 3. The domain (`domainNotServed`): part of the DID.
/// 4. Derive the keys and compute the inception, whose digest is the AID; the
///    DID is built from it.
/// 5. With a template: render it again with the real DID and keys, and map it
///    onto the designations. No key record exists yet.
/// 6. Write the events, publish, and only then record the keys and the DID
///    (R2.1): a refusal from here leaves only allocated derivation paths.
///
/// # Errors
/// `Forbidden` without `KeyMint` or context access; the declared refusals
/// above; `NotFound` for an unknown context; the host's refusal as it
/// reported it.
pub async fn create_did_webs<H: WebsHost>(
    deps: &WebsDeps<'_>,
    auth: &AuthClaims,
    params: CreateDidWebsParams,
    host: &H,
    channel: &str,
) -> Result<CreateDidWebsResult, WebsError> {
    crate::operations::did_webvh::ensure_may_mint(deps.acl_ks, auth).await?;
    auth.require_context(&params.context_id)?;
    mint(deps, Minter::Caller(auth), params, host, channel).await
}

/// On whose authority a `did:webs` is minted.
enum Minter<'a> {
    /// A caller [`create_did_webs`] has checked for `KeyMint` and the context.
    Caller(&'a AuthClaims),
    /// The node itself, minting its own identity before any principal exists
    /// ([`own_identity::create_own_identity`]). Named in the audit row by
    /// `actor`; never a template's caller.
    FirstBoot { actor: &'a str },
}

impl Minter<'_> {
    fn actor(&self) -> &str {
        match self {
            Self::Caller(auth) => &auth.did,
            Self::FirstBoot { actor } => actor,
        }
    }
}

/// [`create_did_webs`] past its caller's gates.
async fn mint<H: WebsHost>(
    deps: &WebsDeps<'_>,
    minter: Minter<'_>,
    params: CreateDidWebsParams,
    host: &H,
    channel: &str,
) -> Result<CreateDidWebsResult, WebsError> {
    if !deps.config.dids.webs_enabled {
        return Err(WebsError::refused(
            WebsRefusal::MethodDisabled,
            "did:webs creation is off on this VTA (alpha): set `webs_enabled = true` under \
             `[dids]` (or VTA_DIDS_WEBS_ENABLED=true) to turn it on",
        ));
    }
    // A level-1 service DID is enabled separately (CONVENTIONS.md 0.2 §1.1). A
    // key-role identity is not this family's (§1): setup makes one for this
    // VTA under its own switch.
    if params.did_class == Some(WebsDidClass::Service)
        && !params.key_roles
        && !deps.config.dids.webs_service_dids
    {
        return Err(WebsError::refused(
            WebsRefusal::ServiceDidNotPermitted,
            "did:webs service DIDs are off on this VTA (alpha). Peers that have not declared \
             did:webs resolution may not verify one; enable it with [dids] webs_service_dids = \
             true (or VTA_DIDS_WEBS_SERVICE_DIDS=true), or create the identity as did:webvh.",
        ));
    }
    if let Some(path) = params.path.as_deref() {
        check_path(path)
            .map_err(|e| WebsError::refused(WebsRefusal::PathRefused, e.to_string()))?;
    }
    crate::webvh_store::get_server(deps.webvh_ks, &params.server_id)
        .await?
        .ok_or_else(|| {
            WebsError::refused(
                WebsRefusal::ServerNotFound,
                format!("hosting server not found: {}", params.server_id),
            )
        })?;
    let mut ctx = crate::contexts::get_context(deps.contexts_ks, &params.context_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {}", params.context_id)))?;
    if params.set_primary {
        match params.did_class {
            None => refuse_service_context(deps.config, &ctx)?,
            Some(class) => check_primary_class(deps, &ctx, class).await?,
        }
    }

    // ── The template, checked before anything is derived (§9.1, §9.2) ──
    let template = match &params.template {
        Some(request) => match &minter {
            Minter::Caller(auth) => Some(plan_template(deps, auth, &params, &ctx, request).await?),
            Minter::FirstBoot { .. } => {
                return Err(AppError::Internal(
                    "a node's own identity is not shaped from a DID template".into(),
                )
                .into());
            }
        },
        None => None,
    };

    let domain = if params.defer_publish {
        // Setup cannot ask the host: the domain is the operator's to name.
        params.domain.clone().ok_or_else(|| {
            WebsError::App(AppError::Validation(
                "a did:webs minted without its host names its domain".into(),
            ))
        })?
    } else {
        host.resolve_domain(params.domain.as_deref())
            .await
            .map_err(|e| match e {
                AppError::Validation(m) => WebsError::refused(WebsRefusal::DomainNotServed, m),
                e => WebsError::from_host(e),
            })?
    };
    let label = params
        .label
        .clone()
        .unwrap_or_else(|| format!("did:webs in {}", params.context_id));

    // ── Keys, at paths allocated under the context's base ──────────────
    let (seed, active_seed_id) = active_seed(deps).await?;
    let derived = keys::derive_entity_keys(
        &seed,
        &ctx.base_path,
        &format!("{label} signing key"),
        &format!("{label} key-agreement key"),
        deps.keys_ks,
    )
    .await
    .map_err(|e| AppError::Internal(format!("{e}")))?;
    let (_, successors) =
        keys::derivation::derive_pre_rotation_keys(&seed, &ctx.base_path, &label, deps.keys_ks, 1)
            .await?;
    drop(seed);
    let successor = successors
        .into_iter()
        .next()
        .ok_or_else(|| AppError::Internal("no successor key was derived".into()))?;

    let signer = ed25519_signer(derived.signing_secret.get_private_bytes())?;
    let signing_qb64 = signer
        .verfer()
        .qb64()
        .map_err(|e| AppError::Internal(format!("encode the signing key: {e}")))?;
    let next_qb64 = ed25519_qb64(&successor.public_key)?;
    let ka_raw: [u8; 32] = derived
        .ka_secret
        .get_public_bytes()
        .try_into()
        .map_err(|_| AppError::Internal("an X25519 public key is 32 bytes".into()))?;
    let key_agreement = KeyAgreementKey::X25519(ka_raw);
    let ka_cesr = key_agreement
        .to_cesr()
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    // A key-role identity's `attestation` and `operational` keys: two more
    // Ed25519 keys, each its own path, neither a key event log key (a role
    // key that were one would bind nothing, VTI-KEY-071). The `messaging` key
    // is the X25519 key above, derived on its own path, never converted from
    // an Ed25519 key (VTI-KEY-184).
    let role_keys = if params.key_roles {
        let (attestation, _) =
            fresh_key(deps, &ctx.base_path, &format!("{label} attestation key")).await?;
        let (operational, _) =
            fresh_key(deps, &ctx.base_path, &format!("{label} operational key")).await?;
        let cesr = |key: &keys::PreRotationKeyData| -> Result<(VerificationKey, String), AppError> {
            let vk = VerificationKey::Ed25519(ed25519_raw(&key.public_key)?);
            let cesr = vk
                .to_cesr()
                .map_err(|e| AppError::Internal(format!("encode a role key: {e}")))?;
            Ok((vk, cesr))
        };
        let (attestation_vk, attestation_cesr) = cesr(&attestation)?;
        let (operational_vk, operational_cesr) = cesr(&operational)?;
        Some(RoleKeys {
            attestation,
            attestation_vk,
            attestation_cesr,
            operational,
            operational_vk,
            operational_cesr,
        })
    } else {
        None
    };

    // ── The inception, and the DID it makes (§9.1 item 4) ──────────────
    // The AID is the digest of an inception event that carries no services or
    // aliases, so it is known before the designations are written, and a
    // template can be rendered with `{DID}` as the DID it will be.
    let inception = Inception::new(
        vec![signing_qb64.clone()],
        Threshold::Simple(1),
        vec![NextKey::PublicKey(next_qb64)],
        Threshold::Simple(1),
    );
    let aid = affinidi_keri::controller::incept(&inception)
        .map_err(|e| AppError::Internal(format!("compute the inception event: {e}")))?
        .said;
    let host_label = did_host_label(&domain, params.path.as_deref());
    let did = format!("did:webs:{host_label}:{aid}");

    let mut builder = CreateConfig::builder(host_label.clone()).controlled(inception);
    builder = match &role_keys {
        Some(roles) => builder.key_roles(
            KeyRoles::new()
                .with_attestation(roles.attestation_vk.clone())
                .with_operational(roles.operational_vk.clone())
                .with_messaging(key_agreement),
        ),
        None => builder.key_agreement(key_agreement),
    };

    // ── Designations ───────────────────────────────────────────────────
    let (mut services, aliases, template_use) = match &template {
        Some(plan) => {
            // §9.1 items 3–4: render with the final DID and the keys the
            // inception was computed with, and map it member by member.
            let rendered_keys = rendered_keys(&derived.signing_pub, &derived.ka_pub);
            let vars = ambient_vars(deps, &params, &ctx, plan, &did, &rendered_keys);
            let designations = render_and_map(plan, &vars, &did, &rendered_keys)?;
            let services = designations
                .services
                .iter()
                .map(designated_service_from_json)
                .collect::<Result<Vec<_>, _>>()?;
            (
                services,
                designations.also_known_as,
                Some(plan.used.clone()),
            )
        }
        None => {
            let (services, aliases) = explicit_designations(deps, &params).await?;
            (services, aliases, None)
        }
    };
    // A resolver renders designated services in the designation's order, and
    // peers walking `service[]` take the first transport they share, so the
    // designation is in transport-preference order (TSP > DIDComm > REST),
    // whatever order the template or the request gave.
    sort_designated_services(&mut services);
    for service in services {
        builder = builder.designated_service(service);
    }
    for aka in aliases {
        builder = builder.also_known_as(aka);
    }

    let created = create_controlled(builder.build(), &[&signer as &dyn KeySigner])
        .map_err(|e| AppError::Internal(format!("create the did:webs: {e}")))?;
    drop(signer);
    let created_did = created.did().to_string();
    let (artifacts, state) = created.into_parts();
    if state.prefix != aid {
        return Err(AppError::Internal(format!(
            "the inception established {}, not the AID {aid} it was computed to",
            state.prefix
        ))
        .into());
    }
    let mnemonic = match params.path.as_deref() {
        Some(path) => format!("{path}/{aid}"),
        None => aid.clone(),
    };
    if created_did != did {
        return Err(AppError::Internal(format!(
            "created {created_did}, but the host would serve {did} from slot {mnemonic}"
        ))
        .into());
    }
    let keri_cesr = String::from_utf8(artifacts.keri_cesr.clone()).map_err(|_| {
        AppError::Internal("the key event stream is not text; it cannot be published".into())
    })?;

    // ── Publish, then commit (R2.1) ────────────────────────────────────
    // Deferred, nothing exists outside this VTA until first boot publishes
    // it, so the commit below is the whole of the effect.
    if !params.defer_publish {
        let published = host
            .publish(&mnemonic, &keri_cesr, Some(&domain))
            .await
            .map_err(WebsError::from_host)?;
        check_published(&published, &did, &mnemonic)?;
    }

    let signing_key_id = format!("{did}#{signing_qb64}");
    let key_agreement_key_id = format!("{did}#{ka_cesr}");
    let next_key_id = format!("{did}#pre-rotation-0");
    let save = |key_id: String, path: String, key_type: KeyType, public: String, what: String| {
        let keys_ks = deps.keys_ks;
        let context_id = params.context_id.clone();
        async move {
            keys::save_key_record(
                keys_ks,
                &key_id,
                &path,
                key_type,
                &public,
                &what,
                Some(&context_id),
                Some(active_seed_id),
            )
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))
        }
    };
    save(
        signing_key_id.clone(),
        derived.signing_path.clone(),
        KeyType::Ed25519,
        derived.signing_pub.clone(),
        derived.signing_label.clone(),
    )
    .await?;
    save(
        key_agreement_key_id.clone(),
        derived.ka_path.clone(),
        KeyType::X25519,
        derived.ka_pub.clone(),
        derived.ka_label.clone(),
    )
    .await?;
    save(
        next_key_id.clone(),
        successor.path.clone(),
        KeyType::Ed25519,
        successor.public_key.clone(),
        successor.label.clone(),
    )
    .await?;
    // A role key's record is named by the id the document gives it, so the
    // VTA finds it by role (`NodeKeyIds::from_document`).
    let mut attestation_key_id = None;
    let mut operational_key_id = None;
    if let Some(roles) = &role_keys {
        for (cesr, key, slot) in [
            (
                &roles.attestation_cesr,
                &roles.attestation,
                &mut attestation_key_id,
            ),
            (
                &roles.operational_cesr,
                &roles.operational,
                &mut operational_key_id,
            ),
        ] {
            let key_id = format!("{did}#{cesr}");
            save(
                key_id.clone(),
                key.path.clone(),
                KeyType::Ed25519,
                key.public_key.clone(),
                key.label.clone(),
            )
            .await?;
            *slot = Some(key_id);
        }
    }

    let now = chrono::Utc::now().to_rfc3339();
    let sn = state.sn;
    webs_store::put(
        deps.webs_ks,
        &WebsDidRecord {
            did: did.clone(),
            aid: aid.clone(),
            context_id: params.context_id.clone(),
            server_id: params.server_id.clone(),
            mnemonic: mnemonic.clone(),
            domain: Some(domain.clone()),
            label: params.label.clone(),
            keri_cesr: artifacts.keri_cesr,
            state,
            signing_key_id: signing_key_id.clone(),
            next_key_id: next_key_id.clone(),
            key_agreement_key_id: key_agreement_key_id.clone(),
            attestation_key_id: attestation_key_id.clone(),
            operational_key_id: operational_key_id.clone(),
            did_class: params.did_class,
            template: template_use.clone(),
            published: !params.defer_publish,
            staged: None,
            deactivated: false,
            slot_removed: false,
            created_at: now.clone(),
            updated_at: now,
        },
    )
    .await?;

    if params.set_primary {
        ctx.did = Some(did.clone());
        ctx.updated_at = chrono::Utc::now();
        crate::contexts::store_context(deps.contexts_ks, &ctx)
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))?;
    }

    vta_audit::record_best_effort(
        deps.audit,
        "did.create.webs",
        minter.actor(),
        Some(&did),
        "success",
        Some(channel),
        Some(&params.context_id),
    )
    .await;

    Ok(CreateDidWebsResult {
        did,
        aid,
        mnemonic,
        domain,
        signing_key_id,
        next_key_id,
        key_agreement_key_id,
        attestation_key_id,
        operational_key_id,
        sn,
        did_class: params.did_class,
        template: template_use,
    })
}

/// Put `services` in transport-preference order by `type` — TSP, DIDComm,
/// REST, WebAuthn, then the rest as they came
/// ([`crate::operations::protocol::document::service_type_rank`]). Stable.
pub fn sort_designated_services(services: &mut [DesignatedService]) {
    services.sort_by_key(|s| crate::operations::protocol::document::service_type_rank(&s.type_));
}

/// The explicit designations of a request without a template: `#didcomm` and
/// `#tsp` at this VTA's mediator, the additional services, the aliases.
async fn explicit_designations(
    deps: &WebsDeps<'_>,
    params: &CreateDidWebsParams,
) -> Result<(Vec<DesignatedService>, Vec<String>), WebsError> {
    let mut services = Vec::new();
    let mediator = deps
        .config
        .messaging
        .as_ref()
        .map(|m| m.mediator_did.trim().to_string())
        .filter(|did| !did.is_empty());
    let add_tsp = crate::operations::did_webvh::document::resolve_add_tsp_service(
        params.add_tsp_service,
        deps.config,
        deps.did_resolver,
    )
    .await;
    if let Some(mediator) = mediator.as_deref() {
        if add_tsp {
            services.push(DesignatedService::new(
                TSP_SERVICE_FRAGMENT,
                TSP_SERVICE_TYPE,
                json!(mediator),
            ));
        }
        if params.add_mediator_service {
            services.push(DesignatedService::new(
                DIDCOMM_FRAGMENT,
                DIDCOMM_SERVICE_TYPE,
                json!([{ "accept": ["didcomm/v2"], "uri": mediator }]),
            ));
        }
    } else if params.add_mediator_service || params.add_tsp_service == Some(true) {
        return Err(WebsError::App(AppError::Validation(
            "a #didcomm or #tsp service routes through this VTA's mediator, and none is \
             configured (`[messaging] mediator_did`)"
                .into(),
        )));
    }
    let mut ids = std::collections::BTreeSet::new();
    if mediator.is_some() && add_tsp {
        ids.insert(TSP_SERVICE_FRAGMENT.to_string());
    }
    if mediator.is_some() && params.add_mediator_service {
        ids.insert(DIDCOMM_FRAGMENT.to_string());
    }
    for service in &params.additional_services {
        if !ids.insert(service.id.clone()) {
            return Err(WebsError::refused(
                WebsRefusal::ServiceIdConflict,
                format!("serviceIdConflict: two services have the id {}", service.id),
            ));
        }
        services.push(service.clone());
    }
    Ok((services, params.also_known_as.clone()))
}

/// A service entry as JSON (`id`, `type`, `serviceEndpoint`, and any further
/// members) as a designated service. The id is a `#fragment`; a `{DID}#…` id,
/// as a DID-document builder writes one before the DID exists, is taken by
/// its fragment, since a designation names a service of the DID it is in.
///
/// # Errors
/// `Validation` for an entry without an id, a `type` or a `serviceEndpoint`.
pub fn designated_service_from_json(v: &serde_json::Value) -> Result<DesignatedService, AppError> {
    let malformed = || AppError::Validation(format!("not a service entry: {v}"));
    let id = v
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(malformed)?;
    let id = id.strip_prefix("{DID}").unwrap_or(id);
    let mut service = DesignatedService::new(
        id,
        "",
        v.get("serviceEndpoint").ok_or_else(malformed)?.clone(),
    );
    service.type_ = v.get("type").ok_or_else(malformed)?.clone();
    if let Some(map) = v.as_object() {
        for (k, val) in map {
            if !matches!(k.as_str(), "id" | "type" | "serviceEndpoint") {
                service.properties.insert(k.clone(), val.clone());
            }
        }
    }
    Ok(service)
}

/// The host published `did` at `mnemonic`, or the publication is refused.
fn check_published(
    published: &RequestUriResponse,
    did: &str,
    mnemonic: &str,
) -> Result<(), WebsError> {
    if published.did_url != did {
        return Err(WebsError::App(AppError::Internal(format!(
            "the hosting server published {} for slot {mnemonic}, not {did}; nothing was \
             recorded here, and the slot must be reconciled on the server",
            published.did_url
        ))));
    }
    Ok(())
}

/// Publish this VTA's own did:webs if setup minted it without its host
/// (`defer_publish`): register its key event log at its slot, on the
/// identifier's own authority — the host accepts a did:webs outside its ACL
/// whose request is signed by a key that log establishes, on a domain whose
/// operator allows it (design note §4, decision 3; affinidi-webvh-service
/// `[[hosting.webs_self_register]]`). Afterwards the host has granted it an
/// owner entry, and every later write takes the ordinary path.
///
/// `Ok(false)`: nothing to do — not a did:webs, no record, or already
/// published. Idempotent: a retry after a lost reply registers the same
/// slot again, which the host answers as the same identifier.
///
/// # Errors
/// The host's refusal, or a host that published another identifier.
pub async fn publish_own_identity<H: WebsHost>(
    webs_ks: &KeyspaceHandle,
    vta_did: &str,
    host: &H,
) -> Result<bool, WebsError> {
    if !vta_did.starts_with("did:webs:") {
        return Ok(false);
    }
    let Some(mut record) = webs_store::get(webs_ks, vta_did).await? else {
        return Ok(false);
    };
    if record.published {
        return Ok(false);
    }
    let keri_cesr = String::from_utf8(record.keri_cesr.clone()).map_err(|_| {
        AppError::Internal("the key event stream is not text; it cannot be published".into())
    })?;
    let published = host
        .publish(&record.mnemonic, &keri_cesr, record.domain.as_deref())
        .await
        .map_err(WebsError::from_host)?;
    check_published(&published, vta_did, &record.mnemonic)?;
    record.published = true;
    record.updated_at = chrono::Utc::now().to_rfc3339();
    webs_store::put(webs_ks, &record).await?;
    Ok(true)
}

/// The host setup hands [`create_did_webs`] with `defer_publish`: it is never
/// asked anything, and says so if it were.
pub struct NoHost;

impl WebsHost for NoHost {
    async fn resolve_domain(&self, _requested: Option<&str>) -> Result<String, AppError> {
        Err(AppError::Internal(
            "no did-hosting server is reachable here (offline setup)".into(),
        ))
    }

    async fn publish(
        &self,
        _mnemonic: &str,
        _keri_cesr: &str,
        _domain: Option<&str>,
    ) -> Result<RequestUriResponse, AppError> {
        Err(AppError::Internal(
            "no did-hosting server is reachable here (offline setup)".into(),
        ))
    }

    async fn delete(&self, _mnemonic: &str, _domain: Option<&str>) -> Result<(), AppError> {
        Err(AppError::Internal(
            "no did-hosting server is reachable here (offline setup)".into(),
        ))
    }
}

/// A key-role identity's `attestation` and `operational` keys, minted for a
/// create.
struct RoleKeys {
    attestation: keys::PreRotationKeyData,
    attestation_vk: VerificationKey,
    attestation_cesr: String,
    operational: keys::PreRotationKeyData,
    operational_vk: VerificationKey,
    operational_cesr: String,
}

/// The record of `did`, for a caller who may act in its context.
///
/// An unknown DID and one in a context the caller cannot reach answer alike.
///
/// # Errors
/// `NotFound` for both.
pub async fn get_did_webs(
    webs_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    did: &str,
) -> Result<WebsDidRecord, AppError> {
    webs_store::get(webs_ks, did)
        .await?
        .filter(|r| auth.has_context_access(&r.context_id))
        .ok_or_else(|| AppError::NotFound(format!("did:webs not found: {did}")))
}

/// The `did:webs` records of `context_id`.
///
/// # Errors
/// `Forbidden` when the caller cannot act in the context.
pub async fn list_did_webs(
    webs_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    context_id: &str,
) -> Result<Vec<WebsDidRecord>, AppError> {
    auth.require_context(context_id)?;
    webs_store::list_by_context(webs_ks, context_id).await
}

/// Refuse to make a `did:webs` the primary DID of `ctx` when that context's
/// primary is this VTA's own identity. Replacing a node's identity is a
/// re-identification — new keys installed, peers told — which setup does; a
/// create that only repointed the context would leave the VTA signing as the
/// old DID.
///
/// The one service identity a VTA can tell from its own records is its own
/// DID, `vta_did`. A context provisioned for a community, a VTN or a host
/// service carries no marker saying so, so it is not refused here: that is a
/// gap, recorded in `docs/02-vta/did-webs.md`.
pub(super) fn refuse_service_context(
    config: &AppConfig,
    ctx: &vta_sdk::contexts::ContextRecord,
) -> Result<(), WebsError> {
    let Some(primary) = ctx.did.as_deref() else {
        return Ok(());
    };
    if config.vta_did.as_deref() == Some(primary) {
        return Err(WebsError::refused(
            WebsRefusal::NodeIdentityContext,
            format!(
                "context {} holds this VTA's own DID ({primary}): a create cannot replace a \
                 node's identity. To make this VTA a did:webs, set it up as one (`vta setup`, \
                 `vta_did` kind `create_webs`)",
                ctx.id
            ),
        ));
    }
    Ok(())
}

mod error;
pub use error::{WebsError, WebsRefusal};

mod own_identity;
pub use own_identity::{
    DEFAULT_OWN_IDENTITY_SERVER_ID, OWN_IDENTITY_CONTEXT, OwnWebsIdentity, create_own_identity,
    own_identity_in_progress,
};

mod template;
use template::{ambient_vars, check_primary_class, plan_template, render_and_map, rendered_keys};

mod lifecycle;
pub use lifecycle::{
    DeleteDidWebsResult, RotateDidWebsResult, RotateRoleKeysResult, UpdateDidWebsParams,
    UpdateDidWebsResult, WebsServices, delete_did_webs, rotate_did_webs_keys,
    rotate_did_webs_role_keys, staged_webs_rotations, update_did_webs, version_id,
};

#[cfg(test)]
mod tests;
