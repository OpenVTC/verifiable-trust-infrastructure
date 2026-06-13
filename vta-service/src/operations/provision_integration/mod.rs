//! `provision-integration` — shared library function driven by both the
//! VTA CLI (`vta bootstrap provision-integration`) and the HTTP endpoint
//! (`POST /bootstrap/provision-integration`).
//!
//! See `docs/02-vta/provision-integration.md` for the full design.
//!
//! Flow, at the broadest level:
//! 1. Precondition checks — caller is admin of the target context;
//!    context exists; template registered.
//! 2. Orchestrate key minting + template rendering via
//!    `super::did_webvh::create_did_webvh` — it already handles the
//!    mint-keys, render-template, build-log, publish-if-not-serverless
//!    flow end-to-end.
//! 3. Read back the minted private key material via
//!    `super::keys::get_key_secret` for inclusion in the sealed bundle.
//! 4. Register the holder (`client_did`) as admin of the target context
//!    via `super::acl::create_acl`.
//! 5. Build + sign a `VtaAuthorizationCredential` (the VC type tag the
//!    VTA issues; see [`vta_sdk::provision_integration::credential`])
//!    using the VTA's `{vta_did}#key-0` signing key (see
//!    `vta_keys::load_vta_vc_issuance_secret`).
//! 6. Assemble the [`TemplateBootstrapPayload`](vta_sdk::provision_integration::TemplateBootstrapPayload)
//!    and seal it to the holder's X25519 (derived from `client_did`)
//!    via `sealed_transfer::seal_payload`. Producer assertion is
//!    `DidSigned` by `{vta_did}#sealed-transfer-0` (a purpose-specific
//!    key, distinct from `#key-0`) unless the caller overrides to
//!    `PinnedOnly` via [`AssertionMode`](crate::operations::provision_integration::AssertionMode)
//!    (dev-only escape hatch).
//! 7. Armor and return, plus a summary for the CLI/HTTP response.
//!
//! Everything persistent (admin ACL row, minted key records, webvh log
//! entry) lands atomically as part of the `create_did_webvh` +
//! `create_acl` calls — the sealed bundle is derived from that state
//! rather than being a separate source of truth.
//!
//! Internal layout:
//! - `mod.rs` (this file) — public types, main orchestrator, tests
//! - `mint` — admin/integration key minting via DID templates
//! - `preconditions` — authz + context/template registration checks
//! - `templates` — context → global → builtin resolution helpers
//! - `vta_keys` — loading the VTA's own keys + building the DidSigned
//!   producer assertion
//! - `webvh` — `WEBVH_SERVER` / `WEBVH_PATH` template-var helpers

mod mint;
mod preconditions;
mod seal;
mod templates;
mod vta_keys;
mod webvh;

pub use preconditions::{
    AmbiguousContext, ResolveContextError, ensure_target_context_or_create, infer_target_context,
    resolve_target_context,
};

use std::collections::BTreeMap;
use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use chrono::Duration;
use serde_json::Value;
use tokio::sync::RwLock;
use tracing::info;

use crate::acl::{Role, delete_acl_entry, get_acl_entry};
use crate::audit::{self, audit};
use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::keys::seed_store::SeedStore;
use crate::server::AppState;
use crate::store::KeyspaceHandle;
use vta_sdk::provision_integration::{
    AdminOfClaim, OperatorOfClaim, VerifiedBootstrapRequest, VtaAuthorizationClaim,
    credential::{VtaAuthorizationParams, issue_vta_authorization_credential},
};
use vta_sdk::sealed_transfer::{
    SealedPayloadV1,
    template_bootstrap::{
        DidKeyMaterial, KeyPair, TemplateBootstrapConfig, TemplateBootstrapPayload, TemplateOutput,
    },
};

/// How the producer assertion on the returned sealed bundle should be
/// constructed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AssertionMode {
    /// Sign the producer assertion with the VTA's purpose-specific
    /// `{vta_did}#sealed-transfer-0` key. Default for production.
    /// See `vta_keys::load_vta_sealed_transfer_secret` (private to the
    /// `provision_integration` module).
    #[default]
    DidSigned,
    /// No in-band signature — consumer relies purely on the out-of-band
    /// digest to anchor trust. Dev/test escape hatch, not for
    /// production flows.
    PinnedOnly,
}

/// Cloned subset of every keystore + handle [`provision_integration`]
/// needs. Both the REST [`AppState`] and the DIDComm
/// [`crate::messaging::router::VtaState`] expose the underlying handles
/// (all `Clone` and Arc-backed); this struct lets the library function
/// be called from either transport without taking on a
/// transport-specific `*State` dependency. Construction is cheap — every
/// field is `Clone` and Arc-shared, so cloning is two pointer bumps per
/// keyspace.
#[derive(Clone)]
pub struct ProvisionIntegrationDeps {
    pub keys_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub audit_ks: KeyspaceHandle,
    pub contexts_ks: KeyspaceHandle,
    pub did_templates_ks: KeyspaceHandle,
    pub imported_ks: KeyspaceHandle,
    pub webvh_ks: KeyspaceHandle,
    /// Sealed-bundle nonce store, for replay protection.
    pub sealed_nonces_ks: KeyspaceHandle,
    pub seed_store: Arc<dyn SeedStore>,
    pub config: Arc<RwLock<AppConfig>>,
    pub did_resolver: Option<DIDCacheClient>,
    pub didcomm_bridge: Arc<DIDCommBridge>,
}

impl From<&AppState> for ProvisionIntegrationDeps {
    fn from(state: &AppState) -> Self {
        Self {
            keys_ks: state.keys_ks.clone(),
            acl_ks: state.acl_ks.clone(),
            audit_ks: state.audit_ks.clone(),
            contexts_ks: state.contexts_ks.clone(),
            did_templates_ks: state.did_templates_ks.clone(),
            imported_ks: state.imported_ks.clone(),
            webvh_ks: state.webvh_ks.clone(),
            sealed_nonces_ks: state.sealed_nonces_ks.clone(),
            seed_store: state.seed_store.clone(),
            config: state.config.clone(),
            did_resolver: state.did_resolver.clone(),
            didcomm_bridge: state.didcomm_bridge.clone(),
        }
    }
}

/// Caller-supplied inputs to [`provision_integration`].
pub struct ProvisionIntegrationParams {
    pub request: VerifiedBootstrapRequest,
    /// The context the integration will live in. May be explicit (from
    /// an operator `--context` flag) or match the `contextHint` on the
    /// request. If both are present and disagree, the caller should
    /// reject before calling us — we don't silently normalize.
    pub context: String,
    /// See [`AssertionMode`].
    pub assertion_mode: AssertionMode,
    /// Override for the VC's `validUntil` window. Defaults to 1 hour
    /// per [`vta_sdk::provision_integration::credential::DEFAULT_VALIDITY`].
    pub vc_validity: Option<Duration>,
}

/// Output of [`provision_integration`] — the armored bundle plus the
/// out-of-band digest the operator communicates to the integration's
/// operator, plus a small summary for CLI display / HTTP response.
pub struct ProvisionIntegrationOutput {
    pub armored: String,
    pub digest: String,
    pub summary: ProvisionSummary,
}

#[derive(Debug)]
pub struct ProvisionSummary {
    /// Ephemeral DID that signed the VP and opens the sealed bundle.
    pub client_did: String,
    /// Long-term admin DID — `client_did` when no rollover, or the
    /// VTA-minted DID when the request carried an `adminTemplate`
    /// (or used the `AdminRotation` ask).
    pub admin_did: String,
    /// True when the VTA minted a fresh long-term admin DID for this
    /// provisioning (i.e. `adminTemplate` was present in the VP, or
    /// the request used the `AdminRotation` ask).
    pub admin_rolled_over: bool,
    /// Integration DID rendered from the integration template. `None`
    /// for the `AdminRotation` ask — that flow only mints an admin
    /// DID and does not produce an integration DID.
    pub integration_did: Option<String>,
    /// Name of the integration template that was rendered. `None`
    /// for the `AdminRotation` ask.
    pub template_name: Option<String>,
    /// `kind` field of the integration template. `None` for the
    /// `AdminRotation` ask.
    pub template_kind: Option<String>,
    /// Name of the admin template, when one was used (i.e. the
    /// request used `adminTemplate` rollover *or* the `AdminRotation`
    /// ask).
    pub admin_template_name: Option<String>,
    pub bundle_id_hex: String,
    /// Number of minted secrets in the payload. For
    /// `TemplateBootstrap`: 1 (integration only) or 2 (integration +
    /// rolled admin). For `AdminRotation`: always 1 (admin only).
    pub secret_count: usize,
    /// Number of template-emitted side outputs. Always 0 for
    /// `AdminRotation`; for `TemplateBootstrap` the count of webvh
    /// logs / DIDComm services / generic outputs.
    pub output_count: usize,
    /// Resolved id of the registered webvh hosting server the VTA
    /// published the integration's `did.jsonl` to. `None` when the
    /// integration is self-hosted (no `WEBVH_SERVER` template var, or
    /// it was explicitly null), or when the request was
    /// `AdminRotation` (no integration mint at all).
    pub webvh_server_id: Option<String>,
}

/// Main entry point. See module docs for the flow.
pub async fn provision_integration(
    state: &ProvisionIntegrationDeps,
    auth: &AuthClaims,
    params: ProvisionIntegrationParams,
) -> Result<ProvisionIntegrationOutput, AppError> {
    let ProvisionIntegrationParams {
        request,
        context,
        assertion_mode,
        vc_validity,
    } = params;

    let client_did = request.holder().to_string();
    let bundle_id = request
        .decode_nonce()
        .map_err(|e| AppError::Validation(format!("bootstrap request nonce decode: {e}")))?;
    let client_x25519_pub = request
        .decode_client_x25519_pub()
        .map_err(|e| AppError::Validation(format!("bootstrap request X25519 derivation: {e}")))?;

    // ── 1. Preconditions ────────────────────────────────────────────
    preconditions::preconditions(state, auth, &context, &request).await?;

    // ── 2. Dispatch on the bootstrap intent ─────────────────────────
    //
    // `AdminRotation` is the lighter sibling of `TemplateBootstrap` —
    // mints only the admin DID, no integration template render, and
    // returns a `SealedPayloadV1::AdminRotation` envelope. Its flow
    // shares preconditions + key-minting helpers but skips the
    // integration mint entirely, so we branch here rather than
    // littering the integration path with `if integration_template`
    // checks.
    if matches!(
        request.ask(),
        vta_sdk::provision_integration::BootstrapAsk::AdminRotation(_)
    ) {
        return provision_admin_rotation(
            state,
            auth,
            &request,
            &context,
            assertion_mode,
            vc_validity,
            bundle_id,
            &client_did,
            &client_x25519_pub,
        )
        .await;
    }

    // ── 3. Extract templates + vars from the ask ────────────────────
    let (template_name, mut template_vars) = preconditions::extract_template(request.ask())?
        .expect("TemplateBootstrap ask must yield an integration template");
    let admin_template_ref = preconditions::extract_admin_template(request.ask());

    // ── 3. Mint + render + publish via create_did_webvh ─────────────
    //
    // Templates ship with a `URL` required var that becomes the
    // integration's own service endpoint inside the rendered DID
    // document (mediator's DIDComm endpoint, webvh hosting URL, etc.).
    // It is *content* of the DID document, separate from where the
    // `did.jsonl` log itself gets published.
    //
    // Publication target is selected by the optional `WEBVH_SERVER`
    // template var:
    //
    //   WEBVH_SERVER absent or null → serverless mode (VTA does not
    //     publish; the integration self-hosts at the URL above).
    //   WEBVH_SERVER set to a registered server id → VTA publishes
    //     `did.jsonl` to that server via its WebVHHosting endpoint.
    //
    // The id is validated against the registered-server catalogue
    // before any state mutation so a typo or stale id fails fast,
    // before key minting writes anything.
    //
    // `URL` is optional at this layer — templates that need it declare
    // it in `requiredVars` and the renderer enforces presence. Keeping
    // it mandatory here would block templates (e.g. non-webvh
    // integrations, tests, internal tooling) that legitimately don't
    // ship a URL as document content.
    let integration_url = template_vars
        .get("URL")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let webvh_server_id = webvh::resolve_webvh_server(&template_vars, &state.webvh_ks).await?;

    // Optional `WEBVH_PATH` template var: the *only* input to the DID's
    // path. The service `URL` never influences the DID name — that
    // derivation leaked the REST route (`…/mediator/v1`) into the
    // identifier and, being deterministic, collided on every re-run.
    // Removed from the map so the template renderer doesn't also see it —
    // it is transport metadata, not document content.
    //
    // The value maps onto the total `WebvhPathMode` below: absent / empty
    // → `AutoAssign` (the hosting server mints a random path),
    // `.well-known` → `WellKnown` (root), any other label → `Explicit`.
    // The mapping is mode-independent: serverless mode never reads
    // `WEBVH_PATH` at all (the DID location comes straight from `URL`), so
    // this only governs server-managed publication.
    let webvh_path = webvh::take_webvh_path(&mut template_vars)?;

    // Optional `WEBVH_DOMAIN` template var: when the webvh hosting server
    // is multi-tenant, this pins which tenant domain the DID is allocated
    // under. Absent → the remote runs its own resolution chain (caller's
    // ACL default → system default). Removed from the map for the same
    // reason as `WEBVH_PATH` — transport metadata, not document content.
    let webvh_domain = webvh::take_webvh_domain(&mut template_vars)?;

    // Decide whether the minted DID should become the context's primary
    // DID. First-integration wins: when the context has no DID yet, bind
    // the newly-minted one so downstream operations (fetch_did_secrets_bundle,
    // build_did_secrets_bundle) resolve without a separate update step.
    // When the context already has a primary (e.g. provisioning a second
    // mediator into the same context), leave it alone — we don't want a
    // later integration silently displacing the first.
    let ctx_before_mint = crate::contexts::get_context(&state.contexts_ks, &context)
        .await?
        .ok_or_else(|| {
            AppError::Internal(format!(
                "context '{context}' disappeared between precondition check and DID mint"
            ))
        })?;
    let set_primary = ctx_before_mint.did.is_none();

    // Peek at the template's `methods` field. Templates declaring only
    // `["key"]` want a did:key integration (ephemeral / headless /
    // signing-only — no hosted did.jsonl log); everything else stays
    // on the webvh path. An empty `methods` list keeps the did:webvh
    // default — `methods` is advisory, and most templates omit it.
    let integration_template = templates::resolve_template_by_name(state, &context, &template_name)
        .await
        .map_err(|e| match e {
            AppError::NotFound(_) => AppError::Validation(format!(
                "integration template '{template_name}' is not registered on this VTA. \
                 Register it via 'pnm did-templates create {template_name} --file <path>' \
                 then retry."
            )),
            other => other,
        })?;
    let use_did_key = templates::template_targets_did_key_only(&integration_template);

    // When the did:key path runs, we already hold the full
    // `DidKeyMaterial` (signing + KA public/private) from the mint
    // helper — there's no keystore round-trip for the KA key because
    // X25519 is derived from the Ed25519 seed, not BIP-32 derived at
    // its own path. Capture it here so the readback section below can
    // skip `get_key_secret` on this branch.
    let mut did_key_material: Option<DidKeyMaterial> = None;

    let (integration_did, signing_key_id, ka_key_id, did_document, did_log) = if use_did_key {
        // did:key path — no webvh publication. `WEBVH_SERVER` /
        // `WEBVH_PATH` / `URL` are all irrelevant here; the template's
        // `methods: ["key"]` is load-bearing metadata, not the URL.
        let (did, skid, kkid, doc, log, material) = mint::mint_integration_via_did_key_template(
            state,
            &context,
            &client_did,
            &template_name,
            &template_vars,
        )
        .await?;
        did_key_material = Some(material);
        (did, skid, kkid, doc, log)
    } else {
        // did:webvh path — `create_did_webvh` takes exactly one of
        // `server_id` / `url`.
        // - WEBVH_SERVER set → `server_id` wins; `url` is unused by that
        //   path, so we drop it even if supplied.
        // - WEBVH_SERVER unset → serverless mode; we need a `url`. This is
        //   the only path where an absent URL is a hard error; surface it
        //   with guidance naming the `WEBVH_SERVER` alternative.

        // Resolve the path request into the explicit, total path mode, and
        // reject an explicit root request on a shared server before any
        // state is written (see `reject_root_on_shared_server`).
        let path_mode = vta_sdk::protocols::did_management::create::WebvhPathMode::from(webvh_path);
        webvh::reject_root_on_shared_server(&path_mode, webvh_server_id.is_some())?;

        let (params_server_id, params_url) = match &webvh_server_id {
            Some(id) => (Some(id.clone()), None),
            None => {
                let url = integration_url.clone().ok_or_else(|| {
                    AppError::Validation(format!(
                        "webvh DIDs need a publication target. Template '{template_name}' \
                         resolved without a 'URL' or 'WEBVH_SERVER' template var. Pass either \
                         `--var URL=https://...` (serverless mode — you publish did.jsonl \
                         yourself) or `--var WEBVH_SERVER=<id>` (route through a webvh \
                         hosting server registered with `vta webvh add-server`). At least one \
                         is required for any webvh-method built-in (did-hosting-control, \
                         did-hosting-daemon, did-hosting-server)."
                    ))
                })?;
                (None, Some(url))
            }
        };

        let template_vars_hashmap: std::collections::HashMap<String, Value> =
            template_vars.clone().into_iter().collect();

        let create_result = super::did_webvh::create_did_webvh(
            &state.keys_ks,
            &state.imported_ks,
            &state.contexts_ks,
            &state.webvh_ks,
            &state.did_templates_ks,
            &*state.seed_store,
            &*state.config.read().await,
            auth,
            super::did_webvh::CreateDidWebvhParams {
                context_id: context.clone(),
                server_id: params_server_id,
                url: params_url,
                // Absent `WEBVH_PATH` → `AutoAssign` (server mints a
                // random path); `.well-known` → `WellKnown` (root, already
                // rejected above on shared servers); a label → `Explicit`.
                path_mode,
                // Explicit tenant domain when the caller set
                // `WEBVH_DOMAIN` (multi-tenant hosting server); `None`
                // lets the remote resolve to its caller-default / system
                // default.
                domain: webvh_domain,
                label: Some(client_did.clone()),
                portable: true,
                add_mediator_service: false,
                additional_services: None,
                pre_rotation_count: 0,
                did_document: None,
                did_log: None,
                set_primary,
                signing_key_id: None,
                ka_key_id: None,
                template: Some(template_name.clone()),
                template_context: None,
                template_vars: template_vars_hashmap,
                // provision-integration always creates an integration DID,
                // never the VTA's own identity.
                is_vta_identity: false,
            },
            state
                .did_resolver
                .as_ref()
                .ok_or_else(|| AppError::Internal("DID resolver not initialized".into()))?,
            &state.didcomm_bridge,
            "provision-integration",
        )
        .await?;

        let did_document = create_result.did_document.clone().ok_or_else(|| {
            AppError::Internal("create_did_webvh did not return did_document".into())
        })?;
        (
            create_result.did.clone(),
            create_result.signing_key_id.clone(),
            create_result.ka_key_id.clone(),
            did_document,
            create_result.log_entry.clone(),
        )
    };

    // did:key path: set the minted DID as primary when the context has
    // none. The webvh path already handles this inside create_did_webvh
    // via `set_primary`.
    if use_did_key && set_primary {
        let mut ctx = ctx_before_mint.clone();
        ctx.did = Some(integration_did.clone());
        ctx.updated_at = chrono::Utc::now();
        crate::contexts::store_context(&state.contexts_ks, &ctx)
            .await
            .map_err(|e| {
                AppError::Internal(format!("set integration did:key as context primary: {e}"))
            })?;
    }

    // ── 4. Read back minted secrets ─────────────────────────────────
    //
    // The did:key branch above already captured the full `DidKeyMaterial`
    // at mint time (X25519 KA isn't BIP-32 derived at its own path, so
    // `get_key_secret` can't recompute it). Skip the readback in that
    // case; the webvh branch still goes through `get_key_secret` so it
    // exercises the same authz surface as any admin-triggered read.
    let mut secrets = BTreeMap::new();
    if let Some(material) = did_key_material {
        secrets.insert(material.did.clone(), material);
    } else {
        let signing_secret_resp = super::keys::get_key_secret(
            &state.keys_ks,
            &state.imported_ks,
            &state.seed_store,
            &state.audit_ks,
            auth,
            &signing_key_id,
            "provision-integration",
        )
        .await?;
        let ka_secret_resp = super::keys::get_key_secret(
            &state.keys_ks,
            &state.imported_ks,
            &state.seed_store,
            &state.audit_ks,
            auth,
            &ka_key_id,
            "provision-integration",
        )
        .await?;

        // The bundle's `key_id` strings must equal the `verificationMethod.id`
        // entries in the *published* DID document. Built-in templates
        // are aligned with the VTA's internal storage convention
        // (`{did}#key-0` / `#key-1`), but operator-uploaded templates
        // may declare arbitrary fragments. Look up the kid by matching
        // publicKeyMultibase so each template gets bundle entries that
        // match its own VM ids — a consumer storing the bundle verbatim
        // can then resolve an inbound JWE's kid against the live document
        // and find the matching private key.
        let signing_kid =
            published_kid_for(&did_document, &signing_secret_resp.public_key_multibase)
                .ok_or_else(|| {
                    AppError::Internal(format!(
                        "rendered DID document for '{integration_did}' has no \
                 verificationMethod matching the minted signing publicKeyMultibase \
                 — template '{template_name}' likely references a different \
                 SIGNING_KEY_MB binding"
                    ))
                })?;
        let ka_kid = published_kid_for(&did_document, &ka_secret_resp.public_key_multibase)
            .ok_or_else(|| {
                AppError::Internal(format!(
                    "rendered DID document for '{integration_did}' has no \
                     verificationMethod matching the minted key-agreement \
                     publicKeyMultibase — template '{template_name}' likely \
                     references a different KA_KEY_MB binding"
                ))
            })?;

        secrets.insert(
            integration_did.clone(),
            DidKeyMaterial {
                did: integration_did.clone(),
                signing_key: KeyPair {
                    key_id: signing_kid,
                    public_key_multibase: signing_secret_resp.public_key_multibase.clone(),
                    private_key_multibase: signing_secret_resp.private_key_multibase.clone(),
                },
                ka_key: KeyPair {
                    key_id: ka_kid,
                    public_key_multibase: ka_secret_resp.public_key_multibase.clone(),
                    private_key_multibase: ka_secret_resp.private_key_multibase.clone(),
                },
            },
        );
    }

    // ── 4.5. Optional admin-DID rollover ───────────────────────────
    //
    // When the request carries an `adminTemplate`, the VTA mints a
    // long-term admin DID under its own key custody and binds the VC
    // subject + ACL row to that DID instead of `client_did`. The
    // ephemeral `client_did` then has no authority at the VTA — it
    // only opened the bundle. See `docs/02-vta/provision-integration.md`
    // §"Admin-DID rollover" and CLAUDE.md "Use DID templates" /
    // "Authorization claims … VC/VP".
    let admin_did = if let Some(ref admin_ref) = admin_template_ref {
        let minted = mint::mint_admin_via_template(state, &context, admin_ref).await?;
        secrets.insert(minted.material.did.clone(), minted.material.clone());
        minted.material.did
    } else {
        client_did.clone()
    };

    // ── 5. Register the (possibly rolled-over) admin as admin ──────
    //
    // ACL principal is `admin_did`: equals `client_did` when no
    // rollover, equals the freshly-minted VTA-derived DID when
    // rollover. The ephemeral `client_did` is never written to the
    // ACL when rollover is in effect — its only role is opening the
    // bundle.
    match super::acl::create_acl(
        &state.acl_ks,
        &state.audit_ks,
        &state.contexts_ks,
        auth,
        &admin_did,
        Role::Admin,
        request.label().map(str::to_string),
        vec![context.clone()],
        None,
        None,
        None,
        "provision-integration",
    )
    .await
    {
        Ok(_) => {}
        // Re-running provision-integration against the same admin_did
        // while the ACL row already exists is either a retry or an
        // operator-driven refresh. Either way the intent is harmless
        // — carry on without bumping the row, surface the conflict in
        // the returned summary if callers need to log.
        Err(AppError::Conflict(_)) => {
            info!(
                admin_did = %admin_did,
                context = %context,
                "ACL row already exists — reusing for provision-integration"
            );
        }
        Err(e) => return Err(e),
    }

    // ── 5.5. Retire the ephemeral after admin rollover ──────────────
    //
    // When the request asked for an admin-DID rollover, the ephemeral
    // `client_did` only existed to open the bundle. Its ACL row
    // (granted by the operator before this call) is now stale —
    // delete it and emit an `acl.swap` audit so the ephemeral →
    // long-term hand-off is recorded the same shape as
    // `operations::acl::swap_acl`. No-op when `admin_did == client_did`
    // (no rollover requested) or when client_did has no ACL row
    // (relayer ≠ holder flow — the ephemeral was never granted on
    // this VTA).
    retire_ephemeral_after_rollover(state, &client_did, &admin_did, &context).await?;

    // ── 6. Build + sign the VTA authorization VC ────────────────────
    let config = state.config.read().await;
    let vta_did = config
        .vta_did
        .as_ref()
        .ok_or_else(|| AppError::Internal("VTA DID not configured".into()))?
        .clone();
    drop(config);

    let template_kind =
        templates::resolve_template_kind(&state.did_templates_ks, &template_name, &context)
            .await
            .unwrap_or_else(|_| "integration".to_string());

    let claim = VtaAuthorizationClaim {
        // Subject is the long-term admin DID — `client_did` when no
        // rollover, the VTA-minted DID when an `adminTemplate` was
        // requested. Holders verify this VC offline at bundle open
        // and install the matching keys from the `secrets` map.
        id: admin_did.clone(),
        admin_of: AdminOfClaim {
            vta: vta_did.clone(),
            context: context.clone(),
            role: "admin".into(),
        },
        operator_of: Some(OperatorOfClaim {
            did: integration_did.clone(),
            template: template_name.clone(),
        }),
    };
    let mut vc_params = VtaAuthorizationParams::new(claim);
    if let Some(validity) = vc_validity {
        vc_params = vc_params.with_validity(validity);
    }

    // Split key-use: `#key-0` issues the VC's Data-Integrity proof;
    // `#sealed-transfer-0` signs the sealed-transfer producer assertion
    // below. Keeping them disjoint means a leak of one doesn't void the
    // other and each can rotate independently.
    let vc_issuer_secret = vta_keys::load_vta_vc_issuance_secret(state, &vta_did).await?;
    let vc = issue_vta_authorization_credential(&vc_issuer_secret, vc_params)
        .await
        .map_err(|e| AppError::Internal(format!("issue VTA authorization VC: {e}")))?;
    let vc_value =
        serde_json::to_value(&vc).map_err(|e| AppError::Internal(format!("serialize VC: {e}")))?;

    // ── 7. Build VtaTrustBundle — VTA DID doc + log ──────────────────
    let vta_trust = vta_keys::load_vta_trust_bundle(state, &vta_did).await?;

    // Template side outputs: today we always ship the webvh log for the
    // integration DID if create_did_webvh produced one. Future template
    // kinds (e.g., `webvh-hosting`) may emit additional outputs.
    let mut outputs = Vec::new();
    if let Some(log) = did_log {
        outputs.push(TemplateOutput::WebvhLog {
            did: integration_did.clone(),
            log,
        });
    }

    // Snapshot counts before the payload is moved into the seal. The
    // summary at the bottom of this fn (`secret_count`, `output_count`)
    // must reflect what is actually in the bundle — hard-coding "1 or 2"
    // based on `admin_rolled_over` silently lies when a future template
    // mints pre-rotation keys or emits multiple side outputs.
    let secret_count = secrets.len();
    let output_count = outputs.len();

    let payload = TemplateBootstrapPayload {
        authorization: vc_value,
        secrets,
        config: TemplateBootstrapConfig {
            template_name: template_name.clone(),
            template_kind: template_kind.clone(),
            did_document,
            outputs,
            vta_url: state.config.read().await.public_url.clone(),
            vta_trust,
        },
    };

    // ── 8. Seal ─────────────────────────────────────────────────────
    let seal::SealedProvisionBundle { armored, digest } = seal::seal_provision_payload(
        state,
        &vta_did,
        assertion_mode,
        bundle_id,
        &client_x25519_pub,
        SealedPayloadV1::TemplateBootstrap(Box::new(payload)),
    )
    .await?;
    let bundle_id_hex = hex_lower(&bundle_id);

    let admin_rolled_over = admin_template_ref.is_some();
    let admin_template_name = admin_template_ref.as_ref().map(|r| r.name.clone());

    info!(
        client_did = %client_did,
        admin_did = %admin_did,
        admin_rolled_over,
        integration_did = %integration_did,
        context = %context,
        template = %template_name,
        admin_template = ?admin_template_name,
        bundle_id = %bundle_id_hex,
        "provision-integration bundle sealed"
    );

    Ok(ProvisionIntegrationOutput {
        armored,
        digest,
        summary: ProvisionSummary {
            client_did,
            admin_did,
            admin_rolled_over,
            integration_did: Some(integration_did),
            template_name: Some(template_name),
            template_kind: Some(template_kind),
            admin_template_name,
            bundle_id_hex,
            secret_count,
            output_count,
            webvh_server_id,
        },
    })
}

use vta_sdk::hex::lower as hex_lower;

/// Retire the ephemeral `client_did`'s ACL row after the VTA has rolled
/// the long-term admin over to a freshly-minted `admin_did`. Emits an
/// `acl.swap` audit entry — same action tag + shape as
/// [`super::acl::swap_acl`] — so audit consumers see a single uniform
/// "ephemeral → long-term hand-off" trail regardless of which path
/// performed the swap.
///
/// No-ops when:
/// - `admin_did == client_did`: no rollover happened, the ephemeral IS
///   the long-term DID, nothing to retire.
/// - `client_did` has no ACL row: relayer ≠ holder flow, the ephemeral
///   was never granted on this VTA, there's nothing to delete and
///   "swap" wouldn't be an accurate label.
///
/// Closes the audit gap surfaced in the May 2026 review: previously the
/// ephemeral row lingered until `acl_sweeper` cleaned it up at TTL
/// expiry, with no record of why it had been superseded.
async fn retire_ephemeral_after_rollover(
    state: &ProvisionIntegrationDeps,
    client_did: &str,
    admin_did: &str,
    context: &str,
) -> Result<(), AppError> {
    if admin_did == client_did {
        return Ok(());
    }
    if get_acl_entry(&state.acl_ks, client_did).await?.is_none() {
        return Ok(());
    }
    delete_acl_entry(&state.acl_ks, client_did).await?;
    info!(
        from = %client_did,
        to = %admin_did,
        context = %context,
        "provision-integration retired ephemeral ACL row after admin rollover"
    );
    audit!(
        "acl.swap",
        actor = client_did,
        resource = admin_did,
        outcome = "success"
    );
    let _ = audit::record(
        &state.audit_ks,
        "acl.swap",
        client_did,
        Some(admin_did),
        "success",
        Some("provision-integration"),
        Some(context),
    )
    .await;
    Ok(())
}

/// `BootstrapAsk::AdminRotation` flow — mints a fresh long-term admin
/// DID via the requested admin template, writes its ACL row, issues
/// the authorization VC (no `operator_of` claim — there's no
/// integration to operate), and seals the result as a
/// [`SealedPayloadV1::AdminRotation`] bundle.
///
/// Sibling to the integration-mint path inside [`provision_integration`].
/// Shares preconditions + key-mint + sealing helpers; differs in that
/// no integration template is rendered, no `did.jsonl` is published,
/// and no integration secrets land in the bundle.
#[allow(clippy::too_many_arguments)]
async fn provision_admin_rotation(
    state: &ProvisionIntegrationDeps,
    auth: &AuthClaims,
    request: &VerifiedBootstrapRequest,
    context: &str,
    assertion_mode: AssertionMode,
    vc_validity: Option<Duration>,
    bundle_id: [u8; 16],
    client_did: &str,
    client_x25519_pub: &[u8; 32],
) -> Result<ProvisionIntegrationOutput, AppError> {
    // Extract the admin template ref (mandatory in this variant).
    let admin_template_ref =
        preconditions::extract_admin_template(request.ask()).ok_or_else(|| {
            AppError::Internal(
                "AdminRotation ask reached provision_admin_rotation without an admin template — \
                 wiring bug; the wire shape requires it"
                    .into(),
            )
        })?;

    // ── 1. Mint admin DID under VTA custody ─────────────────────────
    let minted = mint::mint_admin_via_template(state, context, &admin_template_ref).await?;
    let admin_did = minted.material.did.clone();
    let admin_template_name = admin_template_ref.name.clone();

    // ── 2. Register admin in ACL ────────────────────────────────────
    //
    // Re-run safety: a second AdminRotation against the same admin_did
    // hits a Conflict — same handling as the TemplateBootstrap path.
    match super::acl::create_acl(
        &state.acl_ks,
        &state.audit_ks,
        &state.contexts_ks,
        auth,
        &admin_did,
        Role::Admin,
        request.label().map(str::to_string),
        vec![context.to_string()],
        None,
        None,
        None,
        "provision-integration",
    )
    .await
    {
        Ok(_) => {}
        Err(AppError::Conflict(_)) => {
            info!(
                admin_did = %admin_did,
                context = %context,
                "ACL row already exists — reusing for provision-integration (admin rotation)"
            );
        }
        Err(e) => return Err(e),
    }

    // ── 2.5. Retire the ephemeral after admin rollover ──────────────
    //
    // AdminRotation always mints a fresh admin DID, so the ephemeral
    // `client_did` is always being swapped out. Same shape as the
    // TemplateBootstrap path — see the comment there for rationale.
    retire_ephemeral_after_rollover(state, client_did, &admin_did, context).await?;

    // ── 3. VTA identity ─────────────────────────────────────────────
    let config = state.config.read().await;
    let vta_did = config
        .vta_did
        .as_ref()
        .ok_or_else(|| AppError::Internal("VTA DID not configured".into()))?
        .clone();
    drop(config);

    // ── 4. Build + sign the VTA authorization VC ────────────────────
    //
    // No `operator_of` — there is no integration DID to operate.
    let claim = VtaAuthorizationClaim {
        id: admin_did.clone(),
        admin_of: AdminOfClaim {
            vta: vta_did.clone(),
            context: context.to_string(),
            role: "admin".into(),
        },
        operator_of: None,
    };
    let mut vc_params = VtaAuthorizationParams::new(claim);
    if let Some(validity) = vc_validity {
        vc_params = vc_params.with_validity(validity);
    }

    let vc_issuer_secret = vta_keys::load_vta_vc_issuance_secret(state, &vta_did).await?;
    let vc = issue_vta_authorization_credential(&vc_issuer_secret, vc_params)
        .await
        .map_err(|e| AppError::Internal(format!("issue VTA authorization VC: {e}")))?;
    let vc_value =
        serde_json::to_value(&vc).map_err(|e| AppError::Internal(format!("serialize VC: {e}")))?;

    // ── 5. VTA trust bundle for offline VC verification at first boot
    let vta_trust = vta_keys::load_vta_trust_bundle(state, &vta_did).await?;
    let vta_url = state.config.read().await.public_url.clone();

    // ── 6. Build payload ───────────────────────────────────────────
    let payload = vta_sdk::sealed_transfer::AdminRotationPayload {
        authorization: vc_value,
        admin: minted.material.clone(),
        vta_url,
        vta_trust,
    };

    // ── 7. Seal ─────────────────────────────────────────────────────
    let seal::SealedProvisionBundle { armored, digest } = seal::seal_provision_payload(
        state,
        &vta_did,
        assertion_mode,
        bundle_id,
        client_x25519_pub,
        SealedPayloadV1::AdminRotation(Box::new(payload)),
    )
    .await?;
    let bundle_id_hex = hex_lower(&bundle_id);

    info!(
        client_did = %client_did,
        admin_did = %admin_did,
        context = %context,
        admin_template = %admin_template_name,
        bundle_id = %bundle_id_hex,
        "provision-integration AdminRotation bundle sealed"
    );

    Ok(ProvisionIntegrationOutput {
        armored,
        digest,
        summary: ProvisionSummary {
            client_did: client_did.to_string(),
            admin_did,
            admin_rolled_over: true,
            integration_did: None,
            template_name: None,
            template_kind: None,
            admin_template_name: Some(admin_template_name),
            bundle_id_hex,
            secret_count: 1,
            output_count: 0,
            webvh_server_id: None,
        },
    })
}

/// Find a `verificationMethod.id` whose `publicKeyMultibase` matches
/// `target_mb`. Used to align bundle `key_id` fields with the published
/// DID document so a consumer storing the bundle verbatim can resolve
/// the kid against the live document and find a matching private key.
fn published_kid_for(doc: &Value, target_mb: &str) -> Option<String> {
    doc.get("verificationMethod")?
        .as_array()?
        .iter()
        .find(|vm| {
            vm.get("publicKeyMultibase")
                .and_then(Value::as_str)
                .is_some_and(|mb| mb == target_mb)
        })
        .and_then(|vm| vm.get("id").and_then(Value::as_str))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::preconditions::{extract_admin_template, extract_template, preconditions};
    use super::templates::resolve_template_kind;
    use super::webvh::{resolve_webvh_server, take_webvh_path};
    use super::*;
    use vta_sdk::provision_integration::{BootstrapAsk, DidTemplateRef, TemplateBootstrapAsk};

    fn sample_ask(template_name: &str, with_url: bool) -> BootstrapAsk {
        let mut vars = BTreeMap::new();
        if with_url {
            vars.insert(
                "URL".to_string(),
                Value::String("https://mediator.example.com".into()),
            );
        }
        BootstrapAsk::TemplateBootstrap(TemplateBootstrapAsk {
            context_hint: Some("prod-mediator".into()),
            template: DidTemplateRef {
                name: template_name.into(),
                vars,
            },
            admin_template: None,
            note: None,
        })
    }

    fn sample_ask_with_admin(template_name: &str, admin_template_name: &str) -> BootstrapAsk {
        let mut vars = BTreeMap::new();
        vars.insert(
            "URL".to_string(),
            Value::String("https://mediator.example.com".into()),
        );
        BootstrapAsk::TemplateBootstrap(TemplateBootstrapAsk {
            context_hint: Some("prod-mediator".into()),
            template: DidTemplateRef {
                name: template_name.into(),
                vars,
            },
            admin_template: Some(DidTemplateRef {
                name: admin_template_name.into(),
                vars: BTreeMap::new(),
            }),
            note: None,
        })
    }

    #[test]
    fn extract_template_pulls_name_and_vars() {
        let ask = sample_ask("didcomm-mediator", true);
        let (name, vars) = extract_template(&ask)
            .unwrap()
            .expect("TemplateBootstrap ask should yield Some");
        assert_eq!(name, "didcomm-mediator");
        assert_eq!(
            vars.get("URL").and_then(|v| v.as_str()),
            Some("https://mediator.example.com")
        );
    }

    #[test]
    fn extract_admin_template_returns_none_when_absent() {
        let ask = sample_ask("didcomm-mediator", true);
        assert!(extract_admin_template(&ask).is_none());
    }

    #[test]
    fn extract_admin_template_returns_some_when_present() {
        let ask = sample_ask_with_admin("didcomm-mediator", "vta-admin");
        let admin = extract_admin_template(&ask).expect("admin template");
        assert_eq!(admin.name, "vta-admin");
    }

    #[test]
    fn assertion_mode_default_is_did_signed() {
        assert_eq!(AssertionMode::default(), AssertionMode::DidSigned);
    }

    // ── resolve_webvh_server ────────────────────────────────────────

    use crate::config::StoreConfig;
    use crate::store::Store;
    use crate::test_support::{
        bootstrap_test_vta, open_test_store, signed_request, signed_request_with_vars,
        super_admin_claims, test_deps,
    };
    use chrono::Utc;
    use vta_sdk::webvh::WebvhServerRecord;

    /// Open a fresh tempdir-backed store and return its `webvh` keyspace
    /// plus the dir guard so the caller can drop both at end-of-test.
    async fn fresh_webvh_keyspace() -> (tempfile::TempDir, Store, crate::store::KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let ks = store
            .keyspace(crate::keyspaces::WEBVH)
            .expect("open webvh ks");
        (dir, store, ks)
    }

    fn sample_server_record(id: &str) -> WebvhServerRecord {
        WebvhServerRecord {
            id: id.into(),
            did: format!("did:webvh:{id}"),
            label: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn resolve_webvh_server_absent_returns_none() {
        let (_dir, _store, ks) = fresh_webvh_keyspace().await;
        let vars = BTreeMap::new();
        assert_eq!(resolve_webvh_server(&vars, &ks).await.unwrap(), None);
    }

    #[tokio::test]
    async fn resolve_webvh_server_null_returns_none() {
        let (_dir, _store, ks) = fresh_webvh_keyspace().await;
        let mut vars = BTreeMap::new();
        vars.insert("WEBVH_SERVER".into(), Value::Null);
        assert_eq!(resolve_webvh_server(&vars, &ks).await.unwrap(), None);
    }

    #[tokio::test]
    async fn resolve_webvh_server_empty_string_returns_none() {
        let (_dir, _store, ks) = fresh_webvh_keyspace().await;
        let mut vars = BTreeMap::new();
        vars.insert("WEBVH_SERVER".into(), Value::String("   ".into()));
        assert_eq!(resolve_webvh_server(&vars, &ks).await.unwrap(), None);
    }

    #[tokio::test]
    async fn resolve_webvh_server_unknown_id_is_not_found() {
        let (_dir, _store, ks) = fresh_webvh_keyspace().await;
        let mut vars = BTreeMap::new();
        vars.insert(
            "WEBVH_SERVER".into(),
            Value::String("never-registered".into()),
        );
        let err = resolve_webvh_server(&vars, &ks).await.unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got: {err:?}");
        let msg = err.to_string();
        assert!(msg.contains("never-registered"), "got: {msg}");
        assert!(msg.contains("vta webvh add-server"), "got: {msg}");
    }

    #[tokio::test]
    async fn resolve_webvh_server_registered_id_returns_some() {
        let (_dir, _store, ks) = fresh_webvh_keyspace().await;
        crate::webvh_store::store_server(&ks, &sample_server_record("hosted-edge-1"))
            .await
            .unwrap();

        let mut vars = BTreeMap::new();
        vars.insert("WEBVH_SERVER".into(), Value::String("hosted-edge-1".into()));
        assert_eq!(
            resolve_webvh_server(&vars, &ks).await.unwrap(),
            Some("hosted-edge-1".into())
        );
    }

    #[tokio::test]
    async fn resolve_webvh_server_trims_whitespace() {
        let (_dir, _store, ks) = fresh_webvh_keyspace().await;
        crate::webvh_store::store_server(&ks, &sample_server_record("hosted-edge-1"))
            .await
            .unwrap();

        let mut vars = BTreeMap::new();
        vars.insert(
            "WEBVH_SERVER".into(),
            Value::String("  hosted-edge-1  ".into()),
        );
        assert_eq!(
            resolve_webvh_server(&vars, &ks).await.unwrap(),
            Some("hosted-edge-1".into())
        );
    }

    #[tokio::test]
    async fn resolve_webvh_server_wrong_type_is_validation_error() {
        let (_dir, _store, ks) = fresh_webvh_keyspace().await;
        let mut vars = BTreeMap::new();
        vars.insert("WEBVH_SERVER".into(), Value::Bool(true));
        let err = resolve_webvh_server(&vars, &ks).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got: {err:?}");
        assert!(err.to_string().contains("bool"), "got: {err}");
    }

    // ── take_webvh_path ─────────────────────────────────────────────

    #[test]
    fn take_webvh_path_absent_returns_none() {
        let mut vars = BTreeMap::new();
        vars.insert("URL".into(), Value::String("https://a".into()));
        assert_eq!(take_webvh_path(&mut vars).unwrap(), None);
        assert!(vars.contains_key("URL"), "unrelated keys must survive");
    }

    #[test]
    fn take_webvh_path_null_returns_none_and_removes_key() {
        let mut vars = BTreeMap::new();
        vars.insert("WEBVH_PATH".into(), Value::Null);
        assert_eq!(take_webvh_path(&mut vars).unwrap(), None);
        assert!(
            !vars.contains_key("WEBVH_PATH"),
            "null WEBVH_PATH must still be removed so the renderer never sees it"
        );
    }

    #[test]
    fn take_webvh_path_string_returns_some_and_removes_key() {
        let mut vars = BTreeMap::new();
        vars.insert("URL".into(), Value::String("https://a".into()));
        vars.insert("WEBVH_PATH".into(), Value::String("team/mediator".into()));
        assert_eq!(
            take_webvh_path(&mut vars).unwrap(),
            Some("team/mediator".into())
        );
        assert!(
            !vars.contains_key("WEBVH_PATH"),
            "WEBVH_PATH must be removed so it can't reach the renderer"
        );
        assert!(vars.contains_key("URL"), "unrelated keys must survive");
    }

    #[test]
    fn take_webvh_path_trims_whitespace() {
        let mut vars = BTreeMap::new();
        vars.insert(
            "WEBVH_PATH".into(),
            Value::String("  team/mediator  ".into()),
        );
        assert_eq!(
            take_webvh_path(&mut vars).unwrap(),
            Some("team/mediator".into())
        );
    }

    #[test]
    fn take_webvh_path_empty_string_is_validation_error() {
        let mut vars = BTreeMap::new();
        vars.insert("WEBVH_PATH".into(), Value::String(String::new()));
        let err = take_webvh_path(&mut vars).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got: {err:?}");
        assert!(
            err.to_string().contains("WEBVH_PATH"),
            "error must name the offending var: {err}"
        );
    }

    #[test]
    fn take_webvh_path_whitespace_only_is_validation_error() {
        let mut vars = BTreeMap::new();
        vars.insert("WEBVH_PATH".into(), Value::String("   ".into()));
        let err = take_webvh_path(&mut vars).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got: {err:?}");
    }

    #[test]
    fn take_webvh_path_non_string_is_validation_error() {
        let mut vars = BTreeMap::new();
        vars.insert("WEBVH_PATH".into(), Value::Bool(true));
        let err = take_webvh_path(&mut vars).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got: {err:?}");

        let mut vars = BTreeMap::new();
        vars.insert("WEBVH_PATH".into(), Value::Number(42.into()));
        let err = take_webvh_path(&mut vars).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got: {err:?}");
    }

    // ── preconditions / resolve_template_kind ───────────────────────
    //
    // Cover the three-tier template resolve (context → global → built-in)
    // that both `preconditions` and `resolve_template_kind` share with
    // `resolve_admin_template` and `did_webvh::resolve_template_for_render`.
    // Built-ins like `didcomm-mediator` ship inside `vta_sdk::did_templates`
    // and must resolve without an operator ever running
    // `pnm did-templates create`.

    use vta_sdk::did_templates::{DidTemplate, DidTemplateRecord, Scope};

    // `TestStore`, `open_test_store`, `test_app_config`, `test_deps`,
    // `super_admin_claims`, `signed_request{,_with_vars}`, and
    // `bootstrap_test_vta` moved to `crate::test_support` so integration
    // tests under `tests/` can share them via the `test-support`
    // feature (review item 24).

    fn mediator_template_vars() -> BTreeMap<String, Value> {
        let mut vars = BTreeMap::new();
        vars.insert("URL".into(), Value::String("https://mediator.test".into()));
        vars.insert(
            "WS_URL".into(),
            Value::String("wss://mediator.test/ws".into()),
        );
        vars.insert("ROUTING_KEYS".into(), Value::Array(vec![]));
        vars
    }

    #[tokio::test]
    async fn preconditions_accepts_builtin_integration_template() {
        let ts = open_test_store().await;
        crate::contexts::create_context(&ts.contexts_ks, "prod-mediator", "Prod Mediator")
            .await
            .expect("create context");

        let deps = test_deps(&ts);
        let auth = super_admin_claims();
        let request = signed_request("didcomm-mediator", "prod-mediator").await;

        preconditions(&deps, &auth, "prod-mediator", &request)
            .await
            .expect("built-in didcomm-mediator should satisfy preconditions");
    }

    #[tokio::test]
    async fn preconditions_rejects_unknown_template() {
        let ts = open_test_store().await;
        crate::contexts::create_context(&ts.contexts_ks, "prod-mediator", "Prod Mediator")
            .await
            .expect("create context");

        let deps = test_deps(&ts);
        let auth = super_admin_claims();
        let request = signed_request("never-registered", "prod-mediator").await;

        let err = preconditions(&deps, &auth, "prod-mediator", &request)
            .await
            .expect_err("unknown template must be rejected");
        assert!(matches!(err, AppError::Validation(_)), "got: {err:?}");
        let msg = err.to_string();
        assert!(msg.contains("never-registered"), "got: {msg}");
        assert!(msg.contains("is not registered on this VTA"), "got: {msg}");
    }

    #[tokio::test]
    async fn resolve_template_kind_resolves_builtin_when_no_stored_record() {
        let ts = open_test_store().await;

        let kind = resolve_template_kind(&ts.did_templates_ks, "didcomm-mediator", "prod-mediator")
            .await
            .expect("built-in kind lookup should succeed");
        let expected = vta_sdk::did_templates::load_embedded("didcomm-mediator")
            .expect("built-in template available")
            .kind;
        assert_eq!(kind, expected);
    }

    #[tokio::test]
    async fn resolve_template_kind_prefers_stored_record_over_builtin() {
        // A context-scoped record must shadow the built-in, matching the
        // resolve order in `resolve_admin_template` and
        // `did_webvh::resolve_template_for_render`.
        let ts = open_test_store().await;
        let mut tpl: DidTemplate =
            vta_sdk::did_templates::load_embedded("didcomm-mediator").expect("built-in available");
        "shadowed-kind".clone_into(&mut tpl.kind);
        let record = DidTemplateRecord {
            template: tpl,
            scope: Scope::Context {
                context_id: "prod-mediator".into(),
            },
            created_at: 0,
            updated_at: 0,
            created_by: "test".into(),
        };
        crate::did_templates::store_context_template(
            &ts.did_templates_ks,
            "prod-mediator",
            &record,
        )
        .await
        .expect("store context template");

        let kind = resolve_template_kind(&ts.did_templates_ks, "didcomm-mediator", "prod-mediator")
            .await
            .expect("stored record resolves");
        assert_eq!(kind, "shadowed-kind");
    }

    // ── Full-flow E2E tests ─────────────────────────────────────────
    //
    // Exercise the whole `provision_integration()` orchestration, not
    // just individual helpers. These are the tests that would have
    // caught the 3f4d832 regression (set_primary=false leaving ctx.did
    // unset) and the recent count-bug fix (secret_count/output_count
    // hardcoded instead of computed from the payload).

    #[tokio::test]
    async fn provision_integration_binds_minted_did_when_context_has_none() {
        // This is the direct regression test for 3f4d832. Fresh context
        // with ctx.did = None → after provision_integration, ctx.did
        // must be populated with the newly-minted integration DID.
        let ts = open_test_store().await;
        let (_vta_did, deps) = bootstrap_test_vta(&ts).await;
        crate::contexts::create_context(&ts.contexts_ks, "prod-mediator", "Prod Mediator")
            .await
            .expect("create context");

        let ctx_before = crate::contexts::get_context(&ts.contexts_ks, "prod-mediator")
            .await
            .unwrap()
            .unwrap();
        assert!(
            ctx_before.did.is_none(),
            "precondition: fresh context has no DID"
        );

        let auth = super_admin_claims();
        let request = signed_request_with_vars(
            "didcomm-mediator",
            "prod-mediator",
            mediator_template_vars(),
        )
        .await;

        let output = provision_integration(
            &deps,
            &auth,
            ProvisionIntegrationParams {
                request,
                context: "prod-mediator".into(),
                assertion_mode: AssertionMode::PinnedOnly,
                vc_validity: None,
            },
        )
        .await
        .expect("provision_integration");

        let ctx_after = crate::contexts::get_context(&ts.contexts_ks, "prod-mediator")
            .await
            .unwrap()
            .unwrap();
        assert!(
            ctx_after.did.is_some(),
            "context DID must be populated after provisioning a fresh context"
        );
        assert_eq!(
            ctx_after.did.as_deref(),
            output.summary.integration_did.as_deref(),
            "bound DID must match the minted integration DID returned in the summary"
        );
    }

    #[tokio::test]
    async fn provision_integration_preserves_existing_context_did() {
        // The "first integration wins" invariant: a second provisioning
        // into a context that already has a primary DID must NOT
        // overwrite it. Without this guard a second mediator silently
        // displaces the first.
        let ts = open_test_store().await;
        let (_vta_did, deps) = bootstrap_test_vta(&ts).await;
        let mut ctx = crate::contexts::create_context(&ts.contexts_ks, "prod-mediator", "Prod")
            .await
            .expect("create context");
        let pre_existing_did = "did:webvh:pre-existing.example".to_string();
        ctx.did = Some(pre_existing_did.clone());
        crate::contexts::store_context(&ts.contexts_ks, &ctx)
            .await
            .expect("pre-populate context DID");

        let auth = super_admin_claims();
        let request = signed_request_with_vars(
            "didcomm-mediator",
            "prod-mediator",
            mediator_template_vars(),
        )
        .await;

        provision_integration(
            &deps,
            &auth,
            ProvisionIntegrationParams {
                request,
                context: "prod-mediator".into(),
                assertion_mode: AssertionMode::PinnedOnly,
                vc_validity: None,
            },
        )
        .await
        .expect("provision_integration");

        let ctx_after = crate::contexts::get_context(&ts.contexts_ks, "prod-mediator")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            ctx_after.did.as_deref(),
            Some(pre_existing_did.as_str()),
            "existing primary DID must not be displaced by a later integration"
        );
    }

    #[tokio::test]
    async fn provision_integration_summary_counts_match_payload() {
        // Regression test for the hardcoded `secret_count = if admin { 2 } else { 1 }`
        // and `count_outputs_in_payload` = 1 bugs. The summary must
        // report the actual counts derived from the sealed payload's
        // contents.
        let ts = open_test_store().await;
        let (_vta_did, deps) = bootstrap_test_vta(&ts).await;
        crate::contexts::create_context(&ts.contexts_ks, "prod-mediator", "Prod")
            .await
            .expect("create context");

        let auth = super_admin_claims();
        let request = signed_request_with_vars(
            "didcomm-mediator",
            "prod-mediator",
            mediator_template_vars(),
        )
        .await;

        let output = provision_integration(
            &deps,
            &auth,
            ProvisionIntegrationParams {
                request,
                context: "prod-mediator".into(),
                assertion_mode: AssertionMode::PinnedOnly,
                vc_validity: None,
            },
        )
        .await
        .expect("provision_integration");

        // Without admin_template rollover, exactly one DID's key material
        // is sealed in (integration DID: signing + KA keys).
        assert!(
            !output.summary.admin_rolled_over,
            "no admin rollover requested"
        );
        assert_eq!(
            output.summary.secret_count, 1,
            "exactly one minted integration DID should be in the payload's secrets map"
        );
        // Serverless webvh mint produces exactly one WebvhLog output.
        assert_eq!(
            output.summary.output_count, 1,
            "exactly one webvh log output"
        );
        // And the armored bundle + OOB digest are present.
        assert!(!output.armored.is_empty(), "armored bundle populated");
        assert_eq!(
            output.digest.len(),
            64,
            "SHA-256 digest is 32 bytes hex-encoded"
        );
    }

    #[tokio::test]
    async fn provision_integration_mints_did_key_when_template_methods_is_key() {
        // Item 11b: a template declaring `methods: ["key"]` selects the
        // did:key mint path — no webvh log, no WEBVH_SERVER / URL
        // required, and the returned integration DID is self-resolving.
        //
        // Uses a context-scoped custom template (no built-in
        // integration template with methods=["key"] exists today — the
        // built-in `vta-admin` is kind="admin", used for rollover only).
        let ts = open_test_store().await;
        let (_vta_did, deps) = bootstrap_test_vta(&ts).await;
        crate::contexts::create_context(&ts.contexts_ks, "signer-ctx", "Local signers")
            .await
            .expect("create context");

        // Register a minimal did:key integration template scoped to
        // this context. Only `methods: ["key"]` is load-bearing for the
        // branch; the document shape is the canonical did:key minimal
        // VM (one signing key).
        let tpl_json = serde_json::json!({
            "schemaVersion": 1,
            "name": "local-signer",
            "kind": "signer",
            "description": "Test: did:key integration template",
            "methods": ["key"],
            "requiredVars": [],
            "optionalVars": {},
            "defaults": {},
            "document": {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/multikey/v1"
                ],
                "id": "{DID}",
                "verificationMethod": [{
                    "id": "{DID}#{SIGNING_KEY_MB}",
                    "type": "Multikey",
                    "controller": "{DID}",
                    "publicKeyMultibase": "{SIGNING_KEY_MB}"
                }],
                "authentication": ["{DID}#{SIGNING_KEY_MB}"],
                "assertionMethod": ["{DID}#{SIGNING_KEY_MB}"]
            }
        });
        let tpl = DidTemplate::from_json(tpl_json).expect("valid template");
        let record = DidTemplateRecord {
            template: tpl,
            scope: Scope::Context {
                context_id: "signer-ctx".into(),
            },
            created_at: 0,
            updated_at: 0,
            created_by: "test".into(),
        };
        crate::did_templates::store_context_template(&ts.did_templates_ks, "signer-ctx", &record)
            .await
            .expect("store context template");

        let auth = super_admin_claims();
        let request = signed_request_with_vars("local-signer", "signer-ctx", BTreeMap::new()).await;

        let output = provision_integration(
            &deps,
            &auth,
            ProvisionIntegrationParams {
                request,
                context: "signer-ctx".into(),
                assertion_mode: AssertionMode::PinnedOnly,
                vc_validity: None,
            },
        )
        .await
        .expect("provision_integration");

        let integration_did = output
            .summary
            .integration_did
            .as_deref()
            .expect("TemplateBootstrap path must yield Some(integration_did)");
        assert!(
            integration_did.starts_with("did:key:"),
            "integration DID must be a did:key for templates with methods=[\"key\"], got {integration_did}"
        );
        assert_eq!(
            output.summary.output_count, 0,
            "did:key path emits no webvh log — outputs should be empty"
        );
        assert_eq!(
            output.summary.secret_count, 1,
            "one minted integration DID in secrets (signing + KA keys for that DID)"
        );

        // Context's primary DID should be bound to the minted did:key.
        let ctx_after = crate::contexts::get_context(&ts.contexts_ks, "signer-ctx")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            ctx_after.did.as_deref(),
            Some(integration_did),
            "did:key path must set context primary when ctx.did was None"
        );
    }

    #[tokio::test]
    async fn provision_integration_bundle_kids_match_published_did_document() {
        // Regression test for the kid-numbering mismatch. The canonical
        // `didcomm-mediator` template now publishes verificationMethod
        // ids `#key-0` (signing) and `#key-1` (key-agreement) — matching
        // the VTA's internal storage convention and the other built-in
        // webvh templates (did-hosting-control / did-hosting-daemon / did-hosting-server).
        // Earlier shapes (`#key-1` / `#key-2`) diverged from both, and
        // consumers couldn't match an inbound JWE for `#key-2` to any
        // private key.
        //
        // Asserts (a) the bundle's kids equal `#key-0` / `#key-1`
        // exactly — the literal strings the canonical template declares
        // — and (b) every kid in `payload.secrets` equals a
        // `verificationMethod.id` in `payload.config.did_document`. The
        // doc-derived lookup in `provision_integration` is still
        // load-bearing for any future template that uses non-default
        // fragment names.
        use super::sealed_transfer_open::open_for_test;

        let ts = open_test_store().await;
        let (_vta_did, deps) = bootstrap_test_vta(&ts).await;
        crate::contexts::create_context(&ts.contexts_ks, "prod-mediator", "Prod")
            .await
            .expect("create context");

        let auth = super_admin_claims();
        let request = signed_request_with_vars(
            "didcomm-mediator",
            "prod-mediator",
            mediator_template_vars(),
        )
        .await;

        let output = provision_integration(
            &deps,
            &auth,
            ProvisionIntegrationParams {
                request,
                context: "prod-mediator".into(),
                assertion_mode: AssertionMode::PinnedOnly,
                vc_validity: None,
            },
        )
        .await
        .expect("provision_integration");

        // Open the sealed bundle with the holder's seed (the same
        // `[7u8; 32]` `signed_request_with_vars` signs with).
        let payload = open_for_test(&output.armored, &output.digest, &[7u8; 32]);

        let integration_did = output
            .summary
            .integration_did
            .as_deref()
            .expect("TemplateBootstrap path must yield Some(integration_did)");
        let material = payload
            .secrets
            .get(integration_did)
            .expect("integration DID secrets present");

        // (a) Literal kid assertion. Spelled out so a future regression
        // shows up directly in the diff.
        let expected_signing_kid = format!("{integration_did}#key-0");
        let expected_ka_kid = format!("{integration_did}#key-1");
        assert_eq!(
            material.signing_key.key_id, expected_signing_kid,
            "signing kid must be the canonical didcomm-mediator template's \
             `#key-0` to match the published DID doc"
        );
        assert_eq!(
            material.ka_key.key_id, expected_ka_kid,
            "key-agreement kid must be the canonical didcomm-mediator \
             template's `#key-1` to match the published DID doc"
        );

        // (b) Every kid in the bundle must appear as a
        // `verificationMethod.id` in the published doc — no off-by-one,
        // no dangling references.
        let doc = &payload.config.did_document;
        let vm_ids: Vec<String> = doc["verificationMethod"]
            .as_array()
            .expect("verificationMethod array")
            .iter()
            .filter_map(|vm| vm["id"].as_str().map(str::to_string))
            .collect();
        assert!(
            vm_ids.contains(&material.signing_key.key_id),
            "signing kid {} not in published verificationMethod ids {:?}",
            material.signing_key.key_id,
            vm_ids
        );
        assert!(
            vm_ids.contains(&material.ka_key.key_id),
            "key-agreement kid {} not in published verificationMethod ids {:?}",
            material.ka_key.key_id,
            vm_ids
        );
    }

    // ── BootstrapAsk::AdminRotation flow ────────────────────────────

    use crate::test_support::signed_admin_rotation_request;

    #[tokio::test]
    async fn provision_integration_admin_rotation_mints_fresh_admin_no_integration() {
        // Pins the AdminRotation contract end-to-end against the real
        // server flow:
        //   1. Returns Some(integration_did=None) — no integration mint.
        //   2. The summary's admin_did != client_did (rotation happened).
        //   3. The sealed bundle is a SealedPayloadV1::AdminRotation
        //      variant carrying the rotated admin DID's key material.
        //   4. The freshly-minted admin DID is the one written to the
        //      ACL row (admin role, in-context).
        let ts = open_test_store().await;
        let (_vta_did, deps) = bootstrap_test_vta(&ts).await;
        crate::contexts::create_context(&ts.contexts_ks, "ctx-1", "Test ctx")
            .await
            .expect("create context");

        let auth = super_admin_claims();
        let request = signed_admin_rotation_request("vta-admin", "ctx-1").await;
        let client_did = request.holder().to_string();

        let output = provision_integration(
            &deps,
            &auth,
            ProvisionIntegrationParams {
                request,
                context: "ctx-1".into(),
                assertion_mode: AssertionMode::PinnedOnly,
                vc_validity: None,
            },
        )
        .await
        .expect("provision_integration AdminRotation");

        // (1) Summary contract.
        assert!(
            output.summary.integration_did.is_none(),
            "AdminRotation must not produce an integration DID"
        );
        assert!(
            output.summary.template_name.is_none(),
            "AdminRotation has no integration template"
        );
        assert!(
            output.summary.template_kind.is_none(),
            "AdminRotation has no integration template kind"
        );
        assert!(output.summary.admin_rolled_over);
        assert_eq!(output.summary.secret_count, 1, "admin DID only");
        assert_eq!(output.summary.output_count, 0, "no template outputs");
        assert_eq!(
            output.summary.admin_template_name.as_deref(),
            Some("vta-admin")
        );

        // (2) Rotation must produce a fresh DID.
        assert_ne!(
            output.summary.admin_did, client_did,
            "AdminRotation must mint a fresh admin DID, not echo client_did"
        );

        // (3) Sealed payload variant + key material.
        let payload_bytes = output.armored.clone();
        let bundles =
            vta_sdk::sealed_transfer::armor::decode(&payload_bytes).expect("armor decode");
        assert_eq!(bundles.len(), 1, "single bundle");
        let x_secret = vta_sdk::sealed_transfer::ed25519_seed_to_x25519_secret(&[7u8; 32]);
        let opened =
            vta_sdk::sealed_transfer::open_bundle(&x_secret, &bundles[0], Some(&output.digest))
                .expect("open AdminRotation bundle");
        let rotation_payload = match opened.payload {
            vta_sdk::sealed_transfer::SealedPayloadV1::AdminRotation(boxed) => *boxed,
            other => panic!("expected AdminRotation, got {other:?}"),
        };
        assert_eq!(rotation_payload.admin.did, output.summary.admin_did);
        assert!(
            rotation_payload
                .admin
                .signing_key
                .private_key_multibase
                .starts_with('z')
        );

        // (4) ACL row is written for the rotated DID.
        let acl_entry = crate::acl::get_acl_entry(&deps.acl_ks, &output.summary.admin_did)
            .await
            .expect("ACL lookup")
            .expect("ACL row exists for rotated admin DID");
        assert_eq!(acl_entry.role, crate::acl::Role::Admin);
        assert!(
            acl_entry.allowed_contexts.iter().any(|c| c == "ctx-1"),
            "ACL row contexts must include ctx-1, got {:?}",
            acl_entry.allowed_contexts
        );
    }

    #[tokio::test]
    async fn provision_integration_admin_rotation_retires_ephemeral_acl_and_emits_swap_audit() {
        // Closes the May 2026 review gap: when the rotation mints a fresh
        // long-term admin DID, the ephemeral `client_did` that opened the
        // bundle has no further authority. Its ACL row (granted by the
        // operator just before this call) must be removed AND an
        // `acl.swap` audit entry must land, matching the
        // `operations::acl::swap_acl` audit shape.
        use crate::acl::{AclEntry, Role, store_acl_entry};
        use vta_sdk::protocols::audit_management::list::AuditLogEntry;

        let ts = open_test_store().await;
        let (_vta_did, deps) = bootstrap_test_vta(&ts).await;
        crate::contexts::create_context(&ts.contexts_ks, "ctx-swap", "Swap-audit ctx")
            .await
            .expect("create context");

        // The ephemeral the operator would have granted before calling
        // provision-integration. Hand-write the ACL row directly so the
        // test doesn't depend on `acl::create_acl`'s validation surface
        // (and doesn't need a separate auth ceremony for the grant).
        let request = signed_admin_rotation_request("vta-admin", "ctx-swap").await;
        let client_did = request.holder().to_string();
        let ephemeral_row = AclEntry::new(client_did.clone(), Role::Admin, "test")
            .with_label(Some("ephemeral".into()))
            .with_contexts(vec!["ctx-swap".into()])
            .with_created_at(0);
        store_acl_entry(&deps.acl_ks, &ephemeral_row)
            .await
            .expect("seed ephemeral ACL row");

        let auth = super_admin_claims();
        let output = provision_integration(
            &deps,
            &auth,
            ProvisionIntegrationParams {
                request,
                context: "ctx-swap".into(),
                assertion_mode: AssertionMode::PinnedOnly,
                vc_validity: None,
            },
        )
        .await
        .expect("provision_integration AdminRotation");

        // Ephemeral row gone, long-term row present.
        assert!(
            crate::acl::get_acl_entry(&deps.acl_ks, &client_did)
                .await
                .expect("acl get ephemeral")
                .is_none(),
            "ephemeral ACL row must be retired after admin rollover"
        );
        assert!(
            crate::acl::get_acl_entry(&deps.acl_ks, &output.summary.admin_did)
                .await
                .expect("acl get admin")
                .is_some(),
            "rotated admin ACL row must exist"
        );

        // Audit entry shape: action=acl.swap, actor=ephemeral,
        // resource=long-term, outcome=success, channel=provision-integration,
        // context_id=ctx-swap.
        let entries: Vec<AuditLogEntry> = {
            let raw = deps
                .audit_ks
                .prefix_iter_raw("log:")
                .await
                .expect("audit prefix scan");
            raw.iter()
                .filter_map(|(_, v)| serde_json::from_slice(v).ok())
                .collect()
        };
        let swap_entries: Vec<&AuditLogEntry> =
            entries.iter().filter(|e| e.action == "acl.swap").collect();
        assert_eq!(
            swap_entries.len(),
            1,
            "expected exactly one acl.swap audit entry, got: {:#?}",
            swap_entries
        );
        let swap = swap_entries[0];
        assert_eq!(swap.actor, client_did, "actor = swapped-from (ephemeral)");
        assert_eq!(
            swap.resource.as_deref(),
            Some(output.summary.admin_did.as_str()),
            "resource = swapped-to (rotated long-term admin)"
        );
        assert_eq!(swap.outcome, "success");
        assert_eq!(swap.channel.as_deref(), Some("provision-integration"));
        assert_eq!(swap.context_id.as_deref(), Some("ctx-swap"));
    }

    #[tokio::test]
    async fn provision_integration_admin_rotation_swap_audit_skipped_when_no_ephemeral_row() {
        // Relayer-mode flow: the holder ephemeral was never granted an
        // ACL row on this VTA (the relayer's bearer is the auth context).
        // The retirement helper must no-op silently — no spurious
        // acl.swap audit, no error.
        use vta_sdk::protocols::audit_management::list::AuditLogEntry;

        let ts = open_test_store().await;
        let (_vta_did, deps) = bootstrap_test_vta(&ts).await;
        crate::contexts::create_context(&ts.contexts_ks, "ctx-relayer", "Relayer ctx")
            .await
            .expect("create context");

        let auth = super_admin_claims();
        let request = signed_admin_rotation_request("vta-admin", "ctx-relayer").await;
        let client_did = request.holder().to_string();
        // Deliberately do NOT seed an ACL row for client_did — this
        // mirrors the relayer ≠ holder flow.

        let output = provision_integration(
            &deps,
            &auth,
            ProvisionIntegrationParams {
                request,
                context: "ctx-relayer".into(),
                assertion_mode: AssertionMode::PinnedOnly,
                vc_validity: None,
            },
        )
        .await
        .expect("provision_integration AdminRotation (relayer mode)");

        // Long-term ACL row still gets created (rollover succeeded).
        assert_ne!(output.summary.admin_did, client_did);
        assert!(
            crate::acl::get_acl_entry(&deps.acl_ks, &output.summary.admin_did)
                .await
                .expect("acl get admin")
                .is_some()
        );

        // No acl.swap audit — there was no swap to record.
        let entries: Vec<AuditLogEntry> = {
            let raw = deps
                .audit_ks
                .prefix_iter_raw("log:")
                .await
                .expect("audit prefix scan");
            raw.iter()
                .filter_map(|(_, v)| serde_json::from_slice(v).ok())
                .collect()
        };
        let swap_count = entries.iter().filter(|e| e.action == "acl.swap").count();
        assert_eq!(
            swap_count, 0,
            "no acl.swap entry expected when ephemeral has no ACL row"
        );
    }

    #[tokio::test]
    async fn provision_integration_admin_rotation_rejects_wrong_kind_template() {
        // Admin rotation requires an admin-kind template. If the
        // operator points us at e.g. didcomm-mediator (kind=mediator),
        // mint_admin_via_template fails — confirms the kind check fires
        // through this flow too.
        let ts = open_test_store().await;
        let (_vta_did, deps) = bootstrap_test_vta(&ts).await;
        crate::contexts::create_context(&ts.contexts_ks, "ctx-2", "Test ctx 2")
            .await
            .expect("create context");

        let auth = super_admin_claims();
        let request = signed_admin_rotation_request("didcomm-mediator", "ctx-2").await;

        let result = provision_integration(
            &deps,
            &auth,
            ProvisionIntegrationParams {
                request,
                context: "ctx-2".into(),
                assertion_mode: AssertionMode::PinnedOnly,
                vc_validity: None,
            },
        )
        .await;

        let err = match result {
            Ok(_) => panic!("non-admin template must be rejected"),
            Err(e) => e,
        };
        assert!(matches!(err, AppError::Validation(_)), "got: {err:?}");
        let msg = err.to_string();
        assert!(
            msg.contains("kind") && msg.contains("admin"),
            "error must explain admin-kind requirement, got: {msg}"
        );
    }
}

/// Test-only helper: open a PinnedOnly armored bundle to a holder seed.
/// Lives in a tiny submodule so the test that needs it can `use` the
/// function directly without re-implementing armor decode + HPKE open.
#[cfg(test)]
mod sealed_transfer_open {
    use vta_sdk::sealed_transfer::template_bootstrap::TemplateBootstrapPayload;
    use vta_sdk::sealed_transfer::{
        SealedPayloadV1, armor, ed25519_seed_to_x25519_secret, open_bundle,
    };

    pub fn open_for_test(
        armored: &str,
        digest: &str,
        holder_seed: &[u8; 32],
    ) -> TemplateBootstrapPayload {
        let bundles = armor::decode(armored).expect("armor decode");
        assert_eq!(bundles.len(), 1, "expected single bundle");
        let x_secret = ed25519_seed_to_x25519_secret(holder_seed);
        let opened = open_bundle(&x_secret, &bundles[0], Some(digest)).expect("open bundle");
        match opened.payload {
            SealedPayloadV1::TemplateBootstrap(boxed) => *boxed,
            other => panic!("expected TemplateBootstrap, got {other:?}"),
        }
    }
}
