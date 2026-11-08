//! Key-minting helpers for the provision-integration flow.
//!
//! Two mint paths:
//!   - `mint_admin_via_template` — long-term admin DID for the holder
//!     (did:key only in phase 1)
//!   - `mint_integration_via_did_key_template` — integration DID when
//!     the template declares `methods: ["key"]`
//!
//! Both delegate to `mint_did_key_from_template` for the shared derive +
//! store + render + X25519-KA-derive work. The caller-facing split lets
//! each role emit role-specific Validation errors (e.g. "admin template
//! must have kind='admin'").

use std::collections::BTreeMap;

use serde_json::Value;
use tracing::info;

use crate::error::AppError;
use vta_sdk::did_key::decode_private_key_multibase;
use vta_sdk::did_templates::TemplateVars;
use vta_sdk::provision_integration::DidTemplateRef;
use vta_sdk::sealed_transfer::template_bootstrap::{DidKeyMaterial, KeyPair};

use super::{ProvisionIntegrationDeps, templates};

/// Result of minting a long-term admin DID for the holder via a
/// `kind: "admin"` DID template. The minted key material is registered
/// in the VTA's keystore and returned here so the caller can drop it
/// into `payload.secrets` for the holder to install.
pub(super) struct MintedAdmin {
    pub(super) material: DidKeyMaterial,
}

/// Combined output of [`mint_did_key_from_template`]: key material for
/// installation at the holder plus the rendered DID document (kept for
/// the integration path, discarded for admin rollover).
struct MintedDidKey {
    material: DidKeyMaterial,
    rendered_document: Value,
}

/// Shared did:key mint: derive Ed25519, register keystore records,
/// derive the X25519 KA view, and render the template's DID document.
///
/// Caller is responsible for resolving + validating the template (kind
/// check, methods check). This helper only handles the derivation + save
/// flow — separating that concern lets admin and integration paths
/// share one implementation with role-specific error messages.
async fn mint_did_key_from_template(
    state: &ProvisionIntegrationDeps,
    context: &str,
    template: &vta_sdk::did_templates::DidTemplate,
    template_ref: &DidTemplateRef,
    label: String,
    purpose: &str, // logged — "admin" / "integration"
) -> Result<MintedDidKey, AppError> {
    use crate::keys::derive_and_store_did_key;
    use crate::keys::seeds::{get_active_seed_id, load_seed_bytes};

    let ctx = crate::contexts::get_context(&state.contexts_ks, context)
        .await?
        .ok_or_else(|| {
            AppError::Internal(format!(
                "context '{context}' disappeared between precondition check and did:key mint"
            ))
        })?;
    let active_seed_id = get_active_seed_id(&state.keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("active seed id: {e}")))?;
    let seed = load_seed_bytes(&state.keys_ks, &*state.seed_store, Some(active_seed_id))
        .await
        .map_err(|e| AppError::Internal(format!("load seed: {e}")))?;

    let (minted_did, signing_priv_mb) = derive_and_store_did_key(
        &seed,
        &ctx.base_path,
        context,
        &label,
        &state.keys_ks,
        Some(active_seed_id),
    )
    .await
    .map_err(|e| AppError::Internal(format!("derive did:key: {e}")))?;

    // The did:key multibase IS the signing key's pub multibase by
    // construction — the prefix `did:key:` is purely structural.
    let signing_pub_mb = minted_did
        .strip_prefix("did:key:")
        .ok_or_else(|| {
            AppError::Internal("derive_and_store_did_key returned a non-did:key DID".into())
        })?
        .to_string();
    let signing_key_id = format!("{minted_did}#{signing_pub_mb}");

    // Render the template — validates required vars + the rendered
    // document shape. For did:key the doc isn't published (the DID is
    // self-resolving), but the render still validates the template.
    let mut tpl_vars = TemplateVars::new();
    tpl_vars.insert_string("DID", &minted_did);
    tpl_vars.insert_string("SIGNING_KEY_MB", &signing_pub_mb);
    for (k, v) in &template_ref.vars {
        tpl_vars.insert(k.clone(), v.clone());
    }
    let rendered_document = template.render(&tpl_vars).map_err(|e| {
        AppError::Validation(format!(
            "template '{}' render failed: {e}",
            template_ref.name
        ))
    })?;

    // Derive the X25519 KA view from the same Ed25519 seed. Holders
    // that DIDComm-authenticate as this DID install both the signing
    // key and the KA derivation — bundle is self-describing, holder
    // doesn't need to know the Ed25519→X25519 derivation.
    let signing_seed: [u8; 32] = decode_private_key_multibase(&signing_priv_mb)
        .map_err(|e| AppError::Internal(format!("decode signing seed: {e}")))?;
    let signing_pub_bytes = affinidi_crypto::did_key::did_key_to_ed25519_pub(&minted_did)
        .map_err(|e| AppError::Internal(format!("decode did:key pub: {e}")))?;
    let ka_pub_bytes = affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(&signing_pub_bytes)
        .map_err(|e| AppError::Internal(format!("derive X25519 pub: {e}")))?;
    let ka_priv_bytes = affinidi_crypto::ed25519::ed25519_private_to_x25519(&signing_seed);

    let ka_pub_mb =
        crate::keys::encode_public_multibase(&crate::keys::KeyType::X25519, &ka_pub_bytes);
    let ka_priv_mb =
        crate::keys::encode_private_multibase(&crate::keys::KeyType::X25519, &ka_priv_bytes);
    // did:key Ed25519 resolvers use the X25519 multibase as the KA
    // verification-method fragment. Mirror that convention so the
    // installed key id matches what consumers expect to see in the
    // resolved DID document.
    let ka_key_id = format!("{minted_did}#{ka_pub_mb}");

    info!(
        did = %minted_did,
        context = %context,
        template = %template_ref.name,
        purpose,
        "minted did:key via template"
    );

    Ok(MintedDidKey {
        material: DidKeyMaterial {
            did: minted_did,
            signing_key: KeyPair {
                key_id: signing_key_id,
                public_key_multibase: signing_pub_mb,
                private_key_multibase: signing_priv_mb,
            },
            ka_key: KeyPair {
                key_id: ka_key_id,
                public_key_multibase: ka_pub_mb,
                private_key_multibase: ka_priv_mb,
            },
        },
        rendered_document,
    })
}

/// Mint a fresh long-term admin DID under the VTA's key custody, using
/// the operator-named admin template. Phase 1: did:key (Ed25519) only.
///
/// The signing key is a fresh BIP-32 derivation under the context's
/// base path; the X25519 key-agreement view is derived from the same
/// Ed25519 seed (canonical did:key derivation) so DIDComm authcrypt
/// works without the holder needing to know about the Ed25519→X25519
/// derivation themselves.
pub(super) async fn mint_admin_via_template(
    state: &ProvisionIntegrationDeps,
    context: &str,
    admin_template_ref: &DidTemplateRef,
) -> Result<MintedAdmin, AppError> {
    // 1. Resolve the template (built-in / global / context-scoped).
    let admin_tpl =
        templates::resolve_admin_template(state, context, &admin_template_ref.name).await?;

    // 2. The template must declare admin kind — otherwise the operator
    //    pointed us at a non-admin shape (mediator, webvh-host, etc.)
    //    and the resulting VC binding would be wrong. Fail loud.
    if admin_tpl.kind != "admin" {
        return Err(AppError::Validation(format!(
            "template '{}' has kind '{}', not 'admin'. Admin-DID rollover \
             requires a template that declares kind=\"admin\" (e.g. the \
             built-in 'vta-admin' template).",
            admin_template_ref.name, admin_tpl.kind
        )));
    }

    // 3. Phase 1 only mints did:key admin DIDs. Templates targeting
    //    other methods are accepted at registration time but we reject
    //    them here until the corresponding mint path lands.
    if !admin_tpl.methods.is_empty() && !admin_tpl.methods.iter().any(|m| m == "key") {
        return Err(AppError::Validation(format!(
            "admin template '{}' targets methods {:?}; phase 1 only \
             supports 'key'. Use a did:key admin template (or omit \
             `methods` in the template to accept any).",
            admin_template_ref.name, admin_tpl.methods
        )));
    }

    // 4-7. Delegate the derive + save + render + KA-derive work to the
    //      shared helper. Admin path discards the rendered document —
    //      did:key is self-resolving.
    let minted = mint_did_key_from_template(
        state,
        context,
        &admin_tpl,
        admin_template_ref,
        format!("admin DID for context {context} (provision-integration)"),
        "admin",
    )
    .await?;

    Ok(MintedAdmin {
        material: minted.material,
    })
}

/// Mint a fresh integration DID as a `did:key` via the operator-named
/// template. Selected automatically when the template's `methods`
/// declares `["key"]` only — otherwise provision-integration stays on
/// the webvh path.
///
/// Shape of the returned tuple mirrors the fields of
/// `did_webvh::CreateDidWebvhResultBody` that `provision_integration`
/// actually reads, so the downstream code that builds secrets / VC /
/// payload doesn't branch on "webvh vs key".
pub(super) async fn mint_integration_via_did_key_template(
    state: &ProvisionIntegrationDeps,
    context: &str,
    client_did: &str,
    template_name: &str,
    template_vars: &BTreeMap<String, Value>,
) -> Result<
    (
        String,
        String,
        String,
        Value,
        Option<String>,
        DidKeyMaterial,
    ),
    AppError,
> {
    let template = templates::resolve_template_by_name(state, context, template_name)
        .await
        .map_err(|e| match e {
            AppError::NotFound(_) => AppError::Validation(format!(
                "integration template '{template_name}' is not registered on this VTA. \
                 Register it via 'pnm did-templates create --file <path> --context {context}' (the file's \
                 `name` must be '{template_name}') \
                 then retry."
            )),
            other => other,
        })?;

    let template_ref = DidTemplateRef {
        name: template_name.to_string(),
        vars: template_vars.clone(),
    };
    let label = format!(
        "integration DID for context {context} (provision-integration, did:key, holder {client_did})"
    );
    let minted = mint_did_key_from_template(
        state,
        context,
        &template,
        &template_ref,
        label,
        "integration",
    )
    .await?;

    Ok((
        minted.material.did.clone(),
        minted.material.signing_key.key_id.clone(),
        minted.material.ka_key.key_id.clone(),
        minted.rendered_document,
        None, // did:key has no did.jsonl log
        minted.material,
    ))
}
