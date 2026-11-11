//! A `did:webs` from a DID template (`vta/webs/_shared/0.2` CONVENTIONS.md §9),
//! and the class rules a create obeys (§1.2).
//!
//! The template is resolved as `did:webvh` creation resolves one (context →
//! global → built-in), its variables are checked against what it declares, and
//! it is rendered **twice**: once before any key is derived, with placeholder
//! keys and DID, so that every §9.2 refusal leaves nothing behind; and once
//! after the inception, with the real DID and keys, to read the designations
//! from. Both renders are checked by the same pure function,
//! [`vta_sdk::did_templates::webs::map_webs_document`].

use std::collections::BTreeMap;

use serde_json::{Value, json};
use vta_sdk::contexts::ContextRecord;
use vta_sdk::did_templates::webs::{
    NotRepresentable, RenderedKey, WebsDesignations, WebsRenderedKeys, WebsTemplateRefusal,
    check_key_shape, is_node_kind, map_webs_document,
};
use vta_sdk::did_templates::{DidTemplate, KeyPurpose, Scope, TemplateError, TemplateVars};

use super::{CreateDidWebsParams, WebsDeps, WebsError, WebsRefusal, WebsTemplateRequest};
use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::webs_store::{self, WebsDidClass, WebsTemplateUse};

/// A template resolved and checked, ready to render for the real DID.
pub(super) struct TemplatePlan {
    template: DidTemplate,
    /// The caller's variables, every one declared by the template.
    vars: BTreeMap<String, Value>,
    /// What the record keeps and the response returns.
    pub(super) used: WebsTemplateUse,
}

/// The DID a template is rendered with before the AID exists. Only ever
/// compared with itself: the check is of the document's shape.
const PENDING_DID: &str = "did:webs:pending.invalid:EPendingAidPendingAidPendingAidPendingAid0";

/// Resolve `request`, check its variables, and check its document with
/// placeholder keys (CONVENTIONS.md §9.1, §9.2) — before any key is derived.
pub(super) async fn plan_template(
    deps: &WebsDeps<'_>,
    auth: &AuthClaims,
    params: &CreateDidWebsParams,
    ctx: &ContextRecord,
    request: &WebsTemplateRequest,
) -> Result<TemplatePlan, WebsError> {
    let ks = deps.did_templates_ks.ok_or_else(|| {
        AppError::Internal("no DID template store is open here; a template cannot be read".into())
    })?;
    // A context's templates are visible to that context's administrators
    // (create/0.2, Authorization); naming one the caller cannot reach is the
    // `permissionDenied` CONVENTIONS.md §8 gives a context the caller may not
    // act in, rather than a silent fall-through to the global scope.
    if let Some(ctx) = request.context.as_deref() {
        auth.require_context(ctx)?;
    }
    let record = crate::operations::did_webvh::resolve_template_for_render(
        ks,
        &request.name,
        request.context.as_deref(),
    )
    .await
    .map_err(|e| match e {
        AppError::NotFound(m) => {
            let mut details = json!({ "template": request.name });
            if let Some(c) = &request.context {
                details["templateContext"] = json!(c);
            }
            WebsError::refused_with(WebsRefusal::TemplateNotFound, m, details)
        }
        e => e.into(),
    })?;
    let scope = match &record.scope {
        Scope::Builtin => "builtin".to_string(),
        Scope::Global => "global".to_string(),
        Scope::Context { context_id } => context_id.clone(),
    };
    let template = record.template;

    // §9.2 MAY: a node's template under a class other than `service`.
    if let Some(class) = params.did_class
        && class != WebsDidClass::Service
        && is_node_kind(&template.kind)
    {
        return Err(WebsError::refused_with(
            WebsRefusal::DidClassConflict,
            format!(
                "template '{}' shapes a node's identity (kind `{}`): a DID made from it is a \
                 service DID, not a {} DID",
                template.name,
                template.kind,
                class.as_str()
            ),
            json!({ "requiredClass": "service" }),
        ));
    }

    check_key_shape(&template).map_err(not_representable)?;

    let unknown = template.undeclared_vars(request.vars.keys().map(String::as_str));
    if !unknown.is_empty() {
        return Err(vars_invalid(
            &template.name,
            &[],
            &unknown,
            "does not declare",
        ));
    }

    let plan = TemplatePlan {
        used: WebsTemplateUse {
            name: template.name.clone(),
            scope,
            kind: template.kind.clone(),
        },
        template,
        vars: request.vars.clone(),
    };

    // The document, with placeholder keys and DID: every member is checked
    // here, before a key exists to be left behind.
    let keys = WebsRenderedKeys {
        signing: RenderedKey {
            multibase: "z6MkPendingSigningKey".into(),
            jwk: Some(json!({ "kty": "OKP", "crv": "Ed25519", "x": "pending-signing-key" })),
        },
        key_agreement: RenderedKey {
            multibase: "z6LSPendingKeyAgreementKey".into(),
            jwk: Some(json!({ "kty": "OKP", "crv": "X25519", "x": "pending-key-agreement-key" })),
        },
    };
    let vars = render_vars(&plan, PENDING_DID, &keys, ambient(deps, params, ctx));
    render_and_map(&plan, &vars, PENDING_DID, &keys)?;
    Ok(plan)
}

/// The keys a template is rendered with, from the key records' multibase.
pub(super) fn rendered_keys(signing_mb: &str, ka_mb: &str) -> WebsRenderedKeys {
    let jwk = |mb: &str| crate::operations::did_webvh::document::public_jwk(mb).ok();
    WebsRenderedKeys {
        signing: RenderedKey {
            multibase: signing_mb.to_string(),
            jwk: jwk(signing_mb),
        },
        key_agreement: RenderedKey {
            multibase: ka_mb.to_string(),
            jwk: jwk(ka_mb),
        },
    }
}

/// The variables the renderer is given for the real DID.
pub(super) fn ambient_vars(
    deps: &WebsDeps<'_>,
    params: &CreateDidWebsParams,
    ctx: &ContextRecord,
    plan: &TemplatePlan,
    did: &str,
    keys: &WebsRenderedKeys,
) -> TemplateVars {
    render_vars(plan, did, keys, ambient(deps, params, ctx))
}

/// The configuration and context state a template may name, as `did:webvh`
/// creation supplies it.
fn ambient(deps: &WebsDeps<'_>, params: &CreateDidWebsParams, ctx: &ContextRecord) -> TemplateVars {
    let mut vars = TemplateVars::new();
    if let Some(vta_did) = &deps.config.vta_did {
        vars.insert_string("VTA_DID", vta_did.clone());
    }
    if let Some(url) = &deps.config.public_url {
        vars.insert_string("VTA_URL", url.clone());
    }
    vars.insert_string("CONTEXT_ID", params.context_id.clone());
    if let Some(did) = &ctx.did {
        vars.insert_string("CONTEXT_DID", did.clone());
    }
    vars.insert_string("NOW", chrono::Utc::now().to_rfc3339());
    vars
}

/// The keys under every placeholder the template's slots occupy (§9.1 item 3),
/// the DID, then the caller's variables.
fn render_vars(
    plan: &TemplatePlan,
    did: &str,
    keys: &WebsRenderedKeys,
    mut vars: TemplateVars,
) -> TemplateVars {
    vars.insert_string("DID", did);
    for (slot, spec) in plan.template.key_slots() {
        let key = match spec.purpose {
            KeyPurpose::Signing => &keys.signing,
            KeyPurpose::KeyAgreement => &keys.key_agreement,
            // `check_key_shape` has refused any other purpose.
            _ => continue,
        };
        vars.insert_string(DidTemplate::slot_var(&slot), key.multibase.clone());
        if let Some(jwk) = &key.jwk {
            vars.insert(DidTemplate::slot_var_jwk(&slot), jwk.clone());
        }
    }
    for (k, v) in &plan.vars {
        vars.insert(k.clone(), v.clone());
    }
    vars
}

/// Render and map, refusing as the task declares.
pub(super) fn render_and_map(
    plan: &TemplatePlan,
    vars: &TemplateVars,
    did: &str,
    keys: &WebsRenderedKeys,
) -> Result<WebsDesignations, WebsError> {
    let name = &plan.template.name;
    let rendered = plan.template.render(vars).map_err(|e| match e {
        TemplateError::MissingVars(m) => vars_invalid(name, &split(&m), &[], "requires"),
        TemplateError::Unresolved(m) => vars_invalid(name, &split(&m), &[], "leaves unresolved"),
        e => AppError::Validation(format!("template '{name}' render failed: {e}")).into(),
    })?;
    map_webs_document(&plan.template, &rendered, did, keys).map_err(|e| match e {
        WebsTemplateRefusal::NotRepresentable(n) => not_representable(n),
        WebsTemplateRefusal::ServiceIdConflict { id } => WebsError::refused(
            WebsRefusal::ServiceIdConflict,
            format!("serviceIdConflict: template '{name}' gives two services the id {id}"),
        ),
        // `WebsTemplateRefusal` is `#[non_exhaustive]`.
        e => AppError::Internal(format!("template '{name}': {e:?}")).into(),
    })
}

fn split(names: &str) -> Vec<String> {
    names
        .split(',')
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_string)
        .collect()
}

fn not_representable(n: NotRepresentable) -> WebsError {
    let details = n.details();
    WebsError::refused_with(WebsRefusal::TemplateNotRepresentable, n.message, details)
}

fn vars_invalid(name: &str, missing: &[String], unknown: &[String], what: &str) -> WebsError {
    let mut details = json!({});
    if !missing.is_empty() {
        details["missing"] = json!(missing);
    }
    if !unknown.is_empty() {
        details["unknown"] = json!(unknown);
    }
    let names: Vec<&str> = missing.iter().chain(unknown).map(String::as_str).collect();
    WebsError::refused_with(
        WebsRefusal::TemplateVarsInvalid,
        format!(
            "template '{name}' {what} the variable(s) {}; nothing was derived",
            names.join(", ")
        ),
        details,
    )
}

/// The class of the identity a context's primary DID is, as far as this VTA
/// can tell: its own DID is a service DID, and a `did:webs` it holds is what it
/// was created as. Any other DID's class is not recorded here.
async fn primary_class(
    deps: &WebsDeps<'_>,
    primary: &str,
) -> Result<Option<WebsDidClass>, AppError> {
    if deps.config.vta_did.as_deref() == Some(primary) {
        return Ok(Some(WebsDidClass::Service));
    }
    Ok(webs_store::get(deps.webs_ks, primary)
        .await?
        .and_then(|r| r.did_class))
}

/// CONVENTIONS.md 0.2 §1.2, for a create with `setPrimary` in `class`:
///
/// 1. a persona or relationship DID may not become the primary DID of a
///    context whose primary is a service DID (`requiredClass: service`);
/// 2. a service DID may not replace a persona DID as a context's primary;
///
/// and, as for 0.1, nothing replaces this VTA's own identity by a create
/// (`NodeIdentityContext`).
///
/// A context provisioned for a VTC, a VTN or a host service carries no marker
/// here, so §1.2 item 1's second case is not refused: the gap
/// `docs/02-vta/did-webs.md` records.
pub(super) async fn check_primary_class(
    deps: &WebsDeps<'_>,
    ctx: &ContextRecord,
    class: WebsDidClass,
) -> Result<(), WebsError> {
    let Some(primary) = ctx.did.as_deref() else {
        return Ok(());
    };
    let current = primary_class(deps, primary).await?;
    match (class, current) {
        (WebsDidClass::Persona | WebsDidClass::Relationship, Some(WebsDidClass::Service)) => {
            Err(WebsError::refused_with(
                WebsRefusal::DidClassConflict,
                format!(
                    "context {}'s primary DID {primary} is a service DID: a {} DID cannot become \
                     a node's identity (VTI-KEY-193)",
                    ctx.id,
                    class.as_str()
                ),
                json!({ "requiredClass": "service" }),
            ))
        }
        // Both a persona and a relationship DID would be accepted, so no
        // `requiredClass`.
        (WebsDidClass::Service, Some(WebsDidClass::Persona)) => Err(WebsError::refused(
            WebsRefusal::DidClassConflict,
            format!(
                "context {}'s primary DID {primary} is a persona DID: a service DID does not \
                 replace it (VTI-KEY-193)",
                ctx.id
            ),
        )),
        _ => super::refuse_service_context(deps.config, ctx),
    }
}
