//! Authorization + request-shape checks that run before the VTA
//! mutates any state. Failing here leaves the store untouched — a typo
//! in a template name or a missing context is surfaced with a concrete
//! operator remediation before we mint keys or write ACL rows.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::store::KeyspaceHandle;
use vta_sdk::provision_integration::{BootstrapAsk, DidTemplateRef, VerifiedBootstrapRequest};

use super::ProvisionIntegrationDeps;

/// Returned when [`infer_target_context`] cannot pick a single target
/// context — caller has admin in multiple contexts, or is a super-admin
/// against a multi-context maintainer. Carries the plausible candidates
/// so the transport layer can surface them to the relayer and let them
/// retry with an explicit choice.
///
/// The caller renders this differently per transport: the DIDComm
/// handler emits a `provision/integration:context_required` problem
/// report with `args = candidates`; the REST handler returns a 400
/// with the message and candidates inlined.
#[derive(Debug)]
pub struct AmbiguousContext {
    pub candidates: Vec<String>,
    pub message: String,
}

/// Infer the target context the maintainer should provision into when
/// the caller omits `payload.context`. Implements the three rules
/// pinned in
/// `dtgwg-trust-tasks-tf/specs/provision/integration/0.1/spec.md`
/// §"Context inference":
///
/// 1. **Single-context grant.** If the relayer's ACL entry scopes to
///    exactly one context, use that context.
/// 2. **Single-context maintainer.** If the relayer is a super-admin
///    AND the maintainer has exactly one context registered, use it.
/// 3. **Ambiguous.** Anything else returns
///    [`Err(AmbiguousContext)`] so the caller can surface candidates
///    + retry with an explicit value.
///
/// `Result<Result<…>, …>` is intentional: the outer `Result` is the
/// usual `AppError` plumbing (store-level failures); the inner Result
/// distinguishes "inferred ok" from "ambiguous, here are the candidates"
/// without conflating the two with store errors.
pub async fn infer_target_context(
    auth: &AuthClaims,
    contexts_ks: &KeyspaceHandle,
) -> Result<Result<String, AmbiguousContext>, AppError> {
    // Rule 1: single-context grant — operator already named the bucket
    // on the wire when they granted the ephemeral. Respect it.
    if let Some(ctx) = auth.default_context() {
        return Ok(Ok(ctx.to_string()));
    }

    // Rule 2: super-admin + single-context maintainer. Covers the
    // typical wallet onboarding case where the operator ran
    // `pnm acl create --did <eph> --role admin` (no `--contexts`)
    // against a single-context VTA.
    if auth.is_super_admin() {
        let contexts = crate::contexts::list_contexts(contexts_ks).await?;
        let mut ids: Vec<String> = contexts.iter().map(|c| c.id.clone()).collect();
        ids.sort();
        match ids.len() {
            0 => {
                // No contexts at all — distinct from "ambiguous". The
                // operator needs to create a context first; surface as
                // NotFound with a remediation hint matching the rest of
                // provision-integration's error vocabulary.
                return Err(AppError::NotFound(
                    "no contexts registered on this VTA — create one with \
                     'vta contexts create --id <name>' (offline) or \
                     'pnm contexts create' (online), then retry"
                        .into(),
                ));
            }
            1 => return Ok(Ok(ids.into_iter().next().expect("len == 1"))),
            n => {
                return Ok(Err(AmbiguousContext {
                    candidates: ids,
                    message: format!(
                        "super-admin grant against {n} contexts — \
                         specify which to provision into via payload.context"
                    ),
                }));
            }
        }
    }

    // Rule 3a: multi-context relayer (not super-admin) — caller has
    // admin in N > 1 contexts but didn't say which. Return the list.
    if auth.allowed_contexts.len() > 1 {
        let mut ids = auth.allowed_contexts.clone();
        ids.sort();
        return Ok(Err(AmbiguousContext {
            message: format!(
                "caller holds admin in {} contexts — specify which to provision into via payload.context",
                ids.len()
            ),
            candidates: ids,
        }));
    }

    // Defensive fallthrough: caller is not super-admin (would have
    // matched above), has 0 or 1 allowed_contexts but default_context
    // returned None (so it's 0). A non-super-admin with zero context
    // grants shouldn't reach the inference step — `require_admin`
    // would have rejected. But surface clearly if it does.
    Err(AppError::Forbidden(
        "caller has admin role but no context grants — refusing to infer".into(),
    ))
}

/// Ensure the target `context` exists, optionally creating it
/// inline when `create_context` is set. Centralised here so REST,
/// DIDComm, and the offline CLI all enforce the same semantics:
///
/// - Context exists → returns `Ok(false)` (idempotent, no-op).
/// - Context missing + `create_context: false` → `AppError::NotFound`
///   with the existing precondition message.
/// - Context missing + `create_context: true` → calls
///   [`crate::operations::contexts::create_context`], which itself
///   checks `auth.require_super_admin()`. Context-admin callers
///   land here and surface as `AppError::Forbidden`. Returns
///   `Ok(true)` on success so callers can populate
///   `summary.context_created`.
///
/// Auth concentration: the super-admin gate lives inside
/// `operations::contexts::create_context` exclusively. We don't
/// re-check it here so the boundary stays in one place.
pub async fn ensure_target_context_or_create(
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    context: &str,
    create_context: bool,
) -> Result<bool, AppError> {
    if crate::contexts::get_context(contexts_ks, context)
        .await?
        .is_some()
    {
        return Ok(false);
    }
    if !create_context {
        return Err(AppError::NotFound(format!(
            "context '{context}' is not registered on this VTA — create it first via \
             'vta contexts create --id {context}' (offline) or 'pnm contexts create' (online), \
             or pass '--create-context' to provision it inline"
        )));
    }
    crate::operations::contexts::create_context(
        contexts_ks,
        auth,
        context,
        context.to_string(),
        None,
        None, // top-level context (provisioning never nests)
        "provision-integration",
    )
    .await?;
    Ok(true)
}

/// Failure modes of [`resolve_target_context`], kept distinct so each transport
/// renders the ambiguous case in its own idiom.
#[derive(Debug)]
pub enum ResolveContextError {
    /// Inference couldn't pick a single target — carries the candidates so the
    /// transport can surface them (REST: 400 with candidates inlined; DIDComm:
    /// `provision/integration:context_required` problem report, `args =
    /// candidates`).
    Ambiguous(AmbiguousContext),
    /// Any other failure — storage error, no-context-at-all `NotFound`, the
    /// missing-context-without-`--create-context` `NotFound`, or the super-admin
    /// gate inside `create_context`.
    Op(AppError),
}

impl From<AppError> for ResolveContextError {
    fn from(e: AppError) -> Self {
        Self::Op(e)
    }
}

/// Resolve the provision target context end-to-end: use the caller-supplied
/// `requested` context verbatim, else infer it ([`infer_target_context`]); then
/// ensure it exists, creating it inline when `create_context`
/// ([`ensure_target_context_or_create`]). Returns `(context, context_created)`.
///
/// This is the shared preamble for both provision handlers (REST
/// `routes::bootstrap`, DIDComm `messaging::handlers`) — the context policy
/// (inference rules + create-or-reject + the super-admin gate concentration)
/// lives here once. Both transports pass the **already VP-verified** request
/// separately; only this context step is hoisted (the VP-verify and
/// summary-mapping steps differ per transport by design).
pub async fn resolve_target_context(
    auth: &AuthClaims,
    contexts_ks: &KeyspaceHandle,
    requested: Option<String>,
    create_context: bool,
) -> Result<(String, bool), ResolveContextError> {
    let context = match requested {
        Some(c) => c,
        // `?` on the outer `Result` maps store-level `AppError` → `Op`; the
        // inner `map_err` lifts the ambiguous case.
        None => infer_target_context(auth, contexts_ks)
            .await?
            .map_err(ResolveContextError::Ambiguous)?,
    };
    let created =
        ensure_target_context_or_create(contexts_ks, auth, &context, create_context).await?;
    Ok((context, created))
}

pub(super) async fn preconditions(
    state: &ProvisionIntegrationDeps,
    auth: &AuthClaims,
    context: &str,
    request: &VerifiedBootstrapRequest,
) -> Result<(), AppError> {
    auth.require_admin()?;
    auth.require_context(context)?;

    // Context must exist.
    if crate::contexts::get_context(&state.contexts_ks, context)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound(format!(
            "context '{context}' is not registered on this VTA — create it first via \
             'vta context create --id {context}' (offline) or 'pnm contexts create' (online), \
             or pass '--create-context' to provision it inline"
        )));
    }

    // If the request carries a context hint, it must agree with the
    // chosen context. Silently normalizing hides operator bugs.
    let hint = match request.ask() {
        BootstrapAsk::TemplateBootstrap(ask) => ask.context_hint.as_deref(),
        BootstrapAsk::AdminRotation(ask) => ask.context_hint.as_deref(),
    };
    if let Some(hint) = hint
        && hint != context
    {
        return Err(AppError::Validation(format!(
            "request contextHint '{hint}' does not match provisioning context '{context}'"
        )));
    }

    // Template must be registered. Resolve order matches template-render:
    // context scope → global → built-in. Built-ins always resolve via the
    // SDK's embedded loader; only operator-uploaded templates need a
    // stored record.
    //
    // For TemplateBootstrap: integration template is required, admin
    // template is optional.
    // For AdminRotation: there is no integration template; admin
    // template is required.
    let (integration_template_name, admin_template_name): (Option<String>, Option<String>) =
        match request.ask() {
            BootstrapAsk::TemplateBootstrap(ask) => (
                Some(ask.template.name.clone()),
                ask.admin_template.as_ref().map(|t| t.name.clone()),
            ),
            BootstrapAsk::AdminRotation(ask) => (None, Some(ask.admin_template.name.clone())),
        };

    if let Some(template_name) = integration_template_name.as_deref() {
        let template_registered = crate::did_templates::get_context_template(
            &state.did_templates_ks,
            context,
            template_name,
        )
        .await?
        .is_some()
            || crate::did_templates::get_global_template(&state.did_templates_ks, template_name)
                .await?
                .is_some()
            || vta_sdk::did_templates::load_embedded(template_name).is_ok();
        if !template_registered {
            return Err(AppError::Validation(format!(
                "template '{template_name}' is not registered on this VTA. Register it via \
                 'pnm did-templates create {template_name} --file <path>' then retry"
            )));
        }
    }

    // Admin-template registration check. For AdminRotation this is the
    // primary template; for TemplateBootstrap it's the optional rollover
    // template. Built-ins (`vta-admin`) always resolve via the SDK's
    // embedded loader; only operator-uploaded templates need a stored
    // record.
    if let Some(name) = admin_template_name {
        let registered =
            crate::did_templates::get_context_template(&state.did_templates_ks, context, &name)
                .await?
                .is_some()
                || crate::did_templates::get_global_template(&state.did_templates_ks, &name)
                    .await?
                    .is_some()
                || vta_sdk::did_templates::load_embedded(&name).is_ok();
        if !registered {
            return Err(AppError::Validation(format!(
                "admin template '{name}' is not registered on this VTA. Register it via \
                 'pnm did-templates create {name} --file <path>' then retry, or use the \
                 built-in 'vta-admin' template."
            )));
        }
    }

    Ok(())
}

/// Extract the integration template name + variables from a
/// `TemplateBootstrap` ask. Returns `None` for `AdminRotation` (which
/// has no integration template — caller must dispatch on the variant
/// before reaching the integration mint).
pub(super) fn extract_template(
    ask: &BootstrapAsk,
) -> Result<Option<(String, BTreeMap<String, Value>)>, AppError> {
    match ask {
        BootstrapAsk::TemplateBootstrap(ask) => {
            Ok(Some((ask.template.name.clone(), ask.template.vars.clone())))
        }
        BootstrapAsk::AdminRotation(_) => Ok(None),
    }
}

/// Extract the admin-template reference from an `ask`.
///
/// - `TemplateBootstrap` → `Some(_)` only when `admin_template` is set
///   (operator opted into rollover).
/// - `AdminRotation` → always `Some(_)` (admin template is required).
pub(super) fn extract_admin_template(ask: &BootstrapAsk) -> Option<DidTemplateRef> {
    match ask {
        BootstrapAsk::TemplateBootstrap(ask) => ask.admin_template.clone(),
        BootstrapAsk::AdminRotation(ask) => Some(ask.admin_template.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::Role;
    use crate::store::Store;
    use vti_common::config::StoreConfig;

    async fn fresh_contexts_ks() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let ks = store
            .keyspace(crate::keyspaces::CONTEXTS)
            .expect("open contexts ks");
        (dir, store, ks)
    }

    fn auth(role: Role, allowed_contexts: Vec<&str>) -> AuthClaims {
        AuthClaims {
            did: "did:key:zTestCaller".into(),
            role,
            allowed_contexts: allowed_contexts.iter().map(|s| (*s).to_string()).collect(),
            session_id: "test-session".into(),
            // Synthesized auth claim, not from a JWT — mirrors the
            // shape used by `AuthClaims::synthesize` for DIDComm-only
            // callers in the codebase.
            access_expires_at: 0,
            amr: vec!["synth".into()],
            acr: String::new(),
        }
    }

    async fn seed_context(ks: &KeyspaceHandle, id: &str) {
        crate::contexts::create_context(ks, id, id)
            .await
            .expect("seed context");
    }

    /// Rule 1: single allowed context → returns it. The relayer's grant
    /// already named the bucket; inference respects it without
    /// consulting the contexts keyspace.
    #[tokio::test]
    async fn infer_returns_single_allowed_context() {
        let (_dir, _store, ks) = fresh_contexts_ks().await;
        // Seed multiple contexts to confirm the inference doesn't reach
        // for rule 2's fallback when rule 1 already resolves.
        seed_context(&ks, "ctx-a").await;
        seed_context(&ks, "ctx-b").await;

        let a = auth(Role::Admin, vec!["ctx-b"]);
        let result = infer_target_context(&a, &ks).await.expect("ok");
        assert_eq!(result.expect("not ambiguous"), "ctx-b");
    }

    /// Rule 2: super-admin grant + maintainer has exactly one context →
    /// use it. This is the typical wallet onboarding case where the
    /// operator ran `pnm acl create --did <eph> --role admin` (no
    /// `--contexts` flag = super-admin scoping).
    #[tokio::test]
    async fn infer_super_admin_with_single_context() {
        let (_dir, _store, ks) = fresh_contexts_ks().await;
        seed_context(&ks, "only").await;

        let a = auth(Role::Admin, vec![]); // empty → super-admin
        assert!(a.is_super_admin());

        let result = infer_target_context(&a, &ks).await.expect("ok");
        assert_eq!(result.expect("not ambiguous"), "only");
    }

    /// Rule 3a: super-admin + multiple contexts → ambiguous; carry the
    /// candidates so the caller can surface them and retry.
    #[tokio::test]
    async fn infer_super_admin_with_multiple_contexts_is_ambiguous() {
        let (_dir, _store, ks) = fresh_contexts_ks().await;
        seed_context(&ks, "ctx-a").await;
        seed_context(&ks, "ctx-b").await;
        seed_context(&ks, "ctx-c").await;

        let a = auth(Role::Admin, vec![]);

        let result = infer_target_context(&a, &ks).await.expect("ok");
        let ambiguous = result.expect_err("must be ambiguous with 3 contexts");
        assert_eq!(
            ambiguous.candidates,
            vec![
                "ctx-a".to_string(),
                "ctx-b".to_string(),
                "ctx-c".to_string()
            ]
        );
        assert!(ambiguous.message.contains("3 contexts"));
    }

    /// Rule 3b: multi-context grant (non-super-admin) → ambiguous,
    /// candidates come from the relayer's own `allowed_contexts`.
    #[tokio::test]
    async fn infer_multi_context_grant_is_ambiguous() {
        let (_dir, _store, ks) = fresh_contexts_ks().await;

        let a = auth(Role::Admin, vec!["ctx-x", "ctx-y"]);

        let result = infer_target_context(&a, &ks).await.expect("ok");
        let ambiguous = result.expect_err("two contexts → ambiguous");
        assert_eq!(
            ambiguous.candidates,
            vec!["ctx-x".to_string(), "ctx-y".to_string()]
        );
    }

    /// Super-admin against an empty maintainer → NotFound, not
    /// AmbiguousContext. The remediation is "create a context first"
    /// rather than "pick from the list" (the list is empty).
    #[tokio::test]
    async fn infer_super_admin_with_no_contexts_returns_not_found() {
        let (_dir, _store, ks) = fresh_contexts_ks().await;

        let a = auth(Role::Admin, vec![]);

        let err = infer_target_context(&a, &ks)
            .await
            .expect_err("must NotFound");
        assert!(
            matches!(err, AppError::NotFound(_)),
            "expected NotFound, got {err:?}"
        );
    }

    // ── resolve_target_context (shared REST + DIDComm preamble) ──────────

    /// Caller-supplied context that already exists → returned verbatim,
    /// `context_created = false`, inference not consulted.
    #[tokio::test]
    async fn resolve_uses_requested_existing_context() {
        let (_dir, _store, ks) = fresh_contexts_ks().await;
        seed_context(&ks, "ctx-a").await;
        let a = auth(Role::Admin, vec!["ctx-a"]);

        let (context, created) = resolve_target_context(&a, &ks, Some("ctx-a".into()), false)
            .await
            .map_err(|_| ())
            .expect("resolves");
        assert_eq!(context, "ctx-a");
        assert!(!created);
    }

    /// Requested context that doesn't exist, `create_context = true` →
    /// created inline, `context_created = true`.
    #[tokio::test]
    async fn resolve_creates_requested_context_inline() {
        let (_dir, _store, ks) = fresh_contexts_ks().await;
        let a = auth(Role::Admin, vec![]); // super-admin (create_context gate)

        let (context, created) = resolve_target_context(&a, &ks, Some("ctx-new".into()), true)
            .await
            .expect("resolves");
        assert_eq!(context, "ctx-new");
        assert!(created);
        assert!(
            crate::contexts::get_context(&ks, "ctx-new")
                .await
                .unwrap()
                .is_some(),
            "context must have been created"
        );
    }

    /// Omitted context + ambiguous inference → `ResolveContextError::Ambiguous`
    /// carrying the candidates (the transport renders them).
    #[tokio::test]
    async fn resolve_propagates_ambiguous_inference() {
        let (_dir, _store, ks) = fresh_contexts_ks().await;
        let a = auth(Role::Admin, vec!["ctx-x", "ctx-y"]);

        let err = resolve_target_context(&a, &ks, None, false)
            .await
            .err()
            .expect("ambiguous");
        match err {
            ResolveContextError::Ambiguous(amb) => {
                assert_eq!(
                    amb.candidates,
                    vec!["ctx-x".to_string(), "ctx-y".to_string()]
                );
            }
            ResolveContextError::Op(e) => panic!("expected Ambiguous, got Op({e:?})"),
        }
    }

    /// Requested missing context without `--create-context` → `Op(NotFound)`.
    #[tokio::test]
    async fn resolve_missing_context_without_create_is_op_not_found() {
        let (_dir, _store, ks) = fresh_contexts_ks().await;
        let a = auth(Role::Admin, vec!["ctx-absent"]);

        let err = resolve_target_context(&a, &ks, Some("ctx-absent".into()), false)
            .await
            .err()
            .expect("not found");
        assert!(
            matches!(err, ResolveContextError::Op(AppError::NotFound(_))),
            "expected Op(NotFound)",
        );
    }
}
