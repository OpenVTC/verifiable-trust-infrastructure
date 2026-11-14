//! The routing table for the community's own Trust Task families: one
//! [`AsyncDispatcher`] every family registers its handlers on, keyed on each
//! task's generated payload type (#2579).
//!
//! A family module exposes `register(Routes) -> Routes` and nothing else the
//! router reads: no `URIS` list beside a `match`, and no arm of
//! [`super::dispatch_typed`] per family. The URI a handler answers is the
//! generated type's `TYPE_URI`, so a task cannot be served under a URI no
//! pinned specification publishes, and [`served_uris`] *is* the routing table
//! rather than a list kept in step with it. The `rooms/*` and `git-ns/*`
//! families keep their own dispatchers (their handlers take their own
//! contexts); [`super::dispatch_typed`] asks those first and this one after.
//!
//! # The document stays as received
//!
//! A handler is registered on [`Received<P>`], not on `P`. The dispatcher
//! routes by `P`'s URI and applies `P`'s declared specification policy, but
//! the payload reaches the handler as the JSON that arrived, because:
//!
//! - every handler reads that JSON against the published schema *before*
//!   parsing it (`parse_spec_payload`, root `CLAUDE.md`: some generated
//!   constructors normalise what they parse, so only the JSON shows what was
//!   sent);
//! - the administrative handlers resolve the signer's authority **first** and
//!   read the payload only after, so a stranger learns nothing about the
//!   shape it sent — an order a typed downcast in the router would reverse.
//!
//! [`Received<P>`] deserializes from any JSON value, so the router's downcast
//! cannot fail and a malformed payload is still refused by the handler, in
//! the words it always used.

use std::future::Future;
use std::marker::PhantomData;

use serde_json::Value;
use trust_tasks_rs::{AsyncDispatcher, Payload, TrustTask};

use super::JoinAuthCtx;
use super::helpers::TrustTaskOutcome;
use crate::server::AppState;

/// A task's payload exactly as it arrived, routed by the generated type `P`.
///
/// Carries `P`'s Type URI and declared document requirements (so the router
/// keys and polices it as `P`), and the received JSON untouched.
pub(crate) struct Received<P> {
    raw: Value,
    _payload: PhantomData<fn() -> P>,
}

impl<P> serde::Serialize for Received<P> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.raw.serialize(s)
    }
}

impl<'de, P> serde::Deserialize<'de> for Received<P> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self {
            raw: Value::deserialize(d)?,
            _payload: PhantomData,
        })
    }
}

impl<P: Payload> Payload for Received<P> {
    const TYPE_URI: &'static str = P::TYPE_URI;
    const IS_BEARER: bool = P::IS_BEARER;
    const IS_PROOF_REQUIRED: bool = P::IS_PROOF_REQUIRED;
    const IS_RECIPIENT_REQUIRED: bool = P::IS_RECIPIENT_REQUIRED;
    const IS_ISSUED_AT_REQUIRED: bool = P::IS_ISSUED_AT_REQUIRED;
    const MAX_DOCUMENT_BYTES: Option<usize> = P::MAX_DOCUMENT_BYTES;
    const PAYLOAD_SCHEMA: Option<&'static str> = P::PAYLOAD_SCHEMA;
}

/// The received document back in the untyped form every handler takes.
fn untyped<P>(doc: TrustTask<Received<P>>) -> TrustTask<Value> {
    let TrustTask {
        id,
        thread_id,
        parent_thread_id,
        ceremony,
        type_uri,
        issuer,
        recipient,
        issued_at,
        expires_at,
        payload,
        context,
        proof,
        extra,
    } = doc;
    TrustTask {
        id,
        thread_id,
        parent_thread_id,
        ceremony,
        type_uri,
        issuer,
        recipient,
        issued_at,
        expires_at,
        payload: payload.raw,
        context,
        proof,
        extra,
    }
}

/// What a handler receives beside its document: the service, and how the
/// document arrived.
#[derive(Clone)]
pub(crate) struct TaskCtx {
    pub(crate) state: AppState,
    pub(crate) arrival: JoinAuthCtx,
}

/// The routing table under construction. Each family's `register` adds its
/// handlers with [`Routes::on`] (usually through the [`on!`] macro).
pub(crate) struct Routes {
    dispatcher: AsyncDispatcher<TaskCtx, TrustTaskOutcome>,
    /// Every registration's URI, in order, duplicates kept — so a test can
    /// refuse a URI two handlers claim (the dispatcher would silently keep
    /// the later one).
    registered: Vec<&'static str>,
}

impl Routes {
    fn new() -> Self {
        Self {
            dispatcher: AsyncDispatcher::new(),
            registered: Vec::new(),
        }
    }

    /// Serve `P`'s Type URI with `handler`.
    pub(crate) fn on<P, F, Fut>(mut self, handler: F) -> Self
    where
        P: Payload + 'static,
        F: Fn(TaskCtx, TrustTask<Value>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = TrustTaskOutcome> + Send + 'static,
    {
        self.registered.push(P::TYPE_URI);
        self.dispatcher = self
            .dispatcher
            .on_async(move |doc: TrustTask<Received<P>>, ctx: TaskCtx| handler(ctx, untyped(doc)));
        self
    }
}

/// Register a handler for a generated payload type.
///
/// `on!(routes, P => handle)` calls `handle(state, ctx, doc)`; the closure
/// form names the three (`_` for one a handler does not take) for a handler
/// with another shape:
///
/// ```ignore
/// on!(routes, list::v0_4::Payload => |state, ctx, doc| handle_list(state, ctx, doc, true))
/// ```
macro_rules! on {
    ($routes:expr, $payload:ty => |$state:pat_param, $ctx:pat_param, $doc:pat_param| $body:expr) => {
        $routes.on::<$payload, _, _>(
            |task: $crate::trust_tasks::routing::TaskCtx,
             doc: ::trust_tasks_rs::TrustTask<::serde_json::Value>| async move {
                let $state = &task.state;
                let $ctx = &task.arrival;
                let $doc = doc;
                $body.await
            },
        )
    };
    ($routes:expr, $payload:ty => $handler:path) => {
        $crate::trust_tasks::routing::on!($routes, $payload => |state, ctx, doc| $handler(state, ctx, doc))
    };
}
pub(crate) use on;

/// The table, built once from every family's `register`.
static TASKS: std::sync::LazyLock<Routes> = std::sync::LazyLock::new(build);

fn build() -> Routes {
    use super::*;
    let routes = Routes::new();
    let routes = join_tasks::register(routes);
    let routes = wallet_session_tasks::register(routes);
    let routes = member_admin_tasks::register(routes);
    let routes = credential_exchange::register(routes);
    let routes = notification_tasks::register(routes);
    let routes = vetting_tasks::register(routes);
    #[cfg(feature = "vetting-pcs")]
    let routes = hidden_vetting_tasks::register(routes);
    let routes = backup_tasks::register(routes);
    let routes = admin_tasks::register(routes);
    let routes = oob_tasks::register(routes);
    let routes = auth_tasks::register(routes);
    let routes = install_tasks::register(routes);
    let routes = recognise_tasks::register(routes);
    #[cfg(feature = "website")]
    let routes = website_tasks::register(routes);
    let routes = admin_passkey_tasks::register(routes);
    let routes = whoami_tasks::register(routes);
    let routes = admin_session_tasks::register(routes);
    let routes = signing_key_tasks::register(routes);
    let routes = surface_tasks::register(routes);
    let routes = policy_tasks::register(routes);
    let routes = storage_tasks::register(routes);
    let routes = oid4vp_tasks::register(routes);
    let routes = directory_tasks::register(routes);
    let routes = group_tasks::register(routes);
    let routes = board_tasks::register(routes);
    let routes = badge_tasks::register(routes);
    let routes = community_room_tasks::register(routes);
    let routes = room_admin_tasks::register(routes);
    let routes = role_tasks::register(routes);
    let routes = community_tasks::register(routes);
    let routes = step_up_passkey_tasks::register(routes);
    let routes = step_up_handoff_tasks::register(routes);
    let routes = step_up_approver_tasks::register(routes);
    #[cfg(feature = "voting")]
    let routes = election_tasks::register(routes);
    let routes = network_tasks::register(routes);
    let routes = capability_module_tasks::register(routes);
    let routes = admission_tasks::register(routes);
    let routes = member_tasks::register(routes);
    let routes = personhood_tasks::register(routes);
    let routes = config_tasks::register(routes);
    let routes = acl_tasks::register(routes);
    let routes = member_role_tasks::register(routes);
    let routes = step_up_response_tasks::register(routes);
    let routes = action_tasks::register(routes);
    event_tasks::register(routes)
}

/// Does this table serve `type_uri` (in routing form)?
pub(crate) fn serves(type_uri: &str) -> bool {
    TASKS.dispatcher.registered_uris().contains(&type_uri)
}

/// Every URI this table serves, sorted.
pub(crate) fn served_uris() -> Vec<&'static str> {
    TASKS.dispatcher.registered_uris()
}

/// Every registration's URI, duplicates kept, for the census below.
#[cfg(test)]
pub(crate) fn registrations() -> &'static [&'static str] {
    &TASKS.registered
}

/// Run the handler registered for `doc`'s URI. Only called for a URI
/// [`serves`] names.
pub(crate) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let task = TaskCtx {
        state: state.clone(),
        arrival: ctx.clone(),
    };
    match TASKS
        .dispatcher
        .dispatch_or_reject(doc, task, format!("urn:uuid:{}", uuid::Uuid::new_v4()))
        .await
    {
        Ok(outcome) => outcome,
        // Only the document policy the spine has already applied can refuse
        // here ([`Received`] accepts any payload).
        Err(err_doc) => super::helpers::error_response(err_doc),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dispatcher keeps the later of two registrations for one URI, so
    /// which family answered would depend on registration order. None may.
    #[test]
    fn no_two_handlers_serve_one_uri() {
        let mut seen = std::collections::BTreeSet::new();
        let dupes: Vec<&str> = registrations()
            .iter()
            .copied()
            .filter(|u| !seen.insert(*u))
            .collect();
        assert!(dupes.is_empty(), "registered twice: {dupes:?}");
    }

    /// A registration's URI is what the dispatcher answers — no fragment or
    /// casing makes the census and the router disagree.
    #[test]
    fn every_registration_is_served() {
        for uri in registrations() {
            assert!(serves(uri), "{uri} is registered but not served");
        }
        assert_eq!(registrations().len(), served_uris().len());
    }

    /// Neither of the other two dispatchers serves a URI registered here:
    /// [`super::super::dispatch_typed`] asks them first, so one would shadow
    /// this table without a word.
    #[test]
    fn no_uri_is_also_a_rooms_or_git_ns_task() {
        for uri in served_uris() {
            assert!(!crate::rooms::handlers::serves(uri), "{uri}: also rooms/*");
            assert!(!crate::git_ns::tasks::serves(uri), "{uri}: also git-ns/*");
        }
    }
}
