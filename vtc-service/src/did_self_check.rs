//! Does this VTC's published DID document let a wallet sign in?
//!
//! Wallet sign-in with a trigger link (`auth/oob/*`, sign-in trigger-link
//! contract C4 and C9) depends on two entries in the community's DID document,
//! not on anything this binary controls:
//!
//! - `TrustTaskHTTPS` at the Trust-Task base this VTC serves
//!   (`{public_url}/v1`, so `<base>/trust-tasks` is `POST /v1/trust-tasks`) —
//!   where the wallet sends `auth/oob/claim`, `identify` and `grant`;
//! - `SignInPortal` on the member portal's origin — what the wallet compares
//!   the page's origin against (VTI-LNK-102, VTI-LNK-105).
//!
//! When either is missing the wallet refuses the code ("This code can't be
//! used") and nothing on the VTC side notices: every request it would have
//! seen never arrives. The DID-hosting case that prompted this check
//! (`webvh.storm.ws`, minted from a template that lacked `SignInPortal`) failed
//! exactly that way. `VTCRest` is not checked: neither the portal nor the
//! wallet flow reads it.
//!
//! So the VTC resolves its own DID — at startup, and lazily with a
//! [`CACHE_TTL`] cache — and checks the document as **published**, which is
//! what a wallet sees, not the local mirror. Read-only, and advisory:
//!
//! - it never blocks or fails startup;
//! - a resolution failure is [`Outcome::Unknown`], never "missing" — a
//!   resolver blip must not hide wallet sign-in;
//! - a problem is logged once, as one warning naming what is missing, the
//!   JSON entries to add and the commands that publish them;
//! - the login pages get [`PublicView`] through `GET /v1/member/sign-in/config`
//!   — the service types missing from the public DID document, nothing else.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;
use tracing::{info, warn};

use crate::member_portal::oob;

/// How long a check result is reused before the next lazy refresh.
pub const CACHE_TTL: Duration = Duration::from_secs(300);

/// How long an "unknown" result is reused. Shorter, so a resolver that was
/// not ready at boot (or a blip) is retried soon rather than in five minutes.
pub const UNKNOWN_TTL: Duration = Duration::from_secs(30);

/// How long one resolution may take before the result is "unknown".
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long after boot the first check runs. A VTC that serves its own
/// `did.jsonl` answers its own resolution only once its listener is up.
pub const BOOT_DELAY: Duration = Duration::from_secs(5);

/// One service the published document lacks, or lists wrongly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingService {
    /// The service `type` (`TrustTaskHTTPS`, `SignInPortal`).
    pub service_type: &'static str,
    /// Why it fails, from the existing per-service checks.
    pub reason: String,
    /// The exact entry to publish.
    pub entry: Value,
}

/// The result of one check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The published document lists everything wallet sign-in needs.
    Ok,
    /// It does not; wallet sign-in cannot work until these are published.
    Missing(Vec<MissingService>),
    /// Could not tell: no DID or public URL configured, no resolver, or the
    /// DID did not resolve. Not a finding.
    Unknown(String),
}

/// What the login pages are told: the facts of the public DID document only.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PublicView {
    /// `ok`, `missing` or `unknown`.
    pub status: &'static str,
    /// The service types missing, when `status` is `missing`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<&'static str>,
}

impl Outcome {
    /// How long this result is reused before the next check.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        match self {
            Outcome::Unknown(_) => UNKNOWN_TTL,
            _ => CACHE_TTL,
        }
    }

    /// The public view of this outcome.
    #[must_use]
    pub fn public_view(&self) -> PublicView {
        match self {
            Outcome::Ok => PublicView {
                status: "ok",
                missing: Vec::new(),
            },
            Outcome::Missing(m) => PublicView {
                status: "missing",
                missing: m.iter().map(|s| s.service_type).collect(),
            },
            Outcome::Unknown(_) => PublicView {
                status: "unknown",
                missing: Vec::new(),
            },
        }
    }
}

/// Check a resolved document against what this VTC serves: the Trust-Task
/// base under `public_url` and the member portal's origin. Reuses the
/// portal's own notion of both (`member_portal::oob`), so this cannot disagree
/// with what the sign-in flow enforces.
#[must_use]
pub fn evaluate(doc: &Value, vtc_did: &str, public_url: &str) -> Outcome {
    let mut missing = Vec::new();
    if let Err(reason) = oob::check_trust_task_https(doc, vtc_did, public_url) {
        missing.push(MissingService {
            service_type: oob::TRUST_TASK_HTTPS_TYPE,
            reason,
            entry: oob::trust_task_https_service(vtc_did, public_url),
        });
    }
    if let Err(reason) = oob::check_sign_in_portal(doc, vtc_did, public_url) {
        missing.push(MissingService {
            service_type: "SignInPortal",
            reason,
            entry: oob::sign_in_portal_service(vtc_did, public_url),
        });
    }
    if missing.is_empty() {
        Outcome::Ok
    } else {
        Outcome::Missing(missing)
    }
}

/// The one warning an operator reads: what is missing, the JSON to add, and
/// how to publish it.
#[must_use]
pub fn warning_text(vtc_did: &str, missing: &[MissingService], serves_own_log: bool) -> String {
    let types = missing
        .iter()
        .map(|m| m.service_type)
        .collect::<Vec<_>>()
        .join(", ");
    let reasons = missing
        .iter()
        .map(|m| format!("  - {}: {}", m.service_type, m.reason))
        .collect::<Vec<_>>()
        .join("\n");
    let entries = missing
        .iter()
        .map(|m| format!("  {}", m.entry))
        .collect::<Vec<_>>()
        .join(",\n");
    let install = if serves_own_log {
        "then, because this VTC serves its own did.jsonl, fetch the new log \
         (`pnm did-mgmt dids get-log <did> --out did.jsonl`) and install it here with \
         `cnm did-log install --file did.jsonl`"
    } else {
        "then, if this VTC serves its own did.jsonl (a serverless DID), fetch the new log \
         (`pnm did-mgmt dids get-log <did> --out did.jsonl`) and install it here with \
         `cnm did-log install --file did.jsonl`; a DID host publishes it for you"
    };
    format!(
        "wallet sign-in will not work: this VTC's published DID document is missing {types}, \
         so wallets will refuse its sign-in codes (\"This code can't be used\").\n{reasons}\n\
         Add to the document's `service` array:\n{entries}\n\
         Fix: `pnm did-mgmt dids edit --did {vtc_did}` at the VTA that manages this DID, \
         {install}. See docs/03-vtc/community-lifecycle.md \"Changing the community's \
         transports after mint\". Passkey and other sign-in options keep working."
    )
}

#[derive(Debug)]
struct Cached {
    at: Instant,
    key: (String, String),
    outcome: Outcome,
}

/// The cached self-check. Shared through `AppState`; holds no lock across an
/// await (R1.3) — two concurrent refreshes both resolve, harmlessly.
#[derive(Debug, Default)]
pub struct DidSelfCheck {
    cached: Mutex<Option<Cached>>,
    /// The last outcome logged, so a problem is warned about once per change
    /// rather than every five minutes.
    last_logged: Mutex<Option<Outcome>>,
}

impl DidSelfCheck {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The current outcome, re-checking when the cache is older than
    /// [`CACHE_TTL`] or the configured DID / public URL changed.
    pub async fn current(&self, state: &crate::server::AppState) -> Outcome {
        let (vtc_did, public_url) = {
            let cfg = state.config.read().await;
            (cfg.vtc_did.clone(), cfg.public_url.clone())
        };
        let (Some(vtc_did), Some(public_url)) = (vtc_did, public_url) else {
            return Outcome::Unknown(
                "no VTC DID or public URL configured, so there is no portal origin to check".into(),
            );
        };
        let key = (vtc_did.clone(), public_url.clone());
        if let Some(c) = self.cached.lock().expect("self-check cache").as_ref()
            && c.key == key
            && c.at.elapsed() < c.outcome.ttl()
        {
            return c.outcome.clone();
        }
        let outcome = self.check(state, &vtc_did, &public_url).await;
        *self.cached.lock().expect("self-check cache") = Some(Cached {
            at: Instant::now(),
            key,
            outcome: outcome.clone(),
        });
        outcome
    }

    async fn check(
        &self,
        state: &crate::server::AppState,
        vtc_did: &str,
        public_url: &str,
    ) -> Outcome {
        let outcome = match state.did_resolver.as_ref() {
            None => Outcome::Unknown("no DID resolver".into()),
            Some(resolver) => {
                match tokio::time::timeout(RESOLVE_TIMEOUT, resolver.resolve(vtc_did)).await {
                    Err(_) => Outcome::Unknown("resolving the VTC DID timed out".into()),
                    Ok(Err(e)) => Outcome::Unknown(format!("the VTC DID did not resolve: {e}")),
                    Ok(Ok(resolved)) => match serde_json::to_value(&resolved.doc) {
                        Ok(doc) => evaluate(&doc, vtc_did, public_url),
                        Err(e) => Outcome::Unknown(format!("unreadable DID document: {e}")),
                    },
                }
            }
        };
        self.log_if_changed(state, vtc_did, &outcome).await;
        outcome
    }

    async fn log_if_changed(
        &self,
        state: &crate::server::AppState,
        vtc_did: &str,
        outcome: &Outcome,
    ) {
        {
            let mut last = self.last_logged.lock().expect("self-check log");
            if last.as_ref() == Some(outcome) {
                return;
            }
            *last = Some(outcome.clone());
        }
        match outcome {
            Outcome::Ok => info!(
                vtc_did,
                "DID self-check: the published document lists TrustTaskHTTPS and SignInPortal; \
                 wallet sign-in is available"
            ),
            Outcome::Missing(missing) => {
                let serves_own_log = {
                    let cfg = state.config.read().await.clone();
                    crate::transport_capability::local_did_document(&cfg)
                        .await
                        .is_some()
                };
                warn!(
                    vtc_did,
                    missing = ?missing.iter().map(|m| m.service_type).collect::<Vec<_>>(),
                    "{}",
                    warning_text(vtc_did, missing, serves_own_log)
                );
            }
            Outcome::Unknown(why) => info!(
                vtc_did,
                reason = %why,
                "DID self-check: could not check the published document for wallet sign-in; \
                 will retry"
            ),
        }
    }

    /// The boot check: once, shortly after start, off the startup path.
    pub fn spawn_at_boot(
        state: crate::server::AppState,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        tokio::spawn(async move {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(BOOT_DELAY) => {}
            }
            let _ = state.did_self_check.current(&state).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DID: &str = "did:webvh:QmX:vtc.example";
    const URL: &str = "https://vtc.example";

    fn doc(services: Value) -> Value {
        json!({ "id": DID, "service": services })
    }

    fn good() -> Value {
        doc(json!([
            oob::trust_task_https_service(DID, URL),
            oob::sign_in_portal_service(DID, URL),
        ]))
    }

    #[test]
    fn a_document_with_both_entries_passes() {
        assert_eq!(evaluate(&good(), DID, URL), Outcome::Ok);
        assert_eq!(
            evaluate(&good(), DID, URL).public_view(),
            PublicView {
                status: "ok",
                missing: vec![]
            }
        );
    }

    #[test]
    fn a_missing_sign_in_portal_is_named_with_its_entry() {
        let d = doc(json!([oob::trust_task_https_service(DID, URL)]));
        let Outcome::Missing(m) = evaluate(&d, DID, URL) else {
            panic!("expected missing");
        };
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].service_type, "SignInPortal");
        assert_eq!(
            m[0].entry,
            json!({
                "id": format!("{DID}#sign-in-portal"),
                "type": "SignInPortal",
                "serviceEndpoint": "https://vtc.example/members/",
            })
        );
    }

    #[test]
    fn a_sign_in_portal_on_another_origin_is_missing() {
        let d = doc(json!([
            oob::trust_task_https_service(DID, URL),
            { "id": "x", "type": "SignInPortal", "serviceEndpoint": "https://elsewhere.example/members/" },
        ]));
        assert_eq!(
            evaluate(&d, DID, URL).public_view().missing,
            vec!["SignInPortal"]
        );
    }

    #[test]
    fn a_trust_task_base_this_vtc_does_not_serve_is_missing() {
        // `{URL}` alone is not the base: `<base>/trust-tasks` would 404.
        let d = doc(json!([
            { "id": "t", "type": "TrustTaskHTTPS", "serviceEndpoint": URL },
            oob::sign_in_portal_service(DID, URL),
        ]));
        assert_eq!(
            evaluate(&d, DID, URL).public_view().missing,
            vec!["TrustTaskHTTPS"]
        );
    }

    #[test]
    fn an_empty_document_lists_both_in_order() {
        let view = evaluate(&doc(json!([])), DID, URL).public_view();
        assert_eq!(view.status, "missing");
        assert_eq!(view.missing, vec!["TrustTaskHTTPS", "SignInPortal"]);
    }

    #[test]
    fn unknown_is_retried_sooner_than_a_finding() {
        assert_eq!(Outcome::Ok.ttl(), CACHE_TTL);
        assert_eq!(Outcome::Missing(vec![]).ttl(), CACHE_TTL);
        assert_eq!(Outcome::Unknown(String::new()).ttl(), UNKNOWN_TTL);
    }

    #[test]
    fn unknown_is_not_missing_and_says_nothing_more() {
        let view = Outcome::Unknown("resolver down: secret detail".into()).public_view();
        assert_eq!(
            serde_json::to_value(&view).unwrap(),
            json!({ "status": "unknown" })
        );
    }

    #[test]
    fn the_warning_names_what_is_missing_the_json_and_the_fix() {
        let Outcome::Missing(m) = evaluate(&doc(json!([])), DID, URL) else {
            panic!()
        };
        let text = warning_text(DID, &m, true);
        assert!(text.contains("TrustTaskHTTPS, SignInPortal"), "{text}");
        assert!(text.contains("\"type\":\"SignInPortal\""), "{text}");
        assert!(
            text.contains("\"serviceEndpoint\":\"https://vtc.example/v1\""),
            "{text}"
        );
        assert!(
            text.contains(&format!("pnm did-mgmt dids edit --did {DID}")),
            "{text}"
        );
        assert!(text.contains("cnm did-log install"), "{text}");
        assert!(text.contains("community-lifecycle.md"), "{text}");
    }
}
