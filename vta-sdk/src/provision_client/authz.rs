//! The first round-trip that asks the **VTA** anything.
//!
//! # Why this module exists
//!
//! Two of the three transport legs finish their "authenticate" step without
//! ever contacting the VTA. TSP seals to the VTA's mediator — no challenge, no
//! token. DIDComm's `connect` sets the client's ACL *at the mediator*, which is
//! a different ACL to the VTA's. Only the REST leg runs the
//! challenge/authenticate ceremony, and only that ceremony reads
//! `check_acl_full`.
//!
//! So before this module, a setup DID with no grant on the VTA it was pointed
//! at produced a **green** row and carried on. That is what happened on
//! 2026-08-31: an operator ran OpenVTC's wizard against the wrong VTA, with no
//! ACL entry there and a VTA too old to serve the provisioning version the
//! client dispatches. Both faults were invisible until the mint call failed,
//! and the failure it produced named neither of them.
//!
//! [`verify_authorization`] asks `trust-task-discovery/0.1` — any authenticated
//! caller, answered from the VTA's own dispatch table — and so settles three
//! questions in one call, before anything is minted:
//!
//! | question | how the answer arrives |
//! |---|---|
//! | is this DID granted on this VTA? | `permissionDenied` if not |
//! | is this the VTA I meant? | the reply is *that* VTA's task list |
//! | do we agree on a version? | the URI we will dispatch is in the list, or is not |
//!
//! # Why it is mostly not a gate
//!
//! `trust-task-discovery/0.1` is published and canonical, but it is not
//! ancient. A VTA that does not serve it is not a VTA we should refuse to
//! provision — that would turn a diagnostic into an outage, which is the one
//! way this module could be worse than not existing.
//!
//! So exactly two findings stop the run, and both name a fix:
//!
//! - `permissionDenied` — this DID has no grant on this VTA;
//! - the URI we are about to dispatch is absent from a list we successfully
//!   read.
//!
//! Every other outcome — discovery unsupported, a timeout, a transport error —
//! is `Skipped` and the provisioning call remains the thing that decides.

use tokio::sync::mpsc::UnboundedSender;

use super::diagnostics::{DiagCheck, DiagStatus};
use super::event::VtaEvent;
use crate::client::VtaClient;
use crate::error::VtaError;

/// Ask the VTA what it serves, and check we are allowed to ask.
///
/// `required_task` is the Type URI this run will go on to dispatch, when there
/// is one. Supplying it turns the probe from "can I talk to this VTA" into "can
/// I complete this run against this VTA", which is the question the operator
/// actually has.
///
/// Emits the [`DiagCheck::VerifyAuthorization`] row. Returns `Err` with an
/// operator-facing message on a failure the run cannot recover from; `Ok(())`
/// covers both a clean probe and a VTA that does not serve discovery.
pub(super) async fn verify_authorization(
    client: &VtaClient,
    setup_did: &str,
    vta_did: &str,
    required_task: Option<&str>,
    tx: &UnboundedSender<VtaEvent>,
) -> Result<(), String> {
    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::VerifyAuthorization));

    let served = match client.supported_trust_tasks(&["*"]).await {
        Ok(resp) => resp.supported_types,

        // No grant for this DID on this VTA. The two things worth naming are
        // the DID the grant has to be for and the VTA it has to be on, because
        // the operator who has run `pnm acl create` already will have run it
        // for one of those against the other.
        Err(VtaError::Forbidden(detail)) => {
            // Plain text, no markdown: this string is rendered verbatim into a
            // terminal checklist row, where `**that**` is four stray asterisks.
            let msg = format!(
                "{setup_did} is not authorized on {vta_did}. Run \
                 `pnm acl create --did {setup_did} --role admin` against that VTA — an \
                 ACL grant is per-VTA and one made on a different VTA does not carry — \
                 and confirm {vta_did} is the VTA you meant. ({detail})"
            );
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::VerifyAuthorization,
                DiagStatus::Failed(msg.clone()),
            ));
            return Err(msg);
        }

        // The VTA does not serve discovery. Not a reason to refuse to
        // provision — see the module docs.
        Err(VtaError::UnsupportedTaskType { .. }) => {
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::VerifyAuthorization,
                DiagStatus::Skipped(
                    "this VTA does not serve trust-task-discovery/0.1, so its task list \
                     could not be checked in advance"
                        .into(),
                ),
            ));
            return Ok(());
        }

        // Anything else and we simply did not learn the answer. Stopping here
        // would mean a probe that cannot reach the VTA blocks a provisioning
        // call that might have worked — a diagnostic promoted into an outage,
        // which is the one way this module could be worse than not existing.
        // Only the two findings that name a concrete fix are terminal: no grant
        // (above) and a version the VTA does not serve (below).
        Err(e) => {
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::VerifyAuthorization,
                DiagStatus::Skipped(format!("could not ask {vta_did} what it serves: {e}")),
            ));
            return Ok(());
        }
    };

    if let Some(required) = required_task
        && !served.iter().any(|uri| uri == required)
    {
        let msg = version_skew_message(required, &served, vta_did);
        let _ = tx.send(VtaEvent::CheckDone(
            DiagCheck::VerifyAuthorization,
            DiagStatus::Failed(msg.clone()),
        ));
        return Err(msg);
    }

    let _ = tx.send(VtaEvent::CheckDone(
        DiagCheck::VerifyAuthorization,
        DiagStatus::Ok(format!(
            "{setup_did} is authorized on {vta_did}; it serves {} task types",
            served.len()
        )),
    ));
    Ok(())
}

/// The family of a Trust Task Type URI: everything before its trailing version
/// segment. The version is always the last path segment (SPEC §3.1).
fn task_family(type_uri: &str) -> Option<&str> {
    type_uri.rsplit_once('/').map(|(family, _version)| family)
}

/// Explain a task the VTA does not serve, in the terms that decide what to do
/// about it.
///
/// The distinction is the whole message. A VTA serving **another version of the
/// same family** is a version skew — one side is behind, and the version tells
/// you which. A VTA serving **nothing in the family** is a different animal: a
/// build without the feature, or the wrong VTA entirely.
fn version_skew_message(required: &str, served: &[String], vta_did: &str) -> String {
    let family = task_family(required);
    let mut siblings: Vec<&str> = served
        .iter()
        .map(String::as_str)
        .filter(|uri| family.is_some() && task_family(uri) == family)
        .collect();
    siblings.sort_unstable();

    if siblings.is_empty() {
        return format!(
            "{vta_did} does not serve {required}, or anything else in that family. \
             Either it is built without the feature that provides it, or it is not the \
             VTA you meant to provision against."
        );
    }

    format!(
        "{vta_did} serves {} but this client dispatches {required}. That is a version \
         skew, not a broken VTA: upgrade the VTA to a release that serves {required}, \
         or point this client at one that does.",
        siblings.join(", "),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const V0_3: &str = "https://trusttasks.org/spec/provision/integration/0.3";
    const V0_2: &str = "https://trusttasks.org/spec/provision/integration/0.2";

    /// The message that would have saved the 2026-08-31 incident.
    ///
    /// The VTA served `provision/integration/0.2`; the client dispatched
    /// `0.3`; all the operator saw was `unsupported type: …/0.3`, which reads
    /// as "provisioning is broken" rather than "these two are different ages".
    #[test]
    fn a_sibling_version_is_named_as_a_skew() {
        let msg = version_skew_message(V0_3, &[V0_2.to_string()], "did:webvh:example");
        assert!(
            msg.contains(V0_2),
            "must name what the VTA does serve: {msg}"
        );
        assert!(msg.contains(V0_3), "must name what we asked for: {msg}");
        assert!(msg.contains("version skew"), "{msg}");
    }

    /// A family the VTA does not carry at all is a different diagnosis, and
    /// must not be reported as a skew — there is no version to upgrade to.
    #[test]
    fn an_absent_family_is_not_reported_as_a_skew() {
        let served = vec!["https://trusttasks.org/spec/vault/list/0.1".to_string()];
        let msg = version_skew_message(V0_3, &served, "did:webvh:example");
        assert!(!msg.contains("version skew"), "{msg}");
        assert!(msg.contains("not the VTA you meant"), "{msg}");
    }

    /// A sibling in a *different* family must not be offered as the version to
    /// migrate onto — that would send a client at a task that cannot serve it.
    ///
    /// On a synthetic authority, all three of them. The fixture needs a URI
    /// that shares a long prefix with the family without being in it, and no
    /// such task is published under `provision/` — and `trust_task_manifest`'s
    /// census reads a `trusttasks.org/spec/` literal anywhere under
    /// `vta-sdk/src` as an assertion that the registry serves it. Its own
    /// advice for a URI the registry does not serve is "bind an authority we
    /// control", which is what this is.
    #[test]
    fn only_same_family_versions_are_offered() {
        const WANT: &str = "https://tasks.example/spec/provision/integration/0.3";
        const HAVE: &str = "https://tasks.example/spec/provision/integration/0.2";
        const COUSIN: &str = "https://tasks.example/spec/provision/other/0.9";

        let served = vec![COUSIN.to_string(), HAVE.to_string()];
        let msg = version_skew_message(WANT, &served, "did:webvh:example");
        assert!(msg.contains(HAVE), "{msg}");
        assert!(
            !msg.contains(COUSIN),
            "a neighbouring family is not a version of this one: {msg}"
        );
    }

    #[test]
    fn task_family_strips_only_the_version_segment() {
        assert_eq!(
            task_family(V0_3),
            Some("https://trusttasks.org/spec/provision/integration")
        );
        assert_eq!(task_family("no-slashes"), None);
    }
}
