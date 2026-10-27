//! `cnm members …` — an administrator admitting a DID without a join request.
//!
//! Not `cnm member`, which is a member's verbs on their own membership. These
//! are the console's *Add a member* and *Make this a membership*:
//!
//! - `admit` (`vtc/members/admit/0.1`) — a DID with no access-control entry is
//!   admitted at a community role: the entry, the member record and the
//!   membership credentials, as a completed join leaves them.
//! - `make-membership` (`vtc/members/make-membership/0.1`) — an entry with no
//!   member record (a bootstrap administrator, typically) gets the record and
//!   the credentials at the role it already holds.
//!
//! Both take `vtc.members.manage`, and are decided by the community's
//! `admission` policy, which may refer them to another holder of it: the
//! operation is then parked in the action list and completes itself on
//! approval. They travel as `cnm access` does
//! ([`vtc_target::connect_for_tasks`]), signed with this profile's own key.

use clap::Subcommand;
use vta_cli_common::render::{DIM, GREEN, RESET, bin_name, is_json_output, print_json};
use vta_sdk::session::TransportChoice;
use vtc_client::VtcError;
use vtc_client::members::{AdmitRequest, admit, make_membership};

use crate::vtc::{self as vtc_target, Connected, VtcTarget};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Subcommand)]
pub enum MembersCommands {
    /// Admit a DID as a member without a join request (*Add a member*).
    ///
    /// The DID must hold no access-control entry (an `application` entry —
    /// git rights held by a non-member — is admitted and keeps its grants).
    /// For an entry with no membership, use `make-membership`.
    Admit {
        /// The DID to admit.
        subject: String,
        /// The community role: member, moderator, issuer, or custom:<name>.
        /// Never admin: admit as a member, then `access change-role`.
        #[arg(long, default_value = "member")]
        role: String,
        /// A label for the new entry.
        #[arg(long)]
        label: Option<String>,
        /// Why, for the audit trail and any approvers.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Make an existing access-control entry with no member record a
    /// membership, at the role it already holds (*Make this a membership*).
    MakeMembership {
        /// The DID whose entry becomes a membership.
        subject: String,
        /// Why, for the audit trail and any approvers.
        #[arg(long)]
        reason: Option<String>,
    },
}

/// Run one `cnm members` command. The session is closed on every path out.
pub async fn run(
    command: MembersCommands,
    keyring_key: &str,
    target: &VtcTarget,
    transport: TransportChoice,
) -> CliResult {
    let vtc = vtc_target::connect_for_tasks(keyring_key, target, transport).await?;
    let outcome = run_command(command, &vtc, keyring_key).await;
    vtc.client.shutdown().await;
    outcome
}

async fn run_command(command: MembersCommands, vtc: &Connected, keyring_key: &str) -> CliResult {
    let key = crate::access::signing_key(keyring_key)?;
    match command {
        MembersCommands::Admit {
            subject,
            role,
            label,
            reason,
        } => {
            let req = AdmitRequest {
                subject: subject.clone(),
                role: role.clone(),
                label,
                reason,
            };
            let admitted = vtc
                .client
                .members_admit(&req, &key)
                .await
                .map_err(|e| admission_error(vtc, e, &subject, Some(&role)))?;
            report(
                &admitted,
                &admitted.subject,
                &admitted.role,
                admitted.approval,
            )
        }
        MembersCommands::MakeMembership { subject, reason } => {
            let admitted = vtc
                .client
                .members_make_membership(&subject, reason.as_deref(), &key)
                .await
                .map_err(|e| admission_error(vtc, e, &subject, None))?;
            report(
                &admitted,
                &admitted.subject,
                &admitted.role,
                admitted.approval.into_admit(),
            )
        }
    }
}

/// The two tasks' `Approval` enums are distinct generated types with one set
/// of values; read the make-membership one as admit's for printing.
trait IntoAdmitApproval {
    fn into_admit(self) -> admit::Approval;
}

impl IntoAdmitApproval for make_membership::Approval {
    fn into_admit(self) -> admit::Approval {
        match self {
            Self::PolicyAllowed => admit::Approval::PolicyAllowed,
            Self::Approved => admit::Approval::Approved,
            Self::Waived => admit::Approval::Waived,
            // `#[non_exhaustive]`: a value a later specification adds prints
            // as the closest one — the admission happened either way.
            _ => admit::Approval::Approved,
        }
    }
}

fn report(
    reply: &impl serde::Serialize,
    subject: &str,
    role: &str,
    approval: admit::Approval,
) -> CliResult {
    if is_json_output() {
        print_json(reply)?;
        return Ok(());
    }
    let how = match approval {
        admit::Approval::Waived => " (single-administrator mode waived the approval)",
        admit::Approval::Approved => " after approval",
        _ => "",
    };
    println!("{GREEN}admitted{RESET} {subject} as {role}{how}");
    println!("  {DIM}the membership credential and role credential were issued{RESET}");
    Ok(())
}

/// The declared code a refusal carries, if it is one of these two tasks'.
fn declared_code(err: &VtcError) -> Option<&'static str> {
    let text = match err {
        VtcError::Http { body, .. } => body.as_str(),
        VtcError::Refused { document } => document.as_str(),
        VtcError::NotFound { code, .. } => code.as_str(),
        _ => return None,
    };
    admit::ERROR_CODES
        .iter()
        .chain(make_membership::ERROR_CODES)
        .map(|d| d.code)
        .find(|c| text.contains(&format!("\"{c}\"")) || text == *c)
}

/// The command the operator meant, when a refusal says they reached for the
/// wrong one (root CLAUDE.md, "Operator errors should suggest the fix").
fn suggested_fix(code: &str, subject: &str, role: Option<&str>) -> Option<String> {
    let bin = bin_name();
    let admit_cmd = format!("{bin} members admit {subject} --role member");
    Some(match code {
        c if c == admit::error_codes::HAS_ENTRY.code => format!(
            "{subject} already holds an access-control entry. To make it a membership at the \
             role it holds, run:\n  {bin} members make-membership {subject}"
        ),
        c if c == make_membership::error_codes::NO_ENTRY.code => format!(
            "{subject} holds no access-control entry, so there is nothing to make a membership \
             of. To admit them, run:\n  {admit_cmd}"
        ),
        c if c == make_membership::error_codes::APPLICATION_ENTRY.code => format!(
            "{subject}'s entry is an application entry (git rights held by a non-member). To \
             admit them, keeping those rights, run:\n  {admit_cmd}"
        ),
        c if c == make_membership::error_codes::REMOVED_MEMBER.code => format!(
            "{subject} was a member and was removed. To re-admit them, remove the entry and \
             admit them, which the admission policy decides:\n  {bin} access revoke {subject}\n  \
             {admit_cmd}"
        ),
        c if c == admit::error_codes::ROLE_NOT_PERMITTED.code && role == Some("admin") => format!(
            "a direct admission never seats admin. Admit them as a member, then promote them \
             (which takes its own gesture and another administrator's consent):\n  \
             {admit_cmd}\n  {bin} access change-role {subject} --from member --to admin"
        ),
        _ => return None,
    })
}

/// What to tell the operator when the VTC refuses — or parks — an admission.
fn admission_error(
    vtc: &Connected,
    err: VtcError,
    subject: &str,
    role: Option<&str>,
) -> Box<dyn std::error::Error> {
    if let VtcError::Parked { action_id, message } = &err {
        return format!(
            "{message}\n  Nothing more to send: it runs when the approvals land. Follow it with \
             `{bin} actions show {action_id}`, or withdraw it with `{bin} actions cancel \
             {action_id}`.",
            bin = bin_name()
        )
        .into();
    }
    let text = err.to_string();
    if let Some(fix) = declared_code(&err).and_then(|c| suggested_fix(c, subject, role)) {
        return format!("{fix}\n({text})").into();
    }
    if text.contains("stepUpRequest") || text.contains("passkey gesture") {
        return format!(
            "the VTC needs a passkey gesture from {} before it admits {subject}. Approve it in \
             the admin console, then run the same command again.\n({text})",
            vtc.client_did
        )
        .into();
    }
    format!("the VTC refused {}: {text}", vtc.client_did).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(code: &str) -> VtcError {
        VtcError::Refused {
            document: serde_json::json!({
                "payload": { "code": code, "message": "no" },
            })
            .to_string(),
        }
    }

    /// A refusal that means "the other command" prints that command verbatim.
    #[test]
    fn a_wrong_command_refusal_names_the_right_one() {
        let s = "did:key:zSubject";
        let code = declared_code(&refused(admit::error_codes::HAS_ENTRY.code)).unwrap();
        assert!(
            suggested_fix(code, s, Some("member"))
                .unwrap()
                .contains(&format!("members make-membership {s}"))
        );
        let code = declared_code(&refused(make_membership::error_codes::NO_ENTRY.code)).unwrap();
        assert!(
            suggested_fix(code, s, None)
                .unwrap()
                .contains(&format!("members admit {s} --role member"))
        );
        let code = declared_code(&refused(admit::error_codes::ROLE_NOT_PERMITTED.code)).unwrap();
        let fix = suggested_fix(code, s, Some("admin")).unwrap();
        assert!(fix.contains(&format!("access change-role {s} --from member --to admin")));
        // An unknown role has no other command to suggest.
        assert!(suggested_fix(code, s, Some("overlord")).is_none());
    }

    /// `alreadyMember` is two tasks' code under one local part: each is
    /// matched whole, never by its suffix.
    #[test]
    fn codes_are_matched_whole() {
        assert_eq!(
            declared_code(&refused(make_membership::error_codes::ALREADY_MEMBER.code)),
            Some(make_membership::error_codes::ALREADY_MEMBER.code)
        );
        assert_eq!(declared_code(&refused("alreadyMember")), None);
    }
}
