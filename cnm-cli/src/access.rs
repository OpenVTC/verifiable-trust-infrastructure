//! `cnm access …` — the community's own access-control list, on its VTC.
//!
//! Not `cnm acl`, which administers the community's **VTA**. This is the VTC's
//! ACL: who may administer the community, moderate it, or act in its contexts
//! — the list the admin console shows under *Access control*.
//!
//! Every verb is a canonical `acl/*` Trust Task, signed with this profile's own
//! key and sent through [`vtc_client::VtcClient`]'s document path, so the same
//! command works over whichever transport the client was built for. The VTC
//! authorizes each from the signer's own ACL entry at the moment it runs.

use chrono::{DateTime, Utc};
use clap::Subcommand;
use serde_json::Value;
use vta_cli_common::render::{DIM, GREEN, RESET, bin_name, is_json_output, print_json};
use vtc_client::VtcError;
use vtc_client::acl::{AclGrant, AclListFilter, AclUpdate};

use crate::vtc::{self, Connected, VtcTarget};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Subcommand)]
pub enum AccessCommands {
    /// List the entries you may see.
    List {
        /// Only entries with this role.
        #[arg(long)]
        role: Option<String>,
        /// Only entries touching this scope (context).
        #[arg(long)]
        scope: Option<String>,
        /// How `--scope` reads the hierarchy: acting-in (default), subtree, any.
        #[arg(long, requires = "scope")]
        direction: Option<String>,
        /// Only subjects starting with this prefix.
        #[arg(long)]
        subject_prefix: Option<String>,
    },
    /// Show one entry.
    Show {
        /// The subject DID.
        subject: String,
    },
    /// Write the entry a subject should hold (create, or restate at its
    /// current role).
    Grant {
        /// The subject DID.
        subject: String,
        /// The role: admin, initiator, moderator, member or custom:<name>.
        #[arg(long)]
        role: String,
        /// Scopes (contexts), comma-separated. None for an admin means
        /// community-wide, which needs another administrator's consent.
        #[arg(long, value_delimiter = ',')]
        scopes: Vec<String>,
        /// A human-readable label.
        #[arg(long)]
        label: Option<String>,
        /// Expire the entry after this long: N[s|m|h|d|w].
        #[arg(long)]
        expires: Option<String>,
        /// Why, recorded with the change.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Amend an existing entry's label, scopes or expiry. Never its role.
    Update {
        /// The subject DID.
        subject: String,
        /// The whole intended scope set, comma-separated. Dropping a scope the
        /// entry holds is refused — use `revoke --scopes`.
        #[arg(long, value_delimiter = ',')]
        scopes: Option<Vec<String>>,
        /// Set the label.
        #[arg(long, conflicts_with = "clear_label")]
        label: Option<String>,
        /// Remove the label.
        #[arg(long)]
        clear_label: bool,
        /// Expire the entry after this long from now: N[s|m|h|d|w].
        #[arg(long, conflicts_with = "permanent")]
        expires: Option<String>,
        /// Remove the expiry, making the entry permanent.
        #[arg(long)]
        permanent: bool,
        /// Why, recorded with the change.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Move a subject between roles; `--from` must be its current role.
    ChangeRole {
        /// The subject DID.
        subject: String,
        /// The role it holds now.
        #[arg(long = "from")]
        from_role: String,
        /// The role to move it to.
        #[arg(long = "to")]
        to_role: String,
        /// Why, recorded with the change.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Remove a subject's entry, or only some of its scopes.
    Revoke {
        /// The subject DID.
        subject: String,
        /// Remove only these scopes, comma-separated; the entry stays.
        #[arg(long, value_delimiter = ',')]
        scopes: Option<Vec<String>>,
        /// Why, recorded with the change.
        #[arg(long)]
        reason: Option<String>,
    },
}

pub async fn run(command: AccessCommands, keyring_key: &str, target: &VtcTarget) -> CliResult {
    let vtc = vtc::connect(keyring_key, target).await?;
    let fail = |e: VtcError| access_error(&vtc, e);
    match command {
        AccessCommands::List {
            role,
            scope,
            direction,
            subject_prefix,
        } => {
            let filter = AclListFilter {
                role,
                scope,
                direction,
                subject_prefix,
                ..Default::default()
            };
            let entries = vtc.client.acl_list_all(&filter).await.map_err(fail)?;
            let values: Vec<Value> = entries
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<_, _>>()?;
            if is_json_output() {
                print_json(&values)?;
            } else if values.is_empty() {
                println!("{DIM}no entries{RESET}");
            } else {
                for v in &values {
                    print_entry(v);
                }
            }
        }
        AccessCommands::Show { subject } => {
            let shown = vtc.client.acl_show(&subject).await.map_err(fail)?;
            report(&serde_json::to_value(&shown)?, "entry")?;
        }
        AccessCommands::Grant {
            subject,
            role,
            scopes,
            label,
            expires,
            reason,
        } => {
            let grant = AclGrant {
                subject,
                role,
                scopes,
                label,
                expires_at: expires.as_deref().map(expiry_from_now).transpose()?,
                reason,
            };
            let granted = vtc.client.acl_grant(&grant).await.map_err(fail)?;
            report(&serde_json::to_value(&granted)?, "granted")?;
        }
        AccessCommands::Update {
            subject,
            scopes,
            label,
            clear_label,
            expires,
            permanent,
            reason,
        } => {
            let update = AclUpdate {
                subject,
                label: if clear_label {
                    Some(None)
                } else {
                    label.map(Some)
                },
                scopes,
                expires_at: if permanent {
                    Some(None)
                } else {
                    expires
                        .as_deref()
                        .map(expiry_from_now)
                        .transpose()?
                        .map(Some)
                },
                reason,
            };
            let updated = vtc.client.acl_update(&update).await.map_err(fail)?;
            report(&serde_json::to_value(&updated)?, "updated")?;
        }
        AccessCommands::ChangeRole {
            subject,
            from_role,
            to_role,
            reason,
        } => {
            let changed = vtc
                .client
                .acl_change_role(&subject, &from_role, &to_role, reason.as_deref())
                .await
                .map_err(fail)?;
            report(&serde_json::to_value(&changed)?, "role changed")?;
        }
        AccessCommands::Revoke {
            subject,
            scopes,
            reason,
        } => {
            let revoked = vtc
                .client
                .acl_revoke(&subject, scopes.as_deref(), reason.as_deref())
                .await
                .map_err(fail)?;
            let v = serde_json::to_value(&revoked)?;
            if is_json_output() {
                print_json(&v)?;
            } else if v["entry"].is_null() {
                println!("{GREEN}revoked{RESET} {subject} — the entry is removed");
            } else {
                println!("{GREEN}scopes revoked{RESET}; {subject} now holds:");
                print_entry(&v["entry"]);
            }
        }
    }
    Ok(())
}

/// `now + duration` for an `--expires` value.
fn expiry_from_now(s: &str) -> CliResult<DateTime<Utc>> {
    let secs = vta_cli_common::duration::parse_duration_secs(s)?;
    let secs = i64::try_from(secs).map_err(|_| format!("--expires {s} is too far away"))?;
    Ok(Utc::now() + chrono::TimeDelta::seconds(secs))
}

/// Print a `{entry: …}` reply, or its JSON.
fn report(reply: &Value, verb: &str) -> CliResult {
    if is_json_output() {
        print_json(reply)?;
    } else {
        println!("{GREEN}{verb}{RESET}");
        print_entry(&reply["entry"]);
    }
    Ok(())
}

fn print_entry(e: &Value) {
    let s = |k: &str| e.get(k).and_then(Value::as_str);
    let scopes = e
        .get("scopes")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let role = s("role").unwrap_or("?");
    // An empty scope list is community-wide for an admin and nowhere for every
    // other role — say which, rather than print nothing for both.
    let scopes = match (scopes.is_empty(), role) {
        (true, "admin") => "(community-wide)".to_string(),
        (true, _) => "(none — acts nowhere)".to_string(),
        (false, _) => scopes,
    };
    println!(
        "  {}  {role}  {scopes}{}{}",
        s("subject").unwrap_or("?"),
        s("label").map(|l| format!("  \"{l}\"")).unwrap_or_default(),
        s("expiresAt")
            .map(|t| format!("  {DIM}expires {t}{RESET}"))
            .unwrap_or_default(),
    );
}

/// What to tell the operator when the VTC refuses.
///
/// A refusal that needs a passkey gesture or another administrator's consent
/// carries the ceremony in its `details`; the operator completes it in the
/// admin console, then re-runs the same command.
fn access_error(vtc: &Connected, err: VtcError) -> Box<dyn std::error::Error> {
    let text = err.to_string();
    if text.contains("stepUpRequest") || text.contains("passkey gesture") {
        return format!(
            "the VTC needs a passkey gesture from {} before it makes this change. Approve it in \
             the admin console, then run the same command again.\n({text})",
            vtc.client_did
        )
        .into();
    }
    if text.contains("consentRequests") {
        return format!(
            "another unrestricted administrator has to approve this first; they have been sent \
             the request (`{} consent approve` answers it). Once one approves, run the same \
             command again.\n({text})",
            bin_name()
        )
        .into();
    }
    format!("the VTC refused {}: {text}", vtc.client_did).into()
}
