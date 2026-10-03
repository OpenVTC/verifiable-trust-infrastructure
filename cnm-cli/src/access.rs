//! `cnm access …` — the community's own access-control list, on its VTC.
//!
//! Not `cnm acl`, which administers the community's **VTA**. This is the VTC's
//! ACL: who may administer the community, and with what — the list the admin
//! console shows under *Access control*.
//!
//! Administration is role-based (`docs/05-design-notes/vtc-admin-roles.md`):
//! an entry holds an **administrative role** (`community-admin`, `moderator`,
//! `vetting-lead`, `repo-manager`, `credential-officer`, `auditor`, `approver`)
//! whose ceiling `--capability` may narrow, optionally to a resource
//! (`git.repo.manage@git-ns:github.com/acme`). `list`, `show`, `grant` and
//! `update` speak `acl/*/0.2`; `change-role` moves the **community** role
//! (`member`, `moderator`, `issuer`, `admin`) at 0.1, and `revoke` removes an
//! entry.
//!
//! Every verb is a canonical `acl/*` Trust Task, signed with this profile's own
//! key. They reach the VTC over TSP when it advertises it, else DIDComm, else
//! a signed document over HTTPS (`--transport` pins one), through the connect
//! helper `cnm git` and `cnm backup` share
//! ([`vtc_target::connect_for_tasks`]). The VTC authorizes each from the
//! signer's own ACL entry at the moment it runs.

use chrono::{DateTime, Utc};
use clap::Subcommand;
use serde_json::Value;
use vta_cli_common::render::{DIM, GREEN, RESET, bin_name, is_json_output, print_json};
use vta_sdk::session::TransportChoice;
use vtc_client::acl::{AclGrantV02, AclListFilterV02, AclUpdateV02};
use vtc_client::{HolderKey, VtcError};

use crate::auth;
use crate::vtc::{self as vtc_target, Connected, VtcTarget};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Subcommand)]
pub enum AccessCommands {
    /// List the entries you may see.
    List {
        /// Only entries with this administrative role (`member` for none).
        #[arg(long = "admin-role")]
        admin_role: Option<String>,
        /// Only entries holding this capability (e.g. vtc.roles.assign).
        #[arg(long)]
        capability: Option<String>,
        /// Only entries holding a capability at a qualifier related to this
        /// resource (e.g. git-ns:github.com/acme), read in `--direction`.
        #[arg(long)]
        resource: Option<String>,
        /// How `--resource` reads: actingIn (default), subtree, any.
        #[arg(long, requires = "resource")]
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
        /// The administrative role: community-admin, moderator, vetting-lead,
        /// repo-manager, credential-officer, auditor, approver — or member for
        /// none.
        #[arg(long = "admin-role")]
        admin_role: String,
        /// Narrow the role's ceiling to this capability, optionally at a
        /// resource (cap@resource). Repeatable. Omitted: the full ceiling.
        /// Granting an authority-conferring capability (vtc.roles.assign,
        /// vtc.config.admin, …) needs another holder's consent.
        #[arg(long = "capability")]
        capabilities: Vec<String>,
        /// Let the subject approve others' actions within its role.
        #[arg(long)]
        approve: bool,
        /// Grant approve authority only — no act authority (the
        /// least-privilege approver).
        #[arg(long)]
        approve_only: bool,
        /// The community role, when it should differ from the one the
        /// administrative role implies.
        #[arg(long)]
        community_role: Option<String>,
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
    /// Amend an existing entry's capabilities, approve authority, label or
    /// expiry. Never its role.
    Update {
        /// The subject DID.
        subject: String,
        /// Replace the capability set: cap or cap@resource, repeatable.
        #[arg(long = "capability", conflicts_with = "full_ceiling")]
        capabilities: Vec<String>,
        /// Return the entry to its role's full ceiling.
        #[arg(long)]
        full_ceiling: bool,
        /// Set whether the subject may approve: true or false.
        #[arg(long)]
        approve: Option<bool>,
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
    /// Move a subject's community role (member, moderator, issuer, admin) —
    /// with the administrative role it implies; `--from` must be its current
    /// role.
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
    /// Remove a subject's entry.
    Revoke {
        /// The subject DID.
        subject: String,
        /// Why, recorded with the change.
        #[arg(long)]
        reason: Option<String>,
    },
}

/// Run one `cnm access` command.
///
/// Every verb is an `acl/*` Trust Task, and they all go the one way, through
/// the connect helper `cnm git` and `cnm backup` share
/// ([`vtc_target::connect_for_tasks`]): over TSP when the VTC advertises it,
/// else DIDComm, else a signed document over HTTPS — `transport`
/// (`--transport`) pins one. The session is closed on every path out.
pub async fn run(
    command: AccessCommands,
    keyring_key: &str,
    target: &VtcTarget,
    transport: TransportChoice,
) -> CliResult {
    let vtc = vtc_target::connect_for_tasks(keyring_key, target, transport).await?;
    let outcome = run_command(command, &vtc, keyring_key).await;
    vtc.client.shutdown().await;
    outcome
}

/// This profile's key, as the signer of `acl/*` documents.
fn signing_key(keyring_key: &str) -> CliResult<HolderKey> {
    let session = auth::loaded_session(keyring_key).ok_or_else(|| {
        format!(
            "no stored identity for this community profile. Run `{} setup` first.",
            bin_name()
        )
    })?;
    HolderKey::from_did_key(&session.client_did, &session.private_key_multibase)
        .map_err(|e| format!("this profile's key cannot sign: {e}").into())
}

async fn run_command(command: AccessCommands, vtc: &Connected, keyring_key: &str) -> CliResult {
    let key = signing_key(keyring_key)?;
    let fail = |e: VtcError| access_error(vtc, e);
    match command {
        AccessCommands::List {
            admin_role,
            capability,
            resource,
            direction,
            subject_prefix,
        } => {
            let direction = match (&resource, direction) {
                (Some(_), None) => Some("actingIn".to_string()),
                (_, d) => d,
            };
            let filter = AclListFilterV02 {
                role: admin_role,
                capability,
                resource,
                direction,
                subject_prefix,
                ..Default::default()
            };
            let entries = vtc
                .client
                .acl_list_all_v0_2(&filter, &key)
                .await
                .map_err(fail)?;
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
            let shown = vtc
                .client
                .acl_show_v0_2(&subject, &key)
                .await
                .map_err(fail)?;
            let shown = serde_json::to_value(&shown)?;
            if shown["entry"].is_null() && !is_json_output() {
                println!("{DIM}{subject} holds no entry{RESET}");
            } else {
                report(&shown, "entry")?;
            }
        }
        AccessCommands::Grant {
            subject,
            admin_role,
            capabilities,
            approve,
            approve_only,
            community_role,
            label,
            expires,
            reason,
        } => {
            let grant = AclGrantV02 {
                subject,
                admin_role,
                // No --capability: the role's full ceiling. Approve-only: none.
                capabilities: if approve_only {
                    Some(Vec::new())
                } else {
                    Some(capabilities).filter(|c| !c.is_empty())
                },
                approve: approve || approve_only,
                act: !approve_only,
                community_role,
                label,
                expires_at: expires.as_deref().map(expiry_from_now).transpose()?,
                reason,
            };
            let granted = vtc
                .client
                .acl_grant_v0_2(&grant, &key)
                .await
                .map_err(fail)?;
            report(&serde_json::to_value(&granted)?, "granted")?;
        }
        AccessCommands::Update {
            subject,
            capabilities,
            full_ceiling,
            approve,
            label,
            clear_label,
            expires,
            permanent,
            reason,
        } => {
            let update = AclUpdateV02 {
                subject,
                label: if clear_label {
                    Some(None)
                } else {
                    label.map(Some)
                },
                capabilities: if full_ceiling {
                    Some(None)
                } else {
                    Some(capabilities).filter(|c| !c.is_empty()).map(Some)
                },
                approve,
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
            let updated = vtc
                .client
                .acl_update_v0_2(&update, &key)
                .await
                .map_err(fail)?;
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
                .acl_change_role(&subject, &from_role, &to_role, reason.as_deref(), &key)
                .await
                .map_err(fail)?;
            report(&serde_json::to_value(&changed)?, "role changed")?;
        }
        AccessCommands::Revoke { subject, reason } => {
            let revoked = vtc
                .client
                .acl_revoke(&subject, None, reason.as_deref(), &key)
                .await
                .map_err(fail)?;
            let v = serde_json::to_value(&revoked)?;
            if is_json_output() {
                print_json(&v)?;
            } else {
                println!("{GREEN}revoked{RESET} {subject} — the entry is removed");
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

/// One line per entry: subject, administrative role, and what it may do —
/// "everything" only for a community administrator holding its full ceiling,
/// "nothing" for no administrative role or no act authority (the #746 class:
/// two different authorities never print alike).
fn print_entry(e: &Value) {
    let s = |k: &str| e.get(k).and_then(Value::as_str);
    let role = s("role").unwrap_or("?");
    let acts = e["act"]["scope"] == "all";
    let holds = match e["capabilities"]["scope"].as_str() {
        _ if role == "member" => "nothing".to_string(),
        _ if !acts => "acts nowhere (approves only)".to_string(),
        Some("ceiling") if role == "community-admin" => "everything".to_string(),
        Some("ceiling") => format!("the {role} ceiling"),
        Some("none") => "nothing".to_string(),
        Some("listed") => e["capabilities"]["grants"]
            .as_array()
            .map(|g| {
                g.iter()
                    .map(|g| match g["resource"].as_str() {
                        Some(r) => format!("{}@{r}", g["capability"].as_str().unwrap_or("?")),
                        None => g["capability"].as_str().unwrap_or("?").to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default(),
        _ => "?".to_string(),
    };
    let community = e["ext"]["org.openvtc"]["communityRole"]
        .as_str()
        .map(|c| format!("  {DIM}community role {c}{RESET}"))
        .unwrap_or_default();
    let scopes = holds;
    println!(
        "  {}  {role}  {scopes}{community}{}{}",
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
    // Not a failure: parked for other administrators' approval, and it
    // completes itself when enough approve (VTI-APV-017).
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
    if text.contains("stepUpRequest") || text.contains("passkey gesture") {
        return format!(
            "the VTC needs a passkey gesture from {} before it makes this change. Approve it in \
             the admin console, then run the same command again.\n({text})",
            vtc.client_did
        )
        .into();
    }
    format!("the VTC refused {}: {text}", vtc.client_did).into()
}
