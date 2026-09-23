//! `cnm git …` — the community's git namespaces (`git-ns/*`).
//!
//! Two kinds of command, and the difference is who is authorized:
//!
//! - **Changes** (`namespace bind|unbind`, `grant`, `revoke`, `adopt`, `view`)
//!   are signed `git-ns/*` Trust Tasks, signed with this community profile's
//!   key and authorized by *that DID's git rights* in the VTC's records. A
//!   community administrator's role binds namespaces and nothing more: to
//!   grant, this DID must hold a right that carries the authority.
//! - **Listings** (`namespace list`, `repos`, `view --admin`) are the
//!   administrator's REST reads and authenticate with an admin session, like
//!   `cnm vetting`.
//!
//! A refusal is reported by its specification code with the fix, where there
//! is one — `git-ns:lastOwner` names the grant that makes the revoke possible.

use clap::{Subcommand, ValueEnum};
use serde_json::{Value, json};
use vta_cli_common::duration::parse_duration_secs;
use vta_cli_common::render::{BOLD, DIM, RESET, bin_name, is_json_output, print_json};
use vtc_client::git_ns::{specs, task_error};
use vtc_client::{HolderKey, VtcClient, VtcError};

use crate::auth;
use crate::vtc::{self as vtc_target, VtcTarget};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// `cnm git …`
#[derive(Subcommand)]
pub enum GitCommands {
    /// Namespaces: bind this community to a forge owner, end it, list them.
    Namespace {
        #[command(subcommand)]
        command: NamespaceCommands,
    },
    /// List the repositories the community records (admin session).
    Repos {
        /// Only this namespace (its identifier, from `namespace list`).
        #[arg(long)]
        namespace: Option<String>,
    },
    /// Grant a git right, signed as this profile's DID.
    Grant {
        /// Who receives the right.
        #[arg(long)]
        subject: String,
        #[arg(long, value_enum)]
        right: RightArg,
        /// Forge-qualified and lowercase: `github.com/acme` or
        /// `github.com/acme/widgets`.
        #[arg(long)]
        resource: String,
        /// Lapse after this long (`90d`, `12h`).
        #[arg(long)]
        expires_in: Option<String>,
        /// Why — shown to the resource's owners and admins, never published.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Revoke a recorded git right, signed as this profile's DID.
    Revoke {
        #[arg(long)]
        subject: String,
        #[arg(long, value_enum)]
        right: RightArg,
        #[arg(long)]
        resource: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Create a repository in a namespace, becoming its owner (needs
    /// `git.repo.create`). Where no bot can create it, prints the steps.
    Create {
        /// The namespace identifier (`namespace list`).
        #[arg(long)]
        namespace: String,
        /// The repository name, lowercase.
        name: String,
        #[arg(long, value_enum, default_value_t = VisibilityArg::Public)]
        visibility: VisibilityArg,
        /// Shown by the forge; do not put anything here you would not publish.
        #[arg(long)]
        description: Option<String>,
    },
    /// Hand this profile's ownership of a repository to someone else.
    Transfer {
        /// `github.com/acme/widgets`.
        resource: String,
        /// Who receives ownership.
        #[arg(long)]
        to: String,
    },
    /// Archive a repository: the forge makes it read-only and every
    /// commit-signing right on it is revoked. No task reverses it.
    Archive {
        /// `github.com/acme/widgets`.
        resource: String,
    },
    /// Bring an existing repository under governance and name its owners.
    Adopt {
        /// `github.com/acme/widgets`.
        resource: String,
        /// An owner's DID. Repeat for several; at least one.
        #[arg(long = "owner", required = true)]
        owners: Vec<String>,
    },
    /// What this profile's DID may see (`git-ns/view`), or with `--admin`
    /// every record and reason (admin session).
    View {
        #[arg(long)]
        resource: Option<String>,
        #[arg(long)]
        admin: bool,
    },
}

#[derive(Subcommand)]
pub enum NamespaceCommands {
    /// Bind the community to one owner on one forge. Everything granted in it
    /// is published to the community's Trust Registry, where anyone can read
    /// who owns and who may commit to each repository.
    Bind {
        /// The forge host: `github.com`, `codeberg.org`, a GHES or Forgejo host.
        #[arg(long)]
        forge: String,
        /// The organisation or account, lowercase.
        #[arg(long)]
        owner: String,
        #[arg(long, value_enum, default_value_t = ModeArg::Manual)]
        mode: ModeArg,
    },
    /// End the community's governance of a namespace: every right in it is
    /// revoked and withdrawn from the registry.
    Unbind {
        /// The namespace identifier (`namespace list`).
        namespace: String,
    },
    /// List bound and pending namespaces (admin session).
    List,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum VisibilityArg {
    Public,
    Private,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ModeArg {
    Bridge,
    Manual,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum RightArg {
    #[value(name = "git.ns.admin")]
    NsAdmin,
    #[value(name = "git.repo.create")]
    RepoCreate,
    #[value(name = "git.repo.own")]
    RepoOwn,
    #[value(name = "git.repo.maintain")]
    RepoMaintain,
    #[value(name = "git.commit.sign")]
    CommitSign,
}

impl RightArg {
    fn as_str(self) -> &'static str {
        match self {
            RightArg::NsAdmin => "git.ns.admin",
            RightArg::RepoCreate => "git.repo.create",
            RightArg::RepoOwn => "git.repo.own",
            RightArg::RepoMaintain => "git.repo.maintain",
            RightArg::CommitSign => "git.commit.sign",
        }
    }
}

/// This profile's key, as the signer of `git-ns/*` documents.
fn signing_key(keyring_key: &str) -> CliResult<(String, HolderKey)> {
    let session = auth::loaded_session(keyring_key).ok_or_else(|| {
        format!(
            "no stored identity for this community profile. Run `{} setup` first.",
            bin_name()
        )
    })?;
    let key = HolderKey::from_did_key(&session.client_did, &session.private_key_multibase)
        .map_err(|e| format!("this profile's key cannot sign: {e}"))?;
    Ok((session.client_did, key))
}

/// The fix for a refusal, where the operator's intent maps onto another
/// command.
fn guidance(code: &str, message: &str, did: &str) -> String {
    let bin = bin_name();
    let hint = match code {
        "git-ns:lastOwner" => format!(
            "\nA repository always keeps an owner. Name another first:\n  {bin} git grant \
             --subject <did> --right git.repo.own --resource <repository>\nthen revoke this one."
        ),
        "git-ns:lastAdmin" => format!(
            "\nA namespace always keeps an admin. Grant another first:\n  {bin} git grant \
             --subject <did> --right git.ns.admin --resource <namespace>"
        ),
        "git-ns:escalation" | "permissionDenied" => format!(
            "\nThese commands are authorized by {did}'s own git rights, not by an admin \
             session. See what it holds:\n  {bin} git view"
        ),
        "git-ns:namespaceNotBound" => "\nThe namespace's binding has not completed: finish \
             the step at the URL `namespace bind` printed, then retry."
            .to_string(),
        "git-ns/namespace/bind:alreadyBound" => {
            format!("\nIt is already bound, or binding. See:\n  {bin} git namespace list")
        }
        "git-ns/namespace/bind:noBridge" => "\nNo bridge serves that forge. Bind with \
             `--mode manual`, or configure `[git_ns.bridges]` on the VTC."
            .to_string(),
        "git-ns:unknownRepo" => format!(
            "\nThe VTC records no repository there. Bring it under governance first:\n  {bin} \
             git adopt <resource> --owner <did>"
        ),
        "git-ns/repo/transfer:notOwner" => format!(
            "\nA transfer hands over your own ownership record. A namespace admin names an \
             owner instead:\n  {bin} git grant --subject <did> --right git.repo.own --resource \
             <repository>"
        ),
        "git-ns/repo/create:nameTaken" => format!(
            "\nThe community already records a repository there. See it:\n  {bin} git view \
             --resource <resource>"
        ),
        "git-ns/right/revoke:notGranted" => "\nNothing to revoke: no live record matches. \
             Implied rights (an owner's commit right, an admin's ownership) are not records."
            .to_string(),
        _ => String::new(),
    };
    format!("the community refused it ({code}): {message}{hint}")
}

fn explain(err: VtcError, did: &str) -> Box<dyn std::error::Error> {
    match task_error(&err) {
        Some((code, message)) => guidance(&code, &message, did).into(),
        None => err.to_string().into(),
    }
}

fn show<T: serde::Serialize>(value: &T) -> CliResult {
    if is_json_output() {
        print_json(value)?;
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

pub async fn run(command: GitCommands, keyring_key: &str, target: &VtcTarget) -> CliResult {
    // Signed commands need no session; listings do.
    let anon = || VtcClient::anonymous(&target.base, &target.did);
    match command {
        GitCommands::Namespace { command } => match command {
            NamespaceCommands::Bind { forge, owner, mode } => {
                let (did, key) = signing_key(keyring_key)?;
                let mode = match mode {
                    ModeArg::Bridge => "bridge",
                    ModeArg::Manual => "manual",
                };
                let resp = anon()
                    .git_ns_bind(&forge.to_lowercase(), &owner.to_lowercase(), mode, &key)
                    .await
                    .map_err(|e| explain(e, &did))?;
                let v = serde_json::to_value(&resp)?;
                if is_json_output() {
                    return Ok(print_json(&v)?);
                }
                println!(
                    "{BOLD}{}/{}{RESET} — {} ({})",
                    v["namespace"]["forge"].as_str().unwrap_or_default(),
                    v["namespace"]["owner"].as_str().unwrap_or_default(),
                    v["namespace"]["state"].as_str().unwrap_or_default(),
                    v["namespace"]["id"].as_str().unwrap_or_default(),
                );
                if let Some(url) = v.pointer("/next/url").and_then(Value::as_str) {
                    println!("Prove control of the owner on the forge to finish binding:\n  {url}");
                }
                println!(
                    "{DIM}Rights granted in this namespace are published to the Trust Registry: \
                     anyone can read who owns and who may commit to each repository.{RESET}"
                );
                Ok(())
            }
            NamespaceCommands::Unbind { namespace } => {
                let (did, key) = signing_key(keyring_key)?;
                let resp = anon()
                    .git_ns_unbind(&namespace, &key)
                    .await
                    .map_err(|e| explain(e, &did))?;
                show(&resp)
            }
            NamespaceCommands::List => {
                let vtc = vtc_target::connect(keyring_key, target).await?;
                let v = vtc.client.git_ns_namespaces().await?;
                if is_json_output() {
                    return Ok(print_json(&v)?);
                }
                for ns in v["namespaces"].as_array().into_iter().flatten() {
                    println!(
                        "{BOLD}{}{RESET}  {}  {} {}  admins: {}  repos: {}",
                        ns["resource"].as_str().unwrap_or_default(),
                        ns["id"].as_str().unwrap_or_default(),
                        ns["mode"].as_str().unwrap_or_default(),
                        ns["state"].as_str().unwrap_or_default(),
                        ns["admins"].as_array().map_or(0, Vec::len),
                        ns["repoCount"],
                    );
                }
                Ok(())
            }
        },
        GitCommands::Repos { namespace } => {
            let vtc = vtc_target::connect(keyring_key, target).await?;
            let v = vtc.client.git_ns_repos(namespace.as_deref()).await?;
            if is_json_output() {
                return Ok(print_json(&v)?);
            }
            for r in v["repos"].as_array().into_iter().flatten() {
                println!(
                    "{BOLD}{}{RESET}  {}  owners: {}  sync: {}",
                    r["resource"].as_str().unwrap_or_default(),
                    r["state"].as_str().unwrap_or_default(),
                    r["owners"].as_array().map_or(0, Vec::len),
                    r["syncState"].as_str().unwrap_or_default(),
                );
            }
            Ok(())
        }
        GitCommands::Grant {
            subject,
            right,
            resource,
            expires_in,
            reason,
        } => {
            let (did, key) = signing_key(keyring_key)?;
            let mut payload = json!({
                "subject": subject,
                "right": right.as_str(),
                "resource": resource.to_lowercase(),
            });
            if let Some(d) = expires_in {
                let secs = parse_duration_secs(&d)?;
                let at = chrono::Utc::now() + chrono::Duration::seconds(secs as i64);
                payload["expiresAt"] = json!(at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
            }
            if let Some(r) = reason {
                payload["reason"] = json!(r);
            }
            let payload: specs::right::grant::v0_1::Payload = serde_json::from_value(payload)
                .map_err(|e| format!("that grant is not well formed: {e}"))?;
            let resp = anon()
                .git_ns_grant(&payload, &key)
                .await
                .map_err(|e| explain(e, &did))?;
            show(&resp)
        }
        GitCommands::Revoke {
            subject,
            right,
            resource,
            reason,
        } => {
            let (did, key) = signing_key(keyring_key)?;
            let mut payload = json!({
                "subject": subject,
                "right": right.as_str(),
                "resource": resource.to_lowercase(),
            });
            if let Some(r) = reason {
                payload["reason"] = json!(r);
            }
            let payload: specs::right::revoke::v0_1::Payload = serde_json::from_value(payload)
                .map_err(|e| format!("that revocation is not well formed: {e}"))?;
            let resp = anon()
                .git_ns_revoke(&payload, &key)
                .await
                .map_err(|e| explain(e, &did))?;
            show(&resp)
        }
        GitCommands::Create {
            namespace,
            name,
            visibility,
            description,
        } => {
            let (did, key) = signing_key(keyring_key)?;
            let mut payload = json!({
                "namespace": namespace,
                "name": name.to_lowercase(),
                "visibility": match visibility {
                    VisibilityArg::Public => "public",
                    VisibilityArg::Private => "private",
                },
            });
            if let Some(d) = description {
                payload["description"] = json!(d);
            }
            let payload: specs::repo::create::v0_1::Payload = serde_json::from_value(payload)
                .map_err(|e| format!("that repository is not well formed: {e}"))?;
            let resp = anon()
                .git_ns_create_repo(&payload, &key)
                .await
                .map_err(|e| explain(e, &did))?;
            let v = serde_json::to_value(&resp)?;
            if is_json_output() {
                return Ok(print_json(&v)?);
            }
            println!(
                "{BOLD}{}{RESET} — {}",
                v["repo"]["resource"].as_str().unwrap_or_default(),
                v["repo"]["state"].as_str().unwrap_or_default()
            );
            for (i, step) in v["manualSteps"]
                .as_array()
                .into_iter()
                .flatten()
                .enumerate()
            {
                println!("  {}. {}", i + 1, step.as_str().unwrap_or_default());
            }
            Ok(())
        }
        GitCommands::Transfer { resource, to } => {
            let (did, key) = signing_key(keyring_key)?;
            let resp = anon()
                .git_ns_transfer(&resource.to_lowercase(), &to, &key)
                .await
                .map_err(|e| explain(e, &did))?;
            show(&resp)
        }
        GitCommands::Archive { resource } => {
            let (did, key) = signing_key(keyring_key)?;
            let resp = anon()
                .git_ns_archive(&resource.to_lowercase(), &key)
                .await
                .map_err(|e| explain(e, &did))?;
            show(&resp)
        }
        GitCommands::Adopt { resource, owners } => {
            let (did, key) = signing_key(keyring_key)?;
            let resp = anon()
                .git_ns_adopt(&resource.to_lowercase(), &owners, &key)
                .await
                .map_err(|e| explain(e, &did))?;
            show(&resp)
        }
        GitCommands::View { resource, admin } => {
            if admin {
                let vtc = vtc_target::connect(keyring_key, target).await?;
                let v = vtc.client.git_ns_admin_view(resource.as_deref()).await?;
                return show(&v);
            }
            let (did, key) = signing_key(keyring_key)?;
            let resp = anon()
                .git_ns_view(resource.as_deref(), &key)
                .await
                .map_err(|e| explain(e, &did))?;
            show(&resp)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_last_owner_refusal_names_the_grant_that_resolves_it() {
        let g = guidance("git-ns:lastOwner", "last owner", "did:key:z");
        assert!(g.contains("--right git.repo.own"), "{g}");
    }

    #[test]
    fn right_arguments_carry_the_wire_spelling() {
        assert_eq!(RightArg::CommitSign.as_str(), "git.commit.sign");
        assert_eq!(RightArg::NsAdmin.as_str(), "git.ns.admin");
    }
}
