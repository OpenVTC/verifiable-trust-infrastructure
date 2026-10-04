//! The pull-request gate: who may open a pull request on a governed
//! repository, and what happens to one opened by somebody else.
//!
//! Normative: `git-ns/bridge/event/0.4` (`pullRequestOpened`, *Definitions* —
//! *Pull-request policy* — and request step 6) and `git-ns/bridge/job/0.5`
//! (`closePullRequest`). The forge cannot restrict who opens a pull request
//! against a public repository, so the bridge reports each one opened or
//! reopened, the VTC decides here, and a pull request whose author the policy
//! does not allow is closed by a queued `closePullRequest` job carrying the
//! community's message.
//!
//! # Hygiene, not the merge gate
//!
//! The required commit-trust check (`requiredCheck`) is what keeps untrusted
//! commits out of a governed repository, and nothing here weakens or replaces
//! it. The gate fails **open**: a VTC or bridge that is down, a bridge that
//! does not take job 0.5, or a policy this VTC cannot read leaves a pull
//! request open, and nothing the required check refuses can be merged through
//! it. A pull request the gate did not close is never treated as approved.
//!
//! # Settings
//!
//! Read from the active `gitNamespace` policy's `settings` object, as the
//! other git-namespace settings are ([`super::policy`]):
//!
//! | key | default | meaning |
//! |---|---|---|
//! | `pr_open` | `"anyone"` | `"anyone"`, `"members"`, `"committers"`, `"maintainers"`, or `{"roles": [<VTC role>, …]}` |
//! | `pr_open_overrides` | `{}` | `{"<forge>/<owner>[/<repo>]": <level>}` — a repository's entry wins over its namespace's, which wins over `pr_open` |
//! | `pr_close_message` | [`DEFAULT_CLOSE_MESSAGE`] | Markdown with `{author}`, `{repo}`, `{community}`, `{join_hint}` |
//! | `pr_join_hint` | derived from the community profile | the sentence `{join_hint}` renders to (it may use `{community}` and `{repo}`) |
//! | `pr_exempt` | `["dependabot[bot]"]` | forge logins always allowed |
//!
//! A value this VTC cannot read is reported in the log and replaced by that
//! key's default — for `pr_open`, `anyone`: the gate fails open, as above.
//!
//! # Who is always allowed
//!
//! Whatever the level: an account linked to a holder of `git.repo.own` or
//! `git.repo.maintain` on the repository, by record or by implication (so a
//! namespace admin), and the bridge's own forge account. An account in
//! `pr_exempt` too, which is this VTC's addition. A forge account the VTC has
//! no link for is allowed only under `anyone`. Accounts are matched by forge
//! and id, never by login — except `pr_exempt`, which names logins, and the
//! bridge's own app account, whose `<slug>[bot]` login GitHub reserves for the
//! app.
//!
//! # What a close carries
//!
//! The message is public once posted, so it is rendered from the template and
//! the four placeholders only — the author's login (which the forge already
//! shows), the repository, the community's name and the join hint. Nothing
//! the VTC knows about the author — a DID, membership state, a role, why they
//! were refused — goes into it (`git-ns/bridge/job/0.5`, *Purpose*).

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{debug, info, warn};
use trust_tasks_rs::specs::git_ns::bridge::event::v0_4 as event_wire;

use crate::acl::VtcRole;
use crate::server::AppState;

use super::bridge::{self, BridgeJob, JobKind, JobState, NewJob, PullRequestClose};
use super::model::{ForgeAccount, Mode, Namespace, Repo, RepoState, Resource, Right};
use super::ops::{self, Audit, OpResult, audit, now};
use super::rules;
use super::store::Snapshot;

/// The longest message a `closePullRequest` job may carry
/// (`git-ns/bridge/job/0.5`, `message`).
pub const MAX_MESSAGE_CHARS: usize = 16_384;

/// The message posted on a pull request the policy does not allow, unless the
/// community writes its own (`pr_close_message`).
pub const DEFAULT_CLOSE_MESSAGE: &str = "Hi {author}, thank you for your interest in \
**{repo}**.\n\nPull requests on this repository are open only to contributors that \
{community} has approved, so this one has been closed automatically.\n\n{join_hint}\n\n\
If you believe this is a mistake, a maintainer of the repository can reopen it.";

/// The logins exempt by default: Dependabot, whose pull requests the bridge
/// re-signs (design §9, *Dependabot re-sign bot*).
pub const DEFAULT_EXEMPT: &[&str] = &["dependabot[bot]"];

// ── settings ────────────────────────────────────────────────────────────────

/// Who may open a pull request — the *Pull-request policy*'s levels, from the
/// most open.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PrOpenLevel {
    /// No gate: the default where nothing is configured.
    #[default]
    Anyone,
    /// A linked account of a current member.
    Members,
    /// A linked account of a holder of `git.commit.sign` on the repository,
    /// by record or by implication (a namespace-wide grant included).
    Committers,
    /// A linked account of a holder of `git.repo.maintain` or higher.
    Maintainers,
    /// A linked account of a current member whose VTC role is one of these
    /// (wire form: `admin`, `member`, `custom:<name>`, …).
    Roles(Vec<String>),
}

impl PrOpenLevel {
    /// The name recorded in the audit row and shown to administrators.
    pub fn as_str(&self) -> &'static str {
        match self {
            PrOpenLevel::Anyone => "anyone",
            PrOpenLevel::Members => "members",
            PrOpenLevel::Committers => "committers",
            PrOpenLevel::Maintainers => "maintainers",
            PrOpenLevel::Roles(_) => "roles",
        }
    }

    /// Read one level, as `pr_open` or a `pr_open_overrides` value.
    pub fn parse(v: &Value) -> Result<PrOpenLevel, String> {
        match v {
            Value::String(s) => match s.as_str() {
                "anyone" => Ok(PrOpenLevel::Anyone),
                "members" => Ok(PrOpenLevel::Members),
                "committers" => Ok(PrOpenLevel::Committers),
                "maintainers" => Ok(PrOpenLevel::Maintainers),
                other => Err(format!(
                    "`{other}` is not a level; expected anyone, members, committers, \
                     maintainers or {{\"roles\": [...]}}"
                )),
            },
            Value::Object(o) => {
                if o.keys().any(|k| k != "roles") {
                    return Err("a role level carries `roles` and nothing else".into());
                }
                let Some(items) = o.get("roles").and_then(Value::as_array) else {
                    return Err("`roles` must be a list of VTC role names".into());
                };
                let mut roles = Vec::new();
                for item in items {
                    let Some(name) = item.as_str() else {
                        return Err("`roles` must be a list of VTC role names".into());
                    };
                    // The wire form a role is compared in: `custom:<name>` for a
                    // custom role, exactly as an ACL entry carries it.
                    let role: VtcRole = name.parse().map_err(|e| format!("`{name}`: {e}"))?;
                    let wire = role.to_string();
                    if !roles.contains(&wire) {
                        roles.push(wire);
                    }
                }
                if roles.is_empty() {
                    return Err(
                        "`roles` names no role; use \"maintainers\" to allow only those who \
                         are always allowed"
                            .into(),
                    );
                }
                Ok(PrOpenLevel::Roles(roles))
            }
            _ => Err("a level is a string or {\"roles\": [...]}".into()),
        }
    }
}

/// The community's pull-request policy, as its `gitNamespace` settings state
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrGateSettings {
    /// `pr_open`: the community-wide level.
    pub pr_open: PrOpenLevel,
    /// `pr_open_overrides`: a level for one namespace or one repository,
    /// keyed by its forge-qualified, lowercase resource.
    pub overrides: BTreeMap<String, PrOpenLevel>,
    /// `pr_close_message`.
    pub close_message: String,
    /// `pr_join_hint`; `None` derives one from the community profile.
    pub join_hint: Option<String>,
    /// `pr_exempt`: forge logins always allowed, compared without regard to
    /// case (forge logins are case-insensitive).
    pub exempt: Vec<String>,
}

impl Default for PrGateSettings {
    fn default() -> Self {
        Self {
            pr_open: PrOpenLevel::Anyone,
            overrides: BTreeMap::new(),
            close_message: DEFAULT_CLOSE_MESSAGE.to_string(),
            join_hint: None,
            exempt: DEFAULT_EXEMPT.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl PrGateSettings {
    /// Read the gate's keys from a `settings` object, with every problem
    /// found. A key that cannot be read keeps its default, so the gate fails
    /// open rather than closing pull requests on a typo.
    pub fn from_settings(settings: Option<&Value>) -> (PrGateSettings, Vec<String>) {
        let mut out = PrGateSettings::default();
        let mut problems = Vec::new();
        let Some(obj) = settings.and_then(Value::as_object) else {
            return (out, problems);
        };
        if let Some(v) = obj.get("pr_open") {
            match PrOpenLevel::parse(v) {
                Ok(level) => out.pr_open = level,
                Err(e) => problems.push(format!("pr_open: {e}")),
            }
        }
        if let Some(v) = obj.get("pr_open_overrides") {
            match v.as_object() {
                Some(map) => {
                    for (key, level) in map {
                        // Resources are lowercase on the wire; a community
                        // writing `github.com/Acme` means the same namespace.
                        let resource = match Resource::parse(&key.to_lowercase()) {
                            Ok(r) => r,
                            Err(e) => {
                                problems.push(format!("pr_open_overrides: `{key}`: {e}"));
                                continue;
                            }
                        };
                        match PrOpenLevel::parse(level) {
                            Ok(l) => {
                                out.overrides.insert(resource.to_string(), l);
                            }
                            Err(e) => problems.push(format!("pr_open_overrides: `{key}`: {e}")),
                        }
                    }
                }
                None => problems
                    .push("pr_open_overrides: must be an object of resource to level".to_string()),
            }
        }
        if let Some(v) = obj.get("pr_close_message") {
            match v.as_str() {
                Some(s) if !s.trim().is_empty() => out.close_message = s.to_string(),
                _ => problems.push("pr_close_message: must be a non-empty string".into()),
            }
        }
        if let Some(v) = obj.get("pr_join_hint") {
            match v.as_str() {
                Some(s) => out.join_hint = Some(s.to_string()),
                None => problems.push("pr_join_hint: must be a string".into()),
            }
        }
        if let Some(v) = obj.get("pr_exempt") {
            match v.as_array().and_then(|items| {
                items
                    .iter()
                    .map(|i| i.as_str().map(str::to_string))
                    .collect::<Option<Vec<_>>>()
            }) {
                Some(logins) => out.exempt = logins,
                None => problems.push("pr_exempt: must be a list of forge logins".into()),
            }
        }
        (out, problems)
    }

    /// The level in force on `repo`: its own override, else its namespace's,
    /// else `pr_open`.
    pub fn level_for(&self, repo: &Resource) -> &PrOpenLevel {
        self.overrides
            .get(&repo.to_string())
            .or_else(|| self.overrides.get(&repo.namespace_resource().to_string()))
            .unwrap_or(&self.pr_open)
    }

    /// Whether any level other than `anyone` is configured anywhere — whether
    /// the gate does anything at all in this community.
    pub fn is_configured(&self) -> bool {
        self.pr_open != PrOpenLevel::Anyone
            || self.overrides.values().any(|l| *l != PrOpenLevel::Anyone)
    }

    fn is_exempt(&self, login: &str) -> bool {
        self.exempt.iter().any(|l| l.eq_ignore_ascii_case(login))
    }
}

// ── the decision ────────────────────────────────────────────────────────────

/// What the VTC knows about one forge account, for the decision.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountFacts {
    /// Its login is in `pr_exempt`.
    pub exempt: bool,
    /// It is the bridge's own forge account.
    pub bridge: bool,
    /// The member it is linked to, if any.
    pub linked: Option<LinkedFacts>,
}

/// The holder of a linked account.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkedFacts {
    /// A current member of the community.
    pub member: bool,
    /// Their VTC role, in wire form.
    pub role: Option<String>,
    /// Their git rights on the repository, explicit or implied.
    pub rights: BTreeSet<Right>,
}

impl AccountFacts {
    /// Always allowed, whatever the level (*Pull-request policy*): the
    /// bridge, or an owner or maintainer of the repository.
    pub fn always_allowed(&self) -> bool {
        self.bridge
            || self.linked.as_ref().is_some_and(|l| {
                l.rights.contains(&Right::RepoOwn) || l.rights.contains(&Right::RepoMaintain)
            })
    }
}

/// `opened` or `reopened`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrAction {
    Opened,
    Reopened,
}

/// What the VTC does about one pull request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Left open.
    Allowed,
    /// Reopened by an owner, a maintainer or the bridge: left open, and never
    /// closed again in answer to this event (request step 6.2).
    Override,
    /// Closed: the author is not allowed (request step 6.4).
    Close,
}

/// Request step 6, steps 1 to 3, as a pure function of what the VTC knows.
pub fn decide(
    level: &PrOpenLevel,
    action: PrAction,
    author: &AccountFacts,
    actor: &AccountFacts,
) -> Verdict {
    // 6.1: no gate.
    if *level == PrOpenLevel::Anyone {
        return Verdict::Allowed;
    }
    // 6.2: an owner's, a maintainer's or the bridge's reopen overrides.
    if action == PrAction::Reopened && actor.always_allowed() {
        return Verdict::Override;
    }
    // 6.3: everyone else — an opening, or anybody else's reopen — is the
    // author evaluated afresh.
    if author.always_allowed() || author.exempt {
        return Verdict::Allowed;
    }
    // Unlinked: allowed only under `anyone`, which returned above.
    let Some(linked) = &author.linked else {
        return Verdict::Close;
    };
    let allowed = match level {
        PrOpenLevel::Anyone => true,
        PrOpenLevel::Members => linked.member,
        PrOpenLevel::Committers => linked.rights.contains(&Right::CommitSign),
        PrOpenLevel::Maintainers => linked.rights.contains(&Right::RepoMaintain),
        PrOpenLevel::Roles(roles) => {
            linked.member && linked.role.as_ref().is_some_and(|r| roles.contains(r))
        }
    };
    if allowed {
        Verdict::Allowed
    } else {
        Verdict::Close
    }
}

// ── the message ─────────────────────────────────────────────────────────────

/// What the message's placeholders render to — and all they can.
#[derive(Debug, Clone)]
pub struct MessageContext<'a> {
    pub author: &'a str,
    pub repo: &'a str,
    pub community: &'a str,
    pub join_hint: &'a str,
}

/// Replace each `{name}` in `template` that `lookup` knows, in one pass: a
/// value is never itself scanned for placeholders.
fn substitute(template: &str, lookup: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match after.find('}') {
            Some(close)
                if after[..close]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_') =>
            {
                let name = &after[..close];
                match lookup(name) {
                    Some(v) => out.push_str(&v),
                    None => {
                        out.push('{');
                        out.push_str(name);
                        out.push('}');
                    }
                }
                rest = &after[close + 1..];
            }
            _ => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// A forge login as the message may show it. Logins are letters, digits and
/// hyphens (plus GitHub's `[bot]` suffix); anything else is not rendered, so
/// a bridge-reported value can never inject Markdown into a public comment.
fn display_login(login: &str) -> String {
    let ok = !login.is_empty()
        && login.len() <= 64
        && login
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '[' | ']'));
    if ok {
        login.to_string()
    } else {
        "there".to_string()
    }
}

/// Render the message posted on a pull request the policy does not allow:
/// the template with its four placeholders, at most [`MAX_MESSAGE_CHARS`].
pub fn render_message(template: &str, ctx: &MessageContext<'_>) -> String {
    let author = display_login(ctx.author);
    let rendered = substitute(template, |name| match name {
        "author" => Some(author.clone()),
        "repo" => Some(ctx.repo.to_string()),
        "community" => Some(ctx.community.to_string()),
        "join_hint" => Some(ctx.join_hint.to_string()),
        _ => None,
    });
    let trimmed = rendered.trim();
    if trimmed.chars().count() <= MAX_MESSAGE_CHARS {
        trimmed.to_string()
    } else {
        trimmed.chars().take(MAX_MESSAGE_CHARS).collect()
    }
}

/// The join hint: the community's own (`pr_join_hint`, which may use
/// `{community}` and `{repo}`), or one derived from its profile.
pub fn join_hint(
    configured: Option<&str>,
    community: &str,
    repo: &str,
    public_url: Option<&str>,
) -> String {
    match configured {
        Some(hint) => substitute(hint, |name| match name {
            "community" => Some(community.to_string()),
            "repo" => Some(repo.to_string()),
            _ => None,
        }),
        None => match public_url.filter(|u| !u.trim().is_empty()) {
            Some(url) => format!(
                "To contribute, join {community} at {url} and link your forge account to your \
                 membership."
            ),
            None => format!(
                "To contribute, become a member of {community} and link your forge account to \
                 your membership."
            ),
        },
    }
}

// ── the event ───────────────────────────────────────────────────────────────

/// A `pullRequestOpened` event, as the gate reads it.
#[derive(Debug, Clone)]
pub struct PullRequestOpened {
    pub forge_id: String,
    pub resource: String,
    pub number: u64,
    pub action: PrAction,
    pub author: ForgeAccount,
    pub actor: ForgeAccount,
}

fn account(a: event_wire::ForgeAccount) -> Option<ForgeAccount> {
    let v = serde_json::to_value(a).ok()?;
    serde_json::from_value(v).ok()
}

impl PullRequestOpened {
    /// From the generated event, or `None` for any other event type.
    pub fn from_wire(e: event_wire::ForgeEvent) -> Option<PullRequestOpened> {
        let event_wire::ForgeEvent::PullRequestOpened {
            action,
            actor,
            author,
            forge_id,
            number,
            resource,
            ..
        } = e
        else {
            return None;
        };
        Some(PullRequestOpened {
            forge_id: forge_id.to_string(),
            resource: resource.to_string(),
            number: number.get(),
            action: match action {
                event_wire::PullRequestAction::Opened => PrAction::Opened,
                event_wire::PullRequestAction::Reopened => PrAction::Reopened,
                // A later action this VTC does not know: not judged.
                _ => return None,
            },
            author: account(author)?,
            actor: account(actor)?,
        })
    }
}

/// The bridge's own forge account: on GitHub, its app's `<slug>[bot]`, a
/// login the forge reserves for the app — known once the bridge has reported
/// its app (`ext`, [`super::model::NamespaceForgeStatus`]).
fn is_bridge_account(ns: &Namespace, acct: &ForgeAccount) -> bool {
    ns.forge_status
        .as_ref()
        .and_then(|s| s.app_slug.as_deref())
        .is_some_and(|slug| acct.login.eq_ignore_ascii_case(&format!("{slug}[bot]")))
}

/// What the VTC knows about `acct`, joined through account links (forge and
/// id, never login) to the member it belongs to.
async fn account_facts(
    state: &AppState,
    snap: &Snapshot,
    ns: &Namespace,
    repo: &Resource,
    acct: &ForgeAccount,
    settings: &PrGateSettings,
    members: &[crate::members::Member],
    t: DateTime<Utc>,
) -> OpResult<AccountFacts> {
    let mut facts = AccountFacts {
        exempt: settings.is_exempt(&acct.login),
        bridge: is_bridge_account(ns, acct),
        linked: None,
    };
    // An account on another forge than the namespace's is nobody's here.
    if acct.forge != ns.forge {
        return Ok(facts);
    }
    if let Some(m) = members
        .iter()
        .find(|m| bridge::holds_account(m, &acct.forge, &acct.id))
    {
        let standing = ops::standing(state, &m.did).await?;
        facts.linked = Some(LinkedFacts {
            member: standing.member,
            role: standing.role,
            rights: rules::effective_on(snap, &m.did, repo, t),
        });
    }
    Ok(facts)
}

/// `git-ns/bridge/event/0.4`, request step 6 — after the event has been
/// checked as the serving bridge's, inside its namespace. Called under the
/// git-ns store lock; it waits on nobody (the bridge's job versions are read
/// from what it last answered, never asked for here).
pub async fn on_pull_request_opened(
    state: &AppState,
    snap: &Snapshot,
    ns: &Namespace,
    repo: Option<&Repo>,
    pr: &PullRequestOpened,
) -> OpResult<()> {
    // 6.1: only an active repository in a bridge-mode namespace.
    let Some(repo) = repo.filter(|r| r.state == RepoState::Active && ns.mode == Mode::Bridge)
    else {
        debug!(resource = %pr.resource, "a pull request on a repository not active here; ignored");
        return Ok(());
    };
    let Some(repo_res) = repo.resource() else {
        return Ok(());
    };
    let settings = super::policy::active_pr_gate(state).await;
    let level = settings.level_for(&repo_res).clone();
    if level == PrOpenLevel::Anyone {
        return Ok(());
    }
    let t = now();
    let members = crate::members::list_members(&state.members_ks).await?;
    let author = account_facts(
        state, snap, ns, &repo_res, &pr.author, &settings, &members, t,
    )
    .await?;
    let actor = if pr.action == PrAction::Reopened {
        account_facts(
            state, snap, ns, &repo_res, &pr.actor, &settings, &members, t,
        )
        .await?
    } else {
        author.clone()
    };
    match decide(&level, pr.action, &author, &actor) {
        Verdict::Allowed => {
            debug!(resource = %repo.resource, number = pr.number, "pull request allowed");
            return Ok(());
        }
        Verdict::Override => {
            info!(
                resource = %repo.resource,
                number = pr.number,
                "a pull request reopened by an owner or maintainer is left open (override)"
            );
            return Ok(());
        }
        Verdict::Close => {}
    }
    let Some(bridge_did) = ns.bridge_did.clone() else {
        return Ok(());
    };
    // 6.4: never to a bridge that has not listed job 0.5. What it last said
    // decides here; a bridge not yet asked is asked by the dispatcher, which
    // drops the job if it says no.
    match bridge::cached_job_support(state, &bridge_did).await {
        Some(s) if !s.takes_v0_5 => {
            note_unenforced(state, &ns.id, &bridge_did).await;
            return Ok(());
        }
        Some(_) => clear_unenforced(state, &ns.id).await,
        None => {}
    }
    let (community, public_url) = match crate::community::load_profile(&state.community_ks).await {
        Ok(Some(p)) if !p.name.trim().is_empty() => (p.name, p.public_url),
        Ok(Some(p)) => ("this community".to_string(), p.public_url),
        _ => ("this community".to_string(), None),
    };
    let repo_name = format!(
        "{}/{}",
        repo_res.owner,
        repo_res.repo.clone().unwrap_or_default()
    );
    let hint = join_hint(
        settings.join_hint.as_deref(),
        &community,
        &repo_name,
        public_url.as_deref(),
    );
    let message = render_message(
        &settings.close_message,
        &MessageContext {
            author: &pr.author.login,
            repo: &repo_name,
            community: &community,
            join_hint: &hint,
        },
    );
    let queued = bridge::enqueue_close_pull_request(
        state,
        NewJob {
            namespace_id: ns.id.clone(),
            kind: JobKind::ClosePullRequest,
            payload: json!({
                "namespace": ns.id,
                "kind": "closePullRequest",
                "repo": repo.resource,
                "number": pr.number,
                "message": message,
            }),
            repo_id: Some(repo.id.clone()),
            link_id: None,
        },
        PullRequestClose {
            number: pr.number,
            author_login: pr.author.login.clone(),
            level: level.as_str().to_string(),
        },
    )
    .await?;
    if queued.is_some() {
        info!(
            resource = %repo.resource,
            number = pr.number,
            level = level.as_str(),
            "closing a pull request the pull-request policy does not allow"
        );
    }
    Ok(())
}

// ── the result ──────────────────────────────────────────────────────────────

/// A `closePullRequest` result (`git-ns/bridge/job/0.5`, request step 7). On
/// `succeeded` with `close` applied the close is audited as
/// `gitNs.pullRequest.closed` — the one record of a pull request this VTC
/// keeps. `unchanged` (already closed, or reopened since the job was issued)
/// records nothing; a failure is the job's own `failed` / `partial` state.
pub async fn record_close_result(state: &AppState, issuer: &str, job: &BridgeJob, steps: &[Value]) {
    let close = steps
        .iter()
        .find(|s| s.get("step").and_then(Value::as_str) == Some("close"))
        .and_then(|s| s.get("outcome").and_then(Value::as_str));
    match job.state {
        JobState::Succeeded => {
            clear_unenforced(state, &job.namespace_id).await;
            if close != Some("applied") {
                info!(
                    job_id = %job.job_id,
                    "the bridge found the pull request already closed or reopened since; nothing \
                     closed"
                );
                return;
            }
            let Some(pr) = &job.pull_request else {
                return;
            };
            audit(
                state,
                issuer,
                None,
                Audit {
                    action: "gitNs.pullRequest.closed",
                    namespace: Some(&job.namespace_id),
                    resource: job
                        .payload
                        .get("repo")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    right: None,
                    policy_version: None,
                    detail: Some(
                        json!({
                            "number": pr.number,
                            "author": pr.author_login,
                            "level": pr.level,
                        })
                        .to_string(),
                    ),
                },
            )
            .await;
        }
        _ => warn!(
            job_id = %job.job_id,
            error = ?job.last_error,
            "the bridge did not close a pull request the policy does not allow"
        ),
    }
}

// ── the bridge cannot enforce it ────────────────────────────────────────────

/// The record that a namespace's administrators were told its bridge cannot
/// close pull requests — kept so they are told once, not on every pull
/// request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnenforcedNotice {
    bridge_did: String,
    noticed_at: DateTime<Utc>,
}

fn notice_key(namespace_id: &str) -> String {
    format!("prgate-unenforced:{namespace_id}")
}

/// Tell the namespace's administrators, once, that its pull-request policy is
/// configured but its bridge does not take `git-ns/bridge/job` 0.5 and so
/// cannot close anything (request step 6.4: "the VTC SHOULD tell its operator
/// so rather than let the policy appear to be enforced"). An activity row
/// (`gitNs.pullRequest.gateUnenforced`) and a warning in the log; told again
/// only after the bridge has once taken 0.5 and then stopped.
///
/// Never takes the git-ns store lock: the event handler calls it holding it.
pub async fn note_unenforced(state: &AppState, namespace_id: &str, bridge_did: &str) {
    let ks = &state.git_ns.jobs_ks;
    let key = notice_key(namespace_id);
    if matches!(ks.get::<UnenforcedNotice>(key.clone()).await, Ok(Some(_))) {
        return;
    }
    let notice = UnenforcedNotice {
        bridge_did: bridge_did.to_string(),
        noticed_at: now(),
    };
    if let Err(e) = ks.insert(key, &notice).await {
        warn!(error = %e, "could not record the pull-request gate notice");
    }
    warn!(
        namespace = %namespace_id,
        bridge = %bridge_did,
        "the pull-request policy is configured but the bridge does not take \
         git-ns/bridge/job 0.5, so it cannot close pull requests; upgrade the bridge"
    );
    let resource = super::store::get_namespace(&state.git_ns.ks, namespace_id)
        .await
        .ok()
        .flatten()
        .map(|ns| ns.resource().to_string());
    audit(
        state,
        bridge_did,
        None,
        Audit {
            action: "gitNs.pullRequest.gateUnenforced",
            namespace: Some(namespace_id),
            resource,
            right: None,
            policy_version: None,
            detail: Some("bridgeLacksJob0.5".into()),
        },
    )
    .await;
}

/// The bridge takes 0.5 (again): a later loss of it is told again.
pub async fn clear_unenforced(state: &AppState, namespace_id: &str) {
    let _ = state.git_ns.jobs_ks.remove(notice_key(namespace_id)).await;
}

/// Whether a namespace's administrators have been told its bridge cannot
/// enforce the pull-request policy, and not since seen it take job 0.5.
#[cfg(test)]
pub(crate) async fn is_unenforced(state: &AppState, namespace_id: &str) -> bool {
    matches!(
        state
            .git_ns
            .jobs_ks
            .get::<UnenforcedNotice>(notice_key(namespace_id))
            .await,
        Ok(Some(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linked(member: bool, role: &str, rights: &[Right]) -> AccountFacts {
        AccountFacts {
            linked: Some(LinkedFacts {
                member,
                role: Some(role.into()),
                rights: rights.iter().copied().collect(),
            }),
            ..AccountFacts::default()
        }
    }

    fn unlinked() -> AccountFacts {
        AccountFacts::default()
    }

    fn opened(level: &PrOpenLevel, author: &AccountFacts) -> Verdict {
        decide(level, PrAction::Opened, author, author)
    }

    #[test]
    fn anyone_allows_everybody_including_the_unlinked() {
        assert_eq!(opened(&PrOpenLevel::Anyone, &unlinked()), Verdict::Allowed);
    }

    #[test]
    fn an_unlinked_account_is_allowed_only_under_anyone() {
        for level in [
            PrOpenLevel::Members,
            PrOpenLevel::Committers,
            PrOpenLevel::Maintainers,
            PrOpenLevel::Roles(vec!["member".into()]),
        ] {
            assert_eq!(opened(&level, &unlinked()), Verdict::Close, "{level:?}");
        }
    }

    #[test]
    fn members_needs_a_current_member() {
        let l = PrOpenLevel::Members;
        assert_eq!(opened(&l, &linked(true, "member", &[])), Verdict::Allowed);
        assert_eq!(opened(&l, &linked(false, "member", &[])), Verdict::Close);
    }

    #[test]
    fn committers_needs_commit_sign_explicit_or_implied() {
        let l = PrOpenLevel::Committers;
        assert_eq!(opened(&l, &linked(true, "member", &[])), Verdict::Close);
        assert_eq!(
            opened(&l, &linked(true, "member", &[Right::CommitSign])),
            Verdict::Allowed
        );
    }

    #[test]
    fn maintainers_needs_maintain_or_higher() {
        let l = PrOpenLevel::Maintainers;
        assert_eq!(
            opened(&l, &linked(true, "member", &[Right::CommitSign])),
            Verdict::Close
        );
        assert_eq!(
            opened(
                &l,
                &linked(true, "member", &[Right::RepoMaintain, Right::CommitSign])
            ),
            Verdict::Allowed
        );
    }

    #[test]
    fn roles_needs_a_member_holding_a_named_role() {
        let l = PrOpenLevel::Roles(vec!["moderator".into(), "custom:reviewer".into()]);
        assert_eq!(opened(&l, &linked(true, "member", &[])), Verdict::Close);
        assert_eq!(
            opened(&l, &linked(true, "moderator", &[])),
            Verdict::Allowed
        );
        assert_eq!(
            opened(&l, &linked(true, "custom:reviewer", &[])),
            Verdict::Allowed
        );
        // The role, but not a member (an application entry, a departure).
        assert_eq!(opened(&l, &linked(false, "moderator", &[])), Verdict::Close);
    }

    #[test]
    fn owners_maintainers_and_the_bridge_are_always_allowed() {
        let strict = PrOpenLevel::Roles(vec!["moderator".into()]);
        // An owner by implication (a namespace admin) holds own on the repo.
        let owner = linked(
            false,
            "member",
            &[Right::RepoOwn, Right::RepoMaintain, Right::CommitSign],
        );
        assert_eq!(opened(&strict, &owner), Verdict::Allowed);
        let maintainer = linked(true, "member", &[Right::RepoMaintain]);
        assert_eq!(opened(&strict, &maintainer), Verdict::Allowed);
        let bridge = AccountFacts {
            bridge: true,
            ..AccountFacts::default()
        };
        assert_eq!(opened(&strict, &bridge), Verdict::Allowed);
    }

    #[test]
    fn an_exempt_login_is_allowed_even_unlinked() {
        let exempt = AccountFacts {
            exempt: true,
            ..AccountFacts::default()
        };
        assert_eq!(opened(&PrOpenLevel::Maintainers, &exempt), Verdict::Allowed);
    }

    #[test]
    fn a_reopen_by_an_owner_or_maintainer_is_an_override() {
        let l = PrOpenLevel::Committers;
        let author = unlinked();
        let maintainer = linked(true, "member", &[Right::RepoMaintain, Right::CommitSign]);
        assert_eq!(
            decide(&l, PrAction::Reopened, &author, &maintainer),
            Verdict::Override
        );
        let bridge = AccountFacts {
            bridge: true,
            ..AccountFacts::default()
        };
        assert_eq!(
            decide(&l, PrAction::Reopened, &author, &bridge),
            Verdict::Override
        );
    }

    #[test]
    fn a_reopen_by_anyone_else_re_checks_the_author() {
        let l = PrOpenLevel::Committers;
        // A committer who is not a maintainer reopens an outsider's PR: the
        // outsider is checked again, and closed again.
        let committer = linked(true, "member", &[Right::CommitSign]);
        assert_eq!(
            decide(&l, PrAction::Reopened, &unlinked(), &committer),
            Verdict::Close
        );
        // The author reopening their own allowed PR is not refused for being
        // a reopen.
        assert_eq!(
            decide(&l, PrAction::Reopened, &committer, &committer),
            Verdict::Allowed
        );
        // An opening is never an override, whoever the actor is.
        let owner = linked(true, "member", &[Right::RepoOwn, Right::RepoMaintain]);
        assert_eq!(
            decide(&l, PrAction::Opened, &unlinked(), &owner),
            Verdict::Close
        );
    }

    // ── settings ──

    #[test]
    fn the_defaults_change_nothing() {
        let (s, problems) = PrGateSettings::from_settings(None);
        assert!(problems.is_empty());
        assert_eq!(s, PrGateSettings::default());
        assert_eq!(s.pr_open, PrOpenLevel::Anyone);
        assert!(!s.is_configured());
        assert_eq!(s.exempt, vec!["dependabot[bot]".to_string()]);
        assert!(s.close_message.contains("{join_hint}"));
    }

    #[test]
    fn every_level_and_its_overrides_are_read() {
        let (s, problems) = PrGateSettings::from_settings(Some(&json!({
            "pr_open": "committers",
            "pr_open_overrides": {
                "github.com/Acme": "members",
                "github.com/acme/widgets": { "roles": ["moderator", "custom:reviewer"] },
            },
            "pr_close_message": "Closed, {author}.",
            "pr_join_hint": "Join {community}.",
            "pr_exempt": ["renovate[bot]"],
        })));
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(s.pr_open, PrOpenLevel::Committers);
        let widgets = Resource::parse("github.com/acme/widgets").unwrap();
        let gadgets = Resource::parse("github.com/acme/gadgets").unwrap();
        let other = Resource::parse("github.com/other/x").unwrap();
        assert_eq!(
            s.level_for(&widgets),
            &PrOpenLevel::Roles(vec!["moderator".into(), "custom:reviewer".into()])
        );
        assert_eq!(s.level_for(&gadgets), &PrOpenLevel::Members);
        assert_eq!(s.level_for(&other), &PrOpenLevel::Committers);
        assert_eq!(s.exempt, vec!["renovate[bot]".to_string()]);
        assert!(s.is_exempt("Renovate[BOT]"));
        assert_eq!(s.join_hint.as_deref(), Some("Join {community}."));
    }

    #[test]
    fn an_unreadable_value_keeps_its_default_and_is_reported() {
        let (s, problems) = PrGateSettings::from_settings(Some(&json!({
            "pr_open": "maintainer",
            "pr_open_overrides": { "not a resource": "members", "github.com/acme": "nobody" },
            "pr_close_message": "",
            "pr_exempt": "dependabot[bot]",
        })));
        assert_eq!(s, PrGateSettings::default());
        assert_eq!(problems.len(), 5, "{problems:?}");
        let (s, problems) =
            PrGateSettings::from_settings(Some(&json!({ "pr_open": { "roles": [] } })));
        assert_eq!(s.pr_open, PrOpenLevel::Anyone);
        assert_eq!(problems.len(), 1);
        let (_, problems) =
            PrGateSettings::from_settings(Some(&json!({ "pr_open": { "roles": ["wizard"] } })));
        assert_eq!(problems.len(), 1);
        let (_, problems) = PrGateSettings::from_settings(Some(
            &json!({ "pr_open": { "roles": ["member"], "extra": 1 } }),
        ));
        assert_eq!(problems.len(), 1);
    }

    // ── the message ──

    fn ctx<'a>(author: &'a str, hint: &'a str) -> MessageContext<'a> {
        MessageContext {
            author,
            repo: "acme/widgets",
            community: "Acme Builders",
            join_hint: hint,
        }
    }

    #[test]
    fn the_default_message_renders_every_placeholder() {
        let hint = join_hint(None, "Acme Builders", "acme/widgets", None);
        let m = render_message(DEFAULT_CLOSE_MESSAGE, &ctx("eve-dev", &hint));
        assert!(m.contains("Hi eve-dev"), "{m}");
        assert!(m.contains("**acme/widgets**"), "{m}");
        assert!(m.contains("Acme Builders has approved"), "{m}");
        assert!(m.contains("become a member of Acme Builders"), "{m}");
        assert!(!m.contains('{'), "{m}");
    }

    #[test]
    fn the_join_hint_uses_the_public_url_or_the_communitys_own() {
        let h = join_hint(None, "Acme", "acme/w", Some("https://acme.example/join"));
        assert!(h.contains("join Acme at https://acme.example/join"), "{h}");
        let h = join_hint(
            Some("Ask in #{community} about {repo}."),
            "Acme",
            "acme/w",
            None,
        );
        assert_eq!(h, "Ask in #Acme about acme/w.");
    }

    #[test]
    fn rendering_is_one_pass_and_unknown_placeholders_stay() {
        let m = render_message(
            "{author} {did} {community} {unclosed",
            &MessageContext {
                author: "eve",
                repo: "r",
                community: "{author}",
                join_hint: "",
            },
        );
        // A value is never scanned again, and nothing else is filled in.
        assert_eq!(m, "eve {did} {author} {unclosed");
    }

    #[test]
    fn a_login_that_is_not_a_login_is_not_rendered() {
        let m = render_message("Hi {author}.", &ctx("[x](https://evil)", ""));
        assert_eq!(m, "Hi there.");
        let m = render_message("Hi {author}.", &ctx("dependabot[bot]", ""));
        assert_eq!(m, "Hi dependabot[bot].");
    }

    #[test]
    fn the_message_is_capped_at_the_jobs_limit() {
        let long = "x".repeat(MAX_MESSAGE_CHARS + 50);
        let m = render_message(&long, &ctx("eve", ""));
        assert_eq!(m.chars().count(), MAX_MESSAGE_CHARS);
    }
}
