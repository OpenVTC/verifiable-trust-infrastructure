//! What this bridge is *allowed* to do, independent of what its VTA identity
//! could do.
//!
//! The VTA is the authority: every call is gated server-side on the bridge
//! identity's role, ACL, context scope and — where enabled — the approvals /
//! DTTE policy. This module is a **second, local** gate in front of it, and it
//! exists because of a specific gap in how MCP hosts grant permission.
//!
//! A host approves a *tool*, not a *call*. Once an operator answers "always
//! allow" to `vta_call`, every Trust Task URI the VTA serves is reachable with
//! no further prompt — `contexts/delete/1.0` on the same approval as
//! `contexts/list/1.0`. The host cannot tell those apart; it sees one tool
//! name. So the per-operation decision has to be made here, where the URI is
//! known.
//!
//! Three mechanisms, cheapest first:
//!
//! 1. **Risk classification** ([`Risk`]) — every Trust Task URI is read-only,
//!    mutating, sensitive, or destructive. Unknown verbs classify as
//!    [`Risk::Mutating`], never read-only: a URI this build has never heard of
//!    must not slip through `--read-only`.
//! 2. **Allow / deny globs** — operator-supplied slug patterns. Deny always
//!    wins; a non-empty allow list makes everything else denied.
//! 3. **Confirmation** — the risky tail is put back in front of a human via MCP
//!    elicitation, restoring per-call consent the host's per-tool approval gave
//!    away.
//!
//! The convenience tools route through the same gate under their canonical URI
//! (`sign` → `keys/sign/0.1`), so `--read-only` cannot be walked around by
//! calling `sign` instead of `vta_call`.

use std::fmt;

/// The Trust Task URI prefix every catalog entry carries. Patterns are written
/// against the **slug** — the part after this — so an operator types
/// `acl/*`, not the full URI.
pub const SPEC_PREFIX: &str = "https://trusttasks.org/spec/";

/// How much damage an operation can do, judged from the URI alone.
///
/// Deliberately coarse. This is a gate on *shape*, not a policy engine — the
/// VTA holds the policy engine, and duplicating it here would be a second
/// source of truth that drifts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Risk {
    /// Reads state. Safe to call on a whim; the only class `--read-only`
    /// permits.
    ReadOnly,
    /// Changes state additively and reversibly (create, update, register).
    Mutating,
    /// Exercises key authority, emits secret material, or moves authority
    /// between principals. Not destructive — but a compromised host calling
    /// these is the whole threat model.
    Sensitive,
    /// Removes something, or removes someone's access. Irreversible, or
    /// reversible only by an operator with more authority than the bridge.
    Destructive,
}

impl Risk {
    /// The lowercase name used in logs, audit records and the `vta_status`
    /// tool. Stable — external log processing keys on it.
    pub fn label(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::Mutating => "mutating",
            Self::Sensitive => "sensitive",
            Self::Destructive => "destructive",
        }
    }

    /// What a tool wrapping an operation of this class must declare as its MCP
    /// `readOnlyHint` / `destructiveHint`. Hosts render both and some gate on
    /// them, so a tool whose annotation disagrees with its operation's class is
    /// a security bug rather than a cosmetic one — which is what
    /// `server::tests::tool_annotations_agree_with_the_risk_classifier` pins.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by the annotation census test")
    )]
    pub fn hints(self) -> (bool, bool) {
        (self == Self::ReadOnly, self == Self::Destructive)
    }
}

impl fmt::Display for Risk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Slugs whose risk the verb alone gets wrong.
///
/// Every entry is here because the bare verb is shared with operations of a
/// different class: `acl/grant` and `contexts/create` are both "add a row", but
/// only one of them hands out authority.
const SLUG_OVERRIDES: &[(&str, Risk)] = &[
    // Key authority, exercised.
    ("keys/sign", Risk::Sensitive),
    ("keys/derive-and-sign", Risk::Sensitive),
    ("keys/derive-and-sign-document", Risk::Sensitive),
    ("keys/import", Risk::Sensitive),
    ("vault/sign-trust-task", Risk::Sensitive),
    // Secret material, emitted.
    ("vault/release", Risk::Sensitive),
    ("vault/proxy-login", Risk::Sensitive),
    ("vta/seeds/export-mnemonic", Risk::Sensitive),
    // Authority, moved.
    ("acl/grant", Risk::Sensitive),
    ("acl/update", Risk::Sensitive),
    ("acl/change-role", Risk::Sensitive),
    ("policy/upsert", Risk::Sensitive),
    ("config/patch", Risk::Sensitive),
    ("vta/credentials/issue", Risk::Sensitive),
    ("vta/passkey-vms/enroll-submit", Risk::Sensitive),
    ("did-management/registry/admin-register", Risk::Sensitive),
    ("did-management/domain/set-default", Risk::Sensitive),
    ("provision/integration", Risk::Sensitive),
    // Reads that a verb rule would misread.
    ("vta/contexts/preview-delete", Risk::ReadOnly),
    ("vta/webvh/agent-name/check", Risk::ReadOnly),
    ("trust-task-discovery", Risk::ReadOnly),
    // A backup export is a full-state dump — sensitive in both directions.
    ("vta/backup/initiate-export", Risk::Sensitive),
    ("vta/backup/complete-export", Risk::Sensitive),
];

/// Final-segment verbs that only ever read.
const READ_VERBS: &[&str] = &[
    "list",
    "get",
    "get-many",
    "show",
    "info",
    "whoami",
    "check",
    "check-name",
    "health",
    "query",
    "domains",
    "render",
    "report",
    "status",
    "ping",
    "explain",
    "get-retention",
    "approver-list",
];

/// Final-segment verbs that remove state or access.
const DESTRUCTIVE_VERBS: &[&str] = &[
    "delete",
    "purge",
    "remove",
    "revoke",
    "revoke-session",
    "wipe",
    "disable",
    "deregister",
    "unassign",
    "retire-orphan",
    "rollback",
    "rotate",
    "rotate-keys",
    "swap-key",
    "change-owner",
    "abort",
    "initiate-import",
    "finalize-import",
    "reload-services",
];

/// The slug of a Trust Task URI — the part after [`SPEC_PREFIX`], with the
/// trailing version segment removed. `…/spec/acl/grant/0.1` → `acl/grant`.
///
/// Returns `None` for anything that is not a versioned task URI, including the
/// bare family-namespace constants (`…/spec/acl/`), so callers can refuse
/// rather than guess.
pub fn slug_of(uri: &str) -> Option<&str> {
    let rest = uri.strip_prefix(SPEC_PREFIX)?;
    let (slug, version) = rest.rsplit_once('/')?;
    // A version segment is digits and dots; a trailing `/` leaves it empty.
    if version.is_empty() || !version.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return None;
    }
    (!slug.is_empty()).then_some(slug)
}

/// Classify a Trust Task URI.
///
/// Unknown verbs are [`Risk::Mutating`]. That is the safe default in both
/// directions: `--read-only` refuses them, and confirmation is not demanded for
/// something that may well be a harmless create. The census test below is what
/// stops "unknown" from becoming the common case as the catalog grows.
pub fn classify(uri: &str) -> Risk {
    let Some(slug) = slug_of(uri) else {
        // Not a task URI. The dispatcher will refuse it; classify high so a
        // read-only bridge does not pass it along on the way to that refusal.
        return Risk::Mutating;
    };
    if let Some((_, risk)) = SLUG_OVERRIDES.iter().find(|(s, _)| *s == slug) {
        return *risk;
    }
    let verb = slug.rsplit('/').next().unwrap_or(slug);
    if DESTRUCTIVE_VERBS.contains(&verb) {
        Risk::Destructive
    } else if READ_VERBS.contains(&verb) {
        Risk::ReadOnly
    } else {
        Risk::Mutating
    }
}

/// How much of the risky tail is put back in front of a human.
///
/// Cumulative: each level confirms everything the level below it confirms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConfirmLevel {
    /// Confirm nothing. The host's per-tool approval is the only gate.
    Never,
    /// Confirm [`Risk::Destructive`] only. The default — the host already
    /// prompts per tool, so this adds a prompt exactly where a tool-level
    /// approval is too coarse to be meaningful.
    #[default]
    Destructive,
    /// Also confirm [`Risk::Sensitive`] — signing, secret release, mnemonic
    /// export, ACL changes. The right setting for a bridge holding an operator
    /// session rather than a scoped agent identity.
    Sensitive,
    /// Confirm every call that changes anything. Read-only calls still run
    /// unprompted.
    Always,
}

impl ConfirmLevel {
    /// Parse the `--confirm` flag.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "never" | "none" | "off" => Ok(Self::Never),
            "destructive" => Ok(Self::Destructive),
            "sensitive" => Ok(Self::Sensitive),
            "always" | "all" => Ok(Self::Always),
            other => Err(format!(
                "unknown --confirm value '{other}' (expected never, destructive, sensitive or always)"
            )),
        }
    }

    /// The label used in logs and `vta_status`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Destructive => "destructive",
            Self::Sensitive => "sensitive",
            Self::Always => "always",
        }
    }

    fn wants(self, risk: Risk) -> bool {
        match self {
            Self::Never => false,
            Self::Destructive => risk == Risk::Destructive,
            Self::Sensitive => matches!(risk, Risk::Destructive | Risk::Sensitive),
            Self::Always => risk != Risk::ReadOnly,
        }
    }
}

/// What the guard decided about one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Run it.
    Allow,
    /// Run it only if a human says yes, using the carried prompt.
    Confirm(String),
    /// Refuse, with an operator-facing reason that names the flag which would
    /// have permitted it.
    Deny(String),
}

impl Decision {
    /// The label recorded in the audit log.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Confirm(_) => "confirm",
            Self::Deny(_) => "deny",
        }
    }
}

/// The operator-configured local policy.
#[derive(Debug, Clone, Default)]
pub struct Guard {
    /// Refuse anything that is not [`Risk::ReadOnly`].
    pub read_only: bool,
    /// Slug globs; when non-empty, a call must match one of these.
    pub allow: Vec<String>,
    /// Slug globs that are always refused, checked before `allow`.
    pub deny: Vec<String>,
    /// How much of the risky tail needs a human.
    pub confirm: ConfirmLevel,
}

impl Guard {
    /// Decide one call. `uri` is the canonical Trust Task URI — for the
    /// convenience tools, the URI they wrap.
    pub fn decide(&self, uri: &str) -> Decision {
        let risk = classify(uri);
        let slug = slug_of(uri).unwrap_or(uri);

        if let Some(p) = self.deny.iter().find(|p| glob_match(p, slug)) {
            return Decision::Deny(format!(
                "'{slug}' is denied by this bridge's --deny '{p}'. Remove that pattern to allow it."
            ));
        }
        if !self.allow.is_empty() && !self.allow.iter().any(|p| glob_match(p, slug)) {
            return Decision::Deny(format!(
                "'{slug}' is not in this bridge's --allow list ({}). Add it, or drop --allow to \
                 fall back to the risk rules.",
                self.allow.join(", ")
            ));
        }
        if self.read_only && risk != Risk::ReadOnly {
            return Decision::Deny(format!(
                "'{slug}' is {risk} and this bridge runs with --read-only. Restart it without \
                 --read-only to permit it."
            ));
        }
        if self.confirm.wants(risk) {
            return Decision::Confirm(format!("Approve {risk} VTA operation '{slug}'?"));
        }
        Decision::Allow
    }

    /// A one-line summary for the startup banner and `vta_status`.
    pub fn summary(&self) -> String {
        let mut parts = vec![format!("confirm={}", self.confirm.label())];
        if self.read_only {
            parts.push("read-only".into());
        }
        if !self.allow.is_empty() {
            parts.push(format!("allow=[{}]", self.allow.join(",")));
        }
        if !self.deny.is_empty() {
            parts.push(format!("deny=[{}]", self.deny.join(",")));
        }
        parts.join(" ")
    }
}

/// Slug-glob match, the same shape `vta_supported_tasks` patterns use: `*`
/// matches everything, a trailing `/*` matches a family, anything else is an
/// exact slug.
///
/// Deliberately not a full glob. A pattern language with more corners than this
/// is a pattern language an operator gets subtly wrong while believing they
/// denied something.
pub fn glob_match(pattern: &str, slug: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    match pattern.strip_suffix("/*") {
        // `acl/*` matches `acl/grant` but not `acl` itself.
        Some(prefix) => slug
            .strip_prefix(prefix)
            .is_some_and(|r| r.starts_with('/')),
        None => pattern == slug,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACL_GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";
    const CONTEXTS_LIST: &str = "https://trusttasks.org/spec/vta/contexts/list/1.0";
    const CONTEXTS_DELETE: &str = "https://trusttasks.org/spec/vta/contexts/delete/1.0";
    const KEYS_SIGN: &str = "https://trusttasks.org/spec/keys/sign/0.1";

    #[test]
    fn slug_strips_the_prefix_and_the_version() {
        assert_eq!(slug_of(ACL_GRANT), Some("acl/grant"));
        assert_eq!(slug_of(CONTEXTS_LIST), Some("vta/contexts/list"));
        assert_eq!(
            slug_of("https://trusttasks.org/spec/trust-task-discovery/0.1"),
            Some("trust-task-discovery")
        );
    }

    #[test]
    fn a_family_namespace_is_not_a_task() {
        // These constants exist in the SDK catalog module; treating one as a
        // task would classify it by a verb that is really a family name.
        assert_eq!(slug_of("https://trusttasks.org/spec/acl/"), None);
        assert_eq!(slug_of("https://trusttasks.org/spec/vta/"), None);
        assert_eq!(slug_of("not-a-uri"), None);
    }

    #[test]
    fn verbs_classify() {
        assert_eq!(classify(CONTEXTS_LIST), Risk::ReadOnly);
        assert_eq!(classify(CONTEXTS_DELETE), Risk::Destructive);
        assert_eq!(
            classify("https://trusttasks.org/spec/vta/contexts/create/1.0"),
            Risk::Mutating
        );
        assert_eq!(classify(KEYS_SIGN), Risk::Sensitive);
        assert_eq!(classify(ACL_GRANT), Risk::Sensitive);
    }

    #[test]
    fn preview_delete_is_a_read_not_a_delete() {
        // The verb ends in "delete" but the operation only reports what a
        // delete would remove. Substring matching on the verb would have made
        // a preview refuse under --read-only.
        assert_eq!(
            classify("https://trusttasks.org/spec/vta/contexts/preview-delete/1.0"),
            Risk::ReadOnly
        );
    }

    #[test]
    fn an_unknown_verb_is_mutating_never_read_only() {
        // The catalog grows without this crate. A URI it has never seen must
        // not be handed through a --read-only bridge.
        let unknown = "https://trusttasks.org/spec/vta/frobnicate/twiddle/9.9";
        assert_eq!(classify(unknown), Risk::Mutating);
        let guard = Guard {
            read_only: true,
            ..Guard::default()
        };
        assert!(matches!(guard.decide(unknown), Decision::Deny(_)));
    }

    /// Census: every URI the generic `vta_call` gateway can reach must classify
    /// off an override or a known verb. A new verb landing in the SDK catalog
    /// fails here rather than quietly defaulting to `Mutating` forever.
    #[test]
    fn every_dispatchable_uri_has_a_known_verb() {
        let mut unknown: Vec<&str> = Vec::new();
        for uri in vta_sdk::trust_tasks::dispatch_routed_uris() {
            let Some(slug) = slug_of(uri) else {
                unknown.push(uri);
                continue;
            };
            if SLUG_OVERRIDES.iter().any(|(s, _)| *s == slug) {
                continue;
            }
            let verb = slug.rsplit('/').next().unwrap_or(slug);
            let known = READ_VERBS.contains(&verb)
                || DESTRUCTIVE_VERBS.contains(&verb)
                || MUTATING_VERBS.contains(&verb);
            if !known {
                unknown.push(uri);
            }
        }
        assert!(
            unknown.is_empty(),
            "unclassified Trust Task verbs — add each to READ_VERBS, DESTRUCTIVE_VERBS, \
             MUTATING_VERBS or SLUG_OVERRIDES in guard.rs: {unknown:#?}"
        );
    }

    /// The verbs that are deliberately `Mutating`. Only the census test reads
    /// this — `classify` defaults to `Mutating` without consulting it, so a
    /// runtime miss is safe and a compile-time miss is loud.
    const MUTATING_VERBS: &[&str] = &[
        "create",
        "update",
        "update-did",
        "update-retention",
        "upsert",
        "put",
        "put-many",
        "register",
        "register-with-server",
        "admin-register",
        "enable",
        "set",
        "set-wake",
        "set-default",
        "assign",
        "receive",
        "archive",
        "unarchive",
        "restore",
        "heartbeat",
        "reconcile",
        "publish",
        "cancel",
        "decision",
        "request",
        "approver-set",
        "start",
        "finish",
        "approve-response",
        "enroll-challenge",
        "enroll-submit",
        "issue",
        "import",
        "sign",
        "sign-trust-task",
        "derive-and-sign",
        "derive-and-sign-document",
        "release",
        "proxy-login",
        "grant",
        "change-role",
        "patch",
        "integration",
        "problem-report",
        "stats-sync",
        "refresh",
        "authenticate",
        "challenge",
        "export-mnemonic",
        "initiate-export",
        "complete-export",
        "rename",
    ];

    #[test]
    fn deny_beats_allow() {
        let guard = Guard {
            allow: vec!["*".into()],
            deny: vec!["vta/contexts/*".into()],
            confirm: ConfirmLevel::Never,
            ..Guard::default()
        };
        assert!(matches!(guard.decide(CONTEXTS_LIST), Decision::Deny(_)));
        assert_eq!(guard.decide(ACL_GRANT), Decision::Allow);
    }

    #[test]
    fn a_non_empty_allow_list_denies_everything_else() {
        let guard = Guard {
            allow: vec!["vta/memory/*".into()],
            confirm: ConfirmLevel::Never,
            ..Guard::default()
        };
        assert_eq!(
            guard.decide("https://trusttasks.org/spec/vta/memory/list/0.1"),
            Decision::Allow
        );
        match guard.decide(CONTEXTS_LIST) {
            Decision::Deny(msg) => assert!(msg.contains("--allow"), "{msg}"),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn confirm_levels_are_cumulative() {
        let destructive = Guard::default();
        assert_eq!(destructive.confirm, ConfirmLevel::Destructive);
        assert_eq!(destructive.decide(KEYS_SIGN), Decision::Allow);
        assert!(matches!(
            destructive.decide(CONTEXTS_DELETE),
            Decision::Confirm(_)
        ));

        let sensitive = Guard {
            confirm: ConfirmLevel::Sensitive,
            ..Guard::default()
        };
        assert!(matches!(sensitive.decide(KEYS_SIGN), Decision::Confirm(_)));
        assert!(matches!(
            sensitive.decide(CONTEXTS_DELETE),
            Decision::Confirm(_)
        ));
        assert_eq!(sensitive.decide(CONTEXTS_LIST), Decision::Allow);

        let always = Guard {
            confirm: ConfirmLevel::Always,
            ..Guard::default()
        };
        // Even at `always`, reads run unprompted — a bridge that asks before
        // every `list` gets its prompts clicked through unread.
        assert_eq!(always.decide(CONTEXTS_LIST), Decision::Allow);
        assert!(matches!(
            always.decide("https://trusttasks.org/spec/vta/contexts/create/1.0"),
            Decision::Confirm(_)
        ));
    }

    #[test]
    fn globs_match_families_not_prefixes() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("acl/*", "acl/grant"));
        assert!(!glob_match("acl/*", "acl"));
        // `vault/*` must not swallow `vault-other/…`.
        assert!(!glob_match("vault/*", "vault-other/get"));
        assert!(glob_match("vault/credentials/get", "vault/credentials/get"));
        assert!(!glob_match("vault/credentials/get", "vault/credentials"));
    }

    #[test]
    fn confirm_level_parses_and_rejects() {
        assert_eq!(ConfirmLevel::parse("never").unwrap(), ConfirmLevel::Never);
        assert_eq!(
            ConfirmLevel::parse("SENSITIVE").unwrap(),
            ConfirmLevel::Sensitive
        );
        assert!(ConfirmLevel::parse("sometimes").is_err());
    }
}
