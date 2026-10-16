//! What this community's entry at its VTA must hold for the rooms it owns, and the `pnm`
//! commands that fix it — filled in with this VTC's own DID and contexts, so an
//! administrator can paste them (`docs/03-vtc/community-rooms.md`, *Troubleshooting*).
//!
//! # Why the entry must cover the context holding the VTC's DID
//!
//! The VTA acts on a community room **as the community**: it founds the room's group with
//! the VTC's own DID as the owner's leaf, and signs the community's group changes as that
//! DID. It does so only for a persona the caller may act as — a DID it holds in a context
//! the caller's entry covers. Act scope covers a context and its descendants, never an
//! ancestor, so an entry scoped to the `[rooms.community]` context alone
//! (`vtc-test/rooms`) cannot act as a VTC whose DID lives in its parent (`vtc-test`), and
//! the VTA refuses with "… is not a persona you may act as". The entry has to cover both
//! the context holding the VTC's DID and the rooms context; scoping it to the first covers
//! a rooms context beneath it.
//!
//! # Where the commands are carried
//!
//! Not on the refusal. A `trust-task-error`'s `message` may not carry consumer-internal
//! state (framework *What a `message` May Not Say*) — a VTA context is exactly that — and
//! `keyHolderRefused`'s `details` admits only the VTA's own `code` and `message`. So the
//! filled-in commands ride the **list** read (`vtc/rooms/community/list`,
//! `ext["org.openvtc"].communityRooms.vtaAccess`), answered only to a holder of
//! `vtc.rooms.manage`, as [`Fix`]es each naming the refusals it answers ([`When`]). A
//! client given a refusal picks the first fix that matches it, and shows its commands;
//! the matching rules live here, once, and the clients (the console, `cnm rooms`) apply
//! them as data.
//!
//! # The VTC cannot see its entry
//!
//! Which fix applies is read off the VTA's refusal text where it says so ("DID not in
//! ACL", "does not carry the … capability", "no access to context", "not a persona you
//! may act as"). Any other permission refusal gets every command, with a line on which
//! one applies.

use serde::Serialize;
use serde_json::{Value, json};

use crate::server::AppState;

/// The capabilities the community's own rooms use at its VTA: mint each room's DID,
/// issue its credentials, keep the community's own in the vault.
const ROOM_CAPABILITIES: &[&str] = &["key-mint", "credential-write", "vault-write"];

/// For `vta-account` storage: the community's DID consumes an external account.
const STORAGE_CAPABILITY: &str = "external-auth-use";

/// Said for the context holding the VTC's DID when the VTC does not record it.
pub const DID_CONTEXT_PLACEHOLDER: &str = "<the context holding the VTC's DID>";

/// Said for the rooms context when `[rooms.community]` is absent.
const ROOMS_CONTEXT_PLACEHOLDER: &str = "<the [rooms.community] context>";

/// What this VTC knows about its standing at its VTA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// The VTC's own DID — the subject of its entry at the VTA.
    pub vtc_did: String,
    /// `vta_did`, when set.
    pub vta_did: Option<String>,
    /// `vta_context`: the context at the VTA holding the VTC's DID. `None` for a
    /// configuration written before `vtc setup` recorded it.
    pub did_context: Option<String>,
    /// `[rooms.community] context`, when community rooms are on.
    pub rooms_context: Option<String>,
    /// The contexts of `vta-account` storage configs not retired: the entry acts in
    /// them too.
    pub account_contexts: Vec<String>,
}

impl Facts {
    /// Read from the running configuration and the storage configs. `None` while the
    /// VTC has no DID: there is no entry to speak of.
    pub async fn read(state: &AppState) -> Option<Self> {
        let (vtc_did, vta_did, did_context, rooms_context) = {
            let config = state.config.read().await;
            (
                config.vtc_did.clone().filter(|d| !d.is_empty())?,
                config.vta_did.clone().filter(|d| !d.is_empty()),
                config.vta_context.clone().filter(|c| !c.is_empty()),
                config.rooms.community.as_ref().map(|c| c.context.clone()),
            )
        };
        let mut account_contexts = Vec::new();
        match state.room_storage.configs().await {
            Ok(configs) => {
                for c in &configs {
                    if crate::rooms::storage_configs::state_of(c) == "retired"
                        || c["auth"]["mode"] != "vta-account"
                    {
                        continue;
                    }
                    if let Some(ctx) = c["auth"]["context"].as_str().filter(|s| !s.is_empty()) {
                        account_contexts.push(ctx.to_string());
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "could not read storage configs for the VTA fix"),
        }
        Some(Self {
            vtc_did,
            vta_did,
            did_context,
            rooms_context,
            account_contexts,
        })
    }

    /// Whether the rooms context is the context holding the VTC's DID or beneath it —
    /// `None` when either is unknown.
    pub fn rooms_context_inside(&self) -> Option<bool> {
        Some(vta_sdk::context_path::is_ancestor_or_self(
            self.did_context.as_deref()?,
            self.rooms_context.as_deref()?,
        ))
    }

    /// The contexts the entry needs, fewest first: the one holding the VTC's DID, then
    /// any of the rooms and storage contexts it does not already cover.
    pub fn contexts(&self) -> Vec<String> {
        let mut wanted: Vec<String> = vec![
            self.did_context
                .clone()
                .unwrap_or_else(|| DID_CONTEXT_PLACEHOLDER.to_string()),
        ];
        let rest = self
            .rooms_context
            .iter()
            .chain(self.account_contexts.iter());
        for c in rest {
            let covered = wanted
                .iter()
                .any(|w| vta_sdk::context_path::is_ancestor_or_self(w, c));
            if !covered {
                wanted.push(c.clone());
            }
        }
        // A later context may cover an earlier one only among the known ones; drop any
        // so covered, keeping the order.
        let all = wanted.clone();
        wanted.retain(|c| {
            !all.iter()
                .any(|o| o != c && vta_sdk::context_path::is_ancestor_or_self(o, c))
        });
        wanted
    }

    fn capabilities(&self) -> String {
        let mut caps: Vec<&str> = ROOM_CAPABILITIES.to_vec();
        if !self.account_contexts.is_empty() {
            caps.push(STORAGE_CAPABILITY);
        }
        caps.join(",")
    }

    /// The context `pnm acl list --context` reads: the one holding the VTC's DID, else
    /// the rooms context.
    fn list_context(&self) -> String {
        self.did_context
            .clone()
            .or_else(|| self.rooms_context.clone())
            .unwrap_or_else(|| DID_CONTEXT_PLACEHOLDER.to_string())
    }
}

/// A word as a POSIX shell reads it: bare when it is plainly safe, else quoted.
fn shell_word(s: &str) -> String {
    let plain = !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/%@,+=".contains(&b));
    if plain {
        s.to_string()
    } else if !s.contains('"') && !s.contains('$') && !s.contains('`') && !s.contains('\\') {
        format!("\"{s}\"")
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// One command, and what it is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Command {
    pub purpose: String,
    pub command: String,
}

/// Which refusal a [`Fix`] answers: a `vtc/rooms/community/*` refusal whose code ends in
/// `:<refusal>`, and — when `message_contains` is not empty — whose `message` (which, for
/// `keyHolderRefused`, carries the VTA's own code and message) contains one of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct When {
    pub refusal: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub message_contains: Vec<&'static str>,
}

/// The `pnm` commands for one way the community's entry at its VTA can be wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Fix {
    /// `noEntry`, `scope`, `capability` or `permission`.
    pub id: &'static str,
    pub when: Vec<When>,
    /// What is wrong, in a line.
    pub summary: String,
    pub commands: Vec<Command>,
    /// Who runs them, and what to keep in mind.
    pub note: String,
    /// The command that shows the result.
    pub check: String,
}

impl Fix {
    /// Whether this fix answers the refusal `code` with `message`.
    pub fn matches(&self, code: &str, message: &str) -> bool {
        let short = code.rsplit(':').next().unwrap_or(code);
        code.starts_with("vtc/rooms/community/")
            && self.when.iter().any(|w| {
                w.refusal == short
                    && (w.message_contains.is_empty()
                        || w.message_contains.iter().any(|m| message.contains(m)))
            })
    }

    /// The fix as plain text: the summary, each command on its own line, the check.
    pub fn to_text(&self) -> String {
        let mut out = format!("{}\n", self.summary);
        for c in &self.commands {
            out.push_str(&format!("  # {}\n  {}\n", c.purpose, c.command));
        }
        out.push_str(&format!("then check:\n  {}\n{}", self.check, self.note));
        out
    }
}

const NOT_IN_ACL: &[&str] = &["DID not in ACL", "ACL entry expired"];
const MISSING_CAPABILITY: &[&str] = &["capability"];
const OUT_OF_SCOPE: &[&str] = &[
    "no access to context",
    "persona you may act as",
    "persona you act as",
];
const PERMISSION: &[&str] = &[
    "refused: permissionDenied",
    "refused: forbidden",
    "refused: unauthorized",
    ":noAuthority",
];

/// Every fix, in the order a client tries them: the specific ones first, the catch-all
/// for a permission refusal the VTA did not explain last.
pub fn fixes(f: &Facts) -> Vec<Fix> {
    let did = shell_word(&f.vtc_did);
    let contexts = shell_word(&f.contexts().join(","));
    let caps = f.capabilities();
    let check = format!(
        "pnm acl list --context {} --direction any",
        shell_word(&f.list_context())
    );
    let at_vta = match &f.vta_did {
        Some(v) => format!("the community's VTA ({v})"),
        None => "the community's VTA".to_string(),
    };
    let who = format!("Run these with pnm as someone with admin at {at_vta}.");
    let rooms = f
        .rooms_context
        .clone()
        .unwrap_or_else(|| ROOMS_CONTEXT_PLACEHOLDER.to_string());
    let did_ctx = f
        .did_context
        .clone()
        .unwrap_or_else(|| DID_CONTEXT_PLACEHOLDER.to_string());
    let unknown_ctx = if f.did_context.is_none() {
        format!(
            " This VTC does not record which context holds its DID: replace \
             `{DID_CONTEXT_PLACEHOLDER}` (`pnm did-mgmt dids get {did}` at \
             the VTA shows it), and set `vta_context` in its config.toml so these commands \
             name it."
        )
    } else {
        String::new()
    };
    let keep_others = format!(
        " `--contexts` replaces the entry's list: keep any other context it needs (`pnm acl \
         get {did}` shows them)."
    );
    let create = Command {
        purpose: "give the VTC's DID an entry that may mint, issue and keep credentials".into(),
        command: format!(
            "pnm acl create --did {did} --role initiator --contexts {contexts} \
             --capabilities {caps} --label \"community (rooms)\""
        ),
    };
    let scope = Command {
        purpose: format!(
            "scope the entry to the context holding the VTC's DID ({did_ctx}), which covers \
             the rooms context ({rooms}) beneath it"
        ),
        command: format!("pnm acl update {did} --contexts {contexts}"),
    };
    let get = Command {
        purpose: "see the entry: its role, contexts and capabilities".into(),
        command: format!("pnm acl get {did}"),
    };
    let role = Command {
        purpose: "move it to initiator (skip if it already is)".into(),
        command: format!(
            "pnm acl change-role --did {did} --from <its current role> --to initiator"
        ),
    };
    let caps_cmd = Command {
        purpose: "let it hold what the community's rooms use".into(),
        command: format!("pnm acl update {did} --capabilities {caps}"),
    };
    let caps_note = " `--capabilities` sets exactly this list: add any other capability the VTC \
         uses at its VTA (such as `sign-jws` for an OpenID4VP verifier).";

    vec![
        Fix {
            id: "noEntry",
            when: vec![
                When {
                    refusal: "keyHolderRefused",
                    message_contains: NOT_IN_ACL.to_vec(),
                },
                // Turned on but not yet granted is the usual state after a `noKeyHolder`.
                When {
                    refusal: "noKeyHolder",
                    message_contains: vec![],
                },
            ],
            summary: "The VTC's DID needs an entry at its VTA that may mint DIDs, issue \
                      credentials and keep them, covering the context holding the VTC's DID \
                      and the rooms context."
                .into(),
            commands: vec![create],
            note: format!(
                "{who} If `pnm acl get {did}` shows an expired entry, `pnm acl delete {did}` \
                 first.{unknown_ctx}"
            ),
            check: check.clone(),
        },
        Fix {
            id: "scope",
            when: vec![When {
                refusal: "keyHolderRefused",
                message_contains: OUT_OF_SCOPE.to_vec(),
            }],
            summary: format!(
                "The VTC's entry at its VTA does not cover the context holding the VTC's own \
                 DID ({did_ctx}). The VTA acts as the community only for a DID in a context the \
                 entry covers, and a scope covers a context's descendants, never its parent."
            ),
            commands: vec![scope.clone()],
            note: format!("{who}{keep_others}{unknown_ctx}"),
            check: check.clone(),
        },
        Fix {
            id: "capability",
            when: vec![When {
                refusal: "keyHolderRefused",
                message_contains: MISSING_CAPABILITY.to_vec(),
            }],
            summary: format!(
                "The VTC's entry at its VTA lacks a capability the community's rooms use \
                 ({caps}); the role that carries them is initiator."
            ),
            commands: vec![get.clone(), role.clone(), caps_cmd.clone()],
            note: format!("{who}{caps_note}"),
            check: check.clone(),
        },
        Fix {
            id: "permission",
            when: vec![When {
                refusal: "keyHolderRefused",
                message_contains: PERMISSION.to_vec(),
            }],
            summary: "The community's VTA refused for lack of permission. Read the VTC's entry \
                      first: no entry — create it; its contexts miss the one holding the VTC's \
                      DID — update them; its role is not initiator — change it."
                .into(),
            commands: vec![
                get,
                create_from(&did, &contexts, &caps),
                scope,
                role,
                caps_cmd,
            ],
            note: format!("{who}{keep_others}{caps_note}{unknown_ctx}"),
            check,
        },
    ]
}

fn create_from(did: &str, contexts: &str, caps: &str) -> Command {
    Command {
        purpose: "if it has no entry".into(),
        command: format!(
            "pnm acl create --did {did} --role initiator --contexts {contexts} \
             --capabilities {caps} --label \"community (rooms)\""
        ),
    }
}

/// The fix for a refusal, when one applies.
pub fn fix_for(f: &Facts, code: &str, message: &str) -> Option<Fix> {
    fixes(f).into_iter().find(|x| x.matches(code, message))
}

/// `ext["org.openvtc"].communityRooms.vtaAccess` on the list: what the VTC knows, a
/// warning when its configuration looks wrong, and every fix.
pub fn list_ext(f: &Facts) -> Value {
    let mut v = json!({
        "vtcDid": f.vtc_did,
        "contexts": f.contexts(),
        "fixes": fixes(f),
    });
    if let Some(d) = &f.did_context {
        v["vtcDidContext"] = json!(d);
    }
    if let Some(r) = &f.rooms_context {
        v["roomsContext"] = json!(r);
    }
    if let Some(inside) = f.rooms_context_inside() {
        v["roomsContextInside"] = json!(inside);
    }
    if let Some(w) = warning(f) {
        v["warning"] = json!(w);
    }
    v
}

/// What looks wrong in the configuration, said once on the list.
pub fn warning(f: &Facts) -> Option<String> {
    let rooms = f.rooms_context.as_deref()?;
    let contexts = shell_word(&f.contexts().join(","));
    let did = shell_word(&f.vtc_did);
    match (&f.did_context, f.rooms_context_inside()) {
        (None, _) => Some(format!(
            "This VTC does not record which context at its VTA holds its DID (`vta_context` in \
             config.toml). The VTC's entry there must cover that context as well as `{rooms}`: \
             an entry scoped to `{rooms}` alone cannot act as the community when its DID lives \
             in a parent context. Set `vta_context` so the commands below name it."
        )),
        (Some(d), Some(false)) => Some(format!(
            "`[rooms.community] context` (`{rooms}`) is not inside `{d}`, the context holding \
             this VTC's DID, so the VTC's entry at its VTA must name both: `pnm acl update \
             {did} --contexts {contexts}`. A rooms context beneath `{d}` needs only `{d}`."
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VTC: &str = "did:webvh:QmScid:example.com:test-vtc";

    fn facts(did_ctx: Option<&str>, rooms: Option<&str>, accounts: &[&str]) -> Facts {
        Facts {
            vtc_did: VTC.into(),
            vta_did: Some("did:webvh:QmVta:vta.example.com".into()),
            did_context: did_ctx.map(String::from),
            rooms_context: rooms.map(String::from),
            account_contexts: accounts.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn command_of(fix: &Fix, prefix: &str) -> String {
        fix.commands
            .iter()
            .find(|c| c.command.starts_with(prefix))
            .unwrap_or_else(|| panic!("no `{prefix}` command in {fix:?}"))
            .command
            .clone()
    }

    /// The case that prompted this: the entry scoped to `vtc-test/rooms`, the VTC's DID
    /// in `vtc-test`, and the VTA refusing the founding leaf.
    #[test]
    fn a_persona_refusal_names_the_context_holding_the_vtc_did() {
        let f = facts(Some("vtc-test"), Some("vtc-test/rooms"), &[]);
        let message = format!(
            "the community's VTA refused: permissionDenied `{VTC}` is not a persona you may act \
             as, so it cannot be the owner's leaf in room `did:webvh:x`. Name a DID this agent \
             minted for you in a context you act in"
        );
        let fix = fix_for(&f, "vtc/rooms/community/create:keyHolderRefused", &message).unwrap();
        assert_eq!(fix.id, "scope");
        assert_eq!(
            command_of(&fix, "pnm acl update"),
            format!("pnm acl update {VTC} --contexts vtc-test")
        );
        assert_eq!(fix.check, "pnm acl list --context vtc-test --direction any");
        assert!(fix.note.contains("admin at the community's VTA"));
        assert_eq!(f.rooms_context_inside(), Some(true));
        assert_eq!(
            warning(&f),
            None,
            "a rooms context beneath the DID's is right"
        );
    }

    #[test]
    fn no_entry_is_answered_with_create() {
        let f = facts(Some("vtc"), Some("vtc"), &[]);
        let message =
            format!("the community's VTA refused: permissionDenied DID not in ACL: {VTC}");
        let fix = fix_for(
            &f,
            "vtc/rooms/community/members/add:keyHolderRefused",
            &message,
        )
        .unwrap();
        assert_eq!(fix.id, "noEntry");
        assert_eq!(
            command_of(&fix, "pnm acl create"),
            format!(
                "pnm acl create --did {VTC} --role initiator --contexts vtc --capabilities \
                 key-mint,credential-write,vault-write --label \"community (rooms)\""
            )
        );
        // `noKeyHolder` gets the same entry to add.
        let setup = fix_for(&f, "vtc/rooms/community/create:noKeyHolder", "anything").unwrap();
        assert_eq!(setup.id, "noEntry");
    }

    #[test]
    fn vta_account_storage_adds_its_capability_and_any_context_not_covered() {
        let f = facts(
            Some("vtc-test"),
            Some("vtc-test/rooms"),
            &["vtc-test", "storage"],
        );
        let fix = fix_for(
            &f,
            "vtc/rooms/community/create:keyHolderRefused",
            "the community's VTA refused: permissionDenied DID not in ACL: x",
        )
        .unwrap();
        assert!(
            command_of(&fix, "pnm acl create").contains(
                "--contexts vtc-test,storage --capabilities \
                 key-mint,credential-write,vault-write,external-auth-use"
            ),
            "{fix:?}"
        );
    }

    #[test]
    fn a_missing_capability_moves_the_role_and_sets_the_capabilities() {
        let f = facts(Some("vtc"), Some("vtc"), &[]);
        let message = "the community's VTA refused: permissionDenied vault receive denied: \
                       did:x does not carry the CredentialWrite capability";
        let fix = fix_for(&f, "vtc/rooms/community/create:keyHolderRefused", message).unwrap();
        assert_eq!(fix.id, "capability");
        assert_eq!(
            command_of(&fix, "pnm acl change-role"),
            format!("pnm acl change-role --did {VTC} --from <its current role> --to initiator")
        );
        assert_eq!(
            command_of(&fix, "pnm acl update"),
            format!("pnm acl update {VTC} --capabilities key-mint,credential-write,vault-write")
        );
    }

    #[test]
    fn an_unexplained_permission_refusal_gets_every_command() {
        let f = facts(Some("vtc"), Some("vtc/rooms"), &[]);
        let fix = fix_for(
            &f,
            "vtc/rooms/community/members/remove:keyHolderRefused",
            "the community's VTA refused: permissionDenied something else",
        )
        .unwrap();
        assert_eq!(fix.id, "permission");
        for p in [
            "pnm acl get",
            "pnm acl create",
            "pnm acl update",
            "pnm acl change-role",
        ] {
            command_of(&fix, p);
        }
        assert!(fix.summary.contains("Read the VTC's entry first"));
    }

    #[test]
    fn a_refusal_that_is_not_about_permission_gets_no_fix() {
        let f = facts(Some("vtc"), Some("vtc"), &[]);
        assert!(
            fix_for(
                &f,
                "vtc/rooms/community/create:keyHolderRefused",
                "the community's VTA refused: malformedRequest bad template"
            )
            .is_none()
        );
        assert!(fix_for(&f, "vtc/rooms/community/create:keyHolderUnavailable", "").is_none());
        assert!(fix_for(&f, "permissionDenied", "DID not in ACL").is_none());
    }

    #[test]
    fn an_unrecorded_did_context_is_a_placeholder_and_keeps_the_rooms_context() {
        let f = facts(None, Some("vtc-test/rooms"), &[]);
        assert_eq!(
            f.contexts(),
            vec![DID_CONTEXT_PLACEHOLDER.to_string(), "vtc-test/rooms".into()]
        );
        let fix = &fixes(&f)[1];
        assert_eq!(
            command_of(fix, "pnm acl update"),
            format!("pnm acl update {VTC} --contexts \"{DID_CONTEXT_PLACEHOLDER},vtc-test/rooms\"")
        );
        assert!(fix.note.contains("vta_context"));
        assert!(warning(&f).unwrap().contains("vta_context"));
        assert_eq!(
            fix.check,
            "pnm acl list --context vtc-test/rooms --direction any"
        );
    }

    #[test]
    fn a_rooms_context_outside_the_did_context_is_warned_about_and_named() {
        let f = facts(Some("vtc-test"), Some("rooms"), &[]);
        assert_eq!(f.rooms_context_inside(), Some(false));
        assert_eq!(f.contexts(), vec!["vtc-test".to_string(), "rooms".into()]);
        let w = warning(&f).unwrap();
        assert!(
            w.contains(&format!("pnm acl update {VTC} --contexts vtc-test,rooms")),
            "{w}"
        );
        let ext = list_ext(&f);
        assert_eq!(ext["roomsContextInside"], false);
        assert_eq!(ext["fixes"].as_array().unwrap().len(), 4);
        assert_eq!(ext["fixes"][1]["when"][0]["refusal"], "keyHolderRefused");
    }

    #[test]
    fn the_text_form_carries_every_command() {
        let f = facts(Some("vtc"), Some("vtc"), &[]);
        let fix = &fixes(&f)[3];
        let text = fix.to_text();
        for c in &fix.commands {
            assert!(text.contains(&c.command));
        }
        assert!(text.contains(&fix.check));
    }

    #[test]
    fn shell_words_are_quoted_only_when_needed() {
        assert_eq!(
            shell_word("did:webvh:Qm:a.b:c%3A8"),
            "did:webvh:Qm:a.b:c%3A8"
        );
        assert_eq!(shell_word("a b"), "\"a b\"");
        assert_eq!(shell_word("a$b"), "'a$b'");
        assert_eq!(shell_word("it's $x"), r"'it'\''s $x'");
    }
}
