//! `pnm messaging console` — operate an Affinidi messaging mediator as a DID
//! this VTA manages.
//!
//! The console (`affinidi-messaging-mediator-tui`) authenticates to the
//! mediator, signs Trust Tasks and decrypts the mediator's replies, so it needs
//! the DID's private keys for the length of the session. The VTA has no remote
//! key-agreement operation, so the keys are **exported** — and per
//! VTI-VTA-003 that export is gated by `KeyExport` (a capability distinct
//! from using the key) and audited: each key goes through
//! `keys/export-secret`, never the context secrets bundle. Only the keys that
//! are verification methods of the DID are exported, the secrets live in this
//! process's memory only (zeroised on drop, never logged or written), and they
//! are gone when the console closes.
//!
//! The pnm session's own `did:key` is also offered: its key is already this
//! client's (VTI-CLT-002), so using it exports nothing.

use affinidi_messaging_mediator_admin::{
    AddressBook, ConsoleError, Identity, IdentityChoice, IdentitySource, MediatorConsole,
};
use affinidi_messaging_mediator_tui::{App, default_address_book_path};
use affinidi_secrets_resolver::secrets::Secret;
use async_trait::async_trait;
use vta_sdk::client::VtaClient;
use vta_sdk::did_secrets::select_secret_kid;

use affinidi_messaging_mediator_admin::account_hash;
use affinidi_messaging_mediator_admin::specs::account::update::v0_1::AccountType;

use crate::cli::{GrantRole, MessagingCommands};

/// The `IdentitySource` id for pnm's own session identity.
const SESSION_CHOICE: &str = "pnm-session";
/// Page size when walking a context's keys.
const KEY_PAGE: u64 = 100;

pub(crate) async fn run(
    client: &VtaClient,
    keyring_key: &str,
    mediator_hint: Option<&str>,
    command: MessagingCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        MessagingCommands::Grant {
            target,
            role,
            context,
            did,
            mediator,
            as_session,
        } => {
            if !target.starts_with("did:") {
                return Err(format!("{target} is not a DID").into());
            }
            let source = VtaIdentitySource {
                client,
                keyring_key: keyring_key.to_string(),
            };
            let choices = source.list().await?;
            let choice = choose(&choices, context.as_deref(), did.as_deref(), as_session)?;
            let console = connect(&source, &choice, mediator.as_deref(), mediator_hint).await?;
            if !console.capabilities().mediator_wide {
                return Err(format!(
                    "{} is a {:?} account at {}, and only an administrator can give an \
                     account a role. Act as the mediator's administrator (its admin_did).",
                    console.did(),
                    console.mode(),
                    console.mediator_did()
                )
                .into());
            }
            let hash = account_hash(&target);
            let updated = console
                .update_account(Some(hash.clone()), Some(account_type(role)), None, None)
                .await?;
            // Report what the mediator recorded, not what was asked: a
            // mediator that ignored the role would otherwise read as success.
            let recorded = serde_json::to_value(updated.account_type)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "unknown".into());
            println!("{target}");
            println!("  account {hash}");
            println!("  at      {}", console.mediator_did());
            println!("  is now  {recorded}");
            if recorded != grant_role_wire(role) {
                return Err(format!(
                    "the mediator recorded {recorded}, not {} — nothing else was changed",
                    grant_role_wire(role)
                )
                .into());
            }
            Ok(())
        }
        MessagingCommands::Console {
            context,
            did,
            mediator,
            as_session,
        } => {
            let source = VtaIdentitySource {
                client,
                keyring_key: keyring_key.to_string(),
            };
            let choices = source.list().await?;
            let choice = choose(&choices, context.as_deref(), did.as_deref(), as_session)?;
            let console = connect(&source, &choice, mediator.as_deref(), mediator_hint).await?;

            // The console's address book, with every DID this VTA can name
            // filled in (not saved: the VTA stays the source of those names,
            // and a name saved by hand wins).
            let book_path = default_address_book_path();
            let mut book = match &book_path {
                Some(path) => AddressBook::load(path)
                    .map_err(|e| format!("address book {}: {e}", path.display()))?,
                None => AddressBook::new(),
            };
            seed_address_book(client, &choices, &mut book).await;

            let mut terminal = ratatui::init();
            // Bracketed paste: a pasted DID arrives whole, not as keystrokes.
            let _ = ratatui::crossterm::execute!(
                std::io::stdout(),
                ratatui::crossterm::event::EnableBracketedPaste
            );
            let result = App::new(console)
                .with_address_book(book, book_path)
                .run(&mut terminal)
                .await;
            let _ = ratatui::crossterm::execute!(
                std::io::stdout(),
                ratatui::crossterm::event::DisableBracketedPaste
            );
            ratatui::restore();
            Ok(result?)
        }
    }
}

/// Connect to the mediator as `choice`: to `mediator` when given, else the
/// one in the DID's document, else the mediator this pnm is configured with.
async fn connect(
    source: &VtaIdentitySource<'_>,
    choice: &IdentityChoice,
    mediator: Option<&str>,
    mediator_hint: Option<&str>,
) -> Result<MediatorConsole, Box<dyn std::error::Error>> {
    let mut identity = source.load(choice).await?;
    identity.mediator_did = mediator.map(str::to_string);
    eprintln!("connecting to the mediator as {} …", identity.alias);
    match MediatorConsole::connect(identity.clone()).await {
        // No mediator given and none in the DID document: fall back to the
        // mediator this pnm is configured with.
        Err(ConsoleError::NoMediator(_)) if mediator.is_none() && mediator_hint.is_some() => {
            identity.mediator_did = mediator_hint.map(str::to_string);
            Ok(MediatorConsole::connect(identity).await?)
        }
        other => Ok(other?),
    }
}

fn account_type(role: GrantRole) -> AccountType {
    match role {
        GrantRole::Admin => AccountType::Admin,
        GrantRole::Standard => AccountType::Standard,
    }
}

/// The wire spelling the mediator reports a role in.
fn grant_role_wire(role: GrantRole) -> &'static str {
    match role {
        GrantRole::Admin => "admin",
        GrantRole::Standard => "standard",
    }
}

/// Pick the identity: `--as-session`; else the DIDs `--context` and `--did`
/// narrow to; else every context DID. One candidate is taken, several are
/// asked about.
fn choose(
    choices: &[IdentityChoice],
    context: Option<&str>,
    did: Option<&str>,
    as_session: bool,
) -> Result<IdentityChoice, Box<dyn std::error::Error>> {
    let choices = choices.to_vec();
    if as_session {
        return first(
            narrow(&choices, Some(SESSION_CHOICE), None),
            SESSION_CHOICE,
            None,
        );
    }
    let candidates = narrow(&choices, context, did);
    match candidates.len() {
        0 => first(candidates, context.unwrap_or("any context"), did),
        1 => Ok(candidates[0].clone()),
        // Asked about only when nothing narrowed the choice: the whole list,
        // pnm's own session included.
        _ if context.is_none() && did.is_none() => ask(&choices),
        _ => ask(&candidates.into_iter().cloned().collect::<Vec<_>>()),
    }
}

/// The choices in `context` (or any, the session aside) that are `did` (or
/// any DID).
fn narrow<'a>(
    choices: &'a [IdentityChoice],
    context: Option<&str>,
    did: Option<&str>,
) -> Vec<&'a IdentityChoice> {
    choices
        .iter()
        .filter(|c| match context {
            Some(context) => c.id == context,
            None => c.id != SESSION_CHOICE,
        })
        .filter(|c| did.is_none() || c.did.as_deref() == did)
        .collect()
}

fn first(
    candidates: Vec<&IdentityChoice>,
    context: &str,
    did: Option<&str>,
) -> Result<IdentityChoice, Box<dyn std::error::Error>> {
    candidates.first().map(|c| (*c).clone()).ok_or_else(|| {
        let what = match did {
            Some(did) => format!("{did} in {context}"),
            None => format!("'{context}'"),
        };
        format!(
            "no usable identity {what}: it must be a DID whose keys are in a context you may \
             act in, or --as-session"
        )
        .into()
    })
}

fn ask(choices: &[IdentityChoice]) -> Result<IdentityChoice, Box<dyn std::error::Error>> {
    let labels: Vec<String> = choices
        .iter()
        .map(|c| match &c.detail {
            Some(d) => format!("{}  ({d})", c.label),
            None => c.label.clone(),
        })
        .collect();
    let i = dialoguer::Select::new()
        .with_prompt("Open the mediator console as")
        .items(&labels)
        .default(0)
        .interact()?;
    Ok(choices[i].clone())
}

/// Name every DID this VTA can tell us about, for the console's address book.
/// Later sources override earlier ones for the same DID, so they go from the
/// least specific to the most:
///
/// 1. ACL entries: who may use this VTA, by their label (or role);
/// 2. webvh DIDs the VTA hosts, as `context · mnemonic`;
/// 3. the DIDs of this session's contexts (the console's identity choices), by
///    context name;
/// 4. the VTA itself and this pnm session.
///
/// A source this session may not read (ACLs need an admin) is skipped: naming
/// is a convenience and must never stop the console opening.
async fn seed_address_book(client: &VtaClient, choices: &[IdentityChoice], book: &mut AddressBook) {
    if let Ok(acl) = client.list_acl(None).await {
        for entry in acl.entries {
            let name = entry
                .label
                .filter(|l| !l.trim().is_empty())
                .unwrap_or_else(|| format!("{} (VTA access)", entry.role));
            book.know(&entry.did, &name);
        }
    }

    let context_names: std::collections::HashMap<String, String> = client
        .list_contexts()
        .await
        .map(|r| r.contexts.into_iter().map(|c| (c.id, c.name)).collect())
        .unwrap_or_default();
    if let Ok(webvh) = client.list_dids_webvh(None, None).await {
        for record in webvh.dids {
            let context = context_names
                .get(&record.context_id)
                .cloned()
                .unwrap_or_else(|| record.context_id.clone());
            let name = if record.mnemonic.trim().is_empty() {
                context
            } else {
                format!("{context} · {}", record.mnemonic)
            };
            book.know(&record.did, &name);
        }
    }

    for (did, name) in choice_names(choices) {
        book.know(&did, &name);
    }
    if let Some(vta) = client.vta_did() {
        book.know(vta, "VTA");
    }
}

/// A name for each identity choice's DID: its context's name, told apart by
/// the DID's last segment when a context holds several; `pnm session` for the
/// session's own `did:key`.
fn choice_names(choices: &[IdentityChoice]) -> Vec<(String, String)> {
    let mut per_label: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for c in choices {
        *per_label.entry(c.label.as_str()).or_default() += 1;
    }
    choices
        .iter()
        .filter_map(|c| {
            let did = c.did.clone()?;
            let name = if c.id == SESSION_CHOICE {
                "pnm session".to_string()
            } else if per_label.get(c.label.as_str()).copied().unwrap_or(0) > 1 {
                let tail = did.rsplit(':').next().unwrap_or(&did);
                let tail: String = tail.chars().take(16).collect();
                format!("{} · {tail}", c.label)
            } else {
                c.label.clone()
            };
            Some((did, name))
        })
        .collect()
}

/// The DIDs this pnm session may act as: every DID whose keys are in a
/// context it can see (a context's own DID first), and the session's own
/// `did:key`. Each choice's `id` is its context.
struct VtaIdentitySource<'a> {
    client: &'a VtaClient,
    keyring_key: String,
}

#[async_trait]
impl IdentitySource for VtaIdentitySource<'_> {
    async fn list(&self) -> affinidi_messaging_mediator_admin::Result<Vec<IdentityChoice>> {
        let contexts = self
            .client
            .list_contexts()
            .await
            .map_err(|e| ConsoleError::Identity(format!("listing contexts: {e}")))?;
        let mut choices = Vec::new();
        for c in contexts.contexts {
            let dids = self.context_dids(&c.id, c.did.as_deref()).await?;
            let several = dids.len() > 1;
            for did in dids {
                choices.push(IdentityChoice {
                    id: c.id.clone(),
                    label: c.name.clone(),
                    // With several DIDs in one context, the DID is what tells
                    // the choices apart.
                    detail: Some(if several {
                        format!("{did} — context {}", c.id)
                    } else {
                        format!("context {}", c.id)
                    }),
                    did: Some(did),
                });
            }
        }
        if let Some(session) = crate::auth::loaded_session(&self.keyring_key) {
            choices.push(IdentityChoice {
                id: SESSION_CHOICE.into(),
                label: "this pnm session".into(),
                detail: Some(session.client_did.clone()),
                did: Some(session.client_did),
            });
        }
        Ok(choices)
    }

    async fn load(
        &self,
        choice: &IdentityChoice,
    ) -> affinidi_messaging_mediator_admin::Result<Identity> {
        if choice.id == SESSION_CHOICE {
            return self.session_identity();
        }
        let did = choice
            .did
            .clone()
            .ok_or_else(|| ConsoleError::Identity(format!("context {} has no DID", choice.id)))?;
        let secrets = self.export_did_keys(&choice.id, &did).await?;
        Ok(Identity {
            alias: choice.label.clone(),
            did,
            secrets,
            mediator_did: None,
        })
    }
}

impl VtaIdentitySource<'_> {
    /// The DIDs whose keys are in `context_id`, read from the key records
    /// alone (nothing is exported): `primary`, the context's own DID, first
    /// when its keys are there, then the rest in order.
    async fn context_dids(
        &self,
        context_id: &str,
        primary: Option<&str>,
    ) -> affinidi_messaging_mediator_admin::Result<Vec<String>> {
        let mut dids = std::collections::BTreeSet::new();
        let mut offset = 0;
        loop {
            let page = self
                .client
                .list_keys(offset, KEY_PAGE, Some("active"), Some(context_id))
                .await
                .map_err(|e| {
                    ConsoleError::Identity(format!("listing keys of {context_id}: {e}"))
                })?;
            if page.keys.is_empty() {
                break;
            }
            for key in &page.keys {
                if let Some(did) = key_did(&key.key_id, key.label.as_deref()) {
                    dids.insert(did);
                }
            }
            offset += page.keys.len() as u64;
            if offset >= page.total {
                break;
            }
        }
        Ok(order_dids(dids, primary))
    }

    /// Export the DID's verification-method keys one at a time through
    /// `keys/export-secret` (KeyExport-gated, audited — VTI-VTA-003). Keys in
    /// the context that are not verification methods of the DID are never
    /// exported.
    async fn export_did_keys(
        &self,
        context_id: &str,
        did: &str,
    ) -> affinidi_messaging_mediator_admin::Result<Vec<Secret>> {
        let mut secrets = Vec::new();
        let mut offset = 0;
        loop {
            let page = self
                .client
                .list_keys(offset, KEY_PAGE, Some("active"), Some(context_id))
                .await
                .map_err(|e| {
                    ConsoleError::Identity(format!("listing keys of {context_id}: {e}"))
                })?;
            if page.keys.is_empty() {
                break;
            }
            for key in &page.keys {
                // Decided from the key record alone, before anything is exported.
                let Some(kid) = select_secret_kid(did, &key.key_id, key.label.as_deref()) else {
                    continue;
                };
                if key.exportable == Some(false) {
                    return Err(ConsoleError::Identity(format!(
                        "{kid} is marked non-exportable; the console needs this DID's keys to \
                         sign and decrypt, and the VTA has no remote key agreement"
                    )));
                }
                let exported = self.client.get_key_secret(&key.key_id).await.map_err(|e| {
                    ConsoleError::Identity(format!(
                        "exporting {kid} (needs the KeyExport capability): {e}"
                    ))
                })?;
                let secret = Secret::from_multibase(&exported.private_key_multibase, Some(&kid))
                    .map_err(|e| ConsoleError::Identity(format!("{kid}: {e}")))?;
                secrets.push(secret);
            }
            offset += page.keys.len() as u64;
            if offset >= page.total {
                break;
            }
        }
        if secrets.is_empty() {
            return Err(ConsoleError::Identity(format!(
                "no keys of {did} were found in context {context_id}"
            )));
        }
        Ok(secrets)
    }

    /// pnm's own `did:key`, from the keyring — nothing leaves the VTA.
    fn session_identity(&self) -> affinidi_messaging_mediator_admin::Result<Identity> {
        let session = crate::auth::loaded_session(&self.keyring_key)
            .ok_or_else(|| ConsoleError::Identity("no pnm session — run `pnm setup`".into()))?;
        let seed = crate::auth::session_seed(&session)
            .map_err(|e| ConsoleError::Identity(e.to_string()))?;
        let keys = vta_sdk::did_key::secrets_from_did_key(&session.client_did, &seed)
            .map_err(|e| ConsoleError::Identity(e.to_string()))?;
        Ok(Identity {
            alias: "this pnm session".into(),
            did: session.client_did,
            secrets: vec![keys.signing, keys.key_agreement],
            mediator_did: None,
        })
    }
}

/// The DID a key record belongs to: the part of its verification-method id
/// before `#`, by the same rule [`select_secret_kid`] uses to pick the kid.
fn key_did(key_id: &str, label: Option<&str>) -> Option<String> {
    let vm_id =
        |s: &str| s.starts_with("did:") && s.contains('#') && !s.chars().any(char::is_whitespace);
    let id = if vm_id(key_id) {
        key_id
    } else {
        label.filter(|l| vm_id(l))?
    };
    let did = id.split('#').next()?;
    select_secret_kid(did, key_id, label).map(|_| did.to_string())
}

/// `primary` first when present, then the others in order.
fn order_dids(mut dids: std::collections::BTreeSet<String>, primary: Option<&str>) -> Vec<String> {
    let mut ordered = Vec::with_capacity(dids.len());
    if let Some(primary) = primary
        && dids.remove(primary)
    {
        ordered.push(primary.to_string());
    }
    ordered.extend(dids);
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;

    fn choice(id: &str) -> IdentityChoice {
        IdentityChoice {
            id: id.into(),
            label: id.into(),
            did: Some(format!("did:example:{id}")),
            detail: None,
        }
    }

    fn in_context(id: &str, did: &str) -> IdentityChoice {
        IdentityChoice {
            did: Some(did.into()),
            ..choice(id)
        }
    }

    #[test]
    fn a_grant_never_names_root_admin() {
        // The two roles a grant offers map to exactly the two account types
        // they say, and rootAdmin is not reachable from this command at all.
        assert_eq!(account_type(GrantRole::Admin), AccountType::Admin);
        assert_eq!(account_type(GrantRole::Standard), AccountType::Standard);
        for role in [GrantRole::Admin, GrantRole::Standard] {
            assert_eq!(
                serde_json::to_value(account_type(role)).unwrap(),
                serde_json::Value::String(grant_role_wire(role).into())
            );
        }
    }

    #[test]
    fn a_named_context_or_the_session_is_picked_by_id() {
        let choices = vec![choice("ctx-a"), choice(SESSION_CHOICE)];
        assert_eq!(narrow(&choices, Some("ctx-a"), None)[0].id, "ctx-a");
        assert_eq!(
            narrow(&choices, Some(SESSION_CHOICE), None)[0].id,
            SESSION_CHOICE
        );
        // Unnarrowed, the session is not a context candidate.
        assert_eq!(narrow(&choices, None, None).len(), 1);
    }

    #[test]
    fn identity_choices_are_named_by_context_and_told_apart() {
        let choices = vec![
            IdentityChoice {
                label: "billing".into(),
                ..in_context("ctx-a", "did:webvh:Qm:ex.com:billing")
            },
            IdentityChoice {
                label: "shared".into(),
                ..in_context("ctx-b", "did:webvh:Qm:ex.com:one")
            },
            IdentityChoice {
                label: "shared".into(),
                ..in_context("ctx-b", "did:webvh:Qm:ex.com:two")
            },
            choice(SESSION_CHOICE),
        ];
        let names: std::collections::HashMap<String, String> =
            choice_names(&choices).into_iter().collect();
        assert_eq!(names["did:webvh:Qm:ex.com:billing"], "billing");
        assert_eq!(names["did:webvh:Qm:ex.com:one"], "shared · one");
        assert_eq!(names["did:webvh:Qm:ex.com:two"], "shared · two");
        assert_eq!(
            names[&format!("did:example:{SESSION_CHOICE}")],
            "pnm session"
        );
    }

    #[test]
    fn a_did_picks_one_of_several_in_a_context() {
        let choices = vec![
            in_context("ctx-a", "did:example:one"),
            in_context("ctx-a", "did:example:two"),
            in_context("ctx-b", "did:example:three"),
        ];
        assert_eq!(narrow(&choices, Some("ctx-a"), None).len(), 2);
        let two = narrow(&choices, Some("ctx-a"), Some("did:example:two"));
        assert_eq!(two.len(), 1);
        assert_eq!(two[0].did.as_deref(), Some("did:example:two"));
        // --did alone finds it in whichever context holds it.
        assert_eq!(
            narrow(&choices, None, Some("did:example:three"))[0].id,
            "ctx-b"
        );
        assert!(narrow(&choices, Some("ctx-b"), Some("did:example:one")).is_empty());
    }

    #[test]
    fn an_unusable_context_says_why() {
        let err = first(vec![], "ctx-b", None).unwrap_err().to_string();
        assert!(
            err.contains("ctx-b") && err.contains("--as-session"),
            "{err}"
        );
        let err = first(vec![], "ctx-b", Some("did:example:x"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("did:example:x in ctx-b"), "{err}");
    }

    #[test]
    fn a_key_belongs_to_the_did_its_id_or_label_names() {
        assert_eq!(
            key_did("did:webvh:Qm:ex.com#key-0", None).as_deref(),
            Some("did:webvh:Qm:ex.com")
        );
        // A bare key id with a verification-method label.
        assert_eq!(
            key_did("z6Mkabc", Some("did:peer:2.Vz#key-1")).as_deref(),
            Some("did:peer:2.Vz")
        );
        // A decorative label is not a verification-method id (PR #337).
        assert_eq!(key_did("z6Mkabc", Some("did:key:z6Mk signing key")), None);
        assert_eq!(key_did("z6Mkabc", None), None);
    }

    #[test]
    fn the_context_did_comes_first() {
        let dids: std::collections::BTreeSet<String> =
            ["did:a", "did:b", "did:c"].map(String::from).into();
        assert_eq!(
            order_dids(dids.clone(), Some("did:c")),
            ["did:c", "did:a", "did:b"]
        );
        assert_eq!(order_dids(dids.clone(), None), ["did:a", "did:b", "did:c"]);
        // A context DID with no keys in the context is not offered.
        assert_eq!(order_dids(dids, Some("did:z")), ["did:a", "did:b", "did:c"]);
    }
}
