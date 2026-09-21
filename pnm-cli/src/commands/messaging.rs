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
    ConsoleError, Identity, IdentityChoice, IdentitySource, MediatorConsole,
};
use affinidi_messaging_mediator_tui::App;
use affinidi_secrets_resolver::secrets::Secret;
use async_trait::async_trait;
use vta_sdk::client::VtaClient;
use vta_sdk::did_secrets::select_secret_kid;

use crate::cli::MessagingCommands;

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
        MessagingCommands::Console {
            context,
            mediator,
            as_session,
        } => {
            let source = VtaIdentitySource {
                client,
                keyring_key: keyring_key.to_string(),
            };
            let choice = choose(&source, context.as_deref(), as_session).await?;
            let mut identity = source.load(&choice).await?;
            identity.mediator_did = mediator.clone();

            eprintln!("connecting to the mediator as {} …", identity.alias);
            let console = match MediatorConsole::connect(identity.clone()).await {
                // No mediator given and none in the DID document: fall back to
                // the mediator this pnm is configured with.
                Err(ConsoleError::NoMediator(_))
                    if mediator.is_none() && mediator_hint.is_some() =>
                {
                    identity.mediator_did = mediator_hint.map(str::to_string);
                    MediatorConsole::connect(identity).await?
                }
                other => other?,
            };

            let mut terminal = ratatui::init();
            let result = App::new(console).run(&mut terminal).await;
            ratatui::restore();
            Ok(result?)
        }
    }
}

/// Pick the identity: `--as-session`, `--context`, the only DID-bearing
/// context, or ask.
async fn choose(
    source: &VtaIdentitySource<'_>,
    context: Option<&str>,
    as_session: bool,
) -> Result<IdentityChoice, Box<dyn std::error::Error>> {
    let choices = source.list().await?;
    if as_session {
        return pick(&choices, SESSION_CHOICE);
    }
    if let Some(context) = context {
        return pick(&choices, context);
    }
    let contexts: Vec<&IdentityChoice> =
        choices.iter().filter(|c| c.id != SESSION_CHOICE).collect();
    if contexts.len() == 1 {
        return Ok(contexts[0].clone());
    }
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

fn pick(
    choices: &[IdentityChoice],
    id: &str,
) -> Result<IdentityChoice, Box<dyn std::error::Error>> {
    choices.iter().find(|c| c.id == id).cloned().ok_or_else(|| {
        format!(
            "no usable identity '{id}': it must be a context with a DID you may act in, \
                 or --as-session"
        )
        .into()
    })
}

/// The DIDs this pnm session may act as: every context it can see that has a
/// DID, and the session's own `did:key`.
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
        let mut choices: Vec<IdentityChoice> = contexts
            .contexts
            .into_iter()
            .filter_map(|c| {
                let did = c.did?;
                Some(IdentityChoice {
                    id: c.id.clone(),
                    label: c.name.clone(),
                    detail: Some(format!("context {}", c.id)),
                    did: Some(did),
                })
            })
            .collect();
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

    #[test]
    fn a_named_context_or_the_session_is_picked_by_id() {
        let choices = vec![choice("ctx-a"), choice(SESSION_CHOICE)];
        assert_eq!(pick(&choices, "ctx-a").unwrap().id, "ctx-a");
        assert_eq!(pick(&choices, SESSION_CHOICE).unwrap().id, SESSION_CHOICE);
    }

    #[test]
    fn an_unusable_context_says_why() {
        let err = pick(&[choice("ctx-a")], "ctx-b").unwrap_err().to_string();
        assert!(
            err.contains("ctx-b") && err.contains("--as-session"),
            "{err}"
        );
    }
}
