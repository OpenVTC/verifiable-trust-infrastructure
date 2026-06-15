//! Integration cold-start onboarding.
//!
//! [`IntegrationOnboarding`] packages the **ephemeral `did:key` → ACL grant
//! → auto-rotate on first connect** pattern that the mediator, PNM, and
//! did-hosting services already use, so every external integration gets the
//! flow uniformly without re-deriving it from the lower-level
//! [`SessionStore`](vta_sdk::session::SessionStore) calls.
//!
//! ## The flow
//!
//! 1. **Mint + park** ([`IntegrationOnboarding::begin`]): the integration
//!    mints a fresh, throwaway `did:key` locally (the private key never
//!    crosses the wire) and parks it as a *pending-rotation* session bound to
//!    the target VTA DID. The ephemeral DID is returned for the operator to
//!    authorize.
//! 2. **Grant** (operator, out of band): the VTA operator grants the ephemeral
//!    DID a context-scoped `application` role, e.g.
//!    ```text
//!    vta import-did --did <EPHEMERAL_DID> --role application --context <CTX>
//!    ```
//!    (or `pnm acl create --did <EPHEMERAL_DID> --role application
//!    --contexts <CTX>` against a running VTA).
//! 3. **Connect + rotate** ([`IntegrationOnboarding::connect`] /
//!    [`IntegrationOnboarding::connect_rest`]): on the first successful
//!    authentication the session store atomically swaps the throwaway
//!    `did:key` for a fresh one (mirrors the ACL entry onto the new DID, drops
//!    the temp DID), so the DID that may have been copy-pasted through a
//!    low-trust channel does not remain live.
//!
//! Persisting the integration's *other* long-lived secrets (its identity seed,
//! per-connector platform credentials) is a separate concern handled by
//! [`create_seed_store`](crate::create_seed_store) — see the crate docs.

use rand::Rng;
use vta_sdk::client::VtaClient;
use vta_sdk::session::SessionStore;

/// Error type for the onboarding flow. Wraps the boxed errors the
/// underlying `SessionStore` calls return.
pub type OnboardingError = Box<dyn std::error::Error>;

/// Mint a fresh Ed25519 keypair and derive a `did:key`.
///
/// Returns `(did, private_key_multibase)` — the raw 32-byte seed encoded as
/// Base58Btc multibase, matching the format the rest of the workspace
/// (`CredentialBundle`, `vta-cli-common::local_keygen`) uses. The public-key
/// encoding reuses [`vta_sdk::did_key::ed25519_multibase_pubkey`].
fn mint_ephemeral_did_key() -> (String, String) {
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let did = format!(
        "did:key:{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(&public_key)
    );
    let private_key_multibase = multibase::encode(multibase::Base::Base58Btc, seed);
    (did, private_key_multibase)
}

/// The ephemeral identity an integration must get authorized before its first
/// connect. Hand [`ephemeral_did`](Self::ephemeral_did) to the VTA operator;
/// the private key stays inside the [`SessionStore`].
#[derive(Debug, Clone)]
pub struct OnboardingTicket {
    ephemeral_did: String,
    vta_did: String,
}

impl OnboardingTicket {
    /// The throwaway `did:key` the operator must grant a context-scoped
    /// `application` role before the integration's first connect.
    pub fn ephemeral_did(&self) -> &str {
        &self.ephemeral_did
    }

    /// The VTA DID this ticket is bound to.
    pub fn vta_did(&self) -> &str {
        &self.vta_did
    }

    /// The `vta import-did` command the operator should run (offline / cold
    /// start) to authorize this DID in `context`.
    pub fn import_did_command(&self, context: &str) -> String {
        format!(
            "vta import-did --did {} --role application --context {}",
            self.ephemeral_did, context
        )
    }
}

/// High-level onboarding driver for a single integration identity.
///
/// Wraps a [`SessionStore`] (which owns credential persistence via its
/// pluggable [`SessionBackend`](vta_sdk::session::SessionBackend)) and a
/// session key. Construct one with [`IntegrationOnboarding::new`], or with
/// [`IntegrationOnboarding::with_default_backend`] to pick the SDK's default
/// session backend by compiled features.
pub struct IntegrationOnboarding {
    session: SessionStore,
    session_key: String,
}

impl IntegrationOnboarding {
    /// Build over a caller-provided [`SessionStore`]. Use this to share the
    /// integration's existing session storage.
    pub fn new(session: SessionStore, session_key: impl Into<String>) -> Self {
        Self {
            session,
            session_key: session_key.into(),
        }
    }

    /// Build over the SDK's default session backend (keyring → azure →
    /// config-file → plaintext, by compiled features).
    pub fn with_default_backend(
        service_name: &str,
        sessions_dir: std::path::PathBuf,
        session_key: impl Into<String>,
    ) -> Self {
        Self::new(SessionStore::new(service_name, sessions_dir), session_key)
    }

    /// The session key this driver reads/writes.
    pub fn session_key(&self) -> &str {
        &self.session_key
    }

    /// Borrow the underlying [`SessionStore`] for advanced use (status,
    /// diagnostics, logout).
    pub fn session_store(&self) -> &SessionStore {
        &self.session
    }

    /// True once the integration has a usable (non-pending) session — i.e.
    /// onboarding completed and the temp DID was rotated away.
    pub fn is_onboarded(&self) -> bool {
        self.session.has_session(&self.session_key)
            && !self.session.has_pending_vta_binding(&self.session_key)
    }

    /// Step 1 — mint an ephemeral `did:key` and park it as a pending-rotation
    /// session bound to `vta_did`. Returns the [`OnboardingTicket`] whose DID
    /// the operator must authorize before [`connect`](Self::connect).
    ///
    /// Idempotency: this overwrites any existing session at the configured
    /// key. Call it once per onboarding; guard with [`is_onboarded`](Self::is_onboarded)
    /// if you only want to provision when not already connected.
    pub fn begin(&self, vta_did: &str) -> Result<OnboardingTicket, OnboardingError> {
        let vta_did = vta_did.trim();
        if !vta_did.starts_with("did:") {
            return Err("VTA DID must start with `did:` (e.g. did:webvh:..., did:key:...)".into());
        }
        let (ephemeral_did, private_key_multibase) = mint_ephemeral_did_key();
        self.session.store_pending_rotation(
            &self.session_key,
            &ephemeral_did,
            &private_key_multibase,
            vta_did,
        )?;
        Ok(OnboardingTicket {
            ephemeral_did,
            vta_did: vta_did.to_string(),
        })
    }

    /// Step 3 — connect using the preferred transport (DIDComm if the VTA DID
    /// advertises it, REST otherwise). On the first successful auth this
    /// auto-rotates off the throwaway `did:key`. Returns a connected
    /// [`VtaClient`].
    ///
    /// `url_override` is a REST fallback hint used only when DID resolution
    /// yields no usable endpoint (e.g. a `did:key` VTA); `mediator_did_hint`
    /// pins DIDComm without discovery. Pass `None` for both to rely on DID
    /// resolution.
    pub async fn connect(
        &self,
        url_override: Option<&str>,
        mediator_did_hint: Option<&str>,
    ) -> Result<VtaClient, OnboardingError> {
        self.session
            .connect(&self.session_key, url_override, mediator_did_hint)
            .await
    }

    /// Step 3 (REST only) — authenticate over REST against `base_url`,
    /// auto-rotating off the throwaway `did:key` on first success. Returns the
    /// access token. Use this when the integration speaks REST and does not
    /// need a [`VtaClient`].
    pub async fn connect_rest(&self, base_url: &str) -> Result<String, OnboardingError> {
        self.session
            .ensure_authenticated(base_url, &self.session_key)
            .await
    }

    /// Clear the stored session (credentials + cached tokens).
    pub fn logout(&self) {
        self.session.logout(&self.session_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minted_did_is_did_key_and_seed_roundtrips() {
        let (did, priv_mb) = mint_ephemeral_did_key();
        assert!(did.starts_with("did:key:z"));
        let (_, seed) = multibase::decode(&priv_mb).unwrap();
        assert_eq!(seed.len(), 32, "Ed25519 seed must be 32 bytes");

        // Re-derive the DID from the private seed and confirm it matches.
        let seed: [u8; 32] = seed.try_into().unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let rederived = format!(
            "did:key:{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&signing.verifying_key().to_bytes())
        );
        assert_eq!(rederived, did);
    }

    #[test]
    fn minted_dids_are_unique() {
        let (a, _) = mint_ephemeral_did_key();
        let (b, _) = mint_ephemeral_did_key();
        assert_ne!(a, b);
    }

    #[test]
    fn begin_rejects_non_did_vta() {
        let onboarding = IntegrationOnboarding::with_default_backend(
            "vti-secrets-test",
            std::env::temp_dir(),
            "onboarding-test-rejects",
        );
        assert!(onboarding.begin("not-a-did").is_err());
    }

    #[test]
    fn import_did_command_is_application_scoped() {
        let ticket = OnboardingTicket {
            ephemeral_did: "did:key:z6MkExample".to_string(),
            vta_did: "did:webvh:example.com:vta".to_string(),
        };
        let cmd = ticket.import_did_command("ctx-1");
        assert!(cmd.contains("--role application"));
        assert!(cmd.contains("--did did:key:z6MkExample"));
        assert!(cmd.contains("--context ctx-1"));
    }
}
