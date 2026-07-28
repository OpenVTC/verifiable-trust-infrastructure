//! One TDK + one ATM per **process**, with a session per **identity** on it.
//!
//! # Why this exists
//!
//! Every session constructor in this SDK used to build its own
//! [`TDKSharedState`] *and* its own [`ATM`], then attach exactly one identity to
//! it. A process authenticating as N DIDs therefore held N ATMs, N secrets
//! resolvers, N deletion handlers, and N sets of background tasks — none of
//! which the transport requires (#830).
//!
//! `ATM` already models many identities: `Profiles` is a map keyed by alias with
//! `find_by_did`, and `profile_add` attaches each one with **its own**
//! websocket. The mediator's real ceiling is *one websocket per DID*, which N
//! profiles on one ATM satisfies exactly as well as N ATMs do — each DID still
//! gets one socket. What N ATMs buy is duplicated per-process machinery.
//!
//! ```ignore
//! let hub = SessionHub::new().await?;                       // one TDK + one ATM
//! let finance = DIDCommSession::connect_on(&hub, fin_did, fin_key, vta, med).await?;
//! let legal   = DIDCommSession::connect_on(&hub, leg_did, leg_key, vta, med).await?;
//! // ... one profile and one socket each, everything else shared ...
//! finance.shutdown().await;   // detaches just this identity
//! legal.shutdown().await;
//! hub.shutdown().await;       // tears the shared ATM down
//! ```
//!
//! # What is shared, and what is not
//!
//! | Shared across identities | Per identity |
//! |---|---|
//! | `TDKSharedState` (DID resolver cache, secrets resolver) | `ATMProfile` |
//! | `ATM` + its deletion handler | mediator websocket |
//! | `ATMConfig` | delivery-layer `MessagingService` + subscribers |
//!
//! Sharing the secrets resolver is what makes one ATM able to act as several
//! DIDs: every `Secret`'s id is a verification-method id of its own DID
//! (`{did}#key-0`), so lookups stay unambiguous. It also means a torn-down
//! identity's keys must not linger — `SessionHub::detach` evicts them.
//!
//! # This is not a licence to be multi-tenant
//!
//! The architectural rule is still **one principal per process**
//! (`docs/05-design-notes/multi-tenant-signing.md`, R4). A hub makes holding N
//! identities *cheap*; it does not make it *safe*. It exists for the front door
//! that legitimately terminates requests for N tenants and has not yet split
//! into a process per tenant (R1b) — the cost of that intermediate step should
//! not be N of everything.
//!
//! # Every session still owns its teardown
//!
//! A session built on a hub detaches **itself** on `shutdown()`
//! (`detach` → `profile_remove` → the websocket task is
//! actually told to stop), and leaves the hub running for its siblings. A
//! session built by a legacy constructor owns a private hub and shuts the whole
//! thing down. Neither path may skip the detach: an abandoned websocket
//! transport keeps reconnecting and keeps fighting for the mediator's
//! one-socket-per-DID slot for the life of the process.

use std::collections::HashSet;
use std::sync::Arc;

use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// A shared TDK + ATM that any number of identities attach to.
///
/// Construct one per process with [`new`](Self::new), hand it to the `*_on`
/// constructors ([`DIDCommSession::connect_on`], `TspSession::connect_on`, …),
/// and [`shutdown`](Self::shutdown) it once every session on it is done. See the
/// module docs for what is and is not shared.
///
/// [`DIDCommSession::connect_on`]: crate::didcomm_session::DIDCommSession::connect_on
pub struct SessionHub {
    /// Shared DID-resolution cache + secrets resolver. Held so
    /// [`attach`](Self::attach) can insert an identity's secrets and
    /// [`detach`](Self::detach) can evict them.
    tdk: Arc<TDKSharedState>,
    /// The one ATM every identity on this hub rides.
    atm: Arc<ATM>,
    /// DIDs currently attached. The ATM's own profile map is the real registry;
    /// this exists so "is this DID already attached?" and "attach it" are one
    /// atomic step. Without that, two concurrent `attach` calls for the same DID
    /// both pass the check and the second silently *replaces* the first in the
    /// ATM's map — leaving the first session's socket orphaned and its
    /// `profile_remove` a no-op.
    attached: Mutex<HashSet<String>>,
}

/// Why attaching an identity to a [`SessionHub`] could not proceed.
#[derive(Debug)]
pub enum HubError {
    /// This DID already has a session on this hub. The mediator permits one
    /// websocket per DID, so a second session for the same DID is a duelling
    /// socket, not extra capacity — shut the first one down first (or, if the
    /// two need different mediators, use a second hub).
    AlreadyAttached(String),
    /// The ATM refused the profile (bad mediator DID, unresolvable mediator …).
    Attach(String),
}

impl std::fmt::Display for HubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyAttached(did) => write!(
                f,
                "`{did}` already has a session on this hub — the mediator permits one \
                 websocket per DID, so shut that session down before opening another"
            ),
            Self::Attach(msg) => write!(f, "could not attach the identity: {msg}"),
        }
    }
}

impl std::error::Error for HubError {}

impl SessionHub {
    /// Build a hub with the default TDK + ATM configuration.
    pub async fn new() -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        Self::with_configs(TDKConfig::builder().build()?, ATMConfig::builder().build()?).await
    }

    /// Build a hub with explicit configuration — for consumers that need custom
    /// SSL roots (a self-signed mediator) or fetch-cache tuning.
    ///
    /// Both configs are process-wide once shared, which is the trade the hub
    /// makes: identities that need *different* ATM configuration need different
    /// hubs.
    pub async fn with_configs(
        tdk_config: TDKConfig,
        atm_config: ATMConfig,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        let tdk = Arc::new(TDKSharedState::new(tdk_config).await?);
        let atm = Arc::new(ATM::new(atm_config, Arc::clone(&tdk)).await?);
        debug!("session hub initialised (one TDK + one ATM)");
        Ok(Arc::new(Self {
            tdk,
            atm,
            attached: Mutex::new(HashSet::new()),
        }))
    }

    /// The shared ATM. Sessions pack/unpack and open their own transports
    /// through it.
    pub(crate) fn atm(&self) -> &Arc<ATM> {
        &self.atm
    }

    /// The shared TDK state — the DID-resolution cache and the secrets resolver
    /// every identity on this hub reads through.
    pub(crate) fn tdk(&self) -> &Arc<TDKSharedState> {
        &self.tdk
    }

    /// The DIDs currently holding a session on this hub.
    pub async fn identities(&self) -> Vec<String> {
        let mut dids: Vec<String> = self.attached.lock().await.iter().cloned().collect();
        dids.sort();
        dids
    }

    /// Attach `did` to the hub: insert its secrets into the shared resolver and
    /// register an [`ATMProfile`] with the ATM.
    ///
    /// Returns the profile. The caller then opens whichever transport it needs
    /// on it — `profile_enable_websocket` for DIDComm, `atm.tsp()
    /// .connect_websocket` for TSP — because that choice is the session's, not
    /// the hub's. `live_stream` is deliberately `false` here for the same
    /// reason.
    ///
    /// **The registration is the load-bearing part.** A profile that is never
    /// `profile_add`ed is invisible to `ATM::graceful_shutdown`, which stops
    /// websockets by iterating the profile map — so its socket survives every
    /// shutdown path and reconnects forever (the websocket task transitively
    /// owns the only `Sender` for its own command channel, so nothing else can
    /// ever close it). That was the state of every session in this SDK before
    /// #830.
    ///
    /// On any failure the secrets are evicted again, so a failed attach leaves
    /// no key material in the shared resolver.
    pub(crate) async fn attach(
        self: &Arc<Self>,
        did: &str,
        secrets: Vec<Secret>,
        mediator_did: &str,
    ) -> Result<AttachedIdentity, HubError> {
        let secret_ids: Vec<String> = secrets.iter().map(|s| s.id.clone()).collect();

        // Claim the DID *first*, in one locked step, then release the lock for
        // the slow part. `insert` returning false means someone else holds the
        // claim. Holding the lock across the mediator resolution below instead
        // would serialise every unrelated identity's attach behind one DID
        // document fetch (R1.3 — never hold a lock across an await).
        if !self.attached.lock().await.insert(did.to_string()) {
            return Err(HubError::AlreadyAttached(did.to_string()));
        }

        for secret in secrets {
            self.tdk().secrets_resolver().insert(secret).await;
        }

        let profile = match self.register_profile(did, mediator_did).await {
            Ok(profile) => profile,
            Err(e) => {
                // Nothing is attached, so nothing of this identity may remain —
                // release the claim as well, or the DID is unusable until the
                // process restarts.
                self.attached.lock().await.remove(did);
                self.evict_secrets(&secret_ids).await;
                return Err(e);
            }
        };

        Ok(AttachedIdentity {
            hub: Arc::clone(self),
            profile,
            did: did.to_string(),
            secret_ids,
        })
    }

    /// Build the profile and register it with the ATM. Split out so
    /// [`attach`](Self::attach) has one error path to clean up behind.
    async fn register_profile(
        &self,
        did: &str,
        mediator_did: &str,
    ) -> Result<Arc<ATMProfile>, HubError> {
        // Alias == DID. `profile_remove` takes an alias, and every lookup we do
        // is by DID, so keeping them identical means there is one key.
        let profile = ATMProfile::new(
            self.atm.as_ref(),
            None,
            did.to_string(),
            Some(mediator_did.to_string()),
        )
        .await
        .map_err(|e| HubError::Attach(format!("build profile for `{did}`: {e}")))?;

        // `live_stream: false` — the session opens the transport it needs.
        self.atm
            .profile_add(&profile, false)
            .await
            .map_err(|e| HubError::Attach(format!("register profile for `{did}`: {e}")))
    }

    /// Detach an identity: stop its websocket (via `profile_remove`) and evict
    /// its secrets from the shared resolver.
    ///
    /// Idempotent — a second call for the same DID is a no-op, which is what
    /// lets a session's `shutdown()` be safe to call on any clone.
    pub(crate) async fn detach(&self, did: &str, secret_ids: &[String]) {
        let was_attached = self.attached.lock().await.remove(did);
        if !was_attached {
            return;
        }

        // `profile_remove` sends `Stop` to the websocket transport task and
        // drops it out of the ATM's map. This is the only thing that ends that
        // task: it owns a `Sender` for its own command channel, so the channel
        // never closes on its own.
        match self.atm.profile_remove(did).await {
            Ok(true) => debug!(did, "identity detached from the hub"),
            // Registered by `attach`, so absent here means someone removed it
            // behind our back — worth a word, since a socket may be orphaned.
            Ok(false) => warn!(did, "identity was not registered with the ATM at detach"),
            Err(e) => warn!(did, "could not detach identity cleanly: {e}"),
        }

        self.evict_secrets(secret_ids).await;
    }

    /// Remove `secret_ids` from the shared resolver. A hub outlives the
    /// identities on it, so a detached identity's keys must not stay reachable
    /// to whatever is still running on the hub.
    async fn evict_secrets(&self, secret_ids: &[String]) {
        for id in secret_ids {
            self.tdk().secrets_resolver().remove_secret(id).await;
        }
    }

    /// Shut the hub down: stop every remaining identity's websocket and stop the
    /// ATM's background tasks.
    ///
    /// Sessions should be shut down first — they own their own teardown, and
    /// only they can drain in-flight waiters. This is the backstop for whatever
    /// is left, and it is bounded (see `ATM::graceful_shutdown`).
    pub async fn shutdown(&self) {
        let remaining = self.attached.lock().await.len();
        if remaining > 0 {
            debug!(
                remaining,
                "hub shutdown with identities still attached — stopping their transports"
            );
        }
        self.atm.graceful_shutdown().await;
        self.attached.lock().await.clear();
    }
}

/// One identity's attachment to a [`SessionHub`] — the profile plus everything
/// needed to detach it again.
///
/// Sessions hold this instead of a bare `Arc<ATMProfile>` so that "tear this
/// identity down" is a single call that cannot forget the secrets eviction or
/// the profile removal.
pub(crate) struct AttachedIdentity {
    pub(crate) hub: Arc<SessionHub>,
    pub(crate) profile: Arc<ATMProfile>,
    pub(crate) did: String,
    /// Ids of the secrets this identity inserted into the shared resolver.
    pub(crate) secret_ids: Vec<String>,
}

impl std::fmt::Debug for AttachedIdentity {
    /// Manual: neither the hub nor the ATM behind it is `Debug`, and this is
    /// key-adjacent — print what identifies the attachment, never the material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachedIdentity")
            .field("did", &self.did)
            .field("secrets", &self.secret_ids.len())
            .finish()
    }
}

impl AttachedIdentity {
    /// Detach this identity from its hub. Idempotent.
    pub(crate) async fn detach(&self) {
        self.hub.detach(&self.did, &self.secret_ids).await;
    }
}

/// How a session relates to the hub it runs on — the difference between "I was
/// handed this hub" and "I built it for myself".
///
/// A session that built its own hub is the legacy single-identity shape
/// (`DIDCommSession::connect`, `TspSession::connect`, …): its `shutdown()` must
/// tear the whole ATM down, because nothing else will. A session handed a hub
/// must **not** — its siblings are still using it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum HubOwnership {
    /// The session created the hub and is its only user.
    Exclusive,
    /// The hub was supplied by the caller and outlives this session.
    Shared,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic `did:key` + its DIDComm secrets, for attaching identities
    /// without a network.
    fn identity(seed_byte: u8) -> (String, Vec<Secret>) {
        let seed = [seed_byte; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let did = format!(
            "did:key:{}",
            crate::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
        );
        let secrets = crate::did_key::secrets_from_did_key(&did, &seed).expect("build secrets");
        (did, vec![secrets.signing, secrets.key_agreement])
    }

    /// A `did:key` used where a mediator DID is wanted. It resolves (it is a
    /// `did:key`) but advertises no messaging service, so `ATMProfile::new`
    /// records `mediator: None` and no socket is ever opened — which is exactly
    /// what these tests want: hub bookkeeping, no I/O.
    fn mediator_placeholder() -> String {
        identity(0xEE).0
    }

    #[tokio::test]
    async fn attaching_registers_the_identity_and_its_secrets() {
        let hub = SessionHub::new().await.expect("build hub");
        let (did, secrets) = identity(0x01);
        let secret_ids: Vec<String> = secrets.iter().map(|s| s.id.clone()).collect();

        let attached = hub
            .attach(&did, secrets, &mediator_placeholder())
            .await
            .expect("attach");

        assert_eq!(hub.identities().await, vec![did.clone()]);
        // Registered with the ATM — this is what makes teardown reach the
        // websocket at all (#830).
        assert!(
            hub.atm().find_profile(&did).await.is_some(),
            "the ATM must know about the profile, not just the session"
        );
        for id in &secret_ids {
            assert!(
                hub.tdk().secrets_resolver().get_secret(id).await.is_some(),
                "secret {id} must be resolvable while the identity is attached"
            );
        }

        attached.detach().await;

        assert!(hub.identities().await.is_empty());
        assert!(
            hub.atm().find_profile(&did).await.is_none(),
            "detach must remove the profile from the ATM"
        );
        for id in &secret_ids {
            assert!(
                hub.tdk().secrets_resolver().get_secret(id).await.is_none(),
                "detach must evict {id} — a torn-down identity's keys must not \
                 stay reachable to whatever else runs on the hub"
            );
        }

        hub.shutdown().await;
    }

    #[tokio::test]
    async fn a_second_session_for_the_same_did_is_refused() {
        let hub = SessionHub::new().await.expect("build hub");
        let mediator = mediator_placeholder();
        let (did, secrets) = identity(0x02);
        let first = hub.attach(&did, secrets, &mediator).await.expect("attach");

        let (_, again) = identity(0x02);
        let err = hub
            .attach(&did, again, &mediator)
            .await
            .expect_err("the same DID must not attach twice");
        assert!(matches!(err, HubError::AlreadyAttached(ref d) if *d == did));

        // The refusal must not have disturbed the live identity.
        assert_eq!(hub.identities().await, vec![did.clone()]);
        assert!(hub.atm().find_profile(&did).await.is_some());

        first.detach().await;
        hub.shutdown().await;
    }

    #[tokio::test]
    async fn identities_are_independent_and_detach_is_idempotent() {
        let hub = SessionHub::new().await.expect("build hub");
        let mediator = mediator_placeholder();
        let (alice, alice_secrets) = identity(0x03);
        let (bob, bob_secrets) = identity(0x04);
        let bob_secret_ids: Vec<String> = bob_secrets.iter().map(|s| s.id.clone()).collect();

        let alice_id = hub
            .attach(&alice, alice_secrets, &mediator)
            .await
            .expect("attach alice");
        let bob_id = hub
            .attach(&bob, bob_secrets, &mediator)
            .await
            .expect("attach bob");
        assert_eq!(hub.identities().await.len(), 2);

        // Tearing one identity down must leave its sibling untouched — this is
        // the whole point of a shared hub.
        bob_id.detach().await;
        assert_eq!(hub.identities().await, vec![alice.clone()]);
        assert!(hub.atm().find_profile(&alice).await.is_some());

        // A session's `shutdown()` may be called on several clones.
        bob_id.detach().await;
        assert_eq!(hub.identities().await, vec![alice.clone()]);
        for id in &bob_secret_ids {
            assert!(hub.tdk().secrets_resolver().get_secret(id).await.is_none());
        }

        alice_id.detach().await;
        hub.shutdown().await;
    }

    #[tokio::test]
    async fn a_detached_did_can_attach_again() {
        // The claim is released on detach, so a consumer that reconnects an
        // identity (token refresh, socket rebuild) is not locked out.
        let hub = SessionHub::new().await.expect("build hub");
        let mediator = mediator_placeholder();
        let (did, secrets) = identity(0x05);

        hub.attach(&did, secrets, &mediator)
            .await
            .expect("first attach")
            .detach()
            .await;

        let (_, secrets) = identity(0x05);
        let second = hub
            .attach(&did, secrets, &mediator)
            .await
            .expect("re-attach after detach");
        assert_eq!(hub.identities().await, vec![did]);

        second.detach().await;
        hub.shutdown().await;
    }

    #[test]
    fn already_attached_names_the_did_and_the_fix() {
        let msg = HubError::AlreadyAttached("did:key:zAlice".into()).to_string();
        assert!(
            msg.contains("did:key:zAlice"),
            "names the offending DID: {msg}"
        );
        assert!(
            msg.contains("one websocket per DID"),
            "explains why a second session is not extra capacity: {msg}"
        );
    }

    #[test]
    fn ownership_distinguishes_a_borrowed_hub_from_an_owned_one() {
        // The whole point of the enum: a shared hub must survive its sessions.
        assert_ne!(HubOwnership::Exclusive, HubOwnership::Shared);
    }
}
