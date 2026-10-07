//! `pnm bootstrap claim-did` — the ephemeral DID that authorizes a TEE VTA's
//! first-boot admin claim.
//!
//! The operator mints it before the VTA exists and registers only the public
//! DID with the provisioning stack, which delivers it to the enclave. At
//! `pnm bootstrap connect` the same key is the request's `client_did` and signs
//! it, so the enclave can refuse any other caller before minting an admin.
//!
//! The private key lives only in the OS keyring, never on disk, and a build or
//! environment that would put it anywhere else is refused.

use vta_sdk::secure_store::{self, SecureStore};
use vta_sdk::session::SessionStore;
use zeroize::Zeroizing;

/// Separate from `vta:<slug>` so `pnm setup` can neither rotate nor overwrite it.
pub(crate) fn claim_keyring_key(slug: &str) -> String {
    format!("bootstrap-claim:{slug}")
}

/// A loaded claim key: the public `did:key` and its Ed25519 seed.
pub(crate) struct ClaimKey {
    pub did: String,
    pub seed: Zeroizing<[u8; 32]>,
}

/// Fail closed unless the session store is the OS keyring.
fn require_os_keyring() -> Result<(), Box<dyn std::error::Error>> {
    if !cfg!(feature = "keyring") {
        return Err(
            "the bootstrap claim key is kept only in the OS keyring, and this build \
                    has no `keyring` feature compiled in. Rebuild with it."
                .into(),
        );
    }
    match secure_store::override_from_env() {
        Ok(Some(SecureStore::File)) => Err(format!(
            "{}=file would write the bootstrap claim key to a plaintext file. It is kept only \
             in the OS keyring — unset {} for this command.",
            secure_store::OVERRIDE_ENV,
            secure_store::OVERRIDE_ENV
        )
        .into()),
        Ok(_) => Ok(()),
        Err(msg) => Err(msg.into()),
    }
}

/// `pnm bootstrap claim-did create --slug <SLUG>`
pub async fn run_create(slug: &str) -> Result<(), Box<dyn std::error::Error>> {
    require_os_keyring()?;
    let did = create(&crate::auth::store(), slug)?;

    eprintln!("Bootstrap claim DID created for '{slug}'. Its private key is in the OS keyring.");
    eprintln!();
    eprintln!("Supply this DID when you create the VTA. Only its holder can claim admin:");
    println!("{did}");
    eprintln!();
    eprintln!("Once the VTA is up, from this machine:");
    eprintln!("  pnm bootstrap connect --slug {slug} --vta-did <did> --expect-pcr0 <hex>");
    Ok(())
}

/// `pnm bootstrap claim-did show --slug <SLUG>`
pub async fn run_show(slug: &str) -> Result<(), Box<dyn std::error::Error>> {
    require_os_keyring()?;
    let key = load(&crate::auth::store(), slug)?;
    println!("{}", key.did);
    Ok(())
}

/// `pnm bootstrap claim-did discard --slug <SLUG>`
pub async fn run_discard(slug: &str) -> Result<(), Box<dyn std::error::Error>> {
    require_os_keyring()?;
    let store = crate::auth::store();
    let key = load(&store, slug)?;
    discard(&store, slug);
    eprintln!(
        "Discarded bootstrap claim DID {} for '{slug}'. A VTA registered with it can no longer \
         be claimed from this machine.",
        key.did
    );
    Ok(())
}

/// Load the claim key for `slug` at connect time.
pub(crate) fn load_for_connect(slug: &str) -> Result<ClaimKey, Box<dyn std::error::Error>> {
    require_os_keyring()?;
    load(&crate::auth::store(), slug)
}

/// Drop the claim key once the enclave has minted for it.
pub(crate) fn discard_after_claim(slug: &str) {
    discard(&crate::auth::store(), slug);
}

fn create(store: &SessionStore, slug: &str) -> Result<String, Box<dyn std::error::Error>> {
    let keyring_key = claim_keyring_key(slug);
    // Re-minting would orphan a DID already registered for a VTA.
    if store.has_session(&keyring_key) {
        return Err(format!(
            "a bootstrap claim DID already exists for '{slug}'. Print it with \
             `pnm bootstrap claim-did show --slug {slug}`, or remove it with \
             `pnm bootstrap claim-did discard --slug {slug}` if its VTA is gone."
        )
        .into());
    }

    let (did, private_key_multibase) =
        vta_cli_common::local_keygen::generate_unbound_admin_did_key();
    store.store_pending_vta_binding(&keyring_key, &did, &private_key_multibase)?;

    // A save that reports success but cannot be read back would strand the DID.
    match store.loaded_session(&keyring_key) {
        Some(info) if info.client_did == did => Ok(did),
        _ => Err(
            "the OS keyring accepted the claim key but did not return it on read-back; \
                  nothing was registered — fix the keyring and retry"
                .into(),
        ),
    }
}

fn load(store: &SessionStore, slug: &str) -> Result<ClaimKey, Box<dyn std::error::Error>> {
    let info = store.loaded_session(&claim_keyring_key(slug)).ok_or_else(
        || -> Box<dyn std::error::Error> {
            format!(
                "no bootstrap claim DID for '{slug}' in the OS keyring. A TEE VTA can only be \
                 claimed with the DID registered when it was created — run \
                 `pnm bootstrap claim-did create --slug {slug}` before creating the VTA, and \
                 pass the same --slug to connect."
            )
            .into()
        },
    )?;
    let seed = Zeroizing::new(crate::auth::session_seed(&info)?);
    // Guards against a keyring entry whose DID and key have drifted apart.
    let public = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    if affinidi_crypto::did_key::ed25519_pub_to_did_key(&public) != info.client_did {
        return Err(format!(
            "the bootstrap claim key for '{slug}' does not match its stored DID; refusing to use it"
        )
        .into());
    }
    Ok(ClaimKey {
        did: info.client_did,
        seed,
    })
}

fn discard(store: &SessionStore, slug: &str) {
    store.logout(&claim_keyring_key(slug));
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use vta_sdk::session::{SessionBackend, SessionStore};

    #[derive(Default)]
    struct MemoryBackend(Mutex<HashMap<String, String>>);

    impl SessionBackend for MemoryBackend {
        fn load(&self, key: &str) -> Option<String> {
            self.0.lock().unwrap().get(key).cloned()
        }
        fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
            self.0.lock().unwrap().insert(key.into(), value.into());
            Ok(())
        }
        fn clear(&self, key: &str) {
            self.0.lock().unwrap().remove(key);
        }
    }

    fn store() -> SessionStore {
        SessionStore::with_backend(Box::new(MemoryBackend::default()))
    }

    #[test]
    fn create_then_load_returns_matching_key() {
        let store = store();
        let did = super::create(&store, "acme").unwrap();
        assert!(did.starts_with("did:key:z6Mk"));

        let key = super::load(&store, "acme").unwrap();
        assert_eq!(key.did, did);
        let signed =
            vta_sdk::sealed_transfer::BootstrapRequest::new_signed_claim(&key.seed, [3; 16], None);
        assert_eq!(signed.client_did, did);
        signed.verify_claim_signature().unwrap();
    }

    #[test]
    fn create_refuses_to_replace_an_existing_claim() {
        let store = store();
        let first = super::create(&store, "acme").unwrap();
        let err = super::create(&store, "acme").unwrap_err().to_string();
        assert!(err.contains("claim-did show"), "{err}");
        assert_eq!(super::load(&store, "acme").unwrap().did, first);
    }

    #[test]
    fn claim_is_kept_apart_from_the_vta_session() {
        let store = store();
        super::create(&store, "acme").unwrap();
        assert!(!store.has_session(&crate::config::vta_keyring_key("acme")));
    }

    #[test]
    fn discard_removes_the_key() {
        let store = store();
        super::create(&store, "acme").unwrap();
        super::discard(&store, "acme");
        let err = super::load(&store, "acme").err().unwrap().to_string();
        assert!(err.contains("claim-did create"), "{err}");
    }
}
