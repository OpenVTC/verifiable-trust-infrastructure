//! `pnm bootstrap claim-did` — the ephemeral DID that authorizes a TEE VTA's
//! first-boot admin claim.
//!
//! The operator mints it before the VTA exists and registers only the public
//! DID with the provisioning stack, which delivers it to the enclave. At
//! `pnm bootstrap connect` the same key is the claim's `clientDid` and signs
//! it, so the enclave can refuse any other caller; the enclave then enrols this
//! DID itself as its expiring bootstrap admin (#2066), and `connect` hands that
//! entry over to a long-term key before destroying this one (VTI-CLT-034).
//!
//! The private key lives only in the OS keyring, never on disk, and a build or
//! environment that would put it anywhere else is refused.

use vta_sdk::secure_store::{self, SecureStore};
use vta_sdk::session::SessionStore;
use zeroize::Zeroizing;

/// Keyed by the claim DID, or by slug for keys from older pnm (`create --slug`).
/// Separate from `vta:<slug>` so `pnm setup` can neither rotate nor overwrite it.
fn claim_keyring_key(id: &str) -> String {
    format!("bootstrap-claim:{id}")
}

/// Only an Ed25519 `did:key` can be a claim DID. The input is not echoed: it
/// may be a pasted private key.
fn check_claim_did(did: &str) -> Result<(), Box<dyn std::error::Error>> {
    affinidi_crypto::did_key::did_key_to_ed25519_pub(did)
        .map(|_| ())
        .map_err(|_| {
            "--claim-did must be the public Ed25519 did:key printed by \
             `pnm bootstrap claim-did create` (did:key:z6Mk...)"
                .into()
        })
}

/// A loaded claim key: the public `did:key`, its Ed25519 seed, and the same
/// key in multibase (what authentication as the claim DID signs with).
pub(crate) struct ClaimKey {
    pub did: String,
    pub seed: Zeroizing<[u8; 32]>,
    pub private_key_multibase: Zeroizing<String>,
    /// What the key is stored under: the DID, or a slug for older keys.
    id: String,
}

impl ClaimKey {
    /// The `claim-did discard` argument that removes this key.
    pub(crate) fn discard_arg(&self) -> String {
        if self.id == self.did {
            format!("--claim-did {}", self.did)
        } else {
            format!("--slug {}", self.id)
        }
    }
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

/// `pnm bootstrap claim-did create [--slug <SLUG>]`
pub async fn run_create(slug: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    require_os_keyring()?;
    let did = create(&crate::auth::store(), slug)?;

    eprintln!("Bootstrap claim DID created. Its private key is in the OS keyring.");
    eprintln!();
    eprintln!("Supply this DID when you create the VTA. Only its holder can claim admin:");
    println!("{did}");
    eprintln!();
    eprintln!("Once the VTA is up, from this machine:");
    match slug {
        Some(slug) => {
            eprintln!("  pnm bootstrap connect --slug {slug} --vta-did <did> --expect-pcr0 <hex>")
        }
        None => eprintln!(
            "  pnm bootstrap connect --vta-did <did> --claim-did {did} --expect-pcr0 <hex>"
        ),
    }
    Ok(())
}

/// `pnm bootstrap claim-did show --slug <SLUG>`, for keys stored by slug.
pub async fn run_show(slug: &str) -> Result<(), Box<dyn std::error::Error>> {
    require_os_keyring()?;
    println!("{}", load(&crate::auth::store(), slug)?.did);
    Ok(())
}

/// `pnm bootstrap claim-did discard (--claim-did <DID> | --slug <SLUG>)`
pub async fn run_discard(
    claim_did: Option<&str>,
    slug: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(did) = claim_did {
        check_claim_did(did)?;
    }
    let id = claim_did
        .or(slug)
        .expect("clap requires --claim-did or --slug");
    require_os_keyring()?;
    let store = crate::auth::store();
    if !store.has_session(&claim_keyring_key(id)) {
        // Older pnm stored the key under the slug, where its DID cannot find it.
        let hint = if claim_did.is_some() {
            ". If it was created with `claim-did create --slug <slug>`, pass that --slug instead"
        } else {
            ""
        };
        return Err(format!("{}{hint}", not_found(id)).into());
    }
    discard(&store, id);
    eprintln!(
        "Discarded bootstrap claim key {id}. A VTA registered with it can no longer be \
         claimed from this machine."
    );
    Ok(())
}

/// Load the claim key at connect time: by `claim_did`, else by `slug`.
pub(crate) fn load_for_connect(
    claim_did: Option<&str>,
    slug: &str,
) -> Result<ClaimKey, Box<dyn std::error::Error>> {
    if let Some(did) = claim_did {
        check_claim_did(did)?;
    }
    require_os_keyring()?;
    select(&crate::auth::store(), claim_did, slug)
}

/// Drop the claim key once its bootstrap entry has been handed over.
pub(crate) fn discard_after_claim(claim: &ClaimKey) {
    discard(&crate::auth::store(), &claim.id);
}

/// The key stored under `claim_did`, or under `slug` as older pnm stored it.
/// A slug-keyed key is used for `claim_did` only if it holds that DID.
fn select(
    store: &SessionStore,
    claim_did: Option<&str>,
    slug: &str,
) -> Result<ClaimKey, Box<dyn std::error::Error>> {
    let Some(did) = claim_did else {
        if !store.has_session(&claim_keyring_key(slug)) {
            return Err(format!(
                "no bootstrap claim key stored for '{slug}' in this machine's OS keyring; \
                 pass --claim-did with the DID the VTA was created with"
            )
            .into());
        }
        return load(store, slug);
    };
    // A key stored under the DID is the one: a failure to load it (a DID and
    // key that drifted apart) is reported, never masked as a missing key.
    if store.has_session(&claim_keyring_key(did)) {
        return load(store, did);
    }
    load(store, slug)
        .ok()
        .filter(|key| key.did == did)
        .ok_or_else(|| not_found(did))
}

/// Mint a claim key, stored under its DID, or under `slug` as older pnm did.
fn create(store: &SessionStore, slug: Option<&str>) -> Result<String, Box<dyn std::error::Error>> {
    let (did, private_key_multibase) =
        vta_cli_common::local_keygen::generate_unbound_admin_did_key();
    let id = slug.unwrap_or(&did);
    let keyring_key = claim_keyring_key(id);
    // Re-minting would orphan a DID already registered for a VTA.
    if store.has_session(&keyring_key) {
        return Err(format!(
            "a bootstrap claim key already exists for '{id}'. Print it with \
             `pnm bootstrap claim-did show --slug {id}`, or remove it with \
             `pnm bootstrap claim-did discard --slug {id}` if its VTA is gone."
        )
        .into());
    }
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

fn not_found(id: &str) -> Box<dyn std::error::Error> {
    format!(
        "no bootstrap claim key for {id} in this machine's OS keyring; use the machine \
         that created it"
    )
    .into()
}

/// The key stored under `id` (a claim DID, or a slug for older keys).
fn load(store: &SessionStore, id: &str) -> Result<ClaimKey, Box<dyn std::error::Error>> {
    let info = store
        .loaded_session(&claim_keyring_key(id))
        .ok_or_else(|| not_found(id))?;
    let seed = Zeroizing::new(crate::auth::session_seed(&info)?);
    // Guards against a keyring entry whose DID and key have drifted apart.
    let public = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    if affinidi_crypto::did_key::ed25519_pub_to_did_key(&public) != info.client_did {
        return Err(format!(
            "the bootstrap claim key for {id} does not match its stored DID; refusing to use it"
        )
        .into());
    }
    Ok(ClaimKey {
        did: info.client_did,
        seed,
        private_key_multibase: Zeroizing::new(info.private_key_multibase),
        id: id.to_string(),
    })
}

fn discard(store: &SessionStore, id: &str) {
    store.logout(&claim_keyring_key(id));
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
        let did = super::create(&store, None).unwrap();
        assert!(did.starts_with("did:key:z6Mk"));

        let key = super::load(&store, &did).unwrap();
        assert_eq!(key.did, did);
        let signed = vta_sdk::tee_bootstrap::FirstBootClaim::new_signed(
            &key.seed,
            "did:webvh:QmScid:vta.example.com",
            [3; 16],
            None,
        );
        assert_eq!(signed.client_did, did);
        signed.verify().unwrap();
    }

    #[test]
    fn each_create_mints_its_own_claim() {
        let store = store();
        let first = super::create(&store, None).unwrap();
        let second = super::create(&store, None).unwrap();
        assert_ne!(first, second);
        assert_eq!(super::load(&store, &first).unwrap().did, first);
        assert_eq!(super::load(&store, &second).unwrap().did, second);
    }

    #[test]
    fn discard_removes_the_key() {
        let store = store();
        let did = super::create(&store, None).unwrap();
        super::discard(&store, &did);
        let err = super::load(&store, &did).err().unwrap().to_string();
        assert!(err.contains(&did), "{err}");
        assert!(!err.contains("claim-did create"), "{err}");
    }

    #[test]
    fn claim_did_selects_its_own_key() {
        let store = store();
        let did = super::create(&store, None).unwrap();
        let key = super::select(&store, Some(&did), "any-slug").unwrap();
        assert_eq!(key.did, did);
        assert_eq!(key.discard_arg(), format!("--claim-did {did}"));
    }

    /// A key stored under its DID that no longer matches it is refused as
    /// such, not reported as missing.
    #[test]
    fn drifted_claim_key_is_refused_not_masked() {
        let store = store();
        let did = super::create(&store, None).unwrap();
        let (_, other_key) = vta_cli_common::local_keygen::generate_unbound_admin_did_key();
        store
            .store_pending_vta_binding(&super::claim_keyring_key(&did), &did, &other_key)
            .unwrap();
        let err = super::select(&store, Some(&did), "any-slug")
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("does not match its stored DID"), "{err}");
    }

    #[test]
    fn slug_keyed_key_from_older_pnm_still_works() {
        let store = store();
        let did = super::create(&store, Some("acme")).unwrap();
        assert!(
            super::create(&store, Some("acme")).is_err(),
            "re-mint must be refused"
        );

        // Old command line: no --claim-did.
        assert_eq!(super::select(&store, None, "acme").unwrap().did, did);
        let err = super::select(&store, None, "other")
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("--claim-did"), "{err}");
        // New command line: found by DID through the slug, only if the DID matches.
        let key = super::select(&store, Some(&did), "acme").unwrap();
        assert_eq!(key.discard_arg(), "--slug acme");
        let other = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let err = super::select(&store, Some(other), "acme")
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains(other), "{err}");
    }

    #[test]
    fn unknown_claim_did_names_the_did() {
        let store = store();
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let err = super::load(&store, did).err().unwrap().to_string();
        assert!(err.contains(did), "{err}");
    }

    #[test]
    fn claim_did_must_be_an_ed25519_did_key() {
        for bad in [
            "",
            "did:web:example.com",
            "z3u2en7t5LR2WtQH5PfsRMFLNBXLXmkDTqQr4nvXcrJ8e",
            "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
        ] {
            let err = super::check_claim_did(bad).unwrap_err().to_string();
            assert!(err.contains("Ed25519 did:key"), "{bad}: {err}");
            assert!(bad.is_empty() || !err.contains(bad), "input echoed: {err}");
        }
    }
}
