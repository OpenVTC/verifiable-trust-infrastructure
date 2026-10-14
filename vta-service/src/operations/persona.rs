//! A **persona**: a DID this agent holds for a person in one of their trust contexts, and
//! the key it signs with as that DID.
//!
//! # Why one resolver
//!
//! In a data room a member is a DID: the subject of the invitation the room issued, the
//! identity on their MLS leaf, the subject of their membership and authority credentials,
//! and the signer of anything they narrow those credentials into. All four must be the
//! same DID, and it must be one the member's own agent holds the key for — otherwise the
//! agent cannot act for them, and somebody else's key is standing in for theirs.
//!
//! That DID is **never the interface client's** (a `pnm` session's `did:key`, a wallet
//! extension's, an agent's). A client key lives in the client: this agent cannot sign as it,
//! it changes whenever the client is reinstalled or rotated, and a person using two clients
//! would be two members. So every room path that asks "who is the member?" asks this
//! module, and the answer is a persona the caller may act as — or nothing.
//!
//! # The rule
//!
//! [`persona_signing_key`] answers for `did` and the caller's `auth`:
//!
//! - **A `did:webvh` this agent minted** (`webvh` builds only): the caller must be able to
//!   act in the DID's context. The method is read from the DID's **own log** — no
//!   resolution: this agent published it, and an answer that depends on the network is one
//!   a host can shape — as the first `assertionMethod` entry, under the DID itself, whose
//!   public key is an active Ed25519 key record **of that same context**.
//! - **A `did:key`**: an active Ed25519 key record with that public key, in a context the
//!   caller may act in (or, for a record with no context, a caller who is super-admin).
//!
//! Anything else is `None`, and `None` deliberately does not say why: an unknown DID and one
//! held in a context the caller cannot reach answer alike, so a refusal never tells a caller
//! which DIDs this agent holds for other people. Callers turn `None` into one refusal and
//! must keep it one.
//!
//! # What it is not
//!
//! **This agent's own DID is not a persona.** It is shared infrastructure: every principal's
//! rooms would carry the same identifier, linking them to one another, and acting as it is
//! not bounded by any context a caller acts in. The one task that may still sign as the
//! agent — `rooms/owner/register` naming it as `ownerDid`, which predates personas — handles
//! that case itself ([`crate::operations::room_host::owner_signing_key`]), outside this rule.
//!
//! **It confers nothing.** It decides *which* key; whoever then signs goes through the gated
//! oracle ([`crate::operations::keys::sign_payload`]), which re-checks the key's context, the
//! caller's key scope and the context's signing policy. No key material is derived here.

#[cfg(feature = "webvh")]
use serde_json::Value;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::auth::AuthClaims;

/// The key, and the verification method it is published as, that this agent signs with
/// **as** a persona.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonaKey {
    /// The key record the gated oracle signs with.
    pub key_id: String,
    /// The method the persona's DID document lists the key under, which a proof names.
    pub verification_method: String,
}

/// The stores [`persona_signing_key`] reads.
#[derive(Clone, Copy)]
pub struct PersonaStores<'a> {
    pub keys_ks: &'a KeyspaceHandle,
    /// The `did:webvh` logs this agent publishes. A build without `webvh` publishes none,
    /// so a `did:webvh` is never a persona there.
    #[cfg(feature = "webvh")]
    pub webvh_ks: &'a KeyspaceHandle,
}

impl<'a> PersonaStores<'a> {
    /// The stores, from the running service.
    pub fn from_state(state: &'a crate::server::AppState) -> Self {
        Self {
            keys_ks: &state.keys_ks,
            #[cfg(feature = "webvh")]
            webvh_ks: &state.webvh_ks,
        }
    }
}

/// The key this agent signs with as persona `did`, if `did` is a persona `auth` may act as.
///
/// `None` for a DID this agent does not hold **and** for one it holds in a context the
/// caller cannot act in — indistinguishably, see the module docs.
pub async fn persona_signing_key(
    stores: PersonaStores<'_>,
    auth: &AuthClaims,
    did: &str,
) -> Result<Option<PersonaKey>, AppError> {
    // A DID URL is not a DID. Accepting `did#fragment` here would let a caller name a
    // persona by a string no credential or leaf carries.
    if did.contains('#') {
        return Ok(None);
    }

    if let Some(id) = did.strip_prefix("did:key:") {
        let record = held_ed25519(stores.keys_ks, id, |ctx| match ctx {
            Some(ctx) => auth.has_context_access(ctx),
            None => auth.is_super_admin(),
        })
        .await?;
        return Ok(record.map(|record| PersonaKey {
            key_id: record.key_id,
            verification_method: format!("did:key:{id}#{id}"),
        }));
    }

    #[cfg(feature = "webvh")]
    if did.starts_with("did:webvh:") {
        return webvh_persona_key(stores.keys_ks, stores.webvh_ks, auth, did).await;
    }

    Ok(None)
}

/// The `did:webvh` arm of [`persona_signing_key`].
#[cfg(feature = "webvh")]
async fn webvh_persona_key(
    keys_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    did: &str,
) -> Result<Option<PersonaKey>, AppError> {
    let Some(record) = crate::webvh_store::get_did(webvh_ks, did).await? else {
        return Ok(None);
    };
    if !auth.has_context_access(&record.context_id) {
        return Ok(None);
    }
    let Some(log) = crate::webvh_store::get_did_log(webvh_ks, did).await? else {
        return Ok(None);
    };
    let document = crate::operations::protocol::document::current_document_from_log(&log)
        .map_err(|e| AppError::Internal(format!("read the current document of {did}: {e}")))?;

    // Every method, by id, with its public key — `assertionMethod` may list ids or embed
    // the method itself.
    let mut methods: Vec<(String, String)> = Vec::new();
    let mut add = |m: &Value| {
        if let (Some(id), Some(pk)) = (
            m.get("id").and_then(Value::as_str),
            m.get("publicKeyMultibase").and_then(Value::as_str),
        ) {
            methods.push((id.to_string(), pk.to_string()));
        }
    };
    for m in document["verificationMethod"]
        .as_array()
        .into_iter()
        .flatten()
    {
        add(m);
    }
    for m in document["assertionMethod"].as_array().into_iter().flatten() {
        add(m);
    }
    let absolute = |id: &str| {
        if id.starts_with('#') {
            format!("{did}{id}")
        } else {
            id.to_string()
        }
    };
    for entry in document["assertionMethod"].as_array().into_iter().flatten() {
        let id = match entry {
            Value::String(s) => s.as_str(),
            other => match other.get("id").and_then(Value::as_str) {
                Some(s) => s,
                None => continue,
            },
        };
        let id = absolute(id);
        // Only the DID's own methods: a key named under another DID is not this persona's.
        if !id.starts_with(&format!("{did}#")) {
            continue;
        }
        let Some((_, public_key)) = methods.iter().find(|(m, _)| absolute(m) == id) else {
            continue;
        };
        // Of the DID's own context only: a public key someone copied into their document
        // must not reach a record another context holds.
        if let Some(held) = held_ed25519(keys_ks, public_key, |ctx| {
            ctx == Some(record.context_id.as_str())
        })
        .await?
        {
            return Ok(Some(PersonaKey {
                key_id: held.key_id,
                verification_method: id,
            }));
        }
    }
    Ok(None)
}

/// An active Ed25519 key record holding `public_key`, in a context `in_scope` accepts.
///
/// Compared as key bytes, not as strings: a key published with its multicodec prefix and
/// one recorded without it are the same key.
async fn held_ed25519(
    keys_ks: &KeyspaceHandle,
    public_key: &str,
    in_scope: impl Fn(Option<&str>) -> bool,
) -> Result<Option<vta_sdk::keys::KeyRecord>, AppError> {
    use vta_sdk::did_key::decode_ed25519_public_key_multibase as decode;
    let Ok(wanted) = decode(public_key) else {
        return Ok(None);
    };
    for (_, value) in keys_ks.prefix_iter_raw("key:").await? {
        let Ok(record) = serde_json::from_slice::<vta_sdk::keys::KeyRecord>(&value) else {
            continue;
        };
        if record.key_type == vta_sdk::keys::KeyType::Ed25519
            && record.status == vta_sdk::keys::KeyStatus::Active
            && decode(&record.public_key).is_ok_and(|k| k == wanted)
            && in_scope(record.context_id.as_deref())
        {
            return Ok(Some(record));
        }
    }
    Ok(None)
}

/// Personas as this agent mints them, for tests across the room modules.
#[cfg(test)]
pub(crate) mod test_fixture {
    use super::*;
    use serde_json::Value;

    /// A persona: a DID, the key record it signs with, and its public key.
    pub(crate) struct Persona {
        pub did: String,
        pub key_id: String,
        pub public_key: [u8; 32],
        /// The persona's DID document, for a test resolver to serve.
        pub document: Value,
    }

    /// Mint an Ed25519 key in `context` through the real path, as an admin of everything.
    pub(crate) async fn mint_key(
        keys_ks: &KeyspaceHandle,
        internal_ks: &KeyspaceHandle,
        contexts_ks: &KeyspaceHandle,
        acl_ks: &KeyspaceHandle,
        seed: &std::sync::Arc<dyn vti_secrets::SeedStore>,
        audit: &vta_audit::SharedAuditSink,
        context: &str,
        key_id: &str,
    ) -> [u8; 32] {
        let created = crate::operations::keys::create_key(
            keys_ks,
            internal_ks,
            contexts_ks,
            seed,
            audit,
            acl_ks,
            &crate::test_support::super_admin_claims(),
            crate::operations::keys::CreateKeyParams {
                key_type: vta_keys::KeyType::Ed25519,
                internal: true,
                derivation_path: None,
                key_id: Some(key_id.into()),
                mnemonic: None,
                label: None,
                context_id: Some(context.into()),
            },
            "test",
        )
        .await
        .expect("mint a key");
        vta_sdk::did_key::decode_ed25519_public_key_multibase(&created.public_key)
            .expect("the minted key")
    }

    /// A `did:key` persona in `context`: the key record is named after nothing in
    /// particular, because the resolver matches by key, never by name.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn did_key_persona(
        keys_ks: &KeyspaceHandle,
        internal_ks: &KeyspaceHandle,
        contexts_ks: &KeyspaceHandle,
        acl_ks: &KeyspaceHandle,
        seed: &std::sync::Arc<dyn vti_secrets::SeedStore>,
        audit: &vta_audit::SharedAuditSink,
        context: &str,
        key_id: &str,
    ) -> Persona {
        let raw = mint_key(
            keys_ks,
            internal_ks,
            contexts_ks,
            acl_ks,
            seed,
            audit,
            context,
            key_id,
        )
        .await;
        let id = vta_sdk::did_key::ed25519_multibase_pubkey(&raw);
        let did = format!("did:key:{id}");
        let vm = format!("{did}#{id}");
        Persona {
            document: serde_json::json!({
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": did,
                "verificationMethod": [{
                    "id": vm, "type": "Multikey", "controller": did, "publicKeyMultibase": id,
                }],
                "authentication": [vm],
                "assertionMethod": [vm],
            }),
            did,
            key_id: key_id.into(),
            public_key: raw,
        }
    }

    /// A `did:webvh` persona in `context`: a real published log whose document numbers its
    /// signing method `#key-1` (as the templates do), over a key minted through the real
    /// path into `context`.
    #[cfg(feature = "webvh")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn webvh_persona(
        keys_ks: &KeyspaceHandle,
        internal_ks: &KeyspaceHandle,
        contexts_ks: &KeyspaceHandle,
        acl_ks: &KeyspaceHandle,
        webvh_ks: &KeyspaceHandle,
        seed: &std::sync::Arc<dyn vti_secrets::SeedStore>,
        audit: &vta_audit::SharedAuditSink,
        context: &str,
        key_id: &str,
    ) -> Persona {
        use didwebvh_rs::create::{CreateDIDConfig, create_did};
        use didwebvh_rs::parameters::Parameters as WebVHParameters;

        let raw = mint_key(
            keys_ks,
            internal_ks,
            contexts_ks,
            acl_ks,
            seed,
            audit,
            context,
            key_id,
        )
        .await;
        let published = vta_sdk::did_key::ed25519_multibase_pubkey(&raw);

        // The log's own update key is separate from the persona's signing key.
        let mut update = affinidi_tdk::secrets_resolver::secrets::Secret::generate_ed25519(
            None,
            Some(&[9u8; 32]),
        );
        let update_pub = update.get_public_keymultibase().expect("update key");
        update.id = format!("did:key:{update_pub}#{update_pub}");
        let document = serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "{DID}",
            "verificationMethod": [
                { "id": "{DID}#key-1", "type": "Multikey", "controller": "{DID}",
                  "publicKeyMultibase": published },
            ],
            "authentication": ["{DID}#key-1"],
            "assertionMethod": ["{DID}#key-1"],
        });
        let cfg = CreateDIDConfig::builder()
            .address(format!(
                "https://example.invalid/{context}/{key_id}/did.jsonl"
            ))
            .authorization_key(update)
            .did_document(document)
            .parameters(WebVHParameters {
                update_keys: Some(std::sync::Arc::new(vec![update_pub.into()])),
                ..Default::default()
            })
            .build()
            .expect("create config");
        let result = create_did(cfg).await.expect("create did");
        let did = result.did().to_string();
        let log = serde_json::to_string(result.log_entry()).expect("serialise log");
        crate::webvh_store::store_did_log(webvh_ks, &did, &log)
            .await
            .expect("store log");
        let now = chrono::Utc::now();
        crate::webvh_store::store_did(
            webvh_ks,
            &vta_sdk::webvh::WebvhDidRecord {
                did: did.clone(),
                server_id: "serverless".into(),
                mnemonic: String::new(),
                scid: "irrelevant".into(),
                context_id: context.into(),
                portable: false,
                log_entry_count: 1,
                pre_rotation_count: 0,
                next_fragment_id: 2,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .expect("store did record");
        let document = crate::operations::protocol::document::current_document_from_log(&log)
            .expect("the published document");
        Persona {
            did,
            key_id: key_id.into(),
            public_key: raw,
            document,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_fixture::*;
    use super::*;

    struct Fixture {
        ts: crate::test_support::TestStore,
        seed: std::sync::Arc<dyn vti_secrets::SeedStore>,
    }

    impl Fixture {
        async fn new() -> Self {
            let ts = crate::test_support::open_test_store().await;
            for (id, name) in [("alice", "Alice"), ("bob", "Bob")] {
                crate::contexts::create_context(&ts.contexts_ks, id, name)
                    .await
                    .expect("create context");
            }
            Self {
                ts,
                seed: std::sync::Arc::new(crate::test_support::TestSeedStore(vec![7u8; 32])),
            }
        }

        fn stores(&self) -> PersonaStores<'_> {
            PersonaStores {
                keys_ks: &self.ts.keys_ks,
                #[cfg(feature = "webvh")]
                webvh_ks: &self.ts.webvh_ks,
            }
        }

        async fn did_key(&self, context: &str, key_id: &str) -> Persona {
            did_key_persona(
                &self.ts.keys_ks,
                &self.ts.internal_ks,
                &self.ts.contexts_ks,
                &self.ts.acl_ks,
                &self.seed,
                &self.ts.audit,
                context,
                key_id,
            )
            .await
        }

        #[cfg(feature = "webvh")]
        async fn webvh(&self, context: &str, key_id: &str) -> Persona {
            webvh_persona(
                &self.ts.keys_ks,
                &self.ts.internal_ks,
                &self.ts.contexts_ks,
                &self.ts.acl_ks,
                &self.ts.webvh_ks,
                &self.seed,
                &self.ts.audit,
                context,
                key_id,
            )
            .await
        }
    }

    /// A `did:webvh` minted in the caller's context is a persona the caller may act as, and
    /// its key is the one its own log publishes for `assertionMethod`.
    #[cfg(feature = "webvh")]
    #[tokio::test]
    async fn a_webvh_persona_in_the_callers_context_resolves() {
        let f = Fixture::new().await;
        let alice = f.webvh("alice", "alice-persona").await;
        let caller = crate::test_support::admin_claims_for_context("alice");
        let key = persona_signing_key(f.stores(), &caller, &alice.did)
            .await
            .unwrap()
            .expect("alice's persona");
        assert_eq!(key.key_id, alice.key_id);
        assert_eq!(key.verification_method, format!("{}#key-1", alice.did));
    }

    /// Someone else's persona and a DID nobody holds answer alike, so the answer does not
    /// say which DIDs this agent holds for other people.
    #[cfg(feature = "webvh")]
    #[tokio::test]
    async fn another_contexts_persona_reads_like_an_unknown_one() {
        let f = Fixture::new().await;
        let bob_webvh = f.webvh("bob", "bob-persona").await;
        let bob_key = f.did_key("bob", "bob-did-key").await;
        let caller = crate::test_support::admin_claims_for_context("alice");
        for did in [
            bob_webvh.did.as_str(),
            bob_key.did.as_str(),
            "did:webvh:QmNobody:nowhere.example",
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        ] {
            assert_eq!(
                persona_signing_key(f.stores(), &caller, did).await.unwrap(),
                None,
                "{did}"
            );
        }
    }

    /// A held `did:key` is a persona in its own context and nowhere else.
    #[tokio::test]
    async fn a_held_did_key_is_a_persona_only_in_its_context() {
        let f = Fixture::new().await;
        let alice = f.did_key("alice", "alice-key").await;
        let id = alice.did.strip_prefix("did:key:").unwrap();
        let key = persona_signing_key(
            f.stores(),
            &crate::test_support::admin_claims_for_context("alice"),
            &alice.did,
        )
        .await
        .unwrap()
        .expect("held in alice");
        assert_eq!(key.key_id, "alice-key");
        assert_eq!(key.verification_method, format!("{}#{id}", alice.did));
        assert_eq!(
            vta_sdk::did_key::ed25519_multibase_pubkey(&alice.public_key),
            id
        );

        assert_eq!(
            persona_signing_key(
                f.stores(),
                &crate::test_support::admin_claims_for_context("bob"),
                &alice.did,
            )
            .await
            .unwrap(),
            None
        );
    }

    /// An interface client's `did:key` — a key that lives in the client, not here — is no
    /// persona, whoever asks.
    #[tokio::test]
    async fn a_client_held_did_key_is_not_a_persona() {
        let f = Fixture::new().await;
        let caller = crate::test_support::admin_claims_for_context("alice");
        assert_eq!(
            persona_signing_key(f.stores(), &caller, &caller.did)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            persona_signing_key(
                f.stores(),
                &crate::test_support::super_admin_claims(),
                &caller.did
            )
            .await
            .unwrap(),
            None
        );
    }

    /// A DID URL is not a DID: naming a persona by `did#fragment` is not naming it.
    #[tokio::test]
    async fn a_did_url_is_not_a_persona() {
        let f = Fixture::new().await;
        let alice = f.did_key("alice", "alice-key-2").await;
        let id = alice.did.strip_prefix("did:key:").unwrap();
        assert_eq!(
            persona_signing_key(
                f.stores(),
                &crate::test_support::admin_claims_for_context("alice"),
                &format!("{}#{id}", alice.did),
            )
            .await
            .unwrap(),
            None
        );
    }
}
