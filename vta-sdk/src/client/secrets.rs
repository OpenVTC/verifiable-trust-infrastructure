//! Convenience methods for paginating + bundling key secrets via [`VtaClient`].

use super::VtaClient;
use crate::did_secrets::select_secret_kid;
use crate::error::VtaError;

impl VtaClient {
    /// Fetch all secrets for a context, paginating through all keys.
    ///
    /// Returns TDK `Secret` objects ready for use with DIDComm or signing.
    pub async fn fetch_context_secrets(
        &self,
        context_id: &str,
    ) -> Result<Vec<affinidi_tdk::secrets_resolver::secrets::Secret>, VtaError> {
        let page_size = 100u64;
        let mut offset = 0u64;
        let mut secrets = Vec::new();

        loop {
            let resp = self
                .list_keys(offset, page_size, Some("active"), Some(context_id))
                .await?;

            if resp.keys.is_empty() {
                break;
            }

            for key in &resp.keys {
                let secret_resp = self.get_key_secret(&key.key_id).await?;
                let secret = crate::did_key::secret_from_key_response(&secret_resp)?;
                secrets.push(secret);
            }

            offset += resp.keys.len() as u64;
            if offset >= resp.total {
                break;
            }
        }

        Ok(secrets)
    }

    /// Fetch all secrets for a context as a portable
    /// [`DidSecretsBundle`](crate::did_secrets::DidSecretsBundle).
    ///
    /// One `vta/contexts/secrets/1.0` call: the VTA resolves the context DID,
    /// walks its active keys and returns the bundle.
    ///
    /// # Why this used to be N+1, and why that mattered
    ///
    /// It used to do the walk here — `get_context`, then `list_keys`, then one
    /// `get_key_secret` per key. Three problems, and only the first is about
    /// speed:
    ///
    /// - `get_key_secret` is gated on **global Admin**, so a service that
    ///   wanted the keys of its own context had to hold authority over every
    ///   other context in the VTA to get them. The new task is `Application`
    ///   plus the caller's own context.
    /// - The kid-selection rule ([`select_secret_kid`]) had to be applied by
    ///   every caller, so a second implementation could quietly disagree about
    ///   which secrets belong to the DID. It now lives on one side.
    /// - A bundle assembled from N independent answers has no single point at
    ///   which the VTA decided to release it — nothing to audit, and nothing a
    ///   future "this key may not leave" rule could hook.
    ///
    /// # Falling back
    ///
    /// A VTA older than the task answers `unsupportedType`, and this falls back
    /// to the old walk so a service can be upgraded before the VTA it talks to
    /// is. The fallback is temporary: it is the last caller of
    /// `seeds/export-mnemonic`, which goes when it does.
    pub async fn fetch_did_secrets_bundle(
        &self,
        context_id: &str,
    ) -> Result<crate::did_secrets::DidSecretsBundle, VtaError> {
        match self
            .rpc_tt::<crate::protocols::context_management::secrets::ContextSecretsResultBody>(
                crate::trust_tasks::TASK_CONTEXTS_SECRETS_1_0,
                serde_json::json!({ "id": context_id }),
                30,
            )
            .await
        {
            Ok(body) => return Ok(body.into()),
            Err(VtaError::UnsupportedTaskType { .. }) => {
                tracing::warn!(
                    context = %context_id,
                    "this VTA does not serve vta/contexts/secrets/1.0; falling back to the                      per-key export, which requires global Admin. Upgrade the VTA to drop                      that requirement — the fallback is removed when seeds/export-mnemonic is."
                );
            }
            Err(e) => return Err(e),
        }
        self.fetch_did_secrets_bundle_per_key(context_id).await
    }

    /// The pre-`vta/contexts/secrets/1.0` walk. See the fallback note on
    /// [`Self::fetch_did_secrets_bundle`]; removed with
    /// `seeds/export-mnemonic`.
    async fn fetch_did_secrets_bundle_per_key(
        &self,
        context_id: &str,
    ) -> Result<crate::did_secrets::DidSecretsBundle, VtaError> {
        let ctx = self.get_context(context_id).await?;
        let did = ctx.did.ok_or_else(|| {
            VtaError::Validation(format!("context '{context_id}' has no DID assigned"))
        })?;

        let page_size = 100u64;
        let mut offset = 0u64;
        let mut secrets = Vec::new();

        loop {
            let resp = self
                .list_keys(offset, page_size, Some("active"), Some(context_id))
                .await?;
            if resp.keys.is_empty() {
                break;
            }
            for key in &resp.keys {
                let secret_resp = self.get_key_secret(&key.key_id).await?;
                let entry = crate::did_secrets::SecretEntry::from(secret_resp);
                // The kid a mediator matches inbound JWE recipients against MUST be
                // a verification-method id of *this* context's DID. Resolve it from
                // the authoritative store key_id (falling back to the label only
                // when the label is itself a VM id), and drop anything that isn't a
                // VM id of `did` — see [`select_secret_kid`].
                match select_secret_kid(&did, &entry.key_id, key.label.as_deref()) {
                    Some(kid) => secrets.push(crate::did_secrets::SecretEntry {
                        key_id: kid,
                        ..entry
                    }),
                    None => {
                        tracing::warn!(
                            context = %context_id,
                            did = %did,
                            key_id = %entry.key_id,
                            label = key.label.as_deref().unwrap_or(""),
                            "excluding secret from did-secrets bundle: not a verification \
                             method of the context DID (e.g. an admin did:key minted into \
                             this context, or a free-text-labelled key). Including it would \
                             corrupt the DIDComm operating-secret set and break the \
                             mediator's exact-match recipient lookup."
                        );
                    }
                }
            }
            offset += resp.keys.len() as u64;
            if offset >= resp.total {
                break;
            }
        }

        Ok(crate::did_secrets::DidSecretsBundle { did, secrets })
    }
}

#[cfg(all(test, feature = "test-loopback", feature = "client"))]
mod tests {
    use super::*;
    use crate::client::loopback::LoopbackSink;
    use serde_json::{Value, json};
    use std::sync::{Arc, Mutex};

    const DID: &str = "did:webvh:QmExample:example.com:rooms:host-1";

    /// Answers each task URI from a table, recording the order they arrive in.
    struct Scripted {
        seen: Mutex<Vec<String>>,
        answer: Box<dyn Fn(&str) -> Result<Value, VtaError> + Send + Sync>,
    }

    impl LoopbackSink for Scripted {
        fn dispatch(&self, type_uri: &str, _payload: &Value) -> Result<Value, VtaError> {
            self.seen
                .lock()
                .expect("not poisoned")
                .push(type_uri.to_string());
            (self.answer)(type_uri)
        }
    }

    fn client_of(
        answer: impl Fn(&str) -> Result<Value, VtaError> + Send + Sync + 'static,
    ) -> (crate::client::VtaClient, Arc<Scripted>) {
        let sink = Arc::new(Scripted {
            seen: Mutex::new(Vec::new()),
            answer: Box::new(answer),
        });
        (
            crate::client::VtaClient::loopback(sink.clone() as Arc<dyn LoopbackSink>),
            sink,
        )
    }

    /// The point of the change: one call, not one per key — and the response
    /// is read in the spec's lowerCamelCase, not the internal snake_case.
    #[tokio::test]
    async fn the_bundle_is_one_call() {
        let (client, sink) = client_of(|uri| {
            assert_eq!(uri, crate::trust_tasks::TASK_CONTEXTS_SECRETS_1_0);
            Ok(json!({
                "did": DID,
                "secrets": [
                    { "keyId": format!("{DID}#key-0"), "keyType": "ed25519",
                      "privateKeyMultibase": "zSigning" },
                    { "keyId": format!("{DID}#key-1"), "keyType": "x25519",
                      "privateKeyMultibase": "zAgreement" },
                ]
            }))
        });

        let bundle = client
            .fetch_did_secrets_bundle("rooms/host-1")
            .await
            .expect("the bundle comes back");

        assert_eq!(bundle.did, DID);
        assert_eq!(bundle.secrets.len(), 2);
        assert_eq!(bundle.secrets[0].key_id, format!("{DID}#key-0"));
        assert_eq!(bundle.secrets[0].private_key_multibase, "zSigning");
        assert_eq!(
            sink.seen.lock().expect("not poisoned").len(),
            1,
            "one task, not one per key"
        );
    }

    /// A VTA older than the task must not become a hard failure: a service has
    /// to be upgradable before the VTA it talks to is.
    #[tokio::test]
    async fn an_old_vta_falls_back_to_the_per_key_walk() {
        let (client, sink) = client_of(|uri| {
            if uri == crate::trust_tasks::TASK_CONTEXTS_SECRETS_1_0 {
                return Err(VtaError::UnsupportedTaskType {
                    type_uri: uri.to_string(),
                    served_versions: Vec::new(),
                });
            }
            if uri == crate::trust_tasks::TASK_CONTEXTS_GET_1_0 {
                return Ok(json!({ "id": "rooms/host-1", "name": "Host", "did": DID,
                                  "basePath": "m/0", "createdAt": "2026-01-01T00:00:00Z",
                                  "updatedAt": "2026-01-01T00:00:00Z" }));
            }
            if uri == crate::trust_tasks::TASK_KEYS_LIST_0_1 {
                return Ok(json!({
                    "keys": [ { "keyId": format!("{DID}#key-0"), "keyType": "ed25519",
                                "status": "active", "publicKey": "zPub",
                                "createdAt": "2026-01-01T00:00:00Z",
                                "updatedAt": "2026-01-01T00:00:00Z",
                                "origin": "derived", "derivationPath": "m/0" } ],
                    "total": 1
                }));
            }
            if uri == crate::trust_tasks::TASK_SEEDS_EXPORT_MNEMONIC_1_0 {
                // Serialised from the real response type rather than written by
                // hand: a hand-written fixture drifts silently when a member is
                // added, and passes for the wrong reason.
                return Ok(serde_json::to_value(
                    crate::protocols::key_management::secret::GetKeySecretResultBody {
                        key_id: format!("{DID}#key-0"),
                        key_type: crate::keys::KeyType::Ed25519,
                        public_key_multibase: "zPub".into(),
                        private_key_multibase: "zSigning".into(),
                    },
                )
                .expect("the secret response serialises"));
            }
            panic!("unexpected task: {uri}")
        });

        let bundle = client
            .fetch_did_secrets_bundle("rooms/host-1")
            .await
            .expect("the old walk still assembles a bundle");

        assert_eq!(bundle.did, DID);
        assert_eq!(bundle.secrets.len(), 1);
        assert_eq!(bundle.secrets[0].key_id, format!("{DID}#key-0"));

        let seen = sink.seen.lock().expect("not poisoned").clone();
        assert_eq!(
            seen.first().map(String::as_str),
            Some(crate::trust_tasks::TASK_CONTEXTS_SECRETS_1_0),
            "the new task must be tried first, so an upgraded VTA never takes the old path"
        );
        assert!(
            seen.iter()
                .any(|u| u == crate::trust_tasks::TASK_SEEDS_EXPORT_MNEMONIC_1_0),
            "the fallback is the last caller of seeds/export-mnemonic — when this \
             assertion has nothing to find, the fallback and that task can both go"
        );
    }

    /// Any other error is the caller's to see. Falling back on, say, a
    /// permission refusal would turn one clear error into a second, more
    /// confusing one from a path the caller is even less entitled to.
    #[tokio::test]
    async fn a_non_version_error_does_not_fall_back() {
        let (client, sink) = client_of(|_| Err(VtaError::Forbidden("no access".into())));

        let err = client
            .fetch_did_secrets_bundle("rooms/host-1")
            .await
            .expect_err("a refusal is a refusal");
        assert!(matches!(err, VtaError::Forbidden(_)), "got: {err:?}");
        assert_eq!(
            sink.seen.lock().expect("not poisoned").len(),
            1,
            "one attempt, no fallback"
        );
    }
}
