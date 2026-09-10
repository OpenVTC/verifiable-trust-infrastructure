//! Convenience methods for paginating + bundling key secrets via [`VtaClient`].

use super::VtaClient;
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
    ///   future "this key may not leave" rule could hook — which
    ///   `keys/set-exportability` now is.
    pub async fn fetch_did_secrets_bundle(
        &self,
        context_id: &str,
    ) -> Result<crate::did_secrets::DidSecretsBundle, VtaError> {
        let body: crate::protocols::context_management::secrets::ContextSecretsResultBody = self
            .rpc_tt(
                crate::trust_tasks::TASK_CONTEXTS_SECRETS_1_0,
                serde_json::json!({ "id": context_id }),
                30,
            )
            .await?;
        Ok(body.into())
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

    /// One route, and no second one to drift. The fallback that used to sit
    /// here existed so a service could be upgraded before the VTA it talked to
    /// was; that gap has been closed by deployment, and keeping a second path
    /// to the same bundle would keep `seeds/export-mnemonic` alive to serve it.
    #[tokio::test]
    async fn an_old_vta_is_a_clear_failure_not_a_silent_downgrade() {
        let (client, sink) = client_of(|uri| {
            Err(VtaError::UnsupportedTaskType {
                type_uri: uri.to_string(),
                served_versions: Vec::new(),
            })
        });

        let err = client
            .fetch_did_secrets_bundle("rooms/host-1")
            .await
            .expect_err("a VTA that does not serve the task cannot answer");
        assert!(
            matches!(err, VtaError::UnsupportedTaskType { .. }),
            "the refusal must say which task is missing, so the fix is 'upgrade the VTA' \
             rather than a puzzle; got {err:?}"
        );
        assert_eq!(
            sink.seen.lock().expect("not poisoned").len(),
            1,
            "one attempt: no per-key walk to fall back to"
        );
    }

    /// A refusal surfaces as itself. There is nothing to retry it against, and
    /// nothing that could turn a permission error into a different one.
    #[tokio::test]
    async fn a_refusal_surfaces_as_itself() {
        let (client, sink) = client_of(|_| Err(VtaError::Forbidden("no access".into())));

        let err = client
            .fetch_did_secrets_bundle("rooms/host-1")
            .await
            .expect_err("a refusal is a refusal");
        assert!(matches!(err, VtaError::Forbidden(_)), "got: {err:?}");
        assert_eq!(
            sink.seen.lock().expect("not poisoned").len(),
            1,
            "one attempt"
        );
    }
}
