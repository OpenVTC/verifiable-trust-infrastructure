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
    /// Resolves the context DID, paginates through all active keys,
    /// fetches each secret, and returns a bundle ready for encoding/transport.
    pub async fn fetch_did_secrets_bundle(
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
