//! External-account Trust Task client methods (`external/*/0.1`) — the VTA as
//! the key authority for cloud and third-party accounts.
//!
//! Every method takes the task's generated payload type and returns its
//! generated response type (`trust_tasks_rs::specs::external`), so a caller
//! cannot build a request the schema would refuse.
//!
//! Two helpers carry the family's sealed material:
//! [`seal_external_secret`] seals an account's secret in the client, to a
//! wrapping key from `keys/import-wrapping-key`, for
//! [`VtaClient::external_accounts_secret_set`]; [`open_external_credential`]
//! opens what [`VtaClient::external_credentials_issue`] returns.

use serde::Serialize;
use serde::de::DeserializeOwned;
use trust_tasks_rs::specs::external as ext;

use super::VtaClient;
use crate::error::VtaError;
use crate::trust_tasks;

/// Round-trip timeout (seconds). A probe dials the provider, so it gets more.
const EXTERNAL_TT_TIMEOUT: u64 = 30;
const EXTERNAL_PROBE_TIMEOUT: u64 = 90;

impl VtaClient {
    async fn external_call<P: Serialize, R: DeserializeOwned>(
        &self,
        uri: &str,
        payload: &P,
        timeout: u64,
    ) -> Result<R, VtaError> {
        let payload = serde_json::to_value(payload)
            .map_err(|e| VtaError::Validation(format!("{uri} request: {e}")))?;
        let answer = self.dispatch_trust_task(uri, payload, timeout).await?;
        serde_json::from_value(answer).map_err(|e| {
            VtaError::Protocol(format!("{uri} response does not match its schema: {e}"))
        })
    }

    /// `external/accounts/list/0.1`.
    pub async fn external_accounts_list(
        &self,
        req: &ext::accounts::list::v0_1::Payload,
    ) -> Result<ext::accounts::list::v0_1::Response, VtaError> {
        self.external_call(
            trust_tasks::TASK_EXTERNAL_ACCOUNTS_LIST_0_1,
            req,
            EXTERNAL_TT_TIMEOUT,
        )
        .await
    }

    /// `external/accounts/get/0.1`.
    pub async fn external_accounts_get(
        &self,
        req: &ext::accounts::get::v0_1::Payload,
    ) -> Result<ext::accounts::get::v0_1::Response, VtaError> {
        self.external_call(
            trust_tasks::TASK_EXTERNAL_ACCOUNTS_GET_0_1,
            req,
            EXTERNAL_TT_TIMEOUT,
        )
        .await
    }

    /// `external/accounts/create/0.1`. May be held for other administrators'
    /// consent under the VTA's approvals policy.
    pub async fn external_accounts_create(
        &self,
        req: &ext::accounts::create::v0_1::Payload,
    ) -> Result<ext::accounts::create::v0_1::Response, VtaError> {
        self.external_call(
            trust_tasks::TASK_EXTERNAL_ACCOUNTS_CREATE_0_1,
            req,
            EXTERNAL_TT_TIMEOUT,
        )
        .await
    }

    /// `external/accounts/update/0.1`.
    pub async fn external_accounts_update(
        &self,
        req: &ext::accounts::update::v0_1::Payload,
    ) -> Result<ext::accounts::update::v0_1::Response, VtaError> {
        self.external_call(
            trust_tasks::TASK_EXTERNAL_ACCOUNTS_UPDATE_0_1,
            req,
            EXTERNAL_TT_TIMEOUT,
        )
        .await
    }

    /// `external/accounts/secret/set/0.1`. Seal the secret with
    /// [`seal_external_secret`] first; the answer is only a fingerprint.
    pub async fn external_accounts_secret_set(
        &self,
        req: &ext::accounts::secret::set::v0_1::Payload,
    ) -> Result<ext::accounts::secret::set::v0_1::Response, VtaError> {
        self.external_call(
            trust_tasks::TASK_EXTERNAL_ACCOUNTS_SECRET_SET_0_1,
            req,
            EXTERNAL_TT_TIMEOUT,
        )
        .await
    }

    /// `external/accounts/bindings/grant/0.1`.
    pub async fn external_accounts_bindings_grant(
        &self,
        req: &ext::accounts::bindings::grant::v0_1::Payload,
    ) -> Result<ext::accounts::bindings::grant::v0_1::Response, VtaError> {
        self.external_call(
            trust_tasks::TASK_EXTERNAL_ACCOUNTS_BINDINGS_GRANT_0_1,
            req,
            EXTERNAL_TT_TIMEOUT,
        )
        .await
    }

    /// `external/accounts/bindings/revoke/0.1`.
    pub async fn external_accounts_bindings_revoke(
        &self,
        req: &ext::accounts::bindings::revoke::v0_1::Payload,
    ) -> Result<ext::accounts::bindings::revoke::v0_1::Response, VtaError> {
        self.external_call(
            trust_tasks::TASK_EXTERNAL_ACCOUNTS_BINDINGS_REVOKE_0_1,
            req,
            EXTERNAL_TT_TIMEOUT,
        )
        .await
    }

    /// `external/accounts/setup/0.1`.
    pub async fn external_accounts_setup(
        &self,
        req: &ext::accounts::setup::v0_1::Payload,
    ) -> Result<ext::accounts::setup::v0_1::Response, VtaError> {
        self.external_call(
            trust_tasks::TASK_EXTERNAL_ACCOUNTS_SETUP_0_1,
            req,
            EXTERNAL_TT_TIMEOUT,
        )
        .await
    }

    /// `external/accounts/probe/0.1`. A provider refusal is a report with
    /// `ok: false`, not an error.
    pub async fn external_accounts_probe(
        &self,
        req: &ext::accounts::probe::v0_1::Payload,
    ) -> Result<ext::accounts::probe::v0_1::Response, VtaError> {
        self.external_call(
            trust_tasks::TASK_EXTERNAL_ACCOUNTS_PROBE_0_1,
            req,
            EXTERNAL_PROBE_TIMEOUT,
        )
        .await
    }

    /// `external/accounts/keys/rotate/0.1`.
    pub async fn external_accounts_keys_rotate(
        &self,
        req: &ext::accounts::keys::rotate::v0_1::Payload,
    ) -> Result<ext::accounts::keys::rotate::v0_1::Response, VtaError> {
        self.external_call(
            trust_tasks::TASK_EXTERNAL_ACCOUNTS_KEYS_ROTATE_0_1,
            req,
            EXTERNAL_TT_TIMEOUT,
        )
        .await
    }

    /// `external/accounts/suspend/0.1` — the kill switch.
    pub async fn external_accounts_suspend(
        &self,
        req: &ext::accounts::suspend::v0_1::Payload,
    ) -> Result<ext::accounts::suspend::v0_1::Response, VtaError> {
        self.external_call(
            trust_tasks::TASK_EXTERNAL_ACCOUNTS_SUSPEND_0_1,
            req,
            EXTERNAL_TT_TIMEOUT,
        )
        .await
    }

    /// `external/accounts/resume/0.1`.
    pub async fn external_accounts_resume(
        &self,
        req: &ext::accounts::resume::v0_1::Payload,
    ) -> Result<ext::accounts::resume::v0_1::Response, VtaError> {
        self.external_call(
            trust_tasks::TASK_EXTERNAL_ACCOUNTS_RESUME_0_1,
            req,
            EXTERNAL_TT_TIMEOUT,
        )
        .await
    }

    /// `external/accounts/archive/0.1`.
    pub async fn external_accounts_archive(
        &self,
        req: &ext::accounts::archive::v0_1::Payload,
    ) -> Result<ext::accounts::archive::v0_1::Response, VtaError> {
        self.external_call(
            trust_tasks::TASK_EXTERNAL_ACCOUNTS_ARCHIVE_0_1,
            req,
            EXTERNAL_TT_TIMEOUT,
        )
        .await
    }

    /// `external/accounts/restore/0.1` — lands the account suspended.
    pub async fn external_accounts_restore(
        &self,
        req: &ext::accounts::restore::v0_1::Payload,
    ) -> Result<ext::accounts::restore::v0_1::Response, VtaError> {
        self.external_call(
            trust_tasks::TASK_EXTERNAL_ACCOUNTS_RESTORE_0_1,
            req,
            EXTERNAL_TT_TIMEOUT,
        )
        .await
    }

    /// `external/accounts/delete/0.1` — archived accounts only.
    pub async fn external_accounts_delete(
        &self,
        req: &ext::accounts::delete::v0_1::Payload,
    ) -> Result<ext::accounts::delete::v0_1::Response, VtaError> {
        self.external_call(
            trust_tasks::TASK_EXTERNAL_ACCOUNTS_DELETE_0_1,
            req,
            EXTERNAL_TT_TIMEOUT,
        )
        .await
    }

    /// `external/credentials/issue/0.1`. Open the answer's `sealedCredential`
    /// with [`open_external_credential`]; keep the credential in memory only.
    pub async fn external_credentials_issue(
        &self,
        req: &ext::credentials::issue::v0_1::Payload,
    ) -> Result<ext::credentials::issue::v0_1::Response, VtaError> {
        self.external_call(
            trust_tasks::TASK_EXTERNAL_CREDENTIALS_ISSUE_0_1,
            req,
            EXTERNAL_TT_TIMEOUT,
        )
        .await
    }
}

/// Seal an external account's secret in the client, to `wrapping_did_key` (the
/// `wrappingKey` of a fresh `keys/import-wrapping-key/0.1` answer), naming the
/// account it is for — and, for `s3-static-presign`, the access key id it
/// belongs to. Returns the armor `secret/set` carries.
#[cfg(feature = "sealed-transfer")]
pub async fn seal_external_secret(
    wrapping_did_key: &str,
    context: &str,
    account: &str,
    secret: &str,
    access_key_id: Option<&str>,
) -> Result<String, VtaError> {
    use crate::sealed_transfer::{
        AssertionProof, ExternalSecretPayload, InMemoryNonceStore, ProducerAssertion,
        SealedPayloadV1, armor, generate_ed25519_keypair, seal_payload,
    };
    let recipient = affinidi_crypto::did_key::did_key_to_ed25519_pub(wrapping_did_key)
        .and_then(|ed| affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(&ed))
        .map_err(|e| {
            VtaError::Validation(format!("wrapping key is not an Ed25519 did:key: {e}"))
        })?;
    // The request carrying the bundle is authenticated, and the wrapping key is
    // single-use and seconds old, so `PinnedOnly` is the honest assertion: no
    // producer key is claimed that the VTA could check.
    let (_seed, producer) = generate_ed25519_keypair();
    // A random v4 UUID's bytes: 122 random bits, unique per bundle.
    let bundle_id = uuid::Uuid::new_v4().into_bytes();
    let payload = SealedPayloadV1::ExternalSecret(Box::new(ExternalSecretPayload {
        context: context.to_string(),
        account: account.to_string(),
        secret: secret.to_string(),
        access_key_id: access_key_id.map(str::to_string),
    }));
    let bundle = seal_payload(
        &recipient,
        bundle_id,
        ProducerAssertion {
            producer_did: affinidi_crypto::did_key::ed25519_pub_to_did_key(&producer),
            proof: AssertionProof::PinnedOnly,
        },
        &payload,
        &InMemoryNonceStore::new(),
    )
    .await
    .map_err(|e| VtaError::Protocol(format!("sealing the secret failed: {e}")))?;
    Ok(armor::encode(&bundle))
}

/// Open an issued credential with the consumer's X25519 key-agreement secret.
///
/// The bundle's producer assertion is `PinnedOnly`: its integrity anchor is the
/// proof on the `#response` that carried it, which the client verified before
/// returning it. Do not open a bundle that did not arrive that way.
#[cfg(feature = "sealed-transfer")]
pub fn open_external_credential(
    armored: &str,
    x25519_secret: &[u8; 32],
) -> Result<crate::sealed_transfer::ExternalCredentialPayload, VtaError> {
    use crate::sealed_transfer::{
        PinnedOnlyPolicy, SealedPayloadV1, armor, open_bundle_with_policy,
    };
    let bundles = armor::decode(armored)
        .map_err(|e| VtaError::Protocol(format!("sealed credential armor: {e}")))?;
    let [bundle] = bundles.as_slice() else {
        return Err(VtaError::Protocol(
            "expected exactly one sealed bundle".into(),
        ));
    };
    let opened = open_bundle_with_policy(
        x25519_secret,
        bundle,
        None,
        PinnedOnlyPolicy::CallerHasIndependentTrustAnchor,
    )
    .map_err(|e| VtaError::Protocol(format!("sealed credential did not open: {e}")))?;
    match opened.payload {
        SealedPayloadV1::ExternalCredential(c) => Ok(*c),
        _ => Err(VtaError::Protocol(
            "the sealed bundle is not an external credential".into(),
        )),
    }
}
