//! TPM 2.0 sealing of the `encrypted_file` KEK (`tpm` feature, Linux).
//!
//! The KEK is a TPM "sealed data object": a keyed-hash object with a null
//! scheme whose sensitive part is the 32-byte KEK, created under the owner
//! hierarchy's storage root key (SRK). The SRK is not persisted: it is the
//! primary key the TPM derives deterministically from the owner hierarchy seed
//! and the fixed template below (ECC P-256, AES-128-CFB, the TCG "SRK"
//! shape), so it is recreated identically on every call.
//!
//! When PCRs are configured the object has no usable auth value
//! (`userWithAuth` clear) and its `authPolicy` is a `PolicyPCR` digest over
//! the current values of those SHA-256 PCRs, so it unseals only while they
//! hold the same values. Without PCRs it unseals with an empty auth value, for
//! any process that can use this TPM.
//!
//! The sealed public and private parts go in the envelope header (see
//! [`TpmDescriptor`]); the private part is wrapped by the SRK and useless in
//! any other TPM, or in this one after `tpm2_clear` (which changes the owner
//! seed).
//!
//! Assumes the owner hierarchy has an empty auth value, which is the default.

use std::str::FromStr;

use tss_esapi::Context;
use tss_esapi::TctiNameConf;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{KeyHandle, ObjectHandle, SessionHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::{AuthSession, PolicySession};
use tss_esapi::structures::{
    Digest, EccPoint, KeyedHashScheme, PcrSelectSize, PcrSelectionList, PcrSelectionListBuilder,
    PcrSlot, Private, Public, PublicBuilder, PublicEccParametersBuilder, PublicKeyedHashParameters,
    SensitiveData, SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::traits::{Marshall, UnMarshall};
use zeroize::Zeroizing;

use vti_common::error::AppError;

use super::TpmSettings;
use super::envelope::TpmDescriptor;

fn tpm_err(what: &str) -> impl FnOnce(tss_esapi::Error) -> AppError + '_ {
    move |e| AppError::SecretStore(format!("TPM: {what}: {e}"))
}

fn open_context(tcti: &str) -> Result<Context, AppError> {
    let conf = TctiNameConf::from_str(tcti)
        .map_err(|e| AppError::Config(format!("TPM TCTI '{tcti}' is not valid: {e}")))?;
    Context::new(conf).map_err(tpm_err("opening the TPM"))
}

/// The SRK template: a restricted ECC P-256 decryption (storage) key.
fn srk_template() -> Result<Public, AppError> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .build()
        .map_err(tpm_err("SRK attributes"))?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_128_CFB,
                EccCurve::NistP256,
            )
            .build()
            .map_err(tpm_err("SRK parameters"))?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(tpm_err("SRK template"))
}

fn create_srk(ctx: &mut Context) -> Result<KeyHandle, AppError> {
    let template = srk_template()?;
    ctx.execute_with_nullauth_session(|ctx| {
        ctx.create_primary(Hierarchy::Owner, template, None, None, None, None)
    })
    .map(|r| r.key_handle)
    .map_err(tpm_err("creating the storage root key"))
}

fn pcr_selection(pcrs: &[u8]) -> Result<PcrSelectionList, AppError> {
    let slots = pcrs
        .iter()
        .map(|p| PcrSlot::try_from(1u32 << p).map_err(tpm_err("PCR index")))
        .collect::<Result<Vec<_>, _>>()?;
    PcrSelectionListBuilder::new()
        .with_size_of_select(PcrSelectSize::ThreeOctets)
        .with_selection(HashingAlgorithm::Sha256, &slots)
        .build()
        .map_err(tpm_err("PCR selection"))
}

/// Start a policy (or trial) session and apply `PolicyPCR` over the PCRs'
/// current values.
fn pcr_policy_session(
    ctx: &mut Context,
    session_type: SessionType,
    pcrs: &[u8],
) -> Result<(AuthSession, PolicySession), AppError> {
    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            session_type,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(tpm_err("starting a policy session"))?
        .ok_or_else(|| AppError::SecretStore("TPM: no policy session returned".into()))?;
    let policy = PolicySession::try_from(session).map_err(tpm_err("policy session"))?;
    // An empty digest: the TPM computes it from the PCRs' current values.
    ctx.policy_pcr(policy, Digest::default(), pcr_selection(pcrs)?)
        .map_err(tpm_err("PolicyPCR"))?;
    Ok((session, policy))
}

fn flush_session(ctx: &mut Context, policy: PolicySession) {
    let _ = ctx.flush_context(ObjectHandle::from(SessionHandle::from(policy)));
}

/// Seal `kek` to this TPM, bound to `settings.pcrs` when any are set.
pub(super) fn seal(settings: &TpmSettings, kek: &[u8; 32]) -> Result<TpmDescriptor, AppError> {
    let mut ctx = open_context(&settings.tcti)?;
    let srk = create_srk(&mut ctx)?;
    let result = seal_under(&mut ctx, srk, settings, kek);
    let _ = ctx.flush_context(srk.into());
    result
}

fn seal_under(
    ctx: &mut Context,
    srk: KeyHandle,
    settings: &TpmSettings,
    kek: &[u8; 32],
) -> Result<TpmDescriptor, AppError> {
    let bound = !settings.pcrs.is_empty();
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_no_da(true)
        .with_user_with_auth(!bound)
        .build()
        .map_err(tpm_err("sealed object attributes"))?;
    let mut builder = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default());
    if bound {
        let (_, trial) = pcr_policy_session(ctx, SessionType::Trial, &settings.pcrs)?;
        let digest = ctx.policy_get_digest(trial);
        flush_session(ctx, trial);
        builder = builder.with_auth_policy(digest.map_err(tpm_err("policy digest"))?);
    }
    let public = builder.build().map_err(tpm_err("sealed object template"))?;
    let sensitive = SensitiveData::try_from(kek.to_vec()).map_err(tpm_err("sealed data"))?;
    let created = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.create(srk, public, None, Some(sensitive), None, None)
        })
        .map_err(tpm_err("sealing the key-encryption key"))?;
    Ok(TpmDescriptor {
        pcrs: settings.pcrs.clone(),
        public: created
            .out_public
            .marshall()
            .map_err(tpm_err("marshalling the sealed public part"))?,
        private: created.out_private.value().to_vec(),
    })
}

/// Unseal the KEK in `descriptor`. Uses the PCR list recorded when it was
/// sealed (the object's policy was computed over exactly those).
pub(super) fn unseal(
    settings: &TpmSettings,
    descriptor: &TpmDescriptor,
) -> Result<Zeroizing<[u8; 32]>, AppError> {
    if descriptor.pcrs != settings.pcrs {
        tracing::info!(
            sealed = ?descriptor.pcrs,
            configured = ?settings.pcrs,
            "the TPM-sealed key is bound to different PCRs than configured; the next write \
             re-seals to the configured PCRs"
        );
    }
    let mut ctx = open_context(&settings.tcti)?;
    let srk = create_srk(&mut ctx)?;
    let result = unseal_under(&mut ctx, srk, descriptor);
    let _ = ctx.flush_context(srk.into());
    result
}

fn unseal_under(
    ctx: &mut Context,
    srk: KeyHandle,
    descriptor: &TpmDescriptor,
) -> Result<Zeroizing<[u8; 32]>, AppError> {
    let public = Public::unmarshall(&descriptor.public).map_err(tpm_err("sealed public part"))?;
    let private =
        Private::try_from(descriptor.private.clone()).map_err(tpm_err("sealed private part"))?;
    let object = ctx
        .execute_with_nullauth_session(|ctx| ctx.load(srk, private, public))
        .map_err(tpm_err(
            "loading the sealed key (a different TPM, or the owner hierarchy was cleared?)",
        ))?;

    let data = if descriptor.pcrs.is_empty() {
        ctx.execute_with_nullauth_session(|ctx| ctx.unseal(object.into()))
    } else {
        match pcr_policy_session(ctx, SessionType::Policy, &descriptor.pcrs) {
            Ok((session, policy)) => {
                let r = ctx.execute_with_session(Some(session), |ctx| ctx.unseal(object.into()));
                flush_session(ctx, policy);
                r
            }
            Err(e) => {
                let _ = ctx.flush_context(object.into());
                return Err(e);
            }
        }
    };
    let _ = ctx.flush_context(object.into());
    let data = data.map_err(tpm_err(
        "unsealing the key-encryption key (PCR values changed since it was sealed?)",
    ))?;
    if data.len() != 32 {
        return Err(AppError::SecretStore(
            "TPM: the sealed key-encryption key is not 32 bytes".into(),
        ));
    }
    let mut kek = Zeroizing::new([0u8; 32]);
    kek.copy_from_slice(data.value());
    Ok(kek)
}

/// Run against a real or software TPM only when `VTI_SECRETS_TEST_TCTI` names
/// one (e.g. `swtpm:host=127.0.0.1,port=2321`); otherwise each test returns
/// early. Nothing in CI provides a TPM, so these are for a host that has one.
#[cfg(test)]
mod tests {
    use super::super::super::SeedStore;
    use super::super::EncryptedFileSeedStore;
    use super::*;
    use crate::config::{EncryptedFileConfig, KekSource};

    fn test_tcti() -> Option<String> {
        std::env::var("VTI_SECRETS_TEST_TCTI").ok()
    }

    fn store(dir: &std::path::Path, tcti: &str, pcrs: Vec<u8>) -> EncryptedFileSeedStore {
        let cfg = EncryptedFileConfig::new(KekSource::Tpm {
            pcrs,
            tcti: Some(tcti.to_string()),
        });
        EncryptedFileSeedStore::from_config(&cfg, dir, "seed.enc").unwrap()
    }

    fn extend_pcr16(tcti: &str) {
        use tss_esapi::handles::PcrHandle;
        use tss_esapi::structures::DigestValues;
        let mut ctx = open_context(tcti).unwrap();
        let mut vals = DigestValues::new();
        vals.set(
            HashingAlgorithm::Sha256,
            Digest::try_from(vec![0xa5u8; 32]).unwrap(),
        );
        ctx.execute_with_nullauth_session(|ctx| ctx.pcr_extend(PcrHandle::Pcr16, vals))
            .unwrap();
    }

    #[tokio::test]
    async fn tpm_round_trip_without_pcrs() {
        let Some(tcti) = test_tcti() else { return };
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path(), &tcti, vec![]);
        s.set(b"tpm sealed seed").await.unwrap();
        assert_eq!(s.get().await.unwrap().unwrap(), b"tpm sealed seed");
    }

    #[tokio::test]
    async fn tpm_pcr_binding_holds_until_the_pcr_changes() {
        let Some(tcti) = test_tcti() else { return };
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path(), &tcti, vec![16]);
        s.set(b"pcr bound").await.unwrap();
        assert_eq!(s.get().await.unwrap().unwrap(), b"pcr bound");

        extend_pcr16(&tcti);
        match s.get().await {
            Err(AppError::SecretStore(m)) => assert!(m.contains("unsealing"), "{m}"),
            other => panic!("want an unseal failure after the PCR changed, got {other:?}"),
        }

        // A write re-seals to the current values.
        s.set(b"resealed").await.unwrap();
        assert_eq!(s.get().await.unwrap().unwrap(), b"resealed");
    }

    #[tokio::test]
    async fn tpm_tampered_sealed_blob_fails_closed() {
        let Some(tcti) = test_tcti() else { return };
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path(), &tcti, vec![]);
        s.set(b"x").await.unwrap();
        let mut bytes = std::fs::read(s.path()).unwrap();
        // The descriptor starts at 58; byte 70 is inside the sealed public part.
        bytes[70] ^= 1;
        std::fs::write(s.path(), &bytes).unwrap();
        assert!(s.get().await.is_err());
    }
}
