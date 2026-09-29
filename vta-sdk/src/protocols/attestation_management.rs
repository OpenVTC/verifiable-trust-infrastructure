//! TEE attestation wire types.
//!
//! The attestation reads are Trust Tasks — `spec/vta/attestation/{status,
//! report,config-report}/0.1`, generated under
//! `trust_tasks_rs::specs::vta::attestation` — dispatched on the VTA's spine
//! over every transport. The bespoke `firstperson.network/vta/1.0/attestation/*`
//! DIDComm messages that used to sit here are gone: nothing sent them, and a
//! bare protocol message is not a carriage the Trust Task bindings allow.

/// Response to `spec/vta/attestation/mnemonic-export/1.0`
/// ([`crate::trust_tasks::TASK_ATTESTATION_MNEMONIC_EXPORT_1_0`]): a TEE VTA's
/// BIP-39 seed mnemonic, sealed to the requester.
///
/// The request is a sealed-transfer `BootstrapRequest` (`pnm bootstrap request`):
/// the requester's ephemeral `did:key` and a fresh nonce. The bundle carries a
/// `SeedMnemonic` payload sealed to that key under an `Attested` producer
/// assertion; open it with `pnm bootstrap open --expect-digest <digest>`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MnemonicExportResultBody {
    /// ASCII-armored sealed bundle.
    pub bundle: String,
    /// SHA-256 of the bundle — confirm it out of band before opening.
    pub digest: String,
    /// Seconds that were left in the export window.
    pub window_remaining_secs: u64,
}
