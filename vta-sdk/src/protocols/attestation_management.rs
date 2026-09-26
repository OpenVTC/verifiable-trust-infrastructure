//! DIDComm protocol types for TEE attestation management.

/// Request TEE detection status.
pub const GET_TEE_STATUS: &str = "https://firstperson.network/vta/1.0/attestation/status";
/// Response with TEE detection status.
pub const GET_TEE_STATUS_RESULT: &str =
    "https://firstperson.network/vta/1.0/attestation/status-result";

/// Request a fresh attestation report (body includes nonce).
pub const REQUEST_ATTESTATION: &str = "https://firstperson.network/vta/1.0/attestation/request";
/// Response with attestation report.
pub const ATTESTATION_RESULT: &str = "https://firstperson.network/vta/1.0/attestation/result";

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
