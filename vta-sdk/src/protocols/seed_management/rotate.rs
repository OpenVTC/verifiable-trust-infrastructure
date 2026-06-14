use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RotateSeedBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
}

// Manual Debug — `mnemonic` is the BIP-39 phrase that bootstraps the
// new active seed. Redact via `{:?}`; Serialize is unchanged so the
// rotate-seed wire call still carries the field.
impl std::fmt::Debug for RotateSeedBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotateSeedBody")
            .field("mnemonic", &self.mnemonic.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RotateSeedResultBody {
    pub previous_seed_id: u32,
    pub new_seed_id: u32,
}
