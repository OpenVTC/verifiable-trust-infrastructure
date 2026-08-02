//! Backup management methods on [`VtaClient`]: encrypted export and import.

use super::VtaClient;
use crate::error::VtaError;

impl VtaClient {
    /// Export VTA state to an encrypted backup, inline.
    ///
    /// **The legacy path.** The whole envelope crosses the wire in one
    /// response, which is why this rides a protocol message rather than a Trust
    /// Task — and why it has no TSP dispatcher. The descriptor flow
    /// (`backup/initiate-export` + a blob fetch + `backup/complete-export`) is
    /// the default as of rollout step 5 and works on every transport; this
    /// remains only as the `--use-rest-legacy` escape hatch, and goes at step 6
    /// with the route it calls.
    #[deprecated(
        since = "0.21.3",
        note = "inline export rides a legacy protocol message with no TSP path — \
                use the descriptor flow (backup/initiate-export)"
    )]
    pub async fn backup_export(
        &self,
        password: &str,
        include_audit: bool,
    ) -> Result<crate::protocols::backup_management::types::BackupEnvelope, VtaError> {
        self.rpc(
            crate::protocols::backup_management::EXPORT_BACKUP,
            serde_json::json!({ "password": password, "include_audit": include_audit }),
            crate::protocols::backup_management::EXPORT_BACKUP_RESULT,
            120, // backup can take longer
            |c, url| {
                c.post(format!("{url}/backup/export")).json(
                    &serde_json::json!({ "password": password, "include_audit": include_audit }),
                )
            },
        )
        .await
    }

    /// Import VTA state from an encrypted backup, inline.
    ///
    /// The legacy counterpart of [`backup_export`](Self::backup_export); see
    /// its note.
    #[deprecated(
        since = "0.21.3",
        note = "inline import rides a legacy protocol message with no TSP path — \
                use the descriptor flow (backup/initiate-import)"
    )]
    pub async fn backup_import(
        &self,
        backup: &crate::protocols::backup_management::types::BackupEnvelope,
        password: &str,
        confirm: bool,
    ) -> Result<crate::protocols::backup_management::types::ImportResult, VtaError> {
        self.rpc(
            crate::protocols::backup_management::IMPORT_BACKUP,
            serde_json::json!({ "backup": backup, "password": password, "confirm": confirm }),
            crate::protocols::backup_management::IMPORT_BACKUP_RESULT,
            120,
            |c, url| {
                c.post(format!("{url}/backup/import"))
                    .json(&serde_json::json!({ "backup": backup, "password": password, "confirm": confirm }))
            },
        )
        .await
    }
}
