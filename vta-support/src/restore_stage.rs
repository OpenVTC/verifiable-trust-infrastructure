//! The staged restore: how a backup import crosses the reboot that applies it.
//!
//! # Why a restore is staged rather than applied in place
//!
//! A backup carries a master seed, and in a hardened or TEE deployment the
//! store's at-rest key is *derived from the seed*. Restoring a backup whose
//! seed differs from the running one therefore changes the key every row must
//! be written under — and the running process holds the old key in every
//! keyspace handle it has. Writing the restored state through those handles
//! and then changing the seed leaves a store no boot can read; changing the
//! seed first leaves the running process writing garbage.
//!
//! So an import does three things, in this order, and no more:
//!
//! 1. **Stage** the decrypted payload in the unencrypted `bootstrap` keyspace,
//!    sealed under a key derived from the *restored* seed ([`stage_key`]).
//! 2. **Commit** the restored seed (and JWT key) to wherever the target keeps
//!    them — its secret store, or a KMS-sealed row in an enclave.
//! 3. **Reboot.**
//!
//! Boot then derives the storage key from whatever seed it finds, opens the
//! stage with a key derived from that same seed, and applies the restore under
//! the right storage key before anything else reads the store.
//!
//! # Crash consistency
//!
//! The stage is sealed under the restored seed, so it opens only once step 2
//! has happened. That makes every interruption safe without a separate
//! sentinel:
//!
//! - Interrupted before the commit: the next boot finds a stage it cannot open
//!   under the seed it has, discards it, and boots the unchanged VTA.
//! - Interrupted after the commit: the stage opens, and the boot applies it.
//!   Applying is wipe-then-write, so a boot interrupted *while* applying just
//!   applies again. The stage is removed only after the restored state is
//!   complete.
//!
//! # What is authenticated
//!
//! In an enclave the `bootstrap` keyspace lives on the untrusted parent. The
//! [`StageHeader`] is only a locator — every security-relevant fact about the
//! restore ([`StageMeta`]: who staged it, the anti-rollback binding, the digest
//! of the KMS-sealed secrets it belongs to) travels *inside* the sealed body,
//! where the parent can neither read nor alter it.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use vta_sdk::protocols::backup_management::types::{BackupEnvironment, BackupPayload};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// Locator row for a staged restore, in the `bootstrap` keyspace.
pub const STAGE_HEADER_KEY: &str = "restore:stage";
/// Prefix of the sealed-body chunks, in the `bootstrap` keyspace.
pub const STAGE_CHUNK_PREFIX: &str = "restore:stage-chunk:";
/// The KMS-sealed seed + JWT key a restore into an enclave commits, in the
/// `bootstrap` keyspace. One row, so the commit is a single write: an enclave
/// either boots from it or does not see it at all.
pub const TEE_RESTORED_SECRETS_KEY: &str = "restore:tee-secrets";

/// Chunk size for the sealed body. Well under the vsock store's 16 MiB frame,
/// so a large backup never fails on a single oversized write.
const CHUNK_LEN: usize = 1024 * 1024;
/// HKDF `info` for [`stage_key`]. A new stage format is a new string.
const STAGE_INFO: &[u8] = b"vta-restore-stage/v1";
const NONCE_LEN: usize = 12;

/// Unauthenticated locator for the sealed body. Carries nothing that matters
/// if a hostile store operator changes it: a wrong value only makes the body
/// fail to open.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageHeader {
    pub restore_id: String,
    pub chunks: u32,
    /// base64url AES-GCM nonce for the body.
    pub nonce: String,
}

/// An anti-rollback reservation made when the restore was staged: the external
/// counter for `did` was moved to `version`, and the restored state must be
/// sealed at exactly that version. A replay of the staged restore later finds
/// the counter elsewhere and is refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorBinding {
    pub did: String,
    pub version: u64,
}

/// The authenticated facts about a staged restore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageMeta {
    pub restore_id: String,
    pub staged_at: DateTime<Utc>,
    /// DID of the super-admin who committed the import.
    pub staged_by: String,
    /// The kind of deployment the restore was staged on — and must be applied
    /// on. A stage carried to a different kind of deployment is refused.
    pub target_environment: BackupEnvironment,
    /// The restore replaces an identity the VTA already ran as with a different
    /// one. Hosted-DID registrations then belong to the source, not to this VTA.
    pub cross_identity: bool,
    /// SHA-256 (hex) of the [`TEE_RESTORED_SECRETS_KEY`] row this restore
    /// committed, in an enclave. Boot honours that row only when it matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee_secrets_sha256: Option<String>,
    /// Anti-rollback reservation, when the target runs an external counter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<AnchorBinding>,
}

#[derive(Serialize, Deserialize)]
struct StagedBody {
    meta: StageMeta,
    payload: BackupPayload,
}

/// A staged restore whose body opened under the current seed.
pub struct OpenedStage {
    pub meta: StageMeta,
    pub payload: BackupPayload,
}

/// What [`open_stage`] found.
pub enum StageState {
    /// No restore is staged.
    None,
    /// A restore is staged and committed: its body opened under this seed.
    Committed(Box<OpenedStage>),
    /// A restore is staged but its body does not open under this seed — the
    /// commit never happened (or the rows were tampered with). Nothing to apply.
    Uncommitted { restore_id: String },
}

/// The key a staged body is sealed under: HKDF-SHA256 over the restored seed,
/// salted with the restore id.
#[must_use]
pub fn stage_key(seed: &[u8], restore_id: &str) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(restore_id.as_bytes()), seed);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(STAGE_INFO, out.as_mut())
        .expect("32-byte HKDF output is valid");
    out
}

/// SHA-256 of `bytes`, lowercase hex.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn aad(restore_id: &str, chunks: u32) -> Vec<u8> {
    let mut aad = STAGE_INFO.to_vec();
    aad.push(0);
    aad.extend_from_slice(restore_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&chunks.to_be_bytes());
    aad
}

fn chunk_key(restore_id: &str, index: u32) -> String {
    format!("{STAGE_CHUNK_PREFIX}{restore_id}:{index:06}")
}

/// Seal `payload` under the restored `seed` and write it as the staged restore,
/// replacing any stage already present. The header is written last, so a
/// crash mid-write leaves no header pointing at a partial body.
///
/// `bootstrap_ks` must be the **unencrypted** `bootstrap` handle: boot opens the
/// stage before it knows which storage key applies.
pub async fn write_stage(
    bootstrap_ks: &KeyspaceHandle,
    seed: &[u8],
    meta: StageMeta,
    payload: BackupPayload,
) -> Result<(), AppError> {
    clear_stage(bootstrap_ks).await?;

    let restore_id = meta.restore_id.clone();
    let body = StagedBody { meta, payload };
    let mut plaintext = Zeroizing::new(
        serde_json::to_vec(&body)
            .map_err(|e| AppError::Internal(format!("serialize staged restore: {e}")))?,
    );
    drop(body);

    let chunks = u32::try_from(plaintext.len().div_ceil(CHUNK_LEN).max(1))
        .map_err(|_| AppError::Validation("backup too large to stage".into()))?;
    // Chunk count is fixed before encryption so it can be bound into the AAD:
    // ciphertext expansion is a constant 16-byte tag, which lands in the last
    // chunk and cannot change the count.
    let key = stage_key(seed, &restore_id);
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| AppError::Internal(format!("stage key: {e}")))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::fill(&mut nonce_bytes);
    let nonce: &Nonce<_> = (&nonce_bytes).into();
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad(&restore_id, chunks),
            },
        )
        .map_err(|e| AppError::Internal(format!("seal staged restore: {e}")))?;
    plaintext.zeroize();

    let chunk_len = ciphertext.len().div_ceil(chunks as usize);
    for (i, chunk) in ciphertext.chunks(chunk_len.max(1)).enumerate() {
        bootstrap_ks
            .insert_raw(chunk_key(&restore_id, i as u32), chunk.to_vec())
            .await?;
    }
    let header = StageHeader {
        restore_id,
        chunks,
        nonce: BASE64.encode(nonce_bytes),
    };
    bootstrap_ks
        .insert_raw(
            STAGE_HEADER_KEY,
            serde_json::to_vec(&header)
                .map_err(|e| AppError::Internal(format!("serialize stage header: {e}")))?,
        )
        .await?;
    bootstrap_ks.persist().await
}

/// Read the stage header, if a restore is staged.
pub async fn read_stage_header(
    bootstrap_ks: &KeyspaceHandle,
) -> Result<Option<StageHeader>, AppError> {
    let Some(bytes) = bootstrap_ks.get_raw(STAGE_HEADER_KEY).await? else {
        return Ok(None);
    };
    // A header that does not parse is treated like one that does not open:
    // there is nothing it can safely point at.
    Ok(serde_json::from_slice(&bytes).ok().or_else(|| {
        tracing::warn!("staged-restore header does not parse — ignoring it");
        None
    }))
}

/// Open the staged restore under `seed`.
pub async fn open_stage(
    bootstrap_ks: &KeyspaceHandle,
    seed: &[u8],
) -> Result<StageState, AppError> {
    let Some(header) = read_stage_header(bootstrap_ks).await? else {
        return Ok(StageState::None);
    };
    let uncommitted = || StageState::Uncommitted {
        restore_id: header.restore_id.clone(),
    };

    let mut ciphertext = Vec::new();
    for i in 0..header.chunks {
        match bootstrap_ks
            .get_raw(chunk_key(&header.restore_id, i))
            .await?
        {
            Some(chunk) => ciphertext.extend_from_slice(&chunk),
            None => return Ok(uncommitted()),
        }
    }
    let Ok(nonce_bytes) = BASE64.decode(&header.nonce) else {
        return Ok(uncommitted());
    };
    let Ok(nonce) = Nonce::try_from(nonce_bytes.as_slice()) else {
        return Ok(uncommitted());
    };
    let key = stage_key(seed, &header.restore_id);
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| AppError::Internal(format!("stage key: {e}")))?;
    let Ok(plaintext) = cipher.decrypt(
        &nonce,
        Payload {
            msg: ciphertext.as_slice(),
            aad: &aad(&header.restore_id, header.chunks),
        },
    ) else {
        return Ok(uncommitted());
    };
    let plaintext = Zeroizing::new(plaintext);
    let body: StagedBody = serde_json::from_slice(&plaintext).map_err(|e| {
        // Authenticated but unparseable is not tampering — it is a stage
        // written by a build whose format this one does not read. Refuse
        // loudly rather than discard a committed restore.
        AppError::Internal(format!(
            "staged restore {} opened but does not parse ({e}); it was staged by an \
             incompatible build. Boot the build that staged it to apply it.",
            header.restore_id
        ))
    })?;
    if body.meta.restore_id != header.restore_id {
        return Ok(uncommitted());
    }
    Ok(StageState::Committed(Box::new(OpenedStage {
        meta: body.meta,
        payload: body.payload,
    })))
}

/// Remove the staged restore (header first, so a crash part-way leaves only
/// chunks no header points at — which the next [`clear_stage`] also removes).
pub async fn clear_stage(bootstrap_ks: &KeyspaceHandle) -> Result<(), AppError> {
    bootstrap_ks.remove(STAGE_HEADER_KEY).await?;
    for key in bootstrap_ks.prefix_keys(STAGE_CHUNK_PREFIX).await? {
        bootstrap_ks.remove(key).await?;
    }
    bootstrap_ks.persist().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::protocols::backup_management::types::{BackupConfig, KeyspaceDump};
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    fn store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        (store, dir)
    }

    fn payload(rows: usize) -> BackupPayload {
        BackupPayload {
            active_seed_hex: hex::encode([7u8; 32]),
            active_seed_id: 0,
            seed_records: vec![],
            jwt_signing_key: None,
            key_records: vec![],
            context_records: vec![],
            context_counter: 0,
            path_counters: vec![],
            subcontext_counters: vec![],
            acl_entries: vec![],
            acl_entries_full: vec![],
            seal: None,
            webvh_servers: vec![],
            webvh_dids: vec![],
            webvh_logs: vec![],
            config: BackupConfig {
                vta_did: Some("did:example:vta".into()),
                vta_name: None,
                public_url: None,
                mediator_url: None,
                mediator_did: None,
            },
            audit_logs: vec![],
            imported_secrets: vec![],
            imported_kek_salt: None,
            keyspaces: vec![KeyspaceDump {
                name: "memory".into(),
                rows: (0..rows)
                    .map(|i| (format!("k{i}"), "x".repeat(1000)))
                    .collect(),
            }],
            source_environment: Some(BackupEnvironment::Plain),
            internal_keys_not_carried: vec![],
        }
    }

    fn meta(id: &str) -> StageMeta {
        StageMeta {
            restore_id: id.into(),
            staged_at: Utc::now(),
            staged_by: "did:example:admin".into(),
            target_environment: BackupEnvironment::Tee,
            cross_identity: false,
            tee_secrets_sha256: Some("ab".into()),
            anchor: Some(AnchorBinding {
                did: "did:example:vta".into(),
                version: 7,
            }),
        }
    }

    #[tokio::test]
    async fn a_committed_stage_opens_under_the_restored_seed() {
        let (store, _d) = store();
        let bs = store.keyspace("bootstrap").unwrap();
        // Large enough to span several chunks.
        write_stage(&bs, &[1u8; 32], meta("r1"), payload(3000))
            .await
            .unwrap();
        assert!(bs.prefix_keys(STAGE_CHUNK_PREFIX).await.unwrap().len() > 1);

        match open_stage(&bs, &[1u8; 32]).await.unwrap() {
            StageState::Committed(s) => {
                assert_eq!(s.meta.restore_id, "r1");
                assert_eq!(s.meta.anchor.as_ref().unwrap().version, 7);
                assert_eq!(s.payload.keyspaces[0].rows.len(), 3000);
            }
            _ => panic!("stage must open under the seed it was sealed for"),
        }
    }

    /// The whole crash-consistency argument rests on this: until the restored
    /// seed is committed, the stage cannot be opened.
    #[tokio::test]
    async fn a_stage_does_not_open_under_any_other_seed() {
        let (store, _d) = store();
        let bs = store.keyspace("bootstrap").unwrap();
        write_stage(&bs, &[1u8; 32], meta("r1"), payload(1))
            .await
            .unwrap();
        assert!(matches!(
            open_stage(&bs, &[2u8; 32]).await.unwrap(),
            StageState::Uncommitted { restore_id } if restore_id == "r1"
        ));
    }

    /// A store operator who swaps the header's restore id (to bind the body to
    /// a different stage) or drops a chunk gets an unopenable stage, never a
    /// different one.
    #[tokio::test]
    async fn a_tampered_header_or_missing_chunk_does_not_open() {
        let (store, _d) = store();
        let bs = store.keyspace("bootstrap").unwrap();
        write_stage(&bs, &[1u8; 32], meta("r1"), payload(3000))
            .await
            .unwrap();
        let mut header = read_stage_header(&bs).await.unwrap().unwrap();
        header.chunks -= 1;
        bs.insert_raw(STAGE_HEADER_KEY, serde_json::to_vec(&header).unwrap())
            .await
            .unwrap();
        assert!(matches!(
            open_stage(&bs, &[1u8; 32]).await.unwrap(),
            StageState::Uncommitted { .. }
        ));
    }

    #[tokio::test]
    async fn clearing_removes_header_and_every_chunk() {
        let (store, _d) = store();
        let bs = store.keyspace("bootstrap").unwrap();
        write_stage(&bs, &[1u8; 32], meta("r1"), payload(3000))
            .await
            .unwrap();
        clear_stage(&bs).await.unwrap();
        assert!(matches!(
            open_stage(&bs, &[1u8; 32]).await.unwrap(),
            StageState::None
        ));
        assert!(bs.prefix_keys("restore:").await.unwrap().is_empty());
    }

    #[test]
    fn the_stage_key_depends_on_seed_and_restore_id() {
        assert_ne!(*stage_key(&[1; 32], "a"), *stage_key(&[2; 32], "a"));
        assert_ne!(*stage_key(&[1; 32], "a"), *stage_key(&[1; 32], "b"));
        assert_eq!(*stage_key(&[1; 32], "a"), *stage_key(&[1; 32], "a"));
    }
}
