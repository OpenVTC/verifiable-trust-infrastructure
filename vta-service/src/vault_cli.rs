//! Offline `vta vault …` subcommands — direct fjall access for the
//! `vault:` keyspace. Daemon must be stopped (fjall exclusive lock); not
//! available in TEE deployments (the enclave's vsock-store is the only
//! reader/writer there). Same constraints as `vta acl`, `vta did-mgmt`, etc.
//!
//! Two subcommands today:
//! - `seed` — populate from a JSON file or a built-in demo set.
//! - `wipe` — drop every row (or every row in a single context). Useful
//!   for clearing stale-format rows after a schema migration (e.g. the
//!   M1→M2A `VaultEntry` → `StoredVaultEntry { entry, secret }` wrap
//!   broke deserialisation of pre-M2A seed entries; a wipe is faster
//!   than writing a one-shot re-wrapper).

use std::fs;
use std::path::{Path, PathBuf};

use vti_common::vault::{
    SecretKind, SiteTarget, StoredVaultEntry, VaultEntry, VaultSecret, VaultStatus,
    get_vault_entry, put_stored_vault_entry,
};

use crate::config::AppConfig;
use crate::store::Store;

pub struct VaultSeedArgs {
    /// Optional path to config.toml — falls back to the default search path
    /// AppConfig::load uses.
    pub config_path: Option<PathBuf>,
    /// Path to a JSON file containing an array of VaultEntry objects.
    /// When omitted, three demo entries are seeded under `context`.
    pub entries_file: Option<PathBuf>,
    /// Trust context id the demo entries land under. Required when
    /// `entries_file` is omitted; ignored when entries supply their own
    /// `contextId`.
    pub context: Option<String>,
    /// Print the entries that would be seeded without writing.
    pub dry_run: bool,
    /// Overwrite an existing entry with the same id (otherwise the seeder
    /// fails fast — vault entries with stable ids generally shouldn't be
    /// silently rewritten).
    pub force: bool,
}

pub async fn run_vault_seed(args: VaultSeedArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(args.config_path)?;
    let store = Store::open(&config.store)?;
    let vault_ks = store.keyspace(crate::keyspaces::VAULT)?;

    let records: Vec<StoredVaultEntry> = match (&args.entries_file, &args.context) {
        (Some(path), _) => load_records_from_file(path)?,
        (None, Some(ctx)) => demo_records(ctx),
        (None, None) => {
            return Err("either --entries-file <path> or --context <id> is required".into());
        }
    };

    if records.is_empty() {
        eprintln!("No entries to seed.");
        return Ok(());
    }

    // Validate every record up front — bulk operations with partial failure
    // are confusing. Cheap structural checks + the SecretKind ↔ secret.kind()
    // invariant (entries-from-JSON could violate this; demo entries can't).
    for (i, r) in records.iter().enumerate() {
        let e = &r.entry;
        if e.id.is_empty() {
            return Err(format!("entry {i}: id is empty").into());
        }
        if e.context_id.is_empty() {
            return Err(format!("entry {i} ({}): contextId is empty", e.id).into());
        }
        if e.targets.is_empty() {
            return Err(format!("entry {i} ({}): targets is empty", e.id).into());
        }
        if e.label.is_empty() {
            return Err(format!("entry {i} ({}): label is empty", e.id).into());
        }
        if !r.secret.matches_kind(e.secret_kind) {
            return Err(format!(
                "entry {i} ({}): secretKind {:?} does not match secret variant {:?}",
                e.id,
                e.secret_kind,
                r.secret.kind()
            )
            .into());
        }
        if !args.force
            && let Some(existing) = get_vault_entry(&vault_ks, &e.id).await?
        {
            return Err(format!(
                "entry {} already exists (label={}, version={}); pass --force to overwrite",
                e.id, existing.label, existing.version
            )
            .into());
        }
    }

    if args.dry_run {
        eprintln!("[dry-run] would seed {} entries:", records.len());
        for r in &records {
            eprintln!(
                "  {} — {} ({})",
                r.entry.id,
                r.entry.label,
                secret_kind_label(r.entry.secret_kind)
            );
        }
        return Ok(());
    }

    for r in &records {
        put_stored_vault_entry(&vault_ks, r).await?;
        eprintln!("seeded: {} ({})", r.entry.label, r.entry.id);
    }
    store.persist().await?;

    eprintln!();
    eprintln!("Seeded {} vault entries.", records.len());
    eprintln!("Restart the VTA daemon, then click \"Load entries\" in the wallet popup.");
    Ok(())
}

fn load_records_from_file(
    path: &Path,
) -> Result<Vec<StoredVaultEntry>, Box<dyn std::error::Error>> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let records: Vec<StoredVaultEntry> = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse {} as StoredVaultEntry[]: {e}", path.display()))?;
    Ok(records)
}

/// Built-in demo set — three entries that exercise every visible-in-UI
/// field of the metadata view (multiple targets including iOS, breach flag,
/// never-used entry, custom selectors, tags). Each carries a placeholder
/// secret so the StoredVaultEntry shape is well-formed; real credentials
/// arrive via vault/upsert/0.1 from the wallet.
fn demo_records(context_id: &str) -> Vec<StoredVaultEntry> {
    let now = chrono::Utc::now().to_rfc3339();
    let stamp = stamp_suffix();
    let placeholder_password = || VaultSecret::Password {
        username: Some("demo".into()),
        password: "PLACEHOLDER-replace-via-vault/upsert/0.1".into(),
        totp: None,
        login_config: None,
        secure_notes: None,
        custom_fields: Vec::new(),
    };
    let placeholder_passkey = || VaultSecret::Passkey {
        credential_id: "DEMO-credential-id".into(),
        private_key: "DEMO-private-key".into(),
        algorithm: Some("EdDSA".into()),
        rp_id: "github.com".into(),
        user_handle: Some("DEMO-user-handle".into()),
        secure_notes: None,
    };
    vec![
        StoredVaultEntry {
            entry: VaultEntry {
                id: format!("vault_demo_github_{stamp}"),
                context_id: context_id.into(),
                targets: vec![
                    SiteTarget::WebOrigin {
                        origin: "https://github.com".into(),
                    },
                    SiteTarget::IosApp {
                        bundle_id: "com.github.stwalkerster.codehub".into(),
                        team_id: Some("VEKTX9H2N7".into()),
                    },
                ],
                label: "Work GitHub".into(),
                secret_kind: SecretKind::Passkey,
                tags: vec!["work".into(), "engineering".into()],
                notes: None,
                favicon: None,
                selectors: vec!["recent_uv_required".into()],
                custom_field_names: vec![],
                attachments: vec![],
                expires_at: None,
                breached_at: None,
                password_changed_at: None,
                created_at: now.clone(),
                created_by: Some("cli:vault-seed".into()),
                updated_at: now.clone(),
                updated_by: None,
                last_used_at: Some("2026-05-25T22:11:00Z".into()),
                version: 1,
                // Maintainer-derived; passkey has no principal DID concept.
                principal_did: None,
                status: VaultStatus::Active,
                archived_at: None,
                deleted_at: None,
                grace_until: None,
            },
            secret: placeholder_passkey(),
        },
        StoredVaultEntry {
            entry: VaultEntry {
                id: format!("vault_demo_aws_{stamp}"),
                context_id: context_id.into(),
                targets: vec![SiteTarget::WebOrigin {
                    origin: "https://aws.amazon.com".into(),
                }],
                label: "Work AWS — root".into(),
                secret_kind: SecretKind::Password,
                tags: vec!["work".into(), "high-value".into()],
                notes: Some("Recovery email: ops@example.com".into()),
                favicon: None,
                selectors: vec!["step_up_push".into()],
                custom_field_names: vec![],
                attachments: vec![],
                expires_at: None,
                breached_at: Some("2026-04-22T00:00:00Z".into()),
                password_changed_at: Some("2026-05-01T08:00:00Z".into()),
                created_at: now.clone(),
                created_by: Some("cli:vault-seed".into()),
                updated_at: now.clone(),
                updated_by: None,
                last_used_at: Some(now.clone()),
                version: 1,
                principal_did: None,
                status: VaultStatus::Active,
                archived_at: None,
                deleted_at: None,
                grace_until: None,
            },
            secret: placeholder_password(),
        },
        StoredVaultEntry {
            entry: VaultEntry {
                id: format!("vault_demo_hn_{stamp}"),
                context_id: context_id.into(),
                targets: vec![SiteTarget::WebOrigin {
                    origin: "https://news.ycombinator.com".into(),
                }],
                label: "Hacker News".into(),
                secret_kind: SecretKind::Password,
                tags: vec!["personal".into()],
                notes: None,
                favicon: None,
                selectors: vec![],
                custom_field_names: vec![],
                attachments: vec![],
                expires_at: None,
                breached_at: None,
                password_changed_at: None,
                created_at: now.clone(),
                created_by: Some("cli:vault-seed".into()),
                updated_at: now,
                updated_by: None,
                last_used_at: None,
                version: 1,
                principal_did: None,
                status: VaultStatus::Active,
                archived_at: None,
                deleted_at: None,
                grace_until: None,
            },
            secret: placeholder_password(),
        },
    ]
}

fn secret_kind_label(k: SecretKind) -> &'static str {
    match k {
        SecretKind::Password => "password",
        SecretKind::Passkey => "passkey",
        SecretKind::OauthTokens => "oauth-tokens",
        SecretKind::DidSelfIssued => "did-self-issued",
        SecretKind::DidcommPeer => "didcomm-peer",
        SecretKind::BearerToken => "bearer-token",
        SecretKind::SshKey => "ssh-key",
        SecretKind::Custom => "custom",
    }
}

fn stamp_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{t:x}")
}

// ─── wipe ─────────────────────────────────────────────────────────

pub struct VaultWipeArgs {
    pub config_path: Option<PathBuf>,
    /// Without this, the command reports the row count and exits
    /// without writing. Irreversible against the local store; demand
    /// explicit confirmation rather than silently mutating fjall.
    pub force: bool,
    /// Optional context filter — wipe only rows whose `entry.context_id`
    /// matches. `None` wipes every row in the keyspace.
    ///
    /// Implementation: we walk `vault:` prefix and deserialise each
    /// row. Rows that fail to deserialise (e.g. pre-M2A
    /// bare-VaultEntry format) are unconditionally dropped — the
    /// whole reason this command exists is to clear data that
    /// already can't be read by vault/list/0.1.
    pub context: Option<String>,
}

pub async fn run_vault_wipe(args: VaultWipeArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(args.config_path)?;
    let store = Store::open(&config.store)?;
    let vault_ks = store.keyspace(crate::keyspaces::VAULT)?;

    // Enumerate every key under the `vault:` prefix. We use the raw
    // iterator so a deserialise failure on a single row doesn't abort
    // the count — rows that vault/list/0.1 already can't read are
    // candidates for the wipe by definition.
    let raw_rows = vault_ks.prefix_iter_raw("vault:").await?;
    let total = raw_rows.len();
    if total == 0 {
        eprintln!("Vault keyspace is empty; nothing to wipe.");
        return Ok(());
    }

    // When a context filter is set, partition into "matches" (will be
    // deleted) and "skipped" (unreadable rows + rows in other
    // contexts). Unreadable rows are NOT deleted under a context
    // filter — we can't tell which context they belong to. Tell the
    // user so they can re-run without `--context` to clear them.
    let mut to_delete: Vec<Vec<u8>> = Vec::new();
    let mut unreadable_under_filter: u64 = 0;
    let mut skipped_other_context: u64 = 0;
    if let Some(ctx) = args.context.as_deref() {
        for (key, bytes) in raw_rows {
            match serde_json::from_slice::<StoredVaultEntry>(&bytes) {
                Ok(stored) => {
                    if stored.entry.context_id == ctx {
                        to_delete.push(key);
                    } else {
                        skipped_other_context += 1;
                    }
                }
                Err(_) => {
                    unreadable_under_filter += 1;
                }
            }
        }
    } else {
        // No filter — every row is fair game, including unreadable
        // ones. (That's the whole point of the wipe.)
        to_delete = raw_rows.into_iter().map(|(k, _)| k).collect();
    }

    if to_delete.is_empty() {
        if let Some(ctx) = args.context.as_deref() {
            eprintln!(
                "No rows in context '{ctx}'. {skipped_other_context} row(s) in other contexts, {unreadable_under_filter} unreadable row(s) preserved."
            );
        } else {
            eprintln!("Vault keyspace is empty; nothing to wipe.");
        }
        return Ok(());
    }

    if !args.force {
        eprintln!(
            "Would delete {} vault row(s){}.",
            to_delete.len(),
            args.context
                .as_deref()
                .map(|c| format!(" in context '{c}'"))
                .unwrap_or_default()
        );
        if args.context.is_some() && unreadable_under_filter > 0 {
            eprintln!(
                "  + {unreadable_under_filter} unreadable row(s) would be preserved (re-run without --context to clear them)."
            );
        }
        if args.context.is_some() && skipped_other_context > 0 {
            eprintln!("  + {skipped_other_context} row(s) in other contexts would be preserved.");
        }
        eprintln!("Pass --force to apply.");
        return Ok(());
    }

    let target = to_delete.len();
    for key in to_delete {
        vault_ks.remove(key).await?;
    }
    store.persist().await?;

    eprintln!(
        "Wiped {} vault row(s){}.",
        target,
        args.context
            .as_deref()
            .map(|c| format!(" in context '{c}'"))
            .unwrap_or_default()
    );
    if args.context.is_some() && unreadable_under_filter > 0 {
        eprintln!(
            "Preserved {unreadable_under_filter} unreadable row(s); re-run without --context to clear them."
        );
    }
    eprintln!(
        "Restart the VTA daemon to make the empty (or trimmed) keyspace visible via vault/list/0.1."
    );
    Ok(())
}
