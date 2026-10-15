use std::path::Path;

use super::super::SeedStore;
use super::*;
use crate::config::{EncryptedFileConfig, KekSource, SecretBackend, SecretsConfig};

fn seed() -> Vec<u8> {
    (0u8..64).collect()
}

fn passphrase_file_store(dir: &Path, passphrase: &[u8]) -> EncryptedFileSeedStore {
    let pass = dir.join("passphrase");
    std::fs::write(&pass, passphrase).unwrap();
    let cfg = EncryptedFileConfig::new(KekSource::Passphrase {
        file: Some(pass),
        credential: None,
    });
    EncryptedFileSeedStore::from_config(&cfg, dir, "seed.enc").unwrap()
}

/// A systemd-creds store reading from an explicit credentials directory, so
/// the test never touches the process-wide `CREDENTIALS_DIRECTORY`.
fn creds_store(dir: &Path, creds: &Path, kek: &[u8]) -> EncryptedFileSeedStore {
    std::fs::create_dir_all(creds).unwrap();
    std::fs::write(creds.join("vta-kek"), kek).unwrap();
    let cfg = EncryptedFileConfig::new(KekSource::SystemdCreds {
        credential: "vta-kek".into(),
    });
    EncryptedFileSeedStore::from_config(&cfg, dir, "seed.enc")
        .unwrap()
        .with_credentials_directory(creds)
}

fn expect_secret_store_err(r: Result<Option<Vec<u8>>, AppError>, needle: &str) {
    match r {
        Err(AppError::SecretStore(m)) => assert!(m.contains(needle), "want {needle:?}: {m}"),
        Err(other) => panic!("want a SecretStore error ({needle}), got {other:?}"),
        Ok(v) => panic!(
            "want an error ({needle}), got Ok({})",
            if v.is_some() { "Some" } else { "None" }
        ),
    }
}

#[tokio::test]
async fn passphrase_file_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let store = passphrase_file_store(dir.path(), b"correct horse battery staple\n");
    assert!(store.get().await.unwrap().is_none(), "no file yet");
    store.set(&seed()).await.unwrap();
    assert_eq!(store.get().await.unwrap().unwrap(), seed());

    // The file holds no plaintext.
    let raw = std::fs::read(store.path()).unwrap();
    assert!(!raw.windows(16).any(|w| w == &seed()[..16]));
    assert_eq!(&raw[..8], b"VTISECF\0");
}

#[tokio::test]
async fn passphrase_credential_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let creds = dir.path().join("creds");
    std::fs::create_dir_all(&creds).unwrap();
    std::fs::write(creds.join("vta-pass"), b"from a systemd credential").unwrap();
    let cfg = EncryptedFileConfig::new(KekSource::Passphrase {
        file: None,
        credential: Some("vta-pass".into()),
    });
    let store = EncryptedFileSeedStore::from_config(&cfg, dir.path(), "seed.enc")
        .unwrap()
        .with_credentials_directory(&creds);
    store.set(&seed()).await.unwrap();
    assert_eq!(store.get().await.unwrap().unwrap(), seed());
}

#[tokio::test]
async fn systemd_creds_round_trip_raw_and_hex() {
    let dir = tempfile::tempdir().unwrap();
    let creds = dir.path().join("creds");
    let raw_kek = [0x5au8; 32];

    let store = creds_store(dir.path(), &creds, &raw_kek);
    store.set(&seed()).await.unwrap();
    assert_eq!(store.get().await.unwrap().unwrap(), seed());

    // The same KEK written as hex (with a newline) opens the same file.
    let hex_kek = format!("{}\n", hex::encode(raw_kek));
    let store = creds_store(dir.path(), &creds, hex_kek.as_bytes());
    assert_eq!(store.get().await.unwrap().unwrap(), seed());

    // A different KEK does not.
    let store = creds_store(dir.path(), &creds, &[0x5bu8; 32]);
    expect_secret_store_err(store.get().await, "cannot decrypt");

    // A credential of the wrong shape is refused before any decryption.
    let store = creds_store(dir.path(), &creds, b"too short");
    expect_secret_store_err(store.get().await, "32-byte key");
}

#[tokio::test]
async fn a_missing_credential_is_an_error_not_no_secret() {
    let dir = tempfile::tempdir().unwrap();
    let creds = dir.path().join("creds");
    let store = creds_store(dir.path(), &creds, &[1u8; 32]);
    store.set(&seed()).await.unwrap();
    std::fs::remove_file(creds.join("vta-kek")).unwrap();
    expect_secret_store_err(store.get().await, "vta-kek");
}

#[tokio::test]
async fn wrong_passphrase_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    passphrase_file_store(dir.path(), b"right")
        .set(&seed())
        .await
        .unwrap();
    let store = passphrase_file_store(dir.path(), b"wrong");
    expect_secret_store_err(store.get().await, "cannot decrypt");
}

#[tokio::test]
async fn an_empty_passphrase_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let store = passphrase_file_store(dir.path(), b"\n");
    match store.set(&seed()).await {
        Err(AppError::SecretStore(m)) => assert!(m.contains("empty"), "{m}"),
        other => panic!("want an empty-passphrase error, got {other:?}"),
    }
}

#[tokio::test]
async fn tampering_with_ciphertext_or_header_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let creds = dir.path().join("creds");
    let store = creds_store(dir.path(), &creds, &[9u8; 32]);
    store.set(&seed()).await.unwrap();
    let good = std::fs::read(store.path()).unwrap();

    // Last ciphertext byte (inside the tag), a middle ciphertext byte, a
    // salt byte and a nonce byte: each parses, none decrypts.
    for i in [good.len() - 1, good.len() - 20, 12, 44] {
        let mut bad = good.clone();
        bad[i] ^= 0x01;
        std::fs::write(store.path(), &bad).unwrap();
        expect_secret_store_err(store.get().await, "cannot decrypt");
    }

    // Header fields that fail to parse are errors too, never "no secret".
    for (i, needle) in [(0, "magic"), (9, "AEAD"), (11, "reserved")] {
        let mut bad = good.clone();
        bad[i] ^= 0x01;
        std::fs::write(store.path(), &bad).unwrap();
        expect_secret_store_err(store.get().await, needle);
    }

    // Truncated and empty files.
    std::fs::write(store.path(), &good[..40]).unwrap();
    expect_secret_store_err(store.get().await, "malformed");
    std::fs::write(store.path(), b"").unwrap();
    expect_secret_store_err(store.get().await, "malformed");
}

#[tokio::test]
async fn tampering_with_the_kdf_parameters_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let store = passphrase_file_store(dir.path(), b"pass");
    store.set(&seed()).await.unwrap();
    let good = std::fs::read(store.path()).unwrap();

    // t_cost 3 -> 4: within range, so it parses, but the header is the AAD.
    let mut bad = good.clone();
    assert_eq!(&bad[62..66], &3u32.to_be_bytes());
    bad[65] = 4;
    std::fs::write(store.path(), &bad).unwrap();
    expect_secret_store_err(store.get().await, "cannot decrypt");

    // t_cost 3 -> 2: below the floor, refused before any derivation.
    let mut weak = good;
    weak[65] = 2;
    std::fs::write(store.path(), &weak).unwrap();
    expect_secret_store_err(store.get().await, "outside the accepted range");
}

#[tokio::test]
async fn an_unknown_version_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let creds = dir.path().join("creds");
    let store = creds_store(dir.path(), &creds, &[2u8; 32]);
    store.set(&seed()).await.unwrap();
    let mut bytes = std::fs::read(store.path()).unwrap();
    bytes[8] = 2;
    std::fs::write(store.path(), &bytes).unwrap();
    expect_secret_store_err(store.get().await, "unsupported format version 2");
}

#[tokio::test]
async fn a_file_from_another_kek_source_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let creds = dir.path().join("creds");
    creds_store(dir.path(), &creds, &[2u8; 32])
        .set(&seed())
        .await
        .unwrap();
    let store = passphrase_file_store(dir.path(), b"pass");
    expect_secret_store_err(store.get().await, "'systemd_creds'");
}

#[cfg(unix)]
#[tokio::test]
async fn the_file_is_owner_only_and_written_atomically() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let creds = dir.path().join("creds");
    let store = creds_store(dir.path(), &creds, &[4u8; 32]);
    store.set(&seed()).await.unwrap();
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(store.path()), 0o600);

    // Overwriting a loosened file replaces it with a new 0600 one.
    std::fs::set_permissions(store.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
    store.set(&[1, 2, 3]).await.unwrap();
    assert_eq!(mode(store.path()), 0o600);
    assert_eq!(store.get().await.unwrap().unwrap(), vec![1, 2, 3]);

    // No temporary file is left behind.
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn a_missing_parent_directory_is_created_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let creds = dir.path().join("creds");
    std::fs::create_dir_all(&creds).unwrap();
    std::fs::write(creds.join("k"), [6u8; 32]).unwrap();
    let mut cfg = EncryptedFileConfig::new(KekSource::SystemdCreds {
        credential: "k".into(),
    });
    let nested = dir.path().join("state/sub");
    cfg.path = Some(nested.join("seed.enc"));
    let store = EncryptedFileSeedStore::from_config(&cfg, dir.path(), "unused")
        .unwrap()
        .with_credentials_directory(&creds);
    store.set(&seed()).await.unwrap();
    let mode = std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    assert_eq!(store.get().await.unwrap().unwrap(), seed());
}

#[tokio::test]
async fn delete_removes_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let creds = dir.path().join("creds");
    let store = creds_store(dir.path(), &creds, &[4u8; 32]);
    store.set(&seed()).await.unwrap();
    store.delete().await.unwrap();
    assert!(store.get().await.unwrap().is_none());
    store.delete().await.unwrap();
}

fn config_err(cfg: &EncryptedFileConfig) -> String {
    match EncryptedFileSeedStore::from_config(cfg, Path::new("/tmp"), "seed.enc") {
        Err(AppError::Config(m)) => m,
        Err(other) => panic!("want a Config error, got {other:?}"),
        Ok(_) => panic!("want a Config error, got a store"),
    }
}

#[test]
fn config_validation() {
    let both = EncryptedFileConfig::new(KekSource::Passphrase {
        file: Some("/p".into()),
        credential: Some("c".into()),
    });
    assert!(config_err(&both).contains("exactly one"));
    let neither = EncryptedFileConfig::new(KekSource::Passphrase {
        file: None,
        credential: None,
    });
    assert!(config_err(&neither).contains("exactly one"));
    for bad in ["", ".", "..", "a/b"] {
        let cfg = EncryptedFileConfig::new(KekSource::SystemdCreds {
            credential: bad.into(),
        });
        assert!(config_err(&cfg).contains("credential name"), "{bad:?}");
    }
    let tpm = EncryptedFileConfig::new(KekSource::Tpm {
        pcrs: vec![7, 24],
        tcti: None,
    });
    let msg = config_err(&tpm);
    if cfg!(all(feature = "tpm", target_os = "linux")) {
        assert!(msg.contains("out of range"), "{msg}");
    } else {
        assert!(msg.contains("`tpm` feature"), "{msg}");
    }
}

#[test]
fn the_default_path_is_under_the_data_dir() {
    let cfg = EncryptedFileConfig::new(KekSource::SystemdCreds {
        credential: "k".into(),
    });
    let store = EncryptedFileSeedStore::from_config(&cfg, Path::new("/data"), "seed.enc").unwrap();
    assert_eq!(store.path(), Path::new("/data/seed.enc"));
}

#[test]
fn debug_names_the_source_only() {
    let dir = tempfile::tempdir().unwrap();
    let store = passphrase_file_store(dir.path(), b"hunter2");
    let dbg = format!("{store:?}");
    assert!(
        dbg.contains("passphrase") && !dbg.contains("hunter2"),
        "{dbg}"
    );
}

#[test]
fn toml_forms_parse_and_unknown_fields_are_refused() {
    let parse = |s: &str| toml::from_str::<SecretsConfig>(s);
    let c = parse(
        r#"
backend = "encrypted_file"
[encrypted_file]
path = "/var/lib/vta/seed.enc"
kek = { source = "passphrase", file = "/etc/vta/pass" }
"#,
    )
    .unwrap();
    assert_eq!(c.backend, Some(SecretBackend::EncryptedFile));
    let ef = c.encrypted_file.unwrap();
    assert_eq!(ef.path.as_deref(), Some(Path::new("/var/lib/vta/seed.enc")));
    assert_eq!(
        ef.kek,
        KekSource::Passphrase {
            file: Some("/etc/vta/pass".into()),
            credential: None
        }
    );

    let c = parse(
        "backend = \"encrypted_file\"\n[encrypted_file.kek]\nsource = \"systemd_creds\"\ncredential = \"vta-kek\"\n",
    )
    .unwrap();
    assert_eq!(
        c.encrypted_file.unwrap().kek,
        KekSource::SystemdCreds {
            credential: "vta-kek".into()
        }
    );

    let c = parse("[encrypted_file]\nkek = { source = \"tpm\", pcrs = [0, 7] }\n").unwrap();
    assert_eq!(
        c.encrypted_file.unwrap().kek,
        KekSource::Tpm {
            pcrs: vec![0, 7],
            tcti: None
        }
    );

    // A passphrase is never accepted inline, and typos are loud.
    assert!(
        parse("[encrypted_file]\nkek = { source = \"passphrase\", passphrase = \"x\" }\n").is_err()
    );
    assert!(
        parse("[encrypted_file]\nkek = { source = \"systemd_creds\", credentail = \"x\" }\n")
            .is_err()
    );
    assert!(parse("[encrypted_file]\npaht = \"/x\"\nkek = { source = \"tpm\" }\n").is_err());
    assert!(parse("[encrypted_file]\nkek = { source = \"kms\" }\n").is_err());

    // Round trip: what serializes, parses back to the same thing.
    let c = secrets_with(
        Some(SecretBackend::EncryptedFile),
        Some(EncryptedFileConfig::new(KekSource::SystemdCreds {
            credential: "vta-kek".into(),
        })),
    );
    let text = toml::to_string(&c).unwrap();
    assert!(text.contains("encrypted_file"), "{text}");
    let back = parse(&text).unwrap();
    assert_eq!(back.encrypted_file, c.encrypted_file);
}

// ── factory selection ──────────────────────────────────────────────────

fn secrets_with(
    backend: Option<SecretBackend>,
    encrypted_file: Option<EncryptedFileConfig>,
) -> SecretsConfig {
    SecretsConfig {
        backend,
        encrypted_file,
        ..Default::default()
    }
}

fn factory_config_err(secrets: &SecretsConfig) -> String {
    match crate::create_seed_store(secrets, Path::new("/tmp")) {
        Err(AppError::Config(m)) => m,
        Err(other) => panic!("want a Config error, got {other:?}"),
        Ok(_) => panic!("want a Config error, got a store"),
    }
}

#[test]
fn the_factory_needs_the_table_for_an_explicit_selection() {
    let secrets = secrets_with(Some(SecretBackend::EncryptedFile), None);
    assert!(factory_config_err(&secrets).contains("[secrets.encrypted_file]"));
}

#[test]
fn implicit_resolution_never_picks_encrypted_file() {
    let mut secrets = secrets_with(
        None,
        Some(EncryptedFileConfig::new(KekSource::SystemdCreds {
            credential: "k".into(),
        })),
    );
    assert!(factory_config_err(&secrets).contains("only ever selected explicitly"));

    // With another backend named, the table is just unused.
    secrets.backend = Some(SecretBackend::Plaintext);
    secrets.allow_plaintext = true;
    assert!(crate::create_seed_store(&secrets, Path::new("/tmp")).is_ok());
}

#[tokio::test]
async fn the_factory_builds_a_working_store() {
    let dir = tempfile::tempdir().unwrap();
    let pass = dir.path().join("pass");
    std::fs::write(&pass, b"factory pass").unwrap();
    let secrets = secrets_with(
        Some(SecretBackend::EncryptedFile),
        Some(EncryptedFileConfig::new(KekSource::Passphrase {
            file: Some(pass),
            credential: None,
        })),
    );
    let store = crate::create_seed_store(&secrets, dir.path()).unwrap();
    store.set(&seed()).await.unwrap();
    assert_eq!(store.get().await.unwrap().unwrap(), seed());
    assert!(
        dir.path()
            .join(crate::seed_store::VTA_ENCRYPTED_FILENAME)
            .is_file()
    );
}
