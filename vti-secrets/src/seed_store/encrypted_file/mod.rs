//! Encrypted-at-rest file backend (`backend = "encrypted_file"`, #1820).
//!
//! The secret is kept in one file under AES-256-GCM, keyed from a
//! key-encryption key (KEK) the operator chose explicitly:
//!
//! | `kek.source`    | file key                                   | unattended boot |
//! |-----------------|--------------------------------------------|-----------------|
//! | `passphrase`    | Argon2id(passphrase, salt), m=64 MiB, t=3  | if the passphrase file / credential is |
//! | `systemd_creds` | HKDF-SHA256(KEK from `$CREDENTIALS_DIRECTORY`) | yes (systemd unseals) |
//! | `tpm`           | HKDF-SHA256(KEK unsealed by the TPM 2.0)   | yes             |
//!
//! The envelope format is in [`envelope`]. Every write draws a fresh salt and
//! nonce, so each write has its own file key; with the TPM source each write
//! also seals a fresh random KEK.
//!
//! # Threat model
//!
//! Protects the secret in a copy of the file taken away from the running host
//! — a stolen disk or disk image, a backup, a snapshot, a misdirected `rsync` —
//! provided the KEK did not travel with it (a passphrase file on the same disk
//! does; a systemd credential sealed to the TPM, or a TPM-sealed KEK, does not).
//!
//! Does **not** protect against root, or the service user, on the running
//! host: whoever can read the passphrase file or credential, use the TPM as
//! this host, or read the process's memory can decrypt it. It is a local
//! at-rest control, not an isolation boundary — use a remote backend or a TEE
//! for that.
//!
//! # Failure semantics
//!
//! Fails closed. A missing file is "no secret yet" (`Ok(None)`), as for every
//! other backend; anything else — an unreadable KEK, a wrong passphrase, a bad
//! tag, an unknown version, a malformed header, a header written by a
//! different KEK source than the one configured — is an error.

mod envelope;
#[cfg(all(feature = "tpm", target_os = "linux"))]
mod tpm;

use std::fs::File;
use std::future::Future;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use zeroize::Zeroizing;

use vti_common::error::AppError;

use crate::config::{EncryptedFileConfig, KekSource};
use envelope::{Argon2Params, Header, KekKind, NONCE_LEN, SALT_LEN, TpmDescriptor};

/// The default TCTI for the TPM source: the kernel's resource manager.
const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";
/// Upper bound on a passphrase or credential file; nothing legitimate is close.
const MAX_INPUT_LEN: u64 = 64 * 1024;

/// Encrypted-at-rest file seed store. See the [module docs](self).
#[derive(Clone)]
pub struct EncryptedFileSeedStore {
    path: PathBuf,
    kek: Kek,
    /// Overrides `$CREDENTIALS_DIRECTORY` (tests, non-systemd supervisors).
    credentials_dir: Option<PathBuf>,
}

/// The resolved KEK source. Holds locations only, never key material.
#[derive(Clone)]
enum Kek {
    PassphraseFile(PathBuf),
    PassphraseCredential(String),
    SystemdCreds(String),
    #[cfg_attr(not(all(feature = "tpm", target_os = "linux")), allow(dead_code))]
    Tpm(TpmSettings),
}

#[derive(Clone)]
#[cfg_attr(not(all(feature = "tpm", target_os = "linux")), allow(dead_code))]
pub(crate) struct TpmSettings {
    pub(crate) pcrs: Vec<u8>,
    pub(crate) tcti: String,
}

impl Kek {
    fn kind(&self) -> KekKind {
        match self {
            Self::PassphraseFile(_) | Self::PassphraseCredential(_) => KekKind::Passphrase,
            Self::SystemdCreds(_) => KekKind::SystemdCreds,
            Self::Tpm(_) => KekKind::Tpm,
        }
    }
}

impl std::fmt::Debug for EncryptedFileSeedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedFileSeedStore")
            .field("path", &self.path)
            .field("kek", &self.kek.kind().label())
            .finish()
    }
}

impl EncryptedFileSeedStore {
    /// Build from `[secrets.encrypted_file]`. The file is
    /// `config.path`, or `<data_dir>/<default_filename>` when unset.
    ///
    /// Validates the configuration only; the KEK is not read until the first
    /// [`get`](vti_common::seed_store::SeedStore::get) or `set`, so it is held
    /// in memory only while it is being used.
    pub fn from_config(
        config: &EncryptedFileConfig,
        data_dir: &Path,
        default_filename: &str,
    ) -> Result<Self, AppError> {
        let kek = match &config.kek {
            KekSource::Passphrase { file, credential } => match (file, credential) {
                (Some(path), None) => Kek::PassphraseFile(path.clone()),
                (None, Some(name)) => {
                    validate_credential_name(name)?;
                    Kek::PassphraseCredential(name.clone())
                }
                _ => {
                    return Err(AppError::Config(
                        "secrets.encrypted_file.kek (source = \"passphrase\") needs exactly one \
                         of `file` (a path to a file holding the passphrase) or `credential` (a \
                         systemd credential name). A passphrase is never taken from the config \
                         or an environment variable."
                            .into(),
                    ));
                }
            },
            KekSource::SystemdCreds { credential } => {
                validate_credential_name(credential)?;
                Kek::SystemdCreds(credential.clone())
            }
            KekSource::Tpm { pcrs, tcti } => {
                if !cfg!(all(feature = "tpm", target_os = "linux")) {
                    return Err(AppError::Config(
                        "secrets.encrypted_file.kek source \"tpm\" needs a Linux build with the \
                         vti-secrets `tpm` feature; this binary has no TPM support. Use \
                         source = \"systemd_creds\" (systemd can seal the credential to the TPM) \
                         or \"passphrase\"."
                            .into(),
                    ));
                }
                let mut pcrs = pcrs.clone();
                if let Some(bad) = pcrs.iter().find(|p| **p > envelope::MAX_PCR) {
                    return Err(AppError::Config(format!(
                        "secrets.encrypted_file.kek.pcrs: PCR {bad} is out of range (0-23)"
                    )));
                }
                pcrs.sort_unstable();
                pcrs.dedup();
                Kek::Tpm(TpmSettings {
                    pcrs,
                    tcti: tcti.clone().unwrap_or_else(|| DEFAULT_TCTI.to_string()),
                })
            }
        };
        let path = config
            .path
            .clone()
            .unwrap_or_else(|| data_dir.join(default_filename));
        Ok(Self {
            path,
            kek,
            credentials_dir: None,
        })
    }

    /// Read systemd credentials from `dir` instead of `$CREDENTIALS_DIRECTORY`.
    /// For tests, and for supervisors other than systemd that deliver
    /// credentials the same way.
    pub fn with_credentials_directory(mut self, dir: impl Into<PathBuf>) -> Self {
        self.credentials_dir = Some(dir.into());
        self
    }

    /// The envelope's location.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn credential_path(&self, name: &str) -> Result<PathBuf, AppError> {
        let dir = match &self.credentials_dir {
            Some(d) => d.clone(),
            None => std::env::var_os("CREDENTIALS_DIRECTORY")
                .map(PathBuf::from)
                .ok_or_else(|| {
                    AppError::SecretStore(format!(
                        "systemd credential '{name}' is configured but CREDENTIALS_DIRECTORY is \
                         not set: run the service under systemd with LoadCredential= or \
                         LoadCredentialEncrypted= naming '{name}'"
                    ))
                })?,
        };
        Ok(dir.join(name))
    }

    fn read_passphrase(&self) -> Result<Zeroizing<Vec<u8>>, AppError> {
        let path = match &self.kek {
            Kek::PassphraseFile(p) => p.clone(),
            Kek::PassphraseCredential(name) => self.credential_path(name)?,
            Kek::SystemdCreds(_) | Kek::Tpm(_) => {
                return Err(AppError::SecretStore(
                    "internal: passphrase requested for a non-passphrase KEK source".into(),
                ));
            }
        };
        let mut raw = read_secret_input(&path, "passphrase")?;
        strip_one_newline(&mut raw);
        if raw.is_empty() {
            return Err(AppError::SecretStore(format!(
                "the passphrase in {} is empty",
                path.display()
            )));
        }
        Ok(raw)
    }

    fn read_credential_kek(&self, name: &str) -> Result<Zeroizing<[u8; 32]>, AppError> {
        let path = self.credential_path(name)?;
        let mut raw = read_secret_input(&path, "systemd credential")?;
        decode_kek(&mut raw).ok_or_else(|| {
            AppError::SecretStore(format!(
                "systemd credential '{name}' must hold a 32-byte key: 32 raw bytes or 64 hex \
                 characters (e.g. `openssl rand 32 | systemd-creds encrypt --name={name} - …`)"
            ))
        })
    }

    /// The file key for `header`, deriving or unsealing the KEK as configured.
    fn file_key(&self, header: &Header) -> Result<Zeroizing<[u8; 32]>, AppError> {
        match &self.kek {
            Kek::PassphraseFile(_) | Kek::PassphraseCredential(_) => {
                let params = Argon2Params::decode(&header.descriptor)?;
                let passphrase = self.read_passphrase()?;
                params.derive(&passphrase, &header.salt)
            }
            Kek::SystemdCreds(name) => {
                if !header.descriptor.is_empty() {
                    return Err(AppError::SecretStore(
                        "encrypted secret file is malformed: unexpected systemd-creds descriptor"
                            .into(),
                    ));
                }
                let kek = self.read_credential_kek(name)?;
                envelope::derive_from_kek(&kek, &header.salt, KekKind::SystemdCreds)
            }
            Kek::Tpm(settings) => {
                let descriptor = TpmDescriptor::decode(&header.descriptor)?;
                let kek = unseal_tpm(settings, &descriptor)?;
                envelope::derive_from_kek(&kek, &header.salt, KekKind::Tpm)
            }
        }
    }

    fn get_blocking(&self) -> Result<Option<Vec<u8>>, AppError> {
        let file = match read_envelope(&self.path)? {
            Some(f) => f,
            None => return Ok(None),
        };
        let (header, header_len) = Header::parse(&file)?;
        let configured = self.kek.kind();
        if header.kek != configured {
            return Err(AppError::SecretStore(format!(
                "{} was written with the '{}' key-encryption key source, but the config says \
                 '{}'; refusing to guess",
                self.path.display(),
                header.kek.label(),
                configured.label()
            )));
        }
        let key = self.file_key(&header)?;
        envelope::open(&file, &header, header_len, &key).map(Some)
    }

    fn set_blocking(&self, secret: &[u8]) -> Result<(), AppError> {
        let mut salt = [0u8; SALT_LEN];
        rand::fill(&mut salt);
        let mut nonce = [0u8; NONCE_LEN];
        rand::fill(&mut nonce);

        let (descriptor, key) = match &self.kek {
            Kek::PassphraseFile(_) | Kek::PassphraseCredential(_) => {
                let params = Argon2Params::WRITE;
                let passphrase = self.read_passphrase()?;
                (params.encode(), params.derive(&passphrase, &salt)?)
            }
            Kek::SystemdCreds(name) => {
                let kek = self.read_credential_kek(name)?;
                (
                    Vec::new(),
                    envelope::derive_from_kek(&kek, &salt, KekKind::SystemdCreds)?,
                )
            }
            Kek::Tpm(settings) => {
                // A fresh KEK per write: the old sealed object is simply
                // replaced along with the file.
                let mut kek = Zeroizing::new([0u8; 32]);
                rand::fill(kek.as_mut());
                let descriptor = seal_tpm(settings, &kek)?;
                (
                    descriptor.encode()?,
                    envelope::derive_from_kek(&kek, &salt, KekKind::Tpm)?,
                )
            }
        };
        let header = Header {
            kek: self.kek.kind(),
            salt,
            nonce,
            descriptor,
        };
        let file = envelope::seal(&header, &key, secret)?;
        write_atomic(&self.path, &file)
            .map_err(|e| AppError::SecretStore(format!("writing {}: {e}", self.path.display())))
    }
}

impl super::SeedStore for EncryptedFileSeedStore {
    fn get(&self) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, AppError>> + Send + '_>> {
        let this = self.clone();
        Box::pin(async move {
            // Argon2id at 64 MiB and TPM round-trips are slow, blocking work.
            tokio::task::spawn_blocking(move || this.get_blocking())
                .await
                .map_err(|e| AppError::SecretStore(format!("encrypted_file read task: {e}")))?
        })
    }

    fn set(
        &self,
        secret: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let this = self.clone();
        let secret = Zeroizing::new(secret.to_vec());
        Box::pin(async move {
            tokio::task::spawn_blocking(move || this.set_blocking(&secret))
                .await
                .map_err(|e| AppError::SecretStore(format!("encrypted_file write task: {e}")))?
        })
    }

    fn delete(&self) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        Box::pin(async move {
            match std::fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(AppError::SecretStore(format!(
                    "removing {}: {e}",
                    self.path.display()
                ))),
            }
        })
    }
}

#[cfg(all(feature = "tpm", target_os = "linux"))]
fn seal_tpm(settings: &TpmSettings, kek: &[u8; 32]) -> Result<TpmDescriptor, AppError> {
    tpm::seal(settings, kek)
}

#[cfg(all(feature = "tpm", target_os = "linux"))]
fn unseal_tpm(
    settings: &TpmSettings,
    descriptor: &TpmDescriptor,
) -> Result<Zeroizing<[u8; 32]>, AppError> {
    tpm::unseal(settings, descriptor)
}

// `from_config` refuses a TPM source on these builds, so these are reachable
// only through a bug; they still fail closed.
#[cfg(not(all(feature = "tpm", target_os = "linux")))]
fn seal_tpm(_: &TpmSettings, _: &[u8; 32]) -> Result<TpmDescriptor, AppError> {
    Err(no_tpm())
}

#[cfg(not(all(feature = "tpm", target_os = "linux")))]
fn unseal_tpm(_: &TpmSettings, _: &TpmDescriptor) -> Result<Zeroizing<[u8; 32]>, AppError> {
    Err(no_tpm())
}

#[cfg(not(all(feature = "tpm", target_os = "linux")))]
fn no_tpm() -> AppError {
    AppError::SecretStore("this build has no TPM support (Linux + `tpm` feature)".into())
}

/// A systemd credential name is a single path component.
fn validate_credential_name(name: &str) -> Result<(), AppError> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
        return Err(AppError::Config(format!(
            "secrets.encrypted_file: '{name}' is not a valid systemd credential name"
        )));
    }
    Ok(())
}

/// Read the envelope, or `None` when it does not exist yet.
fn read_envelope(path: &Path) -> Result<Option<Vec<u8>>, AppError> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(AppError::SecretStore(format!(
                "reading {}: {e}",
                path.display()
            )));
        }
    };
    warn_if_not_owner_only(path, &file);
    let mut bytes = Vec::new();
    file.take(envelope::MAX_FILE_LEN + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| AppError::SecretStore(format!("reading {}: {e}", path.display())))?;
    if bytes.len() as u64 > envelope::MAX_FILE_LEN {
        return Err(AppError::SecretStore(format!(
            "{} is larger than any encrypted secret file",
            path.display()
        )));
    }
    Ok(Some(bytes))
}

/// Read a passphrase or KEK file into zeroizing memory, sized up front so a
/// reallocation never leaves a copy behind.
fn read_secret_input(path: &Path, what: &str) -> Result<Zeroizing<Vec<u8>>, AppError> {
    let file = File::open(path)
        .map_err(|e| AppError::SecretStore(format!("reading {what} {}: {e}", path.display())))?;
    warn_if_not_owner_only(path, &file);
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    if len > MAX_INPUT_LEN {
        return Err(AppError::SecretStore(format!(
            "{what} {} is implausibly large",
            path.display()
        )));
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(len as usize + 1));
    file.take(MAX_INPUT_LEN + 1)
        .read_to_end(&mut buf)
        .map_err(|e| AppError::SecretStore(format!("reading {what} {}: {e}", path.display())))?;
    if buf.len() as u64 > MAX_INPUT_LEN {
        return Err(AppError::SecretStore(format!(
            "{what} {} is implausibly large",
            path.display()
        )));
    }
    Ok(buf)
}

fn strip_one_newline(buf: &mut Vec<u8>) {
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    }
}

/// 32 raw bytes, or 64 hex characters with an optional trailing newline.
fn decode_kek(raw: &mut Vec<u8>) -> Option<Zeroizing<[u8; 32]>> {
    let mut kek = Zeroizing::new([0u8; 32]);
    if raw.len() == 32 {
        kek.copy_from_slice(raw);
        return Some(kek);
    }
    strip_one_newline(raw);
    if raw.len() == 64 && hex::decode_to_slice(&raw[..], kek.as_mut()).is_ok() {
        return Some(kek);
    }
    None
}

#[cfg(unix)]
fn warn_if_not_owner_only(path: &Path, file: &File) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = file.metadata()
        && meta.permissions().mode() & 0o077 != 0
    {
        tracing::warn!(
            path = %path.display(),
            mode = format_args!("{:o}", meta.permissions().mode() & 0o777),
            "secret-bearing file is readable by other users; restrict it to the service user (chmod 600)"
        );
    }
}

#[cfg(not(unix))]
fn warn_if_not_owner_only(_: &Path, _: &File) {}

/// Write `bytes` to `path` atomically at owner-only permissions: a new file
/// beside it (0600 from creation, fsynced, via
/// [`vti_common::secure_file::write_secret_file`]) renamed over it, then the
/// directory fsynced. A crash leaves the old file or the new one, never a torn
/// one.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
        vti_common::secure_file::restrict_dir_to_owner(&dir)?;
    }
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("the secret file path has no file name"))?;
    let mut suffix = [0u8; 8];
    rand::fill(&mut suffix);
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        name.to_string_lossy(),
        hex::encode(suffix)
    ));
    vti_common::secure_file::write_secret_file(&tmp, bytes)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    #[cfg(unix)]
    if let Ok(d) = File::open(&dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests;
