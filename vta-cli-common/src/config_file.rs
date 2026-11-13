//! Reading and writing a CLI's TOML profile (`config.toml`) (#2582).
//!
//! Two rules, shared by `pnm` and `cnm`:
//!
//! - **A file that exists but does not parse is fatal.** Treating it as an
//!   empty profile made every configured VTA or community "not configured",
//!   and the suggested fix (`setup`) then overwrote the file with a one-entry
//!   profile, losing every other entry. A missing file is still an empty
//!   profile: that is a first run.
//! - **A save is atomic.** The new contents go to a sibling temporary file,
//!   which is flushed to disk and renamed over the old one, so an
//!   interrupted save leaves the previous profile intact rather than a
//!   truncated one — itself a way to produce the corrupt file the first rule
//!   refuses.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;

/// A profile that exists but cannot be read. Maps to exit code
/// [`crate::exit::CONFIG`].
#[derive(Debug)]
pub struct ConfigFileError {
    path: PathBuf,
    detail: String,
}

impl ConfigFileError {
    /// `detail` is the parser's (or the reader's) own message.
    #[must_use]
    pub fn new(path: &Path, detail: String) -> Self {
        Self {
            path: path.to_path_buf(),
            detail,
        }
    }

    /// The file that could not be read.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Display for ConfigFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path = self.path.display();
        write!(
            f,
            "{path} is not a valid profile: {detail}\n\n\
             Nothing was changed. Fix the file, or move it aside and start again:\n  \
             mv {path} {path}.broken",
            detail = self.detail.trim_end(),
        )
    }
}

impl std::error::Error for ConfigFileError {}

/// Load the TOML profile at `path`, or `T::default()` when there is none.
///
/// A file that exists but cannot be read or parsed is a [`ConfigFileError`],
/// never a default — see the module docs.
pub fn load_toml<T: DeserializeOwned + Default>(path: &Path) -> Result<T, ConfigFileError> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(T::default()),
        Err(e) => return Err(ConfigFileError::new(path, e.to_string())),
    };
    toml::from_str(&contents).map_err(|e| ConfigFileError::new(path, e.to_string()))
}

/// Serialize `value` and atomically replace `path` with it (see
/// [`write_atomic`]).
pub fn save_toml_atomic<T: Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    let contents =
        toml::to_string_pretty(value).map_err(|e| format!("failed to serialize config: {e}"))?;
    write_atomic(path, contents.as_bytes())?;
    Ok(())
}

/// Atomically replace `path` with `bytes`: write a sibling temporary file,
/// fsync it, rename it over `path`, then fsync the directory so the rename
/// itself is durable.
///
/// The temporary file is created owner-only (`0600`) on Unix: a profile
/// names DIDs and mediators an operator need not publish to other users.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other(format!("{} has no file name", path.display())))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    let tmp = dir.join(tmp_name);

    let result = (|| {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        // Persist the rename. A directory cannot be opened for sync on
        // Windows; the rename is what matters there.
        #[cfg(unix)]
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
    struct Profile {
        default: Option<String>,
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "vta-cli-common-config-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn missing_file_is_the_default_profile() {
        let d = tmpdir("missing");
        let p: Profile = load_toml(&d.join("config.toml")).unwrap();
        assert_eq!(p, Profile::default());
    }

    #[test]
    fn a_corrupt_file_is_fatal_names_the_fix_and_is_left_alone() {
        let d = tmpdir("corrupt");
        let path = d.join("config.toml");
        std::fs::write(&path, "default = \"a\"\n}garbage").unwrap();
        let err = load_toml::<Profile>(&path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("is not a valid profile"), "{msg}");
        assert!(
            msg.contains(&format!("mv {} {}.broken", path.display(), path.display())),
            "{msg}"
        );
        assert!(std::fs::read_to_string(&path).unwrap().contains("garbage"));
    }

    #[test]
    fn save_round_trips_and_leaves_no_temporary() {
        let d = tmpdir("save");
        let path = d.join("config.toml");
        std::fs::write(&path, "old").unwrap();
        let p = Profile {
            default: Some("x".into()),
        };
        save_toml_atomic(&path, &p).unwrap();
        assert_eq!(load_toml::<Profile>(&path).unwrap(), p);
        let names: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
    }
}
