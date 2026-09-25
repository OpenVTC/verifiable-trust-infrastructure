//! Connection multiplexing for `pnm`, modelled on `ssh`'s
//! `ControlMaster`/`ControlPersist`.
//!
//! # Why
//!
//! Every `pnm` invocation is a fresh process, so each one re-resolves the VTA
//! and mediator DIDs, opens a TLS connection per host, authenticates to the
//! mediator and upgrades a WebSocket before it sends anything. Measured against
//! a hosted stack that is ~23 network round-trips of setup for a command whose
//! useful work is one. A master holds the authenticated session and later
//! invocations borrow it, which is the same trade `ssh -M` has made since 2004.
//!
//! # Shape
//!
//! - [`ControlMaster`] mirrors `ssh_config(5)`: `no`, `auto`, `yes`, `ask`.
//! - [`ControlPersist`] mirrors it too, defaulting to **10 minutes** idle. This
//!   is what bounds how long the operator's admin key stays resident, so it is
//!   a security control, not just a resource one.
//! - A missing, stale or unusable socket is **never an error** under `auto`:
//!   the command falls back to the ordinary one-shot path, exactly as ssh
//!   "will fall back to connecting normally if the control socket does not
//!   exist, or is not listening".
//!
//! # Security
//!
//! The master holds the only copy of the operator's admin private key in
//! memory and will run any command handed to it, so the socket is the
//! privilege boundary:
//!
//! - the control directory must be owned by us and not group/world accessible,
//!   and is created `0700`;
//! - the socket is `0600` and its path is refused if it is a symlink or not
//!   owned by us (a symlink check closes the swap-the-path race);
//! - every accepted connection has its peer uid checked against our own, so
//!   another user who can reach the socket still cannot drive it;
//! - `ask` requires confirmation before a master is used or created;
//! - the idle timeout evicts the key without operator action.

pub(crate) mod client;
pub(crate) mod fdpass;
pub(crate) mod master;
pub(crate) mod proto;

use std::fmt;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// `ssh_config(5)` ControlMaster, same vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ControlMaster {
    /// Never multiplex; every command is a fresh session.
    No,
    /// Use a master if one is listening, otherwise start one. Falls back to a
    /// direct session if that cannot be done.
    Auto,
    /// Require multiplexing: use a master, starting one if absent, and fail
    /// rather than quietly running a direct session.
    ///
    /// Note this is *not* ssh's `yes`, which means "be the master" and refuses
    /// to attach to an existing one (`mux.c` lets only `auto`/`autoask`/`no`
    /// reach the client path). That reading suits `ssh -M`; for a CLI the
    /// useful strict mode is "never silently fall back", which is this.
    Yes,
    /// Like `auto`, but confirm with the operator first.
    Ask,
}

impl ControlMaster {
    pub(crate) fn enabled(self) -> bool {
        self != Self::No
    }
}

/// `ssh_config(5)` ControlPersist: how long an idle master outlives its
/// clients. `None` means "do not persist" (ssh's `no`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ControlPersist(pub(crate) Option<Duration>);

impl ControlPersist {
    /// Ten minutes — short enough that an unattended workstation is not
    /// holding an admin key all afternoon, long enough to cover a working
    /// session of commands. Held as the string clap advertises so the
    /// documented default and the parsed value cannot drift; the unit test
    /// pins what it parses to.
    pub(crate) const DEFAULT_STR: &'static str = "10m";
}

impl std::str::FromStr for ControlPersist {
    type Err = String;

    /// `no` | `yes`/`0` (forever) | `<n>` seconds | `<n>s` | `<n>m` | `<n>h`,
    /// the subset of `sshd_config(5)` time formats worth supporting here.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        match s {
            "no" => return Ok(Self(None)),
            "yes" | "0" => return Ok(Self(Some(Duration::MAX))),
            _ => {}
        }
        let (digits, mult) = match s.strip_suffix(['s', 'S']) {
            Some(d) => (d, 1),
            None => match s.strip_suffix(['m', 'M']) {
                Some(d) => (d, 60),
                None => match s.strip_suffix(['h', 'H']) {
                    Some(d) => (d, 3600),
                    None => (s, 1),
                },
            },
        };
        let n: u64 = digits.parse().map_err(|_| {
            format!("invalid --control-persist value `{s}` (try `no`, `10m`, `600`)")
        })?;
        Ok(Self(Some(Duration::from_secs(n * mult))))
    }
}

impl fmt::Display for ControlPersist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            None => write!(f, "no"),
            Some(d) if d == Duration::MAX => write!(f, "yes"),
            Some(d) => write!(f, "{}s", d.as_secs()),
        }
    }
}

/// Everything the control layer needs, resolved once in `main`.
#[derive(Debug, Clone)]
pub(crate) struct ControlConfig {
    pub(crate) mode: ControlMaster,
    pub(crate) persist: ControlPersist,
    pub(crate) path: PathBuf,
}

/// Default socket for a slug: `<control dir>/<16 hex of sha256(slug)>.sock`.
///
/// Keyed by slug rather than by DID because the slug is what selects a session;
/// two slugs pointing at one VTA still authenticate as different clients and
/// must not share a master.
///
/// Hashed rather than spelled out because `sun_path` is 104 bytes on macOS and
/// the profile directory alone is ~55 of them, so a real slug overflows once
/// `claim_socket` appends its temporary suffix. This is what ssh's `%C`
/// expansion exists for. It also keeps an operator-chosen slug off the
/// filesystem verbatim.
pub(crate) fn default_control_path(slug: &str) -> Result<PathBuf, String> {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(slug.as_bytes());
    let name: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    let path = control_dir()?.join(format!("{name}.sock"));
    check_socket_path_len(&path)?;
    Ok(path)
}

/// `<profile dir>/control`, created `0700` and verified.
///
/// Rooted in the profile rather than a runtime dir so `PNM_HOME` isolates the
/// control socket the way it isolates every other store.
fn control_dir() -> Result<PathBuf, String> {
    let dir = crate::config::config_dir()
        .map_err(|e| format!("profile directory: {e}"))?
        .join("control");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    harden_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(dir)
}

/// Longest `sun_path` a unix socket can carry, minus the suffix
/// [`master::claim_socket`] appends to its temporary path (`.<pid>.<nanos>`,
/// at most 21 bytes). macOS allows 104
/// bytes and Linux 108; take the smaller so a path that works on one works on
/// both. Exceeding it fails in `bind()` with a bare ENAMETOOLONG, so say it
/// plainly instead — ssh does the same (`ControlPath too long`).
const MAX_SOCKET_PATH: usize = 104 - 24;

/// Force `0700` and refuse a directory we do not own.
fn harden_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    let md = std::fs::metadata(dir)?;
    if md.uid() != current_uid() {
        return Err(io::Error::other(
            "control directory is owned by another user",
        ));
    }
    Ok(())
}

/// Reject a path that cannot fit in a `sockaddr_un`.
pub(crate) fn check_socket_path_len(path: &Path) -> Result<(), String> {
    let len = path.as_os_str().len();
    if len > MAX_SOCKET_PATH {
        return Err(format!(
            "control path is too long for a unix socket ({len} > {MAX_SOCKET_PATH}): {}",
            path.display()
        ));
    }
    Ok(())
}

/// Reject a socket path that is a symlink or not ours before touching it.
///
/// Without the symlink check, anyone who can create the path first can point it
/// at a socket they control and receive commands — and the operator's fds —
/// intended for the master.
pub(crate) fn vet_socket_path(path: &Path) -> io::Result<()> {
    let md = match std::fs::symlink_metadata(path) {
        Ok(md) => md,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if md.file_type().is_symlink() {
        return Err(io::Error::other(
            "control path is a symlink; refusing to use it",
        ));
    }
    if md.uid() != current_uid() {
        return Err(io::Error::other("control path is owned by another user"));
    }
    Ok(())
}

pub(crate) fn current_uid() -> u32 {
    // SAFETY: getuid is always safe and cannot fail.
    unsafe { libc::getuid() }
}

/// uid on the far end of an accepted connection.
pub(crate) fn peer_uid(stream: &std::os::unix::net::UnixStream) -> io::Result<u32> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: getsockopt writes at most `len` bytes into `cred`.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(cred.uid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let (mut uid, mut gid) = (0u32, 0u32);
        // SAFETY: both out-params are valid for the duration of the call.
        let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn persist_accepts_the_ssh_time_vocabulary() {
        assert_eq!(
            ControlPersist::from_str("no").unwrap(),
            ControlPersist(None)
        );
        assert_eq!(
            ControlPersist::from_str("10m").unwrap(),
            ControlPersist(Some(Duration::from_secs(600)))
        );
        assert_eq!(
            ControlPersist::from_str("600").unwrap(),
            ControlPersist(Some(Duration::from_secs(600)))
        );
        assert_eq!(
            ControlPersist::from_str("2h").unwrap(),
            ControlPersist(Some(Duration::from_secs(7200)))
        );
        assert_eq!(
            ControlPersist::from_str("yes").unwrap(),
            ControlPersist(Some(Duration::MAX))
        );
        assert!(ControlPersist::from_str("soon").is_err());
    }

    #[test]
    fn default_persist_is_ten_minutes_and_matches_the_flag() {
        assert_eq!(
            ControlPersist::from_str(ControlPersist::DEFAULT_STR).unwrap(),
            ControlPersist(Some(Duration::from_secs(600))),
            "the shipped default must be ten minutes"
        );
    }

    #[test]
    fn control_path_is_a_fixed_length_hash_of_the_slug() {
        let evil = default_control_path("../../etc/evil").unwrap();
        let name = evil.file_name().unwrap().to_str().unwrap();
        assert_eq!(name.len(), "0123456789abcdef.sock".len());
        assert!(!name.contains('/'), "a slug cannot introduce path segments");
        assert!(
            !name.contains(".."),
            "a slug cannot introduce a parent reference"
        );

        let a = default_control_path("alpha").unwrap();
        let b = default_control_path("beta").unwrap();
        assert_ne!(a, b);
        assert_eq!(a, default_control_path("alpha").unwrap());
    }

    #[test]
    fn a_realistic_slug_fits_on_this_machine() {
        // Spelled out rather than hashed, this overflows sun_path.
        default_control_path("visa-dilemma.vta.affinidi.io").unwrap();
    }

    #[test]
    fn an_overlong_control_path_is_refused_before_bind() {
        let long = PathBuf::from("/tmp")
            .join("x".repeat(MAX_SOCKET_PATH))
            .join("c.sock");
        assert!(check_socket_path_len(&long).is_err());
        assert!(check_socket_path_len(Path::new("/tmp/pnm/c.sock")).is_ok());
    }

    #[test]
    fn a_symlinked_control_path_is_refused() {
        let dir = std::env::temp_dir().join(format!("pnm-ctl-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("real.sock");
        let link = dir.join("link.sock");
        std::fs::write(&target, b"").unwrap();
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(vet_socket_path(&link).is_err());
        assert!(vet_socket_path(&target).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
