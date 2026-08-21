//! Where a tool keeps its long-lived secrets, and what it does when that
//! store cannot be opened.
//!
//! Every tool in this workspace — `vta`, `vtc`, `pnm`, `cnm`, and external
//! consumers such as OpenVTC — resolves the *same* store on the same OS via
//! [`crate::keyring_init::install_default_store`]. What differed until now was
//! the failure behaviour: each printed its own warning and carried on, so a
//! machine whose credential store was unavailable behaved as though the user
//! had simply never logged in.
//!
//! This module holds the two things that behaviour needs to be consistent: one
//! explanation ([`unavailable_message`]) and one deliberate opt-out
//! ([`OVERRIDE_ENV`]).
//!
//! It is always compiled — no feature gate — so a consumer that does not enable
//! the `keyring` feature can still render the same text and honour the same
//! override.

/// Which store a tool was told to use for its sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureStore {
    /// The platform credential store — Keychain, Credential Manager, or the
    /// DBus Secret Service. The default, and the only durable one.
    Os,
    /// A plaintext JSON file at `0600`, for hosts that have no credential
    /// store at all. **Chosen explicitly, never fallen back to.**
    File,
}

/// Environment variable that overrides store selection.
///
/// The only recognised values are `os` and `file`. Anything else is a hard
/// error rather than a silent default — a typo in this variable must not be the
/// difference between a keychain entry and a file on disk.
pub const OVERRIDE_ENV: &str = "VTI_SECURE_STORE";

/// Read [`OVERRIDE_ENV`].
///
/// `Ok(None)` means the operator expressed no preference and the compiled
/// default applies. `Err` carries a ready-to-print explanation of an
/// unrecognised value.
pub fn override_from_env() -> Result<Option<SecureStore>, String> {
    let raw = match std::env::var(OVERRIDE_ENV) {
        Ok(v) => v,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(format!("{OVERRIDE_ENV} is not valid UTF-8"));
        }
    };
    parse_override(&raw)
}

/// The value half of [`override_from_env`], split out so it is testable without
/// mutating process environment shared with every other test in the binary.
fn parse_override(raw: &str) -> Result<Option<SecureStore>, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" => Ok(None),
        "os" | "keyring" => Ok(Some(SecureStore::Os)),
        "file" => Ok(Some(SecureStore::File)),
        other => Err(format!(
            "{OVERRIDE_ENV}={other:?} is not a store. Use `os` for the platform \
             credential store, or `file` for a plaintext file at 0600."
        )),
    }
}

/// The platform-specific remedy for an unreachable credential store.
fn remedy() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "Unlock the login keychain, or run this from a session that has one \
         (an SSH session without `security unlock-keychain` does not)."
    }
    #[cfg(target_os = "linux")]
    {
        "Start a Secret Service provider — gnome-keyring-daemon, KWallet, or \
         KeePassXC — and make sure DBus is reachable ($DBUS_SESSION_BUS_ADDRESS). \
         Headless hosts usually have neither."
    }
    #[cfg(target_os = "windows")]
    {
        "Check that the Credential Manager service is running and that this \
         account has a loaded user profile (a service account run with \
         `LoadUserProfile=false` does not)."
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        "This platform has no supported credential store."
    }
}

/// The one explanation every tool prints when the credential store cannot be
/// opened.
///
/// `tool` is the binary name, so the suggested command line is copy-pasteable.
/// `err` is whatever the store returned; it is taken as `Display` rather than a
/// `keyring_core::Error` so this text is available without the `keyring`
/// feature — external consumers render it too.
///
/// The text deliberately leads with the *consequence*. The failure mode that
/// motivated this is a user being told their network was broken when in fact
/// their credential store had evaporated, so the first line has to say what is
/// actually gone.
pub fn unavailable_message(tool: &str, err: &dyn std::fmt::Display) -> String {
    format!(
        "error: the OS credential store is unavailable, so {tool} cannot read or \
         write your session.\n\
         \n\
           cause: {err}\n\
         \n\
         Your credentials are not lost — they are in a store this process cannot \
         reach. {tool} is stopping rather than continuing as though you had never \
         logged in, which is what it used to do.\n\
         \n\
         {}\n\
         \n\
         On a host that genuinely has no credential store, opt in to file storage \
         deliberately:\n\
         \n\
             {OVERRIDE_ENV}=file {tool} ...\n\
         \n\
         That writes secrets as plaintext JSON at mode 0600. Only use it where the \
         filesystem itself is the trust boundary — an encrypted volume, or a \
         locked-down container.",
        remedy()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The override parser is the gate between "keychain" and "file on disk",
    /// so an unrecognised value must not resolve to either.
    #[test]
    fn an_unknown_override_is_an_error_not_a_default() {
        assert!(matches!(parse_override("os"), Ok(Some(SecureStore::Os))));
        assert!(matches!(
            parse_override("File"),
            Ok(Some(SecureStore::File))
        ));
        assert!(matches!(
            parse_override("  file  "),
            Ok(Some(SecureStore::File))
        ));
        assert!(matches!(parse_override(""), Ok(None)));

        // The dangerous direction: a near-miss must not resolve to `File`.
        assert!(parse_override("plaintext").is_err());
        assert!(parse_override("fil").is_err());
        assert!(parse_override("true").is_err());
    }

    /// The message exists to stop a user diagnosing the wrong subsystem, so the
    /// consequence and the opt-out both have to be in it.
    #[test]
    fn the_message_names_the_consequence_and_the_opt_out() {
        let msg = unavailable_message("pnm", &"no default store");
        assert!(msg.contains("cannot read or write your session"));
        assert!(msg.contains("no default store"));
        assert!(msg.contains("VTI_SECURE_STORE=file pnm"));
        assert!(msg.contains("0600"));
    }
}
