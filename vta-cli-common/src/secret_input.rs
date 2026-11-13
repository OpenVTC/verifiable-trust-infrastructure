//! Reading a secret — a mnemonic, a backup password — without putting it on
//! the command line (#2584, #2585).
//!
//! A value given as an argument lands in shell history and in `ps` output
//! for the life of the process. The sources, in order:
//!
//! 1. a file named by a `--…-file <path>` flag, or `-` for stdin;
//! 2. an environment variable, where the command documents one (for cron);
//! 3. a no-echo prompt, when stdin is a terminal.
//!
//! With none of them, the read fails with a message naming the flag, rather
//! than letting a prompt library fail on a closed terminal.

use std::io::{IsTerminal, Read};
use std::path::Path;

use zeroize::Zeroizing;

/// Where to look for a secret and how to ask for it.
pub struct SecretSource<'a> {
    /// The file from `--…-file`, `-` meaning stdin.
    pub file: Option<&'a Path>,
    /// An environment variable to read, when the command documents one.
    pub env: Option<&'a str>,
    /// The terminal prompt.
    pub prompt: &'a str,
    /// Ask twice on the terminal (a new password, not one being checked).
    pub confirm: bool,
    /// What the secret is, for the error ("backup needs a password").
    pub needs: &'a str,
    /// The flag to name in that error (`--password-file`).
    pub file_flag: &'a str,
}

/// Read the secret from the first source that has one. Trailing newlines
/// from a file or stdin are dropped; an empty secret is an error.
pub fn read_secret(
    src: &SecretSource<'_>,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let secret = if let Some(path) = src.file {
        let raw = if path == Path::new("-") {
            let mut s = Zeroizing::new(String::new());
            std::io::stdin().read_to_string(&mut s)?;
            s
        } else {
            Zeroizing::new(
                std::fs::read_to_string(path)
                    .map_err(|e| format!("could not read {}: {e}", path.display()))?,
            )
        };
        Zeroizing::new(raw.trim_end_matches(['\r', '\n']).to_string())
    } else if let Some(v) = src
        .env
        .and_then(|name| std::env::var(name).ok())
        .filter(|v| !v.is_empty())
    {
        Zeroizing::new(v)
    } else if std::io::stdin().is_terminal() {
        let mut p = dialoguer::Password::new().with_prompt(src.prompt);
        if src.confirm {
            p = p.with_confirmation("Confirm", "the two entries do not match");
        }
        Zeroizing::new(p.interact()?)
    } else {
        return Err(missing_message(src).into());
    };
    if secret.is_empty() {
        return Err(format!("{}: the value given is empty", src.needs).into());
    }
    Ok(secret)
}

fn missing_message(src: &SecretSource<'_>) -> String {
    let env = src.env.map(|e| format!(", or set {e}")).unwrap_or_default();
    format!(
        "{} and there is no terminal to ask on: pass {} <path> (or - for stdin){env}",
        src.needs, src.file_flag
    )
}

/// Warn that a secret was passed as a command-line argument (`flag`), which
/// every process on the machine can read. The value is still used, for one
/// release, so existing scripts keep working while they move to `replacement`.
pub fn warn_argv_secret(flag: &str, replacement: &str) {
    eprintln!(
        "warning: {flag} puts the secret on the command line, where shell history and every \
         process on this machine (ps, /proc/<pid>/cmdline) can read it. It will be removed; \
         use {replacement} instead."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src<'a>(file: Option<&'a Path>, env: Option<&'a str>) -> SecretSource<'a> {
        SecretSource {
            file,
            env,
            prompt: "Password",
            confirm: false,
            needs: "backup needs a password",
            file_flag: "--password-file",
        }
    }

    #[test]
    fn a_file_is_read_without_its_trailing_newline() {
        let p = std::env::temp_dir().join(format!("vcc-secret-{}", std::process::id()));
        std::fs::write(&p, "hunter2\n").unwrap();
        let s = read_secret(&src(Some(&p), None)).unwrap();
        assert_eq!(s.as_str(), "hunter2");
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn an_empty_file_is_refused() {
        let p = std::env::temp_dir().join(format!("vcc-secret-empty-{}", std::process::id()));
        std::fs::write(&p, "\n").unwrap();
        let e = read_secret(&src(Some(&p), None)).unwrap_err().to_string();
        assert!(e.contains("empty"), "{e}");
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn the_missing_message_names_the_flag_and_the_variable() {
        let m = missing_message(&src(None, Some("PNM_BACKUP_PASSWORD")));
        assert!(m.contains("--password-file <path> (or - for stdin)"), "{m}");
        assert!(m.contains("PNM_BACKUP_PASSWORD"), "{m}");
    }
}
