//! One confirmation rule for irreversible commands (#2583).
//!
//! An irreversible command — deleting an ACL entry, revoking a key,
//! deactivating a published DID, purging a vault — asks before it acts:
//!
//! - `--yes` proceeds without asking;
//! - on a terminal, it asks `… [y/N]`, defaulting to no;
//! - with no terminal to ask and no `--yes`, it refuses ([`NotConfirmed`],
//!   exit [`crate::exit::USAGE`]) rather than guessing either way. This is
//!   the rule `rooms prune` set.
//!
//! The prompt goes to stderr, so a command's stdout (JSON under `--json`)
//! carries nothing but its output.

use std::io::{BufRead, IsTerminal, Write};

/// A destructive command refused because there was no terminal to confirm
/// on and no `--yes`.
#[derive(Debug)]
pub struct NotConfirmed {
    what: String,
}

impl NotConfirmed {
    /// `what` names the action, as in the prompt ("delete the ACL entry for …").
    #[must_use]
    pub fn new(what: impl Into<String>) -> Self {
        Self { what: what.into() }
    }
}

impl std::fmt::Display for NotConfirmed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "refusing to {} without confirmation: there is no terminal to ask. If you mean \
             it, run the same command again with --yes.",
            self.what
        )
    }
}

impl std::error::Error for NotConfirmed {}

/// What [`decide`] says to do, given `--yes` and whether a terminal is there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guard {
    /// `--yes`: go ahead.
    Proceed,
    /// Ask on the terminal.
    Ask,
    /// No terminal and no `--yes`: refuse.
    Refuse,
}

/// The rule, separated from the terminal so it can be tested.
#[must_use]
pub fn decide(yes: bool, interactive: bool) -> Guard {
    match (yes, interactive) {
        (true, _) => Guard::Proceed,
        (false, true) => Guard::Ask,
        (false, false) => Guard::Refuse,
    }
}

/// Confirm an irreversible action. `what` is the action in the infinitive,
/// lower case ("delete the ACL entry for did:key:z6Mk…"); `yes` is the
/// command's `--yes`.
///
/// `Ok(true)` to go ahead, `Ok(false)` when the operator answered no (the
/// caller prints that nothing was done and returns success), and
/// `Err(NotConfirmed)` when there was no one to ask.
pub fn confirm_destructive(what: &str, yes: bool) -> Result<bool, Box<dyn std::error::Error>> {
    match decide(yes, std::io::stdin().is_terminal()) {
        Guard::Proceed => Ok(true),
        Guard::Refuse => Err(Box::new(NotConfirmed::new(what))),
        Guard::Ask => {
            let mut stderr = std::io::stderr();
            write!(stderr, "This cannot be undone. {} [y/N] ", capitalise(what))?;
            stderr.flush()?;
            let mut input = String::new();
            std::io::stdin().lock().read_line(&mut input)?;
            let input = input.trim().to_ascii_lowercase();
            Ok(input == "y" || input == "yes")
        }
    }
}

/// [`confirm_destructive`], printing `Nothing was changed.` when the
/// operator declines, so a caller can write
/// `if !confirm_or_cancel(..)? { return Ok(()); }`.
pub fn confirm_or_cancel(what: &str, yes: bool) -> Result<bool, Box<dyn std::error::Error>> {
    let go = confirm_destructive(what, yes)?;
    if !go {
        eprintln!("Cancelled. Nothing was changed.");
    }
    Ok(go)
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().chain(c).collect::<String>() + "?",
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yes_proceeds_a_terminal_asks_and_nothing_refuses() {
        assert_eq!(decide(true, false), Guard::Proceed);
        assert_eq!(decide(true, true), Guard::Proceed);
        assert_eq!(decide(false, true), Guard::Ask);
        assert_eq!(decide(false, false), Guard::Refuse);
    }

    #[test]
    fn the_refusal_names_the_action_and_the_flag() {
        let msg = NotConfirmed::new("revoke key k1").to_string();
        assert!(msg.contains("revoke key k1"), "{msg}");
        assert!(msg.contains("--yes"), "{msg}");
    }

    #[test]
    fn the_prompt_is_a_question() {
        assert_eq!(capitalise("delete x"), "Delete x?");
    }
}
