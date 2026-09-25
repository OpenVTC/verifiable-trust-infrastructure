//! Process exit codes.
//!
//! A script needs to tell "you asked for something that does not exist"
//! from "the operation failed", and neither from "you typed it wrong".
//! Everything used to be 1 except clap's own parse errors, so it could
//! tell none of them apart.
//!
//! `2` stays with clap. The documented matrix put auth there, but clap
//! owns the code for a usage error and moving it would change what every
//! existing caller sees for a typo, so auth takes `5`.
//!
//! Commands that return an error all funnel through one place in `main`,
//! which picks the code from the error rather than each call site
//! guessing. See `exit_code_for`.

/// The operation ran and failed.
pub(crate) const FAILURE: i32 = 1;
/// Usage error. Clap returns this itself for a parse failure; the
/// retired-subcommand redirect uses it for the same reason.
pub(crate) const USAGE: i32 = 2;
/// The named thing does not exist.
pub(crate) const NOT_FOUND: i32 = 3;
/// Bad configuration, or input that failed validation.
pub(crate) const CONFIG: i32 = 4;
/// Not authenticated, or the credential is no longer good. Not the same
/// as being refused a permission: that is a finished operation that
/// failed, and stays `FAILURE`.
pub(crate) const AUTH: i32 = 5;
/// Interrupted. 128 + SIGINT, the shell convention.
pub(crate) const INTERRUPTED: i32 = 130;
