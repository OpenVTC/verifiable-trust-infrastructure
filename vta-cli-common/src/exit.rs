//! Process exit codes shared by `pnm` and `cnm` (#2587).
//!
//! A script needs to tell "you asked for something that does not exist"
//! from "the operation failed", and neither from "you typed it wrong".
//! Both CLIs answer with the same codes, so a script written against one
//! works against the other.
//!
//! `2` stays with clap. It owns the code for a usage error and moving it
//! would change what every existing caller sees for a typo, so auth takes
//! `5`.
//!
//! Commands that return an error funnel through one place in each `main`,
//! which picks the code from the error ([`exit_code_for`]) rather than each
//! call site guessing.

/// The operation ran and failed.
pub const FAILURE: i32 = 1;
/// Usage error. Clap returns this itself for a parse failure.
pub const USAGE: i32 = 2;
/// The named thing does not exist.
pub const NOT_FOUND: i32 = 3;
/// Bad configuration, or input that failed validation.
pub const CONFIG: i32 = 4;
/// Not authenticated, or the credential is no longer good. Not the same
/// as being refused a permission: that is a finished operation that
/// failed, and stays [`FAILURE`].
pub const AUTH: i32 = 5;
/// Interrupted. 128 + SIGINT, the shell convention.
pub const INTERRUPTED: i32 = 130;

/// Exit code for a command that returned an error.
///
/// The SDK's error is already typed, so the variant picks the code. A
/// profile that cannot be read ([`crate::config_file::ConfigFileError`]) is
/// [`CONFIG`]; a destructive command refused for want of `--yes` off a
/// terminal ([`crate::confirm::NotConfirmed`]) is [`USAGE`], because the fix
/// is a flag.
///
/// `Forbidden` stays [`FAILURE`] on purpose: the caller is who they say
/// they are and the operation ran, it was refused. That is not the same
/// signal as "your credential is no good", and a script retrying on
/// [`AUTH`] must not retry on it.
#[must_use]
pub fn exit_code_for(err: &(dyn std::error::Error + 'static)) -> i32 {
    use vta_sdk::error::VtaError;
    if err
        .downcast_ref::<crate::config_file::ConfigFileError>()
        .is_some()
    {
        return CONFIG;
    }
    if err.downcast_ref::<crate::confirm::NotConfirmed>().is_some() {
        return USAGE;
    }
    match err.downcast_ref::<VtaError>() {
        Some(VtaError::NotFound(_)) => NOT_FOUND,
        Some(VtaError::Validation(_)) => CONFIG,
        Some(VtaError::Auth(_)) => AUTH,
        _ => FAILURE,
    }
}

/// Print `err` the way [`crate::render::print_cli_error`] does and exit with
/// the code [`exit_code_for`] picks.
pub fn fail(err: &(dyn std::error::Error + 'static)) -> ! {
    crate::render::print_cli_error(err);
    std::process::exit(exit_code_for(err));
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::error::VtaError;

    fn code(e: Box<dyn std::error::Error>) -> i32 {
        exit_code_for(e.as_ref())
    }

    #[test]
    fn typed_errors_pick_their_code() {
        assert_eq!(code(Box::new(VtaError::NotFound("x".into()))), NOT_FOUND);
        assert_eq!(code(Box::new(VtaError::Auth("x".into()))), AUTH);
        assert_eq!(code(Box::new(VtaError::Validation("x".into()))), CONFIG);
        assert_eq!(code(Box::new(VtaError::Forbidden("x".into()))), FAILURE);
        assert_eq!(code("boom".into()), FAILURE);
        assert_eq!(
            code(Box::new(crate::config_file::ConfigFileError::new(
                std::path::Path::new("/x/config.toml"),
                "line 1".into(),
            ))),
            CONFIG
        );
        assert_eq!(
            code(Box::new(crate::confirm::NotConfirmed::new("x"))),
            USAGE
        );
    }
}
