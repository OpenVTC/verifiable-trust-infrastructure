//! Process exit codes.
//!
//! A script needs to tell "you asked for something that does not exist"
//! from "the operation failed", and neither from "you typed it wrong".
//! Everything used to be 1 except clap's own parse errors, so it could
//! tell none of them apart.
//!
//! `2` stays with clap. The documented matrix put auth there, but clap
//! owns the code for a usage error and moving it would change what every
//! existing caller sees for a typo. Auth gets `5` when the authenticated
//! paths grow typed errors; it is not reserved here until something
//! returns it.

/// The operation ran and failed.
pub(crate) const FAILURE: i32 = 1;
/// Usage error. Clap returns this itself; named here only so nothing
/// else claims the code. Deliberately unreferenced.
#[allow(dead_code)]
pub(crate) const USAGE: i32 = 2;
/// The named thing does not exist.
pub(crate) const NOT_FOUND: i32 = 3;
/// Bad configuration, or input that failed validation.
pub(crate) const CONFIG: i32 = 4;
