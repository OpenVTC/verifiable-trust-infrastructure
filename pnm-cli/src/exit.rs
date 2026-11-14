//! Process exit codes — shared with `cnm` and defined in
//! [`vta_cli_common::exit`], so a script written against one CLI reads the
//! other's codes the same way (#2587).

#[allow(unused_imports)]
pub(crate) use vta_cli_common::exit::{AUTH, CONFIG, FAILURE, INTERRUPTED, NOT_FOUND, USAGE};
