//! The start-up block `pnm` and `cnm` share (#2587).
//!
//! Output format, colour, the binary name hints are printed with and whether
//! the banner is shown are decided the same way in both CLIs, so a script
//! written against one behaves the same against the other:
//!
//! - **Format follows the destination.** A terminal gets the table; anything
//!   else — a pipe, a file, a CI log — gets JSON, because the only reason to
//!   redirect the output is to have something read it. `--json` forces JSON
//!   even on a terminal.
//! - **Colour is for a terminal**, and `NO_COLOR` (<https://no-color.org>)
//!   turns it off even on one. Gated on stdout, where the rendered output goes.
//! - **The banner is for a person**: it goes to stderr, so it is gated on
//!   stderr. Redirecting stdout alone still shows it.

use std::io::IsTerminal;

use crate::render::{self, OutputFormat};

/// Apply the output settings for `bin` (`"pnm"` / `"cnm"`). `json` is the
/// command line's `--json`.
pub fn init_output(bin: &'static str, json: bool) {
    let stdout_is_tty = std::io::stdout().is_terminal();
    if json || !stdout_is_tty {
        render::set_output_format(OutputFormat::Json);
    }
    render::set_color(color_wanted(stdout_is_tty));
    render::set_bin_name(bin);
}

/// Whether colour should be emitted on a destination that `is_tty` or not.
#[must_use]
pub fn color_wanted(is_tty: bool) -> bool {
    is_tty && std::env::var_os("NO_COLOR").is_none()
}

/// Whether the start-up banner should be printed (stderr is a terminal).
#[must_use]
pub fn banner_wanted() -> bool {
    std::io::stderr().is_terminal()
}

/// ANSI codes for the banner, written to stderr: empty when stderr is not a
/// terminal or `NO_COLOR` is set. The banner prints before
/// [`render::set_color`] has a say about stderr, so it asks itself.
#[must_use]
pub fn banner_color(code: &'static str) -> &'static str {
    if color_wanted(std::io::stderr().is_terminal()) {
        code
    } else {
        ""
    }
}

/// Write `C`'s completion script for `shell` to stdout, under the binary
/// name `bin` (#2592).
pub fn print_completions<C: clap::CommandFactory>(shell: clap_complete::Shell, bin: &str) {
    let mut cmd = C::command();
    clap_complete::generate(shell, &mut cmd, bin, &mut std::io::stdout());
}
