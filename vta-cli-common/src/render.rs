use ratatui::{
    buffer::{Buffer, CellDiffOption},
    layout::Rect,
    style::{Color, Modifier},
    widgets::Widget,
};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

// ── Bin-name registration ───────────────────────────────────────────
//
// pnm-cli and cnm-cli both consume this crate's shared command
// handlers. When one of those handlers needs to point the operator at a
// follow-up command (e.g. context-create → "did you mean to run X
// instead?"), it must use the binary the operator actually invoked,
// not a hard-coded `pnm`. Each CLI binary calls `set_bin_name("pnm")`
// or `set_bin_name("cnm")` at startup; handlers read via `bin_name()`
// and fall back to "vta" if neither was registered (the offline `vta
// bootstrap …` path also calls into shared modules).

static BIN_NAME: OnceLock<&'static str> = OnceLock::new();

/// Register the binary name used in operator-facing hints. Call once at
/// CLI startup. Only the first call sticks; later calls are ignored so
/// that nested invocations (e.g. unit tests) don't clobber it.
pub fn set_bin_name(name: &'static str) {
    let _ = BIN_NAME.set(name);
}

/// The binary name registered via [`set_bin_name`]. Defaults to `"vta"`
/// (the offline binary's name) when nothing has been registered, so
/// shared handlers still produce a syntactically valid command string.
pub fn bin_name() -> &'static str {
    BIN_NAME.get().copied().unwrap_or("vta")
}

// ── Full-display toggle ─────────────────────────────────────────────
//
// CLI global `--full-display` flag. When enabled, list commands emit
// every identifier in full (no ratatui-Table truncation) as a sequence
// of key-value blocks. Default rendering stays as the compact table
// for a readable overview; full display is the escape hatch for
// copying complete DIDs, key ids, template names, etc.

static FULL_DISPLAY: AtomicBool = AtomicBool::new(false);

/// Enable or disable full-display output. Called once at CLI startup
/// from the global flag.
pub fn set_full_display(enabled: bool) {
    FULL_DISPLAY.store(enabled, Ordering::Relaxed);
}

/// Current full-display mode. List commands check this to choose
/// between table and full-form output.
pub fn is_full_display() -> bool {
    FULL_DISPLAY.load(Ordering::Relaxed)
}

/// Emit a list entry as aligned `label: value` lines. Used in
/// full-display mode where ratatui-Table truncation would hide full
/// identifiers.
///
/// `pairs` is `[(label, value)]`. Labels are padded to the widest so
/// values line up vertically. A trailing blank line separates entries.
pub fn print_full_entry(pairs: &[(&str, &str)]) {
    let widest = pairs.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
    for (label, value) in pairs {
        let pad = " ".repeat(widest.saturating_sub(label.len()));
        println!("  {label}:{pad}  {DIM}{value}{RESET}");
    }
    println!();
}

/// Print a bold section heading used above a list of full-display
/// entries. Matches the title style of the table-mode block borders.
pub fn print_full_list_title(title: &str, count: usize) {
    println!();
    println!("{BOLD}{title} ({count}){RESET}");
    println!();
}

// ── Output format ───────────────────────────────────────────────────
//
// Global `--json` flag. When enabled, list commands emit a single JSON
// document instead of the ratatui table / full-display rendering. This
// is the automation entry point — scripts piping `pnm acl list --json`
// into `jq` get a stable shape, while interactive operators get the
// human-readable default.

/// Output format selected by the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
}

static OUTPUT_FORMAT: AtomicU8 = AtomicU8::new(0); // 0 = Human, 1 = Json

/// Register the output format. Called once at CLI startup from the
/// global `--json` flag.
pub fn set_output_format(format: OutputFormat) {
    OUTPUT_FORMAT.store(
        match format {
            OutputFormat::Human => 0,
            OutputFormat::Json => 1,
        },
        Ordering::Relaxed,
    );
}

/// Current output format. Default `Human`.
pub fn output_format() -> OutputFormat {
    if OUTPUT_FORMAT.load(Ordering::Relaxed) == 1 {
        OutputFormat::Json
    } else {
        OutputFormat::Human
    }
}

/// Returns true when the operator passed `--json`. List commands check
/// this and dispatch to a JSON serializer instead of their human-
/// readable renderer.
#[must_use]
pub fn is_json_output() -> bool {
    output_format() == OutputFormat::Json
}

/// Pretty-print a serializable value as JSON to stdout. Used by list
/// commands when [`is_json_output`] is true. Errors here are surfaced
/// as a CLI error rather than a panic so the caller can render via
/// `print_cli_error`.
pub fn print_json<T: serde::Serialize>(value: &T) -> Result<(), serde_json::Error> {
    let text = serde_json::to_string_pretty(value)?;
    println!("{text}");
    Ok(())
}

// ── ANSI constants ──────────────────────────────────────────────────

pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const GREEN: &str = "\x1b[32m";
pub const RED: &str = "\x1b[31m";
pub const CYAN: &str = "\x1b[36m";
pub const YELLOW: &str = "\x1b[33m";
pub const RESET: &str = "\x1b[0m";

// ── Error reporting ─────────────────────────────────────────────────

/// Print a CLI error to stderr in a form an operator can act on.
///
/// Downcasts to [`vta_sdk::error::VtaError`] when possible and emits a
/// tailored remediation hint for the common failure modes (auth, network,
/// forbidden, validation). Falls back to the raw error message + source
/// chain for anything else, so unknown failures still get their underlying
/// cause surfaced.
///
/// Call this from the top-level CLI match instead of `eprintln!("Error:
/// {e}")` — the raw form loses auth/network context that operators need
/// to fix things themselves.
pub fn print_cli_error(err: &(dyn std::error::Error + 'static)) {
    use vta_sdk::error::VtaError;
    if let Some(vta_err) = err.downcast_ref::<VtaError>() {
        match vta_err {
            VtaError::Auth(msg) => {
                eprintln!("{RED}\u{2717}{RESET} Authentication failed: {msg}");
                eprintln!(
                    "  {DIM}Token may be expired. Try `pnm setup` to re-authenticate, or check \
                     that the VTA's `/auth` endpoint is reachable.{RESET}"
                );
            }
            VtaError::Forbidden(msg) => {
                eprintln!("{RED}\u{2717}{RESET} Forbidden: {msg}");
                eprintln!(
                    "  {DIM}Your role or context access doesn't permit this operation. \
                     Inspect with `pnm acl get <your-did>`.{RESET}"
                );
            }
            VtaError::NotFound(msg) => {
                eprintln!("{RED}\u{2717}{RESET} Not found: {msg}");
            }
            VtaError::Conflict(msg) => {
                eprintln!("{RED}\u{2717}{RESET} Conflict: {msg}");
            }
            VtaError::Gone(msg) => {
                let bin = bin_name();
                eprintln!("{RED}\u{2717}{RESET} Resource is gone: {msg}");
                eprintln!(
                    "  {DIM}This usually means the bootstrap carve-out has already been used. \
                     For a second admin, run `{bin} bootstrap provision-request` from the new \
                     operator's host and have an existing admin run \
                     `{bin} bootstrap provision-integration` against this VTA.{RESET}"
                );
            }
            VtaError::Validation(msg) => {
                eprintln!("{RED}\u{2717}{RESET} Invalid request: {msg}");
            }
            VtaError::Network(e) => {
                eprintln!("{RED}\u{2717}{RESET} Network error: {e}");
                eprintln!("  {DIM}Is the VTA reachable? Check its URL with `pnm vta info`.{RESET}");
            }
            VtaError::Server { status, body } => {
                eprintln!("{RED}\u{2717}{RESET} Server error (HTTP {status}): {body}");
                eprintln!(
                    "  {DIM}This is a VTA-side failure. Check server logs or contact the operator.{RESET}"
                );
            }
            VtaError::UnsupportedTransport(msg) => {
                eprintln!("{RED}\u{2717}{RESET} Unsupported transport: {msg}");
                eprintln!(
                    "  {DIM}This operation requires a specific transport (REST or DIDComm). \
                     Check which mode your CLI is in and whether the endpoint supports it.{RESET}"
                );
            }
            VtaError::DidcommTransport(msg) => {
                eprintln!("{RED}\u{2717}{RESET} DIDComm transport error: {msg}");
                eprintln!(
                    "  {DIM}Mediator or peer unreachable. Retry after checking mediator \
                     connectivity.{RESET}"
                );
            }
            VtaError::DidcommRemote { code, comment } => {
                eprintln!("{RED}\u{2717}{RESET} Remote error ({code}): {comment}");
            }
            VtaError::Protocol(msg) => {
                eprintln!("{RED}\u{2717}{RESET} Protocol error: {msg}");
            }
            // ── Runtime service-management variants (T0.2) ────────
            VtaError::LastServiceRefused => {
                let bin = bin_name();
                eprintln!(
                    "{RED}\u{2717}{RESET} Refused: would leave the VTA with no advertised services."
                );
                eprintln!(
                    "  {DIM}At least one transport (REST or DIDComm) must remain advertised. \
                     Enable the other transport first via `{bin} services <kind> enable …`, \
                     then retry.{RESET}"
                );
            }
            VtaError::ServiceNotPresent => {
                let bin = bin_name();
                eprintln!("{RED}\u{2717}{RESET} Service is not present.");
                eprintln!(
                    "  {DIM}The service kind isn't currently enabled. Use `{bin} services \
                     <kind> enable …` to bring it online before updating, disabling, or rolling \
                     it back.{RESET}"
                );
            }
            VtaError::ServiceAlreadyEnabled => {
                let bin = bin_name();
                eprintln!("{RED}\u{2717}{RESET} Service is already enabled.");
                eprintln!(
                    "  {DIM}Use `{bin} services <kind> update …` to change its configuration, \
                     or `{bin} services <kind> disable` to remove it.{RESET}"
                );
            }
            VtaError::MediatorHandshakeFailed { reason } => {
                eprintln!("{RED}\u{2717}{RESET} Mediator handshake failed: {reason}");
                eprintln!(
                    "  {DIM}Confirm the mediator DID is correct and the mediator is reachable. \
                     The reason above is the specific cause from the handshake protocol.{RESET}"
                );
            }
            VtaError::DrainTtlOutOfBounds {
                min,
                max,
                requested,
            } => {
                eprintln!(
                    "{RED}\u{2717}{RESET} Drain TTL {requested}s is outside the allowed range \
                     [{min}s, {max}s]."
                );
                eprintln!(
                    "  {DIM}Pick a value within those bounds. The minimum applies when the \
                     command is delivered over DIDComm transport (so the listener stays up long \
                     enough for the response).{RESET}"
                );
            }
            VtaError::NoPriorMutation => {
                let bin = bin_name();
                eprintln!("{RED}\u{2717}{RESET} No prior mutation to roll back.");
                eprintln!(
                    "  {DIM}Use `{bin} services <kind> {{enable,update,disable}} …` directly \
                     instead of rollback.{RESET}"
                );
            }
            other => eprintln!("{RED}\u{2717}{RESET} Error: {other}"),
        }
        return;
    }
    eprintln!("{RED}\u{2717}{RESET} Error: {err}");
    let mut source = err.source();
    while let Some(s) = source {
        eprintln!("  {DIM}caused by: {s}{RESET}");
        source = s.source();
    }
}

// ── Ratatui rendering helpers ───────────────────────────────────────

pub fn print_widget(widget: impl Widget, height: u16) {
    let width = ratatui::crossterm::terminal::size().map_or(120, |(w, _)| w);
    let area = Rect::new(0, 0, width, height);
    let mut buf = Buffer::empty(area);
    widget.render(area, &mut buf);

    let mut out = String::new();
    for y in 0..height {
        let mut cur_fg = Color::Reset;
        let mut cur_bg = Color::Reset;
        let mut cur_mod = Modifier::empty();

        for x in 0..width {
            let cell = &buf[(x, y)];
            if cell.diff_option == CellDiffOption::Skip {
                continue;
            }

            if cell.fg != cur_fg || cell.bg != cur_bg || cell.modifier != cur_mod {
                out.push_str("\x1b[0m");
                push_ansi_fg(&mut out, cell.fg);
                push_ansi_bg(&mut out, cell.bg);
                push_ansi_mod(&mut out, cell.modifier);
                cur_fg = cell.fg;
                cur_bg = cell.bg;
                cur_mod = cell.modifier;
            }

            out.push_str(cell.symbol());
        }
        out.push_str("\x1b[0m\n");
    }

    print!("{out}");
}

pub fn push_ansi_fg(out: &mut String, color: Color) {
    use std::fmt::Write as _;
    match color {
        Color::Reset => {}
        Color::Black => out.push_str("\x1b[30m"),
        Color::Red => out.push_str("\x1b[31m"),
        Color::Green => out.push_str("\x1b[32m"),
        Color::Yellow => out.push_str("\x1b[33m"),
        Color::Blue => out.push_str("\x1b[34m"),
        Color::Magenta => out.push_str("\x1b[35m"),
        Color::Cyan => out.push_str("\x1b[36m"),
        Color::Gray => out.push_str("\x1b[37m"),
        Color::DarkGray => out.push_str("\x1b[90m"),
        Color::LightRed => out.push_str("\x1b[91m"),
        Color::LightGreen => out.push_str("\x1b[92m"),
        Color::LightYellow => out.push_str("\x1b[93m"),
        Color::LightBlue => out.push_str("\x1b[94m"),
        Color::LightMagenta => out.push_str("\x1b[95m"),
        Color::LightCyan => out.push_str("\x1b[96m"),
        Color::White => out.push_str("\x1b[97m"),
        Color::Rgb(r, g, b) => {
            let _ = write!(out, "\x1b[38;2;{r};{g};{b}m");
        }
        Color::Indexed(i) => {
            let _ = write!(out, "\x1b[38;5;{i}m");
        }
    }
}

pub fn push_ansi_bg(out: &mut String, color: Color) {
    use std::fmt::Write as _;
    match color {
        Color::Reset => {}
        Color::Black => out.push_str("\x1b[40m"),
        Color::Red => out.push_str("\x1b[41m"),
        Color::Green => out.push_str("\x1b[42m"),
        Color::Yellow => out.push_str("\x1b[43m"),
        Color::Blue => out.push_str("\x1b[44m"),
        Color::Magenta => out.push_str("\x1b[45m"),
        Color::Cyan => out.push_str("\x1b[46m"),
        Color::Gray => out.push_str("\x1b[47m"),
        Color::DarkGray => out.push_str("\x1b[100m"),
        Color::LightRed => out.push_str("\x1b[101m"),
        Color::LightGreen => out.push_str("\x1b[102m"),
        Color::LightYellow => out.push_str("\x1b[103m"),
        Color::LightBlue => out.push_str("\x1b[104m"),
        Color::LightMagenta => out.push_str("\x1b[105m"),
        Color::LightCyan => out.push_str("\x1b[106m"),
        Color::White => out.push_str("\x1b[107m"),
        Color::Rgb(r, g, b) => {
            let _ = write!(out, "\x1b[48;2;{r};{g};{b}m");
        }
        Color::Indexed(i) => {
            let _ = write!(out, "\x1b[48;5;{i}m");
        }
    }
}

pub fn push_ansi_mod(out: &mut String, modifier: Modifier) {
    if modifier.contains(Modifier::BOLD) {
        out.push_str("\x1b[1m");
    }
    if modifier.contains(Modifier::DIM) {
        out.push_str("\x1b[2m");
    }
    if modifier.contains(Modifier::ITALIC) {
        out.push_str("\x1b[3m");
    }
    if modifier.contains(Modifier::UNDERLINED) {
        out.push_str("\x1b[4m");
    }
    if modifier.contains(Modifier::REVERSED) {
        out.push_str("\x1b[7m");
    }
    if modifier.contains(Modifier::CROSSED_OUT) {
        out.push_str("\x1b[9m");
    }
}

pub fn print_section(title: &str) {
    let pad = 46usize.saturating_sub(title.len());
    println!(
        "\n{DIM}──{RESET} {BOLD}{title}{RESET} {DIM}{}{RESET}",
        "─".repeat(pad)
    );
}
