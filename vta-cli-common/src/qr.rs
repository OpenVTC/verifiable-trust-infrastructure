//! QR codes for DIDs, for a phone to scan off a terminal or a file.
//!
//! A QR code here carries the **bare DID** and nothing else. A DID is already
//! a URI (scheme `did`), so a phone's camera can hand it to any wallet
//! registered for that scheme; a `did://` or app-specific wrapper would be one
//! more format every scanner has to unwrap. The VTC landing page draws its
//! community DID the same way (`GET /v1/community/did-qr.svg`).
//!
//! Level M throughout, as the Keyring enrolment offer uses: a `did:webvh` fits
//! a version-5 code (37 modules), small enough to scan off a terminal.

use qrcode::render::svg;
use qrcode::types::QrError;
use qrcode::{Color, EcLevel, QrCode};

/// Modules of light margin on every side. Scanners need a quiet zone; four
/// is what the QR specification requires.
const QUIET_ZONE: usize = 4;

/// ANSI: black foreground on a bright white background.
const DARK_ON_WHITE: &str = "\x1b[30;107m";
const RESET: &str = "\x1b[0m";

fn encode(data: &str) -> Result<QrCode, QrError> {
    QrCode::with_error_correction_level(data.as_bytes(), EcLevel::M)
}

/// Render `data` for a terminal, two modules per character cell (half
/// blocks), one `String` per output line.
///
/// Every line paints its own colours: black modules on a white ground. A
/// terminal's default colours cannot be used, because on a dark theme they
/// draw the code inverted (light modules on dark), and many phone cameras
/// refuse an inverted code. The quiet zone is part of the output.
pub fn terminal_lines(data: &str) -> Result<Vec<String>, QrError> {
    let code = encode(data)?;
    let width = code.width();
    let colors = code.to_colors();
    let side = width + 2 * QUIET_ZONE;

    // Dark at (x, y) in quiet-zone coordinates; anything outside the code is
    // margin, and margin is light.
    let dark = |x: usize, y: usize| -> bool {
        if x < QUIET_ZONE || y < QUIET_ZONE {
            return false;
        }
        let (cx, cy) = (x - QUIET_ZONE, y - QUIET_ZONE);
        cx < width && cy < width && colors[cy * width + cx] == Color::Dark
    };

    let mut lines = Vec::with_capacity(side.div_ceil(2));
    for y in (0..side).step_by(2) {
        let mut line = String::from(DARK_ON_WHITE);
        for x in 0..side {
            line.push(match (dark(x, y), dark(x, y + 1)) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        line.push_str(RESET);
        lines.push(line);
    }
    Ok(lines)
}

/// Render `data` as a standalone SVG: black modules on white, quiet zone
/// included, sized by its `viewBox` so it scales cleanly.
pub fn svg(data: &str) -> Result<String, QrError> {
    Ok(encode(data)?
        .render::<svg::Color>()
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .quiet_zone(true)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str =
        "did:webvh:QmXi1PZD4NEvcvjfErAzVoCGtBFEv7dhXZQJHvcFY4U83F:webvh.storm.ws:first-vtc";

    /// Undo the half-block packing: the module grid the terminal draws.
    fn drawn_grid(lines: &[String]) -> Vec<Vec<bool>> {
        let mut rows = Vec::new();
        for line in lines {
            let body = line
                .strip_prefix(DARK_ON_WHITE)
                .and_then(|l| l.strip_suffix(RESET))
                .expect("every line paints its own colours and resets them");
            let (mut top, mut bottom) = (Vec::new(), Vec::new());
            for ch in body.chars() {
                let (t, b) = match ch {
                    '█' => (true, true),
                    '▀' => (true, false),
                    '▄' => (false, true),
                    ' ' => (false, false),
                    other => panic!("unexpected glyph {other:?}"),
                };
                top.push(t);
                bottom.push(b);
            }
            rows.push(top);
            rows.push(bottom);
        }
        rows
    }

    #[test]
    fn the_terminal_draws_exactly_the_code_inside_a_quiet_zone() {
        let code = encode(DID).unwrap();
        let width = code.width();
        let colors = code.to_colors();
        let grid = drawn_grid(&terminal_lines(DID).unwrap());
        let side = width + 2 * QUIET_ZONE;

        for (y, row) in grid.iter().enumerate().take(side) {
            assert_eq!(row.len(), side, "row {y} width");
            for (x, &drawn) in row.iter().enumerate() {
                let inside = (QUIET_ZONE..QUIET_ZONE + width).contains(&x)
                    && (QUIET_ZONE..QUIET_ZONE + width).contains(&y);
                let want =
                    inside && colors[(y - QUIET_ZONE) * width + (x - QUIET_ZONE)] == Color::Dark;
                assert_eq!(drawn, want, "module ({x}, {y})");
            }
        }
        // An odd side leaves the last half-row as margin.
        assert!(grid.iter().skip(side).all(|row| row.iter().all(|d| !d)));
    }

    #[test]
    fn a_did_webvh_is_a_version_5_code() {
        assert_eq!(encode(DID).unwrap().width(), 37);
        // (37 + 2 * 4) modules, two rows per line, rounded up.
        assert_eq!(terminal_lines(DID).unwrap().len(), 23);
    }

    #[test]
    fn the_svg_is_standalone_and_scalable() {
        let svg = svg(DID).unwrap();
        assert!(svg.contains("<svg") && svg.contains("viewBox"), "{svg}");
        assert!(!svg.contains("<script"));
    }
}
