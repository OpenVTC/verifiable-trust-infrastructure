//! #2588: every read handler answers in JSON.
//!
//! Both CLIs switch to JSON under `--json` and whenever stdout is not a
//! terminal (`crate::startup`), so a read that prints only prose hands a
//! script a table where it asked for an object. This census holds every
//! `cmd_*` handler whose name says it reads (`get`, `list`, `show`, `seeds`,
//! `status`, `history`, `explain`, `report`, …) to a JSON path: it checks
//! `is_json_output` itself, prints JSON through one of the modules' helpers,
//! or is named below with the reason it needs neither.

/// Handlers exempt from the census, each with why.
const EXEMPT: &[(&str, &str, &str)] = &[
    (
        "did_templates.rs",
        "cmd_show",
        "prints the template (or its rendering) as JSON on every destination",
    ),
    (
        "did_templates.rs",
        "cmd_export",
        "prints the portable template JSON on every destination",
    ),
    (
        "rooms.rs",
        "cmd_rooms_file_get",
        "writes the file's bytes, not a description of them",
    ),
    (
        "rooms_custody.rs",
        "cmd_rooms_keys_list",
        "delegates to cmd_rooms_keys_list_named, which is held here",
    ),
];

/// What counts as a JSON path in a handler's body.
const JSON_MARKERS: &[&str] = &[
    "is_json_output",
    "print_json",
    // The modules' own JSON-aware printers.
    "print_result(",
    "show(&",
    // `elections::cmd_show` delegates to the presenting variant.
    "_presenting(",
];

const READ_WORDS: &[&str] = &[
    "get", "list", "show", "seeds", "info", "status", "view", "history", "export", "explain",
    "report",
];

fn handlers(src: &str) -> Vec<(String, String)> {
    let src = src.split("#[cfg(test)]").next().unwrap_or(src);
    let mut starts: Vec<(usize, String)> = Vec::new();
    for prefix in ["pub async fn cmd_", "pub fn cmd_"] {
        let mut from = 0;
        while let Some(i) = src[from..].find(prefix) {
            let at = from + i;
            // Only a definition at the start of a line.
            if at == 0 || src.as_bytes()[at - 1] == b'\n' {
                let name_start = at + prefix.len() - "cmd_".len();
                let name: String = src[name_start..]
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                starts.push((at, name));
            }
            from = at + prefix.len();
        }
    }
    starts.sort();
    let mut out = Vec::new();
    for (i, (at, name)) in starts.iter().enumerate() {
        let end = starts.get(i + 1).map(|(e, _)| *e).unwrap_or(src.len());
        out.push((name.clone(), src[*at..end].to_string()));
    }
    out
}

#[test]
fn every_read_handler_has_a_json_path() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands");
    let mut missing = Vec::new();
    let mut seen = 0;
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("src/commands")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    files.sort();
    for path in files {
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        let src = std::fs::read_to_string(&path).expect("read");
        for (name, body) in handlers(&src) {
            let words: Vec<&str> = name.split('_').collect();
            if !READ_WORDS.iter().any(|w| words.contains(w)) {
                continue;
            }
            seen += 1;
            if EXEMPT.iter().any(|(f, n, _)| *f == file && *n == name) {
                continue;
            }
            if !JSON_MARKERS.iter().any(|m| body.contains(m)) {
                missing.push(format!("{file}::{name}"));
            }
        }
    }
    assert!(seen > 40, "the census found only {seen} read handlers");
    assert!(
        missing.is_empty(),
        "read handlers with no JSON output (#2588) — give each an `is_json_output` branch \
         printing the SDK response, or list it in EXEMPT with the reason:\n  {}",
        missing.join("\n  ")
    );
}

#[test]
fn every_exemption_names_a_live_handler() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands");
    for (file, name, why) in EXEMPT {
        let src = std::fs::read_to_string(dir.join(file)).expect("exempt file exists");
        assert!(
            handlers(&src).iter().any(|(n, _)| n == name),
            "{file}::{name} is exempt ({why}) but no longer exists"
        );
    }
}
