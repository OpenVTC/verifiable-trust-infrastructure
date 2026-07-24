//! The VTA's keyspace-name registry.
//!
//! The names themselves live in the dependency-free [`vta_keyspaces`] leaf crate
//! so that the VTA subsystem crates (`vta-vault`, …) can name keyspaces without
//! depending on `vta-service`. They are re-exported here unchanged, so every
//! existing `crate::keyspaces::NAME` reference keeps resolving.
//!
//! What stays local to `vta-service`:
//! - the `#[cfg(test)]` test-only keyspace names used by this crate's tests, and
//! - the [`tests::no_bare_keyspace_literals`] guard, which must scan
//!   **this crate's** source tree and so cannot move to the leaf crate.

pub use vta_keyspaces::*;

#[cfg(test)]
mod tests {
    /// Guard (the "CI grep"): no bare `.keyspace("literal")` anywhere in the
    /// crate source except this registry. New code must name keyspaces through
    /// a `crate::keyspaces::*` const (re-exported from [`vta_keyspaces`]).
    #[test]
    fn no_bare_keyspace_literals() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        visit(&src, &mut |path, content| {
            if path.file_name().and_then(|n| n.to_str()) == Some("keyspaces.rs") {
                return;
            }
            for (lineno, line) in content.lines().enumerate() {
                if line.contains(".keyspace(\"") {
                    offenders.push(format!(
                        "{}:{}: {}",
                        path.display(),
                        lineno + 1,
                        line.trim()
                    ));
                }
            }
        });
        assert!(
            offenders.is_empty(),
            "bare keyspace string literal(s) found — use a crate::keyspaces::* const:\n{}",
            offenders.join("\n")
        );
    }

    fn visit(dir: &std::path::Path, f: &mut dyn FnMut(&std::path::Path, &str)) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                visit(&path, f);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs")
                && let Ok(content) = std::fs::read_to_string(&path)
            {
                f(&path, &content);
            }
        }
    }
}
