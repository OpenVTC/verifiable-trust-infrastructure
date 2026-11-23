//! UniFFI copies doc comments into the generated Swift and Kotlin bindings,
//! where they become block comments. Swift nests block comments, so a `/*` in
//! a doc comment (for example a task family written as `vta/pcs/*`) opens a
//! comment that never closes and the generated `VtaMobileCore.swift` does not
//! compile. Write a task family as `vta/pcs/<task>` instead.

use std::fs;
use std::path::Path;

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(dir).expect("read source directory") {
        let path = entry.expect("read directory entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_doc_comment_opens_or_closes_a_block_comment() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files.sort();

    let mut offending = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).expect("read source file");
        for (number, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            let is_doc = trimmed.starts_with("///") || trimmed.starts_with("//!");
            if is_doc && (trimmed.contains("/*") || trimmed.contains("*/")) {
                offending.push(format!(
                    "{}:{}: {}",
                    file.strip_prefix(&src).unwrap_or(file).display(),
                    number + 1,
                    trimmed
                ));
            }
        }
    }

    assert!(
        offending.is_empty(),
        "doc comments must not contain `/*` or `*/` (it breaks the generated \
         Swift bindings; write `vta/pcs/<task>`, not `vta/pcs/*`):\n{}",
        offending.join("\n")
    );
}
