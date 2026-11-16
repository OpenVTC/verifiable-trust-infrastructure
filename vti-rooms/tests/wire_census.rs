//! Every serde type in `src/wire.rs` is held to the published schema (#2581).
//!
//! The types in `wire.rs` are hand-written on purpose (its header says why), and what makes
//! that safe is `schema_conformance.rs`, which validates what each serialises to against the
//! published schemas. That protection only covers the types it names. A type added to
//! `wire.rs` and forgotten there is exactly the drift — a `snake_case` member where the
//! schema says `camelCase` — that no round-trip test can see, because both ends of the round
//! trip are the same struct.
//!
//! So this reads both files as text: every `pub struct` in `wire.rs` that derives
//! `Serialize` or `Deserialize` must be named in `schema_conformance.rs`. A type that never
//! touches the wire (it derives neither, like `CreateRoomTerms`) is not a wire type and is
//! not counted.

use std::path::Path;

/// The serde `pub struct`s of `source`, by name.
fn serde_structs(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut derives_serde = false;
    for line in source.lines() {
        let line = line.trim();
        if line.starts_with("#[derive(") {
            derives_serde = line.contains("Serialize") || line.contains("Deserialize");
            continue;
        }
        if line.starts_with("#[") || line.starts_with("///") || line.starts_with("//") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("pub struct ")
            && derives_serde
        {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            out.push(name);
        }
        derives_serde = false;
    }
    out
}

/// Whether `name` appears in `text` as a whole identifier.
fn names(text: &str, name: &str) -> bool {
    text.match_indices(name).any(|(i, _)| {
        let before = text[..i].chars().next_back();
        let after = text[i + name.len()..].chars().next();
        let ident = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
        !ident(before) && !ident(after)
    })
}

#[test]
fn every_wire_type_is_in_the_schema_conformance_tests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let wire = std::fs::read_to_string(root.join("src/wire.rs")).expect("read src/wire.rs");
    let conformance = std::fs::read_to_string(root.join("tests/schema_conformance.rs"))
        .expect("read tests/schema_conformance.rs");

    let types = serde_structs(&wire);
    assert!(
        types.len() >= 20,
        "the census found only {} serde types in wire.rs ({types:?}); the scan is broken",
        types.len()
    );
    let missing: Vec<&String> = types.iter().filter(|t| !names(&conformance, t)).collect();
    assert!(
        missing.is_empty(),
        "these wire types are not validated against the published schema in \
         tests/schema_conformance.rs: {missing:?}. Add a test that serialises each and \
         checks it with the generated type's `validate_value`."
    );
}

#[test]
fn the_scan_reads_derives_and_skips_the_rest() {
    let src = "#[derive(Debug, Serialize)]\n#[serde(rename_all = \"camelCase\")]\n\
               pub struct A {\n}\n#[derive(Debug)]\npub struct B;\n/// doc\n\
               #[derive(Deserialize)]\npub struct C<T> {}\n";
    assert_eq!(serde_structs(src), ["A", "C"]);
    assert!(names("use A; B", "A"));
    assert!(!names("AB", "A"));
}
