//! Census: every `#[utoipa::path]` must declare the response body its handler
//! actually returns.
//!
//! ## Why this exists
//!
//! The OpenAPI document is assembled from the same route wiring the service
//! serves, so its *paths* cannot drift. Its **response bodies** can: those come
//! from a hand-written `body = T` in each `responses(...)` list, and nothing
//! compared that `T` against the handler's `Json<T>`. Four had drifted by the
//! time this census was written, all the same way — a PR added a response
//! envelope, moved the handler, and left the annotation describing the bare row:
//!
//! - `backup/export` said `BackupEnvelope`, returned `ExportResponse` (#1082)
//! - `members/removed` said `[RemovedMember]`, returned
//!   `RemovedMembersResponse` (#1082)
//! - `endorsement-types/register` said `EndorsementType`, returned
//!   `RegisterResponse` (#1092)
//! - `audit/list` said `Object` for a response that has been typed all along
//!
//! A wrong `body =` is not a documentation nit. `admin-ui`'s wire types are
//! generated from this document (`admin-ui/src/lib/wire.ts`), so an annotation
//! that names the pre-envelope type generates a console that reads the
//! pre-envelope shape — which is exactly the class of defect #1186 fixed by
//! hand across six endpoints, arriving by a new route.
//!
//! ## Why a name comparison is enough
//!
//! The *members* of each schema are derived by `ToSchema`, not written out, so
//! a field cannot drift from its struct. The only thing a human writes is the
//! type's name. Checking the name therefore checks the whole schema, which is
//! why this census is a source scan and not a response-body validator.
//!
//! ## Why source text
//!
//! `#[utoipa::path]` is consumed at compile time into a document that no longer
//! records which Rust type produced a schema, and a handler's return type is not
//! reflected at runtime at all. Neither side of the comparison survives into
//! anything this test could query, so both are read as text — the same
//! technique, for the same reason, as `trust_task_manifest.rs`. A false positive
//! here is a visible string in a failure message, not a silent pass.

use std::path::{Path, PathBuf};

/// Handlers whose actual return type cannot carry a `ToSchema`, so the document
/// names the payload it wraps instead of the wrapper.
///
/// **This list may only shrink**, and an entry needs a reason that is about the
/// *type*, not about the effort of fixing it. "The annotation is out of date" is
/// never a reason to add a line here — that is the defect this census exists to
/// catch, and the fix is one word in the annotation.
const UNTYPED_OK: &[(&str, &str)] = &[(
    "relationships.rs::publish",
    "returns `trust_tasks_rs::TrustTask<PublishResponse>`. The Trust Task \
     envelope is an external type with no `ToSchema`, so the document names the \
     payload it wraps. Typing it properly means declaring a local mirror of the \
     envelope — a hand-maintained copy of someone else's wire type, which is \
     the failure mode this census exists to prevent, not a fix for it.",
)];

/// The size of [`UNTYPED_OK`], asserted so the list cannot grow quietly.
const UNTYPED_OK_COUNT: usize = 1;

#[test]
fn every_documented_response_names_the_type_its_handler_returns() {
    let mut mismatches = Vec::new();
    let mut matched_exceptions = Vec::new();

    for file in route_sources() {
        let src = std::fs::read_to_string(&file).expect("route source is readable");
        let name = file
            .strip_prefix(routes_dir())
            .unwrap_or(&file)
            .to_string_lossy()
            .into_owned();

        for h in handlers(&src) {
            let Some(actual) = h.returns_json else {
                continue;
            };
            let key = format!("{name}::{}", h.func);

            if h.declared.iter().any(|d| same_type(d, &actual)) {
                continue;
            }
            if UNTYPED_OK.iter().any(|(k, _)| *k == key) {
                matched_exceptions.push(key);
                continue;
            }
            let declared = if h.declared.is_empty() {
                "(no `body =` on any success response)".to_string()
            } else {
                h.declared.join(" | ")
            };
            mismatches.push(format!(
                "  {key}\n      declares: {declared}\n      returns:  Json<{actual}>"
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "{} handler(s) document a response body their handler does not return.\n\n{}\n\n\
         The OpenAPI document is what generates `admin-ui/src/lib/wire.ts`, so a wrong \
         `body =` ships a console that reads the wrong shape — silently, because the \
         generated types will typecheck against themselves. Point the annotation at the \
         type the handler returns. If that type genuinely cannot derive `ToSchema`, add it \
         to UNTYPED_OK with a reason about the type.",
        mismatches.len(),
        mismatches.join("\n")
    );

    // An exception that no longer matches anything is a stale line, and a stale
    // line in a table like this is how the table stops being read.
    let stale: Vec<_> = UNTYPED_OK
        .iter()
        .map(|(k, _)| *k)
        .filter(|k| !matched_exceptions.contains(&k.to_string()))
        .collect();
    assert!(
        stale.is_empty(),
        "UNTYPED_OK names handler(s) that no longer mismatch: {stale:?}. \
         Delete the entries and lower UNTYPED_OK_COUNT — an exception kept past \
         the thing it excused is indistinguishable from one nobody checked."
    );
}

/// The exception list may only shrink.
///
/// Same discipline, and same reason, as `ALLOWED_COUNT` in
/// `test_support::response_conformance` and `KNOWN_DRIFT_COUNT` in
/// `trust_tasks::conformance`: the cheapest way to make a census pass is to add
/// a line to a table nobody is watching.
#[test]
fn the_untyped_exception_list_only_shrinks() {
    assert_eq!(
        UNTYPED_OK.len(),
        UNTYPED_OK_COUNT,
        "the UNTYPED_OK list changed. Removing an entry? Lower UNTYPED_OK_COUNT \
         with it. Adding one? A handler whose documented response body is not the \
         one it returns is a defect; this list is for types that cannot carry a \
         `ToSchema`, not for annotations that are merely out of date."
    );
}

// ---------------------------------------------------------------------------
// Source scanning
// ---------------------------------------------------------------------------

fn routes_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/routes")
}

/// Every `.rs` file under `src/routes`, sorted so failures list in a stable
/// order across runs and platforms.
fn route_sources() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![routes_dir()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("routes dir is readable") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

struct Handler {
    func: String,
    /// Types named by `body =` on a 2xx response.
    declared: Vec<String>,
    /// The `T` in the handler's `Json<T>`, if it returns one at all.
    returns_json: Option<String>,
}

/// Pull every `#[utoipa::path(…)]`-annotated handler out of one source file.
fn handlers(src: &str) -> Vec<Handler> {
    const ATTR: &str = "#[utoipa::path(";
    let mut out = Vec::new();
    let mut at = 0;

    while let Some(found) = src[at..].find(ATTR) {
        let attr_start = at + found + ATTR.len() - 1; // at the '('
        let Some(attr_end) = balanced(src, attr_start, '(', ')') else {
            break;
        };
        let attr = &src[attr_start..=attr_end];

        // The annotation sits directly on the handler, so the next `fn` is it.
        let rest = &src[attr_end..];
        let Some(fn_kw) = rest.find(" fn ") else {
            break;
        };
        let after_fn = attr_end + fn_kw + " fn ".len();
        let func: String = src[after_fn..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();

        // Arguments, then the return type up to the body's opening brace.
        let args_start = after_fn + func.len();
        let Some(paren) = src[args_start..].find('(').map(|i| args_start + i) else {
            break;
        };
        let Some(args_end) = balanced(src, paren, '(', ')') else {
            break;
        };
        let ret = src[args_end + 1..]
            .split_once('{')
            .map(|(r, _)| r)
            .unwrap_or("");

        out.push(Handler {
            func,
            declared: declared_bodies(attr),
            returns_json: json_payload(ret),
        });
        at = args_end;
    }
    out
}

/// The types named by `body =` on success responses.
///
/// Error responses are skipped: a 4xx documents a framework error document, not
/// the handler's payload, and comparing one against the success return type
/// would report every route with a documented failure.
fn declared_bodies(attr: &str) -> Vec<String> {
    let mut out = Vec::new();
    for entry in attr.split("(status =").skip(1) {
        let status: String = entry.trim_start().chars().take(3).collect();
        if !status.starts_with('2') {
            continue;
        }
        let Some(body) = entry.split_once("body =") else {
            continue;
        };
        let ty: String = body
            .1
            .trim_start()
            .chars()
            .take_while(|c| !matches!(c, ',' | ')'))
            .collect();
        out.push(ty.trim().to_string());
    }
    out
}

/// The `T` in the first `Json<T>` of a return type, if there is one.
///
/// Handlers returning `impl IntoResponse` or a raw `Response` have no typed
/// payload to compare and yield `None`.
fn json_payload(ret: &str) -> Option<String> {
    let at = ret.find("Json<")?;
    let open = at + "Json<".len() - 1;
    let close = balanced(ret, open, '<', '>')?;
    Some(ret[open + 1..close].trim().to_string())
}

/// Index of the delimiter closing the one at `from`, honouring nesting.
fn balanced(s: &str, from: usize, open: char, close: char) -> Option<usize> {
    let mut depth = 0usize;
    for (i, c) in s.char_indices().skip_while(|(i, _)| *i < from) {
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

/// Do a declared and an actual type name refer to the same schema?
///
/// Normalises the three ways the two sides legitimately differ in spelling:
/// utoipa's `[T]` array sugar against Rust's `Vec<T>`, module qualification on
/// either side, and whitespace inside generics.
fn same_type(declared: &str, actual: &str) -> bool {
    normalise(declared) == normalise(actual)
}

fn normalise(ty: &str) -> String {
    let ty: String = ty.chars().filter(|c| !c.is_whitespace()).collect();
    // `[T]` is how utoipa spells an array; the handler spells it `Vec<T>`.
    let ty = match ty.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        Some(inner) => format!("Vec<{inner}>"),
        None => ty,
    };
    // Drop module qualification: `crate::foo::Bar` and `Bar` are one schema.
    let mut out = String::with_capacity(ty.len());
    let mut segment = String::new();
    for c in ty.chars() {
        if c.is_alphanumeric() || c == '_' || c == ':' {
            segment.push(c);
        } else {
            out.push_str(strip_path(&segment));
            segment.clear();
            out.push(c);
        }
    }
    out.push_str(strip_path(&segment));
    out
}

fn strip_path(segment: &str) -> &str {
    segment.rsplit("::").next().unwrap_or(segment)
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn array_sugar_and_module_paths_are_not_mismatches() {
        assert!(same_type("[RemovedMember]", "Vec<RemovedMember>"));
        assert!(same_type(
            "Vec<SchemaEntry>",
            "Vec<crate::routes::SchemaEntry>"
        ));
        assert!(same_type(
            "Paginated<MemberResponse>",
            "Paginated< MemberResponse >"
        ));
    }

    #[test]
    fn a_real_envelope_drift_is_a_mismatch() {
        // The live #1082 defect this census was written to catch.
        assert!(!same_type("[RemovedMember]", "RemovedMembersResponse"));
        assert!(!same_type("BackupEnvelope", "ExportResponse"));
    }

    #[test]
    fn a_handler_returning_no_json_is_skipped() {
        assert_eq!(json_payload(" -> impl IntoResponse "), None);
        assert_eq!(
            json_payload(" -> Result<(StatusCode, Json<Foo>), AppError> ").as_deref(),
            Some("Foo")
        );
        assert_eq!(
            json_payload(" -> Result<Json<Paginated<Bar>>, AppError> ").as_deref(),
            Some("Paginated<Bar>")
        );
    }

    #[test]
    fn only_success_responses_are_compared() {
        let attr = "(\n get, path = \"/x\",\n responses(\n \
                    (status = 200, description = \"ok\", body = Good),\n \
                    (status = 404, description = \"nope\", body = ErrorDoc),\n ),\n)";
        assert_eq!(declared_bodies(attr), vec!["Good".to_string()]);
    }
}
