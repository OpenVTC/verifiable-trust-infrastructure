//! Generates `$OUT_DIR/trust_tasks_generated.rs` from `trust-tasks.lock` and
//! the bundles vendored under `trust-tasks/`, after checking each bundle
//! against the digest the lock pins. Never touches the network.
//!
//! `.index(true)` also generates `schema_index` over exactly the locked
//! versions; `vti-specs` merges this crate's `INDEX` with its siblings'.
fn main() -> Result<(), trust_tasks_build::Error> {
    trust_tasks_build::Config::new().index(true).compile()?;
    Ok(())
}
