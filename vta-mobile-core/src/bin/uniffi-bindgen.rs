//! Binding generator entry point.
//!
//! Generates the foreign-language bindings from the built library in
//! "library mode", e.g.:
//!
//! ```sh
//! cargo build -p vta-mobile-core            # produces target/debug/libvta_mobile_core.{dylib,so}
//! cargo run  -p vta-mobile-core --bin uniffi-bindgen -- \
//!     generate --library target/debug/libvta_mobile_core.dylib \
//!     --language kotlin --out-dir target/bindings/kotlin
//! ```
fn main() {
    uniffi::uniffi_bindgen_main()
}
