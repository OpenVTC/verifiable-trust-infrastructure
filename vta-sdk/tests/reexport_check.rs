//! Compile-only proof that both discovery entry points live at the same path.
//! `resolve_vta_with_resolver` was added in #813 but omitted from
//! `provision_client`'s re-export list, so it was reachable only through
//! `provision_client::resolve::`. This fails to compile if that regresses.
#[allow(unused_imports)]
use vta_sdk::provision_client::{resolve_vta, resolve_vta_with_resolver};

#[test]
fn both_entry_points_are_exported_from_provision_client() {}
