pub mod commands;
// Waiting out a `requireConsent` gate. Shared with the offline `vta` binary so
// both CLIs answer an approval question the same way.
pub mod consent;
// Terminal rendering for DIDs + their display names. The CLI layer over
// `vta_sdk::display_name`.
pub mod display;
pub mod duration;
pub mod local_keygen;
pub mod render;
pub mod sealed_consumer;
pub mod sealed_producer;
pub mod secure_file;
