pub mod commands;
// Reading and atomically saving a CLI's TOML profile (#2582).
pub mod config_file;
// One confirmation rule for irreversible commands (#2583).
pub mod confirm;
// Waiting out a `requireConsent` gate. Shared with the offline `vta` binary so
// both CLIs answer an approval question the same way.
pub mod consent;
// Answering a consent request as an approver — `pnm consent` and `cnm consent`.
pub mod consent_approve;
// Terminal rendering for DIDs + their display names. The CLI layer over
// `vta_sdk::display_name`.
pub mod display;
pub mod duration;
// Exit codes shared by both CLIs (#2587).
pub mod exit;
pub mod local_keygen;
// A DID as a QR code, for the terminal or an SVG file (`pnm vta qr`).
pub mod qr;
pub mod render;
pub mod sealed_consumer;
pub mod sealed_producer;
// Secrets from a file, stdin, an environment variable or a no-echo prompt —
// never argv (#2584, #2585).
pub mod secret_input;
pub mod secure_file;
// The start-up block both CLIs share: format, colour, banner (#2587).
pub mod startup;
