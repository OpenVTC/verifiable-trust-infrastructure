pub mod commands;
// Waiting out a `requireConsent` gate. Shared with the offline `vta` binary so
// both CLIs answer an approval question the same way.
pub mod consent;
// Answering a consent request as an approver — `pnm consent` and `cnm consent`.
pub mod consent_approve;
// Terminal rendering for DIDs + their display names. The CLI layer over
// `vta_sdk::display_name`.
pub mod display;
pub mod duration;
pub mod local_keygen;
// A DID as a QR code, for the terminal or an SVG file (`pnm vta qr`).
pub mod qr;
pub mod render;
pub mod sealed_consumer;
pub mod sealed_producer;
pub mod secure_file;
