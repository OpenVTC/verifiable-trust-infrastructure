//! DIDComm pack / unpack — wraps the `affinidi-tdk` DIDComm stack.
//!
//! **Slice 3.**
//!
//! Planned surface (pure functions; the transport is native):
//! - `unpack(jwe_bytes, recipient_key_handle) -> PlaintextMessage`
//! - `pack_authcrypt(message, sender_handle, recipient_did) -> JweBytes`
//! - `wrap_forward(jwe, mediator_did) -> JweBytes`
//!
//! The native layer owns the WebSocket to the mediator and hands raw envelope
//! bytes here for decryption / encryption.
