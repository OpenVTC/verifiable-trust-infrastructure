//! DID resolution — wraps `affinidi-did-resolver-cache-sdk`.
//!
//! **Slice 3.**
//!
//! Planned surface:
//! - `resolve_did(did) -> DidDocumentJson`
//! - `key_agreement_key(did) -> Multikey`   (for authcrypt to the VTA)
//!
//! Backed by the caching resolver so repeated lookups (every inbound message)
//! stay cheap; the native layer may seed an offline cache for known DIDs.
