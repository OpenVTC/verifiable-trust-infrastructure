//! `keys/sign-jws/0.1` — a compact JWS (an OpenID4VP request object, a
//! proof-of-possession JWT) made by a VTA-held key that never leaves the VTA.
//!
//! The wire types are the generated ones. The VTA writes `alg` from the key and
//! builds the signing input itself (RFC 8785 header and payload); a producer
//! uses the returned `jws` as it is, since the JSON inside it is not
//! byte-for-byte what was sent.

pub use trust_tasks_rs::specs::keys::sign_jws::v0_1::{
    Payload as SignJwsPayload, Response as SignJwsResponse, ResponseAlg as SignJwsAlg, error_codes,
};

/// Header members a producer may not send: the custodian sets `alg` itself, and
/// signs no `crit`, `b64`, `jwk`, `jku` or `x5u` (the specification's
/// *Forbidden header members*).
pub const FORBIDDEN_HEADER_MEMBERS: &[&str] = &["alg", "crit", "b64", "jwk", "jku", "x5u"];
