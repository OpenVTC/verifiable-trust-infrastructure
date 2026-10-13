//! `keys/sign-csr/0.1` — a PKCS#10 certificate signing request for a VTA-held
//! key, so a certificate authority can certify a key that never leaves the VTA
//! (an EUDI relying-party access certificate).
//!
//! The wire types are the generated ones. The VTA builds the request from the
//! structured subject and the key's own public key, and signs its
//! `CertificationRequestInfo`; nothing else the producer sends reaches it.

pub use trust_tasks_rs::specs::keys::sign_csr::v0_1::{
    Payload as SignCsrPayload, PayloadSubjectAltNames as SignCsrSubjectAltNames,
    RdnAttribute as SignCsrRdnAttribute, RdnAttributeType as SignCsrRdnType,
    Response as SignCsrResponse, error_codes,
};
