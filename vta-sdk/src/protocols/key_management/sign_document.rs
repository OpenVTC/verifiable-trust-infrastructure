//! `keys/sign-document/0.1` — an `eddsa-jcs-2022` Data Integrity proof over a
//! JSON document, made by a VTA-held key that never leaves the VTA, and only
//! as the DID the document names in `issuer` or `controller`.
//!
//! The wire types are the generated ones. The document is carried whole as an
//! open object: the proof covers every member the producer sent, so a producer
//! uses the returned `document` exactly as it is.

pub use trust_tasks_rs::specs::keys::sign_document::v0_1::{
    Payload as SignDocumentPayload, Response as SignDocumentResponse, error_codes,
};
