//! External accounts: the VTA as the key authority for cloud and third-party
//! accounts.
//!
//! An integration keeps needing to authenticate to someone else — a VTC to an
//! S3 bucket, a VTC to Sui, an agent to a SaaS API — and the default answer
//! everywhere is a long-lived secret pasted into the integration's config. This
//! crate is the other answer: the VTA holds the account, and a bound
//! integration gets back only something short-lived and downscoped.
//!
//! The wire surface is the `external/*` Trust Task family (trust-tasks-tf
//! #740); the design is `docs/05-design-notes/vta-external-accounts.md`. This
//! crate holds what does not depend on the service spine:
//!
//! - [`model`] — the stored account and its bindings, and the projection onto
//!   the wire `ExternalAccount`.
//! - [`store`] — persistence in the `external_accounts` keyspace, plus the
//!   wrapped secrets in `external_secrets` (excluded from backup).
//! - [`scope`] — validation of requested scopes and the binding ceiling check,
//!   in the order the issue specification requires.
//! - [`driver`] — the [`ExternalAuthDriver`](driver::ExternalAuthDriver) trait
//!   and the registry of models this build serves.
//! - [`s3_presign`] — the `s3-static-presign` model: SigV4 query presigning.
//! - [`rate`] — the per-binding issuance rate.
//! - [`fingerprint`] — keyed fingerprints of stored secrets.
//!
//! Five rules, from the design note's threat model, hold throughout:
//!
//! 1. No long-lived bearer secret leaves the VTA. Consumers get credentials
//!    that expire in minutes, only inside a sealed-transfer bundle.
//! 2. Keys are pinned at the provider, never fetched from a host — so the VTA
//!    needs no inbound surface.
//! 3. The VTA builds what it signs.
//! 4. Least privilege at three layers: the provider's trust policy, the
//!    binding's ceiling, and each issuance's own scope.
//! 5. Changing an account needs other administrators (the approvals defaults).

pub mod driver;
pub mod fingerprint;
pub mod model;
pub mod rate;
pub mod s3_presign;
pub mod scope;
pub mod store;
