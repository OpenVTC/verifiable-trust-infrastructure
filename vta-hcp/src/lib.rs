//! The VTA's Human Context Protocol (HCP) provider.
//!
//! HCP lives in the VTA, as this subsystem crate behind `vta-service`'s `hcp`
//! cargo feature, off by default; its wire types come from `vti-specs-hcp`
//! (`docs/05-design-notes/hcp.md`, §3 and §11 decision 1). The VTA is the HCP
//! Provider and Authorization Service: it holds the grants, the token hashes,
//! the revocation tombstones, the held `hcp/grants/request`s, the entries,
//! the directives and the notice schedule, under the `hcp_*` keyspaces
//! `vta-keyspaces` names (§10).
//!
//! Empty for now: the skeleton (task X0b of
//! `docs/05-design-notes/hcp-tasks.md`). The provider trait, its context and
//! error types arrive with task A2.
//!
//! Like every subsystem crate it must not depend on `vta-service`, which
//! depends on it; it reaches storage, audit and key custody through the crates
//! below the spine.
