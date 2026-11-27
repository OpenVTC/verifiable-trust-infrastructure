# vta-hcp

The Verifiable Trust Agent's Human Context Protocol (HCP) provider: the VTA as
HCP Provider and Authorization Service, holding the person's grants, token
hashes, revocation tombstones, held grant requests, entries, directives and
notices.

A subsystem crate behind `vta-service`'s `hcp` cargo feature, off by default.
Its wire types come from `vti-specs-hcp`. It does not depend on `vta-service`.
The design is `docs/05-design-notes/hcp.md` in the workspace.

Empty for now: the crate is a skeleton the HCP work fills in.

Part of the [Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace. Apache-2.0.
