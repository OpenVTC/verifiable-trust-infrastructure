# vta-keyspaces

The VTA's keyspace-name registry — a dependency-free leaf crate holding the
`const` names every `store.keyspace(..)` call uses, plus the backup partition
(`ALL` / `BACKED_UP` / `EXCLUDED_FROM_BACKUP`).

It exists so that the VTA's subsystem crates (`vta-vault`, `vta-webvh`, …) can
name keyspaces without depending on `vta-service`. Names live here; per-keyspace
key formats do not.

`vta-service` re-exports this crate as `crate::keyspaces` and keeps the
`no_bare_keyspace_literals` guard that forbids bare `.keyspace("…")` literals in
its own source.

Part of the [Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace. Apache-2.0.
