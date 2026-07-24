# vta-audit

Structured audit logging for security-relevant VTA operations, extracted from
`vta-service` so every subsystem can emit audit events without depending on the
whole service.

- **`audit!`** — a `#[macro_export]`ed macro that emits a structured event to
  the dedicated `audit` tracing target (`INFO` for success, `ERROR` for
  `denied:*` / failure outcomes).
- **`record` / `record_with_detail` / `record_consent` / `cleanup_expired_logs`**
  — persist audit entries to the `audit` fjall keyspace for API-based retrieval.

Depends only on `vti-common` and `vta-sdk`. `vta-service` re-exports it as
`crate::audit`, so existing `crate::audit::record` / `audit!(…)` call sites are
unchanged.

Part of the [Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace. Apache-2.0.
