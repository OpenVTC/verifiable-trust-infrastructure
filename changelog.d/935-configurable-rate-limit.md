### vta-config 0.3.3 / vta-service 0.14.35 — configurable unauth rate limit (#935)

`[server]` gains `rate_limit_interval_secs` and `rate_limit_burst` fields
(defaults: 5 / 10, matching the previous hardcoded values).
`per_second(n)` sets the token replenishment interval — lower = more
permissive. Set `rate_limit_interval_secs = 1` and `rate_limit_burst = 100`
for local dev to avoid 429s during bootstrap flows. Zero values are clamped
to 1 (no panic on misconfiguration). The old name `rate_limit_rps` is
accepted as a serde alias for backwards compatibility.
