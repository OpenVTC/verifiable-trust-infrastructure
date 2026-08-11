### vta-config / vta-service — configurable unauth rate limit (#935)

`[server]` gains `rate_limit_rps` and `rate_limit_burst` fields (defaults:
5 / 10, matching the previous hardcoded values). `per_second(n)` sets the
token replenishment interval — lower = more permissive. Set `rate_limit_rps
= 1` and `rate_limit_burst = 100` for local dev to avoid 429s during
bootstrap flows. Zero values are clamped to 1 (no panic on misconfiguration).
