### vta-config 0.3.3 / vta-service 0.14.37 — configurable unauth rate limit (#936)

`[server]` gains `rate_limit_interval_secs` and `rate_limit_burst`, previously
the hardcoded `UNAUTH_RPS` / `UNAUTH_BURST`. Defaults are unchanged (5 / 10),
so an existing config behaves exactly as before.

Note the units: `rate_limit_interval_secs` is **seconds per token**, not
requests per second — the underlying `tower_governor` `per_second(n)` sets a
replenishment *interval*, so lower is more permissive. The old `UNAUTH_RPS`
name said the opposite of what the value did. A local-dev VTA that fires a
bootstrap flow in a burst wants `rate_limit_interval_secs = 1` with a larger
`rate_limit_burst`, not a larger interval.

A `0` in either field is clamped to 1 rather than panicking the REST thread —
`GovernorConfigBuilder::finish()` returns `None` on a zero period or burst, and
the limiter has no "off" setting to express.
