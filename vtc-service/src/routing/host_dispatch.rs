//! Subdomain-mode `Host` header check + per-surface isolation
//! (Phase 5 M5.1.2, hardened in P3.1).
//!
//! Tower middleware that inspects the request `Host` header against
//! the per-surface map declared in [`crate::config::RoutingConfig`].
//! Behaviour:
//!
//! - When **every** surface has `host = None` (pure path mode), the
//!   middleware is a no-op — the parent router does prefix matching
//!   alone.
//! - When **any** surface has a host set ("host mode"), the
//!   middleware:
//!   1. Reads `Host` from the request (HTTP/2 `:authority` is
//!      normalised onto the `Host` header by axum before the layer
//!      runs).
//!   2. Rejects a Host that matches no configured surface
//!      (case-insensitive) with 404 `HostNotRecognised` when
//!      `subdomain_mode_strict = true` (default). With strict off
//!      (debug aid), an unrecognised host falls through to plain
//!      path matching and surface isolation is **not** enforced.
//!   3. For a recognised host in strict mode, enforces **surface
//!      isolation**: the request path is routed to the surface whose
//!      mount it falls under (longest-prefix match — `/v1…`→api,
//!      `/admin…`→admin, else website), and the request passes only
//!      if *that* surface is the one bound to the request's host. So
//!      `admin.example.com/v1/acl` (api surface, bound to a different
//!      host) returns 404 `SurfaceNotOnHost` rather than serving the
//!      API. This is what actually isolates an operator-deployed
//!      website origin from the admin/API surface — the earlier
//!      version only checked allowlist membership and routed every
//!      path on every recognised host.
//!
//! Parent-root infrastructure routes (`/health`, `/openapi.json`,
//! `/.well-known/did.jsonl`) are mounted outside any surface and must
//! answer on every recognised host (the did:webvh log has to resolve
//! on the website host; liveness has to answer on the api host), so
//! they bypass the surface gate.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::Request;
use axum::http::{StatusCode, header::HOST};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::config::RoutingConfig;

/// Parent-root routes mounted outside any surface mount. They must
/// answer on every recognised host, so the surface gate skips them.
const INFRA_PATHS: &[&str] = &["/health", "/openapi.json", "/.well-known/did.jsonl"];

/// One routable surface: the mount prefix it attaches under and the
/// host it is bound to (`None` in path mode). `priority` breaks ties
/// when two surfaces share a mount length (e.g. admin at `/` next to
/// the website catch-all) — lower wins, matching the parent router's
/// api → admin → website nest precedence.
#[derive(Debug, Clone)]
struct Surface {
    mount: String,
    host: Option<String>,
    priority: u8,
}

impl Surface {
    /// Length of this surface's mount match against `path`, or `None`
    /// if it doesn't claim the path. The `/` catch-all matches every
    /// path but at the lowest specificity (length 1), so a concrete
    /// `/v1` / `/admin` mount always wins the longest-prefix race.
    fn match_len(&self, path: &str) -> Option<usize> {
        if self.mount == "/" {
            return Some(1);
        }
        // `/v1` matches `/v1` and `/v1/...`, but not `/v1abc`.
        if path == self.mount || path.starts_with(&format!("{}/", self.mount)) {
            Some(self.mount.len())
        } else {
            None
        }
    }
}

/// Compiled host/surface map. Cheap to clone, shared across requests
/// via `Arc`. Built once at router-assembly time.
#[derive(Debug, Clone)]
pub struct HostMap {
    /// Lower-cased configured hosts. Empty when every surface uses
    /// path mode — the layer short-circuits.
    hosts: Arc<HashSet<String>>,
    /// Per-surface mount + bound host, used for surface isolation.
    /// Hosts are stored lower-cased.
    surfaces: Arc<Vec<Surface>>,
    strict: bool,
}

impl HostMap {
    /// Compile the surface map from [`RoutingConfig`].
    pub fn from_routing(routing: &RoutingConfig) -> Self {
        let mut hosts = HashSet::new();
        let mut surfaces = Vec::with_capacity(3);
        // Priority order mirrors the parent router's nest precedence:
        // api, then admin_ui, then the website catch-all.
        for (priority, surface) in [&routing.api, &routing.admin_ui, &routing.website]
            .into_iter()
            .enumerate()
        {
            let host = surface.host.as_deref().map(str::to_ascii_lowercase);
            if let Some(h) = host.as_deref() {
                hosts.insert(h.to_string());
            }
            surfaces.push(Surface {
                mount: surface.mount.clone(),
                host,
                priority: priority as u8,
            });
        }
        Self {
            hosts: Arc::new(hosts),
            surfaces: Arc::new(surfaces),
            strict: routing.subdomain_mode_strict,
        }
    }

    /// True when no surface has a `host` set; the middleware is a
    /// no-op in that case.
    pub fn is_path_mode(&self) -> bool {
        self.hosts.is_empty()
    }

    /// True when the configured Host map recognises this header value
    /// (case-insensitive) as belonging to *some* surface. Returns
    /// `true` unconditionally in path mode so callers can use it as a
    /// single decision point.
    fn matches(&self, host_header: &str) -> bool {
        if self.is_path_mode() {
            return true;
        }
        self.hosts.contains(&host_header.to_ascii_lowercase())
    }

    /// The surface that owns `path` (longest mount prefix; ties broken
    /// toward the surface bound to `req_host`, else by `priority`).
    /// `req_host` is already lower-cased.
    fn target_surface(&self, path: &str, req_host: &str) -> Option<&Surface> {
        let best = self
            .surfaces
            .iter()
            .filter_map(|s| s.match_len(path).map(|len| (s, len)))
            .max_by(|(a, alen), (b, blen)| {
                // Longer mount wins; on a tie prefer the surface bound
                // to the request host, then lower priority.
                alen.cmp(blen)
                    .then_with(|| {
                        let a_owns = a.host.as_deref() == Some(req_host);
                        let b_owns = b.host.as_deref() == Some(req_host);
                        a_owns.cmp(&b_owns)
                    })
                    .then_with(|| b.priority.cmp(&a.priority))
            });
        best.map(|(s, _)| s)
    }

    /// Surface-isolation decision for a recognised host in strict
    /// mode. `req_host` is already lower-cased. Returns `true` when
    /// the path's owning surface is bound to this host (or to no host,
    /// i.e. a path-mode surface in a mixed config, which can't be
    /// isolated).
    fn surface_allowed(&self, path: &str, req_host: &str) -> bool {
        if INFRA_PATHS.contains(&path) {
            return true;
        }
        match self.target_surface(path, req_host) {
            Some(s) => match s.host.as_deref() {
                Some(h) => h == req_host,
                None => true,
            },
            // No surface claims the path — let the router 404 it.
            None => true,
        }
    }
}

/// Tower middleware function. Wire via
/// `axum::middleware::from_fn_with_state(host_map.clone(), enforce)`.
pub async fn enforce(
    axum::extract::State(map): axum::extract::State<HostMap>,
    request: Request,
    next: Next,
) -> Response {
    if map.is_path_mode() {
        return next.run(request).await;
    }

    let host = request
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Host-membership gate (unchanged): an unrecognised host is a 404
    // in strict mode, or falls through in the debug-only lax mode.
    let recognised = match host.as_deref() {
        Some(h) => map.matches(h),
        // Missing Host header — HTTP/1.1 requires it. Treat as
        // unrecognised in strict mode.
        None => false,
    };
    if !recognised {
        if map.strict {
            return not_recognised(host);
        }
        return next.run(request).await;
    }

    // Lax mode is a debug aid only — no surface isolation, just plain
    // path matching once the host is recognised.
    if !map.strict {
        return next.run(request).await;
    }

    // Surface-isolation gate: the path must belong to the surface
    // bound to this host.
    let req_host = host.as_deref().unwrap_or_default().to_ascii_lowercase();
    let path = request.uri().path();
    if map.surface_allowed(path, &req_host) {
        return next.run(request).await;
    }

    let body = json!({
        "error": "SurfaceNotOnHost",
        "host": host,
        "path": request.uri().path(),
    });
    (StatusCode::NOT_FOUND, axum::Json(body)).into_response()
}

/// 404 with the same JSON shape as `AppError::IntoResponse` for a
/// host that matches no configured surface.
fn not_recognised(host: Option<String>) -> Response {
    let body = json!({
        "error": "HostNotRecognised",
        "host": host,
    });
    (StatusCode::NOT_FOUND, axum::Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MountConfig;

    fn cfg(
        api_host: Option<&str>,
        admin_host: Option<&str>,
        web_host: Option<&str>,
    ) -> RoutingConfig {
        RoutingConfig {
            api: MountConfig {
                mount: "/v1".into(),
                host: api_host.map(String::from),
            },
            admin_ui: MountConfig {
                mount: "/admin".into(),
                host: admin_host.map(String::from),
            },
            website: MountConfig {
                mount: "/".into(),
                host: web_host.map(String::from),
            },
            subdomain_mode_strict: true,
        }
    }

    #[test]
    fn path_mode_when_no_hosts_set() {
        let map = HostMap::from_routing(&cfg(None, None, None));
        assert!(map.is_path_mode());
        // matches() returns true for anything in path mode.
        assert!(map.matches("anything.example.com"));
    }

    #[test]
    fn matches_recognises_configured_host() {
        let map = HostMap::from_routing(&cfg(
            Some("api.example.com"),
            Some("admin.example.com"),
            None,
        ));
        assert!(!map.is_path_mode());
        assert!(map.matches("api.example.com"));
        assert!(map.matches("ADMIN.example.com")); // case-insensitive
        assert!(!map.matches("other.example.com"));
    }

    #[test]
    fn surface_isolation_routes_path_to_its_own_host() {
        let map = HostMap::from_routing(&cfg(
            Some("api.example.com"),
            Some("admin.example.com"),
            Some("example.com"),
        ));

        // Each surface answers on its own host.
        assert!(map.surface_allowed("/v1/acl", "api.example.com"));
        assert!(map.surface_allowed("/admin/users", "admin.example.com"));
        assert!(map.surface_allowed("/index.html", "example.com"));

        // Cross-surface requests are rejected: the API surface is not
        // served on the admin or website host, and vice-versa.
        assert!(!map.surface_allowed("/v1/acl", "admin.example.com"));
        assert!(!map.surface_allowed("/v1/acl", "example.com"));
        assert!(!map.surface_allowed("/admin/users", "api.example.com"));
        // The website catch-all is not served on the api/admin hosts.
        assert!(!map.surface_allowed("/index.html", "api.example.com"));
    }

    #[test]
    fn infra_paths_answer_on_every_recognised_host() {
        let map = HostMap::from_routing(&cfg(
            Some("api.example.com"),
            Some("admin.example.com"),
            Some("example.com"),
        ));
        for host in ["api.example.com", "admin.example.com", "example.com"] {
            assert!(map.surface_allowed("/health", host), "host {host}");
            assert!(map.surface_allowed("/.well-known/did.jsonl", host));
            assert!(map.surface_allowed("/openapi.json", host));
        }
    }

    #[test]
    fn admin_at_root_in_host_mode_resolves_by_request_host() {
        // admin_ui mounted at `/` next to the website catch-all (also
        // `/`) — equal mount length. The tie breaks toward the surface
        // bound to the request host, so each host serves its own.
        let routing = RoutingConfig {
            api: MountConfig {
                mount: "/v1".into(),
                host: Some("api.example.com".into()),
            },
            admin_ui: MountConfig {
                mount: "/".into(),
                host: Some("admin.example.com".into()),
            },
            website: MountConfig {
                mount: "/".into(),
                host: Some("example.com".into()),
            },
            subdomain_mode_strict: true,
        };
        let map = HostMap::from_routing(&routing);
        assert!(map.surface_allowed("/dashboard", "admin.example.com"));
        assert!(map.surface_allowed("/dashboard", "example.com"));
        // API still isolated to its own host.
        assert!(!map.surface_allowed("/v1/acl", "example.com"));
    }
}
