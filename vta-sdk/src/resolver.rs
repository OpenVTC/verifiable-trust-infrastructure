//! DID-cache configuration helper.
//!
//! Mirrors the toggle `vta-service` exposes via `config.resolver_url`:
//! when a WebSocket URL is supplied, the SDK dispatches every DID
//! resolution to an external `affinidi-did-resolver-cache-server`
//! (typically running alongside the VTA). When `None`, the SDK
//! resolves in-process and caches results in memory.
//!
//! ## Why the env-var path exists
//!
//! `pnm-cli` calls into SDK functions that construct their own
//! `DIDCacheClient` (`session::resolve_vta_endpoint`,
//! `session::resolve_vta_url`, `session::resolve_mediator_did`). Those
//! signatures don't take a config, so threading `PnmConfig.resolver_url`
//! through every call site would mean breaking the SDK's public API for
//! every consumer. Instead, PNM exports its setting as
//! `PNM_RESOLVER_URL` at startup, and the SDK helper picks it up —
//! a single config setting propagates to every resolver construction
//! without surface changes.
//!
//! `vta-service` / `vtc-service` ignore the env var and build their
//! resolver explicitly from their own config (`server.rs` calls
//! `with_network_mode(url)` directly), so PNM's setting does not leak
//! into long-running daemons that have their own opinion.
//!
//! ## One resolver per process, not one per call
//!
//! Those entry points used to build a fresh `DIDCacheClient` on every call.
//! A fresh client has an empty cache, so a single CLI command resolved the
//! VTA's DID from scratch several times — endpoint discovery, the mediator
//! lookup, reply-proof verification — each an HTTP fetch of `did.jsonl` from
//! the same address as the authentication calls that followed. A VTA that
//! hosts its own log serves those fetches on its unauthenticated routes, under
//! the same per-IP rate limiter as `/auth/*`, so the CLI spent the operator's
//! budget before it authenticated. They now resolve through
//! [`shared_did_resolver`], whose cache answers every repeat within its TTL.
//!
//! ## Host policy: which hosts a DID may be fetched from
//!
//! `affinidi-did-resolver-cache-sdk` 0.8.37 (`didwebvh-rs` 0.7) refuses
//! non-public hosts for **both** `did:web` and `did:webvh` by default.
//! `localhost`, `*.localhost`, `*.local`, `*.internal`, `home.arpa` and
//! single-label names are refused before any request is made, and on native
//! targets a name whose DNS answer contains a loopback, RFC 1918,
//! carrier-grade-NAT or link-local address is refused at connect time — so a
//! DID naming an internal host, or a public name whose A record points at
//! `169.254.169.254`, can no longer be used to make this process fetch from
//! the inside of its own network. The default client also refuses redirects
//! and ignores `HTTP(S)_PROXY`.
//!
//! That default is what production wants, and nothing here weakens it. Local
//! development is the case that needs an opt-out: `local-dev/*.toml` publish
//! `http://localhost:3000`, so the VTA's own DID is
//! `did:webvh:{SCID}:localhost%3A3000` and resolving it — which the readiness
//! gate, `vta status` and the `webvh` CLI all do — is refused until the
//! operator says loopback is expected.
//!
//! [`webvh_host_policy`] reads that decision from the switch this workspace
//! already has for the same question about VTA REST endpoints taken out of a
//! DID document: `VTA_ALLOW_PRIVATE_ENDPOINTS` (see
//! [`crate::http::ALLOW_PRIVATE_ENDPOINTS_ENV`]) and the
//! `--allow-private-endpoints` flag that sets it process-wide. One switch
//! rather than a second one, because it is one question: may this process
//! reach hosts that are not on the public internet? Note the cache SDK
//! applies the policy to `did:web` and `did:webvh` together — there is no way
//! to loosen one without the other — and that under `AllowPrivate` a
//! `localhost` DID is fetched over plain `http://`.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_did_resolver_cache_sdk::config::{DIDCacheConfig, DIDCacheConfigBuilder};
use affinidi_did_resolver_cache_sdk::network_resolvers::HostPolicy;

/// Whether this process may resolve DIDs whose host is loopback or otherwise
/// non-public.
///
/// `false` unless the operator opted in — see the module documentation. With
/// the `client` feature this is the same answer
/// [`crate::http::EndpointPolicy::process_default`] gives, so a binary that
/// passes `--allow-private-endpoints` gets both halves from one flag; without
/// it, the environment variable is read directly.
pub fn allow_private_did_hosts() -> bool {
    #[cfg(feature = "client")]
    {
        crate::http::EndpointPolicy::process_default().allow_private
    }
    #[cfg(not(feature = "client"))]
    {
        // Kept in step with `http::ALLOW_PRIVATE_ENDPOINTS_ENV`, which is not
        // compiled without the `client` feature. Same name, same truthy set.
        std::env::var("VTA_ALLOW_PRIVATE_ENDPOINTS")
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false)
    }
}

/// The [`HostPolicy`] every resolver this helper builds is configured with.
///
/// [`HostPolicy::PublicOnly`] — the secure default — unless
/// [`allow_private_did_hosts`] says the operator opted in.
pub fn webvh_host_policy() -> HostPolicy {
    if allow_private_did_hosts() {
        HostPolicy::AllowPrivate
    } else {
        HostPolicy::PublicOnly
    }
}

/// Build a `DIDCacheConfig` honouring an optional remote-resolver URL.
/// When `url` is `Some`, network-mode is enabled — every resolution is
/// dispatched to that WebSocket endpoint. When `None`, the SDK resolves
/// in-process with an in-memory cache.
///
/// The configured [`webvh_host_policy`] applies either way: in network mode a
/// failed dispatch falls back to resolving locally, so the policy is not
/// redundant just because a sidecar is configured.
pub fn build_did_cache_config(url: Option<&str>) -> DIDCacheConfig {
    let mut builder = DIDCacheConfigBuilder::default().with_host_policy(webvh_host_policy());
    if let Some(u) = url {
        builder = builder.with_network_mode(u);
    }
    builder.build()
}

/// Read `PNM_RESOLVER_URL` and build a `DIDCacheConfig` accordingly.
/// Empty string or unset means local mode.
pub fn build_did_cache_config_from_env() -> DIDCacheConfig {
    let url = std::env::var("PNM_RESOLVER_URL")
        .ok()
        .filter(|s| !s.is_empty());
    build_did_cache_config(url.as_deref())
}

// ── The process-shared resolver ─────────────────────────────────────────────

/// What a shared resolver is keyed on: the runtime it was built on, the
/// resolver sidecar it dispatches to, and the host policy it enforces.
///
/// The runtime is part of the key because a `DIDCacheClient` is not
/// runtime-neutral: in network mode it spawns a websocket task on the runtime
/// that built it, and pooled HTTP connections are driven by that runtime too. A
/// process that runs more than one runtime — every `#[tokio::test]` does, and
/// so does a binary that builds one per job — gets one resolver per runtime
/// rather than one that silently stops working when its runtime ends.
#[derive(Clone, PartialEq, Eq, Hash)]
struct SharedKey {
    runtime: tokio::runtime::Id,
    resolver_url: Option<String>,
    allow_private: bool,
}

struct SharedEntry {
    client: DIDCacheClient,
    /// Dead once the runtime that built `client` has shut down: the task
    /// holding the strong half is dropped with every other task on it.
    runtime_alive: std::sync::Weak<()>,
}

static SHARED_RESOLVERS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<SharedKey, SharedEntry>>,
> = std::sync::LazyLock::new(Default::default);

fn shared_resolvers()
-> std::sync::MutexGuard<'static, std::collections::HashMap<SharedKey, SharedEntry>> {
    // A panic while the lock is held leaves a map that is still consistent
    // (every mutation is a single insert or remove), so recover it rather than
    // turn every later resolution in the process into a panic.
    SHARED_RESOLVERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Drop entries whose runtime has shut down, stopping each client first.
fn prune_dead(map: &mut std::collections::HashMap<SharedKey, SharedEntry>) {
    map.retain(|_, entry| {
        let alive = entry.runtime_alive.strong_count() > 0;
        if !alive {
            entry.client.stop();
        }
        alive
    });
}

/// The resolver this process shares for `url`, built on first use.
///
/// Every SDK entry point that used to build a throwaway `DIDCacheClient` per
/// call — [`crate::session::resolve_vta_endpoint`],
/// [`crate::session::resolve_vta_url`],
/// [`crate::session::resolve_mediator_did`], `VtaClient::resolve_did`, reply
/// verification, agent-name lookup — resolves through this instead. A throwaway
/// client starts with an empty cache, so one CLI command resolved the VTA's DID
/// from scratch several times over, each an HTTP fetch from the same address as
/// the authentication calls that followed — against a VTA that hosts its own
/// log, on the same per-IP rate limiter. Sharing one client lets its cache
/// (300 s for `did:web` / `did:webvh`, successes only) answer every repeat.
///
/// Built with [`build_did_cache_config`], so the host policy is the one
/// [`webvh_host_policy`] reports at the time of the call; a change to that
/// opt-in, or a different `url`, gets its own client rather than a cache that
/// was filled under other rules.
///
/// # Lifetime
///
/// One client per (tokio runtime, `url`, host policy). A client whose runtime
/// has shut down is stopped and discarded the next time any shared resolver is
/// requested, and [`shutdown_shared_did_resolvers`] stops all of them — call it
/// from a long-lived embedder that wants the network-mode websocket closed
/// before its runtime ends. Outside a tokio runtime nothing can be shared, so an
/// unshared client is returned.
pub async fn shared_did_resolver(
    url: Option<&str>,
) -> Result<DIDCacheClient, affinidi_did_resolver_cache_sdk::errors::DIDCacheError> {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return DIDCacheClient::new(build_did_cache_config(url)).await;
    };
    let key = SharedKey {
        runtime: handle.id(),
        resolver_url: url.map(str::to_string),
        allow_private: allow_private_did_hosts(),
    };

    {
        let mut map = shared_resolvers();
        prune_dead(&mut map);
        if let Some(entry) = map.get(&key) {
            return Ok(entry.client.clone());
        }
    }

    // Built without the lock held: construction is async, and in network mode
    // it connects to the sidecar.
    let client = DIDCacheClient::new(build_did_cache_config(url)).await?;

    let mut map = shared_resolvers();
    if let Some(entry) = map.get(&key) {
        // Another caller on this runtime built one first. Keep theirs so every
        // caller shares one cache, and stop ours so its network task (if any)
        // does not outlive this call.
        client.stop();
        return Ok(entry.client.clone());
    }
    let sentinel = std::sync::Arc::new(());
    let runtime_alive = std::sync::Arc::downgrade(&sentinel);
    handle.spawn(async move {
        let _sentinel = sentinel;
        std::future::pending::<()>().await;
    });
    map.insert(
        key,
        SharedEntry {
            client: client.clone(),
            runtime_alive,
        },
    );
    Ok(client)
}

/// [`shared_did_resolver`] for the `PNM_RESOLVER_URL` setting — the shared
/// counterpart of [`build_did_cache_config_from_env`].
pub async fn shared_did_resolver_from_env()
-> Result<DIDCacheClient, affinidi_did_resolver_cache_sdk::errors::DIDCacheError> {
    let url = std::env::var("PNM_RESOLVER_URL")
        .ok()
        .filter(|s| !s.is_empty());
    shared_did_resolver(url.as_deref()).await
}

/// Stop and discard every shared resolver.
///
/// Stopping ends a network-mode client's websocket task; the `DIDCacheClient`
/// has no `Drop` impl, so discarding one without stopping it leaves that task
/// reconnecting for as long as its runtime runs. A clone a caller still holds
/// keeps its cache but can no longer dispatch to the sidecar. The next
/// [`shared_did_resolver`] call builds a fresh client.
pub fn shutdown_shared_did_resolvers() {
    let mut map = shared_resolvers();
    for (_, entry) in map.drain() {
        entry.client.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_did_resolver_cache_sdk::DIDCacheClient;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    /// A TCP listener on 127.0.0.1 that counts accepted connections.
    async fn counting_listener() -> (u16, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(socket);
            }
        });
        (port, accepted)
    }

    /// The whole point of the `didwebvh-rs` 0.7 bump, asserted through the
    /// construction path this workspace actually uses rather than through the
    /// dependency's own API: a `did:webvh` DID naming a loopback host is
    /// refused, and the listener it names is never connected to.
    ///
    /// Zero accepted connections is the assertion that matters. "Resolution
    /// failed" alone would also be true of a fetch that happened and then hit
    /// a parse error — which is exactly the SSRF this closes, since the
    /// request itself is the leak. The listener answers nothing, so a refusal
    /// that still dialled would show up here as a non-zero count.
    #[tokio::test]
    async fn default_config_refuses_loopback_webvh_did_without_connecting() {
        let (port, accepted) = counting_listener().await;

        // Built the way every VTA/CLI resolver in this workspace is built.
        let client = DIDCacheClient::new(build_did_cache_config(None))
            .await
            .expect("local-mode DID cache client");

        // Spellings that all canonicalise to loopback, plus a single-label
        // name and a metadata name — each refused by `HostPolicy::PublicOnly`.
        for host in [
            "localhost",
            "LOCALHOST",
            "localhost.",
            "svc.localhost",
            "printer.local",
            "metadata.google.internal",
        ] {
            let did = format!("did:webvh:QmScidNotResolvable:{host}%3A{port}");
            let result = client.resolve(&did).await;
            assert!(result.is_err(), "{did} resolved but should be refused");
            let message = result.unwrap_err().to_string();
            assert!(
                message.contains("BlockedHost"),
                "{did} failed for the wrong reason: {message}"
            );
        }

        // Give any connection that was going to happen time to land.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "a refused did:webvh DID still connected to its host"
        );
    }

    /// Without the opt-in the policy is the strict one. Guards against the
    /// default being flipped by a later refactor of `build_did_cache_config`.
    /// Two callers on one runtime get one resolver, and therefore one cache.
    ///
    /// This is load-bearing rather than an optimisation. A dozen call sites
    /// across `vta-service`, `cnm-cli` and `vtc-service` were each building
    /// their own `DIDCacheClient`, so the same DID was fetched once per
    /// construction and a `did:webvh` host saw a burst of requests for one
    /// logical operation — enough to earn a 429 from its own rate limiter.
    /// They now take the shared one, which only helps if it is actually
    /// shared, and nothing pinned that.
    ///
    /// Counted for **this runtime only**, never over the whole registry. The
    /// registry is process-global and every other `#[tokio::test]` in this
    /// binary registers under its own runtime key, so a total is both noisy
    /// and — worse — not monotonic: `shared_did_resolver` prunes entries whose
    /// runtime has ended before it inserts, so the map can shrink under a test
    /// that is only reading it. An earlier version of this test asserted
    /// `after == before + 1` and failed in CI for exactly that reason, with a
    /// dead entry pruned in the same call that added ours.
    #[tokio::test]
    async fn two_callers_on_one_runtime_share_one_resolver() {
        fn mine() -> usize {
            let id = tokio::runtime::Handle::current().id();
            shared_resolvers()
                .keys()
                .filter(|k| k.runtime == id)
                .count()
        }

        assert_eq!(mine(), 0, "this runtime starts with no registered resolver");

        let first = shared_did_resolver(None).await.expect("first resolver");
        assert_eq!(mine(), 1, "the first call registers one resolver");

        let _second = shared_did_resolver(None).await.expect("second resolver");
        assert_eq!(
            mine(),
            1,
            "the second call must reuse the registered resolver, not build another"
        );

        // No second key is registered to prove the counter can move: the
        // 0 -> 1 step above already does that, and the only other way to move
        // it is a different sidecar URL, which puts the client in network mode
        // and makes this test wait on a socket that is not the subject.

        // Still registered after a caller drops its clone: the registry holds
        // the shared one, so a short-lived caller cannot evict it for the next.
        drop(first);
        assert!(mine() >= 1);
    }

    #[test]
    fn default_policy_is_public_only() {
        // No env var and no `set_allow_private_endpoints` call in this test
        // binary's default state.
        assert_eq!(webvh_host_policy(), HostPolicy::PublicOnly);
    }
}
