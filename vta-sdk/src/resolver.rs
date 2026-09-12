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
    #[test]
    fn default_policy_is_public_only() {
        // No env var and no `set_allow_private_endpoints` call in this test
        // binary's default state.
        assert_eq!(webvh_host_policy(), HostPolicy::PublicOnly);
    }
}
