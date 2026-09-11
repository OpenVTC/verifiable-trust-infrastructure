//! Shared HTTP client construction for the SDK's REST transports.
//!
//! `reqwest` applies **no** request or connect timeout by default, so a hung or
//! blackholed VTA (a half-open load balancer, a SIGSTOPped process, a firewall
//! silently dropping packets) would hang the caller forever. Every REST client
//! in the SDK is built here so the timeouts are applied uniformly.
//!
//! This module is also the SDK's one egress-policy chokepoint: the address
//! classifier ([`classify_ip`], [`classify_host`]), the foreign-fetch guard
//! ([`guard_public_url`]) and the VTA-endpoint guard ([`guard_vta_endpoint`]).
//!
//! The classifier mirrors the one in `affinidi-did-web` (`ip_is_blocked` /
//! `host_is_blocked` / `GuardedResolver`). A shared `affinidi-net-guard` crate is
//! planned to hold that implementation once; when it is published, replace the
//! classifier and resolver below with re-exports from it and keep these public
//! names as shims.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Default total-request timeout for a VTA REST call.
const DEFAULT_REST_TIMEOUT_SECS: u64 = 30;
/// Default TCP/TLS connect timeout.
const DEFAULT_REST_CONNECT_TIMEOUT_SECS: u64 = 10;
/// Upper bound on same-origin redirects a REST call will follow (reqwest's own
/// default limit).
const MAX_REST_REDIRECTS: usize = 10;

/// A `reqwest::Client` with finite request + connect timeouts.
///
/// Overridable via `VTA_REST_TIMEOUT_SECS` / `VTA_REST_CONNECT_TIMEOUT_SECS`
/// (positive integers, seconds); anything missing/zero/unparseable falls back to
/// the defaults. Use this instead of `reqwest::Client::new()` for any REST call
/// to a VTA so a wedged peer surfaces as a timeout error, not an unbounded hang.
///
/// Redirects are followed only while they stay on the origin (scheme, host and
/// port) of the original request. A VTA's REST API has no reason to send a
/// client elsewhere, and following a cross-origin `3xx` would let whoever
/// answers the first request point an authenticated client at an arbitrary
/// host, including internal ones. A cross-origin redirect is returned to the
/// caller as the `3xx` response itself, which callers treat as a failure.
///
/// Panics only if the TLS backend cannot initialize — the same condition under
/// which `reqwest::Client::new()` already panics, so this is not a new failure
/// mode.
///
/// Public so sibling client crates (`vtc-client`) share this one chokepoint
/// rather than each reaching for the untimed `reqwest::Client::new()` — R1.2
/// allows no exceptions, and a client crate is exactly where an unbounded hang
/// reaches an operator.
pub fn rest_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(env_secs("VTA_REST_TIMEOUT_SECS", DEFAULT_REST_TIMEOUT_SECS))
        .connect_timeout(env_secs(
            "VTA_REST_CONNECT_TIMEOUT_SECS",
            DEFAULT_REST_CONNECT_TIMEOUT_SECS,
        ))
        .redirect(same_origin_redirect_policy())
        .build()
        .expect("reqwest client with timeouts (TLS backend init)")
}

/// Follow a redirect only while it stays on the original request's origin.
fn same_origin_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() > MAX_REST_REDIRECTS {
            return attempt.error("too many redirects");
        }
        let same_origin = attempt
            .previous()
            .first()
            .is_some_and(|original| same_origin(original, attempt.url()));
        if same_origin {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
}

/// Scheme, host and port (with the scheme's default port filled in) all match.
fn same_origin(a: &reqwest::Url, b: &reqwest::Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Read a positive-integer seconds value from `var`, falling back to `default`.
fn env_secs(var: &str, default: u64) -> Duration {
    let secs = std::env::var(var)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default);
    Duration::from_secs(secs)
}

// ── Address classification ───────────────────────────────────────────────────

/// What an IP address is, for egress decisions.
///
/// Produced by [`classify_ip`]. Only [`IpClass::Public`] is globally routable;
/// every other class names why an address is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpClass {
    /// Globally routable.
    Public,
    /// `127.0.0.0/8`, `::1`.
    Loopback,
    /// RFC 1918 (`10/8`, `172.16/12`, `192.168/16`) and IPv6 unique-local
    /// `fc00::/7`.
    Private,
    /// `100.64.0.0/10`, carrier-grade NAT (RFC 6598). Also where many overlay
    /// networks and Kubernetes pod ranges live.
    SharedAddressSpace,
    /// `169.254.0.0/16` and `fe80::/10`. Includes the cloud instance-metadata
    /// address `169.254.169.254`.
    LinkLocal,
    /// A cloud instance-metadata address outside link-local: AWS IMDSv6
    /// `fd00:ec2::254` and Alibaba Cloud `100.100.100.200`.
    Metadata,
    /// `0.0.0.0/8` ("this network") and `::`.
    Unspecified,
    /// `255.255.255.255`.
    Broadcast,
    /// `224.0.0.0/4`, `ff00::/8`.
    Multicast,
    /// `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`.
    Documentation,
    /// `198.18.0.0/15`, `2001:2::/48`.
    Benchmarking,
    /// Other special-purpose space that is not globally routable:
    /// `192.0.0.0/24`, `240.0.0.0/4`, deprecated site-local `fec0::/10`,
    /// discard-only `100::/64`, Teredo `2001::/32`, local-use NAT64
    /// `64:ff9b:1::/48`.
    Reserved,
}

impl IpClass {
    /// Whether this class is globally routable.
    pub fn is_public(self) -> bool {
        self == IpClass::Public
    }

    /// Short human-readable description, for error messages.
    pub fn describe(self) -> &'static str {
        match self {
            IpClass::Public => "public",
            IpClass::Loopback => "loopback",
            IpClass::Private => "private-network",
            IpClass::SharedAddressSpace => "carrier-grade NAT",
            IpClass::LinkLocal => "link-local",
            IpClass::Metadata => "cloud metadata",
            IpClass::Unspecified => "unspecified",
            IpClass::Broadcast => "broadcast",
            IpClass::Multicast => "multicast",
            IpClass::Documentation => "documentation",
            IpClass::Benchmarking => "benchmarking",
            IpClass::Reserved => "reserved",
        }
    }
}

/// Classify an IP address.
///
/// IPv6 addresses that embed an IPv4 destination are classified by that
/// destination: IPv4-mapped `::ffff:a.b.c.d`, IPv4-compatible `::a.b.c.d`,
/// NAT64 `64:ff9b::/96` and 6to4 `2002::/16`. Without that, `::ffff:127.0.0.1`
/// reaches loopback while looking like an ordinary IPv6 address.
pub fn classify_ip(addr: IpAddr) -> IpClass {
    match addr {
        IpAddr::V4(a) => classify_ipv4(a),
        IpAddr::V6(a) => classify_ipv6(a),
    }
}

fn classify_ipv4(a: Ipv4Addr) -> IpClass {
    let o = a.octets();
    if o[0] == 0 {
        IpClass::Unspecified
    } else if a.is_loopback() {
        IpClass::Loopback
    } else if o == [100, 100, 100, 200] {
        IpClass::Metadata
    } else if a.is_private() {
        IpClass::Private
    } else if o[0] == 100 && (64..128).contains(&o[1]) {
        IpClass::SharedAddressSpace
    } else if a.is_link_local() {
        IpClass::LinkLocal
    } else if a.is_broadcast() {
        IpClass::Broadcast
    } else if a.is_multicast() {
        IpClass::Multicast
    } else if a.is_documentation() {
        IpClass::Documentation
    } else if o[0] == 198 && (o[1] & 0xfe) == 18 {
        IpClass::Benchmarking
    } else if (o[0] == 192 && o[1] == 0 && o[2] == 0) || o[0] >= 240 {
        IpClass::Reserved
    } else {
        IpClass::Public
    }
}

fn classify_ipv6(a: Ipv6Addr) -> IpClass {
    if a.is_unspecified() {
        return IpClass::Unspecified;
    }
    if a.is_loopback() {
        return IpClass::Loopback;
    }
    if let Some(v4) = embedded_ipv4(a) {
        return classify_ipv4(v4);
    }
    let s = a.segments();
    if a == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254) {
        IpClass::Metadata
    } else if a.is_multicast() {
        IpClass::Multicast
    } else if (s[0] & 0xfe00) == 0xfc00 {
        IpClass::Private
    } else if (s[0] & 0xffc0) == 0xfe80 {
        IpClass::LinkLocal
    } else if s[0] == 0x2001 && s[1] == 0x0db8 {
        IpClass::Documentation
    } else if s[0] == 0x2001 && s[1] == 0x0002 && s[2] == 0 {
        IpClass::Benchmarking
    } else if (s[0] & 0xffc0) == 0xfec0
        || (s[0] == 0x2001 && s[1] == 0)
        || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001)
        || (s[0] == 0x0100 && s[1..4] == [0, 0, 0])
    {
        IpClass::Reserved
    } else {
        IpClass::Public
    }
}

/// The IPv4 destination embedded in an IPv6 address, if it has one:
/// IPv4-mapped, IPv4-compatible, NAT64 well-known prefix, or 6to4.
fn embedded_ipv4(a: Ipv6Addr) -> Option<Ipv4Addr> {
    // `to_ipv4` would report `::1` as the compatible form of `0.0.0.1`.
    if a.is_loopback() || a.is_unspecified() {
        return None;
    }
    // `to_ipv4`, unlike `to_ipv4_mapped`, also covers the compatible form.
    if let Some(v4) = a.to_ipv4() {
        return Some(v4);
    }
    let s = a.segments();
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return Some(Ipv4Addr::from((u32::from(s[6]) << 16) | u32::from(s[7])));
    }
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::from((u32::from(s[1]) << 16) | u32::from(s[2])));
    }
    None
}

/// What a URL host is, for egress decisions. Produced by [`classify_host`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostClass {
    /// An IP literal, with its class.
    Ip(IpClass),
    /// Exactly `localhost` (a trailing root dot is ignored).
    Localhost,
    /// A name that only means something on a local or private network:
    /// `*.localhost`, `*.local` (mDNS), `*.internal`, `*.home.arpa`, and
    /// single-label names.
    LocalName,
    /// A well-known cloud instance-metadata hostname.
    MetadataName,
    /// An ordinary DNS name. Its addresses are only known at connect time.
    Domain,
}

/// Hostnames that serve cloud instance metadata.
const METADATA_NAMES: &[&str] = &[
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
];

/// Classify a parsed URL host.
///
/// Takes the host from [`reqwest::Url::host`], after WHATWG parsing, so the
/// alternative IPv4 spellings (`2130706433`, `0x7f.1`, `127.1`, …) already
/// arrive as the canonical address.
pub fn classify_host(host: &url::Host<&str>) -> HostClass {
    match host {
        url::Host::Ipv4(a) => HostClass::Ip(classify_ipv4(*a)),
        url::Host::Ipv6(a) => HostClass::Ip(classify_ipv6(*a)),
        url::Host::Domain(d) => classify_domain(d),
    }
}

fn classify_domain(domain: &str) -> HostClass {
    // A trailing root dot survives URL parsing, so `localhost.` must normalise
    // to `localhost` before the comparisons below.
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    if d == "localhost" {
        HostClass::Localhost
    } else if METADATA_NAMES.contains(&d.as_str()) {
        HostClass::MetadataName
    } else if d.is_empty()
        || !d.contains('.')
        || d.ends_with(".localhost")
        || d.ends_with(".local")
        || d.ends_with(".internal")
        || d.ends_with(".home.arpa")
    {
        HostClass::LocalName
    } else {
        HostClass::Domain
    }
}

// ── Foreign fetch: attacker-influenceable URLs (status lists, etc.) ──────────
//
// Fetching a URL a third party controls (an issuer-supplied status-list URL on
// the credential-present path) is a privileged operation. It needs strictly
// more hardening than an ordinary REST call to our own VTA — no redirect
// following (CWE-918 SSRF-via-redirect), a response-body cap (a hostile host
// can otherwise stream a multi-GB body to OOM the process), and a URL guard
// that refuses non-public targets. This is the single shared implementation so
// every consumer (VTA vault-present, VTC recognise/present) gets the same
// chokepoint rather than each rolling its own.

/// Timeout for a foreign fetch — deliberately tighter than the REST default.
const FOREIGN_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Default cap on a fetched foreign body. The spec-minimum status list is
/// ~16 KiB; 2 MiB is generous headroom while refusing an OOM-sized stream.
pub const DEFAULT_MAX_FOREIGN_BODY: usize = 2 * 1024 * 1024;

/// Errors from the foreign-fetch helpers. Callers map these into their own
/// error types (e.g. `AppError`, `RecognitionError`).
#[derive(Debug, thiserror::Error)]
pub enum ForeignFetchError {
    /// The URL failed [`guard_public_url`] or [`guard_vta_endpoint`] (bad
    /// scheme, userinfo, non-public host).
    #[error("{0}")]
    Blocked(String),
    /// The response body exceeded the caller's cap.
    #[error("response body exceeds the {max}-byte cap")]
    BodyTooLarge { max: usize },
    /// Reading the response body failed mid-stream.
    #[error("reading response body failed: {0}")]
    Read(String),
}

/// One shared, hardened client for every outbound foreign fetch. `reqwest::Client`
/// is internally ref-counted, so cloning reuses the connection pool.
///
/// - **`redirect(none)`** — [`guard_public_url`] runs once, on the *original*
///   URL. Following redirects would let a public URL `302` to an internal target
///   (`127.0.0.1`, `169.254.169.254`) past the guard. With no follow, a
///   redirecting host yields a non-2xx the caller treats as failure.
/// - **guarded DNS resolver** — a hostname is resolved once, the answers are
///   vetted, and the connection goes to those vetted addresses. A name with any
///   non-public answer fails the request, which also closes the DNS-rebinding
///   window between a check and the connect.
/// - **`no_proxy`** — with `HTTP(S)_PROXY` honoured, the proxy would resolve the
///   target name and the resolver above would never see it.
/// - **`timeout` / `connect_timeout`** — bounded so a hung host can't pin a
///   request open.
///
/// IP-literal hosts never reach the resolver (the connector dials them
/// directly), which is why [`guard_public_url`] must still run first.
///
/// Body size is capped per-fetch by [`read_body_capped`] (reqwest has none).
static FOREIGN_FETCH_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(PublicOnlyResolver)
        .no_proxy()
        .timeout(FOREIGN_FETCH_TIMEOUT)
        .connect_timeout(FOREIGN_FETCH_TIMEOUT)
        .build()
        .expect("hardened foreign-fetch client builds from static config")
});

/// A clone of the shared hardened foreign-fetch client. Use this — never
/// `reqwest::Client::new()` — for any fetch of an attacker-influenceable URL.
pub fn foreign_fetch_client() -> reqwest::Client {
    FOREIGN_FETCH_CLIENT.clone()
}

/// Refusal raised by [`PublicOnlyResolver`] when a hostname resolves to an
/// address that is not globally routable. Travels out through `reqwest`'s error
/// chain.
#[derive(Debug)]
struct BlockedAddress {
    host: String,
    detail: String,
}

impl std::fmt::Display for BlockedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "refusing to connect to {}: {}", self.host, self.detail)
    }
}

impl std::error::Error for BlockedAddress {}

/// A DNS resolver that refuses to hand back a non-public address.
#[derive(Debug, Clone, Copy)]
struct PublicOnlyResolver;

impl reqwest::dns::Resolve for PublicOnlyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let host = name.as_str().to_owned();
            // Port 0: reqwest substitutes the URL's port over whatever we return.
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                .collect();
            let vetted = vet_resolved(&host, addrs)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            Ok(Box::new(vetted.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Fail closed on the whole name: a name with even one non-public answer, or
/// with no answers at all, is not one we are willing to connect to.
fn vet_resolved(host: &str, addrs: Vec<SocketAddr>) -> Result<Vec<SocketAddr>, BlockedAddress> {
    if addrs.is_empty() {
        return Err(BlockedAddress {
            host: host.to_owned(),
            detail: "name resolved to no addresses".into(),
        });
    }
    if let Some(bad) = addrs.iter().find(|a| !classify_ip(a.ip()).is_public()) {
        return Err(BlockedAddress {
            host: host.to_owned(),
            detail: format!(
                "name resolves to non-public {} address {}",
                classify_ip(bad.ip()).describe(),
                bad.ip()
            ),
        });
    }
    Ok(addrs)
}

/// Read a response body into memory, refusing anything larger than `max` bytes.
/// Reads chunk-by-chunk and aborts the moment the cap is crossed — the oversized
/// body is never fully buffered.
pub async fn read_body_capped(
    mut resp: reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, ForeignFetchError> {
    let mut buf = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| ForeignFetchError::Read(e.to_string()))?
    {
        if buf.len() + chunk.len() > max {
            return Err(ForeignFetchError::BodyTooLarge { max });
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Refuse a URL that isn't a plain public HTTPS target before fetching it.
///
/// Rejects: non-`https` schemes, embedded userinfo, IP-literal hosts in any
/// non-public class of [`classify_ip`] (including IPv4 embedded in IPv6 and
/// cloud metadata addresses), and the local-only names of [`classify_host`]
/// (`localhost`, `*.localhost`, `*.local`, `*.internal`, `*.home.arpa`,
/// single-label names, metadata hostnames).
///
/// An ordinary hostname passes here. Its addresses are vetted at connect time
/// by the resolver on [`foreign_fetch_client`], so fetch through that client.
pub fn guard_public_url(url: &str) -> Result<(), ForeignFetchError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| ForeignFetchError::Blocked(format!("invalid url {url}: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(ForeignFetchError::Blocked(format!(
            "url must be https (got scheme {})",
            parsed.scheme()
        )));
    }
    if parsed.username() != "" || parsed.password().is_some() {
        return Err(ForeignFetchError::Blocked(
            "url must not contain userinfo".into(),
        ));
    }
    let host = parsed
        .host()
        .ok_or_else(|| ForeignFetchError::Blocked("url missing host".into()))?;
    match classify_host(&host) {
        HostClass::Domain | HostClass::Ip(IpClass::Public) => Ok(()),
        HostClass::Ip(class) => Err(ForeignFetchError::Blocked(format!(
            "url points at non-public {} IP {host}",
            class.describe()
        ))),
        HostClass::Localhost | HostClass::LocalName | HostClass::MetadataName => Err(
            ForeignFetchError::Blocked(format!("url points at non-public host name {host}")),
        ),
    }
}

// ── VTA endpoints advertised in a DID document ───────────────────────────────

/// Environment variable that permits private-network VTA endpoints. Truthy
/// values: `1`, `true`, `yes`, `on` (case-insensitive).
pub const ALLOW_PRIVATE_ENDPOINTS_ENV: &str = "VTA_ALLOW_PRIVATE_ENDPOINTS";

/// Process-wide opt-in set by a CLI flag; see [`set_allow_private_endpoints`].
static ALLOW_PRIVATE_ENDPOINTS: AtomicBool = AtomicBool::new(false);

/// Permit private-network VTA endpoints for the rest of this process.
///
/// For binaries that expose the opt-in as a flag (`--allow-private-endpoints`).
/// [`EndpointPolicy::process_default`] honours it alongside
/// [`ALLOW_PRIVATE_ENDPOINTS_ENV`].
pub fn set_allow_private_endpoints(allow: bool) {
    ALLOW_PRIVATE_ENDPOINTS.store(allow, Ordering::Relaxed);
}

/// Which VTA endpoints [`guard_vta_endpoint`] accepts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct EndpointPolicy {
    /// Accept RFC 1918, IPv6 unique-local and carrier-grade NAT addresses, and
    /// local-only names (`*.internal`, `*.local`, single-label names, …).
    pub allow_private: bool,
}

impl EndpointPolicy {
    /// Public hosts only, plus loopback. The default.
    pub const fn public_only() -> Self {
        Self {
            allow_private: false,
        }
    }

    /// Also accept private-network hosts.
    pub const fn private_allowed() -> Self {
        Self {
            allow_private: true,
        }
    }

    /// The policy for this process: private endpoints are allowed when
    /// [`set_allow_private_endpoints`] was called with `true`, or when
    /// [`ALLOW_PRIVATE_ENDPOINTS_ENV`] is set to a truthy value.
    pub fn process_default() -> Self {
        let from_env = std::env::var(ALLOW_PRIVATE_ENDPOINTS_ENV)
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);
        Self {
            allow_private: from_env || ALLOW_PRIVATE_ENDPOINTS.load(Ordering::Relaxed),
        }
    }
}

/// The loopback hosts that may be dialled over plain `http://`: exactly
/// `localhost`, any address in `127.0.0.0/8`, and `::1`.
///
/// Matches `is_loopback_host` in `vta-webvh`'s webvh client. IPv4-mapped forms
/// such as `::ffff:127.0.0.1` are deliberately not included.
fn is_loopback_host(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(d) => d.trim_end_matches('.').eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    }
}

/// Vet a VTA REST endpoint taken from a DID document before any request is
/// made to it.
///
/// - The scheme must be `https`, or `http` when the host is loopback
///   (`localhost`, `127.0.0.0/8`, `::1`) for local development.
/// - Always refused: userinfo, schemes other than `http`/`https`, link-local
///   and cloud-metadata addresses and names, unspecified, broadcast, multicast,
///   documentation, benchmarking and reserved addresses, and any IPv6 address
///   embedding a non-public IPv4 destination.
/// - Private-network hosts (RFC 1918, unique-local, carrier-grade NAT,
///   `*.internal`/`*.local`/single-label names) only when
///   `policy.allow_private` is set. The error names the opt-in.
///
/// An ordinary hostname is accepted: its addresses are not known here.
pub fn guard_vta_endpoint(
    url: &str,
    policy: EndpointPolicy,
) -> Result<reqwest::Url, ForeignFetchError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| ForeignFetchError::Blocked(format!("invalid VTA endpoint URL: {e}")))?;
    let scheme = parsed.scheme();
    if scheme != "https" && scheme != "http" {
        return Err(ForeignFetchError::Blocked(format!(
            "VTA endpoint uses unsupported scheme `{scheme}://`; only https:// (or http:// \
             to a loopback host) is accepted"
        )));
    }
    // Checked before anything that echoes the URL, so credentials never land in
    // an error message.
    if parsed.username() != "" || parsed.password().is_some() {
        return Err(ForeignFetchError::Blocked(
            "VTA endpoint must not embed credentials (userinfo) in the URL".into(),
        ));
    }
    let host = parsed
        .host()
        .ok_or_else(|| ForeignFetchError::Blocked("VTA endpoint URL has no host".into()))?;
    let origin = parsed.origin().ascii_serialization();

    if is_loopback_host(&host) {
        return Ok(parsed);
    }
    if scheme == "http" {
        return Err(ForeignFetchError::Blocked(format!(
            "refusing plaintext http:// VTA endpoint {origin}: only a loopback host \
             (localhost, 127.0.0.0/8, ::1) may use http://; advertise an https:// endpoint"
        )));
    }

    let embeds_ipv4 = matches!(host, url::Host::Ipv6(a) if embedded_ipv4(a).is_some());
    let private_reason = match classify_host(&host) {
        HostClass::Domain | HostClass::Ip(IpClass::Public) => return Ok(parsed),
        HostClass::Ip(class @ (IpClass::Private | IpClass::SharedAddressSpace)) if !embeds_ipv4 => {
            class.describe()
        }
        HostClass::LocalName => "private-network name",
        HostClass::Ip(class) => {
            return Err(ForeignFetchError::Blocked(format!(
                "VTA endpoint {origin} is a {} address, which is never accepted",
                class.describe()
            )));
        }
        HostClass::Localhost | HostClass::MetadataName => {
            return Err(ForeignFetchError::Blocked(format!(
                "VTA endpoint {origin} is a reserved host name, which is never accepted"
            )));
        }
    };
    if policy.allow_private {
        Ok(parsed)
    } else {
        Err(ForeignFetchError::Blocked(format!(
            "VTA endpoint {origin} is a {private_reason} host; endpoints advertised in a \
             DID document must be public by default. If this VTA is meant to be reached \
             over a private network, set {ALLOW_PRIVATE_ENDPOINTS_ENV}=1 or pass \
             --allow-private-endpoints"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_secs_uses_default_when_unset_or_junk() {
        // A var that does not exist → default.
        assert_eq!(
            env_secs("VTA_REST_TIMEOUT_SECS_DEFINITELY_UNSET_XYZ", 30),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn rest_client_builds() {
        // Building must not panic in a normal environment (TLS backend present).
        let _ = rest_client();
    }

    #[test]
    fn guard_allows_public_https() {
        guard_public_url("https://example.com/status/list").expect("public https ok");
    }

    #[test]
    fn guard_blocks_plain_http() {
        guard_public_url("http://example.com/status").expect_err("http blocked");
    }

    #[test]
    fn guard_blocks_loopback() {
        guard_public_url("https://127.0.0.1/x").expect_err("loopback blocked");
        guard_public_url("https://127.1/x").expect_err("loopback short form blocked");
    }

    #[test]
    fn guard_blocks_private_v4() {
        guard_public_url("https://10.0.0.1/x").expect_err("10/8 blocked");
        guard_public_url("https://192.168.1.5/x").expect_err("192.168 blocked");
        guard_public_url("https://172.16.0.1/x").expect_err("172.16 blocked");
    }

    #[test]
    fn guard_blocks_cloud_metadata() {
        guard_public_url("https://169.254.169.254/latest/meta-data/")
            .expect_err("link-local metadata blocked");
    }

    #[test]
    fn guard_blocks_v6_internal() {
        guard_public_url("https://[::1]/x").expect_err("v6 loopback blocked");
        guard_public_url("https://[fc00::1]/x").expect_err("v6 ULA blocked");
        guard_public_url("https://[fe80::1]/x").expect_err("v6 link-local blocked");
    }

    #[test]
    fn guard_blocks_userinfo() {
        guard_public_url("https://user:pass@example.com/x").expect_err("userinfo blocked");
    }

    #[test]
    fn guard_blocks_garbage() {
        guard_public_url("not a url").expect_err("garbage blocked");
    }

    // ── Classifier conformance vectors ──────────────────────────────────────

    const IP_BLOCK: &[&str] = &[
        "127.0.0.1",
        "127.255.255.254",
        "0.0.0.0",
        "0.1.2.3",
        "10.0.0.1",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "169.254.169.254",
        "169.254.170.2",
        "100.64.0.1",
        "100.100.100.200",
        "100.127.255.254",
        "192.0.0.1",
        "198.18.0.1",
        "198.19.255.255",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "239.255.255.250",
        "240.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "::ffff:127.0.0.1",
        "::ffff:7f00:1",
        "::ffff:169.254.169.254",
        "::127.0.0.1",
        "64:ff9b::7f00:1",
        "64:ff9b::a9fe:a9fe",
        "64:ff9b:1::a00:1",
        "2002:7f00:1::1",
        "2001:0:4136:e378::1",
        "fc00::1",
        "fd00::1",
        "fd00:ec2::254",
        "fe80::1",
        "febf::1",
        "fec0::1",
        "ff02::1",
        "2001:db8::1",
        "100::1",
    ];

    const IP_ALLOW: &[&str] = &[
        "8.8.8.8",
        "1.1.1.1",
        "11.0.0.1",
        "100.63.255.255",
        "100.128.0.0",
        "172.15.255.255",
        "172.32.0.1",
        "169.253.255.255",
        "192.169.0.1",
        "198.20.0.1",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
        "64:ff9b::808:808",
    ];

    #[test]
    fn classifier_blocks_every_non_public_vector() {
        for v in IP_BLOCK {
            let ip: IpAddr = v.parse().unwrap();
            assert!(
                !classify_ip(ip).is_public(),
                "{v} must not classify as public"
            );
        }
    }

    #[test]
    fn classifier_allows_every_public_vector() {
        for v in IP_ALLOW {
            let ip: IpAddr = v.parse().unwrap();
            assert_eq!(classify_ip(ip), IpClass::Public, "{v} must be public");
        }
    }

    #[test]
    fn classifier_names_the_class() {
        let c = |s: &str| classify_ip(s.parse().unwrap());
        assert_eq!(c("169.254.169.254"), IpClass::LinkLocal);
        assert_eq!(c("100.100.100.200"), IpClass::Metadata);
        assert_eq!(c("fd00:ec2::254"), IpClass::Metadata);
        assert_eq!(c("::ffff:10.0.0.1"), IpClass::Private);
        assert_eq!(c("64:ff9b::a9fe:a9fe"), IpClass::LinkLocal);
        assert_eq!(c("100.64.0.1"), IpClass::SharedAddressSpace);
        assert_eq!(c("fd00::1"), IpClass::Private);
        assert_eq!(c("198.18.0.1"), IpClass::Benchmarking);
    }

    /// Alternative IPv4 spellings, IPv6-embedded loopback, and userinfo tricks.
    /// The ones the WHATWG parser rejects outright are just as refused.
    #[test]
    fn guard_public_url_blocks_url_vectors() {
        for u in [
            "https://2130706433/",
            "https://0x7f000001/",
            "https://017700000001/",
            "https://0177.0.0.1/",
            "https://0x7f.0.0.1/",
            "https://127.1/",
            "https://127.0.1/",
            "https://0/",
            "https://169.254.169.254./",
            "https://%31%32%37.0.0.1/",
            "https://①②⑦.0.0.1/",
            "https://127。0。0。1/",
            "https://[::ffff:127.0.0.1]/",
            "https://[0:0:0:0:0:ffff:7f00:1]/",
            "https://[::1]:8443/",
            "https://example.com@127.0.0.1/",
            "https://127.0.0.1\\@example.com/",
            "https://user:pass@example.com/",
            "https://100.100.100.200/",
            // Invalid under WHATWG parsing.
            "https://0x100000000/",
            "https://1.2.3.4.5/",
            "https://[fe80::1%25en0]/",
        ] {
            assert!(guard_public_url(u).is_err(), "{u} must be refused");
        }
    }

    #[test]
    fn guard_public_url_blocks_local_names() {
        for u in [
            "https://localhost/",
            "https://LOCALHOST./",
            "https://svc.localhost/",
            "https://printer.local/",
            "https://kube-dns.kube-system.svc.cluster.local/",
            "https://metadata.google.internal/",
            "https://router.home.arpa/",
            "https://metadata/",
        ] {
            assert!(guard_public_url(u).is_err(), "{u} must be refused");
        }
        for u in [
            "https://example.com/",
            "https://example.com./",
            "https://localhost.example.com/",
        ] {
            assert!(guard_public_url(u).is_ok(), "{u} must be allowed");
        }
    }

    #[test]
    fn guard_public_url_blocks_non_https_schemes() {
        for u in [
            "http://example.com/",
            "ws://example.com/",
            "ftp://example.com/",
            "file:///etc/passwd",
            "gopher://example.com/",
            "data:text/plain,x",
            "javascript:alert(1)",
            "blob:https://x/y",
        ] {
            assert!(guard_public_url(u).is_err(), "{u} must be refused");
        }
    }

    // ── DNS answers (stubbed) ───────────────────────────────────────────────

    fn socks(ips: &[&str]) -> Vec<SocketAddr> {
        ips.iter()
            .map(|s| SocketAddr::new(s.parse().unwrap(), 0))
            .collect()
    }

    #[test]
    fn resolver_vets_every_answer() {
        assert!(vet_resolved("a.test", socks(&["93.184.216.34"])).is_ok());
        assert!(vet_resolved("b.test", socks(&["127.0.0.1"])).is_err());
        assert!(vet_resolved("c.test", socks(&["93.184.216.34", "10.0.0.1"])).is_err());
        assert!(vet_resolved("d.test", socks(&["::ffff:169.254.169.254"])).is_err());
        assert!(vet_resolved("e.test", socks(&["64:ff9b::7f00:1"])).is_err());
        assert!(vet_resolved("f.test", Vec::new()).is_err());
    }

    #[tokio::test]
    async fn resolver_refuses_a_name_resolving_to_loopback() {
        use reqwest::dns::Resolve;
        let name: reqwest::dns::Name = "localhost".parse().unwrap();
        let result = PublicOnlyResolver.resolve(name).await;
        assert!(result.is_err(), "localhost resolves to loopback; must fail");
    }

    // ── guard_vta_endpoint ──────────────────────────────────────────────────

    const PUBLIC: EndpointPolicy = EndpointPolicy::public_only();
    const PRIVATE: EndpointPolicy = EndpointPolicy::private_allowed();

    #[test]
    fn vta_endpoint_accepts_public_https_and_loopback_http() {
        for u in [
            "https://vta.example.com",
            "https://vta.example.com:8443/api",
            "https://8.8.8.8",
            "http://localhost:8000/",
            "http://localhost:3000/tenant/vta",
            "http://127.0.0.1:9099/",
            "http://127.0.0.1:8100",
            "http://[::1]:7037/",
            "https://localhost:8443",
        ] {
            assert!(
                guard_vta_endpoint(u, PUBLIC).is_ok(),
                "{u} must be accepted"
            );
        }
    }

    #[test]
    fn vta_endpoint_refuses_always_blocked_targets_even_with_opt_in() {
        for u in [
            "http://169.254.169.254/latest/meta-data/",
            "https://169.254.169.254/",
            "https://[fe80::1]/",
            "https://[fd00:ec2::254]/",
            "https://100.100.100.200/",
            "https://metadata.google.internal/",
            "https://0.0.0.0/",
            "https://[::]/",
            "https://224.0.0.1/",
            "https://255.255.255.255/",
            "https://192.0.2.1/",
            "https://[::ffff:127.0.0.1]/",
            "https://[::ffff:10.0.0.5]/",
            "https://user:pw@vta.example",
            "https://user@vta.example",
            "ftp://vta.example/",
            "file:///etc/passwd",
            "http://10.0.0.5/",
            "http://vta.example.com/",
            "http://localhost.example.com/",
            "not a url",
        ] {
            assert!(
                guard_vta_endpoint(u, PRIVATE).is_err(),
                "{u} must be refused even with private endpoints allowed"
            );
        }
    }

    #[test]
    fn vta_endpoint_private_hosts_need_the_opt_in() {
        for u in [
            "https://10.0.0.5",
            "https://192.168.1.10:8100",
            "https://[fd00::1]/",
            "https://100.64.0.1/",
            "https://vta.internal/",
            "https://vta.corp.local/",
            "https://vta:8100/",
        ] {
            let err = guard_vta_endpoint(u, PUBLIC).expect_err(u).to_string();
            assert!(
                err.contains(ALLOW_PRIVATE_ENDPOINTS_ENV)
                    && err.contains("--allow-private-endpoints"),
                "{u}: the refusal must name the opt-in, got: {err}"
            );
            assert!(
                guard_vta_endpoint(u, PRIVATE).is_ok(),
                "{u} must be accepted with the opt-in"
            );
        }
    }

    #[test]
    fn vta_endpoint_refusal_never_echoes_credentials() {
        let err = guard_vta_endpoint("https://user:s3cret@10.0.0.5/", PRIVATE)
            .unwrap_err()
            .to_string();
        assert!(!err.contains("s3cret"), "{err}");
    }

    // ── REST redirect policy ────────────────────────────────────────────────

    #[tokio::test]
    async fn rest_client_stops_at_a_cross_origin_redirect() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let target = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&target)
            .await;

        let origin = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/start"))
            .respond_with(
                ResponseTemplate::new(302).insert_header("location", format!("{}/x", target.uri())),
            )
            .mount(&origin)
            .await;

        let resp = rest_client()
            .get(format!("{}/start", origin.uri()))
            .send()
            .await
            .expect("send");
        assert_eq!(
            resp.status().as_u16(),
            302,
            "cross-origin redirect must not be followed"
        );
        // `target` verifies its `expect(0)` on drop.
    }

    #[tokio::test]
    async fn rest_client_follows_a_same_origin_redirect() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/old"))
            .respond_with(ResponseTemplate::new(308).insert_header("location", "/new"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/new"))
            .respond_with(ResponseTemplate::new(200).set_body_string("moved"))
            .mount(&server)
            .await;

        let resp = rest_client()
            .get(format!("{}/old", server.uri()))
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(resp.text().await.unwrap(), "moved");
    }

    #[test]
    fn same_origin_compares_scheme_host_and_effective_port() {
        let u = |s: &str| reqwest::Url::parse(s).unwrap();
        assert!(same_origin(
            &u("https://a.example/x"),
            &u("https://a.example:443/y")
        ));
        assert!(!same_origin(
            &u("https://a.example/"),
            &u("http://a.example/")
        ));
        assert!(!same_origin(
            &u("https://a.example/"),
            &u("https://b.example/")
        ));
        assert!(!same_origin(
            &u("https://a.example/"),
            &u("https://a.example:8443/")
        ));
    }
}
