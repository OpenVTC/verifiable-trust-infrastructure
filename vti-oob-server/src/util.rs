//! The flow's small pieces: identifiers, the match number, the `did:key`
//! rule (T21), `contextDigest`, instants on the wire, what the approver is
//! shown about the starter, the origin rule (T19), and the trigger link
//! (contract C1, VTI-LNK-*).

use std::net::IpAddr;

use vti_common::error::AppError;

use crate::http::HttpContext;

/// A fresh `requestId`: 16 random bytes as unpadded base64url, 22 characters
/// (contract C1, VTI-LNK-033/034/103).
pub fn new_request_id() -> String {
    use base64::Engine;
    use rand::RngExt;
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The two-digit number the approver types, `00`–`99`.
pub fn new_match_number() -> String {
    use rand::RngExt;
    format!("{:02}", rand::rng().random_range(0..100u32))
}

/// `true` when `did` is an Ed25519 `did:key` (multicodec `0xed01`, 32 bytes).
/// Decided from the identifier alone, before any proof is read (T21).
pub fn is_ed25519_did_key(did: &str) -> bool {
    if !did.starts_with("did:key:z6Mk") {
        return false;
    }
    let Ok((base, bytes)) = multibase::decode(&did["did:key:".len()..]) else {
        return false;
    };
    base == multibase::Base::Base58Btc && bytes.len() == 34 && bytes[..2] == [0xed, 0x01]
}

/// The Ed25519 multikey (`z6Mk…`) inside an Ed25519 `did:key`.
pub fn did_key_multikey(did: &str) -> Option<&str> {
    is_ed25519_did_key(did).then(|| &did["did:key:".len()..])
}

/// `contextDigest`: SHA-256 of the JCS-canonical signed step 2 response,
/// proof included, as a multibase (`z`, base58btc) sha2-256 multihash — the
/// registry's `DigestMultibase` form, as `payloadDigest` already uses.
pub fn context_digest(signed_step2: &serde_json::Value) -> Result<String, AppError> {
    use sha2::Digest;
    let jcs = serde_json_canonicalizer::to_vec(signed_step2)
        .map_err(|e| AppError::Internal(format!("canonicalise step 2: {e}")))?;
    let digest = sha2::Sha256::digest(&jcs);
    let mut buf = Vec::with_capacity(34);
    buf.extend_from_slice(&[0x12, 0x20]);
    buf.extend_from_slice(&digest);
    Ok(multibase::encode(multibase::Base::Base58Btc, &buf))
}

/// Whether two `DigestMultibase` values name the same multihash, whichever
/// of the two permitted headers each uses: `z` (base58btc) or `u` (base64url)
/// (contract C9).
pub fn same_digest(a: &str, b: &str) -> bool {
    fn bytes(s: &str) -> Option<Vec<u8>> {
        match multibase::decode(s) {
            Ok((multibase::Base::Base58Btc | multibase::Base::Base64Url, b)) => Some(b),
            _ => None,
        }
    }
    match (bytes(a), bytes(b)) {
        (Some(x), Some(y)) => x.len() == 34 && x == y,
        _ => false,
    }
}

/// An instant on the wire — an RFC 3339 `…At` member (`sessionEndsAt`,
/// `claimClosesAt`, `decisionClosesAt`) — as epoch seconds. Contract C9 spelt
/// these as integer epoch seconds; the current `auth/oob` revisions spell them
/// RFC 3339, so an integer is no longer one. An instant before the epoch reads
/// as 0, which every caller compares as already past.
pub fn epoch_of(v: &serde_json::Value) -> Option<u64> {
    let t = chrono::DateTime::parse_from_rfc3339(v.as_str()?).ok()?;
    Some(u64::try_from(t.timestamp()).unwrap_or(0))
}

/// RFC 3339 at whole seconds, UTC.
pub fn rfc3339(epoch: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(epoch as i64, 0)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// The network part compared for `sameNetwork`: the whole IPv4 address, or
/// the /64 of an IPv6 one (a phone and a laptop on one network share a
/// prefix, not an address).
fn network_of(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.octets().to_vec(),
            None => v6.octets()[..8].to_vec(),
        },
    }
}

/// `sameNetwork` from the starter's and the approver's egress addresses:
/// `true`, `false`, or `"unknown"` when either is missing or they are of
/// different families. One machine on a dual-stack network can reach the
/// service over IPv6 from the page and over IPv4 from the wallet (or the
/// other way round), so an IPv4 address against an IPv6 prefix says nothing.
pub fn same_network(start: Option<&str>, approver: Option<IpAddr>) -> serde_json::Value {
    match (start.and_then(|s| s.parse::<IpAddr>().ok()), approver) {
        (Some(a), Some(b)) => {
            let (a, b) = (network_of(&a), network_of(&b));
            if a.len() != b.len() {
                return serde_json::Value::String("unknown".into());
            }
            serde_json::Value::Bool(a == b)
        }
        _ => serde_json::Value::String("unknown".into()),
    }
}

/// Browser family and OS from a `User-Agent`, never the full string (T5).
pub fn browser_and_os(user_agent: Option<&str>) -> (String, String) {
    let ua = user_agent.unwrap_or_default();
    let browser = if ua.contains("Edg/") {
        "Edge"
    } else if ua.contains("OPR/") || ua.contains("Opera") {
        "Opera"
    } else if ua.contains("Firefox/") || ua.contains("FxiOS/") {
        "Firefox"
    } else if ua.contains("Chrome/") || ua.contains("CriOS/") || ua.contains("Chromium/") {
        "Chrome"
    } else if ua.contains("Safari/") {
        "Safari"
    } else {
        "unknown"
    };
    let os = if ua.contains("iPhone") || ua.contains("iPad") {
        "iOS"
    } else if ua.contains("Android") {
        "Android"
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        "macOS"
    } else if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("CrOS") {
        "ChromeOS"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "unknown"
    };
    (browser.into(), os.into())
}

/// The origin (`scheme://host[:port]`) of an absolute URL.
pub fn origin_of(url: &str) -> Option<String> {
    let u = url::Url::parse(url).ok()?;
    let origin = u.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

/// The service's own origin for a request arriving on `ctx`: `public_url`'s
/// origin when configured. Without one, the `Origin` header is accepted only
/// when it names the host the request was sent to — the browser's
/// same-origin call.
pub fn portal_origin(public_url: Option<&str>, ctx: &HttpContext) -> Option<String> {
    if let Some(url) = public_url {
        return origin_of(url);
    }
    let origin = ctx.origin.as_deref()?;
    let host = ctx.host.as_deref()?;
    let parsed = url::Url::parse(origin).ok()?;
    let authority = match parsed.port() {
        Some(p) => format!("{}:{p}", parsed.host_str()?),
        None => parsed.host_str()?.to_string(),
    };
    (authority.eq_ignore_ascii_case(host)).then(|| parsed.origin().ascii_serialization())
}

// ── The trigger link (contract C1) ──────────────────────────────────────────

/// The trigger link's flow, in path form (VTI-LNK-042).
pub const SIGN_IN_FLOW: &str = "/vti/flow/sign-in/0.1";

/// Default link host (contract C1).
pub const DEFAULT_LINK_HOST: &str = "link.trustoverip.org";

/// Check a configured link host: the host rules (VTI-LNK-060), and not the
/// portal's own domain (VTI-LNK-084) — a universal link tapped on a page of
/// the same domain opens in the browser, not the wallet.
pub fn check_link_host(link_host: &str, portal_host: Option<&str>) -> Result<(), String> {
    let labels: Vec<&str> = link_host.split('.').collect();
    let label_ok = |l: &&str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if link_host.len() > 253
        || labels.len() < 2
        || !labels.iter().all(label_ok)
        || labels
            .last()
            .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
        || link_host == "localhost"
        || link_host.ends_with(".localhost")
        || link_host.ends_with(".local")
        || link_host.ends_with(".home.arpa")
    {
        return Err(format!(
            "sign-in link host `{link_host}` is not a public DNS name (VTI-LNK-060)"
        ));
    }
    if let Some(portal) = portal_host.map(str::to_ascii_lowercase) {
        let under = |a: &str, b: &str| a == b || a.ends_with(&format!(".{b}"));
        if under(&portal, link_host) || under(link_host, &portal) {
            return Err(format!(
                "sign-in link host `{link_host}` is on the portal's own domain `{portal}`; a \
                 universal link tapped there opens in the browser, not the wallet \
                 (VTI-LNK-084). Use a separate host, such as `{DEFAULT_LINK_HOST}`."
            ));
        }
    }
    Ok(())
}

/// Percent-encode `&`, `=`, `#` and `%`, and nothing else (contract C1).
pub fn encode_from(did: &str) -> String {
    let mut out = String::with_capacity(did.len());
    for c in did.chars() {
        match c {
            '&' => out.push_str("%26"),
            '=' => out.push_str("%3D"),
            '#' => out.push_str("%23"),
            '%' => out.push_str("%25"),
            c => out.push(c),
        }
    }
    out
}

/// The trigger link for a request (contract C1). The portal builds the same
/// text in the browser; this is the reference the tests hold it to.
pub fn trigger_link(
    link_host: &str,
    service_did: &str,
    request_id: &str,
    claim_deadline: u64,
) -> String {
    format!(
        "https://{link_host}/t#_from={}&_id={request_id}&_exp={claim_deadline}&_type={SIGN_IN_FLOW}",
        encode_from(service_did)
    )
}

/// Largest trigger link a producer may emit at QR level M (VTI-LNK-081).
pub const MAX_LINK_BYTES_LEVEL_M: usize = 251;

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn ed25519_did_key(seed: u8) -> String {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let mut buf = vec![0xed, 0x01];
        buf.extend_from_slice(&sk.verifying_key().to_bytes());
        format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, &buf)
        )
    }

    #[test]
    fn request_ids_are_22_base64url_characters() {
        let id = new_request_id();
        assert_eq!(id.len(), 22);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert_ne!(id, new_request_id());
    }

    #[test]
    fn match_numbers_are_two_digits() {
        for _ in 0..200 {
            let n = new_match_number();
            assert_eq!(n.len(), 2);
            assert!(n.bytes().all(|b| b.is_ascii_digit()));
        }
    }

    #[test]
    fn only_ed25519_did_keys_are_accepted() {
        let did = ed25519_did_key(7);
        assert!(is_ed25519_did_key(&did));
        assert_eq!(did_key_multikey(&did), Some(&did["did:key:".len()..]));
        assert!(!is_ed25519_did_key("did:key:zDnaeexample"));
        assert!(!is_ed25519_did_key("did:webvh:abc:example.com"));
        assert!(!is_ed25519_did_key("did:key:z6Mk"));
        assert_eq!(did_key_multikey("did:webvh:abc:example.com"), None);
    }

    #[test]
    fn same_network_compares_v4_addresses_and_v6_prefixes() {
        let v4: IpAddr = "203.0.113.5".parse().unwrap();
        assert_eq!(same_network(Some("203.0.113.5"), Some(v4)), true);
        assert_eq!(same_network(Some("203.0.113.6"), Some(v4)), false);
        let a: IpAddr = "2001:db8:1:2::10".parse().unwrap();
        assert_eq!(same_network(Some("2001:db8:1:2::99"), Some(a)), true);
        assert_eq!(same_network(Some("2001:db8:1:3::99"), Some(a)), false);
        assert_eq!(same_network(None, Some(a)), "unknown");
        // A page on IPv4 and a wallet on IPv6 (or the reverse) can be one
        // machine on a dual-stack network.
        assert_eq!(same_network(Some("203.0.113.5"), Some(a)), "unknown");
        assert_eq!(same_network(Some("2001:db8:1:2::99"), Some(v4)), "unknown");
    }

    #[test]
    fn browser_and_os_never_echo_the_user_agent() {
        let mac_chrome = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                          (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
        assert_eq!(
            browser_and_os(Some(mac_chrome)),
            ("Chrome".into(), "macOS".into())
        );
        let iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 \
                      (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";
        assert_eq!(
            browser_and_os(Some(iphone)),
            ("Safari".into(), "iOS".into())
        );
        assert_eq!(browser_and_os(None), ("unknown".into(), "unknown".into()));
    }

    #[test]
    fn portal_origin_is_the_public_url_or_the_same_origin_call() {
        let ctx = HttpContext::new(
            "192.0.2.1".parse().unwrap(),
            None,
            Some("https://vtn.example:8443".into()),
            Some("vtn.example:8443".into()),
        );
        assert_eq!(
            portal_origin(Some("https://svc.example/base/"), &ctx).as_deref(),
            Some("https://svc.example")
        );
        assert_eq!(
            portal_origin(None, &ctx).as_deref(),
            Some("https://vtn.example:8443")
        );
        let elsewhere = HttpContext::new(
            "192.0.2.1".parse().unwrap(),
            None,
            Some("https://evil.example".into()),
            Some("vtn.example".into()),
        );
        assert_eq!(portal_origin(None, &elsewhere), None);
    }

    #[test]
    fn trigger_link_matches_the_contract_and_fits_level_m() {
        let did = "did:webvh:QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG:members.example.org";
        let link = trigger_link(DEFAULT_LINK_HOST, did, &new_request_id(), 1_760_000_000);
        assert!(link.starts_with("https://link.trustoverip.org/t#_from=did:webvh:"));
        assert!(link.ends_with("&_exp=1760000000&_type=/vti/flow/sign-in/0.1"));
        assert!(link.is_ascii());
        assert!(link.len() <= MAX_LINK_BYTES_LEVEL_M, "{} bytes", link.len());
        assert_eq!(encode_from("a&b=c#d%e"), "a%26b%3Dc%23d%25e");
    }

    #[test]
    fn link_host_must_be_public_and_off_the_portal_domain() {
        assert!(check_link_host(DEFAULT_LINK_HOST, Some("members.example.org")).is_ok());
        assert!(check_link_host("link.example.org", Some("example.org")).is_err());
        assert!(check_link_host("example.org", Some("members.example.org")).is_err());
        assert!(check_link_host("members.example.org", Some("members.example.org")).is_err());
        assert!(check_link_host("localhost", None).is_err());
        assert!(check_link_host("10.0.0.1", None).is_err());
        assert!(check_link_host("Link.Example.org", None).is_err());
    }

    #[test]
    fn context_digest_is_a_multibase_sha256_multihash() {
        let v = serde_json::json!({ "b": 1, "a": [true] });
        let d = context_digest(&v).unwrap();
        assert!(d.starts_with('z'));
        let (_, bytes) = multibase::decode(&d).unwrap();
        assert_eq!(&bytes[..2], &[0x12, 0x20]);
        // Key order does not matter; JCS sorts.
        assert_eq!(
            d,
            context_digest(&serde_json::json!({ "a": [true], "b": 1 })).unwrap()
        );
        let u = multibase::encode(multibase::Base::Base64Url, &bytes);
        assert!(same_digest(&d, &u));
        assert!(!same_digest(&d, &hex::encode(&bytes)));
        assert!(!same_digest(&d, "zabc"));
        assert_eq!(
            epoch_of(&serde_json::json!("2025-10-09T08:53:20Z")),
            Some(1_760_000_000)
        );
        assert_eq!(epoch_of(&serde_json::json!(1_760_000_000u64)), None);
    }
}
