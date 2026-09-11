//! The Vetting Ticket as a URI — what a vetter's QR code carries.
//!
//! A vetter shows an applicant a ticket so the applicant can send
//! `vetting/request/0.1`. Scanned, it is a URI:
//!
//! ```text
//! vetting-ticket:?v=1&community=<pct-encoded DID>&vetter=<pct-encoded DID>&ticket=<ticketId>&secret=<base64url 32 bytes>
//! ```
//!
//! or, for the short code a vetter reads out, `…&code=K7QF-2M9X` in place of
//! `ticket` and `secret`. dtgwg-trust-tasks-tf documents the form informatively
//! in `vetting/request/0.1` ("Ticket URI").
//!
//! The ticket a URI decodes to is the request's own
//! [`Ticket`](request::Ticket), so its members are checked by the published
//! types' constructors.
//!
//! [`decode`] is strict: it refuses an unknown or missing `v`, a repeated
//! member, a ticket that is both scanned and spoken, and any member that breaks
//! the `vetting/request` schema's pattern for it. Members it does not know are
//! ignored, so a later version can add one without breaking this reader.

use super::VettingError;
use crate::protocols::vetting::request::v0_1 as request;
use crate::protocols::vetting::shape;

/// The URI scheme of a ticket URI.
pub const TICKET_URI_SCHEME: &str = "vetting-ticket";

/// The only ticket URI version this reader understands.
pub const TICKET_URI_VERSION: &str = "1";

const WHAT: &str = "ticket URI";

/// A decoded ticket URI: which community, which vetter, and the ticket the
/// applicant presents in `vetting/request/0.1`.
#[derive(Debug, Clone)]
pub struct TicketUri {
    /// The community the vetter vets for.
    pub community: String,
    /// The vetter's DID — the addressee of the request.
    pub vetter: String,
    /// The ticket: scanned (`ticket` + `secret`) or spoken (`code`).
    pub presentation: request::Ticket,
}

/// Render a ticket as a URI.
///
/// Every value is percent-encoded outside RFC 3986's unreserved set, so a DID's
/// `:` travels as `%3A`.
///
/// # Errors
///
/// [`VettingError::Malformed`] for a ticket form this version of the URI has
/// no members for — a form a later `vetting/request` adds.
pub fn encode(uri: &TicketUri) -> Result<String, VettingError> {
    let mut out = format!(
        "{TICKET_URI_SCHEME}:?v={TICKET_URI_VERSION}&community={}&vetter={}",
        pct_encode(&uri.community),
        pct_encode(&uri.vetter)
    );
    match &uri.presentation {
        request::Ticket::QrTicket(ticket) => {
            out.push_str("&ticket=");
            out.push_str(&pct_encode(&ticket.ticket_id));
            out.push_str("&secret=");
            out.push_str(&pct_encode(&ticket.secret));
        }
        request::Ticket::ShortCodeTicket(ticket) => {
            out.push_str("&code=");
            out.push_str(&pct_encode(&ticket.code));
        }
        _ => return Err(malformed("a ticket form the URI has no members for")),
    }
    Ok(out)
}

/// Parse a ticket URI.
///
/// # Errors
///
/// [`VettingError::UnsupportedVersion`] when `v` is present but not
/// [`TICKET_URI_VERSION`]; [`VettingError::Malformed`] for anything else that
/// is wrong — another scheme, a missing or repeated member, bad
/// percent-encoding, a ticket that carries both forms or neither, or a member
/// that breaks its schema pattern.
pub fn decode(input: &str) -> Result<TicketUri, VettingError> {
    let input = input.trim_matches(|c: char| c.is_ascii_whitespace());
    let (scheme, rest) = input
        .split_once(':')
        .ok_or_else(|| malformed("no scheme"))?;
    if !scheme.eq_ignore_ascii_case(TICKET_URI_SCHEME) {
        return Err(malformed("not a vetting-ticket URI"));
    }
    let query = rest
        .strip_prefix('?')
        .ok_or_else(|| malformed("no query"))?;
    // A fragment is not part of a ticket; refuse rather than guess where the
    // query ends.
    if query.contains('#') {
        return Err(malformed("a ticket URI carries no fragment"));
    }

    let mut members = Members::default();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = pair
            .split_once('=')
            .ok_or_else(|| malformed("a member has no value"))?;
        let slot = match name {
            "v" => &mut members.v,
            "community" => &mut members.community,
            "vetter" => &mut members.vetter,
            "ticket" => &mut members.ticket,
            "secret" => &mut members.secret,
            "code" => &mut members.code,
            // A later version may add members; this reader ignores them.
            _ => continue,
        };
        if slot.is_some() {
            return Err(malformed("a member is repeated"));
        }
        *slot = Some(pct_decode(value)?);
    }

    match members.v.as_deref() {
        None => return Err(malformed("no version")),
        Some(TICKET_URI_VERSION) => {}
        Some(other) => {
            return Err(VettingError::UnsupportedVersion {
                what: WHAT,
                version: truncate(other),
            });
        }
    }

    let community = members.community.ok_or_else(|| malformed("no community"))?;
    let vetter = members.vetter.ok_or_else(|| malformed("no vetter"))?;
    // The community is the request's `community`; the vetter, its addressee.
    request::PayloadCommunity::try_from(community.as_str())
        .map_err(|e| malformed(&format!("community: {e}")))?;
    shape::did("vetter", &vetter).map_err(|e| malformed(&e.to_string()))?;

    let presentation = match (members.ticket, members.secret, members.code) {
        (Some(ticket_id), Some(secret), None) => request::Ticket::QrTicket(
            request::QrTicket::try_from(
                request::QrTicket::builder()
                    .ticket_id(ticket_id)
                    .secret(secret),
            )
            .map_err(|e| malformed(&e.to_string()))?,
        ),
        (None, None, Some(code)) => request::Ticket::ShortCodeTicket(
            request::ShortCodeTicket::try_from(request::ShortCodeTicket::builder().code(code))
                .map_err(|e| malformed(&e.to_string()))?,
        ),
        (None, None, None) => return Err(malformed("no ticket")),
        (Some(_), None, None) | (None, Some(_), None) => {
            return Err(malformed("a scanned ticket needs both ticket and secret"));
        }
        _ => return Err(malformed("a ticket is scanned or spoken, not both")),
    };

    Ok(TicketUri {
        community,
        vetter,
        presentation,
    })
}

#[derive(Default)]
struct Members {
    v: Option<String>,
    community: Option<String>,
    vetter: Option<String>,
    ticket: Option<String>,
    secret: Option<String>,
    code: Option<String>,
}

fn malformed(detail: &str) -> VettingError {
    VettingError::Malformed {
        what: WHAT,
        detail: detail.to_string(),
    }
}

/// A refused version is echoed for the log; bound what a hostile QR can put
/// there.
fn truncate(s: &str) -> String {
    s.chars().take(16).collect()
}

/// RFC 3986 unreserved: `ALPHA / DIGIT / "-" / "." / "_" / "~"`.
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn pct_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        if is_unreserved(b) {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0x0F)]));
        }
    }
    out
}

/// Strict percent-decoding: every `%` is followed by two hex digits, the
/// result is UTF-8, and no byte outside the unreserved set and `%` appears
/// literally — a ticket URI is machine-written, so a literal `:` or space is a
/// sign of something else.
fn pct_decode(value: &str) -> Result<String, VettingError> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hi = bytes.get(i + 1).and_then(|b| hex_value(*b));
                let lo = bytes.get(i + 2).and_then(|b| hex_value(*b));
                match (hi, lo) {
                    (Some(hi), Some(lo)) => out.push((hi << 4) | lo),
                    _ => return Err(malformed("bad percent-encoding")),
                }
                i += 3;
            }
            b if is_unreserved(b) => {
                out.push(b);
                i += 1;
            }
            _ => return Err(malformed("a character that must be percent-encoded")),
        }
    }
    String::from_utf8(out).map_err(|_| malformed("a member is not UTF-8"))
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMUNITY: &str = "did:webvh:QmCommunity:vtc.example.com";
    const VETTER: &str = "did:key:z6MkVetter";
    const SECRET: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    fn scanned() -> TicketUri {
        TicketUri {
            community: COMMUNITY.into(),
            vetter: VETTER.into(),
            presentation: serde_json::from_value(
                serde_json::json!({ "ticketId": "t-01:ab.c_d", "secret": SECRET }),
            )
            .unwrap(),
        }
    }

    fn spoken() -> TicketUri {
        TicketUri {
            community: COMMUNITY.into(),
            vetter: VETTER.into(),
            presentation: serde_json::from_value(serde_json::json!({ "code": "K7QF-2M9X" }))
                .unwrap(),
        }
    }

    /// The two decode the same ticket: same community, vetter and ticket JSON.
    fn same(a: &TicketUri, b: &TicketUri) -> bool {
        a.community == b.community
            && a.vetter == b.vetter
            && serde_json::to_value(&a.presentation).unwrap()
                == serde_json::to_value(&b.presentation).unwrap()
    }

    #[test]
    fn a_scanned_ticket_round_trips() {
        let uri = encode(&scanned()).unwrap();
        assert_eq!(
            uri,
            "vetting-ticket:?v=1&community=did%3Awebvh%3AQmCommunity%3Avtc.example.com\
             &vetter=did%3Akey%3Az6MkVetter&ticket=t-01%3Aab.c_d&secret=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        );
        assert!(same(&decode(&uri).unwrap(), &scanned()));
    }

    #[test]
    fn a_spoken_ticket_round_trips() {
        let uri = encode(&spoken()).unwrap();
        assert!(uri.ends_with("&code=K7QF-2M9X"), "{uri}");
        assert!(same(&decode(&uri).unwrap(), &spoken()));
    }

    #[test]
    fn member_order_the_scheme_case_and_surrounding_whitespace_do_not_matter() {
        let uri = "  VETTING-TICKET:?code=K7QF-2M9X&vetter=did%3Akey%3Az6MkVetter\
                   &community=did%3Awebvh%3AQmCommunity%3Avtc.example.com&v=1\n";
        assert!(same(&decode(uri).unwrap(), &spoken()));
    }

    #[test]
    fn an_unknown_member_is_ignored() {
        let uri = format!("{}&future=yes", encode(&spoken()).unwrap());
        assert!(same(&decode(&uri).unwrap(), &spoken()));
    }

    #[test]
    fn an_unknown_or_missing_version_is_refused() {
        let good = encode(&spoken()).unwrap();
        let v2 = good.replace("v=1", "v=2");
        assert!(matches!(
            decode(&v2),
            Err(VettingError::UnsupportedVersion { version, .. }) if version == "2"
        ));
        let none = good.replace("v=1&", "");
        assert!(matches!(decode(&none), Err(VettingError::Malformed { .. })));
        let long = good.replace("v=1", &format!("v={}", "9".repeat(4096)));
        match decode(&long) {
            Err(VettingError::UnsupportedVersion { version, .. }) => assert_eq!(version.len(), 16),
            other => panic!("expected an unsupported version, got {other:?}"),
        }
    }

    #[test]
    fn a_ticket_is_scanned_or_spoken_but_not_both_or_half() {
        let both = format!("{}&code=K7QF-2M9X", encode(&scanned()).unwrap());
        assert!(decode(&both).is_err());
        let half = encode(&scanned())
            .unwrap()
            .replace(&format!("&secret={SECRET}"), "");
        assert!(decode(&half).is_err());
        let neither = format!(
            "vetting-ticket:?v=1&community={}&vetter={}",
            pct_encode(COMMUNITY),
            pct_encode(VETTER)
        );
        assert!(decode(&neither).is_err());
    }

    #[test]
    fn hostile_and_malformed_input_is_refused_without_panicking() {
        let good = encode(&spoken()).unwrap();
        let scanned_uri = encode(&scanned()).unwrap();
        for bad in [
            String::new(),
            "vetting-ticket".into(),
            "vetting-ticket:".into(),
            "vetting-ticket:v=1".into(),
            "https://example.com/?v=1".into(),
            good.replace("v=1", "v=1&v=1"),
            good.replace("community=did", "community=%zzdid"),
            good.replace("community=did", "community=did%3"),
            good.replace("community=did", "community=did%"),
            good.replace("did%3Akey", "did:key"),
            good.replace("did%3Akey", "did%20key"),
            good.replace("community=did%3Awebvh", "community=%FF%FEdid"),
            good.replace(
                "community=did%3Awebvh%3AQmCommunity%3Avtc.example.com",
                "community=",
            ),
            good.replace("community=did%3Awebvh", "community=notadid"),
            good.replace("K7QF-2M9X", "K7QF-2M9U"),
            good.replace("K7QF-2M9X", "k7qf-2m9x"),
            good.replace("K7QF-2M9X", "K7QF2M9X"),
            format!("{good}#frag"),
            format!("{good}&vetter"),
            scanned_uri.replace(SECRET, "short"),
            scanned_uri.replace("t-01%3Aab.c_d", &"a".repeat(129)),
            "vetting-ticket:?".to_string() + &"&".repeat(10_000),
        ] {
            assert!(decode(&bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn every_byte_value_survives_percent_encoding() {
        let all: String = (0u32..=0x2FF).filter_map(char::from_u32).collect();
        assert_eq!(pct_decode(&pct_encode(&all)).unwrap(), all);
    }
}
