//! The correlators an operator should know about (design note §3.6,
//! VTI-CMP-062).
//!
//! A witness DID is public by design, so nothing here is about hiding it.
//! What can leak is the link between a witness and its **operator**: a
//! mediator both use sees both sets of sessions, and a DID log hosted on the
//! operator's own domain names the operator to anyone who resolves the
//! witness. Either is a possible correlation source the operator may accept —
//! so both are **warnings**, at setup and at every start, never refusals
//! (§5 item 1).

use std::fmt;

/// What is known about the operator's own footprint: its VTA's DID, the
/// mediators its DID document names, and the host its DID log is served from.
#[derive(Debug, Clone, Default)]
pub struct OperatorFootprint {
    /// The operator VTA's DID.
    pub vta_did: String,
    /// Every mediator DID the VTA's document names (TSP and DIDComm).
    pub mediators: Vec<String>,
    /// The host the VTA's DID log is served from, when its method has one.
    pub did_log_host: Option<String>,
}

impl OperatorFootprint {
    /// What can be known without resolving anything: the DID-log host,
    /// read off the DID itself.
    pub fn from_did(vta_did: &str) -> Self {
        Self {
            vta_did: vta_did.to_string(),
            mediators: Vec::new(),
            did_log_host: did_log_host(vta_did),
        }
    }

    /// Resolve the VTA's DID document for the mediators it names. A failed
    /// resolution leaves the mediator list empty — and says so, because an
    /// unchecked correlator is not a clean one.
    pub async fn resolve(vta_did: &str) -> Self {
        let mut footprint = Self::from_did(vta_did);
        match vta_sdk::provision_client::resolve_vta(vta_did).await {
            Ok(resolved) => {
                for mediator in [resolved.tsp_mediator_did, resolved.mediator_did]
                    .into_iter()
                    .flatten()
                {
                    if !footprint.mediators.contains(&mediator) {
                        footprint.mediators.push(mediator);
                    }
                }
            }
            Err(e) => tracing::warn!(
                vta_did,
                error = %e,
                "could not resolve the operator VTA's DID, so a witness sharing its mediator \
                 cannot be detected this time"
            ),
        }
        footprint
    }
}

/// One correlator found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorrelationWarning {
    /// The witness and the operator's VTA use the same mediator.
    SharedMediator {
        /// The witness identity's name.
        identity: String,
        /// The mediator they share.
        mediator: String,
    },
    /// The witness's DID log is served from the operator's domain.
    SharedDomain {
        /// The witness identity's name.
        identity: String,
        /// Where the witness's DID log is served.
        witness_host: String,
        /// Where the operator VTA's DID log is served.
        vta_host: String,
    },
}

impl fmt::Display for CorrelationWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SharedMediator { identity, mediator } => write!(
                f,
                "witness {identity:?} uses the same mediator as the operator's VTA ({mediator}). \
                 That mediator sees both the witness's sessions and the VTA's traffic, which is a \
                 possible correlation source. The operator may accept this; to avoid it, use a \
                 mediator the VTA does not."
            ),
            Self::SharedDomain {
                identity,
                witness_host,
                vta_host,
            } => write!(
                f,
                "witness {identity:?} has its DID log at {witness_host}, a domain it shares with \
                 the operator VTA's DID log ({vta_host}). Anyone resolving the witness learns \
                 that domain, which is a possible correlation source. The operator may accept \
                 this; to avoid it, host the witness's log apart from the operator's own domains."
            ),
        }
    }
}

/// The correlators between one witness identity and its operator.
pub fn check(
    identity: &str,
    witness_did: Option<&str>,
    witness_mediator: &str,
    operator: &OperatorFootprint,
) -> Vec<CorrelationWarning> {
    let mut warnings = Vec::new();
    if operator.mediators.iter().any(|m| m == witness_mediator) {
        warnings.push(CorrelationWarning::SharedMediator {
            identity: identity.to_string(),
            mediator: witness_mediator.to_string(),
        });
    }
    if let (Some(witness_host), Some(vta_host)) = (
        witness_did.and_then(did_log_host),
        operator.did_log_host.as_deref(),
    ) && shares_domain(&witness_host, vta_host)
    {
        warnings.push(CorrelationWarning::SharedDomain {
            identity: identity.to_string(),
            witness_host,
            vta_host: vta_host.to_string(),
        });
    }
    warnings
}

/// The host a `did:webvh` / `did:web` log is served from, lower-cased and
/// without a port. `None` for a method that has no such host.
pub fn did_log_host(did: &str) -> Option<String> {
    let rest = if let Some(rest) = did.strip_prefix("did:webvh:") {
        // `did:webvh:<scid>:<host>[:<path>…]`
        rest.split_once(':')?.1
    } else {
        did.strip_prefix("did:web:")?
    };
    let host = rest.split(':').next()?;
    // A port is percent-encoded into the identifier (`example.com%3A8443`).
    let host = host
        .split("%3A")
        .next()
        .and_then(|h| h.split("%3a").next())?
        .to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

/// Whether two hosts belong to the same domain, as far as a warning needs.
///
/// The same host, one a subdomain of the other, or the same last two labels
/// (`witness.example.com` and `vta.example.com`). The last rule is an
/// approximation of a registrable domain — it over-matches under a two-label
/// public suffix such as `co.uk` — which is acceptable for a warning that the
/// operator may accept and never for a refusal.
pub fn shares_domain(a: &str, b: &str) -> bool {
    let a = a.trim_end_matches('.').to_ascii_lowercase();
    let b = b.trim_end_matches('.').to_ascii_lowercase();
    if a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}")) {
        return true;
    }
    let last_two = |h: &str| -> Option<String> {
        let labels: Vec<&str> = h.rsplitn(3, '.').collect();
        (labels.len() >= 2).then(|| format!("{}.{}", labels[1], labels[0]))
    };
    // An IP literal or a single-label host has no parent domain to share.
    let is_ip = |h: &str| h.parse::<std::net::IpAddr>().is_ok();
    !is_ip(&a) && !is_ip(&b) && matches!((last_two(&a), last_two(&b)), (Some(x), Some(y)) if x == y)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VTA: &str = "did:webvh:QmVTA:vta.operator.example";
    const VTA_MEDIATOR: &str = "did:webvh:QmMED:mediator.operator.example";

    fn operator() -> OperatorFootprint {
        OperatorFootprint {
            vta_did: VTA.to_string(),
            mediators: vec![VTA_MEDIATOR.to_string()],
            did_log_host: did_log_host(VTA),
        }
    }

    #[test]
    fn did_log_hosts_are_read_off_the_identifier() {
        assert_eq!(
            did_log_host("did:webvh:QmScid:witness.example.net:w1").as_deref(),
            Some("witness.example.net")
        );
        assert_eq!(
            did_log_host("did:webvh:QmScid:localhost%3A8443:w1").as_deref(),
            Some("localhost")
        );
        assert_eq!(
            did_log_host("did:web:Example.COM:users:a").as_deref(),
            Some("example.com")
        );
        assert_eq!(did_log_host("did:key:z6MkExample"), None);
        assert_eq!(did_log_host("did:webvh:QmScidOnly"), None);
    }

    #[test]
    fn a_shared_mediator_is_warned_about() {
        let warnings = check(
            "community-a",
            Some("did:webvh:QmW:witness.example.net:a"),
            VTA_MEDIATOR,
            &operator(),
        );
        assert_eq!(
            warnings,
            vec![CorrelationWarning::SharedMediator {
                identity: "community-a".into(),
                mediator: VTA_MEDIATOR.into(),
            }]
        );
        let shown = warnings[0].to_string();
        assert!(shown.contains("possible correlation source"), "{shown}");
        assert!(shown.contains("may accept"), "{shown}");
    }

    #[test]
    fn a_shared_domain_is_warned_about() {
        let warnings = check(
            "community-a",
            Some("did:webvh:QmW:witness.operator.example:a"),
            "did:webvh:QmOTHER:mediator.elsewhere.example",
            &operator(),
        );
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(matches!(
            &warnings[0],
            CorrelationWarning::SharedDomain { witness_host, vta_host, .. }
                if witness_host == "witness.operator.example" && vta_host == "vta.operator.example"
        ));
        assert!(
            warnings[0]
                .to_string()
                .contains("possible correlation source")
        );
    }

    #[test]
    fn an_independent_witness_draws_no_warning() {
        let warnings = check(
            "community-a",
            Some("did:webvh:QmW:witness.independent.example:a"),
            "did:webvh:QmOTHER:mediator.elsewhere.example",
            &operator(),
        );
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    /// With no DID yet (before setup mints it) only the mediator can be checked.
    #[test]
    fn before_the_mint_only_the_mediator_is_checked() {
        let warnings = check("a", None, VTA_MEDIATOR, &operator());
        assert_eq!(warnings.len(), 1);
        assert!(matches!(
            warnings[0],
            CorrelationWarning::SharedMediator { .. }
        ));
    }

    #[test]
    fn domain_sharing_rules() {
        assert!(shares_domain("example.com", "example.com"));
        assert!(shares_domain("a.example.com", "example.com"));
        assert!(shares_domain("a.example.com", "b.example.com"));
        assert!(!shares_domain("example.com", "example.org"));
        assert!(!shares_domain("notexample.com", "example.com"));
        assert!(!shares_domain("10.0.0.1", "10.0.0.2"));
        assert!(!shares_domain("localhost", "otherhost"));
    }
}
