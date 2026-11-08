//! The largest document each type may be, decided before the body is parsed.
//!
//! The body is attacker-supplied and arrives unauthenticated, so the size cap
//! is what bounds the parsing, schema validation and proof verification the
//! spine does before it knows who is asking. A body no larger than the default
//! is admitted without looking at it; a larger one has only its top-level
//! `type` (and, for a service that grants raised limits by standing, `issuer`)
//! read, by a scan that keeps no other member.
//!
//! The spine asks a [`SizeGate`]. [`SizeTable`] is the plain per-type table; a
//! service whose raised limits depend on who claims to be sending (and charges
//! a budget for granting them before the claim is verified) implements the
//! trait itself and settles the [`SizeCharge`] once the proof has been checked.

use std::any::Any;

use trust_tasks_rs::{ErrorPayload, RejectReason};

use crate::TrustTaskOutcome;
use crate::reject::unrouted_error_response;

/// The default document limit: 64 KiB — generous for a document of
/// identifiers, a credential or a presentation, and small enough that an
/// unauthenticated flood of them is cheap to refuse.
pub const DEFAULT_MAX_DOCUMENT_BYTES: usize = 64 * 1024;

/// The `details` member naming the limit a refused document exceeded.
pub const DETAILS_MAX_BYTES: &str = "maxBytes";

/// The longest `type` a refusal names. A caller's own `type` is echoed back
/// only when it is short enough to be a Type URI.
const MAX_NAMED_TYPE_CHARS: usize = 256;

/// Something a [`SizeGate`] charged before the document's proof was verified,
/// handed back to [`SizeGate::settle`] once verification concludes.
pub struct SizeCharge(Box<dyn Any + Send + Sync>);

impl SizeCharge {
    /// Wrap the gate's own charge record.
    pub fn new<T: Any + Send + Sync>(charge: T) -> Self {
        Self(Box::new(charge))
    }

    /// The gate's own record, if it is a `T`.
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        self.0.downcast_ref()
    }
}

impl std::fmt::Debug for SizeCharge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SizeCharge(..)")
    }
}

/// The spine's step 0: admit `body`, or refuse it for its size before it is
/// parsed.
#[async_trait::async_trait]
pub trait SizeGate: Send + Sync {
    /// `Ok(None)` admits with nothing to settle; `Ok(Some(charge))` admits with
    /// a charge the spine settles after proof verification; `Err` is the
    /// refusal to answer.
    async fn admit(&self, body: &[u8]) -> Result<Option<SizeCharge>, TrustTaskOutcome>;

    /// Settle `charge` once the document's proof verification concludes:
    /// `verified_signer` is the proven signer, or `None` when verification
    /// failed or the document carried no proof.
    fn settle(&self, _charge: &SizeCharge, _verified_signer: Option<&str>) {}
}

/// A per-type table: `limit(type_uri)` for a type that declares one, `default`
/// otherwise. No charge, no standing — every caller is held to the same table.
pub struct SizeTable<F> {
    default: usize,
    limit: F,
}

impl<F> SizeTable<F>
where
    F: Fn(&str) -> Option<usize> + Send + Sync,
{
    /// A table answering `limit` per type, and `default` for anything it does
    /// not name (and for a body whose `type` cannot be read).
    pub fn new(default: usize, limit: F) -> Self {
        Self { default, limit }
    }
}

/// The table every type is held to [`DEFAULT_MAX_DOCUMENT_BYTES`] by.
pub fn default_size_table() -> SizeTable<fn(&str) -> Option<usize>> {
    SizeTable::new(DEFAULT_MAX_DOCUMENT_BYTES, |_| None)
}

#[async_trait::async_trait]
impl<F> SizeGate for SizeTable<F>
where
    F: Fn(&str) -> Option<usize> + Send + Sync,
{
    async fn admit(&self, body: &[u8]) -> Result<Option<SizeCharge>, TrustTaskOutcome> {
        check_size(body, self.default, |t| {
            (self.limit)(t).unwrap_or(self.default)
        })?;
        Ok(None)
    }
}

/// Admit `body` if it is at most `default` bytes, or at most `limit(type)` for
/// its peeked `type`; otherwise the unrouted `malformedRequest` refusal naming
/// the limit under `details.maxBytes`.
pub fn check_size(
    body: &[u8],
    default: usize,
    limit: impl Fn(&str) -> usize,
) -> Result<(), TrustTaskOutcome> {
    if body.len() <= default {
        return Ok(());
    }
    let type_uri = peek_type(body);
    let max = type_uri.as_deref().map_or(default, &limit);
    if body.len() <= max {
        return Ok(());
    }
    let named = match type_uri.as_deref() {
        Some(t) if t.chars().count() <= MAX_NAMED_TYPE_CHARS => t,
        Some(_) => "its type",
        None => "a document of no readable type",
    };
    let payload: ErrorPayload = RejectReason::MalformedRequest {
        reason: format!(
            "the document is {} bytes; {named} accepts at most {max}",
            body.len()
        ),
    }
    .into();
    Err(unrouted_error_response(payload.with_details(
        serde_json::json!({ DETAILS_MAX_BYTES: max }),
    )))
}

/// The document's top-level `type`, read without keeping anything else.
///
/// `None` for a body that is not a JSON object with a string `type`.
pub fn peek_type(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct TypeOnly {
        #[serde(rename = "type")]
        type_uri: String,
    }
    serde_json::from_slice::<TypeOnly>(body)
        .ok()
        .map(|t| t.type_uri)
}

/// The document's top-level `issuer`, read the same way as [`peek_type`]: a
/// duplicated or non-string one reads as none.
pub fn peek_issuer(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct IssuerOnly {
        issuer: String,
    }
    serde_json::from_slice::<IssuerOnly>(body)
        .ok()
        .map(|t| t.issuer)
}
