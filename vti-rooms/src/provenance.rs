//! A record's provenance and expiry — `basis`, `confidence`, `evidence`, `validFor` and
//! `validUntil` (`rooms/_shared/0.1` `SealedRecordBody`, *Provenance* and *Expiry*;
//! trust-tasks-tf #865).
//!
//! # What these are, and what they are not
//!
//! They say what kind of claim a record is — an observed fact, the author's own statement,
//! something checked against a credential, an agent's inference — what it cites, what it may
//! be used for, and when its author stops standing behind it. **Display and weighting only,
//! never authority**: nothing here grants, widens or evidences a permission, `verified` never
//! stands in for checking what `evidence` names, and nothing `evidence` names is ever fetched.
//!
//! On the sealed tiers they live inside the author's signed body, where a host never sees
//! them; on an `open` room they ride `rooms/records/put` 0.3's `cleartext`, stored and served
//! exactly as received. Either way **expiry is a reader's rule**: a reader hides a record past
//! its `validUntil` from default listings, search and recall, and shows it only on an explicit
//! request, marked expired. No host acts on it.
//!
//! # Why the values are kept as received
//!
//! A sealed body is verified against its signature as JSON, and an open record is served as
//! the writer sent it. A typed round trip would rewrite what it did not understand — a
//! `validUntil` in another RFC 3339 spelling, a confidence of `0.50` as `0.5` — so the members
//! are held as their JSON and **checked** against the specification's generated types
//! ([`check`]) rather than replaced by them.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use trust_tasks_rs::specs::rooms::records::put::v0_3 as spec;

/// The five members, as they are spelled on the wire.
pub const MEMBERS: [&str; 5] = ["basis", "confidence", "evidence", "validFor", "validUntil"];

/// What kind of claim a record is, as its author states it (`RecordBasis`).
///
/// Absent means the author did not say — never one of these by default — and a reader shows
/// it as unstated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum RecordBasis {
    /// The author's own statement: a decision, a preference, a commitment.
    Declared,
    /// Something the author saw, measured or was told directly.
    Observed,
    /// Checked against evidence somebody else can check again. One that names no `evidence`
    /// is an unsupported claim to have checked, and is shown so.
    Verified,
    /// Derived by reasoning: an agent's conclusion, a summary's generalisation.
    Inferred,
}

impl RecordBasis {
    /// The wire value.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Observed => "observed",
            Self::Verified => "verified",
            Self::Inferred => "inferred",
        }
    }
}

impl std::str::FromStr for RecordBasis {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "declared" => Ok(Self::Declared),
            "observed" => Ok(Self::Observed),
            "verified" => Ok(Self::Verified),
            "inferred" => Ok(Self::Inferred),
            other => Err(format!(
                "`{other}` is not a record basis: declared, observed, verified or inferred"
            )),
        }
    }
}

impl std::fmt::Display for RecordBasis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Check every provenance member `object` carries against the specification's own types:
/// `basis` one of the four, `confidence` in `[0, 1]`, `evidence` 1–32 citations each a record
/// or a credential, `validFor` at least one of 1–8 unique absolute IRIs or a 1–512 character
/// note, `validUntil` an RFC 3339 instant. Members other than these five are not looked at.
///
/// `Err` names the member and why, for a writer's or a key holder's refusal.
pub fn check(object: &Map<String, Value>) -> Result<(), String> {
    fn one<T: serde::de::DeserializeOwned>(
        object: &Map<String, Value>,
        member: &str,
    ) -> Result<(), String> {
        match object.get(member) {
            None => Ok(()),
            Some(v) => serde_json::from_value::<T>(v.clone())
                .map(|_| ())
                .map_err(|e| format!("`{member}` is not what the specification allows: {e}")),
        }
    }
    // The schema itself first: the generated types do not carry every bound it states
    // (`confidence` in [0, 1], `uniqueItems`). The members are checked inside the one
    // payload that publishes them all, `rooms/records/put/0.3`'s open-room `cleartext`.
    // One member per probe, so a refusal names the member it is about.
    for member in MEMBERS {
        let Some(v) = object.get(member) else {
            continue;
        };
        let probe = serde_json::json!({
            "roomId": "did:example:room",
            "key": "k",
            "presentation": { "membership": "m", "authority": ["a"] },
            "cleartext": { "body": "", member: v },
        });
        if let Err(e) =
            <spec::Payload as trust_tasks_rs::validate::ValidatedPayload>::validate_value(&probe)
        {
            return Err(format!(
                "`{member}` is not what the specification allows: {}",
                e.messages().join("; ")
            ));
        }
    }
    one::<spec::RecordBasis>(object, "basis")?;
    one::<spec::RecordConfidence>(object, "confidence")?;
    one::<spec::RecordEvidenceList>(object, "evidence")?;
    one::<spec::PermittedUse>(object, "validFor")?;
    one::<spec::RecordValidUntil>(object, "validUntil")?;
    // The generated `PermittedUse` does not enforce `uniqueItems` on `purposes`; the schema
    // does, and a set is what the author meant.
    if let Some(purposes) = object
        .get("validFor")
        .and_then(|v| v.get("purposes"))
        .and_then(Value::as_array)
    {
        let mut seen = std::collections::HashSet::new();
        if !purposes.iter().all(|p| seen.insert(p.to_string())) {
            return Err("`validFor.purposes` names a purpose twice; it is a set".into());
        }
    }
    Ok(())
}

/// The basis `object` states, if it states one this crate knows.
pub fn basis(object: &Map<String, Value>) -> Option<RecordBasis> {
    object
        .get("basis")
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
}

/// When `object`'s author stops standing behind it as current, if they said.
pub fn valid_until(object: &Map<String, Value>) -> Option<chrono::DateTime<chrono::Utc>> {
    object
        .get("validUntil")
        .and_then(Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&chrono::Utc))
}

/// Whether `object` has expired at `now`: its `validUntil` is **at or before** `now`
/// (`SealedRecordBody`, *Expiry*). A reader leaves an expired record out of a default
/// listing, search, browse or recall, and shows it only when asked for expired records,
/// marked as such. Expiry hides; it never deletes.
pub fn is_expired(object: &Map<String, Value>, now: chrono::DateTime<chrono::Utc>) -> bool {
    valid_until(object).is_some_and(|until| until <= now)
}

/// Whether `object` carries any provenance member at all.
pub fn carries_any(object: &Map<String, Value>) -> bool {
    MEMBERS.iter().any(|m| object.contains_key(*m))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn the_basis_values_are_the_specifications() {
        for b in [
            RecordBasis::Declared,
            RecordBasis::Observed,
            RecordBasis::Verified,
            RecordBasis::Inferred,
        ] {
            let wire = serde_json::to_value(b).unwrap();
            serde_json::from_value::<spec::RecordBasis>(wire.clone())
                .unwrap_or_else(|e| panic!("{wire} is not a published basis: {e}"));
            assert_eq!(b.as_str().parse::<RecordBasis>().unwrap(), b);
        }
    }

    #[test]
    fn a_whole_provenance_checks() {
        let o = obj(json!({
            "basis": "inferred",
            "confidence": 0.6,
            "evidence": [
                { "kind": "record", "key": "meetings/2026-10-08", "version": 3 },
                { "kind": "credential", "credentialId": "urn:uuid:1" }
            ],
            "validFor": {
                "purposes": ["https://w3id.org/dpv#ServicePersonalisation"],
                "note": "renewal negotiation only"
            },
            "validUntil": "2026-12-31T23:59:59Z"
        }));
        check(&o).unwrap();
        assert_eq!(basis(&o), Some(RecordBasis::Inferred));
        assert!(carries_any(&o));
    }

    #[test]
    fn what_the_schema_refuses_is_refused() {
        for (bad, why) in [
            (json!({ "basis": "rumoured" }), "basis"),
            (json!({ "confidence": 1.5 }), "confidence"),
            (json!({ "confidence": -0.1 }), "confidence"),
            (json!({ "evidence": [] }), "evidence"),
            (
                json!({ "evidence": [{ "kind": "url", "href": "x" }] }),
                "evidence",
            ),
            (json!({ "validFor": {} }), "validFor"),
            (
                json!({ "validFor": { "purposes": ["a:b", "a:b"] } }),
                "validFor",
            ),
            (json!({ "validUntil": "next tuesday" }), "validUntil"),
        ] {
            let e = check(&obj(bad.clone())).expect_err(&format!("{bad} must be refused"));
            assert!(e.contains(why), "{bad}: {e}");
        }
    }

    #[test]
    fn expiry_is_at_or_before_now() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-22T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert!(is_expired(
            &obj(json!({ "validUntil": "2026-10-22T00:00:00Z" })),
            now
        ));
        assert!(is_expired(
            &obj(json!({ "validUntil": "2026-10-21T23:59:59+00:00" })),
            now
        ));
        assert!(!is_expired(
            &obj(json!({ "validUntil": "2026-10-22T00:00:01Z" })),
            now
        ));
        // Absent means it does not expire.
        assert!(!is_expired(&obj(json!({ "body": "x" })), now));
        assert!(!carries_any(&obj(json!({ "body": "x" }))));
    }
}
