//! swiyu trust statements a verifier identity carries in `verifier_info`.
//!
//! Under swiyu Trust Protocol 2.0 the verifier tells the wallet who it is by
//! adding the statements the trust registry issued about it to every request
//! object's `verifier_info`, each as `{"format": "jwt", "data": <JWS>}`: its
//! Identity Trust Statement first, then any Protected Verification
//! Authorization Trust Statement. The wallet verifies them against the
//! registry; this module only checks, when the operator installs one, that it
//! is a statement about **this** identity and still current, so a statement
//! for another DID or one already expired is caught at install rather than by
//! every wallet that refuses it.
//!
//! A Verification Query Public Statement is not accepted yet: it describes one
//! query, and the swiyu Profile pairs it with `scope` in place of the DCQL
//! query the VTC sends per criterion.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

/// `typ` of an Identity Trust Statement.
pub const IDENTITY_TYP: &str = "swiyu-identity-trust-statement+jwt";
/// `typ` of a Protected Verification Authorization Trust Statement.
pub const PROTECTED_VERIFICATION_TYP: &str =
    "swiyu-protected-verification-authorization-trust-statement+jwt";
/// `typ` of a Verification Query Public Statement.
pub const VERIFICATION_QUERY_TYP: &str = "swiyu-verification-query-public-statement+jwt";

/// The `verifier_info` format of a swiyu trust statement.
pub const FORMAT: &str = "jwt";

/// Which statement it is. The order is the order `verifier_info` carries them
/// in: a wallet reads the identity statement first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StatementKind {
    Identity,
    ProtectedVerification,
}

impl StatementKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Identity => "identity trust statement",
            Self::ProtectedVerification => "protected verification authorization",
        }
    }
}

/// A statement that names the identity and is current.
#[derive(Clone)]
pub struct CheckedStatement {
    pub kind: StatementKind,
    /// The compact JWS, as issued.
    pub jwt: String,
    /// `jti`, which tells two protected-verification statements apart.
    pub jti: Option<String>,
    /// `exp`, seconds since the epoch.
    pub exp: i64,
}

impl std::fmt::Debug for CheckedStatement {
    /// Written by hand: the token is public, but a log line needs only which
    /// statement and until when, not the whole JWS.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckedStatement")
            .field("kind", &self.kind)
            .field("jti", &self.jti)
            .field("exp", &self.exp)
            .finish_non_exhaustive()
    }
}

impl CheckedStatement {
    /// Its `verifier_info` entry.
    pub fn entry(&self) -> Value {
        json!({ "format": FORMAT, "data": self.jwt })
    }
}

fn segment(jwt: &str, n: usize) -> Result<Value, String> {
    let part = jwt
        .split('.')
        .nth(n)
        .ok_or("not a compact JWS (three dot-separated parts)")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| "a JWS part is not base64url")?;
    serde_json::from_slice(&bytes).map_err(|_| "a JWS part is not JSON".to_string())
}

/// Read one statement and check it is about `did` and current at `now`.
pub fn check(jwt: &str, did: &str, now: i64) -> Result<CheckedStatement, String> {
    let jwt = jwt.trim();
    if jwt.split('.').count() != 3 {
        return Err("not a compact JWS (three dot-separated parts)".into());
    }
    let header = segment(jwt, 0)?;
    let payload = segment(jwt, 1)?;
    let kind = match header.get("typ").and_then(Value::as_str) {
        Some(IDENTITY_TYP) => StatementKind::Identity,
        Some(PROTECTED_VERIFICATION_TYP) => StatementKind::ProtectedVerification,
        Some(VERIFICATION_QUERY_TYP) => {
            return Err(
                "a verification query public statement describes one query, and the \
                        VTC asks by each criterion's DCQL query, not by scope; it is not \
                        carried yet"
                    .into(),
            );
        }
        Some(other) => return Err(format!("`typ` `{other}` is not a swiyu trust statement")),
        None => return Err("the header has no `typ`".into()),
    };
    let sub = payload.get("sub").and_then(Value::as_str).unwrap_or("");
    if sub != did {
        return Err(format!(
            "it is about `{sub}`, not this identity's DID `{did}`"
        ));
    }
    let exp = payload
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or("it has no `exp`")?;
    if exp <= now {
        return Err(format!("it expired at {}", timestamp(exp)));
    }
    Ok(CheckedStatement {
        kind,
        jwt: jwt.to_string(),
        jti: payload
            .get("jti")
            .and_then(Value::as_str)
            .map(str::to_string),
        exp,
    })
}

/// `entries` with `statement` added: an identity statement replaces the one
/// held, a protected-verification statement replaces one with the same `jti`.
/// Statements come first, identity first; any other entry keeps its place
/// after them.
pub fn merge(entries: &[Value], statement: &CheckedStatement) -> Vec<Value> {
    let mut statements: Vec<CheckedStatement> = Vec::new();
    let mut others = Vec::new();
    for entry in entries {
        match held(entry) {
            Some(s) => statements.push(s),
            None => others.push(entry.clone()),
        }
    }
    statements.retain(|s| {
        s.kind != statement.kind
            || (s.kind == StatementKind::ProtectedVerification && s.jti != statement.jti)
    });
    statements.push(statement.clone());
    statements.sort_by_key(|s| s.kind);
    statements
        .iter()
        .map(CheckedStatement::entry)
        .chain(others)
        .collect()
}

/// A held `verifier_info` entry read back as a statement, unchecked.
pub fn held(entry: &Value) -> Option<CheckedStatement> {
    if entry.get("format").and_then(Value::as_str) != Some(FORMAT) {
        return None;
    }
    let jwt = entry.get("data").and_then(Value::as_str)?;
    let header = segment(jwt, 0).ok()?;
    let payload = segment(jwt, 1).ok()?;
    let kind = match header.get("typ").and_then(Value::as_str)? {
        IDENTITY_TYP => StatementKind::Identity,
        PROTECTED_VERIFICATION_TYP => StatementKind::ProtectedVerification,
        _ => return None,
    };
    Some(CheckedStatement {
        kind,
        jwt: jwt.to_string(),
        jti: payload
            .get("jti")
            .and_then(Value::as_str)
            .map(str::to_string),
        exp: payload.get("exp").and_then(Value::as_i64).unwrap_or(0),
    })
}

/// What a request object carries: every entry but an expired statement, which
/// a wallet would refuse and which would make the whole request look forged.
/// Returns the entries and the statements left out.
pub fn current(entries: &[Value], now: i64) -> (Vec<Value>, Vec<CheckedStatement>) {
    let mut kept = Vec::new();
    let mut expired = Vec::new();
    for entry in entries {
        match held(entry) {
            Some(s) if s.exp <= now => expired.push(s),
            _ => kept.push(entry.clone()),
        }
    }
    (kept, expired)
}

/// `exp` for a person to read.
pub fn timestamp(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|t| t.to_rfc3339())
        .unwrap_or_else(|| secs.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:webvh:QmScid:example.org:verifier";
    const NOW: i64 = 1_800_000_000;

    fn statement(typ: &str, sub: &str, exp: i64, jti: &str) -> String {
        let enc = |v: Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(&v).unwrap());
        format!(
            "{}.{}.c2ln",
            enc(json!({ "typ": typ, "alg": "ES256", "kid": "did:webvh:registry#key-1" })),
            enc(json!({ "sub": sub, "exp": exp, "iat": NOW - 10, "jti": jti }))
        )
    }

    #[test]
    fn a_current_statement_about_the_identity_is_accepted() {
        let s = check(&statement(IDENTITY_TYP, DID, NOW + 60, "a"), DID, NOW).unwrap();
        assert_eq!(s.kind, StatementKind::Identity);
        assert_eq!(s.entry()["format"], "jwt");
    }

    #[test]
    fn a_statement_for_another_did_expired_or_of_another_kind_is_refused() {
        for (jwt, says) in [
            (
                statement(IDENTITY_TYP, "did:webvh:other", NOW + 60, "a"),
                "not this identity",
            ),
            (statement(IDENTITY_TYP, DID, NOW, "a"), "expired"),
            (
                statement(VERIFICATION_QUERY_TYP, DID, NOW + 60, "a"),
                "one query",
            ),
            (
                statement("JWT", DID, NOW + 60, "a"),
                "not a swiyu trust statement",
            ),
            ("not-a-jws".to_string(), "compact JWS"),
        ] {
            let err = check(&jwt, DID, NOW).unwrap_err();
            assert!(err.contains(says), "{says}: {err}");
        }
    }

    /// The identity statement leads, as the wallet reads it; a new one
    /// replaces it, and protected-verification statements are told apart by
    /// `jti`. Another ecosystem's entry is kept after them.
    #[test]
    fn statements_merge_in_the_order_a_wallet_reads_them() {
        let other = json!({ "format": "registration_cert", "data": "x" });
        let pva1 = check(
            &statement(PROTECTED_VERIFICATION_TYP, DID, NOW + 60, "p1"),
            DID,
            NOW,
        )
        .unwrap();
        let id1 = check(&statement(IDENTITY_TYP, DID, NOW + 60, "i1"), DID, NOW).unwrap();
        let id2 = check(&statement(IDENTITY_TYP, DID, NOW + 90, "i2"), DID, NOW).unwrap();
        let pva2 = check(
            &statement(PROTECTED_VERIFICATION_TYP, DID, NOW + 60, "p2"),
            DID,
            NOW,
        )
        .unwrap();

        let mut entries = vec![other.clone()];
        for s in [&pva1, &id1, &id2, &pva2, &pva1] {
            entries = merge(&entries, s);
        }
        let data: Vec<&str> = entries
            .iter()
            .map(|e| e["data"].as_str().unwrap())
            .collect();
        assert_eq!(
            data,
            [id2.jwt.as_str(), pva2.jwt.as_str(), pva1.jwt.as_str(), "x"]
        );
    }

    #[test]
    fn an_expired_statement_is_left_out_of_the_request() {
        let live = check(&statement(IDENTITY_TYP, DID, NOW + 60, "i"), DID, NOW).unwrap();
        let entries = vec![live.entry(), json!({ "format": "other", "data": "x" })];
        let (kept, expired) = current(&entries, NOW);
        assert_eq!(kept.len(), 2);
        assert!(expired.is_empty());
        let (kept, expired) = current(&entries, NOW + 60);
        assert_eq!(kept, vec![json!({ "format": "other", "data": "x" })]);
        assert_eq!(expired.len(), 1);
    }
}
