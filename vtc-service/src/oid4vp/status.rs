//! What the administrators see of the community's OpenID4VP verifier —
//! `vtc/oid4vp/identities/list/0.1` (#1988).
//!
//! A verifier identity is assembled out of band from parts that each expire or
//! break on their own: the key (cached, or kept by the VTA and signed over the
//! link to it), an EUDI access certificate, swiyu trust statements. A wallet
//! that refuses a request object tells the community nothing, so this reads
//! every part and names what is wrong in the specification's fixed vocabulary,
//! with the command that fixes it.
//!
//! It never reports key material, nor the id of a key the VTA keeps
//! (consumer rule 2).

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, TimeZone, Utc};
use serde_json::Value;
use trust_tasks_rs::specs::vtc::oid4vp::identities::list::v0_1 as list;
use vti_common::error::AppError;

use super::trust_statement::{self, StatementKind};
use super::{KeyCustody, VerifierIdentityRecord, VerifierKind, VerifierSigners};
use crate::server::AppState;

/// How long before a certificate or statement expires it is reported
/// (consumer rule 6 recommends thirty days): enough to obtain a new one.
pub const EXPIRY_WARNING: Duration = Duration::days(30);

/// The report for a running VTC.
pub async fn read(state: &AppState, now: DateTime<Utc>) -> Result<list::Response, AppError> {
    let (default_identity, public_url) = {
        let config = state.config.read().await;
        (
            config.oid4vp.default_identity.clone(),
            config.public_url.clone(),
        )
    };
    let records = super::list_identities(&state.oid4vp_keys_ks).await?;
    report(
        &records,
        &state.oid4vp_signers,
        default_identity.as_deref(),
        public_url.as_deref(),
        now,
    )
    .map_err(|e| AppError::Internal(format!("oid4vp/identities/list: {e}")))
}

fn problem(
    code: list::ProblemCode,
    severity: list::ProblemSeverity,
    detail: String,
) -> Result<list::Problem, String> {
    list::Problem::builder()
        .code(code)
        .severity(severity)
        // Prose for a person; cut rather than fail at the schema's bound.
        .detail(list::ProblemDetail::try_from(truncate(detail)).ok())
        .try_into()
        .map_err(|e| format!("{e}"))
}

fn error(code: list::ProblemCode, detail: String) -> Result<list::Problem, String> {
    problem(code, list::ProblemSeverity::Error, detail)
}

fn warning(code: list::ProblemCode, detail: String) -> Result<list::Problem, String> {
    problem(code, list::ProblemSeverity::Warning, detail)
}

fn truncate(mut s: String) -> String {
    const MAX: usize = 1024;
    if s.chars().count() > MAX {
        s = s.chars().take(MAX - 1).collect::<String>() + "…";
    }
    s
}

fn at(secs: i64) -> Option<DateTime<Utc>> {
    Utc.timestamp_opt(secs, 0).single()
}

/// The `exp` of a compact JWT, read without verifying it — the expiry an
/// administrator needs to see, not a judgement of the token.
fn jwt_exp(jwt: &str) -> Option<i64> {
    let payload = URL_SAFE_NO_PAD.decode(jwt.split('.').nth(1)?).ok()?;
    serde_json::from_slice::<Value>(&payload)
        .ok()?
        .get("exp")?
        .as_i64()
}

/// One `verifier_info` entry: which attestation it is, and when it expires.
fn attestation_of(kind: VerifierKind, entry: &Value) -> (list::AttestationKind, Option<i64>) {
    if let Some(s) = trust_statement::held(entry) {
        let kind = match s.kind {
            StatementKind::Identity => list::AttestationKind::IdentityTrustStatement,
            StatementKind::ProtectedVerification => {
                list::AttestationKind::ProtectedVerificationAuthorization
            }
        };
        return (kind, (s.exp > 0).then_some(s.exp));
    }
    let exp = entry.get("data").and_then(Value::as_str).and_then(jwt_exp);
    // An EUDI identity's only other entry is the registration certificate
    // `vtc oid4vp certificate --registration` installs.
    match kind {
        VerifierKind::Eudi => (list::AttestationKind::RegistrationCertificate, exp),
        VerifierKind::Swiyu => (list::AttestationKind::Other, exp),
    }
}

fn label(kind: list::AttestationKind) -> &'static str {
    match kind {
        list::AttestationKind::IdentityTrustStatement => "identity trust statement",
        list::AttestationKind::ProtectedVerificationAuthorization => {
            "protected verification authorization"
        }
        list::AttestationKind::RegistrationCertificate => "registration certificate",
        _ => "verifier_info entry",
    }
}

/// What the access certificate's leaf says, or why it says nothing.
struct Leaf {
    subject: String,
    issuer: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

fn leaf_of(x5c: &[String]) -> Result<Leaf, String> {
    let der = STANDARD
        .decode(x5c.first().ok_or("the chain is empty")?)
        .map_err(|e| format!("the leaf is not base64: {e}"))?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| format!("the leaf does not parse: {e}"))?;
    let validity = cert.validity();
    Ok(Leaf {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        not_before: at(validity.not_before.timestamp()).ok_or("notBefore is out of range")?,
        not_after: at(validity.not_after.timestamp()).ok_or("notAfter is out of range")?,
    })
}

/// One identity, without `isDefault` (which depends on the others).
fn identity(
    record: &VerifierIdentityRecord,
    signers: &VerifierSigners,
    now: DateTime<Utc>,
) -> Result<(list::builder::Identity, bool), String> {
    use list::ProblemCode as C;
    let id = &record.id;
    let mut problems = Vec::new();

    let custody = match record.custody() {
        Ok(KeyCustody::Local(_)) => list::IdentityCustody::Cached,
        Ok(KeyCustody::Vta(_)) => list::IdentityCustody::Agent,
        Err(e) => {
            problems.push(error(
                C::KeyCustodyInvalid,
                format!(
                    "{e}; remove it with `vtc oid4vp remove --identity {id}` and install it again"
                ),
            )?);
            list::IdentityCustody::Invalid
        }
    };
    if custody != list::IdentityCustody::Invalid {
        match signers.get(id) {
            None => problems.push(error(
                C::SignerNotLoaded,
                "the running VTC has no signer for it — it was installed after start; restart \
                 the VTC to load it"
                    .into(),
            )?),
            Some(signer) if !signer.can_sign() => problems.push(error(
                C::AgentLinkMissing,
                "the VTA keeps this key and the VTC has no link to it: check the VTC's messaging \
                 and that its DID holds `sign-jws` in the key's context at the VTA"
                    .into(),
            )?),
            Some(_) => {}
        }
    }

    let mut certificate = None;
    if record.kind == VerifierKind::Eudi {
        match record.x5c.as_deref() {
            None | Some([]) => problems.push(error(
                C::CertificateMissing,
                format!(
                    "no access certificate is installed: request one with `vtc oid4vp csr \
                     --identity {id}` and install the registrar's chain with `vtc oid4vp \
                     certificate --identity {id}`"
                ),
            )?),
            Some(x5c) => match leaf_of(x5c) {
                Err(e) => problems.push(error(
                    C::CertificateMissing,
                    format!(
                        "the installed access certificate is unreadable ({e}); install the \
                         registrar's chain again with `vtc oid4vp certificate --identity {id}`"
                    ),
                )?),
                Ok(leaf) => {
                    let renew = format!("request a new one with `vtc oid4vp csr --identity {id}`");
                    if now < leaf.not_before {
                        problems.push(error(
                            C::CertificateNotYetValid,
                            format!("the access certificate is valid from {}", leaf.not_before),
                        )?);
                    } else if now >= leaf.not_after {
                        problems.push(error(
                            C::CertificateExpired,
                            format!("the access certificate expired {}; {renew}", leaf.not_after),
                        )?);
                    } else if leaf.not_after - now <= EXPIRY_WARNING {
                        problems.push(warning(
                            C::CertificateExpiresSoon,
                            format!("the access certificate expires {}; {renew}", leaf.not_after),
                        )?);
                    }
                    let chain_length =
                        std::num::NonZeroU64::new(x5c.len() as u64).ok_or("the chain is empty")?;
                    certificate = Some(
                        list::Certificate::builder()
                            .subject(
                                list::CertificateSubject::try_from(truncate(leaf.subject)).ok(),
                            )
                            .issuer(list::CertificateIssuer::try_from(truncate(leaf.issuer)).ok())
                            .not_before(leaf.not_before)
                            .not_after(leaf.not_after)
                            .chain_length(chain_length)
                            .try_into()
                            .map_err(|e| format!("{e}"))?,
                    );
                }
            },
        }
    }

    let mut attestations = Vec::new();
    let mut current_identity_statement = false;
    let fix = format!("install a new one with `vtc oid4vp trust-statement --identity {id}`");
    for entry in record.verifier_info.as_deref().unwrap_or_default() {
        let (kind, exp) = attestation_of(record.kind, entry);
        let expires_at = exp.and_then(at);
        match expires_at {
            Some(exp) if exp <= now => problems.push(warning(
                C::StatementExpired,
                format!(
                    "its {} expired {exp} and is left out of every request; {fix}",
                    label(kind)
                ),
            )?),
            Some(exp) if exp - now <= EXPIRY_WARNING => problems.push(warning(
                C::StatementExpiresSoon,
                format!("its {} expires {exp}; {fix}", label(kind)),
            )?),
            _ => {}
        }
        if kind == list::AttestationKind::IdentityTrustStatement
            && expires_at.is_none_or(|exp| exp > now)
        {
            current_identity_statement = true;
        }
        attestations.push(
            list::Attestation::builder()
                .kind(kind)
                .expires_at(expires_at)
                .try_into()
                .map_err(|e| format!("{e}"))?,
        );
    }
    if record.kind == VerifierKind::Swiyu && !current_identity_statement {
        problems.push(warning(
            C::IdentityStatementMissing,
            format!(
                "it carries no current identity trust statement, which swiyu wallets under \
                 Trust Protocol 2.0 require: fetch it from the trust registry and {}",
                fix.replace("a new one", "it")
            ),
        )?);
    }

    let usable = !problems
        .iter()
        .any(|p| p.severity == list::ProblemSeverity::Error);
    let (did, key_id) = match record.kind {
        VerifierKind::Swiyu => (record.did.clone(), record.kid.clone()),
        VerifierKind::Eudi => (None, None),
    };
    let builder = list::Identity::builder()
        .id(list::IdentityId::try_from(id.clone()).map_err(|e| format!("{e}"))?)
        .kind(match record.kind {
            VerifierKind::Swiyu => list::IdentityKind::Swiyu,
            VerifierKind::Eudi => list::IdentityKind::Eudi,
        })
        .client_id(record.client_id())
        .did(did)
        .key_id(key_id)
        .custody(custody)
        .certificate(certificate)
        .attestations(attestations)
        .problems(problems)
        .installed_at(at(record.installed_at as i64).unwrap_or_default());
    Ok((builder, usable))
}

/// The response, from the stored records, the signers this process loaded and
/// the configuration.
pub fn report(
    records: &[VerifierIdentityRecord],
    signers: &VerifierSigners,
    default_identity: Option<&str>,
    public_url: Option<&str>,
    now: DateTime<Utc>,
) -> Result<list::Response, String> {
    use list::ProblemCode as C;
    let mut problems = Vec::new();
    let reachable = public_url.is_some_and(|u| u.starts_with("https://"));
    if !reachable {
        problems.push(error(
            C::NoPublicUrl,
            "a wallet fetches the request and posts its answer over https: set `public_url` to \
             the community's https address"
                .into(),
        )?);
    }

    // The identity a session naming no prefix is opened on, chosen as
    // `wallet::start` chooses it: among those with a signer and a client id,
    // the configured default, or else the first.
    let selectable =
        |r: &VerifierIdentityRecord| signers.contains_key(&r.id) && r.client_id().is_some();
    let default = match default_identity {
        Some(id) => records.iter().find(|r| r.id == id && selectable(r)),
        None => records.iter().find(|r| selectable(r)),
    };
    if let (Some(id), None) = (default_identity, default) {
        problems.push(error(
            C::DefaultIdentityNotInstalled,
            format!(
                "`[oid4vp] default_identity = \"{id}\"` names no installed identity with a \
                 signer and a client identifier, so a session that names no client identifier \
                 prefix is refused"
            ),
        )?);
    }

    let mut identities = Vec::with_capacity(records.len());
    for record in records {
        let (builder, usable) = identity(record, signers, now)?;
        let is_default = default.is_some_and(|d| d.id == record.id);
        identities.push(
            builder
                .usable(usable && reachable)
                .is_default(is_default)
                .try_into()
                .map_err(|e| format!("{e}"))?,
        );
    }

    list::Response::builder()
        .identities(identities)
        .default_identity(default_identity.map(str::to_string))
        .problems(problems)
        .try_into()
        .map_err(|e| format!("{e}"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::oid4vp::tests::p256_record;
    use crate::oid4vp::{LocalP256Signer, VerifierSigner};

    const URL: Option<&str> = Some("https://community.example");

    fn now() -> DateTime<Utc> {
        Utc.timestamp_opt(1_800_000_000, 0).unwrap()
    }

    fn loaded(records: &[&VerifierIdentityRecord]) -> VerifierSigners {
        records
            .iter()
            .map(|r| {
                let s: Arc<dyn VerifierSigner> = Arc::new(LocalP256Signer::from_record(r).unwrap());
                (r.id.clone(), s)
            })
            .collect()
    }

    fn statement(typ: &str, sub: &str, exp: i64) -> Value {
        let enc = |v: Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(&v).unwrap());
        let jwt = format!(
            "{}.{}.c2ln",
            enc(json!({ "alg": "ES256", "typ": typ })),
            enc(json!({ "sub": sub, "exp": exp }))
        );
        json!({ "format": "jwt", "data": jwt })
    }

    fn as_json(r: &list::Response) -> Value {
        serde_json::to_value(r).unwrap()
    }

    fn codes(v: &Value) -> Vec<String> {
        v["problems"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["code"].as_str().unwrap().to_string())
            .collect()
    }

    /// A swiyu identity with a current identity statement, cached key and a
    /// reachable community is usable and the default; nothing secret is
    /// reported.
    #[test]
    fn a_complete_swiyu_identity_is_usable_and_reports_no_key() {
        let mut record = p256_record("swiyu", 0x31);
        let did = record.did.clone().unwrap();
        record.verifier_info = Some(vec![statement(
            trust_statement::IDENTITY_TYP,
            &did,
            now().timestamp() + 365 * 86_400,
        )]);
        let v = as_json(&report(&[record.clone()], &loaded(&[&record]), None, URL, now()).unwrap());
        let id = &v["identities"][0];
        assert_eq!(id["usable"], true);
        assert_eq!(id["isDefault"], true);
        assert_eq!(id["custody"], "cached");
        assert_eq!(id["clientId"], format!("decentralized_identifier:{did}"));
        assert_eq!(id["attestations"][0]["kind"], "identityTrustStatement");
        assert!(codes(id).is_empty(), "{id}");
        assert!(codes(&v).is_empty());
        let text = v.to_string();
        assert!(!text.contains(record.private_key_multibase.as_deref().unwrap()));
    }

    /// Each part reported in the specification's vocabulary: an expired
    /// statement is a warning (it is left out), its absence is
    /// `identityStatementMissing`, and an identity installed after start is
    /// `signerNotLoaded`, an error.
    #[test]
    fn statements_and_signers_are_reported_by_code() {
        let mut expired = p256_record("expired", 0x32);
        let did = expired.did.clone().unwrap();
        expired.verifier_info = Some(vec![statement(
            trust_statement::IDENTITY_TYP,
            &did,
            now().timestamp() - 1,
        )]);
        let mut soon = p256_record("soon", 0x33);
        soon.verifier_info = Some(vec![statement(
            trust_statement::IDENTITY_TYP,
            &did,
            now().timestamp() + 86_400,
        )]);
        let unloaded = p256_record("unloaded", 0x34);
        let v = as_json(
            &report(
                &[expired.clone(), soon.clone(), unloaded.clone()],
                &loaded(&[&expired, &soon]),
                Some("soon"),
                URL,
                now(),
            )
            .unwrap(),
        );
        let ids = v["identities"].as_array().unwrap();
        assert_eq!(
            codes(&ids[0]),
            ["statementExpired", "identityStatementMissing"]
        );
        assert_eq!(ids[0]["usable"], true, "warnings leave it usable");
        assert_eq!(codes(&ids[1]), ["statementExpiresSoon"]);
        assert_eq!(ids[1]["isDefault"], true);
        assert_eq!(ids[0]["isDefault"], false);
        assert_eq!(
            codes(&ids[2]),
            ["signerNotLoaded", "identityStatementMissing"]
        );
        assert_eq!(ids[2]["usable"], false);
    }

    /// An EUDI identity: no certificate, then an expiring one; and the
    /// community-wide problems make nothing usable (`noPublicUrl`) or name a
    /// default that is not there.
    #[test]
    fn certificates_and_community_problems() {
        let mut eudi = p256_record("eudi", 0x35);
        eudi.kind = VerifierKind::Eudi;
        eudi.did = None;
        eudi.kid = None;
        let signers = loaded(&[&eudi]);
        let v = as_json(&report(&[eudi.clone()], &signers, Some("gone"), None, now()).unwrap());
        assert_eq!(codes(&v), ["noPublicUrl", "defaultIdentityNotInstalled"]);
        let id = &v["identities"][0];
        assert_eq!(codes(id), ["certificateMissing"]);
        assert_eq!(id["clientId"], Value::Null);
        assert_eq!(id["usable"], false);

        let (leaf_pem, ca_pem) = crate::oid4vp::x509::issue_for_test(&eudi, 0x36);
        let chain = crate::oid4vp::x509::check_chain(
            &eudi,
            format!("{leaf_pem}{ca_pem}").as_bytes(),
            now().timestamp(),
        )
        .unwrap();
        eudi.x5c = Some(chain.x5c);
        let leaf = leaf_of(eudi.x5c.as_deref().unwrap()).unwrap();
        // Read a day before it expires.
        let late = leaf.not_after - Duration::days(1);
        let v = as_json(&report(&[eudi.clone()], &signers, None, URL, late).unwrap());
        let id = &v["identities"][0];
        assert_eq!(codes(id), ["certificateExpiresSoon"]);
        assert_eq!(id["usable"], true);
        assert_eq!(id["isDefault"], true);
        assert!(id["clientId"].as_str().unwrap().starts_with("x509_hash:"));
        // The self-signed Access CA is left out of `x5c`, as HAIP asks.
        assert_eq!(id["certificate"]["chainLength"], 1);
        assert!(
            id["certificate"]["subject"]
                .as_str()
                .unwrap()
                .contains("Example community verifier")
        );
        let v = as_json(
            &report(
                &[eudi],
                &signers,
                None,
                URL,
                leaf.not_after + Duration::days(1),
            )
            .unwrap(),
        );
        assert_eq!(codes(&v["identities"][0]), ["certificateExpired"]);
        assert_eq!(v["identities"][0]["usable"], false);
    }
}
