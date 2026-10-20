//! The encrypted levels' wire forms (CONVENTIONS §9.1) ⇄ [`crate::trustees`]'s types.
//!
//! Every task module generates its own copy of the shared definitions, so these read the JSON
//! itself — always JSON that has already parsed as the task's generated payload, so its shape is
//! the schema's — and decode the group elements and scalars, which the schema cannot check.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::{
    ceremony::SealedDealing,
    trustees::{
        ChaumPedersen, Ciphertext, Dealing, ElectionKey, EncryptedQuestion, OneOf,
        PartialDecryption, Point, Schnorr, Sealed, Threshold, TransportKey, TrusteeError,
        point_from_text, point_text, scalar_from_text, scalar_text,
    },
};

type Result<T> = std::result::Result<T, TrusteeError>;

fn bad(what: &str) -> TrusteeError {
    TrusteeError::Encoding(format!("{what} is missing or not the expected shape"))
}

fn text<'a>(v: &'a Value, what: &str) -> Result<&'a str> {
    v.as_str().ok_or_else(|| bad(what))
}

fn index(v: &Value, what: &str) -> Result<u32> {
    v.as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| bad(what))
}

pub fn point(v: &Value) -> Result<Point> {
    point_from_text(text(v, "a group element")?)
}

pub fn ciphertext(v: &Value) -> Result<Ciphertext> {
    Ok(Ciphertext {
        a: point(&v["a"])?,
        b: point(&v["b"])?,
    })
}

pub fn ciphertext_value(c: &Ciphertext) -> Value {
    json!({ "a": point_text(&c.a), "b": point_text(&c.b) })
}

fn sigma(v: &Value) -> Result<(curve25519_dalek::Scalar, curve25519_dalek::Scalar)> {
    Ok((
        scalar_from_text(text(&v["c"], "c")?)?,
        scalar_from_text(text(&v["z"], "z")?)?,
    ))
}

fn sigma_value(c: &curve25519_dalek::Scalar, z: &curve25519_dalek::Scalar) -> Value {
    json!({ "c": scalar_text(c), "z": scalar_text(z) })
}

pub fn schnorr(v: &Value) -> Result<Schnorr> {
    let (c, z) = sigma(v)?;
    Ok(Schnorr { c, z })
}

pub fn chaum_pedersen(v: &Value) -> Result<ChaumPedersen> {
    let (c, z) = sigma(v)?;
    Ok(ChaumPedersen { c, z })
}

pub fn one_of(v: &Value) -> Result<OneOf> {
    let parts = v
        .as_array()
        .ok_or_else(|| bad("a disjunctive proof"))?
        .iter()
        .map(sigma)
        .collect::<Result<_>>()?;
    Ok(OneOf { parts })
}

pub fn one_of_value(p: &OneOf) -> Value {
    Value::Array(p.parts.iter().map(|(c, z)| sigma_value(c, z)).collect())
}

/// A `SealedPayload`.
pub fn sealed(v: &Value) -> Result<Sealed> {
    let (_, body) = multibase::decode(text(&v["body"], "body")?)
        .map_err(|e| TrusteeError::Encoding(e.to_string()))?;
    Ok(Sealed {
        kem: ciphertext(&v["kem"])?,
        body,
    })
}

pub fn sealed_value(s: &Sealed) -> Value {
    json!({
        "kem": ciphertext_value(&s.kem),
        "body": multibase::encode(multibase::Base::Base58Btc, &s.body),
    })
}

pub fn transport_key(v: &Value) -> Result<TransportKey> {
    Ok(TransportKey {
        trustee: index(&v["trustee"], "trustee")?,
        key: point(&v["key"])?,
        pok: schnorr(&v["pok"])?,
    })
}

pub fn transport_key_value(t: &TransportKey) -> Value {
    json!({
        "trustee": t.trustee,
        "key": point_text(&t.key),
        "pok": sigma_value(&t.pok.c, &t.pok.z),
    })
}

/// A `Dealing` with its sealed shares. Two shares for one recipient are refused here: the
/// schema cannot say so.
pub fn dealing(v: &Value) -> Result<SealedDealing> {
    let commitments = v["commitments"]
        .as_array()
        .ok_or_else(|| bad("commitments"))?
        .iter()
        .map(point)
        .collect::<Result<_>>()?;
    let mut shares = BTreeMap::new();
    for s in v["shares"].as_array().ok_or_else(|| bad("shares"))? {
        let r = index(&s["recipient"], "recipient")?;
        if shares.insert(r, sealed(&s["share"])?).is_some() {
            return Err(TrusteeError::DealingInvalid(format!(
                "two shares for trustee {r}"
            )));
        }
    }
    Ok(SealedDealing {
        dealing: Dealing {
            dealer: index(&v["dealer"], "dealer")?,
            commitments,
            pok: schnorr(&v["pok"])?,
        },
        shares,
    })
}

pub fn dealing_value(d: &SealedDealing) -> Value {
    json!({
        "dealer": d.dealing.dealer,
        "commitments": d.dealing.commitments.iter().map(point_text).collect::<Vec<_>>(),
        "pok": sigma_value(&d.dealing.pok.c, &d.dealing.pok.z),
        "shares": d.shares.iter().map(|(r, s)| json!({ "recipient": r, "share": sealed_value(s) })).collect::<Vec<_>>(),
    })
}

pub fn election_key_value(k: &ElectionKey) -> Value {
    json!({
        "key": point_text(&k.key),
        "qualified": k.qualified,
        "verification": k.verification.iter().map(|(j, y)| json!({ "trustee": j, "key": point_text(y) })).collect::<Vec<_>>(),
    })
}

/// An `ElectionKey` as a voter's client passes it. Only the key and its trustees' verification
/// keys are needed to encrypt; `threshold` comes from the manifest.
pub fn election_key(v: &Value, threshold: Threshold) -> Result<ElectionKey> {
    let qualified: BTreeSet<u32> = v["qualified"]
        .as_array()
        .ok_or_else(|| bad("qualified"))?
        .iter()
        .map(|q| index(q, "qualified"))
        .collect::<Result<_>>()?;
    let verification = v["verification"]
        .as_array()
        .ok_or_else(|| bad("verification"))?
        .iter()
        .map(|e| Ok((index(&e["trustee"], "trustee")?, point(&e["key"])?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(ElectionKey {
        threshold,
        key: point(&v["key"])?,
        qualified: qualified.into_iter().collect(),
        verification,
    })
}

/// What a partial decryption is for.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Target {
    /// A sealed cast's KEM, by its board leaf.
    Leaf(u64),
    /// An option's total in a tallied-encrypted election.
    Option { question: String, option: String },
}

pub fn target_value(t: &Target, ct: &Ciphertext) -> Value {
    match t {
        Target::Leaf(l) => json!({ "leafIndex": l, "ciphertext": ciphertext_value(ct) }),
        Target::Option { question, option } => json!({
            "question": question, "option": option, "ciphertext": ciphertext_value(ct),
        }),
    }
}

pub fn target(v: &Value) -> Result<(Target, Ciphertext)> {
    let ct = ciphertext(&v["ciphertext"])?;
    let t = match v.get("leafIndex").and_then(Value::as_u64) {
        Some(l) => Target::Leaf(l),
        None => Target::Option {
            question: text(&v["question"], "question")?.to_string(),
            option: text(&v["option"], "option")?.to_string(),
        },
    };
    Ok((t, ct))
}

/// A `PartialDecryption` by `trustee`.
pub fn partial(v: &Value, trustee: u32) -> Result<(Target, Ciphertext, PartialDecryption)> {
    let (t, ct) = target(&v["target"])?;
    Ok((
        t,
        ct,
        PartialDecryption {
            trustee,
            d: point(&v["d"])?,
            proof: chaum_pedersen(&v["proof"])?,
        },
    ))
}

pub fn partial_value(t: &Target, ct: &Ciphertext, p: &PartialDecryption) -> Value {
    json!({
        "target": target_value(t, ct),
        "d": point_text(&p.d),
        "proof": sigma_value(&p.proof.c, &p.proof.z),
    })
}

/// An `EncryptedQuestion`: its key and the encryption.
pub fn encrypted_question(v: &Value) -> Result<(String, EncryptedQuestion)> {
    let options = v["options"]
        .as_array()
        .ok_or_else(|| bad("options"))?
        .iter()
        .map(|o| Ok((ciphertext(&o["ciphertext"])?, one_of(&o["proof"])?)))
        .collect::<Result<_>>()?;
    Ok((
        text(&v["question"], "question")?.to_string(),
        EncryptedQuestion {
            options,
            sum_proof: one_of(&v["sumProof"])?,
        },
    ))
}

pub fn encrypted_question_value(key: &str, q: &EncryptedQuestion) -> Value {
    json!({
        "question": key,
        "options": q.options.iter().map(|(ct, p)| json!({ "ciphertext": ciphertext_value(ct), "proof": one_of_value(p) })).collect::<Vec<_>>(),
        "sumProof": one_of_value(&q.sum_proof),
    })
}
