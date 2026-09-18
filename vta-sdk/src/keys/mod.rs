use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[non_exhaustive]
pub enum KeyType {
    Ed25519,
    X25519,
    /// ECDSA P-256 key for ES256 signing.
    P256,
    /// ML-DSA-44 (FIPS 204) post-quantum signing key.
    ///
    /// The parameter set W3C Quantum-Resistant Cryptosuites v1.0 defines for
    /// Data Integrity (`mldsa44-jcs-2024`, `mldsa44-rdfc-2024`), so this is the
    /// one a credential proof uses.
    MlDsa44,
    /// ML-DSA-65 (FIPS 204) post-quantum signing key.
    ///
    /// The parameter set Trust Spanning Protocol Rev 3 §8.1 mandates.
    ///
    /// Carried alongside [`KeyType::MlDsa44`] because two specifications
    /// require different sets — the parameter set is chosen by whatever
    /// consumes the key, never by the holder. Not duplication to be tidied
    /// away.
    MlDsa65,
}

/// Which of the two independent quantum-resistance questions a key answers, and
/// how.
///
/// # Why two axes and not one label
///
/// "Is this system post-quantum?" has no single answer, and answering it as
/// though it did is the failure mode worth designing against. **Signature
/// resistance and confidentiality resistance are separate facts**, they migrate
/// on different timetables, and today the second is false almost everywhere:
/// an identity can sign with ML-DSA-44 while still agreeing keys with X25519.
///
/// Collapsing that into one badge produces a claim that is wrong in the
/// direction that matters. A reader shown "post-quantum" for an identity whose
/// key agreement is classical has been told its recorded traffic is safe from
/// harvest-now-decrypt-later, which it is not. The console's own `NamedDid`
/// states the principle for a different case in the same words: being told it
/// **is** would be a lie.
///
/// So a renderer shows both axes or names the one it is showing. A key answers
/// exactly one of them — the axis is decided by what the algorithm can do — and
/// [`KeyType::posture`] returns that answer for a single key. Describing a whole
/// identity means asking every key it publishes, and saying so per axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuantumPosture {
    /// Signs, and a cryptographically relevant quantum computer does not break
    /// it (FIPS 204 ML-DSA).
    PostQuantumSigning,
    /// Signs, and Shor's algorithm breaks it.
    ClassicalSigning,
    /// Agrees a shared secret, and Shor's algorithm breaks it.
    ///
    /// There is deliberately no post-quantum counterpart here yet: the hybrid
    /// KEM this stack uses for confidentiality (MLKEM768-X25519) lives in the
    /// TSP transport, not in a DID document's verification methods, so no
    /// `KeyType` a DID publishes can currently answer this axis in the
    /// affirmative. A variant added before that is true would let a renderer
    /// claim something nothing can yet do.
    ClassicalKeyAgreement,
}

impl QuantumPosture {
    /// A short phrase for an operator-facing surface, naming the **axis** as
    /// well as the answer so it cannot be read as a claim about the other one.
    pub fn label(&self) -> &'static str {
        match self {
            QuantumPosture::PostQuantumSigning => "post-quantum signing",
            QuantumPosture::ClassicalSigning => "classical signing",
            QuantumPosture::ClassicalKeyAgreement => "classical key agreement",
        }
    }

    /// Whether this posture is quantum-resistant **on its own axis**.
    ///
    /// Never sufficient on its own to describe an identity: a `true` here says
    /// nothing about key agreement.
    pub fn is_quantum_resistant(&self) -> bool {
        matches!(self, QuantumPosture::PostQuantumSigning)
    }
}

impl KeyType {
    /// Which axis this key answers, and how. See [`QuantumPosture`].
    pub fn posture(&self) -> QuantumPosture {
        match self {
            KeyType::Ed25519 | KeyType::P256 => QuantumPosture::ClassicalSigning,
            KeyType::X25519 => QuantumPosture::ClassicalKeyAgreement,
            KeyType::MlDsa44 | KeyType::MlDsa65 => QuantumPosture::PostQuantumSigning,
            // No wildcard: `#[non_exhaustive]` binds other crates, not this one.
            // A new key type must state its axis rather than inherit a default,
            // because the default that would be chosen ("classical") is a claim
            // about security, and the wrong one for the next PQC algorithm
            // added.
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum KeyStatus {
    Active,
    Revoked,
}

/// Whether a key was derived from the BIP-32 seed or imported externally.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum KeyOrigin {
    Derived,
    Imported,
    /// Generated from the system CSPRNG, **never** derived from the BIP-39
    /// master seed and **never** exportable.
    ///
    /// The trade this variant makes: a `Derived` key can always be
    /// reconstructed from the mnemonic, which is what makes the VTA
    /// recoverable — and also what makes "the operator cannot obtain this key"
    /// false. An `Internal` key has no derivation path, so the mnemonic
    /// reveals nothing about it and no export surface will return it.
    ///
    /// The cost is symmetrical and permanent: **there is no way to recover an
    /// internal key.** It is not in a backup, not in the mnemonic, and not
    /// re-derivable. Losing the keyspace loses the key, and anything that key
    /// authorises. Use it where a signature must be attributable to this VTA
    /// and nowhere else; do not use it where losing the key would strand an
    /// identity — see the `did:webvh` refusal in `vta-webvh`.
    Internal,
}

fn default_derived() -> KeyOrigin {
    KeyOrigin::Derived
}

/// One key as the maintainer holds it — canonical
/// `keys/_shared/0.1/key-record#KeyRecord`.
///
/// The **wire** names are canonical camelCase; the Rust field names are the
/// maintainer's historical snake_case ones, kept so every call site did not
/// have to move in the same change. Snake_case is additionally accepted on
/// *intake* via aliases, so a producer written against the pre-fold shape keeps
/// working while it migrates — emission is canonical either way.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct KeyRecord {
    #[serde(alias = "key_id")]
    pub key_id: String,
    #[serde(alias = "derivation_path")]
    pub derivation_path: String,
    #[serde(alias = "key_type")]
    pub key_type: KeyType,
    pub status: KeyStatus,
    #[serde(alias = "public_key")]
    pub public_key: String,
    /// Absent when unset, never `null`.
    ///
    /// The shared `KeyRecord` component types this `string`, so `null` is a
    /// type error rather than a spelling of "no label" — and this component is
    /// returned by `keys/{list,create,show,import,rename,revoke}`, so one
    /// missing `skip_serializing_if` here is a violation on six tasks at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Absent when unset, never `null`. **Absence is not "every scope"** — the
    /// spec is explicit that a key with no context is reachable only by a
    /// caller with unrestricted authority, which is the workspace's own
    /// act-scope rule.
    #[serde(default, alias = "context_id", skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Absent when unset, never `null`; the component types it `integer`.
    #[serde(default, alias = "seed_id", skip_serializing_if = "Option::is_none")]
    pub seed_id: Option<u32>,
    /// Whether the private half may be released to a caller.
    ///
    /// `Some(false)` means every export of this key is refused and it can only
    /// be *used* — signing, key agreement — so the material never leaves.
    ///
    /// **`None` means exportable.** That is the permissive reading and it is
    /// deliberate: it is what every record written before this member existed
    /// already meant, so adding the member cannot silently retract access that
    /// callers already have. `Option<bool>` rather than a `#[serde(default)]`
    /// `bool` for the same reason the spec declares no JSON Schema `default` —
    /// a materialised default would rewrite absent as an explicit `true` on the
    /// next save, turning "never asked" into "asked and allowed".
    ///
    /// Not a statement about recoverability. A whole-store backup is a
    /// different mechanism from an export to a caller, and `vta-backup` reads
    /// the `SeedStore` directly rather than going through `get_key_secret`, so
    /// a non-exportable key still restores.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exportable: Option<bool>,
    #[serde(default = "default_derived")]
    pub origin: KeyOrigin,
    #[serde(alias = "created_at")]
    pub created_at: DateTime<Utc>,
    #[serde(alias = "updated_at")]
    pub updated_at: DateTime<Utc>,
}

impl KeyType {
    /// The multicodec prefix for this key type's **public** half, as an
    /// unsigned-varint byte sequence.
    ///
    /// This lives here, beside the enum, for one reason: `KeyType` is
    /// `#[non_exhaustive]`, so a `match` in any *other* crate needs a wildcard
    /// arm — and a wildcard in a codec table is a latent defect. It cannot
    /// produce a correct prefix, so it can only produce a wrong one, and a
    /// multibase string under the wrong prefix round-trips perfectly inside
    /// this workspace and decodes as the wrong algorithm everywhere else.
    ///
    /// `#[non_exhaustive]` binds other crates, not this one, so the match below
    /// is genuinely exhaustive and a new `KeyType` is a compile error here until
    /// it is given a codec. That is the guarantee callers rely on to keep their
    /// own encoders infallible.
    ///
    /// Values verified against `multiformats/multicodec` `table.csv`; the
    /// post-quantum entries are `draft` upstream and pinned by
    /// `affinidi-encoding`'s `pqc_code_points_match_the_multicodec_registry`.
    pub fn multicodec_public(&self) -> &'static [u8] {
        match self {
            KeyType::Ed25519 => &[0xed, 0x01], // ed25519-pub
            KeyType::X25519 => &[0xec, 0x01],  // x25519-pub
            KeyType::P256 => &[0x80, 0x24],    // p256-pub (0x1200)
            KeyType::MlDsa44 => &[0x90, 0x24], // mldsa-44-pub (0x1210)
            KeyType::MlDsa65 => &[0x91, 0x24], // mldsa-65-pub (0x1211)
        }
    }

    /// The multicodec prefix for this key type's **private** half.
    ///
    /// ML-DSA private material is the 32-byte seed xi, so these are the
    /// `-priv-seed` codecs (0x131a / 0x131b), not the multi-kilobyte expanded
    /// private codecs at 0x1317-0x1318. The seed is what lets an ML-DSA key be
    /// re-derived from the BIP-32 chain, which is the only reason a *derived*
    /// post-quantum key is possible at all — so the choice is load-bearing
    /// rather than a size optimisation.
    ///
    /// Exhaustive for the same reason as [`Self::multicodec_public`].
    pub fn multicodec_private(&self) -> &'static [u8] {
        match self {
            KeyType::Ed25519 => &[0x80, 0x26], // ed25519-priv (0x1300)
            KeyType::X25519 => &[0x82, 0x26],  // x25519-priv (0x1302)
            KeyType::P256 => &[0x86, 0x26],    // p256-priv (0x1306)
            KeyType::MlDsa44 => &[0x9a, 0x26], // mldsa-44-priv-seed (0x131a)
            KeyType::MlDsa65 => &[0x9b, 0x26], // mldsa-65-priv-seed (0x131b)
        }
    }

    /// The key type a multibase-encoded **public** key declares, by its
    /// multicodec prefix.
    ///
    /// The inverse of [`Self::multicodec_public`], and built from the same
    /// match so the two cannot drift: a new `KeyType` is a compile error in the
    /// table above, and this follows automatically.
    ///
    /// **Use this only where the key type is genuinely not carried** — reading
    /// a wire format that predates carrying it, for instance. Where a producer
    /// knows the algorithm, it should say so; the prefix is evidence, but a
    /// field is a statement, and Phase 2's recurring defect was exactly a type
    /// asserted where it should have been carried.
    ///
    /// `None` for a string that is not valid multibase, or whose prefix is not
    /// one this build knows. Both are answers a caller must handle: a key it
    /// cannot classify is not a key it should install.
    pub fn from_public_multibase(multibase_str: &str) -> Option<Self> {
        let (_base, bytes) = multibase::decode(multibase_str).ok()?;
        [
            KeyType::Ed25519,
            KeyType::X25519,
            KeyType::P256,
            KeyType::MlDsa44,
            KeyType::MlDsa65,
        ]
        .into_iter()
        .find(|k| bytes.starts_with(k.multicodec_public()))
    }
}

impl std::fmt::Display for KeyType {
    /// Must agree with the `rename_all = "lowercase"` serde spelling, arm for
    /// arm.
    ///
    /// Both reach the wire — serde on every REST body and Trust Task payload,
    /// this on log lines, error messages and the CLI's key table — so a
    /// disagreement reads as one key type in an error and a different one in
    /// the document that caused it. `display_matches_serde` pins it.
    ///
    /// Deliberately exhaustive with no wildcard arm, even though the type is
    /// `#[non_exhaustive]`: that attribute binds other crates, not this one, so
    /// a new variant is still a compile error *here* until it is given a
    /// spelling rather than silently acquiring a `Debug`-ish one.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Ed25519 => write!(f, "ed25519"),
            KeyType::X25519 => write!(f, "x25519"),
            KeyType::P256 => write!(f, "p256"),
            KeyType::MlDsa44 => write!(f, "mldsa44"),
            KeyType::MlDsa65 => write!(f, "mldsa65"),
        }
    }
}

impl std::fmt::Display for KeyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyStatus::Active => write!(f, "active"),
            KeyStatus::Revoked => write!(f, "revoked"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Display` and serde must spell a `KeyType` identically.
    ///
    /// Both spellings reach the wire — serde on REST bodies and Trust Task
    /// payloads, `Display` on logs, errors and the CLI key table — so a drift
    /// between them reads as one key type in an error message and another in
    /// the document that produced it.
    ///
    /// The list is written out rather than derived, so adding a `KeyType`
    /// without adding it here is a visible omission rather than a silently
    /// smaller test.
    #[test]
    fn display_matches_serde() {
        for kt in [
            KeyType::Ed25519,
            KeyType::X25519,
            KeyType::P256,
            KeyType::MlDsa44,
            KeyType::MlDsa65,
        ] {
            let serde_spelling = serde_json::to_string(&kt).expect("serialises");
            assert_eq!(
                kt.to_string(),
                serde_spelling.trim_matches('"'),
                "Display and serde disagree for {kt:?}"
            );
        }
    }

    /// The wire spellings must match the `keys/_shared/0.1` `KeyType`
    /// enumeration, which is what the VTA validates its own responses against.
    ///
    /// Pinned literally: a rename here — including one arriving via a change to
    /// `rename_all` — emits a value the published schema does not list, and the
    /// dispatch spine rejects the VTA's *own* response as a schema violation.
    /// That failure surfaces as a 500 on an operation that otherwise succeeded.
    #[test]
    fn key_type_wire_spellings_match_the_published_schema() {
        for (kt, expected) in [
            (KeyType::Ed25519, "ed25519"),
            (KeyType::X25519, "x25519"),
            (KeyType::P256, "p256"),
            (KeyType::MlDsa44, "mldsa44"),
            (KeyType::MlDsa65, "mldsa65"),
        ] {
            assert_eq!(
                serde_json::to_string(&kt).unwrap(),
                format!("\"{expected}\"")
            );
            assert_eq!(
                serde_json::from_str::<KeyType>(&format!("\"{expected}\"")).unwrap(),
                kt
            );
        }
    }

    /// Every key type has a distinct multicodec pair, and the post-quantum ones
    /// are the registered values.
    ///
    /// The prefixes are unsigned-varint, so they are not the code points read
    /// off the registry table — `0x1210` encodes as `[0x90, 0x24]`. Getting
    /// that conversion wrong produces a multibase string this workspace decodes
    /// perfectly and nobody else can, which is why the expected bytes are
    /// written out rather than computed by the same code that emits them.
    #[test]
    fn multicodecs_are_distinct_and_registered() {
        assert_eq!(KeyType::MlDsa44.multicodec_public(), &[0x90, 0x24]); // 0x1210
        assert_eq!(KeyType::MlDsa65.multicodec_public(), &[0x91, 0x24]); // 0x1211
        assert_eq!(KeyType::MlDsa44.multicodec_private(), &[0x9a, 0x26]); // 0x131a
        assert_eq!(KeyType::MlDsa65.multicodec_private(), &[0x9b, 0x26]); // 0x131b

        let all = [
            KeyType::Ed25519,
            KeyType::X25519,
            KeyType::P256,
            KeyType::MlDsa44,
            KeyType::MlDsa65,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(
                    a.multicodec_public(),
                    b.multicodec_public(),
                    "{a:?} and {b:?} share a public codec"
                );
                assert_ne!(
                    a.multicodec_private(),
                    b.multicodec_private(),
                    "{a:?} and {b:?} share a private codec"
                );
            }
        }
    }

    /// ML-DSA-44 and ML-DSA-65 are both carried on purpose.
    ///
    /// Two specifications mandate different parameter sets — W3C
    /// Quantum-Resistant Cryptosuites defines Data Integrity suites only for
    /// ML-DSA-44, TSP Rev 3 §8.1 requires ML-DSA-65 — so the parameter set is
    /// chosen by whatever consumes the key. This exists to stop them being
    /// "harmonised" into one.
    #[test]
    fn the_two_ml_dsa_parameter_sets_are_distinct() {
        assert_ne!(KeyType::MlDsa44, KeyType::MlDsa65);
        assert_ne!(KeyType::MlDsa44.to_string(), KeyType::MlDsa65.to_string());
    }
}

#[cfg(test)]
mod posture_tests {
    use super::{KeyType, QuantumPosture};

    /// Every key type answers exactly one axis, and the answer is right.
    ///
    /// Pinned as a table because the mapping is a security claim: an entry that
    /// drifts does not fail anything at compile time, it just tells an operator
    /// their classical key is post-quantum.
    #[test]
    fn each_key_type_answers_the_axis_it_can() {
        for (key_type, expected) in [
            (KeyType::Ed25519, QuantumPosture::ClassicalSigning),
            (KeyType::P256, QuantumPosture::ClassicalSigning),
            (KeyType::X25519, QuantumPosture::ClassicalKeyAgreement),
            (KeyType::MlDsa44, QuantumPosture::PostQuantumSigning),
            (KeyType::MlDsa65, QuantumPosture::PostQuantumSigning),
        ] {
            assert_eq!(key_type.posture(), expected, "{key_type:?}");
        }
    }

    /// Only the ML-DSA types are quantum-resistant, and X25519 in particular is
    /// not — it is the key-agreement half that makes "is this identity
    /// post-quantum?" unanswerable with one word.
    #[test]
    fn only_ml_dsa_is_quantum_resistant() {
        assert!(KeyType::MlDsa44.posture().is_quantum_resistant());
        assert!(KeyType::MlDsa65.posture().is_quantum_resistant());
        assert!(!KeyType::Ed25519.posture().is_quantum_resistant());
        assert!(!KeyType::P256.posture().is_quantum_resistant());
        assert!(!KeyType::X25519.posture().is_quantum_resistant());
    }

    /// Every label names its axis.
    ///
    /// A bare "post-quantum" would be read as a claim about the identity, and
    /// for an identity signing with ML-DSA over X25519 key agreement that claim
    /// is false in the direction that matters — it says recorded traffic is safe
    /// from harvest-now-decrypt-later when it is not.
    #[test]
    fn every_label_names_its_axis() {
        for posture in [
            QuantumPosture::PostQuantumSigning,
            QuantumPosture::ClassicalSigning,
            QuantumPosture::ClassicalKeyAgreement,
        ] {
            let label = posture.label();
            assert!(
                label.contains("signing") || label.contains("key agreement"),
                "'{label}' does not say which axis it is about"
            );
        }
    }
}
