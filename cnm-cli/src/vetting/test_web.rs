//! A small, generated PGP web of trust for the bootstrap tests.
//!
//! Every key is an Ed25519 key generated from a fixed seed; every certification,
//! revocation and link signature is made here with rPGP, the same crate that
//! verifies them. Times are relative to the real clock, captured once per test
//! as [`now`], because rPGP stamps a new key's self-signatures with the real
//! time.

use pgp::composed::{
    ArmorOptions, CleartextSignedMessage, KeyType, SecretKeyParamsBuilder, SignedPublicKey,
    SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::ser::Serialize as _;
use pgp::types::{Duration, KeyDetails, Password, Tag, Timestamp};
use rand::SeedableRng;
use rand::rngs::StdRng;

pub const DAY: u64 = 86_400;

/// The test's clock, in Unix seconds.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

fn ts(secs: u64) -> Timestamp {
    Timestamp::from_secs(u32::try_from(secs).expect("timestamp fits u32"))
}

/// One kernel developer's key.
pub struct Person {
    pub secret: SignedSecretKey,
    pub public: SignedPublicKey,
}

/// When every test key was created: 400 days before the first key this process
/// makes, read once.
///
/// An OpenPGP fingerprint covers the key's creation time, so a seed alone does
/// not fix the key. Reading the clock per key made `Person::new(2, "Alice")`
/// a different key whenever two calls straddled a second boundary — a keyring
/// holding both then counted nine keys, not eight.
static KEYS_CREATED: std::sync::LazyLock<u64> = std::sync::LazyLock::new(|| now() - 400 * DAY);

impl Person {
    /// A key with one user ID and one signing subkey, created 400 days before
    /// the process's first key. The same seed is the same key for the whole run.
    pub fn new(seed: u64, name: &str) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let created = ts(*KEYS_CREATED);
        let subkey = SubkeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .created_at(created)
            .build()
            .expect("subkey params");
        let mut params = SecretKeyParamsBuilder::default();
        params
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .created_at(created)
            .primary_user_id(format!("{name} <{}@kernel.example>", name.to_lowercase()))
            .subkeys(vec![subkey]);
        let secret = params
            .build()
            .expect("key params")
            .generate(&mut rng)
            .expect("generate key");
        let public = secret.to_public_key();
        Self { secret, public }
    }

    pub fn fingerprint(&self) -> String {
        format!("{:X}", self.public.primary_key.fingerprint())
    }

    fn config(
        &self,
        typ: SignatureType,
        created: u64,
        expires_after: Option<u64>,
    ) -> SignatureConfig {
        let key = &self.secret.primary_key;
        let mut config = SignatureConfig::v4(typ, key.algorithm(), HashAlgorithm::Sha256);
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(ts(created))).unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint())).unwrap(),
        ];
        if let Some(after) = expires_after {
            config.hashed_subpackets.push(
                Subpacket::regular(SubpacketData::SignatureExpirationTime(Duration::from_secs(
                    u32::try_from(after).unwrap(),
                )))
                .unwrap(),
            );
        }
        config.unhashed_subpackets =
            vec![Subpacket::regular(SubpacketData::IssuerKeyId(key.legacy_key_id())).unwrap()];
        config
    }

    /// A certification by `self` over `other`'s first user ID, made at
    /// `created`, expiring `expires_after` seconds later when given.
    pub fn certification_of(
        &self,
        other: &Person,
        created: u64,
        expires_after: Option<u64>,
    ) -> pgp::packet::Signature {
        self.config(SignatureType::CertGeneric, created, expires_after)
            .sign_certification_third_party(
                &self.secret.primary_key,
                &Password::empty(),
                &other.public.primary_key,
                Tag::UserId,
                &other.public.details.users[0].id,
            )
            .expect("certify")
    }

    /// `self` certifies `other`, and `other`'s public key carries it.
    pub fn certify(&self, other: &mut Person, created: u64, expires_after: Option<u64>) {
        let sig = self.certification_of(other, created, expires_after);
        other.public.details.users[0].signatures.push(sig);
    }

    /// `self` revokes its certification of `other`.
    pub fn revoke_certification(&self, other: &mut Person, created: u64) {
        let sig = self
            .config(SignatureType::CertRevocation, created, None)
            .sign_certification_third_party(
                &self.secret.primary_key,
                &Password::empty(),
                &other.public.primary_key,
                Tag::UserId,
                &other.public.details.users[0].id,
            )
            .expect("revoke certification");
        other.public.details.users[0].signatures.push(sig);
    }

    /// The key's owner revokes the key.
    pub fn revoke_key(&mut self, created: u64) {
        let sig = self
            .config(SignatureType::KeyRevocation, created, None)
            .sign_key(
                &self.secret.primary_key,
                &Password::empty(),
                &self.public.primary_key,
            )
            .expect("revoke key");
        self.public.details.revocation_signatures.push(sig);
    }

    /// What a maintainer's `gpg --clearsign` produces over `text`, signed at
    /// `created` by the primary key or the signing subkey.
    pub fn clearsign(&self, text: &str, created: u64, with_subkey: bool) -> String {
        let msg = if with_subkey {
            let sub = &self.secret.secret_subkeys[0].key;
            let mut config =
                SignatureConfig::v4(SignatureType::Text, sub.algorithm(), HashAlgorithm::Sha256);
            config.hashed_subpackets = vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(ts(created))).unwrap(),
                Subpacket::regular(SubpacketData::IssuerFingerprint(sub.fingerprint())).unwrap(),
            ];
            config.unhashed_subpackets =
                vec![Subpacket::regular(SubpacketData::IssuerKeyId(sub.legacy_key_id())).unwrap()];
            CleartextSignedMessage::new(text, config, sub, &Password::empty())
        } else {
            let config = self.config(SignatureType::Text, created, None);
            CleartextSignedMessage::new(text, config, &self.secret.primary_key, &Password::empty())
        }
        .expect("clearsign");
        msg.to_armored_string(ArmorOptions::default())
            .expect("armor")
    }
}

/// The keys concatenated as `gpg --armor --export` blocks.
pub fn armored_keyring(people: &[&Person]) -> Vec<u8> {
    people
        .iter()
        .map(|p| {
            p.public
                .to_armored_string(ArmorOptions::default())
                .expect("armor key")
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}

/// The keys concatenated as one binary `gpg --export`.
pub fn binary_keyring(people: &[&Person]) -> Vec<u8> {
    people
        .iter()
        .flat_map(|p| p.public.to_bytes().expect("serialise key"))
        .collect()
}

/// The link statement text a maintainer signs.
pub fn link_text(did: &str) -> String {
    format!(
        "I link my OpenPGP key to my Linux Kernel community member identity.\n\
         openvtc-link: {did}\n"
    )
}
