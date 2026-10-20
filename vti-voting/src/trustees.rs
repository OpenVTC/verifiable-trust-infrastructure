//! The trustees' cryptography for the sealed and tallied-encrypted secrecy levels (VTI-VOT-060 –
//! 064): ElGamal over the Ristretto group of `curve25519-dalek`.
//!
//! - **Joint key generation** ([`deal`], [`verify_dealing`], [`verify_share`], [`ElectionKey`]).
//!   Each of `n` trustees deals a random polynomial of degree `t − 1`, publishes Feldman
//!   commitments to it with a proof of knowledge of its constant term, and sends each other
//!   trustee its share. The election key is the sum of the constant terms, which nobody ever
//!   holds; any `t` trustees can decrypt and no `t − 1` can (VTI-VOT-062). There is no dealer.
//!   Shares ride the public board sealed to each recipient's [`TransportKey`] ([`seal_share`],
//!   [`open_share`]); a dealer complained of reveals the share, which [`verify_share`] checks,
//!   and the key forms from the qualified dealers alone (CONVENTIONS §9.6).
//! - **Threshold decryption** ([`partial_decrypt`], [`verify_partial`], [`combine`]). A trustee
//!   publishes `x_j · A` with a Chaum–Pedersen proof that it used the share its public
//!   verification key commits to; any `t` verified partials combine by Lagrange interpolation
//!   (VTI-VOT-063).
//! - **Sealed ballots** ([`seal`], [`open_sealed`]): the ballot's bytes under ChaCha20-Poly1305
//!   with a key derived from a random group element encrypted to the election key — a KEM-DEM
//!   hybrid. Decrypted whole after close.
//! - **Tallied-encrypted ballots** ([`encrypt_vote`], [`verify_vote`], [`tally`]): exponential
//!   ElGamal of each option's 0 or 1, each with a disjunctive proof that it is 0 or 1, and a proof
//!   that the question's selections sum to a count the manifest admits (VTI-VOT-064). Ciphertexts
//!   add; only totals are ever decrypted, and a total is read back by baby-step giant-step.
//!
//! Every proof is non-interactive (Fiat–Shamir over SHA-512) and binds a caller-supplied
//! context — the election, its manifest digest — so a proof made for one election proves nothing
//! in another. The group operations are `curve25519-dalek`'s; the protocol above them is this
//! module's own, following Helios and Belenios, and is unaudited.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use curve25519_dalek::{
    RistrettoPoint, Scalar, constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::CompressedRistretto, traits::Identity,
};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};

/// A group element.
pub type Point = RistrettoPoint;

/// What went wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TrusteeError {
    #[error("a dealing does not hold together: {0}")]
    DealingInvalid(String),
    #[error("a share does not match its dealer's commitments")]
    ShareInvalid,
    #[error("a partial decryption's proof does not verify")]
    PartialInvalid,
    #[error("{have} verified partial decryptions, but {need} are needed")]
    TooFewPartials { have: usize, need: usize },
    #[error("a ballot's proof does not verify: {0}")]
    BallotInvalid(String),
    #[error("the sealed ballot does not open")]
    SealedInvalid,
    #[error("a total is outside the range searched")]
    TotalOutOfRange,
    #[error("an encoding is not valid: {0}")]
    Encoding(String),
    #[error("parameters: {0}")]
    Parameters(String),
}

type Result<T> = std::result::Result<T, TrusteeError>;

// ─── encoding ────────────────────────────────────────────────────────────

/// A point as the wire carries it: its 32-byte compression, multibase base58btc.
pub fn point_text(p: &Point) -> String {
    multibase::encode(multibase::Base::Base58Btc, p.compress().as_bytes())
}

/// The point [`point_text`] wrote; never the identity, never a non-canonical encoding.
///
/// # Errors
/// [`TrusteeError::Encoding`].
pub fn point_from_text(text: &str) -> Result<Point> {
    let (_, bytes) = multibase::decode(text).map_err(|e| TrusteeError::Encoding(e.to_string()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| TrusteeError::Encoding("a point is 32 bytes".into()))?;
    let p = CompressedRistretto(arr)
        .decompress()
        .ok_or_else(|| TrusteeError::Encoding("not a Ristretto point".into()))?;
    if p == Point::identity() {
        return Err(TrusteeError::Encoding(
            "the identity is never a valid element here".into(),
        ));
    }
    Ok(p)
}

/// A scalar as the wire carries it: 32 canonical little-endian bytes, multibase base58btc.
pub fn scalar_text(s: &Scalar) -> String {
    multibase::encode(multibase::Base::Base58Btc, s.as_bytes())
}

/// The scalar [`scalar_text`] wrote; a non-canonical encoding is refused.
///
/// # Errors
/// [`TrusteeError::Encoding`].
pub fn scalar_from_text(text: &str) -> Result<Scalar> {
    let (_, bytes) = multibase::decode(text).map_err(|e| TrusteeError::Encoding(e.to_string()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| TrusteeError::Encoding("a scalar is 32 bytes".into()))?;
    Option::from(Scalar::from_canonical_bytes(arr))
        .ok_or_else(|| TrusteeError::Encoding("not a canonical scalar".into()))
}

/// A uniformly random scalar: 64 random bytes reduced mod ℓ, so the RNG's version never couples
/// to the group's.
fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    let mut b = [0u8; 64];
    rng.fill_bytes(&mut b);
    Scalar::from_bytes_mod_order_wide(&b)
}

/// Fiat–Shamir: SHA-512 over framed parts under a domain tag, reduced to a scalar.
struct Transcript(Sha512);

impl Transcript {
    fn new(domain: &str, ctx: &[u8]) -> Self {
        let mut t = Self(Sha512::new());
        t.bytes(domain.as_bytes());
        t.bytes(ctx);
        t
    }
    fn bytes(&mut self, b: &[u8]) {
        self.0.update((b.len() as u64).to_be_bytes());
        self.0.update(b);
    }
    fn point(&mut self, p: &Point) {
        self.bytes(p.compress().as_bytes());
    }
    fn challenge(self) -> Scalar {
        let out: [u8; 64] = self.0.finalize().into();
        Scalar::from_bytes_mod_order_wide(&out)
    }
}

// ─── proofs ──────────────────────────────────────────────────────────────

/// A Schnorr proof of knowledge of `x` with `X = x·G`, as `(c, z)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schnorr {
    pub c: Scalar,
    pub z: Scalar,
}

fn schnorr_prove<R: RngCore + CryptoRng>(
    x: &Scalar,
    big_x: &Point,
    domain: &str,
    ctx: &[u8],
    rng: &mut R,
) -> Schnorr {
    let w = random_scalar(rng);
    let a = w * G;
    let mut t = Transcript::new(domain, ctx);
    t.point(big_x);
    t.point(&a);
    let c = t.challenge();
    Schnorr { c, z: w + c * x }
}

fn schnorr_verify(big_x: &Point, p: &Schnorr, domain: &str, ctx: &[u8]) -> bool {
    let a = p.z * G - p.c * big_x;
    let mut t = Transcript::new(domain, ctx);
    t.point(big_x);
    t.point(&a);
    t.challenge() == p.c
}

/// A Chaum–Pedersen proof that `log_G(Y) = log_A(D)`, as `(c, z)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChaumPedersen {
    pub c: Scalar,
    pub z: Scalar,
}

const DOMAIN_POK: &str = "vti/vote/trustee/pok/v1";
const DOMAIN_TRANSPORT: &str = "vti/vote/trustee/transport/v1";
const DOMAIN_PARTIAL: &str = "vti/vote/trustee/partial/v1";
const DOMAIN_BIT: &str = "vti/vote/encrypted/option/v1";
const DOMAIN_SUM: &str = "vti/vote/encrypted/question/v1";
const DOMAIN_SEAL: &str = "vti/vote/sealed/key/v1";

fn cp_prove<R: RngCore + CryptoRng>(
    x: &Scalar,
    base: &Point,
    y: &Point,
    d: &Point,
    domain: &str,
    ctx: &[u8],
    rng: &mut R,
) -> ChaumPedersen {
    let w = random_scalar(rng);
    let (a1, a2) = (w * G, w * base);
    let mut t = Transcript::new(domain, ctx);
    for p in [y, base, d, &a1, &a2] {
        t.point(p);
    }
    let c = t.challenge();
    ChaumPedersen { c, z: w + c * x }
}

fn cp_verify(
    base: &Point,
    y: &Point,
    d: &Point,
    p: &ChaumPedersen,
    domain: &str,
    ctx: &[u8],
) -> bool {
    let a1 = p.z * G - p.c * y;
    let a2 = p.z * base - p.c * d;
    let mut t = Transcript::new(domain, ctx);
    for q in [y, base, d, &a1, &a2] {
        t.point(q);
    }
    t.challenge() == p.c
}

// ─── joint key generation ────────────────────────────────────────────────

/// The threshold and number of trustees, and which index is which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Threshold {
    /// How many trustees decryption needs (`t`).
    pub t: u32,
    /// How many trustees there are (`n`). Indices run 1..=n.
    pub n: u32,
}

impl Threshold {
    /// # Errors
    /// [`TrusteeError::Parameters`] unless `2 ≤ t ≤ n` — a single trustee could decrypt alone
    /// (VTI-VOT-062).
    pub fn new(t: u32, n: u32) -> Result<Self> {
        if t < 2 || t > n {
            return Err(TrusteeError::Parameters(format!(
                "the threshold must satisfy 2 <= t <= n (got t={t}, n={n})"
            )));
        }
        Ok(Self { t, n })
    }
}

/// What a trustee publishes: commitments to its polynomial's coefficients, and a proof it knows
/// the constant term (so no trustee can choose its contribution after seeing the others').
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dealing {
    pub dealer: u32,
    pub commitments: Vec<Point>,
    pub pok: Schnorr,
}

/// What a trustee sends one other trustee, privately: its polynomial evaluated at their index.
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    pub dealer: u32,
    pub recipient: u32,
    pub value: Scalar,
}

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Share")
            .field("dealer", &self.dealer)
            .field("recipient", &self.recipient)
            .finish_non_exhaustive()
    }
}

fn eval(coeffs: &[Scalar], at: u32) -> Scalar {
    let x = Scalar::from(at);
    coeffs.iter().rev().fold(Scalar::ZERO, |acc, a| acc * x + a)
}

fn eval_commitments(commitments: &[Point], at: u32) -> Point {
    let x = Scalar::from(at);
    commitments
        .iter()
        .rev()
        .fold(Point::identity(), |acc, c| acc * x + c)
}

/// Trustee `dealer` deals: its public [`Dealing`], and one [`Share`] for every trustee, itself
/// included. Shares are sent each to its recipient privately; the dealing is published.
///
/// # Errors
/// [`TrusteeError::Parameters`] for a dealer index outside 1..=n.
pub fn deal<R: RngCore + CryptoRng>(
    dealer: u32,
    th: Threshold,
    ctx: &[u8],
    rng: &mut R,
) -> Result<(Dealing, Vec<Share>)> {
    if dealer == 0 || dealer > th.n {
        return Err(TrusteeError::Parameters(format!(
            "dealer {dealer} is not in 1..={}",
            th.n
        )));
    }
    let coeffs: Vec<Scalar> = (0..th.t).map(|_| random_scalar(rng)).collect();
    let commitments: Vec<Point> = coeffs.iter().map(|a| a * G).collect();
    let pok = schnorr_prove(
        &coeffs[0],
        &commitments[0],
        DOMAIN_POK,
        &dealer_ctx(ctx, dealer),
        rng,
    );
    let shares = (1..=th.n)
        .map(|j| Share {
            dealer,
            recipient: j,
            value: eval(&coeffs, j),
        })
        .collect();
    Ok((
        Dealing {
            dealer,
            commitments,
            pok,
        },
        shares,
    ))
}

/// `ctx` extended with a trustee's index, 4 bytes big-endian (CONVENTIONS §9.3).
fn dealer_ctx(ctx: &[u8], dealer: u32) -> Vec<u8> {
    let mut v = ctx.to_vec();
    v.extend_from_slice(&dealer.to_be_bytes());
    v
}

/// `ctx` extended with `frame(question)`: the context of a question's sum proof, and the base of
/// its options' (CONVENTIONS §9.3).
pub fn question_ctx(ctx: &[u8], question: &str) -> Vec<u8> {
    let mut v = ctx.to_vec();
    crate::election::frame(&mut v, question.as_bytes());
    v
}

// ─── transport keys and sealed shares ────────────────────────────────────

/// A trustee's transport key: what the other trustees seal its shares to (CONVENTIONS §9.6
/// item 1). Published with a proof of knowledge bound to the trustee's index and the election.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportKey {
    pub trustee: u32,
    pub key: Point,
    pub pok: Schnorr,
}

/// A transport key's secret, held only by its trustee.
#[derive(Clone)]
pub struct TransportSecret {
    pub trustee: u32,
    secret: Scalar,
}

impl std::fmt::Debug for TransportSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportSecret")
            .field("trustee", &self.trustee)
            .finish_non_exhaustive()
    }
}

impl TransportSecret {
    /// A fresh transport secret for `trustee`.
    pub fn generate<R: RngCore + CryptoRng>(trustee: u32, rng: &mut R) -> Self {
        Self {
            trustee,
            secret: random_scalar(rng),
        }
    }

    /// The secret as 32 bytes, for its holder's own custody.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// The secret from 64 uniformly random bytes — a custodian's domain-separated derivation —
    /// reduced mod ℓ, so the same bytes are the same key.
    ///
    /// # Errors
    /// [`TrusteeError::Encoding`] in the negligible case the reduction is zero.
    pub fn from_wide(trustee: u32, wide: &[u8; 64]) -> Result<Self> {
        Self::from_bytes(trustee, Scalar::from_bytes_mod_order_wide(wide).to_bytes())
    }

    /// # Errors
    /// [`TrusteeError::Encoding`] for a non-canonical or zero scalar.
    pub fn from_bytes(trustee: u32, bytes: [u8; 32]) -> Result<Self> {
        let secret: Scalar = Option::from(Scalar::from_canonical_bytes(bytes))
            .ok_or_else(|| TrusteeError::Encoding("not a canonical scalar".into()))?;
        if secret == Scalar::ZERO {
            return Err(TrusteeError::Encoding("a zero transport secret".into()));
        }
        Ok(Self { trustee, secret })
    }

    /// The public transport key with its proof, bound to `ctx`.
    pub fn publish<R: RngCore + CryptoRng>(&self, ctx: &[u8], rng: &mut R) -> TransportKey {
        let key = self.secret * G;
        TransportKey {
            trustee: self.trustee,
            key,
            pok: schnorr_prove(
                &self.secret,
                &key,
                DOMAIN_TRANSPORT,
                &dealer_ctx(ctx, self.trustee),
                rng,
            ),
        }
    }
}

/// Check a published transport key: a trustee index, not the identity, and its proof.
///
/// # Errors
/// [`TrusteeError::Parameters`] for an index outside 1..=n, [`TrusteeError::DealingInvalid`] for
/// a proof that does not verify.
pub fn verify_transport_key(tk: &TransportKey, th: Threshold, ctx: &[u8]) -> Result<()> {
    if tk.trustee == 0 || tk.trustee > th.n {
        return Err(TrusteeError::Parameters(format!(
            "trustee {} is not in 1..={}",
            tk.trustee, th.n
        )));
    }
    if tk.key == Point::identity()
        || !schnorr_verify(
            &tk.key,
            &tk.pok,
            DOMAIN_TRANSPORT,
            &dealer_ctx(ctx, tk.trustee),
        )
    {
        return Err(TrusteeError::DealingInvalid(
            "the transport key's proof does not verify".into(),
        ));
    }
    Ok(())
}

/// `ctx ‖ "share" ‖ dealer ‖ recipient`: what a sealed share is bound to (CONVENTIONS §9.4).
fn share_ctx(ctx: &[u8], dealer: u32, recipient: u32) -> Vec<u8> {
    let mut v = ctx.to_vec();
    v.extend_from_slice(b"share");
    v.extend_from_slice(&dealer.to_be_bytes());
    v.extend_from_slice(&recipient.to_be_bytes());
    v
}

/// Seal a share to its recipient's transport key, so it can ride the public board.
///
/// # Errors
/// [`TrusteeError::Parameters`] when `to` is not the share's recipient's key.
pub fn seal_share<R: RngCore + CryptoRng>(
    share: &Share,
    to: &TransportKey,
    ctx: &[u8],
    rng: &mut R,
) -> Result<Sealed> {
    if to.trustee != share.recipient {
        return Err(TrusteeError::Parameters(format!(
            "a share for trustee {} sealed to trustee {}'s key",
            share.recipient, to.trustee
        )));
    }
    seal_to(
        &to.key,
        share.value.as_bytes(),
        &share_ctx(ctx, share.dealer, share.recipient),
        rng,
    )
}

/// Open the share `dealer` sealed to this transport key's trustee. A share that does not open,
/// or is not a canonical scalar, is grounds for a complaint; whether it matches the dealer's
/// commitments is [`verify_share`]'s to say.
///
/// # Errors
/// [`TrusteeError::ShareInvalid`].
pub fn open_share(
    secret: &TransportSecret,
    dealer: u32,
    sealed: &Sealed,
    ctx: &[u8],
) -> Result<Share> {
    let r_elem = sealed.kem.b - secret.secret * sealed.kem.a;
    let bytes = open_with(&r_elem, sealed, &share_ctx(ctx, dealer, secret.trustee))
        .map_err(|_| TrusteeError::ShareInvalid)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| TrusteeError::ShareInvalid)?;
    let value =
        Option::from(Scalar::from_canonical_bytes(arr)).ok_or(TrusteeError::ShareInvalid)?;
    Ok(Share {
        dealer,
        recipient: secret.trustee,
        value,
    })
}

/// Check a published dealing: `t` commitments, none the identity, and a proof of knowledge of the
/// constant term bound to this dealer and this election.
///
/// # Errors
/// [`TrusteeError::DealingInvalid`].
pub fn verify_dealing(d: &Dealing, th: Threshold, ctx: &[u8]) -> Result<()> {
    if d.dealer == 0 || d.dealer > th.n {
        return Err(TrusteeError::DealingInvalid(format!(
            "dealer {} is not a trustee",
            d.dealer
        )));
    }
    if d.commitments.len() != th.t as usize {
        return Err(TrusteeError::DealingInvalid(format!(
            "{} commitments for a threshold of {}",
            d.commitments.len(),
            th.t
        )));
    }
    if d.commitments.iter().any(|c| *c == Point::identity()) {
        return Err(TrusteeError::DealingInvalid(
            "a commitment is the identity".into(),
        ));
    }
    if !schnorr_verify(
        &d.commitments[0],
        &d.pok,
        DOMAIN_POK,
        &dealer_ctx(ctx, d.dealer),
    ) {
        return Err(TrusteeError::DealingInvalid(
            "the proof of knowledge does not verify".into(),
        ));
    }
    Ok(())
}

/// Check a received share against its dealer's published commitments (Feldman).
///
/// # Errors
/// [`TrusteeError::ShareInvalid`].
pub fn verify_share(d: &Dealing, s: &Share) -> Result<()> {
    if s.dealer != d.dealer || s.value * G != eval_commitments(&d.commitments, s.recipient) {
        return Err(TrusteeError::ShareInvalid);
    }
    Ok(())
}

/// The election's public key and each trustee's public verification key, from the qualified
/// dealers' verified dealings. Anyone can compute it from the board.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectionKey {
    pub threshold: Threshold,
    /// `Y = Σ_{i∈Q} C_i0`.
    pub key: Point,
    /// The qualified dealers `Q`, ascending.
    pub qualified: Vec<u32>,
    /// `Y_j = Σ_{i∈Q} Σ_k j^k C_ik`: trustee `j`'s share times `G`, for every trustee.
    pub verification: BTreeMap<u32, Point>,
}

impl ElectionKey {
    /// Combine the qualified dealers' dealings (CONVENTIONS §9.6 item 5): at least one, one per
    /// dealer, each verified. Which dealers qualify — those with no unjustified complaint — is the
    /// ceremony's to decide; this takes exactly the dealings it is given.
    ///
    /// # Errors
    /// [`TrusteeError::DealingInvalid`] for none, a repeated or an invalid dealing.
    pub fn from_dealings(dealings: &[Dealing], th: Threshold, ctx: &[u8]) -> Result<Self> {
        let dealers: BTreeSet<u32> = dealings.iter().map(|d| d.dealer).collect();
        if dealings.is_empty() || dealers.len() != dealings.len() {
            return Err(TrusteeError::DealingInvalid(
                "at least one dealing, and one per dealer, is needed".into(),
            ));
        }
        for d in dealings {
            verify_dealing(d, th, ctx)?;
        }
        let key = dealings.iter().map(|d| d.commitments[0]).sum();
        let verification = (1..=th.n)
            .map(|j| {
                let yj: Point = dealings
                    .iter()
                    .map(|d| eval_commitments(&d.commitments, j))
                    .sum();
                (j, yj)
            })
            .collect();
        Ok(Self {
            threshold: th,
            key,
            qualified: dealers.into_iter().collect(),
            verification,
        })
    }
}

/// A trustee's secret share of the election key: the sum of every share it received.
#[derive(Clone)]
pub struct TrusteeKey {
    pub index: u32,
    secret: Scalar,
}

impl std::fmt::Debug for TrusteeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrusteeKey")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl TrusteeKey {
    /// The key from every share addressed to `index`, each checked against its dealing, and
    /// checked against the published verification key.
    ///
    /// # Errors
    /// [`TrusteeError::ShareInvalid`] for a share that does not verify or a set that is not one
    /// from each dealer.
    pub fn from_shares(
        index: u32,
        shares: &[Share],
        dealings: &[Dealing],
        ek: &ElectionKey,
    ) -> Result<Self> {
        let by_dealer: HashMap<u32, &Dealing> = dealings.iter().map(|d| (d.dealer, d)).collect();
        let dealers: BTreeSet<u32> = shares.iter().map(|s| s.dealer).collect();
        if dealers.len() != shares.len()
            || dealers.len() != by_dealer.len()
            || !dealers.iter().copied().eq(ek.qualified.iter().copied())
        {
            return Err(TrusteeError::ShareInvalid);
        }
        let mut secret = Scalar::ZERO;
        for s in shares {
            if s.recipient != index {
                return Err(TrusteeError::ShareInvalid);
            }
            let d = by_dealer.get(&s.dealer).ok_or(TrusteeError::ShareInvalid)?;
            verify_share(d, s)?;
            secret += s.value;
        }
        if ek.verification.get(&index) != Some(&(secret * G)) {
            return Err(TrusteeError::ShareInvalid);
        }
        Ok(Self { index, secret })
    }

    /// The share as 32 bytes, for its holder's own custody.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// # Errors
    /// [`TrusteeError::Encoding`] for a non-canonical scalar.
    pub fn from_bytes(index: u32, bytes: [u8; 32]) -> Result<Self> {
        let secret = Option::from(Scalar::from_canonical_bytes(bytes))
            .ok_or_else(|| TrusteeError::Encoding("not a canonical scalar".into()))?;
        Ok(Self { index, secret })
    }
}

// ─── ciphertexts and threshold decryption ────────────────────────────────

/// An ElGamal ciphertext `(A, B) = (r·G, M + r·Y)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ciphertext {
    pub a: Point,
    pub b: Point,
}

impl std::ops::Add for Ciphertext {
    type Output = Self;
    fn add(self, o: Self) -> Self {
        Self {
            a: self.a + o.a,
            b: self.b + o.b,
        }
    }
}

impl Ciphertext {
    fn zero() -> Self {
        Self {
            a: Point::identity(),
            b: Point::identity(),
        }
    }
}

/// A trustee's share of one decryption, `D_j = x_j·A`, with its proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartialDecryption {
    pub trustee: u32,
    pub d: Point,
    pub proof: ChaumPedersen,
}

/// Trustee `key` decrypts its share of `ct`. Made only after voting closes (VTI-VOT-063): that
/// rule is the caller's, not the group's.
pub fn partial_decrypt<R: RngCore + CryptoRng>(
    key: &TrusteeKey,
    ct: &Ciphertext,
    ctx: &[u8],
    rng: &mut R,
) -> PartialDecryption {
    let d = key.secret * ct.a;
    let y = key.secret * G;
    PartialDecryption {
        trustee: key.index,
        d,
        proof: cp_prove(&key.secret, &ct.a, &y, &d, DOMAIN_PARTIAL, ctx, rng),
    }
}

/// Check a partial decryption against its trustee's published verification key.
///
/// # Errors
/// [`TrusteeError::PartialInvalid`].
pub fn verify_partial(
    ek: &ElectionKey,
    ct: &Ciphertext,
    p: &PartialDecryption,
    ctx: &[u8],
) -> Result<()> {
    let y = ek
        .verification
        .get(&p.trustee)
        .ok_or(TrusteeError::PartialInvalid)?;
    if cp_verify(&ct.a, y, &p.d, &p.proof, DOMAIN_PARTIAL, ctx) {
        Ok(())
    } else {
        Err(TrusteeError::PartialInvalid)
    }
}

/// `x·A` from any `t` verified partials of distinct trustees, by Lagrange interpolation at 0;
/// `B − x·A` is the plaintext element.
///
/// # Errors
/// [`TrusteeError::PartialInvalid`] for a partial that does not verify, or
/// [`TrusteeError::TooFewPartials`].
pub fn combine(
    ek: &ElectionKey,
    ct: &Ciphertext,
    partials: &[PartialDecryption],
    ctx: &[u8],
) -> Result<Point> {
    let mut chosen: BTreeMap<u32, Point> = BTreeMap::new();
    for p in partials {
        verify_partial(ek, ct, p, ctx)?;
        chosen.entry(p.trustee).or_insert(p.d);
    }
    let need = ek.threshold.t as usize;
    if chosen.len() < need {
        return Err(TrusteeError::TooFewPartials {
            have: chosen.len(),
            need,
        });
    }
    let idx: Vec<u32> = chosen.keys().copied().take(need).collect();
    let mut xa = Point::identity();
    for &j in &idx {
        xa += lagrange_at_zero(j, &idx) * chosen[&j];
    }
    Ok(ct.b - xa)
}

fn lagrange_at_zero(j: u32, set: &[u32]) -> Scalar {
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    let xj = Scalar::from(j);
    for &k in set {
        if k != j {
            let xk = Scalar::from(k);
            num *= xk;
            den *= xk - xj;
        }
    }
    num * den.invert()
}

// ─── sealed ballots ──────────────────────────────────────────────────────

/// A ballot sealed to the election key: a random element `R` encrypted as `(A, B)`, and the
/// ballot's bytes under ChaCha20-Poly1305 with a key derived from `R`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub kem: Ciphertext,
    pub body: Vec<u8>,
}

fn seal_key(r: &Point) -> Key {
    let mut h = Sha256::new();
    h.update((DOMAIN_SEAL.len() as u64).to_be_bytes());
    h.update(DOMAIN_SEAL.as_bytes());
    h.update(r.compress().as_bytes());
    let k: [u8; 32] = h.finalize().into();
    k.into()
}

fn seal_aad(ctx: &[u8], kem: &Ciphertext) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ctx.len() + 72);
    aad.extend_from_slice(&(ctx.len() as u64).to_be_bytes());
    aad.extend_from_slice(ctx);
    aad.extend_from_slice(kem.a.compress().as_bytes());
    aad.extend_from_slice(kem.b.compress().as_bytes());
    aad
}

/// Seal `ballot` to the election key, bound to `ctx`. The AEAD key is used once, so the nonce is
/// fixed.
///
/// # Errors
/// [`TrusteeError::Encoding`] if the cipher refuses (it does not for any length a ballot has).
pub fn seal<R: RngCore + CryptoRng>(
    ek: &ElectionKey,
    ballot: &[u8],
    ctx: &[u8],
    rng: &mut R,
) -> Result<Sealed> {
    seal_to(&ek.key, ballot, ctx, rng)
}

/// Seal `msg` to the key `to` under `aad_ctx` (CONVENTIONS §9.4).
fn seal_to<R: RngCore + CryptoRng>(
    to: &Point,
    msg: &[u8],
    aad_ctx: &[u8],
    rng: &mut R,
) -> Result<Sealed> {
    let r_elem = random_scalar(rng) * G;
    let r = random_scalar(rng);
    let kem = Ciphertext {
        a: r * G,
        b: r_elem + r * to,
    };
    let body = ChaCha20Poly1305::new(&seal_key(&r_elem))
        .encrypt(
            &Nonce::default(),
            Payload {
                msg,
                aad: &seal_aad(aad_ctx, &kem),
            },
        )
        .map_err(|_| TrusteeError::Encoding("the cipher refused".into()))?;
    Ok(Sealed { kem, body })
}

/// Open a sealed payload whose KEM element `r_elem` is already recovered — a sealed ballot from
/// the element a [`crate::ceremony::Decryption`] combined, under `ctx`.
///
/// # Errors
/// [`TrusteeError::SealedInvalid`].
pub fn open_with(r_elem: &Point, s: &Sealed, aad_ctx: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new(&seal_key(r_elem))
        .decrypt(
            &Nonce::default(),
            Payload {
                msg: &s.body,
                aad: &seal_aad(aad_ctx, &s.kem),
            },
        )
        .map_err(|_| TrusteeError::SealedInvalid)
}

/// Open a sealed ballot from `t` verified partial decryptions of its `kem`.
///
/// # Errors
/// As [`combine`], or [`TrusteeError::SealedInvalid`] if the body does not authenticate.
pub fn open_sealed(
    ek: &ElectionKey,
    s: &Sealed,
    partials: &[PartialDecryption],
    ctx: &[u8],
) -> Result<Vec<u8>> {
    let r_elem = combine(ek, &s.kem, partials, ctx)?;
    open_with(&r_elem, s, ctx)
}

// ─── tallied-encrypted ballots ───────────────────────────────────────────

/// A disjunctive (CDS) proof that a ciphertext encrypts `v·G` for one `v` in a public set, as one
/// `(c_i, z_i)` per value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneOf {
    pub parts: Vec<(Scalar, Scalar)>,
}

// The statement (key, ciphertext, values, domain, context) and the witness (randomness, index)
// are each irreducible here; grouping them would only rename the arguments.
#[allow(clippy::too_many_arguments)]
fn one_of_prove<R: RngCore + CryptoRng>(
    ek: &Point,
    ct: &Ciphertext,
    r: &Scalar,
    values: &[u64],
    actual: usize,
    domain: &str,
    ctx: &[u8],
    rng: &mut R,
) -> OneOf {
    let n = values.len();
    let mut cs = vec![Scalar::ZERO; n];
    let mut zs = vec![Scalar::ZERO; n];
    let mut commits = Vec::with_capacity(n);
    let w = random_scalar(rng);
    for (i, v) in values.iter().enumerate() {
        let bv = ct.b - Scalar::from(*v) * G;
        if i == actual {
            commits.push((w * G, w * ek));
        } else {
            cs[i] = random_scalar(rng);
            zs[i] = random_scalar(rng);
            commits.push((zs[i] * G - cs[i] * ct.a, zs[i] * ek - cs[i] * bv));
        }
    }
    let c = one_of_challenge(ek, ct, values, &commits, domain, ctx);
    let others: Scalar = cs
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != actual)
        .map(|(_, c)| c)
        .sum();
    cs[actual] = c - others;
    zs[actual] = w + cs[actual] * r;
    OneOf {
        parts: cs.into_iter().zip(zs).collect(),
    }
}

fn one_of_challenge(
    ek: &Point,
    ct: &Ciphertext,
    values: &[u64],
    commits: &[(Point, Point)],
    domain: &str,
    ctx: &[u8],
) -> Scalar {
    let mut t = Transcript::new(domain, ctx);
    t.point(ek);
    t.point(&ct.a);
    t.point(&ct.b);
    for v in values {
        t.bytes(&v.to_be_bytes());
    }
    for (a1, a2) in commits {
        t.point(a1);
        t.point(a2);
    }
    t.challenge()
}

fn one_of_verify(
    ek: &Point,
    ct: &Ciphertext,
    values: &[u64],
    p: &OneOf,
    domain: &str,
    ctx: &[u8],
) -> bool {
    if p.parts.len() != values.len() {
        return false;
    }
    let commits: Vec<(Point, Point)> = values
        .iter()
        .zip(&p.parts)
        .map(|(v, (c, z))| {
            let bv = ct.b - Scalar::from(*v) * G;
            (z * G - c * ct.a, z * ek - c * bv)
        })
        .collect();
    let sum: Scalar = p.parts.iter().map(|(c, _)| c).sum();
    one_of_challenge(ek, ct, values, &commits, domain, ctx) == sum
}

/// One question of a tallied-encrypted ballot: a ciphertext of 0 or 1 per option, each with its
/// proof, and a proof that the options' sum is a count the question admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedQuestion {
    pub options: Vec<(Ciphertext, OneOf)>,
    pub sum_proof: OneOf,
}

/// The counts a question admits: `min..=max` selections, and 0 too when it may be left
/// unanswered.
///
/// # Errors
/// [`TrusteeError::Parameters`] for bounds outside the options.
pub fn admitted_counts(options: usize, min: u64, max: u64, optional: bool) -> Result<Vec<u64>> {
    if min > max || max as usize > options || options == 0 {
        return Err(TrusteeError::Parameters(format!(
            "selections {min}..={max} over {options} options"
        )));
    }
    let mut v: BTreeSet<u64> = (min..=max).collect();
    if optional {
        v.insert(0);
    }
    Ok(v.into_iter().collect())
}

/// Encrypt one question's selections (`chosen[i]` for option `i`) with their proofs, bound to
/// `ctx` and the question's index.
///
/// # Errors
/// [`TrusteeError::BallotInvalid`] when the selection count is not one `counts` admits.
pub fn encrypt_vote<R: RngCore + CryptoRng>(
    ek: &ElectionKey,
    chosen: &[bool],
    counts: &[u64],
    ctx: &[u8],
    rng: &mut R,
) -> Result<EncryptedQuestion> {
    let k = chosen.iter().filter(|c| **c).count() as u64;
    let Some(actual_sum) = counts.iter().position(|c| *c == k) else {
        return Err(TrusteeError::BallotInvalid(format!(
            "{k} selections is not admitted"
        )));
    };
    let mut options = Vec::with_capacity(chosen.len());
    let mut r_sum = Scalar::ZERO;
    let mut ct_sum = Ciphertext::zero();
    for (i, on) in chosen.iter().enumerate() {
        let m = u64::from(*on);
        let r = random_scalar(rng);
        let ct = Ciphertext {
            a: r * G,
            b: Scalar::from(m) * G + r * ek.key,
        };
        let proof = one_of_prove(
            &ek.key,
            &ct,
            &r,
            &[0, 1],
            m as usize,
            DOMAIN_BIT,
            &option_ctx(ctx, i),
            rng,
        );
        r_sum += r;
        ct_sum = ct_sum + ct;
        options.push((ct, proof));
    }
    let sum_proof = one_of_prove(
        &ek.key, &ct_sum, &r_sum, counts, actual_sum, DOMAIN_SUM, ctx, rng,
    );
    Ok(EncryptedQuestion { options, sum_proof })
}

fn option_ctx(ctx: &[u8], i: usize) -> Vec<u8> {
    let mut v = ctx.to_vec();
    v.extend_from_slice(&(i as u64).to_be_bytes());
    v
}

/// Check one encrypted question: every option 0 or 1, and the sum a count `counts` admits
/// (VTI-VOT-064).
///
/// # Errors
/// [`TrusteeError::BallotInvalid`].
pub fn verify_vote(
    ek: &ElectionKey,
    q: &EncryptedQuestion,
    options: usize,
    counts: &[u64],
    ctx: &[u8],
) -> Result<()> {
    if q.options.len() != options {
        return Err(TrusteeError::BallotInvalid(format!(
            "{} options encrypted for {options}",
            q.options.len()
        )));
    }
    let mut sum = Ciphertext::zero();
    for (i, (ct, p)) in q.options.iter().enumerate() {
        if !one_of_verify(&ek.key, ct, &[0, 1], p, DOMAIN_BIT, &option_ctx(ctx, i)) {
            return Err(TrusteeError::BallotInvalid(format!(
                "option {i} is not shown to be 0 or 1"
            )));
        }
        sum = sum + *ct;
    }
    if !one_of_verify(&ek.key, &sum, counts, &q.sum_proof, DOMAIN_SUM, ctx) {
        return Err(TrusteeError::BallotInvalid(
            "the selection count is not shown to be admitted".into(),
        ));
    }
    Ok(())
}

/// The homomorphic total of one option over every counted ballot.
pub fn total(ciphertexts: impl IntoIterator<Item = Ciphertext>) -> Ciphertext {
    ciphertexts
        .into_iter()
        .fold(Ciphertext::zero(), |acc, c| acc + c)
}

/// `m` from `m·G`, for `m ≤ max`, by baby-step giant-step: O(√max) time and memory.
///
/// # Errors
/// [`TrusteeError::TotalOutOfRange`].
pub fn tally(m_g: &Point, max: u64) -> Result<u64> {
    let step = (max as f64).sqrt().ceil().max(1.0) as u64;
    let mut baby: HashMap<[u8; 32], u64> = HashMap::with_capacity(step as usize + 1);
    let mut p = Point::identity();
    for j in 0..=step {
        baby.entry(p.compress().to_bytes()).or_insert(j);
        p += G;
    }
    let giant = Scalar::from(step) * G;
    let mut gamma = *m_g;
    let mut i = 0u64;
    while i * step <= max {
        if let Some(j) = baby.get(&gamma.compress().to_bytes()) {
            let m = i * step + j;
            if m <= max {
                return Ok(m);
            }
        }
        gamma -= giant;
        i += 1;
    }
    Err(TrusteeError::TotalOutOfRange)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    const CTX: &[u8] = b"did:webvh:QmCommunity:vtc.example.org\0agm-2027\0digest";

    /// A 3-of-5 key generated jointly, every trustee's key, and the dealings.
    fn ceremony(rng: &mut StdRng) -> (ElectionKey, Vec<TrusteeKey>, Vec<Dealing>) {
        let th = Threshold::new(3, 5).unwrap();
        let mut dealings = Vec::new();
        let mut all_shares = Vec::new();
        for i in 1..=th.n {
            let (d, s) = deal(i, th, CTX, rng).unwrap();
            dealings.push(d);
            all_shares.extend(s);
        }
        let ek = ElectionKey::from_dealings(&dealings, th, CTX).unwrap();
        let keys = (1..=th.n)
            .map(|j| {
                let mine: Vec<Share> = all_shares
                    .iter()
                    .filter(|s| s.recipient == j)
                    .cloned()
                    .collect();
                TrusteeKey::from_shares(j, &mine, &dealings, &ek).unwrap()
            })
            .collect();
        (ek, keys, dealings)
    }

    #[test]
    fn a_sealed_ballot_opens_with_any_threshold_of_trustees_and_not_fewer() {
        let mut rng = StdRng::seed_from_u64(1);
        let (ek, keys, _) = ceremony(&mut rng);
        let ballot = br#"{"answers":[{"question":"chair","choice":["alice"]}]}"#;
        let s = seal(&ek, ballot, CTX, &mut rng).unwrap();
        for subset in [[0usize, 1, 2], [2, 3, 4], [0, 2, 4]] {
            let parts: Vec<_> = subset
                .iter()
                .map(|i| partial_decrypt(&keys[*i], &s.kem, CTX, &mut rng))
                .collect();
            assert_eq!(open_sealed(&ek, &s, &parts, CTX).unwrap(), ballot);
        }
        let two: Vec<_> = keys[..2]
            .iter()
            .map(|k| partial_decrypt(k, &s.kem, CTX, &mut rng))
            .collect();
        assert_eq!(
            open_sealed(&ek, &s, &two, CTX).unwrap_err(),
            TrusteeError::TooFewPartials { have: 2, need: 3 }
        );
        // Bound to its election: the same partials open nothing under another context.
        let parts: Vec<_> = keys[..3]
            .iter()
            .map(|k| partial_decrypt(k, &s.kem, CTX, &mut rng))
            .collect();
        assert!(open_sealed(&ek, &s, &parts, b"another election").is_err());
    }

    #[test]
    fn a_false_partial_decryption_is_refused() {
        let mut rng = StdRng::seed_from_u64(2);
        let (ek, keys, _) = ceremony(&mut rng);
        let s = seal(&ek, b"x", CTX, &mut rng).unwrap();
        let mut p = partial_decrypt(&keys[0], &s.kem, CTX, &mut rng);
        p.d += G;
        assert_eq!(
            verify_partial(&ek, &s.kem, &p, CTX),
            Err(TrusteeError::PartialInvalid)
        );
        // Claiming to be another trustee fails too.
        let mut q = partial_decrypt(&keys[0], &s.kem, CTX, &mut rng);
        q.trustee = 2;
        assert_eq!(
            verify_partial(&ek, &s.kem, &q, CTX),
            Err(TrusteeError::PartialInvalid)
        );
    }

    #[test]
    fn shares_ride_the_board_sealed_to_their_recipients() {
        let mut rng = StdRng::seed_from_u64(10);
        let th = Threshold::new(2, 3).unwrap();
        let secrets: Vec<TransportSecret> = (1..=th.n)
            .map(|j| TransportSecret::generate(j, &mut rng))
            .collect();
        let tks: Vec<TransportKey> = secrets.iter().map(|s| s.publish(CTX, &mut rng)).collect();
        for tk in &tks {
            verify_transport_key(tk, th, CTX).unwrap();
        }
        // A transport key's proof is bound to its index and its election.
        let mut moved = tks[0];
        moved.trustee = 2;
        assert!(verify_transport_key(&moved, th, CTX).is_err());
        assert!(verify_transport_key(&tks[0], th, b"another election").is_err());

        let (d, shares) = deal(1, th, CTX, &mut rng).unwrap();
        let sealed: Vec<Sealed> = shares
            .iter()
            .map(|s| seal_share(s, &tks[s.recipient as usize - 1], CTX, &mut rng).unwrap())
            .collect();
        // Each recipient opens its own, and it checks against the commitments.
        let opened = open_share(&secrets[1], 1, &sealed[1], CTX).unwrap();
        assert_eq!(opened, shares[1]);
        verify_share(&d, &opened).unwrap();
        // Nobody else opens it, nor is it accepted as another dealer's or another election's.
        assert!(open_share(&secrets[2], 1, &sealed[1], CTX).is_err());
        assert!(open_share(&secrets[1], 3, &sealed[1], CTX).is_err());
        assert!(open_share(&secrets[1], 1, &sealed[1], b"another election").is_err());
        // Sealing to the wrong trustee's key is refused before anything is sealed.
        assert!(seal_share(&shares[0], &tks[1], CTX, &mut rng).is_err());
        // The secret round-trips through its custody form.
        let back = TransportSecret::from_bytes(2, secrets[1].to_bytes()).unwrap();
        assert_eq!(open_share(&back, 1, &sealed[1], CTX).unwrap(), shares[1]);
    }

    #[test]
    fn the_key_forms_from_the_qualified_dealers_alone() {
        let mut rng = StdRng::seed_from_u64(11);
        let th = Threshold::new(2, 3).unwrap();
        let mut dealings = Vec::new();
        let mut all_shares = Vec::new();
        for i in 1..=th.n {
            let (d, s) = deal(i, th, CTX, &mut rng).unwrap();
            dealings.push(d);
            all_shares.extend(s);
        }
        // Dealer 3 was disqualified: the key is the other two's.
        let qualified = &dealings[..2];
        let ek = ElectionKey::from_dealings(qualified, th, CTX).unwrap();
        assert_eq!(ek.qualified, vec![1, 2]);
        assert_eq!(ek.verification.len(), 3);
        let keys: Vec<TrusteeKey> = (1..=th.n)
            .map(|j| {
                let mine: Vec<Share> = all_shares
                    .iter()
                    .filter(|s| s.recipient == j && s.dealer != 3)
                    .cloned()
                    .collect();
                TrusteeKey::from_shares(j, &mine, qualified, &ek).unwrap()
            })
            .collect();
        // A share from the disqualified dealer is refused.
        let with_3: Vec<Share> = all_shares
            .iter()
            .filter(|s| s.recipient == 1)
            .cloned()
            .collect();
        assert!(TrusteeKey::from_shares(1, &with_3, &dealings, &ek).is_err());
        // Every trustee — dealer 3 too — still decrypts.
        let s = seal(&ek, b"ballot", CTX, &mut rng).unwrap();
        let parts: Vec<_> = [&keys[0], &keys[2]]
            .iter()
            .map(|k| partial_decrypt(k, &s.kem, CTX, &mut rng))
            .collect();
        assert_eq!(open_sealed(&ek, &s, &parts, CTX).unwrap(), b"ballot");
        assert!(ElectionKey::from_dealings(&[], th, CTX).is_err());
        let dup = [dealings[0].clone(), dealings[0].clone()];
        assert!(ElectionKey::from_dealings(&dup, th, CTX).is_err());
    }

    #[test]
    fn options_are_bound_to_their_question() {
        let mut rng = StdRng::seed_from_u64(12);
        let (ek, _, _) = ceremony(&mut rng);
        let counts = admitted_counts(2, 1, 1, false).unwrap();
        let chair = question_ctx(CTX, "chair");
        let q = encrypt_vote(&ek, &[true, false], &counts, &chair, &mut rng).unwrap();
        verify_vote(&ek, &q, 2, &counts, &chair).unwrap();
        assert!(verify_vote(&ek, &q, 2, &counts, &question_ctx(CTX, "budget")).is_err());
    }

    #[test]
    fn a_bad_share_or_dealing_is_caught() {
        let mut rng = StdRng::seed_from_u64(3);
        let th = Threshold::new(2, 3).unwrap();
        let (d, shares) = deal(1, th, CTX, &mut rng).unwrap();
        verify_dealing(&d, th, CTX).unwrap();
        let mut bad = shares[1].clone();
        bad.value += Scalar::ONE;
        assert_eq!(verify_share(&d, &bad), Err(TrusteeError::ShareInvalid));
        // A dealing replayed under another dealer index, or another election, fails its proof.
        let mut moved = d.clone();
        moved.dealer = 2;
        assert!(verify_dealing(&moved, th, CTX).is_err());
        assert!(verify_dealing(&d, th, b"another election").is_err());
        assert!(
            Threshold::new(1, 3).is_err(),
            "one trustee must never decrypt alone"
        );
    }

    #[test]
    fn encrypted_votes_tally_to_the_totals_and_reveal_nothing_else() {
        let mut rng = StdRng::seed_from_u64(4);
        let (ek, keys, _) = ceremony(&mut rng);
        // Choose exactly one of three; optional.
        let counts = admitted_counts(3, 1, 1, true).unwrap();
        let votes = [
            [true, false, false],
            [false, true, false],
            [true, false, false],
            [false, false, false],
            [true, false, false],
        ];
        let ballots: Vec<EncryptedQuestion> = votes
            .iter()
            .map(|v| encrypt_vote(&ek, v, &counts, CTX, &mut rng).unwrap())
            .collect();
        for b in &ballots {
            verify_vote(&ek, b, 3, &counts, CTX).unwrap();
        }
        let totals: Vec<u64> = (0..3)
            .map(|i| {
                let t = total(ballots.iter().map(|b| b.options[i].0));
                let parts: Vec<_> = keys[1..4]
                    .iter()
                    .map(|k| partial_decrypt(k, &t, CTX, &mut rng))
                    .collect();
                tally(
                    &combine(&ek, &t, &parts, CTX).unwrap(),
                    ballots.len() as u64,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(totals, [3, 1, 0]);
    }

    #[test]
    fn a_ballot_that_votes_twice_or_out_of_range_is_refused() {
        let mut rng = StdRng::seed_from_u64(5);
        let (ek, _, _) = ceremony(&mut rng);
        let one = admitted_counts(2, 1, 1, false).unwrap();
        assert!(encrypt_vote(&ek, &[true, true], &one, CTX, &mut rng).is_err());
        // Forge: encrypt 2 under one option, reusing an honest proof.
        let mut q = encrypt_vote(&ek, &[true, false], &one, CTX, &mut rng).unwrap();
        q.options[0].0.b += G;
        assert!(verify_vote(&ek, &q, 2, &one, CTX).is_err());
        // An honest ballot moved to another election does not verify there.
        let q = encrypt_vote(&ek, &[false, true], &one, CTX, &mut rng).unwrap();
        assert!(verify_vote(&ek, &q, 2, &one, b"another election").is_err());
        // Nor with its options reordered.
        let mut swapped = q.clone();
        swapped.options.swap(0, 1);
        assert!(verify_vote(&ek, &swapped, 2, &one, CTX).is_err());
    }

    #[test]
    fn totals_are_read_back_across_the_range() {
        for m in [0u64, 1, 2, 99, 100, 101, 9_999, 250_000] {
            assert_eq!(tally(&(Scalar::from(m) * G), 250_000).unwrap(), m);
        }
        assert_eq!(
            tally(&(Scalar::from(11u64) * G), 10),
            Err(TrusteeError::TotalOutOfRange)
        );
    }

    #[test]
    fn encodings_round_trip_and_refuse_the_identity() {
        let mut rng = StdRng::seed_from_u64(6);
        let p = random_scalar(&mut rng) * G;
        assert_eq!(point_from_text(&point_text(&p)).unwrap(), p);
        assert!(point_from_text(&point_text(&Point::identity())).is_err());
        let s = random_scalar(&mut rng);
        assert_eq!(scalar_from_text(&scalar_text(&s)).unwrap(), s);
        assert!(
            format!("{:?}", TrusteeKey::from_bytes(1, s.to_bytes()).unwrap())
                .find(&scalar_text(&s))
                .is_none()
        );
    }
}
