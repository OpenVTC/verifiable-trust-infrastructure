//! The trustees' ceremony as the ballot box runs it (CONVENTIONS §9.6 – 9.7): generating the
//! election key on the board, then decrypting after close. A state machine over
//! [`crate::trustees`]'s types; the host maps each [`CeremonyError`] to the task's error code and
//! appends what an accepted step returns to the board.
//!
//! The ballot box never holds a share it can read: shares arrive sealed to their recipients, and
//! a share is in the clear only when its dealer reveals it to answer a complaint.

use std::collections::{BTreeMap, BTreeSet};

use curve25519_dalek::Scalar;

use crate::trustees::{
    Ciphertext, Dealing, ElectionKey, PartialDecryption, Point, Sealed, Share, Threshold,
    TransportKey, combine, verify_dealing, verify_partial, verify_share, verify_transport_key,
};

/// Where the key ceremony stands (`TrusteePhase`, minus the decryption phases the election's own
/// state gives).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    Enrolling,
    Dealing,
    Confirming,
    Keyed,
    Failed,
}

impl Phase {
    /// The `TrusteePhase` wire value.
    pub fn wire(self) -> &'static str {
        match self {
            Self::Enrolling => "enrolling",
            Self::Dealing => "dealing",
            Self::Confirming => "confirming",
            Self::Keyed => "keyed",
            Self::Failed => "failed",
        }
    }
}

/// Why a step was refused. Each names the task error code it answers as.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CeremonyError {
    /// `voting/trustees/enrol:notEnrolling`.
    #[error("the ceremony is not enrolling")]
    NotEnrolling,
    /// `voting/trustees/enrol:alreadyEnrolled`.
    #[error("this trustee has already published another transport key")]
    AlreadyEnrolled,
    /// `voting/trustees/enrol:transportKeyInvalid`.
    #[error("the transport key's proof does not verify")]
    TransportKeyInvalid,
    /// `voting/trustees/deal:notDealing`.
    #[error("the ceremony is not dealing")]
    NotDealing,
    /// `voting/trustees/deal:alreadyDealt`.
    #[error("this trustee has already published another dealing")]
    AlreadyDealt,
    /// `voting/trustees/deal:dealingInvalid`.
    #[error("the dealing does not hold together: {0}")]
    DealingInvalid(String),
    /// `voting/trustees/confirm:notConfirming` and `voting/trustees/justify:notConfirming`.
    #[error("the ceremony is not confirming")]
    NotConfirming,
    /// `voting/trustees/confirm:alreadyConfirmed`.
    #[error("this trustee has already confirmed otherwise")]
    AlreadyConfirmed,
    /// `voting/trustees/justify:noComplaint`.
    #[error("the recipient has not complained of this dealer")]
    NoComplaint,
    /// `voting/trustees/justify:shareInvalid`.
    #[error("the share does not match the dealer's commitments")]
    ShareInvalid,
    /// `voting/trustees/decrypt:notDecrypting`.
    #[error("there is nothing to decrypt")]
    NotDecrypting,
    /// `voting/trustees/decrypt:partialInvalid`.
    #[error("a partial decryption does not verify: {0}")]
    PartialInvalid(String),
    /// `malformedRequest`: an index the manifest does not have, or a complaint against oneself.
    #[error("{0}")]
    Malformed(String),
}

type Result<T> = std::result::Result<T, CeremonyError>;

/// What an accepted step did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Recorded: append it to the board.
    Accepted,
    /// The same step again: answer as the first time, append nothing.
    Repeat,
}

/// A trustee's dealing with its shares, each sealed to its recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedDealing {
    pub dealing: Dealing,
    /// By recipient index, one per trustee.
    pub shares: BTreeMap<u32, Sealed>,
}

/// One complaint and how it stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Complaint {
    pub dealer: u32,
    pub recipient: u32,
    /// The share its dealer revealed, once it checked.
    pub justified: Option<Scalar>,
}

/// The key ceremony of one election.
#[derive(Debug, Clone)]
pub struct Ceremony {
    threshold: Threshold,
    ctx: Vec<u8>,
    phase: Phase,
    transport: BTreeMap<u32, TransportKey>,
    dealings: BTreeMap<u32, SealedDealing>,
    confirmed: BTreeMap<u32, BTreeSet<u32>>,
    justified: BTreeMap<(u32, u32), Scalar>,
    key: Option<ElectionKey>,
}

impl Ceremony {
    /// A ceremony for `threshold.n` trustees, bound to the election's `ctx` (§9.2).
    pub fn new(threshold: Threshold, ctx: Vec<u8>) -> Self {
        Self {
            threshold,
            ctx,
            phase: Phase::Enrolling,
            transport: BTreeMap::new(),
            dealings: BTreeMap::new(),
            confirmed: BTreeMap::new(),
            justified: BTreeMap::new(),
            key: None,
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn threshold(&self) -> Threshold {
        self.threshold
    }
    pub fn key(&self) -> Option<&ElectionKey> {
        self.key.as_ref()
    }
    pub fn transport_keys(&self) -> impl Iterator<Item = &TransportKey> {
        self.transport.values()
    }
    pub fn dealings(&self) -> impl Iterator<Item = &SealedDealing> {
        self.dealings.values()
    }
    /// The trustees that have confirmed, ascending.
    pub fn confirmed(&self) -> impl Iterator<Item = u32> + '_ {
        self.confirmed.keys().copied()
    }

    /// Every complaint made, in (dealer, recipient) order.
    pub fn complaints(&self) -> Vec<Complaint> {
        let mut out: Vec<Complaint> = self
            .confirmed
            .iter()
            .flat_map(|(recipient, against)| {
                against.iter().map(move |dealer| Complaint {
                    dealer: *dealer,
                    recipient: *recipient,
                    justified: self.justified.get(&(*dealer, *recipient)).copied(),
                })
            })
            .collect();
        out.sort_by_key(|c| (c.dealer, c.recipient));
        out
    }

    fn index(&self, i: u32) -> Result<()> {
        if i == 0 || i > self.threshold.n {
            return Err(CeremonyError::Malformed(format!(
                "trustee {i} is not in 1..={}",
                self.threshold.n
            )));
        }
        Ok(())
    }

    /// Step 1: a trustee's transport key.
    ///
    /// # Errors
    /// [`CeremonyError::NotEnrolling`], [`CeremonyError::TransportKeyInvalid`],
    /// [`CeremonyError::AlreadyEnrolled`], [`CeremonyError::Malformed`].
    pub fn enrol(&mut self, tk: TransportKey) -> Result<Step> {
        self.index(tk.trustee)?;
        if let Some(held) = self.transport.get(&tk.trustee) {
            return if *held == tk {
                Ok(Step::Repeat)
            } else {
                Err(CeremonyError::AlreadyEnrolled)
            };
        }
        if self.phase != Phase::Enrolling {
            return Err(CeremonyError::NotEnrolling);
        }
        verify_transport_key(&tk, self.threshold, &self.ctx)
            .map_err(|_| CeremonyError::TransportKeyInvalid)?;
        self.transport.insert(tk.trustee, tk);
        if self.transport.len() == self.threshold.n as usize {
            self.phase = Phase::Dealing;
        }
        Ok(Step::Accepted)
    }

    /// Step 2: a trustee's dealing.
    ///
    /// # Errors
    /// [`CeremonyError::NotDealing`], [`CeremonyError::DealingInvalid`],
    /// [`CeremonyError::AlreadyDealt`], [`CeremonyError::Malformed`].
    pub fn deal(&mut self, d: SealedDealing) -> Result<Step> {
        self.index(d.dealing.dealer)?;
        if let Some(held) = self.dealings.get(&d.dealing.dealer) {
            return if *held == d {
                Ok(Step::Repeat)
            } else {
                Err(CeremonyError::AlreadyDealt)
            };
        }
        if self.phase != Phase::Dealing {
            return Err(CeremonyError::NotDealing);
        }
        verify_dealing(&d.dealing, self.threshold, &self.ctx)
            .map_err(|e| CeremonyError::DealingInvalid(e.to_string()))?;
        if !d.shares.keys().copied().eq(1..=self.threshold.n) {
            return Err(CeremonyError::DealingInvalid(
                "not exactly one sealed share per trustee".into(),
            ));
        }
        self.dealings.insert(d.dealing.dealer, d);
        if self.dealings.len() == self.threshold.n as usize {
            self.phase = Phase::Confirming;
        }
        Ok(Step::Accepted)
    }

    /// Step 3: a trustee confirms, naming the dealers whose shares failed.
    ///
    /// # Errors
    /// [`CeremonyError::NotConfirming`], [`CeremonyError::AlreadyConfirmed`],
    /// [`CeremonyError::Malformed`].
    pub fn confirm(&mut self, trustee: u32, complaints: BTreeSet<u32>) -> Result<Step> {
        self.index(trustee)?;
        for &c in &complaints {
            self.index(c)?;
            if c == trustee {
                return Err(CeremonyError::Malformed(
                    "a trustee does not complain of itself".into(),
                ));
            }
        }
        if let Some(held) = self.confirmed.get(&trustee) {
            return if *held == complaints {
                Ok(Step::Repeat)
            } else {
                Err(CeremonyError::AlreadyConfirmed)
            };
        }
        if self.phase != Phase::Confirming {
            return Err(CeremonyError::NotConfirming);
        }
        self.confirmed.insert(trustee, complaints);
        self.form_if_complete();
        Ok(Step::Accepted)
    }

    /// Step 4: a dealer reveals the share it dealt to a trustee that complained.
    ///
    /// # Errors
    /// [`CeremonyError::NotConfirming`], [`CeremonyError::NoComplaint`],
    /// [`CeremonyError::ShareInvalid`], [`CeremonyError::Malformed`].
    pub fn justify(&mut self, dealer: u32, recipient: u32, value: Scalar) -> Result<Step> {
        self.index(dealer)?;
        self.index(recipient)?;
        if let Some(held) = self.justified.get(&(dealer, recipient)) {
            return if *held == value {
                Ok(Step::Repeat)
            } else {
                Err(CeremonyError::ShareInvalid)
            };
        }
        if self.phase != Phase::Confirming {
            return Err(CeremonyError::NotConfirming);
        }
        if !self
            .confirmed
            .get(&recipient)
            .is_some_and(|c| c.contains(&dealer))
        {
            return Err(CeremonyError::NoComplaint);
        }
        let d = &self.dealings[&dealer].dealing;
        verify_share(
            d,
            &Share {
                dealer,
                recipient,
                value,
            },
        )
        .map_err(|_| CeremonyError::ShareInvalid)?;
        self.justified.insert((dealer, recipient), value);
        self.form_if_complete();
        Ok(Step::Accepted)
    }

    /// The dealers with no unjustified complaint.
    fn qualified(&self) -> Vec<u32> {
        let unjustified: BTreeSet<u32> = self
            .complaints()
            .into_iter()
            .filter(|c| c.justified.is_none())
            .map(|c| c.dealer)
            .collect();
        self.dealings
            .keys()
            .copied()
            .filter(|d| !unjustified.contains(d))
            .collect()
    }

    fn form_if_complete(&mut self) {
        let all_confirmed = self.confirmed.len() == self.threshold.n as usize;
        let all_answered = self.complaints().iter().all(|c| c.justified.is_some());
        if all_confirmed && all_answered {
            self.form();
        }
    }

    /// Item 5: the key from the qualified dealers, or failed unless at least `t` qualify and at
    /// least `t` trustees confirmed. Fewer qualified dealers could all be corrupt — one trustee
    /// complaining of every other dealer at the last moment would otherwise be left holding the
    /// key alone — and fewer confirmations could leave fewer than `t` trustees able to decrypt.
    fn form(&mut self) {
        if self.confirmed.len() < self.threshold.t as usize {
            self.phase = Phase::Failed;
            return;
        }
        let q = self.qualified();
        let dealings: Vec<Dealing> = q.iter().map(|d| self.dealings[d].dealing.clone()).collect();
        match ElectionKey::from_dealings(&dealings, self.threshold, &self.ctx) {
            Ok(k) => {
                self.key = Some(k);
                self.phase = Phase::Keyed;
            }
            Err(_) => self.phase = Phase::Failed,
        }
    }

    /// `votingOpens` has come: form the key from whoever qualifies if confirming, else fail. A
    /// key already formed is untouched. Returns whether the phase changed.
    pub fn deadline(&mut self) -> bool {
        let before = self.phase;
        match self.phase {
            Phase::Keyed | Phase::Failed => {}
            Phase::Confirming => self.form(),
            Phase::Enrolling | Phase::Dealing => self.phase = Phase::Failed,
        }
        self.phase != before
    }
}

/// One decryption round after close: the targets in a fixed order, and the partials accepted.
#[derive(Debug, Clone)]
pub struct Decryption<K> {
    key: ElectionKey,
    ctx: Vec<u8>,
    targets: Vec<(K, Ciphertext)>,
    partials: BTreeMap<u32, Vec<PartialDecryption>>,
}

impl<K: Clone + Eq> Decryption<K> {
    /// The round for `targets`, under the formed `key`.
    pub fn new(key: ElectionKey, ctx: Vec<u8>, targets: Vec<(K, Ciphertext)>) -> Self {
        Self {
            key,
            ctx,
            targets,
            partials: BTreeMap::new(),
        }
    }

    pub fn targets(&self) -> &[(K, Ciphertext)] {
        &self.targets
    }

    /// The trustees whose partials are accepted, ascending.
    pub fn decrypted(&self) -> impl Iterator<Item = u32> + '_ {
        self.partials.keys().copied()
    }

    /// Whether `t` trustees have decrypted every target.
    pub fn complete(&self) -> bool {
        self.partials.len() >= self.key.threshold.t as usize
    }

    /// A trustee's partials: exactly one per target, each for that target's ciphertext, each
    /// verified against the trustee's verification key.
    ///
    /// # Errors
    /// [`CeremonyError::NotDecrypting`] once complete, [`CeremonyError::PartialInvalid`],
    /// [`CeremonyError::Malformed`].
    pub fn accept(
        &mut self,
        trustee: u32,
        given: Vec<(K, Ciphertext, PartialDecryption)>,
    ) -> Result<Step> {
        if trustee == 0 || trustee > self.key.threshold.n {
            return Err(CeremonyError::Malformed(format!(
                "trustee {trustee} is not in 1..={}",
                self.key.threshold.n
            )));
        }
        let parts: Vec<PartialDecryption> = given.iter().map(|(_, _, p)| *p).collect();
        if let Some(held) = self.partials.get(&trustee) {
            // Proofs are randomised, so a repeat is the same document, not merely equal values.
            return if *held == parts {
                Ok(Step::Repeat)
            } else {
                Err(CeremonyError::PartialInvalid(
                    "this trustee's partials are already accepted".into(),
                ))
            };
        }
        if self.complete() {
            return Err(CeremonyError::NotDecrypting);
        }
        if given.len() != self.targets.len() {
            return Err(CeremonyError::PartialInvalid(format!(
                "{} partials for {} targets",
                given.len(),
                self.targets.len()
            )));
        }
        for (i, ((k, ct, p), (tk, tct))) in given.iter().zip(&self.targets).enumerate() {
            if k != tk || ct != tct {
                return Err(CeremonyError::PartialInvalid(format!(
                    "partial {i} is not for target {i}"
                )));
            }
            if p.trustee != trustee {
                return Err(CeremonyError::PartialInvalid(format!(
                    "partial {i} names another trustee"
                )));
            }
            verify_partial(&self.key, ct, p, &self.ctx)
                .map_err(|_| CeremonyError::PartialInvalid(format!("partial {i}")))?;
        }
        self.partials.insert(trustee, parts);
        Ok(Step::Accepted)
    }

    /// Every target's plaintext element, once complete.
    ///
    /// # Errors
    /// [`CeremonyError::NotDecrypting`] before then.
    pub fn plaintexts(&self) -> Result<Vec<(K, Point)>> {
        if !self.complete() {
            return Err(CeremonyError::NotDecrypting);
        }
        self.targets
            .iter()
            .enumerate()
            .map(|(i, (k, ct))| {
                let parts: Vec<PartialDecryption> =
                    self.partials.values().map(|ps| ps[i]).collect();
                combine(&self.key, ct, &parts, &self.ctx)
                    .map(|m| (k.clone(), m))
                    .map_err(|e| CeremonyError::PartialInvalid(e.to_string()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trustees::{
        TransportSecret, TrusteeKey, deal, open_sealed, open_share, partial_decrypt, seal,
        seal_share,
    };
    use rand::{SeedableRng, rngs::StdRng};

    const CTX: &[u8] = b"ceremony-test";

    struct Trustee {
        transport: TransportSecret,
        shares: Vec<Share>,
    }

    fn enrolled(rng: &mut StdRng, th: Threshold) -> (Ceremony, Vec<Trustee>) {
        let mut c = Ceremony::new(th, CTX.to_vec());
        let trustees: Vec<Trustee> = (1..=th.n)
            .map(|j| Trustee {
                transport: TransportSecret::generate(j, rng),
                shares: Vec::new(),
            })
            .collect();
        for t in &trustees {
            let tk = t.transport.publish(CTX, rng);
            assert_eq!(c.enrol(tk).unwrap(), Step::Accepted);
            assert_eq!(c.enrol(tk).unwrap(), Step::Repeat);
        }
        assert_eq!(c.phase(), Phase::Dealing);
        (c, trustees)
    }

    /// Every trustee deals; `corrupt` names a (dealer, recipient) whose sealed share is a wrong
    /// value.
    fn dealt(
        rng: &mut StdRng,
        c: &mut Ceremony,
        corrupt: Option<(u32, u32)>,
    ) -> BTreeMap<u32, Vec<Share>> {
        let th = c.threshold();
        let tks: Vec<TransportKey> = c.transport_keys().copied().collect();
        let mut plain = BTreeMap::new();
        for i in 1..=th.n {
            let (dealing, shares) = deal(i, th, CTX, rng).unwrap();
            let sealed = shares
                .iter()
                .map(|s| {
                    let mut s = s.clone();
                    if corrupt == Some((i, s.recipient)) {
                        s.value += Scalar::ONE;
                    }
                    (
                        s.recipient,
                        seal_share(&s, &tks[s.recipient as usize - 1], CTX, rng).unwrap(),
                    )
                })
                .collect();
            c.deal(SealedDealing {
                dealing,
                shares: sealed,
            })
            .unwrap();
            plain.insert(i, shares);
        }
        assert_eq!(c.phase(), Phase::Confirming);
        plain
    }

    /// Each trustee opens its shares from the board and complains of any that fails.
    fn open_all(c: &Ceremony, trustees: &mut [Trustee]) -> Vec<BTreeSet<u32>> {
        trustees
            .iter_mut()
            .map(|t| {
                let mut complaints = BTreeSet::new();
                for sd in c.dealings() {
                    let j = t.transport.trustee;
                    match open_share(&t.transport, sd.dealing.dealer, &sd.shares[&j], CTX)
                        .and_then(|s| verify_share(&sd.dealing, &s).map(|()| s))
                    {
                        Ok(s) => t.shares.push(s),
                        Err(_) => {
                            complaints.insert(sd.dealing.dealer);
                        }
                    }
                }
                complaints
            })
            .collect()
    }

    #[test]
    fn the_key_forms_and_decrypts_end_to_end() {
        let mut rng = StdRng::seed_from_u64(20);
        let th = Threshold::new(2, 3).unwrap();
        let (mut c, mut trustees) = enrolled(&mut rng, th);
        dealt(&mut rng, &mut c, None);
        let complaints = open_all(&c, &mut trustees);
        for (j, cs) in complaints.into_iter().enumerate() {
            assert!(cs.is_empty());
            c.confirm(j as u32 + 1, cs).unwrap();
        }
        assert_eq!(c.phase(), Phase::Keyed);
        let ek = c.key().unwrap().clone();
        assert_eq!(ek.qualified, vec![1, 2, 3]);
        let dealings: Vec<Dealing> = c.dealings().map(|d| d.dealing.clone()).collect();
        let keys: Vec<TrusteeKey> = trustees
            .iter()
            .map(|t| {
                TrusteeKey::from_shares(t.transport.trustee, &t.shares, &dealings, &ek).unwrap()
            })
            .collect();

        let sealed = seal(&ek, b"ballot", CTX, &mut rng).unwrap();
        let mut round = Decryption::new(ek.clone(), CTX.to_vec(), vec![(7u64, sealed.kem)]);
        for k in &keys[1..] {
            let p = partial_decrypt(k, &sealed.kem, CTX, &mut rng);
            round.accept(k.index, vec![(7, sealed.kem, p)]).unwrap();
        }
        assert!(round.complete());
        // A third arriving late is refused: the round is done.
        let p = partial_decrypt(&keys[0], &sealed.kem, CTX, &mut rng);
        assert_eq!(
            round.accept(1, vec![(7, sealed.kem, p)]),
            Err(CeremonyError::NotDecrypting)
        );
        let parts: Vec<PartialDecryption> = keys[1..]
            .iter()
            .map(|k| partial_decrypt(k, &sealed.kem, CTX, &mut rng))
            .collect();
        assert_eq!(open_sealed(&ek, &sealed, &parts, CTX).unwrap(), b"ballot");
        assert_eq!(round.plaintexts().unwrap().len(), 1);
    }

    #[test]
    fn a_justified_complaint_is_void_and_an_unjustified_one_disqualifies() {
        let mut rng = StdRng::seed_from_u64(21);
        let th = Threshold::new(2, 3).unwrap();

        // Dealer 1 sealed a wrong share to trustee 2, then justifies with the right one.
        let (mut c, mut trustees) = enrolled(&mut rng, th);
        let plain = dealt(&mut rng, &mut c, Some((1, 2)));
        let complaints = open_all(&c, &mut trustees);
        assert_eq!(complaints[1], BTreeSet::from([1]));
        for (j, cs) in complaints.into_iter().enumerate() {
            c.confirm(j as u32 + 1, cs).unwrap();
        }
        assert_eq!(
            c.phase(),
            Phase::Confirming,
            "a complaint holds the key back"
        );
        assert_eq!(
            c.justify(1, 2, plain[&1][1].value + Scalar::ONE),
            Err(CeremonyError::ShareInvalid)
        );
        assert_eq!(
            c.justify(2, 1, Scalar::ONE),
            Err(CeremonyError::NoComplaint)
        );
        c.justify(1, 2, plain[&1][1].value).unwrap();
        assert_eq!(c.phase(), Phase::Keyed);
        assert_eq!(c.key().unwrap().qualified, vec![1, 2, 3]);
        // Trustee 2 uses the revealed share.
        trustees[1].shares.push(Share {
            dealer: 1,
            recipient: 2,
            value: c.complaints()[0].justified.unwrap(),
        });
        let dealings: Vec<Dealing> = c.dealings().map(|d| d.dealing.clone()).collect();
        TrusteeKey::from_shares(2, &trustees[1].shares, &dealings, c.key().unwrap()).unwrap();

        // Dealer 1 never answers: at the deadline it is disqualified, and the key is 2 and 3's.
        let (mut c, mut trustees) = enrolled(&mut rng, th);
        dealt(&mut rng, &mut c, Some((1, 2)));
        for (j, cs) in open_all(&c, &mut trustees).into_iter().enumerate() {
            c.confirm(j as u32 + 1, cs).unwrap();
        }
        assert!(c.deadline());
        assert_eq!(c.phase(), Phase::Keyed);
        assert_eq!(c.key().unwrap().qualified, vec![2, 3]);
    }

    /// CONVENTIONS §9.6 item 5: the key needs `t` qualified dealers and `t` confirmations. One
    /// trustee complaining of every other dealer at the last moment fails the ceremony instead of
    /// leaving its own dealing — a key it alone would know — as the election key.
    #[test]
    fn vot_062_a_key_needs_t_qualified_dealers_and_t_confirmations() {
        let mut rng = StdRng::seed_from_u64(23);
        let th = Threshold::new(2, 3).unwrap();
        let (mut c, mut trustees) = enrolled(&mut rng, th);
        dealt(&mut rng, &mut c, None);
        open_all(&c, &mut trustees);
        c.confirm(1, BTreeSet::from([2, 3])).unwrap();
        c.confirm(2, BTreeSet::new()).unwrap();
        c.confirm(3, BTreeSet::new()).unwrap();
        assert!(c.deadline());
        assert_eq!(c.phase(), Phase::Failed, "only dealer 1 qualified");
        assert!(c.key().is_none());

        // Fewer than t confirmations at the deadline: failed too.
        let (mut c, mut trustees) = enrolled(&mut rng, th);
        dealt(&mut rng, &mut c, None);
        open_all(&c, &mut trustees);
        c.confirm(1, BTreeSet::new()).unwrap();
        assert!(c.deadline());
        assert_eq!(c.phase(), Phase::Failed);
    }

    #[test]
    fn steps_out_of_turn_or_repeated_differently_are_refused() {
        let mut rng = StdRng::seed_from_u64(22);
        let th = Threshold::new(2, 3).unwrap();
        let mut c = Ceremony::new(th, CTX.to_vec());
        let t1 = TransportSecret::generate(1, &mut rng);
        c.enrol(t1.publish(CTX, &mut rng)).unwrap();
        // Another key for the same trustee.
        assert_eq!(
            c.enrol(t1.publish(CTX, &mut rng)),
            Err(CeremonyError::AlreadyEnrolled)
        );
        // A key bound to another election.
        let t2 = TransportSecret::generate(2, &mut rng);
        assert_eq!(
            c.enrol(t2.publish(b"elsewhere", &mut rng)),
            Err(CeremonyError::TransportKeyInvalid)
        );
        assert!(matches!(
            c.enrol(TransportSecret::generate(4, &mut rng).publish(CTX, &mut rng)),
            Err(CeremonyError::Malformed(_))
        ));
        let (d, _) = deal(1, th, CTX, &mut rng).unwrap();
        assert_eq!(
            c.deal(SealedDealing {
                dealing: d,
                shares: BTreeMap::new()
            }),
            Err(CeremonyError::NotDealing)
        );
        assert_eq!(
            c.confirm(1, BTreeSet::new()),
            Err(CeremonyError::NotConfirming)
        );
        assert!(matches!(
            c.confirm(1, BTreeSet::from([1])),
            Err(CeremonyError::Malformed(_))
        ));
        // The deadline before every trustee enrolled fails the ceremony.
        assert!(c.deadline());
        assert_eq!(c.phase(), Phase::Failed);
        assert!(!c.deadline());
    }

    #[test]
    fn a_dealing_without_one_share_per_trustee_is_refused() {
        let mut rng = StdRng::seed_from_u64(23);
        let th = Threshold::new(2, 3).unwrap();
        let (mut c, _) = enrolled(&mut rng, th);
        let tks: Vec<TransportKey> = c.transport_keys().copied().collect();
        let (dealing, shares) = deal(1, th, CTX, &mut rng).unwrap();
        let two: BTreeMap<u32, Sealed> = shares[..2]
            .iter()
            .map(|s| {
                (
                    s.recipient,
                    seal_share(s, &tks[s.recipient as usize - 1], CTX, &mut rng).unwrap(),
                )
            })
            .collect();
        assert!(matches!(
            c.deal(SealedDealing {
                dealing,
                shares: two
            }),
            Err(CeremonyError::DealingInvalid(_))
        ));
    }
}
