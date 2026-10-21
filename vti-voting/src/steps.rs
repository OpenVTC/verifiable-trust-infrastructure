//! The trustees' steps on the board (CONVENTIONS §9.6, "Every step is the trustee's own"). Each
//! enrolment, dealing, confirmation and justification is a `trusteeStep` entry carrying the
//! trustee's signed request exactly as the ballot box received it, so anyone reading the board can
//! tell who took it. Without that, a ballot box could deal in a trustee's name — a polynomial of
//! its own, with matching shares sealed to that trustee's transport key — and hold the election
//! key while every other check passed (VTI-VOT-062).
//!
//! [`read`] turns a request back into a [`TrusteeStep`] once it is the named trustee's. Proofs
//! need DID resolution, which this crate leaves to its caller: a board someone else kept is read
//! through [`ProvenRequests::prove`], whose result is the only way to vouch for a signer here.

use std::{
    collections::{BTreeSet, HashMap},
    future::Future,
};

use curve25519_dalek::Scalar;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trust_tasks_rs::specs::voting::trustees::{
    confirm::v0_1 as confirm, deal::v0_1 as deal, enrol::v0_1 as enrol, justify::v0_1 as justify,
};

use crate::{
    ceremony::{Ceremony, CeremonyError, SealedDealing, Step},
    trustees::{TransportKey, scalar_from_text},
    wire,
};

/// The board entry kind.
pub const KIND: &str = "trusteeStep";

/// The entry kinds `trusteeStep` replaced. Never appended; a board holding one is refused.
pub const RETIRED_KINDS: [&str; 4] = ["transportKey", "dealing", "confirmation", "justification"];

/// The board entry for a request, as received.
pub fn entry(request: &Value) -> Value {
    json!({ "kind": KIND, "request": request })
}

/// One step of the key ceremony.
#[derive(Debug, Clone)]
pub enum TrusteeStep {
    Enrol(TransportKey),
    Deal(SealedDealing),
    Confirm {
        trustee: u32,
        complaints: BTreeSet<u32>,
    },
    Justify {
        dealer: u32,
        recipient: u32,
        share: Scalar,
    },
}

impl TrusteeStep {
    /// Run the step through the ceremony.
    ///
    /// # Errors
    /// The ceremony's refusal.
    pub fn apply(self, c: &mut Ceremony) -> Result<Step, CeremonyError> {
        match self {
            Self::Enrol(tk) => c.enrol(tk),
            Self::Deal(d) => c.deal(d),
            Self::Confirm {
                trustee,
                complaints,
            } => c.confirm(trustee, complaints),
            Self::Justify {
                dealer,
                recipient,
                share,
            } => c.justify(dealer, recipient, share),
        }
    }
}

/// Why a request is not a step of this election's ceremony.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StepError {
    /// Not `voting/trustees/{enrol,deal,confirm,justify}/0.1`.
    #[error("not a trustee step: {0}")]
    NotAStep(String),
    /// Its payload names another community or election.
    #[error("a step of another election")]
    OtherElection,
    /// Its issuer is not the trustee the manifest names at the payload's index (VTI-VOT-062).
    #[error("its issuer is not the trustee the manifest names at index {0}")]
    NotTheTrustee(u32),
    /// Nobody vouched for its proof, or the proof is not its issuer's.
    #[error("its proof is not its issuer's")]
    Unproven,
    /// The payload does not read as the task's.
    #[error("{0}")]
    Malformed(String),
}

/// The election a step must belong to.
#[derive(Debug, Clone, Copy)]
pub struct Election<'a> {
    pub community: &'a str,
    pub election_id: &'a str,
    /// The manifest's `trustees.dids`, in order: trustee `j` is `trustees[j - 1]`.
    pub trustees: &'a [&'a str],
}

fn type_uri<P: trust_tasks_rs::Payload>() -> String {
    P::TYPE_URI.to_string()
}

fn parsed<P: serde::de::DeserializeOwned>(payload: &Value) -> Result<P, StepError> {
    serde_json::from_value(payload.clone()).map_err(|e| StepError::Malformed(e.to_string()))
}

fn index(v: &Value) -> Result<u32, StepError> {
    v.as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| StepError::Malformed("a trustee index".into()))
}

/// `request` as a step of `election`, given `signer`, the party proven to have signed it — the
/// ballot box's own record of a request it verified on receipt, or [`ProvenRequests::signer`]
/// for a board someone else kept. Checks CONVENTIONS §9.6 items 1 – 3 against it; item 4 is
/// `signer`'s provenance.
///
/// # Errors
/// The first check that fails.
pub fn read(
    request: &Value,
    election: Election<'_>,
    signer: &str,
) -> Result<TrusteeStep, StepError> {
    let ty = request["type"].as_str().unwrap_or_default();
    let payload = &request["payload"];
    if request["issuer"].as_str() != Some(signer) {
        return Err(StepError::Unproven);
    }
    if payload["community"].as_str() != Some(election.community)
        || payload["electionId"].as_str() != Some(election.election_id)
    {
        return Err(StepError::OtherElection);
    }
    let malformed = |e: crate::trustees::TrusteeError| StepError::Malformed(e.to_string());
    let (trustee, step) = if ty == type_uri::<enrol::Payload>() {
        let _: enrol::Payload = parsed(payload)?;
        let tk = wire::transport_key(&payload["transportKey"]).map_err(malformed)?;
        (
            index(&payload["transportKey"]["trustee"])?,
            TrusteeStep::Enrol(tk),
        )
    } else if ty == type_uri::<deal::Payload>() {
        let _: deal::Payload = parsed(payload)?;
        let d = wire::dealing(&payload["dealing"]).map_err(malformed)?;
        (index(&payload["dealing"]["dealer"])?, TrusteeStep::Deal(d))
    } else if ty == type_uri::<confirm::Payload>() {
        let _: confirm::Payload = parsed(payload)?;
        let trustee = index(&payload["trustee"])?;
        let complaints = payload["complaints"]
            .as_array()
            .map_or(Ok(BTreeSet::new()), |a| a.iter().map(index).collect())?;
        (
            trustee,
            TrusteeStep::Confirm {
                trustee,
                complaints,
            },
        )
    } else if ty == type_uri::<justify::Payload>() {
        let _: justify::Payload = parsed(payload)?;
        let dealer = index(&payload["dealer"])?;
        let share =
            scalar_from_text(payload["share"].as_str().unwrap_or_default()).map_err(malformed)?;
        (
            dealer,
            TrusteeStep::Justify {
                dealer,
                recipient: index(&payload["recipient"])?,
                share,
            },
        )
    } else {
        return Err(StepError::NotAStep(ty.to_string()));
    };
    let named = trustee
        .checked_sub(1)
        .and_then(|i| election.trustees.get(i as usize));
    if named != Some(&signer) {
        return Err(StepError::NotTheTrustee(trustee));
    }
    Ok(step)
}

/// The signers proven for the trustees' requests on a board: built only by [`Self::prove`], from
/// a verifier the caller supplies (it resolves DIDs; this crate does not).
#[derive(Debug, Clone, Default)]
pub struct ProvenRequests {
    signers: HashMap<[u8; 32], String>,
}

fn digest(request: &Value) -> Option<[u8; 32]> {
    serde_json_canonicalizer::to_vec(request)
        .ok()
        .map(|b| Sha256::digest(b).into())
}

impl ProvenRequests {
    /// Ask `verify` for the signer of every `trusteeStep` request among `entries`: the DID its
    /// proof verifies as (framework SPEC §4.7), or `None`. A request it does not vouch for is
    /// [`StepError::Unproven`] when read.
    pub async fn prove<F, Fut>(entries: &[Value], mut verify: F) -> Self
    where
        F: FnMut(Value) -> Fut,
        Fut: Future<Output = Option<String>>,
    {
        let mut signers = HashMap::new();
        for e in entries.iter().filter(|e| e["kind"] == KIND) {
            let request = &e["request"];
            if let (Some(d), Some(signer)) = (digest(request), verify(request.clone()).await) {
                signers.insert(d, signer);
            }
        }
        Self { signers }
    }

    /// The proven signer of `request`, if any.
    pub fn signer(&self, request: &Value) -> Option<&str> {
        self.signers.get(&digest(request)?).map(String::as_str)
    }
}
