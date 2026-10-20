//! The member's half, which their VTA runs: a key for one election, the blinded ticket request,
//! and the cast.
//!
//! **One key per election.** A VTA derives the seed for [`Voter::from_seed`] from a fresh path
//! under the context's base for each election (VTI-KEY-030), so a tag recovered by a future
//! adversary links one election, never a member's voting history. One key may also not hold two
//! tickets for an election: the registrar's caller allows one ticket per member per election.

use predicate_credential_system::pcs::{
    Attestation, Credential, IssuanceState, PredicateCredentialSystem, RootRequest, UserSecretKey,
};
use rand::{CryptoRng, RngCore};

use crate::{
    VotingError,
    election::Election,
    registrar::PreTicket,
    scheme::{Base, E, G1, VotingParams, point_text},
};

/// The blinded request a voter sends the registrar for a ticket.
pub type TicketRequest = RootRequest<E, Base>;
/// What unblinds the registrar's answer. Secret, kept by the voter until the answer arrives.
pub type TicketState = IssuanceState<E, Base>;

pub struct Voter {
    usk: UserSecretKey<E>,
    id: G1,
}

impl std::fmt::Debug for Voter {
    /// Never `usk`: it is every tag this voter will make.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Voter").finish_non_exhaustive()
    }
}

/// A voter's ticket for one election. Secret: whoever holds it and the voter's key can vote.
pub struct Ticket {
    election: Election,
    cred: Credential<E, Base>,
}

impl std::fmt::Debug for Ticket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ticket")
            .field("election", &self.election.id())
            .finish_non_exhaustive()
    }
}

impl Ticket {
    pub fn election(&self) -> &Election {
        &self.election
    }

    /// The ticket's credential as the suite's canonical encoding, multibase, for an agent to
    /// keep wrapped at rest. **Secret.**
    ///
    /// # Errors
    /// [`VotingError::Serialization`] if the credential cannot be encoded.
    pub fn to_text(&self) -> Result<String, VotingError> {
        vti_vetting_pcs::scheme::enc(&self.cred)
            .map_err(|e| VotingError::Serialization(e.to_string()))
    }

    /// The inverse of [`Self::to_text`], for `election`.
    ///
    /// # Errors
    /// [`VotingError::Serialization`] if the text is not an encoded credential.
    pub fn from_text(election: Election, text: &str) -> Result<Self, VotingError> {
        let cred = vti_vetting_pcs::scheme::dec(text)
            .map_err(|e| VotingError::Serialization(e.to_string()))?;
        Ok(Self { election, cred })
    }
}

/// A cast: the attestation that admits one ballot. The ballot's bytes travel beside it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Cast {
    pub attestation: Attestation<E, Base>,
}

impl Cast {
    /// The tag, multibase: this ticket's nullifier in this election.
    ///
    /// # Errors
    /// [`VotingError::Serialization`] if the point cannot be encoded.
    pub fn tag(&self) -> Result<String, VotingError> {
        point_text(&self.attestation.tag).map_err(|e| VotingError::Serialization(e.to_string()))
    }
}

impl Voter {
    /// A fresh key pair from `rng`.
    ///
    /// # Errors
    /// [`VotingError::Pcs`] if the key pair cannot be generated.
    pub fn generate<R: RngCore + CryptoRng>(
        params: &VotingParams,
        rng: &mut R,
    ) -> Result<Self, VotingError> {
        let (id, usk) = params.open().user_keygen(rng)?;
        Ok(Self { usk, id })
    }

    /// The key pair from a 32-byte seed: the same seed always gives the same key, so a VTA never
    /// stores it.
    ///
    /// # Errors
    /// As [`Self::generate`].
    pub fn from_seed(params: &VotingParams, seed: &[u8; 32]) -> Result<Self, VotingError> {
        Self::generate(params, &mut vti_vetting_pcs::scheme::seeded_rng(seed))
    }

    /// The voter's PCS identifier. The registrar sees it in the request; no cast reveals it.
    pub fn id(&self) -> &G1 {
        &self.id
    }

    /// The blinded request for a ticket to `election`, and the state that unblinds the answer.
    ///
    /// # Errors
    /// [`VotingError::WrongCommunity`], or [`VotingError::Pcs`] if the request cannot be built.
    pub fn ticket_request<R: RngCore + CryptoRng>(
        &self,
        params: &VotingParams,
        election: &Election,
        rng: &mut R,
    ) -> Result<(TicketRequest, TicketState), VotingError> {
        same_community(params, election)?;
        Ok(params.open().root_request(
            params.hvk(),
            &election.predicate(),
            &self.id,
            &self.usk,
            rng,
        )?)
    }

    /// Unblind the registrar's answer into this voter's ticket.
    ///
    /// # Errors
    /// [`VotingError::Pcs`] if it does not unblind under the published key, which is what a
    /// wrong or swapped answer looks like from here.
    pub fn accept_ticket(
        &self,
        params: &VotingParams,
        election: &Election,
        pre: &PreTicket,
        state: &TicketState,
    ) -> Result<Ticket, VotingError> {
        same_community(params, election)?;
        let cred =
            params
                .open()
                .unblind(params.hvk(), &self.usk, &election.predicate(), pre, state)?;
        Ok(Ticket {
            election: election.clone(),
            cred,
        })
    }

    /// The wire `Cast` (conventions §3.6) for a ballot as JSON: the attestation is made over the
    /// ballot's RFC 8785 (JCS) bytes, and `tag` and `attestation` are the suite's canonical
    /// encodings, multibase.
    ///
    /// # Errors
    /// As [`Self::cast`]; [`VotingError::Serialization`] if the ballot cannot be canonicalized.
    pub fn cast_wire<R: RngCore + CryptoRng>(
        &self,
        params: &VotingParams,
        ticket: &Ticket,
        ballot: &serde_json::Value,
        rng: &mut R,
    ) -> Result<serde_json::Value, VotingError> {
        let bytes = serde_json_canonicalizer::to_vec(ballot)
            .map_err(|e| VotingError::Serialization(e.to_string()))?;
        let cast = self.cast(params, ticket, &bytes, rng)?;
        let attestation = vti_vetting_pcs::scheme::enc(&cast.attestation)
            .map_err(|e| VotingError::Serialization(e.to_string()))?;
        Ok(serde_json::json!({
            "ballot": ballot,
            "tag": cast.tag()?,
            "attestation": attestation,
        }))
    }

    /// The wire `EncryptedCast` (CONVENTIONS §9.5) for an encrypted form from
    /// [`encrypted_form`]: the attestation is made over the form's JCS bytes, never the
    /// plaintext ballot's.
    ///
    /// # Errors
    /// As [`Self::cast_wire`].
    pub fn cast_encrypted_wire<R: RngCore + CryptoRng>(
        &self,
        params: &VotingParams,
        ticket: &Ticket,
        form: &EncryptedForm,
        rng: &mut R,
    ) -> Result<serde_json::Value, VotingError> {
        let (field, value) = match form {
            EncryptedForm::Sealed(v) => ("sealed", v),
            EncryptedForm::Encrypted(v) => ("encrypted", v),
        };
        let bytes = serde_json_canonicalizer::to_vec(value)
            .map_err(|e| VotingError::Serialization(e.to_string()))?;
        let cast = self.cast(params, ticket, &bytes, rng)?;
        let attestation = vti_vetting_pcs::scheme::enc(&cast.attestation)
            .map_err(|e| VotingError::Serialization(e.to_string()))?;
        Ok(serde_json::json!({
            field: value,
            "tag": cast.tag()?,
            "attestation": attestation,
        }))
    }

    /// Cast `ballot` with `ticket`: an attestation for the election's point, bound to the ballot.
    ///
    /// # Errors
    /// [`VotingError::WrongCommunity`], or [`VotingError::Pcs`] if the attestation cannot be made.
    pub fn cast<R: RngCore + CryptoRng>(
        &self,
        params: &VotingParams,
        ticket: &Ticket,
        ballot: &[u8],
        rng: &mut R,
    ) -> Result<Cast, VotingError> {
        let election = &ticket.election;
        same_community(params, election)?;
        let attestation = params.open().attest_in_context(
            params.hvk(),
            &self.usk,
            &election.predicate(),
            &ticket.cred,
            &election.point()?,
            &election.ballot_context(ballot),
            rng,
        )?;
        Ok(Cast { attestation })
    }
}

/// A ballot in the form its election's level casts it.
#[derive(Debug, Clone, PartialEq)]
pub enum EncryptedForm {
    /// A `SealedPayload`: the ballot's JCS bytes sealed to the election key.
    Sealed(serde_json::Value),
    /// An `EncryptedBallot`: each choice question's options as 0/1 ciphertexts with proofs.
    Encrypted(serde_json::Value),
}

/// The encrypted form of `ballot` (already checked against the manifest,
/// [`crate::rules::check_ballot`]) under the formed election key (CONVENTIONS §9.4 – 9.5).
///
/// # Errors
/// [`VotingError::Serialization`] for a ballot that cannot be canonicalized, a level that is not
/// encrypted, or a tallied-encrypted ballot that answers anything but choice questions.
pub fn encrypted_form<R: RngCore + CryptoRng>(
    manifest: &trust_tasks_rs::specs::voting::election::register::v0_1::Manifest,
    election: &Election,
    key: &crate::trustees::ElectionKey,
    ballot: &serde_json::Value,
    rng: &mut R,
) -> Result<EncryptedForm, VotingError> {
    use trust_tasks_rs::specs::voting::election::register::v0_1::{Question, SecrecyLevel};
    let bad = |why: String| VotingError::Serialization(why);
    let ctx = election.trustee_context();
    match manifest.secrecy {
        SecrecyLevel::Sealed => {
            let bytes = serde_json_canonicalizer::to_vec(ballot).map_err(|e| bad(e.to_string()))?;
            let sealed =
                crate::trustees::seal(key, &bytes, &ctx, rng).map_err(|e| bad(e.to_string()))?;
            Ok(EncryptedForm::Sealed(crate::wire::sealed_value(&sealed)))
        }
        SecrecyLevel::TalliedEncrypted => {
            let mut questions = Vec::with_capacity(manifest.questions.len());
            for q in &manifest.questions {
                let Question::Choice {
                    key: qkey,
                    options,
                    min_selections,
                    max_selections,
                    optional,
                    ..
                } = q
                else {
                    return Err(bad("a tallied-encrypted election asks choices only".into()));
                };
                let answer = ballot["answers"]
                    .as_array()
                    .and_then(|a| a.iter().find(|a| a["question"] == qkey.as_str()));
                let chosen: Vec<bool> = options
                    .iter()
                    .map(|o| {
                        answer
                            .and_then(|a| a["choice"].as_array())
                            .is_some_and(|c| c.iter().any(|k| k == o.key.as_str()))
                    })
                    .collect();
                let counts = crate::trustees::admitted_counts(
                    options.len(),
                    *min_selections,
                    max_selections.get(),
                    *optional,
                )
                .map_err(|e| bad(e.to_string()))?;
                let eq = crate::trustees::encrypt_vote(
                    key,
                    &chosen,
                    &counts,
                    &crate::trustees::question_ctx(&ctx, qkey.as_str()),
                    rng,
                )
                .map_err(|e| bad(e.to_string()))?;
                questions.push(crate::wire::encrypted_question_value(qkey.as_str(), &eq));
            }
            Ok(EncryptedForm::Encrypted(serde_json::json!({
                "electionId": election.id().as_str(),
                "manifestDigest": crate::rules::digest_multibase(election.manifest_digest()),
                "questions": questions,
            })))
        }
        _ => Err(bad("an open election is cast in the clear".into())),
    }
}

fn same_community(params: &VotingParams, election: &Election) -> Result<(), VotingError> {
    if params.community() == election.community() {
        Ok(())
    } else {
        Err(VotingError::WrongCommunity {
            expected: params.community().to_string(),
            actual: election.community().to_string(),
        })
    }
}
