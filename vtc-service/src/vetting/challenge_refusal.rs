//! Why a hidden-vetting submission's challenge was refused.
//!
//! A hidden-vetting proof is bound to a single-use challenge the community issued over
//! `vtc/vetting/pcs-challenge/0.1` ([`super::pcs_challenge`]), and the community spends it when
//! the proof arrives. The spend can fail four ways, and until this type existed all four reached
//! the applicant as one `malformedRequest` with the cause in a sentence — a client could not tell
//! "you took too long" from "your proof was built over the wrong challenge", which is the
//! difference between "try again" and "your client has a bug".
//!
//! Not behind `vetting-pcs`: the join spine carries it through [`crate::join`] whether or not the
//! build verifies hidden proofs, so the refusal path compiles one way. A build without the
//! feature never constructs one.

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use vta_sdk::protocols::join_requests as jr;
use vta_sdk::protocols::trust_task_reject_reasons as reasons;

/// Which task the refused challenge arrived on — the namespace its code is minted under
/// (SPEC §8.5: a consumer-minted code takes the slug of the request being processed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeTask {
    /// `vtc/join-requests/submit`.
    Submit,
    /// `vtc/join-requests/supplement`.
    Supplement,
}

/// Why the community refused the challenge a hidden-vetting proof is bound to.
///
/// Whichever it is, the challenge the community held for this applicant (if any) is spent by the
/// attempt: the remedy is always a fresh `vtc/vetting/pcs-challenge/0.1`, a proof built over it,
/// and another submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeRefusal {
    /// The community holds no challenge for this applicant: none was asked for, or the one asked
    /// for expired and has since been swept.
    NotIssued,
    /// The challenge was spent by an earlier submission.
    AlreadyUsed,
    /// The challenge's window had closed.
    Expired {
        /// When it stopped being accepted — the `expiresAt` the community answered with.
        expired_at: DateTime<Utc>,
    },
    /// The proof is bound to a challenge other than the one the community holds for this
    /// applicant — most often an older one, replaced when the applicant asked again.
    Mismatch,
}

impl ChallengeRefusal {
    /// A stable, value-free label for logs and audit (`not_issued`, `already_used`, `expired`,
    /// `mismatch`). Never the challenge itself.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NotIssued => "not_issued",
            Self::AlreadyUsed => "already_used",
            Self::Expired { .. } => "expired",
            Self::Mismatch => "mismatch",
        }
    }

    /// The extended error code a client branches on, under `task`'s namespace.
    pub fn code(&self, task: ChallengeTask) -> &'static str {
        match (task, self) {
            (ChallengeTask::Submit, Self::NotIssued) => {
                jr::JOIN_REQUEST_SUBMIT_ERR_CHALLENGE_NOT_ISSUED
            }
            (ChallengeTask::Submit, Self::AlreadyUsed) => {
                jr::JOIN_REQUEST_SUBMIT_ERR_CHALLENGE_ALREADY_USED
            }
            (ChallengeTask::Submit, Self::Expired { .. }) => {
                jr::JOIN_REQUEST_SUBMIT_ERR_CHALLENGE_EXPIRED
            }
            (ChallengeTask::Submit, Self::Mismatch) => {
                jr::JOIN_REQUEST_SUBMIT_ERR_CHALLENGE_MISMATCH
            }
            (ChallengeTask::Supplement, Self::NotIssued) => {
                jr::JOIN_REQUEST_SUPPLEMENT_ERR_CHALLENGE_NOT_ISSUED
            }
            (ChallengeTask::Supplement, Self::AlreadyUsed) => {
                jr::JOIN_REQUEST_SUPPLEMENT_ERR_CHALLENGE_ALREADY_USED
            }
            (ChallengeTask::Supplement, Self::Expired { .. }) => {
                jr::JOIN_REQUEST_SUPPLEMENT_ERR_CHALLENGE_EXPIRED
            }
            (ChallengeTask::Supplement, Self::Mismatch) => {
                jr::JOIN_REQUEST_SUPPLEMENT_ERR_CHALLENGE_MISMATCH
            }
        }
    }

    /// The generic `details.reason` marker beside the code, so a client that does not know the
    /// code still recovers a typed error (SPEC §8.5 fallback): a challenge that is absent is
    /// `not_found`, one that is spent or lapsed is `gone`, and one that is not the challenge the
    /// community holds is `conflict`.
    pub fn marker(&self) -> &'static str {
        match self {
            Self::NotIssued => reasons::NOT_FOUND,
            Self::AlreadyUsed | Self::Expired { .. } => reasons::GONE,
            Self::Mismatch => reasons::CONFLICT,
        }
    }

    /// The `details` annex beyond the marker: `expiredAt` for an expired challenge, so a client
    /// can say when; nothing otherwise. Never the challenge value.
    pub fn details(&self) -> Option<Value> {
        match self {
            Self::Expired { expired_at } => Some(json!({
                "expiredAt": expired_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            })),
            _ => None,
        }
    }
}

const ASK_AGAIN: &str = "ask for a new one with vtc/vetting/pcs-challenge/0.1, build the proof \
                         over it, and submit again";

impl std::fmt::Display for ChallengeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotIssued => write!(
                f,
                "this community holds no hidden-vetting challenge for you — none was asked for, \
                 or it expired and was cleared; {ASK_AGAIN}"
            ),
            Self::AlreadyUsed => write!(
                f,
                "the hidden-vetting challenge this proof is bound to was already used by an \
                 earlier submission, and each is accepted once; {ASK_AGAIN}"
            ),
            Self::Expired { expired_at } => write!(
                f,
                "the hidden-vetting challenge this proof is bound to expired at {}; {ASK_AGAIN}",
                expired_at.to_rfc3339_opts(SecondsFormat::Secs, true)
            ),
            Self::Mismatch => write!(
                f,
                "the proof is bound to a different hidden-vetting challenge from the one this \
                 community issued you — usually an older one, replaced when a newer challenge \
                 was asked for. The challenge it held is spent by this attempt; {ASK_AGAIN}"
            ),
        }
    }
}

impl std::error::Error for ChallengeRefusal {}

/// The form a surface that carries no code sees (REST, the legacy problem-report path): the
/// same `400` every challenge failure has always been, with the sentence that now says which.
impl From<ChallengeRefusal> for vti_common::error::AppError {
    fn from(r: ChallengeRefusal) -> Self {
        Self::Validation(r.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> [ChallengeRefusal; 4] {
        [
            ChallengeRefusal::NotIssued,
            ChallengeRefusal::AlreadyUsed,
            ChallengeRefusal::Expired {
                expired_at: "2026-09-23T10:15:01Z".parse().unwrap(),
            },
            ChallengeRefusal::Mismatch,
        ]
    }

    #[test]
    fn each_refusal_has_its_own_code_under_each_task() {
        let expected = [
            (
                "vtc/join-requests/submit:challengeNotIssued",
                "vtc/join-requests/supplement:challengeNotIssued",
            ),
            (
                "vtc/join-requests/submit:challengeAlreadyUsed",
                "vtc/join-requests/supplement:challengeAlreadyUsed",
            ),
            (
                "vtc/join-requests/submit:challengeExpired",
                "vtc/join-requests/supplement:challengeExpired",
            ),
            (
                "vtc/join-requests/submit:challengeMismatch",
                "vtc/join-requests/supplement:challengeMismatch",
            ),
        ];
        for (r, (submit, supplement)) in all().iter().zip(expected) {
            assert_eq!(r.code(ChallengeTask::Submit), submit, "{r:?}");
            assert_eq!(r.code(ChallengeTask::Supplement), supplement, "{r:?}");
        }
    }

    #[test]
    fn each_refusal_carries_the_marker_a_code_unaware_client_reads() {
        let markers: Vec<_> = all().iter().map(ChallengeRefusal::marker).collect();
        assert_eq!(
            markers,
            [
                reasons::NOT_FOUND,
                reasons::GONE,
                reasons::GONE,
                reasons::CONFLICT
            ]
        );
    }

    #[test]
    fn only_an_expired_refusal_says_when() {
        for r in all() {
            match &r {
                ChallengeRefusal::Expired { .. } => assert_eq!(
                    r.details(),
                    Some(json!({ "expiredAt": "2026-09-23T10:15:01Z" }))
                ),
                _ => assert_eq!(r.details(), None, "{r:?}"),
            }
        }
    }

    /// Every message tells the applicant what to do next, and the kinds are distinct labels.
    #[test]
    fn every_message_names_the_remedy_and_every_kind_is_distinct() {
        let mut kinds = std::collections::BTreeSet::new();
        for r in all() {
            assert!(
                r.to_string().contains("vtc/vetting/pcs-challenge/0.1"),
                "{r}"
            );
            assert!(kinds.insert(r.kind()), "{}", r.kind());
        }
    }
}
