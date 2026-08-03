//! Wait out a `requireConsent` gate from a CLI.
//!
//! A consent-gated task is not refused, it is *deferred*: the VTA raises a
//! question, pushes it to the approver set, and holds the answer. Until this
//! existed, no CLI could answer it — `pnm` printed `auth:consent_required` and
//! exited, so every gated task was simply unreachable from the command line
//! however privileged the operator was. The browser extension implemented the
//! loop; nothing in Rust did.
//!
//! ## Re-submitting is the only way to ask
//!
//! There is no read-only status surface for task-consent, so "has it been
//! approved yet?" can only be asked by submitting the task again. That is safe
//! **while the request is pending** and unsafe once it is resolved, and the
//! difference is load-bearing:
//!
//! - Pending: the gate recognises the same payload, returns the *same*
//!   `challenge`, and deliberately does not re-notify. The push follows the
//!   question, not the submit — so polling cannot ring the approver's device.
//! - Denied or lapsed: the pending record is **deleted**. The next submit finds
//!   nothing, raises a *new* question, and pushes again.
//!
//! So the loop stops the moment the challenge changes. Continuing would turn a
//! "no" into a nag, which is the habituation attack the gate's own design notes
//! warn about — a consent prompt an attacker can summon on demand is worth more
//! to them than one they must wait for. One re-prompt is unavoidable without a
//! server-side status task; an unbounded stream of them is not.
//!
//! ## What the operator has to do
//!
//! Compare the code printed here against the code on the approving device, and
//! approve only if they match. That comparison is the entire security value of
//! the flow: the digest is what the approver signs, so two screens showing the
//! same code means the thing being approved is the thing that will run.

use std::time::Duration;

use vta_sdk::error::VtaError;

/// How often to re-ask while the request is pending.
///
/// Each tick is a submit the gate answers from its pending record without
/// notifying anyone, so this trades responsiveness against request volume
/// only. Three seconds keeps a human-paced approval feeling immediate.
const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// How long to wait before giving up.
///
/// Bounded because the operator is sitting at a terminal. Giving up is not
/// failure — the request stays pending server-side, so re-running the same
/// command resumes waiting on the same challenge.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// Why the wait ended without the task running.
#[derive(Debug)]
pub enum ConsentOutcome {
    /// The approver said no, or the request lapsed — either way the pending
    /// record is gone and the challenge we were waiting on will never be
    /// answered.
    Resolved,
    /// Nobody answered within the timeout. The request is still pending.
    TimedOut,
}

/// Print the approval prompt for a freshly raised consent request.
fn announce(payload_digest: &str, approver_set: &str, min_approvals: u32, exclude_requester: bool) {
    eprintln!();
    eprintln!("  Approval required before this can run.");
    eprintln!();
    eprintln!("      code: {payload_digest}");
    eprintln!();
    if exclude_requester {
        eprintln!(
            "  {min_approvals} approval(s) needed from `{approver_set}`, and this device is not \
             eligible to give them — your policy requires a different device."
        );
        eprintln!("  Check the code above matches the one on your approving device, then approve");
        eprintln!("  it there. Do not approve a code that differs: a mismatch means the change");
        eprintln!("  being shown is not the change that would be made.");
    } else {
        eprintln!(
            "  {min_approvals} approval(s) needed from `{approver_set}`. This device may give \
             one if its DID is a member of that set."
        );
        eprintln!("  Approve on whichever enrolled device is showing this code.");
    }
    eprintln!();
    eprintln!("  Waiting… (Ctrl-C to stop; the request stays pending and re-running resumes it)");
}

/// Run `submit`, and if the VTA defers it for consent, wait for the approval
/// and run it again.
///
/// `submit` MUST produce a byte-identical request each time it is called. The
/// grant is bound to a digest of the payload, so a request that differs on
/// retry — a regenerated nonce, a re-read timestamp — will not match the
/// approval and will raise a second, unanswerable question instead.
///
/// Returns `Ok(Ok(value))` when the task ran, `Ok(Err(outcome))` when the wait
/// ended without it running, and `Err` for any non-consent failure.
pub async fn with_consent<F, Fut, T>(submit: F) -> Result<Result<T, ConsentOutcome>, VtaError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, VtaError>>,
{
    with_consent_timeout(submit, DEFAULT_TIMEOUT).await
}

/// [`with_consent`] with an explicit deadline. Separate so tests do not sleep
/// for the production timeout.
pub async fn with_consent_timeout<F, Fut, T>(
    submit: F,
    timeout: Duration,
) -> Result<Result<T, ConsentOutcome>, VtaError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, VtaError>>,
{
    // The challenge from the first refusal. Everything below is about noticing
    // when the server stops answering with this one.
    let waiting_on = match submit().await {
        Ok(value) => return Ok(Ok(value)),
        Err(VtaError::ConsentRequired {
            payload_digest,
            challenge,
            approver_set,
            min_approvals,
            exclude_requester,
        }) => {
            announce(
                &payload_digest,
                &approver_set,
                min_approvals,
                exclude_requester,
            );
            challenge
        }
        Err(other) => return Err(other),
    };

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Ok(Err(ConsentOutcome::TimedOut));
        }
        tokio::time::sleep(POLL_INTERVAL).await;

        match submit().await {
            Ok(value) => return Ok(Ok(value)),
            Err(VtaError::ConsentRequired { challenge, .. }) if challenge == waiting_on => {
                // Still the same question. The gate answered from its pending
                // record and notified nobody; keep waiting.
            }
            Err(VtaError::ConsentRequired { .. }) => {
                // A *different* challenge means our request is gone — denied,
                // or lapsed — and this submit has just raised a fresh one.
                // Stop here: asking again is what turns a refusal into a nag.
                return Ok(Err(ConsentOutcome::Resolved));
            }
            Err(other) => return Err(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn consent_required(challenge: &str) -> VtaError {
        VtaError::ConsentRequired {
            payload_digest: "ABC123".into(),
            challenge: challenge.into(),
            approver_set: "webvh-approvers".into(),
            min_approvals: 1,
            exclude_requester: true,
        }
    }

    /// The happy path: deferred, then approved.
    #[tokio::test(start_paused = true)]
    async fn an_approval_lets_the_task_through() {
        let calls = AtomicUsize::new(0);
        let out = with_consent(|| async {
            // Deferred twice, then the approval lands.
            match calls.fetch_add(1, Ordering::SeqCst) {
                0 | 1 => Err(consent_required("chal-1")),
                _ => Ok("published"),
            }
        })
        .await
        .expect("no transport error");

        assert!(matches!(out, Ok("published")));
        assert_eq!(calls.load(Ordering::SeqCst), 3, "polled until approved");
    }

    /// A task that is not gated must not pay for the machinery.
    #[tokio::test(start_paused = true)]
    async fn an_ungated_task_runs_immediately() {
        let calls = AtomicUsize::new(0);
        let out = with_consent(|| async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, VtaError>("published")
        })
        .await
        .expect("no transport error");

        assert!(matches!(out, Ok("published")));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "submitted exactly once");
    }

    /// The rule that keeps a denial from becoming a nag.
    ///
    /// A denial deletes the pending request, so the submit that discovers it
    /// has already raised — and pushed — a new one. Stopping on the changed
    /// challenge bounds that at a single prompt. Without this the loop would
    /// re-ask every tick, which is a consent prompt on demand.
    #[tokio::test(start_paused = true)]
    async fn a_changed_challenge_stops_the_loop() {
        let calls = AtomicUsize::new(0);
        let out = with_consent(|| async {
            match calls.fetch_add(1, Ordering::SeqCst) {
                0 => Err::<(), _>(consent_required("chal-1")),
                // Denied: the pending is gone and this submit raised a new one.
                _ => Err(consent_required("chal-2")),
            }
        })
        .await
        .expect("no transport error");

        assert!(matches!(out, Err(ConsentOutcome::Resolved)));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "stopped on the first changed challenge — no further prompts"
        );
    }

    /// Giving up leaves the request pending, so this is a bounded wait rather
    /// than a failure.
    #[tokio::test(start_paused = true)]
    async fn waiting_is_bounded() {
        let calls = AtomicUsize::new(0);
        let out = with_consent_timeout(
            || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err::<(), _>(consent_required("chal-1"))
            },
            Duration::from_secs(10),
        )
        .await
        .expect("no transport error");

        assert!(matches!(out, Err(ConsentOutcome::TimedOut)));
    }

    /// A real failure must not be mistaken for "still waiting".
    #[tokio::test(start_paused = true)]
    async fn a_non_consent_error_surfaces_immediately() {
        let calls = AtomicUsize::new(0);
        let err = with_consent(|| async {
            match calls.fetch_add(1, Ordering::SeqCst) {
                0 => Err::<(), _>(consent_required("chal-1")),
                _ => Err(VtaError::Protocol("the DID vanished".into())),
            }
        })
        .await
        .expect_err("a transport error must propagate");

        assert!(matches!(err, VtaError::Protocol(_)));
    }
}
