//! Shared did:webvh `versionTime` policy.
//!
//! `did:webvh` serialises `versionTime` at whole-second granularity, and a
//! resolver rejects a log entry whose timestamp is in the future or is not
//! strictly later than the previous entry's
//! (`didwebvh-rs::log_entry::read::verify_version_time`).
//!
//! Neither check runs when an entry is *written*: `create_log_entry` signs and
//! appends whatever timestamp it is handed. A bad one is therefore discovered
//! only at resolution — by which point the log is append-only, no later entry
//! can repair it, and the DID is permanently unresolvable. That is the whole
//! reason this policy is centralised here rather than open-coded at each
//! builder: a call site that gets it wrong does not fail, it bricks an
//! identity.
//!
//! An earlier version of this policy backdated genesis by a day and spaced
//! subsequent entries a minute apart by index, to paper over the TEE genesis
//! path stamping real wall-clock time while runtime updates backdated. That
//! asymmetry is gone now: every entry, genesis or update, goes through
//! [`next_version_time`], so there is nothing left to reconcile by shifting
//! timestamps into the past. Instead, when the natural next timestamp (the
//! previous entry's `versionTime` plus one second) would be in the future,
//! this function **waits** for the wall clock to reach it, rather than
//! stamping a timestamp that isn't valid yet. This is the direction
//! did:webvh's own maintainers converged on for rapid version generation
//! (<https://github.com/decentralized-identity/didwebvh/issues/272>,
//! <https://github.com/decentralized-identity/didwebvh/pull/276>). Backdating
//! was a standing liability by comparison — every derived offset was one more
//! thing a longer chain or a changed spacing constant could get wrong.
//!
//! Two consequences are worth stating plainly, because the backdate used to
//! cover both and neither is obvious once it is gone:
//!
//! - **There is no skew tolerance on the verifying side.** `didwebvh-rs`
//!   rejects `versionTime > Utc::now()` outright, with no grace window
//!   (`log_entry::read::verify_version_time`). A near-future entry is
//!   "tolerated" only in the sense that it becomes valid once the *verifier's*
//!   clock passes it — so an entry stamped at our `now` does not resolve for a
//!   peer whose clock is behind ours until the skew clears. A day of
//!   backdating used to absorb that; nothing does now. That is a deliberate
//!   trade, not an oversight, but it does mean host clocks have to be sane:
//!   NTP is the first thing to suspect when a freshly minted DID resolves
//!   locally and not off-box.
//! - **The wait is bounded** ([`MAX_WAIT_SECONDS`]). Waiting is only ever the
//!   right answer for the sub-second-to-one-second gap this policy creates for
//!   itself. A previous entry stamped well ahead of our clock — a chain minted
//!   elsewhere, or a backwards NTP step on this host — would otherwise park
//!   the request, and everything queued behind it, for the whole skew with no
//!   error and no log line. Past the cap we stamp `previous + 1s` anyway and
//!   warn: strict increase is the invariant that must not bend, and a
//!   transiently future-dated entry resolves once clocks agree, whereas a
//!   non-increasing one is fatal and permanent. Transient beats terminal.
//!
//! Every `versionTime` this workspace stamps goes through
//! [`next_version_time`].

use std::future::Future;

use chrono::{DateTime, Duration, FixedOffset, Timelike, Utc};

/// Ceiling on how long [`next_version_time`] will wait for the wall clock to
/// reach a valid timestamp.
///
/// The only legitimate wait is the one this policy creates for itself: at most
/// one second, when two entries on a chain land in the same wall-clock second.
/// Anything longer means the previous entry sits ahead of our clock for a
/// reason waiting cannot fix. See the module docs for what happens past it.
pub const MAX_WAIT_SECONDS: i64 = 5;

/// The `versionTime` to stamp on the next did:webvh log entry of a chain, and
/// how long you must wait before it is safe to use.
///
/// `previous` is the preceding entry's `versionTime`, or `None` for genesis.
/// `now` is the current wall-clock time.
///
/// The returned target is always strictly later than `previous` (when
/// given); once the returned `wait` has elapsed, the target is guaranteed not
/// to be future-dated. In the common case — `previous` comfortably in the
/// past, or this being genesis — `wait` is zero and the target is simply
/// `now`.
///
/// `wait` is measured from the truncated second and so is an upper bound on
/// the real wait, by up to the sub-second remainder. It decides *whether* to
/// wait; [`wait_until_not_future`] recomputes the actual remaining time
/// against the untruncated clock.
///
/// Split out of [`next_version_time`] so the timestamp arithmetic is testable
/// without a real sleep: tests drive `now`/`previous` directly and assert on
/// `(target, wait)`, while [`next_version_time`] is the thin async wrapper
/// that actually waits.
fn plan_version_time(
    previous: Option<DateTime<FixedOffset>>,
    now: DateTime<FixedOffset>,
) -> (DateTime<FixedOffset>, Duration) {
    // Work in whole seconds throughout, because that is the only precision
    // that survives serialisation. Comparing sub-second values would let two
    // entries a few microseconds apart look strictly increasing here and
    // serialise to the identical timestamp on the wire — which is the exact
    // collision this helper exists to prevent.
    let now = truncate_to_second(now);

    match previous.map(truncate_to_second) {
        // The natural next second is already in the past: nothing to wait
        // for.
        Some(prev) if prev < now => (now, Duration::zero()),
        // `prev >= now`: the only strictly-later second is `prev + 1`, which
        // is at or after `now` and so must be waited for.
        Some(prev) => {
            let target = prev + Duration::seconds(1);
            (target, target - now)
        }
        // Genesis: no previous entry to be later than, so `now` is valid
        // immediately.
        None => (now, Duration::zero()),
    }
}

/// The `versionTime` to stamp on the next did:webvh log entry of a chain.
///
/// `previous` is the preceding entry's `versionTime`, or `None` for genesis.
///
/// The result is always strictly later than `previous`, and is never
/// future-dated relative to the wall clock by the time this returns: when the
/// only valid next timestamp is still ahead of `now` (rapid back-to-back
/// entries on the same chain), this function waits for the clock to reach it
/// rather than fabricating a past-dated one.
///
/// **Always pass `previous` when the chain has entries.** This policy makes
/// no assumption about how earlier entries were stamped — a chain whose
/// genesis carries an unusual timestamp (a clock that was skewed at the time,
/// or any log minted by another implementation) still gets a correctly
/// ordered next entry, because it clamps against the actual previous entry
/// rather than an assumed one.
///
/// Calls into the async runtime (`tokio::time::sleep`) only when a wait is
/// actually required; the overwhelmingly common case — `previous` already
/// comfortably in the past, or this being genesis — returns immediately. The
/// wait is capped at [`MAX_WAIT_SECONDS`]; past that we stamp the target
/// anyway and warn rather than park the caller (see the module docs).
pub async fn next_version_time(previous: Option<DateTime<FixedOffset>>) -> DateTime<FixedOffset> {
    let now = Utc::now().fixed_offset();
    let (target, wait) = plan_version_time(previous, now);
    if wait > Duration::zero()
        && let Err(outstanding) = wait_until_not_future(
            target,
            Duration::seconds(MAX_WAIT_SECONDS),
            || Utc::now().fixed_offset(),
            tokio::time::sleep,
        )
        .await
    {
        tracing::warn!(
            version_time = %target,
            outstanding_seconds = outstanding.num_seconds(),
            "the next valid versionTime is more than {MAX_WAIT_SECONDS}s ahead of this \
             host's clock; stamping it rather than parking the request. The entry \
             resolves once clocks agree. Check NTP on this host and on whatever minted \
             the previous log entry."
        );
    }
    target
}

/// Wait until `target` is no longer future-dated according to `now`, or give
/// up once the accumulated sleep would exceed `max_wait`.
///
/// Recheck after every sleep: wall time can move backwards while waiting (for
/// example, due to NTP correction), making the original wait insufficient.
/// Budget the *accumulated* sleep rather than trusting a clock difference, so
/// a clock that keeps stepping backwards cannot loop here indefinitely. The
/// injected functions keep both cases testable.
///
/// `target` is compared against the raw clock, deliberately not a truncated
/// one. It is always a whole second by construction ([`plan_version_time`]),
/// and `target <= now` is exactly the condition a resolver checks, so
/// truncating `now` here would add up to a second of needless waiting — and
/// would never terminate at all for a `target` carrying a sub-second
/// remainder, since the final comparison could never reach zero.
///
/// `Err(remaining)` means it gave up, carrying the wait still outstanding.
async fn wait_until_not_future<Now, Sleep, SleepFuture>(
    target: DateTime<FixedOffset>,
    max_wait: Duration,
    mut now: Now,
    mut sleep: Sleep,
) -> Result<(), Duration>
where
    Now: FnMut() -> DateTime<FixedOffset>,
    Sleep: FnMut(std::time::Duration) -> SleepFuture,
    SleepFuture: Future<Output = ()>,
{
    let mut slept = Duration::zero();
    loop {
        let remaining = target - now();
        if remaining <= Duration::zero() {
            return Ok(());
        }
        if slept + remaining > max_wait {
            return Err(remaining);
        }
        // `remaining` is positive, so conversion to std duration cannot fail.
        if let Ok(std_remaining) = remaining.to_std() {
            sleep(std_remaining).await;
        }
        slept += remaining;
    }
}

/// Drop sub-second precision, matching what `did:webvh` serialises.
fn truncate_to_second(t: DateTime<FixedOffset>) -> DateTime<FixedOffset> {
    t.with_nanosecond(0)
        .expect("zero is always a valid nanosecond")
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_WAIT_SECONDS, next_version_time, plan_version_time, truncate_to_second,
        wait_until_not_future,
    };
    use chrono::{DateTime, Duration, FixedOffset, Utc};
    use std::cell::Cell;
    use std::rc::Rc;

    fn now() -> DateTime<FixedOffset> {
        Utc::now().fixed_offset()
    }

    /// Genesis (`previous = None`) is always immediately usable: no
    /// backdating, no waiting.
    #[test]
    fn genesis_is_now_with_no_wait() {
        let n = now();
        let (target, wait) = plan_version_time(None, n);

        assert_eq!(target.timestamp(), n.timestamp());
        assert_eq!(wait, Duration::zero());
    }

    /// A previous entry safely in the past needs no wait — the overwhelmingly
    /// common case (a real update, minutes or more after the last one).
    #[test]
    fn previous_in_the_past_needs_no_wait() {
        let n = now();
        let prev = n - Duration::hours(1);

        let (target, wait) = plan_version_time(Some(prev), n);

        assert_eq!(target.timestamp(), n.timestamp());
        assert_eq!(wait, Duration::zero());
    }

    /// Two entries landing in the same wall-clock second — the rapid /
    /// back-to-back case — must wait exactly long enough to clear that
    /// second, not silently collide and not overshoot.
    #[test]
    fn same_second_as_previous_waits_exactly_one_second() {
        let n = now();
        let prev = n; // same second, by construction of the truncation

        let (target, wait) = plan_version_time(Some(prev), n);

        assert!(target > prev, "target must be strictly after previous");
        assert_eq!(
            target.timestamp(),
            prev.timestamp() + 1,
            "target must be exactly the next second"
        );
        assert_eq!(wait, Duration::seconds(1));
    }

    /// A previous entry stamped slightly *ahead* of `now` (clock skew, or a
    /// legacy genesis minted by a host whose clock ran fast) must still
    /// produce a strictly later, non-past target — waited out, not
    /// backdated.
    #[test]
    fn previous_ahead_of_now_waits_past_it() {
        let n = now();
        let prev = n + Duration::seconds(3);

        let (target, wait) = plan_version_time(Some(prev), n);

        assert!(target > prev);
        assert_eq!(target.timestamp(), prev.timestamp() + 1);
        assert_eq!(wait, Duration::seconds(4));
    }

    /// The async wrapper actually waits: called twice back-to-back against
    /// the same previous timestamp (simulating a TEE genesis immediately
    /// followed by its first runtime update), the second call must return a
    /// target strictly later than the first, and must not return before the
    /// wait it computed has elapsed.
    #[tokio::test(start_paused = true)]
    async fn waits_for_rapid_back_to_back_calls() {
        let genesis = next_version_time(None).await;

        let started = tokio::time::Instant::now();
        let update = next_version_time(Some(genesis)).await;
        let elapsed = started.elapsed();

        assert!(update > genesis, "update must be strictly after genesis");
        assert_eq!(update.timestamp(), genesis.timestamp() + 1);
        // Paused tokio time only advances via `sleep` — this confirms the
        // second call actually awaited rather than returning immediately
        // with a stamped-but-invalid future timestamp.
        assert!(
            elapsed >= std::time::Duration::from_secs(1),
            "must have waited out the collision, elapsed={elapsed:?}"
        );
    }

    /// The public helper uses Tokio's timer to wait, but resolver validity is
    /// measured against the real wall clock. Verify that a rapid follow-on
    /// entry is no longer future-dated when the helper returns.
    #[tokio::test]
    async fn rapid_update_is_not_future_dated_when_returned() {
        let genesis = next_version_time(None).await;
        let update = next_version_time(Some(genesis)).await;

        assert!(update > genesis, "update must be strictly after genesis");
        assert!(
            update <= Utc::now().fixed_offset(),
            "update must not be future-dated when returned: update={update}"
        );
    }

    /// Wall time can step backwards mid-wait (an NTP correction), which makes
    /// the first sleep insufficient. The loop must notice and wait again.
    ///
    /// `target` is whole-second here because that is what `plan_version_time`
    /// always produces. Handing `wait_until_not_future` a `target` with a
    /// sub-second remainder used to spin forever — `target - truncate(now)`
    /// stays positive even once `now` has reached `target` — which hung this
    /// very test and took the CI job down with it.
    #[tokio::test]
    async fn waits_again_after_a_backward_clock_adjustment() {
        let start = truncate_to_second(now());
        let target = start + Duration::seconds(1);
        let current = Rc::new(Cell::new(start));
        let sleeps = Rc::new(std::cell::RefCell::new(Vec::new()));
        let current_for_clock = Rc::clone(&current);
        let current_for_sleep = Rc::clone(&current);
        let sleeps_for_sleep = Rc::clone(&sleeps);

        let outcome = wait_until_not_future(
            target,
            Duration::seconds(10),
            move || current_for_clock.get(),
            move |duration| {
                sleeps_for_sleep.borrow_mut().push(duration);
                let next = if sleeps_for_sleep.borrow().len() == 1 {
                    start - Duration::seconds(2)
                } else {
                    target
                };
                current_for_sleep.set(next);
                std::future::ready(())
            },
        )
        .await;

        assert_eq!(outcome, Ok(()), "the wait must complete within its budget");
        assert_eq!(
            sleeps.borrow().as_slice(),
            [
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(3)
            ],
            "a backward clock adjustment must trigger another wait"
        );
    }

    /// A previous entry far ahead of this host's clock must not park the
    /// caller — and everything queued behind it — for the length of the skew.
    /// Past the budget the wait is abandoned, with nothing slept at all.
    #[tokio::test]
    async fn gives_up_rather_than_parking_on_a_far_future_target() {
        let start = truncate_to_second(now());
        let target = start + Duration::hours(1);
        let sleeps = Rc::new(std::cell::RefCell::new(Vec::new()));
        let sleeps_for_sleep = Rc::clone(&sleeps);

        let outcome = wait_until_not_future(
            target,
            Duration::seconds(MAX_WAIT_SECONDS),
            move || start,
            move |duration| {
                sleeps_for_sleep.borrow_mut().push(duration);
                std::future::ready(())
            },
        )
        .await;

        assert_eq!(outcome, Err(Duration::hours(1)));
        assert!(
            sleeps.borrow().is_empty(),
            "an over-budget wait must not sleep at all, slept {:?}",
            sleeps.borrow()
        );
    }

    /// The same guarantee end to end: a chain whose previous entry is an hour
    /// ahead of us still returns promptly, with a strictly-later timestamp.
    /// Strict increase is the invariant that must not bend; future-dating is
    /// transient and self-heals once clocks agree.
    #[tokio::test]
    async fn next_version_time_returns_promptly_despite_a_far_future_previous() {
        let previous = Utc::now().fixed_offset() + Duration::hours(1);

        let started = std::time::Instant::now();
        let next = next_version_time(Some(previous)).await;
        let elapsed = started.elapsed();

        assert!(next > previous, "strict increase holds regardless");
        assert_eq!(next.timestamp(), previous.timestamp() + 1);
        assert!(
            elapsed < std::time::Duration::from_secs(MAX_WAIT_SECONDS as u64),
            "must not have waited out the skew, elapsed={elapsed:?}"
        );
    }

    /// A chain whose previous entry is a real wall-clock timestamp from
    /// another implementation — no longer a special case here, since this
    /// policy makes no assumption about how earlier entries were produced —
    /// must still get a strictly later entry.
    #[tokio::test(start_paused = true)]
    async fn clamps_against_a_legacy_previous_entry() {
        let legacy_genesis = Utc::now().fixed_offset() - Duration::seconds(30);

        let next = next_version_time(Some(legacy_genesis)).await;

        assert!(next > legacy_genesis);
        assert_ne!(next.timestamp(), legacy_genesis.timestamp());
    }

    /// The clamp must survive a run of several entries, not just the first
    /// one after a legacy genesis.
    #[tokio::test(start_paused = true)]
    async fn stays_increasing_across_a_run() {
        let mut prev = Utc::now().fixed_offset() - Duration::seconds(5);

        for index in 1..=5 {
            let next = next_version_time(Some(prev)).await;
            assert!(
                next > prev,
                "entry {index} must be strictly after its predecessor"
            );
            assert_ne!(next.timestamp(), prev.timestamp());
            prev = next;
        }
    }

    /// Concurrent callers computing against the *same* previous entry (e.g.
    /// two racing update attempts that both read the same chain head before
    /// either has written) converge on the same, single valid next timestamp
    /// rather than drifting apart or going future-dated. Which one actually
    /// gets to append it is decided by the store's optimistic-concurrency
    /// check, not by this function — this only guarantees that whichever one
    /// does append is stamping a valid entry.
    #[tokio::test(start_paused = true)]
    async fn concurrent_calls_against_the_same_previous_agree() {
        let genesis = next_version_time(None).await;

        let (a, b) = tokio::join!(
            next_version_time(Some(genesis)),
            next_version_time(Some(genesis)),
        );

        assert_eq!(a.timestamp(), b.timestamp());
        assert!(a > genesis);
    }
}
