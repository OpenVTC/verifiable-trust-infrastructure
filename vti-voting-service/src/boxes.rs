//! The service's elections, one lock each (#2604).
//!
//! A [`BallotBox`] is a synchronous state machine over every election it holds, and it makes
//! what it accepts durable — an `fsync` — before it answers. Held as one box under one lock,
//! every task of every community queued behind each cast's `fsync`. Here each election is a
//! box of its own under a lock of its own: a cast holds only its election, so casts in
//! different elections are made durable side by side, and nothing in one community waits on
//! another's.
//!
//! What does not change: within one election, a task runs under that election's lock from
//! start to answer, so nothing reads state the journal does not yet hold — an acknowledged
//! cast is on disk, and a head never covers an entry a crash could lose.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use serde_json::Value;
use vti_voting::service::{BallotBox, Failure, Journal, Restored};

/// One election's box.
pub type Shard = Arc<Mutex<BallotBox>>;

pub struct Boxes {
    did: String,
    journal: Arc<dyn Journal>,
    elections: RwLock<HashMap<(String, String), Shard>>,
    /// Serialises registrations, so a community's quota is read and spent by one at a time.
    registering: Mutex<()>,
}

impl std::fmt::Debug for Boxes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Boxes")
            .field("did", &self.did)
            .finish_non_exhaustive()
    }
}

fn unavailable() -> Failure {
    Failure {
        local: "internalError",
        standard: true,
        reason: "ballot box unavailable".into(),
    }
}

impl Boxes {
    /// A service holding nothing, that keeps nothing across a restart.
    #[must_use]
    pub fn new(did: &str) -> Self {
        Self {
            did: did.to_string(),
            journal: Arc::new(vti_voting::service::NoJournal),
            elections: RwLock::new(HashMap::new()),
            registering: Mutex::new(()),
        }
    }

    /// Rebuild every election `restored` holds, each into a box of its own.
    ///
    /// # Errors
    /// As [`BallotBox::restore`], naming the election that cannot be rebuilt.
    pub fn restore(
        did: &str,
        journal: Arc<dyn Journal>,
        restored: Vec<Restored>,
    ) -> Result<Self, Failure> {
        let mut elections = HashMap::new();
        for r in restored {
            let Some(stored) = &r.election else {
                continue;
            };
            let key = (
                stored.manifest["community"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                stored.manifest["electionId"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            );
            let bb = BallotBox::restore(did, Arc::clone(&journal), vec![r])?;
            elections.insert(key, Arc::new(Mutex::new(bb)));
        }
        Ok(Self {
            did: did.to_string(),
            journal,
            elections: RwLock::new(elections),
            registering: Mutex::new(()),
        })
    }

    /// The box holding `community`'s election `election_id`, if it is registered here.
    #[must_use]
    pub fn get(&self, community: &str, election_id: &str) -> Option<Shard> {
        self.elections
            .read()
            .ok()?
            .get(&(community.to_string(), election_id.to_string()))
            .cloned()
    }

    /// The box for a task naming `community`'s election `election_id`: its own, or — for one
    /// not held here — an empty box, which answers exactly as the one box did for an election
    /// it did not hold (`electionUnknown`, after the payload's own checks).
    #[must_use]
    pub fn for_task(&self, community: &str, election_id: &str) -> Shard {
        self.get(community, election_id).unwrap_or_else(|| {
            Arc::new(Mutex::new(BallotBox::with_journal(
                &self.did,
                Arc::clone(&self.journal),
            )))
        })
    }

    /// How many of `community`'s elections are neither tallied nor cancelled.
    fn unfinished(&self, community: &str) -> Result<usize, Failure> {
        let shards: Vec<Shard> = self
            .elections
            .read()
            .map_err(|_| unavailable())?
            .iter()
            .filter(|((c, _), _)| c == community)
            .map(|(_, s)| Arc::clone(s))
            .collect();
        let mut n = 0;
        for s in shards {
            n += s.lock().map_err(|_| unavailable())?.unfinished(community);
        }
        Ok(n)
    }

    /// `voting/election/register`, under the registration lock: `refused` is asked first with
    /// whether the election is already held and how many unfinished ones the community has,
    /// and a new election is held here only once its box accepted it. Blocking: the
    /// registration is journalled.
    ///
    /// # Errors
    /// What `refused` answers, or what the box does.
    pub fn register(
        &self,
        community: &str,
        election_id: &str,
        refused: impl FnOnce(bool, usize) -> Option<Failure>,
        register: impl FnOnce(&mut BallotBox) -> Result<Value, Failure>,
    ) -> Result<Value, Failure> {
        let _registering = self.registering.lock().map_err(|_| unavailable())?;
        let held = self.get(community, election_id);
        let unfinished = match &held {
            Some(_) => 0,
            None => self.unfinished(community)?,
        };
        if let Some(f) = refused(held.is_some(), unfinished) {
            return Err(f);
        }
        if let Some(shard) = held {
            let mut bb = shard.lock().map_err(|_| unavailable())?;
            return register(&mut bb);
        }
        let mut bb = BallotBox::with_journal(&self.did, Arc::clone(&self.journal));
        let answer = register(&mut bb)?;
        // Held only if the box now holds it under the key a later task names it by.
        if bb.holds(community, election_id) {
            self.elections.write().map_err(|_| unavailable())?.insert(
                (community.to_string(), election_id.to_string()),
                Arc::new(Mutex::new(bb)),
            );
        }
        Ok(answer)
    }
}
