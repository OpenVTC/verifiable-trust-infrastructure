//! Community elections (`vtc/elections/*`, VTI-VOT-001 – 100): the community as **registrar**.
//!
//! The community decides who may vote and issues each of them a ticket, blind; the ballot box
//! the manifest names (a `vti-voting-service`, never this process) admits the casts, keeps the
//! board and counts. The community never sees a ballot, and the ballot box never learns who
//! holds a ticket (VTI-VOT-001, VTI-VOT-002). What this module keeps is the registrar's half:
//! the manifest as registered, where the election stands with its ballot box, who took a ticket
//! (never the ticket), the board heads it read, and the certification.
//!
//! # Talking to the ballot box
//!
//! Over TSP, then DIDComm, signed as this community (VTI-VOT-005) — [`link::BallotBoxLink`],
//! on the VTC's one messaging socket. Remote first: an election is `registered` only once the
//! ballot box said so, closed only once it closed, and a registration that has not been answered
//! is delivered again by [`sweeper`], the one retry owner.
//!
//! # What needs the `voting` feature
//!
//! The PCS registrar key, ticket issuance, manifest checking and certification use `vti-voting`,
//! which brings the arkworks stack, so they and the tasks are built only with `voting`. The
//! records ([`store`]) and the link are always built: the action list pins a parked binding
//! election to its record, whatever the build.

pub mod link;
pub mod store;

#[cfg(feature = "voting")]
pub mod ops;
#[cfg(feature = "voting")]
pub mod sweeper;

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::store::KeyspaceHandle;

/// `[voting]` in `config.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VotingConfig {
    /// The voting services this community will register an election with (VTI-VOT-082). Host
    /// configuration: a change is a config edit and a restart, never a task.
    #[serde(default)]
    pub trusted_ballot_boxes: Vec<TrustedBallotBox>,
}

impl VotingConfig {
    pub fn is_empty(&self) -> bool {
        self.trusted_ballot_boxes.is_empty()
    }

    /// The trusted ballot box `did`, compared verbatim.
    #[must_use]
    pub fn trusted(&self, did: &str) -> Option<&TrustedBallotBox> {
        self.trusted_ballot_boxes.iter().find(|b| b.did == did)
    }
}

/// One trusted voting service, with what members are told about it (`Disclosure`, VTI-VOT-090).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedBallotBox {
    /// Its DID, as a manifest names it in `ballotBox`.
    pub did: String,
    /// Who operates it, as the community names them.
    pub operator: String,
    /// Whether whoever operates this VTC also operates it. Members are told, because the
    /// separation between registrar and ballot box is what keeps a ballot unlinkable.
    pub same_operator: bool,
}

/// The registrar's state: its records and the link to ballot boxes. The trusted ballot boxes
/// are read from the live configuration (`AppConfig::voting`) on every use.
pub struct Elections {
    ks: KeyspaceHandle,
    link: Option<Arc<dyn link::BallotBoxChannel>>,
    #[cfg(feature = "voting")]
    registrar: tokio::sync::OnceCell<Arc<vti_voting::registrar::Registrar>>,
    /// Ticket issuance for one election is one critical section (tickets/issue item 8), and a
    /// rotation carrying a member's tickets to a new DID is inside it too.
    issue_lock: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for Elections {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Elections")
            .field("link", &self.link.is_some())
            .finish_non_exhaustive()
    }
}

impl Elections {
    /// The registrar over `ks`, reaching ballot boxes through `link` (`None` when this VTC
    /// cannot sign or resolve: every create is then left `pendingRegistration` until it can).
    pub fn new(ks: KeyspaceHandle, link: Option<Arc<dyn link::BallotBoxChannel>>) -> Self {
        Self {
            ks,
            link,
            #[cfg(feature = "voting")]
            registrar: tokio::sync::OnceCell::new(),
            issue_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// The records.
    pub fn ks(&self) -> &KeyspaceHandle {
        &self.ks
    }

    /// The link to ballot boxes, when there is one.
    pub fn link(&self) -> Option<&Arc<dyn link::BallotBoxChannel>> {
        self.link.as_ref()
    }

    /// Before a rotation from `from` to `to` commits, carry every ticket `from` holds to `to`
    /// (VTI-VOT-022: one ticket per party per election, whatever key the party signs with).
    /// Without it a member could take a ticket, rotate, and take another under the new DID.
    ///
    /// Hold the returned guard until the rotation has committed or failed: no ticket is issued
    /// to `from` in between. A rotation that then fails leaves `to` holding tickets it has no
    /// standing to use, which costs nothing.
    ///
    /// # Errors
    /// A store failure; the caller then does not rotate.
    pub async fn carry_tickets(
        &self,
        from: &str,
        to: &str,
    ) -> Result<tokio::sync::MutexGuard<'_, ()>, crate::error::AppError> {
        let guard = self.issue_lock.lock().await;
        store::carry_tickets(&self.ks, from, to).await?;
        Ok(guard)
    }
}
