//! Room-oracle Trust Task client methods (`spec/rooms/keys/{present,open}/0.1`).
//!
//! The two calls a member's own VTA answers about a data room, and the reason a
//! client never holds room credentials or room keys:
//!
//! - [`VtaClient::room_present`] asks the VTA to mint a **presentation** for one
//!   operation — attenuated from the member's own authority, one action, bound
//!   to the caller, four hours. The presentation goes to the room's host; the
//!   credentials it was derived from never leave the VTA.
//! - [`VtaClient::room_open`] hands the VTA a sealed record and gets the
//!   plaintext back. The group key stays inside.
//!
//! Both are gated on their own capability (`roomPresent` / `roomOpen`) plus
//! access to the context holding the principal's key. Neither is `Sign`: an
//! agent that may ask for a scoped presentation is not thereby an agent that
//! may sign anything at all with its principal's key.
//!
//! # What this module deliberately does not do
//!
//! Talk to the room's **host**. These are calls to *your* VTA. Posting the
//! resulting presentation to whoever stores the room is a different transport
//! to a different party, and keeping the two apart is what stops a client
//! quietly sending its principal's credentials somewhere they were not minted
//! for.

use serde_json::{Value, json};

use super::VtaClient;
use crate::error::VtaError;
use crate::trust_tasks;

/// Round-trip timeout (seconds) for the room-oracle tasks.
///
/// Both are local work on the VTA — a credential attenuation and a symmetric
/// decrypt — so they are quick, and a long timeout would only mask a VTA that
/// has stopped answering.
const ROOM_TT_TIMEOUT: u64 = 30;

impl VtaClient {
    /// `rooms/keys/present/0.1` — mint a presentation for **one** operation.
    ///
    /// `action` is a single room verb (`read`, `write`, `curate`, `admin`);
    /// there is no "everything" value, deliberately. `audience`, when given,
    /// binds the minted leaf to that party so a captured presentation is
    /// worthless elsewhere — pass the host's DID whenever you know it.
    ///
    /// The reply carries `presentation` (send this to the host) and
    /// `expiresAt`. A request for more than the principal holds fails at the
    /// VTA, in the credential library, rather than producing a presentation the
    /// host will later refuse.
    pub async fn room_present(
        &self,
        room_id: &str,
        action: &str,
        audience: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<Value, VtaError> {
        let mut payload = json!({
            "roomId": room_id,
            "action": action,
        });
        // Omitted rather than sent as null: the published payload types the
        // members as strings, and a `null` would fail schema validation at the
        // spine — the defect class #919 and #921 both landed in.
        if let Some(audience) = audience {
            payload["audience"] = Value::String(audience.to_string());
        }
        if let Some(nonce) = nonce {
            payload["nonce"] = Value::String(nonce.to_string());
        }
        self.dispatch_trust_task(
            trust_tasks::TASK_ROOMS_KEYS_PRESENT_0_1,
            payload,
            ROOM_TT_TIMEOUT,
        )
        .await
    }

    /// `rooms/keys/open/0.1` — decrypt one sealed record.
    ///
    /// `version` and the sealed triple must be exactly what the host returned:
    /// the record's AEAD is bound to `roomId | key | version | epoch`, so a
    /// value adjusted in transit does not open. The reply carries `plaintext`
    /// as base64url.
    ///
    /// **A record sealed under a later epoch than this VTA holds means a missed
    /// commit**, not corruption. The VTA says which epoch it has; deliver the
    /// commit and retry rather than treating the record as damaged.
    pub async fn room_open(
        &self,
        room_id: &str,
        key: &str,
        version: u64,
        ciphertext: &str,
        nonce: &str,
        epoch: u32,
    ) -> Result<Value, VtaError> {
        let payload = json!({
            "roomId": room_id,
            "key": key,
            "version": version,
            "sealed": {
                "ciphertext": ciphertext,
                "nonce": nonce,
                "epoch": epoch,
            },
        });
        self.dispatch_trust_task(
            trust_tasks::TASK_ROOMS_KEYS_OPEN_0_1,
            payload,
            ROOM_TT_TIMEOUT,
        )
        .await
    }
}
