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
    /// `rooms/keys/present` — mint a presentation for **one** operation.
    ///
    /// `action` is a single room verb (`read`, `write`, `curate`, `admin`);
    /// there is no "everything" value, deliberately.
    ///
    /// **There is nothing to say about who may present it.** The VTA grants the
    /// minted leaf to the caller it authenticated, and a host refuses a chain
    /// whose leaf grants to anyone else — so a presentation minted for this
    /// client is worthless to anybody who captures it, and a parameter naming a
    /// different party would only be a way to get that wrong. There is likewise
    /// nothing to say about the host: the chain is bound to a *room*, which is
    /// what lets a room have more than one host, and binding the *request* to
    /// its destination is the `recipient` member of the document that carries
    /// this, per SPEC.md §4.8.2.
    ///
    /// The reply carries `presentation` (send this to the host) and
    /// `expiresAt`. A request for more than the principal holds fails at the
    /// VTA, in the credential library, rather than producing a presentation the
    /// host will later refuse.
    pub async fn room_present(&self, room_id: &str, action: &str) -> Result<Value, VtaError> {
        let payload = json!({
            "roomId": room_id,
            "action": action,
        });
        self.dispatch_trust_task(
            trust_tasks::TASK_ROOMS_KEYS_PRESENT_0_2,
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

    /// `rooms/keys/file-key/0.1` — one file's key, so the caller seals or opens
    /// that file itself and its bytes never pass through the VTA.
    ///
    /// `open_epoch` is `None` to seal (the VTA derives under the room's current
    /// epoch and says which) and the file manifest's `epoch` to open.
    ///
    /// **The key is secret, and opens that file for as long as its ciphertext
    /// exists.** Hold it for one encryption or decryption, never store or log
    /// it, and never hand it to web page script.
    pub async fn room_file_key(
        &self,
        room_id: &str,
        file_id: &str,
        open_epoch: Option<u64>,
    ) -> Result<trust_tasks_rs::specs::rooms::keys::file_key::v0_1::Response, VtaError> {
        let mut payload = json!({
            "roomId": room_id,
            "fileId": file_id,
            "purpose": if open_epoch.is_some() { "open" } else { "seal" },
        });
        if let Some(epoch) = open_epoch {
            payload["epoch"] = json!(epoch);
        }
        let value = self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_KEYS_FILE_KEY_0_1,
                payload,
                ROOM_TT_TIMEOUT,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| {
            VtaError::Protocol(format!(
                "rooms/keys/file-key response does not match its schema: {e}"
            ))
        })
    }
}
