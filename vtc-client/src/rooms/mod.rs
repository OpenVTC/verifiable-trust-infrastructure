//! Client surface for the `rooms/*` Trust Tasks.
//!
//! # What is different about these calls
//!
//! Every other method on [`crate::VtcClient`] carries an operator token: the community
//! knows who you are, and its ACL decides what you may do. **A room call carries no token
//! at all.** It carries a presentation — a membership credential and the authority chain
//! the room itself issued — and the host decides from that alone.
//!
//! That is not a convenience. It is what makes a room portable: a host that consulted its
//! own records to authorize a room operation would become part of that room's membership,
//! and the room could no longer move to a different host without reissuing credentials.
//! So [`RoomSession`] deliberately holds no session, and none of these methods sends a
//! bearer credential.
//!
//! # Holding the chain
//!
//! A [`RoomSession`] carries the whole authority chain, **leaf first**, and sends all of it
//! on every call. The host never fetches a link it was not given — resolving one over the
//! network would make verification depend on availability, turn an identifier into a
//! request the host can be induced to make against an address the *caller* chooses, and
//! signal credential use to whoever hosts that identifier.
//!
//! # Agents hold less than their humans
//!
//! The case the design exists for: a member holds `read`/`write`, and equips their agent
//! with a chain one link longer whose leaf confers only `read`, expires in hours, and is
//! bound to the agent. The agent's `RoomSession` is built exactly like the member's — the
//! difference is entirely in the credentials it was handed, which is the point.

// The group-key and sealing layers live in `vti-rooms` — a VTA needs both to open a
// record on an agent's behalf, and a VTA must not depend on a VTC client. Re-exported
// under their old paths so a caller that had `vtc-client` with `mls` is unaffected.
#[cfg(feature = "mls")]
pub use vti_rooms::{mls, sealed};

pub mod body;
pub mod files;

use crate::{VtcClient, VtcError};

// The wire types and their Type URIs, from the crate that also stores and serves them.
//
// These were defined a second time here until the group-key layer moved out and the
// duplication became a compile error — two structs of one wire form, identical and with
// nothing checking they stayed that way, which is the drift the schema-conformance suite in
// `vti-rooms` exists to catch and could not see from over here.
pub use vti_rooms::Visibility;
pub use vti_rooms::authz::MAX_CHAIN_DEPTH;
pub use vti_rooms::wire::{
    AuthorityPresentation, ChainResponse, CleartextContent, CommitsResponse, CurateRecordResponse,
    EpochLink, ListRecordsResponse, MintEpochResponse, OwnerResponse, PutRecordResponse,
    ROOMS_CREATE_TYPE, ROOMS_EPOCH_CHAIN_TYPE, ROOMS_EPOCH_COMMITS_TYPE, ROOMS_EPOCH_MINT_TYPE,
    ROOMS_OWNER_CLAIM_TYPE, ROOMS_OWNER_TRANSFER_TYPE, ROOMS_RECORDS_CURATE_TYPE,
    ROOMS_RECORDS_GET_TYPE, ROOMS_RECORDS_LIST_TYPE, ROOMS_RECORDS_PUT_TYPE, RelayedCommit,
    SealedContent,
};

/// A caller's standing in one room.
///
/// Holds the credentials, not a session. Build one per room per identity — a member's and
/// their agent's are different sessions against the same room, differing only in the chain
/// they carry.
#[derive(Debug, Clone)]
pub struct RoomSession {
    room_id: String,
    presentation: AuthorityPresentation,
}

impl RoomSession {
    /// Build a session from a membership credential and an authority chain.
    ///
    /// `authority` is **leaf first**: the credential being relied on comes first, and the
    /// one the room issued comes last. Rejected here if it is empty or deeper than
    /// [`MAX_CHAIN_DEPTH`], so a caller learns locally rather than from a rejected request.
    pub fn new(
        room_id: impl Into<String>,
        membership: impl Into<String>,
        authority: Vec<String>,
    ) -> Result<Self, VtcError> {
        if authority.is_empty() {
            return Err(VtcError::Url(
                "an authority chain is required: a room operation is authorized by the chain, \
                 never by a session"
                    .into(),
            ));
        }
        if authority.len() > MAX_CHAIN_DEPTH {
            return Err(VtcError::Url(format!(
                "authority chain is {} deep, exceeding the maximum of {MAX_CHAIN_DEPTH}",
                authority.len()
            )));
        }
        Ok(Self {
            room_id: room_id.into(),
            presentation: AuthorityPresentation {
                membership: membership.into(),
                authority,
                subject_binding: None,
            },
        })
    }

    /// Attach the same-subject proof a `private` room requires.
    ///
    /// Without it a private-room call is refused: two parties could otherwise pool
    /// credentials — one contributing membership, the other authority — and present as a
    /// single party holding both.
    pub fn with_subject_binding(mut self, binding: impl Into<String>) -> Self {
        self.presentation.subject_binding = Some(binding.into());
        self
    }

    /// The room this session acts on.
    pub fn room_id(&self) -> &str {
        &self.room_id
    }

    /// How many links the chain carries. Depth 1 is a grant straight from the room;
    /// depth 2 is typically a member's agent.
    pub fn chain_depth(&self) -> usize {
        self.presentation.authority.len()
    }
}

impl VtcClient {
    /// Register a room with this host.
    ///
    /// The caller brings `room_id`: a room identified by something its host chose could not
    /// move to another host without changing identity.
    pub async fn create_room(
        &self,
        room_id: &str,
        owner_did: &str,
        visibility: Visibility,
        retention_days: Option<u32>,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<serde_json::Value, VtcError> {
        let payload = serde_json::json!({
            "roomId": room_id,
            "ownerDid": owner_did,
            "visibility": visibility,
            "retentionDays": retention_days,
        });
        self.room_task(
            ROOMS_CREATE_TYPE,
            payload,
            signer_did,
            private_key_multibase,
        )
        .await
    }

    /// Write a record.
    ///
    /// Exactly one of `sealed` / `cleartext` — the host refuses the other shape for the
    /// room's tier, so passing both or neither is a request it cannot honour.
    ///
    /// `expected_version` is an optional precondition: `Some(0)` means create-only, and
    /// `Some(n)` requires the stored record to be at version `n`. A mismatch comes back
    /// carrying the current version, so a caller does not have to re-read to learn what it
    /// lost to.
    #[allow(clippy::too_many_arguments)]
    pub async fn put_record(
        &self,
        session: &RoomSession,
        key: &str,
        sealed: Option<SealedContent>,
        cleartext: Option<CleartextContent>,
        expected_version: Option<u64>,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<PutRecordResponse, VtcError> {
        let mut payload = serde_json::json!({
            "roomId": session.room_id,
            "key": key,
            "presentation": session.presentation,
        });
        if let Some(s) = sealed {
            payload["sealed"] =
                serde_json::to_value(s).map_err(|e| VtcError::Url(e.to_string()))?;
        }
        if let Some(c) = cleartext {
            payload["cleartext"] =
                serde_json::to_value(c).map_err(|e| VtcError::Url(e.to_string()))?;
        }
        if let Some(v) = expected_version {
            payload["expectedVersion"] = serde_json::json!(v);
        }
        let value = self
            .room_task(
                ROOMS_RECORDS_PUT_TYPE,
                payload,
                signer_did,
                private_key_multibase,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| VtcError::Http {
            status: 200,
            body: format!("put response is not a PutRecordResponse: {e}"),
        })
    }

    /// Read one record.
    ///
    /// Presents exactly as a write does, and needs no session — which is the point on a
    /// sealed room: authorizing reads by session would hand the host a member identifier on
    /// every access, and a period of those reconstructs the membership the tier withholds.
    pub async fn get_record(
        &self,
        session: &RoomSession,
        key: &str,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<serde_json::Value, VtcError> {
        let payload = serde_json::json!({
            "roomId": session.room_id,
            "key": key,
            "presentation": session.presentation,
        });
        self.room_task(
            ROOMS_RECORDS_GET_TYPE,
            payload,
            signer_did,
            private_key_multibase,
        )
        .await
    }

    /// List record metadata.
    ///
    /// Never returns bodies — fetch the handful that matter with [`VtcClient::get_record`].
    /// `since_version` is the incremental-sync watermark, and the response **includes
    /// tombstones**: a caller that never saw a retraction would resurrect the record on its
    /// next full rebuild.
    ///
    /// `cursor` continues a previous page. **A listing is not complete until the response's
    /// `cursor` is absent** — a page shorter than the one asked for says nothing, which is
    /// why this takes the token rather than leaving callers to guess from a length.
    pub async fn list_records(
        &self,
        session: &RoomSession,
        prefix: Option<&str>,
        since_version: Option<u64>,
        cursor: Option<&str>,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<ListRecordsResponse, VtcError> {
        let mut payload = serde_json::json!({
            "roomId": session.room_id,
            "presentation": session.presentation,
        });
        if let Some(p) = prefix {
            payload["prefix"] = serde_json::json!(p);
        }
        if let Some(v) = since_version {
            payload["sinceVersion"] = serde_json::json!(v);
        }
        if let Some(c) = cursor {
            payload["cursor"] = serde_json::json!(c);
        }
        let value = self
            .room_task(
                ROOMS_RECORDS_LIST_TYPE,
                payload,
                signer_did,
                private_key_multibase,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| VtcError::Http {
            status: 200,
            body: format!("list response is not a ListRecordsResponse: {e}"),
        })
    }

    /// Advance the room's key epoch — how a member is removed.
    ///
    /// Requires a chain conferring `admin`. `epoch` must be exactly one greater than the
    /// current one. The host records the number and never learns the key: distributing it
    /// to the remaining members happens out of its sight.
    pub async fn mint_epoch(
        &self,
        session: &RoomSession,
        epoch: u32,
        reason: Option<&str>,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<MintEpochResponse, VtcError> {
        self.mint_epoch_with_link(
            session,
            epoch,
            None,
            reason,
            signer_did,
            private_key_multibase,
        )
        .await
    }

    /// Mint an epoch and hand the host the rung that keeps the room's past readable.
    ///
    /// The rung is the outgoing epoch's storage key sealed under the incoming one, and
    /// minting is the only moment one party holds both — so this is the only call that can
    /// carry it. A room that advances without one keeps working and silently loses the
    /// ability to read everything written before, for every member including the writer.
    ///
    /// [`Self::mint_epoch`] is this with `None`, which is the right call only for a room
    /// that has deliberately chosen not to keep its history.
    pub async fn mint_epoch_with_link(
        &self,
        session: &RoomSession,
        epoch: u32,
        link: Option<&EpochLink>,
        reason: Option<&str>,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<MintEpochResponse, VtcError> {
        let mut payload = serde_json::json!({
            "roomId": session.room_id,
            "epoch": epoch,
            "presentation": session.presentation,
        });
        if let Some(r) = reason {
            payload["reason"] = serde_json::json!(r);
        }
        if let Some(l) = link {
            payload["link"] = serde_json::to_value(l).map_err(|e| VtcError::Http {
                status: 0,
                body: format!("serialise the epoch link: {e}"),
            })?;
        }
        let value = self
            .room_task(
                ROOMS_EPOCH_MINT_TYPE,
                payload,
                signer_did,
                private_key_multibase,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| VtcError::Http {
            status: 200,
            body: format!("mint response is not a MintEpochResponse: {e}"),
        })
    }

    /// Fetch the room's epoch key chain, highest epoch first.
    ///
    /// What a member calls after joining, or after restoring their group state, so that
    /// records sealed before then still open. Feed the result to
    /// `SealedRoom::add_links`.
    ///
    /// Gated on `read` at the host: reading the room and reading the parts written earlier
    /// are the same act. The rungs are ciphertext — a caller holding no epoch key learns
    /// nothing from them but how many epochs the room has had.
    ///
    /// `from_epoch` returns only rungs at or below that epoch, which is how a member who
    /// already holds the top of the chain asks for the rest.
    pub async fn epoch_chain(
        &self,
        session: &RoomSession,
        from_epoch: Option<u32>,
        limit: Option<u32>,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<ChainResponse, VtcError> {
        let mut payload = serde_json::json!({
            "roomId": session.room_id,
            "presentation": session.presentation,
        });
        if let Some(f) = from_epoch {
            payload["fromEpoch"] = serde_json::json!(f);
        }
        if let Some(l) = limit {
            payload["limit"] = serde_json::json!(l);
        }
        let value = self
            .room_task(
                ROOMS_EPOCH_CHAIN_TYPE,
                payload,
                signer_did,
                private_key_multibase,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| VtcError::Http {
            status: 200,
            body: format!("chain response is not a ChainResponse: {e}"),
        })
    }

    /// Fetch the commits a member missed, from the host's relay.
    ///
    /// `since_epoch` is the **room** epoch this member's key holder is at; the host
    /// returns the commits above it, in ascending order and with no gaps, each
    /// tagged with the room epoch it produced. Apply them in order to the key
    /// holder's group (`rooms/keys/commit`, whose `epoch` is the MLS epoch — one
    /// less). The response's `room_epoch` is where the room is now: a member who
    /// applies everything served and is still behind knows a delivery is missing.
    ///
    /// Gated on `read` at the host. Relaying commits is safe on every tier: a
    /// commit opens nothing for a party outside the group.
    pub async fn epoch_commits(
        &self,
        session: &RoomSession,
        since_epoch: u32,
        limit: Option<u32>,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<CommitsResponse, VtcError> {
        let mut payload = serde_json::json!({
            "roomId": session.room_id,
            "sinceEpoch": since_epoch,
            "presentation": session.presentation,
        });
        if let Some(l) = limit {
            payload["limit"] = serde_json::json!(l);
        }
        let value = self
            .room_task(
                ROOMS_EPOCH_COMMITS_TYPE,
                payload,
                signer_did,
                private_key_multibase,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| VtcError::Http {
            status: 200,
            body: format!("commits response is not a CommitsResponse: {e}"),
        })
    }

    /// Change a record's **standing** — its status, whether it is pinned, or both.
    ///
    /// Needs a chain conferring `curate`, which is deliberately *not* implied by `write`:
    /// deciding what a room's shared knowledge is worth is a different grant from being
    /// able to add to it.
    ///
    /// Separate from [`Self::put_record`] because standing is not content. On a sealed tier
    /// a host cannot read what it stores, so "same body, now deprecated" through `put` would
    /// make a member re-seal and re-upload bytes the host already holds, to say something
    /// that is not about the bytes.
    ///
    /// `status` and `pinned` are independent: omit either to leave it unchanged, and passing
    /// neither changes nothing. The curation assigns a **new version**, because a change
    /// others must converge on is a change like any other — one that left the version alone
    /// would be invisible to every `sinceVersion` watermark in the room.
    #[allow(clippy::too_many_arguments)]
    pub async fn curate_record(
        &self,
        session: &RoomSession,
        key: &str,
        status: Option<String>,
        pinned: Option<bool>,
        reason: Option<String>,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<CurateRecordResponse, VtcError> {
        let mut payload = serde_json::json!({
            "roomId": session.room_id,
            "key": key,
            "presentation": session.presentation,
        });
        // Each member is omitted when absent rather than sent as null: the
        // published schema types them, and "leave unchanged" is absence.
        if let Some(s) = status {
            payload["status"] = serde_json::json!(s);
        }
        if let Some(p) = pinned {
            payload["pinned"] = serde_json::json!(p);
        }
        if let Some(r) = reason {
            payload["reason"] = serde_json::json!(r);
        }
        let value = self
            .room_task(
                ROOMS_RECORDS_CURATE_TYPE,
                payload,
                signer_did,
                private_key_multibase,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| VtcError::Http {
            status: 200,
            body: format!("curate response is not a CurateRecordResponse: {e}"),
        })
    }

    /// Hand the room to another member, deliberately and while still present.
    ///
    /// Requires a chain conferring `admin` — the same grant that mints epochs, since
    /// transferring is the more consequential of the two.
    ///
    /// **The host does not check that `new_owner_did` is a member**, and cannot: it holds no
    /// roster and no MLS group state. That obligation is the outgoing owner's, who can see
    /// the group. Give the room to someone who cannot commit and they inherit a room they
    /// cannot renew.
    pub async fn transfer_owner(
        &self,
        session: &RoomSession,
        new_owner_did: &str,
        reason: Option<&str>,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<OwnerResponse, VtcError> {
        let mut payload = serde_json::json!({
            "roomId": session.room_id,
            "newOwnerDid": new_owner_did,
            "presentation": session.presentation,
        });
        if let Some(r) = reason {
            payload["reason"] = serde_json::json!(r);
        }
        self.owner_task(
            ROOMS_OWNER_TRANSFER_TYPE,
            payload,
            signer_did,
            private_key_multibase,
        )
        .await
    }

    /// Claim a room whose owner has stopped renewing it.
    ///
    /// `nomination` is the succession credential the room issued to this claimant in
    /// advance. All three of the host's conditions must hold together: a valid nomination,
    /// a room that has been **dormant** past its grace window — not merely lapsed — and the
    /// claimant's own membership, which is what `session` carries.
    ///
    /// A claim does not renew the room. It hands over a dormant room, and the new owner's
    /// first act should be the epoch mint that proves they can perform it.
    pub async fn claim_owner(
        &self,
        session: &RoomSession,
        nomination: &str,
        reason: Option<&str>,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<OwnerResponse, VtcError> {
        let mut payload = serde_json::json!({
            "roomId": session.room_id,
            "nomination": nomination,
            "presentation": session.presentation,
        });
        if let Some(r) = reason {
            payload["reason"] = serde_json::json!(r);
        }
        self.owner_task(
            ROOMS_OWNER_CLAIM_TYPE,
            payload,
            signer_did,
            private_key_multibase,
        )
        .await
    }

    /// The shared tail of the two succession verbs, which answer with one shape.
    async fn owner_task(
        &self,
        type_uri: &str,
        payload: serde_json::Value,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<OwnerResponse, VtcError> {
        let value = self
            .room_task(type_uri, payload, signer_did, private_key_multibase)
            .await?;
        serde_json::from_value(value).map_err(|e| VtcError::Http {
            status: 200,
            body: format!("{type_uri} response is not an OwnerResponse: {e}"),
        })
    }

    /// Send one `rooms/*` document and return its response payload.
    ///
    /// The one place a room call is made, so the no-bearer property is visible in a single
    /// function rather than repeated across five: this builds a signed document and posts
    /// it, and sends no other credential.
    async fn room_task(
        &self,
        type_uri: &str,
        payload: serde_json::Value,
        signer_did: &str,
        private_key_multibase: &str,
    ) -> Result<serde_json::Value, VtcError> {
        let retries = if is_room_read(type_uri) {
            READ_RATE_LIMIT_ATTEMPTS - 1
        } else {
            0
        };
        let mut attempt = 0;
        let resp = loop {
            // Signed afresh for every attempt: a document's `id` is spent once it runs, and
            // a read is only ever retried because the host refused it before it ran.
            let doc = vta_sdk::trust_task_sign::build_signed(
                type_uri,
                payload.clone(),
                signer_did,
                private_key_multibase,
                &self.vtc_did,
            )
            .await
            .map_err(|e| VtcError::Signing(e.to_string()))?;

            let resp = self.post_room_document(doc).await?;
            if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
                && attempt < retries
                && let Some(wait) = rate_limit_wait(resp.headers())
            {
                attempt += 1;
                tokio::time::sleep(wait).await;
                continue;
            }
            break resp;
        };
        Self::room_response_payload(resp).await
    }

    /// Send a `rooms/*` document that is **already signed** — one the member's own VTA
    /// completed as the member with `rooms/keys/act` — and return its response payload.
    ///
    /// The document goes as it is: nothing here signs, and nothing here adds a credential.
    /// A read refused for its rate is sent again unchanged, which is sound because the host
    /// refused it before it ran, so its `id` is not spent.
    pub async fn send_signed_room_document(
        &self,
        document: &serde_json::Value,
    ) -> Result<serde_json::Value, VtcError> {
        let type_uri = document
            .get("type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let retries = if is_room_read(type_uri) {
            READ_RATE_LIMIT_ATTEMPTS - 1
        } else {
            0
        };
        let body = serde_json::to_string(document).map_err(|e| VtcError::Url(e.to_string()))?;
        let mut attempt = 0;
        let resp = loop {
            let resp = self.post_room_document(body.clone()).await?;
            if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
                && attempt < retries
                && let Some(wait) = rate_limit_wait(resp.headers())
            {
                attempt += 1;
                tokio::time::sleep(wait).await;
                continue;
            }
            break resp;
        };
        Self::room_response_payload(resp).await
    }

    async fn post_room_document(&self, body: String) -> Result<reqwest::Response, VtcError> {
        Ok(self
            .http
            .post(format!("{}/trust-tasks", self.base_url))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await?)
    }

    async fn room_response_payload(resp: reqwest::Response) -> Result<serde_json::Value, VtcError> {
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(VtcError::Http { status, body });
        }

        let text = resp.text().await?;
        let response_doc: trust_tasks_rs::TrustTask<serde_json::Value> =
            serde_json::from_str(&text).map_err(|e| VtcError::Http {
                status: 200,
                body: format!("unexpected room response (not a Trust Task document): {e}: {text}"),
            })?;
        Ok(response_doc.payload)
    }
}

/// Attempts a room read makes, the first included, when the host answers `429`.
const READ_RATE_LIMIT_ATTEMPTS: usize = 5;

/// The longest `Retry-After` a room read waits out. A longer one is returned to the
/// caller as the `429` it is, rather than turned into a stall the host chooses.
const MAX_READ_RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(30);

/// Whether `type_uri` is a room task that only reads, so repeating it after a `429` cannot
/// do anything twice. Writes are never retried here: retry has one owner per failure
/// domain, and a write's is the caller.
///
/// `rooms/blobs/get` is here although it opens a download: repeating it opens a second,
/// which expires unused, and a refused attempt opened nothing.
fn is_room_read(type_uri: &str) -> bool {
    use trust_tasks_rs::Payload as _;
    use trust_tasks_rs::specs::rooms;
    [
        ROOMS_RECORDS_GET_TYPE,
        ROOMS_RECORDS_LIST_TYPE,
        ROOMS_EPOCH_CHAIN_TYPE,
        ROOMS_EPOCH_COMMITS_TYPE,
        rooms::records::get::v0_2::Payload::TYPE_URI,
        rooms::records::list::v0_2::Payload::TYPE_URI,
        rooms::blobs::get::v0_1::Payload::TYPE_URI,
        rooms::blobs::chunk::v0_1::Payload::TYPE_URI,
        rooms::info::v0_1::Payload::TYPE_URI,
    ]
    .contains(&type_uri)
}

/// How long a `429` asks to be waited out, when that is short enough to wait: its
/// `Retry-After` (`vta_sdk::rate_limit`'s parse, so both forms are read), at least a
/// second when it names none. `None` past [`MAX_READ_RETRY_AFTER`].
fn rate_limit_wait(headers: &reqwest::header::HeaderMap) -> Option<std::time::Duration> {
    let now = chrono::Utc::now();
    let wait = headers
        .get(vta_sdk::rate_limit::RETRY_AFTER_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| vta_sdk::rate_limit::parse_retry_after(v, now))
        .map_or(std::time::Duration::from_secs(1), |at| {
            (at - now).to_std().unwrap_or_default()
        });
    (wait <= MAX_READ_RETRY_AFTER).then_some(wait)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_room_reads_are_retried() {
        use trust_tasks_rs::Payload as _;
        use trust_tasks_rs::specs::rooms;
        assert!(is_room_read(ROOMS_RECORDS_GET_TYPE));
        assert!(is_room_read(rooms::blobs::chunk::v0_1::Payload::TYPE_URI));
        for write in [
            ROOMS_CREATE_TYPE,
            ROOMS_RECORDS_PUT_TYPE,
            ROOMS_EPOCH_MINT_TYPE,
            ROOMS_RECORDS_CURATE_TYPE,
            rooms::blobs::upload::chunk::v0_1::Payload::TYPE_URI,
            rooms::blobs::upload::commit::v0_1::Payload::TYPE_URI,
        ] {
            assert!(!is_room_read(write), "{write} is a write");
        }
    }

    #[test]
    fn a_short_retry_after_is_waited_and_a_long_one_is_not() {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert("retry-after", "3".parse().unwrap());
        let wait = rate_limit_wait(&h).unwrap();
        assert!((2..=3).contains(&wait.as_secs()), "{wait:?}");
        h.insert("retry-after", "3600".parse().unwrap());
        assert_eq!(rate_limit_wait(&h), None);
        assert_eq!(
            rate_limit_wait(&reqwest::header::HeaderMap::new()),
            Some(std::time::Duration::from_secs(1))
        );
    }

    #[test]
    fn a_session_requires_a_chain() {
        let err = RoomSession::new("did:key:zRoom", "vmc", vec![]).unwrap_err();
        assert!(
            format!("{err}").contains("authorized by the chain"),
            "a room session without a chain has nothing to present: {err}"
        );
    }

    #[test]
    fn a_session_refuses_a_chain_past_the_ceiling() {
        let chain: Vec<String> = (0..=MAX_CHAIN_DEPTH).map(|i| format!("vac-{i}")).collect();
        let err = RoomSession::new("did:key:zRoom", "vmc", chain).unwrap_err();
        assert!(format!("{err}").contains("exceeding the maximum"), "{err}");
    }

    /// The agent case, at the level the client models it: same construction, one more link,
    /// and the narrowing lives in the credentials rather than in any flag here.
    #[test]
    fn a_members_session_and_their_agents_differ_only_in_the_chain() {
        let member = RoomSession::new("did:key:zRoom", "vmc", vec!["vac-member".into()])
            .expect("member session");
        let agent = RoomSession::new(
            "did:key:zRoom",
            "vmc",
            vec!["vac-agent".into(), "vac-member".into()],
        )
        .expect("agent session");

        assert_eq!(member.room_id(), agent.room_id());
        assert_eq!(member.chain_depth(), 1, "a grant straight from the room");
        assert_eq!(agent.chain_depth(), 2, "one attenuation deeper");
    }

    #[test]
    fn a_subject_binding_is_attached_only_when_asked_for() {
        let s = RoomSession::new("did:key:zRoom", "vmc", vec!["vac".into()]).unwrap();
        assert!(s.presentation.subject_binding.is_none());
        let s = s.with_subject_binding("proof");
        assert_eq!(s.presentation.subject_binding.as_deref(), Some("proof"));
    }

    /// The wire shape a host reads. `camelCase`, and the binding omitted rather than null
    /// when absent — a host distinguishes absent from present-but-empty.
    #[test]
    fn a_presentation_serialises_camel_case_and_omits_an_absent_binding() {
        let s = RoomSession::new("did:key:zRoom", "vmc", vec!["a".into(), "b".into()]).unwrap();
        let v = serde_json::to_value(&s.presentation).unwrap();
        assert_eq!(v["membership"], "vmc");
        assert_eq!(v["authority"][0], "a", "leaf first");
        assert!(v.get("subjectBinding").is_none());

        let s = s.with_subject_binding("bind");
        let v = serde_json::to_value(&s.presentation).unwrap();
        assert_eq!(v["subjectBinding"], "bind");
    }

    #[test]
    fn visibility_serialises_lowercase_as_the_host_expects() {
        assert_eq!(
            serde_json::to_value(Visibility::Attributed).unwrap(),
            serde_json::json!("attributed")
        );
    }
}
