//! Room-oracle Trust Task client methods (`spec/rooms/keys/{present,open,seal,file-key}`).
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

    /// `rooms/keys/open/0.2` — decrypt one sealed record. A VTA that does not serve
    /// 0.2 (`unsupportedType` / `unsupportedVersion`) is asked at 0.1, which takes the
    /// same payload and answers the same way.
    ///
    /// `version` and the sealed triple must be exactly what the host returned:
    /// the record's AEAD is bound to `roomId | key | version | epoch`, so a
    /// value adjusted in transit does not open. The reply carries `plaintext`
    /// as base64url.
    ///
    /// **An `unknownEpoch` refusal says why in `details.reason`**, and the caller acts on
    /// that, never on the message: `notDelivered` — a commit has not reached the VTA;
    /// deliver it and retry; `beyondChain` — the retained chain does not reach back to the
    /// record's epoch (`details.earliestEpoch`); `removed` — the member was removed at
    /// `details.removedAtEpoch`, and nothing will ever open the record here, so do not
    /// retry.
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
        self.dispatch_at_or_before(
            trust_tasks::TASK_ROOMS_KEYS_OPEN_0_2,
            trust_tasks::TASK_ROOMS_KEYS_OPEN_0_1,
            payload,
        )
        .await
    }

    /// Send `payload` at `current`, and at `previous` when the VTA does not serve
    /// `current` (`unsupportedType` / `unsupportedVersion`, typed as
    /// [`VtaError::UnsupportedTaskType`]).
    ///
    /// For a version pair whose payloads are identical and whose operation is the same:
    /// asking again at the older version is not a retry of a failed operation, because the
    /// first was never routed.
    async fn dispatch_at_or_before(
        &self,
        current: &str,
        previous: &str,
        payload: Value,
    ) -> Result<Value, VtaError> {
        match self
            .dispatch_trust_task(current, payload.clone(), ROOM_TT_TIMEOUT)
            .await
        {
            Err(VtaError::UnsupportedTaskType { .. }) => {
                self.dispatch_trust_task(previous, payload, ROOM_TT_TIMEOUT)
                    .await
            }
            other => other,
        }
    }

    /// `rooms/keys/seal/0.1` — seal one record body under the room's current
    /// epoch, ready for `rooms/records/put`.
    ///
    /// `plaintext` is the body to seal: on a sealed tier, a `SealedRecordBody`
    /// the writer has already signed. The VTA seals what it is given and signs
    /// nothing; attributing a record is the writer's act.
    ///
    /// `version` is the version the record is **meant** to take, bound into the
    /// associated data. The host assigns versions from a room-wide counter, so
    /// a put that lands at another version does not open; the writer re-seals
    /// at the version the host reports and writes again.
    pub async fn room_seal(
        &self,
        room_id: &str,
        key: &str,
        version: u64,
        plaintext: &[u8],
    ) -> Result<trust_tasks_rs::specs::rooms::keys::seal::v0_1::Response, VtaError> {
        let payload = json!({
            "roomId": room_id,
            "key": key,
            "version": version,
            "plaintext": base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                plaintext,
            ),
        });
        let value = self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_KEYS_SEAL_0_1,
                payload,
                ROOM_TT_TIMEOUT,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| {
            VtaError::Protocol(format!(
                "rooms/keys/seal response does not match its schema: {e}"
            ))
        })
    }

    /// `rooms/keys/seal/0.2` — [`VtaClient::room_seal`], with `signAsPrincipal`.
    ///
    /// For the member's **own** client, which holds no key of the member's: `body` is a
    /// `SealedRecordBody` **without** `proof` whose `author` is the member (the persona the
    /// room admitted) and whose `roomId`, `key` and `version` equal these. The VTA signs it
    /// as the member, for `assertionMethod`, then seals the signed body — so the record is
    /// attributed to the member rather than to this client. An agent acting under an
    /// attenuated chain signs its own body and uses [`VtaClient::room_seal`] instead; the
    /// VTA refuses it this flag.
    pub async fn room_seal_as_principal(
        &self,
        room_id: &str,
        key: &str,
        version: u64,
        body: &[u8],
    ) -> Result<trust_tasks_rs::specs::rooms::keys::seal::v0_2::Response, VtaError> {
        let payload = json!({
            "roomId": room_id,
            "key": key,
            "version": version,
            "plaintext": base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                body,
            ),
            "signAsPrincipal": true,
        });
        let value = self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_KEYS_SEAL_0_2,
                payload,
                ROOM_TT_TIMEOUT,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| {
            VtaError::Protocol(format!(
                "rooms/keys/seal/0.2 response does not match its schema: {e}"
            ))
        })
    }

    /// `rooms/keys/act/0.2` — have the VTA complete one host-bound room request **as the
    /// member**, and get it back to send. A VTA that does not serve 0.2
    /// (`unsupportedType` / `unsupportedVersion`) is asked at 0.1 with the same document,
    /// and its answer read as 0.2's.
    ///
    /// `document` is the room request this client means to send — `id`, `type`, `recipient`
    /// (the host), `issuedAt` and `payload` — with no `proof` and no `presentation` in the
    /// payload; build it with [`unsigned_room_request`]. Set `issuer` to name which member
    /// to act as where the caller may act as more than one in the room, and **always** for
    /// a type that names no room (`rooms/blobs/chunk/0.1`,
    /// `rooms/blobs/upload/{commit,abort}/0.2`): the member whose request opened the
    /// transfer, which the VTA never guesses (act 0.2 producer item 2). The VTA
    /// inserts the member's own authority narrowed to the one action the type needs and
    /// granted to the member, sets `issuer` to the member and signs for `authentication`.
    ///
    /// **Send the returned `document` to its `recipient` unaltered**, and to nobody else.
    /// Nothing in it names this client: the host records the member.
    pub async fn room_act(
        &self,
        document: &trust_tasks_rs::specs::rooms::keys::act::v0_2::UnsignedRoomRequest,
    ) -> Result<trust_tasks_rs::specs::rooms::keys::act::v0_2::Response, VtaError> {
        // The two versions' request and response schemas are identical (act 0.2 *What
        // changed from 0.1*), so the same JSON goes at either and either answer reads as
        // 0.2's.
        let payload = json!({ "document": document });
        let value = self
            .dispatch_at_or_before(
                trust_tasks::TASK_ROOMS_KEYS_ACT_0_2,
                trust_tasks::TASK_ROOMS_KEYS_ACT_0_1,
                payload,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| {
            VtaError::Protocol(format!(
                "rooms/keys/act response does not match its schema: {e}"
            ))
        })
    }

    /// `rooms/keys/file-key/0.2` — one file's key, so the caller seals or opens
    /// that file itself and its bytes never pass through the VTA. A VTA that does not
    /// serve 0.2 (`unsupportedType` / `unsupportedVersion`) is asked at 0.1, whose
    /// request and response are 0.2's.
    ///
    /// An `unknownEpoch` refusal says why in `details.reason`, as
    /// [`VtaClient::room_open`]'s does; after `removed` the caller does not retry. A 0.1
    /// VTA says `notDelivered` for a removed member's file too.
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
    ) -> Result<trust_tasks_rs::specs::rooms::keys::file_key::v0_2::Response, VtaError> {
        let mut payload = json!({
            "roomId": room_id,
            "fileId": file_id,
            "purpose": if open_epoch.is_some() { "open" } else { "seal" },
        });
        if let Some(epoch) = open_epoch {
            payload["epoch"] = json!(epoch);
        }
        let value = self
            .dispatch_at_or_before(
                trust_tasks::TASK_ROOMS_KEYS_FILE_KEY_0_2,
                trust_tasks::TASK_ROOMS_KEYS_FILE_KEY_0_1,
                payload,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| {
            VtaError::Protocol(format!(
                "rooms/keys/file-key response does not match its schema: {e}"
            ))
        })
    }

    /// `rooms/owner/group/create/0.1` — found a sealed room's group, with the owner as its
    /// only member, in this VTA.
    ///
    /// `signing_key_id` is the room's signing key, as named to the issuance tasks: control
    /// of it is the entitlement. `member` is the DID the owner's leaf identifies — the
    /// subject of their room credentials — and defaults to the caller.
    ///
    /// Register the room with its host first: a refused registration then costs nothing
    /// to retry, and the group starts at room epoch 1, which is what the host records.
    pub async fn room_group_create(
        &self,
        room_id: &str,
        signing_key_id: &str,
        member: Option<&str>,
    ) -> Result<trust_tasks_rs::specs::rooms::owner::group::create::v0_1::Response, VtaError> {
        let mut payload = json!({ "roomId": room_id, "signingKeyId": signing_key_id });
        if let Some(m) = member {
            payload["member"] = json!(m);
        }
        let value = self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_OWNER_GROUP_CREATE_0_1,
                payload,
                ROOM_TT_TIMEOUT,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| {
            VtaError::Protocol(format!(
                "rooms/owner/group/create response does not match its schema: {e}"
            ))
        })
    }

    /// `rooms/owner/group/add/0.1` — admit `member` to a room's group from the KeyPackage
    /// their key holder minted (base64url).
    ///
    /// The VTA advances the room's epoch at `host_did` first, and only then its own group.
    /// The reply carries the **Welcome** (and, where the group needs it, the ratchet tree):
    /// deliver both to the member's key holder with `rooms/keys/welcome`, never through the
    /// host. The answer is the only copy of the Welcome, so call this inside
    /// [`VtaClient::idempotent`]: the task is `Keyed`, and a retry carrying the same key
    /// gets the first answer back instead of an `alreadyMember` refusal and a lost Welcome.
    pub async fn room_group_add(
        &self,
        room_id: &str,
        host_did: &str,
        member: &str,
        key_package: &str,
        reason: Option<&str>,
    ) -> Result<trust_tasks_rs::specs::rooms::owner::group::add::v0_1::Response, VtaError> {
        let mut payload = json!({
            "roomId": room_id,
            "host": host_did,
            "member": member,
            "keyPackage": key_package,
        });
        if let Some(r) = reason {
            payload["reason"] = json!(r);
        }
        let value = self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_OWNER_GROUP_ADD_0_1,
                payload,
                // Two host round trips at most (an earlier admission settled, then the
                // advance), each over whatever transport the host speaks.
                ROOM_TT_TIMEOUT * 4,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| {
            VtaError::Protocol(format!(
                "rooms/owner/group/add response does not match its schema: {e}"
            ))
        })
    }

    /// `rooms/owner/group/remove/0.1` — remove `member`'s leaf from a room's group, so
    /// nothing sealed from then on is readable to them.
    ///
    /// The VTA advances the room's epoch at `host_did` first, and only then its own group.
    /// It recalls nothing the member already read, and on a `chained` room they keep the
    /// epochs they were in; their authority credential is untouched — let it lapse
    /// separately. Call this inside [`VtaClient::idempotent`]: the task is `Keyed`, and a
    /// retry after a lost reply gets the first answer back instead of a `notMember`
    /// refusal that reads as though the wrong member had been named.
    pub async fn room_group_remove(
        &self,
        room_id: &str,
        host_did: &str,
        member: &str,
        reason: Option<&str>,
    ) -> Result<trust_tasks_rs::specs::rooms::owner::group::remove::v0_1::Response, VtaError> {
        let mut payload = json!({
            "roomId": room_id,
            "host": host_did,
            "member": member,
        });
        if let Some(r) = reason {
            payload["reason"] = json!(r);
        }
        let value = self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_OWNER_GROUP_REMOVE_0_1,
                payload,
                // As for add: an earlier advance settled, then this one.
                ROOM_TT_TIMEOUT * 4,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| {
            VtaError::Protocol(format!(
                "rooms/owner/group/remove response does not match its schema: {e}"
            ))
        })
    }

    /// `rooms/owner/group/renew/0.1` — renew a sealed room: advance its group with a
    /// commit that adds and removes nobody, and the room's epoch at `host_did` with it.
    ///
    /// The only correct renewal of an `attributed` or `private` room — a bare
    /// `rooms/epoch/mint` moves the host without the group and leaves every member unable
    /// to write. The VTA advances the host first, and only then its own group. Every
    /// remaining member's key holder must then apply the commit (`rooms/keys/commit`, or
    /// from the host's relay). Call this inside [`VtaClient::idempotent`]: the task is
    /// `Keyed`, and a retry after a lost reply would otherwise renew a second time.
    pub async fn room_group_renew(
        &self,
        room_id: &str,
        host_did: &str,
        reason: Option<&str>,
    ) -> Result<trust_tasks_rs::specs::rooms::owner::group::renew::v0_1::Response, VtaError> {
        let mut payload = json!({
            "roomId": room_id,
            "host": host_did,
        });
        if let Some(r) = reason {
            payload["reason"] = json!(r);
        }
        let value = self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_OWNER_GROUP_RENEW_0_1,
                payload,
                // As for add: an earlier advance settled, then this one.
                ROOM_TT_TIMEOUT * 4,
            )
            .await?;
        serde_json::from_value(value).map_err(|e| {
            VtaError::Protocol(format!(
                "rooms/owner/group/renew response does not match its schema: {e}"
            ))
        })
    }

    // ── The owner's credential tasks (`rooms/owner/{register,invite,issue-*}`) ──
    //
    // Each payload is built through its generated type, so a value the
    // specification refuses (an empty action list, an over-long key id) is
    // refused here rather than by the VTA.

    /// `rooms/owner/register/0.1` — ask this VTA to register a room with a host
    /// (`rooms/create`), signed **as the owner**.
    ///
    /// `owner_did` must be a DID this VTA holds the signing key for, in a context
    /// the caller acts in — a `did:webvh` it minted, a `did:key` whose key it
    /// holds, or its own DID. `None` means the caller, which works only when the
    /// caller's DID is one of those (a CLI session's `did:key` is not: its key
    /// lives in the client). On a VTC the owner must also be a member of the
    /// community, whose `rooms` policy decides creation against the signer.
    pub async fn room_owner_register(
        &self,
        request: RoomRegistration<'_>,
    ) -> Result<trust_tasks_rs::specs::rooms::owner::register::v0_1::Response, VtaError> {
        let payload = room_register_payload(&request)?;
        let value = self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_OWNER_REGISTER_0_1,
                serde_json::to_value(payload)?,
                // One host round trip, over whatever transport the host speaks.
                ROOM_TT_TIMEOUT * 2,
            )
            .await?;
        parse_response(value, "rooms/owner/register")
    }

    /// `rooms/owner/invite/0.1` — mint a Verifiable Invitation Credential (VIC) in
    /// the room's name, naming `subject`.
    ///
    /// `subject` is the DID that will redeem it at its own key holder
    /// (`rooms/keys/key-package`, then `rooms/keys/welcome`): the key holder checks
    /// the invitation names the party asking. The answer is the only copy of the
    /// credential, so call this inside [`VtaClient::idempotent`] (the task is
    /// `Keyed`).
    pub async fn room_owner_invite(
        &self,
        room_id: &str,
        signing_key_id: &str,
        subject: &str,
        valid_until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<trust_tasks_rs::specs::rooms::owner::invite::v0_1::Response, VtaError> {
        use trust_tasks_rs::specs::rooms::owner::invite::v0_1::Payload;
        let payload = Payload::builder()
            .room_id(room_id)
            .signing_key_id(signing_key_id)
            .subject(subject)
            .valid_until(valid_until);
        let payload = Payload::try_from(payload)
            .map_err(|e| VtaError::Validation(format!("rooms/owner/invite request: {e}")))?;
        let value = self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_OWNER_INVITE_0_1,
                serde_json::to_value(payload)?,
                ROOM_TT_TIMEOUT,
            )
            .await?;
        parse_response(value, "rooms/owner/invite")
    }

    /// `rooms/owner/issue-membership/0.1` — mint the Verifiable Membership
    /// Credential (VMC) `subject` presents on every room operation. Call it inside
    /// [`VtaClient::idempotent`] (the task is `Keyed`).
    pub async fn room_owner_issue_membership(
        &self,
        room_id: &str,
        signing_key_id: &str,
        subject: &str,
        valid_until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<trust_tasks_rs::specs::rooms::owner::issue_membership::v0_1::Response, VtaError>
    {
        use trust_tasks_rs::specs::rooms::owner::issue_membership::v0_1::Payload;
        let payload = Payload::builder()
            .room_id(room_id)
            .signing_key_id(signing_key_id)
            .subject(subject)
            .valid_until(valid_until);
        let payload = Payload::try_from(payload).map_err(|e| {
            VtaError::Validation(format!("rooms/owner/issue-membership request: {e}"))
        })?;
        let value = self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_OWNER_ISSUE_MEMBERSHIP_0_1,
                serde_json::to_value(payload)?,
                ROOM_TT_TIMEOUT,
            )
            .await?;
        parse_response(value, "rooms/owner/issue-membership")
    }

    /// `rooms/owner/issue-authority/0.2` — mint a Verifiable Authority Credential
    /// (VAC): a chain root at the room's scope conferring `actions`.
    ///
    /// `valid_until` is required by the specification, not defaulted: a root is
    /// the grant nothing else withdraws, so expiry is how it ends. An empty
    /// `actions` is refused rather than read as "everything". Call it inside
    /// [`VtaClient::idempotent`] (the task is `Keyed`).
    pub async fn room_owner_issue_authority(
        &self,
        room_id: &str,
        signing_key_id: &str,
        subject: &str,
        actions: Vec<RoomAction>,
        valid_until: chrono::DateTime<chrono::Utc>,
    ) -> Result<trust_tasks_rs::specs::rooms::owner::issue_authority::v0_2::Response, VtaError>
    {
        let payload =
            room_issue_authority_payload(room_id, signing_key_id, subject, actions, valid_until)?;
        let value = self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_OWNER_ISSUE_AUTHORITY_0_2,
                serde_json::to_value(payload)?,
                ROOM_TT_TIMEOUT,
            )
            .await?;
        parse_response(value, "rooms/owner/issue-authority")
    }

    // ── The joiner's key-holder tasks (`rooms/keys/{key-package,welcome,commit,list}`) ──

    /// `rooms/keys/key-package/0.1` — mint an MLS KeyPackage for a room this
    /// caller has been invited to, for the owner to admit with
    /// `rooms/owner/group/add`.
    ///
    /// `invitation` is the VIC as the room issued it (JSON or base64url); it must
    /// name the caller. The private half stays in this VTA, for seven days. The
    /// answer is the only copy of the package, so call this inside
    /// [`VtaClient::idempotent`] (the task is `Keyed`).
    pub async fn room_key_package(
        &self,
        room_id: &str,
        invitation: &str,
    ) -> Result<trust_tasks_rs::specs::rooms::keys::key_package::v0_1::Response, VtaError> {
        use trust_tasks_rs::specs::rooms::keys::key_package::v0_1::Payload;
        let payload = Payload::builder()
            .room_id(room_id)
            .invitation(Some(invitation.to_string()));
        let payload = Payload::try_from(payload)
            .map_err(|e| VtaError::Validation(format!("rooms/keys/key-package request: {e}")))?;
        let value = self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_KEYS_KEY_PACKAGE_0_1,
                serde_json::to_value(payload)?,
                ROOM_TT_TIMEOUT,
            )
            .await?;
        parse_response(value, "rooms/keys/key-package")
    }

    /// `rooms/keys/welcome/0.1` — join a room's group from the Welcome its owner
    /// delivered, consuming the invitation.
    ///
    /// The reply's `epoch` is the **MLS** epoch joined at, per the specification —
    /// one less than the room epoch a host and `rooms/keys/list` report. Call it
    /// inside [`VtaClient::idempotent`] (the task is `Keyed`): a retry that
    /// re-executed would find the group already held and the invitation spent.
    pub async fn room_welcome(
        &self,
        room_id: &str,
        invitation: &str,
        welcome: &str,
        ratchet_tree: Option<&str>,
    ) -> Result<trust_tasks_rs::specs::rooms::keys::welcome::v0_1::Response, VtaError> {
        use trust_tasks_rs::specs::rooms::keys::welcome::v0_1::Payload;
        let payload = Payload::builder()
            .room_id(room_id)
            .invitation(Some(invitation.to_string()))
            .welcome(welcome)
            .ratchet_tree(ratchet_tree.map(str::to_string));
        let payload = Payload::try_from(payload)
            .map_err(|e| VtaError::Validation(format!("rooms/keys/welcome request: {e}")))?;
        let value = self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_KEYS_WELCOME_0_1,
                serde_json::to_value(payload)?,
                ROOM_TT_TIMEOUT,
            )
            .await?;
        parse_response(value, "rooms/keys/welcome")
    }

    /// `rooms/keys/commit/0.1` — apply one MLS Commit to the room's group this VTA
    /// holds, advancing one epoch.
    ///
    /// `mls_epoch` is the **MLS** epoch the commit produces, per the
    /// specification: a commit a host relays at room epoch `n`
    /// (`rooms/epoch/commits`) produces MLS epoch `n - 1`. Delivering one already
    /// applied answers with the unchanged epoch; one that skips ahead is refused
    /// with the epoch to resume from.
    pub async fn room_commit(
        &self,
        room_id: &str,
        commit: &str,
        mls_epoch: std::num::NonZeroU64,
    ) -> Result<trust_tasks_rs::specs::rooms::keys::commit::v0_1::Response, VtaError> {
        use trust_tasks_rs::specs::rooms::keys::commit::v0_1::Payload;
        let payload = Payload::builder()
            .room_id(room_id)
            .commit(commit)
            .epoch(mls_epoch);
        let payload = Payload::try_from(payload)
            .map_err(|e| VtaError::Validation(format!("rooms/keys/commit request: {e}")))?;
        let value = self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_KEYS_COMMIT_0_1,
                serde_json::to_value(payload)?,
                ROOM_TT_TIMEOUT,
            )
            .await?;
        parse_response(value, "rooms/keys/commit")
    }

    /// `rooms/keys/backfill/0.1` — have this VTA fetch the room's epoch key chain from its
    /// host and keep it, so records sealed before it joined open.
    ///
    /// The VTA makes the call to the host (named by DID), so the client needs no channel
    /// to it. `from_epoch` asks for rungs at or below that epoch; a long history is walked
    /// by calling again below what the last answer reached.
    pub async fn room_backfill(
        &self,
        room_id: &str,
        host_did: &str,
        from_epoch: Option<std::num::NonZeroU64>,
    ) -> Result<trust_tasks_rs::specs::rooms::keys::backfill::v0_1::Response, VtaError> {
        use trust_tasks_rs::specs::rooms::keys::backfill::v0_1::Payload;
        let payload = Payload::builder()
            .room_id(room_id)
            .host(host_did)
            .from_epoch(from_epoch);
        let payload = Payload::try_from(payload)
            .map_err(|e| VtaError::Validation(format!("rooms/keys/backfill request: {e}")))?;
        let value = self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_KEYS_BACKFILL_0_1,
                serde_json::to_value(payload)?,
                ROOM_TT_TIMEOUT,
            )
            .await?;
        parse_response(value, "rooms/keys/backfill")
    }

    /// `rooms/keys/list/0.1` — the rooms this VTA holds a group for, each with the
    /// room epoch it is at and how far back it can read.
    ///
    /// Key custody, never membership: a room whose Welcome never arrived is absent
    /// even where a good membership credential is held.
    pub async fn room_keys_list(
        &self,
    ) -> Result<trust_tasks_rs::specs::rooms::keys::list::v0_1::Response, VtaError> {
        let value = self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_KEYS_LIST_0_1,
                json!({}),
                ROOM_TT_TIMEOUT,
            )
            .await?;
        parse_response(value, "rooms/keys/list")
    }
}

/// One room action a VAC confers — the generated `rooms/owner/issue-authority/0.2`
/// item type (`read`, `write`, `curate`, `admin`; parse one with `str::parse`).
pub type RoomAction =
    trust_tasks_rs::specs::rooms::owner::issue_authority::v0_2::PayloadActionsItem;

/// A room's visibility tier, as `rooms/owner/register/0.1` names it (`open`,
/// `attributed`, `private`; parse one with `str::parse`).
pub type RoomVisibility = trust_tasks_rs::specs::rooms::owner::register::v0_1::Visibility;

/// Whether a room keeps its history readable across a membership change
/// (`chained`, `fromJoin`; parse one with `str::parse`).
pub type RoomRetentionPolicy = trust_tasks_rs::specs::rooms::owner::register::v0_1::RetentionPolicy;

/// What [`VtaClient::room_owner_register`] asks for.
#[derive(Debug, Clone)]
pub struct RoomRegistration<'a> {
    /// The room's DID — its identity exists already; this asks a host to store it.
    pub room_id: &'a str,
    /// The host to register with, as a DID.
    pub host_did: &'a str,
    /// Fixed for the life of the room.
    pub visibility: RoomVisibility,
    /// The accountable party, whose key signs `rooms/create`. `None` is the caller.
    pub owner_did: Option<&'a str>,
    /// How long the host is asked to hold the room after it lapses.
    pub retention_days: Option<std::num::NonZeroU64>,
    /// Immutable once set; `None` takes the host's default for the life of the room.
    pub retention_policy: Option<RoomRetentionPolicy>,
}

fn room_register_payload(
    r: &RoomRegistration<'_>,
) -> Result<trust_tasks_rs::specs::rooms::owner::register::v0_1::Payload, VtaError> {
    use trust_tasks_rs::specs::rooms::owner::register::v0_1::Payload;
    let payload = Payload::builder()
        .room_id(r.room_id)
        .host(r.host_did)
        .visibility(r.visibility)
        .owner_did(r.owner_did.map(str::to_string))
        .retention_days(r.retention_days)
        .retention_policy(r.retention_policy);
    Payload::try_from(payload)
        .map_err(|e| VtaError::Validation(format!("rooms/owner/register request: {e}")))
}

fn room_issue_authority_payload(
    room_id: &str,
    signing_key_id: &str,
    subject: &str,
    actions: Vec<RoomAction>,
    valid_until: chrono::DateTime<chrono::Utc>,
) -> Result<trust_tasks_rs::specs::rooms::owner::issue_authority::v0_2::Payload, VtaError> {
    use trust_tasks_rs::specs::rooms::owner::issue_authority::v0_2::Payload;
    // The schema requires at least one action; say so here, in words, rather than
    // letting "confers nothing" travel to the VTA to be refused.
    if actions.is_empty() {
        return Err(VtaError::Validation(
            "rooms/owner/issue-authority needs at least one action (read, write, curate, admin)"
                .into(),
        ));
    }
    let payload = Payload::builder()
        .room_id(room_id)
        .signing_key_id(signing_key_id)
        .subject(subject)
        .actions(actions)
        .valid_until(valid_until);
    Payload::try_from(payload)
        .map_err(|e| VtaError::Validation(format!("rooms/owner/issue-authority request: {e}")))
}

/// Read a reply through the task's generated response type.
fn parse_response<T: serde::de::DeserializeOwned>(value: Value, task: &str) -> Result<T, VtaError> {
    serde_json::from_value(value)
        .map_err(|e| VtaError::Protocol(format!("{task} response does not match its schema: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration() -> RoomRegistration<'static> {
        RoomRegistration {
            room_id: "did:webvh:Qm:rooms.example.org:deal",
            host_did: "did:web:vtc.example.org",
            visibility: "attributed".parse().unwrap(),
            owner_did: Some("did:webvh:Qm:example.org:alice"),
            retention_days: std::num::NonZeroU64::new(30),
            retention_policy: Some("chained".parse().unwrap()),
        }
    }

    /// The register payload goes out in the specification's own member names, and
    /// an absent owner stays absent — the VTA reads absence as "the caller".
    #[test]
    fn a_registration_is_built_through_the_generated_payload() {
        let v = serde_json::to_value(room_register_payload(&registration()).unwrap()).unwrap();
        assert_eq!(
            v,
            json!({
                "roomId": "did:webvh:Qm:rooms.example.org:deal",
                "host": "did:web:vtc.example.org",
                "visibility": "attributed",
                "ownerDid": "did:webvh:Qm:example.org:alice",
                "retentionDays": 30,
                "retentionPolicy": "chained",
            })
        );

        let mut r = registration();
        r.owner_did = None;
        r.retention_days = None;
        r.retention_policy = None;
        let v = serde_json::to_value(room_register_payload(&r).unwrap()).unwrap();
        assert!(v.get("ownerDid").is_none(), "{v}");
        assert!(v.get("retentionPolicy").is_none(), "{v}");
    }

    /// "Confers nothing" and "confers everything" are the two readings of an empty
    /// action list a careless consumer chooses between. Neither is sent.
    #[test]
    fn an_authority_grant_with_no_action_is_refused_before_it_is_sent() {
        let until = chrono::Utc::now() + chrono::Duration::days(30);
        let err =
            room_issue_authority_payload("did:key:zRoom", "key-1", "did:key:zA", vec![], until)
                .expect_err("an empty action list is refused");
        assert!(err.to_string().contains("at least one action"), "{err}");

        let ok = room_issue_authority_payload(
            "did:key:zRoom",
            "key-1",
            "did:key:zA",
            vec!["read".parse().unwrap(), "admin".parse().unwrap()],
            until,
        )
        .unwrap();
        let v = serde_json::to_value(ok).unwrap();
        assert_eq!(v["actions"], json!(["read", "admin"]));
        assert!(
            v["validUntil"].is_string(),
            "validUntil is always sent: {v}"
        );
    }

    /// An action outside the ladder does not parse, so no CLI flag can smuggle one.
    #[test]
    fn only_the_four_room_actions_parse() {
        for a in ["read", "write", "curate", "admin"] {
            assert!(a.parse::<RoomAction>().is_ok(), "{a}");
        }
        assert!("all".parse::<RoomAction>().is_err());
        assert!("Admin".parse::<RoomAction>().is_err());
    }
}

/// An unsigned host-bound room request for [`VtaClient::room_act`]: a fresh `id`, `issuedAt`
/// now, addressed to `host`, carrying `payload` (without `presentation`). `issuer` names the
/// member to act as — never this client's own DID. It is needed where the caller may act as
/// more than one member of the room, and always where `payload` names no room (a download
/// chunk, a direct upload's commit or abort): there it is the member whose request opened
/// the transfer (`rooms/keys/act/0.2` producer item 2).
///
/// # Errors
///
/// [`VtaError::Validation`] when a member does not fit the generated type (a `type` that is
/// not a room type, a `recipient` or `issuer` that is not a DID), or when `payload` names
/// no `roomId` and `issuer` is absent.
pub fn unsigned_room_request(
    type_uri: &str,
    host: &str,
    issuer: Option<&str>,
    payload: Value,
) -> Result<trust_tasks_rs::specs::rooms::keys::act::v0_2::UnsignedRoomRequest, VtaError> {
    if issuer.is_none() && payload.get("roomId").is_none() {
        return Err(VtaError::Validation(format!(
            "`{type_uri}` names no room, so the member to act as is the document's `issuer`: \
             name the member whose request opened the transfer"
        )));
    }
    let mut doc = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "recipient": host,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    });
    if let Some(i) = issuer {
        doc["issuer"] = json!(i);
    }
    serde_json::from_value(doc)
        .map_err(|e| VtaError::Validation(format!("not a room request this can complete: {e}")))
}

#[cfg(test)]
mod act_tests {
    use super::*;

    /// What a member's client hands `rooms/keys/act`: no proof, no presentation, and its
    /// own DID nowhere — `issuer` only when it names a member.
    #[test]
    fn an_unsigned_room_request_names_no_one_but_the_host() {
        let doc = unsigned_room_request(
            "https://trusttasks.org/spec/rooms/records/get/0.1",
            "did:key:zHost",
            None,
            json!({ "roomId": "did:key:zRoom", "key": "k" }),
        )
        .expect("a room request");
        let v = serde_json::to_value(&doc).unwrap();
        assert_eq!(v["recipient"], "did:key:zHost");
        assert!(v.get("issuer").is_none());
        assert!(v.get("proof").is_none());
        assert!(v["id"].as_str().unwrap().starts_with("urn:uuid:"));

        let named = unsigned_room_request(
            "https://trusttasks.org/spec/rooms/records/get/0.1",
            "did:key:zHost",
            Some("did:webvh:example.com:people:alice"),
            json!({ "roomId": "did:key:zRoom", "key": "k" }),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&named).unwrap()["issuer"],
            "did:webvh:example.com:people:alice"
        );
    }

    /// The schema's envelope rules hold here, before the VTA is asked: a non-room type and
    /// a recipient that is not a DID are refused.
    #[test]
    fn a_request_that_is_not_a_room_request_is_refused() {
        assert!(
            unsigned_room_request(
                "https://trusttasks.org/spec/keys/sign/0.1",
                "did:key:zHost",
                None,
                json!({}),
            )
            .is_err()
        );
        assert!(
            unsigned_room_request(
                "https://trusttasks.org/spec/rooms/info/0.1",
                "https://host.example",
                None,
                json!({ "roomId": "did:key:zRoom" }),
            )
            .is_err()
        );
    }

    /// `rooms/keys/act/0.2` producer item 2: a type that names no room carries its member
    /// in `issuer`, always — the VTA refuses to pick one, so the client never asks it to.
    #[test]
    fn a_room_less_request_names_its_member() {
        for (type_uri, payload) in [
            (
                "https://trusttasks.org/spec/rooms/blobs/chunk/0.1",
                json!({ "downloadId": "d", "index": 0 }),
            ),
            (
                "https://trusttasks.org/spec/rooms/blobs/upload/commit/0.2",
                json!({ "uploadId": "u" }),
            ),
            (
                "https://trusttasks.org/spec/rooms/blobs/upload/abort/0.2",
                json!({ "uploadId": "u" }),
            ),
        ] {
            let err = unsigned_room_request(type_uri, "did:key:zHost", None, payload.clone())
                .expect_err("no issuer");
            assert!(matches!(err, VtaError::Validation(_)), "{type_uri}: {err}");
            let named = unsigned_room_request(
                type_uri,
                "did:key:zHost",
                Some("did:webvh:example.com:people:alice"),
                payload,
            )
            .expect("named");
            assert_eq!(
                serde_json::to_value(&named).unwrap()["issuer"],
                "did:webvh:example.com:people:alice"
            );
        }
    }
}
