//! A member's records, through their own VTA: `rooms/keys/browse/0.4`, `rooms/keys/read/0.2`
//! (one record or a batch), `rooms/keys/seal/0.3` and `rooms/keys/act/0.11` — and the
//! writer's rule for the members a room's profile governs (trust-tasks-tf #1027).
//!
//! # The writer's rule
//!
//! A record may carry `kind`, `inReplyTo`, `writtenAt`, `editedAt`, and in its `file` a
//! `width`, `height` or `preview`, only where the room's current profile lists them in
//! `recordMembers` (`SealedRecordBody`, *When a writer may use these members*); a member's
//! name — a record of kind `memberProfile` — only where it also lists `memberProfile`
//! (`rooms/_shared/0.3` `MemberProfileRecord`). Neither the
//! VTA sealing a body nor a host on a sealed tier checks it: it is the writer's, so it is
//! here. [`VtaClient::room_check_record_members`] reads the profile only when a body uses
//! one of them, applies the rule ([`record_members_permitted`] — the rule of
//! `vti_rooms::record_members::permitted`, which this crate cannot depend on: `vti-rooms`
//! sits above `vti-common`, which sits above this crate), and refuses with
//! [`VtaError::RecordMembersNotPermitted`] before anything is sealed or sent. A writer may
//! rely on a profile it resolved within the room's current epoch, so the answer is kept per
//! room, host and member until the room's epoch (`rooms/keys/list`) moves; an `open` room
//! has no epoch and is read every time.
//!
//! # Versions, and older VTAs
//!
//! Each method sends the newest version and falls back when the VTA answers
//! [`VtaError::UnsupportedTaskType`]: browse/0.3, read/0.1 (a batch read key by key), seal/0.2
//! — the last only for a body using none of the governed members, which 0.2 refuses.

use std::collections::HashMap;

use serde_json::{Map, Value, json};

use super::VtaClient;
use crate::error::VtaError;
use crate::trust_tasks;

use vti_specs::rooms::keys::{act::v0_11 as act, browse::v0_4 as browse, read::v0_2 as read};

/// Round-trip timeout (seconds) for one record or a listing: one host request at the VTA, a
/// trace to check, possibly a repair.
const ROOM_READ_TIMEOUT: u64 = 30;

/// Round-trip timeout (seconds) for a batch read. The VTA stops beginning keys after its
/// own 15-second budget, then finishes the key in hand and at most one repair, which can
/// wait 20 seconds for another read's; 60 covers that with room for the transport.
const ROOM_BATCH_READ_TIMEOUT: u64 = 60;

/// Sealing is local work at the VTA.
const ROOM_SEAL_TIMEOUT: u64 = 30;

/// The most keys one `rooms/keys/read/0.2` request may name.
pub const ROOM_READ_MAX_KEYS: usize = 32;

/// What [`VtaClient::room_browse`] passes to the host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoomBrowse {
    /// Only records whose key starts with this.
    pub prefix: Option<String>,
    /// Only records above this version.
    pub since_version: Option<u64>,
    /// The page size to ask the host for — never a cap on the result.
    pub limit: Option<u64>,
}

/// The `recordMembers` this client resolved per room, host and member, with the epoch it
/// resolved them in. Shared by clones of a client.
#[derive(Debug, Default)]
pub(crate) struct RecordMembersCache {
    entries:
        std::sync::Mutex<HashMap<(String, String, Option<String>), (u64, Option<Vec<String>>)>>,
}

impl RecordMembersCache {
    fn get(
        &self,
        key: &(String, String, Option<String>),
        epoch: u64,
    ) -> Option<Option<Vec<String>>> {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries
            .get(key)
            .filter(|(e, _)| *e == epoch)
            .map(|(_, m)| m.clone())
    }

    fn put(&self, key: (String, String, Option<String>), epoch: u64, members: Option<Vec<String>>) {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries.insert(key, (epoch, members));
    }
}

/// The body members `recordMembers` governs, as the wire spells them
/// (`vti_rooms::record_members::BODY_MEMBERS`; `vta-service` pins the two equal).
pub const RECORD_BODY_MEMBERS: [&str; 4] = ["kind", "inReplyTo", "writtenAt", "editedAt"];

/// The `FileManifest` members `recordMembers` governs, inside a record's `file`
/// (`vti_rooms::record_members::FILE_MEMBERS`).
pub const RECORD_FILE_MEMBERS: [&str; 3] = ["width", "height", "preview"];

/// The record kind of a member's name in a room (`rooms/_shared/0.3` `MemberProfileRecord`),
/// and the `recordMembers` value that permits writing one.
pub const MEMBER_PROFILE_KIND: &str = "memberProfile";

/// The `recordMembers` values that permit a record **kind**: a record of that kind is
/// written only where the profile lists the value as well as `kind`. `memberProfile`, a
/// member's name in the room (`rooms/_shared/0.3` `MemberProfileRecord`;
/// `vti_rooms::record_members::KIND_VALUES`).
pub const RECORD_KIND_VALUES: [&str; 1] = [MEMBER_PROFILE_KIND];

/// Every governed member `body` carries, by the name `recordMembers` lists it under, in a
/// fixed order — and, last, the value its `kind` needs listed where that kind is one of
/// [`RECORD_KIND_VALUES`] (`vti_rooms::record_members::used`).
pub fn record_members_used(body: &Map<String, Value>) -> Vec<&'static str> {
    let file = body.get("file").and_then(Value::as_object);
    let kind = body.get("kind").and_then(Value::as_str);
    RECORD_BODY_MEMBERS
        .iter()
        .filter(|m| body.contains_key(**m))
        .chain(
            RECORD_FILE_MEMBERS
                .iter()
                .filter(|m| file.is_some_and(|f| f.contains_key(**m))),
        )
        .chain(RECORD_KIND_VALUES.iter().filter(|v| kind == Some(**v)))
        .copied()
        .collect()
}

/// The writer's rule (`vti_rooms::record_members::permitted`): the governed members `body`
/// uses that `record_members` does not list — empty when it may be written. `None` is no
/// profile, a profile without `recordMembers` or one that could not be resolved, and
/// permits none.
pub fn record_members_permitted(
    body: &Map<String, Value>,
    record_members: Option<&[String]>,
) -> Vec<&'static str> {
    let listed = record_members.unwrap_or_default();
    record_members_used(body)
        .into_iter()
        .filter(|m| !listed.iter().any(|l| l == m))
        .collect()
}

/// The writer's rule over `body`, given the room's `recordMembers` (`None`: no profile, a
/// profile without it, or one that could not be resolved — which permits none).
///
/// `body` is a `SealedRecordBody` or an open room's `cleartext`. `unresolved` is why the
/// profile could not be read, carried into the refusal so an operator is not told the room
/// forbids what it merely could not be asked about.
pub fn check_record_members(
    room_id: &str,
    body: &Value,
    record_members: Option<&[String]>,
    unresolved: Option<String>,
) -> Result<(), VtaError> {
    let Some(obj) = body.as_object() else {
        return Ok(());
    };
    let refused: Vec<String> = record_members_permitted(obj, record_members)
        .into_iter()
        .map(str::to_string)
        .collect();
    if refused.is_empty() {
        return Ok(());
    }
    let listed = record_members.map(<[String]>::to_vec).unwrap_or_default();
    Err(VtaError::RecordMembersNotPermitted {
        room_id: room_id.to_string(),
        refused,
        listed,
        unresolved,
    })
}

impl VtaClient {
    /// `rooms/keys/browse/0.4` — the room's records at `host_did`, metadata only, read as the
    /// member and checked against what the host committed to. Rows are `RecordMetadataV3` as
    /// the host's `rooms/records/list/0.6` served them: `createdAt`, `bodyStoredAt`,
    /// `createdBy` (`open` and `attributed`) and `kind` (`open`), absent where the host
    /// predates them.
    ///
    /// A VTA that does not serve 0.4 is asked browse/0.3, whose rows carry none of them.
    pub async fn room_browse(
        &self,
        room_id: &str,
        host_did: &str,
        options: &RoomBrowse,
        member: Option<&str>,
    ) -> Result<browse::Response, VtaError> {
        let mut payload = json!({ "roomId": room_id, "host": host_did });
        if let Some(p) = &options.prefix {
            payload["prefix"] = json!(p);
        }
        if let Some(v) = options.since_version {
            payload["sinceVersion"] = json!(v);
        }
        if let Some(l) = options.limit {
            payload["limit"] = json!(l);
        }
        name_member(&mut payload, member);
        let value = match self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_KEYS_BROWSE_0_4,
                payload.clone(),
                ROOM_READ_TIMEOUT,
            )
            .await
        {
            Err(VtaError::UnsupportedTaskType { .. }) => {
                self.dispatch_trust_task(
                    trust_tasks::TASK_ROOMS_KEYS_BROWSE_0_3,
                    payload,
                    ROOM_READ_TIMEOUT,
                )
                .await?
            }
            other => other?,
        };
        parse(value, "rooms/keys/browse")
    }

    /// `rooms/keys/read/0.2` naming `key` — one record, fetched from `host_did` as the
    /// member, checked and opened: `plaintext` (base64url) on a sealed tier, `cleartext` on
    /// `open`, with the host's `createdAt`, `createdBy` and `bodyStoredAt` where it served
    /// them. A refusal is the task's: `rooms/keys/read:cannotOpen` with `details.reason`,
    /// `hostRefused`, `hostUnreachable`, `notAMember`.
    ///
    /// A VTA that does not serve 0.2 is asked read/0.1.
    pub async fn room_read(
        &self,
        room_id: &str,
        host_did: &str,
        key: &str,
        member: Option<&str>,
    ) -> Result<read::Response, VtaError> {
        let mut payload = json!({ "roomId": room_id, "host": host_did, "key": key });
        name_member(&mut payload, member);
        let value = match self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_KEYS_READ_0_2,
                payload.clone(),
                ROOM_READ_TIMEOUT,
            )
            .await
        {
            Err(VtaError::UnsupportedTaskType { .. }) => {
                self.dispatch_trust_task(
                    trust_tasks::TASK_ROOMS_KEYS_READ_0_1,
                    payload,
                    ROOM_READ_TIMEOUT,
                )
                .await?
            }
            other => other?,
        };
        parse(value, "rooms/keys/read")
    }

    /// `rooms/keys/read/0.2` naming `keys` — up to [`ROOM_READ_MAX_KEYS`] records in one
    /// request, answered in `results` in the same order, each a record or that key's own
    /// `error`. `rooms/keys/read:notAttempted` (retryable) is a key the VTA did not come to
    /// within its budget for one response: ask for it again.
    ///
    /// A VTA that does not serve 0.2 is asked read/0.1 key by key, and its answers are put
    /// in the same shape — a refusal becoming that key's `error`. A failure to reach the VTA
    /// at all is the call's error.
    pub async fn room_read_batch(
        &self,
        room_id: &str,
        host_did: &str,
        keys: &[&str],
        member: Option<&str>,
    ) -> Result<read::Response, VtaError> {
        if keys.is_empty() || keys.len() > ROOM_READ_MAX_KEYS {
            return Err(VtaError::Validation(format!(
                "a batch read names 1 to {ROOM_READ_MAX_KEYS} keys, not {}",
                keys.len()
            )));
        }
        let mut payload = json!({ "roomId": room_id, "host": host_did, "keys": keys });
        name_member(&mut payload, member);
        match self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_KEYS_READ_0_2,
                payload,
                ROOM_BATCH_READ_TIMEOUT,
            )
            .await
        {
            Err(VtaError::UnsupportedTaskType { .. }) => {}
            other => return parse(other?, "rooms/keys/read"),
        }

        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            let mut payload = json!({ "roomId": room_id, "host": host_did, "key": key });
            name_member(&mut payload, member);
            let entry = match self
                .dispatch_trust_task(
                    trust_tasks::TASK_ROOMS_KEYS_READ_0_1,
                    payload,
                    ROOM_READ_TIMEOUT,
                )
                .await
            {
                Ok(Value::Object(mut fields)) => {
                    fields.remove("roomId");
                    fields.remove("ext");
                    Value::Object(fields)
                }
                Ok(other) => {
                    return Err(VtaError::Protocol(format!(
                        "rooms/keys/read/0.1 answered something other than a record: {other}"
                    )));
                }
                Err(VtaError::Rejected {
                    code,
                    message,
                    details,
                }) => {
                    let retryable = vti_specs::schema_index::error_codes_for(
                        trust_tasks::TASK_ROOMS_KEYS_READ_0_1,
                    )
                    .and_then(|c| c.iter().find(|c| c.code == code))
                    .is_some_and(|c| c.retryable);
                    let mut error = json!({
                        "code": code,
                        "message": message.chars().take(1024).collect::<String>(),
                        "retryable": retryable,
                    });
                    if let Some(d) = details.filter(Value::is_object) {
                        error["details"] = d;
                    }
                    json!({ "key": key, "error": error })
                }
                Err(e) => return Err(e),
            };
            results.push(entry);
        }
        parse(
            json!({ "roomId": room_id, "results": results }),
            "rooms/keys/read",
        )
    }

    /// The room's `recordMembers` as its current profile states them, read through
    /// [`VtaClient::room_profile_read`] as `member` — `None` when the room has no profile, it
    /// lists none, or the profile was cleared. Kept for the room's current epoch
    /// (`rooms/keys/list`), so a writer asks once per epoch; an `open` room, which has no
    /// epoch, is read every time.
    pub async fn room_record_members(
        &self,
        room_id: &str,
        host_did: &str,
        member: Option<&str>,
    ) -> Result<Option<Vec<String>>, VtaError> {
        let epoch = self.room_epoch(room_id, member).await;
        let key = (
            room_id.to_string(),
            host_did.to_string(),
            member.map(str::to_string),
        );
        if let Some(e) = epoch
            && let Some(cached) = self.record_members.get(&key, e)
        {
            return Ok(cached);
        }
        let read = self.room_profile_read(room_id, host_did, member).await?;
        let value = serde_json::to_value(&read)?;
        let members = (value["status"] == "found")
            .then(|| value["profile"]["recordMembers"].clone())
            .and_then(|m| serde_json::from_value::<Vec<String>>(m).ok());
        if let Some(e) = epoch {
            self.record_members.put(key, e, members.clone());
        }
        Ok(members)
    }

    /// The epoch this VTA holds `room_id` at for `member` (or for the one member it holds
    /// the room as), or `None` — an `open` room, or one it cannot say.
    async fn room_epoch(&self, room_id: &str, member: Option<&str>) -> Option<u64> {
        let list = self.room_list(false).await.ok()?;
        let value = serde_json::to_value(&list).ok()?;
        let held: Vec<&Value> = value["rooms"]
            .as_array()?
            .iter()
            .filter(|r| r["roomId"] == room_id)
            .filter(|r| member.is_none_or(|m| r["member"] == m))
            .collect();
        match held.as_slice() {
            [one] => one["epoch"].as_u64(),
            _ => None,
        }
    }

    /// The writer's rule for `body` — a `SealedRecordBody` or an open room's `cleartext` —
    /// in `room_id` at `host_did`: `Ok` when it uses none of the members the room's profile
    /// governs, or only ones the profile lists; otherwise
    /// [`VtaError::RecordMembersNotPermitted`], before anything is sealed or sent. The
    /// profile is read only when the body uses one of them, and a profile that could not be
    /// read permits none.
    pub async fn room_check_record_members(
        &self,
        room_id: &str,
        host_did: &str,
        member: Option<&str>,
        body: &Value,
    ) -> Result<(), VtaError> {
        let uses_any = body
            .as_object()
            .is_some_and(|o| !record_members_used(o).is_empty());
        if !uses_any {
            return Ok(());
        }
        match self.room_record_members(room_id, host_did, member).await {
            Ok(listed) => check_record_members(room_id, body, listed.as_deref(), None),
            Err(e) => check_record_members(room_id, body, None, Some(e.to_string())),
        }
    }

    /// `rooms/keys/seal/0.3` with `signAsPrincipal` — [`VtaClient::room_seal_as_principal`],
    /// for a body that may carry `kind`, `inReplyTo`, `writtenAt`, `editedAt`, or a `file`
    /// with `width`, `height` or `preview`. The VTA does not apply the room's
    /// `recordMembers`: check the body first with [`VtaClient::room_check_record_members`].
    ///
    /// A VTA that does not serve 0.3 is asked seal/0.2 when the body uses none of those
    /// members; one that uses them is refused by 0.2, so the
    /// [`VtaError::UnsupportedTaskType`] is returned instead.
    pub async fn room_seal_as_principal_v0_3(
        &self,
        room_id: &str,
        key: &str,
        version: u64,
        body: &[u8],
    ) -> Result<vti_specs::rooms::keys::seal::v0_3::Response, VtaError> {
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
        match self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_KEYS_SEAL_0_3,
                payload,
                ROOM_SEAL_TIMEOUT,
            )
            .await
        {
            Err(e @ VtaError::UnsupportedTaskType { .. }) => {
                let uses_any = serde_json::from_slice::<Value>(body)
                    .ok()
                    .and_then(|b| b.as_object().cloned())
                    .is_some_and(|o| !record_members_used(&o).is_empty());
                if uses_any {
                    return Err(e);
                }
                let sealed = self
                    .room_seal_as_principal(room_id, key, version, body)
                    .await?;
                parse(serde_json::to_value(sealed)?, "rooms/keys/seal")
            }
            other => parse(other?, "rooms/keys/seal"),
        }
    }

    /// `rooms/keys/act/0.11` — [`VtaClient::room_act`], whose table adds
    /// `rooms/records/put/0.5`, `rooms/records/list/0.6` and `rooms/records/get/0.3`. Build
    /// `document` with [`unsigned_room_request_v0_11`]. A VTA that does not serve 0.11
    /// answers [`VtaError::UnsupportedTaskType`]; ask it [`VtaClient::room_act`] with a type
    /// its table holds.
    pub async fn room_act_v0_11(
        &self,
        document: &act::UnsignedRoomRequest,
    ) -> Result<act::Response, VtaError> {
        let value = self
            .dispatch_trust_task(
                trust_tasks::TASK_ROOMS_KEYS_ACT_0_11,
                json!({ "document": document }),
                ROOM_SEAL_TIMEOUT,
            )
            .await?;
        parse(value, "rooms/keys/act")
    }
}

/// [`super::unsigned_room_request`], as `rooms/keys/act/0.11` takes it.
pub fn unsigned_room_request_v0_11(
    type_uri: &str,
    host: &str,
    issuer: Option<&str>,
    payload: Value,
) -> Result<act::UnsignedRoomRequest, VtaError> {
    let v0_10 = super::unsigned_room_request(type_uri, host, issuer, payload)?;
    serde_json::from_value(serde_json::to_value(v0_10)?)
        .map_err(|e| VtaError::Validation(format!("not a room request this can complete: {e}")))
}

/// Name the member a custody task acts as (`ext["org.openvtc.rooms"].member`).
fn name_member(payload: &mut Value, member: Option<&str>) {
    if let Some(m) = member {
        payload["ext"] = json!({ "org.openvtc.rooms": { "member": m } });
    }
}

fn parse<T: serde::de::DeserializeOwned>(value: Value, task: &str) -> Result<T, VtaError> {
    serde_json::from_value(value)
        .map_err(|e| VtaError::Protocol(format!("{task} response does not match its schema: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listed(m: &[&str]) -> Vec<String> {
        m.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_gate_refuses_a_member_the_profile_does_not_list() {
        let body = json!({ "body": "hi", "kind": "message", "inReplyTo": { "key": "k" } });
        let err = check_record_members("did:example:room", &body, Some(&listed(&["kind"])), None)
            .unwrap_err();
        match err {
            VtaError::RecordMembersNotPermitted {
                refused, listed, ..
            } => {
                assert_eq!(refused, vec!["inReplyTo".to_string()]);
                assert_eq!(listed, vec!["kind".to_string()]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_gate_allows_a_listed_member_and_a_body_using_none() {
        let body = json!({ "body": "hi", "kind": "message", "writtenAt": "2026-01-01T00:00:00Z" });
        check_record_members(
            "did:example:room",
            &body,
            Some(&listed(&["kind", "writtenAt"])),
            None,
        )
        .unwrap();
        check_record_members("did:example:room", &json!({ "body": "plain" }), None, None).unwrap();
    }

    #[test]
    fn no_profile_permits_none_and_a_file_member_is_governed() {
        let body = json!({ "body": "x", "kind": "note" });
        assert!(check_record_members("did:example:room", &body, None, None).is_err());
        let image = json!({ "file": { "fileId": "f", "width": 640 } });
        let err = check_record_members(
            "did:example:room",
            &image,
            Some(&listed(&["kind"])),
            Some("unreachable".into()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("width"), "{err}");
    }
}
