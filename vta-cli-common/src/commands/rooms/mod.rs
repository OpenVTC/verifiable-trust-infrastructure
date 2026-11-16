//! `pnm rooms …` — a member's surface on a data room.
//!
//! # Two parties, two transports, and why that is the whole design
//!
//! Every command here talks to **two** services, and never confuses them:
//!
//! - the operator's **VTA**, over the client's existing session, to complete each
//!   host-bound request **as the member** ([`VtaClient::room_act`],
//!   `rooms/keys/act/0.10`), to seal a record body signed as the member
//!   ([`VtaClient::room_seal_as_principal`]) and to open a sealed record
//!   ([`VtaClient::room_open`]);
//! - the room's **host**, unauthenticated, receiving the completed document unchanged.
//!
//! # The member is the persona, never this client
//!
//! A room admitted the operator's **persona** — a DID their VTA holds — not this CLI's
//! session key. So the record verbs (`list`, `get`, `put`, `curate`, the `rooms/info`
//! lookup and `keys commit --host`) build the request unsigned and have the VTA complete
//! it as the persona: the persona's own authority narrowed to the one action, the persona
//! as `issuer` and signer. The host records the persona, and this client's DID reaches it
//! nowhere. File transfer works the same way (`rooms/blobs/*/0.2`): the begin, the record,
//! the read and — in direct mode — the commit are completed as the persona, and a proxied
//! upload's chunks are signed by a single-use upload key minted for that upload. `renew`
//! and `prune` still present for this client ([`VtaClient::room_present`]) and sign with
//! its own key; `renew` moves separately, and `prune` cannot move to `rooms/keys/act`,
//! whose every version leaves `rooms/epoch/prune` out on purpose.
//!
//! The credentials the presentation is derived from, and the group key that
//! opens a record, stay inside the VTA. This CLI holds neither at any point,
//! which is what makes losing the laptop a smaller event than losing the agent.
//!
//! # Why a fresh presentation per call
//!
//! A presentation names *what may be done*, not who is doing it, and is bound
//! to the party that signed the request it rides. Caching one across commands
//! would mean either re-binding it (impossible without the VTA) or sending it
//! unbound (a bearer token). It is one extra local round-trip and it removes a
//! whole class of mistake, so every command mints its own.
//!
//! # What this surface deliberately does not do
//!
//! **Issue credentials.** Minting a VIC, VMC or VAC needs the *room's* signing
//! key, which is the owner's, not a member's — a different party with different
//! custody. The owner's surface is [`super::rooms_custody`], whose verbs are
//! calls to the VTA holding that key.

use serde_json::Value;
use vta_sdk::prelude::*;
use vtc_client::VtcClient;
pub use vtc_client::rooms::body::RecordBasis;
use vtc_client::rooms::body::{
    RecordLocation, SealedRecordBody, VerifiedRecordBody, verify_record_body,
};
use vtc_client::rooms::{CleartextContent, RoomSession, SealedContent, Visibility};
use vti_specs::vault::credentials::get::v0_2 as vault_get;
/// Everything a room command needs to reach both parties.
///
/// The host DID is optional because an operator may not know it, and it names the
/// **recipient** of the document — nothing more. It used to be passed as the presentation's
/// `audience` as well, on the reading that this bound the presentation to one host. It never
/// could: see [`present`]. A presentation is bound to whoever will sign the request, always,
/// so there is no unbound case for an operator to be warned about.
pub struct RoomTarget<'a> {
    pub host_url: &'a str,
    pub host_did: Option<&'a str>,
    pub room_id: &'a str,
}

impl RoomTarget<'_> {
    fn client(&self) -> VtcClient {
        // The room surface carries no token — a room operation is authorized by
        // the presentation, never by a session with the host — so an anonymous
        // client is the correct one even when the host is a VTC the operator
        // also has an account on.
        VtcClient::anonymous(self.host_url, self.host_did.unwrap_or("did:key:zHost"))
    }
}

/// Mint a presentation for one action.
///
/// # There is no party to name here, and there used to be two
///
/// This passed `target.host_did` as the presentation's `audience` until that was found
/// never to work: `audience` named the party that had to *present* the credential, not the
/// one it was addressed to, so filling it with a host's DID named somebody no presenter can
/// ever be, and every request was refused. Omitting `--host-did` "worked" only because an
/// absent audience skipped the check — so the flag's two states were *broken* and
/// *unprotected*, with nothing in between.
///
/// Neither the field nor this parameter survives. A presentation is granted to the caller
/// the VTA authenticated and a host refuses a chain granting to anyone else, so who may
/// present is established rather than declared; and it is bound to a *room* rather than a
/// host, so there is no destination to name either. `--host-did` keeps its real job:
/// naming the document's `recipient`.
///
/// See `rooms/keys/present/0.2`, which removed both members, and
/// trustoverip/dtgwg-trust-tasks-tf#414.
async fn present(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    action: &str,
) -> Result<RoomSession, Box<dyn std::error::Error>> {
    let minted = client.room_present(target.room_id, action).await?;
    session_from_minted(target.room_id, &minted)
}

/// Rebuild the session from what the VTA minted.
///
/// The VTA answers with the presentation the host expects, so it is read back
/// rather than reassembled from parts — a second assembly is a second chance to
/// get the chain order wrong, and the order is load-bearing (leaf first).
///
/// Every missing member is an error rather than a default. A presentation with
/// no chain is not an empty presentation; it is a reply this client does not
/// understand, and proceeding would send the host something it will refuse for
/// reasons that read as a credential problem.
pub fn session_from_minted(
    room_id: &str,
    minted: &Value,
) -> Result<RoomSession, Box<dyn std::error::Error>> {
    let presentation = minted
        .get("presentation")
        .ok_or_else(|| format!("the VTA's reply carried no presentation: {minted}"))?;
    let membership = presentation
        .get("membership")
        .and_then(Value::as_str)
        .ok_or("the minted presentation carried no membership credential")?;
    let authority_values = presentation
        .get("authority")
        .and_then(Value::as_array)
        .ok_or("the minted presentation carried no authority chain")?;
    let authority: Vec<String> = authority_values
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    // A chain that lost links to a type mismatch is not a shorter chain — it is
    // a different grant, and a shorter one always confers less than the VTA
    // minted. Refuse rather than present it.
    if authority.len() != authority_values.len() {
        return Err("the minted authority chain contained a non-string link".into());
    }

    let mut session = RoomSession::new(room_id, membership, authority)?;
    if let Some(binding) = presentation.get("subjectBinding").and_then(Value::as_str) {
        session = session.with_subject_binding(binding);
    }
    Ok(session)
}

/// Send one room request to the host **as the member**: built here without presentation
/// or proof, completed by the VTA with `rooms/keys/act/0.10`, sent unchanged. Returns the
/// member the VTA acted as and the host's response payload.
///
/// Nothing this client holds goes to the host: not its DID, not its key.
async fn act_and_send(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    type_uri: &str,
    payload: Value,
) -> Result<(String, Value), Box<dyn std::error::Error>> {
    act_and_send_as(client, target, type_uri, payload, None).await
}

/// [`act_and_send`], naming the member to act as — required for a document that names
/// no room (a download chunk, a direct upload's commit or abort), whose authority is
/// the transfer the member's own request opened.
#[allow(deprecated)] // act/0.10, seal/0.2 and get/0.2 are what this CLI sends until it moves (trust-tasks-tf #1027)
async fn act_and_send_as(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    type_uri: &str,
    payload: Value,
    issuer: Option<&str>,
) -> Result<(String, Value), Box<dyn std::error::Error>> {
    let host_did = target.host_did.unwrap_or("did:key:zHost");
    let document = vta_sdk::client::unsigned_room_request(type_uri, host_did, issuer, payload)?;
    let completed = client.room_act(&document).await.map_err(act_refusal)?;
    let principal = completed.principal.to_string();
    let document = serde_json::to_value(&completed.document)?;
    let reply = target.client().send_signed_room_document(&document).await?;
    Ok((principal, reply))
}

/// Send `newest` (a type `rooms/keys/act/0.11` completes) as the member, falling back to
/// `older` through [`act_and_send`] (`rooms/keys/act/0.10`) when the VTA does not serve
/// act/0.11 or the host answers the newer type `unsupportedType`. With no `older` — a
/// request using what only the newer type carries — either is an error that says which
/// party to upgrade. Returns the member, the host's response payload, and whether the
/// newer type was the one answered.
#[allow(deprecated)] // act/0.11: still served and sent; 0.12 adds only rooms/watch
async fn act_and_send_newest(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    newest: (&str, Value),
    older: Option<(&str, Value)>,
) -> Result<(String, Value, bool), Box<dyn std::error::Error>> {
    let (new_type, new_payload) = newest;
    let host_did = target.host_did.unwrap_or("did:key:zHost");
    let document =
        vta_sdk::client::unsigned_room_request_v0_11(new_type, host_did, None, new_payload)?;
    let fall_back = |why: String| -> Result<(&str, Value), Box<dyn std::error::Error>> {
        older.clone().ok_or_else(|| why.into())
    };
    let (old_type, old_payload) = match client.room_act_v0_11(&document).await {
        Ok(completed) => {
            let principal = completed.principal.to_string();
            let document = serde_json::to_value(&completed.document)?;
            match target.client().send_signed_room_document(&document).await {
                Ok(reply) => return Ok((principal, reply, true)),
                Err(e)
                    if vtc_client::git_ns::task_error(&e)
                        .is_some_and(|(code, _)| code == "unsupportedType") =>
                {
                    fall_back(format!(
                        "the room's host does not serve `{new_type}`, which this record needs: \
                         it predates it. Write the record without the members only that \
                         version carries, or ask the host's operator to upgrade."
                    ))?
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(VtaError::UnsupportedTaskType { .. }) => fall_back(format!(
            "your VTA does not serve `rooms/keys/act/0.11`, which completes `{new_type}`: \
             upgrade it, or write the record without the members only that version carries."
        ))?,
        Err(e) => return Err(act_refusal(e).into()),
    };
    let (principal, reply) = act_and_send(client, target, old_type, old_payload).await?;
    Ok((principal, reply, false))
}

/// A `rooms/keys/act` refusal, with what the operator can do about it.
fn act_refusal(e: VtaError) -> String {
    let text = e.to_string();
    let hint = if text.contains("principalAmbiguous") {
        "\n\nYou may act as more than one member of this room: act from the context of \
         the one you mean."
    } else if text.contains("notAMember") {
        "\n\nYour VTA holds no credential this room issued to a persona you may act as. \
         The owner issues them with `pnm rooms owner issue-membership` and \
         `issue-authority --store`."
    } else if text.contains("actionNotHeld") {
        "\n\nYour own credentials for this room do not confer that action."
    } else {
        ""
    };
    format!("{e}{hint}")
}

/// What kind of record this is and what it answers (`kind`, `inReplyTo`; trust-tasks-tf
/// #1027), as `rooms put` takes them. A writer uses either only where the room's profile
/// lists it in `recordMembers`, which [`writer_members`] checks before anything is sent.
#[derive(Debug, Clone, Default)]
pub struct RecordThread {
    /// `message`, `reaction`, `note`, … — an open lowerCamelCase set.
    pub kind: Option<String>,
    /// The record this one answers: `KEY`, or `KEY@VERSION` to answer what it said then.
    pub reply_to: Option<String>,
}

impl RecordThread {
    /// The members as a record body carries them, checked against the specification's
    /// shapes.
    pub fn members(&self) -> Result<serde_json::Map<String, Value>, String> {
        let mut m = serde_json::Map::new();
        if let Some(k) = &self.kind {
            m.insert("kind".into(), serde_json::json!(k));
        }
        if let Some(r) = &self.reply_to {
            let (key, version) = match r.rsplit_once('@') {
                Some((k, v)) => (
                    k,
                    Some(v.parse::<u64>().map_err(|_| {
                        format!("--reply-to {r}: the version after `@` is not a number")
                    })?),
                ),
                None => (r.as_str(), None),
            };
            let mut reference = serde_json::json!({ "key": key });
            if let Some(v) = version {
                reference["version"] = serde_json::json!(v);
            }
            m.insert("inReplyTo".into(), reference);
        }
        vti_rooms::record_members::check(&m)?;
        Ok(m)
    }
}

/// The members a new record carries beyond the base set: `wanted` (from [`RecordThread`]),
/// refused before anything is sent unless the room's profile lists each
/// ([`VtaClient::room_check_record_members`]'s rule), and `writtenAt`, now, wherever the
/// profile lists it. The profile is read through the VTA, which needs the host's DID; with
/// none, nothing beyond `wanted` is added and `wanted` must be empty.
async fn writer_members(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    wanted: serde_json::Map<String, Value>,
) -> Result<serde_json::Map<String, Value>, Box<dyn std::error::Error>> {
    let Some(host_did) = target.host_did else {
        if wanted.is_empty() {
            return Ok(wanted);
        }
        return Err(format!(
            "{} may be written only where the room's profile lists {}, and reading the \
             profile takes the host's DID: pass --host-did.",
            wanted.keys().cloned().collect::<Vec<_>>().join(" and "),
            if wanted.len() == 1 { "it" } else { "them" }
        )
        .into());
    };
    let (listed, unresolved) = match client
        .room_record_members(target.room_id, host_did, None)
        .await
    {
        Ok(l) => (l, None),
        Err(e) => (None, Some(e.to_string())),
    };
    if !wanted.is_empty() {
        vta_sdk::client::check_record_members(
            target.room_id,
            &Value::Object(wanted.clone()),
            listed.as_deref(),
            unresolved,
        )
        .map_err(|e| record_members_refused(e, target))?;
    }
    let mut out = wanted;
    if listed
        .as_ref()
        .is_some_and(|l| l.iter().any(|m| m == "writtenAt"))
    {
        out.insert(
            "writtenAt".into(),
            serde_json::json!(
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            ),
        );
    }
    Ok(out)
}

/// A record the room's profile does not permit, with the command that permits it.
fn record_members_refused(e: VtaError, target: &RoomTarget<'_>) -> Box<dyn std::error::Error> {
    let VtaError::RecordMembersNotPermitted {
        refused, listed, ..
    } = &e
    else {
        return e.into();
    };
    let mut all = listed.clone();
    for r in refused {
        if !all.contains(r) {
            all.push(r.clone());
        }
    }
    format!(
        "{e}\n\nNothing was written. A curator of the room permits them with:\n\n  \
         pnm rooms profile set --room {} --host-did {} --record-members {}\n\n\
         or write the record without --kind, --reply-to and --react.",
        target.room_id,
        target.host_did.unwrap_or("<host-did>"),
        all.join(",")
    )
    .into()
}

/// [`act_and_send`], with the response parsed into its wire type.
pub(crate) async fn act_and_send_parsed<T: serde::de::DeserializeOwned>(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    type_uri: &str,
    payload: Value,
) -> Result<T, Box<dyn std::error::Error>> {
    let (_, reply) = act_and_send(client, target, type_uri, payload).await?;
    parse_reply(type_uri, reply)
}

/// Parse a host's response payload into its wire type, naming the task when it does not fit.
fn parse_reply<T: serde::de::DeserializeOwned>(
    what: &str,
    value: Value,
) -> Result<T, Box<dyn std::error::Error>> {
    serde_json::from_value(value)
        .map_err(|e| format!("the host's {what} response is not one this client reads: {e}").into())
}

/// Resolve `--pin` / `--unpin` into the wire value.
///
/// Three states from two flags: pinned, unpinned, and **unchanged**. Absence has
/// to stay distinguishable from `false`, or a curation meaning to change only
/// the status would silently unpin the record on its way past.
pub fn pinned_from_flags(pin: bool, unpin: bool) -> Option<bool> {
    if pin {
        Some(true)
    } else if unpin {
        Some(false)
    } else {
        None
    }
}

/// The signer for the room-host leg: the operator's own DID and key.
///
/// A room request is signed by the party the presentation was minted *for*, and
/// the VTA minted it for the DID the CLI authenticates as. Signing with any
/// other key produces a presentation bound to somebody else, which the host
/// refuses — correctly, and confusingly, so the two are taken from one place.
pub struct RoomSigner<'a> {
    pub did: &'a str,
    pub key_multibase: &'a str,
}

/// Strip what could drive a terminal from text another member wrote: control characters,
/// escape sequences among them, except newline and tab.
fn inert(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

/// A fresh opaque record key. On a sealed tier a key MUST say nothing about the record.
fn opaque_key() -> String {
    let bytes: [u8; 16] = rand::random();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

/// The serialized string of a generated newtype (a digest, a transfer id).
fn wire_str<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn capitalised(word: &str) -> String {
    let mut chars = word.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// `text` on one line: every control character — line breaks and tabs included — replaced
/// with a space, so a description the community wrote cannot move the cursor, start a
/// line that looks like this client's own, or ring the terminal.
fn one_line(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

/// `value` as one shell word. The room DID comes from the community, so it is quoted
/// unless every character is one no POSIX shell or fish treats specially.
fn shell_word(value: &str) -> String {
    let plain = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ":/._%@+=,-".contains(c));
    if plain {
        value.to_string()
    } else {
        format!("'{}'", inert(value).replace('\'', r"'\''"))
    }
}

mod admin;
mod files;
mod memberships;
mod offers;
mod owner;
mod records;
#[cfg(test)]
mod test_support;
mod watch;

pub use admin::*;
pub use files::*;
pub use memberships::*;
pub use offers::*;
pub use owner::*;
pub use records::*;
pub use watch::*;
