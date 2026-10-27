//! `pnm rooms …` — a member's surface on a data room.
//!
//! # Two parties, two transports, and why that is the whole design
//!
//! Every command here talks to **two** services, and never confuses them:
//!
//! - the operator's **VTA**, over the client's existing session, to complete each
//!   host-bound request **as the member** ([`VtaClient::room_act`],
//!   `rooms/keys/act/0.3`), to seal a record body signed as the member
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
/// or proof, completed by the VTA with `rooms/keys/act/0.3`, sent unchanged. Returns the
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
async fn act_and_send_as(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    type_uri: &str,
    payload: Value,
    issuer: Option<&str>,
) -> Result<(String, Value), Box<dyn std::error::Error>> {
    let host_did = target.host_did.unwrap_or("did:key:zHost");
    let document = vta_sdk::client::unsigned_room_request(type_uri, host_did, issuer, payload)?;
    let completed = client.room_act(&document).await.map_err(|e| {
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
    })?;
    let principal = completed.principal.to_string();
    let document = serde_json::to_value(&completed.document)?;
    let reply = target.client().send_signed_room_document(&document).await?;
    Ok((principal, reply))
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

/// `rooms list` — the room's records, metadata only, read as the member.
pub async fn cmd_rooms_list(
    client: &VtaClient,
    target: RoomTarget<'_>,
    prefix: Option<&str>,
    since_version: Option<u64>,
    limit: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read the listing to its END, then let `limit` decide how much to PRINT.
    // A host pages, and absence of the cursor is the only end-of-listing signal
    // — taking the first page would print "3 record(s)" over a room holding
    // three hundred, which is the failure this whole member exists to prevent.
    let mut listing = list_page(client, &target, prefix, since_version, None).await?;
    let mut cursor = listing.cursor.clone();
    while let Some(c) = cursor {
        let next = list_page(client, &target, prefix, since_version, Some(&c)).await?;
        cursor = next.cursor.clone();
        listing.records.extend(next.records);
    }

    if crate::render::is_json_output() {
        crate::render::print_json(&listing.records)?;
        return Ok(());
    }
    if listing.records.is_empty() {
        println!(
            "No records{}.",
            prefix.map(|p| format!(" under `{p}`")).unwrap_or_default()
        );
        return Ok(());
    }

    let shown = limit.unwrap_or(usize::MAX).min(listing.records.len());
    if shown < listing.records.len() {
        println!(
            "{} record(s), showing {shown} — pass a larger --limit for the rest:",
            listing.records.len()
        );
    } else {
        println!("{} record(s):", listing.records.len());
    }
    for r in listing.records.iter().take(shown) {
        let key = r.get("key").and_then(Value::as_str).unwrap_or("?");
        let version = r.get("version").and_then(Value::as_u64).unwrap_or(0);
        let status = r.get("status").and_then(Value::as_str).unwrap_or("active");
        // On a sealed tier there is no title to show — that is the tier working,
        // not a gap, so say so rather than printing an empty column.
        let title = r
            .get("title")
            .or_else(|| r.get("cleartext").and_then(|c| c.get("title")))
            .and_then(Value::as_str)
            .map(inert)
            .unwrap_or_else(|| "(sealed)".to_string());
        println!("  {key}  v{version}  {status:<10} {title}");
    }
    Ok(())
}

/// One page of `rooms/records/list`, as the member.
async fn list_page(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    prefix: Option<&str>,
    since_version: Option<u64>,
    cursor: Option<&str>,
) -> Result<vti_rooms::wire::ListRecordsResponse, Box<dyn std::error::Error>> {
    let mut payload = serde_json::json!({ "roomId": target.room_id });
    if let Some(p) = prefix {
        payload["prefix"] = serde_json::json!(p);
    }
    if let Some(v) = since_version {
        payload["sinceVersion"] = serde_json::json!(v);
    }
    if let Some(c) = cursor {
        payload["cursor"] = serde_json::json!(c);
    }
    let (_, reply) = act_and_send(
        client,
        target,
        vti_rooms::wire::ROOMS_RECORDS_LIST_TYPE,
        payload,
    )
    .await?;
    parse_reply("rooms/records/list", reply)
}

/// `rooms get` — one record, read as the member and opened through the VTA when it is
/// sealed.
///
/// A sealed record is shown only after its body checks out: the author's signature, the
/// location it was signed for, and on `attributed` that the body's signer is the author the
/// host recorded ([`verify_record_body`]) — the persona, for a record a member's own client
/// wrote. One that fails is refused, never shown with a warning.
pub async fn cmd_rooms_get(
    client: &VtaClient,
    target: RoomTarget<'_>,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_, record) = act_and_send(
        client,
        &target,
        vti_rooms::wire::ROOMS_RECORDS_GET_V2_TYPE,
        serde_json::json!({ "roomId": target.room_id, "key": key }),
    )
    .await?;

    // An `open`-tier record arrives readable. A sealed one arrives as
    // ciphertext this process cannot decrypt, and must not try to: the group
    // key is the VTA's.
    if let Some(cleartext) = record.get("cleartext") {
        if crate::render::is_json_output() {
            crate::render::print_json(cleartext)?;
        } else {
            if let Some(title) = cleartext.get("title").and_then(Value::as_str) {
                println!("{}\n", inert(title));
            }
            println!(
                "{}",
                inert(cleartext.get("body").and_then(Value::as_str).unwrap_or(""))
            );
            // On this tier provenance is the writer's word as the host stored it, unsigned.
            if let Some(obj) = cleartext.as_object()
                && vti_rooms::provenance::carries_any(obj)
            {
                println!("\n{} (unsigned on an open room)", provenance_line(obj));
            }
        }
        return Ok(());
    }

    let sealed: SealedContent =
        serde_json::from_value(record.get("sealed").cloned().ok_or(
            "the record carried neither cleartext nor sealed content; it may be retracted",
        )?)
        .map_err(|e| format!("the host's sealed record is malformed: {e}"))?;
    let version = record
        .get("version")
        .and_then(Value::as_u64)
        .ok_or("the host's record carried no version")?;
    let author = record.get("author").and_then(Value::as_str);

    let body = open_and_verify(client, &target, key, version, &sealed, author).await?;
    let body = body.body();
    if crate::render::is_json_output() {
        crate::render::print_json(body)?;
        return Ok(());
    }
    if let Some(title) = &body.title {
        println!("{}\n", inert(title));
    }
    if let Some(text) = &body.body {
        println!("{}", inert(text));
    }
    if let Some(file) = &body.file {
        println!(
            "\nFile: {} ({} bytes). Fetch it with `pnm rooms file get {key}`.",
            inert(&file.name),
            file.size
        );
    }
    println!("\nWritten by {} at version {version}.", body.author);
    if let Ok(Value::Object(obj)) = serde_json::to_value(body) {
        println!("{}", provenance_line(&obj));
    }
    Ok(())
}

/// `rooms put` — write a record, as the member.
///
/// On an `open` room the record goes in the clear. On `attributed` and `private` it is a
/// [`SealedRecordBody`] naming the member as author, which the VTA signs **as the member**
/// and seals (`rooms/keys/seal/0.2`, `signAsPrincipal`), so the host never sees it and
/// every reader can check that the member wrote it.
pub async fn cmd_rooms_put(
    client: &VtaClient,
    target: RoomTarget<'_>,
    key: &str,
    title: Option<String>,
    body: String,
    expected_version: Option<u64>,
    provenance: RecordProvenance,
) -> Result<(), Box<dyn std::error::Error>> {
    let (sealed_tier, member) = room_tier(client, &target).await?;

    if !sealed_tier {
        if provenance.is_stated() {
            return Err(open_tier_provenance_refused(&target).into());
        }
        let mut payload = serde_json::json!({
            "roomId": target.room_id,
            "key": key,
            "cleartext": CleartextContent { title, body, ..Default::default() },
        });
        if let Some(v) = expected_version {
            payload["expectedVersion"] = serde_json::json!(v);
        }
        let (_, reply) = act_and_send(
            client,
            &target,
            vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE,
            payload,
        )
        .await?;
        let put: vti_rooms::wire::PutRecordResponse = parse_reply("rooms/records/put", reply)?;
        println!("Wrote {} at version {} as {member}", put.key, put.version);
        return Ok(());
    }

    let mut content = SealedRecordBody::new(
        RecordLocation {
            room_id: target.room_id,
            key,
            version: 1,
        },
        &member,
    );
    content.title = title;
    content.body = Some(body);
    provenance.apply(&mut content)?;
    let version = write_sealed(client, &target, content, expected_version).await?;
    println!("Wrote {key} at version {version}, sealed and signed by {member}");
    Ok(())
}

/// A record's provenance and expiry as `rooms put` takes them (`rooms/_shared/0.1`
/// `SealedRecordBody`, *Provenance* and *Expiry*; trust-tasks-tf #865).
///
/// Display and weighting for whoever reads the record, never authority. `basis` `None`
/// leaves it unstated; `pnm` passes `declared` when the operator names none, which is what
/// the specification asks of a client relaying what its member typed.
#[derive(Debug, Clone, Default)]
pub struct RecordProvenance {
    /// What kind of claim the record is.
    pub basis: Option<vtc_client::rooms::body::RecordBasis>,
    /// Whether `basis` was named by the operator rather than defaulted.
    pub basis_named: bool,
    /// The author's own estimate, 0 to 1.
    pub confidence: Option<f64>,
    /// Records of this room cited in support: `KEY`, or `KEY@VERSION` to pin what it said then.
    pub cite_records: Vec<String>,
    /// Credentials cited in support, by `id` — never fetched.
    pub cite_credentials: Vec<String>,
    /// Purposes the record may be used for, each an absolute IRI.
    pub purposes: Vec<String>,
    /// The permitted use in words.
    pub use_note: Option<String>,
    /// When the author stops standing behind the record, RFC 3339.
    pub valid_until: Option<String>,
}

impl RecordProvenance {
    /// Whether the operator stated anything — a defaulted `basis` is not a statement.
    pub fn is_stated(&self) -> bool {
        self.basis_named
            || self.confidence.is_some()
            || !self.cite_records.is_empty()
            || !self.cite_credentials.is_empty()
            || !self.purposes.is_empty()
            || self.use_note.is_some()
            || self.valid_until.is_some()
    }

    /// Put these members on `body`, checked against the specification's types before the
    /// VTA is asked to sign anything.
    pub fn apply(&self, body: &mut SealedRecordBody) -> Result<(), String> {
        body.basis = self.basis;
        body.confidence = self.confidence.map(|c| serde_json::json!(c));
        let mut evidence = Vec::new();
        for cite in &self.cite_records {
            let (key, version) = match cite.rsplit_once('@') {
                Some((k, v)) => (
                    k,
                    Some(v.parse::<u64>().map_err(|_| {
                        format!("--cite-record {cite}: the version after `@` is not a number")
                    })?),
                ),
                None => (cite.as_str(), None),
            };
            let mut e = serde_json::json!({ "kind": "record", "key": key });
            if let Some(v) = version {
                e["version"] = serde_json::json!(v);
            }
            evidence.push(e);
        }
        for id in &self.cite_credentials {
            evidence.push(serde_json::json!({ "kind": "credential", "credentialId": id }));
        }
        body.evidence = (!evidence.is_empty()).then_some(Value::Array(evidence));
        let mut valid_for = serde_json::Map::new();
        if !self.purposes.is_empty() {
            valid_for.insert("purposes".into(), serde_json::json!(self.purposes));
        }
        if let Some(note) = &self.use_note {
            valid_for.insert("note".into(), serde_json::json!(note));
        }
        body.valid_for = (!valid_for.is_empty()).then_some(Value::Object(valid_for));
        body.valid_until = self.valid_until.clone();
        if let Ok(Value::Object(obj)) = serde_json::to_value(&*body) {
            vti_rooms::provenance::check(&obj)?;
        }
        Ok(())
    }
}

/// Why `rooms put` will not state provenance on an `open` room, and what to do instead.
///
/// An open room carries provenance in `rooms/records/put/0.3`'s cleartext, and this client
/// writes as the member through `rooms/keys/act`, whose table (0.1 to 0.6) completes put only
/// at 0.1 and 0.2. Writing 0.3 any other way would record this client's key as the author.
fn open_tier_provenance_refused(target: &RoomTarget<'_>) -> String {
    format!(
        "room {} is `open`: a record's provenance there rides `rooms/records/put/0.3`, which \
         `rooms/keys/act` does not complete yet, so pnm cannot write it as your persona. Write \
         it without --basis, --confidence, --cite-record, --cite-credential, --purpose, \
         --use-note and --valid-until, or in a sealed (`attributed` or `private`) room, where \
         they travel inside the signed body.",
        target.room_id
    )
}

/// What a record says about the kind of claim it is, and whether it has lapsed — shown
/// beside its author (`SealedRecordBody`, *Provenance*: a reader shows `basis`, or says none
/// was stated). Never authority.
fn provenance_line(obj: &serde_json::Map<String, Value>) -> String {
    let mut line = match obj.get("basis").and_then(Value::as_str) {
        Some(b) => format!("Basis: {}", inert(b)),
        None => "Basis: not stated".to_string(),
    };
    if let Some(c) = obj.get("confidence").and_then(Value::as_f64) {
        line.push_str(&format!(" (author's confidence {c})"));
    }
    if obj.get("basis").and_then(Value::as_str) == Some("verified") && !obj.contains_key("evidence")
    {
        line.push_str(" — names no evidence, so the claim to have checked is unsupported");
    }
    if let Some(n) = obj.get("evidence").and_then(Value::as_array).map(Vec::len) {
        line.push_str(&format!("; cites {n} item(s), not fetched"));
    }
    if let Some(use_for) = obj.get("validFor") {
        let purposes = use_for
            .get("purposes")
            .and_then(Value::as_array)
            .map(|p| {
                p.iter()
                    .filter_map(Value::as_str)
                    .map(inert)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        let note = use_for
            .get("note")
            .and_then(Value::as_str)
            .map(|n| format!(" \"{}\"", inert(n)))
            .unwrap_or_default();
        line.push_str(&format!("\nFor use: {purposes}{note}"));
    }
    if let Some(until) = obj.get("validUntil").and_then(Value::as_str) {
        if vti_rooms::provenance::is_expired(obj, chrono::Utc::now()) {
            line.push_str(&format!(
                "\nEXPIRED: its author stopped standing behind it at {}.",
                inert(until)
            ));
        } else {
            line.push_str(&format!("\nValid until {}.", inert(until)));
        }
    }
    line
}

/// `rooms curate` — change a record's standing.
pub async fn cmd_rooms_curate(
    client: &VtaClient,
    target: RoomTarget<'_>,
    key: &str,
    status: Option<String>,
    pinned: Option<bool>,
    reason: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if status.is_none() && pinned.is_none() {
        return Err("nothing to change — pass --status and/or --pin/--unpin".into());
    }
    // `curate` is its own grant, deliberately not implied by `write`: deciding
    // what a room's shared knowledge is worth is a different act from adding to
    // it. So the request is completed for `curate`, and a member who only
    // writes is refused by their own VTA rather than at the host.
    let mut payload = serde_json::json!({ "roomId": target.room_id, "key": key });
    if let Some(s) = status {
        payload["status"] = serde_json::json!(s);
    }
    if let Some(p) = pinned {
        payload["pinned"] = serde_json::json!(p);
    }
    if let Some(r) = reason {
        payload["reason"] = serde_json::json!(r);
    }
    let (_, reply) = act_and_send(
        client,
        &target,
        vti_rooms::wire::ROOMS_RECORDS_CURATE_TYPE,
        payload,
    )
    .await?;
    let out: vti_rooms::wire::CurateRecordResponse = parse_reply("rooms/records/curate", reply)?;
    println!(
        "{} is now {} at version {}{}",
        out.key,
        serde_json::to_value(out.status)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "?".into()),
        out.version,
        if out.pinned { " (pinned)" } else { "" }
    );
    Ok(())
}

/// `rooms renew` — mint the next epoch, which is what keeps an **open** room live.
///
/// Needs `admin`. It is the same act as ordinary use, and it is the whole
/// defence against a hostile succession claim: an owner who renews is
/// structurally safe without thinking about it.
///
/// Refuses an `attributed` or `private` room ([`refuse_sealed_renew`]): there the room's
/// epoch is its MLS group's plus one, and a mint without a commit moves the host and no
/// member — every write is then refused as sealed under a superseded epoch.
pub async fn cmd_rooms_renew(
    client: &VtaClient,
    target: RoomTarget<'_>,
    signer: RoomSigner<'_>,
    epoch: u32,
    reason: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // The tier first, under `read`, before anything is minted: rooms/keys/act/0.2
    // producer item 4 — a client never asks to mint a sealed room's epoch.
    let read = present(client, &target, "read").await?;
    let info = target
        .client()
        .room_info(&read, signer.did, signer.key_multibase)
        .await
        .map_err(|e| format!("could not read the room's tier (rooms/info): {e}"))?;
    refuse_sealed_renew(&wire_str(&info.visibility), &target)?;

    let session = present(client, &target, "admin").await?;
    let minted = target
        .client()
        .mint_epoch(
            &session,
            epoch,
            reason.as_deref(),
            signer.did,
            signer.key_multibase,
        )
        .await?;
    println!("Room {} is at epoch {}", minted.room_id, minted.epoch);
    Ok(())
}

/// `pnm rooms renew` is an open room's renewal only. A sealed room (`attributed` or
/// `private`) renews through the owner's key holder, which advances the group with a commit
/// and the host with it (`rooms/owner/group/renew/0.2`); a bare mint would brick the room
/// for writing while looking like success.
fn refuse_sealed_renew(visibility: &str, target: &RoomTarget<'_>) -> Result<(), String> {
    if visibility == "open" {
        return Ok(());
    }
    Err(format!(
        "room {room} is `{visibility}`: its epoch advances only with a commit of its group, \
         which this client cannot make, and a bare mint would leave every member unable to \
         write. Renew it from the owner's VTA instead:\n\n  pnm rooms owner group-renew \
         --room {room} --host-did {host_did}",
        room = target.room_id,
        host_did = target.host_did.unwrap_or("<the host's DID>"),
    ))
}

/// `rooms prune` — drop the room's epoch key chain below an epoch (`rooms/epoch/prune/0.2`).
///
/// Needs `admin`, and moves the way `renew` does: the VTA presents for this client
/// (`rooms/keys/present`) and this client signs. Not through `rooms/keys/act`, whose every
/// version leaves the prune out on purpose — destroying a room's ability to read its past
/// "warrants a task of its own that states its consequences" rather than riding a
/// signature asked for one operation at a time.
///
/// The specification asks a surface offering this to show what becomes unreadable and not
/// to offer it as an incidental control, so this reads the room first (its current epoch
/// and retention policy, under `read`), prints [`prune_warning`], and goes ahead only on
/// `--yes` or a typed `y` at a terminal. Without a terminal and without `--yes` it refuses:
/// a pipe is not consent.
pub async fn cmd_rooms_prune(
    client: &VtaClient,
    target: RoomTarget<'_>,
    signer: RoomSigner<'_>,
    before_epoch: u32,
    reason: String,
    assume_yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let read = present(client, &target, "read").await?;
    let info = target
        .client()
        .room_info(&read, signer.did, signer.key_multibase)
        .await
        .map_err(|e| format!("could not read the room's epoch (rooms/info): {e}"))?;
    let current = u32::try_from(info.epoch.get()).unwrap_or(u32::MAX);
    if before_epoch >= current {
        return Err(not_ahead_message(&target, before_epoch, current).into());
    }
    let policy = info.retention_policy.as_ref().map(wire_str);

    eprintln!(
        "{}",
        prune_warning(target.room_id, before_epoch, current, policy.as_deref())
    );
    match prune_guard(
        assume_yes,
        std::io::IsTerminal::is_terminal(&std::io::stdin()),
    ) {
        PruneGuard::Proceed => {}
        PruneGuard::Refuse => {
            return Err(format!(
                "refusing to prune without confirmation: there is no terminal to ask. If you \
                 mean it, run it again with --yes:\n\n  {}",
                prune_command(&target, before_epoch, &reason)
            )
            .into());
        }
        PruneGuard::Ask => {
            if !super::contexts::confirm_destructive("Prune the chain?")? {
                println!("Not pruned.");
                return Ok(());
            }
        }
    }

    // `rooms/epoch/prune/0.2`: the host keeps the room's epoch floor and says so, and
    // members' key holders forget what they hold below it.
    let session = present(client, &target, "admin").await?;
    let pruned = target
        .client()
        .prune_epoch_v2(
            &session,
            before_epoch,
            Some(&reason),
            signer.did,
            signer.key_multibase,
        )
        .await
        .map_err(|e| prune_refused(e, &target, before_epoch, current))?;
    let floor = pruned.epoch_floor.0.get();
    let outcome = vtc_client::rooms::PruneResponse {
        room_id: pruned.room_id.to_string(),
        pruned: u32::try_from(pruned.pruned).unwrap_or(u32::MAX),
        earliest_rung: u32::try_from(pruned.earliest_rung.get()).unwrap_or(u32::MAX),
    };
    println!(
        "{} The room's epoch floor is now {floor}: members' VTAs that learn it forget \
         what they hold below it.",
        prune_outcome(&outcome)
    );
    Ok(())
}

/// What `prune` does about confirmation: `--yes` always proceeds; without it a terminal is
/// asked and anything else is refused.
#[derive(Debug, PartialEq, Eq)]
enum PruneGuard {
    Proceed,
    Ask,
    Refuse,
}

fn prune_guard(assume_yes: bool, interactive: bool) -> PruneGuard {
    match (assume_yes, interactive) {
        (true, _) => PruneGuard::Proceed,
        (false, true) => PruneGuard::Ask,
        (false, false) => PruneGuard::Refuse,
    }
}

/// The irreversibility warning (rooms/epoch/prune/0.2 *Consent/purpose*: show what will
/// become unreadable), in the specification's own terms — the rungs go, not the records.
fn prune_warning(room_id: &str, before_epoch: u32, current: u32, policy: Option<&str>) -> String {
    // The off-by-one `rooms/epoch/prune/0.2` states: rung `N = beforeEpoch` survives and
    // still yields epoch `N − 1`, so the floor is `N − 1` and what becomes unreadable is
    // everything *below* it.
    let floor = before_epoch.saturating_sub(1).max(1);
    let span = if floor <= 1 {
        "no epoch: rung 2 survives and still yields epoch 1, so nothing becomes unreadable"
            .to_string()
    } else if floor == 2 {
        "epoch 1".to_string()
    } else {
        format!("epochs 1 to {}", floor - 1)
    };
    let policy_line = match policy {
        Some("fromJoin") => {
            "\n  This room's retention policy is `fromJoin`: it keeps no chain, so there may be \
             nothing to drop."
        }
        _ => "",
    };
    format!(
        "WARNING: this cannot be undone.\n\n\
         Pruning room {room_id} (now at epoch {current}) below epoch {before_epoch} makes \
         {span} unreadable for good:\n\
         \n  - The host erases the epoch key chain below epoch {before_epoch}. Nobody keeps a \
         copy that can bring it back.\n\
         \n  - The records stay, and the host still serves them. What goes is the ability to \
         derive the keys they were sealed under: a member who restarts, moves to a new \
         device, or joins later can never open them again, whatever authority they hold.\n\
         \n  - It reaches members, as far as they conform: the host keeps the room's epoch \
         floor ({floor}), and members' VTAs that learn it forget the rungs and keys they \
         hold below it and never take them back. It is not a recall: anything already \
         read, decrypted or exported stays where it is, and a VTA that does not conform \
         keeps what it held.{policy_line}\n\
         \n  Pruning straight after a membership change tells the host why the change \
         happened; wait if that matters."
    )
}

/// `notAhead`, said before anything is sent, with the floor that would work.
fn not_ahead_message(target: &RoomTarget<'_>, before_epoch: u32, current: u32) -> String {
    let mut msg = format!(
        "--before-epoch {before_epoch} is at or above room {}'s current epoch {current}: \
         pruning there would drop the whole chain, not shorten it.",
        target.room_id
    );
    if current > 1 {
        msg.push_str(&format!(
            " The highest floor that keeps the current epoch readable is {}:\n\n  {}",
            current - 1,
            prune_command(target, current - 1, "<why>")
        ));
    }
    msg
}

/// The corrected command, verbatim, for an operator to run.
fn prune_command(target: &RoomTarget<'_>, before_epoch: u32, reason: &str) -> String {
    let host_did = target
        .host_did
        .map(|d| format!(" --host-did {d}"))
        .unwrap_or_default();
    format!(
        "pnm rooms prune --room {} --host {}{host_did} --before-epoch {before_epoch} \
         --reason {} --yes",
        target.room_id,
        target.host_url,
        shell_word(reason)
    )
}

/// A host's refusal, with the fix where the code names one.
fn prune_refused(
    e: vtc_client::VtcError,
    target: &RoomTarget<'_>,
    before_epoch: u32,
    current: u32,
) -> String {
    let code = vtc_client::git_ns::task_error(&e).map(|(code, _)| code);
    match code.as_deref() {
        Some(c) if c.ends_with("notAhead") => {
            // The room advanced between the read and the prune.
            format!(
                "{e}\n\n{}",
                not_ahead_message(target, before_epoch, current)
            )
        }
        Some(c) if c.ends_with("permissionDenied") => format!(
            "{e}\n\nPruning needs `admin` in the room — not `curate`, which every writer holds. \
             The room's owner grants it with `pnm rooms owner issue-authority --action admin \
             --store`."
        ),
        _ => e.to_string(),
    }
}

/// The host's answer, read the way the specification says to: `pruned: 0` is a success,
/// and `earliestRung` is how far back the chain reaches, not the floor asked for.
fn prune_outcome(r: &vtc_client::rooms::PruneResponse) -> String {
    let dropped = match r.pruned {
        0 => "nothing to drop — the chain already reached back no further".to_string(),
        1 => "1 rung dropped".to_string(),
        n => format!("{n} rungs dropped"),
    };
    format!(
        "Pruned room {}: {dropped}. Its chain now reaches back to epoch {}.",
        r.room_id, r.earliest_rung
    )
}

/// `rooms records prune` — remove the records the room's record retention makes eligible
/// (`rooms/records/prune/0.1`, trust-tasks-tf #868).
///
/// Needs `admin` and moves the way `prune` does: the VTA presents for this client and this
/// client signs (`rooms/keys/act` completes neither task). The specification asks a surface
/// to show a dry run first and not to offer a prune beside reversible controls, so this
/// always asks the host what would go, prints it with what a prune does and does not do, and
/// goes ahead only on `--yes` or a typed `y` at a terminal.
#[allow(clippy::too_many_arguments)]
pub async fn cmd_rooms_records_prune(
    client: &VtaClient,
    target: RoomTarget<'_>,
    signer: RoomSigner<'_>,
    kinds: Vec<String>,
    reason: String,
    dry_run: bool,
    assume_yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let kinds = if kinds.is_empty() {
        vec!["retracted".to_string(), "aged".to_string()]
    } else {
        kinds
    };
    if let Some(bad) = kinds.iter().find(|k| *k != "retracted" && *k != "aged") {
        return Err(format!("--kind {bad}: a kind is `retracted` or `aged`").into());
    }
    let kinds: Vec<&str> = kinds.iter().map(String::as_str).collect();
    let session = present(client, &target, "admin").await?;
    let host = target.client();
    let preview = host
        .prune_records(
            &session,
            &kinds,
            &reason,
            true,
            signer.did,
            signer.key_multibase,
        )
        .await
        .map_err(|e| records_prune_refused(e, &target))?;
    let preview = serde_json::to_value(&preview)?;
    eprintln!("{}", records_prune_preview(target.room_id, &preview));
    if dry_run {
        if crate::render::is_json_output() {
            crate::render::print_json(&preview)?;
        }
        return Ok(());
    }
    if preview["removed"].as_u64() == Some(0) {
        println!("Nothing is eligible now; nothing pruned.");
        return Ok(());
    }
    match prune_guard(
        assume_yes,
        std::io::IsTerminal::is_terminal(&std::io::stdin()),
    ) {
        PruneGuard::Proceed => {}
        PruneGuard::Refuse => {
            return Err(format!(
                "refusing to prune without confirmation: there is no terminal to ask. If you \
                 mean it, run it again with --yes:\n\n  {}",
                records_prune_command(&target, &kinds, &reason)
            )
            .into());
        }
        PruneGuard::Ask => {
            if !super::contexts::confirm_destructive("Remove these records for good?")? {
                println!("Not pruned.");
                return Ok(());
            }
        }
    }
    // A fresh presentation: eligibility is decided again, at the moment of the prune.
    let session = present(client, &target, "admin").await?;
    let done = host
        .prune_records(
            &session,
            &kinds,
            &reason,
            false,
            signer.did,
            signer.key_multibase,
        )
        .await
        .map_err(|e| records_prune_refused(e, &target))?;
    let done = serde_json::to_value(&done)?;
    if crate::render::is_json_output() {
        crate::render::print_json(&done)?;
        return Ok(());
    }
    let removed = done["removed"].as_u64().unwrap_or(0);
    match done.get("prune") {
        Some(mark) => println!(
            "Pruned room {}: {removed} record(s) removed at version {}. Members syncing from \
             below it rebuild their copy.",
            target.room_id, mark["version"]
        ),
        None => println!(
            "Nothing was eligible by the time of the prune; nothing removed in room {}.",
            target.room_id
        ),
    }
    Ok(())
}

/// What a dry run says, and what a prune is — in the specification's terms: records go
/// outright, tombstones included; nothing already read is recalled.
fn records_prune_preview(room_id: &str, preview: &Value) -> String {
    let removed = preview["removed"].as_u64().unwrap_or(0);
    let blobs = preview["blobsReleased"].as_u64().unwrap_or(0);
    let rule = &preview["recordRetention"];
    let mut rule_text = Vec::new();
    if let Some(d) = rule["tombstoneDays"].as_u64() {
        rule_text.push(format!("tombstones kept {d} days"));
    }
    if let Some(d) = rule["recordDays"].as_u64() {
        rule_text.push(format!("records kept {d} days unless pinned"));
    }
    format!(
        "Room {room_id} keeps its records by this rule: {}.\n\
         Under it, a prune now removes {removed} record(s){}.\n\n\
         WARNING: a prune cannot be undone. Removed records go outright — tombstones \
         included — for every member, and the room keeps only a count and a time. It removes \
         them from this host, not from the world: what a member already read, exported or \
         cached stays where it is, and a mirror is pruned separately.",
        rule_text.join(", "),
        if blobs > 0 {
            format!(", releasing {blobs} file(s)")
        } else {
            String::new()
        }
    )
}

/// The corrected command, verbatim.
fn records_prune_command(target: &RoomTarget<'_>, kinds: &[&str], reason: &str) -> String {
    let host_did = target
        .host_did
        .map(|d| format!(" --host-did {d}"))
        .unwrap_or_default();
    let kinds: String = kinds.iter().map(|k| format!(" --kind {k}")).collect();
    format!(
        "pnm rooms records prune --room {} --host {}{host_did}{kinds} --reason {} --yes",
        target.room_id,
        target.host_url,
        shell_word(reason)
    )
}

/// A host's refusal of a records prune, with the fix where the code names one.
fn records_prune_refused(e: vtc_client::VtcError, target: &RoomTarget<'_>) -> String {
    let code = vtc_client::git_ns::task_error(&e).map(|(code, _)| code);
    let host_did = target
        .host_did
        .map(|d| format!(" --host-did {d}"))
        .unwrap_or_default();
    match code.as_deref() {
        Some(c) if c.ends_with("noRetention") => format!(
            "{e}\n\nThe room states no record retention for what you asked, so nothing is \
             eligible. Set one first, for example:\n\n  pnm rooms records retention set \
             --room {} --host {}{host_did} --tombstone-days 30 --reason <why>",
            target.room_id, target.host_url
        ),
        Some(c) if c.ends_with("roomNotLive") => {
            format!("{e}\n\nThe room has lapsed and is read-only until its owner renews it.")
        }
        Some(c) if c.ends_with("permissionDenied") => format!(
            "{e}\n\nPruning records needs `admin` in the room — not `curate`, which every \
             writer holds. The room's owner grants it with `pnm rooms owner issue-authority \
             --action admin --store`."
        ),
        _ => e.to_string(),
    }
}

/// `rooms records retention show` — the record retention in force and the latest prune
/// (`rooms/info/0.2`).
pub async fn cmd_rooms_retention_show(
    client: &VtaClient,
    target: RoomTarget<'_>,
    signer: RoomSigner<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let info = read_info_v2(client, &target, &signer).await?;
    if crate::render::is_json_output() {
        crate::render::print_json(&serde_json::json!({
            "recordRetention": info.get("recordRetention"),
            "lastPrune": info.get("lastPrune"),
        }))?;
        return Ok(());
    }
    println!("{}", retention_lines(&info));
    Ok(())
}

/// `rooms records retention set` — replace the record retention whole, on the condition
/// that the one in force is the one this client just read (`expectedRetention`), so two
/// administrators do not overwrite each other unseen.
#[allow(clippy::too_many_arguments)]
pub async fn cmd_rooms_retention_set(
    client: &VtaClient,
    target: RoomTarget<'_>,
    signer: RoomSigner<'_>,
    tombstone_days: Option<u32>,
    record_days: Option<u32>,
    clear: bool,
    reason: String,
) -> Result<(), Box<dyn std::error::Error>> {
    if !clear && tombstone_days.is_none() && record_days.is_none() {
        return Err(
            "name --tombstone-days, --record-days, or --clear: the retention is \
                    replaced whole, so naming nothing would clear it by accident"
                .into(),
        );
    }
    let info = read_info_v2(client, &target, &signer).await?;
    let expected = info
        .get("recordRetention")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let mut retention = serde_json::Map::new();
    if let Some(d) = tombstone_days {
        retention.insert("tombstoneDays".into(), serde_json::json!(d));
    }
    if let Some(d) = record_days {
        retention.insert("recordDays".into(), serde_json::json!(d));
    }
    let session = present(client, &target, "admin").await?;
    let set = target
        .client()
        .set_record_retention(
            &session,
            Value::Object(retention),
            Some(expected),
            &reason,
            signer.did,
            signer.key_multibase,
        )
        .await
        .map_err(|e| {
            let code = vtc_client::git_ns::task_error(&e).map(|(code, _)| code);
            match code.as_deref() {
                Some(c) if c.ends_with("retentionConflict") => format!(
                    "{e}\n\nAnother administrator changed the retention since this command \
                     read it. Read it again (`pnm rooms records retention show --room {} \
                     --host {}`) and decide again.",
                    target.room_id, target.host_url
                ),
                _ => e.to_string(),
            }
        })?;
    let set = serde_json::to_value(&set)?;
    if crate::render::is_json_output() {
        crate::render::print_json(&set)?;
        return Ok(());
    }
    println!(
        "Room {} record retention: {} (was {}). Nothing is removed until somebody prunes.",
        target.room_id,
        retention_text(&set["recordRetention"]),
        retention_text(&set["previous"])
    );
    Ok(())
}

/// `rooms/info/0.2` as JSON, read under `read`.
async fn read_info_v2(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    signer: &RoomSigner<'_>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let read = present(client, target, "read").await?;
    let info = target
        .client()
        .room_info_v2(&read, signer.did, signer.key_multibase)
        .await
        .map_err(|e| format!("could not read the room (rooms/info/0.2): {e}"))?;
    Ok(serde_json::to_value(&info)?)
}

/// A record retention in words; `{}` or absent is "none".
fn retention_text(rule: &Value) -> String {
    let mut parts = Vec::new();
    if let Some(d) = rule.get("tombstoneDays").and_then(Value::as_u64) {
        parts.push(format!("tombstones {d} days"));
    }
    if let Some(d) = rule.get("recordDays").and_then(Value::as_u64) {
        parts.push(format!("records {d} days (pinned excepted)"));
    }
    if parts.is_empty() {
        "none — no record is eligible by age".to_string()
    } else {
        parts.join(", ")
    }
}

/// The retention and latest prune `rooms/info/0.2` reports, as lines.
fn retention_lines(info: &Value) -> String {
    let rule = info.get("recordRetention").cloned().unwrap_or(Value::Null);
    let mut out = format!("Record retention: {}", retention_text(&rule));
    match info.get("lastPrune") {
        Some(p) => out.push_str(&format!(
            "\nLast prune: {} record(s) at {}, version {}",
            p["removed"],
            p["at"].as_str().unwrap_or("?"),
            p["version"]
        )),
        None => out.push_str("\nLast prune: never"),
    }
    out
}

/// `rooms create` — register a room with a host.
///
/// The only command here that needs no presentation: the room has issued
/// nothing yet, so there is no chain to present. The host checks the request's
/// own proof instead, which is why this must be signed as the owner it names.
pub async fn cmd_rooms_create(
    target: RoomTarget<'_>,
    signer: RoomSigner<'_>,
    visibility: &str,
    retention_days: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let visibility: Visibility = serde_json::from_value(Value::String(visibility.to_string()))
        .map_err(|_| "visibility must be one of: open, attributed, private")?;

    target
        .client()
        .create_room(
            target.room_id,
            signer.did,
            visibility,
            retention_days,
            signer.did,
            signer.key_multibase,
        )
        .await
        .map_err(|e| {
            format!(
                "{e}\n\nA community host decides whose rooms it stores. If this says \
                 `not-a-member`, you are not a member there; if it says \
                 `private-tier-not-enabled`, that community has not turned the tier on."
            )
        })?;
    println!("Registered {} as {}", target.room_id, signer.did);
    println!(
        "  Next: the room must issue you a membership and an authority credential before \
         you can act in it."
    );
    Ok(())
}

// ─── Files ───────────────────────────────────────────────────────────────
//
// Sealing and opening a room file locally, with one file's key from the VTA
// (`rooms/keys/file-key/0.2`). The bytes never pass through the VTA; what the
// VTA releases opens this one file and nothing else.
//
// What is written is the upload's whole input and nothing more: the sealed
// chunks, the blob manifest a host checks, and the file manifest that belongs
// inside the sealed record body. Uploading them is `rooms/blobs/upload/*` and
// a record put naming the blob.

/// The blob manifest beside the chunks.
const BLOB_MANIFEST: &str = "blob.json";
/// The file manifest — the sealed record body's `file` member.
const FILE_MANIFEST: &str = "file.json";
/// The sealed chunks, in index order.
const CHUNKS_DIR: &str = "chunks";

fn chunk_path(dir: &std::path::Path, index: usize) -> std::path::PathBuf {
    dir.join(CHUNKS_DIR).join(format!("{index:06}.bin"))
}

fn file_key_bytes(
    resp: &trust_tasks_rs::specs::rooms::keys::file_key::v0_2::Response,
) -> Result<vti_rooms::files::FileKey, Box<dyn std::error::Error>> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(resp.key.as_str())?;
    bytes
        .try_into()
        .map_err(|_| "the VTA returned a file key that is not 32 bytes".into())
}

/// `rooms file seal` — seal a local file for a room, ready to upload.
pub async fn cmd_rooms_file_seal(
    client: &VtaClient,
    room_id: &str,
    path: &std::path::Path,
    out: &std::path::Path,
    padme: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use vti_rooms::files::{self, FileBinding, Padding};

    if out.exists() {
        return Err(format!("{} already exists; choose a new directory", out.display()).into());
    }
    let plaintext = std::fs::read(path)?;
    // The name is the uploader's and is sealed: only members see it.
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("the file has no usable name")?;

    // A fresh id for every file: the segment nonces are counters, so two files
    // under one key would reuse them.
    let file_id = files::new_file_id();
    let resp = client
        .room_file_key(room_id, &files::encode_file_id(&file_id), None)
        .await?;
    let key = file_key_bytes(&resp)?;
    let sealed = files::seal_file(
        &key,
        FileBinding {
            room_id: room_id.to_string(),
            file_id,
            epoch: resp.epoch.get(),
            segment_size: files::DEFAULT_SEGMENT_SIZE,
        },
        name,
        None,
        &plaintext,
        if padme { Padding::Padme } else { Padding::None },
    )?;
    std::fs::create_dir_all(out.join(CHUNKS_DIR))?;
    for (i, chunk) in sealed.chunks.iter().enumerate() {
        std::fs::write(chunk_path(out, i), chunk)?;
    }
    std::fs::write(
        out.join(BLOB_MANIFEST),
        serde_json::to_vec_pretty(&sealed.blob)?,
    )?;
    std::fs::write(
        out.join(FILE_MANIFEST),
        serde_json::to_vec_pretty(&sealed.file)?,
    )?;
    println!(
        "Sealed {} ({} bytes) under epoch {} into {}\n  blobRef  {}\n  chunks   {} of {} bytes",
        name,
        sealed.file.size,
        sealed.file.epoch,
        out.display(),
        sealed.file.blob_ref,
        sealed.blob.chunks.chunk_count,
        sealed.blob.chunks.chunk_size,
    );
    println!(
        "  {FILE_MANIFEST} goes inside the sealed record body; it names the file and is never \
         sent to the host in the clear."
    );
    Ok(())
}

/// `rooms file open` — open a sealed file directory, refusing one that is not
/// the file its author signed.
pub async fn cmd_rooms_file_open(
    client: &VtaClient,
    room_id: &str,
    dir: &std::path::Path,
    out: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use vti_rooms::files::{self, BlobManifest, FileManifest};

    if out.exists() {
        return Err(format!("{} already exists; refusing to overwrite it", out.display()).into());
    }
    let file: FileManifest = serde_json::from_slice(&std::fs::read(dir.join(FILE_MANIFEST))?)?;
    let blob: BlobManifest = serde_json::from_slice(&std::fs::read(dir.join(BLOB_MANIFEST))?)?;
    // The file manifest is the author's; the blob manifest is whoever served it.
    // Before a byte is trusted: it is the blob the author named, and its chunk size
    // and count are the ones the author's segment size and length give.
    file.check_blob(&blob)?;
    let mut chunks = Vec::with_capacity(blob.chunks.chunk_count as usize);
    for (i, expected) in blob.chunks.chunk_digests.iter().enumerate() {
        let chunk = std::fs::read(chunk_path(dir, i))?;
        if !files::same_digest(&files::digest_multibase(&chunk), expected) {
            return Err(format!("chunk {i} does not match the manifest").into());
        }
        chunks.push(chunk);
    }

    let resp = client
        .room_file_key(room_id, &file.file_id, Some(file.epoch))
        .await?;
    let key = file_key_bytes(&resp)?;
    let plaintext = files::open_file(&key, room_id, &file, &blob, &chunks)?;

    // Written beside the target and moved into place, so a failure leaves nothing that
    // looks like the file.
    let tmp = out.with_extension("partial");
    std::fs::write(&tmp, &plaintext)?;
    std::fs::rename(&tmp, out)?;
    println!(
        "Opened {} ({} bytes) into {} — the digest its author signed matches.",
        // Untrusted text from another member: escaped, so it cannot drive the terminal.
        file.name.escape_debug(),
        plaintext.len(),
        out.display()
    );
    Ok(())
}

// ─── Sealed records and files, end to end ────────────────────────────────

/// How many times a sealed write re-seals for the version the host actually assigned before
/// giving up. Versions come from a room-wide counter, so each retry loses only to a write
/// that landed between this one's seal and its put.
const SEALED_WRITE_ATTEMPTS: usize = 4;

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

/// Whether the room seals its records, from `rooms/info` read as the member — and which
/// member the VTA acted as, which is the author a sealed body names.
async fn room_tier(
    client: &VtaClient,
    target: &RoomTarget<'_>,
) -> Result<(bool, String), Box<dyn std::error::Error>> {
    use trust_tasks_rs::Payload as _;
    let (member, reply) = act_and_send(
        client,
        target,
        trust_tasks_rs::specs::rooms::info::v0_1::Payload::TYPE_URI,
        serde_json::json!({ "roomId": target.room_id }),
    )
    .await
    .map_err(|e| format!("could not read the room's tier (rooms/info): {e}"))?;
    let visibility = reply
        .get("visibility")
        .and_then(Value::as_str)
        .ok_or("the host's rooms/info response names no visibility")?;
    Ok((visibility != "open", member))
}

/// Have the VTA sign `content` **as the member** and seal it (`rooms/keys/seal/0.2`), and
/// put it as the member (`rooms/keys/act/0.3`), re-sealing at the version the host assigned
/// whenever that is not the one sealed for. Returns the version written.
///
/// The record's associated data and its signed body both name the version, and the host
/// assigns it from a room-wide counter, so the version is predicted from the room's head and
/// a miss is corrected by a rewrite. Until that rewrite lands the record does not open,
/// which is why a write that runs out of attempts says so and names the key.
async fn write_sealed(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    content: SealedRecordBody,
    expected_version: Option<u64>,
) -> Result<u64, Box<dyn std::error::Error>> {
    write_sealed_naming(client, target, content, expected_version, None).await
}

/// [`write_sealed`], naming `blobs` committed in the room (`rooms/records/put/0.2`).
async fn write_sealed_naming(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    content: SealedRecordBody,
    expected_version: Option<u64>,
    blobs: Option<Vec<String>>,
) -> Result<u64, Box<dyn std::error::Error>> {
    let head = list_page(client, target, None, None, None)
        .await?
        .head_version
        .unwrap_or(0);

    let key = content.key.clone();
    let mut intended = head + 1;
    let mut expected = expected_version;
    let mut landed = 0;
    for _ in 0..SEALED_WRITE_ATTEMPTS {
        // Unsigned: the VTA signs it as its author, the member, before sealing.
        let unsigned = serde_json::to_vec(&content.clone().at_version(intended))?;
        let sealed = client
            .room_seal_as_principal(target.room_id, &key, intended, &unsigned)
            .await?
            .sealed;
        let mut payload = serde_json::json!({
            "roomId": target.room_id,
            "key": key,
            "sealed": {
                "ciphertext": sealed.ciphertext,
                "nonce": sealed.nonce,
                "epoch": sealed.epoch.get(),
            },
        });
        if let Some(v) = expected {
            payload["expectedVersion"] = serde_json::json!(v);
        }
        let put_type = match &blobs {
            Some(b) => {
                payload["blobs"] = serde_json::json!(b);
                vti_rooms::wire::ROOMS_RECORDS_PUT_V2_TYPE
            }
            None => vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE,
        };
        let (_, reply) = act_and_send(client, target, put_type, payload)
            .await
            .map_err(|e| put_refused(e, target))?;
        let put: vti_rooms::wire::PutRecordResponse = parse_reply("rooms/records/put", reply)?;
        landed = put.version;
        if landed == intended {
            return Ok(landed);
        }
        // Another write took the predicted version. The record is stored but sealed for the
        // wrong one, so it does not open; rewrite it, and only over what just landed.
        expected = Some(landed);
        intended = landed + 1;
    }
    Err(format!(
        "{key} is stored at version {landed} but sealed for another version, so it does not \
         open: the room kept moving under {SEALED_WRITE_ATTEMPTS} attempts. Write it again \
         with --expected-version {landed}."
    )
    .into())
}

/// The `pnm rooms keys commit` that brings this VTA's group up to the room's epoch,
/// with the target's own values. `--host-did` only when the operator gave one: a VTC
/// needs it, another host may not have one to give.
fn keys_commit_command(target: &RoomTarget<'_>) -> String {
    let mut cmd = format!(
        "pnm rooms keys commit --room {} --host {}",
        target.room_id, target.host_url
    );
    if let Some(did) = target.host_did {
        cmd.push_str(&format!(" --host-did {did}"));
    }
    cmd
}

/// `rooms/records/put` refused `e`: when the host says the record was sealed under an
/// epoch the room has moved past (the declared `epochMismatch`), say what happened and
/// print the command that catches up. Anything else is returned as it was.
fn put_refused(
    e: Box<dyn std::error::Error>,
    target: &RoomTarget<'_>,
) -> Box<dyn std::error::Error> {
    let refusal = e
        .downcast_ref::<vtc_client::VtcError>()
        .and_then(vtc_client::git_ns::task_error);
    match refusal {
        Some((code, message)) => match put_refusal_hint(&code, &message, target) {
            Some(hint) => hint.into(),
            None => e,
        },
        None => e,
    }
}

/// The operator-facing text for a `rooms/records/put` refusal `code`, when there is one.
fn put_refusal_hint(code: &str, message: &str, target: &RoomTarget<'_>) -> Option<String> {
    use trust_tasks_rs::specs::rooms::records::put;
    let epoch_mismatch = [
        put::v0_1::error_codes::EPOCH_MISMATCH.code,
        put::v0_2::error_codes::EPOCH_MISMATCH.code,
    ];
    if !epoch_mismatch.contains(&code) {
        return None;
    }
    Some(format!(
        "the host refused the record: {message}\n\n\
         The room has moved on to a newer epoch — it was renewed, or its membership changed — \
         and this VTA has not applied the commit that moved it, so it sealed the record under \
         the old epoch. Nothing was written. Catch up, then write again:\n\n  {}",
        keys_commit_command(target)
    ))
}

/// The operator-facing text for a `rooms/keys/open` refusal.
fn open_refusal_hint(e: &VtaError, target: &RoomTarget<'_>) -> String {
    use trust_tasks_rs::specs::rooms::keys::open::v0_2::error_codes::UNKNOWN_EPOCH;
    epoch_refusal_hint(e, target, UNKNOWN_EPOCH.code, Sealed::Record)
}

/// The operator-facing text for a `rooms/keys/file-key` refusal, as `pnm rooms file
/// get` and `file open` print it — the same remedies a record's refusal names.
fn file_key_refusal_hint(e: &VtaError, target: &RoomTarget<'_>) -> String {
    use trust_tasks_rs::specs::rooms::keys::file_key::v0_2::error_codes::UNKNOWN_EPOCH;
    epoch_refusal_hint(e, target, UNKNOWN_EPOCH.code, Sealed::File)
}

/// What a refused epoch had sealed, for the wording of [`epoch_refusal_hint`].
#[derive(Clone, Copy)]
enum Sealed {
    Record,
    File,
}

impl Sealed {
    fn noun(self) -> &'static str {
        match self {
            Self::Record => "record",
            Self::File => "file",
        }
    }
}

/// The remedy for a refused epoch, from the declared `unknownEpoch` (`code`) and its
/// `details.reason`.
///
/// The epoch cases have opposite remedies, so they are told apart by reason —
/// `notDelivered` (catch up), `beyondChain` (backfill) and `removed` (no commit will
/// help: `rooms/keys/{open,file-key}/0.2` say a caller MUST NOT retry after catching up)
/// — never by the message. The text checks are only for a refusal that carries no reason.
fn epoch_refusal_hint(e: &VtaError, target: &RoomTarget<'_>, code: &str, sealed: Sealed) -> String {
    let noun = sealed.noun();
    let text = e.to_string();
    let reason = (e.rejection_code() == Some(code))
        .then(|| e.rejection_details())
        .flatten()
        .and_then(|d| d.get("reason"))
        .and_then(Value::as_str);
    let backfill = || {
        format!(
            "The {noun} is older than any key this VTA holds — it was written before you \
             joined. Fetch the room's history: `pnm rooms keys backfill --room {} --host-did \
             {}`.",
            target.room_id,
            target.host_did.unwrap_or("<host-did>")
        )
    };
    let hint = match reason {
        Some("removed") => {
            let at = e
                .rejection_details()
                .and_then(|d| d.get("removedAtEpoch"))
                .and_then(Value::as_u64)
                .map(|n| format!(" at epoch {n}"))
                .unwrap_or_default();
            format!(
                "You were removed from this room's group{at}. {}s sealed since then will \
                 never open for you, and no commit will change that; what was sealed before \
                 your removal still opens. Rejoining takes a fresh invitation from the room's \
                 owner.",
                capitalised(noun)
            )
        }
        Some("notDelivered") => format!(
            "The {noun} is newer than this VTA's group: a commit has not been applied here. \
             Catch up, then try again:\n\n  {}",
            keys_commit_command(target),
        ),
        Some("beyondChain") => backfill(),
        _ if text.contains("cannot reach") => backfill(),
        _ if text.contains("has not been delivered") => format!(
            "The {noun} is newer than this VTA's group. Catch up with `{}`; if that says you \
             were removed, nothing sealed after your removal will open.",
            keys_commit_command(target)
        ),
        _ => format!("The {noun} did not open with any key this VTA holds."),
    };
    format!("{e}\n\n{hint}")
}

fn capitalised(word: &str) -> String {
    let mut chars = word.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// Open a sealed record through the VTA and check its body before anything in it is used.
///
/// `version` is the record's; the body is opened, and its signed location checked, at the
/// version it was **sealed** at — `sealed.version` where the host served one, because a
/// curation moves a record past its body. A record curated by a host that predates that
/// member carries none, and the VTA searches earlier versions and says which opened.
async fn open_and_verify(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    key: &str,
    version: u64,
    sealed: &SealedContent,
    host_author: Option<&str>,
) -> Result<VerifiedRecordBody, Box<dyn std::error::Error>> {
    let sealed_at = sealed
        .sealed_at(version)
        .map_err(|why| format!("refusing record {key}: the host says {why}"))?;
    let opened = client
        .room_open(
            target.room_id,
            key,
            sealed_at,
            &sealed.ciphertext,
            &sealed.nonce,
            sealed.epoch,
        )
        .await
        // The failures operators will actually hit, named where they will read them. Each
        // reads like corruption if nobody says otherwise.
        .map_err(|e| open_refusal_hint(&e, target))?;
    let plaintext = opened
        .get("plaintext")
        .and_then(Value::as_str)
        .ok_or("the VTA opened the record but returned no plaintext")?;
    let bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, plaintext)?;

    let resolver = vta_sdk::trust_task_proof::TrustTaskVmResolver::from_optional(
        vta_sdk::resolver::shared_did_resolver_from_env().await.ok(),
    );
    // Where the VTA found it sealed, if not where it was asked to look.
    let opened_at = opened
        .pointer("/ext/org.openvtc.rooms/sealedAt")
        .and_then(Value::as_u64)
        .unwrap_or(sealed_at);
    if opened_at > sealed_at {
        return Err(format!(
            "refusing record {key}: the VTA opened it at version {opened_at}, past the {sealed_at} it was asked for"
        )
        .into());
    }
    let location = RecordLocation {
        room_id: target.room_id,
        key,
        version: opened_at,
    };
    Ok(verify_record_body(&bytes, location, host_author, &resolver)
        .await
        .map_err(|e| format!("refusing record {key}: {e}"))?)
}

/// The part size a direct upload is cut into: one part up to [`SINGLE_PART_MAX`], else
/// parts of this size (storage's multipart floor is 5 MiB).
const DIRECT_PART: usize = 8 * 1024 * 1024;
/// The largest blob sent as one direct part.
const SINGLE_PART_MAX: usize = 16 * 1024 * 1024;
/// How many times a direct upload asks again for targets before giving up.
const DIRECT_BEGIN_ATTEMPTS: usize = 64;

/// The part plan (`directParts`) for `ciphertext`: its parts, and each one's sha2-256.
fn direct_plan(ciphertext: &[u8]) -> (usize, Value) {
    use sha2::Digest as _;
    let part = if ciphertext.len() <= SINGLE_PART_MAX {
        ciphertext.len().max(1)
    } else {
        DIRECT_PART
    };
    let digests: Vec<String> = ciphertext
        .chunks(part)
        .map(|c| vti_common::blob_store::sha256_digest_multibase(&sha2::Sha256::digest(c).into()))
        .collect();
    (
        part,
        serde_json::json!({ "partSize": part, "partCount": digests.len(), "partDigests": digests }),
    )
}

/// `rooms file put` — seal a local file, upload its ciphertext, and write the record that
/// names it, all **as the member** (`rooms/blobs/*/0.2` through `rooms/keys/act`).
///
/// The file is sealed here under one file's key from the VTA (`rooms/keys/file-key`); its
/// bytes never pass through the VTA, and the host receives only ciphertext. The member's
/// VTA signs the begin, the record and — in direct mode — the commit, as the member; the
/// bytes go straight to the room's storage over targets the host issued (direct) or to the
/// host as chunk documents signed by a single-use upload key minted here for this upload
/// alone (proxied). This client's own key signs nothing the host receives.
pub async fn cmd_rooms_file_put(
    client: &VtaClient,
    target: RoomTarget<'_>,
    path: &std::path::Path,
    title: Option<String>,
    description: Option<String>,
    tags: Vec<String>,
    padme: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use trust_tasks_rs::Payload as _;
    use trust_tasks_rs::specs::rooms::blobs::upload;
    use vti_rooms::files::{self, FileBinding, Padding};

    let (sealed_tier, member) = room_tier(client, &target).await?;
    if !sealed_tier {
        return Err(
            "this room is `open`: its records are cleartext, and a file's manifest \
                    belongs inside a sealed body. Files go in `attributed` and `private` rooms."
                .into(),
        );
    }

    let plaintext = std::fs::read(path)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("the file has no usable name")?;
    // A fresh id for every file: the segment nonces are counters, so two files
    // under one key would reuse them.
    let file_id = files::new_file_id();
    let resp = client
        .room_file_key(target.room_id, &files::encode_file_id(&file_id), None)
        .await?;
    let file_key = file_key_bytes(&resp)?;
    let sealed = files::seal_file(
        &file_key,
        FileBinding {
            room_id: target.room_id.to_string(),
            file_id,
            epoch: resp.epoch.get(),
            segment_size: files::DEFAULT_SEGMENT_SIZE,
        },
        name,
        None,
        &plaintext,
        if padme { Padding::Padme } else { Padding::None },
    )?;
    let ciphertext: Vec<u8> = sealed.chunks.concat();

    // The upload key: minted here for this upload alone, from no key held for anything
    // else, and dropped when the upload ends.
    let (key_did, key_secret) = crate::local_keygen::generate_unbound_admin_did_key();
    let key_secret = zeroize::Zeroizing::new(key_secret);
    let (part_size, plan) = direct_plan(&ciphertext);
    let begin_payload = serde_json::json!({
        "roomId": target.room_id,
        "manifest": sealed.blob,
        "uploadKey": key_did,
        "directParts": plan,
    });
    let begin = || async {
        let (_, reply) = act_and_send(
            client,
            &target,
            upload::begin::v0_2::Payload::TYPE_URI,
            begin_payload.clone(),
        )
        .await?;
        parse_reply::<upload::begin::v0_2::Response>("rooms/blobs/upload/begin", reply)
    };
    let mut begun = begin().await?;
    let direct = wire_str(&begun.mode) == "direct";
    let upload_id = begun.upload_id.to_string();
    let host = target.client();

    let sent: Result<(), Box<dyn std::error::Error>> = async {
        if begun.already_committed == Some(true) {
            return Ok(());
        }
        if direct {
            // Each part to its own target, with exactly the headers it names; begin again,
            // with the identical manifest and plan, for parts beyond the first batch or
            // whose target lapsed.
            for _ in 0..DIRECT_BEGIN_ATTEMPTS {
                if begun.missing.is_empty() {
                    return Ok(());
                }
                if begun.targets.is_empty() {
                    return Err("the host answered direct mode with no targets".into());
                }
                for t in &begun.targets {
                    let i = usize::try_from(t.index)
                        .ok()
                        .filter(|i| i * part_size < ciphertext.len().max(1))
                        .ok_or("the host issued a target for a part that does not exist")?;
                    let part =
                        &ciphertext[i * part_size..((i + 1) * part_size).min(ciphertext.len())];
                    vtc_client::rooms::files::put_part(t, part).await?;
                }
                begun = begin().await?;
            }
            return Err("the upload did not finish: the host kept asking for parts".into());
        }
        for index in &begun.missing {
            let i = usize::try_from(index.0)
                .ok()
                .filter(|i| *i < sealed.chunks.len())
                .ok_or_else(|| {
                    format!("the host asked for chunk {}, which does not exist", index.0)
                })?;
            host.upload_chunk_v2(
                &upload_id,
                i as u64,
                &sealed.chunks[i],
                &key_did,
                &key_secret,
            )
            .await?;
        }
        Ok(())
    }
    .await;

    // Commit and abort: the upload key's (proxied), or the member's own (direct).
    let finish = |type_uri: &'static str| {
        let (upload_id, key_did, key_secret, member) = (
            upload_id.clone(),
            key_did.clone(),
            key_secret.clone(),
            member.clone(),
        );
        let target = &target;
        async move {
            let payload = serde_json::json!({ "uploadId": upload_id });
            if direct {
                act_and_send_as(client, target, type_uri, payload, Some(&member))
                    .await
                    .map(|(_, reply)| reply)
            } else {
                let doc = vta_sdk::trust_task_sign::build_signed(
                    type_uri,
                    payload,
                    &key_did,
                    &key_secret,
                    target.host_did.unwrap_or("did:key:zHost"),
                )
                .await
                .map_err(|e| format!("could not sign with the upload key: {e}"))?;
                let doc: Value = serde_json::from_str(&doc)?;
                Ok(target.client().send_signed_room_document(&doc).await?)
            }
        }
    };
    if let Err(e) = sent {
        // Release what `begin` reserved rather than leaving it to expire.
        let _ = finish(upload::abort::v0_2::Payload::TYPE_URI).await;
        return Err(e);
    }
    let committed: upload::commit::v0_2::Response = parse_reply(
        "rooms/blobs/upload/commit",
        finish(upload::commit::v0_2::Payload::TYPE_URI).await?,
    )?;
    let blob_ref = wire_str(&committed.blob_ref);
    if !files::same_digest(&blob_ref, &sealed.file.blob_ref) {
        return Err(format!(
            "the host committed {blob_ref}, not the blob sealed here ({})",
            sealed.file.blob_ref
        )
        .into());
    }

    let key = opaque_key();
    let mut content = SealedRecordBody::new(
        RecordLocation {
            room_id: target.room_id,
            key: &key,
            version: 1,
        },
        &member,
    );
    content.title = title;
    content.description = description;
    content.tags = tags;
    content.file = Some(sealed.file.clone());
    let version = write_sealed_naming(
        client,
        &target,
        content,
        Some(0),
        Some(vec![blob_ref.clone()]),
    )
    .await?;

    if crate::render::is_json_output() {
        crate::render::print_json(&serde_json::json!({
            "key": key,
            "version": version,
            "blobRef": blob_ref,
            "size": sealed.file.size,
            "mode": if direct { "direct" } else { "proxied" },
        }))?;
        return Ok(());
    }
    println!(
        "Put {name} ({} bytes, {}) as record {key} at version {version}, as {member}\n  blobRef  {blob_ref}\n  Members fetch it with `pnm rooms file get {key}`.",
        sealed.file.size,
        if direct {
            "straight to the room's storage"
        } else {
            "through the host"
        }
    );
    Ok(())
}

/// A local file name from one another member chose: the last path component, without
/// leading dots, never empty.
fn local_name(untrusted: &str) -> String {
    let base = untrusted
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .trim_start_matches('.');
    let clean = inert(base).replace(['\n', '\t'], " ");
    if clean.trim().is_empty() {
        "room-file".to_string()
    } else {
        clean
    }
}

/// `rooms file get` — fetch a record's file **as the member**, check it against what its
/// author signed, and write the plaintext.
///
/// The record and the blob are asked for through the member's VTA (`rooms/keys/act`); the
/// bytes come straight from the room's storage when the host offers it (`direct`, a ranged
/// read per chunk), or chunk by chunk through the host, each request signed as the member.
/// Nothing is written unless every check holds: the record body's signature and location,
/// the blob being the one the author named, every chunk against the manifest, and the
/// plaintext against the author's digest.
pub async fn cmd_rooms_file_get(
    client: &VtaClient,
    target: RoomTarget<'_>,
    key: &str,
    out: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    use trust_tasks_rs::Payload as _;
    use trust_tasks_rs::specs::rooms::blobs::{chunk as blob_chunk, get as blob_get};
    use vti_rooms::files::{self, BlobManifest};

    let (member, record) = act_and_send(
        client,
        &target,
        vti_rooms::wire::ROOMS_RECORDS_GET_V2_TYPE,
        serde_json::json!({ "roomId": target.room_id, "key": key }),
    )
    .await?;
    let record: vtc_client::rooms::files::GetRecordV2Response =
        parse_reply("rooms/records/get", record)?;
    let sealed = record.sealed.as_ref().ok_or(
        "the record has no sealed body: it is on an `open` room, or it has been retracted",
    )?;
    let sealed = SealedContent {
        ciphertext: sealed.ciphertext.clone(),
        nonce: sealed.nonce.clone(),
        epoch: u32::try_from(sealed.epoch.get())
            .map_err(|_| "the record's epoch is beyond what this client can represent")?,
        // The version the body was sealed at, where a curation moved the record past it
        // (rooms `_shared/0.1` `SealedRecord.version`): opened and verified there, and a
        // `sealed.version` above the record's own refused by `open_and_verify`.
        version: sealed.version.map(std::num::NonZeroU64::get),
    };
    let verified = open_and_verify(
        client,
        &target,
        key,
        record.version.get(),
        &sealed,
        record.author.as_deref(),
    )
    .await?;
    let file = verified
        .body()
        .file
        .clone()
        .ok_or("the record carries no file")?;
    let named = record
        .blobs
        .iter()
        .flatten()
        .any(|b| files::same_digest(&wire_str(b), &file.blob_ref));
    if !named {
        return Err(
            "the host does not name the file's blob on this record; it may have been \
                    released"
                .into(),
        );
    }

    let (_, started) = act_and_send(
        client,
        &target,
        blob_get::v0_2::Payload::TYPE_URI,
        serde_json::json!({ "roomId": target.room_id, "blobRef": file.blob_ref, "direct": true }),
    )
    .await?;
    let started: blob_get::v0_2::Response = parse_reply("rooms/blobs/get", started)?;
    let blob: BlobManifest = serde_json::from_value(serde_json::to_value(&started.manifest)?)?;
    // The file manifest is the author's; the blob manifest is the host's. Before a byte is
    // trusted: it is the blob the author named, and its shape is the one the author's
    // segment size and length give.
    file.check_blob(&blob)?;
    let size = blob.size;
    let chunk_size = blob.chunks.chunk_size;
    let mut chunks = Vec::with_capacity(blob.chunks.chunk_digests.len());
    for (i, expected) in blob.chunks.chunk_digests.iter().enumerate() {
        let chunk = match (&started.target, &started.download_id) {
            (Some(t), _) => {
                let start = i as u64 * chunk_size;
                vtc_client::rooms::files::get_range(t, start..(start + chunk_size).min(size))
                    .await?
            }
            (None, Some(download_id)) => {
                let (_, reply) = act_and_send_as(
                    client,
                    &target,
                    blob_chunk::v0_1::Payload::TYPE_URI,
                    serde_json::json!({ "downloadId": download_id, "index": i }),
                    Some(&member),
                )
                .await?;
                let c: blob_chunk::v0_1::Response = parse_reply("rooms/blobs/chunk", reply)?;
                base64::Engine::decode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    c.data.as_str(),
                )?
            }
            (None, None) => {
                return Err("the host answered with neither a target nor a download".into());
            }
        };
        if !files::same_digest(&files::digest_multibase(&chunk), expected) {
            return Err(format!("chunk {i} does not match the manifest").into());
        }
        chunks.push(chunk);
    }

    let resp = client
        .room_file_key(target.room_id, &file.file_id, Some(file.epoch))
        .await
        .map_err(|e| file_key_refusal_hint(&e, &target))?;
    let file_key = file_key_bytes(&resp)?;
    let plaintext = files::open_file(&file_key, target.room_id, &file, &blob, &chunks)?;

    let out = match out {
        Some(p) => p.to_path_buf(),
        None => std::path::PathBuf::from(local_name(&file.name)),
    };
    if out.exists() {
        return Err(format!("{} already exists; refusing to overwrite it", out.display()).into());
    }
    // Written beside the target and moved into place, so a failure leaves nothing that
    // looks like the file.
    let tmp = out.with_extension("partial");
    std::fs::write(&tmp, &plaintext)?;
    std::fs::rename(&tmp, &out)?;
    println!(
        "Fetched {} ({} bytes) into {}, written by {}; it matches the digest they signed.",
        inert(&file.name).escape_debug(),
        plaintext.len(),
        out.display(),
        verified.body().author
    );
    Ok(())
}

/// `rooms owner group-create` — found a sealed room's group in this VTA, with the owner
/// as its only member (`rooms/owner/group/create/0.1`).
pub async fn cmd_rooms_owner_group_create(
    client: &VtaClient,
    room_id: &str,
    signing_key_id: &str,
    member: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .room_group_create(room_id, signing_key_id, member)
        .await
        .map_err(|e| {
            format!(
                "{e}\n\n`noSigningKey` means this VTA will not let you name `{signing_key_id}` — \
                 check it with `pnm keys list --context <id>`. `alreadyExists` means it already \
                 holds this room's group, which is never replaced."
            )
        })?;
    println!("Founded the group of {room_id} at epoch {}.", resp.epoch);
    println!(
        "  Next: admit members with `pnm rooms owner invite` and `pnm rooms owner group-add`. \
         Writing needs your own membership and authority credentials in this VTA \
         (`pnm rooms owner issue-membership` / `issue-authority --store`), if not issued yet."
    );
    Ok(())
}

/// An earlier removal the VTA was settling when it took this request, and whose revocation
/// list the host refused on redelivery, explained for the operator — or `None` when `e` is
/// not that refusal.
///
/// It is `rooms/owner/group/{add,renew,remove}:earlierRemovalRefused` at `add/0.3`,
/// `renew/0.2` and `remove/0.3`, and at `remove/0.1` (a `private` room's removal) the
/// task's own `hostRefused` carrying the same `details` (`member`, `code`, `listKept`) —
/// `rooms/owner/group/remove/0.3` item 8.2. The earlier removal did not take effect, and
/// nothing of `this` was done: the fix is to run the command again, then remove the
/// earlier member again if that is still wanted.
fn earlier_removal_refused(
    e: &VtaError,
    room_id: &str,
    host_did: &str,
    signing_key_id: Option<&str>,
    this: &str,
) -> Option<String> {
    let VtaError::Rejected { code, details, .. } = e else {
        return None;
    };
    let task = code.strip_prefix("rooms/owner/group/")?;
    let d = details.as_ref()?;
    let ours = task.ends_with(":earlierRemovalRefused")
        || (task.ends_with(":hostRefused") && d.get("member").is_some());
    if !ours {
        return None;
    }
    let earlier = d["member"].as_str().unwrap_or("an earlier member");
    let host_code = d["code"].as_str().unwrap_or("no code given");
    let kept = if d["listKept"].as_bool() == Some(true) {
        format!(
            "Their withdrawal is kept in the room's revocation list and carried by every later \
             one; the host enforces it only if it ever accepted that list — deliver it again \
             with\n    pnm rooms owner revoke --room {room_id} --signing-key {} --host \
             {host_did}",
            signing_key_id.unwrap_or("<the room's key>")
        )
    } else {
        "Their withdrawal was discarded: no host accepted it.".to_string()
    };
    Some(format!(
        "Nothing was done: an earlier removal of {earlier} from {room_id} did not take effect \
         — {host_did} refused its revocation list when your VTA delivered it again \
         ({host_code}). {earlier} is still in the room's group. {kept}\n\nRun this command \
         again to {this}; then remove {earlier} again if that is still wanted."
    ))
}

/// `rooms owner group-remove` — remove a member from a room.
///
/// With `signing_key_id`, `rooms/owner/group/remove/0.3`: the room's key withdraws the member's credentials at the host first, and then the
/// room advances — the removal takes effect at the host at once. On a `private` room, where
/// the host cannot be told whom to refuse, it refuses and this falls back to 0.1, which the
/// specification keeps as that tier's removal. Without `signing_key_id`, 0.1: the group
/// alone, credentials left valid.
///
/// An earlier removal the VTA was still settling, whose list the host refused on
/// redelivery, is reported as `earlierRemovalRefused`: that removal did not take effect, and
/// nothing of this one was done — this says which member, and what to run.
#[allow(clippy::too_many_arguments)]
pub async fn cmd_rooms_owner_group_remove(
    client: &VtaClient,
    room_id: &str,
    host_did: &str,
    member: &str,
    signing_key_id: Option<&str>,
    mirrors: &[String],
    until: Option<chrono::DateTime<chrono::Utc>>,
    reason: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let hint = |e: VtaError| {
        format!(
            "{e}\n\n`epochConflict` means another admin advanced the room: catch up and \
             retry. `hostUnreachable` leaves the outcome unknown; running this again \
             settles it with the host before anything else. `ownLeaf` means {member} is \
             you: hand the room on with rooms/owner/transfer instead. `noSigningKey` means \
             this VTA will not let you name the room's key — check `pnm keys list`."
        )
    };
    if let Some(key) = signing_key_id {
        // Under one idempotency key, so a retry after a lost reply reports the removal that
        // happened instead of `notMember`.
        match client
            .idempotent(|| {
                client
                    .room_group_remove_v0_3(room_id, host_did, member, key, mirrors, until, reason)
            })
            .await
        {
            Ok(resp) => {
                let r = serde_json::to_value(&resp).unwrap_or_default();
                println!(
                    "Removed {member} from {room_id}: withdrawn at the host from {} (revocation \
                     list {}), and the room is now at epoch {}.",
                    r["revokedAt"].as_str().unwrap_or("now"),
                    r["revocation"]["sequence"],
                    r["epoch"]
                );
                if let Some(pending) = r["mirrorsPending"].as_array().filter(|p| !p.is_empty()) {
                    let pending: Vec<&str> = pending.iter().filter_map(Value::as_str).collect();
                    println!(
                        "  Not yet withdrawn at: {}. Deliver it with `pnm rooms owner revoke \
                         --room {room_id} --signing-key {key} --host <did>` (no withdrawal).",
                        pending.join(", ")
                    );
                }
                println!(
                    "  The host refuses their credentials, and anything they delegated, from \
                     now on. Nothing they already read can be recalled."
                );
                return Ok(());
            }
            // 0.3 item 8.2: an earlier removal did not take effect, and this one was not
            // started. Say which member, whether their withdrawal survives, and what to run.
            Err(e)
                if let Some(said) = earlier_removal_refused(
                    &e,
                    room_id,
                    host_did,
                    Some(key),
                    &format!("remove {member}"),
                ) =>
            {
                return Err(said.into());
            }
            // The one case the specification hands to 0.1: a private room's host cannot be
            // told whom to refuse.
            Err(VtaError::Rejected { code, .. })
                if code == "rooms/owner/group/remove:privateRoom" =>
            {
                println!(
                    "{room_id} is private: a member cannot be withdrawn one at a time there. \
                     Removing them from the group (0.1) instead."
                );
            }
            Err(e) => return Err(hint(e).into()),
        }
    }
    let resp = client
        .idempotent(|| client.room_group_remove(room_id, host_did, member, reason))
        .await
        .map_err(|e| {
            earlier_removal_refused(&e, room_id, host_did, None, &format!("remove {member}"))
                .unwrap_or_else(|| hint(e))
        })?;
    println!(
        "Removed {member} from {room_id}'s group; the room is now at epoch {}.",
        resp.epoch
    );
    println!(
        "  Nothing sealed from now on is readable to them. Their credentials are NOT \
         withdrawn at the host and stay valid until they expire: on an open or attributed \
         room pass --signing-key to withdraw them, or reset every credential with \
         `pnm rooms owner revoke --reset`."
    );
    Ok(())
}

/// `rooms owner revoke` — withdraw credentials a room issued (`rooms/owner/revoke/0.1`),
/// signed as the room and delivered to every host serving it. With nothing to withdraw,
/// re-delivers the list the VTA holds.
#[allow(clippy::too_many_arguments)]
pub async fn cmd_rooms_owner_revoke(
    client: &VtaClient,
    room_id: &str,
    signing_key_id: &str,
    hosts: &[String],
    subjects: &[String],
    credentials: &[String],
    reset: bool,
    until: Option<chrono::DateTime<chrono::Utc>>,
    reason: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use trust_tasks_rs::specs::rooms::owner::revoke::v0_1::Withdrawal;
    let until = until.map(|u| u.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    let mut raw: Vec<serde_json::Value> = Vec::new();
    for s in subjects {
        raw.push(serde_json::json!({ "kind": "subject", "subject": s }));
    }
    for c in credentials {
        raw.push(serde_json::json!({ "kind": "credential", "credentialId": c }));
    }
    if reset {
        raw.push(serde_json::json!({ "kind": "room" }));
    }
    if let Some(u) = &until {
        for w in &mut raw {
            w["until"] = serde_json::json!(u);
        }
    }
    let withdraw: Vec<Withdrawal> = raw
        .into_iter()
        .map(serde_json::from_value)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("a withdrawal is not one rooms/owner/revoke accepts: {e}"))?;
    let resp = client
        .idempotent(|| client.room_owner_revoke(room_id, signing_key_id, hosts, &withdraw, reason))
        .await
        .map_err(|e| {
            format!(
                "{e}\n\n`noList` means there is nothing to re-deliver: name a withdrawal. \
                 `entryNotPermitted` means the room is private: only --reset applies there. \
                 `noSigningKey` means this VTA will not let you name `{signing_key_id}` — check \
                 `pnm keys list`. `noAuthority` means it holds no `admin` grant of the room \
                 for a persona you act as."
            )
        })?;
    let r = serde_json::to_value(&resp).unwrap_or_default();
    println!(
        "{room_id}'s revocation list is at sequence {} ({}).",
        r["head"]["sequence"],
        r["head"]["digest"].as_str().unwrap_or_default()
    );
    for d in r["deliveries"].as_array().into_iter().flatten() {
        let host = d["host"].as_str().unwrap_or_default();
        match d["outcome"].as_str().unwrap_or_default() {
            "accepted" => println!(
                "  {host}: in force from {}",
                d["inForceAt"].as_str().unwrap_or_default()
            ),
            "refused" => {
                let code = d["code"].as_str().unwrap_or_default();
                println!("  {host}: REFUSED ({code})");
                if code == "rooms/revocations/put:stale" {
                    println!(
                        "    The host holds a later list this VTA did not sign: the room's key \
                         may be in more than one party's hands."
                    );
                }
            }
            _ => println!("  {host}: no answer — run this again with no withdrawal to deliver it"),
        }
    }
    Ok(())
}

/// `rooms owner group-renew` — renew a sealed room (`rooms/owner/group/renew/0.2`): advance its group with a commit that changes no membership, and
/// the room at its host with that commit. An earlier removal the VTA was settling, refused
/// at the host, is explained as `group-remove` explains it: nothing of the renewal was done.
pub async fn cmd_rooms_owner_group_renew(
    client: &VtaClient,
    room_id: &str,
    host_did: &str,
    reason: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Under one idempotency key, so a retry after a lost reply reports the renewal that
    // happened instead of renewing a second time.
    let resp = client
        .idempotent(|| client.room_group_renew(room_id, host_did, reason))
        .await
        .map_err(|e| {
            earlier_removal_refused(&e, room_id, host_did, None, &format!("renew {room_id}"))
                .unwrap_or_else(|| {
                    format!(
                        "{e}\n\n`noGroup` means this VTA holds no group for {room_id}: an \
                         `open` room renews with `pnm rooms renew`. `epochConflict` means \
                         another admin advanced the room: catch up and retry. \
                         `hostUnreachable` leaves the outcome unknown; running this again \
                         settles it with the host before anything else."
                    )
                })
        })?;
    println!(
        "Renewed {room_id}; the room is now at epoch {}.",
        resp.epoch
    );
    println!(
        "  Nobody joined or left. Every remaining member's VTA must apply the commit before \
         it can write again: each runs `pnm rooms keys commit --room {room_id} --host <url> \
         --host-did {host_did}`."
    );
    Ok(())
}

/// `rooms owner group-add` — admit a member from their KeyPackage
/// (`rooms/owner/group/add/0.3`) and write the Welcome
/// to `out` for delivery. An earlier removal the VTA was settling, refused at the host, is
/// explained as `group-remove` explains it: nothing of the admission was done.
pub async fn cmd_rooms_owner_group_add(
    client: &VtaClient,
    room_id: &str,
    host_did: &str,
    member: &str,
    key_package_src: &str,
    reason: Option<&str>,
    out: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if out.exists() {
        return Err(format!("{} already exists; refusing to overwrite it", out.display()).into());
    }
    let key_package = if key_package_src == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
        s
    } else {
        std::fs::read_to_string(key_package_src)?
    };
    let key_package = key_package.trim().to_string();

    // Under one idempotency key: the answer is the only copy of the Welcome, and a
    // retry that re-executed would be refused `alreadyMember` with the Welcome lost.
    let resp = client
        .idempotent(|| client.room_group_add(room_id, host_did, member, &key_package, reason))
        .await
        .map_err(|e| {
            earlier_removal_refused(&e, room_id, host_did, None, &format!("admit {member}"))
                .unwrap_or_else(|| {
                    format!(
                        "{e}\n\n`epochConflict` means another admin advanced the room: catch \
                         up and retry. `hostUnreachable` leaves the outcome unknown; running \
                         this again settles it with the host before anything else."
                    )
                })
        })?;

    let delivery = serde_json::json!({
        "roomId": room_id,
        "member": resp.member.as_str(),
        "epoch": resp.epoch,
        "welcome": resp.welcome.as_str(),
        "ratchetTree": resp.ratchet_tree.as_ref().map(|t| t.as_str()),
    });
    std::fs::write(out, serde_json::to_vec_pretty(&delivery)?)?;
    println!(
        "Admitted {member} to {room_id}; the room is now at epoch {}.",
        resp.epoch
    );
    println!(
        "  Deliver {} to the member's key holder (rooms/keys/welcome) directly — never \
         through the host.",
        out.display()
    );
    Ok(())
}

// ─── A community's offers ────────────────────────────────────────────────
//
// A community that owns a room offers its members admission
// (`vtc/rooms/community/members/add`). The member lists their offers and accepts one with
// documents signed as the DID the offer is addressed to — a persona their VTA holds — so
// this client builds each request unsigned and has the VTA complete it as that DID with
// `rooms/keys/act`, which inserts no presentation for these types. The completed
// document goes to the community over its Trust Task HTTPS endpoint, unchanged: a
// persona-signed document rides HTTPS, never this client's own DIDComm session.
//
// The listing is `vtc/rooms/offers/list/0.3`, completed at `rooms/keys/act/0.6` — the first
// version whose table lists it — which adds the renewals of the rooms the member is already
// in to 0.2's offers and their descriptions. Members and communities upgrade on their own
// schedules, so a VTA or a community that does not serve 0.3 (`unsupportedType` /
// `unsupportedVersion` from either) is read at 0.2 (act 0.4), and failing that at 0.1 (act
// 0.3): those listings carry no renewals, and 0.1's offers no description.
//
// A renewal is collected with `pnm rooms offers renew`: its membership and authority are
// stored in the member's VTA **in place of** the ones they renew — never beside them, since
// a key holder holding two authorities from one room cannot choose between them.
//
// On a sealed tier the acceptance carries a KeyPackage, and the VTA completes it only with
// one it minted itself for that member and room (act 0.3 recipient item 10) — so this
// client asks for it there (`rooms/keys/key-package`, against the offer's invitation),
// never makes it itself.
//
// **This is one surface of several.** The member may accept the same offer in their
// community's member portal, or in OpenVTC, and each reads the same two records — the
// community's (`vtc/rooms/memberships/list`) and the VTA's (`rooms/keys/list`) — and keeps
// none of its own. So an acceptance is a sequence each of whose steps answers a repeat with
// its first answer: `key-package/0.2` returns the KeyPackage another surface may already
// have sent, the community answers it with the Welcome it kept, and the VTA answers a
// Welcome it already processed `alreadyJoined`. Whatever another surface began, this one
// finishes; and a room already joined is said to be, not accepted again.

/// The community an offer came from, and the DID it is addressed to.
pub struct OfferTarget<'a> {
    /// Base URL of the community's Trust Task endpoint (e.g. `https://vtc.example.com/v1`).
    pub vtc_url: &'a str,
    /// The community's DID — the `recipient` of every document.
    pub vtc_did: &'a str,
    /// The DID the community addressed its offers to: a persona your VTA holds.
    pub member: &'a str,
}

/// Which party an offer document failed at: the member's VTA, completing it as the member,
/// or the community, answering it. A refusal means something different from each —
/// `unsupportedType` from the VTA is an agent to upgrade, from the community a community
/// that does not serve that version — so each is kept apart until it is reported.
enum OfferStepError {
    /// The member's VTA did not complete the document (`rooms/keys/act`).
    Act(VtaError),
    /// The community refused the completed document, or did not answer it.
    Community(vtc_client::VtcError),
    /// Neither: the document could not be built or serialised.
    Local(Box<dyn std::error::Error>),
}

impl OfferStepError {
    /// Whether the party that answered does not serve the task at the version asked
    /// (`unsupportedType` / `unsupportedVersion`): the cue to ask at an older one.
    fn unsupported(&self) -> bool {
        match self {
            Self::Act(e) => matches!(e, VtaError::UnsupportedTaskType { .. }),
            Self::Community(e) => vtc_client::git_ns::task_error(e).is_some_and(|(code, _)| {
                let local = code.rsplit(':').next().unwrap_or(&code);
                local == "unsupportedType" || local == "unsupportedVersion"
            }),
            Self::Local(_) => false,
        }
    }

    /// The error to report, with a hint where the operator's fix is known.
    fn report(self, target: &OfferTarget<'_>) -> Box<dyn std::error::Error> {
        match self {
            Self::Act(e) => {
                let text = e.to_string();
                let hint = if matches!(e, VtaError::UnsupportedTaskType { .. }) {
                    "\n\nYour VTA does not serve the rooms/keys/act version that signs this \
                     request as you (0.6 for offers/list 0.3, 0.5 for memberships, 0.4 for \
                     offers/list 0.2, 0.3 for the rest): upgrade it."
                        .to_string()
                } else if text.contains("issuerNotPrincipal") {
                    format!(
                        "\n\nYour VTA holds no `authentication` key of `{}` that you may act as. \
                         Pass the persona DID the community knows you by as --member.",
                        target.member
                    )
                } else if text.contains("keyPackageNotHeld") {
                    "\n\nThe KeyPackage was not minted by your VTA for this member and room, or \
                     it has been used or has expired: run this again without --key-package to \
                     mint one."
                        .to_string()
                } else {
                    String::new()
                };
                format!("{e}{hint}").into()
            }
            Self::Community(e) => format!("{}: {e}", target.vtc_did).into(),
            Self::Local(e) => e,
        }
    }
}

/// Have the VTA complete a request to the community as `target.member`
/// (`rooms/keys/act/0.6`, or the newest version below it that completes the type) and send
/// it to the community. Returns the community's response
/// payload, or the party that failed.
async fn act_and_send_offer(
    client: &VtaClient,
    target: &OfferTarget<'_>,
    type_uri: &str,
    payload: Value,
) -> Result<Value, OfferStepError> {
    let document = vta_sdk::client::unsigned_community_request(
        type_uri,
        target.vtc_did,
        target.member,
        payload,
    )
    .map_err(|e| OfferStepError::Local(e.into()))?;
    let completed = client
        .room_act_community(&document)
        .await
        .map_err(OfferStepError::Act)?;
    let document =
        serde_json::to_value(&completed.document).map_err(|e| OfferStepError::Local(e.into()))?;
    VtcClient::anonymous(target.vtc_url, target.vtc_did)
        .send_signed_room_document(&document)
        .await
        .map_err(OfferStepError::Community)
}

/// One offer as this client shows it: `vtc/rooms/offers/list/0.2`'s, which is 0.1's with
/// the room's `description` when it has one. An offer read at 0.1 has none.
type CommunityOffer = trust_tasks_rs::specs::vtc::rooms::offers::list::v0_2::OfferV2;

/// A renewal of an admission the member holds (`vtc/rooms/offers/list/0.3`).
type CommunityRenewal = trust_tasks_rs::specs::vtc::rooms::offers::list::v0_3::Renewal;

/// The listing version asked: 0.3 (with renewals) through act 0.6, 0.2 (with descriptions)
/// through act 0.4, or 0.1 through act 0.3, for a VTA or a community that does not serve the
/// newer one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum OffersListVersion {
    V0_3,
    V0_2,
    V0_1,
}

/// What a listing answered: the offers, and at 0.3 the renewals.
type OffersListing = (Vec<CommunityOffer>, Vec<CommunityRenewal>);

/// `vtc/rooms/offers/list` at `at`, signed as the member: every offer (one page at a time),
/// read as [`CommunityOffer`], and at 0.3 the renewals the first page carries.
async fn list_offers_at(
    client: &VtaClient,
    target: &OfferTarget<'_>,
    at: OffersListVersion,
) -> Result<OffersListing, OfferStepError> {
    use trust_tasks_rs::Payload as _;
    use trust_tasks_rs::specs::vtc::rooms::offers::list::{v0_1, v0_2, v0_3};
    let type_uri = match at {
        OffersListVersion::V0_3 => v0_3::Payload::TYPE_URI,
        OffersListVersion::V0_2 => v0_2::Payload::TYPE_URI,
        OffersListVersion::V0_1 => v0_1::Payload::TYPE_URI,
    };
    let mut items = Vec::new();
    let mut renewals = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let payload = match &cursor {
            Some(c) => serde_json::json!({ "cursor": c }),
            None => serde_json::json!({}),
        };
        let reply = act_and_send_offer(client, target, type_uri, payload).await?;
        let page = offers_page(at, reply).map_err(OfferStepError::Local)?;
        items.extend(page.0);
        renewals.extend(page.2);
        match page.1 {
            Some(next) => cursor = Some(next),
            None => return Ok((items, renewals)),
        }
    }
}

/// One page of the community's answer at `at`: its offers, each read as a [`CommunityOffer`]
/// (an `Offer` is an `OfferV2` without `description`, and 0.3's `OfferV2` is 0.2's), the
/// next cursor, and at 0.3 its renewals.
#[allow(clippy::type_complexity)]
fn offers_page(
    at: OffersListVersion,
    reply: Value,
) -> Result<(Vec<CommunityOffer>, Option<String>, Vec<CommunityRenewal>), Box<dyn std::error::Error>>
{
    use trust_tasks_rs::specs::vtc::rooms::offers::list::{v0_1, v0_2, v0_3};
    match at {
        OffersListVersion::V0_3 => {
            let page: v0_3::Response = parse_reply("vtc/rooms/offers/list/0.3", reply)?;
            let items = page
                .items
                .into_iter()
                .map(|o| {
                    serde_json::to_value(o)
                        .and_then(serde_json::from_value::<CommunityOffer>)
                        .map_err(|e| format!("an offer read at 0.3 does not read as 0.2's: {e}"))
                })
                .collect::<Result<_, _>>()?;
            Ok((
                items,
                page.next_cursor.map(|c| c.to_string()),
                page.renewals,
            ))
        }
        OffersListVersion::V0_2 => {
            let page: v0_2::Response = parse_reply("vtc/rooms/offers/list/0.2", reply)?;
            Ok((
                page.items,
                page.next_cursor.map(|c| c.to_string()),
                Vec::new(),
            ))
        }
        OffersListVersion::V0_1 => {
            let page: v0_1::Response = parse_reply("vtc/rooms/offers/list/0.1", reply)?;
            let items = page
                .items
                .into_iter()
                .map(|o| {
                    serde_json::to_value(o)
                        .and_then(serde_json::from_value::<CommunityOffer>)
                        .map_err(|e| format!("an offer read at 0.1 does not read as 0.2's: {e}"))
                })
                .collect::<Result<_, _>>()?;
            Ok((items, page.next_cursor.map(|c| c.to_string()), Vec::new()))
        }
    }
}

/// Every offer the community has made to the member, and the renewals of the rooms they are
/// in: at `vtc/rooms/offers/list/0.3` (act 0.6), else 0.2 (act 0.4), else 0.1 (act 0.3),
/// each tried when the member's VTA or the community does not serve the one before. Which
/// one answered is returned beside them.
async fn list_offers(
    client: &VtaClient,
    target: &OfferTarget<'_>,
) -> Result<(OffersListing, OffersListVersion), Box<dyn std::error::Error>> {
    let mut last = None;
    for at in [
        OffersListVersion::V0_3,
        OffersListVersion::V0_2,
        OffersListVersion::V0_1,
    ] {
        match list_offers_at(client, target, at).await {
            Ok(listing) => return Ok((listing, at)),
            Err(e) if e.unsupported() => last = Some(e),
            Err(e) => return Err(e.report(target)),
        }
    }
    Err(last.expect("every version tried").report(target))
}

/// `pnm rooms offers list` — the rooms the community has offered you, each with what it is
/// for when the community says.
pub async fn cmd_rooms_offers_list(
    client: &VtaClient,
    target: OfferTarget<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ((offers, renewals), _) = list_offers(client, &target).await?;
    if offers.is_empty() && renewals.is_empty() {
        println!(
            "No offers from {} are addressed to {}.",
            target.vtc_did, target.member
        );
        return Ok(());
    }
    for o in &offers {
        print!("{}", offer_lines(o, &target));
    }
    for r in &renewals {
        print!("{}", renewal_lines(r, &target));
    }
    Ok(())
}

/// The lines `pnm rooms offers list` prints for one renewal, with the command that collects
/// it.
fn renewal_lines(r: &CommunityRenewal, target: &OfferTarget<'_>) -> String {
    let actions: Vec<String> = r.actions.0.iter().map(ToString::to_string).collect();
    format!(
        "{}  {}  [{}]  {}  renewal  until {} (renews {})\n  renew: {}\n",
        r.room_id.as_str(),
        inert(r.label.as_str()),
        r.visibility,
        actions.join(","),
        r.valid_until.to_rfc3339(),
        r.renews.to_rfc3339(),
        renew_command(r.room_id.as_str(), target),
    )
}

/// The `pnm rooms offers renew` line for one renewal, ready to paste.
fn renew_command(room_id: &str, target: &OfferTarget<'_>) -> String {
    format!(
        "pnm rooms offers renew --room {} --vtc {} --vtc-did {} --member {}",
        shell_word(room_id),
        shell_word(target.vtc_url),
        shell_word(target.vtc_did),
        shell_word(target.member),
    )
}

/// The vault handle under which the member's VTA holds the `type_tag` credential `room_id`
/// issued `member`: `None` when it holds none. More than one is refused — a key holder that
/// holds two cannot choose between them, and nor can this client.
async fn held_room_credential(
    client: &VtaClient,
    room_id: &str,
    member: &str,
    type_tag: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let found = client
        .cred_vault_query(serde_json::json!({ "type": type_tag, "issuerDid": room_id }))
        .await
        .map_err(|e| format!("your VTA's credential vault did not answer a query: {e}"))?;
    let mut mine = Vec::new();
    for descriptor in found["credentials"].as_array().cloned().unwrap_or_default() {
        let Some(id) = descriptor["id"].as_str() else {
            continue;
        };
        let got = client
            .cred_vault_get(id)
            .await
            .map_err(|e| format!("your VTA's credential vault did not return {id}: {e}"))?;
        if got["credential"]["credentialSubject"]["id"].as_str() == Some(member) {
            mine.push(id.to_string());
        }
    }
    match mine.len() {
        0 => Ok(None),
        1 => Ok(mine.pop()),
        n => Err(format!(
            "your VTA holds {n} {type_tag}s that {room_id} issued {member}, and acts on the \
             room with none of them until one is left: remove the older (`pnm cred-vault \
             delete`) and renew again"
        )
        .into()),
    }
}

/// `pnm rooms offers renew` — collect a renewal of a room you are in: store its membership
/// and authority in your VTA in place of the ones they renew (`vtc/rooms/offers/list/0.3`
/// surface items 1–3). Storing one already stored is success, so any surface may collect it
/// first.
pub async fn cmd_rooms_offers_renew(
    client: &VtaClient,
    target: OfferTarget<'_>,
    room_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ((_, renewals), at) = list_offers(client, &target).await?;
    if at != OffersListVersion::V0_3 {
        return Err(format!(
            "{} answered at vtc/rooms/offers/list/{}, which carries no renewals: the \
             community, or your VTA (rooms/keys/act 0.6 signs list 0.3), predates them",
            target.vtc_did,
            if at == OffersListVersion::V0_2 {
                "0.2"
            } else {
                "0.1"
            }
        )
        .into());
    }
    let renewal = renewals
        .into_iter()
        .find(|r| r.room_id.as_str() == room_id)
        .ok_or_else(|| {
            format!(
                "{} lists no renewal of {room_id} for {}: `pnm rooms offers list` shows what it \
                 has for you",
                target.vtc_did, target.member
            )
        })?;
    for (what, type_tag, credential) in [
        (
            "membership",
            "MembershipCredential",
            renewal.credentials.membership.as_str(),
        ),
        (
            "authority",
            "AuthorityCredential",
            renewal.credentials.authority.as_str(),
        ),
    ] {
        let body: Value = serde_json::from_str(credential)
            .map_err(|e| format!("the renewal's {what} credential is not JSON: {e}"))?;
        let replaces = held_room_credential(client, room_id, target.member, type_tag).await?;
        client
            .cred_vault_receive(body, replaces.as_deref())
            .await
            .map_err(|e| {
                format!("your VTA's credential vault refused the renewed {what} credential: {e}")
            })?;
    }
    println!(
        "Renewed {room_id} for {}: valid until {} (it was until {}).",
        target.member,
        renewal.valid_until.to_rfc3339(),
        renewal.renews.to_rfc3339(),
    );
    Ok(())
}

/// The lines `pnm rooms offers list` prints for one offer. The label and description are
/// the community's text: control characters in them never reach the terminal, and the
/// description is kept to one line.
fn offer_lines(o: &CommunityOffer, target: &OfferTarget<'_>) -> String {
    use trust_tasks_rs::specs::vtc::rooms::offers::list::v0_2::OfferV2State;
    let actions: Vec<String> = o.actions.0.iter().map(ToString::to_string).collect();
    let mut out = format!(
        "{}  {}  [{}]  {}  {}  until {}\n",
        o.room_id.as_str(),
        inert(o.label.as_str()),
        o.visibility,
        actions.join(","),
        o.state,
        o.valid_until.to_rfc3339(),
    );
    if let Some(description) = &o.description {
        out.push_str(&format!("  about: {}\n", one_line(description.as_str())));
    }
    if o.state == OfferV2State::Open {
        out.push_str(&format!(
            "  accept: {}\n",
            accept_command(o.room_id.as_str(), target)
        ));
    }
    out
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

/// The `pnm rooms offers accept` line for one offer, ready to paste: every value filled in,
/// so the operator never types a `<placeholder>` a shell reads as a redirect.
fn accept_command(room_id: &str, target: &OfferTarget<'_>) -> String {
    format!(
        "pnm rooms offers accept --room {} --vtc {} --vtc-did {} --member {}",
        shell_word(room_id),
        shell_word(target.vtc_url),
        shell_word(target.vtc_did),
        shell_word(target.member),
    )
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

/// `pnm rooms offers accept` — take up an offer: store its credentials in your VTA, mint a
/// KeyPackage there on a sealed tier, accept as the member, and join with the Welcome.
///
/// `key_package` reuses a KeyPackage your VTA minted for this member and room — for a run
/// whose answer was lost after the community admitted you, so the retry is the identical
/// acceptance the community (and its VTA) answers with the same Welcome.
pub async fn cmd_rooms_offers_accept(
    client: &VtaClient,
    target: OfferTarget<'_>,
    room_id: &str,
    key_package: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use trust_tasks_rs::Payload as _;
    use trust_tasks_rs::specs::vtc::rooms::offers::accept::v0_1 as accept;

    let ((offers, _), _) = list_offers(client, &target).await?;
    let offer = offers
        .into_iter()
        .find(|o| o.room_id.as_str() == room_id)
        .ok_or_else(|| {
            format!(
                "{} has no open offer to {room_id} addressed to {}: `pnm rooms offers list` \
                 shows what it has offered you",
                target.vtc_did, target.member
            )
        })?;
    let sealed = offer.visibility.to_string() != "open";

    // The membership and authority credentials the room issued the member, into the VTA's
    // vault, where its presentation oracle finds them for every later room request. Stored
    // under their own ids, so a second run replaces rather than duplicates.
    for (what, credential) in [
        ("membership", offer.credentials.membership.as_str()),
        ("authority", offer.credentials.authority.as_str()),
    ] {
        let body: Value = serde_json::from_str(credential)
            .map_err(|e| format!("the offer's {what} credential is not JSON: {e}"))?;
        client.cred_vault_receive(body, None).await.map_err(|e| {
            format!("your VTA's credential vault refused the {what} credential: {e}")
        })?;
    }
    let invitation = offer.credentials.invitation.as_str();

    // Joined already — here, or from another surface: nothing to accept, and minting
    // again would only make a KeyPackage nobody admits.
    if sealed && holds_group(client, room_id, target.member).await? {
        println!(
            "{room_id} is already joined as {} by your VTA — accepted here or from another \
             surface. Nothing to do.",
            target.member
        );
        return Ok(());
    }

    let key_package = match (sealed, key_package) {
        (false, _) => None,
        (true, Some(src)) => Some(std::fs::read_to_string(src)?.trim().to_string()),
        // From the VTA, never made here: act completes an acceptance only with a KeyPackage
        // the same key holder minted for this member and room.
        (true, None) => Some(offered_key_package(client, room_id, invitation).await?),
    };

    let mut payload = serde_json::json!({ "roomId": room_id });
    if let Some(kp) = &key_package {
        payload["keyPackage"] = Value::String(kp.clone());
    }
    let reply = act_and_send_offer(client, &target, accept::Payload::TYPE_URI, payload)
        .await
        .map_err(|e| e.report(&target))
        .map_err(|e| match &key_package {
            Some(kp) => format!(
                "{e}\n\nIf the community may have admitted you, retry the identical acceptance \
                 with this KeyPackage (save it to a file and pass --key-package <file>):\n{kp}"
            ),
            None => e.to_string(),
        })?;
    let accepted: accept::Response = parse_reply("vtc/rooms/offers/accept", reply)?;

    match &accepted.welcome {
        Some(welcome) => {
            let joined = client
                .idempotent(|| {
                    client.room_welcome(
                        room_id,
                        invitation,
                        welcome.as_str(),
                        accepted.ratchet_tree.as_ref().map(|t| t.as_str()),
                    )
                })
                .await;
            match joined {
                Ok(joined) => println!(
                    "Accepted {room_id} as {} and joined its group at room epoch {}.",
                    target.member,
                    joined.epoch + 1
                ),
                // Another surface handed the same Welcome over first: joined all the same.
                Err(e) if e.to_string().contains("alreadyJoined") => println!(
                    "Accepted {room_id} as {}; your VTA had already joined its group from \
                     another surface.",
                    target.member
                ),
                Err(e) => {
                    return Err(format!(
                        "admitted at room epoch {}, but your VTA did not join from the \
                         Welcome: {e}",
                        accepted.epoch
                    )
                    .into());
                }
            }
        }
        None if sealed => {
            return Err(format!(
                "the community admitted you to sealed room {room_id} but sent no Welcome"
            )
            .into());
        }
        None => println!(
            "Accepted {room_id} as {}; the room is open, at epoch {}.",
            target.member, accepted.epoch
        ),
    }
    println!(
        "  Read it with `pnm rooms list --room {room_id} --host {} --host-did {}`.",
        target.vtc_url,
        offer.host.as_str()
    );
    Ok(())
}

/// Whether the VTA holds `room`'s group for `member` (`rooms/keys/list`): custody, which
/// with the community's record is what every surface shows the member.
async fn holds_group(
    client: &VtaClient,
    room: &str,
    member: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let held = client.room_list(false).await?;
    Ok(held
        .rooms
        .iter()
        .any(|r| r.room_id.as_str() == room && r.member.as_str() == member))
}

/// The KeyPackage for an acceptance: the one the VTA already holds for this room, member
/// and invitation — which another surface may already have sent — or a new one
/// (`rooms/keys/key-package/0.2`).
async fn offered_key_package(
    client: &VtaClient,
    room: &str,
    invitation: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let kp = client.room_key_package(room, invitation).await?;
    if kp.already_minted {
        eprintln!(
            "Your VTA already held a KeyPackage for this offer — another surface may \
             have begun this acceptance; finishing it."
        );
    }
    Ok(kp.key_package.to_string())
}

/// `vtc/rooms/memberships/list/0.1`, signed as the member: the community's whole record of
/// their admissions (one page at a time).
async fn list_memberships(
    client: &VtaClient,
    target: &OfferTarget<'_>,
) -> Result<
    Vec<trust_tasks_rs::specs::vtc::rooms::memberships::list::v0_1::RoomMembership>,
    Box<dyn std::error::Error>,
> {
    use trust_tasks_rs::Payload as _;
    use trust_tasks_rs::specs::vtc::rooms::memberships::list::v0_1 as list;
    let mut items = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let payload = match &cursor {
            Some(c) => serde_json::json!({ "cursor": c }),
            None => serde_json::json!({}),
        };
        let reply = act_and_send_offer(client, target, list::Payload::TYPE_URI, payload)
            .await
            .map_err(|e| e.report(target))?;
        let page: list::Response = parse_reply("vtc/rooms/memberships/list", reply)?;
        items.extend(page.items);
        match page.next_cursor {
            Some(next) => cursor = Some(next.to_string()),
            None => return Ok(items),
        }
    }
}

/// What a surface shows for one room — `vtc/rooms/memberships/list/0.1` *One record, every
/// surface*: the community's state and the key holder's custody, read the same way by
/// every surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomStanding {
    /// Offered and not yet accepted.
    Offered,
    /// Admitted, and openable: an open room, or a sealed one whose group the VTA holds.
    Joined,
    /// Admitted to a sealed room whose group the VTA does not hold, while the community
    /// still keeps the Welcome: an acceptance to finish.
    Unfinished,
    /// Admitted to a sealed room whose group the VTA does not hold, and the Welcome is no
    /// longer kept: only an administrator re-admitting the member repairs it.
    NeedsReadmission,
    /// Removed by an administrator.
    Removed,
}

impl RoomStanding {
    /// The table in `vtc/rooms/memberships/list/0.1`.
    pub fn of(state: &str, sealed: bool, held: bool, welcome_kept: bool) -> Self {
        match state {
            "offered" => Self::Offered,
            "removed" => Self::Removed,
            _ if !sealed || held => Self::Joined,
            _ if welcome_kept => Self::Unfinished,
            _ => Self::NeedsReadmission,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Joined => "joined",
            Self::Unfinished => "accepted, not finished",
            Self::NeedsReadmission => "admitted, not openable here",
            Self::Removed => "removed",
        }
    }
}

/// `pnm rooms memberships` — every room the community has offered you and where each
/// stands, as every surface you use shows it: the community's record
/// (`vtc/rooms/memberships/list`) beside your VTA's custody (`rooms/keys/list`).
pub async fn cmd_rooms_memberships(
    client: &VtaClient,
    target: OfferTarget<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let rooms = list_memberships(client, &target).await?;
    if rooms.is_empty() {
        println!(
            "{} has offered no rooms to {}.",
            target.vtc_did, target.member
        );
        return Ok(());
    }
    let held = client.room_list(false).await?;
    for r in &rooms {
        let room_id = r.room_id.as_str();
        let holds = held
            .rooms
            .iter()
            .any(|h| h.room_id.as_str() == room_id && h.member.as_str() == target.member);
        let standing = RoomStanding::of(
            &r.state.to_string(),
            r.visibility.to_string() != "open",
            holds,
            r.repeat_accept_until.is_some(),
        );
        let actions: Vec<String> = r.actions.0.iter().map(ToString::to_string).collect();
        println!(
            "{room_id}  {}  [{}]  {}  {}",
            inert(r.label.as_str()),
            r.visibility,
            actions.join(","),
            standing.label(),
        );
        match standing {
            RoomStanding::Offered | RoomStanding::Unfinished => {
                println!("  accept: {}", accept_command(room_id, &target));
            }
            RoomStanding::NeedsReadmission => println!(
                "  Your VTA never joined this room's group and the community no longer keeps \
                 the Welcome: ask an administrator to remove and re-admit you."
            ),
            RoomStanding::Joined | RoomStanding::Removed => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn prune_target() -> RoomTarget<'static> {
        RoomTarget {
            host_url: "https://host.example",
            host_did: Some("did:web:host.example"),
            room_id: "did:webvh:Qm:example.com:rooms:northwind",
        }
    }

    /// rooms/epoch/prune/0.2 *Consent/purpose*: `--yes` always proceeds; without it a
    /// terminal is asked and a pipe is refused — never pruned unasked.
    #[test]
    fn a_prune_without_yes_asks_a_terminal_and_refuses_a_pipe() {
        assert_eq!(prune_guard(true, false), PruneGuard::Proceed);
        assert_eq!(prune_guard(true, true), PruneGuard::Proceed);
        assert_eq!(prune_guard(false, true), PruneGuard::Ask);
        assert_eq!(prune_guard(false, false), PruneGuard::Refuse);
    }

    /// The warning says what becomes unreadable, that it cannot be undone, that the
    /// records stay, and that members' VTAs keep what they already derived.
    #[test]
    fn the_prune_warning_names_what_becomes_unreadable() {
        // `beforeEpoch: 5` → floor 4: rung 5 still yields epoch 4, so epochs 1 to 3 go
        // (`rooms/epoch/prune/0.2`, *The floor, and the off-by-one*).
        let w = prune_warning("did:example:room", 5, 7, Some("chained"));
        assert!(w.contains("cannot be undone"), "{w}");
        assert!(w.contains("epochs 1 to 3"), "{w}");
        assert!(w.contains("epoch floor (4)"), "{w}");
        assert!(w.contains("now at epoch 7"), "{w}");
        assert!(w.contains("The records stay"), "{w}");
        assert!(w.contains("members' VTAs"), "{w}");
        assert!(!w.contains("fromJoin"), "{w}");

        assert!(prune_warning("r", 3, 4, None).contains("unreadable for good"));
        assert!(prune_warning("r", 3, 4, None).contains("epoch 1 "));
        assert!(prune_warning("r", 2, 3, None).contains("nothing becomes unreadable"));
        assert!(prune_warning("r", 3, 4, Some("fromJoin")).contains("keeps no chain"));
    }

    /// `notAhead`, refused locally with the highest floor that works, as a command.
    #[test]
    fn a_floor_at_the_current_epoch_suggests_the_one_below() {
        let t = prune_target();
        let msg = not_ahead_message(&t, 7, 7);
        assert!(msg.contains("current epoch 7"), "{msg}");
        assert!(
            msg.contains(
                "pnm rooms prune --room did:webvh:Qm:example.com:rooms:northwind \
                 --host https://host.example --host-did did:web:host.example \
                 --before-epoch 6 --reason '<why>' --yes"
            ),
            "{msg}"
        );
        // At epoch 1 there is no floor below to suggest.
        assert!(!not_ahead_message(&t, 1, 1).contains("pnm rooms prune"));
    }

    /// The host's declared codes are answered with the fix, not the bare error.
    #[test]
    fn a_hosts_prune_refusal_is_explained() {
        let t = prune_target();
        let refusal = |code: &str| vtc_client::VtcError::Http {
            status: 400,
            body: json!({
                "type": "https://trusttasks.org/spec/trust-task-error/0.1",
                "payload": { "code": code, "message": "no" },
            })
            .to_string(),
        };
        let msg = prune_refused(refusal("rooms/epoch/prune:notAhead"), &t, 7, 7);
        assert!(msg.contains("--before-epoch 6"), "{msg}");
        let msg = prune_refused(refusal("permissionDenied"), &t, 3, 7);
        assert!(msg.contains("needs `admin`"), "{msg}");
        assert!(msg.contains("issue-authority --action admin"), "{msg}");
        let msg = prune_refused(refusal("rooms/epoch/prune:chainTooDeep"), &t, 3, 7);
        assert!(!msg.contains("needs `admin`"), "{msg}");
    }

    /// `pruned: 0` is a success, and the reach printed is `earliestRung`, not the floor.
    #[test]
    fn a_prune_outcome_reports_reach_not_the_request() {
        let r = |pruned, earliest_rung| vtc_client::rooms::PruneResponse {
            room_id: "did:example:room".into(),
            pruned,
            earliest_rung,
        };
        let none = prune_outcome(&r(0, 3));
        assert!(none.contains("nothing to drop"), "{none}");
        assert!(none.contains("reaches back to epoch 3"), "{none}");
        assert!(prune_outcome(&r(1, 5)).contains("1 rung dropped"));
        assert!(prune_outcome(&r(4, 5)).contains("4 rungs dropped"));
    }

    fn rejected(code: &str, details: Value) -> VtaError {
        VtaError::Rejected {
            code: code.into(),
            message: "refused".into(),
            details: Some(details),
        }
    }

    /// `earlierRemovalRefused` at add 0.3 / renew 0.2 / remove 0.3, and an earlier
    /// version's `hostRefused` carrying the same `details`, are explained alike; a
    /// `hostRefused` of the request's own advance (`{code, reason}`) is not.
    #[test]
    fn an_earlier_removal_is_explained_whichever_version_reported_it() {
        let d =
            json!({ "member": "did:key:zEarlier", "code": "permissionDenied", "listKept": true });
        for code in [
            "rooms/owner/group/add:earlierRemovalRefused",
            "rooms/owner/group/renew:earlierRemovalRefused",
            "rooms/owner/group/remove:earlierRemovalRefused",
            "rooms/owner/group/add:hostRefused",
            "rooms/owner/group/renew:hostRefused",
        ] {
            let said = earlier_removal_refused(
                &rejected(code, d.clone()),
                "did:room",
                "did:host",
                None,
                "admit did:key:zNew",
            )
            .unwrap_or_else(|| panic!("{code} is an earlier removal"));
            assert!(said.starts_with("Nothing was done"), "{said}");
            assert!(said.contains("did:key:zEarlier"), "{said}");
            assert!(
                said.contains("pnm rooms owner revoke --room did:room"),
                "{said}"
            );
            assert!(said.contains("again to admit did:key:zNew"), "{said}");
        }
        let own = rejected(
            "rooms/owner/group/add:hostRefused",
            json!({ "code": "permissionDenied", "reason": "not today" }),
        );
        assert!(earlier_removal_refused(&own, "r", "h", None, "x").is_none());
        let kept_not = rejected(
            "rooms/owner/group/renew:earlierRemovalRefused",
            json!({ "member": "did:key:zEarlier", "code": "rooms/revocations/put:listInvalid",
                "listKept": false }),
        );
        let said = earlier_removal_refused(&kept_not, "r", "h", None, "x").unwrap();
        assert!(said.contains("discarded"), "{said}");
    }

    /// `vtc/rooms/memberships/list/0.1`'s table: the same answers, the same standing.
    #[test]
    fn a_rooms_standing_follows_the_one_record() {
        use RoomStanding::*;
        assert_eq!(RoomStanding::of("offered", true, false, false), Offered);
        assert_eq!(RoomStanding::of("admitted", false, false, false), Joined);
        assert_eq!(RoomStanding::of("admitted", true, true, true), Joined);
        assert_eq!(RoomStanding::of("admitted", true, false, true), Unfinished);
        assert_eq!(
            RoomStanding::of("admitted", true, false, false),
            NeedsReadmission
        );
        assert_eq!(RoomStanding::of("removed", true, true, false), Removed);
    }

    fn minted(authority: Value) -> Value {
        json!({
            "presentation": {
                "membership": "vmc-blob",
                "authority": authority,
            },
            "expiresAt": "2026-09-07T16:00:00Z",
        })
    }

    fn vtc_target() -> RoomTarget<'static> {
        RoomTarget {
            host_url: "https://community.example/v1",
            host_did: Some("did:webvh:community.example"),
            room_id: "did:webvh:example.com:rooms:northwind",
        }
    }

    const CATCH_UP: &str = "pnm rooms keys commit --room did:webvh:example.com:rooms:northwind \
                            --host https://community.example/v1 --host-did did:webvh:community.example";

    /// An offer's accept line carries the offer's own room DID and runs as pasted.
    #[test]
    fn an_offer_prints_its_accept_command_with_the_room_filled_in() {
        let target = OfferTarget {
            vtc_url: "https://vtc.example/v1",
            vtc_did: "did:webvh:Qm1:vtc.example",
            member: "did:webvh:Qm2:alice.example",
        };
        assert_eq!(
            accept_command("did:webvh:Qm3:vtc.example:room-dids:ab12", &target),
            "pnm rooms offers accept --room did:webvh:Qm3:vtc.example:room-dids:ab12 \
             --vtc https://vtc.example/v1 --vtc-did did:webvh:Qm1:vtc.example \
             --member did:webvh:Qm2:alice.example"
        );
    }

    fn offer_v2(description: Option<&str>) -> Value {
        let mut o = json!({
            "roomId": "did:webvh:Qm3:vtc.example:room-dids:ab12",
            "host": "did:webvh:Qm1:vtc.example",
            "label": "Board\u{1b}[2J papers",
            "visibility": "private",
            "actions": ["read", "write"],
            "validUntil": "2026-12-01T00:00:00Z",
            "offeredAt": "2026-10-01T00:00:00Z",
            "state": "open",
            "credentials": {
                "membership": "{}",
                "authority": "{}",
                "invitation": "inv"
            }
        });
        if let Some(d) = description {
            o["description"] = json!(d);
        }
        o
    }

    fn offer_target() -> OfferTarget<'static> {
        OfferTarget {
            vtc_url: "https://vtc.example/v1",
            vtc_did: "did:webvh:Qm1:vtc.example",
            member: "did:webvh:Qm2:alice.example",
        }
    }

    /// `vtc/rooms/offers/list/0.2`: an offer shows what its room is for, on one line of its
    /// own, with every control character the community wrote replaced — a line break
    /// cannot forge a line of this client's, an escape cannot reach the terminal.
    #[test]
    fn an_offer_shows_its_description_on_one_inert_line() {
        let offer: CommunityOffer = serde_json::from_value(offer_v2(Some(
            "Papers for the board:\nagenda\tminutes\u{7}\r\n  accept: rm -rf ~",
        )))
        .unwrap();
        let text = offer_lines(&offer, &offer_target());
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "{text}");
        assert!(lines[0].contains("Board[2J papers"), "{text}");
        assert!(
            !text.contains('\u{1b}') && !text.contains('\u{7}'),
            "{text}"
        );
        assert_eq!(
            lines[1],
            "  about: Papers for the board: agenda minutes     accept: rm -rf ~"
        );
        assert!(
            lines[2].starts_with("  accept: pnm rooms offers accept"),
            "{text}"
        );

        // A room without a description (or an offer read at 0.1) prints no `about` line.
        let bare: CommunityOffer = serde_json::from_value(offer_v2(None)).unwrap();
        assert!(!offer_lines(&bare, &offer_target()).contains("about:"));
    }

    /// An offer read at `vtc/rooms/offers/list/0.1` reads as 0.2's, with no description.
    #[test]
    fn an_offers_list_0_1_page_reads_as_0_2() {
        let mut v1 = offer_v2(None);
        v1["label"] = json!("Board");
        let (items, next, _) = offers_page(
            OffersListVersion::V0_1,
            json!({ "items": [v1], "nextCursor": "c2" }),
        )
        .expect("a 0.1 page");
        assert_eq!(items.len(), 1);
        assert!(items[0].description.is_none());
        assert_eq!(next.as_deref(), Some("c2"));

        let (items, next, renewals) = offers_page(
            OffersListVersion::V0_2,
            json!({ "items": [offer_v2(Some("What it is for"))] }),
        )
        .expect("a 0.2 page");
        assert_eq!(
            items[0].description.as_ref().map(|d| d.as_str()),
            Some("What it is for")
        );
        assert!(next.is_none());
        assert!(renewals.is_empty(), "0.2 carries no renewals");
    }

    /// `vtc/rooms/offers/list/0.3`: the offers, and the renewals of rooms the member is in,
    /// each printed with the command that collects it.
    #[test]
    fn an_offers_list_0_3_page_carries_renewals_and_their_renew_command() {
        let (items, _, renewals) = offers_page(
            OffersListVersion::V0_3,
            json!({
                "items": [offer_v2(None)],
                "renewals": [{
                    "roomId": "did:webvh:Qm:rooms.example:wg", "host": "did:example:community",
                    "label": "Working group", "visibility": "attributed", "actions": ["read"],
                    "validUntil": "2027-11-10T00:00:00Z", "renews": "2026-11-10T00:00:00Z",
                    "issuedAt": "2026-10-20T09:00:00Z",
                    "credentials": { "membership": "{}", "authority": "{}" },
                }],
            }),
        )
        .expect("a 0.3 page");
        assert_eq!(items.len(), 1);
        assert_eq!(renewals.len(), 1);
        let lines = renewal_lines(&renewals[0], &offer_target());
        assert!(lines.contains("renewal  until 2027-11-10"), "{lines}");
        assert!(
            lines.contains("pnm rooms offers renew --room did:webvh:Qm:rooms.example:wg"),
            "{lines}"
        );
    }

    /// The fallback cue: `unsupportedType` / `unsupportedVersion` from either party — the
    /// member's VTA (act 0.4) or the community (offers/list 0.2) — and nothing else.
    #[test]
    fn only_an_unsupported_answer_falls_back_to_offers_list_0_1() {
        let community = |code: &str| {
            OfferStepError::Community(vtc_client::VtcError::Http {
                status: 400,
                body: json!({
                    "type": "https://trusttasks.org/spec/trust-task-error/0.5",
                    "payload": { "code": code, "message": "no" }
                })
                .to_string(),
            })
        };
        assert!(community("unsupportedType").unsupported());
        assert!(community("unsupportedVersion").unsupported());
        assert!(!community("vtc/rooms/offers/list:notAMember").unsupported());
        assert!(!community("permissionDenied").unsupported());
        assert!(
            !OfferStepError::Community(vtc_client::VtcError::Http {
                status: 502,
                body: "bad gateway".into(),
            })
            .unsupported()
        );

        assert!(
            OfferStepError::Act(VtaError::UnsupportedTaskType {
                type_uri: "https://trusttasks.org/spec/rooms/keys/act/0.4".into(),
                served_versions: vec![],
            })
            .unsupported()
        );
        assert!(
            !OfferStepError::Act(VtaError::Rejected {
                code: "rooms/keys/act:issuerNotPrincipal".into(),
                message: "no".into(),
                details: None,
            })
            .unsupported()
        );
    }

    /// A room DID is the community's text: anything a shell would act on is quoted.
    #[test]
    fn a_room_id_a_shell_would_read_is_quoted() {
        assert_eq!(shell_word("did:web:x"), "did:web:x");
        assert_eq!(shell_word("a;rm -rf ~"), "'a;rm -rf ~'");
        assert_eq!(shell_word("it's"), r"'it'\''s'");
        assert_eq!(shell_word("$(x)"), "'$(x)'");
        assert_eq!(shell_word(""), "''");
    }

    /// A put sealed under a superseded epoch (`epochMismatch`, read off the host's
    /// `trust-task-error` document) names the catch-up command with the real values, not
    /// the raw HTTP body.
    #[test]
    fn a_superseded_epoch_put_prints_keys_commit_with_the_real_values() {
        let body = json!({
            "type": "https://trusttasks.org/spec/rooms/records/put/0.1#error",
            "payload": {
                "code": "rooms/records/put:epochMismatch",
                "message": "record is sealed under epoch 2, room `r` is at 3",
            },
        });
        let err: Box<dyn std::error::Error> = Box::new(vtc_client::VtcError::Http {
            status: 400,
            body: body.to_string(),
        });
        let text = put_refused(err, &vtc_target()).to_string();
        assert!(text.contains(CATCH_UP), "{text}");
        assert!(text.contains("sealed under epoch 2"), "{text}");
        assert!(!text.contains("HTTP 400"), "{text}");
    }

    /// Any other refusal passes through untouched, and no `--host-did` is invented for a
    /// host the operator named none for.
    #[test]
    fn other_put_refusals_pass_through_and_no_host_did_is_invented() {
        let t = vtc_target();
        assert!(put_refusal_hint("rooms/records/put:recordTooLarge", "", &t).is_none());
        let err: Box<dyn std::error::Error> = Box::new(vtc_client::VtcError::Http {
            status: 500,
            body: "not a document".into(),
        });
        assert_eq!(
            put_refused(err, &t).to_string(),
            "VTC returned HTTP 500: not a document"
        );

        let bare = RoomTarget {
            host_did: None,
            ..vtc_target()
        };
        assert_eq!(
            keys_commit_command(&bare),
            "pnm rooms keys commit --room did:webvh:example.com:rooms:northwind \
             --host https://community.example/v1"
        );
    }

    fn open_rejected(reason: &str, extra: Value) -> VtaError {
        let mut details = json!({ "reason": reason });
        details
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        VtaError::Rejected {
            code: "rooms/keys/open:unknownEpoch".into(),
            message: "record is sealed under epoch 4".into(),
            details: Some(details),
        }
    }

    /// A member removed from the group is told so, and is not sent to `keys commit`,
    /// which can never open what was sealed after the removal.
    #[test]
    fn a_removed_member_is_told_it_was_removed_not_to_catch_up() {
        let text = open_refusal_hint(
            &open_rejected("removed", json!({ "removedAtEpoch": 3 })),
            &vtc_target(),
        );
        assert!(
            text.contains("You were removed from this room's group at epoch 3"),
            "{text}"
        );
        assert!(!text.contains("keys commit"), "{text}");
    }

    fn file_key_rejected(reason: &str, message: &str) -> VtaError {
        VtaError::Rejected {
            code: "rooms/keys/file-key:unknownEpoch".into(),
            message: message.into(),
            details: Some(json!({ "reason": reason })),
        }
    }

    /// `pnm rooms file get` names the same remedies a record's refusal does. A removed
    /// member's file comes as `removed` (`rooms/keys/file-key/0.2`), and the operator is
    /// told so and not sent to `keys commit` — the caller MUST NOT retry after catching up.
    #[test]
    fn a_file_key_refusal_names_the_remedy() {
        let removed = VtaError::Rejected {
            code: "rooms/keys/file-key:unknownEpoch".into(),
            message: "the file is sealed under epoch 4, and this member was removed".into(),
            details: Some(json!({ "reason": "removed", "removedAtEpoch": 3 })),
        };
        let text = file_key_refusal_hint(&removed, &vtc_target());
        assert!(
            text.contains("You were removed from this room's group at epoch 3"),
            "{text}"
        );
        assert!(text.contains("Files sealed since then"), "{text}");
        assert!(!text.contains("keys commit"), "{text}");

        // Only behind: catch up.
        let behind_commit = file_key_refusal_hint(
            &file_key_rejected("notDelivered", "the file is sealed under epoch 4"),
            &vtc_target(),
        );
        assert!(behind_commit.contains(CATCH_UP), "{behind_commit}");

        let behind = file_key_refusal_hint(
            &file_key_rejected("beyondChain", "sealed under epoch 1"),
            &vtc_target(),
        );
        assert!(behind.contains("pnm rooms keys backfill"), "{behind}");
        assert!(behind.contains("The file is older"), "{behind}");

        // An `open` code is not a file-key one: the reason is not read across tasks.
        let wrong_task = VtaError::Rejected {
            code: "rooms/keys/open:unknownEpoch".into(),
            message: "x".into(),
            details: Some(json!({ "reason": "beyondChain" })),
        };
        assert!(
            file_key_refusal_hint(&wrong_task, &vtc_target()).contains("did not open with any key")
        );
    }

    /// A member who is only behind gets the catch-up command with the real values.
    #[test]
    fn a_member_behind_is_told_to_catch_up() {
        let text = open_refusal_hint(
            &open_rejected("notDelivered", json!({ "heldEpoch": 2 })),
            &vtc_target(),
        );
        assert!(text.contains(CATCH_UP), "{text}");
    }

    /// `pnm rooms renew` refuses a sealed room and names the command that renews it
    /// (rooms/keys/act/0.3 producer item 4); an open room renews as before.
    #[test]
    fn renew_refuses_a_sealed_room_and_names_group_renew() {
        let target = RoomTarget {
            host_url: "https://community.example/v1",
            host_did: Some("did:webvh:community.example"),
            room_id: "did:webvh:example.com:rooms:northwind",
        };
        assert!(refuse_sealed_renew("open", &target).is_ok());
        for tier in ["attributed", "private"] {
            let e = refuse_sealed_renew(tier, &target).expect_err(tier);
            assert!(
                e.contains(
                    "pnm rooms owner group-renew --room did:webvh:example.com:rooms:northwind \
                     --host-did did:webvh:community.example"
                ),
                "{e}"
            );
            assert!(e.contains(tier), "{e}");
        }
        let no_did = RoomTarget {
            host_did: None,
            ..target
        };
        let e = refuse_sealed_renew("private", &no_did).unwrap_err();
        assert!(e.contains("--host-did <the host's DID>"), "{e}");
    }

    #[test]
    fn a_minted_presentation_becomes_a_session() {
        let session = session_from_minted("did:webvh:room", &minted(json!(["leaf", "root"])))
            .expect("a well-formed reply rebuilds");
        assert_eq!(session.room_id(), "did:webvh:room");
        assert_eq!(session.chain_depth(), 2, "leaf first, root last");
    }

    /// A private room's presentation carries the same-subject proof, and losing
    /// it on the way through would turn a valid call into a refusal the
    /// operator cannot explain.
    #[test]
    fn a_subject_binding_survives_the_rebuild() {
        let mut m = minted(json!(["leaf"]));
        m["presentation"]["subjectBinding"] = json!("zk-proof-blob");
        let session =
            session_from_minted("did:webvh:room", &m).expect("a private presentation rebuilds");
        assert_eq!(session.chain_depth(), 1);
    }

    /// Each missing member is refused rather than defaulted. A reply this
    /// client does not understand must not become a request the host refuses
    /// for reasons that read as a credential problem.
    #[test]
    fn an_unreadable_reply_is_refused_rather_than_guessed() {
        assert!(
            session_from_minted("r", &json!({})).is_err(),
            "no presentation"
        );
        assert!(
            session_from_minted("r", &json!({ "presentation": { "authority": ["a"] } })).is_err(),
            "no membership"
        );
        assert!(
            session_from_minted("r", &json!({ "presentation": { "membership": "m" } })).is_err(),
            "no chain"
        );
        assert!(
            session_from_minted("r", &minted(json!([]))).is_err(),
            "an empty chain authorizes nothing and must not be sent"
        );
    }

    /// A link that is not a string would otherwise be filtered out, silently
    /// shortening the chain — and a shorter chain confers less than the VTA
    /// minted, so the call would fail somewhere far from the cause.
    #[test]
    fn a_malformed_link_does_not_silently_shorten_the_chain() {
        let err = session_from_minted("r", &minted(json!(["leaf", 7])))
            .expect_err("a non-string link is refused");
        assert!(
            err.to_string().contains("non-string"),
            "the error must name the cause: {err}"
        );
    }

    /// Another member's text reaches a terminal: an escape sequence in it must not.
    #[test]
    fn untrusted_text_loses_its_control_characters_but_keeps_its_lines() {
        assert_eq!(inert("a\x1b[2Jb\nc\td\x07"), "a[2Jb\nc\td");
    }

    /// A file name chosen by another member must not choose where it is written.
    #[test]
    fn a_file_name_cannot_leave_the_directory_or_hide() {
        assert_eq!(local_name("../../etc/passwd"), "passwd");
        assert_eq!(local_name("C:\\Users\\x\\evil.exe"), "evil.exe");
        assert_eq!(local_name(".bashrc"), "bashrc");
        assert_eq!(local_name("term sheet.pdf"), "term sheet.pdf");
        assert_eq!(local_name("../"), "room-file");
        assert_eq!(local_name("a\nb.txt"), "a b.txt");
    }

    /// Record keys on a sealed tier say nothing, and do not repeat.
    #[test]
    fn opaque_keys_are_fresh_and_uninformative() {
        let (a, b) = (opaque_key(), opaque_key());
        assert_ne!(a, b);
        assert_eq!(a.len(), 22, "16 random bytes, base64url");
    }

    #[test]
    fn pin_flags_keep_unchanged_distinct_from_unpinned() {
        assert_eq!(pinned_from_flags(true, false), Some(true));
        assert_eq!(pinned_from_flags(false, true), Some(false));
        assert_eq!(
            pinned_from_flags(false, false),
            None,
            "neither flag must leave the pin alone, not clear it"
        );
    }
}
