//! `rooms watch`: through the VTA (one-shot or live), or through the host at an
//! address of the client's own.

use super::*;

/// What `rooms watch` asks for when the VTA watches (`rooms/keys/watch/0.1`).
#[derive(Debug, Clone)]
pub struct WatchThroughVta<'a> {
    /// The host's DID.
    pub host_did: &'a str,
    /// The rooms to watch there, each at most once (at most 64).
    pub room_ids: &'a [String],
    /// The member to watch as; `None` takes the one `rooms/keys/list` names for the rooms.
    pub member: Option<&'a str>,
    /// The host's URL, used only to find the member of an `open` room, which
    /// `rooms/keys/list` does not list.
    pub host_url: Option<&'a str>,
    /// The highest version read, for a single room.
    pub since: Option<u64>,
    /// How long each watch lasts if it does not fire, in seconds.
    pub lease_secs: Option<u64>,
    /// End the watches instead.
    pub cancel: bool,
}

/// `rooms watch` — ask your VTA to watch rooms at one host for you (`rooms/keys/watch/0.1`):
/// it arms the host's `rooms/watch` for each room as your member, at an address of its own
/// used for that one watch, and passes the host's one signal on to this client as
/// `rooms/keys/changed/0.1` — the way it sends a `task-consent/granted`. This client needs
/// no address a host can reach, and the host never learns it, or the VTA.
///
/// One signal per arming: read the room, then watch it again with `--since` the version
/// read to. A VTA that does not serve `rooms/keys/watch/0.1` is refused with what to do
/// instead: `--via-host` with an address of your own ([`cmd_rooms_watch_via_host`]), or
/// polling.
#[allow(deprecated)] // one-shot watches are rooms/keys/watch/0.1 and rooms/watch/0.1, still served
pub async fn cmd_rooms_watch(
    client: &VtaClient,
    req: WatchThroughVta<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if req.room_ids.is_empty() || req.room_ids.len() > vta_sdk::client::ROOM_WATCH_MAX_ROOMS {
        return Err(format!(
            "name 1 to {} rooms (--room) at one host",
            vta_sdk::client::ROOM_WATCH_MAX_ROOMS
        )
        .into());
    }
    if req.since.is_some() && req.room_ids.len() > 1 {
        return Err(
            "--since is the version one room was read to: watch one room with it, or \
                    watch several without it"
                .into(),
        );
    }
    let member = match req.member {
        Some(m) => m.to_string(),
        None => watch_member(client, &req).await?,
    };
    let host = req.host_did;
    let answer = if req.cancel {
        let rooms: Vec<&str> = req.room_ids.iter().map(String::as_str).collect();
        client.room_watch_cancel(&member, host, &rooms).await
    } else {
        let rooms: Vec<vta_sdk::client::RoomWatch> = req
            .room_ids
            .iter()
            .map(|r| vta_sdk::client::RoomWatch {
                room_id: r.clone(),
                since_version: req.since,
            })
            .collect();
        client
            .room_watch(&member, host, &rooms, req.lease_secs)
            .await
    }
    .map_err(|e| vta_watch_refused(e, &req, &member))?;
    if crate::render::is_json_output() {
        crate::render::print_json(&answer)?;
        return Ok(());
    }
    for w in &answer.watches {
        let room = wire_str(&w.room_id);
        match (w.armed, &w.expires_at, &w.refused) {
            (true, Some(until), _) => println!(
                "Watching room {room} as {member} until {}: your VTA passes on the host's one \
                 signal (rooms/keys/changed) when the room moves past {}, then nothing until \
                 you watch again.",
                wire_str(until),
                req.since.map_or_else(
                    || "its current version".to_string(),
                    |v| format!("version {v}")
                ),
            ),
            (true, None, _) => println!("Watching room {room} as {member}."),
            (false, _, Some(reason)) => {
                let reason = wire_str(reason);
                let host_code = w.host_code.as_ref().map(wire_str);
                println!(
                    "Not watching room {room}: {}",
                    watch_reason(&reason, host_code.as_deref())
                );
            }
            (false, _, None) => println!("No watch on room {room} any more."),
        }
    }
    Ok(())
}

/// `rooms watch --live` — a **live** watch through your VTA (`rooms/keys/watch/0.2`,
/// trust-tasks-tf #1087): a tail of the room while this command runs in the foreground.
/// Your VTA arms the host's `rooms/watch/0.2` live and passes on every signal the host
/// sends — coalesced to at most one a second — and each is printed as it arrives. The
/// watch is renewed about every [`vta_sdk::client::LIVE_RENEW_EVERY`] (the host leases at
/// most 120 seconds) and cancelled when the command ends (Ctrl-C), as Producer item 6 asks.
///
/// Only on a room whose signal delay is `none`: elsewhere the host refuses
/// `rooms/watch:liveNotPermitted`, and this says how to change the room's setting. A watch
/// answered without `live` — a VTA or host that implements only 0.1 — is one-shot, so this
/// cancels it and says so rather than tail a room that will signal once.
pub async fn cmd_rooms_watch_live(
    client: &VtaClient,
    req: WatchThroughVta<'_>,
    vta_did: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if req.cancel {
        return Err("--live arms a watch; cancel one with --cancel alone".into());
    }
    if req.room_ids.is_empty() || req.room_ids.len() > vta_sdk::client::ROOM_WATCH_MAX_ROOMS {
        return Err(format!(
            "name 1 to {} rooms (--room) at one host",
            vta_sdk::client::ROOM_WATCH_MAX_ROOMS
        )
        .into());
    }
    if req.since.is_some() && req.room_ids.len() > 1 {
        return Err(
            "--since is the version one room was read to: watch one room with it, or \
             watch several without it"
                .into(),
        );
    }
    let member = match req.member {
        Some(m) => m.to_string(),
        None => watch_member(client, &req).await?,
    };
    let host = req.host_did;
    let vta_did = vta_did.or(client.vta_did()).map(str::to_string);
    let rooms_at = |since: Option<u64>| -> Vec<vta_sdk::client::RoomWatch> {
        req.room_ids
            .iter()
            .map(|r| vta_sdk::client::RoomWatch {
                room_id: r.clone(),
                since_version: since,
            })
            .collect()
    };

    let answer = client
        .room_watch_live(&member, host, &rooms_at(req.since), req.lease_secs)
        .await
        .map_err(|e| vta_watch_refused(e, &req, &member))?;
    let live = live_rooms(&answer, &req)?;
    if live.is_empty() {
        cancel_live(client, &member, host, req.room_ids).await;
        return Err("no room is watched live; nothing to tail".into());
    }
    eprintln!(
        "Watching {} live as {member}: each signal is printed as it arrives. Ctrl-C ends \
         the watch.",
        live.join(", ")
    );

    let mut renew_at = tokio::time::Instant::now() + vta_sdk::client::LIVE_RENEW_EVERY;
    let mut failed_renewals = 0u32;
    let ended = loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break Ok(()),
            _ = tokio::time::sleep_until(renew_at) => {
                renew_at = tokio::time::Instant::now() + vta_sdk::client::LIVE_RENEW_EVERY;
                // A renewal names the room alone: the watch keeps the version it last
                // signalled as its watermark (`rooms/watch/0.2` Host item 3).
                match client
                    .room_watch_live(&member, host, &rooms_at(None), req.lease_secs)
                    .await
                {
                    Ok(renewed) => {
                        failed_renewals = 0;
                        if let Err(e) = live_rooms(&renewed, &req).and_then(|still| {
                            if still.is_empty() {
                                Err("no room is watched live any more".into())
                            } else {
                                Ok(())
                            }
                        }) {
                            break Err(e);
                        }
                    }
                    // A renewal is this command's schedule, not a retry: the next one is a
                    // minute away and the lease outlasts it. Two in a row end the tail.
                    Err(e) => {
                        failed_renewals += 1;
                        eprintln!("Could not renew the live watch: {e}");
                        if failed_renewals >= 2 {
                            break Err(format!("the live watch could not be renewed: {e}").into());
                        }
                    }
                }
            }
            frame = client.receive_next(1) => match frame {
                Ok(Some(frame)) => print_live_signal(&frame, &member, host, vta_did.as_deref()),
                Ok(None) => {}
                Err(e) => break Err(format!(
                    "this client cannot receive the signals ({e}); a live watch needs the \
                     DIDComm or TSP transport"
                ).into()),
            },
        }
    };
    cancel_live(client, &member, host, req.room_ids).await;
    ended
}

/// The rooms `answer` says are watched live, printing each one that is not with what to do;
/// an error when a room was refused live because of its signal delay.
pub(super) fn live_rooms(
    answer: &vti_specs::rooms::keys::watch::v0_2::Response,
    req: &WatchThroughVta<'_>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut live = Vec::new();
    for w in &answer.watches {
        let room = wire_str(&w.room_id);
        let refused = w.refused.as_ref().map(wire_str);
        let host_code = w.host_code.as_ref().map(wire_str);
        match (w.armed, w.live == Some(true), refused.as_deref()) {
            (true, true, _) => live.push(room),
            (true, false, _) => eprintln!(
                "Room {room} is watched one-shot, not live: your VTA or the host implements \
                 only rooms/watch 0.1. Watch it without --live and re-arm after each read."
            ),
            (false, _, Some("hostRefused"))
                if host_code.as_deref() == Some(vta_sdk::client::LIVE_NOT_PERMITTED) =>
            {
                return Err(live_not_permitted(&room, req).into());
            }
            (false, _, Some(reason)) => eprintln!(
                "Not watching room {room}: {}",
                watch_reason(reason, host_code.as_deref())
            ),
            (false, _, None) => eprintln!("No watch on room {room}."),
        }
    }
    Ok(live)
}

/// What to do when a host refuses a live watch: the room's signal delay is not `none`.
pub(super) fn live_not_permitted(room: &str, req: &WatchThroughVta<'_>) -> String {
    format!(
        "the host refused a live watch on room {room}: its signal delay is not `none` \
         (rooms/watch:liveNotPermitted). A live watch is permitted only on a room that sends \
         its signals at once. A room administrator can change that for every member:\n\n  \
         pnm rooms signal-delay set --room {room} --host {} --none --reason \"<why>\"\n\nor \
         watch it one-shot, without --live.",
        req.host_url.unwrap_or("<URL>")
    )
}

/// Print one frame if it is a `rooms/keys/changed` for this watch from this client's VTA
/// (Consumer item 1); anything else is not this command's.
pub(super) fn print_live_signal(frame: &str, member: &str, host: &str, vta_did: Option<&str>) {
    let Ok(value) = serde_json::from_str::<Value>(frame) else {
        return;
    };
    let doc = [
        value.get("document"),
        value.get("body").and_then(|b| b.get("document")),
        value.get("body"),
        Some(&value),
    ]
    .into_iter()
    .flatten()
    .find(|d| vta_sdk::client::room_changed_signal(d).is_some());
    let Some(doc) = doc else {
        return;
    };
    if let (Some(vta), Some(issuer)) = (vta_did, doc.get("issuer").and_then(Value::as_str))
        && issuer.split('#').next() != Some(vta)
    {
        return;
    }
    let Some(signal) = vta_sdk::client::room_changed_signal(doc) else {
        return;
    };
    if wire_str(&signal.member) != member || wire_str(&signal.host) != host {
        return;
    }
    if crate::render::is_json_output() {
        println!("{}", serde_json::to_string(&signal).unwrap_or_default());
    } else {
        println!(
            "{}  room {} is at version {}",
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            wire_str(&signal.room_id),
            signal.latest_version.get()
        );
    }
}

/// End the live watches (Producer item 6's SHOULD). A cancel that does not land leaves the
/// host's watch to its two-minute lease.
pub(super) async fn cancel_live(client: &VtaClient, member: &str, host: &str, room_ids: &[String]) {
    let rooms: Vec<&str> = room_ids.iter().map(String::as_str).collect();
    match client.room_watch_cancel(member, host, &rooms).await {
        Ok(_) => eprintln!("Live watch cancelled."),
        Err(e) => eprintln!(
            "Could not cancel the live watch ({e}); it ends by itself within two minutes."
        ),
    }
}

/// The member to watch as, where none was named: the one `rooms/keys/list` names for every
/// room, else — for an `open` room, which it does not list — the one the VTA completes the
/// room's requests as.
pub(super) async fn watch_member(
    client: &VtaClient,
    req: &WatchThroughVta<'_>,
) -> Result<String, Box<dyn std::error::Error>> {
    let listed = client
        .room_list(false)
        .await
        .map_err(|e| format!("could not list the rooms your VTA holds: {e}"))?;
    let mut members = std::collections::BTreeSet::new();
    let mut unlisted = Vec::new();
    for room in req.room_ids {
        let held: Vec<String> = listed
            .rooms
            .iter()
            .filter(|e| wire_str(&e.room_id) == *room)
            .map(|e| wire_str(&e.member))
            .collect();
        if held.is_empty() {
            unlisted.push(room.clone());
        }
        members.extend(held);
    }
    if !unlisted.is_empty()
        && let Some(url) = req.host_url
    {
        for room in &unlisted {
            let (_, member) = room_tier(
                client,
                &RoomTarget {
                    host_url: url,
                    host_did: Some(req.host_did),
                    room_id: room,
                },
            )
            .await?;
            members.insert(member);
        }
        unlisted.clear();
    }
    match (members.len(), unlisted.is_empty()) {
        (1, true) => Ok(members.into_iter().next().expect("one member")),
        (0, _) | (1, false) => Err(format!(
            "your VTA lists no member for {}: name it with --member, or pass the host's URL \
             with --host so an open room's member can be found",
            unlisted.join(", ")
        )
        .into()),
        _ => Err(format!(
            "you read these rooms as more than one member ({}): watch as one with --member",
            members.into_iter().collect::<Vec<_>>().join(", ")
        )
        .into()),
    }
}

/// What a room's `refused` means, and what to do about it.
pub(super) fn watch_reason(reason: &str, host_code: Option<&str>) -> String {
    match reason {
        "notAMember" => {
            "your VTA holds no credential this room issued to the member: poll it, or ask \
             the owner for one"
                .into()
        }
        "actionNotHeld" => "the member's credentials for this room do not confer `read`".into(),
        "limitReached" => {
            "your VTA holds as many watches as it allows; cancel one you no longer need \
             (--cancel), or poll this room with `pnm rooms list --since-version`"
                .into()
        }
        "hostUnreachable" => {
            "the host could not be reached, or advertises no transport your VTA speaks; try \
             again later"
                .into()
        }
        "hostRefused" => format!(
            "the host refused ({}); poll this room with `pnm rooms list --since-version`",
            host_code.unwrap_or("no code")
        ),
        other => other.to_string(),
    }
}

/// A `rooms/keys/watch` refusal of the whole request, with what the operator can do.
pub(super) fn vta_watch_refused(e: VtaError, req: &WatchThroughVta<'_>, member: &str) -> String {
    match &e {
        VtaError::UnsupportedTaskType { .. } => format!(
            "{e}\n\nYour VTA does not serve `rooms/keys/watch/0.1`, so it cannot watch for \
             you. Arm the host's watch with an address you receive at yourself:\n\n  pnm rooms \
             watch --via-host --room {} --host <URL> --host-did {} --address <DID>\n\nor poll \
             the room with `pnm rooms list --since-version`.",
            req.room_ids.first().map(String::as_str).unwrap_or("<ROOM>"),
            req.host_did
        ),
        _ if e.to_string().contains("memberNotPrincipal") => format!(
            "{e}\n\n{member} is not a member your VTA holds keys for that you may act as. \
             `pnm rooms keys list` names the members you read rooms as; pass one with --member."
        ),
        _ => e.to_string(),
    }
}

/// `rooms watch --via-host` — ask the room's host for one content-free signal
/// (`rooms/changed/0.1`) at `address`, a DID this client receives at, the first time the room
/// moves past `since` (`rooms/watch/0.1`), or cancel that watch.
///
/// Completed **as the member** by the VTA with `rooms/keys/act/0.12`, whose table lists
/// `rooms/watch` (`read`), and sent to the host by this client. The address must be a DID
/// you receive at and use for watches only — never this client's own DID, the VTA's or the
/// member's (Producer item 6, which binds this client: the VTA completes the request without
/// reading the address, so they are refused here, before anything is sent to the host);
/// on a `private` room, one you use for that one watch. A VTA that predates act/0.12 is
/// asked the way #2457 did: it presents for this client (`read`) and this client signs.
#[allow(deprecated)] // one-shot watches are rooms/keys/watch/0.1 and rooms/watch/0.1, still served
pub async fn cmd_rooms_watch_via_host(
    client: &VtaClient,
    target: RoomTarget<'_>,
    signer: RoomSigner<'_>,
    vta_did: Option<&str>,
    address: &str,
    since: Option<u64>,
    lease_secs: Option<u64>,
    cancel: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !address.starts_with("did:") {
        return Err(format!("--address {address}: a watch's address is a DID").into());
    }
    // Producer item 6 is the producer's to keep: the VTA completes the request without
    // reading the address (Recipient item 6), so these are refused here or nowhere.
    let vta_did = vta_did.or(client.vta_did());
    if let Some(whose) = forbidden_watch_address(address, signer.did, vta_did, None) {
        return Err(watch_address_refused(address, whose).into());
    }
    let mut payload = serde_json::json!({ "roomId": target.room_id, "address": address });
    if cancel {
        payload["cancel"] = serde_json::json!(true);
    } else {
        if let Some(v) = since {
            payload["sinceVersion"] = serde_json::json!(v);
        }
        if let Some(l) = lease_secs {
            payload["leaseSeconds"] = serde_json::json!(l);
        }
    }
    let host_did = target.host_did.unwrap_or("did:key:zHost");
    let document = vta_sdk::client::unsigned_room_request_v0_12(
        vti_rooms::watch::WATCH_TYPE,
        host_did,
        None,
        payload,
    )?;
    #[allow(deprecated)] // `--via-host` arms a one-shot watch, still rooms/watch/0.1
    let answer: vti_specs::rooms::watch::v0_1::Response =
        match client.room_act_v0_12(&document).await {
            Ok(completed) => {
                // The member is known once the VTA has resolved it; the completed document
                // has not been sent.
                let member = wire_str(&completed.principal);
                if let Some(whose) =
                    forbidden_watch_address(address, signer.did, vta_did, Some(&member))
                {
                    return Err(watch_address_refused(address, whose).into());
                }
                let document = serde_json::to_value(&completed.document)?;
                let reply = target
                    .client()
                    .send_signed_room_document(&document)
                    .await
                    .map_err(|e| watch_refused(e, &target, address))?;
                parse_reply("rooms/watch", reply)?
            }
            // A VTA from before act/0.12 completes no watch as the member: it presents for this
            // client, which signs — the host then sees this client as the presenter.
            Err(VtaError::UnsupportedTaskType { .. }) => {
                let session = present(client, &target, "read").await?;
                let host = target.client();
                if cancel {
                    host.cancel_watch(&session, address, signer.did, signer.key_multibase)
                        .await
                } else {
                    host.watch(
                        &session,
                        address,
                        since,
                        lease_secs,
                        signer.did,
                        signer.key_multibase,
                    )
                    .await
                }
                .map_err(|e| watch_refused(e, &target, address))?
            }
            Err(e) => return Err(act_refusal(e).into()),
        };
    if crate::render::is_json_output() {
        crate::render::print_json(&answer)?;
        return Ok(());
    }
    match (answer.armed, &answer.expires_at) {
        (true, Some(until)) => println!(
            "Watching room {} for {address} until {}: the host sends one signal the first \
             time the room moves past {}, then nothing until you watch again.",
            target.room_id,
            wire_str(until),
            since.map_or_else(
                || "its current version".to_string(),
                |v| format!("version {v}")
            ),
        ),
        (true, None) => println!("Watching room {} for {address}.", target.room_id),
        (false, _) => println!(
            "No watch on room {} for {address} any more.",
            target.room_id
        ),
    }
    Ok(())
}

/// Whose DID `address` is, where `rooms/keys/act/0.12` Producer item 6 forbids it as a
/// watch's address: the identifier this client authenticates to its VTA with, the VTA's own
/// DID, or the member's. `None` where it is none of them (or the party is not known).
pub fn forbidden_watch_address(
    address: &str,
    client_did: &str,
    vta_did: Option<&str>,
    member: Option<&str>,
) -> Option<&'static str> {
    let party = |d: &str| d.split('#').next().unwrap_or(d).to_string();
    let address = party(address);
    if address == party(client_did) {
        Some("this client's own DID")
    } else if vta_did.is_some_and(|v| address == party(v)) {
        Some("your VTA's DID")
    } else if member.is_some_and(|m| address == party(m)) {
        Some("the member's own DID")
    } else {
        None
    }
}

pub(super) fn watch_address_refused(address: &str, whose: &str) -> String {
    format!(
        "--address {address} is {whose}, which a watch's address may not be \
         (rooms/keys/act/0.12 Producer item 6): name a DID you receive at and use for watches \
         only, or let your VTA watch for you (omit --via-host)"
    )
}

/// A `rooms/watch` refusal, with what the operator can do about it.
pub(super) fn watch_refused(
    e: vtc_client::VtcError,
    target: &RoomTarget<'_>,
    address: &str,
) -> Box<dyn std::error::Error> {
    let code = vtc_client::git_ns::task_error(&e).map(|(c, _)| c);
    let hint = match code.as_deref() {
        Some(c) if c.ends_with("addressUnreachable") => format!(
            "\n\nThe host could not resolve {address}, or its DID document advertises no \
             transport the host speaks (TSP or DIDComm). Use an address whose document names \
             a mediator."
        ),
        Some(c) if c.ends_with("limitReached") => format!(
            "\n\nThe host holds as many watches as it allows. Cancel one you no longer need:\n\n  \
             pnm rooms watch --via-host --room {} --host {} --host-did {} --address <DID> --cancel",
            target.room_id,
            target.host_url,
            target.host_did.unwrap_or("<host-did>")
        ),
        Some("unsupportedType") => {
            "\n\nThe room's host does not serve `rooms/watch/0.1`: poll the room with \
             `pnm rooms list --since-version` instead."
                .to_string()
        }
        _ => String::new(),
    };
    format!("{e}{hint}").into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `rooms/keys/act/0.12` Producer item 6 is kept by the producer: the client's own DID,
    /// the VTA's and the member's are refused as a watch's address, fragment or not.
    #[test]
    fn a_watch_address_may_not_be_the_clients_the_vtas_or_the_members() {
        let (me, vta, m) = ("did:key:zMe", "did:webvh:Qm:vta.example", "did:key:zMember");
        assert_eq!(
            forbidden_watch_address("did:key:zMe#zMe", me, Some(vta), None),
            Some("this client's own DID")
        );
        assert_eq!(
            forbidden_watch_address(vta, me, Some(vta), Some(m)),
            Some("your VTA's DID")
        );
        assert_eq!(
            forbidden_watch_address(m, me, Some(vta), Some(m)),
            Some("the member's own DID")
        );
        assert_eq!(
            forbidden_watch_address("did:key:zWatches", me, Some(vta), Some(m)),
            None
        );
    }
}
