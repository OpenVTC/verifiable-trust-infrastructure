//! Room administration: renew, the epoch and record prunes, retention, the
//! signal delay, and creating a room.

use super::*;

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
pub(super) fn refuse_sealed_renew(visibility: &str, target: &RoomTarget<'_>) -> Result<(), String> {
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
            if !crate::commands::contexts::confirm_destructive("Prune the chain?")? {
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
pub(super) enum PruneGuard {
    Proceed,
    Ask,
    Refuse,
}

pub(super) fn prune_guard(assume_yes: bool, interactive: bool) -> PruneGuard {
    match (assume_yes, interactive) {
        (true, _) => PruneGuard::Proceed,
        (false, true) => PruneGuard::Ask,
        (false, false) => PruneGuard::Refuse,
    }
}

/// The irreversibility warning (rooms/epoch/prune/0.2 *Consent/purpose*: show what will
/// become unreadable), in the specification's own terms — the rungs go, not the records.
pub(super) fn prune_warning(
    room_id: &str,
    before_epoch: u32,
    current: u32,
    policy: Option<&str>,
) -> String {
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
pub(super) fn not_ahead_message(
    target: &RoomTarget<'_>,
    before_epoch: u32,
    current: u32,
) -> String {
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
pub(super) fn prune_command(target: &RoomTarget<'_>, before_epoch: u32, reason: &str) -> String {
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
pub(super) fn prune_refused(
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
pub(super) fn prune_outcome(r: &vtc_client::rooms::PruneResponse) -> String {
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
/// (`rooms/records/prune/0.2`, trust-tasks-tf #868).
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
            if !crate::commands::contexts::confirm_destructive("Remove these records for good?")? {
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
pub(super) fn records_prune_preview(room_id: &str, preview: &Value) -> String {
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
pub(super) fn records_prune_command(
    target: &RoomTarget<'_>,
    kinds: &[&str],
    reason: &str,
) -> String {
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
pub(super) fn records_prune_refused(e: vtc_client::VtcError, target: &RoomTarget<'_>) -> String {
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
/// (`rooms/info/0.3`).
pub async fn cmd_rooms_retention_show(
    client: &VtaClient,
    target: RoomTarget<'_>,
    signer: RoomSigner<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let info = read_info(client, &target, &signer).await?;
    if crate::render::is_json_output() {
        crate::render::print_json(&serde_json::json!({
            "recordRetention": info.get("recordRetention"),
            "lastPrune": info.get("lastPrune"),
        }))?;
        return Ok(());
    }
    println!("{}", retention_lines(&info));
    if let Some(delay) = info.get("signalDelay").and_then(Value::as_str) {
        println!("{}", signal_delay_text(delay));
    }
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
    let info = read_info(client, &target, &signer).await?;
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

/// `rooms signal-delay show` — the room's signal delay (`rooms/info/0.4`).
pub async fn cmd_rooms_signal_delay_show(
    client: &VtaClient,
    target: RoomTarget<'_>,
    signer: RoomSigner<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let info = read_info(client, &target, &signer).await?;
    let delay = info
        .get("signalDelay")
        .and_then(Value::as_str)
        .unwrap_or("randomised");
    if crate::render::is_json_output() {
        crate::render::print_json(&serde_json::json!({ "signalDelay": delay }))?;
        return Ok(());
    }
    println!("{}", signal_delay_text(delay));
    Ok(())
}

/// A signal delay in words.
pub(super) fn signal_delay_text(delay: &str) -> String {
    match delay {
        "none" => "Signal delay: none — the host sends a watch signal as soon as a write is \
                   stored"
            .to_string(),
        _ => "Signal delay: randomised — the host waits a few seconds, at random, before each \
              watch signal"
            .to_string(),
    }
}

/// What `none` gives up, in the specification's terms (`rooms/signal-delay/set/0.1`, *What
/// `none` gives up*): shown before the request is sent (Producer, SHOULD).
pub const SIGNAL_DELAY_NONE_TRADE_OFF: &str = "Turning the delay off: the host's wait keeps a \
signal's time from marking one write. In a busy room that costs little — the room's rhythm \
shows in its writes anyway. In a quiet room, one write followed by one signal at once tells \
anyone who sees both reach and leave the host when the writer wrote, and that writer and \
watcher share the room. `none` removes only the host's own wait: mediators and push gateways \
still take the time they take.";

/// `rooms signal-delay set` — change the room's signal delay (`rooms/signal-delay/set/0.1`).
/// Needs `admin`.
pub async fn cmd_rooms_signal_delay_set(
    client: &VtaClient,
    target: RoomTarget<'_>,
    signer: RoomSigner<'_>,
    signal_delay: &str,
    reason: String,
) -> Result<(), Box<dyn std::error::Error>> {
    if signal_delay == "none" && !crate::render::is_json_output() {
        eprintln!("{SIGNAL_DELAY_NONE_TRADE_OFF}\n");
    }
    let session = present(client, &target, "admin").await?;
    let set = target
        .client()
        .set_signal_delay(
            &session,
            signal_delay,
            &reason,
            signer.did,
            signer.key_multibase,
        )
        .await
        .map_err(|e| signal_delay_refused(e, &target))?;
    let set = serde_json::to_value(&set)?;
    if crate::render::is_json_output() {
        crate::render::print_json(&set)?;
        return Ok(());
    }
    let now = set["signalDelay"].as_str().unwrap_or(signal_delay);
    let was = set["previous"].as_str().unwrap_or("randomised");
    if now == was {
        println!(
            "Room {}: the signal delay was already {now}; nothing changed.",
            target.room_id
        );
    } else {
        println!(
            "Room {}: signal delay {now} (was {was}). Every member reads it in the room's \
             info.",
            target.room_id
        );
    }
    Ok(())
}

/// A host's refusal of a signal-delay change, with the fix where the code names one.
pub(super) fn signal_delay_refused(e: vtc_client::VtcError, target: &RoomTarget<'_>) -> String {
    let code = vtc_client::git_ns::task_error(&e).map(|(code, _)| code);
    match code.as_deref() {
        Some(c) if c.ends_with("signalDelayNotPermitted") => format!(
            "{e}\n\nThis host keeps the randomised delay on every room it holds; it will not \
             turn it off for room {}. Nothing was recorded.",
            target.room_id
        ),
        Some(c) if c.ends_with("permissionDenied") => format!(
            "{e}\n\nChanging the signal delay needs `admin` in the room — the grant that \
             decides its other terms. The room's owner grants it with `pnm rooms owner \
             issue-authority --action admin --store`."
        ),
        Some(c) if c.ends_with("unsupportedType") => format!(
            "{e}\n\nThis host predates rooms/signal-delay/set: every room it holds keeps the \
             randomised delay."
        ),
        _ => e.to_string(),
    }
}

/// `rooms/info/0.5` as JSON (0.4 or 0.3 from a host that predates it — 0.3 read as
/// `randomised`), read under `read`.
pub(super) async fn read_info(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    signer: &RoomSigner<'_>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let read = present(client, target, "read").await?;
    let info = target
        .client()
        .room_info(&read, signer.did, signer.key_multibase)
        .await
        .map_err(|e| format!("could not read the room (rooms/info): {e}"))?;
    Ok(serde_json::to_value(&info)?)
}

/// A record retention in words; `{}` or absent is "none".
pub(super) fn retention_text(rule: &Value) -> String {
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

/// The retention and latest prune `rooms/info/0.3` reports, as lines.
pub(super) fn retention_lines(info: &Value) -> String {
    let rule = info.get("recordRetention").cloned().unwrap_or(Value::Null);
    let mut out = format!("Record retention: {}", retention_text(&rule));
    match info.get("lastPrune") {
        Some(p) => out.push_str(&format!(
            "\nLast prune: {} record(s) at {}, version {}",
            p["removed"],
            p["prunedAt"].as_str().unwrap_or("?"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::rooms::test_support::*;
    use serde_json::json;

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
}
