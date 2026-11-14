//! Records: list, read and get (newest first or in order), put, a member's name,
//! curate, and the provenance a record states.

use super::*;

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
    // A member's name (`kind: memberProfile`, which an open room's listing shows) is not a
    // note: it is never listed or counted as a record, only read as a name
    // (`MemberProfileRecord`, *Reading one*, rule 1). On a sealed tier the host never sees a
    // kind, so nothing is set aside there.
    let (name_rows, records): (Vec<&Value>, Vec<&Value>) = listing.records.iter().partition(|r| {
        r.get("kind").and_then(Value::as_str) == Some(vti_rooms::member_profile::KIND)
    });
    let mut names = vti_rooms::member_profile::Names::default();
    for r in &name_rows {
        let Some(by) = r.get("createdBy").and_then(Value::as_str) else {
            continue;
        };
        let row = r.get("cleartext").unwrap_or(r);
        // A listing row is metadata: its `title` and `kind` stand for the cleartext's, and
        // an empty body is what a name record carries.
        let mut cleartext = serde_json::Map::new();
        for m in ["kind", "title", "writtenAt", "editedAt"] {
            if let Some(v) = row.get(m) {
                cleartext.insert(m.into(), v.clone());
            }
        }
        cleartext.insert("body".into(), Value::String(String::new()));
        let stored = r
            .get("bodyStoredAt")
            .or_else(|| r.get("updatedAt"))
            .and_then(Value::as_str);
        let author = r.get("author").and_then(Value::as_str).unwrap_or(by);
        names.offer(
            author,
            &cleartext,
            stored,
            r.get("version").and_then(Value::as_u64),
            true,
        );
    }

    if records.is_empty() {
        println!(
            "No records{}.",
            prefix.map(|p| format!(" under `{p}`")).unwrap_or_default()
        );
    } else {
        let shown = limit.unwrap_or(usize::MAX).min(records.len());
        if shown < records.len() {
            println!(
                "{} record(s), showing {shown} — pass a larger --limit for the rest:",
                records.len()
            );
        } else {
            println!("{} record(s):", records.len());
        }
        for r in records.iter().take(shown) {
            list_row(r, &names);
        }
        unread_summary(client, target.room_id, &records).await;
    }
    let mut named: Vec<(&str, &str)> = names.iter().collect();
    if !named.is_empty() {
        named.sort();
        println!("\nMembers' names in this room (each one's own claim, not verified):");
        for (did, name) in named {
            println!("  {}  {}", inert(did), inert(name));
        }
    }
    Ok(())
}

/// How many of `records` are unread against the member's read marker for the room, which
/// their VTA keeps across their devices (`rooms/keys/list/0.3`, `rooms/keys/read-marker/set`)
/// — and how to mark them read. Says nothing when no marker is held, or when the room is held
/// as several members (whose markers differ). This reader keeps no copy of the room, so it
/// counts as `rooms/changed` step 4 says such a reader does: a record whose `createdAt`
/// (else `updatedAt`) is after the marker's `createdAt`; without one, a record past the
/// marker's version.
pub(super) async fn unread_summary(client: &VtaClient, room_id: &str, records: &[&Value]) {
    let Ok(list) = client.room_list_v0_3(true).await else {
        return;
    };
    let held: Vec<_> = list
        .rooms
        .iter()
        .filter(|r| r.room_id.as_str() == room_id)
        .collect();
    let [entry] = held.as_slice() else {
        return;
    };
    let Some(marker) = &entry.read_marker else {
        return;
    };
    let stored = |r: &Value| {
        r.get("createdAt")
            .or_else(|| r.get("updatedAt"))
            .and_then(Value::as_str)
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            .map(|t| t.with_timezone(&chrono::Utc))
    };
    let unread = records
        .iter()
        .filter(|r| match &marker.created_at {
            Some(seen) => stored(r).is_none_or(|t| t > *seen),
            None => r.get("version").and_then(Value::as_u64).unwrap_or(0) > marker.version,
        })
        .count();
    let member = entry.member.as_str();
    if unread == 0 {
        println!(
            "\nAll read (your read marker is at version {}).",
            marker.version
        );
        return;
    }
    println!(
        "\n{unread} unread since your read marker (version {}).",
        marker.version
    );
    if let Some(newest) = records
        .iter()
        .filter_map(|r| r.get("version").and_then(Value::as_u64))
        .max()
    {
        println!(
            "Mark read on every device: pnm rooms keys mark-read {room_id} --member {member} \
             --version {newest}"
        );
    }
}

/// One record of `rooms list`, its writer named as they named themselves where known.
pub(super) fn list_row(r: &Value, names: &vti_rooms::member_profile::Names) {
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
    let by = r
        .get("createdBy")
        .and_then(Value::as_str)
        .and_then(|d| names.name(d).map(|n| format!("  — by \"{}\"", inert(n))))
        .unwrap_or_default();
    println!("  {key}  v{version}  {status:<10} {title}{by}");
}

/// One page of `rooms/records/list`, as the member.
pub(super) async fn list_page(
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
    // list/0.6 where the VTA and host serve it — its rows add when the host stored each
    // record and by whom, and an open room's `kind` — else list/0.5. A cursor is the
    // version's own, so a later page asks the version the first one was answered at.
    let (_, mut reply, _) = act_and_send_newest(
        client,
        target,
        (vti_rooms::wire::ROOMS_RECORDS_LIST_V6_TYPE, payload.clone()),
        Some((vti_rooms::wire::ROOMS_RECORDS_LIST_V5_TYPE, payload)),
    )
    .await?;
    // List 0.5 and 0.6 name the continuation token `nextCursor`; the listing type reads
    // `cursor`.
    if let Some(obj) = reply.as_object_mut()
        && let Some(next) = obj.remove("nextCursor")
    {
        obj.insert("cursor".into(), next);
    }
    parse_reply("rooms/records/list", reply)
}

/// How `rooms list --newest` / `rooms read --newest` open a conversation at its head.
#[derive(Debug, Clone, Default)]
pub struct NewestPage<'a> {
    /// Only records whose key starts with this.
    pub prefix: Option<&'a str>,
    /// Only records above this version — a newest-first catch-up stops here.
    pub since_version: Option<u64>,
    /// Records per host page; [`NEWEST_DEFAULT_LIMIT`] when unset.
    pub limit: Option<usize>,
    /// Host pages to read; one when unset — a conversation's first screen.
    pub pages: Option<u64>,
    /// A `nextCursor` an earlier `--newest` printed, to read the page before it.
    pub cursor: Option<&'a str>,
    /// Only records below this version (`rooms/keys/browse/0.6`): "load older" from the
    /// lowest version already shown, with no cursor to keep.
    pub before_version: Option<u64>,
}

/// The page size `--newest` asks for when `--limit` is not given.
pub const NEWEST_DEFAULT_LIMIT: usize = 50;

/// The rows of a newest-first page as a conversation shows them: a member's name record
/// set aside (it is a name, not a message), the rest ordered by the host's `createdAt` —
/// else `updatedAt`, for a record stored before the host kept `createdAt` — oldest first,
/// so the newest message is printed last, nearest the prompt. Never by row order: an old
/// message edited a moment ago sits at the head of a newest-first listing, and is shown
/// where it was written (`rooms/records/list/0.7` *What a newest-first page holds*).
pub fn conversation_order(records: &[Value]) -> Vec<&Value> {
    let mut rows: Vec<&Value> = records
        .iter()
        .filter(|r| r.get("kind").and_then(Value::as_str) != Some(vti_rooms::member_profile::KIND))
        .collect();
    let at = |r: &Value| {
        r.get("createdAt")
            .or_else(|| r.get("updatedAt"))
            .and_then(Value::as_str)
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
    };
    // Stable, so two records written in one instant keep the host's (descending) order
    // reversed by version below.
    rows.sort_by(|a, b| {
        at(a).cmp(&at(b)).then_with(|| {
            let v = |r: &Value| r.get("version").and_then(Value::as_u64).unwrap_or(0);
            v(a).cmp(&v(b))
        })
    });
    rows
}

/// The pnm command line that lists a room oldest first, to the end — what to run where
/// `--newest` cannot be served.
pub(super) fn oldest_first_command(room_id: &str, host_url: &str, host_did: &str) -> String {
    format!("pnm rooms list --room {room_id} --host {host_url} --host-did {host_did}")
}

/// `rooms/keys/browse/0.6` (0.5 from a VTA that predates it, for a page naming no
/// `--before-version`), newest first: the member's VTA lists the room at its host from the
/// head down — or from below `--before-version` — `pages` host pages, and answers the host's
/// cursor when it stopped early. Every refusal that has a better command names it.
pub(super) async fn browse_newest(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    page: &NewestPage<'_>,
    verb: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let host_did = target.host_did.ok_or_else(|| {
        format!(
            "`rooms {verb} --newest` has your VTA list the room at its host, which it finds by \
             its DID: pass --host-did, e.g.\n  pnm rooms {verb} --newest --room {} --host {} \
             --host-did <the host's DID>",
            target.room_id, target.host_url
        )
    })?;
    let options = vta_sdk::client::RoomBrowse {
        prefix: page.prefix.map(str::to_string),
        since_version: page.since_version,
        limit: Some(page.limit.unwrap_or(NEWEST_DEFAULT_LIMIT) as u64),
        order: Some(vta_sdk::client::RoomListOrder::NewestFirst),
        max_pages: Some(page.pages.unwrap_or(1).max(1)),
        cursor: page.cursor.map(str::to_string),
        before_version: page.before_version,
    };
    let fallback = oldest_first_command(target.room_id, target.host_url, host_did);
    // Paging older by cursor instead of by version: what to run where `--before-version`
    // cannot be served.
    let by_cursor = format!(
        "pnm rooms {verb} --newest --room {} --host {} --host-did {host_did}, then the \
         --cursor it prints",
        target.room_id, target.host_url
    );
    match client
        .room_browse(target.room_id, host_did, &options, None)
        .await
    {
        Ok(listing) => Ok(serde_json::to_value(listing)?),
        Err(VtaError::UnsupportedTaskType { .. }) if page.before_version.is_some() => Err(format!(
            "your VTA does not serve `rooms/keys/browse/0.6`, which pages older by \
                 version. Upgrade it, or page older with the cursor instead:\n  {by_cursor}"
        )
        .into()),
        Err(VtaError::UnsupportedTaskType { .. }) => Err(format!(
            "your VTA does not serve `rooms/keys/browse/0.5`, which lists a room newest first. \
             Upgrade it, or list the room oldest first, to the end:\n  {fallback}"
        )
        .into()),
        Err(VtaError::Rejected {
            code,
            message,
            details,
        }) if code.ends_with(":hostRefused") => {
            let host_code = details
                .as_ref()
                .and_then(|d| d.get("code"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if host_code == "unsupportedType" && page.before_version.is_some() {
                Err(format!(
                    "the room's host does not serve `rooms/records/list/0.8`, so it cannot list \
                     below a version. Page older with the cursor instead:\n  {by_cursor}"
                )
                .into())
            } else if host_code == "unsupportedType" {
                Err(format!(
                    "the room's host does not serve `rooms/records/list/0.7`, so it cannot list \
                     newest first. List the room oldest first, to the end:\n  {fallback}"
                )
                .into())
            } else if host_code.ends_with("invalidCursor") {
                Err(format!(
                    "the host refused the cursor: it was not issued for this newest-first \
                     listing and these bounds (or has expired). Start again from the head:\n  pnm rooms {verb} \
                     --newest --room {} --host {} --host-did {host_did}",
                    target.room_id, target.host_url
                )
                .into())
            } else {
                Err(format!("trust task failed [{code}]: {message}").into())
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// What to run for the page before this one, when the VTA stopped with a cursor: the
/// cursor, and — needing no cursor kept, from a VTA and host serving browse/0.6 and
/// list/0.8 — `--before-version` the lowest version on this page.
///
/// The cursor line repeats this page's `--prefix`, `--since-version` and
/// `--before-version`: a host's cursor is accepted only under the bounds it was issued for
/// (`rooms/records/list/0.8`).
pub(super) fn older_page_hint(
    verb: &str,
    target: &RoomTarget<'_>,
    page: &NewestPage<'_>,
    listing: &Value,
) -> Option<String> {
    let cursor = listing.get("nextCursor").and_then(Value::as_str)?;
    let mut base = format!(
        "pnm rooms {verb} --newest --room {} --host {} --host-did {}",
        target.room_id,
        target.host_url,
        target.host_did.unwrap_or("<the host's DID>")
    );
    if let Some(p) = page.prefix {
        base.push_str(&format!(" --prefix {p}"));
    }
    if let Some(s) = page.since_version {
        base.push_str(&format!(" --since-version {s}"));
    }
    let bounded = match page.before_version {
        Some(b) => format!("{base} --before-version {b}"),
        None => base.clone(),
    };
    let lowest = listing["records"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r.get("version").and_then(Value::as_u64))
        .min();
    Some(match lowest {
        Some(v) => format!(
            "Older records: {bounded} --cursor {cursor}\n           or: {base} --before-version {v}"
        ),
        None => format!("Older records: {bounded} --cursor {cursor}"),
    })
}

/// `rooms list --newest` — a conversation from its head: the newest page of the room's
/// records, metadata only, read by the member's VTA (`rooms/keys/browse/0.5`), shown in
/// the order they were written with the newest last, and the command for the page before.
pub async fn cmd_rooms_list_newest(
    client: &VtaClient,
    target: RoomTarget<'_>,
    page: NewestPage<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listing = browse_newest(client, &target, &page, "list").await?;
    if crate::render::is_json_output() {
        crate::render::print_json(&listing)?;
        return Ok(());
    }
    let records = listing["records"].as_array().cloned().unwrap_or_default();
    let shown = conversation_order(&records);
    let names = vti_rooms::member_profile::Names::default();
    if shown.is_empty() {
        println!("No records at the head of this room.");
    } else {
        println!(
            "The {} newest record(s), oldest first, the newest last:",
            shown.len()
        );
        for r in shown {
            list_row(r, &names);
        }
    }
    match older_page_hint("list", &target, &page, &listing) {
        Some(hint) => println!("\n{hint}"),
        None => println!("\nThat is the whole listing."),
    }
    Ok(())
}

/// `rooms read --newest` — the newest records of a conversation, opened: the head page
/// from [`cmd_rooms_list_newest`]'s listing, its live records read through the VTA as
/// `rooms read` reads named keys, in the order they were written.
pub async fn cmd_rooms_read_newest(
    client: &VtaClient,
    target: RoomTarget<'_>,
    page: NewestPage<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listing = browse_newest(client, &target, &page, "read").await?;
    let records = listing["records"].as_array().cloned().unwrap_or_default();
    let keys: Vec<String> = conversation_order(&records)
        .into_iter()
        .filter(|r| r.get("status").and_then(Value::as_str) != Some("retracted"))
        .filter_map(|r| r.get("key").and_then(Value::as_str).map(str::to_string))
        .collect();
    let hint = older_page_hint("read", &target, &page, &listing);
    if keys.is_empty() {
        println!("No records at the head of this room.");
    } else {
        cmd_rooms_read(client, target, &keys).await?;
    }
    if !crate::render::is_json_output()
        && let Some(hint) = hint
    {
        println!("\n{hint}");
    }
    Ok(())
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
    let payload = serde_json::json!({ "roomId": target.room_id, "key": key });
    let (_, record, _) = act_and_send_newest(
        client,
        &target,
        (vti_rooms::wire::ROOMS_RECORDS_GET_V3_TYPE, payload.clone()),
        Some((vti_rooms::wire::ROOMS_RECORDS_GET_V2_TYPE, payload)),
    )
    .await?;
    let stored = stored_line(&record);

    // An `open`-tier record arrives readable. A sealed one arrives as
    // ciphertext this process cannot decrypt, and must not try to: the group
    // key is the VTA's.
    if let Some(cleartext) = record.get("cleartext") {
        if crate::render::is_json_output() {
            crate::render::print_json(cleartext)?;
        } else if let Some(obj) = cleartext
            .as_object()
            .filter(|o| vti_rooms::member_profile::is_member_profile(o))
        {
            let author = record
                .get("createdBy")
                .or_else(|| record.get("author"))
                .and_then(Value::as_str)
                .unwrap_or("its author");
            println!("{}", name_record_line(obj, author, true));
            if let Some(line) = &stored {
                println!("{line}");
            }
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
            if let Some(obj) = cleartext.as_object()
                && let Some(line) = thread_line(obj)
            {
                println!("\n{line}");
            }
            if let Some(line) = &stored {
                println!("{line}");
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
    if let Ok(Value::Object(obj)) = serde_json::to_value(body)
        && vti_rooms::member_profile::is_member_profile(&obj)
    {
        println!("{}", name_record_line(&obj, &body.author, false));
        if let Some(line) = &stored {
            println!("{line}");
        }
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
        if let Some(line) = thread_line(&obj) {
            println!("{line}");
        }
    }
    if let Some(line) = &stored {
        println!("{line}");
    }
    Ok(())
}

/// A record's `kind`, what it answers and when its author says it was written and edited —
/// the author's word, shown as such.
pub(super) fn thread_line(obj: &serde_json::Map<String, Value>) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(k) = obj.get("kind").and_then(Value::as_str) {
        parts.push(format!("Kind: {}", inert(k)));
    }
    if let Some(r) = obj.get("inReplyTo") {
        let key = r
            .get("key")
            .and_then(Value::as_str)
            .map(inert)
            .unwrap_or_default();
        match r.get("version").and_then(Value::as_u64) {
            Some(v) => parts.push(format!("In reply to {key}@{v}")),
            None => parts.push(format!("In reply to {key}")),
        }
    }
    if let Some(w) = obj.get("writtenAt").and_then(Value::as_str) {
        parts.push(format!("written {}", inert(w)));
    }
    if let Some(e) = obj.get("editedAt").and_then(Value::as_str) {
        parts.push(format!("edited {}", inert(e)));
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}

/// What the host recorded about a record (`rooms/records/get/0.3`, `RecordMetadataV3`):
/// when it first stored it and for whom, and when it stored this body.
pub(super) fn stored_line(record: &Value) -> Option<String> {
    let created = record.get("createdAt").and_then(Value::as_str);
    let by = record.get("createdBy").and_then(Value::as_str);
    let body = record.get("bodyStoredAt").and_then(Value::as_str);
    if created.is_none() && body.is_none() {
        return None;
    }
    let mut line = String::from("The host first stored it");
    if let Some(c) = created {
        line.push_str(&format!(" at {}", inert(c)));
    }
    if let Some(b) = by {
        line.push_str(&format!(" for {}", inert(b)));
    }
    if let Some(b) = body {
        line.push_str(&format!("; this body at {}", inert(b)));
    }
    line.push('.');
    Some(line)
}

/// `rooms read` — several records at once, read **by your VTA** (`rooms/keys/read/0.2`):
/// it fetches each from the host as you, checks what the host asserted, and opens it, and
/// answers every key on its own — a record, or why that one key was not read. Keys past
/// [`vta_sdk::client::ROOM_READ_MAX_KEYS`] go in further requests.
///
/// A sealed record is shown only after its body checks out, as `rooms get` checks it
/// ([`verify_record_body`]); one that fails is reported for its key and nothing of it shown.
pub async fn cmd_rooms_read(
    client: &VtaClient,
    target: RoomTarget<'_>,
    keys: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let host_did = target.host_did.ok_or(
        "`rooms read` has your VTA fetch the records from the host, which it finds by its DID: \
         pass --host-did",
    )?;
    let mut results = Vec::with_capacity(keys.len());
    let mut sealed_at = serde_json::Map::new();
    for chunk in keys.chunks(vta_sdk::client::ROOM_READ_MAX_KEYS) {
        let refs: Vec<&str> = chunk.iter().map(String::as_str).collect();
        let answer = client
            .room_read_batch(target.room_id, host_did, &refs, None)
            .await?;
        let answer = serde_json::to_value(answer)?;
        if let Some(Value::Object(at)) = answer.pointer("/ext/org.openvtc.rooms/sealedAt") {
            sealed_at.extend(at.clone());
        }
        results.extend(answer["results"].as_array().cloned().unwrap_or_default());
    }
    if crate::render::is_json_output() {
        crate::render::print_json(&results)?;
        return Ok(());
    }
    let resolver = vta_sdk::trust_task_proof::TrustTaskVmResolver::from_optional(
        vta_sdk::resolver::shared_did_resolver_from_env().await.ok(),
    );
    // Open every record first, so a name read anywhere in the batch shows beside its
    // author's other records (`MemberProfileRecord`, *Showing a name*).
    let mut opened: Vec<Result<Option<serde_json::Map<String, Value>>, String>> =
        Vec::with_capacity(results.len());
    let mut names = vti_rooms::member_profile::Names::default();
    for r in &results {
        let key = r["key"].as_str().unwrap_or("?");
        let version = r["version"].as_u64().unwrap_or(0);
        let open_tier = r.get("cleartext").is_some();
        let shown = if let Some(cleartext) = r.get("cleartext").and_then(Value::as_object) {
            Ok(Some(cleartext.clone()))
        } else if let Some(plaintext) = r["plaintext"].as_str() {
            let bytes = base64::Engine::decode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                plaintext,
            )?;
            let at = sealed_at
                .get(key)
                .and_then(Value::as_u64)
                .unwrap_or(version);
            let location = RecordLocation {
                room_id: target.room_id,
                key,
                version: at,
            };
            match verify_record_body(&bytes, location, r["author"].as_str(), &resolver).await {
                Ok(body) => match serde_json::to_value(body.body())? {
                    Value::Object(obj) => Ok(Some(obj)),
                    _ => Ok(None),
                },
                Err(e) => Err(e.to_string()),
            }
        } else {
            // A tombstone, or the room's own profile, which is not opened here.
            Ok(None)
        };
        if let Ok(Some(obj)) = &shown
            && r["status"].as_str().unwrap_or("active") == "active"
        {
            let author = obj
                .get("author")
                .or_else(|| r.get("author"))
                .or_else(|| r.get("createdBy"))
                .and_then(Value::as_str);
            if let Some(author) = author {
                let stored = r
                    .get("bodyStoredAt")
                    .or_else(|| r.get("updatedAt"))
                    .and_then(Value::as_str);
                names.offer(author, obj, stored, r["version"].as_u64(), open_tier);
            }
        }
        opened.push(shown);
    }

    for (i, (r, shown)) in results.iter().zip(opened).enumerate() {
        if i > 0 {
            println!();
        }
        let key = r["key"].as_str().unwrap_or("?");
        if let Some(e) = r.get("error") {
            let code = e["code"].as_str().unwrap_or("?");
            let again = if e["retryable"] == true {
                " — ask for it again"
            } else {
                ""
            };
            println!(
                "{}: not read [{code}]{again}: {}",
                inert(key),
                inert(e["message"].as_str().unwrap_or(""))
            );
            continue;
        }
        let version = r["version"].as_u64().unwrap_or(0);
        let status = r["status"].as_str().unwrap_or("active");
        println!("{}  v{version}  {status}", inert(key));
        let shown = match shown {
            Ok(s) => s,
            Err(e) => {
                println!("  refused: {e}");
                continue;
            }
        };
        if let Some(obj) = &shown {
            let author = obj
                .get("author")
                .or_else(|| r.get("createdBy"))
                .and_then(Value::as_str);
            if vti_rooms::member_profile::is_member_profile(obj) {
                // A name, not a note: never shown or counted as one.
                println!(
                    "  {}",
                    name_record_line(
                        obj,
                        author.unwrap_or("its author"),
                        r.get("cleartext").is_some()
                    )
                );
            } else {
                if let Some(title) = obj.get("title").and_then(Value::as_str) {
                    println!("  {}", inert(title));
                }
                if let Some(text) = obj.get("body").and_then(Value::as_str) {
                    println!("  {}", inert(text));
                }
                if let Some(line) = thread_line(obj) {
                    println!("  {line}");
                }
                if let Some(author) = author {
                    println!("  Written by {}.", author_line(author, &names));
                }
                // As `rooms get` shows it: these keys were asked for by name, so an expired
                // record is shown, marked (`RecordValidUntil`: only on explicit request).
                let open_tier = r.get("cleartext").is_some();
                if !open_tier || vti_rooms::provenance::carries_any(obj) {
                    let unsigned = if open_tier {
                        " (unsigned on an open room)"
                    } else {
                        ""
                    };
                    println!("  {}{unsigned}", provenance_line(obj).replace('\n', "\n  "));
                }
            }
        }
        if let Some(line) = stored_line(r) {
            println!("  {line}");
        }
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
    thread: RecordThread,
) -> Result<(), Box<dyn std::error::Error>> {
    // Checked before anything is sent: the shapes here, the room's permission below.
    let wanted = thread.members()?;
    let (sealed_tier, member) = room_tier(client, &target).await?;
    let members = writer_members(client, &target, wanted.clone()).await?;

    if !sealed_tier {
        let mut payload = serde_json::json!({
            "roomId": target.room_id,
            "key": key,
            "cleartext": CleartextContent { title, body, ..Default::default() },
        });
        // Provenance rides the cleartext from put/0.3 on, unsigned and stored as received
        // (`rooms/records/put/0.5` Producer item 9, Host item 11), and no room profile
        // governs it — so both versions below carry it.
        for (k, v) in provenance.members()? {
            payload["cleartext"][k] = v;
        }
        if let Some(v) = expected_version {
            payload["expectedVersion"] = serde_json::json!(v);
        }
        // put/0.3 carries none of the governed members: it is the fallback only for a record
        // that asked for none — `writtenAt`, added because the profile permits it, is left
        // out rather than refusing the write.
        let older = wanted
            .is_empty()
            .then(|| (vti_rooms::wire::ROOMS_RECORDS_PUT_V3_TYPE, payload.clone()));
        let mut newest = payload;
        for (k, v) in members {
            newest["cleartext"][k] = v;
        }
        let (_, reply, _) = act_and_send_newest(
            client,
            &target,
            (vti_rooms::wire::ROOMS_RECORDS_PUT_V5_TYPE, newest),
            older,
        )
        .await?;
        let put: vti_rooms::wire::PutRecordResponse = parse_reply("rooms/records/put", reply)?;
        println!("Wrote {} at version {} as {member}", put.key, put.version);
        keep_name_near_head(client, &target, put.version).await;
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
    content.kind = members
        .get("kind")
        .and_then(Value::as_str)
        .map(str::to_string);
    content.in_reply_to = members.get("inReplyTo").cloned();
    content.written_at = members
        .get("writtenAt")
        .and_then(Value::as_str)
        .map(str::to_string);
    let version = write_sealed(client, &target, content, expected_version).await?;
    println!("Wrote {key} at version {version}, sealed and signed by {member}");
    keep_name_near_head(client, &target, version).await;
    Ok(())
}

/// `rooms name set` / `rooms name clear` — write the member's own name in the room: a record
/// of kind `memberProfile` with the name in `title` (`rooms/_shared/0.3`
/// `MemberProfileRecord`; trust-tasks-tf #1035). `name` empty withdraws it.
///
/// Refused before anything is sent unless the room's profile lists both `kind` and
/// `memberProfile` in `recordMembers` (a reader that predates the kind would show every
/// name as a note). The member keeps **one** such record: a later name is a new version of
/// the record it already holds, found by reading the room's records as the member — on a
/// sealed tier that opens them through the VTA, which costs a read of the room — so that a
/// retry leaves one record. On `open` it is the cleartext of `rooms/records/put/0.5`; on
/// `attributed` and `private` a body the VTA signs as the member and seals
/// (`rooms/keys/seal/0.3`), put with `rooms/keys/act/0.11`.
pub async fn cmd_rooms_name_set(
    client: &VtaClient,
    target: RoomTarget<'_>,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use vti_rooms::member_profile;
    member_profile::check_name(name)?;
    let withdrawing = member_profile::is_withdrawal(name);
    // `kind` and the name: the writer's rule asks for `kind` and `memberProfile` listed.
    let wanted = member_profile::sealed_members(name)?;
    let (sealed_tier, member) = room_tier(client, &target).await?;
    let members = writer_members(client, &target, wanted).await.map_err(|e| {
        format!(
            "{e}\n\nA member's name is a record of kind `memberProfile`, which the room's \
                 profile must list as well as `kind`."
        )
    })?;
    // `writer_members` refused unless the profile was read; the second read is the cache's.
    let listed = match target.host_did {
        Some(h) => client
            .room_record_members(target.room_id, h, None)
            .await
            .ok()
            .flatten(),
        None => None,
    };
    let lists = |m: &str| listed.as_ref().is_some_and(|l| l.iter().any(|x| x == m));

    let held = own_name_record(client, &target, sealed_tier, &member).await?;
    let (key, expected) = match &held {
        Some((key, version)) => (key.clone(), *version),
        // Create-only: a second `memberProfile` record is what a retry must not leave.
        None => (opaque_key(), 0),
    };
    let edited_at = (held.is_some() && lists("editedAt")).then(|| {
        serde_json::json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    });

    let version = if !sealed_tier {
        let mut cleartext = member_profile::cleartext(name)?;
        if let Some(w) = members.get("writtenAt") {
            cleartext.insert("writtenAt".into(), w.clone());
        }
        if let Some(e) = &edited_at {
            cleartext.insert("editedAt".into(), e.clone());
        }
        let payload = serde_json::json!({
            "roomId": target.room_id,
            "key": key,
            "cleartext": cleartext,
            "expectedVersion": expected,
        });
        // put/0.5 only: no earlier version carries `kind`.
        let (_, reply, _) = act_and_send_newest(
            client,
            &target,
            (vti_rooms::wire::ROOMS_RECORDS_PUT_V5_TYPE, payload),
            None,
        )
        .await
        .map_err(|e| put_refused(e, &target))?;
        let put: vti_rooms::wire::PutRecordResponse = parse_reply("rooms/records/put", reply)?;
        put.version
    } else {
        let mut content = SealedRecordBody::new(
            RecordLocation {
                room_id: target.room_id,
                key: &key,
                version: 1,
            },
            &member,
        );
        content.title = Some(name.to_string());
        content.kind = Some(member_profile::KIND.to_string());
        content.written_at = members
            .get("writtenAt")
            .and_then(Value::as_str)
            .map(str::to_string);
        content.edited_at = edited_at.and_then(|e| e.as_str().map(str::to_string));
        write_sealed(client, &target, content, Some(expected)).await?
    };
    if withdrawing {
        println!(
            "Withdrew your name in room {} (record {key}, version {version}, as {member}).",
            target.room_id
        );
    } else {
        println!(
            "Your name in room {} is now \"{}\" (record {key}, version {version}, as {member}). \
             Other members see it beside your records; it is your claim, not a verified one.",
            target.room_id,
            inert(name)
        );
    }
    Ok(())
}

/// The `memberProfile` record `member` already holds in the room, as `(key, version)` —
/// the one a new name is written over. On `open` the listing says each record's kind and
/// who created it; on a sealed tier the records `member` may have written (all of them where
/// the host records no author) are opened through the VTA. The most recently stored wins,
/// and of two stored at the same time the one with the greater `version` (rule 2).
pub(super) async fn own_name_record(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    sealed_tier: bool,
    member: &str,
) -> Result<Option<(String, u64)>, Box<dyn std::error::Error>> {
    own_name_record_since(client, target, sealed_tier, member, None).await
}

/// [`own_name_record`], among the records above `since_version` only — `None` reads the
/// whole room.
pub(super) async fn own_name_record_since(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    sealed_tier: bool,
    member: &str,
    since_version: Option<u64>,
) -> Result<Option<(String, u64)>, Box<dyn std::error::Error>> {
    let mut listing = list_page(client, target, None, since_version, None).await?;
    let mut cursor = listing.cursor.clone();
    while let Some(c) = cursor {
        let next = list_page(client, target, None, since_version, Some(&c)).await?;
        cursor = next.cursor.clone();
        listing.records.extend(next.records);
    }
    let active =
        |r: &&Value| r.get("status").and_then(Value::as_str).unwrap_or("active") != "retracted";
    let stamp = |r: &Value| {
        r.get("bodyStoredAt")
            .or_else(|| r.get("updatedAt"))
            .and_then(Value::as_str)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
    };
    let created_by = |r: &Value| {
        r.get("createdBy")
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    // Rule 2: the most recently stored, and of two stored at the same time the greater
    // `version` — so the pick never depends on the order the rows came in.
    let version_of = |r: &Value| r.get("version").and_then(Value::as_u64);
    let pick = |rows: Vec<&Value>| {
        rows.into_iter()
            .max_by_key(|r| (stamp(r), version_of(r)))
            .and_then(|r| {
                Some((
                    r.get("key")?.as_str()?.to_string(),
                    r.get("version")?.as_u64()?,
                ))
            })
    };
    if !sealed_tier {
        let rows: Vec<&Value> = listing
            .records
            .iter()
            .filter(active)
            .filter(|r| {
                r.get("kind").and_then(Value::as_str) == Some(vti_rooms::member_profile::KIND)
            })
            .filter(|r| created_by(r).as_deref() == Some(member))
            .collect();
        return Ok(pick(rows));
    }
    let Some(host_did) = target.host_did else {
        return Ok(None);
    };
    // Where the host records who created a record, only `member`'s need opening.
    let candidates: Vec<&Value> = listing
        .records
        .iter()
        .filter(active)
        .filter(|r| created_by(r).is_none_or(|c| c == member))
        .collect();
    let keys: Vec<String> = candidates
        .iter()
        .filter_map(|r| r.get("key").and_then(Value::as_str).map(str::to_string))
        .collect();
    let mut mine = std::collections::HashSet::new();
    for chunk in keys.chunks(vta_sdk::client::ROOM_READ_MAX_KEYS) {
        let refs: Vec<&str> = chunk.iter().map(String::as_str).collect();
        let answer = serde_json::to_value(
            client
                .room_read_batch(target.room_id, host_did, &refs, None)
                .await?,
        )?;
        for r in answer["results"].as_array().into_iter().flatten() {
            let Some(plaintext) = r["plaintext"].as_str() else {
                continue;
            };
            let Ok(bytes) = base64::Engine::decode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                plaintext,
            ) else {
                continue;
            };
            let Ok(Value::Object(body)) = serde_json::from_slice::<Value>(&bytes) else {
                continue;
            };
            if vti_rooms::member_profile::is_member_profile(&body)
                && body.get("author").and_then(Value::as_str) == Some(member)
                && let Some(k) = r["key"].as_str()
            {
                mine.insert(k.to_string());
            }
        }
    }
    Ok(pick(
        candidates
            .into_iter()
            .filter(|r| {
                r.get("key")
                    .and_then(Value::as_str)
                    .is_some_and(|k| mine.contains(k))
            })
            .collect(),
    ))
}

/// How far, in versions, a member's name record may fall behind a record it writes before it
/// writes the name again (`MemberProfileRecord`, *Near the room's head*): the largest page
/// `rooms/records/list/0.6` returns.
pub const NAME_HEAD_DISTANCE: u64 = 500;

/// Whether a write assigned `written` leaves a name record at `name_version` more than
/// [`NAME_HEAD_DISTANCE`] versions behind — when the writer writes its name again.
pub fn name_needs_rewrite(written: u64, name_version: u64) -> bool {
    written > name_version.saturating_add(NAME_HEAD_DISTANCE)
}

/// The current version of the member's name record `key`: its name (`None` where it is
/// withdrawn or not a name) and the `writtenAt` and `editedAt` it carries.
pub(super) async fn name_record_content(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    sealed_tier: bool,
    key: &str,
) -> Result<(Option<String>, Option<String>, Option<String>), Box<dyn std::error::Error>> {
    let object = if sealed_tier {
        let host_did = target
            .host_did
            .ok_or("reading a sealed record takes the host's DID")?;
        let answer = serde_json::to_value(
            client
                .room_read_batch(target.room_id, host_did, &[key], None)
                .await?,
        )?;
        let plaintext = answer["results"]
            .as_array()
            .and_then(|r| r.first())
            .and_then(|r| r["plaintext"].as_str())
            .ok_or("the VTA could not open the name record")?
            .to_string();
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, plaintext)?;
        serde_json::from_slice::<Value>(&bytes)?
    } else {
        let payload = serde_json::json!({ "roomId": target.room_id, "key": key });
        let (_, record, _) = act_and_send_newest(
            client,
            target,
            (vti_rooms::wire::ROOMS_RECORDS_GET_V3_TYPE, payload),
            None,
        )
        .await?;
        record.get("cleartext").cloned().unwrap_or(Value::Null)
    };
    let Value::Object(obj) = object else {
        return Ok((None, None, None));
    };
    let field = |k: &str| obj.get(k).and_then(Value::as_str).map(str::to_string);
    let name = vti_rooms::member_profile::check(&obj, !sealed_tier)
        .ok()
        .and_then(|()| vti_rooms::member_profile::name_of(&obj, !sealed_tier))
        .map(str::to_string);
    Ok((name, field("writtenAt"), field("editedAt")))
}

/// After a write the host assigned `written`: write the member's name again, over the same
/// record, when it is more than [`NAME_HEAD_DISTANCE`] versions behind — keeping its
/// `writtenAt`, setting no new `editedAt` (an earlier one stays as it is), and writing
/// nothing for a withdrawn name or a member with none (`MemberProfileRecord`, *Near the
/// room's head* and *Writing it again*). Best effort: the write it follows has landed, so a
/// failure here is reported and nothing more.
pub(super) async fn keep_name_near_head(client: &VtaClient, target: &RoomTarget<'_>, written: u64) {
    if let Err(e) = keep_name_near_head_inner(client, target, written).await {
        eprintln!(
            "Note: your name in room {} could not be written again near the room's head: {e}",
            target.room_id
        );
    }
}

pub(super) async fn keep_name_near_head_inner(
    client: &VtaClient,
    target: &RoomTarget<'_>,
    written: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    use vti_rooms::member_profile;
    // A name record at version 1 or later is at most `written - 1` behind.
    if written <= NAME_HEAD_DISTANCE + 1 {
        return Ok(());
    }
    let (sealed_tier, member) = room_tier(client, target).await?;
    // One page back first: a name record there is near enough, and the room's whole
    // history need not be read.
    let floor = written - NAME_HEAD_DISTANCE - 1;
    if own_name_record_since(client, target, sealed_tier, &member, Some(floor))
        .await?
        .is_some()
    {
        return Ok(());
    }
    let Some((key, version)) = own_name_record(client, target, sealed_tier, &member).await? else {
        return Ok(());
    };
    if !name_needs_rewrite(written, version) {
        return Ok(());
    }
    let (name, written_at, edited_at) =
        name_record_content(client, target, sealed_tier, &key).await?;
    // A withdrawn name is not written again.
    let Some(name) = name.filter(|n| !member_profile::is_withdrawal(n)) else {
        return Ok(());
    };
    // Still a write of a `memberProfile` record: only where the profile lists it.
    if writer_members(client, target, member_profile::sealed_members(&name)?)
        .await
        .is_err()
    {
        return Ok(());
    }
    let new_version = if !sealed_tier {
        let mut cleartext = member_profile::cleartext(&name)?;
        if let Some(w) = &written_at {
            cleartext.insert("writtenAt".into(), serde_json::json!(w));
        }
        if let Some(e) = &edited_at {
            cleartext.insert("editedAt".into(), serde_json::json!(e));
        }
        let payload = serde_json::json!({
            "roomId": target.room_id,
            "key": key,
            "cleartext": cleartext,
            "expectedVersion": version,
        });
        let (_, reply, _) = act_and_send_newest(
            client,
            target,
            (vti_rooms::wire::ROOMS_RECORDS_PUT_V5_TYPE, payload),
            None,
        )
        .await?;
        parse_reply::<vti_rooms::wire::PutRecordResponse>("rooms/records/put", reply)?.version
    } else {
        let mut content = SealedRecordBody::new(
            RecordLocation {
                room_id: target.room_id,
                key: &key,
                version: 1,
            },
            &member,
        );
        content.title = Some(name);
        content.kind = Some(member_profile::KIND.to_string());
        content.written_at = written_at;
        content.edited_at = edited_at;
        write_sealed(client, target, content, Some(version)).await?
    };
    eprintln!(
        "Wrote your name in room {} again (record {key}, version {new_version}), so readers \
         of the room's recent records find it.",
        target.room_id
    );
    Ok(())
}

/// A `memberProfile` record shown as what it is — its author's name in this room — and
/// never as a note (`MemberProfileRecord`, *Reading one*, rule 1). One whose shape is not a
/// name's is said to be refused as one.
pub(super) fn name_record_line(
    obj: &serde_json::Map<String, Value>,
    author: &str,
    open: bool,
) -> String {
    use vti_rooms::member_profile;
    match member_profile::check(obj, open) {
        Err(e) => format!(
            "A member-name record by {}, refused as a name: {e}",
            inert(author)
        ),
        Ok(()) => match member_profile::name_of(obj, open) {
            Some(n) => format!(
                "{}'s name in this room: \"{}\" — their own claim, not verified.",
                inert(author),
                inert(n)
            ),
            None => format!("{} withdrew their name in this room.", inert(author)),
        },
    }
}

/// How a reader shows an author: the DID, and the name they gave themselves in this room
/// where one was read — always beside the DID, so two members giving the same name stay
/// apart, and worded as their claim (`MemberProfileRecord`, *Showing a name*).
pub(super) fn author_line(author: &str, names: &vti_rooms::member_profile::Names) -> String {
    match names.name(author) {
        Some(n) => format!("{} (calls themselves \"{}\")", inert(author), inert(n)),
        None => inert(author),
    }
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

    /// The members as they are spelled on the wire (`vti_rooms::provenance::MEMBERS`),
    /// checked against the specification's types before anything is signed or sent. Empty
    /// when nothing is stated and `basis` is unstated.
    pub fn members(&self) -> Result<serde_json::Map<String, Value>, String> {
        let mut out = serde_json::Map::new();
        if let Some(basis) = self.basis {
            out.insert(
                "basis".into(),
                serde_json::to_value(basis).map_err(|e| e.to_string())?,
            );
        }
        if let Some(c) = self.confidence {
            out.insert("confidence".into(), serde_json::json!(c));
        }
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
        if !evidence.is_empty() {
            out.insert("evidence".into(), Value::Array(evidence));
        }
        let mut valid_for = serde_json::Map::new();
        if !self.purposes.is_empty() {
            valid_for.insert("purposes".into(), serde_json::json!(self.purposes));
        }
        if let Some(note) = &self.use_note {
            valid_for.insert("note".into(), serde_json::json!(note));
        }
        if !valid_for.is_empty() {
            out.insert("validFor".into(), Value::Object(valid_for));
        }
        if let Some(until) = &self.valid_until {
            out.insert("validUntil".into(), serde_json::json!(until));
        }
        vti_rooms::provenance::check(&out)?;
        Ok(out)
    }

    /// Put these members on `body`, inside what its author signs (`attributed`, `private`).
    pub fn apply(&self, body: &mut SealedRecordBody) -> Result<(), String> {
        let members = self.members()?;
        body.basis = self.basis;
        body.confidence = members.get("confidence").cloned();
        body.evidence = members.get("evidence").cloned();
        body.valid_for = members.get("validFor").cloned();
        body.valid_until = self.valid_until.clone();
        Ok(())
    }
}

/// What a record says about the kind of claim it is, and whether it has lapsed — shown
/// beside its author (`SealedRecordBody`, *Provenance*: a reader shows `basis`, or says none
/// was stated). Never authority.
pub(super) fn provenance_line(obj: &serde_json::Map<String, Value>) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::rooms::test_support::*;
    use serde_json::json;

    /// A newest-first page is shown in the order it was written, never in row order: an old
    /// message edited a moment ago heads the listing and is shown where it was written; a
    /// member's name is not a message (`rooms/records/list/0.7` *What a newest-first page
    /// holds*).
    #[test]
    fn a_newest_first_page_is_shown_in_the_order_it_was_written() {
        let rows = vec![
            json!({ "key": "edited", "version": 9, "createdAt": "2026-01-01T09:00:00Z",
                    "updatedAt": "2026-01-03T09:00:00Z" }),
            json!({ "key": "name", "version": 8, "kind": vti_rooms::member_profile::KIND,
                    "createdAt": "2026-01-03T08:00:00Z" }),
            json!({ "key": "newest", "version": 7, "createdAt": "2026-01-02T12:00:00Z" }),
            json!({ "key": "legacy", "version": 6, "updatedAt": "2026-01-02T10:00:00Z" }),
        ];
        let keys: Vec<&str> = conversation_order(&rows)
            .into_iter()
            .map(|r| r["key"].as_str().unwrap())
            .collect();
        assert_eq!(keys, ["edited", "legacy", "newest"]);
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

    /// `MemberProfileRecord`, *Near the room's head* (trust-tasks-tf #1038): a writer writes
    /// its name again only when the version its write was assigned exceeds the name
    /// record's by **more than** 500 — the largest page `rooms/records/list/0.6` returns.
    #[test]
    fn a_name_is_written_again_only_past_500_versions_behind() {
        assert_eq!(NAME_HEAD_DISTANCE, 500);
        assert!(
            !name_needs_rewrite(501, 1),
            "exactly 500 behind is near enough"
        );
        assert!(name_needs_rewrite(502, 1));
        assert!(!name_needs_rewrite(10, 9));
        assert!(
            !name_needs_rewrite(3, 7),
            "a name record ahead of the write"
        );
        assert!(!name_needs_rewrite(u64::MAX, u64::MAX - 500));
    }

    /// The tie-break rule 2 gained: of a member's name records stored at the same time,
    /// the greater `version` is the one written over, whatever order the listing gave.
    #[test]
    fn a_reader_names_by_the_greater_version_on_a_tie() {
        let named = |n: &str| {
            json!({ "kind": "memberProfile", "title": n, "body": "" })
                .as_object()
                .unwrap()
                .clone()
        };
        let at = Some("2026-01-01T00:00:00Z");
        let mut names = vti_rooms::member_profile::Names::default();
        names.offer("did:key:zA", &named("Seven"), at, Some(7), true);
        names.offer("did:key:zA", &named("Three"), at, Some(3), true);
        assert_eq!(names.name("did:key:zA"), Some("Seven"));
        assert_eq!(
            author_line("did:key:zA", &names),
            "did:key:zA (calls themselves \"Seven\")"
        );
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

    /// `--kind` and `--reply-to KEY[@VERSION]` as a body carries them, shape-checked.
    #[test]
    fn a_record_thread_is_the_bodys_kind_and_in_reply_to() {
        let m = RecordThread {
            kind: Some("message".into()),
            reply_to: Some("msg-1@4".into()),
        }
        .members()
        .unwrap();
        assert_eq!(m["kind"], "message");
        assert_eq!(m["inReplyTo"], json!({ "key": "msg-1", "version": 4 }));
        let m = RecordThread {
            kind: None,
            reply_to: Some("msg-1".into()),
        }
        .members()
        .unwrap();
        assert_eq!(m["inReplyTo"], json!({ "key": "msg-1" }));
        assert!(RecordThread::default().members().unwrap().is_empty());
        for bad in [
            RecordThread {
                kind: Some("Message".into()),
                reply_to: None,
            },
            RecordThread {
                kind: None,
                reply_to: Some("msg-1@four".into()),
            },
            RecordThread {
                kind: None,
                reply_to: Some("msg-1@0".into()),
            },
        ] {
            assert!(bad.members().is_err(), "{bad:?}");
        }
    }

    /// A member the profile does not list is refused with the command that lists it — every
    /// member already listed, and the one refused.
    #[test]
    fn a_refused_record_member_prints_the_profile_command() {
        let target = prune_target();
        let refused = vta_sdk::client::check_record_members(
            target.room_id,
            &json!({ "kind": "reaction", "inReplyTo": { "key": "k" } }),
            Some(&["kind".to_string()]),
            None,
        )
        .unwrap_err();
        let text = record_members_refused(refused, &target).to_string();
        assert!(
            text.contains(
                "pnm rooms profile set --room did:webvh:Qm:example.com:rooms:northwind \
                 --host-did did:web:host.example --record-members kind,inReplyTo"
            ),
            "{text}"
        );
        assert!(text.contains("Nothing was written"), "{text}");
    }

    /// A name record reads as its author's name — or a withdrawal, or a refusal — never as
    /// a note; an author is shown by DID with the name beside it, as their own claim.
    #[test]
    fn a_name_record_is_shown_as_a_name_and_beside_its_authors_did() {
        let obj = |v: Value| v.as_object().unwrap().clone();
        let named = obj(serde_json::json!({ "kind": "memberProfile", "title": "Alice" }));
        let line = name_record_line(&named, "did:key:zA", false);
        assert!(
            line.contains("did:key:zA's name in this room: \"Alice\""),
            "{line}"
        );
        assert!(line.contains("not verified"), "{line}");
        let withdrawn = obj(serde_json::json!({ "kind": "memberProfile", "title": "" }));
        assert!(name_record_line(&withdrawn, "did:key:zA", false).contains("withdrew"));
        let bad = obj(serde_json::json!({ "kind": "memberProfile", "title": "A", "body": "x" }));
        assert!(name_record_line(&bad, "did:key:zA", false).contains("refused as a name"));

        let mut names = vti_rooms::member_profile::Names::default();
        names.offer("did:key:zA", &named, None, None, false);
        assert_eq!(
            author_line("did:key:zA", &names),
            "did:key:zA (calls themselves \"Alice\")"
        );
        assert_eq!(author_line("did:key:zB", &names), "did:key:zB");
    }

    /// `rooms/records/put/0.5` Producer item 9: an open room's cleartext carries the same
    /// provenance a sealed body signs, spelled the same, so a reader reads one shape.
    #[test]
    fn an_open_record_carries_the_provenance_a_sealed_body_signs() {
        let p = stated();
        let members = p.members().unwrap();
        assert_eq!(members["basis"], "inferred");
        assert_eq!(members["confidence"], 0.6);
        assert_eq!(
            members["evidence"],
            json!([
                {"kind": "record", "key": "meetings/q3", "version": 3},
                {"kind": "credential", "credentialId": "urn:uuid:1"}
            ])
        );
        assert_eq!(members["validFor"]["note"], "renewal only");
        assert_eq!(members["validUntil"], "2026-12-31T23:59:59Z");

        let mut body = SealedRecordBody::new(
            RecordLocation {
                room_id: "did:example:room",
                key: "k",
                version: 1,
            },
            "did:key:zA",
        );
        p.apply(&mut body).unwrap();
        let Value::Object(signed) = serde_json::to_value(&body).unwrap() else {
            panic!("a body is an object");
        };
        for m in vti_rooms::provenance::MEMBERS {
            assert_eq!(signed.get(m), members.get(m), "{m} differs between tiers");
        }
    }

    #[test]
    fn unstated_provenance_adds_nothing_to_an_open_record() {
        assert!(RecordProvenance::default().members().unwrap().is_empty());
    }

    /// Checked before anything is signed or sent, on either tier.
    #[test]
    fn provenance_the_specification_refuses_is_refused_before_sending() {
        let mut p = stated();
        p.confidence = Some(1.5);
        assert!(p.members().unwrap_err().contains("confidence"));
        let mut p = stated();
        p.cite_records = vec!["k@latest".into()];
        assert!(p.members().unwrap_err().contains("--cite-record"));
    }
}
