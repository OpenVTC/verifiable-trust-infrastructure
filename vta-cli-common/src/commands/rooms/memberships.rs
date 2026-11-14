//! `rooms memberships`: the rooms the member holds and what each one's state
//! means.

use super::*;

/// `vtc/rooms/memberships/list/0.2`, signed as the member through `rooms/keys/act/0.10`:
/// the community's whole record of their admissions, with each room's own state (one page at
/// a time). A community that does not serve 0.2 is reported, never read at 0.1.
pub(super) async fn list_memberships(
    client: &VtaClient,
    target: &OfferTarget<'_>,
) -> Result<
    Vec<vti_specs::vtc::rooms::memberships::list::v0_2::RoomMembershipV2>,
    Box<dyn std::error::Error>,
> {
    use trust_tasks_rs::Payload as _;
    use vti_specs::vtc::rooms::memberships::list::v0_2 as list;
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

/// What a surface shows for one room — `vtc/rooms/memberships/list/0.2` *One record, every
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
    /// Admitted, but the room was closed to every member — archived with no access, or
    /// scheduled for removal: its host refuses the member's credentials, and the community
    /// restores them if the room reopens.
    Suspended,
    /// Removed by an administrator.
    Removed,
}

impl RoomStanding {
    /// The table in `vtc/rooms/memberships/list/0.2`.
    pub fn of(state: &str, sealed: bool, held: bool, welcome_kept: bool) -> Self {
        match state {
            "offered" => Self::Offered,
            "removed" => Self::Removed,
            "suspended" => Self::Suspended,
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
            Self::Suspended => "suspended",
            Self::Removed => "removed",
        }
    }
}

/// What the room's own state means to the member, in a line — `None` for an active room.
/// `room_state` and `room_access` are `vtc/rooms/memberships/list/0.2`'s `roomState` and
/// `roomAccess`; `purge_at` its `purgeAt`, RFC 3339.
pub fn room_condition(
    room_state: &str,
    room_access: Option<&str>,
    purge_at: Option<&str>,
) -> Option<String> {
    match (room_state, room_access) {
        ("active", _) => None,
        ("archived", Some("readOnly")) => Some(
            "Archived, read-only: you can still read it; nothing can be written, uploaded or \
             curated until an administrator unarchives it."
                .into(),
        ),
        ("archived", _) => Some(
            "Archived, closed for now: the community withdrew everyone's access and kept the \
             content. If it is reopened your access is restored — collect it with \
             `pnm rooms offers renew`."
                .into(),
        ),
        ("removalScheduled", _) | ("purging", _) => Some(match purge_at {
            Some(at) => format!(
                "Being removed: closed to every member, and its content is deleted on {at}. \
                 Nothing of it can be read from now on."
            ),
            None => {
                "Being removed: closed to every member, and its content is being deleted.".into()
            }
        }),
        ("removed", _) => Some("Removed: the community deleted the room and its content.".into()),
        (other, _) => Some(format!("The room is {other}.")),
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
        let room_state = r.room_state.to_string();
        let room_access = r.room_access.as_ref().map(ToString::to_string);
        let purge_at = r
            .purge_at
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
        let condition = room_condition(&room_state, room_access.as_deref(), purge_at.as_deref());
        println!(
            "{room_id}  {}  [{}]  {}  {}{}",
            inert(r.label.as_str()),
            r.visibility,
            actions.join(","),
            standing.label(),
            if condition.is_some() {
                format!("  ({room_state})")
            } else {
                String::new()
            },
        );
        if let Some(c) = &condition {
            println!("  {c}");
        }
        // No acceptance to finish, or re-admission to ask for, in a room that admits no one.
        let room_admits = room_state == "active";
        match standing {
            RoomStanding::Offered | RoomStanding::Unfinished if room_admits => {
                println!("  accept: {}", accept_command(room_id, &target));
            }
            RoomStanding::NeedsReadmission if room_admits => println!(
                "  Your VTA never joined this room's group and the community no longer keeps \
                 the Welcome: ask an administrator to remove and re-admit you."
            ),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `vtc/rooms/memberships/list/0.1`'s table: the same answers, the same standing.
    #[test]
    fn a_rooms_condition_says_what_its_state_means() {
        assert_eq!(room_condition("active", None, None), None);
        assert!(
            room_condition("archived", Some("readOnly"), None)
                .unwrap()
                .contains("read-only")
        );
        assert!(
            room_condition("archived", Some("noAccess"), None)
                .unwrap()
                .contains("pnm rooms offers renew")
        );
        assert!(
            room_condition(
                "removalScheduled",
                Some("noAccess"),
                Some("2026-12-02T10:00:00Z")
            )
            .unwrap()
            .contains("2026-12-02T10:00:00Z")
        );
        assert!(
            room_condition("removed", None, None)
                .unwrap()
                .starts_with("Removed")
        );
    }

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
        // 0.2: an admission the room's closure withdrew, whatever the custody.
        assert_eq!(RoomStanding::of("suspended", true, true, true), Suspended);
        assert_eq!(
            RoomStanding::of("suspended", false, false, false),
            Suspended
        );
    }
}
