//! Membership offers: listing, renewing and accepting them.

use super::*;

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
// The listing is `vtc/rooms/offers/list/0.4`, completed at `rooms/keys/act/0.10`: the
// community's offers with their descriptions, and the renewals of the rooms the member is
// already in (`renewsAt`). A VTA or a community that serves neither is reported, never
// read at an older version.

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
pub(super) enum OfferStepError {
    /// The member's VTA did not complete the document (`rooms/keys/act`).
    Act(VtaError),
    /// The community refused the completed document, or did not answer it.
    Community(vtc_client::VtcError),
    /// Neither: the document could not be built or serialised.
    Local(Box<dyn std::error::Error>),
}

impl OfferStepError {
    /// The error to report, with a hint where the operator's fix is known.
    pub(super) fn report(self, target: &OfferTarget<'_>) -> Box<dyn std::error::Error> {
        match self {
            Self::Act(e) => {
                let text = e.to_string();
                let hint = if matches!(e, VtaError::UnsupportedTaskType { .. }) {
                    "\n\nYour VTA does not serve rooms/keys/act/0.10, which signs this request \
                     as you: upgrade it."
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
/// (`rooms/keys/act/0.10`) and send
/// it to the community. Returns the community's response
/// payload, or the party that failed.
#[allow(deprecated)] // act/0.10, seal/0.2 and get/0.2 are what this CLI sends until it moves (trust-tasks-tf #1027)
pub(super) async fn act_and_send_offer(
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

/// One offer as this client shows it: `vtc/rooms/offers/list/0.4`'s, with the room's
/// `description` when it has one.
pub(super) type CommunityOffer = vti_specs::vtc::rooms::offers::list::v0_4::OfferV2;

/// A renewal of an admission the member holds (`vtc/rooms/offers/list/0.4`).
pub(super) type CommunityRenewal = vti_specs::vtc::rooms::offers::list::v0_4::Renewal;

/// What a listing answered: the offers, and the renewals.
pub(super) type OffersListing = (Vec<CommunityOffer>, Vec<CommunityRenewal>);

/// One page of the community's `vtc/rooms/offers/list/0.4` answer: its offers, the next
/// cursor, and its renewals.
#[allow(clippy::type_complexity)]
pub(super) fn offers_page(
    reply: Value,
) -> Result<(Vec<CommunityOffer>, Option<String>, Vec<CommunityRenewal>), Box<dyn std::error::Error>>
{
    use vti_specs::vtc::rooms::offers::list::v0_4;
    let page: v0_4::Response = parse_reply("vtc/rooms/offers/list/0.4", reply)?;
    Ok((
        page.items,
        page.next_cursor.map(|c| c.to_string()),
        page.renewals,
    ))
}

/// Every offer the community has made to the member, and the renewals of the rooms they are
/// in: `vtc/rooms/offers/list/0.4`, signed as the member through `rooms/keys/act/0.10`, one
/// page at a time. A VTA or a community that serves neither is told so; nothing older is
/// asked.
pub(super) async fn list_offers(
    client: &VtaClient,
    target: &OfferTarget<'_>,
) -> Result<OffersListing, Box<dyn std::error::Error>> {
    use trust_tasks_rs::Payload as _;
    let type_uri = vti_specs::vtc::rooms::offers::list::v0_4::Payload::TYPE_URI;
    let mut items = Vec::new();
    let mut renewals = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let payload = match &cursor {
            Some(c) => serde_json::json!({ "cursor": c }),
            None => serde_json::json!({}),
        };
        let reply = act_and_send_offer(client, target, type_uri, payload)
            .await
            .map_err(|e| e.report(target))?;
        let page = offers_page(reply)?;
        items.extend(page.0);
        renewals.extend(page.2);
        match page.1 {
            Some(next) => cursor = Some(next),
            None => return Ok((items, renewals)),
        }
    }
}

/// `pnm rooms offers list` — the rooms the community has offered you, each with what it is
/// for when the community says.
pub async fn cmd_rooms_offers_list(
    client: &VtaClient,
    target: OfferTarget<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (offers, renewals) = list_offers(client, &target).await?;
    // JSON under --json or off a terminal, like every read (#2588).
    if crate::render::is_json_output() {
        crate::render::print_json(&serde_json::json!({
            "offers": offers,
            "renewals": renewals,
        }))?;
        return Ok(());
    }
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
pub(super) fn renewal_lines(r: &CommunityRenewal, target: &OfferTarget<'_>) -> String {
    let actions: Vec<String> = r.actions.0.iter().map(ToString::to_string).collect();
    format!(
        "{}  {}  [{}]  {}  renewal  until {} (renews {})\n  renew: {}\n",
        r.room_id.as_str(),
        inert(r.label.as_str()),
        r.visibility,
        actions.join(","),
        r.valid_until.to_rfc3339(),
        r.renews_at.to_rfc3339(),
        renew_command(r.room_id.as_str(), target),
    )
}

/// The `pnm rooms offers renew` line for one renewal, ready to paste.
pub(super) fn renew_command(room_id: &str, target: &OfferTarget<'_>) -> String {
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
pub(super) async fn held_room_credential(
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
        // A room's membership is a Data Integrity credential, so its body is a
        // JSON object; a body carried as bytes is some other credential.
        let subject = match &got {
            vault_get::Response::Variant0 { credential, .. } => credential
                .get("credentialSubject")
                .and_then(|s| s.get("id"))
                .and_then(Value::as_str),
            _ => None,
        };
        if subject == Some(member) {
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
/// and authority in your VTA in place of the ones they renew (`vtc/rooms/offers/list/0.4`
/// surface items 1–3, carried unchanged into 0.4). Storing one already stored is success, so any surface may collect it
/// first.
pub async fn cmd_rooms_offers_renew(
    client: &VtaClient,
    target: OfferTarget<'_>,
    room_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_, renewals) = list_offers(client, &target).await?;
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
        renewal.renews_at.to_rfc3339(),
    );
    Ok(())
}

/// The lines `pnm rooms offers list` prints for one offer. The label and description are
/// the community's text: control characters in them never reach the terminal, and the
/// description is kept to one line.
pub(super) fn offer_lines(o: &CommunityOffer, target: &OfferTarget<'_>) -> String {
    use vti_specs::vtc::rooms::offers::list::v0_4::OfferV2State;
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

/// The `pnm rooms offers accept` line for one offer, ready to paste: every value filled in,
/// so the operator never types a `<placeholder>` a shell reads as a redirect.
pub(super) fn accept_command(room_id: &str, target: &OfferTarget<'_>) -> String {
    format!(
        "pnm rooms offers accept --room {} --vtc {} --vtc-did {} --member {}",
        shell_word(room_id),
        shell_word(target.vtc_url),
        shell_word(target.vtc_did),
        shell_word(target.member),
    )
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
    use vti_specs::vtc::rooms::offers::accept::v0_1 as accept;

    let (offers, _) = list_offers(client, &target).await?;
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
pub(super) async fn holds_group(
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
pub(super) async fn offered_key_package(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::rooms::test_support::*;
    use serde_json::json;

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

    /// `vtc/rooms/offers/list/0.4`: the offers, and the renewals of rooms the member is in
    /// (`renewsAt`), each printed with the command that collects it.
    #[test]
    fn an_offers_list_0_4_page_carries_renewals_and_their_renew_command() {
        let (items, _, renewals) = offers_page(json!({
            "items": [offer_v2(None)],
            "renewals": [{
                "roomId": "did:webvh:Qm:rooms.example:wg", "host": "did:example:community",
                "label": "Working group", "visibility": "attributed", "actions": ["read"],
                "validUntil": "2027-11-10T00:00:00Z", "renewsAt": "2026-11-10T00:00:00Z",
                "issuedAt": "2026-10-20T09:00:00Z",
                "credentials": { "membership": "{}", "authority": "{}" },
            }],
        }))
        .expect("a 0.4 page");
        assert_eq!(items.len(), 1);
        assert_eq!(renewals.len(), 1);
        let lines = renewal_lines(&renewals[0], &offer_target());
        assert!(lines.contains("renewal  until 2027-11-10"), "{lines}");
        assert!(
            lines.contains("pnm rooms offers renew --room did:webvh:Qm:rooms.example:wg"),
            "{lines}"
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
}
