//! The owner's group commands: create, add, remove, renew, revoke.

use super::*;

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
/// `renew/0.2` and `remove/0.4`, with `details` `member`, `code` and `listKept` —
/// `rooms/owner/group/remove/0.4` item 8.2. The earlier removal did not take effect, and
/// nothing of `this` was done: the fix is to run the command again, then remove the
/// earlier member again if that is still wanted.
pub(super) fn earlier_removal_refused(
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
    if !task.ends_with(":earlierRemovalRefused") {
        return None;
    }
    let d = details.as_ref()?;
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

/// `rooms owner group-remove` — remove a member from a room
/// (`rooms/owner/group/remove/0.4`, trust-tasks-tf #975).
///
/// On an `attributed` room the room's key (`signing_key_id`, required there) withdraws the
/// member's credentials at the host first, and then the room advances — the removal takes
/// effect at the host at once. On a `private` room, where the host cannot be told whom to
/// refuse, the same version removes their leaf alone and says so (`withdrawn: false`): their
/// credentials stay valid at the host until they expire, and this never reports that as a
/// withdrawal.
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
        let fix = match &e {
            VtaError::Rejected { code, .. }
                if code == "rooms/owner/group/remove:noSigningKey" && signing_key_id.is_none() =>
            {
                format!(
                    "\n\n{room_id} is not private: removing {member} withdraws their credentials \
                     at the host, signed as the room. Run\n    pnm rooms owner group-remove \
                     --room {room_id} --host-did {host_did} --member {member} --signing-key \
                     <the room's key>"
                )
            }
            _ => String::new(),
        };
        format!(
            "{e}{fix}\n\n`epochConflict` means another admin advanced the room: catch up and \
             retry. `hostUnreachable` leaves the outcome unknown; running this again \
             settles it with the host before anything else. `ownLeaf` means {member} is \
             you: hand the room on with rooms/owner/transfer instead. `noSigningKey` means \
             this VTA will not let you name the room's key — check `pnm keys list`."
        )
    };
    // Under one idempotency key, so a retry after a lost reply reports the removal that
    // happened instead of `notMember`.
    let resp = client
        .idempotent(|| {
            client.room_group_remove(
                room_id,
                host_did,
                member,
                signing_key_id,
                mirrors,
                until,
                reason,
            )
        })
        .await
        .map_err(|e| {
            // Item 8.2: an earlier removal did not take effect, and this one was not
            // started. Say which member, whether their withdrawal survives, and what to run.
            earlier_removal_refused(
                &e,
                room_id,
                host_did,
                signing_key_id,
                &format!("remove {member}"),
            )
            .unwrap_or_else(|| hint(e))
        })?;
    if !resp.withdrawn {
        // A private room: never represented as a withdrawal (the producer requirement).
        println!(
            "Removed {member} from {room_id}'s group; the room is now at epoch {}.",
            resp.epoch
        );
        println!(
            "  Nothing sealed from now on is readable to them. {room_id} is private, so their \
             credentials are NOT withdrawn at the host: they stay valid until they expire. \
             To reset every credential the room has issued, run `pnm rooms owner revoke \
             --reset` and re-admit those who remain."
        );
        return Ok(());
    }
    let r = serde_json::to_value(&resp).unwrap_or_default();
    println!(
        "Removed {member} from {room_id}: withdrawn at the host from {} (revocation list {}), \
         and the room is now at epoch {}.",
        r["revokedAt"].as_str().unwrap_or("now"),
        r["revocation"]["sequence"],
        r["epoch"]
    );
    if !resp.mirrors_pending.is_empty() {
        let pending: Vec<&str> = resp.mirrors_pending.iter().map(|m| m.as_str()).collect();
        println!(
            "  Not yet withdrawn at: {}. Deliver it with `pnm rooms owner revoke --room \
             {room_id} --signing-key {} --host <did>` (no withdrawal).",
            pending.join(", "),
            signing_key_id.unwrap_or("<the room's key>")
        );
    }
    println!(
        "  The host refuses their credentials, and anything they delegated, from now on. \
         Nothing they already read can be recalled."
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
    use vti_specs::rooms::owner::revoke::v0_1::Withdrawal;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::rooms::test_support::*;
    use serde_json::json;

    /// `earlierRemovalRefused` at add 0.3 / renew 0.2 / remove 0.4 is explained alike; a
    /// `hostRefused` (`{code, reason}`, or `{stage, code}`) is not.
    #[test]
    fn an_earlier_removal_is_explained_whichever_version_reported_it() {
        let d =
            json!({ "member": "did:key:zEarlier", "code": "permissionDenied", "listKept": true });
        for code in [
            "rooms/owner/group/add:earlierRemovalRefused",
            "rooms/owner/group/renew:earlierRemovalRefused",
            "rooms/owner/group/remove:earlierRemovalRefused",
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
}
