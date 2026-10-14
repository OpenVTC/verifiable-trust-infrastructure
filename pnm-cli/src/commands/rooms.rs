//! `pnm rooms …` dispatch — thin shim over the shared room commands.
//!
//! The implementations live in `vta_cli_common::commands::rooms`; this maps the
//! parsed subcommand onto them and supplies the one thing the shared layer
//! cannot obtain for itself: the operator's own signing identity.
//!
//! # Why the signer comes from the stored session
//!
//! A room request is signed by the party the presentation was minted **for**,
//! and the VTA mints for the DID the client authenticated as. `VtaClient` does
//! not expose its signing key — correctly; it is held in the session store —
//! so the identity is read from the same place authentication reads it. Taking
//! it from anywhere else would produce a presentation bound to one DID and a
//! signature by another, which the host refuses and which reads as a
//! credential problem rather than a wiring one.

use vta_cli_common::commands::rooms::{self, RoomSigner, RoomTarget};
use vta_sdk::client::VtaClient;

use crate::cli::{RoomCommands, RoomFileCommands, RoomOwnerCommands};

/// The operator's DID and key, from the session this CLI authenticates with.
fn signer(keyring_key: &str) -> Result<vta_sdk::session::SessionInfo, Box<dyn std::error::Error>> {
    crate::auth::loaded_session(keyring_key).ok_or_else(|| -> Box<dyn std::error::Error> {
        "not authenticated — run `pnm auth login` first. A room request is signed by the \
         DID your VTA minted the presentation for, so this needs your session."
            .into()
    })
}

pub(crate) async fn run(
    client: &VtaClient,
    keyring_key: &str,
    command: RoomCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    // Sealing and opening locally need no host and no signing identity of their
    // own: the VTA is the only party, and the client is already authenticated to it.
    let command = match command {
        RoomCommands::File {
            command:
                RoomFileCommands::Seal {
                    path,
                    room_id,
                    out,
                    pad,
                },
        } => return rooms::cmd_rooms_file_seal(client, &room_id, &path, &out, pad).await,
        RoomCommands::File {
            command: RoomFileCommands::Open { dir, room_id, out },
        } => return rooms::cmd_rooms_file_open(client, &room_id, &dir, &out).await,
        // The owner's group verbs are calls to this VTA alone: it reaches the host
        // itself, as its principal, so they need no session key of their own.
        RoomCommands::Owner { command } => {
            return match command {
                RoomOwnerCommands::GroupCreate {
                    room_id,
                    signing_key,
                    member,
                } => {
                    rooms::cmd_rooms_owner_group_create(
                        client,
                        &room_id,
                        &signing_key,
                        member.as_deref(),
                    )
                    .await
                }
                RoomOwnerCommands::GroupAdd {
                    room_id,
                    host_did,
                    member,
                    key_package,
                    reason,
                    out,
                } => {
                    rooms::cmd_rooms_owner_group_add(
                        client,
                        &room_id,
                        &host_did,
                        &member,
                        &key_package,
                        reason.as_deref(),
                        &out,
                    )
                    .await
                }
            };
        }
        other => other,
    };

    let session = signer(keyring_key)?;
    let signer = RoomSigner {
        did: &session.client_did,
        key_multibase: &session.private_key_multibase,
    };

    match command {
        RoomCommands::File { command } => match command {
            RoomFileCommands::Put {
                path,
                room_id,
                host,
                host_did,
                title,
                description,
                tags,
                pad,
            } => {
                rooms::cmd_rooms_file_put(
                    client,
                    RoomTarget {
                        host_url: &host,
                        host_did: host_did.as_deref(),
                        room_id: &room_id,
                    },
                    signer,
                    &path,
                    title,
                    description,
                    tags,
                    pad,
                )
                .await
            }
            RoomFileCommands::Get {
                key,
                room_id,
                host,
                host_did,
                out,
            } => {
                rooms::cmd_rooms_file_get(
                    client,
                    RoomTarget {
                        host_url: &host,
                        host_did: host_did.as_deref(),
                        room_id: &room_id,
                    },
                    signer,
                    &key,
                    out.as_deref(),
                )
                .await
            }
            RoomFileCommands::Seal { .. } | RoomFileCommands::Open { .. } => {
                unreachable!("local file commands are dispatched before the signer is read")
            }
        },
        RoomCommands::List {
            room_id,
            host,
            host_did,
            prefix,
            since_version,
            limit,
        } => {
            rooms::cmd_rooms_list(
                client,
                RoomTarget {
                    host_url: &host,
                    host_did: host_did.as_deref(),
                    room_id: &room_id,
                },
                signer,
                prefix.as_deref(),
                since_version,
                limit,
            )
            .await
        }
        RoomCommands::Get {
            key,
            room_id,
            host,
            host_did,
        } => {
            rooms::cmd_rooms_get(
                client,
                RoomTarget {
                    host_url: &host,
                    host_did: host_did.as_deref(),
                    room_id: &room_id,
                },
                signer,
                &key,
            )
            .await
        }
        RoomCommands::Put {
            key,
            body,
            room_id,
            host,
            host_did,
            title,
            expected_version,
        } => {
            rooms::cmd_rooms_put(
                client,
                RoomTarget {
                    host_url: &host,
                    host_did: host_did.as_deref(),
                    room_id: &room_id,
                },
                signer,
                &key,
                title,
                body,
                expected_version,
            )
            .await
        }
        RoomCommands::Curate {
            key,
            room_id,
            host,
            host_did,
            status,
            pin,
            unpin,
            reason,
        } => {
            let pinned = rooms::pinned_from_flags(pin, unpin);
            rooms::cmd_rooms_curate(
                client,
                RoomTarget {
                    host_url: &host,
                    host_did: host_did.as_deref(),
                    room_id: &room_id,
                },
                signer,
                &key,
                status,
                pinned,
                reason,
            )
            .await
        }
        RoomCommands::Renew {
            epoch,
            room_id,
            host,
            host_did,
            reason,
        } => {
            rooms::cmd_rooms_renew(
                client,
                RoomTarget {
                    host_url: &host,
                    host_did: host_did.as_deref(),
                    room_id: &room_id,
                },
                signer,
                epoch,
                reason,
            )
            .await
        }
        RoomCommands::Owner { .. } => {
            unreachable!("the owner's group verbs are answered above, before the session is read")
        }
        RoomCommands::Create {
            room_id,
            host,
            host_did,
            visibility,
            retention_days,
        } => {
            rooms::cmd_rooms_create(
                RoomTarget {
                    host_url: &host,
                    host_did: host_did.as_deref(),
                    room_id: &room_id,
                },
                signer,
                &visibility,
                retention_days,
            )
            .await
        }
    }
}
