//! `cnm member …` — the batch-1 member-facing VTC verbs, served as signed
//! Trust Tasks by the community's VTC (`vtc/members/{renew,rotate,
//! rotate-challenge,personhood/revoke}`, `vtc/relationships/{list,publish,
//! revoke}`, `vtc/endorsements/issue`).
//!
//! Every verb here is dispatched by the VTC's spine
//! (`trust_tasks::member_tasks`, #1809) and reached the way `cnm access`
//! reaches its ACL verbs ([`vtc_target::connect_for_tasks`]): signed with
//! this profile's own key, over TSP when the VTC advertises it, else
//! DIDComm, else a signed document over HTTPS (`--transport` pins one). The
//! VTC authorizes each verb from the signer's own ACL row at the moment it
//! runs — a member acting on their own membership and relationships, or an
//! administrator / issuer where the specification names one.

use clap::Subcommand;
use serde_json::Value;
use vta_cli_common::render::{DIM, GREEN, RESET, is_json_output, print_json};
use vta_sdk::session::TransportChoice;
use vtc_client::{RotationReason, VtcClient, VtcError};

use crate::vtc::{self as vtc_target, VtcTarget};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Subcommand)]
pub enum MemberCommands {
    /// Renew your own membership: re-issues your VMC + role credential.
    Renew,

    /// Rotate your own DID — a two-step, dual-signed ceremony.
    Rotate {
        #[command(subcommand)]
        command: RotateCommands,
    },

    /// Clear a member's personhood flag. The subject themselves, or an
    /// administrator.
    RevokePersonhood {
        /// The member DID whose personhood is revoked.
        did: String,
    },

    /// Verifiable Relationship Credentials (VRCs) between members.
    Relationships {
        #[command(subcommand)]
        command: RelationshipCommands,
    },

    /// Mint a custom Verifiable Endorsement Credential. Admin or Issuer.
    Endorse {
        /// The DID the endorsement is about.
        subject: String,
        /// The endorsement type's registered URI.
        #[arg(long = "type")]
        type_uri: String,
        /// The claim body, as a JSON object.
        #[arg(long)]
        claim: String,
        /// Override the community's default validity (30 days): N[s|m|h|d|w].
        #[arg(long)]
        valid_for: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum RotateCommands {
    /// Open a rotation ceremony and print the challenge to sign.
    Challenge {
        /// Why you're rotating: routine, compromise, device-loss, migration
        /// or unspecified (the default when omitted).
        #[arg(long)]
        reason: Option<String>,
    },

    /// Complete a rotation opened by `challenge`.
    ///
    /// `old-signature` and `new-signature` are each a hex-encoded Ed25519
    /// signature over the domain tag `challenge` printed
    /// (`signingPayloadHex`, decoded from hex) followed by the compact JSON
    /// `{"rotationId":…,"oldDid":…,"newDid":…,"expiresAt":…}` —
    /// `canonicalTemplate` with `newDid` filled in and `expiresAt` as Unix
    /// seconds. Compute them with the old and new DID's own keys; this
    /// command only carries the finished ceremony to the VTC, since the new
    /// key is not one this profile holds.
    Finish {
        #[arg(long)]
        rotation_id: String,
        #[arg(long)]
        old_did: String,
        #[arg(long)]
        new_did: String,
        #[arg(long)]
        old_signature: String,
        #[arg(long)]
        new_signature: String,
    },
}

#[derive(Subcommand)]
pub enum RelationshipCommands {
    /// List the Verifiable Relationship Credentials naming a member.
    List {
        /// The member DID.
        did: String,
    },

    /// Publish a self-issued Verifiable Relationship Credential.
    Publish {
        /// Path to the signed VRC, as JSON.
        vrc_file: String,
        /// Path to a proof-of-possession document, when the VRC's `issuer`
        /// is not your own membership DID (a pairwise relationship DID).
        #[arg(long)]
        pop_file: Option<String>,
    },

    /// Revoke a relationship credential you issued (or, as an administrator,
    /// any). Any other caller gets the same "not found" a missing id would.
    /// Does not cover an edge published under a pairwise relationship DID
    /// (not your own membership DID) — that still needs the VTC's bearer
    /// route with a proof of possession, which this command does not send.
    Revoke {
        /// The relationship (VRC) id.
        id: String,
    },
}

/// Run one `cnm member` command. Every verb is a signed Trust Task.
pub async fn run(
    command: MemberCommands,
    keyring_key: &str,
    target: &VtcTarget,
    transport: TransportChoice,
) -> CliResult {
    let vtc = vtc_target::connect_for_tasks(keyring_key, target, transport).await?;
    let outcome = run_command(command, &vtc.client).await;
    vtc.client.shutdown().await;
    outcome
}

async fn run_command(command: MemberCommands, vtc: &VtcClient) -> CliResult {
    match command {
        MemberCommands::Renew => {
            let renewed = vtc.renew().await.map_err(member_error)?;
            report(&serde_json::to_value(&renewed)?, "renewed")
        }
        MemberCommands::Rotate { command } => run_rotate(command, vtc).await,
        MemberCommands::RevokePersonhood { did } => {
            let revoked = vtc.revoke_personhood(&did).await.map_err(member_error)?;
            report(&serde_json::to_value(&revoked)?, "personhood revoked")
        }
        MemberCommands::Relationships { command } => run_relationships(command, vtc).await,
        MemberCommands::Endorse {
            subject,
            type_uri,
            claim,
            valid_for,
        } => {
            let claim: Value = serde_json::from_str(&claim)
                .map_err(|e| format!("--claim is not valid JSON: {e}"))?;
            let valid_for_seconds = valid_for
                .as_deref()
                .map(vta_cli_common::duration::parse_duration_secs)
                .transpose()?;
            let issued = vtc
                .issue_endorsement(&subject, &type_uri, claim, valid_for_seconds)
                .await
                .map_err(member_error)?;
            report(&serde_json::to_value(&issued)?, "issued")
        }
    }
}

async fn run_rotate(command: RotateCommands, vtc: &VtcClient) -> CliResult {
    match command {
        RotateCommands::Challenge { reason } => {
            let reason = reason.as_deref().map(parse_reason).transpose()?;
            let challenge = vtc.rotate_challenge(reason).await.map_err(member_error)?;
            report(
                &serde_json::to_value(&challenge)?,
                "rotation challenge opened",
            )
        }
        RotateCommands::Finish {
            rotation_id,
            old_did,
            new_did,
            old_signature,
            new_signature,
        } => {
            let rotated = vtc
                .rotate(
                    &rotation_id,
                    &old_did,
                    &new_did,
                    &old_signature,
                    &new_signature,
                )
                .await
                .map_err(member_error)?;
            report(&serde_json::to_value(&rotated)?, "rotated")
        }
    }
}

async fn run_relationships(command: RelationshipCommands, vtc: &VtcClient) -> CliResult {
    match command {
        RelationshipCommands::List { did } => {
            let items = vtc.list_relationships(&did).await.map_err(member_error)?;
            if is_json_output() {
                print_json(&items)?;
            } else if items.is_empty() {
                println!("{DIM}no relationships.{RESET}");
            } else {
                for r in &items {
                    println!(
                        "{}  {} -> {}  {DIM}({}){RESET}",
                        r.id, r.issuer_did, r.subject_did, r.created_at
                    );
                }
            }
            Ok(())
        }
        RelationshipCommands::Publish { vrc_file, pop_file } => {
            let vrc: Value = serde_json::from_str(&std::fs::read_to_string(&vrc_file)?)?;
            let pop = pop_file
                .map(|p| -> CliResult<Value> {
                    Ok(serde_json::from_str(&std::fs::read_to_string(&p)?)?)
                })
                .transpose()?;
            let published = vtc
                .publish_relationship(vrc, pop)
                .await
                .map_err(member_error)?;
            report(&serde_json::to_value(&published)?, "published")
        }
        RelationshipCommands::Revoke { id } => {
            let revoked = vtc.revoke_relationship(&id).await.map_err(member_error)?;
            report(&serde_json::to_value(&revoked)?, "revoked")
        }
    }
}

fn parse_reason(s: &str) -> CliResult<RotationReason> {
    Ok(match s {
        "routine" => RotationReason::Routine,
        "compromise" => RotationReason::Compromise,
        "device-loss" | "deviceLoss" => RotationReason::DeviceLoss,
        "migration" => RotationReason::Migration,
        "unspecified" => RotationReason::Unspecified,
        other => {
            return Err(format!(
                "--reason must be one of routine, compromise, device-loss, migration, \
                 unspecified (got `{other}`)"
            )
            .into());
        }
    })
}

/// Print a reply as pretty JSON, or its structured form under `--json`.
fn report(value: &Value, verb: &str) -> CliResult {
    if is_json_output() {
        print_json(value)?;
    } else {
        println!("{GREEN}{verb}{RESET}");
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

fn member_error(err: VtcError) -> Box<dyn std::error::Error> {
    err.to_string().into()
}
