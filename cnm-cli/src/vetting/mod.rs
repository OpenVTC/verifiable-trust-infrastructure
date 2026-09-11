//! `cnm vetting …` — the community-admin side of peer identity vetting.
//!
//! Every command drives the VTC's vetting admin REST surface through
//! [`vtc_client::VtcClient`]: the vetter grants (`/v1/vetting/vetters`), the
//! automatic-grant configuration (`/v1/vetting/auto-grant`), the community's
//! branding (`/v1/community/branding`) and the statement withdrawal notices
//! (`/v1/vetting/revocations`). A grant is withdrawn like any endorsement,
//! with `DELETE /v1/credentials/endorsements/{endorsementId}`.
//!
//! `bootstrap-pgp` seeds the first vetters from an existing OpenPGP web of
//! trust; its graph and link logic is the pure [`wot`] and [`plan`] pair.
//!
//! The routes are REST-only and need a community-admin token, so every command
//! mints a bearer token for the session's REST base (the same way `cnm backup`
//! does) and fails with the fix when there is none. There are no retries here:
//! a failed call is reported, not repeated.

mod bootstrap;
pub mod plan;
#[cfg(test)]
mod test_web;
pub mod wot;

use chrono::{DateTime, Utc};
use clap::{Subcommand, ValueEnum};
use ratatui::layout::Constraint;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Cell, Row, Table};
use serde_json::{Value, json};
use vta_cli_common::display::did_cell;
use vta_cli_common::duration::{humanize_duration, parse_duration_secs};
use vta_cli_common::render::{
    BOLD, DIM, GREEN, RESET, YELLOW, bin_name, is_full_display, is_json_output, print_full_entry,
    print_full_list_title, print_json, print_widget,
};
use vta_sdk::client::VtaClient;
use vtc_client::join_requests::CommunityBranding;
use vtc_client::vetting::{
    AutoGrantConfig, AutoGrantStatus, GrantOrigin, MAX_AUTO_GRANT_SWEEP_MINUTES,
    MAX_VETTER_GRANT_VALIDITY_SECONDS, MIN_AUTO_GRANT_SWEEP_MINUTES,
    MIN_VETTER_GRANT_VALIDITY_SECONDS, VetterGrantRow,
};
use vtc_client::{VtcClient, VtcError};

pub use bootstrap::BootstrapPgpArgs;

use crate::auth;

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// `cnm vetting …`
#[derive(Subcommand)]
pub enum VettingCommands {
    /// Vetter grants: list them, name a member a vetter, withdraw a grant, or
    /// deliver a grant credential again.
    Vetters {
        #[command(subcommand)]
        command: VetterCommands,
    },

    /// Automatic vetter grants: the sweep that names vetters by the
    /// `vetterEligibility` policy.
    #[command(name = "auto-grant")]
    AutoGrant {
        #[command(subcommand)]
        command: AutoGrantCommands,
    },

    /// How the community presents itself to an applicant's client
    /// (`join-requests/manifest/0.2` branding).
    Branding {
        #[command(subcommand)]
        command: BrandingCommands,
    },

    /// Vetting statement withdrawal notices, and the admissions each touches.
    Revocations,

    /// Seed vetters from an OpenPGP web of trust.
    ///
    /// Members link their OpenPGP key to their member DID with a clearsigned
    /// statement (`openvtc-link: <memberDid>`). Every active member whose
    /// linked key is within --max-depth certification hops of a root key, and
    /// who holds no live grant, is named a vetter. Run with --dry-run first.
    #[command(name = "bootstrap-pgp")]
    BootstrapPgp(BootstrapPgpArgs),
}

/// `cnm vetting vetters …`
#[derive(Subcommand)]
pub enum VetterCommands {
    /// Every vetter grant, newest first.
    List,
    /// Name a current member a vetter.
    Grant {
        /// The member's DID.
        member_did: String,
        /// How long the grant is valid: `N[s|m|h|d|w]`, one day to two years
        /// (e.g. `180d`). The community's default of one year when absent.
        #[arg(long)]
        validity: Option<String>,
    },
    /// Withdraw a vetter grant. The vetter's statements stop counting and
    /// their profile is deleted.
    Revoke {
        /// The grant's endorsement id, from `cnm vetting vetters list`.
        endorsement_id: String,
    },
    /// Deliver a vetter's live grant credential again, when their wallet lost
    /// it. Nothing new is issued.
    Resend {
        /// The vetter's member DID.
        member_did: String,
    },
}

/// `cnm vetting auto-grant …`
#[derive(Subcommand)]
pub enum AutoGrantCommands {
    /// The configuration and the last sweep.
    Show,
    /// Change the configuration. Values not given keep their current setting.
    Set {
        /// Turn the sweep on (`true`) or off (`false`).
        #[arg(long)]
        enabled: Option<bool>,
        /// Minutes between sweeps, 5–1440.
        #[arg(long)]
        sweep_minutes: Option<u32>,
        /// Validity of a grant the sweep issues: `N[s|m|h|d|w]`, one day to
        /// two years.
        #[arg(long)]
        validity: Option<String>,
    },
}

/// `cnm vetting branding …`
#[derive(Subcommand)]
pub enum BrandingCommands {
    /// The community's branding.
    Show,
    /// Change the branding. Values not given keep their current setting.
    Set {
        /// The name an applicant's client shows, 1–128 characters.
        #[arg(long)]
        display_name: Option<String>,
        /// Accent colour, `#rrggbb`.
        #[arg(long)]
        accent_color: Option<String>,
        /// Logo, an `https` URL of at most 2048 characters.
        #[arg(long)]
        logo_url: Option<String>,
        /// Remove a value: `display-name`, `accent-color` or `logo-url`
        /// (comma-separated or repeated).
        #[arg(long, value_enum, value_delimiter = ',')]
        clear: Vec<BrandingField>,
    },
}

/// A branding member `--clear` can remove.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum BrandingField {
    DisplayName,
    AccentColor,
    LogoUrl,
}

/// Run a `cnm vetting` command.
pub async fn run(command: VettingCommands, client: &VtaClient, keyring_key: &str) -> CliResult {
    if let VettingCommands::BootstrapPgp(args) = command {
        // The keyring, roots and links are read and checked before any call to
        // the community, so a mistake in them costs no round trip.
        return bootstrap::run(args, client, keyring_key).await;
    }
    let vtc = connect(client, keyring_key).await?;
    match command {
        VettingCommands::Vetters { command } => match command {
            VetterCommands::List => cmd_vetters_list(&vtc).await,
            VetterCommands::Grant {
                member_did,
                validity,
            } => cmd_vetters_grant(&vtc, &member_did, validity.as_deref()).await,
            VetterCommands::Revoke { endorsement_id } => {
                cmd_vetters_revoke(&vtc, &endorsement_id).await
            }
            VetterCommands::Resend { member_did } => cmd_vetters_resend(&vtc, &member_did).await,
        },
        VettingCommands::AutoGrant { command } => match command {
            AutoGrantCommands::Show => cmd_auto_grant_show(&vtc).await,
            AutoGrantCommands::Set {
                enabled,
                sweep_minutes,
                validity,
            } => cmd_auto_grant_set(&vtc, enabled, sweep_minutes, validity.as_deref()).await,
        },
        VettingCommands::Branding { command } => match command {
            BrandingCommands::Show => cmd_branding_show(&vtc).await,
            BrandingCommands::Set {
                display_name,
                accent_color,
                logo_url,
                clear,
            } => {
                let change = BrandingChange {
                    display_name,
                    accent_color,
                    logo_url,
                    clear,
                };
                cmd_branding_set(&vtc, change).await
            }
        },
        VettingCommands::Revocations => cmd_revocations(&vtc).await,
        VettingCommands::BootstrapPgp(_) => unreachable!("handled above"),
    }
}

/// A community-admin [`VtcClient`] for the session's REST base.
async fn connect(client: &VtaClient, keyring_key: &str) -> CliResult<VtcClient> {
    let base = client.rest_url().ok_or_else(|| {
        format!(
            "`{bin} vetting` uses the community's admin REST API, and this session has no REST \
             URL for it.\nPass the VTC's API base before the subcommand: \
             `{bin} --url https://<vtc-host>/v1 vetting …`",
            bin = bin_name()
        )
    })?;
    let token = auth::ensure_authenticated(base, keyring_key).await?;
    let vtc_did = auth::loaded_session(keyring_key)
        .and_then(|s| s.vta_did)
        .unwrap_or_default();
    Ok(VtcClient::with_token(base, &vtc_did, token))
}

// ---------------------------------------------------------------------------
// vetters
// ---------------------------------------------------------------------------

async fn cmd_vetters_list(vtc: &VtcClient) -> CliResult {
    let list = vtc
        .list_vetter_grants()
        .await
        .map_err(|e| guidance(e, Op::VettersList))?;
    if is_json_output() {
        print_json(&list.vetters)?;
        return Ok(());
    }
    if list.vetters.is_empty() {
        println!("No vetter grants.");
        println!(
            "  {DIM}Name a member a vetter with `{} vetting vetters grant <memberDid>`.{RESET}",
            bin_name()
        );
        return Ok(());
    }
    let now = Utc::now();
    if is_full_display() {
        print_full_list_title("Vetter grants", list.vetters.len());
        for row in &list.vetters {
            print_full_entry(&[
                ("Member", &row.member_did),
                ("Status", grant_status(row, now)),
                ("Origin", origin_label(row.origin)),
                ("Valid from", &date(row.valid_from)),
                ("Valid until", &row.valid_until.map_or("—".into(), date)),
                ("Endorsement", &row.endorsement_id),
                ("Credential", &row.credential_id),
                ("Profile", &profile_label(row)),
            ]);
        }
        return Ok(());
    }

    let header = Row::new(vec![
        "Member",
        "Status",
        "Origin",
        "Valid Until",
        "Endorsement ID",
        "Profile",
    ])
    .style(header_style())
    .bottom_margin(1);
    let rows: Vec<Row> = list
        .vetters
        .iter()
        .map(|row| {
            let status = grant_status(row, now);
            let status_style = match status {
                "live" => Style::default().fg(Color::Green),
                "revoked" => Style::default().fg(Color::Red),
                _ => Style::default().fg(Color::Yellow),
            };
            Row::new(vec![
                did_cell(&row.member_did),
                Cell::from(status).style(status_style),
                Cell::from(origin_label(row.origin)),
                Cell::from(row.valid_until.map_or("—".into(), date)),
                Cell::from(row.endorsement_id.clone()),
                Cell::from(profile_label(row)),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Min(30),
            Constraint::Length(12),
            Constraint::Length(7),
            Constraint::Length(11),
            Constraint::Length(36),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .column_spacing(2)
    .block(bordered(format!(
        " Vetter grants ({}) ",
        list.vetters.len()
    )));
    print_widget(table, height(list.vetters.len()));
    println!(
        "  {DIM}Withdraw a grant with `{bin} vetting vetters revoke <endorsementId>`; \
         `{bin} --full-display vetting vetters list` shows every DID in full.{RESET}",
        bin = bin_name()
    );
    Ok(())
}

async fn cmd_vetters_grant(vtc: &VtcClient, member_did: &str, validity: Option<&str>) -> CliResult {
    let validity_seconds = validity
        .map(|v| parse_grant_validity("--validity", v))
        .transpose()?;
    let result = vtc
        .grant_vetter(member_did, validity_seconds)
        .await
        .map_err(|e| guidance(e, Op::Grant { member_did }))?;
    let grant = &result.grant;
    if is_json_output() {
        let mut value = serde_json::to_value(grant)?;
        value["created"] = json!(result.created);
        print_json(&value)?;
        return Ok(());
    }
    if result.created {
        println!("{GREEN}✓{RESET} Named {member_did} a vetter.");
    } else {
        println!(
            "{YELLOW}!{RESET} {member_did} already holds a live vetter grant — nothing new was \
             issued."
        );
        if validity_seconds.is_some() {
            println!(
                "  {DIM}--validity applies to a new grant only. To change it, revoke this grant \
                 and grant again.{RESET}"
            );
        }
    }
    println!("  Endorsement:  {}", grant.endorsement_id);
    println!("  Credential:   {}", grant.credential_id);
    println!(
        "  Valid:        {} → {}",
        date(grant.valid_from),
        date(grant.valid_until)
    );
    println!(
        "  {DIM}Withdraw it with `{} vetting vetters revoke {}`.{RESET}",
        bin_name(),
        grant.endorsement_id
    );
    Ok(())
}

async fn cmd_vetters_revoke(vtc: &VtcClient, endorsement_id: &str) -> CliResult {
    let revoked = vtc
        .revoke_endorsement(endorsement_id)
        .await
        .map_err(|e| guidance(e, Op::Revoke { endorsement_id }))?;
    if is_json_output() {
        print_json(&revoked)?;
        return Ok(());
    }
    println!(
        "{GREEN}✓{RESET} Revoked endorsement {} (credential {}) at {}.",
        revoked.endorsement_id, revoked.revocation.credential_id, revoked.revocation.revoked_at
    );
    println!(
        "  {DIM}A vetter whose grant is revoked no longer counts toward any join, and their \
         profile is removed from listings.{RESET}"
    );
    Ok(())
}

async fn cmd_vetters_resend(vtc: &VtcClient, member_did: &str) -> CliResult {
    let sent = vtc
        .resend_vetter_grant(member_did)
        .await
        .map_err(|e| guidance(e, Op::Resend { member_did }))?;
    if is_json_output() {
        print_json(&sent)?;
        return Ok(());
    }
    // R1.1: a send the transport accepted is not a delivery, so do not say
    // "delivered".
    println!(
        "{GREEN}✓{RESET} Handed credential {} to the community's messaging transport for \
         {member_did}.",
        sent.credential_id
    );
    println!("  Valid until:  {}", date(sent.valid_until));
    println!(
        "  {DIM}Delivery is not confirmed by the member's wallet; ask the vetter to check it.{RESET}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// auto-grant
// ---------------------------------------------------------------------------

async fn cmd_auto_grant_show(vtc: &VtcClient) -> CliResult {
    let status = vtc
        .auto_grant()
        .await
        .map_err(|e| guidance(e, Op::AutoGrantShow))?;
    print_auto_grant(&status)
}

async fn cmd_auto_grant_set(
    vtc: &VtcClient,
    enabled: Option<bool>,
    sweep_minutes: Option<u32>,
    validity: Option<&str>,
) -> CliResult {
    if enabled.is_none() && sweep_minutes.is_none() && validity.is_none() {
        return Err(format!(
            "nothing to change. Pass at least one of --enabled <true|false>, --sweep-minutes \
             <{MIN_AUTO_GRANT_SWEEP_MINUTES}–{MAX_AUTO_GRANT_SWEEP_MINUTES}> or --validity \
             <duration>.\nSee the current configuration with `{} vetting auto-grant show`.",
            bin_name()
        )
        .into());
    }
    let validity_seconds = validity
        .map(|v| parse_grant_validity("--validity", v))
        .transpose()?;
    if let Some(m) = sweep_minutes
        && !(MIN_AUTO_GRANT_SWEEP_MINUTES..=MAX_AUTO_GRANT_SWEEP_MINUTES).contains(&m)
    {
        return Err(format!(
            "--sweep-minutes {m} is out of range: the sweep runs every \
             {MIN_AUTO_GRANT_SWEEP_MINUTES} to {MAX_AUTO_GRANT_SWEEP_MINUTES} minutes (a day). \
             Try `--sweep-minutes 60`."
        )
        .into());
    }
    // PUT replaces the whole configuration and an absent member takes its
    // default, so start from what is stored: `--sweep-minutes 30` alone must
    // not quietly switch the sweep off.
    let current = vtc
        .auto_grant()
        .await
        .map_err(|e| guidance(e, Op::AutoGrantShow))?;
    let config = merged_auto_grant(&current, enabled, sweep_minutes, validity_seconds);
    config
        .check_shape()
        .map_err(|e| format!("the automatic-grant configuration is out of bounds: {e}"))?;
    let stored = vtc
        .configure_auto_grant(&config)
        .await
        .map_err(|e| guidance(e, Op::AutoGrantSet))?;
    if !is_json_output() {
        println!("{GREEN}✓{RESET} Automatic vetter grants updated.");
    }
    print_auto_grant(&stored)
}

fn merged_auto_grant(
    current: &AutoGrantStatus,
    enabled: Option<bool>,
    sweep_minutes: Option<u32>,
    validity_seconds: Option<u64>,
) -> AutoGrantConfig {
    AutoGrantConfig {
        enabled: enabled.unwrap_or(current.enabled),
        sweep_minutes: Some(sweep_minutes.unwrap_or(current.sweep_minutes)),
        validity_seconds: Some(validity_seconds.unwrap_or(current.validity_seconds)),
    }
}

fn print_auto_grant(status: &AutoGrantStatus) -> CliResult {
    if is_json_output() {
        print_json(status)?;
        return Ok(());
    }
    let enabled = if status.enabled {
        format!("{GREEN}on{RESET}")
    } else {
        format!("{YELLOW}off{RESET}")
    };
    println!("  Enabled:        {enabled}");
    println!("  Sweep every:    {} minutes", status.sweep_minutes);
    println!(
        "  Grant validity: {}",
        humanize_duration(status.validity_seconds)
    );
    match &status.last_sweep {
        Some(sweep) => println!(
            "  Last sweep:     {} — {} granted, {} revoked, {} errors",
            sweep.ran_at.to_rfc3339(),
            sweep.granted,
            sweep.revoked,
            sweep.errors
        ),
        None => println!("  Last sweep:     {DIM}none yet{RESET}"),
    }
    if !status.enabled {
        println!(
            "  {DIM}Turn it on with `{} vetting auto-grant set --enabled true`. Which members it \
             names is the `vetterEligibility` policy's decision.{RESET}",
            bin_name()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// branding
// ---------------------------------------------------------------------------

async fn cmd_branding_show(vtc: &VtcClient) -> CliResult {
    let branding = vtc
        .branding()
        .await
        .map_err(|e| guidance(e, Op::BrandingShow))?;
    print_branding(&branding)
}

/// The `branding set` flags.
#[derive(Debug, Default)]
struct BrandingChange {
    display_name: Option<String>,
    accent_color: Option<String>,
    logo_url: Option<String>,
    clear: Vec<BrandingField>,
}

async fn cmd_branding_set(vtc: &VtcClient, change: BrandingChange) -> CliResult {
    if change.display_name.is_none()
        && change.accent_color.is_none()
        && change.logo_url.is_none()
        && change.clear.is_empty()
    {
        return Err(format!(
            "nothing to change. Pass --display-name, --accent-color, --logo-url or --clear \
             <field>.\nSee the current branding with `{} vetting branding show`.",
            bin_name()
        )
        .into());
    }
    let current = vtc
        .branding()
        .await
        .map_err(|e| guidance(e, Op::BrandingShow))?;
    let branding = merged_branding(current, change)?;
    branding.check_shape().map_err(|e| {
        format!(
            "the branding is out of bounds: {e}.\nA display name is 1–128 characters, an accent \
             colour `#rrggbb`, and a logo an https URL of at most 2048 characters."
        )
    })?;
    let stored = vtc
        .set_branding(&branding)
        .await
        .map_err(|e| guidance(e, Op::BrandingSet))?;
    if !is_json_output() {
        println!("{GREEN}✓{RESET} Branding updated.");
    }
    print_branding(&stored)
}

/// Apply `change` over `current`. PUT replaces the whole branding, so a value
/// the operator did not mention is carried over rather than cleared.
fn merged_branding(
    mut current: CommunityBranding,
    change: BrandingChange,
) -> CliResult<CommunityBranding> {
    for field in &change.clear {
        let set = match field {
            BrandingField::DisplayName => change.display_name.is_some(),
            BrandingField::AccentColor => change.accent_color.is_some(),
            BrandingField::LogoUrl => change.logo_url.is_some(),
        };
        if set {
            return Err(format!(
                "--clear {} and a new value for it were both given; pass one or the other",
                field
                    .to_possible_value()
                    .map(|v| v.get_name().to_string())
                    .unwrap_or_default()
            )
            .into());
        }
        match field {
            BrandingField::DisplayName => current.display_name = None,
            BrandingField::AccentColor => current.accent_color = None,
            BrandingField::LogoUrl => current.logo_url = None,
        }
    }
    if change.display_name.is_some() {
        current.display_name = change.display_name;
    }
    if change.accent_color.is_some() {
        current.accent_color = change.accent_color;
    }
    if change.logo_url.is_some() {
        current.logo_url = change.logo_url;
    }
    Ok(current)
}

fn print_branding(branding: &CommunityBranding) -> CliResult {
    if is_json_output() {
        print_json(branding)?;
        return Ok(());
    }
    let unset = format!("{DIM}(not set){RESET}");
    let show = |v: &Option<String>| v.clone().unwrap_or_else(|| unset.clone());
    println!("  Display name:  {}", show(&branding.display_name));
    println!("  Accent colour: {}", show(&branding.accent_color));
    println!("  Logo URL:      {}", show(&branding.logo_url));
    if branding.display_name.is_none()
        && branding.accent_color.is_none()
        && branding.logo_url.is_none()
    {
        println!(
            "  {DIM}No branding is published on the join manifest. Set it with `{} vetting \
             branding set --display-name …`.{RESET}",
            bin_name()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// revocations
// ---------------------------------------------------------------------------

async fn cmd_revocations(vtc: &VtcClient) -> CliResult {
    let notices = vtc
        .vetting_revocations()
        .await
        .map_err(|e| guidance(e, Op::Revocations))?;
    if is_json_output() {
        print_json(&notices)?;
        return Ok(());
    }
    if notices.is_empty() {
        println!("No vetting statement has been withdrawn.");
        return Ok(());
    }
    if is_full_display() {
        print_full_list_title("Statement withdrawals", notices.len());
        for n in &notices {
            print_full_entry(&[
                ("Recorded", &n.recorded_at.to_rfc3339()),
                ("Vetter", &n.issuer),
                ("Statement", &n.statement_id),
                ("Digest", &n.statement_digest_multibase),
                ("Reason", n.reason.as_deref().unwrap_or("—")),
                ("Review", &n.review_state),
                ("Members", &join_or_dash(&n.affected_members)),
                ("Join requests", &join_or_dash(&n.affected_join_requests)),
            ]);
        }
        return Ok(());
    }
    let header = Row::new(vec![
        "Recorded",
        "Vetter",
        "Statement",
        "Reason",
        "Review",
        "Affected Members",
    ])
    .style(header_style())
    .bottom_margin(1);
    let rows: Vec<Row> = notices
        .iter()
        .map(|n| {
            let review = if n.review_state == "needsReview" {
                Cell::from("needs review").style(Style::default().fg(Color::Yellow))
            } else {
                Cell::from("no admission")
            };
            Row::new(vec![
                Cell::from(date(n.recorded_at)),
                did_cell(&n.issuer),
                Cell::from(n.statement_id.clone()),
                Cell::from(n.reason.clone().unwrap_or_else(|| "—".into())),
                review,
                Cell::from(n.affected_members.len().to_string()),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(11),
            Constraint::Min(30),
            Constraint::Min(30),
            Constraint::Length(15),
            Constraint::Length(13),
            Constraint::Length(16),
        ],
    )
    .header(header)
    .column_spacing(2)
    .block(bordered(format!(
        " Statement withdrawals ({}) ",
        notices.len()
    )));
    print_widget(table, height(notices.len()));
    let pending = notices
        .iter()
        .filter(|n| n.review_state == "needsReview")
        .count();
    if pending > 0 {
        println!(
            "  {BOLD}{pending}{RESET} {DIM}withdrawal(s) touch a current membership. \
             `{} --full-display vetting revocations` names the members and join requests; the \
             vetting facts a request was decided on are at `GET /v1/join-requests/<id>/vetting`.{RESET}",
            bin_name()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Errors that say what to do
// ---------------------------------------------------------------------------

/// Which call failed, so a status can be read as the operator's situation.
#[derive(Debug, Clone, Copy)]
enum Op<'a> {
    VettersList,
    Grant { member_did: &'a str },
    Revoke { endorsement_id: &'a str },
    Resend { member_did: &'a str },
    AutoGrantShow,
    AutoGrantSet,
    BrandingShow,
    BrandingSet,
    Revocations,
    Members,
}

impl Op<'_> {
    /// The route, for a 404 that means the VTC does not serve it at all.
    fn route(&self) -> &'static str {
        match self {
            Self::VettersList | Self::Grant { .. } => "/v1/vetting/vetters",
            Self::Revoke { .. } => "/v1/credentials/endorsements/{id}",
            Self::Resend { .. } => "/v1/vetting/vetters/{memberDid}/resend",
            Self::AutoGrantShow | Self::AutoGrantSet => "/v1/vetting/auto-grant",
            Self::BrandingShow | Self::BrandingSet => "/v1/community/branding",
            Self::Revocations => "/v1/vetting/revocations",
            Self::Members => "/v1/members",
        }
    }
}

/// Turn a client error into an operator error that names the fix.
fn guidance(err: VtcError, op: Op<'_>) -> Box<dyn std::error::Error> {
    let bin = bin_name();
    let message = match err {
        VtcError::Http { status: 401, .. } => format!(
            "the VTC refused this session's token (401).\nRe-authenticate with `{bin} auth login \
             --credential-bundle <bundle>`, or run `{bin} setup` again."
        ),
        VtcError::Http { status: 403, .. } => format!(
            "this identity is not a community admin (403); vetting administration is admin-only.\n\
             Check the session's DID with `{bin} auth status`, and ask an existing admin to grant \
             it the admin role."
        ),
        VtcError::Http { status, body } => {
            let detail = human_message(&body);
            match (op, status) {
                (Op::Grant { member_did }, 400) => format!(
                    "the community refused to name {member_did} a vetter: {detail}\n\
                     Only a current member can be a vetter. Check the DID is the member's DID \
                     (not their PGP key or email), and if they have applied, approve their join \
                     request first; then re-run `{bin} vetting vetters grant {member_did}`."
                ),
                (Op::Revoke { endorsement_id }, 404) => format!(
                    "there is no endorsement {endorsement_id}.\nList the vetter grants with \
                     `{bin} vetting vetters list` and pass the Endorsement ID column (not the \
                     member DID or credential id)."
                ),
                (Op::Revoke { endorsement_id }, 400) => format!(
                    "`{endorsement_id}` is not an endorsement id: {detail}\nEndorsement ids are \
                     UUIDs; copy one from `{bin} vetting vetters list`."
                ),
                (Op::Resend { member_did }, 404) => format!(
                    "{member_did} holds no live vetter grant whose credential the community \
                     kept, so there is nothing to resend.\nGrant one with `{bin} vetting vetters \
                     grant {member_did}`. A grant recorded before credentials were kept cannot \
                     be resent: revoke it (`{bin} vetting vetters revoke <endorsementId>`) and \
                     grant again."
                ),
                (Op::Resend { member_did }, 503) => format!(
                    "the community could not hand the credential to its messaging transport \
                     ({detail}).\nThe grant still stands. Check the VTC's mediator is configured \
                     and reachable (`{bin} health`), then re-run `{bin} vetting vetters resend \
                     {member_did}`."
                ),
                (Op::AutoGrantSet, 400) => format!(
                    "the community refused the automatic-grant configuration: {detail}\n\
                     --sweep-minutes is {MIN_AUTO_GRANT_SWEEP_MINUTES}–{MAX_AUTO_GRANT_SWEEP_MINUTES} \
                     and --validity one day to two years."
                ),
                (Op::AutoGrantSet, 503) => format!(
                    "the community refused to change automatic grants because its audit log is \
                     not configured ({detail}). Configure the VTC's audit writer and retry."
                ),
                (Op::BrandingSet, 400) => format!(
                    "the community refused the branding: {detail}\nA display name is 1–128 \
                     characters, an accent colour `#rrggbb`, and a logo an https URL of at most \
                     2048 characters."
                ),
                (_, 404) => format!(
                    "the VTC does not serve {} (404) — it predates the vetter registry.\nUpgrade \
                     the VTC to a release with peer identity vetting.",
                    op.route()
                ),
                (_, _) => format!("the VTC answered HTTP {status}: {detail}"),
            }
        }
        VtcError::Transport(e) => format!(
            "could not reach the VTC: {e}.\nCheck the community is up and its URL resolves with \
             `{bin} health`."
        ),
        VtcError::NotAuthenticated => {
            format!(
                "no session token for the VTC. Run `{bin} auth login --credential-bundle <bundle>`."
            )
        }
        other => other.to_string(),
    };
    message.into()
}

/// The `message` or `error` of a JSON error body, else the body itself.
fn human_message(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| {
            ["message", "error", "detail"]
                .iter()
                .find_map(|k| v.get(*k).and_then(Value::as_str).map(str::to_string))
        })
        .unwrap_or_else(|| {
            if body.is_empty() {
                "no detail".into()
            } else {
                body.to_string()
            }
        })
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Parse a grant validity flag and check it against the grant bounds.
fn parse_grant_validity(flag: &str, value: &str) -> CliResult<u64> {
    let secs = parse_duration_secs(value)
        .map_err(|e| format!("{flag} {value}: {e}. Use N[s|m|h|d|w], e.g. `{flag} 365d`"))?;
    if !(MIN_VETTER_GRANT_VALIDITY_SECONDS..=MAX_VETTER_GRANT_VALIDITY_SECONDS).contains(&secs) {
        return Err(format!(
            "{flag} {value} is {}; a vetter grant is valid for one day to two years. Try `{flag} \
             365d`.",
            humanize_duration(secs)
        )
        .into());
    }
    Ok(secs)
}

fn grant_status(row: &VetterGrantRow, now: DateTime<Utc>) -> &'static str {
    if row.revoked {
        "revoked"
    } else if row.live {
        "live"
    } else if row.valid_until.is_some_and(|u| u <= now) {
        "expired"
    } else {
        "not member"
    }
}

fn origin_label(origin: GrantOrigin) -> &'static str {
    match origin {
        GrantOrigin::Auto => "auto",
        GrantOrigin::Manual => "manual",
    }
}

fn profile_label(row: &VetterGrantRow) -> String {
    let Some(p) = &row.profile else {
        return "—".into();
    };
    let mut parts = vec![if p.listed { "listed" } else { "unlisted" }.to_string()];
    if let Some(name) = &p.display_name {
        parts.push(name.clone());
    }
    if let Some(country) = &p.country {
        parts.push(country.clone());
    }
    if p.event_count > 0 {
        parts.push(format!("{} events", p.event_count));
    }
    parts.join(" · ")
}

fn date(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%d").to_string()
}

fn join_or_dash(items: &[String]) -> String {
    if items.is_empty() {
        "—".into()
    } else {
        items.join(", ")
    }
}

fn header_style() -> Style {
    Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD)
}

fn bordered(title: String) -> Block<'static> {
    Block::bordered()
        .title(title)
        .border_style(Style::default().fg(Color::DarkGray))
}

fn height(rows: usize) -> u16 {
    u16::try_from(rows).unwrap_or(u16::MAX - 4) + 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_validity_is_bounded_with_a_suggestion() {
        assert_eq!(
            parse_grant_validity("--validity", "365d").unwrap(),
            31_536_000
        );
        let err = parse_grant_validity("--validity", "3h")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("one day to two years") && err.contains("365d"),
            "{err}"
        );
        let err = parse_grant_validity("--validity", "3y")
            .unwrap_err()
            .to_string();
        assert!(err.contains("N[s|m|h|d|w]"), "{err}");
    }

    #[test]
    fn auto_grant_set_keeps_what_it_was_not_told_to_change() {
        let current = AutoGrantStatus {
            enabled: true,
            sweep_minutes: 60,
            validity_seconds: 31_536_000,
            last_sweep: None,
        };
        let config = merged_auto_grant(&current, None, Some(30), None);
        assert!(
            config.enabled,
            "--sweep-minutes alone must not turn the sweep off"
        );
        assert_eq!(config.sweep_minutes, Some(30));
        assert_eq!(config.validity_seconds, Some(31_536_000));
        let off = merged_auto_grant(&current, Some(false), None, None);
        assert!(!off.enabled);
        assert_eq!(off.sweep_minutes, Some(60));
    }

    #[test]
    fn branding_set_merges_clears_and_refuses_a_contradiction() {
        let current = CommunityBranding {
            display_name: Some("Linux Kernel".into()),
            accent_color: Some("#1a2b3c".into()),
            logo_url: Some("https://kernel.example/logo.svg".into()),
            ext: None,
        };
        let merged = merged_branding(
            current.clone(),
            BrandingChange {
                accent_color: Some("#000000".into()),
                clear: vec![BrandingField::LogoUrl],
                ..BrandingChange::default()
            },
        )
        .unwrap();
        assert_eq!(merged.display_name.as_deref(), Some("Linux Kernel"));
        assert_eq!(merged.accent_color.as_deref(), Some("#000000"));
        assert!(merged.logo_url.is_none());

        let err = merged_branding(
            current,
            BrandingChange {
                logo_url: Some("https://x.example/l.svg".into()),
                clear: vec![BrandingField::LogoUrl],
                ..BrandingChange::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("--clear logo-url"), "{err}");
    }

    #[test]
    fn errors_name_the_command_that_fixes_them() {
        let revoke = guidance(
            VtcError::Http {
                status: 404,
                body: r#"{"error":"not found"}"#.into(),
            },
            Op::Revoke {
                endorsement_id: "did:key:zWrong",
            },
        )
        .to_string();
        assert!(revoke.contains("vetting vetters list"), "{revoke}");

        let resend = guidance(
            VtcError::Http {
                status: 404,
                body: String::new(),
            },
            Op::Resend {
                member_did: "did:key:zCarol",
            },
        )
        .to_string();
        assert!(
            resend.contains("vetting vetters grant did:key:zCarol"),
            "{resend}"
        );

        let grant = guidance(
            VtcError::Http {
                status: 400,
                body: r#"{"message":"did:key:zX is not a current member"}"#.into(),
            },
            Op::Grant {
                member_did: "did:key:zX",
            },
        )
        .to_string();
        assert!(
            grant.contains("is not a current member") && grant.contains("approve their join"),
            "{grant}"
        );

        let old_vtc = guidance(
            VtcError::Http {
                status: 404,
                body: String::new(),
            },
            Op::AutoGrantShow,
        )
        .to_string();
        assert!(old_vtc.contains("/v1/vetting/auto-grant") && old_vtc.contains("Upgrade"));
    }
}
