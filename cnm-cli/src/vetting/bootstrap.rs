//! `cnm vetting bootstrap-pgp` — seed a community's first vetters from an
//! OpenPGP web of trust.
//!
//! The order is deliberate: everything local (the keyring, the roots, the link
//! statements) is read and verified before the community is contacted, then
//! the community's roster is read once, then — only without `--dry-run` — the
//! grants are made one at a time. A grant that fails is reported and the rest
//! carry on; nothing is retried here (the community's grant converges, so
//! running the command again is the retry).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use clap::Args;
use ratatui::layout::Constraint;
use ratatui::style::{Color, Style};
use ratatui::widgets::{Cell, Row, Table};
use serde::Serialize;
use serde_json::json;
use vta_cli_common::display::did_cell;
use vta_cli_common::render::{
    BOLD, DIM, GREEN, RED, RESET, YELLOW, bin_name, is_full_display, is_json_output,
    print_full_entry, print_full_list_title, print_json, print_widget,
};
use vta_sdk::client::VtaClient;

use super::plan::{Action, PlanRow, Roster, plan};
use super::wot::{CertStats, Keyring, LinkCheck, check_link, mark_ambiguous, shortest_paths};
use super::{CliResult, Op, bordered, guidance, header_style, height, parse_grant_validity};

/// Largest link statement read. A clearsigned one-line statement is a few
/// kilobytes; anything far larger is not one.
const MAX_LINK_BYTES: u64 = 64 * 1024;

/// `cnm vetting bootstrap-pgp` arguments.
#[derive(Args, Debug)]
pub struct BootstrapPgpArgs {
    /// The OpenPGP keyring: the root keys, the keys that certify, and the
    /// linked keys. Binary (`gpg --export > keyring.gpg`) or ASCII-armored,
    /// one or many key blocks.
    #[arg(long)]
    pub keyring: PathBuf,

    /// Root key fingerprints, comma-separated: the 40 hex digits
    /// `gpg --fingerprint` prints (spaces allowed inside quotes).
    #[arg(long, value_delimiter = ',', required = true)]
    pub roots: Vec<String>,

    /// Most certification hops from a root a linked key may be: 0 means only
    /// the root keys themselves, 1 their direct certifications, and so on.
    #[arg(long)]
    pub max_depth: u32,

    /// Directory of link statements, one `gpg --clearsign` output per member,
    /// each carrying the line `openvtc-link: <memberDid>`.
    #[arg(long)]
    pub links: PathBuf,

    /// Print what would be granted, and grant nothing.
    #[arg(long)]
    pub dry_run: bool,

    /// Validity of each grant: `N[s|m|h|d|w]`, one day to two years. The
    /// community's default of one year when absent.
    #[arg(long)]
    pub validity: Option<String>,
}

/// What the web of trust looked like, for the summary.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Summary {
    keys: usize,
    unusable_keys: usize,
    skipped: Vec<String>,
    roots: Vec<String>,
    reachable_keys: usize,
    within_max_depth: usize,
    max_depth: u32,
    #[serde(serialize_with = "serialize_stats")]
    certifications: CertStats,
    links: usize,
}

fn serialize_stats<S: serde::Serializer>(stats: &CertStats, s: S) -> Result<S::Ok, S::Error> {
    json!({
        "counted": stats.counted,
        "expired": stats.expired,
        "revoked": stats.revoked,
        "invalid": stats.invalid,
        "unknownIssuer": stats.unknown_issuer,
        "unusableIssuer": stats.unusable_issuer,
    })
    .serialize(s)
}

/// The outcome of one grant the command made.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "result", rename_all = "camelCase")]
enum GrantOutcome {
    #[serde(rename_all = "camelCase")]
    Granted {
        endorsement_id: String,
    },
    #[serde(rename_all = "camelCase")]
    AlreadyGranted {
        endorsement_id: String,
    },
    Failed {
        error: String,
    },
}

pub(super) async fn run(
    args: BootstrapPgpArgs,
    client: &VtaClient,
    keyring_key: &str,
) -> CliResult {
    let validity = args
        .validity
        .as_deref()
        .map(|v| parse_grant_validity("--validity", v))
        .transpose()?;
    let now = unix_now();

    let bytes = std::fs::read(&args.keyring).map_err(|e| {
        format!(
            "could not read --keyring {}: {e}.\nExport one with `gpg --export > keyring.gpg`.",
            args.keyring.display()
        )
    })?;
    let keyring = Keyring::parse(&bytes, now)?;
    let roots = keyring.resolve_roots(&args.roots)?;
    let (edges, stats) = keyring.certifications(now);
    let reach = shortest_paths(&edges, &roots);

    let statements = read_links(&args.links)?;
    let mut checks: Vec<LinkCheck> = statements
        .iter()
        .map(|(name, text)| match text {
            Ok(text) => check_link(&keyring, name, text, now),
            Err(problem) => LinkCheck {
                source: name.clone(),
                member_did: None,
                fingerprint: None,
                problem: Some(super::wot::LinkProblem::NotCleartextSigned(problem.clone())),
            },
        })
        .collect();
    mark_ambiguous(&mut checks);

    let vtc = super::connect(client, keyring_key).await?;
    let members: BTreeSet<String> = vtc
        .list_members(None)
        .await
        .map_err(|e| guidance(e, Op::Members))?
        .into_iter()
        .map(|m| m.did)
        .collect();
    let live_grants: BTreeMap<String, String> = vtc
        .list_vetter_grants()
        .await
        .map_err(|e| guidance(e, Op::VettersList))?
        .vetters
        .into_iter()
        .filter(|g| g.live)
        .map(|g| (g.member_did, g.endorsement_id))
        .collect();

    let rows = plan(
        &checks,
        &keyring,
        &reach,
        Roster {
            members: &members,
            live_grants: &live_grants,
        },
        args.max_depth,
    );
    let summary = Summary {
        keys: keyring.keys().len(),
        unusable_keys: keyring
            .keys()
            .iter()
            .filter(|k| k.problem.is_some())
            .count(),
        skipped: keyring.skipped.clone(),
        roots,
        reachable_keys: reach.len(),
        within_max_depth: reach.values().filter(|r| r.depth <= args.max_depth).count(),
        max_depth: args.max_depth,
        certifications: stats,
        links: checks.len(),
    };

    if args.dry_run {
        if is_json_output() {
            print_json(&json!({ "dryRun": true, "summary": summary, "rows": rows }))?;
        } else {
            print_summary(&summary);
            print_rows(&rows, None);
            let to_grant = rows.iter().filter(|r| r.action == Action::Grant).count();
            println!(
                "\n{YELLOW}Dry run — nothing was granted.{RESET} Re-run without --dry-run to \
                 grant the {to_grant} row(s) marked `grant`."
            );
        }
        return Ok(());
    }

    let mut outcomes: Vec<Option<GrantOutcome>> = Vec::with_capacity(rows.len());
    for row in &rows {
        let (Action::Grant, Some(did)) = (&row.action, &row.member_did) else {
            outcomes.push(None);
            continue;
        };
        let payload = super::grant_payload(did, validity).map_err(|e| e.to_string());
        let outcome = match payload {
            Err(error) => GrantOutcome::Failed { error },
            Ok(payload) => match vtc.grant_vetter(&payload).await {
                Ok(g) if g.created => GrantOutcome::Granted {
                    endorsement_id: g.grant.endorsement_id.into(),
                },
                Ok(g) => GrantOutcome::AlreadyGranted {
                    endorsement_id: g.grant.endorsement_id.into(),
                },
                Err(e) => GrantOutcome::Failed {
                    error: guidance(e, Op::Grant { member_did: did }).to_string(),
                },
            },
        };
        outcomes.push(Some(outcome));
    }
    let failed = outcomes
        .iter()
        .filter(|o| matches!(o, Some(GrantOutcome::Failed { .. })))
        .count();

    if is_json_output() {
        let results: Vec<_> = rows
            .iter()
            .zip(&outcomes)
            .map(|(row, outcome)| {
                let mut value = serde_json::to_value(row).unwrap_or_default();
                if let Some(outcome) = outcome {
                    value["grant"] = serde_json::to_value(outcome).unwrap_or_default();
                }
                value
            })
            .collect();
        print_json(&json!({ "dryRun": false, "summary": summary, "rows": results }))?;
    } else {
        print_summary(&summary);
        print_rows(&rows, Some(&outcomes));
        let granted = outcomes
            .iter()
            .filter(|o| matches!(o, Some(GrantOutcome::Granted { .. })))
            .count();
        println!("\n{GREEN}{granted}{RESET} vetter(s) granted, {RED}{failed}{RESET} failed.");
    }
    if failed > 0 {
        return Err(format!(
            "{failed} grant(s) failed — see the result column. Fix the cause and run the same \
             command again: members already granted are skipped."
        )
        .into());
    }
    Ok(())
}

/// Every regular, non-hidden file in `dir`, sorted by name, with its text or
/// why it could not be read as text.
fn read_links(dir: &Path) -> CliResult<Vec<(String, Result<String, String>)>> {
    let entries = std::fs::read_dir(dir).map_err(|e| {
        format!(
            "could not read --links {}: {e}.\nPass a directory holding one `gpg --clearsign` \
             link statement per member.",
            dir.display()
        )
    })?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let meta = entry.metadata()?;
        if name.starts_with('.') || !meta.is_file() {
            continue;
        }
        let text = if meta.len() > MAX_LINK_BYTES {
            Err(format!(
                "{} bytes is too large for a link statement",
                meta.len()
            ))
        } else {
            std::fs::read(entry.path())
                .map_err(|e| e.to_string())
                .and_then(|b| String::from_utf8(b).map_err(|_| "not UTF-8 text".to_string()))
        };
        files.push((name, text));
    }
    if files.is_empty() {
        return Err(format!(
            "--links {} holds no link statements.\nEach member signs one with their PGP key:\n  \
             printf 'openvtc-link: <memberDid>\\n' | gpg --clearsign > <name>.asc\nand the files \
             are collected into this directory.",
            dir.display()
        )
        .into());
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

fn print_summary(s: &Summary) {
    let c = &s.certifications;
    println!(
        "{BOLD}Keyring{RESET}         {} keys ({} unusable: revoked, expired or without a \
         self-signed user ID)",
        s.keys, s.unusable_keys
    );
    for skipped in &s.skipped {
        println!("                {DIM}skipped: {skipped}{RESET}");
    }
    println!(
        "{BOLD}Certifications{RESET}  {} counted; ignored {} expired, {} revoked, {} invalid, \
         {} by keys not in the keyring, {} by unusable keys",
        c.counted, c.expired, c.revoked, c.invalid, c.unknown_issuer, c.unusable_issuer
    );
    println!(
        "{BOLD}Roots{RESET}           {} — {} keys reachable, {} within --max-depth {}",
        s.roots.join(", "),
        s.reachable_keys,
        s.within_max_depth,
        s.max_depth
    );
    println!("{BOLD}Links{RESET}           {} statements read\n", s.links);
}

fn print_rows(rows: &[PlanRow], outcomes: Option<&[Option<GrantOutcome>]>) {
    let result_of = |i: usize| -> String {
        match outcomes.and_then(|o| o[i].as_ref()) {
            Some(GrantOutcome::Granted { endorsement_id }) => format!("granted ({endorsement_id})"),
            Some(GrantOutcome::AlreadyGranted { .. }) => "already granted".into(),
            Some(GrantOutcome::Failed { .. }) => "failed".into(),
            None => short_action(&rows[i].action),
        }
    };

    if is_full_display() {
        print_full_list_title("Link statements", rows.len());
        for (i, row) in rows.iter().enumerate() {
            print_full_entry(&[
                ("File", &row.source),
                ("Member DID", row.member_did.as_deref().unwrap_or("—")),
                ("Fingerprint", row.fingerprint.as_deref().unwrap_or("—")),
                ("User ID", row.primary_user_id.as_deref().unwrap_or("—")),
                ("Depth", &row.depth.map_or("—".into(), |d| d.to_string())),
                ("Path", &full_path(&row.path)),
                ("Action", &result_of(i)),
            ]);
        }
    } else {
        let header = Row::new(vec![
            "Member DID",
            "Key",
            "Primary User ID",
            "Depth",
            "Certification Path",
            "Action",
        ])
        .style(header_style())
        .bottom_margin(1);
        let table_rows: Vec<Row> = rows
            .iter()
            .enumerate()
            .map(|(i, row)| {
                let label = result_of(i);
                let style = match (&row.action, outcomes.and_then(|o| o[i].as_ref())) {
                    (_, Some(GrantOutcome::Failed { .. })) => Style::default().fg(Color::Red),
                    (Action::Grant, _) => Style::default().fg(Color::Green),
                    (Action::AlreadyGranted { .. }, _) => Style::default(),
                    (Action::InvalidLink { .. }, _) => Style::default().fg(Color::Red),
                    _ => Style::default().fg(Color::Yellow),
                };
                Row::new(vec![
                    row.member_did
                        .as_deref()
                        .map_or_else(|| Cell::from("—"), did_cell),
                    Cell::from(row.fingerprint.as_deref().map_or("—".into(), short_key)),
                    Cell::from(row.primary_user_id.clone().unwrap_or_else(|| "—".into())),
                    Cell::from(row.depth.map_or("—".into(), |d| d.to_string())),
                    Cell::from(short_path(&row.path)),
                    Cell::from(label).style(style),
                ])
            })
            .collect();
        let table = Table::new(
            table_rows,
            [
                Constraint::Min(28),
                Constraint::Length(16),
                Constraint::Min(24),
                Constraint::Length(5),
                Constraint::Min(24),
                Constraint::Min(16),
            ],
        )
        .header(header)
        .column_spacing(2)
        .block(bordered(format!(" Link statements ({}) ", rows.len())));
        print_widget(table, height(rows.len()));
    }

    // The table has room for a label, not a reason. Every row that is not a
    // plain grant says why here, keyed by file so the operator can find it.
    let notes: Vec<String> = rows
        .iter()
        .enumerate()
        .filter_map(|(i, row)| {
            let reason = match (&row.action, outcomes.and_then(|o| o[i].as_ref())) {
                (_, Some(GrantOutcome::Failed { error })) => error.clone(),
                (Action::InvalidLink { reason } | Action::TooFar { reason }, _) => reason.clone(),
                (Action::NotAMember, _) => format!(
                    "{} is not an active member — they must join before they can vet",
                    row.member_did.as_deref().unwrap_or("the DID")
                ),
                _ => return None,
            };
            Some(format!("  {}: {reason}", row.source))
        })
        .collect();
    if !notes.is_empty() {
        println!("{BOLD}Notes{RESET}");
        for note in notes {
            println!("{note}");
        }
    }
    if !is_full_display() {
        println!(
            "  {DIM}Keys show their 16-digit key id; `{} --full-display vetting bootstrap-pgp …` \
             prints full fingerprints, DIDs and paths.{RESET}",
            bin_name()
        );
    }
}

fn short_action(action: &Action) -> String {
    match action {
        Action::Grant => "grant".into(),
        Action::AlreadyGranted { .. } => "already granted".into(),
        Action::TooFar { .. } => "too far".into(),
        Action::NotAMember => "not a member".into(),
        Action::InvalidLink { .. } => "invalid link".into(),
    }
}

/// The long key id: the fingerprint's last 16 hex digits.
fn short_key(fingerprint: &str) -> String {
    fingerprint[fingerprint.len().saturating_sub(16)..].to_string()
}

fn short_path(path: &[String]) -> String {
    if path.is_empty() {
        return "—".into();
    }
    path.iter()
        .map(|fp| fp[fp.len().saturating_sub(8)..].to_string())
        .collect::<Vec<_>>()
        .join(" → ")
}

fn full_path(path: &[String]) -> String {
    if path.is_empty() {
        "—".into()
    } else {
        path.join(" → ")
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_files_are_read_in_name_order_and_hidden_files_skipped() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("b.asc"), "b").unwrap();
        std::fs::write(dir.path().join("a.asc"), "a").unwrap();
        std::fs::write(dir.path().join(".DS_Store"), "x").unwrap();
        std::fs::write(dir.path().join("binary.asc"), [0xff, 0xfe]).unwrap();
        std::fs::create_dir(dir.path().join("nested")).unwrap();
        let files = read_links(dir.path()).unwrap();
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["a.asc", "b.asc", "binary.asc"]);
        assert_eq!(files[2].1, Err("not UTF-8 text".to_string()));
    }

    #[test]
    fn an_empty_link_directory_shows_how_to_make_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_links(dir.path()).unwrap_err().to_string();
        assert!(err.contains("gpg --clearsign"), "{err}");
    }

    #[test]
    fn keys_and_paths_are_shortened_for_the_table() {
        let fp = "0123456789ABCDEF0123456789ABCDEF01234567";
        assert_eq!(short_key(fp), "89ABCDEF01234567");
        assert_eq!(
            short_path(&[
                fp.to_string(),
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF76543210".to_string()
            ]),
            "01234567 → 76543210"
        );
    }
}
