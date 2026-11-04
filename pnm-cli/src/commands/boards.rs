//! `pnm boards …` — a member taking part in their community's boards, with every key in their
//! VTA ([`vta_cli_common::commands::boards`]).

use vta_cli_common::commands::boards::{self, BoardTarget, Proposal};
use vta_sdk::client::VtaClient;

use crate::cli::{BoardCommands, BoardTarget as Target, IdeaText};

fn target<'a>(t: &'a Target, context: Option<&'a str>) -> BoardTarget<'a> {
    BoardTarget {
        vtc_url: &t.vtc,
        vtc_did: &t.vtc_did,
        member: &t.member,
        entry: t.entry.as_deref(),
        context,
    }
}

fn proposal(i: &IdeaText) -> Proposal<'_> {
    Proposal {
        title: i.title.as_deref(),
        description: i.description.as_deref(),
        format: i.format.as_deref(),
        topic: i.topic.as_deref(),
    }
}

pub(crate) async fn run(
    client: &VtaClient,
    command: BoardCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        BoardCommands::List { status, target: t } => {
            boards::cmd_list(client, target(&t, None), status.as_deref()).await
        }
        BoardCommands::Show {
            board_id,
            states,
            target: t,
        } => boards::cmd_show(client, target(&t, None), &board_id, &states).await,
        BoardCommands::Propose {
            board_id,
            idea,
            target: t,
        } => {
            if idea.title.is_none() || idea.description.is_none() {
                return Err("an idea needs --title and --description".into());
            }
            boards::cmd_propose(client, target(&t, None), &board_id, proposal(&idea)).await
        }
        BoardCommands::Update {
            idea_id,
            idea,
            target: t,
        } => boards::cmd_update(client, target(&t, None), &idea_id, proposal(&idea)).await,
        BoardCommands::Withdraw { idea_id, target: t } => {
            boards::cmd_withdraw(client, target(&t, None), &idea_id).await
        }
        BoardCommands::Notes {
            board_id,
            idea,
            all,
            target: t,
        } => boards::cmd_notes(client, target(&t, None), &board_id, idea.as_deref(), all).await,
        BoardCommands::Note {
            board_id,
            text,
            idea,
            target: t,
        } => boards::cmd_note(client, target(&t, None), &board_id, &text, idea.as_deref()).await,
        BoardCommands::WithdrawNote { note_id, target: t } => {
            boards::cmd_withdraw_note(client, target(&t, None), &note_id).await
        }
        BoardCommands::TakeTickets {
            board_id,
            context,
            target: t,
        } => boards::cmd_take_tickets(client, target(&t, Some(&context)), &board_id).await,
    }
}
