//! `pnm elections …` — a member reading their community's elections and voting in them, with
//! every key in their VTA ([`vta_cli_common::commands::elections`]).

use vta_cli_common::commands::elections::{self, VoteTarget};
use vta_cli_common::commands::elections_trustee::{self as trustee, TrusteeTarget};
use vta_sdk::client::VtaClient;

use crate::cli::{ElectionCommands, ElectionTarget, TrusteeCommands};

fn target(t: &ElectionTarget) -> VoteTarget<'_> {
    VoteTarget {
        vtc_url: &t.vtc,
        vtc_did: &t.vtc_did,
        member: &t.member,
        context: &t.context,
    }
}

fn trustee_target(t: &crate::cli::TrusteeTarget) -> TrusteeTarget<'_> {
    TrusteeTarget {
        community: &t.community,
        ballot_box: &t.ballot_box,
        trustee: &t.trustee,
        context: &t.context,
    }
}

pub(crate) async fn run(
    client: &VtaClient,
    command: ElectionCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        ElectionCommands::List { target: t } => elections::cmd_list(client, target(&t)).await,
        ElectionCommands::Show {
            election_id,
            target: t,
        } => elections::cmd_show(client, target(&t), &election_id).await,
        ElectionCommands::Vote {
            election_id,
            answers,
            ballot,
            no_delay,
            target: t,
        } => {
            elections::cmd_vote(
                client,
                target(&t),
                &election_id,
                &answers,
                ballot.as_ref(),
                no_delay,
            )
            .await
        }
        ElectionCommands::Trustee(TrusteeCommands::Status {
            election_id,
            target: t,
        }) => trustee::cmd_status(client, trustee_target(&t), &election_id).await,
        ElectionCommands::Trustee(TrusteeCommands::Step {
            election_id,
            watch,
            target: t,
        }) => trustee::cmd_step(client, trustee_target(&t), &election_id, watch).await,
    }
}
