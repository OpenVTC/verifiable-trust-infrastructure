//! Ticket → cast → ballot box, end to end, and every way a cast must fail.
//!
//! Test names carry the requirement they hold (VTI-VOT-*, the VTI specification's Community Voting chapter).

use rand::{SeedableRng, rngs::StdRng};
use vti_voting::{
    VotingError,
    ballot_box::{Admission, BallotBox, MemoryNullifiers, Revote},
    election::{Election, ElectionId},
    registrar::Registrar,
    scheme::VotingParams,
    voter::{Ticket, Voter},
};

const COMMUNITY: &str = "did:webvh:Qm123:riverside.example";

fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

fn election(id: &str) -> Election {
    Election::new(COMMUNITY, ElectionId::new(id).unwrap(), [7; 32]).unwrap()
}

/// A voter who went through the whole ticket round for `e`.
fn ticketed(reg: &Registrar, e: &Election, seed: u64) -> (Voter, Ticket) {
    let params = reg.params();
    let mut r = rng(seed);
    let voter = Voter::generate(&params, &mut r).unwrap();
    let (request, state) = voter.ticket_request(&params, e, &mut r).unwrap();
    let pre = reg.issue_ticket(e, voter.id(), &request, &mut r).unwrap();
    let ticket = voter.accept_ticket(&params, e, &pre, &state).unwrap();
    (voter, ticket)
}

fn ballot_box(params: &VotingParams, e: &Election, revote: Revote) -> BallotBox<MemoryNullifiers> {
    BallotBox::new(params, e.clone(), revote, MemoryNullifiers::default()).unwrap()
}

#[test]
fn vot_040_a_ticketed_cast_is_counted() {
    let reg = Registrar::generate(COMMUNITY, &mut rng(1)).unwrap();
    let params = reg.params();
    let e = election("agm-2027");
    let (voter, ticket) = ticketed(&reg, &e, 2);
    let cast = voter.cast(&params, &ticket, b"yes", &mut rng(3)).unwrap();
    let mut bb = ballot_box(&params, &e, Revote::Replace);
    assert!(matches!(
        bb.admit(&cast, b"yes").unwrap(),
        Admission::Counted { .. }
    ));
}

#[test]
fn vot_040_a_ticket_from_another_registrar_is_refused() {
    let ours = Registrar::generate(COMMUNITY, &mut rng(1)).unwrap();
    // Same community identifier, another key: a forged registrar.
    let forged = Registrar::generate(COMMUNITY, &mut rng(99)).unwrap();
    let e = election("agm-2027");
    let (voter, ticket) = ticketed(&forged, &e, 2);
    let cast = voter
        .cast(&forged.params(), &ticket, b"yes", &mut rng(3))
        .unwrap();
    let mut bb = ballot_box(&ours.params(), &e, Revote::Replace);
    assert!(matches!(
        bb.admit(&cast, b"yes"),
        Err(VotingError::ProofRejected(_))
    ));
}

#[test]
fn vot_040_a_ticket_for_another_election_is_refused() {
    let reg = Registrar::generate(COMMUNITY, &mut rng(1)).unwrap();
    let params = reg.params();
    let (voter, ticket) = ticketed(&reg, &election("survey-1"), 2);
    let cast = voter.cast(&params, &ticket, b"yes", &mut rng(3)).unwrap();
    let mut bb = ballot_box(&params, &election("agm-2027"), Revote::Replace);
    assert_eq!(bb.admit(&cast, b"yes"), Err(VotingError::WrongClass));
}

#[test]
fn vot_041_a_second_ballot_replaces_the_first_under_one_tag() {
    let reg = Registrar::generate(COMMUNITY, &mut rng(1)).unwrap();
    let params = reg.params();
    let e = election("agm-2027");
    let (voter, ticket) = ticketed(&reg, &e, 2);
    let first = voter.cast(&params, &ticket, b"yes", &mut rng(3)).unwrap();
    let second = voter.cast(&params, &ticket, b"no", &mut rng(4)).unwrap();
    // Fresh randomness, same tag: the nullifier depends on the key and the election only.
    assert_eq!(first.tag().unwrap(), second.tag().unwrap());
    let mut bb = ballot_box(&params, &e, Revote::Replace);
    bb.admit(&first, b"yes").unwrap();
    assert!(matches!(
        bb.admit(&second, b"no").unwrap(),
        Admission::Replaced { .. }
    ));
    assert_eq!(bb.store().len(), 1);
}

#[test]
fn vot_041_without_revote_a_different_second_ballot_is_refused() {
    let reg = Registrar::generate(COMMUNITY, &mut rng(1)).unwrap();
    let params = reg.params();
    let e = election("agm-2027");
    let (voter, ticket) = ticketed(&reg, &e, 2);
    let first = voter.cast(&params, &ticket, b"yes", &mut rng(3)).unwrap();
    let second = voter.cast(&params, &ticket, b"no", &mut rng(4)).unwrap();
    let mut bb = ballot_box(&params, &e, Revote::Refuse);
    bb.admit(&first, b"yes").unwrap();
    assert_eq!(bb.admit(&second, b"no"), Err(VotingError::AlreadyVoted));
}

#[test]
fn vot_042_a_resent_cast_is_answered_as_the_first_time() {
    let reg = Registrar::generate(COMMUNITY, &mut rng(1)).unwrap();
    let params = reg.params();
    let e = election("agm-2027");
    let (voter, ticket) = ticketed(&reg, &e, 2);
    let cast = voter.cast(&params, &ticket, b"yes", &mut rng(3)).unwrap();
    for revote in [Revote::Replace, Revote::Refuse] {
        let mut bb = ballot_box(&params, &e, revote);
        bb.admit(&cast, b"yes").unwrap();
        assert!(matches!(
            bb.admit(&cast, b"yes").unwrap(),
            Admission::AlreadyCounted { .. }
        ));
    }
}

#[test]
fn vot_031_tags_differ_across_voters_and_across_elections() {
    let reg = Registrar::generate(COMMUNITY, &mut rng(1)).unwrap();
    let params = reg.params();
    let e1 = election("agm-2027");
    let e2 = election("survey-1");
    // One key, ticketed for two elections (the VTA uses a fresh key per election; this checks
    // that even a reused key gives unrelated tags).
    let mut r = rng(2);
    let voter = Voter::generate(&params, &mut r).unwrap();
    let mut tag_in = |e: &Election| {
        let (req, st) = voter.ticket_request(&params, e, &mut r).unwrap();
        let pre = reg.issue_ticket(e, voter.id(), &req, &mut r).unwrap();
        let t = voter.accept_ticket(&params, e, &pre, &st).unwrap();
        voter
            .cast(&params, &t, b"x", &mut r)
            .unwrap()
            .tag()
            .unwrap()
    };
    let a1 = tag_in(&e1);
    let a2 = tag_in(&e2);
    assert_ne!(a1, a2);
    let (other, ticket) = ticketed(&reg, &e1, 5);
    let b1 = other
        .cast(&params, &ticket, b"x", &mut rng(6))
        .unwrap()
        .tag()
        .unwrap();
    assert_ne!(a1, b1);
}

#[test]
fn vot_020_the_cast_does_not_carry_the_voter_identifier() {
    let reg = Registrar::generate(COMMUNITY, &mut rng(1)).unwrap();
    let params = reg.params();
    let e = election("agm-2027");
    let (voter, ticket) = ticketed(&reg, &e, 2);
    let cast = voter.cast(&params, &ticket, b"yes", &mut rng(3)).unwrap();
    let id = vti_voting::scheme::point_text(voter.id()).unwrap();
    let wire = serde_json::to_string(&cast).unwrap();
    assert!(!wire.contains(&id), "the registrar saw this identifier");
    assert_ne!(cast.tag().unwrap(), id);
}

#[test]
fn vot_044_verification_needs_only_published_parameters() {
    let reg = Registrar::generate(COMMUNITY, &mut rng(1)).unwrap();
    let e = election("agm-2027");
    let (voter, ticket) = ticketed(&reg, &e, 2);
    let cast = voter
        .cast(&reg.params(), &ticket, b"yes", &mut rng(3))
        .unwrap();
    // An auditor rebuilds the parameters from the community's published identifier and hvk.
    let auditor = VotingParams::new(COMMUNITY, reg.hvk().clone()).unwrap();
    let bb = ballot_box(&auditor, &e, Revote::Replace);
    assert_eq!(bb.verify(&cast, b"yes").unwrap(), cast.tag().unwrap());
}

#[test]
fn vot_030_a_cast_cannot_be_moved_to_another_ballot() {
    let reg = Registrar::generate(COMMUNITY, &mut rng(1)).unwrap();
    let params = reg.params();
    let e = election("agm-2027");
    let (voter, ticket) = ticketed(&reg, &e, 2);
    let cast = voter.cast(&params, &ticket, b"yes", &mut rng(3)).unwrap();
    let mut bb = ballot_box(&params, &e, Revote::Replace);
    assert!(matches!(
        bb.admit(&cast, b"no"),
        Err(VotingError::ProofRejected(_))
    ));
    assert!(bb.store().is_empty());
}

#[test]
fn vot_011_a_ballot_for_another_manifest_does_not_count() {
    let reg = Registrar::generate(COMMUNITY, &mut rng(1)).unwrap();
    let params = reg.params();
    let registered = election("agm-2027");
    // The voter was shown a different manifest for the same election identifier.
    let shown = Election::new(COMMUNITY, ElectionId::new("agm-2027").unwrap(), [8; 32]).unwrap();
    let (voter, ticket) = ticketed(&reg, &shown, 2);
    let cast = voter.cast(&params, &ticket, b"yes", &mut rng(3)).unwrap();
    let mut bb = ballot_box(&params, &registered, Revote::Replace);
    assert!(matches!(
        bb.admit(&cast, b"yes"),
        Err(VotingError::ProofRejected(_))
    ));
}

#[test]
fn a_registrar_refuses_another_communitys_election() {
    let reg = Registrar::generate(COMMUNITY, &mut rng(1)).unwrap();
    let other = Election::new("did:example:other", ElectionId::new("e").unwrap(), [0; 32]).unwrap();
    let params = VotingParams::new("did:example:other", reg.hvk().clone()).unwrap();
    let mut r = rng(2);
    let voter = Voter::generate(&params, &mut r).unwrap();
    let (req, _) = voter.ticket_request(&params, &other, &mut r).unwrap();
    assert!(matches!(
        reg.issue_ticket(&other, voter.id(), &req, &mut r),
        Err(VotingError::WrongCommunity { .. })
    ));
}

#[test]
fn derived_keys_are_stable_and_separate_from_vetting() {
    let secret = [42u8; 32];
    let a = Registrar::derive(COMMUNITY, &secret).unwrap();
    let b = Registrar::derive(COMMUNITY, &secret).unwrap();
    assert_eq!(a.public_text().unwrap(), b.public_text().unwrap());
    let vetting = vti_vetting_pcs::issuer::Issuer::derive(COMMUNITY, &secret).unwrap();
    assert_ne!(
        a.public_text().unwrap(),
        vetting.public_text().unwrap().0,
        "one master secret must not give the vetting key as the voting key"
    );
}

#[test]
fn a_seeded_voter_key_is_stable() {
    let reg = Registrar::generate(COMMUNITY, &mut rng(1)).unwrap();
    let a = Voter::from_seed(&reg.params(), &[3; 32]).unwrap();
    let b = Voter::from_seed(&reg.params(), &[3; 32]).unwrap();
    assert_eq!(a.id(), b.id());
}
