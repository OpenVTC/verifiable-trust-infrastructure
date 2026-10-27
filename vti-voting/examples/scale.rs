//! Phase 0 benchmark: what each step of a ticket and a cast costs, and what that means for a
//! community of 300,000.
//!
//! ```sh
//! cargo run -p vti-voting --release --example scale -- [voters] [threads]
//! ```
//!
//! Defaults: 500 voters, every available core for the parallel verification.

use std::{
    thread,
    time::{Duration, Instant},
};

use ark_serialize::CanonicalSerialize;
use rand::{SeedableRng, rngs::StdRng};
use vti_voting::{
    ballot_box::{BallotBox, MemoryNullifiers, Revote},
    election::{Election, ElectionId},
    registrar::Registrar,
    voter::{Cast, Voter},
};

const COMMUNITY: &str = "did:webvh:QmBench:community.example";
const TARGET: f64 = 300_000.0;

fn main() {
    let mut args = std::env::args().skip(1);
    let n: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(500);
    let threads: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or_else(|| {
        thread::available_parallelism()
            .map(std::num::NonZero::get)
            .unwrap_or(1)
    });

    let mut rng = StdRng::seed_from_u64(1);
    let t = Instant::now();
    let reg = Registrar::derive(COMMUNITY, &[9; 32]).unwrap();
    let setup = t.elapsed();
    let params = reg.params();
    let election = Election::new(COMMUNITY, ElectionId::new("bench").unwrap(), [1; 32]).unwrap();

    let (mut keygen, mut request, mut issue, mut accept, mut cast_t) = (
        Duration::ZERO,
        Duration::ZERO,
        Duration::ZERO,
        Duration::ZERO,
        Duration::ZERO,
    );
    let mut casts: Vec<(Cast, Vec<u8>)> = Vec::with_capacity(n);
    for i in 0..n {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&(i as u64).to_le_bytes());

        let t = Instant::now();
        let voter = Voter::from_seed(&params, &seed).unwrap();
        keygen += t.elapsed();

        let t = Instant::now();
        let (req, state) = voter.ticket_request(&params, &election, &mut rng).unwrap();
        request += t.elapsed();

        let t = Instant::now();
        let pre = reg
            .issue_ticket(&election, voter.id(), &req, &mut rng)
            .unwrap();
        issue += t.elapsed();

        let t = Instant::now();
        let ticket = voter
            .accept_ticket(&params, &election, &pre, &state)
            .unwrap();
        accept += t.elapsed();

        let ballot = format!("{{\"q1\":\"yes\",\"voter\":{i}}}").into_bytes();
        let t = Instant::now();
        let cast = voter.cast(&params, &ticket, &ballot, &mut rng).unwrap();
        cast_t += t.elapsed();
        casts.push((cast, ballot));
    }

    // Admission on one thread: verification plus the nullifier insert.
    let mut bb = BallotBox::new(
        &params,
        election.clone(),
        Revote::Replace,
        MemoryNullifiers::default(),
    )
    .unwrap();
    let t = Instant::now();
    for (c, b) in &casts {
        bb.admit(c, b).unwrap();
    }
    let admit_serial = t.elapsed();

    // Verification across `threads`: what an auditor's recount does.
    let bb = &bb;
    let t = Instant::now();
    thread::scope(|s| {
        for chunk in casts.chunks(n.div_ceil(threads)) {
            s.spawn(move || {
                for (c, b) in chunk {
                    bb.verify(c, b).unwrap();
                }
            });
        }
    });
    let verify_parallel = t.elapsed();

    let mut bytes = Vec::new();
    casts[0]
        .0
        .attestation
        .serialize_compressed(&mut bytes)
        .unwrap();
    let json = serde_json::to_vec(&casts[0].0).unwrap();

    let per = |d: Duration| d.as_secs_f64() * 1000.0 / n as f64;
    let at_target = |d: Duration| d.as_secs_f64() / n as f64 * TARGET;
    println!("vti-voting scale benchmark: {n} voters, {threads} threads for parallel verification");
    println!(
        "registrar key derivation        {:>9.2} ms (once)",
        setup.as_secs_f64() * 1000.0
    );
    println!();
    println!(
        "{:<32}{:>12}{:>22}",
        "step", "ms each", "300,000 on one core"
    );
    for (name, d) in [
        ("voter key (VTA)", keygen),
        ("ticket request (VTA)", request),
        ("ticket issuance (VTC, serial)", issue),
        ("ticket unblind (VTA)", accept),
        ("cast: attest (VTA)", cast_t),
        ("admit: verify + record (box)", admit_serial),
    ] {
        println!("{name:<32}{:>12.2}{:>20.0} s", per(d), at_target(d));
    }
    println!();
    println!(
        "recount on {threads} threads            {:>9.2} ms each   {:>8.0} s for 300,000",
        per(verify_parallel),
        at_target(verify_parallel)
    );
    println!(
        "issuance rate (one VTC)         {:>9.0} tickets / s",
        n as f64 / issue.as_secs_f64()
    );
    println!(
        "admission rate (one core)       {:>9.0} casts / s",
        n as f64 / admit_serial.as_secs_f64()
    );
    println!(
        "attestation size                {:>9} bytes compressed, {} bytes as JSON",
        bytes.len(),
        json.len()
    );
}
