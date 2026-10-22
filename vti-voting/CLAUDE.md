# CLAUDE.md — vti-voting

Crate guidance. The workspace `CLAUDE.md` applies too.

## What this crate is

(The crate's full entry from the workspace `CLAUDE.md` crate map.)

**Community voting** (VTI-VOT-001 – 100; published, as `vta-service` runs its voter role). The PCS core: `registrar` (voting helper key under its own deployment label, tickets under `voter/<election>`), `voter` (fresh key per election, blind ticket request, `cast_wire` = `attest_in_context` for the election point over the ballot's JCS bytes), `ballot_box` (verifies on the published `hvk` alone; the tag is the per-election nullifier). `board` (RFC 9162 log, inclusion/consistency proofs), `rules` + `tally` over the generated `voting/*` types, and `service::BallotBox` — every `voting/*` task as a state machine with a `Journal` (rebuilt by replaying the board). `audit` re-verifies a whole board from the published key alone (certification, any auditor). `trustees`: the sealed and tallied-encrypted levels' cryptography on Ristretto (`curve25519-dalek`) — dealer-free t-of-n key generation (Feldman + proof of knowledge), Chaum–Pedersen-proven partial decryptions, sealed ballots (ElGamal KEM + ChaCha20-Poly1305), and exponential-ElGamal ballots with 0/1 and selection-count proofs; scalars from bytes, never its `rand_core` (PCS pins rand 0.8). Unaudited protocol code over audited group operations. Wire types: `trust_tasks_rs::specs::voting` (0.32.3+). Benchmark: `examples/scale.rs`
