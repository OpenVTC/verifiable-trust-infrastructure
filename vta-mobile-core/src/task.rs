//! Trust Task build / verify — wraps `trust-tasks-rs` + `trust-tasks-proof`.
//!
//! **Slice 2** (pure, synchronous). Blocked on republishing `trust-tasks-rs`:
//! crates.io 0.1.2 predates the `evidence` / `acceptableEvidence` fields
//! merged to `dtgwg-trust-tasks-tf` (PRs #61/#62).
//!
//! Planned surface:
//! - `parse_step_up_request(json) -> StepUpRequest`   (subject, reason, challenge, acceptable_evidence)
//! - `verify_task_proof(json) -> VerifiedTask`         (Data Integrity proof check)
//! - `build_error(thread_id, code) -> TaskJson`
