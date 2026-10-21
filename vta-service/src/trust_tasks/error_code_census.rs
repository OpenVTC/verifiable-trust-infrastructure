//! The declared-error-code census (#1600): every extended error code a
//! dispatched, published task **declares** must be witnessed by a test that
//! asserts this service **emitting** it, or sit in a baseline that only
//! shrinks.
//!
//! ## Why this exists
//!
//! The schema-conformance sweep next door (`conformance.rs`) witnesses the
//! success path only. A specification can declare extended codes under SPEC
//! §8.5, the service can answer every one of them as a bare `taskFailed`, and
//! every gate stays green. That shipped on the VTC (#1591, #1593), whose census
//! (`vtc-service/src/trust_tasks/error_code_census.rs`) this mirrors.
//!
//! ## How it works
//!
//! The census is **derived, not hand-maintained**. Its scope is the sweep's
//! dispatched ∩ published URI set ([`super::conformance::resolved_uris`]), and
//! each URI's declared codes come from
//! `trust_tasks_rs::schema_index::error_codes_for`, generated from the
//! specification's `errorCodes` front matter.
//!
//! A code is **witnessed** when a test in this crate (a `#[cfg(test)]` module
//! under `src/`, a `*_tests.rs` file, or anything under `tests/`) asserts on it:
//! an `assert` line, or one of the four lines below one, spells either the full
//! wire code as a string literal (`assert_eq!(code(&out), "keys/…:notFound")`,
//! the usual form here) or the generated constant's path down to at least its
//! task (`…::issue::v0_3::error_codes::RESPONSE_TOO_LARGE`). Finding it is
//! derived from the tree rather than listed here.
//!
//! Every other declared code must be in [`unwitnessed`], a typed baseline:
//!
//! - a code that gains a witness must leave it (listing it in both fails);
//! - its length is held under [`UNWITNESSED_CEILING`], a ratchet: shrinking
//!   needs no edit here, growing past it — a newly dispatched task declaring
//!   codes nothing tests — does.
//!
//! ## What a witness proves, and what it does not
//!
//! The census reads test source; it does not run the test. The test runs in
//! the same `cargo test -p vta-service` invocation, so a witness that fails is
//! a red build either way. What the census adds is the *requirement* that such
//! an assertion exist for every declared code.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use trust_tasks_rs::DeclaredErrorCode;
use trust_tasks_rs::schema_index::error_codes_for;

use super::conformance::resolved_uris;

/// Declared codes nothing yet shows the service emitting. **Only shrinks.**
///
/// Typed paths, not strings: a code the specification stops declaring is a
/// compile error here, not a stale row.
fn unwitnessed() -> Vec<DeclaredErrorCode> {
    use trust_tasks_rs::specs as s;
    vec![
        // BASELINE-BEGIN — generated from this test's own failure output.
        s::acl::change_role::v0_1::error_codes::ROLE_NOT_RECOGNIZED,
        s::acl::change_role::v0_1::error_codes::STATE_MISMATCH,
        s::acl::grant::v0_1::error_codes::ROLE_NOT_RECOGNIZED,
        s::acl::revoke::v0_1::error_codes::LAST_AUTHORITY_PROTECTED,
        s::acl::revoke::v0_1::error_codes::SUBJECT_NOT_PRESENT,
        s::acl::swap_key::v0_1::error_codes::LINK_PROOF_INVALID,
        s::acl::swap_key::v0_1::error_codes::LINK_PROOF_REQUIRED,
        s::acl::swap_key::v0_1::error_codes::NOT_HOLDER,
        s::acl::swap_key::v0_1::error_codes::SUBJECT_ALREADY_IN_USE,
        s::acl::swap_key::v0_1::error_codes::SUBJECT_NOT_FOUND,
        s::acl::update::v0_1::error_codes::NARROWING_NOT_PERMITTED,
        s::acl::update::v0_1::error_codes::NOT_FOUND,
        s::acl::update::v0_1::error_codes::ROLE_CHANGE_NOT_PERMITTED,
        s::audit::list::v0_1::error_codes::INVALID_CURSOR,
        s::auth::revoke_session::v0_2::error_codes::SESSION_NOT_FOUND,
        s::auth::step_up::approve_response::v0_3::error_codes::ACR_UNSATISFIED,
        s::auth::step_up::approve_response::v0_3::error_codes::APPROVER_UNAUTHORIZED,
        s::auth::step_up::approve_response::v0_3::error_codes::ASSERTION_INVALID,
        s::auth::step_up::approve_response::v0_3::error_codes::CHALLENGE_EXPIRED,
        s::auth::step_up::approve_response::v0_3::error_codes::CHALLENGE_UNKNOWN,
        s::auth::step_up::approve_response::v0_3::error_codes::NO_GATE,
        s::auth::step_up::approve_response::v0_3::error_codes::SUBJECT_MISMATCH,
        s::auth::whoami::v0_1::error_codes::NO_SESSION,
        s::consent::approver_list::v1_0::error_codes::NOT_AUTHORIZED,
        s::consent::approver_set::v1_0::error_codes::INVALID_BINDING,
        s::consent::approver_set::v1_0::error_codes::NOT_AUTHORIZED,
        s::consent::decision::v1_0::error_codes::CHALLENGE_MISMATCH,
        s::consent::decision::v1_0::error_codes::NOT_AUTHORIZED,
        s::consent::decision::v1_0::error_codes::SUBJECT_INVALID,
        s::consent::list::v1_0::error_codes::NOT_AUTHORIZED,
        s::consent::request::v1_0::error_codes::NO_APPROVER,
        s::consent::request::v1_0::error_codes::RATE_LIMITED,
        s::consent::request::v1_0::error_codes::SUBJECT_INVALID,
        s::consent::revoke::v1_0::error_codes::NOT_AUTHORIZED,
        s::consent::revoke::v1_0::error_codes::NOT_FOUND,
        s::credential_exchange::issue::v0_1::error_codes::UNOPENABLE_BUNDLE,
        s::credential_exchange::issue::v0_1::error_codes::UNSUPPORTED_FORMAT,
        s::credential_exchange::offer::v0_1::error_codes::UNSUPPORTED_CREDENTIAL,
        s::credential_exchange::pending::approve::v0_1::error_codes::NOT_FOUND,
        s::credential_exchange::pending::deny::v0_1::error_codes::NOT_FOUND,
        s::credential_exchange::query::v0_1::error_codes::CONSENT_REQUIRED,
        s::credential_exchange::query::v0_1::error_codes::NO_MATCH,
        s::device::disable::v0_1::error_codes::ALREADY_DISABLED,
        s::device::disable::v0_1::error_codes::NOT_FOUND,
        s::device::heartbeat::v0_1::error_codes::NOT_REGISTERED,
        s::device::register::v0_1::error_codes::ALREADY_REGISTERED,
        s::device::register::v0_1::error_codes::ATTESTATION_FAILED,
        s::device::register::v0_1::error_codes::HPKE_KEY_INVALID,
        s::device::register::v0_1::error_codes::NO_PENDING_ENROLMENT,
        s::device::set_wake::v0_1::error_codes::GATEWAY_UNREACHABLE,
        s::device::set_wake::v0_1::error_codes::INVALID_HANDLE,
        s::device::set_wake::v0_1::error_codes::NOT_REGISTERED,
        s::device::wipe::v0_1::error_codes::NOT_FOUND,
        s::device::wipe::v0_1::error_codes::WIPE_PARTIAL,
        s::external::accounts::archive::v0_1::error_codes::INVALID_TRANSITION,
        s::external::accounts::bindings::grant::v0_1::error_codes::CEILING_NOT_APPLICABLE,
        s::external::accounts::bindings::revoke::v0_1::error_codes::NO_SUCH_BINDING,
        s::external::accounts::delete::v0_1::error_codes::INVALID_TRANSITION,
        s::external::accounts::keys::rotate::v0_1::error_codes::NO_ROTATION_PENDING,
        s::external::accounts::keys::rotate::v0_1::error_codes::NOT_KEY_MODEL,
        s::external::accounts::keys::rotate::v0_1::error_codes::PROBE_FAILED,
        s::external::accounts::keys::rotate::v0_1::error_codes::ROTATION_PENDING,
        s::external::accounts::restore::v0_1::error_codes::INVALID_TRANSITION,
        s::external::accounts::resume::v0_1::error_codes::INVALID_TRANSITION,
        s::external::accounts::secret::set::v0_1::error_codes::NOT_STATIC_MODEL,
        s::external::accounts::suspend::v0_1::error_codes::INVALID_TRANSITION,
        s::external::credentials::issue::v0_3::error_codes::NO_KEY_AGREEMENT,
        s::external::credentials::issue::v0_3::error_codes::NOT_BROKERED,
        s::external::credentials::issue::v0_3::error_codes::NOT_ACTIVE,
        s::external::credentials::issue::v0_3::error_codes::NOT_BOUND,
        s::external::credentials::issue::v0_3::error_codes::PROVIDER_REFUSED,
        s::external::credentials::issue::v0_3::error_codes::PROVIDER_SETUP_REQUIRED,
        s::external::credentials::issue::v0_3::error_codes::PROVIDER_UNAVAILABLE,
        s::keys::export_secret::v0_1::error_codes::NEVER_EXPORTABLE,
        s::keys::export_secret::v0_1::error_codes::NOT_EXPORTABLE,
        s::keys::revoke::v0_1::error_codes::BOUND_TO_IDENTIFIER,
        s::keys::set_exportability::v0_1::error_codes::NOT_PERMITTED_FOR_THIS_KEY,
        s::keys::sign_csr::v0_1::error_codes::FAILED_PRECONDITION,
        s::keys::sign_csr::v0_1::error_codes::KEY_TYPE_UNSUPPORTED,
        s::keys::sign_csr::v0_1::error_codes::SUBJECT_INVALID,
        s::keys::sign_jws::v0_1::error_codes::FAILED_PRECONDITION,
        s::keys::sign_jws::v0_1::error_codes::HEADER_MEMBER_FORBIDDEN,
        s::keys::sign_jws::v0_1::error_codes::KEY_TYPE_UNSUPPORTED,
        s::keys::sign_jws::v0_1::error_codes::PAYLOAD_INVALID,
        s::keys::sign_sshsig::v0_1::error_codes::FAILED_PRECONDITION,
        s::keys::sign::v0_1::error_codes::FAILED_PRECONDITION,
        s::keys::rename::v0_1::error_codes::ALREADY_EXISTS,
        s::persona::attribute::delete::v1_0::error_codes::REFERENCED,
        s::persona::attribute::delete::v1_0::error_codes::VERSION_CONFLICT,
        s::persona::attribute::list::v1_0::error_codes::CURSOR_INVALID,
        s::persona::attribute::put::v1_0::error_codes::VALUE_TYPE_MISMATCH,
        s::persona::attribute::put::v1_0::error_codes::VERSION_CONFLICT,
        s::persona::binding::list::v1_0::error_codes::CURSOR_INVALID,
        s::persona::binding::set::v1_0::error_codes::CONTEXT_NOT_FOUND,
        s::persona::binding::set::v1_0::error_codes::NO_PERSONA_HERE,
        s::persona::binding::set::v1_0::error_codes::PROFILE_NOT_FOUND,
        s::persona::binding::set::v1_0::error_codes::VERSION_CONFLICT,
        s::persona::contact::get::v1_0::error_codes::NOT_FOUND,
        s::persona::contact::get::v1_0::error_codes::REVISION_REAPED,
        s::persona::contact::list::v1_0::error_codes::CURSOR_INVALID,
        s::persona::contact::put::v1_0::error_codes::DOCUMENT_TOO_LARGE,
        s::persona::disclosure::history::v1_0::error_codes::CURSOR_INVALID,
        s::persona::disclosure::present::v1_0::error_codes::PREVIEW_NOT_FOUND,
        s::persona::disclosure::present::v1_0::error_codes::STALE_CLAIM,
        s::persona::disclosure::preview::v1_0::error_codes::NOT_BOUND,
        s::persona::disclosure::preview::v1_0::error_codes::RENDERER_CANNOT_CARRY,
        s::persona::disclosure::preview::v1_0::error_codes::RENDERER_UNAVAILABLE,
        s::persona::facet::delete::v1_0::error_codes::VERSION_CONFLICT,
        s::persona::facet::list::v1_0::error_codes::INVALID_CURSOR,
        s::persona::facet::put::v1_0::error_codes::FACE_ALREADY_PLACED,
        s::persona::facet::put::v1_0::error_codes::UNRESOLVED_REFERENCE,
        s::persona::facet::put::v1_0::error_codes::VERSION_CONFLICT,
        s::persona::local::binding::set::v1_0::error_codes::NOT_LOCAL_PROFILE,
        s::persona::local::binding::set::v1_0::error_codes::PROFILE_RETIRED,
        s::persona::local::binding::set::v1_0::error_codes::UNTIL_NOT_FUTURE,
        s::persona::local::profile::delete::v1_0::error_codes::BOUND,
        s::persona::local::profile::put::v1_0::error_codes::REFERENCE_NOT_PERMITTED,
        s::persona::profile::compose::v1_0::error_codes::DUPLICATE_SLOT,
        s::persona::profile::compose::v1_0::error_codes::PERSONA_AMBIGUOUS,
        s::persona::profile::compose::v1_0::error_codes::UNTIL_NOT_FUTURE,
        s::persona::profile::delete::v1_0::error_codes::BOUND,
        s::persona::profile::delete::v1_0::error_codes::VERSION_CONFLICT,
        s::persona::profile::get::v1_0::error_codes::NOT_FOUND,
        s::persona::profile::list::v1_0::error_codes::CURSOR_INVALID,
        s::persona::profile::put::v1_0::error_codes::UNRESOLVED_REFERENCE,
        s::persona::profile::put::v1_0::error_codes::VERSION_CONFLICT,
        s::persona::profile::reinstate::v1_0::error_codes::VERSION_CONFLICT,
        s::persona::profile::retire::v1_0::error_codes::VERSION_CONFLICT,
        s::persona::world::delete::v1_0::error_codes::VERSION_CONFLICT,
        s::persona::world::list::v1_0::error_codes::INVALID_CURSOR,
        s::persona::world::put::v1_0::error_codes::FACE_ALREADY_PLACED,
        s::persona::world::put::v1_0::error_codes::UNRESOLVED_REFERENCE,
        s::persona::world::put::v1_0::error_codes::VERSION_CONFLICT,
        s::policy::delete::v0_1::error_codes::NOT_FOUND,
        s::policy::delete::v0_1::error_codes::VERSION_CONFLICT,
        s::policy::delete::v0_1::error_codes::WOULD_ORPHAN_CONTEXTS,
        s::policy::get::v0_1::error_codes::NOT_FOUND,
        s::policy::upsert::v0_2::error_codes::CONTEXT_NOT_FOUND,
        s::policy::upsert::v0_2::error_codes::NOT_FOUND,
        s::policy::upsert::v0_2::error_codes::REGO_INVALID,
        s::policy::upsert::v0_2::error_codes::VERSION_CONFLICT,
        s::provision::integration::v0_3::error_codes::ASSERTION_UNSUPPORTED,
        s::provision::integration::v0_3::error_codes::CONTEXT_NOT_FOUND,
        s::provision::integration::v0_3::error_codes::ENVELOPE_UNSUPPORTED,
        s::provision::integration::v0_3::error_codes::FORBIDDEN,
        s::provision::integration::v0_3::error_codes::INVALID_BOOTSTRAP_REQUEST,
        s::provision::integration::v0_3::error_codes::TEMPLATE_NOT_FOUND,
        s::provision::integration::v0_3::error_codes::TEMPLATE_VARS_INVALID,
        s::rooms::keys::backfill::v0_1::error_codes::NOT_A_MEMBER,
        s::rooms::keys::browse::v0_1::error_codes::HOST_REFUSED,
        s::rooms::keys::browse::v0_1::error_codes::HOST_UNREACHABLE,
        s::rooms::keys::browse::v0_1::error_codes::NOT_A_MEMBER,
        s::rooms::keys::chain::v0_1::error_codes::NOT_A_MEMBER,
        s::rooms::keys::commit::v0_1::error_codes::COMMIT_INVALID,
        s::rooms::keys::commit::v0_1::error_codes::EPOCH_GAP,
        s::rooms::keys::commit::v0_1::error_codes::NOT_A_MEMBER,
        s::rooms::keys::key_package::v0_1::error_codes::NOT_INVITED,
        s::rooms::keys::open::v0_2::error_codes::DID_NOT_OPEN,
        s::rooms::keys::present::v0_2::error_codes::ACTION_NOT_HELD,
        s::rooms::keys::read::v0_1::error_codes::NOT_A_MEMBER,
        s::rooms::keys::welcome::v0_1::error_codes::NOT_INVITED,
        s::rooms::owner::anchor::v0_1::error_codes::HOST_REFUSED,
        s::rooms::owner::anchor::v0_1::error_codes::HOST_UNREACHABLE,
        s::rooms::owner::anchor::v0_1::error_codes::NOT_THE_OWNER,
        s::rooms::owner::anchor::v0_1::error_codes::NOT_WITNESSED,
        s::rooms::owner::invite::v0_1::error_codes::NO_SIGNING_KEY,
        s::rooms::owner::issue_authority::v0_2::error_codes::EMPTY_ACTIONS,
        s::rooms::owner::issue_authority::v0_2::error_codes::NO_SIGNING_KEY,
        s::rooms::owner::issue_membership::v0_1::error_codes::NO_SIGNING_KEY,
        s::task_consent::decision::v0_1::error_codes::CHALLENGE_MISMATCH,
        s::task_consent::decision::v0_1::error_codes::NO_PENDING,
        s::task_consent::decision::v0_1::error_codes::NOT_AN_APPROVER,
        s::task_consent::decision::v0_1::error_codes::REQUESTER_EXCLUDED,
        s::vault::credentials::archive::v0_1::error_codes::NOT_ACTIVE,
        s::vault::credentials::archive::v0_1::error_codes::NOT_FOUND,
        s::vault::credentials::delete::v0_1::error_codes::ALREADY_DELETED,
        s::vault::credentials::delete::v0_1::error_codes::NOT_FOUND,
        s::vault::credentials::get::v0_1::error_codes::NOT_FOUND,
        s::vault::credentials::purge::v0_1::error_codes::NOT_FOUND,
        s::vault::credentials::query::v0_1::error_codes::FILTER_REQUIRED,
        s::vault::credentials::receive::v0_1::error_codes::FORMAT_UNSUPPORTED,
        s::vault::credentials::receive::v0_1::error_codes::VERIFICATION_FAILED,
        s::vault::credentials::restore::v0_1::error_codes::GRACE_EXPIRED,
        s::vault::credentials::restore::v0_1::error_codes::NOT_DELETED,
        s::vault::credentials::restore::v0_1::error_codes::NOT_FOUND,
        s::vault::credentials::unarchive::v0_1::error_codes::NOT_ARCHIVED,
        s::vault::credentials::unarchive::v0_1::error_codes::NOT_FOUND,
        s::vault::delete::v0_1::error_codes::NOT_FOUND,
        s::vault::delete::v0_1::error_codes::VERSION_CONFLICT,
        s::vault::get::v0_1::error_codes::NOT_FOUND,
        s::vault::list::v0_1::error_codes::CONTEXT_NOT_FOUND,
        s::vault::list::v0_1::error_codes::CURSOR_INVALID,
        s::vault::list::v0_1::error_codes::FILTER_CONFLICT,
        s::vault::proxy_login::v0_1::error_codes::CREDENTIAL_REJECTED,
        s::vault::proxy_login::v0_1::error_codes::ENVELOPE_UNSUPPORTED,
        s::vault::proxy_login::v0_1::error_codes::NOT_FOUND,
        s::vault::proxy_login::v0_1::error_codes::NOT_PROXYABLE,
        s::vault::proxy_login::v0_1::error_codes::POLICY_DENY,
        s::vault::proxy_login::v0_1::error_codes::STEP_UP_REQUIRED,
        s::vault::proxy_login::v0_1::error_codes::TARGET_UNREACHABLE,
        s::vault::release::v0_1::error_codes::ENVELOPE_UNSUPPORTED,
        s::vault::release::v0_1::error_codes::NOT_FOUND,
        s::vault::release::v0_1::error_codes::POLICY_DENY,
        s::vault::release::v0_1::error_codes::STEP_UP_REQUIRED,
        s::vault::sign_trust_task::v0_1::error_codes::ENVELOPE_ALREADY_PROOFED,
        s::vault::sign_trust_task::v0_1::error_codes::ENVELOPE_EXPIRED,
        s::vault::sign_trust_task::v0_1::error_codes::ENVELOPE_INVALID,
        s::vault::sign_trust_task::v0_1::error_codes::ENVELOPE_ISSUER_MISMATCH,
        s::vault::sign_trust_task::v0_1::error_codes::NOT_FOUND,
        s::vault::sign_trust_task::v0_1::error_codes::NOT_SIGNABLE,
        s::vault::sign_trust_task::v0_1::error_codes::POLICY_DENY,
        s::vault::sign_trust_task::v0_1::error_codes::STEP_UP_REQUIRED,
        s::vault::upsert::v0_1::error_codes::CONTEXT_CHANGE_FORBIDDEN,
        s::vault::upsert::v0_1::error_codes::CONTEXT_NOT_FOUND,
        s::vault::upsert::v0_1::error_codes::ENVELOPE_UNSUPPORTED,
        s::vault::upsert::v0_1::error_codes::NOT_FOUND,
        s::vault::upsert::v0_1::error_codes::SEALED_SECRET_INVALID,
        s::vault::upsert::v0_1::error_codes::SECRET_REQUIRED,
        s::vault::upsert::v0_1::error_codes::VERSION_CONFLICT,
        s::vta::app_state::delete::v1_0::error_codes::VERSION_CONFLICT,
        s::vta::app_state::get_many::v1_0::error_codes::DUPLICATE_KEY,
        s::vta::app_state::get::v1_0::error_codes::NOT_FOUND,
        s::vta::app_state::list::v1_0::error_codes::CURSOR_INVALID,
        s::vta::app_state::list::v1_0::error_codes::WATERMARK_TOO_OLD,
        s::vta::app_state::put_many::v1_0::error_codes::BATCH_TOO_LARGE,
        s::vta::app_state::put_many::v1_0::error_codes::DUPLICATE_KEY,
        s::vta::app_state::put::v1_0::error_codes::NOT_FOUND,
        s::vta::app_state::put::v1_0::error_codes::VALUE_TOO_LARGE,
        s::vta::app_state::put::v1_0::error_codes::CONTEXT_NOT_FOUND,
        s::vta::backup::abort::v1_0::error_codes::NOT_FOUND,
        s::vta::backup::complete_export::v1_0::error_codes::NOT_FOUND,
        s::vta::backup::complete_export::v1_0::error_codes::TERMINAL_STATE,
        s::vta::backup::finalize_import::v1_1::error_codes::BUNDLE_DIGEST_MISMATCH,
        s::vta::backup::finalize_import::v1_1::error_codes::DECRYPTION_FAILED,
        s::vta::backup::finalize_import::v1_1::error_codes::INCOMPLETE_UPLOAD,
        s::vta::backup::finalize_import::v1_1::error_codes::MALFORMED_BUNDLE,
        s::vta::backup::finalize_import::v1_1::error_codes::NO_BYTES_UPLOADED,
        s::vta::backup::finalize_import::v1_1::error_codes::NOT_FOUND,
        s::vta::backup::finalize_import::v1_1::error_codes::TERMINAL_STATE,
        s::vta::backup::get_chunk::v1_0::error_codes::CHUNK_OUT_OF_RANGE,
        s::vta::backup::get_chunk::v1_0::error_codes::NOT_FOUND,
        s::vta::backup::get_chunk::v1_0::error_codes::TERMINAL_STATE,
        s::vta::backup::initiate_export::v1_1::error_codes::BUNDLE_TOO_LARGE,
        s::vta::backup::initiate_export::v1_1::error_codes::TOO_MANY_OPEN_BUNDLES,
        s::vta::backup::initiate_export::v1_1::error_codes::TRANSPORT_UNAVAILABLE,
        s::vta::backup::initiate_export::v1_1::error_codes::UNSUPPORTED_ALGORITHM,
        s::vta::backup::initiate_export::v1_1::error_codes::WEAK_PASSWORD,
        s::vta::backup::initiate_import::v1_1::error_codes::CHUNK_SIZE_UNACCEPTABLE,
        s::vta::backup::initiate_import::v1_1::error_codes::INVALID_DIGEST,
        s::vta::backup::initiate_import::v1_1::error_codes::INVALID_MANIFEST,
        s::vta::backup::initiate_import::v1_1::error_codes::TOO_MANY_OPEN_BUNDLES,
        s::vta::backup::initiate_import::v1_1::error_codes::TRANSPORT_UNAVAILABLE,
        s::vta::backup::initiate_import::v1_1::error_codes::UNSUPPORTED_ALGORITHM,
        s::vta::backup::put_chunk::v1_0::error_codes::CHUNK_OUT_OF_RANGE,
        s::vta::backup::put_chunk::v1_0::error_codes::CHUNK_SIZE_MISMATCH,
        s::vta::backup::put_chunk::v1_0::error_codes::DIGEST_MISMATCH,
        s::vta::backup::put_chunk::v1_0::error_codes::NOT_FOUND,
        s::vta::backup::put_chunk::v1_0::error_codes::TERMINAL_STATE,
        s::vta::contexts::create::v1_0::error_codes::PARENT_NOT_FOUND,
        s::vta::contexts::delete::v1_0::error_codes::NOT_FOUND,
        s::vta::contexts::get::v1_0::error_codes::NOT_FOUND,
        s::vta::contexts::preview_delete::v1_0::error_codes::NOT_FOUND,
        s::vta::contexts::secrets::v1_0::error_codes::NOT_FOUND,
        s::vta::contexts::secrets::v1_0::error_codes::NOT_RELEASABLE,
        s::vta::contexts::update::v1_0::error_codes::NOT_FOUND,
        s::vta::credentials::issue::v0_2::error_codes::HOLDER_INVALID,
        s::vta::credentials::issue::v0_2::error_codes::PROFILE_VIOLATION,
        s::vta::credentials::issue::v0_2::error_codes::SCOPE_EMPTY,
        s::vta::credentials::issue::v0_2::error_codes::STEP_UP_REQUIRED,
        s::vta::credentials::issue::v0_2::error_codes::VALIDITY_TOO_LONG,
        s::vta::credentials::list::v0_1::error_codes::CURSOR_INVALID,
        s::vta::credentials::revoke::v0_1::error_codes::ALREADY_REVOKED,
        s::vta::credentials::revoke::v0_1::error_codes::NOT_FOUND,
        s::vta::did_templates::create::v3_0::error_codes::CONTEXT_NOT_FOUND,
        s::vta::did_templates::create::v3_0::error_codes::DUPLICATE_NAME,
        s::vta::did_templates::delete::v2_0::error_codes::NOT_FOUND,
        s::vta::did_templates::get::v3_0::error_codes::NOT_FOUND,
        s::vta::did_templates::render::v2_0::error_codes::NOT_FOUND,
        s::vta::did_templates::update::v3_0::error_codes::NOT_FOUND,
        s::vta::management::reload_services::v1_0::error_codes::RELOAD_FAILED,
        s::vta::memory::delete::v0_1::error_codes::CONTEXT_FORBIDDEN,
        s::vta::memory::delete::v0_1::error_codes::NOT_FOUND,
        s::vta::memory::list::v0_1::error_codes::CONTEXT_FORBIDDEN,
        s::vta::memory::put::v0_1::error_codes::CONTEXT_FORBIDDEN,
        s::vta::memory::put::v0_1::error_codes::VALUE_TOO_LARGE,
        s::vta::passkey_vms::enroll_challenge::v0_1::error_codes::DID_NOT_FOUND,
        s::vta::passkey_vms::revoke::v0_1::error_codes::DID_NOT_FOUND,
        s::vta::pcs::applications::create::v0_1::error_codes::PARAMETERS_INVALID,
        s::vta::pcs::applications::create::v0_1::error_codes::UNSUPPORTED_SUITE,
        s::vta::pcs::attest::v0_1::error_codes::APPLICANT_INVALID,
        s::vta::pcs::attest::v0_1::error_codes::COMMUNITY_MISMATCH,
        s::vta::pcs::attest::v0_1::error_codes::NO_TOKEN,
        s::vta::pcs::attest::v0_1::error_codes::NOT_ENROLLED,
        s::vta::pcs::attest::v0_1::error_codes::NOT_FOUND,
        s::vta::pcs::attest::v0_1::error_codes::PARAMETERS_INVALID,
        s::vta::pcs::prove::v0_1::error_codes::NOT_FOUND,
        s::vta::pcs::prove::v0_1::error_codes::PARAMETERS_INVALID,
        s::vta::pcs::prove::v0_1::error_codes::UNSUPPORTED_SUITE,
        s::vta::pcs::root_accept::v0_1::error_codes::CREDENTIAL_INVALID,
        s::vta::pcs::root_accept::v0_1::error_codes::NO_REQUEST_IN_FLIGHT,
        s::vta::pcs::root_accept::v0_1::error_codes::NOT_FOUND,
        s::vta::pcs::root_accept::v0_1::error_codes::PARAMETERS_INVALID,
        s::vta::pcs::root_accept::v0_1::error_codes::UNSUPPORTED_SUITE,
        s::vta::pcs::root_request::v0_1::error_codes::LABEL_NOT_LIVE,
        s::vta::pcs::root_request::v0_1::error_codes::PARAMETERS_INVALID,
        s::vta::pcs::root_request::v0_1::error_codes::UNSUPPORTED_SUITE,
        s::vta::pcs::tokens::abandon::v0_1::error_codes::NOT_FOUND,
        s::vta::pcs::tokens::accept::v0_1::error_codes::NO_DRAW_IN_FLIGHT,
        s::vta::pcs::tokens::accept::v0_1::error_codes::NOT_FOUND,
        s::vta::pcs::tokens::accept::v0_1::error_codes::PARAMETERS_INVALID,
        s::vta::pcs::tokens::accept::v0_1::error_codes::TOKENS_INVALID,
        s::vta::pcs::tokens::accept::v0_1::error_codes::UNSUPPORTED_SUITE,
        s::vta::pcs::tokens::request::v0_1::error_codes::LABEL_NOT_LIVE,
        s::vta::pcs::tokens::request::v0_1::error_codes::NOT_FOUND,
        s::vta::pcs::tokens::request::v0_1::error_codes::PARAMETERS_INVALID,
        s::vta::pcs::tokens::request::v0_1::error_codes::UNSUPPORTED_SUITE,
        s::vta::pcs::verify_attestation::v0_1::error_codes::ATTESTATION_INVALID,
        s::vta::pcs::verify_attestation::v0_1::error_codes::NOT_FOUND,
        s::vta::pcs::verify_attestation::v0_1::error_codes::PARAMETERS_INVALID,
        s::vta::pcs::verify_attestation::v0_1::error_codes::UNSUPPORTED_SUITE,
        // Declared for an engine that does not serve every level's cast task. This one
        // serves `vta/pcs/vote` and `vta/pcs/vote-encrypted`, so every level registers and
        // the code cannot occur here (trust-tasks-tf #845).
        s::vta::pcs::voter::register::v0_1::error_codes::UNSUPPORTED_SECRECY,
        s::vta::services::disable::v1_0::error_codes::NOT_AUTHORIZED,
        s::vta::services::disable::v1_0::error_codes::NOT_FOUND,
        s::vta::services::drain::cancel::v1_0::error_codes::CONFLICT,
        s::vta::services::drain::cancel::v1_0::error_codes::NOT_AUTHORIZED,
        s::vta::services::drain::cancel::v1_0::error_codes::NOT_FOUND,
        s::vta::services::enable::v1_0::error_codes::CONFLICT,
        s::vta::services::enable::v1_0::error_codes::NOT_AUTHORIZED,
        s::vta::services::enable::v1_0::error_codes::VALIDATION_FAILED,
        s::vta::services::get::v1_0::error_codes::NOT_FOUND,
        s::vta::services::report::v0_1::error_codes::INVALID_WINDOW,
        s::vta::services::rollback::v1_1::error_codes::CONFLICT,
        s::vta::services::rollback::v1_1::error_codes::NOT_AUTHORIZED,
        s::vta::services::rollback::v1_1::error_codes::NOT_FOUND,
        s::vta::services::update::v1_1::error_codes::NOT_AUTHORIZED,
        s::vta::services::update::v1_1::error_codes::NOT_FOUND,
        s::vta::services::update::v1_1::error_codes::VALIDATION_FAILED,
        s::vta::webvh::agent_name::disable::v1_0::error_codes::NOT_FOUND,
        s::vta::webvh::agent_name::enable::v1_0::error_codes::NOT_FOUND,
        s::vta::webvh::agent_name::list::v1_0::error_codes::NOT_FOUND,
        s::vta::webvh::agent_name::remove::v1_0::error_codes::NOT_FOUND,
        s::vta::webvh::agent_name::set::v1_0::error_codes::NOT_FOUND,
        s::vta::webvh::dids::create::v1_1::error_codes::PATH_TAKEN,
        s::vta::webvh::dids::create::v1_1::error_codes::TEMPLATE_NOT_FOUND,
        s::vta::webvh::dids::delete::v1_0::error_codes::NOT_FOUND,
        s::vta::webvh::dids::get::v1_0::error_codes::NOT_FOUND,
        s::vta::webvh::dids::realign_keys::v1_0::error_codes::CONFLICT,
        s::vta::webvh::dids::realign_keys::v1_0::error_codes::NOT_FOUND,
        s::vta::webvh::dids::register_with_server::v1_0::error_codes::LOCATION_TAKEN,
        s::vta::webvh::dids::rotate_keys::v1_0::error_codes::NOT_FOUND,
        s::vta::webvh::dids::update::v1_0::error_codes::INVALID_DOCUMENT,
        s::vta::webvh::dids::update::v1_0::error_codes::NOT_FOUND,
        s::vta::webvh::dids::update::v1_0::error_codes::VERSION_CONFLICT,
        s::vta::webvh::servers::reconcile::v0_1::error_codes::LISTING_UNAVAILABLE,
        s::vta::webvh::servers::remove::v1_0::error_codes::NOT_FOUND,
        s::vta::webvh::servers::retire_orphan::v0_1::error_codes::DID_MISMATCH,
        s::vta::webvh::servers::retire_orphan::v0_1::error_codes::LISTING_UNAVAILABLE,
        s::vta::webvh::servers::retire_orphan::v0_1::error_codes::NOT_ORPHANED,
        s::vta::witness::open::v0_2::error_codes::WITNESS_UNRESOLVABLE,
        s::vta::witness::present::v0_2::error_codes::NOT_FOUND,
        // Dispatched only when a workspace build unifies features in; a
        // `-p vta-service` run skips these rows (out of scope there).
        s::vta::attestation::config_report::v0_1::error_codes::EVIDENCE_UNAVAILABLE,
        s::vta::attestation::config_report::v0_1::error_codes::NOT_ATTESTED,
        s::vta::attestation::mnemonic_status::v0_1::error_codes::NOT_AVAILABLE,
        s::vta::attestation::report::v0_1::error_codes::EVIDENCE_UNAVAILABLE,
        s::vta::attestation::report::v0_1::error_codes::NOT_ATTESTED,
        s::vta::attestation::status::v0_1::error_codes::NOT_ATTESTED,
        // BASELINE-END
    ]
}

/// The ceiling [`unwitnessed`]'s length may never exceed — a ratchet, not a
/// count. Only *growing* the baseline past it needs an edit, which always
/// wants a human decision.
const UNWITNESSED_CEILING: usize = 373;

/// Every declared code in scope, keyed by code, with the URI declaring it.
fn declared_in_scope() -> BTreeMap<&'static str, (&'static str, DeclaredErrorCode)> {
    let mut out = BTreeMap::new();
    for uri in resolved_uris() {
        let codes = error_codes_for(uri).unwrap_or_else(|| {
            panic!(
                "{uri} resolves in schema_for but not in error_codes_for — the two \
                 indexes are generated from one loop and must agree"
            )
        });
        for declared in codes {
            out.insert(declared.code, (uri, *declared));
        }
    }
    out
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The test code of this crate: every file under `tests/`, every `*_tests.rs`,
/// and the part of any other `src/` file from its first `#[cfg(test)]` on.
fn test_sources() -> Vec<(PathBuf, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    rust_files(&root.join("tests"), &mut files);
    let tests_dir = root.join("tests");
    files
        .into_iter()
        .filter_map(|path| {
            let text = std::fs::read_to_string(&path).ok()?;
            let whole = path.starts_with(&tests_dir)
                || path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with("_tests.rs"));
            if whole {
                return Some((path, text));
            }
            let start = text.find("#[cfg(test)]")?;
            Some((path, text[start..].to_string()))
        })
        .collect()
}

/// What the tests assert on.
#[derive(Default)]
struct Asserted {
    /// Every string literal on an `assert` line or within the four lines below
    /// one (a multi-line `assert_eq!`).
    literals: BTreeSet<String>,
    /// Every `…::error_codes::IDENT` path in the same window, as written.
    constant_paths: Vec<String>,
}

impl Asserted {
    /// Whether `declared` (from `uri`) is asserted, by literal or by a path to
    /// its generated constant that names at least its task and version.
    fn covers(&self, uri: &str, declared: &DeclaredErrorCode) -> bool {
        if self.literals.contains(declared.code) {
            return true;
        }
        // Compared from the end, so a test's `use … as ext` alias still
        // matches; the task, its version, `error_codes` and the identifier
        // must all agree, which no other task's constant does.
        let full = constant_path(uri, declared);
        self.constant_paths.iter().any(|written| {
            full.rsplit("::")
                .zip(written.rsplit("::"))
                .take_while(|(a, b)| a == b)
                .count()
                >= 4
        })
    }
}

/// `module::path::vX_Y::error_codes::IDENT` for a declared code.
fn constant_path(uri: &str, declared: &DeclaredErrorCode) -> String {
    baseline_row(uri, declared)
        .trim_start_matches("s::")
        .trim_end_matches(',')
        .to_string()
}

fn asserted(sources: &[(PathBuf, String)]) -> Asserted {
    let mut out = Asserted::default();
    for (path, text) in sources {
        if path.ends_with("error_code_census.rs") {
            continue;
        }
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let near_assert = lines[i.saturating_sub(4)..=i]
                .iter()
                .any(|l| l.contains("assert"));
            if !near_assert {
                continue;
            }
            for (j, part) in line.split('"').enumerate() {
                if j % 2 == 1 {
                    out.literals.insert(part.to_string());
                }
            }
            let mut rest = *line;
            while let Some(at) = rest.find("::error_codes::") {
                let start = rest[..at]
                    .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
                    .map_or(0, |i| i + 1);
                let after = &rest[at + "::error_codes::".len()..];
                let end = after
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(after.len());
                out.constant_paths.push(format!(
                    "{}::error_codes::{}",
                    rest[start..at].trim_start_matches("trust_tasks_rs::specs::"),
                    &after[..end]
                ));
                rest = &after[end..];
            }
        }
    }
    out
}

/// The ready-to-paste baseline row for a declared code.
fn baseline_row(uri: &str, declared: &DeclaredErrorCode) -> String {
    let tail = uri
        .strip_prefix("https://trusttasks.org/spec/")
        .unwrap_or(uri);
    let (slug, version) = tail.rsplit_once('/').unwrap_or((tail, ""));
    let module = slug.replace('-', "_").replace('/', "::");
    let version = format!("v{}", version.replace('.', "_"));
    let mut ident = String::new();
    for (i, c) in declared.local().chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            ident.push('_');
        }
        ident.push(c.to_ascii_uppercase());
    }
    format!("s::{module}::{version}::error_codes::{ident},")
}

#[test]
fn every_declared_error_code_is_witnessed_or_baselined() {
    let declared = declared_in_scope();
    assert!(
        !declared.is_empty(),
        "no dispatched, published task declares an error code — the census is \
         broken, not the code"
    );

    let asserted = asserted(&test_sources());
    let witnessed: BTreeSet<&'static str> = declared
        .iter()
        .filter(|(_, (uri, d))| asserted.covers(uri, d))
        .map(|(code, _)| *code)
        .collect();

    let baseline = unwitnessed();
    let mut baselined: BTreeSet<&'static str> = BTreeSet::new();
    for b in &baseline {
        // Out of scope is not stale: the dispatched set depends on features,
        // and a workspace run unifies more of them than `-p vta-service` does
        // (the attestation tasks are dispatched only under the first). A row
        // whose code no specification declares any more is a compile error
        // (typed paths), so nothing is lost by skipping it here.
        if !declared.contains_key(b.code) {
            continue;
        }
        assert!(
            !witnessed.contains(b.code),
            "{} is witnessed AND baselined — remove it from the baseline; that is the \
             baseline shrinking, which is the point",
            b.code
        );
        assert!(baselined.insert(b.code), "{} baselined twice", b.code);
    }

    let missing: Vec<String> = declared
        .iter()
        .filter(|(code, _)| !witnessed.contains(*code) && !baselined.contains(*code))
        .map(|(code, (uri, d))| format!("{code}  ({uri})\n      {}", baseline_row(uri, d)))
        .collect();
    assert!(
        missing.is_empty(),
        "these declared error codes have no test asserting them and are not baselined:\n  \
         {}\n\nWrite a test that drives the service into each and asserts the full code \
         string. Baselining is for codes that predate this census, not for new tasks.",
        missing.join("\n  ")
    );

    assert!(
        baseline.len() <= UNWITNESSED_CEILING,
        "the unwitnessed baseline grew past its ceiling ({} > {UNWITNESSED_CEILING}) — a \
         dispatched task declares codes nothing shows this service emitting. Witness them, \
         or — only if that is truly not yet possible — raise UNWITNESSED_CEILING with a reason.",
        baseline.len()
    );
    if baseline.len() < UNWITNESSED_CEILING {
        eprintln!(
            "error-code census: the unwitnessed baseline ({}) is below its ceiling \
             (UNWITNESSED_CEILING = {UNWITNESSED_CEILING}) — lower the ceiling to lock in \
             the improvement",
            baseline.len()
        );
    }
    eprintln!(
        "error-code census: {} declared in scope, {} witnessed, {} baselined",
        declared.len(),
        witnessed.len(),
        baseline.len()
    );
}
