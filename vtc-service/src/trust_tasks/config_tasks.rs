//! The community's configuration verbs: profile update, the portable
//! configuration pair, DID hosting, endorsement types and the backup export.
//!
//! Moved out of `trust_tasks/mod.rs` (#2579); the spine glue and the router
//! stay there.

use super::routing::{Routes, on};
use super::*;

/// Register every task this family serves (#2579).
pub(super) fn register(routes: Routes) -> Routes {
    let routes = on!(routes, vti_specs::vtc::community::profile::update::v0_1::Payload => handle_community_profile_update);
    let routes = on!(routes, vti_specs::vtc::config::export::v0_1::Payload => handle_config_export);
    let routes = on!(routes, vti_specs::vtc::config::did_hosting::list::v0_1::Payload => handle_did_hosting_list);
    let routes = on!(routes, vti_specs::vtc::config::import::v0_1::Payload => handle_config_import);
    let routes = on!(routes, vti_specs::vtc::endorsement_types::register::v0_1::Payload => handle_endorsement_type_register);
    let routes = on!(routes, vti_specs::vtc::endorsement_types::delete::v0_1::Payload => handle_endorsement_type_delete);
    on!(routes, vti_specs::vtc::backup::export::v0_1::Payload => handle_backup_export)
}

/// `vtc/community/profile/update/0.1` — edit the community's public profile.
///
/// Administrator only, from the signer's ACL entry — `AdminAuth`'s question,
/// and the only one the REST route asks.
///
/// # Why the payload is read twice
///
/// The same reason `members/update` reads it twice. The generated `Payload`
/// types `extensions` as a map with `default`, so once parsed an **absent**
/// bag and an empty one are the same value — and this task's rule is that
/// absent leaves the field unchanged while a supplied value replaces it.
/// Mapping the generated type straight through would clear the community's
/// extensions on every update that did not mention them. The route's own
/// `CommunityProfileUpdate` types it `Option<Value>` and keeps the
/// distinction. The generated parse still runs, and runs first, because it is
/// what validates the document against its published schema.
///
/// The nullable members (`logoUrl`, `publicUrl`, `contactEmail`) are a
/// *different* case and the double read does not rescue them: the published
/// task says an explicit `null` clears them, and
/// `CommunityProfileUpdate`'s `Option<Option<String>>` has no double-option
/// deserializer, so serde folds `null` onto the outer `None` and the operation
/// reads it as "unchanged". That is the store's behaviour, identical on the
/// bearer route, and it is pinned by
/// `an_explicit_null_does_not_yet_clear_a_nullable_member` rather than left
/// for a client to find.
pub(super) async fn handle_community_profile_update(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor =
        match capable_signer(state, ctx, &doc, crate::acl::Capability::SurfaceAdmin, None).await {
            Ok(a) => a,
            Err(reject) => return reject,
        };
    let _checked: community_profile_update::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let update: crate::community::CommunityProfileUpdate = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::community::ops::profile::update_profile_inner(state, &actor.did, update).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

// ─── the portable-configuration pair (#1641 phase 2, batch 3) ────────────

/// `vtc/config/export/0.1` — the community's portable configuration.
///
/// Administrator only, from the signer's ACL entry — the `AdminAuth` question
/// the removed bearer route asked, and the only one. A read, but not a
/// harmless one: the document carries every db-layer config override and the
/// full community profile, which is why the task declares a proof. As on the
/// removed route, it writes no audit row.
///
/// # This is the task's only binding
///
/// Unlike batches 1 and 2, the pair's bearer routes were removed in the same
/// change rather than kept as transitional paths. Nothing called them: the
/// admin console has no screen for either (`vtc-console-signing.md` §7), and
/// neither `vtc-client`, `cnm` nor openvtc reaches them.
pub(super) async fn handle_config_export(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // The gate the console's live `config` topic shares (`admin_events`).
    let cap = crate::admin_events::read_capability(crate::admin_events::Topic::Config)
        .unwrap_or(crate::acl::Capability::ConfigAdmin);
    if let Err(reject) = capable_signer(state, ctx, &doc, cap, None).await {
        return reject;
    }
    let _checked: config_export::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::community::ops::config::export_inner(state).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `vtc/config/did-hosting/list/0.1` — the `did:webvh` hosting servers the
/// community's VTA reports (`vta/webvh/servers/list`), asked as the community
/// over the link it keeps, for choosing `dids.webvh_server`
/// ([`crate::did_hosting`]). `vtc.config.admin`. Each server's id, DID and
/// label only, and one whose id the configuration could not name is left out
/// (item 2).
pub(super) async fn handle_did_hosting_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) =
        capable_signer(state, ctx, &doc, crate::acl::Capability::ConfigAdmin, None).await
    {
        return reject;
    }
    if let Err(reject) = parse_spec_payload::<did_hosting_list::Payload>(&doc) {
        return reject;
    }
    let Some(holder) = state.community_rooms.key_holder() else {
        return reject_with_code(
            &doc,
            extended_code(DID_HOSTING_ERR_NO_KEY_HOLDER),
            "this community has no link to a VTA: its identities can only be served here",
            None,
        );
    };
    let answer = holder
        .ask(
            vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_LIST_1_0,
            serde_json::json!({}),
            crate::rooms::community::SIGN_TIMEOUT,
        )
        .await;
    let answer = match answer {
        Ok(a) => a,
        Err(crate::rooms::community::HolderError::Unavailable(why)) => {
            return reject_with_code(
                &doc,
                extended_code(DID_HOSTING_ERR_KEY_HOLDER_UNAVAILABLE),
                format!("the community's VTA did not answer: {why}"),
                None,
            );
        }
        Err(crate::rooms::community::HolderError::Refused { code, message }) => {
            return reject_with_code(
                &doc,
                extended_code(DID_HOSTING_ERR_KEY_HOLDER_REFUSED),
                format!("the community's VTA refused: {code} {message}"),
                Some(crate::rooms::community::HolderError::refused_details(
                    &code, &message,
                )),
            );
        }
    };
    let servers: Vec<Value> = answer
        .get("servers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|s| {
            let id = s.get("id")?.as_str()?;
            crate::did_hosting::validate(&Value::String(id.to_string())).ok()?;
            if id == crate::did_hosting::LOCAL {
                return None;
            }
            let mut out = serde_json::json!({ "id": id, "did": s.get("did")?.as_str()? });
            if let Some(label) = s.get("label").and_then(Value::as_str) {
                out["label"] = Value::String(label.chars().take(256).collect());
            }
            Some(out)
        })
        .take(256)
        .collect();
    success_response(&doc, serde_json::json!({ "servers": servers }))
}

/// `vtc/config/import/0.1` — preview (`confirm: false`, the default) or apply
/// a portable configuration.
///
/// An **unrestricted** administrator only, from the signer's ACL entry. The
/// removed bearer route asked only `AdminAuth`, but an import writes the same
/// community-wide overrides `config/patch` does — the unrestricted-admin
/// consent threshold among them — so it takes what `config/patch` takes, or a
/// context admin could reach through the import what the patch refuses it. The
/// audit rows name the signer. This is the task's only binding; see
/// [`handle_config_export`].
///
/// # Why the payload is read twice
///
/// The generated parse runs first because it is what validates the document
/// against its published schema. The operation then reads the payload as
/// `ImportRequest`, the type the import has always diffed from, rather than
/// mapping the generated `CommunityProfileSnapshot` across member by member:
/// the diff compares the incoming profile with the stored `CommunityProfile`,
/// and building that from the JSON with the stored type's own deserializer is
/// what keeps an unchanged profile reading as unchanged.
///
/// # Size
///
/// This door caps a document at 64 KiB where the removed route allowed 1 MB.
/// The payload is a community profile plus at most five small config
/// overrides, and the profile is the one §6b of the design note measured for
/// `community/profile/update`, at about 44 KiB at the worst encoding. So any
/// import whose profile is within those caps fits, and the cap refuses with
/// 413 rather than truncating.
pub(super) async fn handle_config_import(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor =
        match capable_signer(state, ctx, &doc, crate::acl::Capability::ConfigAdmin, None).await {
            Ok(a) => a,
            Err(reject) => return reject,
        };
    let _checked: config_import::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let request: crate::community::ops::config::ImportRequest = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    // VTI-APV-020: an applied import that lowers the consent threshold takes
    // the gesture and the consent of the threshold as it stands, as
    // `config/patch` does. A preview writes nothing and asks nothing, and a
    // document the import refuses outright asks for no gesture.
    if request.confirm
        && request.document.schema_version == crate::community::ops::config::EXPORT_SCHEMA_VERSION
    {
        // VTI-CMP-090: an import that changes the trusted-witness list takes
        // the gesture and the consent `config/patch` does.
        if let Err(refusal) = acl_tasks::settle_witness_list_gate(
            state,
            &actor,
            &doc,
            &request.document.config_overrides,
            ", by configuration import",
        )
        .await
        {
            return refusal;
        }
        match crate::community::ops::config::lowered_threshold(
            state,
            &request.document.config_overrides,
        )
        .await
        {
            Ok(None) => {}
            Ok(Some((from, to))) => {
                if let Err(refusal) = acl_tasks::settle_consent_gate(
                    state,
                    &actor,
                    &doc,
                    crate::acl::admin_consent::Act::LowerThreshold,
                    crate::config_store::UNRESTRICTED_ADMIN_CONSENT_THRESHOLD,
                    &format!(
                        "Import a configuration that lowers the unrestricted-admin consent \
                         threshold from {from} to {to}"
                    ),
                    &format!(
                        "Lower the number of administrators who must consent to a new \
                         unrestricted administrator from {from} to {to}, by configuration import"
                    ),
                )
                .await
                {
                    return refusal;
                }
            }
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    }
    match crate::community::ops::config::import_inner(state, &actor.did, request).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

// ─── the endorsement-type writes (#1641 phase 2, batch 4) ────────────────

/// `vtc/endorsement-types/register/0.1` — register an endorsement type.
///
/// Administrator only, from the signer's ACL entry — `AdminAuth`'s question,
/// and the only one the REST route asks. `createdByDid` and the audit row name
/// the signer.
///
/// # Why the payload is read twice
///
/// The generated parse runs first because it is what validates the document
/// against its published schema. The operation then reads the payload as the
/// route's `RegisterBody`, because the generated type folds an **absent**
/// `claimSchema` and an empty one into the same default map, and the stored
/// row keeps them apart. Issuance treats the two alike — `{}` admits any
/// claim — but a listing shows which one the operator registered, and the
/// bearer route stores what it was sent, so this door does too.
///
/// # Size
///
/// `claimSchema` is operator-authored and the task publishes no bound for it,
/// so the operation caps it at 32 KiB serialised on both doors
/// (`CLAIM_SCHEMA_MAX_BYTES`). With `typeUri` ≤ 512 and `description` ≤ 1024
/// characters, every registration that passes fits this door's 64 KiB cap.
pub(super) async fn handle_endorsement_type_register(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor =
        match capable_signer(state, ctx, &doc, crate::acl::Capability::SurfaceAdmin, None).await {
            Ok(a) => a,
            Err(reject) => return reject,
        };
    let _checked: endorsement_type_register::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let body: crate::endorsement_types::ops::RegisterBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::endorsement_types::ops::register_inner(state, &actor.did, body).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `vtc/endorsement-types/delete/0.1` — delete an endorsement type nothing
/// references.
///
/// Administrator only, from the signer's ACL entry — `AdminAuth`'s question,
/// and the only one the REST route asks. The REST route takes the type URI as
/// a path segment; here it is the payload's `typeUri`, and both reach the same
/// `delete_inner`, so the `notFound` / `inUse` refusals are the same codes on
/// each.
pub(super) async fn handle_endorsement_type_delete(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor =
        match capable_signer(state, ctx, &doc, crate::acl::Capability::SurfaceAdmin, None).await {
            Ok(a) => a,
            Err(reject) => return reject,
        };
    let checked: endorsement_type_delete::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::endorsement_types::ops::delete_inner(
        state,
        &actor.did,
        checked.type_uri.to_string(),
    )
    .await
    {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

// ─── the backup export (#1641 phase 2, batch 5) ──────────────────────────

/// `vtc/backup/export/0.1` — an encrypted full-state backup.
///
/// **Super-admin only**, like `members/purge`: the bearer route demanded
/// `SuperAdminAuth`, so the signer's ACL entry must be an unrestricted admin
/// (`require_super_admin`), not merely an admin — a context-scoped admin is
/// refused here exactly as there. The audit row names the signer.
///
/// # The password in the document
///
/// The export password rides in the payload, so it is in a document that is
/// signed but not encrypted. That is no worse than the bearer route's body:
/// the REST binding is TLS, DIDComm and TSP encrypt end to end, and the spine
/// records a document's identifier and digest — never its payload. The digest
/// is over a document carrying a fresh `id` and `issuedAt`, so it is no oracle
/// for the password.
///
/// # The reply is recorded in full
///
/// The spine records a successful reply against the document's `id`, so a
/// redelivery is answered with the same envelope rather than a second export
/// under a fresh salt and nonce. That keeps a second, password-encrypted copy
/// of the backup in `accepted_ids` for the acceptance window. The keyspace is
/// excluded from backup, so a copy never ends up inside a later export.
///
/// Only the export moved. `vtc/backup/import/0.1` carries the whole envelope in
/// its request, which a 64 KiB document cannot hold; it is not served, and the
/// chunked `backup/*` family ([`backup_tasks`]) is the restore — §6b of the
/// design note.
pub(super) async fn handle_backup_export(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor =
        match capable_signer(state, ctx, &doc, crate::acl::Capability::BackupExport, None).await {
            Ok(a) => a,
            Err(reject) => return reject,
        };
    if let Err(reject) = refuse_hop_by_hop_backup(ctx, &doc, "export") {
        return reject;
    }
    let checked: backup_export::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::backup::ops::export_inner(
        state,
        &actor.did,
        checked.password.as_str(),
        checked.include_audit,
    )
    .await
    {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// Refuse a backup export or import that arrived over the REST binding.
///
/// The export and `finalize-import` carry the password that opens a complete
/// copy of the community, and the export's reply (or `initiate-export`'s
/// manifest) is the bundle it opens. Over REST both exist in plaintext
/// wherever TLS terminates. So these tasks are served only over a channel
/// confidential end-to-end between the administrator and this VTC: DIDComm or
/// TSP (the backup family's Channel requirement,
/// trustoverip/dtgwg-trust-tasks-tf#646). Checked after the super-admin check
/// and before any state is serialized, a slot is opened or a key is derived.
/// The chunks themselves are ciphertext and are not affected.
pub(super) fn refuse_hop_by_hop_backup(
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
    what: &str,
) -> Result<(), TrustTaskOutcome> {
    match ctx.transport {
        JoinTransport::DIDComm | JoinTransport::Tsp => Ok(()),
        JoinTransport::Rest => Err(app_error_to_reject(
            doc,
            &AppError::Forbidden(format!(
                "a backup {what} is refused over REST: the backup password and the bundle \
                 would exist in plaintext wherever TLS terminates. Send it over DIDComm or TSP"
            )),
        )),
    }
}

/// The portable-configuration pair, served as signed Trust Task documents —
/// **#1641 phase 2, batch 3**.
///
/// `vtc/config/export/0.1` and `vtc/config/import/0.1` both declare `proof`
/// REQUIRED and were served only as flat-payload REST behind a bearer JWT.
/// They are now bound here as well, on batches 1 and 2's terms.
///
/// What these tests hold, and why:
///
/// - **The gate each bearer route applied must still refuse what it refused.**
///   Both routes apply exactly `AdminAuth` — no super-admin bar, no context
///   scoping — so a member is refused and a context-scoped admin is not.
/// - **A preview writes nothing.** `confirm` defaults to `false`, and the safe
///   direction of that default is the whole point of it; a door that applied
///   on a preview would overwrite a live community's configuration.
/// - **An exported document imports as a no-op.** The pair exists to move a
///   configuration between hosts, so what one verb emits the other must read
///   back unchanged.
/// - **The published `ext` members are accepted.** The route's hand-written
///   types refused them under `deny_unknown_fields`, which the generated
///   schema permits; a schema-valid document refused as malformed is the
///   divergence this batch closed on both doors.
#[cfg(test)]
mod config_pair_tests {
    use super::*;
    use crate::acl::VtcRole;
    use crate::community::ops::config::{
        IMPORT_ERR_COMMUNITY_DID_MISMATCH, IMPORT_ERR_UNSUPPORTED_SCHEMA_VERSION, export_inner,
    };
    use crate::community::{CommunityProfile, load_profile, store_profile};
    use crate::config_store::ConfigStore;
    use crate::test_support::{TEST_VTC_DID, TestVtc};
    use crate::trust_tasks::test_fixtures::{
        assert_conforms, dispatch, error_code, payload_of, seed_acl, signed, unsigned,
    };
    use serde_json::json;
    use vti_rooms_dtg::test_support::Party;

    struct Fixture {
        vtc: TestVtc,
        /// `VtcRole::Admin`, unrestricted.
        admin: Party,
        /// `VtcRole::Admin` scoped to one context — still an administrator,
        /// and neither verb asks the super-admin question.
        scoped_admin: Party,
        /// `VtcRole::Member` — authenticated, authorized for none of this.
        member: Party,
    }

    async fn fixture() -> Fixture {
        // `with_audit` because an applied import refuses rather than acts when
        // it cannot record what it changed; `with_signers` because the spine
        // signs its replies.
        let vtc = TestVtc::builder()
            .with_audit(true)
            .with_signers(true)
            .build()
            .await;
        store_profile(
            &vtc.state.community_ks,
            &CommunityProfile::new(TEST_VTC_DID, "Example Community"),
        )
        .await
        .expect("seed the community profile");

        let admin = Party::new();
        let scoped_admin = Party::new();
        let member = Party::new();
        seed_acl(&vtc, &admin.did, VtcRole::Admin, vec![]).await;
        seed_acl(
            &vtc,
            &scoped_admin.did,
            VtcRole::Admin,
            vec!["ctx-a".to_string()],
        )
        .await;
        seed_acl(&vtc, &member.did, VtcRole::Member, vec![]).await;

        Fixture {
            vtc,
            admin,
            scoped_admin,
            member,
        }
    }

    /// This community's own export, renamed and carrying one override — a
    /// document that differs from what is stored in exactly two places.
    async fn changed_document(vtc: &TestVtc) -> Value {
        let mut document = serde_json::to_value(
            export_inner(&vtc.state)
                .await
                .expect("export the seeded community")
                .document,
        )
        .expect("the document serialises");
        document["communityProfile"]["name"] = json!("Imported Community");
        document["configOverrides"] = json!({ "log.level": "debug" });
        document
    }

    async fn stored_name(vtc: &TestVtc) -> String {
        load_profile(&vtc.state.community_ks)
            .await
            .expect("read profile")
            .expect("row")
            .name
    }

    async fn stored_log_level(vtc: &TestVtc) -> Option<Value> {
        ConfigStore::new(vtc.state.config_ks.clone())
            .get("log.level")
            .await
            .expect("read override")
    }

    // ─── the premise ─────────────────────────────────────────────────────

    /// If the registry ever relaxed one of these declarations, every test
    /// below would be asserting nothing. This one says so first.
    #[test]
    fn every_moved_task_declares_the_proof_these_tests_assume() {
        for uri in [CONFIG_EXPORT_TYPE, CONFIG_IMPORT_TYPE] {
            let policy = vti_specs::schema_index::spec_policy_for(uri)
                .unwrap_or_else(|| panic!("{uri} has no published spec policy"));
            assert!(
                policy.is_proof_required,
                "{uri} no longer declares proof REQUIRED — these tests now assert \
                 nothing, and the design note should be re-read"
            );
        }
    }

    // ─── VTI-OPS-020: a proof by the issuer, authorized from their ACL ────

    /// **VTI-OPS-020.** A signed admin document exports the configuration,
    /// and the reply conforms to the published `#response`.
    #[tokio::test]
    async fn vti_ops_020_a_signed_admin_document_exports_the_configuration() {
        let fix = fixture().await;
        ConfigStore::new(fix.vtc.state.config_ks.clone())
            .put("log.level", &json!("warn"))
            .await
            .expect("seed an override");

        let doc = signed(&fix.admin, CONFIG_EXPORT_TYPE, json!({})).await;
        let out = dispatch(&fix.vtc, &doc).await;

        assert!(
            out.status.is_success(),
            "a signed admin document must be accepted: {}",
            String::from_utf8_lossy(&out.body)
        );
        let document = &payload_of(&out)["document"];
        assert_eq!(document["communityProfile"]["name"], "Example Community");
        assert_eq!(document["configOverrides"]["log.level"], "warn");
        assert_conforms::<config_export::Response>(&out);
    }

    /// **VTI-OPS-020.** A signed import without `confirm` is a preview: it
    /// reports the change and writes nothing.
    #[tokio::test]
    async fn vti_ops_020_a_signed_import_previews_by_default_and_writes_nothing() {
        let fix = fixture().await;
        let document = changed_document(&fix.vtc).await;

        let doc = signed(
            &fix.admin,
            CONFIG_IMPORT_TYPE,
            json!({ "document": document }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;

        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        let payload = payload_of(&out);
        assert_eq!(payload["status"], "preview");
        assert_eq!(payload["profileChanges"][0]["key"], "name");
        assert_eq!(payload["overrideChanges"][0]["key"], "log.level");
        assert_conforms::<config_import::Response>(&out);

        assert_eq!(stored_name(&fix.vtc).await, "Example Community");
        assert_eq!(stored_log_level(&fix.vtc).await, None);
    }

    /// **VTI-OPS-020.** With `confirm: true` the same document is applied.
    #[tokio::test]
    async fn vti_ops_020_a_confirmed_signed_import_applies_the_document() {
        let fix = fixture().await;
        let document = changed_document(&fix.vtc).await;

        let doc = signed(
            &fix.admin,
            CONFIG_IMPORT_TYPE,
            json!({ "document": document, "confirm": true }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;

        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        assert_eq!(payload_of(&out)["status"], "imported");
        assert_conforms::<config_import::Response>(&out);

        assert_eq!(stored_name(&fix.vtc).await, "Imported Community");
        assert_eq!(stored_log_level(&fix.vtc).await, Some(json!("debug")));
    }

    /// The pair's purpose: what `export` emits, `import` reads back as no
    /// change at all. Both halves go through this door.
    #[tokio::test]
    async fn an_exported_document_imports_as_no_change() {
        let fix = fixture().await;
        let export = signed(&fix.admin, CONFIG_EXPORT_TYPE, json!({})).await;
        let out = dispatch(&fix.vtc, &export).await;
        assert!(out.status.is_success());
        let document = payload_of(&out)["document"].clone();

        let import = signed(
            &fix.admin,
            CONFIG_IMPORT_TYPE,
            json!({ "document": document, "confirm": true }),
        )
        .await;
        let out = dispatch(&fix.vtc, &import).await;
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        let payload = payload_of(&out);
        assert_eq!(payload["profileChanges"], json!([]), "{payload}");
        assert_eq!(payload["overrideChanges"], json!([]), "{payload}");
        assert_eq!(payload["rejected"], json!([]), "{payload}");
    }

    /// **VTI-OPS-020.** The same documents unsigned are refused with the
    /// framework's own code, and nothing is written.
    #[tokio::test]
    async fn vti_ops_020_an_unsigned_config_document_is_refused() {
        let fix = fixture().await;
        let document = changed_document(&fix.vtc).await;

        for (uri, payload) in [
            (CONFIG_EXPORT_TYPE, json!({})),
            (
                CONFIG_IMPORT_TYPE,
                json!({ "document": document, "confirm": true }),
            ),
        ] {
            let doc = unsigned(&fix.admin, uri, payload);
            let out = dispatch(&fix.vtc, &doc).await;
            assert_eq!(
                error_code(&out).as_deref(),
                Some("proofRequired"),
                "{uri}: SPEC §7.2 item 7 names the code: {}",
                String::from_utf8_lossy(&out.body)
            );
        }
        assert_eq!(stored_name(&fix.vtc).await, "Example Community");
    }

    /// Authorization is the **signer's ACL entry**: a correctly signed
    /// document from a member, or from a DID with no row at all, is refused —
    /// what `AdminAuth` refused on both REST routes.
    #[tokio::test]
    async fn a_signer_who_is_not_an_admin_is_refused_both_verbs() {
        let fix = fixture().await;
        let stranger = Party::new();
        let document = changed_document(&fix.vtc).await;

        for signer in [&fix.member, &stranger] {
            for (uri, payload) in [
                (CONFIG_EXPORT_TYPE, json!({})),
                (
                    CONFIG_IMPORT_TYPE,
                    json!({ "document": document, "confirm": true }),
                ),
            ] {
                let doc = signed(signer, uri, payload).await;
                let out = dispatch(&fix.vtc, &doc).await;
                assert_eq!(
                    error_code(&out).as_deref(),
                    Some("permissionDenied"),
                    "{uri}: {}",
                    String::from_utf8_lossy(&out.body)
                );
            }
        }
        assert_eq!(stored_name(&fix.vtc).await, "Example Community");
        assert_eq!(stored_log_level(&fix.vtc).await, None);
    }

    /// **Both verbs take `vtc.config.admin`** (`vtc-admin-roles.md` §4). An
    /// administrator without it — a moderator — may do neither.
    #[tokio::test]
    async fn vti_acl_030_config_export_and_import_need_vtc_config_admin() {
        let fix = fixture().await;
        let document = changed_document(&fix.vtc).await;

        let doc = signed(&fix.scoped_admin, CONFIG_EXPORT_TYPE, json!({})).await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some("permissionDenied"),
            "export takes vtc.config.admin: {}",
            String::from_utf8_lossy(&out.body)
        );

        // An import writes community-wide configuration (#1829): refused, and
        // nothing is stored.
        let doc = signed(
            &fix.scoped_admin,
            CONFIG_IMPORT_TYPE,
            json!({ "document": document, "confirm": true }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some("permissionDenied"),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        assert_ne!(stored_name(&fix.vtc).await, "Imported Community");
    }

    // ─── the operation's own refusals ────────────────────────────────────

    /// A document taken from another community is the declared
    /// `communityDidMismatch`, carried as a code rather than flattened.
    #[tokio::test]
    async fn another_communitys_document_is_the_declared_mismatch() {
        let fix = fixture().await;
        let mut document = changed_document(&fix.vtc).await;
        document["communityProfile"]["communityDid"] = json!("did:web:elsewhere.example");

        let doc = signed(
            &fix.admin,
            CONFIG_IMPORT_TYPE,
            json!({ "document": document, "confirm": true }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some(IMPORT_ERR_COMMUNITY_DID_MISMATCH),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        assert_eq!(stored_name(&fix.vtc).await, "Example Community");
    }

    /// A `schemaVersion` this build does not read is the declared
    /// `unsupportedSchemaVersion` — valid against the schema, refused by the
    /// operation before it diffs anything.
    #[tokio::test]
    async fn an_unknown_schema_version_is_the_declared_refusal() {
        let fix = fixture().await;
        let mut document = changed_document(&fix.vtc).await;
        document["schemaVersion"] = json!(2);

        let doc = signed(
            &fix.admin,
            CONFIG_IMPORT_TYPE,
            json!({ "document": document }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some(IMPORT_ERR_UNSUPPORTED_SCHEMA_VERSION),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
    }

    /// The published `ext` extension points — on the payload and on the
    /// document — are accepted. The route's types refused both under
    /// `deny_unknown_fields` until this batch, so a schema-valid document was
    /// answered as malformed.
    #[tokio::test]
    async fn the_published_ext_members_are_accepted() {
        let fix = fixture().await;
        let mut document = changed_document(&fix.vtc).await;
        document["ext"] = json!({ "org.example": { "note": "from staging" } });

        let doc = signed(
            &fix.admin,
            CONFIG_IMPORT_TYPE,
            json!({
                "document": document,
                "ext": { "org.example": { "ticket": "OPS-1" } },
            }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert!(
            out.status.is_success(),
            "a schema-valid document must not be refused as malformed: {}",
            String::from_utf8_lossy(&out.body)
        );
        assert_eq!(payload_of(&out)["status"], "preview");
    }
}

/// The endorsement-type registry's two writes, served as signed Trust Task
/// documents — **#1641 phase 2, batch 4**.
///
/// `vtc/endorsement-types/register/0.1` and `vtc/endorsement-types/delete/0.1`
/// declare `proof` REQUIRED and were served only as bearer REST. They are
/// served only here now: the admin console signs both, and their bearer
/// routes are gone.
///
/// What these tests hold beyond the earlier batches':
///
/// - **The size bounds both doors now share.** `claimSchema` is capped at
///   32 KiB serialised so every registration that passes fits the signed
///   door's 64 KiB document cap; the cap is the operation's, so the refusal is
///   the same code on either door.
/// - **An absent `claimSchema` stays absent.** The generated payload folds
///   absent into an empty map; the arm reads the raw payload so the stored row
///   records what the operator sent.
/// - **`inUse` still reports both halves.** The refusal is the operation's,
///   reached through the same `delete_inner`.
#[cfg(test)]
mod endorsement_type_tests {
    use super::*;
    use crate::acl::VtcRole;
    use crate::endorsement_types::get_type;
    use crate::endorsement_types::ops::{
        CLAIM_SCHEMA_MAX_BYTES, DELETE_ERR_IN_USE, DELETE_ERR_NOT_FOUND, REGISTER_ERR_EXISTS,
        REGISTER_ERR_RESERVED,
    };
    use crate::test_support::TestVtc;
    use crate::trust_tasks::test_fixtures::{
        assert_conforms, dispatch, error_code, payload_of, seed_acl, signed, unsigned,
    };
    use serde_json::json;
    use vti_rooms_dtg::test_support::Party;

    const TYPE: &str = "https://example.org/predicates/vetted/1";

    struct Fixture {
        vtc: TestVtc,
        admin: Party,
        scoped_admin: Party,
        member: Party,
    }

    async fn fixture() -> Fixture {
        let vtc = TestVtc::builder()
            .with_audit(true)
            .with_signers(true)
            .build()
            .await;
        let admin = Party::new();
        let scoped_admin = Party::new();
        let member = Party::new();
        seed_acl(&vtc, &admin.did, VtcRole::Admin, vec![]).await;
        seed_acl(
            &vtc,
            &scoped_admin.did,
            VtcRole::Admin,
            vec!["ctx-a".to_string()],
        )
        .await;
        seed_acl(&vtc, &member.did, VtcRole::Member, vec![]).await;
        Fixture {
            vtc,
            admin,
            scoped_admin,
            member,
        }
    }

    async fn register(fix: &Fixture, from: &Party, payload: Value) -> TrustTaskOutcome {
        let doc = signed(from, ENDORSEMENT_TYPE_REGISTER_TYPE, payload).await;
        dispatch(&fix.vtc, &doc).await
    }

    async fn delete(fix: &Fixture, from: &Party, type_uri: &str) -> TrustTaskOutcome {
        let doc = signed(
            from,
            ENDORSEMENT_TYPE_DELETE_TYPE,
            json!({ "typeUri": type_uri }),
        )
        .await;
        dispatch(&fix.vtc, &doc).await
    }

    async fn stored(fix: &Fixture) -> Option<crate::endorsement_types::EndorsementType> {
        get_type(&fix.vtc.state.endorsement_types_ks, TYPE)
            .await
            .expect("read type")
    }

    // ─── the premise ─────────────────────────────────────────────────────

    #[test]
    fn every_moved_task_declares_the_proof_these_tests_assume() {
        for uri in [ENDORSEMENT_TYPE_REGISTER_TYPE, ENDORSEMENT_TYPE_DELETE_TYPE] {
            let policy = vti_specs::schema_index::spec_policy_for(uri)
                .unwrap_or_else(|| panic!("{uri} has no published spec policy"));
            assert!(
                policy.is_proof_required,
                "{uri} no longer declares proof REQUIRED — these tests now assert \
                 nothing, and the design note should be re-read"
            );
        }
    }

    // ─── VTI-OPS-020: a proof by the issuer, authorized from their ACL ────

    /// **VTI-OPS-020.** A signed admin document registers a type, and the row
    /// names the signer.
    #[tokio::test]
    async fn vti_ops_020_a_signed_admin_document_registers_a_type() {
        let fix = fixture().await;
        let out = register(
            &fix,
            &fix.admin,
            json!({
                "typeUri": TYPE,
                "description": "Peer identity vetting",
                "claimSchema": { "type": "object" },
            }),
        )
        .await;
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        assert_eq!(payload_of(&out)["endorsementType"]["typeUri"], TYPE);
        assert_conforms::<endorsement_type_register::Response>(&out);

        let row = stored(&fix).await.expect("the type is registered");
        assert_eq!(row.created_by_did, fix.admin.did);
        assert_eq!(row.claim_schema, Some(json!({ "type": "object" })));
    }

    /// **VTI-OPS-020.** A signed admin document deletes an unreferenced type.
    #[tokio::test]
    async fn vti_ops_020_a_signed_admin_document_deletes_a_type() {
        let fix = fixture().await;
        assert!(
            register(&fix, &fix.admin, json!({ "typeUri": TYPE }))
                .await
                .status
                .is_success()
        );

        let out = delete(&fix, &fix.admin, TYPE).await;
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        assert_eq!(payload_of(&out)["typeUri"], TYPE);
        assert_conforms::<endorsement_type_delete::Response>(&out);
        assert!(stored(&fix).await.is_none());
    }

    /// **VTI-OPS-020.** Unsigned, both are refused with the framework's code.
    #[tokio::test]
    async fn vti_ops_020_an_unsigned_document_is_refused() {
        let fix = fixture().await;
        for (uri, payload) in [
            (ENDORSEMENT_TYPE_REGISTER_TYPE, json!({ "typeUri": TYPE })),
            (ENDORSEMENT_TYPE_DELETE_TYPE, json!({ "typeUri": TYPE })),
        ] {
            let out = dispatch(&fix.vtc, &unsigned(&fix.admin, uri, payload)).await;
            assert_eq!(
                error_code(&out).as_deref(),
                Some("proofRequired"),
                "{uri}: {}",
                String::from_utf8_lossy(&out.body)
            );
        }
        assert!(stored(&fix).await.is_none());
    }

    /// Authorization is the signer's ACL entry: a member, and a DID with no
    /// row, are refused both verbs — what `AdminAuth` refused on the REST
    /// routes.
    #[tokio::test]
    async fn a_signer_who_is_not_an_admin_is_refused_both_verbs() {
        let fix = fixture().await;
        let stranger = Party::new();
        for signer in [&fix.member, &stranger] {
            let out = register(&fix, signer, json!({ "typeUri": TYPE })).await;
            assert_eq!(error_code(&out).as_deref(), Some("permissionDenied"));
            let out = delete(&fix, signer, TYPE).await;
            assert_eq!(error_code(&out).as_deref(), Some("permissionDenied"));
        }
        assert!(stored(&fix).await.is_none());
    }

    /// Both verbs take `vtc.surface.admin` (`vtc-admin-roles.md` §4): a
    /// moderator, who holds no such capability, is refused both.
    #[tokio::test]
    async fn vti_acl_030_endorsement_types_need_vtc_surface_admin() {
        let fix = fixture().await;
        let out = register(&fix, &fix.scoped_admin, json!({ "typeUri": TYPE })).await;
        assert_eq!(error_code(&out).as_deref(), Some("permissionDenied"));
        let out = delete(&fix, &fix.scoped_admin, TYPE).await;
        assert_eq!(error_code(&out).as_deref(), Some("permissionDenied"));
    }

    // ─── the operations' own refusals ────────────────────────────────────

    /// The declared `reserved` and `exists`, carried as codes.
    #[tokio::test]
    async fn the_declared_register_refusals_are_carried_as_codes() {
        let fix = fixture().await;
        let out = register(
            &fix,
            &fix.admin,
            json!({ "typeUri": crate::endorsements::VETTER_GRANT_ROW_TYPE }),
        )
        .await;
        assert_eq!(error_code(&out).as_deref(), Some(REGISTER_ERR_RESERVED));

        assert!(
            register(&fix, &fix.admin, json!({ "typeUri": TYPE }))
                .await
                .status
                .is_success()
        );
        // A fresh document — a new `id` — so this is the operation refusing a
        // second registration, not the accepted-id record answering a replay.
        let out = register(&fix, &fix.admin, json!({ "typeUri": TYPE })).await;
        assert_eq!(error_code(&out).as_deref(), Some(REGISTER_ERR_EXISTS));
    }

    /// A `claimSchema` over the cap is refused, and nothing is stored. The
    /// document itself is under 64 KiB, so this is the operation's bound
    /// speaking, not the transport's.
    #[tokio::test]
    async fn a_claim_schema_over_the_cap_is_refused() {
        let fix = fixture().await;
        let padding = "x".repeat(CLAIM_SCHEMA_MAX_BYTES);
        let out = register(
            &fix,
            &fix.admin,
            json!({
                "typeUri": TYPE,
                "claimSchema": { "type": "object", "description": padding },
            }),
        )
        .await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some("malformedRequest"),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        assert!(stored(&fix).await.is_none());
    }

    /// A `claimSchema` that is not a JSON Schema is refused with the framework's
    /// `malformedRequest`, which the operation declares because the task has no
    /// code of its own for it. Before this batch, mapping that declared code
    /// panicked the dispatcher: it read every declared code as `<slug>:<local>`.
    #[tokio::test]
    async fn a_claim_schema_that_is_not_a_schema_is_malformed_not_a_panic() {
        let fix = fixture().await;
        let out = register(
            &fix,
            &fix.admin,
            json!({ "typeUri": TYPE, "claimSchema": { "type": "not-a-type" } }),
        )
        .await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some("malformedRequest"),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        assert!(stored(&fix).await.is_none());
    }

    /// An omitted `claimSchema` is stored as absent, not as an empty schema —
    /// the distinction the arm reads the raw payload for.
    #[tokio::test]
    async fn an_omitted_claim_schema_is_stored_as_absent() {
        let fix = fixture().await;
        assert!(
            register(&fix, &fix.admin, json!({ "typeUri": TYPE }))
                .await
                .status
                .is_success()
        );
        assert_eq!(stored(&fix).await.expect("row").claim_schema, None);
    }

    /// The declared `notFound`.
    #[tokio::test]
    async fn deleting_an_unknown_type_is_the_declared_not_found() {
        let fix = fixture().await;
        let out = delete(&fix, &fix.admin, TYPE).await;
        assert_eq!(error_code(&out).as_deref(), Some(DELETE_ERR_NOT_FOUND));
    }

    /// The declared `inUse`, for a type an Accepts criterion still requires —
    /// and the type is still there afterwards.
    #[tokio::test]
    async fn deleting_a_referenced_type_is_the_declared_in_use() {
        let fix = fixture().await;
        assert!(
            register(&fix, &fix.admin, json!({ "typeUri": TYPE }))
                .await
                .status
                .is_success()
        );
        let schemas_ks = &fix.vtc.state.schemas_ks;
        let entry: crate::schemas::SchemaEntry = serde_json::from_value(json!({
            "typeUri": "StatementCredential",
            "dtgType": "StatementCredential",
            "kind": "accepts",
            "createdAt": "2026-09-24T00:00:00Z",
            "createdByDid": fix.admin.did,
        }))
        .expect("schema entry");
        crate::schemas::storage::store_schema(schemas_ks, &entry)
            .await
            .expect("store the referenced schema");
        let criterion: crate::schemas::accepts::AcceptsCriterion = serde_json::from_value(json!({
            "id": "vetted",
            "admission": "automatic",
            "vetting": {
                "version": "0.1",
                "statementType": TYPE,
                "minStatements": 2,
                "minByMethod": { "inPerson": 1 },
                "acceptedMethods": ["inPerson", "video"],
                "maxStatementAge": "P120D",
                "eligibleVetters": { "role": "vetter" },
            },
            "createdAt": "2026-09-24T00:00:00Z",
            "createdByDid": fix.admin.did,
        }))
        .expect("criterion");
        crate::schemas::accepts::store_accepts(schemas_ks, &criterion)
            .await
            .expect("store the criterion");

        let out = delete(&fix, &fix.admin, TYPE).await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some(DELETE_ERR_IN_USE),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        assert!(stored(&fix).await.is_some());
    }
}

/// The backup export, served as a signed Trust Task document — **#1641
/// phase 2, batch 5**.
///
/// What these tests hold beyond the earlier batches':
///
/// - **The super-admin bar.** The bearer route took `SuperAdminAuth`, so a
///   context-scoped admin — admitted by every earlier batch's verbs — is
///   refused here, as `members/purge` refuses one.
/// - **A redelivery answers with the same envelope.** The spine records the
///   reply, so the second delivery of one document gets the first export back
///   rather than a second one under a fresh salt and nonce.
#[cfg(test)]
mod backup_export_tests {
    use super::*;
    use crate::acl::VtcRole;
    use crate::test_support::{TEST_VTC_DID, TestVtc};
    use crate::trust_tasks::test_fixtures::{
        assert_conforms, dispatch, dispatch_didcomm, error_code, payload_of, seed_acl, signed,
        unsigned,
    };
    use serde_json::json;
    use vti_rooms_dtg::test_support::Party;

    const PASSWORD: &str = "a-long-enough-backup-password";

    struct Fixture {
        vtc: TestVtc,
        super_admin: Party,
        scoped_admin: Party,
        member: Party,
    }

    async fn fixture() -> Fixture {
        let vtc = TestVtc::builder()
            .vtc_did(TEST_VTC_DID)
            .with_audit(true)
            .with_signers(true)
            .build()
            .await;
        // The export reads the signing bundle from the configured secret
        // store. The default build compiles `keyring`, which a test cannot
        // reach, so name the plaintext backend and seed the store through the
        // same factory the route calls.
        let store = {
            let mut config = vtc.state.config.write().await;
            config.secrets.backend = Some(crate::config::SecretBackend::Plaintext);
            crate::keys::seed_store::create_secret_store(&config).expect("plaintext store")
        };
        store
            .set(b"signing-bundle")
            .await
            .expect("seed the secret store");

        let super_admin = Party::new();
        let scoped_admin = Party::new();
        let member = Party::new();
        seed_acl(&vtc, &super_admin.did, VtcRole::Admin, vec![]).await;
        seed_acl(
            &vtc,
            &scoped_admin.did,
            VtcRole::Admin,
            vec!["ctx-a".to_string()],
        )
        .await;
        seed_acl(&vtc, &member.did, VtcRole::Member, vec![]).await;
        Fixture {
            vtc,
            super_admin,
            scoped_admin,
            member,
        }
    }

    #[test]
    fn the_moved_task_declares_the_proof_these_tests_assume() {
        let policy = vti_specs::schema_index::spec_policy_for(BACKUP_EXPORT_TYPE)
            .expect("backup/export has a published spec policy");
        assert!(
            policy.is_proof_required,
            "backup/export no longer declares proof REQUIRED — these tests now \
             assert nothing, and the design note should be re-read"
        );
    }

    /// **VTI-OPS-020.** A signed super-admin document exports the community,
    /// and the reply conforms to the published `#response`.
    #[tokio::test]
    async fn vti_ops_020_a_signed_super_admin_document_exports() {
        let fix = fixture().await;
        let doc = signed(
            &fix.super_admin,
            BACKUP_EXPORT_TYPE,
            json!({ "password": PASSWORD }),
        )
        .await;
        let out = dispatch_didcomm(&fix.vtc, &doc).await;
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        let envelope = &payload_of(&out)["envelope"];
        assert_eq!(envelope["sourceDid"], TEST_VTC_DID);
        assert!(
            envelope["ciphertext"]
                .as_str()
                .is_some_and(|c| !c.is_empty())
        );
        assert_conforms::<backup_export::Response>(&out);
    }

    /// The super-admin bar holds: a context-scoped admin is refused, as
    /// `SuperAdminAuth` refused them on the bearer route, and so is a member.
    #[tokio::test]
    async fn only_a_super_admin_may_export() {
        let fix = fixture().await;
        for signer in [&fix.scoped_admin, &fix.member] {
            let doc = signed(signer, BACKUP_EXPORT_TYPE, json!({ "password": PASSWORD })).await;
            let out = dispatch(&fix.vtc, &doc).await;
            assert_eq!(
                error_code(&out).as_deref(),
                Some("permissionDenied"),
                "{}",
                String::from_utf8_lossy(&out.body)
            );
        }
    }

    /// **VTI-OPS-020.** Unsigned, it is refused with the framework's code.
    #[tokio::test]
    async fn vti_ops_020_an_unsigned_export_is_refused() {
        let fix = fixture().await;
        let doc = unsigned(
            &fix.super_admin,
            BACKUP_EXPORT_TYPE,
            json!({ "password": PASSWORD }),
        );
        let out = dispatch(&fix.vtc, &doc).await;
        assert_eq!(error_code(&out).as_deref(), Some("proofRequired"));
    }

    /// A password under the minimum is the declared `passwordTooShort`.
    #[tokio::test]
    async fn a_short_password_is_the_declared_refusal() {
        let fix = fixture().await;
        let short = "x".repeat(vta_sdk::protocols::backup_management::MIN_BACKUP_PASSWORD_LEN - 1);
        let doc = signed(
            &fix.super_admin,
            BACKUP_EXPORT_TYPE,
            json!({ "password": short }),
        )
        .await;
        let out = dispatch_didcomm(&fix.vtc, &doc).await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some(vti_specs::vtc::backup::export::v0_1::error_codes::PASSWORD_TOO_SHORT.code),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
    }

    /// **VTI-OPS-025.** The same document delivered twice is answered with the
    /// same envelope: the spine recorded the first reply, so the second
    /// delivery does not run a second export under a fresh salt and nonce.
    #[tokio::test]
    async fn vti_ops_025_a_redelivered_export_answers_with_the_same_envelope() {
        let fix = fixture().await;
        let doc = signed(
            &fix.super_admin,
            BACKUP_EXPORT_TYPE,
            json!({ "password": PASSWORD }),
        )
        .await;
        let first = dispatch_didcomm(&fix.vtc, &doc).await;
        let second = dispatch_didcomm(&fix.vtc, &doc).await;
        assert!(first.status.is_success() && second.status.is_success());
        assert_eq!(
            payload_of(&first)["envelope"],
            payload_of(&second)["envelope"],
            "a redelivery must be answered with the recorded export"
        );
    }

    /// The backup password and the backup never cross a hop-by-hop channel:
    /// the same signed super-admin document is refused over REST.
    #[tokio::test]
    async fn an_export_over_rest_is_refused() {
        let fix = fixture().await;
        let doc = signed(
            &fix.super_admin,
            BACKUP_EXPORT_TYPE,
            json!({ "password": PASSWORD }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some("permissionDenied"),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        assert!(String::from_utf8_lossy(&out.body).contains("DIDComm or TSP"));
    }

    /// With no audit trail to record it in, the export is refused rather than
    /// released unrecorded.
    #[tokio::test]
    async fn an_export_with_no_audit_trail_is_refused() {
        let vtc = TestVtc::builder()
            .vtc_did(TEST_VTC_DID)
            .with_audit(false)
            .with_signers(true)
            .build()
            .await;
        // Everything else an export needs is in place, so the audit trail is
        // the only thing missing.
        let store = {
            let mut config = vtc.state.config.write().await;
            config.secrets.backend = Some(crate::config::SecretBackend::Plaintext);
            crate::keys::seed_store::create_secret_store(&config).expect("plaintext store")
        };
        store.set(b"signing-bundle").await.expect("seed the store");
        let admin = Party::new();
        seed_acl(&vtc, &admin.did, VtcRole::Admin, vec![]).await;
        let doc = signed(&admin, BACKUP_EXPORT_TYPE, json!({ "password": PASSWORD })).await;
        let out = dispatch_didcomm(&vtc, &doc).await;
        // The reply masks internal detail; what matters is that no envelope
        // left.
        assert_eq!(error_code(&out).as_deref(), Some("internalError"));
        assert!(payload_of(&out).get("envelope").is_none());
    }
}
