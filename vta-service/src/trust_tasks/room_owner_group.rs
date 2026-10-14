//! The owner's half of a sealed room's MLS group — `rooms/owner/group/create/0.1` and
//! `rooms/owner/group/add/0.1`.
//!
//! Every member reaches a room's group by a Welcome (`rooms/keys/welcome`), except the
//! owner, whom nobody can welcome: `create` founds the group with the owner as its only
//! leaf. `add` admits a member — it builds the commit and the Welcome, advances the room's
//! epoch at its host, and returns the Welcome for the caller to deliver.
//!
//! # Remote first (`add` items 2–7)
//!
//! The host is advanced **before** this agent's own group, never after. The add is built
//! on a copy and kept durably as a pending admission ([`room_groups::PendingAdd`]) while the
//! live group stays where it is; `rooms/epoch/mint` goes to the host; only an accepted
//! advance replaces the live group. A refusal discards the pending admission. An unknown
//! outcome — a host that could not be reached, or an answer that could not be read — keeps
//! it: the host may have accepted, and a key holder cannot process its own commit from the
//! wire, so the pending group is the only way to follow it there. The next `add` for the
//! room asks the host which epoch it is at and settles the pending admission first.

use serde_json::Value;
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::rooms::owner::group::{add as spec_add, create as spec_create};
use vti_common::acl::Capability;
use vti_common::error::AppError;

use crate::auth::AuthClaims;
use crate::operations::room_groups::{self, CreateGroupError, PrepareAddError, Reconciled};
use crate::operations::room_host::{RoomTaskError, send_room_task_typed};
use crate::server::AppState;

use super::TrustTaskOutcome;
use super::helpers::{app_error_to_reject, parse_payload, reject_with_code, success_response};
use super::room_group::{declared, now, outbound_identity, record, signing_context};

/// `rooms/owner/group/create/0.1` — found a room's group, with the owner as its only leaf.
pub(super) async fn handle_create(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec_create::v0_1::error_codes as codes;
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::CredentialWrite,
        "founding a room's group",
    )
    .await
    {
        return r;
    }
    let req: spec_create::v0_1::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let room_id = req.room_id.as_str();

    // Item 1: control of the room's signing key, the gate issuing its credentials uses —
    // checked without signing anything, since founding produces no signature.
    if let Err(e) = crate::operations::keys::require_key_nameable(
        &state.keys_ks,
        &state.acl_ks,
        auth,
        req.signing_key_id.as_str(),
    )
    .await
    {
        return reject_with_code(
            &doc,
            declared(codes::NO_SIGNING_KEY),
            format!(
                "this agent will not found room `{room_id}`'s group on key `{}`: {e}",
                req.signing_key_id.as_str()
            ),
            None,
        );
    }

    let member = req
        .member
        .as_ref()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| auth.did.clone());
    match room_groups::create_group(&state.room_groups_ks, room_id, &member, now()).await {
        Ok(epoch) => {
            record(state, "rooms.owner.group.create", auth, room_id).await;
            success_response(
                &doc,
                serde_json::json!({ "roomId": room_id, "epoch": epoch }),
            )
        }
        // Item 2: never replace a group.
        Err(CreateGroupError::AlreadyExists { epoch }) => reject_with_code(
            &doc,
            declared(codes::ALREADY_EXISTS),
            format!(
                "this agent already holds room `{room_id}`'s group, at epoch {epoch}; founding \
                 over it would discard the key schedule its sealed records depend on"
            ),
            Some(serde_json::json!({ "epoch": epoch })),
        ),
        Err(CreateGroupError::App(e)) => app_error_to_reject(&doc, e),
    }
}

/// `rooms/owner/group/add/0.1` — admit a member, advancing the room at its host first.
pub(super) async fn handle_add(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec_add::v0_1::error_codes as codes;
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::CredentialWrite,
        "admitting a member to a room's group",
    )
    .await
    {
        return r;
    }
    let req: spec_add::v0_1::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let room_id = req.room_id.as_str().to_string();
    let host = req.host.as_str().to_string();
    let member = req.member.as_str().to_string();

    if room_groups::load(&state.room_groups_ks, &room_id)
        .await
        .map(|g| g.is_none())
        .unwrap_or(false)
    {
        return reject_with_code(
            &doc,
            declared(codes::NO_GROUP),
            format!(
                "this agent holds no group for room `{room_id}`: found one with \
                 rooms/owner/group/create, or join by a Welcome"
            ),
            None,
        );
    }

    let (vta_did, resolver) = match outbound_identity(state, &doc).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let host_call = HostCall {
        state,
        auth,
        vta_did: &vta_did,
        resolver: &resolver,
        room_id: &room_id,
    };

    // Item 6: an admission left pending by an earlier request is settled against the host
    // before another is built. Its own host is asked — the one it was sent to.
    match room_groups::pending_add(&state.room_groups_ks, &room_id).await {
        Ok(Some(pending)) => {
            let host_epoch = match host_call.epoch(&pending.host).await {
                Ok(e) => e,
                Err(e) => {
                    return reject_with_code(
                        &doc,
                        declared(codes::HOST_UNREACHABLE),
                        format!(
                            "an earlier admission to room `{room_id}` is waiting on host `{}`, \
                             and asking it which epoch it is at failed: {}",
                            pending.host,
                            e.into_app_error()
                        ),
                        None,
                    );
                }
            };
            match room_groups::reconcile_pending_add(
                &state.room_groups_ks,
                &room_id,
                &pending,
                host_epoch,
                now(),
            )
            .await
            {
                Ok(Reconciled::Applied | Reconciled::Discarded) => {}
                Ok(Reconciled::Conflict) => {
                    return reject_with_code(
                        &doc,
                        declared(codes::EPOCH_CONFLICT),
                        format!(
                            "room `{room_id}` is at epoch {host_epoch} at its host, which this \
                             agent's group has not reached; catch up with rooms/epoch/commits \
                             and try again"
                        ),
                        Some(serde_json::json!({ "hostEpoch": host_epoch })),
                    );
                }
                Err(e) => return app_error_to_reject(&doc, e),
            }
        }
        Ok(None) => {}
        Err(e) => return app_error_to_reject(&doc, e),
    }

    // The owner's `admin` authority, minted before anything is built: a caller without it
    // learns so without leaving a pending admission behind.
    let minted =
        match crate::operations::room_oracle::present(state, auth, &vta_did, &room_id, "admin")
            .await
        {
            Ok(m) => m,
            Err(e @ (AppError::NotFound(_) | AppError::Forbidden(_) | AppError::Validation(_))) => {
                return reject_with_code(
                    &doc,
                    declared(codes::NO_AUTHORITY),
                    format!(
                        "this agent holds no authority credential conferring `admin` on room \
                     `{room_id}` for its caller, so it cannot advance the room's epoch: {e}"
                    ),
                    None,
                );
            }
            Err(e) => return app_error_to_reject(&doc, e),
        };

    let key_package = match decode_b64(req.key_package.as_str()) {
        Ok(k) => k,
        Err(e) => {
            return reject_with_code(
                &doc,
                declared(codes::KEY_PACKAGE_INVALID),
                format!("the KeyPackage is not base64url: {e}"),
                None,
            );
        }
    };

    // Items 2 and 3: built on a copy and retained durably before the host is contacted.
    let pending = match room_groups::prepare_add(
        &state.room_groups_ks,
        &room_id,
        &host,
        &member,
        &key_package,
        now(),
    )
    .await
    {
        Ok(p) => p,
        Err(PrepareAddError::NoGroup) => {
            return reject_with_code(
                &doc,
                declared(codes::NO_GROUP),
                format!("this agent holds no group for room `{room_id}`"),
                None,
            );
        }
        Err(PrepareAddError::AlreadyMember) => {
            return reject_with_code(
                &doc,
                declared(codes::ALREADY_MEMBER),
                format!("`{member}` already has a leaf in room `{room_id}`'s group"),
                None,
            );
        }
        Err(PrepareAddError::KeyPackageInvalid(why)) => {
            return reject_with_code(
                &doc,
                declared(codes::KEY_PACKAGE_INVALID),
                format!("the KeyPackage cannot admit `{member}`: {why}"),
                None,
            );
        }
        Err(PrepareAddError::App(e)) => return app_error_to_reject(&doc, e),
    };

    // Item 4: the advance, with the link and the commit, under the owner's authority.
    let mut mint = serde_json::json!({
        "roomId": room_id,
        "epoch": pending.epoch,
        "presentation": minted.presentation,
        "commit": pending.commit,
    });
    if let Some(link) = &pending.link {
        mint["link"] = serde_json::to_value(link).unwrap_or(Value::Null);
    }
    if let Some(reason) = &req.reason {
        mint["reason"] = serde_json::json!(reason.as_str());
    }
    match host_call
        .send(&host, vti_rooms::wire::ROOMS_EPOCH_MINT_TYPE, mint)
        .await
    {
        Ok(_) => {}
        // Item 5: a refusal is the host's answer — the advance did not happen — so the
        // pending admission is discarded and the live group never moved.
        Err(RoomTaskError::Refused { code, reason, .. }) => {
            if let Err(e) = room_groups::discard_pending_add(&state.room_groups_ks, &room_id).await
            {
                return app_error_to_reject(&doc, e);
            }
            if code == "rooms/epoch/mint:nonSequential" {
                let host_epoch = host_call.epoch(&host).await.ok();
                return reject_with_code(
                    &doc,
                    declared(codes::EPOCH_CONFLICT),
                    format!(
                        "host `{host}` is not at epoch {} for room `{room_id}`: another admin \
                         advanced it. Catch up with rooms/epoch/commits and try again.",
                        pending.epoch - 1
                    ),
                    host_epoch.map(|e| serde_json::json!({ "hostEpoch": e })),
                );
            }
            return reject_with_code(
                &doc,
                declared(codes::HOST_REFUSED),
                format!("host `{host}` declined to advance room `{room_id}`: {code}: {reason}"),
                Some(serde_json::json!({ "code": code, "reason": reason })),
            );
        }
        // An unknown outcome keeps the pending admission: the host may have accepted, and
        // the next request settles it (item 6). Discarding here could strand this agent an
        // epoch behind a room that did advance, with no way to follow.
        Err(RoomTaskError::Unknown(e)) => {
            return reject_with_code(
                &doc,
                declared(codes::HOST_UNREACHABLE),
                format!(
                    "the epoch advance for room `{room_id}` did not get an answer from host \
                     `{host}`: {e}. Whether it took effect is unknown; the next admission to \
                     this room settles it with the host first."
                ),
                None,
            );
        }
    }

    if let Err(e) =
        room_groups::promote_pending_add(&state.room_groups_ks, &room_id, &pending, now()).await
    {
        // The host advanced and this agent could not record it. The pending row survives,
        // and the next request promotes it (item 6), so this is a delay, not a loss.
        return app_error_to_reject(&doc, e);
    }

    // The member's DID and the room, never the Welcome or the KeyPackage.
    record(state, "rooms.owner.group.add", auth, &room_id).await;
    success_response(
        &doc,
        serde_json::json!({
            "roomId": room_id,
            "member": member,
            "epoch": pending.epoch,
            "welcome": pending.welcome,
        }),
    )
}

/// What `add` needs to speak to a host as this agent.
struct HostCall<'a> {
    state: &'a AppState,
    auth: &'a AuthClaims,
    vta_did: &'a str,
    resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
    room_id: &'a str,
}

impl HostCall<'_> {
    async fn send(&self, host: &str, task: &str, payload: Value) -> Result<Value, RoomTaskError> {
        let key = format!("{}#key-0", self.vta_did);
        send_room_task_typed(
            signing_context(self.state, self.auth),
            &self.state.room_groups_ks,
            self.room_id,
            &crate::operations::outbound::Outbound::from_app_state(self.state, self.resolver),
            host,
            &key,
            self.vta_did,
            &crate::operations::credentials::vta_signing_vm(self.vta_did),
            task,
            &format!("{task}#response"),
            payload,
        )
        .await
    }

    /// The room's epoch at `host`, from `rooms/info` under the owner's `read` grant.
    async fn epoch(&self, host: &str) -> Result<u32, RoomTaskError> {
        let minted = crate::operations::room_oracle::present(
            self.state,
            self.auth,
            self.vta_did,
            self.room_id,
            "read",
        )
        .await
        .map_err(RoomTaskError::Unknown)?;
        let info = self
            .send(
                host,
                vti_rooms::wire::ROOMS_INFO_TYPE,
                serde_json::json!({ "roomId": self.room_id, "presentation": minted.presentation }),
            )
            .await?;
        info.get("epoch")
            .and_then(Value::as_u64)
            .and_then(|e| u32::try_from(e).ok())
            .ok_or_else(|| {
                RoomTaskError::Unknown(AppError::Internal(format!(
                    "host `{host}` described room `{}` without an epoch",
                    self.room_id
                )))
            })
    }
}

fn decode_b64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim())
}

#[cfg(test)]
mod tests {
    //! The owner's group verbs against a stand-in room host on a loopback port.
    //!
    //! The host is a stub because what is under test is this agent's side of the
    //! conversation — what it sends, and above all what it does with each kind of
    //! answer — and a stub is the only host that can be told to accept an advance and then
    //! lose the reply. It answers `rooms/epoch/mint` and `rooms/info` with documents signed
    //! as its own DID, which this agent requires of every reply it acts on.

    use std::sync::{Arc, Mutex};

    use chrono::{Duration as Span, Utc};
    use dtg_credentials::DTGCredential;
    use trust_tasks_rs::TypeUri;
    use vti_rooms_dtg::test_support::Party;

    use super::*;
    use crate::operations::room_oracle::{AUTHORITY_TYPE, MEMBERSHIP_TYPE};

    /// What the stub host does with the next epoch advance.
    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        Accept,
        Refuse,
        /// Advance the room, then answer with something unreadable: the outcome the
        /// caller sees is unknown, while the host has in fact moved.
        AcceptThenLose,
    }

    struct Host {
        epoch: u32,
        mode: Mode,
    }

    struct StubHost {
        did: String,
        state: Arc<Mutex<Host>>,
    }

    async fn start_host(vta_did: String) -> (StubHost, serde_json::Value) {
        let party = Party::new();
        let state = Arc::new(Mutex::new(Host {
            epoch: 1,
            mode: Mode::Accept,
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let host_did = party.did.clone();
        let shared = state.clone();
        let app = axum::Router::new().route(
            "/trust-tasks",
            axum::routing::post(move |axum::Json(req): axum::Json<Value>| {
                let shared = shared.clone();
                let host_did = host_did.clone();
                let secret = party.secret_multibase.clone();
                let vta_did = vta_did.clone();
                async move {
                    let task = req["type"].as_str().unwrap_or_default().to_string();
                    let room_id = req["payload"]["roomId"].clone();
                    let answer = {
                        let mut h = shared.lock().unwrap();
                        if task == vti_rooms::wire::ROOMS_INFO_TYPE {
                            Ok(serde_json::json!({
                                "roomId": room_id, "visibility": "attributed",
                                "retentionPolicy": "chained", "epoch": h.epoch,
                            }))
                        } else if task == vti_rooms::wire::ROOMS_EPOCH_MINT_TYPE {
                            let asked = req["payload"]["epoch"].as_u64().unwrap_or(0) as u32;
                            match h.mode {
                                Mode::Refuse => Err(("permissionDenied", "not today")),
                                _ if asked != h.epoch + 1 => {
                                    Err(("rooms/epoch/mint:nonSequential", "wrong epoch"))
                                }
                                mode => {
                                    h.epoch = asked;
                                    if mode == Mode::AcceptThenLose {
                                        return (
                                            axum::http::StatusCode::BAD_GATEWAY,
                                            "the reply was lost".to_string(),
                                        );
                                    }
                                    Ok(serde_json::json!({ "roomId": room_id, "epoch": asked }))
                                }
                            }
                        } else {
                            Err(("unsupportedTask", "stub"))
                        }
                    };
                    let doc = match answer {
                        Err((code, msg)) => serde_json::json!({
                            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                            "type": "https://trusttasks.org/spec/trust-task-error/0.5",
                            "payload": { "code": code, "message": msg },
                        }),
                        Ok(payload) => {
                            let mut doc: trust_tasks_rs::TrustTask<Value> =
                                serde_json::from_value(serde_json::json!({
                                    "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                                    "type": format!("{task}#response"),
                                    "issuer": host_did,
                                    "recipient": vta_did,
                                    "issuedAt": Utc::now().to_rfc3339(),
                                    "threadId": req["id"],
                                    "payload": payload,
                                }))
                                .unwrap();
                            vta_sdk::trust_task_sign::sign_in_place(&mut doc, &host_did, &secret)
                                .await
                                .unwrap();
                            serde_json::to_value(doc).unwrap()
                        }
                    };
                    (axum::http::StatusCode::OK, doc.to_string())
                }
            }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        // The host's DID document: its own key, and the HTTPS binding on loopback.
        let mb = party.did.strip_prefix("did:key:").unwrap();
        let vm = format!("{}#{mb}", party.did);
        let doc = serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": party.did,
            "verificationMethod": [{
                "id": vm, "type": "Multikey", "controller": party.did, "publicKeyMultibase": mb,
            }],
            "authentication": [vm],
            "assertionMethod": [vm],
            "service": [{
                "id": format!("{}#rest", party.did), "type": "TrustTaskHTTPS",
                "serviceEndpoint": format!("http://127.0.0.1:{port}"),
            }],
        });
        (
            StubHost {
                did: party.did.clone(),
                state,
            },
            doc,
        )
    }

    const OWNER_KEY_PATH: &str = "m/44'/0'/7'/0'/1'";
    const ROOM_KEY_PATH: &str = "m/44'/0'/7'/0'/2'";

    /// An owner's VTA: the room's signing key, the owner's identity, their `admin`
    /// grant and membership in the vault, and a resolver that knows the host.
    struct Owner {
        state: AppState,
        _dir: tempfile::TempDir,
        member: String,
        room: Party,
        room_key: String,
        host: StubHost,
    }

    async fn owner() -> Owner {
        let (mut state, dir) = crate::test_support::build_signing_test_app_state().await;
        let member = crate::test_support::seed_holder_key(&state, OWNER_KEY_PATH, None).await;
        let room_signing = crate::test_support::seed_holder_key(&state, ROOM_KEY_PATH, None).await;
        let room_key = format!(
            "{room_signing}#{}",
            room_signing.strip_prefix("did:key:").unwrap()
        );
        let room = Party::new();

        let now = Utc::now();
        let mut vac = DTGCredential::new_vac(
            room.did.clone(),
            dtg_credentials::IssuerScope::Public,
            member.clone(),
            room.did.clone(),
            vec!["read".into(), "write".into(), "admin".into()],
            now - Span::minutes(1),
            now + Span::days(30),
        )
        .unwrap()
        .with_id("urn:uuid:vac-owner");
        vac.sign(&room.secret, None).await.unwrap();
        let mut vmc = DTGCredential::new_vmc(
            room.did.clone(),
            member.clone(),
            now - Span::minutes(1),
            Some(now + Span::days(30)),
            false,
        );
        vmc.sign(&room.secret, None).await.unwrap();
        vault(&state, AUTHORITY_TYPE, &room.did, &vac).await;
        vault(&state, MEMBERSHIP_TYPE, &room.did, &vmc).await;

        let vta_did = state.config.read().await.vta_did.clone().unwrap();
        let (host, host_doc) = start_host(vta_did).await;
        let mut resolver = affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .unwrap();
        resolver
            .add_did_document(&host.did, serde_json::from_value(host_doc).unwrap())
            .await;
        state.did_resolver = Some(resolver);

        Owner {
            state,
            _dir: dir,
            member,
            room,
            room_key,
            host,
        }
    }

    async fn vault(state: &AppState, type_tag: &str, issuer: &str, cred: &DTGCredential) {
        use crate::vault::model::{CredentialFormat, CredentialStatus, StoredCredential};
        use vti_common::vault::VaultStatus;
        crate::vault::storage::put(
            &state.vault_ks,
            &StoredCredential {
                id: format!("{type_tag}-{issuer}"),
                format: CredentialFormat::EddsaJcs2022,
                types: vec![type_tag.into()],
                schema_id: None,
                community_did: None,
                context_id: None,
                subject_did: None,
                issuer_did: Some(issuer.to_string()),
                purpose: None,
                status: CredentialStatus::Unknown,
                valid_from: None,
                valid_until: None,
                received_at: "2026-01-01T00:00:00Z".into(),
                source: None,
                tags: Default::default(),
                body: serde_json::to_vec(cred).unwrap(),
                lifecycle: VaultStatus::Active,
                archived_at: None,
                deleted_at: None,
                grace_until: None,
            },
        )
        .await
        .unwrap();
    }

    fn request(uri: &str, payload: Value) -> TrustTask<Value> {
        let uri: TypeUri = uri.parse().unwrap();
        TrustTask::new("urn:uuid:owner-group-test", uri, payload)
    }

    fn body(outcome: TrustTaskOutcome) -> Value {
        serde_json::from_slice(&outcome.body).expect("a document")
    }

    async fn create(o: &Owner, key: &str) -> Value {
        body(
            handle_create(
                &o.state,
                &crate::test_support::super_admin_claims(),
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_OWNER_GROUP_CREATE_0_1,
                    serde_json::json!({
                        "roomId": o.room.did, "signingKeyId": key, "member": o.member,
                    }),
                ),
            )
            .await,
        )
    }

    async fn add(o: &Owner, member: &str, key_package: &str) -> Value {
        body(
            handle_add(
                &o.state,
                &crate::test_support::super_admin_claims(),
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_OWNER_GROUP_ADD_0_1,
                    serde_json::json!({
                        "roomId": o.room.did, "host": o.host.did, "member": member,
                        "keyPackage": key_package, "reason": "joining the deal team",
                    }),
                ),
            )
            .await,
        )
    }

    async fn live_epoch(o: &Owner) -> u32 {
        let r = room_groups::load(&o.state.room_groups_ks, &o.room.did)
            .await
            .unwrap()
            .expect("a group");
        vti_rooms::sealed::SealedRoom::new(
            o.room.did.as_str(),
            vti_rooms::mls::RoomGroup::restore(&r.snapshot).unwrap(),
        )
        .room_epoch()
    }

    /// A joiner's VTA: a KeyPackage minted for the room.
    async fn joiner(room: &str) -> (AppState, tempfile::TempDir, String, String) {
        let (state, dir) = crate::test_support::build_signing_test_app_state().await;
        let did = Party::new().did;
        let pending = room_groups::mint_key_package(&state.room_groups_ks, room, &did, 3600, 0)
            .await
            .unwrap();
        (state, dir, did, pending.key_package)
    }

    #[tokio::test]
    async fn create_founds_the_group_at_the_epoch_a_host_records_and_never_twice() {
        let o = owner().await;
        let first = create(&o, &o.room_key).await;
        assert_eq!(first["payload"]["epoch"], 1, "{first}");
        assert_eq!(live_epoch(&o).await, 1);

        let again = create(&o, &o.room_key).await;
        assert_eq!(
            again["payload"]["code"], "rooms/owner/group/create:alreadyExists",
            "{again}"
        );
        assert_eq!(again["payload"]["details"]["epoch"], 1, "{again}");
    }

    #[tokio::test]
    async fn create_refuses_a_key_the_caller_cannot_name() {
        let o = owner().await;
        let out = create(&o, "did:key:z6MkNobody#z6MkNobody").await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/create:noSigningKey",
            "{out}"
        );
        assert!(
            room_groups::load(&o.state.room_groups_ks, &o.room.did)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The whole admission: the host advances first, the owner's group follows, and the
    /// newcomer's own VTA joins from the Welcome — after which each can open what the other
    /// sealed.
    #[tokio::test]
    async fn an_admitted_member_joins_and_both_read_each_other() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (j_state, _j_dir, j_did, kp) = joiner(&o.room.did).await;

        let out = add(&o, &j_did, &kp).await;
        assert_eq!(out["payload"]["epoch"], 2, "{out}");
        assert_eq!(o.host.state.lock().unwrap().epoch, 2, "the host advanced");
        assert_eq!(live_epoch(&o).await, 2, "and only then the owner's group");
        assert!(
            room_groups::pending_add(&o.state.room_groups_ks, &o.room.did)
                .await
                .unwrap()
                .is_none()
        );

        let welcome = {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(out["payload"]["welcome"].as_str().unwrap())
                .unwrap()
        };
        let joined = room_groups::join(&j_state.room_groups_ks, &o.room.did, &j_did, &welcome, 0)
            .await
            .expect("the newcomer's VTA joins from the Welcome");
        assert_eq!(joined + 1, 2, "at the room's new epoch");

        let from_owner = room_groups::seal_record(
            &o.state.room_groups_ks,
            &o.room.did,
            "notes/1",
            1,
            b"from the owner",
        )
        .await
        .unwrap();
        let opened = room_groups::open_record(
            &j_state.room_groups_ks,
            &o.room.did,
            "notes/1",
            1,
            &from_owner.ciphertext,
            &from_owner.nonce,
            from_owner.epoch,
        )
        .await
        .unwrap();
        assert_eq!(opened, b"from the owner");

        let from_member = room_groups::seal_record(
            &j_state.room_groups_ks,
            &o.room.did,
            "notes/2",
            2,
            b"from the member",
        )
        .await
        .unwrap();
        let opened = room_groups::open_record(
            &o.state.room_groups_ks,
            &o.room.did,
            "notes/2",
            2,
            &from_member.ciphertext,
            &from_member.nonce,
            from_member.epoch,
        )
        .await
        .unwrap();
        assert_eq!(opened, b"from the member");

        // Admitting the same member twice is refused, not a second leaf.
        let (_s2, _d2, _did2, kp2) = joiner(&o.room.did).await;
        let again = add(&o, &j_did, &kp2).await;
        assert_eq!(
            again["payload"]["code"], "rooms/owner/group/add:alreadyMember",
            "{again}"
        );
    }

    /// A KeyPackage naming somebody else is refused: an owner admits the party they meant.
    #[tokio::test]
    async fn a_key_package_for_someone_else_is_refused() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s, _d, _did, kp) = joiner(&o.room.did).await;
        let out = add(&o, "did:key:z6MkSomebodyElse", &kp).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/add:keyPackageInvalid",
            "{out}"
        );
        assert_eq!(
            o.host.state.lock().unwrap().epoch,
            1,
            "nothing reached the host"
        );
        assert!(
            room_groups::pending_add(&o.state.room_groups_ks, &o.room.did)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Item 5: a refusal is the host's answer, so the owner's group does not move.
    #[tokio::test]
    async fn a_host_refusal_leaves_the_group_where_it_was() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        o.host.state.lock().unwrap().mode = Mode::Refuse;
        let (_s, _d, did, kp) = joiner(&o.room.did).await;

        let out = add(&o, &did, &kp).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/add:hostRefused",
            "{out}"
        );
        assert_eq!(live_epoch(&o).await, 1);
        assert!(
            room_groups::pending_add(&o.state.room_groups_ks, &o.room.did)
                .await
                .unwrap()
                .is_none(),
            "a refused admission leaves nothing pending"
        );
    }

    /// A host another admin advanced answers `nonSequential`: `epochConflict`, carrying the
    /// host's epoch, and nothing changes here.
    #[tokio::test]
    async fn a_room_advanced_elsewhere_is_an_epoch_conflict() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        o.host.state.lock().unwrap().epoch = 5;
        let (_s, _d, did, kp) = joiner(&o.room.did).await;

        let out = add(&o, &did, &kp).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/add:epochConflict",
            "{out}"
        );
        assert_eq!(out["payload"]["details"]["hostEpoch"], 5, "{out}");
        assert_eq!(live_epoch(&o).await, 1);
    }

    /// Items 3, 5 and 6: the host accepts and the answer is lost. The outcome is unknown,
    /// so the pending admission is kept — and the next request finds the host at its epoch
    /// and applies it, rather than leaving this agent behind a room that moved.
    #[tokio::test]
    async fn an_advance_whose_answer_was_lost_is_settled_by_the_next_request() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        o.host.state.lock().unwrap().mode = Mode::AcceptThenLose;
        let (_s, _d, did, kp) = joiner(&o.room.did).await;

        let out = add(&o, &did, &kp).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/add:hostUnreachable",
            "{out}"
        );
        assert_eq!(
            o.host.state.lock().unwrap().epoch,
            2,
            "the host did advance"
        );
        assert_eq!(live_epoch(&o).await, 1, "this agent does not know that yet");
        assert!(
            room_groups::pending_add(&o.state.room_groups_ks, &o.room.did)
                .await
                .unwrap()
                .is_some(),
            "an unknown outcome keeps the pending admission"
        );

        // The next admission settles the first against the host before anything else.
        o.host.state.lock().unwrap().mode = Mode::Accept;
        let (_s2, _d2, did2, kp2) = joiner(&o.room.did).await;
        let out = add(&o, &did2, &kp2).await;
        assert_eq!(out["payload"]["epoch"], 3, "{out}");
        assert_eq!(live_epoch(&o).await, 3);
        let group = room_groups::load(&o.state.room_groups_ks, &o.room.did)
            .await
            .unwrap()
            .unwrap();
        let group = vti_rooms::mls::RoomGroup::restore(&group.snapshot).unwrap();
        assert!(
            group.leaf_of(&did).is_some(),
            "the first admission was applied"
        );
        assert!(group.leaf_of(&did2).is_some());
    }

    /// A pending admission the host never took is discarded, and the room carries on.
    #[tokio::test]
    async fn a_pending_admission_the_host_never_took_is_discarded() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s, _d, did, kp) = joiner(&o.room.did).await;
        let key_package = {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&kp)
                .unwrap()
        };
        // As if the process died between storing the pending admission and sending it.
        room_groups::prepare_add(
            &o.state.room_groups_ks,
            &o.room.did,
            &o.host.did,
            &did,
            &key_package,
            0,
        )
        .await
        .unwrap();

        let (_s2, _d2, did2, kp2) = joiner(&o.room.did).await;
        let out = add(&o, &did2, &kp2).await;
        assert_eq!(out["payload"]["epoch"], 2, "{out}");
        let group = room_groups::load(&o.state.room_groups_ks, &o.room.did)
            .await
            .unwrap()
            .unwrap();
        let group = vti_rooms::mls::RoomGroup::restore(&group.snapshot).unwrap();
        assert!(group.leaf_of(&did).is_none(), "never admitted");
        assert!(group.leaf_of(&did2).is_some());
    }

    /// Without the owner's `admin` grant nothing is built and nothing is sent.
    #[tokio::test]
    async fn no_admin_authority_is_refused_before_anything_is_built() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        crate::vault::storage::delete(
            &o.state.vault_ks,
            &format!("{AUTHORITY_TYPE}-{}", o.room.did),
        )
        .await
        .unwrap();
        let (_s, _d, did, kp) = joiner(&o.room.did).await;
        let out = add(&o, &did, &kp).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/add:noAuthority",
            "{out}"
        );
        assert!(
            room_groups::pending_add(&o.state.room_groups_ks, &o.room.did)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn add_without_a_group_says_so() {
        let o = owner().await;
        let (_s, _d, did, kp) = joiner(&o.room.did).await;
        let out = add(&o, &did, &kp).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/add:noGroup",
            "{out}"
        );
    }
}
