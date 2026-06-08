//! [`AuditEvent`] — the tagged enum of every audit-log variant.
//!
//! Ships the **Phase-0 vocabulary** matching spec §11.4. Phase-1+
//! variants land alongside their owning features (join requests,
//! members, policies, registry, VRC, etc.) and follow the same
//! pattern: one variant per semantically distinct event, with a
//! purpose-built data struct.
//!
//! ## Wire contract
//!
//! - Tagged form `#[serde(tag = "type", content = "data")]` so
//!   external consumers (SIEM, later webhooks) discriminate on the
//!   `type` field. **Variant identifiers are part of the wire
//!   contract — don't rename them without bumping
//!   `EVENT_VERSION`.**
//! - Data structs use `#[serde(rename_all = "camelCase")]` for
//!   downstream tooling friendliness. Field names are also wire
//!   contract.
//!
//! ## Sensitive-field redaction
//!
//! [`ConfigChange::redact_if`] walks a [`ConfigChangedData`] and
//! masks `old_value` / `new_value` for any key matched by the caller-
//! supplied sensitivity predicate. The emitter (config endpoint
//! handlers, M0.8) calls this **before** persisting the event so
//! sensitive values never reach the audit keyspace in cleartext.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::key_store::RotationReason;

/// Marker used in place of redacted config values. Distinguishable
/// from a JSON null / empty string by callers introspecting an
/// archived audit row.
pub const REDACTED_MARKER: &str = "<redacted>";

// ---------------------------------------------------------------------------
// AuditEvent
// ---------------------------------------------------------------------------

/// Audit-event payload. Tagged on `type` with the variant name and
/// the variant's data under `data`. Phase-0 vocabulary only;
/// Phase-1+ adds variants alongside the features that emit them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "data")]
pub enum AuditEvent {
    /// Bootstrap completed — the first admin DID was written into the
    /// ACL and the install carve-out was permanently closed.
    CommunityInstalled(CommunityInstalledData),

    /// `vtc admin emergency-bootstrap` was invoked with a valid
    /// master-seed mnemonic, re-opening the install carve-out exactly
    /// once. Loud event — surfaced prominently in diagnostics on next
    /// daemon start so a forgotten emergency action is impossible to
    /// miss.
    EmergencyBootstrapInvoked(EmergencyBootstrapData),

    /// A passkey was registered against an admin DID (initial enrol
    /// at install **or** a subsequent additional-device enrolment).
    AdminPasskeyRegistered(AdminPasskeyData),

    /// A passkey was revoked from an admin DID. The CAS check that
    /// refuses to leave zero passkeys runs *before* the event is
    /// emitted, so any persisted `AdminPasskeyRevoked` leaves at
    /// least one passkey behind.
    AdminPasskeyRevoked(AdminPasskeyData),

    /// One or more runtime configuration keys were modified via
    /// `PATCH /v1/admin/config`. Per-key sensitivity is honoured —
    /// values for keys flagged sensitive are redacted via
    /// [`ConfigChange::redact_if`] before persistence.
    ConfigChanged(ConfigChangedData),

    /// `POST /v1/admin/config/reload` applied hot-reloadable settings
    /// in-place. Lists which keys actually re-applied (a key that
    /// was unchanged-or-already-active doesn't appear).
    ConfigReloaded(ConfigReloadedData),

    /// `POST /v1/admin/config/restart` initiated graceful shutdown.
    /// Emitted **before** the process exits so the next-boot replay
    /// can correlate the restart with the prior config patches that
    /// triggered it.
    RestartRequested(RestartRequestedData),

    /// `PUT /v1/community/profile` updated one or more profile
    /// fields. Records which fields changed by name; the values
    /// themselves stay out of the audit log (profile data isn't
    /// security-sensitive by nature, but keeping the event small
    /// is operator-friendly).
    CommunityProfileUpdated(CommunityProfileUpdatedData),

    /// The community `audit_key` was rotated. Emitted under the
    /// **new** key (the rotation itself is what creates the new
    /// epoch), so an investigator can find the row by querying the
    /// `audit_by_type` index without needing to walk the prior
    /// epoch.
    AuditKeyRotated(AuditKeyRotatedData),

    /// `PATCH /v1/members/{did}` updated profile or non-role
    /// metadata on a member's record. Lists the field names that
    /// changed; values stay out of the envelope.
    MemberUpdated(MemberUpdatedData),

    /// `PATCH /v1/members/{did}` reassigned the member's role.
    /// Distinct event from `MemberUpdated` because role changes
    /// are security-significant — SIEM filters key on this
    /// variant separately. Admin promotion uses
    /// [`AdminPromoted`] instead (spec §10.4 keeps the two
    /// paths separate).
    RoleChanged(RoleChangedData),

    /// `POST /v1/members/{did}/promote-to-admin` finished with
    /// a successful step-up UV ceremony. Spec §10.4 makes this
    /// its own variant (distinct from `RoleChanged`) so SIEM
    /// rules can target it; admin elevation is the highest-
    /// privilege grant the community emits.
    AdminPromoted(AdminPromotedData),

    /// `POST /v1/join-requests` (REST or DIDComm) accepted a
    /// well-formed submission and persisted it as `Pending`. The
    /// actor on this event is the applicant DID — they're the
    /// principal, even though the daemon's authenticated identity
    /// did not vouch for them.
    JoinRequestSubmitted(JoinRequestData),

    /// An admin / moderator approved a pending join request via
    /// `POST /v1/join-requests/{id}/approve`. Always paired with a
    /// `MemberAdded` emission in the same transaction (the
    /// approve flow writes the ACL + Member rows atomically).
    JoinRequestApproved(JoinRequestData),

    /// An admin / moderator rejected a pending join request. The
    /// `reason` field is operator-supplied and may be empty.
    JoinRequestRejected(JoinRequestRejectedData),

    /// New member row written. Companion event to
    /// `JoinRequestApproved` — the latter is what an audit
    /// query for "who approved this" matches, the former is
    /// what "when did <did> join" matches. Spec §10.1.
    MemberAdded(MemberAddedData),

    /// Member row removed (or anonymised) per spec §10.2. Spec §5
    /// `Disposition` decides whether the row is purged outright,
    /// tombstoned with the DID retained, or kept historical.
    MemberRemoved(MemberRemovedData),

    /// A member discharged the `reciprocate_vmc` obligation: they
    /// counter-signed the issued VMC with a member-issued reciprocal
    /// VC, completing the bidirectional DTG membership edge
    /// (`join-requests/accept/1.0`). The audit envelope's
    /// `target_did` carries the member.
    MembershipReciprocated(MembershipReciprocatedData),

    /// `POST /v1/policies` accepted an upload, compiled the source,
    /// and persisted a new revision. The row is **not yet active** —
    /// activation is a separate event. Spec §7.1; Phase 2 M2.3.
    PolicyUploaded(PolicyUploadedData),

    /// `POST /v1/policies/{id}/activate` flipped the active pointer
    /// for a purpose. Carries the predecessor's id so a forensic
    /// audit can chain backwards through revisions without scanning
    /// the whole `policies:` keyspace. Spec §7.1; Phase 2 M2.3.
    PolicyActivated(PolicyActivatedData),

    /// A new VMC was minted (join-approve or renewal). Spec §6.1.
    VmcIssued(CredentialIssuedData),

    /// A new role VEC was minted (join-approve, renewal, or role
    /// change). Spec §6.1.
    VecIssued(CredentialIssuedData),

    /// `POST /v1/members/me/renew` re-minted the member's VMC +
    /// role VEC. Spec §6.3. `personhood_changed` flips when the
    /// renewal's `personhood.rego` re-eval produced a different
    /// flag than the prior VMC.
    MembershipRenewed(MembershipRenewedData),

    /// A status-list bit was flipped (revocation / suspension).
    /// Spec §6.2.
    StatusListFlipped(StatusListFlippedData),

    /// A member rotated to a fresh DID. The audit envelope's
    /// `actor_did` is the **new** DID (it's the principal going
    /// forward); the prior DID lives in the data struct. Spec
    /// §10.5; Phase 2 M2.15.
    DidRotated(DidRotatedData),

    /// The daemon's trust-registry reachability state flipped
    /// (`active` ↔ `degraded`). Spec §8.1; Phase 3 M3.2. SIEM
    /// filters key on this to alert when the registry connection
    /// drops or recovers.
    RegistryStatusChanged(RegistryStatusChangedData),

    /// A `MembershipSyncer` job completed successfully against
    /// the registry. Spec §8.3; Phase 3 M3.4.
    RegistrySyncSucceeded(RegistrySyncOutcomeData),

    /// A `MembershipSyncer` job flipped to the `Failed` state
    /// after exhausting its retry budget. Spec §8.3 calls these
    /// out for operator attention — failed `Purge` jobs are
    /// silent privacy regressions. Phase 3 M3.4.
    RegistrySyncFailed(RegistrySyncOutcomeData),

    /// A member-initiated `Purge` (RTBF) bypassed the active
    /// `registry.rego.min_disposition` floor. Spec §8.2 calls
    /// these out: RTBF always overrides the policy envelope.
    /// The audit envelope's `actor_did_hash` is the HMAC-hashed
    /// identifier per §11.1; the `actor_did_plain` field is
    /// `None` for these envelopes (privacy-preserving by
    /// construction). Phase 3 M3.6.
    RegistryRecordPolicyOverride(RegistryRecordPolicyOverrideData),

    /// A cross-community session was minted (or denied). Spec
    /// §8.4; Phase 3 M3.10. The `outcome` field discriminates
    /// `minted` from `denied`; the `reason` is populated only
    /// on `denied` and carries one of [`RecognitionError`]'s
    /// stable reason codes
    /// (`issuer-key-unresolved` / `proof-invalid` /
    /// `status-list-failed` / `issuer-not-recognised` /
    /// `registry-unreachable` / `validity-window` / `malformed`
    /// / `role-mapping-denied`).
    CrossCommunitySessionMinted(CrossCommunitySessionMintedData),

    // ─── Phase 4 lifecycle ─────────────────────────────────
    /// A member published a self-issued Verifiable Recognition
    /// Credential (VRC) — a trust edge `issuer-member → subject-
    /// member` per spec §5.4 + §6.1. Phase 4 M4.6. The actor is
    /// the issuer; the target is the subject DID.
    VrcPublished(VrcPublishedData),

    /// A VRC was revoked — either by the original issuer or by
    /// an admin acting on behalf of the community. Phase 4 M4.6.
    /// Per D7, VRCs carry no `credentialStatus`; revocation is
    /// row deletion in the local `relationships:` keyspace.
    VrcRevoked(VrcRevokedData),

    /// A member's personhood flag was asserted true via
    /// `POST /v1/members/{did}/personhood/assert`. Phase 4
    /// M4.3. The actor is the asserter (admin or issuer); the
    /// target is the member. Per D2 review (VP-only assert),
    /// the presented evidence is verified at assert time and
    /// discarded — no `evidence_sha256` field on this envelope.
    PersonhoodAsserted(PersonhoodAssertedData),

    /// A member's personhood flag was revoked. Phase 4 M4.4 +
    /// M4.2.2. The `reason` discriminator pins which of the
    /// three triggers fired: `"admin"` (admin `DELETE`),
    /// `"self"` (member `DELETE`), or `"renewal-policy"`
    /// (renewal-time policy downgrade per D5 review's
    /// `downgrade` arm).
    PersonhoodRevoked(PersonhoodRevokedData),

    /// A custom (non-role) endorsement credential was issued
    /// by an issuer or admin. Phase 4 M4.8. Per D8 review, the
    /// credential carries a `credentialStatus` entry on the
    /// shared `Revocation` status list — `status_list_index`
    /// records the allocated slot.
    CustomEndorsementIssued(CustomEndorsementIssuedData),

    /// A custom endorsement was revoked. Phase 4 M4.8. Flips
    /// the `Revocation` status-list bit at the credential's
    /// `status_list_index`. Paired with a
    /// `StatusListFlipped { purpose: "revocation", index,
    /// revoked: true }` envelope (existing variant) so the
    /// status-list audit surface stays uniform.
    CustomEndorsementRevoked(CustomEndorsementRevokedData),

    /// An operator registered a new custom endorsement type
    /// via `POST /v1/endorsement-types`. Phase 4 M4.8.1 (D4
    /// review). The actor is the admin; the `type_uri` field
    /// records what was registered.
    EndorsementTypeRegistered(EndorsementTypeRegisteredData),

    /// An operator deleted a custom endorsement type via
    /// `DELETE /v1/endorsement-types/{uri}`. Phase 4 M4.8.1.
    /// The registry refuses deletion when at least one live
    /// endorsement of this type still exists; this envelope
    /// only fires after a successful delete.
    EndorsementTypeDeleted(EndorsementTypeDeletedData),

    /// `PUT /v1/website/files/{path}` succeeded. Phase 5 M5.5.2.
    /// Records the path + size + SHA-256 of the new content so the
    /// audit log carries enough material to reconstruct a deploy
    /// without persisting the full file body.
    WebsiteFileWritten(WebsiteFileWrittenData),

    /// `DELETE /v1/website/files/{path}` succeeded. Phase 5
    /// M5.5.2. Records the path; no content digest because the
    /// file no longer exists.
    WebsiteFileDeleted(WebsiteFileDeletedData),

    /// `POST /v1/website/deploy` succeeded. Phase 5 M5.5.3.
    /// Captures the bundle's SHA-256, byte size, target deploy
    /// mode, and (managed mode only) the new generation number
    /// + how many old generations were pruned.
    WebsiteBundleDeployed(WebsiteBundleDeployedData),

    /// `POST /v1/website/rollback/{gen}` succeeded. Phase 5
    /// M5.5.4. Managed mode only. Records the symlink swap so
    /// the audit log surfaces which generation served before vs.
    /// after.
    WebsiteGenerationRolledBack(WebsiteGenerationRolledBackData),

    /// Emitted exactly once at daemon boot when the embedded
    /// admin UX (`admin-ui` cargo feature) is enabled. Captures
    /// the SHA-256 of the baked `index.html` so an operator can
    /// correlate which build of the admin SPA is currently
    /// serving. Phase 5 M5.7.2.
    AdminUiServed(AdminUiServedData),
}

// ---------------------------------------------------------------------------
// Variant data structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CommunityInstalledData {
    pub community_did: String,
    /// `jti` of the install token that was consumed. Lets a forensic
    /// audit correlate the bootstrap with the specific install URL
    /// the operator clicked.
    pub install_token_jti: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EmergencyBootstrapData {
    /// Host name of the machine running the CLI command, as
    /// reported by the OS. Recorded for forensic context — the CLI
    /// can't be trusted, but a mismatch with the expected operator
    /// host is a useful smoke signal.
    pub operator_hostname: String,
    /// Wall clock at the time the CLI ran. Distinct from the
    /// envelope timestamp, which is when the daemon next started
    /// and emitted the event — the gap between the two is itself
    /// audit-worthy.
    pub invoked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AdminPasskeyData {
    /// Hex-encoded WebAuthn credential id. Operator-recognisable;
    /// distinct from the cred_id bytes the storage layer holds.
    pub credential_id_hex: String,
    /// Operator-friendly label (e.g. `"MacBook Air Touch ID"`).
    pub label: String,
    /// `usb` / `nfc` / `ble` / `internal` etc., as WebAuthn reports
    /// them. Helpful for "which device just got revoked" UX.
    pub transports: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigChangedData {
    pub changes: Vec<ConfigChange>,
    /// `true` when at least one changed key is restart-required.
    /// Emitter computes this from the per-key taxonomy (M0.8) so the
    /// audit consumer doesn't need to know the schema.
    pub requires_restart: bool,
}

/// One field's worth of change. `old_value` is `None` if the key
/// wasn't previously set (default-only); `new_value` is the
/// post-PATCH value. Use [`Self::redact_if`] before persisting to
/// mask sensitive values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigChange {
    pub key: String,
    pub old_value: Option<Value>,
    pub new_value: Value,
    pub source_before: ConfigSource,
}

impl ConfigChange {
    /// Mask the value fields in-place if `sensitive(&self.key)`.
    /// Returns `true` if a redaction was applied so the caller can
    /// log it.
    pub fn redact_if<F>(&mut self, sensitive: F) -> bool
    where
        F: Fn(&str) -> bool,
    {
        if sensitive(&self.key) {
            self.old_value = Some(Value::String(REDACTED_MARKER.to_string()));
            self.new_value = Value::String(REDACTED_MARKER.to_string());
            true
        } else {
            false
        }
    }
}

/// Where the prior value came from in the three-layer config
/// overlay. Mirrors the source annotation surfaced on
/// `GET /v1/admin/config` (spec §14.6). Reproduced here so the
/// audit log is self-contained and doesn't need the config module's
/// type to deserialise.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    Env,
    Db,
    Toml,
    Default,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigReloadedData {
    /// Keys that actually re-applied. Excludes keys whose new value
    /// equalled the live value (no-op).
    pub keys_reloaded: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RestartRequestedData {
    /// `restart.drain_timeout` value (seconds) the daemon will use
    /// when draining in-flight requests. Lets an oncall correlate a
    /// long-tail timeout with a restart.
    pub drain_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CommunityProfileUpdatedData {
    /// Names of fields that changed (e.g. `name`, `description`,
    /// `logo_url`, `extensions`). Values themselves stay out of the
    /// audit log.
    pub fields_changed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuditKeyRotatedData {
    pub previous_key_id: String,
    pub new_key_id: String,
    pub rotation_reason: RotationReason,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MemberUpdatedData {
    /// Names of the fields changed on this PATCH (e.g.
    /// `["publishConsent", "departurePreference"]`). Field values
    /// stay out of the audit log — operator-facing extensions data
    /// can be arbitrarily large, and the metadata `publish_consent`
    /// / `departure_preference` shifts are individually
    /// non-sensitive.
    pub fields_changed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RoleChangedData {
    /// Previous role, serialised via the service's role-enum
    /// `Display` impl (e.g. `"moderator"`, `"custom:editor"`).
    /// String-typed so this struct stays in vti-common without
    /// taking a dep on vtc-service's `VtcRole`.
    pub previous_role: String,
    pub new_role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AdminPromotedData {
    /// Role the member held immediately before promotion.
    pub previous_role: String,
    /// Credential id of the passkey used in the step-up UV
    /// ceremony that authorised the promotion. Spec §10.4 calls
    /// out the UV requirement; recording the credential id makes
    /// the chain of authority auditable.
    pub authorising_credential_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestData {
    /// UUID of the JoinRequest row in the `join_requests:` keyspace.
    pub request_id: String,
    /// Transport the request arrived over (`"rest"` / `"didcomm"`),
    /// recorded for diagnostics.
    pub transport: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestRejectedData {
    pub request_id: String,
    /// Operator-supplied reason, capped at 1024 chars at the
    /// route layer. May be empty.
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MemberAddedData {
    /// Role assigned at admission. Phase 1 always emits
    /// `"member"` (the default role on approve); future phases
    /// may emit `"moderator"` / `"issuer"` etc. when invite
    /// flows admit at higher tiers.
    pub role: String,
    /// `request_id` of the JoinRequest the admission resolved.
    /// `None` for out-of-band additions (e.g. emergency bootstrap)
    /// that don't pass through a join request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_join_request_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MemberRemovedData {
    /// `disposition` after resolving `PolicyDefault`. One of
    /// `"purge"`, `"tombstone"`, `"historical"`.
    pub disposition: String,
    /// Optional operator-supplied reason on admin removal. Empty
    /// for self-removal.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

/// Payload for [`AuditEvent::PolicyUploaded`].
///
/// Records the *immutable* outcome of compilation: the new id, what
/// purpose this revision targets, the source hash, and the
/// monotone per-purpose version. The actual Rego source stays in
/// the `policies:<id>` row — the audit envelope only carries the
/// hash so the log doesn't bloat for large policies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyUploadedData {
    /// UUID of the new Policy row.
    pub policy_id: String,
    /// Wire-form camelCase purpose (`"join"`, `"removal"`, …).
    pub purpose: String,
    /// SHA-256 of the source, lowercase hex.
    pub sha256: String,
    /// Per-purpose monotone counter the upload landed under.
    pub version: u32,
}

/// Payload for [`AuditEvent::MembershipReciprocated`].
///
/// The audit envelope's `target_did` already carries the member; this
/// adds the join request that admitted them, the VMC they reciprocated,
/// and the id of the member-issued reciprocal VC, so an investigator can
/// chain "admitted → reciprocated" without scanning the members keyspace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MembershipReciprocatedData {
    /// UUID of the JoinRequest the reciprocation closes.
    pub request_id: String,
    /// `id` of the VMC the member reciprocated (the community → member
    /// half of the edge).
    pub vmc_id: String,
    /// `id` of the member-issued reciprocal VC (the member → community
    /// half).
    pub reciprocal_vc_id: String,
}

/// Payload for [`AuditEvent::VmcIssued`] + [`AuditEvent::VecIssued`].
///
/// The audit envelope's `target_did` already carries the member;
/// this struct adds the credential id + type + the issuance
/// window so an investigator can correlate "who got which VC
/// when" without cross-referencing the credential store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CredentialIssuedData {
    /// VC `id` URI (typically `urn:uuid:<server-allocated>`).
    pub credential_id: String,
    /// Wire-form credential type (`"VerifiableMembershipCredential"`
    /// for VMC, `"VerifiableEndorsementCredential"` for VEC).
    pub credential_type: String,
    /// RFC3339 `validFrom` from the issued VC.
    pub valid_from: String,
    /// RFC3339 `validUntil` from the issued VC.
    pub valid_until: String,
    /// Status-list slot for VMCs (revocation list). `None` for
    /// VECs and other credential types that don't carry a
    /// status-list entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_list_index: Option<u32>,
}

/// Payload for [`AuditEvent::MembershipRenewed`]. Phase 2 M2.13.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MembershipRenewedData {
    /// New VMC id.
    pub vmc_id: String,
    /// New role VEC id.
    pub role_vec_id: String,
    /// Whether the `personhood.rego` re-eval produced a different
    /// flag than the prior VMC (spec §6.3 step 3). Phase 2 ships
    /// the deny-all stub so this is always `false` in MVP; the
    /// field is on the wire from day one so Phase 4's
    /// `assert`/`revoke` endpoints don't break the audit schema.
    pub personhood_changed: bool,
}

/// Payload for [`AuditEvent::StatusListFlipped`]. Phase 2 M2.14.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StatusListFlippedData {
    /// Wire-form status purpose (`"revocation"` / `"suspension"`).
    pub purpose: String,
    /// Slot index that was flipped.
    pub index: u32,
    /// Direction of the flip — `true` = revoked/suspended,
    /// `false` = un-suspended. Revocation flips are one-way per
    /// spec §6.2; suspension flips can go either direction.
    pub revoked: bool,
}

/// Payload for [`AuditEvent::RegistryRecordPolicyOverride`].
/// Phase 3 M3.6. Carries `reason` (always `"rtbf"` in Phase 3
/// — future overrides could land additional reason codes),
/// the attempted disposition the policy would have enforced,
/// and the effective disposition the override produced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RegistryRecordPolicyOverrideData {
    /// Short reason code. Phase 3 only emits `"rtbf"`; the
    /// field is shaped as a free string so Phase 4+ can
    /// introduce additional codes (`"legal-hold"`, etc.)
    /// without bumping the envelope version.
    pub reason: String,
    /// The disposition the active `registry.rego.min_disposition`
    /// would have enforced (e.g. `"tombstone"`).
    pub attempted_disposition: String,
    /// The disposition the override applied (always `"purge"`
    /// for RTBF overrides; Phase 4+ may add new effective
    /// dispositions for legal-hold paths).
    pub effective_disposition: String,
}

/// Payload for [`AuditEvent::RegistrySyncSucceeded`] +
/// [`AuditEvent::RegistrySyncFailed`]. Phase 3 M3.4. The
/// `actor_did` on the envelope is the VTC's own DID; the
/// `target_did` is the member being synced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RegistrySyncOutcomeData {
    /// UUID of the `SyncJob` row.
    pub job_id: String,
    /// Wire-form `SyncJobKind` — `"publishMember"`,
    /// `"updateMember"`, `"deleteMember"`, or
    /// `"markDeparted"`.
    pub kind: String,
    /// Number of attempts the job made (1 for happy-path
    /// succeed-on-first-try, higher when retries fired).
    pub attempts: u32,
    /// On failure: the last error message. On success:
    /// `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Payload for [`AuditEvent::CrossCommunitySessionMinted`].
/// Phase 3 M3.10. The envelope's `actor_did` (HMAC-hashed per
/// §11.1) is the bearer of the foreign credentials — i.e. the
/// caller of `POST /v1/auth/recognise`. The envelope's
/// `target_did` is the local subject DID the session was minted
/// to (same value on `minted`; absent on `denied` because no
/// local subject was established).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CrossCommunitySessionMintedData {
    /// `"minted"` or `"denied"`. Stable wire form so SIEM
    /// rules can key on it.
    pub outcome: String,
    /// Foreign community's issuer DID (e.g.
    /// `did:webvh:peer.example.com:abc`).
    pub foreign_issuer_did: String,
    /// Role claim from the foreign VEC — present even on
    /// `denied` so operators can see what was attempted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foreign_role: Option<String>,
    /// Local role the foreign role mapped onto. Populated on
    /// `minted` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapped_role: Option<String>,
    /// Clamped session TTL in seconds. `min(jwt_default,
    /// vec.validUntil - now, vmc.validUntil - now)`. Populated
    /// on `minted` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    /// On `denied`: a short reason code from
    /// [`RecognitionError::reason_code`] or
    /// `"role-mapping-denied"` for the policy-rejection arm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ─── Phase 4 payload structs ──────────────────────────────

/// Payload for [`AuditEvent::VrcPublished`]. Phase 4 M4.6.
/// Self-issued trust edge from one member to another.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VrcPublishedData {
    /// Server-allocated id (UUID) of the relationship row.
    /// The wire-form `id` lives at `urn:uuid:<vrc_id>` on the
    /// VRC's top-level `id` field.
    pub vrc_id: String,
    /// Subject DID — the *other* member the edge points at.
    /// HMAC-hashed in `target_did_hash` on the envelope; the
    /// raw value lives here only when operator policy allows
    /// (default: omitted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_did: Option<String>,
    /// Free-form trust-relationship type tag from the VRC's
    /// `endorsement.type`. Examples: `"endorses"`, `"reports-to"`,
    /// `"collaborates-with"` — operator-defined.
    pub edge_type: String,
}

/// Payload for [`AuditEvent::VrcRevoked`]. Phase 4 M4.6.
/// Issued whether the original issuer or an admin performed
/// the revocation; the envelope's `actor_did` distinguishes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VrcRevokedData {
    pub vrc_id: String,
    /// `"issuer"` (the original member revoked their own VRC)
    /// or `"admin"` (an admin revoked on behalf of the
    /// community).
    pub revoked_by: String,
}

/// Payload for [`AuditEvent::PersonhoodAsserted`]. Phase 4
/// M4.3. The envelope's `actor_did` is the asserter (admin or
/// issuer); `target_did_hash` is the member.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PersonhoodAssertedData {
    /// VMC id minted with the new `personhood: true` flag.
    /// Empty when the assert ran inside an idempotent retry
    /// that didn't mint a fresh credential.
    pub vmc_id: String,
    /// `now` at assert time, in RFC3339. Persisted on the
    /// Member row as `personhood_asserted_at` (per D2 review,
    /// only the timestamp persists — not the VP itself).
    pub asserted_at: String,
}

/// Payload for [`AuditEvent::PersonhoodRevoked`]. Phase 4
/// M4.4 / M4.2.2.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PersonhoodRevokedData {
    /// VMC id minted with the new `personhood: false` flag.
    /// `None` on the `refuse` arm of `on_personhood_fail`
    /// (no VMC re-mint).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vmc_id: Option<String>,
    /// Discriminator for the three triggers: `"admin"`,
    /// `"self"`, or `"renewal-policy"`.
    pub reason: String,
}

/// Payload for [`AuditEvent::CustomEndorsementIssued`]. Phase 4
/// M4.8.2. The envelope's `actor_did` is the issuer (issuer-
/// role member or admin); `target_did_hash` is the subject.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CustomEndorsementIssuedData {
    /// Server-allocated id (UUID) of the endorsement row.
    pub endorsement_id: String,
    /// The registered endorsement type URI.
    pub endorsement_type: String,
    /// Allocated slot index on the shared `Revocation` status
    /// list (D8 review). Paired with the credential's
    /// `credentialStatus.statusListIndex` field.
    pub status_list_index: u32,
}

/// Payload for [`AuditEvent::CustomEndorsementRevoked`]. Phase 4
/// M4.8.4. Paired with the existing `StatusListFlipped` envelope
/// so the bit-flip is independently auditable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CustomEndorsementRevokedData {
    pub endorsement_id: String,
    pub endorsement_type: String,
}

/// Payload for [`AuditEvent::EndorsementTypeRegistered`].
/// Phase 4 M4.8.1 (D4 review).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EndorsementTypeRegisteredData {
    /// The newly-registered type URI. Operators use this on
    /// the issuance path's `body.type` field.
    pub type_uri: String,
    /// Optional human-readable description supplied at
    /// registration time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Payload for [`AuditEvent::EndorsementTypeDeleted`]. Phase 4
/// M4.8.1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EndorsementTypeDeletedData {
    pub type_uri: String,
}

/// Payload for [`AuditEvent::WebsiteFileWritten`]. Phase 5 M5.5.2.
/// Records enough material to audit the deploy without persisting
/// the file body itself — the SHA-256 + size pin what was written.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WebsiteFileWrittenData {
    /// Path **relative to** `website.root_dir`, NFC-normalised
    /// and free of `..` segments.
    pub path: String,
    /// File size in bytes (post-write).
    pub size_bytes: u64,
    /// SHA-256 of the written content, hex-encoded. Doubles as
    /// the ETag value the response returns to the caller.
    pub sha256: String,
}

/// Payload for [`AuditEvent::WebsiteFileDeleted`]. Phase 5 M5.5.2.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WebsiteFileDeletedData {
    /// Path **relative to** `website.root_dir`, NFC-normalised.
    pub path: String,
}

/// Payload for [`AuditEvent::WebsiteBundleDeployed`]. Phase 5
/// M5.5.3. Live + managed modes share this variant; the
/// `target_generation` + `pruned_generations` fields are populated
/// in managed mode and zero in live mode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WebsiteBundleDeployedData {
    /// SHA-256 of the uploaded tar.gz, hex-encoded.
    pub bundle_sha256: String,
    /// Size of the uploaded tar.gz, in bytes.
    pub bundle_size_bytes: u64,
    /// `"live"` or `"managed"` (matches
    /// `website.deploy_mode`).
    pub deploy_mode: String,
    /// New generation number in managed mode; `0` in live mode.
    pub target_generation: u32,
    /// Number of old generations pruned to honour
    /// `managed_generations_keep` (managed mode only; `0` in
    /// live mode).
    pub pruned_generations: u32,
}

/// Payload for [`AuditEvent::WebsiteGenerationRolledBack`]. Phase
/// 5 M5.5.4. Managed mode only — the symlink swap is the audit
/// surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WebsiteGenerationRolledBackData {
    /// Generation `current` pointed at before the rollback.
    pub from_generation: u32,
    /// Generation `current` now points at.
    pub to_generation: u32,
}

/// Payload for [`AuditEvent::AdminUiServed`]. Phase 5 M5.7.2.
/// Captures enough material that an operator who suspects an
/// admin UX compromise can pin the exact bytes that were baked
/// into the running daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AdminUiServedData {
    /// SHA-256 of the baked `index.html` (hex-encoded). Doubles
    /// as the `version` field of `GET /admin/build-info.json`.
    pub index_sha256: String,
    /// Number of files baked into the binary (informational —
    /// surfaces accidental directory bloat).
    pub file_count: u32,
    /// `"embedded"` or `"external"`. Embedded serves the baked
    /// SPA; external delegates to an operator-supplied origin.
    pub mode: String,
}

/// Payload for [`AuditEvent::RegistryStatusChanged`]. Phase 3
/// M3.2.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RegistryStatusChangedData {
    /// Status before the flip — `"active"` or `"degraded"`.
    pub from: String,
    /// Status after the flip.
    pub to: String,
    /// Optional reason — error string from the last health
    /// probe when flipping to `degraded`, or a short
    /// confirmation message when flipping back to `active`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Payload for [`AuditEvent::DidRotated`]. Phase 2 M2.15.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DidRotatedData {
    pub old_did: String,
    pub new_did: String,
    /// DID method of the new DID — `"did:key"` /
    /// `"did:webvh"`. Spec §10.5 keeps the two paths
    /// cryptographically distinct so SIEM rules can target
    /// each.
    pub method: String,
    /// New VMC id minted in the same transaction (status-list
    /// slot reused). `None` if issuance was skipped (e.g.
    /// daemon misconfiguration).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vmc_id: Option<String>,
    /// New role VEC id minted in the same transaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_vec_id: Option<String>,
}

/// Payload for [`AuditEvent::PolicyActivated`].
///
/// Records the active-pointer flip for a purpose. `previous_policy_id`
/// is `None` when the purpose had no prior active row (first
/// activation for that purpose) — that case is itself audit-worthy
/// and distinct from "activated a successor". Carries the new
/// revision's hash so consumers don't have to cross-reference the
/// `PolicyUploaded` event to know what bytecode is now live.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyActivatedData {
    pub policy_id: String,
    pub purpose: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_policy_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn round_trip(event: &AuditEvent) {
        let s = serde_json::to_string(event).unwrap();
        let back: AuditEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(&back, event);
    }

    fn wire_value(event: &AuditEvent) -> Value {
        serde_json::to_value(event).unwrap()
    }

    // ──────────── tag + content shape ────────────

    #[test]
    fn community_installed_tagged_wire_shape() {
        let e = AuditEvent::CommunityInstalled(CommunityInstalledData {
            community_did: "did:webvh:example.com:abc".into(),
            install_token_jti: "jti-1".into(),
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "CommunityInstalled");
        assert_eq!(v["data"]["communityDid"], "did:webvh:example.com:abc");
        assert_eq!(v["data"]["installTokenJti"], "jti-1");
        round_trip(&e);
    }

    #[test]
    fn emergency_bootstrap_tagged_wire_shape() {
        let invoked_at = DateTime::parse_from_rfc3339("2026-05-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let e = AuditEvent::EmergencyBootstrapInvoked(EmergencyBootstrapData {
            operator_hostname: "ops-01.example.com".into(),
            invoked_at,
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "EmergencyBootstrapInvoked");
        assert_eq!(v["data"]["operatorHostname"], "ops-01.example.com");
        round_trip(&e);
    }

    #[test]
    fn admin_passkey_registered_round_trip() {
        let e = AuditEvent::AdminPasskeyRegistered(AdminPasskeyData {
            credential_id_hex: "deadbeef".into(),
            label: "MacBook Air Touch ID".into(),
            transports: vec!["internal".into(), "hybrid".into()],
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "AdminPasskeyRegistered");
        assert_eq!(v["data"]["credentialIdHex"], "deadbeef");
        assert_eq!(v["data"]["transports"][0], "internal");
        round_trip(&e);
    }

    #[test]
    fn admin_passkey_revoked_round_trip() {
        let e = AuditEvent::AdminPasskeyRevoked(AdminPasskeyData {
            credential_id_hex: "feedface".into(),
            label: "iPhone Face ID".into(),
            transports: vec!["hybrid".into()],
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "AdminPasskeyRevoked");
        round_trip(&e);
    }

    #[test]
    fn config_changed_round_trip() {
        let e = AuditEvent::ConfigChanged(ConfigChangedData {
            changes: vec![ConfigChange {
                key: "log.level".into(),
                old_value: Some(json!("info")),
                new_value: json!("debug"),
                source_before: ConfigSource::Toml,
            }],
            requires_restart: false,
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "ConfigChanged");
        assert_eq!(v["data"]["changes"][0]["key"], "log.level");
        assert_eq!(v["data"]["changes"][0]["newValue"], "debug");
        assert_eq!(v["data"]["changes"][0]["sourceBefore"], "toml");
        round_trip(&e);
    }

    #[test]
    fn config_reloaded_round_trip() {
        let e = AuditEvent::ConfigReloaded(ConfigReloadedData {
            keys_reloaded: vec!["log.level".into(), "audit.retention.config_changed".into()],
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "ConfigReloaded");
        assert_eq!(
            v["data"]["keysReloaded"][1],
            "audit.retention.config_changed"
        );
        round_trip(&e);
    }

    #[test]
    fn restart_requested_round_trip() {
        let e = AuditEvent::RestartRequested(RestartRequestedData {
            drain_timeout_seconds: 30,
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "RestartRequested");
        assert_eq!(v["data"]["drainTimeoutSeconds"], 30);
        round_trip(&e);
    }

    #[test]
    fn community_profile_updated_round_trip() {
        let e = AuditEvent::CommunityProfileUpdated(CommunityProfileUpdatedData {
            fields_changed: vec!["name".into(), "logo_url".into()],
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "CommunityProfileUpdated");
        assert_eq!(v["data"]["fieldsChanged"][0], "name");
        round_trip(&e);
    }

    #[test]
    fn audit_key_rotated_round_trip() {
        let e = AuditEvent::AuditKeyRotated(AuditKeyRotatedData {
            previous_key_id: "11111111-1111-1111-1111-111111111111".into(),
            new_key_id: "22222222-2222-2222-2222-222222222222".into(),
            rotation_reason: RotationReason::Rtbf,
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "AuditKeyRotated");
        assert_eq!(v["data"]["rotationReason"], "Rtbf");
        round_trip(&e);
    }

    // ──────────── ConfigChange::redact_if ────────────

    #[test]
    fn redact_if_masks_sensitive_keys() {
        let mut change = ConfigChange {
            key: "server.tls.cert_path".into(),
            old_value: Some(json!("/etc/old.pem")),
            new_value: json!("/etc/new.pem"),
            source_before: ConfigSource::Db,
        };
        let redacted = change.redact_if(|k| k.starts_with("server.tls."));
        assert!(redacted);
        assert_eq!(change.old_value, Some(json!(REDACTED_MARKER)));
        assert_eq!(change.new_value, json!(REDACTED_MARKER));
        // Key + source survive — redaction is value-only.
        assert_eq!(change.key, "server.tls.cert_path");
        assert_eq!(change.source_before, ConfigSource::Db);
    }

    #[test]
    fn redact_if_leaves_non_sensitive_keys_untouched() {
        let mut change = ConfigChange {
            key: "log.level".into(),
            old_value: Some(json!("info")),
            new_value: json!("debug"),
            source_before: ConfigSource::Toml,
        };
        let original = change.clone();
        let redacted = change.redact_if(|k| k.starts_with("server.tls."));
        assert!(!redacted);
        assert_eq!(change, original);
    }

    #[test]
    fn redact_if_handles_unset_old_value() {
        let mut change = ConfigChange {
            key: "server.tls.key_path".into(),
            old_value: None,
            new_value: json!("/etc/new.key"),
            source_before: ConfigSource::Default,
        };
        change.redact_if(|k| k.starts_with("server.tls."));
        // Even when the previous value was unset, redaction inserts a
        // <redacted> marker so the audit record can't be distinguished
        // from "previously empty, now empty" — preserves the
        // sensitivity boundary.
        assert_eq!(change.old_value, Some(json!(REDACTED_MARKER)));
    }

    // ──────────── Variant catalog snapshot ────────────
    //
    // Pins the wire-discriminator strings. Renaming a variant
    // breaks SIEM ingestion and webhook consumers; this test makes
    // such a change visible in review.

    #[test]
    fn policy_uploaded_round_trip() {
        let e = AuditEvent::PolicyUploaded(PolicyUploadedData {
            policy_id: "11111111-1111-1111-1111-111111111111".into(),
            purpose: "join".into(),
            sha256: "abc123".into(),
            version: 4,
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "PolicyUploaded");
        assert_eq!(
            v["data"]["policyId"],
            "11111111-1111-1111-1111-111111111111"
        );
        assert_eq!(v["data"]["purpose"], "join");
        assert_eq!(v["data"]["sha256"], "abc123");
        assert_eq!(v["data"]["version"], 4);
        round_trip(&e);
    }

    #[test]
    fn policy_activated_round_trip_with_predecessor() {
        let e = AuditEvent::PolicyActivated(PolicyActivatedData {
            policy_id: "22222222-2222-2222-2222-222222222222".into(),
            purpose: "removal".into(),
            sha256: "deadbeef".into(),
            previous_policy_id: Some("11111111-1111-1111-1111-111111111111".into()),
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "PolicyActivated");
        assert_eq!(
            v["data"]["previousPolicyId"],
            "11111111-1111-1111-1111-111111111111"
        );
        round_trip(&e);
    }

    #[test]
    fn policy_activated_omits_predecessor_when_none() {
        // First activation for a purpose has no predecessor — verify
        // the field is omitted on the wire (Option skip), not
        // serialised as `null`. SIEM filters key on field presence.
        let e = AuditEvent::PolicyActivated(PolicyActivatedData {
            policy_id: "22222222-2222-2222-2222-222222222222".into(),
            purpose: "personhood".into(),
            sha256: "cafe".into(),
            previous_policy_id: None,
        });
        let v = wire_value(&e);
        assert!(
            v["data"].get("previousPolicyId").is_none(),
            "previousPolicyId should be omitted, got {v}"
        );
        round_trip(&e);
    }

    #[test]
    fn vmc_issued_round_trip() {
        let e = AuditEvent::VmcIssued(CredentialIssuedData {
            credential_id: "urn:uuid:11111111-1111-1111-1111-111111111111".into(),
            credential_type: "VerifiableMembershipCredential".into(),
            valid_from: "2026-05-12T00:00:00Z".into(),
            valid_until: "2026-06-11T00:00:00Z".into(),
            status_list_index: Some(42),
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "VmcIssued");
        assert_eq!(
            v["data"]["credentialType"],
            "VerifiableMembershipCredential"
        );
        assert_eq!(v["data"]["statusListIndex"], 42);
        round_trip(&e);
    }

    #[test]
    fn vec_issued_round_trip_omits_status_list_index_when_none() {
        let e = AuditEvent::VecIssued(CredentialIssuedData {
            credential_id: "urn:uuid:22222222-2222-2222-2222-222222222222".into(),
            credential_type: "VerifiableEndorsementCredential".into(),
            valid_from: "2026-05-12T00:00:00Z".into(),
            valid_until: "2026-06-11T00:00:00Z".into(),
            status_list_index: None,
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "VecIssued");
        assert!(
            v["data"].get("statusListIndex").is_none(),
            "statusListIndex should be omitted when None, got {v}"
        );
        round_trip(&e);
    }

    #[test]
    fn membership_renewed_round_trip() {
        let e = AuditEvent::MembershipRenewed(MembershipRenewedData {
            vmc_id: "urn:uuid:vmc-1".into(),
            role_vec_id: "urn:uuid:vec-1".into(),
            personhood_changed: true,
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "MembershipRenewed");
        assert_eq!(v["data"]["personhoodChanged"], true);
        round_trip(&e);
    }

    #[test]
    fn status_list_flipped_round_trip() {
        let e = AuditEvent::StatusListFlipped(StatusListFlippedData {
            purpose: "revocation".into(),
            index: 7,
            revoked: true,
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "StatusListFlipped");
        assert_eq!(v["data"]["purpose"], "revocation");
        assert_eq!(v["data"]["index"], 7);
        assert_eq!(v["data"]["revoked"], true);
        round_trip(&e);
    }

    #[test]
    fn did_rotated_round_trip_with_credential_ids() {
        let e = AuditEvent::DidRotated(DidRotatedData {
            old_did: "did:key:zOld".into(),
            new_did: "did:key:zNew".into(),
            method: "did:key".into(),
            vmc_id: Some("urn:uuid:vmc-2".into()),
            role_vec_id: Some("urn:uuid:vec-2".into()),
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "DidRotated");
        assert_eq!(v["data"]["method"], "did:key");
        assert_eq!(v["data"]["oldDid"], "did:key:zOld");
        assert_eq!(v["data"]["newDid"], "did:key:zNew");
        assert_eq!(v["data"]["vmcId"], "urn:uuid:vmc-2");
        round_trip(&e);
    }

    #[test]
    fn did_rotated_omits_credential_ids_when_none() {
        let e = AuditEvent::DidRotated(DidRotatedData {
            old_did: "did:key:zOld".into(),
            new_did: "did:key:zNew".into(),
            method: "did:key".into(),
            vmc_id: None,
            role_vec_id: None,
        });
        let v = wire_value(&e);
        assert!(v["data"].get("vmcId").is_none());
        assert!(v["data"].get("roleVecId").is_none());
        round_trip(&e);
    }

    #[test]
    fn registry_sync_succeeded_round_trip() {
        let e = AuditEvent::RegistrySyncSucceeded(RegistrySyncOutcomeData {
            job_id: "11111111-1111-1111-1111-111111111111".into(),
            kind: "publishMember".into(),
            attempts: 1,
            last_error: None,
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "RegistrySyncSucceeded");
        assert_eq!(v["data"]["kind"], "publishMember");
        assert_eq!(v["data"]["attempts"], 1);
        assert!(
            v["data"].get("lastError").is_none(),
            "lastError should be omitted on success: {v}"
        );
        round_trip(&e);
    }

    #[test]
    fn registry_sync_failed_round_trip_carries_last_error() {
        let e = AuditEvent::RegistrySyncFailed(RegistrySyncOutcomeData {
            job_id: "22222222-2222-2222-2222-222222222222".into(),
            kind: "deleteMember".into(),
            attempts: 17,
            last_error: Some("permanent: bad input".into()),
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "RegistrySyncFailed");
        assert_eq!(v["data"]["attempts"], 17);
        assert_eq!(v["data"]["lastError"], "permanent: bad input");
        round_trip(&e);
    }

    #[test]
    fn registry_status_changed_round_trip() {
        let e = AuditEvent::RegistryStatusChanged(RegistryStatusChangedData {
            from: "active".into(),
            to: "degraded".into(),
            reason: Some("connection refused".into()),
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "RegistryStatusChanged");
        assert_eq!(v["data"]["from"], "active");
        assert_eq!(v["data"]["to"], "degraded");
        assert_eq!(v["data"]["reason"], "connection refused");
        round_trip(&e);
    }

    #[test]
    fn registry_status_changed_omits_reason_when_none() {
        let e = AuditEvent::RegistryStatusChanged(RegistryStatusChangedData {
            from: "degraded".into(),
            to: "active".into(),
            reason: None,
        });
        let v = wire_value(&e);
        assert!(
            v["data"].get("reason").is_none(),
            "reason should be omitted when None, got {v}"
        );
        round_trip(&e);
    }

    #[test]
    fn registry_record_policy_override_round_trip() {
        let e = AuditEvent::RegistryRecordPolicyOverride(RegistryRecordPolicyOverrideData {
            reason: "rtbf".into(),
            attempted_disposition: "tombstone".into(),
            effective_disposition: "purge".into(),
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "RegistryRecordPolicyOverride");
        assert_eq!(v["data"]["reason"], "rtbf");
        assert_eq!(v["data"]["attemptedDisposition"], "tombstone");
        assert_eq!(v["data"]["effectiveDisposition"], "purge");
        round_trip(&e);
    }

    #[test]
    fn cross_community_session_minted_round_trip() {
        let e = AuditEvent::CrossCommunitySessionMinted(CrossCommunitySessionMintedData {
            outcome: "minted".into(),
            foreign_issuer_did: "did:webvh:peer.example.com:abc".into(),
            foreign_role: Some("moderator".into()),
            mapped_role: Some("monitor".into()),
            ttl_seconds: Some(900),
            reason: None,
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "CrossCommunitySessionMinted");
        assert_eq!(v["data"]["outcome"], "minted");
        assert_eq!(
            v["data"]["foreignIssuerDid"],
            "did:webvh:peer.example.com:abc"
        );
        assert_eq!(v["data"]["foreignRole"], "moderator");
        assert_eq!(v["data"]["mappedRole"], "monitor");
        assert_eq!(v["data"]["ttlSeconds"], 900);
        assert!(
            v["data"].get("reason").is_none(),
            "reason should be omitted on minted: {v}"
        );
        round_trip(&e);
    }

    #[test]
    fn cross_community_session_minted_denied_carries_reason() {
        let e = AuditEvent::CrossCommunitySessionMinted(CrossCommunitySessionMintedData {
            outcome: "denied".into(),
            foreign_issuer_did: "did:webvh:peer.example.com:abc".into(),
            foreign_role: Some("admin".into()),
            mapped_role: None,
            ttl_seconds: None,
            reason: Some("issuer-not-recognised".into()),
        });
        let v = wire_value(&e);
        assert_eq!(v["data"]["outcome"], "denied");
        assert_eq!(v["data"]["reason"], "issuer-not-recognised");
        assert!(v["data"].get("mappedRole").is_none());
        assert!(v["data"].get("ttlSeconds").is_none());
        round_trip(&e);
    }

    // ─── Phase 4 round-trip coverage ───────────────────

    #[test]
    fn vrc_published_round_trip() {
        let e = AuditEvent::VrcPublished(VrcPublishedData {
            vrc_id: "11111111-1111-1111-1111-111111111111".into(),
            subject_did: Some("did:key:zSubject".into()),
            edge_type: "endorses".into(),
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "VrcPublished");
        assert_eq!(v["data"]["vrcId"], "11111111-1111-1111-1111-111111111111");
        assert_eq!(v["data"]["subjectDid"], "did:key:zSubject");
        assert_eq!(v["data"]["edgeType"], "endorses");
        round_trip(&e);
    }

    #[test]
    fn vrc_published_omits_subject_did_when_none() {
        let e = AuditEvent::VrcPublished(VrcPublishedData {
            vrc_id: "id".into(),
            subject_did: None,
            edge_type: "reports-to".into(),
        });
        let v = wire_value(&e);
        assert!(v["data"].get("subjectDid").is_none());
        round_trip(&e);
    }

    #[test]
    fn vrc_revoked_round_trip() {
        let e = AuditEvent::VrcRevoked(VrcRevokedData {
            vrc_id: "id".into(),
            revoked_by: "issuer".into(),
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "VrcRevoked");
        assert_eq!(v["data"]["revokedBy"], "issuer");
        round_trip(&e);
    }

    #[test]
    fn personhood_asserted_round_trip() {
        let e = AuditEvent::PersonhoodAsserted(PersonhoodAssertedData {
            vmc_id: "vmc-7".into(),
            asserted_at: "2026-05-14T10:00:00Z".into(),
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "PersonhoodAsserted");
        assert_eq!(v["data"]["vmcId"], "vmc-7");
        assert_eq!(v["data"]["assertedAt"], "2026-05-14T10:00:00Z");
        round_trip(&e);
    }

    #[test]
    fn personhood_revoked_round_trip() {
        let e = AuditEvent::PersonhoodRevoked(PersonhoodRevokedData {
            vmc_id: Some("vmc-8".into()),
            reason: "admin".into(),
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "PersonhoodRevoked");
        assert_eq!(v["data"]["vmcId"], "vmc-8");
        assert_eq!(v["data"]["reason"], "admin");
        round_trip(&e);
    }

    #[test]
    fn personhood_revoked_omits_vmc_id_when_refuse_arm() {
        // `refuse` arm of on_personhood_fail doesn't re-mint
        // a VMC, so vmc_id is None.
        let e = AuditEvent::PersonhoodRevoked(PersonhoodRevokedData {
            vmc_id: None,
            reason: "renewal-policy".into(),
        });
        let v = wire_value(&e);
        assert!(v["data"].get("vmcId").is_none());
        assert_eq!(v["data"]["reason"], "renewal-policy");
        round_trip(&e);
    }

    #[test]
    fn custom_endorsement_issued_round_trip() {
        let e = AuditEvent::CustomEndorsementIssued(CustomEndorsementIssuedData {
            endorsement_id: "end-1".into(),
            endorsement_type: "https://example.com/v1/skills/rust".into(),
            status_list_index: 42,
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "CustomEndorsementIssued");
        assert_eq!(
            v["data"]["endorsementType"],
            "https://example.com/v1/skills/rust"
        );
        assert_eq!(v["data"]["statusListIndex"], 42);
        round_trip(&e);
    }

    #[test]
    fn custom_endorsement_revoked_round_trip() {
        let e = AuditEvent::CustomEndorsementRevoked(CustomEndorsementRevokedData {
            endorsement_id: "end-1".into(),
            endorsement_type: "https://example.com/v1/skills/rust".into(),
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "CustomEndorsementRevoked");
        round_trip(&e);
    }

    #[test]
    fn endorsement_type_registered_round_trip() {
        let e = AuditEvent::EndorsementTypeRegistered(EndorsementTypeRegisteredData {
            type_uri: "https://example.com/v1/skills/rust".into(),
            description: Some("Rust proficiency endorsement".into()),
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "EndorsementTypeRegistered");
        assert_eq!(v["data"]["typeUri"], "https://example.com/v1/skills/rust");
        assert_eq!(v["data"]["description"], "Rust proficiency endorsement");
        round_trip(&e);
    }

    #[test]
    fn endorsement_type_registered_omits_description_when_none() {
        let e = AuditEvent::EndorsementTypeRegistered(EndorsementTypeRegisteredData {
            type_uri: "https://example.com/v1/x".into(),
            description: None,
        });
        let v = wire_value(&e);
        assert!(v["data"].get("description").is_none());
        round_trip(&e);
    }

    #[test]
    fn endorsement_type_deleted_round_trip() {
        let e = AuditEvent::EndorsementTypeDeleted(EndorsementTypeDeletedData {
            type_uri: "https://example.com/v1/skills/rust".into(),
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "EndorsementTypeDeleted");
        round_trip(&e);
    }

    #[test]
    fn variant_discriminator_strings() {
        let cases: Vec<(AuditEvent, &str)> = vec![
            (
                AuditEvent::CommunityInstalled(CommunityInstalledData {
                    community_did: "did:webvh:x".into(),
                    install_token_jti: "j".into(),
                }),
                "CommunityInstalled",
            ),
            (
                AuditEvent::EmergencyBootstrapInvoked(EmergencyBootstrapData {
                    operator_hostname: "h".into(),
                    invoked_at: Utc::now(),
                }),
                "EmergencyBootstrapInvoked",
            ),
            (
                AuditEvent::AdminPasskeyRegistered(AdminPasskeyData {
                    credential_id_hex: "0".into(),
                    label: "x".into(),
                    transports: vec![],
                }),
                "AdminPasskeyRegistered",
            ),
            (
                AuditEvent::AdminPasskeyRevoked(AdminPasskeyData {
                    credential_id_hex: "0".into(),
                    label: "x".into(),
                    transports: vec![],
                }),
                "AdminPasskeyRevoked",
            ),
            (
                AuditEvent::ConfigChanged(ConfigChangedData {
                    changes: vec![],
                    requires_restart: false,
                }),
                "ConfigChanged",
            ),
            (
                AuditEvent::ConfigReloaded(ConfigReloadedData {
                    keys_reloaded: vec![],
                }),
                "ConfigReloaded",
            ),
            (
                AuditEvent::RestartRequested(RestartRequestedData {
                    drain_timeout_seconds: 0,
                }),
                "RestartRequested",
            ),
            (
                AuditEvent::CommunityProfileUpdated(CommunityProfileUpdatedData {
                    fields_changed: vec![],
                }),
                "CommunityProfileUpdated",
            ),
            (
                AuditEvent::AuditKeyRotated(AuditKeyRotatedData {
                    previous_key_id: "p".into(),
                    new_key_id: "n".into(),
                    rotation_reason: RotationReason::Initial,
                }),
                "AuditKeyRotated",
            ),
            (
                AuditEvent::PolicyUploaded(PolicyUploadedData {
                    policy_id: "p".into(),
                    purpose: "join".into(),
                    sha256: "x".into(),
                    version: 1,
                }),
                "PolicyUploaded",
            ),
            (
                AuditEvent::PolicyActivated(PolicyActivatedData {
                    policy_id: "p".into(),
                    purpose: "join".into(),
                    sha256: "x".into(),
                    previous_policy_id: None,
                }),
                "PolicyActivated",
            ),
            (
                AuditEvent::VmcIssued(CredentialIssuedData {
                    credential_id: "id".into(),
                    credential_type: "VerifiableMembershipCredential".into(),
                    valid_from: "vf".into(),
                    valid_until: "vu".into(),
                    status_list_index: None,
                }),
                "VmcIssued",
            ),
            (
                AuditEvent::VecIssued(CredentialIssuedData {
                    credential_id: "id".into(),
                    credential_type: "VerifiableEndorsementCredential".into(),
                    valid_from: "vf".into(),
                    valid_until: "vu".into(),
                    status_list_index: None,
                }),
                "VecIssued",
            ),
            (
                AuditEvent::MembershipRenewed(MembershipRenewedData {
                    vmc_id: "v".into(),
                    role_vec_id: "r".into(),
                    personhood_changed: false,
                }),
                "MembershipRenewed",
            ),
            (
                AuditEvent::StatusListFlipped(StatusListFlippedData {
                    purpose: "revocation".into(),
                    index: 0,
                    revoked: true,
                }),
                "StatusListFlipped",
            ),
            (
                AuditEvent::DidRotated(DidRotatedData {
                    old_did: "o".into(),
                    new_did: "n".into(),
                    method: "did:key".into(),
                    vmc_id: None,
                    role_vec_id: None,
                }),
                "DidRotated",
            ),
            (
                AuditEvent::RegistryStatusChanged(RegistryStatusChangedData {
                    from: "active".into(),
                    to: "degraded".into(),
                    reason: None,
                }),
                "RegistryStatusChanged",
            ),
            (
                AuditEvent::RegistrySyncSucceeded(RegistrySyncOutcomeData {
                    job_id: "j".into(),
                    kind: "publishMember".into(),
                    attempts: 1,
                    last_error: None,
                }),
                "RegistrySyncSucceeded",
            ),
            (
                AuditEvent::RegistrySyncFailed(RegistrySyncOutcomeData {
                    job_id: "j".into(),
                    kind: "deleteMember".into(),
                    attempts: 1,
                    last_error: Some("x".into()),
                }),
                "RegistrySyncFailed",
            ),
            (
                AuditEvent::RegistryRecordPolicyOverride(RegistryRecordPolicyOverrideData {
                    reason: "rtbf".into(),
                    attempted_disposition: "tombstone".into(),
                    effective_disposition: "purge".into(),
                }),
                "RegistryRecordPolicyOverride",
            ),
            (
                AuditEvent::CrossCommunitySessionMinted(CrossCommunitySessionMintedData {
                    outcome: "minted".into(),
                    foreign_issuer_did: "did:webvh:peer".into(),
                    foreign_role: Some("moderator".into()),
                    mapped_role: Some("monitor".into()),
                    ttl_seconds: Some(900),
                    reason: None,
                }),
                "CrossCommunitySessionMinted",
            ),
            (
                AuditEvent::VrcPublished(VrcPublishedData {
                    vrc_id: "id".into(),
                    subject_did: Some("did:key:zX".into()),
                    edge_type: "endorses".into(),
                }),
                "VrcPublished",
            ),
            (
                AuditEvent::VrcRevoked(VrcRevokedData {
                    vrc_id: "id".into(),
                    revoked_by: "admin".into(),
                }),
                "VrcRevoked",
            ),
            (
                AuditEvent::PersonhoodAsserted(PersonhoodAssertedData {
                    vmc_id: "v".into(),
                    asserted_at: "2026-05-14T10:00:00Z".into(),
                }),
                "PersonhoodAsserted",
            ),
            (
                AuditEvent::PersonhoodRevoked(PersonhoodRevokedData {
                    vmc_id: Some("v".into()),
                    reason: "self".into(),
                }),
                "PersonhoodRevoked",
            ),
            (
                AuditEvent::CustomEndorsementIssued(CustomEndorsementIssuedData {
                    endorsement_id: "end".into(),
                    endorsement_type: "https://x/v1/t".into(),
                    status_list_index: 0,
                }),
                "CustomEndorsementIssued",
            ),
            (
                AuditEvent::CustomEndorsementRevoked(CustomEndorsementRevokedData {
                    endorsement_id: "end".into(),
                    endorsement_type: "https://x/v1/t".into(),
                }),
                "CustomEndorsementRevoked",
            ),
            (
                AuditEvent::EndorsementTypeRegistered(EndorsementTypeRegisteredData {
                    type_uri: "https://x/v1/t".into(),
                    description: None,
                }),
                "EndorsementTypeRegistered",
            ),
            (
                AuditEvent::EndorsementTypeDeleted(EndorsementTypeDeletedData {
                    type_uri: "https://x/v1/t".into(),
                }),
                "EndorsementTypeDeleted",
            ),
            (
                AuditEvent::WebsiteFileWritten(WebsiteFileWrittenData {
                    path: "index.html".into(),
                    size_bytes: 42,
                    sha256: "deadbeef".into(),
                }),
                "WebsiteFileWritten",
            ),
            (
                AuditEvent::WebsiteFileDeleted(WebsiteFileDeletedData {
                    path: "old.html".into(),
                }),
                "WebsiteFileDeleted",
            ),
            (
                AuditEvent::WebsiteBundleDeployed(WebsiteBundleDeployedData {
                    bundle_sha256: "deadbeef".into(),
                    bundle_size_bytes: 1024,
                    deploy_mode: "managed".into(),
                    target_generation: 7,
                    pruned_generations: 2,
                }),
                "WebsiteBundleDeployed",
            ),
            (
                AuditEvent::WebsiteGenerationRolledBack(WebsiteGenerationRolledBackData {
                    from_generation: 7,
                    to_generation: 5,
                }),
                "WebsiteGenerationRolledBack",
            ),
            (
                AuditEvent::AdminUiServed(AdminUiServedData {
                    index_sha256: "deadbeef".into(),
                    file_count: 3,
                    mode: "embedded".into(),
                }),
                "AdminUiServed",
            ),
        ];
        for (event, expected) in cases {
            let v = serde_json::to_value(&event).unwrap();
            assert_eq!(v["type"], expected, "discriminator drift for {expected}");
        }
    }
}
