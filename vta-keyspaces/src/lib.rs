//! Central registry of the VTA's keyspace names.
//!
//! Every `store.keyspace(..)` call in the VTA (`vta-service` server, offline
//! CLIs, backup, tests) names its keyspace through a `const` here rather than a
//! bare string literal. This is the single source of truth that killed the
//! `"imported"` / `"imported_secrets"` test-vs-production divergence (a test
//! opened a *different*, empty keyspace than the one production writes). The
//! `no_bare_keyspace_literals` guard in `vta-service` keeps it that way by
//! scanning that crate's source for bare `.keyspace("…")` literals.
//!
//! Keyspace *names* live here; per-keyspace *key formats* (the `key:`, `seed:`,
//! `path_counter:` … record families inside a keyspace) are a separate concern
//! and are not yet centralised.
//!
//! A near-leaf crate: it holds the shared keyspace vocabulary (the name
//! constants) plus the [`Keyspaces`] handle bundle, so that every VTA subsystem
//! crate can name and pass keyspaces without depending on `vta-service`. Its
//! only dependency is `vti-common` (for `KeyspaceHandle`).

use vti_common::store::KeyspaceHandle;

/// Shared bundle of borrowed keyspace handles passed to operations that need
/// several keyspaces at once.
///
/// The struct is a pure field bundle — the constructors that borrow it from a
/// concrete `AppState` / `VtaState` live in `vta-service` (they know those
/// types), so this stays free of any `vta-service` dependency.
pub struct Keyspaces<'a> {
    pub keys: &'a KeyspaceHandle,
    pub acl: &'a KeyspaceHandle,
    pub contexts: &'a KeyspaceHandle,
    pub did_templates: &'a KeyspaceHandle,
    pub audit: &'a KeyspaceHandle,
    pub imported: &'a KeyspaceHandle,
    /// Per-context agent memory ([`MEMORY`]). Here so a context deletion can
    /// take the context's entries with it.
    pub memory: &'a KeyspaceHandle,
    /// Per-context application state ([`APP_STATE`]). Here so a context
    /// deletion can take the context's records with it — left behind, they
    /// reappear in any new context created under the same id.
    pub app_state: &'a KeyspaceHandle,
    /// Non-extractable internal key material ([`INTERNAL_KEYS`]), so a context
    /// deletion takes the material of the context's internal keys with their
    /// records.
    pub internal: &'a KeyspaceHandle,
    /// The holder's credential vault ([`VAULT`]): credentials and vault entries
    /// in a context's custody go with the context.
    pub vault: &'a KeyspaceHandle,
    /// Inbound-messaging consent ([`CONSENT`]): grants and pending requests
    /// decided in a context go with it.
    pub consent: &'a KeyspaceHandle,
    /// Per-(platform, context) approver bindings ([`CONSENT_APPROVERS`]).
    pub consent_approvers: &'a KeyspaceHandle,
    /// The persona store ([`PERSONA`]): its context-scoped half goes with the
    /// context.
    pub persona: &'a KeyspaceHandle,
    /// Hidden-vetting and voting engine state ([`PCS_ENGINE`]), each record
    /// naming the context its key is derived under.
    pub pcs_engine: &'a KeyspaceHandle,
    /// Notifications held for the principal ([`NOTIFICATIONS`]), per context.
    pub notifications: &'a KeyspaceHandle,
    /// External accounts ([`EXTERNAL_ACCOUNTS`]), keyed by context.
    pub external_accounts: &'a KeyspaceHandle,
    /// The wrapped secrets of external accounts ([`EXTERNAL_SECRETS`]).
    pub external_secrets: &'a KeyspaceHandle,
    /// Collection claims, conflicts and settings ([`COLLECTION`]). Here so a
    /// context deletion ends every claim for its identifiers (VTI-NTF-090) and
    /// drops its setting, so a context created again under the id starts
    /// enabled (VTI-NTF-094).
    pub collection: &'a KeyspaceHandle,
    #[cfg(feature = "webvh")]
    pub webvh: &'a KeyspaceHandle,
}

/// Master seed + key records (`key:`, `seed:`, `path_counter:`,
/// `active_seed_id`, `imported_kek_salt`, …) and the backup import sentinel.
pub const KEYS: &str = "keys";
/// Auth sessions + challenges.
pub const SESSIONS: &str = "sessions";
/// ACL entries + the seal record + the integrity-anchor root.
pub const ACL: &str = "acl";
/// Trust contexts (the BIP-32 key hierarchy roots).
pub const CONTEXTS: &str = "contexts";
/// Stored DID templates (global + context-scoped).
pub const DID_TEMPLATES: &str = "did_templates";
/// Audit log.
pub const AUDIT: &str = "audit";
/// The keyed-hash keys the audit log commits actor and target identifiers
/// under, and their history.
///
/// Separate from [`AUDIT`] because the two have opposite lifetimes: entries
/// are erased when their retention expires, and a key must outlive every entry
/// that references it or those entries stop being checkable against a
/// candidate identifier.
pub const AUDIT_KEY: &str = "audit_key";
/// Imported secret material (KEK-wrapped). Named `imported_secrets`, **not**
/// `imported` — the latter was a long-standing test-only typo that operated on
/// an empty keyspace disjoint from production. Always reference this const.
pub const IMPORTED_SECRETS: &str = "imported_secrets";
/// Non-extractable internal signing keys.
///
/// Deliberately **not** [`IMPORTED_SECRETS`]: that keyspace wraps its contents
/// under a KEK derived from the BIP-39 master seed, so anything stored there is
/// reconstructible by whoever holds the mnemonic. Internal keys exist precisely
/// to have no such path — their material is generated from the system CSPRNG,
/// never derived, and lives here instead.
///
/// In [`EXCLUDED_FROM_BACKUP`] by design, not by omission. A backup containing
/// this keyspace would be an export of keys the VTA promises never to export.
pub const INTERNAL_KEYS: &str = "internal_keys";
/// Holder credential vault (third-party secrets stored on this VTA).
pub const VAULT: &str = "vault";
/// Persistent runtime service-enable state (`operations::protocol::runtime_state`).
pub const SERVICE_STATE: &str = "service_state";
/// Sealed-bootstrap anti-replay nonce log.
pub const SEALED_NONCES: &str = "sealed_nonces";
/// In-flight backup-bundle control-plane records.
pub const BACKUP_BUNDLES: &str = "backup_bundles";
/// WebVH DID records + `did.jsonl` state.
pub const WEBVH: &str = "webvh";
/// In-flight passkey-as-verificationMethod enrolment state.
pub const PASSKEY_VMS: &str = "passkey_vms";
/// Persisted protocol-management drain set.
pub const DRAINS: &str = "drains";
/// Per-kind previous-config snapshots for fail-forward rollback.
/// (Historically `operations::protocol::snapshot::KEYSPACE_NAME`.)
pub const SNAPSHOT: &str = "service_prev_config";
/// KMS-protected, unencrypted boot keyspace (TEE integrity manifest, etc.).
pub const BOOTSTRAP: &str = "bootstrap";
/// Inbound-messaging consent: durable grants + TTL'd pending requests
/// (`vti_common::consent`). The VTA is the first gate for bridged conversations.
pub const CONSENT: &str = "consent";
/// Per-(platform, context) approver bindings — who decides consent and how the
/// prompt routes (`vti_common::consent::ApproverBinding`).
pub const CONSENT_APPROVERS: &str = "consent_approvers";
/// VTA-issued credentials (minted by `vta/credentials/issue/0.1`, revoked by
/// `vta/credentials/revoke/0.1`). One record per credential keyed `cred:<id>`;
/// revocation is a tombstone (`revokedAt` set in place), not a delete. Distinct
/// from [`VAULT`] (which stores credentials the holder *holds*).
pub const ISSUED_CREDENTIALS: &str = "issued_credentials";

/// Per-context key/value store for AI-agent memory (`vta/memory/{put,list,
/// delete}/0.1`). One record per `(contextId, key)` pair, keyed
/// `mem:<contextId>:<key>`; `list` is a `mem:<contextId>:` prefix scan. Durable
/// user data → in [`BACKED_UP`].
pub const MEMORY: &str = "memory";

/// A member's MLS group state for each data room they belong to
/// (`rooms/keys/{welcome,commit,open}`), keyed **per member**:
/// `room-group/<roomId>/<persona>`, beside the member's pending KeyPackage
/// (`room-kp/…`), pending epoch advance (`room-advance/…`), root memory
/// (`room-roots/…`), the epoch a commit removed the member at
/// (`room-removed/…`) and an owner's last applied admission, Welcome included, kept
/// for at most 24 hours so a repeated request can be answered
/// (`room-admitted/…`, `rooms/owner/group/add/0.3` item 8) under the same
/// `<roomId>/<persona>`. One VTA may hold several
/// members of one room — several principals, or several personas of one — and
/// each is a different leaf with different secrets. Rows a per-room build wrote
/// (`room-group:<roomId>`, …) are moved under their member on first touch.
///
/// **This holds group secrets.** Whoever reads a row can decrypt every record
/// the group could, up to its epoch — the same class of material as [`KEYS`],
/// and it inherits the same protection: the KMS storage key in a TEE
/// deployment, and a trusted data directory outside one.
///
/// In [`BACKED_UP`], and that is a decision rather than a default. A member who
/// restores a VTA without their room groups has lost the ability to read every
/// sealed room they belong to, with no way to recover it — the group cannot be
/// re-derived, and rejoining means a fresh invitation from every owner. The
/// backup already carries the credential vault and the master seed; group state
/// belongs with them.
pub const ROOM_GROUPS: &str = "room_groups";

/// Invitation credentials this VTA has consumed by joining a room
/// (`rooms/keys/welcome`), keyed `room-vic:<credentialId>`.
///
/// Separate from [`ROOM_GROUPS`] because it outlives them: a member who leaves a
/// room discards the group, and the consumed-invitation record must survive that
/// or the same invitation would let them be re-added without a fresh one. Single
/// use means single use.
pub const ROOM_INVITATIONS: &str = "room_invitations";

/// The holder's identity attributes, profiles, bindings and contacts
/// (`persona/*`) — the fourth store, beside [`VAULT`] (secrets and
/// credentials), [`MEMORY`] (agent memory) and [`APP_STATE`] (uninterpreted
/// application JSON).
///
/// It is a distinct store because disclosure control is its point, and a
/// maintainer that cannot read a record cannot decide which of its members may
/// leave, cannot audit which ones did, and cannot answer "what have I shared
/// with whom". [`APP_STATE`] promises never to interpret its records, so it
/// cannot host this; and a namespace there is collision avoidance rather than a
/// trust boundary, so a compromised application sharing a context could remove
/// the holder's identity data.
///
/// **Two scopes share the keyspace, and the split is a security control rather
/// than a filing decision.** The pool and profiles are *agent-scoped* — above
/// every context — so that the correlation index can see the risk it most needs
/// to report: the same value presented by two personas in two different
/// contexts, which a per-context index cannot see by construction. Bindings,
/// contacts and disclosure records are context-scoped, because a persona lives
/// in a context and so do its counterparties.
///
/// Nothing inside a context may read the agent-scoped prefixes. The holder
/// pushes a materialised projection down; a context never pulls. That is
/// enforced at dispatch, not here, but the prefix split is what makes the
/// enforcement expressible.
///
/// Agent-scoped:
///
/// - `pa:<attributeId>` — one attribute of the pool.
/// - `pp:<profileId>` — one profile.
/// - `pxi:<hmac>` — correlation index, keyed by a keyed hash of the value so
///   exact-match lookup works with no plaintext index over personal data.
/// - `pxr:<attributeId>:<profileId>` — attribute → profile reverse index, so a
///   delete can name its referring profiles without scanning every profile.
///
/// Context-scoped:
///
/// - `pb:<contextId>:<personaDid>` — binding of a profile to a persona DID.
/// - `pc:<contextId>:<contactId>` — a contact's current revision.
/// - `pcr:<contextId>:<contactId>:<rev>` — superseded contact revisions,
///   reference-counted rather than reaped on a flat TTL: a revision behind a
///   disclosure record is evidence the holder can still be asked to account for.
/// - `pd:<contextId>:<seq:020>` — append-only disclosure record.
/// - `plp:<contextId>:<profileId>` — context-local profile (inline entries
///   only). A *separate prefix*, not a flag on `pp:`, so a context-scoped list
///   scans a space that structurally cannot contain a pool profile — a filter
///   bug there would be the same one-line leak the authorization rule exists to
///   remove.
/// - `plb:<contextId>:<personaDid>` — binding of a local profile.
///
/// The holder's identity is the account → in [`BACKED_UP`]. A restored agent
/// that came back without it would be an agent that no longer knows who its
/// holder is.
pub const PERSONA: &str = "persona";

/// Versioned, namespaced application state (`vta/app-state/{get,put,list,
/// delete,get-many,put-many}/1.0`) — the third store, beside [`VAULT`] (secrets
/// and credentials) and [`MEMORY`] (agent memory), for JSON an application owns
/// and the VTA does not interpret.
///
/// Four record shapes share the keyspace, distinguished by prefix:
///
/// - `app:<contextId>:<namespace>:<key>` — the record itself. `list` in
///   snapshot mode is an `app:<contextId>:<namespace>:` prefix scan.
/// - `appv:<contextId>:<namespace>:<version:020}>` — version index, mapping a
///   zero-padded counter value to its record key. Change-feed `list` scans this
///   so it can return changes in version order and paginate over a stable
///   storage key; a scan-and-sort over the records could do neither.
/// - `appc:<contextId>:<namespace>` — the namespace's monotonic write counter.
/// - `appt:<contextId>:<namespace>` — the oldest version still covered by a
///   retained tombstone, which is what `sinceVersion` is checked against.
///
/// Deliberately **not** [`MEMORY`]: clearing an agent's memory has to stay a
/// safe thing for a user to ask, which it cannot be if account state lives
/// there. Durable user data — an account's recoverability depends on it — so it
/// is in [`BACKED_UP`], and a restore that came back without it would defeat
/// the point of the feature.
pub const APP_STATE: &str = "app_state";

/// Rego policy modules for the Policy Decision Point (`policy/{upsert,list,
/// delete,evaluate}`). One `policy::PolicyModule` per id, keyed `policy:<id>`;
/// the active set is every enabled row, priority-ordered. Durable operator
/// security config → in [`BACKED_UP`] (a lost policy set would silently drop
/// enforcement on restore).
pub const POLICY: &str = "policy";

/// Task-execution consent for the PDP's `requireConsent` disposition: pending
/// approvals keyed by payload digest, and granted consents a re-submitted task
/// consumes. Distinct from [`CONSENT`] (messaging-bridge conversation consent).
/// One `vti_common::task_consent::PendingTaskConsent` per `pending:<digest>` and
/// `vti_common::task_consent::TaskConsentGrant` per `grant:<digest>:<requester>`.
/// Durable operator-facing security state → [`BACKED_UP`].
pub const TASK_CONSENT: &str = "task_consent";

/// Durable reliable-messaging outbox backing `vti_common::outbox_store::`
/// `VtiOutboxStore` for the delivery-layer `MessagingService` (D2 P2a
/// cut-over). Holds `Guaranteed`-delivery outbox entries; dormant in P2a (all
/// current sends are `BestEffort`) but wired so the drain/confirmation loops
/// persist across restarts once P2b adds guaranteed VTA pushes. Runtime state,
/// not backed up.
pub const OUTBOX: &str = "outbox";

/// Trust Task pushes in flight or recently finished — one record per push,
/// holding the signed document, the transport plan and the outcome
/// (`vti_common::trust_task_push`). Encrypted at rest; runtime delivery state
/// like [`OUTBOX`], not backed up.
pub const TRUST_TASK_PUSHES: &str = "trust_task_pushes";

/// Idempotency records for keyed Trust Tasks — one row per
/// `(actor, idempotency-key)`, holding the request digest and, for tasks whose
/// response may be replayed, the original response. Lets a client's retry of a
/// lost reply converge on the first execution instead of producing a second
/// durable effect.
///
/// Persistent rather than in-memory (unlike the `(actor, envelope-id)` replay
/// cache it sits beside) because the window that matters is exactly the one a
/// restart falls inside: the VTA processed the request, the reply was lost, and
/// the client is still retrying. Swept on TTL by
/// `vta_sweepers::idempotency_sweeper`. Runtime state, not backed up.
pub const IDEMPOTENCY: &str = "idempotency";

/// The record of accepted Trust Task document identifiers (VTI-OPS-025 … 027,
/// SPEC §7.2 item 11): one row per document `id` accepted for execution,
/// `accepted:<id>`, holding the digest of the document accepted under it, the
/// instant the row may be dropped (the end of that document's acceptance
/// window) and, for a task whose response may be replayed, that response.
///
/// Persistent rather than in-memory because the acceptance window outlives a
/// restart: a document accepted a minute before one is still acceptable after
/// it, and must still be refused. Shared by every binding (VTI-OPS-027).
/// Swept on its deadline (`vti_trust_task_server::accepted_store::sweep_expired`).
/// Runtime state, not backed up.
pub const ACCEPTED_IDS: &str = "accepted_ids";

/// Durable TSP relationship state, backing the SDK's `RelationshipStore` for the
/// TSP transport. One record per facet per `(our_vid, their_vid)` pair — the
/// relationship FSM state, thread digests, reply path and learned capability.
///
/// Persistent because Rev 3 §7.2.2 has an endpoint silently drop application
/// traffic from a VID it holds no relationship with: an in-memory store wiped on
/// restart makes every established peer's messages vanish until each
/// re-handshakes. Persisting the state turns a restart transparent (design note
/// `docs/05-design-notes/tsp-relationship-recovery.md`, D1). Runtime state, not
/// backed up — a relationship is re-establishable (D2/D3), and like [`SESSIONS`]
/// it is scoped to this VTA's DIDs, so a restore re-drives it rather than
/// carrying it.
pub const RELATIONSHIPS: &str = "relationships";

/// External accounts a VTA holds at clouds and third-party providers
/// (`external/accounts/*`), keyed `acct:<context>:<accountId>`, plus a
/// `retired:<context>:<accountId>` tombstone per deleted id so an id is never
/// reused while a provider-side trust policy may still name it.
///
/// Settings, bindings, state and the approvals that changed them — never a
/// secret or a private key. In [`BACKED_UP`]: a restore that came back without
/// them would strand every integration bound to an account, while the
/// provider-side setup they describe still exists.
pub const EXTERNAL_ACCOUNTS: &str = "external_accounts";

/// The secret halves of external accounts whose model holds one
/// (`s3-static-presign`, `static-secret`), set by
/// `external/accounts/secret/set/0.1` and wrapped under the seed-derived KEK the
/// way imported keys are. Keyed `secret:<context>:<accountId>`.
///
/// In [`EXCLUDED_FROM_BACKUP`], and that is the point: a VTA backup is portable
/// and password-protected, so a super-admin holding a backup and its password
/// could otherwise take a provider secret away. A restored account reports
/// `providerSetupRequired` until its secret is set again.
pub const EXTERNAL_SECRETS: &str = "external_secrets";

/// The VTA's hidden-vetting **PCS engine** state (`vta/pcs/*`): one vetter
/// engine per (context, community), keyed `vetter:<digest(context, community)>`,
/// one applicant engine per application, keyed `app:<applicationId>`, and the
/// voter and trustee engines (`voter:<digest>`, `trustee:<digest>`). The keys
/// are digests, so finding a context's records means reading each record's
/// `contextId`; the wrapped state sits beside each under `secret:<key>`.
///
/// Never a `usk`: each member key is re-derived from its context's base on
/// every use (VTI-KEY-030). The rest of an engine — class credentials, unspent
/// tokens, draws and enrolments in flight, attestations held — is secret, and
/// is stored wrapped under the seed-derived KEK the way imported keys are.
///
/// In [`BACKED_UP`]: an applicant's attestations cannot be replaced without
/// its vetters sitting again, and the KEK is a function of the seed the
/// restore brings back.
pub const PCS_ENGINE: &str = "pcs_engine";

/// The VTA's records of **witnessed sessions** in flight (`vta/witness/*`): one per
/// session, keyed `session:<sessionId>`, from `vta/witness/open` until the record
/// expires — minutes, near the witness's own session lifetime — with an accepted
/// session reduced to its stub (`vta/_shared/0.6/CONVENTIONS.md` §3).
///
/// Holds the session document as signed, the relationship and member DIDs, the
/// credential handles and their digests. Never a presentation or a challenge.
///
/// In [`EXCLUDED_FROM_BACKUP`]: transient by construction. A restored record would
/// name a session the witness has long since expired, and the VWC a completed
/// session produced is in the credential vault, which is backed up.
pub const WITNESS_SESSIONS: &str = "witness_sessions";

/// The **notifications** this VTA holds for its principal (`notifications/notify`,
/// `notifications/relay`, `vta/notifications/*`, VTI-NTF-050): one record per
/// (originator, `notificationId`) a DID it holds keys of was sent, keyed
/// `held:<contextId>\0<recordId>` with the dedup index `dedup:<digest of addressee,
/// originator and notificationId>` beside it. Each record keeps the delivering document exactly
/// as received, so a client can verify every proof itself.
///
/// In [`BACKED_UP`]: a held notification cannot be fetched again — an originator
/// delivers each revision once, and a relayer re-sends only later revisions — so a
/// restore without it would lose what the principal was told they may take part
/// in, a member-party election among it (VTI-NTF-063).
pub const NOTIFICATIONS: &str = "notifications";

/// **Collection** of the principal's identifiers (`vta/collection/*`,
/// VTI-NTF-080 – 098): the collection claims — `claim:<contextId>\0<did>`, a
/// client's lease on being a persona DID's one collector at its mediator — the
/// identifiers the VTA stopped collecting for after another connection kept
/// closing its own (`conflict:<contextId>\0<did>`), the identities provisioned
/// for another party, which their holders collect for (`provisioned:<did>`),
/// each context's collection-by-default setting once changed
/// (`context-setting:<contextId>`, VTI-NTF-094), the operator's suspension as
/// last applied at boot (`suspension`, VTI-NTF-098), and the record that the
/// upgrade backfill of `provisioned:` has run (`backfill:provisioned`).
///
/// In [`BACKED_UP`]: a claim names a client that is connected for the
/// identifier until the claim ends. A restore without it would make the
/// restored VTA the second connection to every claimed persona, which is the
/// eviction fight the claim exists to prevent (VTI-NTF-081).
pub const COLLECTION: &str = "collection";

/// The watches this VTA holds for its principal's clients (`rooms/keys/watch/0.1`): one
/// record per armed watch, keyed by a digest of (caller, member, host, room), holding
/// exactly what Recipient item 6 lets it keep — the caller, the member, the room, the
/// host, the address it armed with and that address's key material, and when the watch
/// lapses. Never a watermark, a signalled version or the time a signal arrived. A record
/// is deleted when its watch fires, is cancelled or lapses (30 days at most), when the
/// caller's standing to act as the member is withdrawn, or when the member's credentials
/// for the room are gone.
///
/// In [`EXCLUDED_FROM_BACKUP`]: a backup is a durable copy, and the specification asks the
/// VTA not to keep an address, or a history of watches, once it has forgotten the watch.
/// A restored VTA holds no watches; a client re-arms after its next read, or polls.
pub const ROOM_KEY_WATCHES: &str = "room_key_watches";

/// Every production keyspace. Partitioned by [`BACKED_UP`] +
/// [`EXCLUDED_FROM_BACKUP`]; the [`tests::backup_partition_is_total`] guard
/// asserts the partition stays exhaustive so a newly-added keyspace can't be
/// silently omitted from the backup decision.
pub const ALL: &[&str] = &[
    INTERNAL_KEYS,
    KEYS,
    SESSIONS,
    ACL,
    CONTEXTS,
    DID_TEMPLATES,
    AUDIT,
    AUDIT_KEY,
    IMPORTED_SECRETS,
    VAULT,
    SERVICE_STATE,
    SEALED_NONCES,
    BACKUP_BUNDLES,
    WEBVH,
    PASSKEY_VMS,
    DRAINS,
    SNAPSHOT,
    BOOTSTRAP,
    CONSENT,
    CONSENT_APPROVERS,
    ISSUED_CREDENTIALS,
    MEMORY,
    ROOM_GROUPS,
    ROOM_INVITATIONS,
    APP_STATE,
    PERSONA,
    POLICY,
    TASK_CONSENT,
    OUTBOX,
    TRUST_TASK_PUSHES,
    IDEMPOTENCY,
    ACCEPTED_IDS,
    RELATIONSHIPS,
    EXTERNAL_ACCOUNTS,
    EXTERNAL_SECRETS,
    PCS_ENGINE,
    WITNESS_SESSIONS,
    NOTIFICATIONS,
    COLLECTION,
    ROOM_KEY_WATCHES,
];

/// Keyspaces a backup carries, **every row of each**, as a raw dump.
///
/// A backup exists to bring an agent back, so the rule is inclusion: a
/// keyspace is here unless there is a reason on [`EXCLUDED_FROM_BACKUP`] for
/// leaving it out. Within a carried keyspace the only rows left behind are the
/// few that belong to one *deployment* rather than to the agent — see
/// [`is_environment_bound`] — and the restore re-creates those for the target.
///
/// Every name here is exported by `vta_backup::ops::export_backup` without a
/// per-keyspace code path: it walks this list. `every_backed_up_keyspace_
/// survives_a_round_trip` in `vta-backup` writes a row into each and asserts
/// it comes back, so a keyspace cannot be listed here and silently skipped —
/// which is exactly what happened to ten of them while export was a set of
/// hand-written collectors.
pub const BACKED_UP: &[&str] = &[
    KEYS,
    ACL,
    CONTEXTS,
    DID_TEMPLATES,
    AUDIT,
    // Without the keys, a restored audit log still verifies as a chain and
    // still says what happened, but no entry can be checked against a
    // candidate identifier again — the commitments become opaque. The key is
    // generated rather than derived, so nothing else reproduces it.
    AUDIT_KEY,
    IMPORTED_SECRETS,
    // The holder's secrets and credentials. The reason a person keeps a VTA.
    VAULT,
    WEBVH,
    // Which transports this VTA serves. The DID log restored beside it
    // advertises them, and a document naming a transport the node does not
    // serve fails at the peer as a parse error, not as "not served".
    SERVICE_STATE,
    SNAPSHOT,
    DRAINS,
    // Anti-replay for sealed bootstrap requests. Restoring it only ever makes
    // the restored agent stricter; leaving it behind reopens every request
    // still inside its validity window.
    SEALED_NONCES,
    CONSENT,
    CONSENT_APPROVERS,
    // Credentials this VTA issued. Losing the records loses the ability to
    // revoke them, while every copy in the wild stays valid.
    ISSUED_CREDENTIALS,
    // Durable agent memory is user data and must survive a restore.
    MEMORY,
    ROOM_GROUPS,
    ROOM_INVITATIONS,
    // Application state IS the user's account for a consumer built on it —
    // labels, relationships, contacts, join history. A restore that came back
    // without it would return a VTA whose applications no longer recognise
    // their own data, which is the failure the store exists to prevent.
    APP_STATE,
    // The holder's own identity — attributes, profiles, bindings, contacts.
    // A restore that came back without it would return an agent that no longer
    // knows who its holder is, which is most of what the restore was for.
    PERSONA,
    // Operator security policy — must survive a restore, else enforcement
    // silently reverts to whatever defaults boot-install provides.
    POLICY,
    // Task-consent grants are durable authorizations a re-submitted task
    // consumes; losing them on restore would strand in-flight approvals.
    TASK_CONSENT,
    // The external accounts a community's integrations are bound to. Their
    // secrets are not here; see EXTERNAL_SECRETS.
    EXTERNAL_ACCOUNTS,
    // Hidden-vetting engine state, wrapped. An applicant's attestations are not
    // replaceable without its vetters sitting again.
    PCS_ENGINE,
    // What the principal was told they may take part in. An originator sends each
    // revision once, so a lost record is not fetched again (VTI-NTF-050).
    NOTIFICATIONS,
    // Who collects for each persona. A restored VTA without the claims would be
    // the second connection to every claimed persona (VTI-NTF-081).
    COLLECTION,
];

/// Keyspaces deliberately **not** in a backup, each for a stated reason.
pub const EXCLUDED_FROM_BACKUP: &[&str] = &[
    // Non-extractable internal signing keys. Excluding them is the feature:
    // a backup that carried them would export keys the VTA guarantees never
    // to export, and restoring one elsewhere would silently clone a signer.
    // Their *records* live in KEYS and are carried; the restore reports every
    // one whose material stayed behind.
    INTERNAL_KEYS,
    // Live sessions are bound to the JWT key and the node that issued them.
    SESSIONS,
    // The control plane of the transfer carrying this very backup.
    BACKUP_BUNDLES,
    // TTL'd, in-flight passkey enrolment ceremonies.
    PASSKEY_VMS,
    // The deployment's own boot material: KMS ciphertexts, the integrity
    // manifest, the staged restore itself. A restore writes the target's.
    BOOTSTRAP,
    // Reliable-messaging outbox: runtime delivery state, re-driven from live
    // sends, not part of a state backup.
    OUTBOX,
    // Trust Task push records: the same runtime delivery state as the outbox
    // they drive, bounded by their retention sweep.
    TRUST_TASK_PUSHES,
    // Trust-Task idempotency records. Short-lived by construction (a retry
    // window, not durable state) and scoped to the VTA that served the original
    // request — restoring one elsewhere would claim to have already performed
    // operations that instance never did.
    IDEMPOTENCY,
    // The accepted-document-id record. Its horizon is the acceptance window —
    // minutes — so a restored row is all but certainly expired, and an expired
    // row refuses nothing. It is execution bookkeeping of the VTA that did the
    // executing, and it holds recorded task responses, which a backup's scope
    // (the agent's durable state) does not take.
    ACCEPTED_IDS,
    // TSP relationship state: durable across a restart, but re-establishable by
    // a re-handshake (design note D2/D3) and scoped to this VTA's DIDs — so a
    // restore re-drives it, like [`SESSIONS`], rather than carrying it.
    RELATIONSHIPS,
    // Provider secrets of external accounts. A portable, password-protected
    // backup must not be a way to take one away; a restored account asks for
    // its secret again (`providerSetupRequired`).
    EXTERNAL_SECRETS,
    // Witnessed sessions in flight: minutes long, and useless once the witness
    // has expired its own side. A completed session's VWC and evidence are in
    // the credential vault, which is carried.
    WITNESS_SESSIONS,
    // Watches armed for the principal's clients (`rooms/keys/watch/0.1`): each lapses
    // within 30 days, holds a per-watch address's key material, and the specification
    // asks that no copy of an address outlive its watch (Recipient item 6).
    ROOM_KEY_WATCHES,
];

/// Rows inside a [`BACKED_UP`] keyspace that belong to the **deployment**, not
/// to the agent, as `(keyspace, key prefix)`.
///
/// A backup moves between a plain VTA, a hardened one and a Nitro enclave in
/// any direction. These rows only mean something in the environment that wrote
/// them, or are derived from that environment's storage key, so copying one
/// would be wrong on the target: the restore leaves them out and re-creates
/// what the target needs.
pub const ENVIRONMENT_BOUND_ROWS: &[(&str, &str)] = &[
    // TEE identity mirror, did.jsonl copy, Mode-B carve-out sentinel and the
    // legacy admin credential. The restore writes the target's own.
    (KEYS, "tee:"),
    // The hardened deployment's JWT key row. The key itself travels as the
    // payload's `jwt_signing_key` and lands wherever the target keeps it.
    (KEYS, "hardened:"),
    // Restore / import bookkeeping of the source.
    (KEYS, "backup:"),
    (KEYS, "restore:"),
    // Blinded persona indexes are keyed by an HMAC whose key is derived from
    // the storage key, so they are meaningless under any other one. The
    // restore rebuilds them from the rows they index.
    (PERSONA, "pxi:"),
    (PERSONA, "pxf:"),
    (PERSONA, "pxfv"),
];

/// Whether `key` in `keyspace` is an [`ENVIRONMENT_BOUND_ROWS`] row.
#[must_use]
pub fn is_environment_bound(keyspace: &str, key: &[u8]) -> bool {
    ENVIRONMENT_BOUND_ROWS
        .iter()
        .any(|(ks, prefix)| *ks == keyspace && key.starts_with(prefix.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The backup partition must be total and disjoint: every production
    /// keyspace is either backed up or explicitly excluded. Adding a keyspace
    /// to [`ALL`] without classifying it fails here — that's the point.
    #[test]
    fn backup_partition_is_total() {
        let all: BTreeSet<&str> = ALL.iter().copied().collect();
        let backed: BTreeSet<&str> = BACKED_UP.iter().copied().collect();
        let excluded: BTreeSet<&str> = EXCLUDED_FROM_BACKUP.iter().copied().collect();

        assert_eq!(all.len(), ALL.len(), "ALL has a duplicate");
        assert!(
            backed.is_disjoint(&excluded),
            "a keyspace is both backed up and excluded: {:?}",
            backed.intersection(&excluded).collect::<Vec<_>>()
        );
        let union: BTreeSet<&str> = backed.union(&excluded).copied().collect();
        assert_eq!(
            union, all,
            "backup partition is not exhaustive — every keyspace in ALL must be in \
             exactly one of BACKED_UP / EXCLUDED_FROM_BACKUP"
        );
    }

    /// An environment-bound rule for a keyspace a backup never carries would be
    /// dead, and one naming an unknown keyspace would be a typo that silently
    /// lets a deployment row travel.
    #[test]
    fn environment_bound_rows_name_backed_up_keyspaces() {
        for (ks, prefix) in ENVIRONMENT_BOUND_ROWS {
            assert!(
                BACKED_UP.contains(ks),
                "environment-bound rule ({ks}, {prefix}) names a keyspace that is not backed up"
            );
            assert!(
                !prefix.is_empty(),
                "an empty prefix would drop the whole keyspace"
            );
        }
    }

    #[test]
    fn environment_bound_rows_are_matched_by_prefix_within_their_keyspace() {
        assert!(is_environment_bound(KEYS, b"tee:vta_did"));
        assert!(is_environment_bound(KEYS, b"hardened:jwt_key"));
        assert!(is_environment_bound(PERSONA, b"pxi:abcd"));
        // Same prefix, different keyspace: carried.
        assert!(!is_environment_bound(ACL, b"tee:mode-b"));
        // The agent's own rows are carried.
        assert!(!is_environment_bound(KEYS, b"key:abc"));
        assert!(!is_environment_bound(PERSONA, b"pa:01H"));
        assert!(!is_environment_bound(WEBVH, b"server:srv1"));
    }
}

// ---------------------------------------------------------------------------
// What a DID deletion means for each keyspace
// ---------------------------------------------------------------------------

/// What happens to a keyspace's DID-keyed contents when that DID is deleted.
///
/// Deleting a DID is not one cleanup. It is four different relationships, and
/// treating them alike gets one of them wrong in a way nobody notices until it
/// matters:
///
/// * things the DID **owns** go with it;
/// * things that **name it as a subject of authorization** must go with it, or
///   they become authority for an identity that no longer resolves;
/// * things that **depend on it to function** must *stop* the deletion, because
///   cascading would silently break them;
/// * credentials the VTA **issued** cannot be deleted at all — copies exist
///   elsewhere — so the only honest action is revocation.
///
/// # Why this is an enum and not a list in a function
///
/// The failure mode is not getting today's answers wrong. It is a keyspace
/// added next quarter that nobody classifies, whose rows then quietly outlive
/// the DID they belong to. [`ALL`] is already pinned by a census test for the
/// backup partition, for exactly the same reason; this rides the same rail, so
/// "we forgot" is a red test rather than an orphan found months later in a log.
///
/// The classifications below are judgements and several are arguable. That is
/// fine — the point of the census is to force the question to be asked, not to
/// claim these answers are the last word.
///
/// # A label is a claim about the code
///
/// `Cascade`, `Blocks` and `Revoke` say what a DID deletion *does*, and
/// `vta-service`'s `did_delete_labels_match_the_cascade` test holds them to the
/// cascade's own list of what it reaches. A keyspace whose rows should go with
/// the DID (or should stop the deletion) but which the cascade does not reach
/// yet is [`Orphaned`](DidDeleteEffect::Orphaned), with the effect it should
/// have written beside it — labelling it `Cascade` would be the comfortable
/// version of the orphan this census exists to catch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DidDeleteEffect {
    /// Rows belonging to the DID are removed with it.
    Cascade,
    /// A row referencing the DID **blocks** the deletion: something still in
    /// use would break. Refused, never forced — the operator is told what to
    /// unpick first.
    Blocks,
    /// Rows cannot be removed, because the VTA is not the only holder. They
    /// are revoked instead.
    Revoke,
    /// Nothing here is keyed to a DID.
    Unrelated,
    /// Rows here can name the DID, and a DID deletion leaves them in place
    /// today. The comment beside each says what the deletion should do with
    /// them. A known gap, stated rather than labelled away.
    Orphaned,
}

/// The effect a DID deletion has on `keyspace`, or `None` if the name is not a
/// keyspace this build knows.
///
/// Every entry in [`ALL`] is classified — see `did_delete_census` in this
/// module's tests.
#[must_use]
pub const fn did_delete_effect(keyspace: &str) -> Option<DidDeleteEffect> {
    use DidDeleteEffect::*;
    // `const fn` cannot match on `&str`, so this is a byte-slice match.
    Some(match keyspace.as_bytes() {
        // ---- Removed with the DID ----------------------------------------
        // Its key records (`<did>#key-N`, `#pre-rotation-N`) and its own log.
        b"keys" | b"webvh" => Cascade,
        // An ACL entry outliving its DID is the worst of the orphans: live
        // authority for an identity that can no longer be resolved or rotated.
        // The VTC learned this the expensive way (#1194, #1196). Sessions are
        // authority already issued, and go the same way.
        b"acl" | b"sessions" => Cascade,

        // ---- Depends on the DID to function ------------------------------
        // A context whose `did` is this one: deleting the DID would strand it,
        // so the operator is told to reassign it first.
        b"contexts" => Blocks,

        // ---- Cannot be deleted, only revoked -----------------------------
        // Third parties hold copies. Deleting our record achieves nothing but
        // losing our ability to revoke it.
        b"issued_credentials" => Revoke,

        // ---- Should go with the DID; the cascade does not reach them -----
        // Material of the DID's imported / internal keys. The cascade removes
        // the key *records* only. (A context deletion takes both.)
        b"internal_keys" | b"imported_secrets" => Orphaned,
        // Delivery and protocol state keyed by DID: stale the moment it goes.
        // TSP relationships name this VTA's DID as one half of each
        // `(our_vid, their_vid)` pair; with that VID gone the relationship can
        // neither send nor be sent to.
        b"outbox" | b"trust_task_pushes" | b"relationships" => Orphaned,
        // In-flight passkey enrolment for the DID (TTL'd).
        b"passkey_vms" => Orphaned,
        // Consent state and the vault are held *for* a holder; with the holder
        // gone they are unreachable by anyone.
        b"consent" | b"task_consent" | b"vault" => Orphaned,
        // Per-holder application state and memory. Keyed by context, not DID,
        // and purged by a context deletion; a lone DID deletion leaves them.
        b"app_state" | b"memory" => Orphaned,
        // A member's room groups, and the invitations they were joined under.
        // Held for the holder in the same sense the vault is: the group state
        // decrypts a room *that member* belongs to, and with the member gone
        // nobody can use it or ever will again.
        //
        // The consumed-invitation records should go with them and not before:
        // while the member exists, a consumed invitation MUST outlive the group
        // it let them join, or leaving a room would make the same invitation
        // work twice.
        b"room_groups" | b"room_invitations" => Orphaned,
        // Hidden-vetting engines: a vetter's names the member DID it draws
        // tokens as, an applicant's the DID it joins as. Purged with their
        // context; a lone DID deletion leaves them.
        b"pcs_engine" => Orphaned,
        // A witnessed session in flight is the relationship DID's (minutes long).
        b"witness_sessions" => Orphaned,
        // A held notification was addressed to the DID.
        b"notifications" => Orphaned,
        // A collection claim, conflict or provisioned marker names the DID. Not
        // reached by the cascade; the collector's sweep drops claims and
        // conflicts on an identifier that is no longer collectable within one
        // pass, and such a claim is not in force meanwhile (VTI-NTF-090). A
        // context's setting, the suspension and the backfill record name no
        // DID as their subject.
        b"collection" => Orphaned,
        // A watch names its member and its caller. Not reached by the cascade; the
        // watch sweep forgets a watch whose caller may no longer act as the member
        // (`rooms/keys/watch/0.1` Recipient item 7) within one pass, and every watch
        // lapses within 30 days.
        b"room_key_watches" => Orphaned,
        // Persona is two scopes in one keyspace and only one half is DID-keyed:
        // a binding is keyed by the persona DID, and a contact records the
        // persona that knows it. Those should cascade (a context deletion takes
        // them); the agent-scoped rows — the attribute pool, the profiles, and
        // their indexes — are keyed to no DID and must survive, because a
        // profile may be bound to several personas.
        b"persona" => Orphaned,
        // These should *block*: a DID named in an advertised service entry (or
        // its rollback snapshot), a policy or approver set that names it, an
        // external account binding whose consumer it is. Cascading breaks
        // something still in use; but nothing checks them yet.
        b"service_state" | b"service_prev_config" => Orphaned,
        b"policy" | b"consent_approvers" | b"external_accounts" => Orphaned,

        // ---- Not keyed to a DID ------------------------------------------
        // The audit log is deliberately here: it is append-only, and the record
        // that a DID was deleted is the one thing that must survive deleting it.
        b"audit" | b"audit_key" => Unrelated,
        b"did_templates" | b"sealed_nonces" | b"backup_bundles" => Unrelated,
        b"drains" | b"bootstrap" | b"idempotency" => Unrelated,
        // Keyed by Trust Task document `id`, and gone within the document's
        // acceptance window. Cascading would hand a deleted DID's accepted ids
        // back while their documents can still arrive — the replay the record
        // exists to refuse.
        b"accepted_ids" => Unrelated,
        // Keyed by account, never by DID; the account row carries the bindings.
        b"external_secrets" => Unrelated,

        _ => return None,
    })
}

#[cfg(test)]
mod did_delete_tests {
    use super::*;

    /// Every keyspace must have an answer to "what happens to this when a DID
    /// is deleted".
    ///
    /// This is the whole point of the classification. Adding a keyspace is
    /// easy; remembering that its rows might outlive the DID they belong to is
    /// not, and nothing about adding one prompts the question. This test asks
    /// it, once, at the only moment anyone is looking.
    ///
    /// A new keyspace fails here until it is classified. `Unrelated` is a
    /// perfectly good answer — but it has to be a chosen one.
    #[test]
    fn every_keyspace_is_classified_for_did_deletion() {
        let unclassified: Vec<&str> = ALL
            .iter()
            .copied()
            .filter(|ks| did_delete_effect(ks).is_none())
            .collect();
        assert!(
            unclassified.is_empty(),
            "these keyspaces have no DID-deletion effect declared: {unclassified:?}\n\
             Add them to `did_delete_effect`. `Unrelated` is a fine answer if \
             nothing in the keyspace is keyed to a DID — but it must be chosen, \
             not defaulted."
        );
    }

    /// An unknown name is not silently `Unrelated`. The distinction matters:
    /// `None` means "this build does not know that keyspace", and answering
    /// `Unrelated` to it would let a typo read as "nothing to clean up".
    #[test]
    fn an_unknown_keyspace_has_no_effect_rather_than_a_harmless_one() {
        assert_eq!(did_delete_effect("not_a_keyspace"), None);
        assert_eq!(did_delete_effect(""), None);
    }

    /// The credential keyspace must never be classified `Cascade`.
    ///
    /// Pinned explicitly because it is the one that looks most like a cascade
    /// and is not: the VTA is not the only holder of what it issued, so
    /// deleting our record destroys the ability to revoke it while leaving
    /// every copy in the wild valid forever. That is the exact residue an ACL
    /// revoke left behind on the VTC.
    #[test]
    fn issued_credentials_are_revoked_never_deleted() {
        assert_eq!(
            did_delete_effect(ISSUED_CREDENTIALS),
            Some(DidDeleteEffect::Revoke)
        );
    }

    /// The audit log must survive the deletion it records.
    #[test]
    fn the_audit_log_is_never_cascaded() {
        assert_eq!(did_delete_effect(AUDIT), Some(DidDeleteEffect::Unrelated));
    }
}

// ---------------------------------------------------------------------------
// What a context deletion means for each keyspace
// ---------------------------------------------------------------------------

/// What happens to a keyspace's context-scoped contents when that context is
/// deleted (`vta/contexts/delete`).
///
/// The question that matters is narrower than "is this tidy": a context can be
/// created again **under the same id**, and anything keyed by (or carrying) the
/// old id that survives the deletion is inherited by the new one. That has
/// happened twice — application state syncing a deleted profile's personas back
/// (#2415), and a vetter engine record pinning the old member DID so the new
/// context's `vta/pcs/root-request` failed with `memberMismatch`.
///
/// Same rail as [`DidDeleteEffect`]: every keyspace in [`ALL`] must be
/// classified, and `vta-service`'s `context_delete_labels_match_the_cascade`
/// test holds the [`Purged`](ContextDeleteEffect::Purged) set to the list the
/// cascade itself declares, so a label cannot claim a purge the code does not do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContextDeleteEffect {
    /// The context's rows are removed with it.
    Purged,
    /// Context-scoped rows are deliberately kept; the reason is beside each.
    Retained,
    /// Context-scoped rows are not removed, but each expires on its own within
    /// a bounded time, and none is found again through a recreated context.
    Lapses,
    /// Nothing here is scoped to a context.
    Unrelated,
}

/// The effect a context deletion has on `keyspace`, or `None` if the name is
/// not a keyspace this build knows.
#[must_use]
pub const fn context_delete_effect(keyspace: &str) -> Option<ContextDeleteEffect> {
    use ContextDeleteEffect::*;
    Some(match keyspace.as_bytes() {
        // ---- Removed with the context -----------------------------------
        // The context record and its daily quota counters; its key records and
        // the material of its imported / internal keys; its DIDs (through the
        // full DID deletion); its ACL scope; its DID templates.
        b"contexts" | b"keys" | b"imported_secrets" | b"internal_keys" => Purged,
        b"webvh" | b"acl" | b"did_templates" => Purged,
        // Data held for the principal in the context.
        b"app_state" | b"memory" | b"persona" | b"vault" => Purged,
        b"consent" | b"consent_approvers" | b"notifications" => Purged,
        // Engine records name the context their key is derived under; left
        // behind, a recreated context inherits a vetter pinned to the old
        // member DID and an old derivation path.
        b"pcs_engine" => Purged,
        // Live accounts are deleted the way `external/accounts/delete` deletes
        // one: secret gone, id retired. The `retired:` tombstones are kept —
        // see `Retained` below for why that is not a resurrection.
        b"external_accounts" | b"external_secrets" => Purged,
        // Collection claims and conflicts on the context's identifiers end with
        // it (VTI-NTF-090), and so does its setting, so a context created again
        // under the id starts enabled (VTI-NTF-094).
        b"collection" => Purged,

        // ---- Kept on purpose --------------------------------------------
        // Append-only; the record that a context was deleted must survive it.
        b"audit" | b"audit_key" => Retained,
        // Credentials the VTA issued: third parties hold copies, so the record
        // is what revokes them. The context's DIDs are deleted through the DID
        // cascade, which revokes what was issued to them.
        b"issued_credentials" => Retained,
        // Operator policy. An approval rule naming a context id is the
        // operator's statement about that id, not data the context owned.
        b"policy" => Retained,
        // Keyed by member persona DID and by credential id, never by context. A
        // recreated context's personas are new DIDs and cannot reach them; a
        // consumed invitation must stay consumed (single use).
        b"room_groups" | b"room_invitations" => Retained,

        // ---- Expire on their own ----------------------------------------
        // Live sessions keep the context in their access token's `contexts`
        // claim until it expires; a refresh re-reads the ACL, which the
        // deletion already narrowed. TTL'd consent, enrolment, idempotency and
        // witness records likewise.
        b"sessions" | b"task_consent" | b"passkey_vms" => Lapses,
        b"idempotency" | b"accepted_ids" | b"witness_sessions" => Lapses,
        // A watch whose caller loses standing in the context is forgotten by the
        // watch sweep's next pass, and every watch lapses within 30 days. Its member
        // is a persona DID, which a recreated context never holds again.
        b"room_key_watches" => Lapses,

        // ---- Not scoped to a context ------------------------------------
        b"service_state" | b"service_prev_config" | b"sealed_nonces" => Unrelated,
        b"backup_bundles" | b"drains" | b"bootstrap" => Unrelated,
        b"outbox" | b"trust_task_pushes" | b"relationships" => Unrelated,

        _ => return None,
    })
}

#[cfg(test)]
mod context_delete_tests {
    use super::*;

    /// Every keyspace must answer "what happens to this context's rows here
    /// when the context is deleted" — a keyspace added without an answer is
    /// the next one whose rows a recreated context inherits.
    #[test]
    fn every_keyspace_is_classified_for_context_deletion() {
        let unclassified: Vec<&str> = ALL
            .iter()
            .copied()
            .filter(|ks| context_delete_effect(ks).is_none())
            .collect();
        assert!(
            unclassified.is_empty(),
            "these keyspaces have no context-deletion effect declared: {unclassified:?}\n\
             Add them to `context_delete_effect`, and if their rows are scoped to a \
             context, purge them in `vta-service`'s `delete_context`."
        );
        assert_eq!(context_delete_effect("not_a_keyspace"), None);
    }

    /// The audit log survives the deletion it records.
    #[test]
    fn the_audit_log_is_never_purged() {
        assert_eq!(
            context_delete_effect(AUDIT),
            Some(ContextDeleteEffect::Retained)
        );
    }
}
