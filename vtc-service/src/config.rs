use crate::error::AppError;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Re-export shared config types
pub use vti_common::config::{
    AuthConfig, FjallTuning, LogConfig, LogFormat, MessagingConfig, StoreConfig,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub vtc_did: Option<String>,
    pub vta_did: Option<String>,
    /// The context at `vta_did` holding this community's own DID — the one `vtc setup`
    /// provisioned it in. Written by setup; **absent** in a configuration written before
    /// it was, which changes nothing but the community rooms' fix commands
    /// ([`crate::rooms::vta_access`]), which then name it by a placeholder. The
    /// community's entry at its VTA must cover it for the VTA to act as the community.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vta_context: Option<String>,
    #[serde(alias = "community_name")]
    pub vtc_name: Option<String>,
    #[serde(alias = "community_description")]
    pub vtc_description: Option<String>,
    pub public_url: Option<String>,
    #[serde(default = "default_server_config")]
    pub server: ServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default = "default_store_config")]
    pub store: StoreConfig,
    /// Optional Fjall memory tuning (`[fjall]`) — the block cache, write
    /// buffer and journal-size caps that keep the store's memory use
    /// inside a pod's Kubernetes limit. Every field defaults to `None`
    /// (fjall's own defaults, unchanged). See
    /// [`vti_common::config::FjallTuning`].
    #[serde(default)]
    pub fjall: FjallTuning,
    pub messaging: Option<MessagingConfig>,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub secrets: SecretsConfig,
    /// Signed audit-checkpoint settings (#708). The interval is the
    /// attacker's free truncation window, so it sets the residual risk
    /// directly; `0` disables checkpointing.
    #[serde(default)]
    pub audit_checkpoints: crate::audit_checkpoint::AuditCheckpointConfig,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub cors: CorsConfig,
    /// Trust-registry settings (Phase 3 M3.2). When `url` is
    /// unset, registry features no-op and `registry_status`
    /// reports `"degraded"`. Otherwise the daemon health-pings
    /// the registry at boot and on a periodic interval.
    #[serde(default)]
    pub registry: RegistryConfig,
    /// Membership lifecycle hooks — capability grant propagation
    /// (`design-docs/vtc-membership-hooks.md`). Absent ⇒ no hook relay.
    #[serde(default)]
    pub hooks: crate::hooks::HooksConfig,
    /// Git namespaces (`git-ns/*`): which bridge serves which forge, and the
    /// consent-class fallback. Absent ⇒ manual-mode namespaces only, elevated
    /// actions for community administrators.
    #[serde(default)]
    pub git_ns: crate::git_ns::GitNsConfig,
    /// Renewal-path settings (Phase 4 M4.2.2). Currently
    /// gates the renewal-time behaviour when `personhood.rego`
    /// flips a previously-asserted member's flag to `false`.
    #[serde(default)]
    pub renewal: RenewalConfig,
    /// Retention sweeper settings (§5.5). Controls the window after which
    /// terminal join requests (and expired credential-exchange / Failed
    /// sync-job rows) are purged, plus the sweep cadence. Defaults to a
    /// 30-day window swept hourly.
    #[serde(default)]
    pub join_requests: crate::join::retention::JoinRequestsConfig,
    /// Public community website settings (Phase 5 M5.4). When
    /// `root_dir` is unset the website handler 503s — the
    /// feature is opt-in by operator configuration, even though
    /// the cargo feature is default-on.
    #[serde(default)]
    pub website: WebsiteConfig,
    /// Admin UX settings (Phase 5 M5.7): where the console and the member
    /// portal are served from — the binary, or a directory an owner has
    /// customised.
    #[serde(default)]
    pub admin_ui: AdminUiConfig,
    /// Trust Task document-dispatch settings (#1641). Holds no switch any more
    /// — the one it carried, `require_declared_proof`, became the only
    /// behaviour — and exists to keep a config that still declares the retired
    /// key from being read as if it said nothing.
    #[serde(default)]
    pub trust_tasks: TrustTasksConfig,
    /// Authority settings for the community's ACL (VTI-APV-014).
    #[serde(default)]
    pub acl: AclConfig,
    /// The DID-document cache (`[did_cache]`): how long a member's or peer's
    /// document is trusted before it is resolved again. One cache serves the
    /// REST, Trust Task, DIDComm and TSP paths alike. Bounded — see
    /// [`vti_common::config::DidCacheConfig`].
    #[serde(default)]
    pub did_cache: vti_common::config::DidCacheConfig,
    /// Local GeoIP database (`[geoip]`) for the city and country a wallet
    /// shows its approver at sign-in. Absent ⇒ every location is `"unknown"`.
    #[serde(default)]
    pub geoip: GeoIpConfig,
    /// Data rooms hosted here (`[rooms]`): for now, room files.
    #[serde(default)]
    pub rooms: RoomsConfig,
    /// OpenID4VP wallet sessions (`[oid4vp]`): how long a session stays open,
    /// how many an applicant may hold, how long unclaimed evidence is kept, and
    /// the largest wallet response accepted. See [`crate::oid4vp::session`].
    #[serde(default)]
    pub oid4vp: Oid4vpConfig,
    /// The witnesses this community trusts (`[witnesses]`): whose Verifiable
    /// Witness Credentials count as evidence here. **Absent or empty means
    /// none does.** Runtime-patchable as `witnesses.trusted`. See
    /// [`crate::credentials::trusted_witnesses`].
    #[serde(
        default,
        skip_serializing_if = "crate::credentials::trusted_witnesses::WitnessesConfig::is_empty"
    )]
    pub witnesses: crate::credentials::trusted_witnesses::WitnessesConfig,
    /// The member directory (`[directory]`): the listing a new card starts
    /// with, how long a retired field's values are kept, the facet threshold
    /// and the per-member read rate. **Absent means the defaults**, which are
    /// the narrow ones the directory chapter asks for (VTI-DIR-041). See
    /// [`crate::directory`].
    #[serde(default, skip_serializing_if = "DirectoryConfig::is_default")]
    pub directory: DirectoryConfig,
    /// The community's groups (`[groups]`, the `vtc/groups/*` tasks): where its VTA
    /// mints each group's identity, and how long the credentials it issues last.
    ///
    /// **Absent means off**, as every configuration written before groups existed is:
    /// such a VTC starts exactly as before, and a create is refused `noKeyHolder`
    /// naming this section. Writing it is what turns them on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<GroupsConfig>,
    #[serde(skip)]
    pub config_path: PathBuf,
}

/// Where the community's groups get their identities (`[groups]`).
///
/// The community's VTA (`vta_did`) holds every group's keys: it mints each group's
/// `did:webvh` from the `vtc-group` template and signs, as the group, the membership
/// credentials the group issues, and as the community, the authority credential the
/// community issues the group. This community holds no group key. It reaches the VTA
/// over the messaging link it already keeps, so `vta_did` and `[messaging]` are needed
/// too, and this community's DID needs an entry at the VTA in `context` with
/// `key-mint` and `sign-document`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct GroupsConfig {
    /// The context at the community's VTA the groups' keys are minted in. Absent:
    /// `[rooms.community] context`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// A `did:webvh` hosting server registered at the VTA, by its id there, that
    /// publishes each group's log. **Absent**: the groups' identities are minted
    /// serverless and this community serves each log itself, at
    /// `<public_url>/group-dids/<id>/did.jsonl`, so `public_url` must be set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webvh_server: Option<String>,
    /// How long the community's authority credential to a group lasts, in days.
    /// Default 365, renewed well before it lapses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_valid_days: Option<u32>,
    /// How long a member's group membership credential lasts, in days. Default 30,
    /// renewed while the member stays; its expiry is its revocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_valid_days: Option<u32>,
    /// How long before a group's authority credential lapses the community
    /// renews it, in days. Default: 30, or a member credential's life where
    /// that is longer, so every member receives the new authority with a
    /// renewed credential before the old one lapses. Never more than half the
    /// authority's own life (`groups::renewal`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_renew_within_days: Option<u32>,
}

impl GroupsConfig {
    /// [`Self::authority_renew_within_days`], defaulted, and never more than
    /// half the authority's own life: a renewal due again as soon as it landed
    /// would renew on every pass.
    pub fn authority_renew_within(&self) -> chrono::Duration {
        let days = self
            .authority_renew_within_days
            .unwrap_or_else(|| 30.max(self.credential_valid_days()))
            .min(self.authority_valid_days() / 2)
            .max(1);
        chrono::Duration::days(i64::from(days))
    }

    /// How long before a member's group credential lapses it is renewed: a
    /// third of its life (ten days of a 30-day credential), at least an hour.
    pub fn credential_renew_within(&self) -> chrono::Duration {
        let life = chrono::Duration::days(i64::from(self.credential_valid_days()));
        (life / 3).max(chrono::Duration::hours(1))
    }

    /// [`Self::authority_valid_days`], defaulted and at least one day.
    pub fn authority_valid_days(&self) -> u32 {
        self.authority_valid_days.unwrap_or(365).max(1)
    }

    /// [`Self::credential_valid_days`], defaulted and at least one day.
    pub fn credential_valid_days(&self) -> u32 {
        self.credential_valid_days.unwrap_or(30).max(1)
    }
}

/// The member directory (`[directory]`).
///
/// A host setting, written by the operator. Widening any of it — a wider
/// `default_listing` above all — widens what a new card exposes, so it is not
/// runtime-patchable: the community's administrators change the schema, never
/// these.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DirectoryConfig {
    /// `listed` (the default), `findable` or `hidden`: where a new card
    /// starts. Every member may always choose `hidden`.
    #[serde(default = "DirectoryConfig::default_listing")]
    pub default_listing: String,
    /// Days a retired field's values are kept before they are erased, so a
    /// mistaken retirement can be undone by the operator. Default 30.
    #[serde(default = "DirectoryConfig::default_retention_days")]
    pub retention_days: u32,
    /// The facet threshold *k* (VTI-DIR-113): a count below it is shown only as
    /// "fewer than k". Default 5, at least 2.
    #[serde(default = "DirectoryConfig::default_facet_threshold")]
    pub facet_threshold: u32,
    /// `vtc/directory/entries/list` requests one caller may make per minute
    /// (VTI-DIR-114). Default 60.
    #[serde(default = "DirectoryConfig::default_list_rate")]
    pub list_rate_per_minute: u32,
    /// Whether a member may publish their card beyond the community with
    /// `vtc/directory/card/publish` (VTI-DIR-046). Default `true`: publication
    /// is still the member's own decision, signed with their membership DID,
    /// and needs their registry-publication consent. `false` refuses it
    /// (`notAvailable`), and the disclosure statement says no card leaves the
    /// community.
    #[serde(default = "DirectoryConfig::default_external_cards")]
    pub external_cards: bool,
    /// Pictures one member or administrator may upload per hour
    /// (`vtc/directory/images/upload`). Default 30.
    #[serde(default = "DirectoryConfig::default_image_uploads")]
    pub image_uploads_per_hour: u32,
}

impl DirectoryConfig {
    fn default_listing() -> String {
        "listed".into()
    }
    fn default_retention_days() -> u32 {
        30
    }
    fn default_facet_threshold() -> u32 {
        5
    }
    fn default_list_rate() -> u32 {
        60
    }
    fn default_external_cards() -> bool {
        true
    }
    fn default_image_uploads() -> u32 {
        30
    }

    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    /// The settings the directory runs with. A value it cannot use is refused
    /// at boot rather than read as something wider.
    pub fn settings(&self) -> Result<crate::directory::model::Settings, String> {
        let default_listing = crate::directory::model::Listing::parse(&self.default_listing)
            .ok_or_else(|| {
                format!(
                    "[directory] default_listing = {:?}: expected listed, findable or hidden",
                    self.default_listing
                )
            })?;
        if self.facet_threshold < 2 {
            return Err("[directory] facet_threshold must be at least 2".into());
        }
        if self.list_rate_per_minute == 0 {
            return Err("[directory] list_rate_per_minute must be at least 1".into());
        }
        if self.image_uploads_per_hour == 0 {
            return Err("[directory] image_uploads_per_hour must be at least 1".into());
        }
        Ok(crate::directory::model::Settings {
            default_listing,
            retention_days: self.retention_days,
            facet_threshold: self.facet_threshold,
            list_rate_per_minute: self.list_rate_per_minute,
            external_cards: self.external_cards,
            image_uploads_per_hour: self.image_uploads_per_hour,
        })
    }
}

impl Default for DirectoryConfig {
    fn default() -> Self {
        Self {
            default_listing: Self::default_listing(),
            retention_days: Self::default_retention_days(),
            facet_threshold: Self::default_facet_threshold(),
            list_rate_per_minute: Self::default_list_rate(),
            external_cards: Self::default_external_cards(),
            image_uploads_per_hour: Self::default_image_uploads(),
        }
    }
}

/// Data rooms hosted by this community (`[rooms]`).
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RoomsConfig {
    /// Room files (`[rooms.files]`): the `rooms/blobs/*` tasks and `rooms/records/put/0.2`.
    ///
    /// **Absent means off**, and absent is what every configuration written before room
    /// files existed has. Such a VTC starts exactly as before: no directory is created,
    /// no storage config is seeded, uploads are refused and the console says how to turn
    /// files on. Writing the section is what turns them on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<RoomFilesConfig>,
    /// How much `rooms/*` traffic `POST /v1/trust-tasks` admits (`[rooms.rate_limits]`,
    /// [`crate::routing::trust_task_admission`]). **Absent means the defaults**, which is
    /// what every configuration written before this section existed has.
    #[serde(default, skip_serializing_if = "RoomRateLimitsConfig::is_unset")]
    pub rate_limits: RoomRateLimitsConfig,
    /// Rooms the community itself owns (`[rooms.community]`, the
    /// `vtc/rooms/community/*` tasks): where its VTA mints their identities.
    ///
    /// **Absent means off**, as every configuration written before community rooms
    /// existed is: such a VTC starts exactly as before, and a create is refused
    /// `noKeyHolder` naming this section. Writing it is what turns them on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub community: Option<CommunityRoomsConfig>,
}

/// Where the community's own rooms get their identities (`[rooms.community]`).
///
/// The community owns these rooms and its VTA (`vta_did`) holds their keys: it mints
/// each room's `did:webvh` from the `room` template, signs its credentials and holds the
/// community's place in a sealed room's group. This community holds no room key. It
/// reaches the VTA over the messaging link it already keeps, so `vta_did` and
/// `[messaging]` are needed too, and this community's DID needs an entry at the VTA in
/// `context` with `key-mint`, `credential-write`, `vault-write` and `room-open` (which
/// writes each room's profile into it), and `vault-read` to renew the authority over a
/// room created before renewal recorded where it is kept.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CommunityRoomsConfig {
    /// The context at the community's VTA the rooms' keys are minted in. This
    /// community's own entry there must act in it.
    pub context: String,
    /// A `did:webvh` hosting server registered at the VTA, by its id there, that
    /// publishes each room's log. **Absent**: the rooms' identities are minted
    /// serverless and this community serves each log itself, at
    /// `<public_url>/room-dids/<id>/did.jsonl`, so `public_url` must be set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webvh_server: Option<String>,
    /// The mediator each room's DID document names (the `room` template's
    /// `MEDIATOR_DID`). Absent: `[messaging] mediator_did`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mediator_did: Option<String>,
    /// How long the community's own `admin` authority over a room it creates lasts,
    /// in days. Default 365. A room whose owner's authority has lapsed can no longer
    /// admit or remove anyone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_valid_days: Option<u32>,
    /// How long before the community's own authority over a room lapses this
    /// community asks its VTA to renew it, in days. Default 30. Bounded by half of
    /// [`Self::authority_valid_days`], so a renewal is never due again the moment it
    /// lands (`rooms::community_renewal`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_renew_within_days: Option<u32>,
}

impl CommunityRoomsConfig {
    /// [`Self::authority_valid_days`], defaulted and at least one day.
    pub fn authority_valid_days(&self) -> u32 {
        self.authority_valid_days.unwrap_or(365).max(1)
    }

    /// [`Self::authority_renew_within_days`], defaulted, and never more than half the
    /// authority's own life: a renewal that was due again as soon as it landed would ask
    /// the VTA for a fresh credential on every pass.
    pub fn authority_renew_within(&self) -> chrono::Duration {
        let configured = chrono::Duration::days(i64::from(
            self.authority_renew_within_days
                .unwrap_or(crate::rooms::community_renewal::DEFAULT_RENEW_WITHIN_DAYS),
        ));
        let half_life = chrono::Duration::days(i64::from(self.authority_valid_days())) / 2;
        configured.min(half_life)
    }
}

/// The budgets room traffic is charged to on the HTTPS Trust Task door
/// (`[rooms.rate_limits]`). Every measure is optional; an absent one keeps its default.
///
/// Each budget is a token bucket: `*_burst` documents back to back, then one every
/// `*_interval_ms` **milliseconds per document** — an interval, not a rate, so a
/// *larger* interval is a *tighter* limit. Zero is read as 1.
///
/// Read when the first room document arrives; a change takes a restart.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RoomRateLimitsConfig {
    /// Every `rooms/*` document from one address, charged **before** anything in it is
    /// verified. Default burst 400, then one every 10 ms. A document that does not go on
    /// to verify and be authorized by its room costs this budget more (see
    /// [`crate::routing::trust_task_admission`]), so a flood of unverifiable documents
    /// stops here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_burst: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_interval_ms: Option<u64>,
    /// One presenter's operations in one room, charged **after** the room has
    /// authorized them. Default burst 120, then one every 100 ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presenter_burst: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presenter_interval_ms: Option<u64>,
    /// One presenter's file chunks in one room (`rooms/blobs/upload/chunk`,
    /// `rooms/blobs/chunk`), charged once the presenter is shown to hold the transfer.
    /// Default burst 200, then one every 20 ms — a 100 MB file at the default 256 KiB
    /// chunk is 400 chunks, about four seconds of waiting past the burst.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_burst: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_interval_ms: Option<u64>,
}

/// One budget: a burst, then one document every `interval`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoomBudget {
    pub burst: u32,
    pub interval: std::time::Duration,
}

impl RoomBudget {
    fn from(burst: Option<u32>, interval_ms: Option<u64>, default: RoomBudget) -> Self {
        Self {
            burst: burst.map_or(default.burst, |b| b.max(1)),
            interval: interval_ms.map_or(default.interval, |ms| {
                std::time::Duration::from_millis(ms.max(1))
            }),
        }
    }
}

/// The shipped room budgets: the per-address pre-verification ceiling.
pub const ROOM_ADDRESS_DEFAULT: RoomBudget = RoomBudget {
    burst: 400,
    interval: std::time::Duration::from_millis(10),
};
/// The shipped per-(room, presenter) budget for ordinary room operations.
pub const ROOM_PRESENTER_DEFAULT: RoomBudget = RoomBudget {
    burst: 120,
    interval: std::time::Duration::from_millis(100),
};
/// The shipped per-(room, presenter) budget for file chunks.
pub const ROOM_TRANSFER_DEFAULT: RoomBudget = RoomBudget {
    burst: 200,
    interval: std::time::Duration::from_millis(20),
};

impl RoomRateLimitsConfig {
    fn is_unset(&self) -> bool {
        *self == Self::default()
    }

    /// The per-address ceiling every room document is charged before verification.
    pub fn address(&self) -> RoomBudget {
        RoomBudget::from(
            self.address_burst,
            self.address_interval_ms,
            ROOM_ADDRESS_DEFAULT,
        )
    }

    /// The per-(room, presenter) budget for authorized room operations.
    pub fn presenter(&self) -> RoomBudget {
        RoomBudget::from(
            self.presenter_burst,
            self.presenter_interval_ms,
            ROOM_PRESENTER_DEFAULT,
        )
    }

    /// The per-(room, presenter) budget for file chunks.
    pub fn transfer(&self) -> RoomBudget {
        RoomBudget::from(
            self.transfer_burst,
            self.transfer_interval_ms,
            ROOM_TRANSFER_DEFAULT,
        )
    }
}

impl RoomsConfig {
    /// Whether this community accepts room files: a `[rooms.files]` section, not
    /// switched off inside it.
    pub fn files_enabled(&self) -> bool {
        self.files.as_ref().is_some_and(|f| f.enabled)
    }
}

/// Room files (`[rooms.files]`), `docs/05-design-notes/data-rooms-files.md` §5–§6.
///
/// **Off unless the section is present.** Writing `[rooms.files]` turns uploads on; an
/// operator does that knowing files will be stored under the directories it names.
/// Reads of stored files and records without files are served either way.
/// The limits are the same measures `room-host` takes on its command line. An absent one
/// keeps the shipped default of §6.2.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RoomFilesConfig {
    /// Accept uploads. Default `true` once the section is present; `false` keeps the
    /// section's settings and refuses uploads.
    #[serde(default = "default_files_enabled")]
    pub enabled: bool,
    /// The root of the `local` storage config seeded on first start. Default
    /// `<store.data_dir>/room-blobs`. Once seeded the stored config wins, and is changed
    /// with `vtc/storage/configs/update`. Not in a VTC backup, which carries the index
    /// of files (`room_blobs`) and never their bytes: back it up beside the data
    /// directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_dir: Option<PathBuf>,
    /// The directories a `local` storage config's root may be placed beneath. Default
    /// `[<store.data_dir>/room-storage]`. An administrator's config names a directory
    /// strictly inside one of these, after symbolic links are resolved, so the console
    /// can never point this service at the rest of the machine.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_storage_bases: Vec<PathBuf>,
    /// The largest single file, at most 1 GiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_file_bytes: Option<u64>,
    /// Limits on each room as a whole.
    #[serde(default)]
    pub room: RoomFileLimits,
    /// Limits on each member's own uploads in a room. Not applied on a `private` room.
    #[serde(default)]
    pub member: RoomFileLimits,
    /// Total stored across every room.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_capacity_bytes: Option<u64>,
    /// How long a file nothing names any more is kept before it is deleted. Default 168.
    #[serde(default = "default_orphan_grace_hours")]
    pub orphan_grace_hours: u64,
    /// How often deleted and abandoned files are collected. Default 600.
    #[serde(default = "default_blob_sweep_interval_secs")]
    pub sweep_interval_secs: u64,
    /// Which rooms a `rooms/blobs/*/0.2` transfer may go straight between the member
    /// and the room's storage, where that storage can issue time-limited URLs (an
    /// `s3` config through the community's VTA) and the member asks for it:
    /// `"not_private"` (the default) for `open` and `attributed` rooms; `"all"` to
    /// include `private` rooms, whose readers' network addresses the storage
    /// provider then sees; `"off"` to keep every transfer through this service.
    /// Browsers need the bucket's CORS set for it (`docs/02-vta/data-rooms.md` §8.2).
    #[serde(default, skip_serializing_if = "is_default_direct")]
    pub direct_transfer: vti_rooms::blobs::DirectTransfer,
}

fn is_default_direct(d: &vti_rooms::blobs::DirectTransfer) -> bool {
    *d == vti_rooms::blobs::DirectTransfer::default()
}

/// Limits at one scope; an absent measure keeps its default.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RoomFileLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_files: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_file_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
}

fn default_files_enabled() -> bool {
    true
}

fn default_orphan_grace_hours() -> u64 {
    vti_rooms::blobs::DEFAULT_ORPHAN_GRACE_SECS / 3600
}

fn default_blob_sweep_interval_secs() -> u64 {
    600
}

impl Default for RoomFilesConfig {
    fn default() -> Self {
        Self {
            enabled: default_files_enabled(),
            blob_dir: None,
            local_storage_bases: Vec::new(),
            max_file_bytes: None,
            room: RoomFileLimits::default(),
            member: RoomFileLimits::default(),
            storage_capacity_bytes: None,
            orphan_grace_hours: default_orphan_grace_hours(),
            sweep_interval_secs: default_blob_sweep_interval_secs(),
            direct_transfer: Default::default(),
        }
    }
}

impl RoomFilesConfig {
    /// The limits this configuration sets, over the shipped defaults.
    pub fn limits(&self) -> vti_rooms::blobs::HostLimits {
        let mut limits = vti_rooms::blobs::HostLimits {
            files_enabled: self.enabled,
            orphan_grace_secs: self.orphan_grace_hours.saturating_mul(3600),
            storage_capacity_bytes: self.storage_capacity_bytes,
            ..Default::default()
        };
        if let Some(v) = self.max_file_bytes {
            limits.max_file_bytes = v;
        }
        let set = |slot: &mut Option<u64>, v: Option<u64>| {
            if v.is_some() {
                *slot = v;
            }
        };
        set(&mut limits.room.max_files, self.room.max_files);
        set(&mut limits.room.max_file_bytes, self.room.max_file_bytes);
        set(&mut limits.room.max_bytes, self.room.max_bytes);
        set(&mut limits.member.max_files, self.member.max_files);
        set(
            &mut limits.member.max_file_bytes,
            self.member.max_file_bytes,
        );
        set(&mut limits.member.max_bytes, self.member.max_bytes);
        limits
    }
}

/// OpenID4VP wallet-session settings (`[oid4vp]`), read when a session opens
/// and when a wallet answers — `vtc/join-requests/wallet-session/start/0.1`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Oid4vpConfig {
    /// Seconds a session stays open for a wallet to answer. The specification
    /// asks for minutes, not hours (consumer rule 8). Default 600.
    #[serde(default = "default_oid4vp_session_ttl")]
    pub session_ttl_secs: u64,
    /// Open sessions one applicant may hold at once (consumer rule 12).
    /// Default 3.
    #[serde(default = "default_oid4vp_max_open_sessions")]
    pub max_open_sessions: usize,
    /// Seconds evidence not bound to a join request is held for the
    /// applicant's next submission before it is discarded (consumer rule 11:
    /// hours, not days). Default 21600 (6 hours).
    #[serde(default = "default_oid4vp_evidence_hold")]
    pub evidence_hold_secs: u64,
    /// The largest wallet response body accepted at `response_uri`, in bytes.
    /// swiyu advises verifiers to plan for responses far above the VTC's usual
    /// cap; raise this if the communities' credentials are large. Default
    /// 4 MiB.
    #[serde(default = "default_oid4vp_max_response_bytes")]
    pub max_response_bytes: usize,
    /// The verifier identity (`vtc oid4vp install --identity <id>`) used when a
    /// session names no client identifier prefix. Unset: the first installed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_identity: Option<String>,
    /// The URI scheme of the wallet invocation link, in place of the
    /// ecosystem's own (`swiyu-verify` for a swiyu identity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_uri_scheme: Option<String>,
    /// PEM files of the certificates this community trusts to certify
    /// credential issuers that are known by an X.509 chain instead of a DID —
    /// the EUDI PID providers' list, a Rulebook's anchor. Read at boot; a file
    /// that does not load stops it. Empty: no such issuer is trusted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub x509_trust_anchors: Vec<std::path::PathBuf>,
    /// The swiyu trust registry this community takes issuer trust from: an
    /// issuer it publishes an Identity Trust Statement about counts as one the
    /// community recognises (`credentialIssuers: recognised`). Unset: none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swiyu_trust: Option<SwiyuTrustConfig>,
}

/// `[oid4vp.swiyu_trust]` — where swiyu issuer trust is read from
/// ([`crate::oid4vp::swiyu_issuer`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SwiyuTrustConfig {
    /// The trust registry's base URL, `https` — the Sandbox's is
    /// `https://trust-reg.trust-infra.swiyu-int.admin.ch`.
    pub registry_url: String,
    /// The DID that signs its identity trust statements (the ecosystem's trust
    /// anchor). A statement signed by any other key is refused.
    pub trust_anchor_did: String,
}

impl SwiyuTrustConfig {
    /// Refuse, at boot, a registry that is not `https` or an anchor that is
    /// not a DID — either would admit nobody, silently.
    pub fn check(&self) -> Result<(), String> {
        let url = url::Url::parse(&self.registry_url)
            .map_err(|e| format!("[oid4vp.swiyu_trust] registry_url: {e}"))?;
        if url.scheme() != "https" {
            return Err("[oid4vp.swiyu_trust] registry_url must be https".into());
        }
        if !self.trust_anchor_did.starts_with("did:") || self.trust_anchor_did.contains('#') {
            return Err("[oid4vp.swiyu_trust] trust_anchor_did must be a DID".into());
        }
        Ok(())
    }
}

fn default_oid4vp_session_ttl() -> u64 {
    600
}

fn default_oid4vp_max_open_sessions() -> usize {
    3
}

fn default_oid4vp_evidence_hold() -> u64 {
    6 * 3600
}

fn default_oid4vp_max_response_bytes() -> usize {
    4 * 1024 * 1024
}

impl Default for Oid4vpConfig {
    fn default() -> Self {
        Self {
            session_ttl_secs: default_oid4vp_session_ttl(),
            max_open_sessions: default_oid4vp_max_open_sessions(),
            evidence_hold_secs: default_oid4vp_evidence_hold(),
            max_response_bytes: default_oid4vp_max_response_bytes(),
            x509_trust_anchors: Vec::new(),
            swiyu_trust: None,
            default_identity: None,
            wallet_uri_scheme: None,
        }
    }
}

/// Local GeoIP lookups (`[geoip]`) — base design §12.6: a local database only,
/// never a third-party call. See `docs/03-vtc/geoip.md` and [`crate::geoip`].
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct GeoIpConfig {
    /// Path of a MaxMind DB (`.mmdb`) file with the GeoIP2 City record shape:
    /// DB-IP "IP to City Lite" (recommended, CC BY 4.0 — attribution
    /// required) or MaxMind GeoLite2 City. Re-read when it changes on disk, so
    /// a refresh needs no restart. `None` (default): no lookups, every
    /// sign-in location is `"unknown"`. A file that cannot be read is a
    /// warning at startup, not a boot failure. Env: `VTC_GEOIP_DATABASE`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<PathBuf>,
}

/// Authority settings for the community's ACL.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AclConfig {
    /// How many **other** unrestricted admins must consent before anyone is
    /// granted unrestricted admin authority, or has an entry widened to it
    /// (VTI-APV-014). The requester never counts (VTI-APV-007).
    ///
    /// At least 1: a second party is the requirement, so there is no value that
    /// switches it off. A value the community cannot meet — more than its
    /// unrestricted admins other than the requester — is refused when it is
    /// written at runtime (VTI-APV-009); see `crate::acl::admin_consent`.
    #[serde(default = "default_unrestricted_admin_consent_threshold")]
    pub unrestricted_admin_consent_threshold: u64,
    /// How long, in seconds, an operation parked for approval stays open
    /// before it expires (VTI-APV-008) — `docs/05-design-notes/vtc-action-list.md`
    /// §5. Default 72 hours, bounded 15 minutes to 14 days. An open action keeps
    /// the `expiresAt` it was raised with; a change binds only later ones.
    #[serde(default = "default_action_lifetime")]
    pub action_lifetime: u64,
    /// How many open actions one requester may hold at once (§7a.1).
    #[serde(default = "default_action_max_open_per_requester")]
    pub action_max_open_per_requester: u64,
    /// How many open actions the community may hold at once (§7a.1).
    #[serde(default = "default_action_max_open")]
    pub action_max_open: u64,
    /// Seconds after a decline during which the same requester may not raise
    /// the same kind of action against the same subject again (§7a.1).
    #[serde(default = "default_action_decline_cooldown")]
    pub action_decline_cooldown: u64,
    /// Seconds a reduction of an unrestricted administrator waits before it
    /// lands when nobody but the requester and the subject could consent to it
    /// — the two-administrator case (VTI-APV-019,
    /// `docs/05-design-notes/vtc-action-list.md` §8.2). Default 24 hours,
    /// bounded 0 to 7 days; 0 lands it at once. The requester may cancel it
    /// meanwhile; the subject sees it coming but cannot block it.
    #[serde(default = "default_removal_cooling_off")]
    pub removal_cooling_off: u64,
    /// Whether a raised action is also pushed, VTC-signed, to each approver's
    /// devices as `task-consent/request/0.1`. **Off by default**
    /// (`vtc-action-list.md` §11.6): the action list is the source of truth,
    /// and a push is best-effort at most.
    #[serde(default)]
    pub consent_request_push: bool,
    /// **Single-administrator mode** (VTI-APV-022). When `true`, an operation
    /// that would wait for another administrator's consent (VTI-APV-018, -020,
    /// VTI-VTC-022) runs on the requester's operation-bound passkey gesture
    /// (VTI-APV-015) instead, audited at `Critical` — whether or not other
    /// administrators' entries exist. The mode is the host's statement that
    /// every administrator is the same person, under as many identifiers (one
    /// per device, say) as they hold (item 2); turn it off on the host and
    /// ordinary consent applies again. A reduction of another administrator
    /// (VTI-APV-019) keeps its gesture, notice, `Critical` row and
    /// cooling-off. An administrator whose entry is unrestricted may also edit
    /// its own entry, on the same gesture (VTI-ACL-052 item 3).
    ///
    /// Host configuration only (VTI-APV-022 item 1): read once at start, and
    /// deliberately absent from the runtime `config/patch` registry and from
    /// `vtc/config/import`, which refuse it by name. Set by `vtc setup
    /// --single-admin`, or by editing `config.toml` and restarting. Not
    /// written to `config.toml` unless on.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub single_admin_mode: bool,
}

impl Default for AclConfig {
    fn default() -> Self {
        Self {
            unrestricted_admin_consent_threshold: default_unrestricted_admin_consent_threshold(),
            action_lifetime: default_action_lifetime(),
            action_max_open_per_requester: default_action_max_open_per_requester(),
            action_max_open: default_action_max_open(),
            action_decline_cooldown: default_action_decline_cooldown(),
            removal_cooling_off: default_removal_cooling_off(),
            consent_request_push: false,
            single_admin_mode: false,
        }
    }
}

pub(crate) fn default_unrestricted_admin_consent_threshold() -> u64 {
    1
}

/// 72 hours: a weekend for a small team (`vtc-action-list.md` §5).
pub(crate) fn default_action_lifetime() -> u64 {
    72 * 3600
}

pub(crate) fn default_action_max_open_per_requester() -> u64 {
    5
}

pub(crate) fn default_action_max_open() -> u64 {
    50
}

pub(crate) fn default_action_decline_cooldown() -> u64 {
    3600
}

/// 24 hours (`vtc-action-list.md` §11.4).
pub(crate) fn default_removal_cooling_off() -> u64 {
    24 * 3600
}

/// Trust Task document-dispatch settings. **Empty of live settings**: every
/// check the dispatcher applies is now unconditional.
///
/// The acceptance window over `issuedAt` (`VTI-OPS-024`), the in-band
/// `recipient` (`VTI-OPS-023`), audience binding, the replay record
/// (`VTI-OPS-025`…`027`), verification of any `proof` present against the
/// document's own `issuer`, and — since this change — the refusal of a
/// document carrying **no** proof for a task whose specification declares one
/// REQUIRED (`VTI-OPS-020`, `VTI-OPS-021`, `VTI-OPS-093`).
///
/// What remains here is the retired key, kept so a config that still sets it
/// is answered rather than ignored.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct TrustTasksConfig {
    /// **Retired**: `[trust_tasks] require_declared_proof` (#1641, removed by
    /// #1672).
    ///
    /// It gated one refusal — a document carrying no `proof` for a task whose
    /// specification declares one REQUIRED (SPEC §7.2 item 7, VTI-OPS-021,
    /// VTI-OPS-093) — and defaulted to `false` for exactly one reason:
    /// `openvtc-core` built `join-requests/{submit,status}`,
    /// `members/{self-remove,vmc}` and `members/personhood/assert` with a
    /// deliberate "no `proof` is attached", so enforcing would have refused
    /// every join on a community serving that client. #1659's own removal
    /// condition was "when `openvtc-core` signs the five documents above, the
    /// default flips and this field goes with it". openvtc#371 signs them
    /// (`trust_task_doc::build_signed_value`), so it has.
    ///
    /// Present only to answer a config that still declares it, and the two
    /// values are answered differently because they are different intents:
    ///
    /// - `true` — the behaviour the operator asked for, which is now the only
    ///   behaviour. Nothing is lost by proceeding, so [`AppConfig::load`]
    ///   warns and starts. Delete the line.
    /// - `false` — an intent that can no longer be honoured at all. Starting
    ///   anyway would enforce the opposite of what the file says, so the
    ///   deserializer refuses it here, where the operator is still reading
    ///   their own config rather than a client's refusals.
    ///
    /// Absent (the state to arrive at) deserializes to `None` via `default`.
    #[serde(
        default,
        deserialize_with = "refuse_disabling_declared_proof",
        skip_serializing
    )]
    pub require_declared_proof: Option<bool>,
}

/// Reject `require_declared_proof = false`, and pass `true` through for
/// [`AppConfig::load`] to warn about.
///
/// Only ever called when the key is present — `#[serde(default)]` covers its
/// absence — so reaching this function means the operator wrote it down.
///
/// The refusal is here, in the deserializer, rather than in `load`: it must
/// hold for every path that parses an `AppConfig`, not only the one the daemon
/// boots through. The *warning* cannot be, because `load` runs before
/// `init_tracing` and a `warn!` with no subscriber installed is exactly the
/// silence this is meant to avoid.
fn refuse_disabling_declared_proof<'de, D>(d: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    if bool::deserialize(d)? {
        return Ok(Some(true));
    }
    Err(serde::de::Error::custom(
        "`[trust_tasks] require_declared_proof = false` has been retired and \
         cannot be honoured. A document carrying no `proof` for a task whose \
         specification declares one REQUIRED is now always refused \
         (VTI-OPS-020/021/093, Trust Tasks SPEC §7.2 item 7); the switch \
         existed only while `openvtc-core` sent those documents unsigned, and \
         openvtc#371 signs them. Delete the key. A community still serving an \
         `openvtc` build older than that change must upgrade the client — \
         there is no longer a setting that will accept its unsigned joins, \
         status polls, self-removals, VMC collection or personhood assertions.",
    ))
}

/// Admin UX configuration (§12.2, Phase 5 M5.7).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct AdminUiConfig {
    /// `"embedded"` (default): serve the baked admin SPA at
    /// `routing.admin_ui.mount`. `"directory"`: serve the console
    /// from [`Self::dir`] on disk instead, so a community owner can
    /// restyle or rebuild it without rebuilding the daemon.
    ///
    /// `"external"` (an SPA hosted on another origin) is retired and
    /// refused: it was never served, and the console cannot work from
    /// another origin — it reads the CSRF cookie, calls the API by
    /// relative URL, and passkeys are bound to the VTC's own origin.
    #[serde(default = "default_admin_ui_mode")]
    pub mode: String,
    /// Directory the console is served from when `mode = "directory"`.
    /// Must hold an `index.html` (the SPA shell); every other path is
    /// served from it or falls back to that shell. `vtc admin-ui export
    /// <dir>` writes the baked console here as a starting point.
    /// Required with `mode = "directory"`, refused with any other mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<std::path::PathBuf>,
    /// Directory the **member portal** (`/members/*`) is served from instead
    /// of the binary, independent of `mode`. Must hold an `index.html`;
    /// `vtc admin-ui export --members <dir>` writes the baked portal there
    /// as a starting point. `None` (default) serves the baked portal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members_dir: Option<std::path::PathBuf>,
    /// Retired with `mode = "external"`. Present only to **refuse** a config
    /// that still declares it; absent (the only accepted state)
    /// deserializes to `()`.
    #[serde(
        default,
        deserialize_with = "refuse_retired_external_origin",
        skip_serializing
    )]
    pub external_origin: (),
    /// WebAuthn RP-ID override. When `None`, derived from the
    /// routing mode (path-mode → base host; subdomain-mode →
    /// base domain).
    #[serde(default)]
    pub rp_id: Option<String>,
    /// Directory the daemon scans for third-party plugins. Each
    /// subdirectory is one plugin: `<plugin_dir>/<id>/manifest.json`
    /// declares the manifest; the daemon serves the directory's
    /// static files under `/admin/plugins/<id>/`. `None` (default)
    /// → only built-in plugins, no third-party scan.
    ///
    /// Plugin IDs must match `^[a-z][a-z0-9-]*$` — anything else
    /// is dropped from the manifest endpoint with a `warn!`.
    #[serde(default)]
    pub plugin_dir: Option<std::path::PathBuf>,
    /// Host of the **trigger link** the member portal's wallet sign-in shows
    /// as a QR code and a link (`https://<host>/t#_from=…`). `None` (default)
    /// means `link.trustoverip.org`, the shared host every participating
    /// wallet declares. Must be a public DNS name and must **not** be on the
    /// portal's own domain: a universal link tapped on a page of the same
    /// domain opens in the browser, not the wallet (VTI-LNK-060, VTI-LNK-084).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_in_link_host: Option<String>,
}

impl Default for AdminUiConfig {
    fn default() -> Self {
        Self {
            mode: default_admin_ui_mode(),
            dir: None,
            members_dir: None,
            external_origin: (),
            rp_id: None,
            plugin_dir: None,
            sign_in_link_host: None,
        }
    }
}

/// Reject `admin_ui.external_origin` with the replacement. Only called when
/// the key is present, so reaching it *is* the error.
fn refuse_retired_external_origin<'de, D>(_: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    Err(serde::de::Error::custom(RETIRED_EXTERNAL_MODE))
}

const RETIRED_EXTERNAL_MODE: &str = "admin_ui `mode = \"external\"` and `external_origin` have been \
     retired — the console cannot run from another origin. To customise it, serve it from a \
     directory instead: `vtc admin-ui export <dir>`, then `mode = \"directory\"` and \
     `dir = \"<dir>\"`, and remove `external_origin`.";

fn default_admin_ui_mode() -> String {
    "embedded".into()
}

impl AdminUiConfig {
    /// The trigger-link host the portal's wallet sign-in uses.
    pub fn sign_in_link_host(&self) -> &str {
        self.sign_in_link_host
            .as_deref()
            .unwrap_or(crate::member_portal::oob::DEFAULT_LINK_HOST)
    }

    /// The directory to serve the console from, when `mode = "directory"`.
    /// `None` for every other mode.
    pub fn serve_dir(&self) -> Option<&std::path::Path> {
        match self.mode.as_str() {
            "directory" => self.dir.as_deref(),
            _ => None,
        }
    }

    /// Shape checks: a known mode, and `dir` set exactly when the mode is
    /// `"directory"`. A `dir` beside another mode is refused rather than
    /// ignored — an owner who customised a console and sees the stock one
    /// would otherwise have no clue why. Whether the directory exists is
    /// checked at boot ([`crate::admin_ui::check_serve_dir`]), not here,
    /// so a config can be written before the directory is.
    fn validate(&self) -> Result<(), AppError> {
        match (self.mode.as_str(), self.dir.is_some()) {
            ("directory", true) | ("embedded", false) => Ok(()),
            ("external", _) => Err(AppError::Config(RETIRED_EXTERNAL_MODE.into())),
            ("directory", false) => Err(AppError::Config(
                "admin_ui.mode = \"directory\" needs admin_ui.dir — the directory \
                 holding the console's index.html (`vtc admin-ui export <dir>` writes \
                 the built-in console there to start from)"
                    .into(),
            )),
            ("embedded", true) => Err(AppError::Config(format!(
                "admin_ui.dir is set but admin_ui.mode = \"{}\", so it would be \
                 ignored — set mode = \"directory\" to serve the console from it, or \
                 remove dir",
                self.mode
            ))),
            (other, _) => Err(AppError::Config(format!(
                "admin_ui.mode = \"{other}\" is not one of \"embedded\", \"directory\""
            ))),
        }
    }
}

/// Public community website (§12.1, Phase 5 M5.4.1). Filesystem-
/// backed static hosting under [`Self::root_dir`].
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct WebsiteConfig {
    /// Directory served as the site root. `None` disables the
    /// handler entirely (it 503s with a clear error). No default
    /// — operators opt in by setting this to a real path.
    #[serde(default)]
    pub root_dir: Option<PathBuf>,
    /// Deploy mode: `"live"` (default) or `"managed"`. See
    /// [`crate::website::WebsiteRoot`].
    #[serde(default = "default_deploy_mode")]
    pub deploy_mode: String,
    /// Cache TTL for the live-mode FD cache, in seconds.
    /// Defaults to 5 — short enough that `scp` / `rsync` edits
    /// surface quickly, long enough to amortise repeat hits.
    #[serde(default = "default_live_cache_ttl_seconds")]
    pub live_cache_ttl_seconds: u64,
    /// Managed mode: retain this many old generations beyond
    /// the active one. Default 5.
    #[serde(default = "default_managed_generations_keep")]
    pub managed_generations_keep: u32,
    /// `Cache-Control` header on every successful response.
    /// Defaults to `"public, max-age=300"` — five minutes for a
    /// CDN to cache.
    #[serde(default = "default_cache_control")]
    pub cache_control: String,
    /// Extensions refused unconditionally. Default
    /// `[".cgi", ".php", ".exe"]`. Lowercased + dot-prefixed.
    #[serde(default = "default_executable_blocklist")]
    pub executable_blocklist: Vec<String>,
    /// Maximum bundle size for `POST /v1/website/deploy` (M5.5).
    /// Tested at the management API; informational here.
    #[serde(default = "default_max_bundle_size_mb")]
    pub max_bundle_size_mb: u64,
    /// Maximum size for a single `PUT /v1/website/files/...`
    /// upload (M5.5). Tested at the management API; informational
    /// here.
    #[serde(default = "default_max_file_size_mb")]
    pub max_file_size_mb: u64,
    /// Per-site override file (relative to `root_dir`). Currently
    /// supports a single key, `csp = "..."`, that replaces the
    /// default CSP for this site. Default `".vtc-website.toml"`.
    #[serde(default = "default_csp_override_file")]
    pub csp_override_file: String,
}

impl Default for WebsiteConfig {
    fn default() -> Self {
        Self {
            root_dir: None,
            deploy_mode: default_deploy_mode(),
            live_cache_ttl_seconds: default_live_cache_ttl_seconds(),
            managed_generations_keep: default_managed_generations_keep(),
            cache_control: default_cache_control(),
            executable_blocklist: default_executable_blocklist(),
            max_bundle_size_mb: default_max_bundle_size_mb(),
            max_file_size_mb: default_max_file_size_mb(),
            csp_override_file: default_csp_override_file(),
        }
    }
}

fn default_deploy_mode() -> String {
    "live".into()
}
fn default_live_cache_ttl_seconds() -> u64 {
    5
}
fn default_managed_generations_keep() -> u32 {
    5
}
fn default_cache_control() -> String {
    "public, max-age=300".into()
}
fn default_executable_blocklist() -> Vec<String> {
    vec![".cgi".into(), ".php".into(), ".exe".into()]
}
fn default_max_bundle_size_mb() -> u64 {
    50
}
fn default_max_file_size_mb() -> u64 {
    10
}
fn default_csp_override_file() -> String {
    ".vtc-website.toml".into()
}

/// Renewal-path settings. Phase 4 M4.2.2.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub struct RenewalConfig {
    /// What to do when the active `personhood.rego` returns
    /// `false` for a member whose current `personhood` flag
    /// is `true` (spec §6.3 step 3 + Phase 4 plan D5 review).
    ///
    /// - [`PersonhoodFailMode::Downgrade`] (default): flip the
    ///   Member row's flag to `false`, re-mint the VMC with
    ///   `personhood: false`, audit a `PersonhoodRevoked
    ///   { reason: "renewal-policy" }` envelope, **succeed**.
    ///   Preserves §3-B "ACL is authoritative" — membership
    ///   lifecycle is decoupled from personhood lifecycle.
    /// - [`PersonhoodFailMode::Refuse`]: return `422
    ///   Unprocessable Entity` with stable reason
    ///   `personhood-renewal-refused`. Member row stays
    ///   `true`; no VMC re-mint; no audit envelope. Caller
    ///   re-asserts via the assert endpoint before retrying.
    #[serde(default)]
    pub on_personhood_fail: PersonhoodFailMode,
}

/// What renewal does when `personhood.rego` drops a previously-
/// asserted member's flag to `false`. See [`RenewalConfig`].
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PersonhoodFailMode {
    /// Re-mint with `personhood: false`. Default. Recommended
    /// for most deployments.
    #[default]
    Downgrade,
    /// Return `422`. Stricter privacy posture.
    Refuse,
}

/// Trust-registry runtime settings.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct RegistryConfig {
    /// Base URL of the upstream TRQP-compliant registry
    /// (e.g. `https://registry.example.com`).
    ///
    /// **Optional, and no longer the primary address.** With [`Self::did`] set
    /// this is the REST *arm* of the messaging client — used only when the
    /// registry advertises `TRQPRest` and no messaging transport. On its own it
    /// selects the HTTP-only client, which can answer TRQP queries but cannot
    /// write records (the upstream exposes writes over Trust Tasks only).
    ///
    /// Neither `url` nor `did` ⇒ registry features no-op, `registry_status`
    /// reads `"degraded"`, sync is skipped.
    #[serde(default)]
    pub url: Option<String>,
    /// DID of the trust registry.
    ///
    /// The primary address: the registry is reached over whichever transport
    /// both DID documents advertise (TSP > DIDComm > REST, matched on service
    /// `type`). Covers membership sync (`registry/record/{put,delete,query}`),
    /// recognition queries, the health probe, and the git-trust /
    /// `governance/capability/*` hook relay — so a registry that publishes a
    /// DID and nothing else is fully usable.
    ///
    /// Unset ⇒ the hook relay is not spawned and the client falls back to
    /// [`Self::url`], if set.
    #[serde(default)]
    pub did: Option<String>,
    /// Period (seconds) between background health probes.
    /// `0` disables the periodic probe (only boot-time probe
    /// runs). Default: 60s.
    ///
    /// Over messaging the probe is a read-only `registry/record/query` round
    /// trip, so `registry_status` tracks whether the registry actually answers
    /// — not merely whether a URL is up.
    #[serde(default = "default_health_probe_interval")]
    pub health_probe_interval_seconds: u64,
    /// Period (seconds) between background drift checks — the comparison of
    /// the local `registry_records` mirror against what the registry actually
    /// holds. `0` disables it. Default: 900s (15 minutes).
    ///
    /// Much slower than the health probe on purpose. The probe is one round
    /// trip and answers "is the registry up"; a drift check enumerates the
    /// whole graph and answers "is what we published still there", which
    /// changes on the timescale of membership events, not of sockets.
    #[serde(default = "default_drift_check_interval")]
    pub drift_check_interval_seconds: u64,
    /// Per-call HTTP timeout for registry operations (seconds).
    /// Default: 5s.
    #[serde(default = "default_registry_http_timeout")]
    pub http_timeout_seconds: u64,
    /// RTBF-batch coalescing window (hours) — spec §8.2 +
    /// M3.7. When the syncer's walker fires an RTBF override,
    /// the resulting `DeleteMember` job is parked for at
    /// least this many hours before the registry call goes
    /// out. The window de-correlates the override audit
    /// envelope's timestamp from the registry record's
    /// disappearance so an external observer can't time-align
    /// the two and re-identify the RTBF requester. Set to `0`
    /// to disable batching (RTBF jobs dispatch immediately —
    /// useful in tests; **not recommended in production**).
    /// Default: 24h.
    #[serde(default = "default_rtbf_batch_window_hours")]
    pub rtbf_batch_window_hours: u64,
}

fn default_health_probe_interval() -> u64 {
    60
}

fn default_drift_check_interval() -> u64 {
    900
}

fn default_registry_http_timeout() -> u64 {
    5
}

fn default_rtbf_batch_window_hours() -> u64 {
    24
}

impl Default for RegistryConfig {
    fn default() -> Self {
        // Production defaults — match the serde-default
        // values. Deriving Default would zero every numeric
        // field, silently disabling the periodic probe + the
        // RTBF batch protection. Keep the two in sync by
        // construction.
        Self {
            url: None,
            did: None,
            health_probe_interval_seconds: default_health_probe_interval(),
            drift_check_interval_seconds: default_drift_check_interval(),
            http_timeout_seconds: default_registry_http_timeout(),
            rtbf_batch_window_hours: default_rtbf_batch_window_hours(),
        }
    }
}

/// Per-surface mount config (spec §9.2). Phase-0 surfaces:
///
/// - `api` — the JSON REST + DIDComm management surface. **Always
///   mounted**; this is the daemon's reason to exist.
/// - `admin_ui` — the (eventual) admin SPA. Phase 0 leaves the
///   mount declared but doesn't serve anything; the slot reserves
///   the path so cookie scopes don't collide later.
/// - `website` — public community site (Phase 5+). Same story —
///   the mount is reserved, the route table is empty.
///
/// **Mode**: per the spec, each surface can be path-prefixed
/// (`mount`) or host-routed (`host`). Phase 0 exercises only the
/// path-prefix default. Subdomain mode is accepted by the config
/// parser but not driven by any code path until later phases.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct RoutingConfig {
    #[serde(default = "default_api_mount")]
    pub api: MountConfig,
    #[serde(default = "default_admin_ui_mount")]
    pub admin_ui: MountConfig,
    #[serde(default = "default_website_mount")]
    pub website: MountConfig,
    /// Subdomain-mode strictness (Phase 5 M5.1.2). When at least one
    /// surface has `host` set:
    ///
    /// - `true` (default): a request whose `Host` header doesn't match
    ///   any configured surface returns 404 `HostNotRecognised`.
    /// - `false`: unknown hosts fall back to path-mode prefix
    ///   matching against the parent router. Debug aid only — not
    ///   recommended for production.
    ///
    /// No effect when every surface has `host = None` (pure path
    /// mode).
    #[serde(default = "default_subdomain_mode_strict")]
    pub subdomain_mode_strict: bool,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            api: default_api_mount(),
            admin_ui: default_admin_ui_mount(),
            website: default_website_mount(),
            subdomain_mode_strict: default_subdomain_mode_strict(),
        }
    }
}

fn default_subdomain_mode_strict() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct MountConfig {
    /// Path prefix the surface attaches under (e.g. `/v1`,
    /// `/admin`, `/`). Path mode is the Phase-0 default.
    pub mount: String,
    /// Optional host header for subdomain mode. Accepted by the
    /// config parser; not exercised by Phase-0 routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

fn default_api_mount() -> MountConfig {
    MountConfig {
        mount: "/v1".into(),
        host: None,
    }
}

fn default_admin_ui_mount() -> MountConfig {
    MountConfig {
        mount: "/admin".into(),
        host: None,
    }
}

fn default_website_mount() -> MountConfig {
    MountConfig {
        mount: "/".into(),
        host: None,
    }
}

/// CORS allowlist (spec §9.3). Wildcards (`*`) are refused at
/// config-load — the spec demands an explicit allowlist so the
/// admin UX origin (and only that origin) can mutate the daemon.
///
/// When the list is empty, **CORS is disabled** — every cross-
/// origin request gets the default browser rejection. Path-mode
/// deployments serving the admin UX same-origin don't need any
/// entries.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct CorsConfig {
    /// Exact-match origin allowlist. Each entry is a full origin
    /// (`https://host:port` — no path). Wildcards rejected.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub trust_xff_cidrs: Vec<IpNetwork>,
    /// Retired: `trust_xff`. Present only to **refuse** a config that still
    /// declares it — replaced by `trust_xff_cidrs`, an explicit trusted-proxy
    /// CIDR allowlist. Absent (the only accepted state) deserializes to `()`
    /// via `default`.
    #[serde(
        default,
        deserialize_with = "refuse_retired_trust_xff",
        skip_serializing
    )]
    pub trust_xff: (),
}

/// Reject `trust_xff` with the migration the operator needs.
///
/// Only ever called when the key is present — `#[serde(default)]` covers its
/// absence — so reaching this function *is* the error.
fn refuse_retired_trust_xff<'de, D>(_: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    Err(serde::de::Error::custom(
        "`trust_xff` has been retired. Replace it with `trust_xff_cidrs = [\"<cidr>\", ...]` \
         — the addresses of the reverse proxies actually in front of this VTC. A `true` \
         config silently keying the rate limiter on the socket peer after this change \
         collapses every client behind that proxy into one shared bucket.",
    ))
}

// `deny_unknown_fields` so a typo'd backend selector (`aws_secretname`,
// `gcp_secrets_name`, …) is a loud parse error rather than a silently-dropped
// key that lets the factory fall through to the keyring/plaintext default
// (P0.8). Safe here — `SecretsConfig` carries no serde aliases; the
// alias-bearing fields live on the parent `AppConfig`, which is intentionally
// left lenient until the alias audit in the plan.
/// Explicit secret-store backend selector.
///
/// When set on [`SecretsConfig::backend`], it wins outright over the
/// legacy "whichever selector field is set" implicit resolution — so a
/// declarative deploy (K8s, an immutable image) states its backend once
/// and unambiguously, and `create_secret_store` validates that the
/// backend's required fields are present rather than silently picking a
/// different backend whose field happens to also be set. When unset
/// (`None`), resolution is unchanged (implicit priority chain).
///
/// Variant → required field: `vault` → `vault_addr`, `k8s` →
/// `k8s_secret_name`, `aws` → `aws_secret_name`, `gcp` → `gcp_secret_name`
/// (+ `gcp_project`), `azure` → `azure_vault_url`, `config` → `secret`.
/// `encrypted-file` → the `[secrets.encrypted_file]` table.
/// `keyring` and `plaintext` need no field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretBackend {
    /// OS keyring (the default when nothing is selected).
    Keyring,
    /// HashiCorp Vault (KV v2).
    Vault,
    /// Kubernetes `Secret`.
    K8s,
    /// AWS Secrets Manager.
    Aws,
    /// GCP Secret Manager.
    Gcp,
    /// Azure Key Vault.
    Azure,
    /// Hex secret inlined in `[secrets] secret` in config.toml (read-only).
    Config,
    /// Plaintext file under the data dir — NOT secure, dev/test only.
    Plaintext,
    /// AEAD-encrypted file under the data dir (`secret.enc` by default), keyed
    /// by the KEK source in `[secrets.encrypted_file]`. Only ever selected
    /// explicitly. Implemented by `vti_secrets::seed_store::EncryptedFileSeedStore`.
    EncryptedFile,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsConfig {
    /// Explicit backend selector. When set, it overrides the implicit
    /// "whichever selector field is set" resolution and `create_secret_store`
    /// validates the chosen backend's required fields. Omit to keep the
    /// legacy priority-chain behaviour. Accepts `keyring` | `vault` | `k8s`
    /// | `aws` | `gcp` | `azure` | `config` | `plaintext` | `encrypted-file`.
    #[serde(default)]
    pub backend: Option<SecretBackend>,
    /// Hex-encoded VTC key material (config-secret feature)
    pub secret: Option<String>,
    /// AWS Secrets Manager secret name (aws-secrets feature)
    pub aws_secret_name: Option<String>,
    /// AWS region override (aws-secrets feature)
    pub aws_region: Option<String>,
    /// GCP project ID (gcp-secrets feature)
    pub gcp_project: Option<String>,
    /// GCP secret name (gcp-secrets feature)
    pub gcp_secret_name: Option<String>,
    /// Azure Key Vault URL (azure-secrets feature)
    pub azure_vault_url: Option<String>,
    /// Azure Key Vault secret name (azure-secrets feature)
    pub azure_secret_name: Option<String>,
    /// OS keyring service name (keyring feature).
    /// Change this to run multiple VTC instances on the same machine.
    #[serde(default = "default_keyring_service")]
    pub keyring_service: String,
    /// HashiCorp Vault server URL (vault-secrets feature). Setting this
    /// activates the Vault backend. Field names mirror the VTA's
    /// (`vti_secrets::SecretsConfig`) so the shared Vault builder is reused.
    pub vault_addr: Option<String>,
    /// KV v2 mount path (vault-secrets feature). Default `secret`.
    #[serde(default = "default_vault_kv_mount")]
    pub vault_kv_mount: String,
    /// KV v2 secret path under the mount, e.g. `vtc/key-bundle`
    /// (vault-secrets feature).
    pub vault_secret_path: Option<String>,
    /// Field name within the KV v2 secret that holds the hex-encoded key
    /// material (vault-secrets feature). Default `seed`.
    #[serde(default = "default_vault_secret_key")]
    pub vault_secret_key: String,
    /// Vault Enterprise namespace, if any (vault-secrets feature).
    pub vault_namespace: Option<String>,
    /// Auth method: `kubernetes` (default), `token`, or `approle`
    /// (vault-secrets feature).
    #[serde(default = "default_vault_auth_method")]
    pub vault_auth_method: String,
    /// Kubernetes auth role name (vault-secrets feature, kubernetes auth).
    pub vault_k8s_role: Option<String>,
    /// Kubernetes auth mount path (vault-secrets feature). Default
    /// `kubernetes`.
    #[serde(default = "default_vault_k8s_mount")]
    pub vault_k8s_mount: String,
    /// File holding the ServiceAccount JWT presented to Vault
    /// (vault-secrets feature, kubernetes auth). Default is the
    /// kubelet-mounted projected volume path.
    #[serde(default = "default_vault_k8s_jwt_path")]
    pub vault_k8s_jwt_path: String,
    /// Static token (vault-secrets feature, token auth). Prefer the
    /// `VAULT_TOKEN` env var over hard-coding here.
    pub vault_token: Option<String>,
    /// AppRole role_id (vault-secrets feature, approle auth).
    pub vault_approle_role_id: Option<String>,
    /// AppRole secret_id (vault-secrets feature, approle auth).
    pub vault_approle_secret_id: Option<String>,
    /// AppRole mount path (vault-secrets feature). Default `approle`.
    #[serde(default = "default_vault_approle_mount")]
    pub vault_approle_mount: String,
    /// Skip TLS certificate verification — dev/test only
    /// (vault-secrets feature).
    #[serde(default)]
    pub vault_skip_verify: bool,
    /// Kubernetes `Secret` name holding the hex-encoded VTC key material
    /// (k8s-secrets feature). Setting this activates the Kubernetes
    /// backend.
    pub k8s_secret_name: Option<String>,
    /// Kubernetes namespace the `Secret` lives in (k8s-secrets feature).
    /// When unset, the in-cluster ServiceAccount namespace (or the
    /// kubeconfig context namespace) is used, falling back to `default`.
    pub k8s_namespace: Option<String>,
    /// Key within the `Secret`'s `data` map that holds the hex-encoded
    /// key material (k8s-secrets feature). Default `secret`.
    #[serde(default = "default_k8s_secret_key")]
    pub k8s_secret_key: String,
    /// `[secrets.encrypted_file]`: location and key-encryption key source for
    /// `backend = "encrypted-file"` (the shape is `vti_secrets`'s, shared with
    /// the VTA). Never selects the backend by itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_file: Option<vti_secrets::EncryptedFileConfig>,
}

fn default_keyring_service() -> String {
    "vtc".to_string()
}

fn default_k8s_secret_key() -> String {
    "secret".to_string()
}

fn default_vault_kv_mount() -> String {
    "secret".to_string()
}

fn default_vault_secret_key() -> String {
    "seed".to_string()
}

fn default_vault_auth_method() -> String {
    "kubernetes".to_string()
}

fn default_vault_k8s_mount() -> String {
    "kubernetes".to_string()
}

fn default_vault_k8s_jwt_path() -> String {
    "/var/run/secrets/kubernetes.io/serviceaccount/token".to_string()
}

fn default_vault_approle_mount() -> String {
    "approle".to_string()
}

// Manual Debug — `secret` is the hex-encoded VTC key material; leaking
// it via a stray `{:?}` (e.g. a future `debug!(?config)`) would
// compromise every key derived from it. Redact it; the other fields are
// backend *names*, not secrets, so they print verbatim.
impl std::fmt::Debug for SecretsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretsConfig")
            .field("backend", &self.backend)
            .field("secret", &self.secret.as_ref().map(|_| "<redacted>"))
            .field("aws_secret_name", &self.aws_secret_name)
            .field("aws_region", &self.aws_region)
            .field("gcp_project", &self.gcp_project)
            .field("gcp_secret_name", &self.gcp_secret_name)
            .field("azure_vault_url", &self.azure_vault_url)
            .field("azure_secret_name", &self.azure_secret_name)
            .field("keyring_service", &self.keyring_service)
            .field("vault_addr", &self.vault_addr)
            .field("vault_kv_mount", &self.vault_kv_mount)
            .field("vault_secret_path", &self.vault_secret_path)
            .field("vault_secret_key", &self.vault_secret_key)
            .field("vault_namespace", &self.vault_namespace)
            .field("vault_auth_method", &self.vault_auth_method)
            .field("vault_k8s_role", &self.vault_k8s_role)
            .field("vault_k8s_mount", &self.vault_k8s_mount)
            .field("vault_k8s_jwt_path", &self.vault_k8s_jwt_path)
            // Secret-bearing: redact (token / approle secret_id are bearer creds).
            .field(
                "vault_token",
                &self.vault_token.as_ref().map(|_| "<redacted>"),
            )
            .field("vault_approle_role_id", &self.vault_approle_role_id)
            .field(
                "vault_approle_secret_id",
                &self.vault_approle_secret_id.as_ref().map(|_| "<redacted>"),
            )
            .field("vault_approle_mount", &self.vault_approle_mount)
            .field("vault_skip_verify", &self.vault_skip_verify)
            .field("k8s_secret_name", &self.k8s_secret_name)
            .field("k8s_namespace", &self.k8s_namespace)
            .field("k8s_secret_key", &self.k8s_secret_key)
            .field("encrypted_file", &self.encrypted_file)
            .finish()
    }
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            backend: None,
            secret: None,
            aws_secret_name: None,
            aws_region: None,
            gcp_project: None,
            gcp_secret_name: None,
            azure_vault_url: None,
            azure_secret_name: None,
            keyring_service: default_keyring_service(),
            vault_addr: None,
            vault_kv_mount: default_vault_kv_mount(),
            vault_secret_path: None,
            vault_secret_key: default_vault_secret_key(),
            vault_namespace: None,
            vault_auth_method: default_vault_auth_method(),
            vault_k8s_role: None,
            vault_k8s_mount: default_vault_k8s_mount(),
            vault_k8s_jwt_path: default_vault_k8s_jwt_path(),
            vault_token: None,
            vault_approle_role_id: None,
            vault_approle_secret_id: None,
            vault_approle_mount: default_vault_approle_mount(),
            vault_skip_verify: false,
            k8s_secret_name: None,
            k8s_namespace: None,
            k8s_secret_key: default_k8s_secret_key(),
            encrypted_file: None,
        }
    }
}

fn default_host() -> String {
    default_host_value()
}

fn default_port() -> u16 {
    default_port_value()
}

/// Compiled-in default for `server.host`. Exposed crate-wide so the
/// three-layer overlay in `config_store` can attribute the layer
/// source correctly (a TOML value equal to this is treated as
/// `Default`, not `Toml`).
pub(crate) fn default_host_value() -> String {
    "0.0.0.0".to_string()
}

/// Compiled-in default for `server.port`. See [`default_host_value`].
pub(crate) fn default_port_value() -> u16 {
    8200
}

fn default_server_config() -> ServerConfig {
    ServerConfig::default()
}

/// Refuse a config that would break the spec's routing
/// invariants. Phase-0 enforcement:
///
/// - **Path-mode mounts must be unique.** Two surfaces sharing the
///   same prefix would race for routes; reject at load.
/// - **`admin_ui.mount` must not be `/` in path mode.** Spec §9.3:
///   "refuses to start if cookie scopes would overlap (e.g., admin
///   mounted at / is rejected)". With admin at root, the future
///   admin session cookie's `Path=/admin` constraint collapses to
///   "any path", letting public-website JS read admin cookies.
/// - **Path-mode mounts start with `/`.** A bare `admin` mount is
///   almost certainly a typo; bail loud.
/// - **`api.mount` cannot equal `admin_ui.mount`.** Same family
///   of routes; cookie-scope rationale doesn't apply but the
///   ambiguity does.
fn validate_routing(routing: &RoutingConfig) -> Result<(), AppError> {
    for (name, m) in [
        ("api", &routing.api),
        ("admin_ui", &routing.admin_ui),
        ("website", &routing.website),
    ] {
        if !m.mount.starts_with('/') {
            return Err(AppError::Config(format!(
                "routing.{name}.mount must start with '/': got '{}'",
                m.mount
            )));
        }
    }

    // Cookie-scope guard. Only fires in path mode for the admin_ui
    // surface — subdomain mode (host set) carries its own scope.
    if routing.admin_ui.host.is_none() && routing.admin_ui.mount == "/" {
        return Err(AppError::Config(
            "routing.admin_ui.mount = '/' would collapse the admin cookie scope; \
             pick a non-root prefix (default: '/admin') or enable subdomain mode via \
             routing.admin_ui.host"
                .into(),
        ));
    }

    // Mount uniqueness (path mode only — subdomain mode disambiguates
    // by host). The `website` catch-all is allowed to share `/` with
    // a non-mounted slot, but pairwise duplicates between api +
    // admin_ui + website are rejected.
    let path_mounts: Vec<(&str, &str)> = [
        (
            "api",
            routing.api.host.as_deref(),
            routing.api.mount.as_str(),
        ),
        (
            "admin_ui",
            routing.admin_ui.host.as_deref(),
            routing.admin_ui.mount.as_str(),
        ),
        (
            "website",
            routing.website.host.as_deref(),
            routing.website.mount.as_str(),
        ),
    ]
    .into_iter()
    .filter_map(|(name, host, mount)| host.is_none().then_some((name, mount)))
    .collect();

    for i in 0..path_mounts.len() {
        for j in (i + 1)..path_mounts.len() {
            let (a, am) = path_mounts[i];
            let (b, bm) = path_mounts[j];
            if am == bm {
                return Err(AppError::Config(format!(
                    "routing.{a}.mount and routing.{b}.mount both = '{am}'; \
                     path-mode mounts must be unique",
                )));
            }
        }
    }
    Ok(())
}

/// Force host separation for an operator-deployed filesystem website.
///
/// The trust boundary is **deployed website content (untrusted) vs the
/// admin SPA + API (trusted)** — not admin-vs-API. The admin session
/// cookie is `Path=/` (the API lives at `/v1`, not under `/admin`, so
/// the SPA→API call needs it; an earlier `Path=/admin` design was
/// reverted), so in a shared origin operator-deployed website JS (or
/// stored XSS in marketing content) runs same-origin with the admin
/// SPA and can ride the cookie to call authenticated `/v1` endpoints.
/// The only posture that actually isolates that content is to put the
/// website on its **own host** (host-only cookies + `SameSite=Strict`
/// then keep the admin cookie off the website origin, and the P3.1
/// per-surface gate keeps `/v1` / `/admin` off the website host).
///
/// So when a *filesystem* website is configured (`website.root_dir`
/// set), require `routing.website.host` to be set and distinct from
/// the api and admin_ui hosts. The in-tree default landing page
/// (`root_dir` unset) is code we ship and trust, so it may stay
/// co-resident — this check does not fire for it.
fn validate_website_isolation(
    routing: &RoutingConfig,
    website_on_filesystem: bool,
) -> Result<(), AppError> {
    if !website_on_filesystem {
        return Ok(());
    }

    let website_host = routing.website.host.as_deref().map(str::to_ascii_lowercase);
    let Some(website_host) = website_host else {
        return Err(AppError::Config(
            "a filesystem website (website.root_dir) would share an origin with the \
             admin/API surface, letting deployed website content ride the admin session \
             cookie; set routing.website.host to a dedicated host, or remove \
             website.root_dir to serve the trusted built-in landing page"
                .into(),
        ));
    };

    for (name, surface) in [("api", &routing.api), ("admin_ui", &routing.admin_ui)] {
        if surface.host.as_deref().map(str::to_ascii_lowercase) == Some(website_host.clone()) {
            return Err(AppError::Config(format!(
                "routing.website.host = '{website_host}' collides with routing.{name}.host; \
                 a filesystem website must be on a host distinct from the admin/API surface \
                 so deployed content can't ride the admin session cookie"
            )));
        }
    }

    Ok(())
}

/// Refuse a CORS allowlist that includes `*` or empty / whitespace
/// entries. Spec §9.3: "wildcards refused". An empty
/// `allowed_origins` is valid — that's "no cross-origin requests
/// permitted" (same-origin path-mode default).
fn validate_cors(cors: &CorsConfig) -> Result<(), AppError> {
    for origin in &cors.allowed_origins {
        let trimmed = origin.trim();
        if trimmed.is_empty() {
            return Err(AppError::Config(
                "cors.allowed_origins contains an empty / whitespace entry".into(),
            ));
        }
        if trimmed == "*" || trimmed.contains('*') {
            return Err(AppError::Config(format!(
                "cors.allowed_origins entry '{trimmed}' uses a wildcard; \
                 spec §9.3 demands an exact-match allowlist"
            )));
        }
        if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
            return Err(AppError::Config(format!(
                "cors.allowed_origins entry '{trimmed}' must be a full origin \
                 (e.g., 'https://admin.example.com')"
            )));
        }
    }
    Ok(())
}

fn default_store_config() -> StoreConfig {
    StoreConfig {
        data_dir: PathBuf::from("data/vtc"),
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            trust_xff_cidrs: Vec::new(),
            trust_xff: (),
        }
    }
}

impl AppConfig {
    pub fn load(config_path: Option<PathBuf>) -> Result<Self, AppError> {
        Self::load_with_unknown_keys(config_path).map(|(config, _)| config)
    }

    /// [`Self::load`], also returning the dotted path of every key in the file
    /// that no field claims — a typo, a removed/renamed setting, or a key
    /// filed under the wrong `[section]` (a key appended below a table header
    /// belongs to that table). Reported, never rejected: a config that boots
    /// today must keep booting. Pass the list to [`Self::warn_unknown_keys`]
    /// once tracing is up — this runs before it. Keyring VTI-06.
    pub fn load_with_unknown_keys(
        config_path: Option<PathBuf>,
    ) -> Result<(Self, Vec<String>), AppError> {
        let path = config_path
            .or_else(|| std::env::var("VTC_CONFIG_PATH").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("config.toml"));

        if !path.exists() {
            return Err(AppError::Config(format!(
                "configuration file not found: {}",
                path.display()
            )));
        }

        let contents = std::fs::read_to_string(&path).map_err(AppError::Io)?;
        // Through `serde_ignored`, so a key the schema does not recognise is
        // recorded instead of silently dropped (Keyring VTI-06).
        let parse_err = |e: toml::de::Error| {
            AppError::Config(format!("failed to parse {}: {e}", path.display()))
        };
        let de = toml::Deserializer::parse(&contents).map_err(parse_err)?;
        let mut unknown_keys: Vec<String> = Vec::new();
        let mut config: AppConfig =
            serde_ignored::deserialize(de, |key_path| unknown_keys.push(key_path.to_string()))
                .map_err(parse_err)?;

        config.config_path = path.clone();

        // The retired `[trust_tasks] require_declared_proof`. `= false` never
        // reaches here — the deserializer refuses it, because that intent can no
        // longer be honoured. `= true` is now the only behaviour, so the
        // operator's intent is intact and the only thing left to do is delete
        // the line; say so and start.
        //
        // `eprintln!` rather than `warn!` deliberately: this runs before
        // `init_tracing`, so a `warn!` here would have no subscriber and the
        // operator would never learn their config has a dead key in it.
        if config.trust_tasks.require_declared_proof == Some(true) {
            eprintln!(
                "warning: {}: `[trust_tasks] require_declared_proof = true` has been retired. \
                 It is now the only behaviour — a document carrying no `proof` for a task whose \
                 specification declares one REQUIRED is always refused (VTI-OPS-020/021/093) — \
                 so this deployment's behaviour is unchanged. Delete the key.",
                path.display()
            );
        }

        // Apply env var overrides
        if let Ok(vtc_did) = std::env::var("VTC_DID") {
            config.vtc_did = Some(vtc_did);
        }
        if let Ok(vta_did) = std::env::var("VTC_VTA_DID") {
            config.vta_did = Some(vta_did);
        }
        if let Ok(host) = std::env::var("VTC_SERVER_HOST") {
            config.server.host = host;
        }
        if let Ok(port) = std::env::var("VTC_SERVER_PORT") {
            config.server.port = port
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTC_SERVER_PORT: {e}")))?;
        }
        if let Ok(level) = std::env::var("VTC_LOG_LEVEL") {
            config.log.level = level;
        }
        if let Ok(format) = std::env::var("VTC_LOG_FORMAT") {
            config.log.format = match format.to_lowercase().as_str() {
                "json" => LogFormat::Json,
                "text" => LogFormat::Text,
                other => {
                    return Err(AppError::Config(format!(
                        "invalid VTC_LOG_FORMAT '{other}', expected 'text' or 'json'"
                    )));
                }
            };
        }
        if let Ok(public_url) = std::env::var("VTC_PUBLIC_URL") {
            config.public_url = Some(public_url);
        }
        if let Ok(data_dir) = std::env::var("VTC_STORE_DATA_DIR") {
            config.store.data_dir = PathBuf::from(data_dir);
        }
        // Fjall memory settings (STORAGE_FJALL_BLOCK_CACHE / _WRITE_BUFFER /
        // _MAX_JOURNAL) — shared, unprefixed names; see
        // `vti_common::config::apply_fjall_env_overrides`.
        vti_common::config::apply_fjall_env_overrides(&mut config.fjall)
            .map_err(AppError::Config)?;

        // Messaging env var overrides
        match (
            std::env::var("VTC_MESSAGING_MEDIATOR_URL"),
            std::env::var("VTC_MESSAGING_MEDIATOR_DID"),
        ) {
            (Ok(url), Ok(did)) => {
                config.messaging = Some(MessagingConfig {
                    mediator_url: url,
                    mediator_did: did,
                    mediator_host: None,
                    setup_acl: false,
                    drain_inbox_on_start: false,
                });
            }
            (Ok(url), Err(_)) => {
                let messaging = config.messaging.get_or_insert(MessagingConfig {
                    mediator_url: String::new(),
                    mediator_did: String::new(),
                    mediator_host: None,
                    setup_acl: false,
                    drain_inbox_on_start: false,
                });
                messaging.mediator_url = url;
            }
            (Err(_), Ok(did)) => {
                let messaging = config.messaging.get_or_insert(MessagingConfig {
                    mediator_url: String::new(),
                    mediator_did: String::new(),
                    mediator_host: None,
                    setup_acl: false,
                    drain_inbox_on_start: false,
                });
                messaging.mediator_did = did;
            }
            (Err(_), Err(_)) => {}
        }

        // Secrets env var overrides
        if let Ok(secret) = std::env::var("VTC_SECRETS_SECRET") {
            config.secrets.secret = Some(secret);
        }
        if let Ok(name) = std::env::var("VTC_SECRETS_AWS_SECRET_NAME") {
            config.secrets.aws_secret_name = Some(name);
        }
        if let Ok(region) = std::env::var("VTC_SECRETS_AWS_REGION") {
            config.secrets.aws_region = Some(region);
        }
        if let Ok(project) = std::env::var("VTC_SECRETS_GCP_PROJECT") {
            config.secrets.gcp_project = Some(project);
        }
        if let Ok(name) = std::env::var("VTC_SECRETS_GCP_SECRET_NAME") {
            config.secrets.gcp_secret_name = Some(name);
        }
        if let Ok(url) = std::env::var("VTC_SECRETS_AZURE_VAULT_URL") {
            config.secrets.azure_vault_url = Some(url);
        }
        if let Ok(name) = std::env::var("VTC_SECRETS_AZURE_SECRET_NAME") {
            config.secrets.azure_secret_name = Some(name);
        }
        if let Ok(service) = std::env::var("VTC_SECRETS_KEYRING_SERVICE") {
            config.secrets.keyring_service = service;
        }
        // Kubernetes Secret backend. The namespace is commonly injected from
        // the pod's own metadata via the Downward API, so an env override is
        // the natural way to set it.
        if let Ok(name) = std::env::var("VTC_SECRETS_K8S_SECRET_NAME") {
            config.secrets.k8s_secret_name = Some(name);
        }
        if let Ok(ns) = std::env::var("VTC_SECRETS_K8S_NAMESPACE") {
            config.secrets.k8s_namespace = Some(ns);
        }
        if let Ok(key) = std::env::var("VTC_SECRETS_K8S_SECRET_KEY") {
            config.secrets.k8s_secret_key = key;
        }

        // Auth env var overrides
        if let Ok(expiry) = std::env::var("VTC_AUTH_ACCESS_EXPIRY") {
            config.auth.access_token_expiry = expiry
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTC_AUTH_ACCESS_EXPIRY: {e}")))?;
        }
        if let Ok(expiry) = std::env::var("VTC_AUTH_REFRESH_EXPIRY") {
            config.auth.refresh_token_expiry = expiry
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTC_AUTH_REFRESH_EXPIRY: {e}")))?;
        }
        if let Ok(ttl) = std::env::var("VTC_AUTH_CHALLENGE_TTL") {
            config.auth.challenge_ttl = ttl
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTC_AUTH_CHALLENGE_TTL: {e}")))?;
        }
        if let Ok(interval) = std::env::var("VTC_AUTH_SESSION_CLEANUP_INTERVAL") {
            config.auth.session_cleanup_interval = interval.parse().map_err(|e| {
                AppError::Config(format!("invalid VTC_AUTH_SESSION_CLEANUP_INTERVAL: {e}"))
            })?;
        }
        if let Ok(key) = std::env::var("VTC_AUTH_JWT_SIGNING_KEY") {
            config.auth.jwt_signing_key = Some(key);
        }
        // Empty clears a `[geoip] database` set in the file.
        if let Ok(path) = std::env::var("VTC_GEOIP_DATABASE") {
            config.geoip.database = (!path.trim().is_empty()).then(|| PathBuf::from(path));
        }

        config.validate_routing_and_cors()?;
        let did_cache_errors = config.did_cache.validation_errors();
        if !did_cache_errors.is_empty() {
            return Err(AppError::Config(did_cache_errors.join("; ")));
        }
        Ok((config, unknown_keys))
    }

    /// Validate the routing + CORS sections per spec §9.2 / §9.3.
    /// Called at the tail of [`Self::load`]; surfaced as a
    /// public helper so tests can drive it directly without
    /// touching the filesystem.
    pub fn validate_routing_and_cors(&self) -> Result<(), AppError> {
        validate_routing(&self.routing)?;
        validate_website_isolation(&self.routing, self.website.root_dir.is_some())?;
        validate_cors(&self.cors)?;
        self.admin_ui.validate()?;
        self.witnesses.validate(self.vtc_did.as_deref())?;
        Ok(())
    }

    /// Warn once per key from [`Self::load_with_unknown_keys`], naming its
    /// full dotted path. Call after the tracing subscriber is installed —
    /// loading runs before it, so a warning logged there would be dropped.
    pub fn warn_unknown_keys(&self, unknown_keys: &[String]) {
        for key in unknown_keys {
            tracing::warn!("{}", unknown_key_message(&self.config_path, key));
        }
    }

    pub fn save(&self) -> Result<(), AppError> {
        self.validate_routing_and_cors()?;
        let contents = toml::to_string_pretty(self)
            .map_err(|e| AppError::Config(format!("failed to serialize config: {e}")))?;
        std::fs::write(&self.config_path, contents).map_err(AppError::Io)?;
        Ok(())
    }
}

/// The operator-facing warning for one unrecognised config key.
fn unknown_key_message(config_path: &std::path::Path, key: &str) -> String {
    let path = config_path.display();
    match key.rsplit_once('.') {
        Some((table, leaf)) => format!(
            "unknown configuration key `{key}` in {path} — ignored. There is no `{leaf}` \
             setting in [{table}]. Check for a typo or a removed/renamed setting; if \
             `{leaf}` belongs to another section, note that a key placed after a [table] \
             header belongs to that table, so a key appended at the end of the file lands \
             in its last section."
        ),
        None => format!(
            "unknown configuration key `{key}` in {path} — ignored. Check for a typo or a \
             removed/renamed setting."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Room files are off with no `[rooms.files]` section — every configuration
    /// written before they existed — and on once the section is written. The
    /// documented section parses into the limits it says.
    #[test]
    fn room_files_are_off_without_the_section_and_on_with_it() {
        let empty: AppConfig = toml::from_str("").expect("empty config");
        assert!(empty.rooms.files.is_none());
        assert!(!empty.rooms.files_enabled());
        // And a saved config does not grow a section the operator never wrote.
        assert!(!toml::to_string(&empty).unwrap().contains("[rooms.files]"));

        let paths: AppConfig = toml::from_str(
            "[rooms.files]\nlocal_storage_bases = [\"/srv/vtc/room-storage\"]\n\
             blob_dir = \"/srv/vtc/room-blobs\"\n",
        )
        .expect("the section the console suggests");
        assert!(
            paths.rooms.files_enabled(),
            "writing the section turns files on"
        );

        let off: AppConfig = toml::from_str("[rooms.files]\nenabled = false\n").unwrap();
        assert!(!off.rooms.files_enabled());

        let cfg: AppConfig = toml::from_str(
            "[rooms.files]\nmax_file_bytes = 1048576\norphan_grace_hours = 24\n\
             [rooms.files.room]\nmax_files = 50\n[rooms.files.member]\nmax_bytes = 2048\n",
        )
        .expect("a [rooms.files] section");
        let limits = cfg.rooms.files.as_ref().unwrap().limits();
        assert!(limits.files_enabled);
        assert_eq!(limits.max_file_bytes, 1_048_576);
        assert_eq!(limits.orphan_grace_secs, 24 * 3600);
        assert_eq!(limits.room.max_files, Some(50));
        assert_eq!(limits.member.max_bytes, Some(2048));
        // Unset measures keep the shipped defaults.
        assert_eq!(
            limits.room.max_bytes,
            vti_rooms::blobs::HostLimits::default().room.max_bytes
        );

        assert!(
            toml::from_str::<AppConfig>("[rooms.files]\nenable = true\n").is_err(),
            "a misspelt key is refused, not ignored"
        );
    }

    #[test]
    fn geoip_database_is_optional() {
        let empty: AppConfig = toml::from_str("").expect("empty config");
        assert_eq!(empty.geoip.database, None);
        // Unset is not written back, so a saved config stays as it was.
        assert!(!toml::to_string(&empty).unwrap().contains("database"));

        let set: AppConfig =
            toml::from_str("[geoip]\ndatabase = \"/var/lib/vtc/dbip-city-lite.mmdb\"")
                .expect("geoip config");
        assert_eq!(
            set.geoip.database.as_deref(),
            Some(std::path::Path::new("/var/lib/vtc/dbip-city-lite.mmdb"))
        );
    }

    #[test]
    fn admin_ui_dir_goes_with_directory_mode_only() {
        let parse = |s: &str| toml::from_str::<AdminUiConfig>(s).expect("parse admin_ui");

        let directory = parse("mode = \"directory\"\ndir = \"/srv/console\"");
        directory.validate().unwrap();
        assert_eq!(
            directory.serve_dir(),
            Some(std::path::Path::new("/srv/console"))
        );

        parse("").validate().unwrap();
        assert_eq!(parse("").serve_dir(), None);

        // Directory mode without a directory, a directory the mode would
        // ignore, and an unknown mode are each refused.
        for bad in [
            "mode = \"directory\"",
            "dir = \"/srv/console\"",
            "mode = \"custom\"",
        ] {
            assert!(parse(bad).validate().is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn retired_external_mode_is_refused_naming_directory_mode() {
        let err = parse_admin_ui("mode = \"external\"")
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("mode = \"directory\""), "{err}");

        let err = toml::from_str::<AdminUiConfig>("external_origin = \"https://a.example\"")
            .unwrap_err()
            .to_string();
        assert!(err.contains("vtc admin-ui export"), "{err}");
    }

    fn parse_admin_ui(s: &str) -> AdminUiConfig {
        toml::from_str(s).expect("parse admin_ui")
    }

    #[test]
    fn secret_backend_selector_parses_each_variant() {
        // Every accepted spelling maps to its variant (kebab-case wire form).
        for (wire, expected) in [
            ("keyring", SecretBackend::Keyring),
            ("vault", SecretBackend::Vault),
            ("k8s", SecretBackend::K8s),
            ("aws", SecretBackend::Aws),
            ("gcp", SecretBackend::Gcp),
            ("azure", SecretBackend::Azure),
            ("config", SecretBackend::Config),
            ("plaintext", SecretBackend::Plaintext),
            ("encrypted-file", SecretBackend::EncryptedFile),
        ] {
            let cfg: SecretsConfig =
                toml::from_str(&format!("backend = \"{wire}\"")).expect("parse backend");
            assert_eq!(cfg.backend, Some(expected), "wire form {wire:?}");
        }
    }

    #[test]
    fn secret_backend_omitted_is_none() {
        // Back-compat: an existing `[secrets]` with no `backend` key parses
        // to None (implicit resolution preserved).
        let cfg: SecretsConfig = toml::from_str("keyring_service = \"vtc\"").expect("parse");
        assert_eq!(cfg.backend, None);
    }

    #[test]
    fn retired_trust_xff_key_is_refused() {
        let err = toml::from_str::<ServerConfig>("trust_xff = true")
            .expect_err("retired trust_xff key must be rejected");
        assert!(format!("{err}").contains("trust_xff_cidrs"), "{err}");
    }

    #[test]
    fn trust_xff_cidrs_still_parses() {
        let cfg: ServerConfig =
            toml::from_str("trust_xff_cidrs = [\"127.0.0.1/32\"]").expect("parse");
        assert_eq!(cfg.trust_xff_cidrs.len(), 1);
    }

    #[test]
    fn secret_backend_unknown_is_rejected() {
        assert!(
            toml::from_str::<SecretsConfig>("backend = \"hashicorp\"").is_err(),
            "unknown backend spelling must be a parse error"
        );
    }

    #[test]
    fn secrets_config_debug_redacts_secret() {
        let cfg = SecretsConfig {
            secret: Some("deadbeefdeadbeef".into()),
            keyring_service: "vtc".into(),
            // Vault bearer creds are also secret-bearing — must not leak.
            vault_token: Some("hvs.SUPERSECRETTOKEN".into()),
            vault_approle_secret_id: Some("APPROLE_SECRET_ID_XYZ".into()),
            ..Default::default()
        };
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("<redacted>"), "got {dbg}");
        assert!(!dbg.contains("deadbeef"), "secret leaked: {dbg}");
        assert!(
            !dbg.contains("SUPERSECRETTOKEN"),
            "vault_token leaked: {dbg}"
        );
        assert!(
            !dbg.contains("APPROLE_SECRET_ID_XYZ"),
            "vault_approle_secret_id leaked: {dbg}"
        );
        // Non-secret backend names still print.
        assert!(dbg.contains("vtc"));
    }

    // ── Parse contract ──────────────────────────────────────────────
    //
    // These tests guard the on-disk config shape. A rename or a
    // missing #[serde(default)] here breaks every operator's
    // config.toml on upgrade.

    #[test]
    fn empty_toml_parses_with_all_defaults() {
        let config: AppConfig = toml::from_str("").expect("empty TOML must parse");
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8200, "VTC default port is 8200");
        assert!(config.vtc_did.is_none());
        assert!(config.vta_did.is_none());
        assert!(config.messaging.is_none());
    }

    #[test]
    fn minimal_toml_parses() {
        let toml_src = r#"
            vtc_did = "did:key:zVTC"
            vta_did = "did:key:zVTA"
        "#;
        let config: AppConfig = toml::from_str(toml_src).expect("minimal TOML must parse");
        assert_eq!(config.vtc_did.as_deref(), Some("did:key:zVTC"));
        assert_eq!(config.vta_did.as_deref(), Some("did:key:zVTA"));
    }

    #[test]
    fn community_name_alias_is_accepted() {
        // Backward-compat: older configs used `community_name` before
        // the rename to `vtc_name`. The serde alias preserves their
        // configs. Breaking this breaks existing operators.
        let toml_src = r#"
            community_name = "Alpha Community"
            community_description = "First VTC"
        "#;
        let config: AppConfig = toml::from_str(toml_src).expect("alias must parse");
        assert_eq!(config.vtc_name.as_deref(), Some("Alpha Community"));
        assert_eq!(config.vtc_description.as_deref(), Some("First VTC"));
    }

    #[test]
    fn vtc_name_canonical_field_is_accepted() {
        let toml_src = r#"
            vtc_name = "Alpha"
            vtc_description = "Canonical"
        "#;
        let config: AppConfig = toml::from_str(toml_src).expect("canonical name parses");
        assert_eq!(config.vtc_name.as_deref(), Some("Alpha"));
    }

    #[test]
    fn invalid_toml_produces_config_error() {
        let err = toml::from_str::<AppConfig>("server.port = \"not-a-number\"")
            .expect_err("invalid port type must fail parse");
        let msg = format!("{err}");
        assert!(msg.contains("port"), "error must name the field: {msg}");
    }

    #[test]
    fn server_port_bounds() {
        // u16 range enforced by serde — 70000 must fail.
        let toml_src = r#"
            [server]
            port = 70000
        "#;
        let err =
            toml::from_str::<AppConfig>(toml_src).expect_err("out-of-range port must not parse");
        assert!(format!("{err}").contains("port"), "got {err}");
    }

    #[test]
    fn secrets_config_keyring_service_defaults_to_vtc() {
        // Keyring service name is per-service — VTC uses "vtc" so it
        // doesn't collide with a VTA running on the same host.
        let empty: AppConfig = toml::from_str("").unwrap();
        assert_eq!(empty.secrets.keyring_service, "vtc");
    }

    #[test]
    fn secrets_unknown_key_is_a_named_parse_error() {
        // P0.8: a typo'd backend selector must be a loud parse error, not a
        // silently-dropped key that lets the factory fall through to the
        // default backend with an empty store.
        let toml_src = r#"
            [secrets]
            aws_secretname = "prod/vtc"
        "#;
        let err = toml::from_str::<AppConfig>(toml_src)
            .expect_err("unknown [secrets] key must not parse");
        let msg = format!("{err}");
        assert!(
            msg.contains("aws_secretname"),
            "error must name the offending key: {msg}"
        );
    }

    #[test]
    fn secrets_known_keys_still_parse() {
        // deny_unknown_fields must not reject the legitimate fields.
        let toml_src = r#"
            [secrets]
            keyring_service = "vtc-test"
            aws_secret_name = "prod/vtc"
            aws_region = "us-east-1"
        "#;
        let config: AppConfig = toml::from_str(toml_src).expect("known keys parse");
        assert_eq!(config.secrets.keyring_service, "vtc-test");
        assert_eq!(config.secrets.aws_secret_name.as_deref(), Some("prod/vtc"));
    }

    #[test]
    fn config_round_trip_preserves_fields() {
        // Serialize then parse — catches field additions that break
        // serialization symmetry (e.g. a serialize-only field that
        // can't parse back).
        let original: AppConfig = toml::from_str(
            r#"
            vtc_did = "did:key:zVTC"
            vta_did = "did:key:zVTA"
            vtc_name = "Round Trip"
            public_url = "https://vtc.example.com"
        "#,
        )
        .unwrap();

        let serialized = toml::to_string_pretty(&original).expect("serialize ok");
        let parsed: AppConfig = toml::from_str(&serialized).expect("re-parse ok");
        assert_eq!(parsed.vtc_did, original.vtc_did);
        assert_eq!(parsed.vta_did, original.vta_did);
        assert_eq!(parsed.vtc_name, original.vtc_name);
        assert_eq!(parsed.public_url, original.public_url);
    }

    // -- the retired `[trust_tasks] require_declared_proof` (#1641 → #1672) --

    /// The intent that can no longer be honoured. Starting on this config would
    /// enforce the opposite of what it says, so it does not start — and the
    /// error names what replaced the switch, because "delete this key" is not
    /// actionable for the operator whose clients are about to be refused.
    #[test]
    fn a_config_asking_to_disable_the_declared_proof_check_fails_to_load() {
        let err = toml::from_str::<AppConfig>("[trust_tasks]\nrequire_declared_proof = false\n")
            .expect_err("the retired leniency must not be honoured");

        let rendered = err.to_string();
        for expected in ["retired", "openvtc#371", "VTI-OPS-020/021/093"] {
            assert!(
                rendered.contains(expected),
                "the refusal must name {expected}, got: {rendered}"
            );
        }
    }

    /// The other half, and the reason this is a warning rather than a second
    /// refusal: `= true` asked for what the service now does unconditionally,
    /// so the operator's intent survives and only the line is stale.
    /// `AppConfig::load` says so on stderr; parsing must not fail.
    #[test]
    fn a_config_that_already_enabled_it_still_loads() {
        let config: AppConfig = toml::from_str("[trust_tasks]\nrequire_declared_proof = true\n")
            .expect("`= true` was already the behaviour; it must not become a startup failure");
        assert_eq!(config.trust_tasks.require_declared_proof, Some(true));
    }

    /// Absence is the state to arrive at, and it is silent.
    #[test]
    fn a_config_without_the_retired_key_says_nothing() {
        let config: AppConfig = toml::from_str("").expect("empty TOML must parse");
        assert_eq!(config.trust_tasks.require_declared_proof, None);
    }

    /// The retired key is `skip_serializing`, so a config this service writes
    /// back never re-emits it — an operator who deletes it does not get it
    /// handed back by the next round trip.
    #[test]
    fn the_retired_key_is_never_written_back() {
        let config: AppConfig =
            toml::from_str("[trust_tasks]\nrequire_declared_proof = true\n").expect("parses");
        let serialized = toml::to_string_pretty(&config).expect("serialize ok");
        assert!(
            !serialized.contains("require_declared_proof"),
            "a retired key must not be re-emitted: {serialized}"
        );
    }

    /// Write `contents` to a `config.toml` in a fresh tempdir and run it
    /// through the real loader — the only path that collects unknown keys.
    fn load(contents: &str) -> ((AppConfig, Vec<String>), tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, contents).expect("write config");
        let config = AppConfig::load_with_unknown_keys(Some(path)).expect("load config");
        (config, dir)
    }

    /// The DID-document cache is bounded by default, and a TTL past the
    /// bound is refused at load rather than honoured: it is how long a key
    /// revoked from a member's document keeps verifying here.
    #[test]
    fn the_did_cache_ttl_is_bounded() {
        let ((config, _), _dir) = load("");
        assert_eq!(
            config.did_cache.ttl_secs,
            vti_common::config::DID_CACHE_TTL_DEFAULT_SECS
        );

        let ((config, _), _dir) = load("[did_cache]\nttl_secs = 30\n");
        assert_eq!(config.did_cache.ttl_secs, 30);

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[did_cache]\nttl_secs = 3600\n").expect("write config");
        let err = AppConfig::load_with_unknown_keys(Some(path)).expect_err("3600 s is refused");
        assert!(format!("{err}").contains("did_cache.ttl_secs"), "{err}");
    }

    /// Keyring VTI-06: a key appended below the last table header is filed
    /// under that table, took no effect, and used to be dropped without a
    /// word. It is now recorded with the dotted path it actually landed at.
    #[test]
    fn a_key_appended_after_the_last_table_is_reported_with_its_dotted_path() {
        let ((config, unknown_keys), _dir) = load(
            "vtc_name = \"acme\"\n\
             [cors]\nallowed_origins = [\"https://admin.example.com\"]\n\
             [join_requests]\n\
             allowed_origins = [\"https://app.example.com\"]\n",
        );
        assert_eq!(
            unknown_keys,
            vec!["join_requests.allowed_origins".to_string()]
        );
        let msg = unknown_key_message(&config.config_path, &unknown_keys[0]);
        assert!(msg.contains("`join_requests.allowed_origins`"), "{msg}");
        assert!(
            msg.contains("a key placed after a [table] header belongs to that table"),
            "{msg}"
        );
    }

    /// A top-level typo is reported as-is, with no table to blame.
    #[test]
    fn a_top_level_typo_is_reported_plainly() {
        let ((config, unknown_keys), _dir) = load("vtc_naem = \"acme\"\n");
        assert_eq!(unknown_keys, vec!["vtc_naem".to_string()]);
        assert!(!unknown_key_message(&config.config_path, "vtc_naem").contains("[table]"));
    }

    /// A valid config — including a serde alias — reports nothing; a warning
    /// that always fires is one operators learn to ignore.
    #[test]
    fn a_valid_config_reports_no_unknown_keys() {
        let ((config, unknown_keys), _dir) = load(
            "community_name = \"acme\"\n\
             [server]\nport = 9000\n\
             [cors]\nallowed_origins = [\"https://admin.example.com\"]\n",
        );
        assert!(unknown_keys.is_empty(), "{:?}", unknown_keys);
        assert_eq!(config.vtc_name.as_deref(), Some("acme"));
    }

    /// What [`AppConfig::save`] writes, [`AppConfig::load`] recognises in full
    /// — so a config the service wrote itself never warns on the next start.
    #[test]
    fn a_saved_config_reloads_with_no_unknown_keys() {
        let config: AppConfig = toml::from_str("").expect("empty TOML parses");
        let written = toml::to_string_pretty(&config).expect("serialize ok");
        let ((_, unknown_keys), _dir) = load(&written);
        assert!(unknown_keys.is_empty(), "{:?}", unknown_keys);
    }
}

#[cfg(test)]
mod room_rate_limit_tests {
    use super::*;

    /// No `[rooms.rate_limits]` — every configuration written before it existed —
    /// is the shipped defaults, and is not written back out.
    #[test]
    fn an_absent_section_is_the_defaults() {
        let rooms: RoomsConfig = toml::from_str("").unwrap();
        assert_eq!(rooms.rate_limits, RoomRateLimitsConfig::default());
        assert_eq!(rooms.rate_limits.address(), ROOM_ADDRESS_DEFAULT);
        assert_eq!(rooms.rate_limits.presenter(), ROOM_PRESENTER_DEFAULT);
        assert_eq!(rooms.rate_limits.transfer(), ROOM_TRANSFER_DEFAULT);
        assert!(!toml::to_string(&rooms).unwrap().contains("rate_limits"));
    }

    #[test]
    fn a_partial_section_keeps_the_rest_and_zero_is_one() {
        let rooms: RoomsConfig =
            toml::from_str("[rate_limits]\npresenter_burst = 30\ntransfer_interval_ms = 0\n")
                .unwrap();
        let l = &rooms.rate_limits;
        assert_eq!(l.presenter().burst, 30);
        assert_eq!(l.presenter().interval, ROOM_PRESENTER_DEFAULT.interval);
        assert_eq!(l.transfer().interval, std::time::Duration::from_millis(1));
        assert_eq!(l.address(), ROOM_ADDRESS_DEFAULT);
        assert!(toml::from_str::<RoomsConfig>("[rate_limits]\nburst = 1\n").is_err());
    }
}
