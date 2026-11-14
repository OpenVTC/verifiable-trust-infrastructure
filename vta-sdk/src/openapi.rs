//! OpenAPI schemas for published Trust Task types a service serves over REST
//! (feature `openapi`).
//!
//! A generated type is foreign to every crate that serves it, so `ToSchema`
//! cannot be derived on it — and a local struct describing it would be exactly
//! the hand-written copy the generated types exist to remove. The schema comes
//! from the specification instead. Each type below wraps one generated type
//! transparently — the JSON on the wire is the generated type's own — and
//! documents it by rendering the JSON Schema that type embeds as OpenAPI
//! components.
//!
//! A handler takes and returns `Json<Wrapper>`, and its `#[utoipa::path]` names
//! the wrapper as the body, so the document describes what the specification
//! publishes rather than what someone transcribed from it. A field of a local
//! admin type can point at one with `#[schema(value_type = …)]`.
//!
//! ## Component names
//!
//! The task's slug and version, then the definition:
//! `VtcVettingVettersListV0_1Payload`, `VtcVettingVettersListV0_1ListedVetter`.
//! Two specifications that each define a `VetterEvent` cannot collide, and a
//! reader can tell which specification a component came from.
//!
//! ## What the rendering carries
//!
//! Structure and bounds: types, members, `required`, `additionalProperties`,
//! `oneOf`/`anyOf`/`allOf`, `enum`/`const`, `format`, patterns, lengths, item
//! counts and numeric ranges. JSON Schema keywords utoipa's model has no field
//! for — `dependentSchemas`, `dependentRequired`, `not`, `propertyNames` — are
//! not rendered; a service enforces them at runtime through
//! [`crate::protocols::vetting::CheckShape`].
//!
//! ## Exposing another type
//!
//! Add a line to the [`spec_types!`] table: the wrapper's name, the generated
//! type, and — for a type that is a `$defs` entry of another type's schema rather
//! than a payload or response itself — the carrier and the definition's name.

use std::borrow::Cow;
use std::ops::{Deref, DerefMut};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::openapi::schema::{
    AdditionalProperties, AllOfBuilder, AnyOfBuilder, ArrayBuilder, ObjectBuilder, OneOfBuilder,
    Schema, SchemaFormat, SchemaType, Type,
};
use utoipa::openapi::{Ref, RefOr};

use crate::protocols::vetting::vetters;
use vti_specs::credential_exchange;
use vti_specs::did_management::did::register;
use vti_specs::git_ns::view as git_ns_view;
use vti_specs::vtc::badges;
use vti_specs::vtc::boards;
use vti_specs::vtc::config;
use vti_specs::vtc::directory;
use vti_specs::vtc::endorsement_types;
use vti_specs::vtc::groups;
use vti_specs::vtc::invitations::deliver as invitation_deliver;
use vti_specs::vtc::join_requests::manifest;
use vti_specs::vtc::members::credentials as member_credentials;
use vti_specs::vtc::networks;
use vti_specs::vtc::registry::{records, sync_jobs};
use vti_specs::vtc::rooms::{
    community as rooms_community, get as rooms_get, limits::set as rooms_limits_set,
    storage::assign as rooms_storage_assign, storage::migrate as rooms_storage_migrate,
    usage as rooms_usage,
};
use vti_specs::vtc::schemas::accepts;
use vti_specs::vtc::storage::configs as storage_configs;
use vti_specs::vtc::storage::credentials::set as storage_credentials_set;

/// Transparent wrappers documenting generated types, one per line.
macro_rules! spec_types {
    ($(
        $(#[$doc:meta])*
        $name:ident($ty:ty) $(in $carrier:ty as $definition:literal)?;
    )+) => {
        $(
            $(#[$doc])*
            #[derive(Debug, Clone, Serialize, Deserialize)]
            #[serde(transparent)]
            pub struct $name(pub $ty);

            impl $name {
                /// The wrapped value.
                pub fn into_inner(self) -> $ty {
                    self.0
                }
            }

            impl From<$ty> for $name {
                fn from(value: $ty) -> Self {
                    Self(value)
                }
            }

            impl Deref for $name {
                type Target = $ty;
                fn deref(&self) -> &$ty {
                    &self.0
                }
            }

            impl DerefMut for $name {
                fn deref_mut(&mut self) -> &mut $ty {
                    &mut self.0
                }
            }

            impl utoipa::PartialSchema for $name {
                fn schema() -> RefOr<Schema> {
                    spec_types!(@rendered $ty $(, $carrier, $definition)?).schema
                }
            }

            impl utoipa::ToSchema for $name {
                fn name() -> Cow<'static, str> {
                    Cow::Owned(spec_types!(@rendered $ty $(, $carrier, $definition)?).name)
                }

                fn schemas(schemas: &mut Vec<(String, RefOr<Schema>)>) {
                    schemas.extend(
                        spec_types!(@rendered $ty $(, $carrier, $definition)?).definitions,
                    );
                }
            }
        )+
    };
    (@rendered $ty:ty) => {
        rendered::<$ty>(None)
    };
    (@rendered $ty:ty, $carrier:ty, $definition:literal) => {
        rendered::<$carrier>(Some($definition))
    };
}

spec_types! {
    /// `vtc/invitations/deliver/0.1` payload.
    InvitationDeliver01Payload(invitation_deliver::v0_1::Payload);
    /// `vtc/invitations/deliver/0.1#response`.
    InvitationDeliver01Response(invitation_deliver::v0_1::Response);
    /// `credential-exchange/request/0.1` payload — also the body of a VTC's
    /// `POST /v1/credential-exchange/request`, which redeems an offer over HTTPS.
    CredentialRequest01Payload(credential_exchange::request::v0_1::Payload);
    /// `credential-exchange/issue/0.1` payload — the answer to a request, returned
    /// as the HTTPS response where a messaging binding would send it on-thread.
    CredentialIssue01Payload(credential_exchange::issue::v0_1::Payload);
    /// `did-management/did/register/0.1` payload — also the body of a VTC's
    /// `POST /v1/admin/did/register`, which installs its own self-hosted log.
    DidRegister01Payload(register::v0_1::Payload);
    /// `did-management/did/register/0.1#response`.
    DidRegister01Response(register::v0_1::Response);
    /// `vtc/vetting/vetters/grant/0.1` payload.
    VetterGrant01Payload(vetters::grant::v0_1::Payload);
    /// `vtc/vetting/vetters/grant/0.1#response`.
    VetterGrant01Response(vetters::grant::v0_1::Response);
    /// `vtc/vetting/vetters/list/0.1` payload.
    VetterList01Payload(vetters::list::v0_1::Payload);
    /// `vtc/vetting/vetters/list/0.1#response`.
    VetterList01Response(vetters::list::v0_1::Response);
    /// `vtc/vetting/vetters/show/0.1` payload.
    VetterShow01Payload(vetters::show::v0_1::Payload);
    /// `vtc/vetting/vetters/show/0.1#response`.
    VetterShow01Response(vetters::show::v0_1::Response);
    /// `vtc/vetting/vetters/resend/0.2#response`.
    VetterResend02Response(vetters::resend::v0_2::Response);
    /// `vtc/endorsement-types/register/0.1` payload.
    EndorsementTypeRegister01Payload(endorsement_types::register::v0_1::Payload);
    /// `vtc/endorsement-types/delete/0.1#response`.
    EndorsementTypeDelete01Response(endorsement_types::delete::v0_1::Response);
    /// `vtc/vetting/vetters/profile/0.1`'s `VettingMethod`.
    VetterProfile01VettingMethod(vetters::profile::v0_1::VettingMethod)
        in vetters::profile::v0_1::Payload as "VettingMethod";
    /// `vtc/join-requests/manifest/0.4#response` — the criteria, and the
    /// directory's disclosure statement.
    JoinManifest04Response(manifest::v0_4::Response);
    /// `vtc/schemas/accepts/register/0.2` payload — one join criterion as an
    /// administrator states it.
    AcceptsRegister02Payload(accepts::register::v0_2::Payload);
    /// `vtc/schemas/accepts/list/0.2#response` — the criteria as stored.
    AcceptsList02Response(accepts::list::v0_2::Response);
    /// `vtc/join-requests/manifest/0.4`'s `VettingRequirements`.
    JoinManifest04VettingRequirements(manifest::v0_4::VettingRequirements)
        in manifest::v0_4::Response as "VettingRequirements";
    /// `vtc/join-requests/manifest/0.4`'s `CommunityBranding` — also the body of a
    /// VTC's `GET`/`PUT /v1/community/branding`.
    JoinManifest04CommunityBranding(manifest::v0_4::CommunityBranding)
        in manifest::v0_4::Response as "CommunityBranding";
    /// One entry of `vtc/join-requests/manifest/0.4`'s `requestedAttributes` —
    /// also the item of a VTC's `GET`/`PUT /v1/community/requested-attributes`.
    /// Declared inline in the specification, so rendered from its pointer.
    JoinManifest04RequestedAttribute(manifest::v0_4::ResponseRequestedAttributesItem)
        in manifest::v0_4::Response
        as "RequestedAttribute@/$defs/Response/properties/requestedAttributes/items";
    /// `vtc/registry/sync-jobs/list/0.2` payload.
    RegistrySyncJobsList02Payload(sync_jobs::list::v0_2::Payload);
    /// `vtc/registry/sync-jobs/list/0.2#response`.
    RegistrySyncJobsList02Response(sync_jobs::list::v0_2::Response);
    /// `vtc/registry/sync-jobs/retry/0.2` payload: exactly one of `jobId`,
    /// `allFailed` or `allWaiting`; a pending job waiting out its backoff is
    /// eligible, a held one never.
    RegistrySyncJobsRetry02Payload(sync_jobs::retry::v0_2::Payload);
    /// `vtc/registry/sync-jobs/retry/0.2#response`.
    RegistrySyncJobsRetry02Response(sync_jobs::retry::v0_2::Response);
    /// `vtc/registry/sync-jobs/discard/0.1` payload.
    RegistrySyncJobsDiscard01Payload(sync_jobs::discard::v0_1::Payload);
    /// `vtc/registry/sync-jobs/discard/0.1#response`.
    RegistrySyncJobsDiscard01Response(sync_jobs::discard::v0_1::Response);
    /// `vtc/registry/records/list/0.2` payload.
    RegistryRecordsList02Payload(records::list::v0_2::Payload);
    /// `vtc/registry/records/list/0.2#response`.
    RegistryRecordsList02Response(records::list::v0_2::Response);
    /// `vtc/members/credentials/0.1#response` — the membership pair's bodies
    /// for one member, plus whether the acknowledgement is bound to the grant.
    MemberCredentials01Response(member_credentials::v0_1::Response);
    /// `vtc/rooms/get/0.3#response` — one hosted room's host record (instants as
    /// RFC 3339 strings), storage placement, limits and usage, with the room's
    /// migration as `vtc/rooms/storage/migrate/0.3` reports it.
    RoomsGet03Response(rooms_get::v0_3::Response);
    /// `vtc/rooms/usage/0.1` payload — grouping, filter, sort and page.
    RoomsUsage01Payload(rooms_usage::v0_1::Payload);
    /// `vtc/rooms/usage/0.1#response` — one page of usage rows.
    RoomsUsage01Response(rooms_usage::v0_1::Response);
    /// `vtc/rooms/limits/set/0.1` payload — an override, or the clearing of one.
    RoomsLimitsSet01Payload(rooms_limits_set::v0_1::Payload);
    /// `vtc/rooms/limits/set/0.1#response` — the limits after the change.
    RoomsLimitsSet01Response(rooms_limits_set::v0_1::Response);
    /// `vtc/rooms/storage/assign/0.2` payload — point a room at another config.
    RoomsStorageAssign02Payload(rooms_storage_assign::v0_2::Payload);
    /// `vtc/rooms/storage/assign/0.2#response`.
    RoomsStorageAssign02Response(rooms_storage_assign::v0_2::Response);
    /// `vtc/rooms/storage/migrate/0.3` payload — move a room's existing files onto its
    /// assigned config.
    RoomsStorageMigrate03Payload(rooms_storage_migrate::v0_3::Payload);
    /// `vtc/rooms/storage/migrate/0.3#response` — the migration, its progress, and
    /// why and until when it is paused or waiting.
    RoomsStorageMigrate03Response(rooms_storage_migrate::v0_3::Response);
    /// `vtc/rooms/community/create/0.4` payload — a room the community itself
    /// owns: its label, description, tags, tier, retention and the reason recorded
    /// with it.
    RoomsCommunityCreate04Payload(rooms_community::create::v0_4::Payload);
    /// `vtc/rooms/community/create/0.4#response` — the room as the community owns
    /// it, with its details, and whether its profile was written (`roomProfile`).
    RoomsCommunityCreate04Response(rooms_community::create::v0_4::Response);
    /// `vtc/rooms/community/list/0.4` payload — a page, optionally only the rooms
    /// carrying one tag, or in the given states.
    RoomsCommunityList04Payload(rooms_community::list::v0_4::Payload);
    /// `vtc/rooms/community/list/0.4#response` — one page of the rooms the
    /// community owns, with their details and their state (`status`).
    RoomsCommunityList04Response(rooms_community::list::v0_4::Response);
    /// `vtc/rooms/community/get/0.4#response` — one room the community owns, with
    /// its details and its state (`status`).
    RoomsCommunityGet04Response(rooms_community::get::v0_4::Response);
    /// `vtc/rooms/community/archive/0.1` payload — archive a room read-only or with
    /// no access, and why.
    RoomsCommunityArchive01Payload(rooms_community::archive::v0_1::Payload);
    /// `vtc/rooms/community/archive/0.1#response` — the room, whether it changed, the
    /// offers withdrawn, and the revocation list in force where credentials were withdrawn.
    RoomsCommunityArchive01Response(rooms_community::archive::v0_1::Response);
    /// `vtc/rooms/community/unarchive/0.1` payload.
    RoomsCommunityUnarchive01Payload(rooms_community::unarchive::v0_1::Payload);
    /// `vtc/rooms/community/unarchive/0.1#response` — the room, and whether it changed.
    RoomsCommunityUnarchive01Response(rooms_community::unarchive::v0_1::Response);
    /// `vtc/rooms/community/remove/0.1` payload — remove an archived room after a grace
    /// period, or at once.
    RoomsCommunityRemove01Payload(rooms_community::remove::v0_1::Payload);
    /// `vtc/rooms/community/remove/0.1#response` — the room, scheduled for removal or
    /// being purged.
    RoomsCommunityRemove01Response(rooms_community::remove::v0_1::Response);
    /// `vtc/rooms/community/removal/cancel/0.1` payload.
    RoomsCommunityRemovalCancel01Payload(rooms_community::removal::cancel::v0_1::Payload);
    /// `vtc/rooms/community/removal/cancel/0.1#response` — the room, archived with no
    /// access again.
    RoomsCommunityRemovalCancel01Response(rooms_community::removal::cancel::v0_1::Response);
    /// `vtc/rooms/community/update/0.3` payload — a room's new label, description
    /// or tags, and the reason recorded with them; a new label or description is
    /// also written into the room as its profile.
    RoomsCommunityUpdate03Payload(rooms_community::update::v0_3::Payload);
    /// `vtc/rooms/community/update/0.3#response` — the room, whether the request
    /// changed it, and its profile's state (`roomProfile`).
    RoomsCommunityUpdate03Response(rooms_community::update::v0_3::Response);
    /// `vtc/rooms/community/members/add/0.2` payload — admit an active member
    /// with actions, an expiry and a reason.
    RoomsCommunityMembersAdd02Payload(rooms_community::members::add::v0_2::Payload);
    /// `vtc/rooms/community/members/add/0.2#response` — the member's record.
    RoomsCommunityMembersAdd02Response(rooms_community::members::add::v0_2::Response);
    /// `vtc/rooms/community/members/remove/0.2` payload.
    RoomsCommunityMembersRemove02Payload(rooms_community::members::remove::v0_2::Payload);
    /// `vtc/rooms/community/members/remove/0.2#response` — the member's record; on
    /// `open` and `attributed` rooms the revocation list in force at the room's host and
    /// the withdrawal's time; on a sealed tier the first epoch sealed without them.
    RoomsCommunityMembersRemove02Response(rooms_community::members::remove::v0_2::Response);
    /// `vtc/directory/fields/list/0.1` payload.
    DirectoryFieldsList01Payload(directory::fields::list::v0_1::Payload);
    /// `vtc/directory/fields/list/0.1#response` — the schema and the listing default.
    DirectoryFieldsList01Response(directory::fields::list::v0_1::Response);
    /// `vtc/directory/fields/define/0.1` payload — a new community field.
    DirectoryFieldsDefine01Payload(directory::fields::define::v0_1::Payload);
    /// `vtc/directory/fields/define/0.1#response`.
    DirectoryFieldsDefine01Response(directory::fields::define::v0_1::Response);
    /// `vtc/directory/fields/update/0.1` payload — the members of a field to change.
    DirectoryFieldsUpdate01Payload(directory::fields::update::v0_1::Payload);
    /// `vtc/directory/fields/update/0.1#response`.
    DirectoryFieldsUpdate01Response(directory::fields::update::v0_1::Response);
    /// `vtc/directory/fields/retire/0.1` payload.
    DirectoryFieldsRetire01Payload(directory::fields::retire::v0_1::Payload);
    /// `vtc/directory/fields/retire/0.1#response` — the field, with its purge date.
    DirectoryFieldsRetire01Response(directory::fields::retire::v0_1::Response);
    /// `vtc/directory/card/assert/0.1` payload — administrator-asserted values.
    DirectoryCardAssert01Payload(directory::card::assert::v0_1::Payload);
    /// `vtc/directory/card/assert/0.1#response` — which fields were written.
    DirectoryCardAssert01Response(directory::card::assert::v0_1::Response);
    /// `vtc/directory/entries/list/0.2` payload — browse, search and filter.
    DirectoryEntriesList02Payload(directory::entries::list::v0_2::Payload);
    /// `vtc/directory/entries/list/0.2#response` — one page of projected entries and facets.
    DirectoryEntriesList02Response(directory::entries::list::v0_2::Response);
    /// `vtc/directory/entries/show/0.1` payload — by entry or, for administrators, by DID.
    DirectoryEntriesShow01Payload(directory::entries::show::v0_1::Payload);
    /// `vtc/directory/entries/show/0.1#response` — one projected entry.
    DirectoryEntriesShow01Response(directory::entries::show::v0_1::Response);
    /// `vtc/directory/card/show/0.1` payload.
    DirectoryCardShow01Payload(directory::card::show::v0_1::Payload);
    /// `vtc/directory/card/show/0.1#response` — the member's own card, whole.
    DirectoryCardShow01Response(directory::card::show::v0_1::Response);
    /// `vtc/directory/card/update/0.1` payload — the member's values, visibilities and discoverability.
    DirectoryCardUpdate01Payload(directory::card::update::v0_1::Payload);
    /// `vtc/directory/card/update/0.1#response` — the card as it now stands.
    DirectoryCardUpdate01Response(directory::card::update::v0_1::Response);
    /// `vtc/directory/disclosure/0.1` payload.
    DirectoryDisclosure01Payload(directory::disclosure::v0_1::Payload);
    /// `vtc/directory/disclosure/0.1#response` — what the directory would
    /// disclose about a member, and to whom.
    DirectoryDisclosure01Response(directory::disclosure::v0_1::Response);
    /// `vtc/directory/images/upload/0.1` payload — one picture, base64url.
    DirectoryImagesUpload01Payload(directory::images::upload::v0_1::Payload);
    /// `vtc/directory/images/upload/0.1#response` — the stored picture's reference.
    DirectoryImagesUpload01Response(directory::images::upload::v0_1::Response);
    /// `vtc/directory/images/get/0.1` payload — an entry and its picture field.
    DirectoryImagesGet01Payload(directory::images::get::v0_1::Payload);
    /// `vtc/directory/images/get/0.1#response` — the picture, where the projection shows it.
    DirectoryImagesGet01Response(directory::images::get::v0_1::Response);
    /// `vtc/directory/card/publish/0.1` payload — the member's signed external card.
    DirectoryCardPublish01Payload(directory::card::publish::v0_1::Payload);
    /// `vtc/directory/card/publish/0.1#response` — where the external card stands.
    DirectoryCardPublish01Response(directory::card::publish::v0_1::Response);
    /// `vtc/directory/card/public/0.1` payload — an entry, and the card expected.
    DirectoryCardPublic01Payload(directory::card::public::v0_1::Payload);
    /// `vtc/directory/card/public/0.1#response` — the card exactly as its member signed it.
    DirectoryCardPublic01Response(directory::card::public::v0_1::Response);
    /// `vtc/networks/list/0.2` payload — which memberships to list.
    NetworksList02Payload(networks::list::v0_2::Payload);
    /// `vtc/networks/list/0.2#response` — the community's network memberships.
    NetworksList02Response(networks::list::v0_2::Response);
    /// `vtc/networks/show/0.2` payload — one membership, by network DID.
    NetworksShow02Payload(networks::show::v0_2::Payload);
    /// `vtc/networks/show/0.2#response` — the membership and its credentials.
    NetworksShow02Response(networks::show::v0_2::Response);
    /// `vtc/networks/preview/0.1` payload — the network to read before joining.
    NetworksPreview01Payload(networks::preview::v0_1::Payload);
    /// `vtc/networks/preview/0.1#response` — the network, and where the community stands.
    NetworksPreview01Response(networks::preview::v0_1::Response);
    /// `vtc/networks/join/0.2` payload — accept a network's listing.
    NetworksJoin02Payload(networks::join::v0_2::Payload);
    /// `vtc/networks/join/0.2#response` — the membership as it now stands.
    NetworksJoin02Response(networks::join::v0_2::Response);
    /// `vtc/networks/leave/0.2` payload — depart a network.
    NetworksLeave02Payload(networks::leave::v0_2::Payload);
    /// `vtc/networks/leave/0.2#response` — the membership as it now stands.
    NetworksLeave02Response(networks::leave::v0_2::Response);
    /// `vtc/networks/repudiate/0.2` payload — reject a network's listing.
    NetworksRepudiate02Payload(networks::repudiate::v0_2::Payload);
    /// `vtc/networks/repudiate/0.2#response` — the membership as it now stands.
    NetworksRepudiate02Response(networks::repudiate::v0_2::Response);
    /// `vtc/groups/create/0.1` payload — a new static group.
    GroupsCreate01Payload(groups::create::v0_1::Payload);
    /// `vtc/groups/create/0.1#response` — the group as stored.
    GroupsCreate01Response(groups::create::v0_1::Response);
    /// `vtc/groups/update/0.1` payload — a group's settings.
    GroupsUpdate01Payload(groups::update::v0_1::Payload);
    /// `vtc/groups/update/0.1#response` — the group as it now stands.
    GroupsUpdate01Response(groups::update::v0_1::Response);
    /// `vtc/groups/delete/0.1` payload — the group to delete, and why.
    GroupsDelete01Payload(groups::delete::v0_1::Payload);
    /// `vtc/groups/delete/0.1#response` — whether the group is gone.
    GroupsDelete01Response(groups::delete::v0_1::Response);
    /// `vtc/groups/list/0.2` payload — which groups to list.
    GroupsList02Payload(groups::list::v0_2::Payload);
    /// `vtc/groups/list/0.2#response` — the groups the caller may see.
    GroupsList02Response(groups::list::v0_2::Response);
    /// `vtc/groups/show/0.1` payload — one group.
    GroupsShow01Payload(groups::show::v0_1::Payload);
    /// `vtc/groups/show/0.1#response` — the group as the caller may see it.
    GroupsShow01Response(groups::show::v0_1::Response);
    /// `vtc/groups/members/add/0.1` payload — adding a member.
    GroupsMembersAdd01Payload(groups::members::add::v0_1::Payload);
    /// `vtc/groups/members/add/0.1#response` — the membership, and the credential offered.
    GroupsMembersAdd01Response(groups::members::add::v0_1::Response);
    /// `vtc/groups/members/remove/0.1` payload — removing a member.
    GroupsMembersRemove01Payload(groups::members::remove::v0_1::Payload);
    /// `vtc/groups/members/remove/0.1#response` — the membership ended.
    GroupsMembersRemove01Response(groups::members::remove::v0_1::Response);
    /// `vtc/groups/members/list/0.2` payload — one group's members.
    GroupsMembersList02Payload(groups::members::list::v0_2::Payload);
    /// `vtc/groups/members/list/0.2#response` — the members the caller may see.
    GroupsMembersList02Response(groups::members::list::v0_2::Response);
    /// `vtc/groups/join/0.1` payload — joining or asking to.
    GroupsJoin01Payload(groups::join::v0_1::Payload);
    /// `vtc/groups/join/0.1#response` — what came of it.
    GroupsJoin01Response(groups::join::v0_1::Response);
    /// `vtc/groups/leave/0.1` payload — leaving, or withdrawing a request.
    GroupsLeave01Payload(groups::leave::v0_1::Payload);
    /// `vtc/groups/leave/0.1#response` — what came of it.
    GroupsLeave01Response(groups::leave::v0_1::Response);
    /// `vtc/boards/create/0.1` payload — creating a board.
    BoardsCreate01Payload(boards::create::v0_1::Payload);
    /// `vtc/boards/create/0.1#response` — the board as created.
    BoardsCreate01Response(boards::create::v0_1::Response);
    /// `vtc/boards/update/0.1` payload — changing, closing or archiving a board.
    BoardsUpdate01Payload(boards::update::v0_1::Payload);
    /// `vtc/boards/update/0.1#response` — the board as changed.
    BoardsUpdate01Response(boards::update::v0_1::Response);
    /// `vtc/boards/delete/0.1` payload — the closed board to delete, and why.
    BoardsDelete01Payload(boards::delete::v0_1::Payload);
    /// `vtc/boards/delete/0.1#response` — what was removed, and when the tombstones go.
    BoardsDelete01Response(boards::delete::v0_1::Response);
    /// `vtc/boards/facilitators/add/0.1` payload — appointing a board's facilitator.
    BoardsFacilitatorsAdd01Payload(boards::facilitators::add::v0_1::Payload);
    /// `vtc/boards/facilitators/add/0.1#response` — the board's appointed facilitators.
    BoardsFacilitatorsAdd01Response(boards::facilitators::add::v0_1::Response);
    /// `vtc/boards/facilitators/remove/0.1` payload — ending a facilitator's appointment.
    BoardsFacilitatorsRemove01Payload(boards::facilitators::remove::v0_1::Payload);
    /// `vtc/boards/facilitators/remove/0.1#response` — the board's appointed facilitators.
    BoardsFacilitatorsRemove01Response(boards::facilitators::remove::v0_1::Response);
    /// `vtc/boards/facilitators/list/0.1` payload — the board whose facilitators to read.
    BoardsFacilitatorsList01Payload(boards::facilitators::list::v0_1::Payload);
    /// `vtc/boards/facilitators/list/0.1#response` — each appointment, by entry.
    BoardsFacilitatorsList01Response(boards::facilitators::list::v0_1::Response);
    /// `vtc/boards/list/0.1` payload — the boards the caller may see.
    BoardsList01Payload(boards::list::v0_1::Payload);
    /// `vtc/boards/list/0.1#response` — the boards.
    BoardsList01Response(boards::list::v0_1::Response);
    /// `vtc/boards/show/0.1` payload — one board and its ideas.
    BoardsShow01Payload(boards::show::v0_1::Payload);
    /// `vtc/boards/show/0.1#response` — the board and a page of its ideas.
    BoardsShow01Response(boards::show::v0_1::Response);
    /// `vtc/boards/ideas/propose/0.1` payload — proposing an idea.
    BoardsIdeasPropose01Payload(boards::ideas::propose::v0_1::Payload);
    /// `vtc/boards/ideas/propose/0.1#response` — the idea as proposed.
    BoardsIdeasPropose01Response(boards::ideas::propose::v0_1::Response);
    /// `vtc/boards/ideas/update/0.1` payload — changing one's own proposed idea.
    BoardsIdeasUpdate01Payload(boards::ideas::update::v0_1::Payload);
    /// `vtc/boards/ideas/update/0.1#response` — the idea as changed.
    BoardsIdeasUpdate01Response(boards::ideas::update::v0_1::Response);
    /// `vtc/boards/ideas/withdraw/0.1` payload — withdrawing one's own proposed idea.
    BoardsIdeasWithdraw01Payload(boards::ideas::withdraw::v0_1::Payload);
    /// `vtc/boards/ideas/withdraw/0.1#response` — the idea, withdrawn.
    BoardsIdeasWithdraw01Response(boards::ideas::withdraw::v0_1::Response);
    /// `vtc/boards/ideas/decide/0.1` payload — a facilitator accepting, declining, merging or reopening an idea.
    BoardsIdeasDecide01Payload(boards::ideas::decide::v0_1::Payload);
    /// `vtc/boards/ideas/decide/0.1#response` — the idea as decided.
    BoardsIdeasDecide01Response(boards::ideas::decide::v0_1::Response);
    /// `vtc/boards/ideas/select/0.1` payload — a facilitator selecting a tallied idea or not.
    BoardsIdeasSelect01Payload(boards::ideas::select::v0_1::Payload);
    /// `vtc/boards/ideas/select/0.1#response` — the idea, with the result it was decided with.
    BoardsIdeasSelect01Response(boards::ideas::select::v0_1::Response);
    /// `vtc/boards/notes/add/0.1` payload — adding a note to a board or an idea.
    BoardsNotesAdd01Payload(boards::notes::add::v0_1::Payload);
    /// `vtc/boards/notes/add/0.1#response` — the note.
    BoardsNotesAdd01Response(boards::notes::add::v0_1::Response);
    /// `vtc/boards/notes/list/0.1` payload — a board's or an idea's notes.
    BoardsNotesList01Payload(boards::notes::list::v0_1::Payload);
    /// `vtc/boards/notes/list/0.1#response` — the notes the caller may read.
    BoardsNotesList01Response(boards::notes::list::v0_1::Response);
    /// `vtc/boards/notes/withdraw/0.1` payload — withdrawing one's own note.
    BoardsNotesWithdraw01Payload(boards::notes::withdraw::v0_1::Payload);
    /// `vtc/boards/notes/withdraw/0.1#response` — the note, withdrawn.
    BoardsNotesWithdraw01Response(boards::notes::withdraw::v0_1::Response);
    /// `vtc/boards/notes/hide/0.1` payload — a facilitator hiding or showing a note.
    BoardsNotesHide01Payload(boards::notes::hide::v0_1::Payload);
    /// `vtc/boards/notes/hide/0.1#response` — the note.
    BoardsNotesHide01Response(boards::notes::hide::v0_1::Response);
    /// `vtc/badges/settings/show/0.1` payload — the community's badge settings.
    BadgesSettingsShow01Payload(badges::settings::show::v0_1::Payload);
    /// `vtc/badges/settings/show/0.1#response`.
    BadgesSettingsShow01Response(badges::settings::show::v0_1::Response);
    /// `vtc/badges/settings/update/0.1` payload — changing the badge settings.
    BadgesSettingsUpdate01Payload(badges::settings::update::v0_1::Payload);
    /// `vtc/badges/settings/update/0.1#response`.
    BadgesSettingsUpdate01Response(badges::settings::update::v0_1::Response);
    /// `vtc/badges/create/0.1` payload — defining a badge.
    BadgesCreate01Payload(badges::create::v0_1::Payload);
    /// `vtc/badges/create/0.1#response`.
    BadgesCreate01Response(badges::create::v0_1::Response);
    /// `vtc/badges/update/0.1` payload — changing a badge.
    BadgesUpdate01Payload(badges::update::v0_1::Payload);
    /// `vtc/badges/update/0.1#response`.
    BadgesUpdate01Response(badges::update::v0_1::Response);
    /// `vtc/badges/retire/0.1` payload — retiring a badge.
    BadgesRetire01Payload(badges::retire::v0_1::Payload);
    /// `vtc/badges/retire/0.1#response`.
    BadgesRetire01Response(badges::retire::v0_1::Response);
    /// `vtc/badges/promote/0.1` payload — turning a kudos badge into a community badge.
    BadgesPromote01Payload(badges::promote::v0_1::Payload);
    /// `vtc/badges/promote/0.1#response`.
    BadgesPromote01Response(badges::promote::v0_1::Response);
    /// `vtc/badges/list/0.1` payload — the badges the signer may see.
    BadgesList01Payload(badges::list::v0_1::Payload);
    /// `vtc/badges/list/0.1#response`.
    BadgesList01Response(badges::list::v0_1::Response);
    /// `vtc/badges/show/0.1` payload — one badge as the signer sees it.
    BadgesShow01Payload(badges::show::v0_1::Payload);
    /// `vtc/badges/show/0.1#response`.
    BadgesShow01Response(badges::show::v0_1::Response);
    /// `vtc/badges/images/upload/0.1` payload — a badge picture, re-encoded and stored.
    BadgesImagesUpload01Payload(badges::images::upload::v0_1::Payload);
    /// `vtc/badges/images/upload/0.1#response`.
    BadgesImagesUpload01Response(badges::images::upload::v0_1::Response);
    /// `vtc/badges/images/get/0.1` payload — a badge's picture.
    BadgesImagesGet01Payload(badges::images::get::v0_1::Payload);
    /// `vtc/badges/images/get/0.1#response`.
    BadgesImagesGet01Response(badges::images::get::v0_1::Response);
    /// `vtc/badges/awards/offer/0.1` payload — offering a community badge.
    BadgesAwardsOffer01Payload(badges::awards::offer::v0_1::Payload);
    /// `vtc/badges/awards/offer/0.1#response`.
    BadgesAwardsOffer01Response(badges::awards::offer::v0_1::Response);
    /// `vtc/badges/awards/withdraw/0.1` payload — withdrawing an open offer.
    BadgesAwardsWithdraw01Payload(badges::awards::withdraw::v0_1::Payload);
    /// `vtc/badges/awards/withdraw/0.1#response`.
    BadgesAwardsWithdraw01Response(badges::awards::withdraw::v0_1::Response);
    /// `vtc/badges/awards/revoke/0.1` payload — taking an accepted award back.
    BadgesAwardsRevoke01Payload(badges::awards::revoke::v0_1::Payload);
    /// `vtc/badges/awards/revoke/0.1#response`.
    BadgesAwardsRevoke01Response(badges::awards::revoke::v0_1::Response);
    /// `vtc/badges/claims/create/0.1` payload — issuing a claim code for an event.
    BadgesClaimsCreate01Payload(badges::claims::create::v0_1::Payload);
    /// `vtc/badges/claims/create/0.1#response`.
    BadgesClaimsCreate01Response(badges::claims::create::v0_1::Response);
    /// `vtc/badges/claims/list/0.1` payload — a badge's claim codes, never a code.
    BadgesClaimsList01Payload(badges::claims::list::v0_1::Payload);
    /// `vtc/badges/claims/list/0.1#response`.
    BadgesClaimsList01Response(badges::claims::list::v0_1::Response);
    /// `vtc/badges/claims/withdraw/0.1` payload — a claim code admits no one more.
    BadgesClaimsWithdraw01Payload(badges::claims::withdraw::v0_1::Payload);
    /// `vtc/badges/claims/withdraw/0.1#response`.
    BadgesClaimsWithdraw01Response(badges::claims::withdraw::v0_1::Response);
    /// `vtc/badges/claims/redeem/0.1` payload — a member claims the badge with a code.
    BadgesClaimsRedeem01Payload(badges::claims::redeem::v0_1::Payload);
    /// `vtc/badges/claims/redeem/0.1#response`.
    BadgesClaimsRedeem01Response(badges::claims::redeem::v0_1::Response);
    /// `vtc/badges/awards/share/0.1` payload — the holder shows an award outside.
    BadgesAwardsShare01Payload(badges::awards::share::v0_1::Payload);
    /// `vtc/badges/awards/share/0.1#response`.
    BadgesAwardsShare01Response(badges::awards::share::v0_1::Response);
    /// `vtc/badges/awards/unshare/0.1` payload — the holder stops showing it.
    BadgesAwardsUnshare01Payload(badges::awards::unshare::v0_1::Payload);
    /// `vtc/badges/awards/unshare/0.1#response`.
    BadgesAwardsUnshare01Response(badges::awards::unshare::v0_1::Response);
    /// `vtc/badges/awards/list/0.1` payload — a badge's awards, to its owners.
    BadgesAwardsList01Payload(badges::awards::list::v0_1::Payload);
    /// `vtc/badges/awards/list/0.1#response`.
    BadgesAwardsList01Response(badges::awards::list::v0_1::Response);
    /// `vtc/badges/holders/list/0.1` payload — a badge's holders.
    BadgesHoldersList01Payload(badges::holders::list::v0_1::Payload);
    /// `vtc/badges/holders/list/0.1#response`.
    BadgesHoldersList01Response(badges::holders::list::v0_1::Response);
    /// `vtc/badges/wall/show/0.1` payload — a member's badge wall.
    BadgesWallShow01Payload(badges::wall::show::v0_1::Payload);
    /// `vtc/badges/wall/show/0.1#response`.
    BadgesWallShow01Response(badges::wall::show::v0_1::Response);
    /// `vtc/badges/mine/list/0.1` payload — the signer's own badges and offers.
    BadgesMineList01Payload(badges::mine::list::v0_1::Payload);
    /// `vtc/badges/mine/list/0.1#response`.
    BadgesMineList01Response(badges::mine::list::v0_1::Response);
    /// `vtc/badges/mine/accept/0.1` payload — accepting an offer.
    BadgesMineAccept01Payload(badges::mine::accept::v0_1::Payload);
    /// `vtc/badges/mine/accept/0.1#response`.
    BadgesMineAccept01Response(badges::mine::accept::v0_1::Response);
    /// `vtc/badges/mine/decline/0.1` payload — declining an offer.
    BadgesMineDecline01Payload(badges::mine::decline::v0_1::Payload);
    /// `vtc/badges/mine/decline/0.1#response`.
    BadgesMineDecline01Response(badges::mine::decline::v0_1::Response);
    /// `vtc/badges/mine/hide/0.1` payload — hiding a held badge from the portal.
    BadgesMineHide01Payload(badges::mine::hide::v0_1::Payload);
    /// `vtc/badges/mine/hide/0.1#response`.
    BadgesMineHide01Response(badges::mine::hide::v0_1::Response);
    /// `vtc/badges/mine/show/0.1` payload — showing a hidden badge again.
    BadgesMineShow01Payload(badges::mine::show::v0_1::Payload);
    /// `vtc/badges/mine/show/0.1#response`.
    BadgesMineShow01Response(badges::mine::show::v0_1::Response);
    /// `vtc/badges/mine/arrange/0.1` payload — ordering and pinning the wall.
    BadgesMineArrange01Payload(badges::mine::arrange::v0_1::Payload);
    /// `vtc/badges/mine/arrange/0.1#response`.
    BadgesMineArrange01Response(badges::mine::arrange::v0_1::Response);
    /// `vtc/badges/kudos/give/0.1` payload — giving a kudos badge.
    BadgesKudosGive01Payload(badges::kudos::give::v0_1::Payload);
    /// `vtc/badges/kudos/give/0.1#response`.
    BadgesKudosGive01Response(badges::kudos::give::v0_1::Response);
    /// `vtc/badges/kudos/list/0.1` payload — kudos given and received.
    BadgesKudosList01Payload(badges::kudos::list::v0_1::Payload);
    /// `vtc/badges/kudos/list/0.1#response`.
    BadgesKudosList01Response(badges::kudos::list::v0_1::Response);
    /// `vtc/groups/requests/list/0.2` payload — requests to the caller's groups.
    GroupsRequestsList02Payload(groups::requests::list::v0_2::Payload);
    /// `vtc/groups/requests/list/0.2#response` — the requests.
    GroupsRequestsList02Response(groups::requests::list::v0_2::Response);
    /// `vtc/groups/requests/decide/0.1` payload — a decision on a request.
    GroupsRequestsDecide01Payload(groups::requests::decide::v0_1::Payload);
    /// `vtc/groups/requests/decide/0.1#response` — the request, and the membership it made.
    GroupsRequestsDecide01Response(groups::requests::decide::v0_1::Response);
    /// `vtc/groups/managers/add/0.1` payload — appointing a group's manager.
    GroupsManagersAdd01Payload(groups::managers::add::v0_1::Payload);
    /// `vtc/groups/managers/add/0.1#response` — the group's managers.
    GroupsManagersAdd01Response(groups::managers::add::v0_1::Response);
    /// `vtc/groups/managers/remove/0.1` payload — ending a manager's appointment.
    GroupsManagersRemove01Payload(groups::managers::remove::v0_1::Payload);
    /// `vtc/groups/managers/remove/0.1#response` — the group's managers.
    GroupsManagersRemove01Response(groups::managers::remove::v0_1::Response);
    /// `vtc/config/did-hosting/list/0.1` payload — nothing to filter by.
    ConfigDidHostingList01Payload(config::did_hosting::list::v0_1::Payload);
    /// `vtc/config/did-hosting/list/0.1#response` — the hosting servers the
    /// community's VTA can publish its identities through.
    ConfigDidHostingList01Response(config::did_hosting::list::v0_1::Response);
    /// `vtc/groups/bindings/add/0.1` payload — binding a group to a room.
    GroupsBindingsAdd01Payload(groups::bindings::add::v0_1::Payload);
    /// `vtc/groups/bindings/add/0.1#response` — the binding recorded.
    GroupsBindingsAdd01Response(groups::bindings::add::v0_1::Response);
    /// `vtc/groups/bindings/remove/0.1` payload — ending a binding, and why.
    GroupsBindingsRemove01Payload(groups::bindings::remove::v0_1::Payload);
    /// `vtc/groups/bindings/remove/0.1#response` — where its removal stands.
    GroupsBindingsRemove01Response(groups::bindings::remove::v0_1::Response);
    /// `vtc/groups/bindings/list/0.1` payload — one group's bindings.
    GroupsBindingsList01Payload(groups::bindings::list::v0_1::Payload);
    /// `vtc/groups/bindings/list/0.1#response` — the group's bindings.
    GroupsBindingsList01Response(groups::bindings::list::v0_1::Response);
    /// `vtc/directory/card/present/0.1` payload — the fields a presentation fills.
    DirectoryCardPresent01Payload(directory::card::present::v0_1::Payload);
    /// `vtc/directory/card/present/0.1#response` — each field's verified value.
    DirectoryCardPresent01Response(directory::card::present::v0_1::Response);
    /// `vtc/directory/notes/append/0.1` payload — a note about a member, or a redaction.
    DirectoryNotesAppend01Payload(directory::notes::append::v0_1::Payload);
    /// `vtc/directory/notes/append/0.1#response` — the note as stored.
    DirectoryNotesAppend01Response(directory::notes::append::v0_1::Response);
    /// `vtc/directory/notes/list/0.2` payload — one member's notes, a page at a time.
    DirectoryNotesList02Payload(directory::notes::list::v0_2::Payload);
    /// `vtc/directory/notes/list/0.2#response` — notes newest first, redacted text withheld.
    DirectoryNotesList02Response(directory::notes::list::v0_2::Response);
    /// `vtc/directory/notes/export/0.1` payload — one member's notes, and why.
    DirectoryNotesExport01Payload(directory::notes::export::v0_1::Payload);
    /// `vtc/directory/notes/export/0.1#response` — every note as written.
    DirectoryNotesExport01Response(directory::notes::export::v0_1::Response);
    /// `vtc/directory/export/0.2` payload — the whole directory, and why.
    DirectoryExport02Payload(directory::export::v0_2::Payload);
    /// `vtc/directory/export/0.2#response` — one page of JSContact cards.
    DirectoryExport02Response(directory::export::v0_2::Response);
    /// `vtc/rooms/community/members/list/0.2` payload.
    RoomsCommunityMembersList02Payload(rooms_community::members::list::v0_2::Payload);
    /// `vtc/rooms/community/members/list/0.2#response` — one page of a room's
    /// members, offered, admitted, suspended or removed.
    RoomsCommunityMembersList02Response(rooms_community::members::list::v0_2::Response);
    /// `vtc/storage/configs/list/0.2#response` — with `roleArn` and `notAllowed`.
    StorageConfigsList02Response(storage_configs::list::v0_2::Response);
    /// `vtc/storage/configs/get/0.2#response` — one config, its facts and rooms.
    StorageConfigsGet02Response(storage_configs::get::v0_2::Response);
    /// `vtc/storage/configs/create/0.3` payload. Carries no secret.
    StorageConfigsCreate03Payload(storage_configs::create::v0_3::Payload);
    /// `vtc/storage/configs/create/0.3#response`.
    StorageConfigsCreate03Response(storage_configs::create::v0_3::Response);
    /// `vtc/storage/configs/update/0.3` payload.
    StorageConfigsUpdate03Payload(storage_configs::update::v0_3::Payload);
    /// `vtc/storage/configs/update/0.3#response`.
    StorageConfigsUpdate03Response(storage_configs::update::v0_3::Response);
    /// `vtc/storage/configs/retire/0.3#response`.
    StorageConfigsRetire03Response(storage_configs::retire::v0_3::Response);
    /// `vtc/storage/configs/probe/0.1#response` — each step of a canary round trip.
    StorageConfigsProbe01Response(storage_configs::probe::v0_1::Response);
    /// `vtc/storage/credentials/set/0.3` payload — a `sealed` config's credential, sealed
    /// to the community in the administrator's own client. Never carries it in the clear.
    StorageCredentialsSet03Payload(storage_credentials_set::v0_3::Payload);
    /// `vtc/storage/credentials/set/0.3#response` — the config's credential state, by
    /// fingerprint, and the probe's outcome.
    StorageCredentialsSet03Response(storage_credentials_set::v0_3::Response);
    /// `vtc/storage/credentials/set/0.3`'s `SealedCredentialCleartext` — what a producer
    /// seals inside the block. Never a payload member, never sent unsealed.
    StorageCredentialsSet03Cleartext(storage_credentials_set::v0_3::SealedCredentialCleartext)
        in storage_credentials_set::v0_3::Payload as "SealedCredentialCleartext";
    /// `git-ns/view/0.6#response` — namespaces, repositories and recorded git
    /// rights.
    GitNsView06Response(git_ns_view::v0_6::Response);
    /// `git-ns/view/0.6`'s `RepoSummary` — one repository as the VTC records it.
    GitNsView06RepoSummary(git_ns_view::v0_6::RepoSummary)
        in git_ns_view::v0_6::Response as "RepoSummary";
    /// `git-ns/view/0.6`'s `RightRecord` — one recorded git right.
    GitNsView06RightRecord(git_ns_view::v0_6::RightRecord)
        in git_ns_view::v0_6::Response as "RightRecord";
    /// `git-ns/view/0.6`'s `GitNamespace` — the VTC's binding to one owner on
    /// one forge.
    GitNsView06GitNamespace(git_ns_view::v0_6::GitNamespace)
        in git_ns_view::v0_6::Response as "GitNamespace";
    /// `git-ns/view/0.6`'s `DriftItem` — one difference between the forge
    /// and the projection.
    GitNsView06DriftItem(git_ns_view::v0_6::DriftItem)
        in git_ns_view::v0_6::Response as "DriftItem";
}

/// One type's component, and every other definition of its schema, which the
/// component may refer to.
struct Rendered {
    name: String,
    schema: RefOr<Schema>,
    definitions: Vec<(String, RefOr<Schema>)>,
}

/// Render the type `definition` names in `C`'s embedded schema — or, when it
/// names none, `C` itself.
///
/// `definition` is a `$defs` name, or `Name@<json-pointer>` for a type the
/// specification declares inline rather than as a named definition (an array's
/// item type, say). The node is still taken from `C`'s own published schema, so
/// the document cannot drift from the specification; the name before `@` is
/// only what the component is called.
fn rendered<C: trust_tasks_rs::Payload>(definition: Option<&str>) -> Rendered {
    let prefix = component_prefix(C::TYPE_URI);
    let schema: Value = C::PAYLOAD_SCHEMA
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(Value::Bool(true));
    let definitions = schema
        .get("$defs")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    // A named definition; else the definition a response schema's root refers
    // to; else the root itself, which is a payload.
    let own = definition.map(str::to_string).or_else(|| {
        schema
            .get("$ref")
            .and_then(Value::as_str)
            .and_then(|r| r.strip_prefix("#/$defs/"))
            .map(str::to_string)
    });
    if let Some((label, pointer)) = own.as_deref().and_then(|d| d.split_once('@')) {
        return Rendered {
            name: format!("{prefix}{label}"),
            schema: convert(
                schema.pointer(pointer).unwrap_or(&Value::Bool(true)),
                &prefix,
            ),
            definitions: definitions
                .iter()
                .map(|(definition, node)| (format!("{prefix}{definition}"), convert(node, &prefix)))
                .collect(),
        };
    }
    let (name, node) = match &own {
        Some(definition) => (
            format!("{prefix}{definition}"),
            definitions
                .get(definition)
                .cloned()
                .unwrap_or(Value::Bool(true)),
        ),
        None => (format!("{prefix}Payload"), schema.clone()),
    };

    Rendered {
        name,
        schema: convert(&node, &prefix),
        definitions: definitions
            .iter()
            .filter(|(definition, _)| own.as_deref() != Some(definition.as_str()))
            .map(|(definition, node)| (format!("{prefix}{definition}"), convert(node, &prefix)))
            .collect(),
    }
}

/// `https://trusttasks.org/spec/vtc/join-requests/manifest/0.4#response` →
/// `VtcJoinRequestsManifestV0_4`.
fn component_prefix(type_uri: &str) -> String {
    let path = type_uri.split('#').next().unwrap_or(type_uri);
    let path = path.split_once("/spec/").map_or(path, |(_, p)| p);
    let mut segments: Vec<&str> = path.split('/').collect();
    let version = segments.pop().unwrap_or_default();
    let mut out = String::new();
    for word in segments.iter().flat_map(|s| s.split('-')) {
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
        }
    }
    out.push('V');
    out.push_str(&version.replace('.', "_"));
    out
}

fn convert(node: &Value, prefix: &str) -> RefOr<Schema> {
    let Some(obj) = node.as_object() else {
        // `true`: anything.
        return RefOr::T(Schema::Object(
            ObjectBuilder::new()
                .schema_type(SchemaType::AnyValue)
                .build(),
        ));
    };
    let description = obj.get("description").and_then(Value::as_str);

    if let Some(target) = obj.get("$ref").and_then(Value::as_str) {
        let name = target
            .strip_prefix("#/$defs/")
            .map_or_else(|| target.to_string(), |d| format!("{prefix}{d}"));
        return RefOr::Ref(Ref::from_schema_name(name));
    }
    if let Some(items) = obj.get("oneOf").and_then(Value::as_array) {
        let builder = items
            .iter()
            .fold(OneOfBuilder::new().description(description), |b, item| {
                b.item(convert(item, prefix))
            });
        return RefOr::T(Schema::OneOf(builder.build()));
    }
    if let Some(items) = obj.get("anyOf").and_then(Value::as_array) {
        let builder = items
            .iter()
            .fold(AnyOfBuilder::new().description(description), |b, item| {
                b.item(convert(item, prefix))
            });
        return RefOr::T(Schema::AnyOf(builder.build()));
    }
    if let Some(items) = obj.get("allOf").and_then(Value::as_array) {
        let builder = items
            .iter()
            .fold(AllOfBuilder::new().description(description), |b, item| {
                b.item(convert(item, prefix))
            });
        return RefOr::T(Schema::AllOf(builder.build()));
    }

    match obj.get("type").and_then(Value::as_str) {
        Some("object") => object(obj, description, prefix),
        Some("array") => array(obj, description, prefix),
        None if obj.contains_key("properties") => object(obj, description, prefix),
        Some("string") => scalar(obj, description, SchemaType::Type(Type::String)),
        Some("integer") => scalar(obj, description, SchemaType::Type(Type::Integer)),
        Some("number") => scalar(obj, description, SchemaType::Type(Type::Number)),
        Some("boolean") => scalar(obj, description, SchemaType::Type(Type::Boolean)),
        _ => scalar(obj, description, SchemaType::AnyValue),
    }
}

fn object(obj: &Map<String, Value>, description: Option<&str>, prefix: &str) -> RefOr<Schema> {
    let mut b = ObjectBuilder::new()
        .schema_type(SchemaType::Type(Type::Object))
        .description(description);
    if let Some(properties) = obj.get("properties").and_then(Value::as_object) {
        for (name, property) in properties {
            b = b.property(name, convert(property, prefix));
        }
    }
    for required in obj
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        b = b.required(required);
    }
    match obj.get("additionalProperties") {
        Some(Value::Bool(allowed)) => {
            b = b.additional_properties(Some(AdditionalProperties::<Schema>::FreeForm(*allowed)));
        }
        Some(schema @ Value::Object(_)) => {
            b = b.additional_properties(Some(AdditionalProperties::RefOr(convert(schema, prefix))));
        }
        _ => {}
    }
    b = b.min_properties(count(obj, "minProperties"));
    RefOr::T(Schema::Object(b.build()))
}

fn array(obj: &Map<String, Value>, description: Option<&str>, prefix: &str) -> RefOr<Schema> {
    let mut b = ArrayBuilder::new().description(description);
    if let Some(items) = obj.get("items") {
        b = b.items(convert(items, prefix));
    }
    b = b
        .min_items(count(obj, "minItems"))
        .max_items(count(obj, "maxItems"))
        .unique_items(obj.get("uniqueItems") == Some(&Value::Bool(true)));
    RefOr::T(Schema::Array(b.build()))
}

fn scalar(
    obj: &Map<String, Value>,
    description: Option<&str>,
    schema_type: SchemaType,
) -> RefOr<Schema> {
    let mut b = ObjectBuilder::new()
        .schema_type(schema_type)
        .description(description)
        .format(
            obj.get("format")
                .and_then(Value::as_str)
                .map(|f| SchemaFormat::Custom(f.to_string())),
        )
        .pattern(obj.get("pattern").and_then(Value::as_str))
        .min_length(count(obj, "minLength"))
        .max_length(count(obj, "maxLength"))
        .minimum(number(obj, "minimum"))
        .maximum(number(obj, "maximum"));
    if let Some(values) = obj.get("enum").and_then(Value::as_array) {
        b = b.enum_values(Some(values.iter().cloned()));
    } else if let Some(value) = obj.get("const") {
        b = b.enum_values(Some([value.clone()]));
    }
    RefOr::T(Schema::Object(b.build()))
}

fn count(obj: &Map<String, Value>, keyword: &str) -> Option<usize> {
    obj.get(keyword)
        .and_then(Value::as_u64)
        .and_then(|n| usize::try_from(n).ok())
}

fn number(obj: &Map<String, Value>, keyword: &str) -> Option<utoipa::Number> {
    let value = obj.get(keyword)?;
    value
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .map(utoipa::Number::UInt)
        .or_else(|| {
            value
                .as_i64()
                .and_then(|n| isize::try_from(n).ok())
                .map(utoipa::Number::Int)
        })
        .or_else(|| value.as_f64().map(utoipa::Number::Float))
}

#[cfg(test)]
mod tests {
    use super::*;
    use utoipa::{PartialSchema, ToSchema};

    fn every_ref(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                if let Some(Value::String(r)) = map.get("$ref") {
                    out.push(r.clone());
                }
                map.values().for_each(|v| every_ref(v, out));
            }
            Value::Array(items) => items.iter().for_each(|v| every_ref(v, out)),
            _ => {}
        }
    }

    #[test]
    fn components_are_named_for_their_specification() {
        assert_eq!(
            component_prefix("https://trusttasks.org/spec/vtc/join-requests/manifest/0.4#response"),
            "VtcJoinRequestsManifestV0_4"
        );
        assert_eq!(
            VetterList01Response::name(),
            "VtcVettingVettersListV0_1Response"
        );
        assert_eq!(
            VetterGrant01Payload::name(),
            "VtcVettingVettersGrantV0_1Payload"
        );
        assert_eq!(
            JoinManifest04VettingRequirements::name(),
            "VtcJoinRequestsManifestV0_4VettingRequirements"
        );
    }

    /// Every reference resolves to a component the type brings with it, so a
    /// document built from these has no dangling `$ref` and no JSON Schema
    /// `$defs` pointer OpenAPI cannot follow.
    #[test]
    fn every_reference_resolves_to_a_component_the_type_brings() {
        fn check<T: ToSchema>() {
            let mut components = vec![(T::name().into_owned(), <T as PartialSchema>::schema())];
            T::schemas(&mut components);
            let names: Vec<&str> = components.iter().map(|(n, _)| n.as_str()).collect();
            let mut refs = Vec::new();
            for (_, schema) in &components {
                every_ref(&serde_json::to_value(schema).unwrap(), &mut refs);
            }
            assert!(components.len() > 1 || refs.is_empty());
            for r in refs {
                let name = r
                    .strip_prefix("#/components/schemas/")
                    .unwrap_or_else(|| panic!("{r} is not a component reference"));
                assert!(names.contains(&name), "{r} dangles");
            }
        }
        check::<VetterGrant01Payload>();
        check::<VetterGrant01Response>();
        check::<VetterList01Payload>();
        check::<VetterList01Response>();
        check::<VetterShow01Payload>();
        check::<VetterShow01Response>();
        check::<VetterResend02Response>();
        check::<EndorsementTypeDelete01Response>();
        check::<VetterProfile01VettingMethod>();
        check::<JoinManifest04Response>();
        check::<AcceptsRegister02Payload>();
        check::<AcceptsList02Response>();
        check::<JoinManifest04VettingRequirements>();
        check::<JoinManifest04CommunityBranding>();
        check::<JoinManifest04RequestedAttribute>();
        check::<RegistrySyncJobsList02Payload>();
        check::<RegistrySyncJobsList02Response>();
        check::<RegistrySyncJobsRetry02Payload>();
        check::<RegistrySyncJobsRetry02Response>();
        check::<RegistrySyncJobsDiscard01Payload>();
        check::<RegistrySyncJobsDiscard01Response>();
        check::<RegistryRecordsList02Payload>();
        check::<RegistryRecordsList02Response>();
        check::<DirectoryFieldsList01Payload>();
        check::<DirectoryFieldsList01Response>();
        check::<DirectoryFieldsDefine01Payload>();
        check::<DirectoryFieldsDefine01Response>();
        check::<DirectoryFieldsUpdate01Payload>();
        check::<DirectoryFieldsUpdate01Response>();
        check::<DirectoryFieldsRetire01Payload>();
        check::<DirectoryFieldsRetire01Response>();
        check::<DirectoryCardAssert01Payload>();
        check::<DirectoryCardAssert01Response>();
        check::<DirectoryEntriesList02Payload>();
        check::<DirectoryEntriesList02Response>();
        check::<DirectoryEntriesShow01Payload>();
        check::<DirectoryEntriesShow01Response>();
        check::<DirectoryCardShow01Payload>();
        check::<DirectoryCardShow01Response>();
        check::<DirectoryCardUpdate01Payload>();
        check::<DirectoryCardUpdate01Response>();
        check::<DirectoryDisclosure01Payload>();
        check::<DirectoryDisclosure01Response>();
        check::<DirectoryImagesUpload01Payload>();
        check::<DirectoryImagesUpload01Response>();
        check::<DirectoryImagesGet01Payload>();
        check::<DirectoryImagesGet01Response>();
        check::<DirectoryCardPublish01Payload>();
        check::<DirectoryCardPublish01Response>();
        check::<DirectoryCardPublic01Payload>();
        check::<DirectoryCardPublic01Response>();
        check::<GroupsCreate01Payload>();
        check::<GroupsCreate01Response>();
        check::<GroupsUpdate01Payload>();
        check::<GroupsUpdate01Response>();
        check::<GroupsDelete01Payload>();
        check::<GroupsDelete01Response>();
        check::<GroupsList02Payload>();
        check::<GroupsList02Response>();
        check::<GroupsShow01Payload>();
        check::<GroupsShow01Response>();
        check::<GroupsMembersAdd01Payload>();
        check::<GroupsMembersAdd01Response>();
        check::<GroupsMembersRemove01Payload>();
        check::<GroupsMembersRemove01Response>();
        check::<GroupsMembersList02Payload>();
        check::<GroupsMembersList02Response>();
        check::<GroupsJoin01Payload>();
        check::<GroupsJoin01Response>();
        check::<GroupsLeave01Payload>();
        check::<GroupsLeave01Response>();
        check::<BoardsCreate01Payload>();
        check::<BoardsCreate01Response>();
        check::<BoardsUpdate01Payload>();
        check::<BoardsUpdate01Response>();
        check::<BoardsDelete01Payload>();
        check::<BoardsDelete01Response>();
        check::<BoardsFacilitatorsAdd01Payload>();
        check::<BoardsFacilitatorsAdd01Response>();
        check::<BoardsFacilitatorsRemove01Payload>();
        check::<BoardsFacilitatorsRemove01Response>();
        check::<BoardsFacilitatorsList01Payload>();
        check::<BoardsFacilitatorsList01Response>();
        check::<BoardsList01Payload>();
        check::<BoardsList01Response>();
        check::<BoardsShow01Payload>();
        check::<BoardsShow01Response>();
        check::<BoardsIdeasPropose01Payload>();
        check::<BoardsIdeasPropose01Response>();
        check::<BoardsIdeasUpdate01Payload>();
        check::<BoardsIdeasUpdate01Response>();
        check::<BoardsIdeasWithdraw01Payload>();
        check::<BoardsIdeasWithdraw01Response>();
        check::<BoardsIdeasDecide01Payload>();
        check::<BoardsIdeasDecide01Response>();
        check::<BoardsIdeasSelect01Payload>();
        check::<BoardsIdeasSelect01Response>();
        check::<BoardsNotesAdd01Payload>();
        check::<BoardsNotesAdd01Response>();
        check::<BoardsNotesList01Payload>();
        check::<BoardsNotesList01Response>();
        check::<BoardsNotesWithdraw01Payload>();
        check::<BoardsNotesWithdraw01Response>();
        check::<BoardsNotesHide01Payload>();
        check::<BoardsNotesHide01Response>();
        check::<BadgesSettingsShow01Payload>();
        check::<BadgesSettingsShow01Response>();
        check::<BadgesSettingsUpdate01Payload>();
        check::<BadgesSettingsUpdate01Response>();
        check::<BadgesCreate01Payload>();
        check::<BadgesCreate01Response>();
        check::<BadgesUpdate01Payload>();
        check::<BadgesUpdate01Response>();
        check::<BadgesRetire01Payload>();
        check::<BadgesRetire01Response>();
        check::<BadgesPromote01Payload>();
        check::<BadgesPromote01Response>();
        check::<BadgesList01Payload>();
        check::<BadgesList01Response>();
        check::<BadgesShow01Payload>();
        check::<BadgesShow01Response>();
        check::<BadgesImagesUpload01Payload>();
        check::<BadgesImagesUpload01Response>();
        check::<BadgesImagesGet01Payload>();
        check::<BadgesImagesGet01Response>();
        check::<BadgesAwardsOffer01Payload>();
        check::<BadgesAwardsOffer01Response>();
        check::<BadgesAwardsWithdraw01Payload>();
        check::<BadgesAwardsWithdraw01Response>();
        check::<BadgesAwardsRevoke01Payload>();
        check::<BadgesAwardsRevoke01Response>();
        check::<BadgesClaimsCreate01Payload>();
        check::<BadgesClaimsCreate01Response>();
        check::<BadgesClaimsList01Payload>();
        check::<BadgesClaimsList01Response>();
        check::<BadgesClaimsWithdraw01Payload>();
        check::<BadgesClaimsWithdraw01Response>();
        check::<BadgesClaimsRedeem01Payload>();
        check::<BadgesClaimsRedeem01Response>();
        check::<BadgesAwardsShare01Payload>();
        check::<BadgesAwardsShare01Response>();
        check::<BadgesAwardsUnshare01Payload>();
        check::<BadgesAwardsUnshare01Response>();
        check::<BadgesAwardsList01Payload>();
        check::<BadgesAwardsList01Response>();
        check::<BadgesHoldersList01Payload>();
        check::<BadgesHoldersList01Response>();
        check::<BadgesWallShow01Payload>();
        check::<BadgesWallShow01Response>();
        check::<BadgesMineList01Payload>();
        check::<BadgesMineList01Response>();
        check::<BadgesMineAccept01Payload>();
        check::<BadgesMineAccept01Response>();
        check::<BadgesMineDecline01Payload>();
        check::<BadgesMineDecline01Response>();
        check::<BadgesMineHide01Payload>();
        check::<BadgesMineHide01Response>();
        check::<BadgesMineShow01Payload>();
        check::<BadgesMineShow01Response>();
        check::<BadgesMineArrange01Payload>();
        check::<BadgesMineArrange01Response>();
        check::<BadgesKudosGive01Payload>();
        check::<BadgesKudosGive01Response>();
        check::<BadgesKudosList01Payload>();
        check::<BadgesKudosList01Response>();
        check::<GroupsRequestsList02Payload>();
        check::<GroupsRequestsList02Response>();
        check::<GroupsRequestsDecide01Payload>();
        check::<GroupsRequestsDecide01Response>();
        check::<GroupsManagersAdd01Payload>();
        check::<GroupsManagersAdd01Response>();
        check::<GroupsManagersRemove01Payload>();
        check::<GroupsManagersRemove01Response>();
        check::<DirectoryCardPresent01Payload>();
        check::<DirectoryCardPresent01Response>();
        check::<DirectoryNotesAppend01Payload>();
        check::<DirectoryNotesAppend01Response>();
        check::<DirectoryNotesList02Payload>();
        check::<DirectoryNotesList02Response>();
        check::<DirectoryNotesExport01Payload>();
        check::<DirectoryNotesExport01Response>();
        check::<DirectoryExport02Payload>();
        check::<DirectoryExport02Response>();
    }

    #[test]
    fn a_rendered_schema_keeps_the_specifications_bounds() {
        let mut components = Vec::new();
        VetterList01Response::schemas(&mut components);
        let listed = components
            .iter()
            .find(|(n, _)| n == "VtcVettingVettersListV0_1ListedVetter")
            .map(|(_, s)| serde_json::to_value(s).unwrap())
            .expect("ListedVetter is a component");
        assert_eq!(listed["additionalProperties"], false);
        assert!(
            listed["required"]
                .as_array()
                .unwrap()
                .contains(&Value::from("vetterDid"))
        );
        assert_eq!(listed["properties"]["languages"]["maxItems"], 16);
        assert_eq!(listed["properties"]["vetterDid"]["pattern"], "^did:");

        let root = serde_json::to_value(VetterGrant01Payload::schema()).unwrap();
        assert_eq!(root["properties"]["validitySeconds"]["minimum"], 86_400);
        assert_eq!(root["required"], serde_json::json!(["memberDid"]));
    }

    #[test]
    fn a_wrapper_is_invisible_on_the_wire() {
        let json = serde_json::json!({ "memberDid": "did:key:zCarol" });
        let wrapped: VetterGrant01Payload = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(wrapped.member_did.as_str(), "did:key:zCarol");
        assert_eq!(serde_json::to_value(&wrapped).unwrap(), json);
    }
}
