//! What this bridge knows about working with a community, for the assistant
//! on the other end of the pipe: the operator guides, served as resources,
//! and one prompt per multi-step workflow.
//!
//! The guides are the workspace's own `docs/03-vtc/*.md`, embedded at build
//! time — one source of truth, pinned to the binary's own version, never a
//! second description of the community. A prompt is short and procedural: the
//! preconditions to check, the tasks to send in order, which of them park on
//! the action list for other administrators, and what the member sees
//! afterwards. It links the guide rather than restating it.
//!
//! Every task a prompt names must be a slug this bridge pins
//! (`every_slug_a_prompt_names_is_pinned`), so a prompt cannot send the
//! assistant after an operation `vtc_call` would refuse.

use serde_json::Value;

/// One operator guide, embedded.
pub struct Guide {
    /// The resource topic: `vtc://guide/<topic>`.
    pub topic: &'static str,
    /// A short name for the resource list.
    pub title: &'static str,
    /// Where it came from, for the reader.
    pub source: &'static str,
    /// The guide, as written.
    pub text: &'static str,
}

/// The guides, in the order the resource list shows them.
pub const GUIDES: &[Guide] = &[
    Guide {
        topic: "groups",
        title: "Community groups",
        source: "docs/03-vtc/groups.md",
        text: include_str!("../../docs/03-vtc/groups.md"),
    },
    Guide {
        topic: "boards",
        title: "Community boards",
        source: "docs/03-vtc/boards.md",
        text: include_str!("../../docs/03-vtc/boards.md"),
    },
    Guide {
        topic: "elections",
        title: "Elections, polls and surveys",
        source: "docs/03-vtc/elections.md",
        text: include_str!("../../docs/03-vtc/elections.md"),
    },
    Guide {
        topic: "rooms",
        title: "Community-owned data rooms",
        source: "docs/03-vtc/community-rooms.md",
        text: include_str!("../../docs/03-vtc/community-rooms.md"),
    },
    Guide {
        topic: "rooms-quickstart",
        title: "Data rooms, end to end",
        source: "docs/03-vtc/data-rooms-quickstart.md",
        text: include_str!("../../docs/03-vtc/data-rooms-quickstart.md"),
    },
    Guide {
        topic: "admission",
        title: "Join criteria",
        source: "docs/03-vtc/join-criteria.md",
        text: include_str!("../../docs/03-vtc/join-criteria.md"),
    },
    Guide {
        topic: "lifecycle",
        title: "Membership lifecycle",
        source: "docs/03-vtc/community-lifecycle.md",
        text: include_str!("../../docs/03-vtc/community-lifecycle.md"),
    },
    Guide {
        topic: "vetting",
        title: "Vetting",
        source: "docs/03-vtc/vetting.md",
        text: include_str!("../../docs/03-vtc/vetting.md"),
    },
    Guide {
        topic: "directory",
        title: "Member directory",
        source: "docs/03-vtc/member-directory.md",
        text: include_str!("../../docs/03-vtc/member-directory.md"),
    },
    Guide {
        topic: "admin-access",
        title: "Administrators, roles and consent",
        source: "docs/03-vtc/admin-access.md",
        text: include_str!("../../docs/03-vtc/admin-access.md"),
    },
    Guide {
        topic: "badges",
        title: "Member badges",
        source: "docs/03-vtc/badges.md",
        text: include_str!("../../docs/03-vtc/badges.md"),
    },
];

/// The resource URI prefix every guide sits under.
pub const GUIDE_URI_PREFIX: &str = "vtc://guide/";

/// The resource URI of a guide topic.
pub fn guide_uri(topic: &str) -> String {
    format!("{GUIDE_URI_PREFIX}{topic}")
}

/// The guide at `uri`, when it is one.
pub fn guide_at(uri: &str) -> Option<&'static Guide> {
    let topic = uri.strip_prefix(GUIDE_URI_PREFIX)?;
    GUIDES.iter().find(|g| g.topic == topic)
}

/// One step of a workflow.
pub struct Step {
    /// The task's slug (no prefix, no version): what `vtc_list_operations`
    /// is asked for.
    pub task: &'static str,
    /// What it does here and what to put in it.
    pub what: &'static str,
    /// When set, the community parks this step on its action list for other
    /// administrators, and the text says who approves.
    pub parks: Option<&'static str>,
}

/// One argument a prompt takes, all optional: what the operator already
/// knows, folded into the brief.
pub struct Argument {
    pub name: &'static str,
    pub description: &'static str,
}

/// One workflow, as a prompt.
pub struct Workflow {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    /// Who must hold what, and what must be configured, before step 1.
    pub preconditions: &'static [&'static str],
    pub steps: &'static [Step],
    /// What the member on the other side sees, and does.
    pub afterwards: &'static [&'static str],
    /// Guide topics to read first.
    pub guides: &'static [&'static str],
    pub arguments: &'static [Argument],
}

/// The workflows, in the order the prompt list shows them.
pub const WORKFLOWS: &[Workflow] = &[
    Workflow {
        name: "setup-group",
        title: "Set up a community group",
        description: "Create a group, appoint its managers, decide how members get in, and \
                      optionally bind it to a room or to capabilities.",
        preconditions: &[
            "The community has `[groups]` configured and a link to its VTA; without them \
             `vtc/groups/create` is refused `noKeyHolder` naming what to add.",
            "You hold `vtc.groups.manage` (in the `community-admin` ceiling) to create a \
             group and to manage every group; a manager appointed to one group holds it \
             for that group only.",
        ],
        steps: &[
            Step {
                task: "vtc/groups/list",
                what: "See the groups that exist, so a new one does not duplicate a name.",
                parks: None,
            },
            Step {
                task: "vtc/groups/create",
                what: "Create it: `name`, `kind` (`static`, or `dynamic` with a `rule` over \
                       verified facts), `visibility` and `showMembers` (`admins`, \
                       `groupMembers` or `members`), for a static group a `joinPolicy` \
                       (`closed`: managers add; `request`: members ask, managers decide; \
                       `open`: members join), `issuesCredentials` if members should get a \
                       group credential, and a `reason`. The community's VTA mints the \
                       group's DID and the community authorises it; the group is recorded \
                       only after both succeed.",
                parks: None,
            },
            Step {
                task: "vtc/groups/managers/add",
                what: "Appoint the group's managers by DID: a resource grant for that one \
                       group on their entry, delegated by you. A manager needs no \
                       administrative role.",
                parks: None,
            },
            Step {
                task: "vtc/groups/members/add",
                what: "For a `closed` static group, add the first members by DID. Where the \
                       group issues credentials the VTA signs each member a membership \
                       credential, as the group, before the membership is recorded. For a \
                       `request` group, read `vtc/groups/requests/list` and decide each with \
                       `vtc/groups/requests/decide`; for an `open` group members join \
                       themselves with `vtc/groups/join`.",
                parks: Some(
                    "only when the group carries authority (a `grants` or `role` binding): \
                     then adding a member is granting them that authority, and another \
                     administrator who holds it approves",
                ),
            },
            Step {
                task: "vtc/groups/bindings/add",
                what: "Optional. Bind a community-owned room (`kind: room`, with the \
                       `actions` and `validFor` every member is offered; takes \
                       `vtc.rooms.manage` and your bound step-up), or make the group carry \
                       authority with a `grants` or `role` binding — only a `closed` group \
                       may, and it stays closed while it does.",
                parks: Some(
                    "for a `grants` or `role` binding: binding a capability is granting it, \
                     so another administrator who holds it approves (VTI-DIR-104); a room \
                     binding never parks",
                ),
            },
            Step {
                task: "vtc/groups/show",
                what: "Read the group back: members, managers, bindings, and when its \
                       authority credential lapses (shown to managers).",
                parks: None,
            },
        ],
        afterwards: &[
            "Members see the group in the directory where `visibility` admits them, and in \
             the member portal; a member of an `open` or `request` group can leave with \
             `vtc/groups/leave`.",
            "A member of a credential-issuing group holds a group credential that renews \
             while they stay and lapses at its expiry when they leave.",
            "A manager whose appointer leaves the community has the appointment put to \
             review on the action list (`acl.grants.review`).",
        ],
        guides: &["groups", "admin-access"],
        arguments: &[
            Argument {
                name: "name",
                description: "The group's name, if decided.",
            },
            Argument {
                name: "purpose",
                description: "What the group is for, in the operator's words.",
            },
        ],
    },
    Workflow {
        name: "create-board",
        title: "Create a community board",
        description: "Open a board where members propose ideas and each accepted idea is put \
                      to a vote, appoint its facilitators, and run it to selection.",
        preconditions: &[
            "The community is built with `voting` and has `[voting]` configured with at \
             least one trusted ballot box; otherwise every template is refused \
             `templateInvalid`.",
            "Creating a board takes `vtc.boards.manage` **and** `vtc.elections.manage`, \
             both unqualified. A facilitator needs only `vtc.boards.manage` for that board.",
        ],
        steps: &[
            Step {
                task: "vtc/elections/ballot-boxes/list",
                what: "Read the trusted ballot boxes; the board's election template names one.",
                parks: None,
            },
            Step {
                task: "vtc/boards/create",
                what: "Create the board: title, `audience` (`members`, or one group), the \
                       proposal window and the voting window, optional topics, formats, a \
                       limit on ideas per member, the selection rule in plain words, an \
                       optional timetable of slots, and the election `template` — the \
                       question each idea's election asks, its secrecy, revote rule, board \
                       visibility and ballot box. The template is checked as \
                       `vtc/elections/create` checks a manifest, and every board election \
                       allows closing early.",
                parks: None,
            },
            Step {
                task: "vtc/boards/facilitators/add",
                what: "Appoint facilitators by DID: active members, no administrative role \
                       needed; the appointment is a grant for that one board on their entry, \
                       naming you as appointer. `vtc/boards/facilitators/list` shows them.",
                parks: None,
            },
            Step {
                task: "vtc/boards/show",
                what: "Read it back. From here members propose (`vtc/boards/ideas/propose`) \
                       and leave notes (`vtc/boards/notes/add`) while the proposal window is \
                       open.",
                parks: None,
            },
            Step {
                task: "vtc/boards/ideas/decide",
                what: "As a facilitator, accept, decline (with a reason the audience sees) or \
                       merge each idea. Accepting opens the idea's election at the ballot box \
                       from the template; it stays `proposed` until the ballot box registers \
                       it. A facilitator does not decide their own idea while the board has \
                       another facilitator.",
                parks: None,
            },
            Step {
                task: "vtc/boards/ideas/select",
                what: "Once voting closes, select (or not) each idea, optionally into a \
                       timetable slot, with the verified result in view. A selection that \
                       departs from the board's rule needs a reason.",
                parks: None,
            },
            Step {
                task: "vtc/boards/update",
                what: "Change the board while it runs (title, windows, topics, limit, rule, \
                       timetable; the audience and voting window are fixed once voting \
                       opens), and close it: `closed` takes no new ideas and ends the voting \
                       on every idea — an election open for voting is closed early and \
                       counted as it stands; one not yet open is cancelled. `archived` hides \
                       it. `vtc/boards/delete` removes a closed board whose elections have \
                       all ended, with a bound step-up.",
                parks: None,
            },
        ],
        afterwards: &[
            "Members propose, edit and withdraw their own ideas and notes from the portal, \
             and vote on each accepted idea from their wallet: the ballot goes from their \
             VTA to the ballot box, never through the community and never through this \
             bridge.",
            "A public board shows `ballotsOnBoard` while voting is open, never running \
             totals.",
        ],
        guides: &["boards", "elections"],
        arguments: &[
            Argument {
                name: "title",
                description: "The board's title, if decided.",
            },
            Argument {
                name: "audience",
                description: "`members`, or the group it is for.",
            },
        ],
    },
    Workflow {
        name: "run-election",
        title: "Run an election, poll or survey",
        description: "Create an election from a manifest, follow its registration and voting, \
                      and certify the result. A poll is a non-binding election.",
        preconditions: &[
            "The community has `[voting]` configured with the trusted ballot boxes it may \
             use (VTI-VOT-082).",
            "You hold `vtc.elections.manage`. Members take tickets and cast through their \
             own VTAs, never through the community.",
        ],
        steps: &[
            Step {
                task: "vtc/elections/ballot-boxes/list",
                what: "Read the trusted ballot boxes; the manifest names one.",
                parks: None,
            },
            Step {
                task: "vtc/elections/create",
                what: "Create it from a manifest: identifier, title, the questions and their \
                       options and bounds, who votes (`roll`: the community's members, one \
                       group, the holders of a membership credential of one DID, or a list), \
                       the schedule (registration, voting open and close, all ahead and in \
                       order), counting and secrecy, the ballot box, and `binding`. The \
                       community refuses an inconsistent manifest `invalidManifest`; read \
                       the schema with `vtc_list_operations` detail `full` first.",
                parks: Some(
                    "when `binding: true` — the result decides something in the \
                     community's name, so another holder of `vtc.elections.manage` \
                     approves after your bound step-up (VTI-VOT-081)",
                ),
            },
            Step {
                task: "vtc/elections/show",
                what: "Follow it: whether the ballot box has registered it, the schedule, the \
                       tickets issued, and later the result. `vtc/elections/list` lists them.",
                parks: None,
            },
            Step {
                task: "vtc/elections/close",
                what: "Close voting early, only where the manifest allows it; \
                       `vtc/elections/cancel` cancels, with a reason.",
                parks: None,
            },
            Step {
                task: "vtc/elections/certify",
                what: "Once the ballot box has tallied: the community reads the result, the \
                       head and every entry from the ballot box itself and re-verifies the \
                       whole board from its own voting key. Auditors' attestations may be \
                       attached beside it. A certified result authorizes nothing by itself.",
                parks: None,
            },
        ],
        afterwards: &[
            "A member the roll admits takes one ticket (`vtc/elections/tickets/issue`, \
             normally through their VTA) and casts to the ballot box from their wallet; \
             the community never sees a ballot.",
            "Under a credential roll, eligibility is proven at the claim, so a member who \
             joins after the election is called is admitted.",
            "A notified election appears in the member portal; a receipt can be checked \
             against the community's kept board heads with `vtc/elections/tombstones/show`.",
        ],
        guides: &["elections"],
        arguments: &[
            Argument {
                name: "question",
                description: "What is being asked, in the operator's words.",
            },
            Argument {
                name: "roll",
                description: "Who votes: members, a group, or a credential holder set.",
            },
        ],
    },
    Workflow {
        name: "open-data-room",
        title: "Open a community data room",
        description: "Create a room the community owns, offer members admission, and watch \
                      them join.",
        preconditions: &[
            "The community has `[rooms.community]` configured, a link to its VTA, and an \
             entry at that VTA covering the room's context with `key-mint`, \
             `credential-write`, `vault-write` and `room-open`; otherwise a create is \
             refused `noKeyHolder` or `keyHolderRefused` naming what to add.",
            "You hold `vtc.rooms.manage` (distinct from `vtc.rooms.admin`, which is hosting). \
             Creating, admitting and removing each take your bound step-up and never park.",
        ],
        steps: &[
            Step {
                task: "vtc/rooms/community/list",
                what: "See the rooms the community owns, their tiers and lifecycle, and when \
                       the community's own authority over each lapses.",
                parks: None,
            },
            Step {
                task: "vtc/rooms/community/create",
                what: "Create the room: `label`, optional description and tags, `tier` \
                       (`attributed` by default, or `open`; `private` is not served for \
                       community rooms), history (`chained` or `fromJoin`), retention days, \
                       a storage location where you hold `vtc.rooms.admin`, and a `reason`. \
                       The community's VTA mints the room's DID, founds its group and issues \
                       the community's own credentials before the room is recorded.",
                parks: None,
            },
            Step {
                task: "vtc/rooms/community/members/add",
                what: "Offer a member admission by DID: `actions` (`read`, `write`, \
                       `curate`), how many days it is valid, and a reason. An offer is \
                       recorded only after the VTA issued its credentials. To admit a whole \
                       group instead, bind it with `vtc/groups/bindings/add` (`kind: room`).",
                parks: None,
            },
            Step {
                task: "vtc/rooms/community/members/list",
                what: "See who is offered, admitted or removed. `vtc/rooms/community/get` \
                       reads one room; `vtc/rooms/community/update` changes its details.",
                parks: None,
            },
            Step {
                task: "vtc/rooms/community/members/remove",
                what: "Remove a member, or withdraw an open offer, with a reason. On a \
                       sealed tier the answer says from which epoch the member is out. \
                       `vtc/rooms/community/archive` and `vtc/rooms/community/remove` are \
                       the room's own lifecycle.",
                parks: None,
            },
        ],
        afterwards: &[
            "The member reads their offers with `vtc/rooms/offers/list`, stores the \
             credentials in their own VTA's vault, mints a key package there for a sealed \
             room, and accepts with `vtc/rooms/offers/accept`; the community's VTA adds them \
             to the group and answers with the Welcome their VTA processes.",
            "`vtc/rooms/memberships/list`, signed as the member, is the one record every \
             surface (portal, `pnm`, OpenVTC) shows of where each admission stands.",
            "The community renews its own authority over the room before it lapses; a \
             member admitted through a group binding is renewed into the offers' `renewals`.",
        ],
        guides: &["rooms", "rooms-quickstart", "groups"],
        arguments: &[
            Argument {
                name: "label",
                description: "The room's label, if decided.",
            },
            Argument {
                name: "members",
                description: "Who should be admitted: DIDs, or a group.",
            },
        ],
    },
    Workflow {
        name: "admit-member",
        title: "Admit a member",
        description: "Decide a join request, or admit someone directly, and see what they \
                      hold afterwards.",
        preconditions: &[
            "Deciding a join request takes `vtc.join.decide`; admitting directly takes \
             `vtc.members.manage`, and a role other than `member` takes `vtc.roles.assign` \
             too. `admin` is never seated by admission: admit, then promote.",
            "Read what applicants must meet with `vtc/schemas/accepts/list`; changing a \
             criterion (`vtc/schemas/accepts/register`, `vtc/schemas/accepts/delete`) is a \
             change to who may join and parks for the other holders of `vtc.surface.admin`.",
        ],
        steps: &[
            Step {
                task: "vtc/join-requests/list",
                what: "The review queue: list pending requests (`status: pending`), then \
                       read one with `vtc/join-requests/show` — what the applicant \
                       presented and which criterion it met.",
                parks: None,
            },
            Step {
                task: "vtc/join-requests/decide",
                what: "Approve or reject it. An approval allocates a revocation slot, writes \
                       the ACL entry and member record, issues the membership credential and \
                       role credential, and delivers them to the member's wallet.",
                parks: None,
            },
            Step {
                task: "vtc/members/admit",
                what: "Or admit directly, without a join request: `subject` DID, `role` \
                       (default `member`), an optional `label` and a `reason`. It skips the \
                       criteria and vetting, so the community's `admission` policy decides \
                       whether now. A former member is re-admitted as returning.",
                parks: Some(
                    "when the `admission` policy answers `refer`: another holder of \
                     `vtc.members.manage` approves, never the requester or the subject",
                ),
            },
            Step {
                task: "vtc/members/make-membership",
                what: "For an ACL entry with no member record — typically the bootstrap \
                       administrator — write the record and issue the credentials at the \
                       role the entry already holds. `admit` refuses `hasEntry` when this \
                       is the right task, and names it.",
                parks: Some("as `vtc/members/admit`, when the policy answers `refer`"),
            },
            Step {
                task: "vtc/members/credentials",
                what: "Read what the member now holds; `vtc/members/list` lists members by \
                       role. Promote later with `vtc/members/role/set`, which takes its own \
                       step-up and consent.",
                parks: None,
            },
        ],
        afterwards: &[
            "The new member signs in to the member portal with their wallet, appears in the \
             directory, and can take part in groups, boards, rooms and elections their \
             standing admits.",
            "Removal is `vtc/members/admin-remove`, a reduction that parks for another \
             administrator when the member holds administrative authority.",
        ],
        guides: &["lifecycle", "admission", "vetting"],
        arguments: &[
            Argument {
                name: "subject",
                description: "The applicant's or member's DID, if known.",
            },
            Argument {
                name: "role",
                description: "The role to seat, default `member`.",
            },
        ],
    },
    Workflow {
        name: "create-badge",
        title: "Create a member badge",
        description: "Define a community or kudos badge with its picture, then give it: \
                      offer it to members or a group, let members ask, give it by a rule, or \
                      hand out a claim code at an event.",
        preconditions: &[
            "Badges are on (`vtc/badges/settings/show`); otherwise every badge task is \
             refused `badgesOff`. Turning them on is `vtc/badges/settings/update`.",
            "Defining a community badge takes `vtc.badges.admin`; a kudos badge, any \
             active member the settings admit. A community badge is backed by a badge group \
             whose DID the community's VTA mints, so the community needs `[groups]` and its \
             VTA link, as a group does.",
            "A badge that may be shown outside the community needs the community's public \
             location; its picture and description are then public, its holders never.",
        ],
        steps: &[
            Step {
                task: "vtc/badges/images/upload",
                what: "Upload the picture (`mediaType`, base64 `data`). The community \
                       re-encodes it and answers its digest; `vtc/badges/create` names the \
                       picture by that digest.",
                parks: None,
            },
            Step {
                task: "vtc/badges/create",
                what: "Create it: `kind` (`community`: owners give it, backed by a badge \
                       group, an Open Badges 3.0 credential per holder; `kudos`: any member \
                       gives it, no credential), `name`, `description`, `image`, `reason`, and \
                       for a community badge its `owners`, `criteria`, `requestable`, \
                       `repeatable`, `shareableOutside`, or `automatic` with a rule (which may \
                       count `kudosReceived`, `ideasSelected`, `electionTickets`). \
                       `vtc/badges/promote` makes a kudos badge a community one later, \
                       creating its group.",
                parks: None,
            },
            Step {
                task: "vtc/badges/awards/offer",
                what: "Offer it to members by entry id (`to`) or to a `group`. An offer is \
                       not a holding: nothing is issued until the member accepts. A \
                       `requestable` badge is asked for with `vtc/groups/join` on its group \
                       and decided with `vtc/groups/requests/decide`.",
                parks: None,
            },
            Step {
                task: "vtc/badges/claims/create",
                what: "Optional, for an event: a claim code with a `label`, `validUntil` (at \
                       most 90 days ahead) and a `limit`. The code is answered once and never \
                       again; `vtc/badges/claims/list` shows its claims, \
                       `vtc/badges/claims/withdraw` stops it.",
                parks: None,
            },
            Step {
                task: "vtc/badges/show",
                what: "Read it back; `vtc/badges/holders/list` lists who holds it.",
                parks: None,
            },
        ],
        afterwards: &[
            "A member sees an offer on the badges page of the member portal and accepts or \
             declines it; an accepted community badge's credential is issued by the badge \
             group and offered to their wallet.",
            "Taking an award back is `vtc/badges/awards/revoke`; retiring the badge is \
             `vtc/badges/retire`, which revokes every credential its group issued and \
             withdraws its claim codes.",
        ],
        guides: &["badges", "groups"],
        arguments: &[
            Argument {
                name: "name",
                description: "The badge's name, if decided.",
            },
            Argument {
                name: "kind",
                description: "`community` or `kudos`.",
            },
        ],
    },
    Workflow {
        name: "my-badges",
        title: "Your badges",
        description: "As a member: accept or decline what you were offered, arrange and hide \
                      your wall, redeem a claim code, show an award outside, give kudos.",
        preconditions: &[
            "This is the member's own wall, so sign in as the member (`vtc_sign_in`, a member \
             sign-in); an administrator's identity sees its own badges, not anyone else's.",
            "Badges are on in the community (`vtc/badges/settings/show`).",
        ],
        steps: &[
            Step {
                task: "vtc/badges/mine/list",
                what: "What you hold and what you were offered, with each award's state.",
                parks: None,
            },
            Step {
                task: "vtc/badges/mine/accept",
                what: "Accept an offer: it becomes a holding, and for a community badge the \
                       credential is issued and offered to your wallet. \
                       `vtc/badges/mine/decline` refuses it instead.",
                parks: None,
            },
            Step {
                task: "vtc/badges/claims/redeem",
                what: "Enter a claim code from an event: redeeming is your consent, and you \
                       hold the badge at once.",
                parks: None,
            },
            Step {
                task: "vtc/badges/mine/arrange",
                what: "Order and pin your wall. `vtc/badges/mine/hide` takes a holding off \
                       your wall, the holder list and the counts — hidden is portal-only, and \
                       the badge's owners still see you as a hidden holder; \
                       `vtc/badges/mine/show` puts it back.",
                parks: None,
            },
            Step {
                task: "vtc/badges/awards/share",
                what: "Show a community badge outside the community, where it allows: the \
                       community serves your credential at a link you hand out, until \
                       `vtc/badges/awards/unshare`.",
                parks: None,
            },
            Step {
                task: "vtc/badges/kudos/give",
                what: "Thank another member with a kudos badge (`badgeId`, `to`, an optional \
                       `note`); they accept it like any offer.",
                parks: None,
            },
        ],
        afterwards: &[
            "Other members see your wall on your directory card, as you arranged it.",
            "Leaving a badge's group, or the community, ends the holding: a share stops and \
             the credential's status is revoked.",
        ],
        guides: &["badges"],
        arguments: &[Argument {
            name: "code",
            description: "A claim code to redeem, if the member has one.",
        }],
    },
    Workflow {
        name: "grant-administration",
        title: "Grant administration",
        description: "Give an entry an administrative role or capabilities, bounded by your \
                      own, with another administrator's consent.",
        preconditions: &[
            "You hold `vtc.roles.assign` and every capability you grant, at a resource at \
             least as wide; no grant outlives your own entry, and nobody grants themselves \
             anything (VTI-ACL-071).",
            "There is another administrator whose approve scope reaches what you grant: \
             every authority-conferring grant is a second-party action (VTI-APV-018). In \
             single-administrator mode your bound step-up stands in, audited `Critical`.",
        ],
        steps: &[
            Step {
                task: "acl/list",
                what: "Read the entries: each one's administrative role, what it administers \
                       and its community role; `acl/show` reads one with every axis stated.",
                parks: None,
            },
            Step {
                task: "vtc/roles/list",
                what: "The roles available: the built-in ceilings (`community-admin`, \
                       `moderator`, `vetting-lead`, `repo-manager`, `credential-officer`, \
                       `auditor`, `approver`) and the community's custom roles. Defining a \
                       custom role (`vtc/roles/define`) parks for holders of \
                       `vtc.roles.assign` and `vtc.approvals.admin`.",
                parks: None,
            },
            Step {
                task: "acl/grant",
                what: "Grant: `subject` DID, `role`, optionally a listed capability scope \
                       with resource qualifiers (`group:<id>`, `board:<id>`, `policy:join`, \
                       `git-ns:<forge>/<owner>`), an approve scope within your own, an \
                       expiry and a reason. A refusal names what exceeded you \
                       (`delegationExceedsGranter`, `capabilityOutsideCeiling`, \
                       `approveWiderThanGranter`).",
                parks: Some(
                    "when it confers authority: holders of the same capabilities at a \
                     covering resource approve, after your bound step-up; the entry is \
                     written on the approval, re-checked then",
                ),
            },
            Step {
                task: "vtc/members/role/set",
                what: "For an existing member, set their administrative role instead; \
                       `acl/update` narrows or widens an entry's capabilities and \
                       `acl/change-role` changes the role. Widening parks like a grant; \
                       narrowing or demoting another administrator parks as a reduction \
                       (VTI-APV-019), the subject excluded from approving.",
                parks: Some("as `acl/grant`, when authority is conferred or reduced"),
            },
            Step {
                task: "vtc/admin/invites/create",
                what: "For an administrator who has no DID yet, mint a passkey invitation \
                       instead: they claim it with a passkey, whose `did:key` becomes their \
                       entry.",
                parks: Some("always, as a grant of what the invitation confers"),
            },
            Step {
                task: "vtc/admin/actions/show",
                what: "Follow a parked action by the id the parked result named; \
                       `vtc/admin/actions/list` lists them. Another administrator approves \
                       with `task-consent/decision` signed by their own DID — from their \
                       console, wallet or `cnm`, or from a bridge whose entry holds approve \
                       authority. The requester never approves; one decline closes it.",
                parks: None,
            },
        ],
        afterwards: &[
            "An administrator made by a completed action is issued a step-up approver \
             enrolment invite automatically; the requester delivers its claim code by a \
             separate channel.",
            "When a granter leaves the community, the entries they granted go to review \
             (`acl.grants.review`) for the holders of `vtc.roles.assign`: re-affirmed under \
             the approver's own authority, or withdrawn.",
            "`acl/revoke` removes an entry's authority: a reduction, parked on the same \
             terms.",
        ],
        guides: &["admin-access"],
        arguments: &[
            Argument {
                name: "subject",
                description: "The DID to grant to, if known.",
            },
            Argument {
                name: "role",
                description: "The role or capabilities intended.",
            },
        ],
    },
];

/// The workflow named `name`.
pub fn workflow(name: &str) -> Option<&'static Workflow> {
    WORKFLOWS.iter().find(|w| w.name == name)
}

/// The prompt text for `workflow`, folding in whatever the operator already
/// said in `arguments`.
pub fn render(workflow: &Workflow, arguments: Option<&serde_json::Map<String, Value>>) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# {}\n\n{}\n\n",
        workflow.title, workflow.description
    ));

    let given: Vec<(&str, String)> = arguments
        .map(|args| {
            workflow
                .arguments
                .iter()
                .filter_map(|a| {
                    let value = args.get(a.name)?;
                    let text = match value {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    (!text.trim().is_empty()).then_some((a.name, text))
                })
                .collect()
        })
        .unwrap_or_default();
    if !given.is_empty() {
        out.push_str("## What the operator already said\n\n");
        for (name, value) in given {
            out.push_str(&format!("- {name}: {value}\n"));
        }
        out.push('\n');
    }

    out.push_str("## Before anything\n\n");
    for p in workflow.preconditions {
        out.push_str(&format!("- {p}\n"));
    }
    out.push_str(
        "- Ask `vtc_whoami` and `vtc_supported_tasks` first, and read each operation's \
         payload schema with `vtc_list_operations` (detail `full`) before calling it.\n\n",
    );

    out.push_str("## Steps, in order\n\n");
    for (i, step) in workflow.steps.iter().enumerate() {
        out.push_str(&format!("{}. `{}` — {}", i + 1, step.task, step.what));
        if let Some(parks) = step.parks {
            out.push_str(&format!(
                "\n   **Parks** {parks}. A `vtc_call` result with `status: \"parked\"` is \
                 not a failure: do not resend; follow the named action with \
                 `vtc/admin/actions/show`."
            ));
        }
        out.push('\n');
    }
    out.push('\n');

    out.push_str("## Afterwards\n\n");
    for a in workflow.afterwards {
        out.push_str(&format!("- {a}\n"));
    }
    out.push('\n');

    out.push_str("## Read first\n\n");
    for topic in workflow.guides {
        if let Some(g) = GUIDES.iter().find(|g| g.topic == *topic) {
            out.push_str(&format!(
                "- `{}` — {} ({})\n",
                guide_uri(topic),
                g.title,
                g.source
            ));
        }
    }
    out.push_str(
        "\nRules: every call is one signed Trust Task sent as this bridge's identity, and \
         the community decides; this bridge's own policy may refuse or ask the operator to \
         confirm a step. Report a refusal with the community's code and message, never \
         retry a parked or refused step on your own, and never put a member's personal \
         text (a label, a note) in a log or summary beyond what the task needs.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Every slug that is pinned, with no prefix and no version.
    fn pinned_slugs() -> BTreeSet<&'static str> {
        vti_specs::schema_index::type_uris()
            .filter(|uri| !uri.contains('#'))
            .filter_map(vti_mcp_common::guard::slug_of)
            .collect()
    }

    /// The slugs a prompt names, in its steps and in backticks anywhere in
    /// its text.
    fn slugs_named(workflow: &Workflow) -> BTreeSet<String> {
        let mut out: BTreeSet<String> = workflow.steps.iter().map(|s| s.task.to_string()).collect();
        let text = render(workflow, None);
        for token in text.split('`').skip(1).step_by(2) {
            let is_slug = token.split_once('/').is_some_and(|(family, rest)| {
                matches!(family, "vtc" | "acl" | "task-consent" | "rooms" | "policy")
                    && !rest.is_empty()
                    && rest.chars().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || c == '/' || c == '-'
                    })
            });
            if is_slug {
                out.insert(token.to_string());
            }
        }
        out
    }

    /// A prompt may not send the assistant after an operation `vtc_call`
    /// would refuse: every task it names, in a step or in passing, is pinned.
    #[test]
    fn every_slug_a_prompt_names_is_pinned() {
        let pinned = pinned_slugs();
        let mut missing = Vec::new();
        for w in WORKFLOWS {
            for slug in slugs_named(w) {
                if !pinned.contains(slug.as_str()) {
                    missing.push(format!("{}: {slug}", w.name));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "prompts name unpinned tasks:\n{}",
            missing.join("\n")
        );
    }

    #[test]
    fn every_prompt_reads_a_guide_that_exists_and_guides_are_real() {
        for w in WORKFLOWS {
            assert!(!w.guides.is_empty(), "{} names no guide", w.name);
            for topic in w.guides {
                assert!(
                    GUIDES.iter().any(|g| g.topic == *topic),
                    "{} names an unknown guide {topic}",
                    w.name
                );
            }
            assert!(!w.steps.is_empty() && !w.preconditions.is_empty());
        }
        for g in GUIDES {
            assert!(
                g.text.starts_with("# "),
                "{} does not start with a heading",
                g.source
            );
            assert!(g.text.len() > 1000, "{} is suspiciously short", g.source);
            assert_eq!(
                guide_at(&guide_uri(g.topic)).map(|g| g.topic),
                Some(g.topic)
            );
        }
        assert!(guide_at("vtc://guide/nope").is_none());
        assert!(guide_at("vtc://status").is_none());
    }

    #[test]
    fn names_are_unique_and_the_workflows_are_there() {
        let names: BTreeSet<&str> = WORKFLOWS.iter().map(|w| w.name).collect();
        assert_eq!(names.len(), WORKFLOWS.len());
        for expected in [
            "setup-group",
            "create-board",
            "run-election",
            "open-data-room",
            "admit-member",
            "grant-administration",
            "create-badge",
            "my-badges",
        ] {
            assert!(workflow(expected).is_some(), "missing {expected}");
        }
        let topics: BTreeSet<&str> = GUIDES.iter().map(|g| g.topic).collect();
        assert_eq!(topics.len(), GUIDES.len());
    }

    #[test]
    fn rendering_folds_in_what_the_operator_said_and_marks_parked_steps() {
        let w = workflow("grant-administration").unwrap();
        let mut args = serde_json::Map::new();
        args.insert("subject".into(), Value::String("did:key:zAlice".into()));
        args.insert("ignored".into(), Value::String("not an argument".into()));
        let text = render(w, Some(&args));
        assert!(text.contains("- subject: did:key:zAlice"));
        assert!(!text.contains("not an argument"));
        assert!(text.contains("**Parks**"));
        assert!(text.contains("`vtc://guide/admin-access`"));
        let plain = render(w, None);
        assert!(!plain.contains("What the operator already said"));
    }
}
