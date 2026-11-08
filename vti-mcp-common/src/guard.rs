//! What a bridge is *allowed* to do, independent of what its node identity
//! could do.
//!
//! The node — a VTA or a VTC — is the authority: every call is gated
//! server-side on the bridge identity's role, ACL, scope or capabilities and
//! — where enabled — the approvals policy. This module is a **second, local**
//! gate in front of it, and it exists because of a specific gap in how MCP
//! hosts grant permission.
//!
//! A host approves a *tool*, not a *call*. Once an operator answers "always
//! allow" to the generic `vta_call` / `vtc_call`, every Trust Task URI the
//! node serves is reachable with no further prompt — `contexts/delete/1.1` on
//! the same approval as `contexts/list/1.0`. The host cannot tell those apart;
//! it sees one tool name. So the per-operation decision has to be made here,
//! where the URI is known.
//!
//! One table serves every bridge. A slug is a slug whichever node serves it,
//! and a placement decided for one bridge (`acl/grant` moves authority) is
//! the same decision for the other; the census tests hold every pinned
//! request URI, and every URI a bridge can dispatch, to a classified verb.
//!
//! Three mechanisms, cheapest first:
//!
//! 1. **Risk classification** ([`Risk`]) — every Trust Task URI is read-only,
//!    mutating, sensitive, or destructive. Unknown verbs classify as
//!    [`Risk::Mutating`], never read-only: a URI this build has never heard of
//!    must not slip through `--read-only`.
//! 2. **Allow / deny globs** — operator-supplied slug patterns. Deny always
//!    wins; a non-empty allow list makes everything else denied.
//! 3. **Confirmation** — the risky tail is put back in front of a human via MCP
//!    elicitation, restoring per-call consent the host's per-tool approval gave
//!    away.
//!
//! The convenience tools route through the same gate under their canonical URI
//! (`sign` → `keys/sign/0.1`), so `--read-only` cannot be walked around by
//! calling `sign` instead of `vta_call`.

use std::fmt;

/// The Trust Task URI prefix every catalog entry carries. Patterns are written
/// against the **slug** — the part after this — so an operator types
/// `acl/*`, not the full URI.
pub const SPEC_PREFIX: &str = "https://trusttasks.org/spec/";

/// How much damage an operation can do, judged from the URI alone.
///
/// Deliberately coarse. This is a gate on *shape*, not a policy engine — the
/// VTA holds the policy engine, and duplicating it here would be a second
/// source of truth that drifts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Risk {
    /// Reads state. Safe to call on a whim; the only class `--read-only`
    /// permits.
    ReadOnly,
    /// Changes state additively and reversibly (create, update, register).
    Mutating,
    /// Exercises key authority, emits secret material, or moves authority
    /// between principals. Not destructive — but a compromised host calling
    /// these is the whole threat model.
    Sensitive,
    /// Removes something, or removes someone's access. Irreversible, or
    /// reversible only by an operator with more authority than the bridge.
    Destructive,
}

impl Risk {
    /// The lowercase name used in logs, audit records and the `vta_status`
    /// tool. Stable — external log processing keys on it.
    pub fn label(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::Mutating => "mutating",
            Self::Sensitive => "sensitive",
            Self::Destructive => "destructive",
        }
    }

    /// What a tool wrapping an operation of this class must declare as its MCP
    /// `readOnlyHint` / `destructiveHint`. Hosts render both and some gate on
    /// them, so a tool whose annotation disagrees with its operation's class is
    /// a security bug rather than a cosmetic one — which is what each bridge's
    /// `tool_annotations_agree_with_the_risk_classifier` test pins.
    pub fn hints(self) -> (bool, bool) {
        (self == Self::ReadOnly, self == Self::Destructive)
    }
}

impl fmt::Display for Risk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Slugs whose risk the verb alone gets wrong.
///
/// Every entry is here because the bare verb is shared with operations of a
/// different class: `acl/grant` and `contexts/create` are both "add a row", but
/// only one of them hands out authority.
const SLUG_OVERRIDES: &[(&str, Risk)] = &[
    // External accounts (`external/*`). Issuance mints a provider credential,
    // so a standing approval would let an agent mint them indefinitely: the
    // specification asks for approval per call, which `Sensitive` gives.
    ("external/credentials/issue", Risk::Sensitive),
    // A provider secret, set; who may use an account, widened; an account
    // switched back on. Each moves authority.
    ("external/accounts/secret/set", Risk::Sensitive),
    ("external/accounts/bindings/grant", Risk::Sensitive),
    ("external/accounts/resume", Risk::Sensitive),
    // The provider-side setup, generated: reads only, contacts nothing.
    ("external/accounts/setup", Risk::ReadOnly),
    // Writes and deletes a canary object at the provider.
    ("external/accounts/probe", Risk::Mutating),
    // The kill switch: withdraws every consumer's access at once, like
    // `disable`. Reversible, and a host should still confirm it.
    ("external/accounts/suspend", Risk::Destructive),
    ("external/accounts/archive", Risk::Destructive),
    ("external/accounts/restore", Risk::Mutating),
    // The witnessed party (`vta/witness/*`). `open` and `present` sign as the
    // principal's relationship DID, and `present` puts the principal's
    // credentials — under the member link, its member DID too — in a document
    // addressed to a third party: disclosure on the principal's behalf, so a
    // blanket `vta_call` approval must not cover it. `accept` stores a VWC the
    // session's own witness issued, and discloses nothing.
    ("vta/witness/open", Risk::Sensitive),
    ("vta/witness/present", Risk::Sensitive),
    // A held credential presented to a verifier the caller names, signed as its
    // subject: a disclosure to a third party, so approved per call.
    ("vault/credentials/present", Risk::Sensitive),
    ("vta/witness/accept", Risk::Mutating),
    // `vta/pcs/vetter/recover`: replaces the key a vetter engine runs under
    // (searching the context's derivable keys for it) and discards enrolments
    // and draws in flight. It moves which key acts for the vetter, so a host
    // confirms it rather than leaving it to a blanket approval.
    ("vta/pcs/vetter/recover", Risk::Sensitive),
    // Key authority, exercised.
    ("keys/sign", Risk::Sensitive),
    ("keys/sign-sshsig", Risk::Sensitive),
    ("keys/sign-jws", Risk::Sensitive),
    ("keys/sign-csr", Risk::Sensitive),
    ("keys/sign-document", Risk::Sensitive),
    ("keys/derive-and-sign", Risk::Sensitive),
    ("keys/derive-and-sign-document", Risk::Sensitive),
    ("keys/import", Risk::Sensitive),
    ("vault/sign-trust-task", Risk::Sensitive),
    // Secret material, emitted.
    ("vault/release", Risk::Sensitive),
    ("vault/proxy-login", Risk::Sensitive),
    ("keys/export-secret", Risk::Sensitive),
    // The root seed, sealed to the caller: the export of every key this VTA
    // holds, so it is classified with `keys/export-secret`.
    ("vta/attestation/mnemonic-export", Risk::Sensitive),
    // Whether a mnemonic export window is open, and until when. Reads state
    // only and returns no secret, but its verb is not a read verb.
    ("vta/attestation/mnemonic-status", Risk::ReadOnly),
    // Returns the private keys of a context's DID. The verb rule would read
    // `secrets` as an ordinary mutation, and the task's own `sideEffects` are
    // `none` — it reads and changes nothing — so neither the verb nor the side
    // effect is what makes it risky. What comes back is the whole authority of
    // that DID, which is `Sensitive` by the definition above: secret material,
    // emitted. It belongs beside `export-mnemonic`, whose replacement it is.
    //
    // Deliberately NOT `ReadOnly` despite being a read. `ReadOnly` is the class
    // `--read-only` permits and means "safe to call on a whim"; handing an MCP
    // host a signing key on a blanket `vta_call` approval is the threat model
    // this module exists for. Note this is the opposite call from the one in
    // `vta-sdk`'s `retry_safety`, and correctly so: that asks what a SECOND
    // execution costs (nothing — it is idempotent), this asks what ONE
    // execution discloses.
    ("vta/contexts/secrets", Risk::Sensitive),
    // Custody rules, changed. `keys/set-exportability` decides whether a key
    // may ever leave — one direction forecloses that, the other restores it —
    // so a blanket `vta_call` approval must not silently cover it. The verb
    // rule would read `set-exportability` as an ordinary mutation, and in the
    // lifting direction it is the step that lets a protected key out.
    ("keys/set-exportability", Risk::Sensitive),
    // Authority, moved.
    ("acl/grant", Risk::Sensitive),
    ("acl/update", Risk::Sensitive),
    ("acl/change-role", Risk::Sensitive),
    ("policy/upsert", Risk::Sensitive),
    ("config/patch", Risk::Sensitive),
    ("vta/credentials/issue", Risk::Sensitive),
    ("vta/passkey-vms/enroll-submit", Risk::Sensitive),
    ("did-management/registry/admin-register", Risk::Sensitive),
    ("did-management/domain/set-default", Risk::Sensitive),
    ("provision/integration", Risk::Sensitive),
    // The room oracle mints a credential conferring authority on the caller.
    // It stores nothing, which is why the verb rule would read it as ordinary,
    // and it belongs here beside `vta/credentials/issue`: an MCP host approves
    // a *tool*, so a blanket `vta_call` approval must not silently cover
    // minting a presentation over its principal's standing in a room.
    ("rooms/keys/present", Risk::Sensitive),
    // Secret material, emitted: `open` returns a room record's plaintext. It
    // belongs beside `vault/release` rather than with the ordinary mutations,
    // because what comes back is content the room encrypted.
    ("rooms/keys/open", Risk::Sensitive),
    // Key material, emitted: one file's key, which opens that file's ciphertext
    // for as long as the ciphertext exists. More than `open` returns, not less.
    ("rooms/keys/file-key", Risk::Sensitive),
    // Key material, accepted. A Welcome carries a group's secrets and joining
    // is a membership change made on the principal's behalf — not something a
    // blanket `vta_call` approval should cover silently.
    ("rooms/keys/welcome", Risk::Sensitive),
    // Key material, accepted — and the verb rule would read `chain` as an
    // ordinary mutation because what it stores is ciphertext. What it actually
    // does is extend how far back every subsequent `rooms/keys/open` can reach,
    // to the room's whole retained history. A blanket `vta_call` approval must
    // not silently cover widening what the principal's key holder can decrypt.
    ("rooms/keys/chain", Risk::Sensitive),
    // Fetches key material from a named host and keeps it. Sensitive for the
    // same reason `chain` is — it extends what this agent can decrypt — with the
    // addition that it makes an outbound call to a party the caller names.
    ("rooms/keys/backfill", Risk::Sensitive),
    // Returns a record's PLAINTEXT — on a sealed tier, material the room
    // withholds from its own host — after an outbound call to a party the caller
    // names. Both halves are why this is sensitive; either alone would be.
    // Publishes permanently, in the room's name, and rotates the room DID's
    // update key on the way. Nothing here can be taken back.
    ("rooms/owner/anchor", Risk::Destructive),
    ("rooms/keys/read", Risk::Sensitive),
    // Metadata only, and still sensitive: it presents the principal's room
    // credentials to a caller-named host, which on a tier that discloses
    // subjects names them to it.
    ("rooms/keys/browse", Risk::Sensitive),
    // Secret material, accepted AND emitted. `seal` takes a record's plaintext and
    // returns it encrypted under the room's key — the one direction in this family
    // where cleartext room material travels INTO the oracle. It belongs beside
    // `open`, which is the same exchange run the other way.
    ("rooms/keys/seal", Risk::Sensitive),
    // A read, and the verb rule would get it right — but what it lists is the
    // principal's room membership as key custody sees it, which is more than any
    // single room operation discloses. Named here so that is a decision rather
    // than a default.
    ("rooms/keys/list", Risk::ReadOnly),
    // Writes only the member's own private name for a room, in their VTA, reversibly. The
    // VTA refuses it from a delegate — an agent is never the member — so a host approving
    // `vta_call` gains nothing here; named so the class is a decision.
    ("rooms/keys/label", Risk::Mutating),
    // The room's own profile. `read` returns what a sealed room withholds from its host
    // after an outbound call to a host the caller names, as `rooms/keys/read` does.
    // `write` signs, as the member, what every member of the room is shown the room is
    // called — and an agent reading it back must treat it as text, never instructions.
    ("rooms/keys/profile/read", Risk::Sensitive),
    ("rooms/keys/profile/write", Risk::Sensitive),
    // Issuance, signed as the room. `invite` and `issue-membership` decide who
    // may enter and remain; `issue-authority` decides what they may do, and an
    // `admin` grant is the authority to mint epochs and transfer the room. The
    // verb rule would read all three as ordinary mutations. An MCP host approves
    // a *tool*, so a blanket `vta_call` must not silently cover deciding a room's
    // membership.
    ("rooms/owner/invite", Risk::Sensitive),
    ("rooms/owner/issue-membership", Risk::Sensitive),
    ("rooms/owner/issue-authority", Risk::Sensitive),
    // Announces a room, and its owner, to a host the caller names. Nothing
    // secret leaves — the disclosure is the room's existence and who answers for
    // it — but it creates durable state at a third party.
    ("rooms/owner/register", Risk::Sensitive),
    // The owner's half of a sealed room's group. `create` founds the key
    // schedule every record will be sealed under; `add` admits a reader to all
    // of it from now on and advances the room at its host. Both decide who can
    // read the room — the same decision issuance makes, so the same tier.
    ("rooms/owner/group/create", Risk::Sensitive),
    ("rooms/owner/group/add", Risk::Sensitive),
    // `remove` ends a member's reading from now on and advances the room at
    // its host in the owner's name: the same decision, the other way.
    ("rooms/owner/group/remove", Risk::Sensitive),
    // `revoke` withdraws credentials the room issued, signed as the room and enforced at
    // every host at once: the inverse of issuance, the same tier.
    ("rooms/owner/revoke", Risk::Sensitive),
    // `renew` advances the room at its host in the owner's name, and every
    // member's key holder must then follow it: the owner's decision, not a read.
    ("rooms/owner/group/renew", Risk::Sensitive),
    // The holder's own identity, emitted. `disclosure/present` is the one
    // persona task that hands claims to a named verifier, under a persona DID,
    // and writes the record saying it did. It sits beside `rooms/keys/present`
    // for the same reason: an MCP host approves a *tool*, so a blanket
    // `vta_call` approval must not silently cover deciding who learns the
    // principal's name.
    ("persona/disclosure/present", Risk::Sensitive),
    // Reads that a verb rule would misread.
    ("vta/contexts/preview-delete", Risk::ReadOnly),
    ("vta/webvh/agent-name/check", Risk::ReadOnly),
    ("trust-task-discovery", Risk::ReadOnly),
    // Mints an ephemeral wrapping key that lives only in the VTA's memory for a
    // minute and is discarded on first use — no record, nothing persisted. The
    // verb rule would read it as an ordinary mutation; what it returns is a
    // public key.
    ("keys/import-wrapping-key", Risk::ReadOnly),
    // A backup export is a full-state dump — sensitive in both directions.
    ("vta/backup/initiate-export", Risk::Sensitive),
    ("vta/backup/complete-export", Risk::Sensitive),
    // A chunk of that dump. Each `get-chunk` releases part of the encrypted
    // export, so it is classified with `complete-export` rather than read as the
    // ordinary `get` its verb would suggest. `put-chunk` writes part of a bundle
    // that `finalize-import` may later impose on the whole agent.
    ("vta/backup/get-chunk", Risk::Sensitive),
    ("vta/backup/put-chunk", Risk::Sensitive),
    // ── The community's families (a `vtc-mcp` bridge reaches these) ──────
    //
    // The node-neutral `backup/*` family the VTC serves: the same full-state
    // dump as `vta/backup/*`, classified the same way in both directions.
    ("backup/initiate-export", Risk::Sensitive),
    ("backup/complete-export", Risk::Sensitive),
    ("backup/get-chunk", Risk::Sensitive),
    ("backup/put-chunk", Risk::Sensitive),
    // One signed document each, and what comes back is the community's
    // whole configuration, its member directory, or the administrators'
    // notes about a member (released only behind a `Critical` step-up).
    ("vtc/backup/export", Risk::Sensitive),
    ("vtc/config/export", Risk::Sensitive),
    ("vtc/directory/export", Risk::Sensitive),
    ("vtc/directory/notes/export", Risk::Sensitive),
    // Authority, conferred. An admin invitation and the first-administrator
    // bootstrap seat an administrator; a role change, a custom role and the
    // record of an offline ACL write move what an entry may do; the join
    // decision, direct admission and make-membership make a member and issue
    // the membership credential; a vetter grant confers vetting authority;
    // an endorsement is a credential the community signs about a member.
    ("vtc/admin/invites/create", Risk::Sensitive),
    ("vtc/admin/bootstrap", Risk::Sensitive),
    ("vtc/members/role/set", Risk::Sensitive),
    ("vtc/roles/define", Risk::Sensitive),
    ("vtc/operator/offline-write", Risk::Sensitive),
    ("vtc/join-requests/decide", Risk::Sensitive),
    ("vtc/members/admit", Risk::Sensitive),
    ("vtc/members/make-membership", Risk::Sensitive),
    ("vtc/vetting/vetters/grant", Risk::Sensitive),
    ("vtc/endorsements/issue", Risk::Sensitive),
    // Groups and boards: an appointment is a resource grant on the
    // appointee's entry; a binding provisions capabilities (or room
    // admission) into every member's entry; adding or admitting a member
    // issues the group's credential and may confer what the group's bindings
    // carry. The verb rule reads each as an ordinary `add` / `decide`.
    ("vtc/boards/facilitators/add", Risk::Sensitive),
    ("vtc/groups/managers/add", Risk::Sensitive),
    ("vtc/groups/bindings/add", Risk::Sensitive),
    ("vtc/groups/members/add", Risk::Sensitive),
    ("vtc/groups/requests/decide", Risk::Sensitive),
    // Admission to a community room, decided by an administrator: the same
    // decision `rooms/owner/issue-membership` makes.
    ("vtc/rooms/community/members/add", Risk::Sensitive),
    // A member presents a credential to the community, which keeps the
    // disclosed claims: a disclosure on the principal's behalf, like
    // `vault/credentials/present`.
    ("vtc/directory/card/present", Risk::Sensitive),
    // Networks: joining one as a community, and acknowledging a network's
    // membership offer, each bind the community to a network's rules; a room
    // pass is a credential minted to the caller on presented evidence.
    ("vtc/networks/join", Risk::Sensitive),
    ("vtn/memberships/join", Risk::Sensitive),
    ("vtn/membership/acknowledge", Risk::Sensitive),
    ("vtn/rooms/pass", Risk::Sensitive),
    // A listed party asking about its own membership offer: a read whose
    // verb would otherwise be taken as making one.
    ("vtn/membership/offer", Risk::ReadOnly),
    // Git namespaces: binding and reseating a namespace, adopting a repository
    // (which names its owners), transferring one, the emergency self-grant and
    // its ratification each move forge authority.
    ("git-ns/namespace/bind", Risk::Sensitive),
    ("git-ns/namespace/reseat", Risk::Sensitive),
    ("git-ns/repo/adopt", Risk::Sensitive),
    ("git-ns/repo/transfer", Risk::Sensitive),
    ("git-ns/right/break-glass", Risk::Sensitive),
    ("git-ns/right/ratify", Risk::Sensitive),
    // Activating a policy changes what every later decision is judged by —
    // the same tier as `policy/upsert`.
    ("policy/activate", Risk::Sensitive),
    // Sign-in and step-up factors. `respond` delivers the member's signed
    // grant that binds a browser key to their identity; enrolling or
    // authorising a signing key, or an approver or step-up passkey, adds a
    // factor that will answer for the subject from then on.
    ("auth/oob/respond", Risk::Sensitive),
    ("auth/signing-key/authorize", Risk::Sensitive),
    ("auth/signing-key/enroll", Risk::Sensitive),
    ("auth/step-up/approver/enroll", Risk::Sensitive),
    ("auth/step-up/approver/invite", Risk::Sensitive),
    ("auth/passkey/enroll/invite", Risk::Sensitive),
    // Credential exchange: an offer opens an issuance, approving a pending
    // one issues, and `present` discloses a credential to a verifier.
    ("credential-exchange/offer", Risk::Sensitive),
    ("credential-exchange/pending/approve", Risk::Sensitive),
    ("credential-exchange/present", Risk::Sensitive),
    // Rooms, host side. Minting an epoch seals the room's history under the
    // owner's authority; transferring the room moves that authority. A blob
    // chunk is a fetch of ciphertext — a read the verb rule would take for the
    // upload's `chunk`.
    ("rooms/epoch/mint", Risk::Sensitive),
    ("rooms/owner/transfer", Risk::Sensitive),
    ("rooms/blobs/chunk", Risk::ReadOnly),
    // A trustee authorised onto an election holds a share of its key.
    ("voting/trustees/authorize", Risk::Sensitive),
    // An approver's decision on a parked action: the approval that lets an
    // authority-conferring grant, a reduction or a referred admission run.
    // The verb rule would read `decision` as an ordinary mutation; what it is
    // is this identity vouching for someone else's authority.
    ("task-consent/decision", Risk::Sensitive),
    // The starter's half of a wallet sign-in: opening a request, polling for
    // the person's approval, withdrawing it. Nothing happens without the
    // person approving in their wallet, and a `--read-only` bridge still has
    // to sign in to read as them — so the starter's three steps are the one
    // class that mode permits. The approver's steps (`identify`, `respond`)
    // stay where they were.
    ("auth/oob/request", Risk::ReadOnly),
    ("auth/oob/redeem", Risk::ReadOnly),
    ("auth/oob/cancel", Risk::ReadOnly),
    // A member's own badge wall: declining an offer and hiding a badge are
    // theirs to undo and remove nothing from anyone else, so neither takes
    // the confirmation the verbs `decline` and `hide` carry elsewhere.
    ("vtc/badges/mine/decline", Risk::Mutating),
    ("vtc/badges/mine/hide", Risk::Mutating),
];

/// Final-segment verbs that only ever read.
const READ_VERBS: &[&str] = &[
    // `rooms/changed`: a host's one-way signal; `rooms/keys/changed`: the VTA passing one
    // on to the client that watched. Neither changes anything a client could ask for.
    "changed",
    "list",
    "get",
    "get-many",
    "show",
    "info",
    "whoami",
    "check",
    "check-name",
    "health",
    "query",
    "domains",
    "render",
    "report",
    // `vta/attestation/config-report`: fresh evidence over the booted
    // config's digest — a public read, no state changes.
    "config-report",
    "status",
    // `vta/health/details`: the VTA's public health flags.
    "details",
    "ping",
    "explain",
    "get-retention",
    "approver-list",
    // Checks the audit log's hash chain and reports what it found. A read of
    // the whole log and nothing else — it writes nothing, and the answer being
    // "broken" is a fact about what is already there.
    "verify",
    // `persona/profile/usage`: where a face is worn now. Reads bindings only.
    "usage",
    // `persona/profile/timeline`: a face's history. Reads only, and carries
    // no value.
    "timeline",
    // Reads the record of what was disclosed to whom. Only ever a read — the
    // disclosure itself is written by `present`, not by looking at it later.
    "history",
    // Reports how linkable a value would make the holder. It reads the pool
    // and writes nothing; classifying it above ReadOnly while
    // `persona/attribute/list` — which returns the values themselves — stays
    // ReadOnly would be incoherent.
    "analyze",
    // ── The community's families ─────────────────────────────────────────
    // `auth/passkey/admin-list`, `git-ns/account/link-status`,
    // `git-ns/view`, `git-ns/right/issued-by-departed`: administrators' reads.
    "admin-list",
    "link-status",
    "view",
    "issued-by-departed",
    // `policy/active`: which policy is in force.
    "active",
    // `vtc/admin/events/subscribe`: a stream of hints to re-read — never a
    // record, never an id (the admin console live channel).
    "subscribe",
    // `vtc/directory/card/public`, `vtc/directory/disclosure`: what the
    // directory shows, and the statement of what it discloses to whom.
    "public",
    "disclosure",
    // `vtc/join-requests/manifest`: what a community asks of an applicant.
    "manifest",
    // `vtc/members/credentials`: the membership-pair credential bodies the
    // community holds for a member — public credentials, no secret.
    "credentials",
    // `vtc/policies/test`: evaluates a policy against an input and keeps
    // nothing.
    "test",
    // `vtc/registry/diagnostics`, `vtc/relationships/graph`,
    // `vtc/networks/evidence` (the credentials linking a group to a network),
    // `vtc/elections/tombstones`, `registry/recognition` (a TRQP query).
    "diagnostics",
    "graph",
    "evidence",
    "tombstones",
    "recognition",
    // `rooms/epoch/chain`, `rooms/epoch/commits`: the epoch chain and its
    // commits, read. (`rooms/keys/chain` is an override above: it stores.)
    "chain",
    "commits",
    // `voting/board/{consistency,head,inclusion}`: proofs over the board.
    "consistency",
    "head",
    "inclusion",
    // `vtn/directory/{federated,search,summary}`, `vtn/graph/member`.
    "federated",
    "search",
    "summary",
    "member",
];

/// Final-segment verbs that remove state or access.
const DESTRUCTIVE_VERBS: &[&str] = &[
    "delete",
    "purge",
    // `persona/attribute/purge-version`: destroys kept earlier values of an
    // attribute for good.
    "purge-version",
    // `persona/profile/retire`: takes a face off every context it is worn in.
    // Reversible and nothing is erased, but it withdraws access everywhere at
    // once — the kind of act a host should confirm, like `disable`.
    "retire",
    "remove",
    "revoke",
    "revoke-session",
    "wipe",
    "disable",
    // `did-management/{did,domain}/set-state`: disables (or re-enables) a DID or
    // a whole domain — the retired `disable` folded into one task, so it takes
    // `disable`'s confirmation.
    "set-state",
    "deregister",
    "unassign",
    "retire-orphan",
    "rollback",
    "rotate",
    "rotate-keys",
    "swap-key",
    "change-owner",
    "abort",
    "initiate-import",
    "finalize-import",
    "reload-services",
    // `vta/pcs/attest`: spends an attestation token for good and is the
    // vetter's word that a person was checked — the act a host must confirm.
    "attest",
    // `vta/pcs/tokens/abandon`: discards a draw's serials, so an answer the
    // community sends later can never be taken.
    "abandon",
    // `vta/pcs/vote`: builds a signed cast of the principal's ballot. The
    // client sends it, but the document is the vote — the act a host must
    // confirm, every time, whatever was approved before.
    "vote",
    // `vta/pcs/vote-encrypted`: the same, for a sealed or tallied-encrypted ballot.
    "vote-encrypted",
    // `vta/pcs/trustee/justify`: reveals a share of the election key the trustee
    // dealt, for good — the act a host must confirm.
    "justify",
    // `vta/pcs/trustee/decrypt`: the trustee's share of decrypting the result. With
    // enough others it decides what the election says — a trustee's word, like
    // `attest`.
    "decrypt",
    // ── The community's families ─────────────────────────────────────────
    // `withdraw`: a board idea or note, a join request, a published hidden
    // vetting criterion — each taken back for good.
    "withdraw",
    // `credential-exchange/pending/deny`, `vetting/decline`: close a request
    // against the asker.
    "deny",
    "decline",
    // `git-ns/account/unlink`, `git-ns/namespace/unbind`: sever a forge
    // account or a namespace from the community.
    "unlink",
    "unbind",
    // `config/restart`: the service goes down to come back.
    "restart",
    // `voting/election/close`, `vtc/elections/close`: ends the voting;
    // `vtc/elections/certify`: fixes the result for good.
    "close",
    "certify",
    // `vtc/groups/leave`, `vtc/networks/leave`, `vtn/memberships/leave`: ends
    // the caller's own membership.
    "leave",
    // `vtc/members/admin-remove`, `vtc/members/self-remove`.
    "admin-remove",
    "self-remove",
    // `voting/ballot/cast`, `cast-encrypted`: the member's vote — confirmed
    // every time, like `vta/pcs/vote`.
    "cast",
    "cast-encrypted",
    // `vtc/boards/notes/hide`: moderation the board's audience sees.
    "hide",
    // `vtc/registry/sync-jobs/discard`: drops a pending projection.
    "discard",
    // `vtc/relationships/suspend`, `vtn/listings/suspend`: withdraws standing
    // (reversibly, and a host should still confirm it — as `disable`).
    "suspend",
    // `vtc/networks/repudiate`, `vtn/membership/repudiate`,
    // `vtn/memberships/repudiate`: disowns a membership or a listing.
    "repudiate",
    // `vtc/vetting/vetters/pcs-binding/reset`: discards a vetter's binding.
    "reset",
    // `vtc/vetting/revoke-statement`: withdraws a vetting statement.
    "revoke-statement",
    // `rooms/epoch/prune`, `rooms/records/prune`: the host drops records.
    "prune",
];

/// Final-segment verbs that are deliberately `Mutating`.
///
/// Only the census ([`unclassified_verbs`]) reads this — `classify` defaults
/// to `Mutating` without consulting it, so a runtime miss is safe and a
/// census miss is loud.
const MUTATING_VERBS: &[&str] = &[
    // `notifications/notify`, `notifications/relay`: a counterparty's delivery, which may
    // be held — replacing a lower revision of the same notification, never anything else.
    "notify",
    "relay",
    // `vta/notifications/dismiss`: hides a held notification from the default list; it
    // stays readable and listable when asked for (VTI-NTF-052). Removes nothing.
    "dismiss",
    // `vta/notifications/deposit`: a client hands over a notification it received for a
    // persona DID; the VTA holds it exactly as a direct delivery would (VTI-NTF-055).
    "deposit",
    // `vta/collection/claim`: records a lease naming the caller as a persona DID's one
    // collector and closes the VTA's own connection for it (VTI-NTF-082). Removes nothing;
    // `release` (below) ends it.
    "claim",
    // `rooms/keys/act`: signs a host-bound room request as the member — a write or a
    // curation as readily as a read. It changes nothing here itself, but what it signs
    // can change a room, so it is never a read.
    "act",
    // `rooms/keys/watch`: arms (or cancels) watches at a room's host as the member and
    // keeps one record per watch until it fires. Removes nothing a client holds.
    "watch",
    // `persona/profile/compose`: makes a face, may pool a value and bind
    // it. Creates; removes nothing.
    "compose",
    // `persona/attribute/promote`: widens a local value into the pool.
    // One-way, but it removes no value and no access — the face and its
    // wearers carry on presenting exactly what they did.
    "promote",
    // `persona/profile/reinstate`: makes a face wearable; binds nothing.
    "reinstate",
    // Mints a KeyPackage and retains its private half. Consequential, but
    // what it emits is public by construction — hence Mutating rather than
    // Sensitive, unlike its siblings `welcome` and `open`.
    "key-package",
    // Advances the group one epoch. No secret crosses in either direction.
    "commit",
    // `persona/disclosure/preview` reads like a read and is not one: it
    // mints the single-use token `present` consumes, so a replayed preview
    // hands out a second authorisation to disclose. `--read-only` must not
    // permit it. Nothing leaves the agent, which is why it stops here and
    // does not join `present` among the sensitive slugs.
    "preview",
    // `vta/pcs/*` (the hidden-vetting engine): each stores engine state —
    // an attestation kept, an enrolment or a draw in flight, tokens or a
    // class credential taken in — and none removes anything. `prove`
    // stores nothing, but it exercises the applicant's key to build the
    // proof a join is decided on, so `--read-only` must not permit it.
    "verify-attestation",
    "prove",
    "root-request",
    "root-accept",
    // `vta/pcs/voter/receipt`: keeps a receipt and checks its inclusion;
    // stores, removes nothing.
    "receipt",
    // `vta/pcs/voter/read`: stores nothing, but signs as the member's
    // membership DID, so `--read-only` must not permit it — as `prove`.
    "read",
    // `vta/pcs/trustee/{enrol,deal,keys}`: the trustee's transport key, its
    // dealing and its key share — each kept, each published or confirmed as
    // the trustee persona.
    "enrol",
    "deal",
    "keys",
    "accept",
    "create",
    "update",
    "update-did",
    "update-retention",
    "upsert",
    "put",
    "put-many",
    "register",
    "register-with-server",
    "admin-register",
    "enable",
    "set",
    "set-wake",
    "set-default",
    "assign",
    "receive",
    "archive",
    "unarchive",
    "restore",
    "heartbeat",
    "reconcile",
    "publish",
    // `vtc/badges/awards/share|unshare`: the holder starts or stops the community serving
    // their own badge credential at a public location, as `publish` does their external
    // card. Reversible by the holder; stopping revokes nothing (VTI-BDG-070).
    "share",
    "unshare",
    "cancel",
    "decision",
    "request",
    "approver-set",
    "start",
    "finish",
    "approve-response",
    "enroll-challenge",
    "enroll-submit",
    "issue",
    "import",
    "sign",
    "sign-trust-task",
    "derive-and-sign",
    "derive-and-sign-document",
    "release",
    "proxy-login",
    "grant",
    "change-role",
    "patch",
    "integration",
    "problem-report",
    "stats-sync",
    "refresh",
    "authenticate",
    "challenge",
    "export-mnemonic",
    "initiate-export",
    "complete-export",
    "rename",
    // Renames a DID's key records onto the verification-method ids its
    // published document declares. Beside `rename`, which is the same act
    // one record at a time — and deliberately NOT `Sensitive`, despite
    // touching key custody, which is the call worth explaining.
    //
    // `keys/set-exportability` is `Sensitive` because a caller chooses the
    // direction and one of them lets a protected key out. Here the caller
    // chooses nothing: the payload carries a DID and a boolean, and every
    // target name is derived by the agent from that DID's own log. There is
    // no argument that points it anywhere, so the worst a blanket
    // `vta_call` approval can do is move records into agreement with the
    // document they were always supposed to match.
    //
    // No secret is emitted either — the response carries verification-method
    // ids and the *public* halves behind them, both already world-readable
    // in the DID document.
    "realign-keys",
    // ── The community's families ─────────────────────────────────────────
    // Wallet sign-in (`auth/oob/*`): `identify` claims a request, `redeem`
    // turns an approved one into its outcome. (`respond` is an override.)
    "identify",
    "redeem",
    // `auth/step-up/approve-request`, `consent/approve-request`: opens a
    // request someone else answers. `approve` alone is
    // `credential-exchange/pending/approve`, an override.
    "approve-request",
    "approve",
    // `config/reload`: re-reads configuration.
    "reload",
    // Git namespaces: links an account, the bridge's event / job / result
    // traffic, drift resolution, the break-glass notice, role projection.
    "link",
    "event",
    "job",
    "result",
    "resolve",
    "break-glass-notice",
    "reproject",
    // `push/provision`, `push/wake`: the push gateway's allowlist and a wake.
    "provision",
    "wake",
    // Uploads (`vtc/website/upload/*`, `rooms/blobs/upload/*`,
    // `vtc/directory/images/upload`), and a website deploy.
    "begin",
    "chunk",
    "upload",
    "deploy",
    // `task-consent/granted`: a fire-and-forget notice to re-submit.
    "granted",
    // `vetting/session`, `witness/session`: opens a session with an
    // applicant; `witness/session/submit`, `vtc/join-requests/submit`,
    // `submit-receipt`, `supplement`: the applicant's side of a ceremony.
    "session",
    "submit",
    "submit-receipt",
    "supplement",
    // `voting/trustees/confirm`: a trustee confirms the shares it was dealt.
    "confirm",
    // `vtc/admin/actions/acknowledge`: an administrator acknowledges an
    // offline write. (`vtn/membership/acknowledge` is an override.)
    "acknowledge",
    // `vtc/auth/admin-session`, `vtc/auth/recognise`: session minting, as
    // `authenticate`.
    "admin-session",
    "recognise",
    // Boards: `propose` an idea, `decide` on it (`join-requests/decide` and
    // `groups/requests/decide` are overrides), `select` among them, `add` a
    // note (the authority-conferring `add`s are overrides).
    "propose",
    "decide",
    "select",
    "add",
    // Directory: an administrator asserts a field, defines one, appends a
    // note; a member asserts their personhood with evidence.
    "assert",
    "define",
    "append",
    // Groups and networks: `join` a group (joining a network is an
    // override); deliveries and notices between parties.
    "join",
    "deliver",
    "notice",
    "send",
    // Members: the notices the community sends, a renewal, the VMC exchange,
    // the rotation challenge, the self-removal receipt.
    "authority-reduced-notice",
    "authority-reduction-pending-notice",
    "removal-notice",
    "step-up-passkey-notice",
    "removed",
    "renew",
    "request-vmc",
    "solicit-vmc",
    "vmc",
    "rotate-challenge",
    "self-remove-receipt",
    // `vtc/registry/sync-jobs/retry`, `vtn/outbox/retry`: re-queues.
    "retry",
    // `vtc/rooms/storage/migrate`: moves a room's blobs between stores.
    "migrate",
    // `vtc/storage/configs/probe`: writes and deletes a canary.
    "probe",
    // Hidden vetting: the challenge, a vetter's event mode, class credential,
    // token draw, profile and resend.
    "pcs-challenge",
    "event-mode",
    "pcs-root",
    "pcs-tokens",
    "profile",
    "resend",
    // `rooms/records/curate`: demotes, retracts, restores or pins a record.
    "curate",
    // Badges: an owner offers one (nothing is issued until the member
    // accepts), a member gives kudos, a member arranges their own wall.
    "offer",
    "give",
    "arrange",
];

/// The URIs among `uris` that classify off no override and no known verb,
/// each with the verb `classify` would have defaulted on, and an empty verb
/// for one that is not a versioned task URI at all.
///
/// Both censuses are built on this: this crate's, over every pinned request
/// URI, and each bridge's, over every URI its generic tool can dispatch.
pub fn unclassified_verbs<'a>(uris: impl IntoIterator<Item = &'a str>) -> Vec<(&'a str, &'a str)> {
    let mut unknown = Vec::new();
    for uri in uris {
        let Some(slug) = slug_of(uri) else {
            unknown.push((uri, ""));
            continue;
        };
        if SLUG_OVERRIDES.iter().any(|(s, _)| *s == slug) {
            continue;
        }
        let verb = slug.rsplit('/').next().unwrap_or(slug);
        let known = READ_VERBS.contains(&verb)
            || DESTRUCTIVE_VERBS.contains(&verb)
            || MUTATING_VERBS.contains(&verb);
        if !known {
            unknown.push((uri, verb));
        }
    }
    unknown
}

/// The census, as a test helper: panic naming every URI in `uris` whose verb
/// no list classifies, with the lines ready to paste into whichever list is
/// right.
///
/// # Panics
///
/// When any URI is unclassified.
pub fn assert_every_verb_is_known<'a>(uris: impl IntoIterator<Item = &'a str>) {
    let unknown = unclassified_verbs(uris);
    let template: String = unknown
        .iter()
        .map(|(uri, verb)| format!("    \"{verb}\", // {uri}\n"))
        .collect();
    assert!(
        unknown.is_empty(),
        "unclassified Trust Task verbs — decide whether each reads, destroys or merely \
         mutates, then paste its line into READ_VERBS, DESTRUCTIVE_VERBS or MUTATING_VERBS \
         in vti-mcp-common/src/guard.rs (shown here ready to paste into whichever list is \
         right — `classify` would otherwise default it to Mutating silently):\n{template}"
    );
}

/// The slug of a Trust Task URI — the part after [`SPEC_PREFIX`], with the
/// trailing version segment removed. `…/spec/acl/grant/0.1` → `acl/grant`.
///
/// Returns `None` for anything that is not a versioned task URI, including the
/// bare family-namespace constants (`…/spec/acl/`), so callers can refuse
/// rather than guess.
pub fn slug_of(uri: &str) -> Option<&str> {
    let rest = uri.strip_prefix(SPEC_PREFIX)?;
    let (slug, version) = rest.rsplit_once('/')?;
    // A version segment is digits and dots; a trailing `/` leaves it empty.
    if version.is_empty() || !version.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return None;
    }
    (!slug.is_empty()).then_some(slug)
}

/// Classify a Trust Task URI.
///
/// Unknown verbs are [`Risk::Mutating`]. That is the safe default in both
/// directions: `--read-only` refuses them, and confirmation is not demanded for
/// something that may well be a harmless create. The census test below is what
/// stops "unknown" from becoming the common case as the catalog grows.
pub fn classify(uri: &str) -> Risk {
    let Some(slug) = slug_of(uri) else {
        // Not a task URI. The dispatcher will refuse it; classify high so a
        // read-only bridge does not pass it along on the way to that refusal.
        return Risk::Mutating;
    };
    if let Some((_, risk)) = SLUG_OVERRIDES.iter().find(|(s, _)| *s == slug) {
        return *risk;
    }
    let verb = slug.rsplit('/').next().unwrap_or(slug);
    if DESTRUCTIVE_VERBS.contains(&verb) {
        Risk::Destructive
    } else if READ_VERBS.contains(&verb) {
        Risk::ReadOnly
    } else {
        Risk::Mutating
    }
}

/// How much of the risky tail is put back in front of a human.
///
/// Cumulative: each level confirms everything the level below it confirms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConfirmLevel {
    /// Confirm nothing. The host's per-tool approval is the only gate.
    Never,
    /// Confirm [`Risk::Destructive`] only. The default — the host already
    /// prompts per tool, so this adds a prompt exactly where a tool-level
    /// approval is too coarse to be meaningful.
    #[default]
    Destructive,
    /// Also confirm [`Risk::Sensitive`] — signing, secret release, mnemonic
    /// export, ACL changes. The right setting for a bridge holding an operator
    /// session rather than a scoped agent identity.
    Sensitive,
    /// Confirm every call that changes anything. Read-only calls still run
    /// unprompted.
    Always,
}

impl ConfirmLevel {
    /// Parse the `--confirm` flag.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "never" | "none" | "off" => Ok(Self::Never),
            "destructive" => Ok(Self::Destructive),
            "sensitive" => Ok(Self::Sensitive),
            "always" | "all" => Ok(Self::Always),
            other => Err(format!(
                "unknown --confirm value '{other}' (expected never, destructive, sensitive or always)"
            )),
        }
    }

    /// The label used in logs and `vta_status`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Destructive => "destructive",
            Self::Sensitive => "sensitive",
            Self::Always => "always",
        }
    }

    fn wants(self, risk: Risk) -> bool {
        match self {
            Self::Never => false,
            Self::Destructive => risk == Risk::Destructive,
            Self::Sensitive => matches!(risk, Risk::Destructive | Risk::Sensitive),
            Self::Always => risk != Risk::ReadOnly,
        }
    }
}

/// What the guard decided about one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Run it.
    Allow,
    /// Run it only if a human says yes, using the carried prompt.
    Confirm(String),
    /// Refuse, with an operator-facing reason that names the flag which would
    /// have permitted it.
    Deny(String),
}

impl Decision {
    /// The label recorded in the audit log.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Confirm(_) => "confirm",
            Self::Deny(_) => "deny",
        }
    }
}

/// The operator-configured local policy.
#[derive(Debug, Clone, Default)]
pub struct Guard {
    /// Refuse anything that is not [`Risk::ReadOnly`].
    pub read_only: bool,
    /// Slug globs; when non-empty, a call must match one of these.
    pub allow: Vec<String>,
    /// Slug globs that are always refused, checked before `allow`.
    pub deny: Vec<String>,
    /// How much of the risky tail needs a human.
    pub confirm: ConfirmLevel,
    /// What the node is called in a confirmation prompt — `VTA`, `VTC` — so
    /// the human asked knows which thing the operation is about to touch.
    pub node: &'static str,
}

impl Guard {
    /// Decide one call. `uri` is the canonical Trust Task URI — for the
    /// convenience tools, the URI they wrap.
    pub fn decide(&self, uri: &str) -> Decision {
        let risk = classify(uri);
        let slug = slug_of(uri).unwrap_or(uri);

        if let Some(p) = self.deny.iter().find(|p| glob_match(p, slug)) {
            return Decision::Deny(format!(
                "'{slug}' is denied by this bridge's --deny '{p}'. Remove that pattern to allow it."
            ));
        }
        if !self.allow.is_empty() && !self.allow.iter().any(|p| glob_match(p, slug)) {
            return Decision::Deny(format!(
                "'{slug}' is not in this bridge's --allow list ({}). Add it, or drop --allow to \
                 fall back to the risk rules.",
                self.allow.join(", ")
            ));
        }
        if self.read_only && risk != Risk::ReadOnly {
            return Decision::Deny(format!(
                "'{slug}' is {risk} and this bridge runs with --read-only. Restart it without \
                 --read-only to permit it."
            ));
        }
        if self.confirm.wants(risk) {
            let node = if self.node.is_empty() {
                String::new()
            } else {
                format!("{} ", self.node)
            };
            return Decision::Confirm(format!("Approve {risk} {node}operation '{slug}'?"));
        }
        Decision::Allow
    }

    /// A one-line summary for the startup banner and `vta_status`.
    pub fn summary(&self) -> String {
        let mut parts = vec![format!("confirm={}", self.confirm.label())];
        if self.read_only {
            parts.push("read-only".into());
        }
        if !self.allow.is_empty() {
            parts.push(format!("allow=[{}]", self.allow.join(",")));
        }
        if !self.deny.is_empty() {
            parts.push(format!("deny=[{}]", self.deny.join(",")));
        }
        parts.join(" ")
    }
}

/// Slug-glob match, the same shape `vta_supported_tasks` patterns use: `*`
/// matches everything, a trailing `/*` matches a family, anything else is an
/// exact slug.
///
/// Deliberately not a full glob. A pattern language with more corners than this
/// is a pattern language an operator gets subtly wrong while believing they
/// denied something.
pub fn glob_match(pattern: &str, slug: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    match pattern.strip_suffix("/*") {
        // `acl/*` matches `acl/grant` but not `acl` itself.
        Some(prefix) => slug
            .strip_prefix(prefix)
            .is_some_and(|r| r.starts_with('/')),
        None => pattern == slug,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACL_GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";
    const CONTEXTS_LIST: &str = "https://trusttasks.org/spec/vta/contexts/list/1.0";
    const CONTEXTS_DELETE: &str = "https://trusttasks.org/spec/vta/contexts/delete/1.1";
    const KEYS_SIGN: &str = "https://trusttasks.org/spec/keys/sign/0.1";

    #[test]
    fn slug_strips_the_prefix_and_the_version() {
        assert_eq!(slug_of(ACL_GRANT), Some("acl/grant"));
        assert_eq!(slug_of(CONTEXTS_LIST), Some("vta/contexts/list"));
        assert_eq!(
            slug_of("https://trusttasks.org/spec/trust-task-discovery/0.3"),
            Some("trust-task-discovery")
        );
    }

    #[test]
    fn a_family_namespace_is_not_a_task() {
        // These constants exist in the SDK catalog module; treating one as a
        // task would classify it by a verb that is really a family name.
        assert_eq!(slug_of("https://trusttasks.org/spec/acl/"), None);
        assert_eq!(slug_of("https://trusttasks.org/spec/vta/"), None);
        assert_eq!(slug_of("not-a-uri"), None);
    }

    #[test]
    fn verbs_classify() {
        assert_eq!(classify(CONTEXTS_LIST), Risk::ReadOnly);
        assert_eq!(classify(CONTEXTS_DELETE), Risk::Destructive);
        assert_eq!(
            classify("https://trusttasks.org/spec/vta/contexts/create/1.0"),
            Risk::Mutating
        );
        assert_eq!(classify(KEYS_SIGN), Risk::Sensitive);
        assert_eq!(classify(ACL_GRANT), Risk::Sensitive);
    }

    #[test]
    fn preview_delete_is_a_read_not_a_delete() {
        // The verb ends in "delete" but the operation only reports what a
        // delete would remove. Substring matching on the verb would have made
        // a preview refuse under --read-only.
        assert_eq!(
            classify("https://trusttasks.org/spec/vta/contexts/preview-delete/1.0"),
            Risk::ReadOnly
        );
    }

    #[test]
    fn an_unknown_verb_is_mutating_never_read_only() {
        // The catalog grows without this crate. A URI it has never seen must
        // not be handed through a --read-only bridge.
        let unknown = "https://trusttasks.org/spec/vta/frobnicate/twiddle/9.9";
        assert_eq!(classify(unknown), Risk::Mutating);
        let guard = Guard {
            read_only: true,
            ..Guard::default()
        };
        assert!(matches!(guard.decide(unknown), Decision::Deny(_)));
    }

    /// Census: every pinned request Type URI — every version any VTI node
    /// serves or sends, whichever bridge reaches it — must classify off an
    /// override or a known verb. A new verb landing in a pinned specification
    /// fails here rather than quietly defaulting to `Mutating` forever. Each
    /// bridge runs the same census over what it can dispatch.
    #[test]
    fn every_pinned_request_uri_has_a_known_verb() {
        let request_uris = vti_specs::schema_index::type_uris().filter(|uri| !uri.contains('#'));
        assert_every_verb_is_known(request_uris);
    }

    #[test]
    fn the_confirm_prompt_names_the_node() {
        let guard = Guard {
            node: "VTC",
            ..Guard::default()
        };
        match guard.decide(CONTEXTS_DELETE) {
            Decision::Confirm(prompt) => {
                assert_eq!(
                    prompt,
                    "Approve destructive VTC operation 'vta/contexts/delete'?"
                );
            }
            other => panic!("expected a confirmation, got {other:?}"),
        }
        match Guard::default().decide(CONTEXTS_DELETE) {
            Decision::Confirm(prompt) => {
                assert_eq!(
                    prompt,
                    "Approve destructive operation 'vta/contexts/delete'?"
                );
            }
            other => panic!("expected a confirmation, got {other:?}"),
        }
    }

    #[test]
    fn deny_beats_allow() {
        let guard = Guard {
            allow: vec!["*".into()],
            deny: vec!["vta/contexts/*".into()],
            confirm: ConfirmLevel::Never,
            ..Guard::default()
        };
        assert!(matches!(guard.decide(CONTEXTS_LIST), Decision::Deny(_)));
        assert_eq!(guard.decide(ACL_GRANT), Decision::Allow);
    }

    #[test]
    fn a_non_empty_allow_list_denies_everything_else() {
        let guard = Guard {
            allow: vec!["vta/memory/*".into()],
            confirm: ConfirmLevel::Never,
            ..Guard::default()
        };
        assert_eq!(
            guard.decide("https://trusttasks.org/spec/vta/memory/list/0.1"),
            Decision::Allow
        );
        match guard.decide(CONTEXTS_LIST) {
            Decision::Deny(msg) => assert!(msg.contains("--allow"), "{msg}"),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn confirm_levels_are_cumulative() {
        let destructive = Guard::default();
        assert_eq!(destructive.confirm, ConfirmLevel::Destructive);
        assert_eq!(destructive.decide(KEYS_SIGN), Decision::Allow);
        assert!(matches!(
            destructive.decide(CONTEXTS_DELETE),
            Decision::Confirm(_)
        ));

        let sensitive = Guard {
            confirm: ConfirmLevel::Sensitive,
            ..Guard::default()
        };
        assert!(matches!(sensitive.decide(KEYS_SIGN), Decision::Confirm(_)));
        assert!(matches!(
            sensitive.decide(CONTEXTS_DELETE),
            Decision::Confirm(_)
        ));
        assert_eq!(sensitive.decide(CONTEXTS_LIST), Decision::Allow);

        let always = Guard {
            confirm: ConfirmLevel::Always,
            ..Guard::default()
        };
        // Even at `always`, reads run unprompted — a bridge that asks before
        // every `list` gets its prompts clicked through unread.
        assert_eq!(always.decide(CONTEXTS_LIST), Decision::Allow);
        assert!(matches!(
            always.decide("https://trusttasks.org/spec/vta/contexts/create/1.0"),
            Decision::Confirm(_)
        ));
    }

    #[test]
    fn globs_match_families_not_prefixes() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("acl/*", "acl/grant"));
        assert!(!glob_match("acl/*", "acl"));
        // `vault/*` must not swallow `vault-other/…`.
        assert!(!glob_match("vault/*", "vault-other/get"));
        assert!(glob_match("vault/credentials/get", "vault/credentials/get"));
        assert!(!glob_match("vault/credentials/get", "vault/credentials"));
    }

    #[test]
    fn confirm_level_parses_and_rejects() {
        assert_eq!(ConfirmLevel::parse("never").unwrap(), ConfirmLevel::Never);
        assert_eq!(
            ConfirmLevel::parse("SENSITIVE").unwrap(),
            ConfirmLevel::Sensitive
        );
        assert!(ConfirmLevel::parse("sometimes").is_err());
    }
}
