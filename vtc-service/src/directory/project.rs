//! The projection: what of one entry one viewer is shown.
//!
//! A value leaves only where the subject's visibility admits the viewer, the
//! field's ceiling admits the viewer, and the community's `directory` policy
//! permits it — the three intersected, never unioned (VTI-DIR-020, -021). This
//! module computes the first two and asks the policy only to narrow what they
//! allow: a policy answer naming a field the host withheld changes nothing.
//! Which audiences a viewer is in is the host's to decide, never the policy's.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use vti_common::error::AppError;

use super::model::{Audience, Card, FieldDef, FieldSource, FieldState, Listing};
use crate::acl::VtcAclEntry;
use crate::ceremony::{
    self, Evidence, Facts, Purpose, Verdict, VerifiedFacts,
    facts::{Actor, Context, MemberState, State, Subject as FactSubject},
};
use crate::members::Member;
use crate::policy::engine::CompiledPolicy;

/// Who is reading, and which audiences they are in.
#[derive(Debug, Clone, Default)]
pub struct Viewer {
    pub did: String,
    /// The viewer's community role, for the policy's facts.
    pub role: Option<String>,
    /// An active member (VTI-MEM-001), not merely an ACL entry.
    pub active_member: bool,
    /// Holds `vtc.directory.admin`: the `admins` audience, every entry and
    /// every field.
    pub directory_admin: bool,
    /// Holds `vtc.members.manage`: the `admins` audience for derived fields,
    /// and addressing an entry by DID.
    pub members_manage: bool,
    /// The members this viewer holds an in-force edge with, by membership DID.
    pub connected: BTreeSet<String>,
    /// The community groups that count as the viewer's for the `groups`
    /// audience: those they belong to whose member list they may see
    /// (`crate::groups::audience_groups`).
    pub groups: BTreeSet<String>,
    /// The public: anyone, unidentified. Never a directory reader — only the
    /// viewer an external card is computed for ([`public_fields`]).
    pub public: bool,
}

impl Viewer {
    /// Anyone at all, with no standing in the community.
    pub fn public() -> Self {
        Viewer {
            public: true,
            ..Viewer::default()
        }
    }
}

impl Viewer {
    /// Whether this viewer may use the directory at all (`entries/*` item 1).
    pub fn may_read(&self) -> bool {
        self.active_member || self.directory_admin || self.members_manage
    }

    /// Whether this viewer is an administrator of the directory, who reads
    /// every entry whole (`entries/list` item 5).
    pub fn is_admin(&self) -> bool {
        self.directory_admin
    }

    /// May this viewer see entries whose member is not active (VTI-DIR-111)?
    fn sees_inactive(&self) -> bool {
        self.directory_admin || self.members_manage
    }
}

/// One subject: their card and what the community's other records say of them.
#[derive(Debug, Clone)]
pub struct Subject {
    pub card: Card,
    /// The community role, from the live ACL entry.
    pub role: String,
    pub joined_at: DateTime<Utc>,
    pub personhood: bool,
    /// Active per VTI-MEM-001: a live, unsuspended, non-`application` entry
    /// and a member record not removed.
    pub active: bool,
    /// The community groups the subject is in.
    pub groups: BTreeSet<String>,
}

impl Subject {
    pub fn from_records(
        mut card: Card,
        entry: Option<&VtcAclEntry>,
        member: Option<&Member>,
    ) -> Self {
        // A verified value whose credential lapsed is shown to nobody, even
        // before the sweeper withdraws it (`card/present` item 7).
        let at = Utc::now();
        card.values.retain(|_, v| !super::present::lapsed(v, at));
        let now = vti_common::auth::session::now_epoch();
        let active = matches!(
            (entry, member),
            (Some(e), Some(m))
                if !e.is_expired(now)
                    && !e.is_suspended()
                    && e.role != crate::acl::VtcRole::Application
                    && !m.is_removed()
        );
        Subject {
            role: entry.map(|e| e.role.to_string()).unwrap_or_default(),
            joined_at: member.map(|m| m.joined_at).unwrap_or_else(Utc::now),
            personhood: member.is_some_and(|m| m.personhood),
            active,
            groups: BTreeSet::new(),
            card,
        }
    }

    fn derived(&self, key: &str) -> Option<Value> {
        match key {
            "role" => Some(Value::String(self.role.clone())),
            "joinedAt" => Some(Value::String(self.joined_at.format("%Y-%m-%d").to_string())),
            "did" => Some(Value::String(self.card.did.clone())),
            "personhood" => Some(Value::Bool(self.personhood)),
            _ => None,
        }
    }

    /// The groups that count as this subject's `groups` audience: those they
    /// named, among those they are in.
    fn audience_groups(&self) -> BTreeSet<&String> {
        match &self.card.group_audience {
            Some(named) => self.groups.iter().filter(|g| named.contains(g)).collect(),
            None => self.groups.iter().collect(),
        }
    }
}

/// Whether `viewer` is in `audience` for `field` of `subject`.
fn in_audience(viewer: &Viewer, subject: &Subject, field: &FieldDef, audience: Audience) -> bool {
    let admin =
        viewer.directory_admin || (field.source == FieldSource::Derived && viewer.members_manage);
    match audience {
        Audience::Admins => admin,
        Audience::Groups => {
            admin
                || subject
                    .audience_groups()
                    .iter()
                    .any(|g| viewer.groups.contains(*g))
        }
        Audience::Connections => admin || viewer.connected.contains(&subject.card.did),
        Audience::Members => admin || viewer.active_member,
        Audience::Public => true,
    }
}

/// The fields of `subject` the host lets `viewer` see, before policy: every
/// active field with a value whose chosen visibility and ceiling both admit the
/// viewer. The subject, and the directory's administrators, see every active
/// field.
fn host_fields(viewer: &Viewer, subject: &Subject, schema: &[FieldDef]) -> Map<String, Value> {
    let mut out = Map::new();
    let whole = viewer.did == subject.card.did || viewer.is_admin();
    for f in schema.iter().filter(|f| f.state == FieldState::Active) {
        let value = if f.source == FieldSource::Derived {
            subject.derived(&f.key)
        } else {
            subject.card.values.get(&f.key).cloned()
        };
        let Some(value) = value else { continue };
        if whole
            || (in_audience(viewer, subject, f, subject.card.chosen(f))
                && in_audience(viewer, subject, f, f.ceiling))
        {
            out.insert(f.key.clone(), value);
        }
    }
    out
}

/// The answer to "what of this entry may this viewer see?".
#[derive(Debug, Clone, PartialEq)]
pub enum Projection {
    /// Nothing: the entry does not exist for this viewer (VTI-DIR-110).
    None,
    /// The fields, and whether the viewer is connected to the subject.
    Some {
        fields: Map<String, Value>,
        connected: bool,
        shared_groups: Vec<String>,
    },
}

/// What the projection needs that does not change from entry to entry.
pub struct ProjectionContext<'a> {
    pub schema: &'a [FieldDef],
    pub policy: &'a CompiledPolicy,
    pub community_did: &'a str,
    pub member_count: u64,
    pub now: DateTime<Utc>,
}

/// Legacy `directory` policy field names, from before the card model.
fn current_name(key: &str) -> &str {
    match key {
        "joined_at" => "joinedAt",
        other => other,
    }
}

/// Project `subject` for `viewer`.
///
/// `how` says how the entry was reached, which decides whether its listing
/// admits it: a browse only finds `listed`, a search `listed` and `findable`,
/// a read by identifier anything but `hidden`.
pub fn project(
    ctx: &ProjectionContext<'_>,
    viewer: &Viewer,
    subject: &Subject,
    how: Reached,
) -> Result<Projection, AppError> {
    let own = viewer.did == subject.card.did;
    if !own {
        if !subject.active && !viewer.sees_inactive() {
            return Ok(Projection::None);
        }
        if !viewer.is_admin() && !how.admits(subject.card.discoverability.listing) {
            return Ok(Projection::None);
        }
    }
    let mut fields = host_fields(viewer, subject, ctx.schema);
    let connected = viewer.connected.contains(&subject.card.did);
    let shared_groups: Vec<String> = subject
        .groups
        .intersection(&viewer.groups)
        .cloned()
        .collect();

    if !own {
        match narrow_by_policy(ctx, viewer, subject, &fields)? {
            Narrowing::Deny => return Ok(Projection::None),
            Narrowing::Keep => {}
            Narrowing::To(allowed) => fields.retain(|k, _| allowed.contains(k.as_str())),
        }
        if fields.is_empty() {
            return Ok(Projection::None);
        }
    }
    Ok(Projection::Some {
        fields,
        connected,
        shared_groups,
    })
}

/// Every active field of `subject` that holds a value, stored or derived —
/// what an administrator reads of an entry whole, and what
/// `vtc/directory/export` carries. Never a note: notes are not fields.
pub fn every_field(schema: &[FieldDef], subject: &Subject) -> Map<String, Value> {
    let mut out = Map::new();
    for f in schema.iter().filter(|f| f.state == FieldState::Active) {
        let value = if f.source == FieldSource::Derived {
            subject.derived(&f.key)
        } else {
            subject.card.values.get(&f.key).cloned()
        };
        if let Some(v) = value {
            out.insert(f.key.clone(), v);
        }
    }
    out
}

/// The subject's public values: what the public would be shown of their card —
/// visibility `public`, ceiling `public`, and the `directory` policy permitting
/// it to a viewer with no standing (`card/publish` item 4). Empty for a member
/// who is not active. The listing plays no part: it decides who may find an
/// entry inside the community, not what a card published beyond it carries.
pub fn public_fields(
    ctx: &ProjectionContext<'_>,
    subject: &Subject,
) -> Result<Map<String, Value>, AppError> {
    if !subject.active {
        return Ok(Map::new());
    }
    let viewer = Viewer::public();
    let mut fields = host_fields(&viewer, subject, ctx.schema);
    if fields.is_empty() {
        return Ok(fields);
    }
    match narrow_by_policy(ctx, &viewer, subject, &fields)? {
        Narrowing::Deny => return Ok(Map::new()),
        Narrowing::Keep => {}
        Narrowing::To(allowed) => fields.retain(|k, _| allowed.contains(k.as_str())),
    }
    Ok(fields)
}

/// How a read reached an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reached {
    Browse,
    Search,
    Identifier,
}

impl Reached {
    fn admits(self, listing: Listing) -> bool {
        match self {
            Reached::Browse => listing == Listing::Listed,
            Reached::Search | Reached::Identifier => listing != Listing::Hidden,
        }
    }
}

enum Narrowing {
    Deny,
    Keep,
    To(BTreeSet<String>),
}

fn narrow_by_policy(
    ctx: &ProjectionContext<'_>,
    viewer: &Viewer,
    subject: &Subject,
    permitted: &Map<String, Value>,
) -> Result<Narrowing, AppError> {
    let facts = Facts {
        purpose: Purpose::Directory,
        now: ctx.now,
        actor: Actor {
            did: viewer.did.clone(),
            role: viewer.role.clone(),
            authenticated: !viewer.public,
        },
        subject: FactSubject {
            did: subject.card.did.clone(),
        },
        context: Context {
            community_did: ctx.community_did.to_string(),
            channel: "trust-task".to_string(),
            member_count: ctx.member_count,
            thread_id: None,
        },
        evidence: Evidence {
            vetting: None,
            invitation: None,
            presentation: None,
            // What the host already allows, so a policy can narrow by field
            // and by audience without re-deriving either.
            request: Some(json!({
                "entryId": subject.card.entry_id,
                "fields_requested": permitted.keys().collect::<Vec<_>>(),
                "listing": subject.card.discoverability.listing.as_str(),
                "viewer": {
                    "directoryAdmin": viewer.directory_admin,
                    "membersManage": viewer.members_manage,
                    "connected": viewer.connected.contains(&subject.card.did),
                    "public": viewer.public,
                },
            })),
            criterion: None,
        },
        state: State {
            subject_member: Some(MemberState {
                role: subject.role.clone(),
                status: if subject.active { "active" } else { "removed" }.to_string(),
                joined_at: subject.joined_at,
                personhood: None,
            }),
        },
    };
    let verified = VerifiedFacts::assemble(facts).map_err(AppError::from)?;
    match ceremony::decide(&verified, ctx.policy)? {
        Verdict::Allow(a) => Ok(match a.fields {
            None => Narrowing::Keep,
            Some(list) => Narrowing::To(list.iter().map(|k| current_name(k).to_string()).collect()),
        }),
        Verdict::Deny(_) => Ok(Narrowing::Deny),
        // Directory reads are synchronous: a policy that refers or asks for
        // more is misconfigured, and the safe reading is "nothing".
        Verdict::Refer(_) | Verdict::RequestMore(_) => Ok(Narrowing::Deny),
    }
}

/// The `DirectoryEntry` wire form of a projection.
pub fn entry_wire(entry_id: &str, projection: &Projection) -> Option<Value> {
    let Projection::Some {
        fields,
        connected,
        shared_groups,
    } = projection
    else {
        return None;
    };
    let mut out = json!({ "entryId": entry_id, "fields": fields });
    // Present only when true: `false` would say the community looked.
    if *connected {
        out["connected"] = Value::Bool(true);
    }
    if !shared_groups.is_empty() {
        out["sharedGroups"] = json!(shared_groups);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::cards::fresh;
    use crate::directory::fields::base_fields;
    use crate::directory::model::Settings;
    use crate::policy::engine::compile;

    const ALLOW_ALL: &str = r#"package vtc.directory
import rego.v1
default decision := {"effect": "deny", "with": {"code": "x"}}
decision := {"effect": "allow", "with": {}} if input.actor.authenticated == true
"#;

    fn policy(src: &str) -> CompiledPolicy {
        compile(src, uuid::Uuid::nil()).unwrap()
    }

    fn subject(listing: Listing) -> Subject {
        let mut card = fresh(
            "did:example:carol",
            &Settings::default(),
            Some("Carol"),
            Utc::now(),
        );
        card.discoverability.listing = listing;
        card.values.insert("pronouns".into(), json!("she/her"));
        Subject {
            card,
            role: "member".into(),
            joined_at: Utc::now(),
            personhood: true,
            active: true,
            groups: BTreeSet::new(),
        }
    }

    fn member(did: &str) -> Viewer {
        Viewer {
            did: did.into(),
            role: Some("member".into()),
            active_member: true,
            ..Viewer::default()
        }
    }

    fn run(p: &CompiledPolicy, v: &Viewer, s: &Subject, how: Reached) -> Projection {
        let schema = base_fields();
        let ctx = ProjectionContext {
            schema: &schema,
            policy: p,
            community_did: "did:example:community",
            member_count: 2,
            now: Utc::now(),
        };
        project(&ctx, v, s, how).unwrap()
    }

    fn keys(p: &Projection) -> Vec<String> {
        match p {
            Projection::Some { fields, .. } => fields.keys().cloned().collect(),
            Projection::None => vec![],
        }
    }

    #[test]
    fn vti_dir_041_a_member_sees_name_and_role_by_default() {
        let p = policy(ALLOW_ALL);
        let got = run(
            &p,
            &member("did:example:dave"),
            &subject(Listing::Listed),
            Reached::Browse,
        );
        assert_eq!(keys(&got), vec!["displayName", "role"]);
    }

    #[test]
    fn vti_dir_022_the_subject_sees_everything() {
        let p = policy(ALLOW_ALL);
        let got = run(
            &p,
            &member("did:example:carol"),
            &subject(Listing::Hidden),
            Reached::Browse,
        );
        let k = keys(&got);
        for want in [
            "displayName",
            "pronouns",
            "role",
            "joinedAt",
            "did",
            "personhood",
        ] {
            assert!(k.contains(&want.to_string()), "{want} in {k:?}");
        }
    }

    #[test]
    fn vti_dir_020_choice_and_ceiling_are_intersected() {
        let p = policy(ALLOW_ALL);
        let mut s = subject(Listing::Listed);
        s.card
            .visibility
            .insert("pronouns".into(), Audience::Public);
        let mut schema = base_fields();
        // The community narrows the ceiling after the member chose public.
        schema
            .iter_mut()
            .find(|f| f.key == "pronouns")
            .unwrap()
            .ceiling = Audience::Admins;
        let ctx = ProjectionContext {
            schema: &schema,
            policy: &p,
            community_did: "did:example:community",
            member_count: 2,
            now: Utc::now(),
        };
        let got = project(&ctx, &member("did:example:dave"), &s, Reached::Browse).unwrap();
        assert!(!keys(&got).contains(&"pronouns".to_string()));
    }

    #[test]
    fn connections_see_what_is_shown_to_connections() {
        let p = policy(ALLOW_ALL);
        let mut s = subject(Listing::Listed);
        s.card
            .visibility
            .insert("pronouns".into(), Audience::Connections);
        let stranger = member("did:example:dave");
        assert!(!keys(&run(&p, &stranger, &s, Reached::Browse)).contains(&"pronouns".into()));
        let mut friend = member("did:example:erin");
        friend.connected.insert("did:example:carol".into());
        let got = run(&p, &friend, &s, Reached::Browse);
        assert!(keys(&got).contains(&"pronouns".into()));
        assert!(matches!(
            got,
            Projection::Some {
                connected: true,
                ..
            }
        ));
    }

    #[test]
    fn vti_dir_112_listing_decides_how_an_entry_is_found() {
        let p = policy(ALLOW_ALL);
        let v = member("did:example:dave");
        assert_eq!(
            run(&p, &v, &subject(Listing::Findable), Reached::Browse),
            Projection::None
        );
        assert_ne!(
            run(&p, &v, &subject(Listing::Findable), Reached::Search),
            Projection::None
        );
        assert_eq!(
            run(&p, &v, &subject(Listing::Hidden), Reached::Search),
            Projection::None
        );
        assert_eq!(
            run(&p, &v, &subject(Listing::Hidden), Reached::Identifier),
            Projection::None
        );
        let admin = Viewer {
            directory_admin: true,
            ..member("did:example:admin")
        };
        let got = run(&p, &admin, &subject(Listing::Hidden), Reached::Browse);
        assert!(
            keys(&got).contains(&"did".to_string()),
            "admins see every entry whole"
        );
    }

    #[test]
    fn vti_dir_111_an_inactive_member_is_never_projected_to_members() {
        let p = policy(ALLOW_ALL);
        let mut s = subject(Listing::Listed);
        s.active = false;
        assert_eq!(
            run(&p, &member("did:example:dave"), &s, Reached::Browse),
            Projection::None
        );
    }

    #[test]
    fn vti_dir_021_policy_narrows_and_never_widens() {
        let narrowing = policy(
            r#"package vtc.directory
import rego.v1
default decision := {"effect": "allow", "with": {"fields": ["role", "did", "joined_at"]}}
"#,
        );
        let got = run(
            &narrowing,
            &member("did:example:dave"),
            &subject(Listing::Listed),
            Reached::Browse,
        );
        // `did` and `joinedAt` are named but the host withheld them.
        assert_eq!(keys(&got), vec!["role"]);
        let deny = policy(
            "package vtc.directory\nimport rego.v1\ndefault decision := {\"effect\": \"deny\", \"with\": {\"code\": \"no\"}}\n",
        );
        assert_eq!(
            run(
                &deny,
                &member("did:example:dave"),
                &subject(Listing::Listed),
                Reached::Browse
            ),
            Projection::None
        );
    }

    #[test]
    fn members_manage_sees_derived_fields_only() {
        let p = policy(ALLOW_ALL);
        let moderator = Viewer {
            members_manage: true,
            ..member("did:example:mod")
        };
        let k = keys(&run(
            &p,
            &moderator,
            &subject(Listing::Listed),
            Reached::Browse,
        ));
        assert!(k.contains(&"did".to_string()) && k.contains(&"joinedAt".to_string()));
        assert!(!k.contains(&"pronouns".to_string()));
    }

    #[test]
    fn entry_wire_omits_false_connection() {
        let w = entry_wire(
            "dir_aaaaaaaaaaaaaaaa",
            &Projection::Some {
                fields: Map::new(),
                connected: false,
                shared_groups: vec![],
            },
        )
        .unwrap();
        assert!(w.get("connected").is_none() && w.get("sharedGroups").is_none());
    }
}
