//! What `cnm vetting bootstrap-pgp` does for each link statement.
//!
//! Pure: it combines the verified links, the web of trust's distances and the
//! community's roster (active members and live vetter grants) into one row per
//! statement. The command renders the rows for `--dry-run` and grants the
//! `grant` rows otherwise; nothing here talks to the community.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::wot::{Keyring, LinkCheck, Reach};

/// What the bootstrap does, or would do, for one link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "camelCase")]
pub enum Action {
    /// A member within `--max-depth` with no live grant: grant them.
    Grant,
    /// The member already holds a live vetter grant.
    #[serde(rename_all = "camelCase")]
    AlreadyGranted { endorsement_id: String },
    /// The linked key is unreachable from the roots, or further than
    /// `--max-depth`.
    TooFar { reason: String },
    /// The DID is not an active member of the community.
    NotAMember,
    /// The link statement is not trusted.
    InvalidLink { reason: String },
}

/// One link statement and what the bootstrap does about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanRow {
    /// The link file.
    pub source: String,
    /// The DID the statement links, when it could be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_did: Option<String>,
    /// The linked key's primary fingerprint, when a signature identified it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// The key's primary user ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_user_id: Option<String>,
    /// Certification hops from the nearest root; absent when unreachable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
    /// Fingerprints from a root to the key, both ends included.
    pub path: Vec<String>,
    /// What happens.
    #[serde(flatten)]
    pub action: Action,
}

/// What the community knows that the web of trust does not.
#[derive(Debug, Clone, Copy)]
pub struct Roster<'a> {
    /// DIDs of the community's active members.
    pub members: &'a BTreeSet<String>,
    /// Member DID → endorsement id of their live vetter grant.
    pub live_grants: &'a BTreeMap<String, String>,
}

/// One row per link statement, sorted by member DID then file.
///
/// The action is the first that applies, in this order: an untrusted link; a
/// DID that is not a member (nothing can be granted to a non-member however
/// well their key is certified); a key unreachable or beyond `max_depth`; a
/// live grant already held; otherwise `grant`. The same key linking the same
/// DID in two files is one row.
pub fn plan(
    checks: &[LinkCheck],
    keyring: &Keyring,
    reach: &BTreeMap<String, Reach>,
    roster: Roster<'_>,
    max_depth: u32,
) -> Vec<PlanRow> {
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut ordered: Vec<&LinkCheck> = checks.iter().collect();
    ordered.sort_by(|a, b| a.source.cmp(&b.source));

    let mut rows = Vec::new();
    for check in ordered {
        if check.problem.is_none()
            && let (Some(did), Some(fp)) = (&check.member_did, &check.fingerprint)
            && !seen.insert((did.clone(), fp.clone()))
        {
            continue;
        }
        let key_reach = check.fingerprint.as_ref().and_then(|fp| reach.get(fp));
        let action = match (&check.problem, &check.member_did) {
            (Some(problem), _) => Action::InvalidLink {
                reason: problem.to_string(),
            },
            (None, None) => Action::InvalidLink {
                reason: "no DID".into(),
            },
            (None, Some(did)) if !roster.members.contains(did) => Action::NotAMember,
            (None, Some(did)) => match key_reach {
                None => Action::TooFar {
                    reason: "not reachable from any root".into(),
                },
                Some(r) if r.depth > max_depth => Action::TooFar {
                    reason: format!("depth {} exceeds --max-depth {max_depth}", r.depth),
                },
                Some(_) => match roster.live_grants.get(did) {
                    Some(endorsement_id) => Action::AlreadyGranted {
                        endorsement_id: endorsement_id.clone(),
                    },
                    None => Action::Grant,
                },
            },
        };
        rows.push(PlanRow {
            source: check.source.clone(),
            member_did: check.member_did.clone(),
            fingerprint: check.fingerprint.clone(),
            primary_user_id: check
                .fingerprint
                .as_ref()
                .and_then(|fp| keyring.get(fp))
                .and_then(|k| k.primary_user_id.clone()),
            depth: key_reach.map(|r| r.depth),
            path: key_reach.map(|r| r.path.clone()).unwrap_or_default(),
            action,
        });
    }
    rows.sort_by(|a, b| (&a.member_did, &a.source).cmp(&(&b.member_did, &b.source)));
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vetting::test_web::{DAY, link_text, now};
    use crate::vetting::wot::tests::Web;
    use crate::vetting::wot::{check_link, mark_ambiguous, shortest_paths};

    /// Links for the web in `wot::tests`, against a community where alice,
    /// bob, carol and erin are members and bob already vets. Max depth 2.
    #[test]
    fn members_within_depth_are_granted_and_everyone_else_is_explained() {
        let web = Web::new();
        let ring = web.keyring();
        let t = now();
        let roots = ring.resolve_roots(&[web.root.fingerprint()]).unwrap();
        let (edges, _) = ring.certifications(t);
        let reach = shortest_paths(&edges, &roots);

        let signed = |p: &crate::vetting::test_web::Person, did: &str| {
            p.clearsign(&link_text(did), t - DAY, false)
        };
        let tampered = signed(&web.bob, "did:key:zBob").replace("zBob", "zBobby");
        let mut checks = vec![
            check_link(&ring, "alice.asc", &signed(&web.alice, "did:key:zAlice"), t),
            check_link(
                &ring,
                "alice-copy.asc",
                &signed(&web.alice, "did:key:zAlice"),
                t,
            ),
            check_link(&ring, "bob.asc", &signed(&web.bob, "did:key:zBob"), t),
            check_link(&ring, "carol.asc", &signed(&web.carol, "did:key:zCarol"), t),
            check_link(&ring, "dave.asc", &signed(&web.dave, "did:key:zDave"), t),
            check_link(&ring, "erin.asc", &signed(&web.erin, "did:key:zErin"), t),
            check_link(&ring, "mallory.asc", &tampered, t),
        ];
        mark_ambiguous(&mut checks);

        let members: BTreeSet<String> = [
            "did:key:zAlice",
            "did:key:zBob",
            "did:key:zCarol",
            "did:key:zErin",
        ]
        .map(String::from)
        .into();
        let live_grants = BTreeMap::from([("did:key:zBob".to_string(), "e-bob".to_string())]);
        let rows = plan(
            &checks,
            &ring,
            &reach,
            Roster {
                members: &members,
                live_grants: &live_grants,
            },
            2,
        );

        let by_did = |did: &str| {
            rows.iter()
                .filter(|r| r.member_did.as_deref() == Some(did))
                .collect::<Vec<_>>()
        };
        let alice = by_did("did:key:zAlice");
        assert_eq!(alice.len(), 1, "a repeated link is one row");
        assert_eq!(alice[0].action, Action::Grant);
        assert_eq!(alice[0].depth, Some(1));
        assert_eq!(
            alice[0].path,
            vec![web.root.fingerprint(), web.alice.fingerprint()]
        );
        assert_eq!(
            alice[0].primary_user_id.as_deref(),
            Some("Alice <alice@kernel.example>")
        );

        assert_eq!(
            by_did("did:key:zBob")[0].action,
            Action::AlreadyGranted {
                endorsement_id: "e-bob".into()
            }
        );
        assert_eq!(
            by_did("did:key:zCarol")[0].action,
            Action::TooFar {
                reason: "depth 3 exceeds --max-depth 2".into()
            }
        );
        assert_eq!(by_did("did:key:zDave")[0].action, Action::NotAMember);
        assert_eq!(
            by_did("did:key:zErin")[0].action,
            Action::TooFar {
                reason: "not reachable from any root".into()
            },
            "erin's only certification expired"
        );
        assert!(matches!(
            by_did("did:key:zBobby")[0].action,
            Action::InvalidLink { .. }
        ));

        // The JSON an automation reads.
        let json = serde_json::to_value(alice[0]).unwrap();
        assert_eq!(json["action"], "grant");
        assert_eq!(json["memberDid"], "did:key:zAlice");
        assert_eq!(json["depth"], 1);
        let bob = serde_json::to_value(by_did("did:key:zBob")[0]).unwrap();
        assert_eq!(bob["action"], "alreadyGranted");
        assert_eq!(bob["endorsementId"], "e-bob");
    }
}
