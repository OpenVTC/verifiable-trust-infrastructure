//! Room-scoped credentials for the storage configs whose authority this community
//! holds itself: `ambient` (the machine's own cloud identity) and `sealed` (a
//! long-lived credential set with `vtc/storage/credentials/set`)
//! (`vtc/storage/configs/create/0.2`, "Room-scoped credentials").
//!
//! With `vta-account` the community's VTA mints and downscopes every credential. With
//! `ambient` and `sealed` the community does what the VTA would:
//!
//! - one credential per (config, scope, access), where a scope is **one room's
//!   prefix** (`<config prefix>rooms/<32 hex of SHA-256(roomId)>/`) or the probe's
//!   (`<config prefix>probe/`) and never the bucket (rule 1);
//! - limited to the object actions of one kind of operation — read, write or delete
//!   ([`Access`]) — and never listing, a bucket- or account-level action, an ACL,
//!   policy or IAM action, or a wildcard (rule 2);
//! - built from validated values by an encoder: the AWS session policy by a JSON
//!   encoder ([`aws::session_policy`]), the Google access boundary's condition by a
//!   CEL builder that quotes its literals ([`gcs::access_boundary`]) (rule 5);
//! - asked for 900 seconds wherever the provider takes a lifetime, and dropped
//!   [`MAX_LIFETIME`] after it was obtained whatever the provider granted (rules 3, 4,
//!   6);
//! - held in memory only ([`CredentialCache`]), never logged, audited, returned or
//!   persisted, and dropped with the config's backend when the config changes or the
//!   service stops (rule 7);
//! - and never replaced by the unscoped authority when it cannot be obtained: the
//!   operation fails, and a probe says where (rule 8).
//!
//! Whether `ambient` and `sealed` exist on this host at all is its operator's choice
//! ([`HostAuth`], `[rooms.files.auth]`, item 9).

pub mod aws;
pub mod gcs;

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::config::StorageAuthHostConfig;

/// The longest any room-scoped credential is used after it was obtained, whatever the
/// provider granted (rule 6).
pub const MAX_LIFETIME: Duration = Duration::from_secs(15 * 60);

/// The lifetime asked of a provider that takes one (rules 3 and 4).
pub const REQUESTED_LIFETIME_SECS: i32 = 900;

/// A cached credential is renewed this long before it must stop being used, so a
/// request presigned with it lives a useful while.
const RENEW_MARGIN: Duration = Duration::from_secs(120);

/// The host operator's permission for the modes that hold authority on this machine
/// (`vtc/storage/configs/create/0.2` item 9), and how its ambient identity is used.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostAuth {
    pub ambient: bool,
    pub sealed: bool,
    /// The role an `ambient` `s3` config assumes when it names none.
    pub aws_role_arn: Option<String>,
    /// This host's egress, as an `aws:SourceIp` condition.
    pub aws_source_ip: Option<String>,
    /// The service account an ambient Google token is minted for, with a 900-second
    /// lifetime.
    pub gcs_service_account: Option<String>,
}

impl From<&StorageAuthHostConfig> for HostAuth {
    fn from(c: &StorageAuthHostConfig) -> Self {
        Self {
            ambient: c.ambient,
            sealed: c.sealed,
            aws_role_arn: c.aws_role_arn.clone(),
            aws_source_ip: c.aws_source_ip.clone(),
            gcs_service_account: c.gcs_service_account.clone(),
        }
    }
}

impl HostAuth {
    /// Whether this host permits `mode` (`vta-account` always).
    pub fn permits(&self, mode: &str) -> bool {
        match mode {
            "ambient" => self.ambient,
            "sealed" => self.sealed,
            _ => true,
        }
    }
}

/// What a room-scoped credential may reach, below a config's own prefix.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Scope {
    /// One room's blobs: `rooms/<32 hex of SHA-256(roomId)>/`.
    Room(String),
    /// The probe's canaries: `probe/`, never under any room.
    Probe,
}

impl Scope {
    /// The scope of the room `room_id`. The prefix is derived here, never taken
    /// from a request (rule 5).
    pub fn room(room_id: &str) -> Self {
        Self::Room(vti_common::blob_store::room_prefix(room_id))
    }

    /// The scope's object prefix beneath a config's `prefix` (`""` when it has none).
    pub fn object_prefix(&self, config_prefix: &str) -> String {
        match self {
            Self::Room(p) => format!("{config_prefix}{p}"),
            Self::Probe => format!("{config_prefix}{}", vti_common::blob_store::PROBE_PREFIX),
        }
    }

    /// A short, non-identifying tag for the provider's own audit trail: the room
    /// prefix's hash, or `probe`.
    pub fn tag(&self) -> &str {
        match self {
            Self::Room(p) => p
                .strip_prefix("rooms/")
                .and_then(|h| h.strip_suffix('/'))
                .unwrap_or("room"),
            Self::Probe => "probe",
        }
    }

    pub fn is_room(&self) -> bool {
        matches!(self, Self::Room(_))
    }
}

/// The kind of object operation a credential carries (rule 2). Each is its own
/// credential, so a read never holds a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Access {
    /// Read an object (and its metadata).
    Read,
    /// Create an object, and the multipart actions an upload in parts needs.
    Write,
    /// Delete an object.
    Delete,
}

impl Access {
    pub fn letter(self) -> char {
        match self {
            Self::Read => 'r',
            Self::Write => 'w',
            Self::Delete => 'd',
        }
    }
}

/// A credential, with the instant it stops being used.
#[derive(Clone)]
pub struct Held<C> {
    pub credential: C,
    pub stop_at: DateTime<Utc>,
}

/// When a credential obtained at `obtained` and expiring (by the provider's word) at
/// `provider_expiry` stops being used: whichever comes first of that expiry and
/// [`MAX_LIFETIME`] after it was obtained (rule 6).
pub fn stop_at(obtained: DateTime<Utc>, provider_expiry: Option<DateTime<Utc>>) -> DateTime<Utc> {
    let cap = obtained + chrono::Duration::from_std(MAX_LIFETIME).expect("15 minutes fits");
    match provider_expiry {
        Some(e) if e < cap => e,
        _ => cap,
    }
}

/// Live room-scoped credentials, in memory only (rule 7), keyed by (scope, access).
///
/// No lock is held across an await: a miss is minted outside the lock and inserted
/// after, so two racing operations may each mint one — harmless, and the later
/// replaces the earlier.
pub struct CredentialCache<C> {
    inner: Mutex<HashMap<(Scope, Access), Held<C>>>,
}

impl<C> Default for CredentialCache<C> {
    fn default() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }
}

impl<C: Clone> CredentialCache<C> {
    /// A credential for `(scope, access)` still good for a while, if one is held.
    pub fn get(&self, scope: &Scope, access: Access, now: DateTime<Utc>) -> Option<Held<C>> {
        let margin = chrono::Duration::from_std(RENEW_MARGIN).expect("fits");
        let map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        map.get(&(scope.clone(), access))
            .filter(|h| h.stop_at - margin > now)
            .cloned()
    }

    pub fn put(&self, scope: Scope, access: Access, held: Held<C>) {
        let mut map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = Utc::now();
        map.retain(|_, h| h.stop_at > now);
        map.insert((scope, access), held);
    }

    /// How many rooms hold a live credential now (`CredentialState.
    /// roomsHoldingCredentials`); the probe's scope is not a room.
    pub fn rooms_holding(&self, now: DateTime<Utc>) -> usize {
        let map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut rooms: Vec<&Scope> = map
            .iter()
            .filter(|((s, _), h)| s.is_room() && h.stop_at > now)
            .map(|((s, _), _)| s)
            .collect();
        rooms.sort_by_key(|s| s.tag().to_string());
        rooms.dedup();
        rooms.len()
    }
}

/// A provider error, without anything that could be a credential: a URL's query is
/// cut, and long unbroken tokens are elided.
pub fn scrub_provider_error(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(1024));
    for word in text.split_inclusive(char::is_whitespace) {
        let (body, tail) = match word.find(char::is_whitespace) {
            Some(i) => word.split_at(i),
            None => (word, ""),
        };
        let body = match body.find('?') {
            Some(i) if body.contains("://") => format!("{}?…", &body[..i]),
            _ => body.to_string(),
        };
        let tokenish = body.len() >= 32
            && body
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+/=_-.".contains(c));
        out.push_str(if tokenish { "…" } else { &body });
        out.push_str(tail);
    }
    out.chars().take(1024).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_stops_at_fifteen_minutes_or_its_expiry_whichever_is_first() {
        let t = Utc::now();
        assert_eq!(stop_at(t, None), t + chrono::Duration::minutes(15));
        assert_eq!(
            stop_at(t, Some(t + chrono::Duration::hours(1))),
            t + chrono::Duration::minutes(15)
        );
        assert_eq!(
            stop_at(t, Some(t + chrono::Duration::minutes(5))),
            t + chrono::Duration::minutes(5)
        );
    }

    #[test]
    fn a_room_scope_is_its_hashed_prefix_beneath_the_configs() {
        let s = Scope::room("did:webvh:QmRoom:example.com:room");
        let p = s.object_prefix("tenant-a/");
        assert!(p.starts_with("tenant-a/rooms/") && p.ends_with('/'), "{p}");
        assert!(!p.contains("example"));
        assert_eq!(s.tag().len(), 32);
        assert_eq!(Scope::Probe.object_prefix(""), "probe/");
    }

    #[test]
    fn the_cache_keeps_one_credential_per_scope_and_access_until_it_must_stop() {
        let cache: CredentialCache<u32> = CredentialCache::default();
        let now = Utc::now();
        let a = Scope::room("did:key:zA");
        let b = Scope::room("did:key:zB");
        cache.put(
            a.clone(),
            Access::Read,
            Held {
                credential: 1,
                stop_at: now + chrono::Duration::minutes(15),
            },
        );
        assert_eq!(cache.get(&a, Access::Read, now).unwrap().credential, 1);
        // Never another room's, never another access.
        assert!(cache.get(&b, Access::Read, now).is_none());
        assert!(cache.get(&a, Access::Write, now).is_none());
        // Not reused in its last minutes.
        assert!(
            cache
                .get(&a, Access::Read, now + chrono::Duration::minutes(14))
                .is_none()
        );
        cache.put(
            Scope::Probe,
            Access::Write,
            Held {
                credential: 2,
                stop_at: now + chrono::Duration::minutes(15),
            },
        );
        cache.put(
            a.clone(),
            Access::Write,
            Held {
                credential: 3,
                stop_at: now + chrono::Duration::minutes(15),
            },
        );
        assert_eq!(cache.rooms_holding(now), 1, "the probe is not a room");
    }

    #[test]
    fn a_provider_error_loses_what_could_be_a_credential() {
        let s = scrub_provider_error(
            "denied https://sts.amazonaws.com/?Action=AssumeRole&X-Amz-Security-Token=abc \
             token ya29.a0AfH6SMBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        );
        assert!(!s.contains("X-Amz-Security-Token"), "{s}");
        assert!(!s.contains("ya29"), "{s}");
        assert!(s.contains("denied"));
    }
}
