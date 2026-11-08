use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct DeleteContextResultBody {
    pub id: String,
    pub deleted: bool,
    /// One entry per `did:webvh` DID in the deleted subtree whose local record
    /// went while its hosting server did not confirm removal of the published
    /// log. **Those DIDs may still resolve.**
    ///
    /// A partial success reported as a success — the subtree-wide form of
    /// `vta/webvh/dids/delete/1.0`'s `daemonCleanupError` — so a consumer
    /// surfaces it rather than treating the deletion as complete. Absent when
    /// every host copy was confirmed gone, which is the ordinary case;
    /// `skip_serializing_if` keeps it off the wire then, because an empty
    /// array reads as a report that was made and came back clean, and that is
    /// a different claim from one that had nothing to report.
    #[serde(
        default,
        alias = "daemon_cleanup_errors",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub daemon_cleanup_errors: Vec<String>,
}

/// Summary of resources that will be removed when deleting a context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeleteContextPreviewBody {
    pub id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct DeleteContextPreviewResultBody {
    pub id: String,
    /// Sub-contexts that would go with this one, as full paths, deepest
    /// first. Every other array here is the union over these and the named
    /// context, because that is what the deletion acts on.
    #[serde(default, alias = "sub_contexts", skip_serializing_if = "Vec::is_empty")]
    pub sub_contexts: Vec<String>,
    pub keys: Vec<String>,
    #[serde(alias = "webvh_dids")]
    pub webvh_dids: Vec<String>,
    /// ACL entries that will be deleted (only have this context).
    #[serde(alias = "acl_entries_removed")]
    pub acl_entries_removed: Vec<String>,
    /// ACL entries that will have this context removed from their allowed list.
    #[serde(alias = "acl_entries_updated")]
    pub acl_entries_updated: Vec<String>,
    /// DID templates scoped to this context that will be deleted.
    #[serde(default, alias = "did_templates")]
    pub did_templates: Vec<String>,
}

/// One DID whose published log a context deletion could not confirm removed
/// from its hosting server — an entry of the `hostCleanupFailures` array that
/// `vta/contexts/delete:hostCleanupFailed` carries in its error `details`.
///
/// Read from the error rather than a response, so it is a hand-written mirror
/// of the code's `detailsSchema`, which the codegen does not turn into a type.
/// Read leniently: this only decides what an operator is shown before being
/// asked, so an unexpected member must not hide the DIDs it came with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostCleanupFailure {
    pub did: String,
    /// The VTA's id for the hosting server, when it records one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Why removal was not confirmed, for a human.
    pub reason: String,
}

impl std::fmt::Display for HostCleanupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.did, self.reason)
    }
}

/// What a `vta/contexts/delete:hostCleanupFailed` refusal established.
///
/// The code alone says only that the VTA refused; the DIDs in its required
/// `details.hostCleanupFailures` are what make the follow-up decision — retry
/// with `abandonHostCopies` and leave those logs published — an informed one.
/// Nothing between the wire and this type checks the details against the
/// code's `detailsSchema` (`VtaError::Rejected` carries them as sent, and the
/// generated error-code tables do not hold the schema), so the check is made
/// here, and a refusal whose evidence cannot be read is kept apart from one
/// whose evidence can (#2404).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostCleanupRefusal {
    /// The details hold one or more well-formed entries: the DIDs whose
    /// published logs were not confirmed removed. Only this case carries what
    /// an operator must be shown before being offered `abandonHostCopies`.
    Evidenced(Vec<HostCleanupFailure>),
    /// The code matched but the details are absent, empty or malformed. Still
    /// this refusal — nothing was deleted locally and a plain retry is still
    /// right — but no basis for offering the abandonment, because nobody can
    /// say which logs it would leave behind. `why` says what was wrong.
    Unreadable { why: String },
}

/// Classify `err` as a `vta/contexts/delete:hostCleanupFailed` refusal, or
/// `None` when it is any other error.
///
/// Matches the exact declared code only — never a generic `taskFailed`, however
/// its message reads. The details are held to the code's `detailsSchema`:
/// `hostCleanupFailures` present with at least one entry, each with a non-empty
/// `did` and `reason` and, when present, a non-empty `server`. Unknown members
/// are ignored rather than refused, so an addition the schema later makes does
/// not hide the DIDs it came with.
pub fn host_cleanup_refusal(err: &crate::error::VtaError) -> Option<HostCleanupRefusal> {
    use vti_specs::vta::contexts::delete::v1_1::error_codes::HOST_CLEANUP_FAILED;
    let crate::error::VtaError::Rejected { code, details, .. } = err else {
        return None;
    };
    if code != HOST_CLEANUP_FAILED.code {
        return None;
    }
    Some(match read_failures(details.as_ref()) {
        Ok(failures) => HostCleanupRefusal::Evidenced(failures),
        Err(why) => HostCleanupRefusal::Unreadable { why },
    })
}

fn read_failures(details: Option<&serde_json::Value>) -> Result<Vec<HostCleanupFailure>, String> {
    let raw = details
        .ok_or("the refusal carried no details")?
        .get("hostCleanupFailures")
        .ok_or("the refusal's details carried no `hostCleanupFailures`")?;
    let failures: Vec<HostCleanupFailure> = serde_json::from_value(raw.clone())
        .map_err(|e| format!("`hostCleanupFailures` is malformed: {e}"))?;
    if failures.is_empty() {
        return Err(
            "`hostCleanupFailures` is empty; the specification requires at least one entry".into(),
        );
    }
    for (i, f) in failures.iter().enumerate() {
        if f.did.is_empty() {
            return Err(format!("`hostCleanupFailures[{i}].did` is empty"));
        }
        if f.reason.is_empty() {
            return Err(format!("`hostCleanupFailures[{i}].reason` is empty"));
        }
        if f.server.as_deref() == Some("") {
            return Err(format!("`hostCleanupFailures[{i}].server` is empty"));
        }
    }
    Ok(failures)
}

/// The DIDs a `vta/contexts/delete:hostCleanupFailed` refusal names, or `None`
/// when `err` is any other error **or** the refusal's details cannot be read.
///
/// Until #2404 an unreadable refusal came back as `Some(vec![])`, which a
/// caller could not tell from evidence and which led the CLI to offer
/// abandoning host copies it could not name. Use [`host_cleanup_refusal`],
/// which keeps that case as [`HostCleanupRefusal::Unreadable`].
#[deprecated(note = "use `host_cleanup_refusal`, which reports unreadable evidence separately")]
pub fn host_cleanup_failures(err: &crate::error::VtaError) -> Option<Vec<HostCleanupFailure>> {
    match host_cleanup_refusal(err)? {
        HostCleanupRefusal::Evidenced(failures) => Some(failures),
        HostCleanupRefusal::Unreadable { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::VtaError;
    use serde_json::{Value, json};
    use vti_specs::vta::contexts::delete::v1_1::error_codes::HOST_CLEANUP_FAILED;

    fn refusal(code: &str, details: Option<Value>) -> VtaError {
        VtaError::Rejected {
            code: code.to_string(),
            message: "host cleanup failed".into(),
            details,
        }
    }

    fn declared(details: Option<Value>) -> VtaError {
        refusal(HOST_CLEANUP_FAILED.code, details)
    }

    fn unreadable(err: &VtaError) -> bool {
        matches!(
            host_cleanup_refusal(err),
            Some(HostCleanupRefusal::Unreadable { .. })
        )
    }

    #[test]
    fn well_formed_details_are_evidence() {
        let err = declared(Some(json!({ "hostCleanupFailures": [
            { "did": "did:webvh:a", "server": "host-1", "reason": "unreachable" },
            { "did": "did:webvh:b", "reason": "refused" },
        ]})));
        let Some(HostCleanupRefusal::Evidenced(failures)) = host_cleanup_refusal(&err) else {
            panic!("expected evidence");
        };
        assert_eq!(failures.len(), 2);
        assert_eq!(failures[0].server.as_deref(), Some("host-1"));
        assert_eq!(failures[1].did, "did:webvh:b");
    }

    #[test]
    fn an_unknown_member_does_not_hide_the_dids() {
        let err = declared(Some(json!({ "hostCleanupFailures": [
            { "did": "did:webvh:a", "reason": "unreachable", "retryAt": "later" },
        ]})));
        assert!(matches!(
            host_cleanup_refusal(&err),
            Some(HostCleanupRefusal::Evidenced(f)) if f.len() == 1
        ));
    }

    #[test]
    fn absent_details_are_not_evidence() {
        assert!(unreadable(&declared(None)));
        assert!(unreadable(&declared(Some(json!({})))));
    }

    #[test]
    fn an_empty_list_is_not_evidence() {
        assert!(unreadable(&declared(Some(
            json!({ "hostCleanupFailures": [] })
        ))));
    }

    #[test]
    fn malformed_entries_are_not_an_empty_list() {
        for bad in [
            json!({ "hostCleanupFailures": [{ "reason": "unreachable" }] }),
            json!({ "hostCleanupFailures": [{ "did": "did:webvh:a" }] }),
            json!({ "hostCleanupFailures": [{ "did": "", "reason": "x" }] }),
            json!({ "hostCleanupFailures": [{ "did": "did:webvh:a", "reason": "" }] }),
            json!({ "hostCleanupFailures": [{ "did": "did:webvh:a", "reason": "x", "server": "" }] }),
            json!({ "hostCleanupFailures": "did:webvh:a" }),
            json!({ "hostCleanupFailures": [ "did:webvh:a" ] }),
        ] {
            let err = declared(Some(bad.clone()));
            assert!(unreadable(&err), "{bad} read as evidence");
            #[allow(deprecated)]
            let legacy = host_cleanup_failures(&err);
            assert_eq!(
                legacy, None,
                "{bad} read as a list by the deprecated helper"
            );
        }
    }

    #[test]
    fn another_refusal_is_not_this_one_whatever_it_says() {
        let details = Some(json!({ "hostCleanupFailures": [
            { "did": "did:webvh:a", "reason": "unreachable" },
        ]}));
        assert_eq!(
            host_cleanup_refusal(&refusal("taskFailed", details.clone())),
            None
        );
        assert_eq!(
            host_cleanup_refusal(&refusal("vta/contexts/delete:notEmpty", details)),
            None
        );
        assert_eq!(
            host_cleanup_refusal(&VtaError::Protocol(
                "vta/contexts/delete:hostCleanupFailed".into()
            )),
            None
        );
    }
}
