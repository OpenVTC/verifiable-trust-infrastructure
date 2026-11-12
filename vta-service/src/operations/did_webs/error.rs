//! What a `did:webs` operation refuses, typed, so the Trust Task slice answers
//! with the code the task declares (`vta/webs/dids/*/0.1`) rather than reading
//! it back out of a message.

use std::fmt;

use crate::error::AppError;

/// A refusal a `vta/webs/dids/*` task declares a code for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WebsRefusal {
    /// `[dids] webs_enabled` is off (`create:methodDisabled`).
    MethodDisabled,
    /// The hosting server is not registered (`create:serverNotFound`).
    ServerNotFound,
    /// The host was built without `method-webs` (`create:hostDoesNotHostWebs`).
    HostDoesNotHostWebs,
    /// The host serves no such domain, or none to default to
    /// (`create:domainNotServed`).
    DomainNotServed,
    /// The slot path is malformed or the host refused it (`create:pathRefused`).
    PathRefused,
    /// A `service` DID, and `[dids] webs_service_dids` is off
    /// (`create/0.2:serviceDidNotPermitted`, CONVENTIONS.md 0.2 §1.1).
    ServiceDidNotPermitted,
    /// The DID would become the primary DID of the context holding this VTA's
    /// own identity: a create cannot re-identify a node. `create/0.1` answers
    /// it as `serviceDidNotPermitted`; `create/0.2`, whose code of that name
    /// now means only the configuration switch, as `permissionDenied`.
    NodeIdentityContext,
    /// The class disagrees with the identity the DID would become or replace
    /// (`create/0.2:didClassConflict`, CONVENTIONS.md 0.2 §1.2). Details:
    /// `requiredClass`, when one class would be accepted.
    DidClassConflict,
    /// No such template in any scope visible to the caller
    /// (`create/0.2:templateNotFound`).
    TemplateNotFound,
    /// Missing, unknown or unresolved template variables
    /// (`create/0.2:templateVarsInvalid`). Details: `missing`, `unknown`.
    TemplateVarsInvalid,
    /// The template describes what a did:webs derivation cannot reproduce
    /// (`create/0.2:templateNotRepresentable`, CONVENTIONS.md 0.2 §9.2).
    /// Details: `reason`, `members`.
    TemplateNotRepresentable,
    /// No such `did:webs`, or not one the caller may reach (`*:notFound`).
    NotFound,
    /// `expectedVersionId` is not the DID's latest event (`*:versionConflict`).
    VersionConflict,
    /// The update designates what already stands (`update:noChange`).
    NoChange,
    /// Two services share an id (`vta/webs/dids:serviceIdConflict`).
    ServiceIdConflict,
    /// The DID is deactivated (`vta/webs/dids:deactivated`).
    Deactivated,
    /// The host refused the publication (`vta/webs/dids:publishRefused`).
    PublishRefused,
}

/// A `did:webs` operation's error: a declared refusal, or anything else.
#[derive(Debug)]
#[non_exhaustive]
pub enum WebsError {
    /// A refusal the task declares, with what to tell the caller.
    Refused(WebsRefusal, String),
    /// A refusal the task declares, with the `details` its code declares.
    RefusedWith(WebsRefusal, String, serde_json::Value),
    /// Everything else: authorisation, storage, transport.
    App(AppError),
}

impl WebsError {
    pub(crate) fn refused(kind: WebsRefusal, message: impl Into<String>) -> Self {
        Self::Refused(kind, message.into())
    }

    pub(crate) fn refused_with(
        kind: WebsRefusal,
        message: impl Into<String>,
        details: serde_json::Value,
    ) -> Self {
        Self::RefusedWith(kind, message.into(), details)
    }

    /// The declared refusal, if this is one.
    pub fn refusal(&self) -> Option<WebsRefusal> {
        match self {
            Self::Refused(kind, _) | Self::RefusedWith(kind, _, _) => Some(*kind),
            Self::App(_) => None,
        }
    }

    /// The host's answer to a publication, sorted into the refusals the tasks
    /// declare. The host's code is the bracketed suffix
    /// [`crate::webvh_host::host_refusal`] writes; a host built without
    /// `method-webs` says so by name (affinidi-webvh-service#341). A transport
    /// failure is not a refusal and is passed on as it is.
    pub(crate) fn from_host(e: AppError) -> Self {
        let message = e.to_string();
        let refused = matches!(
            e,
            AppError::Validation(_)
                | AppError::Conflict(_)
                | AppError::Forbidden(_)
                | AppError::NotFound(_)
        );
        if !refused {
            return Self::App(e);
        }
        let kind = if message.contains("method-webs") || message.contains("does not host did:webs")
        {
            WebsRefusal::HostDoesNotHostWebs
        } else if message.contains("unknownDomain]") {
            WebsRefusal::DomainNotServed
        } else if message.contains("invalidPath]") || message.contains("pathTaken]") {
            WebsRefusal::PathRefused
        } else {
            WebsRefusal::PublishRefused
        };
        Self::Refused(kind, message)
    }
}

impl fmt::Display for WebsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(_, message) | Self::RefusedWith(_, message, _) => f.write_str(message),
            Self::App(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for WebsError {}

impl From<AppError> for WebsError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

/// For callers outside the Trust Task slice: each refusal as the HTTP-shaped
/// error it is.
impl From<WebsError> for AppError {
    fn from(e: WebsError) -> Self {
        match e {
            WebsError::App(e) => e,
            WebsError::Refused(kind, m) | WebsError::RefusedWith(kind, m, _) => match kind {
                WebsRefusal::NotFound
                | WebsRefusal::ServerNotFound
                | WebsRefusal::TemplateNotFound => AppError::NotFound(m),
                WebsRefusal::MethodDisabled
                | WebsRefusal::ServiceDidNotPermitted
                | WebsRefusal::NodeIdentityContext => AppError::Forbidden(m),
                WebsRefusal::VersionConflict
                | WebsRefusal::ServiceIdConflict
                | WebsRefusal::Deactivated
                | WebsRefusal::DidClassConflict => AppError::Conflict(m),
                _ => AppError::Validation(m),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_refusal_is_sorted_by_its_code() {
        let host = |code: &str| {
            WebsError::from_host(crate::webvh_host::host_refusal(code, "no")).refusal()
        };
        assert_eq!(
            host("did/register:unknownDomain"),
            Some(WebsRefusal::DomainNotServed)
        );
        assert_eq!(
            host("did/register:invalidPath"),
            Some(WebsRefusal::PathRefused)
        );
        assert_eq!(
            host("did/register:pathTaken"),
            Some(WebsRefusal::PathRefused)
        );
        assert_eq!(
            host("did/register:invalidLog"),
            Some(WebsRefusal::PublishRefused)
        );
        assert_eq!(
            WebsError::from_host(AppError::Validation(
                "the DID hosting service refused the request: this host does not host did:webs: \
                 it was built without the `method-webs` feature [validationError]"
                    .into()
            ))
            .refusal(),
            Some(WebsRefusal::HostDoesNotHostWebs)
        );
        // Unreachable is not a refusal.
        assert_eq!(
            WebsError::from_host(AppError::Internal("timeout".into())).refusal(),
            None
        );
    }
}
