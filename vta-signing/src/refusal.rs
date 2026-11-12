/// Why a request could not be built into bytes to sign — each a code the
/// specification declares.
///
/// Deliberately **not** `#[non_exhaustive]`: the set is the specification's,
/// and a service that maps every refusal to a wire code (the VTA's Trust Task
/// layer) wants the compiler to fail when one is added without a mapping. A new
/// variant is therefore a breaking change of this crate, as it is of the
/// specification.
#[derive(Debug, PartialEq, Eq)]
pub enum FormatRefusal {
    /// `keys/sign-jws:headerMemberForbidden`, naming the member.
    HeaderMemberForbidden(String),
    /// `keys:invalidArgument`.
    InvalidArgument(String),
    /// `keys/sign-jws:payloadInvalid`.
    PayloadInvalid(String),
    /// `keys/sign-csr:subjectInvalid`: `member` is `subject` or
    /// `subjectAltNames`, `index` the element of its array.
    SubjectInvalid {
        member: &'static str,
        index: Option<usize>,
        reason: String,
    },
    /// `keys/sign-document:proofPresent`.
    ProofPresent,
    /// `keys/sign-document:documentInvalid`, with its `reason`: `noSigner`,
    /// `signerMalformed` or `notCanonicalizable`.
    DocumentInvalid(&'static str),
    /// `keys/sign-document:issuerMismatch`, naming `issuer` or `controller`.
    IssuerMismatch(&'static str),
    /// `keys/sign-document:purposeNotAuthorized`, naming the purpose.
    PurposeNotAuthorized(&'static str),
}
