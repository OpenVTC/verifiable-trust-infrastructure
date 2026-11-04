//! Which result a sign-in asks for — the host's own set of audiences.
//!
//! `purpose` cannot say it: `auth/oob/request`'s `Purpose` is a closed enum
//! (`login`), and every audience is a login. So the starter names one under
//! the `ext` member [`SESSION_EXT`], and the service repeats it in the signed
//! step 1 and step 2 responses, so the wallet can show it and the grant's
//! `contextDigest` covers it: an approval given for one audience cannot be
//! redeemed as another (T19).
//!
//! The crate stores the audience on the request record, fixed at `request`,
//! and before `redeem` issues anything it holds the stored audience equal to
//! the one signed into step 1 ([`crate::OobRequest::signed_audience`]). What
//! the audiences are, and what each one gates and issues, is the host's.

use std::fmt::Debug;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// The `ext` namespace that says which audience a sign-in asks for.
pub const SESSION_EXT: &str = "org.openvtc.session";

/// A host's set of audiences.
///
/// The [`Default`] audience is what a request with no [`SESSION_EXT`] member
/// asks for, and what a stored record without an `audience` reads as. It is
/// never written to the record, and its responses carry no `ext` at all
/// ([`Audience::to_ext`] returns `None`), so a host with one audience signs
/// exactly what the specification shows.
pub trait Audience:
    Copy + Default + PartialEq + Eq + Debug + Serialize + DeserializeOwned + Send + Sync + 'static
{
    /// Read the audience a `request` asks for from its `ext`. No `ext`, or no
    /// [`SESSION_EXT`] member in it, is the default. A [`SESSION_EXT`] member
    /// that does not name an audience this host serves is refused (`Err`, the
    /// message the starter gets) rather than read as any of them.
    fn from_ext(ext: Option<&Value>) -> Result<Self, String>;

    /// The `ext` the service puts on its responses for this audience. `None`
    /// for the default audience.
    fn to_ext(self) -> Option<Value>;

    /// Whether this is the default audience (and so is left off the record).
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}
