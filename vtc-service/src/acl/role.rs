//! `VtcRole` — the VTC-specific role taxonomy.
//!
//! Spec §5.3:
//! ```text
//! enum VtcRole { Admin, Moderator, Issuer, Member, Custom(String) }
//! ```
//!
//! ## Why a new enum
//!
//! `vti_common::acl::Role` carries the VTA's role taxonomy
//! (`Admin`, `Initiator`, `Application`, `Reader`, `Monitor`) and is
//! shared between VTA + VTC. Adding the VTC variants
//! (`Moderator`, `Issuer`, `Member`, `Custom`) to the shared enum
//! would force every VTA-side code path to handle roles it has no
//! semantics for. Phase-1 plan §D1 keeps the role taxonomy
//! service-owned — VTC ships its own enum, VTA stays untouched.
//!
//! ## Wire shape (and why not `#[serde(tag)]`)
//!
//! The plan originally proposed
//! `#[serde(tag = "type", content = "value")]`, which would
//! serialise `VtcRole::Admin` as `{"type":"admin"}`. That breaks
//! backwards-compatibility with the existing `acl:<did>` rows
//! written by Phase 0's bootstrap path, which store the role as a
//! plain lowercase string (`"admin"`) via
//! `vti_common::acl::Role`'s `#[serde(rename_all = "lowercase")]`.
//!
//! Instead, every variant is a single string. The `Custom`
//! variant uses a `custom:` prefix to distinguish from the named
//! variants:
//!
//! | Variant | Wire |
//! |---|---|
//! | `Admin` | `"admin"` |
//! | `Moderator` | `"moderator"` |
//! | `Issuer` | `"issuer"` |
//! | `Member` | `"member"` |
//! | `Custom("editor")` | `"custom:editor"` |
//!
//! The `custom:` prefix makes the encoding unambiguous: a string
//! that doesn't start with `custom:` can only be one of the four
//! named variants. Custom names are validated against a
//! conservative charset (lowercase alphanumeric + `-` + `_`,
//! 1..=64 chars) so a malicious `custom:admin` value cannot
//! decode to the `Admin` variant via the colon-strip.
//!
//! **Phase-1 outcome note**: the on-disk wire shape diverges from
//! the plan's proposal for the backwards-compat reason above.
//! Captured here so the deviation is findable from the plan doc.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use vti_common::error::AppError;

/// The VTC's role taxonomy. See module docs for the wire shape.
#[derive(Debug, Clone, PartialEq, Eq, Hash, utoipa::ToSchema)]
pub enum VtcRole {
    /// Full management access. Spec §5.3 default permission matrix.
    Admin,
    /// Approves / rejects join requests; policy-gated removal of
    /// other members.
    Moderator,
    /// Issues VEC / VWC / RCard on behalf of the community.
    Issuer,
    /// Standard member. Default role on join.
    Member,
    /// Community-defined custom role. Receives **no implicit
    /// grants** from the standard permission matrix; the only
    /// authoritative source of `Custom` permissions is
    /// `role_definitions.rego` (spec §5.3, Phase 2+).
    Custom(String),
}

const CUSTOM_PREFIX: &str = "custom:";
const CUSTOM_NAME_MAX: usize = 64;

impl VtcRole {
    /// Returns the wire-shape representation as borrowed-or-owned
    /// `String`. Used by `Display` + `Serialize`.
    fn as_wire(&self) -> String {
        match self {
            VtcRole::Admin => "admin".into(),
            VtcRole::Moderator => "moderator".into(),
            VtcRole::Issuer => "issuer".into(),
            VtcRole::Member => "member".into(),
            VtcRole::Custom(name) => format!("{CUSTOM_PREFIX}{name}"),
        }
    }

    /// Construct a `VtcRole::Custom(name)` after validating the
    /// charset. Returns `AppError::Validation` on invalid input.
    /// Use this rather than the bare enum variant when the input
    /// comes from outside the daemon (REST body, DIDComm message).
    pub fn custom(name: impl Into<String>) -> Result<Self, AppError> {
        let name = name.into();
        validate_custom_name(&name)?;
        Ok(VtcRole::Custom(name))
    }

    /// Returns `true` for the four named variants, `false` for
    /// `Custom`. Used by `validate_role_assignment` in the
    /// permission-matrix check to short-circuit Custom-role
    /// lookups against the (Phase-2) `role_definitions.rego`
    /// output.
    pub fn is_standard(&self) -> bool {
        !matches!(self, VtcRole::Custom(_))
    }
}

impl fmt::Display for VtcRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_wire())
    }
}

impl FromStr for VtcRole {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, AppError> {
        match s {
            "admin" => Ok(VtcRole::Admin),
            "moderator" => Ok(VtcRole::Moderator),
            "issuer" => Ok(VtcRole::Issuer),
            "member" => Ok(VtcRole::Member),
            other => {
                if let Some(name) = other.strip_prefix(CUSTOM_PREFIX) {
                    validate_custom_name(name)?;
                    Ok(VtcRole::Custom(name.to_string()))
                } else {
                    Err(AppError::Validation(format!(
                        "unknown VTC role '{other}'. Expected one of admin, moderator, issuer, \
                         member, or custom:<name>."
                    )))
                }
            }
        }
    }
}

impl Serialize for VtcRole {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_wire())
    }
}

impl<'de> Deserialize<'de> for VtcRole {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        VtcRole::from_str(&s).map_err(serde::de::Error::custom)
    }
}

fn validate_custom_name(name: &str) -> Result<(), AppError> {
    if name.is_empty() {
        return Err(AppError::Validation(
            "custom role name cannot be empty".into(),
        ));
    }
    if name.len() > CUSTOM_NAME_MAX {
        return Err(AppError::Validation(format!(
            "custom role name too long (max {CUSTOM_NAME_MAX} chars)"
        )));
    }
    if !name.chars().all(is_valid_name_char) {
        return Err(AppError::Validation(format!(
            "custom role name '{name}' contains disallowed characters \
             (allowed: lowercase a–z, digits, `-`, `_`)"
        )));
    }
    Ok(())
}

fn is_valid_name_char(c: char) -> bool {
    matches!(c, 'a'..='z' | '0'..='9' | '-' | '_')
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_variants_round_trip_through_wire() {
        for (variant, wire) in [
            (VtcRole::Admin, "admin"),
            (VtcRole::Moderator, "moderator"),
            (VtcRole::Issuer, "issuer"),
            (VtcRole::Member, "member"),
        ] {
            let serialised = serde_json::to_string(&variant).unwrap();
            assert_eq!(serialised, format!("\"{wire}\""));
            let deserialised: VtcRole = serde_json::from_str(&serialised).unwrap();
            assert_eq!(deserialised, variant);
            assert_eq!(variant.to_string(), wire);
        }
    }

    #[test]
    fn custom_variant_round_trips() {
        let r = VtcRole::custom("editor").unwrap();
        let serialised = serde_json::to_string(&r).unwrap();
        assert_eq!(serialised, "\"custom:editor\"");
        let deserialised: VtcRole = serde_json::from_str(&serialised).unwrap();
        assert_eq!(deserialised, r);
    }

    #[test]
    fn custom_constructor_validates_charset() {
        assert!(VtcRole::custom("editor").is_ok());
        assert!(VtcRole::custom("trust-anchor").is_ok());
        assert!(VtcRole::custom("badge_holder_42").is_ok());

        for bad in ["", "EDITOR", "with spaces", "colon:bad", "../../etc"] {
            let err = VtcRole::custom(bad).expect_err(&format!("expected reject: {bad}"));
            assert!(matches!(err, AppError::Validation(_)));
        }
    }

    #[test]
    fn deserialise_rejects_unknown_string() {
        let err = serde_json::from_str::<VtcRole>("\"unknown\"").unwrap_err();
        assert!(err.to_string().contains("unknown VTC role"));
    }

    #[test]
    fn deserialise_rejects_custom_with_bad_charset() {
        // Decoder must run the same validation as the constructor —
        // otherwise a malicious peer could write
        // `"custom:UPPER"` to disk and bypass the charset rule.
        let err = serde_json::from_str::<VtcRole>("\"custom:UPPER\"").unwrap_err();
        assert!(err.to_string().contains("disallowed characters"));
    }

    #[test]
    fn deserialise_rejects_custom_with_empty_name() {
        let err = serde_json::from_str::<VtcRole>("\"custom:\"").unwrap_err();
        assert!(err.to_string().contains("cannot be empty"));
    }

    #[test]
    fn deserialise_rejects_custom_with_name_too_long() {
        let name = "a".repeat(CUSTOM_NAME_MAX + 1);
        let err = serde_json::from_str::<VtcRole>(&format!("\"custom:{name}\"")).unwrap_err();
        assert!(err.to_string().contains("too long"));
    }

    #[test]
    fn custom_name_with_colon_does_not_smuggle_admin() {
        // The colon-strip in from_str only fires for the *first*
        // colon-after-`custom:`. A `custom:admin` value would
        // still decode as `Custom("admin")`, *not* `Admin`.
        // Confirmed here so the encoding stays unambiguous.
        let r: VtcRole = serde_json::from_str("\"custom:admin\"").unwrap();
        assert_eq!(r, VtcRole::Custom("admin".into()));
        assert_ne!(r, VtcRole::Admin);
    }

    #[test]
    fn is_standard_returns_true_only_for_named_variants() {
        assert!(VtcRole::Admin.is_standard());
        assert!(VtcRole::Moderator.is_standard());
        assert!(VtcRole::Issuer.is_standard());
        assert!(VtcRole::Member.is_standard());
        assert!(!VtcRole::Custom("x".into()).is_standard());
    }

    #[test]
    fn from_str_handles_vti_common_admin_wire_shape() {
        // The existing `vti_common::acl::Role::Admin` serialises
        // as `"admin"`. Phase-0 `acl:<did>` rows written via that
        // path must decode to `VtcRole::Admin` without
        // re-serialisation. This pins that path.
        let role = VtcRole::from_str("admin").unwrap();
        assert_eq!(role, VtcRole::Admin);
    }
}
