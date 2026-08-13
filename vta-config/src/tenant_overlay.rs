//! Typed, allowlisted tenant-config overlay for un-baked TEE deployments.
//!
//! Background: `docs/05-design-notes/tenant-config-allowlist.md`.
//!
//! In `BAKE_CONFIG=false` (fleet) mode the enclave image bakes everything
//! *except* a small, named set of tenant-scoped fields; the parent (an
//! **untrusted** host) delivers those at runtime. This module is the allowlist
//! that keeps that delivery honest: the parent may hand a running enclave ONLY
//! the fields named in [`TenantConfigOverlay`]. `#[serde(deny_unknown_fields)]`
//! turns any other key — an operator typo *or* a malicious injection — into the
//! **same** hard parse error, so a field that isn't named here (`admin_did`,
//! `mode`, every `allow_*` break-glass flag, …) structurally cannot reach the
//! enclave's config. That is the fail-closed property a hand-maintained denylist
//! floor cannot give.
//!
//! `BAKE_CONFIG=true` / self-host builds never accept an overlay and are
//! untouched by any of this.

use serde::Deserialize;

/// Everything a fleet operator is allowed to hand a running enclave at runtime
/// (over `vsock:5800`). Anything not named here CANNOT reach the enclave's
/// config — [`serde(deny_unknown_fields)`] makes an unrecognized key a hard
/// parse error, not a silently-ignored one.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantConfigOverlay {
    #[serde(default)]
    pub vta_did: Option<String>,
    #[serde(default)]
    pub vta_name: Option<String>,
    #[serde(default)]
    pub public_url: Option<String>,
    #[serde(default)]
    pub tee_kms: Option<TenantKmsOverlay>,
    #[serde(default)]
    pub messaging: Option<TenantMessagingOverlay>,
}

/// The tenant-scoped subset of `[tee.kms]` an operator may deliver at runtime.
///
/// Note what is **absent on purpose**: `admin_did`, `admin_context_id`, and
/// every `allow_*` break-glass flag. None of those can be carried by this type,
/// so the parent cannot weaken KMS/attestation enforcement or inject an
/// un-attested super-admin through the config channel.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantKmsOverlay {
    /// Full KMS key ARN. The region is *derived* from the ARN
    /// ([`region_from_arn`]) rather than accepted as a separate field, so there
    /// is no "region says X, key_arn says Y" ambiguity to adjudicate. Validated
    /// against the baked [`allowed_kms_accounts`] before use
    /// ([`validate_key_arn`]).
    ///
    /// [`allowed_kms_accounts`]: crate::TeeConfig::allowed_kms_accounts
    pub key_arn: String,
    #[serde(default)]
    pub vta_did_template: Option<String>,
    #[serde(default)]
    pub anchor_table_name: Option<String>,
    /// KMS-sealed anti-rollback writer credential. Self-protecting: only the
    /// genuine enclave image can `kms:Decrypt` it, so delivering it over the
    /// (untrusted) config channel exposes nothing.
    #[serde(default)]
    pub anchor_writer_credential_ciphertext: Option<String>,
}

/// The tenant-scoped subset of `[messaging]` an operator may deliver at runtime.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantMessagingOverlay {
    #[serde(default)]
    pub mediator_did: Option<String>,
    #[serde(default)]
    pub mediator_url: Option<String>,
}

/// Failure applying a [`TenantConfigOverlay`] to a baked base config.
///
/// Every variant is fail-closed: an overlay that trips any of these must abort
/// the boot rather than fall through to a weaker config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantOverlayError {
    /// The overlay's `key_arn` is not a well-formed
    /// `arn:aws:kms:<region>:<account>:key/<id>`.
    MalformedKeyArn(String),
    /// The overlay carries a `tee_kms` block but the baked base has no
    /// `[tee.kms]` section to apply it onto.
    BaseMissingKmsSection,
    /// The baked `allowed_kms_accounts` is empty, so no overlay `key_arn` is
    /// accepted (fail closed — an empty allowlist is "deny", never "allow all").
    NoAccountsAllowlisted,
    /// The overlay's `key_arn` names an AWS account that is not in the baked,
    /// PCR0-committed `allowed_kms_accounts`.
    KeyArnAccountNotAllowed {
        account: String,
        allowed: Vec<String>,
    },
    /// The overlay supplies an `anchor_writer_credential_ciphertext` but neither
    /// the overlay nor the baked base provides the `anchor.table_name` the
    /// credential belongs to.
    AnchorWriterWithoutTable,
}

impl std::fmt::Display for TenantOverlayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedKeyArn(arn) => write!(
                f,
                "tenant overlay key_arn is not a well-formed KMS ARN \
                 (arn:aws:kms:<region>:<account>:key/<id>): {arn}"
            ),
            Self::BaseMissingKmsSection => write!(
                f,
                "tenant overlay carries a tee_kms block but the baked base config \
                 has no [tee.kms] section to apply it onto"
            ),
            Self::NoAccountsAllowlisted => write!(
                f,
                "tenant overlay supplies a key_arn but the baked \
                 tee.allowed_kms_accounts is empty — refusing (empty allowlist \
                 means deny, not allow-all)"
            ),
            Self::KeyArnAccountNotAllowed { account, allowed } => write!(
                f,
                "tenant overlay key_arn names AWS account {account}, which is not \
                 in the baked tee.allowed_kms_accounts {allowed:?}"
            ),
            Self::AnchorWriterWithoutTable => write!(
                f,
                "tenant overlay supplies anchor_writer_credential_ciphertext but \
                 no anchor table_name is available (neither in the overlay nor the \
                 baked base)"
            ),
        }
    }
}

impl std::error::Error for TenantOverlayError {}

/// Validate a KMS `key_arn` against the baked account allowlist.
///
/// Fail-closed on every path: a malformed ARN, an empty allowlist, or an
/// account not on the list all reject.
pub fn validate_key_arn(key_arn: &str, allowed: &[String]) -> Result<(), TenantOverlayError> {
    // arn:aws:kms:<region>:<account>:key/<id>
    let parts: Vec<&str> = key_arn.splitn(6, ':').collect();
    let account = match parts.as_slice() {
        ["arn", "aws", "kms", region, account, rest]
            if !region.is_empty() && !account.is_empty() && rest.starts_with("key/") =>
        {
            *account
        }
        _ => return Err(TenantOverlayError::MalformedKeyArn(key_arn.to_string())),
    };
    if allowed.is_empty() {
        return Err(TenantOverlayError::NoAccountsAllowlisted);
    }
    if !allowed.iter().any(|a| a == account) {
        return Err(TenantOverlayError::KeyArnAccountNotAllowed {
            account: account.to_string(),
            allowed: allowed.to_vec(),
        });
    }
    Ok(())
}

/// Derive the AWS region from a KMS `key_arn`. Callers should have already run
/// [`validate_key_arn`], but this re-validates the shape so it can be used
/// standalone.
pub fn region_from_arn(key_arn: &str) -> Result<String, TenantOverlayError> {
    let parts: Vec<&str> = key_arn.splitn(6, ':').collect();
    match parts.as_slice() {
        ["arn", "aws", "kms", region, account, rest]
            if !region.is_empty() && !account.is_empty() && rest.starts_with("key/") =>
        {
            Ok((*region).to_string())
        }
        _ => Err(TenantOverlayError::MalformedKeyArn(key_arn.to_string())),
    }
}

/// Apply a validated [`TenantConfigOverlay`] onto a baked base [`AppConfig`],
/// field by field.
///
/// Explicit assignment (never a generic/recursive merge) so the exact "what can
/// change" set is visible in this one function body, not implied by struct
/// shape. Only compiled for `feature = "tee"` builds, which are the only ones
/// that carry a `[tee]` section to overlay onto.
#[cfg(feature = "tee")]
pub fn apply_tenant_overlay(
    base: &mut crate::AppConfig,
    overlay: TenantConfigOverlay,
) -> Result<(), TenantOverlayError> {
    if let Some(v) = overlay.vta_did {
        base.vta_did = Some(v);
    }
    if let Some(v) = overlay.vta_name {
        base.vta_name = Some(v);
    }
    if let Some(v) = overlay.public_url {
        base.public_url = Some(v);
    }

    if let Some(kms_overlay) = overlay.tee_kms {
        // Clone the baked allowlist before taking a mutable borrow of `base.tee`.
        let allowed = base.tee.allowed_kms_accounts.clone();
        let kms = base
            .tee
            .kms
            .as_mut()
            .ok_or(TenantOverlayError::BaseMissingKmsSection)?;

        validate_key_arn(&kms_overlay.key_arn, &allowed)?;
        // Region is derived from the (now-validated) ARN, never taken separately.
        kms.region = region_from_arn(&kms_overlay.key_arn)?;
        kms.key_arn = kms_overlay.key_arn;

        if let Some(v) = kms_overlay.vta_did_template {
            kms.vta_did_template = Some(v);
        }

        // Anchor sub-config: patch an existing one, or materialize it when the
        // overlay supplies the required `table_name`.
        if kms_overlay.anchor_table_name.is_some()
            || kms_overlay.anchor_writer_credential_ciphertext.is_some()
        {
            match kms.anchor.as_mut() {
                Some(anchor) => {
                    if let Some(t) = kms_overlay.anchor_table_name {
                        anchor.table_name = t;
                    }
                    if let Some(c) = kms_overlay.anchor_writer_credential_ciphertext {
                        anchor.writer_credential_ciphertext = Some(c);
                    }
                }
                None => {
                    // `table_name` is required to construct an anchor; a writer
                    // credential with nowhere to live is fail-closed.
                    let table_name = kms_overlay
                        .anchor_table_name
                        .ok_or(TenantOverlayError::AnchorWriterWithoutTable)?;
                    kms.anchor = Some(crate::TeeAnchorConfig {
                        table_name,
                        writer_credential_ciphertext: kms_overlay
                            .anchor_writer_credential_ciphertext,
                    });
                }
            }
        }
    }

    if let Some(m) = overlay.messaging {
        match base.messaging.as_mut() {
            Some(msg) => {
                if let Some(v) = m.mediator_did {
                    msg.mediator_did = v;
                }
                if let Some(v) = m.mediator_url {
                    msg.mediator_url = v;
                }
            }
            None => {
                // `MessagingConfig` has no `Default` (mediator_did is required),
                // so construct explicitly from the overlay + neutral defaults.
                base.messaging = Some(crate::MessagingConfig {
                    mediator_did: m.mediator_did.unwrap_or_default(),
                    mediator_url: m.mediator_url.unwrap_or_default(),
                    mediator_host: None,
                    setup_acl: false,
                    drain_inbox_on_start: false,
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD_ARN: &str = "arn:aws:kms:us-east-1:111122223333:key/abcd-ef01-2345";

    // -- The core structural guarantee (design note §3.7): the overlay type
    //    physically cannot carry a forbidden/unknown field. This fails the BUILD
    //    (a compile-run test), not a specific boot, if the allowlist regresses.

    #[test]
    fn overlay_rejects_allow_flags_admin_did_and_mode() {
        let poison = [
            r#"{"tee_kms":{"key_arn":"arn:x","allow_unanchored":true}}"#,
            r#"{"tee_kms":{"key_arn":"arn:x","allow_kms_reinit":true}}"#,
            r#"{"tee_kms":{"key_arn":"arn:x","allow_unattested_fallback":true}}"#,
            r#"{"tee_kms":{"key_arn":"arn:x","allow_fingerprint_init":true}}"#,
            r#"{"tee_kms":{"key_arn":"arn:x","allow_anchor_init":true}}"#,
            r#"{"tee_kms":{"key_arn":"arn:x","admin_did":"did:key:zEvil"}}"#,
            r#"{"tee_kms":{"key_arn":"arn:x","admin_context_id":"root"}}"#,
            r#"{"admin_did":"did:key:zEvil"}"#,
            r#"{"mode":"optional"}"#,
            r#"{"tee":{"mode":"optional"}}"#,
            r#"{"resolver_url":"http://evil"}"#,
            r#"{"storage_key_salt":"x"}"#,
            r#"{"messaging":{"mediator_did":"did:x","setup_acl":true}}"#,
        ];
        for p in poison {
            assert!(
                serde_json::from_str::<TenantConfigOverlay>(p).is_err(),
                "overlay must reject unknown/forbidden field: {p}"
            );
        }
    }

    #[test]
    fn overlay_accepts_the_allowlisted_fields() {
        let ok = format!(
            r#"{{"vta_name":"acme","public_url":"https://vta.acme.example.com",
                 "vta_did":"did:webvh:scid:acme.example.com:vta",
                 "tee_kms":{{"key_arn":"{GOOD_ARN}",
                             "vta_did_template":"did:webvh:{{SCID}}:acme.example.com:vta",
                             "anchor_table_name":"vta-rollback-anchor-acme",
                             "anchor_writer_credential_ciphertext":"base64=="}},
                 "messaging":{{"mediator_did":"did:webvh:scid:mediator","mediator_url":"wss://m"}}}}"#
        );
        let parsed: TenantConfigOverlay =
            serde_json::from_str(&ok).expect("well-formed overlay must parse");
        assert_eq!(parsed.vta_name.as_deref(), Some("acme"));
        let kms = parsed.tee_kms.expect("tee_kms present");
        assert_eq!(kms.key_arn, GOOD_ARN);
    }

    // -- key_arn validation (§3.5): shape + account allowlist, fail-closed.

    #[test]
    fn validate_key_arn_accepts_allowlisted_account() {
        let allowed = vec!["111122223333".to_string()];
        assert_eq!(validate_key_arn(GOOD_ARN, &allowed), Ok(()));
    }

    #[test]
    fn validate_key_arn_rejects_unlisted_account() {
        let allowed = vec!["999988887777".to_string()];
        assert_eq!(
            validate_key_arn(GOOD_ARN, &allowed),
            Err(TenantOverlayError::KeyArnAccountNotAllowed {
                account: "111122223333".to_string(),
                allowed,
            })
        );
    }

    #[test]
    fn validate_key_arn_empty_allowlist_is_deny() {
        assert_eq!(
            validate_key_arn(GOOD_ARN, &[]),
            Err(TenantOverlayError::NoAccountsAllowlisted)
        );
    }

    #[test]
    fn validate_key_arn_rejects_malformed() {
        let allowed = vec!["111122223333".to_string()];
        for bad in [
            "not-an-arn",
            "arn:aws:s3:::bucket",
            "arn:aws:kms:us-east-1:111122223333:alias/foo",
            "arn:aws:kms::111122223333:key/abc", // empty region
            "arn:aws:kms:us-east-1::key/abc",    // empty account
            "",
        ] {
            assert!(
                matches!(
                    validate_key_arn(bad, &allowed),
                    Err(TenantOverlayError::MalformedKeyArn(_))
                ),
                "expected MalformedKeyArn for {bad:?}"
            );
        }
    }

    #[test]
    fn region_is_derived_from_arn() {
        assert_eq!(region_from_arn(GOOD_ARN).as_deref(), Ok("us-east-1"));
        assert!(region_from_arn("bogus").is_err());
    }

    // -- apply onto a baked base (tee-only).

    #[cfg(feature = "tee")]
    #[test]
    fn apply_overlay_sets_key_arn_and_derives_region() {
        let mut base: crate::AppConfig = toml::from_str(
            r#"
            [tee]
            allowed_kms_accounts = ["111122223333"]
            [tee.kms]
            region = "PLACEHOLDER"
            key_arn = "PLACEHOLDER"
            "#,
        )
        .expect("base config parses");

        let overlay: TenantConfigOverlay =
            serde_json::from_str(&format!(r#"{{"tee_kms":{{"key_arn":"{GOOD_ARN}"}}}}"#)).unwrap();

        apply_tenant_overlay(&mut base, overlay).expect("apply succeeds");
        let kms = base.tee.kms.as_ref().unwrap();
        assert_eq!(kms.key_arn, GOOD_ARN);
        assert_eq!(kms.region, "us-east-1");
    }

    #[cfg(feature = "tee")]
    #[test]
    fn apply_overlay_rejects_unlisted_account() {
        let mut base: crate::AppConfig = toml::from_str(
            r#"
            [tee]
            allowed_kms_accounts = ["999988887777"]
            [tee.kms]
            region = "PLACEHOLDER"
            key_arn = "PLACEHOLDER"
            "#,
        )
        .unwrap();
        let overlay: TenantConfigOverlay =
            serde_json::from_str(&format!(r#"{{"tee_kms":{{"key_arn":"{GOOD_ARN}"}}}}"#)).unwrap();
        assert!(matches!(
            apply_tenant_overlay(&mut base, overlay),
            Err(TenantOverlayError::KeyArnAccountNotAllowed { .. })
        ));
        // Fail-closed: the placeholder key_arn was NOT overwritten.
        assert_eq!(base.tee.kms.as_ref().unwrap().key_arn, "PLACEHOLDER");
    }

    #[cfg(feature = "tee")]
    #[test]
    fn apply_overlay_missing_base_kms_section_errors() {
        let mut base: crate::AppConfig = toml::from_str("").unwrap();
        let overlay: TenantConfigOverlay =
            serde_json::from_str(&format!(r#"{{"tee_kms":{{"key_arn":"{GOOD_ARN}"}}}}"#)).unwrap();
        assert_eq!(
            apply_tenant_overlay(&mut base, overlay),
            Err(TenantOverlayError::BaseMissingKmsSection)
        );
    }
}
