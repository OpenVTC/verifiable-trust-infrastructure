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
///
/// Note what is **absent on purpose**: there is no `vta_did` field. The VTA's
/// own identity is *provisioned*, not merely *named*: the enclave derives the
/// signing / key-agreement / sealed-transfer keys (BIP-32 from the sealed seed),
/// builds and signs the `did:webvh` document, and only then adopts the DID —
/// see [`vta_did_template`](TenantKmsOverlay::vta_did_template) and ADR-0109.
/// Accepting a bare DID string would install an identity with **no key
/// records**, so the overlay only carries the template the enclave provisions
/// from; the resulting DID becomes the authoritative stored identity and later
/// boots restore it from the encrypted store.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantConfigOverlay {
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
    /// The baked config sets `tee.kms.allow_anchor_init = true` (so a fresh-store
    /// boot may establish the anti-rollback manifest baseline) but no external
    /// anchor `table_name` is configured — that would silently drop to
    /// manifest-only protection. The overlay MUST supply `anchor_table_name`.
    AnchorTableRequired,
    /// The baked base has no `[messaging]` section and the overlay's `messaging`
    /// block omits `mediator_did`, which is required to construct one.
    MessagingMediatorDidRequired,
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
            Self::AnchorTableRequired => write!(
                f,
                "baked tee.kms.allow_anchor_init = true but no external anchor \
                 table_name is configured — the tenant overlay must supply \
                 anchor_table_name (else anti-rollback drops to manifest-only)"
            ),
            Self::MessagingMediatorDidRequired => write!(
                f,
                "tenant overlay carries a messaging block and the baked base has \
                 no [messaging] section — the overlay must supply mediator_did"
            ),
        }
    }
}

impl std::error::Error for TenantOverlayError {}

/// Parse a KMS key ARN into `(region, account)`, enforcing the full shape:
/// `arn:aws:kms:<region>:<12-digit-account>:key/<non-empty-id>`.
///
/// Rejects alias ARNs, empty region, non-12-digit or non-numeric accounts, and
/// an empty key identifier.
fn parse_kms_key_arn(key_arn: &str) -> Option<(&str, &str)> {
    let parts: Vec<&str> = key_arn.splitn(6, ':').collect();
    match parts.as_slice() {
        ["arn", "aws", "kms", region, account, resource]
            if !region.is_empty()
                && is_aws_account_id(account)
                && resource
                    .strip_prefix("key/")
                    .is_some_and(|id| !id.is_empty()) =>
        {
            Some((region, account))
        }
        _ => None,
    }
}

/// True for a syntactically valid AWS account ID: exactly 12 ASCII digits.
fn is_aws_account_id(s: &str) -> bool {
    s.len() == 12 && s.bytes().all(|b| b.is_ascii_digit())
}

/// Validate a KMS `key_arn` against the baked account allowlist.
///
/// Fail-closed on every path: a malformed ARN (bad shape, alias, non-12-digit
/// account, or empty key id), an empty allowlist, or an account not on the list
/// all reject.
pub fn validate_key_arn(key_arn: &str, allowed: &[String]) -> Result<(), TenantOverlayError> {
    let (_region, account) = parse_kms_key_arn(key_arn)
        .ok_or_else(|| TenantOverlayError::MalformedKeyArn(key_arn.to_string()))?;
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
    parse_kms_key_arn(key_arn)
        .map(|(region, _account)| region.to_string())
        .ok_or_else(|| TenantOverlayError::MalformedKeyArn(key_arn.to_string()))
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
                // `MessagingConfig` has no `Default` because `mediator_did` is
                // required — so materialize it only when the overlay actually
                // supplies one. Defaulting to `""` here would hand the service a
                // structurally invalid DID and return `Ok`, which is the one
                // fail-*open* path in this function.
                let mediator_did = m
                    .mediator_did
                    .ok_or(TenantOverlayError::MessagingMediatorDidRequired)?;
                base.messaging = Some(crate::MessagingConfig {
                    mediator_did,
                    mediator_url: m.mediator_url.unwrap_or_default(),
                    mediator_host: None,
                    setup_acl: false,
                    drain_inbox_on_start: false,
                });
            }
        }
    }

    // Fleet safety: if the baked policy allows establishing the anti-rollback
    // manifest baseline on a fresh store (`allow_anchor_init = true`), an
    // external anchor table MUST be configured — otherwise a fresh boot silently
    // drops to manifest-only protection.
    //
    // Checked on EVERY apply, not just overlays that carry a `tee_kms` block: an
    // overlay that simply omits `tee_kms` reaches the same degraded state, so
    // scoping this to the `tee_kms` arm would make "send no KMS block" the way
    // around it. (Self-host/baked configs don't run this apply path at all.)
    if let Some(kms) = base.tee.kms.as_ref()
        && kms.allow_anchor_init
        && kms.anchor.is_none()
    {
        return Err(TenantOverlayError::AnchorTableRequired);
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
            // A bare, keyless DID string is NOT identity provisioning (ADR-0109):
            // the enclave provisions from `vta_did_template`, so `vta_did` is not
            // an overlay field and must be rejected structurally.
            r#"{"vta_did":"did:webvh:scid:acme.example.com:vta"}"#,
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
            "arn:aws:kms:us-east-1:111122223333:key/", // empty key id
            "arn:aws:kms:us-east-1:12345:key/abc", // account not 12 digits
            "arn:aws:kms:us-east-1:11112222333a:key/abc", // account non-numeric
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

    #[cfg(feature = "tee")]
    #[test]
    fn apply_overlay_requires_anchor_when_allow_anchor_init_is_baked() {
        // Fleet base bakes allow_anchor_init = true; an overlay with no anchor
        // table must be rejected (would silently drop to manifest-only).
        let base_toml = r#"
            [tee]
            allowed_kms_accounts = ["111122223333"]
            [tee.kms]
            region = "PLACEHOLDER"
            key_arn = "PLACEHOLDER"
            allow_anchor_init = true
        "#;

        let mut base: crate::AppConfig = toml::from_str(base_toml).unwrap();
        let no_anchor: TenantConfigOverlay =
            serde_json::from_str(&format!(r#"{{"tee_kms":{{"key_arn":"{GOOD_ARN}"}}}}"#)).unwrap();
        assert_eq!(
            apply_tenant_overlay(&mut base, no_anchor),
            Err(TenantOverlayError::AnchorTableRequired)
        );

        // With an anchor table the overlay applies.
        let mut base: crate::AppConfig = toml::from_str(base_toml).unwrap();
        let with_anchor: TenantConfigOverlay = serde_json::from_str(&format!(
            r#"{{"tee_kms":{{"key_arn":"{GOOD_ARN}","anchor_table_name":"vta-anchor-acme"}}}}"#
        ))
        .unwrap();
        apply_tenant_overlay(&mut base, with_anchor).expect("apply with anchor succeeds");
        assert_eq!(
            base.tee
                .kms
                .as_ref()
                .unwrap()
                .anchor
                .as_ref()
                .unwrap()
                .table_name,
            "vta-anchor-acme"
        );
    }

    #[cfg(feature = "tee")]
    #[test]
    fn anchor_requirement_is_not_bypassable_by_omitting_the_tee_kms_block() {
        // Regression: the allow_anchor_init guard used to live INSIDE the
        // `if let Some(tee_kms)` arm, so an overlay that simply omitted the
        // tee_kms block applied cleanly and left the enclave in exactly the
        // degraded (manifest-only anti-rollback) state the guard exists to
        // prevent — "send no KMS block" was the way around it.
        let base_toml = r#"
            [tee]
            allowed_kms_accounts = ["111122223333"]
            [tee.kms]
            region = "us-east-1"
            key_arn = "arn:aws:kms:us-east-1:111122223333:key/already-baked"
            allow_anchor_init = true
        "#;

        // An empty overlay.
        let mut base: crate::AppConfig = toml::from_str(base_toml).unwrap();
        let empty: TenantConfigOverlay = serde_json::from_str("{}").unwrap();
        assert_eq!(
            apply_tenant_overlay(&mut base, empty),
            Err(TenantOverlayError::AnchorTableRequired)
        );

        // An overlay that carries other fields but no tee_kms.
        let mut base: crate::AppConfig = toml::from_str(base_toml).unwrap();
        let no_kms: TenantConfigOverlay =
            serde_json::from_str(r#"{"vta_name":"acme","public_url":"https://vta.acme.test"}"#)
                .unwrap();
        assert_eq!(
            apply_tenant_overlay(&mut base, no_kms),
            Err(TenantOverlayError::AnchorTableRequired)
        );

        // Same base, but the baked config already has an anchor → nothing to
        // require, so a tee_kms-free overlay applies.
        let with_baked_anchor = format!("{base_toml}\n[tee.kms.anchor]\ntable_name = \"baked\"\n");
        let mut base: crate::AppConfig = toml::from_str(&with_baked_anchor).unwrap();
        let empty: TenantConfigOverlay = serde_json::from_str("{}").unwrap();
        apply_tenant_overlay(&mut base, empty)
            .expect("no requirement to enforce when the base already has an anchor");
    }

    #[cfg(feature = "tee")]
    #[test]
    fn materializing_messaging_without_a_mediator_did_is_refused() {
        // Regression: this arm used to `unwrap_or_default()`, writing
        // `mediator_did = ""` — a structurally invalid DID — and returning Ok.
        // It was the one fail-OPEN path in the function.
        let mut base: crate::AppConfig = toml::from_str("").unwrap();
        let url_only: TenantConfigOverlay =
            serde_json::from_str(r#"{"messaging":{"mediator_url":"wss://mediator.test/ws"}}"#)
                .unwrap();
        assert_eq!(
            apply_tenant_overlay(&mut base, url_only),
            Err(TenantOverlayError::MessagingMediatorDidRequired)
        );
        assert!(base.messaging.is_none(), "fail-closed: nothing was written");

        // With a mediator_did it materializes.
        let mut base: crate::AppConfig = toml::from_str("").unwrap();
        let full: TenantConfigOverlay = serde_json::from_str(
            r#"{"messaging":{"mediator_did":"did:web:mediator.test","mediator_url":"wss://mediator.test/ws"}}"#,
        )
        .unwrap();
        apply_tenant_overlay(&mut base, full).expect("apply succeeds");
        let msg = base.messaging.as_ref().unwrap();
        assert_eq!(msg.mediator_did, "did:web:mediator.test");
        assert_eq!(msg.mediator_url, "wss://mediator.test/ws");
    }

    #[cfg(feature = "tee")]
    #[test]
    fn effective_config_digest_reflects_overlay_key_arn() {
        // The critical property (design-note attestation fix): the attestation
        // digest must change with the tenant's key_arn, not stay pinned to the
        // baked placeholder.
        let base_toml = r#"
            [tee]
            allowed_kms_accounts = ["111122223333", "444455556666"]
            [tee.kms]
            region = "PLACEHOLDER"
            key_arn = "PLACEHOLDER"
        "#;
        let mut a: crate::AppConfig = toml::from_str(base_toml).unwrap();
        let mut b: crate::AppConfig = toml::from_str(base_toml).unwrap();
        apply_tenant_overlay(
            &mut a,
            serde_json::from_str(
                r#"{"tee_kms":{"key_arn":"arn:aws:kms:us-east-1:111122223333:key/aaaa"}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        apply_tenant_overlay(
            &mut b,
            serde_json::from_str(
                r#"{"tee_kms":{"key_arn":"arn:aws:kms:us-west-2:444455556666:key/bbbb"}}"#,
            )
            .unwrap(),
        )
        .unwrap();

        let da = a.compute_config_attestation_digest().unwrap();
        let db = b.compute_config_attestation_digest().unwrap();
        assert_eq!(da.len(), 48, "SHA-384 is 48 bytes");
        assert_ne!(
            da, db,
            "digest must differ when the tenant key_arn/region differs"
        );
        // Deterministic: same effective config → same digest.
        assert_eq!(da, a.compute_config_attestation_digest().unwrap());
    }
}
