//! Bootstrap request — W3C Verifiable Presentation signed by the
//! integration's ephemeral `client_did` (Ed25519).
//!
//! Wire shape is a VP with no embedded VCs. The VP's custom fields
//! (`nonce`, `validUntil`, `label`, `ask`) carry the operator's intent
//! and are covered by the VP's proof.
//!
//! Typestate: the deserialized [`BootstrapRequest`] is inert until
//! [`BootstrapRequest::verify`] produces a [`VerifiedBootstrapRequest`]
//! that downstream handlers consume.

use std::collections::BTreeMap;

use affinidi_crypto::did_key as did_key_helpers;
use affinidi_data_integrity::{
    DataIntegrityProof, SignOptions, VerifyOptions, crypto_suites::CryptoSuite,
};
use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::sealed_transfer::SealedTransferError;

use super::{BOOTSTRAP_CONTEXT_URL, ProvisionIntegrationError, VC_V2_CONTEXT_URL};

/// VP-framed bootstrap request. Wire shape conforms to VC Data Model 2.0
/// §6.1 (VPs MAY omit `verifiableCredential`; self-attested presentation
/// of arbitrary claims is permitted).
///
/// Standard VP fields (`@context`, `type`, `holder`, `id`, `proof`) are
/// at the top level; the custom bootstrap fields (`nonce`, `validUntil`,
/// `label`, `ask`) sit alongside as additional properties authenticated
/// by the same proof.
///
/// `deny_unknown_fields` keeps attackers from smuggling fields past the
/// verifier — every field on the wire must be recognised here or the
/// request is rejected before the DI proof is even checked.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRequest {
    /// JSON-LD contexts. Must include `https://www.w3.org/ns/credentials/v2`
    /// and `https://openvtc.org/contexts/bootstrap-v1`.
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// VP types. MUST include `VerifiablePresentation`; SHOULD include
    /// `BootstrapRequest` so verifiers can filter.
    #[serde(rename = "type")]
    pub types: Vec<String>,

    /// Unique id for this presentation. URN-shaped.
    pub id: String,

    /// Ephemeral `did:key` of the integration. Bundle is HPKE-sealed to
    /// this DID's X25519 derivation; proof verifies against this DID.
    pub holder: String,

    /// Random 16-byte nonce, base64url-no-pad. Becomes the sealed-bundle
    /// `bundle_id`.
    pub nonce: String,

    /// Freshness bound. ISO-8601 RFC 3339, UTC. Verifier allows ±5min
    /// skew.
    #[serde(rename = "validUntil")]
    pub valid_until: String,

    /// Optional human-readable tag for audit-log triage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// What the holder is asking the VTA to do.
    pub ask: BootstrapAsk,

    /// Data Integrity proof. `eddsa-jcs-2022`, `proofPurpose =
    /// "authentication"`, signed by the holder's key.
    pub proof: Value,
}

/// Tagged enum of bootstrap intents. Extensible — add new variants as new
/// kinds of integration bootstrap emerge.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BootstrapAsk {
    /// Template-driven integration bootstrap. The VTA mints a fresh
    /// integration DID via `template`, optionally rotates the admin DID
    /// to a fresh `admin_template`-derived identity, and ships both
    /// (plus the integration DID's keys, did.jsonl, VC, trust bundle)
    /// in a [`SealedPayloadV1::TemplateBootstrap`](crate::sealed_transfer::SealedPayloadV1)
    /// bundle.
    ///
    /// The `templateBootstrap` alias accepts the
    /// `provision/integration/0.2` camelCase tag; serialisation keeps the
    /// 0.1 `TemplateBootstrap` form. The tag is inside the signed VP, so
    /// verification must run over the wire bytes — see
    /// [`BootstrapRequest::verify_value`].
    #[serde(alias = "templateBootstrap")]
    TemplateBootstrap(TemplateBootstrapAsk),
    /// Admin-DID rotation only — no integration DID minted. The VTA
    /// renders `admin_template`, mints a fresh long-term admin DID,
    /// binds the authorization VC + ACL row to that DID, and ships
    /// only the admin material in a [`SealedPayloadV1::AdminRotation`]
    /// bundle.
    ///
    /// Use when the consumer brings (or will mint elsewhere) its own
    /// integration DID and only needs a long-term admin credential at
    /// this VTA — rolling the ephemeral setup did:key over to a fresh
    /// VTA-minted admin identity in a single round-trip.
    ///
    /// [`SealedPayloadV1::AdminRotation`]:
    /// crate::sealed_transfer::SealedPayloadV1::AdminRotation
    ///
    /// The `adminRotation` alias accepts the `provision/integration/0.2`
    /// camelCase tag; serialisation keeps the 0.1 `AdminRotation` form.
    #[serde(alias = "adminRotation")]
    AdminRotation(AdminRotationAsk),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateBootstrapAsk {
    /// VTA context this integration will live in. The operator must
    /// confirm on the producer side (via CLI `--context`); this field
    /// is a hint for the common case where integration and admin agree
    /// up front.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "contextHint")]
    pub context_hint: Option<String>,

    /// Template name + variables. Template must already be registered
    /// at the VTA; inline definitions are rejected.
    pub template: DidTemplateRef,

    /// Optional admin-DID template. When present, the VTA renders it,
    /// mints a fresh admin DID + keys, and binds the authorization VC
    /// and ACL row to that DID — rolling the holder over from the
    /// ephemeral `client_did` to a long-term VTA-minted admin identity
    /// in a single bootstrap round-trip.
    ///
    /// When absent, the authorization VC's subject is `client_did` and
    /// the ACL row is written for `client_did` (pre-rollover
    /// behaviour).
    ///
    /// The admin template must declare `kind: "admin"` at the VTA and
    /// be registered (built-in or operator-uploaded) just like the
    /// integration template.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "adminTemplate")]
    pub admin_template: Option<DidTemplateRef>,

    /// Free-form operator note for audit logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Admin-only rotation ask. Mints a fresh long-term admin DID via
/// `admin_template`; no integration template, no integration DID.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRotationAsk {
    /// VTA context the admin grant lands in. Hint for the common case;
    /// the producer-side caller must agree with `--context` if both are
    /// supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "contextHint")]
    pub context_hint: Option<String>,

    /// Admin-DID template — typically the built-in `vta-admin`. Must be
    /// registered at the VTA and declare `kind: "admin"`.
    #[serde(rename = "adminTemplate")]
    pub admin_template: DidTemplateRef,

    /// Free-form operator note for audit logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Reference to a DID template registered at the VTA.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidTemplateRef {
    /// Template name the VTA already knows (built-in or operator-
    /// uploaded via `pnm did-templates create`).
    pub name: String,
    /// Variable bindings to pass to the template renderer. Must satisfy
    /// the template's `requiredVars`; `optionalVars` overrides accepted.
    #[serde(default)]
    pub vars: BTreeMap<String, Value>,
}

impl BootstrapRequest {
    /// Build + sign a bootstrap request with the holder's Ed25519 seed.
    ///
    /// `ed25519_seed` must be the private seed whose public derivation
    /// encodes to the `client_did` passed in — caller responsibility to
    /// keep them matched.
    pub async fn sign(
        ed25519_seed: &[u8; 32],
        client_did: &str,
        nonce: [u8; 16],
        validity: Duration,
        label: Option<String>,
        ask: BootstrapAsk,
    ) -> Result<Self, ProvisionIntegrationError> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

        let now = Utc::now();
        let valid_until = now + validity;

        // Build a Secret whose `id` encodes the did:key-with-fragment
        // verification method shape the Data Integrity resolver
        // recognises (`did:key:zXxx#zXxx`).
        let vm_id = did_key_to_vm(client_did).ok_or_else(|| {
            ProvisionIntegrationError::Parse(format!("invalid client_did: {client_did}"))
        })?;
        let mut signer = Secret::generate_ed25519(Some(&vm_id), Some(ed25519_seed));
        signer.id = vm_id.clone();

        // The unsigned VP body — all fields except `proof`. Data Integrity
        // signs this serialized structure (plus the signed proof config)
        // under JCS canonicalization.
        let unsigned = Self {
            context: vec![VC_V2_CONTEXT_URL.into(), BOOTSTRAP_CONTEXT_URL.into()],
            types: vec!["VerifiablePresentation".into(), "BootstrapRequest".into()],
            id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            holder: client_did.to_string(),
            nonce: B64URL.encode(nonce),
            valid_until: rfc3339(valid_until),
            label,
            ask,
            proof: Value::Null, // placeholder — replaced after sign
        };

        let sign_options = SignOptions::new()
            .with_proof_purpose("authentication")
            .with_created(now);

        // Sign the document-with-null-proof. Verifiers must reconstruct
        // the same shape to re-derive the canonical bytes.
        let mut signing_doc = serde_json::to_value(&unsigned)
            .map_err(|e| ProvisionIntegrationError::Parse(format!("serialize VP: {e}")))?;
        // Strip `proof` before signing — JCS is sensitive to field
        // presence; the verifier sees the final VP with `proof`
        // populated, so sign-time must use the same shape after the
        // proof is removed.
        if let Some(obj) = signing_doc.as_object_mut() {
            obj.remove("proof");
        }

        let proof = DataIntegrityProof::sign(&signing_doc, &signer, sign_options)
            .await
            .map_err(|e| ProvisionIntegrationError::DataIntegrity(format!("sign VP: {e}")))?;

        let mut out = unsigned;
        out.proof = serde_json::to_value(&proof)
            .map_err(|e| ProvisionIntegrationError::Parse(format!("serialize proof: {e}")))?;
        Ok(out)
    }

    /// Verify the proof + freshness + structure, returning the typestate
    /// form that downstream handlers consume.
    ///
    /// Re-serialises `self` and delegates to [`verify_value`]. Use this for
    /// Rust-internal round-trips where this crate both built and verifies
    /// the request. **Network handlers MUST call [`verify_value`] with the
    /// bytes exactly as received** — re-serialising the typed struct
    /// re-imposes this crate's wire casing and would reject any holder
    /// (e.g. a 0.2 client) whose signed casing differs.
    ///
    /// [`verify_value`]: Self::verify_value
    pub fn verify(self) -> Result<VerifiedBootstrapRequest, ProvisionIntegrationError> {
        let value = serde_json::to_value(&self)
            .map_err(|e| ProvisionIntegrationError::Parse(format!("serialize VP: {e}")))?;
        Self::verify_value(value)
    }

    /// Verify a bootstrap VP from its JSON **exactly as received on the
    /// wire**, returning the typestate form downstream handlers consume.
    ///
    /// The Data Integrity proof covers the JCS canonicalisation of the VP
    /// with `proof` removed. Verifying against the bytes as received —
    /// rather than re-serialising the typed [`BootstrapRequest`] — means a
    /// holder whose wire casing differs from this crate's serde output
    /// still verifies. Concretely, a `provision/integration/0.2` client
    /// signs `ask.type` as camelCase (`templateBootstrap`); re-serialising
    /// the typed enum would re-impose the 0.1 `TemplateBootstrap` casing
    /// and break the proof. JCS preserves string *values*, so the signed
    /// casing survives canonicalisation and the proof checks out — while
    /// the typed view (built via the `BootstrapAsk` aliases) still drives
    /// downstream business logic on a normalised enum.
    pub fn verify_value(
        value: Value,
    ) -> Result<VerifiedBootstrapRequest, ProvisionIntegrationError> {
        // Typed view for structural fields + downstream business logic.
        // `deny_unknown_fields` still rejects smuggled fields; the
        // `BootstrapAsk` aliases accept both 0.1 (`TemplateBootstrap`) and
        // 0.2 (`templateBootstrap`) tag casings.
        let req: BootstrapRequest = serde_json::from_value(value.clone())
            .map_err(|e| ProvisionIntegrationError::Parse(format!("parse VP: {e}")))?;

        // Structure checks first (cheap, deterministic).
        if !req.types.iter().any(|t| t == "VerifiablePresentation") {
            return Err(ProvisionIntegrationError::InvalidClaim(
                "type array must include 'VerifiablePresentation'".into(),
            ));
        }
        if !req.types.iter().any(|t| t == "BootstrapRequest") {
            return Err(ProvisionIntegrationError::InvalidClaim(
                "type array must include 'BootstrapRequest'".into(),
            ));
        }

        // Holder DID must be a decodable did:key (Ed25519).
        let holder_ed_pub = did_key_helpers::did_key_to_ed25519_pub(&req.holder)
            .map_err(|e| ProvisionIntegrationError::HolderMismatch(format!("holder: {e}")))?;

        // Parse the proof out (typed view carries the same proof bytes).
        let proof: DataIntegrityProof = serde_json::from_value(req.proof.clone())
            .map_err(|e| ProvisionIntegrationError::BadProof(format!("parse proof: {e}")))?;

        // Cryptosuite check — only JCS is accepted here. If we add RDFC
        // later, widen this allowlist.
        if !matches!(proof.cryptosuite, CryptoSuite::EddsaJcs2022) {
            return Err(ProvisionIntegrationError::BadProof(format!(
                "unsupported cryptosuite {:?} (expected eddsa-jcs-2022)",
                proof.cryptosuite
            )));
        }

        // Proof's `verificationMethod` must live under the holder DID
        // (same DID, any fragment). Prevents a proof by someone else's
        // key being accepted via a forged `holder` field.
        let vm_did = proof
            .verification_method
            .split_once('#')
            .map(|(d, _)| d)
            .ok_or_else(|| {
                ProvisionIntegrationError::HolderMismatch("verificationMethod missing '#'".into())
            })?;
        if vm_did != req.holder {
            return Err(ProvisionIntegrationError::HolderMismatch(format!(
                "verificationMethod DID '{}' does not match holder '{}'",
                vm_did, req.holder
            )));
        }

        // Verify the proof against the VP as received, with `proof`
        // stripped — the exact shape the holder signed.
        let mut signing_doc = value;
        if let Some(obj) = signing_doc.as_object_mut() {
            obj.remove("proof");
        }

        proof
            .verify_with_public_key(&signing_doc, &holder_ed_pub, VerifyOptions::new())
            .map_err(|e| ProvisionIntegrationError::BadProof(format!("verify VP: {e}")))?;

        // Freshness (±5min skew).
        let now = Utc::now();
        let skew = Duration::minutes(5);
        let vu = req
            .valid_until
            .parse::<DateTime<Utc>>()
            .map_err(|e| ProvisionIntegrationError::Parse(format!("validUntil: {e}")))?;
        if vu + skew < now {
            return Err(ProvisionIntegrationError::Expired(format!(
                "validUntil {vu} has passed"
            )));
        }

        Ok(VerifiedBootstrapRequest { inner: req })
    }
}

/// Post-verification form. Only constructable via
/// [`BootstrapRequest::verify`]. Any function that takes this is
/// guaranteed to be looking at a verified request whose `holder` actually
/// signed the bytes and whose `validUntil` has not passed.
#[derive(Debug, Clone)]
pub struct VerifiedBootstrapRequest {
    inner: BootstrapRequest,
}

impl VerifiedBootstrapRequest {
    /// The ephemeral `did:key` that signed this request.
    pub fn holder(&self) -> &str {
        &self.inner.holder
    }

    /// The 16-byte nonce (decoded). Becomes the sealed-bundle
    /// `bundle_id`.
    pub fn decode_nonce(&self) -> Result<[u8; 16], SealedTransferError> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        let raw = B64URL
            .decode(&self.inner.nonce)
            .map_err(|e| SealedTransferError::Base64(e.to_string()))?;
        raw.try_into()
            .map_err(|_| SealedTransferError::Wire("nonce must be 16 bytes".into()))
    }

    /// Raw 32-byte Ed25519 pubkey under `holder`'s did:key.
    pub fn decode_client_ed25519_pub(&self) -> Result<[u8; 32], ProvisionIntegrationError> {
        did_key_helpers::did_key_to_ed25519_pub(&self.inner.holder)
            .map_err(|e| ProvisionIntegrationError::HolderMismatch(format!("holder did:key: {e}")))
    }

    /// X25519 pubkey derived from the holder's Ed25519 pub, suitable for
    /// HPKE seal.
    pub fn decode_client_x25519_pub(&self) -> Result<[u8; 32], ProvisionIntegrationError> {
        let ed = self.decode_client_ed25519_pub()?;
        did_key_helpers::ed25519_pub_to_x25519_bytes(&ed).map_err(|e| {
            ProvisionIntegrationError::HolderMismatch(format!("holder X25519 derivation: {e}"))
        })
    }

    /// The operator's bootstrap intent. Phase 1: always `TemplateBootstrap`.
    pub fn ask(&self) -> &BootstrapAsk {
        &self.inner.ask
    }

    pub fn label(&self) -> Option<&str> {
        self.inner.label.as_deref()
    }

    pub fn id(&self) -> &str {
        &self.inner.id
    }

    pub fn valid_until(&self) -> &str {
        &self.inner.valid_until
    }

    /// Escape hatch for callers that need the raw VP JSON (e.g., to
    /// archive the request alongside the issued bundle for audit).
    pub fn as_wire(&self) -> &BootstrapRequest {
        &self.inner
    }

    /// Take ownership of the underlying wire form.
    pub fn into_wire(self) -> BootstrapRequest {
        self.inner
    }
}

// Builder ---------------------------------------------------------------

/// Ergonomic builder for VP-framed provision bootstrap requests.
///
/// Wraps [`BootstrapRequest::sign`] with a typed interface for the common
/// `TemplateBootstrap` ask shape, so callers don't have to assemble
/// [`BootstrapAsk`] / [`TemplateBootstrapAsk`] / [`DidTemplateRef`] by hand.
///
/// Two sign entry points:
///
/// - [`sign_with`](Self::sign_with) — reuse an existing long-lived
///   Ed25519 identity (the integration already has a keypair in its
///   keystore and wants the signed VP to bind to it).
///
/// - [`sign_ephemeral`](Self::sign_ephemeral) — mint a fresh keypair
///   scoped to this one bootstrap round-trip. Returns the seed so the
///   caller can persist it however they like (keyring, keystore,
///   plaintext file under 0600, etc.) and later match it to the
///   returned sealed bundle at open time.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use chrono::Duration;
/// use vta_sdk::provision_integration::ProvisionRequestBuilder;
///
/// let signed = ProvisionRequestBuilder::new("didcomm-mediator")
///     .var("URL", "https://mediator.example.com")
///     .context_hint("mediator-prod")
///     .admin_template("vta-admin")
///     .validity(Duration::days(7))
///     .label("mediator-prod-bootstrap")
///     .sign_ephemeral()
///     .await?;
///
/// // Persist `signed.seed` under `bundle_id_hex` so the matching
/// // `bootstrap open` can retrieve it. Hand `signed.request` (JSON)
/// // to the VTA operator.
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ProvisionRequestBuilder {
    /// Integration template name. `Some(_)` selects the
    /// [`BootstrapAsk::TemplateBootstrap`] intent; `None` selects
    /// [`BootstrapAsk::AdminRotation`] (admin-only path — no integration
    /// minted). Set via [`new`](Self::new) or
    /// [`for_admin_rotation`](Self::for_admin_rotation) respectively.
    template: Option<String>,
    vars: BTreeMap<String, Value>,
    context_hint: Option<String>,
    admin_template_name: Option<String>,
    admin_template_vars: BTreeMap<String, Value>,
    validity: Duration,
    label: Option<String>,
    note: Option<String>,
}

impl ProvisionRequestBuilder {
    /// Start a new builder targeting the named DID template (e.g.
    /// `"didcomm-mediator"`, `"did-host-http"`, or an operator-uploaded
    /// custom template). Selects the [`BootstrapAsk::TemplateBootstrap`]
    /// intent — the VTA mints an integration DID via this template.
    pub fn new(template_name: impl Into<String>) -> Self {
        Self {
            template: Some(template_name.into()),
            vars: BTreeMap::new(),
            context_hint: None,
            admin_template_name: None,
            admin_template_vars: BTreeMap::new(),
            validity: Duration::hours(1),
            label: None,
            note: None,
        }
    }

    /// Start a new builder for the [`BootstrapAsk::AdminRotation`]
    /// intent: the VTA renders `admin_template_name` (typically the
    /// built-in `"vta-admin"`), mints a fresh admin DID under its own
    /// custody, binds the authorization VC + ACL row to it, and ships
    /// the admin DID's key material — no integration DID, no integration
    /// template render.
    ///
    /// `vars`-style mutators ([`var`](Self::var), [`vars`](Self::vars))
    /// and [`admin_template`](Self::admin_template) are no-ops in this
    /// mode — there's no integration template to feed and the admin
    /// template is already pinned. Pass admin-template variables via
    /// [`admin_template_var`](Self::admin_template_var).
    pub fn for_admin_rotation(admin_template_name: impl Into<String>) -> Self {
        Self {
            template: None,
            vars: BTreeMap::new(),
            context_hint: None,
            admin_template_name: Some(admin_template_name.into()),
            admin_template_vars: BTreeMap::new(),
            validity: Duration::hours(1),
            label: None,
            note: None,
        }
    }

    /// Insert a single template variable. Later calls with the same key
    /// overwrite earlier ones.
    pub fn var(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.vars.insert(key.into(), value.into());
        self
    }

    /// Bulk-insert template variables from any iterable.
    pub fn vars<I, K, V>(mut self, entries: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<Value>,
    {
        for (k, v) in entries {
            self.vars.insert(k.into(), v.into());
        }
        self
    }

    /// Hint the target context on the VTA. The VTA operator may override
    /// this at provision time; when they do and the hint disagrees, the
    /// request is rejected rather than silently normalised.
    pub fn context_hint(mut self, ctx: impl Into<String>) -> Self {
        self.context_hint = Some(ctx.into());
        self
    }

    /// Opt into long-term admin-DID rollover: the VTA mints a fresh
    /// admin DID under its own key custody using the named template
    /// (typically the built-in `"vta-admin"`), binds the authorization
    /// VC + ACL row to that DID instead of the ephemeral `client_did`,
    /// and ships the private keys sealed alongside the integration's
    /// own keys.
    pub fn admin_template(mut self, name: impl Into<String>) -> Self {
        self.admin_template_name = Some(name.into());
        self
    }

    /// Add a variable to the admin-template render. No-op unless
    /// [`admin_template`](Self::admin_template) has been set.
    pub fn admin_template_var(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.admin_template_vars.insert(key.into(), value.into());
        self
    }

    /// Freshness window for the VP's `validUntil`. Default is 1h. Widen
    /// to days for setup flows where the request is shuttled between
    /// hosts offline.
    pub fn validity(mut self, d: Duration) -> Self {
        self.validity = d;
        self
    }

    /// Free-form human label echoed back in audit logs.
    pub fn label(mut self, l: impl Into<String>) -> Self {
        self.label = Some(l.into());
        self
    }

    /// Operator note attached to the ask (shows up in provision-time
    /// audit records).
    pub fn note(mut self, n: impl Into<String>) -> Self {
        self.note = Some(n.into());
        self
    }

    fn build_ask(&self) -> BootstrapAsk {
        match &self.template {
            Some(name) => BootstrapAsk::TemplateBootstrap(TemplateBootstrapAsk {
                context_hint: self.context_hint.clone(),
                template: DidTemplateRef {
                    name: name.clone(),
                    vars: self.vars.clone(),
                },
                admin_template: self
                    .admin_template_name
                    .as_ref()
                    .map(|name| DidTemplateRef {
                        name: name.clone(),
                        vars: self.admin_template_vars.clone(),
                    }),
                note: self.note.clone(),
            }),
            None => BootstrapAsk::AdminRotation(AdminRotationAsk {
                context_hint: self.context_hint.clone(),
                // `for_admin_rotation` is the only constructor that
                // leaves `template = None`, and it requires an admin
                // template name. A `None` here means a caller mutated
                // the builder past that invariant, which we treat as a
                // programmer error.
                admin_template: DidTemplateRef {
                    name: self
                        .admin_template_name
                        .clone()
                        .expect("admin rotation builder requires an admin template name"),
                    vars: self.admin_template_vars.clone(),
                },
                note: self.note.clone(),
            }),
        }
    }

    /// Sign with a caller-supplied Ed25519 seed plus its corresponding
    /// `did:key`. The caller is responsible for keeping the pair matched
    /// — the VP's `holder` is `client_did`, and the Data Integrity proof
    /// is verified against the key encoded in that DID.
    ///
    /// Use this when the integration already has a long-lived keypair
    /// (stored in its own keystore, keyring, TEE, etc.) that it wants
    /// to reuse as the bootstrap identity.
    pub async fn sign_with(
        self,
        ed25519_seed: &[u8; 32],
        client_did: &str,
    ) -> Result<BootstrapRequest, ProvisionIntegrationError> {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|e| ProvisionIntegrationError::Parse(format!("random nonce: {e}")))?;
        let ask = self.build_ask();
        BootstrapRequest::sign(
            ed25519_seed,
            client_did,
            nonce,
            self.validity,
            self.label,
            ask,
        )
        .await
    }

    /// Mint a fresh ephemeral Ed25519 keypair, derive its `did:key`, and
    /// sign the VP with it. Returns the VP plus the seed + derived
    /// `client_did` + `bundle_id` — the caller must persist the seed
    /// (addressed by `bundle_id`) somewhere retrievable at bundle-open
    /// time.
    ///
    /// The HPKE recipient secret used by
    /// [`sealed_transfer::open_bundle`](crate::sealed_transfer::open_bundle)
    /// derives from this seed via
    /// [`sealed_transfer::ed25519_seed_to_x25519_secret`][crate::sealed_transfer::ed25519_seed_to_x25519_secret].
    pub async fn sign_ephemeral(self) -> Result<SignedEphemeralRequest, ProvisionIntegrationError> {
        let (seed, pub_bytes) = crate::sealed_transfer::generate_ed25519_keypair();
        let client_did = did_key_helpers::ed25519_pub_to_did_key(&pub_bytes);
        let mut bundle_id = [0u8; 16];
        getrandom::fill(&mut bundle_id)
            .map_err(|e| ProvisionIntegrationError::Parse(format!("random nonce: {e}")))?;
        let ask = self.build_ask();
        let request = BootstrapRequest::sign(
            &seed,
            &client_did,
            bundle_id,
            self.validity,
            self.label,
            ask,
        )
        .await?;
        Ok(SignedEphemeralRequest {
            request,
            client_did,
            seed,
            bundle_id,
        })
    }
}

/// Output of [`ProvisionRequestBuilder::sign_ephemeral`].
///
/// Carries the signed VP plus the private material the caller needs to
/// (a) persist the seed for bundle-open time, and (b) correlate the
/// returned sealed bundle back to this request by `bundle_id`.
///
/// `seed` is wrapped in [`Zeroizing`] so the in-memory copy is scrubbed
/// on drop. Clone before persisting if you need the bytes after this
/// struct goes out of scope.
#[derive(Debug)]
pub struct SignedEphemeralRequest {
    /// The signed VP — serialize with serde_json and hand to the VTA
    /// operator, or write to disk.
    pub request: BootstrapRequest,
    /// The `did:key:z6Mk...` derived from the ephemeral public key.
    /// Mirrors `request.holder`.
    pub client_did: String,
    /// 32-byte Ed25519 seed. Persist under `bundle_id` (hex-encoded) and
    /// retrieve at `bootstrap open` time to derive the HPKE secret.
    pub seed: Zeroizing<[u8; 32]>,
    /// 16-byte nonce used both as the VP's `nonce` field and as the
    /// sealed-bundle id. Lookup key for the persisted seed.
    pub bundle_id: [u8; 16],
}

// Helpers ---------------------------------------------------------------

/// Build the verificationMethod id for a `did:key:z6Mk...` string —
/// `did:key:z6Mk...#z6Mk...`.
fn did_key_to_vm(did: &str) -> Option<String> {
    let rest = did.strip_prefix("did:key:")?;
    Some(format!("{did}#{rest}"))
}

fn rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed_transfer::generate_ed25519_keypair;

    fn sample_ask() -> BootstrapAsk {
        BootstrapAsk::TemplateBootstrap(TemplateBootstrapAsk {
            context_hint: Some("prod-mediator".into()),
            template: DidTemplateRef {
                name: "didcomm-mediator".into(),
                vars: BTreeMap::from([(
                    "URL".to_string(),
                    Value::String("https://mediator.example.com".into()),
                )]),
            },
            admin_template: None,
            note: None,
        })
    }

    fn sample_ask_with_admin_rollover() -> BootstrapAsk {
        BootstrapAsk::TemplateBootstrap(TemplateBootstrapAsk {
            context_hint: Some("prod-mediator".into()),
            template: DidTemplateRef {
                name: "didcomm-mediator".into(),
                vars: BTreeMap::from([(
                    "URL".to_string(),
                    Value::String("https://mediator.example.com".into()),
                )]),
            },
            admin_template: Some(DidTemplateRef {
                name: "vta-admin".into(),
                vars: BTreeMap::new(),
            }),
            note: None,
        })
    }

    fn sample_client_did(seed_byte: u8) -> ([u8; 32], String) {
        let (seed, pub_bytes) = {
            let (s, p) = generate_ed25519_keypair();
            (*s, p)
        };
        let _ = seed_byte;
        let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);
        (seed, did)
    }

    #[tokio::test]
    async fn sign_and_verify_round_trip() {
        let (seed, client_did) = sample_client_did(1);
        let vp = BootstrapRequest::sign(
            &seed,
            &client_did,
            [7u8; 16],
            Duration::hours(1),
            Some("smoke test".into()),
            sample_ask(),
        )
        .await
        .unwrap();

        assert_eq!(vp.holder, client_did);
        assert!(vp.types.iter().any(|t| t == "VerifiablePresentation"));
        assert!(vp.types.iter().any(|t| t == "BootstrapRequest"));

        let verified = vp.verify().expect("verify signed VP");
        assert_eq!(verified.holder(), client_did);
        assert_eq!(verified.decode_nonce().unwrap(), [7u8; 16]);
        assert!(matches!(verified.ask(), BootstrapAsk::TemplateBootstrap(_)));
        assert_eq!(verified.label(), Some("smoke test"));
    }

    #[tokio::test]
    async fn roundtrip_via_json() {
        let (seed, client_did) = sample_client_did(2);
        let vp = BootstrapRequest::sign(
            &seed,
            &client_did,
            [9u8; 16],
            Duration::hours(1),
            None,
            sample_ask(),
        )
        .await
        .unwrap();

        let json = serde_json::to_string(&vp).unwrap();
        let parsed: BootstrapRequest = serde_json::from_str(&json).unwrap();
        parsed.verify().expect("verify deserialized VP");
    }

    #[tokio::test]
    async fn tampered_nonce_rejected() {
        let (seed, client_did) = sample_client_did(3);
        let mut vp = BootstrapRequest::sign(
            &seed,
            &client_did,
            [1u8; 16],
            Duration::hours(1),
            None,
            sample_ask(),
        )
        .await
        .unwrap();

        // Attacker flips the nonce to a different value while keeping the
        // proof unchanged — must fail.
        vp.nonce = {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2u8; 16])
        };

        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::BadProof(_)),
            "expected BadProof, got {err:?}"
        );
    }

    #[tokio::test]
    async fn tampered_ask_rejected() {
        let (seed, client_did) = sample_client_did(4);
        let mut vp = BootstrapRequest::sign(
            &seed,
            &client_did,
            [5u8; 16],
            Duration::hours(1),
            None,
            sample_ask(),
        )
        .await
        .unwrap();

        // Attacker swaps the requested template to a different one.
        vp.ask = BootstrapAsk::TemplateBootstrap(TemplateBootstrapAsk {
            context_hint: Some("prod-mediator".into()),
            template: DidTemplateRef {
                name: "attacker-template".into(),
                vars: BTreeMap::new(),
            },
            admin_template: None,
            note: None,
        });

        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::BadProof(_)),
            "expected BadProof, got {err:?}"
        );
    }

    #[tokio::test]
    async fn expired_request_rejected() {
        let (seed, client_did) = sample_client_did(5);
        // Sign with negative validity — validUntil is already in the past.
        let vp = BootstrapRequest::sign(
            &seed,
            &client_did,
            [8u8; 16],
            Duration::hours(-2),
            None,
            sample_ask(),
        )
        .await
        .unwrap();

        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::Expired(_)),
            "expected Expired, got {err:?}"
        );
    }

    #[tokio::test]
    async fn admin_template_round_trips_through_sign_verify() {
        let (seed, client_did) = sample_client_did(11);
        let vp = BootstrapRequest::sign(
            &seed,
            &client_did,
            [12u8; 16],
            Duration::hours(1),
            Some("rollover".into()),
            sample_ask_with_admin_rollover(),
        )
        .await
        .unwrap();

        // VP must serialize the new field with its `adminTemplate` JSON
        // name, not the snake_case Rust name.
        let json = serde_json::to_value(&vp).unwrap();
        let admin_tpl = &json["ask"]["adminTemplate"];
        assert!(!admin_tpl.is_null(), "adminTemplate must serialize");
        assert_eq!(admin_tpl["name"], "vta-admin");

        // Round-trip through deserialize + verify; field must survive.
        let parsed: BootstrapRequest = serde_json::from_value(json).unwrap();
        let verified = parsed.verify().expect("verify");
        let BootstrapAsk::TemplateBootstrap(ask) = verified.ask() else {
            panic!("expected TemplateBootstrap ask")
        };
        let admin = ask
            .admin_template
            .as_ref()
            .expect("admin_template preserved");
        assert_eq!(admin.name, "vta-admin");
    }

    #[tokio::test]
    async fn admin_template_omitted_is_backward_compatible() {
        // Older callers built `TemplateBootstrapAsk` without the new
        // field; their on-the-wire JSON has no `adminTemplate` key. That
        // shape must still deserialize and verify.
        let (seed, client_did) = sample_client_did(13);
        let vp = BootstrapRequest::sign(
            &seed,
            &client_did,
            [14u8; 16],
            Duration::hours(1),
            None,
            sample_ask(),
        )
        .await
        .unwrap();

        let json = serde_json::to_value(&vp).unwrap();
        // Confirm the field really is absent on the wire — `skip_serializing_if`
        // keeps the legacy shape stable when callers don't set it.
        assert!(
            json["ask"].get("adminTemplate").is_none(),
            "absent field must be omitted from wire JSON, got: {}",
            json["ask"]
        );

        let parsed: BootstrapRequest = serde_json::from_value(json).unwrap();
        let verified = parsed.verify().expect("verify legacy-shape VP");
        let BootstrapAsk::TemplateBootstrap(ask) = verified.ask() else {
            panic!("expected TemplateBootstrap ask")
        };
        assert!(ask.admin_template.is_none());
    }

    #[tokio::test]
    async fn tampered_admin_template_rejected() {
        // Same threat model as `tampered_ask_rejected` but for the new
        // field: an attacker editing the admin template name after
        // signing must fail proof verification.
        let (seed, client_did) = sample_client_did(15);
        let mut vp = BootstrapRequest::sign(
            &seed,
            &client_did,
            [16u8; 16],
            Duration::hours(1),
            None,
            sample_ask_with_admin_rollover(),
        )
        .await
        .unwrap();

        let BootstrapAsk::TemplateBootstrap(ref mut ask) = vp.ask else {
            panic!("expected TemplateBootstrap ask")
        };
        ask.admin_template = Some(DidTemplateRef {
            name: "attacker-admin-template".into(),
            vars: BTreeMap::new(),
        });

        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::BadProof(_)),
            "expected BadProof, got {err:?}"
        );
    }

    #[tokio::test]
    async fn holder_swap_rejected() {
        let (seed_a, did_a) = sample_client_did(6);
        let (_, did_b) = sample_client_did(7);

        let mut vp = BootstrapRequest::sign(
            &seed_a,
            &did_a,
            [4u8; 16],
            Duration::hours(1),
            None,
            sample_ask(),
        )
        .await
        .unwrap();

        // Attacker rewrites the holder field to point at did_b, hoping the
        // verifier will resolve did_b's pubkey. Proof still signed by did_a.
        vp.holder = did_b;

        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::HolderMismatch(_)),
            "expected HolderMismatch, got {err:?}"
        );
    }

    #[test]
    fn client_x25519_derivation_matches_sealed_transfer() {
        // A verified request's decode_client_x25519_pub() must agree with
        // deriving X25519 directly from the Ed25519 seed through the
        // sealed-transfer helper.
        use crate::sealed_transfer::ed25519_seed_to_x25519_secret;
        use crate::sealed_transfer::hpke::{open, seal};

        let (seed, ed_pub) = {
            let (s, p) = generate_ed25519_keypair();
            (*s, p)
        };
        let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&ed_pub);

        // Simulate a VerifiedBootstrapRequest by directly constructing it
        // (tests need not sign/verify to exercise the derivation path).
        let wire = BootstrapRequest {
            context: vec![VC_V2_CONTEXT_URL.into(), BOOTSTRAP_CONTEXT_URL.into()],
            types: vec!["VerifiablePresentation".into(), "BootstrapRequest".into()],
            id: "urn:uuid:test".into(),
            holder: did.clone(),
            nonce: {
                use base64::Engine;
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 16])
            },
            valid_until: "2099-01-01T00:00:00Z".into(),
            label: None,
            ask: sample_ask(),
            proof: Value::Null,
        };
        let verified = VerifiedBootstrapRequest { inner: wire };

        let recipient_x_pub = verified.decode_client_x25519_pub().unwrap();
        let sealed = seal(&recipient_x_pub, b"hello", b"aad").unwrap();

        let x_secret = ed25519_seed_to_x25519_secret(&seed);
        let opened = open(&x_secret, &sealed, b"aad").unwrap();
        assert_eq!(opened, b"hello");
    }

    // ── ProvisionRequestBuilder ─────────────────────────────────────

    #[tokio::test]
    async fn builder_sign_ephemeral_verifies_and_carries_ask() {
        let signed = ProvisionRequestBuilder::new("didcomm-mediator")
            .var("URL", "https://mediator.example.com")
            .context_hint("mediator-prod")
            .validity(Duration::hours(2))
            .label("builder-smoke-test")
            .sign_ephemeral()
            .await
            .expect("sign_ephemeral");

        // client_did is the derivation of the ephemeral pubkey; the VP's
        // holder must match.
        assert_eq!(signed.request.holder, signed.client_did);
        assert!(signed.client_did.starts_with("did:key:z6Mk"));

        // bundle_id round-trips through the VP's nonce field.
        let verified = signed.request.clone().verify().expect("verify VP");
        assert_eq!(verified.decode_nonce().unwrap(), signed.bundle_id);

        // Ask preserves the TemplateBootstrap shape + caller vars.
        match verified.ask() {
            BootstrapAsk::TemplateBootstrap(ask) => {
                assert_eq!(ask.template.name, "didcomm-mediator");
                assert_eq!(
                    ask.template.vars.get("URL").and_then(|v| v.as_str()),
                    Some("https://mediator.example.com")
                );
                assert_eq!(ask.context_hint.as_deref(), Some("mediator-prod"));
                assert!(ask.admin_template.is_none());
            }
            other => panic!("expected TemplateBootstrap, got {other:?}"),
        }
        assert_eq!(verified.label(), Some("builder-smoke-test"));
    }

    #[tokio::test]
    async fn builder_admin_template_attaches_rollover_ref() {
        let signed = ProvisionRequestBuilder::new("didcomm-mediator")
            .var("URL", "https://mediator.example.com")
            .admin_template("vta-admin")
            .sign_ephemeral()
            .await
            .expect("sign_ephemeral");

        let verified = signed.request.clone().verify().expect("verify VP");
        match verified.ask() {
            BootstrapAsk::TemplateBootstrap(ask) => {
                let admin = ask.admin_template.as_ref().expect("admin template set");
                assert_eq!(admin.name, "vta-admin");
                assert!(admin.vars.is_empty());
            }
            other => panic!("expected TemplateBootstrap, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn builder_bulk_vars_preserved() {
        let signed = ProvisionRequestBuilder::new("didcomm-mediator")
            .vars([
                ("URL", Value::String("https://m.example.com".into())),
                ("ROUTING_KEYS", Value::Array(vec![])),
            ])
            .sign_ephemeral()
            .await
            .expect("sign_ephemeral");

        let verified = signed.request.clone().verify().expect("verify VP");
        match verified.ask() {
            BootstrapAsk::TemplateBootstrap(ask) => {
                assert_eq!(
                    ask.template.vars.get("URL").and_then(|v| v.as_str()),
                    Some("https://m.example.com")
                );
                assert!(ask.template.vars.get("ROUTING_KEYS").unwrap().is_array());
            }
            other => panic!("expected TemplateBootstrap, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn builder_sign_with_reuses_caller_identity() {
        // Pre-mint a "long-lived" identity the caller already has.
        let (seed, pub_bytes) = {
            let (s, p) = crate::sealed_transfer::generate_ed25519_keypair();
            (*s, p)
        };
        let client_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);

        let vp = ProvisionRequestBuilder::new("didcomm-mediator")
            .var("URL", "https://m.example.com")
            .sign_with(&seed, &client_did)
            .await
            .expect("sign_with");

        assert_eq!(vp.holder, client_did);
        let verified = vp.verify().expect("verify VP");
        assert_eq!(verified.holder(), client_did);
    }

    #[tokio::test]
    async fn builder_distinct_bundle_ids_per_call() {
        // Two back-to-back ephemeral requests must not collide on
        // bundle_id / nonce — the seed cache is addressed by that id.
        let a = ProvisionRequestBuilder::new("didcomm-mediator")
            .var("URL", "https://m.example.com")
            .sign_ephemeral()
            .await
            .unwrap();
        let b = ProvisionRequestBuilder::new("didcomm-mediator")
            .var("URL", "https://m.example.com")
            .sign_ephemeral()
            .await
            .unwrap();
        assert_ne!(a.bundle_id, b.bundle_id);
        assert_ne!(a.client_did, b.client_did);
    }

    // ── Mutation coverage for `verify()` — item 19 ──────────────────
    //
    // Enumerate every way a middlebox could try to alter a signed VP
    // and assert `verify()` rejects it. Table-driven rather than
    // `proptest`-random: the attack surface is specific, finite, and
    // better expressed as "one test per thing-that-must-not-happen"
    // than as a fuzzer that may or may not happen to flip the right
    // bit. Each case includes a matching error variant to prevent
    // regressions where the VP fails for *some* reason (not the
    // intended one) — a false negative we'd have missed with a loose
    // `unwrap_err()`.
    async fn build_valid_vp() -> (BootstrapRequest, String) {
        let (seed, client_did) = sample_client_did(0xAA);
        let vp = BootstrapRequest::sign(
            &seed,
            &client_did,
            [0xBB; 16],
            Duration::hours(1),
            Some("item-19-fixture".into()),
            sample_ask(),
        )
        .await
        .expect("sign fixture VP");
        (vp, client_did)
    }

    #[tokio::test]
    async fn verify_fixture_round_trips() {
        // Sanity: the fixture itself must verify, otherwise every
        // mutation test below trivially "passes" by hitting an
        // unrelated structural bug.
        let (vp, _) = build_valid_vp().await;
        vp.verify().expect("fixture VP verifies");
    }

    /// Build a `provision/integration/0.2`-shape VP: identical to a 0.1
    /// VP except `ask.type` is camelCase (`templateBootstrap`), signed
    /// over that exact wire form. A 0.2 holder (e.g. the browser plugin)
    /// signs camelCase; this proves `verify_value` checks the proof
    /// against the bytes as received rather than this crate's serde
    /// re-rendering. Returns the signed VP JSON + holder DID.
    async fn build_valid_camelcase_vp() -> (Value, String) {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

        let (seed, client_did) = sample_client_did(0xD2);
        let vm_id = did_key_to_vm(&client_did).expect("vm id");
        let mut signer = Secret::generate_ed25519(Some(&vm_id), Some(&seed));
        signer.id = vm_id;

        let now = Utc::now();
        let mut doc = serde_json::json!({
            "@context": [VC_V2_CONTEXT_URL, BOOTSTRAP_CONTEXT_URL],
            "type": ["VerifiablePresentation", "BootstrapRequest"],
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "holder": client_did,
            "nonce": B64URL.encode([0xD2u8; 16]),
            "validUntil": rfc3339(now + Duration::hours(1)),
            "label": "v0.2-camelcase-fixture",
            // 0.2 wire form: camelCase tag, inside the signed VP.
            "ask": {
                "type": "templateBootstrap",
                "template": {
                    "name": "didcomm-mediator",
                    "vars": { "URL": "https://mediator.example.com" }
                }
            }
        });

        let sign_options = SignOptions::new()
            .with_proof_purpose("authentication")
            .with_created(now);
        let proof = DataIntegrityProof::sign(&doc, &signer, sign_options)
            .await
            .expect("sign camelCase VP");
        doc.as_object_mut()
            .unwrap()
            .insert("proof".into(), serde_json::to_value(&proof).unwrap());
        (doc, client_did)
    }

    #[tokio::test]
    async fn verify_value_accepts_v0_2_camelcase_ask() {
        // A 0.2 holder signs `ask.type` as camelCase. Verifying over the
        // wire bytes (not the re-serialised typed struct) must accept it,
        // and the typed view must normalise to the `TemplateBootstrap`
        // variant for downstream business logic.
        let (doc, holder) = build_valid_camelcase_vp().await;
        let verified = BootstrapRequest::verify_value(doc).expect("0.2 camelCase VP verifies");
        assert_eq!(verified.holder(), holder);
        assert!(matches!(verified.ask(), BootstrapAsk::TemplateBootstrap(_)));
    }

    #[tokio::test]
    async fn verify_value_rejects_tampered_v0_2_ask() {
        // Mutating the camelCase ask after signing must still fail the
        // proof — the as-received path is not a casing loophole that
        // skips integrity.
        let (mut doc, _) = build_valid_camelcase_vp().await;
        doc["ask"]["template"]["name"] = Value::String("swapped-template".into());
        let err = BootstrapRequest::verify_value(doc).unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::BadProof(_)),
            "tampered 0.2 ask must yield BadProof, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_holder_mutation() {
        let (mut vp, _) = build_valid_vp().await;
        let (_other_seed, other_did) = sample_client_did(0xCC);
        vp.holder = other_did;
        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::HolderMismatch(_)),
            "swapping holder must yield HolderMismatch, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_nonce_mutation() {
        // Nonce is inside the signed body — changing any byte
        // invalidates the signature. Should fail at proof-verify, not
        // earlier structural checks.
        let (mut vp, _) = build_valid_vp().await;
        vp.nonce = "CCCCCCCCCCCCCCCCCCCCCC".to_string();
        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::BadProof(_)),
            "nonce mutation must yield BadProof, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_ask_mutation() {
        // Fields inside `ask` are also signed — tampering with the
        // template name, vars, or admin_template must invalidate.
        let (mut vp, _) = build_valid_vp().await;
        let BootstrapAsk::TemplateBootstrap(ref mut ask) = vp.ask else {
            panic!("expected TemplateBootstrap ask")
        };
        ask.template.name = "swapped-template".into();
        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::BadProof(_)),
            "ask.template.name mutation must yield BadProof, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_valid_until_mutation() {
        // Mutating validUntil to a different but still-valid timestamp
        // (not "in the past", just different from signed) — still
        // signed bytes, so the proof must fail.
        let (mut vp, _) = build_valid_vp().await;
        vp.valid_until = "2099-01-01T00:00:00Z".to_string();
        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::BadProof(_)),
            "validUntil mutation must yield BadProof, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_id_mutation() {
        let (mut vp, _) = build_valid_vp().await;
        vp.id = "urn:uuid:11111111-1111-1111-1111-111111111111".to_string();
        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::BadProof(_)),
            "id mutation must yield BadProof, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_label_mutation() {
        let (mut vp, _) = build_valid_vp().await;
        vp.label = Some("attacker-controlled-label".into());
        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::BadProof(_)),
            "label mutation must yield BadProof, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_missing_vp_type() {
        // Structural precondition: if a middlebox strips
        // "VerifiablePresentation" from the type array, the early
        // InvalidClaim check fires before we ever look at the proof.
        let (mut vp, _) = build_valid_vp().await;
        vp.types.retain(|t| t != "VerifiablePresentation");
        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::InvalidClaim(_)),
            "missing VerifiablePresentation must yield InvalidClaim, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_missing_bootstrap_request_type() {
        let (mut vp, _) = build_valid_vp().await;
        vp.types.retain(|t| t != "BootstrapRequest");
        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::InvalidClaim(_)),
            "missing BootstrapRequest must yield InvalidClaim, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_cryptosuite_downgrade() {
        // Swap eddsa-jcs-2022 → eddsa-rdfc-2022. Even if RDFC is
        // a "valid" DI suite in general, we don't accept it here —
        // the allowlist is tight so a future signer-side bug or
        // downgrade attack can't sneak through a different suite.
        let (mut vp, _) = build_valid_vp().await;
        let mut proof_obj = vp.proof.as_object().expect("proof is an object").clone();
        proof_obj.insert(
            "cryptosuite".to_string(),
            Value::String("eddsa-rdfc-2022".into()),
        );
        vp.proof = Value::Object(proof_obj);
        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::BadProof(_)),
            "cryptosuite downgrade must yield BadProof, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_verification_method_did_swap() {
        // `verificationMethod` DID (pre-`#`) must match `holder`.
        // Swapping only the VM (leaving the signature bytes valid
        // over the *original* holder) is exactly the "forged holder"
        // attack the check guards against.
        let (mut vp, _) = build_valid_vp().await;
        let (_other_seed, other_did) = sample_client_did(0xDD);
        let mut proof_obj = vp.proof.as_object().expect("proof is an object").clone();
        // Preserve a fragment (#key) so the `split_once('#')` check
        // doesn't short-circuit first — the DID-mismatch path is what
        // we want to exercise.
        proof_obj.insert(
            "verificationMethod".into(),
            Value::String(format!("{other_did}#key")),
        );
        vp.proof = Value::Object(proof_obj);
        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::HolderMismatch(_)),
            "VM DID swap must yield HolderMismatch, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_signature_byte_flip() {
        // Flip one byte in the proofValue (base58btc of the signature).
        // The mutated signature must fail Ed25519 verification.
        let (mut vp, _) = build_valid_vp().await;
        let mut proof_obj = vp.proof.as_object().expect("proof is an object").clone();
        let original_pv = proof_obj
            .get("proofValue")
            .and_then(|v| v.as_str())
            .expect("proofValue present")
            .to_string();
        // Flip the last char to a different base58btc-valid char.
        // (Avoid '0' / 'O' / 'I' / 'l' which aren't in the alphabet.)
        let last = original_pv.chars().next_back().unwrap();
        let replacement = if last == '1' { '2' } else { '1' };
        let mut mutated: String = original_pv.chars().take(original_pv.len() - 1).collect();
        mutated.push(replacement);
        proof_obj.insert("proofValue".into(), Value::String(mutated));
        vp.proof = Value::Object(proof_obj);
        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::BadProof(_)),
            "signature byte-flip must yield BadProof, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_malformed_proof_object() {
        // Proof isn't a proper DataIntegrityProof shape at all.
        let (mut vp, _) = build_valid_vp().await;
        vp.proof = Value::String("not-a-proof".into());
        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::BadProof(_)),
            "malformed proof must yield BadProof, got {err:?}"
        );
    }

    #[test]
    fn deserialize_rejects_unknown_top_level_field() {
        // `deny_unknown_fields` must reject a VP body that tries to
        // smuggle a field past the verifier — the guard runs before
        // `verify()` so a modified VP never even reaches DI proof
        // checking. Regression net for the item-22 hardening pass.
        let json = serde_json::json!({
            "@context": [VC_V2_CONTEXT_URL, BOOTSTRAP_CONTEXT_URL],
            "type": ["VerifiablePresentation", "BootstrapRequest"],
            "id": "urn:uuid:00000000-0000-0000-0000-000000000000",
            "holder": "did:key:zTest",
            "nonce": "AAAAAAAAAAAAAAAAAAAAAA",
            "validUntil": "2099-01-01T00:00:00Z",
            "ask": {
                "type": "TemplateBootstrap",
                "template": { "name": "didcomm-mediator" }
            },
            "proof": {},
            "extraSneakyField": "attacker-controlled-value"
        });
        let err = serde_json::from_value::<BootstrapRequest>(json).unwrap_err();
        assert!(
            err.to_string().contains("extraSneakyField")
                || err.to_string().contains("unknown field"),
            "error must mention the rejected field, got: {err}"
        );
    }

    #[test]
    fn deserialize_rejects_unknown_field_in_ask() {
        // Same guard must kick in at the nested `ask` level — an
        // attacker-controlled field inside TemplateBootstrapAsk is
        // every bit as dangerous as one at the top.
        let json = serde_json::json!({
            "@context": [VC_V2_CONTEXT_URL, BOOTSTRAP_CONTEXT_URL],
            "type": ["VerifiablePresentation", "BootstrapRequest"],
            "id": "urn:uuid:00000000-0000-0000-0000-000000000000",
            "holder": "did:key:zTest",
            "nonce": "AAAAAAAAAAAAAAAAAAAAAA",
            "validUntil": "2099-01-01T00:00:00Z",
            "ask": {
                "type": "TemplateBootstrap",
                "template": { "name": "didcomm-mediator" },
                "smugglerField": 42
            },
            "proof": {}
        });
        let err = serde_json::from_value::<BootstrapRequest>(json).unwrap_err();
        assert!(
            err.to_string().contains("smugglerField") || err.to_string().contains("unknown field"),
            "error must mention the rejected nested field, got: {err}"
        );
    }

    // ── AdminRotation variant ────────────────────────────────────────

    fn sample_admin_rotation_ask() -> BootstrapAsk {
        BootstrapAsk::AdminRotation(AdminRotationAsk {
            context_hint: Some("prod-mediator".into()),
            admin_template: DidTemplateRef {
                name: "vta-admin".into(),
                vars: BTreeMap::new(),
            },
            note: None,
        })
    }

    #[tokio::test]
    async fn admin_rotation_ask_round_trips_through_sign_verify() {
        let (seed, client_did) = sample_client_did(0xE0);
        let vp = BootstrapRequest::sign(
            &seed,
            &client_did,
            [0xE1; 16],
            Duration::hours(1),
            Some("admin-rotation".into()),
            sample_admin_rotation_ask(),
        )
        .await
        .unwrap();

        // VP must serialize the AdminRotation tag with its `adminTemplate`
        // JSON name, not the snake_case Rust name.
        let json = serde_json::to_value(&vp).unwrap();
        assert_eq!(json["ask"]["type"], "AdminRotation");
        assert_eq!(json["ask"]["adminTemplate"]["name"], "vta-admin");

        let parsed: BootstrapRequest = serde_json::from_value(json).unwrap();
        let verified = parsed.verify().expect("verify");
        match verified.ask() {
            BootstrapAsk::AdminRotation(ask) => {
                assert_eq!(ask.admin_template.name, "vta-admin");
                assert_eq!(ask.context_hint.as_deref(), Some("prod-mediator"));
            }
            other => panic!("expected AdminRotation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn admin_rotation_tampered_template_rejected() {
        let (seed, client_did) = sample_client_did(0xE2);
        let mut vp = BootstrapRequest::sign(
            &seed,
            &client_did,
            [0xE3; 16],
            Duration::hours(1),
            None,
            sample_admin_rotation_ask(),
        )
        .await
        .unwrap();

        let BootstrapAsk::AdminRotation(ref mut ask) = vp.ask else {
            panic!("expected AdminRotation ask")
        };
        ask.admin_template.name = "attacker-admin-template".into();

        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::BadProof(_)),
            "expected BadProof, got {err:?}"
        );
    }

    #[tokio::test]
    async fn for_admin_rotation_builder_emits_admin_rotation_variant() {
        let signed = ProvisionRequestBuilder::for_admin_rotation("vta-admin")
            .context_hint("ctx-1")
            .label("openvtc-cli2 first-boot")
            .sign_ephemeral()
            .await
            .expect("sign_ephemeral");

        let verified = signed.request.clone().verify().expect("verify VP");
        match verified.ask() {
            BootstrapAsk::AdminRotation(ask) => {
                assert_eq!(ask.admin_template.name, "vta-admin");
                assert_eq!(ask.context_hint.as_deref(), Some("ctx-1"));
            }
            other => panic!("expected AdminRotation, got {other:?}"),
        }
        assert_eq!(verified.label(), Some("openvtc-cli2 first-boot"));
    }
}
