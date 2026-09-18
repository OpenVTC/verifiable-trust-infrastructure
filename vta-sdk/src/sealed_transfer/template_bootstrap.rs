//! `SealedPayloadV1::TemplateBootstrap` payload shape.
//!
//! Lives under `sealed_transfer` (not `provision_integration`) so the
//! enum variant compiles whenever the `sealed-transfer` feature is on —
//! opening a bundle never requires `affinidi-vc`. The VC inside is
//! stored as `serde_json::Value`; consumers that want a typed view parse
//! it via `crate::provision_integration::credential`.
//!
//! Carries:
//! - The VTA-issued admin-authorization VC (short-lived, opaque JSON).
//! - Private key material the VTA minted for DIDs the integration will
//!   operate (zeroized on drop).
//! - First-boot config (template outputs, VTA trust bundle, connect URL).
//!
//! See `docs/02-vta/provision-integration.md` §"Payload" for the full
//! design.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Top-level payload for `SealedPayloadV1::AdminRotation`.
///
/// Carries everything an integration needs to switch its long-term
/// admin DID from the ephemeral setup `did:key` over to a fresh,
/// VTA-minted admin identity. Unlike [`TemplateBootstrapPayload`],
/// there is no integration DID, no `did_document`, and no template
/// outputs — the consumer brings (or mints elsewhere) its own
/// integration-side DIDs and only needs an admin credential at this
/// VTA.
///
/// Produced by the `BootstrapAsk::AdminRotation` flow on the VTA;
/// opened on the consumer side by the SDK's `provision_client`
/// runners which surface it as a `VtaReply::AdminOnly`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRotationPayload {
    /// VTA-issued `VtaAuthorizationCredential` (no `operator_of`
    /// claim — there's no integration to operate). Short-lived,
    /// verified once at bundle open, then archived.
    pub authorization: serde_json::Value,

    /// Key material for the freshly-minted admin DID. The consumer
    /// installs this in its keystore and uses it as the long-term
    /// authentication identity at the VTA.
    pub admin: DidKeyMaterial,

    /// URL the integration should use to reach the VTA's REST API.
    /// `None` when the VTA is DIDComm-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vta_url: Option<String>,

    /// VTA identity material — enough to verify the authorization VC
    /// offline at first boot.
    pub vta_trust: VtaTrustBundle,
}

/// Top-level payload for `SealedPayloadV1::TemplateBootstrap`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateBootstrapPayload {
    /// VTA-issued `VtaAuthorizationCredential`. Short-lived; verified at
    /// bundle open; never re-verified after that (ACL is the steady-
    /// state authority).
    pub authorization: serde_json::Value,

    /// Private key material for DIDs the VTA minted on the integration's
    /// behalf, keyed by DID URI. Usually one entry (the agent DID the
    /// template rendered); may be empty if the template only needed
    /// admin-level authorization.
    pub secrets: BTreeMap<String, DidKeyMaterial>,

    /// Non-credential first-boot configuration.
    pub config: TemplateBootstrapConfig,
}

/// Key material for a single DID the integration now controls. Secret
/// bytes are zeroized on drop.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidKeyMaterial {
    /// The DID this material is for (e.g. the rendered integration DID).
    pub did: String,
    /// Ed25519 signing keypair.
    pub signing_key: KeyPair,
    /// X25519 key-agreement keypair.
    pub ka_key: KeyPair,
}

/// A single keypair with DID-URL-qualified key id. The private half is
/// held in a [`Zeroizing`] buffer at rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPair {
    /// DID URL with fragment, e.g. `did:webvh:host/path#key-0`. Matches
    /// the `id` of the corresponding verification method in the DID doc.
    pub key_id: String,
    /// Multibase-encoded public key.
    pub public_key_multibase: String,
    /// Multibase-encoded private key. Not zeroized during serde to keep
    /// the derived `Serialize`/`Deserialize` simple; wrap in
    /// [`Zeroizing`] via [`Self::private_zeroizing`] when loading into
    /// live memory.
    pub private_key_multibase: String,
}

impl KeyPair {
    /// Take the private key out into a [`Zeroizing`] buffer. Call at
    /// the moment you use the key (e.g. feed to a signer) so the
    /// cleartext scalar lives on the stack for as little time as
    /// possible.
    pub fn private_zeroizing(&self) -> Zeroizing<String> {
        Zeroizing::new(self.private_key_multibase.clone())
    }
}

/// Top-level payload for `SealedPayloadV1::TemplateBootstrapV2`.
///
/// Identical to [`TemplateBootstrapPayload`] except that each DID's key
/// material is a [`DidKeyMaterialV2`], which can carry a signing key beyond the
/// primary one.
///
/// # Why a new variant rather than a field on the old one
///
/// [`DidKeyMaterial`] and [`TemplateBootstrapPayload`] both carry
/// `#[serde(deny_unknown_fields)]`, so adding a key field to either makes every
/// existing opener reject the whole payload:
///
/// ```text
/// unknown field `pq_signing_key`, expected one of `did`, `signing_key`, `ka_key`
/// ```
///
/// A message that reads like a corrupted payload of a format the opener
/// believes it understands. The workspace rule (CLAUDE.md, "Sealed-transfer is
/// the only secret-bearing wire format") says to add a variant instead, and the
/// failure that produces is the better one — it names what the opener does not
/// know:
///
/// ```text
/// unknown variant `template_bootstrap_v2`, expected one of `admin_credential`, …
/// ```
///
/// # When a producer emits this instead of [`TemplateBootstrapPayload`]
///
/// **The shape follows the template.** V2 only when the rendered template
/// declares a key slot beyond `signing` / `ka`; every v1 template — which is
/// every built-in — keeps producing `TemplateBootstrap` byte-identically. So an
/// opener that has not been updated is unaffected until someone deliberately
/// provisions it from a template that asks for more keys than it can install,
/// and is then told so by name.
///
/// This is the same no-migration property as the proof rule one layer up: one
/// key emits a proof object, several emit an array. The wire shape follows what
/// is actually there, and nothing has a flag to set.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateBootstrapPayloadV2 {
    /// VTA-issued `VtaAuthorizationCredential`. Short-lived; verified at
    /// bundle open; never re-verified after that (ACL is the steady-state
    /// authority).
    pub authorization: serde_json::Value,

    /// Private key material for DIDs the VTA minted on the integration's
    /// behalf, keyed by DID URI.
    pub secrets: BTreeMap<String, DidKeyMaterialV2>,

    /// Non-credential first-boot configuration. Unchanged from V1 — nothing
    /// about extra keys touches it, and reusing the type means a consumer that
    /// already reads a `TemplateBootstrapConfig` reads this one.
    pub config: TemplateBootstrapConfig,
}

/// Key material for a single DID, able to carry more than one signing key.
///
/// # Why the pair stays structural
///
/// The primary signing key is not one entry among several, and making it one
/// would lose two facts that are true and load-bearing:
///
/// - **A `did:webvh`'s primary signing key is what signs its log**, and
///   didwebvh 1.0 mandates `eddsa-jcs-2022` for log-entry proofs. It is
///   Ed25519 and cannot be otherwise.
/// - **The VTC derives its storage key, install-token signer and audit key from
///   that same Ed25519 seed** (`vtc-service/src/server.rs`). A bundle able to
///   omit it is a bundle able to brick the consumer.
///
/// So post-quantum signing arrives as an *addition*, never a substitution —
/// which is also the shape `LocalSigner` already has (primary first, then the
/// rest), so the chain from template to signature is one idea end to end.
///
/// A flat slot list was the alternative. It is the slot map Phase 2
/// deliberately rejected for `DerivedEntityKeys`: the arity of the first two is
/// a true property worth keeping in the type rather than making every reader a
/// lookup that can fail.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidKeyMaterialV2 {
    /// The DID this material is for.
    pub did: String,
    /// The primary signing keypair — `#key-0` by convention, and the key the
    /// DID's log is signed with.
    pub signing_key: SlotKeyPair,
    /// The key-agreement keypair.
    pub ka_key: SlotKeyPair,
    /// Signing keys beyond the primary — a post-quantum one, so the holder can
    /// issue a credential carrying one proof each verifier can check.
    ///
    /// Empty on a classical-only DID, and skipped on the wire when empty, so a
    /// V2 payload for such a DID differs from a V1 one only in its variant tag.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_signing_keys: Vec<SlotKeyPair>,
}

/// A keypair together with the template slot it was minted for and the
/// algorithm it actually is.
///
/// # Why `slot` and `key_type` are carried
///
/// `slot` is the join back to what was asked for: the template declares
/// `pq-signing`, the renderer substitutes `{PQ_SIGNING_KEY_MB}`, and this says
/// which declaration each key answers. Without it a consumer has to infer
/// intent from the algorithm.
///
/// `key_type` is carried rather than derived from the multicodec prefix for the
/// reason Phase 2 arrived at the hard way: *a type asserted where it should
/// have been carried* was the shape of almost every defect in that phase. The
/// prefix and this field must agree, and a consumer that can check should —
/// they come from the same producer, so disagreement means a bug, not an
/// attack.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotKeyPair {
    /// The template key slot this key was minted for: `signing`, `ka`,
    /// `pq-signing`, …
    pub slot: String,
    /// The algorithm this key is, as the `keyType` vocabulary spells it
    /// (`ed25519`, `x25519`, `mldsa44`, …).
    pub key_type: crate::keys::KeyType,
    /// DID URL with fragment. Matches the `id` of the corresponding
    /// verification method in the published DID document.
    pub key_id: String,
    /// Multibase-encoded public key.
    pub public_key_multibase: String,
    /// Multibase-encoded private key. Wrap in [`Zeroizing`] via
    /// [`Self::private_zeroizing`] when loading into live memory.
    pub private_key_multibase: String,
}

impl DidKeyMaterialV2 {
    /// Read a V1 [`DidKeyMaterial`] as the V2 shape.
    ///
    /// Total, and not a guess. V1 has exactly two slots, which are
    /// [`SLOT_SIGNING`](crate::did_templates::SLOT_SIGNING) and
    /// [`SLOT_KA`](crate::did_templates::SLOT_KA) by the format's definition,
    /// and no additional keys — that is what "V1" *means*. Its two algorithms
    /// are equally definitional: [`DidKeyMaterial`] documents them as an Ed25519
    /// signing keypair and an X25519 key-agreement keypair, and the format
    /// admits nothing else.
    ///
    /// So each key's type comes from its multicodec prefix when that classifies
    /// — the bytes are the ground truth about the bytes — and from the format's
    /// contract when it does not.
    ///
    /// # Why an unclassifiable key is not refused
    ///
    /// It was, briefly. The round-trips in `tests/provision_client_e2e.rs`
    /// caught why that was wrong: every runner opens through
    /// `response_to_result_v2` now, so the strictness applied to **every** V1
    /// bundle from **every** existing VTA — rejecting at open time what the V1
    /// path had always accepted, over a field the V1 path did not even have.
    ///
    /// That bought nothing. For the classical pair nobody acts on `key_type`:
    /// the consumer decodes the private half with its own explicit codec check
    /// (`VtcKeyBundle::ed25519_private_bytes`), so a mislabelled pair cannot
    /// reach a signer. The inference is confined to the one place it is safe —
    /// V1's two slots, whose algorithms the format fixes.
    ///
    /// An **additional** signing key is never inferred. It exists only in a V2
    /// bundle, where the producer stated its algorithm outright, and there
    /// `key_type` *is* load-bearing because it selects the cryptosuite.
    pub fn from_v1(v1: &DidKeyMaterial) -> Self {
        use crate::did_templates::{SLOT_KA, SLOT_SIGNING};
        use crate::keys::KeyType;
        Self {
            did: v1.did.clone(),
            signing_key: SlotKeyPair::from_v1_pair(SLOT_SIGNING, &v1.signing_key, KeyType::Ed25519),
            ka_key: SlotKeyPair::from_v1_pair(SLOT_KA, &v1.ka_key, KeyType::X25519),
            additional_signing_keys: Vec::new(),
        }
    }
}

impl SlotKeyPair {
    /// Read a V1 [`KeyPair`] into a slot-tagged one.
    ///
    /// `contract` is what the V1 format says this slot is, used when the public
    /// key's multicodec does not classify. See [`DidKeyMaterialV2::from_v1`]
    /// for why that fallback exists and why it is safe only here.
    fn from_v1_pair(slot: &str, pair: &KeyPair, contract: crate::keys::KeyType) -> Self {
        Self {
            slot: slot.to_string(),
            key_type: crate::keys::KeyType::from_public_multibase(&pair.public_key_multibase)
                .unwrap_or(contract),
            key_id: pair.key_id.clone(),
            public_key_multibase: pair.public_key_multibase.clone(),
            private_key_multibase: pair.private_key_multibase.clone(),
        }
    }

    /// Take the private key out into a [`Zeroizing`] buffer, at the moment it
    /// is used.
    pub fn private_zeroizing(&self) -> Zeroizing<String> {
        Zeroizing::new(self.private_key_multibase.clone())
    }
}

/// First-boot configuration carried alongside the authorization VC.
/// Non-credential data: template metadata, rendered DID document,
/// template-declared side outputs, connect URL, VTA trust material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateBootstrapConfig {
    /// Name of the template the VTA rendered (audit).
    pub template_name: String,
    /// Template's `kind` field (`"mediator"`, `"webvh-hosting"`, etc.).
    /// Consumers dispatch on this for kind-specific handling.
    pub template_kind: String,
    /// The fully-rendered DID document for the integration's DID, as
    /// JSON. The integration's own webvh host should publish this.
    pub did_document: serde_json::Value,
    /// Template-declared side outputs (e.g. `did.jsonl` log for webvh,
    /// DIDComm service advertisement for mediators).
    pub outputs: Vec<TemplateOutput>,
    /// URL the integration should use to reach the VTA's REST API.
    /// None when the integration doesn't make outbound VTA calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vta_url: Option<String>,
    /// VTA identity material — enough for the integration to verify the
    /// authorization VC offline at first boot.
    pub vta_trust: VtaTrustBundle,
}

/// Side outputs a template renderer emits alongside the DID document.
///
/// Typed variants exist for output kinds every VTA deployment knows
/// about; a catch-all [`Self::Generic`] variant carries arbitrary
/// template-declared outputs so operator-uploaded templates that need
/// novel first-boot artefacts (status-list URLs, OOB invitations, TLS
/// CSRs, webhook configs, …) work without an SDK change.
///
/// Downstream consumers that understand a specific `kind` string match
/// on `Generic { kind, payload }` for that kind; everything else they
/// forward to a default handler or log-and-ignore. Preserves the
/// "uploading a template is the whole author surface for new
/// integrations" invariant from `CLAUDE.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TemplateOutput {
    /// Raw `did.jsonl` log for a `did:webvh` DID. The integration writes
    /// this to `/.well-known/did.jsonl` on its own webvh host at first
    /// boot.
    WebvhLog {
        /// Which DID the log describes.
        did: String,
        /// Raw newline-delimited JSON log content.
        log: String,
    },
    /// DIDComm v2 service-endpoint advertisement the integration should
    /// publish on its DID doc (and which the template already embedded
    /// there — duplicated here for operational config convenience).
    DidCommService {
        /// Which DID the service belongs to.
        did: String,
        url: String,
        accept: Vec<String>,
        routing_keys: Vec<String>,
    },
    /// Extensibility escape hatch for template-declared outputs the SDK
    /// doesn't know about. `kind` is a short string the template author
    /// picks (lowercase kebab-case by convention — e.g. `status-list`,
    /// `oob-invitation`, `tls-csr`). `payload` is whatever JSON the
    /// template emitted; consumers dispatch on `kind` and parse
    /// `payload` as their expected shape.
    Generic {
        /// Caller-chosen tag identifying the output kind. Must not
        /// collide with the snake_case discriminant of an existing
        /// typed variant (`webvh_log`, `didcomm_service`) — consumers
        /// match typed variants first, so a `Generic { kind:
        /// "webvh_log", … }` would still deserialize as
        /// `Generic` but shadow nothing, just confuse readers. Enforce
        /// naming elsewhere (template validator) rather than in the
        /// wire shape.
        kind: String,
        /// Free-form JSON the template author produced. Consumers that
        /// understand `kind` parse this into a typed shape of their
        /// own; consumers that don't log + skip.
        payload: serde_json::Value,
    },
}

/// VTA identity material an integration needs to verify the returned
/// sealed bundle's contents offline.
///
/// Shipped *inside* every provisioning bundle. On first boot the
/// integration:
///   1. Takes `vta_did_document` as the trust anchor.
///   2. If `vta_did_log` is present, replays the log and confirms the
///      rendered doc matches — cross-verifying the shipped doc.
///   3. Extracts the `assertionMethod` verification method from the doc
///      and uses it to verify the authorization VC's proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VtaTrustBundle {
    pub vta_did: String,
    pub vta_did_document: serde_json::Value,
    /// Raw `did.jsonl` for `did:webvh` VTAs — lets the integration
    /// verify the doc independently. None for self-resolving methods
    /// like `did:key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vta_did_log: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed_transfer::SealedPayloadV1;
    use serde_json::json;

    fn sample_payload() -> TemplateBootstrapPayload {
        TemplateBootstrapPayload {
            authorization: json!({ "type": ["VerifiableCredential", "VtaAuthorizationCredential"] }),
            secrets: BTreeMap::from([(
                "did:webvh:mediator.example.com".to_string(),
                DidKeyMaterial {
                    did: "did:webvh:mediator.example.com".into(),
                    signing_key: KeyPair {
                        key_id: "did:webvh:mediator.example.com#key-0".into(),
                        public_key_multibase: "z6Mk...".into(),
                        private_key_multibase: "z...".into(),
                    },
                    ka_key: KeyPair {
                        key_id: "did:webvh:mediator.example.com#key-1".into(),
                        public_key_multibase: "z6LS...".into(),
                        private_key_multibase: "z...".into(),
                    },
                },
            )]),
            config: TemplateBootstrapConfig {
                template_name: "didcomm-mediator".into(),
                template_kind: "mediator".into(),
                did_document: json!({ "id": "did:webvh:mediator.example.com" }),
                outputs: vec![TemplateOutput::WebvhLog {
                    did: "did:webvh:mediator.example.com".into(),
                    log: "{...}".into(),
                }],
                vta_url: Some("https://vta.example.com".into()),
                vta_trust: VtaTrustBundle {
                    vta_did: "did:webvh:vta.example.com".into(),
                    vta_did_document: json!({ "id": "did:webvh:vta.example.com" }),
                    vta_did_log: Some("{...}".into()),
                },
            },
        }
    }

    #[test]
    fn template_bootstrap_payload_json_round_trip() {
        let payload = sample_payload();
        let json = serde_json::to_string(&payload).unwrap();
        let parsed: TemplateBootstrapPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.config.template_name, "didcomm-mediator");
        assert_eq!(parsed.secrets.len(), 1);
    }

    #[test]
    fn sealed_payload_variant_round_trip() {
        let payload = SealedPayloadV1::TemplateBootstrap(Box::new(sample_payload()));
        // JSON round-trip.
        let json = serde_json::to_string(&payload).unwrap();
        let parsed: SealedPayloadV1 = serde_json::from_str(&json).unwrap();
        match parsed {
            SealedPayloadV1::TemplateBootstrap(p) => {
                assert_eq!(p.config.template_kind, "mediator");
                assert_eq!(p.config.outputs.len(), 1);
            }
            other => panic!("expected TemplateBootstrap, got {other:?}"),
        }
    }

    #[test]
    fn template_output_webvh_log_tag_on_wire() {
        // The `type` tag in the enum's wire form should be snake_case
        // (`webvh_log`, `did_comm_service`) — matches existing
        // SealedPayloadV1 convention and is stable across the wire.
        let out = TemplateOutput::WebvhLog {
            did: "did:webvh:x".into(),
            log: "line".into(),
        };
        let v = serde_json::to_value(&out).unwrap();
        assert_eq!(v["type"], "webvh_log");
    }

    #[test]
    fn template_output_generic_round_trips_arbitrary_payload() {
        // Generic extensibility: a template author who needs a novel
        // first-boot artefact (e.g. a status-list URL, OOB invitation,
        // TLS CSR) embeds it via TemplateOutput::Generic without an
        // SDK change. Wire shape preserves the kind tag + free-form
        // JSON payload verbatim through serialize → deserialize.
        let original = TemplateOutput::Generic {
            kind: "status-list".into(),
            payload: json!({
                "statusListUrl": "https://issuer.example.com/status",
                "expires": "2026-12-31T00:00:00Z",
            }),
        };
        let wire = serde_json::to_value(&original).unwrap();
        assert_eq!(wire["type"], "generic");
        assert_eq!(wire["kind"], "status-list");
        assert_eq!(
            wire["payload"]["statusListUrl"],
            "https://issuer.example.com/status"
        );

        let parsed: TemplateOutput = serde_json::from_value(wire).unwrap();
        match parsed {
            TemplateOutput::Generic { kind, payload } => {
                assert_eq!(kind, "status-list");
                assert_eq!(payload["expires"], "2026-12-31T00:00:00Z");
            }
            other => panic!("expected Generic, got {other:?}"),
        }
    }

    fn sample_admin_rotation_payload() -> AdminRotationPayload {
        AdminRotationPayload {
            authorization: json!({ "type": ["VerifiableCredential", "VtaAuthorizationCredential"] }),
            admin: DidKeyMaterial {
                did: "did:key:z6MkAdmin".into(),
                signing_key: KeyPair {
                    key_id: "did:key:z6MkAdmin#z6MkAdmin".into(),
                    public_key_multibase: "z6MkAdminSigning".into(),
                    private_key_multibase: "zAdminSigningPriv".into(),
                },
                ka_key: KeyPair {
                    key_id: "did:key:z6MkAdmin#z6LSAdmin".into(),
                    public_key_multibase: "z6LSAdminKa".into(),
                    private_key_multibase: "zAdminKaPriv".into(),
                },
            },
            vta_url: Some("https://vta.example.com".into()),
            vta_trust: VtaTrustBundle {
                vta_did: "did:webvh:vta.example.com".into(),
                vta_did_document: json!({ "id": "did:webvh:vta.example.com" }),
                vta_did_log: None,
            },
        }
    }

    #[test]
    fn admin_rotation_payload_json_round_trip() {
        let payload = sample_admin_rotation_payload();
        let json = serde_json::to_string(&payload).unwrap();
        let parsed: AdminRotationPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.admin.did, "did:key:z6MkAdmin");
        assert_eq!(parsed.vta_url.as_deref(), Some("https://vta.example.com"));
    }

    #[test]
    fn admin_rotation_sealed_payload_variant_round_trip() {
        let payload = SealedPayloadV1::AdminRotation(Box::new(sample_admin_rotation_payload()));
        let json = serde_json::to_string(&payload).unwrap();
        // Wire tag must be `admin_rotation` (snake_case) — matches the
        // SealedPayloadV1 convention. Regression net for an accidental
        // rename or for `serde(rename_all = "snake_case")` falling off
        // the enum.
        assert!(
            json.contains("\"admin_rotation\""),
            "wire tag must be snake_case `admin_rotation`, got: {json}"
        );
        let parsed: SealedPayloadV1 = serde_json::from_str(&json).unwrap();
        match parsed {
            SealedPayloadV1::AdminRotation(p) => {
                assert_eq!(p.admin.did, "did:key:z6MkAdmin");
            }
            other => panic!("expected AdminRotation, got {other:?}"),
        }
    }

    #[test]
    fn template_output_generic_coexists_with_typed_variants() {
        // An outputs vec can mix typed + generic entries — simulates
        // a template that emits both a standard WebvhLog and a
        // novel side output.
        let outputs = vec![
            TemplateOutput::WebvhLog {
                did: "did:webvh:mediator.example".into(),
                log: "one\ntwo\n".into(),
            },
            TemplateOutput::Generic {
                kind: "oob-invitation".into(),
                payload: json!({"url": "https://mediator.example/oob?c=abc"}),
            },
        ];
        let wire = serde_json::to_string(&outputs).unwrap();
        let parsed: Vec<TemplateOutput> = serde_json::from_str(&wire).unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(matches!(parsed[0], TemplateOutput::WebvhLog { .. }));
        match &parsed[1] {
            TemplateOutput::Generic { kind, .. } => assert_eq!(kind, "oob-invitation"),
            other => panic!("expected Generic at index 1, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod v2_tests {
    use super::*;
    use crate::keys::KeyType;
    use crate::sealed_transfer::SealedPayloadV1;
    use serde_json::json;

    fn config() -> TemplateBootstrapConfig {
        TemplateBootstrapConfig {
            template_name: "vtc-host".into(),
            template_kind: "vtc-host".into(),
            did_document: json!({ "id": "did:webvh:vtc.example" }),
            outputs: vec![],
            vta_url: None,
            vta_trust: VtaTrustBundle {
                vta_did: "did:webvh:vta.example".into(),
                vta_did_document: json!({ "id": "did:webvh:vta.example" }),
                vta_did_log: None,
            },
        }
    }

    fn hybrid_material() -> DidKeyMaterialV2 {
        DidKeyMaterialV2 {
            did: "did:webvh:vtc.example".into(),
            signing_key: SlotKeyPair {
                slot: "signing".into(),
                key_type: KeyType::Ed25519,
                key_id: "did:webvh:vtc.example#key-0".into(),
                public_key_multibase: "z6MkSigning".into(),
                private_key_multibase: "zPrivSigning".into(),
            },
            ka_key: SlotKeyPair {
                slot: "ka".into(),
                key_type: KeyType::X25519,
                key_id: "did:webvh:vtc.example#key-1".into(),
                public_key_multibase: "z6LSka".into(),
                private_key_multibase: "zPrivKa".into(),
            },
            additional_signing_keys: vec![SlotKeyPair {
                slot: "pq-signing".into(),
                key_type: KeyType::MlDsa44,
                key_id: "did:webvh:vtc.example#key-2".into(),
                public_key_multibase: "zPqPublic".into(),
                private_key_multibase: "zPqPrivate".into(),
            }],
        }
    }

    /// **The reason this is a variant and not a field.**
    ///
    /// Both V1 payload types carry `deny_unknown_fields`, so a third key field
    /// makes an existing opener reject the whole bundle — with a message that
    /// reads as a corrupted payload of a format it thinks it understands. The
    /// variant's failure names what the opener does not know instead, which is
    /// the difference between a diagnosable error and a mysterious one.
    ///
    /// Both halves are pinned because either one changing would quietly remove
    /// the argument for the design.
    #[test]
    fn a_field_addition_would_have_been_rejected_as_corruption() {
        let with_extra_field = json!({
            "did": "did:webvh:x",
            "signing_key": {"key_id":"did:webvh:x#key-0","public_key_multibase":"z1","private_key_multibase":"z2"},
            "ka_key": {"key_id":"did:webvh:x#key-1","public_key_multibase":"z3","private_key_multibase":"z4"},
            "pq_signing_key": {"key_id":"did:webvh:x#key-2","public_key_multibase":"z5","private_key_multibase":"z6"},
        });
        let err = serde_json::from_value::<DidKeyMaterial>(with_extra_field)
            .expect_err("deny_unknown_fields refuses a third key field");
        assert!(
            err.to_string().contains("unknown field `pq_signing_key`"),
            "got: {err}"
        );

        // The other half — what an opener that does *not* have this variant
        // sees — cannot be asserted from inside a build that has it. It was
        // measured on `main` before the variant existed:
        //
        //     unknown variant `template_bootstrap_v2`, expected one of
        //     `admin_credential`, ... `messaging_bridge_credentials`
        //
        // What is testable here is the property that message depends on: the
        // enum is externally tagged, so an unrecognised tag is reported *as a
        // variant name*, not as a malformed field of a variant serde picked.
        // If this ever became untagged or `other`-defaulted, the diagnosable
        // failure would silently become an undiagnosable one.
        let future_variant = json!({ "template_bootstrap_v9": { "anything": 1 } });
        let err = serde_json::from_value::<SealedPayloadV1>(future_variant)
            .expect_err("an opener cannot read a variant it does not have");
        assert!(
            err.to_string()
                .contains("unknown variant `template_bootstrap_v9`"),
            "an unrecognised payload must fail by naming the variant: {err}"
        );
    }

    #[test]
    fn the_v2_payload_round_trips_through_the_sealed_envelope() {
        let payload = SealedPayloadV1::TemplateBootstrapV2(Box::new(TemplateBootstrapPayloadV2 {
            authorization: json!({ "type": ["VerifiableCredential"] }),
            secrets: BTreeMap::from([("did:webvh:vtc.example".to_string(), hybrid_material())]),
            config: config(),
        }));

        let json = serde_json::to_string(&payload).unwrap();
        assert!(
            json.contains("\"template_bootstrap_v2\""),
            "the wire tag must be snake_case, matching every other variant: {json}"
        );

        let parsed: SealedPayloadV1 = serde_json::from_str(&json).unwrap();
        let SealedPayloadV1::TemplateBootstrapV2(p) = parsed else {
            panic!("expected TemplateBootstrapV2");
        };
        let material = &p.secrets["did:webvh:vtc.example"];
        assert_eq!(material.additional_signing_keys.len(), 1);
        assert_eq!(material.additional_signing_keys[0].slot, "pq-signing");
        assert_eq!(
            material.additional_signing_keys[0].key_type,
            KeyType::MlDsa44,
            "the algorithm must survive the wire as a value, not be re-inferred"
        );
    }

    /// With no extra keys, a V2 payload's key material is V1's content under a
    /// different tag — `additional_signing_keys` is skipped entirely. Pinned
    /// because it is what makes the variant cheap: a consumer reading V2 does
    /// not pay for a field nobody filled in.
    #[test]
    fn an_empty_additional_list_is_absent_from_the_wire() {
        let mut material = hybrid_material();
        material.additional_signing_keys.clear();
        let json = serde_json::to_string(&material).unwrap();
        assert!(
            !json.contains("additional_signing_keys"),
            "an empty list must not appear on the wire: {json}"
        );
        let parsed: DidKeyMaterialV2 = serde_json::from_str(&json).unwrap();
        assert!(parsed.additional_signing_keys.is_empty());
    }

    /// The V1 lift reads each key's algorithm from its multicodec prefix — the
    /// only carrier V1 has — rather than assuming the pair.
    #[test]
    fn a_v1_payload_lifts_with_its_algorithms_read_from_the_keys() {
        // Real multibase: ed25519-pub (0xed 0x01) and x25519-pub (0xec 0x01).
        let ed = multibase::encode(
            multibase::Base::Base58Btc,
            [&[0xed, 0x01][..], &[7u8; 32][..]].concat(),
        );
        let x = multibase::encode(
            multibase::Base::Base58Btc,
            [&[0xec, 0x01][..], &[9u8; 32][..]].concat(),
        );

        let v1 = DidKeyMaterial {
            did: "did:webvh:x".into(),
            signing_key: KeyPair {
                key_id: "did:webvh:x#key-0".into(),
                public_key_multibase: ed,
                private_key_multibase: "zPriv0".into(),
            },
            ka_key: KeyPair {
                key_id: "did:webvh:x#key-1".into(),
                public_key_multibase: x,
                private_key_multibase: "zPriv1".into(),
            },
        };

        let lifted = DidKeyMaterialV2::from_v1(&v1);
        assert_eq!(lifted.signing_key.slot, "signing");
        assert_eq!(lifted.signing_key.key_type, KeyType::Ed25519);
        assert_eq!(lifted.ka_key.slot, "ka");
        assert_eq!(lifted.ka_key.key_type, KeyType::X25519);
        assert!(lifted.additional_signing_keys.is_empty());
    }

    /// A key whose multicodec does not classify falls back to what the V1
    /// format **defines** the slot to be — it is not refused.
    ///
    /// This reverses the first version of this lift, and the reversal is the
    /// point. Refusing here rejected, at open time, V1 bundles that the V1 path
    /// had always accepted — for every existing VTA, since every runner now
    /// opens through the V2 path — over a field the V1 path did not even have.
    ///
    /// Nothing acts on `key_type` for the classical pair: the consumer decodes
    /// the private half with its own explicit codec check. So the fallback
    /// cannot mislead a signer, while refusing could break provisioning
    /// outright.
    #[test]
    fn a_v1_key_the_multicodec_cannot_classify_takes_the_formats_word() {
        let junk = multibase::encode(
            multibase::Base::Base58Btc,
            [&[0xff, 0xff][..], &[1u8; 32][..]].concat(),
        );
        let v1 = DidKeyMaterial {
            did: "did:webvh:x".into(),
            signing_key: KeyPair {
                key_id: "did:webvh:x#key-0".into(),
                public_key_multibase: junk.clone(),
                private_key_multibase: "zPriv0".into(),
            },
            ka_key: KeyPair {
                key_id: "did:webvh:x#key-1".into(),
                // Not even valid multibase — the shape a synthetic test fixture
                // has, and what `provision_client_e2e`'s round-trips carry.
                public_key_multibase: "z6LSNotARealKey".into(),
                private_key_multibase: "zPriv1".into(),
            },
        };

        let lifted = DidKeyMaterialV2::from_v1(&v1);
        assert_eq!(
            lifted.signing_key.key_type,
            KeyType::Ed25519,
            "V1's signing slot is Ed25519 by definition of the format"
        );
        assert_eq!(
            lifted.ka_key.key_type,
            KeyType::X25519,
            "V1's key-agreement slot is X25519 by definition of the format"
        );
    }

    /// And the precedence: a multicodec that *does* classify wins over the
    /// contract. The bytes are the ground truth about the bytes, so a V1 bundle
    /// carrying something other than the pair is reported as what it is rather
    /// than as what the format expected.
    #[test]
    fn a_readable_multicodec_beats_the_format_contract() {
        let pq = multibase::encode(
            multibase::Base::Base58Btc,
            [KeyType::MlDsa44.multicodec_public(), &[7u8; 32][..]].concat(),
        );
        let v1 = DidKeyMaterial {
            did: "did:webvh:x".into(),
            signing_key: KeyPair {
                key_id: "did:webvh:x#key-0".into(),
                public_key_multibase: pq,
                private_key_multibase: "zPriv0".into(),
            },
            ka_key: KeyPair {
                key_id: "did:webvh:x#key-1".into(),
                public_key_multibase: "zJunk".into(),
                private_key_multibase: "zPriv1".into(),
            },
        };
        assert_eq!(
            DidKeyMaterialV2::from_v1(&v1).signing_key.key_type,
            KeyType::MlDsa44,
            "a readable prefix must not be overridden by the contract"
        );
    }

    /// The V1 payload's own shape is unchanged    /// The V1 payload's own shape is unchanged — pinned here rather than only
    /// in the V1 tests, because the whole no-migration claim rests on a V1
    /// producer and a V1 opener being untouched by this variant existing.
    #[test]
    fn the_v1_variant_is_byte_identical_to_what_it_always_was() {
        let payload = SealedPayloadV1::TemplateBootstrap(Box::new(TemplateBootstrapPayload {
            authorization: json!({}),
            secrets: BTreeMap::new(),
            config: config(),
        }));
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"template_bootstrap\""));
        assert!(
            !json.contains("template_bootstrap_v2"),
            "a V1 payload must not acquire the V2 tag: {json}"
        );
    }
}
