//! The signing oracle: opaque payloads, SSHSIG, JWS, certificate requests,
//! Data Integrity documents, and signing as a delegated identity
//! (`derive-and-sign*`).

use super::*;

/// Sign a payload using a VTA-managed key.
///
/// For derived keys, re-derives from BIP-32 seed. For imported keys,
/// decrypts from the imported_secrets keyspace. Key material is zeroized
/// after signing.
///
/// `audit` is required rather than optional: this is the one chokepoint every
/// transport reaches the signing oracle through, so a caller who could opt out
/// of the trail could sign unrecorded. See the audit call at the tail.
#[allow(clippy::too_many_arguments)]
pub async fn sign_payload(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    internal_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    key_id: &str,
    payload: &[u8],
    algorithm: &SignAlgorithm,
    domain: SigningDomain,
    channel: &str,
) -> Result<SignResultBody, AppError> {
    sign_payload_recorded(
        keys_ks,
        imported_ks,
        internal_ks,
        contexts_ks,
        acl_ks,
        seed_store,
        audit,
        auth,
        key_id,
        payload,
        algorithm,
        domain,
        channel,
        SignAuditRow::GENERIC,
    )
    .await
}

/// The audit row a successful signature writes: the action, and a detail line
/// for an operation that knows what it signed.
#[derive(Debug, Clone, Copy)]
pub(super) struct SignAuditRow<'a> {
    action: &'a str,
    detail: Option<&'a str>,
}

impl SignAuditRow<'_> {
    /// The generic oracle's row. It records no detail: the payload is the
    /// caller's bytes and the VTA cannot say what they are.
    const GENERIC: SignAuditRow<'static> = SignAuditRow {
        action: "keys.sign",
        detail: None,
    };
}

/// [`sign_payload`], recording the success under `row`.
///
/// Every gate, the key-type check and the zeroization are the same; only the
/// audit row differs, so an operation that built the bytes itself
/// ([`sign_sshsig`]) can say what it signed without a second row.
#[allow(clippy::too_many_arguments)]
pub(super) async fn sign_payload_recorded(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    internal_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    key_id: &str,
    payload: &[u8],
    algorithm: &SignAlgorithm,
    domain: SigningDomain,
    channel: &str,
    row: SignAuditRow<'_>,
) -> Result<SignResultBody, AppError> {
    // Gate 0 — the generic oracle needs `Sign` (VTI-VTA-003, VTI-VTA-007).
    // Only for `Opaque`: those bytes came from a caller, which is the generic
    // signing request `Sign` names. `ProtocolDefined` input is built inside the
    // VTA by an operation that has already applied the constrained capability
    // its own task requires (`credential-write` for a room's credentials, for
    // instance) — and VTI-VTA-007 is precisely that such a grant must not have
    // to carry the general one. Before any lookup, so a refused caller learns
    // nothing about which key ids exist.
    let gate0_caller = if domain == SigningDomain::Opaque {
        Some(ensure_may_sign_caller(acl_ks, auth, "keys/sign").await?)
    } else {
        None
    };

    // Scope before existence: an out-of-scope caller gets the same refusal for
    // a key that exists and one that does not.
    let record = load_record_in_caller_scope(keys_ks, auth, key_id).await?;

    if record.status != KeyStatus::Active {
        return Err(AppError::Validation(
            "cannot sign with a revoked key".into(),
        ));
    }

    // The caller's row for gate 4: the one gate 0 read, or read now. Either
    // way it is read once per signature.
    let caller = match gate0_caller {
        Some(caller) => caller,
        None => CallerAcl::read(acl_ks, auth).await?,
    };

    // The key's context as key custody reads it: the policy below and the
    // custody base path come from this one read.
    let mut custody_context = None;
    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
        // Gate 4 (#818) — the caller's own ACL row may narrow which key ids
        // it can invoke the oracle on. Runs strictly AFTER `require_context`,
        // so a caller can never reach (or learn about) a key outside its
        // contexts by naming it here — the filter intersects with the context
        // scope, never widens it. Placed BEFORE the policy quota so a refused
        // call burns none of the context's daily sign budget.
        require_key_in_caller_scope(&caller, key_id)?;
        // Context policy is a resource-bound guardrail: it constrains the key's
        // context regardless of the actor — even the super-admin. This is what
        // lets a higher authority (e.g. a VTC/fleet-pushed policy) or the
        // owner's own policy bind every signer; the owner relaxes it via policy
        // CRUD, never by bypassing it here. Resolved across the whole ancestor
        // chain, so a child context can only narrow the set, never widen it. An
        // unscoped key (no context) has no policy and is naturally unrestricted
        // (and super-admin-only, gated below).
        let context = crate::operations::key_custody::load_sign_context(contexts_ks, ctx).await?;
        let policy = context.policy();
        if !policy.allows_signing_key(key_id) {
            return Err(AppError::Forbidden(format!(
                "signing key {key_id} is not permitted by the policy of context {ctx}"
            )));
        }
        if let Some(limit) = policy.quota_for("sign") {
            crate::contexts::enforce_daily_quota(contexts_ks, ctx, "sign", limit).await?;
        }
        custody_context = Some(context);
    } else {
        if !auth.is_super_admin() {
            return Err(AppError::Forbidden(
                "only super admin can use unscoped keys".into(),
            ));
        }
        // Gate 4 applies to unscoped keys too: the filter can only ever
        // *narrow* whatever the context dimension allowed, and a super-admin
        // whose entry names specific keys asked to be bound to them.
        require_key_in_caller_scope(&caller, key_id)?;
    }

    // What gets signed, which is not always what was handed in: an opaque

    // payload is framed under its domain tag first. See `SigningDomain`.

    let to_sign = domain.signing_input(payload);

    let payload = to_sign.as_ref();

    let signature_bytes = match record.origin {
        // The one place internal key material is used. It never leaves this
        // call: `vta_keys::internal::sign` loads, signs, and zeroizes without
        // returning the secret to any caller.
        KeyOrigin::Internal => {
            let expected = matches!(
                (algorithm, &record.key_type),
                (SignAlgorithm::EdDSA, KeyType::Ed25519) | (SignAlgorithm::ES256, KeyType::P256)
            );
            if !expected {
                return Err(AppError::Validation(format!(
                    "algorithm {} incompatible with key type {}",
                    algorithm, record.key_type
                )));
            }
            vta_keys::internal::sign(internal_ks, key_id, payload).await?
        }
        KeyOrigin::Imported => {
            // Decrypt imported secret and sign
            let seed = load_seed_bytes(keys_ks, &**seed_store, None)
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?;
            let mut secret_bytes = imported::load_secret(
                imported_ks,
                keys_ks,
                &seed,
                key_id,
                &record.key_type.to_string(),
            )
            .await?;

            let sig = match (algorithm, &record.key_type) {
                (SignAlgorithm::EdDSA, KeyType::Ed25519) => {
                    let signing_key = ed25519_dalek::SigningKey::from_bytes(
                        secret_bytes
                            .as_slice()
                            .try_into()
                            .map_err(|_| AppError::Internal("invalid Ed25519 key length".into()))?,
                    );
                    use ed25519_dalek::Signer;
                    signing_key.sign(payload).to_bytes().to_vec()
                }
                (SignAlgorithm::ES256, KeyType::P256) => {
                    let secret_key = p256::SecretKey::from_slice(&secret_bytes)
                        .map_err(|e| AppError::Internal(format!("invalid P-256 key: {e}")))?;
                    let signing_key = p256::ecdsa::SigningKey::from(&secret_key);
                    use p256::ecdsa::signature::Signer;
                    let sig: p256::ecdsa::Signature = signing_key.sign(payload);
                    sig.to_bytes().to_vec()
                }
                _ => {
                    secret_bytes.zeroize();
                    return Err(AppError::Validation(format!(
                        "algorithm {} incompatible with key type {}",
                        algorithm, record.key_type
                    )));
                }
            };
            secret_bytes.zeroize();
            sig
        }
        // Through key custody: a record whose path lies outside its context's
        // base is refused before anything is signed (`vta_keys::custody` rule 6).
        KeyOrigin::Derived => {
            if !matches!(
                (algorithm, &record.key_type),
                (SignAlgorithm::EdDSA, KeyType::Ed25519) | (SignAlgorithm::ES256, KeyType::P256)
            ) {
                return Err(AppError::Validation(format!(
                    "algorithm {} incompatible with key type {}",
                    algorithm, record.key_type
                )));
            }
            let key = crate::operations::key_custody::derive_record_key_in(
                contexts_ks,
                keys_ks,
                &**seed_store,
                audit,
                &auth.did,
                &record,
                custody_context.as_ref(),
                channel,
            )
            .await?;
            match record.key_type {
                KeyType::P256 => {
                    let p256_secret = key.p256_secret()?;
                    let signing_key = p256::ecdsa::SigningKey::from(&p256_secret.secret_key);
                    use p256::ecdsa::signature::Signer;
                    let sig: p256::ecdsa::Signature = signing_key.sign(payload);
                    sig.to_bytes().to_vec()
                }
                _ => {
                    let bytes = key.ed25519_signing_key_bytes()?;
                    let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
                    use ed25519_dalek::Signer;
                    signing_key.sign(payload).to_bytes().to_vec()
                }
            }
        }
    };

    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature_bytes);

    info!(channel, key_id = %key_id, "payload signed");

    // A signature is the most consequential thing this agent does with a key,
    // and it was the one key operation absent from the queryable trail.
    // `keys/create`, `keys/revoke`, `keys/secret` and `keys/derive-and-sign`
    // all record; the oracle that actually signs did not. An incident review
    // could establish that a key existed and that nobody exported it, and not
    // that it had signed four thousand times — which is the question asked
    // first when a key is suspected.
    //
    // Recorded here rather than in each transport's handler because this is the
    // chokepoint all four callers reach the oracle through (the Trust Task,
    // REST, DIDComm, and the rooms signer). A handler-level row would have to
    // be remembered four times and again for the fifth caller; here a new
    // caller is audited by construction.
    //
    // Success only, deliberately: a refusal returns from one of the gates
    // above, and for Trust Tasks the dispatch spine already records those as
    // `task.refused` with the URI. The REST and DIDComm refusal rows are a
    // separate gap, and belong wherever those two transports grow a spine of
    // their own rather than in eight early returns here.
    //
    // The payload is deliberately not recorded: it is the caller's bytes, may
    // carry anything, and the trail answers "which key signed, for whom, over
    // what transport", not "what did it say". The action name matches
    // `keys.derive-and-sign`, the sibling oracle, rather than this module's
    // older `key.*` rows.
    audit::record_with_detail_best_effort(
        audit,
        row.action,
        &auth.did,
        Some(key_id),
        "success",
        Some(channel),
        record.context_id.as_deref(),
        row.detail,
    )
    .await;

    Ok(SignResultBody {
        key_id: key_id.to_string(),
        signature,
        algorithm: algorithm.clone(),
    })
}

/// Why [`sign_sshsig`] refused, where `keys/sign-sshsig/0.1` declares a code for
/// it. Every other refusal is an [`AppError`], rendered as usual.
#[derive(Debug)]
#[non_exhaustive]
pub enum SshsigRefusal {
    /// `keys/sign-sshsig:failedPrecondition` — the key exists, is the caller's
    /// to use, and is not `active`.
    KeyNotActive(String),
    /// `keys:invalidArgument` — a digest that is not the length its algorithm
    /// produces, or an algorithm the key cannot perform.
    InvalidArgument(String),
    /// Anything else: the capability gate, scope, policy, quota, storage.
    App(AppError),
}

impl From<AppError> for SshsigRefusal {
    fn from(e: AppError) -> Self {
        SshsigRefusal::App(e)
    }
}

/// The SSHSIG gate: the caller must hold [`Capability::SignSshsig`], or
/// [`Capability::Sign`], which confers strictly more.
///
/// `keys/sign-sshsig/0.1` forbids requiring `sign` here — that would put the
/// general oracle in every commit signer's hands, the grant this task exists to
/// avoid — and lets a custodian accept it. An entry narrowed to `sign-sshsig`
/// alone is the shape `did-git-sign` is provisioned with.
pub(crate) async fn ensure_may_sign_sshsig(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
) -> Result<(), AppError> {
    let entry = entry_for_capability_gate(acl_ks, auth, "keys/sign-sshsig", "sign-sshsig").await?;
    if entry_or_role_has(entry.as_ref(), auth, Capability::SignSshsig)
        || entry_or_role_has(entry.as_ref(), auth, Capability::Sign)
    {
        return Ok(());
    }
    Err(AppError::Forbidden(format!(
        "keys/sign-sshsig denied: {} carries neither the sign-sshsig nor the sign capability",
        auth.did
    )))
}

/// `keys/sign-sshsig/0.1`: an SSHSIG signature over `message_hash`.
///
/// The VTA builds the signed data itself
/// ([`vta_sdk::protocols::key_management::sign_sshsig::signed_data`]) and signs
/// that as [`SigningDomain::ProtocolDefined`] — never bytes the caller chose, so
/// the result verifies as an SSHSIG statement in `namespace` and as nothing
/// else. That is what makes the narrower capability safe to grant.
///
/// Order: capability, digest shape, then the key (scope before existence, as
/// everywhere), then the signing chokepoint, which re-applies scope, the
/// context's signing policy and its daily quota. The audit row names the
/// namespace and the digest — enough to answer "who signed this commit" after a
/// compromise, and nothing about the commit itself.
#[allow(clippy::too_many_arguments)]
pub async fn sign_sshsig(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    internal_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    key_id: &str,
    algorithm: &SignAlgorithm,
    namespace: &str,
    hash_algorithm: &str,
    expected_digest_len: usize,
    message_hash: &[u8],
    channel: &str,
) -> Result<SignResultBody, SshsigRefusal> {
    use vta_sdk::protocols::key_management::sign_sshsig::signed_data;

    ensure_may_sign_sshsig(acl_ks, auth).await?;

    if message_hash.len() != expected_digest_len {
        return Err(SshsigRefusal::InvalidArgument(format!(
            "messageHash is {} bytes; {hash_algorithm} produces {expected_digest_len}",
            message_hash.len()
        )));
    }

    let record = load_record_in_caller_scope(keys_ks, auth, key_id).await?;
    if record.status != KeyStatus::Active {
        return Err(SshsigRefusal::KeyNotActive(format!(
            "key {key_id} is not active and cannot sign"
        )));
    }
    if !matches!(
        (algorithm, &record.key_type),
        (SignAlgorithm::EdDSA, KeyType::Ed25519) | (SignAlgorithm::ES256, KeyType::P256)
    ) {
        return Err(SshsigRefusal::InvalidArgument(format!(
            "algorithm {algorithm} incompatible with key type {}",
            record.key_type
        )));
    }

    let data = signed_data(namespace, hash_algorithm, message_hash);
    let detail = format!(
        "namespace={namespace} {hash_algorithm}={}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(message_hash)
    );
    Ok(sign_payload_recorded(
        keys_ks,
        imported_ks,
        internal_ks,
        contexts_ks,
        acl_ks,
        seed_store,
        audit,
        auth,
        key_id,
        &data,
        algorithm,
        SigningDomain::ProtocolDefined,
        channel,
        SignAuditRow {
            action: "keys.sign-sshsig",
            detail: Some(&detail),
        },
    )
    .await?)
}

/// Why [`sign_jws`] or [`sign_csr`] refused, where its specification declares a
/// code for it. Every other refusal is an [`AppError`], rendered as usual.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProtocolSignRefusal {
    /// `…:failedPrecondition` — the key is the caller's to use and not
    /// `active`.
    KeyNotActive(String),
    /// `…:keyTypeUnsupported`, with the key's type.
    KeyTypeUnsupported(KeyType),
    /// A refusal of the request's own content.
    Format(crate::operations::sign_formats::FormatRefusal),
    /// Anything else: the capability gate, scope, policy, quota, storage.
    App(AppError),
}

impl From<AppError> for ProtocolSignRefusal {
    fn from(e: AppError) -> Self {
        ProtocolSignRefusal::App(e)
    }
}

impl From<crate::operations::sign_formats::FormatRefusal> for ProtocolSignRefusal {
    fn from(e: crate::operations::sign_formats::FormatRefusal) -> Self {
        ProtocolSignRefusal::Format(e)
    }
}

/// The gate of a protocol signing task: the caller must hold `cap` itself.
///
/// Unlike SSHSIG, `sign` is **not** accepted in its place. `keys/sign-jws` and
/// `keys/sign-csr` say a custodian that frames `keys/sign` payloads under its
/// own signing domain — this one does, [`SigningDomain::Opaque`] — has made
/// `sign` a grant that cannot yield a JWS or a certificate request, and SHOULD
/// NOT widen it into one here. Every role that derives `sign` derives both, so
/// only an entry narrowed to `sign` alone is refused.
pub(super) async fn ensure_may_protocol_sign(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    task: &str,
    cap: Capability,
    cap_name: &str,
) -> Result<(), AppError> {
    let entry = entry_for_capability_gate(acl_ks, auth, task, cap_name).await?;
    if entry_or_role_has(entry.as_ref(), auth, cap) {
        return Ok(());
    }
    Err(AppError::Forbidden(format!(
        "{task} denied: {} does not carry the {cap_name} capability",
        auth.did
    )))
}

/// The active record `key_id` names for a protocol signing task, the
/// algorithm the chokepoint signs it with, and its public key.
pub(super) async fn protocol_signing_key(
    keys_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    key_id: &str,
) -> Result<(KeyRecord, SignAlgorithm, vta_sdk::jws::JwsKey), ProtocolSignRefusal> {
    let record = load_record_in_caller_scope(keys_ks, auth, key_id).await?;
    if record.status != KeyStatus::Active {
        return Err(ProtocolSignRefusal::KeyNotActive(format!(
            "key {key_id} is not active and cannot sign"
        )));
    }
    // The key alone decides the algorithm (RFC 8725 §2.1). The chokepoint signs
    // Ed25519 and P-256; anything else this custodian does not implement.
    let algorithm = match record.key_type {
        KeyType::Ed25519 => SignAlgorithm::EdDSA,
        KeyType::P256 => SignAlgorithm::ES256,
        ref other => return Err(ProtocolSignRefusal::KeyTypeUnsupported(other.clone())),
    };
    let public = vta_sdk::jws::JwsKey::from_did_key(&format!("did:key:{}", record.public_key))
        .map_err(|e| AppError::Internal(format!("key {key_id}'s public key: {e}")))?;
    Ok((record, algorithm, public))
}

/// `keys/sign-jws/0.1`: a compact JWS from a key that never leaves the VTA.
///
/// The VTA writes `alg` from the key, refuses the header members it sets or
/// never signs, checks an `x5c` names this key, and builds the signing input
/// itself ([`crate::operations::sign_formats`]) — signed as
/// [`SigningDomain::ProtocolDefined`], since a JWS signing input is its own
/// domain separation. Scope, the context's signing policy and its daily quota
/// apply through the same chokepoint as `keys/sign`. The audit row records
/// `alg`, `typ` and the SHA-256 of the signing input, never the payload.
#[allow(clippy::too_many_arguments)]
pub async fn sign_jws(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    internal_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    key_id: &str,
    header: &serde_json::Map<String, serde_json::Value>,
    payload: crate::operations::sign_formats::JwsPayload<'_>,
    channel: &str,
) -> Result<(String, &'static str), ProtocolSignRefusal> {
    use sha2::{Digest, Sha256};
    ensure_may_protocol_sign(
        acl_ks,
        auth,
        "keys/sign-jws",
        Capability::SignJws,
        "sign-jws",
    )
    .await?;
    let (_, algorithm, public) = protocol_signing_key(keys_ks, auth, key_id).await?;
    crate::operations::sign_formats::check_jws_header(header, &public)?;
    let input = crate::operations::sign_formats::jws_signing_input(public.alg(), header, payload)?;

    let typ = header
        .get("typ")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("-");
    let detail = format!(
        "alg={} typ={typ} sha256={}",
        public.alg(),
        hex::encode(Sha256::digest(input.as_bytes()))
    );
    let signed = sign_payload_recorded(
        keys_ks,
        imported_ks,
        internal_ks,
        contexts_ks,
        acl_ks,
        seed_store,
        audit,
        auth,
        key_id,
        input.as_bytes(),
        &algorithm,
        SigningDomain::ProtocolDefined,
        channel,
        SignAuditRow {
            action: "keys.sign-jws",
            detail: Some(&detail),
        },
    )
    .await?;
    Ok((format!("{input}.{}", signed.signature), public.alg()))
}

/// `keys/sign-csr/0.1`: a PKCS#10 certificate signing request (PEM) for a key
/// that never leaves the VTA, and that key's public half as its record
/// carries it.
///
/// The VTA builds the `CertificationRequestInfo` from the checked subject, the
/// requested alternative names and the key's own public key
/// ([`crate::operations::sign_formats`]), and signs that DER as
/// [`SigningDomain::ProtocolDefined`] through the same chokepoint as
/// `keys/sign`. The audit row records the subject, the alternative names and
/// the SHA-256 of the signed DER.
#[allow(clippy::too_many_arguments)]
pub async fn sign_csr(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    internal_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    key_id: &str,
    subject: &[vta_sdk::protocols::key_management::sign_csr::SignCsrRdnAttribute],
    alt_names: Option<&vta_sdk::protocols::key_management::sign_csr::SignCsrSubjectAltNames>,
    channel: &str,
) -> Result<(String, String), ProtocolSignRefusal> {
    use crate::operations::sign_formats::{
        CsrKey, certification_request_info, certification_request_pem, check_csr_subject,
    };
    use sha2::{Digest, Sha256};
    ensure_may_protocol_sign(
        acl_ks,
        auth,
        "keys/sign-csr",
        Capability::SignCsr,
        "sign-csr",
    )
    .await?;
    let (record, algorithm, public) = protocol_signing_key(keys_ks, auth, key_id).await?;
    let key = CsrKey::from_jws_key(&public)
        .ok_or_else(|| ProtocolSignRefusal::KeyTypeUnsupported(record.key_type.clone()))?;
    check_csr_subject(subject)?;
    let info = certification_request_info(subject, alt_names, &key);

    let subject_text = subject
        .iter()
        .map(|a| format!("{}={}", a.type_, a.value.as_str()))
        .collect::<Vec<_>>()
        .join(",");
    let names_text = alt_names
        .map(|n| {
            n.dns
                .iter()
                .map(|d| format!("dns:{}", d.as_str()))
                .chain(n.uri.iter().map(|u| format!("uri:{}", u.as_str())))
                .chain(n.email.iter().map(|e| format!("email:{}", e.as_str())))
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let detail = format!(
        "subject={subject_text} san={names_text} sha256={}",
        hex::encode(Sha256::digest(&info))
    );
    let signed = sign_payload_recorded(
        keys_ks,
        imported_ks,
        internal_ks,
        contexts_ks,
        acl_ks,
        seed_store,
        audit,
        auth,
        key_id,
        &info,
        &algorithm,
        SigningDomain::ProtocolDefined,
        channel,
        SignAuditRow {
            action: "keys.sign-csr",
            detail: Some(&detail),
        },
    )
    .await?;
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&signed.signature)
        .map_err(|e| AppError::Internal(format!("signature encoding: {e}")))?;
    let pem = certification_request_pem(&info, &key, &signature).map_err(AppError::Internal)?;
    Ok((pem, record.public_key))
}

/// What [`sign_document`] returns: the document with its proof, the proof on
/// its own, and the DID it was signed as.
#[derive(Debug, Clone)]
pub struct SignedDocument {
    pub document: serde_json::Value,
    pub proof: serde_json::Value,
    pub signer_did: String,
}

/// How far a `created` the producer names may be from this VTA's clock
/// (`keys/sign-document` item 10).
pub(super) const DOCUMENT_CREATED_WINDOW: chrono::Duration = chrono::Duration::minutes(5);

/// `keys/sign-document/0.1`: an `eddsa-jcs-2022` Data Integrity proof over a
/// JSON document, from a key that never leaves the VTA, made **only as the DID
/// the document names** in `issuer` or `controller`, and only for a
/// relationship that DID's document grants the key.
///
/// The checks run in the specification's order — the document's own before the
/// key is looked up, the key's DID document after — so no refusal says
/// anything about a key the caller could not name. The signer DID's document
/// is never taken from the request: a `did:key`'s is read from the identifier,
/// a `did:peer`'s derived from it, a `did:webvh` this VTA minted read from its
/// own log, and anything else resolved. The VTA builds the proof configuration and the hash
/// data itself ([`crate::operations::sign_formats`]) and signs those 64 bytes as
/// [`SigningDomain::ProtocolDefined`] through the same chokepoint as
/// `keys/sign`, so scope, the context's signing policy and its daily quota
/// apply. The audit row names the signer, the method, the purpose, the
/// document's `id` and `type`, and the SHA-256 of the hash data — never the
/// document.
#[allow(clippy::too_many_arguments)]
pub async fn sign_document(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    internal_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    audit: &vta_audit::SharedAuditSink,
    stores: crate::operations::persona::PersonaStores<'_>,
    resolver: Option<&affinidi_did_resolver_cache_sdk::DIDCacheClient>,
    auth: &AuthClaims,
    key_id: &str,
    document: &serde_json::Value,
    proof_purpose: Option<&str>,
    created: Option<&str>,
    challenge: Option<&str>,
    domain: Option<&str>,
    channel: &str,
) -> Result<SignedDocument, ProtocolSignRefusal> {
    use crate::operations::sign_formats::{
        FormatRefusal, did_key_methods, document_proof_config, document_signer,
        eddsa_jcs_2022_hash_data, signer_methods,
    };
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    // Items 1 – 2.
    ensure_may_protocol_sign(
        acl_ks,
        auth,
        "keys/sign-document",
        Capability::SignDocument,
        "sign-document",
    )
    .await?;
    // Items 3 – 4: the document alone.
    let signer = document_signer(document)?;
    // Items 5 – 7: the key — in scope, active, and Ed25519 (the one key type
    // `eddsa-jcs-2022` has).
    let (record, _, _) = protocol_signing_key(keys_ks, auth, key_id).await?;
    if record.key_type != KeyType::Ed25519 {
        return Err(ProtocolSignRefusal::KeyTypeUnsupported(record.key_type));
    }
    let key = vta_sdk::did_key::decode_ed25519_public_key_multibase(&record.public_key)
        .map_err(|e| AppError::Internal(format!("key {key_id}'s public key: {e}")))?;

    // Item 8: the signer DID's own document, never one from the request.
    let own = match did_key_methods(&signer) {
        Some(m) => Some(m),
        None => crate::operations::persona::own_document(stores, &signer)
            .await?
            .map(|doc| signer_methods(&signer, &doc)),
    };
    let methods = match own {
        Some(m) => m,
        None => {
            let Some(resolver) = resolver else {
                return Err(ProtocolSignRefusal::KeyNotActive(format!(
                    "this VTA resolves no DID documents, so it cannot tell whether {key_id} is                      a verification method of {signer}"
                )));
            };
            let resolved = resolver.resolve(&signer).await.map_err(|e| {
                ProtocolSignRefusal::KeyNotActive(format!(
                    "the document of {signer} could not be resolved: {e}"
                ))
            })?;
            let doc = serde_json::to_value(&resolved.doc)
                .map_err(|e| AppError::Internal(format!("resolved document: {e}")))?;
            signer_methods(&signer, &doc)
        }
    };
    let named_by = if document.get("issuer").is_some() {
        "issuer"
    } else {
        "controller"
    };
    let keyed: Vec<_> = methods.into_iter().filter(|m| m.key == key).collect();
    if keyed.is_empty() {
        return Err(FormatRefusal::IssuerMismatch(named_by).into());
    }
    // Item 9: the first method the DID lists the key under for this purpose.
    let purpose: &'static str = match proof_purpose.unwrap_or("assertionMethod") {
        "assertionMethod" => "assertionMethod",
        "authentication" => "authentication",
        other => {
            return Err(AppError::Validation(format!("proofPurpose {other} is not served")).into());
        }
    };
    let Some(method) = keyed.iter().find(|m| m.purposes.contains(&purpose)) else {
        return Err(FormatRefusal::PurposeNotAuthorized(purpose).into());
    };

    // Item 10: the key's signature dates the proof, so the producer cannot
    // back- or forward-date it beyond the window.
    let now = Utc::now();
    let created = match created {
        Some(c) => {
            let at = chrono::DateTime::parse_from_rfc3339(c)
                .map_err(|e| FormatRefusal::InvalidArgument(format!("created: {e}")))?;
            if (at.with_timezone(&Utc) - now).abs() > DOCUMENT_CREATED_WINDOW {
                return Err(FormatRefusal::InvalidArgument(format!(
                    "created {c} is more than five minutes from this VTA's clock"
                ))
                .into());
            }
            c.to_string()
        }
        None => now.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    };

    // Item 11: the proof is built here, and these 64 bytes are all that is
    // signed.
    let config = document_proof_config(document, &method.id, purpose, &created, challenge, domain);
    let hash_data = eddsa_jcs_2022_hash_data(document, &config).map_err(AppError::Internal)?;
    let detail = format!(
        "signer={signer} vm={} purpose={purpose} id={} type={} sha256={}",
        method.id,
        document
            .get("id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-"),
        document
            .get("type")
            .map(|t| t.to_string())
            .unwrap_or_else(|| "-".into()),
        hex::encode(Sha256::digest(hash_data))
    );
    let signed = sign_payload_recorded(
        keys_ks,
        imported_ks,
        internal_ks,
        contexts_ks,
        acl_ks,
        seed_store,
        audit,
        auth,
        key_id,
        &hash_data,
        &SignAlgorithm::EdDSA,
        SigningDomain::ProtocolDefined,
        channel,
        SignAuditRow {
            action: "keys.sign-document",
            detail: Some(&detail),
        },
    )
    .await?;
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&signed.signature)
        .map_err(|e| AppError::Internal(format!("signature encoding: {e}")))?;

    // Item 12.
    let mut proof = config;
    proof["proofValue"] = multibase::encode(multibase::Base::Base58Btc, signature).into();
    let mut secured = document.clone();
    secured["proof"] = proof.clone();
    Ok(SignedDocument {
        document: secured,
        proof,
        signer_did: signer,
    })
}

/// Ephemeral derive-and-sign: derive an Ed25519 key at `derivation_path` from
/// the VTA's seed, sign `payload`, and return `{ public_key, signature }`
/// **without persisting a `KeyRecord`**.
///
/// This is the signing oracle that lets a fleet manager (whose fleet seed *is*
/// this VTA's seed, ideally TEE-sealed) act as any derived child identity — e.g.
/// a per-VTA super-admin at `m/26'/9'/<idx>'` — so the seed never leaves the
/// VTA.
///
/// **Super-admin only, and only inside `m/26'/9'`**
/// ([`vta_keys::custody::DELEGATED_IDENTITY_ROOT`]). The caller picks the
/// identity it signs as, so a role-only gate let a context-scoped admin sign as
/// any key the VTA holds, including its own `did:webvh` update key. The subtree
/// confinement holds even for a super-admin: this oracle never signs as a key
/// a record exists for. Every signature is audited with the path and a digest
/// of what was signed (VTI-VTA-006).
#[allow(clippy::too_many_arguments)]
pub async fn derive_and_sign(
    keys_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    auth: &AuthClaims,
    audit: &vta_audit::SharedAuditSink,
    key_type: &KeyType,
    derivation_path: &str,
    payload: &[u8],
    algorithm: &SignAlgorithm,
    channel: &str,
) -> Result<DeriveAndSignResultBody, AppError> {
    // The same `Sign` gate as the stored-key oracle: this signs caller-supplied
    // bytes too, and a super-admin narrowed without `sign` asked not to.
    ensure_may_sign(acl_ks, auth, "keys/derive-and-sign").await?;
    let signing_bytes = crate::operations::key_custody::derive_delegated_identity(
        keys_ks,
        &**seed_store,
        auth,
        derivation_path,
        "keys.derive-and-sign",
        audit,
        channel,
    )
    .await?;

    if !matches!(
        (algorithm, key_type),
        (SignAlgorithm::EdDSA, KeyType::Ed25519)
    ) {
        return Err(AppError::Validation(format!(
            "derive-and-sign currently supports only EdDSA/Ed25519 (got {algorithm}/{key_type:?})"
        )));
    }

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_bytes);
    let public_key =
        encode_public_multibase(&KeyType::Ed25519, signing_key.verifying_key().as_bytes());

    use ed25519_dalek::Signer;
    let signature_bytes = signing_key.sign(payload).to_bytes().to_vec();
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature_bytes);

    info!(
        channel,
        derivation_path = %derivation_path,
        "ephemeral derive-and-sign (no key record persisted)"
    );
    record_delegated_signature(
        audit,
        auth,
        "keys.derive-and-sign",
        derivation_path,
        &format!("keyType={key_type} alg={algorithm}"),
        payload,
        channel,
    )
    .await;

    Ok(DeriveAndSignResultBody {
        public_key,
        signature,
        algorithm: algorithm.clone(),
    })
}

/// Derive an Ed25519 key at `derivation_path` and attach an `eddsa-jcs-2022`
/// Data-Integrity proof to `document`, signed **as the derived key**, persisting
/// no key record. The DI-signing counterpart of [`derive_and_sign`].
///
/// Uses the same `DataIntegrityProof::sign` the VTA uses to issue VCs, so the
/// proof is correct-by-construction for any `affinidi-data-integrity` verifier.
/// This is how a fleet manager has its fleet VTA sign an `auth/authenticate/0.3`
/// document as a per-VTA super-admin (`m/26'/9'/<idx>'`) — the seed never leaves
/// the VTA. **Super-admin only, inside `m/26'/9'`**, for the reasons given on
/// [`derive_and_sign`]. Audited with a digest of the signed document.
#[allow(clippy::too_many_arguments)]
pub async fn derive_and_sign_document(
    keys_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    auth: &AuthClaims,
    audit: &vta_audit::SharedAuditSink,
    key_type: &KeyType,
    derivation_path: &str,
    mut document: serde_json::Value,
    proof_purpose: Option<&str>,
    channel: &str,
) -> Result<DeriveAndSignDocumentResultBody, AppError> {
    // `Sign`, as for `derive_and_sign`: the document is the caller's, and any
    // JSON object is accepted, so this is a general signing request.
    ensure_may_sign(acl_ks, auth, "keys/derive-and-sign-document").await?;
    // A proof no verifier accepts is refused before any key is derived: the
    // purpose must name a signing relationship (VTI-KEY-022), never
    // `keyAgreement` or an arbitrary string. A did:key's key is listed under
    // all four, so any of them verifies.
    let proof_purpose =
        vti_common::auth::ProofPurpose::parse(proof_purpose.unwrap_or("assertionMethod"))
            .map_err(|e| AppError::Validation(format!("proofPurpose: {e}")))?
            .as_str();
    let signing_bytes = crate::operations::key_custody::derive_delegated_identity(
        keys_ks,
        &**seed_store,
        auth,
        derivation_path,
        "keys.derive-and-sign-document",
        audit,
        channel,
    )
    .await?;

    if !matches!(key_type, KeyType::Ed25519) {
        return Err(AppError::Validation(format!(
            "derive-and-sign-document currently supports only Ed25519 (got {key_type:?})"
        )));
    }
    if !document.is_object() {
        return Err(AppError::Validation(
            "document must be a JSON object".into(),
        ));
    }

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_bytes);

    // The derived identity's did:key + its verification method (did:key:zX#zX),
    // and a Secret built from the derived private key — identical to how the VTA
    // builds its issuer Secret.
    let pub_mb = encode_public_multibase(&KeyType::Ed25519, signing_key.verifying_key().as_bytes());
    let signer_did = format!("did:key:{pub_mb}");
    let priv_mb = encode_private_multibase(&KeyType::Ed25519, &signing_key.to_bytes());
    let mut secret = Secret::from_multibase(&priv_mb, None)
        .map_err(|e| AppError::Internal(format!("construct derived Secret: {e}")))?;
    secret.id = format!("{signer_did}#{pub_mb}");

    // JCS is presence-sensitive — sign the proof-less shape (verifiers strip
    // `proof` too).
    if let Some(obj) = document.as_object_mut() {
        obj.remove("proof");
    }
    let proof = DataIntegrityProof::sign(
        &document,
        &secret,
        SignOptions::new()
            .with_proof_purpose(proof_purpose)
            .with_cryptosuite(CryptoSuite::EddsaJcs2022)
            .with_created(Utc::now()),
    )
    .await
    .map_err(|e| AppError::Internal(format!("DI-sign document: {e}")))?;
    document
        .as_object_mut()
        .expect("checked is_object above")
        .insert(
            "proof".to_string(),
            serde_json::to_value(&proof)
                .map_err(|e| AppError::Internal(format!("serialize proof: {e}")))?,
        );

    info!(
        channel,
        derivation_path = %derivation_path,
        "derive-and-sign-document (DI proof, no key record persisted)"
    );
    let signed_bytes = serde_json::to_vec(&document)
        .map_err(|e| AppError::Internal(format!("serialize signed document: {e}")))?;
    record_delegated_signature(
        audit,
        auth,
        "keys.derive-and-sign-document",
        derivation_path,
        &format!("keyType={key_type} proofPurpose={proof_purpose}"),
        &signed_bytes,
        channel,
    )
    .await;
    Ok(DeriveAndSignDocumentResultBody {
        signer_did,
        document,
    })
}

/// Audit a delegated-identity signature: who, as which path, and a SHA-256 of
/// what was signed (VTI-VTA-006: record what was signed, for which caller). A
/// digest, not the payload, because the payload may carry personal data an
/// audit row must not embed (VTI-AUD-005).
pub(super) async fn record_delegated_signature(
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    action: &str,
    derivation_path: &str,
    detail: &str,
    signed: &[u8],
    channel: &str,
) {
    use sha2::Digest;
    let digest = hex::encode(sha2::Sha256::digest(signed));
    audit::record_with_detail_best_effort(
        audit,
        action,
        &auth.did,
        Some(derivation_path),
        "success",
        Some(channel),
        None,
        Some(&format!("{detail} sha256:{digest}")),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthClaims;
    use crate::operations::keys::test_support::*;
    use vti_common::acl::Role;

    /// VTI-KEY-032 (found alongside FTL-29904): a context-scoped admin must not
    /// make the VTA derive a key outside its own context's subtree. The target
    /// here is the VTA's own `did:webvh` update-key path. Before the fix
    /// `create_key` accepted it, recorded the key under the caller's context,
    /// and `get_key_secret`'s scope check, which reads that context, then
    /// released the VTA's private key.
    #[tokio::test]
    async fn vti_key_032_context_admin_cannot_derive_outside_its_context() {
        let h = TestHarness::new().await;
        let super_admin = h.super_admin_auth();
        let tenant = h.context_admin_auth();

        let victim = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit,
            &h.acl_ks,
            &super_admin,
            CreateKeyParams {
                internal: false,
                key_type: KeyType::Ed25519,
                derivation_path: Some("m/26'/0'/0'/0'".into()),
                key_id: Some("vta-update-key".into()),
                mnemonic: None,
                label: None,
                context_id: None,
            },
            "test",
        )
        .await
        .expect("super-admin creates the VTA's own key");

        let attempt = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit,
            &h.acl_ks,
            &tenant,
            CreateKeyParams {
                internal: false,
                key_type: KeyType::Ed25519,
                derivation_path: Some("m/26'/0'/0'/0'".into()),
                key_id: Some("innocuous".into()),
                mnemonic: None,
                label: None,
                context_id: Some("test-ctx".into()),
            },
            "test",
        )
        .await;
        assert!(
            matches!(attempt, Err(AppError::Forbidden(_))),
            "a context admin must not choose a derivation path, got {:?}",
            attempt.map(|c| c.public_key == victim.public_key)
        );

        // Defence in depth (custody rule 6): a record already planted this way,
        // by a build before the fix or through a restore, is inert. It can be
        // neither exported nor used to sign, even by its own context's admin.
        let now = chrono::Utc::now();
        let planted = KeyRecord {
            key_id: "planted".into(),
            derivation_path: "m/26'/0'/0'/0'".into(),
            key_type: KeyType::Ed25519,
            status: KeyStatus::Active,
            public_key: victim.public_key.clone(),
            label: None,
            context_id: Some("test-ctx".into()),
            exportable: None,
            seed_id: None,
            origin: KeyOrigin::Derived,
            created_at: now,
            updated_at: now,
        };
        h.keys_ks
            .insert(keys::store_key("planted"), &planted)
            .await
            .unwrap();
        let export = get_key_secret(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &tenant,
            "planted",
            ExportChannel::Local("test"),
        )
        .await;
        assert!(
            matches!(export, Err(AppError::Forbidden(_))),
            "export: {export:?}"
        );
        let sign = sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &tenant,
            "planted",
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
            "test",
        )
        .await;
        assert!(
            matches!(sign, Err(AppError::Forbidden(_))),
            "sign: {sign:?}"
        );
    }

    /// `keys/derive-and-sign` lets the caller pick the identity it signs as, so
    /// it is super-admin only and confined to the delegated subtree: a tenant
    /// admin cannot sign as the VTA (or anyone else) through it.
    #[tokio::test]
    async fn derive_and_sign_refuses_a_context_admin_and_foreign_paths() {
        let h = TestHarness::new().await;
        let sign = async |auth: &AuthClaims, path: &str| {
            derive_and_sign(
                &h.keys_ks,
                &h.acl_ks,
                &h.seed_store,
                auth,
                &h.audit,
                &KeyType::Ed25519,
                path,
                b"x",
                &SignAlgorithm::EdDSA,
                "test",
            )
            .await
        };
        let tenant = h.context_admin_auth();
        let admin = h.super_admin_auth();
        assert!(matches!(
            sign(&tenant, "m/26'/9'/0'").await,
            Err(AppError::Forbidden(_))
        ));
        // The VTA's did:webvh update-key path: refused even for a super-admin.
        assert!(matches!(
            sign(&admin, "m/26'/0'/0'/0'").await,
            Err(AppError::Forbidden(_))
        ));
        assert!(sign(&admin, "m/26'/9'/0'").await.is_ok());
    }

    #[tokio::test]
    async fn test_sign_and_verify_ed25519() {
        let h = TestHarness::new().await;
        let auth = h.super_admin_auth();

        // First create a key
        let key = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit,
            &h.acl_ks,
            &auth,
            CreateKeyParams {
                internal: false,
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some("sign-test-key".into()),
                mnemonic: None,
                label: None,
                context_id: Some("test-ctx".into()),
            },
            "test",
        )
        .await
        .expect("create_key should succeed");

        // Sign a payload
        let payload = b"hello world";
        let result = sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &auth,
            &key.key_id,
            payload,
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
            "test",
        )
        .await
        .expect("sign_payload should succeed");

        assert_eq!(result.key_id, "sign-test-key");
        assert_eq!(result.algorithm, SignAlgorithm::EdDSA);
        // Verify the signature is valid base64url
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&result.signature)
            .expect("signature should be valid base64url");
        assert!(!decoded.is_empty(), "decoded signature must be non-empty");
        // Ed25519 signatures are 64 bytes
        assert_eq!(decoded.len(), 64, "Ed25519 signature should be 64 bytes");
    }

    #[tokio::test]
    async fn derive_and_sign_is_ephemeral_admin_only_and_verifies() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let h = TestHarness::new().await;
        let auth = h.super_admin_auth();
        let payload = b"fleet super-admin auth challenge";

        let result = derive_and_sign(
            &h.keys_ks,
            &h.acl_ks,
            &h.seed_store,
            &auth,
            &h.audit,
            &KeyType::Ed25519,
            "m/26'/9'/0'",
            payload,
            &SignAlgorithm::EdDSA,
            "test",
        )
        .await
        .expect("derive_and_sign should succeed for an admin");

        // The signature verifies against the returned (derived) public key.
        let (_, pk_bytes) = multibase::decode(&result.public_key).expect("multibase pubkey");
        assert_eq!(&pk_bytes[0..2], &[0xed, 0x01], "ed25519-pub multicodec");
        let vk = VerifyingKey::from_bytes(pk_bytes[2..].try_into().unwrap()).unwrap();
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&result.signature)
            .unwrap();
        let sig = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
        vk.verify(payload, &sig).expect("signature must verify");

        // Ephemeral: no key record was persisted.
        let listed = list_keys(
            &h.keys_ks,
            &auth,
            ListKeysParams {
                cursor: None,
                limit: None,
                status: None,
                context_id: None,
            },
            "test",
        )
        .await
        .expect("list keys");
        assert!(
            listed.keys.is_empty(),
            "derive_and_sign must not persist a key"
        );

        // A non-admin caller is rejected.
        let non_admin = AuthClaims {
            role: Role::Application,
            ..h.super_admin_auth()
        };
        assert!(
            derive_and_sign(
                &h.keys_ks,
                &h.acl_ks,
                &h.seed_store,
                &non_admin,
                &h.audit,
                &KeyType::Ed25519,
                "m/26'/9'/0'",
                payload,
                &SignAlgorithm::EdDSA,
                "test",
            )
            .await
            .is_err(),
            "non-admin must be rejected"
        );
    }

    #[tokio::test]
    async fn derive_and_sign_document_grafts_di_proof_as_derived_key() {
        let h = TestHarness::new().await;
        let auth = h.super_admin_auth();
        let doc = serde_json::json!({
            "type": "https://trusttasks.org/spec/auth/authenticate/0.3",
            "payload": { "challenge": "abc", "sessionId": "s1" },
        });

        let res = derive_and_sign_document(
            &h.keys_ks,
            &h.acl_ks,
            &h.seed_store,
            &auth,
            &h.audit,
            &KeyType::Ed25519,
            "m/26'/9'/0'",
            doc.clone(),
            None,
            "test",
        )
        .await
        .expect("derive_and_sign_document should succeed for an admin");

        // Signer is the derived super-admin did:key.
        assert!(
            res.signer_did.starts_with("did:key:z6Mk"),
            "{}",
            res.signer_did
        );
        // A proof was grafted, by the derived key, with a proofValue.
        let proof = res.document.get("proof").expect("proof grafted");
        assert!(
            proof.get("proofValue").and_then(|v| v.as_str()).is_some(),
            "proof has a proofValue"
        );
        let vm = proof
            .get("verificationMethod")
            .and_then(|v| v.as_str())
            .unwrap();
        assert!(
            vm.starts_with(&res.signer_did),
            "vm {vm} bound to signer {}",
            res.signer_did
        );

        // Deterministic: same path → same signer.
        let res2 = derive_and_sign_document(
            &h.keys_ks,
            &h.acl_ks,
            &h.seed_store,
            &auth,
            &h.audit,
            &KeyType::Ed25519,
            "m/26'/9'/0'",
            doc,
            None,
            "test",
        )
        .await
        .unwrap();
        assert_eq!(res.signer_did, res2.signer_did);

        // Non-admin rejected.
        let non_admin = AuthClaims {
            role: Role::Application,
            ..h.super_admin_auth()
        };
        assert!(
            derive_and_sign_document(
                &h.keys_ks,
                &h.acl_ks,
                &h.seed_store,
                &non_admin,
                &h.audit,
                &KeyType::Ed25519,
                "m/26'/9'/0'",
                serde_json::json!({"x": 1}),
                None,
                "test",
            )
            .await
            .is_err(),
            "non-admin must be rejected"
        );
    }

    /// Context policy gates the signing oracle as a *resource-bound* guardrail:
    /// the key's context policy binds every signer — a context-scoped actor and
    /// the super-admin alike — while a key the policy permits still signs.
    #[tokio::test]
    async fn sign_payload_honours_context_policy_signable_keys() {
        use crate::contexts::{ContextRecord, store_context};
        use vta_sdk::context_policy::ContextPolicy;

        let h = TestHarness::new().await;
        let admin = h.super_admin_auth();

        // A context whose policy only permits a *different* key id.
        let now = chrono::Utc::now();
        store_context(
            &h.contexts_ks,
            &ContextRecord {
                id: "locked-ctx".into(),
                name: "locked".into(),
                did: None,
                description: None,
                parent: None,
                base_path: "m/26'/2'/9'".into(),
                index: 9,
                created_at: now,
                updated_at: now,
                context_policy: Some(ContextPolicy {
                    signable_keys: Some(["allowed-key".to_string()].into_iter().collect()),
                    ..ContextPolicy::unrestricted()
                }),
            },
        )
        .await
        .expect("store locked-ctx");

        let key = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit,
            &h.acl_ks,
            &admin,
            CreateKeyParams {
                internal: false,
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some("blocked-key".into()),
                mnemonic: None,
                label: None,
                context_id: Some("locked-ctx".into()),
            },
            "test",
        )
        .await
        .expect("create_key");

        // A context-scoped actor is denied: blocked-key is not in the allow-list.
        let scoped = AuthClaims {
            did: "did:key:z6MkScopedStaff".to_string(),
            role: Role::Admin,
            allowed_contexts: vec!["locked-ctx".to_string()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        let denied = sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &scoped,
            &key.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
            "test",
        )
        .await;
        assert!(
            matches!(denied, Err(crate::error::AppError::Forbidden(_))),
            "context-scoped sign of a non-allowed key must be Forbidden, got {denied:?}"
        );

        // Resource-bound: even the super-admin is gated by the key's context
        // policy. (The owner relaxes it via policy CRUD, not by bypassing here.)
        let denied_admin = sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &admin,
            &key.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
            "test",
        )
        .await;
        assert!(
            matches!(denied_admin, Err(crate::error::AppError::Forbidden(_))),
            "super-admin is also bound by the key's context policy, got {denied_admin:?}"
        );

        // A key the policy *does* permit signs fine for the scoped actor.
        let allowed = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit,
            &h.acl_ks,
            &admin,
            CreateKeyParams {
                internal: false,
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some("allowed-key".into()),
                mnemonic: None,
                label: None,
                context_id: Some("locked-ctx".into()),
            },
            "test",
        )
        .await
        .expect("create allowed-key");
        sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &scoped,
            &allowed.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
            "test",
        )
        .await
        .expect("policy permits allowed-key");
    }

    /// Gate 4 (#818): the caller's own ACL row may narrow which key ids it
    /// can invoke the oracle on — the actor-scoped complement of the
    /// resource-bound `signable_keys` policy pinned above.
    #[tokio::test]
    async fn sign_payload_honours_acl_allowed_keys() {
        use vti_common::acl::{AclEntry, store_acl_entry};

        let h = TestHarness::new().await;
        let admin = h.super_admin_auth();

        // Two keys in the same context — the split gate 4 exists to express.
        for id in ["tenant-key-a", "tenant-key-b"] {
            create_key(
                &h.keys_ks,
                &h.internal_ks,
                &h.contexts_ks,
                &h.seed_store,
                &h.audit,
                &h.acl_ks,
                &admin,
                CreateKeyParams {
                    internal: false,
                    key_type: KeyType::Ed25519,
                    derivation_path: None,
                    key_id: Some(id.into()),
                    mnemonic: None,
                    label: None,
                    context_id: Some("test-ctx".into()),
                },
                "test",
            )
            .await
            .expect("create key");
        }

        let caller_did = "did:key:z6MkFilteredSigner";
        let claims = AuthClaims {
            did: caller_did.to_string(),
            role: Role::Application,
            allowed_contexts: vec!["test-ctx".to_string()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        let sign = |key_id: &'static str| {
            let claims = claims.clone();
            let h = &h;
            async move {
                sign_payload(
                    &h.keys_ks,
                    &h.imported_ks,
                    &h.internal_ks,
                    &h.contexts_ks,
                    &h.acl_ks,
                    &h.seed_store,
                    &h.audit,
                    &claims,
                    key_id,
                    b"payload",
                    &SignAlgorithm::EdDSA,
                    SigningDomain::Opaque,
                    "test",
                )
                .await
            }
        };

        // No ACL filter (`allowed_keys: None`): every key in scope — the
        // pre-#818 behaviour, byte-identical.
        let entry = AclEntry::new(caller_did, Role::Application, "did:key:zSetup")
            .with_contexts(vec!["test-ctx".into()]);
        store_acl_entry(&h.acl_ks, &entry).await.unwrap();
        sign("tenant-key-a").await.expect("no filter: key-a signs");
        sign("tenant-key-b").await.expect("no filter: key-b signs");

        // A filter naming exactly key-a: key-b is refused, key-a still signs.
        // The narrowing bound the very next request — same claims, same live
        // "session", no revocation step in between (the gate reads the row).
        store_acl_entry(
            &h.acl_ks,
            &entry
                .clone()
                .with_allowed_keys(Some(["tenant-key-a".to_string()].into_iter().collect())),
        )
        .await
        .unwrap();
        sign("tenant-key-a").await.expect("filter names key-a");
        let denied = sign("tenant-key-b").await;
        assert!(
            matches!(denied, Err(crate::error::AppError::Forbidden(_))),
            "a key outside the caller's allowed_keys must be Forbidden, got {denied:?}"
        );

        // Trap 1: PRESENT-BUT-EMPTY is authorized on NO keys — the narrowest
        // grant, never a wildcard. If a bare `is_empty()` ever sneaks into
        // the gate, this is the assertion that catches it.
        store_acl_entry(
            &h.acl_ks,
            &entry.clone().with_allowed_keys(Some(Default::default())),
        )
        .await
        .unwrap();
        for key in ["tenant-key-a", "tenant-key-b"] {
            let denied = sign(key).await;
            assert!(
                matches!(denied, Err(crate::error::AppError::Forbidden(_))),
                "an EMPTY allowed_keys must refuse every key (got {denied:?} for {key})"
            );
        }
    }

    /// Gate 4 still binds when gate 0 does not run. A `ProtocolDefined`
    /// signature skips the `Sign` capability gate (VTI-VTA-007), so the row
    /// gate 4 judges is read on its own path. That is the case a "not loaded"
    /// state could have let through as "no row": [`CallerAcl`] has no such
    /// state, and this pins that the narrowing still refuses.
    #[tokio::test]
    async fn gate_4_binds_a_protocol_defined_signature_too() {
        use vti_common::acl::{AclEntry, store_acl_entry};

        let h = TestHarness::new().await;
        let admin = h.super_admin_auth();
        for id in ["proto-key-a", "proto-key-b"] {
            create_key(
                &h.keys_ks,
                &h.internal_ks,
                &h.contexts_ks,
                &h.seed_store,
                &h.audit,
                &h.acl_ks,
                &admin,
                CreateKeyParams {
                    internal: false,
                    key_type: KeyType::Ed25519,
                    derivation_path: None,
                    key_id: Some(id.into()),
                    mnemonic: None,
                    label: None,
                    context_id: Some("test-ctx".into()),
                },
                "test",
            )
            .await
            .expect("create key");
        }

        let caller_did = "did:key:z6MkProtocolSigner";
        let claims = AuthClaims {
            did: caller_did.to_string(),
            role: Role::Application,
            allowed_contexts: vec!["test-ctx".to_string()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        store_acl_entry(
            &h.acl_ks,
            &AclEntry::new(caller_did, Role::Application, "did:key:zSetup")
                .with_contexts(vec!["test-ctx".into()])
                .with_allowed_keys(Some(["proto-key-a".to_string()].into_iter().collect())),
        )
        .await
        .unwrap();

        let sign = |key_id: &'static str| {
            let claims = claims.clone();
            let h = &h;
            async move {
                sign_payload(
                    &h.keys_ks,
                    &h.imported_ks,
                    &h.internal_ks,
                    &h.contexts_ks,
                    &h.acl_ks,
                    &h.seed_store,
                    &h.audit,
                    &claims,
                    key_id,
                    b"payload",
                    &SignAlgorithm::EdDSA,
                    SigningDomain::ProtocolDefined,
                    "test",
                )
                .await
            }
        };
        sign("proto-key-a")
            .await
            .expect("the key the filter names signs");
        let denied = sign("proto-key-b").await;
        assert!(
            matches!(denied, Err(crate::error::AppError::Forbidden(_))),
            "gate 4 must refuse a key outside allowed_keys without gate 0, got {denied:?}"
        );
    }

    /// Gate 4 intersects — it never widens. A filter naming a key outside the
    /// caller's contexts does not grant it: the context gate still runs
    /// first, so the caller is refused before its key filter is even asked.
    /// And the filter binds the unscoped-key path too: a super-admin whose
    /// entry names specific keys asked to be bound to them.
    #[tokio::test]
    async fn sign_payload_allowed_keys_only_narrows_never_widens() {
        use crate::contexts::{ContextRecord, store_context};
        use vta_sdk::context_policy::ContextPolicy;
        use vti_common::acl::{AclEntry, store_acl_entry};

        let h = TestHarness::new().await;
        let admin = h.super_admin_auth();

        // A key in a context the caller does NOT hold.
        let now = chrono::Utc::now();
        store_context(
            &h.contexts_ks,
            &ContextRecord {
                id: "other-ctx".into(),
                name: "other".into(),
                did: None,
                description: None,
                parent: None,
                base_path: "m/26'/2'/31'".into(),
                index: 31,
                created_at: now,
                updated_at: now,
                context_policy: Some(ContextPolicy::unrestricted()),
            },
        )
        .await
        .unwrap();
        let foreign = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit,
            &h.acl_ks,
            &admin,
            CreateKeyParams {
                internal: false,
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some("foreign-key".into()),
                mnemonic: None,
                label: None,
                context_id: Some("other-ctx".into()),
            },
            "test",
        )
        .await
        .unwrap();

        // The caller's entry NAMES the foreign key — and must still be
        // refused, because the filter intersects with the context scope.
        let caller_did = "did:key:z6MkOverreach";
        store_acl_entry(
            &h.acl_ks,
            &AclEntry::new(caller_did, Role::Application, "did:key:zSetup")
                .with_contexts(vec!["test-ctx".into()])
                .with_allowed_keys(Some(["foreign-key".to_string()].into_iter().collect())),
        )
        .await
        .unwrap();
        let claims = AuthClaims {
            did: caller_did.to_string(),
            role: Role::Application,
            allowed_contexts: vec!["test-ctx".to_string()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        let denied = sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &claims,
            &foreign.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
            "test",
        )
        .await;
        assert!(
            matches!(denied, Err(crate::error::AppError::Forbidden(_))),
            "naming a key in allowed_keys must not reach past the context scope, got {denied:?}"
        );

        // Unscoped keys are gated too: a super-admin whose own row carries a
        // filter is bound by it even where no context policy exists.
        let unscoped = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit,
            &h.acl_ks,
            &admin,
            CreateKeyParams {
                internal: false,
                key_type: KeyType::Ed25519,
                derivation_path: Some("m/26'/2'/77'/0'".into()),
                key_id: Some("unscoped-key".into()),
                mnemonic: None,
                label: None,
                context_id: None,
            },
            "test",
        )
        .await
        .unwrap();
        store_acl_entry(
            &h.acl_ks,
            &AclEntry::new(&admin.did, Role::Admin, "did:key:zSetup")
                .with_allowed_keys(Some(["some-other-key".to_string()].into_iter().collect())),
        )
        .await
        .unwrap();
        let denied = sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &admin,
            &unscoped.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
            "test",
        )
        .await;
        assert!(
            matches!(denied, Err(crate::error::AppError::Forbidden(_))),
            "a filtered super-admin is bound on unscoped keys too, got {denied:?}"
        );
    }

    /// A caller authorized in one context cannot sign with another context's
    /// key (#805).
    ///
    /// This is the property a declined proposal rests on. The VTA does not
    /// inspect what it signs, so "a multi-domain signer cannot sign as a domain
    /// it does not hold" is true *only* because the caller's context scope is
    /// checked against the key's. If this regressed, a compromised gateway
    /// holding one domain's session could sign as any domain whose key id it
    /// could name — and nothing about the request would look wrong.
    ///
    /// Note the granularity being pinned: **per context, not per key id**. A
    /// caller scoped to a context may sign with *every* key in it by default.
    /// Per-key narrowing exists in two opt-in forms — the resource-bound
    /// `signable_keys` policy and the actor-scoped `allowed_keys` ACL filter
    /// (#818), each covered above; separation between domains still comes
    /// from giving each its own context.
    #[tokio::test]
    async fn sign_payload_refuses_a_key_outside_the_callers_contexts() {
        use crate::contexts::{ContextRecord, store_context};
        use vta_sdk::context_policy::ContextPolicy;

        let h = TestHarness::new().await;
        let admin = h.super_admin_auth();

        // Two tenant contexts, both with an unrestricted policy — so the only
        // thing that can refuse below is the caller's context scope, not the
        // `signable_keys` guardrail (which has its own test above).
        let now = chrono::Utc::now();
        for (idx, id) in [(21u32, "domain-a"), (22, "domain-b")] {
            store_context(
                &h.contexts_ks,
                &ContextRecord {
                    id: id.into(),
                    name: id.into(),
                    did: None,
                    description: None,
                    parent: None,
                    base_path: format!("m/26'/2'/{idx}'"),
                    index: idx,
                    created_at: now,
                    updated_at: now,
                    context_policy: Some(ContextPolicy::unrestricted()),
                },
            )
            .await
            .unwrap_or_else(|e| panic!("store {id}: {e:?}"));
        }

        let key = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit,
            &h.acl_ks,
            &admin,
            CreateKeyParams {
                internal: false,
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some("domain-a-key".into()),
                mnemonic: None,
                label: None,
                context_id: Some("domain-a".into()),
            },
            "test",
        )
        .await
        .expect("create domain-a-key");

        // Authorized in `domain-b` only — a different tenant of the same VTA.
        let other_tenant = AuthClaims {
            did: "did:key:z6MkDomainB".to_string(),
            role: Role::Admin,
            allowed_contexts: vec!["domain-b".to_string()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };

        let denied = sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &other_tenant,
            &key.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
            "test",
        )
        .await;
        assert!(
            matches!(denied, Err(crate::error::AppError::Forbidden(_))),
            "signing another context's key must be Forbidden, got {denied:?}"
        );

        // ...and the same caller signs fine once the key is in *their* context,
        // so the refusal above is the scope check and not an unrelated failure.
        let own = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit,
            &h.acl_ks,
            &admin,
            CreateKeyParams {
                internal: false,
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some("domain-b-key".into()),
                mnemonic: None,
                label: None,
                context_id: Some("domain-b".into()),
            },
            "test",
        )
        .await
        .expect("create domain-b-key");
        sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &other_tenant,
            &own.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
            "test",
        )
        .await
        .expect("a caller signs with a key in their own context");
    }

    /// An **unscoped** key (no `context_id`) is super-admin-only (#805).
    ///
    /// Such a key has no context, so it has no context policy to constrain it —
    /// the resource-bound guardrail that binds even a super-admin simply does
    /// not apply. That makes the role floor the only thing standing between a
    /// scoped caller and an unconstrained signer, which is why it is asserted
    /// rather than assumed.
    #[tokio::test]
    async fn sign_payload_restricts_unscoped_keys_to_super_admin() {
        let h = TestHarness::new().await;
        let admin = h.super_admin_auth();

        let key = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit,
            &h.acl_ks,
            &admin,
            CreateKeyParams {
                internal: false,
                key_type: KeyType::Ed25519,
                derivation_path: Some("m/26'/2'/99'/0'".into()),
                key_id: Some("unscoped-key".into()),
                mnemonic: None,
                label: None,
                // No context — hence the explicit path (a context would
                // otherwise supply its own base path).
                context_id: None,
            },
            "test",
        )
        .await
        .expect("create unscoped-key");

        // A context-scoped admin is *not* a super-admin (its list is non-empty),
        // so it is refused — the `ActScope` distinction, not a role comparison.
        let scoped = AuthClaims {
            did: "did:key:z6MkScopedStaff".to_string(),
            role: Role::Admin,
            allowed_contexts: vec!["some-ctx".to_string()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        assert!(!scoped.is_super_admin());

        let denied = sign_payload(
            &h.keys_ks,
            &h.internal_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &scoped,
            &key.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
            "test",
        )
        .await;
        assert!(
            matches!(denied, Err(crate::error::AppError::Forbidden(_))),
            "a scoped caller must not sign with an unscoped key, got {denied:?}"
        );

        sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &admin,
            &key.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
            "test",
        )
        .await
        .expect("super-admin may use an unscoped key");
    }

    /// The other half: an internal key must actually be usable. A key nobody
    /// can export *and* nobody can sign with is just a liability.
    #[tokio::test]
    async fn an_internal_key_signs_through_the_oracle() {
        let h = TestHarness::new().await;
        let created = mint_internal(&h, "k-sign").await;
        assert_eq!(created.origin, keys::KeyOrigin::Internal);
        assert_eq!(
            created.derivation_path, "internal",
            "an internal key records no BIP-32 path — there is nothing to derive"
        );

        let sig = sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &h.super_admin_auth(),
            "k-sign",
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
            "test",
        )
        .await
        .expect("an internal key must be usable for signing");
        assert!(!sig.signature.is_empty());
    }

    /// An internal key has no derivation path, so it cannot be named after one.
    /// Refusing here beats minting an unrecoverable key under a generated id
    /// the operator never chose and may not record.
    #[tokio::test]
    async fn an_internal_key_requires_an_explicit_key_id() {
        let h = TestHarness::new().await;
        let err = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit,
            &h.acl_ks,
            &h.super_admin_auth(),
            CreateKeyParams {
                internal: true,
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: None,
                mnemonic: None,
                label: None,
                context_id: None,
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("explicit key_id")),
            "{err:?}"
        );
    }

    /// VTI-VTA-003 / VTI-VTA-007: `sign` is the capability to use a key through
    /// the generic oracle. An entry narrowed without it is refused opaque
    /// signing — which, before, the role floor let straight through.
    #[tokio::test]
    async fn vti_vta_007_opaque_signing_without_sign_is_refused() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-sign").await;
        let auth = h.context_admin_auth();

        sign_as(&h, &auth, "k-sign", SigningDomain::Opaque)
            .await
            .expect("an un-narrowed admin derives sign");

        store_narrowed(&h, &auth, vec![Capability::KeyExport]).await;
        let err = sign_as(&h, &auth, "k-sign", SigningDomain::Opaque)
            .await
            .expect_err("narrowed away, sign is gone");
        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("sign capability")),
            "{err:?}"
        );
        // Before the lookup: an id that does not exist is refused the same way.
        let absent = sign_as(&h, &auth, "k-none", SigningDomain::Opaque)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), absent.to_string());
    }

    /// VTI-VTA-007 the other way round: a constrained grant must not need the
    /// general one. Protocol-defined input is built inside the VTA by an
    /// operation that applied its own capability, so `sign` is not demanded.
    #[tokio::test]
    async fn vti_vta_007_protocol_defined_signing_does_not_need_sign() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-room").await;
        let auth = h.context_admin_auth();
        store_narrowed(&h, &auth, vec![Capability::CredentialWrite]).await;

        sign_as(&h, &auth, "k-room", SigningDomain::ProtocolDefined)
            .await
            .expect("a credential-write grant signs its own documents without sign");
    }

    /// The ephemeral oracles take caller bytes too, so they need `sign` — even
    /// from a super-admin, when its entry was narrowed without it.
    #[tokio::test]
    async fn derive_and_sign_without_sign_is_refused() {
        let h = TestHarness::new().await;
        let auth = h.super_admin_auth();
        store_narrowed(&h, &auth, vec![Capability::KeyExport]).await;

        let err = derive_and_sign(
            &h.keys_ks,
            &h.acl_ks,
            &h.seed_store,
            &auth,
            &h.audit,
            &KeyType::Ed25519,
            "m/26'/9'/0'",
            b"hello",
            &SignAlgorithm::EdDSA,
            "test",
        )
        .await
        .expect_err("no sign");
        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("sign capability")),
            "{err:?}"
        );

        let err = derive_and_sign_document(
            &h.keys_ks,
            &h.acl_ks,
            &h.seed_store,
            &auth,
            &h.audit,
            &KeyType::Ed25519,
            "m/26'/9'/0'",
            serde_json::json!({ "a": 1 }),
            None,
            "test",
        )
        .await
        .expect_err("no sign");
        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("sign capability")),
            "{err:?}"
        );
    }

    /// The signature verifies over the SSHSIG signed data — and over nothing
    /// the caller sent. That is the property that makes `sign-sshsig` safe to
    /// grant where `sign` is not.
    #[tokio::test]
    async fn sign_sshsig_verifies_as_sshsig_and_as_nothing_else() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use vta_sdk::protocols::key_management::sign_sshsig::signed_data;

        let h = TestHarness::new().await;
        let key = mint_derived(&h, "git-key").await;
        let auth = git_signer(&h).await;
        let digest = [0x5Au8; 64];

        let out = sshsig(&h, &h.audit, &auth, "git-key", &digest)
            .await
            .expect("a sign-sshsig holder signs");
        assert_eq!(out.algorithm, SignAlgorithm::EdDSA);

        let (_, pk) = multibase::decode(&key.public_key).expect("multibase public key");
        let vk = VerifyingKey::from_bytes(pk[2..].try_into().unwrap()).unwrap();
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&out.signature)
            .unwrap();
        let sig = Signature::from_slice(&sig).unwrap();
        vk.verify(&signed_data("git", "sha512", &digest), &sig)
            .expect("verifies over the SSHSIG signed data");
        assert!(
            vk.verify(&digest, &sig).is_err(),
            "not over the bare digest"
        );
        assert!(
            vk.verify(&signed_data("file", "sha512", &digest), &sig)
                .is_err(),
            "not under another namespace"
        );
    }

    /// The narrowing holds: a commit signer cannot reach the general oracle.
    #[tokio::test]
    async fn a_sign_sshsig_entry_cannot_use_the_generic_oracle() {
        let h = TestHarness::new().await;
        mint_derived(&h, "git-key").await;
        let auth = git_signer(&h).await;
        let denied = sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &auth,
            "git-key",
            b"anything at all",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
            "test",
        )
        .await;
        assert!(
            matches!(denied, Err(AppError::Forbidden(ref m)) if m.contains("sign capability")),
            "{denied:?}"
        );
    }

    /// `sign` confers strictly more, so the spec lets a custodian accept it;
    /// an entry with neither is refused before any key is looked up.
    #[tokio::test]
    async fn sign_sshsig_takes_either_capability_and_refuses_neither() {
        let h = TestHarness::new().await;
        mint_derived(&h, "git-key").await;
        let auth = git_signer(&h).await;

        store_narrowed(&h, &auth, vec![Capability::Sign]).await;
        sshsig(&h, &h.audit, &auth, "git-key", &[1u8; 64])
            .await
            .expect("sign is accepted in place of sign-sshsig");

        store_narrowed(&h, &auth, vec![Capability::VaultRead]).await;
        let denied = sshsig(&h, &h.audit, &auth, "no-such-key", &[1u8; 64]).await;
        assert!(
            matches!(denied, Err(SshsigRefusal::App(AppError::Forbidden(ref m))) if m.contains("sign-sshsig")),
            "refused at the capability gate, before the key is looked up: {denied:?}"
        );
    }

    /// The two refusals the specification declares codes for.
    #[tokio::test]
    async fn sign_sshsig_declared_refusals() {
        let h = TestHarness::new().await;
        mint_derived(&h, "git-key").await;
        let auth = git_signer(&h).await;

        let short = sshsig(&h, &h.audit, &auth, "git-key", &[1u8; 32]).await;
        assert!(
            matches!(short, Err(SshsigRefusal::InvalidArgument(_))),
            "a sha256-length digest under sha512: {short:?}"
        );

        let mut record: KeyRecord = h
            .keys_ks
            .get(keys::store_key("git-key"))
            .await
            .unwrap()
            .unwrap();
        record.status = KeyStatus::Revoked;
        h.keys_ks
            .insert(keys::store_key("git-key"), &record)
            .await
            .unwrap();
        let revoked = sshsig(&h, &h.audit, &auth, "git-key", &[1u8; 64]).await;
        assert!(
            matches!(revoked, Err(SshsigRefusal::KeyNotActive(_))),
            "{revoked:?}"
        );
    }

    /// One row per signature, under its own action, naming the namespace and
    /// the digest — what a post-compromise review asks for.
    #[tokio::test]
    async fn sign_sshsig_audits_namespace_and_digest() {
        let h = TestHarness::new().await;
        mint_derived(&h, "git-key").await;
        let auth = git_signer(&h).await;
        let sink = recording_sink(false);
        let audit: vta_audit::SharedAuditSink = sink.clone();

        sshsig(&h, &audit, &auth, "git-key", &[7u8; 64])
            .await
            .expect("signs");

        let rows = sink.rows.lock().await;
        let signed: Vec<_> = rows
            .iter()
            .filter(|r| r.action.starts_with("keys.sign"))
            .collect();
        assert_eq!(signed.len(), 1, "exactly one signing row: {rows:?}");
        assert_eq!(signed[0].action, "keys.sign-sshsig");
        assert_eq!(signed[0].resource.as_deref(), Some("git-key"));
        let detail = signed[0].detail.as_deref().unwrap_or_default();
        assert!(detail.starts_with("namespace=git sha512="), "{detail}");
    }

    /// A JWS from a P-256 and an Ed25519 key: `alg` from the key, the header
    /// the producer asked for, and a signature that verifies under the key.
    #[tokio::test]
    async fn sign_jws_signs_a_jws_that_verifies_under_the_key() {
        let h = TestHarness::new().await;
        let auth = verifier(&h, vec![Capability::SignJws]).await;
        for (key_id, key_type, want_alg) in [
            ("verifier-p256", KeyType::P256, "ES256"),
            ("verifier-ed", KeyType::Ed25519, "EdDSA"),
        ] {
            let record = mint_of_type(&h, key_id, key_type).await;
            let (token, alg) = jws(
                &h,
                &h.audit,
                &auth,
                key_id,
                serde_json::json!({ "typ": "oauth-authz-req+jwt", "kid": "did:example:v#key-1" }),
                serde_json::json!({ "nonce": "n-1", "iat": 1_791_709_200 }),
            )
            .await
            .expect("a sign-jws holder signs");
            assert_eq!(alg, want_alg);
            let claims = record_key(&record)
                .verify_compact(&token)
                .expect("verifies");
            assert_eq!(claims["nonce"], "n-1");
            let header: serde_json::Value = serde_json::from_slice(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(token.split('.').next().unwrap())
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                header,
                serde_json::json!({ "alg": want_alg, "typ": "oauth-authz-req+jwt", "kid": "did:example:v#key-1" })
            );
        }
    }

    /// `sign` does not authorize either task here — this VTA frames
    /// `keys/sign` payloads, so `sign` is a grant that cannot yield a JWS or a
    /// certificate request — and each narrowed grant reaches only its own task.
    #[tokio::test]
    async fn protocol_signing_takes_its_own_capability_only() {
        let h = TestHarness::new().await;
        mint_of_type(&h, "verifier-p256", KeyType::P256).await;
        let subject = serde_json::json!({ "subject": [{ "type": "CN", "value": "Verifier" }] });

        let auth = verifier(&h, vec![Capability::Sign]).await;
        let denied = jws(
            &h,
            &h.audit,
            &auth,
            "verifier-p256",
            serde_json::json!({}),
            serde_json::json!({}),
        )
        .await;
        assert!(
            matches!(denied, Err(ProtocolSignRefusal::App(AppError::Forbidden(ref m))) if m.contains("sign-jws")),
            "{denied:?}"
        );
        let denied = csr(&h, &h.audit, &auth, "verifier-p256", subject.clone()).await;
        assert!(
            matches!(denied, Err(ProtocolSignRefusal::App(AppError::Forbidden(ref m))) if m.contains("sign-csr")),
            "{denied:?}"
        );

        let auth = verifier(&h, vec![Capability::SignJws]).await;
        let denied = csr(&h, &h.audit, &auth, "verifier-p256", subject.clone()).await;
        assert!(matches!(
            denied,
            Err(ProtocolSignRefusal::App(AppError::Forbidden(_)))
        ));
        let denied = sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &auth,
            "verifier-p256",
            b"anything at all",
            &SignAlgorithm::ES256,
            SigningDomain::Opaque,
            "test",
        )
        .await;
        assert!(matches!(denied, Err(AppError::Forbidden(_))), "{denied:?}");

        let auth = verifier(&h, vec![Capability::SignCsr]).await;
        csr(&h, &h.audit, &auth, "verifier-p256", subject)
            .await
            .expect("a sign-csr holder gets a request");
    }

    /// The refusals `keys/sign-jws/0.1` declares a code for.
    #[tokio::test]
    async fn sign_jws_declared_refusals() {
        use crate::operations::sign_formats::FormatRefusal;
        let h = TestHarness::new().await;
        let record = mint_of_type(&h, "verifier-p256", KeyType::P256).await;
        let other = mint_of_type(&h, "other-p256", KeyType::P256).await;
        mint_of_type(&h, "agreement", KeyType::X25519).await;
        let auth = verifier(&h, vec![Capability::SignJws]).await;
        let sign = |key: &'static str, header: serde_json::Value| {
            jws(
                &h,
                &h.audit,
                &auth,
                key,
                header,
                serde_json::json!({ "a": 1 }),
            )
        };

        let forbidden = sign("verifier-p256", serde_json::json!({ "alg": "none" })).await;
        assert!(
            matches!(forbidden, Err(ProtocolSignRefusal::Format(FormatRefusal::HeaderMemberForbidden(ref m))) if m == "alg"),
            "{forbidden:?}"
        );
        let wrong_cert = sign(
            "verifier-p256",
            serde_json::json!({ "x5c": [x5c_for(&other)] }),
        )
        .await;
        assert!(
            matches!(
                wrong_cert,
                Err(ProtocolSignRefusal::Format(FormatRefusal::InvalidArgument(
                    _
                )))
            ),
            "{wrong_cert:?}"
        );
        let (token, _) = sign(
            "verifier-p256",
            serde_json::json!({ "x5c": [x5c_for(&record)] }),
        )
        .await
        .expect("an x5c certifying the named key is signed");
        record_key(&record).verify_compact(&token).unwrap();

        let ka = sign("agreement", serde_json::json!({})).await;
        assert!(
            matches!(
                ka,
                Err(ProtocolSignRefusal::KeyTypeUnsupported(KeyType::X25519))
            ),
            "{ka:?}"
        );

        let mut revoked = record.clone();
        revoked.status = KeyStatus::Revoked;
        h.keys_ks
            .insert(keys::store_key("verifier-p256"), &revoked)
            .await
            .unwrap();
        let inactive = sign("verifier-p256", serde_json::json!({})).await;
        assert!(
            matches!(inactive, Err(ProtocolSignRefusal::KeyNotActive(_))),
            "{inactive:?}"
        );
    }

    /// The request names what was asked, carries the key's own public key, and
    /// its signature verifies — for P-256 (the EUDI access-certificate case)
    /// and Ed25519.
    #[tokio::test]
    async fn sign_csr_builds_a_request_a_ca_accepts() {
        use x509_parser::prelude::*;
        let h = TestHarness::new().await;
        let auth = verifier(&h, vec![Capability::SignCsr]).await;
        for (key_id, key_type) in [
            ("access-p256", KeyType::P256),
            ("access-ed", KeyType::Ed25519),
        ] {
            let record = mint_of_type(&h, key_id, key_type.clone()).await;
            let (pem, public_key) = csr(
                &h,
                &h.audit,
                &auth,
                key_id,
                serde_json::json!({
                    "subject": [
                        { "type": "C", "value": "DE" },
                        { "type": "O", "value": "Example Community e.V." },
                        { "type": "organizationIdentifier", "value": "LEIXG-5299000EXAMPLE000001" },
                        { "type": "CN", "value": "Example Community Verifier" }
                    ],
                    "subjectAltNames": {
                        "dns": ["verifier.community.example"],
                        "uri": ["https://verifier.community.example"]
                    }
                }),
            )
            .await
            .expect("a request");
            assert_eq!(public_key, record.public_key);
            assert!(pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----\n"));
            assert!(pem.lines().all(|l| l.len() <= 64));

            let (_, der) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
            let (rest, req) = X509CertificationRequest::from_der(&der.contents).unwrap();
            assert!(rest.is_empty());
            req.verify_signature()
                .expect("the request's signature verifies");
            let info = &req.certification_request_info;
            assert_eq!(
                info.subject.to_string(),
                "C=DE, O=Example Community e.V., OID(2.5.4.97)=LEIXG-5299000EXAMPLE000001, CN=Example Community Verifier",
                "{key_type:?}"
            );
            let own = crate::operations::sign_formats::subject_public_key_info(
                &crate::operations::sign_formats::CsrKey::from_jws_key(&record_key(&record))
                    .unwrap(),
            );
            assert_eq!(
                info.subject_pki.raw,
                own.as_slice(),
                "the key's own public key"
            );
            let extensions: Vec<_> = req.requested_extensions().unwrap().collect();
            assert_eq!(extensions.len(), 1, "the subjectAltName alone");
            let ParsedExtension::SubjectAlternativeName(san) = extensions[0] else {
                panic!("{:?}", extensions[0]);
            };
            assert_eq!(
                san.general_names,
                vec![
                    GeneralName::DNSName("verifier.community.example"),
                    GeneralName::URI("https://verifier.community.example"),
                ]
            );
        }
    }

    /// A subject attribute that breaks the table is refused as it stands, and
    /// nothing is signed.
    #[tokio::test]
    async fn sign_csr_refuses_a_subject_it_would_have_to_repair() {
        use crate::operations::sign_formats::FormatRefusal;
        let h = TestHarness::new().await;
        mint_of_type(&h, "access-p256", KeyType::P256).await;
        let auth = verifier(&h, vec![Capability::SignCsr]).await;
        let sink = recording_sink(false);
        let audit: vta_audit::SharedAuditSink = sink.clone();
        let refused = csr(
            &h,
            &audit,
            &auth,
            "access-p256",
            serde_json::json!({ "subject": [{ "type": "CN", "value": "ok" }, { "type": "C", "value": "de" }] }),
        )
        .await;
        assert!(
            matches!(
                refused,
                Err(ProtocolSignRefusal::Format(FormatRefusal::SubjectInvalid {
                    member: "subject",
                    index: Some(1),
                    ..
                }))
            ),
            "{refused:?}"
        );
        assert!(
            sink.rows
                .lock()
                .await
                .iter()
                .all(|r| !r.action.starts_with("keys.sign"))
        );
    }

    /// One row per signature, under each task's own action, carrying the
    /// digest of what was signed and never the payload.
    #[tokio::test]
    async fn protocol_signing_audits_the_digest_not_the_payload() {
        let h = TestHarness::new().await;
        mint_of_type(&h, "verifier-p256", KeyType::P256).await;
        let auth = verifier(&h, vec![Capability::SignJws, Capability::SignCsr]).await;
        let sink = recording_sink(false);
        let audit: vta_audit::SharedAuditSink = sink.clone();

        jws(
            &h,
            &audit,
            &auth,
            "verifier-p256",
            serde_json::json!({ "typ": "oauth-authz-req+jwt" }),
            serde_json::json!({ "nonce": "secret-nonce" }),
        )
        .await
        .unwrap();
        csr(
            &h,
            &audit,
            &auth,
            "verifier-p256",
            serde_json::json!({ "subject": [{ "type": "CN", "value": "Verifier" }] }),
        )
        .await
        .unwrap();

        let rows = sink.rows.lock().await;
        let signed: Vec<_> = rows
            .iter()
            .filter(|r| r.action.starts_with("keys.sign"))
            .collect();
        assert_eq!(signed.len(), 2, "{rows:?}");
        assert_eq!(signed[0].action, "keys.sign-jws");
        let detail = signed[0].detail.as_deref().unwrap_or_default();
        assert!(
            detail.starts_with("alg=ES256 typ=oauth-authz-req+jwt sha256="),
            "{detail}"
        );
        assert!(!detail.contains("secret-nonce"));
        assert_eq!(signed[1].action, "keys.sign-csr");
        let detail = signed[1].detail.as_deref().unwrap_or_default();
        assert!(
            detail.starts_with("subject=CN=Verifier san= sha256="),
            "{detail}"
        );
    }
}
