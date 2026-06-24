use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use vta_sdk::protocols::key_management::{
    create::CreateKeyResultBody,
    derive_and_sign::{DeriveAndSignBody, DeriveAndSignResultBody},
    derive_and_sign_document::{DeriveAndSignDocumentBody, DeriveAndSignDocumentResultBody},
    list::ListKeysResultBody,
    rename::RenameKeyResultBody,
    revoke::RevokeKeyResultBody,
    secret::GetKeySecretResultBody,
    sign::{SignAlgorithm, SignResultBody},
};
use vta_sdk::protocols::seed_management::{
    list::ListSeedsResultBody, rotate::RotateSeedResultBody,
};

use crate::auth::{AdminAuth, AuthClaims};
use crate::error::AppError;
use crate::keys::KeyRecord;
use crate::keys::KeyStatus;
use crate::keys::KeyType;
use crate::operations;
use crate::server::AppState;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateKeyRequest {
    pub key_type: KeyType,
    pub derivation_path: Option<String>,
    pub key_id: Option<String>,
    pub mnemonic: Option<String>,
    pub label: Option<String>,
    pub context_id: Option<String>,
}

/// POST /keys — create a new key record. Auth: Admin or Initiator. Context-scoped.
#[utoipa::path(
    post, path = "/keys", tag = "keys",
    security(("bearer_jwt" = [])),
    request_body = CreateKeyRequest,
    responses(
        (status = 201, description = "Key created", body = CreateKeyResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin/initiator"),
    ),
)]
pub async fn create_key(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateKeyRequest>,
) -> Result<(StatusCode, Json<CreateKeyResultBody>), AppError> {
    let result = operations::keys::create_key(
        &state.keys_ks,
        &state.contexts_ks,
        &state.seed_store,
        &state.audit_ks,
        &auth.0,
        operations::keys::CreateKeyParams {
            key_type: req.key_type,
            derivation_path: req.derivation_path,
            key_id: req.key_id,
            mnemonic: req.mnemonic,
            label: req.label,
            context_id: req.context_id,
        },
        "rest",
    )
    .await?;
    Ok((StatusCode::CREATED, Json(result)))
}

/// GET /keys/{key_id}/secret — retrieve private key material. Auth: Admin or Initiator.
#[utoipa::path(
    get, path = "/keys/{key_id}/secret", tag = "keys",
    security(("bearer_jwt" = [])),
    params(("key_id" = String, Path, description = "Key identifier")),
    responses(
        (status = 200, description = "Private key material", body = GetKeySecretResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin/initiator"),
        (status = 404, description = "Key not found"),
    ),
)]
pub async fn get_key_secret(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<GetKeySecretResultBody>, AppError> {
    let result = operations::keys::get_key_secret(
        &state.keys_ks,
        &state.imported_ks,
        &state.seed_store,
        &state.audit_ks,
        &auth.0,
        &key_id,
        "rest",
    )
    .await?;
    Ok(Json(result))
}

/// GET /keys/{key_id} — retrieve a single key record. Auth: any authenticated user.
#[utoipa::path(
    get, path = "/keys/{key_id}", tag = "keys",
    security(("bearer_jwt" = [])),
    params(("key_id" = String, Path, description = "Key identifier")),
    responses(
        (status = 200, description = "Key record", body = KeyRecord),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 404, description = "Key not found"),
    ),
)]
pub async fn get_key(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<KeyRecord>, AppError> {
    let result = operations::keys::get_key(&state.keys_ks, &auth, &key_id, "rest").await?;
    Ok(Json(result))
}

/// DELETE /keys/{key_id} — revoke/invalidate a key. Auth: Admin or Initiator.
#[utoipa::path(
    delete, path = "/keys/{key_id}", tag = "keys",
    security(("bearer_jwt" = [])),
    params(("key_id" = String, Path, description = "Key identifier")),
    responses(
        (status = 200, description = "Key revoked", body = RevokeKeyResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin/initiator"),
        (status = 404, description = "Key not found"),
    ),
)]
pub async fn invalidate_key(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<RevokeKeyResultBody>, AppError> {
    let result = operations::keys::revoke_key(
        &state.keys_ks,
        &state.imported_ks,
        &state.audit_ks,
        &auth.0,
        &key_id,
        "rest",
    )
    .await?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RenameKeyRequest {
    pub key_id: String,
}

/// PATCH /keys/{key_id} — rename a key's identifier. Auth: Admin or Initiator.
#[utoipa::path(
    patch, path = "/keys/{key_id}", tag = "keys",
    security(("bearer_jwt" = [])),
    params(("key_id" = String, Path, description = "Key identifier")),
    request_body = RenameKeyRequest,
    responses(
        (status = 200, description = "Key renamed", body = RenameKeyResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin/initiator"),
        (status = 404, description = "Key not found"),
    ),
)]
pub async fn rename_key(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(key_id): Path<String>,
    Json(req): Json<RenameKeyRequest>,
) -> Result<Json<RenameKeyResultBody>, AppError> {
    let result = operations::keys::rename_key(
        &state.keys_ks,
        &state.audit_ks,
        &auth.0,
        &key_id,
        &req.key_id,
        "rest",
    )
    .await?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListKeysQuery {
    pub offset: Option<u64>,
    pub limit: Option<u64>,
    pub status: Option<KeyStatus>,
    pub context_id: Option<String>,
}

/// GET /keys — list key records with optional filters. Auth: any authenticated user. Context-scoped.
#[utoipa::path(
    get, path = "/keys", tag = "keys",
    security(("bearer_jwt" = [])),
    params(ListKeysQuery),
    responses(
        (status = 200, description = "Key records", body = ListKeysResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
    ),
)]
pub async fn list_keys(
    auth: AuthClaims,
    State(state): State<AppState>,
    Query(query): Query<ListKeysQuery>,
) -> Result<Json<ListKeysResultBody>, AppError> {
    let result = operations::keys::list_keys(
        &state.keys_ks,
        &auth,
        operations::keys::ListKeysParams {
            offset: query.offset,
            limit: query.limit,
            status: query.status,
            context_id: query.context_id,
        },
        "rest",
    )
    .await?;
    Ok(Json(result))
}

// ── Seed endpoints ────────────────────────────────────────────────

/// GET /keys/seeds — list all seed records. Auth: Admin or Initiator.
#[utoipa::path(
    get, path = "/keys/seeds", tag = "keys",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Seed records", body = ListSeedsResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin/initiator"),
    ),
)]
pub async fn list_seeds(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<ListSeedsResultBody>, AppError> {
    let result = operations::seeds::list_seeds(&state.keys_ks, "rest").await?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RotateSeedRequest {
    pub mnemonic: Option<String>,
}

/// POST /keys/seeds/rotate — rotate the active seed, optionally supplying a mnemonic. Auth: Admin or Initiator.
#[utoipa::path(
    post, path = "/keys/seeds/rotate", tag = "keys",
    security(("bearer_jwt" = [])),
    request_body = RotateSeedRequest,
    responses(
        (status = 200, description = "Seed rotated", body = RotateSeedResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin/initiator"),
    ),
)]
pub async fn rotate_seed(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<RotateSeedRequest>,
) -> Result<Json<RotateSeedResultBody>, AppError> {
    let result = operations::seeds::rotate_seed(
        &state.keys_ks,
        &state.imported_ks,
        &state.seed_store,
        &state.audit_ks,
        &_auth.0.did,
        req.mnemonic.as_deref(),
        "rest",
    )
    .await?;
    Ok(Json(result))
}

// ── Sign endpoint ─────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SignRequest {
    pub payload: String,
    pub algorithm: SignAlgorithm,
}

/// POST /keys/{key_id}/sign — sign a base64url payload with the specified key. Auth: Application or higher.
#[utoipa::path(
    post, path = "/keys/{key_id}/sign", tag = "keys",
    security(("bearer_jwt" = [])),
    params(("key_id" = String, Path, description = "Key identifier")),
    request_body = SignRequest,
    responses(
        (status = 200, description = "Signature", body = SignResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 404, description = "Key not found"),
    ),
)]
pub async fn sign_with_key(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(key_id): Path<String>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResultBody>, AppError> {
    auth.require_write()?;
    use base64::Engine;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.payload)
        .map_err(|e| AppError::Validation(format!("invalid base64url payload: {e}")))?;

    let result = operations::keys::sign_payload(
        &state.keys_ks,
        &state.imported_ks,
        &state.contexts_ks,
        &state.seed_store,
        &auth,
        &key_id,
        &payload,
        &req.algorithm,
        "rest",
    )
    .await?;
    Ok(Json(result))
}

/// POST /keys/derive-and-sign — ephemerally derive a key at a BIP-32 path, sign a
/// base64url payload, and return `{ public_key, signature }` without persisting a
/// key record. Auth: admin.
#[utoipa::path(
    post, path = "/keys/derive-and-sign", tag = "keys",
    security(("bearer_jwt" = [])),
    request_body = DeriveAndSignBody,
    responses(
        (status = 200, description = "Derived public key + signature", body = DeriveAndSignResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn derive_and_sign_key(
    auth: AuthClaims,
    State(state): State<AppState>,
    Json(req): Json<DeriveAndSignBody>,
) -> Result<Json<DeriveAndSignResultBody>, AppError> {
    auth.require_admin()?;
    use base64::Engine;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.payload)
        .map_err(|e| AppError::Validation(format!("invalid base64url payload: {e}")))?;

    let result = operations::keys::derive_and_sign(
        &state.keys_ks,
        &state.seed_store,
        &auth,
        &req.key_type,
        &req.derivation_path,
        &payload,
        &req.algorithm,
        "rest",
    )
    .await?;
    Ok(Json(result))
}

/// POST /keys/derive-and-sign-document — derive a key at a BIP-32 path and
/// attach an `eddsa-jcs-2022` Data-Integrity proof to the document, signed as
/// the derived key, without persisting a key record. Auth: admin.
#[utoipa::path(
    post, path = "/keys/derive-and-sign-document", tag = "keys",
    security(("bearer_jwt" = [])),
    request_body = DeriveAndSignDocumentBody,
    responses(
        (status = 200, description = "Signer DID + DI-signed document", body = DeriveAndSignDocumentResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn derive_and_sign_document_key(
    auth: AuthClaims,
    State(state): State<AppState>,
    Json(req): Json<DeriveAndSignDocumentBody>,
) -> Result<Json<DeriveAndSignDocumentResultBody>, AppError> {
    auth.require_admin()?;
    let result = operations::keys::derive_and_sign_document(
        &state.keys_ks,
        &state.seed_store,
        &auth,
        &req.key_type,
        &req.derivation_path,
        req.document,
        req.proof_purpose.as_deref(),
        "rest",
    )
    .await?;
    Ok(Json(result))
}

// ── Import key endpoints ─────────────────────────────────────────

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct WrappingKeyResponse {
    pub kid: String,
    pub kty: String,
    pub crv: String,
    pub x: String,
}

/// GET /keys/import/wrapping-key — get an ephemeral X25519 public key for REST key wrapping.
#[utoipa::path(
    get, path = "/keys/import/wrapping-key", tag = "keys",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Ephemeral wrapping public key", body = WrappingKeyResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn get_wrapping_key(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<WrappingKeyResponse>, AppError> {
    let (kid, x) = state.wrapping_cache.generate().await;
    Ok(Json(WrappingKeyResponse {
        kid,
        kty: "OKP".into(),
        crv: "X25519".into(),
        x,
    }))
}

/// REST `POST /keys/import` request body.
///
/// **The plaintext `private_key_multibase` shape is deliberately not
/// accepted here.** Posting raw key material over a session-bearer-
/// authenticated REST call relies entirely on TLS for confidentiality
/// — the key is decrypted by the TLS terminator before the VTA sees
/// it, which on Nitro Enclave means the host network stack reads
/// plaintext private keys out of memory.
///
/// `#[serde(deny_unknown_fields)]` is load-bearing: any client posting
/// the legacy `private_key_multibase` field gets a specific
/// `unknown field` 400, not a generic missing-field error. That
/// turns "the field is silently ignored" into "the operator gets a
/// pointer to the migration path."
///
/// Use one of:
/// - `private_key_sealed` — armored sealed-transfer bundle
///   ([`SealedPayloadV1::RawPrivateKey`]). Preferred. Fetch the
///   ephemeral wrapping pubkey from `GET /keys/import/wrapping-key`,
///   then seal locally and POST.
/// - `private_key_jwe` — legacy ECDH-ES + A256GCM compact JWE,
///   wrapped against the same ephemeral key. Retained for in-flight
///   callers; new code should pick `private_key_sealed`.
///
/// The DIDComm transport accepts `private_key_multibase` directly
/// because authcrypt already provides end-to-end confidentiality —
/// the SDK shape ([`vta_sdk::client::ImportKeyRequest`]) keeps the
/// field for that future handler.
///
/// [`SealedPayloadV1::RawPrivateKey`]:
///     vta_sdk::sealed_transfer::SealedPayloadV1::RawPrivateKey
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[derive(utoipa::ToSchema)]
pub struct ImportKeyRestRequest {
    pub key_type: KeyType,
    /// Sealed-transfer armored bundle — preferred REST transport.
    pub private_key_sealed: Option<String>,
    /// Legacy JWE compact serialization. Retained for existing clients.
    pub private_key_jwe: Option<String>,
    pub label: Option<String>,
    pub context_id: Option<String>,
}

/// POST /keys/import — import an externally-created private key. Auth: Admin only.
#[utoipa::path(
    post, path = "/keys/import", tag = "keys",
    security(("bearer_jwt" = [])),
    request_body = ImportKeyRestRequest,
    responses(
        (status = 201, description = "Key imported", body = CreateKeyResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn import_key(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<ImportKeyRestRequest>,
) -> Result<(StatusCode, Json<CreateKeyResultBody>), AppError> {
    // Unwrap the private key based on transport. Sealed-transfer is
    // preferred; JWE is kept as a fallback for legacy clients. The
    // plaintext `private_key_multibase` path is intentionally not
    // accepted here — see [`ImportKeyRestRequest`] doc comment.
    let private_key_bytes = if let Some(sealed) = req.private_key_sealed.as_deref() {
        let (sealed_type, bytes) = state.wrapping_cache.unwrap_sealed(sealed).await?;
        if sealed_type != req.key_type.to_string() {
            return Err(AppError::Validation(format!(
                "sealed key_type `{sealed_type}` does not match request key_type `{}`",
                req.key_type
            )));
        }
        bytes
    } else if let Some(jwe) = req.private_key_jwe {
        tracing::warn!(
            "key import via legacy JWE path — prefer private_key_sealed (sealed-transfer)"
        );
        state.wrapping_cache.unwrap_jwe(&jwe).await?
    } else {
        return Err(AppError::Validation(
            "one of private_key_sealed or private_key_jwe is required; raw \
             private_key_multibase over REST is not accepted (TLS-only \
             confidentiality is insufficient — use the GET /keys/import/wrapping-key \
             ECDH flow)"
                .into(),
        ));
    };

    let result = operations::keys::import_key(
        &state.keys_ks,
        &state.imported_ks,
        &state.seed_store,
        &state.audit_ks,
        &auth.0,
        operations::keys::ImportKeyParams {
            key_type: req.key_type,
            private_key_bytes,
            label: req.label,
            context_id: req.context_id,
        },
        "rest",
    )
    .await?;
    Ok((StatusCode::CREATED, Json(result)))
}
