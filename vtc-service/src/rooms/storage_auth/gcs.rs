//! `gcs` configs on `ambient` or `sealed` authentication
//! (`vtc/storage/configs/create/0.2`, "Room-scoped credentials", rule 4 and the
//! paragraph on `sealed`).
//!
//! A **source token** — the machine's own (application default credentials, minted
//! for the operator's `[rooms.files.auth] gcs_service_account` with a 900-second
//! lifetime where one is named), or one minted from a sealed service-account key
//! against Google's own token endpoint, never a `token_uri` the key file names — is
//! exchanged at Google's Security Token Service for a **downscoped** token under a
//! Credential Access Boundary: one rule, the config's bucket, only the predefined
//! object roles the operation needs, and an availability condition naming the
//! room's prefix, built by a CEL builder that quotes its literals ([`cel_string`]).
//!
//! Objects are then read and written through `object_store`, one store per access,
//! each presenting only its own downscoped token ([`GcsRoomStore`]).

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use object_store::ObjectStore;
use object_store::gcp::{GcpCredential, GoogleCloudStorageBuilder};
use serde_json::{Value, json};
use vti_common::blob_store::object::ObjectStoreBlobs;
use vti_common::blob_store::{BackendRef, BlobKey, BlobStore, Deletion, Health};
use vti_common::error::AppError;
use zeroize::Zeroizing;

use super::{Access, CredentialCache, Held, Scope, scrub_provider_error};

/// Google's Security Token Service.
pub const STS_TOKEN_URL: &str = "https://sts.googleapis.com/v1/token";
/// Google's OAuth 2.0 token endpoint: where a sealed key's assertion goes, whatever
/// the key file says.
pub const OAUTH_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// Whether `s` reads as a service-account email (`name@project.iam.gserviceaccount.com`
/// or any `local@domain`): no whitespace, one `@`.
pub fn is_service_account(s: &str) -> bool {
    let mut parts = s.split('@');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(l), Some(d), None) if !l.is_empty() && d.contains('.')
    ) && !s.chars().any(char::is_whitespace)
        && s.len() <= 320
}

/// A CEL string literal for `s`: single-quoted, with `\`, `'`, and every control
/// character escaped — so no value can close the literal and add an expression.
pub fn cel_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

/// The predefined object roles of one [`Access`] (rule 4). A write reads first —
/// a content address already stored is not written again — so it carries the viewer
/// role beside the creator's; a delete has no narrower predefined role than
/// `objectUser`.
pub fn roles(access: Access) -> &'static [&'static str] {
    match access {
        Access::Read => &["inRole:roles/storage.objectViewer"],
        Access::Write => &[
            "inRole:roles/storage.objectViewer",
            "inRole:roles/storage.objectCreator",
        ],
        Access::Delete => &["inRole:roles/storage.objectUser"],
    }
}

/// The Credential Access Boundary for one bucket, object prefix and access (rules 4,
/// 5): a JSON document whose one condition is a CEL expression built by
/// [`cel_string`].
pub fn access_boundary(bucket: &str, object_prefix: &str, access: Access) -> Value {
    let resource_name = format!("projects/_/buckets/{bucket}/objects/{object_prefix}");
    json!({
        "accessBoundary": {
            "accessBoundaryRules": [{
                "availableResource": format!("//storage.googleapis.com/projects/_/buckets/{bucket}"),
                "availablePermissions": roles(access),
                "availabilityCondition": {
                    "expression": format!("resource.name.startsWith({})", cel_string(&resource_name)),
                },
            }],
        },
    })
}

/// Where source tokens come from.
#[async_trait]
pub trait SourceToken: Send + Sync {
    /// A source token and, when known, its expiry.
    async fn token(&self) -> Result<(Zeroizing<String>, Option<DateTime<Utc>>), String>;
}

/// `ambient`: application default credentials — impersonating the operator's named
/// service account with a 900-second lifetime when there is one.
pub struct AmbientSource {
    service_account: Option<String>,
    creds: tokio::sync::OnceCell<google_cloud_auth::credentials::AccessTokenCredentials>,
}

impl AmbientSource {
    pub fn new(service_account: Option<String>) -> Self {
        Self {
            service_account,
            creds: tokio::sync::OnceCell::new(),
        }
    }
}

#[async_trait]
impl SourceToken for AmbientSource {
    async fn token(&self) -> Result<(Zeroizing<String>, Option<DateTime<Utc>>), String> {
        use google_cloud_auth::credentials::{Builder, impersonated};
        let creds = self
            .creds
            .get_or_try_init(|| async {
                match &self.service_account {
                    None => Builder::default()
                        .build_access_token_credentials()
                        .map_err(|e| scrub_provider_error(&e.to_string())),
                    Some(sa) => {
                        let source = Builder::default()
                            .build()
                            .map_err(|e| scrub_provider_error(&e.to_string()))?;
                        impersonated::Builder::from_source_credentials(source)
                            .with_target_principal(sa)
                            .with_lifetime(std::time::Duration::from_secs(
                                super::REQUESTED_LIFETIME_SECS as u64,
                            ))
                            .build_access_token_credentials()
                            .map_err(|e| scrub_provider_error(&e.to_string()))
                    }
                }
            })
            .await?;
        let t = creds
            .access_token()
            .await
            .map_err(|e| scrub_provider_error(&e.to_string()))?;
        // The library does not say when it expires; [`super::stop_at`] holds it to
        // 15 minutes from now either way.
        Ok((Zeroizing::new(t.token), None))
    }
}

/// `sealed`: a service-account key, exchanged at Google's own token endpoint for an
/// access token through the JWT-bearer grant (RFC 7523).
pub struct ServiceAccountSource {
    client_email: String,
    private_key_id: String,
    private_key: Zeroizing<String>,
    token_url: String,
    http: reqwest::Client,
}

impl ServiceAccountSource {
    /// From the key's three members that matter; the rest of the file is ignored,
    /// `token_uri` included.
    pub fn new(
        client_email: &str,
        private_key_id: &str,
        private_key: &str,
        http: reqwest::Client,
    ) -> Self {
        Self {
            client_email: client_email.to_string(),
            private_key_id: private_key_id.to_string(),
            private_key: Zeroizing::new(private_key.to_string()),
            token_url: OAUTH_TOKEN_URL.to_string(),
            http,
        }
    }

    /// Point at a stand-in token endpoint, for tests.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_token_url(mut self, url: &str) -> Self {
        self.token_url = url.to_string();
        self
    }

    /// The signed assertion: RS256, for Google's token endpoint, 15 minutes.
    fn assertion(&self) -> Result<Zeroizing<String>, String> {
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        let now = Utc::now().timestamp();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.private_key_id.clone());
        let claims = json!({
            "iss": self.client_email,
            "scope": CLOUD_PLATFORM_SCOPE,
            "aud": OAUTH_TOKEN_URL,
            "iat": now,
            "exp": now + i64::from(super::REQUESTED_LIFETIME_SECS),
        });
        let key = EncodingKey::from_rsa_pem(self.private_key.as_bytes())
            .map_err(|_| "the service-account key's private_key is not an RSA PEM key")?;
        encode(&header, &claims, &key)
            .map(Zeroizing::new)
            .map_err(|_| "the service-account assertion could not be signed".to_string())
    }
}

#[async_trait]
impl SourceToken for ServiceAccountSource {
    async fn token(&self) -> Result<(Zeroizing<String>, Option<DateTime<Utc>>), String> {
        let assertion = self.assertion()?;
        let res = self
            .http
            .post(&self.token_url)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(|e| scrub_provider_error(&e.without_url().to_string()))?;
        token_response(res, "the token endpoint").await
    }
}

/// An OAuth token response's `access_token` and expiry; a refusal's `error` only,
/// never its body.
async fn token_response(
    res: reqwest::Response,
    from: &str,
) -> Result<(Zeroizing<String>, Option<DateTime<Utc>>), String> {
    let status = res.status();
    let body: Value = res
        .json()
        .await
        .map_err(|_| format!("{from} answered {status} with no JSON"))?;
    if !status.is_success() {
        let error = body["error"].as_str().unwrap_or("unknown");
        return Err(format!(
            "{from} refused ({status}): {}",
            scrub_provider_error(error)
        ));
    }
    let token = body["access_token"]
        .as_str()
        .ok_or_else(|| format!("{from} answered with no access_token"))?;
    let expiry = body["expires_in"]
        .as_i64()
        .map(|s| Utc::now() + chrono::Duration::seconds(s));
    Ok((Zeroizing::new(token.to_string()), expiry))
}

/// Where a config's objects are.
#[derive(Debug, Clone)]
pub struct GcsTarget {
    pub config_id: String,
    pub bucket: String,
    /// `""` or ending `/`.
    pub prefix: String,
}

impl GcsTarget {
    pub fn from_settings(config_id: &str, settings: &Value) -> Result<Self, String> {
        Ok(Self {
            config_id: config_id.to_string(),
            bucket: settings["bucket"]
                .as_str()
                .ok_or("a gcs config names no bucket")?
                .to_string(),
            prefix: settings["prefix"].as_str().unwrap_or_default().to_string(),
        })
    }
}

/// One `gcs` config's backend.
pub struct GcsBackend {
    target: GcsTarget,
    source: Arc<dyn SourceToken>,
    sts_url: String,
    http: reqwest::Client,
    cache: CredentialCache<Arc<GcpCredential>>,
    stores: Mutex<HashMap<Scope, Arc<dyn BlobStore>>>,
    /// Object stores built for each access, in tests.
    #[cfg(any(test, feature = "test-support"))]
    test_stores: Option<Arc<dyn Fn(Access) -> Arc<dyn ObjectStore> + Send + Sync>>,
}

impl GcsBackend {
    pub fn new(target: GcsTarget, source: Arc<dyn SourceToken>, http: reqwest::Client) -> Self {
        Self {
            target,
            source,
            sts_url: STS_TOKEN_URL.to_string(),
            http,
            cache: CredentialCache::default(),
            stores: Mutex::new(HashMap::new()),
            #[cfg(any(test, feature = "test-support"))]
            test_stores: None,
        }
    }

    /// A stand-in STS, for tests.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_sts_url(mut self, url: &str) -> Self {
        self.sts_url = url.to_string();
        self
    }

    /// Stand-in object stores, for tests.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_test_stores(
        mut self,
        f: Arc<dyn Fn(Access) -> Arc<dyn ObjectStore> + Send + Sync>,
    ) -> Self {
        self.test_stores = Some(f);
        self
    }

    pub fn rooms_holding(&self) -> usize {
        self.cache.rooms_holding(Utc::now())
    }

    /// A downscoped token for `(scope, access)`, minted when none is held. Never the
    /// source token in its place (rule 8).
    pub async fn token(&self, scope: &Scope, access: Access) -> Result<Arc<GcpCredential>, String> {
        let now = Utc::now();
        if let Some(held) = self.cache.get(scope, access, now) {
            return Ok(held.credential);
        }
        let (source, source_expiry) = self.source.token().await?;
        let boundary = access_boundary(
            &self.target.bucket,
            &scope.object_prefix(&self.target.prefix),
            access,
        );
        let options = serde_json::to_string(&boundary).expect("JSON serialises");
        let res = self
            .http
            .post(&self.sts_url)
            .form(&[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                (
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:access_token",
                ),
                (
                    "requested_token_type",
                    "urn:ietf:params:oauth:token-type:access_token",
                ),
                ("subject_token", source.as_str()),
                ("options", options.as_str()),
            ])
            .send()
            .await
            .map_err(|e| scrub_provider_error(&e.without_url().to_string()))?;
        let (token, expiry) = token_response(res, "Google's Security Token Service").await?;
        // A downscoped token inherits its source's expiry.
        let expiry = match (expiry, source_expiry) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let held = Held {
            credential: Arc::new(GcpCredential {
                bearer: token.to_string(),
            }),
            stop_at: super::stop_at(now, expiry),
        };
        tracing::info!(
            config = %self.target.config_id,
            scope = scope.tag(),
            access = ?access,
            expires = %held.stop_at,
            "room-scoped storage credential issued"
        );
        self.cache.put(scope.clone(), access, held.clone());
        Ok(held.credential)
    }

    fn object_store(
        self: &Arc<Self>,
        scope: &Scope,
        access: Access,
    ) -> Result<Arc<dyn ObjectStore>, AppError> {
        #[cfg(any(test, feature = "test-support"))]
        if let Some(f) = &self.test_stores {
            return Ok(f(access));
        }
        let provider = Arc::new(ScopedToken {
            backend: self.clone(),
            scope: scope.clone(),
            access,
        });
        let store = GoogleCloudStorageBuilder::new()
            .with_bucket_name(&self.target.bucket)
            .with_credentials(provider)
            .build()
            .map_err(|e| AppError::Config(format!("GCS store: {e}")))?;
        Ok(Arc::new(store))
    }

    /// The store for `scope`: one `object_store` per access, each with only its own
    /// downscoped token.
    pub fn store(self: &Arc<Self>, scope: Scope) -> Result<Arc<dyn BlobStore>, AppError> {
        let mut stores = self.stores.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(s) = stores.get(&scope) {
            return Ok(s.clone());
        }
        let prefix = (!self.target.prefix.is_empty()).then_some(self.target.prefix.as_str());
        let at = |access| -> Result<ObjectStoreBlobs, AppError> {
            Ok(ObjectStoreBlobs::new(
                "gcs",
                self.object_store(&scope, access)?,
                prefix,
            ))
        };
        let store: Arc<dyn BlobStore> = Arc::new(GcsRoomStore {
            scope_prefix: scope.object_prefix(""),
            read: at(Access::Read)?,
            write: at(Access::Write)?,
            delete: at(Access::Delete)?,
        });
        if stores.len() >= 4096 {
            stores.clear();
        }
        stores.insert(scope, store.clone());
        Ok(store)
    }
}

/// `object_store`'s credential hook, answering with one scope's downscoped token.
struct ScopedToken {
    backend: Arc<GcsBackend>,
    scope: Scope,
    access: Access,
}

impl std::fmt::Debug for ScopedToken {
    // Never the token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScopedToken")
            .field("scope", &self.scope.tag())
            .field("access", &self.access)
            .finish()
    }
}

#[async_trait]
impl object_store::CredentialProvider for ScopedToken {
    type Credential = GcpCredential;

    async fn get_credential(&self) -> object_store::Result<Arc<GcpCredential>> {
        self.backend
            .token(&self.scope, self.access)
            .await
            .map_err(|why| object_store::Error::Generic {
                store: "GCS",
                source: format!("no room-scoped credential: {why}").into(),
            })
    }
}

/// One scope of a `gcs` config: reads, writes and deletes each through their own
/// store, and nothing outside the scope's prefix.
pub struct GcsRoomStore {
    /// The scope's prefix, relative to the config's.
    scope_prefix: String,
    read: ObjectStoreBlobs,
    write: ObjectStoreBlobs,
    delete: ObjectStoreBlobs,
}

impl GcsRoomStore {
    fn inside(&self, key: &BlobKey) -> Result<(), AppError> {
        if key.as_str().starts_with(&self.scope_prefix) {
            Ok(())
        } else {
            Err(AppError::Internal(format!(
                "blob `{}` lies outside the credential's scope",
                key.as_str()
            )))
        }
    }
}

#[async_trait]
impl BlobStore for GcsRoomStore {
    fn kind(&self) -> &'static str {
        "gcs"
    }

    async fn put(&self, key: &BlobKey, staged: &Path, size: u64) -> Result<BackendRef, AppError> {
        self.inside(key)?;
        self.write.put(key, staged, size).await
    }

    async fn get_range(&self, at: &BackendRef, start: u64, end: u64) -> Result<Vec<u8>, AppError> {
        self.inside(&at.key)?;
        self.read.get_range(at, start, end).await
    }

    async fn delete(&self, at: &BackendRef) -> Result<Deletion, AppError> {
        self.inside(&at.key)?;
        self.delete.delete(at).await
    }

    /// Whether a read-scoped token can be had and used: a head of an object that
    /// should not exist under the scope.
    async fn health(&self) -> Health {
        self.read.health().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn a_cel_literal_cannot_be_closed_by_its_value() {
        assert_eq!(cel_string("rooms/ab/"), "'rooms/ab/'");
        assert_eq!(cel_string("a'b"), "'a\\'b'");
        assert_eq!(cel_string("a\\'||true"), "'a\\\\\\'||true'");
        assert_eq!(cel_string("x\ny"), "'x\\ny'");
    }

    #[test]
    fn the_boundary_names_one_bucket_one_prefix_and_object_roles_only() {
        let b = access_boundary(
            "northwind-rooms",
            "tenant-'a/rooms/0123456789abcdef0123456789abcdef/",
            Access::Read,
        );
        let rules = b["accessBoundary"]["accessBoundaryRules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0]["availableResource"],
            "//storage.googleapis.com/projects/_/buckets/northwind-rooms"
        );
        assert_eq!(
            rules[0]["availablePermissions"],
            json!(["inRole:roles/storage.objectViewer"])
        );
        assert_eq!(
            rules[0]["availabilityCondition"]["expression"],
            "resource.name.startsWith('projects/_/buckets/northwind-rooms/objects/tenant-\\'a/rooms/0123456789abcdef0123456789abcdef/')"
        );
        for access in [Access::Read, Access::Write, Access::Delete] {
            for r in roles(access) {
                assert!(
                    [
                        "inRole:roles/storage.objectViewer",
                        "inRole:roles/storage.objectCreator",
                        "inRole:roles/storage.objectUser"
                    ]
                    .contains(r)
                );
            }
        }
    }

    struct Fixed;
    #[async_trait]
    impl SourceToken for Fixed {
        async fn token(&self) -> Result<(Zeroizing<String>, Option<DateTime<Utc>>), String> {
            Ok((Zeroizing::new("source-token".into()), None))
        }
    }

    /// A stand-in STS: records each exchange's options and answers a fresh token.
    async fn sts() -> (String, Arc<Mutex<Vec<Value>>>, Arc<AtomicUsize>) {
        use axum::{Form, Json, Router, extract::State, routing::post};
        type S = (Arc<Mutex<Vec<Value>>>, Arc<AtomicUsize>);
        async fn token(
            State((seen, n)): State<S>,
            Form(f): Form<HashMap<String, String>>,
        ) -> Json<Value> {
            assert_eq!(f["subject_token"], "source-token");
            assert_eq!(
                f["grant_type"],
                "urn:ietf:params:oauth:grant-type:token-exchange"
            );
            seen.lock()
                .unwrap()
                .push(serde_json::from_str(&f["options"]).unwrap());
            let i = n.fetch_add(1, Ordering::SeqCst);
            Json(json!({ "access_token": format!("downscoped-{i}"), "expires_in": 3600 }))
        }
        let state: S = (Arc::default(), Arc::default());
        let app = Router::new()
            .route("/v1/token", post(token))
            .with_state(state.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (format!("http://{addr}/v1/token"), state.0, state.1)
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap()
    }

    /// Each (room, access) is exchanged once and reused; its boundary names that
    /// room's prefix and nothing wider.
    #[tokio::test]
    async fn each_room_and_access_gets_its_own_downscoped_token() {
        let (url, seen, n) = sts().await;
        let target = GcsTarget::from_settings(
            "gcs-eu",
            &json!({"kind": "gcs", "bucket": "northwind-rooms", "prefix": "t/"}),
        )
        .unwrap();
        let b = GcsBackend::new(target, Arc::new(Fixed), client()).with_sts_url(&url);
        let a = Scope::room("did:key:zA");
        let t1 = b.token(&a, Access::Read).await.unwrap();
        let t2 = b.token(&a, Access::Read).await.unwrap();
        assert_eq!(t1.bearer, t2.bearer);
        b.token(&a, Access::Write).await.unwrap();
        b.token(&Scope::room("did:key:zB"), Access::Read)
            .await
            .unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 3);
        let seen = seen.lock().unwrap();
        let expr = seen[0]["accessBoundary"]["accessBoundaryRules"][0]["availabilityCondition"]
            ["expression"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            expr.contains(&format!("objects/{}", a.object_prefix("t/"))),
            "{expr}"
        );
        assert_eq!(b.rooms_holding(), 2);
    }

    /// The store refuses any key outside its scope, and serves one inside it.
    #[tokio::test]
    async fn a_room_store_never_reaches_another_room() {
        let mem: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let target = GcsTarget::from_settings("g", &json!({"bucket": "bkt"})).unwrap();
        let b = Arc::new(
            GcsBackend::new(target, Arc::new(Fixed), client())
                .with_test_stores(Arc::new(move |_| mem.clone())),
        );
        let store = b.store(Scope::room("did:key:zA")).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("x");
        std::fs::write(&staged, b"hello").unwrap();
        let blob = vti_common::blob_store::sha256_digest_multibase(&[3; 32]);
        let mine = BlobKey::for_room("did:key:zA", &blob).unwrap();
        let theirs = BlobKey::for_room("did:key:zB", &blob).unwrap();
        let at = store.put(&mine, &staged, 5).await.unwrap();
        assert_eq!(store.get_range(&at, 0, 5).await.unwrap(), b"hello");
        assert!(store.put(&theirs, &staged, 5).await.is_err());
    }

    /// A sealed key's assertion goes to the token endpoint it is configured with —
    /// Google's — and is RS256-signed by the key.
    #[test]
    fn a_service_account_assertion_names_googles_endpoint() {
        assert!(is_service_account(
            "rooms@northwind.iam.gserviceaccount.com"
        ));
        assert!(!is_service_account("not an email"));
        assert!(!is_service_account("a@b@c.d"));
    }
}
