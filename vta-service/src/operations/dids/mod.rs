//! Method-neutral DID management: what every identity this VTA holds is,
//! whatever its method (`docs/05-design-notes/did-management.md`).
//!
//! A [`DidEngine`] is what holds identities of one kind, keyed by **how their
//! authority is kept** rather than by the DID string's prefix: the webvh log
//! engine serves `did:webvh` and its `did:scid:vh:1` form, the KERI engine
//! serves `did:webs`, and the key engine serves the `did:key` identities this
//! VTA minted. [`engines`] is the one list of them, and [`for_did`] the one
//! place a DID is matched to its engine.
//!
//! The questions answered here are the ones whose answer means the same for
//! every method — which identities, in which context, the VTA's key ids for
//! them, whether one is its context's DID. What an identity *does* (create,
//! update, rotate, delete, its log or key event log) stays with its method's
//! own operations.

pub mod primary;

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::auth::AuthClaims;
use crate::operations::persona::{PersonaStores, Relationship};

/// One identity, as every method has it (`vta/dids/_shared/0.2`
/// `DidSummary`; CONVENTIONS.md §20.3).
///
/// Built by the engines and turned into a task's generated response type at
/// the handler, which checks it against the schema on the way out.
#[derive(Debug, Clone, PartialEq)]
pub struct DidSummary {
    /// As presented.
    pub did: String,
    /// The method profile's name: `webvh`, `scid:vh`, `webs`, `key`.
    pub method: &'static str,
    pub context_id: Option<String>,
    /// The DID class it was created in; `None` where none was recorded.
    pub class: Option<&'static str>,
    /// Key assurance level. Every identity an engine here holds is level 1:
    /// none of them is a key-role identity yet (key-roles plan).
    pub level: u8,
    pub primary: bool,
    pub deactivated: bool,
    pub server_id: Option<String>,
    pub label: Option<String>,
    pub signing_key_id: Option<String>,
    pub key_agreement_key_id: Option<String>,
    pub also_known_as: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// The method profile's Summary details, the inner object only.
    pub method_details: Option<Map<String, Value>>,
}

impl DidSummary {
    /// The wire form: the `DidSummary` definition's members, `methodDetails`
    /// keyed by `method`.
    pub fn to_value(&self) -> Value {
        let mut v = json!({
            "did": self.did,
            "method": self.method,
            "level": self.level,
            "primary": self.primary,
            "deactivated": self.deactivated,
            "alsoKnownAs": self.also_known_as,
            "createdAt": self.created_at.to_rfc3339(),
            "updatedAt": self.updated_at.to_rfc3339(),
        });
        let o = v.as_object_mut().expect("an object literal");
        let mut put = |k: &str, val: &Option<String>| {
            if let Some(val) = val {
                o.insert(k.to_string(), json!(val));
            }
        };
        put("contextId", &self.context_id);
        put("serverId", &self.server_id);
        put("label", &self.label);
        put("signingKeyId", &self.signing_key_id);
        put("keyAgreementKeyId", &self.key_agreement_key_id);
        if let Some(class) = self.class {
            o.insert("class".into(), json!(class));
        }
        if let Some(details) = &self.method_details {
            o.insert(
                "methodDetails".into(),
                json!({ self.method: Value::Object(details.clone()) }),
            );
        }
        v
    }
}

/// What a listing is narrowed to (`vta/dids/list/0.1`). Every filter narrows,
/// and they combine as a conjunction.
#[derive(Debug, Clone, Default)]
pub struct DidFilter {
    pub context_id: Option<String>,
    pub methods: Option<Vec<String>>,
    pub server_id: Option<String>,
    pub class: Option<String>,
    pub include_deactivated: bool,
}

impl DidFilter {
    fn matches(&self, s: &DidSummary) -> bool {
        self.context_id
            .as_deref()
            .is_none_or(|c| s.context_id.as_deref() == Some(c))
            && self
                .methods
                .as_ref()
                .is_none_or(|m| m.iter().any(|m| m == s.method))
            && self
                .server_id
                .as_deref()
                .is_none_or(|id| s.server_id.as_deref() == Some(id))
            && self.class.as_deref().is_none_or(|c| s.class == Some(c))
            && (self.include_deactivated || !s.deactivated)
    }
}

/// The stores an engine reads. Borrowed from the running service, or from a
/// test's own keyspaces.
#[derive(Clone, Copy)]
pub struct DidStores<'a> {
    pub keys_ks: &'a KeyspaceHandle,
    pub contexts_ks: &'a KeyspaceHandle,
    #[cfg(feature = "webvh")]
    pub webvh_ks: &'a KeyspaceHandle,
    pub webs_ks: &'a KeyspaceHandle,
}

impl<'a> DidStores<'a> {
    pub fn from_state(state: &'a crate::server::AppState) -> Self {
        Self {
            keys_ks: &state.keys_ks,
            contexts_ks: &state.contexts_ks,
            #[cfg(feature = "webvh")]
            webvh_ks: &state.webvh_ks,
            webs_ks: &state.webs_ks,
        }
    }

    fn persona(&self) -> PersonaStores<'a> {
        PersonaStores {
            keys_ks: self.keys_ks,
            #[cfg(feature = "webvh")]
            webvh_ks: self.webvh_ks,
            #[cfg(feature = "webs")]
            webs_ks: self.webs_ks,
        }
    }
}

/// Which context names which DID as its own, read once per answer.
struct Primaries(HashMap<String, String>);

impl Primaries {
    async fn load(contexts_ks: &KeyspaceHandle) -> Result<Self, AppError> {
        Ok(Self(
            crate::contexts::list_contexts(contexts_ks)
                .await?
                .into_iter()
                .filter_map(|c| c.did.map(|did| (did, c.id)))
                .collect(),
        ))
    }

    /// Whether any of `forms` is a context's DID. A did:scid identity is its
    /// context's DID in either of its forms.
    fn any(&self, forms: &[&str]) -> bool {
        forms.iter().any(|f| self.0.contains_key(*f))
    }
}

/// Whether `auth` may see an identity in `context` (CONVENTIONS.md §20.2): an
/// identity in no context is reachable by an unrestricted caller only.
pub fn reachable(auth: &AuthClaims, context: Option<&str>) -> bool {
    match context {
        Some(ctx) => auth.has_context_access(ctx),
        None => auth.is_super_admin(),
    }
}

/// One DID method this VTA holds a profile for, as it supports it now
/// (`MethodInfo`).
#[derive(Debug, Clone, PartialEq)]
pub struct MethodInfo {
    pub method: &'static str,
    pub listed: bool,
    pub creatable: bool,
    pub classes: Vec<&'static str>,
    pub operations: Vec<&'static str>,
}

impl MethodInfo {
    pub fn to_value(&self) -> Value {
        json!({
            "method": self.method,
            "listed": self.listed,
            "creatable": self.creatable,
            "classes": self.classes,
            "operations": self.operations,
        })
    }
}

/// What holds identities of one kind.
#[async_trait]
pub trait DidEngine: Send + Sync {
    /// The method profile names this engine's identities are summarised under.
    fn methods(&self) -> &'static [&'static str];

    /// Whether `did`, in any form it is given out as, is this engine's kind.
    /// Says nothing about whether the VTA holds it.
    fn owns(&self, did: &str) -> bool;

    /// Every identity of this engine that `auth` may reach.
    async fn summaries(
        &self,
        stores: DidStores<'_>,
        auth: &AuthClaims,
    ) -> Result<Vec<DidSummary>, AppError>;

    /// The identity `did` names, in either form, if the VTA holds it and
    /// `auth` may reach it.
    async fn summary(
        &self,
        stores: DidStores<'_>,
        auth: &AuthClaims,
        did: &str,
    ) -> Result<Option<DidSummary>, AppError> {
        Ok(self
            .summaries(stores, auth)
            .await?
            .into_iter()
            .find(|s| s.did == did || s.also_known_as.iter().any(|a| a == did)))
    }

    /// The DIDs of this engine recorded against `context_id`, by the handle
    /// the engine's own operations take, whoever asks. For a deletion's
    /// preview and cascade.
    async fn context_dids(
        &self,
        stores: DidStores<'_>,
        context_id: &str,
    ) -> Result<Vec<String>, AppError>;

    /// How this VTA supports the engine's methods now.
    fn info(&self, config: &vta_config::AppConfig) -> Vec<MethodInfo>;
}

/// Every engine this build has, in a stable order.
// Each push is gated on a feature, which a `vec![]` literal cannot express.
#[allow(clippy::vec_init_then_push)]
pub fn engines() -> Vec<&'static dyn DidEngine> {
    let mut all: Vec<&'static dyn DidEngine> = Vec::new();
    #[cfg(feature = "webvh")]
    all.push(&WebvhEngine);
    #[cfg(feature = "webs")]
    all.push(&WebsEngine);
    all.push(&KeyEngine);
    all
}

/// The engine whose kind `did` is, if this build has one.
pub fn for_did(did: &str) -> Option<&'static dyn DidEngine> {
    engines().into_iter().find(|e| e.owns(did))
}

/// Every identity `auth` may see, filtered and sorted by DID.
pub async fn list(
    stores: DidStores<'_>,
    auth: &AuthClaims,
    filter: &DidFilter,
) -> Result<Vec<DidSummary>, AppError> {
    let mut all = Vec::new();
    for engine in engines() {
        if let Some(methods) = &filter.methods
            && !engine
                .methods()
                .iter()
                .any(|m| methods.iter().any(|f| f == m))
        {
            continue;
        }
        all.extend(engine.summaries(stores, auth).await?);
    }
    all.retain(|s| filter.matches(s));
    all.sort_by(|a, b| a.did.cmp(&b.did));
    Ok(all)
}

/// One identity, or `None` for one the VTA holds no record of **and** for one
/// `auth` cannot reach — indistinguishably (CONVENTIONS.md §20.2).
pub async fn get(
    stores: DidStores<'_>,
    auth: &AuthClaims,
    did: &str,
) -> Result<Option<DidSummary>, AppError> {
    match for_did(did) {
        Some(engine) => engine.summary(stores, auth, did).await,
        None => Ok(None),
    }
}

/// Every DID recorded against `context_id`, of every engine, by the handle
/// its own operations take.
pub async fn context_dids(
    stores: DidStores<'_>,
    context_id: &str,
) -> Result<Vec<(&'static dyn DidEngine, String)>, AppError> {
    let mut out = Vec::new();
    for engine in engines() {
        for did in engine.context_dids(stores, context_id).await? {
            out.push((engine, did));
        }
    }
    Ok(out)
}

/// The methods this VTA holds, as it supports them now.
pub fn methods(config: &vta_config::AppConfig) -> Vec<MethodInfo> {
    engines().into_iter().flat_map(|e| e.info(config)).collect()
}

/// The VTA's id for the key `did` signs with, through the persona oracle the
/// VTA already uses to act as an identity — the one rule for "which key is
/// this DID's", rather than a second per-method copy of it.
async fn signing_key_id(
    stores: DidStores<'_>,
    auth: &AuthClaims,
    did: &str,
) -> Result<Option<String>, AppError> {
    Ok(crate::operations::persona::persona_key_for(
        stores.persona(),
        auth,
        did,
        Relationship::AssertionMethod,
    )
    .await?
    .map(|k| k.key_id))
}

// ─── did:webvh and its did:scid:vh:1 form ────────────────────────────────

/// The webvh log engine: `did:webvh` logs, presented as themselves or as their
/// `did:scid:vh:1` form.
#[cfg(feature = "webvh")]
pub struct WebvhEngine;

#[cfg(feature = "webvh")]
impl WebvhEngine {
    async fn summarise(
        &self,
        stores: DidStores<'_>,
        auth: &AuthClaims,
        record: vta_sdk::webvh::WebvhDidRecord,
        scid: Option<&crate::webvh_store::ScidIdentity>,
        primaries: &Primaries,
    ) -> Result<DidSummary, AppError> {
        let (did, method, also_known_as) = match scid {
            Some(s) if s.presented => (s.scid_did.clone(), "scid:vh", vec![s.webvh_did.clone()]),
            Some(s) if s.alias_listed => (record.did.clone(), "webvh", vec![s.scid_did.clone()]),
            _ => (record.did.clone(), "webvh", Vec::new()),
        };
        let mut forms = vec![record.did.as_str()];
        if let Some(s) = scid {
            forms.push(s.scid_did.as_str());
        }
        let key_agreement_key_id = key_agreement_from_document(stores, &record.did).await?;
        let mut details = Map::new();
        details.insert("scid".into(), json!(record.scid));
        if record.server_id != "serverless" {
            details.insert("mnemonic".into(), json!(record.mnemonic));
        }
        details.insert("portable".into(), json!(record.portable));
        details.insert("logEntryCount".into(), json!(record.log_entry_count));
        details.insert("preRotationCount".into(), json!(record.pre_rotation_count));
        Ok(DidSummary {
            signing_key_id: signing_key_id(stores, auth, &record.did).await?,
            key_agreement_key_id,
            did,
            method,
            context_id: Some(record.context_id.clone()),
            class: None,
            level: 1,
            primary: primaries.any(&forms),
            // The VTA ends a did:webvh by deleting it (`webvh/dids/delete`), so
            // every log it still holds is live.
            deactivated: false,
            server_id: (record.server_id != "serverless").then(|| record.server_id.clone()),
            label: None,
            also_known_as,
            created_at: record.created_at,
            updated_at: record.updated_at,
            method_details: Some(details),
        })
    }
}

/// The VTA's id for the first key the identity's current document lists under
/// `keyAgreement`, where the VTA holds that key.
#[cfg(feature = "webvh")]
async fn key_agreement_from_document(
    stores: DidStores<'_>,
    did: &str,
) -> Result<Option<String>, AppError> {
    let Some(doc) = crate::operations::persona::own_document(stores.persona(), did).await? else {
        return Ok(None);
    };
    let Some(first) = doc
        .get("keyAgreement")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
    else {
        return Ok(None);
    };
    let id = match first {
        Value::String(s) => s.clone(),
        Value::Object(o) => match o.get("id").and_then(Value::as_str) {
            Some(s) => s.to_string(),
            None => return Ok(None),
        },
        _ => return Ok(None),
    };
    let id = if id.starts_with('#') {
        format!("{did}{id}")
    } else {
        id
    };
    let held: Option<vta_sdk::keys::KeyRecord> =
        stores.keys_ks.get(vta_keys::store_key(&id)).await?;
    Ok(held.map(|r| r.key_id))
}

#[cfg(feature = "webvh")]
#[async_trait]
impl DidEngine for WebvhEngine {
    fn methods(&self) -> &'static [&'static str] {
        &["webvh", "scid:vh"]
    }

    fn owns(&self, did: &str) -> bool {
        did.starts_with("did:webvh:") || vta_sdk::did_scid::is_scid(did)
    }

    async fn summaries(
        &self,
        stores: DidStores<'_>,
        auth: &AuthClaims,
    ) -> Result<Vec<DidSummary>, AppError> {
        let scids: HashMap<String, crate::webvh_store::ScidIdentity> =
            crate::webvh_store::list_scid_identities(stores.webvh_ks)
                .await?
                .into_iter()
                .map(|s| (s.webvh_did.clone(), s))
                .collect();
        let primaries = Primaries::load(stores.contexts_ks).await?;
        let mut out = Vec::new();
        for record in crate::webvh_store::list_dids(stores.webvh_ks).await? {
            if !reachable(auth, Some(&record.context_id)) {
                continue;
            }
            let scid = scids.get(&record.did);
            out.push(
                self.summarise(stores, auth, record, scid, &primaries)
                    .await?,
            );
        }
        Ok(out)
    }

    async fn summary(
        &self,
        stores: DidStores<'_>,
        auth: &AuthClaims,
        did: &str,
    ) -> Result<Option<DidSummary>, AppError> {
        let Some(log_did) = crate::webvh_store::log_did_for(stores.webvh_ks, did).await? else {
            return Ok(None);
        };
        let Some(record) = crate::webvh_store::get_did(stores.webvh_ks, &log_did).await? else {
            return Ok(None);
        };
        if !reachable(auth, Some(&record.context_id)) {
            return Ok(None);
        }
        let scid = crate::webvh_store::list_scid_identities(stores.webvh_ks)
            .await?
            .into_iter()
            .find(|s| s.webvh_did == log_did);
        let primaries = Primaries::load(stores.contexts_ks).await?;
        Ok(Some(
            self.summarise(stores, auth, record, scid.as_ref(), &primaries)
                .await?,
        ))
    }

    async fn context_dids(
        &self,
        stores: DidStores<'_>,
        context_id: &str,
    ) -> Result<Vec<String>, AppError> {
        Ok(crate::webvh_store::list_dids(stores.webvh_ks)
            .await?
            .into_iter()
            .filter(|r| r.context_id == context_id)
            .map(|r| r.did)
            .collect())
    }

    fn info(&self, _config: &vta_config::AppConfig) -> Vec<MethodInfo> {
        use vta_sdk::trust_tasks as t;
        let operations = vec![
            t::TASK_WEBVH_DIDS_CREATE_1_2,
            t::TASK_WEBVH_DIDS_GET_1_0,
            t::TASK_WEBVH_DIDS_UPDATE_1_1,
            t::TASK_WEBVH_DIDS_ROTATE_KEYS_1_0,
            t::TASK_WEBVH_DIDS_REALIGN_KEYS_1_0,
            t::TASK_WEBVH_DIDS_REGISTER_WITH_SERVER_1_0,
            t::TASK_WEBVH_DIDS_DELETE_1_0,
        ];
        ["webvh", "scid:vh"]
            .into_iter()
            .map(|method| MethodInfo {
                method,
                listed: true,
                creatable: true,
                classes: Vec::new(),
                operations: operations.clone(),
            })
            .collect()
    }
}

// ─── did:webs ─────────────────────────────────────────────────────────────

/// The KERI engine: `did:webs` identities and their key event logs.
#[cfg(feature = "webs")]
pub struct WebsEngine;

#[cfg(feature = "webs")]
impl WebsEngine {
    fn summarise(
        record: crate::webs_store::WebsDidRecord,
        primaries: &Primaries,
    ) -> Result<DidSummary, AppError> {
        let domain = record.domain.clone().unwrap_or_default();
        // The aliases the AID designates for itself in its own stream — the
        // record keeps none of its own.
        let kels = affinidi_did_webs::Kels::parse(&record.keri_cesr)
            .map_err(|e| AppError::Internal(format!("read the stream of {}: {e}", record.did)))?;
        let also_known_as = affinidi_did_webs::designated_aliases(&kels, &record.aid)
            .map_err(|e| AppError::Internal(format!("read the aliases of {}: {e}", record.did)))?
            .aliases;
        let mut details = Map::new();
        details.insert("aid".into(), json!(record.aid));
        details.insert("slot".into(), json!(record.mnemonic));
        details.insert("domain".into(), json!(domain));
        details.insert("sequenceNumber".into(), json!(record.state.sn));
        details.insert(
            "keriCesrUrl".into(),
            json!(format!("https://{domain}/{}/keri.cesr", record.mnemonic)),
        );
        details.insert(
            "didJsonUrl".into(),
            json!(format!("https://{domain}/{}/did.json", record.mnemonic)),
        );
        let parse = |s: &str| {
            DateTime::parse_from_rfc3339(s)
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or_default()
        };
        Ok(DidSummary {
            primary: primaries.any(&[record.did.as_str()]),
            did: record.did.clone(),
            method: "webs",
            context_id: Some(record.context_id.clone()),
            class: record.did_class.map(|c| c.as_str()),
            level: 1,
            deactivated: record.deactivated,
            server_id: Some(record.server_id.clone()),
            label: record.label.clone(),
            // The key a client signs in with as this DID. For a key-role
            // identity that is its `operational` key, the one its document
            // lists under `authentication`; the key event log's own key
            // (`record.signing_key_id`) is in no relationship there, and a
            // proof naming it is refused (VTI-KEY-072).
            signing_key_id: (!record.deactivated).then(|| {
                record
                    .operational_key_id
                    .clone()
                    .unwrap_or_else(|| record.signing_key_id.clone())
            }),
            key_agreement_key_id: (!record.deactivated)
                .then(|| record.key_agreement_key_id.clone()),
            also_known_as,
            created_at: parse(&record.created_at),
            updated_at: parse(&record.updated_at),
            method_details: Some(details),
        })
    }
}

#[cfg(feature = "webs")]
#[async_trait]
impl DidEngine for WebsEngine {
    fn methods(&self) -> &'static [&'static str] {
        &["webs"]
    }

    fn owns(&self, did: &str) -> bool {
        did.starts_with("did:webs:")
    }

    async fn summaries(
        &self,
        stores: DidStores<'_>,
        auth: &AuthClaims,
    ) -> Result<Vec<DidSummary>, AppError> {
        let primaries = Primaries::load(stores.contexts_ks).await?;
        crate::webs_store::list(stores.webs_ks)
            .await?
            .into_iter()
            .filter(|r| reachable(auth, Some(&r.context_id)))
            .map(|r| Self::summarise(r, &primaries))
            .collect()
    }

    async fn summary(
        &self,
        stores: DidStores<'_>,
        auth: &AuthClaims,
        did: &str,
    ) -> Result<Option<DidSummary>, AppError> {
        let Some(record) = crate::webs_store::get(stores.webs_ks, did).await? else {
            return Ok(None);
        };
        if !reachable(auth, Some(&record.context_id)) {
            return Ok(None);
        }
        let primaries = Primaries::load(stores.contexts_ks).await?;
        Self::summarise(record, &primaries).map(Some)
    }

    async fn context_dids(
        &self,
        stores: DidStores<'_>,
        context_id: &str,
    ) -> Result<Vec<String>, AppError> {
        Ok(
            crate::webs_store::list_by_context(stores.webs_ks, context_id)
                .await?
                .into_iter()
                .map(|r| r.did)
                .collect(),
        )
    }

    fn info(&self, config: &vta_config::AppConfig) -> Vec<MethodInfo> {
        use vta_sdk::trust_tasks as t;
        let creatable = config.dids.webs_enabled;
        let mut classes = Vec::new();
        if creatable {
            classes.extend(["relationship", "persona"]);
            if config.dids.webs_service_dids {
                classes.push("service");
            }
        }
        vec![MethodInfo {
            method: "webs",
            listed: true,
            creatable,
            classes,
            operations: vec![
                t::TASK_VTA_WEBS_DIDS_CREATE_0_2,
                t::TASK_VTA_WEBS_DIDS_GET_0_1,
                t::TASK_VTA_WEBS_DIDS_UPDATE_0_1,
                t::TASK_VTA_WEBS_DIDS_ROTATE_KEYS_0_1,
                t::TASK_VTA_WEBS_DIDS_DELETE_0_1,
            ],
        }]
    }
}

// ─── did:key ──────────────────────────────────────────────────────────────

/// The key engine: a `did:key` this VTA minted, held as the key record whose
/// id is the DID's own `did:key:<mb>#<mb>` (`vta_keys::derive_and_store_did_key`).
pub struct KeyEngine;

const DID_KEY_RECORDS: &str = "key:did:key:";

impl KeyEngine {
    /// The DID a key record is, if it is a `did:key`'s own key, active.
    fn did_of(record: &vta_sdk::keys::KeyRecord) -> Option<String> {
        let (did, fragment) = record.key_id.split_once('#')?;
        let id = did.strip_prefix("did:key:")?;
        (id == fragment && record.status == vta_sdk::keys::KeyStatus::Active)
            .then(|| did.to_string())
    }

    fn summarise(
        record: vta_sdk::keys::KeyRecord,
        did: String,
        primaries: &Primaries,
    ) -> DidSummary {
        DidSummary {
            primary: primaries.any(&[did.as_str()]),
            did,
            method: "key",
            context_id: record.context_id.clone(),
            class: None,
            level: 1,
            deactivated: false,
            server_id: None,
            label: record.label.clone(),
            signing_key_id: Some(record.key_id.clone()),
            key_agreement_key_id: None,
            also_known_as: Vec::new(),
            created_at: record.created_at,
            updated_at: record.updated_at,
            method_details: None,
        }
    }

    async fn records(
        keys_ks: &KeyspaceHandle,
    ) -> Result<Vec<(vta_sdk::keys::KeyRecord, String)>, AppError> {
        let mut out = Vec::new();
        for (_, value) in keys_ks.prefix_iter_raw(DID_KEY_RECORDS).await? {
            let record: vta_sdk::keys::KeyRecord = serde_json::from_slice(&value)?;
            if let Some(did) = Self::did_of(&record) {
                out.push((record, did));
            }
        }
        Ok(out)
    }
}

#[async_trait]
impl DidEngine for KeyEngine {
    fn methods(&self) -> &'static [&'static str] {
        &["key"]
    }

    fn owns(&self, did: &str) -> bool {
        did.starts_with("did:key:")
    }

    async fn summaries(
        &self,
        stores: DidStores<'_>,
        auth: &AuthClaims,
    ) -> Result<Vec<DidSummary>, AppError> {
        let primaries = Primaries::load(stores.contexts_ks).await?;
        Ok(Self::records(stores.keys_ks)
            .await?
            .into_iter()
            .filter(|(r, _)| reachable(auth, r.context_id.as_deref()))
            .map(|(r, did)| Self::summarise(r, did, &primaries))
            .collect())
    }

    async fn summary(
        &self,
        stores: DidStores<'_>,
        auth: &AuthClaims,
        did: &str,
    ) -> Result<Option<DidSummary>, AppError> {
        let Some(id) = did.strip_prefix("did:key:") else {
            return Ok(None);
        };
        if id.contains('#') {
            return Ok(None);
        }
        let record: Option<vta_sdk::keys::KeyRecord> = stores
            .keys_ks
            .get(vta_keys::store_key(&format!("{did}#{id}")))
            .await?;
        let Some(record) = record else {
            return Ok(None);
        };
        let Some(own) = Self::did_of(&record) else {
            return Ok(None);
        };
        if !reachable(auth, record.context_id.as_deref()) {
            return Ok(None);
        }
        let primaries = Primaries::load(stores.contexts_ks).await?;
        Ok(Some(Self::summarise(record, own, &primaries)))
    }

    async fn context_dids(
        &self,
        stores: DidStores<'_>,
        context_id: &str,
    ) -> Result<Vec<String>, AppError> {
        Ok(Self::records(stores.keys_ks)
            .await?
            .into_iter()
            .filter(|(r, _)| r.context_id.as_deref() == Some(context_id))
            .map(|(_, did)| did)
            .collect())
    }

    fn info(&self, _config: &vta_config::AppConfig) -> Vec<MethodInfo> {
        vec![MethodInfo {
            method: "key",
            listed: true,
            // Minted by provisioning and setup, never by a create task.
            creatable: false,
            classes: Vec::new(),
            operations: Vec::new(),
        }]
    }
}

#[cfg(test)]
mod tests;
