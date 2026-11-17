//! Method-neutral DID client methods (`vta/dids/{list,get,methods/list}/0.1`):
//! what every identity a VTA holds is, whatever its method
//! (`docs/05-design-notes/did-management.md`).
//!
//! These answer *which identities* and *what is this one* once, for every
//! method. What an identity does — create, update, rotate, its log or key
//! event log, delete — stays with its method's own client methods
//! (`webvh.rs`, `webs.rs`).

use serde_json::{Value, json};
use vti_specs::vta::dids;

use super::VtaClient;
use crate::error::VtaError;
use crate::trust_tasks;

/// Round-trip timeout (seconds): reads only.
const DIDS_TT_TIMEOUT: u64 = 30;

/// The most pages [`VtaClient::list_dids`] reads before deciding the VTA is
/// misbehaving: a cursor that never ends must not spin a client. At the
/// maximum page size this is 25,000 identities.
const MAX_PAGES: usize = 50;

/// What [`VtaClient::list_dids`] is narrowed to. Every filter narrows.
#[derive(Debug, Clone, Default)]
pub struct DidListFilter {
    pub context_id: Option<String>,
    /// Method profile names: `webvh`, `scid:vh`, `webs`, `key`.
    pub methods: Option<Vec<String>>,
    pub server_id: Option<String>,
    /// `relationship`, `persona` or `service`.
    pub class: Option<String>,
    pub include_deactivated: bool,
}

impl DidListFilter {
    fn payload(&self, cursor: Option<&str>) -> Value {
        let mut p = json!({});
        let o = p.as_object_mut().expect("an object literal");
        if let Some(c) = &self.context_id {
            o.insert("contextId".into(), json!(c));
        }
        if let Some(m) = &self.methods {
            o.insert("methods".into(), json!(m));
        }
        if let Some(s) = &self.server_id {
            o.insert("serverId".into(), json!(s));
        }
        if let Some(c) = &self.class {
            o.insert("class".into(), json!(c));
        }
        if self.include_deactivated {
            o.insert("includeDeactivated".into(), json!(true));
        }
        if let Some(c) = cursor {
            o.insert("cursor".into(), json!(c));
        }
        p
    }
}

impl VtaClient {
    async fn dids_call<R: serde::de::DeserializeOwned>(
        &self,
        uri: &str,
        payload: Value,
    ) -> Result<R, VtaError> {
        let answer = self
            .dispatch_trust_task(uri, payload, DIDS_TT_TIMEOUT)
            .await?;
        serde_json::from_value(answer).map_err(|e| {
            VtaError::Protocol(format!("{uri} response does not match its schema: {e}"))
        })
    }

    /// `vta/dids/list/0.1`, one page. A page carrying `nextCursor` is not the
    /// whole listing; [`Self::list_dids`] reads to the end.
    pub async fn list_dids_page(
        &self,
        filter: &DidListFilter,
        cursor: Option<&str>,
    ) -> Result<dids::list::v0_1::Response, VtaError> {
        self.dids_call(trust_tasks::TASK_VTA_DIDS_LIST_0_1, filter.payload(cursor))
            .await
    }

    /// `vta/dids/list/0.1`, read to the end: every identity the caller may
    /// see, whatever its method. Only an absent `nextCursor` ends it.
    pub async fn list_dids(
        &self,
        filter: &DidListFilter,
    ) -> Result<Vec<dids::list::v0_1::DidSummary>, VtaError> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let page = self.list_dids_page(filter, cursor.as_deref()).await?;
            all.extend(page.dids);
            match page.next_cursor {
                Some(next) => cursor = Some(next.to_string()),
                None => return Ok(all),
            }
        }
        Err(VtaError::Protocol(format!(
            "vta/dids/list did not end after {MAX_PAGES} pages; refusing to return a partial list"
        )))
    }

    /// `vta/dids/get/0.1` — one identity's summary. `vta/dids/get:notFound`
    /// (as [`VtaError::Rejected`]) for one the VTA does not hold **or** the
    /// caller cannot see.
    pub async fn get_did(&self, did: &str) -> Result<dids::get::v0_1::DidSummary, VtaError> {
        let r: dids::get::v0_1::Response = self
            .dids_call(trust_tasks::TASK_VTA_DIDS_GET_0_1, json!({ "did": did }))
            .await?;
        Ok(r.did)
    }

    /// `vta/dids/methods/list/0.1` — the DID methods the VTA holds, lists and
    /// will create now, and the tasks that serve each.
    pub async fn did_methods(
        &self,
    ) -> Result<Vec<dids::methods::list::v0_1::MethodInfo>, VtaError> {
        let r: dids::methods::list::v0_1::Response = self
            .dids_call(trust_tasks::TASK_VTA_DIDS_METHODS_LIST_0_1, json!({}))
            .await?;
        Ok(r.methods)
    }
}
