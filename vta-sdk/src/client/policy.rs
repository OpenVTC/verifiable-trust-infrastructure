//! Runtime Policy Decision Point management on [`VtaClient`] — the canonical
//! `policy/*` family.
//!
//! Every method goes through `rpc_tt`, so the whole surface works over DIDComm
//! and TSP as well as REST. That is the point: the VTA whose approval rules
//! most needed editing was one that advertises no REST service at all, and the
//! previous step-up policy surface was REST-only in this SDK — an operator
//! could not so much as read the policy that was blocking them.
//!
//! # REST is not wired yet
//!
//! `rpc_tt` needs a REST request builder for its `Transport::Rest` arm, and the
//! `/policies` paths below are what the routes will be. They do **not** exist
//! on the VTA yet: this slice ships the trust-task dispatch only, and the REST
//! handlers land with the rest of the route work. A REST-transport caller gets
//! a 404 until then, which is why the CLI wrapper is transport-agnostic and
//! every test drives the trust-task path.

use super::VtaClient;
use crate::error::VtaError;
use crate::protocols::policy_management::{
    DeletePolicyBody, DeletePolicyResultBody, GetPolicyBody, GetPolicyResultBody, ListPoliciesBody,
    ListPoliciesResultBody, UpsertPolicyBody, UpsertPolicyResultBody,
};

#[cfg(feature = "client")]
impl VtaClient {
    /// `policy/list/0.2` — enumerate stored policy modules.
    pub async fn list_policies(
        &self,
        req: ListPoliciesBody,
    ) -> Result<ListPoliciesResultBody, VtaError> {
        self.rpc_tt(
            crate::trust_tasks::TASK_POLICY_LIST_0_2,
            serde_json::to_value(&req)?,
            30,
            // No `.query(&req)`: reqwest is built without default features here,
            // so query-string serialization is unavailable. Filters ride the
            // trust-task payload
        )
        .await
    }

    /// `policy/get/0.1` — read one policy module by id.
    pub async fn get_policy(&self, id: &str) -> Result<GetPolicyResultBody, VtaError> {
        let req = GetPolicyBody {
            id: id.to_string(),
            ext: None,
        };
        self.rpc_tt(
            crate::trust_tasks::TASK_POLICY_GET_0_1,
            serde_json::to_value(&req)?,
            30,
        )
        .await
    }

    /// `policy/upsert/0.2` — create or revise a policy module. Super-admin.
    ///
    /// For the declarative approvals row, build the request with
    /// [`crate::approvals::synthesize_rego`] over the rules and put the same
    /// rules in `ext`: the VTA re-derives and byte-compares, so a module built
    /// any other way is refused.
    pub async fn upsert_policy(
        &self,
        req: UpsertPolicyBody,
    ) -> Result<UpsertPolicyResultBody, VtaError> {
        self.rpc_tt(
            crate::trust_tasks::TASK_POLICY_UPSERT_0_2,
            serde_json::to_value(&req)?,
            30,
        )
        .await
    }

    /// `policy/delete/0.1` — remove a policy module. Super-admin.
    pub async fn delete_policy(
        &self,
        req: DeletePolicyBody,
    ) -> Result<DeletePolicyResultBody, VtaError> {
        let _id = req.id.clone();
        self.rpc_tt(
            crate::trust_tasks::TASK_POLICY_DELETE_0_1,
            serde_json::to_value(&req)?,
            30,
        )
        .await
    }
}
