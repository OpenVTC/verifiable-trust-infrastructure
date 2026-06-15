//! `device/*` Trust Task client methods.
//!
//! A `DeviceBinding` is the device-facing half of an `AclEntry`. These methods
//! drive the `device/*` slice through the generic trust-task dispatcher
//! ([`VtaClient::dispatch_trust_task`]) — there is no dedicated REST route.
//! They power the `pnm device …` CLI and the agent-runtime SDK.
//!
//! Registration requires the caller's DID to already be in the ACL
//! (provision-integration mints it via the `ai-agent` template); the caller
//! always acts on its **own** binding.
//!
//! The dispatcher routes the canonical `0.1` task URIs (see
//! `vta-service::trust_tasks::dispatch_table!`); the `#[allow(deprecated)]`
//! mirrors the service-side `REST_ROUTED` allowance — the `0.1` consts are
//! marked deprecated in favour of `0.2`, but `0.1` is what the VTA dispatches.
#![allow(deprecated)]

use serde_json::{Value, json};

use super::VtaClient;
use crate::error::VtaError;
use crate::trust_tasks;

/// Round-trip timeout (seconds) for device trust tasks. Device ops are cheap
/// ACL-entry mutations; 30s is generous and keeps a wedged mediator from
/// hanging a CLI invocation indefinitely.
const DEVICE_TT_TIMEOUT: u64 = 30;

impl VtaClient {
    /// `device/register/0.1` — claim a `DeviceBinding` on the caller's ACL
    /// entry. `consumer_kind` is the wire `consumerKind` object, e.g.
    /// `{ "kind": "service", "serviceKind": "ai-agent" }` for a personal AI
    /// agent. Returns the registered binding.
    pub async fn device_register(
        &self,
        consumer_kind: Value,
        display_name: &str,
        platform: Option<&str>,
        hpke_public_key: Option<&str>,
    ) -> Result<Value, VtaError> {
        let mut payload = json!({
            "consumerKind": consumer_kind,
            "displayName": display_name,
        });
        if let Some(p) = platform {
            payload["platform"] = json!(p);
        }
        if let Some(k) = hpke_public_key {
            payload["hpkePublicKey"] = json!(k);
        }
        self.dispatch_trust_task(
            trust_tasks::TASK_DEVICE_REGISTER_0_1,
            payload,
            DEVICE_TT_TIMEOUT,
        )
        .await
    }

    /// `device/heartbeat/0.1` — refresh `lastSeenAt` (and `platform` if
    /// supplied). Returns server time + any queued operations for the device.
    pub async fn device_heartbeat(&self, platform: Option<&str>) -> Result<Value, VtaError> {
        let mut payload = json!({});
        if let Some(p) = platform {
            payload["platform"] = json!(p);
        }
        self.dispatch_trust_task(
            trust_tasks::TASK_DEVICE_HEARTBEAT_0_1,
            payload,
            DEVICE_TT_TIMEOUT,
        )
        .await
    }

    /// `device/list/0.1` — list the caller's registered devices. `filters` is
    /// the wire filter object (`{}` for all); e.g.
    /// `{ "consumerKindFilter": "service", "serviceKindFilter": "ai-agent" }`.
    pub async fn device_list(&self, filters: Value) -> Result<Value, VtaError> {
        self.dispatch_trust_task(
            trust_tasks::TASK_DEVICE_LIST_0_1,
            filters,
            DEVICE_TT_TIMEOUT,
        )
        .await
    }

    /// `device/disable/0.1` — disable a device by id (the record is kept; it can
    /// no longer authenticate). The maintainer/operator kill switch.
    pub async fn device_disable(&self, device_id: &str) -> Result<Value, VtaError> {
        let payload = json!({ "deviceId": device_id });
        self.dispatch_trust_task(
            trust_tasks::TASK_DEVICE_DISABLE_0_1,
            payload,
            DEVICE_TT_TIMEOUT,
        )
        .await
    }

    /// `device/wipe/0.1` — issue a remote-wipe for a compromised/lost device.
    /// Marks the binding wiped (and disabled, so it can no longer authenticate)
    /// and records the `reason` in the audit log. `scope` is one of `cache`,
    /// `cache-and-keys`, or `full` (how aggressively the device should wipe).
    pub async fn device_wipe(
        &self,
        device_id: &str,
        reason: &str,
        scope: &str,
    ) -> Result<Value, VtaError> {
        let payload = json!({ "deviceId": device_id, "reason": reason, "scope": scope });
        self.dispatch_trust_task(
            trust_tasks::TASK_DEVICE_WIPE_0_1,
            payload,
            DEVICE_TT_TIMEOUT,
        )
        .await
    }

    /// `device/set-wake/0.1` — convey the device's opaque push `WakeHandle`
    /// (`gateway` + `handle`). The VTA records it and returns the trigger
    /// allowlist; over DIDComm it provisions the allowlist to the gateway.
    pub async fn device_set_wake(
        &self,
        gateway: &str,
        handle: &str,
        suggested_triggers: Vec<String>,
    ) -> Result<Value, VtaError> {
        let payload = json!({
            "wakeHandle": { "gateway": gateway, "handle": handle },
            "suggestedTriggers": suggested_triggers,
        });
        self.dispatch_trust_task(
            trust_tasks::TASK_DEVICE_SET_WAKE_0_1,
            payload,
            DEVICE_TT_TIMEOUT,
        )
        .await
    }
}
