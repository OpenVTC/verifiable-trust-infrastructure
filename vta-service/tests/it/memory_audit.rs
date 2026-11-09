//! What a VTA's audit trail says about agent memory, read back over the wire
//! the way `pnm memory history` reads it (#2116, VTI-AUD-005).

use vta_sdk::client::VtaClient;
use vta_sdk::protocols::audit_management::list::ListAuditLogsBody;
use vta_service::test_support::MockVta;

async fn signing_client(mock: &MockVta, seed: u8, role: &str, contexts: Vec<String>) -> VtaClient {
    let vta_did = mock.vta_did().to_string();
    let (identity, token) = mock
        .ctx
        .mint_signing_identity(seed, role, contexts, &vta_did)
        .await;
    let client = VtaClient::new(mock.base_url()).with_identity(identity);
    client.set_token_async(token).await;
    client
}

async fn rows(admin: &VtaClient, action: &str) -> Vec<serde_json::Value> {
    let page = admin
        .list_audit_logs(&ListAuditLogsBody {
            from: None,
            to: None,
            action: Some(action.into()),
            actor: None,
            outcome: None,
            context_id: Some("agent".into()),
            cursor: None,
            limit: Some(50),
        })
        .await
        .expect("audit list");
    page.entries
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .collect()
}

/// An agent's reads and writes are on the trail, attributed to the agent, with
/// the items named by commitment: a read says how many it returned and which,
/// a write which item — and no memory key appears anywhere.
#[tokio::test]
async fn memory_activity_reads_back_by_commitment_never_by_key() {
    let mock = MockVta::start().await;
    let agent = signing_client(&mock, 51, "application", vec!["agent".into()]).await;
    let admin = signing_client(&mock, 52, "admin", vec![]).await;

    agent
        .memory_put_versioned(
            "agent",
            "person/grace-hopper",
            "met at the conference",
            None,
        )
        .await
        .expect("put");
    agent
        .memory_get("agent", &["person/grace-hopper"])
        .await
        .expect("get");

    let put = rows(&admin, "memory.put").await;
    let get = rows(&admin, "memory.get").await;
    assert_eq!(put.len(), 1, "{put:#?}");
    assert_eq!(get.len(), 1, "{get:#?}");
    let agent_did = put[0]["actor"].as_str().unwrap().to_string();
    assert_eq!(
        get[0]["actor"],
        agent_did.as_str(),
        "attributed to the agent"
    );

    let item = put[0]["target"]
        .as_str()
        .unwrap_or_else(|| panic!("no commitment: {:#}", put[0]));
    assert!(item.starts_with("hmac-sha256:"), "{item}");
    let read = get[0]["detail"]["reason"]
        .as_str()
        .expect("what the read returned");
    assert!(read.starts_with("items=1 refs="), "{read}");
    assert!(
        read.contains(item),
        "the get names the item the put wrote: {read}"
    );

    for row in put.iter().chain(&get) {
        assert!(
            !row.to_string().contains("grace-hopper"),
            "a memory key reached the trail: {row}"
        );
    }
}
