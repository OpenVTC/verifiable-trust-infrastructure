//! The boot-time ACL migration (`docs/05-design-notes/vtc-admin-roles.md` §9):
//! a VTC upgraded in place over a store of pre-role ACL rows rewrites each one
//! before anything is authorized, so no administrator is locked out.
//!
//! - every legacy row maps exactly as a backup import maps it;
//! - the migration is audited once (`AclMigrated`, `Critical`), and the
//!   context-scoped administrators it left with no administrative role are
//!   raised as an `acknowledge` item for the remaining community
//!   administrators (VTI-VTC-023);
//! - a second boot does nothing;
//! - a row that cannot be mapped refuses the boot, naming the DID and the fix,
//!   and changes nothing.

use serde_json::json;

use vtc_service::acl::migrate::{BootMigration, migrate_on_boot};
use vtc_service::acl::{AdminAuthority, AdminRole, VtcRole, get_acl_entry};
use vtc_service::test_support::TestVtc;

const CA: &str = "did:key:z6MkLegacyCommunityAdmin";
const SCOPED: &str = "did:key:z6MkLegacyScopedAdmin";
const MODERATOR: &str = "did:key:z6MkLegacyModerator";
const ISSUER: &str = "did:key:z6MkLegacyIssuer";
const CUSTOM: &str = "did:key:z6MkLegacyEditor";
const MEMBER: &str = "did:key:z6MkLegacyMember";

async fn vtc() -> TestVtc {
    TestVtc::builder().with_audit(true).build().await
}

/// Write `did`'s ACL row in the pre-role shape, bytes as the old daemon did.
async fn legacy(vtc: &TestVtc, did: &str, role: &str, contexts: &[&str]) {
    let row = json!({
        "did": did,
        "role": role,
        "label": "before roles",
        "allowed_contexts": contexts,
        "created_at": 7,
        "created_by": "did:key:vtc-install",
    });
    vtc.state
        .acl_ks
        .insert_raw(
            format!("acl:{did}").into_bytes(),
            serde_json::to_vec(&row).unwrap(),
        )
        .await
        .unwrap();
}

async fn seed_legacy_store(vtc: &TestVtc) {
    legacy(vtc, CA, "admin", &[]).await;
    legacy(vtc, SCOPED, "admin", &["ctx-a"]).await;
    legacy(vtc, MODERATOR, "moderator", &[]).await;
    legacy(vtc, ISSUER, "issuer", &[]).await;
    legacy(vtc, CUSTOM, "custom:editor", &[]).await;
    legacy(vtc, MEMBER, "member", &[]).await;
}

async fn row(vtc: &TestVtc, did: &str) -> vtc_service::acl::VtcAclEntry {
    get_acl_entry(&vtc.state.acl_ks, did)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("{did} survives"))
}

async fn audit_rows(vtc: &TestVtc, variant: &str) -> Vec<vti_common::audit::AuditEnvelope> {
    vtc.state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&v).ok())
        .filter(|env| env.event.variant_name() == variant)
        .collect()
}

#[tokio::test]
async fn a_boot_over_legacy_rows_migrates_audits_and_raises_an_acknowledgement() {
    let vtc = vtc().await;
    seed_legacy_store(&vtc).await;

    let done = migrate_on_boot(&vtc.state)
        .await
        .expect("the store migrates");
    assert_eq!(
        done,
        BootMigration {
            migrated: 6,
            administrators: 3,
            lost_admin_authority: vec![SCOPED.to_string()],
        }
    );

    // Each row maps as §9 says, keeping what the old row carried.
    let ca = row(&vtc, CA).await;
    assert_eq!(ca.admin, AdminAuthority::community_admin());
    assert_eq!(ca.label.as_deref(), Some("before roles"));
    assert_eq!(ca.created_at, 7);
    let scoped = row(&vtc, SCOPED).await;
    assert_eq!(
        scoped.admin,
        AdminAuthority::none(),
        "a context label meant nothing"
    );
    assert_eq!(scoped.role, VtcRole::Admin, "the community role is kept");
    assert_eq!(
        row(&vtc, MODERATOR).await.admin.admin_role,
        Some(AdminRole::Moderator)
    );
    assert_eq!(
        row(&vtc, ISSUER).await.admin.admin_role,
        Some(AdminRole::CredentialOfficer)
    );
    assert_eq!(row(&vtc, CUSTOM).await.admin, AdminAuthority::none());
    assert_eq!(row(&vtc, MEMBER).await.admin, AdminAuthority::none());

    // One audit row, Critical, naming the counts and who lost authority.
    let audited = audit_rows(&vtc, "AclMigrated").await;
    assert_eq!(audited.len(), 1);
    assert_eq!(
        audited[0].event.severity(),
        vti_common::audit::AuditSeverity::Critical
    );
    match &audited[0].event {
        vti_common::audit::AuditEvent::AclMigrated(data) => {
            assert_eq!(data.migrated, 6);
            assert_eq!(data.administrators, 3);
            assert_eq!(data.lost_admin_authority, vec![SCOPED.to_string()]);
        }
        other => panic!("{other:?}"),
    }

    // The loss is raised for the remaining community administrators.
    assert!(
        vtc_service::admin_actions::operator_item_raised(
            &vtc.state,
            &format!("acl-migration:{SCOPED}")
        )
        .await
        .unwrap(),
        "an acknowledge item names the scoped administrator that lost authority"
    );
}

/// A second boot finds nothing in the old shape and does nothing: no write, no
/// second audit row, no second item.
#[tokio::test]
async fn a_second_boot_is_a_no_op() {
    let vtc = vtc().await;
    seed_legacy_store(&vtc).await;
    migrate_on_boot(&vtc.state).await.unwrap();
    let before = vtc.state.acl_ks.prefix_iter_raw(Vec::new()).await.unwrap();

    let again = migrate_on_boot(&vtc.state).await.unwrap();
    assert_eq!(again, BootMigration::default());
    assert_eq!(
        vtc.state.acl_ks.prefix_iter_raw(Vec::new()).await.unwrap(),
        before
    );
    assert_eq!(audit_rows(&vtc, "AclMigrated").await.len(), 1);
}

/// A store with nothing in the old shape — a fresh install — is untouched and
/// audits nothing.
#[tokio::test]
async fn a_store_already_role_based_is_untouched() {
    let vtc = vtc().await;
    crate::common::signed::seed_role(&vtc, CA, VtcRole::Admin, &[]).await;
    assert_eq!(
        migrate_on_boot(&vtc.state).await.unwrap(),
        BootMigration::default()
    );
    assert!(audit_rows(&vtc, "AclMigrated").await.is_empty());
}

/// A row that cannot be mapped refuses the boot with a message naming the DID
/// and the fix — and nothing is written, not even the rows that would map.
#[tokio::test]
async fn an_unmappable_row_refuses_the_boot_and_changes_nothing() {
    let vtc = vtc().await;
    seed_legacy_store(&vtc).await;
    const BAD: &str = "did:key:z6MkUnmappable";
    vtc.state
        .acl_ks
        .insert_raw(
            format!("acl:{BAD}").into_bytes(),
            br#"{"did":"did:key:z6MkUnmappable","role":"superuser!"}"#.to_vec(),
        )
        .await
        .unwrap();
    let before = vtc.state.acl_ks.prefix_iter_raw(Vec::new()).await.unwrap();

    let err = migrate_on_boot(&vtc.state)
        .await
        .expect_err("an unmappable row refuses the boot")
        .to_string();
    assert!(err.contains(BAD), "names the DID: {err}");
    assert!(err.contains("vtc acl remove"), "names the fix: {err}");
    assert!(err.contains("vtc acl add"), "names the fix: {err}");
    assert_eq!(
        vtc.state.acl_ks.prefix_iter_raw(Vec::new()).await.unwrap(),
        before,
        "nothing is written"
    );
    assert!(audit_rows(&vtc, "AclMigrated").await.is_empty());
}
