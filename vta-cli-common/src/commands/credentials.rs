use vta_sdk::prelude::*;
use vta_sdk::sealed_transfer::SealedPayloadV1;

use super::acl::validate_role;
use crate::local_keygen::generate_admin_did_key;
use crate::sealed_producer::{SealedRecipient, emit_sealed_output, seal_for_recipient};

pub async fn cmd_auth_credential_create(
    client: &VtaClient,
    role: String,
    label: Option<String>,
    contexts: Vec<String>,
    recipient: SealedRecipient,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_role(&role)?;

    // Fetch VTA metadata for the credential bundle.
    let config = client.get_config().await?;
    let vta_did = config
        .vta_did()
        .map(str::to_string)
        .ok_or("VTA DID not configured — cannot mint credential")?;
    let vta_url = config.public_url().map(str::to_string);

    // Mint locally, then register the did:key via POST /acl. The private key
    // never crosses the wire — it reaches the recipient only via the sealed
    // bundle below.
    let (bundle, did) = generate_admin_did_key(vta_did, vta_url);
    let mut acl_req =
        vta_sdk::client::CreateAclRequest::new(&did, &role).contexts(contexts.clone());
    if let Some(l) = label {
        acl_req = acl_req.label(l);
    }
    client.create_acl(acl_req).await?;

    let sealed = seal_for_recipient(
        &recipient,
        &SealedPayloadV1::AdminCredential(Box::new(bundle)),
    )
    .await?;

    println!("Credentials generated:");
    println!("  DID:  {did}");
    println!("  Role: {role}");
    if !contexts.is_empty() {
        println!("  Contexts: {}", contexts.join(", "));
    }
    if let Some(ref rlabel) = recipient.label {
        println!("  Recipient: {rlabel}");
    }
    println!();
    emit_sealed_output(&sealed, None)?;
    Ok(())
}
