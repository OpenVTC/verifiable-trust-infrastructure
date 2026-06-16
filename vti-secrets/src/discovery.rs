//! Secret enumeration for setup wizards.
//!
//! Lists existing secret *names* in a cloud secret manager so a setup wizard
//! can offer a "pick an existing secret or type a new name" prompt. These are
//! read-only discovery helpers — distinct from the [`SeedStore`](crate::SeedStore)
//! backends, which read/write the one configured secret at runtime.
//!
//! Homed here (rather than duplicated in each service's wizard) so the VTA and
//! VTC share one implementation and don't each carry the cloud SDKs directly.
//! Each function is gated by the same feature as its backend, and all cap the
//! result at 10k names to bound memory + keep the picker usable.

#[cfg(any(
    feature = "aws-secrets",
    feature = "gcp-secrets",
    feature = "azure-secrets"
))]
const MAX_SECRETS: usize = 10_000;

/// List all secret names in AWS Secrets Manager for the resolved region
/// (from `region` or the ambient AWS config). Paginated; capped at 10k.
#[cfg(feature = "aws-secrets")]
pub async fn list_aws_secrets(
    region: Option<&str>,
) -> Result<Vec<String>, vti_common::error::AppError> {
    use vti_common::error::AppError;

    let mut config_loader = aws_config::from_env();
    if let Some(region) = region {
        config_loader = config_loader.region(aws_config::Region::new(region.to_owned()));
    }
    let sdk_config = config_loader.load().await;
    let client = aws_sdk_secretsmanager::Client::new(&sdk_config);

    let mut names: Vec<String> = Vec::new();
    let mut next_token: Option<String> = None;
    loop {
        let mut req = client.list_secrets();
        if let Some(token) = next_token.as_ref() {
            req = req.next_token(token.clone());
        }
        let output = req
            .send()
            .await
            .map_err(|e| AppError::SecretStore(format!("AWS list_secrets failed: {e}")))?;
        names.extend(
            output
                .secret_list()
                .iter()
                .filter_map(|entry| entry.name().map(String::from)),
        );
        if names.len() >= MAX_SECRETS {
            names.truncate(MAX_SECRETS);
            break;
        }
        match output.next_token() {
            Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
            _ => break,
        }
    }
    Ok(names)
}

/// List all secret names in a GCP project's Secret Manager. The
/// `projects/<id>/secrets/` prefix is stripped so the picker shows bare
/// names. Paginated; capped at 10k.
#[cfg(feature = "gcp-secrets")]
pub async fn list_gcp_secrets(project: &str) -> Result<Vec<String>, vti_common::error::AppError> {
    use vti_common::error::AppError;

    let client = google_cloud_secretmanager_v1::client::SecretManagerService::builder()
        .build()
        .await
        .map_err(|e| AppError::SecretStore(format!("GCP Secret Manager client error: {e}")))?;
    let prefix = format!("projects/{project}/secrets/");

    let mut names: Vec<String> = Vec::new();
    let mut page_token: Option<String> = None;
    loop {
        let mut req = client
            .list_secrets()
            .set_parent(format!("projects/{project}"));
        if let Some(token) = page_token.as_ref() {
            req = req.set_page_token(token.clone());
        }
        let response = req
            .send()
            .await
            .map_err(|e| AppError::SecretStore(format!("GCP list_secrets failed: {e}")))?;
        names.extend(
            response
                .secrets
                .iter()
                .map(|s| s.name.strip_prefix(&prefix).unwrap_or(&s.name).to_owned()),
        );
        if names.len() >= MAX_SECRETS {
            names.truncate(MAX_SECRETS);
            break;
        }
        if response.next_page_token.is_empty() {
            break;
        }
        page_token = Some(response.next_page_token);
    }
    Ok(names)
}

/// List all secret names in an Azure Key Vault. Credentials resolve via
/// `DeveloperToolsCredential` (Azure CLI / Developer CLI / VS Code),
/// matching the runtime [`AzureSeedStore`](crate::seed_store::AzureSeedStore).
/// Capped at 10k.
#[cfg(feature = "azure-secrets")]
pub async fn list_azure_secrets(
    vault_url: &str,
) -> Result<Vec<String>, vti_common::error::AppError> {
    use azure_security_keyvault_secrets::{ResourceExt, SecretClient};
    use futures_util::TryStreamExt;
    use vti_common::error::AppError;

    let credential = azure_identity::DeveloperToolsCredential::new(None)
        .map_err(|e| AppError::SecretStore(format!("Azure credential error: {e}")))?;
    let client = SecretClient::new(vault_url, credential, None)
        .map_err(|e| AppError::SecretStore(format!("Azure Key Vault client error: {e}")))?;

    let mut names: Vec<String> = Vec::new();
    let mut pager = client
        .list_secret_properties(None)
        .map_err(|e| AppError::SecretStore(format!("Azure list_secret_properties failed: {e}")))?;
    while let Some(secret) = pager
        .try_next()
        .await
        .map_err(|e| AppError::SecretStore(format!("Azure list page error: {e}")))?
    {
        let id = secret
            .resource_id()
            .map_err(|e| AppError::SecretStore(format!("Azure resource_id parse error: {e}")))?;
        names.push(id.name);
        if names.len() >= MAX_SECRETS {
            break;
        }
    }
    Ok(names)
}
