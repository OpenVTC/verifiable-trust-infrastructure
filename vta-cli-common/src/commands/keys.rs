use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Cell, Row, Table},
};
use vta_sdk::prelude::*;

use crate::render::{is_full_display, print_full_entry, print_full_list_title, print_widget};

pub async fn cmd_key_create(
    client: &VtaClient,
    key_type: &str,
    derivation_path: Option<String>,
    mnemonic: Option<String>,
    label: Option<String>,
    context_id: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_type = match key_type {
        "ed25519" => KeyType::Ed25519,
        "x25519" => KeyType::X25519,
        "p256" => KeyType::P256,
        other => {
            return Err(
                format!("unknown key type '{other}', expected ed25519, x25519, or p256").into(),
            );
        }
    };
    let mut req = CreateKeyRequest::new(key_type);
    if let Some(p) = derivation_path {
        req = req.derivation_path(p);
    }
    if let Some(m) = mnemonic {
        req = req.mnemonic(m);
    }
    if let Some(l) = label {
        req = req.label(l);
    }
    if let Some(c) = context_id {
        req = req.context(c);
    }
    let resp = client.create_key(req).await?;
    println!("Key created:");
    println!("  Key ID:          {}", resp.key_id);
    println!("  Key Type:        {}", resp.key_type);
    println!("  Derivation Path: {}", resp.derivation_path);
    println!("  Public Key:      {}", resp.public_key);
    println!("  Status:          {}", resp.status);
    if let Some(label) = &resp.label {
        println!("  Label:           {label}");
    }
    println!(
        "  Created At:      {}",
        crate::duration::format_local_datetime(resp.created_at)
    );
    Ok(())
}

pub async fn cmd_key_import(
    client: &VtaClient,
    key_type: &str,
    private_key: Option<String>,
    private_key_file: Option<std::path::PathBuf>,
    label: Option<String>,
    context_id: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_type = match key_type {
        "ed25519" => KeyType::Ed25519,
        "x25519" => KeyType::X25519,
        "p256" => KeyType::P256,
        other => {
            return Err(
                format!("unknown key type '{other}', expected ed25519, x25519, or p256").into(),
            );
        }
    };

    // Read private key bytes
    let private_key_multibase = if let Some(key_str) = private_key {
        key_str
    } else if let Some(path) = private_key_file {
        let bytes = std::fs::read(&path)
            .map_err(|e| format!("failed to read key file '{}': {e}", path.display()))?;
        // If file is text (multibase), use as-is; otherwise encode as multibase
        match String::from_utf8(bytes.clone()) {
            Ok(s) if s.starts_with('z') || s.starts_with('f') || s.starts_with('u') => {
                s.trim().to_string()
            }
            _ => multibase::encode(multibase::Base::Base58Btc, &bytes),
        }
    } else {
        return Err("either --private-key or --private-key-file is required".into());
    };

    // Fetch the server's ephemeral wrapping pubkey and seal the private
    // key via sealed-transfer. The REST `POST /keys/import` handler no
    // longer accepts `private_key_multibase` (the previous fallback) —
    // posting raw key material over a TLS-only channel was rejected by
    // the April 2026 security review (patch #9). If the wrapping-key
    // fetch fails, surface the error to the operator with the cause
    // intact rather than silently downgrading to a request the server
    // would reject as `unknown field`.
    let wrapping_key = client.get_wrapping_key().await.map_err(|e| {
        format!(
            "failed to fetch ephemeral wrapping key from {}/keys/import/wrapping-key: {e} \
             — the VTA must support sealed-transfer key import (vta-sdk ≥ 0.8); \
             raw `private_key_multibase` over REST is no longer accepted",
            client.endpoint_label()
        )
    })?;
    let sealed = seal_private_key(&wrapping_key.x, &key_type, &private_key_multibase).await?;

    let req = ImportKeyRequest {
        key_type,
        private_key_sealed: Some(sealed),
        private_key_jwe: None,
        private_key_multibase: None,
        label,
        context_id,
    };
    let resp = client.import_key(req).await?;

    println!("Key imported successfully:");
    println!("  Key ID:     {}", resp.key_id);
    println!("  Key Type:   {}", resp.key_type);
    println!("  Public Key: {}", resp.public_key);
    println!("  Status:     {}", resp.status);
    println!("  Origin:     imported");
    if let Some(label) = &resp.label {
        println!("  Label:      {label}");
    }
    println!(
        "  Created At: {}",
        crate::duration::format_local_datetime(resp.created_at)
    );
    eprintln!();
    eprintln!(
        "\x1b[1;33mWarning: securely delete the source key material \u{2014} the VTA now holds this secret.\x1b[0m"
    );

    Ok(())
}

/// Seal a multibase-encoded private key to the VTA's wrapping pubkey using
/// HPKE via `vta_sdk::sealed_transfer`. Returns an armored bundle suitable
/// for the `private_key_sealed` field of `ImportKeyRequest`.
async fn seal_private_key(
    vta_pub_b64: &str,
    key_type: &KeyType,
    private_key_multibase: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use vta_sdk::sealed_transfer::{
        AssertionProof, InMemoryNonceStore, ProducerAssertion, RawPrivateKey, SealedPayloadV1,
        armor, generate_ed25519_keypair, seal_payload,
    };

    // JWK `x` is base64url-no-pad; the server encodes with URL_SAFE_NO_PAD
    // in wrapping.rs.
    let vta_pub_bytes: [u8; 32] = B64URL
        .decode(vta_pub_b64)?
        .try_into()
        .map_err(|_| "wrapping public key must be 32 bytes")?;

    let (_, key_bytes) = multibase::decode(private_key_multibase)?;

    let payload = SealedPayloadV1::RawPrivateKey(RawPrivateKey {
        key_type: key_type.to_string(),
        key_bytes_b64: B64URL.encode(&key_bytes),
    });

    // Producer identity is irrelevant here — the server trusts the request
    // because it's authenticated at the request layer, and the sealed bundle
    // is protected by HPKE bound to the server's wrapping pubkey. The
    // PinnedOnly assertion is just a placeholder for wire-format uniformity.
    let (_seed, producer_ed_pub) = generate_ed25519_keypair();
    let producer = ProducerAssertion {
        producer_did: affinidi_crypto::did_key::ed25519_pub_to_did_key(&producer_ed_pub),
        proof: AssertionProof::PinnedOnly,
    };

    let bundle_id: [u8; 16] = rand::random();

    let nonce_store = InMemoryNonceStore::new();
    let bundle = seal_payload(&vta_pub_bytes, bundle_id, producer, &payload, &nonce_store).await?;
    Ok(armor::encode(&bundle))
}

pub async fn cmd_key_get(
    client: &VtaClient,
    key_id: &str,
    secret: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if secret {
        let resp = client.get_key_secret(key_id).await?;
        println!("Key ID:               {}", resp.key_id);
        println!("Key Type:             {}", resp.key_type);
        println!("Public Key Multibase: {}", resp.public_key_multibase);
        println!("Secret Key Multibase: {}", resp.private_key_multibase);
    } else {
        let resp = client.get_key(key_id).await?;
        println!("Key ID:          {}", resp.key_id);
        println!("Key Type:        {}", resp.key_type);
        println!("Derivation Path: {}", resp.derivation_path);
        println!("Public Key:      {}", resp.public_key);
        println!("Status:          {}", resp.status);
        if let Some(label) = &resp.label {
            println!("Label:           {label}");
        }
        println!(
            "Created At:      {}",
            crate::duration::format_local_datetime(resp.created_at)
        );
        println!(
            "Updated At:      {}",
            crate::duration::format_local_datetime(resp.updated_at)
        );
    }
    Ok(())
}

pub async fn cmd_key_revoke(
    client: &VtaClient,
    key_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.invalidate_key(key_id).await?;
    println!("Key revoked:");
    println!("  Key ID:     {}", resp.key_id);
    println!("  Status:     {}", resp.status);
    println!(
        "  Updated At: {}",
        crate::duration::format_local_datetime(resp.updated_at)
    );
    Ok(())
}

pub async fn cmd_key_rename(
    client: &VtaClient,
    key_id: &str,
    new_key_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.rename_key(key_id, new_key_id).await?;
    println!("Key renamed:");
    println!("  Key ID:     {}", resp.key_id);
    println!(
        "  Updated At: {}",
        crate::duration::format_local_datetime(resp.updated_at)
    );
    Ok(())
}

pub async fn cmd_key_list(
    client: &VtaClient,
    offset: u64,
    limit: u64,
    status: Option<String>,
    context_id: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .list_keys(offset, limit, status.as_deref(), context_id.as_deref())
        .await?;

    if crate::render::is_json_output() {
        crate::render::print_json(&resp)?;
        return Ok(());
    }

    if resp.keys.is_empty() {
        println!("No keys found.");
        return Ok(());
    }

    let end = (offset + resp.keys.len() as u64).min(resp.total);

    if is_full_display() {
        print_full_list_title(
            &format!("Keys (showing {}..{} of {}", offset + 1, end, resp.total),
            resp.keys.len(),
        );
        for key in &resp.keys {
            let label = key.label.as_deref().unwrap_or("—");
            let created = key
                .created_at
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S %:z")
                .to_string();
            let status = key.status.to_string();
            let key_type = key.key_type.to_string();
            print_full_entry(&[
                ("Key ID", &key.key_id),
                ("Label", label),
                ("Type", &key_type),
                ("Status", &status),
                ("Derivation", &key.derivation_path),
                ("Created", &created),
            ]);
        }
        return Ok(());
    }

    let dim = Style::default().fg(Color::DarkGray);
    let bold = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);

    let rows: Vec<Row> = resp
        .keys
        .iter()
        .map(|key| {
            let label = key.label.clone().unwrap_or_else(|| "\u{2014}".into());
            let created = key
                .created_at
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d")
                .to_string();

            let status_span = match key.status {
                vta_sdk::keys::KeyStatus::Active => {
                    Span::styled(key.status.to_string(), Style::default().fg(Color::Green))
                }
                vta_sdk::keys::KeyStatus::Revoked => {
                    Span::styled(key.status.to_string(), Style::default().fg(Color::Red))
                }
            };

            let id_line = Line::from(vec![
                Span::styled("\u{25b8} ", Style::default().fg(Color::Cyan)),
                Span::styled(key.key_id.clone(), bold),
            ]);

            let detail_line = Line::from(vec![
                Span::raw("  "),
                Span::styled(label, Style::default().fg(Color::Yellow)),
                Span::styled("  \u{2502}  ", dim),
                Span::raw(key.key_type.to_string()),
                Span::styled("  \u{2502}  ", dim),
                status_span,
                Span::styled("  \u{2502}  ", dim),
                Span::styled(key.derivation_path.clone(), dim),
                Span::styled("  \u{2502}  ", dim),
                Span::styled(created, dim),
            ]);

            Row::new(vec![Cell::from(Text::from(vec![id_line, detail_line]))])
                .height(2)
                .bottom_margin(1)
        })
        .collect();

    let title = format!(" Keys ({}\u{2013}{} of {}) ", offset + 1, end, resp.total);

    let table = Table::new(rows, [Constraint::Min(1)])
        .block(Block::bordered().title(title).border_style(dim));

    let height = (resp.keys.len() as u16 * 3).saturating_sub(1) + 2;
    print_widget(table, height);

    Ok(())
}

pub async fn cmd_seeds_list(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.list_seeds().await?;

    if resp.seeds.is_empty() {
        println!("No seed records found.");
        println!("  (pre-rotation state: using external seed store as generation 0)");
        println!("  Active seed ID: {}", resp.active_seed_id);
        return Ok(());
    }

    println!("{} seed generation(s):\n", resp.seeds.len());
    for seed in &resp.seeds {
        println!("  Seed ID:     {}", seed.id);
        println!("  Status:      {}", seed.status);
        println!(
            "  Created:     {}",
            crate::duration::format_local_datetime(seed.created_at)
        );
        if let Some(retired_at) = seed.retired_at {
            println!(
                "  Retired:     {}",
                crate::duration::format_local_datetime(retired_at)
            );
        }
        println!();
    }
    println!("Active seed ID: {}", resp.active_seed_id);

    Ok(())
}

pub async fn cmd_seeds_rotate(
    client: &VtaClient,
    mnemonic: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.rotate_seed(mnemonic).await?;

    println!("Seed rotated successfully.");
    println!("  Previous seed ID: {} (retired)", resp.previous_seed_id);
    println!("  New active seed ID: {}", resp.new_seed_id);

    Ok(())
}

pub async fn cmd_key_bundle(
    client: &VtaClient,
    context: &str,
    recipient: crate::sealed_producer::SealedRecipient,
) -> Result<(), Box<dyn std::error::Error>> {
    let bundle = client.fetch_did_secrets_bundle(context).await?;
    crate::sealed_producer::emit_did_secrets_bundle(bundle, &recipient, context, None).await
}

pub async fn cmd_key_secrets(
    client: &VtaClient,
    key_ids: Vec<String>,
    context: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_ids = if key_ids.is_empty() {
        let ctx = context.as_deref().ok_or(
            "provide key IDs as arguments, or use --context to export all active keys in a context",
        )?;
        let resp = client
            .list_keys(0, 10000, Some("active"), Some(ctx))
            .await?;
        resp.keys.into_iter().map(|k| k.key_id).collect()
    } else {
        key_ids
    };
    if key_ids.is_empty() {
        println!("No active keys found.");
        return Ok(());
    }
    for (i, key_id) in key_ids.iter().enumerate() {
        if i > 0 {
            println!();
        }
        let resp = client.get_key_secret(key_id).await?;
        println!("Key ID:               {}", resp.key_id);
        println!("Key Type:             {}", resp.key_type);
        println!("Public Key Multibase: {}", resp.public_key_multibase);
        println!("Secret Key Multibase: {}", resp.private_key_multibase);
    }
    Ok(())
}
