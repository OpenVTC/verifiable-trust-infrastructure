use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Cell, Row, Table},
};
use vta_sdk::prelude::*;

use crate::render::{is_full_display, print_full_entry, print_full_list_title, print_widget};

#[allow(clippy::too_many_arguments)]
/// Render a key type with the quantum-resistance axis it answers.
///
/// Says which axis, always. "post-quantum" alone would invite the reading that
/// the *identity* is post-quantum, and an identity that signs with ML-DSA while
/// agreeing keys with X25519 is not — its recorded traffic is still exposed to
/// harvest-now-decrypt-later. An operator reading a key row should come away
/// knowing one fact about one key, not a conclusion about a system.
///
/// See [`vta_sdk::keys::QuantumPosture`] for why the two axes are never
/// collapsed.
fn key_type_with_posture(key_type: &KeyType) -> String {
    let rendered = serde_json::to_value(key_type)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{key_type:?}"));
    format!("{rendered} ({})", key_type.posture().label())
}

pub async fn cmd_key_create(
    client: &VtaClient,
    key_type: &str,
    derivation_path: Option<String>,
    mnemonic: Option<String>,
    label: Option<String>,
    context_id: Option<String>,
    internal: bool,
    yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_type = match key_type {
        "ed25519" => KeyType::Ed25519,
        "x25519" => KeyType::X25519,
        "p256" => KeyType::P256,
        // Post-quantum signing (FIPS 204). The VTA has been able to derive
        // these since the BIP-32 work landed; this match was the only thing
        // standing between an operator and a PQC key.
        "mldsa44" => KeyType::MlDsa44,
        "mldsa65" => KeyType::MlDsa65,
        other => {
            return Err(format!(
                "unknown key type '{other}', expected ed25519, x25519, p256, mldsa44 or mldsa65"
            )
            .into());
        }
    };
    // An internal key is the one thing this CLI can create that cannot be
    // undone by any later command, restored from the mnemonic, or recovered
    // from a backup. Say so plainly, and require the operator to type the
    // consequence rather than mash `y` — a habitual yes/no prompt is not
    // proportionate to a permanent, silent loss of signing ability.
    if internal {
        eprintln!();
        eprintln!("  ⚠  You are about to create a NON-RECOVERABLE internal key.");
        eprintln!();
        eprintln!("     • Its material is generated from the system CSPRNG and is NOT");
        eprintln!("       derived from your BIP-39 seed. Your 24-word mnemonic will NOT");
        eprintln!("       recover it.");
        eprintln!("     • It is excluded from `pnm backup export`. A restored VTA will");
        eprintln!("       NOT have it.");
        eprintln!("     • It can never be exported — not by you, not by an admin, not");
        eprintln!("       under internal authority. The VTA will only sign with it.");
        eprintln!("     • If this VTA's storage is lost, every signature this key was");
        eprintln!("       the sole authority for becomes unproducible, permanently.");
        eprintln!();
        eprintln!("     It CANNOT be used to sign did:webvh log entries, precisely");
        eprintln!("     because losing it would freeze that DID forever. It CAN be a");
        eprintln!("     signing verificationMethod inside a DID document.");
        eprintln!();

        if !yes {
            eprint!("     Type 'i understand this key cannot be recovered' to continue: ");
            use std::io::{BufRead, Write};
            std::io::stderr().flush().ok();
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            if !line
                .trim()
                .eq_ignore_ascii_case("i understand this key cannot be recovered")
            {
                return Err("aborted: confirmation phrase not matched".into());
            }
        }
    }

    let mut req = CreateKeyRequest::new(key_type);
    if internal {
        req.internal = Some(true);
    }
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
    println!(
        "  Key Type:        {}",
        key_type_with_posture(&resp.key_type)
    );
    println!("  Derivation Path: {}", resp.derivation_path);
    println!("  Public Key:      {}", resp.public_key);
    println!("  Status:          {}", resp.status);
    if resp.origin == vta_sdk::keys::KeyOrigin::Internal {
        println!();
        println!("  ⚠  This is an internal key. It cannot be exported, is excluded from");
        println!("     backups, and cannot be recovered from your mnemonic. If this VTA's");
        println!("     storage is lost, this key is gone.");
    }
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
        // Deliberately NOT offered here, though `keys create` accepts them.
        // The VTA's import path validates a supplied private key against its
        // algorithm and refuses any type it cannot check, ML-DSA included —
        // offering it here would take the operator's key material and fail at
        // the far end. Named explicitly so the refusal reads as "not supported
        // yet" rather than "no such algorithm", which is what the generic
        // message would imply.
        "mldsa44" | "mldsa65" => {
            return Err(format!(
                "importing a post-quantum key ('{key_type}') is not supported yet — the VTA \
                 validates imported key material per algorithm and has no checker for ML-DSA. \
                 Use `keys create --type {key_type}` to have the VTA derive one instead."
            )
            .into());
        }
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

    let req = match import_carrier(client.trust_task_transport()) {
        // DIDComm and TSP are confidential end to end, so `keys/import/0.1`
        // takes the cleartext multibase carrier there. There is no wrapping
        // key to fetch: it would add a round trip the channel does not need.
        ImportCarrier::Multibase => ImportKeyRequest {
            key_type,
            private_key_sealed: None,
            private_key_jwe: None,
            private_key_multibase: Some(private_key_multibase),
            label,
            context_id,
        },
        // Over REST, TLS terminates wherever the operator terminates it, and
        // the VTA refuses a cleartext key (the April 2026 review, patch #9).
        // The key is sealed to an ephemeral wrapping key from
        // `keys/import-wrapping-key/0.1` — an Ed25519 did:key, sealed to its
        // X25519 counterpart — instead. If the fetch fails, the cause is
        // surfaced rather than downgraded to a request the server would refuse.
        ImportCarrier::Sealed => {
            let wrapping_key = client.get_wrapping_key().await.map_err(|e| {
                format!(
                    "failed to fetch an ephemeral wrapping key (keys/import-wrapping-key/0.1) \
                     from {}: {e} — a cleartext key over REST is not accepted",
                    client.endpoint_label()
                )
            })?;
            let sealed = seal_private_key(
                &wrapping_key.wrapping_key,
                &key_type,
                &private_key_multibase,
            )
            .await?;
            ImportKeyRequest {
                key_type,
                private_key_sealed: Some(sealed),
                private_key_jwe: None,
                private_key_multibase: None,
                label,
                context_id,
            }
        }
    };
    let resp = client.import_key(req).await?;

    println!("Key imported successfully:");
    println!("  Key ID:     {}", resp.key_id);
    println!("  Key Type:   {}", key_type_with_posture(&resp.key_type));
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

/// How `keys import` carries the private key to the VTA.
#[derive(Debug, PartialEq, Eq)]
enum ImportCarrier {
    /// Cleartext multibase, for a transport confidential end to end.
    Multibase,
    /// HPKE-sealed to the VTA's wrapping key, for REST.
    Sealed,
}

/// The carrier `keys/import/0.1` accepts over the transport this client uses
/// for Trust Tasks.
fn import_carrier(surface: vta_sdk::client::SurfaceTransport) -> ImportCarrier {
    use vta_sdk::client::SurfaceTransport;
    match surface {
        SurfaceTransport::Didcomm | SurfaceTransport::Tsp => ImportCarrier::Multibase,
        SurfaceTransport::Rest => ImportCarrier::Sealed,
    }
}

/// Seal a multibase-encoded private key to the VTA's wrapping key — an
/// Ed25519 `did:key`, sealed to its X25519 counterpart — using HPKE via
/// `vta_sdk::sealed_transfer`. Returns an armored bundle suitable for the
/// `private_key_sealed` field of `ImportKeyRequest`.
async fn seal_private_key(
    wrapping_did_key: &str,
    key_type: &KeyType,
    private_key_multibase: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use vta_sdk::sealed_transfer::{
        AssertionProof, InMemoryNonceStore, ProducerAssertion, RawPrivateKey, SealedPayloadV1,
        armor, generate_ed25519_keypair, seal_payload,
    };

    let vta_pub_bytes = affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(
        &affinidi_crypto::did_key::did_key_to_ed25519_pub(wrapping_did_key)?,
    )?;

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
        println!(
            "Key Type:             {}",
            key_type_with_posture(&resp.key_type)
        );
        println!("Public Key Multibase: {}", resp.public_key_multibase);
        println!("Secret Key Multibase: {}", resp.private_key_multibase);
    } else {
        let resp = client.get_key(key_id).await?;
        println!("Key ID:          {}", resp.key_id);
        println!("Key Type:        {}", key_type_with_posture(&resp.key_type));
        println!("Derivation Path: {}", resp.derivation_path);
        println!("Public Key:      {}", resp.public_key);
        println!("Status:          {}", resp.status);
        // Printed only when it has been decided. A line reading "Exportable:
        // yes" on every key would turn "nobody has considered this" into
        // "somebody allowed it" — the same conflation the record avoids by
        // storing `None` rather than `Some(true)`.
        if resp.exportable == Some(false) {
            println!("Exportable:      no — the private half is never released");
        }
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

/// Mark a key as releasable, or refuse every future export of it.
///
/// `exportable` is required rather than defaulted and there is no toggle: the
/// state is absolute, so re-running a command whose output you did not see
/// lands where you asked rather than undoing it.
pub async fn cmd_key_set_exportability(
    client: &VtaClient,
    key_id: &str,
    exportable: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.set_key_exportability(key_id, exportable).await?;
    if crate::render::is_json_output() {
        crate::render::print_json(&resp)?;
        return Ok(());
    }
    if resp.key.exportable == Some(false) {
        println!("{} is no longer exportable.", resp.key.key_id);
        println!(
            "Its private half will not be released to any caller. It can still be used for \
             signing and key agreement, so anything that asks the VTA to *use* it keeps working."
        );
        println!(
            "Undoing this needs more authority than setting it did — super-admin, or a fresh \
             step-up on your session."
        );
    } else {
        println!("{} is exportable.", resp.key.key_id);
        println!("Ordinary release rules apply: a caller entitled to the key can be given it.");
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

/// `pnm keys bundle-key <key-id>`: seal one P-256 key, which no DID publishes,
/// to a recipient. This is the hand-off for a key whose identity another
/// protocol fixes, such as an EUDI verifier's access-certificate key (#1988):
/// the identity is an X.509 certificate, so there is no DID whose secrets
/// `pnm keys bundle <context>` could export.
///
/// The VTA exports the key under `keys/export-secret/0.1`, which audits it,
/// and the key leaves this process only inside the sealed bundle.
pub async fn cmd_key_bundle_one(
    client: &VtaClient,
    key_id: &str,
    recipient: crate::sealed_producer::SealedRecipient,
    out: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let secret = client.get_key_secret(key_id).await?;
    if secret.key_type != KeyType::P256 {
        return Err(format!(
            "key {key_id} is {}; `pnm keys bundle-key` seals a P-256 key that no DID publishes. \
             For a DID's keys run `pnm keys bundle <context>`",
            secret.key_type
        )
        .into());
    }
    let scalar = p256_private_scalar(&secret.private_key_multibase)?;
    crate::sealed_producer::emit_raw_private_key_bundle(
        KeyType::P256,
        &scalar,
        key_id,
        &recipient,
        out,
    )
    .await
}

/// The subject a `pnm keys sign-csr` request names, attribute by attribute.
#[derive(Debug, Default, Clone)]
pub struct CsrSubjectArgs {
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
    pub organization: Option<String>,
    pub organizational_units: Vec<String>,
    pub organization_identifier: Option<String>,
    pub serial_number: Option<String>,
    pub common_name: String,
    pub email_address: Option<String>,
    pub dns: Vec<String>,
    pub uri: Vec<String>,
    pub email: Vec<String>,
}

impl CsrSubjectArgs {
    /// The `keys/sign-csr` subject in encoded order — `C`, `ST`, `L`, `O`,
    /// `OU`…, `organizationIdentifier`, `serialNumber`, `CN`, `emailAddress`:
    /// most general first, the order a DN prints in reverse — and the
    /// alternative names, if any. Values go as given; the VTA checks them
    /// and repairs nothing.
    pub fn to_request(
        &self,
    ) -> Result<
        (
            Vec<vta_sdk::protocols::key_management::sign_csr::SignCsrRdnAttribute>,
            Option<vta_sdk::protocols::key_management::sign_csr::SignCsrSubjectAltNames>,
        ),
        Box<dyn std::error::Error>,
    > {
        fn one<'a>(t: &'static str, v: &'a Option<String>) -> Option<(&'static str, &'a str)> {
            v.as_deref().map(|v| (t, v))
        }
        let attrs: Vec<(&str, &str)> = [
            one("C", &self.country),
            one("ST", &self.state),
            one("L", &self.locality),
            one("O", &self.organization),
        ]
        .into_iter()
        .flatten()
        .chain(
            self.organizational_units
                .iter()
                .map(|ou| ("OU", ou.as_str())),
        )
        .chain(
            [
                one("organizationIdentifier", &self.organization_identifier),
                one("serialNumber", &self.serial_number),
                Some(("CN", self.common_name.as_str())),
                one("emailAddress", &self.email_address),
            ]
            .into_iter()
            .flatten(),
        )
        .collect();
        let subject = attrs
            .into_iter()
            .map(|(t, v)| serde_json::from_value(serde_json::json!({ "type": t, "value": v })))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("subject: {e}"))?;
        let names = if self.dns.is_empty() && self.uri.is_empty() && self.email.is_empty() {
            None
        } else {
            let mut names = serde_json::Map::new();
            for (member, list) in [
                ("dns", &self.dns),
                ("uri", &self.uri),
                ("email", &self.email),
            ] {
                if !list.is_empty() {
                    names.insert(member.into(), serde_json::json!(list));
                }
            }
            Some(
                serde_json::from_value(serde_json::Value::Object(names))
                    .map_err(|e| format!("subject alternative names: {e}"))?,
            )
        };
        Ok((subject, names))
    }
}

/// `pnm keys sign-csr <key-id>`: a PKCS#10 certificate signing request for a
/// key that stays in the VTA (`keys/sign-csr/0.1`) — for an EUDI verifier's
/// access certificate, say, whose key the VTC uses through the VTA rather than
/// holding it.
///
/// The VTA builds the request from the subject and the key's own public key.
/// As the specification asks of a producer, the `publicKey` it answers with is
/// compared with the key's record before the request is written.
pub async fn cmd_key_sign_csr(
    client: &VtaClient,
    key_id: &str,
    subject: &CsrSubjectArgs,
    out: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (rdns, names) = subject.to_request()?;
    let record = client.get_key(key_id).await?;
    let response = client.sign_csr(key_id, rdns, names).await?;
    if response.public_key.as_str() != record.public_key {
        return Err(format!(
            "the VTA's request certifies {}, not key {key_id} ({}); not writing it",
            response.public_key.as_str(),
            record.public_key
        )
        .into());
    }
    match out {
        Some(path) => {
            std::fs::write(path, response.csr.as_str())?;
            eprintln!(
                "Wrote the certificate signing request to {}",
                path.display()
            );
        }
        None => print!("{}", response.csr.as_str()),
    }
    eprintln!("Key:        {key_id} ({})", record.key_type);
    eprintln!("Public key: {}", record.public_key);
    Ok(())
}

/// The 32-byte private scalar of a `p256-priv` multikey (multicodec 0x1306).
fn p256_private_scalar(
    private_key_multibase: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    const P256_PRIV: [u8; 2] = [0x86, 0x26];
    let (_, bytes) = multibase::decode(private_key_multibase)?;
    let bytes = zeroize::Zeroizing::new(bytes);
    match bytes.strip_prefix(&P256_PRIV[..]) {
        Some(scalar) if scalar.len() == 32 => Ok(zeroize::Zeroizing::new(scalar.to_vec())),
        _ => Err("the VTA returned a key that is not a P-256 private multikey".into()),
    }
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
        println!(
            "Key Type:             {}",
            key_type_with_posture(&resp.key_type)
        );
        println!("Public Key Multibase: {}", resp.public_key_multibase);
        println!("Secret Key Multibase: {}", resp.private_key_multibase);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CsrSubjectArgs, ImportCarrier, import_carrier, p256_private_scalar};
    use vta_sdk::client::SurfaceTransport;

    /// The flags become the subject in encoded order (most general first),
    /// whatever order they were given in, and the names only when asked for.
    #[test]
    fn sign_csr_subject_is_in_encoded_order() {
        let args = CsrSubjectArgs {
            common_name: "Example Community Verifier".into(),
            organization_identifier: Some("LEIXG-5299000EXAMPLE000001".into()),
            organization: Some("Example Community e.V.".into()),
            country: Some("DE".into()),
            dns: vec!["verifier.community.example".into()],
            ..CsrSubjectArgs::default()
        };
        let (subject, names) = args.to_request().unwrap();
        assert_eq!(
            serde_json::to_value(&subject).unwrap(),
            serde_json::json!([
                { "type": "C", "value": "DE" },
                { "type": "O", "value": "Example Community e.V." },
                { "type": "organizationIdentifier", "value": "LEIXG-5299000EXAMPLE000001" },
                { "type": "CN", "value": "Example Community Verifier" }
            ])
        );
        assert_eq!(
            serde_json::to_value(names.unwrap()).unwrap(),
            serde_json::json!({ "dns": ["verifier.community.example"] })
        );

        let bare = CsrSubjectArgs {
            common_name: "Verifier".into(),
            ..CsrSubjectArgs::default()
        };
        assert!(bare.to_request().unwrap().1.is_none());
    }

    /// The scalar comes out of a `p256-priv` multikey; anything else is
    /// refused rather than sealed as if it were one.
    #[test]
    fn bundle_key_takes_the_p256_scalar_and_nothing_else() {
        let mut p256 = vec![0x86, 0x26];
        p256.extend([7u8; 32]);
        let mb = multibase::encode(multibase::Base::Base58Btc, &p256);
        assert_eq!(p256_private_scalar(&mb).unwrap().as_slice(), &[7u8; 32]);

        let mut ed25519 = vec![0x80, 0x26];
        ed25519.extend([7u8; 32]);
        let mb = multibase::encode(multibase::Base::Base58Btc, &ed25519);
        assert!(p256_private_scalar(&mb).is_err());
        let short = multibase::encode(multibase::Base::Base58Btc, [0x86, 0x26, 1]);
        assert!(p256_private_scalar(&short).is_err());
    }

    /// `keys/import/0.1` over DIDComm or TSP takes the multibase carrier, with
    /// no wrapping-key fetch (a REST route). Over REST the key is sealed, since
    /// the VTA refuses a cleartext key there.
    #[test]
    fn keys_import_carrier_follows_the_trust_task_transport() {
        assert_eq!(
            import_carrier(SurfaceTransport::Didcomm),
            ImportCarrier::Multibase
        );
        assert_eq!(
            import_carrier(SurfaceTransport::Tsp),
            ImportCarrier::Multibase
        );
        assert_eq!(
            import_carrier(SurfaceTransport::Rest),
            ImportCarrier::Sealed
        );
    }
}
