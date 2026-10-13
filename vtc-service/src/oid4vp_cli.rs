//! `vtc oid4vp {request,install,attach,csr,certificate,list,remove}` — install the key
//! of an OpenID4VP verifier identity this VTC presents to wallets
//! (`crate::oid4vp`).
//!
//! The VTA mints the identity and its key; the VTC keeps no VTA credential, so
//! the key reaches it by a sealed hand-off the operator relays, the same shape
//! as every other secret that moves between these tools:
//!
//! 1. `vtc oid4vp request --identity swiyu` writes a sealed-transfer request
//!    and keeps its private half here (0600).
//! 2. On the admin workstation: mint the identity —
//!    `pnm did-mgmt dids create --context <ctx> --template swiyu-verifier --did-url <swiyu slot URL>`
//!    — upload its `did.jsonl` to the swiyu slot, then seal its keys to the
//!    request: `pnm keys bundle <ctx> --recipient request.json`. The digest is
//!    printed there; carry it here separately from the bundle.
//! 3. `vtc oid4vp install --identity swiyu --bundle bundle.armor --digest <hex>`
//!    opens the bundle, keeps the P-256 request-signing key, and stores it
//!    encrypted in `oid4vp_keys`.
//!
//! An EUDI identity has no DID; its key is a bare P-256 key
//! (`pnm keys create --key-type p256`) sealed by `pnm keys bundle-key`. After
//! `install`, `vtc oid4vp csr` writes a certificate signing request signed by
//! that key, and `vtc oid4vp certificate` installs the access certificate chain
//! the operator's registrar issued (`crate::oid4vp::x509`). Until then the
//! identity opens no session.
//!
//! Or the key stays in the VTA: `vtc oid4vp attach` records the VTA's key id
//! and public key, and the daemon signs every request object through
//! `keys/sign-jws` (`crate::oid4vp::VtaHeldSigner`). An EUDI identity's
//! certificate request then comes from the admin workstation
//! (`pnm keys sign-csr`), since this VTC has no key to sign one with.
//!
//! Offline: run on a **stopped** daemon, which holds the store's lock and
//! loads the identities at boot. Not for TEE deployments (the VTC has none).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use vta_sdk::keys::KeyType;
use vta_sdk::sealed_transfer::{
    BootstrapRequest, SealedPayloadV1, armor, ed25519_seed_to_x25519_secret,
    generate_ed25519_keypair, open_bundle,
};

use crate::config::AppConfig;
use crate::oid4vp::trust_statement;
use crate::oid4vp::x509::{CsrSubject, build_csr, check_chain};
use crate::oid4vp::{
    KeyCustody, LocalP256Signer, VerifierIdentityRecord, VerifierKind, delete_identity,
    get_identity, list_identities, put_identity,
};
use crate::store::keyspaces;

type CliResult = Result<(), Box<dyn std::error::Error>>;

/// The file holding a pending request's private seed, beside the store.
fn request_key_path(config: &AppConfig, identity: &str) -> PathBuf {
    config
        .store
        .data_dir
        .join("oid4vp")
        .join(format!("{identity}.request-key"))
}

fn check_identity_name(identity: &str) -> Result<(), String> {
    if identity.is_empty()
        || identity.len() > 64
        || !identity
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(format!(
            "identity '{identity}' must be 1-64 characters of [a-z0-9-]"
        ));
    }
    Ok(())
}

/// `vtc oid4vp request --identity <id> [--out <file>]`.
pub async fn run_request(
    config_path: Option<PathBuf>,
    identity: String,
    out: Option<PathBuf>,
) -> CliResult {
    check_identity_name(&identity)?;
    let config = AppConfig::load(config_path)?;
    let key_path = request_key_path(&config, &identity);
    if let Some(dir) = key_path.parent() {
        std::fs::create_dir_all(dir)?;
        crate::secure_file::restrict_dir_to_owner(dir)?;
    }

    let (seed, public) = generate_ed25519_keypair();
    let nonce: [u8; 16] = rand::random();
    // The seed and the nonce the bundle must be addressed to, together: a
    // bundle sealed to another request does not open with this key.
    let mut stored = seed.to_vec();
    stored.extend_from_slice(&nonce);
    std::fs::write(&key_path, &stored)?;
    crate::secure_file::restrict_file_to_owner(&key_path)?;

    let request = BootstrapRequest::new(public, nonce, Some(format!("vtc oid4vp {identity}")));
    let json = serde_json::to_string_pretty(&request)?;
    match &out {
        Some(path) => std::fs::write(path, &json)?,
        None => println!("{json}"),
    }

    eprintln!();
    eprintln!(
        "Request for verifier identity '{identity}' written{}.",
        match &out {
            Some(p) => format!(" to {}", p.display()),
            None => String::new(),
        }
    );
    eprintln!("Its private half stays here: {}", key_path.display());
    eprintln!();
    eprintln!("On the admin workstation, for a swiyu verifier:");
    eprintln!(
        "  pnm did-mgmt dids create --context <context> --template swiyu-verifier \
         --did-url <swiyu identifier-registry slot URL>"
    );
    eprintln!("  # upload the printed did.jsonl to that slot with your swiyu API token, then:");
    eprintln!("  pnm keys bundle <context> --recipient <this request file> > bundle.armor");
    eprintln!();
    eprintln!("For an EUDI verifier:");
    eprintln!("  pnm keys create --key-type p256 --context <context> --label eudi-verifier");
    eprintln!("  pnm keys bundle-key <key id> --recipient <this request file> --out bundle.armor");
    eprintln!();
    eprintln!("Then, with this VTC stopped:");
    eprintln!(
        "  vtc oid4vp install --identity {identity} --bundle <bundle file> --digest <digest pnm \
         printed>"
    );
    Ok(())
}

/// `vtc oid4vp install --identity <id> --bundle <file> --digest <hex>`.
pub async fn run_install(
    config_path: Option<PathBuf>,
    identity: String,
    bundle_path: PathBuf,
    digest: String,
    kid: Option<String>,
) -> CliResult {
    check_identity_name(&identity)?;
    let config = AppConfig::load(config_path)?;
    let key_path = request_key_path(&config, &identity);
    let record = open_and_select(&key_path, &bundle_path, &digest, &identity, kid.as_deref())?;

    // The record must be one the daemon can sign with before it is stored.
    LocalP256Signer::from_record(&record)?;

    let storage_key = crate::server::offline_storage_key(&config).await?;
    let store = crate::store::offline::open_offline(&config.store)?;
    let ks = store
        .keyspace(keyspaces::OID4VP_KEYS)?
        .with_encryption(storage_key);
    let replaced = get_identity(&ks, &identity).await?.is_some();
    put_identity(&ks, &record).await?;
    store.persist().await?;
    // The request is spent: its key opened exactly this bundle.
    let _ = std::fs::remove_file(&key_path);

    println!(
        "{} verifier identity '{identity}'.",
        if replaced { "Replaced" } else { "Installed" }
    );
    print_identity(&record);
    match record.kind {
        VerifierKind::Swiyu => println!("Start the VTC to load it."),
        VerifierKind::Eudi => {
            println!("Next, request its access certificate from your registrar:");
            println!(
                "  vtc oid4vp csr --identity {identity} --common-name <name> --organization <org> \
                 --organization-identifier <id> --country <CC> --out {identity}.csr"
            );
            println!("then install what it issues:");
            println!("  vtc oid4vp certificate --identity {identity} --chain <chain.pem>");
        }
    }
    Ok(())
}

/// `vtc oid4vp attach --identity <id> --vta-key <key id> --public-key <zDn…>
/// [--did <did> --kid <kid>]`.
pub async fn run_attach(
    config_path: Option<PathBuf>,
    identity: String,
    vta_key: String,
    public_key: String,
    swiyu: Option<(String, String)>,
) -> CliResult {
    let config = AppConfig::load(config_path)?;
    let record = attach_record(&identity, &vta_key, &public_key, swiyu)?;
    crate::oid4vp::VtaHeldSigner::from_record(&record, Default::default())?;

    let storage_key = crate::server::offline_storage_key(&config).await?;
    let store = crate::store::offline::open_offline(&config.store)?;
    let ks = store
        .keyspace(keyspaces::OID4VP_KEYS)?
        .with_encryption(storage_key);
    let replaced = get_identity(&ks, &identity).await?.is_some();
    put_identity(&ks, &record).await?;
    store.persist().await?;

    println!(
        "{} verifier identity '{identity}', signed by the VTA's key {vta_key}.",
        if replaced { "Replaced" } else { "Attached" }
    );
    print_identity(&record);
    println!();
    println!("The VTA must let this VTC sign with that key. On the admin workstation:");
    println!(
        "  pnm acl create --did {} --role application --contexts <the key's context> \
         --capabilities sign-jws",
        config.vtc_did.as_deref().unwrap_or("<this VTC's DID>")
    );
    if config.vta_did.is_none() {
        println!("and set `vta_did` in this VTC's config: the daemon will not start without it.");
    }
    if record.kind == VerifierKind::Eudi {
        println!("Request its access certificate there too:");
        println!(
            "  pnm keys sign-csr {vta_key} --common-name <name> --organization <org> \
             --organization-identifier <id> --country <CC> --out {identity}.csr"
        );
        println!("then install what the registrar issues:");
        println!("  vtc oid4vp certificate --identity {identity} --chain <chain.pem>");
    } else {
        println!("Then start the VTC to load it.");
    }
    Ok(())
}

/// The record `attach` stores: a P-256 public key and the VTA's id for it,
/// with no private key. Split out to be testable without a store.
fn attach_record(
    identity: &str,
    vta_key: &str,
    public_key: &str,
    swiyu: Option<(String, String)>,
) -> Result<VerifierIdentityRecord, Box<dyn std::error::Error>> {
    check_identity_name(identity)?;
    if vta_key.trim().is_empty() {
        return Err("--vta-key must name the key at the VTA".into());
    }
    let jwk = affinidi_crypto::JWK::from_multikey(public_key.trim())
        .map_err(|e| format!("--public-key is not a multibase public key: {e}"))?;
    let mut public_jwk = serde_json::to_value(&jwk)?;
    if let Some(obj) = public_jwk.as_object_mut() {
        obj.remove("d");
        obj.remove("kid");
        obj.retain(|_, v| !v.is_null());
    }
    if public_jwk.get("crv").and_then(serde_json::Value::as_str) != Some("P-256") {
        return Err(
            "--public-key must be a P-256 key (zDn…); swiyu and EUDI wallets accept ES256 only"
                .into(),
        );
    }
    let (kind, did, kid) = match swiyu {
        Some((did, kid)) => {
            if !kid.starts_with(&format!("{did}#")) {
                return Err(format!("--kid {kid} is not a verification method of {did}").into());
            }
            (VerifierKind::Swiyu, Some(did), Some(kid))
        }
        None => (VerifierKind::Eudi, None, None),
    };
    Ok(VerifierIdentityRecord {
        id: identity.to_string(),
        kind,
        did,
        kid,
        public_jwk,
        private_key_multibase: None,
        vta_key_id: Some(vta_key.trim().to_string()),
        x5c: None,
        verifier_info: None,
        installed_at: now_secs(),
    })
}

fn print_identity(record: &VerifierIdentityRecord) {
    println!("  kind:      {:?}", record.kind);
    match record.custody() {
        Ok(KeyCustody::Local(_)) => println!("  key held:  here (signs locally)"),
        Ok(KeyCustody::Vta(id)) => println!("  key held:  in the VTA, as {id} (keys/sign-jws)"),
        Err(e) => println!("  key held:  {e}"),
    }
    if let Some(did) = &record.did {
        println!("  DID:       {did}");
    }
    if let Some(kid) = &record.kid {
        println!("  key:       {kid}");
    }
    match record.client_id() {
        Some(client_id) => println!("  client_id: {client_id}"),
        None => println!("  client_id: (none yet — install its access certificate)"),
    }
    let now = now_secs() as i64;
    let statements: Vec<_> = record
        .verifier_info
        .iter()
        .flatten()
        .filter_map(trust_statement::held)
        .collect();
    for s in &statements {
        let state = if s.exp <= now { "EXPIRED" } else { "expires" };
        println!(
            "  statement: {} ({state} {})",
            s.kind.label(),
            trust_statement::timestamp(s.exp)
        );
    }
    if record.kind == VerifierKind::Swiyu
        && !statements
            .iter()
            .any(|s| s.kind == trust_statement::StatementKind::Identity && s.exp > now)
    {
        println!(
            "  statement: no current identity trust statement — wallets cannot tell who is \
             asking (`vtc oid4vp trust-statement`)"
        );
    }
}

/// Read an installed EUDI identity, offline.
async fn open_eudi_identity(
    config: &AppConfig,
    identity: &str,
) -> Result<
    (
        crate::store::Store,
        crate::store::KeyspaceHandle,
        VerifierIdentityRecord,
    ),
    Box<dyn std::error::Error>,
> {
    let storage_key = crate::server::offline_storage_key(config).await?;
    let store = crate::store::offline::open_offline(&config.store)?;
    let ks = store
        .keyspace(keyspaces::OID4VP_KEYS)?
        .with_encryption(storage_key);
    let record = get_identity(&ks, identity).await?.ok_or_else(|| {
        format!("no verifier identity '{identity}'; `vtc oid4vp list` shows them")
    })?;
    if record.kind != VerifierKind::Eudi {
        return Err(format!(
            "verifier identity '{identity}' is a {:?} identity; only an EUDI identity has an \
             access certificate",
            record.kind
        )
        .into());
    }
    Ok((store, ks, record))
}

/// `vtc oid4vp csr --identity <id> --common-name … [--out <file>]`.
pub async fn run_csr(
    config_path: Option<PathBuf>,
    identity: String,
    subject: CsrSubject,
    out: Option<PathBuf>,
) -> CliResult {
    let config = AppConfig::load(config_path)?;
    let (_store, _ks, record) = open_eudi_identity(&config, &identity).await?;
    if let KeyCustody::Vta(key_id) = record.custody()? {
        return Err(format!(
            "verifier identity '{identity}' keeps its key in the VTA; request its certificate \
             there: pnm keys sign-csr {key_id} --common-name … (same subject flags)"
        )
        .into());
    }
    let pem = build_csr(&record, &subject)?;
    match &out {
        Some(path) => {
            std::fs::write(path, &pem)?;
            eprintln!("Certificate signing request written to {}.", path.display());
        }
        None => print!("{pem}"),
    }
    eprintln!(
        "Submit it to your registrar for an access certificate, then:\n  vtc oid4vp certificate \
         --identity {identity} --chain <chain.pem>"
    );
    Ok(())
}

/// `vtc oid4vp certificate --identity <id> --chain <pem>
/// [--registration-certificate <file> --registration-format <format>]`.
pub async fn run_certificate(
    config_path: Option<PathBuf>,
    identity: String,
    chain: PathBuf,
    registration: Option<(PathBuf, String)>,
) -> CliResult {
    let config = AppConfig::load(config_path)?;
    let (store, ks, mut record) = open_eudi_identity(&config, &identity).await?;
    let pem = std::fs::read(&chain).map_err(|e| format!("read {}: {e}", chain.display()))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let checked = check_chain(&record, &pem, now)?;
    record.x5c = Some(checked.x5c);
    if let Some((path, format)) = registration {
        record.verifier_info = Some(vec![registration_info(&path, &format)?]);
    }
    put_identity(&ks, &record).await?;
    store.persist().await?;

    println!("Installed the access certificate of verifier identity '{identity}'.");
    println!("  subject:   {}", checked.subject);
    println!(
        "  expires:   {}",
        chrono::DateTime::from_timestamp(checked.not_after, 0)
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| checked.not_after.to_string())
    );
    if checked.dropped_root {
        println!("  (the self-signed root at the end of the file is left out of x5c)");
    }
    if let Some(info) = &record.verifier_info {
        println!("  verifier_info: {} entry", info.len());
    }
    print_identity(&record);
    println!("Start the VTC to use it.");
    Ok(())
}

/// A `verifier_info` entry for a registration certificate file.
fn registration_info(
    path: &Path,
    format: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let data =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let (data, format) = (data.trim(), format.trim());
    if data.is_empty() || format.is_empty() {
        return Err("the registration certificate and its format must not be empty".into());
    }
    Ok(serde_json::json!({ "format": format, "data": data }))
}

/// Open the sealed bundle with the pending request's key and pick out the
/// P-256 key the identity signs its request objects with.
///
/// Split from [`run_install`] so the selection rules are testable without a
/// secret store.
fn open_and_select(
    key_path: &Path,
    bundle_path: &Path,
    digest: &str,
    identity: &str,
    kid: Option<&str>,
) -> Result<VerifierIdentityRecord, Box<dyn std::error::Error>> {
    let stored = std::fs::read(key_path).map_err(|e| {
        format!(
            "no pending request for identity '{identity}' at {} ({e}); run `vtc oid4vp request \
             --identity {identity}` first",
            key_path.display()
        )
    })?;
    if stored.len() != 48 {
        return Err(format!("{} is not a request key", key_path.display()).into());
    }
    let seed: [u8; 32] = stored[..32].try_into().expect("length checked");
    let nonce: [u8; 16] = stored[32..].try_into().expect("length checked");

    let armored = std::fs::read_to_string(bundle_path)
        .map_err(|e| format!("read {}: {e}", bundle_path.display()))?;
    let bundles = armor::decode(&armored)?;
    let [bundle] = bundles.as_slice() else {
        return Err(format!("expected one sealed bundle, found {}", bundles.len()).into());
    };
    if bundle.bundle_id != nonce {
        return Err("this bundle was sealed to a different request".into());
    }
    let opened = open_bundle(
        &ed25519_seed_to_x25519_secret(&seed),
        bundle,
        Some(digest.trim()),
    )?;
    let secrets = match opened.payload {
        SealedPayloadV1::DidSecrets(secrets) => secrets,
        SealedPayloadV1::RawPrivateKey(raw) => {
            if kid.is_some() {
                return Err("--kid names a key of a DID; this bundle holds one bare key".into());
            }
            return eudi_record(identity, &raw);
        }
        _ => {
            return Err(
                "the bundle carries neither DID secrets nor a key; seal it with \
                        `pnm keys bundle <context>` (swiyu) or `pnm keys bundle-key <key id>` \
                        (EUDI)"
                    .into(),
            );
        }
    };

    let p256: Vec<_> = secrets
        .secrets
        .iter()
        .filter(|s| s.key_type == KeyType::P256)
        .filter(|s| kid.is_none_or(|k| s.key_id == k))
        .collect();
    let entry = match p256.as_slice() {
        [one] => *one,
        [] => {
            return Err(format!(
                "the bundle for {} holds no P-256 key{}; a swiyu verifier signs its requests \
                 with ES256",
                secrets.did,
                kid.map(|k| format!(" named {k}")).unwrap_or_default()
            )
            .into());
        }
        many => {
            return Err(format!(
                "the bundle holds {} P-256 keys; name the request-signing one with --kid ({})",
                many.len(),
                many.iter()
                    .map(|s| s.key_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .into());
        }
    };
    if !entry.key_id.starts_with(&format!("{}#", secrets.did)) {
        return Err(format!(
            "key {} is not a verification method of {}",
            entry.key_id, secrets.did
        )
        .into());
    }

    let secret = affinidi_tdk::secrets_resolver::secrets::Secret::from_multibase(
        &entry.private_key_multibase,
        Some(&entry.key_id),
    )?;
    let public = secret.get_public_keymultibase()?;
    let jwk = affinidi_crypto::JWK::from_multikey(&public)?;
    let mut public_jwk = serde_json::to_value(&jwk)?;
    if let Some(obj) = public_jwk.as_object_mut() {
        obj.remove("d");
        obj.remove("kid");
        obj.retain(|_, v| !v.is_null());
    }

    Ok(VerifierIdentityRecord {
        id: identity.to_string(),
        kind: VerifierKind::Swiyu,
        did: Some(secrets.did.clone()),
        kid: Some(entry.key_id.clone()),
        public_jwk,
        private_key_multibase: Some(entry.private_key_multibase.clone()),
        vta_key_id: None,
        x5c: None,
        verifier_info: None,
        installed_at: now_secs(),
    })
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// An EUDI identity from the bare P-256 key `pnm keys bundle-key` sealed. It
/// has no certificate yet.
fn eudi_record(
    identity: &str,
    raw: &vta_sdk::sealed_transfer::RawPrivateKey,
) -> Result<VerifierIdentityRecord, Box<dyn std::error::Error>> {
    use base64::Engine as _;
    if raw.key_type != KeyType::P256.to_string() {
        return Err(format!(
            "the bundle holds a {} key; an EUDI verifier signs its requests with a P-256 key",
            raw.key_type
        )
        .into());
    }
    let scalar = zeroize::Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&raw.key_bytes_b64)?,
    );
    let kp = affinidi_crypto::p256::generate(Some(&scalar))?;
    let secret = affinidi_tdk::secrets_resolver::secrets::Secret::generate_p256(
        None,
        Some(&kp.private_bytes),
    )?;
    let mut public_jwk = serde_json::to_value(&kp.jwk)?;
    if let Some(obj) = public_jwk.as_object_mut() {
        obj.remove("d");
        obj.remove("kid");
        obj.retain(|_, v| !v.is_null());
    }
    Ok(VerifierIdentityRecord {
        id: identity.to_string(),
        kind: VerifierKind::Eudi,
        did: None,
        kid: None,
        public_jwk,
        private_key_multibase: Some(secret.get_private_keymultibase()?),
        vta_key_id: None,
        x5c: None,
        verifier_info: None,
        installed_at: now_secs(),
    })
}

/// `vtc oid4vp list`.
pub async fn run_list(config_path: Option<PathBuf>) -> CliResult {
    let config = AppConfig::load(config_path)?;
    let storage_key = crate::server::offline_storage_key(&config).await?;
    let store = crate::store::offline::open_offline(&config.store)?;
    let ks = store
        .keyspace(keyspaces::OID4VP_KEYS)?
        .with_encryption(storage_key);
    let identities = list_identities(&ks).await?;
    if identities.is_empty() {
        println!("No verifier identities installed.");
        return Ok(());
    }
    for r in identities {
        println!("{}", r.id);
        print_identity(&r);
    }
    Ok(())
}

/// `vtc oid4vp trust-statement --identity <id> --file <jwt> [--file …]`.
///
/// Every file is checked before anything is stored: one statement for another
/// DID, or already expired, installs none of them.
pub async fn run_trust_statement(
    config_path: Option<PathBuf>,
    identity: String,
    files: Vec<PathBuf>,
) -> CliResult {
    let config = AppConfig::load(config_path)?;
    let storage_key = crate::server::offline_storage_key(&config).await?;
    let store = crate::store::offline::open_offline(&config.store)?;
    let ks = store
        .keyspace(keyspaces::OID4VP_KEYS)?
        .with_encryption(storage_key);
    let mut record = get_identity(&ks, &identity).await?.ok_or_else(|| {
        format!("no verifier identity '{identity}'; `vtc oid4vp list` shows them")
    })?;
    let did = match (&record.kind, &record.did) {
        (VerifierKind::Swiyu, Some(did)) => did.clone(),
        _ => {
            return Err(format!(
                "verifier identity '{identity}' is not a swiyu identity; an EUDI identity \
                 carries its registration certificate instead (`vtc oid4vp certificate \
                 --registration-certificate …`)"
            )
            .into());
        }
    };
    let now = now_secs() as i64;
    let mut checked = Vec::new();
    for path in &files {
        let jwt =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let statement = trust_statement::check(&jwt, &did, now)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        checked.push(statement);
    }
    let mut entries = record.verifier_info.take().unwrap_or_default();
    for statement in &checked {
        entries = trust_statement::merge(&entries, statement);
    }
    record.verifier_info = Some(entries);
    put_identity(&ks, &record).await?;
    store.persist().await?;

    println!("Installed on verifier identity '{identity}':");
    for s in &checked {
        println!(
            "  {} (expires {})",
            s.kind.label(),
            trust_statement::timestamp(s.exp)
        );
    }
    print_identity(&record);
    println!("Start the VTC to carry them.");
    Ok(())
}

/// `vtc oid4vp remove --identity <id>`.
pub async fn run_remove(config_path: Option<PathBuf>, identity: String) -> CliResult {
    let config = AppConfig::load(config_path)?;
    let storage_key = crate::server::offline_storage_key(&config).await?;
    let store = crate::store::offline::open_offline(&config.store)?;
    let ks = store
        .keyspace(keyspaces::OID4VP_KEYS)?
        .with_encryption(storage_key);
    if delete_identity(&ks, &identity).await? {
        store.persist().await?;
        println!("Removed verifier identity '{identity}'.");
    } else {
        println!("No verifier identity '{identity}'.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry};
    use vta_sdk::sealed_transfer::{
        AssertionProof, InMemoryNonceStore, ProducerAssertion, bundle_digest, seal_payload,
    };

    const DID: &str = "did:webvh:Qm1:identifier-reg.example:api:v1:did:abc";

    fn p256_entry(fragment: &str, seed: u8) -> SecretEntry {
        let kp = affinidi_crypto::p256::generate(Some(&[seed; 32])).unwrap();
        let secret = affinidi_tdk::secrets_resolver::secrets::Secret::generate_p256(
            None,
            Some(&kp.private_bytes),
        )
        .unwrap();
        SecretEntry {
            key_id: format!("{DID}#{fragment}"),
            key_type: KeyType::P256,
            private_key_multibase: secret.get_private_keymultibase().unwrap(),
        }
    }

    /// `attach` records the VTA's key and its public half — never a private
    /// key — as a swiyu identity under its DID or an EUDI one without, and
    /// refuses a key wallets would not accept or a `kid` outside the DID.
    #[test]
    fn attach_records_a_vta_key_and_no_private_key() {
        let p256 =
            affinidi_tdk::secrets_resolver::secrets::Secret::generate_p256(None, Some(&[9; 32]))
                .unwrap()
                .get_public_keymultibase()
                .unwrap();
        let swiyu = attach_record(
            "swiyu",
            "verifier-p256",
            &p256,
            Some((DID.into(), format!("{DID}#key-1"))),
        )
        .unwrap();
        assert_eq!(swiyu.kind, VerifierKind::Swiyu);
        assert!(matches!(
            swiyu.custody(),
            Ok(KeyCustody::Vta("verifier-p256"))
        ));
        assert_eq!(swiyu.public_jwk["crv"], "P-256");
        assert!(swiyu.public_jwk.get("d").is_none());
        crate::oid4vp::VtaHeldSigner::from_record(&swiyu, Default::default()).unwrap();

        let eudi = attach_record("eudi", "access-p256", &p256, None).unwrap();
        assert_eq!(eudi.kind, VerifierKind::Eudi);
        assert!(eudi.client_id().is_none(), "no certificate yet");

        let ed25519 =
            affinidi_tdk::secrets_resolver::secrets::Secret::generate_ed25519(None, Some(&[9; 32]))
                .get_public_keymultibase()
                .unwrap();
        assert!(attach_record("eudi", "k", &ed25519, None).is_err());
        assert!(
            attach_record(
                "swiyu",
                "k",
                &p256,
                Some((DID.into(), "did:example:other#key-1".into()))
            )
            .is_err()
        );
    }

    /// A pending request's key file and a bundle sealed to it, as `request`
    /// and `pnm keys bundle` would leave them.
    async fn sealed(dir: &Path, secrets: Vec<SecretEntry>) -> (PathBuf, PathBuf, String) {
        sealed_payload(
            dir,
            SealedPayloadV1::DidSecrets(Box::new(DidSecretsBundle {
                did: DID.into(),
                secrets,
            })),
        )
        .await
    }

    async fn sealed_payload(dir: &Path, payload: SealedPayloadV1) -> (PathBuf, PathBuf, String) {
        let (seed, public) = generate_ed25519_keypair();
        let nonce = [9u8; 16];
        let key_path = dir.join("swiyu.request-key");
        let mut stored = seed.to_vec();
        stored.extend_from_slice(&nonce);
        std::fs::write(&key_path, &stored).unwrap();

        let request = BootstrapRequest::new(public, nonce, None);
        let (_p, producer_pk) = generate_ed25519_keypair();
        let bundle = seal_payload(
            &request.decode_client_x25519_pub().unwrap(),
            nonce,
            ProducerAssertion {
                producer_did: affinidi_crypto::did_key::ed25519_pub_to_did_key(&producer_pk),
                proof: AssertionProof::PinnedOnly,
            },
            &payload,
            &InMemoryNonceStore::new(),
        )
        .await
        .unwrap();
        let bundle_path = dir.join("bundle.armor");
        std::fs::write(&bundle_path, armor::encode(&bundle)).unwrap();
        (key_path, bundle_path, bundle_digest(&bundle))
    }

    /// The P-256 key comes out of the bundle as a record its own signer
    /// accepts, named by the DID and verification method it was sealed under.
    #[tokio::test]
    async fn the_request_signing_key_is_taken_from_the_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let (key, bundle, digest) =
            sealed(dir.path(), vec![p256_entry("verifier-key-1", 0x31)]).await;
        let record = open_and_select(&key, &bundle, &digest, "swiyu", None).unwrap();
        assert_eq!(record.did.as_deref(), Some(DID));
        assert_eq!(record.kid, Some(format!("{DID}#verifier-key-1")));
        assert_eq!(record.public_jwk["crv"], "P-256");
        assert!(record.public_jwk.get("d").is_none());
        LocalP256Signer::from_record(&record).expect("a usable signer");
    }

    #[tokio::test]
    async fn a_wrong_digest_or_a_different_request_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (key, bundle, _digest) =
            sealed(dir.path(), vec![p256_entry("verifier-key-1", 0x31)]).await;
        assert!(open_and_select(&key, &bundle, &"00".repeat(32), "swiyu", None).is_err());

        // Another request's key file cannot open it.
        let other = tempfile::tempdir().unwrap();
        let (other_key, _b, _d) = sealed(other.path(), vec![p256_entry("k", 0x32)]).await;
        let (_k, bundle2, digest2) = sealed(dir.path(), vec![p256_entry("k", 0x33)]).await;
        assert!(open_and_select(&other_key, &bundle2, &digest2, "swiyu", None).is_err());
    }

    /// No P-256 key, or more than one without `--kid`, is refused by name.
    #[tokio::test]
    async fn the_key_must_be_unambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let (key, bundle, digest) = sealed(
            dir.path(),
            vec![p256_entry("a", 0x31), p256_entry("b", 0x32)],
        )
        .await;
        let err = open_and_select(&key, &bundle, &digest, "swiyu", None).unwrap_err();
        assert!(err.to_string().contains("--kid"), "{err}");

        let dir = tempfile::tempdir().unwrap();
        let (key, bundle, digest) = sealed(
            dir.path(),
            vec![p256_entry("a", 0x31), p256_entry("b", 0x32)],
        )
        .await;
        let record =
            open_and_select(&key, &bundle, &digest, "swiyu", Some(&format!("{DID}#b"))).unwrap();
        assert_eq!(record.kid, Some(format!("{DID}#b")));
    }

    fn raw_key(key_type: &str, bytes: &[u8]) -> SealedPayloadV1 {
        use base64::Engine as _;
        SealedPayloadV1::RawPrivateKey(vta_sdk::sealed_transfer::RawPrivateKey {
            key_type: key_type.into(),
            key_bytes_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
        })
    }

    /// A bare P-256 key (`pnm keys bundle-key`) installs as an EUDI identity
    /// with no DID and, until its certificate, no `client_id`.
    #[tokio::test]
    async fn a_bare_p256_key_installs_as_an_eudi_identity() {
        let dir = tempfile::tempdir().unwrap();
        let (key, bundle, digest) = sealed_payload(dir.path(), raw_key("p256", &[0x44; 32])).await;
        let record = open_and_select(&key, &bundle, &digest, "eudi", None).unwrap();
        assert_eq!(record.kind, VerifierKind::Eudi);
        assert!(record.did.is_none() && record.kid.is_none());
        assert!(record.client_id().is_none());
        let expected = affinidi_crypto::p256::generate(Some(&[0x44; 32])).unwrap();
        assert_eq!(
            record.public_jwk["x"],
            serde_json::to_value(&expected.jwk).unwrap()["x"]
        );
        LocalP256Signer::from_record(&record).expect("a usable signer");
    }

    #[tokio::test]
    async fn a_bare_key_of_another_type_or_with_kid_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (key, bundle, digest) =
            sealed_payload(dir.path(), raw_key("ed25519", &[0x44; 32])).await;
        let err = open_and_select(&key, &bundle, &digest, "eudi", None).unwrap_err();
        assert!(err.to_string().contains("P-256"), "{err}");

        let dir = tempfile::tempdir().unwrap();
        let (key, bundle, digest) = sealed_payload(dir.path(), raw_key("p256", &[0x44; 32])).await;
        let err = open_and_select(&key, &bundle, &digest, "eudi", Some("x")).unwrap_err();
        assert!(err.to_string().contains("--kid"), "{err}");
    }

    #[test]
    fn identity_names_are_bounded() {
        assert!(check_identity_name("swiyu").is_ok());
        assert!(check_identity_name("../x").is_err());
        assert!(check_identity_name("").is_err());
    }
}
