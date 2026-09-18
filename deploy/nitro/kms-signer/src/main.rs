// KMS-backed signer for VTA Nitro Enclave images.
//
// Two subcommands:
//   mint-cert  — build an X.509 cert whose public key is a non-exportable KMS
//                asymmetric key, self-signed via kms:Sign. Nitro measures this
//                cert into PCR8.
//   sign-eif   — sign an existing EIF. The `--key` may be a KMS key ARN (the
//                private key never leaves KMS) or a local PEM key path. The
//                heavy lifting (COSE_Sign1 over PCR0, DER→r‖s, section splice,
//                CRC) is done by aws-nitro-enclaves-image-format.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use aws_nitro_enclaves_image_format::utils::eif_signer::{EifSigner, SignKeyData};

use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};

use const_oid::db::rfc5912::ECDSA_WITH_SHA_384;
use der::asn1::{BitString, UtcTime};
use der::{Decode, DecodePem, Encode, EncodePem};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::time::{Time, Validity};

const CERT_SUBJECT: &str = "CN=VTA Enclave Signing Key,O=Verifiable Trust Infrastructure";
const CERT_VALIDITY_SECS: u64 = 3650 * 24 * 3600; // 10 years

#[derive(Parser)]
#[command(name = "kms-signer", about = "KMS-backed Nitro EIF signer")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Mint the PCR8 certificate carrying the KMS public key (self-signed via kms:Sign).
    MintCert {
        /// KMS key ARN or key id (ECC_NIST_P384, SIGN_VERIFY).
        #[arg(long)]
        key_arn: String,
        /// AWS region (defaults to the environment/profile region).
        #[arg(long)]
        region: Option<String>,
        /// Output certificate path (PEM).
        #[arg(long, default_value = "signing-cert.pem")]
        out: PathBuf,
    },
    /// Sign an existing EIF in place using a KMS key ARN or a local PEM key.
    SignEif {
        /// KMS key ARN, or a path to a local private key PEM.
        #[arg(long)]
        key: String,
        /// Signing certificate PEM (must carry the same public key as `--key`).
        #[arg(long)]
        cert: PathBuf,
        /// Path to the EIF to sign in place.
        #[arg(long)]
        eif: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        // KMS calls need an async context; the crate's EIF signer must NOT run
        // inside a Tokio runtime (it spawns its own), so only mint-cert uses one.
        Command::MintCert {
            key_arn,
            region,
            out,
        } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(mint_cert(&key_arn, region.as_deref(), &out))
        }
        Command::SignEif { key, cert, eif } => sign_eif(&key, &cert, &eif),
    }
}

fn sign_eif(key: &str, cert: &PathBuf, eif: &PathBuf) -> Result<()> {
    let eif_str = eif
        .to_str()
        .ok_or_else(|| anyhow!("EIF path is not valid UTF-8"))?;

    // SignKeyData::new auto-detects a KMS ARN vs. a local key path.
    let key_data = SignKeyData::new(key, cert.as_path())
        .map_err(|e| anyhow!("failed to load signing key/cert: {e}"))?;
    let signer =
        EifSigner::new(Some(key_data)).ok_or_else(|| anyhow!("failed to construct EifSigner"))?;

    signer
        .sign_image(eif_str)
        .map_err(|e| anyhow!("failed to sign EIF: {e}"))?;

    println!("Signed EIF: {}", eif_str);
    Ok(())
}

async fn mint_cert(key_arn: &str, region: Option<&str>, out: &PathBuf) -> Result<()> {
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Some(r) = region {
        loader = loader.region(aws_config::Region::new(r.to_string()));
    }
    let conf = loader.load().await;
    let kms = aws_sdk_kms::Client::new(&conf);

    // 1. Fetch the KMS public key (DER SubjectPublicKeyInfo for asymmetric keys).
    let pk = kms
        .get_public_key()
        .key_id(key_arn)
        .send()
        .await
        .context("kms:GetPublicKey failed")?;
    let spki_der = pk
        .public_key()
        .ok_or_else(|| anyhow!("KMS returned no public key"))?
        .as_ref()
        .to_vec();
    let spki = SubjectPublicKeyInfoOwned::from_der(&spki_der)
        .context("failed to parse KMS public key SPKI")?;

    // 2. Assemble the TBSCertificate (self-issued, self-subject).
    let name: Name = CERT_SUBJECT
        .parse()
        .context("invalid certificate subject")?;
    let sig_alg = AlgorithmIdentifierOwned {
        oid: ECDSA_WITH_SHA_384,
        parameters: None,
    };
    // RFC 5280 requires UTCTime (not GeneralizedTime) for validity dates before
    // 2050; encode explicitly so openssl and other verifiers can parse the cert.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before epoch")?
        .as_secs();
    let validity = Validity {
        not_before: Time::UtcTime(
            UtcTime::from_unix_duration(std::time::Duration::from_secs(now_secs))
                .context("not_before time")?,
        ),
        not_after: Time::UtcTime(
            UtcTime::from_unix_duration(std::time::Duration::from_secs(
                now_secs + CERT_VALIDITY_SECS,
            ))
            .context("not_after time")?,
        ),
    };
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[0x01]).context("serial number")?,
        signature: sig_alg.clone(),
        issuer: name.clone(),
        validity,
        subject: name,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None,
    };

    // 3. Sign the DER-encoded TBS via KMS. KMS hashes with SHA-384 and returns a
    //    DER ECDSA-Sig-Value — exactly the X.509 signature encoding.
    let tbs_der = tbs.to_der().context("encode TBSCertificate")?;
    let sig = kms
        .sign()
        .key_id(key_arn)
        .message(Blob::new(tbs_der))
        .message_type(MessageType::Raw)
        .signing_algorithm(SigningAlgorithmSpec::EcdsaSha384)
        .send()
        .await
        .context("kms:Sign failed")?;
    let sig_der = sig
        .signature()
        .ok_or_else(|| anyhow!("KMS returned no signature"))?
        .as_ref()
        .to_vec();

    // 4. Assemble the final certificate and write PEM.
    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(&sig_der).context("wrap signature bitstring")?,
    };
    let pem = cert
        .to_pem(der::pem::LineEnding::LF)
        .context("encode certificate PEM")?;
    std::fs::write(out, pem).with_context(|| format!("write {}", out.display()))?;

    // Sanity: re-parse what we wrote.
    let written = std::fs::read_to_string(out)?;
    Certificate::from_pem(written.as_bytes()).context("re-parse minted certificate")?;

    println!("Wrote certificate: {}", out.display());
    Ok(())
}
