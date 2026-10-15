//! The `encrypted_file` envelope, format version 1.
//!
//! ```text
//! offset  len   field
//! 0       8     magic            "VTISECF\0"
//! 8       1     format version   1
//! 9       1     AEAD id          1 = AES-256-GCM
//! 10      1     KEK source       1 = passphrase (Argon2id)
//!                                2 = systemd-creds (HKDF-SHA256)
//!                                3 = TPM 2.0 sealed (HKDF-SHA256)
//! 11      1     reserved         0
//! 12      32    salt             Argon2id salt, or HKDF salt
//! 44      12    nonce            AES-GCM nonce
//! 56      2     descriptor len   big-endian u16, at most 8192
//! 58      n     descriptor       the KEK source's parameters (below)
//! 58+n    ...   ciphertext       AES-256-GCM output, tag included (>= 16)
//! ```
//!
//! Everything before the ciphertext is the header, and the whole header is the
//! AEAD's associated data: changing the KDF parameters, the source, the salt or
//! a sealed TPM blob fails the tag check, never decrypts to something else.
//!
//! Descriptors:
//! - passphrase: `m_cost`, `t_cost`, `p_cost` as big-endian u32 (12 bytes);
//! - systemd-creds: empty;
//! - TPM: see [`TpmDescriptor`].
//!
//! A salt and nonce are drawn fresh on every write, so every write uses a fresh
//! file key and a nonce is never reused under a key.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use vti_common::error::AppError;

pub(super) const MAGIC: [u8; 8] = *b"VTISECF\0";
pub(super) const FORMAT_V1: u8 = 1;
pub(super) const AEAD_AES_256_GCM: u8 = 1;
pub(super) const SALT_LEN: usize = 32;
pub(super) const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Length of the header up to (not including) the descriptor.
pub(super) const FIXED_LEN: usize = 8 + 4 + SALT_LEN + NONCE_LEN + 2;
const MAX_DESCRIPTOR_LEN: usize = 8192;
/// No legitimate envelope comes anywhere near this; refusing a larger file
/// keeps a planted multi-gigabyte file from being read into memory.
pub(super) const MAX_FILE_LEN: u64 = 1 << 20;

/// HKDF `info` for the systemd-creds and TPM sources. The source byte is
/// appended, so one KEK used for two sources still yields unrelated file keys.
const HKDF_INFO: &[u8] = b"vti-secrets/encrypted-file/v1\0";

fn malformed(what: impl std::fmt::Display) -> AppError {
    AppError::SecretStore(format!("encrypted secret file is malformed: {what}"))
}

/// Where the key-encryption key comes from, as recorded in the header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum KekKind {
    Passphrase = 1,
    SystemdCreds = 2,
    Tpm = 3,
}

impl KekKind {
    fn from_u8(b: u8) -> Result<Self, AppError> {
        match b {
            1 => Ok(Self::Passphrase),
            2 => Ok(Self::SystemdCreds),
            3 => Ok(Self::Tpm),
            other => Err(malformed(format_args!("unknown KEK source id {other}"))),
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Passphrase => "passphrase",
            Self::SystemdCreds => "systemd_creds",
            Self::Tpm => "tpm",
        }
    }
}

/// The parsed header. Only the salt, nonce and public parameters live here;
/// none of it is secret.
pub(super) struct Header {
    pub kek: KekKind,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub descriptor: Vec<u8>,
}

impl Header {
    pub(super) fn encode(&self) -> Result<Vec<u8>, AppError> {
        let len = u16::try_from(self.descriptor.len())
            .ok()
            .filter(|l| usize::from(*l) <= MAX_DESCRIPTOR_LEN)
            .ok_or_else(|| {
                AppError::SecretStore(format!(
                    "encrypted secret file descriptor too large: {} bytes",
                    self.descriptor.len()
                ))
            })?;
        let mut out = Vec::with_capacity(FIXED_LEN + self.descriptor.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&[FORMAT_V1, AEAD_AES_256_GCM, self.kek as u8, 0]);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.descriptor);
        Ok(out)
    }

    /// Parse the header at the front of `file`, returning it and its length
    /// (the AAD is `file[..len]`). Every deviation is an error.
    pub(super) fn parse(file: &[u8]) -> Result<(Self, usize), AppError> {
        if file.len() < FIXED_LEN {
            return Err(malformed("shorter than the fixed header"));
        }
        if file[..8] != MAGIC {
            return Err(malformed("not an encrypted_file envelope (bad magic)"));
        }
        if file[8] != FORMAT_V1 {
            return Err(AppError::SecretStore(format!(
                "encrypted secret file has unsupported format version {} (this build reads {FORMAT_V1})",
                file[8]
            )));
        }
        if file[9] != AEAD_AES_256_GCM {
            return Err(malformed(format_args!("unknown AEAD id {}", file[9])));
        }
        let kek = KekKind::from_u8(file[10])?;
        if file[11] != 0 {
            return Err(malformed("reserved byte is not zero"));
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&file[12..12 + SALT_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&file[44..44 + NONCE_LEN]);
        let dlen = usize::from(u16::from_be_bytes([file[56], file[57]]));
        if dlen > MAX_DESCRIPTOR_LEN {
            return Err(malformed("descriptor too long"));
        }
        let header_len = FIXED_LEN + dlen;
        if file.len() < header_len + TAG_LEN {
            return Err(malformed("truncated"));
        }
        let descriptor = file[FIXED_LEN..header_len].to_vec();
        Ok((
            Self {
                kek,
                salt,
                nonce,
                descriptor,
            },
            header_len,
        ))
    }
}

/// Encrypt `plaintext` under `key`, returning the complete file contents.
pub(super) fn seal(header: &Header, key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, AppError> {
    let mut out = header.encode()?;
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| AppError::SecretStore(format!("aes key: {e}")))?;
    let nonce = Nonce::try_from(header.nonce.as_slice())
        .map_err(|_| AppError::SecretStore("aes nonce length".into()))?;
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &out,
            },
        )
        .map_err(|e| AppError::SecretStore(format!("encrypting the secret file failed: {e}")))?;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a file whose header (`file[..header_len]`) was parsed as `header`.
/// A wrong key and a modified file are the same error: the tag does not match.
pub(super) fn open(
    file: &[u8],
    header: &Header,
    header_len: usize,
    key: &[u8; 32],
) -> Result<Vec<u8>, AppError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| AppError::SecretStore(format!("aes key: {e}")))?;
    let nonce = Nonce::try_from(header.nonce.as_slice())
        .map_err(|_| AppError::SecretStore("aes nonce length".into()))?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &file[header_len..],
                aad: &file[..header_len],
            },
        )
        .map_err(|_| {
            AppError::SecretStore(
                "cannot decrypt the encrypted secret file: wrong key-encryption key \
                 (passphrase / credential / TPM state) or the file was modified"
                    .into(),
            )
        })
}

/// Argon2id cost parameters, stored as the passphrase descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Argon2Params {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Argon2Params {
    /// What every write uses: 64 MiB, 3 passes, 4 lanes (the profile
    /// `vta-backup` uses for its envelopes).
    pub(super) const WRITE: Self = Self {
        m_cost: 64 * 1024,
        t_cost: 3,
        p_cost: 4,
    };
    /// Floors a file must meet to be read, so a file written with weakened
    /// parameters (by a buggy or hostile writer) is refused rather than
    /// trusted. m >= 64 MiB, t >= 3.
    const MIN_M: u32 = 64 * 1024;
    const MIN_T: u32 = 3;
    const MIN_P: u32 = 1;
    /// Ceilings, so a planted file cannot make a read allocate without bound.
    const MAX_M: u32 = 2 * 1024 * 1024; // 2 GiB
    const MAX_T: u32 = 64;
    const MAX_P: u32 = 16;

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12);
        out.extend_from_slice(&self.m_cost.to_be_bytes());
        out.extend_from_slice(&self.t_cost.to_be_bytes());
        out.extend_from_slice(&self.p_cost.to_be_bytes());
        out
    }

    pub(super) fn decode(d: &[u8]) -> Result<Self, AppError> {
        if d.len() != 12 {
            return Err(malformed("passphrase descriptor must be 12 bytes"));
        }
        let word = |i: usize| u32::from_be_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]);
        let p = Self {
            m_cost: word(0),
            t_cost: word(4),
            p_cost: word(8),
        };
        if !(Self::MIN_M..=Self::MAX_M).contains(&p.m_cost)
            || !(Self::MIN_T..=Self::MAX_T).contains(&p.t_cost)
            || !(Self::MIN_P..=Self::MAX_P).contains(&p.p_cost)
        {
            return Err(malformed(format_args!(
                "Argon2id parameters m={} KiB t={} p={} are outside the accepted range \
                 (m {}..={} KiB, t {}..={}, p {}..={})",
                p.m_cost,
                p.t_cost,
                p.p_cost,
                Self::MIN_M,
                Self::MAX_M,
                Self::MIN_T,
                Self::MAX_T,
                Self::MIN_P,
                Self::MAX_P
            )));
        }
        Ok(p)
    }

    pub(super) fn derive(
        &self,
        passphrase: &[u8],
        salt: &[u8; SALT_LEN],
    ) -> Result<Zeroizing<[u8; 32]>, AppError> {
        let params = argon2::Params::new(self.m_cost, self.t_cost, self.p_cost, Some(32))
            .map_err(|e| AppError::SecretStore(format!("argon2 params: {e}")))?;
        let argon =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut key = Zeroizing::new([0u8; 32]);
        argon
            .hash_password_into(passphrase, salt, key.as_mut())
            .map_err(|e| AppError::SecretStore(format!("argon2: {e}")))?;
        Ok(key)
    }
}

/// File key for the systemd-creds and TPM sources:
/// `HKDF-SHA256(salt, KEK, "vti-secrets/encrypted-file/v1\0" || source)`.
pub(super) fn derive_from_kek(
    kek: &[u8; 32],
    salt: &[u8; SALT_LEN],
    kind: KekKind,
) -> Result<Zeroizing<[u8; 32]>, AppError> {
    let mut info = HKDF_INFO.to_vec();
    info.push(kind as u8);
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), kek)
        .expand(&info, key.as_mut())
        .map_err(|e| AppError::SecretStore(format!("hkdf: {e}")))?;
    Ok(key)
}

/// The TPM source's descriptor: the PCRs the KEK is bound to and the sealed
/// object, as the TPM marshalled it.
///
/// ```text
/// 1   PCR bank      1 = SHA-256
/// 1   PCR count     n (0 = not PCR-bound)
/// n   PCR indexes   ascending, each 0..=23
/// 2   public len    big-endian u16, then TPM2B_PUBLIC contents (marshalled TPMT_PUBLIC)
/// 2   private len   big-endian u16, then TPM2B_PRIVATE contents
/// ```
///
/// The private part is the KEK wrapped by the TPM's storage key; it is only
/// usable inside the same TPM, under the same owner hierarchy seed.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct TpmDescriptor {
    pub pcrs: Vec<u8>,
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

const PCR_BANK_SHA256: u8 = 1;
pub(super) const MAX_PCR: u8 = 23;

impl TpmDescriptor {
    #[cfg_attr(not(all(feature = "tpm", target_os = "linux")), allow(dead_code))]
    pub(super) fn encode(&self) -> Result<Vec<u8>, AppError> {
        let too_big = |what: &str| AppError::SecretStore(format!("TPM {what} blob too large"));
        let pcr_count = u8::try_from(self.pcrs.len()).map_err(|_| too_big("PCR list"))?;
        let pub_len = u16::try_from(self.public.len()).map_err(|_| too_big("public"))?;
        let priv_len = u16::try_from(self.private.len()).map_err(|_| too_big("private"))?;
        let mut out = vec![PCR_BANK_SHA256, pcr_count];
        out.extend_from_slice(&self.pcrs);
        out.extend_from_slice(&pub_len.to_be_bytes());
        out.extend_from_slice(&self.public);
        out.extend_from_slice(&priv_len.to_be_bytes());
        out.extend_from_slice(&self.private);
        Ok(out)
    }

    pub(super) fn decode(d: &[u8]) -> Result<Self, AppError> {
        let bad = |what: &str| malformed(format_args!("TPM descriptor: {what}"));
        let mut rest = d;
        let mut take = |n: usize| -> Result<&[u8], AppError> {
            if rest.len() < n {
                return Err(bad("truncated"));
            }
            let (head, tail) = rest.split_at(n);
            rest = tail;
            Ok(head)
        };
        if take(1)?[0] != PCR_BANK_SHA256 {
            return Err(bad("unsupported PCR bank"));
        }
        let count = usize::from(take(1)?[0]);
        let pcrs = take(count)?.to_vec();
        if pcrs.iter().any(|p| *p > MAX_PCR) || pcrs.windows(2).any(|w| w[0] >= w[1]) {
            return Err(bad("PCR indexes must be ascending and at most 23"));
        }
        let len = take(2)?;
        let pub_len = usize::from(u16::from_be_bytes([len[0], len[1]]));
        let public = take(pub_len)?.to_vec();
        let len = take(2)?;
        let priv_len = usize::from(u16::from_be_bytes([len[0], len[1]]));
        let private = take(priv_len)?.to_vec();
        if !rest.is_empty() {
            return Err(bad("trailing bytes"));
        }
        if public.is_empty() || private.is_empty() {
            return Err(bad("empty sealed object"));
        }
        Ok(Self {
            pcrs,
            public,
            private,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(kek: KekKind, descriptor: Vec<u8>) -> Header {
        Header {
            kek,
            salt: [1; SALT_LEN],
            nonce: [2; NONCE_LEN],
            descriptor,
        }
    }

    #[test]
    fn header_round_trips() {
        let h = header(KekKind::Tpm, vec![9; 40]);
        let mut bytes = h.encode().unwrap();
        bytes.extend_from_slice(&[0; TAG_LEN]);
        let (back, len) = Header::parse(&bytes).unwrap();
        assert_eq!(len, FIXED_LEN + 40);
        assert_eq!(back.kek, KekKind::Tpm);
        assert_eq!(back.salt, h.salt);
        assert_eq!(back.nonce, h.nonce);
        assert_eq!(back.descriptor, h.descriptor);
    }

    #[test]
    fn malformed_headers_are_errors() {
        let good = {
            let mut b = header(KekKind::SystemdCreds, vec![]).encode().unwrap();
            b.extend_from_slice(&[0; TAG_LEN]);
            b
        };
        let mutate = |i: usize, v: u8| {
            let mut b = good.clone();
            b[i] = v;
            b
        };
        for (bytes, needle) in [
            (good[..10].to_vec(), "shorter"),
            (mutate(0, b'X'), "magic"),
            (mutate(8, 2), "version 2"),
            (mutate(9, 7), "AEAD"),
            (mutate(10, 9), "KEK source"),
            (mutate(11, 1), "reserved"),
            (mutate(57, 1), "truncated"),
            (good[..FIXED_LEN + TAG_LEN - 1].to_vec(), "truncated"),
        ] {
            match Header::parse(&bytes) {
                Err(AppError::SecretStore(m)) => assert!(m.contains(needle), "{needle}: {m}"),
                Err(other) => panic!("{needle}: wrong error kind {other:?}"),
                Ok(_) => panic!("{needle}: parsed"),
            }
        }
    }

    #[test]
    fn seal_open_round_trip_and_tag_covers_the_header() {
        let key = [7u8; 32];
        let h = header(KekKind::SystemdCreds, vec![]);
        let file = seal(&h, &key, b"secret seed").unwrap();
        let (parsed, len) = Header::parse(&file).unwrap();
        assert_eq!(open(&file, &parsed, len, &key).unwrap(), b"secret seed");

        // Flip a salt byte: the header still parses, the tag fails.
        let mut tampered = file.clone();
        tampered[20] ^= 1;
        let (parsed, len) = Header::parse(&tampered).unwrap();
        assert!(open(&tampered, &parsed, len, &key).is_err());

        // Wrong key.
        let (parsed, len) = Header::parse(&file).unwrap();
        assert!(open(&file, &parsed, len, &[8u8; 32]).is_err());
    }

    #[test]
    fn argon2_params_enforce_floors_and_ceilings() {
        assert_eq!(
            Argon2Params::decode(&Argon2Params::WRITE.encode()).unwrap(),
            Argon2Params::WRITE
        );
        for weak in [
            Argon2Params {
                m_cost: 64 * 1024 - 1,
                ..Argon2Params::WRITE
            },
            Argon2Params {
                t_cost: 2,
                ..Argon2Params::WRITE
            },
            Argon2Params {
                p_cost: 0,
                ..Argon2Params::WRITE
            },
            Argon2Params {
                m_cost: u32::MAX,
                ..Argon2Params::WRITE
            },
        ] {
            assert!(Argon2Params::decode(&weak.encode()).is_err(), "{weak:?}");
        }
        assert!(Argon2Params::decode(&[0; 11]).is_err());
    }

    #[test]
    fn hkdf_separates_sources() {
        let kek = [3u8; 32];
        let salt = [4u8; SALT_LEN];
        let a = derive_from_kek(&kek, &salt, KekKind::SystemdCreds).unwrap();
        let b = derive_from_kek(&kek, &salt, KekKind::Tpm).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn tpm_descriptor_round_trips_and_rejects_bad_input() {
        let d = TpmDescriptor {
            pcrs: vec![0, 7, 23],
            public: vec![1; 50],
            private: vec![2; 70],
        };
        let bytes = d.encode().unwrap();
        assert!(TpmDescriptor::decode(&bytes).unwrap() == d);

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(TpmDescriptor::decode(&trailing).is_err());
        assert!(TpmDescriptor::decode(&bytes[..bytes.len() - 1]).is_err());

        let mut bank = bytes.clone();
        bank[0] = 2;
        assert!(TpmDescriptor::decode(&bank).is_err());

        let unsorted = TpmDescriptor {
            pcrs: vec![7, 0],
            ..d.clone()
        };
        assert!(TpmDescriptor::decode(&unsorted.encode().unwrap()).is_err());
        let out_of_range = TpmDescriptor {
            pcrs: vec![24],
            ..d.clone()
        };
        assert!(TpmDescriptor::decode(&out_of_range.encode().unwrap()).is_err());
        let empty = TpmDescriptor {
            public: vec![],
            ..d
        };
        assert!(TpmDescriptor::decode(&empty.encode().unwrap()).is_err());
    }
}
