//! Files in a room: the file key, the STREAM construction, and the blob manifest.
//!
//! A file is a record plus a blob. The record is an ordinary room record whose sealed body
//! carries a [`FileManifest`]; the blob is the file's ciphertext, held outside the record by
//! whatever store the host uses, and named on the record by its [`blob_ref`]. Normative
//! source: `rooms/_shared/0.1/blobs.schema.json` (`FileManifest`, `BlobManifest`,
//! `BlobRef`) in `dtgwg-trust-tasks-tf`, and `docs/05-design-notes/data-rooms-files.md` §3.
//!
//! # The file key
//!
//! ```text
//! file_key = HKDF-SHA256(ikm  = storage_key(epoch),
//!                        salt = fileId,
//!                        info = "openvtc/room/file/v1" || roomId || u64be(epoch))
//! ```
//!
//! Derived per file and never stored. `fileId` is its 32 raw bytes (the manifest carries
//! them base64url) and `roomId` its UTF-8 bytes. Bound to the room and the epoch, so a key
//! released for one room cannot open a blob relocated from another, and releasing one
//! exposes one file: `storage_key` cannot be recovered from it, so no sibling can be
//! derived.
//!
//! # The STREAM construction
//!
//! The plaintext is cut into `segment_size` segments, the last holding the remainder (an
//! empty file is one empty final segment). Segment `i` is sealed with ChaCha20-Poly1305,
//! the AEAD records already use, under
//!
//! ```text
//! nonce_i = u32be(0) || u64be(i)
//! aad_i   = "openvtc/room/file/v1" || roomId || fileId || u64be(epoch) || u64be(i) || u8(final)
//! ```
//!
//! `final` is 1 on the last segment only, so a host that truncates, reorders or splices
//! ciphertext produces an authentication failure, never a shorter or rearranged file. This
//! is the online-AE STREAM construction of Hoang, Reyhanitabar, Rogaway and Vizár, the shape
//! `age` and Tink's streaming AEAD use. The nonces are counters, so a file key must never
//! seal two files; the fresh random `fileId` is what guarantees it.
//!
//! One sealed segment is one transfer chunk, so `segment_size + 16` is the blob's
//! `chunkSize`. The transfer ceiling of 262144 bytes per chunk therefore puts the largest
//! segment at 262128, and the 4096-chunk ceiling caps a blob at 1 GiB of ciphertext.
//!
//! # Which half needs which part
//!
//! The manifest, the digests and Padmé are plain arithmetic and build everywhere, because a
//! host checks manifests and digests without holding any key. The key derivation and the
//! sealer and opener sit behind the `files` feature, which `mls` implies: a party handed one
//! file's key (a CLI, the wallet extension) needs them and not OpenMLS.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// The domain label of the file key and every segment's associated data.
pub const FILE_LABEL: &[u8] = b"openvtc/room/file/v1";

/// ChaCha20-Poly1305's tag: what sealing adds to each segment.
pub const TAG_LEN: usize = 16;

/// The smallest segment: the transfer floor of 16384 bytes per chunk, less the tag.
pub const MIN_SEGMENT_SIZE: usize = 16_368;

/// The largest segment: the transfer ceiling of 262144 bytes per chunk, less the tag.
pub const MAX_SEGMENT_SIZE: usize = 262_128;

/// The segment size a sealer uses unless told otherwise: one full transfer chunk.
pub const DEFAULT_SEGMENT_SIZE: usize = MAX_SEGMENT_SIZE;

/// The most chunks a blob may have.
pub const MAX_CHUNKS: u64 = 4096;

/// What can go wrong building, sealing or opening a file.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FileError {
    /// A segment size outside `MIN_SEGMENT_SIZE..=MAX_SEGMENT_SIZE`.
    #[error("segment size {0} is outside {MIN_SEGMENT_SIZE}..={MAX_SEGMENT_SIZE}")]
    SegmentSize(usize),

    /// A file that needs more than [`MAX_CHUNKS`] segments at this segment size.
    #[error("the file needs {0} segments; a blob holds at most {MAX_CHUNKS}")]
    TooLarge(u64),

    /// A segment of the wrong length for its position, or one sealed after the final one.
    #[error("segment {index}: {why}")]
    Segment { index: u64, why: &'static str },

    /// A segment did not authenticate.
    ///
    /// One variant for every reason, as for a record: the AEAD cannot distinguish a wrong
    /// key from a relocated, truncated, reordered or spliced blob, and a caller acting on a
    /// guess would be acting on nothing.
    #[error(
        "segment {0} did not open: wrong key, or the blob was relocated, truncated, reordered \
         or spliced"
    )]
    DidNotOpen(u64),

    /// The decrypted file is not the one its author signed.
    #[error("the decrypted file does not match the digest its author signed")]
    DigestMismatch,

    /// Padding that is not zero bytes, or a size larger than what was decrypted.
    #[error("bad padding: {0}")]
    Padding(&'static str),

    /// The opener ended before the final segment.
    #[error("the blob ended after {seen} of {expected} segments")]
    Incomplete { seen: u64, expected: u64 },

    /// A value on the wire that does not decode.
    #[error("{0}")]
    Decode(String),
}

// ─── Digests ─────────────────────────────────────────────────────────────

/// `DigestMultibase` of `bytes`: a sha2-256 multihash, base58btc.
#[must_use]
pub fn digest_multibase(bytes: &[u8]) -> String {
    crate::merkle::to_multibase(&Sha256::digest(bytes).into())
}

/// `DigestMultibase` of a hash already computed.
#[must_use]
pub fn hash_multibase(hash: [u8; 32]) -> String {
    crate::merkle::to_multibase(&hash)
}

/// A blob's `BlobRef`: the digest of its manifest's RFC 8785 (JCS) canonicalization.
///
/// Generic over the manifest's type because the generated bindings carry one copy of the
/// shared `BlobManifest` per task module (`rooms/blobs/upload/begin` and `rooms/blobs/get`
/// each have their own), and both must produce the same reference. What is hashed is the
/// JSON, so the Rust type does not matter as long as it serializes to the schema.
pub fn blob_ref<T: Serialize>(manifest: &T) -> Result<String, FileError> {
    let canonical = serde_json_canonicalizer::to_string(manifest)
        .map_err(|e| FileError::Decode(format!("canonicalize the manifest: {e}")))?;
    Ok(digest_multibase(canonical.as_bytes()))
}

/// Compare two `DigestMultibase` values as decoded multihash bytes, never as strings.
///
/// The same digest has a base58btc and a base64url spelling, and both are conforming.
pub fn same_digest(a: &str, b: &str) -> bool {
    match (multibase::decode(a), multibase::decode(b)) {
        (Ok((_, a)), Ok((_, b))) => a == b,
        _ => false,
    }
}

// ─── Manifests ───────────────────────────────────────────────────────────

/// A blob's ciphertext manifest, as `rooms/_shared/0.1/blobs.schema.json` defines
/// `BlobManifest`.
///
/// Not a task payload, so not a generated type: the generated bindings copy this shared
/// definition into every module that names it, and [`blob_ref`] works on any of them.
/// Convert to a generated one through serde when a request needs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlobManifest {
    /// Ciphertext bytes, padding included.
    pub size: u64,
    pub chunks: ChunkManifest,
    /// Digest of the whole ciphertext.
    pub digest: String,
}

/// The chunk terms of a [`BlobManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChunkManifest {
    pub chunk_size: u64,
    pub chunk_count: u64,
    pub chunk_digests: Vec<String>,
}

impl BlobManifest {
    /// This manifest's `BlobRef`.
    pub fn blob_ref(&self) -> Result<String, FileError> {
        blob_ref(self)
    }

    /// The rules JSON Schema cannot state: `chunkCount` is ceil(size / chunkSize), and
    /// there is one digest per chunk.
    pub fn check(&self) -> Result<(), FileError> {
        let c = &self.chunks;
        if c.chunk_size == 0 || self.size == 0 {
            return Err(FileError::Decode("an empty blob or chunk size".into()));
        }
        if c.chunk_count != self.size.div_ceil(c.chunk_size) {
            return Err(FileError::Decode(format!(
                "chunkCount {} is not ceil({} / {})",
                c.chunk_count, self.size, c.chunk_size
            )));
        }
        if c.chunk_digests.len() as u64 != c.chunk_count {
            return Err(FileError::Decode(format!(
                "{} chunk digests for {} chunks",
                c.chunk_digests.len(),
                c.chunk_count
            )));
        }
        if c.chunk_count > MAX_CHUNKS {
            return Err(FileError::TooLarge(c.chunk_count));
        }
        Ok(())
    }
}

/// Builds a [`BlobManifest`] from sealed chunks, as they are produced.
#[derive(Default)]
pub struct ManifestBuilder {
    chunk_size: u64,
    digests: Vec<String>,
    whole: Sha256,
    size: u64,
}

impl ManifestBuilder {
    /// For a blob whose chunks are `chunk_size` bytes, all but the last.
    pub fn new(chunk_size: u64) -> Self {
        Self {
            chunk_size,
            ..Self::default()
        }
    }

    /// Add the next chunk, in order.
    pub fn push(&mut self, chunk: &[u8]) {
        self.digests.push(digest_multibase(chunk));
        self.whole.update(chunk);
        self.size += chunk.len() as u64;
    }

    /// The manifest, checked.
    pub fn finish(self) -> Result<BlobManifest, FileError> {
        let manifest = BlobManifest {
            size: self.size,
            chunks: ChunkManifest {
                chunk_size: self.chunk_size,
                chunk_count: self.digests.len() as u64,
                chunk_digests: self.digests,
            },
            digest: hash_multibase(self.whole.finalize().into()),
        };
        manifest.check()?;
        Ok(manifest)
    }
}

/// The sealed body's `file` member: everything that describes a file, sealed with the
/// record and signed by its author. `FileManifest` in `rooms/_shared/0.1/blobs.schema.json`.
///
/// Client-to-client: no host task carries it, because a host receives only ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileManifest {
    /// 32 random bytes, base64url without padding.
    pub file_id: String,
    /// Untrusted text: strip path separators before using it as a local file name.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// Plaintext bytes, before padding.
    pub size: u64,
    /// Digest of the plaintext.
    pub digest: String,
    pub epoch: u64,
    pub segment_size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub padding: Option<Padding>,
    pub blob_ref: String,
}

impl FileManifest {
    /// The `fileId` as its 32 bytes.
    pub fn file_id_bytes(&self) -> Result<FileId, FileError> {
        decode_file_id(&self.file_id)
    }

    /// Whether the plaintext was padded before sealing. Absent means [`Padding::None`].
    pub fn padding(&self) -> Padding {
        self.padding.unwrap_or(Padding::None)
    }

    /// The length of the plaintext as sealed: `padme(size)` when padded, else `size`.
    #[must_use]
    pub fn padded_len(&self) -> u64 {
        match self.padding() {
            Padding::None => self.size,
            Padding::Padme => padme_len(self.size),
        }
    }

    /// The checks a reader makes before trusting a byte of `blob`, from
    /// `FileManifest`'s *Reading* rules: the blob is the one this manifest's author named,
    /// it is self-consistent, its `chunkSize` is `segmentSize + 16`, and its `chunkCount`
    /// is `max(1, ceil(paddedLength / segmentSize))`.
    pub fn check_blob(&self, blob: &BlobManifest) -> Result<(), FileError> {
        blob.check()?;
        if !same_digest(&blob.blob_ref()?, &self.blob_ref) {
            return Err(FileError::Decode(
                "the blob manifest is not the one the file's author named".into(),
            ));
        }
        let segment =
            usize::try_from(self.segment_size).map_err(|_| FileError::SegmentSize(usize::MAX))?;
        check_segment_size(segment)?;
        if blob.chunks.chunk_size != self.segment_size + TAG_LEN as u64 {
            return Err(FileError::Decode(format!(
                "chunkSize {} is not segmentSize {} + {TAG_LEN}",
                blob.chunks.chunk_size, self.segment_size
            )));
        }
        let expected = segment_count(self.padded_len(), segment);
        if blob.chunks.chunk_count != expected {
            return Err(FileError::Decode(format!(
                "chunkCount {} is not the {expected} a {}-byte plaintext in {segment}-byte \
                 segments needs",
                blob.chunks.chunk_count,
                self.padded_len()
            )));
        }
        if blob.size != self.padded_len() + expected * TAG_LEN as u64 {
            return Err(FileError::Decode(format!(
                "a {}-byte blob cannot hold a {}-byte plaintext in {expected} segments",
                blob.size,
                self.padded_len()
            )));
        }
        Ok(())
    }
}

/// How the plaintext was padded before sealing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Padding {
    None,
    Padme,
}

/// A file's identifier: 32 random bytes, the salt of its key.
pub type FileId = [u8; 32];

/// The `fileId` member's 32 bytes.
pub fn decode_file_id(encoded: &str) -> Result<FileId, FileError> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| FileError::Decode(format!("fileId is not base64url: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| FileError::Decode("fileId is not 32 bytes".into()))
}

/// The `fileId` member for 32 bytes.
#[must_use]
pub fn encode_file_id(id: &FileId) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id)
}

// ─── Padmé ───────────────────────────────────────────────────────────────

/// The Padmé length for `len`: at most 12 % larger, and leaking O(log log len) bits.
///
/// Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and Communication with
/// PURBs" (PETS 2019).
#[must_use]
pub fn padme_len(len: u64) -> u64 {
    if len < 2 {
        return len;
    }
    let e = 63 - u64::from(len.leading_zeros()); // floor(log2 len)
    let s = 64 - u64::from(e.leading_zeros()); // floor(log2 e) + 1
    let last_bits = e - s;
    let mask = (1u64 << last_bits) - 1;
    (len + mask) & !mask
}

// ─── Segment arithmetic ──────────────────────────────────────────────────

/// How many segments a plaintext of `len` bytes needs: at least one, so that an empty file
/// is one empty final segment.
#[must_use]
pub fn segment_count(len: u64, segment_size: usize) -> u64 {
    len.div_ceil(segment_size as u64).max(1)
}

/// Refuse a segment size outside `MIN_SEGMENT_SIZE..=MAX_SEGMENT_SIZE`.
pub fn check_segment_size(segment_size: usize) -> Result<(), FileError> {
    if (MIN_SEGMENT_SIZE..=MAX_SEGMENT_SIZE).contains(&segment_size) {
        Ok(())
    } else {
        Err(FileError::SegmentSize(segment_size))
    }
}

#[cfg(feature = "files")]
pub use keyed::*;

#[cfg(feature = "files")]
mod keyed {
    use super::*;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use hkdf::Hkdf;

    /// A room's per-epoch storage key — `retention::StorageKey`, restated so this half
    /// builds without the group layer.
    pub type StorageKey = [u8; 32];

    /// One file's key. Opens that file and nothing else.
    pub type FileKey = [u8; 32];

    /// A fresh `fileId`. Never reuse one: the segment nonces are counters.
    pub fn new_file_id() -> FileId {
        let mut id = [0u8; 32];
        getrandom::fill(&mut id).expect("OS randomness unavailable");
        id
    }

    /// Derive one file's key from the room's storage key for `epoch`.
    #[must_use]
    pub fn derive_file_key(
        storage_key: &StorageKey,
        room_id: &str,
        file_id: &FileId,
        epoch: u64,
    ) -> FileKey {
        let mut info = Vec::with_capacity(FILE_LABEL.len() + room_id.len() + 8);
        info.extend_from_slice(FILE_LABEL);
        info.extend_from_slice(room_id.as_bytes());
        info.extend_from_slice(&epoch.to_be_bytes());
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(file_id), storage_key)
            .expand(&info, &mut key)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        key
    }

    /// What binds a file's segments to their place: the room, the file and the epoch.
    #[derive(Debug, Clone)]
    pub struct FileBinding {
        pub room_id: String,
        pub file_id: FileId,
        pub epoch: u64,
        pub segment_size: usize,
    }

    impl FileBinding {
        fn nonce(index: u64) -> Nonce {
            let mut n = [0u8; 12];
            n[4..].copy_from_slice(&index.to_be_bytes());
            Nonce::from(n)
        }

        fn aad(&self, index: u64, last: bool) -> Vec<u8> {
            let mut aad = Vec::with_capacity(FILE_LABEL.len() + self.room_id.len() + 32 + 17);
            aad.extend_from_slice(FILE_LABEL);
            aad.extend_from_slice(self.room_id.as_bytes());
            aad.extend_from_slice(&self.file_id);
            aad.extend_from_slice(&self.epoch.to_be_bytes());
            aad.extend_from_slice(&index.to_be_bytes());
            aad.push(u8::from(last));
            aad
        }

        /// The transfer chunk size: one sealed segment.
        #[must_use]
        pub fn chunk_size(&self) -> u64 {
            (self.segment_size + TAG_LEN) as u64
        }
    }

    /// Seals a file one segment at a time, in order.
    ///
    /// Every segment but the last is exactly `segment_size` bytes; the last holds the
    /// remainder (zero bytes only for an empty file). A segment after the final one is
    /// refused, which is what makes a reused sealer a loud error rather than a nonce reuse.
    pub struct FileSealer {
        cipher: ChaCha20Poly1305,
        binding: FileBinding,
        index: u64,
        done: bool,
        manifest: ManifestBuilder,
    }

    impl FileSealer {
        pub fn new(key: &FileKey, binding: FileBinding) -> Result<Self, FileError> {
            check_segment_size(binding.segment_size)?;
            Ok(Self {
                cipher: ChaCha20Poly1305::new(&Key::from(*key)),
                manifest: ManifestBuilder::new(binding.chunk_size()),
                binding,
                index: 0,
                done: false,
            })
        }

        /// Seal the next segment. `last` marks the final one.
        pub fn seal_segment(&mut self, plaintext: &[u8], last: bool) -> Result<Vec<u8>, FileError> {
            let index = self.index;
            if self.done {
                return Err(FileError::Segment {
                    index,
                    why: "the final segment has already been sealed",
                });
            }
            let size = self.binding.segment_size;
            if !last && plaintext.len() != size {
                return Err(FileError::Segment {
                    index,
                    why: "every segment but the last is exactly the segment size",
                });
            }
            if last && plaintext.len() > size {
                return Err(FileError::Segment {
                    index,
                    why: "the final segment is larger than the segment size",
                });
            }
            if last && plaintext.is_empty() && index > 0 {
                return Err(FileError::Segment {
                    index,
                    why: "only an empty file has an empty final segment",
                });
            }
            if index + 1 > MAX_CHUNKS {
                return Err(FileError::TooLarge(index + 1));
            }
            let sealed = self
                .cipher
                .encrypt(
                    &FileBinding::nonce(index),
                    Payload {
                        msg: plaintext,
                        aad: &self.binding.aad(index, last),
                    },
                )
                .map_err(|_| FileError::Segment {
                    index,
                    why: "the AEAD refused to seal",
                })?;
            self.manifest.push(&sealed);
            self.index += 1;
            self.done = last;
            Ok(sealed)
        }

        /// The blob's manifest, once the final segment is sealed.
        pub fn finish(self) -> Result<BlobManifest, FileError> {
            if !self.done {
                return Err(FileError::Segment {
                    index: self.index,
                    why: "finished before the final segment",
                });
            }
            self.manifest.finish()
        }
    }

    /// Opens a file one sealed segment (one transfer chunk) at a time, in order.
    ///
    /// The segment count comes from the blob's manifest, which its author signed through
    /// the `blobRef` in the sealed record. A host that lies about it gains nothing: the
    /// segment it calls final was sealed non-final, or the reverse, and does not open.
    pub struct FileOpener {
        cipher: ChaCha20Poly1305,
        binding: FileBinding,
        expected: u64,
        index: u64,
    }

    impl FileOpener {
        pub fn new(
            key: &FileKey,
            binding: FileBinding,
            chunk_count: u64,
        ) -> Result<Self, FileError> {
            check_segment_size(binding.segment_size)?;
            if chunk_count == 0 || chunk_count > MAX_CHUNKS {
                return Err(FileError::TooLarge(chunk_count));
            }
            Ok(Self {
                cipher: ChaCha20Poly1305::new(&Key::from(*key)),
                binding,
                expected: chunk_count,
                index: 0,
            })
        }

        /// Open the next segment.
        pub fn open_segment(&mut self, sealed: &[u8]) -> Result<Vec<u8>, FileError> {
            let index = self.index;
            if index >= self.expected {
                return Err(FileError::Segment {
                    index,
                    why: "more segments than the manifest names",
                });
            }
            let last = index + 1 == self.expected;
            let plain = self
                .cipher
                .decrypt(
                    &FileBinding::nonce(index),
                    Payload {
                        msg: sealed,
                        aad: &self.binding.aad(index, last),
                    },
                )
                .map_err(|_| FileError::DidNotOpen(index))?;
            if !last && plain.len() != self.binding.segment_size {
                return Err(FileError::Segment {
                    index,
                    why: "a segment before the last is not the segment size",
                });
            }
            self.index += 1;
            Ok(plain)
        }

        /// Whether every segment has been opened.
        pub fn finish(self) -> Result<(), FileError> {
            if self.index == self.expected {
                Ok(())
            } else {
                Err(FileError::Incomplete {
                    seen: self.index,
                    expected: self.expected,
                })
            }
        }
    }

    /// Seals a file as it arrives, in pieces of any size, emitting whole chunks.
    ///
    /// Takes the plaintext's total size up front, which a browser `File` and a local file
    /// both know. That is what lets it tell the final segment from the others without
    /// holding one back, and what lets it pad with Padmé, whose length depends on the size.
    pub struct StreamSealer {
        sealer: FileSealer,
        binding: FileBinding,
        buf: Vec<u8>,
        size: u64,
        padded: u64,
        received: u64,
        count: u64,
        emitted: u64,
        hasher: Sha256,
        name: String,
        media_type: Option<String>,
        padding: Padding,
    }

    impl StreamSealer {
        pub fn new(
            key: &FileKey,
            binding: FileBinding,
            size: u64,
            padding: Padding,
            name: &str,
            media_type: Option<&str>,
        ) -> Result<Self, FileError> {
            let padded = match padding {
                Padding::None => size,
                Padding::Padme => padme_len(size),
            };
            let count = segment_count(padded, binding.segment_size);
            if count > MAX_CHUNKS {
                return Err(FileError::TooLarge(count));
            }
            Ok(Self {
                sealer: FileSealer::new(key, binding.clone())?,
                binding,
                buf: Vec::new(),
                size,
                padded,
                received: 0,
                count,
                emitted: 0,
                hasher: Sha256::new(),
                name: name.to_string(),
                media_type: media_type.map(str::to_string),
                padding,
            })
        }

        /// How many chunks the sealed blob will have.
        #[must_use]
        pub fn chunk_count(&self) -> u64 {
            self.count
        }

        /// Feed the next plaintext bytes; returns the chunks they completed, in order.
        pub fn push(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>, FileError> {
            self.received += data.len() as u64;
            if self.received > self.size {
                return Err(FileError::Segment {
                    index: self.emitted,
                    why: "more plaintext than the declared size",
                });
            }
            self.hasher.update(data);
            self.buf.extend_from_slice(data);
            let seg = self.binding.segment_size;
            let mut out = Vec::new();
            while self.buf.len() >= seg && self.emitted + 1 < self.count {
                let rest = self.buf.split_off(seg);
                out.push(self.sealer.seal_segment(&self.buf, false)?);
                self.buf = rest;
                self.emitted += 1;
            }
            Ok(out)
        }

        /// Seal what remains: the final chunks, the blob's manifest, and the file's.
        pub fn finish(mut self) -> Result<(Vec<Vec<u8>>, BlobManifest, FileManifest), FileError> {
            if self.received != self.size {
                return Err(FileError::Incomplete {
                    seen: self.received,
                    expected: self.size,
                });
            }
            self.buf
                .resize(self.buf.len() + (self.padded - self.size) as usize, 0);
            let seg = self.binding.segment_size;
            let mut out = Vec::new();
            while self.emitted + 1 < self.count {
                let rest = self.buf.split_off(seg);
                out.push(self.sealer.seal_segment(&self.buf, false)?);
                self.buf = rest;
                self.emitted += 1;
            }
            out.push(self.sealer.seal_segment(&self.buf, true)?);
            let blob = self.sealer.finish()?;
            let file = FileManifest {
                file_id: encode_file_id(&self.binding.file_id),
                name: self.name,
                media_type: self.media_type,
                size: self.size,
                digest: hash_multibase(self.hasher.finalize().into()),
                epoch: self.binding.epoch,
                segment_size: self.binding.segment_size as u64,
                padding: (self.padding == Padding::Padme).then_some(Padding::Padme),
                blob_ref: blob.blob_ref()?,
            };
            Ok((out, blob, file))
        }
    }

    /// Opens a file chunk by chunk, emitting plaintext with the padding removed.
    ///
    /// Each chunk authenticates on its own, so what it emits was sealed under this file's
    /// key; but the file is only the one its author signed once [`StreamOpener::finish`]
    /// has checked the digest. **A caller must not treat the file as received until then**:
    /// write to a temporary place and move it into view after `finish` succeeds.
    pub struct StreamOpener {
        opener: FileOpener,
        size: u64,
        padded: u64,
        position: u64,
        hasher: Sha256,
        digest: String,
    }

    impl StreamOpener {
        /// For the file `file` describes, stored as `blob`.
        ///
        /// Runs [`FileManifest::check_blob`] first, so no byte is opened from a blob whose
        /// shape the author's manifest does not account for.
        pub fn new(
            key: &FileKey,
            room_id: &str,
            file: &FileManifest,
            blob: &BlobManifest,
        ) -> Result<Self, FileError> {
            file.check_blob(blob)?;
            let segment_size = file.segment_size as usize;
            let padded = file.padded_len();
            let chunk_count = blob.chunks.chunk_count;
            let binding = FileBinding {
                room_id: room_id.to_string(),
                file_id: file.file_id_bytes()?,
                epoch: file.epoch,
                segment_size,
            };
            Ok(Self {
                opener: FileOpener::new(key, binding, chunk_count)?,
                size: file.size,
                padded,
                position: 0,
                hasher: Sha256::new(),
                digest: file.digest.clone(),
            })
        }

        /// Open the next chunk; returns its plaintext, with any padding removed.
        pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, FileError> {
            let mut plain = self.opener.open_segment(chunk)?;
            let start = self.position;
            self.position += plain.len() as u64;
            if self.position > self.padded {
                return Err(FileError::Padding("more plaintext than the manifest names"));
            }
            if self.position > self.size {
                let keep = self.size.saturating_sub(start) as usize;
                if plain[keep..].iter().any(|b| *b != 0) {
                    return Err(FileError::Padding("padding bytes are not zero"));
                }
                plain.truncate(keep);
            }
            self.hasher.update(&plain);
            Ok(plain)
        }

        /// Check that every chunk arrived and the file is the one its author signed.
        ///
        /// Only after this returns `Ok` may a caller treat what [`StreamOpener::push`]
        /// emitted as received; on an error it discards it.
        pub fn finish(self) -> Result<(), FileError> {
            self.opener.finish()?;
            if self.position != self.padded {
                return Err(FileError::Padding(
                    "the decrypted length is not what the manifest's size and padding give",
                ));
            }
            if !same_digest(&hash_multibase(self.hasher.finalize().into()), &self.digest) {
                return Err(FileError::DigestMismatch);
            }
            Ok(())
        }
    }

    /// A whole file, sealed: its chunks and the manifests naming them.
    pub struct SealedFile {
        pub chunks: Vec<Vec<u8>>,
        pub blob: BlobManifest,
        pub file: FileManifest,
    }

    /// Seal a whole file in memory. For the CLI and tests; a browser streams.
    pub fn seal_file(
        key: &FileKey,
        binding: FileBinding,
        name: &str,
        media_type: Option<&str>,
        plaintext: &[u8],
        padding: Padding,
    ) -> Result<SealedFile, FileError> {
        let mut sealer = StreamSealer::new(
            key,
            binding,
            plaintext.len() as u64,
            padding,
            name,
            media_type,
        )?;
        let mut chunks = sealer.push(plaintext)?;
        let (last, blob, file) = sealer.finish()?;
        chunks.extend(last);
        Ok(SealedFile { chunks, blob, file })
    }

    /// Open a whole file in memory, and check it against the digest its author signed.
    ///
    /// Refuses a mismatch rather than returning the bytes with a warning.
    pub fn open_file(
        key: &FileKey,
        room_id: &str,
        file: &FileManifest,
        blob: &BlobManifest,
        chunks: &[Vec<u8>],
    ) -> Result<Vec<u8>, FileError> {
        let mut opener = StreamOpener::new(key, room_id, file, blob)?;
        let mut plain = Vec::with_capacity(file.size as usize);
        for chunk in chunks {
            plain.extend_from_slice(&opener.push(chunk)?);
        }
        opener.finish()?;
        Ok(plain)
    }
}

#[cfg(all(test, feature = "files"))]
mod tests {
    use super::*;

    const ROOM: &str = "did:webvh:zRoom";
    const SEG: usize = MIN_SEGMENT_SIZE;

    fn key() -> FileKey {
        derive_file_key(&[7u8; 32], ROOM, &[1u8; 32], 3)
    }

    fn binding() -> FileBinding {
        FileBinding {
            room_id: ROOM.into(),
            file_id: [1u8; 32],
            epoch: 3,
            segment_size: SEG,
        }
    }

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    fn sealed(len: usize) -> SealedFile {
        seal_file(&key(), binding(), "f.bin", None, &data(len), Padding::None).unwrap()
    }

    #[test]
    fn files_round_trip_at_every_boundary() {
        for len in [0, 1, SEG - 1, SEG, SEG + 1, 3 * SEG, 3 * SEG + 5] {
            let s = sealed(len);
            assert_eq!(
                s.blob.chunks.chunk_count,
                segment_count(len as u64, SEG),
                "len {len}"
            );
            let opened = open_file(&key(), ROOM, &s.file, &s.blob, &s.chunks).unwrap();
            assert_eq!(opened, data(len), "len {len}");
        }
    }

    #[test]
    fn an_empty_file_is_one_tag() {
        let s = sealed(0);
        assert_eq!(s.chunks.len(), 1);
        assert_eq!(s.chunks[0].len(), TAG_LEN);
        assert_eq!(s.blob.size, TAG_LEN as u64);
    }

    #[test]
    fn the_manifest_is_consistent_and_its_ref_is_stable() {
        let s = sealed(2 * SEG + 3);
        s.blob.check().unwrap();
        assert_eq!(s.blob.chunks.chunk_size, (SEG + TAG_LEN) as u64);
        assert_eq!(s.file.blob_ref, s.blob.blob_ref().unwrap());
        // Same key and id seal identically (deterministic), so the ref is reproducible.
        assert_eq!(sealed(2 * SEG + 3).file.blob_ref, s.file.blob_ref);
    }

    #[test]
    fn truncation_fails() {
        let s = sealed(3 * SEG);
        // The signed manifest's size already says three segments…
        assert!(open_file(&key(), ROOM, &s.file, &s.blob, &s.chunks[..2]).is_err());
        // …and a host that also lies about the count still fails at the AEAD: the segment
        // it calls final was sealed non-final.
        let mut opener = FileOpener::new(&key(), binding(), 2).unwrap();
        opener.open_segment(&s.chunks[0]).unwrap();
        assert_eq!(
            opener.open_segment(&s.chunks[1]),
            Err(FileError::DidNotOpen(1))
        );
    }

    #[test]
    fn appending_after_the_final_segment_fails() {
        let s = sealed(2 * SEG);
        let mut more = s.chunks.clone();
        more.push(s.chunks[0].clone());
        assert!(open_file(&key(), ROOM, &s.file, &s.blob, &more).is_err());
    }

    #[test]
    fn reordering_fails() {
        let s = sealed(3 * SEG);
        let mut swapped = s.chunks.clone();
        swapped.swap(0, 1);
        assert_eq!(
            open_file(&key(), ROOM, &s.file, &s.blob, &swapped),
            Err(FileError::DidNotOpen(0))
        );
    }

    #[test]
    fn splicing_two_uploads_fails() {
        let a = sealed(2 * SEG);
        let b = seal_file(
            &key(),
            FileBinding {
                file_id: [2u8; 32],
                ..binding()
            },
            "g",
            None,
            &data(2 * SEG),
            Padding::None,
        )
        .unwrap();
        let spliced = vec![a.chunks[0].clone(), b.chunks[1].clone()];
        assert!(open_file(&key(), ROOM, &a.file, &a.blob, &spliced).is_err());
    }

    #[test]
    fn stripping_the_final_flag_fails() {
        // Seal the same plaintext with the final segment marked non-final: the host cannot
        // turn a complete file into a prefix of a longer one, or the reverse.
        let mut sealer = FileSealer::new(&key(), binding()).unwrap();
        let first = sealer.seal_segment(&data(SEG), false).unwrap();
        let mut opener = FileOpener::new(&key(), binding(), 1).unwrap();
        assert_eq!(opener.open_segment(&first), Err(FileError::DidNotOpen(0)));
    }

    #[test]
    fn the_wrong_room_epoch_or_file_does_not_open() {
        let s = sealed(SEG + 1);
        assert!(open_file(&key(), "did:webvh:zOther", &s.file, &s.blob, &s.chunks).is_err());
        let mut other_epoch = s.file.clone();
        other_epoch.epoch = 4;
        assert!(open_file(&key(), ROOM, &other_epoch, &s.blob, &s.chunks).is_err());
        let mut other_id = s.file.clone();
        other_id.file_id = encode_file_id(&[9u8; 32]);
        assert!(open_file(&key(), ROOM, &other_id, &s.blob, &s.chunks).is_err());
        let wrong_key = derive_file_key(&[8u8; 32], ROOM, &[1u8; 32], 3);
        assert!(open_file(&wrong_key, ROOM, &s.file, &s.blob, &s.chunks).is_err());
    }

    #[test]
    fn keys_are_bound_to_room_file_and_epoch() {
        let base = derive_file_key(&[7u8; 32], ROOM, &[1u8; 32], 3);
        assert_ne!(
            base,
            derive_file_key(&[7u8; 32], "did:webvh:zOther", &[1u8; 32], 3)
        );
        assert_ne!(base, derive_file_key(&[7u8; 32], ROOM, &[2u8; 32], 3));
        assert_ne!(base, derive_file_key(&[7u8; 32], ROOM, &[1u8; 32], 4));
    }

    #[test]
    fn a_tampered_digest_is_refused_not_warned() {
        let s = sealed(10);
        let mut lying = s.file.clone();
        lying.digest = digest_multibase(b"something else");
        assert_eq!(
            open_file(&key(), ROOM, &lying, &s.blob, &s.chunks),
            Err(FileError::DigestMismatch)
        );
    }

    #[test]
    fn streaming_in_odd_pieces_matches_whole_file_sealing() {
        let plain = data(3 * SEG + 17);
        let whole = sealed(plain.len());
        let mut sealer = StreamSealer::new(
            &key(),
            binding(),
            plain.len() as u64,
            Padding::None,
            "f.bin",
            None,
        )
        .unwrap();
        let mut chunks = Vec::new();
        for piece in plain.chunks(7_001) {
            chunks.extend(sealer.push(piece).unwrap());
        }
        let (last, blob, file) = sealer.finish().unwrap();
        chunks.extend(last);
        assert_eq!(chunks, whole.chunks);
        assert_eq!(blob, whole.blob);
        assert_eq!(file, whole.file);

        let mut opener = StreamOpener::new(&key(), ROOM, &file, &blob).unwrap();
        let mut out = Vec::new();
        for c in &chunks {
            out.extend(opener.push(c).unwrap());
        }
        opener.finish().unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn a_sealer_refuses_more_or_less_than_the_declared_size() {
        let mut s = StreamSealer::new(&key(), binding(), 10, Padding::None, "f", None).unwrap();
        assert!(s.push(&data(11)).is_err());
        let mut s = StreamSealer::new(&key(), binding(), 10, Padding::None, "f", None).unwrap();
        s.push(&data(9)).unwrap();
        assert!(s.finish().is_err());
    }

    #[test]
    fn a_reader_refuses_a_blob_the_file_manifest_does_not_account_for() {
        let s = sealed(2 * SEG + 1);
        s.file.check_blob(&s.blob).unwrap();

        // Another file's blob: the author named a different one.
        let other = sealed(2 * SEG + 2);
        assert!(s.file.check_blob(&other.blob).is_err());

        // A blob shaped for another segment size, under a manifest that names it.
        let mut wrong_size = s.file.clone();
        wrong_size.segment_size = SEG as u64 + 1;
        assert!(wrong_size.check_blob(&s.blob).is_err());

        // The right blob, but a manifest claiming a size that needs another count.
        let mut wrong_count = s.file.clone();
        wrong_count.size = 4 * SEG as u64;
        assert!(wrong_count.check_blob(&s.blob).is_err());

        // An empty file is one 16-byte chunk.
        let empty = sealed(0);
        empty.file.check_blob(&empty.blob).unwrap();
        assert_eq!((empty.blob.size, empty.blob.chunks.chunk_count), (16, 1));
    }

    #[test]
    fn padding_that_is_not_zero_is_refused() {
        let size = 100u64;
        let padded = padme_len(size) as usize;
        assert!(padded > size as usize, "the case needs padding to exist");
        let mut plain = data(size as usize);
        plain.resize(padded, 0xff);
        // Sealed as if unpadded, then described as padded: the tail is 0xff.
        let mut s = seal_file(&key(), binding(), "f", None, &plain, Padding::None).unwrap();
        s.file.size = size;
        s.file.padding = Some(Padding::Padme);
        s.file.digest = digest_multibase(&plain[..size as usize]);
        assert_eq!(
            open_file(&key(), ROOM, &s.file, &s.blob, &s.chunks),
            Err(FileError::Padding("padding bytes are not zero"))
        );
    }

    #[test]
    fn padme_pads_and_unpads() {
        for len in [0u64, 1, 2, 9, 100, 1000, 70_000, 1 << 20] {
            let p = padme_len(len);
            assert!(p >= len);
            assert!(p as f64 <= (len as f64) * 1.12 + 1.0, "{len} -> {p}");
        }
        assert_eq!(padme_len(9), 10);
        let plain = data(SEG + 100);
        let s = seal_file(&key(), binding(), "f", None, &plain, Padding::Padme).unwrap();
        assert_eq!(s.file.padding, Some(Padding::Padme));
        assert_eq!(
            open_file(&key(), ROOM, &s.file, &s.blob, &s.chunks).unwrap(),
            plain
        );
    }

    #[test]
    fn a_sealer_refuses_to_seal_after_the_end_or_wrong_sizes() {
        let mut sealer = FileSealer::new(&key(), binding()).unwrap();
        assert!(sealer.seal_segment(&data(SEG - 1), false).is_err());
        sealer.seal_segment(&data(5), true).unwrap();
        assert!(sealer.seal_segment(&data(5), true).is_err());
        assert!(
            FileSealer::new(
                &key(),
                FileBinding {
                    segment_size: MAX_SEGMENT_SIZE + 1,
                    ..binding()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn digests_compare_decoded() {
        let d = digest_multibase(b"x");
        let (_, raw) = multibase::decode(&d).unwrap();
        let b64 = multibase::encode(multibase::Base::Base64Url, raw);
        assert!(same_digest(&d, &b64));
        assert!(!same_digest(&d, &digest_multibase(b"y")));
    }

    /// Regenerate the fixture with `VTI_WRITE_FILE_VECTORS=1`.
    #[test]
    fn test_vectors_match_the_fixture() {
        let vectors = vectors::build();
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/file-vectors.json"
        );
        let json = serde_json::to_string_pretty(&vectors).unwrap() + "\n";
        if std::env::var_os("VTI_WRITE_FILE_VECTORS").is_some() {
            std::fs::write(path, &json).unwrap();
        }
        let on_disk = std::fs::read_to_string(path).expect("fixture present");
        assert_eq!(
            on_disk, json,
            "file vectors drifted; regenerate deliberately"
        );
    }

    mod vectors {
        use super::super::*;
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        use serde_json::{Value, json};

        pub fn build() -> Value {
            let storage_key = [0x42u8; 32];
            let room = "did:webvh:QmExampleRoom:rooms.example";
            let file_id: FileId = core::array::from_fn(|i| i as u8);
            let epoch = 7;
            let key = derive_file_key(&storage_key, room, &file_id, epoch);
            let cases: Vec<Value> = [
                (0usize, Padding::None),
                (5, Padding::None),
                (MIN_SEGMENT_SIZE + 3, Padding::None),
                (100, Padding::Padme),
            ]
            .into_iter()
            .map(|(len, padding)| {
                let plain: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
                let s = seal_file(
                    &key,
                    FileBinding {
                        room_id: room.into(),
                        file_id,
                        epoch,
                        segment_size: MIN_SEGMENT_SIZE,
                    },
                    "vector.bin",
                    Some("application/octet-stream"),
                    &plain,
                    padding,
                )
                .unwrap();
                json!({
                    "plaintextLength": len,
                    "plaintext": "bytes i % 256 for i in 0..plaintextLength",
                    "padding": padding,
                    "chunkSha256": s.chunks.iter().map(|c| digest_multibase(c)).collect::<Vec<_>>(),
                    "firstChunkHead": B64.encode(&s.chunks[0][..s.chunks[0].len().min(32)]),
                    "blobManifest": s.blob,
                    "fileManifest": s.file,
                })
            })
            .collect();
            json!({
                "description": "Test vectors for the room file construction (rooms/_shared/0.1/blobs.schema.json FileManifest). fileId and roomId enter the KDF and AAD as raw bytes and UTF-8 respectively.",
                "storageKey": B64.encode(storage_key),
                "roomId": room,
                "fileId": encode_file_id(&file_id),
                "epoch": epoch,
                "segmentSize": MIN_SEGMENT_SIZE,
                "fileKey": B64.encode(key),
                "cases": cases,
            })
        }
    }
}
