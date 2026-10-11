//! Files in a room, for a browser: seal a file as it is read, open one as it downloads.
//!
//! The construction is [`vti_rooms::files`]; this is its boundary, under the same two-layer
//! rule as the rest of the crate (logic in plain methods, error conversion in the
//! `#[wasm_bindgen]` wrappers).
//!
//! # Two ways in, and which one keeps the key out of JavaScript
//!
//! - **From a [`RoomMember`]** ([`RoomMember::file_sealer`], [`RoomMember::file_opener`]):
//!   the file key is derived inside this module from the group this member holds, and never
//!   crosses. This is the boundary's rule — secrets do not cross — kept.
//! - **From a key** ([`FileSealer::with_key`], [`FileOpener::with_key`]): for the wallet
//!   extension, which holds no group and gets one file's key from the member's VTA
//!   (`rooms/keys/file-key/0.1`). That key is in the extension's JavaScript by necessity, so
//!   this path belongs **only** in the extension's own context (its service worker or
//!   offscreen document), never in a web page: a page that held a file key would hold that
//!   file's ciphertext open forever. `data-rooms-files.md` §4.1.
//!
//! # Shape
//!
//! Chunks travel concatenated in one `Uint8Array`, because every chunk but a file's last is
//! exactly `chunkSize` bytes and the caller splits on that. It saves an array of arrays at
//! the boundary, which `wasm-bindgen` cannot return without `js-sys`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Serialize;
use vti_rooms::files::{
    self, BlobManifest, DEFAULT_SEGMENT_SIZE, FileBinding, FileKey, FileManifest, Padding,
    StreamOpener, StreamSealer,
};
use wasm_bindgen::prelude::*;

use crate::{RoomMember, err, js};

/// What [`FileSealer::finish`] leaves behind: the two manifests, as JSON.
///
/// `blob` goes to the host in `rooms/blobs/upload/begin`; `file` goes inside the sealed
/// record body, where only members see it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Manifests<'a> {
    blob: &'a BlobManifest,
    file: &'a FileManifest,
}

fn padding(padme: bool) -> Padding {
    if padme { Padding::Padme } else { Padding::None }
}

fn decode_key(key: &str) -> Result<FileKey, String> {
    B64.decode(key)
        .map_err(err)?
        .try_into()
        .map_err(|_| "a file key is 32 bytes".to_string())
}

/// Seals one file, in pieces of any size, as it is read.
#[wasm_bindgen]
pub struct FileSealer {
    inner: Option<StreamSealer>,
    chunk_size: u32,
    manifests: Option<(BlobManifest, FileManifest)>,
}

impl FileSealer {
    fn from_parts(
        key: &FileKey,
        binding: FileBinding,
        size: u64,
        padme: bool,
        name: &str,
        media_type: Option<String>,
    ) -> Result<FileSealer, String> {
        let chunk_size = binding.chunk_size() as u32;
        let inner = StreamSealer::new(
            key,
            binding,
            size,
            padding(padme),
            name,
            media_type.as_deref(),
        )
        .map_err(err)?;
        Ok(FileSealer {
            inner: Some(inner),
            chunk_size,
            manifests: None,
        })
    }

    /// Seal with a key the member's VTA released. **Extension context only.**
    #[allow(clippy::too_many_arguments)]
    pub fn with_key(
        room_id: &str,
        file_id: &str,
        epoch: u64,
        key: &str,
        size: u64,
        padme: bool,
        name: &str,
        media_type: Option<String>,
        segment_size: Option<u32>,
    ) -> Result<FileSealer, String> {
        let binding = FileBinding {
            room_id: room_id.to_string(),
            file_id: files::decode_file_id(file_id).map_err(err)?,
            epoch,
            segment_size: segment_size.map_or(DEFAULT_SEGMENT_SIZE, |s| s as usize),
        };
        Self::from_parts(&decode_key(key)?, binding, size, padme, name, media_type)
    }

    /// Feed the next bytes of the file; returns the chunks they completed, concatenated.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        let sealer = self.inner.as_mut().ok_or("this file is already sealed")?;
        Ok(sealer.push(data).map_err(err)?.concat())
    }

    /// Seal the rest; returns the remaining chunks, concatenated, the last one short.
    pub fn finish(&mut self) -> Result<Vec<u8>, String> {
        let sealer = self.inner.take().ok_or("this file is already sealed")?;
        let (chunks, blob, file) = sealer.finish().map_err(err)?;
        self.manifests = Some((blob, file));
        Ok(chunks.concat())
    }

    /// `{ blob, file }` as JSON, once [`FileSealer::finish`] has run.
    pub fn manifests(&self) -> Result<String, String> {
        let (blob, file) = self
            .manifests
            .as_ref()
            .ok_or("the manifests exist once the file is finished")?;
        serde_json::to_string(&Manifests { blob, file }).map_err(err)
    }
}

#[wasm_bindgen]
impl FileSealer {
    /// See [`FileSealer::with_key`].
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = withKey)]
    pub fn with_key_js(
        room_id: &str,
        file_id: &str,
        epoch: u64,
        key: &str,
        size: u64,
        padme: bool,
        name: &str,
        media_type: Option<String>,
        segment_size: Option<u32>,
    ) -> Result<FileSealer, JsError> {
        Self::with_key(
            room_id,
            file_id,
            epoch,
            key,
            size,
            padme,
            name,
            media_type,
            segment_size,
        )
        .map_err(js)
    }

    /// The size every chunk but the last has: split [`FileSealer::push`]'s output on it.
    #[wasm_bindgen(getter, js_name = chunkSize)]
    pub fn chunk_size_js(&self) -> u32 {
        self.chunk_size
    }

    /// See [`FileSealer::push`].
    #[wasm_bindgen(js_name = push)]
    pub fn push_js(&mut self, data: &[u8]) -> Result<Vec<u8>, JsError> {
        self.push(data).map_err(js)
    }

    /// See [`FileSealer::finish`].
    #[wasm_bindgen(js_name = finish)]
    pub fn finish_js(&mut self) -> Result<Vec<u8>, JsError> {
        self.finish().map_err(js)
    }

    /// See [`FileSealer::manifests`].
    #[wasm_bindgen(js_name = manifests)]
    pub fn manifests_js(&self) -> Result<String, JsError> {
        self.manifests().map_err(js)
    }
}

/// Opens one file, chunk by chunk, as it downloads.
///
/// **What [`FileOpener::push`] returns is provisional.** Each chunk authenticates under this
/// file's key, but the file is the one its author signed only once the digest checks. The
/// caller writes the plaintext to a temporary destination and releases it — saves it under
/// its final name, renders it, hands it to a page — only after [`FileOpener::finish`] has
/// returned and [`FileOpener::verified`] is `true`. On any error it discards the
/// destination. `FileManifest`'s *Reading* rules; `data-rooms-files.md` §4.1.
#[wasm_bindgen]
pub struct FileOpener {
    inner: Option<StreamOpener>,
    verified: bool,
    manifest: Option<FileManifest>,
}

/// What a verified [`FileOpener::finish`] reports.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Verified<'a> {
    verified: bool,
    size: u64,
    digest: &'a str,
}

impl FileOpener {
    /// Open with a key the member's VTA released. **Extension context only.**
    ///
    /// `blob_manifest` is what the host served with the download (`rooms/blobs/get`); it is
    /// checked against the author's `file_manifest` before any byte is opened.
    pub fn with_key(
        room_id: &str,
        key: &str,
        file_manifest: &str,
        blob_manifest: &str,
    ) -> Result<FileOpener, String> {
        let (file, blob) = manifests(file_manifest, blob_manifest)?;
        let inner = StreamOpener::new(&decode_key(key)?, room_id, &file, &blob).map_err(err)?;
        Ok(FileOpener::from_parts(inner, file))
    }

    fn from_parts(inner: StreamOpener, file: FileManifest) -> FileOpener {
        FileOpener {
            inner: Some(inner),
            verified: false,
            manifest: Some(file),
        }
    }

    /// Open the next chunk; returns its plaintext with any padding removed.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, String> {
        self.inner
            .as_mut()
            .ok_or("this file is already finished")?
            .push(chunk)
            .map_err(err)
    }

    /// Check that every chunk arrived, the padding is zero and the plaintext is the one its
    /// author signed. Returns `{ verified: true, size, digest }` as JSON; any failure is an
    /// error and leaves [`FileOpener::verified`] `false`.
    pub fn finish(&mut self) -> Result<String, String> {
        self.inner
            .take()
            .ok_or("this file is already finished")?
            .finish()
            .map_err(err)?;
        self.verified = true;
        let file = self.manifest.as_ref().ok_or("no manifest")?;
        serde_json::to_string(&Verified {
            verified: true,
            size: file.size,
            digest: &file.digest,
        })
        .map_err(err)
    }

    /// Whether [`FileOpener::finish`] has verified the file. Until it is `true`, nothing
    /// [`FileOpener::push`] returned may be released.
    pub fn verified(&self) -> bool {
        self.verified
    }
}

fn manifests(file: &str, blob: &str) -> Result<(FileManifest, BlobManifest), String> {
    Ok((
        serde_json::from_str(file).map_err(err)?,
        serde_json::from_str(blob).map_err(err)?,
    ))
}

#[wasm_bindgen]
impl FileOpener {
    /// See [`FileOpener::with_key`].
    #[wasm_bindgen(js_name = withKey)]
    pub fn with_key_js(
        room_id: &str,
        key: &str,
        file_manifest: &str,
        blob_manifest: &str,
    ) -> Result<FileOpener, JsError> {
        Self::with_key(room_id, key, file_manifest, blob_manifest).map_err(js)
    }

    /// See [`FileOpener::push`].
    #[wasm_bindgen(js_name = push)]
    pub fn push_js(&mut self, chunk: &[u8]) -> Result<Vec<u8>, JsError> {
        self.push(chunk).map_err(js)
    }

    /// See [`FileOpener::finish`].
    #[wasm_bindgen(js_name = finish)]
    pub fn finish_js(&mut self) -> Result<String, JsError> {
        self.finish().map_err(js)
    }

    /// See [`FileOpener::verified`].
    #[wasm_bindgen(getter, js_name = verified)]
    pub fn verified_js(&self) -> bool {
        self.verified()
    }
}

impl RoomMember {
    /// Start sealing a file under this room's current epoch, with a fresh `fileId`. The
    /// file key is derived here and never leaves.
    pub fn file_sealer(
        &self,
        size: u64,
        padme: bool,
        name: &str,
        media_type: Option<String>,
        segment_size: Option<u32>,
    ) -> Result<FileSealer, String> {
        let file_id = files::new_file_id();
        let (key, epoch) = self.inner.file_key_for_seal(&file_id).map_err(err)?;
        let binding = FileBinding {
            room_id: self.inner.room_id().to_string(),
            file_id,
            epoch: u64::from(epoch),
            segment_size: segment_size.map_or(DEFAULT_SEGMENT_SIZE, |s| s as usize),
        };
        FileSealer::from_parts(&key, binding, size, padme, name, media_type)
    }

    /// Start opening a file from its sealed manifest and the blob manifest the host served,
    /// walking the epoch chain for its key.
    pub fn file_opener(
        &mut self,
        file_manifest: &str,
        blob_manifest: &str,
    ) -> Result<FileOpener, String> {
        let (file, blob) = manifests(file_manifest, blob_manifest)?;
        // Epochs are u64 on the wire and u32 in a room's group; one that does not fit is
        // refused, never truncated.
        let epoch = u32::try_from(file.epoch)
            .map_err(|_| format!("epoch {} is beyond any epoch a room reaches", file.epoch))?;
        let key = self
            .inner
            .file_key_for_open(&file.file_id_bytes().map_err(err)?, epoch)
            .map_err(err)?;
        let inner = StreamOpener::new(&key, self.inner.room_id(), &file, &blob).map_err(err)?;
        Ok(FileOpener::from_parts(inner, file))
    }
}

#[wasm_bindgen]
impl RoomMember {
    /// See [`RoomMember::file_sealer`].
    #[wasm_bindgen(js_name = fileSealer)]
    pub fn file_sealer_js(
        &self,
        size: u64,
        padme: bool,
        name: &str,
        media_type: Option<String>,
        segment_size: Option<u32>,
    ) -> Result<FileSealer, JsError> {
        self.file_sealer(size, padme, name, media_type, segment_size)
            .map_err(js)
    }

    /// See [`RoomMember::file_opener`].
    #[wasm_bindgen(js_name = fileOpener)]
    pub fn file_opener_js(
        &mut self,
        file_manifest: &str,
        blob_manifest: &str,
    ) -> Result<FileOpener, JsError> {
        self.file_opener(file_manifest, blob_manifest).map_err(js)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vti_rooms::mls::RoomGroup;
    use vti_rooms::sealed::SealedRoom;

    fn member() -> RoomMember {
        RoomMember {
            inner: SealedRoom::new(
                "did:webvh:zRoom",
                RoomGroup::create("did:key:zAlice").unwrap(),
            ),
        }
    }

    fn split(bytes: &[u8], size: usize) -> Vec<Vec<u8>> {
        bytes.chunks(size).map(<[u8]>::to_vec).collect()
    }

    #[test]
    fn a_member_seals_and_opens_a_file_without_a_key_crossing() {
        let mut m = member();
        let plain: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
        let mut sealer = m
            .file_sealer(plain.len() as u64, false, "a.bin", None, None)
            .unwrap();
        let mut out = Vec::new();
        for piece in plain.chunks(65_536) {
            out.extend(sealer.push(piece).unwrap());
        }
        out.extend(sealer.finish().unwrap());
        let manifests: serde_json::Value =
            serde_json::from_str(&sealer.manifests().unwrap()).unwrap();
        let chunks = split(&out, sealer.chunk_size as usize);
        assert_eq!(
            manifests["blob"]["chunks"]["chunkCount"],
            chunks.len() as u64
        );

        let file = manifests["file"].to_string();
        let blob = manifests["blob"].to_string();
        let mut opener = m.file_opener(&file, &blob).unwrap();
        let mut back = Vec::new();
        for c in &chunks {
            back.extend(opener.push(c).unwrap());
        }
        assert!(!opener.verified(), "nothing is verified before finish");
        let report: serde_json::Value = serde_json::from_str(&opener.finish().unwrap()).unwrap();
        assert_eq!(report["verified"], true);
        assert!(opener.verified());
        assert_eq!(back, plain);
    }

    #[test]
    fn a_released_key_opens_the_same_file() {
        let m = member();
        let file_id = [3u8; 32];
        let (key, epoch) = m.inner.file_key_for_seal(&file_id).unwrap();
        let mut sealer = FileSealer::with_key(
            "did:webvh:zRoom",
            &files::encode_file_id(&file_id),
            u64::from(epoch),
            &B64.encode(key),
            5,
            true,
            "n",
            Some("text/plain".into()),
            Some(files::MIN_SEGMENT_SIZE as u32),
        )
        .unwrap();
        let mut out = sealer.push(b"hello").unwrap();
        out.extend(sealer.finish().unwrap());
        let manifests: serde_json::Value =
            serde_json::from_str(&sealer.manifests().unwrap()).unwrap();
        let mut opener = FileOpener::with_key(
            "did:webvh:zRoom",
            &B64.encode(key),
            &manifests["file"].to_string(),
            &manifests["blob"].to_string(),
        )
        .unwrap();
        assert_eq!(opener.push(&out).unwrap(), b"hello");
        opener.finish().unwrap();
        assert!(opener.finish().is_err(), "a finished opener stays finished");
    }

    /// A file whose plaintext is not the one its author signed never verifies.
    #[test]
    fn a_digest_mismatch_is_never_verified() {
        let mut m = member();
        let mut sealer = m.file_sealer(5, false, "n", None, None).unwrap();
        let mut out = sealer.push(b"hello").unwrap();
        out.extend(sealer.finish().unwrap());
        let mut manifests: serde_json::Value =
            serde_json::from_str(&sealer.manifests().unwrap()).unwrap();
        manifests["file"]["digest"] = files::digest_multibase(b"other").into();
        let mut opener = m
            .file_opener(
                &manifests["file"].to_string(),
                &manifests["blob"].to_string(),
            )
            .unwrap();
        opener.push(&out).unwrap();
        assert!(opener.finish().is_err());
        assert!(!opener.verified());
    }
}
