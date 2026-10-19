//! Directory pictures: an avatar or a community `image` field
//! (`vtc/directory/images/{upload,get}/0.1`).
//!
//! **Re-encoded, never stored as sent.** An upload is decoded, its orientation
//! applied, scaled to at most [`MAX_DIMENSION`] on the longer side and encoded
//! afresh, so no metadata block (EXIF, XMP, ICC, comments) and no byte the
//! writer sent survives. The digest a reader sees is of the community's own
//! encoding, so it links nothing across communities (VTI-DIR-051).
//!
//! **Owned until a card holds it.** An upload belongs to its writer — a
//! member's entry, or the directory's administrators — and a card accepts a
//! picture only its own writer uploaded (`images/upload` item 5). One a card
//! does not take up within [`UPLOAD_HOLD`] is erased, and so is one no card
//! holds any longer ([`collect`]).
//!
//! **Read only through the projection.** Nothing here answers a digest on its
//! own: `images/get` projects the entry for its caller first. A digest is not a
//! capability.
//!
//! Rows in the `directory` keyspace: `img:<sha256>` (the bytes),
//! `imgmeta:<sha256>` ([`Stored`]) and `upload:<owner>:<sha256>` ([`Upload`]).

use std::collections::BTreeSet;
use std::io::Cursor;

use chrono::{DateTime, Duration, Utc};
use image::{DynamicImage, ImageDecoder, ImageFormat, ImageReader, Limits};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vti_common::error::AppError;
use vti_common::store::{Batch, KeyspaceHandle};

use super::cards;

/// The largest image accepted or stored (`CardBlobRef.size`).
pub const MAX_IMAGE_BYTES: usize = 262_144;

/// The longer side of a stored image, in pixels. The specification allows up to
/// 1024; a directory shows pictures small, and a community keeps no more than
/// it shows.
pub const MAX_DIMENSION: u32 = 512;

/// How long an upload no card holds is kept (`images/upload` item 4).
pub const UPLOAD_HOLD: Duration = Duration::hours(24);

/// The media types a `CardBlobRef` admits.
pub const MEDIA_TYPES: [&str; 4] = ["image/png", "image/jpeg", "image/webp", "image/avif"];

/// The largest picture decoded, before scaling. Bounds the memory a hostile
/// upload can make the decoder take.
const MAX_DECODE_DIMENSION: u32 = 8192;
const MAX_DECODE_ALLOC: u64 = 128 * 1024 * 1024;

/// Smaller sizes tried when an encoding does not fit [`MAX_IMAGE_BYTES`].
const SIZES: [u32; 5] = [MAX_DIMENSION, 384, 256, 192, 128];
const JPEG_QUALITIES: [u8; 3] = [85, 75, 65];

/// Why an upload was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadError {
    TooLarge,
    NotAnImage,
}

/// A picture as the community stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoded {
    pub bytes: Vec<u8>,
    pub media_type: &'static str,
}

impl Encoded {
    pub fn sha256(&self) -> String {
        hex::encode(Sha256::digest(&self.bytes))
    }

    /// The `CardBlobRef` a card holds for it.
    pub fn blob_ref(&self) -> Value {
        json!({
            "sha256": self.sha256(),
            "mediaType": self.media_type,
            "size": self.bytes.len(),
        })
    }
}

/// Decode `data` as an image of `media_type` and encode it afresh: orientation
/// applied, metadata gone, at most [`MAX_DIMENSION`] on the longer side, PNG
/// where it has transparency and JPEG where it has none (`images/upload`
/// items 2 and 3). CPU-bound: call it off the async runtime.
pub fn reencode(data: &[u8], media_type: &str) -> Result<Encoded, UploadError> {
    if data.len() > MAX_IMAGE_BYTES {
        return Err(UploadError::TooLarge);
    }
    let format = match media_type {
        "image/png" => ImageFormat::Png,
        "image/jpeg" => ImageFormat::Jpeg,
        "image/webp" => ImageFormat::WebP,
        // AVIF is a type a card may hold, but this build cannot decode it.
        _ => return Err(UploadError::NotAnImage),
    };
    let mut reader = ImageReader::with_format(Cursor::new(data), format);
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DECODE_DIMENSION);
    limits.max_image_height = Some(MAX_DECODE_DIMENSION);
    limits.max_alloc = Some(MAX_DECODE_ALLOC);
    reader.limits(limits);
    let mut decoder = reader.into_decoder().map_err(refusal)?;
    let orientation = decoder.orientation().map_err(refusal)?;
    let mut img = DynamicImage::from_decoder(decoder).map_err(refusal)?;
    img.apply_orientation(orientation);
    if img.width() == 0 || img.height() == 0 {
        return Err(UploadError::NotAnImage);
    }

    let transparent = img.color().has_alpha() && img.to_rgba8().pixels().any(|p| p.0[3] < 255);
    for size in SIZES {
        let scaled = if img.width().max(img.height()) > size {
            img.resize(size, size, image::imageops::FilterType::Lanczos3)
        } else {
            img.clone()
        };
        if transparent {
            let mut out = Vec::new();
            let encoder = image::codecs::png::PngEncoder::new_with_quality(
                &mut out,
                image::codecs::png::CompressionType::Best,
                image::codecs::png::FilterType::Adaptive,
            );
            scaled
                .to_rgba8()
                .write_with_encoder(encoder)
                .map_err(|_| UploadError::NotAnImage)?;
            if out.len() <= MAX_IMAGE_BYTES {
                return Ok(Encoded {
                    bytes: out,
                    media_type: "image/png",
                });
            }
        } else {
            let rgb = scaled.to_rgb8();
            for quality in JPEG_QUALITIES {
                let mut out = Vec::new();
                let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, quality);
                rgb.write_with_encoder(encoder)
                    .map_err(|_| UploadError::NotAnImage)?;
                if out.len() <= MAX_IMAGE_BYTES {
                    return Ok(Encoded {
                        bytes: out,
                        media_type: "image/jpeg",
                    });
                }
            }
        }
    }
    // A 128-pixel image always fits; reaching here means the encoder misbehaved.
    Err(UploadError::TooLarge)
}

/// A decoder's refusal: a picture beyond the decoding bounds — a few kilobytes
/// that claim to be tens of thousands of pixels across — is too large; anything
/// else is not a picture of its type.
fn refusal(e: image::ImageError) -> UploadError {
    match e {
        image::ImageError::Limits(_) => UploadError::TooLarge,
        _ => UploadError::NotAnImage,
    }
}

/// Who uploaded a picture, and so which card may take it up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owner {
    /// A member, by their entry — so a rotation keeps their uploads theirs.
    Member(String),
    /// The directory's administrators, for `admin`-sourced image fields.
    Admins,
}

impl Owner {
    fn tag(&self) -> String {
        match self {
            Owner::Member(entry_id) => format!("m:{entry_id}"),
            Owner::Admins => "a".to_string(),
        }
    }
}

/// `imgmeta:<sha256>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stored {
    pub media_type: String,
    pub size: usize,
    pub stored_at: DateTime<Utc>,
}

/// `upload:<owner>:<sha256>`: the writer's hold on a picture no card has
/// taken up yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Upload {
    pub expires_at: DateTime<Utc>,
}

fn img_key(sha: &str) -> Vec<u8> {
    format!("img:{sha}").into_bytes()
}

fn meta_key(sha: &str) -> Vec<u8> {
    format!("imgmeta:{sha}").into_bytes()
}

fn upload_key(owner: &Owner, sha: &str) -> Vec<u8> {
    format!("upload:{}:{sha}", owner.tag()).into_bytes()
}

/// Store `encoded` for `owner`, answering its `CardBlobRef` and when the hold
/// lapses. Uploading a picture again renews its hold.
pub async fn store(
    ks: &KeyspaceHandle,
    owner: &Owner,
    encoded: &Encoded,
    now: DateTime<Utc>,
) -> Result<(Value, DateTime<Utc>), AppError> {
    let sha = encoded.sha256();
    let expires_at = now + UPLOAD_HOLD;
    let _guard = super::WRITE_LOCK.lock().await;
    let mut batch = Batch::new();
    batch
        .insert_raw(img_key(&sha), encoded.bytes.clone())
        .insert(
            meta_key(&sha),
            &Stored {
                media_type: encoded.media_type.to_string(),
                size: encoded.bytes.len(),
                stored_at: now,
            },
        )?
        .insert(upload_key(owner, &sha), &Upload { expires_at })?;
    ks.apply_batch(batch).await?;
    Ok((encoded.blob_ref(), expires_at))
}

/// Whether `owner` may put the picture `sha` on a card: they uploaded it, the
/// hold has not lapsed and the picture is still stored.
pub async fn may_reference(
    ks: &KeyspaceHandle,
    owner: &Owner,
    sha: &str,
    now: DateTime<Utc>,
) -> Result<bool, AppError> {
    let Some(upload) = ks.get::<Upload>(upload_key(owner, sha)).await? else {
        return Ok(false);
    };
    Ok(upload.expires_at > now && ks.get_raw(meta_key(sha)).await?.is_some())
}

/// The stored picture `sha`, if it is still kept.
pub async fn get(ks: &KeyspaceHandle, sha: &str) -> Result<Option<(Stored, Vec<u8>)>, AppError> {
    let Some(meta) = ks.get::<Stored>(meta_key(sha)).await? else {
        return Ok(None);
    };
    Ok(ks.get_raw(img_key(sha)).await?.map(|bytes| (meta, bytes)))
}

/// The digest of a picture value, if `value` is one.
pub fn sha_of(value: &Value) -> Option<&str> {
    value.get("sha256").and_then(Value::as_str)
}

/// The pictures `values` holds, by digest.
pub fn held_by<'a>(values: impl IntoIterator<Item = &'a Value>) -> BTreeSet<String> {
    values
        .into_iter()
        .filter_map(sha_of)
        .map(str::to_string)
        .collect()
}

/// Erase every lapsed hold, and every picture neither a card nor a live hold
/// keeps (`images/upload` item 6). Returns how many pictures were erased.
pub async fn collect(ks: &KeyspaceHandle, now: DateTime<Utc>) -> Result<usize, AppError> {
    let _guard = super::WRITE_LOCK.lock().await;
    let mut kept: BTreeSet<String> = BTreeSet::new();
    for card in cards::all(ks).await? {
        kept.extend(held_by(card.values.values()));
    }
    let mut batch = Batch::new();
    for (key, raw) in ks.prefix_iter_raw(b"upload:".to_vec()).await? {
        let sha = String::from_utf8_lossy(&key)
            .rsplit(':')
            .next()
            .unwrap_or_default()
            .to_string();
        let live = serde_json::from_slice::<Upload>(&raw).is_ok_and(|u| u.expires_at > now);
        if live {
            kept.insert(sha);
        } else {
            batch.remove(key);
        }
    }
    let mut erased = 0;
    for (key, _) in ks.prefix_iter_raw(b"imgmeta:".to_vec()).await? {
        let sha = String::from_utf8_lossy(&key)["imgmeta:".len()..].to_string();
        if !kept.contains(&sha) {
            batch.remove(key).remove(img_key(&sha));
            erased += 1;
        }
    }
    ks.apply_batch(batch).await?;
    Ok(erased)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(width: u32, height: u32, alpha: u8) -> Vec<u8> {
        let img = image::RgbaImage::from_pixel(width, height, image::Rgba([200, 30, 30, alpha]));
        let mut out = Vec::new();
        DynamicImage::ImageRgba8(img)
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    }

    fn jpeg_with_exif() -> Vec<u8> {
        let img = image::RgbImage::from_pixel(64, 32, image::Rgb([10, 120, 200]));
        let mut out = Vec::new();
        let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 90);
        // A camera's EXIF block: a GPS position must not survive.
        image::ImageEncoder::set_exif_metadata(&mut encoder, b"Exif\0\0GPS-SECRET".to_vec()).ok();
        image::ImageEncoder::write_image(
            encoder,
            img.as_raw(),
            64,
            32,
            image::ExtendedColorType::Rgb8,
        )
        .unwrap();
        out
    }

    #[test]
    fn an_opaque_picture_is_stored_as_jpeg_and_a_transparent_one_as_png() {
        let opaque = reencode(&png(40, 40, 255), "image/png").unwrap();
        assert_eq!(opaque.media_type, "image/jpeg");
        let clear = reencode(&png(40, 40, 10), "image/png").unwrap();
        assert_eq!(clear.media_type, "image/png");
    }

    #[test]
    fn a_large_picture_is_scaled_to_the_bound() {
        let big = reencode(&png(1500, 600, 255), "image/png").unwrap();
        let back = image::load_from_memory(&big.bytes).unwrap();
        assert_eq!(back.width(), MAX_DIMENSION);
        assert!(back.height() <= MAX_DIMENSION);
    }

    #[test]
    fn metadata_and_the_bytes_sent_are_gone() {
        let sent = jpeg_with_exif();
        assert!(
            sent.windows(10).any(|w| w == b"GPS-SECRET"),
            "fixture carries EXIF"
        );
        let stored = reencode(&sent, "image/jpeg").unwrap();
        assert!(!stored.bytes.windows(10).any(|w| w == b"GPS-SECRET"));
        assert_ne!(stored.bytes, sent);
    }

    #[test]
    fn what_does_not_decode_as_its_type_is_refused() {
        assert_eq!(
            reencode(b"not an image", "image/png"),
            Err(UploadError::NotAnImage)
        );
        // A PNG sent as a JPEG is not a JPEG.
        assert_eq!(
            reencode(&png(4, 4, 255), "image/jpeg"),
            Err(UploadError::NotAnImage)
        );
        assert_eq!(
            reencode(&png(4, 4, 255), "image/avif"),
            Err(UploadError::NotAnImage)
        );
        assert_eq!(
            reencode(&vec![0u8; MAX_IMAGE_BYTES + 1], "image/png"),
            Err(UploadError::TooLarge)
        );
    }

    #[test]
    fn a_picture_claiming_more_pixels_than_are_decoded_is_too_large() {
        let bomb = png(MAX_DECODE_DIMENSION + 1, 1, 255);
        assert!(bomb.len() < 4096, "small on the wire: {}", bomb.len());
        assert_eq!(reencode(&bomb, "image/png"), Err(UploadError::TooLarge));
    }

    #[test]
    fn the_same_picture_encodes_the_same_way() {
        let a = reencode(&png(30, 20, 255), "image/png").unwrap();
        let b = reencode(&png(30, 20, 255), "image/png").unwrap();
        assert_eq!(a.sha256(), b.sha256());
    }

    #[tokio::test]
    async fn only_its_uploader_may_use_a_picture_and_an_unheld_one_is_erased() {
        let ks = super::super::tests::scratch().await;
        let now = Utc::now();
        let enc = reencode(&png(8, 8, 255), "image/png").unwrap();
        let carol = Owner::Member("dir_carol".into());
        let (blob, expires) = store(&ks, &carol, &enc, now).await.unwrap();
        let sha = blob["sha256"].as_str().unwrap().to_string();
        assert_eq!(expires, now + UPLOAD_HOLD);
        assert!(may_reference(&ks, &carol, &sha, now).await.unwrap());
        assert!(
            !may_reference(&ks, &Owner::Member("dir_dave".into()), &sha, now)
                .await
                .unwrap()
        );
        assert!(!may_reference(&ks, &Owner::Admins, &sha, now).await.unwrap());

        // Held: kept. Lapsed and on no card: erased.
        assert_eq!(collect(&ks, now).await.unwrap(), 0);
        let later = now + UPLOAD_HOLD + Duration::seconds(1);
        assert!(!may_reference(&ks, &carol, &sha, later).await.unwrap());
        assert_eq!(collect(&ks, later).await.unwrap(), 1);
        assert!(get(&ks, &sha).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_picture_on_a_card_outlives_its_hold() {
        let ks = super::super::tests::scratch().await;
        let now = Utc::now();
        let enc = reencode(&png(8, 8, 255), "image/png").unwrap();
        let card = cards::ensure(&ks, "did:example:carol", &Default::default(), None)
            .await
            .unwrap();
        let owner = Owner::Member(card.entry_id.clone());
        let (blob, _) = store(&ks, &owner, &enc, now).await.unwrap();
        let mut next = card.clone();
        next.values.insert("avatar".into(), blob.clone());
        next.revision += 1;
        let applied = cards::Applied {
            card: next,
            changed: vec!["avatar".into()],
            widens: true,
        };
        assert!(cards::commit(&ks, &card, &applied).await.unwrap());
        let later = now + UPLOAD_HOLD + Duration::hours(1);
        assert_eq!(collect(&ks, later).await.unwrap(), 0);
        assert!(
            get(&ks, blob["sha256"].as_str().unwrap())
                .await
                .unwrap()
                .is_some()
        );
    }
}
