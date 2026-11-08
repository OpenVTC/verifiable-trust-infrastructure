//! Showing an award outside the community (`vtc/badges/awards/share|unshare`,
//! VTI-BDG-070 – 072): the records behind a share and the baked picture.
//!
//! A share is the holder's choice, award by award, to have the community serve their
//! badge credential at a public location. The location carries a **token** of 256
//! random bits generated for that share and derived from nothing (`share` item 5); the
//! award records it (`Award.shared`), and `bshare:<token>` indexes it back to the award.
//! What is served is the holder's credential of the badge **as last issued**, kept at
//! `bcred:<badgeId>:<entryId>` each time [`super::credential::issue`] signs one in the
//! outside regime, so a repeat award or a renewal is served at the same location
//! (`share` item 10). A share ends — the index row and `Award.shared` both go — when the
//! holder stops it, the award is taken back, the badge is retired or the holder departs
//! (`share` item 9); the public routes also re-check the award on every request, so a
//! location whose award no longer stands answers as one that never existed.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::{Award, BADGE_SHARED_PATH, Badge};

/// The holder's share of one award: the token and the locations it answers at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Shared {
    /// Never on the wire as such; only inside the locations.
    pub token: String,
    pub verification_url: String,
    pub baked_image_url: String,
    pub since: DateTime<Utc>,
}

impl Shared {
    /// `AwardShare` on the wire.
    pub fn wire(&self) -> Value {
        json!({
            "verificationUrl": self.verification_url,
            "bakedImageUrl": self.baked_image_url,
            "since": self.since,
        })
    }
}

/// A fresh share token: 256 bits from the CSPRNG, base64url — at least the 128 bits
/// `share` item 5 asks, and derived from nothing.
fn new_token() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Whether `token` is spelled as [`new_token`] spells one: 43 base64url characters.
pub fn plain_token(token: &str) -> bool {
    token.len() == 43
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The locations a share with `token` answers at, under the community's public origin.
pub fn locations(public_url: &str, token: &str) -> (String, String) {
    let base = format!(
        "{}/{BADGE_SHARED_PATH}/{token}",
        public_url.trim_end_matches('/')
    );
    let image = format!("{base}/image.png");
    (base, image)
}

fn token_key(token: &str) -> Vec<u8> {
    format!("bshare:{token}").into_bytes()
}

fn credential_key(badge_id: &str, entry_id: &str) -> Vec<u8> {
    format!("bcred:{badge_id}:{entry_id}").into_bytes()
}

/// Keep `credential`, just issued to `entry_id` for `badge_id` in the outside regime, as
/// the one its shares serve.
pub async fn keep_credential(
    ks: &KeyspaceHandle,
    badge_id: &str,
    entry_id: &str,
    credential: &Value,
) -> Result<(), AppError> {
    ks.insert(credential_key(badge_id, entry_id), credential)
        .await
}

/// The credential `entry_id`'s shares of `badge_id` serve: the last one issued.
pub async fn kept_credential(
    ks: &KeyspaceHandle,
    badge_id: &str,
    entry_id: &str,
) -> Result<Option<Value>, AppError> {
    ks.get(credential_key(badge_id, entry_id)).await
}

/// Start sharing `award` at locations under `public_url`, or answer the share in force
/// (`share` item 5: a share of an award already shared answers the same locations).
/// The caller holds [`super::WRITE_LOCK`] and has checked the award may be shared.
pub async fn start(
    ks: &KeyspaceHandle,
    award: &mut Award,
    public_url: &str,
) -> Result<bool, AppError> {
    if award.shared.is_some() {
        return Ok(false);
    }
    let token = new_token();
    let (verification_url, baked_image_url) = locations(public_url, &token);
    ks.insert(token_key(&token), &award.award_id).await?;
    award.shared = Some(Shared {
        token,
        verification_url,
        baked_image_url,
        since: Utc::now(),
    });
    super::put_award(ks, award).await?;
    Ok(true)
}

/// Discard `award`'s share token and clear `shared`, leaving the caller to write the award
/// (as a take-back does, with its new state). Answers whether it was shared. The caller
/// holds [`super::WRITE_LOCK`].
pub async fn forget(ks: &KeyspaceHandle, award: &mut Award) -> Result<bool, AppError> {
    let Some(shared) = award.shared.take() else {
        return Ok(false);
    };
    ks.remove(token_key(&shared.token)).await?;
    Ok(true)
}

/// Stop sharing `award` and write it (`unshare`). Answers whether it was shared. The
/// caller holds [`super::WRITE_LOCK`].
pub async fn stop(ks: &KeyspaceHandle, award: &mut Award) -> Result<bool, AppError> {
    if !forget(ks, award).await? {
        return Ok(false);
    }
    super::put_award(ks, award).await?;
    Ok(true)
}

/// Stop every share of `badge_id`'s awards: the badge is retired. Takes
/// [`super::WRITE_LOCK`].
pub async fn stop_all_of_badge(ks: &KeyspaceHandle, badge_id: &str) -> Result<usize, AppError> {
    let _guard = super::WRITE_LOCK.lock().await;
    let mut n = 0;
    for mut a in super::awards_of_badge(ks, badge_id).await? {
        if stop(ks, &mut a).await? {
            n += 1;
        }
    }
    Ok(n)
}

/// What a share token answers, if it answers anything: the award, still accepted and
/// still shared under this very token, of a badge still shown outside and not retired,
/// with the credential kept for its holder. Anything else is `None` — a stopped share
/// answers as one that never existed (`share` item 9).
pub async fn resolve(
    ks: &KeyspaceHandle,
    token: &str,
) -> Result<Option<(Award, Badge, Value)>, AppError> {
    if !plain_token(token) {
        return Ok(None);
    }
    let Some(award_id) = ks.get::<String>(token_key(token)).await? else {
        return Ok(None);
    };
    let Some(award) = super::get_award(ks, &award_id).await? else {
        return Ok(None);
    };
    let current = award
        .shared
        .as_ref()
        .is_some_and(|s| s.token.as_bytes() == token.as_bytes());
    if !award.is_accepted() || !current {
        return Ok(None);
    }
    let Some(badge) = super::get_badge(ks, &award.badge_id).await? else {
        return Ok(None);
    };
    if !badge.shareable_outside || !badge.is_active() || !badge.is_community() {
        return Ok(None);
    }
    let Some(credential) = kept_credential(ks, &badge.badge_id, &award.entry_id).await? else {
        return Ok(None);
    };
    Ok(Some((award, badge, credential)))
}

/// The Open Badges keyword a PNG's `iTXt` chunk carries a baked credential under
/// (Open Badges 3.0, §5.3 "Baking").
pub const PNG_BAKE_KEYWORD: &str = "openbadgecredential";

/// `picture` (a PNG or JPEG the community re-encoded) as a PNG with `credential` baked
/// into an uncompressed `iTXt` chunk, as Open Badges 3.0 bakes a PNG (`share` item 6).
/// A JPEG is converted, since only PNG and SVG carry a baked credential.
pub fn bake_png(picture: &[u8], credential: &Value) -> Result<Vec<u8>, String> {
    let rgba = image::load_from_memory(picture)
        .map_err(|e| format!("decode badge picture: {e}"))?
        .to_rgba8();
    let (w, h) = rgba.dimensions();
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, w, h);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        encoder
            .add_itxt_chunk(PNG_BAKE_KEYWORD.to_string(), credential.to_string())
            .map_err(|e| format!("bake: {e}"))?;
        let mut writer = encoder.write_header().map_err(|e| format!("bake: {e}"))?;
        writer
            .write_image_data(rgba.as_raw())
            .map_err(|e| format!("bake: {e}"))?;
        writer.finish().map_err(|e| format!("bake: {e}"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_carries_256_random_bits_and_names_nothing() {
        let a = new_token();
        let b = new_token();
        assert!(plain_token(&a));
        assert_ne!(a, b);
        assert!(!plain_token("short"));
        assert!(!plain_token(&format!("{}/", &a[..42])));
    }

    #[test]
    fn the_locations_sit_under_the_public_origin() {
        let (v, i) = locations("https://c.example/", "T");
        assert_eq!(v, "https://c.example/badges/shared/T");
        assert_eq!(i, "https://c.example/badges/shared/T/image.png");
    }

    #[test]
    fn a_baked_png_carries_the_credential_in_an_itxt_chunk() {
        let mut picture = Vec::new();
        image::RgbaImage::from_pixel(4, 4, image::Rgba([10, 20, 30, 255]))
            .write_to(
                &mut std::io::Cursor::new(&mut picture),
                image::ImageFormat::Png,
            )
            .unwrap();
        let credential =
            json!({ "id": "urn:uuid:x", "type": ["VerifiableCredential", "OpenBadgeCredential"] });
        let baked = bake_png(&picture, &credential).unwrap();
        let decoder = png::Decoder::new(std::io::Cursor::new(&baked));
        let reader = decoder.read_info().unwrap();
        let chunk = reader
            .info()
            .utf8_text
            .iter()
            .find(|c| c.keyword == PNG_BAKE_KEYWORD)
            .expect("the baked chunk");
        assert!(!chunk.compressed);
        let text = chunk.get_text().unwrap();
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), credential);
    }
}
