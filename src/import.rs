//! Turning things the user has — a URI, an image of a QR code — into accounts.

use anyhow::{bail, Context, Result};

use crate::i18n;

use crate::otp::migration::{self, BatchCollector};
use crate::otp::uri::OtpAuth;

/// What a single decoded string turned out to be.
///
/// Debug is safe to derive here: both payload types redact their secrets.
#[derive(Debug)]
pub enum Scanned {
    /// A plain `otpauth://` URI: one account.
    Single(Box<OtpAuth>),
    /// One QR code of a Google Authenticator export, possibly of several.
    Migration(Box<migration::MigrationPayload>),
}

/// Classifies and parses one decoded string.
pub fn parse_any(text: &str) -> Result<Scanned> {
    let text = text.trim();
    if text
        .to_ascii_lowercase()
        .starts_with("otpauth-migration://")
    {
        Ok(Scanned::Migration(Box::new(
            migration::parse(text).with_context(i18n::migration_unreadable)?,
        )))
    } else if text.to_ascii_lowercase().starts_with("otpauth://") {
        Ok(Scanned::Single(Box::new(OtpAuth::parse(text)?)))
    } else {
        bail!("{}", i18n::not_an_otpauth_value())
    }
}

/// Collects accounts from a set of decoded strings, insisting that a
/// multi-part Google export is complete before returning anything.
pub fn collect(texts: &[String]) -> Result<Vec<OtpAuth>> {
    let mut singles = Vec::new();
    let mut batches = BatchCollector::new();
    let mut saw_migration = false;

    for text in texts {
        match parse_any(text)? {
            Scanned::Single(entry) => singles.push(*entry),
            Scanned::Migration(payload) => {
                saw_migration = true;
                batches.add(*payload)?;
            }
        }
    }

    if saw_migration {
        // A partial export is the main hazard here: importing one QR code of
        // three and reporting success would leave the user believing they had
        // migrated while most accounts were still only on the phone.
        singles.extend(batches.finish()?);
    }
    Ok(singles)
}

/// Reads a text file of URIs, one per line.
///
/// Accepts both shapes, because the natural thing to do with a decoded QR
/// payload is paste it into a file — and a file of Google migration parts must
/// still go through the completeness check.
pub fn read_file(path: &std::path::Path) -> Result<Vec<String>> {
    let text = zeroize::Zeroizing::new(
        std::fs::read_to_string(path)
            .with_context(|| i18n::err_cannot_read(&path.display().to_string()))?,
    );
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect())
}

/// Reads QR codes out of image files.
#[cfg(feature = "qr")]
pub mod qr {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::Path;

    use image::imageops::FilterType;
    use image::{DynamicImage, GrayImage};

    /// Resampling ladder, tried in order.
    ///
    /// `rqrr`'s binarisation is sensitive to how many pixels each QR module
    /// covers. A phone screenshot of a dense Google export — version 20 and up,
    /// with anti-aliased edges — routinely *detects* the grid at native
    /// resolution and then fails its format checksum, while decoding cleanly
    /// once resampled. Rejecting the image after a single attempt turned the
    /// main migration path into "crop it yourself and hope", so the image is
    /// retried at several scales instead.
    ///
    /// Ordered by cost times likelihood: the native pass is free and often
    /// enough, downscaling is cheap, and the 2x pass is the expensive last
    /// resort. Lanczos throughout — nearest-neighbour was measurably less
    /// reliable on the same inputs.
    const SCALES: &[f32] = &[1.0, 0.75, 1.5, 1.25, 2.0];

    /// Skip a scale that would blow past this, rather than spend a second
    /// resampling a photo nobody needs resampled.
    const MAX_PIXELS: u64 = 40_000_000;

    /// Decodes every QR code found in one image.
    pub fn decode_file(path: &Path) -> Result<Vec<String>> {
        let image =
            image::open(path).with_context(|| i18n::qr_cannot_open(&path.display().to_string()))?;

        let mut found: BTreeSet<String> = BTreeSet::new();
        let mut grids_seen = 0usize;

        for scale in SCALES {
            let Some(candidate) = resample(&image, *scale) else {
                continue;
            };
            let (grids, decoded) = scan(candidate);
            grids_seen = grids_seen.max(grids);
            found.extend(decoded);

            // Stop as soon as one pass reads everything it could see: an image
            // holding two codes must not be accepted on the strength of one.
            if grids > 0 && found.len() >= grids {
                break;
            }
        }

        if found.is_empty() {
            if grids_seen == 0 {
                bail!("{}", i18n::qr_no_code(&path.display().to_string()));
            }
            bail!(
                "{}",
                i18n::qr_unreadable(
                    &i18n::qr_code_count(grids_seen),
                    &path.display().to_string()
                )
            );
        }
        Ok(found.into_iter().collect())
    }

    fn resample(image: &DynamicImage, scale: f32) -> Option<GrayImage> {
        if (scale - 1.0).abs() < f32::EPSILON {
            return Some(image.to_luma8());
        }
        let width = (image.width() as f32 * scale) as u32;
        let height = (image.height() as f32 * scale) as u32;
        if width == 0 || height == 0 || u64::from(width) * u64::from(height) > MAX_PIXELS {
            return None;
        }
        Some(
            image
                .resize_exact(width, height, FilterType::Lanczos3)
                .to_luma8(),
        )
    }

    /// Returns how many grids were found and what could be read from them.
    fn scan(image: GrayImage) -> (usize, Vec<String>) {
        let mut prepared = rqrr::PreparedImage::prepare(image);
        let grids = prepared.detect_grids();
        let decoded = grids
            .iter()
            .filter_map(|grid| grid.decode().ok().map(|(_meta, content)| content))
            .collect();
        (grids.len(), decoded)
    }

    /// Decodes several images, reporting which file each failure came from.
    pub fn decode_files(paths: &[std::path::PathBuf]) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for path in paths {
            out.extend(decode_file(path)?);
        }
        Ok(out)
    }
}

#[cfg(not(feature = "qr"))]
pub mod qr {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_the_two_uri_shapes() {
        assert!(matches!(
            parse_any("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").unwrap(),
            Scanned::Single(_)
        ));
        assert!(parse_any("https://example.com").is_err());
        assert!(parse_any("JBSWY3DPEHPK3PXP")
            .unwrap_err()
            .to_string()
            .contains("add"));
    }

    #[test]
    fn collects_several_plain_uris() {
        let uris = vec![
            "otpauth://totp/A:one?secret=JBSWY3DPEHPK3PXP".to_string(),
            "otpauth://totp/B:two?secret=JBSWY3DPEHPK3PXP".to_string(),
        ];
        let accounts = collect(&uris).unwrap();
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[1].account, "two");
    }
}
