//! End-to-end QR test: encode a payload into a real PNG, then read it back
//! through the same code path a phone screenshot takes.
//!
//! The unit tests cover the protobuf and URI parsers with synthetic bytes.
//! This covers the part they cannot: that `image` decodes the file and `rqrr`
//! finds and reads the code.

#![cfg(feature = "qr")]

use std::path::Path;

use image::imageops::FilterType;
use image::{DynamicImage, GenericImage, ImageBuffer, Luma};
use neko_auth::import::{self, qr};
use neko_auth::otp::{self, Algorithm};
use qrcode::{Color, QrCode};

/// Renders `data` as a PNG, with the quiet zone and scale a detector expects.
fn write_qr(path: &Path, data: &str) {
    let code = QrCode::new(data.as_bytes()).expect("payload fits in a QR code");
    let width = code.width();
    let colors = code.to_colors();

    // 8 px per module and a 4-module quiet zone — roughly what a phone
    // screenshot of an export code looks like.
    const SCALE: u32 = 8;
    const QUIET: u32 = 4;
    let side = (width as u32 + QUIET * 2) * SCALE;

    let image = ImageBuffer::from_fn(side, side, |x, y| {
        let mx = x / SCALE;
        let my = y / SCALE;
        if mx < QUIET || my < QUIET || mx >= QUIET + width as u32 || my >= QUIET + width as u32 {
            return Luma([255u8]);
        }
        let index = (my - QUIET) as usize * width + (mx - QUIET) as usize;
        match colors[index] {
            Color::Dark => Luma([0u8]),
            Color::Light => Luma([255u8]),
        }
    });
    image.save(path).expect("cannot write the PNG");
}

/// Builds a Google Authenticator export payload by hand.
mod google {
    use data_encoding::BASE64;

    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    fn len_field(field: u32, data: &[u8]) -> Vec<u8> {
        let mut out = varint(u64::from(field) << 3 | 2);
        out.extend(varint(data.len() as u64));
        out.extend_from_slice(data);
        out
    }

    fn varint_field(field: u32, value: u64) -> Vec<u8> {
        let mut out = varint(u64::from(field) << 3);
        out.extend(varint(value));
        out
    }

    pub fn account(secret: &[u8], name: &str, issuer: &str) -> Vec<u8> {
        let mut out = len_field(1, secret);
        out.extend(len_field(2, name.as_bytes()));
        out.extend(len_field(3, issuer.as_bytes()));
        out.extend(varint_field(4, 1)); // SHA1
        out.extend(varint_field(5, 1)); // 6 digits
        out.extend(varint_field(6, 2)); // TOTP
        out
    }

    pub fn payload(accounts: &[Vec<u8>], size: u64, index: u64, batch: u64) -> String {
        let mut body = Vec::new();
        for account in accounts {
            body.extend(len_field(1, account));
        }
        body.extend(varint_field(2, 1));
        body.extend(varint_field(3, size));
        body.extend(varint_field(4, index));
        body.extend(varint_field(5, batch));

        let encoded = BASE64
            .encode(&body)
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        format!("otpauth-migration://offline?data={encoded}")
    }
}

const SEED: &[u8] = b"12345678901234567890";

#[test]
fn a_plain_otpauth_qr_code_is_read_from_a_png() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("code.png");
    write_qr(
        &path,
        "otpauth://totp/GitHub:zoe%40example.com\
         ?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub",
    );

    let entries = import::collect(&qr::decode_file(&path).unwrap()).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].issuer.as_deref(), Some("GitHub"));
    assert_eq!(entries[0].account, "zoe@example.com");
    assert_eq!(entries[0].secret.as_slice(), SEED);
}

#[test]
fn a_google_export_qr_code_yields_working_codes() {
    // The acceptance test for the whole migration path: what comes out of the
    // image must generate the same code the phone shows. Pinned against the
    // RFC 6238 vector so it does not depend on a device being present.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("export.png");
    write_qr(
        &path,
        &google::payload(
            &[google::account(SEED, "zoe@example.com", "GitHub")],
            1,
            0,
            7,
        ),
    );

    let entries = import::collect(&qr::decode_file(&path).unwrap()).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].secret.as_slice(), SEED);

    let code = otp::totp(&entries[0].secret, 59, 30, Algorithm::Sha1, 8).unwrap();
    assert_eq!(code.as_str(), "94287082");
}

#[test]
fn a_three_part_export_must_be_scanned_in_full() {
    let dir = tempfile::tempdir().unwrap();
    let mut paths = Vec::new();
    for (index, name) in ["one", "two", "three"].iter().enumerate() {
        let path = dir.path().join(format!("part{index}.png"));
        write_qr(
            &path,
            &google::payload(
                &[google::account(SEED, name, "Issuer")],
                3,
                index as u64,
                99,
            ),
        );
        paths.push(path);
    }

    // Two of three: refused, and the message names the missing part.
    let partial = qr::decode_files(&paths[..2]).unwrap();
    let err = import::collect(&partial).unwrap_err().to_string();
    assert!(err.contains("part 3"), "unhelpful message: {err}");

    // All three: reassembled in batch order.
    let all = qr::decode_files(&paths).unwrap();
    let entries = import::collect(&all).unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.account.as_str()).collect();
    assert_eq!(names, ["one", "two", "three"]);
}

#[test]
fn an_image_with_no_qr_code_is_reported_clearly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blank.png");
    ImageBuffer::from_pixel(64, 64, Luma([255u8]))
        .save(&path)
        .unwrap();

    let err = qr::decode_file(&path).unwrap_err().to_string();
    assert!(err.contains("no QR code found"), "{err}");
}

/// Renders `data` the way a phone screenshot of it looks: one pixel per module
/// resampled up to a fractional module size, so the edges are anti-aliased,
/// then dropped into a tall page with other dark shapes on it.
fn write_screenshot(path: &Path, data: &str, module_pixels: f32) {
    let code = QrCode::new(data.as_bytes()).expect("payload fits in a QR code");
    let width = code.width();
    let colors = code.to_colors();

    // Drawn crisply at a high multiple first, then scaled down to the target
    // module size. That is the order a phone does it in, and it produces the
    // light anti-aliasing of a real screenshot rather than the ringing you get
    // from blowing up a one-pixel-per-module bitmap.
    const SUPERSAMPLE: u32 = 8;
    let crisp = ImageBuffer::from_fn(
        width as u32 * SUPERSAMPLE,
        width as u32 * SUPERSAMPLE,
        |x, y| {
            let module = (y / SUPERSAMPLE) as usize * width + (x / SUPERSAMPLE) as usize;
            match colors[module] {
                Color::Dark => Luma([0u8]),
                Color::Light => Luma([255u8]),
            }
        },
    );

    let side = (width as f32 * module_pixels) as u32;
    let scaled = DynamicImage::ImageLuma8(crisp).resize_exact(side, side, FilterType::Lanczos3);

    // A page the shape of a phone screen, with the code partway down.
    let (page_w, page_h) = (1206u32, 2622u32);
    let mut page = DynamicImage::ImageLuma8(ImageBuffer::from_pixel(page_w, page_h, Luma([255u8])));

    // A dark square above it, standing in for the app icon that a detector can
    // mistake for a finder pattern.
    for y in 370..470 {
        for x in 90..190 {
            page.put_pixel(x, y, image::Rgba([20, 20, 20, 255]));
        }
    }

    let ox = (page_w - side) / 2;
    let oy = page_h / 3;
    image::imageops::overlay(&mut page, &scaled, ox as i64, oy as i64);
    page.save(path).expect("cannot write the PNG");
}

/// A payload the size Google actually produces: several accounts in one code.
fn dense_migration_payload() -> String {
    let accounts: Vec<Vec<u8>> = (0..6)
        .map(|i| {
            google::account(
                SEED,
                &format!("person{i}+authenticator@example.com"),
                &format!("Some Service With A Long Name {i}"),
            )
        })
        .collect();
    google::payload(&accounts, 1, 0, 4242)
}

#[test]
fn a_dense_screenshot_decodes_even_when_it_needs_resampling() {
    // The case that sent a real Google export back as unreadable: at the
    // module size a phone screenshot lands on, rqrr either misses the grid or
    // locks onto one and fails its format checksum, and only a resampled pass
    // reads it. Deleting the resampling ladder makes this test fail.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("screenshot.png");
    let payload = dense_migration_payload();
    write_screenshot(&path, &payload, 6.5);

    let decoded = qr::decode_file(&path).expect("a phone screenshot must decode");
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0], payload);

    let entries = import::collect(&decoded).unwrap();
    assert_eq!(entries.len(), 6);
    assert_eq!(entries[0].secret.as_slice(), SEED);
}

#[test]
fn several_module_sizes_all_decode() {
    // Different phones and screenshot scalings land on different module sizes;
    // the ladder has to cover the range rather than one lucky value.
    let dir = tempfile::tempdir().unwrap();
    let payload = dense_migration_payload();
    // Every one of these fails when the image is only tried at its native
    // resolution, which is what shipped first and what sent a real export back
    // as unreadable.
    for module_pixels in [3.2f32, 5.5, 7.5] {
        let path = dir.path().join(format!("s{module_pixels}.png"));
        write_screenshot(&path, &payload, module_pixels);
        let decoded =
            qr::decode_file(&path).unwrap_or_else(|e| panic!("{module_pixels} px per module: {e}"));
        assert_eq!(decoded[0], payload, "{module_pixels} px per module");
    }
}
