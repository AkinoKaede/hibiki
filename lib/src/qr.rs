//! Shared QR payload rendering. The quiet zone is never cropped.
use crate::{Error, Result};
use qrcode::{Color, EcLevel, QrCode};
fn code(text: &str) -> Result<QrCode> {
    QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M)
        .map_err(|_| Error::Invalid("data too large for a QR code".into()))
}
pub fn terminal(text: &str) -> Result<String> {
    let code = code(text)?;
    let width = code.width() + 8;
    let dark = |x: usize, y: usize| {
        x >= 4 && y >= 4 && x < width - 4 && y < width - 4 && code[(x - 4, y - 4)] == Color::Dark
    };
    let mut result = String::new();
    for y in (0..width).step_by(2) {
        for x in 0..width {
            result.push(match (dark(x, y), dark(x, y + 1)) {
                (false, false) => ' ',
                (true, false) => '▀',
                (false, true) => '▄',
                (true, true) => '█',
            });
        }
        result.push('\n');
    }
    Ok(result)
}
pub fn png(text: &str) -> Result<Vec<u8>> {
    let code = code(text)?;
    let modules = code.width() + 8;
    let width = modules * 8;
    let mut pixels = vec![255u8; width * width];
    for y in 0..code.width() {
        for x in 0..code.width() {
            if code[(x, y)] == Color::Dark {
                for dy in 0..8 {
                    for dx in 0..8 {
                        pixels[((y + 4) * 8 + dy) * width + (x + 4) * 8 + dx] = 0;
                    }
                }
            }
        }
    }
    let mut result = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut result, width as u32, width as u32);
        encoder.set_color(png::ColorType::Grayscale);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder
            .write_header()
            .map_err(|_| Error::Invalid("QR image encoding failed".into()))?;
        writer
            .write_image_data(&pixels)
            .map_err(|_| Error::Invalid("QR image encoding failed".into()))?;
    }
    Ok(result)
}
