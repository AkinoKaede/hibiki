//! Shared QR payload rendering. The quiet zone is never cropped.
use crate::{Error, Result};
use qrcode::{Color, EcLevel, QrCode};
use zeroize::Zeroizing;

/// One grayscale pixel per module, including the four-module quiet zone.
pub struct Matrix {
    width: usize,
    pixels: Zeroizing<Vec<u8>>,
}

impl Matrix {
    pub fn new(text: &str) -> Result<Self> {
        let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M)
            .map_err(|_| Error::Invalid("data too large for a QR code".into()))?;
        let width = code.width() + 8;
        let mut pixels = Zeroizing::new(vec![255; width * width]);
        for y in 0..code.width() {
            for x in 0..code.width() {
                if code[(x, y)] == Color::Dark {
                    pixels[(y + 4) * width + x + 4] = 0;
                }
            }
        }
        Ok(Self { width, pixels })
    }

    pub fn width(&self) -> usize {
        self.width
    }

    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    pub fn terminal(&self) -> String {
        let dark = |x: usize, y: usize| y < self.width && self.pixels[y * self.width + x] == 0;
        let mut result = String::new();
        for y in (0..self.width).step_by(2) {
            for x in 0..self.width {
                result.push(match (dark(x, y), dark(x, y + 1)) {
                    (false, false) => ' ',
                    (true, false) => '▀',
                    (false, true) => '▄',
                    (true, true) => '█',
                });
            }
            result.push('\n');
        }
        result
    }
}

pub fn terminal(text: &str) -> Result<String> {
    Ok(Matrix::new(text)?.terminal())
}
pub fn png(text: &str) -> Result<Vec<u8>> {
    let matrix = Matrix::new(text)?;
    let modules = matrix.width();
    let width = modules * 8;
    let mut pixels = vec![255u8; width * width];
    for y in 0..modules {
        for x in 0..modules {
            if matrix.pixels()[y * modules + x] == 0 {
                for dy in 0..8 {
                    for dx in 0..8 {
                        pixels[(y * 8 + dy) * width + x * 8 + dx] = 0;
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
