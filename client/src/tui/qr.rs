/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

//! Pixel-perfect QR images, with an unscaled text fallback.
use base64::{Engine, engine::general_purpose::STANDARD};
use hibiki_lib::qr::Matrix;
use image::{DynamicImage, GrayImage, Luma, imageops};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    widgets::{Paragraph, Wrap},
};
use ratatui_image::{
    Image,
    protocol::{Protocol, kitty::Kitty},
};
use std::io::{self, Write};
use zeroize::Zeroizing;

pub type CellSize = (u16, u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ImageLayout {
    cells: (u16, u16),
    cell_size: CellSize,
    scale: u32,
}

impl ImageLayout {
    fn fit(modules: usize, area: Rect, cell_size: CellSize) -> Option<Self> {
        let (cw, ch) = cell_size;
        if cw == 0 || ch == 0 {
            return None;
        }
        for scale in (2..=12).rev() {
            let side = modules as u32 * scale;
            let columns = side.div_ceil(u32::from(cw));
            let rows = side.div_ceil(u32::from(ch));
            // The Kitty widget's Unicode placeholder table has 297 positions.
            if columns <= u32::from(area.width).min(297) && rows <= u32::from(area.height).min(297)
            {
                return Some(Self {
                    cells: (columns as u16, rows as u16),
                    cell_size,
                    scale,
                });
            }
        }
        None
    }

    fn image(self, matrix: &Matrix) -> DynamicImage {
        let modules = matrix.width() as u32;
        let source = GrayImage::from_raw(modules, modules, matrix.pixels().to_vec()).unwrap();
        let side = modules * self.scale;
        let code = imageops::resize(&source, side, side, imageops::FilterType::Nearest);
        // Pad to whole cells instead of stretching a square to the cell aspect ratio.
        let width = u32::from(self.cells.0) * u32::from(self.cell_size.0);
        let height = u32::from(self.cells.1) * u32::from(self.cell_size.1);
        let mut image = GrayImage::from_pixel(width, height, Luma([255]));
        imageops::overlay(
            &mut image,
            &code,
            ((width - side) / 2).into(),
            ((height - side) / 2).into(),
        );
        image.into()
    }
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

struct CachedCode {
    text: Zeroizing<String>,
    matrix: Matrix,
    terminal: Zeroizing<String>,
}

struct CachedImage {
    id: u32,
    layout: ImageLayout,
    protocol: ImageProtocol,
}

enum ImageProtocol {
    Unicode(Protocol),
    // Warp supports Kitty's original placement commands, but released versions
    // may reject the Unicode-placeholder extension used by ratatui-image.
    Direct {
        transmission: Option<Zeroizing<String>>,
        position: Rect,
    },
}

fn direct_transmission(image: DynamicImage, id: u32) -> Zeroizing<String> {
    use std::fmt::Write;
    let pixels = image.to_rgba8();
    let chunks = pixels.as_raw().chunks(3072);
    let count = chunks.len();
    let mut result = Zeroizing::new(String::new());
    for (i, chunk) in chunks.enumerate() {
        result.push_str("\x1b_Gq=2,");
        if i == 0 {
            write!(
                result,
                "a=t,f=32,t=d,i={id},s={},v={},",
                image.width(),
                image.height()
            )
            .unwrap();
        }
        write!(
            result,
            "m={};{}\x1b\\",
            u8::from(i + 1 < count),
            STANDARD.encode(chunk)
        )
        .unwrap();
    }
    result
}

#[derive(Default)]
pub struct View {
    pub cell_size: Option<CellSize>,
    pub direct_placement: bool,
    code: Option<CachedCode>,
    image: Option<CachedImage>,
    retired: Vec<u32>,
}

impl View {
    fn clear_image(&mut self) {
        if let Some(image) = self.image.take() {
            self.retired.push(image.id);
        }
    }

    pub fn clear(&mut self) {
        self.clear_image();
        self.code = None;
    }

    /// Delete only images owned by this view, never another application's images.
    pub fn flush_deletions(&mut self, output: &mut impl Write) -> io::Result<()> {
        for id in &self.retired {
            write!(output, "\x1b_Ga=d,d=I,i={id},q=2;\x1b\\")?;
        }
        if !self.retired.is_empty() {
            output.flush()?;
            self.retired.clear();
        }
        Ok(())
    }

    /// Run after Ratatui finishes a frame so normal cell writes cannot erase a
    /// direct placement. A stable placement ID replaces its old position.
    pub fn flush_graphics(&mut self, output: &mut impl Write) -> io::Result<()> {
        self.flush_deletions(output)?;
        if let Some(CachedImage {
            id,
            protocol:
                ImageProtocol::Direct {
                    transmission,
                    position,
                },
            ..
        }) = &mut self.image
        {
            if let Some(data) = transmission.as_ref() {
                output.write_all(data.as_bytes())?;
                *transmission = None;
            }
            write!(
                output,
                "\x1b7\x1b[{};{}H\x1b_Ga=p,i={id},p=1,c={},r={},C=1,q=2;\x1b\\\x1b8",
                position.y + 1,
                position.x + 1,
                position.width,
                position.height
            )?;
            output.flush()?;
        }
        Ok(())
    }

    pub fn draw(&mut self, f: &mut Frame, text: &str, area: Rect) {
        if self
            .code
            .as_ref()
            .is_none_or(|code| code.text.as_str() != text)
        {
            self.clear();
            match Matrix::new(text) {
                Ok(matrix) => {
                    self.code = Some(CachedCode {
                        text: Zeroizing::new(text.into()),
                        terminal: Zeroizing::new(matrix.terminal()),
                        matrix,
                    });
                }
                Err(error) => {
                    f.render_widget(
                        Paragraph::new(error.to_string()).wrap(Wrap { trim: false }),
                        area,
                    );
                    return;
                }
            }
        }
        let code = self.code.as_ref().unwrap();
        let layout = self
            .cell_size
            .and_then(|cell_size| ImageLayout::fit(code.matrix.width(), area, cell_size));
        if let Some(layout) = layout {
            if self
                .image
                .as_ref()
                .is_none_or(|image| image.layout != layout)
            {
                self.clear_image();
                let code = self.code.as_ref().unwrap();
                let id = u32::from_str_radix(&hibiki_lib::random_id()[..8], 16)
                    .unwrap()
                    .max(1);
                let bounds = Rect::new(0, 0, layout.cells.0, layout.cells.1);
                let pixels = layout.image(&code.matrix);
                let protocol = if self.direct_placement {
                    Some(ImageProtocol::Direct {
                        transmission: Some(direct_transmission(pixels, id)),
                        position: bounds,
                    })
                } else {
                    Kitty::new(pixels, bounds, id, false)
                        .ok()
                        .map(|image| ImageProtocol::Unicode(Protocol::Kitty(image)))
                };
                if let Some(protocol) = protocol {
                    self.image = Some(CachedImage {
                        id,
                        layout,
                        protocol,
                    });
                }
            }
            if let Some(image) = &mut self.image {
                let bounds = centered(area, layout.cells.0, layout.cells.1);
                match &mut image.protocol {
                    ImageProtocol::Unicode(protocol) => {
                        f.render_widget(Image::new(protocol), bounds)
                    }
                    ImageProtocol::Direct { position, .. } => {
                        *position = bounds;
                        f.render_widget(
                            Paragraph::new("").style(Style::default().bg(Color::White)),
                            bounds,
                        );
                    }
                }
                return;
            }
        } else {
            self.clear_image();
        }
        let code = self.code.as_ref().unwrap();
        let width = code.matrix.width() as u16;
        let height = width.div_ceil(2);
        if width <= area.width && height <= area.height {
            f.render_widget(
                Paragraph::new(code.terminal.as_str())
                    .style(Style::default().fg(Color::Black).bg(Color::White)),
                centered(area, width, height),
            );
        } else {
            f.render_widget(Paragraph::new("Terminal too small for this QR code. Enlarge it or press e to export a .png image.").wrap(Wrap { trim: false }), area);
        }
    }
}
