/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

//! Validate framing and allocation bounds using borrowed bytes before decoding secrets.
use super::{Result, invalid};
struct Shape {
    name: &'static str,
    fields: &'static [Field],
}
struct Field {
    tag: u32,
    repeated: bool,
    oneof: Option<i32>,
    nested: Option<usize>,
    wire: u8,
    utf8: bool,
}
include!(concat!(env!("OUT_DIR"), "/wire-shapes.rs"));
pub const MAX_MESSAGES: usize = 65_536;

pub fn check(bytes: &[u8], name: &str) -> Result<()> {
    let node = SHAPES
        .iter()
        .position(|shape| shape.name == name)
        .ok_or_else(|| invalid("unknown wire schema"))?;
    let mut budget = MAX_MESSAGES;
    message(bytes, node, 0, &mut budget)
}
fn varint(bytes: &mut &[u8]) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let (&byte, rest) = bytes
            .split_first()
            .ok_or_else(|| invalid("truncated varint"))?;
        *bytes = rest;
        if shift == 63 && byte > 1 {
            return Err(invalid("varint overflow"));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(invalid("varint overflow"))
}
fn take<'a>(bytes: &mut &'a [u8], size: usize) -> Result<&'a [u8]> {
    let (value, rest) = bytes
        .split_at_checked(size)
        .ok_or_else(|| invalid("truncated field"))?;
    *bytes = rest;
    Ok(value)
}
fn key(bytes: &mut &[u8]) -> Result<(u32, u8)> {
    let key = u32::try_from(varint(bytes)?).map_err(|_| invalid("invalid field key"))?;
    if key >> 3 == 0 {
        return Err(invalid("zero field number"));
    }
    Ok((key >> 3, (key & 7) as u8))
}
fn message(mut bytes: &[u8], node: usize, depth: usize, budget: &mut usize) -> Result<()> {
    if depth >= 100 || *budget == 0 {
        return Err(invalid("wire nesting or message count limit"));
    }
    *budget -= 1;
    let shape = &SHAPES[node];
    // Schema fields are few; masks avoid allocation and contain no payload bytes.
    let mut seen = 0u64;
    let mut oneofs = 0u64;
    while !bytes.is_empty() {
        let (tag, wire) = key(&mut bytes)?;
        let field = shape
            .fields
            .iter()
            .enumerate()
            .find(|(_, field)| field.tag == tag);
        if let Some((index, field)) = field {
            if !field.repeated && seen & (1 << index) != 0 {
                return Err(invalid("duplicate singular field"));
            }
            seen |= 1 << index;
            if let Some(index) = field.oneof {
                if oneofs & (1 << index) != 0 {
                    return Err(invalid("duplicate oneof selection"));
                }
                oneofs |= 1 << index;
            }
            if wire != field.wire {
                return Err(invalid("incorrect field wire type"));
            }
        }
        match wire {
            0 => {
                varint(&mut bytes)?;
            }
            1 => {
                take(&mut bytes, 8)?;
            }
            2 => {
                let size = usize::try_from(varint(&mut bytes)?)
                    .map_err(|_| invalid("field length overflow"))?;
                let value = take(&mut bytes, size)?;
                if field.is_some_and(|(_, field)| field.utf8) {
                    std::str::from_utf8(value).map_err(|_| invalid("invalid UTF-8 field"))?;
                }
                if let Some((
                    _,
                    Field {
                        nested: Some(node), ..
                    },
                )) = field
                {
                    message(value, *node, depth + 1, budget)?;
                }
            }
            3 => skip_group(&mut bytes, tag, depth + 1, budget)?,
            5 => {
                take(&mut bytes, 4)?;
            }
            _ => return Err(invalid("invalid wire type")),
        }
    }
    Ok(())
}
fn skip_group(bytes: &mut &[u8], end: u32, depth: usize, budget: &mut usize) -> Result<()> {
    if depth >= 100 || *budget == 0 {
        return Err(invalid("wire nesting or message count limit"));
    }
    *budget -= 1;
    loop {
        let (tag, wire) = key(bytes)?;
        match wire {
            0 => {
                varint(bytes)?;
            }
            1 => {
                take(bytes, 8)?;
            }
            2 => {
                let size = usize::try_from(varint(bytes)?)
                    .map_err(|_| invalid("field length overflow"))?;
                take(bytes, size)?;
            }
            3 => skip_group(bytes, tag, depth + 1, budget)?,
            4 if tag == end => return Ok(()),
            5 => {
                take(bytes, 4)?;
            }
            _ => return Err(invalid("invalid group")),
        }
    }
}
