/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

//! Human CLI selectors only. Wire messages and stored identities always use full IDs.
use crate::{Error, Result};

pub fn resolve_id<'a>(input: &str, ids: impl IntoIterator<Item = &'a str>) -> Result<String> {
    if input.len() < 6 || !input.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Invalid(
            "ID prefixes must contain at least 6 hexadecimal characters".into(),
        ));
    }
    let input = input.to_ascii_lowercase();
    let mut matches: Vec<_> = ids
        .into_iter()
        .filter(|id| id.starts_with(&input))
        .collect();
    matches.sort_unstable();
    matches.dedup();
    // A complete identifier remains unambiguous even in mixed-length collections.
    if let Some(id) = matches.iter().find(|id| **id == input) {
        return Ok((*id).into());
    }
    match matches.as_slice() {
        [id] => Ok((*id).into()),
        [] => Err(Error::Invalid("no matching ID; refresh the list".into())),
        _ => Err(Error::Invalid(format!(
            "ambiguous ID prefix; use more characters. Matching IDs:\n{}",
            matches.join("\n")
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_unique_at_least_six_character_prefixes_resolve() {
        let a = "abcdef0123456789";
        let b = "abcdef0999999999";
        assert_eq!(resolve_id("ABCDEF01", [a, b]).unwrap(), a);
        assert_eq!(resolve_id(a, [a, b]).unwrap(), a);
        assert!(resolve_id("abcde", [a]).is_err());
        assert!(
            resolve_id("abcdef", [a, b])
                .unwrap_err()
                .to_string()
                .contains(b)
        );
        assert!(resolve_id("aaaaaaa", [a, b]).is_err());
        assert!(resolve_id("abcdef\n", [a]).is_err());
        assert_eq!(resolve_id("abcdef", [a, a]).unwrap(), a);
    }
}
