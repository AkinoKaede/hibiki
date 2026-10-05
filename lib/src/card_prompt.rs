//! GnuPG agent/findkey.c prompt_for_card formatting (STABLE-BRANCH-2-4).
/// Human card number as displayed by GnuPG, retaining the full AID elsewhere.
pub fn card_number(serial: &str) -> String {
    let serial = serial.to_ascii_uppercase();
    if serial.len() == 32
        && serial.starts_with("D27600012401")
        && serial.bytes().all(|b| b.is_ascii_hexdigit())
    {
        if &serial[16..20] == "0006" && serial[20..28].bytes().all(|b| b.is_ascii_digit()) {
            let number = serial[20..28].parse::<u32>().unwrap_or(0);
            format!(
                "{} {:03} {:03}",
                number / 1_000_000,
                number / 1000 % 1000,
                number % 1000
            )
        } else {
            format!("{} {}", &serial[16..20], &serial[20..28])
        }
    } else if serial.len() == 20 && serial.ends_with('0') {
        serial[..19].into()
    } else {
        serial
    }
}
pub fn description(serial: &str, label: &str) -> String {
    format!(
        "Please insert the card with serial number:\n\n  {}\n  {}",
        card_number(serial),
        label
    )
}
/// Match the complete GnuPG insertion prompt, not arbitrary mentions of a key.
/// SETDESC is already Assuan-unescaped by pinentry. Unknown/localized formats
/// remain ordinary confirmations rather than unexpectedly opening a reader.
pub fn insertion_number(description: &str) -> Option<String> {
    let body = description.strip_prefix("Please insert the card with serial number:")?;
    let mut lines = body.trim().lines();
    let number = lines.next()?.trim();
    let groups: Vec<_> = number.split_ascii_whitespace().collect();
    let valid = match groups.as_slice() {
        [manufacturer, serial] => {
            manufacturer.len() == 4
                && serial.len() == 8
                && manufacturer
                    .bytes()
                    .chain(serial.bytes())
                    .all(|b| b.is_ascii_hexdigit())
        }
        [a, b, c] => {
            (1..=2).contains(&a.len())
                && b.len() == 3
                && c.len() == 3
                && a.bytes()
                    .chain(b.bytes())
                    .chain(c.bytes())
                    .all(|b| b.is_ascii_digit())
        }
        [serial] => {
            matches!(serial.len(), 19 | 20 | 32) && serial.bytes().all(|b| b.is_ascii_hexdigit())
        }
        _ => false,
    };
    // GnuPG optionally includes one card/key label after the number.
    (valid && lines.count() <= 1).then(|| groups.join(" ").to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn insertion_prompts_require_the_exact_header_and_a_card_number() {
        for serial in [
            "D2760001240103040005000012340000",
            "D2760001240100000006120808620000",
            "12345678901234567890",
        ] {
            assert_eq!(
                insertion_number(&description(serial, "Signing key")),
                Some(card_number(serial))
            );
        }
        assert_eq!(
            insertion_number("Please insert the card with serial number: 0005 00001234"),
            Some("0005 00001234".into())
        );
        for text in [
            "Confirm use of this key?",
            "Please insert the card with serial number:",
            "Please insert the card with serial number: nope",
            "Please insert the card with serial number: 0005 00001234 please",
            "Prefix Please insert the card with serial number: 0005 00001234",
            "Please insert the card with serial number:\n0005 00001234\nlabel\nother",
        ] {
            assert_eq!(insertion_number(text), None, "{text}");
        }
    }
    #[test]
    fn native_card_number_formats() {
        assert_eq!(
            card_number("D2760001240100000006120808620000"),
            "12 080 862"
        );
        assert_eq!(
            card_number("D2760001240103040005000012340000"),
            "0005 00001234"
        );
        assert_eq!(card_number("12345678901234567890"), "1234567890123456789");
        assert_eq!(
            description("ABC", ""),
            "Please insert the card with serial number:\n\n  ABC\n  "
        );
    }
}
