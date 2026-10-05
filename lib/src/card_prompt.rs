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
pub fn description(serial: Option<&str>, label: Option<&str>) -> String {
    match serial {
        Some(serial) => format!(
            "Please insert the card with serial number:\n\n  {}\n  {}",
            card_number(serial),
            label.unwrap_or_default()
        ),
        None => "Please insert your OpenPGP card.".into(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
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
            description(Some("ABC"), None),
            "Please insert the card with serial number:\n\n  ABC\n  "
        );
    }
}
