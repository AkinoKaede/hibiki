/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

use hibiki_lib::{assuan::*, protocol::ServiceKind::*};
#[test]
fn binary_framing_and_full_inquiries() {
    let bytes: Vec<_> = (0..=255).cycle().take(2500).collect();
    let mut out = Vec::new();
    for line in data_lines(&bytes) {
        assert!(line.len() < MAX_LINE);
        let Response::Data(d) = parse_response(&line).unwrap() else {
            panic!()
        };
        out.extend_from_slice(&unescape(d).unwrap());
    }
    assert_eq!(bytes, out);
    assert_eq!(&*unescape(b"a+b%25").unwrap(), b"a+b%");
    assert_eq!(
        parse_response(b"INQUIRE NEEDPIN |A|Enter PIN%0Acard").unwrap(),
        Response::Inquire(b"NEEDPIN |A|Enter PIN%0Acard")
    );
    for line in [b"OK\nERR 1".as_slice(), b"D x\rOK", b"INQUIRE ", b"ERR x"] {
        assert!(parse_response(line).is_err());
    }
    assert!(unescape(b"bad%").is_err());
    assert!(framing(&vec![0; MAX_LINE]).is_err());
}
#[test]
fn services_enforce_distinct_command_boundaries() {
    for c in [
        "SERIALNO --demand=D27600012401 openpgp",
        "LEARN --force",
        "READKEY --info -- 0123456789ABCDEF",
        "SETDATA --append AABB",
        "PKSIGN --hash=sha512 OPENPGP.1",
        "PKDECRYPT OPENPGP.2",
    ] {
        validate_command(Scdaemon, c.as_bytes()).unwrap();
        assert!(validate_command(Pinentry, c.as_bytes()).is_err());
    }
    for c in [
        "SETDESC Enter PIN",
        "SETERROR Retry",
        "SETREPEAT Again",
        "GETPIN",
        "CONFIRM --one-button",
        "OPTION ttyname=/dev/tty",
    ] {
        validate_command(Pinentry, c.as_bytes()).unwrap();
    }
    for c in [
        "PASSWD",
        "GENKEY --force 1",
        "WRITEKEY OPENPGP.1",
        "SETATTR LOGIN user",
        "APDU 00A40000",
        "PKSIGN --unknown x",
        "OPTION putenv=ATTACK=1",
        "SERIALNO piv",
        "SETDATA xyz",
    ] {
        assert!(validate_command(Scdaemon, c.as_bytes()).is_err(), "{c}");
    }
    for service in [Scdaemon, Pinentry] {
        assert!(validate_command(service, b"NOP\nGETPIN").is_err());
        assert!(validate_command(service, b"NOP\0").is_err());
    }
}
#[test]
fn complete_results_only_and_redacted_debug() {
    for lines in [
        vec!["OK", "D extra"],
        vec!["OK", "OK"],
        vec!["D partial"],
        vec!["INQUIRE NEEDPIN", "OK"],
        vec!["D broken%", "OK"],
    ] {
        assert!(
            AssuanResult {
                lines: lines.into_iter().map(Line::from).collect()
            }
            .validate()
            .is_err()
        );
    }
    assert!(AssuanResult::error(83886179, "canceled").canceled());
    assert!(AssuanResult::error(67109062, "canceled").canceled());
    assert!(!format!("{:?}", Line::from("D secret-passphrase")).contains("secret-passphrase"));
}
