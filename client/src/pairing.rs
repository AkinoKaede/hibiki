//! Local, fail-closed presentation of a signed admission request.
use crate::terminal::{HEADING, WARNING};
use anstream::{
    AutoStream,
    stream::{AsLockedWrite, RawStream},
};
use anyhow::{Context, Result, bail};
use hibiki_lib::invitation::AdmissionRequest;
use hibiki_lib::{channel::VerifiedChannelState, identity::Device};
use std::io::{BufRead, Read, Write};

pub fn show_device(output: &mut (impl RawStream + AsLockedWrite), device: &Device) -> Result<()> {
    write_device(&mut AutoStream::auto(output), device)
}

fn write_device(output: &mut impl Write, device: &Device) -> Result<()> {
    let words = device.public_key_words()?;
    // Debug formatting escapes terminal control sequences in untrusted display names.
    writeln!(output, "{HEADING}Device name:{HEADING:#} {:?}", device.name)?;
    writeln!(output, "{HEADING}Device ID:{HEADING:#} {}", device.id())?;
    writeln!(
        output,
        "{HEADING}Verification words:{HEADING:#}\n{}",
        crate::presentation::words(&words)
    )?;
    writeln!(
        output,
        "These 24 words verify this device’s public key. They are not a recovery phrase."
    )?;
    output.flush()?;
    Ok(())
}
fn answer(input: &mut impl BufRead, output: &mut impl Write, prompt: &str) -> Result<String> {
    write!(output, "{WARNING}{prompt}{WARNING:#}")?;
    output.flush()?;
    let mut response = String::new();
    input.take(1025).read_line(&mut response)?;
    if response.len() > 1024 {
        bail!("answer too long");
    }
    Ok(response.trim().to_owned())
}

pub fn choose_approval(
    requests: Vec<AdmissionRequest>,
    state: &VerifiedChannelState,
    request_id: Option<&str>,
    input: &mut impl BufRead,
    output: &mut (impl RawStream + AsLockedWrite),
) -> Result<Option<AdmissionRequest>> {
    let mut output = AutoStream::auto(output);
    let output = &mut output;
    let mut candidates = Vec::new();
    for request in requests {
        hibiki_core::management::validate_pending(&request, state)?;
        let id = request.id()?;
        candidates.push((id, request));
    }
    if let Some(prefix) = request_id {
        let id = hibiki_lib::selection::resolve_id(
            prefix,
            candidates.iter().map(|(id, _)| id.as_str()),
        )?;
        candidates.retain(|(candidate, _)| candidate == &id);
    }
    candidates.sort_by(|a, b| a.0.cmp(&b.0));
    if candidates.is_empty() {
        if request_id.is_some() {
            bail!("request ID not found; it may have been approved or invalidated");
        }
        writeln!(output, "No pending requests.")?;
        return Ok(None);
    }
    writeln!(
        output,
        "{HEADING}Channel:{HEADING:#} {:?} ({})",
        state.name, state.id
    )?;
    let index = if candidates.len() == 1 {
        0
    } else {
        for (index, (id, request)) in candidates.iter().enumerate() {
            writeln!(
                output,
                "{}) {:?}  device={}  request={id}",
                index + 1,
                request.body.device.name,
                request.body.device.id()
            )?;
        }
        let selected = answer(input, output, "Select request number (Enter to cancel): ")?;
        if selected.is_empty() {
            return Ok(None);
        }
        selected
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .filter(|n| *n < candidates.len())
            .context("invalid request selection; nothing approved")?
    };
    let (id, request) = candidates.swap_remove(index);
    writeln!(output, "{HEADING}Request ID:{HEADING:#} {id}")?;
    write_device(output, &request.body.device)?;
    writeln!(
        output,
        "{WARNING}Compare the 24 verification words and request ID with the joining device using a trusted channel.{WARNING:#}"
    )?;
    if answer(input, output, "Approve this device? [y/N]: ")?.eq_ignore_ascii_case("y") {
        return Ok(Some(request));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hibiki_lib::{
        channel::{ChannelGenesis, MembershipProof},
        identity::Identity,
    };
    use std::io::Cursor;

    fn fixture() -> (VerifiedChannelState, AdmissionRequest) {
        let founder = Identity::generate("founder".into()).unwrap();
        let applicant = Identity::generate("new device".into()).unwrap();
        let proof = MembershipProof {
            genesis: ChannelGenesis::create(&founder, hibiki_lib::random_id(), "test".into())
                .unwrap(),
            events: vec![],
        };
        let state = proof.verify().unwrap();
        let request =
            AdmissionRequest::create(&applicant, &state, hibiki_lib::random_id(), 0).unwrap();
        (state, request)
    }
    #[test]
    fn approval_defaults_to_no_and_requires_explicit_y() {
        let (state, request) = fixture();
        for response in ["", "\n", "n\n", "N\n", "yes\n", "unexpected\n"] {
            let mut output = Vec::new();
            assert!(
                choose_approval(
                    vec![request.clone()],
                    &state,
                    None,
                    &mut Cursor::new(response),
                    &mut output
                )
                .unwrap()
                .is_none()
            );
            let text = String::from_utf8(output).unwrap();
            assert!(text.contains(&crate::presentation::words(
                &request.body.device.public_key_words().unwrap()
            )));
            assert!(text.contains("[y/N]"));
        }
        for response in ["y\n", "Y\n"] {
            let result = choose_approval(
                vec![request.clone()],
                &state,
                Some(&request.id().unwrap()),
                &mut Cursor::new(response),
                &mut Vec::new(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(result, request);
        }
    }
    #[test]
    fn interactive_selection_approves_only_the_displayed_request() {
        let (state, first) = fixture();
        let second = AdmissionRequest::create(
            &Identity::generate("second".into()).unwrap(),
            &state,
            hibiki_lib::random_id(),
            0,
        )
        .unwrap();
        let mut expected = [first.clone(), second.clone()];
        expected.sort_by_key(|r| r.id().unwrap());
        let mut output = Vec::new();
        let result = choose_approval(
            vec![first.clone(), second.clone()],
            &state,
            None,
            &mut Cursor::new("2\ny\n"),
            &mut output,
        )
        .unwrap()
        .unwrap();
        assert_eq!(result, expected[1]);
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains(&crate::presentation::words(
                    &expected[1].body.device.public_key_words().unwrap()
                ))
        );
        assert!(
            choose_approval(
                vec![first.clone(), second.clone()],
                &state,
                None,
                &mut Cursor::new("\n"),
                &mut Vec::new()
            )
            .unwrap()
            .is_none()
        );
        assert!(
            choose_approval(
                vec![first, second],
                &state,
                None,
                &mut Cursor::new("0\ny\n"),
                &mut Vec::new()
            )
            .is_err()
        );
    }
    #[test]
    fn foreign_or_tampered_requests_never_reach_confirmation() {
        let (state, mut request) = fixture();
        request.signature[0] ^= 1;
        let mut output = Vec::new();
        assert!(
            choose_approval(
                vec![request],
                &state,
                None,
                &mut Cursor::new("y\n"),
                &mut output
            )
            .is_err()
        );
        assert!(output.is_empty());
        let (_, foreign) = fixture();
        assert!(
            choose_approval(
                vec![foreign],
                &state,
                None,
                &mut Cursor::new("y\n"),
                &mut output
            )
            .is_err()
        );
        assert!(output.is_empty());
    }
    #[test]
    fn display_names_cannot_inject_terminal_instructions() {
        let device = Identity::generate("\x1b[2J\nApprove fake?".into())
            .unwrap()
            .device
            .clone();
        let mut output = Vec::new();
        show_device(&mut output, &device).unwrap();
        assert!(!output.contains(&0x1b));
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("\\nApprove fake?")
        );
    }
}
