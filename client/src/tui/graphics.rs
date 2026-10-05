//! Startup-only capability query. All reads are bounded and finish before EventStream starts.
use super::qr::CellSize;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use std::{
    io::{self, Write},
    time::{Duration, Instant},
};

const QUERY: &[u8] = b"\x1b_Gi=31,s=1,v=1,a=q,t=d,f=24;AAAA\x1b\\\x1b[16t\x1b[5n";
const TIMEOUT: Duration = Duration::from_millis(300);

#[derive(Default)]
pub struct Detection {
    pub cell_size: Option<CellSize>,
    pub direct_placement: bool,
    pub input: Vec<Event>,
}

pub fn detect() -> Detection {
    let term = std::env::var("TERM").unwrap_or_default();
    if term.starts_with("screen")
        || term.starts_with("tmux")
        || std::env::var_os("TMUX").is_some()
        || std::env::var_os("STY").is_some()
    {
        return Detection::default();
    }
    let mut stdout = io::stdout().lock();
    if stdout
        .write_all(QUERY)
        .and_then(|_| stdout.flush())
        .is_err()
    {
        return Detection::default();
    }
    let mut input = Vec::new();
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline && input.len() < 8192 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let mut fd = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        // No detached reader: a missing response cannot consume later keystrokes.
        let ready = unsafe { libc::poll(&mut fd, 1, remaining.as_millis().max(1) as i32) };
        if ready < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if ready <= 0 || fd.revents & libc::POLLIN == 0 {
            break;
        }
        let mut bytes = [0; 1024];
        // Avoid Stdin's buffered reader, which could prefetch keystrokes that
        // crossterm's subsequent direct tty reads would never see.
        let count =
            unsafe { libc::read(libc::STDIN_FILENO, bytes.as_mut_ptr().cast(), bytes.len()) };
        if count <= 0 {
            break;
        }
        input.extend_from_slice(&bytes[..count as usize]);
        if input.windows(4).any(|window| window == b"\x1b[0n") {
            break;
        }
    }
    let mut result = parse(&input, current_cell_size());
    // Only use Unicode placeholders on terminals known to implement them.
    // A positive basic Kitty query alone does not promise that extension.
    let program = std::env::var("TERM_PROGRAM").unwrap_or_default();
    result.direct_placement = program == "WarpTerminal"
        || !(term == "xterm-kitty" || term == "xterm-ghostty" || program == "ghostty");
    result
}

pub fn current_cell_size() -> Option<CellSize> {
    let size = crossterm::terminal::window_size().ok()?;
    if size.columns == 0 || size.rows == 0 {
        return None;
    }
    let cell = (size.width / size.columns, size.height / size.rows);
    valid_cell_size(cell).then_some(cell)
}

fn valid_cell_size((width, height): CellSize) -> bool {
    (1..=1024).contains(&width) && (1..=1024).contains(&height)
}

fn parse(bytes: &[u8], fallback: Option<CellSize>) -> Detection {
    let text = String::from_utf8_lossy(bytes);
    let mut remaining = text.as_ref();
    let mut detection = Detection::default();
    let mut kitty = false;
    let mut cell_size = fallback;
    while !remaining.is_empty() {
        if let Some(rest) = remaining.strip_prefix("\x1b_G")
            && let Some((response, rest)) = rest.split_once("\x1b\\")
        {
            kitty |= response == "i=31;OK";
            remaining = rest;
            continue;
        }
        if let Some(rest) = remaining.strip_prefix("\x1b[200~")
            && let Some((paste, rest)) = rest.split_once("\x1b[201~")
        {
            detection.input.push(Event::Paste(paste.into()));
            remaining = rest;
            continue;
        }
        if let Some(rest) = remaining.strip_prefix("\x1b[")
            && let Some(end) = rest.find(|c: char| ('@'..='~').contains(&c))
        {
            let sequence = &rest[..=end];
            if let Some(dimensions) = sequence
                .strip_prefix("6;")
                .and_then(|s| s.strip_suffix('t'))
            {
                if let Some((height, width)) = dimensions.split_once(';')
                    && let (Ok(w), Ok(h)) = (width.parse::<u16>(), height.parse::<u16>())
                    && valid_cell_size((w, h))
                {
                    cell_size = Some((w, h));
                }
            } else if let Some(key) = sequence_key(sequence) {
                detection.input.push(Event::Key(key.into()));
            }
            remaining = &rest[end + 1..];
            continue;
        }
        if let Some(rest) = remaining.strip_prefix("\x1bO")
            && let Some(c) = rest.chars().next()
        {
            if let Some(key) = sequence_key(&c.to_string()) {
                detection.input.push(Event::Key(key.into()));
            }
            remaining = &rest[c.len_utf8()..];
            continue;
        }
        let c = remaining.chars().next().unwrap();
        remaining = &remaining[c.len_utf8()..];
        let (code, modifiers) = match c {
            '\x1b' => (KeyCode::Esc, KeyModifiers::NONE),
            '\r' | '\n' => (KeyCode::Enter, KeyModifiers::NONE),
            '\t' => (KeyCode::Tab, KeyModifiers::NONE),
            '\x7f' | '\x08' => (KeyCode::Backspace, KeyModifiers::NONE),
            '\x01'..='\x1a' => (
                KeyCode::Char((c as u8 + b'a' - 1) as char),
                KeyModifiers::CONTROL,
            ),
            c if !c.is_control() => (KeyCode::Char(c), KeyModifiers::NONE),
            _ => continue,
        };
        detection
            .input
            .push(Event::Key(KeyEvent::new(code, modifiers)));
    }
    detection.cell_size = if kitty { cell_size } else { None };
    detection
}

fn sequence_key(sequence: &str) -> Option<KeyCode> {
    Some(match sequence {
        "A" => KeyCode::Up,
        "B" => KeyCode::Down,
        "C" => KeyCode::Right,
        "D" => KeyCode::Left,
        "H" => KeyCode::Home,
        "F" => KeyCode::End,
        "Z" => KeyCode::BackTab,
        "3~" => KeyCode::Delete,
        "5~" => KeyCode::PageUp,
        "6~" => KeyCode::PageDown,
        _ => return None,
    })
}
