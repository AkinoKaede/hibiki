//! Styles for human-readable output. Render through anstream so redirected
//! output and NO_COLOR remain plain text; never use these in Assuan messages.
use anstyle::{AnsiColor, Color, Style};

pub const HEADING: Style = Style::new()
    .bold()
    .fg_color(Some(Color::Ansi(AnsiColor::Cyan)));
pub const SUCCESS: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green)));
pub const WARNING: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow)));
pub const ERROR: Style = Style::new()
    .bold()
    .fg_color(Some(Color::Ansi(AnsiColor::Red)));
