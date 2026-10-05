//! Interactive management uses its own control connection; the service daemon is untouched.
use crate::{
    management::{self, Manager, Snapshot},
    presentation::{self, safe},
    storage::{App, Config},
};
use anyhow::{Context, Result, bail};
use crossterm::{
    event::{
        DisableBracketedPaste, EnableBracketedPaste, Event, EventStream, KeyCode, KeyEvent,
        KeyEventKind, KeyModifiers,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use futures_util::StreamExt;
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use std::{
    io::{IsTerminal, Write},
    path::PathBuf,
    time::Duration,
};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

const PAGES: [&str; 5] = ["Overview", "Channels", "Devices", "Requests", "Settings"];
#[derive(Clone)]
enum Action {
    Refresh,
    Init {
        server: String,
        name: String,
        insecure: bool,
    },
    Select(String),
    Rename(String),
    Ping(String, String),
    Approve(String, String),
    Reject(String, String),
    Revoke(String, String, bool, u64),
    Leave(String),
    Invite(String),
    Join(Zeroizing<String>),
    Create(String),
    Settings(Box<Config>, Vec<u8>, Box<Config>),
    Export(Zeroizing<String>, PathBuf, bool),
}
enum Update {
    Snapshot(Box<Snapshot>),
    Done(String, Option<Zeroizing<String>>),
    Error(String),
    Offline(String),
}
struct TerminalGuard;
impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        let guard = Self;
        execute!(
            std::io::stdout(),
            EnterAlternateScreen,
            EnableBracketedPaste
        )?;
        Ok(guard)
    }
}
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            std::io::stdout(),
            DisableBracketedPaste,
            LeaveAlternateScreen,
            crossterm::cursor::Show
        );
    }
}
struct Field {
    label: &'static str,
    value: Zeroizing<String>,
    secret: bool,
}
impl Field {
    fn new(label: &'static str, value: impl Into<String>, secret: bool) -> Self {
        Self {
            label,
            value: Zeroizing::new(value.into()),
            secret,
        }
    }
}
#[derive(Clone)]
enum FormKind {
    Rename,
    Init,
    Join,
    Create,
    Settings(Box<Config>, Vec<u8>),
    Export(Zeroizing<String>),
}
enum Modal {
    Menu {
        choices: Vec<(String, ActionChoice)>,
        selected: usize,
    },
    Form {
        title: String,
        fields: Vec<Field>,
        kind: FormKind,
        selected: usize,
    },
    Confirm {
        title: String,
        details: String,
        action: Action,
        affirmative: bool,
        verified: bool,
        approval: bool,
        scroll: u16,
    },
    Secret {
        qr: bool,
        title: String,
        text: Zeroizing<String>,
        scroll: u16,
    },
    Result {
        text: String,
        scroll: u16,
    },
    Help,
}
#[derive(Clone)]
enum ActionChoice {
    Execute(Action),
    Form(FormKind),
    Verification(String),
}
struct Row {
    id: String,
    title: String,
    detail: String,
}
#[derive(Default)]
struct Ui {
    snapshot: Option<Snapshot>,
    page: usize,
    focus: usize,
    selected: Option<String>,
    filter: String,
    filtering: bool,
    modal: Option<Modal>,
    message: String,
    busy: bool,
    detail_scroll: u16,
}
impl Ui {
    fn rows(&self) -> Vec<Row> {
        let Some(s) = &self.snapshot else {
            return Vec::new();
        };
        let rows = match self.page {
            1 => s
                .channels
                .iter()
                .map(|c| Row {
                    id: c.id.clone(),
                    title: format!(
                        "{}{} · {}",
                        if c.selected { "* " } else { "" },
                        safe(&c.name),
                        if c.member { "Member" } else { "Not a member" }
                    ),
                    detail: format!(
                        "Channel: {}\nChannel ID: {}\nRevision: {}\nMembers: {}\nStatus: {}\n{}",
                        safe(&c.name),
                        c.id,
                        c.revision,
                        c.devices.len(),
                        if c.available {
                            "Current"
                        } else {
                            "Unavailable / cached"
                        },
                        c.error.as_deref().map(safe).unwrap_or_default()
                    ),
                })
                .collect(),
            2 => s
                .channels
                .iter()
                .flat_map(|c| {
                    c.devices.iter().map(move |d| Row {
                        id: format!("{}:{}", c.id, d.id),
                        title: format!(
                            "{}{} · {}",
                            safe(&d.name),
                            if d.local { " (this device)" } else { "" },
                            safe(&c.name)
                        ),
                        detail: format!(
                            "Channel: {}\n{}\n{}",
                            safe(&c.name),
                            if d.approved_by.is_none() {
                                "Approval role: Channel founder"
                            } else {
                                ""
                            },
                            presentation::device_details(d)
                        ),
                    })
                })
                .collect(),
            3 => s
                .channels
                .iter()
                .flat_map(|c| {
                    c.pending.iter().map(|p| Row {
                        id: p.id.clone(),
                        title: format!(
                            "{} · {}{}",
                            safe(&p.device.name),
                            safe(&p.channel_name),
                            if p.own { " (your request)" } else { "" }
                        ),
                        detail: presentation::pending_details(p),
                    })
                })
                .collect(),
            _ => Vec::new(),
        };
        let query = self.filter.to_lowercase();
        let mut rows: Vec<Row> = rows;
        rows.retain(|r| {
            format!("{} {}", r.title, r.detail)
                .to_lowercase()
                .contains(&query)
        });
        rows
    }
    fn current(&self) -> Option<Row> {
        self.rows()
            .into_iter()
            .find(|r| self.selected.as_ref() == Some(&r.id))
    }
    fn move_selection(&mut self, delta: isize) {
        let rows = self.rows();
        if rows.is_empty() {
            self.selected = None;
            return;
        }
        let old = rows
            .iter()
            .position(|r| self.selected.as_ref() == Some(&r.id))
            .unwrap_or(0);
        let index = (old as isize + delta).rem_euclid(rows.len() as isize) as usize;
        self.selected = Some(rows[index].id.clone());
        self.detail_scroll = 0;
    }
    fn apply_snapshot(&mut self, snapshot: Snapshot) {
        if let Some(Modal::Confirm {
            action: Action::Revoke(channel, device, _, revision),
            ..
        }) = &self.modal
            && !snapshot
                .channels
                .iter()
                .find(|c| &c.id == channel)
                .is_some_and(|c| {
                    c.revision == *revision
                        && c.devices.iter().any(|d| &d.id == device && d.can_revoke)
                })
        {
            self.modal = None;
            self.message =
                "Revocation authority changed. Confirmation canceled; nothing submitted.".into();
        }
        if let Some(Modal::Confirm {
            action: Action::Approve(_, id) | Action::Reject(_, id),
            ..
        }) = &self.modal
            && !snapshot
                .channels
                .iter()
                .any(|c| c.pending.iter().any(|p| &p.id == id))
        {
            self.modal = None;
            self.message =
                "Request was handled elsewhere. Selection cleared; nothing submitted.".into();
        }
        self.snapshot = Some(snapshot);
        if self.current().is_none() {
            self.selected = self.rows().first().map(|r| r.id.clone());
        }
    }
    fn form(&mut self, kind: FormKind) {
        let (title, fields) = match &kind {
            FormKind::Rename => (
                "Rename this device",
                vec![Field::new(
                    "Device name",
                    self.snapshot
                        .as_ref()
                        .map(|s| s.local_device.name.clone())
                        .unwrap_or_default(),
                    false,
                )],
            ),
            FormKind::Init => (
                "Initialize Hibiki",
                vec![
                    Field::new("Relay URL", "wss://", false),
                    Field::new("Device name", "", false),
                    Field::new("Allow insecure ws (true/false)", "false", false),
                ],
            ),
            FormKind::Join => ("Join channel", vec![Field::new("Invitation", "", true)]),
            FormKind::Create => (
                "Create channel",
                vec![Field::new("Channel name", "", false)],
            ),
            FormKind::Export(_) => (
                "Export secret (0600)",
                vec![Field::new("File path", "", false)],
            ),
            FormKind::Settings(c, _) => (
                "Edit local settings",
                vec![
                    Field::new("Scdaemon enabled", c.scdaemon.enabled.to_string(), false),
                    Field::new(
                        "Scdaemon program (blank: discover)",
                        c.scdaemon
                            .program
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default(),
                        false,
                    ),
                    Field::new("Pinentry enabled", c.pinentry.enabled.to_string(), false),
                    Field::new(
                        "Pinentry program (blank: discover)",
                        c.pinentry
                            .program
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default(),
                        false,
                    ),
                    Field::new(
                        "Command timeout (1..3600 seconds)",
                        c.operation_timeout_seconds.to_string(),
                        false,
                    ),
                ],
            ),
        };
        self.modal = Some(Modal::Form {
            title: title.into(),
            fields,
            kind,
            selected: 0,
        });
    }
    fn action_menu(&mut self) {
        let Some(s) = &self.snapshot else {
            return;
        };
        let online = s.relay_connected;
        let mut choices = Vec::new();
        if self.page == 4 {
            choices.push((
                "Edit local service settings".into(),
                ActionChoice::Form(FormKind::Settings(
                    Box::new(s.config.clone()),
                    s.config_source.clone(),
                )),
            ));
        }
        if self.page <= 1
            && let Some(c) = s
                .channels
                .iter()
                .find(|c| self.selected.as_ref() == Some(&c.id) && c.member)
        {
            choices.push((
                "Use as default channel".into(),
                ActionChoice::Execute(Action::Select(c.id.clone())),
            ));
        }
        if online {
            if self.page == 2 || self.page == 4 {
                choices.push((
                    "Rename this device".into(),
                    ActionChoice::Form(FormKind::Rename),
                ));
            }
            if self.page <= 1 {
                choices.push(("Join a channel".into(), ActionChoice::Form(FormKind::Join)));
                if s.allow_channel_creation {
                    choices.push((
                        "Create a channel".into(),
                        ActionChoice::Form(FormKind::Create),
                    ));
                }
                if let Some(c) = s
                    .channels
                    .iter()
                    .find(|c| self.selected.as_ref() == Some(&c.id))
                {
                    if c.member {
                        choices.push((
                            "Generate invitation".into(),
                            ActionChoice::Execute(Action::Invite(c.id.clone())),
                        ));
                    }
                    choices.push((
                        "Leave channel / withdraw own requests".into(),
                        ActionChoice::Execute(Action::Leave(c.id.clone())),
                    ));
                }
            }
            if self.page == 2
                && let Some(id) = &self.selected
                && let Some((channel, device)) = id.split_once(':')
            {
                if device != s.local_device.id {
                    choices.push((
                        "Ping this device".into(),
                        ActionChoice::Execute(Action::Ping(channel.into(), device.into())),
                    ));
                }
                if s.channels
                    .iter()
                    .find(|c| c.id == channel)
                    .is_some_and(|c| c.devices.iter().any(|d| d.id == device && d.can_revoke))
                {
                    choices.push((
                        "Revoke device membership".into(),
                        ActionChoice::Execute(Action::Revoke(
                            channel.into(),
                            device.into(),
                            false,
                            s.channels
                                .iter()
                                .find(|c| c.id == channel)
                                .unwrap()
                                .revision,
                        )),
                    ));
                    if let Some(c) = s.channels.iter().find(|c| c.id == channel)
                        && c.devices
                            .iter()
                            .any(|d| d.id == device && !d.revocation_subtree.is_empty())
                    {
                        choices.push((
                            "Revoke entire approval subtree".into(),
                            ActionChoice::Execute(Action::Revoke(
                                channel.into(),
                                device.into(),
                                true,
                                c.revision,
                            )),
                        ));
                    }
                }
            }
            if self.page == 3
                && let Some(p) = s
                    .channels
                    .iter()
                    .flat_map(|c| &c.pending)
                    .find(|p| self.selected.as_ref() == Some(&p.id))
            {
                if p.own {
                    choices.push((
                        "Show verification QR / text".into(),
                        ActionChoice::Verification(p.verification.clone()),
                    ));
                    choices.push((
                        "Withdraw own request".into(),
                        ActionChoice::Execute(Action::Leave(p.channel.clone())),
                    ));
                } else {
                    choices.push((
                        "Review and approve".into(),
                        ActionChoice::Execute(Action::Approve(p.channel.clone(), p.id.clone())),
                    ));
                    choices.push((
                        "Reject request".into(),
                        ActionChoice::Execute(Action::Reject(p.channel.clone(), p.id.clone())),
                    ));
                }
            }
        }
        if choices.is_empty() {
            self.message = if online {
                "Select an item to manage it."
            } else {
                "Relay offline. Online changes are disabled; local settings remain editable."
            }
            .into();
        } else {
            self.modal = Some(Modal::Menu {
                choices,
                selected: 0,
            });
        }
    }
    fn choose(&mut self, choice: ActionChoice, tx: &mpsc::Sender<Action>) {
        match choice {
            ActionChoice::Form(kind) => self.form(kind),
            ActionChoice::Verification(text) => {
                self.modal = Some(Modal::Secret {
                    qr: true,
                    title: "Waiting for approval · public verification code".into(),
                    text: Zeroizing::new(text),
                    scroll: 0,
                });
            }
            ActionChoice::Execute(action) => match &action {
                Action::Select(_) | Action::Ping(..) | Action::Invite(_) => self.submit(action, tx),
                _ => {
                    let approval = matches!(action, Action::Approve(..));
                    let explanation = match action {
                        Action::Approve(..) => {
                            "Compare the complete request ID and all 24 words with the joining device. Press Space only after verifying."
                        }
                        Action::Revoke(..) => {
                            "This device will lose access. Rejoining requires a fresh request and approval."
                        }
                        Action::Leave(..) => {
                            "Withdraw your pending requests and leave this channel. Other devices remain members."
                        }
                        _ => "Reject this request. The applicant may request admission again.",
                    };
                    let mut detail = self.current().map(|r| r.detail).unwrap_or_default();
                    if let Action::Revoke(channel, device, subtree, _) = &action
                        && let Some(c) = self
                            .snapshot
                            .as_ref()
                            .and_then(|s| s.channels.iter().find(|c| &c.id == channel))
                        && let Some(d) = c.devices.iter().find(|d| &d.id == device)
                    {
                        let affected: Vec<_> = c
                            .devices
                            .iter()
                            .filter(|item| {
                                if *subtree {
                                    d.revocation_subtree.contains(&item.id)
                                } else {
                                    item.id == *device
                                }
                            })
                            .collect();
                        detail = format!(
                            "Revoke {} device(s){}:\n\n{}",
                            affected.len(),
                            if *subtree {
                                " (entire subtree)"
                            } else {
                                " (selected device only)"
                            },
                            affected
                                .iter()
                                .map(|d| format!("{}\n{}", safe(&d.name), d.id))
                                .collect::<Vec<_>>()
                                .join("\n\n")
                        );
                    }
                    self.modal = Some(Modal::Confirm {
                        title: "Confirm management action".into(),
                        details: format!("{detail}\n\n{explanation}"),
                        action,
                        affirmative: false,
                        verified: false,
                        approval,
                        scroll: 0,
                    });
                }
            },
        }
    }
    fn submit(&mut self, action: Action, tx: &mpsc::Sender<Action>) {
        if self.busy {
            self.message = "An action is already in progress.".into();
            return;
        }
        if tx.try_send(action).is_err() {
            self.message = "Management worker is busy; try again.".into();
            return;
        }
        self.busy = true;
        self.modal = None;
        self.message = "Working…".into();
    }
    fn form_action(kind: &FormKind, fields: &[Field]) -> Result<Action> {
        let value = |i: usize| fields[i].value.to_string();
        let boolean = |i: usize| -> Result<bool> {
            fields[i]
                .value
                .trim()
                .parse::<bool>()
                .context("use true or false")
        };
        Ok(match kind {
            FormKind::Rename => Action::Rename(value(0)),
            FormKind::Init => Action::Init {
                server: value(0),
                name: value(1),
                insecure: boolean(2)?,
            },
            FormKind::Join => Action::Join(Zeroizing::new(value(0))),
            FormKind::Create => Action::Create(value(0)),
            FormKind::Export(text) => {
                if fields[0].value.trim().is_empty() {
                    bail!("file path is required");
                }
                Action::Export(text.clone(), PathBuf::from(value(0)), false)
            }
            FormKind::Settings(expected, source) => {
                let mut edited = (**expected).clone();
                edited.scdaemon.enabled = boolean(0)?;
                edited.pinentry.enabled = boolean(2)?;
                edited.scdaemon.program =
                    (!fields[1].value.is_empty()).then(|| PathBuf::from(value(1)));
                edited.pinentry.program =
                    (!fields[3].value.is_empty()).then(|| PathBuf::from(value(3)));
                edited.operation_timeout_seconds =
                    value(4).parse().context("timeout must be a number")?;
                Action::Settings(expected.clone(), source.clone(), Box::new(edited))
            }
        })
    }
    fn key(&mut self, key: KeyEvent, tx: &mpsc::Sender<Action>) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return true;
        }
        if let Some(mut modal) = self.modal.take() {
            if key.code == KeyCode::Esc {
                return false;
            }
            match &mut modal {
                Modal::Help => {}
                Modal::Secret {
                    text, scroll, qr, ..
                } => match key.code {
                    KeyCode::Char('v') => {
                        *qr = !*qr;
                        *scroll = 0;
                    }
                    KeyCode::Char('e') => {
                        self.form(FormKind::Export(text.clone()));
                        return false;
                    }
                    KeyCode::Down | KeyCode::Char('j') => *scroll = scroll.saturating_add(1),
                    KeyCode::Up | KeyCode::Char('k') => *scroll = scroll.saturating_sub(1),
                    _ => {}
                },
                Modal::Result { scroll, .. } => match key.code {
                    KeyCode::Down | KeyCode::Char('j') => *scroll = scroll.saturating_add(1),
                    KeyCode::Up | KeyCode::Char('k') => *scroll = scroll.saturating_sub(1),
                    _ => {}
                },
                Modal::Menu { choices, selected } => match key.code {
                    KeyCode::Down | KeyCode::Char('j') => {
                        *selected = (*selected + 1) % choices.len()
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        *selected = (*selected + choices.len() - 1) % choices.len()
                    }
                    KeyCode::Enter => {
                        let choice = choices[*selected].1.clone();
                        self.choose(choice, tx);
                        return false;
                    }
                    _ => {}
                },
                Modal::Confirm {
                    action,
                    affirmative,
                    verified,
                    approval,
                    scroll,
                    ..
                } => match key.code {
                    KeyCode::Up | KeyCode::Char('k') => *scroll = scroll.saturating_sub(1),
                    KeyCode::Down | KeyCode::Char('j') => *scroll = scroll.saturating_add(1),
                    KeyCode::Left | KeyCode::Right | KeyCode::Tab => *affirmative = !*affirmative,
                    KeyCode::Char(' ') if *approval => *verified = !*verified,
                    KeyCode::Enter => {
                        if !*affirmative {
                            return false;
                        }
                        if *approval && !*verified {
                            self.message =
                                "Verify the request ID and all 24 words, then press Space.".into();
                        } else {
                            self.submit(action.clone(), tx);
                            return false;
                        }
                    }
                    _ => {}
                },
                Modal::Form {
                    fields,
                    kind,
                    selected,
                    ..
                } => match key.code {
                    KeyCode::Tab | KeyCode::Down => {
                        *selected = (*selected + 1) % (fields.len() + 1)
                    }
                    KeyCode::BackTab | KeyCode::Up => {
                        *selected = (*selected + fields.len()) % (fields.len() + 1)
                    }
                    KeyCode::Enter if *selected < fields.len() => *selected += 1,
                    KeyCode::Enter => match Self::form_action(kind, fields) {
                        Ok(Action::Export(text, path, false)) if path.exists() => {
                            self.modal = Some(Modal::Confirm {
                                title: "Overwrite file?".into(),
                                details: format!(
                                    "Replace {} with this secret export (permissions 0600).",
                                    safe(&path.display().to_string())
                                ),
                                action: Action::Export(text, path, true),
                                affirmative: false,
                                verified: false,
                                approval: false,
                                scroll: 0,
                            });
                            return false;
                        }
                        Ok(action) => {
                            self.submit(action, tx);
                            return false;
                        }
                        Err(error) => self.message = format!("{error:#}"),
                    },
                    KeyCode::Backspace if *selected < fields.len() => {
                        fields[*selected].value.pop();
                    }
                    KeyCode::Char(c)
                        if *selected < fields.len()
                            && !c.is_control()
                            && fields[*selected].value.len() < 32768 =>
                    {
                        fields[*selected].value.push(c);
                    }
                    _ => {}
                },
            }
            self.modal = Some(modal);
            return false;
        }
        if self.filtering {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => self.filtering = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                }
                KeyCode::Char(c) => self.filter.push(c),
                _ => {}
            }
            self.selected = self.rows().first().map(|r| r.id.clone());
            return false;
        }
        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Char('?') => self.modal = Some(Modal::Help),
            KeyCode::Char('i') if self.page == 1 => {
                if let Some(channel) = self
                    .snapshot
                    .as_ref()
                    .filter(|s| s.relay_connected)
                    .and_then(|s| {
                        s.channels.iter().find(|c| {
                            self.selected.as_ref() == Some(&c.id) && c.member && c.available
                        })
                    })
                    .map(|c| c.id.clone())
                {
                    self.submit(Action::Invite(channel), tx);
                }
            }
            KeyCode::Tab => self.focus = (self.focus + 1) % 3,
            KeyCode::BackTab => self.focus = (self.focus + 2) % 3,
            KeyCode::Char('/') => {
                self.filtering = true;
            }
            KeyCode::Esc => {
                self.focus = 1;
                self.filter.clear();
                self.detail_scroll = 0;
            }
            KeyCode::Char('r') => {
                let _ = tx.try_send(Action::Refresh);
            }
            KeyCode::Char('a') => self.action_menu(),
            KeyCode::Enter => {
                if self.focus == 2 || self.page == 4 {
                    self.action_menu();
                } else {
                    self.focus = 2;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.focus == 0 {
                    self.page = (self.page + 1) % 5;
                    self.selected = self.rows().first().map(|r| r.id.clone());
                } else if self.focus == 2 {
                    self.detail_scroll = self.detail_scroll.saturating_add(1);
                } else {
                    self.move_selection(1);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.focus == 0 {
                    self.page = (self.page + 4) % 5;
                    self.selected = self.rows().first().map(|r| r.id.clone());
                } else if self.focus == 2 {
                    self.detail_scroll = self.detail_scroll.saturating_sub(1);
                } else {
                    self.move_selection(-1);
                }
            }
            KeyCode::Char(c @ '1'..='5') => {
                self.page = (c as u8 - b'1') as usize;
                self.selected = self.rows().first().map(|r| r.id.clone());
                self.detail_scroll = 0;
            }
            _ => {}
        }
        false
    }
    fn draw(&self, f: &mut Frame) {
        let area = f.area();
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(1),
                Constraint::Length(3),
                Constraint::Length(2),
            ])
            .split(area);
        let status = self
            .snapshot
            .as_ref()
            .map(|s| {
                format!(
                    "{} · relay {} · daemon {} · snapshot {}",
                    safe(&s.local_device.name),
                    if s.relay_connected {
                        "online"
                    } else {
                        "offline (cached)"
                    },
                    if s.daemon_running {
                        "running"
                    } else {
                        "not running"
                    },
                    presentation::timestamp(s.captured_at)
                )
            })
            .unwrap_or_else(|| "Initialize this device to begin".into());
        f.render_widget(
            Paragraph::new(status).block(
                Block::default()
                    .title("Hibiki · management")
                    .borders(Borders::ALL),
            ),
            parts[0],
        );
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(15), Constraint::Min(1)])
            .split(parts[1]);
        let items: Vec<_> = PAGES
            .iter()
            .enumerate()
            .map(|(i, name)| ListItem::new(format!("{} {name}", i + 1)))
            .collect();
        let mut nav = ListState::default().with_selected(Some(self.page));
        f.render_stateful_widget(
            List::new(items)
                .block(pane("Navigation", self.focus == 0))
                .highlight_style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
            cols[0],
            &mut nav,
        );
        let content = cols[1];
        let rows = self.rows();
        let overview=self.snapshot.as_ref().map(|s|format!("{}\n\nRelay: {}\nDaemon: {}\nChannels: {}\nPending requests: {}\nDefault channel: {}\nChannel creation: {}\n\nPress a for actions. Settings edits do not restart the daemon.",presentation::device_details(&s.local_device),safe(&s.config.server),if s.daemon_running{"Running"}else{"Not running"},s.channels.len(),s.channels.iter().map(|c|c.pending.len()).sum::<usize>(),s.config.default_channel.as_deref().unwrap_or("Not selected"),if s.allow_channel_creation{"Allowed"}else{"Requires an administrator invitation"})).unwrap_or_else(||"No identity. Complete the initialization form.".into());
        let settings=self.snapshot.as_ref().map(|s| {
            let describe=|c:&Config|format!("Scdaemon: {}\n  Program: {}\nPinentry: {}\n  Program: {}\nTimeout: {} seconds",if c.scdaemon.enabled{"Enabled"}else{"Disabled"},c.scdaemon.program.as_ref().map(|p|safe(&p.display().to_string())).unwrap_or_else(||"Auto-discover".into()),if c.pinentry.enabled{"Enabled"}else{"Disabled"},c.pinentry.program.as_ref().map(|p|safe(&p.display().to_string())).unwrap_or_else(||"Auto-discover".into()),c.operation_timeout_seconds);
            let restart=s.running_config.as_ref().is_some_and(|c|c.scdaemon!=s.config.scdaemon||c.pinentry!=s.config.pinentry||c.operation_timeout_seconds!=s.config.operation_timeout_seconds);
            format!("CONFIGURED\n{}\n\nRUNNING DAEMON\n{}\n\n{}\nDefault channel changes affect new adapter sessions only.\nPress a to edit.",describe(&s.config),s.running_config.as_ref().map(describe).unwrap_or_else(||"Not running".into()),if restart{"Restart daemon to apply the configured service settings."}else{"No unapplied service changes."})
        }).unwrap_or_default();
        if self.page == 0 || self.page == 4 {
            f.render_widget(
                Paragraph::new(if self.page == 0 { overview } else { settings })
                    .wrap(Wrap { trim: false })
                    .scroll((self.detail_scroll, 0))
                    .block(pane(PAGES[self.page], self.focus != 0)),
                content,
            );
        } else {
            let split = if area.width >= 110 {
                Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
                    .split(content)
                    .to_vec()
            } else {
                vec![content, content]
            };
            if area.width >= 110 || self.focus != 2 {
                let items: Vec<_> = if rows.is_empty() {
                    vec![ListItem::new("No matching entries")]
                } else {
                    rows.iter()
                        .map(|r| ListItem::new(r.title.clone()))
                        .collect()
                };
                let mut selection = ListState::default().with_selected(
                    rows.iter()
                        .position(|r| self.selected.as_ref() == Some(&r.id)),
                );
                f.render_stateful_widget(
                    List::new(items)
                        .highlight_symbol("› ")
                        .highlight_style(if self.focus == 1 {
                            Style::default()
                                .fg(Color::Black)
                                .bg(Color::Cyan)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(Color::Gray)
                        })
                        .block(pane(
                            format!("{} · {}", PAGES[self.page], rows.len()),
                            self.focus == 1,
                        )),
                    split[0],
                    &mut selection,
                );
            }
            if area.width >= 110 || self.focus == 2 {
                f.render_widget(
                    Paragraph::new(
                        self.current().map(|r| r.detail).unwrap_or_else(|| {
                            "Select an entry. Enter: details · a: actions".into()
                        }),
                    )
                    .wrap(Wrap { trim: false })
                    .scroll((self.detail_scroll, 0))
                    .block(pane("Details · full identities", self.focus == 2)),
                    split[1],
                );
            }
        }
        f.render_widget(
            Paragraph::new(safe(&self.message)).wrap(Wrap { trim: false }),
            parts[2],
        );
        f.render_widget(Paragraph::new(if self.filtering{format!("Filter: {}",safe(&self.filter))}else{"1–5 pages · Tab focus · ↑↓/jk move · Enter details · a actions · i invite · / filter · r refresh · ? help · q quit".into()}),parts[3]);
        if let Some(modal) = &self.modal {
            let rect = Rect::new(
                area.x + area.width / 20,
                area.y + area.height / 20,
                area.width.saturating_sub(area.width / 10),
                area.height.saturating_sub(area.height / 10),
            );
            f.render_widget(Clear, rect);
            match modal {
                Modal::Menu{choices,selected}=>{
                    let mut state=ListState::default().with_selected(Some(*selected));
                    f.render_stateful_widget(List::new(choices.iter().map(|(s,_)|ListItem::new(s.as_str())).collect::<Vec<_>>()).highlight_symbol("› ").highlight_style(Style::default().fg(Color::Cyan)).block(Block::default().borders(Borders::ALL).title("Actions · Enter select · Esc cancel")),rect,&mut state);
                },
                Modal::Form{title,fields,selected,..}=>{
                    let mut text=String::new();
                    for (i,field) in fields.iter().enumerate(){text.push_str(&format!("{}{}\n{}\n\n",if i==*selected{"› "}else{"  "},field.label,if field.secret{"•".repeat(field.value.chars().count().min(40))}else{safe(&field.value)}));}
                    text.push_str(if *selected==fields.len(){"› [ Save / Continue ]"}else{"  [ Save / Continue ]"});
                    // Scroll with the focused field on short terminals.
                    let scroll=((*selected*3+3) as u16).saturating_sub(rect.height.saturating_sub(3));
                    f.render_widget(Paragraph::new(text).wrap(Wrap{trim:false}).scroll((scroll,0)).block(Block::default().borders(Borders::ALL).title(format!("{title} · Tab next · Enter continue · Esc cancel"))),rect);
                },
                Modal::Confirm{title,details,affirmative,approval,verified,scroll,..}=>{
                    let text=format!("{}\n\n{}\n{}",details,if *approval{if *verified{"[x] Identity verified (Space to change)"}else{"[ ] I compared the request ID and all 24 words (Space)"}}else{""},if *affirmative{"  Cancel     [ Confirm ]"}else{"[ Cancel ]     Confirm"});
                    f.render_widget(Paragraph::new(text).wrap(Wrap{trim:false}).scroll((*scroll,0)).block(Block::default().borders(Borders::ALL).title(format!("{title} · ↑↓ scroll · Tab choose · Enter submit · Esc cancel"))),rect);
                },
                Modal::Secret{title,text,scroll,qr}=> {
                    let block = Block::default().borders(Borders::ALL).title(format!("{title} · v QR/text · e export (.png for image) · Esc clear"));
                    if *qr {
                        let rendered = hibiki_lib::qr::terminal(text).unwrap_or_else(|e| e.to_string());
                        let width = rendered.lines().map(|l| l.chars().count()).max().unwrap_or(0);
                        if width + 2 > rect.width as usize || rendered.lines().count() + 2 > rect.height as usize {
                            f.render_widget(Paragraph::new("Terminal too small for this QR code. Enlarge it or press e to export a .png image.").wrap(Wrap{trim:false}).block(block),rect);
                        } else {
                            f.render_widget(Paragraph::new(rendered).style(Style::default().fg(Color::Black).bg(Color::White)).block(block),rect);
                        }
                    } else { f.render_widget(Paragraph::new(safe(text)).wrap(Wrap{trim:false}).scroll((*scroll,0)).block(block),rect); }
                },
                Modal::Result{text,scroll}=>f.render_widget(Paragraph::new(text.as_str()).wrap(Wrap{trim:false}).scroll((*scroll,0)).block(Block::default().borders(Borders::ALL).title("Result · ↑↓ scroll · Esc close")),rect),
                Modal::Help=>f.render_widget(Paragraph::new("1–5: page   Tab: focus   ↑↓ / j k: navigate\nEnter: details   a: actions   i: invite (Channels)   /: filter   r: refresh\nEsc: close/cancel   q / Ctrl-C: quit\n\nManagement uses a separate relay connection.\nOffline data is marked cached; online changes are disabled.\nService settings require a daemon restart; the TUI never restarts it.\nSecrets are not saved unless you explicitly export them.\nApproval always requires full identity comparison.\n\nPress Esc to close.").wrap(Wrap{trim:false}).block(Block::default().borders(Borders::ALL).title("Help")),rect),
            }
        }
    }
}

fn pane(title: impl Into<String>, focused: bool) -> Block<'static> {
    let title = title.into();
    let title = if focused { format!("{title} *") } else { title };
    Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_type(if focused {
            BorderType::Double
        } else {
            BorderType::Plain
        })
        .border_style(if focused {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        })
}

async fn execute_action(
    manager: &mut Manager,
    action: Action,
) -> Result<(String, Option<Zeroizing<String>>)> {
    match action {
        Action::Ping(channel, peer) => {
            let report = crate::diagnostics::ping(&manager.app, channel, peer, 4).await?;
            Ok((crate::diagnostics::ping_text(&report), None))
        }
        Action::Rename(name) => {
            manager.rename(name).await?;
            Ok(("Device renamed. Keys and verification words unchanged; restart daemon to refresh its local name.".into(), None))
        }
        Action::Select(channel) => {
            manager.select(&channel)?;
            Ok((
                "Default channel updated for new adapter sessions.".into(),
                None,
            ))
        }
        Action::Approve(c, r) => {
            manager.approve(&c, &r).await?;
            Ok(("Request approved.".into(), None))
        }
        Action::Reject(c, r) => {
            manager.reject(&c, &r).await?;
            Ok(("Request rejected.".into(), None))
        }
        Action::Revoke(c, d, subtree, revision) => {
            manager.revoke(&c, &d, subtree, revision).await?;
            Ok(("Device membership revoked.".into(), None))
        }
        Action::Leave(c) => {
            manager.leave(&c).await?;
            Ok(("Left channel / withdrew own requests.".into(), None))
        }
        Action::Invite(c) => Ok((
            "One-use invitation · expires in 24 hours".into(),
            Some(manager.invitation(&c).await?),
        )),
        Action::Join(text) => {
            let result = manager.join(text.to_string()).await?;
            Ok((
                format!(
                    "{}: {}",
                    if result.request.is_some() {
                        "Waiting for approval · show this verification code"
                    } else {
                        "Joined"
                    },
                    safe(&result.name)
                ),
                (!result.verification.is_empty()).then(|| Zeroizing::new(result.verification)),
            ))
        }
        Action::Create(name) => Ok((
            "Channel created · one-use invitation · expires in 24 hours".into(),
            Some(manager.create(name).await?),
        )),
        _ => bail!("unsupported online action"),
    }
}
fn export_secret(text: &str, path: &std::path::Path, overwrite: bool) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if overwrite {
        crate::storage::atomic_write(
            path,
            &if path.extension().is_some_and(|e| e == "png") {
                hibiki_lib::qr::png(text)?
            } else {
                text.as_bytes().to_vec()
            },
        )?;
    } else {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(&if path.extension().is_some_and(|e| e == "png") {
            hibiki_lib::qr::png(text)?
        } else {
            text.as_bytes().to_vec()
        })?;
        file.sync_all()?;
    }
    Ok(())
}
async fn worker(
    mut app: Option<App>,
    mut commands: mpsc::Receiver<Action>,
    updates: mpsc::Sender<Update>,
) {
    let mut manager: Option<Manager> = None;
    let mut received_snapshot = false;
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let action = tokio::select! { _=interval.tick()=>Action::Refresh, action=commands.recv()=>{let Some(a)=action else{break;};a} };
        let result = match action {
            Action::Refresh => Ok(None),
            Action::Select(channel) => match &app {
                Some(current) => management::select_channel(current, &channel).map(|new| {
                    app = Some(new);
                    Some((
                        "Default channel updated for new adapter sessions.".into(),
                        None,
                    ))
                }),
                None => Err(anyhow::anyhow!("initialize this device first")),
            },
            Action::Init {
                server,
                name,
                insecure,
            } => match App::initialize(server, name, insecure) {
                Ok(new) => {
                    app = Some(new);
                    Ok(Some(("Device initialized.".into(), None)))
                }
                Err(e) => Err(e),
            },
            Action::Settings(expected, source, edited) => match &app {
                Some(current) => {
                    match management::save_settings(current, &expected, &source, &edited).await {
                        Ok(new) => {
                            app = Some(new);
                            manager = None;
                            Ok(Some((
                                "Settings saved. Restart daemon to apply service changes.".into(),
                                None,
                            )))
                        }
                        Err(e) => Err(e),
                    }
                }
                None => Err(anyhow::anyhow!("initialize this device first")),
            },
            Action::Export(text, path, overwrite) => export_secret(&text, &path, overwrite)
                .map(|_| Some(("Secret exported with permissions 0600.".into(), None))),
            action => {
                if let Some(m) = manager.as_mut() {
                    match tokio::time::timeout(Duration::from_secs(30), execute_action(m, action))
                        .await
                    {
                        Ok(result) => result.map(Some),
                        Err(_) => Err(anyhow::anyhow!(
                            "management action timed out; refresh before retrying"
                        )),
                    }
                } else {
                    Err(anyhow::anyhow!(
                        "relay offline; reconnect before changing membership"
                    ))
                }
            }
        };
        match result {
            Ok(Some((message, secret))) => {
                let _ = updates.send(Update::Done(message, secret)).await;
            }
            Err(error) => {
                let _ = updates.send(Update::Error(format!("{error:#}"))).await;
            }
            _ => {}
        }
        let Some(current) = &app else {
            continue;
        };
        match App::load(Some(&current.config_file)) {
            Ok(latest) => app = Some(latest),
            Err(error) => {
                let _ = updates
                    .send(Update::Error(format!(
                        "Could not reload configuration: {error:#}"
                    )))
                    .await;
                continue;
            }
        }
        let current = app.as_ref().unwrap();
        if manager
            .as_ref()
            .is_some_and(|m| m.connection.closed.is_cancelled())
        {
            manager = None;
        }
        if manager.is_none() {
            match tokio::time::timeout(Duration::from_secs(5), Manager::connect(current.clone()))
                .await
            {
                Ok(Ok(value)) => manager = Some(value),
                _ => {
                    if !received_snapshot
                        && let Ok(snapshot) = management::local_snapshot(current).await
                    {
                        let _ = updates.send(Update::Snapshot(Box::new(snapshot))).await;
                    }
                    let _ = updates
                        .send(Update::Offline(
                            "Relay offline; showing cached data. Retrying…".into(),
                        ))
                        .await;
                    continue;
                }
            }
        }
        let m = manager.as_mut().unwrap();
        m.app = current.clone();
        match tokio::time::timeout(Duration::from_secs(10), m.snapshot()).await {
            Ok(Ok(snapshot)) => {
                received_snapshot = true;
                let _ = updates.send(Update::Snapshot(Box::new(snapshot))).await;
            }
            _ => {
                manager = None;
                let _ = updates
                    .send(Update::Offline(
                        "Refresh failed; cached data may be out of date. Reconnecting…".into(),
                    ))
                    .await;
            }
        }
    }
}

pub async fn run(explicit: Option<PathBuf>) -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!(
            "hibiki tui requires an interactive terminal; use CLI commands with --json for automation"
        );
    }
    let explicit = explicit.or_else(|| std::env::var_os("HIBIKI_CONFIG").map(PathBuf::from));
    let paths = hibiki_lib::paths::AppPaths::discover()?;
    let app = match App::load(explicit.as_deref()) {
        Ok(app) => Some(app),
        Err(_)
            if explicit.is_none()
                && !paths
                    .config_candidates(None, "client.toml")
                    .iter()
                    .any(|p| p.exists())
                && !paths.data.join("identity.bin").exists() =>
        {
            None
        }
        Err(error) => {
            return Err(
                error.context("could not load configuration; existing files were not changed")
            );
        }
    };
    let _guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
    let (tx, rx) = mpsc::channel(1);
    let (updates, mut output) = mpsc::channel(8);
    let mut ui = Ui::default();
    if app.is_none() {
        ui.form(FormKind::Init);
    }
    let job = tokio::spawn(worker(app, rx, updates));
    let mut events = EventStream::new();
    let result=async {
        loop {
            terminal.draw(|frame|ui.draw(frame))?;
            tokio::select! {
                _=tokio::signal::ctrl_c()=>break,
                update=output.recv()=>match update {
                    Some(Update::Snapshot(snapshot))=>ui.apply_snapshot(*snapshot),
                    Some(Update::Done(message,secret))=>{ui.busy=false;ui.message=message.clone();if let Some(text)=secret{ui.modal=Some(Modal::Secret{title:message,text,scroll:0,qr:false});}else if message.contains('\n'){ui.modal=Some(Modal::Result{text:message,scroll:0});}},
                    Some(Update::Error(message))=>{ui.busy=false;ui.message=message.clone();ui.modal=Some(Modal::Result{text:message,scroll:0});},
                    Some(Update::Offline(message))=>{ui.message=message;if let Some(s)=&mut ui.snapshot{s.relay_connected=false;}},
                    None=>bail!("management worker stopped"),
                },
                event=events.next()=>match event {
                    Some(Ok(Event::Key(key)))=>if ui.key(key,&tx){break;},
                    Some(Ok(Event::Paste(text)))=>if let Some(Modal::Form{fields,selected,..})=&mut ui.modal && *selected<fields.len() && fields[*selected].value.len()+text.len()<=32768{fields[*selected].value.push_str(text.trim());},
                    Some(Ok(Event::Resize(..)))=>{},
                    Some(Err(error))=>return Err(error.into()),None=>break,_=>{},
                }
            }
        }
        Ok::<_,anyhow::Error>(())
    }.await;
    job.abort();
    let _ = job.await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refresh_never_redirects_an_open_approval_to_another_request() {
        use crate::management::{ChannelRow, DeviceRow, PendingRow};
        let device = DeviceRow {
            id: "a".repeat(64),
            name: "同名设备".into(),
            local: false,
            online: Some(true),
            approved_by: None,
            approver_name: None,
            can_revoke: false,
            revoked_by_server: false,
            reverse_revoke_available_at: None,
            revocation_subtree: vec![],
            verification_words: (0..24)
                .map(|i| format!("word{i}"))
                .collect::<Vec<_>>()
                .join(" "),
        };
        let snapshot = |id: &str| Snapshot {
            schema_version: 1,
            captured_at: 1,
            relay_connected: true,
            local_device: device.clone(),
            channels: vec![ChannelRow {
                id: "channel".into(),
                name: "test".into(),
                selected: true,
                member: true,
                revision: 1,
                available: true,
                devices: vec![device.clone()],
                pending: vec![PendingRow {
                    id: id.into(),
                    verification: "hibiki-verify-v1:fixture".into(),
                    channel: "channel".into(),
                    channel_name: "test".into(),
                    device: device.clone(),
                    created_at: 1,
                    own: false,
                }],
                error: None,
            }],
            config: Config::default(),
            config_source: vec![],
            running_config: None,
            daemon_running: false,
            daemon_relay_connected: false,
            allow_channel_creation: false,
        };
        let mut ui = Ui {
            page: 3,
            ..Default::default()
        };
        ui.apply_snapshot(snapshot("old-request"));
        ui.modal = Some(Modal::Confirm {
            title: "Approve".into(),
            details: device.verification_words.clone(),
            action: Action::Approve("channel".into(), "old-request".into()),
            affirmative: true,
            verified: true,
            approval: true,
            scroll: 0,
        });
        ui.apply_snapshot(snapshot("replacement-request"));
        assert!(ui.modal.is_none());
        assert!(ui.message.contains("handled elsewhere"));
        let mut before = snapshot("request");
        before.channels[0].devices[0].can_revoke = true;
        ui.apply_snapshot(before.clone());
        ui.modal = Some(Modal::Confirm {
            title: "Revoke subtree".into(),
            details: String::new(),
            action: Action::Revoke("channel".into(), device.id.clone(), true, 1),
            affirmative: false,
            verified: false,
            approval: false,
            scroll: 0,
        });
        before.channels[0].revision = 2;
        ui.apply_snapshot(before);
        assert!(ui.modal.is_none());
        assert!(ui.message.contains("Confirmation canceled"));
        // The replacement can be selected, but never inherits approval consent.
        let backend = ratatui::backend::TestBackend::new(38, 15);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| ui.draw(frame)).unwrap();
    }
    #[test]
    fn settings_form_preserves_unowned_fields_and_validates_booleans() {
        let mut ui = Ui::default();
        let config = Config {
            server: "wss://relay.example/hibiki".into(),
            ..Config::default()
        };
        ui.form(FormKind::Settings(Box::new(config.clone()), vec![]));
        let Some(Modal::Form { fields, kind, .. }) = &mut ui.modal else {
            panic!()
        };
        fields[0].value = Zeroizing::new("true".into());
        let Action::Settings(_, _, edited) = Ui::form_action(kind, fields).unwrap() else {
            panic!()
        };
        assert!(edited.scdaemon.enabled);
        assert_eq!(edited.server, config.server);
        fields[0].value = Zeroizing::new("yes".into());
        assert!(Ui::form_action(kind, fields).is_err());
    }
    #[test]
    fn export_is_private_and_never_silently_overwrites() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invite");
        export_secret("secret", &path, false).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(export_secret("replacement", &path, false).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "secret");
    }
    #[tokio::test]
    async fn approval_defaults_to_cancel_and_requires_verification() {
        let (tx, mut rx) = mpsc::channel(4);
        let mut ui = Ui::default();
        let confirm = || Modal::Confirm {
            title: "Approve".into(),
            details: String::new(),
            action: Action::Approve("channel".into(), "request".into()),
            affirmative: false,
            verified: false,
            approval: true,
            scroll: 0,
        };
        ui.modal = Some(confirm());
        ui.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), &tx);
        assert!(rx.try_recv().is_err());
        ui.modal = Some(confirm());
        ui.key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE), &tx);
        ui.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), &tx);
        assert!(rx.try_recv().is_err());
        ui.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE), &tx);
        ui.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), &tx);
        assert!(matches!(rx.try_recv(), Ok(Action::Approve(..))));
    }
}
