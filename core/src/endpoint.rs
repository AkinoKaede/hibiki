//! A session handle. Dropping any handle cancels its actor and owned child process.
use anyhow::{Context, Result, bail};
use hibiki_lib::{
    assuan::{self, Line, Response},
    protocol::{SessionInput, SessionOutput},
};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub struct Endpoint {
    pub peer: String,
    pub card_serial: Option<String>,
    pub operation: Arc<Mutex<Option<String>>>,
    pub tx: mpsc::Sender<SessionInput>,
    pub rx: mpsc::Receiver<SessionOutput>,
    pub stop: CancellationToken,
    pub done: CancellationToken,
    request: u64,
    inquiry: bool,
    active: bool,
    bytes: usize,
    lines: usize,
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
impl Endpoint {
    pub fn new(
        tx: mpsc::Sender<SessionInput>,
        rx: mpsc::Receiver<SessionOutput>,
        stop: CancellationToken,
        done: CancellationToken,
    ) -> Self {
        Self {
            peer: String::new(),
            card_serial: None,
            operation: Arc::new(Mutex::new(None)),
            tx,
            rx,
            stop,
            done,
            request: 0,
            inquiry: false,
            active: false,
            bytes: 0,
            lines: 0,
        }
    }
    pub fn bind_operation(&self, id: Option<String>) {
        *self.operation.lock().unwrap() = id;
    }
    pub async fn command(&mut self, line: Line) -> Result<()> {
        if self.active {
            bail!("command already active");
        }
        self.request = self
            .request
            .checked_add(1)
            .context("request counter overflow")?;
        self.active = true;
        self.inquiry = false;
        self.bytes = 0;
        self.lines = 0;
        self.tx
            .send(SessionInput::Command {
                request: self.request,
                line,
            })
            .await?;
        Ok(())
    }
    pub async fn next(&mut self) -> Result<Line> {
        let Some(SessionOutput::Line { request, line }) = self.rx.recv().await else {
            bail!("service session ended");
        };
        if request != self.request || !self.active || self.inquiry {
            bail!("unexpected response or request ID");
        }
        self.bytes += line.len();
        self.lines += 1;
        if self.bytes > assuan::MAX_DATA || self.lines > assuan::MAX_LINES {
            bail!("service response limit");
        }
        match assuan::parse_response(&line)? {
            Response::Inquire(_) => self.inquiry = true,
            Response::Ok | Response::Err(_) => self.active = false,
            Response::Data(d) => {
                assuan::unescape(d)?;
            }
            _ => {}
        }
        Ok(line)
    }
    pub async fn answer(&mut self, line: Line) -> Result<()> {
        if !self.active || !self.inquiry {
            bail!("no pending inquiry");
        }
        assuan::framing(&line)?;
        if &*line == b"END" || &*line == b"CAN" {
            self.inquiry = false;
        } else if let Ok(Response::Data(d)) = assuan::parse_response(&line) {
            assuan::unescape(d)?;
        } else {
            bail!("invalid inquiry reply");
        }
        self.tx
            .send(SessionInput::InquiryReply {
                request: self.request,
                line,
            })
            .await?;
        Ok(())
    }
    pub async fn close(self) {
        self.stop.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(3), self.done.cancelled()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn request_ids_and_inquiry_state_are_enforced() {
        let (tx, mut input) = mpsc::channel(8);
        let (out, rx) = mpsc::channel(8);
        let mut ep = Endpoint::new(tx, rx, CancellationToken::new(), CancellationToken::new());
        assert!(ep.answer("END".into()).await.is_err());
        ep.command("GETPIN".into()).await.unwrap();
        assert!(ep.command("NOP".into()).await.is_err());
        assert!(matches!(
            input.recv().await,
            Some(SessionInput::Command { request: 1, .. })
        ));
        out.send(SessionOutput::Line {
            request: 1,
            line: "INQUIRE QUALITY abc".into(),
        })
        .await
        .unwrap();
        ep.next().await.unwrap();
        assert!(ep.answer("OK".into()).await.is_err());
        ep.answer("D 100".into()).await.unwrap();
        ep.answer("END".into()).await.unwrap();
        out.send(SessionOutput::Line {
            request: 2,
            line: "OK".into(),
        })
        .await
        .unwrap();
        assert!(ep.next().await.is_err());
    }
}
