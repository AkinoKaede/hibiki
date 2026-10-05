/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

use anyhow::{Result, bail};
use hibiki_lib::assuan::{self, AssuanResult, Line};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

pub async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Option<Line>> {
    let mut line = Line(Vec::with_capacity(assuan::MAX_LINE));
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            bail!("unterminated Assuan line");
        }
        let length = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |n| n + 1);
        if line.len() + length > assuan::MAX_LINE {
            bail!("Assuan line exceeds limit");
        }
        let ended = available[length - 1] == b'\n';
        line.0.extend_from_slice(&available[..length]);
        reader.consume(length);
        if ended {
            line.0.pop();
            if line.last() == Some(&b'\r') {
                line.0.pop();
            }
            assuan::framing(&line)?;
            return Ok(Some(line));
        }
    }
}
pub async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, line: &[u8]) -> Result<()> {
    assuan::framing(line)?;
    writer.write_all(line).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}
pub async fn write_result<W: AsyncWrite + Unpin>(
    writer: &mut W,
    result: &AssuanResult,
) -> Result<()> {
    result.validate()?;
    for line in &result.lines {
        write_line(writer, line).await?;
    }
    Ok(())
}

/// Buffered reader that wipes consumed plaintext and its allocation on drop.
/// Unlike a standard BufReader, it does not retain a PIN after consume().
pub struct SecretReader<R> {
    inner: R,
    buffer: zeroize::Zeroizing<Vec<u8>>,
    position: usize,
    filled: usize,
}
impl<R> SecretReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buffer: zeroize::Zeroizing::new(vec![0; 8192]),
            position: 0,
            filled: 0,
        }
    }
}
impl<R: tokio::io::AsyncRead + Unpin> AsyncBufRead for SecretReader<R> {
    fn poll_fill_buf(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<&[u8]>> {
        let this = self.get_mut();
        if this.position == this.filled {
            let mut target = tokio::io::ReadBuf::new(&mut this.buffer);
            std::task::ready!(std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut target))?;
            this.filled = target.filled().len();
            this.position = 0;
        }
        std::task::Poll::Ready(Ok(&this.buffer[this.position..this.filled]))
    }
    fn consume(self: std::pin::Pin<&mut Self>, amount: usize) {
        use zeroize::Zeroize;
        let this = self.get_mut();
        let end = (this.position + amount).min(this.filled);
        this.buffer[this.position..end].zeroize();
        this.position = end;
    }
}
impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for SecretReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let bytes = std::task::ready!(self.as_mut().poll_fill_buf(cx))?;
        let n = bytes.len().min(buf.remaining());
        buf.put_slice(&bytes[..n]);
        self.consume(n);
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    #[tokio::test]
    async fn fragmented_lines_and_limits() {
        let (mut tx, rx) = tokio::io::duplex(32);
        tokio::spawn(async move {
            for part in [b"D %".as_slice(), b"00", b"\xff%25\r", b"\nOK\n"] {
                tx.write_all(part).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let mut reader = SecretReader::new(rx);
        assert_eq!(
            &*read_line(&mut reader).await.unwrap().unwrap(),
            b"D %00\xff%25"
        );
        assert_eq!(&*read_line(&mut reader).await.unwrap().unwrap(), b"OK");
        assert!(read_line(&mut reader).await.unwrap().is_none());
        assert!(read_line(&mut SecretReader::new(&b"OK"[..])).await.is_err());
        assert!(
            read_line(&mut SecretReader::new(
                vec![b'x'; assuan::MAX_LINE + 1].as_slice()
            ))
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn consumed_secrets_are_wiped_without_losing_buffered_lines() {
        let mut reader = SecretReader::new(&b"D private%25value\nOK\n"[..]);
        let line = read_line(&mut reader).await.unwrap().unwrap();
        assert_eq!(&*line, b"D private%25value");
        assert!(reader.buffer[..reader.position].iter().all(|b| *b == 0));
        assert_eq!(&*read_line(&mut reader).await.unwrap().unwrap(), b"OK");
        assert!(reader.buffer.iter().all(|b| *b == 0));
    }
}
