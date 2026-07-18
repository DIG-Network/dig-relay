//! Minimal HTTP/1.1 request peeking + response writing for the relay's `:443`-facing listener.
//!
//! The relay accepts every connection on one TCP port (TLS terminated upstream at the load balancer),
//! and that port must carry TWO surfaces:
//!
//! - the **RelayMessage WebSocket wire** (a WS `Upgrade` request — the peer protocol), and
//! - the **peer-stats dashboard** (an ordinary `GET /` / `GET /stats.json` / `GET /mascot.png`).
//!
//! A WebSocket handshake IS an HTTP request, so we read the request head first, decide which surface
//! it is, and — for the wire — hand the request bytes back to the WebSocket handshake via [`Prefixed`]
//! so the tungstenite handshake re-reads them unchanged. This keeps the wire path byte-for-byte the
//! same for peers while letting a browser reach the dashboard on the same port.
//!
//! This is a deliberately tiny HTTP surface (request line + headers, no body — the dashboard is
//! read-only GETs and a WS handshake carries no body); it is NOT a general HTTP server.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// The largest request head we will buffer before giving up (a valid WS handshake or dashboard GET is
/// well under this; the cap stops a client dribbling headers forever to grow our buffer).
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// The parsed essentials of an HTTP/1.1 request head — only the fields the relay routes on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    /// The request method, uppercased (`GET`, `POST`, …).
    pub method: String,
    /// The request target as sent — path plus optional `?query` (e.g. `/stats.json?full=1`).
    pub target: String,
    /// The `Host` header value, if present (used to build an absolute redirect `Location`).
    pub host: Option<String>,
    /// Whether this is a WebSocket upgrade (`Connection: Upgrade` + `Upgrade: websocket`) — i.e. a
    /// relay-wire client rather than a browser hitting the dashboard.
    pub is_websocket_upgrade: bool,
}

impl RequestHead {
    /// The path with any `?query` stripped — what the dashboard router matches on.
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or(&self.target)
    }
}

/// Read and parse the HTTP request head (everything up to and including the terminating blank line).
///
/// Returns the parsed [`RequestHead`] plus the exact bytes consumed, so a WebSocket upgrade can be
/// replayed to the handshake via [`Prefixed`]. Errors if no complete head arrives within
/// [`MAX_HEAD_BYTES`] or the stream ends first — the caller drops such a connection.
pub async fn read_request_head<S>(stream: &mut S) -> std::io::Result<(RequestHead, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before a complete HTTP request head",
            ));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() >= MAX_HEAD_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP request head exceeded the size cap",
            ));
        }
    }
    let head = parse_request_head(&buf)?;
    Ok((head, buf))
}

/// Parse the raw request-head bytes into a [`RequestHead`]. Pure (no I/O) so it is fully unit-tested.
pub fn parse_request_head(bytes: &[u8]) -> std::io::Result<RequestHead> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "non-UTF-8 request head")
    })?;
    let mut lines = text.split("\r\n");

    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let method = parts
        .next()
        .filter(|m| !m.is_empty())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing method"))?
        .to_ascii_uppercase();
    let target = parts
        .next()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing request target")
        })?
        .to_string();

    let mut host = None;
    let mut connection_upgrade = false;
    let mut upgrade_websocket = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("host") {
            host = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("connection") {
            // May be a comma list, e.g. "keep-alive, Upgrade".
            connection_upgrade = value
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
        } else if name.eq_ignore_ascii_case("upgrade") {
            upgrade_websocket = value.eq_ignore_ascii_case("websocket");
        }
    }

    Ok(RequestHead {
        method,
        target,
        host,
        is_websocket_upgrade: connection_upgrade && upgrade_websocket,
    })
}

/// Write a complete, no-keep-alive HTTP/1.1 response (status line, the given headers, `Content-Length`,
/// `Connection: close`, then the body) and flush. The relay serves one response per connection.
pub async fn write_response<S>(
    stream: &mut S,
    status: u16,
    reason: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut head = format!("HTTP/1.1 {status} {reason}\r\n");
    for (name, value) in headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    head.push_str("Connection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

/// A stream that first replays a buffered `prefix` (the already-read request head) and then delegates
/// to the underlying stream — so the WebSocket handshake can re-read the exact request bytes we peeked.
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    /// Wrap `inner`, replaying `prefix` before any bytes from `inner`.
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let remaining = &self.prefix[self.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn parses_a_plain_get_with_host_and_query() {
        let raw = b"GET /stats.json?full=1 HTTP/1.1\r\nHost: relay.dig.net\r\nAccept: */*\r\n\r\n";
        let head = parse_request_head(raw).unwrap();
        assert_eq!(head.method, "GET");
        assert_eq!(head.target, "/stats.json?full=1");
        assert_eq!(head.path(), "/stats.json");
        assert_eq!(head.host.as_deref(), Some("relay.dig.net"));
        assert!(!head.is_websocket_upgrade);
    }

    #[test]
    fn detects_a_websocket_upgrade_case_insensitively() {
        let raw = b"GET / HTTP/1.1\r\nHost: relay.dig.net\r\nConnection: keep-alive, Upgrade\r\nUpgrade: WebSocket\r\nSec-WebSocket-Key: x\r\n\r\n";
        let head = parse_request_head(raw).unwrap();
        assert!(
            head.is_websocket_upgrade,
            "Connection: Upgrade + Upgrade: websocket = a wire client"
        );
    }

    #[test]
    fn a_get_without_upgrade_is_not_a_websocket() {
        let raw = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
        assert!(!parse_request_head(raw).unwrap().is_websocket_upgrade);
    }

    #[test]
    fn rejects_a_malformed_request_line() {
        assert!(parse_request_head(b"\r\n\r\n").is_err());
    }

    #[tokio::test]
    async fn reads_the_head_and_returns_the_consumed_bytes() {
        let raw = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
        let mut stream = std::io::Cursor::new(raw.to_vec());
        let (head, consumed) = read_request_head(&mut stream).await.unwrap();
        assert_eq!(head.method, "GET");
        assert_eq!(consumed, raw, "consumed bytes are exactly the request head");
    }

    #[tokio::test]
    async fn prefixed_replays_the_head_then_the_rest() {
        // Prefixed must yield the buffered head first, then whatever the inner stream holds — so the
        // WebSocket handshake sees the original byte stream unchanged.
        let prefix = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        let rest = b"FRAME-BYTES".to_vec();
        let inner = std::io::Cursor::new(rest.clone());
        let mut s = Prefixed::new(prefix.clone(), inner);
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        let mut expected = prefix;
        expected.extend_from_slice(&rest);
        assert_eq!(out, expected);
    }
}
