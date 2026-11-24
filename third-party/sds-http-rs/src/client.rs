use crate::server::{wait_shutdown, ErrorKind};
use crate::tls::build_client_config;
use rustls::pki_types::ServerName;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{watch, Mutex};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

#[derive(Clone)]
pub struct ClientSettings {
    pub host: String,
    pub port: u16,
    pub default_port: u16,
    pub is_https: bool,
    pub verify_certificate: bool,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub verify_file: Option<String>,
}

pub struct ClientResponseData {
    pub http_version: String,
    pub status_code: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

enum ClientStream {
    Plain {
        stream: TcpStream,
        buf: Vec<u8>,
    },
    Tls {
        stream: Box<TlsStream<TcpStream>>,
        buf: Vec<u8>,
    },
}

impl ClientStream {
    async fn read_chunk(&mut self, tmp: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain { stream, .. } => stream.read(tmp).await,
            Self::Tls { stream, .. } => stream.read(tmp).await,
        }
    }

    async fn write_all_and_flush(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Self::Plain { stream, .. } => {
                stream.write_all(data).await?;
                stream.flush().await
            }
            Self::Tls { stream, .. } => {
                stream.write_all(data).await?;
                stream.flush().await
            }
        }
    }

    fn take_buf(&mut self) -> &mut Vec<u8> {
        match self {
            Self::Plain { buf, .. } | Self::Tls { buf, .. } => buf,
        }
    }
}

pub struct HttpClientInstance {
    rt: tokio::runtime::Runtime,
    settings: ClientSettings,
    tls_connector: Option<TlsConnector>,
    pool: Arc<Mutex<Vec<ClientStream>>>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl HttpClientInstance {
    pub fn create(mut settings: ClientSettings) -> Result<Self, String> {
        if settings.default_port == 0 {
            settings.default_port = if settings.is_https { 443 } else { 80 };
        }
        if settings.port == 0 {
            settings.port = settings.default_port;
        }
        let tls_connector = if settings.is_https {
            let cfg = build_client_config(
                settings.verify_certificate,
                settings.cert_file.as_deref().map(Path::new),
                settings.key_file.as_deref().map(Path::new),
                settings.verify_file.as_deref().map(Path::new),
            )?;
            Some(TlsConnector::from(cfg))
        } else {
            None
        };

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("sds-http-cli")
            .enable_all()
            .build()
            .map_err(|e| format!("failed to build client tokio runtime: {e}"))?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        Ok(Self {
            rt,
            settings,
            tls_connector,
            pool: Arc::new(Mutex::new(Vec::new())),
            shutdown_tx,
            shutdown_rx,
        })
    }

    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
        let pool = self.pool.clone();
        self.rt.block_on(async move {
            pool.lock().await.clear();
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
        timeout_secs: i64,
        timeout_connect_secs: i64,
        max_response_bytes: usize,
    ) -> Result<ClientResponseData, (ErrorKind, String)> {
        let settings = self.settings.clone();
        let connector = self.tls_connector.clone();
        let pool = self.pool.clone();
        let mut shutdown_rx = self.shutdown_rx.clone();
        let method = method.to_string();
        let path = if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        };
        let headers = headers.to_vec();
        let body = body.to_vec();

        self.rt.block_on(async move {
            if *shutdown_rx.borrow() {
                return Err((ErrorKind::OperationAborted, "client stopped".into()));
            }

            let req_wire = build_request_wire(&settings, &method, &path, &headers, &body)?;
            let req_close = headers.iter().any(|(k, v)| {
                k.eq_ignore_ascii_case("connection")
                    && v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close"))
            });
            let is_head = method.eq_ignore_ascii_case("HEAD");

            let req_timeout = if timeout_secs > 0 {
                Some(Duration::from_secs(timeout_secs as u64))
            } else {
                None
            };
            let connect_timeout = if timeout_connect_secs > 0 {
                Some(Duration::from_secs(timeout_connect_secs as u64))
            } else {
                req_timeout
            };

            let idle_conn = pool.lock().await.pop();
            let mut attempt_reconnect = idle_conn.is_some();
            let mut conn = match idle_conn {
                Some(c) => c,
                None => {
                    tokio::select! {
                        biased;
                        _ = wait_shutdown(&mut shutdown_rx) => return Err((ErrorKind::OperationAborted, "client stopped".into())),
                        res = connect_stream(&settings, connector.as_ref(), connect_timeout) => res?,
                    }
                }
            };

            loop {
                let op = async {
                    conn.write_all_and_flush(&req_wire).await.map_err(|e| {
                        (
                            classify_client_io(&e),
                            format!("client write failed: {e}"),
                            is_retryable_io(&e),
                        )
                    })?;
                    read_client_response(&mut conn, max_response_bytes, is_head, settings.is_https).await
                };

                let res = tokio::select! {
                    biased;
                    _ = wait_shutdown(&mut shutdown_rx) => return Err((ErrorKind::OperationAborted, "client stopped".into())),
                    r = run_opt_timeout(req_timeout, op) => match r {
                        Ok(inner) => inner,
                        Err(()) => return Err((ErrorKind::TimedOut, "request timed out".into())),
                    }
                };

                match res {
                    Ok((resp, keep_alive)) => {
                        if keep_alive && !req_close && !*shutdown_rx.borrow() {
                            let mut guard = pool.lock().await;
                            if guard.is_empty() {
                                guard.push(conn);
                            }
                        }
                        return Ok(resp);
                    }
                    Err((kind, msg, retryable)) => {
                        if attempt_reconnect && retryable && !*shutdown_rx.borrow() {
                            attempt_reconnect = false;
                            conn = tokio::select! {
                                biased;
                                _ = wait_shutdown(&mut shutdown_rx) => return Err((ErrorKind::OperationAborted, "client stopped".into())),
                                res = connect_stream(&settings, connector.as_ref(), connect_timeout) => res?,
                            };
                            continue;
                        }
                        return Err((kind, msg));
                    }
                }
            }
        })
    }
}

async fn run_opt_timeout<F, T>(dur: Option<Duration>, fut: F) -> Result<T, ()>
where
    F: std::future::Future<Output = T>,
{
    match dur {
        Some(d) => tokio::time::timeout(d, fut).await.map_err(|_| ()),
        None => Ok(fut.await),
    }
}

async fn run_opt_deadline<F, T>(deadline: Option<tokio::time::Instant>, fut: F) -> Result<T, ()>
where
    F: std::future::Future<Output = T>,
{
    match deadline {
        Some(dl) => tokio::time::timeout_at(dl, fut).await.map_err(|_| ()),
        None => Ok(fut.await),
    }
}

async fn connect_stream(
    settings: &ClientSettings,
    connector: Option<&TlsConnector>,
    timeout: Option<Duration>,
) -> Result<ClientStream, (ErrorKind, String)> {
    let deadline = timeout.map(|d| tokio::time::Instant::now() + d);
    let tcp_fut = TcpStream::connect((settings.host.as_str(), settings.port));
    let tcp = match run_opt_deadline(deadline, tcp_fut).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err((ErrorKind::Io, format!("connect failed: {e}"))),
        Err(()) => return Err((ErrorKind::TimedOut, "connect timed out".into())),
    };
    let _ = tcp.set_nodelay(true);

    if let Some(conn) = connector {
        let server_name = ServerName::try_from(settings.host.clone()).map_err(|_| {
            (
                ErrorKind::Tls,
                format!("invalid TLS server name '{}'", settings.host),
            )
        })?;
        let tls = match run_opt_deadline(deadline, conn.connect(server_name, tcp)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err((ErrorKind::Tls, format!("TLS handshake failed: {e}"))),
            Err(()) => return Err((ErrorKind::TimedOut, "TLS handshake timed out".into())),
        };
        Ok(ClientStream::Tls {
            stream: Box::new(tls),
            buf: Vec::with_capacity(4096),
        })
    } else {
        Ok(ClientStream::Plain {
            stream: tcp,
            buf: Vec::with_capacity(4096),
        })
    }
}

fn build_request_wire(
    settings: &ClientSettings,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<Vec<u8>, (ErrorKind, String)> {
    if settings.host.is_empty() || settings.host.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err((ErrorKind::Protocol, "invalid client request host".into()));
    }
    if method.is_empty() || !method.bytes().all(crate::http::is_tchar) {
        return Err((ErrorKind::Protocol, "invalid client HTTP method".into()));
    }
    if path.is_empty() || path.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err((ErrorKind::Protocol, "invalid client request path".into()));
    }
    for (k, v) in headers {
        if k.is_empty() || !k.bytes().all(crate::http::is_tchar) {
            return Err((
                ErrorKind::Protocol,
                "invalid client request header name".into(),
            ));
        }
        if !v.bytes().all(|b| b == b'\t' || (0x20..=0x7e).contains(&b)) {
            return Err((
                ErrorKind::Protocol,
                "invalid client request header value".into(),
            ));
        }
    }

    let mut out = Vec::with_capacity(256 + body.len());
    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");

    let has_host = headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("host"));
    if !has_host {
        out.extend_from_slice(b"Host: ");
        if let Ok(ip) = settings.host.parse::<IpAddr>() {
            match ip {
                IpAddr::V6(_) => {
                    out.push(b'[');
                    out.extend_from_slice(settings.host.as_bytes());
                    out.push(b']');
                }
                IpAddr::V4(_) => out.extend_from_slice(settings.host.as_bytes()),
            }
        } else {
            out.extend_from_slice(settings.host.as_bytes());
        }
        if settings.port != settings.default_port {
            out.push(b':');
            out.extend_from_slice(settings.port.to_string().as_bytes());
        }
        out.extend_from_slice(b"\r\n");
    }

    for (k, v) in headers {
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    if !body.is_empty() {
        let has_len = headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
        let is_chunked = headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("transfer-encoding")
                && v.split(',').any(|t| t.trim().eq_ignore_ascii_case("chunked"))
        });
        if !has_len && !is_chunked {
            out.extend_from_slice(b"Content-Length: ");
            out.extend_from_slice(body.len().to_string().as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }

    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    Ok(out)
}

async fn read_client_response(
    conn: &mut ClientStream,
    max_response_bytes: usize,
    is_head: bool,
    is_https: bool,
) -> Result<(ClientResponseData, bool), (ErrorKind, String, bool)> {
    let mut tmp = [0u8; 8192];

    let head_end = loop {
        let buf = conn.take_buf();
        if let Some(pos) = find_response_head_end(buf) {
            break pos;
        }
        if buf.len() > 256 * 1024 {
            return Err((
                ErrorKind::MessageSize,
                "response header exceeds limit".into(),
                false,
            ));
        }
        let buf_empty = buf.is_empty();
        let n = conn.read_chunk(&mut tmp).await.map_err(|e| {
            (
                classify_client_io(&e),
                format!("client read failed: {e}"),
                buf_empty && is_retryable_io(&e),
            )
        })?;
        if n == 0 {
            return Err((
                ErrorKind::Eof,
                "eof reading response header".into(),
                buf_empty,
            ));
        }
        conn.take_buf().extend_from_slice(&tmp[..n]);
    };

    let raw_head = {
        let buf = conn.take_buf();
        let head = buf[..head_end].to_vec();
        buf.drain(..head_end);
        head
    };

    let crlf_count = raw_head.windows(2).filter(|w| *w == b"\r\n").count();
    let header_lines_count = crlf_count.saturating_sub(2);
    if header_lines_count > 512 {
        return Err((
            ErrorKind::Protocol,
            "too many HTTP response headers".into(),
            false,
        ));
    }

    let mut header_storage = vec![httparse::EMPTY_HEADER; header_lines_count.max(32)];
    let mut resp = httparse::Response::new(&mut header_storage);
    let parsed_len = match resp.parse(&raw_head) {
        Ok(httparse::Status::Complete(len)) => len,
        Err(httparse::Error::TooManyHeaders) => {
            return Err((
                ErrorKind::Protocol,
                "too many HTTP response headers".into(),
                false,
            ))
        }
        _ => {
            return Err((
                ErrorKind::Protocol,
                "malformed HTTP response header".into(),
                false,
            ))
        }
    };
    if parsed_len != raw_head.len() {
        return Err((
            ErrorKind::Protocol,
            "malformed HTTP response header".into(),
            false,
        ));
    }

    let (http_minor, http_version) = match resp.version {
        Some(0) => (0u8, "1.0".to_string()),
        Some(1) => (1u8, "1.1".to_string()),
        _ => {
            return Err((
                ErrorKind::Protocol,
                "unsupported HTTP response version".into(),
                false,
            ))
        }
    };

    let code = resp.code.ok_or_else(|| {
        (
            ErrorKind::Protocol,
            "missing HTTP response status code".to_string(),
            false,
        )
    })?;
    let status_code = extract_status_line_code(&raw_head, code, resp.reason.unwrap_or(""));

    let mut headers = Vec::with_capacity(resp.headers.len());
    for h in resp.headers.iter() {
        let val = String::from_utf8_lossy(h.value).trim().to_string();
        headers.push((h.name.to_string(), val));
    }

    let mut content_length: Option<usize> = None;
    let mut transfer_encodings: Vec<String> = Vec::new();
    let mut server_close = false;
    for (k, v) in &headers {
        if k.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err((
                    ErrorKind::Protocol,
                    "duplicate response Content-Length".into(),
                    false,
                ));
            }
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err((
                    ErrorKind::Protocol,
                    "invalid response Content-Length".into(),
                    false,
                ));
            }
            let len = v.parse::<usize>().map_err(|_| {
                (
                    ErrorKind::Protocol,
                    "invalid response Content-Length".to_string(),
                    false,
                )
            })?;
            content_length = Some(len);
        } else if k.eq_ignore_ascii_case("transfer-encoding") {
            for tok in v.split(',') {
                let trimmed = tok.trim();
                if trimmed.is_empty() {
                    return Err((
                        ErrorKind::Protocol,
                        "empty response Transfer-Encoding".into(),
                        false,
                    ));
                }
                transfer_encodings.push(trimmed.to_ascii_lowercase());
            }
        } else if k.eq_ignore_ascii_case("connection") {
            for tok in v.split(',') {
                if tok.trim().eq_ignore_ascii_case("close") {
                    server_close = true;
                }
            }
        }
    }

    let is_chunked = if transfer_encodings.is_empty() {
        false
    } else {
        if content_length.is_some() {
            return Err((
                ErrorKind::Protocol,
                "response contains both Transfer-Encoding and Content-Length".into(),
                false,
            ));
        }
        if transfer_encodings.as_slice() != ["chunked"] {
            return Err((
                ErrorKind::Protocol,
                "unsupported response Transfer-Encoding".into(),
                false,
            ));
        }
        true
    };

    let mut keep_alive = !server_close && http_minor >= 1;

    let body = if is_head || code == 204 || code == 304 || (100..200).contains(&code) {
        Vec::new()
    } else if is_chunked {
        read_chunked_body(conn, max_response_bytes, &mut tmp).await?
    } else if let Some(len) = content_length {
        if len > max_response_bytes {
            return Err((
                ErrorKind::MessageSize,
                "response body exceeds max_response_streambuf_size".into(),
                false,
            ));
        }
        read_exact_body(conn, len, &mut tmp).await?
    } else {
        keep_alive = false;
        read_until_eof_body(conn, max_response_bytes, is_https, &mut tmp).await?
    };

    Ok((
        ClientResponseData {
            http_version,
            status_code,
            headers,
            body,
        },
        keep_alive,
    ))
}

fn find_response_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|pos| pos + 4)
}

fn extract_status_line_code(raw_head: &[u8], code: u16, reason: &str) -> String {
    if let Some(line_end) = raw_head.iter().position(|&b| b == b'\n') {
        let line = &raw_head[..line_end];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(sp) = line.iter().position(|&b| b == b' ') {
            return String::from_utf8_lossy(&line[sp + 1..]).to_string();
        }
    }
    if reason.is_empty() {
        code.to_string()
    } else {
        format!("{code} {reason}")
    }
}

async fn read_exact_body(
    conn: &mut ClientStream,
    len: usize,
    tmp: &mut [u8],
) -> Result<Vec<u8>, (ErrorKind, String, bool)> {
    let mut out = Vec::with_capacity(len);
    {
        let buf = conn.take_buf();
        let take = buf.len().min(len);
        out.extend_from_slice(&buf[..take]);
        buf.drain(..take);
    }
    while out.len() < len {
        let needed = (len - out.len()).min(tmp.len());
        let n = conn.read_chunk(&mut tmp[..needed]).await.map_err(|e| {
            (
                classify_client_io(&e),
                format!("client body read failed: {e}"),
                false,
            )
        })?;
        if n == 0 {
            return Err((
                ErrorKind::Eof,
                "unexpected EOF reading response body".into(),
                false,
            ));
        }
        out.extend_from_slice(&tmp[..n]);
    }
    Ok(out)
}

async fn read_until_eof_body(
    conn: &mut ClientStream,
    max_bytes: usize,
    is_https: bool,
    tmp: &mut [u8],
) -> Result<Vec<u8>, (ErrorKind, String, bool)> {
    let mut out = std::mem::take(conn.take_buf());
    if out.len() > max_bytes {
        return Err((
            ErrorKind::MessageSize,
            "response body exceeds max_response_streambuf_size".into(),
            false,
        ));
    }
    loop {
        match conn.read_chunk(tmp).await {
            Ok(0) => break,
            Ok(n) => {
                if out.len().saturating_add(n) > max_bytes {
                    return Err((
                        ErrorKind::MessageSize,
                        "response body exceeds max_response_streambuf_size".into(),
                        false,
                    ));
                }
                out.extend_from_slice(&tmp[..n]);
            }
            Err(e) if is_https && e.kind() == io::ErrorKind::UnexpectedEof => {
                // Match Simple-Web-Server HTTPS client clean_error_code for stream_truncated.
                break;
            }
            Err(e) => {
                return Err((
                    classify_client_io(&e),
                    format!("client body EOF read failed: {e}"),
                    false,
                ))
            }
        }
    }
    Ok(out)
}

async fn read_chunked_body(
    conn: &mut ClientStream,
    max_bytes: usize,
    tmp: &mut [u8],
) -> Result<Vec<u8>, (ErrorKind, String, bool)> {
    let mut out = Vec::new();
    loop {
        let line_end = loop {
            let buf = conn.take_buf();
            if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
                break pos;
            }
            if buf.len() > 8192 {
                return Err((ErrorKind::Protocol, "chunk header too long".into(), false));
            }
            let n = conn.read_chunk(tmp).await.map_err(|e| {
                (
                    classify_client_io(&e),
                    format!("client chunk header read failed: {e}"),
                    false,
                )
            })?;
            if n == 0 {
                return Err((ErrorKind::Eof, "unexpected EOF in chunked body".into(), false));
            }
            conn.take_buf().extend_from_slice(&tmp[..n]);
        };

        let size_line = {
            let buf = conn.take_buf();
            let line = String::from_utf8_lossy(&buf[..line_end]).to_string();
            buf.drain(..line_end + 2);
            line
        };
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| (ErrorKind::Protocol, "invalid chunk size".into(), false))?;

        if chunk_size == 0 {
            // Drain terminating CRLF (and any optional trailers up to empty line).
            loop {
                let buf = conn.take_buf();
                if buf.starts_with(b"\r\n") {
                    buf.drain(..2);
                    break;
                }
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    buf.drain(..pos + 4);
                    break;
                }
                if buf.len() > 16384 {
                    return Err((
                        ErrorKind::MessageSize,
                        "chunked response trailers exceed limit".into(),
                        false,
                    ));
                }
                let n = conn.read_chunk(tmp).await.map_err(|e| {
                    (
                        classify_client_io(&e),
                        format!("client chunk trailer read failed: {e}"),
                        false,
                    )
                })?;
                if n == 0 {
                    return Err((
                        ErrorKind::Eof,
                        "unexpected EOF in chunked trailers".into(),
                        false,
                    ));
                }
                conn.take_buf().extend_from_slice(&tmp[..n]);
            }
            return Ok(out);
        }

        if out.len().saturating_add(chunk_size) > max_bytes {
            return Err((
                ErrorKind::MessageSize,
                "chunked response exceeds max_response_streambuf_size".into(),
                false,
            ));
        }

        let chunk = read_exact_body(conn, chunk_size, tmp).await?;
        out.extend_from_slice(&chunk);

        // Consume trailing CRLF after chunk payload
        while conn.take_buf().len() < 2 {
            let n = conn.read_chunk(tmp).await.map_err(|e| {
                (
                    classify_client_io(&e),
                    format!("client chunk trailer read failed: {e}"),
                    false,
                )
            })?;
            if n == 0 {
                return Err((ErrorKind::Eof, "unexpected EOF after chunk".into(), false));
            }
            conn.take_buf().extend_from_slice(&tmp[..n]);
        }
        if &conn.take_buf()[..2] != b"\r\n" {
            return Err((ErrorKind::Protocol, "missing CRLF after chunk".into(), false));
        }
        conn.take_buf().drain(..2);
    }
}

fn classify_client_io(err: &io::Error) -> ErrorKind {
    match err.kind() {
        io::ErrorKind::UnexpectedEof => ErrorKind::Eof,
        io::ErrorKind::TimedOut => ErrorKind::TimedOut,
        io::ErrorKind::InvalidData => ErrorKind::Protocol,
        _ => ErrorKind::Io,
    }
}

fn is_retryable_io(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::UnexpectedEof
    )
}
