use crate::http::{
    inject_connection_close, parse_request_head, scan_head_end, FramingError, ParsedRequestHead,
};
use crate::tls::build_server_config;
use socket2::{Domain, Protocol, Socket, Type};
use std::ffi::c_void;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener as StdTcpListener};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    None = 0,
    OperationAborted = 1,
    Eof = 2,
    Protocol = 3,
    MessageSize = 4,
    TimedOut = 5,
    Tls = 6,
    Io = 7,
}

pub enum ResponseAction {
    Send {
        bytes: Vec<u8>,
        close_connection: bool,
    },
    Abort,
}

pub struct ResponseSenderHandle {
    tx: Option<oneshot::Sender<ResponseAction>>,
}

impl ResponseSenderHandle {
    pub fn new(tx: oneshot::Sender<ResponseAction>) -> Self {
        Self { tx: Some(tx) }
    }

    pub fn send(mut self, bytes: Vec<u8>, close_connection: bool) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(ResponseAction::Send {
                bytes,
                close_connection,
            });
        }
    }

    pub fn abort(mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(ResponseAction::Abort);
        }
    }
}

impl Drop for ResponseSenderHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(ResponseAction::Abort);
        }
    }
}

#[derive(Clone)]
pub struct ServerCallbacks {
    pub user_data: usize,
    pub on_bound: Option<extern "C" fn(*mut c_void, u16)>,
    pub create_connection: extern "C" fn(
        *mut c_void,
        u64,
        *const u8,
        usize,
        u16,
        *const u8,
        usize,
        u16,
    ) -> *mut c_void,
    pub drop_connection: extern "C" fn(*mut c_void, *mut c_void),
    pub on_connection_accepted: Option<extern "C" fn(*mut c_void, *mut c_void) -> bool>,
    pub on_verify_client: Option<extern "C" fn(*mut c_void, u64, *const u8, usize) -> bool>,
    pub on_verify_failed: Option<extern "C" fn(*mut c_void, *mut c_void, *mut ResponseSenderHandle)>,
    pub on_connection_authenticated: Option<extern "C" fn(*mut c_void, *mut c_void) -> bool>,
    pub create_request:
        extern "C" fn(*mut c_void, *mut c_void, *const ServerRequestHeadFfi) -> *mut c_void,
    pub drop_request: extern "C" fn(*mut c_void, *mut c_void),
    pub on_request_header: Option<extern "C" fn(*mut c_void, *mut c_void) -> bool>,
    pub attach_request_body: extern "C" fn(*mut c_void, *mut c_void, *const u8, usize),
    pub dispatch_request: extern "C" fn(*mut c_void, *mut c_void, *mut ResponseSenderHandle),
    pub on_error: Option<extern "C" fn(*mut c_void, *mut c_void, *mut c_void, ErrorKind, *const u8, usize)>,
}

// Safety: C++ ServerBase lifetime outlives the Rust runtime and all callbacks guard with ScopeRunner
// and mutexes/atomic refcounts.
unsafe impl Send for ServerCallbacks {}
unsafe impl Sync for ServerCallbacks {}

#[repr(C)]
pub struct HeaderSliceFfi {
    pub name: *const u8,
    pub name_len: usize,
    pub value: *const u8,
    pub value_len: usize,
}

#[repr(C)]
pub struct ServerRequestHeadFfi {
    pub method: *const u8,
    pub method_len: usize,
    pub path: *const u8,
    pub path_len: usize,
    pub query_string: *const u8,
    pub query_string_len: usize,
    pub http_version: *const u8,
    pub http_version_len: usize,
    pub raw_header: *const u8,
    pub raw_header_len: usize,
    pub headers: *const HeaderSliceFfi,
    pub header_count: usize,
    pub local_addr: *const u8,
    pub local_addr_len: usize,
    pub local_port: u16,
    pub remote_addr: *const u8,
    pub remote_addr_len: usize,
    pub remote_port: u16,
}

#[derive(Clone)]
pub struct ServerSettings {
    pub port: u16,
    pub thread_pool_size: usize,
    pub timeout_request_secs: i64,
    pub timeout_content_secs: i64,
    pub max_request_streambuf_size: usize,
    pub max_request_header_size: usize,
    pub address: String,
    pub reuse_address: bool,
    pub is_https: bool,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub verify_file: Option<String>,
    pub require_client_cert: bool,
}

struct CxxConnectionGuard {
    ptr: *mut c_void,
    user_data: usize,
    drop_fn: extern "C" fn(*mut c_void, *mut c_void),
}

unsafe impl Send for CxxConnectionGuard {}
unsafe impl Sync for CxxConnectionGuard {}

impl Drop for CxxConnectionGuard {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            (self.drop_fn)(self.user_data as *mut c_void, self.ptr);
            self.ptr = std::ptr::null_mut();
        }
    }
}

struct CxxRequestGuard {
    ptr: *mut c_void,
    user_data: usize,
    drop_fn: extern "C" fn(*mut c_void, *mut c_void),
}

unsafe impl Send for CxxRequestGuard {}
unsafe impl Sync for CxxRequestGuard {}

impl Drop for CxxRequestGuard {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            (self.drop_fn)(self.user_data as *mut c_void, self.ptr);
            self.ptr = std::ptr::null_mut();
        }
    }
}

pub(crate) async fn wait_shutdown(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|&s| s).await;
}

pub struct HttpServerInstance {
    rt: tokio::runtime::Runtime,
    settings: ServerSettings,
    tls_acceptor: Option<TlsAcceptor>,
    std_listener: std::sync::Mutex<Option<StdTcpListener>>,
    local_port: u16,
    callbacks: Arc<ServerCallbacks>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

fn bind_std_listener(address: &str, port: u16, reuse_address: bool) -> io::Result<StdTcpListener> {
    let make_bound = |domain: Domain, addr: SocketAddr, dual_stack: bool| -> io::Result<StdTcpListener> {
        let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        if dual_stack {
            let _ = sock.set_only_v6(false);
        }
        sock.set_reuse_address(reuse_address)?;
        sock.bind(&addr.into())?;
        sock.listen(1024)?;
        sock.set_nonblocking(true)?;
        Ok(sock.into())
    };

    if address.is_empty() {
        let v6_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
        match make_bound(Domain::IPV6, v6_addr, true) {
            Ok(listener) => Ok(listener),
            Err(err) => {
                // Fall back to IPv4 wildcard when IPv6 is disabled on the host/container.
                if is_af_not_supported(&err) {
                    let v4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
                    make_bound(Domain::IPV4, v4_addr, false)
                } else {
                    Err(err)
                }
            }
        }
    } else {
        let ip: IpAddr = address.parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid bind address '{address}': {e}"),
            )
        })?;
        let addr = SocketAddr::new(ip, port);
        match ip {
            IpAddr::V4(_) => make_bound(Domain::IPV4, addr, false),
            IpAddr::V6(v6) => make_bound(Domain::IPV6, addr, v6.is_unspecified()),
        }
    }
}

fn is_af_not_supported(err: &io::Error) -> bool {
    if err.kind() == io::ErrorKind::Unsupported {
        return true;
    }
    #[cfg(unix)]
    if let Some(code) = err.raw_os_error() {
        // EAFNOSUPPORT (97 Linux, 47 macOS), EADDRNOTAVAIL (99 Linux, 49 macOS), EPROTONOSUPPORT
        return matches!(code, 97 | 47 | 99 | 49 | 93 | 43);
    }
    #[cfg(windows)]
    if let Some(code) = err.raw_os_error() {
        // WSAEAFNOSUPPORT (10047), WSAEPROTONOSUPPORT (10043)
        return matches!(code, 10047 | 10043);
    }
    false
}

impl HttpServerInstance {
    pub fn create(settings: ServerSettings, callbacks: ServerCallbacks) -> Result<Self, String> {
        let tls_acceptor = if settings.is_https {
            let cert = settings
                .cert_file
                .as_deref()
                .ok_or_else(|| "HTTPS server requires certification_file".to_string())?;
            let key = settings
                .key_file
                .as_deref()
                .ok_or_else(|| "HTTPS server requires private_key_file".to_string())?;
            let verify_path = settings.verify_file.as_deref().map(Path::new);
            let tls_cfg = build_server_config(
                Path::new(cert),
                Path::new(key),
                verify_path,
                settings.require_client_cert,
            )?;
            Some(TlsAcceptor::from(tls_cfg))
        } else {
            None
        };

        let std_listener = bind_std_listener(&settings.address, settings.port, settings.reuse_address)
            .map_err(|e| format!("failed to bind server socket: {e}"))?;
        let local_port = std_listener
            .local_addr()
            .map_err(|e| format!("failed to query bound port: {e}"))?
            .port();

        let workers = settings.thread_pool_size.max(2);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .thread_name("sds-http")
            .enable_all()
            .build()
            .map_err(|e| format!("failed to build tokio runtime: {e}"))?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        Ok(Self {
            rt,
            settings,
            tls_acceptor,
            std_listener: std::sync::Mutex::new(Some(std_listener)),
            local_port,
            callbacks: Arc::new(callbacks),
            shutdown_tx,
            shutdown_rx,
        })
    }

    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub fn run(&self) -> Result<(), String> {
        let std_listener = self
            .std_listener
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| "server already started".to_string())?;
        let callbacks = self.callbacks.clone();
        let tls_acceptor = self.tls_acceptor.clone();
        let settings = self.settings.clone();
        let shutdown_rx = self.shutdown_rx.clone();
        let local_port = self.local_port;

        self.rt.block_on(async move {
            let listener = TcpListener::from_std(std_listener)
                .map_err(|e| format!("failed to adopt listener: {e}"))?;

            if let Some(on_bound) = callbacks.on_bound {
                let ud = callbacks.user_data;
                let _ = tokio::task::spawn_blocking(move || {
                    on_bound(ud as *mut c_void, local_port);
                })
                .await;
            }

            let mut tasks = JoinSet::new();
            let mut loop_shutdown = shutdown_rx.clone();

            loop {
                tokio::select! {
                    biased;
                    _ = wait_shutdown(&mut loop_shutdown) => {
                        emit_error(&callbacks, None, None, ErrorKind::OperationAborted, "operation aborted").await;
                        break;
                    }
                    Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((stream, remote_addr)) => {
                                let _ = stream.set_nodelay(true);
                                let local_addr = stream.local_addr().unwrap_or_else(|_| {
                                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), local_port)
                                });
                                let conn_cb = callbacks.clone();
                                let conn_tls = tls_acceptor.clone();
                                let conn_settings = settings.clone();
                                let conn_shutdown = shutdown_rx.clone();
                                tasks.spawn(async move {
                                    handle_connection(
                                        stream,
                                        local_addr,
                                        remote_addr,
                                        conn_tls,
                                        conn_settings,
                                        conn_cb,
                                        conn_shutdown,
                                    )
                                    .await;
                                });
                            }
                            Err(err) => {
                                let retry_immediately = matches!(
                                    err.kind(),
                                    io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset
                                );
                                let kind = classify_io_error(&err);
                                let msg = err.to_string();
                                emit_error(&callbacks, None, None, kind, &msg).await;
                                if !retry_immediately {
                                    tokio::select! {
                                        biased;
                                        _ = wait_shutdown(&mut loop_shutdown) => {
                                            emit_error(&callbacks, None, None, ErrorKind::OperationAborted, "operation aborted").await;
                                            break;
                                        }
                                        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                                    }
                                }
                            }
                        }
                    }
                }
            }

            drop(listener);
            while tasks.join_next().await.is_some() {}
            Ok(())
        })
    }
}

async fn emit_error(
    callbacks: &Arc<ServerCallbacks>,
    conn: Option<&Arc<CxxConnectionGuard>>,
    req: Option<&Arc<CxxRequestGuard>>,
    kind: ErrorKind,
    msg: &str,
) {
    let Some(on_error) = callbacks.on_error else {
        return;
    };
    let ud = callbacks.user_data;
    let conn_clone = conn.cloned();
    let req_clone = req.cloned();
    let msg_owned = msg.as_bytes().to_vec();
    let _ = tokio::task::spawn_blocking(move || {
        let conn_ptr = conn_clone
            .as_ref()
            .map_or(std::ptr::null_mut(), |c| c.ptr);
        let req_ptr = req_clone
            .as_ref()
            .map_or(std::ptr::null_mut(), |r| r.ptr);
        on_error(
            ud as *mut c_void,
            conn_ptr,
            req_ptr,
            kind,
            msg_owned.as_ptr(),
            msg_owned.len(),
        );
    })
    .await;
}

fn timeout_duration(secs: i64) -> Option<Duration> {
    if secs > 0 {
        Some(Duration::from_secs(secs as u64))
    } else {
        None
    }
}

async fn run_with_timeout<F, T>(dur: Option<Duration>, fut: F) -> Result<T, ()>
where
    F: std::future::Future<Output = T>,
{
    match dur {
        Some(d) => tokio::time::timeout(d, fut).await.map_err(|_| ()),
        None => Ok(fut.await),
    }
}

async fn run_until_deadline<F, T>(
    deadline: Option<tokio::time::Instant>,
    fut: F,
) -> Result<T, ()>
where
    F: std::future::Future<Output = T>,
{
    match deadline {
        Some(dl) => tokio::time::timeout_at(dl, fut).await.map_err(|_| ()),
        None => Ok(fut.await),
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    tls_acceptor: Option<TlsAcceptor>,
    settings: ServerSettings,
    callbacks: Arc<ServerCallbacks>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let conn_id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
    let local_str = local_addr.ip().to_string();
    let remote_str = remote_addr.ip().to_string();
    let local_port = local_addr.port();
    let remote_port = remote_addr.port();

    let conn_guard = {
        let cb = callbacks.clone();
        let l_bytes = local_str.as_bytes().to_vec();
        let r_bytes = remote_str.as_bytes().to_vec();
        match tokio::task::spawn_blocking(move || {
            let ud = cb.user_data as *mut c_void;
            let ptr = (cb.create_connection)(
                ud,
                conn_id,
                l_bytes.as_ptr(),
                l_bytes.len(),
                local_port,
                r_bytes.as_ptr(),
                r_bytes.len(),
                remote_port,
            );
            Arc::new(CxxConnectionGuard {
                ptr,
                user_data: cb.user_data,
                drop_fn: cb.drop_connection,
            })
        })
        .await
        {
            Ok(g) => g,
            Err(_) => return,
        }
    };

    if let Some(on_accepted) = callbacks.on_connection_accepted {
        let ud = callbacks.user_data;
        let g = conn_guard.clone();
        let accepted = tokio::task::spawn_blocking(move || on_accepted(ud as *mut c_void, g.ptr))
            .await
            .unwrap_or(false);
        if !accepted {
            return;
        }
    }

    let req_timeout = timeout_duration(settings.timeout_request_secs);

    if let Some(acceptor) = tls_acceptor {
        let hs_res = tokio::select! {
            biased;
            _ = wait_shutdown(&mut shutdown_rx) => return,
            res = run_with_timeout(req_timeout, acceptor.accept(stream)) => res,
        };

        let mut tls_stream = match hs_res {
            Ok(Ok(s)) => s,
            Ok(Err(err)) => {
                let kind = classify_tls_io_error(&err);
                let msg = err.to_string();
                emit_error(&callbacks, Some(&conn_guard), None, kind, &msg).await;
                return;
            }
            Err(()) => {
                emit_error(
                    &callbacks,
                    Some(&conn_guard),
                    None,
                    ErrorKind::TimedOut,
                    "TLS handshake timed out",
                )
                .await;
                return;
            }
        };

        if let Some(on_verify) = callbacks.on_verify_client {
            let leaf_der = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(|c| c.as_ref().to_vec());
            let verified = match leaf_der {
                Some(der) if !der.is_empty() => {
                    let ud = callbacks.user_data;
                    tokio::task::spawn_blocking(move || {
                        on_verify(ud as *mut c_void, conn_id, der.as_ptr(), der.len())
                    })
                    .await
                    .unwrap_or(false)
                }
                _ => false,
            };

            if !verified {
                if let Some(on_verify_failed) = callbacks.on_verify_failed {
                    let (tx, rx) = oneshot::channel();
                    let sender_addr =
                        Box::into_raw(Box::new(ResponseSenderHandle::new(tx))) as usize;
                    let ud = callbacks.user_data;
                    let g = conn_guard.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        on_verify_failed(
                            ud as *mut c_void,
                            g.ptr,
                            sender_addr as *mut ResponseSenderHandle,
                        );
                    })
                    .await;

                    let content_timeout = timeout_duration(settings.timeout_content_secs);
                    let action = tokio::select! {
                        biased;
                        _ = wait_shutdown(&mut shutdown_rx) => None,
                        res = run_with_timeout(content_timeout, rx) => res.ok().and_then(|r| r.ok()),
                    };
                    if let Some(ResponseAction::Send { bytes, .. }) = action {
                        let out = inject_connection_close(bytes);
                        let _ = run_with_timeout(content_timeout, async {
                            let _ = tls_stream.write_all(&out).await;
                            let _ = tls_stream.flush().await;
                        })
                        .await;
                    }
                }
                let _ = tokio::time::timeout(Duration::from_secs(1), tls_stream.shutdown()).await;
                return;
            }
        }

        if let Some(on_auth) = callbacks.on_connection_authenticated {
            let ud = callbacks.user_data;
            let g = conn_guard.clone();
            let allowed = tokio::task::spawn_blocking(move || on_auth(ud as *mut c_void, g.ptr))
                .await
                .unwrap_or(false);
            if !allowed {
                return;
            }
        }

        run_http_loop(
            tls_stream,
            &local_str,
            local_port,
            &remote_str,
            remote_port,
            &conn_guard,
            &settings,
            &callbacks,
            &mut shutdown_rx,
        )
        .await;
    } else {
        if let Some(on_auth) = callbacks.on_connection_authenticated {
            let ud = callbacks.user_data;
            let g = conn_guard.clone();
            let allowed = tokio::task::spawn_blocking(move || on_auth(ud as *mut c_void, g.ptr))
                .await
                .unwrap_or(false);
            if !allowed {
                return;
            }
        }

        run_http_loop(
            stream,
            &local_str,
            local_port,
            &remote_str,
            remote_port,
            &conn_guard,
            &settings,
            &callbacks,
            &mut shutdown_rx,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_http_loop<S>(
    mut stream: S,
    local_str: &str,
    local_port: u16,
    remote_str: &str,
    remote_port: u16,
    conn_guard: &Arc<CxxConnectionGuard>,
    settings: &ServerSettings,
    callbacks: &Arc<ServerCallbacks>,
    shutdown_rx: &mut watch::Receiver<bool>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req_timeout = timeout_duration(settings.timeout_request_secs);
    let content_timeout = timeout_duration(settings.timeout_content_secs);
    let max_header = settings.max_request_header_size.max(1);
    let max_body = settings.max_request_streambuf_size;
    let mut read_buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 8192];
    let mut served_any = false;

    loop {
        // 1. Read request head up to \r\n\r\n within a single req_timeout deadline across reads
        //    so slowloris 1-byte drips cannot extend the header deadline.
        let head_deadline = req_timeout.map(|d| tokio::time::Instant::now() + d);
        let head_end = loop {
            match scan_head_end(&read_buf, max_header) {
                Ok(Some(idx)) => break idx,
                Ok(None) => {}
                Err(FramingError::HeadersTooLarge) => {
                    emit_error(
                        callbacks,
                        Some(conn_guard),
                        None,
                        ErrorKind::MessageSize,
                        "request header too large",
                    )
                    .await;
                    return;
                }
                Err(err) => {
                    emit_error(
                        callbacks,
                        Some(conn_guard),
                        None,
                        ErrorKind::Protocol,
                        &err.to_string(),
                    )
                    .await;
                    return;
                }
            }

            let read_res = tokio::select! {
                biased;
                _ = wait_shutdown(shutdown_rx) => return,
                res = run_until_deadline(head_deadline, stream.read(&mut tmp)) => res,
            };

            match read_res {
                Ok(Ok(0)) => {
                    if !read_buf.is_empty() || !served_any {
                        emit_error(callbacks, Some(conn_guard), None, ErrorKind::Eof, "eof").await;
                    }
                    return;
                }
                Ok(Ok(n)) => {
                    read_buf.extend_from_slice(&tmp[..n]);
                }
                Ok(Err(err)) => {
                    let kind = classify_io_error(&err);
                    emit_error(callbacks, Some(conn_guard), None, kind, &err.to_string()).await;
                    return;
                }
                Err(()) => {
                    emit_error(
                        callbacks,
                        Some(conn_guard),
                        None,
                        ErrorKind::TimedOut,
                        "request header timeout",
                    )
                    .await;
                    return;
                }
            }
        };

        let raw_head = read_buf[..head_end].to_vec();
        read_buf.drain(..head_end);

        // 2. Parse & strictly validate RFC 9112 framing.
        let parsed: ParsedRequestHead = match parse_request_head(&raw_head, max_body) {
            Ok(p) => p,
            Err(err) => {
                let kind = match err {
                    FramingError::BodyTooLarge | FramingError::HeadersTooLarge => {
                        ErrorKind::MessageSize
                    }
                    _ => ErrorKind::Protocol,
                };
                emit_error(callbacks, Some(conn_guard), None, kind, &err.to_string()).await;
                return;
            }
        };

        // 3. Construct C++ Request BEFORE reading body so on_request_header inspects head and
        // attaches per-request admission leases.
        let req_guard = {
            let cb = callbacks.clone();
            let cg = conn_guard.clone();
            let parsed_clone = parsed.clone();
            let raw_clone = raw_head.clone();
            let l_bytes = local_str.as_bytes().to_vec();
            let r_bytes = remote_str.as_bytes().to_vec();

            match tokio::task::spawn_blocking(move || {
                let header_slices: Vec<HeaderSliceFfi> = parsed_clone
                    .headers
                    .iter()
                    .map(|(k, v)| HeaderSliceFfi {
                        name: k.as_ptr(),
                        name_len: k.len(),
                        value: v.as_ptr(),
                        value_len: v.len(),
                    })
                    .collect();
                let head_ffi = ServerRequestHeadFfi {
                    method: parsed_clone.method.as_ptr(),
                    method_len: parsed_clone.method.len(),
                    path: parsed_clone.path.as_ptr(),
                    path_len: parsed_clone.path.len(),
                    query_string: parsed_clone.query_string.as_ptr(),
                    query_string_len: parsed_clone.query_string.len(),
                    http_version: parsed_clone.http_version.as_ptr(),
                    http_version_len: parsed_clone.http_version.len(),
                    raw_header: raw_clone.as_ptr(),
                    raw_header_len: raw_clone.len(),
                    headers: header_slices.as_ptr(),
                    header_count: header_slices.len(),
                    local_addr: l_bytes.as_ptr(),
                    local_addr_len: l_bytes.len(),
                    local_port,
                    remote_addr: r_bytes.as_ptr(),
                    remote_addr_len: r_bytes.len(),
                    remote_port,
                };
                let ptr = (cb.create_request)(cb.user_data as *mut c_void, cg.ptr, &head_ffi);
                Arc::new(CxxRequestGuard {
                    ptr,
                    user_data: cb.user_data,
                    drop_fn: cb.drop_request,
                })
            })
            .await
            {
                Ok(g) => g,
                Err(_) => return,
            }
        };

        if let Some(on_head) = callbacks.on_request_header {
            let ud = callbacks.user_data;
            let rg = req_guard.clone();
            let allowed = tokio::task::spawn_blocking(move || on_head(ud as *mut c_void, rg.ptr))
                .await
                .unwrap_or(false);
            if !allowed {
                return;
            }
        }

        // 4. Read exact Content-Length body within content_timeout.
        let body_len = parsed.content_length;
        let mut body_buf: Vec<u8> = Vec::new();
        if body_len > 0 {
            let already = read_buf.len().min(body_len);
            if already > 0 {
                body_buf.extend_from_slice(&read_buf[..already]);
                read_buf.drain(..already);
            }
            if body_buf.len() < body_len {
                body_buf.reserve(body_len - body_buf.len());
                let read_body_res = tokio::select! {
                    biased;
                    _ = wait_shutdown(shutdown_rx) => return,
                    res = run_with_timeout(content_timeout, async {
                        while body_buf.len() < body_len {
                            let needed = (body_len - body_buf.len()).min(tmp.len());
                            let n = stream.read(&mut tmp[..needed]).await?;
                            if n == 0 {
                                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof reading body"));
                            }
                            body_buf.extend_from_slice(&tmp[..n]);
                        }
                        Ok::<(), io::Error>(())
                    }) => res,
                };
                match read_body_res {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        let kind = classify_io_error(&err);
                        emit_error(
                            callbacks,
                            Some(conn_guard),
                            Some(&req_guard),
                            kind,
                            &err.to_string(),
                        )
                        .await;
                        return;
                    }
                    Err(()) => {
                        emit_error(
                            callbacks,
                            Some(conn_guard),
                            Some(&req_guard),
                            ErrorKind::TimedOut,
                            "request body timeout",
                        )
                        .await;
                        return;
                    }
                }
            }

            let cb = callbacks.clone();
            let rg = req_guard.clone();
            let _ = tokio::task::spawn_blocking(move || {
                (cb.attach_request_body)(
                    cb.user_data as *mut c_void,
                    rg.ptr,
                    body_buf.as_ptr(),
                    body_buf.len(),
                );
            })
            .await;
        }

        // 5. Dispatch C++ handler and await oneshot response.
        let (tx, rx) = oneshot::channel();
        let sender_addr = Box::into_raw(Box::new(ResponseSenderHandle::new(tx))) as usize;
        {
            let cb = callbacks.clone();
            let rg = req_guard.clone();
            let _ = tokio::task::spawn_blocking(move || {
                (cb.dispatch_request)(
                    cb.user_data as *mut c_void,
                    rg.ptr,
                    sender_addr as *mut ResponseSenderHandle,
                );
            })
            .await;
        }

        let action = tokio::select! {
            biased;
            _ = wait_shutdown(shutdown_rx) => return,
            res = run_with_timeout(content_timeout, rx) => {
                match res {
                    Ok(Ok(act)) => act,
                    Ok(Err(_)) => return,
                    Err(()) => {
                        emit_error(
                            callbacks,
                            Some(conn_guard),
                            Some(&req_guard),
                            ErrorKind::TimedOut,
                            "response timeout",
                        )
                        .await;
                        return;
                    }
                }
            }
        };

        let (bytes, close_after) = match action {
            ResponseAction::Abort => return,
            ResponseAction::Send {
                bytes,
                close_connection,
            } => (bytes, close_connection || parsed.close_after_response),
        };

        let wire_bytes = if close_after {
            inject_connection_close(bytes)
        } else {
            bytes
        };

        let write_res = tokio::select! {
            biased;
            _ = wait_shutdown(shutdown_rx) => return,
            res = run_with_timeout(content_timeout, async {
                stream.write_all(&wire_bytes).await?;
                stream.flush().await
            }) => res,
        };

        match write_res {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                let kind = classify_io_error(&err);
                emit_error(
                    callbacks,
                    Some(conn_guard),
                    Some(&req_guard),
                    kind,
                    &err.to_string(),
                )
                .await;
                return;
            }
            Err(()) => {
                emit_error(
                    callbacks,
                    Some(conn_guard),
                    Some(&req_guard),
                    ErrorKind::TimedOut,
                    "response write timeout",
                )
                .await;
                return;
            }
        }

        // Release per-request admission lease immediately after write+flush completes,
        // before awaiting the next keep-alive request.
        drop(req_guard);
        served_any = true;

        if close_after {
            let _ = tokio::time::timeout(Duration::from_secs(1), stream.shutdown()).await;
            return;
        }
        if read_buf.is_empty() && read_buf.capacity() > 64 * 1024 {
            read_buf = Vec::with_capacity(4096);
        }
    }
}

fn classify_io_error(err: &io::Error) -> ErrorKind {
    match err.kind() {
        io::ErrorKind::UnexpectedEof => ErrorKind::Eof,
        io::ErrorKind::TimedOut => ErrorKind::TimedOut,
        io::ErrorKind::InvalidData => ErrorKind::Protocol,
        _ => ErrorKind::Io,
    }
}

fn classify_tls_io_error(err: &io::Error) -> ErrorKind {
    if err.kind() == io::ErrorKind::UnexpectedEof {
        ErrorKind::Eof
    } else if err.kind() == io::ErrorKind::TimedOut {
        ErrorKind::TimedOut
    } else {
        ErrorKind::Tls
    }
}
